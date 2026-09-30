use std::{env, ffi::OsString, path::PathBuf, process};

use easy_sandbox::config::{LimitRequest, NetworkMode, NetworkRule, Policy, PolicyMode};
use easy_sandbox::verify::{self, CaseFile, Defaults};

mod policy;

/// Launcher defaults, used when neither the caller nor a policy sets a value.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MEMORY_MIB: u64 = 512;
/// Where the P3 proxy socket appears inside the sandbox.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const SANDBOX_PROXY_PATH: &str = "/run/proxy.sock";
/// Environment variable that tells a payload how to reach the proxy.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const PROXY_ENV: &str = "EASY_SANDBOX_PROXY";

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Debug)]
struct RunConfig {
    rootfs: PathBuf,
    workspace: PathBuf,
    timeout_ms: u64,
    memory_mib: Option<u64>,
    cpu_seconds: Option<u64>,
    max_processes: Option<u64>,
    secure: bool,
    /// Policy to enforce, after the YAML document has been parsed.
    policy: Option<Policy>,
    /// Frozen allowlist for the P3 proxy, from the policy or `--proxy-allow`.
    proxy_rules: Option<Vec<NetworkRule>>,
    /// True when the run may use the proxy: the baseline then permits `AF_UNIX`
    /// sockets so the payload can reach it, and nothing else.
    proxy_enabled: bool,
    /// Host-side proxy socket, bind-mounted at [`SANDBOX_PROXY_PATH`].
    proxy_socket: Option<PathBuf>,
    /// JSONL run record destination, when `--record` was given.
    record: Option<PathBuf>,
    command: Vec<OsString>,
}

/// Exactly what the caller asked for, before defaults and policy caps.
#[derive(Clone, Debug, Default)]
struct CliOptions {
    rootfs: Option<PathBuf>,
    workspace: Option<PathBuf>,
    timeout_ms: Option<u64>,
    memory_mib: Option<u64>,
    memory_unlimited: bool,
    cpu_seconds: Option<u64>,
    max_processes: Option<u64>,
    secure: bool,
    /// `--proxy-allow HOST:PORT`, repeatable: enable the P3 proxy without a
    /// policy document.
    proxy_allow: Vec<String>,
    /// Internal flag: host path of the proxy socket, set by the parent.
    proxy_socket: Option<PathBuf>,
    /// `--record PATH`: write a JSONL run record (`-` means stderr).
    record: Option<PathBuf>,
    command: Vec<OsString>,
}

impl CliOptions {
    /// Apply the launcher defaults and then the policy caps.
    ///
    /// A policy can only ever tighten what the caller asked for; the caller
    /// cannot exceed a policy value.  See [`LimitRequest::resolve`].
    fn resolve(&self, policy: Option<&Policy>) -> Result<RunConfig, String> {
        let limits = policy.map(|policy| &policy.limits);
        let timeout_ms = LimitRequest::from(self.timeout_ms)
            .resolve(
                limits.and_then(|limits| limits.timeout_ms),
                LimitRequest::Value(DEFAULT_TIMEOUT_MS),
            )
            .as_option()
            .ok_or_else(|| "--timeout-ms must be greater than zero".to_string())?;
        if timeout_ms == 0 {
            return Err("--timeout-ms must be greater than zero".to_string());
        }
        let memory_request = if self.memory_unlimited {
            LimitRequest::Unlimited
        } else {
            LimitRequest::from(self.memory_mib)
        };
        let memory_mib = memory_request.resolve(
            limits.and_then(|limits| limits.memory_mib),
            LimitRequest::Value(DEFAULT_MEMORY_MIB),
        );
        let cpu_seconds = LimitRequest::from(self.cpu_seconds).resolve(
            limits.and_then(|limits| limits.cpu_seconds),
            LimitRequest::Unset,
        );
        let max_processes = LimitRequest::from(self.max_processes).resolve(
            limits.and_then(|limits| limits.max_processes),
            LimitRequest::Unset,
        );

        // The proxy allowlist comes from the policy document or from
        // `--proxy-allow`.  They are never merged: a union of two allowlists
        // would be a silent widening of the stricter one.
        let policy_proxy = policy.is_some_and(|policy| policy.network.mode == NetworkMode::Proxy);
        if policy_proxy && !self.proxy_allow.is_empty() {
            return Err(
                "use either --policy with network.mode: proxy or --proxy-allow, not both"
                    .to_string(),
            );
        }
        let proxy_rules = if policy_proxy {
            policy.map(|policy| policy.network.allow.clone())
        } else if self.proxy_allow.is_empty() {
            None
        } else {
            let mut rules = Vec::with_capacity(self.proxy_allow.len());
            for entry in &self.proxy_allow {
                rules.push(parse_proxy_allow(entry)?);
            }
            Some(rules)
        };

        Ok(RunConfig {
            rootfs: self
                .rootfs
                .clone()
                .ok_or_else(|| "--rootfs is required".to_string())?,
            workspace: self
                .workspace
                .clone()
                .ok_or_else(|| "--workspace is required".to_string())?,
            timeout_ms,
            memory_mib: memory_mib.as_option(),
            cpu_seconds: cpu_seconds.as_option(),
            max_processes: max_processes.as_option(),
            secure: self.secure,
            policy: policy.cloned(),
            proxy_enabled: proxy_rules.is_some() || self.proxy_socket.is_some(),
            proxy_rules,
            proxy_socket: self.proxy_socket.clone(),
            record: self.record.clone(),
            command: self.command.clone(),
        })
    }
}

/// Parse one `--proxy-allow HOST:PORT` entry into a proxy rule.
///
/// The proxy refuses IP literals, so an address here is a configuration error
/// rather than a rule that can never match.
fn parse_proxy_allow(entry: &str) -> Result<NetworkRule, String> {
    let (host, port) = entry
        .rsplit_once(':')
        .ok_or_else(|| format!("--proxy-allow expects HOST:PORT, got {entry:?}"))?;
    if host.is_empty() || host.contains('/') || host.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "--proxy-allow expects a hostname (the proxy refuses IP literals), got {host:?}"
        ));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| format!("--proxy-allow port is not a number: {port:?}"))?;
    if port == 0 {
        return Err("--proxy-allow port must be between 1 and 65535".to_string());
    }
    Ok(NetworkRule {
        host: host.to_ascii_lowercase(),
        ports: vec![port],
    })
}

enum Mode {
    Run {
        options: CliOptions,
        policy_path: Option<PathBuf>,
    },
    Child {
        options: CliOptions,
        frozen_policy: Option<String>,
    },
    Verify(VerifyArgs),
}

/// Options of the `verify` subcommand.
#[derive(Clone, Debug)]
struct VerifyArgs {
    policy: PathBuf,
    cases: PathBuf,
    report: Option<PathBuf>,
    records: Option<PathBuf>,
    rootfs: PathBuf,
    workspace: PathBuf,
    timeout_ms: u64,
}

fn usage() {
    eprintln!(
        "usage: easy-sandbox run --rootfs DIR --workspace DIR [options] -- COMMAND [ARGS...]\n\
         options:\n\
           --timeout-ms N       wall-clock timeout (default: 30000)\n\
           --memory-mib N       address-space limit (default: 512)\n\
           --no-memory-limit    do not set an address-space limit\n\
           --cpu-seconds N      CPU-time limit\n\
           --max-processes N    RLIMIT_NPROC soft limit\n\
           --secure             require Landlock ABI 3 and seccomp\n\
           --policy PATH        YAML policy to enforce; implies --secure and can\n\
                                only tighten the limits above.  network.mode:\n\
                                proxy mounts a CONNECT proxy at /run/proxy.sock,\n\
                                exposed as $EASY_SANDBOX_PROXY\n\
           --proxy-allow H:P    allow HOST:PORT through that proxy without a\n\
                                policy; repeatable, refused for IP literals\n\
           --record PATH        append a JSONL run record (`-` means stderr)\n\
         policy modes: enforce installs the layers, observe records them as\n\
         unapproved candidates and installs none of them.\n\
         \n\
         usage: easy-sandbox verify --policy PATH --cases PATH --rootfs DIR\n\
                     --workspace DIR [--report PATH] [--records DIR]\n\
         Each case declares an expectation (allow/deny) or none at all, in\n\
         which case its verdict stays pending for a human to decide.\n\
         \n\
         Linux only; the launcher refuses to run as uid 0."
    );
}

fn parse_u64(name: &str, value: OsString) -> Result<u64, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{name} must be UTF-8"))?
        .parse::<u64>()
        .map_err(|_| format!("invalid {name}"))
}

fn next_value<I: Iterator<Item = OsString>>(
    args: &mut I,
    option: &str,
) -> Result<OsString, String> {
    args.next()
        .ok_or_else(|| format!("missing value for {option}"))
}

/// Parse `easy-sandbox verify ...`.
fn parse_verify_args(mut args: impl Iterator<Item = OsString>) -> Result<VerifyArgs, String> {
    let mut policy = None;
    let mut cases = None;
    let mut report = None;
    let mut records = None;
    let mut rootfs = None;
    let mut workspace = None;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;

    while let Some(arg) = args.next() {
        let name = arg
            .to_str()
            .ok_or_else(|| "option must be UTF-8".to_string())?;
        match name {
            "--policy" => policy = Some(PathBuf::from(next_value(&mut args, name)?)),
            "--cases" => cases = Some(PathBuf::from(next_value(&mut args, name)?)),
            "--report" => report = Some(PathBuf::from(next_value(&mut args, name)?)),
            "--records" => records = Some(PathBuf::from(next_value(&mut args, name)?)),
            "--rootfs" => rootfs = Some(PathBuf::from(next_value(&mut args, name)?)),
            "--workspace" => workspace = Some(PathBuf::from(next_value(&mut args, name)?)),
            "--timeout-ms" => timeout_ms = parse_u64(name, next_value(&mut args, name)?)?,
            _ => return Err(format!("unknown verify option: {name}")),
        }
    }
    if timeout_ms == 0 {
        return Err("--timeout-ms must be greater than zero".to_string());
    }
    Ok(VerifyArgs {
        policy: policy.ok_or_else(|| "verify requires --policy".to_string())?,
        cases: cases.ok_or_else(|| "verify requires --cases".to_string())?,
        report,
        records,
        rootfs: rootfs.ok_or_else(|| "verify requires --rootfs".to_string())?,
        workspace: workspace.ok_or_else(|| "verify requires --workspace".to_string())?,
        timeout_ms,
    })
}

/// Locate this launcher, so a verification run re-enters the same binary.
fn launcher_path() -> Result<PathBuf, String> {
    std::env::current_exe()
        .or_else(|error| match std::env::args_os().next() {
            Some(argv0) => {
                let path = PathBuf::from(argv0);
                if path.is_absolute() {
                    Ok(path)
                } else {
                    Err(error)
                }
            }
            None => Err(error),
        })
        .map_err(|error| format!("cannot locate launcher: {error}"))
}

/// Run `verify`: independent cases against one frozen policy.
fn run_verify(args: &VerifyArgs) -> i32 {
    let policy = match Policy::from_yaml_file(&args.policy) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!(
                "easy-sandbox: policy-rejected: cannot load policy {}: {error}",
                args.policy.display()
            );
            return 125;
        }
    };
    if policy.mode != PolicyMode::Enforce {
        eprintln!(
            "easy-sandbox: policy-rejected: verify needs a policy in enforce mode; this one declares {:?}",
            policy.mode
        );
        return 125;
    }
    if let Err(error) = policy::Plan::compile(&policy) {
        eprintln!("easy-sandbox: policy-rejected: {error}");
        return 125;
    }
    let cases = match CaseFile::from_yaml_file(&args.cases) {
        Ok(cases) => cases,
        Err(error) => {
            eprintln!("easy-sandbox: {error}");
            return 125;
        }
    };
    let launcher = match launcher_path() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("easy-sandbox: {error}");
            return 125;
        }
    };
    let defaults = Defaults {
        rootfs: args.rootfs.clone(),
        workspace: args.workspace.clone(),
        timeout_ms: args.timeout_ms,
    };
    let report = match verify::verify(
        &launcher,
        &args.policy,
        &policy,
        &cases,
        &defaults,
        args.records.as_deref(),
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("easy-sandbox: {error}");
            return 125;
        }
    };

    let rendered = match serde_json::to_string_pretty(&report) {
        Ok(rendered) => rendered,
        Err(error) => {
            eprintln!("easy-sandbox: cannot render report: {error}");
            return 125;
        }
    };
    match args.report.as_deref() {
        Some(path) if path != std::path::Path::new("-") => {
            if let Err(error) = std::fs::write(path, format!("{rendered}\n")) {
                eprintln!(
                    "easy-sandbox: cannot write report {}: {error}",
                    path.display()
                );
                return 125;
            }
        }
        _ => println!("{rendered}"),
    }

    for case in &report.cases {
        if case.verdict != easy_sandbox::events::Verdict::Pass {
            eprintln!(
                "easy-sandbox: verify {:?} {}: {}",
                case.verdict, case.name, case.detail
            );
        }
    }
    eprintln!(
        "easy-sandbox: verify passed={} failed={} pending={}",
        report.summary.passed, report.summary.failed, report.summary.pending
    );
    if report.summary.failed > 0 {
        1
    } else if report.summary.pending > 0 {
        2
    } else {
        0
    }
}

fn parse_args() -> Result<Mode, String> {
    let mut args = env::args_os().skip(1);
    let subcommand = args
        .next()
        .ok_or_else(|| "missing subcommand".to_string())?;
    // `verify` is a separate entry point: it drives `run` for each case.
    if subcommand == "verify" {
        return parse_verify_args(args).map(Mode::Verify);
    }
    let child = subcommand == "__child";
    if !child && subcommand != "run" {
        return Err(format!("unknown subcommand: {subcommand:?}"));
    }

    let mut options = CliOptions::default();
    let mut policy_path = None;
    let mut frozen_policy = None;
    let mut command_started = false;

    while let Some(arg) = args.next() {
        if command_started {
            options.command.push(arg);
            continue;
        }
        if arg == "--" {
            command_started = true;
            continue;
        }
        let name = arg
            .to_str()
            .ok_or_else(|| "option must be UTF-8".to_string())?;
        match name {
            "--rootfs" => options.rootfs = Some(PathBuf::from(next_value(&mut args, name)?)),
            "--workspace" => options.workspace = Some(PathBuf::from(next_value(&mut args, name)?)),
            "--timeout-ms" => {
                options.timeout_ms = Some(parse_u64(name, next_value(&mut args, name)?)?)
            }
            "--memory-mib" => {
                options.memory_mib = Some(parse_u64(name, next_value(&mut args, name)?)?);
                options.memory_unlimited = false;
            }
            "--no-memory-limit" => {
                options.memory_mib = None;
                options.memory_unlimited = true;
            }
            "--cpu-seconds" => {
                options.cpu_seconds = Some(parse_u64(name, next_value(&mut args, name)?)?)
            }
            "--max-processes" => {
                options.max_processes = Some(parse_u64(name, next_value(&mut args, name)?)?)
            }
            "--secure" => options.secure = true,
            "--proxy-allow" => {
                let value = next_value(&mut args, name)?;
                options.proxy_allow.push(
                    value
                        .into_string()
                        .map_err(|_| "--proxy-allow must be UTF-8".to_string())?,
                );
            }
            // `--policy` is the caller-facing entry point; the child receives
            // the validated document through the internal `--frozen-policy`
            // flag so that a policy file can never change between the parent's
            // validation and the child's enforcement.
            "--policy" if !child => policy_path = Some(PathBuf::from(next_value(&mut args, name)?)),
            "--frozen-policy" if child => {
                let value = next_value(&mut args, name)?;
                frozen_policy = Some(
                    value
                        .into_string()
                        .map_err(|_| "--frozen-policy must be UTF-8".to_string())?,
                );
            }
            "--proxy-socket" if child => {
                options.proxy_socket = Some(PathBuf::from(next_value(&mut args, name)?));
            }
            // The record is written by the parent: paths given by the caller do
            // not exist inside the sandbox rootfs.
            "--record" => options.record = Some(PathBuf::from(next_value(&mut args, name)?)),
            _ if name.starts_with('-') => return Err(format!("unknown option: {name}")),
            _ => return Err(format!("expected -- before command, got {name}")),
        }
    }

    if options.command.is_empty() {
        return Err("a command is required after --".to_string());
    }
    Ok(if child {
        Mode::Child {
            options,
            frozen_policy,
        }
    } else {
        Mode::Run {
            options,
            policy_path,
        }
    })
}

/// Read, validate, and pre-flight a policy document.
///
/// Every failure here means the run must not start: exit status 125.
fn load_policy(path: Option<&PathBuf>) -> Result<Option<Policy>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    // Every policy problem is prefixed with a stable marker so a caller can
    // tell "the policy was rejected" from "the sandbox could not be built".
    let policy = Policy::from_yaml_file(path).map_err(|error| {
        format!(
            "policy-rejected: cannot load policy {}: {error}",
            path.display()
        )
    })?;
    // Reject anything the sandbox could not enforce *before* a child exists.
    policy::Plan::compile(&policy).map_err(|error| format!("policy-rejected: {error}"))?;
    Ok(Some(policy))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{PROXY_ENV, RunConfig, SANDBOX_PROXY_PATH};
    use std::{
        ffi::CString,
        fs, io,
        os::fd::RawFd,
        os::unix::{
            ffi::OsStrExt,
            process::{CommandExt, ExitStatusExt},
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use easy_sandbox::{
        config::{NetworkRule, PolicyMode},
        events::{EventKind, RunLimits},
        proxy::{self, Listener},
        run::{self, Recorder},
    };
    use std::sync::{Arc, Mutex};

    const SETUP_FAILED: i32 = 125;
    const EXEC_FAILED: i32 = 126;
    const TIMEOUT: i32 = 124;
    const USER_NAMESPACE: libc::c_int = libc::CLONE_NEWUSER;
    const ISOLATION_NAMESPACES: libc::c_int = libc::CLONE_NEWNS
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWPID;

    type Result<T> = std::result::Result<T, String>;

    pub fn run_parent(mut config: RunConfig) -> i32 {
        let expected_parent = unsafe { libc::getppid() };
        if let Err(error) = set_parent_death_signal(expected_parent) {
            eprintln!("easy-sandbox: {error}");
            return SETUP_FAILED;
        }
        if unsafe { libc::geteuid() } == 0 {
            eprintln!(
                "easy-sandbox: refusing to run as uid 0; use an unprivileged service account"
            );
            return SETUP_FAILED;
        }
        if let Err(error) = validate_and_prepare(&mut config) {
            eprintln!("easy-sandbox: {error}");
            return SETUP_FAILED;
        }

        // P4: the record is written by this parent and by the sandbox child.
        let frozen = match &config.policy {
            Some(policy) => match policy.to_yaml_string() {
                Ok(document) => document,
                Err(error) => {
                    eprintln!("easy-sandbox: {error}");
                    return SETUP_FAILED;
                }
            },
            None => String::new(),
        };
        let observe = config
            .policy
            .as_ref()
            .is_some_and(|policy| policy.mode == PolicyMode::Observe);
        let mut recorder = match &config.record {
            Some(path) => match Recorder::open(
                path,
                "launcher-parent",
                run::run_id(),
                run::fingerprint(&frozen),
            ) {
                Ok(recorder) => recorder,
                Err(error) => {
                    eprintln!("easy-sandbox: {error}");
                    return SETUP_FAILED;
                }
            },
            None => Recorder::disabled(),
        };
        recorder.record(run::run_started(
            mode_name(&config),
            config.policy.as_ref().map_or(0, |policy| policy.version),
            &frozen,
            RunLimits {
                timeout_ms: config.timeout_ms,
                memory_mib: config.memory_mib,
                cpu_seconds: config.cpu_seconds,
                max_processes: config.max_processes,
            },
            &config.rootfs.display().to_string(),
            &config.workspace.display().to_string(),
            &config
                .command
                .iter()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        ));
        if observe {
            // Observe records the intent and applies none of it: every entry
            // stays an unapproved candidate for a human to review.
            if let Some(policy) = &config.policy {
                for candidate in run::candidates(policy) {
                    recorder.record(candidate);
                }
            }
        }
        let recorder = Arc::new(Mutex::new(recorder));
        let record = |kind: EventKind| {
            if let Ok(mut recorder) = recorder.lock() {
                recorder.record(kind);
            }
        };

        // The proxy runs in this trusted parent process, which is the only
        // component that resolves names and opens outbound connections.  It is
        // itself a policy restriction, so observe mode does not install it.
        let proxy = if config.proxy_enabled && !observe {
            let rules = config.proxy_rules.clone().unwrap_or_default();
            let version = config.policy.as_ref().map_or(0, |policy| policy.version);
            match start_proxy(rules, version, Arc::clone(&recorder)) {
                Ok(listener) => Some(listener),
                Err(error) => {
                    eprintln!("easy-sandbox: {error}");
                    return SETUP_FAILED;
                }
            }
        } else {
            None
        };
        if config.proxy_enabled {
            record(EventKind::Restriction {
                layer: "proxy".to_string(),
                installed: proxy.is_some(),
                reason: if observe {
                    "observe-mode".to_string()
                } else {
                    "not-installed".to_string()
                },
            });
        }

        let executable = match std::env::current_exe().or_else(|error| {
            // Minimal initramfs environments may intentionally have no /proc.
            // An absolute argv[0] is enough to re-exec the launcher there.
            match std::env::args_os().next() {
                Some(argv0) => {
                    let path = PathBuf::from(argv0);
                    if path.is_absolute() {
                        Ok(path)
                    } else {
                        Err(error)
                    }
                }
                None => Err(error),
            }
        }) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("easy-sandbox: cannot locate launcher: {error}");
                return SETUP_FAILED;
            }
        };
        let mut command = Command::new(executable);
        command
            .arg("__child")
            .arg("--rootfs")
            .arg(&config.rootfs)
            .arg("--workspace")
            .arg(&config.workspace)
            .arg("--timeout-ms")
            .arg(config.timeout_ms.to_string());
        if let Some(memory_mib) = config.memory_mib {
            command.arg("--memory-mib").arg(memory_mib.to_string());
        } else {
            command.arg("--no-memory-limit");
        }
        if let Some(cpu_seconds) = config.cpu_seconds {
            command.arg("--cpu-seconds").arg(cpu_seconds.to_string());
        }
        if let Some(max_processes) = config.max_processes {
            command
                .arg("--max-processes")
                .arg(max_processes.to_string());
        }
        if config.secure {
            command.arg("--secure");
        }
        if let Some(policy) = &config.policy {
            // Freeze the validated document: the child must not re-read a file
            // that could have changed since validation.
            match policy.to_yaml_string() {
                Ok(frozen) => {
                    command.arg("--frozen-policy").arg(frozen);
                }
                Err(error) => {
                    eprintln!("easy-sandbox: {error}");
                    cleanup_proxy(proxy);
                    return SETUP_FAILED;
                }
            }
        }
        if let Some(listener) = &proxy {
            // The payload reaches the host-side proxy through this socket; it
            // is bind-mounted inside the sandbox at a fixed path.
            command.arg("--proxy-socket").arg(listener.path());
        }
        command.arg("--").args(&config.command);
        command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("HOME", "/workspace")
            .env("USER", "sandbox")
            .env("LANG", "C");
        if proxy.is_some() {
            // Only published when the socket really exists inside the sandbox.
            command.env(PROXY_ENV, SANDBOX_PROXY_PATH);
        }

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                eprintln!("easy-sandbox: cannot start supervisor: {error}");
                cleanup_proxy(proxy);
                return SETUP_FAILED;
            }
        };
        let started = Instant::now();
        let outcome = supervise(&mut child, config.timeout_ms);
        // The launcher only ever executes the payload after every layer is in
        // place: reaching the payload (anything but a setup failure) is the
        // evidence that the floor was installed, and 125 is the evidence that
        // it was not.  Observe mode never installs the policy's own layers.
        let started_ok = outcome.code != SETUP_FAILED;
        let reason = if started_ok {
            ""
        } else {
            "sandbox-failed-to-start"
        };
        if config.secure || config.policy.is_some() {
            record(restriction("p1-baseline", started_ok, reason));
        }
        if config.policy.is_some() {
            let layer_reason = if observe {
                "observe-mode"
            } else if !started_ok {
                reason
            } else {
                ""
            };
            record(restriction(
                "policy-landlock",
                started_ok && !observe,
                layer_reason,
            ));
            record(restriction(
                "policy-seccomp",
                started_ok && !observe,
                layer_reason,
            ));
        }
        record(EventKind::TaskResult {
            status: outcome.status.to_string(),
            exit_code: outcome.exit_code,
            duration_ms: started.elapsed().as_millis() as u64,
        });
        if let Ok(mut recorder) = recorder.lock() {
            recorder.close();
        }
        // The proxy socket file and its private directory do not outlive the run.
        cleanup_proxy(proxy);
        outcome.code
    }

    /// How a supervised run ended.
    struct Outcome {
        code: i32,
        status: &'static str,
        exit_code: Option<i32>,
    }

    fn restriction(layer: &str, installed: bool, reason: &str) -> EventKind {
        EventKind::Restriction {
            layer: layer.to_string(),
            installed,
            reason: reason.to_string(),
        }
    }

    /// Name of the effective mode for the record.
    fn mode_name(config: &RunConfig) -> &'static str {
        match &config.policy {
            Some(policy) => match policy.mode {
                PolicyMode::Enforce => "enforce",
                PolicyMode::Observe => "observe",
                PolicyMode::Verify => "verify",
            },
            None if config.secure => "baseline",
            None => "p0",
        }
    }

    /// Bind the P3 proxy listener from the frozen allowlist.
    fn start_proxy(
        rules: Vec<NetworkRule>,
        policy_version: u32,
        recorder: Arc<Mutex<Recorder>>,
    ) -> std::result::Result<Listener, String> {
        let dir = proxy::private_socket_dir("easy-sandbox-proxy")
            .map_err(|error| format!("proxy socket directory: {error}"))?;
        Listener::start(
            dir,
            format!("{}", std::process::id()),
            policy_version,
            rules,
            Some(recorder),
        )
        .map_err(|error| format!("proxy listener: {error}"))
    }

    fn cleanup_proxy(proxy: Option<Listener>) {
        if let Some(listener) = proxy {
            listener.cleanup();
        }
    }

    fn supervise(child: &mut Child, timeout_ms: u64) -> Outcome {
        let pid = child.id() as libc::pid_t;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let signal = status.signal();
                    return Outcome {
                        code: status
                            .code()
                            .or_else(|| signal.map(|signal| 128 + signal))
                            .unwrap_or(SETUP_FAILED),
                        status: if signal.is_some() {
                            "signalled"
                        } else {
                            "exited"
                        },
                        exit_code: status.code(),
                    };
                }
                Ok(None) if Instant::now() >= deadline => {
                    unsafe {
                        // The supervisor and the PID-namespace payload share this process group.
                        libc::kill(-pid, libc::SIGKILL);
                    }
                    let _ = child.wait();
                    eprintln!("easy-sandbox: timeout after {timeout_ms} ms");
                    return Outcome {
                        code: TIMEOUT,
                        status: "timeout",
                        exit_code: Some(TIMEOUT),
                    };
                }
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    eprintln!("easy-sandbox: wait failed: {error}");
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                    let _ = child.wait();
                    return Outcome {
                        code: SETUP_FAILED,
                        status: "wait-failed",
                        exit_code: Some(SETUP_FAILED),
                    };
                }
            }
        }
    }

    pub fn run_child(config: RunConfig) -> i32 {
        // Re-check the frozen document before any namespace exists, so an
        // unenforceable policy never leaves a partially built sandbox behind.
        if let Some(policy) = &config.policy {
            if let Err(error) = crate::policy::Plan::compile(policy) {
                eprintln!("easy-sandbox: policy-rejected: {error}");
                return SETUP_FAILED;
            }
        }
        let expected_parent = unsafe { libc::getppid() };
        if let Err(error) = set_parent_death_signal(expected_parent) {
            eprintln!("easy-sandbox: {error}");
            return SETUP_FAILED;
        }
        if let Err(error) = setup_namespaces_and_mounts(&config) {
            eprintln!("easy-sandbox: {error}");
            return SETUP_FAILED;
        }
        // Mapping UID/GID 0 is a credential transition and may clear an
        // earlier PDEATHSIG. Re-arm it after namespace setup while the
        // helper is still in the outer PID namespace.
        if let Err(error) = set_parent_death_signal(expected_parent) {
            eprintln!("easy-sandbox: {error}");
            return SETUP_FAILED;
        }

        // getppid() is 0 inside the child PID namespace even while its parent
        // is alive. A pipe closes that otherwise undetectable PDEATHSIG race.
        let mut lifetime = [0; 2];
        if unsafe { libc::pipe2(lifetime.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            eprintln!(
                "easy-sandbox: lifetime pipe: {}",
                io::Error::last_os_error()
            );
            return SETUP_FAILED;
        }
        let child = unsafe { libc::fork() };
        match child {
            -1 => {
                eprintln!("easy-sandbox: fork payload: {}", io::Error::last_os_error());
                SETUP_FAILED
            }
            0 => {
                unsafe {
                    libc::close(lifetime[1]);
                }
                // PDEATHSIG is cleared across fork, so set it again for PID 1.
                let parent = unsafe { libc::getppid() };
                if let Err(error) = set_parent_death_signal(parent) {
                    eprintln!("easy-sandbox: {error}");
                    unsafe { libc::_exit(SETUP_FAILED) }
                }
                let mut byte = 0u8;
                let n = unsafe { libc::read(lifetime[0], (&mut byte as *mut u8).cast(), 1) };
                if n != -1 || io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
                    unsafe { libc::_exit(SETUP_FAILED) }
                }
                unsafe {
                    libc::close(lifetime[0]);
                }
                namespace_init(&config)
            }
            init_pid => {
                unsafe {
                    libc::close(lifetime[0]);
                }
                let code = supervise_init(init_pid);
                unsafe {
                    libc::close(lifetime[1]);
                }
                code
            }
        }
    }

    fn namespace_init(config: &RunConfig) -> i32 {
        if let Err(error) = mount_proc_and_drop_privileges() {
            eprintln!("easy-sandbox: namespace init: {error}");
            unsafe { libc::_exit(SETUP_FAILED) }
        }
        // Keep this trusted PID 1 untraceable by the same-UID payload. It keeps
        // PDEATHSIG and its process group; payload setsid/prctl cannot alter it.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
            unsafe { libc::_exit(SETUP_FAILED) }
        }
        let child = unsafe { libc::fork() };
        if child == 0 {
            payload(config)
        } else if child < 0 {
            unsafe { libc::_exit(SETUP_FAILED) }
        } else {
            loop {
                let mut status = 0;
                let reaped = unsafe { libc::waitpid(-1, &mut status, 0) };
                if reaped == child {
                    let code = if libc::WIFEXITED(status) {
                        libc::WEXITSTATUS(status)
                    } else if libc::WIFSIGNALED(status) {
                        128 + libc::WTERMSIG(status)
                    } else {
                        SETUP_FAILED
                    };
                    // Exiting PID 1 kills every remaining process in this
                    // namespace, including detached sessions and double forks.
                    unsafe { libc::_exit(code) }
                }
                if reaped == -1 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    unsafe { libc::_exit(SETUP_FAILED) }
                }
            }
        }
    }

    fn validate_and_prepare(config: &mut RunConfig) -> Result<()> {
        if config.rootfs.as_os_str().is_empty() || config.workspace.as_os_str().is_empty() {
            return Err("rootfs and workspace must not be empty".to_string());
        }
        config.rootfs = fs::canonicalize(&config.rootfs)
            .map_err(|error| format!("rootfs is not a directory: {error}"))?;
        config.workspace = fs::canonicalize(&config.workspace)
            .map_err(|error| format!("workspace is not a directory: {error}"))?;
        if config.rootfs == Path::new("/") {
            return Err("rootfs must not be the host root directory".to_string());
        }
        if !config.rootfs.is_dir() {
            return Err("rootfs is not a directory".to_string());
        }
        if !config.workspace.is_dir() {
            return Err("workspace is not a directory".to_string());
        }
        if config.workspace == config.rootfs
            || config.workspace.starts_with(&config.rootfs)
            || config.rootfs.starts_with(&config.workspace)
        {
            return Err(
                "rootfs and workspace must be separate, non-nested directories".to_string(),
            );
        }

        // These mount points are created before the rootfs is made read-only.
        for relative in [".old_root", "workspace", "tmp", "proc", "dev"] {
            fs::create_dir_all(config.rootfs.join(relative))
                .map_err(|error| format!("create rootfs/{relative}: {error}"))?;
        }
        // Observe mode never installs the proxy, so it needs no mount point.
        let installs_proxy = config.proxy_enabled
            && !config
                .policy
                .as_ref()
                .is_some_and(|policy| policy.mode == PolicyMode::Observe);
        if installs_proxy {
            // Mount point for the host-side proxy socket.  The placeholder is
            // empty on the host side; the child bind-mounts the socket onto it.
            fs::create_dir_all(config.rootfs.join("run"))
                .map_err(|error| format!("create rootfs/run: {error}"))?;
            fs::File::create(config.rootfs.join("run/proxy.sock"))
                .map_err(|error| format!("create rootfs/run/proxy.sock: {error}"))?;
        }
        Ok(())
    }

    fn set_parent_death_signal(parent_pid: libc::pid_t) -> Result<()> {
        let result = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
        if result != 0 {
            return Err(last_error("set parent-death signal"));
        }
        if unsafe { libc::getppid() } != parent_pid {
            return Err("launcher parent exited during startup".to_string());
        }
        Ok(())
    }

    fn write_uid_gid_maps(uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
        // setgroups must be denied before an unprivileged gid_map write.
        let setgroups = Path::new("/proc/self/setgroups");
        if setgroups.exists() {
            fs::write(setgroups, b"deny\n").map_err(|error| format!("write setgroups: {error}"))?;
        }
        fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))
            .map_err(|error| format!("write uid_map: {error}"))?;
        fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))
            .map_err(|error| format!("write gid_map: {error}"))?;
        if unsafe { libc::setresgid(0, 0, 0) } != 0 {
            return Err(last_error("set namespace gid"));
        }
        if unsafe { libc::setresuid(0, 0, 0) } != 0 {
            return Err(last_error("set namespace uid"));
        }
        // setgroups is locked by gid_map setup. Launch from a dedicated
        // account without supplementary groups when those groups carry access.
        Ok(())
    }

    fn supervise_init(init_pid: libc::pid_t) -> i32 {
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(init_pid, &mut status, 0) };
            if result == init_pid {
                break;
            }
            if result == -1 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return SETUP_FAILED;
            }
        }
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            SETUP_FAILED
        }
    }

    fn payload(config: &RunConfig) -> i32 {
        if let Err(error) = apply_limits(config) {
            eprintln!("easy-sandbox: resource limit: {error}");
            unsafe { libc::_exit(SETUP_FAILED) }
        }
        let observe = config
            .policy
            .as_ref()
            .is_some_and(|policy| policy.mode == PolicyMode::Observe);

        // `--policy` implies the P1 baseline, and observe mode still pays for
        // it: the floor is never traded away, only the policy's own layers are
        // left out.  A proxy policy is the one case where the baseline itself
        // permits AF_UNIX sockets so the payload can reach the proxy socket.
        if config.secure || config.policy.is_some() {
            if let Err(error) = crate::policy::enforce_baseline(config.proxy_enabled && !observe) {
                eprintln!("easy-sandbox: enforcement-failed: {error}");
                unsafe { libc::_exit(SETUP_FAILED) }
            }
        }
        if let Some(policy) = &config.policy {
            // Observe mode records the policy's layers instead of installing
            // them; the parent writes that down once this process has finished.
            if !observe {
                if let Err(error) = crate::policy::enforce_policy(policy) {
                    eprintln!("easy-sandbox: enforcement-failed: {error}");
                    unsafe { libc::_exit(SETUP_FAILED) }
                }
            }
        }
        let mut argv = Vec::with_capacity(config.command.len() + 1);
        let mut strings = Vec::with_capacity(config.command.len());
        for argument in &config.command {
            match CString::new(argument.as_os_str().as_bytes()) {
                Ok(value) => strings.push(value),
                Err(_) => {
                    eprintln!("easy-sandbox: command contains NUL byte");
                    unsafe { libc::_exit(EXEC_FAILED) }
                }
            }
        }
        for argument in &strings {
            argv.push(argument.as_ptr());
        }
        argv.push(std::ptr::null());
        unsafe {
            libc::execvp(strings[0].as_ptr(), argv.as_ptr());
        }
        eprintln!(
            "easy-sandbox: exec {}: {}",
            config.command[0].to_string_lossy(),
            io::Error::last_os_error()
        );
        unsafe { libc::_exit(EXEC_FAILED) }
    }

    fn mount_proc_and_drop_privileges() -> Result<()> {
        // A minimal initramfs may already have procfs mounted so uid_map and
        // gid_map exist before the user namespace is created. Detach that
        // inherited view after entering our private mount namespace, then
        // mount a procfs instance scoped to the new PID namespace.
        let proc_path = cstr("/proc")?;
        unsafe {
            libc::umount2(proc_path.as_ptr(), libc::MNT_DETACH);
        }
        mount(
            Some(cstr("proc")?),
            Path::new("/proc"),
            Some(cstr("proc")?),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            None,
        )?;
        close_inherited_fds(3);
        set_no_new_privs()?;
        drop_capabilities()?;
        unsafe {
            libc::umask(0o077);
        }
        Ok(())
    }

    fn apply_limits(config: &RunConfig) -> Result<()> {
        if let Some(memory_mib) = config.memory_mib {
            let bytes = memory_mib
                .checked_mul(1024 * 1024)
                .ok_or_else(|| "memory limit overflows".to_string())?;
            set_limit(libc::RLIMIT_AS, bytes, "address space")?;
        }
        if let Some(cpu_seconds) = config.cpu_seconds {
            set_limit(libc::RLIMIT_CPU, cpu_seconds, "CPU time")?;
        }
        if let Some(max_processes) = config.max_processes {
            set_limit(libc::RLIMIT_NPROC, max_processes, "process count")?;
        }
        Ok(())
    }

    fn set_limit(resource: libc::__rlimit_resource_t, value: u64, label: &str) -> Result<()> {
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(format!("set {label}: {}", io::Error::last_os_error()));
        }
        Ok(())
    }

    fn set_no_new_privs() -> Result<()> {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(last_error("set no_new_privs"));
        }
        Ok(())
    }

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    fn drop_capabilities() -> Result<()> {
        for capability in 0..64 {
            unsafe {
                libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0);
            }
        }
        unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            );
        }
        let header = CapHeader {
            version: 0x2008_0522,
            pid: 0,
        };
        let data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        let result =
            unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
        if result != 0 {
            return Err(last_error("drop capabilities"));
        }
        Ok(())
    }

    fn close_inherited_fds(first: RawFd) {
        let result =
            unsafe { libc::syscall(libc::SYS_close_range, first as libc::c_uint, u32::MAX, 0u32) };
        if result == 0 {
            return;
        }
        if let Ok(entries) = fs::read_dir("/proc/self/fd") {
            for entry in entries.flatten() {
                if let Ok(fd) = entry.file_name().to_string_lossy().parse::<RawFd>() {
                    if fd >= first {
                        unsafe { libc::close(fd) };
                    }
                }
            }
        }
    }

    fn mount_proc_root(config: &RunConfig) -> Result<()> {
        let rootfs = &config.rootfs;
        mount(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )?;
        mount(Some(path_cstr(rootfs)?), rootfs, None, libc::MS_BIND, None)?;
        mount(
            None,
            rootfs,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )?;
        let workspace_target = rootfs.join("workspace");
        mount(
            Some(path_cstr(&config.workspace)?),
            &workspace_target,
            None,
            libc::MS_BIND,
            None,
        )?;
        mount(
            None,
            &workspace_target,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV,
            None,
        )?;
        if let Some(socket) = &config.proxy_socket {
            // The only network endpoint the payload can reach.
            mount(
                Some(path_cstr(socket)?),
                &rootfs.join("run/proxy.sock"),
                None,
                libc::MS_BIND,
                None,
            )?;
        }
        mount(
            Some(cstr("tmpfs")?),
            &rootfs.join("tmp"),
            Some(cstr("tmpfs")?),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some(cstr("size=64m,mode=1777")?),
        )?;
        mount(
            Some(cstr("tmpfs")?),
            &rootfs.join("dev"),
            Some(cstr("tmpfs")?),
            libc::MS_NOSUID | libc::MS_NOEXEC,
            Some(cstr("size=8m,mode=755")?),
        )?;
        bind_device_nodes(&rootfs.join("dev"))?;
        if unsafe { libc::chdir(path_cstr(rootfs)?.as_ptr()) } != 0 {
            return Err(last_error("chdir rootfs"));
        }
        let new_root = cstr(".")?;
        let old_root = cstr(".old_root")?;
        if unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), old_root.as_ptr()) } != 0
        {
            return Err(last_error("pivot_root"));
        }
        if unsafe { libc::chdir(cstr("/")?.as_ptr()) } != 0 {
            return Err(last_error("chdir new root"));
        }
        if unsafe { libc::umount2(cstr("/.old_root")?.as_ptr(), libc::MNT_DETACH) } != 0 {
            return Err(last_error("detach old root"));
        }
        let _ = fs::remove_dir("/.old_root");
        if unsafe { libc::chdir(cstr("/workspace")?.as_ptr()) } != 0 {
            return Err(last_error("chdir workspace"));
        }
        Ok(())
    }

    fn bind_device_nodes(dev_dir: &Path) -> Result<()> {
        for name in ["null", "zero", "urandom"] {
            let source = Path::new("/dev").join(name);
            let target = dev_dir.join(name);
            fs::File::create(&target)
                .map_err(|error| format!("create /dev/{name} mount point: {error}"))?;
            mount(
                Some(path_cstr(&source)?),
                &target,
                None,
                libc::MS_BIND,
                None,
            )?;
        }
        Ok(())
    }

    fn setup_namespaces_and_mounts(config: &RunConfig) -> Result<()> {
        let host_uid = unsafe { libc::getuid() };
        let host_gid = unsafe { libc::getgid() };
        if unsafe { libc::unshare(USER_NAMESPACE) } != 0 {
            return Err(last_error("unshare user namespace"));
        }
        write_uid_gid_maps(host_uid, host_gid)?;
        if unsafe { libc::unshare(ISOLATION_NAMESPACES) } != 0 {
            return Err(last_error("unshare mount/net/ipc/uts/pid namespaces"));
        }
        let hostname = cstr("easy-sandbox")?;
        if unsafe { libc::sethostname(hostname.as_ptr(), 12) } != 0 {
            return Err(last_error("set sandbox hostname"));
        }
        mount_proc_root(config)
    }

    fn mount(
        source: Option<CString>,
        target: &Path,
        filesystem: Option<CString>,
        flags: libc::c_ulong,
        data: Option<CString>,
    ) -> Result<()> {
        let target = path_cstr(target)?;
        let source = source
            .as_ref()
            .map_or(std::ptr::null(), |value| value.as_ptr());
        let filesystem = filesystem
            .as_ref()
            .map_or(std::ptr::null(), |value| value.as_ptr());
        let data = data.as_ref().map_or(std::ptr::null(), |value| {
            value.as_ptr() as *const libc::c_void
        });
        if unsafe { libc::mount(source, target.as_ptr(), filesystem, flags, data) } != 0 {
            return Err(last_error(&format!("mount {}", target.to_string_lossy())));
        }
        Ok(())
    }

    fn cstr(value: &str) -> Result<CString> {
        CString::new(value).map_err(|_| format!("invalid NUL in {value:?}"))
    }

    fn path_cstr(path: &Path) -> Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("path contains NUL: {}", path.display()))
    }

    fn last_error(context: &str) -> String {
        format!("{context}: {}", io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    use super::RunConfig;

    pub fn run_parent(_config: RunConfig) -> i32 {
        eprintln!("easy-sandbox: this prototype requires Linux");
        125
    }

    pub fn run_child(_config: RunConfig) -> i32 {
        eprintln!("easy-sandbox: this prototype requires Linux");
        125
    }
}

fn main() {
    let mode = match parse_args() {
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("easy-sandbox: {error}");
            usage();
            process::exit(64);
        }
    };
    let code = match mode {
        Mode::Verify(args) => run_verify(&args),
        Mode::Run {
            options,
            policy_path,
        } => {
            // An unreadable, invalid, or unenforceable policy is a setup
            // failure: the payload never runs.
            let policy = match load_policy(policy_path.as_ref()) {
                Ok(policy) => policy,
                Err(error) => {
                    eprintln!("easy-sandbox: {error}");
                    process::exit(125);
                }
            };
            let config = match options.resolve(policy.as_ref()) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("easy-sandbox: {error}");
                    usage();
                    process::exit(64);
                }
            };
            linux::run_parent(config)
        }
        Mode::Child {
            options,
            frozen_policy,
        } => {
            let policy = match frozen_policy
                .as_deref()
                .map(Policy::from_yaml_str)
                .transpose()
            {
                Ok(policy) => policy,
                Err(error) => {
                    eprintln!("easy-sandbox: {error}");
                    process::exit(125);
                }
            };
            let config = match options.resolve(policy.as_ref()) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("easy-sandbox: {error}");
                    process::exit(125);
                }
            };
            linux::run_child(config)
        }
    };
    process::exit(code);
}
