//! P1 baseline and P2 policy enforcement.
//!
//! Two layers exist and both are one-way:
//!
//! * [`enforce_baseline`] installs the static P1 rules that `--secure` promises.
//! * [`enforce_policy`] compiles a validated YAML policy into extra Landlock and
//!   seccomp restrictions and installs them after (and on top of) the baseline.
//!
//! The layers cannot be combined into something more permissive: Landlock
//! rulesets stack as intersecting layers and seccomp filters only add denied
//! entry points, so a policy can restrict further but never widen what P0/P1
//! already promised.  Everything fails closed: an unsupported Landlock ABI, an
//! unknown syscall name, or a path that does not exist inside the sandbox
//! aborts before the payload runs.
//!
//! There is exactly one deliberate relaxation, and only `network.mode: proxy`
//! asks for it: the P1 baseline itself stops denying every socket syscall and
//! denies only the domains other than `AF_UNIX`.  The payload can then reach
//! the host-side proxy socket and nothing else -- the sandbox network namespace
//! has no route out, and `AF_INET`/`AF_INET6` sockets cannot be created at all.
//! With `network.mode: disabled` the P1 socket denial is unchanged.
//!
//! A Landlock rule applies to the path it names and to everything beneath it,
//! and path traversal inside that subtree needs no separate grant (verified on
//! Landlock ABI 1: a rule on `/tmp/x/dir` is enough to read `dir/sub/file`
//! while an unlisted ancestor stays unlistable).  The policy layer therefore
//! adds exactly one rule per listed path, and nothing outside those paths can
//! be read, listed, or executed.

use std::path::PathBuf;

use easy_sandbox::config::{NetworkMode, NetworkRule, Policy, PolicyMode};

/// Device nodes that P0 always keeps usable.  A policy cannot withdraw them:
/// they carry no data and P0 promises them, so removing them would only make
/// otherwise valid payloads fail.  Only the Linux layer can enforce this, so
/// other targets treat the list as unused.
#[allow(dead_code)]
const DEVICE_NODES: [&str; 3] = ["/dev/null", "/dev/zero", "/dev/urandom"];

/// A validated policy compiled into enforceable primitives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Paths inside the sandbox that the payload may read and execute.
    pub read_paths: Vec<PathBuf>,
    /// Paths inside the sandbox that the payload may create, modify, or remove.
    pub write_paths: Vec<PathBuf>,
    /// Syscall numbers resolved from `syscalls.deny`.
    pub denied_syscalls: Vec<i64>,
    /// Frozen allowlist for the P3 host-side proxy, or `None` when the policy
    /// asks for `network.mode: disabled`.
    pub proxy_rules: Option<Vec<NetworkRule>>,
    /// Declared mode: `enforce` installs the layers, `observe` records them
    /// without installing them.
    pub mode: PolicyMode,
}

impl Plan {
    /// Compile a validated policy, or explain why it cannot be enforced.
    ///
    /// The policy document itself is already strictly validated by
    /// [`Policy::validate`]; this step rejects the mode that is not a run mode
    /// at all and resolves syscall names to numbers.  Unknown syscall names are
    /// an error, never a silent no-op.
    pub fn compile(policy: &Policy) -> Result<Self, String> {
        if policy.mode == PolicyMode::Verify {
            return Err(
                "policy mode Verify drives `easy-sandbox verify --cases FILE`, not a run"
                    .to_string(),
            );
        }
        // Strict validation has already paired proxy mode with a valid
        // allowlist and disabled mode with an empty one.
        let proxy_rules = match policy.network.mode {
            NetworkMode::Disabled => None,
            NetworkMode::Proxy => Some(policy.network.allow.clone()),
        };

        let mut denied_syscalls = Vec::with_capacity(policy.syscalls.deny.len());
        for name in &policy.syscalls.deny {
            denied_syscalls.push(
                resolve_syscall(name)
                    .map_err(|error| format!("syscalls.deny {name:?}: {error}"))?,
            );
        }

        Ok(Self {
            read_paths: policy.filesystem.read.iter().map(PathBuf::from).collect(),
            write_paths: policy.filesystem.write.iter().map(PathBuf::from).collect(),
            denied_syscalls,
            proxy_rules,
            mode: policy.mode,
        })
    }
}

/// Install the P1 baseline for the current process.
///
/// `allow_unix_sockets` is set only by `network.mode: proxy`: it turns "deny
/// every socket syscall" into "deny every domain except `AF_UNIX`".
///
/// Only the Linux child calls the enforcement behind this; other targets keep
/// the module compiling so the CLI and the schema stay checkable everywhere.
#[allow(dead_code)]
pub fn enforce_baseline(allow_unix_sockets: bool) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        linux::enforce_baseline(allow_unix_sockets)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = allow_unix_sockets;
        Err("P1 baseline enforcement is only available on Linux".to_string())
    }
}

/// Install the rules of a validated policy for the current process.
///
/// The caller must have installed the baseline first; the P2 layer is purely
/// additive.
#[allow(dead_code)]
pub fn enforce_policy(policy: &Policy) -> Result<(), String> {
    let plan = Plan::compile(policy)?;
    #[cfg(target_os = "linux")]
    {
        linux::enforce_policy(&plan)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = &plan;
        Err("P2 policy enforcement is only available on Linux".to_string())
    }
}

/// Resolve a policy syscall name to its kernel number.
fn resolve_syscall(name: &str) -> Result<i64, String> {
    #[cfg(target_os = "linux")]
    {
        linux::resolve_syscall(name)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(format!("syscall {name:?} can only be resolved on Linux"))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::convert::TryInto;
    use std::path::Path;

    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, RestrictionStatus,
        Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    };
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, apply_filter,
    };

    use super::{DEVICE_NODES, Plan};

    /// Landlock ABI 3 is required because it is the first ABI that mediates
    /// truncate/ftruncate/O_TRUNC.  Without it, a read-only path rule can be
    /// bypassed by truncating an already-open file.
    const REQUIRED_ABI: ABI = ABI::V3;

    fn hard_requirement() -> CompatLevel {
        CompatLevel::HardRequirement
    }

    /// Resolve a policy syscall name.
    ///
    /// Only names in this table are accepted.  A typo must fail the run instead
    /// of silently leaving the syscall allowed.
    pub fn resolve_syscall(name: &str) -> Result<i64, String> {
        let number = match name {
            "mount" => libc::SYS_mount,
            "umount2" => libc::SYS_umount2,
            "pivot_root" => libc::SYS_pivot_root,
            "unshare" => libc::SYS_unshare,
            "setns" => libc::SYS_setns,
            "clone" => libc::SYS_clone,
            "clone3" => libc::SYS_clone3,
            "open_tree" => libc::SYS_open_tree,
            "move_mount" => libc::SYS_move_mount,
            "fsopen" => libc::SYS_fsopen,
            "fsconfig" => libc::SYS_fsconfig,
            "fsmount" => libc::SYS_fsmount,
            "fspick" => libc::SYS_fspick,
            "mount_setattr" => libc::SYS_mount_setattr,
            "ptrace" => libc::SYS_ptrace,
            "process_vm_readv" => libc::SYS_process_vm_readv,
            "process_vm_writev" => libc::SYS_process_vm_writev,
            "pidfd_getfd" => libc::SYS_pidfd_getfd,
            "pidfd_send_signal" => libc::SYS_pidfd_send_signal,
            "process_madvise" => libc::SYS_process_madvise,
            "bpf" => libc::SYS_bpf,
            "keyctl" => libc::SYS_keyctl,
            "add_key" => libc::SYS_add_key,
            "request_key" => libc::SYS_request_key,
            "userfaultfd" => libc::SYS_userfaultfd,
            "io_uring_setup" => libc::SYS_io_uring_setup,
            "io_uring_enter" => libc::SYS_io_uring_enter,
            "io_uring_register" => libc::SYS_io_uring_register,
            "perf_event_open" => libc::SYS_perf_event_open,
            "kcmp" => libc::SYS_kcmp,
            "socket" => libc::SYS_socket,
            "socketpair" => libc::SYS_socketpair,
            "connect" => libc::SYS_connect,
            "execve" => libc::SYS_execve,
            "execveat" => libc::SYS_execveat,
            "chmod" => libc::SYS_chmod,
            "fchmod" => libc::SYS_fchmod,
            "chown" => libc::SYS_chown,
            "fchown" => libc::SYS_fchown,
            "lchown" => libc::SYS_lchown,
            "kill" => libc::SYS_kill,
            "tkill" => libc::SYS_tkill,
            "tgkill" => libc::SYS_tgkill,
            "prctl" => libc::SYS_prctl,
            "seccomp" => libc::SYS_seccomp,
            "reboot" => libc::SYS_reboot,
            "kexec_load" => libc::SYS_kexec_load,
            "init_module" => libc::SYS_init_module,
            "finit_module" => libc::SYS_finit_module,
            "delete_module" => libc::SYS_delete_module,
            "swapon" => libc::SYS_swapon,
            "swapoff" => libc::SYS_swapoff,
            "acct" => libc::SYS_acct,
            "settimeofday" => libc::SYS_settimeofday,
            "clock_settime" => libc::SYS_clock_settime,
            "adjtimex" => libc::SYS_adjtimex,
            "fanotify_init" => libc::SYS_fanotify_init,
            "uname" => libc::SYS_uname,
            "sysinfo" => libc::SYS_sysinfo,
            "sethostname" => libc::SYS_sethostname,
            "setdomainname" => libc::SYS_setdomainname,
            "personality" => libc::SYS_personality,
            "quotactl" => libc::SYS_quotactl,
            "kexec_file_load" => libc::SYS_kexec_file_load,
            _ => return Err(format!("unsupported syscall name: {name:?}")),
        };
        Ok(number as i64)
    }

    fn open_path(path: &Path) -> Result<PathFd, String> {
        PathFd::new(path).map_err(|error| format!("landlock open {}: {error}", path.display()))
    }

    fn apply_ruleset(status: RestrictionStatus, layer: &str) -> Result<(), String> {
        if status.ruleset != RulesetStatus::FullyEnforced {
            return Err(format!(
                "{layer} was not fully enforced: {:?}",
                status.ruleset
            ));
        }
        Ok(())
    }

    /// P1: rootfs readable and executable, workspace and tmp writable, three
    /// minimal device nodes.
    fn enforce_baseline_landlock() -> Result<(), String> {
        let abi = REQUIRED_ABI;
        let all = AccessFs::from_all(abi);
        let read = AccessFs::from_read(abi);
        let device_rw = AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate;

        let created = Ruleset::default()
            .set_compatibility(hard_requirement())
            .handle_access(all)
            .map_err(|error| format!("Landlock ABI 3+ is required: {error}"))?
            .create()
            .map_err(|error| format!("landlock create: {error}"))?
            .add_rule(PathBeneath::new(open_path(Path::new("/"))?, read))
            .map_err(|error| format!("landlock allow root read: {error}"))?
            .add_rule(PathBeneath::new(open_path(Path::new("/workspace"))?, all))
            .map_err(|error| format!("landlock allow workspace: {error}"))?
            .add_rule(PathBeneath::new(open_path(Path::new("/tmp"))?, all))
            .map_err(|error| format!("landlock allow tmp: {error}"))?
            .add_rule(PathBeneath::new(
                open_path(Path::new("/dev/null"))?,
                device_rw,
            ))
            .map_err(|error| format!("landlock allow /dev/null: {error}"))?
            .add_rule(PathBeneath::new(
                open_path(Path::new("/dev/zero"))?,
                device_rw,
            ))
            .map_err(|error| format!("landlock allow /dev/zero: {error}"))?
            .add_rule(PathBeneath::new(
                open_path(Path::new("/dev/urandom"))?,
                device_rw,
            ))
            .map_err(|error| format!("landlock allow /dev/urandom: {error}"))?
            .restrict_self()
            .map_err(|error| format!("landlock restrict_self: {error}"))?;

        apply_ruleset(created, "the P1 landlock baseline")
    }

    /// A rule that matches every domain but `AF_UNIX`.
    ///
    /// seccomp cannot inspect the sockaddr a payload passes to connect(2), so
    /// the boundary is drawn at socket creation: a payload may only ever hold
    /// `AF_UNIX` sockets, and the sandbox network namespace has no route out.
    fn deny_non_unix_domain() -> Result<Vec<SeccompRule>, String> {
        Ok(vec![
            SeccompRule::new(vec![
                SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Ne,
                    libc::AF_UNIX as u64,
                )
                .map_err(|error| format!("seccomp socket domain condition: {error}"))?,
            ])
            .map_err(|error| format!("seccomp socket domain rule: {error}"))?,
        ])
    }

    fn unconditional_rules(
        allow_unix_sockets: bool,
    ) -> Result<BTreeMap<i64, Vec<SeccompRule>>, String> {
        let mut rules = BTreeMap::new();
        // Namespace and kernel attack-surface syscalls.  mount(2) and
        // pivot_root(2) are also blocked even though the mount namespace is
        // already private: this prevents an untrusted command from changing
        // the topology after policy installation.
        for syscall in [
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_open_tree,
            libc::SYS_move_mount,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_fspick,
            libc::SYS_mount_setattr,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_bpf,
            libc::SYS_keyctl,
            libc::SYS_userfaultfd,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            rules.insert(syscall as i64, Vec::new());
        }
        // The P3 proxy is the only reason a payload holds a socket at all.
        let socket_rule = if allow_unix_sockets {
            deny_non_unix_domain()?
        } else {
            Vec::new()
        };
        rules.insert(libc::SYS_socket as i64, socket_rule.clone());
        rules.insert(libc::SYS_socketpair as i64, socket_rule);
        Ok(rules)
    }

    fn add_clone_namespace_rules(
        rules: &mut BTreeMap<i64, Vec<SeccompRule>>,
    ) -> Result<(), String> {
        let flags = [
            libc::CLONE_NEWNS,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWNET,
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWCGROUP,
        ];
        let mut conditions = Vec::new();
        for flag in flags {
            conditions.push(
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::MaskedEq(flag as u64),
                        flag as u64,
                    )
                    .map_err(|error| format!("seccomp clone condition: {error}"))?,
                ])
                .map_err(|error| format!("seccomp clone rule: {error}"))?,
            );
        }
        rules.insert(libc::SYS_clone as i64, conditions);
        Ok(())
    }

    fn target_arch() -> Result<seccompiler::TargetArch, String> {
        std::env::consts::ARCH
            .try_into()
            .map_err(|error| format!("seccomp target architecture: {error}"))
    }

    fn build_filter(
        rules: BTreeMap<i64, Vec<SeccompRule>>,
        error: u32,
        layer: &str,
    ) -> Result<(), String> {
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(error),
            target_arch()?,
        )
        .map_err(|error| format!("seccomp {layer} build: {error}"))?;
        let program: BpfProgram = filter
            .try_into()
            .map_err(|error| format!("seccomp {layer} compile: {error}"))?;
        apply_filter(&program).map_err(|error| format!("seccomp {layer} install: {error}"))
    }

    fn enforce_baseline_seccomp(allow_unix_sockets: bool) -> Result<(), String> {
        install_x32_guard()?;

        // glibc falls back to clone(2) when clone3(2) returns ENOSYS.  Install
        // this tiny filter separately because seccompiler's match action is
        // global to one filter; the rest of the deny list returns EPERM.
        let clone3 = [(libc::SYS_clone3 as i64, Vec::new())]
            .into_iter()
            .collect();
        build_filter(clone3, libc::ENOSYS as u32, "clone3")?;

        let mut rules = unconditional_rules(allow_unix_sockets)?;
        add_clone_namespace_rules(&mut rules)?;
        build_filter(rules, libc::EPERM as u32, "baseline")
    }

    /// P2: landlock layer driven by the policy's filesystem lists.
    ///
    /// Only the listed paths (plus the fixed device nodes) are granted; a
    /// listed directory also covers traversal inside it.
    fn enforce_policy_landlock(plan: &Plan) -> Result<(), String> {
        let abi = REQUIRED_ABI;
        let all = AccessFs::from_all(abi);
        let read = AccessFs::from_read(abi);
        let device_rw = AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate;

        let mut created = Ruleset::default()
            .set_compatibility(hard_requirement())
            .handle_access(all)
            .map_err(|error| format!("Landlock ABI 3+ is required: {error}"))?
            .create()
            .map_err(|error| format!("landlock create: {error}"))?;

        for path in &plan.read_paths {
            created = created
                .add_rule(PathBeneath::new(open_path(path)?, read))
                .map_err(|error| format!("landlock allow read {}: {error}", path.display()))?;
        }
        for path in &plan.write_paths {
            created = created
                .add_rule(PathBeneath::new(open_path(path)?, all))
                .map_err(|error| format!("landlock allow write {}: {error}", path.display()))?;
        }
        for device in DEVICE_NODES {
            created = created
                .add_rule(PathBeneath::new(open_path(Path::new(device))?, device_rw))
                .map_err(|error| format!("landlock allow {device}: {error}"))?;
        }

        let status = created
            .restrict_self()
            .map_err(|error| format!("landlock restrict_self: {error}"))?;
        apply_ruleset(status, "the P2 landlock policy layer")
    }

    /// P2: deny every syscall the policy lists, in addition to the baseline.
    fn enforce_policy_seccomp(plan: &Plan) -> Result<(), String> {
        if plan.denied_syscalls.is_empty() {
            return Ok(());
        }
        let rules: BTreeMap<i64, Vec<SeccompRule>> = plan
            .denied_syscalls
            .iter()
            .map(|number| (*number, Vec::new()))
            .collect();
        build_filter(rules, libc::EPERM as u32, "policy")
    }

    pub fn enforce_baseline(allow_unix_sockets: bool) -> Result<(), String> {
        enforce_baseline_landlock()?;
        enforce_baseline_seccomp(allow_unix_sockets)
    }

    pub fn enforce_policy(plan: &Plan) -> Result<(), String> {
        enforce_policy_landlock(plan)?;
        enforce_policy_seccomp(plan)
    }

    // seccompiler validates the audit architecture, but x86-64 also accepts
    // the x32 ABI under the same AUDIT_ARCH_X86_64 value.  Its syscall numbers
    // carry __X32_SYSCALL_BIT and would otherwise miss our normal rules and
    // fall through to the allow action.  Install a six-instruction guard
    // before the generated filters.  Other architectures have no x32 ABI.
    #[cfg(target_arch = "x86_64")]
    fn install_x32_guard() -> Result<(), String> {
        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_JMP_JEQ_K: u16 = 0x15;
        const BPF_JMP_JSET_K: u16 = 0x45;
        const BPF_RET_K: u16 = 0x06;
        const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
        const X32_SYSCALL_BIT: u32 = 0x4000_0000;

        let mut program = [
            libc::sock_filter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 4,
            },
            libc::sock_filter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 3,
                k: AUDIT_ARCH_X86_64,
            },
            libc::sock_filter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: BPF_JMP_JSET_K,
                jt: 1,
                jf: 0,
                k: X32_SYSCALL_BIT,
            },
            libc::sock_filter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
            libc::sock_filter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_KILL_PROCESS,
            },
        ];
        let filter = libc::sock_fprog {
            len: program.len() as libc::c_ushort,
            filter: program.as_mut_ptr(),
        };
        let result = unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &filter as *const libc::sock_fprog,
                0,
                0,
            )
        };
        if result != 0 {
            return Err(format!(
                "seccomp x32 guard install: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn install_x32_guard() -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(source: &str) -> Policy {
        Policy::from_yaml_str(source).expect("valid policy document")
    }

    const SIMPLE: &str = r#"
version: 1
filesystem:
  read: ["/bin", "/lib"]
  write: ["/workspace"]
network:
  mode: disabled
  allow: []
limits:
  timeout_ms: 30000
syscalls:
  deny: [mount, ptrace]
mode: enforce
"#;

    #[cfg(target_os = "linux")]
    #[test]
    fn compiles_paths_and_denied_syscalls() {
        let plan = Plan::compile(&policy(SIMPLE)).expect("compiles");
        assert_eq!(
            plan.read_paths,
            vec![PathBuf::from("/bin"), PathBuf::from("/lib")]
        );
        assert_eq!(plan.write_paths, vec![PathBuf::from("/workspace")]);
        assert_eq!(plan.denied_syscalls.len(), 2);
    }

    #[test]
    fn observe_compiles_without_being_enforced() {
        let source = SIMPLE
            .replace("mode: enforce", "mode: observe")
            .replace("deny: [mount, ptrace]", "deny: []");
        let plan = Plan::compile(&policy(&source)).expect("observe compiles");
        assert_eq!(plan.mode, PolicyMode::Observe);

        let enforce = SIMPLE.replace("deny: [mount, ptrace]", "deny: []");
        assert_eq!(
            Plan::compile(&policy(&enforce)).expect("compiles").mode,
            PolicyMode::Enforce
        );
    }

    #[test]
    fn verify_is_not_a_run_mode() {
        let source = SIMPLE.replace("mode: enforce", "mode: verify");
        let error = Plan::compile(&policy(&source)).expect_err("verify is not a run mode");
        assert!(error.contains("verify --cases"), "{error}");
    }

    #[test]
    fn proxy_mode_compiles_into_a_frozen_allowlist() {
        let source = SIMPLE
            .replace(
                "  mode: disabled\n  allow: []",
                "  mode: proxy\n  allow:\n    - host: api.example.com\n      ports: [443, 8443]",
            )
            .replace("deny: [mount, ptrace]", "deny: []");
        let plan = Plan::compile(&policy(&source)).expect("proxy mode compiles");
        let rules = plan.proxy_rules.expect("allowlist");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].host, "api.example.com");
        assert_eq!(rules[0].ports, vec![443, 8443]);
    }

    #[test]
    fn disabled_network_carries_no_proxy_rules() {
        let source = SIMPLE.replace("deny: [mount, ptrace]", "deny: []");
        let plan = Plan::compile(&policy(&source)).expect("compiles");
        assert!(plan.proxy_rules.is_none());
    }

    #[test]
    fn empty_policy_is_valid_and_denies_everything() {
        let source = SIMPLE
            .replace("read: [\"/bin\", \"/lib\"]", "read: []")
            .replace("write: [\"/workspace\"]", "write: []")
            .replace("deny: [mount, ptrace]", "deny: []");
        let plan = Plan::compile(&policy(&source)).expect("compiles");
        assert!(plan.read_paths.is_empty());
        assert!(plan.write_paths.is_empty());
        assert!(plan.denied_syscalls.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolves_known_syscall_names_and_rejects_unknown_ones() {
        assert_eq!(resolve_syscall("mount").unwrap(), libc::SYS_mount as i64);
        assert_eq!(resolve_syscall("ptrace").unwrap(), libc::SYS_ptrace as i64);
        assert!(
            resolve_syscall("not_a_syscall")
                .unwrap_err()
                .contains("unsupported syscall name")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unknown_syscall_name_fails_the_whole_policy() {
        let source = SIMPLE.replace("deny: [mount, ptrace]", "deny: [mount, not_a_syscall]");
        let error = Plan::compile(&policy(&source)).expect_err("unknown name must fail closed");
        assert!(error.contains("not_a_syscall"), "{error}");
    }
}
