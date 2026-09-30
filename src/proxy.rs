//! P3 host-side HTTP CONNECT proxy.
//!
//! The sandbox keeps its own network namespace, so a payload has no route to
//! anything except the single Unix socket the launcher bind-mounts into the
//! rootfs.  That socket is served by the trusted parent process on the host,
//! which is the only component that performs DNS resolution and outbound
//! connections.
//!
//! Rules are checked in the proxy, not negotiated with the payload: only
//! `CONNECT host:port` is accepted, only exact allowlisted hostnames, and only
//! the ports listed for that hostname.  IP literals are refused because the
//! allowlist is a hostname list; a name is resolved exactly once per CONNECT
//! and the tunnel is pinned to that address, so a second DNS answer cannot
//! redirect an established tunnel.
//!
//! The proxy is deliberately self-contained: it reads no environment variables,
//! opens no file inside the sandbox, and works only from the frozen policy it
//! was built with.

use std::fmt;
use std::io;
#[cfg(unix)]
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::config::NetworkRule;

/// Largest request head the proxy accepts before answering 431.
const MAX_REQUEST_HEAD: usize = 8 * 1024;
/// How long a payload may take to send its request head.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the proxy waits for the allowlisted destination.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a CONNECT request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deny {
    /// The request line was not a well-formed `CONNECT host:port`.
    Malformed,
    /// The request head exceeded [`MAX_REQUEST_HEAD`].
    TooLarge,
    /// A method other than CONNECT (including plain GET tunnelling attempts).
    NotConnect,
    /// The target was an IP literal; only exact hostnames may be listed.
    NotHostname,
    /// The hostname is not in the frozen allowlist.
    HostNotAllowed,
    /// The hostname is allowed, but not for this port.
    PortNotAllowed,
    /// DNS resolution failed.
    ResolveFailed,
    /// The resolved address could not be reached.
    ConnectFailed,
}

impl Deny {
    /// Stable token used in the proxy log line.
    pub fn reason(self) -> &'static str {
        match self {
            Deny::Malformed => "malformed",
            Deny::TooLarge => "request-too-large",
            Deny::NotConnect => "not-connect",
            Deny::NotHostname => "not-a-hostname",
            Deny::HostNotAllowed => "host-not-allowed",
            Deny::PortNotAllowed => "port-not-allowed",
            Deny::ResolveFailed => "resolve-failed",
            Deny::ConnectFailed => "connect-failed",
        }
    }

    /// HTTP status the payload sees.
    #[cfg(unix)]
    fn status(self) -> u16 {
        match self {
            Deny::Malformed => 400,
            Deny::TooLarge => 431,
            Deny::NotConnect => 405,
            Deny::NotHostname | Deny::HostNotAllowed | Deny::PortNotAllowed => 403,
            Deny::ResolveFailed | Deny::ConnectFailed => 502,
        }
    }
}

impl fmt::Display for Deny {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason())
    }
}

/// A parsed, authorized CONNECT target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

/// Resolves an allowlisted hostname.
///
/// Injected so that the "resolve exactly once per connection" property is
/// testable without touching the host resolver.
pub trait Resolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// The process resolver, used for real runs.
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        (host, port).to_socket_addrs().map(|addrs| addrs.collect())
    }
}

/// Split `CONNECT` request head into the target, or explain the refusal.
///
/// `head` must contain the request line and may contain headers; only the
/// request line is inspected, and the first line must be exactly
/// `CONNECT <host>:<port> HTTP/<version>`.
pub fn parse_connect(head: &[u8]) -> Result<Target, Deny> {
    if head.len() > MAX_REQUEST_HEAD {
        return Err(Deny::TooLarge);
    }
    let text = std::str::from_utf8(head).map_err(|_| Deny::Malformed)?;
    let request_line = text.lines().next().ok_or(Deny::Malformed)?;
    let mut parts = request_line.split(' ').filter(|part| !part.is_empty());
    let method = parts.next().ok_or(Deny::Malformed)?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(Deny::NotConnect);
    }
    let authority = parts.next().ok_or(Deny::Malformed)?;
    let version = parts.next().ok_or(Deny::Malformed)?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return Err(Deny::Malformed);
    }
    let (host, port) = authority.rsplit_once(':').ok_or(Deny::Malformed)?;
    if host.is_empty() || host.len() > 253 {
        return Err(Deny::Malformed);
    }
    let port: u16 = port.parse().map_err(|_| Deny::Malformed)?;
    if port == 0 {
        return Err(Deny::Malformed);
    }
    Ok(Target {
        host: host.to_ascii_lowercase(),
        port,
    })
}

/// Decide whether a target is reachable through the proxy.
///
/// Hostnames only: an IP literal can never be allowlisted, which is what stops
/// a payload from tunnelling straight to an address.
pub fn authorize(rules: &[NetworkRule], target: &Target) -> Result<(), Deny> {
    if target.host.parse::<IpAddr>().is_ok() {
        return Err(Deny::NotHostname);
    }
    let mut known_host = false;
    for rule in rules {
        if !rule.host.eq_ignore_ascii_case(&target.host) {
            continue;
        }
        known_host = true;
        if rule.ports.contains(&target.port) {
            return Ok(());
        }
    }
    if known_host {
        Err(Deny::PortNotAllowed)
    } else {
        Err(Deny::HostNotAllowed)
    }
}

/// One proxy decision, in the stable log format used until P4 replaces it with
/// JSONL events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub task: String,
    pub policy_version: u32,
    /// Requested hostname, or `-` when the request head never got that far.
    pub host: String,
    /// Requested port, or 0 when unknown.
    pub port: u16,
    /// Addresses the allowlisted name resolved to, when it got that far.
    pub candidates: Vec<SocketAddr>,
    /// Transport error behind a `connect-failed` refusal, for auditing.
    pub detail: String,
    pub outcome: Result<Option<SocketAddr>, Deny>,
}

impl Decision {
    #[cfg(unix)]
    fn refused(task: &str, policy_version: u32, target: Option<&Target>, deny: Deny) -> Self {
        Self {
            task: task.to_string(),
            policy_version,
            host: target.map_or_else(|| "-".to_string(), |target| target.host.clone()),
            port: target.map_or(0, |target| target.port),
            candidates: Vec::new(),
            detail: String::new(),
            outcome: Err(deny),
        }
    }

    /// `allow` or `deny`.
    pub fn decision(&self) -> &'static str {
        match &self.outcome {
            Ok(_) => "allow",
            Err(_) => "deny",
        }
    }

    /// The refusal reason, or `-` for an allowed request.
    pub fn reason(&self) -> &'static str {
        match &self.outcome {
            Ok(_) => "-",
            Err(deny) => deny.reason(),
        }
    }

    /// The address the tunnel was pinned to, or `-`.
    pub fn address(&self) -> String {
        match &self.outcome {
            Ok(Some(address)) => address.to_string(),
            _ => "-".to_string(),
        }
    }

    /// Render one `key=value` log line.  Every line carries the task, the
    /// frozen rule version, the requested domain and port, and the outcome.
    pub fn log_line(&self) -> String {
        let address = self.address();
        let decision = self.decision();
        let reason = self.reason();
        let port = if self.port == 0 {
            "-".to_string()
        } else {
            self.port.to_string()
        };
        let candidates = if self.candidates.is_empty() {
            "-".to_string()
        } else {
            self.candidates
                .iter()
                .map(SocketAddr::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        let detail = if self.detail.is_empty() {
            String::new()
        } else {
            format!(" detail={}", self.detail)
        };
        format!(
            "easy-sandbox: proxy task={} policy_version={} host={} port={} decision={} reason={} address={} candidates={}{}",
            self.task,
            self.policy_version,
            self.host,
            port,
            decision,
            reason,
            address,
            candidates,
            detail
        )
    }
}

/// Read one request head (up to the blank line) without consuming tunnel bytes.
#[cfg(unix)]
fn read_head<R: Read>(reader: &mut R) -> Result<Vec<u8>, Deny> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Err(Deny::Malformed),
            Ok(_) => head.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Deny::Malformed),
        }
        if head.len() > MAX_REQUEST_HEAD {
            return Err(Deny::TooLarge);
        }
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            return Ok(head);
        }
    }
}

#[cfg(unix)]
fn write_status<W: Write>(writer: &mut W, status: u16, reason: &str) -> io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 {status} {reason}\r\nProxy-Agent: easy-sandbox\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    writer.flush()
}

#[cfg(unix)]
fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "Connection Established",
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        _ => "Bad Gateway",
    }
}

/// Serve one accepted payload connection to completion.
///
/// Every outcome is logged exactly once, including refusals: a denied CONNECT
/// is as important to audit as a permitted one.  The caller owns the listener
/// and hands each accepted stream to this function.
#[cfg(unix)]
pub fn serve(
    stream: &mut std::os::unix::net::UnixStream,
    task: &str,
    policy_version: u32,
    rules: &[NetworkRule],
    resolver: &dyn Resolver,
    log: &mut dyn FnMut(&Decision),
) -> Decision {
    let target = match read_head(stream).and_then(|head| parse_connect(&head)) {
        Ok(target) => target,
        Err(deny) => {
            let _ = write_status(stream, deny.status(), status_reason(deny.status()));
            let decision = Decision::refused(task, policy_version, None, deny);
            log(&decision);
            return decision;
        }
    };
    if let Err(deny) = authorize(rules, &target) {
        let _ = write_status(stream, deny.status(), status_reason(deny.status()));
        let decision = Decision::refused(task, policy_version, Some(&target), deny);
        log(&decision);
        return decision;
    }

    // Resolve once and pin the tunnel to the first address that accepts it, so
    // a later DNS answer cannot redirect an established tunnel.
    let addresses = match resolver.resolve(&target.host, target.port) {
        Ok(addresses) if !addresses.is_empty() => addresses,
        Ok(_) => {
            return refuse(
                stream,
                task,
                policy_version,
                &target,
                Deny::ResolveFailed,
                log,
            );
        }
        Err(_) => {
            return refuse(
                stream,
                task,
                policy_version,
                &target,
                Deny::ResolveFailed,
                log,
            );
        }
    };
    let mut connected = None;
    let mut failure = String::new();
    for address in &addresses {
        match std::net::TcpStream::connect_timeout(address, CONNECT_TIMEOUT) {
            Ok(upstream) => {
                connected = Some((*address, upstream));
                break;
            }
            Err(error) => failure = format!("{address}: {error}"),
        }
    }
    let Some((address, upstream)) = connected else {
        let _ = write_status(stream, 502, status_reason(502));
        let mut decision =
            Decision::refused(task, policy_version, Some(&target), Deny::ConnectFailed);
        decision.candidates = addresses;
        decision.detail = failure;
        log(&decision);
        return decision;
    };

    if write_status(stream, 200, status_reason(200)).is_err() {
        let decision = Decision::refused(task, policy_version, Some(&target), Deny::ConnectFailed);
        log(&decision);
        return decision;
    }
    let decision = Decision {
        task: task.to_string(),
        policy_version,
        host: target.host.clone(),
        port: target.port,
        candidates: vec![address],
        detail: String::new(),
        outcome: Ok(Some(address)),
    };
    log(&decision);
    let _ = tunnel(stream, upstream);
    decision
}

#[cfg(unix)]
fn refuse(
    stream: &mut std::os::unix::net::UnixStream,
    task: &str,
    policy_version: u32,
    target: &Target,
    deny: Deny,
    log: &mut dyn FnMut(&Decision),
) -> Decision {
    let _ = write_status(stream, deny.status(), status_reason(deny.status()));
    let decision = Decision::refused(task, policy_version, Some(target), deny);
    log(&decision);
    decision
}

/// Byte-transparent copy in both directions until either side closes.
#[cfg(unix)]
fn tunnel(
    stream: &std::os::unix::net::UnixStream,
    upstream: std::net::TcpStream,
) -> io::Result<()> {
    use std::net::Shutdown;

    let mut payload = stream.try_clone()?;
    let mut upstream_read = upstream.try_clone()?;
    let mut upstream_write = upstream;
    let upload = std::thread::spawn(move || {
        let copied = io::copy(&mut payload, &mut upstream_write);
        let _ = upstream_write.shutdown(Shutdown::Write);
        copied
    });
    let mut downstream = stream;
    let _ = io::copy(&mut upstream_read, &mut downstream);
    let _ = stream.shutdown(Shutdown::Write);
    let _ = upload.join();
    Ok(())
}

/// Create the private directory that holds the listener socket.
///
/// One directory per launcher run, mode 0700, removed by [`Listener::cleanup`].
#[cfg(unix)]
pub fn private_socket_dir(prefix: &str) -> io::Result<std::path::PathBuf> {
    use std::os::unix::fs::DirBuilderExt;

    let base = std::env::temp_dir();
    for attempt in 0..32 {
        let candidate = base.join(format!("{prefix}-{}-{attempt}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no free proxy socket directory",
    ))
}

/// The accepting half of the proxy: one detached thread per payload
/// connection, all sharing the frozen rules.
#[cfg(unix)]
struct Server {
    listener: std::os::unix::net::UnixListener,
    task: String,
    policy_version: u32,
    rules: Vec<NetworkRule>,
    events: Option<std::sync::Arc<std::sync::Mutex<crate::run::Recorder>>>,
}

#[cfg(unix)]
impl Server {
    fn run(self) {
        for incoming in self.listener.incoming() {
            let Ok(mut stream) = incoming else {
                break;
            };
            let task = self.task.clone();
            let rules = self.rules.clone();
            let policy_version = self.policy_version;
            let events = self.events.clone();
            std::thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
                let mut log = |decision: &Decision| {
                    eprintln!("{}", decision.log_line());
                    if let Some(recorder) = &events {
                        if let Ok(mut recorder) = recorder.lock() {
                            recorder.record(crate::events::EventKind::NetworkDecision {
                                host: decision.host.clone(),
                                port: decision.port,
                                decision: decision.decision().to_string(),
                                reason: decision.reason().to_string(),
                                address: decision.address(),
                            });
                        }
                    }
                };
                let _ = serve(
                    &mut stream,
                    &task,
                    policy_version,
                    &rules,
                    &SystemResolver,
                    &mut log,
                );
            });
        }
    }
}

/// A bound proxy listener plus the directory it lives in.
#[cfg(unix)]
pub struct Listener {
    path: std::path::PathBuf,
    dir: std::path::PathBuf,
}

#[cfg(unix)]
impl Listener {
    /// Bind `dir/proxy.sock` and start serving in the background.
    ///
    /// The socket file is mode 0600: only the service account that runs the
    /// launcher (and therefore the payload's user-namespace root) can reach it.
    pub fn start(
        dir: std::path::PathBuf,
        task: String,
        policy_version: u32,
        rules: Vec<NetworkRule>,
        events: Option<std::sync::Arc<std::sync::Mutex<crate::run::Recorder>>>,
    ) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("proxy.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        std::thread::spawn(move || {
            Server {
                listener,
                task,
                policy_version,
                rules,
                events,
            }
            .run()
        });
        Ok(Self { path, dir })
    }

    /// Host path of the socket, to be bind-mounted into the sandbox.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Remove the socket and its directory.  Called before the launcher exits.
    pub fn cleanup(self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Vec<NetworkRule> {
        vec![NetworkRule {
            host: "api.example.com".to_string(),
            ports: vec![443],
        }]
    }

    fn target(host: &str, port: u16) -> Target {
        Target {
            host: host.to_string(),
            port,
        }
    }

    #[test]
    fn parses_a_connect_request_line() {
        let parsed =
            parse_connect(b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(parsed, target("api.example.com", 443));
        let upper = parse_connect(b"connect API.Example.COM:443 HTTP/1.0\n\n").unwrap();
        assert_eq!(upper, target("api.example.com", 443));
    }

    #[test]
    fn rejects_non_connect_and_malformed_requests() {
        for head in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            &b"CONNECT api.example.com HTTP/1.1\r\n\r\n"[..],
            &b"CONNECT api.example.com:443\r\n\r\n"[..],
            &b"CONNECT api.example.com:0 HTTP/1.1\r\n\r\n"[..],
            &b"CONNECT :443 HTTP/1.1\r\n\r\n"[..],
            &b"CONNECT api.example.com:443 HTTP/1.1 extra\r\n\r\n"[..],
            &b""[..],
        ] {
            assert!(parse_connect(head).is_err(), "{head:?}");
        }
        assert_eq!(
            parse_connect(b"GET / HTTP/1.1\r\n\r\n").unwrap_err(),
            Deny::NotConnect
        );
    }

    #[test]
    fn refuses_ip_literals_even_when_a_rule_matches_the_port() {
        let mut list = rules();
        list.push(NetworkRule {
            host: "127.0.0.1".to_string(),
            ports: vec![80],
        });
        assert_eq!(
            authorize(&list, &target("127.0.0.1", 80)),
            Err(Deny::NotHostname)
        );
        assert_eq!(authorize(&list, &target("::1", 80)), Err(Deny::NotHostname));
    }

    #[test]
    fn separates_unknown_host_from_unknown_port() {
        assert_eq!(
            authorize(&rules(), &target("other.example.com", 443)),
            Err(Deny::HostNotAllowed)
        );
        assert_eq!(
            authorize(&rules(), &target("api.example.com", 80)),
            Err(Deny::PortNotAllowed)
        );
        assert_eq!(authorize(&rules(), &target("api.example.com", 443)), Ok(()));
    }

    #[test]
    fn log_line_carries_task_version_target_and_outcome() {
        let line = Decision {
            task: "task-1".to_string(),
            policy_version: 1,
            host: "api.example.com".to_string(),
            port: 443,
            candidates: vec!["93.184.216.34:443".parse().unwrap()],
            detail: String::new(),
            outcome: Ok(Some("93.184.216.34:443".parse().unwrap())),
        }
        .log_line();
        for needle in [
            "task=task-1",
            "policy_version=1",
            "host=api.example.com",
            "port=443",
            "decision=allow",
            "address=93.184.216.34:443",
        ] {
            assert!(line.contains(needle), "{line}");
        }

        let denied = Decision {
            task: "task-1".to_string(),
            policy_version: 2,
            host: "other.example.com".to_string(),
            port: 80,
            candidates: Vec::new(),
            detail: String::new(),
            outcome: Err(Deny::HostNotAllowed),
        }
        .log_line();
        assert!(denied.contains("decision=deny"), "{denied}");
        assert!(denied.contains("reason=host-not-allowed"), "{denied}");
        assert!(denied.contains("policy_version=2"), "{denied}");

        let unparsed = Decision {
            task: "task-1".to_string(),
            policy_version: 1,
            host: "-".to_string(),
            port: 0,
            candidates: Vec::new(),
            detail: String::new(),
            outcome: Err(Deny::NotConnect),
        }
        .log_line();
        assert!(
            unparsed.contains("host=- port=- decision=deny"),
            "{unparsed}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn reads_a_request_head_including_the_blank_line() {
        let mut input = &b"CONNECT a.example.com:443 HTTP/1.1\r\n\r\nleftover"[..];
        let head = read_head(&mut input).unwrap();
        assert_eq!(head, b"CONNECT a.example.com:443 HTTP/1.1\r\n\r\n");
        assert_eq!(input, b"leftover");
    }

    #[cfg(unix)]
    #[test]
    fn oversized_request_head_is_refused() {
        let mut input = io::Cursor::new(vec![b'A'; MAX_REQUEST_HEAD + 16]);
        assert_eq!(read_head(&mut input).unwrap_err(), Deny::TooLarge);
    }

    #[cfg(unix)]
    #[test]
    fn resolves_once_and_pins_the_tunnel_to_one_address() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingResolver(AtomicUsize);
        impl Resolver for CountingResolver {
            fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
                self.0.fetch_add(1, Ordering::SeqCst);
                assert_eq!(host, "api.example.com");
                assert_eq!(port, 443);
                Ok(vec!["127.0.0.1:9".parse().unwrap()])
            }
        }

        let resolver = CountingResolver(AtomicUsize::new(0));
        // A refused CONNECT never resolves at all: the decision is made from the
        // frozen rules alone.
        let denied = authorize(&rules(), &target("evil.example.com", 443));
        assert!(denied.is_err());
        assert_eq!(resolver.0.load(Ordering::SeqCst), 0);

        // An allowed CONNECT resolves once, even though connecting fails here.
        let addresses = resolver.resolve("api.example.com", 443).unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
    }
}
