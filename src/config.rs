//! Versioned policy configuration for EasySandbox.
//!
//! The YAML document is intentionally small and strict.  Every object rejects
//! unknown fields, enum values are case-sensitive, and semantic validation is
//! performed after deserialization.  Parsing a policy is therefore safe to do
//! before launching a sandbox: an invalid policy never becomes a permissive
//! default by accident.

use std::fmt;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The only policy format currently accepted.
pub const CURRENT_POLICY_VERSION: u32 = 1;

/// A complete sandbox policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub limits: Limits,
    pub syscalls: SyscallPolicy,
    pub mode: PolicyMode,
}

/// Filesystem paths are interpreted inside the sandbox root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    /// Paths that the workload may read.
    pub read: Vec<String>,
    /// Paths that the workload may create, modify, or remove.
    pub write: Vec<String>,
}

/// Network behavior.  Direct host networking is intentionally not a policy
/// value; future outbound access goes through the proxy mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub allow: Vec<NetworkRule>,
}

/// Network modes supported by the policy schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    Disabled,
    Proxy,
}

/// One exact domain and an explicit set of destination ports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    pub host: String,
    pub ports: Vec<u16>,
}

/// Optional process resource limits.  An omitted value means that this
/// particular limit is left to the launcher/default runtime policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub memory_mib: Option<u64>,
    #[serde(default)]
    pub cpu_seconds: Option<u64>,
    #[serde(default)]
    pub max_processes: Option<u64>,
}

/// Syscalls to deny in enforce mode.  Names are kept as strings so the
/// architecture-specific seccomp compiler can resolve them later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyscallPolicy {
    pub deny: Vec<String>,
}

/// Execution mode for the policy/verification pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Observe,
    Enforce,
    Verify,
}

/// Errors returned while loading or validating a policy.
#[derive(Debug)]
pub enum PolicyError {
    Io(std::io::Error),
    Yaml(serde_yaml::Error),
    Invalid(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "policy I/O error: {error}"),
            Self::Yaml(error) => write!(formatter, "policy YAML error: {error}"),
            Self::Invalid(message) => write!(formatter, "invalid policy: {message}"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    /// Parse and validate a YAML policy document.
    pub fn from_yaml_str(source: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_yaml::from_str(source).map_err(PolicyError::Yaml)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Read, parse, and validate a YAML policy file.
    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let source = fs::read_to_string(path).map_err(PolicyError::Io)?;
        Self::from_yaml_str(&source)
    }

    /// Validate semantic constraints not expressible in serde's data model.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != CURRENT_POLICY_VERSION {
            return Err(PolicyError::Invalid(format!(
                "unsupported version {}; expected {}",
                self.version, CURRENT_POLICY_VERSION
            )));
        }

        validate_paths("filesystem.read", &self.filesystem.read, false)?;
        validate_paths("filesystem.write", &self.filesystem.write, true)?;
        validate_network(&self.network)?;
        validate_limits(&self.limits)?;
        validate_syscalls(&self.syscalls)?;
        Ok(())
    }

    /// Serialize a validated policy using the stable YAML representation.
    pub fn to_yaml_string(&self) -> Result<String, PolicyError> {
        self.validate()?;
        serde_yaml::to_string(self).map_err(PolicyError::Yaml)
    }
}

fn validate_paths(
    field: &str,
    paths: &[String],
    reject_root_write: bool,
) -> Result<(), PolicyError> {
    for (index, value) in paths.iter().enumerate() {
        if value.is_empty() {
            return Err(PolicyError::Invalid(format!(
                "{field}[{index}] must not be empty"
            )));
        }
        if value.as_bytes().contains(&0) {
            return Err(PolicyError::Invalid(format!(
                "{field}[{index}] contains NUL"
            )));
        }
        // Sandbox paths are POSIX paths.  They are validated with POSIX rules
        // instead of the host's path semantics so that the same document is
        // accepted or rejected identically on every platform.
        if !value.starts_with('/') {
            return Err(PolicyError::Invalid(format!(
                "{field}[{index}] must be an absolute sandbox path"
            )));
        }
        if value
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        {
            return Err(PolicyError::Invalid(format!(
                "{field}[{index}] must not contain '.' or '..' components"
            )));
        }
        if reject_root_write && value == "/" {
            return Err(PolicyError::Invalid(
                "filesystem.write must not grant the sandbox root".to_string(),
            ));
        }
        if paths[..index].iter().any(|previous| previous == value) {
            return Err(PolicyError::Invalid(format!(
                "{field} contains duplicate path {value:?}"
            )));
        }
    }
    Ok(())
}

fn validate_network(network: &NetworkPolicy) -> Result<(), PolicyError> {
    for (index, rule) in network.allow.iter().enumerate() {
        let host = rule.host.trim();
        if host.is_empty() || host != rule.host {
            return Err(PolicyError::Invalid(format!(
                "network.allow[{index}].host must be a non-empty hostname without surrounding whitespace"
            )));
        }
        if host.len() > 253 || host.contains('/') || host.contains(':') || host.contains("://") {
            return Err(PolicyError::Invalid(format!(
                "network.allow[{index}].host is not a hostname: {host:?}"
            )));
        }
        for label in host.split('.') {
            if label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(PolicyError::Invalid(format!(
                    "network.allow[{index}].host is not a valid exact hostname: {host:?}"
                )));
            }
        }
        if rule.ports.is_empty() {
            return Err(PolicyError::Invalid(format!(
                "network.allow[{index}].ports must contain at least one port"
            )));
        }
        for (port_index, port) in rule.ports.iter().enumerate() {
            if *port == 0 {
                return Err(PolicyError::Invalid(format!(
                    "network.allow[{index}].ports[{port_index}] must be between 1 and 65535"
                )));
            }
            if rule.ports[..port_index].contains(port) {
                return Err(PolicyError::Invalid(format!(
                    "network.allow[{index}].ports contains duplicate port {port}"
                )));
            }
        }
    }
    if matches!(network.mode, NetworkMode::Disabled) && !network.allow.is_empty() {
        return Err(PolicyError::Invalid(
            "network.allow must be empty when network.mode is disabled".to_string(),
        ));
    }
    Ok(())
}

fn validate_limits(limits: &Limits) -> Result<(), PolicyError> {
    let values = [
        ("limits.timeout_ms", limits.timeout_ms),
        ("limits.memory_mib", limits.memory_mib),
        ("limits.cpu_seconds", limits.cpu_seconds),
        ("limits.max_processes", limits.max_processes),
    ];
    for (field, value) in values {
        if value == Some(0) {
            return Err(PolicyError::Invalid(format!(
                "{field} must be greater than zero"
            )));
        }
    }
    Ok(())
}

fn validate_syscalls(syscalls: &SyscallPolicy) -> Result<(), PolicyError> {
    for (index, name) in syscalls.deny.iter().enumerate() {
        if name.is_empty()
            || name.len() > 64
            || !name.as_bytes()[0].is_ascii_lowercase()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(PolicyError::Invalid(format!(
                "syscalls.deny[{index}] is not a valid syscall name: {name:?}"
            )));
        }
        if syscalls.deny[..index]
            .iter()
            .any(|previous| previous == name)
        {
            return Err(PolicyError::Invalid(format!(
                "syscalls.deny contains duplicate syscall {name:?}"
            )));
        }
    }
    Ok(())
}

/// A limit requested by the launcher or its caller, before a policy applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitRequest {
    /// Nothing was requested; the launcher default decides.
    Unset,
    /// The caller explicitly asked for no limit (`--no-memory-limit`).
    Unlimited,
    /// A concrete value.
    Value(u64),
}

impl From<Option<u64>> for LimitRequest {
    fn from(value: Option<u64>) -> Self {
        match value {
            Some(value) => LimitRequest::Value(value),
            None => LimitRequest::Unset,
        }
    }
}

impl LimitRequest {
    /// Apply a policy ceiling and a launcher default.
    ///
    /// A policy is authoritative for every field it defines and can only cap a
    /// caller-provided value: an explicit request is reduced to the policy
    /// value and never raised above it, while a policy value is used as-is
    /// when the caller stays silent.  The launcher default only fills the gap
    /// left by both.  A run therefore never becomes more permissive than the
    /// launcher defaults, the caller request, or the policy, whichever is
    /// strictest.
    pub fn resolve(self, policy: Option<u64>, default: LimitRequest) -> LimitRequest {
        match (self, policy) {
            (LimitRequest::Value(requested), Some(ceiling)) => {
                LimitRequest::Value(requested.min(ceiling))
            }
            (LimitRequest::Value(requested), None) => LimitRequest::Value(requested),
            (LimitRequest::Unlimited | LimitRequest::Unset, Some(ceiling)) => {
                LimitRequest::Value(ceiling)
            }
            (LimitRequest::Unlimited, None) => LimitRequest::Unlimited,
            (LimitRequest::Unset, None) => default,
        }
    }

    /// The concrete limit value, if the run has one.
    pub fn as_option(self) -> Option<u64> {
        match self {
            LimitRequest::Value(value) => Some(value),
            LimitRequest::Unlimited | LimitRequest::Unset => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
version: 1
filesystem:
  read: ["/usr", "/bin"]
  write: ["/workspace"]
network:
  mode: proxy
  allow:
    - host: api.example.com
      ports: [443]
limits:
  timeout_ms: 30000
  memory_mib: 512
  cpu_seconds: 30
  max_processes: 64
syscalls:
  deny: [mount, pivot_root, ptrace]
mode: enforce
"#;

    #[test]
    fn parses_and_round_trips_valid_policy() {
        let policy = Policy::from_yaml_str(VALID).expect("valid policy");
        assert_eq!(policy.version, CURRENT_POLICY_VERSION);
        assert_eq!(policy.network.mode, NetworkMode::Proxy);
        assert_eq!(policy.mode, PolicyMode::Enforce);
        let serialized = policy.to_yaml_string().expect("serialize policy");
        let reparsed = Policy::from_yaml_str(&serialized).expect("round trip");
        assert_eq!(policy, reparsed);
    }

    #[test]
    fn rejects_unknown_fields_at_every_level() {
        for (needle, replacement) in [
            ("version: 1", "version: 1\nextra: true"),
            (
                "  write: [\"/workspace\"]",
                "  write: [\"/workspace\"]\n  execute: [\"/bin\"]",
            ),
            ("  mode: proxy", "  mode: proxy\n  direct: true"),
            (
                "      ports: [443]",
                "      ports: [443]\n      protocol: https",
            ),
            ("  memory_mib: 512", "  memory_mib: 512\n  swap_mib: 1"),
            (
                "  deny: [mount, pivot_root, ptrace]",
                "  deny: [mount, pivot_root, ptrace]\n  allow: []",
            ),
        ] {
            let source = VALID.replace(needle, replacement);
            assert!(
                matches!(Policy::from_yaml_str(&source), Err(PolicyError::Yaml(_))),
                "{needle}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_version_and_enum_values() {
        let version = VALID.replace("version: 1", "version: 2");
        assert!(matches!(
            Policy::from_yaml_str(&version),
            Err(PolicyError::Invalid(_))
        ));
        let mode = VALID.replace("mode: enforce", "mode: audit");
        assert!(matches!(
            Policy::from_yaml_str(&mode),
            Err(PolicyError::Yaml(_))
        ));
        let network = VALID.replace("mode: proxy", "mode: direct");
        assert!(matches!(
            Policy::from_yaml_str(&network),
            Err(PolicyError::Yaml(_))
        ));
    }

    #[test]
    fn rejects_path_network_limit_and_syscall_errors() {
        for source in [
            VALID.replace("/usr", "usr"),
            VALID.replace("write: [\"/workspace\"]", "write: [\"/\"]"),
            VALID.replace("api.example.com", "api/example.com"),
            VALID.replace("ports: [443]", "ports: [0]"),
            VALID.replace("timeout_ms: 30000", "timeout_ms: 0"),
            VALID.replace("mount, pivot_root, ptrace", "mount, bad-name, ptrace"),
            VALID.replace("mount, pivot_root, ptrace", "mount, mount, ptrace"),
        ] {
            assert!(
                matches!(Policy::from_yaml_str(&source), Err(PolicyError::Invalid(_))),
                "{source}"
            );
        }
    }

    #[test]
    fn disabled_network_cannot_have_allow_rules() {
        let source = VALID.replace("mode: proxy", "mode: disabled");
        assert!(matches!(
            Policy::from_yaml_str(&source),
            Err(PolicyError::Invalid(_))
        ));
    }

    #[test]
    fn empty_lists_are_valid_deny_defaults() {
        let source = VALID
            .replace("read: [\"/usr\", \"/bin\"]", "read: []")
            .replace("write: [\"/workspace\"]", "write: []")
            .replace(
                "mode: proxy\n  allow:\n    - host: api.example.com\n      ports: [443]",
                "mode: disabled\n  allow: []",
            )
            .replace("deny: [mount, pivot_root, ptrace]", "deny: []");
        assert!(Policy::from_yaml_str(&source).is_ok());
    }

    #[test]
    fn policy_caps_an_explicit_request_but_never_raises_it() {
        let default = LimitRequest::Value(512);
        assert_eq!(
            LimitRequest::Value(4096).resolve(Some(512), default),
            LimitRequest::Value(512)
        );
        assert_eq!(
            LimitRequest::Value(128).resolve(Some(512), default),
            LimitRequest::Value(128)
        );
        assert_eq!(
            LimitRequest::Value(4096).resolve(None, default),
            LimitRequest::Value(4096)
        );
    }

    #[test]
    fn policy_value_wins_when_the_caller_stays_silent() {
        let default = LimitRequest::Value(512);
        assert_eq!(
            LimitRequest::Unset.resolve(Some(4096), default),
            LimitRequest::Value(4096)
        );
        assert_eq!(LimitRequest::Unset.resolve(None, default), default);
        assert_eq!(
            LimitRequest::Unset.resolve(None, LimitRequest::Unset),
            LimitRequest::Unset
        );
    }

    #[test]
    fn an_explicit_request_for_no_limit_is_still_capped_by_the_policy() {
        let default = LimitRequest::Value(512);
        assert_eq!(
            LimitRequest::Unlimited.resolve(Some(512), default),
            LimitRequest::Value(512)
        );
        assert_eq!(
            LimitRequest::Unlimited.resolve(None, default),
            LimitRequest::Unlimited
        );
        assert_eq!(LimitRequest::Unlimited.as_option(), None);
        assert_eq!(LimitRequest::Value(7).as_option(), Some(7));
    }
}
