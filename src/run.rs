//! Run records: freeze the policy, then write one JSONL line per event.
//!
//! The launcher parent and the sandbox child both append to the same file.
//! Each event is a single `write` of one line, which keeps concurrent appends
//! from interleaving inside a line.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::config::Policy;
use crate::events::{EVENT_VERSION, Event, EventKind, RunLimits};

/// A change detector over the frozen policy document.
///
/// The record also carries the document itself, so this fingerprint is only
/// used to notice that two runs disagree about the policy.  It is deliberately
/// not a cryptographic commitment.
pub fn fingerprint(document: &str) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in document.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

/// Wall-clock milliseconds, or 0 when the clock is unavailable.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Identifier shared by every event of one run.
pub fn run_id() -> String {
    format!("{}-{}", std::process::id(), now_ms())
}

enum Destination {
    File(File),
    Stderr,
}

/// Appends events to the run record.
///
/// A disabled recorder accepts events and drops them, so call sites never need
/// to check whether recording was requested.
pub struct Recorder {
    destination: Option<Destination>,
    writer: String,
    run_id: String,
    fingerprint: String,
    started: Instant,
    seq: u64,
}

impl Recorder {
    pub fn disabled() -> Self {
        Self {
            destination: None,
            writer: String::new(),
            run_id: String::new(),
            fingerprint: String::new(),
            started: Instant::now(),
            seq: 0,
        }
    }

    /// Open `path` in append mode; `-` writes to stderr instead.
    pub fn open(
        path: &Path,
        writer: &str,
        run_id: String,
        fingerprint: String,
    ) -> Result<Self, String> {
        let destination = if path == Path::new("-") {
            Destination::Stderr
        } else {
            Destination::File(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|error| format!("cannot open record {}: {error}", path.display()))?,
            )
        };
        Ok(Self {
            destination: Some(destination),
            writer: writer.to_string(),
            run_id,
            fingerprint,
            started: Instant::now(),
            seq: 0,
        })
    }

    pub fn enabled(&self) -> bool {
        self.destination.is_some()
    }

    /// Append one event.  Serialization or I/O failures are ignored on purpose:
    /// a record that cannot be written must never turn into a sandbox failure.
    pub fn record(&mut self, kind: EventKind) {
        let Some(destination) = self.destination.as_mut() else {
            return;
        };
        self.seq += 1;
        let event = Event {
            v: EVENT_VERSION,
            seq: self.seq,
            writer: self.writer.clone(),
            run_id: self.run_id.clone(),
            policy_fingerprint: self.fingerprint.clone(),
            at_ms: self.started.elapsed().as_millis() as u64,
            kind,
        };
        let Ok(mut line) = serde_json::to_string(&event) else {
            return;
        };
        line.push('\n');
        match destination {
            Destination::File(file) => {
                let _ = file.write_all(line.as_bytes());
            }
            Destination::Stderr => {
                let _ = std::io::stderr().write_all(line.as_bytes());
            }
        }
    }

    /// Record how many events this writer emitted.
    pub fn close(&mut self) {
        if self.enabled() {
            let events = self.seq;
            self.record(EventKind::RecordClosed { events });
        }
    }
}

/// The restrictions a policy asks for, as unapproved candidates.
///
/// Observe mode installs none of them: the point is to hand a reviewer the
/// exact list that would be enforced, with every entry still unapproved.
pub fn candidates(policy: &Policy) -> Vec<EventKind> {
    let mut events = Vec::new();
    let mut push = |field: &str, value: String| {
        events.push(EventKind::Candidate {
            field: field.to_string(),
            value,
            state: "unapproved".to_string(),
        });
    };

    for path in &policy.filesystem.read {
        push("filesystem.read", path.clone());
    }
    for path in &policy.filesystem.write {
        push("filesystem.write", path.clone());
    }
    for name in &policy.syscalls.deny {
        push("syscalls.deny", name.clone());
    }
    for rule in &policy.network.allow {
        push(
            "network.allow",
            format!(
                "{}:{}",
                rule.host,
                rule.ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        );
    }
    if let Some(timeout_ms) = policy.limits.timeout_ms {
        push("limits.timeout_ms", timeout_ms.to_string());
    }
    if let Some(memory_mib) = policy.limits.memory_mib {
        push("limits.memory_mib", memory_mib.to_string());
    }
    if let Some(cpu_seconds) = policy.limits.cpu_seconds {
        push("limits.cpu_seconds", cpu_seconds.to_string());
    }
    if let Some(max_processes) = policy.limits.max_processes {
        push("limits.max_processes", max_processes.to_string());
    }
    events
}

/// Fill the `RunStarted` payload from plain values.
#[allow(clippy::too_many_arguments)]
pub fn run_started(
    mode: &str,
    policy_version: u32,
    policy: &str,
    limits: RunLimits,
    rootfs: &str,
    workspace: &str,
    command: &[String],
) -> EventKind {
    EventKind::RunStarted {
        mode: mode.to_string(),
        policy_version,
        policy: policy.to_string(),
        limits,
        rootfs: rootfs.to_string(),
        workspace: workspace.to_string(),
        command: command.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
version: 1
filesystem:
  read: ["/bin"]
  write: ["/workspace"]
network:
  mode: proxy
  allow:
    - host: api.example.com
      ports: [443, 8443]
limits:
  timeout_ms: 5000
  memory_mib: 256
syscalls:
  deny: [mount, ptrace]
mode: observe
"#;

    #[test]
    fn fingerprint_notices_a_changed_document() {
        let first = fingerprint("version: 1\n");
        assert_eq!(first.len(), 16);
        assert_ne!(first, fingerprint("version: 1\nmode: observe\n"));
        assert_eq!(first, fingerprint("version: 1\n"));
    }

    #[test]
    fn an_empty_recorder_swallows_events() {
        let mut recorder = Recorder::disabled();
        assert!(!recorder.enabled());
        recorder.record(EventKind::RecordClosed { events: 0 });
        recorder.close();
    }

    #[test]
    fn observe_candidates_cover_every_policy_field() {
        let policy = Policy::from_yaml_str(POLICY).expect("valid policy");
        let candidates = candidates(&policy);
        let rendered: Vec<String> = candidates
            .iter()
            .map(|event| match event {
                EventKind::Candidate {
                    field,
                    value,
                    state,
                } => {
                    assert_eq!(state, "unapproved");
                    format!("{field}={value}")
                }
                other => panic!("unexpected event {other:?}"),
            })
            .collect();
        assert_eq!(
            rendered,
            vec![
                "filesystem.read=/bin",
                "filesystem.write=/workspace",
                "syscalls.deny=mount",
                "syscalls.deny=ptrace",
                "network.allow=api.example.com:443,8443",
                "limits.timeout_ms=5000",
                "limits.memory_mib=256",
            ]
        );
    }

    #[test]
    fn recording_appends_one_line_per_event() {
        let directory =
            std::env::temp_dir().join(format!("easy-sandbox-record-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("create scratch");
        let path = directory.join("run.jsonl");
        let _ = std::fs::remove_file(&path);

        let mut recorder = Recorder::open(
            &path,
            "launcher-parent",
            "run-1".to_string(),
            "abc".to_string(),
        )
        .expect("open record");
        recorder.record(EventKind::TaskResult {
            status: "exited".to_string(),
            exit_code: Some(0),
            duration_ms: 3,
        });
        recorder.close();

        let contents = std::fs::read_to_string(&path).expect("read record");
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "{contents}");
        for line in &lines {
            let event: Event = serde_json::from_str(line).expect("parseable event");
            assert_eq!(event.run_id, "run-1");
            assert_eq!(event.policy_fingerprint, "abc");
        }
        assert!(lines[1].contains("\"kind\":\"record-closed\""));
        let _ = std::fs::remove_dir_all(&directory);
    }
}
