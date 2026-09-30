//! Versioned event and report types for the observe/enforce/verify pipeline.
//!
//! One run produces a JSONL record: every line is one [`Event`].  The record is
//! the only artifact a reviewer or an SDK needs, so the field names are part of
//! the public contract and are covered by [`EVENT_VERSION`].
//!
//! Nothing here decides anything.  Enforcement lives in `policy.rs`, and the
//! verdicts of a verification run live in `verify.rs`; this module only
//! describes what was recorded and how it is serialized.

use serde::{Deserialize, Serialize};

/// Version of the event envelope and of every payload below it.
pub const EVENT_VERSION: u32 = 1;

/// Effective resource limits of a run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunLimits {
    pub timeout_ms: u64,
    #[serde(default)]
    pub memory_mib: Option<u64>,
    #[serde(default)]
    pub cpu_seconds: Option<u64>,
    #[serde(default)]
    pub max_processes: Option<u64>,
}

/// What happened, tagged by `kind`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EventKind {
    /// First event of a record.  `policy` carries the frozen document itself,
    /// so the exact bytes that were enforced are recoverable without a hash.
    RunStarted {
        mode: String,
        policy_version: u32,
        policy: String,
        limits: RunLimits,
        rootfs: String,
        workspace: String,
        command: Vec<String>,
    },
    /// One enforcement layer and whether it was installed.
    ///
    /// In observe mode the policy layers are reported with
    /// `installed: false` and a reason, which is the whole point of the mode:
    /// the record shows what was *not* enforced.
    Restriction {
        layer: String,
        installed: bool,
        reason: String,
    },
    /// A restriction the policy asks for but that no human has approved yet.
    ///
    /// Candidates are never applied automatically; they exist so that a
    /// reviewer can turn them into an enforced policy deliberately.
    Candidate {
        field: String,
        value: String,
        state: String,
    },
    /// A proxy decision.  Refusals are recorded exactly like allowances.
    NetworkDecision {
        host: String,
        port: u16,
        decision: String,
        reason: String,
        address: String,
    },
    /// How the payload ended.
    TaskResult {
        status: String,
        #[serde(default)]
        exit_code: Option<i32>,
        duration_ms: u64,
    },
    /// Last event: how many events the writer emitted.
    RecordClosed { events: u64 },
}

/// One line of a run record.
///
/// `deny_unknown_fields` is deliberately absent here: serde cannot combine it
/// with a flattened enum.  [`EventKind`] denies unknown fields itself, so a
/// foreign key is still rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// [`EVENT_VERSION`] of this envelope.
    pub v: u32,
    /// Per-writer sequence number; ordering across writers uses `at_ms`.
    pub seq: u64,
    /// `launcher-parent` or `launcher-child`.
    pub writer: String,
    pub run_id: String,
    /// Change detector over the frozen policy document.
    pub policy_fingerprint: String,
    /// Milliseconds since this writer started.
    pub at_ms: u64,
    #[serde(flatten)]
    pub kind: EventKind,
}

/// Verdict of one verification case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The case behaved as its expectation required.
    Pass,
    /// The case contradicted its expectation.
    Fail,
    /// The observation could not be classified; a human has to decide.
    Pending,
}

/// What a case expected, if anything was declared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Expectation {
    /// The command must be able to do its work.
    Allow,
    /// The command must be refused by the frozen policy.
    Deny,
}

/// One case of a verification report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseReport {
    pub name: String,
    #[serde(default)]
    pub expectation: Option<Expectation>,
    pub verdict: Verdict,
    #[serde(default)]
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    /// Why the verdict is what it is, in one line.
    pub detail: String,
}

/// Counts of a report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub pending: usize,
}

impl VerdictSummary {
    pub fn of(cases: &[CaseReport]) -> Self {
        let mut summary = Self {
            total: cases.len(),
            ..Self::default()
        };
        for case in cases {
            match case.verdict {
                Verdict::Pass => summary.passed += 1,
                Verdict::Fail => summary.failed += 1,
                Verdict::Pending => summary.pending += 1,
            }
        }
        summary
    }
}

/// The policy a report was produced against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportPolicy {
    pub path: String,
    pub version: u32,
    pub fingerprint: String,
}

/// A verification report, described by `docs/report.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyReport {
    pub v: u32,
    pub kind: String,
    /// Unix milliseconds when the report was written, or 0 when unavailable.
    pub generated_at_ms: u64,
    pub policy: ReportPolicy,
    pub cases: Vec<CaseReport>,
    pub summary: VerdictSummary,
}

impl VerifyReport {
    pub const KIND: &'static str = "easy-sandbox-verify-report";

    pub fn new(policy: ReportPolicy, cases: Vec<CaseReport>, generated_at_ms: u64) -> Self {
        Self {
            v: EVENT_VERSION,
            kind: Self::KIND.to_string(),
            generated_at_ms,
            policy,
            summary: VerdictSummary::of(&cases),
            cases,
        }
    }

    /// A report passes only when nothing failed and nothing is pending.
    pub fn passed(&self) -> bool {
        self.summary.failed == 0 && self.summary.pending == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> Event {
        Event {
            v: EVENT_VERSION,
            seq: 7,
            writer: "launcher-parent".to_string(),
            run_id: "run-1".to_string(),
            policy_fingerprint: "deadbeef".to_string(),
            at_ms: 12,
            kind: EventKind::NetworkDecision {
                host: "api.example.com".to_string(),
                port: 443,
                decision: "deny".to_string(),
                reason: "port-not-allowed".to_string(),
                address: "-".to_string(),
            },
        }
    }

    #[test]
    fn events_round_trip_as_tagged_json() {
        let event = sample_event();
        let line = serde_json::to_string(&event).expect("serialize");
        assert!(line.contains("\"kind\":\"network-decision\""), "{line}");
        let parsed: Event = serde_json::from_str(&line).expect("deserialize");
        assert_eq!(parsed, event);
    }

    #[test]
    fn unknown_event_fields_are_rejected() {
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&sample_event()).unwrap()).unwrap();
        value["surprise"] = serde_json::json!(1);
        assert!(serde_json::from_value::<Event>(value).is_err());
    }

    #[test]
    fn run_started_carries_the_frozen_policy() {
        let event = Event {
            v: EVENT_VERSION,
            seq: 1,
            writer: "launcher-parent".to_string(),
            run_id: "run-1".to_string(),
            policy_fingerprint: "abc".to_string(),
            at_ms: 0,
            kind: EventKind::RunStarted {
                mode: "observe".to_string(),
                policy_version: 1,
                policy: "version: 1\n".to_string(),
                limits: RunLimits {
                    timeout_ms: 5000,
                    memory_mib: Some(256),
                    cpu_seconds: None,
                    max_processes: None,
                },
                rootfs: "/srv/rootfs".to_string(),
                workspace: "/srv/work".to_string(),
                command: vec!["/bin/true".to_string()],
            },
        };
        let parsed: Event =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).expect("round trip");
        assert_eq!(parsed, event);
    }

    #[test]
    fn summary_counts_every_verdict() {
        let case = |verdict| CaseReport {
            name: "case".to_string(),
            expectation: Some(Expectation::Allow),
            verdict,
            exit_code: Some(0),
            duration_ms: 1,
            detail: String::new(),
        };
        let cases = vec![
            case(Verdict::Pass),
            case(Verdict::Pending),
            case(Verdict::Fail),
        ];
        let summary = VerdictSummary::of(&cases);
        assert_eq!(
            summary,
            VerdictSummary {
                total: 3,
                passed: 1,
                failed: 1,
                pending: 1
            }
        );
    }

    #[test]
    fn a_report_with_pending_cases_does_not_pass() {
        let report = VerifyReport::new(
            ReportPolicy {
                path: "p.yaml".to_string(),
                version: 1,
                fingerprint: "abc".to_string(),
            },
            vec![CaseReport {
                name: "unknown".to_string(),
                expectation: None,
                verdict: Verdict::Pending,
                exit_code: Some(3),
                duration_ms: 5,
                detail: "no expectation declared".to_string(),
            }],
            0,
        );
        assert!(!report.passed());
        assert_eq!(report.summary.pending, 1);
    }
}
