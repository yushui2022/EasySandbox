//! Verification runs: independent cases checked against one frozen policy.
//!
//! A case is a command plus an expectation.  `allow` cases must be able to do
//! their work, `deny` cases must be refused by the policy, and a case that
//! declares no expectation is reported as `pending` so that a human decides
//! instead of the tool guessing.
//!
//! The verdicts are pure functions of the observed exit status: nothing here
//! can widen a policy, and no verdict turns into an automatic permission.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::config::Policy;
use crate::events::{CaseReport, Expectation, ReportPolicy, Verdict, VerifyReport};
use crate::run;

/// Timeout used when neither the case nor the caller sets one.
pub const DEFAULT_CASE_TIMEOUT_MS: u64 = 30_000;

/// One declared verification case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub name: String,
    /// Omitted on purpose means "unknown": the verdict stays pending.
    #[serde(default)]
    pub expectation: Option<Expectation>,
    pub command: Vec<String>,
    /// Sandbox root for this case; the caller's default when omitted.
    #[serde(default)]
    pub rootfs: Option<PathBuf>,
    /// Workspace for this case; the caller's default when omitted.
    #[serde(default)]
    pub workspace: Option<PathBuf>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// A file of independent cases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseFile {
    pub cases: Vec<Case>,
}

impl CaseFile {
    /// Parse and check a case file.  Independent cases must be well formed
    /// before anything runs, so a typo never looks like a policy result.
    pub fn from_yaml_str(source: &str) -> Result<Self, String> {
        let file: Self =
            serde_yaml::from_str(source).map_err(|error| format!("cases YAML error: {error}"))?;
        if file.cases.is_empty() {
            return Err("cases file declares no cases".to_string());
        }
        for (index, case) in file.cases.iter().enumerate() {
            if case.name.trim().is_empty() {
                return Err(format!("cases[{index}].name must not be empty"));
            }
            if case.command.is_empty() {
                return Err(format!("cases[{index}].command must not be empty"));
            }
            if case.timeout_ms == Some(0) {
                return Err(format!(
                    "cases[{index}].timeout_ms must be greater than zero"
                ));
            }
            if file.cases[..index]
                .iter()
                .any(|other| other.name == case.name)
            {
                return Err(format!("cases contains duplicate name {:?}", case.name));
            }
        }
        Ok(file)
    }

    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self, String> {
        let source = std::fs::read_to_string(path.as_ref())
            .map_err(|error| format!("cannot read cases {}: {error}", path.as_ref().display()))?;
        Self::from_yaml_str(&source)
    }
}

/// Defaults applied to cases that do not override them.
#[derive(Clone, Debug)]
pub struct Defaults {
    pub rootfs: PathBuf,
    pub workspace: PathBuf,
    pub timeout_ms: u64,
}

/// Turn one observation into a verdict.
///
/// `124` is the launcher timeout and `125` a sandbox or policy setup failure:
/// neither says anything about the case, so they stay pending unless the case
/// required the command to run at all.
pub fn verdict(expectation: Option<Expectation>, exit_code: Option<i32>) -> (Verdict, String) {
    match (expectation, exit_code) {
        (None, Some(code)) => (
            Verdict::Pending,
            format!("no expectation declared; observed exit {code}"),
        ),
        (None, None) => (
            Verdict::Pending,
            "no expectation declared; the payload was killed by a signal".to_string(),
        ),
        (Some(Expectation::Allow), Some(0)) => (Verdict::Pass, "allowed as required".to_string()),
        (Some(Expectation::Allow), Some(124)) => (
            Verdict::Pending,
            "timed out before the case could be decided".to_string(),
        ),
        (Some(Expectation::Allow), Some(125)) => (
            Verdict::Fail,
            "the sandbox refused to start the case".to_string(),
        ),
        (Some(Expectation::Allow), Some(126)) => (
            Verdict::Fail,
            "the command could not be executed".to_string(),
        ),
        (Some(Expectation::Allow), Some(code)) => (
            Verdict::Fail,
            format!("expected to be allowed, exited {code}"),
        ),
        (Some(Expectation::Allow), None) => (
            Verdict::Pending,
            "killed by a signal before the case could be decided".to_string(),
        ),
        (Some(Expectation::Deny), Some(0)) => (
            Verdict::Fail,
            "expected to be denied, but the command succeeded".to_string(),
        ),
        (Some(Expectation::Deny), Some(124)) => (
            Verdict::Pending,
            "timed out; cannot attribute the failure to the policy".to_string(),
        ),
        (Some(Expectation::Deny), Some(125)) => (
            Verdict::Pending,
            "the sandbox refused to start; the denial cannot be attributed".to_string(),
        ),
        (Some(Expectation::Deny), Some(126)) => (
            Verdict::Fail,
            "the command could not be executed, so nothing was denied".to_string(),
        ),
        (Some(Expectation::Deny), Some(code)) => {
            (Verdict::Pass, format!("refused with exit {code}"))
        }
        (Some(Expectation::Deny), None) => (
            Verdict::Pending,
            "killed by a signal; cannot attribute the failure".to_string(),
        ),
    }
}

/// Run every case against `policy_path` and build the report.
///
/// Cases are executed by re-invoking this same launcher with `run`, so a
/// verification run goes through exactly the code path a real caller uses.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    launcher: &Path,
    policy_path: &Path,
    policy: &Policy,
    cases: &CaseFile,
    defaults: &Defaults,
    records: Option<&Path>,
) -> Result<VerifyReport, String> {
    if records.is_some_and(|dir| !dir.is_dir()) {
        return Err("--records must be an existing directory".to_string());
    }
    let document = policy
        .to_yaml_string()
        .map_err(|error| format!("cannot freeze policy: {error}"))?;

    let mut reports = Vec::with_capacity(cases.cases.len());
    for case in &cases.cases {
        let rootfs = case
            .rootfs
            .clone()
            .unwrap_or_else(|| defaults.rootfs.clone());
        let workspace = case
            .workspace
            .clone()
            .unwrap_or_else(|| defaults.workspace.clone());
        let timeout_ms = case.timeout_ms.unwrap_or(defaults.timeout_ms);

        let mut command = Command::new(launcher);
        command
            .arg("run")
            .arg("--rootfs")
            .arg(&rootfs)
            .arg("--workspace")
            .arg(&workspace)
            .arg("--timeout-ms")
            .arg(timeout_ms.to_string())
            .arg("--policy")
            .arg(policy_path);
        if let Some(dir) = records {
            command
                .arg("--record")
                .arg(dir.join(format!("{}.jsonl", case.name)));
        }
        command
            .arg("--")
            .args(&case.command)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let started = Instant::now();
        let status = command
            .status()
            .map_err(|error| format!("cannot run case {:?}: {error}", case.name))?;
        let duration_ms = started.elapsed().as_millis() as u64;
        let exit_code = status.code();
        let (outcome, detail) = verdict(case.expectation, exit_code);
        reports.push(CaseReport {
            name: case.name.clone(),
            expectation: case.expectation,
            verdict: outcome,
            exit_code,
            duration_ms,
            detail,
        });
    }

    Ok(VerifyReport::new(
        ReportPolicy {
            path: policy_path.display().to_string(),
            version: policy.version,
            fingerprint: run::fingerprint(&document),
        },
        reports,
        run::now_ms(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASES: &str = r#"
cases:
  - name: legitimate-write
    expectation: allow
    command: ["/bin/sh", "-c", "printf ok > /workspace/out.txt"]
  - name: forbidden-read
    expectation: deny
    command: ["/bin/sh", "-c", "cat /proc/self/status"]
  - name: mystery
    command: ["/bin/true"]
"#;

    #[test]
    fn case_files_are_validated_before_anything_runs() {
        let file = CaseFile::from_yaml_str(CASES).expect("valid cases");
        assert_eq!(file.cases.len(), 3);
        assert_eq!(file.cases[0].expectation, Some(Expectation::Allow));
        assert_eq!(file.cases[2].expectation, None);

        assert!(CaseFile::from_yaml_str("cases: []").is_err());
        assert!(CaseFile::from_yaml_str("cases:\n  - name: x\n    command: []").is_err());
        assert!(
            CaseFile::from_yaml_str(
                "cases:\n  - name: x\n    command: [\"true\"]\n  - name: x\n    command: [\"true\"]"
            )
            .is_err()
        );
        assert!(
            CaseFile::from_yaml_str("cases:\n  - name: x\n    command: [\"true\"]\n    extra: 1")
                .is_err()
        );
    }

    #[test]
    fn allow_cases_must_run() {
        assert_eq!(verdict(Some(Expectation::Allow), Some(0)).0, Verdict::Pass);
        assert_eq!(verdict(Some(Expectation::Allow), Some(7)).0, Verdict::Fail);
        assert_eq!(
            verdict(Some(Expectation::Allow), Some(125)).0,
            Verdict::Fail
        );
        assert_eq!(
            verdict(Some(Expectation::Allow), Some(124)).0,
            Verdict::Pending
        );
    }

    #[test]
    fn deny_cases_must_be_refused() {
        assert_eq!(verdict(Some(Expectation::Deny), Some(1)).0, Verdict::Pass);
        assert_eq!(verdict(Some(Expectation::Deny), Some(0)).0, Verdict::Fail);
        // A sandbox that refused to start proves nothing about the policy.
        assert_eq!(
            verdict(Some(Expectation::Deny), Some(125)).0,
            Verdict::Pending
        );
        assert_eq!(
            verdict(Some(Expectation::Deny), Some(124)).0,
            Verdict::Pending
        );
    }

    #[test]
    fn undeclared_expectations_stay_pending() {
        let (outcome, detail) = verdict(None, Some(3));
        assert_eq!(outcome, Verdict::Pending);
        assert!(detail.contains("observed exit 3"), "{detail}");
        assert_eq!(verdict(None, None).0, Verdict::Pending);
    }
}
