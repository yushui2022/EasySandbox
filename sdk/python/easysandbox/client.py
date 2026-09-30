"""Process-level client for the easy-sandbox launcher.

The SDK never reimplements isolation.  It builds an argument vector, runs the
launcher, and interprets what comes back: the exit status, the launcher's
stable failure markers, and the JSONL run record.  A caller can therefore
distinguish a payload exit code, a timeout, a refused policy, an unavailable
enforcement primitive and a verification verdict without parsing prose.

Two shapes are shared with the TypeScript SDK, byte for byte:

* ``RunRequest.canonical()`` -- the normalized request (defaults filled, keys
  sorted, argument vector included);
* ``RunResult.canonical()`` / ``VerifyResult.canonical()`` -- the normalized
  outcome, with volatile fields (timings, sequence numbers, absolute paths)
  removed so two runs and two SDKs can be compared directly.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

DEFAULT_TIMEOUT_MS = 30_000

#: Marks a launcher failure caused by the policy document itself.
POLICY_REJECTED_MARKER = "policy-rejected"
#: Marks a launcher failure caused by an enforcement primitive (Landlock ABI,
#: seccomp install, proxy socket) rather than by the policy document.
ENFORCEMENT_MARKER = "enforcement-failed"


class Outcome(str, Enum):
    """What a run means, derived from the launcher's exit status."""

    EXITED = "exited"
    TIMEOUT = "timeout"
    POLICY_REJECTED = "policy_rejected"
    ENFORCEMENT_UNAVAILABLE = "enforcement_unavailable"
    EXEC_FAILED = "exec_failed"
    SETUP_FAILED = "setup_failed"


class VerifyOutcome(str, Enum):
    """What a verification run means."""

    ALL_PASSED = "all_passed"
    FAILED = "failed"
    PENDING = "pending"
    REJECTED = "rejected"


class SandboxError(RuntimeError):
    """The launcher could not be run at all."""


class ReportError(ValueError):
    """A verification report does not match the documented shape."""


@dataclass(frozen=True)
class RunRequest:
    """One sandbox run, before it becomes an argument vector."""

    rootfs: str
    workspace: str
    command: Sequence[str]
    policy: str | None = None
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    memory_mib: int | None = None
    cpu_seconds: int | None = None
    max_processes: int | None = None
    secure: bool = False
    proxy_allow: Sequence[str] = ()
    record: str | None = None

    def argv(self) -> list[str]:
        """The launcher arguments, in a fixed order."""
        argv = [
            "run",
            "--rootfs",
            self.rootfs,
            "--workspace",
            self.workspace,
            "--timeout-ms",
            str(self.timeout_ms),
        ]
        if self.memory_mib is not None:
            argv += ["--memory-mib", str(self.memory_mib)]
        if self.cpu_seconds is not None:
            argv += ["--cpu-seconds", str(self.cpu_seconds)]
        if self.max_processes is not None:
            argv += ["--max-processes", str(self.max_processes)]
        if self.secure:
            argv.append("--secure")
        if self.policy is not None:
            argv += ["--policy", self.policy]
        for entry in self.proxy_allow:
            argv += ["--proxy-allow", entry]
        if self.record is not None:
            argv += ["--record", self.record]
        argv.append("--")
        argv += list(self.command)
        return argv

    def canonical(self) -> dict[str, Any]:
        """Normalized request: every default spelled out, keys sorted."""
        return {
            "command": list(self.command),
            "cpu_seconds": self.cpu_seconds,
            "max_processes": self.max_processes,
            "memory_mib": self.memory_mib,
            "policy": self.policy,
            "proxy_allow": list(self.proxy_allow),
            "record": self.record,
            "rootfs": self.rootfs,
            "secure": self.secure,
            "timeout_ms": self.timeout_ms,
            "workspace": self.workspace,
            "argv": self.argv(),
        }

    def canonical_json(self) -> str:
        return json.dumps(self.canonical(), indent=2, sort_keys=True)


@dataclass
class RunResult:
    """Everything the launcher reported about one run."""

    outcome: Outcome
    exit_code: int
    request: RunRequest
    stdout: str = ""
    stderr: str = ""
    record_path: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def rejected(self) -> bool:
        return self.outcome in (Outcome.POLICY_REJECTED, Outcome.ENFORCEMENT_UNAVAILABLE)

    def canonical(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "exit_code": self.exit_code,
            "request": self.request.canonical(),
            "events": [event_kinds(event) for event in self.events],
        }


@dataclass
class VerifyResult:
    """A verification run and the report it produced."""

    outcome: VerifyOutcome
    exit_code: int
    report: dict[str, Any]

    def canonical(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "exit_code": self.exit_code,
            # A rejected verification never produced a report.
            "report": canonical_report(self.report) if self.report else None,
        }


def event_kinds(event: Mapping[str, Any]) -> str:
    """The `kind` of one record event, or `unknown`."""
    kind = event.get("kind")
    return kind if isinstance(kind, str) else "unknown"


def classify(exit_code: int, stderr: str) -> Outcome:
    """Map an exit status and the launcher's markers onto an outcome."""
    if exit_code == 124:
        return Outcome.TIMEOUT
    if exit_code == 126:
        return Outcome.EXEC_FAILED
    if exit_code == 125:
        if POLICY_REJECTED_MARKER in stderr:
            return Outcome.POLICY_REJECTED
        if ENFORCEMENT_MARKER in stderr:
            return Outcome.ENFORCEMENT_UNAVAILABLE
        return Outcome.SETUP_FAILED
    return Outcome.EXITED


def parse_events(record: str | os.PathLike[str] | None) -> list[dict[str, Any]]:
    """Read a JSONL run record into memory, ignoring blank lines."""
    if not record:
        return []
    path = Path(record)
    if not path.is_file():
        return []
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            # A writer may be in the middle of a line; the next read wins.
            continue
    return events


REPORT_KEYS = {"v", "kind", "generated_at_ms", "policy", "cases", "summary"}
REPORT_POLICY_KEYS = {"path", "version", "fingerprint"}
REPORT_CASE_KEYS = {"name", "expectation", "verdict", "exit_code", "duration_ms", "detail"}
REPORT_VERDICTS = {"pass", "fail", "pending"}


def validate_report(report: Mapping[str, Any]) -> None:
    """Check a report against docs/report.schema.json.

    The same checks exist in the TypeScript SDK, so a caller gets the same
    acceptance decision in both languages.  No JSON Schema dependency is used:
    the report is small and its shape is fixed.
    """
    if set(report) != REPORT_KEYS:
        raise ReportError(f"report keys differ: {sorted(set(report))}")
    if report["v"] != 1:
        raise ReportError(f"unsupported report version {report['v']!r}")
    if report["kind"] != "easy-sandbox-verify-report":
        raise ReportError(f"unexpected report kind {report['kind']!r}")
    policy = report["policy"]
    if not isinstance(policy, Mapping) or set(policy) != REPORT_POLICY_KEYS:
        raise ReportError("report policy block has the wrong shape")
    if not isinstance(policy["version"], int) or not isinstance(policy["fingerprint"], str):
        raise ReportError("report policy block has the wrong types")
    cases = report["cases"]
    if not isinstance(cases, list) or not cases:
        raise ReportError("a report must contain at least one case")
    for case in cases:
        if not isinstance(case, Mapping) or not set(case) <= REPORT_CASE_KEYS:
            raise ReportError(f"case has unexpected fields: {sorted(set(case))}")
        if case.get("verdict") not in REPORT_VERDICTS:
            raise ReportError(f"unknown verdict {case.get('verdict')!r}")
        if "name" not in case or "duration_ms" not in case or "detail" not in case:
            raise ReportError("case is missing a required field")
    summary = report["summary"]
    if not isinstance(summary, Mapping) or set(summary) != {"total", "passed", "failed", "pending"}:
        raise ReportError("summary block has the wrong shape")
    if summary["total"] != len(cases):
        raise ReportError("summary total does not match the case count")
    if summary["passed"] + summary["failed"] + summary["pending"] != summary["total"]:
        raise ReportError("summary does not add up")


def canonical_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Drop volatile fields so two runs of the same cases compare equal."""
    validate_report(report)
    return {
        "v": report["v"],
        "kind": report["kind"],
        "policy": {
            "version": report["policy"]["version"],
            "fingerprint": report["policy"]["fingerprint"],
        },
        "cases": [
            {
                "name": case["name"],
                "expectation": case.get("expectation"),
                "verdict": case["verdict"],
                "exit_code": case.get("exit_code"),
                "detail": case["detail"],
            }
            for case in report["cases"]
        ],
        "summary": dict(report["summary"]),
    }


class Sandbox:
    """Runs one launcher binary on behalf of a caller."""

    def __init__(self, binary: str | os.PathLike[str]):
        self.binary = str(binary)

    def _spawn(self, argv: Sequence[str]) -> subprocess.Popen[str]:
        try:
            return subprocess.Popen(
                [self.binary, *argv],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as error:  # pragma: no cover - depends on the host
            raise SandboxError(f"cannot start {self.binary}: {error}") from error

    def run(self, request: RunRequest) -> RunResult:
        """Run to completion and return the classified result."""
        temporary_directory = None
        effective = request
        if request.record is None:
            # The record is always collected, so events are available even when
            # the caller did not ask for a file.  The canonical form keeps the
            # caller's request, so this internal path never leaks into it.
            temporary_directory = tempfile.mkdtemp(prefix="easysandbox-")
            effective = replace(request, record=str(Path(temporary_directory) / "run.jsonl"))
        try:
            process = self._spawn(effective.argv())
            stdout, stderr = process.communicate()
            exit_code = process.returncode
            events = parse_events(effective.record)
        finally:
            if temporary_directory is not None:
                shutil.rmtree(temporary_directory, ignore_errors=True)
        return RunResult(
            outcome=classify(exit_code, stderr),
            exit_code=exit_code,
            request=request,
            stdout=stdout,
            stderr=stderr,
            record_path=request.record,
            events=events,
        )

    def stream(self, request: RunRequest, poll_interval: float = 0.02) -> "RunStream":
        """Yield events while the run happens, then expose the result."""
        return RunStream(self, request, poll_interval)

    def verify(
        self,
        *,
        policy: str,
        cases: str,
        rootfs: str,
        workspace: str,
        report: str | None = None,
        records: str | None = None,
        timeout_ms: int | None = None,
    ) -> VerifyResult:
        """Run independent cases and return the validated report."""
        with tempfile.TemporaryDirectory(prefix="easysandbox-verify-") as directory:
            report_path = report or str(Path(directory) / "report.json")
            argv = [
                "verify",
                "--policy",
                policy,
                "--cases",
                cases,
                "--rootfs",
                rootfs,
                "--workspace",
                workspace,
                "--report",
                report_path,
            ]
            if records is not None:
                argv += ["--records", records]
            if timeout_ms is not None:
                argv += ["--timeout-ms", str(timeout_ms)]
            process = self._spawn(argv)
            _stdout, stderr = process.communicate()
            exit_code = process.returncode

            if exit_code == 125:
                return VerifyResult(
                    outcome=VerifyOutcome.REJECTED,
                    exit_code=exit_code,
                    report={},
                )
            path = Path(report_path)
            if not path.is_file():
                raise ReportError(f"verify wrote no report; stderr={stderr[-300:]}")
            parsed = json.loads(path.read_text(encoding="utf-8"))
            validate_report(parsed)
            if exit_code == 0:
                outcome = VerifyOutcome.ALL_PASSED
            elif exit_code == 1:
                outcome = VerifyOutcome.FAILED
            else:
                outcome = VerifyOutcome.PENDING
            return VerifyResult(outcome=outcome, exit_code=exit_code, report=parsed)


class RunStream:
    """Iterator over a run's events, available while the sandbox is running."""

    def __init__(self, sandbox: Sandbox, request: RunRequest, poll_interval: float):
        self._sandbox = sandbox
        self._request = request
        self._poll_interval = poll_interval
        self.result: RunResult | None = None

    def __iter__(self) -> Iterator[dict[str, Any]]:
        handle, record = tempfile.mkstemp(prefix="easysandbox-stream-", suffix=".jsonl")
        os.close(handle)
        effective = replace(self._request, record=record)
        process = self._sandbox._spawn(effective.argv())
        collected: list[dict[str, Any]] = []
        try:
            while True:
                for event in parse_events(record)[len(collected) :]:
                    collected.append(event)
                    yield event
                if process.poll() is not None:
                    for event in parse_events(record)[len(collected) :]:
                        collected.append(event)
                        yield event
                    break
                time.sleep(self._poll_interval)
            stdout, stderr = process.communicate()
            # Only a fully drained stream has a result; an aborted iteration
            # leaves `result` unset and the temporary record removed.
            self.result = RunResult(
                outcome=classify(process.returncode, stderr),
                exit_code=process.returncode,
                request=self._request,
                stdout=stdout,
                stderr=stderr,
                record_path=self._request.record,
                events=collected,
            )
        finally:
            Path(record).unlink(missing_ok=True)
