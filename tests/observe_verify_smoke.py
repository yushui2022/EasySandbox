#!/usr/bin/env python3
"""Linux-only acceptance tests for the P4 observe/enforce/verify pipeline.

Three things are checked:

* a run can be recorded as JSONL, with the frozen policy document inside the
  record and one `restriction` line per enforcement layer;
* observe mode records the policy's restrictions and installs none of them
  (on a kernel with Landlock ABI 3; older kernels must still fail closed);
* `verify` turns independent cases into a report where a case that declared no
  expectation stays `pending` instead of being guessed at.

The report shape is validated against ``docs/report.schema.json`` by hand: the
suite only depends on the standard library.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import Any

OBSERVE_POLICY = """\
version: 1
filesystem:
  read: ["/bin"]
  write: ["/workspace"]
network:
  mode: disabled
  allow: []
limits:
  timeout_ms: 5000
syscalls:
  deny: [uname]
mode: observe
"""

ENFORCE_POLICY = OBSERVE_POLICY.replace("mode: observe", "mode: enforce")

# A `deny` case is written as a command that *fails* when the policy refuses it,
# which is what an ordinary workload looks like: it reports its own failure.
CASES = """\
cases:
  - name: legitimate-bin-read
    expectation: allow
    command: ["/bin/probe", "allowed-read", "/bin/probe"]
  - name: forbidden-unlisted-write
    expectation: deny
    command: ["/bin/probe", "allowed-write", "/tmp/verify-tmp.txt"]
  - name: undeclared-mystery
    command: ["/bin/probe", "identity"]
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, help="path to easy-sandbox")
    parser.add_argument("--scratch", default="/mnt/g/DevCache/Temp/EasySandbox")
    args = parser.parse_args()
    scratch = pathlib.Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "suite": "easy-sandbox-p4-observe-verify",
        "platform": sys.platform,
        "tests": [],
    }

    def record(name: str, ok: bool, detail: str = "", **extra: Any) -> None:
        item: dict[str, Any] = {"name": name, "ok": ok}
        if detail:
            item["detail"] = detail
        item.update(extra)
        result["tests"].append(item)

    def finish(status: str) -> int:
        result["status"] = status
        result["scratch"] = str(scratch)
        report = scratch / "observe-verify-result.json"
        report.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0 if status == "pass" else 1

    if not sys.platform.startswith("linux"):
        result["note"] = "P4 acceptance requires Linux namespaces; run from Linux/WSL."
        return finish("unsupported-platform")

    binary = pathlib.Path(args.binary).resolve()
    cc = shutil.which("cc") or shutil.which("clang")
    if not binary.is_file() or not cc:
        record("binary-and-compiler-available", False, f"binary={binary} cc={cc}")
        return finish("invalid-input")

    run_dir = pathlib.Path(
        tempfile.mkdtemp(
            prefix="easy-sandbox-observe-",
            dir=os.environ.get("EASY_SANDBOX_LINUX_TMP", "/tmp"),
        )
    )
    rootfs = run_dir / "rootfs"
    workspace = run_dir / "workspace"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "tmp").mkdir()
    workspace.mkdir()
    probe = rootfs / "bin" / "probe"
    compile_proc = subprocess.run(
        [
            cc, "-static", "-O2", "-Wall", "-Wextra", "-o", str(probe),
            str(pathlib.Path(__file__).with_name("probe.c")),
        ],
        capture_output=True,
        text=True,
    )
    if compile_proc.returncode != 0:
        record("compile-static-probe", False, compile_proc.stderr[-4000:])
        return finish("probe-build-failed")
    record("compile-static-probe", True)

    fixtures = scratch / "p4"
    fixtures.mkdir(exist_ok=True)
    observe_policy = fixtures / "observe.yaml"
    observe_policy.write_text(OBSERVE_POLICY, encoding="utf-8")
    enforce_policy = fixtures / "enforce.yaml"
    enforce_policy.write_text(ENFORCE_POLICY, encoding="utf-8")
    cases_file = fixtures / "cases.yaml"
    cases_file.write_text(CASES, encoding="utf-8")

    base_env = os.environ.copy()

    def run_launcher(flags: list[str], *probe_args: str) -> subprocess.CompletedProcess[str]:
        command = [
            str(binary), "run",
            "--rootfs", str(rootfs),
            "--workspace", str(workspace),
            *flags,
            "--", "/bin/probe", *probe_args,
        ]
        return subprocess.run(command, env=base_env, capture_output=True, text=True, timeout=60)

    def read_events(path: pathlib.Path) -> list[dict[str, Any]]:
        events = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events

    abi_proc = run_launcher([], "landlock-abi")
    abi_ok = abi_proc.returncode == 0

    # --- recording works for every mode -------------------------------------
    for mode, policy_path in (("observe", observe_policy), ("enforce", enforce_policy)):
        record_path = fixtures / f"{mode}.jsonl"
        record_path.unlink(missing_ok=True)
        proc = run_launcher(["--policy", str(policy_path), "--record", str(record_path)], "identity")
        record(f"{mode}-run-finished", proc.returncode in (0, 125), f"exit={proc.returncode}")
        if not record_path.is_file():
            record(f"{mode}-record-written", False, "no record file")
            continue
        events = read_events(record_path)
        record(f"{mode}-record-written", True, f"events={len(events)}")
        started = [event for event in events if event["kind"] == "run-started"]
        record(
            f"{mode}-record-freezes-the-policy",
            bool(started)
            and started[0]["mode"] == mode
            and f"mode: {mode}" in started[0]["policy"],
            json.dumps(started[0])[:200] if started else "no run-started event",
        )
        record(
            f"{mode}-record-states-the-outcome",
            any(event["kind"] == "task-result" for event in events),
            json.dumps(events[-1])[:200],
        )
        for event in events:
            record(f"{mode}-record-shape", "seq" in event and "run_id" in event, json.dumps(event)[:200])
            break

        restrictions = [event for event in events if event["kind"] == "restriction"]
        candidates = [event for event in events if event["kind"] == "candidate"]
        if not abi_ok:
            continue
        installed = {event["layer"]: event["installed"] for event in restrictions}
        if mode == "enforce":
            record(
                "enforce-installs-every-layer",
                installed.get("p1-baseline") is True
                and installed.get("policy-landlock") is True
                and installed.get("policy-seccomp") is True,
                json.dumps(installed),
            )
        else:
            record(
                "observe-installs-only-the-floor",
                installed.get("p1-baseline") is True
                and installed.get("policy-landlock") is False
                and installed.get("policy-seccomp") is False,
                json.dumps(installed),
            )
            record(
                "observe-records-candidates-without-approving-them",
                len(candidates) >= 4
                and all(candidate["state"] == "unapproved" for candidate in candidates),
                json.dumps(candidates[:3]),
            )

    # --- verify -------------------------------------------------------------
    report_path = fixtures / "report.json"
    report_path.unlink(missing_ok=True)
    records_dir = fixtures / "records"
    records_dir.mkdir(exist_ok=True)
    verify_cmd = [
        str(binary), "verify",
        "--policy", str(enforce_policy),
        "--cases", str(cases_file),
        "--rootfs", str(rootfs),
        "--workspace", str(workspace),
        "--report", str(report_path),
        "--records", str(records_dir),
    ]
    verify_proc = subprocess.run(verify_cmd, env=base_env, capture_output=True, text=True, timeout=120)
    record(
        "verify-exits-nonzero-when-cases-are-not-settled",
        verify_proc.returncode in (1, 2),
        f"exit={verify_proc.returncode}; stderr={verify_proc.stderr[-300:]}",
    )
    if not report_path.is_file():
        record("verify-writes-a-report", False, verify_proc.stderr[-300:])
    else:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        record("verify-writes-a-report", True)
        record(
            "verify-report-has-the-documented-shape",
            report.get("v") == 1
            and report.get("kind") == "easy-sandbox-verify-report"
            and set(report) == {"v", "kind", "generated_at_ms", "policy", "cases", "summary"}
            and set(report["policy"]) == {"path", "version", "fingerprint"}
            and all(
                set(case) <= {"name", "expectation", "verdict", "exit_code", "duration_ms", "detail"}
                and case["verdict"] in ("pass", "fail", "pending")
                for case in report["cases"]
            ),
            json.dumps(report)[:300],
        )
        record(
            "verify-report-summary-is-consistent",
            report["summary"]["total"] == len(report["cases"])
            and report["summary"]["passed"]
            + report["summary"]["failed"]
            + report["summary"]["pending"]
            == report["summary"]["total"],
            json.dumps(report["summary"]),
        )
        verdicts = {case["name"]: case["verdict"] for case in report["cases"]}
        record(
            "verify-keeps-undeclared-cases-pending",
            verdicts.get("undeclared-mystery") == "pending",
            json.dumps(verdicts),
        )
        if abi_ok:
            record(
                "verify-passes-both-directions",
                verdicts.get("legitimate-bin-read") == "pass"
                and verdicts.get("forbidden-unlisted-write") == "pass",
                json.dumps(verdicts),
            )
            record(
                "verify-records-every-case",
                all((records_dir / f"{name}.jsonl").is_file() for name in verdicts),
                f"present={sorted(path.name for path in records_dir.glob('*.jsonl'))}",
            )
        else:
            # Without Landlock ABI 3 every policy run is refused up front, so an
            # `allow` case can only fail and a `deny` case cannot be attributed.
            record(
                "verify-fails-closed-without-abi3",
                verdicts.get("legitimate-bin-read") == "fail"
                and verdicts.get("forbidden-unlisted-write") == "pending",
                json.dumps(verdicts),
            )
            record(
                "observe-fails-closed-without-abi3",
                run_launcher(
                    ["--policy", str(observe_policy), "--record", str(fixtures / "closed.jsonl")],
                    "identity",
                ).returncode
                == 125,
                "observe still pays for the P1 floor",
            )

    # --- request errors are rejected before anything runs --------------------
    bad_cases = {
        "empty": "cases: []",
        "duplicate-names": "cases:\n  - name: x\n    command: [\"true\"]\n  - name: x\n    command: [\"true\"]\n",
        "unknown-field": "cases:\n  - name: x\n    command: [\"true\"]\n    mode: allow\n",
        "no-command": "cases:\n  - name: x\n    command: []\n",
        "bad-expectation": "cases:\n  - name: x\n    expectation: maybe\n    command: [\"true\"]\n",
    }
    for name, text in bad_cases.items():
        path = fixtures / f"cases-{name}.yaml"
        path.write_text(text, encoding="utf-8")
        proc = subprocess.run(
            [
                str(binary), "verify",
                "--policy", str(enforce_policy),
                "--cases", str(path),
                "--rootfs", str(rootfs),
                "--workspace", str(workspace),
            ],
            env=base_env, capture_output=True, text=True, timeout=60,
        )
        record(f"verify-rejects-{name}", proc.returncode == 125, f"exit={proc.returncode}; {proc.stderr[-200:]}")

    observe_mode_verify = subprocess.run(
        [
            str(binary), "verify",
            "--policy", str(observe_policy),
            "--cases", str(cases_file),
            "--rootfs", str(rootfs),
            "--workspace", str(workspace),
        ],
        env=base_env, capture_output=True, text=True, timeout=60,
    )
    record(
        "verify-requires-an-enforce-mode-policy",
        observe_mode_verify.returncode == 125 and "enforce mode" in observe_mode_verify.stderr,
        observe_mode_verify.stderr[-200:],
    )

    result["landlock_abi_ok"] = abi_ok
    result["run_dir"] = str(run_dir)
    return finish("pass" if all(test.get("ok") for test in result["tests"]) else "fail")


if __name__ == "__main__":
    raise SystemExit(main())
