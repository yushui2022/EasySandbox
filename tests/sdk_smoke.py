#!/usr/bin/env python3
"""Cross-SDK acceptance tests for the P5 clients.

The Python and TypeScript SDKs must turn the same inputs into the same
normalized request, the same classified outcome and the same normalized
verification report.  Both are driven through their command line entries with
one shared JSON spec, so the comparison is between the SDKs and not between two
test harnesses.

The TypeScript half needs Node with erasable-syntax support
(`node --experimental-strip-types`, Node >= 22.6).  Set ``EASY_SANDBOX_NODE`` to
a node binary, or have ``node`` on PATH; without one the TypeScript checks are
reported as skipped, never as passed.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

MINIMUM_NODE = (22, 6)

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
PYTHON_SDK = PROJECT_ROOT / "sdk" / "python"
TYPESCRIPT_SDK = PROJECT_ROOT / "sdk" / "typescript" / "easysandbox.ts"
REPORT_SCHEMA = PROJECT_ROOT / "docs" / "report.schema.json"

GOOD_POLICY = """\
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
  deny: []
mode: enforce
"""

BROKEN_POLICY = GOOD_POLICY.replace("version: 1", "version: 1\nunexpected: true")

VERIFY_CASES = """\
cases:
  - name: legit-read
    expectation: allow
    command: ["/bin/probe", "allowed-read", "/bin/probe"]
  - name: forbidden-write
    expectation: deny
    command: ["/bin/probe", "allowed-write", "/tmp/sdk-tmp.txt"]
  - name: unclear
    command: ["/bin/probe", "identity"]
"""


def node_version(node: str) -> tuple[int, int] | None:
    try:
        finished = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=20)
    except OSError:
        return None
    match = re.match(r"v(\d+)\.(\d+)", finished.stdout.strip())
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, help="path to easy-sandbox")
    parser.add_argument("--scratch", default="/mnt/g/DevCache/Temp/EasySandbox")
    args = parser.parse_args()
    scratch = pathlib.Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {"suite": "easy-sandbox-p5-sdk", "platform": sys.platform, "tests": []}

    def record(name: str, ok: bool, detail: str = "", **extra: Any) -> None:
        item: dict[str, Any] = {"name": name, "ok": ok}
        if detail:
            item["detail"] = detail
        item.update(extra)
        result["tests"].append(item)

    def finish(status: str) -> int:
        result["status"] = status
        result["scratch"] = str(scratch)
        report = scratch / "sdk-smoke-result.json"
        report.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0 if status == "pass" else 1

    if not sys.platform.startswith("linux"):
        result["note"] = "P5 acceptance requires Linux namespaces; run from Linux/WSL."
        return finish("unsupported-platform")

    binary = pathlib.Path(args.binary).resolve()
    if not binary.is_file():
        record("binary-exists", False, f"not a file: {binary}")
        return finish("invalid-input")

    node = os.environ.get("EASY_SANDBOX_NODE") or shutil.which("node")
    node_ok = False
    if node:
        version = node_version(node)
        node_ok = version is not None and version >= MINIMUM_NODE
        record(
            "typescript-runtime",
            node_ok,
            f"{node} reports {version}; need >= {MINIMUM_NODE[0]}.{MINIMUM_NODE[1]} for --experimental-strip-types",
        )
    else:
        record(
            "typescript-runtime",
            False,
            "no node on PATH and EASY_SANDBOX_NODE is unset; the TypeScript checks are skipped",
            skipped=True,
        )

    # --- fixtures -----------------------------------------------------------
    run_dir = pathlib.Path(
        tempfile.mkdtemp(prefix="easysandbox-sdk-", dir=os.environ.get("EASY_SANDBOX_LINUX_TMP", "/tmp"))
    )
    rootfs = run_dir / "rootfs"
    workspace = run_dir / "workspace"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "tmp").mkdir()
    workspace.mkdir()
    cc = shutil.which("cc") or shutil.which("clang")
    if cc is None:
        record("compiler-available", False, "cc/clang not found")
        return finish("invalid-input")
    probe = rootfs / "bin" / "probe"
    compiled = subprocess.run(
        [
            cc, "-static", "-O2", "-Wall", "-Wextra", "-o", str(probe),
            str(PROJECT_ROOT / "tests" / "probe.c"),
        ],
        capture_output=True,
        text=True,
    )
    if compiled.returncode != 0:
        record("compile-static-probe", False, compiled.stderr[-2000:])
        return finish("probe-build-failed")
    record("compile-static-probe", True)

    fixtures = scratch / "p5"
    fixtures.mkdir(exist_ok=True)
    good_policy = fixtures / "good.yaml"
    good_policy.write_text(GOOD_POLICY, encoding="utf-8")
    broken_policy = fixtures / "broken.yaml"
    broken_policy.write_text(BROKEN_POLICY, encoding="utf-8")
    cases_file = fixtures / "cases.yaml"
    cases_file.write_text(VERIFY_CASES, encoding="utf-8")

    def spec(**overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "binary": str(binary),
            "rootfs": str(rootfs),
            "workspace": str(workspace),
            "command": ["/bin/probe", "identity"],
            "timeout_ms": 5000,
        }
        base.update(overrides)
        return base

    def run_python(command: str, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(PYTHON_SDK)
        return subprocess.run(
            [sys.executable, "-m", "easysandbox", command],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=environment,
            timeout=120,
        )

    def run_typescript(command: str, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
        assert node is not None
        return subprocess.run(
            [node, "--experimental-strip-types", str(TYPESCRIPT_SDK), command],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=120,
        )

    def compare(name: str, payload: dict[str, Any], python_command: str | None = None) -> None:
        command = python_command or name
        py = run_python(command, payload)
        record(f"{name}-python-succeeded", py.returncode == 0, py.stderr[-300:])
        if not node_ok:
            return
        ts = run_typescript(command, payload)
        record(f"{name}-typescript-succeeded", ts.returncode == 0, ts.stderr[-300:])
        record(
            f"{name}-byte-identical",
            py.stdout == ts.stdout and py.stdout.strip() != "",
            f"python={py.stdout[:200]!r}\ntypescript={ts.stdout[:200]!r}",
        )

    # --- the same normalized request ---------------------------------------
    rich = spec(
        policy=str(good_policy),
        timeout_ms=4321,
        memory_mib=256,
        cpu_seconds=7,
        max_processes=16,
        secure=True,
        proxy_allow=["api.example.com:443", "other.example.com:8443"],
        record=str(run_dir / "rich.jsonl"),
        command=["/bin/probe", "identity"],
    )
    compare("canonical", rich)

    # --- the same classified outcome ---------------------------------------
    compare("run", spec(command=["/bin/probe", "identity"]))
    compare("run", spec(timeout_ms=300, command=["/bin/probe", "sleep", "2"]), python_command="run")
    compare("run", spec(policy=str(broken_policy)), python_command="run")

    abi_probe = subprocess.run(
        [
            str(binary), "run", "--rootfs", str(rootfs), "--workspace", str(workspace),
            "--", "/bin/probe", "landlock-abi",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    abi_ok = abi_probe.returncode == 0
    compare("run", spec(policy=str(good_policy)), python_command="run")

    # --- the same normalized report ----------------------------------------
    verify_spec = spec(policy=str(good_policy), cases=str(cases_file), report=str(run_dir / "report.json"))
    compare("verify", verify_spec)

    # --- outcome classification is what the caller sees ---------------------
    python_outcomes = {}
    for label, payload in [
        ("exited", spec(command=["/bin/probe", "identity"])),
        ("timeout", spec(timeout_ms=300, command=["/bin/probe", "sleep", "2"])),
        ("policy_rejected", spec(policy=str(broken_policy))),
        ("enforcement", spec(policy=str(good_policy))),
    ]:
        finished = run_python("run", payload)
        outcome = json.loads(finished.stdout)["outcome"] if finished.stdout else "no-output"
        python_outcomes[label] = outcome
    record("python-classifies-payload-exit", python_outcomes["exited"] == "exited", python_outcomes["exited"])
    record("python-classifies-timeout", python_outcomes["timeout"] == "timeout", python_outcomes["timeout"])
    record(
        "python-classifies-policy-rejection",
        python_outcomes["policy_rejected"] == "policy_rejected",
        python_outcomes["policy_rejected"],
    )
    record(
        "python-classifies-enforcement-availability",
        python_outcomes["enforcement"]
        == ("exited" if abi_ok else "enforcement_unavailable"),
        f"{python_outcomes['enforcement']} (landlock ABI ok={abi_ok})",
    )

    verify_outcome = json.loads(run_python("verify", verify_spec).stdout)["outcome"]
    record(
        "verify-outcome-reflects-the-verdicts",
        verify_outcome == ("pending" if abi_ok else "failed"),
        f"{verify_outcome} (landlock ABI ok={abi_ok})",
    )
    if node_ok:
        ts_verify = json.loads(run_typescript("verify", verify_spec).stdout)
        record(
            "typescript-agrees-on-verify-outcome",
            ts_verify["outcome"] == verify_outcome,
            f"python={verify_outcome} typescript={ts_verify['outcome']}",
        )

    # --- the Python surface itself -----------------------------------------
    sys.path.insert(0, str(PYTHON_SDK))
    import easysandbox  # noqa: E402  (imported after PYTHONPATH is set)

    schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
    record(
        "report-schema-is-shipped",
        schema.get("title", "").startswith("EasySandbox verification report"),
        json.dumps(schema["required"]),
    )

    from easysandbox import RunRequest, Sandbox  # noqa: E402

    sandbox = Sandbox(binary)
    streamed = sandbox.stream(
        RunRequest(
            rootfs=str(rootfs),
            workspace=str(workspace),
            command=["/bin/probe", "identity"],
        )
    )
    kinds = [event.get("kind") for event in streamed]
    record("python-stream-yields-events", kinds[:1] == ["run-started"], json.dumps(kinds))
    record(
        "python-stream-exposes-the-result",
        streamed.result is not None and streamed.result.outcome is easysandbox.Outcome.EXITED,
        f"outcome={getattr(streamed.result, 'outcome', None)}",
    )

    try:
        easysandbox.validate_report({"v": 1})
        record("python-rejects-broken-reports", False, "no error raised")
    except easysandbox.ReportError as error:
        record("python-rejects-broken-reports", True, str(error))

    verified = sandbox.verify(
        policy=str(good_policy),
        cases=str(cases_file),
        rootfs=str(rootfs),
        workspace=str(workspace),
    )
    # Without Landlock ABI 3 every case run is refused, so the verdicts differ
    # from a capable kernel; what must hold either way is that the SDK reads and
    # validates a real report.
    expected_outcome = (
        easysandbox.VerifyOutcome.PENDING if abi_ok else easysandbox.VerifyOutcome.FAILED
    )
    record(
        "python-verify-reads-the-report",
        verified.outcome is expected_outcome and verified.report is not None,
        f"outcome={verified.outcome} (landlock ABI ok={abi_ok})",
    )
    canonical = verified.canonical()["report"]
    record(
        "python-verify-canonicalizes-the-report",
        canonical is not None and "generated_at_ms" not in canonical,
        json.dumps(canonical)[:200],
    )

    result["node_ok"] = node_ok
    result["landlock_abi_ok"] = abi_ok
    result["run_dir"] = str(run_dir)
    failures = [test for test in result["tests"] if not test.get("ok") and not test.get("skipped")]
    return finish("pass" if not failures else "fail")


if __name__ == "__main__":
    raise SystemExit(main())
