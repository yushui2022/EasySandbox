#!/usr/bin/env python3
"""Linux-only acceptance tests for the EasySandbox P2 policy layer.

The suite has two halves:

* policy documents that must be rejected *before* a sandbox starts (exit
  status 125), which are meaningful on every kernel; and
* enforcement checks that need Landlock ABI 3+, which report fail-closed
  behaviour on older kernels (WSL2 5.15 reports ABI 1) and are exercised for
  real by ``scripts/validate-vm.sh`` on the Ubuntu 6.8 kernel.

The enforcement half only asserts the promised boundary: a listed path can be
used, an unlisted path cannot, a policy can only tighten the P1 baseline, the
launcher still refuses to run as uid 0, and the exit-status contract holds.
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

VALID = """\
version: 1
filesystem:
  read: ["/bin"]
  write: ["/workspace"]
network:
  mode: disabled
  allow: []
limits:
  timeout_ms: 5000
  memory_mib: 256
  cpu_seconds: 5
  max_processes: 16
syscalls:
  deny: [uname]
mode: enforce
"""

# The rejected-document cases below are all mutations of VALID, so VALID itself
# must be free of document-level errors.  Otherwise a broken template would make
# every rejection case "pass" for the wrong reason.
DOCUMENT_ERROR_MARKERS = (
    "invalid policy",
    "policy YAML error",
    "cannot load policy",
    "unsupported syscall name",
    "is not executable yet",
)


def document_errors(stderr: str) -> str:
    return "; ".join(marker for marker in DOCUMENT_ERROR_MARKERS if marker in stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, help="path to easy-sandbox")
    parser.add_argument(
        "--scratch",
        default="/mnt/g/DevCache/Temp/EasySandbox",
        help="scratch directory; keep generated files off the system disk",
    )
    args = parser.parse_args()
    scratch = pathlib.Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "suite": "easy-sandbox-p2-policy",
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
        report = scratch / "policy-smoke-result.json"
        report.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0 if status == "pass" else 1

    if not sys.platform.startswith("linux"):
        result["note"] = "P2 acceptance requires Linux namespaces and Landlock; run from Linux/WSL."
        return finish("unsupported-platform")

    binary = pathlib.Path(args.binary).resolve()
    cc = shutil.which("cc") or shutil.which("clang")
    if not binary.is_file() or not cc:
        record("binary-and-compiler-available", False, f"binary={binary} cc={cc}")
        return finish("invalid-input")

    linux_run_base = pathlib.Path(os.environ.get("EASY_SANDBOX_LINUX_TMP", "/tmp"))
    run_dir = pathlib.Path(tempfile.mkdtemp(prefix="easy-sandbox-policy-", dir=linux_run_base))
    rootfs = run_dir / "rootfs"
    workspace = run_dir / "workspace"
    rootfs_bin = rootfs / "bin"
    (rootfs / "tmp").mkdir(parents=True)
    rootfs_bin.mkdir(parents=True)
    workspace.mkdir()
    (run_dir / "host-sentinel").write_text("host-only\n", encoding="utf-8")
    probe = rootfs_bin / "probe"

    compile_cmd = [
        cc,
        "-static",
        "-O2",
        "-Wall",
        "-Wextra",
        "-o",
        str(probe),
        str(pathlib.Path(__file__).with_name("probe.c")),
    ]
    compile_proc = subprocess.run(compile_cmd, capture_output=True, text=True)
    if compile_proc.returncode != 0:
        record("compile-static-probe", False, compile_proc.stderr[-4000:], command=compile_cmd)
        return finish("probe-build-failed")
    record("compile-static-probe", True)

    base_env = os.environ.copy()
    base_env["EASY_SANDBOX_SECRET"] = "must-not-cross-boundary"

    def run_launcher(
        flags: list[str], probe_args: list[str], extra_env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        cmd = [
            str(binary),
            "run",
            "--rootfs",
            str(rootfs),
            "--workspace",
            str(workspace),
            *flags,
            "--",
            "/bin/probe",
            *probe_args,
        ]
        return subprocess.run(
            cmd, env=extra_env or base_env, capture_output=True, text=True, timeout=60
        )

    def expect(name: str, proc: subprocess.CompletedProcess[str], code: int) -> None:
        record(
            name,
            proc.returncode == code,
            f"expected {code}, got {proc.returncode}; stderr={proc.stderr[-500:]}",
            returncode=proc.returncode,
        )

    policies = scratch / "policies"
    policies.mkdir(exist_ok=True)

    def policy(name: str, text: str) -> pathlib.Path:
        path = policies / f"{name}.yaml"
        path.write_text(text, encoding="utf-8")
        return path

    # --- documents that must be rejected before a sandbox exists (125) -------
    rejected: dict[str, str] = {
        "unknown-field": VALID.replace("version: 1", "version: 1\nextra: true"),
        "unsupported-version": VALID.replace("version: 1", "version: 2"),
        "relative-read-path": VALID.replace('read: ["/bin"]', 'read: ["bin"]'),
        "parent-dir-component": VALID.replace('read: ["/bin"]', 'read: ["/bin/../etc"]'),
        "root-write": VALID.replace('write: ["/workspace"]', 'write: ["/"]'),
        "duplicate-read-path": VALID.replace('read: ["/bin"]', 'read: ["/bin", "/bin"]'),
        "zero-timeout": VALID.replace("timeout_ms: 5000", "timeout_ms: 0"),
        "disabled-network-with-allow": VALID.replace(
            "  allow: []", "  allow:\n    - host: api.example.com\n      ports: [443]"
        ),
        "unknown-syscall-name": VALID.replace("deny: [uname]", "deny: [uname, not_a_syscall]"),
        "verify-mode": VALID.replace("mode: enforce", "mode: verify"),
    }
    for name, text in rejected.items():
        path = policy(name, text)
        proc = run_launcher(["--policy", str(path)], ["proc"])
        expect(f"rejects-{name}", proc, 125)
        # A document error must be reported before the kernel is touched; if
        # this run failed on the Landlock ABI instead, the document was accepted
        # and the case above proved nothing.
        record(
            f"rejects-{name}-before-enforcement",
            "Landlock ABI 3+" not in proc.stderr,
            proc.stderr[-300:],
        )

    # `network.mode: proxy` is a valid document since P3; only its enforcement
    # needs Landlock ABI 3, and tests/network_smoke.py covers that boundary.
    proxy_policy = policy(
        "proxy",
        VALID.replace(
            "  mode: disabled\n  allow: []",
            "  mode: proxy\n  allow:\n    - host: api.example.com\n      ports: [443]",
        ),
    )
    proxy_proc = run_launcher(["--policy", str(proxy_policy)], ["proc"])
    record(
        "accepts-proxy-network-policy",
        not document_errors(proxy_proc.stderr),
        document_errors(proxy_proc.stderr) or proxy_proc.stderr[-300:],
    )

    # `mode: observe` is a valid document since P4: it records the policy's
    # restrictions instead of installing them (see tests/observe_verify_smoke.py).
    observe_policy = policy("observe", VALID.replace("mode: enforce", "mode: observe"))
    observe_proc = run_launcher(
        ["--policy", str(observe_policy), "--record", str(policies / "observe.jsonl")], ["proc"]
    )
    record(
        "accepts-observe-mode-policy",
        not document_errors(observe_proc.stderr),
        document_errors(observe_proc.stderr) or observe_proc.stderr[-300:],
    )

    missing = policies / "does-not-exist.yaml"
    missing.unlink(missing_ok=True)
    expect("rejects-missing-policy-file", run_launcher(["--policy", str(missing)], ["proc"]), 125)

    missing_path = policy("missing-sandbox-path", VALID.replace('read: ["/bin"]', 'read: ["/bin", "/nope"]'))
    missing_proc = run_launcher(["--policy", str(missing_path)], ["proc"])
    expect("rejects-missing-sandbox-path", missing_proc, 125)
    record(
        "missing-sandbox-path-is-reported",
        "landlock open /nope" in missing_proc.stderr or "ABI 3" in missing_proc.stderr,
        missing_proc.stderr[-300:],
    )

    frozen = policy("frozen", VALID)
    expect(
        "rejects-internal-frozen-policy-on-run",
        run_launcher(
            ["--frozen-policy", frozen.read_text(encoding="utf-8")],
            ["proc"],
        ),
        64,
    )

    example = pathlib.Path(__file__).resolve().parent.parent / "docs" / "policy.example.yaml"
    if example.is_file():
        example_proc = run_launcher(["--policy", str(example)], ["proc"])
        # The shipped example lists paths this minimal rootfs does not contain,
        # so the run may still fail closed.  What matters here is that the
        # document itself never fails validation.
        record(
            "shipped-example-policy-is-valid",
            not document_errors(example_proc.stderr),
            document_errors(example_proc.stderr) or example_proc.stderr[-300:],
        )

    # --- enforcement needs Landlock ABI 3 -----------------------------------
    abi_proc = run_launcher([], ["landlock-abi"])
    abi_ok = abi_proc.returncode == 0
    valid_policy = policy("valid", VALID)
    if not abi_ok:
        record(
            "landlock-abi-probe",
            abi_proc.returncode == 2,
            f"expected 2 (ABI < 3) or 0, got {abi_proc.returncode}",
        )
        probe_proc = run_launcher(["--policy", str(valid_policy)], ["workspace-write"])
        expect("policy-fails-closed-without-abi3", probe_proc, 125)
        record(
            "policy-failure-names-landlock",
            "Landlock ABI 3+" in probe_proc.stderr,
            probe_proc.stderr[-300:],
        )
        record(
            "valid-policy-has-no-document-errors",
            not document_errors(probe_proc.stderr),
            document_errors(probe_proc.stderr) or probe_proc.stderr[-300:],
        )
        record(
            "enforcement-checks-deferred-to-vm",
            True,
            "kernel reports Landlock ABI < 3; scripts/validate-vm.sh runs these on 6.8",
        )
    else:
        record("landlock-abi-probe", True, "ABI >= 3")

        marker = workspace / "policy-write.txt"
        marker.unlink(missing_ok=True)
        allowed_proc = run_launcher(
            ["--policy", str(valid_policy)], ["allowed-write", "/workspace/policy-write.txt"]
        )
        expect("policy-allows-listed-write", allowed_proc, 0)
        record("policy-listed-write-landed", marker.is_file())
        record(
            "valid-policy-has-no-document-errors",
            not document_errors(allowed_proc.stderr),
            document_errors(allowed_proc.stderr) or allowed_proc.stderr[-300:],
        )

        expect(
            "policy-denies-unlisted-write",
            run_launcher(["--policy", str(valid_policy)], ["denied-write", "/tmp/policy-tmp.txt"]),
            0,
        )
        record("policy-unlisted-write-did-not-land", not (rootfs / "tmp" / "policy-tmp.txt").exists())
        expect(
            "policy-allows-listed-read",
            run_launcher(["--policy", str(valid_policy)], ["allowed-read", "/bin/probe"]),
            0,
        )
        expect(
            "policy-denies-unlisted-read",
            run_launcher(["--policy", str(valid_policy)], ["denied-read", "/proc/self/status"]),
            0,
        )
        expect(
            "policy-denies-listed-syscall",
            run_launcher(["--policy", str(valid_policy)], ["syscall-denied"]),
            0,
        )
        expect(
            "policy-keeps-p1-socket-denial",
            run_launcher(["--policy", str(valid_policy)], ["secure-syscalls"]),
            0,
        )
        expect(
            "policy-keeps-minimal-devices",
            run_launcher(["--policy", str(valid_policy)], ["dev-check"]),
            0,
        )
        expect(
            "policy-keeps-identity-mapping",
            run_launcher(["--policy", str(valid_policy)], ["identity"]),
            0,
        )
        expect(
            "policy-keeps-host-root-hidden",
            run_launcher(["--policy", str(valid_policy)], ["host-absent", str(run_dir / "host-sentinel")]),
            0,
        )

        widening = policy(
            "widening", VALID.replace('write: ["/workspace"]', 'write: ["/bin", "/workspace"]')
        )
        expect(
            "policy-cannot-widen-rootfs-mount",
            run_launcher(["--policy", str(widening)], ["denied-write", "/bin/policy-escape"]),
            0,
        )

        shortened = policy("short-timeout", VALID.replace("timeout_ms: 5000", "timeout_ms: 300"))
        expect(
            "policy-shortens-default-timeout",
            run_launcher(["--policy", str(shortened)], ["sleep", "2"]),
            124,
        )
        expect(
            "policy-caps-explicit-timeout",
            run_launcher(["--policy", str(shortened), "--timeout-ms", "30000"], ["sleep", "2"]),
            124,
        )
        expect(
            "policy-secure-flag-still-accepted",
            run_launcher(["--policy", str(valid_policy), "--secure"], ["workspace-write"]),
            0,
        )

    result["landlock_abi_ok"] = abi_ok
    result["run_dir"] = str(run_dir)
    return finish("pass" if all(test.get("ok") for test in result["tests"]) else "fail")


if __name__ == "__main__":
    raise SystemExit(main())
