#!/usr/bin/env python3
"""Linux-only acceptance tests for easy-sandbox P0 and optional P1.

The suite intentionally tests only the promised P0 boundary: namespaces, a
read-only rootfs, writable workspace, private /tmp and /proc, empty network,
identity/capability cleanup, descriptor cleanup, and descendant cleanup.
On kernels without Landlock ABI 3, the P1 check must fail closed with exit
status 125; on a capable kernel it also checks a permitted workspace write.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


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
    result_path = scratch / "smoke-result.json"
    result: dict[str, Any] = {"suite": "easy-sandbox-p0-p1", "platform": sys.platform, "tests": []}

    def record(name: str, ok: bool, detail: str = "", **extra: Any) -> None:
        item: dict[str, Any] = {"name": name, "ok": ok}
        if detail:
            item["detail"] = detail
        item.update(extra)
        result["tests"].append(item)

    if not sys.platform.startswith("linux"):
        result["status"] = "unsupported-platform"
        result["note"] = "P0 acceptance requires Linux namespaces; run from Linux/WSL."
        result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 2

    binary = pathlib.Path(args.binary).resolve()
    if not binary.is_file():
        result["status"] = "invalid-input"
        record("binary-exists", False, f"not a file: {binary}")
        result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 2

    cc = shutil.which("cc") or shutil.which("clang")
    if not cc:
        result["status"] = "missing-tool"
        record("compile-static-probe", False, "cc/clang was not found; install nothing automatically")
        result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 2

    linux_run_base = pathlib.Path(os.environ.get("EASY_SANDBOX_LINUX_TMP", "/tmp"))
    run_dir = pathlib.Path(tempfile.mkdtemp(prefix="easy-sandbox-run-", dir=linux_run_base))
    rootfs = run_dir / "rootfs"
    workspace = run_dir / "workspace"
    rootfs_bin = rootfs / "bin"
    (rootfs / "tmp").mkdir(parents=True)
    rootfs_bin.mkdir(parents=True)
    workspace.mkdir()
    (run_dir / "host-sentinel").write_text("host-only\n", encoding="utf-8")
    probe = rootfs_bin / "probe"

    compile_cmd = [cc, "-static", "-O2", "-Wall", "-Wextra", "-o", str(probe), str(pathlib.Path(__file__).with_name("probe.c"))]
    compile_proc = subprocess.run(compile_cmd, capture_output=True, text=True)
    if compile_proc.returncode != 0:
        result["status"] = "probe-build-failed"
        record("compile-static-probe", False, compile_proc.stderr[-4000:], command=compile_cmd)
        result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 2
    record("compile-static-probe", True)

    base_env = os.environ.copy()
    base_env["EASY_SANDBOX_SECRET"] = "must-not-cross-boundary"
    base_env["AWS_SECRET_ACCESS_KEY"] = "must-not-cross-boundary"

    def run_probe(
        mode: str,
        *probe_args: str,
        timeout_ms: int = 5000,
        memory_mib: int | None = None,
        cpu_seconds: int | None = None,
        max_processes: int | None = None,
        env: dict[str, str] | None = None,
        pass_fds: tuple[int, ...] = (),
        secure: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [
            str(binary),
            "run",
            "--rootfs",
            str(rootfs),
            "--workspace",
            str(workspace),
            "--timeout-ms",
            str(timeout_ms),
        ]
        if memory_mib is not None:
            cmd += ["--memory-mib", str(memory_mib)]
        if cpu_seconds is not None:
            cmd += ["--cpu-seconds", str(cpu_seconds)]
        if max_processes is not None:
            cmd += ["--max-processes", str(max_processes)]
        if secure:
            cmd += ["--secure"]
        cmd += ["--", "/bin/probe", mode, *probe_args]
        return subprocess.run(cmd, env=env or base_env, pass_fds=pass_fds, capture_output=True, text=True, timeout=max(5, timeout_ms / 1000 + 5))

    def expect(name: str, proc: subprocess.CompletedProcess[str], code: int) -> None:
        record(name, proc.returncode == code, f"expected {code}, got {proc.returncode}; stderr={proc.stderr[-500:]}", returncode=proc.returncode)

    expect("workspace-is-writable", run_probe("workspace-write"), 0)
    record("workspace-file-created", (workspace / "probe-workspace-write.txt").is_file())
    expect(
        "resource-flags-accepted",
        run_probe("workspace-write", memory_mib=64, cpu_seconds=2, max_processes=8),
        0,
    )

    rootfs_probe_marker = rootfs / "bin" / "probe-rootfs-write"
    expect("rootfs-is-read-only", run_probe("rootfs-write"), 0)
    record("rootfs-write-did-not-land-on-host", not rootfs_probe_marker.exists())

    expect("tmp-is-private-writable", run_probe("tmp-write"), 0)
    record("tmp-write-did-not-land-in-rootfs", not (rootfs / "tmp" / "probe-tmp.txt").exists())
    expect("dev-has-minimal-devices", run_probe("dev-check"), 0)
    expect("namespace-identity-is-root-without-host-root", run_probe("identity"), 0)
    expect("caps-dropped-and-no-new-privs", run_probe("caps-env"), 0)
    host_pid = os.getpid() if os.getpid() != 1 else os.getppid()
    if host_pid <= 1:
        host_pid = 999999
    expect("proc-is-private", run_probe("proc", str(host_pid)), 0)
    expect("network-is-unreachable", run_probe("net"), 0)
    expect("host-root-is-not-visible", run_probe("host-absent", str(run_dir / "host-sentinel")), 0)
    expect("stdin-is-devnull", run_probe("stdin"), 0)
    stdout_proc = run_probe("stdout")
    expect("stdout-is-captured", stdout_proc, 0)
    record("stdout-content-crosses-pipe", "probe-output" in stdout_proc.stdout)

    fd_path = run_dir / "fd-sentinel"
    fd_path.write_text("fd\n", encoding="utf-8")
    saved_fd3: int | None = None
    saved_fd4: int | None = None
    try:
        try:
            saved_fd3 = os.dup(3)
        except OSError:
            saved_fd3 = None
        try:
            saved_fd4 = os.dup(4)
        except OSError:
            saved_fd4 = None
        with fd_path.open("rb") as external_file:
            os.dup2(external_file.fileno(), 3)
            with socket.socket() as external_socket:
                os.dup2(external_socket.fileno(), 4)
                fd_proc = run_probe("fd", pass_fds=(3, 4))
        expect("inherited-files-and-sockets-are-closed", fd_proc, 0)
    finally:
        if saved_fd3 is None:
            try:
                os.close(3)
            except OSError:
                pass
        else:
            os.dup2(saved_fd3, 3)
            os.close(saved_fd3)
        if saved_fd4 is None:
            try:
                os.close(4)
            except OSError:
                pass
        else:
            os.dup2(saved_fd4, 4)
            os.close(saved_fd4)

    late_normal = "/workspace/normal-late.txt"
    expect("normal-exit-status", run_probe("background-write", late_normal, "1"), 0)
    time.sleep(1.8)
    record("normal-exit-kills-descendants", not (workspace / "normal-late.txt").exists())

    late_timeout = "/workspace/timeout-late.txt"
    expect("timeout-is-124", run_probe("sleep-fork", late_timeout, "1", timeout_ms=250), 124)
    time.sleep(1.8)
    record("timeout-kills-descendants", not (workspace / "timeout-late.txt").exists())

    expect("detached-normal-exit", run_probe("detached-exit", "/workspace/detached-normal.txt", "1"), 0)
    time.sleep(1.5)
    record("normal-exit-kills-detached-session", not (workspace / "detached-normal.txt").exists())
    (workspace / "escape-ready").unlink(missing_ok=True)
    expect("detached-timeout-is-124", run_probe("detached-sleep", "/workspace/detached-timeout.txt", "1", timeout_ms=400), 124)
    record("detached-payload-started", (workspace / "escape-ready").exists())
    time.sleep(1.5)
    record("timeout-kills-detached-session", not (workspace / "detached-timeout.txt").exists())

    late_caller = "/workspace/caller-late.txt"
    (workspace / "escape-ready").unlink(missing_ok=True)
    caller_cmd = [
        str(binary),
        "run",
        "--rootfs",
        str(rootfs),
        "--workspace",
        str(workspace),
        "--timeout-ms",
        "10000",
        "--",
        "/bin/probe",
        "detached-sleep",
        late_caller,
        "1",
    ]
    caller = subprocess.Popen(
        [sys.executable, "-c", "import subprocess,sys,time; subprocess.Popen(sys.argv[1:]); time.sleep(30)", *caller_cmd],
        env=base_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        if (workspace / "escape-ready").exists():
            break
        time.sleep(0.05)
    record("caller-death-payload-started", (workspace / "escape-ready").exists())
    caller.kill()
    caller.wait(timeout=5)
    time.sleep(1.8)
    record("caller-death-kills-descendants", not (workspace / "caller-late.txt").exists())

    expect("exit-status-is-transparent", run_probe("exit", "37"), 37)

    secure_marker = workspace / "probe-workspace-write.txt"
    secure_marker.unlink(missing_ok=True)
    abi_proc = run_probe("landlock-abi")
    if abi_proc.returncode not in (0, 2):
        record(
            "landlock-abi-probe",
            False,
            f"expected 0 (ABI >= 3) or 2 (older/unsupported), got {abi_proc.returncode}; stderr={abi_proc.stderr[-500:]}",
            returncode=abi_proc.returncode,
        )
    else:
        record(
            "landlock-abi-probe",
            True,
            "ABI >= 3" if abi_proc.returncode == 0 else "ABI < 3 or unavailable",
            returncode=abi_proc.returncode,
        )
        secure_proc = run_probe("workspace-write", secure=True)
        if abi_proc.returncode == 0:
            expect("secure-policy-allows-workspace", secure_proc, 0)
            record("secure-workspace-file-created", secure_marker.is_file())
            expect("baseline-allows-socketpair", run_probe("socketpair-allowed"), 0)
            expect("baseline-allows-proc-comm-write", run_probe("proc-write-allowed"), 0)
            expect("secure-seccomp-denies-sockets", run_probe("secure-syscalls", secure=True), 0)
            expect("secure-landlock-denies-proc-write", run_probe("secure-proc-write-denied", secure=True), 0)
            expect("secure-allows-devices", run_probe("dev-check", secure=True), 0)
        else:
            expect("secure-policy-fails-closed", secure_proc, 125)
            record("secure-policy-did-not-run-payload", not secure_marker.exists())

    missing_root = run_dir / "missing-rootfs"
    invalid = [
        str(binary),
        "run",
        "--rootfs",
        str(missing_root),
        "--workspace",
        str(workspace),
        "--",
        "/bin/probe",
        "proc",
    ]
    invalid_proc = subprocess.run(invalid, env=base_env, capture_output=True, text=True)
    expect("missing-rootfs-fails-closed", invalid_proc, 125)

    rootfs_file = run_dir / "rootfs-file"
    rootfs_file.write_text("not a directory\n", encoding="utf-8")
    invalid_file = [
        str(binary),
        "run",
        "--rootfs",
        str(rootfs_file),
        "--workspace",
        str(workspace),
        "--",
        "/bin/probe",
        "proc",
    ]
    invalid_file_proc = subprocess.run(invalid_file, env=base_env, capture_output=True, text=True)
    expect("file-rootfs-fails-closed", invalid_file_proc, 125)

    workspace_inside = rootfs / "inside-workspace"
    workspace_inside.mkdir()
    invalid_workspace = [
        str(binary),
        "run",
        "--rootfs",
        str(rootfs),
        "--workspace",
        str(workspace_inside),
        "--",
        "/bin/probe",
        "proc",
    ]
    invalid_workspace_proc = subprocess.run(invalid_workspace, env=base_env, capture_output=True, text=True)
    expect("workspace-inside-rootfs-fails-closed", invalid_workspace_proc, 125)

    root_input = [
        str(binary),
        "run",
        "--rootfs",
        "/",
        "--workspace",
        str(workspace),
        "--",
        "/bin/probe",
        "proc",
    ]
    root_proc = subprocess.run(root_input, env=base_env, capture_output=True, text=True)
    expect("host-root-input-fails-closed", root_proc, 125)

    result["status"] = "pass" if all(test.get("ok") for test in result["tests"]) else "fail"
    result["scratch"] = str(scratch)
    result["run_dir"] = str(run_dir)
    result_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
