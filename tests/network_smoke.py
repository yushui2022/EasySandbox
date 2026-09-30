#!/usr/bin/env python3
"""Linux-only acceptance tests for the EasySandbox P3 proxy layer.

The sandbox has no route out of its network namespace, so the only way to reach
anything is the CONNECT proxy the launcher mounts at ``/run/proxy.sock``.  The
suite runs a real TCP server on the host, builds a policy that allowlists it,
and checks both sides of the boundary:

* the allowlisted destination works end to end, including tunnelled bytes;
* everything else is refused by the proxy (other hosts, other ports, IP
  literals, non-CONNECT methods) and the upstream server never sees it;
* the socket relaxation is limited to ``AF_UNIX`` -- ``AF_INET`` sockets cannot
  even be created;
* every decision, including refusals, is logged with the task, domain, port,
  rule version and outcome.

It needs a working launcher and namespaces, not Landlock ABI 3: the proxy
boundary is enforced by the trusted parent process, so this suite also runs on
WSL2's 5.15 kernel.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

# A hostname the test machine resolves without any privilege: the proxy refuses
# IP literals on purpose, so the allowlist has to name a host.
ALLOWED_HOST = "localhost"
UPSTREAM_PAYLOAD = "hello-from-upstream"

BASE_POLICY = """\
version: 1
filesystem:
  read: ["/bin"]
  write: ["/workspace"]
network:
  mode: proxy
  allow:
    - host: {host}
      ports: [{ports}]
limits:
  timeout_ms: 5000
  memory_mib: 256
  max_processes: 16
syscalls:
  deny: []
mode: enforce
"""


class Upstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        with self.server.hits_lock:  # type: ignore[attr-defined]
            self.server.hits += 1  # type: ignore[attr-defined]
        if self.server.silent:  # type: ignore[attr-defined]
            # Accept the connection and then stall: the proxy connects, the
            # payload waits, and only the launcher timeout can end the run.
            time.sleep(30)
            return
        self.request.sendall((UPSTREAM_PAYLOAD + "\n").encode())
        self.request.settimeout(2.0)
        try:
            self.request.recv(64)
        except OSError:
            pass


def start_upstream(silent: bool = False) -> tuple[Upstream, int]:
    server = Upstream(("127.0.0.1", 0), UpstreamHandler)
    server.hits = 0  # type: ignore[attr-defined]
    server.silent = silent  # type: ignore[attr-defined]
    server.hits_lock = threading.Lock()  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, help="path to easy-sandbox")
    parser.add_argument("--scratch", default="/mnt/g/DevCache/Temp/EasySandbox")
    args = parser.parse_args()
    scratch = pathlib.Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "suite": "easy-sandbox-p3-proxy",
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
        report = scratch / "network-smoke-result.json"
        report.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0 if status == "pass" else 1

    if not sys.platform.startswith("linux"):
        result["note"] = "P3 acceptance requires Linux namespaces; run from Linux/WSL."
        return finish("unsupported-platform")

    binary = pathlib.Path(args.binary).resolve()
    cc = shutil.which("cc") or shutil.which("clang")
    if not binary.is_file() or not cc:
        record("binary-and-compiler-available", False, f"binary={binary} cc={cc}")
        return finish("invalid-input")

    run_dir = pathlib.Path(
        tempfile.mkdtemp(prefix="easy-sandbox-network-", dir=os.environ.get("EASY_SANDBOX_LINUX_TMP", "/tmp"))
    )
    rootfs = run_dir / "rootfs"
    workspace = run_dir / "workspace"
    (rootfs / "bin").mkdir(parents=True)
    (rootfs / "tmp").mkdir()
    workspace.mkdir()
    probe = rootfs / "bin" / "probe"
    compile_cmd = [
        cc, "-static", "-O2", "-Wall", "-Wextra", "-o", str(probe),
        str(pathlib.Path(__file__).with_name("probe.c")),
    ]
    compile_proc = subprocess.run(compile_cmd, capture_output=True, text=True)
    if compile_proc.returncode != 0:
        record("compile-static-probe", False, compile_proc.stderr[-4000:], command=compile_cmd)
        return finish("probe-build-failed")
    record("compile-static-probe", True)

    upstream, upstream_port = start_upstream()
    quiet_upstream, quiet_port = start_upstream(silent=True)
    unused_port = free_port()

    policies = scratch / "policies"
    policies.mkdir(exist_ok=True)
    allowed_ports = [upstream_port, quiet_port]
    policy_path = policies / "network.yaml"
    policy_path.write_text(
        BASE_POLICY.format(
            host=ALLOWED_HOST,
            ports=", ".join(str(port) for port in allowed_ports),
        ),
        encoding="utf-8",
    )

    caller_env = os.environ.copy()
    # A caller-set proxy variable must not change any decision.
    caller_env["HTTP_PROXY"] = "http://127.0.0.1:1"
    caller_env["HTTPS_PROXY"] = "http://127.0.0.1:1"

    def run_probe(
        *probe_args: str, timeout_ms: int = 10000, with_policy: bool = False
    ) -> subprocess.CompletedProcess[str]:
        # `--proxy-allow` is the P0-level entry point: the proxy boundary lives
        # in the trusted parent, so this works on any Linux kernel, while the
        # policy form additionally installs the Landlock baseline.
        gate = (
            ["--policy", str(policy_path)]
            if with_policy
            else [
                flag
                for port in allowed_ports
                for flag in ("--proxy-allow", f"{ALLOWED_HOST}:{port}")
            ]
        )
        cmd = [
            str(binary), "run",
            "--rootfs", str(rootfs),
            "--workspace", str(workspace),
            "--timeout-ms", str(timeout_ms),
            *gate,
            "--", "/bin/probe", *probe_args,
        ]
        return subprocess.run(cmd, env=caller_env, capture_output=True, text=True, timeout=60)

    def expect(name: str, proc: subprocess.CompletedProcess[str], code: int) -> None:
        record(
            name,
            proc.returncode == code,
            f"expected {code}, got {proc.returncode}; stdout={proc.stdout[-300:]}; stderr={proc.stderr[-300:]}",
        )

    # --- the proxy socket replaces every other network capability -----------
    expect("proxy-environment-is-published", run_probe("proxy-env"), 0)
    env_proc = run_probe("proxy-env")
    record("proxy-environment-points-at-the-socket", "/run/proxy.sock" in env_proc.stdout, env_proc.stdout.strip())
    # The proxy is the only way out: the sandbox network namespace has no route,
    # so a payload cannot reach the upstream directly even though the proxy can.
    expect("direct-egress-is-unreachable", run_probe("net"), 0)

    # --- allowed destination -------------------------------------------------
    hits_before = upstream.hits  # type: ignore[attr-defined]
    allowed = run_probe("proxy-connect", f"{ALLOWED_HOST}:{upstream_port}", "ping")
    expect("allowed-host-connects", allowed, 0)
    record("allowed-host-returns-200", "200" in allowed.stdout.splitlines()[0] if allowed.stdout else False, allowed.stdout[:200])
    record("tunnelled-bytes-cross", UPSTREAM_PAYLOAD in allowed.stdout, allowed.stdout[:300])
    record("upstream-was-reached", upstream.hits > hits_before, f"hits={upstream.hits}")  # type: ignore[attr-defined]

    # --- refusals, with the upstream never reached ---------------------------
    quiet_before = quiet_upstream.hits  # type: ignore[attr-defined]
    for name, target, expect_status, reason in [
        ("denied-host-is-refused", f"example.com:{quiet_port}", "403", "host-not-allowed"),
        ("denied-port-is-refused", f"{ALLOWED_HOST}:{unused_port}", "403", "port-not-allowed"),
        ("ip-literal-is-refused", f"127.0.0.1:{quiet_port}", "403", "not-a-hostname"),
    ]:
        proc = run_probe("proxy-connect", target)
        expect(name, proc, 0)
        record(f"{name}-status", expect_status in proc.stdout, proc.stdout[:200])
        record(f"{name}-logged", f"decision=deny reason={reason}" in proc.stderr, proc.stderr[-300:])
    record(
        "refused-targets-never-reach-upstream",
        quiet_upstream.hits == quiet_before,  # type: ignore[attr-defined]
        f"hits={quiet_upstream.hits}",  # type: ignore[attr-defined]
    )

    for name, request_line in [
        ("non-connect-method-is-refused", "GET / HTTP/1.1"),
        ("tunnel-without-authority-is-refused", "CONNECT localhost HTTP/1.1"),
    ]:
        proc = run_probe("proxy-raw", request_line)
        expect(name, proc, 0)
        record(f"{name}-status", "405" in proc.stdout or "400" in proc.stdout, proc.stdout[:200])

    # --- the decision log carries task, domain, port, version and outcome ----
    record(
        "allow-decision-is-logged",
        "decision=allow" in allowed.stderr
        and f"host={ALLOWED_HOST}" in allowed.stderr
        and f"port={upstream_port}" in allowed.stderr
        and "policy_version=" in allowed.stderr
        and "task=" in allowed.stderr,
        allowed.stderr[-300:],
    )
    record("proxy-rules-ignore-caller-environment", "decision=allow" in allowed.stderr, "")

    # --- the policy form of the same boundary needs Landlock ABI 3 ------------
    abi_proc = subprocess.run(
        [
            str(binary), "run",
            "--rootfs", str(rootfs),
            "--workspace", str(workspace),
            "--timeout-ms", "10000",
            "--", "/bin/probe", "landlock-abi",
        ],
        env=caller_env, capture_output=True, text=True, timeout=60,
    )
    if abi_proc.returncode == 0:
        policy_allowed = run_probe(f"{ALLOWED_HOST}:{upstream_port}", "ping", with_policy=True)
        expect("policy-driven-proxy-connects", policy_allowed, 0)
        record("policy-driven-proxy-returns-200", "200" in policy_allowed.stdout, policy_allowed.stdout[:200])
        record(
            "policy-driven-proxy-is-logged-with-rule-version",
            "decision=allow" in policy_allowed.stderr and "policy_version=1" in policy_allowed.stderr,
            policy_allowed.stderr[-300:],
        )
        expect(
            "policy-still-denies-unlisted-read",
            run_probe("denied-read", "/proc/self/status", with_policy=True),
            0,
        )
        expect(
            "policy-still-denies-unlisted-write",
            run_probe("denied-write", "/tmp/proxy-tmp.txt", with_policy=True),
            0,
        )
        # The seccomp domain rule is part of the baseline, so it only exists
        # under --secure or a policy: AF_UNIX yes, everything else no.
        expect("af-unix-socketpair-is-allowed", run_probe("unix-socketpair", with_policy=True), 0)
        expect("af-inet-socket-is-denied", run_probe("inet-socket", with_policy=True), 0)
    else:
        record(
            "policy-driven-proxy-deferred-to-vm",
            abi_proc.returncode == 2,
            f"kernel Landlock ABI < 3 (probe exit {abi_proc.returncode}); scripts/validate-vm.sh covers it",
        )

    # --- a stalled tunnel is still owned by the launcher timeout -------------
    expect("stalled-tunnel-is-killed", run_probe("proxy-connect", f"{ALLOWED_HOST}:{quiet_port}", "ping", timeout_ms=800), 124)

    # --- no socket file is left behind --------------------------------------
    leftovers = sorted(pathlib.Path(tempfile.gettempdir()).glob("easy-sandbox-proxy-*"))
    record("proxy-socket-directory-is-removed", not leftovers, f"leftovers={leftovers}")

    upstream.shutdown()
    quiet_upstream.shutdown()
    result["run_dir"] = str(run_dir)
    return finish("pass" if all(test.get("ok") for test in result["tests"]) else "fail")


if __name__ == "__main__":
    raise SystemExit(main())
