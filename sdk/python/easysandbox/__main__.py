"""Command line entry point shared by the cross-SDK tests.

    python3 -m easysandbox canonical   < spec.json   # normalized request
    python3 -m easysandbox run         < spec.json   # normalized result
    python3 -m easysandbox verify      < spec.json   # normalized report

The spec uses the same keys in both languages::

    {
      "binary": "/path/to/easy-sandbox",
      "rootfs": "/srv/rootfs",
      "workspace": "/srv/work",
      "command": ["/bin/sh", "-c", "true"],
      "policy": "/srv/policy.yaml",
      "timeout_ms": 5000,
      "proxy_allow": ["api.example.com:443"],
      "record": "/srv/run.jsonl",
      "cases": "/srv/cases.yaml",
      "report": "/srv/report.json",
      "records": "/srv/records"
    }

Every subcommand prints sorted, indented JSON so two SDKs can be compared byte
for byte.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Mapping

from .client import RunRequest, Sandbox


def request_from_spec(spec: Mapping[str, Any]) -> RunRequest:
    """Build a request from a shared spec, filling in documented defaults."""
    return RunRequest(
        rootfs=spec["rootfs"],
        workspace=spec["workspace"],
        command=list(spec["command"]),
        policy=spec.get("policy"),
        timeout_ms=int(spec.get("timeout_ms", 30_000)),
        memory_mib=spec.get("memory_mib"),
        cpu_seconds=spec.get("cpu_seconds"),
        max_processes=spec.get("max_processes"),
        secure=bool(spec.get("secure", False)),
        proxy_allow=tuple(spec.get("proxy_allow", ())),
        record=spec.get("record"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="easysandbox", description=__doc__)
    parser.add_argument("command", choices=["canonical", "run", "verify"])
    parser.add_argument(
        "--binary",
        default=os.environ.get("EASY_SANDBOX_BIN", "easy-sandbox"),
        help="launcher to run (a spec may override it)",
    )
    args = parser.parse_args(argv)

    spec = json.load(sys.stdin)
    binary = spec.get("binary", args.binary)

    if args.command == "canonical":
        print(json.dumps(request_from_spec(spec).canonical(), indent=2, sort_keys=True))
        return 0

    sandbox = Sandbox(binary)
    if args.command == "run":
        result = sandbox.run(request_from_spec(spec))
        print(json.dumps(result.canonical(), indent=2, sort_keys=True))
        return 0

    verified = sandbox.verify(
        policy=spec["policy"],
        cases=spec["cases"],
        rootfs=spec["rootfs"],
        workspace=spec["workspace"],
        report=spec.get("report"),
        records=spec.get("records"),
        timeout_ms=spec.get("timeout_ms"),
    )
    print(json.dumps(verified.canonical(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
