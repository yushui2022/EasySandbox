"""Python SDK for easy-sandbox.

```python
from easysandbox import Outcome, RunRequest, Sandbox

sandbox = Sandbox("/usr/local/bin/easy-sandbox")
result = sandbox.run(
    RunRequest(
        rootfs="/srv/rootfs",
        workspace="/srv/work",
        policy="/srv/policies/agent.yaml",
        record="/srv/records/run.jsonl",
        command=["/bin/sh", "-c", "printf ok > /workspace/result.txt"],
    )
)
if result.outcome is Outcome.POLICY_REJECTED:
    ...
```

The SDK only builds an argument vector, runs the launcher and interprets its
exit status, failure markers and JSONL record; it never reimplements
namespaces, Landlock or seccomp.  `RunRequest.canonical()`,
`RunResult.canonical()` and `VerifyResult.canonical()` are the same shapes the
TypeScript SDK produces, which is what the cross-SDK test compares.
"""

from .client import (
    DEFAULT_TIMEOUT_MS,
    ENFORCEMENT_MARKER,
    POLICY_REJECTED_MARKER,
    Outcome,
    ReportError,
    RunRequest,
    RunResult,
    RunStream,
    Sandbox,
    SandboxError,
    VerifyOutcome,
    VerifyResult,
    canonical_report,
    classify,
    parse_events,
    validate_report,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_TIMEOUT_MS",
    "ENFORCEMENT_MARKER",
    "POLICY_REJECTED_MARKER",
    "Outcome",
    "ReportError",
    "RunRequest",
    "RunResult",
    "RunStream",
    "Sandbox",
    "SandboxError",
    "VerifyOutcome",
    "VerifyResult",
    "canonical_report",
    "classify",
    "parse_events",
    "validate_report",
    "__version__",
]
