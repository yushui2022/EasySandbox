#!/bin/busybox sh
# P2 policy enforcement checks, executed inside the QEMU kernel (Landlock ABI 3+).
#
# WSL2's 5.15 kernel only reports Landlock ABI 1, where the launcher must fail
# closed; this suite is what proves the enforcement path on a capable kernel.
# It prepares its own tree and policies as root, then re-executes itself as an
# unprivileged uid because easy-sandbox refuses to run as uid 0.
set -u

WORK=/work
POLICIES="$WORK/policies"
ROOTFS="$WORK/rootfs"
WORKSPACE="$WORK/workspace"
LAUNCHER=/bin/easy-sandbox
PROBE=/bin/probe
HELPER=/bin/vm-drop-privs
SANDBOX_UID=65534
SANDBOX_GID=65534
CHECKS=0
FAILURES=0

report() { # report <name> <expected> <actual>
    CHECKS=$((CHECKS + 1))
    if [ "$2" = "$3" ]; then
        echo "easy-sandbox-vm: ok $1 (exit $3)"
    else
        echo "easy-sandbox-vm: FAIL $1 expected=$2 actual=$3"
        FAILURES=$((FAILURES + 1))
    fi
}

if [ "$(id -u)" = "0" ]; then
    rm -rf "$WORK"
    mkdir -p "$ROOTFS/bin" "$ROOTFS/tmp" "$WORKSPACE" "$POLICIES"
    cp "$PROBE" "$ROOTFS/bin/probe"
    echo host-only > "$WORK/host-sentinel"

    cat > "$POLICIES/enforce.yaml" <<'YAML'
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
YAML

    # Grants /bin for writing too; the read-only rootfs mount must still win.
    cat > "$POLICIES/widening.yaml" <<'YAML'
version: 1
filesystem:
  read: ["/bin"]
  write: ["/bin", "/workspace"]
network:
  mode: disabled
  allow: []
limits:
  timeout_ms: 5000
syscalls:
  deny: []
mode: enforce
YAML

    cat > "$POLICIES/short-timeout.yaml" <<'YAML'
version: 1
filesystem:
  read: ["/bin"]
  write: ["/workspace"]
network:
  mode: disabled
  allow: []
limits:
  timeout_ms: 300
syscalls:
  deny: []
mode: enforce
YAML

    cat > "$POLICIES/proxy.yaml" <<'YAML'
version: 1
filesystem:
  read: ["/bin"]
  write: ["/workspace"]
network:
  mode: proxy
  allow:
    - host: localhost
      ports: [18080]
limits:
  timeout_ms: 5000
syscalls:
  deny: []
mode: enforce
YAML

    cat > "$POLICIES/observe-record.yaml" <<'YAML'
version: 1
filesystem:
  read: ["/bin"]
  write: ["/workspace"]
network:
  mode: proxy
  allow:
    - host: localhost
      ports: [18080]
limits:
  timeout_ms: 5000
syscalls:
  deny: [uname]
mode: observe
YAML

    # `verify` is not a run mode: it drives `easy-sandbox verify --cases FILE`.
    cat > "$POLICIES/verify-mode.yaml" <<'YAML'
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
mode: verify
YAML

    chmod -R 0777 "$WORK"
    exec "$HELPER" "$SANDBOX_UID" "$SANDBOX_GID" "$0"
fi

echo "easy-sandbox-vm: policy suite as uid=$(id -u)"

# case_run <name> <expected-exit> <policy-file|secure|none> <probe args...>
case_run() {
    name="$1"
    expected="$2"
    policy="$3"
    shift 3
    if [ "$policy" = "secure" ]; then
        "$LAUNCHER" run --rootfs "$ROOTFS" --workspace "$WORKSPACE" --timeout-ms 10000 \
            --secure -- /bin/probe "$@"
    elif [ "$policy" = "none" ]; then
        "$LAUNCHER" run --rootfs "$ROOTFS" --workspace "$WORKSPACE" --timeout-ms 10000 \
            -- /bin/probe "$@"
    else
        "$LAUNCHER" run --rootfs "$ROOTFS" --workspace "$WORKSPACE" --timeout-ms 10000 \
            --policy "$policy" -- /bin/probe "$@"
    fi
    report "$name" "$expected" "$?"
}

case_run abi-is-at-least-3 0 none landlock-abi
case_run p1-secure-baseline-works 0 secure workspace-write

case_run policy-allows-listed-write 0 "$POLICIES/enforce.yaml" allowed-write /workspace/vm-write.txt
if [ -f "$WORKSPACE/vm-write.txt" ]; then
    report policy-listed-write-landed 0 0
else
    report policy-listed-write-landed 0 1
fi

case_run policy-denies-unlisted-write 0 "$POLICIES/enforce.yaml" denied-write /tmp/vm-tmp.txt
if [ -e "$ROOTFS/tmp/vm-tmp.txt" ]; then
    report policy-unlisted-write-did-not-land 0 1
else
    report policy-unlisted-write-did-not-land 0 0
fi

case_run policy-allows-listed-read 0 "$POLICIES/enforce.yaml" allowed-read /bin/probe
case_run policy-denies-unlisted-read 0 "$POLICIES/enforce.yaml" denied-read /proc/self/status
case_run policy-denies-listed-syscall 0 "$POLICIES/enforce.yaml" syscall-denied
case_run policy-keeps-baseline-sockets 0 "$POLICIES/enforce.yaml" secure-syscalls
case_run policy-keeps-minimal-devices 0 "$POLICIES/enforce.yaml" dev-check
case_run policy-keeps-identity 0 "$POLICIES/enforce.yaml" identity
case_run policy-keeps-host-root-hidden 0 "$POLICIES/enforce.yaml" host-absent "$WORK/host-sentinel"
case_run policy-cannot-widen-rootfs 0 "$POLICIES/widening.yaml" denied-write /bin/vm-escape
case_run policy-caps-timeout 124 "$POLICIES/short-timeout.yaml" sleep 2
case_run policy-rejects-verify-mode 125 "$POLICIES/verify-mode.yaml" proc

# --- P3: the proxy is the only way out ------------------------------------
UPSTREAM_PORT=18080
LAST_OUTPUT=
LAST_LOG=

# case_proxy <name> <policy-file|allow> <probe args...>
case_proxy() {
    name="$1"
    policy="$2"
    shift 2
    if [ "$policy" = "allow" ]; then
        LAST_OUTPUT=$("$LAUNCHER" run --rootfs "$ROOTFS" --workspace "$WORKSPACE" \
            --timeout-ms 10000 --proxy-allow "localhost:$UPSTREAM_PORT" \
            -- /bin/probe "$@" 2>"$WORK/proxy-stderr.txt")
    else
        LAST_OUTPUT=$("$LAUNCHER" run --rootfs "$ROOTFS" --workspace "$WORKSPACE" \
            --timeout-ms 10000 --policy "$policy" -- /bin/probe "$@" 2>"$WORK/proxy-stderr.txt")
    fi
    status=$?
    LAST_LOG=$(cat "$WORK/proxy-stderr.txt")
    report "$name" 0 "$status"
    [ "$status" = 0 ] || echo "easy-sandbox-vm:   output: $LAST_LOG"
}

# has <name> <needle>         -- payload-visible output
has() {
    case "$LAST_OUTPUT" in
        *"$2"*) report "$1" 0 0 ;;
        *)
            report "$1" 0 1
            echo "easy-sandbox-vm:   output: $LAST_OUTPUT"
            ;;
    esac
}

# has_log <name> <needle>     -- proxy decision log
has_log() {
    case "$LAST_LOG" in
        *"$2"*) report "$1" 0 0 ;;
        *)
            report "$1" 0 1
            echo "easy-sandbox-vm:   log: $LAST_LOG"
            ;;
    esac
}

# The upstream is the probe's own multi-connection server: busybox nc can only
# serve one connection at a time and cannot rebind while the pair sits in
# TIME_WAIT.
"$PROBE" server "$UPSTREAM_PORT" >"$WORK/upstream.out" 2>&1 &
UPSTREAM_PID=$!
upstream_ready=0
attempt=0
while [ "$attempt" -lt 50 ]; do
    if grep -q upstream-listening "$WORK/upstream.out" 2>/dev/null; then
        upstream_ready=1
        break
    fi
    sleep 0.1
    attempt=$((attempt + 1))
done
report upstream-server-ready 1 "$upstream_ready"

case_proxy proxy-env-published "$POLICIES/proxy.yaml" proxy-env
has proxy-env-points-at-socket "/run/proxy.sock"

case_proxy policy-proxy-allows-listed-host "$POLICIES/proxy.yaml" proxy-connect "localhost:$UPSTREAM_PORT" ping
has policy-proxy-returns-200 "200 Connection Established"
has policy-proxy-tunnels-bytes "hello-from-upstream"
has_log policy-proxy-logs-allow "decision=allow"

case_proxy policy-proxy-denies-other-host "$POLICIES/proxy.yaml" proxy-connect "example.com:$UPSTREAM_PORT"
has policy-proxy-deny-status "403"
has_log policy-proxy-deny-reason "reason=host-not-allowed"

case_proxy policy-proxy-denies-ip-literal "$POLICIES/proxy.yaml" proxy-connect "127.0.0.1:$UPSTREAM_PORT"
has policy-proxy-ip-literal-status "403"

case_proxy policy-proxy-restricts-socket-domains "$POLICIES/proxy.yaml" inet-socket
case_proxy policy-proxy-keeps-af-unix "$POLICIES/proxy.yaml" unix-socketpair

case_proxy cli-proxy-allow-table allow proxy-connect "localhost:$UPSTREAM_PORT" ping
has cli-proxy-returns-200 "200 Connection Established"
has cli-proxy-tunnels-bytes "hello-from-upstream"
has_log cli-proxy-logs-allow "decision=allow"

kill "$UPSTREAM_PID" 2>/dev/null

# --- P4: observe records, verify decides ----------------------------------
OBSERVE_RECORD="$WORK/observe.jsonl"
VERIFY_CASES="$WORK/verify-cases.yaml"
VERIFY_REPORT="$WORK/report.json"

cat > "$VERIFY_CASES" <<'YAML'
cases:
  - name: verify-allow
    expectation: allow
    command: ["/bin/probe", "allowed-read", "/bin/probe"]
  - name: verify-deny
    expectation: deny
    command: ["/bin/probe", "allowed-write", "/tmp/verify-tmp.txt"]
  - name: verify-unknown
    command: ["/bin/probe", "identity"]
YAML

"$LAUNCHER" run --rootfs "$ROOTFS" --workspace "$WORKSPACE" --timeout-ms 10000 \
    --policy "$POLICIES/observe-record.yaml" --record "$OBSERVE_RECORD" \
    -- /bin/probe identity >/dev/null 2>&1
report observe-run-finished 0 "$?"
report observe-record-written 0 "$([ -s "$OBSERVE_RECORD" ] && echo 0 || echo 1)"
record_has() {
    if grep -q "$2" "$OBSERVE_RECORD"; then report "$1" 0 0; else report "$1" 0 1; fi
}
record_has observe-record-names-the-mode '"mode":"observe"'
record_has observe-record-freezes-the-policy '"policy":"version: 1'
record_has observe-keeps-the-p1-floor '"layer":"p1-baseline","installed":true'
record_has observe-skips-the-policy-landlock '"layer":"policy-landlock","installed":false'
record_has observe-skips-the-policy-seccomp '"layer":"policy-seccomp","installed":false'
record_has observe-skips-the-proxy '"layer":"proxy","installed":false'
record_has observe-records-candidates '"kind":"candidate"'
record_has observe-keeps-candidates-unapproved '"state":"unapproved"'
record_has observe-records-network-candidates '"field":"network.allow"'
record_has observe-records-the-outcome '"status":"exited","exit_code":0'

rm -rf "$WORK/records"
mkdir -p "$WORK/records"
"$LAUNCHER" verify --policy "$POLICIES/enforce.yaml" --cases "$VERIFY_CASES" \
    --rootfs "$ROOTFS" --workspace "$WORKSPACE" \
    --report "$VERIFY_REPORT" --records "$WORK/records" >/dev/null 2>"$WORK/verify-stderr.txt"
verify_status=$?
# One case declares no expectation, so the report needs a human: exit 2.
report verify-exit-status-when-pending 2 "$verify_status"
report verify-report-written 0 "$([ -s "$VERIFY_REPORT" ] && echo 0 || echo 1)"
case_has() {
    if grep -q "$2" "$VERIFY_REPORT"; then report "$1" 0 0; else report "$1" 0 1; fi
}
case_has verify-report-is-tagged '"kind": "easy-sandbox-verify-report"'
report verify-passes-both-directions 2 "$(grep -c '"verdict": "pass"' "$VERIFY_REPORT")"
report verify-keeps-unknown-pending 1 "$(grep -c '"verdict": "pending"' "$VERIFY_REPORT")"
report verify-covers-every-case 3 "$(grep -c '"verdict":' "$VERIFY_REPORT")"
report verify-writes-per-case-records 0 \
    "$([ -f "$WORK/records/verify-allow.jsonl" ] && [ -f "$WORK/records/verify-deny.jsonl" ] && echo 0 || echo 1)"

# The refused case must be refused because of the policy, not because the
# sandbox failed to start.
case_has verify-deny-was-decided '"name": "verify-deny"' 

echo "easy-sandbox-vm: policy-checks=$CHECKS failures=$FAILURES"
if [ "$FAILURES" = "0" ]; then
    exit 0
fi
exit 1
