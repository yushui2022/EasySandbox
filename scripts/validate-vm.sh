#!/usr/bin/env bash
set -euo pipefail

# Reproducible, non-persistent QEMU validation for Landlock ABI 3+.
# All generated state is kept under G:\\DevCache\\Temp\\EasySandbox\\vm.
# This script never installs a package into WSL and never modifies its kernel.

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_DIR="${EASY_SANDBOX_VM_DIR:-/mnt/g/DevCache/Temp/EasySandbox/vm}"
DOWNLOAD_DIR="$BASE_DIR/downloads"
KERNEL_DIR="$BASE_DIR/kernel"
INITRD_DIR="$BASE_DIR/initrd"
LOG_DIR="$BASE_DIR/logs"
RESULT_JSON="$BASE_DIR/vm-result.json"
mkdir -p "$DOWNLOAD_DIR" "$KERNEL_DIR" "$INITRD_DIR" "$LOG_DIR"

say() { printf '[validate-vm] %s\n' "$*" >&2; }
fail() { say "ERROR: $*"; exit 1; }

command -v qemu-system-x86_64 >/dev/null || fail "qemu-system-x86_64 is required"
command -v dpkg-deb >/dev/null || fail "dpkg-deb is required"
command -v gzip >/dev/null || fail "gzip is required"
command -v cc >/dev/null || fail "cc is required"

if ! compgen -G "$DOWNLOAD_DIR/linux-image-unsigned-*.deb" >/dev/null; then
    say "downloading Ubuntu 6.8 unsigned kernel into $DOWNLOAD_DIR"
    (cd "$DOWNLOAD_DIR" && apt-get download linux-image-unsigned-6.8.0-31-generic)
fi
if ! compgen -G "$DOWNLOAD_DIR/busybox-static_*.deb" >/dev/null; then
    say "downloading busybox-static into $DOWNLOAD_DIR"
    (cd "$DOWNLOAD_DIR" && apt-get download busybox-static)
fi

KERNEL_DEB="$(find "$DOWNLOAD_DIR" -maxdepth 1 -name 'linux-image-unsigned-*.deb' | sort | tail -n1)"
BUSYBOX_DEB="$(find "$DOWNLOAD_DIR" -maxdepth 1 -name 'busybox-static_*.deb' | sort | tail -n1)"
[ -n "$KERNEL_DEB" ] || fail "kernel package not found"
[ -n "$BUSYBOX_DEB" ] || fail "busybox package not found"

# These are dedicated, regenerable subdirectories; reject unsafe overrides.
BASE_DIR="$(realpath "$BASE_DIR")"
case "$BASE_DIR" in /|/mnt|/mnt/g|/mnt/g/Projects) fail "unsafe VM directory";; esac
for target in "$KERNEL_DIR" "$INITRD_DIR"; do
    case "$(realpath -m "$target")" in "$BASE_DIR"/*) ;; *) fail "unsafe generated directory: $target";; esac
done
rm -rf -- "$KERNEL_DIR" "$INITRD_DIR"
mkdir -p "$KERNEL_DIR" "$INITRD_DIR/bin" "$INITRD_DIR/dev" "$INITRD_DIR/proc" "$INITRD_DIR/sys" "$INITRD_DIR/run"
dpkg-deb -x "$KERNEL_DEB" "$KERNEL_DIR"
dpkg-deb -x "$BUSYBOX_DEB" "$BASE_DIR/busybox-extract"
BUSYBOX="$BASE_DIR/busybox-extract/usr/bin/busybox"
[ -x "$BUSYBOX" ] || fail "busybox binary not found in package"
cp "$BUSYBOX" "$INITRD_DIR/bin/busybox"
chmod 0755 "$INITRD_DIR/bin/busybox"
ln -sf busybox "$INITRD_DIR/bin/sh"
cp "$PROJECT_DIR/scripts/vm-init" "$INITRD_DIR/init"
chmod 0755 "$INITRD_DIR/init"

cc -static -O2 -Wall -Wextra -o "$INITRD_DIR/bin/landlock-probe" "$PROJECT_DIR/scripts/landlock_probe.c"
chmod 0755 "$INITRD_DIR/bin/landlock-probe"

# Optional P2 policy phase: only a *static* easy-sandbox can run in the
# initramfs, so the phase is skipped unless the caller points at one.
#   RUSTFLAGS="-C target-feature=+crt-static" \
#     cargo build --release --target x86_64-unknown-linux-gnu
POLICY_PHASE=0
STATIC_BIN="${EASY_SANDBOX_STATIC_BIN:-}"
if [ -n "$STATIC_BIN" ] && [ -x "$STATIC_BIN" ]; then
    say "including the launcher and the P2 policy suite: $STATIC_BIN"
    case "$(basename "$STATIC_BIN")" in
        easy-sandbox) ;;
        *) fail "EASY_SANDBOX_STATIC_BIN must point at easy-sandbox" ;;
    esac
    cp "$STATIC_BIN" "$INITRD_DIR/bin/easy-sandbox"
    chmod 0755 "$INITRD_DIR/bin/easy-sandbox"
    cc -static -O2 -Wall -Wextra -o "$INITRD_DIR/bin/probe" "$PROJECT_DIR/tests/probe.c"
    cc -static -O2 -Wall -Wextra -o "$INITRD_DIR/bin/vm-drop-privs" "$PROJECT_DIR/scripts/vm-drop-privs.c"
    cp "$PROJECT_DIR/scripts/vm-policy-tests.sh" "$INITRD_DIR/bin/policy-tests.sh"
    chmod 0755 "$INITRD_DIR/bin/probe" "$INITRD_DIR/bin/vm-drop-privs" "$INITRD_DIR/bin/policy-tests.sh"
    # The P3 proxy resolves allowlisted names on the trusted side; inside the
    # initramfs that needs a host table for the test hostname.
    mkdir -p "$INITRD_DIR/etc"
    printf '127.0.0.1\tlocalhost\n' > "$INITRD_DIR/etc/hosts"
    POLICY_PHASE=1
else
    say "EASY_SANDBOX_STATIC_BIN is not set or not executable; the initramfs will boot the ABI probe only"
fi

KERNEL="$(find "$KERNEL_DIR/boot" -maxdepth 1 -type f -name 'vmlinuz-*' | sort | tail -n1)"
[ -n "$KERNEL" ] || fail "kernel image not found"

INITRD="$BASE_DIR/initramfs.cpio.gz"
(cd "$INITRD_DIR" && find . -print | "$BUSYBOX" cpio -o -H newc 2>/dev/null | gzip -9 > "$INITRD")

HOST_PROBE_JSON="$BASE_DIR/host-landlock-probe.json"
HOST_PROBE_BIN="$BASE_DIR/host-landlock-probe"
cc -static -O2 -Wall -Wextra -o "$HOST_PROBE_BIN" "$PROJECT_DIR/scripts/landlock_probe.c"
set +e
"$HOST_PROBE_BIN" > "$HOST_PROBE_JSON"
HOST_PROBE_STATUS=$?
set -e

QEMU_LOG="$LOG_DIR/qemu-$(date +%Y%m%d-%H%M%S).log"
ACCEL=tcg
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ACCEL=kvm; fi
say "booting kernel $(basename "$KERNEL") with accel=$ACCEL"
set +e
timeout --foreground --kill-after=3s 120s qemu-system-x86_64 \
    -machine q35,accel="$ACCEL" \
    -m 256M -smp 1 \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append 'console=ttyS0 panic=-1 oops=panic rdinit=/init lsm=landlock' \
    -nographic -serial mon:stdio -monitor none -no-reboot -nodefaults -net none \
    >"$QEMU_LOG" 2>&1
QEMU_STATUS=$?
set -e

VM_STATUS="unknown"
if grep -q 'easy-sandbox-vm: complete status=0' "$QEMU_LOG"; then
    VM_STATUS=pass
elif grep -q 'easy-sandbox-vm: complete status=' "$QEMU_LOG"; then
    VM_STATUS=fail
fi

cat > "$RESULT_JSON" <<EOF
{
  "suite": "easy-sandbox-landlock-vm",
  "kernel": "$(basename "$KERNEL")",
  "host_uname": "$(uname -r)",
  "host_probe_exit": $HOST_PROBE_STATUS,
  "host_probe": $(cat "$HOST_PROBE_JSON"),
  "qemu_accel": "$ACCEL",
  "qemu_exit": $QEMU_STATUS,
  "policy_phase": $POLICY_PHASE,
  "vm_status": "$VM_STATUS",
  "qemu_log": "$QEMU_LOG"
}
EOF

cat "$RESULT_JSON"
say "last QEMU lines:"
tail -n 40 "$QEMU_LOG"
[ "$VM_STATUS" = pass ]

