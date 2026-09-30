# AgentSandbox P1 策略说明

P1 通过 `easy-sandbox run --secure` 启用。它不改变 rootfs、workspace、超时或资源限制的接口，只在载荷 exec 前增加两层内核约束。

Landlock 使用 ABI 3 的 hard requirement。`/` 只允许读取和执行，`/workspace` 与 `/tmp` 允许完整文件操作，`/dev/null`、`/dev/zero`、`/dev/urandom` 只允许设备读写和截断。没有 ABI 3 的内核直接返回初始化失败，不降级为 P0。

seccomp 使用默认允许、明确拒绝的静态规则，拒绝 mount/pivot_root/umount、namespace 进入和创建、ptrace/process_vm、bpf/keyctl、userfaultfd、io_uring、socket/socketpair 等入口；`clone` 只拒绝带 `CLONE_NEW*` 的 flags，普通 fork 和线程仍可用。`clone3` 返回 `ENOSYS` 以便 libc 回退到 `clone`。x86_64 额外拒绝 x32 syscall ABI。

这是静态基线，不是动态策略学习器。P1 不允许 Agent 在运行中放宽文件权限，也不提供网络代理；离线任务是当前支持范围。策略安装失败时载荷不会执行。

## 验证

```bash
export CARGO_TARGET_DIR=/mnt/g/DevCache/CargoTarget/EasySandbox
cargo fmt --check
cargo check --release
cargo test --release
python3 tests/smoke.py --binary target/release/easy-sandbox
```

`smoke.py` 会先运行 P0 验收，再用当前内核的 Landlock ABI 判断 `--secure` 应成功还是返回 `125`。WSL2 5.15 的 ABI 1 只能验证 fail-closed；`scripts/validate-vm.sh` 在 G 盘临时目录用 QEMU Ubuntu 6.8 做 ABI 3+ 的独立探针验证。

## 风险

- P1 仍共享宿主内核，不能替代 microVM 的硬件边界。
- socket 被默认拒绝，任何需要网络或 Unix socket 的 Agent 任务会失败；网络能力必须在后续显式策略中设计。
- seccomp 是拒绝列表而非完整 allowlist，后续需要用独立合法/禁止用例扩充回归测试。
