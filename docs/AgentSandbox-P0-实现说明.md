# AgentSandbox P0 实现说明

## 目标

在 Linux 上提供一个可由 Agent SDK 调用的最小进程沙箱：每次运行有独立的 user、mount、PID、network、IPC、UTS namespace；只有指定 rootfs 和 `/workspace` 可见；宿主环境变量和额外文件描述符不继承；超时能回收整个进程组。

P0 不承诺完整的安全策略。Landlock、seccomp、cgroups 和网络代理分别留在 P1–P4，避免在隔离边界还没被实测前堆出一个无法审计的大系统。当前已提供可选的 P1 `--secure`，但默认运行仍保持 P0 行为；P1 的规则和限制见 `docs/AgentSandbox-P1-策略说明.md`。

## 文件 / 模块

- `Cargo.toml`：基础依赖是 `libc`；Linux 目标额外启用 `landlock` 和 `seccompiler`，Windows 仍可只做 CLI/stub 检查。
- `src/main.rs`：CLI、父进程 supervisor、Linux namespace/mount/pivot_root、PID1 回收、rlimit 和能力清理。
- `README.md`：运行边界、命令行和部署限制。
- `tests/`：Linux 验收探针与 smoke test；不把它们伪装成通用单元测试。

## 执行顺序

1. 父进程校验 rootfs/workspace，创建 mount point，拒绝 root 身份和两个目录互相嵌套。
2. 父进程启动同一二进制的隐藏 `__child` supervisor，清空环境并建立独立 process group。
3. supervisor 设置 parent-death signal，创建 user/mount/net/IPC/UTS/PID namespace，写入单一 UID/GID 映射。
4. supervisor 把 rootfs bind 后只读重挂载，把外部 workspace 读写挂载到 `/workspace`，把 `/tmp` 和最小 `/dev` 挂载为临时 tmpfs，再执行 `pivot_root`。
5. supervisor fork 出 PID namespace 的可信 PID 1；PID 1 挂载本 namespace 的 `/proc`，关闭额外 FD、设置 `no_new_privs`、清空 capabilities 和 rlimit，然后再 fork 出载荷子进程。
6. 如果指定 `--secure`，载荷子进程在 exec 前安装 P1 的 Landlock 和 seccomp 规则；策略失败直接返回 125。可信 PID 1 等待载荷并转发退出码；它退出时，内核会终止本 PID namespace 中剩余进程，因此即使载荷调用 `setsid` 或清除自身 PDEATHSIG，超时和调用方死亡仍能回收。超时则杀 process group 中的可信 PID 1。

## 验证方式

在 WSL2 或真实 Linux 上，把 Cargo 目标目录设为 `G:\DevCache\CargoTarget\EasySandbox`（WSL 路径 `/mnt/g/DevCache/CargoTarget/EasySandbox`），执行：

```bash
cargo fmt --check
cargo check --release
python3 tests/smoke.py --binary target/release/easy-sandbox
```

验收重点是：宿主哨兵不可见、rootfs 写入失败、workspace 写入成功、网络连接失败、`/proc` 只显示沙箱 PID、宿主环境密钥不继承、超时后的后台子进程无残留、非法输入 fail closed。rootfs/workspace 需要放在 Linux 原生文件系统；WSL 下不要把它们放在 `/mnt/g` 的 DrvFs 目录，测试结果仍写到 `G:\DevCache\Temp\EasySandbox`。

## 真实风险

- 这是共享宿主内核的进程沙箱，不是 microVM；内核漏洞、侧信道和某些资源耗尽攻击仍在边界外。
- 默认 P0 尚无 Landlock/seccomp；`--secure` 才启用 P1 静态规则。namespace root 在 supervisor 阶段仍需要 mount capability，不能把 P0 对外描述成完整的 syscall 安全边界。
- `RLIMIT_NPROC` 是软限制，不等价于 cgroups 的 PID 限额；cgroups v2 不在当前四项后续路线内，生产部署需由外部运行时补充资源配额。
- rootfs/workspace 中的 Unix socket 仍可能代表外部服务能力，服务端不能把不受信任的 socket 暴露给载荷。
- WSL2 能力、发行版 AppArmor 配置、内核版本和宿主运行时策略可能使 unshare/tmpfs/pivot_root 失败；失败必须保持 fail closed。
