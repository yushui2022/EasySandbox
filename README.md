# EasySandbox

给 agent 工作负载用的、**故意做小**的 Linux 进程沙箱启动器：单文件 CLI，无 root 运行，没有守护进程，没有镜像格式，没有 API 服务。

它要回答的问题只有一个：*把一段不可信的 agent 生成代码放到宿主机上跑，怎么用尽可能少的机制把破坏面压到最小，并且让“到底限制了哪些东西”是能被审计、能被验收的？*

```bash
easy-sandbox run \
  --rootfs /srv/agent-rootfs \
  --workspace /srv/agent-work/123 \
  --policy docs/policy.example.yaml \
  -- /bin/sh -c 'printf ok > /workspace/result.txt'
```

## 定位

**它做**：把载荷关进 namespace，用只读 rootfs 和单一可写目录限制文件系统，用 Landlock + seccomp 在内核里收紧 syscall 面，用宿主侧 CONNECT 代理把出网收敛到一份域名白名单，并把“限制了哪些东西”和“验收结论”落成结构化记录。

**它不做**（也无意成为）：CubeSandbox / E2B / microVM 的替代品，不提供独立内核、不提供快照与热启动、不做多租户强隔离。边界是**共享宿主内核的单租户或受信任部署**。

## 特性

按层叠加，每一层都只能收紧，不能放宽。

| 层 | 内容 |
|---|---|
| **P0 进程隔离** | user / mount / PID / network / IPC / UTS namespace；rootfs 只读 bind；`/workspace` 读写挂载；64 MiB tmpfs `/tmp`；`pivot_root`；最小 `/dev`（`null`/`zero`/`urandom`）；清空环境变量、`close_range` 关掉继承的 FD；`no_new_privs`、capability 清零、AS/CPU/NPROC rlimit |
| **P0 生命周期** | 可信 PID 1 + 进程组 + `PDEATHSIG` 递归回收；墙钟超时杀整个进程组，载荷即使脱离会话也不会留在宿主上 |
| **P1 静态基线** | `--secure`：Landlock ABI 3（HardRequirement，不满足即 `125` fail closed）+ seccomp deny（namespace / mount / ptrace / bpf / io_uring / socket 等；`clone3` 返回 `ENOSYS`；x86_64 额外装 x32 guard） |
| **P2 声明式策略** | `--policy PATH`：版本化 YAML 描述文件读写、syscall 拒绝、资源上限；编译成叠加在 P1 之上的 Landlock + seccomp 层，限制值取三者中最严 |
| **P3 网络代理** | `network.mode: proxy`（或 `--proxy-allow HOST:PORT`）：出网只剩 `/run/proxy.sock` 一个 CONNECT 端点，代理跑在受信任的父进程里，是唯一做 DNS 和对外连接的组件 |
| **P4 记录与验收** | `--record PATH` 写 JSONL 运行事件；`mode: observe` 干跑并产出待审批候选；`easy-sandbox verify` 用独立用例验收一份策略并产出报告 |
| **P5 SDK** | Python（纯标准库）与 TypeScript（零依赖单文件），只拼参数、执行启动器、解释结果，不复制隔离逻辑 |

## 架构

父/子两段式：父进程是受信任的监督者，子进程是沙箱里可信的 PID 1。

```
调用方（CLI / SDK / 服务端）
      │
      ▼
┌─────────────────────────────────────────────────────┐
│ 父进程：受信任的监督者                                 │
│   · 解析策略 → 校验 → 预检能否执行，任何失败都是 125      │
│   · 把校验过的策略原文「冻结」后传给子进程               │
│   · 解析域名白名单、拉起 CONNECT 代理、写运行记录        │
│   · 看门狗：超时杀掉载荷的整个进程组                    │
└─────────────────────────────────────────────────────┘
      │ fork + clone(user/mount/PID/net/IPC/UTS)
      ▼
┌─────────────────────────────────────────────────────┐
│ 子进程：可信 PID 1                                   │
│   pivot_root → 清环境 → 清 capability → rlimit        │
│   ├─ L1 P1 基线（Landlock ABI 3 + seccomp）          │
│   ├─ L2 P2 策略（由 YAML 编译的叠加层）               │
│   └─ L3 P3 代理（唯一出网路径 /run/proxy.sock）        │
│                    ▼                                │
│              载荷进程（非特权 uid，capability 已清零）  │
└─────────────────────────────────────────────────────┘
```

两个刻意的设计决定：

- **父进程先校验、再冻结**。策略在父进程解析并预检“内核能不能执行”，然后以原文形式传给子进程；运行期间改动策略文件不会生效，子进程也不会重新读文件。
- **代理在父进程**。沙箱内没有任何 DNS 解析和对外连接能力，出网决策只由冻结的策略产生。

## 快速开始

Linux 或 WSL2。仓库用 Rust 2024 edition，需要 Rust 1.85+。

```bash
cargo build --release

# rootfs 由调用方预置：至少要有目标命令和动态链接器，或直接用静态 busybox
easy-sandbox run \
  --rootfs /srv/agent-rootfs \
  --workspace /srv/agent-work/123 \
  --timeout-ms 30000 \
  -- /bin/sh -c 'printf ok > /workspace/result.txt'
```

`rootfs` 会被绑定为**只读**，`workspace` 读写挂载到 `/workspace`，两者互不嵌套。启动器**拒绝以宿主 uid 0 运行**——避免把宿主 root 身份误当成安全的 user namespace 身份。

没有 Landlock 和 seccomp 也照样能跑：不带 `--secure` / `--policy` 时就是 P0 基线。

## CLI

### `easy-sandbox run`

| 参数 | 说明 |
|---|---|
| `--rootfs DIR` | 必填。只读根文件系统目录 |
| `--workspace DIR` | 必填。读写工作目录，挂到 `/workspace` |
| `--timeout-ms N` | 墙钟超时，默认 `30000` |
| `--memory-mib N` | 地址空间上限，默认 `512` |
| `--no-memory-limit` | 不设地址空间上限（仍可能被策略压回来） |
| `--cpu-seconds N` | CPU 时间上限 |
| `--max-processes N` | `RLIMIT_NPROC` 软限制 |
| `--secure` | 要求 Landlock ABI 3+ 并装载 P1 seccomp 基线 |
| `--policy PATH` | 装载 YAML 策略；隐含 `--secure` |
| `--proxy-allow HOST:PORT` | 直接用 CLI 给代理白名单，可重复 |
| `--record PATH` | 写 JSONL 运行记录，`-` 表示写 stderr |
| `-- COMMAND [ARGS...]` | 载荷命令 |

同一个参数重复出现时**最后指定的生效**，所以“服务端默认值 + 调用方覆盖”不需要额外语法。`--proxy-allow` 与策略里的 `network.mode: proxy` 不能同时用：两份白名单取并集就等于放宽了更严的那份。

### `easy-sandbox verify`

```bash
easy-sandbox verify --policy p.yaml --cases cases.yaml \
  --rootfs /srv/rootfs --workspace /srv/work \
  --report report.json --records records/
```

`--rootfs` / `--workspace` 必填，`--report` / `--records` 可选。要求策略是 `enforce` 模式。

### 退出码

| 码 | 含义 |
|---|---|
| `124` | 超时 |
| `125` | 沙箱初始化失败，含策略无法执行 |
| `126` | 载荷命令无法执行 |
| 其他 | 来自载荷 |
| `verify`：`0` 全通过 / `1` 有 fail / `2` 只剩 pending / `125` 输入或策略错误 |

## 策略

字段与注释见 [`docs/policy.example.yaml`](docs/policy.example.yaml)：

```yaml
version: 1

filesystem:
  read: [/usr, /bin, /lib, /lib64]   # 读取 + 执行
  write: [/workspace, /tmp]

network:
  mode: disabled                     # disabled | proxy
  allow: []                          # mode: proxy 时列 host/ports

limits:
  timeout_ms: 30000
  memory_mib: 512
  cpu_seconds: 30
  max_processes: 64

syscalls:
  deny: [mount, pivot_root, ptrace, bpf, keyctl]

mode: enforce                        # enforce | observe
```

- **只收紧，不放宽**。Landlock ruleset 是叠加的，seccomp 只增加拒绝项，`filesystem` 规则与固定挂载取交集——所以策略里写 `write: [/bin]` 也改不动只读 rootfs。
- `filesystem.read` 同时授予**执行**，目录规则覆盖整个子树，所以列 `/bin` 就够执行 `/bin/sh`。除列出的路径和固定的三个设备节点外，其余路径不可读、不可列目录、不可执行。
- `limits` 的值是**调用方的上限**。有效值取「启动器默认值、CLI 请求、策略上限」三者中最严的一个：策略压不掉调用方的显式请求？——不，策略永远赢；CLI 也永远赢不了策略。
- `syscalls.deny` 的名字在编译期映射为 seccomp 拒绝项（见 `src/policy.rs` 的 `resolve_syscall`）。**未知名字让整次运行以 `125` 失败**，不会静默忽略。
- 文档是严格的：未知字段、版本不符、非沙箱内绝对路径、相对路径、`.`/`..`、零值上限，全部 `125`。

## 网络

默认 `mode: disabled`，沙箱没有任何出网路径。`mode: proxy` 时载荷只能连到 `/run/proxy.sock`：

```bash
# 策略入口
easy-sandbox run --rootfs /srv/rootfs --workspace /srv/work \
  --policy docs/policy.example.yaml -- /bin/app

# 没有策略文件时用 CLI 直接给白名单
easy-sandbox run --rootfs /srv/rootfs --workspace /srv/work \
  --proxy-allow api.example.com:443 -- /bin/app
```

- 载荷用 HTTP `CONNECT host:port` 与代理通信，路径由 `$EASY_SANDBOX_PROXY` 给出（默认 `/run/proxy.sock`）。
- 只接受 `CONNECT`；只放行白名单里的**精确域名**与端口；**IP 字面量一律拒绝**，所以 `--proxy-allow` 也只接受域名。
- 域名在代理侧解析，**一次连接只解析一次**并把隧道钉在该地址上，客户端无法用第二次解析改变目的地。
- socket 是 0600、目录 0700、退出即删除；代理不读环境变量、不打开沙箱内任何文件，规则只来自冻结的策略。
- 每次判定记录一行：`task / policy_version / host / port / decision / reason / address / candidates`。

```
easy-sandbox: proxy task=1234 policy_version=1 host=api.example.com port=443 decision=allow reason=- address=93.184.216.34:443 candidates=93.184.216.34:443
easy-sandbox: proxy task=1234 policy_version=1 host=evil.example.com port=443 decision=deny reason=host-not-allowed address=- candidates=-
```

代理是**唯一的放宽点**：`mode: proxy` 把 P1 基线里“拒绝所有 socket syscall”改成“只允许 `AF_UNIX`”，`AF_INET`/`AF_INET6` 依然无法创建，沙箱自己的 network namespace 也没有路由。

## 记录与验证

`--record PATH` 写 JSONL（`-` 写 stderr）：

```bash
easy-sandbox run --rootfs /srv/rootfs --workspace /srv/work \
  --policy docs/policy.example.yaml --record run.jsonl -- /bin/app
```

每行一个事件，字段固定为 `v / seq / writer / run_id / policy_fingerprint / at_ms / kind`；`kind` 取 `run-started`、`restriction`、`candidate`、`network-decision`、`task-result`、`record-closed`。`run-started` 里带**冻结的策略原文**——所以“这一次到底按哪份策略跑的”不需要靠哈希去猜。各层的装载结果（`p1-baseline` / `policy-landlock` / `policy-seccomp` / `proxy`）由父进程依据子进程结果记录，与“载荷只在所有层装载成功后才运行”的契约一致。

`mode: observe` 是策略的**干跑**：P1 基线照常装载（观察不等于放宽），策略自己的 Landlock、seccomp 和代理层只记录不装载，并把策略要求的每一项限制写成 `candidate` 事件（`state: unapproved`）。审批方式就是把 `mode` 改成 `enforce` 再跑一次。

> 诚实说明：Landlock ABI 6 以下没有内核侧审计日志，所以 observe 记录的是**“策略打算限制什么”**，不是**“载荷实际用了什么”**。要拿到真实使用面需要内核审计或跟踪器，不在当前路线图内。

`verify` 用独立用例给一份 enforce 策略做回归：

```yaml
cases:
  - name: legit-write          # 必须能跑成
    expectation: allow
    command: ["/bin/sh", "-c", "printf ok > /workspace/out.txt"]
  - name: forbidden-read       # 必须被拒：命令自己因此失败
    expectation: deny
    command: ["/bin/sh", "-c", "cat /proc/self/status"]
  - name: still-unclear        # 不写 expectation → 判定保持 pending
    command: ["/bin/my-service", "--probe"]
```

判定规则：`allow` 且退出 0 → `pass`；`deny` 且退出非 0（且不是 124/125）→ `pass`；沙箱起不来（125）或超时（124）时 `deny` 用例**无法归因** → `pending`；没写 `expectation` → 永远 `pending`。报告字段见 [`docs/report.schema.json`](docs/report.schema.json)。

## SDK

[`sdk/python/`](sdk/python)（纯标准库）与 [`sdk/typescript/easysandbox.ts`](sdk/typescript/easysandbox.ts)（零依赖单文件，Node ≥ 22.6 用 `--experimental-strip-types` 直接运行）：

```python
from easysandbox import Outcome, RunRequest, Sandbox

sandbox = Sandbox("/usr/local/bin/easy-sandbox")
result = sandbox.run(
    RunRequest(rootfs="/srv/rootfs", workspace="/srv/work", policy="/srv/policy.yaml",
               record="/srv/run.jsonl", command=["/bin/app"])
)
if result.outcome is Outcome.TIMEOUT:
    ...

for event in sandbox.stream(RunRequest(rootfs="/srv/rootfs", workspace="/srv/work",
                                       command=["/bin/app"])):
    print(event["kind"])          # 边跑边收事件

report = sandbox.verify(policy="/srv/policy.yaml", cases="/srv/cases.yaml",
                        rootfs="/srv/rootfs", workspace="/srv/work")
```

```typescript
const sandbox = new Sandbox("/usr/local/bin/easy-sandbox");
const result = await sandbox.run({ rootfs, workspace, policy, command });
if (result.outcome === "enforcement_unavailable") { /* Landlock 版本不够 */ }

const stream = sandbox.stream({ rootfs, workspace, command });
for await (const event of stream.events) { console.log(event.kind); }

const verified = await sandbox.verify({ policy, cases, rootfs, workspace });
```

- `outcome` 把退出码和启动器的稳定标记合成枚举：`exited`、`timeout`（124）、`policy_rejected`（125 且 stderr 带 `policy-rejected`）、`enforcement_unavailable`（125 且带 `enforcement-failed`）、`exec_failed`（126）、`setup_failed`（其他 125）。
- `RunRequest.canonical()`、`result.canonical()`、`verify().canonical()` 在两种语言里**逐字节一致**：补全默认值、排序键、剔除易变字段（时间戳、序号、临时记录路径），便于跨语言对比与留档。
- `verify()` 按 `docs/report.schema.json` 校验报告，形状不符直接抛错；`verify().outcome` 区分 `all_passed`、`failed`、`pending`、`rejected`。
- 两个 SDK 都不复制隔离逻辑。

## 安全模型

**保证**：

- 载荷跑在独立 namespace 里，看不到宿主文件系统，rootfs 只读，只有 `/workspace` 可写。
- 载荷能力已清零、`no_new_privs` 已设、环境变量已清空、继承的 FD 已关闭。
- `--secure` / `--policy` 下额外限制不可绕过：Landlock 不满足即 fail closed，**不存在自动降级路径**。
- 策略只能收紧，Never 放宽 P0/P1；策略文件在运行期间被改动不影响本次运行。
- 载荷即使 fork 后脱离会话，超时也由父进程按进程组回收，不会留在宿主上。
- 出网只有代理一条路，代理只放行白名单里的精确域名，且每个连接只解析一次。

**不保证**：

- 不防内核漏洞。共享宿主内核，提权取决于内核本身。
- 不作多租户隔离。同一宿主上的其他租户/其他沙箱不在这套机制的保护范围内。
- 不限制 CPU 时间片之外的算力占用（`--cpu-seconds` 是累计 CPU 时间，不是墙钟配额）。
- 不校验 rootfs 与 workspace 的内容——**它们必须由服务端预置并由服务端掌控**。
- observe 模式下没有内核审计，无法回答“载荷实际用了什么”。
- 非 rootfs 分区的目录要访问，只能显式挂进 workspace。

## 验证

每个结论都有可复现的验收脚本，`tests/` 下的套件都输出 JSON 报告（`status` + 逐项 `ok/detail`），不会把未执行的项算作通过。

```bash
cargo fmt --check
cargo test --release

# 需要非特权账号（启动器拒绝 uid 0 运行）
python3 tests/smoke.py --binary target/release/easy-sandbox                 # P0/P1
python3 tests/policy_smoke.py --binary target/release/easy-sandbox          # P2 文档校验 + fail closed
python3 tests/network_smoke.py --binary target/release/easy-sandbox         # P3 代理边界（无需 Landlock）
python3 tests/observe_verify_smoke.py --binary target/release/easy-sandbox  # P4 记录与 verify 判定
EASY_SANDBOX_NODE=/path/to/node \
  python3 tests/sdk_smoke.py --binary target/release/easy-sandbox           # P5 跨 SDK 一致性
```

`sdk_smoke.py` 需要 Node ≥ 22.6 才能跑 TypeScript 那一半；没有就把 TypeScript 项标为 skipped，不会假装通过。

`--secure` / `--policy` 的**真实强制效果**需要 Landlock ABI 3+。WSL2 的 5.15 内核只报告 ABI 1，在那边验证到的是 fail-closed 分支；[`scripts/validate-vm.sh`](scripts/validate-vm.sh) 会启动 Ubuntu 6.8 QEMU 内核（ABI 4），把静态构建的启动器和 [`scripts/vm-policy-tests.sh`](scripts/vm-policy-tests.sh) 一起放进 initramfs 跑完整策略套件：

```bash
RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-gnu
EASY_SANDBOX_STATIC_BIN=target/x86_64-unknown-linux-gnu/release/easy-sandbox \
  scripts/validate-vm.sh
```

### 最近一次全量结果

| 套件 | 环境 | 断言 | 结果 |
|---|---|---|---|
| `cargo test --release` | WSL2 5.15 | 38 | pass |
| `tests/smoke.py`（P0/P1） | WSL2 5.15 / Landlock ABI 1 | 37 | pass |
| `tests/policy_smoke.py`（P2） | WSL2 5.15 / Landlock ABI 1 | 33 | pass |
| `tests/network_smoke.py`（P3） | WSL2 5.15 | 27 | pass |
| `tests/observe_verify_smoke.py`（P4） | WSL2 5.15 | 24 | pass |
| `tests/sdk_smoke.py`（P5） | WSL2 5.15 / Node 22.11 | 32 | pass |
| `vm-policy-tests.sh`（P2–P4 强制） | QEMU 6.8 / Landlock ABI 4 | 54 | `failures=0`，`vm_status: pass` |

VM 那 54 项才是 `--policy` 强制效果的真凭据：读写白名单生效、未列 syscall 被内核拒绝、P1 基线仍然生效、策略无法突破只读 rootfs、代理放行与拒绝、observe 只装载 P1 基线、verify 判定与报告形状。

## 目录结构

```
src/
  main.rs      CLI、父/子两段式监督者、参数与策略解析
  config.rs    版本化 YAML schema 与校验（含 LimitRequest 取严规则）
  policy.rs    P1 基线 + 由策略编译出的 Landlock/seccomp 层
  proxy.rs     宿主侧 CONNECT 代理与域名白名单
  run.rs       单次运行的编排
  events.rs    JSONL 运行记录
  verify.rs    用例、判定与报告
sdk/           Python / TypeScript SDK
tests/         Python 验收套件 + C 探针（probe.c）
scripts/       Landlock 探针、QEMU 验证链路、VM 内策略套件
docs/          P0 实现说明、P1 策略说明、P2–P5 路线图、策略示例、报告 schema
```

## 已知限制

- **只在 Linux 上有效**。Windows 上 `cargo check` 只能验证 CLI 和非 Linux stub，不能证明任何隔离效果。
- `--secure` / `--policy` 要求 Landlock ABI 3+；低于此不是“降级运行”，而是 `125` 失败。
- Landlock ABI < 6 没有内核审计，observe 只能记录策略意图。
- rootfs 与 workspace 由服务端预置并提供，沙箱不负责其内容正确性。
- 单租户 / 受信任部署，不是多租户隔离边界。

## 文档

- [P0 实现说明](docs/AgentSandbox-P0-实现说明.md)
- [P1 策略说明](docs/AgentSandbox-P1-策略说明.md)
- [P2–P5 路线图](docs/AgentSandbox-P2-P5-路线图.md)（模块、执行顺序、验收标准）
- [策略示例](docs/policy.example.yaml)
- [报告 schema](docs/report.schema.json)

## License

MIT
