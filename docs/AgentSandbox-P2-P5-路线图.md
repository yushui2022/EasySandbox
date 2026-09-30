# AgentSandbox 后续路线：P2–P5

当前路线只完善四项能力：网络代理与域名白名单、YAML 策略、observe/enforce/verify 闭环、Python/TypeScript SDK。项目不实现 microVM，也不承诺多租户对抗性安全保证。

## 进度

- **P2 已完成**：`src/config.rs` 保留版本化 schema；`src/policy.rs` 拆成 P1 基线（`enforce_baseline`）与由 schema 编译的策略层（`Plan::compile` / `enforce_policy`）；`src/main.rs` 增加 `--policy PATH`（隐含 `--secure`）与内部 `--frozen-policy`，并在父进程完成校验、限制取严和无策略时的默认值回退。
  验收证据：`cargo test --release` 覆盖 schema 与计划编译；`tests/policy_smoke.py` 在 WSL（Landlock ABI 1）验证 14 项非法或不可执行的策略输入全部 fail closed、合法策略与 `docs/policy.example.yaml` 不被文档错误拒绝；`scripts/validate-vm.sh` 在 Ubuntu 6.8（ABI 4）内核上跑 `scripts/vm-policy-tests.sh` 的 16 条断言，覆盖读写白名单、syscall 拒绝、P1 基线仍生效、策略无法突破只读 rootfs、策略上限收窄超时、`observe` 模式拒绝。
- **P3 已完成**：`src/proxy.rs` 提供宿主侧 CONNECT 代理（只接受 `CONNECT`、只放行精确域名与端口、拒绝 IP 字面量、每次连接只解析一次并钉住地址、按 `task / policy_version / host / port / decision / reason / address / candidates` 记录判定）；启动器把代理 socket 以 0600 绑在私有目录并 bind mount 到沙箱 `/run/proxy.sock`，父进程串行/并发地服务请求，退出时删除。`network.mode: proxy` 与 `--proxy-allow HOST:PORT` 是仅有的两个入口，二者互斥。
  验收证据：`tests/network_smoke.py` 在 WSL 上 27 项通过，覆盖允许目标端到端、拒绝其它域名/端口/IP 字面量/非 CONNECT 方法、拒绝目标不触达上游、调用方环境变量被忽略、直连不可达、隧道停摆由启动器超时回收、socket 目录被清理；`scripts/vm-policy-tests.sh` 在 ABI 4 内核上新增代理段，验证策略入口与 CLI 入口都能放行白名单目标并成功隧道、`AF_INET` 被 seccomp 拒绝而 `AF_UNIX` 保留。
- **P4 已完成**：`src/events.rs` 固定事件与报告类型（`v / seq / writer / run_id / policy_fingerprint / at_ms / kind`，`kind` 为 `run-started`、`restriction`、`candidate`、`network-decision`、`task-result`、`record-closed`）；`src/run.rs` 负责冻结策略（记录原文 + 变更指纹）、写 JSONL 并把策略要求转成未审批候选；`src/verify.rs` 解析独立用例、按纯函数判定 `pass/fail/pending` 并产出报告；`src/main.rs` 增加 `--record PATH`、`mode: observe` 的干跑语义与 `verify` 子命令；`docs/report.schema.json` 固化报告字段。
  验收证据：`cargo test` 覆盖事件往返、未知字段拒绝、候选枚举、记录追加与判定矩阵；`tests/observe_verify_smoke.py` 在 WSL 上 24 项通过（记录形状、策略原文冻结、ABI<3 时 observe 与 verify 都 fail closed、用例文件校验、enforce 模式要求）；`scripts/vm-policy-tests.sh` 在 ABI 4 内核上共 54 项断言全绿，其中 P4 部分验证 observe 只装载 P1 基线、策略层与代理记为未装载、候选全部 `unapproved`，以及 verify 让 allow/deny 用例 `pass`、未声明期望的用例保持 `pending`（退出码 2）并写出逐用例记录。
- **P5 已完成**：`sdk/python/`（纯标准库：`Sandbox.run/stream/verify`、`Outcome`/`VerifyOutcome` 枚举、按 `docs/report.schema.json` 校验报告）与 `sdk/typescript/easysandbox.ts`（零依赖单文件，`Sandbox.run/stream/verify` + Promise/AsyncGenerator API）。两者都不复制隔离逻辑，只拼参数、执行启动器、解释退出码、`policy-rejected` / `enforcement-failed` 标记与 JSONL 记录；`canonical()` 系列在两语言里产出逐字节一致的规范化请求/结果/报告。启动器同时补了稳定失败标记：策略文档问题一律带 `policy-rejected:`，强制层安装失败一律带 `enforcement-failed:`。
  验收证据：`tests/sdk_smoke.py` 用同一份 JSON spec 分别驱动两个 SDK 的命令行入口并逐字节比对（规范化请求、`exited`/`timeout`/`policy_rejected`/`enforcement_unavailable` 四种运行结果、verification 结果与报告），另在进程内验证 Python 的 `stream()`、报告校验与只读规范化；TypeScript 半边需要 Node ≥ 22.6，缺少运行时只记 skipped、不会假装通过。全部 P0–P5 套件合计：WSL 上 5 套 157 项断言，QEMU 6.8（ABI 4）54 项断言。

## 目标

在保持现有 P0/P1 进程隔离边界的前提下，把静态 `--secure` 基线变成一套可读、可验证、可被 Agent SDK 调用的策略执行接口。

## 模块与顺序

### P2：策略核心与 YAML

- `src/config.rs`：定义版本化 YAML schema，包含文件读写、网络、syscall、资源限制和任务模式。
- `src/policy.rs`：把 schema 编译成 Landlock、seccomp 和运行时参数；未知字段默认报错，不静默放宽权限。
- `src/main.rs`：增加 `--policy PATH`，保留现有 CLI 参数作为兼容入口。
- `docs/policy.example.yaml`：提供最小离线任务策略。

验收：同一份策略在 observe、enforce、verify 三种模式下解析结果一致；缺少必要字段、版本不支持或路径越界时返回 125；默认策略不能比 P0/P1 放宽。

### P3：网络代理与域名白名单

- `src/network.rs`：沙箱内只暴露代理入口，禁止直接出网。
- `src/proxy.rs`：在宿主侧执行 DNS 解析、域名/端口匹配和连接转发；默认拒绝 IP 直连、重定向到未授权域名和非 HTTP CONNECT 目标。
- `tests/network_smoke.py`：使用本地测试服务器覆盖允许域名、拒绝域名、IP 直连、DNS 重绑定和超时。

验收：允许列表之外的连接在内核/代理边界被拒绝；日志能关联任务、域名、端口、规则版本和结果；代理自身不继承 Agent 的文件、环境变量或工作目录权限。

### P4：observe / enforce / verify 闭环

- `src/events.rs`：统一事件格式，记录策略拒绝、候选权限需求、禁止行为尝试和任务验收结果。
- `src/run.rs`：冻结策略版本，执行一次任务并写出 JSONL 运行记录。
- `src/verify.rs`：对独立合法用例和明确禁止用例生成报告；未知事件保持待判定。
- `docs/report.schema.json`：固定报告字段，支持后续 SDK 消费。

验收：observe 只记录不自动放宽；enforce 按冻结策略拒绝；verify 使用未参与学习的独立用例；任何权限扩大都生成候选 diff 并等待人工审批。

### P5：Python / TypeScript SDK

- `sdk/python/`：提供同步执行、流式事件、超时和报告读取接口。
- `sdk/typescript/`：提供对应的 Promise/AsyncIterator API。
- SDK 只负责进程/API 调用和 schema 校验，不复制 namespace、Landlock 或 seccomp 逻辑。

验收：两个 SDK 对同一份策略产生相同的规范化请求和报告；沙箱退出码、超时、策略拒绝和验证结果都能被调用方稳定区分。

## 执行顺序

虽然产品能力按“网络、策略、闭环、SDK”描述，代码实现先做 P2 的 schema 和执行适配，再做 P3 网络代理；P4 依赖前两者的事件格式，P5 最后冻结公开接口。每个阶段都保留 P0/P1 smoke 回归。

## 真实风险

- 代理只解决网络访问控制，不改变共享宿主内核的边界。
- YAML 是配置面，不是安全边界；最终仍由 Landlock、seccomp、namespace 和代理内核/进程强制。
- observe 的新事件不能直接等同于越权；权限扩大必须人工审批。
- Python/TypeScript SDK 不提供额外隔离能力，调用方仍需使用受控 rootfs、workspace 和服务账号。
