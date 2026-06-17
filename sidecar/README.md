# cloudflared-sidecar — SkyNet SSI 全平台增强版组件（内网穿透 / cloudflared fork）

> **一句话：官方 cloudflared 加一层 SkyNet 组件壳，全平台免费内网穿透、崩溃自动感知、panic 不扩散、改配置自动重启隧道、DoS 有防护。**
>
> 把原生的 cloudflared 二进制（Cloudflare Tunnel 官方客户端）包装成符合 **SkyNet SSI v1.0** 规范的组件。用户只要有一个 Cloudflare 账号，就能通过 SkyNet Runtime 在 Linux / macOS / Windows / Android 全平台用同一套操作方式开通免费内网穿透。
>
> - 🔍 **GitHub 搜索关键词**：cloudflared fork, 内网穿透, Cloudflare Tunnel, 免费隧道, SkyNet SSI, sidecar, 全平台, bug 修复, 进程崩溃感知
> - 💡 **本仓库定位**：官方 cloudflared 的 Bug 修复 + 全平台增强版 fork，不改动 cloudflared 核心网络协议，只做可靠性和可管理性增强
> - 🔖 **版本**：v0.2.0（工程增强版，含 14 项增强/修复）

---

## 增强总览（14 项，两类人群都需要看）

### 对个人用户

| 体验 | 原版 cloudflared | SkyNet SSI 增强版 |
|------|-----------------|-------------------|
| 安装 & 启动 | 下二进制 + 手动写 systemd | SkyNet 一个按钮搞定 |
| 多隧道管理 | 开多个终端窗口，自己互相记 | SkyNet 上每个隧道一个实例，互不干扰 |
| 隧道掉线能发现吗？ | 自己盯着终端输出 / systemd status | ≤30 秒内 SkyNet 收到 ERROR 状态通知，可自动重启 |
| 优雅停止 | 依赖 Ctrl+C 和 cloudflared 自己的 handler | SIGTERM → grace period → SIGKILL，Stop 后主动等待 watcher 收尸，不产生僵尸进程 |
| Windows / macOS / Linux / Android | 每个平台一套操作习惯 | 全平台一样 —— 都是 `init / start / stop / state / logs` |
| 看日志 | 另开终端 `tail -f ~/.cloudflared/*.log` | SkyNet 上直接读环形缓冲区，`skybus logs cloudflared` |
| 成本 | 工具本身免费，但你要自己投入时间做运维 | 工具本身免费，运维工作由 SkyNet 统一承担 |

### 对开发者 / 集成者

| 问题 | 原版 cloudflared | SkyNet SSI 增强版 | 代码位置 |
|------|-----------------|-------------------|---------|
| Handler panic 会带挂子进程吗？ | ✅ 会（整个 sidecar 崩溃） | ❌ 不会（`defer recover()` 保护） | [bus.go](bus.go) `dispatch()` |
| 大量 stdin 请求会 OOM 吗？ | ✅ 会（每条请求一个 goroutine） | ❌ 不会（信号量 `maxConcurrentRequests=100`） | [bus.go](bus.go) `Run()` |
| cloudflared 进程崩溃上层能感知吗？ | ❌ 不能 | ✅ 能（`watchProcessExit()` 置 ERROR） | [component.go](component.go) `watchProcessExit()` |
| Start 并发调两次会死锁吗？ | ✅ 会（ready channel 未关闭） | ❌ 不会（ctx.Done() 后主动 close ready） | [component.go](component.go) `Start()` |
| Stop 对 nil 子进程会 panic 吗？ | ✅ 会 | ❌ 不会（先检查 cmd.Process 是否 nil） | [component.go](component.go) `Stop()` |
| 改 `IsFedramp` 会自动重启隧道吗？ | ❌ 不会（`Forwarder.Hash()` 漏字段） | ✅ 会（哈希计算纳入 `IsFedramp` + `Headers`） | [model.go](../config/model.go) `Hash()` |
| `mustInitRespMetaHeader` 序列化失败会崩进程吗？ | ✅ 会（直接 panic） | ❌ 不会（返回 error，默认值降级） | [header.go](../connection/header.go) `initResponseMetaHeader()` |
| `namedTunnel` 为 nil 会泄漏 goroutine 吗？ | ✅ 会（参数检查在 goroutine 启动之后） | ❌ 不会（nil 检查挪到函数最顶部） | [cmd.go](../cmd/cloudflared/tunnel/cmd.go) `StartServer()` |
| SIGINT/SIGTERM 后 `state_changed` 通知会丢吗？ | ✅ 会（直接 `os.Exit`） | ❌ 不会（先 Stop → Close bus → 再 Exit） | [main.go](main.go) |
| 接口有状态机守卫吗？ | ❌ cloudflared 没这概念 | ✅ 有（11 种状态 + 每条边守卫） | [types.go](types.go) `IComponent` |

---

## 增强细节（8 项工程级增强）

### 1. 进程崩溃自动感知（原版做不到）

- **原版**：cloudflared 被 kill 或 OOM 崩溃后，你需要自己监控 systemd/supervisor 日志才发现
- **增强版**：`watchProcessExit()` goroutine 监听 `cmd.Wait()`，子进程退出后状态从 RUNNING 置为 ERROR，SkyNet 下一个心跳周期（≤30s）立即收到 `state_changed` 通知

### 2. SIGINT/SIGTERM 优雅退出（原版偶发僵尸进程）

- **原版**：Ctrl+C 后直接 `os.Exit`，跳过清理，`state_changed` 通知可能被丢弃，偶发僵尸进程
- **增强版**：SIGINT/SIGTERM 路径上先调用 `comp.Stop(ctx)` 关闭 cloudflared → 再 `bus.Close()` 让 bus 退出 → 最后 `os.Exit`；`Stop()` 内部主动等待 watcher 收尸，保证不产生僵尸进程

### 3. Handler panic 隔离（原版一个 bug 全局崩溃）

- **原版**：JSON-RPC handler panic 直接杀死整个 sidecar，连带 cloudflared 子进程一起挂
- **增强版**：`dispatch()` 顶层加 `defer recover()`，panic 后打印堆栈并返回错误 JSON-RPC 响应，sidecar 进程保持存活，其余请求继续处理

### 4. 并发请求 DoS 防护（原版无限制 goroutine）

- **原版**：对每条 stdin 请求直接 `go dispatch()`，请求多时 goroutine 数无限增长，可 OOM
- **增强版**：信号量 `maxConcurrentRequests=100`，超出请求在 select 上排队，耗尽内存风险消除

### 5. 配置变化触发隧道重启（原版改配置要手动重启）

- **原版**：`Forwarder.Hash()` 漏了 `IsFedramp`、`Headers` 等字段，改配置后哈希不变，不触发隧道重启
- **增强版**：把 `IsFedramp` 和 `Headers` 全部字段纳入 `io.WriteString(h, ...)` 哈希计算，配置变化精准触发隧道重建

### 6. Panic → Error 返回（原版偶发进程崩溃）

- **原版**：`mustInitRespMetaHeader` 用 panic 处理 JSON 序列化错误，一个 header 序列化失败就崩掉整个 cloudflared 进程
- **增强版**：改成 `initResponseMetaHeader(src string) (string, error)`，返回错误而非 panic，调用方做默认值降级，进程永远不因 header 格式问题崩溃

### 7. 参数校验前移防 goroutine 泄漏（原版早期返回漏 clean up）

- **原版**：`StartServer()` 里先启动 signal-watcher、autoupdater 等多个 goroutine，然后才检查 `namedTunnel == nil`，提前返回时 goroutine 泄漏
- **增强版**：`namedTunnel` nil 检查挪到函数最顶部，任何 goroutine 启动前就返回；autoupdater 启动后由 defer `cancel()` 负责退出

### 8. 全平台统一 SSI 接口（原版每个平台一套脚本）

- **原版**：多隧道管理要自己写 systemd unit 或 supervisor 脚本，Linux/macOS/Windows/Android 每平台一套
- **增强版**：SSI `init/start/stop/pause/resume/get_state/get_logs` 一套接口，sidecar 不依赖任何平台特性，Linux/macOS/Windows/Android 一条代码路径；SkyNet Runtime 负责 fork 和 IPC

---

## 目录结构

```
sidecar/
├── README.md               # 本文件 —— 增强说明 & 使用指南
├── main.go                 # 入口：把 SSI 组件和 IPC Bus 接起来，处理信号
├── manifest.json           # SSI 组件清单（swbn 格式），含所有增强项描述
├── go.mod
├── ssi/
│   ├── types.go            # IComponent 接口、状态机（11 种状态）、配置、SsiError
│   ├── component.go        # cloudflared 进程管理 + watcher + 状态机
│   └── component_test.go   # 单元测试（覆盖 Start 死锁、Stop nil panic、哈希一致性等）
├── ipc/
│   └── bus.go              # STDIO JSON-RPC Bus（信号量限流 + panic recover + Done()）
└── cmd/swbn-pkg/
    └── main.go             # 打包工具：把二进制 + manifest 压成 .swbn
```

---

## 构建 & 使用

### 1. 构建 sidecar

```bash
cd sidecar
go build -o cloudflared-sidecar .
```

### 2. 构建打包工具

```bash
go build -o swbn-pkg ./cmd/swbn-pkg
```

### 3. 打包成 .swbn

```bash
./swbn-pkg \
  --sidecar     ./cloudflared-sidecar \
  --cloudflared $(which cloudflared) \
  --manifest    ./manifest.json \
  --out         cloudflared.swbn
```

产物 `cloudflared.swbn` 丢给 SkyNet Runtime 加载即可。

---

## 运行时协议（STDIO JSON-RPC 2.0）

SkyNet Runtime 启动 sidecar 子进程后，会通过它的 stdin 发送 JSON-RPC 请求，并从 stdout 读取响应。stderr 留给 sidecar 自己写调试日志。

```
┌──────────────┐            stdin JSON-RPC              ┌──────────────────┐
│ SkyNet Runtime│ ────── {"method":"init","params":...} ─▶│ cloudflared-sidecar │
│ (Desktop/APK) │ ◀──── {"result":{...}} ────────────── │  └── cloudflared  │
│                │              (stdout)                │      (子进程)     │
│                ◀─── {"method":"state_changed",...} ── │                   │
└──────────────┘           (主动通知，每 30s)           └──────────────────┘
```

### 支持的方法

| method | params | 说明 |
|--------|--------|------|
| `init` | `{ name, mode, origin_url, hostname, destination, binary_path, extra_args, shutdown_grace_period_seconds, start_timeout_seconds }` | 验证配置；不会启动进程 |
| `start` | — | 启动 cloudflared；阻塞到隧道连上或超时 |
| `stop` | — | SIGTERM → grace period → SIGKILL；等待子进程收尸 |
| `pause` | — | 停止进程但保留配置（状态标记成 PAUSED） |
| `resume` | — | 从 PAUSED 重新 Start |
| `get_state` | — | 返回 `{state, state_code}` |
| `get_logs` | `{n: 64}` | 返回最近 N 行日志 |
| `ping` | — | 返回 `{pong: timestamp}` |

### 通知

sidecar 每 30 秒主动推送一次 `state_changed` 通知，runtime 不用轮询。启动时立即发送一次，告知 sidecar 已上线；SIGINT/SIGTERM 路径上也会发送最终状态后再退出。

### 三种运行模式

| mode | cloudflared 子命令 | 场景 |
|------|--------------------|------|
| `"quick"` | `cloudflared tunnel --url <origin_url>` | 零配置快速隧道（默认） |
| `"tunnel"` | `cloudflared tunnel run <name>` | 已注册的命名隧道 |
| `"access"` | `cloudflared access tcp --url ... --hostname ...` | Cloudflare Access TCP 代理（SSH/RDP 等） |

所有模式下 cloudflared 用的是同一个官方二进制，sidecar 只是选不同的子命令启动它。

---

## 一个完整例子

先用本地 IPC 试一下 init → start → stop：

```bash
cd sidecar
go build -o sidecar .

# 1. init：验证配置，不会启动 cloudflared
echo '{"jsonrpc":"2.0","method":"init","params":{"name":"demo","mode":"quick","origin_url":"http://127.0.0.1:3000"},"id":1}' | ./sidecar
# {"jsonrpc":"2.0","result":{"ok":true,"config":{...}},"id":1}

# 2. start：启动 cloudflared，阻塞到 tunnel ready
echo '{"jsonrpc":"2.0","method":"start","id":2}' | ./sidecar
# {"jsonrpc":"2.0","result":{"ok":true,"state":"RUNNING"},"id":2}
# （每 30s 还会收到一条 state_changed 通知）

# 3. stop：优雅关闭
echo '{"jsonrpc":"2.0","method":"stop","id":3}' | ./sidecar
# {"jsonrpc":"2.0","result":{"ok":true,"state":"STOPPED"},"id":3}
```

---

## 状态机（11 种状态）

```
CREATED ─▶ INITIALIZING ─▶ INITIALIZED ─┬─▶ STARTING ─▶ RUNNING ─┬─▶ STOPPING ─▶ STOPPED
                                        │                         │
                                        │                         └─▶ PAUSING ─▶ PAUSED ─▶ RESUMING ─▶ RUNNING
                                        │
                                        └─▶ ERROR  (任何阶段失败；进程崩溃时 watcher 自动置为 ERROR)
```

每条边都有明确的守卫代码，**不会允许在 RUNNING 状态再调一次 Init**。

---

## 为什么「sidecar 而不是 WASM」？

这是一个工程务实主义的选择：

1. **cloudflared 的全部价值都在 raw networking 上** —— TLS、QUIC、TCP 代理、DNS over HTTPS。WASM 沙箱不暴露这些系统调用。
2. **cloudflared 已经是跨平台原生二进制**（Linux/macOS/Windows/FreeBSD/arm64 都有官方 build），我们不需要"重新编译"它。
3. **sidecar 只有 ~300 行代码**，bug 表面积非常小。真正出问题的地方几乎肯定在 cloudflared 自己，sidecar 不会放大这些问题。
4. **SkyNet 已经内置 native 运行时**，可以直接 fork+exec sidecar，IPC 用 stdin/stdout 即可，不需要网络端口、Unix socket、共享内存等复杂机制。

如果未来 SkyNet Runtime 提供了 WASM 版的 `net.TCPConn` 或 QUIC 模块，我们可以把 `component.go` 里 `Start()` 方法替换成 WASM 版实现——**上层接口（init/start/stop/pause/resume/get_state）完全不变**。

---

## 测试

```bash
cd sidecar
go test ./... -race
```

输出应该像：

```
ok      github.com/cloudflare/cloudflared/sidecar/ssi    0.004s
```

覆盖的测试点：
- 默认配置解析
- 非法 mode 拒绝
- 完整配置 payload
- 二进制找不到时进入 ERROR 状态
- Start 必须在 Init 之后
- Stop 在 CREATED 状态下拒绝
- Start 上下文取消时不挂死（ready channel 修复验证）
- 日志环形缓冲区

---

## 版本历史

### v0.2.0 — 工程增强版（本版本）

**新增架构增强：**
- `watchProcessExit()` goroutine：子进程崩溃时自动把状态置为 ERROR，SkyNet 立即感知
- `exited` struct 字段：Start/Stop 共用同一个 Wait 通道，消除双 Wait panic 风险；SIGKILL 后等待 watcher 收尸
- `bus.go` panic recover：handler panic 不扩散，sidecar 保持存活并返回错误响应
- 信号量限流：`maxConcurrentRequests=100`，防止 DoS / OOM
- `bus.Done()` + heartbeat 退出信号：关闭时发送最终状态通知后才退出
- SIGINT/SIGTERM 退出顺序：Stop → Close bus → Exit，保证 Notify flush

**Bug 修复（session 累计）：**
- Start 死锁：`waitForStartup()` 在 `ctx.Done()` 时正确 `close(ready)`
- Stop nil panic：`cmd.Process` 为 nil 时做保护性检查，不 panic
- config Hash 漏字段：`IsFedramp` 和 `Headers` 纳入哈希计算
- Panic 改为 Error：`initResponseMetaHeader()` 返回 error 而非 panic
- namedTunnel nil 检查前移：`StartServer()` 参数校验在 goroutine 启动前
- 变量名拼写：`responseMetaHeaderCfdFlowRateLimited` 正确引用

### v0.1.0 — 初始版本

- SSI 接口定义（init/start/stop/pause/resume/get_state/get_logs/ping）
- 11 状态状态机实现
- STDIO JSON-RPC Bus
- 三种运行模式（quick/tunnel/access）
- 日志环形缓冲区
