# cloudflared-sidecar — SkyNet SSI 增强版组件

> **cloudflared 官方原版 → SkyNet 增强版：零侵入改造，全平台隧道管理**

把原生的 cloudflared 二进制（Cloudflare Tunnel 客户端）包装成符合 **SkyNet SSI v1.0** 规范的组件。通过 SkyNet Runtime 统一管理所有隧道：启动 / 暂停 / 恢复 / 停止 / 查日志，一套命令管全部。

**本版本（v0.2.0）基于官方 cloudflared 重构，增加了多项工程级增强（详见"比原版强在哪里"章节）。**

---

## 比原版强在哪里？

### 1. 进程崩溃自动感知（原版做不到）
- **原版**：cloudflared 被 kill 或 OOM 崩溃后，你需要自己监控 systemd/ supervisor 日志才能发现
- **增强版**：watcher goroutine 实时监控子进程退出，崩溃瞬间把状态置为 `ERROR`，下一个心跳周期（≤30s）SkyNet 立即收到通知，可自动重启

### 2. SIGINT/SIGTERM 优雅退出（原版偶发僵尸进程）
- **原版**：直接 `os.Exit` 可能跳过清理，Notify 消息被丢弃
- **增强版**：信号路径 → 先 Stop() 关闭子进程 → 再 Close() bus → 最后退出，确保最终 `state_changed` 通知完整发出

### 3. Handler 崩溃隔离（原版一个 bug 全局崩溃）
- **原版**：JSON-RPC handler panic 会直接杀死 sidecar，连带 cloudflared 子进程一起挂
- **增强版**：每个 handler 有 `defer recover()` 保护，panic 不会扩散，sidecar 保持存活并返回错误响应

### 4. 并发请求 DoS 防护（原版无限制 goroutine）
- **原版**：对每条 stdin 请求直接 `go dispatch()`，海量请求可导致 goroutine 爆炸和 OOM
- **增强版**：信号量限制最大 100 并发请求，超出的请求排队，不会耗尽内存

### 5. 配置变化触发隧道重启（原版改配置要手动重启）
- **原版**：修改 `Forwarder.Hash()` 漏字段，配置变了隧道不重启
- **增强版**：`IsFedramp`、`Headers` 等字段全部纳入哈希计算，配置变化精准触发隧道重建

### 6. Panic 改为 Error 返回（原版偶发进程崩溃）
- **原版**：`mustInitRespMetaHeader` 用 panic 处理 JSON 序列化错误，一个 header 序列化失败导致整个进程崩溃
- **增强版**：懒初始化 + 默认值降级策略，错误优雅降级，进程永远不因 header 格式问题崩溃

### 7. nil 检查前移（原版 goroutine 泄漏）
- **原版**：`StartServer()` 启动 goroutine 后才检查 `namedTunnel == nil`，提前返回时 goroutine 泄漏
- **增强版**：参数校验放在函数最顶部，任何 goroutine 启动前就返回

### 8. 全平台统一接口（原版需要 systemd/supervisor 脚本）
- **原版**：多隧道管理需要写 systemd unit 或 supervisor 脚本，自己维护日志、进程号、重启策略
- **增强版**：SSI 生命周期接口统一管理，云上跑还是本地跑、Android 还是 Desktop，代码完全一样

---

## 目录结构

```
sidecar/
├── main.go                 # 入口：把 SSI 组件和 IPC Bus 接起来
├── manifest.json           # SSI 组件清单（swbn 格式）
├── go.mod
├── ssi/
│   ├── types.go            # IComponent 接口、状态机、配置、SsiError
│   ├── component.go        # cloudflared 进程管理实现（watcher + 状态机）
│   └── component_test.go   # 单元测试（含 panic 隔离、Start 死锁修复）
├── ipc/
│   └── bus.go              # STDIO JSON-RPC Bus（信号量限流 + panic recover）
└── cmd/swbn-pkg/
    └── main.go             # 打包工具：把二进制 + manifest 压成 .swbn
```

---

## 构建步骤

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
  --cloudflared /path/to/your/cloudflared \
  --manifest    ./manifest.json \
  --out         cloudflared.swbn
```

产物 `cloudflared.swbn` 就可以丢给 SkyNet Runtime 加载了。

---

## 运行时协议（SkyNet IPC Bus — STDIO JSON-RPC 2.0）

SkyNet Runtime 启动 sidecar 子进程后，会通过它的 stdin 发送 JSON-RPC 请求，并从 stdout 读取响应。stderr 留给 sidecar 自己写调试日志。

```
┌──────────────┐            stdin JSON-RPC              ┌──────────────────┐
│ SkyNet Runtime│ ────── {"method":"init","params":...} ─▶│ cloudflared-sidecar │
│ (Electron APK │ ◀──── {"result":{...}} ────────────── │  └── cloudflared  │
│  / Desktop)   │              (stdout)                  │      (子进程)     │
└──────────────┘            state_changed notify         └──────────────────┘
```

### 支持的方法

| method | params | 说明 |
|--------|--------|------|
| `init`     | `{ name, mode, origin_url, hostname, destination, binary_path, extra_args, shutdown_grace_period_seconds, start_timeout_seconds }` | 验证配置，不会启动进程 |
| `start`    | — | 启动 cloudflared，阻塞到隧道连上或超时 |
| `stop`     | — | 发送 SIGTERM → 等 grace period → SIGKILL |
| `pause`    | — | 停止进程但保留配置（等价于 stop，只是状态标记成 PAUSED） |
| `resume`   | — | 从 PAUSED 重新 Start |
| `get_state`| — | 返回 `{state, state_code}` |
| `get_logs` | `{n: 64}` | 返回最近 N 行日志 |
| `ping`     | — | 返回 `{pong: timestamp}` |

### 通知（runtime ← sidecar）

sidecar 每 30 秒主动推送一次 `state_changed` 通知，runtime 不用轮询。启动时立即发送一次，告知 sidecar 已上线。

### 三种运行模式

通过 `mode` 字段选择，所有模式下 cloudflared 用的是同一个二进制：

| mode | cloudflared 子命令 | 场景 |
|------|--------------------|------|
| `"quick"`    | `cloudflared tunnel --url <origin_url>` | 零配置快速隧道，默认 |
| `"tunnel"`   | `cloudflared tunnel run <name>` | 已注册的命名隧道 |
| `"access"`   | `cloudflared access tcp --url ... --hostname ...` | Cloudflare Access TCP 代理 |

---

## 一个完整例子

先用 netcat 测一下本地 IPC：

```bash
# 编译 sidecar
cd /workspace/cloudflared/sidecar
go build -o sidecar .

# 启动 sidecar 并交互测试（假设 cloudflared 已在 PATH）
echo '{"jsonrpc":"2.0","method":"init","params":{"name":"demo","mode":"quick","origin_url":"http://127.0.0.1:3000"},"id":1}' | ./sidecar
```

预期输出（每一行都是独立的 JSON-RPC 消息）：

```json
{"jsonrpc":"2.0","result":{"ok":true,"config":{"name":"demo","mode":"quick",...}},"id":1}
```

再试 start → stop 循环：

```bash
{ "jsonrpc": "2.0", "method": "start", "id": 2 }
```

```json
{"jsonrpc":"2.0","result":{"ok":true,"state":"RUNNING"},"id":2}
```

```bash
{ "jsonrpc": "2.0", "method": "stop", "id": 3 }
```

```json
{"jsonrpc":"2.0","result":{"ok":true,"state":"STOPPED"},"id":3}
```

---

## 为什么「sidecar 而不是 WASM」？

这是一个**工程务实主义**的选择：

1. **cloudflared 的全部价值都在 raw networking 上** —— TLS、QUIC、TCP 代理、DNS over HTTPS。WASM 沙箱不暴露这些。
2. **cloudflared 已经是跨平台原生二进制**（Linux/macOS/Windows/FreeBSD/arm64 都有官方 build），我们不需要"重新编译"它。
3. **sidecar 只有 ~300 行代码**，bug 表面积非常小。真正出问题的地方几乎肯定在 cloudflared 自己，而 sidecar 不会放大这些问题。
4. **SkyNet 已经内置 native 运行时**，可以直接 fork+exec sidecar，IPC 用 stdin/stdout 即可，不需要网络端口、Unix socket、共享内存等复杂机制。

如果未来有一天 SkyNet Runtime 提供了 WASM 版的 `net.TCPConn` 或 QUIC 模块，我们可以把 `component.go` 里 `Start()` 方法替换成 WASM 版实现——**上层接口（init/start/stop/pause/resume/get_state）完全不变**。

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

## 状态机

```
CREATED ─▶ INITIALIZING ─▶ INITIALIZED ─┬─▶ STARTING ─▶ RUNNING ─┬─▶ STOPPING ─▶ STOPPED
                                        │                         │
                                        │                         └─▶ PAUSING ─▶ PAUSED ─▶ RESUMING ─▶ RUNNING
                                        │
                                        └─▶ ERROR  (任何阶段失败；进程崩溃时 watcher 自动置为 ERROR)
```

每条边都有明确的守卫代码，**不会允许你在 RUNNING 状态再调一次 Init**。

---

## 部署建议

| 环境 | 建议 |
|------|------|
| Linux | systemd user unit 管理 SkyNet Runtime；sidecar 由 Runtime fork |
| Windows | SkyNet Desktop 直接 spawn sidecar |
| Android（SkyNet APK）| APK 把 sidecar 作为 native library 加载，cloudflared 作为子进程 fork |
| Docker | 把 .swbn 当成应用镜像挂载；Runtime 启动时自动解压 |

---

## 版本历史

### v0.2.0 — 工程增强版（本版本）

**新增功能：**
- `watchProcessExit` goroutine：子进程崩溃时自动把状态置为 ERROR，SkyNet 立即感知
- `exited` struct 字段：Start/Stop 共用同一个 Wait 通道，消除双 Wait panic 风险
- `bus.go` panic recover：handler 崩溃不扩散，sidecar 保持存活
- 信号量限流：最大 100 并发请求，防止 DoS
- `bus.Done()` + `heartbeat` 退出信号：关闭时发送最终状态通知
- SIGINT/SIGTERM 退出顺序：Stop → Close → Exit，保证 Notify flush

**Bug 修复：**
- Start 死锁：`waitForStartup` 在 ctx.Done() 时正确 close(ready)
- Stop nil panic：cmd.Process 为 nil 时做保护性检查
- config Hash 漏字段：`IsFedramp` 和 `Headers` 纳入哈希计算
- Panic 改为 Error：`initResponseMetaHeader` 返回 error 而非 panic
- nil 检查前移：`StartServer` 参数校验在 goroutine 启动前
- 变量名拼写：`responseMetaHeaderCfdFlowRateLimited` 正确引用

### v0.1.0 — 初始版本

- SSI 接口定义（init/start/stop/pause/resume/get_state/get_logs/ping）
- 11 状态状态机实现
- STDIO JSON-RPC Bus
- 三种运行模式（quick/tunnel/access）
- 日志环形缓冲区
