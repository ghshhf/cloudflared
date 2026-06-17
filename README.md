# Cloudflare Tunnel client（SkyNet SSI 增强版 fork — 全平台免费内网穿透）

> **【本仓库是什么】** 这是 cloudflared 官方仓库的 Bug 修复 + 全平台增强版 fork。上游 cloudflared 是 Cloudflare Tunnel 官方客户端，我们在不改动 cloudflared 核心网络协议的前提下，补齐了它作为"系统组件"在可靠性、可管理性、可观测性上的多处短板，让它能被 SkyNet Runtime 全平台托管。**用户只需一个 Cloudflare 账号，就能在 Linux / macOS / Windows / Android 全平台用同一套操作方式开通免费内网穿透。**
>
> **为什么需要这个 fork：** 官方 cloudflared 是一个"命令行工具"，你需要自己写 systemd unit、自己写 supervisor 脚本、自己想办法监控进程崩溃、自己处理多隧道管理。而在本仓库的 `sidecar/` 目录里，我们给它套上了一层符合 [SkyNet SSI v1.0](sidecar/README.md) 规范的组件壳：**它仍然是你熟悉的那个 cloudflared，只是变得能被 SkyNet 一键启动、崩溃会自动报错、能在 Android 上跑、改配置会自动重启隧道、handler panic 不会把整个子进程带挂。**
>
> **增强点速览（14 项，按 session 汇总）：** 进程崩溃自动感知（watcher goroutine）｜panic 隔离（defer recover）｜并发请求 DoS 防护（信号量限流 100）｜SIGINT/SIGTERM 优雅退出｜配置哈希包含 IsFedramp + Headers｜mustInitRespMetaHeader panic→error 返回｜namedTunnel nil 检查前移防 goroutine 泄漏｜Start 死锁修复｜Stop nil panic 修复｜变量名拼写修复｜全平台统一 SSI 生命周期接口｜统一状态机（11 种状态）｜环形日志缓冲区｜30 秒心跳 `state_changed` 通知

---

Contains the command-line client for Cloudflare Tunnel, a tunneling daemon that proxies traffic from the Cloudflare network to your origins.
This daemon sits between Cloudflare network and your origin (e.g. a webserver). Cloudflare attracts client requests and sends them to you
via this daemon, without requiring you to poke holes on your firewall --- your origin can remain as closed as possible.
Extensive documentation can be found in the [Cloudflare Tunnel section](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel) of the Cloudflare Docs.
All usages related with proxying to your origins are available under `cloudflared tunnel help`.

You can also use `cloudflared` to access Tunnel origins (that are protected with `cloudflared tunnel`) for TCP traffic
at Layer 4 (i.e., not HTTP/websocket), which is relevant for use cases such as SSH, RDP, etc.
Such usages are available under `cloudflared access help`.

You can instead use [WARP client](https://developers.cloudflare.com/warp-client/)
to access private origins behind Tunnels for Layer 4 traffic without requiring `cloudflared access` commands on the client side.

---

## 这一版 fork 比官方原版强在哪里？（8 项工程级增强）

| # | 增强项 | 原版 cloudflared | SkyNet SSI 增强版 | 代码位置 |
|---|--------|-----------------|-------------------|---------|
| 1 | **进程崩溃自动感知** | 子进程被 kill/OOM 后，需要自己翻 systemd 日志才知道 | watcher goroutine 监听 `cmd.Wait()`，崩溃后状态置为 ERROR，≤30s 发到 SkyNet 告警 | [sidecar/ssi/component.go](sidecar/ssi/component.go) `watchProcessExit()` |
| 2 | **优雅退出顺序** | Ctrl+C 后直接 `os.Exit`，`state_changed` 通知可能被丢，偶尔产生僵尸进程 | SIGTERM → grace period → SIGKILL；Stop 后主动等待 watcher 收尸；SIGINT/SIGTERM 路径上先 Stop 再 Close bus 再 Exit | [sidecar/ssi/component.go](sidecar/ssi/component.go) `Stop()`；[sidecar/main.go](sidecar/main.go) |
| 3 | **Panic 隔离** | 一个 handler panic 就杀死整个 sidecar，连带 cloudflared 子进程一起挂 | `dispatch()` 顶层加 `defer recover()`，panic 后返回错误响应但 sidecar 保持存活 | [sidecar/ipc/bus.go](sidecar/ipc/bus.go) `dispatch()` |
| 4 | **DoS 防护** | 对每条 stdin 请求直接 `go dispatch()`，请求多时 goroutine 爆炸，可 OOM | 信号量限流 `maxConcurrentRequests=100`，超出请求排队 | [sidecar/ipc/bus.go](sidecar/ipc/bus.go) `Run()` |
| 5 | **配置变化触发重启** | `Forwarder.Hash()` 漏字段，改了 `IsFedramp`/`Headers` 后隧道不重启 | 哈希计算纳入全部相关字段，配置变化精准触发重建 | [config/model.go](config/model.go) `Hash()` |
| 6 | **Panic → Error** | `mustInitRespMetaHeader` 用 panic 处理 JSON 序列化错误，一次 header 失败就崩进程 | 改成 `error` 返回 + 懒初始化 + 默认值降级 | [connection/header.go](connection/header.go) `initResponseMetaHeader()` |
| 7 | **参数校验前移** | `StartServer()` 启动 goroutine 后才检查 `namedTunnel == nil`，提前返回时 goroutine 泄漏 | nil 检查挪到函数最顶部，任何 goroutine 启动前就返回 | [cmd/cloudflared/tunnel/cmd.go](cmd/cloudflared/tunnel/cmd.go) `StartServer()` |
| 8 | **全平台统一接口** | 多隧道管理要自己写 systemd/supervisor，每平台一套操作习惯 | SSI `init/start/stop/pause/resume/get_state/get_logs` 一套接口，Linux/macOS/Windows/Android 全平台一条代码路径 | [sidecar/ssi/types.go](sidecar/ssi/types.go) `IComponent` 接口 |

---

## 个人用户：用它是什么体验？

**核心承诺：只要你有一个 Cloudflare 账号，全平台免费内网穿透就能跑。**

- **准备阶段**：登录一次 Cloudflare（或者注册一个免费账号），拿到 token；在本地电脑上装 SkyNet Desktop（或在 Android 上装 SkyNet APK）。
- **平时使用**：在 SkyNet 里点开 "cloudflared" 组件，填入你想暴露的本地地址（例如 `http://127.0.0.1:3000` 是你本地开发的网站），点启动即可。
- **多隧道管理**：想同时暴露 3000 端口、5000 端口、一个 VNC 的 5900 端口？分别创建三个 `cloudflared@xx` 组件实例，互相独立、互不干扰。
- **不需要**：手动写 systemd unit、手动跑 `cloudflared tunnel login`、自己开三个终端窗口、自己写重启脚本。
- **云免费层**：Cloudflare 对个人用户有免费额度，Tunnel 功能本身免费，所以这条链路对你来说零成本。

---

## 开发者：用它是什么体验？

**集成成本从 N 降到 1：** 你只要会发 JSON-RPC 消息，就能管 cloudflared。`init/start/stop/pause/resume/get_state/get_logs` 一套协议，SkyNet 的 Desktop、APK、CLI 三套壳子共用。

**可靠性从"依赖外部系统"到"自带沙箱"：** 上层系统给 sidecar 发的任何请求，不会因为一个 handler bug 让整个 sidecar 进程死掉；子进程崩溃后 sidecar 能主动把状态置为 ERROR，你可以基于这个状态做自动重启。

**接口严格、状态可观测：** 11 种状态 + 每条状态边有守卫（例如 RUNNING 状态下再调用 Init 会直接被拒绝），上层代码几乎不可能写出"时序错了就出怪问题"的 bug。

**构建：**

```bash
cd sidecar
go build -o cloudflared-sidecar .        # 构建 sidecar
go test ./... -race                        # 跑单元测试
./swbn-pkg --sidecar ./cloudflared-sidecar --cloudflared $(which cloudflared) --manifest ./manifest.json --out cloudflared.swbn
```

生成的 `.swbn` 可以直接丢给 SkyNet Runtime 加载。

---

## Before you get started（官方原文保留）

Before you use Cloudflare Tunnel, you'll need to complete a few steps in the Cloudflare dashboard: you need to add a
website to your Cloudflare account. Note that today it is possible to use Tunnel without a website (e.g. for private
routing), but for legacy reasons this requirement is still necessary:
1. [Add a website to Cloudflare](https://developers.cloudflare.com/fundamentals/manage-domains/add-site/)
2. [Change your domain nameservers to Cloudflare](https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/)

## Installing `cloudflared`

Downloads are available as standalone binaries, a Docker image, and Debian, RPM, and Homebrew packages. You can also find releases [here](https://github.com/cloudflare/cloudflared/releases) on the `cloudflared` GitHub repository.

* You can [install on macOS](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/#macos) via Homebrew or by downloading the [latest Darwin amd64 release](https://github.com/cloudflare/cloudflared/releases)
* Binaries, Debian, and RPM packages for Linux [can be found here](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/#linux)
* A Docker image of `cloudflared` is [available on DockerHub](https://hub.docker.com/r/cloudflare/cloudflared)
* You can install on Windows machines with the [steps here](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/#windows)
* To build from source, install the required version of go, mentioned in the [Development](#development) section below. Then you can run `make cloudflared`.

User documentation for Cloudflare Tunnel can be found at https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/

## Creating Tunnels and routing traffic

Once installed, you can authenticate `cloudflared` into your Cloudflare account and begin creating Tunnels to serve traffic to your origins.

* Create a Tunnel with [these instructions](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/get-started/create-remote-tunnel/)
* Route traffic to that Tunnel:
  * Via public [DNS records in Cloudflare](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/)
  * Or via a public hostname guided by a [Cloudflare Load Balancer](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/public-load-balancers/)
  * Or from [WARP client private traffic](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/private-net/)

## TryCloudflare

Want to test Cloudflare Tunnel before adding a website to Cloudflare? You can do so with TryCloudflare using the documentation [available here](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/trycloudflare/).

## Deprecated versions

Cloudflare currently supports versions of cloudflared that are **within one year** of the most recent release. Breaking changes unrelated to feature availability may be introduced that will impact versions released more than one year ago. You can read more about upgrading cloudflared in our [developer documentation](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/update-cloudflared/).

## Development

### Requirements
- [GNU Make](https://www.gnu.org/software/make/)
- [capnp](https://capnproto.org/install.html)
- [go >= 1.26](https://go.dev/doc/install)
- Optional tools:
  - [capnpc-go](https://pkg.go.dev/zombiezen.com/go/capnproto2/capnpc-go)
  - [goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports)
  - [golangci-lint](https://github.com/golangci/golangci-lint)
  - [gomocks](https://pkg.go.dev/go.uber.org/mock)

### Build
To build cloudflared locally run `make cloudflared`

### Test
To locally run the tests run `make test`

### Linting
To format the code and keep a good code quality use `make fmt` and `make lint`

### Mocks
After changes on interfaces you might need to regenerate the mocks, so run `make mocks`

### Git Hooks
To avoid CI errors, you can install pre-push hooks that run linting and tests before each push:
```bash
make install-hooks
```
This will configure git to use the hooks in `.githooks/` that run `make fmt-check lint test` before each push.

---

## 版本对照

本 fork 的发行基于以下语义：

| Tag | cloudflared 上游版本 | SkyNet SSI sidecar 版本 |
|-----|---------------------|-------------------------|
| `skynet/v0.2.0` | 与上游 master 同步 | v0.2.0（工程增强版，14 项 bug fix） |
| `skynet/v0.1.0` | 与上游 master 同步 | v0.1.0（初始版本，SSI 接口 + STDIO JSON-RPC Bus） |

**上游持续同步策略：** 我们定期把官方 cloudflared 的 commit 合并回这个 fork。sidecar/ 目录对 cloudflared 主二进制是零侵入的，所以合并冲突只在我们改过的几个文件上出现（`config/model.go`、`connection/header.go`、`cmd/cloudflared/tunnel/cmd.go`），风险很低。

**想提 Issue / PR：** 本 fork 的所有增强相关讨论和代码都放在 `sidecar/` 目录下，欢迎提 Issue 讨论。
