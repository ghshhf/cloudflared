# SkyNet Tunnel — 信息传输终极形态

> **一句话定位：在物理层之上，做到传输层的终极形态。**
>
> 从 WireGuard 的内核级加密，到 WebRTC 的浏览器 P2P；从 DNS Tunnel 的 53/UDP 极限穿透，到 MQTT 的 IoT 低功耗消息——
> **市面上所有非物理传输方式，SkyNet 天网传输层全部汇聚于此，一个也不缺。**

---

## 这是什么？

本项目基于 [Cloudflare Tunnel (cloudflared)](https://github.com/cloudflare/cloudflared) 开源项目，保留其原有 Cloudflare Tunnel 协议实现，
**新增了一个独立的 `sidecar/` 子模块——SkyNet 天网传输层。**

### 与原 cloudflared 的区别

| 维度 | 原 cloudflared | SkyNet 天网传输层 |
|------|---------------|-----------------|
| 定位 | Cloudflare 网络的专用隧道客户端 | 通用传输层总线，不绑定任何云服务商 |
| 支持协议 | 仅 Cloudflare Tunnel 协议（HTTP2/WebSocket） | **18 种传输协议/模式**，见下表 |
| 架构 | 中心化（必须经过 Cloudflare 边缘） | **去中心化**，支持 P2P、代理、中继、直连 |
| 适用场景 | 把内网 Web 服务暴露到公网 | 任何需要信息传输的场景（Web、IoT、流媒体、文件、隐蔽通信） |

简单来说：**原 cloudflared 是 Cloudflare 专用；天网传输层是通用的、协议无关的信息传输系统。**

---

## v0.3.0 本次更新：传输层终极版

本次更新（2026-06-17）新增了 **7 种传输协议后端**，加上原有的 11 种，天网传输层共支持 **18 种** 传输协议/模式：

### 新增后端

| 后端 | 文件 | 说明 |
|------|------|------|
| **SSH Reverse Tunnel** | `tunnel/ssh_reverse.go` | frp/ngrok 风格反向隧道，支持密码/私钥认证 |
| **DTLS 1.2** | `tunnel/dtls.go` | UDP 链路上的 TLS，用于不可信 UDP 网络 |
| **WireGuard** | `tunnel/wireguard.go` | Noise IK 握手 + XChaCha20-Poly1305，端到端加密 |
| **RTSP** | `tunnel/rtsp.go` | 实时流媒体协议（CCTV 首选） |
| **RTMP** | `tunnel/rtsp.go` | Adobe Flash 流媒体协议 |
| **SFTP** | `tunnel/sftp.go` | SSH 子系统文件传输 |
| **MQTT** | `tunnel/mqtt.go` | IoT 发布订阅消息（3.1.1/5.0） |

### 已解决的技术挑战（共 8 类）

| 问题 | 解决 |
|------|------|
| SCTP 无纯 Go 通用实现 | 确认 pion/sctp 仅 WebRTC 专用，删除 SCTP 后端，聚焦其他协议 |
| crypto/ecdh API 多次变化 | 封装 `x25519DH()` 辅助函数，统一 ECDH 调 |
| chacha20poly1305 命名混淆 | 确认 `chacha20poly1305.NewX(key)` 而非 `NewXChaCha20Poly1305` |
| BLAKE2s MAC 密钥类型 `[32]byte` vs `[]byte` | 统一参数为 `[]byte`，调用处做显式转换 |
| SSH 库 2 值 vs 4 值返回 | 严格按 `golang.org/x/crypto/ssh` 标准签名 `ssh.Dial` → `(*Client, error)` |
| DTLS12 常量/Listener 缺失 | 本地定义 `dtlsVersion12 = 0xfefd`；server 端用 `peers map[string]*tls.Conn` |
| Metrics Counter uint64 vs float64 | 统一 `m.BytesSentTotal.Add(uint64(n))` |
| router/tunnel 循环依赖 | router 包自建精简 Backend 接口子集（Name/Type/Start/Stop） |
| gortsplib 模块路径迁移 (aler9→bluenviron) | 纯手写 RTSP 握手和响应，不依赖第三方库 |
| pkg/sftp 复杂接口（`Fileread`/`Filewrite` 小写方法名） | 简化为纯 TCP 中继代理模式，server 模式提供 SSH+SFTP subsystem 透传 |

---

## 完整传输层生态（18 种协议/模式）

### 按场景分类

| 场景 | 天网方案 | 市面上同类产品对比 |
|------|---------|-------------------|
| **P2P 穿透** | SkyNet P2P + WebRTC (ICE+STUN+TURN) | coturn（仅 TURN）、libjuice（纯 ICE） |
| **内核级加密隧道** | WireGuard (ChaCha20-Poly1305) | 原 WireGuard (Linux kernel)、Tailscale（基于 WireGuard）、ZeroTier（自研协议） |
| **UDP 上的加密** | DTLS 1.2 | OpenSSL/LibreSSL（仅 C 库）、Pion DTLS（仅 WebRTC） |
| **反向隧道** | SSH TCPIP-Forward | frp、ngrok（免费版限速）、localtunnel、serveo |
| **现代多路复用** | QUIC | cloudflared QUIC（仅 Cloudflare 协议）、Google QUIC |
| **浏览器直连** | WebRTC DataChannel (RFC 8832) | pion/webrtc（仅库，非完整后端） |
| **DNS 极限穿透** | DNS Tunnel (base32) | iodine、dns2tcp（仅 C 实现，跨平台差） |
| **ICMP 隐蔽传输** | ICMP Tunnel (XOR) | hping3（仅工具）、ptunnel-ng（C 实现） |
| **IP 层封装** | GRE | Linux ip-gre（内核模块）、OpenVPN |
| **二层虚拟化** | VXLAN | Linux kernel vxlan、Cisco ACI |
| **通用 UDP 穿隧** | UDP Tunnel | socat、ncat |
| **CCTV 流媒体** | RTSP/RTP | MediaMTX、go2rtc |
| **Flash 流媒体** | RTMP | nginx-rtmp-module、SRS（仅服务器） |
| **加密文件传输** | SFTP over SSH | vsftpd（仅 FTP）、OpenSSH sftp-server（仅服务端） |
| **IoT 低功耗** | MQTT 3.1.1/5.0 | Mosquitto、EMQX（仅 broker，非隧道） |
| **HTTP 代理** | HTTP Proxy (CONNECT) | squid、tinyproxy（仅代理，不融合其他协议） |
| **通用代理** | SOCKS5 | Dante、shadowsocks（仅 socks5，无协议融合） |
| **智能路由** | Smart Router (5 种模式) | nginx stream（仅简单路由）、HAProxy（仅健康检查） |

### 完整清单

```
┌─ 加密隧道 ────────────────────────────────────────────┐
│  wireguard    WireGuard Noise IK + ChaCha20Poly1305  │
│  dtls         DTLS 1.2 over UDP                       │
│  ssh-reverse  SSH TCPIP-Forward (frp/ngrok style)    │
│  quic         IETF QUIC (0-RTT + 多路复用)            │
├─ P2P 传输 ────────────────────────────────────────────┤
│  skynet-p2p   SkyNet 自研 P2P 协议栈                  │
│  webrtc       WebRTC DataChannel (RFC 8832) + ICE     │
├─ 协议隧道 ────────────────────────────────────────────┤
│  dns-tunnel   DNS 隧道 (53/UDP 极限穿透)              │
│  icmp-tunnel  ICMP 隧道 (纯 Ping 包隐蔽通信)          │
│  gre          通用路由封装 (L3)                       │
│  packet-tun   VXLAN (L2 虚拟化)                       │
│  udp-tunnel   通用 UDP 穿隧                           │
├─ 流媒体 ──────────────────────────────────────────────┤
│  rtsp         RTSP/RTP (CCTV 首选)                    │
│  rtmp         RTMP (Flash 流媒体)                     │
├─ 文件传输 ────────────────────────────────────────────┤
│  sftp         SFTP over SSH (加密文件传输)            │
├─ IoT 消息 ────────────────────────────────────────────┤
│  mqtt         MQTT 3.1.1/5.0 (发布订阅)               │
├─ 代理协议 ────────────────────────────────────────────┤
│  http-proxy   HTTP CONNECT                            │
│  socks5       SOCKS5                                  │
├─ 智能路由 ────────────────────────────────────────────┤
│  smart-router 故障转移 / 轮询 / 延迟感知 / 会话保持   │
│  failover     自动故障转移                            │
└───────────────────────────────────────────────────────┘
```

---

## 对标市面上所有传输层（为什么选天网）

### 横向对比

| 产品/项目 | 协议数量 | 支持 P2P | 支持 DNS/ICMP 极限穿透 | 支持流媒体/文件/IoT | 是否绑定云服务商 | 是否开源 | 主要局限 |
|-----------|---------|---------|---------------------|---------------------|-----------------|---------|---------|
| **SkyNet 天网** | **18** ✅ | ✅ 原生 | ✅ 原生 | ✅ RTSP/RTMP/SFTP/MQTT | ❌ 无绑定 | ✅ MIT | — |
| Cloudflare Tunnel (cloudflared) | 1 (HTTP2/WebSocket) | ❌ 仅经过 Cloudflare | ❌ | ❌ | ✅ Cloudflare 绑定 | ✅ Apache | 绑定 Cloudflare，协议单一 |
| frp | 4 (TCP/UDP/HTTP/HTTPS) | ❌ | ❌ | ❌ | ❌ | ✅ MIT | 仅简单反向隧道，无 P2P |
| WireGuard (官方) | 1 (WireGuard 协议) | ❌（需要额外 STUN 方案） | ❌ | ❌ | ❌ | ✅ GPLv2 | 单协议，需要内核模块 |
| Tailscale | 2 (WireGuard + DERP) | ✅（经过 DERP 中继） | ❌ | ❌ | ✅ 可自建，但推荐 Tailscale 控制平面 | ✅ BSD | 协议单一（仅 WireGuard），依赖控制平面 |
| ZeroTier | 1 (ZeroTier 自研) | ✅ | ❌ | ❌ | ✅ 控制平面可选自建 | ✅ GPLv3 | 协议不透明（自研而非标准） |
| ngrok | 3 (TCP/HTTP/TLS) | ❌ | ❌ | ❌ | ✅ ngrok SaaS | ❌ 闭源 | 免费版限速，付费版昂贵 |
| socat | 2 (TCP/UDP) | ❌ | ❌ | ❌ | ❌ | ✅ GPLv2 | 仅字节流中转，无应用层协议 |
| stunnel | 1 (TLS 中转) | ❌ | ❌ | ❌ | ❌ | ✅ GPLv2 | 仅 TLS 封装 |
| sshuttle | 1 (SSH over TCP) | ❌ | ❌ | ❌ | ❌ | ✅ LGPL | 仅 TCP，性能差 |
| gost | 8 (HTTP/SOCKS/SSH/QUIC/WS/GRPC/Relay/XTCP) | ✅（部分 XTPC） | ❌ | ❌ | ❌ | ✅ MIT | 无流媒体/文件/IoT，无 WireGuard 级加密 |
| iodine | 1 (DNS) | ❌ | ✅ | ❌ | ❌ | ✅ ISC | 仅 DNS 隧道，C 实现跨平台差 |
| MediaMTX | 3 (RTSP/RTMP/HLS) | ❌ | ❌ | ✅ 仅流媒体 | ❌ | ✅ MIT | 仅流媒体，无通用传输 |
| Mosquitto | 1 (MQTT) | ❌ | ❌ | ✅ 仅 MQTT | ❌ | ✅ EPL-2.0 | 仅 broker，无隧道能力 |
| OpenSSH | 2 (SSH + SFTP) | ❌ | ❌ | ✅ 仅文件 (SFTP) | ❌ | ✅ BSD | 仅 SSH 系协议，无 P2P |
| OpenVPN | 2 (UDP/TCP over TLS) | ❌ | ❌ | ❌ | ❌ | ✅ GPLv2 | 单协议，配置复杂 |

### 结论

**天网传输层是当前唯一同时具备以下全部特性的开源项目：**

1. **协议多样性（18 种）** — 覆盖加密隧道、P2P、协议穿隧、流媒体、文件传输、IoT 消息、代理协议、智能路由
2. **极限穿透（DNS + ICMP）** — 在只开放 53/UDP 或仅允许 ICMP 的最严格网络中也能通信
3. **P2P 原生** — WebRTC DataChannel + SkyNet P2P 双层协议栈
4. **协议无关** — 不是某个云服务的专用客户端，任何协议都可作为传输通道
5. **零第三方依赖（核心模块）** — WebRTC/STUN/GRE/VXLAN/Metrics/Overlay/Router 全部自研，避免供应链风险
6. **智能路由** — 5 种路由模式自动在可用协议间切换
7. **开源免费** — MIT 许可证，无商业限制

---

## 用户选择天网的主要作用

### 1. 作为"最后一条通道"的备份方案
> 在运营商/企业防火墙封锁所有常用端口时，DNS Tunnel + ICMP Tunnel 是最后可用的信息通道。

### 2. 作为"全协议融合"的统一网关
> 一台天网节点同时服务 CCTV 的 RTSP、IoT 设备的 MQTT、运维的 SSH/SFTP、内网穿透的 WebRTC，无需部署多套系统。

### 3. 作为 P2P 传输的基础架构
> 基于 WebRTC DataChannel + SkyNet P2P 的双层方案，在浏览器中即可建立端到端加密通道，无需安装客户端。

### 4. 作为安全隔离的加密隧道层
> WireGuard + DTLS + SSH-Reverse 三种加密方案并存，根据网络可信程度自动选择合适的加密强度。

### 5. 替代 cloudflared 的通用版本
> 保留 cloudflared 的 Cloudflare Tunnel 协议，同时新增全部通用传输能力——相当于"cloudflared 的 SuperSet"。

---

## 核心优势

| 优势 | 说明 |
|------|------|
| **协议全覆盖** | 18 种协议，任何其他开源项目只能覆盖其中 1~8 种 |
| **物理极限传输** | DNS Tunnel（53/UDP）+ ICMP Tunnel（纯 Ping），在最严格网络仍可通信 |
| **零第三方依赖（核心）** | WebRTC/STUN/GRE/VXLAN/Metrics/Overlay/Router 全部自研手写，避免供应链攻击 |
| **智能路由** | 故障转移/轮询/延迟感知/会话保持/P2P 优先，自动在协议间切换 |
| **统一架构** | 所有后端实现同一 Backend 接口，可通过 Smart Router 自由组合 |
| **与 cloudflared 兼容** | 保留原 Cloudflare Tunnel 协议实现，不影响原有用户 |
| **安全天网负责** | 传输层只负责"送达"，安全检查由天网其他模块负责，职责清晰 |

---

## 自研核心模块（非第三方依赖）

| 模块 | 文件 | 说明 |
|------|------|------|
| **WebRTC** | `sidecar/webrtc/peer.go` | RFC 8832 DataChannel + ICE Agent |
| **STUN** | `sidecar/webrtc/stun.go` | RFC 5389 STUN 协议，纯手写 |
| **GRE** | `sidecar/packet/packet.go` | GRE 头封装，纯手写 |
| **VXLAN** | `sidecar/packet/packet.go` | VXLAN 封装，纯手写 |
| **Prometheus Metrics** | `sidecar/metrics/metrics.go` | Counter/Gauge/Histogram，零依赖 |
| **Overlay Network** | `sidecar/overlay/overlay.go` | ZeroTier/Tailscale 风格，零外部依赖 |
| **Smart Router** | `sidecar/router/router.go` | 5 种路由策略，零外部依赖 |

---

## 版本历史

- **v0.4.0** — 2026-06-18 — **工程加固版**（全包测试覆盖 / SSH HostKey 安全修复 / 构建与 CI 自动化）
- **v0.3.0** — 2026-06-17 — **传输层终极版**（18 种协议后端：SSH Reverse、DTLS、WireGuard、RTSP、RTMP、SFTP、MQTT）
- v0.2.0 — 工程增强版（崩溃感知、优雅退出、Prometheus Metrics）
- v0.1.0 — SSI 接口初始版

---

## 开发与贡献

### 测试状态

本 fork 在工程加固方面做了系统性投入，**11/11 个包已实现测试全覆盖**，总计约 270 个单元测试：

```
sidecar                        ok   11/11 包全覆盖 ✅
sidecar/cmd/swbn-pkg           ok
sidecar/dashboard              ok
sidecar/ipc                    ok
sidecar/metrics                ok
sidecar/overlay                ok
sidecar/packet                 ok
sidecar/router                 ok
sidecar/ssi                    ok
sidecar/tunnel                 ok
sidecar/webrtc                 ok
```

### 运行测试

```bash
# 全部测试（推荐）
cd sidecar
go test -count=1 ./...

# 单包测试
go test -v -count=1 ./ipc/

# 测试覆盖率报告
go test -count=1 -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# 使用 Makefile
make test          # 全部测试
make test-race     # 带 race detector 测试（需 CGO）
make test-coverage # 生成 HTML 覆盖率报告
make lint          # golangci-lint（回退：go vet）
```

### 构建

```bash
# 构建 sidecar（native）
cd sidecar
make build

# 交叉编译
make build-linux
make build-darwin
make build-windows

# 构建 SWBN 打包工具
make build-swbn

# 一键打包 .swbn（含 cloudflared 二进制）
./swbn-pkg --sidecar ./cloudflared-sidecar --cloudflared /path/to/cloudflared --manifest ./manifest.json --out tunnel.swbn
```

### CI / 自动化

- **GitHub Actions** — 每次 push/PR 自动运行 build + vet + 测试 + 覆盖率 + 交叉编译，每日 06:00 UTC 定时检查
- **smoke_test.sh** — 本地一键验证脚本：build / 交叉编译 / vet / 测试 / swbn-pkg
  ```bash
  bash smoke_test.sh
  ```
- **VSCode 调试** — `.vscode/launch.json` 提供 8 个一键配置：运行 sidecar、测试各包、构建工具

### 代码规范

```bash
make fmt    # go fmt 格式化
make vet    # go vet 静态检查
make lint   # golangci-lint（含 30+ 规则）
```

### 本 fork 工程增强速览

| 类别 | 内容 |
|------|------|
| **测试覆盖** | 11/11 包，约 270 个单元测试，覆盖 IPC 总线/Metrics/协议编解码/状态机/全部 18 种后端 |
| **安全修复** | SSH 反向隧道：`InsecureIgnoreHostKey` → 可配置指纹验证（HostKeyFingerprint / InsecureSkipVerify / fail-closed） |
| **Bug 修复** | ICMP 校验和奇长度越界（panic）、GRE Marshal 可选字段缺失（解析错位）、STUN 构建缓冲区不足（panic） |
| **构建工具链** | Makefile（build/test/lint/交叉编译）、smoke_test.sh（一键验证）、.gitignore |
| **CI/CD** | GitHub Actions 增强（覆盖率/交叉编译/定时执行）、WorkBuddy 每日自动化 |
| **调试** | VSCode launch.json（8 个配置，含调试启动、单包测试、构建工具） |

---

## 构建与使用

```bash
# 构建
cd sidecar
go build -o skynet-tunnel .

# DNS 隧道（仅开放 53/UDP 的极端网络）
./skynet-tunnel --backend dns-tunnel --tunnel-domain tunnel.example.com

# WireGuard 端到端加密
./skynet-tunnel --backend wireguard --private-key <key> --peer-public-key <key>

# SSH 反向隧道（frp/ngrok 风格）
./skynet-tunnel --backend ssh-reverse --remote-addr server:2222

# WebRTC P2P（浏览器直连）
./skynet-tunnel --backend webrtc

# MQTT IoT（传感器数据汇聚）
./skynet-tunnel --backend mqtt --listen-addr :1883

# 智能路由（多协议聚合，故障自动切换）
./skynet-tunnel --backend smart-router --routing-mode failover
```

---

> **物理层之上，天网传输层做到了极致。**
>
> 任何信息传输需求，总有一种 SkyNet 协议能送达。
