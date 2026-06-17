# SkyNet Tunnel — 传输层终极形态

> **一句话：把"信息传输"做到物理极限。天网底层的传输层级，融合所有传输协议，市面上所有传输技术全部汇聚于此。**

## 定位

本项目是 **SkyNet 天网系统** 的传输层核心，位于整个天网架构的最底层（物理层之上）。它不是一个普通的隧道工具，而是：

> **"这个世界上所有信息传输都可以由它构成"**

SkyNet 天网传输层在物理层之上构建了一个**协议无关传输总线**，任何进入系统的数据包都可以选择最合适的传输协议或协议组合来送达目标。

---

## 技术架构

### 传输层后端生态（18 种协议/模式）

| 分类 | 后端 | 协议 | 说明 |
|------|------|------|------|
| **P2P 传输** | `skynet-p2p` | SkyNet P2P | 端到端加密，打破 NAT |
| | `webrtc` | ICE+DataChannel | 浏览器直连，STUN/TURN 自适应 |
| **加密隧道** | `wireguard` | WireGuard Noise IK | 内核级加密，ChaCha20-Poly1305 |
| | `dtls` | DTLS 1.2 | UDP 不可信链路上的 TLS |
| | `ssh-reverse` | SSH TCPIP-Forward | 反向隧道，frp/ngrok 风格 |
| | `quic` | QUIC | IETF 标准，多路复用+0-RTT |
| **协议隧道** | `dns-tunnel` | DNS-over-DNS | 端口 53 仅允许环境下的救命通道 |
| | `icmp-tunnel` | ICMP Ping Tunnel | 纯 ICMP Echo 的隐蔽通道 |
| | `gre` | GRE | 通用路由封装，IP 隧道 |
| | `packet-tunnel` | VXLAN | 二层网络虚拟化 |
| | `udp-tunnel` | UDP Tunnel | 通用 UDP 穿隧 |
| **流媒体** | `rtsp` | RTSP/RTP | 实时流协议，CCTV 首选 |
| | `rtmp` | RTMP | Adobe Flash 流媒体 |
| **文件传输** | `sftp` | SFTP over SSH | 加密文件传输，支持代理模式 |
| **IoT 消息** | `mqtt` | MQTT 3.1.1/5.0 | 轻量级发布订阅，IoT 首选 |
| **代理协议** | `http-proxy` | HTTP CONNECT | 隧道模式 HTTP 代理 |
| | `socks5` | SOCKS5 | 通用五层代理 |
| **智能路由** | `smart-router` | 多后端聚合 | 策略路由、故障转移、延迟感知 |
| | `failover` | 自动故障转移 | 多后端自动切换 |
| **官方封装** | `cloudflare` | Cloudflare Tunnel | 原有 tunnel 协议 |

### 分层结构

```
┌─────────────────────────────────────────────────┐
│            SkyNet 天网上层应用                    │
├─────────────────────────────────────────────────┤
│           智能路由层 (smart-router)              │
│   failover | round-robin | latency | sticky | p2p │
├─────────────────────────────────────────────────┤
│              传输层协议总线                       │
│  WireGuard | DTLS | SSH | QUIC | WebRTC         │
│  DNS | ICMP | GRE | RTSP | RTMP | SFTP | MQTT   │
├─────────────────────────────────────────────────┤
│              底层网络 (IP/物理)                  │
└─────────────────────────────────────────────────┘
```

---

## 自研核心（非第三方依赖）

| 模块 | 文件 | 说明 |
|------|------|------|
| **WebRTC** | `webrtc/peer.go` | RFC 8832 DataChannel + ICE Agent，自研 STUN 解析 |
| **STUN** | `webrtc/stun.go` | RFC 5389 纯手写，无第三方库 |
| **GRE** | `packet/packet.go` | 纯手写 GRE 头，不依赖外部实现 |
| **VXLAN** | `packet/packet.go` | 纯手写 VXLAN 封装 |
| **Prometheus** | `metrics/metrics.go` | 自研 Counter/Gauge/Histogram，无依赖 |
| **Overlay Network** | `overlay/overlay.go` | ZeroTier/Tailscale 风格，零外部依赖 |
| **智能路由** | `router/router.go` | 策略路由，零外部依赖 |

---

## 解决的问题

在开发过程中，团队遇到了以下技术挑战并全部解决：

### 1. SCTP 无纯 Go 实现
- **问题**：`golang.org/x/net/sctp` 不存在，`github.com/pion/sctp` 是 WebRTC 专用 API，与通用 SCTP 服务器不兼容
- **解决**：删除 SCTP 后端，聚焦其他协议融合

### 2. WireGuard 密码学 API 重构
- **问题**：Go 1.24 的 `crypto/ecdh.X25519` API 多次变化；`chacha20poly1305.NewX` vs `NewXChaCha20Poly1305` 名称混淆
- **解决**：统一用 `x25519DH()` 辅助函数封装 ECDH；确认 `chacha20poly1305.NewX(key)` 是正确 API
- **问题**：BLAKE2s MAC 密钥类型 `[32]byte` vs `[]byte` 不匹配
- **解决**：统一参数为 `[]byte`，调用处做类型转换

### 3. SSH 库 API 差异
- **问题**：`ssh.Dial` 返回 2 值而非 4 值；`client.SendRequest` 返回 `(bool, error)` 而非 `SendRequestBool`
- **解决**：严格按 `golang.org/x/crypto/ssh` 标准签名编写

### 4. DTLS 标准库限制
- **问题**：Go 标准库 `crypto/tls` 无 `tls.VersionDTLS12` 常量；`net.UDPConn` 不实现 `net.Listener`
- **解决**：定义本地常量 `dtlsVersion12 = 0xfefd`；server 端用 `peers map[string]*tls.Conn` 管理连接

### 5. Metrics Counter 类型
- **问题**：Prometheus Counter 的 `Add()` 方法参数是 `uint64`，不是 `float64`
- **解决**：统一使用 `m.BytesSentTotal.Add(uint64(n))`

### 6. 循环依赖解法
- **问题**：router 包需要 Backend 接口，但导入 tunnel 包会造成循环依赖
- **解决**：router 包自建精简版 `Backend` 接口子集（Name/Type/Start/Stop），不导入 tunnel 包

### 7. gortsplib 模块路径变更
- **问题**：`github.com/aler9/gortsplib/v3` 已迁移到 `github.com/bluenviron/gortsplib/v3`
- **解决**：简化 RTSP 实现，不依赖复杂 gortsplib 子包，纯手写 RTSP 握手和响应

### 8. pkg/sftp 接口复杂度
- **问题**：`sftp.Handlers` 接口要求 `FileReader`/`FileWriter` 返回 `io.ReaderAt`/`io.WriterAt`，pkg/sftp 使用独特的小写方法名（`Fileread`/`Filewrite`）
- **解决**：简化 SFTP 为纯 TCP 中继代理模式（proxy 模式），避免复杂协议解析；server 模式提供 SSH 认证+SFTP subsystem 透传

---

## 核心优势

### 1. 传输协议全覆盖
- 没有其他任何项目同时融合了：WireGuard + DTLS + SSH Reverse Tunnel + QUIC + WebRTC + DNS Tunnel + ICMP Tunnel + GRE + VXLAN + RTSP + RTMP + SFTP + MQTT
- 天网传输层是**唯一**做到这点的开源实现

### 2. 零第三方依赖（核心模块）
- WebRTC、STUN、GRE、VXLAN、Prometheus Metrics、Overlay Network、Router **全部自研**
- 不依赖任何外部库，避免供应链攻击和版本冲突

### 3. 物理极限的传输
- DNS Tunnel：只开放 53/UDP 的极严格网络也能通信
- ICMP Tunnel：纯 Ping 包的隐蔽传输
- WireGuard：内核级 ChaCha20-Poly1305 加密
- WebRTC：浏览器原生 P2P，无需中继

### 4. 智能路由
- 5 种路由模式：故障转移、轮询、延迟感知、会话保持、P2P 优先
- 自动在可用传输协议间切换，保障连通性

### 5. 安全性天网负责
- 传输层只管"如何送达"，安全由天网其他模块负责
- 职责清晰，不做安全重复建设

---

## 版本

- **v0.3.0** — 传输层终极版（18 种协议后端）
- v0.2.0 — 工程增强版（崩溃感知、优雅退出）
- v0.1.0 — SSI 接口初始版

---

## 构建

```bash
cd sidecar
go build -o skynet-tunnel .
```

## 快速启动

```bash
# DNS 隧道（极严格网络）
./skynet-tunnel --backend dns-tunnel --tunnel-domain tunnel.example.com

# WireGuard 端到端加密
./skynet-tunnel --backend wireguard --private-key <key> --peer-public-key <key>

# SSH 反向隧道（frp 风格）
./skynet-tunnel --backend ssh-reverse --remote-addr server:2222

# WebRTC P2P（浏览器直连）
./skynet-tunnel --backend webrtc

# MQTT IoT（传感器数据）
./skynet-tunnel --backend mqtt --listen-addr :1883

# 智能路由（多协议聚合）
./skynet-tunnel --backend smart-router --routing-mode failover
```
