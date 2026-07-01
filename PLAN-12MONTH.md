# cloudflared (SkyNet SSI Enhanced Fork) — 12 个月更新计划

> **项目定位**：独立的全平台内网穿透平台，通过 SkyNet SSI sidecar 层将 cloudflared（初始 backend）改造为可托管的系统组件，并扩展为 18 协议通用传输层。自 fork 增强版发布那一刻起完全独立，不依赖上游同步。
>
> **当前状态**：sidecar MVP 完成（v0.4.0，~17k SLOC，270 测试用例），0 外部用户/贡献者，skynet-p2p stub 未实现。
>
> **周期**：2026-07 ~ 2027-06

---

## M1（7月）— P2P + 发布流程

- [🔴 P0] **完整实现 `skynet-p2p` 后端** — 当前是 stub。基于 WebRTC ICE + STUN/TURN 做 NAT 穿透 + DHT/信令服务器做 peer discovery + UDP hole-punching
- [🔴 P0] **创建 git tag + 发布流程** — 补打 `skynet/v0.1.0` ~ `skynet/v0.4.0` 的 tag；创建 CHANGELOG.md；之后每次发布打 tag + 写 Release Notes
- [🟠 P1] **修复 `RecentLogs()` 返回 nil** — `cloudflare.go:251` 当前什么都不返回，IPC get_logs 没输出
- [🟡 P2] **实现 cloudflared 二进制自动下载** — sidecar init 时自动检测本地缺二进制，从 GitHub Releases 下载并校验 SHA256
- [🟡 P2] **proxy_pool 加缓存 + 限流** — 当前每次请求都直连 20+ 源，加 5 分钟内存缓存 + 速率限制

## M2（8月）— 测试 + 安全基线

- [🔴 P0] **集成测试框架** — 当前只有单元测试。用 Docker Compose 搭 mock Cloudflare edge + sidecar，端到端验证隧道连通性
- [🟠 P1] **权限审计** — 检查 manifest.json 声明的权限是否精确，剔除多余的
- [🟠 P1] **SSH HostKey 指纹验证 fail-closed** — 当前没配指纹也能连，改成没配置就拒绝连接
- [🟠 P1] **DNS/ICMP 隧道加密评估** — DNS 用 base32 明文、ICMP 用固定 XOR key，评估是否升级到 AEAD
- [🟡 P2] **TODO 整理** — 把代码里的 TODO 全清一遍，能修的就地修，不能修的提 Issue

## M3（9月）— Dashboard + 开发者体验

- [🔴 P0] **Web Dashboard 功能补齐** — 当前只展示基本状态。加：实时日志流（SSE）、一键切换 backend、流量图表、配置编辑
- [🟠 P1] **开发者文档站** — 基于 GitHub Pages 或 VitePress 搭文档站：SSI 协议、backend 开发指南、发布流程
- [🟠 P1] **manifest.json 更新** — 版本升到 v0.5.0，补充新 backend 和 enhancement 列表
- [🟡 P2] **sidecar Makefile 优化** — 加 `make release`（自动 tag + build + Release）、`make integ-test`
- [🟡 P2] **golangci-lint 全绿** — 确认 CI 上 lint 全通过，设为阻断项

## M4（10月）— 性能 + 可靠性

- [🔴 P0] **多 backend 基准测试** — 写 bench 套件，对比 18 个 backend 的延迟、吞吐量、内存、CPU，发一份 benchmark 报告
- [🔴 P0] **failover 自动回切** — 当前 primary backend 恢复后不会自动切回去，加可配置的回切延迟
- [🟠 P1] **内存优化** — 跑 7 天 pprof 快照，优化 ring buffer、overlay、smart-router 的内存路径
- [🟠 P1] **proxy_pool 存活模型** — 加代理存活概率打分、低质量源自动剔除、用户自定义源 API
- [🟠 P1] **Windows 服务安装器** — 已有 Linux systemd + macOS launchd，加 Windows 服务自注册（sc.exe / WinSW）
- [🟡 P2] **goroutine leak 检测** — CI 集成 goleak，测试结束时检测未关闭的 goroutine

## M5（11月）— 安全深度审计

- [🔴 P0] **AI 驱动全模块安全审计** — 用 AI 对 sidecar 每个模块做 STRIDE 分类扫描：IPC 接口输入校验、配置文件注入、backend 数据传输加密、状态机边界条件。输出漏洞清单 + 修复方案（零成本，不需要外部安全团队）
- [🔴 P0] **STRIDE 威胁建模** — 对 sidecar 全模块做 STRIDE 分析，出威胁矩阵 + 缓解措施表
- [🟠 P1] **govulncheck CI** — 对 vendor 目录做定期 CVE 扫描，发现漏洞自动通知
- [🟠 P1] **JSON-RPC 输入校验** — 加参数 schema 校验（字符串长度上限、嵌套深度限制），不依赖 panic recover
- [🟠 P1] **Web Dashboard 加登录** — 当前 dashboard 无认证，加 token / OAuth / localhost-only 登录
- [🟡 P2] **包签名 + SBOM** — 发布 `.swbn` 包时加 GPG/cosign 签名 + 生成 SBOM

## M6（12月）— 可观测性

- [🔴 P0] **Prometheus 指标增强** — 加 backend 级流量统计、延迟分位值（p50/p95/p99）、隧道 uptime、重启次数
- [🟠 P1] **结构化日志** — 统一用 zerolog 输出 JSON 格式，加 request_id 追踪
- [🟠 P1] **OpenTelemetry 集成** — 继承上游 OTel SDK，加 sidecar 自定义 spans（backend 调用链路、状态机变迁）
- [🟡 P2] **告警模板 + Grafana 面板** — 提供 Prometheus 告警规则（子进程 crash、高延迟）和 Grafana dashboard 样板
- [🟡 P2] **跨进程链路追踪** — 通过 SkyNet IPC 传递 trace context，sidecar ↔ Runtime 跨进程追踪

## M7（1月）— SkyNet Runtime 深度集成

- [🔴 P0] **IPC 升级到双向 streaming** — 当前是 request-response 模式，升级到同一通道并发 request + server push
- [🔴 P0] **Android 完整适配** — ARM64 交叉编译、Google Play 合规性检查、Android 文件系统权限验证
- [🟠 P1] **一键安装脚本** — `curl | bash`（**注意**：必须先实现签名校验 + HTTPS-only + 安装前 hash 校验）
- [🟠 P1] **多隧道编排 demo** — docker-compose 示例：同时暴露 HTTP + SSH + VNC 三个隧道
- [🟡 P2] **Docker 镜像自动化** — 构建并推送到 ghcr.io，配 docker-compose 一键部署

## M8（2月）— 移动端 & 桌面

- [🔴 P0] **SkyNet Android APK** — sidecar + SkyNet Runtime 打包成 APK，前台 service + 通知栏状态 + 隧道开关
- [🟠 P1] **一键隧道创建** — Android 端扫码/粘贴 Token 就创建隧道，不用手动改配置文件
- [🟡 P2] **iOS 适配调研** — 出可行性报告，分析 iOS 网络扩展限制
- [🟡 P2] **Tauri 桌面 GUI** — 轻量桌面应用：隧道管理、状态面板、日志、backend 切换
- [🟡 P2] **Homebrew Cask / Scoop** — 方便 macOS 和 Windows 用户安装

## M9（3月）— 插件 & 扩展

- [🔴 P0] **Backend 插件 API** — 设计 Go plugin 或 wasm 插件接口，第三方不用改 sidecar 本体就能加 backend
- [🟠 P1] **智能路由器升级** — 加基于实时延迟的自动模式切换、历史策略学习
- [🟠 P1] **Overlay Network 优化** — NAT 类型检测、自动选路、IP 池冲突检测
- [🟠 P1] **WebRTC 生产化** — TURN 中继、ICE restart 重连、SDP 互通性测试
- [🟡 P2] **评估非 Cloudflare Tunnel 支持** — 自建边缘节点、frp 兼容后端，扩展"通用传输层"定位

## M10（4月）— 文档 & 社区基建

- [🔴 P0] **完整用户手册** — 覆盖 18 个 backend 的中英文手册：安装、配置、常见问题、排错
- [🟠 P1] **API 参考文档** — 自动生成 IPC 接口 OpenAPI 规范和 Go 包文档
- [🟠 P1] **社区贡献指南** — CONTRIBUTING.md + PR/Issue 模板 + Code review checklist + 行为准则
- [🟠 P1] **实战教程** — 5~10 个真实场景教程：NAS 穿透、游戏服务器、远程开发、物联网、企业内部网
- [🟡 P2] **GitHub Discussions** — 开启问答 / Show and Tell / 想法 分区

## M11（5月）— 企业功能

- [🔴 P0] **ACL/多租户** — 基于 token 的读写权限、隧道级隔离、操作审计日志
- [🟠 P1] **配置加密** — Token / 私钥 / 密码用 AES-256-GCM 加密存储，配置文件可安全提交到 VCS
- [🟠 P1] **批量部署** — Ansible playbook + Terraform provider 示例，管理 100+ 实例
- [🟡 P2] **LDAP/OIDC 集成** — Web Dashboard 支持企业 IdP
- [🟡 P2] **日志归档** — 支持输出到 Elasticsearch / Loki / S3

## M12（6月）— 多云 & 未来

- [🔴 P0] **多云 Tunnel 管理器** — 一个 sidecar 同时管 Cloudflare + AWS Systems Manager + 自建 frp + ngrok 等
- [🟠 P1] **Mesh 网络模式** — 多 sidecar 自动组 mesh，跨区域/跨云内网互通
- [🟠 P1] **Wasm backend** — 支持 wasm 编译的自定义 backend（Rust/C/C++ → wasm → sidecar 加载）
- [🟠 P1] **年度回顾 & 路线图** — 总结用户反馈、性能数据、安全审计结果，出 2027-2028 路线图
- [🟡 P2] **商业化评估** — 调研开源核心 + 企业增值付费的可行性

---

## 当前已知缺口（需优先处理）

| 问题 | 优先级 | 影响 | 未修复代价 |
|------|--------|------|-----------|
| skynet-p2p 未实现（stub） | 🔴 P0 | 18 协议的旗舰功能不可用 | 品牌承诺与实际脱节 |
| RecentLogs 返回 nil | 🟠 P1 | IPC get_logs 没输出 | 上层无法排查故障 |
| 无 git tag | 🟠 P1 | 无法精确回溯版本 | 版本管理混乱 |
| proxy_pool 无缓存/限流 | 🟠 P1 | 多实例同时启动被源站限流 | 生产环境不可靠 |
| manifest 版本滞留在 v0.2.0 | 🟡 P2 | 与实际代码不符 | 用户/工具看到错误版本号 |

---

> **注意**：M7~M12 的内容（尤其是企业功能和商业化评估）取决于 M1~M6 后的社区反馈和实际用量。如果 fork 6 个月内没有获得实质性的外部用户，M10-M12 应更多聚焦技术深化而非社区扩展。**建议 M6 结束时做一次 full review 调整后半段计划。**
