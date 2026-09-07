# Changelog

本项目使用 [Semantic Versioning](https://semver.org/) 记录公开版本。

## [0.1.12] - 2026-09-07

### Fixed

- 修复泛域名 DNS 检测使用字面量 `*.domain` 查询的问题，改用具体探针并自动修复旧版快照。
- 修复 Web Tunnel 只读取主域名状态的问题，按显式绑定域名分别判断 HTTP/HTTPS 公网就绪状态。
- 移除无效的固定 Headscale `/register` 链接，改由官方 Tailscale 客户端发起带上下文的授权流程。

## [0.1.11] - 2026-09-07

### Added

- 增加公网域名运行日志、筛选与导出，帮助定位 DNS、证书、HTTPS 和反向代理问题。
- 增加手动证书原子启用、删除与状态展示，并在删除后保持手动模式。

### Fixed

- 修复手动证书域名的 Caddy 证书加载和 SNI 选择策略。
- 增加域名服务运行事件数据库迁移，并仅保存脱敏诊断信息。

## [0.1.10] - 2026-09-07

### Fixed

- 为 Cloudflare 自动证书显式配置 Caddy `certificates.automate`，恢复已有根证书选择及根域名、泛域名的自动签发与续期。
- 自动证书与手动证书混用时同时保留 `automate` 和 `load_files`，避免不同域名的证书来源互相覆盖。

## [0.1.9] - 2026-09-07

### Fixed

- 修正 Caddy 2.11 原生 JSON 中 `trusted_proxies_strict` 的字段类型，恢复 HTTPS 配置加载、证书选择和公网 Host 路由。

## [0.1.8] - 2026-09-07

### Added

- 增加 Cloudflare DNS 托管预览、冲突确认、同值接管、双栈同步、漂移检测和受控删除。
- 根域名与泛域名证书分别展示申请阶段、SAN、签发/到期/预计续期、尝试次数和 Caddy 下次重试。
- 域名列表增加单项和批量 DNS 同步入口，并支持 Reduced Motion 与状态播报。

### Changed

- 正式运行固定使用 Production CA，ACME 环境选择不再出现在产品 UI 或写入 API。
- Cloudflare Token 与证书来源解耦，手动证书域名也可使用同一 Token 托管 DNS。

### Fixed

- 修复历史 Tunnel 列表查询字段错位导致旧穿透服务无法读取的问题。
- 修复 Caddy 把域名 ID 当作域名文本比较、导致精确服务路由被泛域名 404 兜底过滤的问题。
- 修复根证书与泛域名证书必须位于同一张证书才会被识别，以及详细 ACME 错误被摘要覆盖的问题。

## [0.1.7] - 2026-09-07

### Added

- 将公网入口升级为“一个主域名 + 多个附加域名”，每个域名独立绑定 Web Service。
- 域名列表支持全选、批量重新检测和批量申请证书；单域名可手动请求 Caddy 处理证书。
- 展示根证书和泛域名证书的 SAN、到期时间、Caddy 预计续期窗口、CA 限流与下次重试时间。
- 支持 Cloudflare DNS-01 独立 Token、手动证书校验，以及持久化 `/data/nexo/caddy-storage`。
- 增加主域名迁移、设备 ACK 恢复、服务冲突检查和带替代域名的删除流程。

### Changed

- 证书申请、续期和指数退避完全交由 Caddy Automatic HTTPS；Server 只协调配置并呈现状态。
- Headscale 反向代理保留 POST、长连接和 `tailscale-control-protocol` 升级，回环代理列入可信来源。

## [0.1.6] - 2026-09-07

### Added

- 增加未分配 Tunnel 保留、手动共享网络、多网段 SiteLink 及逐路由状态展示。
- 增加 Tunnel 批量分配、启停和删除，以及设备和 SiteLink 的编辑能力。

### Changed

- Headscale 节点支持同步重命名，站点互联支持按地址族维护下一跳。

## [0.1.5] - 2026-09-06

### Added

- 增加站点、设备、共享网络、站点互联和穿透服务的依赖感知删除流程，并通过迁移保留旧数据库的升级兼容性。
- 增加逐路由网关应用结果，分别校验 IPv4/IPv6 转发能力和 Headscale 路由收敛状态。

### Changed

- Headscale 对尚未发现的路由独立保持 Pending；可见路由仍可继续批准和撤销，避免单条路由阻塞整批收敛。
- 设备删除完成后同步删除 Headscale Node，避免旧组网身份残留在拓扑中。
- 正式镜像和 Compose 配置升级至 `0.1.5`，默认日志时区为 `Asia/Shanghai`。

### Fixed

- 修复资源删除完成前仍可重复修改或重新应用的问题，并确保删除操作按依赖顺序清理相关应用状态。

## [0.1.4] - 2026-09-06

### Added

- 增加 Web PWA 安装能力、离线应用壳和移动端图标资源。
- 重整网络互联页面，按站点集中管理共享网络、站点互联和静态路由确认。

### Changed

- 统一穿透服务、域名与 HTTPS 的用户界面和错误日志表述。
- 统一 API 时间字段为 Unix 秒，并为 Tunnel 数据连接启用 TCP keepalive。
- 正式镜像和 Compose 配置升级至 `0.1.4`，默认日志时区为 `Asia/Shanghai`。

### Fixed

- 为历史数据库中的时间字段补充一次性类型迁移，避免时间字段读取失败。

## [0.1.3] - 2026-09-06

### Added

- 完善网关控制台、站点互联管理和发布验收覆盖。

### Changed

- 统一正式部署配置与 `0.1.3` 镜像版本。

## [0.1.2] - 2026-09-06

### Added

- Web“添加设备”流程可直接指定设备名称、站点和 Server 地址，并生成完整 Agent Compose。

### Changed

- Server 正式 Compose 不再要求环境变量；Agent 正式 Compose 只保留 Server URL 和一次性入网 Token。
- Agent 自动从 Server URL 推导固定控制与 Tunnel 端口，设备能力由官方镜像和运行时探测提供。

### Fixed

- Server 不再把 loopback 或通配监听地址作为 Agent 的数据通道地址下发。

## [0.1.1] - 2026-09-06

### Fixed

- 修正 Server 与 Agent 运行时 Debian 基础镜像的固定摘要，确保 GitHub 发布构建可从官方镜像仓库复现。

## [0.1.0] - 2026-09-06

### Added

- Web 可视化设备入网、管理员 Session、CSRF 与本地恢复流程。
- Subnet Gateway 与双向 Site Gateway，保留真实 LAN 源 IP。
- TCP Tunnel，以及 HTTP/HTTPS Web Service 公网访问。
- 内置但独立运行的 Headscale、Caddy 和 Tailscale Linux 组件。
- Cloudflare DNS-01 根域名与泛域名证书，支持手动证书模式。
- Desired、Applied 与错误状态分离，并支持重启后的自动收敛。

### Security

- Agent 控制与 Tunnel 数据通道使用设备证书和 mTLS。
- 管理密码使用 Argon2id；LAN HTTP 与公网 HTTPS Session 相互隔离。
- API Key、DNS Token、私钥和自定义 CA 保存为受限 Secret 文件。

[0.1.7]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.7
[0.1.5]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.5
[0.1.6]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.6
[0.1.4]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.4
[0.1.3]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.3
[0.1.2]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.2
[0.1.1]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.1
[0.1.0]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.0
