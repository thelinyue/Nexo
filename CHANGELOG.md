# Changelog

本项目使用 [Semantic Versioning](https://semver.org/) 记录公开版本。

## [0.2.11]

- Server 设置页可手动保存公网 IPv4，DNS A 记录按有效配置自动更新；Agent 在多个公网 IPv6 地址中自动保持或选择可用地址。
- IPv6 直连复用已签发的域名泛域名证书，域名变更不再重复申请；修复 Emby 等带查询参数的资源请求被认证子请求错误拦截。
- Server 启动时等待 Caddy 管理接口就绪，避免记录短暂的配置加载失败；Server 与 Agent 日志使用本地时区。
- 服务列表的复制按钮紧跟公网地址，桌面和手机布局保持一致。
- 本次发布 Server（含 Web）与 Agent；部署和兼容性见 [v0.2.11 发布说明](docs/releases/v0.2.11.md)。

## [0.2.10]

- 修复 IPv6 直连证书 CSR 携带 rcgen 默认 CN 导致公网 CA 拒签；Agent 保留原私钥自动修复旧请求，Server 在提交订单前校验 CN。
- 修复反向代理状态刷新与 Caddy 事件写入的锁顺序冲突，避免启动后管理页面和健康检查无响应。
- 状态刷新仅回写相同配置版本的有效服务，避免等待期间的旧快照覆盖新配置。
- Server 与 Agent 控制通道错误补充对端、最后收发时间及消息数量，诊断不记录消息正文或凭据。
- Caddy 日志区分证书、TLS 握手、HTTP 请求与运行错误，避免将代理断连或 HTTP 429 误报为证书故障。
- 本次发布 Server 与 Agent，从 v0.2.9 更新无需数据库迁移。更新步骤见 [v0.2.10 发布说明](docs/releases/v0.2.10.md)。

## [0.2.9]

- HTTPS 服务支持自定义公网端口，访问地址、跳转、认证与 Caddy 路由按端口隔离，已有服务保持 443。
- 新增可选 IPv6 直连：Agent 本地证书与 Caddy 入口、独立 mTLS 管理连接和集中授权；IPv4 继续经 Server 转发。
- DNS 验证支持 Cloudflare、阿里云 DNS 和腾讯云 DNSPod，按记录所有权维护 A/AAAA/TXT，保留故障重试与撤销保护。
- 精简域名列表与详情，将转发 IPv4 配置移至 Server TOML；DNS 解析器留空时使用 Caddy 默认值。
- 本次发布 Server 与 Agent，启用直连需两端更新。兼容性、验证范围与部署步骤见 [v0.2.9 发布说明](docs/releases/v0.2.9.md)。

## [0.2.8]

- 内置 Caddy 支持 HTTPS 管理入口，复用域名证书，保留原 IP 入口及管理员、来源和 CSRF 校验。
- HTTPS 反向代理新增强制 HTTPS 开关；使用保留方法、路径及查询参数的 307 跳转，已有服务保持原行为。
- 完善服务表单、移动端添加入口和服务器设置反馈。
- 包含 v0.2.7 未完成发布的原生 Agent Compose / docker run 及环境变量修复；相对上一正式版发布 Server 与 Agent。更新与数据库变更说明见 [v0.2.8 发布说明](docs/releases/v0.2.8.md)。

## [0.2.7]（发布未完成，改动纳入 v0.2.8）

- 修复 Agent 部署入口回退为 Shell 安装脚本的问题：Compose 直接返回原生 YAML，docker run 返回单条启动命令，均预填连接参数。
- Agent 支持 `NEXO_SERVER_URL`、`NEXO_ENROLLMENT_TOKEN`、`NEXO_DEVICE_NAME`，非空值逐项覆盖 TOML，不回写配置文件；已有身份继续复用。
- 本次发布 Server 与 Agent，已有 v0.2.5 / v0.2.6 数据和身份可保留。详情见 [v0.2.7 发布说明](docs/releases/v0.2.7.md)。

## [0.2.6]

- Server 首次创建管理员支持非空环境变量逐项覆盖 TOML，并明确区分随机密码、指定密码及已有账号的日志。
- 页面生成的 Agent 部署命令自动保存受限权限配置并启动，拒绝覆盖已有文件。
- 桌面表单统一居中，完善取消、关闭、未保存确认与域名页面布局。
- 本次仅发布 Server（含 Web），Agent 保持 v0.2.5；部署包只包含 Server 模板并固定镜像版本。兼容性及操作步骤见 [v0.2.6 发布说明](docs/releases/v0.2.6.md)。

## [0.2.5]

- Server 与 Agent 使用 TOML 启动配置，管理地址、可信代理和公网 IP 在管理页面设置。
- 简化当前数据库初始化与共享密钥接入，Linux 临时 Socket 使用独立运行目录，完善配置、部署、复制和备份恢复流程。
- 登录与邀请注册采用紧凑表单，防止重复提交；用户列表统一单行展示，账号操作收纳到更多菜单，改进桌面宽度与移动端布局。
- 本次同时发布 Server 与 Agent，必须全新安装；不支持从旧版原地升级或迁移数据库、身份与环境配置。详情见 [v0.2.5 发布说明](docs/releases/v0.2.5.md)。

## [0.2.4]

- 增加 UDP 隧道、VPS 反向代理服务、Web 服务密码保护、流量统计与配额管理。
- 改进 Agent 入网、内网重定向、服务协议选择和工作区导航，并在首次启动时自动创建管理员账号。
- Server 与 Agent 均有代码变化，必须共同升级。升级前备份数据和配置；现有 v0.2.x 数据目录继续使用，启动时会自动补齐所需数据库结构。详情见 [v0.2.4 发布说明](docs/releases/v0.2.4.md)。

## [0.2.1]

- Agent 添加流程可生成 Docker Compose 或 `docker run` 部署命令，自动填入 Server 地址与一次性入网凭证。
- 官方 Compose 改用各组件的 latest 稳定标签；发布流程只更新本次实际发布组件的 latest，且不会回退到旧版本。
- 本次仅发布 Server，Agent 保持 `0.2.0`；无需数据库迁移。升级方法见 [v0.2.1 发布说明](docs/releases/v0.2.1.md)。

## [0.2.0]

- 产品收敛为 TCP、HTTP、HTTPS 内网穿透，移除 Headscale、Tailscale 与虚拟组网管理。
- 提供工作空间隔离、账号邀请与恢复、Agent 入网审批、mTLS 通道和身份自动续签。
- 统一管理公网域名、解析检查、Cloudflare DNS 验证及 Caddy 自动证书。
- 本版本发布 Server 与 Agent，仅支持全新安装，不从 v0.1.x 迁移数据。部署与兼容说明见 [v0.2.0 发布说明](docs/releases/v0.2.0.md)。

## [0.1.17] - 2026-09-08

### Added

- 增加 Agent 脱敏连接观测、P2P/节点中继/DERP 中继分类和受限异步连接检测。
- 增加检测网段的一次确认批量启用，原子完成路由创建、Agent 广告、控制面批准和工作空间授权。
- Auth Key 加入的 Tailscale 节点按签发工作空间自动归属，未知来源节点继续隔离。

### Changed

- 将设备、私网访问、公网服务、访问策略及域名、密钥、组网设置整合到统一“网络”入口。
- 普通共享网段默认启用 SNAT；无 SNAT 与静态回程路由仅保留在高级 SiteLink 流程。
- 统一设备、路由、域名和公网服务的产品状态与详情 Sheet，并保留跨域名配置的服务草稿。

### Release

- Server、Web、共享协议和 Agent 均有代码变化，本版本同时发布 `server` 与 `agent`，必须共同升级。

## [0.1.15] - 2026-09-08

### Fixed

- 修复 Headscale Supervisor 在连续配置通知竞态下停止监控、导致 Headscale 子进程永久退出的问题。
- 访问控制策略校验区分策略内容无效和组网服务暂不可用，并对页面隐藏内部连接错误。

### Release

- 本版本为 Server-only 正式发布，Agent 保持 `0.1.14`，无需升级。

## [0.1.14] - 2026-09-08

### Fixed

- 修复移动端 OIDC 登录被旧版 PWA 应用壳和 Service Worker 导航 fallback 截断的问题。
- 修复访问控制页面使用虚构 `preview` 目标校验当前 Headscale Policy 的问题。
- 修复设备列表重复显示同一个组网地址，并让 Agent 为 tailscaled 设置持久化状态目录。
- 修正 JWKS 标准 `use` 字段，并更新 Server/Agent 发布示例。

## [0.1.13] - 2026-09-07

### Added

- 增加 Nexo 账号与 Headscale OIDC 账号映射、固定签名密钥和账号撤销同步。
- 增加 OIDC 登录、授权回调及官方 Tailscale 客户端注册流程。
- 增加 OIDC 账号迁移和相关服务端、浏览器验收测试。

### Changed

- 收敛认证、Headscale、策略和公网入口状态处理，统一错误日志和部署检查。

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
