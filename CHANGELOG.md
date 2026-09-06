# Changelog

本项目使用 [Semantic Versioning](https://semver.org/) 记录公开版本。

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

[0.1.2]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.2
[0.1.1]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.1
[0.1.0]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.0
