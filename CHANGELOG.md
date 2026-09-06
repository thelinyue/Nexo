# Changelog

本项目使用 [Semantic Versioning](https://semver.org/) 记录公开版本。

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

[0.1.1]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.1
[0.1.0]: https://github.com/thelinyue/Nexo/releases/tag/v0.1.0
