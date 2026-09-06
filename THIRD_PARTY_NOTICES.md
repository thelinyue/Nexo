# Third-Party Notices

Nexo 官方容器镜像包含以下独立运行的第三方组件。它们不被编译进 Nexo
单一可执行文件，各自继续适用原项目许可证。

| 组件 | 固定版本 | 许可证 | 项目地址 |
| --- | --- | --- | --- |
| Caddy | 2.11.4 | [Apache-2.0](licenses/CADDY.txt) | https://github.com/caddyserver/caddy |
| caddy-dns/cloudflare | 0.2.4 | [Apache-2.0](licenses/CADDY_DNS_CLOUDFLARE.txt) | https://github.com/caddy-dns/cloudflare |
| Headscale | 0.29.3 | [BSD-3-Clause](licenses/HEADSCALE.txt) | https://github.com/juanfont/headscale |
| Tailscale | 1.102.3 | [BSD-3-Clause](licenses/TAILSCALE.txt) | https://github.com/tailscale/tailscale |

Rust 与 Web 构建依赖的准确版本记录在 `Cargo.lock` 和
`web/package-lock.json` 中。版权归各上游项目所有。
