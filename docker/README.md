# Nexo Server/Agent 容器

`compose.phase1.yml` 提供 Server 与 Agent 的最小部署示例。Server 容器内的
Headscale 使用 `8281`，只允许本机/容器内部访问，不作为公网入口。第二阶段的
Caddy 公网入口使用 `80/443`，管理入口使用 `8280`，Agent 控制通道使用 `9890`，
Tunnel 数据通道使用 `9891`。

Agent Gateway 只需要：

- `/dev/net/tun`
- `NET_ADMIN`
- 持久化 `/data/nexo-agent`

不要使用 `privileged: true` 或挂载 Docker Socket。Linux 生产环境使用
`network_mode: host`，让静态路由可以指向真实的 LAN 网关地址。

`compose.integration.yml` 是 Linux CI 验收拓扑脚手架，启动后由验收脚本负责：

1. 批准两个 Agent 并创建家庭/办公室共享网络；
2. 创建 Site Link，确认两侧静态路由；
3. 验证双向大文件 TCP/HTTPS 和真实源 IP；
4. 关闭 Link、依次重启 Agent/Server，检查 Mesh 保持在线且路由自动收敛。

在原生 Linux 或具备 Docker Engine 的 WSL2 环境中可直接执行完整验收
（需要 `docker`、`curl`、`jq`）：

```bash
bash docker/site-to-site-smoke.sh
```

脚本会创建 default 租户下的两个站点、生成并批准两个 Agent 入网请求，随后
验证双向 HTTP/HTTPS、8 MiB TCP 传输、真实 LAN 源地址、关闭互联和重启恢复。
验收终端镜像只包含测试用的 Python/OpenSSL/curl，不包含 Nexo 或 Tailscale。

Server 内置 Headscale 默认开启 MagicDNS，组网名称后缀为 `mesh.nexo.internal`；
生产部署可通过 `NEXO_MESH_DNS_BASE_DOMAIN` 指定其他内部域名。公网 Caddy、公开域名
和泛域名证书仍属于第二阶段。

如果 Windows 侧没有 Docker CLI，请从已安装 Docker Engine 的 WSL2 发行版中执行上述命令。

管理员恢复需要本地 Docker 权限，可执行 `docker compose -f docker/compose.phase2.yml
exec nexo-server nexo admin recover` 获取一次性 Recovery Code；恢复码不会写入
SQLite 或普通日志，输入恢复页面后会立即吊销全部旧 Session。
