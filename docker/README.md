# Nexo Server/Agent 容器

正式部署直接使用仓库根目录的 `compose.yml` 和 `compose.agent.yml`。`TZ`
可覆盖 Server、Agent 和内置子进程的日志时区，默认是 `Asia/Shanghai`；Agent
另需 `NEXO_SERVER_URL` 和首次入网的一次性 `NEXO_ENROLLMENT_TOKEN`。Server
容器内的组网服务使用 `8281`，只允许
本机访问，不作为公网入口。内置
Caddy 公网入口使用 `80/443`，管理入口使用 `8280`，Agent 控制通道使用 `9890`，
Tunnel 数据通道使用 `9891`。

Agent Gateway 只需要：

- `/dev/net/tun`
- `NET_ADMIN`
- 持久化 `/data/nexo-agent`

不要使用 `privileged: true` 或挂载 Docker Socket。Linux 生产环境使用
`network_mode: host`，让 Agent 检测真实 LAN 网卡并访问家庭服务。

`compose.phase2.integration.yml` 是 Linux 验收拓扑，启动后由验收脚本负责：

1. 批准两个 Agent 并创建家庭/办公室共享网络；
2. 签发工作空间密钥，接入一台不运行 Nexo Agent 的官方 Tailscale 客户端；
3. 验证客户端访问子网、SNAT、公网 Web/TCP、WebSocket 和大文件；
4. 关闭子网、依次重启 Agent/Server，检查身份保留及路由自动收敛。

在原生 Linux 或具备 Docker Engine 的 WSL2 环境中可直接执行完整验收
（需要 `docker`、`curl`、`jq`）：

```bash
bash docker/network-smoke.sh
```

脚本使用独立的测试工作空间和容器卷，生成并批准两个 Agent 入网请求，不创建站点。
LAN 服务终端不安装 Nexo/Tailscale，也不配置静态回程路由。官方客户端仅连接控制网络，
访问 LAN 服务必须经过 Agent 子网转发；服务端源地址应为 Agent 的 LAN 地址。

Server 默认开启“使用设备名称访问”，内部名称后缀由官方镜像管理。公网域名、
证书、设备名称、共享网络和公网访问统一在 Web 中配置。

如果 Windows 侧没有 Docker CLI，请从已安装 Docker Engine 的 WSL2 发行版中执行上述命令。

## 真实 Cloudflare ACME 验收

`cloudflare-acme-smoke.sh` 只用于发布前的人工验收，不进入普通 CI。请使用
Cloudflare 管理的独立测试域名，Token 仅授予对应 Zone 的 `Zone:Read` 和
`DNS:Edit`，并保存到仓库外的文本文件。脚本不会修改 A/AAAA；Caddy 只会在
签发期间创建并清理 `_acme-challenge` TXT 记录。

先执行 Staging，确认 DNS-01 和本机 Caddy TLS 闭环：

```bash
NEXO_REAL_ACME_DOMAIN=nexo-test.example.com \
NEXO_CLOUDFLARE_TOKEN_FILE=/run/secrets/cloudflare-token \
NEXO_ACME_KEEP_IMAGE=true \
bash docker/cloudflare-acme-smoke.sh staging
```

Staging 通过后，使用同一构建镜像执行一次 Production。Production 必须显式
确认，避免误用正式签发额度：

```bash
NEXO_REAL_ACME_DOMAIN=nexo-test.example.com \
NEXO_CLOUDFLARE_TOKEN_FILE=/run/secrets/cloudflare-token \
NEXO_ACME_SKIP_BUILD=true \
NEXO_CONFIRM_PRODUCTION_ACME=yes \
bash docker/cloudflare-acme-smoke.sh production
```

每次运行都使用并清理固定前缀的独立容器和数据卷。不要使用承载真实业务的
生产根域名反复运行该脚本，也不要把 Token 内容写入命令行、仓库或日志。

管理员恢复需要本地 Docker 权限，可执行 `docker compose -f docker/compose.phase2.yml
exec nexo-server nexo admin recover` 获取一次性 Recovery Code；恢复码不会写入
SQLite 或普通日志，输入恢复页面后会立即吊销全部旧 Session。
