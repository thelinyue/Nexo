# Nexo（联巢）

Nexo 是面向个人自托管、NAS/HomeLab 和小型网络环境的设备、异地组网与公网访问管理服务。
它把设备、共享网络、站点互联、Web 服务和 TCP 端口集中到一个 Web 界面中，正常使用不需要编辑配置文件。

## v0.1.0 快速开始

首个正式版本仅支持 `linux/amd64` Docker。Server 与 Agent 使用独立镜像，
Agent 可以安装在其他家庭、办公室或 VPS 上并加入任意 Nexo Server。

从 [v0.1.0 Release](https://github.com/thelinyue/Nexo/releases/tag/v0.1.0)
下载 `nexo-v0.1.0-docker.tar.gz` 并解压，然后：

```bash
cp .env.example .env
# 编辑 .env 中的公网或 LAN 可达地址
docker compose up -d
docker compose exec nexo-server nexo bootstrap-code
```

打开 `http://<Server-LAN-IP>:8280`，使用一次性口令创建管理员。公网域名和
证书继续在 Web 中配置；未配置 HTTPS 时，LAN 管理入口仍可使用，但新的组网
应用会保持受限状态。

在其他站点部署 Agent：

```bash
# 在该站点准备相同的 .env，并将地址指向目标 Nexo Server
docker compose -f compose.agent.yml up -d
```

首次启动前，将 Web 中创建的一次性入网 Token 填入 `NEXO_ENROLLMENT_TOKEN`。
设备成功加入后立即从 `.env` 中删除 Token，再次执行 Compose 应用配置。Agent
身份保存在 `./data/nexo-agent`，不会绑定到生成 Token 的那台 Server 镜像。

## 第二阶段能力

- 首次打开 LAN 管理入口完成管理员初始化，之后使用 Argon2id 密码和服务端 Session 登录。
- 设备通过一次性入网请求加入 Nexo，批准后自动建立异地组网身份。
- Subnet Gateway 和 Site Gateway 保留第一阶段的双向 LAN 互联、真实源 IP 和稳定设备身份。
- “公网访问”支持 TCP 端口以及 HTTP/HTTPS Web Service；Web Service 通过受限本地桥接，不暴露 Origin 端口。
- 配置了根域名后，内置公网入口提供泛域名证书和 `nexo.<domain>` 管理入口、`mesh.<domain>` 组网入口。
- Caddy、Headscale 和 Tailscale 是镜像中的独立组件，由 Nexo 负责协调；普通用户不需要操作它们的配置或命令。

当前阶段明确不包含 Exit Node、默认路由、UDP、TLS passthrough、NAT 转换、跨租户共享或 Caddy 路径路由。

## 固定端口

| 端口 | 用途 | 暴露范围 |
| --- | --- | --- |
| `8280` | LAN HTTP 管理入口 | `0.0.0.0` |
| `9888` | Caddy 到 Nexo 的本机 HTTPS 管理后端 | `127.0.0.1` |
| `8281` | 内置组网控制服务 | `127.0.0.1` |
| `8290` | Caddy 管理 API | `127.0.0.1` |
| `9890` | Agent mTLS 控制通道 | `0.0.0.0` |
| `9891` | Tunnel TLS/Yamux 数据通道 | `0.0.0.0` |
| `80/443` | 公网 HTTP/HTTPS 入口 | `0.0.0.0` |
| `20000-29999` | 自动分配的公网 TCP Tunnel 端口 | `0.0.0.0` |

`8281` 和 `8290` 不应映射到公网。LAN 页面会持续提示当前为未加密 HTTP，建议只在可信局域网使用；正式公网管理应使用 HTTPS。

## 本地开发

服务端默认监听 `0.0.0.0:8280`，设备控制通道默认监听 `0.0.0.0:9890`。未设置 `NEXO_HEADSCALE_ENABLED` 或 `NEXO_CADDY_ENABLED` 时，本地开发不会启动宿主机上的未知组件。

```powershell
$env:NEXO_HTTP_ADDR = "127.0.0.1:8280"
$env:NEXO_CONTROL_ADDR = "127.0.0.1:9890"
cargo run -p nexo-server
```

首次启动后，在本机读取一次性初始化口令：

```powershell
cargo run -p nexo-server -- bootstrap-code
```

打开 `http://127.0.0.1:8280`，输入口令、管理员用户名和不少于 12 个字符的密码。创建首个管理员后，Bootstrap Code Secret 会永久销毁。

忘记密码时，必须在拥有本地 Docker/主机权限的环境执行：

```powershell
cargo run -p nexo-server -- admin recover
```

命令只显示 10 分钟有效、仅可使用一次的 Recovery Code；在恢复页面设置新密码后，所有旧 Session 会立即吊销。旧版 `recover` 命令仍兼容，但新部署统一使用 `admin recover`。

官方 Server 镜像同样提供 `nexo` 命令别名：

```bash
docker compose -f docker/compose.phase2.yml exec nexo-server nexo admin recover
```

## Docker 部署

正式发布使用仓库根目录的 [`compose.yml`](compose.yml) 和
[`compose.agent.yml`](compose.agent.yml)，镜像标签固定为 `0.1.0`，不会隐式
升级。开发环境的源码构建示例仍保留在 [`docker/compose.phase2.yml`](docker/compose.phase2.yml)。
它们使用 host network，保留真实 LAN 转发所需的最小权限：Agent 只授予
`/dev/net/tun` 和 `NET_ADMIN`，不使用 `privileged` 或 Docker Socket。

在原生 Linux 或具备 Docker Engine 的 WSL2 发行版中运行：

```bash
docker compose -f docker/compose.phase2.yml up -d --build
```

如需验收第一阶段 Site-to-Site 拓扑：

```bash
bash docker/site-to-site-smoke.sh
```

验收拓扑只使用固定的 `nexo-phase1-integration` Compose 项目和测试卷，失败时先输出相关状态与日志，然后清理自身资源，不会触碰其他项目或 `.edge-screenshot/`。

## 数据备份、恢复与升级

Nexo Server 的 SQLite、身份、API Key、证书和其他 Secret 均位于
`./data/nexo`。备份必须覆盖整个目录，不能只复制 `nexo.db`。一致性备份流程：

```bash
docker compose stop nexo-server
tar -C . -czf nexo-data-$(date +%Y%m%d-%H%M%S).tar.gz data/nexo
docker compose start nexo-server
```

Agent 的 `./data/nexo-agent` 保存设备身份；重装站点前也应单独备份。恢复时先
停止对应容器，把现有数据目录移到安全位置，再解压完整备份并启动。恢复后检查
管理员登录、设备身份、Tunnel 和组网状态是否自动收敛。

升级时先完成备份，再将 Compose 中两个镜像改为同一个新版本号，执行：

```bash
docker compose pull
docker compose up -d
```

数据库迁移只向前执行。升级后的数据目录不得直接交给旧版本二进制；需要回滚时，
必须同时恢复升级前的完整数据备份和对应旧镜像。

## Web Service 与 TCP Tunnel

管理员登录后，在“公网访问”页面选择：

- **Web 服务**：填写访问名称、本地地址和端口，选择 HTTP 或 HTTPS Origin。HTTP 服务只走 80；HTTPS 服务走 443，80 对同名主机返回 308 跳转。
- **TCP 端口**：选择自动分配或手动填写 `20000-29999` 中的端口。端口占用会在保存前由 Server 和宿主机同时检查。

修改流程始终显示“正在应用 / 已生效 / 应用失败”，失败时保留上一份 Applied 配置。证书私钥、Cloudflare Token 和自定义 CA 只保存为 `0600` Secret 文件，不会进入数据库导出、日志或 API 响应。

## 组网

设备、共享本地网络和站点互联均通过 Web Desired State 管理。Nexo 会拒绝默认路由、重叠网段和错误租户；Site Gateway 使用不改写源地址的策略。关闭站点互联只撤销两侧路由，组网设备本身仍保持连接。

公网域名配置完成前，已有设备信息仍可查看，但新的公网组网入口和新的网关应用会保持受限状态。更换已经被设备或 Web Service 使用的根域名前，必须先移除这些依赖。

## 开发检查

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cd web && npm run build
bash -n docker/site-to-site-smoke.sh
git diff --check
```
