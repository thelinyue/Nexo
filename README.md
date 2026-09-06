# Nexo（联巢）

Nexo 是面向个人自托管、NAS/HomeLab 和小型网络环境的设备、异地组网与公网访问管理服务。
它把设备、共享网络、站点互联、Web 服务和 TCP 端口集中到一个 Web 界面中，正常使用不需要编辑配置文件。

## v0.1.4 快速开始

当前版本仅支持 `linux/amd64` Docker。Server 与 Agent 使用独立镜像，
Agent 可以安装在其他家庭、办公室或 VPS 上并加入任意 Nexo Server。

### 部署 Server

新建一个空目录，将下面内容保存为 `compose.yml`。该配置不需要 `.env`，可以
直接复制并启动：

```yaml
name: nexo

services:
  nexo-server:
    image: ghcr.io/thelinyue/nexo-server:0.1.4
    container_name: nexo-server
    network_mode: host
    environment:
      TZ: ${TZ:-Asia/Shanghai}
    volumes:
      - ./data/nexo:/data/nexo
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "curl --fail --silent http://127.0.0.1:8280/health >/dev/null"]
      interval: 10s
      timeout: 3s
      retries: 6
```

```bash
docker compose up -d
docker compose exec nexo-server nexo bootstrap-code
```

打开 `http://<Server-LAN-IP>:8280`，使用一次性口令创建管理员。公网域名和
证书继续在 Web 中配置；未配置 HTTPS 时，LAN 管理入口仍可使用，但新的组网
应用会保持受限状态。

### 添加 Agent

在 Web 的“添加设备”中填写设备名称和站点，Nexo 会生成一份已经包含 Server
地址和一次性 Token 的完整 Compose。复制到目标设备并运行：

```bash
docker compose up -d
```

需要手动准备时，也可以直接使用下面的完整模板，只替换两个值：

```yaml
name: nexo-agent

services:
  nexo-agent:
    image: ghcr.io/thelinyue/nexo-agent:0.1.4
    container_name: nexo-agent
    network_mode: host
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      net.ipv4.ip_forward: "1"
      net.ipv6.conf.all.forwarding: "1"
    environment:
      TZ: ${TZ:-Asia/Shanghai}
      NEXO_SERVER_URL: "http://192.168.1.10:8280"
      NEXO_ENROLLMENT_TOKEN: "请替换为 Web 生成的一次性 Token"
    volumes:
      - ./data/nexo-agent:/data/nexo-agent
    restart: unless-stopped
```

| 环境变量 | 用途 | 格式与示例 | 要求 |
| --- | --- | --- | --- |
| `TZ` | Server、Agent 及内置子进程的日志时区 | `Asia/Shanghai`、`UTC` | 可选，默认 `Asia/Shanghai`；使用 IANA 时区名称 |
| `NEXO_SERVER_URL` | Agent 首次联系的 Nexo 管理地址，并用于自动推导同一主机的 `9890/9891` | `http://192.168.1.10:8280` 或 `https://nexo.example.com` | 必填；必须能从 Agent 所在网络访问 |
| `NEXO_ENROLLMENT_TOKEN` | 授权一台设备提交入网请求 | Web 生成的短时字符串 | 首次入网必填且属于敏感信息；领取设备身份后失效，可从 Compose 或 `.env` 删除 |

设备名称、所属站点、域名与 HTTPS、共享网络和穿透服务都在 Web 中管理。
官方镜像内的组件路径、监听地址、能力开关和数据目录不需要用户设置。Agent
身份保存在 `./data/nexo-agent`，容器重启后不会再次使用已经失效的 Token。

## 第二阶段能力

- 首次打开 LAN 管理入口完成管理员初始化，之后使用 Argon2id 密码和服务端 Session 登录。
- 设备通过一次性入网请求加入 Nexo，批准后自动建立异地组网身份。
- Subnet Gateway 和 Site Gateway 保留第一阶段的双向 LAN 互联、真实源 IP 和稳定设备身份。
- “公网访问”下的“内网穿透”支持 TCP 端口以及 HTTP/HTTPS Web Service；每条资源称为“穿透服务”，Web Service 通过受限本地桥接，不暴露 Origin 端口。
- “域名与 HTTPS”负责根域名、证书来源和生效状态；配置后提供泛域名证书和 `nexo.<domain>` 管理地址、`mesh.<domain>` 组网地址。
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
[`compose.agent.yml`](compose.agent.yml)，镜像标签固定为 `0.1.4`，不会隐式
升级。开发环境的源码构建示例仍保留在 [`docker/compose.phase2.yml`](docker/compose.phase2.yml)。
它们使用 host network，保留真实 LAN 转发所需的最小权限：Agent 只授予
`/dev/net/tun` 和 `NET_ADMIN`，不使用 `privileged` 或 Docker Socket。

`8280`、`9890`、`9891`、`80` 和 `443` 是进程启动前就必须建立的固定网络
边界，因此不能依赖 Web 启动后修改。本版本不支持为控制和 Tunnel 数据通道
自定义 NAT 映射端口。

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

## 穿透服务

管理员登录后，在“公网访问 > 内网穿透”页面添加穿透服务：

- **Web 服务**：填写访问名称、本地地址和端口，选择 HTTP 或 HTTPS Origin。HTTP 服务只走 80；HTTPS 服务走 443，80 对同名主机返回 308 跳转。
- **TCP 端口**：选择自动分配或手动填写 `20000-29999` 中的端口。端口占用会在保存前由 Server 和宿主机同时检查。

修改流程始终显示“配置生效中 / 已生效 / 配置失败”，失败时保留上一份 Applied 配置。证书私钥、Cloudflare Token 和自定义 CA 只保存为 `0600` Secret 文件，不会进入数据库导出、日志或 API 响应。

## Web PWA

Nexo Web 可从支持 PWA 的桌面或移动浏览器安装，启动地址为 `/#/overview`。Service Worker 只预缓存应用壳和带版本的静态资源；`/api/` 请求始终联网，账户、设备、穿透服务和网络数据不会写入离线缓存。断网时页面会显示“无法连接 Nexo”并提供重试，新版本也只在用户确认后刷新。

浏览器设备模拟用于验证响应式布局与 Service Worker 行为，不能替代真实 iOS Safari 主屏幕模式或 Android 安装后的验收。

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
