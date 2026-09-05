# Nexo（联巢）

Nexo 是面向个人自托管、NAS/HomeLab 和小型网络环境的设备、异地组网与公网访问管理服务。
它把设备、共享网络、站点互联、Web 服务和 TCP 端口集中到一个 Web 界面中，正常使用不需要编辑配置文件。

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

生产示例见 [`docker/compose.phase2.yml`](docker/compose.phase2.yml)。它使用 host network，保留真实 LAN 转发所需的最小权限：Agent 只授予 `/dev/net/tun` 和 `NET_ADMIN`，不使用 `privileged` 或 Docker Socket。

在原生 Linux 或具备 Docker Engine 的 WSL2 发行版中运行：

```bash
docker compose -f docker/compose.phase2.yml up -d --build
```

如需验收第一阶段 Site-to-Site 拓扑：

```bash
bash docker/site-to-site-smoke.sh
```

验收拓扑只使用固定的 `nexo-phase1-integration` Compose 项目和测试卷，失败时先输出相关状态与日志，然后清理自身资源，不会触碰其他项目或 `.edge-screenshot/`。

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
