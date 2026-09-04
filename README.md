# Nexo（联巢）

Nexo 是面向个人自托管环境的设备、隧道和异地组网管理服务。

## 当前开发阶段

第一阶段已经建立内置 Headscale 与真实 Site Gateway 的状态边界：

- 管理端创建一次性入网凭证，明文只返回一次，数据库只保存摘要。
- Agent 可以通过 `NEXO_SERVER_URL` 指向任意 Nexo Server。
- Agent 在本地生成私钥和 CSR，提交设备信息后进入 `awaiting_approval`。
- 服务端首次启动生成设备身份 CA；管理员批准后签发仅用于 TLS 客户端认证的设备证书。
- Agent 自动轮询审批结果并一次性领取证书链，状态随后变为 `consumed`；私钥始终留在 Agent。
- 服务端同时监听独立的 mTLS 控制通道；Agent 领取证书后会使用设备证书持续发送心跳，服务端只接受证书指纹与设备 ID 匹配的连接。
- Agent 在控制通道首次握手时只读探测 TUN、NET_ADMIN、IP 转发和本地直连网段，并上报结构化的 Subnet Gateway / Site Gateway 能力状态；探测不会修改宿主机网络配置，也不会自动发布网段。
- 服务端会在 mTLS 握手响应及后续心跳确认中下发该设备对应的最新网关 Desired State，Agent 会回传带 revision 的应用 ACK；Agent 已将本地发布网段、远端接收路由和站点互联的 SNAT 策略整理成应用计划。默认只生成计划，设置 `NEXO_TAILSCALE_APPLY=true` 后才执行 Tailscale CLI；命令成功但 Headscale 尚未批准时 ACK 仍保持 `CHECKING`，不会把未生效的路由标记为 `READY`。每次实际应用前 Agent 都会重新检查网关能力；命令失败会按指数退避和抖动重试，不会在每个心跳中重复执行。
- 共享网络和站点互联都支持显式启用/关闭；关闭操作会递增 Desired State revision，并下发带 `enabled=false` 的撤销路由，避免 Agent 继续保留旧配置。
- Server 镜像内置固定版本的 Headscale 子进程；Supervisor 负责配置生成、健康检查、退避重启和优雅关闭。Nexo 只通过异步 HTTP Adapter 调用 Headscale API，不读取 Headscale 内部数据库。
- Headscale API Key 只保存在权限受限的独立 Secret 文件；首次启动和剩余 14 天时会先自检新 Key，再原子切换并吊销旧 Key。运行期间也会定期检查轮换，明文不进入 SQLite、日志或 Web API。
- Web 批准设备后，Agent 通过 mTLS 控制通道领取一次性 Mesh Enrollment；Server 根据 Pre-auth Key ID 绑定稳定 Node ID。重启会恢复未完成尝试，身份错配只能通过携带旧 Node ID 和明确确认的高级恢复接口处理。
- Agent 镜像内置独立的固定版本 Tailscale/tailscaled 文件；Site Gateway 始终使用 `accept-routes=true`、`snat-subnet-routes=false`，保留真实 LAN 源地址，不实现 Exit Node、默认路由或网段转换。
- 内置 Headscale 默认启用 MagicDNS（后缀默认为 `mesh.nexo.internal`，可用 `NEXO_MESH_DNS_BASE_DOMAIN` 调整）；Agent 通过 `accept-dns=true` 接收组网名称解析。
- 每条网关路由分别记录本地应用、Headscale 发现/批准/Serving 和对端接受状态；没有逐路由 ACK、Headscale Serving 或两侧静态路由确认时，UI 不会显示 `READY`。
- Agent 的能力报告会带上每个已检测局域网接口的本地地址；共享网络和站点互联查询会返回 `gateway_address` 以及双向 `static_routes` 引导，用户可据此把远端网段添加到两侧路由器。Nexo 只展示目标网段和下一跳，不会自动登录或修改路由器。
- `GET /api/v1/sites`、`GET /api/v1/devices`、`GET /api/v1/site-networks` 和 `GET /api/v1/site-links` 已提供给 Web 概览及创建表单使用；共享网络和站点互联响应同时返回用户可读名称、网段和应用状态，避免 UI 暴露内部 ID。
- Web 概览中的“新建共享网络”和“新建互联”会根据设备最近上报的能力与本地网段生成可选项；提交后立即回读 Desired / Applied 状态，服务端返回的网段冲突或能力错误会直接显示在表单内。
- 共享网络和站点互联响应额外返回独立的 `health_status` / `health_error`；健康状态会综合设备在线、能力报告、本地网段和应用确认，`ready` 才表示当前网关条件完整，`degraded` 只表示仍在等待或设备暂时离线，`failed` 表示需要处理的能力或数据问题。
- 公网 Tunnel、Caddy、公开域名和泛域名证书仍属于第二阶段；当前不会把待签发设备伪装为在线设备。

## 本地运行

Web 概览原型位于 `web/`，使用系统字体与可适配的明暗材质；开发预览可执行：

```powershell
cd web
npm install
npm run build
```

Linux Docker 的第一阶段闭环部署和双向 Site-to-Site 验收见 [`docker/README.md`](docker/README.md)。

```powershell
$env:NEXO_ADMIN_TOKEN = "仅用于本地开发的管理员凭证"
$env:NEXO_HTTP_ADDR = "127.0.0.1:9888"
# 可选：默认 0.0.0.0:9890，Agent 通过此地址建立 mTLS 控制通道
$env:NEXO_CONTROL_ADDR = "127.0.0.1:9890"
# 若 Agent 连接地址不是 nexo-server，可与 Agent 设置相同的证书名称
$env:NEXO_CONTROL_SERVER_NAME = "nexo-server"
cargo run -p nexo-server
```

管理端点要求 `X-Nexo-Admin-Token` 请求头。未配置 `NEXO_ADMIN_TOKEN` 时，创建和审批接口会拒绝请求。

创建入网凭证：

```powershell
curl.exe -X POST http://127.0.0.1:9888/api/v1/enrollments `
  -H "content-type: application/json" `
  -H "x-nexo-admin-token: 仅用于本地开发的管理员凭证" `
  -d '{"tenant_id":"default","ttl_seconds":900}'
```

Agent 使用响应中的 `token`：

```powershell
$env:NEXO_SERVER_URL = "http://127.0.0.1:9888"
$env:NEXO_CONTROL_ADDR = "127.0.0.1:9890"
$env:NEXO_CONTROL_SERVER_NAME = "nexo-server"
$env:NEXO_ENROLLMENT_TOKEN = "一次性 token"
$env:NEXO_DEVICE_NAME = "家庭 NAS"
# 可选：默认 ./data/nexo-agent；容器部署建议挂载持久卷
$env:NEXO_STATE_DIR = "./data/nexo-agent"
# 可选：显式启用本机 Tailscale CLI；默认 false，仅生成计划
$env:NEXO_TAILSCALE_APPLY = "true"
# 可选：Tailscale 二进制路径，默认从 PATH 查找 tailscale
$env:NEXO_TAILSCALE_BIN = "tailscale"
cargo run -p nexo-agent
```

Agent 会显示 `awaiting_approval` 并等待管理员批准。管理员可查询并批准：

```powershell
curl.exe -H "x-nexo-admin-token: 仅用于本地开发的管理员凭证" `
  http://127.0.0.1:9888/api/v1/enrollments/入网请求 ID
curl.exe -X POST `
  -H "x-nexo-admin-token: 仅用于本地开发的管理员凭证" `
  http://127.0.0.1:9888/api/v1/enrollments/入网请求 ID/approve
```

批准后 Agent 会自动领取并保存以下本地材料：

- `device-key.pem`：Agent 私钥，只在 Agent 本地生成和使用。
- `device-cert.pem`：服务端签发的设备客户端证书。
- `server-ca.pem`：验证 Nexo Server 身份的 CA 证书。
- `device-id`：服务端分配的设备 ID。

如果设置了 `NEXO_CONTROL_ADDR`，Agent 领取身份后会自动连接 mTLS 控制通道，首次连接和后续心跳都会更新服务端设备在线状态。控制通道服务端证书由 Nexo 自有设备 CA 签发，名称默认是 `nexo-server`；通过 Docker Compose 部署时应让 Agent 使用能解析到服务端的名称，并同步设置 `NEXO_CONTROL_SERVER_NAME`。

## 网关 Desired State API

Agent 首次通过 mTLS 控制通道上报本地网卡、TUN、NET_ADMIN 和 IP 转发探测结果。管理员在此基础上明确选择共享网络：

```powershell
curl.exe -X POST http://127.0.0.1:9888/api/v1/site-networks `
  -H "content-type: application/json" `
  -H "x-nexo-admin-token: 仅用于本地开发的管理员凭证" `
  -d '{"tenant_id":"default","site_id":"站点 ID","name":"家庭网络","publisher_device_id":"设备 ID","interface_id":"eth0","prefix":"192.168.10.0/24"}'
```

接口会检查设备最近上报的能力和网卡前缀，只创建 `CHECKING` 的 Desired State；服务端随后通过 mTLS 下发本地及站点互联所需的目标网段。`applied_prefix` 仍为空，直到 Agent 与 Headscale Adapter 完成真实路由应用并回传逐路由结果，且 Headscale 已发现、批准并提供路由。两个站点的互联使用 `/api/v1/site-links`，提交前会拒绝重叠网段并要求两端网关在线且具备站点网关能力。Nexo 不会自动修改用户路由器，但会在 Linux 网关中应用 Tailscale 转发参数。

关闭或重新启用配置：

```powershell
# 关闭共享本地网络；Agent 会收到撤销路由
curl.exe -X POST -H "x-nexo-admin-token: 仅用于本地开发的管理员凭证" `
  http://127.0.0.1:9888/api/v1/site-networks/网络 ID/disable

# 重新启用共享本地网络
curl.exe -X POST -H "x-nexo-admin-token: 仅用于本地开发的管理员凭证" `
  http://127.0.0.1:9888/api/v1/site-networks/网络 ID/enable

# 站点互联同样支持 /disable 和 /enable
curl.exe -X POST -H "x-nexo-admin-token: 仅用于本地开发的管理员凭证" `
  http://127.0.0.1:9888/api/v1/site-links/互联 ID/disable
```

接口响应中的 `enabled`、`desired_revision`、`apply_status` 和 `applied_prefix` 分别表示配置开关、期望版本、应用阶段和已确认的网段；`CHECKING` 不等于路由已经生效。

生产部署应通过 HTTPS 保护管理 API，并使用后续管理员 Session 替换开发阶段的 Bootstrap Token；
同时应保护 Nexo 数据目录，因为其中包含服务端设备 CA 私钥。
