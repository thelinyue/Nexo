# Nexo（联巢）

Nexo 是面向个人自托管环境的设备、隧道和异地组网管理服务。

## 当前开发阶段

第三阶段已经建立设备入网的状态边界：

- 管理端创建一次性入网凭证，明文只返回一次，数据库只保存摘要。
- Agent 可以通过 `NEXO_SERVER_URL` 指向任意 Nexo Server。
- Agent 在本地生成私钥和 CSR，提交设备信息后进入 `awaiting_approval`。
- 服务端首次启动生成设备身份 CA；管理员批准后签发仅用于 TLS 客户端认证的设备证书。
- Agent 自动轮询审批结果并一次性领取证书链，状态随后变为 `consumed`；私钥始终留在 Agent。
- 服务端同时监听独立的 mTLS 控制通道；Agent 领取证书后会使用设备证书持续发送心跳，服务端只接受证书指纹与设备 ID 匹配的连接。
- Agent 在控制通道首次握手时只读探测 TUN、NET_ADMIN、IP 转发和本地直连网段，并上报结构化的 Subnet Gateway / Site Gateway 能力状态；探测不会修改宿主机网络配置，也不会自动发布网段。
- 服务端会在 mTLS 握手响应及后续心跳确认中下发该设备对应的最新网关 Desired State，Agent 会回传带 revision 的应用 ACK；当前未接入 Tailscale 路由执行器，因此 ACK 保持 `CHECKING`，不会把未生效的路由标记为 `READY`。
- `nexo-headscale-adapter` 已定义 Nexo 路由申请边界；未配置 API 时返回可展示的 Pending 结果，业务代码不会读取 Headscale 内部数据库。
- Tunnel/组网配置下发仍是后续切片；当前不会把待签发设备伪装为在线设备。

## 本地运行

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

接口会检查设备最近上报的能力和网卡前缀，只创建 `CHECKING` 的 Desired State；服务端随后通过 mTLS 下发本地及站点互联所需的目标网段。`applied_prefix` 仍为空，直到 Agent 与 Headscale Adapter 完成真实路由应用并回传 `READY` ACK。两个站点的互联使用 `/api/v1/site-links`，提交前会拒绝重叠网段并要求两端网关在线且具备站点网关能力。当前切片不会自动修改宿主机转发、路由器静态路由或发布 Headscale 路由。

生产部署应通过 HTTPS 保护管理 API，并使用后续管理员 Session 替换开发阶段的 Bootstrap Token；
同时应保护 Nexo 数据目录，因为其中包含服务端设备 CA 私钥。
