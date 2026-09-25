# Nexo 容器说明

`Dockerfile.server` 构建管理入口、控制服务与 Tunnel 公网入口；`Dockerfile.agent` 构建只负责本地目标代理和 Tunnel 通道的 Agent。默认 Compose 使用各组件最新稳定版 `latest`，数字标签保留用于回退。首次安装使用空数据目录，已有 v0.2.x 安装更新时保留原目录；v0.1.x 需要全新安装。

新安装从 [README 快速部署](../README.md#快速部署) 开始，日常服务与账号操作见 [使用指南](../docs/usage.md)。以下维护命令均在对应组件的原安装目录运行。

Agent 不需要 `NET_ADMIN`、`/dev/net/tun`、转发 sysctl、iptables 或 iproute2。宿主机需允许 Agent 访问 Server 入网 API、控制端口、数据端口和本地应用端口。

默认监听：Server Web/API `8280`、Agent 控制 `9890`、Tunnel 数据 `9891`，TCP 自动分配公网端口范围 `20000-29999`。管理 API 可由前置 HTTPS 代理保护；`9890/9891` 使用设备证书双向 TLS，必须直连或 TCP 透传。Web Tunnel 的 `80/443` 交给 Caddy。

## 更新、备份与恢复

`latest` 是可移动的稳定版别名，不代表容器会自动更新。Server 和 Agent 独立发布，仅对发布说明列出的更新组件操作；需要配套更新时，先安排维护窗口，再按该版本说明处理两端。更新前记录正在运行的数字版本（管理页版本信息或容器镜像的 `org.opencontainers.image.version` 标签），保存原 Compose 和环境变量。

Server 更新命令：

```sh
docker compose -f compose.yml pull nexo-server
docker compose -f compose.yml up -d --no-deps nexo-server
docker compose -f compose.yml ps
docker compose -f compose.yml logs --tail=100 nexo-server
```

仅在 Agent 有更新时，在其主机的原目录执行：

```sh
docker compose -f compose.agent.yml pull nexo-agent
docker compose -f compose.agent.yml up -d --no-deps nexo-agent
docker compose -f compose.agent.yml logs --tail=100 nexo-agent
```

旧 Compose 若固定了数字版本，需手动将对应服务的 `image` 改为 `latest`。不要为更新重建身份目录，也不要运行新安装脚本覆盖旧配置。

### 备份与版本回退

备份前停止需要备份的组件，以获得一致的数据库和身份文件；这会中断该组件负责的转发。备份完成后用 `docker compose -f 对应配置文件 start 对应服务名` 恢复原容器。

| 组件 | 停止命令 | 需要一起备份 |
| --- | --- | --- |
| Server | `docker compose -f compose.yml stop nexo-server` | `compose.yml`、存在时的 `.env`、整个 `data/nexo` |
| Agent | `docker compose -f compose.agent.yml stop nexo-agent` | `compose.agent.yml`、`.env`、整个 `data/nexo-agent` |

Server 数据包含数据库、内部 CA、身份、Caddy 证书及域名凭据；Agent 数据包含私钥与证书。备份应存放在受限位置，保留文件权限，不能只备份数据库，也不要用清空证书缓存的方式排障。

回退时先核对目标版本的数据兼容说明，再把对应组件镜像改为更新前记录的数字版本。若数据结构不兼容，应在停止组件后恢复该版本的完整备份，再启动；先保留当前数据副本，不要直接覆盖或删除。v0.1.x 回退必须恢复原 v0.1.x 镜像、配置和数据，不能挂载新版目录。

## 常见问题

| 现象 | 优先检查 |
| --- | --- |
| 管理页无法访问 | 容器状态、8280 监听、可信来源防火墙规则；配置公网 HTTPS 后检查代理及请求协议 |
| Agent 一直等待或离线 | 入网凭证是否过期、是否已批准、Server URL 是否可达、9890/9891 是否直连或 TCP 透传 |
| TCP 服务无法访问 | Agent 能否访问本地目标、公网分配端口是否放行、访问地址是否误用了 HTTP 代理域名 |
| 域名解析正确但 HTTPS 不通 | Caddy 加载结果、证书错误、80/443 冲突、公网 DNS 与防火墙；解析正确不代表转发已通 |
| Caddy 监听失败 | 主机上其他反向代理是否已占用同一 IP 的 80/443；host 网络下不能靠 Compose ports 解决冲突 |
| 设备证书过期或私钥丢失 | 使用下方“设备身份恢复”，保留原 Agent 和服务绑定 |
| Server 报旧数据结构 | 使用新的空目录部署，不复制 v0.1.x 数据进入新版目录 |

日志仅在本地排查，分享前删除凭据、私钥和用户数据。Caddy Admin API `8290` 仅供本机使用，不要开放到公网。

## Tunnel 连接与持久身份

| 环境变量 | 默认值 | 用途 |
| --- | --- | --- |
| Server `NEXO_CONTROL_ADDR` | `0.0.0.0:9890` | 控制监听地址 |
| Server `NEXO_TUNNEL_ADDR` | `0.0.0.0:9891` | 数据监听地址 |
| Server `NEXO_TUNNEL_ENDPOINT` | 未设置 | 向 Agent 下发外部可达的数据地址，格式为 `主机:端口` |
| Server `NEXO_PUBLIC_BIND` | `0.0.0.0` | TCP 服务公网监听 IP，可指定 `::` 使用 IPv6 |
| Agent `NEXO_CONTROL_ENDPOINT` | Server URL 主机的 `9890` 端口 | 覆盖控制连接地址，格式为 `主机:端口` |
| Agent `NEXO_TUNNEL_ENDPOINT` | Server URL 主机的 `9891` 端口 | Server 未下发数据地址时使用的备用地址 |
| Agent `NEXO_STATE_DIR` | 镜像内 `/data/nexo-agent`；本机 `./data/nexo-agent` | 身份持久化目录 |

IPv6 地址使用 `[地址]:端口`。Compose 自定义变量需写入对应服务的 `environment`。Agent 的 `NEXO_SERVER_URL` 指向 Web/API；即使 API 使用 HTTPS 的 `443` 端口，控制与数据也仍使用各自端口。

页面中的 TCP 访问地址使用请求管理页时的主机名，管理页反向代理应保留原始 `Host`。若管理域名经过仅支持 HTTP 的代理，TCP 客户端需改用直达 Server 的 IP 或 DNS 名称。HTTP/HTTPS 地址使用服务绑定的域名，公网端口默认为 `80/443`。

Server 的 `transport/identity.json` 保存私有 CA 与服务端身份；Agent 的 `identity.json` 保存设备私钥和证书。首次入网使用 Token 提交 CSR，需在管理页批准；已保存身份后可清空 Token，重启自动恢复。更换 Server 时使用独立 Agent 目录。备份整个数据目录，避免仅恢复数据库而丢失 CA；不要复制同一 Agent 身份到多台主机。内部设备身份与 Caddy 公网证书相互独立。

内部设备证书有效期 365 天、服务端证书 825 天，均在到期前 30 天自动续签。设备经现有 mTLS 控制连接提交新的 CSR，私钥不离开 Agent；新证书先保存到磁盘，再确认替换。响应丢失会复用同一待签请求，安装确认丢失可由下一次 mTLS 连接补齐。续签保持设备 ID、服务绑定、配置版本及现有转发连接不变，新连接使用新证书。服务端使用原 CA 续签并热更新证书，无需重启监听器。

失败按 30 秒、1 分钟、2 分钟逐步退避，最长 1 小时；Agent 在心跳时检查重试，服务端每分钟检查。重试状态持久保存，重启继续；磁盘完全不可写时仍会在内存中重试并记录日志。Agent 列表提示临近到期、续签失败和已过期，详情显示有效期、错误原因和下次重试时间；服务端证书状态位于 Agent 页的“服务端身份”。这些提醒来自本地页面和日志，不发送外部通知。

内部 CA 有效期 10 年，在到期前 180 天提示维护，信任根更换仍需管理员安排。已过期的设备证书不会绕过 mTLS 校验；长期离线直到证书过期的设备可按下文“设备身份恢复”重新授权。Caddy 独立管理公网域名证书，内部身份续签不占用公网 ACME 配额。使用配套的新版 Server 与 Agent 才能完成内部续签。

公网 HTTPS 默认回源到 Agent 上的普通 HTTP 服务。修改目标、停用、删除服务会中断既有连接；客户端应自行重连。通道暂时中断时 Agent 自动重连，已断开的应用连接不会被续传。

## Caddy 配置

Server 镜像使用 Go 1.27.1 / xcaddy 0.4.7 构建 Caddy 2.11.4，包含 Cloudflare DNS 模块 0.2.4。Nexo 主程序仍为 Rust，Go 仅用于构建带此模块的 Caddy。Caddy 默认启用；直接运行 Rust 二进制时，需要自行安装 Caddy 或指定可执行文件路径。Caddy 启动失败不会阻止登录管理页，域名卡片会显示加载失败及原因。

| 环境变量 | 默认值 | 用途 |
| --- | --- | --- |
| `NEXO_CADDY_ENABLED` | `true` | 设置为 `false` 后不启动 Caddy，页面显示已停用 |
| `NEXO_CADDY_BIN` | 镜像内 `/usr/local/bin/caddy`；本机 `caddy` | Caddy 可执行文件 |
| `NEXO_CADDY_HTTP_LISTEN` | `:80` | Caddy HTTP 监听地址 |
| `NEXO_CADDY_HTTPS_LISTEN` | `:443` | Caddy HTTPS 监听地址 |
| `NEXO_CADDY_ADMIN_URL` | `http://127.0.0.1:8290` | 仅允许本机回环 IP，不向公网开放 |
| `NEXO_CLOUDFLARE_API_TOKEN` | 无 | 仅兼容已有管理员域名的旧 DNS-01 配置；新增域名在页面按域名设置凭据 |

建议在“域名与证书 → 证书配置”选择 Cloudflare DNS 验证并提交 Token，支持传统、`cfut_`、`cfat_` 格式。Token 应仅授权所需 Zone 的 Zone Read 和 DNS Edit。Server 通过创建并清理临时 `_nexo-verification` TXT 记录核对权限和归属，不修改 A/AAAA。每个域名的凭据独立存入 `${NEXO_DATA_DIR}/secrets/public-domains/<域名 ID>/credential-<随机 ID>.token`，Linux 目录 `0700`、文件 `0600`，不要直接编辑这些候选文件。

Caddy 使用文件占位读取凭据，Server 向 `/load` 发送 `Cache-Control: must-revalidate` 热更新，无需重启 Caddy。新文件不会覆盖 Applied 配置引用的旧凭据，失败后保留可恢复的旧配置。已有的 `cloudflare.token` 手工文件仍会转换为文件引用并热加载；全局环境变量仅兼容已有管理员域名，修改环境变量仍需重建 Server 容器，普通用户不会继承管理员的凭据。

DNS 高级设置按域名独立保存：最多 4 个 IPv4/IPv6 解析器（可附端口，默认 53），默认使用阿里云公共 DNS `223.5.5.5:53`、`223.6.6.6:53`，留空恢复此默认值，已有自定义解析器保持不变。传播等待 0–120 秒，传播超时 1–600 秒，留空使用 Caddy 默认值。这些选项只影响 DNS-01 证书验证，域名归属始终由 Server 的系统 DNS 检查。

选择 Cloudflare DNS 验证后，服务共用同级泛域名证书；多级子域名按直接父域复用，例如 `a.team.example.com` 与 `b.team.example.com` 共用 `*.team.example.com`，根域名另行管理。新域名需先验证并保存 Token 再切换 DNS 模式，避免无凭据时错误发起签发。新增同级服务不会增加证书申请。选择 HTTP 验证则按具体主机名签发。已有证书文件无需删除，续期与重试由 Caddy 管理。

Compose 使用 host 网络，新增环境变量应填入 `nexo-server.environment`，并确保宿主机 `80/443` 不被其他服务占用。新域名默认 HTTP-01，为具体主机名签发证书，公网 TCP 80、443 必须可达；仅修改监听地址不会改变 CA 的验证端口。泛域名只能使用 DNS-01；它可免除入站验证端口要求，用户访问 HTTPS 服务仍需能到达 Caddy。默认保留 Caddy 的 HTTP/1.1、HTTP/2、HTTP/3；HTTP/3 需另行开放宿主机/路由器/云防火墙的 UDP 443，并用真实外部 HTTP/3 客户端验证。普通 HTTPS 成功或 Alt-Svc 响应头不等于 HTTP/3 已可达。

持久化整个 `/data/nexo`：`caddy-storage` 保存 ACME 账号、证书和私钥，`caddy/applied.json` 保存最后成功加载的配置。不要通过清空证书目录来重试申请，以免重复签发触发 CA 限流。Server 不自行调度证书重试；错误、下次重试时间及到期时间来自 Caddy。管理页的运行记录按账号所属工作空间隔离，最多返回最近 100 条，凭据不会写入页面诊断。

## 账号、设备恢复与域名接入

### 管理入口与账号恢复

默认 Caddy 的 `80/443` 用于穿透服务；管理 API 位于 `8280`。前置 HTTPS 代理若与 Server 同机，应使用独立监听 IP，或将内置 Caddy 改为其他本机监听端口并配置服务域名回源。HTTP-01 的公网验证入口仍为 TCP 80。host 网络下不存在 Docker 端口映射层，不能仅添加 `ports` 来解决监听冲突。

公网部署时在 Server 的 `.env` 中配置 `NEXO_PUBLIC_URL=https://你的管理域名`，并将 `NEXO_TRUSTED_PROXIES` 设置为直连 Server 的反向代理 IP（多个地址用逗号分隔，不支持 CIDR）。代理必须覆盖写入 `X-Forwarded-Proto`，HTTPS 请求使用单值 `https`，同时保留原始 Host。例如同机代理可使用 `127.0.0.1`；请按实际连接地址填写，不要信任来源不受控的代理。

配置 HTTPS 管理地址后，不经可信代理的 API 请求会被拒绝；`/health` 仍供本机健康检查使用。HTTPS 登录 Cookie 带 `Secure`，写入检查 Origin 和 CSRF。未配置公网地址时保留局域网 HTTP 访问，管理页会提示当前连接未使用 HTTPS。Agent 的 `NEXO_SERVER_URL` 也应改为此 HTTPS 入口；控制和数据端口继续由 mTLS 保护。

认证请求按直连 IP 限制为每 5 分钟 20 次，登录账号每 5 分钟最多尝试 10 次；不采信 `X-Forwarded-For`，同一代理后的用户共享 IP 配额。限流状态保存在进程内，重启会重置；密码验证在独立线程执行，并限制同时最多 2 次，避免阻塞数据库与 Tunnel 管理。

忘记密码时，在 Server 主机运行：

```sh
docker compose exec nexo-server nexo admin recover
# 可明确指定唯一管理员的当前用户名
docker compose exec nexo-server nexo admin recover --username admin
```

命令只在终端显示一次恢复码，有效期 15 分钟。进入登录页的“忘记密码”，输入恢复码和新密码。重新生成撤销之前的恢复码；成功后旧密码与该账号的全部旧会话失效，业务数据保留。直接运行二进制时使用 `nexo-server admin recover`，并设置原数据目录的 `NEXO_DATA_DIR`。恢复码不能通过未登录的 HTTP 接口生成，也不要发到公开日志或工单。

### 设备身份恢复

证书已过期、私钥丢失或身份文件损坏时：

1. 在原 Agent 的详情页选择“恢复设备身份”，生成一小时有效的凭证。重新生成会撤销此前的恢复邀请；尚未批准的邀请可以在列表中撤销。
2. 在原 Agent 主机停止正常实例，保留原数据卷。将下方 `恢复凭证` 替换为页面显示的值，运行一次恢复命令：

```sh
docker compose -f compose.agent.yml stop nexo-agent
docker compose -f compose.agent.yml run --rm -e NEXO_ENROLLMENT_TOKEN=恢复凭证 nexo-agent --recover-identity
```

3. 保持命令运行，在 Agent 列表核对原设备并“批准恢复”。此时 Server 替换注册证书、清除旧续签材料、关闭旧控制和数据连接；原设备 ID、名称、服务绑定、公网端口和启停状态保留。
4. 命令成功退出后，正常启动 Agent：`docker compose -f compose.agent.yml up -d nexo-agent`。不需要重新创建服务。

恢复使用新私钥和 CSR，私钥不上传。批准前原身份仍有效；Agent 只在新证书验证并安全落盘后替换身份文件。网络或进程中断后可以用同一凭证再次运行恢复命令，复用 `recovery-key.json`，无需重复批准。如果原身份文件仍可读，Agent 会检查恢复目标与原设备一致。不要删除 Server 中的原设备，否则无法保留原 ID；不要同时运行恢复实例与正常实例。

直接运行 Agent 二进制时，设置原 `NEXO_STATE_DIR`、`NEXO_SERVER_URL` 及新的 `NEXO_ENROLLMENT_TOKEN`，执行 `nexo-agent --recover-identity`。恢复命令成功后退出；正常启动不带此参数。

### 域名接入与页面状态

Server 在新增域名或服务域名变化后自动检查一次，解析成功后停止自动查询。未解析或查询超时时，每 5 分钟重试一次，最多额外重试 3 次；解析地址与 Server 不一致只提示核对，不持续重试，避免误判 CDN 代理地址。后台每 5 秒扫描配置变化与到期重试，不会重新查询已有成功结果。检查状态只保存在进程内，Server 重启后会重新检查一次。

列表直接显示解析状态，点击状态可查看详细结果、下次重试时间、剩余次数及 A/AAAA 配置说明。自动重试耗尽后会提示核对配置；DNS 服务商侧的修改不会自动触发检查，需要确认时可选择“重新检查”。手动检查不会重置已用的自动重试次数，仍需登录、CSRF 校验并受限流保护。页面刷新只读取快照，不会重复发起 DNS 查询，检查结果不影响转发或 Caddy 运行。可选配置 `NEXO_PUBLIC_IPS=IPv4,IPv6`，用于展示预期地址并核对全部解析结果；没有可达 IPv6 时不要配置 AAAA。此功能只查询 DNS，不修改 DNS 记录。

检查使用 Server 的 DNS 解析器，不代表外网访问已通过。使用 Cloudflare 等 CDN 时，解析 IP 与 Server 不同可能是正常代理行为，还需核对回源设置。公网验收应使用移动网络等外部网络打开服务地址。Caddy 的加载、签发与失败状态仍独立展示。

服务、Agent、证书和会话列表在前台每 5 秒更新；后台或编辑时暂停，回到页面、网络恢复时重新检查。会话过期会要求重新登录，并保留当前页面的未提交表单；密码和草稿不写入浏览器持久存储。

## 本机集成验证

开发构建、账号恢复、Caddy、Tunnel 和身份续签验收统一见 [穿透验收](../docs/network-experience.md#本机集成验证)。本机测试结果不能代替公网 DNS、ACME 或防火墙验收。

## 多用户与热重载验收

具体命令、覆盖场景和验证边界见 [多用户与热重载验收](../docs/network-experience.md#多用户与热重载验收)。
