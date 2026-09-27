# 容器、配置与维护

本次发布 Server 与 Agent v0.2.8，包含 v0.2.7 未完成发布的 Agent 部署修复。已有 v0.2.5 / v0.2.6 / v0.2.7 数据和身份可继续使用，Server 自动补充强制 HTTPS 配置字段，已有反向代理默认保持关闭；从 v0.2.4 及更早版本安装仍要求两端使用全新目录，不导入旧数据库或旧身份。当前格式的数据读取失败时停止启动并保留文件。正常重启、身份恢复、续签和备份恢复继续支持。

本仓库模板配合 v0.2.8 镜像使用；相对上一正式版两端均有代码变化，不自动部署 VPS。更新步骤见 [v0.2.8 发布说明](../docs/releases/v0.2.8.md)。

## 部署与首次启动

Server 使用仓库根目录的 [compose.yml](../compose.yml)，Agent 使用 [compose.agent.yml](../compose.agent.yml)。保留 host 网络、端口清单及原挂载路径；host 下 `ports` 不提供映射，实际端口由应用和宿主机防火墙控制。

Server 首次启动自动生成 `./data/nexo/server.toml`（容器内 `/data/nexo/server.toml`），默认 `0.0.0.0:8280` 提供首页、静态资源和 API，Caddy 默认启用。默认用户名 `admin`，密码留空生成随机密码，首次日志显示一次。指定密码可预置 TOML，或向容器传入 `NEXO_ADMIN_USERNAME` / `NEXO_ADMIN_PASSWORD`；密码至少 6 个字符、不超过 1024 字节。非空环境变量逐项优先于 TOML，未设置或为空时回退到 TOML，密码中的空格保留。环境变量不会回写配置文件；初始化后清除 TOML、Compose 或 `.env` 中的初始密码。数据库仅保存密码哈希。

仓库 Compose 已映射这两个可选变量，可通过宿主机环境或同目录 `.env` 传入；自定义 Compose 也须在 `environment` 中传入容器，仅创建 `.env` 不会自动注入。此支持从 Server v0.2.6 开始提供。已有账号不会因更改环境变量、TOML 或重启而重设密码；需要重设时使用下方的账号恢复流程。

账号初始化信息写入容器日志，执行 `docker compose logs nexo-server` 查看；`docker compose up -d` 只负责后台启动，不显示应用日志。首次创建且环境变量、TOML 密码均为空时，日志显示用户名与随机密码。指定密码时只显示用户名和“使用指定密码”；已有账号时明确显示“已有账号，跳过管理员初始化”及恢复入口，不再打印密码。

Agent 操作顺序：

1. 在页面“添加 Agent”填写 Server 地址及设备名称，选择 Compose 或 docker run。
2. Compose 直接复制 YAML 到 NAS 的 Compose 项目，或保存为 `compose.agent.yml` 后执行 `docker compose -f compose.agent.yml up -d`；docker run 直接复制单条命令到终端执行。两种方式均内嵌连接环境变量，无需预先保存 TOML。
3. 回到页面查看“最近接入”。配置含接入密钥，且 Docker 管理员可通过容器信息查看，请勿分享；每台主机使用独立数据目录。已有 Agent 保留原目录和身份。
4. 接入后可清空环境变量 `NEXO_ENROLLMENT_TOKEN` 或 TOML 中的 `enrollment_token`；保留 Server 地址，正常重启复用身份，无需重新接入。

新 Agent 没有 TOML 时会生成权限为 `0600` 的模板，再读取连接环境变量；两者均未提供必要配置时明确退出。环境变量不回写模板。共享接入密钥可用于多台设备；重置密钥不撤销已接入设备。缺少或损坏身份不能通过复制其他设备目录解决。

## 启动配置

两端统一支持 `--config`、`--data-dir`。默认读取数据目录中的对应 TOML。相对文件路径按 TOML 所在目录解析；配置只在启动读取，修改后重启。未知字段、类型错误和非法地址报错，程序不覆盖已有配置或修改排版。自动创建的 Linux TOML 权限为 `0600`。

完整中文模板：[server.toml](../config/server.toml)、[agent.toml](../config/agent.toml)。Server 首次创建管理员读取 `NEXO_ADMIN_USERNAME` / `NEXO_ADMIN_PASSWORD`；Agent 读取 `NEXO_SERVER_URL` / `NEXO_ENROLLMENT_TOKEN` / `NEXO_DEVICE_NAME`。非空值逐项覆盖 TOML，空值回退到 TOML，均不回写文件。显式身份恢复的命令行凭证优先于环境变量。其他 `NEXO_*` 启动环境变量不生效，`TZ` 等通用系统变量保留。

| Server 字段 | 默认值 / 用途 |
| --- | --- |
| `http_addr` | `0.0.0.0:8280`，网页与 API |
| `control_addr` | `0.0.0.0:9890`，mTLS 控制 |
| `tunnel_addr` / `udp_addr` | `0.0.0.0:9891`，TCP / QUIC 数据 |
| `tunnel_endpoint` / `udp_endpoint` | 可选外部地址 `主机:端口`；IPv6 使用方括号 |
| `public_bind` | `0.0.0.0`，服务公网监听 IP |
| `runtime_dir` | `/run/nexo`，Linux 运行目录 |
| `web_dir` | 留空使用程序旁 `web`，开发环境使用工作目录 `web/dist` |
| `admin.username` / `admin.password` | 仅用于首次初始化 |
| `caddy.enabled` / `caddy.binary` | `true` / PATH 中的 `caddy`；带目录路径按 TOML 解析 |
| `caddy.admin_url` | `http://127.0.0.1:8290`，只允许本机回环 IP |
| `caddy.http_listen` / `caddy.https_listen` | `:80` / `:443` |

Agent 的 `server_url` 是 HTTP/HTTPS API 地址；控制与数据始终使用各自的 mTLS/QUIC 端口。`control_endpoint` 默认 Server URL 主机的 9890，`tunnel_endpoint` 默认该主机的 9891；`udp_endpoint` 留空使用 Agent 数据备用地址。Server 下发的明确地址优先。`device_name` 默认 Nexo Agent，`enrollment_token` 仅首次接入使用。

## 存储、Socket 与备份恢复

| 内容 | 位置 |
| --- | --- |
| 启动参数 | 数据目录 `server.toml` / `agent.toml` |
| 页面设置、用户、服务和流量 | Server `nexo.db` |
| CA、Server 身份 | Server `transport/identity.json` |
| Agent 私钥和证书 | Agent `identity.json` |
| 接入密钥解密材料、域名凭据 | Server `secrets/` |
| Caddy 最后成功配置 | Server `caddy/applied.json` |
| 公网证书、ACME 账号和私钥 | Server `caddy-storage/` |
| 临时 Web Tunnel Socket | `/run/nexo/tunnel-sockets/<服务ID>.sock` |

Linux 保留 Unix Socket，程序自动创建运行目录，目录权限 `0700`、Socket `0600`，拒绝覆盖普通文件或符号链接。非 root 或多实例部署必须设置各自独占、可写的 `runtime_dir`。默认使用容器内部的 `/run/nexo`，无需额外挂载；停用、删除及正常退出清理本实例 Socket，重新监听时处理遗留节点，容器重建后根据数据库重新监听。Caddy 沿用启动恢复流程，在当前监听器准备好后应用路由。Windows 继续用本机随机 TCP 端口。

tmpfs 是可选部署项，并非运行依赖。只读容器根文件系统需要为 `runtime_dir` 提供可写位置，例如在 Server 服务中设置 `tmpfs: ["/run/nexo:mode=0700"]`。Unix Socket 的传输数据由内核处理，不会作为 Socket 文件内容写入磁盘；使用 tmpfs 不代表转发吞吐提升。

备份前停止对应组件，完整复制 `./data/nexo` 或 `./data/nexo-agent`；不要只复制 SQLite。恢复时把完整备份放入空目录，使用同一版本和对应挂载启动。Socket 运行目录不备份；证书、凭据、身份和 Caddy Applied 文件必须保留。不要将同一 Agent 身份同时恢复到多台设备。

恢复后检查账号登录、服务转发、共享密钥解密、Agent 身份及证书是否保持。跨主机恢复需检查 TOML 中的绝对路径、对外连接地址及管理页面保存的代理 IP。此处没有在线备份、定时备份或云同步功能。

## Caddy 与域名凭据

建议在“域名与证书 → 证书配置”选择 Cloudflare DNS 验证并提交 Token，支持传统、`cfut_`、`cfat_` 格式。Token 应仅授权所需 Zone 的 Zone Read 和 DNS Edit。Server 通过创建并清理临时 `_nexo-verification` TXT 记录核对权限和归属，不修改 A/AAAA。每个域名的凭据独立存入 `<数据目录>/secrets/public-domains/<域名 ID>/credential-<随机 ID>.token`，Linux 目录 `0700`、文件 `0600`，不要直接编辑这些候选文件。

Caddy 使用文件占位读取凭据，Server 向 `/load` 发送 `Cache-Control: must-revalidate` 热更新，无需重启 Caddy。新文件不会覆盖 Applied 配置引用的旧凭据，失败后保留可恢复的旧配置。

DNS 高级设置按域名独立保存：最多 4 个 IPv4/IPv6 解析器（可附端口，默认 53），默认使用阿里云公共 DNS `223.5.5.5:53`、`223.6.6.6:53`，留空恢复此默认值，已有自定义解析器保持不变。传播等待 0–120 秒，传播超时 1–600 秒，留空使用 Caddy 默认值。这些选项只影响 DNS-01 证书验证，域名归属始终由 Server 的系统 DNS 检查。

选择 Cloudflare DNS 验证后，服务共用同级泛域名证书；多级子域名按直接父域复用，例如 `a.team.example.com` 与 `b.team.example.com` 共用 `*.team.example.com`，根域名另行管理。新域名需先验证并保存 Token 再切换 DNS 模式，避免无凭据时错误发起签发。新增同级服务不会增加证书申请。选择 HTTP 验证则按具体主机名签发。已有证书文件无需删除，续期与重试由 Caddy 管理。

Compose 使用 host 网络，启动参数填写在 `server.toml`，并确保宿主机 `80/443` 不被其他服务占用。新域名默认 HTTP-01，为具体主机名签发证书，公网 TCP 80、443 必须可达；仅修改监听地址不会改变 CA 的验证端口。泛域名只能使用 DNS-01；它可免除入站验证端口要求，用户访问 HTTPS 服务仍需能到达 Caddy。默认保留 Caddy 的 HTTP/1.1、HTTP/2、HTTP/3；HTTP/3 需另行开放宿主机/路由器/云防火墙的 UDP 443，并用真实外部 HTTP/3 客户端验证。普通 HTTPS 成功或 Alt-Svc 响应头不等于 HTTP/3 已可达。

持久化整个 `/data/nexo`：`caddy-storage` 保存 ACME 账号、证书和私钥，`caddy/applied.json` 保存最后成功加载的配置。不要通过清空证书目录来重试申请，以免重复签发触发 CA 限流。Server 不自行调度证书重试；错误、下次重试时间及到期时间来自 Caddy。管理页的运行记录按账号所属工作空间隔离，最多返回最近 100 条，凭据不会写入页面诊断。

## 账号、设备恢复与域名接入

### 管理入口与账号恢复

默认 Caddy 的 `80/443` 同时承载服务和 HTTPS 管理入口，管理 API 默认位于 `8280`。无需再为管理页面创建反向代理服务；Caddy 与其他程序不能同时监听同一地址的 `80/443`。

管理员登录后，打开“账号设置 → 管理员功能 → 服务器设置”（手机端从“我的”进入）：

1. 先在域名管理验证自己空间的域名并开启 HTTPS。HTTP 验证要求公网 TCP 80、443 可达；Cloudflare DNS 验证沿用已配置的凭据和泛域名证书。
2. 在当前 `http://IP:8280` 入口开启“HTTPS 管理入口”，选择域名、填写子域名（默认 `nexo`）并保存。系统自动配置本机回源与代理信任，无需填写可信代理 IP，也无需先切换到 HTTPS。
3. 将管理子域名的 A/AAAA 解析指向服务器；DNS 证书验证不会自动创建访问解析记录。等待页面显示“已配置”后，通过“打开管理入口”访问。

管理域名启用“强制 HTTPS”：HTTP 请求通过 307 跳转至 HTTPS，保留方法、路径和查询参数，不缓存跳转。ACME 验证请求仍由 Caddy 处理。原 `http://IP:8280` 继续可用，可用于证书或代理异常时修正配置；该连接仍是明文，应限制公网可达范围。HTTPS 登录 Cookie 带 `Secure`，写入继续检查 Origin 和 CSRF。

设置保存到 `nexo.db`，重启后保留。路由加载、证书签发和访问解析有各自的状态；“已配置”不代表公网网络已验证。失败显示原因并自动重试，不需要清空证书目录。更换域名直接修改并保存；关闭管理入口只撤销专用路由和重定向，不删除共享域名、证书或其他服务。被引用的域名须先解除管理入口绑定才能删除。

“公网 IP 校验（可选）”只核对域名 A/AAAA 解析结果，留空不核对指向，不修改 DNS 或监听地址。服务器设置作用于整个平台，域名选择属于登录管理员自己的空间，不随代管空间切换。旧手工代理配置升级后保留原安全规则，直到管理员显式保存新的内置 Caddy 设置。

新增 HTTPS 反向代理默认开启“强制 HTTPS”，可在编辑服务时关闭。此选项只影响对外访问，与目标回源协议无关；对外切换为 HTTP 时不生效，切回 HTTPS 时保留原选择。已有反向代理保持原行为，不会因升级自动开启。关闭开关后不会额外提供明文代理。Agent 的 `server_url` 建议使用 HTTPS 管理入口；控制和数据端口继续由 mTLS 保护。

认证请求按直连 IP 限制为每 5 分钟 20 次，登录账号每 5 分钟最多尝试 10 次；不采信 `X-Forwarded-For`，同一代理后的用户共享 IP 配额。限流状态保存在进程内，重启会重置；密码验证在独立线程执行，并限制同时最多 2 次，避免阻塞数据库与 Tunnel 管理。

忘记密码时，在 Server 主机运行：

```sh
docker compose exec nexo-server nexo --data-dir /data/nexo admin recover
# 可明确指定唯一管理员的当前用户名
docker compose exec nexo-server nexo --data-dir /data/nexo admin recover --username admin
```

命令只在终端显示一次恢复码，有效期 15 分钟。进入登录页的“忘记密码”，输入恢复码和新密码。重新生成撤销之前的恢复码；成功后旧密码与该账号的全部旧会话失效，业务数据保留。直接运行二进制时使用 `nexo-server admin recover`，并用 `--data-dir` 指定原数据目录。恢复码不能通过未登录的 HTTP 接口生成，也不要发到公开日志或工单。

### 设备身份恢复

证书已过期、私钥丢失或身份文件损坏时：

1. 在原 Agent 的详情页选择“恢复设备身份”，生成一小时有效的凭证。重新生成会撤销此前的恢复邀请；尚未批准的邀请可以在列表中撤销。
2. 在原 Agent 主机停止正常实例，保留原数据卷。将下方 `恢复凭证` 替换为页面显示的值，运行一次恢复命令：

```sh
docker compose -f compose.agent.yml stop nexo-agent
docker compose -f compose.agent.yml run --rm nexo-agent --recover-identity --enrollment-token 恢复凭证
```

3. 保持命令运行，在 Agent 列表核对原设备并“批准恢复”。此时 Server 替换注册证书、清除旧续签材料、关闭旧控制和数据连接；原设备 ID、名称、服务绑定、公网端口和启停状态保留。
4. 命令成功退出后，正常启动 Agent：`docker compose -f compose.agent.yml up -d nexo-agent`。不需要重新创建服务。

恢复使用新私钥和 CSR，私钥不上传。批准前原身份仍有效；Agent 只在新证书验证并安全落盘后替换身份文件。网络或进程中断后可以用同一凭证再次运行恢复命令，复用 `recovery-key.json`，无需重复批准。如果原身份文件仍可读，Agent 会检查恢复目标与原设备一致。不要删除 Server 中的原设备，否则无法保留原 ID；不要同时运行恢复实例与正常实例。

直接运行时使用 `nexo-agent --data-dir ./data/nexo-agent --recover-identity --enrollment-token 恢复凭证`。保持原数据目录及 `agent.toml` 中的 Server 地址；恢复成功后退出，普通启动不带恢复参数。

### 域名接入与页面状态

Server 在新增域名或服务域名变化后自动检查一次，解析成功后停止自动查询。未解析或查询超时时，每 5 分钟重试一次，最多额外重试 3 次；解析地址与 Server 不一致只提示核对，不持续重试，避免误判 CDN 代理地址。后台每 5 秒扫描配置变化与到期重试，不会重新查询已有成功结果。检查状态只保存在进程内，Server 重启后会重新检查一次。

列表直接显示解析状态，点击状态可查看详细结果、下次重试时间、剩余次数及 A/AAAA 配置说明。自动重试耗尽后会提示核对配置；DNS 服务商侧的修改不会自动触发检查，需要确认时可选择“重新检查”。手动检查不会重置已用的自动重试次数，仍需登录、CSRF 校验并受限流保护。页面刷新只读取快照，不会重复发起 DNS 查询，检查结果不影响转发或 Caddy 运行。可选在“服务器设置 → 公网 IP”中填写 IPv4、IPv6，用于展示预期地址并核对全部解析结果；没有可达 IPv6 时不要配置 AAAA。此功能只查询 DNS，不修改 DNS 记录。

检查使用 Server 的 DNS 解析器，不代表外网访问已通过。使用 Cloudflare 等 CDN 时，解析 IP 与 Server 不同可能是正常代理行为，还需核对回源设置。公网验收应使用移动网络等外部网络打开服务地址。Caddy 的加载、签发与失败状态仍独立展示。

服务、Agent、证书和会话列表在前台每 5 秒更新；后台或编辑时暂停，回到页面、网络恢复时重新检查。会话过期会要求重新登录，并保留当前页面的未提交表单；密码和草稿不写入浏览器持久存储。

## 本机集成验证

开发构建、账号恢复、Caddy、Tunnel 和身份续签验收统一见 [穿透验收](../docs/network-experience.md#本机集成验证)。本机测试结果不能代替公网 DNS、ACME 或防火墙验收。

## 多用户与热重载验收

具体命令、覆盖场景和验证边界见 [多用户与热重载验收](../docs/network-experience.md#多用户与热重载验收)。

共享密钥本地验收（无需 Docker/Caddy）：`python docker/shared-access-smoke.py --server-bin target/debug/nexo-server.exe --agent-bin target/debug/nexo-agent.exe`。验证多设备独立身份、TCP 转发、密钥重置、删除防重放和进程重启。
