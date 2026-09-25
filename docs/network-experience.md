# Nexo v0.2.0 穿透验收

当前产品只覆盖 TCP、HTTP、HTTPS 三种内网穿透。验收以服务页、Agent 控制连接、公网域名和证书状态为中心，不依赖额外客户端或虚拟网卡。

## 场景

1. 使用空数据目录启动 Server，确认首次安装页可以创建本地管理员。
2. 创建 Agent 入网 Token，Agent 轮询批准状态后建立控制连接；Server 将 Agent 状态显示为在线。
3. 创建 TCP 服务，确认公网端口分配、启停、改绑和删除都能同步到 Agent。
4. 创建 HTTP/HTTPS 服务，确认最终地址、域名绑定、DNS 解析检查与 A/AAAA 配置说明和证书运行日志可见。
5. 重启 Server 或 Agent，确认心跳恢复，Tunnel Desired State 重新下发，旧连接在删除后终止。
6. 在桌面深色、移动浅色和移动横屏检查焦点返回、键盘操作、长地址换行、无横向溢出，以及减少动态/透明度设置。

## 数据目录兼容策略

v0.2.0 只接受 `product_metadata.generation=tunnel-only-v1` 的新基线。检测到任何旧结构时，Server 必须停止并提示使用空数据目录；旧目录不会转换或删除。

## 端口

管理入口 `8280`、Agent 控制 `9890`、Tunnel 数据 `9891`，TCP 公网端口默认使用 `20000-29999`。控制与数据通道原生使用 mTLS，前置代理必须 TCP 透传；管理入口可使用 HTTPS 反向代理，并限制来源。完整真实流量验收命令见下文。解析检查不会自动创建或同步 A/AAAA 记录，也不能代替真实外网访问。

## 本机集成验证

以下命令在仓库根目录执行；需要先安装 Rust、Node.js 和相应测试依赖。真实流量脚本需要可运行的 Server、Agent 与 Caddy 二进制。

### 恢复流程验收

Node 22+ 可直接运行真实 Server/Agent 验收，测试只使用独立目录和本机随机端口：

```sh
node docker/recovery-smoke.mjs --server-bin target/debug/nexo-server --agent-bin target/debug/nexo-agent --report .edge-screenshot/recovery-runtime/report.json
```

Windows 将二进制路径加上 `.exe`。验证账号恢复与旧会话撤销、恢复命令中断重试、设备身份替换和旧连接关闭、私钥丢失后恢复、服务绑定与真实 TCP 转发保留、HTTPS 代理识别、CSRF 和登录限流。测试日志与身份保留在 `.edge-screenshot/recovery-runtime/run-*` 中，只用于本地诊断，不可用作生产身份或公开发布。

### Caddy 与 Tunnel 验收

设置 `NEXO_TEST_CADDY_BIN` 指向 Caddy 二进制后运行：

```bash
cargo test -p nexo-server real_caddy_reuses_wildcards_and_keeps_last_good_config -- --ignored --nocapture
```

该测试使用随机回环端口和 `.localhost` 域名，验证真实配置加载、Caddy 内部 CA 签发、有效期读取、HTTPS 握手与失败配置保留；同时验证旧单域名证书切换到泛域名、同级及多级服务共用证书、新增同级服务不增加证书。测试不会安装系统根证书，也不会向公网 CA 申请证书；公网 ACME 与 Cloudflare DNS-01 还需使用自己的真实域名和受限凭据验证。

完整转发验收使用 Python 3.10+ 标准库，在独立临时目录运行真实 Server、Agent 和 Caddy：

```bash
cargo build -p nexo-server -p nexo-agent
python3 docker/tunnel-smoke.py \
  --server-bin target/debug/nexo-server \
  --agent-bin target/debug/nexo-agent \
  --caddy-bin /usr/local/bin/caddy
```

Windows 将二进制路径改为 `.exe`。脚本验证 TCP 大文件、并发与半关闭、HTTP/HTTPS、WebSocket、mTLS 拒绝无效身份、目标修改、启停删除、独立数据重连及进程重启恢复。Linux 同时覆盖实际 Unix socket 路径。临时目录保留日志与测试身份用于诊断，不可用于生产；可用 `--report 路径.json` 保存验收结果。

内部证书验收额外需要 Python `cryptography`，使用同样的三个二进制参数运行 `docker/identity-renewal-smoke.py`。它只修改独立临时目录中的测试证书，模拟进入续签时间、磁盘写入失败与恢复，并验证自动重试、证书热更新、身份和长连接保留；不修改系统时间，也不连接公网 CA。

## 多用户与热重载验收

管理页通过“用户管理”分享单次注册链接；账号隔离与启停说明见 [使用指南](usage.md#多用户分享)。服务端在原有 v0.2.0 数据库上增量添加用户邀请和域名配置，不替换已有数据。

用户管理采用单管理员模式。管理员可修改自己和普通用户的用户名；改名后目标账号的旧会话与恢复码失效，资源身份不变。管理员不可停用、删除或修改角色，邀请只创建普通用户。删除普通用户需输入当前用户名，将删除其整个工作空间并关闭转发；不会卸载远端 Agent 或删除实际应用文件。若提示公网配置和凭据清理正在重试，账号及转发已经撤销，Server 会在 Caddy 恢复后自动回收不再被运行配置及 Applied 文件引用的域名凭据，重启后仍会继续处理。

```sh
python docker/multiuser-smoke.py \
  --server-bin target/debug/nexo-server \
  --agent-bin target/debug/nexo-agent \
  --caddy-bin /usr/local/bin/caddy \
  --report /tmp/nexo-multiuser-report.json
```

该测试启动独立 Server、两个 Agent 和多个浏览器会话，覆盖跨空间拒绝、单次邀请、用户停用后的 TCP/WebSocket 断流与恢复、密码恢复隔离，以及 Caddy 重载时保留既有 WebSocket。测试仅在独立临时数据库中设置 `.localhost` 归属，不提供生产绕过验证的开关。安装 `aioquic` 后还会用内部 CA 校验证书，通过 UDP 实际请求 HTTP/3；未安装时明确跳过该项。此结果不能证明公网 UDP 443 可达。

```sh
NEXO_TEST_CADDY_BIN=/usr/local/bin/caddy cargo test -p nexo-server real_caddy -- --ignored --nocapture
```

包含相同 JSON 强制重载文件凭据、两种新版 Token 装配、无效候选配置保留旧 Applied 文件测试，不使用真实 Token、不访问 Cloudflare 或公网 CA。公网 DNS-01/HTTP-01 仍需在受控真实域名和 ACME staging 环境中单独验收。
