# 流量天眼

## 方案边界

参考 HP-Lite 的驾驶舱布局，不整体移植 HP-Lite。首页采用五项指标、实时吞吐、状态码分布、访客画像、来源排行、服务排行与请求流的组织方式，继续使用 Nexo 的主题、空间权限和服务模型。

天眼是访问与转发行为的只读统计，不替代原有流量额度账本。页面保留原有用量、配额和管理操作；不能用天眼统计反推可用额度。

## 已有能力

- 最近 60 秒 QPS、时段请求数、双向数据量、平均响应时长和运行时长。
- 实时、1 小时、24 小时、7 天、30 天和 90 天范围，协议、服务类型、HTTP 状态分组与用户/服务筛选。
- 请求、错误、延迟、TCP/UDP 会话趋势，以及服务、路径、域名、来源网段与国家/地区排行。
- 单服务详情、请求/会话游标翻页、暂停显示、返回最新、键盘选点与全屏。
- 采集覆盖、延迟、丢弃事件和缺失时段提示；图表不跨缺口连线，不把缺少延迟样本解释为零毫秒。

## 统计口径

- HTTP/HTTPS 事实来自 Caddy 的完成日志；WebSocket 在升级连接结束后计入，不代表首字节延迟。
- TCP/UDP 数据量按真实转发成功写入统计，会话明细在连接结束后产生。会话明细中的字节不再重复计入流量汇总。
- p50/p95 使用延迟桶上界，不是精确逐请求分位数。
- 访客按入口和北京时间自然日近似去重，长周期展示日去重数之和；共享出口可能低估，跨入口访问可能高估。
- 请求与会话明细保留 7 天，小时聚合保留 90 天；历史未采集数据不能补回。
- 来源只保存 IPv4 /24 或 IPv6 /48 网段；查询参数、原始 IP 和访客摘要不出现在请求明细接口中。统计队列不保存请求体、Cookie 或认证头。
- 地域与运营商来自本地数据库，可分别设置 `NEXO_GEOIP_DATABASE` 和 `NEXO_GEOIP_ASN_DATABASE`。未配置时显示未知，不调用外部 IP 查询服务。

## 本地验证

```powershell
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cd web
npm run build
npx playwright test tests/traffic-eye.spec.ts tests/home.spec.ts tests/home-design.spec.ts
```

浏览器配置包括桌面深色、手机浅色、手机横屏和移动 WebKit。接口 mock 的浏览器测试证明交互与布局，不代表真实转发链路验收。

真实 Caddy 日志采集可单独验证，不访问公网 CA：

```powershell
$env:NEXO_TEST_CADDY = "C:\path\to\caddy.exe"
cargo test -p nexo-server real_caddy_access_log_reaches_private_queue -- --ignored --test-threads=1 --nocapture
$env:NEXO_TEST_CADDY_BIN = $env:NEXO_TEST_CADDY
cargo test -p nexo-agent real_caddy_direct_range_upload_upgrade_authorization_and_revoke -- --ignored --test-threads=1 --nocapture
```

本轮另用独立临时目录验证了真实 Server + Agent + Caddy 的 HTTP 请求、未知主机排除、查询参数脱敏和 TCP 双向精确计数；UDP 则验证了零长度数据报、双向精确计数、活动会话、停用后的结束明细以及不重复累计会话字节。Agent 的真实 IPv6 回环直连测试验证了 HTTPS Range、1 MiB 上传、WebSocket、拒绝响应及内部探测排除均产生正确的脱敏采集结果。未部署线上服务。本地报告位于 `.edge-screenshot/traffic-eye-runtime/`，不作为线上部署证据。

### 隔离进程冒烟

旧脚本的假 Cloudflare 凭据会触发真实 DNS API，不能靠忽略就绪错误使测试通过。现在使用仅编译进 Rust 测试程序的 DNS Zone 替身和该夹具自行生成的 CA，仍执行真实入口探测、状态协调和转发。正式 Server 二进制没有 DNS 替身或测试 CA 环境变量入口；脚本未提供测试程序时会在写入假凭据之前明确报错。节点及普通 Agent 仍使用正常构建的二进制。测试不会安装系统信任，不使用生产数据库或公网 80/443 端口。

```powershell
cargo +1.89.0 build --workspace --locked
$artifacts = cargo +1.89.0 test -p nexo-server -p nexo-agent --no-run --locked --message-format=json | ForEach-Object { $_ | ConvertFrom-Json }
$serverTest = ($artifacts | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.target.name -eq 'nexo-server' } | Select-Object -Last 1).executable
$agentTest = ($artifacts | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.target.name -eq 'nexo-agent' } | Select-Object -Last 1).executable
python docker/tunnel-smoke.py --server-bin target/debug/nexo-server.exe --server-test-bin $serverTest --agent-bin target/debug/nexo-agent.exe --agent-test-bin $agentTest --caddy-bin $env:NEXO_TEST_CADDY_BIN --report .edge-screenshot/traffic-eye-runtime/tunnel-report.json
python docker/node-port-smoke.py --server-bin target/debug/nexo-server.exe --server-test-bin $serverTest --agent-bin target/debug/nexo-agent.exe --caddy-bin $env:NEXO_TEST_CADDY_BIN --http-port 18080 --https-port 18443 --report .edge-screenshot/traffic-eye-runtime/node-report.json
```

复用 Harness 的其他脚本也可通过 `NEXO_SMOKE_SERVER_TEST_BIN` 指定测试程序。Windows 运行冒烟期间不要重新链接同一个测试程序，应先等测试结束或复制到隔离目录后运行。

- 完整穿透覆盖真实 HTTPS、HTTP、TCP、WebSocket、额度拦截、断线重连、协议切换、身份校验和离线备份恢复；同时核对天眼精确字节、脱敏、事实/小时聚合及隐私密钥持久化。
- 独立节点覆盖真实节点进程、mTLS/Yamux、HTTP/HTTPS 日志回传、8 MiB 响应字节、节点归属、内部探测排除和查询脱敏。回环节点不等于公网 VPS 验收。
- 可选的 `--agent-test-bin` 将真实 Agent Caddy IPv6 回环采集事实映射到隔离服务，通过生产 mTLS/Yamux 客户端送达控制器，断开后重放同一批次并验证去重、非直连服务拒收和双向字节一致。入口访问授权在该 Agent 测试中仍为本地 RPC 夹具；它不证明公网 IPv6 地址发现、AAAA 发布、外网连通或真实客户端授权的完整链路。

### 真实 MMDB 验收

使用 MaxMind 官方 [MaxMind-DB 测试库](https://github.com/maxmind/MaxMind-DB/tree/main/test-data) 中的 `GeoIP2-Country-Test.mmdb` 和 `GeoLite2-ASN-Test.mmdb`，不要用这些稀疏测试库作为生产地域数据库；测试库不随 Nexo 分发。

```powershell
$env:NEXO_GEOIP_DATABASE = 'C:\path\to\GeoIP2-Country-Test.mmdb'
$env:NEXO_GEOIP_ASN_DATABASE = 'C:\path\to\GeoLite2-ASN-Test.mmdb'
cargo +1.89.0 test -p nexo-core real_mmdb_classification_and_unavailable_database_fallback --locked -- --ignored --nocapture
Remove-Item Env:NEXO_GEOIP_DATABASE, Env:NEXO_GEOIP_ASN_DATABASE
```

此测试读取真实二进制库，覆盖 IPv4、IPv6、IPv4-mapped IPv6、中文国家名、ASN 组织和未命中地址，并通过隔离子进程验证未配置、文件缺失及文件损坏时显示未知。它验证本地解码与脱敏，不验证商业地域库的现实准确性或更新质量。

### 2026-10-25 本机验收记录

- Rust 1.89.0 工作区：305 项通过、16 项按需忽略；格式检查、Clippy `-D warnings`、非测试二进制构建通过。真实 Caddy 采集、反代生命周期及真实 MMDB 测试另行执行通过。
- 全量 Playwright 四项目矩阵：1185 项通过、183 项条件跳过、零失败；不是只重跑首页用例。构建随矩阵启动执行通过。
- 完整穿透冒烟：23 项通过，包含 IPv6 回环事实跨进程上报、重连重放与天眼离线恢复；独立节点冒烟：6 项通过。
- `docker/udp-smoke.py --idle`：19 项通过，含 1024 会话、阻断/丢包恢复、精确额度与 1/5/15 分钟真实空闲、过期后内网推送边界及客户端恢复。报告为 `udp-idle-report.json`，不等同于真实 RDP 客户端验收。
- 当时的本机报告与日志位于 `.edge-screenshot/traffic-eye-runtime/`，浏览器最终状态位于 `.edge-screenshot/traffic-eye-complete/.last-run.json`；该轮未提交、发布或部署线上。后续发布见 [v0.2.24 发布说明](releases/v0.2.24.md)，历史测试产物可能已按清理规范移除。

### 仍需外部环境验收

尚未部署线上服务。公网 IPv6 地址发现与 AAAA/DNS 发布、外网客户端访问、真实 VPS 跨公网丢包重连及生产数据库升级未在本机回环测试中验收；真实 RDP 会话也未验收。IPv6 入口测试中的访问授权仍为夹具，不能把统计上传通过解释为完整公网认证链路已验收。
