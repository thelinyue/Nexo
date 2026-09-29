# Nexo / frp TCP 与 HTTPS 对照测量

**本次最终范围为 72 轮日常场景：正常本地链路、TCP 与 HTTPS 域名入口、1/8 并发、大文件与混合负载，每组重复 3 次，比较直连/Nexo/frp。** 采用修正后的 64 MiB 对象重新执行全部 72 轮，不复用此前 1 MiB 数据。正式数据与报告在 `target/frp-performance/daily/`。

## 实测结果

**72/72 轮完成，24 个组各 3 次，无请求错误，24 轮 Nexo 额度校验全部通过。** HTTPS 主矩阵实际协商 HTTP/1.1；本次未展开 HTTP/2、弱网和新连接握手性能对比。专属进程及 namespace 已清理。

环境为 AMD Ryzen 5 7500F、WSL2 Linux 6.18.33.2、12 个逻辑 CPU；frp 0.71.0、Caddy 2.11.4、Go 1.25.1。以下为三次中位数，吞吐单位 MiB/s；mixed 的并发 N 表示 N 个下载加 N 个短请求。

| 场景 | 并发 | 直连吞吐 | Nexo 吞吐 | frp 吞吐 | Nexo 短请求 p95 ms | frp 短请求 p95 ms |
|---|---:|---:|---:|---:|---:|---:|
| TCP 大文件 | 1 | 891.07 | 203.75 | 289.97 | — | — |
| TCP 大文件 | 8 | 6552.14 | 237.99 | 373.34 | — | — |
| TCP 混合 | 1 | 1061.36 | 215.64 | 247.76 | 1.75 | 0.61 |
| TCP 混合 | 8 | 6313.55 | 231.94 | 274.75 | 53.77 | 3.25 |
| HTTPS 域名大文件 | 1 | 414.46 | 258.39 | 299.43 | — | — |
| HTTPS 域名大文件 | 8 | 3886.33 | 368.77 | 376.35 | — | — |
| HTTPS 域名混合 | 1 | 528.55 | 252.37 | 263.88 | 1.73 | 1.08 |
| HTTPS 域名混合 | 8 | 3617.84 | 401.89 | 445.30 | 17.59 | 7.83 |

本地单并发大文件中，Nexo TCP 吞吐比 frp 低约 30%，HTTPS 低约 14%，三轮区间不重叠。8 并发的结论需要更谨慎：Nexo TCP 大文件为 228.98–479.43 MiB/s，HTTPS 为 282.50–489.60 MiB/s，均与 frp 区间重叠；不能把中位数差距解释为稳定的性能比例。

更值得后续定位的是混合负载响应延迟：Nexo 8 并发 TCP 短请求 p95 为 12.07–75.94 ms，frp 为 2.81–3.90 ms；HTTPS 分别为 16.48–26.21 与 7.57–8.11 ms。这证明本夹具下存在响应延迟差距，但尚不能确定是复用调度、TCP 行为、额度热路径还是其他原因。

8 并发大文件的产品 CPU 秒/GiB：TCP 为 Nexo 12.69、frp 8.00；HTTPS 为 Nexo 7.78、frp 10.34。进程峰值 RSS 之和分别为 TCP 55.63/44.57 MiB、HTTPS 71.63/110.04 MiB。资源排序随场景变化，且 TCP 的 Nexo 额外包含空闲 Caddy，不能据此宣称某一产品总是更省资源。

网络未主动注入丢包，但高负载仍观察到大量 TCP 重传，尤其直连 8 并发。计数覆盖 namespace 内所有 TCP，并非单条隧道。直连吞吐有明显余量，但直连混合 HTTPS 本身 p95 约 10.95 ms，说明负载端、源站和宿主调度也参与结果；本次不把它当成产品极限或真实互联网体验。三次重复只提供范围，不提供统计显著性结论。

后续优化建议限定为：优先针对混合负载尾延迟做剖析，再逐项验证缓冲或 TCP 参数；当前数据不足以支持更换协议、取消额度锁或调整生产参数。本次不追加测量。

完整范围、各轮原始数据和统计在 `target/frp-performance/daily/REPORT.md`、`NNNN.json.gz` 与 `summary.json`。`source/` 保存测量脚本、构建时 Git HEAD 和已跟踪文件 diff（并非包含全部未跟踪产品文件的完整源码归档）；`binaries/` 保存实际测试程序，`lscpu.json` 保存 CPU 信息。复现实验可直接使用归档二进制和脚本。测试期间二进制未替换，后续工作区变化不代表已由本次测试覆盖。

## 实现与测试口径

本次只新增本地测量工具，不修改 Server/Agent/Web 的产品行为，不发布、不接触线上 VPS/NAS。Nexo 使用当前工作区 release 构建；frp 固定官方 v0.71.0；Caddy 与 Nexo 使用同一二进制。本次保留已有混合工作区中的其他改动。

| 拓扑 | 直连 | Nexo | frp |
|---|---|---|---|
| TCP | 测试端 → 源站 | TCP 隧道 | TCP 代理 |
| HTTPS 透传 | 测试端 → TLS 源站 | TCP 隧道透传 TLS | TCP 代理透传 TLS |
| HTTPS 域名入口 | Caddy → HTTP 源站 | Nexo 管理的 Caddy → 隧道 → HTTP 源站 | 同配置 Caddy → frp TCP 代理 → HTTP 源站 |

域名入口的直连/frp Caddy 配置复用真实 Nexo 生成的通用 TLS/反代设置，更换监听、存储及业务回源地址，并移除只有 Nexo 控制面才提供的内部访问检查。Nexo 组保留真实访问检查（公开服务也经过该检查），因此此组比较实际产品入口，不是纯隧道性能。frp/直连不会额外启动 Nexo 来冒充等价配置。不把 frp 原生 SNI 转发与 TLS 终止混为一谈。TLS 入口使用同一临时 CA/证书，客户端验证证书并固定 TLS 1.3；错误 CA 必须被拒绝。内部证书有效期为 72 小时，以覆盖完整矩阵；隔离网络没有公网路由。

frp 使用 TCP、双向证书验证、TCP 多路复用、poolCount=0，禁用压缩和额外业务加密。Nexo 保留认证、精确额度计数、原有缓冲、15 秒心跳与 45 秒超时。因此比较完整产品行为，不把差距直接归因于语言或复用协议。

## 可复现工具

- `docker/performance-frp.py`：namespace/veth、进程生命周期、证书及真实 Nexo/Caddy/frp 夹具、逐轮采样、恢复验收和断点续跑。
- `docker/performance-load.go`：同一 Go 源站/客户端，持续 TCP、HTTPS HTTP/1.1、单连接 HTTP/2；逐块校验内容，采集连接/TLS/TTFB/完整响应计时。
- `docker/performance-report.py`：从逐轮压缩 JSON 生成中文 Markdown 和完整分组 JSON。未完成、请求失败、协议/会话恢复验收失败不会显示成全部通过。

Linux 需要 root、iproute2、ethtool、OpenSSL、Python 3，以及编译负载工具用的 Go 1.25.1 或兼容版本。namespace 由脚本创建，只有 veth 对和 loopback；不修改宿主路由。MTU 1500，关闭 TSO/GSO/GRO，避免大包卸载改变 netem 丢包粒度。

每轮 SQLite、身份与进程日志写入 Linux 原生临时目录，停止进程后再复制到结果目录，避免 WSL 的 `/mnt/d` 文件访问放大产品间的 I/O 差异。本次 `/tmp` 为 tmpfs，数据库资源结果不代表生产磁盘 I/O。归档配置中的临时绝对路径用于审计，复现应运行夹具重新生成配置。

```sh
# 在工作区根目录构建当前代码；只写构建产物。
cargo build --release --locked -p nexo-server -p nexo-agent
go test docker/performance-load.go docker/performance-load_test.go
go build -o /tmp/performance-load docker/performance-load.go
python3 docker/test-performance.py

# 从官方 Release 取得固定版本，解压到独立测试目录。
curl -fL https://github.com/fatedier/frp/releases/download/v0.71.0/frp_0.71.0_linux_amd64.tar.gz -o /tmp/frp.tar.gz
tar -xzf /tmp/frp.tar.gz -C /tmp

# Caddy 应为项目支持的含 DNS 模块版本。以下路径替换为实际二进制。
sudo python3 docker/performance-frp.py \
  --server-bin "$PWD/target/release/nexo-server" \
  --agent-bin "$PWD/target/release/nexo-agent" \
  --caddy-bin /path/to/caddy \
  --frps-bin /tmp/frp_0.71.0_linux_amd64/frps \
  --frpc-bin /tmp/frp_0.71.0_linux_amd64/frpc \
  --load-bin /tmp/performance-load \
  --output "$PWD/target/frp-performance/daily"

python3 docker/performance-report.py target/frp-performance/daily \
  --report target/frp-performance/daily/REPORT.md
```

同一参数和输出目录可跳过已完成轮次；不同矩阵、时长或二进制路径要求新目录，避免把两次实验混在一起。保留所用二进制，不在运行途中替换。逐轮写入先用临时文件，再原子替换，避免中断留下半份 JSON。

## 矩阵与指标

默认矩阵为 TCP/HTTPS 域名入口 × 正常本地网络 × 1/8 并发 × bulk/mixed × 三次重复 × 直连/Nexo/frp，共 **72 轮**。纯预热与测量为 24 分钟，另加启动和验收。此前 1 MiB 对象会放大每次请求开销，已归档为诊断数据；本次 64 MiB 全部重测。

工具仍支持正常不限速，以及 100 Mbps 下的正常、附加 RTT 50/100 ms、丢包 0.1%/1%。后五种不进入本次最终性能对比；100 ms RTT 和 1% 丢包只用于先前的短时夹具验收。限速/延迟/丢包施加在 veth 两端出口，两个方向各承担一半 RTT；延迟与丢包不交叉。控制链路也经过这条模拟跨端链路。重传采样记录两个 namespace 的 TCP 重传，包含少量控制和本地连接，不能冒充单一数据连接重传。

每轮预热 5 秒、测量 15 秒，产品及源站每轮重新启动。下载 worker 重复读取 64 MiB 完整响应（`--bulk-mib 64`）；短请求为 1 KiB。TCP 和 HTTP/1.1 主矩阵复用连接。mixed 同时运行 N 个下载和 N 个短请求 worker。HTTP/2 专项将同样数量的 worker 映射为一条连接上的并发流，实际连接数必须为 1。

HTTPS 透传、HTTP/2、新建连接和会话恢复保留功能验收数据，不再展开完整性能矩阵。`--special` 与网络/并发选项只供以后针对具体问题补测。固定随机种子轮换三条路径，并交错拓扑。

吞吐只计测量窗口内读到且校验正确的有效载荷；短请求延迟统计窗口内开始的请求，允许窗口结束后完成，失败另计。原始请求时长采用 **10 微秒直方图**，保存每个桶的完整频数；这不是逐请求时间序列，不能用于关联单次请求与单次重传。分位数采用桶中点，摘要同时保留各轮中位数/范围及合并样本 p95/p99。

CPU 覆盖整个负载进程的预热、测量及收尾；CPU 秒/GiB 使用相同阶段载荷，不拿整个 CPU 时间除以仅测量窗口的字节。HTTP/2 预建连接的 1 KiB 探测单独计入归一化分母。RSS 每 50 ms 采样；各进程峰值之和不是同时峰值。源站和负载端资源单列，Nexo/frp 域名入口都计入 Caddy。保留实际 TLS 协商、客户端连接数、连接复用及会话恢复计数。

本夹具的 Nexo 保持 Caddy 启用，TCP/HTTPS 透传组的空闲 Caddy 资源也计入产品总量；frp 仅在域名入口组启动 Caddy。原始结果分别保存各进程 CPU/RSS，可独立查看 Server/Agent 或 frps/frpc。不能把产品总 RSS 差异解释为纯 TCP 隧道所需内存差异。

## 额度检查与边界

源码按 Server 成功写入计费。HTTPS 透传包含内层 TLS 握手、记录和关闭消息；域名入口统计 Caddy 的 HTTP 回源字节，均不等于文件大小。连接关闭时，已成功排队的字节可能还没被另一端应用读到。因此每轮保存两端原始读写量，并执行：

1. Nexo 额度增量与隧道流量统计的精确一致性。
2. TCP/HTTPS 透传下，额度应处于两端实际接收字节之和与两端实际发送字节之和之间。
3. 单独检查错误 CA、8 并发、Agent 身份复用/重连，以及 Server 重启后额度持久化与 HTTPS 恢复。

源站与额度恰好相等作为诊断值保留，不把合法的 TLS 收尾差异误报为计费错误。Caddy 会改变 HTTP 头，域名入口不能使用 TLS 客户端字节作为 HTTP 回源计数的上/下界。TCP 半关闭由负载程序逐轮核对。已有产品的并发额度限制回归不因本工具而删除或放宽。

## 结果位置与限制

夹具验收已完成 84 轮：32 并发，100 Mbps/100 ms RTT 与 100 Mbps/1% 丢包，三种拓扑及 HTTPS 专项，预热 0.5 秒、测量 2 秒、一次重复，下载对象为旧版 1 MiB。请求错误为 0，28 轮 Nexo 额度/流量及适用的端点范围检查全部通过；HTTP/2 实际客户端连接数均为 1，会话恢复专项确实发生恢复。另有六项证书、重连和持久化验收通过。负载内容/时间窗口与统计矩阵测试、Go vet、Python 编译检查通过。这些是功能验收，不是正式性能结论。

正式结果应查看 `target/frp-performance/daily/REPORT.md` 的实际完成数；脚本每 30 轮更新报告，最后再次更新。原始数据位于同目录的 `NNNN.json.gz`，分组结果为 `summary.json`，新测轮次的进程日志和配置在 `rounds/`。本次不复用旧测量；`full/` 和 `objects-1m/` 保留先前 1 MiB 诊断数据。旧大矩阵已主动停止，不将其停止记录视为产品故障。短时 `smoke*`、`validation*`、`acceptance` 和 `recovery-check` 只用于夹具验收，不混入正式性能统计。

本地 WSL、共享宿主、负载工具与源站 CPU、随机丢包、内核调度均影响结果。不限速组只代表本机端到端能力；先比较直连余量并检查工具资源，再判断是否能归因于产品。100 Mbps 包含协议开销。未完成的矩阵不形成最终排名，完整本地矩阵也不能代替实际 VPS/NAS 测量。
