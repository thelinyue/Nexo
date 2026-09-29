# 2026-09-29 性能优化与对照测量

## 已实施的变化

- 流量历史按全空间、单空间、单隧道选择显式 SQL，继续使用已有索引。保留授权、用户存在性、未落盘数据合并和时间边界。
- TCP、UDP、反代状态在锁外计算，用短事务提交一批结果。NULL 安全的差异条件避免稳定状态触发行更新；保留配置版本与删除保护，组合服务只提交聚合状态。
- Caddy Supervisor 复用 HTTP 连接池。GET 保留 3 秒超时，加载保留 10 秒超时，均不使用系统代理。无变更轮次读取实际配置一次，加载后再次确认；读取失败不清理凭据。
- JS/CSS 在构建时生成 gzip 旁路文件，Server 按 Accept-Encoding 协商并返回 Vary；不支持 gzip 时返回原文件。API 保持 no-store。
- 页面模块按访问加载，已有页面实例、草稿和滚动位置仍保留；分包首次加载后恢复标题焦点，加载失败显示可重试错误。
- 首页当前空间的隧道筛选复用概览列表，其他空间独立请求。轮询周期与隐藏页面暂停行为保持原样。

没有改变公开 API、数据库结构、协议、认证、月额度语义、15 秒心跳或 45 秒超时。Agent 生产源码没有变化；传输参数的实验修改仅存在于临时源码副本。本次没有发布、部署或更新版本号。

## SQL 与 Server 局部结果

采用项目实际绑定的 SQLite 3.46.0、Linux release 构建、内存数据库、20 个空间各一条隧道、七天分钟记录共 201600 行。预热后各执行 9 次，比较返回的完整结果。

| 单隧道七天查询 | 中位耗时 |
|---|---:|
| 原可选 OR 条件 | 36.202 ms |
| 显式 tenant_id/tunnel_id 条件 | 2.715 ms |

该样本约快 13.3 倍，仅代表这条 SQL。查询计划使用已有 `(tenant_id,tunnel_id,minute)` 主键索引；没有添加索引、汇总表或缓存。数据规模、空间分布和磁盘会影响线上收益。

回归测试确认稳定状态的数据库 total_changes 不增长、错误从非 NULL 恢复为 NULL 时更新、协议明细独立变化时更新、旧版本/删除服务不能被覆盖、批内失败回滚。没有将 UPDATE 数量减少换算为物理磁盘 IOPS。

Caddy 模拟 Admin 测试同时核对实际 TCP 对端端口与请求数：首次配置加载读取两次，稳定轮次一次；连接得到复用，Admin 失败后暂停清理，实际配置丢失后可重新加载。真实 Caddy 集成测试另行执行。

## 前端实测

优化前生产构建入口为 429.77 KB（Vite 估算 gzip 133.82 KB）。拆分后约 233.55 KB（gzip 约 75.45 KB），入口原始体积下降约 45.7%。并非整个应用体积减少：PWA 仍预缓存所有分包，约 1.73 MiB，保证离线能力。

真实 release Server + Chromium 的回环测量：入口 JS 实际 gzip 74533 字节、原文件 233550 字节；CSS 实际 gzip 16268 字节、原文件 89899 字节。解压后内容逐字节一致，identity 回退正常，API 不缓存。

三次新浏览器上下文、禁用 Service Worker 的登录页可见时间约 72.0/59.9/60.8 ms。这是本机验收值，没有优化前同口径页面耗时，不能据此宣称线上首屏提升。已验证首次登录、离线加载尚未访问的服务分包、离线重开网络错误、恢复联网及 Service Worker 更新激活。

## 传输实验方法与边界

使用 Linux release Server/Agent、WSL2 内核 6.18.33.2、12 个逻辑处理器。每个实验均创建独立数据目录与身份，专属 network namespace 内仅启用 loopback。tc netem 仅匹配本次被测链路端口，不更改宿主或线上网络。

- 四种构建：默认 8 KiB、32 KiB、64 KiB 双向复制缓冲，以及默认缓冲 + Yamux 承载 TCP 两端 TCP_NODELAY。每次只改变一项；生产默认保持原样。
- 五种网络条件：正常、附加 RTT 50 ms、附加 RTT 100 ms、丢包 0.1%、丢包 1%；延迟与丢包分别测试，不表示所有交叉组合。
- 并发 1/8/32；总计 8 MiB 下载按并发均分；短请求每 worker 5 次、每次响应 1 KiB；混合时下载和短请求同时开始。
- 每种组合 3 次，交替直连/隧道先后顺序。记录有效载荷吞吐、每轮短请求 p95、Server/Agent 进程 CPU 秒数与 10 ms 采样峰值 RSS、namespace TCP 重传。
- 每次校验完整内容、长度和半关闭；隧道额度增量必须等于响应字节加 8 字节请求头，直连不能计入额度。

这是短时回环筛选实验：没有限速，loopback MTU/分段、Python 源站与负载线程、WSL 调度和非专用宿主的其他负载均会影响结果；没有模拟真实跨地域路由。8 MiB 是整批总量，32 并发时每条仅 256 KiB，不是长时间饱和吞吐。表中 p95 是三次运行各自 p95 的中位数，不是合并样本的 p95。CPU 分辨率来自 /proc，极短测试可显示 0；RSS 是采样峰值而非精确最大值。同一 Agent 数据连接在场景间复用，拥塞窗口可能继承；随机丢包只重复三次，数值用于候选筛选，不作为精确增益承诺。

统计热路径另用无网络 sink 做 20 万次 8 KiB 写入微测量，涵盖计数、时间处理、额度与锁的总成本，不能解释为纯 mutex 耗时或实际吞吐：

| 并发线程 | 未计数 ns/次 | 带统计及额度 ns/次 |
|---|---:|---:|
| 1 | 2.8 | 101.0 |
| 8 | 3.5 | 221.9 |
| 32 | 9.8 | 269.5 |

该结果不能支持取消额度锁；并发额度精确性仍由原回归测试保护。

## 传输矩阵结果与建议

四种构建各 270 组，合计 **1080 组全部完成**。所有响应内容、长度、半关闭及额度计数校验通过。下表均取三次测量中位数。

### 正常回环：隧道批量吞吐（MiB/s）

| 并发 | 默认 8 KiB | 32 KiB | 64 KiB | 8 KiB + NODELAY |
|---|---:|---:|---:|---:|
| 1 | 116.90 | 138.45 | 126.52 | 285.98 |
| 8 | 109.16 | 130.03 | 74.04 | 270.47 |
| 32 | 166.40 | 90.77 | 94.06 | 166.82 |

### 正常回环：混合负载短请求 p95（ms）

| 并发 | 默认 8 KiB | 32 KiB | 64 KiB | 8 KiB + NODELAY |
|---|---:|---:|---:|---:|
| 1 | 44.92 | 49.39 | 47.93 | 1.53 |
| 8 | 62.59 | 71.01 | 91.91 | 23.22 |
| 32 | 86.51 | 71.06 | 66.53 | 56.67 |

### 8 并发：不同网络下混合负载短请求 p95（ms）

| 条件 | 默认 8 KiB | 32 KiB | 64 KiB | 8 KiB + NODELAY |
|---|---:|---:|---:|---:|
| 正常 | 62.59 | 71.01 | 91.91 | 23.22 |
| RTT 50 ms | 198.42 | 197.94 | 237.33 | 155.23 |
| RTT 100 ms | 348.23 | 347.63 | 348.14 | 401.75 |
| 丢包 0.1% | 61.40 | 58.01 | 68.86 | 21.94 |
| 丢包 1% | 90.91 | 220.28 | 211.15 | 27.84 |

### 默认参数、8 并发：直连与隧道批量吞吐（MiB/s）

| 条件 | 直连源站 | Nexo 隧道 | 隧道本轮 TCP 重传中位数 |
|---|---:|---:|---:|
| 正常 | 280.67 | 109.16 | 0 |
| RTT 50 ms | 22.19 | 17.85 | 13 |
| RTT 100 ms | 11.25 | 8.84 | 14 |
| 丢包 0.1% | 281.30 | 72.94 | 7 |
| 丢包 1% | 286.80 | 100.61 | 7 |

### 资源记录

CPU 为正常回环 8 并发批量测试的进程 CPU 秒数中位数；RSS 为各构建全部测试中的采样最大值，包含持续运行后的分配器与窗口状态，不能全部归因于复制缓冲。

| 构建 | Server CPU 秒 | Agent CPU 秒 | Server RSS MiB | Agent RSS MiB |
|---|---:|---:|---:|---:|
| default | 0.030 | 0.030 | 52.34 | 14.76 |
| buffer32 | 0.020 | 0.010 | 56.16 | 16.58 |
| buffer64 | 0.020 | 0.020 | 66.50 | 18.65 |
| nodelay | 0.050 | 0.040 | 58.11 | 14.22 |

结论：

- 增大复制缓冲没有一致收益：32 KiB 在部分低并发场景更快，在 32 并发正常回环中反而低于默认；64 KiB 同样存在明显波动。本次保留 8 KiB。
- TCP_NODELAY 是下一轮最值得验证的候选：正常回环单并发混合负载的短请求 p95 从 44.92 ms 降到 1.53 ms；但 RTT 100 ms、8 并发混合负载 p95 从 348.23 ms 上升到 401.75 ms，存在相反结果。未将实验设置写入生产代码，后续需在实际 VPS/NAS 上验证长时传输、CPU 和带宽代价。
- 高 RTT 下吞吐和小请求延迟变化显著；不能从这组 loopback 数据断言需要更换 Yamux、增大 64 MiB 窗口或取消额度锁。
- 保留 8 KiB、现有 TCP 行为及所有额度/认证机制。测量完成不等于线上吞吐验收。

## 验证结果

- 最终 Linux release Server：149 项回归通过、0 失败、0 忽略，包含真实 Caddy 集成、静态 gzip 协商、API no-store、事务回滚、额度和心跳超时。两项手动性能测量单独执行并记录在前文，不重复计为回归通过。
- 真实 Server + Agent + Caddy：21 项转发验收通过，覆盖 HTTP/HTTPS/WebSocket、8 MiB 数据、半关闭/背压、并发、额度、断线重连、启停/删除、重启和已落库统计恢复。
- 浏览器：桌面 Chromium、手机 Chromium、手机 WebKit 共 91 项通过，41 项按测试的项目/视口条件跳过，未计入通过。覆盖导航焦点/草稿、分包失败重试、账号切换、代管空间、PWA 与首页请求复用。
- 真实 release 静态服务额外确认 Content-Encoding、Vary、原文件回退、逐字节解压一致性、离线分包和 Service Worker 更新。
- Clippy `-D warnings`、修改的 Rust 文件格式检查、Python 编译检查、生产前端构建与 `git diff --check` 通过。
- 全部 1080 组传输样本完成；没有访问或修改线上 VPS/NAS，也没有把回环结果认定为线上提速。

## 复现

```sh
# 本地 Rust：普通回归、SQL 与统计开销测量
cargo test -p nexo-server
cargo test --release -p nexo-server measure_ -- --ignored --nocapture --test-threads=1

# 真实 Caddy 回归：必须指定包含项目所需 DNS 模块的二进制
NEXO_TEST_CADDY_BIN=/path/to/caddy cargo test --release -p nexo-server -- --include-ignored --test-threads=1

# Linux：正常 release 构建，然后生成三组临时副本参数实验
cargo build --release -p nexo-server -p nexo-agent
python3 docker/performance-variants.py --output /tmp/nexo-variants --target-dir /tmp/nexo-perf-build

# 必须先成功创建自己的 namespace，再设置清理；不要复用系统网络 namespace
sudo ip netns add nexo-perf
sudo ip netns exec nexo-perf ip link set lo up
sudo ip netns exec nexo-perf python3 docker/performance-probe.py \
  --server-bin "$PWD/target/release/nexo-server" \
  --agent-bin "$PWD/target/release/nexo-agent" \
  --netem --label default --report /tmp/nexo-default.json
sudo ip netns del nexo-perf
```

参数实验用 `/tmp/nexo-variants/{buffer32,buffer64,nodelay}` 下的二进制分别执行同一命令。探针在 finally 中停止自己启动的进程并移除自己 namespace 内的 qdisc；调用方始终应清理创建的 namespace。默认 3 次、8 MiB，可用 `--repetitions`、`--mib` 延长测量。

```sh
cd web
npm run build
npx playwright test tests/home.spec.ts tests/navigation.spec.ts tests/workspace-layout.spec.ts tests/pwa-launch.spec.ts tests/multiuser.spec.ts tests/responsive-accounts.spec.ts --project=desktop-dark --project=mobile-light --project=mobile-webkit
```

原始本机数据保存在 `target/performance/`，包含各构建 JSON、日志、浏览器记录及真实转发结果；这是忽略的测量产物，不含生产凭据，也不作为固定性能门禁。
