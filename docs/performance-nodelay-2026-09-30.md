# TCP_NODELAY 候选优化与配对测量

本次完成普通 Yamux 数据连接两端的 TCP_NODELAY 配对验证，**36/36 轮完成，全部采用标准通过，已将两处设置落地到 Server/Agent 源码**。不修改协议、额度、缓冲、心跳或其他数据路径；测量阶段未提交、未发布、未访问线上实例。

## 实测结果与采用结论

下表为 8 个下载＋8 个短请求的三次 p95 中位数，单位 ms；只比较同一当前源码快照的两种构建，不与旧版 frp 数据混算。

| 网络/入口 | 默认 | TCP_NODELAY | p95 降幅 | 改善配对数 |
|---|---:|---:|---:|---:|
| 正常 TCP | 22.45 | 11.29 | 约 50% | 2/3 |
| 正常 HTTPS | 61.69 | 15.30 | 约 75% | 3/3 |
| RTT 100 ms TCP | 593.80 | 368.69 | 约 38% | 3/3 |
| RTT 100 ms HTTPS | 594.03 | 356.80 | 约 40% | 3/3 |

高 RTT 三轮最差 p95：TCP 从 600.02 降至 471.20 ms，HTTPS 从 594.15 降至 474.27 ms。正常单连接下载吞吐中位数：TCP 201.05 → 216.90 MiB/s（+7.88%），HTTPS 257.29 → 292.97 MiB/s（+13.87%）。六个场景中最大的吞吐中位数下降为 0.46%，最大的 CPU 秒/GiB 中位数增加为 6.92%，均在约定限制内。

**仍有波动，不能宣称尾延迟问题已彻底解决。** 正常 TCP 混合组候选三轮 p95 为 11.20–75.94 ms，而默认为 12.60–56.59 ms；本轮按预先约定的中位数及至少两对改善条件通过，并未证明每一轮都更快，也不提供统计显著性或线上收益承诺。

验证结果：36 轮请求错误为 0，36 轮额度/统计及适用的端点范围校验通过；187 项 Rust 测试通过、9 项显式忽略（不计为通过）；21 项真实转发验收通过，包含半关闭、背压、并发额度、数据重连及持久化；四种端点组合各 4 项恢复验收通过。Go 测试及 vet、3 项 Python 矩阵/决策统计测试、修改 Rust 文件的格式检查通过。最终落地的两份 Rust 文件与受测候选只存在排版空白差异，测试专属进程及 namespace 已清理。

这次 Server 和 Agent 都有实际运行时代码变化；测量阶段未发布，后续正式发布记录见 [v0.2.14](releases/v0.2.14.md)。

## 实现与验收规则

`docker/performance-nodelay-build.py` 复制当前工作区的构建输入，使用相同 Rust 1.97、Cargo.lock 和 release 参数先构建 default，再只修改普通 Server `data_session` 和 Agent `run_data`，构建 nodelay。设置失败返回中文上下文并沿用原重连流程。候选源码与 `candidate.patch` 都归档，原默认源码可由候选副本反向应用补丁恢复。

两个版本都包含快照时已有功能；旧 frp 测量不混入本次统计。控制连接、其他 ALPN、客户端入口和回源连接不跟随设置。当前产品默认复制缓冲为 8 KiB，最大 128 条逻辑流、64 MiB 总接收窗口。

采用要求为：正常 TCP/HTTPS 混合 p95 中位数均降低至少 20%，各至少两对重复改善；RTT 100 ms 组的 p95 中位数和三轮最差值退化不超过 10%；各组吞吐中位数下降不超过 10%，产品 CPU 秒/GiB 增加不超过 15%；功能和额度校验全部通过。仅为本次决策，未增加永久性能门禁。任何条件未满足或数据不完整，都不自动修改生产默认，也不追加矩阵。

## 固定 36 轮

| 场景 | 网络 | 并行负载 |
|---|---|---|
| 单连接下载 | 本地不限速 | 1 个 64 MiB 下载 worker |
| 日常混合 | 本地不限速 | 8 个下载和 8 个 1 KiB 短请求 worker |
| 退化复核 | 100 Mbps、附加 RTT 100 ms | 8 个下载和 8 个短请求 worker |

每场景覆盖 TCP 和 HTTPS 域名入口、两个版本、三次重复，共 36 轮。固定随机种子交错配对顺序，每轮重建进程和连接。HTTPS 使用相同受信任临时 CA、TLS 1.3、HTTP/1.1 keep-alive；关闭压缩，不跳过证书验证。

每轮预热 5 秒、测量 15 秒。100 Mbps 下 8 个 64 MiB 响应仅有效载荷完成就需约 43 秒，因此两版负载工具均使用 120 秒请求超时，运行器最多允许额外 150 秒收尾；没有修改产品超时。吞吐只计测量窗口内有效字节，允许窗口内开始的请求在收尾阶段完成。CPU 秒/GiB 的 CPU 与载荷分母均覆盖预热、测量及收尾，不把收尾 CPU 除以仅测量窗口字节。

RSS 是各进程 50 ms 采样峰值之和，不是同时峰值；Nexo TCP 组包含空闲 Caddy，两种构建口径相同。重传覆盖两个 namespace 的所有 TCP，不能直接归于单一 Yamux 数据连接。SQLite 使用 Linux /tmp，本机为 tmpfs；本地共享 WSL 结果不代表生产磁盘或 VPS/NAS 网络。

## 复现

构建需要 WSL/Linux Docker、`rust:1.97-bookworm`；脚本复用 `codex-nexo-next-target` 和 `codex-nexo-next-registry` Cargo 缓存卷。输出目录必须不存在，保证两版从同一个源码副本产生。测量依赖 Linux root、iproute2、ethtool、OpenSSL、Python3、Go 1.25.1，以及项目支持的 Caddy 二进制。

```sh
python3 docker/performance-nodelay-build.py --output /tmp/nexo-nodelay-pair
go test docker/performance-load.go docker/performance-load_test.go
go build -o /tmp/performance-load docker/performance-load.go
python3 docker/test-performance.py

python3 docker/tunnel-smoke.py \
  --server-bin /tmp/nexo-nodelay-pair/nodelay/nexo-server \
  --agent-bin /tmp/nexo-nodelay-pair/nodelay/nexo-agent \
  --caddy-bin /path/to/caddy \
  --report target/nodelay-performance/run/smoke.json

sudo python3 docker/performance-frp.py \
  --server-bin /tmp/nexo-nodelay-pair/default/nexo-server \
  --agent-bin /tmp/nexo-nodelay-pair/default/nexo-agent \
  --nodelay-server-bin /tmp/nexo-nodelay-pair/nodelay/nexo-server \
  --nodelay-agent-bin /tmp/nexo-nodelay-pair/nodelay/nexo-agent \
  --caddy-bin /path/to/caddy --load-bin /tmp/performance-load \
  --request-timeout 120 --drain-timeout 150 \
  --output target/nodelay-performance/run
```

测量前自动验收四种端点组合：默认/默认、候选/候选、默认 Server/候选 Agent、候选 Server/默认 Agent。每组核对可信证书、错误 CA 拒绝、Agent 重启身份复用及 Server 重启额度持久化与 HTTPS 恢复。这些功能验收不计入性能轮数。

本次原始数据与逐项采用判定位于 `target/nodelay-performance/2026-09-30/`：`NNNN.json.gz`、`summary.json`、`REPORT.md`，每轮配置和日志在 `rounds/`，兼容性结果在 `compatibility/`。测量脚本、完整候选构建输入和实际二进制会一起保存，后续工作区变化不代表已被本次验收覆盖。
