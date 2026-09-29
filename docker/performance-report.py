#!/usr/bin/env python3
"""将逐轮原始结果汇总为可审阅的中文报告；未完成/失败样本显式保留。"""
import argparse
from collections import Counter, defaultdict
import gzip
import json
import math
from pathlib import Path
import statistics


def percentile(histogram, fraction):
    total = sum(histogram.values())
    if not total: return None
    count = 0
    for bucket, size in sorted((int(k), v) for k, v in histogram.items()):
        count += size
        if count >= math.ceil(total * fraction): return (bucket + .5) / 100


def summarize(row):
    result = row["result"]
    workers = result["workers"]
    hist = Counter()
    for worker in workers:
        if worker["kind"] == "short": hist.update(worker["latency_10us"])
    errors = sum(sum(w["errors"].values()) for w in workers)
    requests = sum(w["requests"] for w in workers)
    payload = sum(w["measured_bytes"] for w in workers)
    total = sum(w.get("total_bytes", 0) for w in workers) + result.get("setup_payload_bytes", 0)
    product_cpu = sum(v for k,v in result["cpu_seconds"].items() if k not in ("load", "origin"))
    elapsed = result.get("load_process_seconds", result["warm_seconds"]+result["measure_seconds"]+result["drain_seconds"])
    return {"mib_s": payload/result["measure_seconds"]/1048576,
            "tcp_retransmits": sum(result.get("tcp_retransmits", [])),
            "requests_s": requests/result["measure_seconds"], "errors": errors,
            "failure_rate": errors/(errors+requests) if errors+requests else None,
            "p50_ms": percentile(hist, .5), "p95_ms": percentile(hist, .95), "p99_ms": percentile(hist, .99),
            "cpu_seconds_per_gib": product_cpu/(total/1073741824) if total else None,
            "load_cpu_cores": result["cpu_seconds"].get("load", 0)/elapsed,
            "origin_cpu_cores": result["cpu_seconds"].get("origin", 0)/elapsed,
            "product_peak_rss_mib_sum": sum(v for k,v in result["peak_rss_bytes"].items() if k not in ("load", "origin"))/1048576}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path); parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads((args.directory / "metadata.json").read_text())
    rows = [json.load(gzip.open(p, "rt")) for p in sorted(args.directory.glob("[0-9][0-9][0-9][0-9].json.gz"))]
    measured = [r for r in rows if r["status"] == "measured"]
    failed = [r for r in rows if r["status"] != "measured"]
    previous_attempts = [json.load(gzip.open(p, "rt")) for p in sorted(args.directory.glob("*.failed-*.gz"))]
    groups = defaultdict(list)
    keys = ("topology", "condition", "concurrency", "protocol", "mode", "workload", "path")
    for row in measured: groups[tuple(row[k] for k in keys)].append(row)
    aggregated = []
    for key, samples in sorted(groups.items()):
        value = dict(zip(keys, key)); values = [summarize(r) for r in samples]
        value["rounds"] = len(samples)
        for metric in values[0]:
            numbers = [v[metric] for v in values if v[metric] is not None]
            value[metric] = {"median": statistics.median(numbers), "min": min(numbers), "max": max(numbers)} if numbers else None
        pooled = Counter()
        for row in samples:
            for worker in row["result"]["workers"]:
                if worker["kind"] == "short": pooled.update(worker["latency_10us"])
        value["pooled_p95_ms"] = percentile(pooled, .95)
        value["pooled_p99_ms"] = percentile(pooled, .99)
        aggregated.append(value)
    (args.directory / "summary.json").write_text(json.dumps(aggregated, ensure_ascii=False, indent=2))
    errors = sum(summarize(r)["errors"] for r in measured)
    quota = [r for r in measured if "quota_matches_traffic" in r]
    quota_failed = [r for r in quota if not r["quota_matches_traffic"] or not r.get("quota_within_wire_bounds", True)]
    check_failed = [r for r in measured if any(not v for v in r.get("checks", {}).values())]
    lines = ["# Nexo 与 frp：TCP / HTTPS 本地对照", "",
             f"已落盘 {len(rows)}/{metadata['total_rounds']} 轮：测量完成 {len(measured)}，夹具失败 {len(failed)}，请求错误 {errors}。",
             "**完整矩阵尚未完成，当前结果不能代替最终结论。**" if len(rows) != metadata["total_rounds"] else "本次配置的矩阵已落盘；失败和错误见下文，不能视为全部通过。" if failed or errors or quota_failed or check_failed else "本次配置的矩阵已完成，无请求错误；是否为正式完整矩阵请核对轮数和时长。",
             "", f"frp {metadata['frp_version']}；Caddy {metadata['caddy_version']}；Linux {metadata['kernel']}；{metadata['cpu_count']} 个逻辑 CPU。",
             f"每轮预热 {metadata['warm_seconds']} 秒、测量 {metadata['duration_seconds']} 秒；本次网络配置：{', '.join(metadata.get('selected_conditions', sorted({r['condition'] for r in rows})))}。条件定义见 metadata.json，延迟和丢包不交叉。",
             "", "## 计量与限制", "",
             "- 每轮重新启动产品与源站，使用独立 veth/namespace、MTU 1500，关闭 TSO/GSO/GRO；不连接公网和线上实例。",
             f"- 下载对象 {metadata.get('bulk_mib', 1)} MiB，短请求 1 KiB；mixed 为 N 个下载和 N 个短请求并行。拓扑分别比较，HTTPS 使用受信任测试 CA、TLS 1.3，关闭压缩。",
             "- Nexo 域名入口保留内部访问检查；frp/直连复用通用 Caddy 配置，不依赖 Nexo 控制面。因此域名入口差距包含访问检查成本，不能全部归于隧道。",
             "- 吞吐仅计固定测量窗口内已读取并校验的有效载荷；请求延迟按窗口内开始的成功请求统计，允许收尾完成，错误单列。",
             "- 原始延迟以 10 微秒直方图保存，分位数取桶中点。摘要表是每轮 p95 的中位数；summary.json 同时包含合并样本分位数。",
             "- CPU 覆盖预热、测量与收尾，CPU 秒/GiB 使用同一区间的有效载荷；RSS 为 50 ms 采样峰值，各进程峰值相加不等于同时峰值。",
             "- 源站和负载端 CPU/RSS 单独保存。不限速结果只说明本机端到端能力；直连余量不足或工具饱和时，不能据此判断隧道上限。",
             "- Nexo TCP 组也保留空闲 Caddy，其资源计入产品总量；frp 仅域名入口组启动 Caddy，纯隧道资源应查看分进程数据。",
             "- 共享 WSL 宿主、Go 源站/负载实现影响结果；本次 SQLite 临时目录位于 tmpfs，不能代表生产磁盘 I/O。",
             f"- Nexo 额度与流量统计精确核对、透传两端读写范围检查：{len(quota)-len(quota_failed)}/{len(quota)} 通过。TLS/取消允许未送达的排队字节，源站读写总数不强行等同于 Server 成功写入计费。",
             f"- 请求/连接复用/会话恢复/额度验收有 {len(check_failed)} 轮未通过，见逐轮 checks；未关闭认证和统计。", "",
             "## 主矩阵：吞吐与短请求 p95", "",
             "| 拓扑 | 网络 | 并发 | 负载 | 直连 MiB/s | Nexo MiB/s | frp MiB/s | Nexo/frp | Nexo p95 ms | frp p95 ms | 每组轮数 |",
             "|---|---|---:|---|---:|---:|---:|---:|---:|---:|---|"]
    lookup = {tuple(v[k] for k in keys): v for v in aggregated}
    labels = {"tcp": "TCP", "passthrough": "HTTPS 透传", "domain": "HTTPS 域名入口"}
    def number(value): return "—" if value is None else f"{value:.2f}"
    for topology in ("tcp", "passthrough", "domain"):
        for condition in ("unlimited", "100m", "rtt50", "rtt100", "loss01", "loss1"):
            for concurrency in (1, 8, 32):
                for workload in ("bulk", "short", "mixed"):
                    prefix = (topology, condition, concurrency, "tcp" if topology == "tcp" else "h1", "keepalive", workload)
                    entries = [lookup.get(prefix + (path,)) for path in ("direct", "nexo", "frp")]
                    if not any(entries): continue
                    def metric(entry, name): return entry[name]["median"] if entry and entry[name] else None
                    rates = [metric(e, "mib_s") for e in entries]
                    ratio = rates[1]/rates[2] if rates[1] is not None and rates[2] else None
                    lines.append(f"| {labels[topology]} | {condition} | {concurrency} | {workload} | " + " | ".join(number(v) for v in rates+[ratio,metric(entries[1],"p95_ms"),metric(entries[2],"p95_ms")]) + " | " + "/".join(str(e['rounds']) if e else '0' for e in entries) + " |")
    if any(r["protocol"] == "h2" or r["mode"] != "keepalive" for r in aggregated):
        lines += ["", "## HTTPS 专项", "", "| 拓扑 | 网络 | 并发 | 协议/模式 | 负载 | 路径 | MiB/s | p95 ms | 轮数 |", "|---|---|---:|---|---|---|---:|---:|---:|---:|"]
    for row in aggregated:
        if row["protocol"] != "h2" and row["mode"] == "keepalive": continue
        lines.append(f"| {labels[row['topology']]} | {row['condition']} | {row['concurrency']} | {row['protocol']}/{row['mode']} | {row['workload']} | {row['path']} | {number(row['mib_s']['median'])} | {number(row['p95_ms']['median'] if row['p95_ms'] else None)} | {row['rounds']} |")
    lines += ["", "## 资源示例：8 并发下载", "", "CPU 为产品相关进程合计，域名入口包含 Caddy；源站和压测端见原始 JSON。", "",
              "| 拓扑 | 网络 | 路径 | CPU 秒/GiB | 进程峰值 RSS 之和 MiB | 压测端 CPU 核 | 源站 CPU 核 | 轮数 |", "|---|---|---|---:|---:|---:|---:|---:|"]
    for row in aggregated:
        if row["concurrency"] != 8 or row["condition"] not in ("unlimited", "rtt100") or row["workload"] != "bulk" or row["mode"] != "keepalive" or row["protocol"] == "h2": continue
        cpu = row["cpu_seconds_per_gib"]
        lines.append(f"| {labels[row['topology']]} | {row['condition']} | {row['path']} | {number(cpu['median'] if cpu else None)} | {number(row['product_peak_rss_mib_sum']['median'])} | {number(row['load_cpu_cores']['median'])} | {number(row['origin_cpu_cores']['median'])} | {row['rounds']} |")
    lines += ["", "## 各组波动范围", "", "括号内为各轮最小值至最大值，前项为中位数。请求速率合计下载与短请求；延迟仅指短请求。重传为两个 namespace 合计，包含控制连接。", "",
              "| 场景/路径 | 吞吐 MiB/s | 短请求 p95 ms | 请求/s | 重传数 |", "|---|---:|---:|---:|---:|"]
    def spread(value):
        return "—" if value is None else f"{number(value['median'])} ({number(value['min'])}–{number(value['max'])})"
    for row in aggregated:
        scene = f"{labels[row['topology']]}/{row['condition']}/{row['concurrency']}/{row['workload']}/{row['protocol']}/{row['mode']}/{row['path']}"
        lines.append(f"| {scene} | {spread(row['mib_s'])} | {spread(row['p95_ms'])} | {spread(row['requests_s'])} | {spread(row['tcp_retransmits'])} |")
    lines += ["", "## 不限速直连余量", "", "检查直连吞吐是否高于隧道；直连更快仅说明本夹具有余量，不证明不存在单核或调度瓶颈。未满足的场景列在下方。高负载重传不等于主动注入丢包，重传原因需要另行定位。"]
    for topology in ("tcp", "passthrough", "domain"):
        for concurrency in (1,8,32):
            prefix = (topology,"unlimited",concurrency,"tcp" if topology == "tcp" else "h1","keepalive","bulk")
            entries = [lookup.get(prefix+(path,)) for path in ("direct","nexo","frp")]
            if all(entries):
                rates = [e["mib_s"]["median"] for e in entries]
                if rates[0] <= max(rates[1:]): lines.append(f"- {labels[topology]} / {concurrency} 并发：直连 {rates[0]:.2f}、Nexo {rates[1]:.2f}、frp {rates[2]:.2f} MiB/s。")
    lines += ["", "## 异常与复现", "", "原始逐轮数据、矩阵、二进制路径和版本见同目录的 metadata.json、matrix.json、NNNN.json.gz；进程日志与配置在 rounds/。"]
    for row in failed: lines.append(f"- 夹具失败：{row.get('error')}")
    for row in previous_attempts: lines.append(f"- 已保留的早期夹具失败/重试：{row.get('error')}。原始记录在 *.failed-*.gz，未当作产品请求失败或成功性能样本。")
    for row in check_failed: lines.append(f"- 验收异常：{row['topology']}/{row['condition']}/{row['mode']}/{row['path']}：{row['checks']}。")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines)+"\n", encoding="utf-8")
    print(json.dumps({"completed": len(measured), "expected": metadata["total_rounds"], "failed": len(failed), "request_errors": errors, "quota_mismatches": len(quota_failed)}))


if __name__ == "__main__": main()
