#!/usr/bin/env python3
"""按本次已约定规则报告 NODELAY 配对实验；不作为 CI 性能门禁。"""
import argparse
from collections import defaultdict
import gzip
import importlib.util
import json
from pathlib import Path
import statistics

spec = importlib.util.spec_from_file_location("performance_report", Path(__file__).with_name("performance-report.py"))
report = importlib.util.module_from_spec(spec); spec.loader.exec_module(report)


def assess(rows):
    groups = defaultdict(dict)
    valid = len(rows) == 36
    for row in rows:
        valid &= row.get("status") == "measured" and bool(row.get("checks")) and all(row.get("checks", {}).values())
        if row.get("status") != "measured": continue
        value = report.summarize(row)
        valid &= value["errors"] == 0
        result = row["result"]
        valid &= (result["bulk_mib"], result["warm_seconds"], result["measure_seconds"], result["request_timeout_seconds"]) == (64, 5, 15, 120)
        key = (row["topology"], row["condition"], row["concurrency"], row["workload"])
        samples = groups[key].setdefault(row["variant"], {})
        valid &= row["repetition"] not in samples
        samples[row["repetition"]] = value
    valid &= len(groups) == 6
    comparisons = []
    for key, variants in sorted(groups.items()):
        if set(variants) != {"default", "nodelay"} or any(set(v) != {0, 1, 2} for v in variants.values()):
            valid = False
            continue
        metrics = {}
        for variant, samples in variants.items():
            metrics[variant] = {}
            for metric in samples[0]:
                values = [s[metric] for s in samples.values() if s[metric] is not None]
                metrics[variant][metric] = dict(median=statistics.median(values), min=min(values), max=max(values)) if values else None
        before, after = metrics["default"], metrics["nodelay"]
        rules = {"throughput": after["mib_s"]["median"] >= before["mib_s"]["median"] * .9,
                 "cpu": after["cpu_seconds_per_gib"]["median"] <= before["cpu_seconds_per_gib"]["median"] * 1.15}
        improved_pairs = None
        if key[3] == "mixed":
            improved_pairs = sum(variants["nodelay"][i]["p95_ms"] < variants["default"][i]["p95_ms"] for i in range(3))
            if key[1] == "unlimited":
                rules["latency"] = after["p95_ms"]["median"] <= before["p95_ms"]["median"] * .8 and improved_pairs >= 2
            else:
                rules["latency"] = (after["p95_ms"]["median"] <= before["p95_ms"]["median"] * 1.1
                                    and after["p95_ms"]["max"] <= before["p95_ms"]["max"] * 1.1)
        comparisons.append(dict(topology=key[0], condition=key[1], concurrency=key[2], workload=key[3],
                                metrics=metrics, improved_pairs=improved_pairs, rules=rules))
    return dict(complete_and_valid=bool(valid), performance_accepted=bool(valid and all(all(c["rules"].values()) for c in comparisons)), comparisons=comparisons)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path); parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    rows = [json.load(gzip.open(p, "rt")) for p in sorted(args.directory.glob("[0-9][0-9][0-9][0-9].json.gz"))]
    summary = assess(rows)
    compatibility = {}
    for name in ("default", "nodelay", "old-server", "old-agent"):
        file = args.directory / "compatibility" / name / "recovery.json"
        compatibility[name] = json.loads(file.read_text()) if file.exists() else None
    smoke = args.directory / "smoke.json"
    summary["functional_checks_passed"] = all(v and len(v.get("passed", [])) == 4 for v in compatibility.values()) and smoke.exists() and len(json.loads(smoke.read_text()).get("passed", [])) >= 21
    summary["adopt"] = summary["performance_accepted"] and summary["functional_checks_passed"]
    (args.directory / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    lines = ["# TCP_NODELAY 本地配对实验", "", f"结果已落盘 {len(rows)}/36 轮。采用结论：{'通过采用标准' if summary['adopt'] else '不采用；未完成、校验失败或性能标准未全部满足'}。", "",
             "两组为同一源码快照的 release 构建，仅普通 Yamux 底层 TCP_NODELAY 不同。TCP 与 HTTPS 域名入口分别比较，HTTPS 固定受信任 CA、TLS 1.3、HTTP/1.1 keep-alive。每轮预热 5 秒、测量 15 秒，64 MiB 下载、1 KiB 短请求；混合为 8 个下载加 8 个短请求。RTT 组限速 100 Mbps、附加 RTT 100 ms，无主动丢包。", "",
             "请求超时 120 秒、额外收尾上限 150 秒，仅为压测参数。吞吐只计测量窗口，CPU 秒/GiB 按整个负载进程相同阶段归一化。下面为三次中位数，括号为最小至最大。", "",
             "| 场景 | 版本 | MiB/s | 短请求 p95 ms | CPU 秒/GiB | RSS 峰值之和 MiB |", "|---|---|---:|---:|---:|---:|"]
    def show(value):
        return "—" if value is None else f"{value['median']:.2f} ({value['min']:.2f}–{value['max']:.2f})"
    for group in summary["comparisons"]:
        label = f"{group['topology']}/{group['condition']}/{group['concurrency']}/{group['workload']}"
        for variant, metrics in group["metrics"].items():
            lines.append(f"| {label} | {variant} | {show(metrics['mib_s'])} | {show(metrics['p95_ms'])} | {show(metrics['cpu_seconds_per_gib'])} | {show(metrics['product_peak_rss_mib_sum'])} |")
    lines += ["", "## 采用规则逐项结果", "", "正常混合 p95 降低至少 20%，至少两对改善；RTT 组 p95 中位数及最差值退化不超过 10%；所有场景吞吐下降不超过 10%、CPU 秒/GiB 增加不超过 15%。这是本次判断规则，不是永久 CI 门禁。", ""]
    for group in summary["comparisons"]:
        lines.append(f"- {group['topology']}/{group['condition']}/{group['workload']}：{group['rules']}；改善配对数 {group['improved_pairs']}。")
    lines += ["", "## 验收与限制", "", f"完整且校验通过：{summary['complete_and_valid']}；功能及混搭验收：{summary['functional_checks_passed']}。",
              "本地 WSL、共享宿主和调度会影响结果，不能代表 VPS/NAS。重传为两个 namespace 总量，不足以定位单条数据连接。保留认证、额度、默认缓冲及心跳。SQLite 位于 Linux /tmp（本机 tmpfs），不代表磁盘 I/O。没有混入旧 frp 数据。",
              "原始 NNNN.json.gz 保存错误、延迟直方图、CPU/RSS、重传和流量检查；summary.json 包含 p50/p95/p99、每秒请求数、源站/压测端 CPU 和波动范围。compatibility 保存四种端点组合的证书及恢复验收，smoke.json 保存转发回归。"]
    for row in rows:
        if row.get("status") != "measured" or not all(row.get("checks", {}).values()):
            lines.append(f"- 异常：{row.get('variant')}/{row.get('topology')}/{row.get('condition')} {row.get('error', row.get('checks'))}")
    args.report.write_text("\n".join(lines)+"\n", encoding="utf-8")
    print(json.dumps({"completed": len(rows), "valid": summary["complete_and_valid"], "adopt": summary["adopt"]}))


if __name__ == "__main__": main()
