"""检查矩阵覆盖及报告统计口径，防止遗漏场景或把分位数平均化。"""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result


class PerformanceTests(unittest.TestCase):
    def test_matrix_and_special_cases(self):
        probe = module("performance-frp")
        args = SimpleNamespace(topologies="tcp,passthrough,domain", conditions=",".join(probe.CONDITIONS),
                               concurrency="1,8,32", repetitions=5, special=False, workloads="bulk,short,mixed")
        rows = probe.cases(args)
        self.assertEqual(len(rows), 2430)
        self.assertEqual(len({tuple(sorted(r.items())) for r in rows}), 2430)
        args.special = True
        rows = probe.cases(args)
        self.assertEqual(len(rows), 3330)
        self.assertTrue(all(r["topology"] != "tcp" and r["condition"] in ("unlimited", "rtt100")
                            for r in rows if r["protocol"] == "h2" or r["mode"] != "keepalive"))
        self.assertEqual(rows, probe.cases(args))
        args.topologies = "tcp,domain"; args.conditions = "unlimited"; args.concurrency = "1,8"
        args.workloads = "bulk,mixed"; args.repetitions = 3; args.special = False
        self.assertEqual(len(probe.cases(args)), 72)
        args.nodelay_server_bin = "candidate"
        rows = probe.cases(args)
        self.assertEqual(len(rows), 36)
        self.assertEqual({(r["condition"], r["concurrency"], r["workload"]) for r in rows},
                         {("unlimited", 1, "bulk"), ("unlimited", 8, "mixed"), ("rtt100", 8, "mixed")})
        for first, second in zip(rows[::2], rows[1::2]):
            self.assertEqual({first["variant"], second["variant"]}, {"default", "nodelay"})
            self.assertEqual({k: v for k, v in first.items() if k != "variant"},
                             {k: v for k, v in second.items() if k != "variant"})

    def test_percentile_uses_sample_counts_and_numeric_buckets(self):
        report = module("performance-report")
        self.assertEqual(report.percentile({"2": 95, "100": 5}, .95), .025)
        self.assertEqual(report.percentile({"2": 95, "100": 5}, .99), 1.005)
        self.assertIsNone(report.percentile({}, .95))

    def test_nodelay_decision_rejects_worst_latency_and_incomplete_samples(self):
        probe = module("performance-frp")
        decision = module("performance-nodelay-report")
        rows = probe.cases(SimpleNamespace(nodelay_server_bin="candidate"))
        for row in rows:
            latency = 100 if row["condition"] == "rtt100" else 10
            if row["variant"] == "nodelay": latency *= .7
            row.update(status="measured", checks={"payload_and_requests": True},
                       result=dict(bulk_mib=64, warm_seconds=5, measure_seconds=15, request_timeout_seconds=120),
                       metrics=dict(errors=0, mib_s=100, cpu_seconds_per_gib=10, p95_ms=latency))
        with patch.object(decision.report, "summarize", side_effect=lambda row: row["metrics"]):
            self.assertTrue(decision.assess(rows)["performance_accepted"])
            self.assertFalse(decision.assess(rows[:-1])["performance_accepted"])
            target = next(r for r in rows if r["condition"] == "rtt100" and r["variant"] == "nodelay")
            target["metrics"]["p95_ms"] = 120  # 中位数仍改善，但单轮最差值违反约定。
            self.assertFalse(decision.assess(rows)["performance_accepted"])
            target["metrics"]["p95_ms"] = 70
            for row in rows:
                if row["variant"] == "nodelay": row["metrics"]["cpu_seconds_per_gib"] = 12
            self.assertFalse(decision.assess(rows)["performance_accepted"])


if __name__ == "__main__": unittest.main()
