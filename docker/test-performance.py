"""检查矩阵覆盖及报告统计口径，防止遗漏场景或把分位数平均化。"""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest


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

    def test_percentile_uses_sample_counts_and_numeric_buckets(self):
        report = module("performance-report")
        self.assertEqual(report.percentile({"2": 95, "100": 5}, .95), .025)
        self.assertEqual(report.percentile({"2": 95, "100": 5}, .99), 1.005)
        self.assertIsNone(report.percentile({}, .95))


if __name__ == "__main__": unittest.main()
