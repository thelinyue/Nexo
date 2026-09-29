#!/usr/bin/env python3
"""真实 release Server/Agent 的隔离性能探针；不修改产品参数，不访问现有实例。"""
import argparse
import concurrent.futures
import importlib.util
import json
import math
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import threading
import time

spec = importlib.util.spec_from_file_location("tunnel_smoke", Path(__file__).with_name("tunnel-smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class Origin(socketserver.BaseRequestHandler):
    """8 字节长度请求对应固定内容响应；逐块校验，避免将错误响应计入吞吐。"""
    def handle(self):
        try:
            header = b""
            while len(header) < 8:
                part = self.request.recv(8 - len(header))
                if not part:
                    return  # Agent 健康探测不发送业务数据。
                header += part
            remaining, = struct.unpack("!Q", header)
            block = b"x" * 65536
            while remaining:
                size = min(remaining, len(block))
                self.request.sendall(block[:size])
                remaining -= size
        except OSError:
            pass


class OriginServer(smoke.EchoServer):
    # 混合测试最多 64 个同时连接；不能让 Python 默认的 5 项 accept 队列成为瓶颈。
    request_queue_size = 256


class Harness(smoke.Harness):
    def start_server(self):
        self.server = self.launch("server", self.args.server_bin, {
            "admin.username": "admin", "admin.password": "Test-tunnel-only-4821!",
            "data_dir": str(self.root / "server"), "http_addr": f"127.0.0.1:{self.ports['api']}",
            "control_addr": f"127.0.0.1:{self.ports['control']}",
            "tunnel_addr": f"127.0.0.1:{self.ports['data']}",
            "udp_addr": f"127.0.0.1:{self.ports['data']}",
            "tunnel_endpoint": f"127.0.0.1:{self.ports['data']}",
            "public_bind": "127.0.0.1", "caddy.enabled": False,
        })
        smoke.wait_for(lambda: self.api("auth/status"), "性能测试 Server 启动")


def download(port, length):
    started = time.perf_counter()
    with socket.create_connection(("127.0.0.1", port), timeout=60) as stream:
        stream.sendall(struct.pack("!Q", length))
        stream.shutdown(socket.SHUT_WR)
        count = 0
        while chunk := stream.recv(65536):
            assert chunk == b"x" * len(chunk), "响应内容不一致"
            count += len(chunk)
        assert count == length, (count, length)
    return (time.perf_counter() - started) * 1000


def usage(pid):
    # Linux /proc 直接读取进程累计 CPU 和 RSS，不采集命令行、环境或凭据。
    data = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    cpu = (int(data[11]) + int(data[12])) / os.sysconf("SC_CLK_TCK")
    rss = int(data[21]) * os.sysconf("SC_PAGE_SIZE")
    return cpu, rss


def retransmits():
    lines = Path("/proc/net/snmp").read_text().splitlines()
    for index, line in enumerate(lines):
        if line.startswith("Tcp:"):
            return int(dict(zip(line.split()[1:], lines[index + 1].split()[1:]))["RetransSegs"])
    raise RuntimeError("内核未提供 TCP 重传计数")


def network(port, rtt, loss):
    """仅在专属 network namespace 的 lo 上设置端口过滤，不接触宿主网络。"""
    subprocess.run(["tc", "qdisc", "del", "dev", "lo", "root"], capture_output=True)
    if not rtt and not loss:
        return
    def tc(*args):
        subprocess.run(["tc", *args], check=True, capture_output=True)
    tc("qdisc", "add", "dev", "lo", "root", "handle", "1:", "prio", "bands", "3",
       "priomap", *(["0"] * 16))
    tc("qdisc", "add", "dev", "lo", "parent", "1:3", "handle", "30:", "netem",
       "delay", f"{rtt / 2}ms", "loss", f"{loss}%", "limit", "10000")
    for field in ("sport", "dport"):
        tc("filter", "add", "dev", "lo", "protocol", "ip", "parent", "1:", "prio", "1",
           "u32", "match", "ip", field, str(port), "0xffff", "flowid", "1:3")


def measure(harness, port, concurrency, workload, total_bytes):
    before = {name: usage(proc.pid)[0] for name, proc in [("server", harness.server), ("agent", harness.agent)]}
    peak = {"server": 0, "agent": 0}
    stop = threading.Event()
    def sample():
        while not stop.is_set():
            for name, proc in [("server", harness.server), ("agent", harness.agent)]:
                peak[name] = max(peak[name], usage(proc.pid)[1])
            stop.wait(0.01)
    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    start_retransmits = retransmits()
    started = time.perf_counter()
    sizes = []
    latencies = []
    try:
        # 各并发使用相同总下载量，短请求每个 worker 5 次；混合时两组同时开始。
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency * 2) as pool:
            start = threading.Barrier(concurrency * (2 if workload == "mixed" else 1))
            def worker(short):
                start.wait()
                lengths = [1024] * 5 if short else [total_bytes // concurrency]
                return lengths, [download(port, length) for length in lengths]
            futures = []
            if workload != "short":
                futures.extend((False, pool.submit(worker, False)) for _ in range(concurrency))
            if workload != "bulk":
                futures.extend((True, pool.submit(worker, True)) for _ in range(concurrency))
            for short, future in futures:
                lengths, values = future.result()
                sizes.extend(lengths)
                if short:
                    latencies.extend(values)
        elapsed = time.perf_counter() - started
    finally:
        stop.set()
        sampler.join()
    cpu = {name: round(usage(proc.pid)[0] - before[name], 4) for name, proc in [("server", harness.server), ("agent", harness.agent)]}
    return {
        "seconds": round(elapsed, 4), "payload_bytes": sum(sizes), "requests": len(sizes),
        "payload_mib_s": round(sum(sizes) / elapsed / 1048576, 3),
        "short_p95_ms": round(sorted(latencies)[math.ceil(len(latencies) * .95) - 1], 3) if latencies else None,
        "cpu_seconds": cpu, "peak_rss_bytes": peak,
        "tcp_retransmits": retransmits() - start_retransmits,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--agent-bin", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--label", default="default-8k-nagle")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--mib", type=int, default=8)
    parser.add_argument("--netem", action="store_true")
    args = parser.parse_args()
    if os.name != "posix" or not Path("/proc/net/snmp").exists():
        parser.error("CPU/RSS/重传采样要求 Linux")
    if args.netem and os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        parser.error("--netem 必须在独立 network namespace 中运行")
    if args.repetitions < 1 or args.mib < 1:
        parser.error("重复次数与 MiB 必须大于零")
    harness = Harness(args)
    origin = OriginServer(("127.0.0.1", 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    report = {"label": args.label, "kernel": os.uname().release, "total_bulk_mib": args.mib,
              "repetitions": args.repetitions, "scenarios": [], "temporary_directory": str(harness.root)}
    target = Path(args.report)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        harness.start_server()
        harness.csrf = harness.api("auth/login", "POST", {"username": "admin", "password": "Test-tunnel-only-4821!"})["csrf_token"]
        harness.start_agent(harness.api("agent-access-key", "POST", {})["token"])
        device = smoke.wait_for(lambda: next((r["id"] for r in harness.api("devices") if r["status"] == "online"), None), "Agent 上线")
        tunnel = harness.api("tunnels", "POST", {"name": "performance", "protocol": "tcp", "device_id": device,
            "local_address": "127.0.0.1", "local_port": origin.server_address[1], "public_port": harness.ports["public"], "enabled": True})
        smoke.wait_for(lambda: harness.ready(tunnel["id"]), "TCP 隧道就绪")
        conditions = [(0, 0)] + ([(50, 0), (100, 0), (0, .1), (0, 1)] if args.netem else [])
        for rtt, loss in conditions:
            for concurrency in (1, 8, 32):
                for workload in ("bulk", "short", "mixed"):
                    for repetition in range(args.repetitions):
                        # 交替先后顺序，减小缓存和温度导致的单向偏差。
                        for path in (("direct", "tunnel") if repetition % 2 == 0 else ("tunnel", "direct")):
                            if args.netem:
                                network(origin.server_address[1] if path == "direct" else harness.ports["data"], rtt, loss)
                            before = harness.api("traffic/quota")["used_bytes"]
                            row = {"path": path, "rtt_ms": rtt, "loss_percent": loss, "concurrency": concurrency,
                                   "workload": workload, "repetition": repetition}
                            row.update(measure(harness, origin.server_address[1] if path == "direct" else harness.ports["public"], concurrency, workload, args.mib * 1048576))
                            expected = row["payload_bytes"] + 8 * row["requests"] if path == "tunnel" else 0
                            actual = harness.api("traffic/quota")["used_bytes"] - before
                            assert actual == expected, f"额度计数不一致：{actual} != {expected}"
                            row["quota_bytes"] = actual
                            report["scenarios"].append(row)
                            target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
                            print(json.dumps(row), flush=True)
    finally:
        if args.netem:
            subprocess.run(["tc", "qdisc", "del", "dev", "lo", "root"], capture_output=True)
        harness.close()
        origin.shutdown()
        origin.server_close()


if __name__ == "__main__":
    main()
