#!/usr/bin/env python3
"""本地 Nexo/frp TCP 与 HTTPS 对照；自建 namespace，无宿主路由和线上操作。"""
import argparse
import copy
import gzip
import importlib.util
import json
import os
from pathlib import Path
import random
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

spec = importlib.util.spec_from_file_location("smoke", Path(__file__).with_name("tunnel-smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
SERVER, CLIENT = "10.231.0.1", "10.231.0.2"
HOST = "secure.nexo-smoke.localhost"
CONDITIONS = {"unlimited": (0, 0, 0), "100m": (100, 0, 0), "rtt50": (100, 50, 0),
              "rtt100": (100, 100, 0), "loss01": (100, 0, .1), "loss1": (100, 0, 1)}


def command(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def get_json(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=10) as r:
        return json.load(r)


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


class Harness(smoke.Harness):
    """仅改测试实例的绑定和启动 namespace，认证、协调和 Caddy 都走真实产品路径。"""
    def __init__(self, args, root):
        super().__init__(args)
        self.root.rmdir()
        self.destination = root / str(time.time_ns())
        # SQLite、身份与运行日志放在 Linux 原生文件系统；测量后归档，避免 WSL /mnt/d I/O 干扰。
        self.root = Path(tempfile.mkdtemp(prefix="nfp-case-"))
        # Unix socket 路径长度有限；测量产物可在较深目录，运行时必须使用短临时路径。
        self.runtime = Path(tempfile.mkdtemp(prefix="nfp-"))
        self.resources = {}

    def launch(self, name, binary, config):
        agent = "server_url" in config
        if agent:
            config.update(server_url=f"http://{SERVER}:{self.ports['api']}",
                          control_endpoint=f"{SERVER}:{self.ports['control']}",
                          tunnel_endpoint=f"{SERVER}:{self.ports['data']}")
        else:
            for key in ("http_addr", "control_addr", "tunnel_addr", "udp_addr"):
                config[key] = config[key].replace("127.0.0.1", "0.0.0.0")
            config["tunnel_endpoint"] = f"{SERVER}:{self.ports['data']}"
            config["udp_endpoint"] = f"{SERVER}:{self.ports['data']}"
            config["runtime_dir"] = str(self.runtime)
        directory = Path(config.pop("data_dir")); directory.mkdir(parents=True, exist_ok=True)
        component = "agent" if agent else "server"
        (directory / f"{component}.toml").write_text("\n".join(f"{k} = {json.dumps(v)}" for k, v in config.items()))
        prefix = ["ip", "netns", "exec", self.args.client_ns] if agent else []
        return self.spawn(name, prefix + [binary, "--data-dir", str(directory)])

    def spawn(self, name, argv):
        log = (self.root / f"{name}-{len(self.logs)}.log").open("wb"); self.logs.append(log)
        p = subprocess.Popen([str(a) for a in argv], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        self.processes.append(p); self.resources[name] = p.pid
        return p

    def prepare_local_certificates(self):
        destination = self.root / "server/caddy-storage"
        if not destination.exists():
            shutil.copytree(self.args.seed / "server/caddy-storage", destination)

    def setup(self, topology):
        self.start_server()
        self.csrf = self.api("auth/login", "POST", {"username": "admin", "password": "Test-tunnel-only-4821!"})["csrf_token"]
        self.start_agent(self.api("agent-access-key", "POST", {})["token"])
        device = smoke.wait_for(lambda: next((d["id"] for d in self.api("devices") if d["status"] == "online"), None), "Agent 就绪")
        local_port = {"tcp": 18081, "passthrough": 18443, "domain": 18080}[topology]
        body = {"name": "secure", "protocol": "tcp", "device_id": device, "local_address": "127.0.0.1",
                "local_port": local_port, "public_port": self.ports["public"], "enabled": True}
        if topology == "domain":
            domain = self.api("public-domains", "POST", {"domain": "nexo-smoke.localhost", "https_enabled": True})
            with sqlite3.connect(self.root / "server/nexo.db") as db:
                db.execute("UPDATE domain_settings SET verified=1,certificate_mode='http01' WHERE domain_id=?", (domain["id"],))
            body.update(protocol="https", public_port=None, hostname="secure", public_domain_id=domain["id"])
        tunnel = self.api("tunnels", "POST", body)
        smoke.wait_for(lambda: self.ready(tunnel["id"]), "隧道就绪")
        self.tunnel_id = tunnel["id"]
        # Caddy 是 Server 的子进程，必须纳入域名入口 CPU/RSS，而非漏算代理成本。
        children = Path(f"/proc/{self.server.pid}/task/{self.server.pid}/children").read_text().split()
        for child in children:
            if "caddy" in Path(f"/proc/{child}/comm").read_text(): self.resources["caddy"] = int(child)
        return f"127.0.0.1:{self.ports['https' if topology == 'domain' else 'public']}"

    def close(self):
        # 每个进程自有进程组，包括其 Caddy 子进程；只清理本夹具创建的进程。
        for p in reversed(self.processes):
            try: os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError: pass
        for p in reversed(self.processes):
            try: p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL); p.wait()
        for log in self.logs: log.close()
        shutil.copytree(self.root, self.destination)
        shutil.rmtree(self.root)
        shutil.rmtree(self.runtime)


def frp(h, topology, certs):
    port = {"tcp": 18081, "passthrough": 18443, "domain": 18080}[topology]
    server = f'''bindAddr = "{SERVER}"
bindPort = 17000
proxyBindAddr = "127.0.0.1"
auth.method = "token"
auth.token = "isolated-performance-fixture"
transport.tcpMux = true
transport.tls.force = true
transport.tls.certFile = "{certs}/peer.crt"
transport.tls.keyFile = "{certs}/peer.key"
transport.tls.trustedCaFile = "{certs}/ca.crt"
'''
    client = f'''serverAddr = "{SERVER}"
serverPort = 17000
auth.method = "token"
auth.token = "isolated-performance-fixture"
transport.protocol = "tcp"
transport.poolCount = 0
transport.tcpMux = true
transport.tls.enable = true
transport.tls.certFile = "{certs}/peer.crt"
transport.tls.keyFile = "{certs}/peer.key"
transport.tls.trustedCaFile = "{certs}/ca.crt"
transport.tls.serverName = "frp.test"
[[proxies]]
name = "performance"
type = "tcp"
localIP = "127.0.0.1"
localPort = {port}
remotePort = 17001
transport.useEncryption = false
transport.useCompression = false
'''
    for name, data in [("frps", server), ("frpc", client)]: (h.root / f"{name}.toml").write_text(data)
    h.frps = h.spawn("server", [h.args.frps_bin, "-c", h.root / "frps.toml"])
    def server_ready():
        with socket.create_connection((SERVER, 17000), timeout=1): return True
    smoke.wait_for(server_ready, "frps 监听就绪")
    h.frpc = h.spawn("agent", ["ip", "netns", "exec", h.args.client_ns, h.args.frpc_bin, "-c", h.root / "frpc.toml"])
    def ready():
        with socket.create_connection(("127.0.0.1", 17001), timeout=1): return True
    smoke.wait_for(ready, "frp 就绪")
    return "127.0.0.1:17001"


def caddy(h, template, upstream):
    config = copy.deepcopy(template)
    config["admin"] = {"listen": f"127.0.0.1:{h.ports['admin']}"}
    config["storage"]["root"] = str(h.args.seed / "server/caddy-storage")
    for name, srv in config["apps"]["http"]["servers"].items():
        srv["listen"] = [f"127.0.0.1:{h.ports['https' if name == 'https' else 'http']}"]
    def replace(value):
        if isinstance(value, dict):
            if value.get("handler") == "reverse_proxy" and any(str(u.get("dial", "")).startswith("unix/") for u in value.get("upstreams", [])):
                value["upstreams"] = [{"dial": upstream}]
            for item in value.values(): replace(item)
        elif isinstance(value, list):
            # Nexo 的公开入口也经过内部访问检查。frp/直连没有 Nexo 控制面，
            # 只复用通用 Caddy 配置；不能保留指向已退出夹具的访问检查代理。
            value[:] = [item for item in value if not (isinstance(item, dict) and item.get("handler") == "reverse_proxy"
                        and any("X-Nexo-Access" in key for key in item.get("headers", {}).get("request", {}).get("set", {})))]
            for item in value: replace(item)
    replace(config)
    write_json(h.root / "caddy.json", config)
    h.spawn("caddy", [h.args.caddy_bin, "run", "--config", h.root / "caddy.json"])
    smoke.wait_for(lambda: get_json(f"http://127.0.0.1:{h.ports['admin']}/config/"), "Caddy 就绪")
    return f"127.0.0.1:{h.ports['https']}"


def shape(args, condition):
    rate, rtt, loss = CONDITIONS[condition]
    for prefix in ([], ["ip", "netns", "exec", args.client_ns]):
        subprocess.run(prefix + ["tc", "qdisc", "del", "dev", "perf0", "root"], capture_output=True)
        if rate or rtt or loss:
            argv = prefix + ["tc", "qdisc", "add", "dev", "perf0", "root", "netem", "limit", "10000", "delay", f"{rtt/2}ms", "loss", f"{loss}%"]
            if rate: argv += ["rate", f"{rate}mbit"]
            command(*argv)


def usage(pid):
    data = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return ((int(data[11]) + int(data[12])) / os.sysconf("SC_CLK_TCK"), int(data[21]) * os.sysconf("SC_PAGE_SIZE"))


def netstats(args):
    snapshots = []
    for prefix in ([], ["ip", "netns", "exec", args.client_ns]):
        data = command(*prefix, "cat", "/proc/net/snmp", capture_output=True, text=True).stdout.splitlines()
        index = next(i for i, line in enumerate(data) if line.startswith("Tcp:"))
        tcp = dict(zip(data[index].split()[1:], map(int, data[index+1].split()[1:])))
        snapshots.append(tcp["RetransSegs"])
    return snapshots


def run_load(h, addr, row):
    args = h.args
    if h.server and h.server.poll() is None:
        h.resources.pop("caddy", None)
        for child in Path(f"/proc/{h.server.pid}/task/{h.server.pid}/children").read_text().split():
            if "caddy" in Path(f"/proc/{child}/comm").read_text(): h.resources["caddy"] = int(child)
    argv = [args.load_bin, "-addr", addr, "-ca", args.ca, "-protocol", row["protocol"], "-workload", row["workload"],
            "-mode", row["mode"], "-concurrency", str(row["concurrency"]), "-warm", str(args.warm), "-duration", str(args.duration),
            "-bulk-mib", str(args.bulk_mib), "-request-timeout", f"{args.request_timeout}s"]
    with (h.root / "load.json").open("wb") as output, (h.root / "load.log").open("wb") as errors:
        before = {k: usage(pid)[0] for k, pid in h.resources.items()}
        idle = {k: usage(pid)[1] for k, pid in h.resources.items()}
        peaks = {k: 0 for k in h.resources}; cpu = {}; retrans = netstats(args)
        load_started = time.monotonic()
        p = subprocess.Popen([str(a) for a in argv], stdout=output, stderr=errors, start_new_session=True)
        h.processes.append(p)
        h.resources["load"] = p.pid; before["load"] = 0; peaks["load"] = 0
        deadline = time.monotonic() + args.warm + args.duration + args.drain_timeout
        while True:
            exited = os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            for name, pid in h.resources.items():
                try:
                    current, rss = usage(pid); cpu[name] = current - before[name]; peaks[name] = max(peaks[name], rss)
                except FileNotFoundError: pass
            if exited is not None:
                p.wait(); break
            if time.monotonic() > deadline:
                p.kill(); p.wait(); raise TimeoutError("负载进程超时，原始日志已保存")
            time.sleep(.05)
        if p.returncode: raise RuntimeError(f"负载程序失败，查看 {h.root / 'load.log'}")
        result = json.loads((h.root / "load.json").read_text())
        result.update(cpu_seconds=cpu, peak_rss_bytes=peaks, idle_rss_bytes=idle,
                      tcp_retransmits=[b-a for a,b in zip(retrans, netstats(args))],
                      load_process_seconds=time.monotonic()-load_started)
        h.resources.pop("load")
        return result


def certificates(args):
    args.seed = args.output / "seed"
    if not (args.seed / "server/caddy-storage").exists():
        seed = smoke.Harness(args)
        try:
            # 全矩阵超过默认内部证书的 12 小时寿命；一次签发 72 小时，避免中途续签影响比较。
            storage = seed.root / "server/caddy-storage"
            config = {"admin": {"listen": f"127.0.0.1:{seed.ports['admin']}"},
                      "storage": {"module": "file_system", "root": str(storage)},
                      "apps": {"pki": {"certificate_authorities": {"local": {"install_trust": False}}},
                               "tls": {"certificates": {"automate": ["nexo-smoke.localhost", HOST]},
                                       "automation": {"policies": [{"issuers": [{"module": "internal", "lifetime": "72h"}]}]}}}}
            write_json(seed.root / "issue.json", config)
            with (seed.root / "issue.log").open("wb") as log:
                issuer = subprocess.Popen([args.caddy_bin, "run", "--config", str(seed.root / "issue.json")], stdout=log, stderr=log)
                try: smoke.wait_for(lambda: len(list((storage / "certificates/local").glob("*/*.crt"))) == 2, "签发测试证书")
                finally: issuer.terminate(); issuer.wait(timeout=10)
            shutil.copytree(storage / "certificates/local", storage / "certificates/acme-v02.api.letsencrypt.org-directory")
            shutil.copytree(seed.root / "server", args.seed / "server")
        finally:
            seed.close()
            shutil.rmtree(seed.root)
    storage = args.seed / "server/caddy-storage"
    args.ca = storage / "pki/authorities/local/root.crt"
    cert = storage / f"certificates/local/{HOST}/{HOST}.crt"
    key = cert.with_suffix(".key")
    frpcerts = args.seed / "frp"; frpcerts.mkdir(exist_ok=True)
    if not (frpcerts / "peer.crt").exists():
        command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "7", "-subj", "/CN=frp-test-ca",
                "-keyout", frpcerts / "ca.key", "-out", frpcerts / "ca.crt", capture_output=True)
        command("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=frp.test", "-keyout", frpcerts / "peer.key", "-out", frpcerts / "peer.csr", capture_output=True)
        (frpcerts / "extensions").write_text("subjectAltName=DNS:frp.test\nextendedKeyUsage=serverAuth,clientAuth\n")
        command("openssl", "x509", "-req", "-in", frpcerts / "peer.csr", "-CA", frpcerts / "ca.crt", "-CAkey", frpcerts / "ca.key",
                "-CAcreateserial", "-days", "7", "-extfile", frpcerts / "extensions", "-out", frpcerts / "peer.crt", capture_output=True)
    return cert, key, frpcerts


def cases(args):
    if getattr(args, "nodelay_server_bin", None):
        # 固定的配对实验，避免多个选择参数意外展开成笛卡尔积。
        rows = []
        rng = random.Random(20260930)
        for condition, concurrency, workload in (("unlimited", 1, "bulk"), ("unlimited", 8, "mixed"), ("rtt100", 8, "mixed")):
            for repetition in range(3):
                for topology in ("tcp", "domain"):
                    variants = ["default", "nodelay"]; rng.shuffle(variants)
                    for variant in variants:
                        rows.append(dict(topology=topology, condition=condition, concurrency=concurrency,
                                         protocol="tcp" if topology == "tcp" else "h1", mode="keepalive",
                                         workload=workload, repetition=repetition, path="nexo", variant=variant))
        return rows
    rows = []
    for topology in args.topologies.split(","):
        for condition in args.conditions.split(","):
            variants = [("tcp" if topology == "tcp" else "h1", "keepalive", w) for w in args.workloads.split(",")]
            if args.special and topology != "tcp" and condition in ("unlimited", "rtt100"):
                variants += [("h1", mode, "short") for mode in ("fresh", "resume")]
                variants += [("h2", "keepalive", w) for w in ("bulk", "short", "mixed")]
            for concurrency in map(int, args.concurrency.split(",")):
                for protocol, mode, workload in variants:
                    for repetition in range(args.repetitions):
                        paths = ["direct", "nexo", "frp"]
                        random.Random(20260929 + len(rows)).shuffle(paths)
                        for path in paths:
                            rows.append(dict(topology=topology, condition=condition, concurrency=concurrency, protocol=protocol,
                                             mode=mode, workload=workload, repetition=repetition, path=path))
    # 各拓扑交错运行，让早期样本同时覆盖 TCP/HTTPS，也减少按产品或拓扑集中运行的时间偏差。
    condition_order = {name: index for index, name in enumerate(args.conditions.split(","))}
    rows.sort(key=lambda r: (condition_order[r["condition"]], r["concurrency"], r["protocol"] == "h2",
                             r["mode"] != "keepalive", r["workload"], r["repetition"], r["topology"]))
    return rows


def verify_recovery(args, cert, key, include_frp=True):
    """在计时前验证身份复用、重连和持久化；不让恢复等待时间混入稳态性能。"""
    target = args.output / "recovery.json"
    if target.exists(): return
    check_args = copy.copy(args); check_args.warm = .2; check_args.duration = .5
    h = Harness(check_args, args.output / "recovery")
    checks = []
    try:
        h.spawn("origin", ["ip", "netns", "exec", args.client_ns, args.load_bin, "-role", "origin", "-cert", cert, "-key", key])
        addr = h.setup("domain")
        row = dict(protocol="h1", mode="keepalive", workload="short", concurrency=8)
        def probe():
            result = run_load(h, addr, row)
            return not any(w["errors"] for w in result["workers"]) and sum(w["requests"] for w in result["workers"]) > 0
        assert probe(), "HTTPS 初始验收失败"
        checks.append("受信任 CA / TLS 1.3 / 8 并发 HTTPS")
        # 错误 CA 必须在握手阶段失败，不能把跳过验证误记为 HTTPS 性能。
        wrong_ca = args.seed / "frp/ca.crt"
        attempt = command(args.load_bin, "-addr", addr, "-ca", wrong_ca, "-protocol", "h1", "-warm", "0", "-duration", ".2", capture_output=True, text=True)
        rejected = json.loads(attempt.stdout)["workers"]
        assert sum(w["requests"] for w in rejected) == 0 and any(w["errors"] for w in rejected), "错误 CA 未被拒绝"
        assert all("certificate" in message for w in rejected for message in w["errors"]), "错误 CA 验收出现非证书错误"
        checks.append("错误 CA 被拒绝")
        h.agent.terminate(); h.agent.wait(timeout=10)
        h.start_agent()
        smoke.wait_for(lambda: h.ready(h.tunnel_id), "Agent 重连")
        # apply_status 可能短暂保留 ready；等待真实请求成功确认数据面恢复。
        smoke.wait_for(probe, "HTTPS 数据通道恢复")
        checks.append("重启 Agent 后复用身份并恢复 HTTPS")
        quota = h.api("traffic/quota")["used_bytes"]
        h.stop_server(); h.start_server()
        h.csrf = h.api("auth/login", "POST", {"username": "admin", "password": "Test-tunnel-only-4821!"})["csrf_token"]
        assert h.api("traffic/quota")["used_bytes"] == quota, "Server 重启后额度未持久化"
        smoke.wait_for(lambda: h.ready(h.tunnel_id), "Server 重启恢复")
        smoke.wait_for(probe, "重启后 HTTPS 数据通道恢复")
        checks.append("重启 Server 后额度持久化及 HTTPS 恢复")
    finally: h.close()
    if not include_frp:
        write_json(target, {"passed": checks})
        return
    h = Harness(check_args, args.output / "recovery-frp")
    try:
        h.spawn("origin", ["ip", "netns", "exec", args.client_ns, args.load_bin, "-role", "origin", "-cert", cert, "-key", key])
        addr = frp(h, "passthrough", args.seed / "frp")
        assert probe(), "frp HTTPS 初始验收失败"
        h.frpc.terminate(); h.frpc.wait(timeout=10)
        h.frpc = h.spawn("agent", ["ip", "netns", "exec", args.client_ns, args.frpc_bin, "-c", h.root / "frpc.toml"])
        smoke.wait_for(probe, "frpc 重启恢复")
        checks.append("重启 frpc 后 HTTPS 恢复")
        h.frps.terminate(); h.frps.wait(timeout=10)
        h.frps = h.spawn("server", [args.frps_bin, "-c", h.root / "frps.toml"])
        smoke.wait_for(probe, "frps 重启恢复")
        checks.append("重启 frps 后 frpc 重连及 HTTPS 恢复")
        write_json(target, {"passed": checks})
    finally: h.close()


def inside(args):
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("内部测试进程必须运行在专属 network namespace")
    comparison = bool(args.nodelay_server_bin)
    for binary in (() if comparison else (args.frps_bin, args.frpc_bin)):
        if command(binary, "--version", capture_output=True, text=True).stdout.strip() != "0.71.0":
            raise ValueError("本对照固定使用 frp 0.71.0")
    cert, key, frpcerts = certificates(args)
    template_path = args.output / "caddy-template.json"
    if not template_path.exists():
        bootstrap = Harness(args, args.output / "bootstrap")
        try:
            bootstrap.spawn("origin", ["ip", "netns", "exec", args.client_ns, args.load_bin, "-role", "origin", "-cert", cert, "-key", key])
            bootstrap.setup("domain")
            write_json(template_path, get_json(f"http://127.0.0.1:{bootstrap.ports['admin']}/config/"))
        finally: bootstrap.close()
    template = json.loads(template_path.read_text())
    if comparison:
        # 两端同时更新及两种混搭都做真实恢复验收，不纳入性能轮数。
        for server, agent, name in ((args.server_bin, args.agent_bin, "default"),
                                   (args.nodelay_server_bin, args.nodelay_agent_bin, "nodelay"),
                                   (args.server_bin, args.nodelay_agent_bin, "old-server"),
                                   (args.nodelay_server_bin, args.agent_bin, "old-agent")):
            check_args = copy.copy(args)
            check_args.server_bin = server; check_args.agent_bin = agent
            check_args.output = args.output / "compatibility" / name
            check_args.output.mkdir(parents=True, exist_ok=True)
            verify_recovery(check_args, cert, key, include_frp=False)
            print(f"COMPATIBILITY {name} passed", flush=True)
    else:
        verify_recovery(args, cert, key)
    matrix = cases(args)
    matrix_path = args.output / "matrix.json"
    if matrix_path.exists() and json.loads(matrix_path.read_text()) != matrix:
        raise ValueError("输出目录已有不同测试矩阵，请使用新的输出目录")
    write_json(matrix_path, matrix)
    metadata = {"kernel": os.uname().release, "cpu_count": os.cpu_count(), "warm_seconds": args.warm, "duration_seconds": args.duration,
                "total_rounds": len(matrix), "frp_version": None if comparison else command(args.frps_bin, "--version", capture_output=True, text=True).stdout.strip(),
                "caddy_version": command(args.caddy_bin, "version", capture_output=True, text=True).stdout.strip(),
                "load_version": command("go", "version", capture_output=True, text=True).stdout.strip() if shutil.which("go") else "see build command",
                "conditions": CONDITIONS, "binary_paths": {k: getattr(args, k) for k in ("server_bin", "agent_bin", "frps_bin", "frpc_bin", "caddy_bin", "load_bin", "nodelay_server_bin", "nodelay_agent_bin")}}
    metadata["offloads_disabled"] = ["tso", "gso", "gro"]
    metadata["bulk_mib"] = args.bulk_mib
    metadata["request_timeout_seconds"] = args.request_timeout
    metadata["drain_timeout_seconds"] = args.drain_timeout
    metadata["selected_conditions"] = sorted({r["condition"] for r in matrix})
    metadata["selected_topologies"] = args.topologies.split(",")
    metadata["repetitions"] = args.repetitions
    metadata["concurrency"] = list(map(int, args.concurrency.split(",")))
    metadata["started_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    metadata_path = args.output / "metadata.json"
    if metadata_path.exists():
        previous = json.loads(metadata_path.read_text())
        for field in ("warm_seconds", "duration_seconds", "binary_paths", "frp_version", "caddy_version", "bulk_mib", "request_timeout_seconds", "drain_timeout_seconds"):
            if previous.get(field) != metadata[field]: raise ValueError(f"已有结果的 {field} 不同，请使用新的输出目录")
    write_json(metadata_path, metadata)
    for index, row in enumerate(matrix):
        target = args.output / f"{index:04d}.json.gz"
        if target.exists():
            with gzip.open(target, "rt") as saved:
                if json.load(saved).get("status") == "measured": continue
            target.rename(target.with_name(f"{target.stem}.failed-{time.time_ns()}.gz"))
        print(f"START {index+1}/{len(matrix)} {json.dumps(row)}", flush=True)
        root = args.output / "rounds" / f"{index:04d}"
        round_args = copy.copy(args)
        if row.get("variant") == "nodelay":
            round_args.server_bin = args.nodelay_server_bin; round_args.agent_bin = args.nodelay_agent_bin
        h = Harness(round_args, root)
        try:
            shape(args, "unlimited")
            h.spawn("origin", ["ip", "netns", "exec", args.client_ns, args.load_bin, "-role", "origin", "-cert", cert, "-key", key])
            smoke.wait_for(lambda: get_json(f"http://{CLIENT}:18082"), "源站就绪")
            topology, path = row["topology"], row["path"]
            addr = f"{CLIENT}:{ {'tcp':18081,'passthrough':18443,'domain':18080}[topology]}"
            if path == "nexo": addr = h.setup(topology)
            elif path == "frp": addr = frp(h, topology, frpcerts)
            if topology == "domain" and path != "nexo": addr = caddy(h, template, addr)
            before = get_json(f"http://{CLIENT}:18082")
            quota_before = h.api("traffic/quota")["used_bytes"] if path == "nexo" else 0
            shape(args, row["condition"])
            row["result"] = run_load(h, addr, row)
            # 保留网络条件让末尾 TLS/FIN 排队数据先排空，不能移除 qdisc 人为丢弃它们。
            time.sleep(.5)
            shape(args, "unlimited")
            # 待连接关闭后的 TLS close_notify/FIN 和流量计数可见，再核对全部预热及测量字节。
            time.sleep(.2)
            after = get_json(f"http://{CLIENT}:18082")
            row["origin_wire_bytes"] = {k: after[k]-before[k] for k in before}
            if path == "nexo":
                def sampled():
                    used = h.api("traffic/quota")["used_bytes"] - quota_before
                    total = h.api(f"traffic/history?range=1h&tunnel_id={h.tunnel_id}")["total"]
                    return (used, total) if sum(total.values()) == used else None
                # 额度是同步热路径，历史接口按后台周期采样；等待采样追上已结束的传输。
                used, traffic = smoke.wait_for(sampled, "流量采样追上额度", timeout=10)
                row["quota_bytes"] = used
                after = get_json(f"http://{CLIENT}:18082")
                row["origin_wire_bytes"] = {k: after[k]-before[k] for k in before}
                row["origin_equals_quota"] = used == sum(row["origin_wire_bytes"].values())
                row["traffic_bytes"] = traffic
                row["quota_matches_traffic"] = row["quota_bytes"] == sum(traffic.values())
                # TLS 关闭和连接取消允许排队字节未到达另一端，不能拿源站的读取数冒充 Server 成功写入数。
                # 透传路径的两端接收量构成下界、两端发送量构成上界；域名入口的 Caddy 会变换 HTTP 头，不能套用此界。
                if topology != "domain":
                    lower = row["origin_wire_bytes"]["read"] + row["result"]["wire_read"]
                    upper = row["origin_wire_bytes"]["written"] + row["result"]["wire_written"]
                    row["quota_wire_bounds"] = [lower, upper]
                    row["quota_within_wire_bounds"] = lower <= row["quota_bytes"] <= upper
            row["connections_after"] = command("ss", "-tn", capture_output=True, text=True).stdout
            workers = row["result"]["workers"]
            request_errors = sum(sum(w["errors"].values()) for w in workers)
            row["checks"] = {"payload_and_requests": request_errors == 0,
                             "single_h2_connection": row["protocol"] != "h2" or row["result"]["client_connections"] == 1,
                             "fresh_without_resumption": row["mode"] != "fresh" or sum(w["resumed_sessions"] for w in workers) == 0,
                             "resumption_observed": row["mode"] != "resume" or sum(w["resumed_sessions"] for w in workers) > 0}
            if "quota_matches_traffic" in row: row["checks"]["quota_matches_traffic"] = row["quota_matches_traffic"]
            if "quota_within_wire_bounds" in row: row["checks"]["quota_within_wire_bounds"] = row["quota_within_wire_bounds"]
            row["status"] = "measured"
        except (Exception, KeyboardInterrupt) as error:
            row.update(status="failed", error=str(error))
        finally:
            h.close()
            partial = target.with_name(target.name + ".partial")
            with gzip.open(partial, "wt", encoding="utf-8") as out: json.dump(row, out, ensure_ascii=False)
            partial.replace(target)
        print(f"DONE {index+1}/{len(matrix)} {row['status']}", flush=True)
        if (index+1) % 30 == 0 or index+1 == len(matrix):
            report = "performance-nodelay-report.py" if comparison else "performance-report.py"
            command(sys.executable, Path(__file__).with_name(report), args.output, "--report", args.output / "REPORT.md")
        if row["status"] == "failed": raise RuntimeError(row["error"])


def main():
    def interrupted(signum, frame): raise KeyboardInterrupt("测试被中断，清理专属进程和网络")
    signal.signal(signal.SIGTERM, interrupted)
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("server", "agent", "caddy", "frps", "frpc", "load"):
        p.add_argument(f"--{name}-bin", required=name not in ("frps", "frpc"))
    p.add_argument("--nodelay-server-bin", help="与当前版本进行固定 36 轮 NODELAY 对照")
    p.add_argument("--nodelay-agent-bin")
    p.add_argument("--request-timeout", type=float, default=30)
    p.add_argument("--drain-timeout", type=float, default=90)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--warm", type=float, default=5); p.add_argument("--duration", type=float, default=15)
    p.add_argument("--repetitions", type=int, default=3); p.add_argument("--concurrency", default="1,8")
    p.add_argument("--topologies", default="tcp,domain"); p.add_argument("--conditions", default="unlimited")
    p.add_argument("--workloads", default="bulk,mixed")
    p.add_argument("--bulk-mib", type=int, default=64)
    p.add_argument("--special", action="store_true"); p.add_argument("--client-ns", help=argparse.SUPPRESS)
    args = p.parse_args()
    if bool(args.nodelay_server_bin) != bool(args.nodelay_agent_bin): p.error("候选 Server/Agent 必须同时提供")
    if not args.nodelay_server_bin and not (args.frps_bin and args.frpc_bin): p.error("frp 对照必须提供 frps/frpc")
    if args.request_timeout <= 0 or args.drain_timeout <= 0: p.error("请求及收尾超时必须为正")
    if args.nodelay_server_bin and (args.warm, args.duration, args.repetitions, args.bulk_mib, args.request_timeout, args.drain_timeout) != (5, 15, 3, 64, 120, 150):
        p.error("NODELAY 对照固定预热 5 秒、测量 15 秒、3 次重复、64 MiB、请求超时 120 秒、收尾 150 秒")
    if os.name != "posix" or os.geteuid() != 0: p.error("要求 Linux root，以创建本测试专属网络 namespace")
    for executable in ("ip", "tc", "ss", "ethtool", "openssl"):
        if not shutil.which(executable): p.error(f"缺少测试工具：{executable}")
    if args.warm < 0 or args.duration <= 0 or args.repetitions < 1: p.error("预热不能为负，时长和重复次数必须为正")
    if not 1 <= args.bulk_mib <= 1024: p.error("每个大文件响应必须介于 1 和 1024 MiB")
    if any(c not in CONDITIONS for c in args.conditions.split(",")): p.error("未知网络条件")
    if any(t not in ("tcp", "passthrough", "domain") for t in args.topologies.split(",")): p.error("未知测试拓扑")
    if any(w not in ("bulk", "short", "mixed") for w in args.workloads.split(",")): p.error("未知负载")
    if any(int(c) < 1 for c in args.concurrency.split(",")): p.error("并发必须为正")
    args.output = args.output.resolve(); args.output.mkdir(parents=True, exist_ok=True)
    for name in ("server", "agent", "caddy", "frps", "frpc", "load", "nodelay_server", "nodelay_agent"):
        value = getattr(args, f"{name}_bin")
        if value: setattr(args, f"{name}_bin", str(Path(value).resolve()))
    if args.client_ns: return inside(args)
    namespaces = [f"nexo-frp-{os.getpid()}-{side}" for side in ("s", "c")]
    created = []
    try:
        for ns in namespaces:
            command("ip", "netns", "add", ns); created.append(ns)
            command("ip", "-n", ns, "link", "set", "lo", "up")
        command("ip", "-n", namespaces[0], "link", "add", "perf0", "type", "veth", "peer", "name", "peer0")
        command("ip", "-n", namespaces[0], "link", "set", "peer0", "netns", namespaces[1])
        command("ip", "-n", namespaces[1], "link", "set", "peer0", "name", "perf0")
        for ns, addr in zip(namespaces, (SERVER, CLIENT)):
            command("ip", "-n", ns, "addr", "add", addr+"/24", "dev", "perf0")
            command("ip", "-n", ns, "link", "set", "perf0", "mtu", "1500", "up")
            command("ip", "netns", "exec", ns, "ethtool", "-K", "perf0", "tso", "off", "gso", "off", "gro", "off", capture_output=True)
        child = subprocess.Popen(["ip", "netns", "exec", namespaces[0], sys.executable, str(Path(__file__).resolve()), *sys.argv[1:], "--client-ns", namespaces[1]], start_new_session=True)
        try:
            if child.wait() != 0: raise RuntimeError("隔离测试失败，已保留日志和逐轮结果")
        finally:
            if child.poll() is None:
                child.terminate()
                try: child.wait(timeout=30)
                except subprocess.TimeoutExpired: child.kill(); child.wait()
    finally:
        for ns in reversed(created):
            pids = command("ip", "netns", "pids", ns, capture_output=True, text=True).stdout.split()
            for pid in pids:
                try: os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError: pass
            command("ip", "netns", "del", ns)


if __name__ == "__main__": main()
