#!/usr/bin/env python3
"""独立临时目录运行真实 Server/Agent，验证 UDP、组合服务及资源用量，不连接公网。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import statistics
import threading
import time
import urllib.error

spec = importlib.util.spec_from_file_location("tunnel_smoke", Path(__file__).with_name("tunnel-smoke.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Echo(socketserver.BaseRequestHandler):
    targets = {}
    def handle(self):
        payload, socket_ = self.request
        self.targets[payload] = self.client_address
        socket_.sendto(getattr(self.server, "prefix", b"") + payload, self.client_address)


class Proxy:
    """只转发本机 QUIC 流量，可模拟公网 UDP 被阻断，不修改主机防火墙。"""
    def __init__(self, target):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        self.target = ("127.0.0.1", target)
        self.client = None
        self.blocked = False
        self.closed = False
        self.drop_every = 0
        self.delay = 0
        self.received = 0
        self.socket.settimeout(0.2)
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while not self.closed:
            try:
                payload, source = self.socket.recvfrom(65536)
                self.received += 1
                if self.blocked or (self.drop_every and self.received % self.drop_every == 0):
                    continue
                if self.delay:
                    time.sleep(self.delay)
                if source == self.target:
                    if self.client:
                        self.socket.sendto(payload, self.client)
                else:
                    self.client = source
                    self.socket.sendto(payload, self.target)
            except (socket.timeout, ConnectionResetError):
                pass
            except OSError:
                break

    def close(self):
        self.closed = True
        self.socket.close()


def exchange(client, port, payload, attempts=3):
    for attempt in range(attempts):
        client.sendto(payload, ("127.0.0.1", port))
        try:
            received = client.recv(65536)
            assert received == payload, "UDP 数据报串线或边界损坏"
            return
        except socket.timeout:
            if attempt + 1 == attempts:
                raise


def client():
    result = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    result.bind(("127.0.0.1", 0))
    result.settimeout(3)
    return result


def memory(pid):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [(name, ctypes.c_size_t) for name in ["peak", "working", "paged_peak", "paged", "nonpaged_peak", "nonpaged", "pagefile", "pagefile_peak"]]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x410, False, pid)
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        query = ctypes.WinDLL("psapi").GetProcessMemoryInfo
        query.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        try:
            if not query(handle, ctypes.byref(counters), counters.cb):
                raise ctypes.WinError(ctypes.get_last_error())
            return round(counters.working / 1048576, 2)
        finally:
            kernel.CloseHandle(handle)
    return round(int(Path(f"/proc/{pid}/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1048576, 2)


class Harness(base.Harness):
    def __init__(self, args):
        super().__init__(args)
        self.proxy = Proxy(self.ports["data"])
        self.measurements = []

    def start_server(self):
        self.server = self.launch("server", self.args.server_bin, {
            "NEXO_ADMIN_USERNAME": "admin", "NEXO_ADMIN_PASSWORD": "Test-udp-only-4821!",
            "NEXO_DATA_DIR": str(self.root / "server"), "NEXO_HTTP_ADDR": f"127.0.0.1:{self.ports['api']}",
            "NEXO_CONTROL_ADDR": f"127.0.0.1:{self.ports['control']}", "NEXO_TUNNEL_ADDR": f"127.0.0.1:{self.ports['data']}",
            "NEXO_TUNNEL_ENDPOINT": f"127.0.0.1:{self.ports['data']}", "NEXO_PUBLIC_BIND": "127.0.0.1",
            "NEXO_UDP_ADDR": f"127.0.0.1:{self.ports['data']}", "NEXO_UDP_ENDPOINT": f"127.0.0.1:{self.proxy.port}", "NEXO_CADDY_ENABLED": "false",
        })
        base.wait_for(lambda: self.api("auth/status"), "Server 启动")

    def run(self):
        tcp = base.EchoServer(("127.0.0.1", 0), base.Echo)
        udp = socketserver.UDPServer(tcp.server_address, Echo)
        udp.max_packet_size = 65536
        for service in [tcp, udp]:
            threading.Thread(target=service.serve_forever, daemon=True).start()
        try:
            self.start_server()
            self.csrf = self.api("auth/login", "POST", {"username": "admin", "password": "Test-udp-only-4821!"})["csrf_token"]
            invite = self.api("enrollments", "POST", {"ttl_seconds": 3600})
            self.start_agent(invite["token"])
            base.wait_for(lambda: any(r["status"] == "awaiting_approval" for r in self.api("enrollments")), "Agent CSR")
            device = self.api(f"enrollments/{invite['id']}/approve", "POST", {"device_name": "UDP 验收 Agent"})["device_id"]
            base.wait_for(lambda: any(d["id"] == device and d["status"] == "online" for d in self.api("devices")), "控制通道上线")
            time.sleep(.3)
            assert self.proxy.received == 0, "未启用 UDP 服务时不应建立 QUIC"
            self.check("没有 UDP 服务时不建立额外数据连接")
            body = {"name": "远程桌面", "protocol": "tcp_udp", "device_id": device, "local_address": "127.0.0.1", "local_port": tcp.server_address[1], "public_port": self.ports["public"], "enabled": True}
            tunnel = self.api("tunnels", "POST", body)
            base.wait_for(lambda: self.ready(tunnel["id"]), "TCP+UDP 两种通道就绪")
            base.exchange(body["public_port"], b"tcp-and-udp")
            with client() as sock:
                for size in [0, 1, 1200, 4096, 65507]:
                    exchange(sock, body["public_port"], bytes([size % 251]) * size)
            self.check("真实 TCP+UDP 同端口、零长度和 65507 字节数据报")

            with client() as stable:
                exchange(stable, body["public_port"], b"stable-client")
                origin_peer = Echo.targets[b"stable-client"]
                for index in range(8):
                    with client() as closed:
                        closed.sendto(b"closed-client", ("127.0.0.1", body["public_port"]))
                    time.sleep(.1)
                    exchange(stable, body["public_port"], b"stable-client")
                    assert Echo.targets[b"stable-client"] == origin_peer, "单个客户端关闭不能重建其他 UDP 会话"
            self.check("客户端关闭引发 ICMP 不影响其他 UDP 会话")

            for count in [1, 32, 128, 512, 1024]:
                self.agent.terminate()
                self.agent.wait(timeout=10)
                self.start_agent()
                time.sleep(1)
                base.wait_for(lambda: self.ready(tunnel["id"]), "Agent 重连")
                sockets = []
                latency = []
                try:
                    for index in range(count):
                        sock = client()
                        sockets.append(sock)
                        exchange(sock, body["public_port"], index.to_bytes(4, "big") * 16)
                    for index, sock in enumerate(sockets):
                        start = time.perf_counter()
                        exchange(sock, body["public_port"], index.to_bytes(4, "big") * 16)
                        latency.append((time.perf_counter() - start) * 1000)
                    row = {"sessions": count, "server_rss_mib": memory(self.server.pid), "agent_rss_mib": memory(self.agent.pid), "p50_ms": round(statistics.median(latency), 2), "p95_ms": round(sorted(latency)[int((count-1)*.95)], 2)}
                    self.measurements.append(row)
                    self.check("并发隔离与资源测量 " + json.dumps(row))
                finally:
                    for sock in sockets:
                        sock.close()

            self.proxy.blocked = True
            base.wait_for(lambda: any(t["id"] == tunnel["id"] and t["apply_status"] == "partial" for t in self.api("tunnels")), "阻断 UDP 后部分可用", timeout=65)
            base.exchange(body["public_port"], b"tcp-survives-udp-failure")
            self.proxy.blocked = False
            base.wait_for(lambda: self.ready(tunnel["id"]), "UDP 恢复", timeout=65)
            with client() as sock:
                exchange(sock, body["public_port"], b"udp-restored")
            self.check("UDP 阻断时 TCP 保留，恢复后无需保存配置")
            self.proxy.drop_every = 17
            self.proxy.delay = .02
            try:
                for index in range(10):
                    with client() as sock:
                        exchange(sock, body["public_port"], f"loss-delay-{index}".encode())
            finally:
                self.proxy.drop_every = 0
                self.proxy.delay = 0
            self.check("QUIC 丢包与延迟环境下应用重试可恢复响应")


            self.api(f"tunnels/{tunnel['id']}", "PUT", {**body, "enabled": False})
            with client() as sock:
                sock.settimeout(.5)
                sock.sendto(b"disabled", ("127.0.0.1", body["public_port"]))
                try:
                    sock.recv(1024)
                    raise AssertionError("停用后仍有 UDP 回包")
                except (socket.timeout, ConnectionResetError):
                    pass
            self.api(f"tunnels/{tunnel['id']}", "PUT", body)
            base.wait_for(lambda: self.ready(tunnel["id"]), "重新启用")
            self.check("组合服务停用与恢复")
            self.stop_server()
            self.start_server()
            self.csrf = self.api("auth/login", "POST", {"username": "admin", "password": "Test-udp-only-4821!"})["csrf_token"]
            base.wait_for(lambda: self.ready(tunnel["id"]), "保留数据和身份的进程重启")
            with client() as sock:
                exchange(sock, body["public_port"], b"restart")
            self.check("重启保留服务、身份及组合协议")
            before = self.api("traffic/quota")["used_bytes"]
            with client() as sock:
                exchange(sock, body["public_port"], b"meter-exact")
            used = self.api("traffic/quota")["used_bytes"]
            assert used - before == 2 * len(b"meter-exact"), "UDP 统计必须只计算应用载荷"
            quota_path = f"admin/traffic/quota?user_id={self.api('auth/status')['user_id']}"
            self.api(quota_path, "PUT", {"monthly_limit_bytes": used + 1})
            with client() as sock:
                sock.settimeout(.5)
                sock.sendto(b"too-large", ("127.0.0.1", body["public_port"]))
                try:
                    sock.recv(1024)
                    raise AssertionError("余额不足时不应转发数据报")
                except socket.timeout:
                    pass
            assert self.api("traffic/quota")["used_bytes"] == used
            self.api(quota_path, "PUT", {"monthly_limit_bytes": None})
            self.check("UDP 双向精确计数、余额不足整包拒绝及恢复额度")
            with socket.socket() as occupied:
                occupied.bind(("127.0.0.1", 0))
                occupied.listen()
                partial = self.api("tunnels", "POST", {**body, "name": "TCP 端口冲突", "public_port": occupied.getsockname()[1]})
                base.wait_for(lambda: any(t["id"] == partial["id"] and t["apply_status"] == "partial" and t["protocol_statuses"]["udp"]["status"] == "ready" for t in self.api("tunnels")), "TCP 监听冲突时 UDP 保留")
                with client() as sock:
                    exchange(sock, partial["public_port"], b"udp-survives-tcp-conflict")
            base.wait_for(lambda: self.ready(partial["id"]), "TCP 端口释放后恢复")
            base.exchange(partial["public_port"], b"tcp-recovered")
            self.api(f"tunnels/{partial['id']}", "DELETE")
            self.check("TCP 监听冲突时 UDP 保留，端口释放后自动恢复")

            # 同一个公网客户端在修改目标后必须进入新版本会话，旧 socket 不能继续回包。
            replacement = socketserver.UDPServer(("127.0.0.1", 0), Echo)
            replacement.prefix = b"new-origin:"
            replacement.max_packet_size = 65536
            threading.Thread(target=replacement.serve_forever, daemon=True).start()
            try:
                single = self.api("tunnels", "POST", {**body, "name": "UDP 独立服务", "protocol": "udp", "public_port": None})
                base.wait_for(lambda: self.ready(single["id"]), "UDP 独立服务")
                with client() as sock:
                    exchange(sock, single["public_port"], b"original")
                    self.api(f"tunnels/{single['id']}", "PUT", {**body, "protocol": "udp", "public_port": single["public_port"], "local_port": replacement.server_address[1]})
                    base.wait_for(lambda: self.ready(single["id"]), "UDP 目标更新")
                    sock.sendto(b"changed", ("127.0.0.1", single["public_port"]))
                    assert sock.recv(65536) == b"new-origin:changed"
                    self.api(f"tunnels/{single['id']}", "DELETE")
                    sock.settimeout(.5)
                    sock.sendto(b"deleted", ("127.0.0.1", single["public_port"]))
                    try:
                        sock.recv(65536)
                        raise AssertionError("删除后旧 UDP 会话仍可转发")
                    except (socket.timeout, ConnectionResetError):
                        pass
                self.check("独立 UDP 服务修改目标撤销旧会话、删除撤销公网入口")
            finally:
                replacement.shutdown()
                replacement.server_close()
            class IPv6Server(socketserver.UDPServer):
                address_family = socket.AF_INET6
            v6 = IPv6Server(("::1", 0), Echo)
            threading.Thread(target=v6.serve_forever, daemon=True).start()
            try:
                single = self.api("tunnels", "POST", {**body, "name": "IPv6 UDP", "protocol": "udp", "public_port": None, "local_address": "::1", "local_port": v6.server_address[1]})
                base.wait_for(lambda: self.ready(single["id"]), "IPv6 UDP 目标")
                with client() as sock:
                    exchange(sock, single["public_port"], b"ipv6-origin")
                self.api(f"tunnels/{single['id']}", "DELETE")
                self.check("真实 IPv6 UDP 回源")
            finally:
                v6.shutdown()
                v6.server_close()
            if self.args.idle:
                sockets = [client() for _ in range(3)]
                try:
                    for index, sock in enumerate(sockets):
                        exchange(sock, body["public_port"], f"idle-{index}".encode())
                    started = time.monotonic()
                    for index, minutes in enumerate([1, 5, 15]):
                        target = started + minutes * 60 + (2 if minutes >= 5 else 0)
                        while time.monotonic() < target:
                            time.sleep(min(10, target - time.monotonic()))
                        sock = sockets[index]
                        udp.socket.sendto(b"origin-push", Echo.targets[f"idle-{index}".encode()])
                        sock.settimeout(.5)
                        if minutes == 1:
                            assert sock.recv(1024) == b"origin-push"
                        else:
                            try:
                                sock.recv(1024)
                                raise AssertionError("过期会话不应继续接收内网推送")
                            except socket.timeout:
                                pass
                        sock.settimeout(3)
                        exchange(sock, body["public_port"], f"resume-{index}".encode())
                        self.check(f"空闲 {minutes} 分钟：内网推送边界及客户端恢复")
                finally:
                    for sock in sockets:
                        sock.close()
        finally:
            for service in [tcp, udp]:
                service.shutdown()
                service.server_close()

    def close(self):
        super().close()
        self.proxy.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--agent-bin", required=True)
    parser.add_argument("--report")
    parser.add_argument("--idle", action="store_true", help="额外运行 1/5/15 分钟真实空闲验收")
    args = parser.parse_args()
    harness = Harness(args)
    print("Test directory:", harness.root, flush=True)
    try:
        harness.run()
        if args.report:
            Path(args.report).write_text(json.dumps({"checks": harness.checks, "measurements": harness.measurements, "rdp": "not tested"}, ensure_ascii=False, indent=2), encoding="utf-8")
    finally:
        harness.close()
