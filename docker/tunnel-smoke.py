#!/usr/bin/env python3
"""使用独立临时目录和随机回环端口验证真实 Server + Agent + Caddy，不连接公网 CA。"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import ssl
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


TAIL = b"\x00half-close-complete"


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while chunk := self.request.recv(65536):
                self.request.sendall(chunk)
            self.request.sendall(TAIL)
        except (OSError, ConnectionError):
            pass


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            pass  # 重启或停用时，既有回源连接会被主动关闭。

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            accept = base64.b64encode(hashlib.sha1((self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            while frame := self.rfile.read(2):
                if len(frame) < 2:
                    break
                mask = self.rfile.read(4)
                payload = self.rfile.read(frame[1] & 127)
                payload = bytes(value ^ mask[i % 4] for i, value in enumerate(payload))
                self.wfile.write(bytes([0x81, len(payload)]) + payload)
                self.wfile.flush()
            self.close_connection = True
            return
        payload = b"nexo-real-origin\n" if self.path != "/large" else bytes(range(256)) * 32768
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for(check, label, timeout=45):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError, urllib.error.URLError) as error:
            last = str(error)
        time.sleep(0.2)
    raise AssertionError(f"等待超时：{label}；最后结果：{last}")


def exchange(public_port, payload):
    with socket.create_connection(("127.0.0.1", public_port), timeout=20) as stream:
        def write():
            stream.sendall(payload)
            stream.shutdown(socket.SHUT_WR)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            sending = pool.submit(write)
            received = bytearray()
            while chunk := stream.recv(65536):
                received.extend(chunk)
            sending.result()
        assert received == payload + TAIL, f"TCP 字节不匹配：收到 {len(received)} 字节"


class Harness:
    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="nexo-e2e-"))
        self.ports = {key: port() for key in ["api", "control", "data", "admin", "http", "https", "public"]}
        assert len(set(self.ports.values())) == len(self.ports)
        self.url = f"http://127.0.0.1:{self.ports['api']}"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.csrf = ""
        self.processes = []
        self.logs = []
        self.checks = []
        self.server = None
        self.agent = None

    def check(self, text):
        self.checks.append(text)
        print("PASS", text, flush=True)

    def before_restart(self, device, tcp, secure):
        """可由证书续签验收复用当前真实转发环境。"""
        pass

    def api(self, path, method="GET", body=None):
        request = urllib.request.Request(self.url + "/api/v1/" + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers={"Content-Type": "application/json", "x-nexo-csrf": self.csrf})
        with self.opener.open(request, timeout=10) as response:
            return json.load(response)

    def launch(self, name, binary, env):
        log = open(self.root / f"{name}-{len(self.logs)}.log", "wb")
        self.logs.append(log)
        process = subprocess.Popen([str(Path(binary).resolve())], env={**os.environ, **env}, stdout=log, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        self.processes.append(process)
        return process

    def start_server(self):
        self.server = self.launch("server", self.args.server_bin, {
            "NEXO_DATA_DIR": str(self.root / "server"), "NEXO_HTTP_ADDR": f"127.0.0.1:{self.ports['api']}",
            "NEXO_CONTROL_ADDR": f"127.0.0.1:{self.ports['control']}", "NEXO_TUNNEL_ADDR": f"127.0.0.1:{self.ports['data']}",
            "NEXO_TUNNEL_ENDPOINT": f"127.0.0.1:{self.ports['data']}", "NEXO_PUBLIC_BIND": "127.0.0.1",
            "NEXO_CADDY_BIN": str(Path(self.args.caddy_bin).resolve()), "NEXO_CADDY_ENABLED": "true",
            "NEXO_CADDY_ADMIN_URL": f"http://127.0.0.1:{self.ports['admin']}",
            "NEXO_CADDY_HTTP_LISTEN": f"127.0.0.1:{self.ports['http']}", "NEXO_CADDY_HTTPS_LISTEN": f"127.0.0.1:{self.ports['https']}",
            "NEXO_CLOUDFLARE_API_TOKEN": "",
        })
        def started():
            assert self.server.poll() is None, f"Server 已退出，请查看 {self.logs[-1].name}"
            return self.api("auth/status")
        wait_for(started, "Server 启动")

    def start_agent(self, token="", directory="agent"):
        self.agent = self.launch(directory, self.args.agent_bin, {
            "NEXO_SERVER_URL": self.url, "NEXO_STATE_DIR": str(self.root / directory), "NEXO_ENROLLMENT_TOKEN": token,
            "NEXO_CONTROL_ENDPOINT": f"127.0.0.1:{self.ports['control']}", "NEXO_TUNNEL_ENDPOINT": f"127.0.0.1:{self.ports['data']}",
        })
        return self.agent

    def stop_server(self):
        if self.server and self.server.poll() is None:
            self.server.terminate()
            self.server.wait(timeout=10)
            if os.name != "nt":
                assert self.server.returncode == 0, "Server 未正常处理 SIGTERM"
                assert not list((self.root / "server/tunnel-sockets").glob("*.sock")), "退出后仍残留 Unix socket"
        # Windows 强制结束父进程不会运行 Rust Drop；只停止本测试独占端口上的 Caddy。
        try:
            request = urllib.request.Request(f"http://127.0.0.1:{self.ports['admin']}/stop", data=b"", method="POST")
            with self.opener.open(request, timeout=3):
                pass
        except (OSError, urllib.error.URLError):
            pass

    def ready(self, tunnel_id):
        return next((t for t in self.api("tunnels") if t["id"] == tunnel_id and t["apply_status"] == "ready"), None)

    def web(self, host, secure=False, path="/"):
        stream = socket.create_connection(("127.0.0.1", self.ports["https" if secure else "http"]), timeout=15)
        if secure:
            ca = self.root / "server/caddy-storage/pki/authorities/local/root.crt"
            stream = ssl.create_default_context(cafile=str(ca)).wrap_socket(stream, server_hostname=host)
        with stream:
            stream.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            response = http.client.HTTPResponse(stream)
            response.begin()
            return response.status, response.read()

    def run(self):
        echo = EchoServer(("127.0.0.1", 0), Echo)
        origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        for service in [echo, origin]:
            threading.Thread(target=service.serve_forever, daemon=True).start()
        try:
            self.start_server()
            code = next((self.root / "server").glob("*bootstrap*")).read_text().strip()
            result = self.api("auth/initialize", "POST", {"bootstrap_code": code, "username": "admin", "password": "Test-tunnel-only-4821!"})
            self.csrf = result["csrf_token"]
            assert self.api("auth/status")["authenticated"], "登录后状态查询失败"
            invitation = self.api("enrollments", "POST", {"ttl_seconds": 3600})
            self.start_agent(invitation["token"])
            wait_for(lambda: any(row["status"] == "awaiting_approval" for row in self.api("enrollments")), "Agent 提交 CSR")
            device = self.api(f"enrollments/{invitation['id']}/approve", "POST", {"device_name": "验收 Agent"})["device_id"]
            wait_for(lambda: any(row["id"] == device and row["status"] == "online" for row in self.api("devices")), "mTLS 控制上线")
            self.check("真实入网审批与 mTLS 控制连接")
            domain = self.api("public-domains", "POST", {"domain": "nexo-smoke.localhost", "https_enabled": True})
            # 归属验证由独立测试覆盖；本地固定夹具不查询公网 DNS、不触发公网 ACME。
            with sqlite3.connect(self.root / "server/nexo.db") as db:
                db.execute("UPDATE domain_settings SET verified=1,certificate_mode='cloudflare_dns',legacy=1 WHERE domain_id=?", (domain["id"],))
            def create(protocol, name, local_port, public_port=None):
                return self.api("tunnels", "POST", {"name": name, "protocol": protocol, "device_id": device, "local_address": "127.0.0.1", "local_port": local_port, "enabled": True, "public_port": public_port, "hostname": name if protocol != "tcp" else None, "public_domain_id": domain["id"] if protocol != "tcp" else None})
            tcp = create("tcp", "echo", echo.server_address[1], self.ports["public"])
            web = create("http", "web", origin.server_address[1])
            secure = create("https", "secure", origin.server_address[1])
            assert tcp["public_address"] == f"127.0.0.1:{self.ports['public']}"
            assert web["public_address"] == "http://web.nexo-smoke.localhost"
            assert secure["public_address"] == "https://secure.nexo-smoke.localhost"
            for tunnel in [tcp, web, secure]:
                wait_for(lambda: self.ready(tunnel["id"]), f"{tunnel['protocol']} 服务就绪")
            exchange(self.ports["public"], bytes(range(256)) * 32768)
            self.check("TCP 8 MiB 双向传输、背压与半关闭")
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(lambda i: exchange(self.ports["public"], bytes([i]) * 131072), range(8)))
            self.check("8 条并发 Yamux 逻辑流互不串流")
            assert self.web("web.nexo-smoke.localhost") == (200, b"nexo-real-origin\n")
            assert self.web("secure.nexo-smoke.localhost", True) == (200, b"nexo-real-origin\n")
            status, body = self.web("secure.nexo-smoke.localhost", True, "/large")
            assert status == 200 and body == bytes(range(256)) * 32768
            assert self.web("unknown.nexo-smoke.localhost")[0] == 404
            self.check("Caddy HTTP / HTTPS → Tunnel → 本地 HTTP；TLS 校验与大响应")
            with socket.create_connection(("127.0.0.1", self.ports["http"]), timeout=10) as stream:
                stream.sendall(b"GET /ws HTTP/1.1\r\nHost: web.nexo-smoke.localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
                response = b""
                while not response.endswith(b"\r\n\r\n"):
                    response += stream.recv(1)
                assert b"101 Switching Protocols" in response
                payload, mask = b"websocket-through-tunnel", b"abcd"
                stream.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload)))
                response = bytearray()
                while len(response) < len(payload) + 2:
                    response.extend(stream.recv(100))
                assert response[2:] == payload
            self.check("WebSocket Upgrade 与帧转发")
            for protocol in ["http", "https"]:
                self.api(f"tunnels/{secure['id']}", "PUT", {"name": "secure", "protocol": protocol, "device_id": device, "local_address": "127.0.0.1", "local_port": origin.server_address[1], "enabled": True, "hostname": "secure", "public_domain_id": domain["id"]})
                wait_for(lambda: self.ready(secure["id"]), f"切换公网协议为 {protocol}")
                assert self.web("secure.nexo-smoke.localhost", protocol == "https")[0] == 200
            self.check("HTTP / HTTPS 协议切换后，状态等待 Caddy 新路由加载")
            # 匿名 TLS 和伪造 ID 均不能取得服务配置。
            saved = json.loads((self.root / "agent/identity.json").read_text())
            cert_path, key_path = self.root / "client.crt", self.root / "client.key"
            cert_path.write_text(saved["certificate_pem"])
            key_path.write_text(saved["key_pem"])
            context = ssl.create_default_context(cadata=saved["ca_pem"])
            def rejected(context, claimed):
                try:
                    with socket.create_connection(("127.0.0.1", self.ports["control"]), timeout=5) as raw:
                        with context.wrap_socket(raw, server_hostname="nexo-server") as stream:
                            stream.sendall(json.dumps({"type": "hello", "device_id": claimed, "agent_version": "test"}).encode() + b"\n")
                            assert not stream.recv(4096), "无效身份取得了控制配置"
                except ssl.SSLCertVerificationError:
                    raise  # 服务端证书验证失败不能冒充“无效客户端被拒绝”。
                except (ssl.SSLError, ConnectionError):
                    pass
            rejected(context, device)
            context.load_cert_chain(cert_path, key_path)
            rejected(context, "another-device")
            self.check("无客户端证书与伪造设备 ID 被拒绝")
            # 用本测试设备的有效证书替换数据会话，制造仅数据连接断开，不影响控制连接。
            with socket.create_connection(("127.0.0.1", self.ports["public"]), timeout=5) as active:
                active.sendall(b"before-data-reconnect")
                assert active.recv(100) == b"before-data-reconnect"
                with socket.create_connection(("127.0.0.1", self.ports["data"]), timeout=5) as raw:
                    with context.wrap_socket(raw, server_hostname="nexo-server"):
                        try:
                            assert not active.recv(100), "替换数据会话后旧连接未结束"
                        except ConnectionResetError:
                            pass
            def data_reconnected():
                try:
                    exchange(self.ports["public"], b"data-reconnected")
                    return True
                except (OSError, AssertionError):
                    return False
            wait_for(data_reconnected, "数据通道独立重连")
            assert self.agent.poll() is None
            self.check("数据通道独立断线后自动重连，Agent 进程保持运行")

            def update_tcp(local_port):
                return self.api(f"tunnels/{tcp['id']}", "PUT", {"name": "echo", "protocol": "tcp", "device_id": device, "local_address": "127.0.0.1", "local_port": local_port, "enabled": True})
            with socket.create_connection(("127.0.0.1", self.ports["public"]), timeout=5) as active:
                active.sendall(b"before-edit")
                assert active.recv(100) == b"before-edit"
                updated = update_tcp(origin.server_address[1])
                assert updated["public_port"] == self.ports["public"]
                assert updated["apply_revision"] > tcp["apply_revision"]
                try:
                    assert not active.recv(100), "修改目标后旧连接未结束"
                except ConnectionResetError:
                    pass
            wait_for(lambda: self.ready(tcp["id"]), "新目标配置应用")
            with socket.create_connection(("127.0.0.1", self.ports["public"]), timeout=5) as stream:
                stream.sendall(b"GET / HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n\r\n")
                response = http.client.HTTPResponse(stream)
                response.begin()
                assert response.status == 200 and response.read() == b"nexo-real-origin\n"
            update_tcp(echo.server_address[1])
            wait_for(lambda: self.ready(tcp["id"]), "恢复 Echo 目标")
            self.check("修改目标递增配置版本、关闭旧连接，保留公网端口并转发到新目标")
            with socket.create_connection(("127.0.0.1", self.ports["public"]), timeout=5) as active:
                active.sendall(b"before-disable")
                assert active.recv(100) == b"before-disable"
                self.api(f"tunnels/{tcp['id']}/disable", "POST", {})
                try:
                    assert not active.recv(100), "停用后已有连接仍在转发"
                except ConnectionResetError:
                    pass
            try:
                with socket.create_connection(("127.0.0.1", self.ports["public"]), timeout=2):
                    raise AssertionError("停用后端口仍可连接")
            except (ConnectionRefusedError, TimeoutError):
                pass
            self.api(f"tunnels/{tcp['id']}/enable", "POST", {})
            wait_for(lambda: self.ready(tcp["id"]), "重新启用 TCP")
            exchange(self.ports["public"], b"enabled")
            self.check("停用关闭公网监听和已有连接，启用恢复")
            self.before_restart(device, tcp, secure)
            before = (self.root / "agent/identity.json").read_bytes()
            self.agent.terminate()
            self.agent.wait(timeout=10)
            wait_for(lambda: not self.ready(tcp["id"]), "Agent 离线降级")
            self.start_agent()
            wait_for(lambda: self.ready(tcp["id"]), "Agent 重启恢复")
            assert (self.root / "agent/identity.json").read_bytes() == before
            exchange(self.ports["public"], b"agent-restarted")
            self.check("Agent 无入网 Token 重启，复用原身份并恢复数据连接")
            self.stop_server()
            self.start_server()
            wait_for(lambda: self.ready(secure["id"]), "Server 重启后恢复 HTTPS")
            exchange(self.ports["public"], b"server-restarted")
            assert self.web("secure.nexo-smoke.localhost", True)[0] == 200
            assert len(self.api("devices")) == 1
            self.check("Server 重启恢复监听、CA、证书与 Agent 自动重连")
            self.api(f"tunnels/{web['id']}", "DELETE")
            wait_for(lambda: self.web("web.nexo-smoke.localhost")[0] != 200, "删除 HTTP 撤销路由")
            self.api(f"devices/{device}", "DELETE")
            wait_for(lambda: not self.api("devices"), "删除 Agent")
            rejected(context, device)
            self.check("删除服务撤销入口；删除 Agent 后原证书失效")
        finally:
            echo.shutdown()
            origin.shutdown()
            echo.server_close()
            origin.server_close()

    def close(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        self.stop_server()
        for log in self.logs:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--agent-bin", required=True)
    parser.add_argument("--caddy-bin", required=True)
    parser.add_argument("--report")
    args = parser.parse_args()
    test = Harness(args)
    print("Test directory:", test.root, flush=True)
    try:
        test.run()
        if args.report:
            target = Path(args.report)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps({"passed": test.checks, "platform": os.name}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"All {len(test.checks)} checks passed.", flush=True)
    finally:
        test.close()


if __name__ == "__main__":
    main()
