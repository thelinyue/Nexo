#!/usr/bin/env python3
"""隔离验证真实 VPS 节点的自定义 HTTP/HTTPS 端口，不使用公网 DNS/CA 或生产数据库。

管理 API、Agent 和源站只监听回环；节点入口使用指定端口。测试身份通过本机注册 API
签发，测试证书由 Caddy 内部 CA 生成。这个夹具不代替 HTTPS 安装接入或 DNS 验收。
"""
import argparse
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location("tunnel_smoke", Path(__file__).with_name("tunnel-smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class NodeHarness(smoke.Harness):
    def close(self):
        super().close()
        # Windows 强制结束节点不会运行 Drop；只在本夹具通过端口独占检查并启动节点后清理其 Caddy。
        if getattr(self, "node_process", None) is not None:
            try:
                request = urllib.request.Request("http://127.0.0.1:8290/stop", data=b"", method="POST")
                with self.opener.open(request, timeout=3):
                    pass
            except (OSError, urllib.error.URLError):
                pass

    def api(self, path, method="GET", body=None):
        try:
            return super().api(path, method, body)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"{method} {path}: {error.code} {error.read().decode()}") from None

    def launch(self, name, binary, config):
        if name == "server":
            config["caddy.enabled"] = False
            config["caddy.http_listen"] = f":{self.args.http_port}"
        return super().launch(name, binary, config)

    def request_node(self, host, secure=False, path="/", *, payload=None, headers=None):
        port = self.args.https_port if secure else self.args.http_port
        stream = socket.create_connection((self.args.node_ip, port), timeout=5)
        if secure:
            ca = self.root / "server/caddy-storage/pki/authorities/local/root.crt"
            stream = ssl.create_default_context(cafile=str(ca)).wrap_socket(stream, server_hostname=host)
        with stream:
            method = "GET"
            body = b""
            fields = {"Host": f"{host}:{port}", "Connection": "close", **(headers or {})}
            if payload is not None:
                method = "POST"
                body = json.dumps(payload).encode()
                fields.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
            head = "".join(f"{name}: {value}\r\n" for name, value in fields.items())
            stream.sendall(f"{method} {path} HTTP/1.1\r\n{head}\r\n".encode() + body)
            response = http.client.HTTPResponse(stream)
            response.begin()
            return response.status, dict(response.getheaders()), response.read()

    def run(self):
        # 在产生测试文件或进程前检查独占端口，不停止任何已有服务。
        for port in (self.args.http_port, self.args.https_port, 9891, 8282, 8290):
            with socket.socket() as sock:
                sock.bind(("0.0.0.0", port))
        origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), smoke.Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            self.start_server()
            self.stop_server()
            with sqlite3.connect(self.root / "server/nexo.db") as db:
                db.execute("INSERT INTO server_settings(id,value) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value", (json.dumps({"public_url":"https://127.0.0.1", "managed":True}),))
            self.start_server()
            self.csrf = self.api("auth/login", "POST", {"username":"admin", "password":"Test-tunnel-only-4821!"})["csrf_token"]
            invitation = self.api("agent-access-key", "POST", {})
            self.start_agent(invitation["token"])
            device = smoke.wait_for(lambda: next((d["id"] for d in self.api("devices") if d["status"] == "online"), None), "Agent 上线")
            domain = self.api("public-domains", "POST", {"domain":"nexo-smoke.localhost", "https_enabled":True})
            self.configure_local_domain(domain)
            services = []
            for protocol, host in [("http", "web"), ("https", "secure")]:
                services.append(self.api("tunnels", "POST", {"name":host, "protocol":protocol, "device_id":device, "local_address":"127.0.0.1", "local_port":origin.server_address[1], "hostname":host, "public_domain_id":domain["id"], "https_port":self.args.https_port, "compression_enabled": protocol == "https"}))
            tcp = self.api("tunnels", "POST", {"name":"tcp", "protocol":"tcp", "device_id":device,
                "local_address":"127.0.0.1", "local_port":origin.server_address[1], "compression_enabled":True})
            access_password = secrets.token_urlsafe(9)
            protected = self.api("tunnels", "POST", {
                "name": "locked", "protocol": "http", "device_id": device,
                "local_address": "127.0.0.1", "local_port": origin.server_address[1],
                "hostname": "locked", "public_domain_id": domain["id"],
                "access_mode": "password", "access_password": access_password,
            })
            assert services[0]["public_address"] == f"http://web.nexo-smoke.localhost:{self.args.http_port}"
            assert services[1]["public_address"] == f"https://secure.nexo-smoke.localhost:{self.args.https_port}"
            self.check("服务地址显示自定义 HTTP/HTTPS 公网端口")

            node_dir = self.root / "node"
            node_dir.mkdir(mode=0o700)
            key_path, csr_path = node_dir / "key.pem", node_dir / "request.pem"
            subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=test-node", "-keyout", str(key_path), "-out", str(csr_path)], check=True, capture_output=True)
            enrollment = self.api("nodes", "POST", {"name":"隔离端口验收", "public_ipv4":"203.0.113.10"})
            assert enrollment["http_port"] == self.args.http_port
            registered = self.api("node/register", "POST", {"token":enrollment["token"], "csr":csr_path.read_text()})
            node_id = registered["id"]
            registered.update(server_url="https://127.0.0.1", key=key_path.read_text())
            identity = node_dir / "node-identity.json"
            identity.write_text(json.dumps(registered))
            identity.chmod(0o600)
            self.api(f"nodes/{node_id}/approve", "POST", {})
            cert_dir = self.root / "server/caddy-storage/certificates/local/secure.nexo-smoke.localhost"
            dest = self.root / "server/nodes/certificates" / services[1]["id"]
            dest.mkdir(parents=True, mode=0o700)
            shutil.copyfile(cert_dir / "secure.nexo-smoke.localhost.key", dest / "key.pem")
            (dest / "key.pem").chmod(0o600)
            with sqlite3.connect(self.root / "server/nexo.db") as db:
                db.execute("UPDATE relay_nodes SET public_ipv4=? WHERE id=?", (self.args.node_ip, node_id))
                db.execute("INSERT INTO relay_node_grants VALUES(?,?)", (node_id, services[0]["tenant_id"]))
                for service in [*services, tcp, protected]:
                    db.execute("DELETE FROM service_nodes WHERE service_id=?", (service["id"],))
                    db.execute("INSERT INTO service_nodes VALUES(?,?)", (service["id"], node_id))
                # 覆盖节点跳转路由；隧道表单当前未开放强制 HTTPS，此处仅设置测试快照。
                db.execute("UPDATE tunnels SET http_redirect_enabled=1 WHERE id=?", (services[1]["id"],))
                db.execute("INSERT INTO relay_certificates(service_id,hostname,chain,expires_at,retry_at) VALUES(?,?,?,?,?)", (services[1]["id"], "secure.nexo-smoke.localhost", (cert_dir / "secure.nexo-smoke.localhost.crt").read_text(), int(time.time())+3600, int(time.time())+86400))
            log = open(self.root / "node.log", "wb")
            self.logs.append(log)
            node_binary = Path(self.args.node_bin or self.args.server_bin).resolve()
            node_caddy = Path(self.args.node_caddy_bin or self.args.caddy_bin).resolve()
            environment = dict(os.environ, NEXO_CADDY_BINARY=str(node_caddy))
            node = subprocess.Popen([str(node_binary), "--data-dir", str(node_dir), "node"], env=environment, stdout=log, stderr=subprocess.STDOUT)
            self.node_process = node
            self.processes.append(node)
            smoke.wait_for(lambda: self.request_node("web.nexo-smoke.localhost")[0] == 200, "HTTP 节点转发", timeout=75)
            assert self.request_node("web.nexo-smoke.localhost")[2] == b"nexo-real-origin\n"
            self.check("自定义 HTTP 端口经真实节点 mTLS/Yamux 转发到 Agent 源站")
            smoke.wait_for(lambda: self.request_node("secure.nexo-smoke.localhost", True)[0] == 200, "HTTPS 节点转发")
            assert self.request_node("secure.nexo-smoke.localhost", True)[2] == b"nexo-real-origin\n"
            self.check("自定义 HTTPS 端口完成证书主机名校验和真实转发")
            status, headers, _ = self.request_node("secure.nexo-smoke.localhost", path="/probe?q=1")
            assert status in (301, 302, 307, 308)
            assert headers["Location"] == f"https://secure.nexo-smoke.localhost:{self.args.https_port}/probe?q=1"
            self.check(f"HTTP 跳转保留 HTTPS {self.args.https_port} 及原始路径和参数")
            def healthy():
                with sqlite3.connect(self.root / "server/nexo.db") as db:
                    return db.execute(
                        "SELECT COUNT(*) FROM relay_public_health WHERE node_id=? AND service_id IN (?, ?) AND healthy=1",
                        (node_id, services[0]["id"], services[1]["id"]),
                    ).fetchone()[0] == 2
            smoke.wait_for(healthy, "管理 Server 在自定义端口完成连续三次公网入口探测", timeout=90)
            self.check("管理 Server 在实际 HTTP/HTTPS 端口完成健康探测")
            def node_health():
                with self.opener.open("http://127.0.0.1:8282/health", timeout=3) as response:
                    return json.load(response)
            health = smoke.wait_for(node_health, "节点回环健康接口")
            version = subprocess.check_output([node_binary, "--version"], text=True).split()[-1]
            assert health["version"] == version and health["instance"]
            self.check("节点回环健康接口返回当前进程实例与版本")

            locked_host = "locked.nexo-smoke.localhost"
            status, _, _ = self.request_node(locked_host)
            assert status == 401, status
            status, headers, _ = self.request_node(locked_host, headers={"Accept": "text/html"})
            assert status == 303 and headers["Location"].startswith("/.nexo-access/"), status
            origin_header = {"Origin": f"http://{locked_host}:{self.args.http_port}"}
            status, _, _ = self.request_node(locked_host, path="/.nexo-access/login",
                payload={"password": access_password + "x"}, headers=origin_header)
            assert status == 401, status
            status, headers, _ = self.request_node(locked_host, path="/.nexo-access/login",
                payload={"password": access_password, "return_to": "/"}, headers=origin_header)
            assert status == 200, status
            cookie = headers["Set-Cookie"].split(";", 1)[0]
            assert self.request_node(locked_host, headers={"Cookie": cookie})[2] == b"nexo-real-origin\n"
            self.check("节点通过管理端验证访问密码并带有效会话转发请求")

            quota = f"nodes/{node_id}/traffic/quota"
            self.api(quota, "PUT", {"monthly_limit_bytes": 64 * 1024 * 1024})
            def tcp_response():
                with socket.create_connection((self.args.node_ip, tcp["public_port"]), timeout=3) as client:
                    client.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    with client.makefile("rb") as response:
                        if b"nexo-real-origin\n" in response.read():
                            return client.getsockname()[0]
            client_ip = smoke.wait_for(tcp_response, "独立节点压缩 TCP 双向转发")
            def tcp_fact():
                items = self.api(f"traffic/analytics/sessions?tunnel_id={tcp['id']}")["items"]
                return next((e for e in items if e["node"] == node_id and e["to_public"] > 0), None)
            tcp_session = smoke.wait_for(tcp_fact, "独立节点 TCP 会话回传")
            assert tcp_session["source"] == ".".join(client_ip.split(".")[:3]) + ".0/24"
            assert tcp_session["country"] == "未知"
            assert any(row["label"] == "未知" for row in self.api(f"traffic/analytics/summary?tunnel_id={tcp['id']}")["breakdowns"]["session_country"])
            self.check("独立节点 TCP 会话上报来源网段与地域，压缩转发完成")
            for service in services:
                host = f"{service['name']}.nexo-smoke.localhost"
                secure = service["protocol"] == "https"
                # 完成日志异步上报；用唯一的大响应事实核对字节，避免依赖心跳批次的到达顺序。
                def observed():
                    result = self.api(f"traffic/analytics/requests?tunnel_id={service['id']}")["items"]
                    return result if result and all(e["node"] == node_id for e in result) else None
                smoke.wait_for(observed, "独立节点访问事实回传控制器")
                before = self.api(f"traffic/analytics/summary?range=1h&tunnel_id={service['id']}")["totals"]["requests"]
                assert self.request_node(host, secure, "/large?token=node-private")[2] == bytes(range(256)) * 32768
                def large_request():
                    items = self.api(f"traffic/analytics/requests?tunnel_id={service['id']}")["items"]
                    return next((e for e in items if e["path"] == "/large"), None)
                fact = smoke.wait_for(large_request, "独立节点大响应和查询参数脱敏")
                assert fact["node"] == node_id and fact["to_public"] == 8 * 1024 * 1024
                assert fact["status"] == 200 and "visitor" not in fact
                assert self.api(f"traffic/analytics/summary?range=1h&tunnel_id={service['id']}")["totals"]["requests"] >= before + 1
                assert all(not e["path"].startswith("/.nexo-") and "node-private" not in json.dumps(e) for e in observed())
            self.check("独立节点 HTTP/HTTPS 完成日志经 mTLS 回传，8 MiB 字节、节点归属、探测排除和查询脱敏正确")
            smoke.wait_for(lambda: self.api(quota)["used_bytes"] >= 16 * 1024 * 1024, "节点额度结算写入 Server 账本")
            self.check("节点预算及真实转发用量写入管理端账本")
            ca = self.root / "server/caddy-storage/pki/authorities/local/root.crt"
            print("READY_PUBLIC " + json.dumps({"ip":self.args.node_ip, "http_port":self.args.http_port, "https_port":self.args.https_port, "ca_file":str(ca)}), flush=True)
            time.sleep(self.args.hold_seconds)
        finally:
            origin.shutdown()
            origin.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("server-bin", "agent-bin", "caddy-bin"):
        parser.add_argument("--"+name, required=True)
    parser.add_argument("--node-bin", help="从独立节点包解出的 nexo-server，省略时使用 Server 的 node 子命令")
    parser.add_argument("--node-caddy-bin", help="从独立节点包解出的标准 Caddy，省略时使用 --caddy-bin")
    parser.add_argument("--server-test-bin", help="隔离 DNS 夹具所需的 Server 测试程序")
    parser.add_argument("--node-ip", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--https-port", type=int, default=8443)
    parser.add_argument("--hold-seconds", type=int, default=0)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    if args.http_port in (80, 443) or args.https_port in (80, 443):
        parser.error("隔离验收不使用生产 80/443 端口")
    test = NodeHarness(args)
    print("Test directory:", test.root, flush=True)
    try:
        test.run()
        Path(args.report).write_text(json.dumps({"passed":test.checks, "http_port":args.http_port, "https_port":args.https_port}, ensure_ascii=False, indent=2))
        print(f"All {len(test.checks)} checks passed.", flush=True)
    finally:
        test.close()


if __name__ == "__main__":
    main()
