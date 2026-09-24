#!/usr/bin/env python3
"""真实多账号/Agent 验收；复用穿透验收环境，只在测试数据库注入本机域名归属。"""
import asyncio
import http.cookiejar
import importlib.util
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location("tunnel_smoke", Path(__file__).with_name("tunnel-smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class UserClient:
    def __init__(self, base):
        self.base = base
        self.csrf = ""
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def api(self, path, method="GET", body=None):
        request = urllib.request.Request(self.base + "/api/v1/" + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers={"Content-Type": "application/json", "x-nexo-csrf": self.csrf})
        with self.opener.open(request, timeout=10) as response:
            return json.load(response)


def denied(action, expected):
    try:
        action()
    except urllib.error.HTTPError as error:
        assert error.code == expected, (error.code, expected)
        return
    raise AssertionError("越权或已撤销操作未被拒绝")


def websocket(port, host):
    stream = socket.create_connection(("127.0.0.1", port), timeout=8)
    stream.sendall(f"GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n".encode())
    response = b""
    while not response.endswith(b"\r\n\r\n"):
        part = stream.recv(1)
        assert part, "WebSocket 握手中断"
        response += part
    assert b"101 Switching Protocols" in response
    return stream


def frame(stream, payload):
    mask = b"abcd"
    stream.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + bytes(value ^ mask[i % 4] for i, value in enumerate(payload)))
    response = bytearray()
    while len(response) < len(payload) + 2:
        part = stream.recv(256)
        assert part, "WebSocket 帧转发中断"
        response.extend(part)
    assert response[2:] == payload


def closed(stream):
    try:
        data = stream.recv(256)
        # WebSocket Close 帧也表示原应用数据流已经终止。
        assert not data or data[0] & 0x0f == 8, "停用后仍在转发应用数据"
    except (ConnectionResetError, ConnectionAbortedError):
        pass


async def http3(harness):
    """需额外安装 aioquic；使用内部 CA 校验证书和 h3 ALPN，绝不降级到 TCP。"""
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration

    class H3Client(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = H3Connection(self._quic)
            self.done = asyncio.get_running_loop().create_future()
            self.body = bytearray()
            self.status = None

        def quic_event_received(self, event):
            for item in self.http.handle_event(event):
                if isinstance(item, HeadersReceived):
                    self.status = dict(item.headers).get(b":status")
                if isinstance(item, DataReceived):
                    self.body.extend(item.data)
                    if item.stream_ended and not self.done.done():
                        self.done.set_result((self.status, bytes(self.body)))

    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], server_name="secure.nexo-smoke.localhost")
    config.load_verify_locations(cafile=str(harness.root / "server/caddy-storage/pki/authorities/local/root.crt"))
    async with connect("127.0.0.1", harness.ports["https"], configuration=config, create_protocol=H3Client) as client:
        assert client._quic.tls.alpn_negotiated == "h3"
        stream = client._quic.get_next_available_stream_id()
        client.http.send_headers(stream_id=stream, headers=[(b":method", b"GET"), (b":scheme", b"https"), (b":authority", b"secure.nexo-smoke.localhost"), (b":path", b"/")], end_stream=True)
        client.transmit()
        assert await asyncio.wait_for(client.done, 10) == (b"200", b"nexo-real-origin\n")


class MultiuserHarness(smoke.Harness):
    def before_restart(self, device, tcp, secure):
        alice, bob = UserClient(self.url), UserClient(self.url)
        for client, username in [(alice, "alice"), (bob, "bob")]:
            invite = self.api("admin/invitations", "POST")
            result = client.api("auth/invitations/accept", "POST", {"token": invite["token"], "username": username, "password": "safe-multiuser-password"})
            client.csrf = result["csrf_token"]
        user = alice.api("auth/status")
        workspace = user["workspace_id"]
        prefix = f"admin/workspaces/{workspace}"
        assert not alice.api("tunnels") and not bob.api("devices")
        denied(lambda: bob.api(prefix + "/tunnels"), 403)
        denied(lambda: alice.api("admin/users"), 403)
        self.check("邀请创建独立工作空间，普通用户不能访问管理员资源或其他空间")

        invite = alice.api("enrollments", "POST", {})
        original_agent = self.agent
        agent = self.start_agent(invite["token"], "alice-agent")
        self.agent = original_agent
        smoke.wait_for(lambda: any(row["status"] == "awaiting_approval" for row in alice.api("enrollments")), "Alice Agent 提交身份")
        alice_device = alice.api(f"enrollments/{invite['id']}/approve", "POST", {"device_name": "Alice Agent"})["device_id"]
        smoke.wait_for(lambda: any(row["status"] == "online" for row in alice.api("devices")), "Alice Agent 上线")
        assert len(self.api(prefix + "/devices")) == 1
        domain = alice.api("public-domains", "POST", {"domain": "alice-smoke.localhost", "https_enabled": False})
        assert domain["certificate_mode"] == "http01" and domain["verification_status"] == "pending"
        web_input = {"name": "alice-web", "protocol": "http", "device_id": alice_device, "local_address": "127.0.0.1", "local_port": secure["local_port"], "hostname": "web", "public_domain_id": domain["id"]}
        denied(lambda: alice.api("tunnels", "POST", web_input), 400)
        denied(lambda: bob.api(f"public-domains/{domain['id']}/cloudflare-credential", "PUT", {"token": "a"*40}), 404)
        with sqlite3.connect(self.root / "server/nexo.db") as db:
            db.execute("UPDATE domain_settings SET verified=1 WHERE domain_id=?", (domain["id"],))
        web = alice.api("tunnels", "POST", web_input)
        public_port = smoke.port()
        alice_tcp = alice.api("tunnels", "POST", {"name": "alice-tcp", "protocol": "tcp", "device_id": alice_device, "local_address": "127.0.0.1", "local_port": tcp["local_port"], "public_port": public_port})
        smoke.wait_for(lambda: all(item["apply_status"] == "ready" for item in alice.api("tunnels")), "Alice HTTP/TCP 转发就绪")
        pending = alice.api("enrollments", "POST", {})
        recovery = self.api(f"admin/users/{user['user_id']}/recovery", "POST")
        self.check("用户自助入网；未验证域名禁止发布，跨空间凭据更新被拒绝")

        with websocket(self.ports["http"], "web.alice-smoke.localhost") as ws, socket.create_connection(("127.0.0.1", public_port), timeout=8) as active:
            frame(ws, b"before-reload")
            admin_url = f"http://127.0.0.1:{self.ports['admin']}"
            with self.opener.open(admin_url + "/config/") as response:
                config = response.read()
            reload = urllib.request.Request(admin_url + "/load", data=config, method="POST", headers={"Content-Type": "application/json", "Cache-Control": "must-revalidate"})
            with self.opener.open(reload):
                pass
            frame(ws, b"after-reload")
            self.check("真实 Caddy 强制重载后旧 WebSocket 继续双向传输")
            active.sendall(b"before-user-disable")
            assert active.recv(100) == b"before-user-disable"
            self.api(f"admin/users/{user['user_id']}", "PATCH", {"enabled": False})
            closed(active)
            closed(ws)
        denied(lambda: alice.api("tunnels"), 401)
        denied(lambda: alice.api("auth/login", "POST", {"username": "alice", "password": "safe-multiuser-password"}), 401)
        denied(lambda: UserClient(self.url).api("auth/recover", "POST", {"recovery_code": recovery["token"], "new_password": "revoked-code-password"}), 401)
        assert not self.api(prefix + "/enrollments")
        saved = self.api(prefix + "/tunnels")
        assert all(item["enabled"] for item in saved)
        assert next(item["public_port"] for item in saved if item["id"] == alice_tcp["id"]) == public_port
        smoke.wait_for(lambda: all(item["status"] == "offline" for item in self.api(prefix + "/devices")), "停用账号的 Agent 拒绝重连")
        identity = json.loads((self.root / "alice-agent/identity.json").read_text())
        cert, key = self.root / "alice.crt", self.root / "alice.key"
        cert.write_text(identity["certificate_pem"])
        key.write_text(identity["key_pem"])
        context = ssl.create_default_context(cadata=identity["ca_pem"])
        context.load_cert_chain(cert, key)
        try:
            with socket.create_connection(("127.0.0.1", self.ports["control"]), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="nexo-server") as stream:
                    stream.sendall(json.dumps({"type":"hello","device_id":alice_device,"agent_version":"test"}).encode()+b"\n")
                    assert not stream.recv(4096), "停用账号的有效设备证书取得了控制配置"
        except ssl.SSLCertVerificationError:
            raise
        except (ssl.SSLError, ConnectionError):
            pass
        # 同时确认其他用户服务和会话仍正常。
        smoke.exchange(self.ports["public"], b"admin-unaffected")
        assert bob.api("auth/status")["authenticated"]
        self.check("停用立即断开 TCP/WebSocket、撤销会话和入网/恢复凭证，其他用户正常")
        self.api(f"admin/users/{user['user_id']}", "PATCH", {"enabled": True})
        result = alice.api("auth/login", "POST", {"username": "alice", "password": "safe-multiuser-password"})
        alice.csrf = result["csrf_token"]
        assert not alice.api("enrollments")
        smoke.wait_for(lambda: all(item["apply_status"] == "ready" for item in alice.api("tunnels")), "重新启用恢复转发")
        smoke.exchange(public_port, b"alice-restored")
        with websocket(self.ports["http"], "web.alice-smoke.localhost") as ws:
            frame(ws, b"before-delete")
            alice.api(f"tunnels/{web['id']}", "DELETE")
            closed(ws)
        self.check("重新启用恢复原地址，删除服务立即断开 WebSocket，不等待重载延迟")
        new_recovery = self.api(f"admin/users/{user['user_id']}/recovery", "POST")
        UserClient(self.url).api("auth/recover", "POST", {"recovery_code": new_recovery["token"], "new_password": "new-alice-password"})
        denied(lambda: alice.api("tunnels"), 401)
        assert bob.api("auth/status")["authenticated"]
        self.check("普通用户恢复链接只重设目标账号并吊销其会话")
        result = alice.api("auth/login", "POST", {"username": "alice", "password": "new-alice-password"})
        alice.csrf = result["csrf_token"]
        self.api(f"admin/users/{user['user_id']}", "PATCH", {"username": "alice-renamed"})
        denied(lambda: alice.api("tunnels"), 401)
        denied(lambda: alice.api("auth/login", "POST", {"username": "alice", "password": "new-alice-password"}), 401)
        result = alice.api("auth/login", "POST", {"username": "alice-renamed", "password": "new-alice-password"})
        alice.csrf = result["csrf_token"]
        assert alice.api("auth/status")["workspace_id"] == workspace
        smoke.exchange(public_port, b"rename-keeps-tunnel")
        self.check("改名撤销旧会话和旧登录名，保留用户身份、工作空间及真实转发")
        web = alice.api("tunnels", "POST", web_input)
        smoke.wait_for(lambda: all(item["apply_status"] == "ready" for item in alice.api("tunnels")), "整空间删除前恢复 Web 服务")
        alice.api("enrollments", "POST", {})
        final_recovery = self.api(f"admin/users/{user['user_id']}/recovery", "POST")
        # 本机 HTTP 域名的专属测试凭据没有接入签发，不调用 Cloudflare。
        secret_dir = self.root / "server/secrets/public-domains" / domain["id"]
        secret_dir.mkdir(parents=True, exist_ok=True)
        (secret_dir / "credential-unused.token").write_text("local-unused-test-token")
        with websocket(self.ports["http"], "web.alice-smoke.localhost") as ws, socket.create_connection(("127.0.0.1", public_port), timeout=8) as active:
            frame(ws, b"before-account-delete")
            active.sendall(b"delete-active-tcp")
            assert active.recv(100) == b"delete-active-tcp"
            result = self.api(f"admin/users/{user['user_id']}", "DELETE", {"confirm_username": "alice-renamed"})
            assert result["deleted"] and not result["cleanup_pending"], result
            closed(active)
            closed(ws)
        denied(lambda: alice.api("tunnels"), 401)
        denied(lambda: self.api(prefix + "/devices"), 404)
        denied(lambda: UserClient(self.url).api("auth/recover", "POST", {"recovery_code": final_recovery["token"], "new_password": "deleted-account-password"}), 401)
        assert not secret_dir.exists()
        try:
            with socket.create_connection(("127.0.0.1", self.ports["control"]), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="nexo-server") as stream:
                    stream.sendall(json.dumps({"type": "hello", "device_id": alice_device, "agent_version": "test"}).encode()+b"\n")
                    assert not stream.recv(4096), "删除用户后旧 Agent 身份仍可连接"
        except ssl.SSLCertVerificationError:
            raise
        except (ssl.SSLError, ConnectionError):
            pass
        assert all(item["id"] != user["user_id"] for item in self.api("admin/users"))
        smoke.exchange(self.ports["public"], b"other-user-still-serving")
        assert bob.api("auth/status")["authenticated"]
        self.check("删除用户同步断开 TCP/WebSocket、拒绝 Agent 重连、撤销凭证并清理域名 Secret，其他用户正常")
        agent.terminate()
        agent.wait(timeout=10)
        if importlib.util.find_spec("aioquic"):
            asyncio.run(http3(self))
            self.check("本机 UDP HTTP/3 h3 ALPN、证书校验及实际 Tunnel HTTP 响应")
        else:
            print("SKIP 本机 HTTP/3：未安装 aioquic；未验证公网 UDP 443", flush=True)


if __name__ == "__main__":
    smoke.Harness = MultiuserHarness
    smoke.main()
