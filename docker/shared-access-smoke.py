#!/usr/bin/env python3
"""本机真实 Server/Agent 共享密钥验收，不依赖 Docker、Caddy 或公网服务。"""
import argparse
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import sqlite3
import threading
import time
import urllib.error

spec = importlib.util.spec_from_file_location("tunnel_smoke", Path(__file__).with_name("tunnel-smoke.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(65536):
            self.request.sendall(data)


class Harness(smoke.Harness):
    """复用进程与临时目录隔离；每台 Agent 使用独立目录，所有密钥只留在测试目录内。"""
    def start_server(self):
        self.server = self.launch("server", self.args.server_bin, {
            "NEXO_DATA_DIR": str(self.root / "server"),
            "NEXO_HTTP_ADDR": f"127.0.0.1:{self.ports['api']}",
            "NEXO_CONTROL_ADDR": f"127.0.0.1:{self.ports['control']}",
            "NEXO_TUNNEL_ADDR": f"127.0.0.1:{self.ports['data']}",
            "NEXO_TUNNEL_ENDPOINT": f"127.0.0.1:{self.ports['data']}",
            "NEXO_PUBLIC_BIND": "127.0.0.1", "NEXO_CADDY_ENABLED": "false",
        })
        smoke.wait_for(lambda: self.api("auth/status"), "Server 启动")

    def online(self, count):
        devices = self.api("devices")
        return devices if len(devices) == count and all(d["status"] == "online" for d in devices) else None

    def reject(self, path, body, expected):
        try:
            self.api(path, "POST", body)
        except urllib.error.HTTPError as error:
            assert error.code == expected, (path, error.code)
        else:
            raise AssertionError(f"应拒绝请求：{path}")

    def run(self):
        self.start_server()
        code = (self.root / "server/bootstrap.code").read_text().strip()
        self.csrf = self.api("auth/initialize", "POST", {"bootstrap_code": code, "username": "admin", "password": "Local-shared-smoke-4821!"})["csrf_token"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            keys = list(pool.map(lambda _: self.api("agent-access-key", "POST", {}), range(6)))
        key = keys[0]["token"]
        assert all(k["token"] == key for k in keys)
        assert self.api("agent-access-key")["token"] == key
        self.check("并发准备配置只生成一把空间密钥，重新读取不轮换")
        a = self.start_agent(key, "agent-a")
        b = self.start_agent(key, "agent-b")
        devices = smoke.wait_for(lambda: self.online(2), "两台设备独立上线")
        identity_a = json.loads((self.root / "agent-a/identity.json").read_text())
        identity_b = json.loads((self.root / "agent-b/identity.json").read_text())
        assert identity_a["device_id"] != identity_b["device_id"]
        assert identity_a["key_pem"] != identity_b["key_pem"]
        assert identity_a["certificate_pem"] != identity_b["certificate_pem"]
        self.check("同一密钥接入两台真实 Agent，设备 ID、私钥与证书独立")
        with sqlite3.connect(self.root / "server/nexo.db") as db:
            csr = db.execute("SELECT csr_pem FROM agent_registrations WHERE device_id=?", (identity_a["device_id"],)).fetchone()[0]
        retry = {"token": key, "csr_pem": csr, "device_name": "retry", "agent_version": "smoke"}
        assert self.api("agent/register", "POST", retry)["device_id"] == identity_a["device_id"]
        assert len(self.api("devices")) == 2
        self.check("响应丢失后的同 CSR 重试复用身份")

        with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo) as echo:
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            tunnels = []
            for item in devices:
                tunnel = self.api("tunnels", "POST", {"name": item["id"], "protocol": "tcp", "device_id": item["id"], "local_address": "127.0.0.1", "local_port": echo.server_address[1], "enabled": True})
                tunnels.append(tunnel)
                smoke.wait_for(lambda: self.ready(tunnel["id"]), "独立服务配置下发")
                with socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5) as stream:
                    stream.sendall(b"shared-key-device-isolation")
                    assert stream.recv(128) == b"shared-key-device-isolation"
            self.check("两台设备分别接收服务配置并完成真实 TCP 转发")
            new_key = self.api("agent-access-key/reset", "POST", {})["token"]
            assert key != new_key
            self.reject("agent/register", retry, 401)
            a.terminate(); a.wait(timeout=10)
            a = self.start_agent(key, "agent-a")
            smoke.wait_for(lambda: self.online(2), "保留目录重启不依赖旧密钥")
            assert json.loads((self.root / "agent-a/identity.json").read_text())["device_id"] == identity_a["device_id"]
            self.check("重置不影响现有设备，旧密钥配置保留目录仍能重启")
            denied = self.start_agent(key, "old-key-new-agent")
            denied.wait(timeout=20)
            assert denied.returncode != 0
            assert not (self.root / "old-key-new-agent/identity.json").exists()
            c = self.start_agent(new_key, "agent-c")
            smoke.wait_for(lambda: self.online(3), "新密钥添加第三台设备")
            self.check("旧密钥拒绝新增设备，新密钥正常接入")
            self.api(f"devices/{identity_a['device_id']}", "DELETE")
            smoke.wait_for(lambda: self.online(2), "删除只影响目标设备")
            retry["token"] = new_key
            self.reject("agent/register", retry, 409)
            a.terminate(); a.wait(timeout=10)
            a = self.start_agent(new_key, "agent-a")
            time.sleep(4)
            assert len(self.api("devices")) == 2
            assert all(d["id"] != identity_a["device_id"] for d in self.api("devices"))
            assert all(t["device_id"] is None and not t["enabled"] for t in self.api("tunnels") if t["name"] == identity_a["device_id"])
            self.check("删除断开原身份并停用关联服务，旧 CSR 和旧目录不能复活设备")
            self.stop_server(); self.start_server()
            smoke.wait_for(lambda: self.online(2), "Server 重启恢复连接")
            assert self.api("agent-access-key")["token"] == new_key
            self.check("Server 重启保留密钥加密材料，设备自动重连")
            echo.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--agent-bin", required=True)
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
