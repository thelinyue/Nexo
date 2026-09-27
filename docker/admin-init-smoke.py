#!/usr/bin/env python3
"""隔离目录运行真实 Server，验证管理员初始化、凭据输出和重启行为；不连接公网。"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Server:
    """每次启动独立日志，显式复用测试数据目录以检查重启不会覆盖账号。"""
    def __init__(self, binary, directory, run, credentials):
        directory.mkdir(parents=True, exist_ok=True)
        self.log_path = directory / f"{run}.log"
        self.log = self.log_path.open("wb")
        port = free_port()
        self.url = f"http://127.0.0.1:{port}/api/v1/"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("NEXO_")}
        self.env.update({
            "NEXO_DATA_DIR": str(directory), "NEXO_HTTP_ADDR": f"127.0.0.1:{port}",
            "NEXO_CONTROL_ADDR": "127.0.0.1:0", "NEXO_TUNNEL_ADDR": "127.0.0.1:0",
            "NEXO_UDP_ADDR": "127.0.0.1:0", "NEXO_CADDY_ENABLED": "false",
            "NEXO_PUBLIC_BIND": "127.0.0.1", **credentials,
        })
        self.process = subprocess.Popen([binary], env=self.env, stdout=self.log, stderr=subprocess.STDOUT,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)

    def api(self, route, body=None):
        request = urllib.request.Request(self.url + route,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=2) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, None

    def ready(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert self.process.poll() is None, f"Server 提前退出：{self.log_path}"
            try:
                status, body = self.api("auth/status")
                if status == 200:
                    assert body["initialized"] and not body["authenticated"]
                    return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.1)
        raise AssertionError(f"Server 启动超时：{self.log_path}")

    def output(self):
        return self.log_path.read_text(encoding="utf-8")

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-bin", required=True)
    args = parser.parse_args()
    binary = str(Path(args.server_bin).resolve())
    root = Path(tempfile.mkdtemp(prefix="nexo-admin-init-"))
    print("Test directory:", root, flush=True)
    generated_passwords = []
    for name, credentials, username, explicit_password in [
        ("defaults", {}, "admin", None),
        ("empty", {"NEXO_ADMIN_USERNAME": " \t", "NEXO_ADMIN_PASSWORD": ""}, "admin", None),
        ("username", {"NEXO_ADMIN_USERNAME": " owner "}, "owner", None),
        ("password", {"NEXO_ADMIN_PASSWORD": " explicit-password-4821 "}, "admin", " explicit-password-4821 "),
        ("explicit", {"NEXO_ADMIN_USERNAME": " owner ", "NEXO_ADMIN_PASSWORD": "explicit-password-4821"}, "owner", "explicit-password-4821"),
    ]:
        directory = root / name
        directory.mkdir()
        (directory / "bootstrap.code").write_text("obsolete-bootstrap", encoding="utf-8")
        server = Server(binary, directory, "first", credentials)
        try:
            server.ready()
            output = server.output()
            matches = re.findall(r"自动生成的密码：([0-9a-f]{48})", output)
            if explicit_password is None:
                assert len(matches) == 1 and f"用户名：{username}" in output
                password = matches[0]
                generated_passwords.append(password)
            else:
                assert not matches and explicit_password not in output
                password = explicit_password
            assert server.api("auth/login", {"username": username, "password": password})[0] == 200
            assert server.api("auth/initialize", {"bootstrap_code": "obsolete-bootstrap", "username": "attacker", "password": "attacker-password-1234"})[0] in (404, 405)
            with sqlite3.connect(directory / "nexo.db") as db:
                before = db.execute("SELECT id,username,password_hash FROM users").fetchall()
                assert len(before) == 1 and before[0][2].startswith("$argon2")
        finally:
            server.close()
        server = Server(binary, directory, "restart", {"NEXO_ADMIN_USERNAME": "x", "NEXO_ADMIN_PASSWORD": "invalid"})
        try:
            server.ready()
            assert "自动生成的密码：" not in server.output() and password not in server.output()
            assert server.api("auth/login", {"username": username, "password": password})[0] == 200
            with sqlite3.connect(directory / "nexo.db") as db:
                assert db.execute("SELECT id,username,password_hash FROM users").fetchall() == before
        finally:
            server.close()
        print(f"PASS {name}: 首次登录、输出策略、旧接口拒绝、重启凭据不变", flush=True)
    assert len(set(generated_passwords)) == len(generated_passwords)
    for name, credentials, variable in [
        ("bad-name", {"NEXO_ADMIN_USERNAME": "x", "NEXO_ADMIN_PASSWORD": "explicit-secret-4821"}, "NEXO_ADMIN_USERNAME"),
        ("bad-password", {"NEXO_ADMIN_PASSWORD": "short-4821"}, "NEXO_ADMIN_PASSWORD"),
    ]:
        server = Server(binary, root / name, "invalid", credentials)
        try:
            assert server.process.wait(timeout=30) != 0
            output = server.output()
            assert variable in output and credentials["NEXO_ADMIN_PASSWORD"] not in output
            with sqlite3.connect(root / name / "nexo.db") as db:
                assert db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        finally:
            server.close()
        print(f"PASS {name}: 非法配置停止启动、不写入账号、不泄露密码", flush=True)
    result = subprocess.run([binary, "bootstrap-code"], capture_output=True)
    assert result.returncode != 0
    print("PASS 旧 bootstrap-code 命令已移除", flush=True)


if __name__ == "__main__":
    main()
