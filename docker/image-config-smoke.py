#!/usr/bin/env python3
"""验证本地构建镜像的默认配置、静态资源和重启；只操作本脚本创建的容器。"""
import argparse
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import urllib.request
import uuid


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-image", required=True)
    parser.add_argument("--agent-image", required=True)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="nexo-image-test-"))
    server = "nexo-image-server-" + uuid.uuid4().hex[:12]
    agent = "nexo-image-agent-" + uuid.uuid4().hex[:12]
    denied = "nexo-image-denied-" + uuid.uuid4().hex[:12]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    print("测试目录:", root, flush=True)
    try:
        (root / "server").mkdir()
        docker("run", "-d", "--name", server, "-p", "127.0.0.1::8280",
               "-v", f"{root / 'server'}:/data/nexo", args.server_image)

        def check_web():
            address = docker("port", server, "8280/tcp")
            url = "http://" + address
            deadline = time.monotonic() + 30
            while True:
                try:
                    with opener.open(url + "/health", timeout=1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "默认镜像未启动"
                    time.sleep(.2)
            with opener.open(url + "/") as response:
                html = response.read().decode()
            assets = re.findall(r'(?:src|href)="([^"]+\.(?:js|css))"', html)
            assert any(p.endswith(".js") for p in assets) and any(p.endswith(".css") for p in assets)
            for path in assets + ["/manifest.webmanifest", "/sw.js"]:
                with opener.open(url + "/" + path.lstrip("/")) as response:
                    assert response.status == 200 and response.read()
            return url

        url = check_web()
        config = root / "server/server.toml"
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        original = config.read_bytes()
        caddy = json.loads(docker("exec", server, "curl", "-fsS", "http://127.0.0.1:8290/config/"))
        assert caddy["storage"]["root"].startswith("/data/nexo/")
        # 仅在内存中提取随机密码，不输出日志或凭据。
        password = re.search(r"自动生成的密码：([^\r\n]+)", docker("logs", server)).group(1)

        def login(url):
            request = urllib.request.Request(url + "/api/v1/auth/login", data=json.dumps({"username": "admin", "password": password}).encode(), headers={"Content-Type": "application/json"})
            with opener.open(request) as response:
                assert response.status == 200

        login(url)
        docker("restart", server)
        login(check_web())
        assert config.read_bytes() == original
        print("PASS Server 无额外运行目录挂载、默认配置 0600、8280 静态/PWA/登录、Caddy、同一账号重启", flush=True)

        (root / "agent").mkdir()
        docker("create", "--name", agent, "-v", f"{root / 'agent'}:/data/nexo-agent", args.agent_image)
        docker("start", agent)
        assert docker("wait", agent) != "0"
        error = subprocess.run(["docker", "logs", agent], capture_output=True, text=True)
        assert "server_url" in error.stderr + error.stdout
        assert stat.S_IMODE((root / "agent/agent.toml").stat().st_mode) == 0o600
        assert not (root / "agent/identity.json").exists()
        print("PASS Agent 默认生成 0600 TOML，缺失地址时明确退出并保留文件", flush=True)

        locked = root / "locked"
        locked.mkdir(mode=0o755)
        marker = locked / "keep.txt"
        marker.write_text("preserve", encoding="utf-8")
        docker("create", "--name", denied, "--user", "65534:65534", "-v", f"{locked}:/data/nexo", args.server_image)
        docker("start", denied)
        assert docker("wait", denied) != "0"
        error = subprocess.run(["docker", "logs", denied], capture_output=True, text=True)
        assert "无法创建" in error.stderr + error.stdout
        assert marker.read_text(encoding="utf-8") == "preserve"
        assert sorted(p.name for p in locked.iterdir()) == ["keep.txt"]
        print("PASS 非 root 无写权限时明确退出，不生成数据库或覆盖已有文件", flush=True)
    finally:
        for name in [server, agent, denied]:
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
