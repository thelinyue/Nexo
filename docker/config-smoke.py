#!/usr/bin/env python3
"""独立目录验证 TOML、网页资源、管理员环境变量与完整目录恢复，不访问公网。"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--agent-bin", required=True)
    args = parser.parse_args()
    server, agent = str(Path(args.server_bin).resolve()), str(Path(args.agent_bin).resolve())
    root = Path(tempfile.mkdtemp(prefix="nexo-config-"))
    print("测试目录:", root, flush=True)
    result = subprocess.run([agent, "--data-dir", str(root / "agent")], capture_output=True)
    assert result.returncode != 0
    assert (root / "agent/agent.toml").is_file()
    assert "server_url" in result.stderr.decode("utf-8")
    assert not (root / "agent/identity.json").exists()
    print("PASS 空 Agent 生成模板并提示缺失字段，不创建身份", flush=True)

    web = Path(__file__).resolve().parents[1] / "web/dist"
    assert (web / "index.html").exists(), "先构建网页"
    config_dir = root / "configuration"
    config_dir.mkdir()
    config = config_dir / "server.toml"
    shutil.copytree(web, root / "web")
    web = root / "web"
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", 8280))
            port = 8280
        except OSError:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            print("SKIP 8280 已被占用，本次使用随机端口", flush=True)
    # 相对路径按配置所在目录解析，而非数据目录或进程工作目录。
    values = {"http_addr": f"127.0.0.1:{port}", "control_addr": "127.0.0.1:0", "tunnel_addr": "127.0.0.1:0", "udp_addr": "127.0.0.1:0", "web_dir": os.path.relpath(web, config_dir), "runtime_dir": "../runtime", "caddy.enabled": False, "admin.password": "123456"}
    config.write_text("# 手工注释不丢失\n" + "\n".join(f"{k} = {json.dumps(v)}" for k, v in values.items()), encoding="utf-8")
    original = config.read_bytes()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def run(directory):
        log = open(root / f"{directory.name}.log", "wb")
        process = subprocess.Popen([server, "--data-dir", str(directory), "--config", str(config)], stdout=log, stderr=subprocess.STDOUT,
            env={**os.environ, "NEXO_HTTP_ADDR": "invalid-ignored", "NEXO_ADMIN_USERNAME": "env-owner", "NEXO_ADMIN_PASSWORD": "env-secret-4821", "NEXO_DATA_DIR": str(root / "unused")},
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            end = time.monotonic() + 20
            while True:
                assert process.poll() is None, f"启动失败，见 {log.name}"
                try:
                    with opener.open(f"http://127.0.0.1:{port}/health", timeout=1):
                        break
                except OSError:
                    assert time.monotonic() < end, "启动超时"
                    time.sleep(.1)
            with opener.open(f"http://127.0.0.1:{port}/") as response:
                html = response.read().decode()
            paths = re.findall(r'(?:src|href)="([^"]+\.(?:js|css))"', html) + ["/manifest.webmanifest", "/sw.js"]
            assert any(p.endswith(".js") for p in paths) and any(p.endswith(".css") for p in paths)
            for path in paths:
                with opener.open(f"http://127.0.0.1:{port}/{path.lstrip('/')}") as response:
                    assert response.status == 200 and response.read()
            request = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1/auth/login", data=json.dumps({"username": "env-owner", "password": "env-secret-4821"}).encode(), headers={"Content-Type": "application/json"})
            with opener.open(request) as response:
                assert response.status == 200
            assert not (root / "unused").exists()
        finally:
            process.terminate()
            process.wait(timeout=10)
            log.close()

    run(root / "server")
    assert config.read_bytes() == original
    # 清除初始密码后仍可登录；完整备份恢复到空目录，保留同一身份和账号。
    config.write_text(config.read_text(encoding="utf-8").replace('admin.password = "123456"', 'admin.password = ""'), encoding="utf-8")
    shutil.copytree(root / "server", root / "restored")
    identity = (root / "server/transport/identity.json").read_bytes()
    run(root / "restored")
    assert (root / "restored/transport/identity.json").read_bytes() == identity
    print(f"PASS {port} 网页、JS/CSS、PWA、登录；管理员环境变量优先，其他旧环境变量无效；相对路径及完整备份恢复", flush=True)
    for text in ['unknown = true', 'http_addr = "invalid"', 'admin.password = ["do-not-log-secret"]']:
        config.write_text(text, encoding="utf-8")
        result = subprocess.run([server, "--config", str(config), "--data-dir", str(root / "invalid")], capture_output=True)
        assert result.returncode != 0
        assert config.read_text(encoding="utf-8") == text
        assert "do-not-log-secret" not in result.stderr.decode("utf-8")
        assert not (root / "invalid/nexo.db").exists()
    print("PASS 未知字段、非法地址、凭据类型错误保留配置且不泄露原文", flush=True)


if __name__ == "__main__":
    main()
