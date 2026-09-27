#!/usr/bin/env python3
"""运行真实 Server/Agent，验证连接环境变量优先级、文件保留及原身份复用。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tomllib

spec = importlib.util.spec_from_file_location("shared_smoke", Path(__file__).with_name("shared-access-smoke.py"))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--agent-bin", required=True)
    args = parser.parse_args()
    test = shared.Harness(args)
    print("Test directory:", test.root, flush=True)

    # 每个子进程独立环境，避免修改父进程或并发测试的全局变量。
    def launch(directory, environment):
        log = open(test.root / f"agent-env-{len(test.logs)}.log", "wb")
        test.logs.append(log)
        env = {key: value for key, value in os.environ.items() if not key.startswith("NEXO_")}
        process = subprocess.Popen([str(Path(args.agent_bin).resolve()), "--data-dir", str(directory)],
                                   env={**env, **environment}, stdout=log, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        test.processes.append(process)
        return process

    def registered(process, directory):
        assert process.poll() is None, "Agent 提前退出，查看测试目录中的日志"
        path = directory / "identity.json"
        return json.loads(path.read_text()) if path.exists() else None

    try:
        test.start_server()
        test.csrf = test.api("auth/login", "POST", {"username": "admin", "password": "Local-shared-smoke-4821!"})["csrf_token"]
        token = test.api("agent-access-key", "POST", {})["token"]
        env = {"NEXO_SERVER_URL": test.url, "NEXO_ENROLLMENT_TOKEN": token, "NEXO_DEVICE_NAME": "环境 NAS '$HOME'"}
        config = {"server_url": test.url, "enrollment_token": token, "device_name": "TOML NAS",
                  "control_endpoint": f"127.0.0.1:{test.ports['control']}"}
        for name, values, environment, expected_name in [
            ("env-only", None, env, env["NEXO_DEVICE_NAME"]),
            ("env-priority", {**config, "server_url": "invalid", "enrollment_token": "invalid", "device_name": "ignored"}, env, env["NEXO_DEVICE_NAME"]),
            ("env-partial", config, {"NEXO_DEVICE_NAME": "部分覆盖", "NEXO_SERVER_URL": ""}, "部分覆盖"),
            ("env-empty", config, {key: "" for key in env}, "TOML NAS"),
            ("toml-only", config, {}, "TOML NAS"),
        ]:
            directory = test.root / name
            directory.mkdir()
            path = directory / "agent.toml"
            if values is not None:
                path.write_text("# 手工配置保持原样\n" + "\n".join(f"{key} = {json.dumps(value, ensure_ascii=False)}" for key, value in values.items()), encoding="utf-8")
            before = path.read_bytes() if path.exists() else None
            process = launch(directory, environment)
            identity = shared.smoke.wait_for(lambda: registered(process, directory), name)
            device = next(item for item in test.api("devices") if item["id"] == identity["device_id"])
            assert device["name"] == expected_name
            if values is not None:
                shared.smoke.wait_for(lambda: any(item["id"] == identity["device_id"] and item["status"] == "online" for item in test.api("devices")), "环境配置 Agent 上线")
            process.terminate()
            process.wait(timeout=10)
            if before is None:
                assert tomllib.loads(path.read_text())["server_url"] == ""
                assert token not in path.read_text()
            else:
                assert path.read_bytes() == before
            test.check(f"{name}: 真实接入、设备名称与配置文件保留")

        directory = test.root / "env-only"
        identity_path = directory / "identity.json"
        original = identity_path.read_bytes()
        device_id = json.loads(original)["device_id"]
        (directory / "agent.toml").write_text(f'control_endpoint = "127.0.0.1:{test.ports["control"]}"\n', encoding="utf-8")
        process = launch(directory, {**env, "NEXO_ENROLLMENT_TOKEN": ""})
        shared.smoke.wait_for(lambda: any(item["id"] == device_id and item["status"] == "online" for item in test.api("devices")), "清除接入密钥后复用身份上线")
        process.terminate()
        process.wait(timeout=10)
        assert identity_path.read_bytes() == original
        assert len(test.api("devices")) == 5
        test.check("清除环境接入密钥后重启保留原身份，不新增设备")

        for name, environment, directory in [
            ("identity-mismatch", {**env, "NEXO_SERVER_URL": "http://127.0.0.1:1"}, directory),
            ("invalid-url", {**env, "NEXO_SERVER_URL": "invalid"}, test.root / "invalid-url"),
            ("missing-token", {**env, "NEXO_ENROLLMENT_TOKEN": ""}, test.root / "missing-token"),
        ]:
            process = launch(directory, environment)
            assert process.wait(timeout=20) != 0
            if name == "identity-mismatch":
                assert identity_path.read_bytes() == original
            else:
                assert not (directory / "identity.json").exists()
            test.check(f"{name}: 明确拒绝且不覆盖身份")
        for log in test.logs:
            assert token not in Path(log.name).read_text(encoding="utf-8"), "日志泄露接入密钥"
        test.check("日志不输出接入密钥")
    finally:
        test.close()


if __name__ == "__main__":
    main()
