"""在临时 Linux 目录执行页面生成的命令，用 Docker 替身记录启动参数，不启动真实容器。"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tomllib

payload = json.load(sys.stdin)
with tempfile.TemporaryDirectory(prefix="nexo-agent-install-") as directory:
    root = Path(directory)
    binary = root / "bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$PWD/docker.calls"\n')
    docker.chmod(0o700)
    env = {**os.environ, "PATH": f"{binary}:{os.environ['PATH']}"}
    for case in payload["cases"]:
        target = root / case["method"]
        target.mkdir()

        def execute():
            return subprocess.run(["sh"], input=case["command"], text=True, cwd=target,
                                  env=env, capture_output=True, timeout=10)

        result = execute()
        assert result.returncode == 0, result.stderr
        config = target / "data/nexo-agent/agent.toml"
        assert tomllib.loads(config.read_text()) == payload["expected"]
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        assert not (target / "injected").exists(), "Shell 展开了配置内容"
        calls = (target / "docker.calls").read_text().splitlines()
        if case["method"] == "compose":
            assert calls == ["compose version", "compose -f ./compose.agent.yml up -d"], calls
            assert "./data/nexo-agent:/data/nexo-agent" in (target / "compose.agent.yml").read_text()
        else:
            assert len(calls) == 1 and calls[0].startswith("run -d --name nexo-agent "), calls
            assert "--volume ./data/nexo-agent:/data/nexo-agent" in calls[0]
        assert payload["expected"]["enrollment_token"] not in "\n".join(calls)

        # 重复粘贴不能重写配置或再次启动；也不能覆盖单独存在的 Compose 文件。
        original = config.read_bytes()
        (target / "docker.calls").write_text("")
        result = execute()
        assert result.returncode != 0 and "已有配置" in result.stderr
        assert config.read_bytes() == original
        assert "up -d" not in (target / "docker.calls").read_text()
        assert "run -d" not in (target / "docker.calls").read_text()
        config.unlink()
        if case["method"] == "compose":
            compose = target / "compose.agent.yml"
            compose.write_text("保留已有部署\n")
            result = execute()
            assert result.returncode != 0 and not config.exists()
            assert compose.read_text() == "保留已有部署\n"
            compose.unlink()

        # 悬空符号链接也属于已有配置，不能被重定向写入。
        config.symlink_to(target / "missing.toml")
        result = execute()
        assert result.returncode != 0 and "已有配置" in result.stderr
        assert not (target / "missing.toml").exists()
