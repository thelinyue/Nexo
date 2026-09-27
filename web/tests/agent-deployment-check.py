"""用真实 Compose 解析 YAML，用 Docker 替身捕获单条命令参数，不启动容器。"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

payload = json.load(sys.stdin)
with tempfile.TemporaryDirectory(prefix="nexo-agent-deployment-") as directory:
    root = Path(directory)
    # Compose 自身解析插值和转义；不通过文本包含断言冒充可部署的 YAML。
    result = subprocess.run(["docker", "compose", "-f", "-", "config", "--format", "json"],
                            input=payload["compose"], text=True, cwd=root,
                            capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    service = json.loads(result.stdout)["services"]["nexo-agent"]
    # config 的输出可再次作为 Compose 输入，因此会保留字面 $ 的双写形式。
    expected_environment = {key: value.replace("$", "$$") for key, value in payload["expected"].items()}
    assert service["environment"] == {"TZ": "Asia/Shanghai", **expected_environment}, service["environment"]
    assert service["network_mode"] == "host"
    assert service["restart"] == "unless-stopped"
    assert service["volumes"][0]["target"] == "/data/nexo-agent"
    assert service.get("command") is None and service.get("entrypoint") is None

    binary = root / "bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text(f"#!{sys.executable}\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n")
    docker.chmod(0o700)
    result = subprocess.run(["sh", "-c", payload["command"]], text=True, cwd=root,
                            env={**os.environ, "PATH": f"{binary}:{os.environ['PATH']}"},
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    args = json.loads(result.stdout)
    expected = ["run", "-d", "--name", "nexo-agent", "--network", "host", "--restart", "unless-stopped",
                "--env", "TZ=Asia/Shanghai"]
    for name, value in payload["expected"].items():
        expected.extend(["--env", f"{name}={value}"])
    expected.extend(["--volume", "./data/nexo-agent:/data/nexo-agent", service["image"]])
    assert args == expected, args
    assert not (root / "injected").exists(), "Shell 展开了连接参数"
    assert not (root / "data").exists(), "部署内容不应包含写文件脚本"
