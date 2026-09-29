"""在可丢弃的 Linux 容器运行完整安装器，验证端口、重试和身份复用。

示例：docker run --rm --network none -e NEXO_INSTALLER_TEST=1 \
  -v "$PWD:/src:ro" python:3.12-bookworm python3 /src/docker/test_node_installer.py
下载、包管理和 systemd 使用替身；真实 shell、解包校验、权限和 runuser 保留。
这不替代真实 systemd 启动或公网注册验收。
"""
import hashlib
import os
from pathlib import Path
import pty
import select
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import unittest


class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("NEXO_INSTALLER_TEST") != "1" or not Path("/.dockerenv").exists() or os.geteuid() != 0:
            raise RuntimeError("仅允许在明确指定的可丢弃 root 容器中运行安装器测试")
        cls.paths = [Path(p) for p in ("/opt/nexo-node", "/var/lib/nexo-node", "/var/lib/nexo-node-update", "/usr/local/lib/nexo-node")]
        cls.units = [Path("/etc/systemd/system") / f"nexo-node{suffix}" for suffix in (".service", "-update.service", "-update.path")]
        if any(p.exists() for p in cls.paths + cls.units):
            raise RuntimeError("测试容器已有 Nexo 安装，拒绝覆盖")
        Path("/etc/systemd/system").mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nexo-installer-test-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "systemctl.log"
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", TEST_PACKAGE=str(self.root / "release"), TEST_SYSTEMCTL=str(self.log))
        self.script = Path(__file__).with_name("install-node.sh")
        self.write_executable(self.bin / "apt-get", "#!/bin/sh\ncat >/dev/null\n")
        self.write_executable(self.bin / "systemctl", '#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_SYSTEMCTL"\n')
        self.write_executable(self.bin / "curl", '''#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
url = next(arg for arg in args if arg.startswith('https://'))
if not url.startswith('https://github.com/thelinyue/Nexo/releases/download/v0.2.12/'):
    raise SystemExit(22)
if os.environ.get('TEST_DOWNLOAD_FAIL'):
    raise SystemExit(22)
shutil.copyfile(pathlib.Path(os.environ['TEST_PACKAGE']) / url.rsplit('/', 1)[1], args[args.index('-o') + 1])
''')
        release = self.root / "release"
        release.mkdir()
        files = self.root / "files"
        files.mkdir()
        self.write_executable(files / "nexo-server", '''#!/usr/bin/env python3
import json, pathlib, sys
if sys.argv[1:] == ['--version']:
    print('nexo 0.2.12')
else:
    assert '--enroll-only' in sys.argv and '--server-url' in sys.argv
    assert 'test-enrollment-secret' not in ' '.join(sys.argv)
    assert 'test-enrollment-secret' not in str(__import__('os').environ)
    assert sys.stdin.readline().strip() == 'test-enrollment-secret'
    root = pathlib.Path(sys.argv[sys.argv.index('--data-dir') + 1])
    (root / 'node-identity.json').write_text(json.dumps({'server_url': sys.argv[sys.argv.index('--server-url') + 1], 'id': 'test-node'}))
''')
        for name in ("caddy", "node-updater.py", "LICENSE", "THIRD_PARTY_NOTICES.md"):
            (files / name).write_text("test fixture\n")
        asset = release / f"nexo-node-0.2.12-linux-{os.uname().machine}.tar.gz"
        with tarfile.open(asset, "w:gz") as archive:
            for file in files.iterdir():
                archive.add(file, arcname=file.name)
        (release / "SHA256SUMS").write_text(f"{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n")

    @staticmethod
    def write_executable(path, content):
        path.write_text(content)
        path.chmod(0o755)

    def tearDown(self):
        # 仅移除本测试在隔离容器中创建的固定路径；setUpClass 已拒绝任何已有安装。
        for path in self.units:
            path.unlink(missing_ok=True)
        for path in self.paths:
            if path.exists():
                shutil.rmtree(path)
        self.temp.cleanup()

    def run_installer(self, *extra, input_token=None):
        args = ["bash", str(self.script), "--server", "https://manage.example", "--version", "0.2.12", "--http-port", "8080", "--https-port", "8443", "--data-port", "9892", *extra]
        if input_token is not None:
            result = subprocess.run(args, input=input_token, text=True, capture_output=True, env=self.env, timeout=20)
            output = result.stdout + result.stderr
            self.assertNotIn("test-enrollment-secret", output)
            return result.returncode, output
        child, terminal = pty.fork()
        if child == 0:
            os.execvpe(args[0], args, self.env)
        output = bytearray()
        sent = False
        deadline = time.monotonic() + 20
        try:
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(terminal, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
                    if not sent and "不回显".encode() in output:
                        os.write(terminal, b"test-enrollment-secret\n")
                        sent = True
            else:
                os.kill(child, 9)
                self.fail("安装器未在限定时间内结束")
        finally:
            os.close(terminal)
            _, status = os.waitpid(child, 0)
        text = output.decode(errors="replace")
        self.assertNotIn("test-enrollment-secret", text)
        return os.waitstatus_to_exitcode(status), text

    def test_custom_ports_and_reinstall_preserve_identity(self):
        with socket.socket() as http, socket.socket() as https:
            http.bind(("0.0.0.0", 80))
            https.bind(("0.0.0.0", 443))
            code, output = self.run_installer()
            self.assertEqual(code, 0, output)
        identity = Path("/var/lib/nexo-node/node-identity.json")
        original = identity.read_bytes()
        self.assertEqual(identity.stat().st_mode & 0o777, 0o600)
        self.assertIn("9892、8080、8443", output)
        self.assertIn("enable --now nexo-node-update.path nexo-node.service", self.log.read_text())
        code, output = self.run_installer()
        self.assertEqual(code, 0, output)
        self.assertEqual(identity.read_bytes(), original)
        self.assertNotIn("粘贴节点接入凭证", output)
        code, output = self.run_installer("--server", "https://other.example")
        self.assertNotEqual(code, 0)
        self.assertIn("已接入另一个管理地址", output)
        self.assertEqual(identity.read_bytes(), original)

    def test_embedded_credential_installs_without_terminal_or_prompt(self):
        self.env["token"] = "unrelated-exported-variable"
        code, output = self.run_installer(input_token="test-enrollment-secret\n")
        self.assertEqual(code, 0, output)
        self.assertNotIn("粘贴节点接入凭证", output)
        identity = Path("/var/lib/nexo-node/node-identity.json")
        original = identity.read_bytes()
        self.assertNotIn(b"test-enrollment-secret", original)
        self.assertNotIn("test-enrollment-secret", self.units[0].read_text())
        code, output = self.run_installer(input_token="")
        self.assertEqual(code, 0, output)
        self.assertEqual(identity.read_bytes(), original)

    def test_missing_embedded_credential_does_not_install(self):
        code, output = self.run_installer(input_token="")
        self.assertNotEqual(code, 0)
        self.assertIn("缺少接入凭证", output)
        self.assertFalse(Path("/opt/nexo-node").exists())
        self.assertNotIn("粘贴节点接入凭证", output)

    def test_occupied_port_stops_before_installation(self):
        with socket.socket() as occupied:
            occupied.bind(("0.0.0.0", 8443))
            code, output = self.run_installer()
        self.assertNotEqual(code, 0)
        self.assertIn("端口 8443 已被占用", output)
        self.assertFalse(Path("/opt/nexo-node").exists())
        self.assertFalse(self.log.exists())

    def test_conflicting_ports_are_rejected(self):
        code, output = self.run_installer("--https-port", "9892")
        self.assertNotEqual(code, 0)
        self.assertIn("端口不能相同", output)
        self.assertFalse(Path("/opt/nexo-node").exists())

    def test_download_failure_is_actionable_and_retryable(self):
        self.env["TEST_DOWNLOAD_FAIL"] = "1"
        code, output = self.run_installer()
        self.assertNotEqual(code, 0)
        self.assertIn("下载失败", output)
        self.assertFalse(self.units[0].exists())
        self.assertFalse(Path("/var/lib/nexo-node/node-identity.json").exists())
        del self.env["TEST_DOWNLOAD_FAIL"]
        code, output = self.run_installer()
        self.assertEqual(code, 0, output)

    def test_corrupted_package_never_registers_or_starts(self):
        asset = next((self.root / "release").glob("*.tar.gz"))
        asset.write_bytes(b"corrupt")
        code, output = self.run_installer()
        self.assertNotEqual(code, 0)
        self.assertIn("安装包校验失败", output)
        self.assertFalse(self.units[0].exists())
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
