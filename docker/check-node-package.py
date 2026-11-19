#!/usr/bin/env python3
"""验证旧助手能解包，运行解包后的静态 Linux 程序。"""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


def main(asset, version):
    spec = importlib.util.spec_from_file_location(
        "node_updater", Path(__file__).with_name("node-updater.py")
    )
    updater = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(updater)
    with tempfile.TemporaryDirectory() as directory, tarfile.open(asset) as archive:
        root = Path(directory)
        for member in updater.validate_archive(archive):
            with archive.extractfile(member) as source, (root / member.name).open("wb") as target:
                shutil.copyfileobj(source, target)
        for name in ("nexo-server", "caddy"):
            binary = root / name
            binary.chmod(0o755)
            elf = subprocess.check_output(["readelf", "-W", "-l", "-d", binary], text=True)
            if "(NEEDED)" in elf or any(line.split()[:1] == ["INTERP"] for line in elf.splitlines()):
                raise ValueError(f"{name} 必须为静态 Linux 程序")
        node = root / "nexo-server"
        actual = subprocess.check_output([node, "--version"], text=True, timeout=10).split()[-1]
        if actual != version:
            raise ValueError(f"节点程序版本 {actual} 与发布版本 {version} 不一致")
        for args, code in [(["node", "--help"], 0), ([], 2), (["admin", "recover"], 2)]:
            result = subprocess.run(
                [node, "--data-dir", root / "data", *args], capture_output=True, timeout=10
            )
            if result.returncode != code or (root / "data").exists():
                raise ValueError("节点程序入口与安装约定不符")
        caddy = root / "caddy"
        subprocess.run([caddy, "version"], check=True, timeout=10)
        modules = subprocess.check_output([caddy, "list-modules"], text=True, timeout=10)
        if any(line.startswith("dns.providers.") for line in modules.splitlines()):
            raise ValueError("节点 Caddy 应使用标准模块")
    print(f"节点安装包已验证：{asset}，{Path(asset).stat().st_size} 字节")


if __name__ == "__main__":
    main(*sys.argv[1:])
