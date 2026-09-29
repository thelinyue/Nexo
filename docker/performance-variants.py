#!/usr/bin/env python3
"""在临时源码副本构建传输实验，生产工作区和默认参数不变。要求 Linux cargo。"""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def replace(path, old, new):
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise RuntimeError(f"实验注入位置已变化：{path.name}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--target-dir", required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nexo-perf-source-") as temporary:
        root = Path(temporary)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copy2(source / name, root / name)
        for name in ("crates", "migrations", "config"):
            shutil.copytree(source / name, root / name)
        (root / "web/src/data").mkdir(parents=True)
        shutil.copy2(source / "web/src/data/hd-icons.json", root / "web/src/data/hd-icons.json")
        paths = [root / "crates/nexo-server/src/transport.rs", root / "crates/nexo-agent/src/main.rs"]
        originals = [path.read_text(encoding="utf-8") for path in paths]
        for label, size, nodelay in [("buffer32", 32768, False), ("buffer64", 65536, False), ("nodelay", 8192, True)]:
            for path, text in zip(paths, originals):
                path.write_text(text, encoding="utf-8")
            for path, io in zip(paths, ("socket", "local")):
                replace(path, f"tokio::io::copy_bidirectional(&mut {io}, &mut stream).await?;",
                        f"tokio::io::copy_bidirectional_with_sizes(&mut {io}, &mut stream, {size}, {size}).await?;")
            if nodelay:
                # 只改变承载 Yamux 的 TCP 两端；控制连接、回源与公网入口不参与此变量。
                replace(paths[0], "nexo_tunnel::configure_tunnel_tcp_keepalive(&socket)?;",
                        "nexo_tunnel::configure_tunnel_tcp_keepalive(&socket)?; if data { socket.set_nodelay(true)?; }")
                replace(paths[1], "Ok(stream) => {\n                delay = 1;",
                        "Ok(stream) => {\n                stream.get_ref().0.set_nodelay(true).expect(\"实验数据连接设置失败\");\n                delay = 1;")
            subprocess.run(["cargo", "build", "--release", "--locked", "--manifest-path", str(root / "Cargo.toml"),
                            "--target-dir", args.target_dir, "-p", "nexo-server", "-p", "nexo-agent"], check=True)
            destination = output / label
            destination.mkdir(exist_ok=True)
            for binary in ("nexo-server", "nexo-agent"):
                shutil.copy2(Path(args.target_dir) / "release" / binary, destination / binary)
            print(f"实验构建完成：{label}", flush=True)


if __name__ == "__main__":
    main()
