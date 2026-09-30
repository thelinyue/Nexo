#!/usr/bin/env python3
"""从同一源码副本构建默认/NODELAY 两组程序；不修改产品工作区。"""
import argparse
import difflib
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = output / "source"
    root.mkdir()
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copy2(source / name, root / name)
    for name in ("crates", "migrations", "config", "web", "docker"):
        shutil.copytree(source / name, root / name,
                        ignore=shutil.ignore_patterns("node_modules", "dist", "test-results", "playwright-report", ".cache"))
    (output / "git-head.txt").write_text(subprocess.check_output(["git", "-c", f"safe.directory={source}", "-C", str(source), "rev-parse", "HEAD"], text=True))
    edits = {
        "crates/nexo-server/src/transport.rs": (
            ") -> Result<()> {\n    let (sender, mut receiver) = mpsc::channel::<OpenStream>",
            ") -> Result<()> {\n    // 仅普通 Yamux 数据连接禁用 Nagle，避免小帧等待；控制及其他 ALPN 路径不受影响。\n"
            "    stream.get_ref().0.set_nodelay(true).context(\"设置 Tunnel 数据连接 TCP_NODELAY 失败\")?;\n"
            "    let (sender, mut receiver) = mpsc::channel::<OpenStream>"),
        "crates/nexo-agent/src/main.rs": (
            "let connected = connect_tls(&connector, &endpoint).await;",
            "// 每次数据重连都重新设置；失败进入现有重试流程，不影响控制连接。\n"
            "        let connected = connect_tls(&connector, &endpoint).await.and_then(|stream| {\n"
            "            stream.get_ref().0.set_nodelay(true).context(\"设置 Tunnel 数据连接 TCP_NODELAY 失败\")?;\n"
            "            Ok(stream)\n        });"),
    }
    patch = []
    for label in ("default", "nodelay"):
        if label == "nodelay":
            for name, (old, new) in edits.items():
                path = root / name
                before = path.read_text()
                if before.count(old) != 1:
                    raise RuntimeError(f"候选注入位置不唯一：{name}")
                after = before.replace(old, new, 1)
                path.write_text(after)
                patch.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True), "a/"+name, "b/"+name))
            (output / "candidate.patch").write_text("".join(patch))
        # 复用已有 Cargo 缓存；两组使用相同编译器、锁文件和构建路径。
        subprocess.run(["docker", "run", "--rm", "-v", f"{root}:/src",
                        "-v", "codex-nexo-next-target:/target", "-v", "codex-nexo-next-registry:/usr/local/cargo/registry",
                        "-v", f"{output}:/out", "-w", "/src", "-e", "CARGO_TARGET_DIR=/target",
                        "rust:1.97-bookworm", "sh", "-c",
                        f"cargo build --release --locked -p nexo-server -p nexo-agent && mkdir /out/{label} && cp /target/release/nexo-server /target/release/nexo-agent /out/{label}/"], check=True)
        print(f"构建完成：{label}", flush=True)


if __name__ == "__main__": main()
