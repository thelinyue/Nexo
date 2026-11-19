#!/usr/bin/env bash
# 在目标架构 Linux 上构建静态原生包，避免新发行版 glibc 阻止 Debian 12 / Ubuntu 22.04 启动。
set -euo pipefail
# 直接调用脚本时也按发布清单决定是否生成节点包。
node_version=$(python3 - <<'PY'
import json

with open("release-manifest.json", encoding="utf-8") as file:
    manifest = json.load(file)
print(manifest["node_version"] if "node" in manifest["components"] else "")
PY
)
if [[ -z "$node_version" ]]; then
  echo '本次节点代码未变化，保留原节点版本，不生成安装包'
  exit 0
fi
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
[[ "$node_version" == "$version" ]] || { echo '节点发布版本必须与本次构建版本一致' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) architecture=x86_64; target=x86_64-unknown-linux-musl;;
  aarch64) architecture=aarch64; target=aarch64-unknown-linux-musl;;
  *) echo '原生节点包仅支持 x86_64 和 ARM64' >&2; exit 1;;
esac
rustup target add "$target"
cargo build --release --locked --target "$target" -p nexo-node
package_dir=$(mktemp -d)
trap 'rm -rf -- "$package_dir"' EXIT
docker buildx build --target caddy-node --output "type=local,dest=$package_dir" -f docker/Dockerfile.server .
# 旧更新助手只接收固定文件名的普通文件，继续使用现有 ExecStart 和回滚路径。
cp "${CARGO_TARGET_DIR:-target}/$target/release/nexo-node" "$package_dir/nexo-server"
cp docker/node-updater.py LICENSE THIRD_PARTY_NOTICES.md "$package_dir/"
chmod 755 "$package_dir/nexo-server" "$package_dir/caddy"
mkdir -p dist
asset="dist/nexo-node-$version-linux-$architecture.tar.gz"
tar -C "$package_dir" -czf "$asset" nexo-server caddy node-updater.py LICENSE THIRD_PARTY_NOTICES.md
python3 docker/check-node-package.py "$asset" "$version"
