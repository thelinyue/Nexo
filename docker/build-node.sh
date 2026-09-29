#!/usr/bin/env bash
# 在目标架构 Linux 上构建静态原生包，避免新发行版 glibc 阻止 Debian 12 / Ubuntu 22.04 启动。
set -euo pipefail
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
case "$(uname -m)" in
  x86_64) architecture=x86_64; target=x86_64-unknown-linux-musl;;
  aarch64) architecture=aarch64; target=aarch64-unknown-linux-musl;;
  *) echo '原生节点包仅支持 x86_64 和 ARM64' >&2; exit 1;;
esac
npm --prefix web ci --ignore-scripts
npm --prefix web run build
rustup target add "$target"
cargo build --release --locked --target "$target" -p nexo-server
docker build --target caddy-build -f docker/Dockerfile.server -t nexo-node-caddy-build .
container=$(docker create nexo-node-caddy-build)
package_dir=$(mktemp -d)
trap 'docker rm "$container" >/dev/null; rm -rf -- "$package_dir"' EXIT
docker cp "$container:/usr/local/bin/caddy" "$package_dir/caddy"
cp "target/$target/release/nexo-server" docker/node-updater.py LICENSE THIRD_PARTY_NOTICES.md "$package_dir/"
chmod 755 "$package_dir/nexo-server" "$package_dir/caddy"
"$package_dir/nexo-server" --version
"$package_dir/caddy" version
mkdir -p dist
tar -C "$package_dir" -czf "dist/nexo-node-$version-linux-$architecture.tar.gz" nexo-server caddy node-updater.py LICENSE THIRD_PARTY_NOTICES.md
