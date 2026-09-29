#!/usr/bin/env bash
# 原生 VPS 安装器：接入凭证只通过标准输入传给节点，不保存在服务参数或日志。
set -euo pipefail
set +x
umask 077
server=''
version=''
http_port=80
https_port=443
data_port=9891
while (($#)); do
  case "$1" in
    --server) server="${2:?缺少管理地址}"; shift 2;;
    --version) version="${2:?缺少版本}"; shift 2;;
    --http-port) http_port="${2:?缺少 HTTP 端口}"; shift 2;;
    --https-port) https_port="${2:?缺少 HTTPS 端口}"; shift 2;;
    --data-port) data_port="${2:?缺少数据端口}"; shift 2;;
    *) echo '仅支持 --server、--version、--http-port、--https-port 和 --data-port 参数' >&2; exit 1;;
  esac
done
[[ $EUID == 0 ]] || { echo '请使用 sudo 执行安装命令' >&2; exit 1; }
[[ "$server" == https://* && "$server" != *$'\n'* ]] || { echo '请填写 HTTPS 管理地址' >&2; exit 1; }
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo '版本格式无效' >&2; exit 1; }
for port in "$http_port" "$https_port" "$data_port"; do
  [[ "$port" =~ ^[1-9][0-9]{0,4}$ && "$port" -le 65535 ]] || { echo '端口必须在 1–65535 之间' >&2; exit 1; }
  case "$port" in 8282|8290) echo '公网端口与节点内部端口冲突' >&2; exit 1;; esac
done
[[ "$http_port" != "$https_port" && "$http_port" != "$data_port" && "$https_port" != "$data_port" ]] || { echo 'HTTP、HTTPS 与数据端口不能相同' >&2; exit 1; }
. /etc/os-release
case "$ID:$VERSION_ID" in debian:12|debian:13|ubuntu:22.04|ubuntu:24.04) ;; *) echo '支持 Debian 12/13、Ubuntu 22.04/24.04' >&2; exit 1;; esac
case "$(uname -m)" in x86_64|aarch64) ;; *) echo '仅支持 x86_64 和 ARM64' >&2; exit 1;; esac
if [[ -f /etc/systemd/system/nexo-node.service ]] && ! grep -Fq 'ExecStart=/opt/nexo-node/current/nexo-server' /etc/systemd/system/nexo-node.service; then
  echo '已有同名 systemd 服务，未接管；请先核对配置' >&2; exit 1
fi
command -v systemctl >/dev/null || { echo '安装需要 systemd' >&2; exit 1; }
# 先读取标准输入中的一次性凭证，避免 apt 等子进程消耗；不导出为环境变量。
token=''
export -n token
if [[ ! -f /var/lib/nexo-node/node-identity.json ]]; then
  if [[ -t 0 ]]; then
    read -r -s -p '粘贴节点接入凭证（不回显）：' token </dev/tty
    echo
  else
    IFS= read -r token || [[ -n "$token" ]] || { echo '缺少接入凭证，请重新复制完整安装命令' >&2; exit 1; }
  fi
  [[ -n "$token" && ${#token} -le 128 ]] || { echo '接入凭证格式无效，请重新复制完整安装命令' >&2; exit 1; }
fi
apt-get update -qq </dev/null
apt-get install -y --no-install-recommends ca-certificates curl python3 </dev/null
python3 - "$server" <<'PY'
import json, pathlib, sys, urllib.parse
url = urllib.parse.urlsplit(sys.argv[1])
if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
    raise SystemExit('管理地址必须是 HTTPS，不得包含凭据、路径或查询参数')
identity = pathlib.Path('/var/lib/nexo-node/node-identity.json')
if identity.exists() and json.loads(identity.read_text())['server_url'].rstrip('/') != sys.argv[1].rstrip('/'):
    raise SystemExit('此 VPS 已接入另一个管理地址，身份已保留；请先核对原节点配置')
PY
if [[ ! -f /var/lib/nexo-node/node-identity.json ]]; then
  python3 - "$http_port" "$https_port" "$data_port" <<'PY'
import socket, sys
for port in (int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), 8282, 8290):
    with socket.socket() as sock:
        try:
            sock.bind(('0.0.0.0', port))
        except OSError:
            raise SystemExit(f'端口 {port} 已被占用。请在节点安装页选择空闲端口，或由管理员调整配置后重试；未接管已有服务')
PY
fi
getent passwd nexo-node >/dev/null || useradd --system --home-dir /var/lib/nexo-node --shell /usr/sbin/nologin nexo-node
install -d -m 755 /opt/nexo-node /opt/nexo-node/releases /usr/local/lib/nexo-node
install -d -o nexo-node -g nexo-node -m 700 /var/lib/nexo-node
install -d -m 755 /var/lib/nexo-node-update
install -d -o nexo-node -g nexo-node -m 700 /var/lib/nexo-node-update/inbox
tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
asset="nexo-node-${version}-linux-$(uname -m).tar.gz"
release="https://github.com/thelinyue/Nexo/releases/download/v${version}"
curl --fail --location --connect-timeout 15 --max-time 300 --proto '=https' --proto-redir '=https' "$release/$asset" -o "$tmpdir/$asset" || { echo '下载失败：请确认所选版本已发布当前架构的节点安装包，并检查 VPS 到 GitHub 的网络后重试' >&2; exit 1; }
curl --fail --location --connect-timeout 15 --max-time 60 --proto '=https' --proto-redir '=https' "$release/SHA256SUMS" -o "$tmpdir/SHA256SUMS" || { echo '无法下载官方校验文件，未安装；请稍后重试' >&2; exit 1; }
python3 - "$tmpdir" "$asset" "$version" <<'PY'
import hashlib, pathlib, sys, tarfile, tempfile, shutil, subprocess
root, name, version = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
expected = dict((line.split()[1].lstrip('*'), line.split()[0]) for line in (root/'SHA256SUMS').read_text().splitlines() if len(line.split()) == 2)
if hashlib.sha256((root/name).read_bytes()).hexdigest() != expected.get(name):
    raise SystemExit('安装包校验失败，未安装')
destination = pathlib.Path('/opt/nexo-node/releases')/version
if destination.is_symlink():
    raise SystemExit('版本目录不允许符号链接')
if not destination.exists():
    with tempfile.TemporaryDirectory(dir=destination.parent) as staging:
        staging = pathlib.Path(staging)
        unpacked = staging/'unpacked'
        unpacked.mkdir()
        # 安装器使用 umask 077 保护凭证；程序目录需允许专用节点用户遍历。
        unpacked.chmod(0o755)
        with tarfile.open(root/name) as archive:
            allowed = {'nexo-server', 'caddy', 'node-updater.py', 'LICENSE', 'THIRD_PARTY_NOTICES.md'}
            members = archive.getmembers()
            if len(members) != len(allowed) or {m.name for m in members} != allowed or any(not m.isfile() or m.size > 300*1024*1024 for m in members):
                raise SystemExit('安装包文件清单、路径或类型无效')
            for member in members:
                with archive.extractfile(member) as source, (unpacked/member.name).open('wb') as target:
                    shutil.copyfileobj(source, target)
        for binary in ('nexo-server', 'caddy'):
            (unpacked/binary).chmod(0o755)
        result = subprocess.run([str(unpacked/'nexo-server'), '--version'], check=True, capture_output=True, text=True, timeout=10)
        if result.stdout.strip().split()[-1] != version:
            raise SystemExit('程序版本与安装包不匹配')
        unpacked.rename(destination)
PY
install -m 755 "/opt/nexo-node/releases/$version/node-updater.py" /usr/local/lib/nexo-node/updater.py
if [[ ! -L /opt/nexo-node/current ]]; then
  ln -s "/opt/nexo-node/releases/$version" /opt/nexo-node/current
fi
cat >/etc/systemd/system/nexo-node.service <<'UNIT'
[Unit]
Description=Nexo VPS node
After=network-online.target
Wants=network-online.target
[Service]
User=nexo-node
Group=nexo-node
Environment=NEXO_CADDY_BINARY=/opt/nexo-node/current/caddy
ExecStart=/opt/nexo-node/current/nexo-server --data-dir /var/lib/nexo-node node
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/nexo-node /var/lib/nexo-node-update/inbox
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/nexo-node-update.service <<'UNIT'
[Unit]
Description=Nexo constrained node updater
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/nexo-node/updater.py
TimeoutStartSec=20min
UNIT
cat >/etc/systemd/system/nexo-node-update.path <<'UNIT'
[Unit]
Description=Nexo node update request watcher
Wants=nexo-node-update.service
After=nexo-node.service
[Path]
PathChanged=/var/lib/nexo-node-update/inbox/request.json
Unit=nexo-node-update.service
[Install]
WantedBy=multi-user.target
UNIT
if [[ ! -f /var/lib/nexo-node/node-identity.json ]]; then
  # enroll-only 保存身份后退出；不在安装器中启动第二个常驻转发进程。
  printf '%s\n' "$token" | runuser -u nexo-node -- /opt/nexo-node/current/nexo-server --data-dir /var/lib/nexo-node node --server-url "$server" --enroll-only
  unset token
fi
systemctl daemon-reload
systemctl enable --now nexo-node-update.path nexo-node.service
echo '节点已安装，请在 Nexo 节点页审批并分配工作空间。'
echo "请按服务需要放行 TCP $data_port、$http_port、$https_port 和业务端口；防火墙未自动修改。"
echo "端口检查已使用 HTTP $http_port / HTTPS $https_port；实际监听由管理 Server 下发，请将 caddy.http_listen 和服务 HTTPS 端口设为相同值。"
echo '重复安装保留原节点身份和当前版本；后续版本更新请使用节点管理页。'
