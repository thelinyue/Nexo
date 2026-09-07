#!/usr/bin/env bash
# Nexo 第二阶段 Linux Docker 验收：公网入口、管理员 Session、Tunnel、
# Headscale/Caddy 隔离，以及双向 Site-to-Site 路由的重启收敛。
# Headscale 官方 CLI 只用于读取节点数量和稳定 Node ID，不读取任何数据库。
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$SCRIPT_DIR/compose.phase2.integration.yml}"
COMPOSE_PROJECT_NAME="nexo-phase2-integration"
export COMPOSE_PROJECT_NAME

HTTP_URL="${NEXO_HTTP_URL:-http://127.0.0.1:29828}"
BOOTSTRAP_CODE="${NEXO_ADMIN_TOKEN:-integration-admin}"
ADMIN_USERNAME="${NEXO_ADMIN_USERNAME:-integration-admin}"
ADMIN_PASSWORD="${NEXO_ADMIN_PASSWORD:-integration-password-1234}"
PUBLIC_DOMAIN="${NEXO_PHASE2_DOMAIN:-phase2.test}"
CURL_CONNECT_TIMEOUT="${NEXO_CURL_CONNECT_TIMEOUT:-3}"
CURL_MAX_TIME="${NEXO_CURL_MAX_TIME:-20}"

COOKIE_JAR="$(mktemp)"
SECURE_COOKIE_JAR="$(mktemp)"
CERT_DIR="$(mktemp -d -t nexo-phase2-certs.XXXXXX)"
export NEXO_PHASE2_CERT_DIR="$CERT_DIR"
CSRF_TOKEN=""
HEADSCALE_PID=""
HEADSCALE_STOPPED=0
CADDY_PID=""
CADDY_STOPPED=0

dc() {
  docker compose --project-name "$COMPOSE_PROJECT_NAME" --file "$COMPOSE_FILE" "$@"
}

http_curl() {
  curl --silent --show-error --noproxy '*' \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" "$@"
}

cleanup_on_exit() {
  local exit_code=$?
  if ((exit_code != 0)) && command -v docker >/dev/null 2>&1; then
    echo "验收失败，先输出 Compose 状态和相关容器日志" >&2
    dc ps -a >&2 || true
    if [[ -n "$CSRF_TOKEN" ]]; then
      echo "Nexo 设备与组网状态快照：" >&2
      api "$HTTP_URL/api/v1/devices" | jq . >&2 || true
      api "$HTTP_URL/api/v1/mesh/status" | jq . >&2 || true
      if [[ -n "${link:-}" ]]; then
        api "$HTTP_URL/api/v1/site-links/$link" | jq . >&2 || true
      fi
    fi
    dc logs --no-color --tail=160 nexo-server home-gateway office-gateway outside-probe >&2 || true
  fi
  if [[ -n "$HEADSCALE_PID" && "$HEADSCALE_STOPPED" == "1" ]]; then
    dc exec -T nexo-server sh -c "kill -CONT $HEADSCALE_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$CADDY_PID" && "$CADDY_STOPPED" == "1" ]]; then
    dc exec -T nexo-server sh -c "kill -CONT $CADDY_PID" >/dev/null 2>&1 || true
  fi
  if command -v docker >/dev/null 2>&1; then
    # 项目名固定，只清理本脚本创建的服务和测试卷，不触碰其它 Compose
    # 项目、仓库文件或 .edge-screenshot/。
    dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  rm -f "$COOKIE_JAR" "$SECURE_COOKIE_JAR"
  rm -rf "$CERT_DIR"
  exit "$exit_code"
}
trap cleanup_on_exit EXIT

for command in docker curl jq openssl python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "需要安装 $command 才能执行阶段二 Linux Docker 验收" >&2
    exit 2
  fi
done
if ! docker compose version >/dev/null 2>&1; then
  echo "当前 Docker 不支持 Compose V2（需要 docker compose）" >&2
  exit 2
fi

api() {
  http_curl --fail --cookie "$COOKIE_JAR" -H "x-nexo-csrf: $CSRF_TOKEN" "$@"
}

request_json() {
  local method="$1"
  local url="$2"
  local body="$3"
  local jar="${4:-$COOKIE_JAR}"
  local csrf="${5:-$CSRF_TOKEN}"
  http_curl --fail -H "content-type: application/json" \
    --cookie "$jar" -H "x-nexo-csrf: $csrf" \
    -X "$method" "$url" -d "$body"
}

post_json() { request_json POST "$1" "$2"; }
put_json() { request_json PUT "$1" "$2"; }
delete_json() { request_json DELETE "$1" '{}'; }

expect_status() {
  local expected="$1"
  local method="$2"
  local url="$3"
  local body="$4"
  local actual
  actual="$(http_curl -H "content-type: application/json" \
    --cookie "$COOKIE_JAR" -H "x-nexo-csrf: $CSRF_TOKEN" \
    -X "$method" "$url" -d "$body" -o /dev/null -w '%{http_code}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "期望 HTTP $expected，实际为 HTTP $actual：$url" >&2
    return 1
  fi
}

wait_for() {
  local description="$1"
  local command="$2"
  local attempts="${3:-60}"
  for ((i = 1; i <= attempts; i++)); do
    if eval "$command" >/dev/null 2>&1; then
      echo "✓ $description"
      return 0
    fi
    sleep 2
  done
  echo "✗ 等待超时：$description" >&2
  return 1
}

generate_test_certificate() {
  local ext_file="$CERT_DIR/server.ext"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj "/CN=Nexo Phase2 Test CA" \
    -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/mesh-ca.crt" >/dev/null 2>&1
  openssl req -new -newkey rsa:2048 -nodes \
    -subj "/CN=$PUBLIC_DOMAIN" \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" >/dev/null 2>&1
  printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    "subjectAltName=DNS:$PUBLIC_DOMAIN,DNS:*.$PUBLIC_DOMAIN" >"$ext_file"
  openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/mesh-ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -days 2 -extfile "$ext_file" \
    -out "$CERT_DIR/server.crt" >/dev/null 2>&1
}

create_site() {
  post_json "$HTTP_URL/api/v1/sites" \
    "{\"tenant_id\":\"default\",\"name\":\"$1\"}" | jq -r '.id'
}

create_token() {
  post_json "$HTTP_URL/api/v1/enrollments" \
    "{\"tenant_id\":\"default\",\"site_id\":\"$1\",\"ttl_seconds\":1800}" \
    | jq -r '.token'
}

find_enrollment() {
  local name="$1"
  for ((i = 1; i <= 90; i++)); do
    local id
    id="$(api "$HTTP_URL/api/v1/enrollments" | jq -r --arg name "$name" \
      '.[] | select(.device_name == $name and .status == "awaiting_approval") | .enrollment_id' \
      | head -n 1)"
    if [[ -n "$id" && "$id" != "null" ]]; then
      printf '%s' "$id"
      return 0
    fi
    sleep 2
  done
  echo "找不到设备入网请求：$name" >&2
  return 1
}

approve() { api -X POST "$HTTP_URL/api/v1/enrollments/$1/approve" >/dev/null; }

device_id() {
  api "$HTTP_URL/api/v1/devices" | jq -r --arg name "$1" \
    '.[] | select(.name == $name) | .id' | head -n 1
}

headscale_nodes() {
  dc exec -T nexo-server /usr/local/bin/headscale \
    --config /data/nexo/headscale/config.yaml nodes list --output json
}

headscale_node_ids() {
  headscale_nodes | jq -c \
    '((if type == "array" then . else (.nodes // []) end)
      | map(.id // .node_id // .nodeId // empty | tostring) | sort)'
}

headscale_node_count() { headscale_node_ids | jq 'length'; }

headscale_pid() {
  dc exec -T nexo-server sh -c '
    for comm in /proc/[0-9]*/comm; do
      read -r name < "$comm" || continue
      if [ "$name" = "headscale" ]; then
        printf "%s" "${comm#/proc/}" | sed "s#/comm##"
        exit 0
      fi
    done
    exit 1
  '
}

caddy_pid() {
  dc exec -T nexo-server sh -c '
    for comm in /proc/[0-9]*/comm; do
      read -r name < "$comm" || continue
      if [ "$name" = "caddy" ]; then
        printf "%s" "${comm#/proc/}" | sed "s#/comm##"
        exit 0
      fi
    done
    exit 1
  '
}

public_request() {
  local scheme="$1"
  local host="$2"
  local path="$3"
  local jar="${4:-}"
  local url="http://$host:28080$path"
  local -a args=(--resolve "$host:28080:127.0.0.1")
  if [[ "$scheme" == "https" ]]; then
    url="https://$host:28443$path"
    args=(--insecure --resolve "$host:28443:127.0.0.1")
  fi
  if [[ -n "$jar" ]]; then
    args+=(--cookie "$jar")
  fi
  http_curl --fail "${args[@]}" "$url"
}

echo "生成阶段二临时 CA 和根域名/泛域名证书"
generate_test_certificate

echo "清理上一次同名验收拓扑并一次性构建验收镜像"
dc down --volumes --remove-orphans >/dev/null 2>&1 || true
dc build nexo-server home-gateway office-gateway home-terminal office-terminal outside-probe
dc up -d --no-build nexo-server
wait_for "Nexo Server 健康" "http_curl --fail '$HTTP_URL/health'" 90

echo "初始化测试管理员 Session"
initialize_response="$(http_curl --fail -c "$COOKIE_JAR" \
  -H 'content-type: application/json' -X POST \
  "$HTTP_URL/api/v1/auth/initialize" \
  -d "$(jq -cn --arg code "$BOOTSTRAP_CODE" --arg username "$ADMIN_USERNAME" \
    --arg password "$ADMIN_PASSWORD" \
    '{bootstrap_code:$code,username:$username,password:$password}')")"
CSRF_TOKEN="$(printf '%s' "$initialize_response" | jq -r '.csrf_token // empty')"
if [[ -z "$CSRF_TOKEN" ]]; then
  echo "管理员初始化未返回 CSRF Token" >&2
  exit 1
fi
echo "✓ LAN HTTP Session 已建立"

echo "配置验收域名、手动证书并启用 HTTPS"
put_json "$HTTP_URL/api/v1/settings/public-entry" \
  "$(jq -cn --arg domain "$PUBLIC_DOMAIN" \
    '{base_domain:$domain,https_enabled:true,certificate_mode:"manual",acme_environment:"staging"}')" \
  >/dev/null
post_json "$HTTP_URL/api/v1/settings/public-entry/certificate" \
  "$(jq -cn --arg certificate "$(<"$CERT_DIR/server.crt")" \
    --arg private_key "$(<"$CERT_DIR/server.key")" \
    '{certificate_pem:$certificate,private_key_pem:$private_key}')" >/dev/null
put_json "$HTTP_URL/api/v1/settings/public-entry" \
  "$(jq -cn --arg domain "$PUBLIC_DOMAIN" \
    '{base_domain:$domain,https_enabled:true,certificate_mode:"manual",acme_environment:"staging"}')" \
  >/dev/null
wait_for "公网 HTTPS 入口 READY" \
  "test \"\$(api '$HTTP_URL/api/v1/settings/public-entry' | jq -r '.apply_status')\" = READY" 90
wait_for "Caddy HTTPS 管理入口可访问" \
  "public_request https nexo.$PUBLIC_DOMAIN /api/v1/auth/status | jq -e '.initialized == true'" 90
wait_for "Headscale 组网组件正常" \
  "test \"\$(api '$HTTP_URL/api/v1/mesh/status' | jq -r '.status')\" = normal" 120

echo "创建站点和 Agent 入网凭证"
home_site="$(create_site 家庭)"
office_site="$(create_site 办公室)"
home_token="$(create_token "$home_site")"
office_token="$(create_token "$office_site")"
export NEXO_HOME_ENROLLMENT_TOKEN="$home_token"
export NEXO_OFFICE_ENROLLMENT_TOKEN="$office_token"
dc up -d --no-build home-gateway office-gateway
home_enrollment="$(find_enrollment 家庭网关)"
office_enrollment="$(find_enrollment 办公网关)"
approve "$home_enrollment"
approve "$office_enrollment"
unset NEXO_HOME_ENROLLMENT_TOKEN NEXO_OFFICE_ENROLLMENT_TOKEN

wait_for "家庭网关在线" \
  "test \"\$(api '$HTTP_URL/api/v1/devices' | jq -r '.[] | select(.name == \"家庭网关\") | .status')\" = online" 120
wait_for "办公网关在线" \
  "test \"\$(api '$HTTP_URL/api/v1/devices' | jq -r '.[] | select(.name == \"办公网关\") | .status')\" = online" 120
wait_for "家庭网关已连接异地组网" \
  "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select(.name == \"家庭网关\" and .mesh_status == \"connected\")] | length == 1'" 180
wait_for "办公网关已连接异地组网" \
  "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select(.name == \"办公网关\" and .mesh_status == \"connected\")] | length == 1'" 180
home_device="$(device_id 家庭网关)"
office_device="$(device_id 办公网关)"

dc up -d --no-build --no-recreate home-terminal office-terminal outside-probe
wait_for "家庭终端 HTTP 服务" \
  "dc exec -T home-terminal curl --fail --silent --noproxy '*' --connect-timeout 3 --max-time 10 http://192.168.10.100:8800/source" 60
wait_for "办公室终端 HTTP 服务" \
  "dc exec -T office-terminal curl --fail --silent --noproxy '*' --connect-timeout 3 --max-time 10 http://192.168.20.100:8800/source" 60

home_iface="$(api "$HTTP_URL/api/v1/devices" | jq -r \
  '.[] | select(.name == "家庭网关") | .gateway_report.local_networks[] | select(.prefix == "192.168.10.0/24") | .interface_id' | head -n 1)"
office_iface="$(api "$HTTP_URL/api/v1/devices" | jq -r \
  '.[] | select(.name == "办公网关") | .gateway_report.local_networks[] | select(.prefix == "192.168.20.0/24") | .interface_id' | head -n 1)"
[[ -n "$home_iface" && -n "$office_iface" ]]

echo "验证默认路由、错误租户和重叠网段会被拒绝"
expect_status 400 POST "$HTTP_URL/api/v1/site-networks" \
  "{\"tenant_id\":\"default\",\"site_id\":\"$home_site\",\"name\":\"默认路由\",\"publisher_device_id\":\"$home_device\",\"interface_id\":\"$home_iface\",\"prefix\":\"0.0.0.0/0\"}"
expect_status 400 POST "$HTTP_URL/api/v1/site-networks" \
  "{\"tenant_id\":\"default\",\"site_id\":\"$home_site\",\"name\":\"IPv6 默认路由\",\"publisher_device_id\":\"$home_device\",\"interface_id\":\"$home_iface\",\"prefix\":\"::/0\"}"
expect_status 404 POST "$HTTP_URL/api/v1/sites" \
  '{"tenant_id":"missing-tenant","name":"错误租户"}'

home_network="$(post_json "$HTTP_URL/api/v1/site-networks" \
  "{\"tenant_id\":\"default\",\"site_id\":\"$home_site\",\"name\":\"家庭局域网\",\"publisher_device_id\":\"$home_device\",\"interface_id\":\"$home_iface\",\"prefix\":\"192.168.10.0/24\"}" | jq -r '.id')"
expect_status 409 POST "$HTTP_URL/api/v1/site-networks" \
  "{\"tenant_id\":\"default\",\"site_id\":\"$office_site\",\"name\":\"办公室冲突网段\",\"publisher_device_id\":\"$office_device\",\"interface_id\":\"$office_iface\",\"prefix\":\"192.168.10.0/24\"}"
api "$HTTP_URL/api/v1/site-networks" | jq -e --arg site "$office_site" \
  '[.[] | select(.site_id == $site and .desired_prefix == "192.168.10.0/24")] | length == 0' \
  >/dev/null
api "$HTTP_URL/api/v1/site-links" | jq -e 'length == 0' >/dev/null
office_network="$(post_json "$HTTP_URL/api/v1/site-networks" \
  "{\"tenant_id\":\"default\",\"site_id\":\"$office_site\",\"name\":\"办公室局域网\",\"publisher_device_id\":\"$office_device\",\"interface_id\":\"$office_iface\",\"prefix\":\"192.168.20.0/24\"}" | jq -r '.id')"
link="$(post_json "$HTTP_URL/api/v1/site-links" \
  "{\"tenant_id\":\"default\",\"left_site_id\":\"$home_site\",\"left_network_id\":\"$home_network\",\"right_site_id\":\"$office_site\",\"right_network_id\":\"$office_network\"}" | jq -r '.id')"
post_json "$HTTP_URL/api/v1/site-links/$link/router-confirmations/$home_site" '{}' >/dev/null
post_json "$HTTP_URL/api/v1/site-links/$link/router-confirmations/$office_site" '{}' >/dev/null
wait_for "Site Gateway 路由 READY" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 180

echo "验证双向 Site-to-Site HTTP、HTTPS、8 MiB 和真实源 IP"
dc exec -T office-terminal curl --fail --silent --noproxy '*' \
  --connect-timeout 3 --max-time 15 http://192.168.10.100:8800/source \
  | grep -q 'source=192.168.20.100'
dc exec -T home-terminal curl --fail --silent --noproxy '*' \
  --connect-timeout 3 --max-time 15 http://192.168.20.100:8800/source \
  | grep -q 'source=192.168.10.100'
dc exec -T office-terminal curl --fail --silent --insecure --noproxy '*' \
  --connect-timeout 3 --max-time 15 https://192.168.10.100:8843/source \
  | grep -q 'source=192.168.20.100'
dc exec -T home-terminal curl --fail --silent --insecure --noproxy '*' \
  --connect-timeout 3 --max-time 15 https://192.168.20.100:8843/source \
  | grep -q 'source=192.168.10.100'
[[ "$(dc exec -T office-terminal curl --fail --silent --noproxy '*' \
  --connect-timeout 3 --max-time 30 http://192.168.10.100:8800/large | wc -c)" -ge 8388608 ]]
[[ "$(dc exec -T home-terminal curl --fail --silent --noproxy '*' \
  --connect-timeout 3 --max-time 30 http://192.168.20.100:8800/large | wc -c)" -ge 8388608 ]]
echo "✓ 双向 Site-to-Site 数据面与源 IP 保留通过"

echo "创建 HTTP、HTTPS 和 TCP Tunnel"
origin_ca_pem="$(dc exec -T home-terminal cat /etc/ssl/certs/nexo-terminal-ca.crt)"
http_tunnel="$(post_json "$HTTP_URL/api/v1/tunnels" \
  "$(jq -cn --arg tenant default --arg device "$home_device" \
    --arg name Plain --arg host plain --arg address 192.168.10.100 \
    '{tenant_id:$tenant,device_id:$device,name:$name,protocol:"http",local_address:$address,local_port:8800,hostname:$host,origin_protocol:"http",service_name:"Plain Web"}')" | jq -r '.id')"
https_tunnel="$(post_json "$HTTP_URL/api/v1/tunnels" \
  "$(jq -cn --arg tenant default --arg device "$home_device" \
    --arg name Secure --arg host secure --arg address 192.168.10.100 \
    --arg ca "$origin_ca_pem" \
    '{tenant_id:$tenant,device_id:$device,name:$name,protocol:"https",local_address:$address,local_port:8843,hostname:$host,origin_protocol:"https",origin_tls_server_name:"nexo-integration-terminal",origin_tls_verification:"custom_ca",origin_ca_pem:$ca,service_name:"Secure Web"}')" | jq -r '.id')"
tcp_tunnel="$(post_json "$HTTP_URL/api/v1/tunnels" \
  "$(jq -cn --arg tenant default --arg device "$home_device" \
    --arg name TCP --arg address 192.168.10.100 \
    '{tenant_id:$tenant,device_id:$device,name:$name,protocol:"tcp",local_address:$address,local_port:8800,public_port:20000}')" | jq -r '.id')"
wait_for "HTTP Tunnel READY" \
  "api '$HTTP_URL/api/v1/tunnels/$http_tunnel' | jq -e '.apply_status == \"ready\"'" 180
wait_for "HTTPS Tunnel READY" \
  "api '$HTTP_URL/api/v1/tunnels/$https_tunnel' | jq -e '.apply_status == \"ready\"'" 180
wait_for "TCP Tunnel READY" \
  "api '$HTTP_URL/api/v1/tunnels/$tcp_tunnel' | jq -e '.apply_status == \"ready\"'" 180

echo "验证 HTTP-only、HTTPS、308 跳转、WebSocket 和 8 MiB 传输"
public_request http plain."$PUBLIC_DOMAIN" /source | grep -q 'source=192.168.10.2'
echo "✓ HTTP-only Web Service"
root_headers="$(http_curl --resolve "$PUBLIC_DOMAIN:28080:127.0.0.1" \
  -D - -o /dev/null "http://$PUBLIC_DOMAIN:28080/")"
grep -qi '^HTTP/.* 308' <<<"$root_headers"
grep -qi "location: https://nexo.$PUBLIC_DOMAIN" <<<"$root_headers"
echo "✓ 根域名 308 跳转"
public_request https secure."$PUBLIC_DOMAIN" /source | grep -q 'source=192.168.10.2'
echo "✓ HTTPS Web Service 与自定义 Origin CA"
[[ "$(public_request http plain."$PUBLIC_DOMAIN" /large | wc -c)" -ge 8388608 ]]
[[ "$(public_request https secure."$PUBLIC_DOMAIN" /large | wc -c)" -ge 8388608 ]]
echo "✓ HTTP/HTTPS 8 MiB 传输"

websocket_probe() {
  local host="$1"
  local port="$2"
  dc exec -T outside-probe python3 - "$host" "$port" <<'PY'
import base64
import hashlib
import os
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
key = base64.b64encode(os.urandom(16)).decode()
sock = socket.create_connection(("172.29.0.2", port), timeout=8)
request = (
    f"GET /ws HTTP/1.1\r\nHost: {host}\r\n"
    "Upgrade: websocket\r\nConnection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
).encode()
sock.sendall(request)
response = b""
while b"\r\n\r\n" not in response:
    chunk = sock.recv(4096)
    if not chunk:
        raise SystemExit("WebSocket 握手提前断开")
    response += chunk
if b" 101 " not in response.split(b"\r\n", 1)[0]:
    raise SystemExit(f"WebSocket 握手失败：{response!r}")
expected = base64.b64encode(
    hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
)
if expected not in response:
    raise SystemExit("WebSocket Sec-WebSocket-Accept 校验失败")
payload = b"nexo-websocket-ok"
mask = os.urandom(4)
masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
sock.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)
header = sock.recv(2)
if len(header) != 2 or (header[0] & 0x0F) != 1:
    raise SystemExit("WebSocket 回显帧无效")
length = header[1] & 0x7F
if length == 126:
    length = int.from_bytes(sock.recv(2), "big")
elif length == 127:
    length = int.from_bytes(sock.recv(8), "big")
echo = b""
while len(echo) < length:
    echo += sock.recv(length - len(echo))
if echo != payload:
    raise SystemExit("WebSocket 回显内容不一致")
sock.close()
PY
}
websocket_probe plain."$PUBLIC_DOMAIN" 80
echo "✓ HTTP/HTTPS、8 MiB 和 WebSocket 通过"

echo "验证 TCP Tunnel 和并发连接"
dc exec -T outside-probe curl --fail --silent --show-error --noproxy '*' \
  --connect-timeout 3 --max-time 15 http://172.29.0.2:20000/source \
  | grep -q 'source=192.168.10.2'
tcp_pids=()
for i in $(seq 1 8); do
  dc exec -T outside-probe curl --fail --silent --show-error --noproxy '*' \
    --connect-timeout 3 --max-time 15 http://172.29.0.2:20000/source \
    >"$CERT_DIR/tcp-$i.out" 2>&1 &
  tcp_pids+=("$!")
done
for pid in "${tcp_pids[@]}"; do wait "$pid"; done
echo "✓ TCP Tunnel 并发连接通过"

echo "模拟 9891 黑洞，验证既有公网入口及时降级并自动恢复"
blackhole_started_at="$(date +%s)"
dc exec -T home-gateway iptables -I OUTPUT 1 \
  -p tcp -d 172.29.0.2 --dport 9891 -j DROP
wait_for "9891 黑洞后两个既有 Web 入口降级" \
  "api '$HTTP_URL/api/v1/tunnels' | jq -e --arg http '$http_tunnel' --arg https '$https_tunnel' \
    '[.[] | select((.id == \$http or .id == \$https) and .apply_status == \"checking\" and .apply_error == \"等待 Agent Tunnel 数据连接\")] | length == 2'" 50
blackhole_detected_after="$(( $(date +%s) - blackhole_started_at ))"
if ((blackhole_detected_after > 100)); then
  echo "9891 黑洞检测耗时 ${blackhole_detected_after}s，超过 100 秒验收上限" >&2
  exit 1
fi
echo "✓ 9891 黑洞在 ${blackhole_detected_after}s 内被识别"
dc exec -T home-gateway iptables -D OUTPUT \
  -p tcp -d 172.29.0.2 --dport 9891 -j DROP
wait_for "HTTP Tunnel 自动重连并恢复 READY" \
  "api '$HTTP_URL/api/v1/tunnels/$http_tunnel' | jq -e '.apply_status == \"ready\"'" 90
wait_for "HTTPS Tunnel 自动重连并恢复 READY" \
  "api '$HTTP_URL/api/v1/tunnels/$https_tunnel' | jq -e '.apply_status == \"ready\"'" 90
public_request http plain."$PUBLIC_DOMAIN" /source | grep -q 'source=192.168.10.2'
public_request https secure."$PUBLIC_DOMAIN" /source | grep -q 'source=192.168.10.2'
echo "✓ 两个既有 Web 公网入口已恢复可访问"

echo "验证 HTTP Session 与 HTTPS Session 不能交叉复用"
local_status="$(api "$HTTP_URL/api/v1/auth/status")"
[[ "$(printf '%s' "$local_status" | jq -r '.authenticated')" == true ]]
secure_with_local="$(public_request https nexo."$PUBLIC_DOMAIN" /api/v1/auth/status "$COOKIE_JAR")"
[[ "$(printf '%s' "$secure_with_local" | jq -r '.authenticated')" == false ]]
secure_login="$(http_curl --fail --insecure \
  --resolve "nexo.$PUBLIC_DOMAIN:28443:127.0.0.1" \
  --cookie-jar "$SECURE_COOKIE_JAR" \
  -H 'content-type: application/json' -X POST \
  "https://nexo.$PUBLIC_DOMAIN:28443/api/v1/auth/login" \
  -d "$(jq -cn --arg username "$ADMIN_USERNAME" --arg password "$ADMIN_PASSWORD" \
    '{username:$username,password:$password}')")"
secure_csrf="$(printf '%s' "$secure_login" | jq -r '.csrf_token')"
[[ -n "$secure_csrf" ]]
secure_status="$(public_request https nexo."$PUBLIC_DOMAIN" /api/v1/auth/status "$SECURE_COOKIE_JAR")"
[[ "$(printf '%s' "$secure_status" | jq -r '.authenticated')" == true ]]
local_with_secure="$(http_curl --fail --cookie "$SECURE_COOKIE_JAR" \
  -H "x-nexo-csrf: $CSRF_TOKEN" "$HTTP_URL/api/v1/auth/status")"
[[ "$(printf '%s' "$local_with_secure" | jq -r '.authenticated')" == false ]]
echo "✓ HTTP/HTTPS Session 隔离通过"

echo "验证 Caddy 停止不影响 LAN 管理和 TCP Tunnel"
CADDY_PID="$(caddy_pid)"
dc exec -T nexo-server sh -c "kill -STOP $CADDY_PID"
CADDY_STOPPED=1
wait_for "Caddy 停止后 LAN 管理仍可用" "http_curl --fail '$HTTP_URL/health'" 30
dc exec -T outside-probe curl --fail --silent --show-error --noproxy '*' \
  --connect-timeout 3 --max-time 15 http://172.29.0.2:20000/source >/dev/null
dc exec -T nexo-server sh -c "kill -CONT $CADDY_PID"
CADDY_STOPPED=0
wait_for "Caddy 恢复后管理 API 可用" \
  "dc exec -T nexo-server curl --fail --silent --noproxy '*' http://127.0.0.1:8290/config/" 90

nodes_before="$(headscale_node_ids)"

echo "关闭 Site Link，确认 LAN 中断但 Mesh 保持连接"
post_json "$HTTP_URL/api/v1/site-links/$link/disable" '{}' >/dev/null
wait_for "Site Link 关闭" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"disabled\"'" 120
if dc exec -T office-terminal curl --fail --silent --show-error --noproxy '*' \
  --connect-timeout 3 --max-time 8 http://192.168.10.100:8800/source >/dev/null 2>&1; then
  echo "关闭 Site Link 后仍可访问家庭 LAN" >&2
  exit 1
fi
if dc exec -T home-terminal curl --fail --silent --show-error --noproxy '*' \
  --connect-timeout 3 --max-time 8 http://192.168.20.100:8800/source >/dev/null 2>&1; then
  echo "关闭 Site Link 后仍可访问办公室 LAN" >&2
  exit 1
fi
wait_for "关闭 Link 后两台设备 Mesh 仍连接" \
  "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select((.name == \"家庭网关\" or .name == \"办公网关\") and .mesh_status == \"connected\")] | length == 2'" 120

echo "依次重启两个 Agent、Nexo Server 和 Headscale"
dc restart home-gateway
wait_for "家庭 Agent 重启后在线" \
  "test \"\$(api '$HTTP_URL/api/v1/devices' | jq -r '[.[] | select(.name == \"家庭网关\" and .status == \"online\")] | length')\" -eq 1" 120
dc restart office-gateway
wait_for "办公室 Agent 重启后在线" \
  "test \"\$(api '$HTTP_URL/api/v1/devices' | jq -r '[.[] | select(.name == \"办公网关\" and .status == \"online\")] | length')\" -eq 1" 120
wait_for "Agent 重启后无重复设备" \
  "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select(.name == \"家庭网关\" or .name == \"办公网关\")] | length == 2'" 120
wait_for "Agent 重启后无重复 Mesh Node" "test \"\$(headscale_node_count)\" -eq 2" 120
[[ "$nodes_before" == "$(headscale_node_ids)" ]]

post_json "$HTTP_URL/api/v1/site-links/$link/enable" '{}' >/dev/null
wait_for "Site Link 重新启用后恢复 READY" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 180

dc restart nexo-server
wait_for "Nexo Server 重启后健康" "http_curl --fail '$HTTP_URL/health'" 120
wait_for "Nexo Server 重启后 Site Link 自动收敛" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 180
wait_for "Nexo Server 重启后无重复 Mesh Node" "test \"\$(headscale_node_count)\" -eq 2" 120
[[ "$nodes_before" == "$(headscale_node_ids)" ]]

HEADSCALE_PID="$(headscale_pid)"
dc exec -T nexo-server sh -c "kill -TERM $HEADSCALE_PID"
wait_for "Headscale 子进程重启后组件正常" \
  "test \"\$(api '$HTTP_URL/api/v1/mesh/status' | jq -r '.status')\" = normal" 120
wait_for "Headscale 重启后无重复 Mesh Node" "test \"\$(headscale_node_count)\" -eq 2" 120
[[ "$nodes_before" == "$(headscale_node_ids)" ]]

HEADSCALE_PID="$(headscale_pid)"
dc exec -T nexo-server sh -c "kill -STOP $HEADSCALE_PID"
HEADSCALE_STOPPED=1
post_json "$HTTP_URL/api/v1/site-links/$link/recheck" '{}' >/dev/null
wait_for "Headscale 不可用时路由进入 retrying" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"retrying\"'" 90
wait_for "Headscale 不可用时组网状态受限" \
  "test \"\$(api '$HTTP_URL/api/v1/mesh/status' | jq -r '.status')\" != normal" 90
dc exec -T nexo-server sh -c "kill -CONT $HEADSCALE_PID"
HEADSCALE_STOPPED=0
wait_for "Headscale 恢复后组件正常" \
  "test \"\$(api '$HTTP_URL/api/v1/mesh/status' | jq -r '.status')\" = normal" 120
wait_for "Headscale 恢复后 Site Link 自动收敛" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 180
[[ "$nodes_before" == "$(headscale_node_ids)" ]]

echo "验证 8281/8290 仅限 Server 本机访问"
if dc exec -T outside-probe curl --silent --show-error --noproxy '*' \
  --connect-timeout 2 --max-time 5 http://172.29.0.2:8281/api/v1/health >/dev/null 2>&1; then
  echo "外部容器能够访问 Headscale 8281" >&2
  exit 1
fi
if dc exec -T outside-probe curl --silent --show-error --noproxy '*' \
  --connect-timeout 2 --max-time 5 http://172.29.0.2:8290/config/ >/dev/null 2>&1; then
  echo "外部容器能够访问 Caddy Admin 8290" >&2
  exit 1
fi
echo "✓ 内部管理端口隔离通过"

echo "按依赖顺序删除 Tunnel、Site Link、共享网络、设备和站点"
for tunnel_id in "$http_tunnel" "$https_tunnel" "$tcp_tunnel"; do
  delete_json "$HTTP_URL/api/v1/tunnels/$tunnel_id" \
    | jq -e --arg id "$tunnel_id" '.id == $id and .deleted == true and .pending == false' \
    >/dev/null
done
api "$HTTP_URL/api/v1/tunnels" | jq -e --arg http "$http_tunnel" --arg https "$https_tunnel" --arg tcp "$tcp_tunnel" \
  '[.[] | select(.id == $http or .id == $https or .id == $tcp)] | length == 0' \
  >/dev/null

delete_json "$HTTP_URL/api/v1/site-links/$link" \
  | jq -e --arg id "$link" '.id == $id and .deleted == false and .pending == true' \
  >/dev/null
wait_for "Site Link 已完成删除" \
  "api '$HTTP_URL/api/v1/site-links' | jq -e --arg id '$link' '[.[] | select(.id == \$id)] | length == 0'" 180

for network_id in "$home_network" "$office_network"; do
  delete_json "$HTTP_URL/api/v1/site-networks/$network_id" \
    | jq -e --arg id "$network_id" '.id == $id and .deleted == false and .pending == true' \
    >/dev/null
done
wait_for "两侧共享网络已完成删除" \
  "api '$HTTP_URL/api/v1/site-networks' | jq -e --arg home '$home_network' --arg office '$office_network' \
    '[.[] | select(.id == \$home or .id == \$office)] | length == 0'" 180

echo "确认删除互联和共享网络后双向 LAN 路由均已失效"
if dc exec -T office-terminal curl --fail --silent --show-error --noproxy '*' \
  --connect-timeout 3 --max-time 8 http://192.168.10.100:8800/source >/dev/null 2>&1; then
  echo "删除 Site Link 和共享网络后仍可访问家庭 LAN" >&2
  exit 1
fi
if dc exec -T home-terminal curl --fail --silent --show-error --noproxy '*' \
  --connect-timeout 3 --max-time 8 http://192.168.20.100:8800/source >/dev/null 2>&1; then
  echo "删除 Site Link 和共享网络后仍可访问办公室 LAN" >&2
  exit 1
fi
echo "✓ 删除后双向 LAN 路由均已失效"

delete_json "$HTTP_URL/api/v1/devices/$home_device" \
  | jq -e --arg id "$home_device" '.id == $id and .deleted == true and .pending == false' \
  >/dev/null
delete_json "$HTTP_URL/api/v1/devices/$office_device" \
  | jq -e --arg id "$office_device" '.id == $id and .deleted == true and .pending == false' \
  >/dev/null
wait_for "两台设备及 Headscale Node 已完成删除" \
  "api '$HTTP_URL/api/v1/devices' | jq -e --arg home '$home_device' --arg office '$office_device' \
    '[.[] | select(.id == \$home or .id == \$office)] | length == 0' && test \"\$(headscale_node_count)\" -eq 0" 120

delete_json "$HTTP_URL/api/v1/sites/$home_site" \
  | jq -e --arg id "$home_site" '.id == $id and .deleted == true and .pending == false' \
  >/dev/null
delete_json "$HTTP_URL/api/v1/sites/$office_site" \
  | jq -e --arg id "$office_site" '.id == $id and .deleted == true and .pending == false' \
  >/dev/null
api "$HTTP_URL/api/v1/sites" | jq -e --arg home "$home_site" --arg office "$office_site" \
  '[.[] | select(.id == $home or .id == $office)] | length == 0' >/dev/null
api "$HTTP_URL/api/v1/devices" | jq -e --arg home "$home_device" --arg office "$office_device" \
  '[.[] | select(.id == $home or .id == $office)] | length == 0' >/dev/null
api "$HTTP_URL/api/v1/site-networks" | jq -e --arg home "$home_network" --arg office "$office_network" \
  '[.[] | select(.id == $home or .id == $office)] | length == 0' >/dev/null
api "$HTTP_URL/api/v1/site-links" | jq -e --arg id "$link" \
  '[.[] | select(.id == $id)] | length == 0' >/dev/null
api "$HTTP_URL/api/v1/tunnels" | jq -e --arg http "$http_tunnel" --arg https "$https_tunnel" --arg tcp "$tcp_tunnel" \
  '[.[] | select(.id == $http or .id == $https or .id == $tcp)] | length == 0' >/dev/null
echo "✓ 删除资源已从相关 API 列表中移除"
echo "第二阶段 Linux Docker 公网访问和 Site-to-Site 完整验收通过"
