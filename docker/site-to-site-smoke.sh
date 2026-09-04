#!/usr/bin/env bash
# Linux Docker 验收：从设备入网、Web 批准、路由收敛到双向 TCP/HTTPS。
# 该脚本只使用公开 API 和终端容器，不读取 Nexo/Headscale 数据库。
set -Eeuo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker/compose.integration.yml}"
HTTP_URL="${NEXO_HTTP_URL:-http://127.0.0.1:19888}"
ADMIN_TOKEN="${NEXO_ADMIN_TOKEN:-integration-admin}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-nexo-phase1-integration}"
export COMPOSE_PROJECT_NAME

if ! command -v docker >/dev/null || ! command -v curl >/dev/null || ! command -v jq >/dev/null; then
  echo "需要安装 docker、curl 和 jq 才能执行 Linux Site-to-Site 验收" >&2
  exit 2
fi

dc() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

api() {
  curl --fail --silent --show-error --noproxy '*' \
    -H "x-nexo-admin-token: $ADMIN_TOKEN" "$@"
}

post_json() {
  local url="$1"
  local body="$2"
  curl --fail --silent --show-error --noproxy '*' \
    -H "content-type: application/json" \
    -H "x-nexo-admin-token: $ADMIN_TOKEN" \
    -X POST "$url" -d "$body"
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

wait_for "Nexo Server 健康" "curl --fail --silent --noproxy '*' '$HTTP_URL/health'"

create_site() {
  post_json "$HTTP_URL/api/v1/sites" \
    "{\"tenant_id\":\"default\",\"name\":\"$1\"}" | jq -r '.id'
}

create_token() {
  post_json "$HTTP_URL/api/v1/enrollments" \
    '{"tenant_id":"default","ttl_seconds":1800}' | jq -r '.token'
}

find_enrollment() {
  local name="$1"
  for ((i = 1; i <= 60; i++)); do
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

approve() {
  local id="$1"
  api -X POST "$HTTP_URL/api/v1/enrollments/$id/approve" >/dev/null
}

device_id() {
  api "$HTTP_URL/api/v1/devices" | jq -r --arg name "$1" \
    '.[] | select(.name == $name) | .id' | head -n 1
}

echo "启动 Nexo Server 与 Headscale"
dc up -d nexo-server
home_site="$(create_site 家庭)"
office_site="$(create_site 办公室)"
home_token="$(create_token)"
office_token="$(create_token)"

echo "启动两个非 privileged Agent Gateway"
NEXO_ENROLLMENT_TOKEN="$home_token" dc up -d home-gateway
NEXO_ENROLLMENT_TOKEN="$office_token" dc up -d office-gateway
home_enrollment="$(find_enrollment 家庭网关)"
office_enrollment="$(find_enrollment 办公网关)"
approve "$home_enrollment"
approve "$office_enrollment"
NEXO_ENROLLMENT_TOKEN='' dc up -d home-terminal office-terminal

wait_for "家庭网关在线" "test \"\$(api '$HTTP_URL/api/v1/devices' | jq -r '.[] | select(.name == \"家庭网关\") | .status')\" = online"
wait_for "办公网关在线" "test \"\$(api '$HTTP_URL/api/v1/devices' | jq -r '.[] | select(.name == \"办公网关\") | .status')\" = online"
home_device="$(device_id 家庭网关)"
office_device="$(device_id 办公网关)"

wait_for "家庭网关能力报告" "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select(.name == \"家庭网关\" and .gateway_report != null)] | length == 1'"
wait_for "办公网关能力报告" "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select(.name == \"办公网关\" and .gateway_report != null)] | length == 1'"
home_iface="$(api "$HTTP_URL/api/v1/devices" | jq -r \
  '.[] | select(.name == "家庭网关") | .gateway_report.local_networks[] | select(.prefix == "192.168.10.0/24") | .interface_id' | head -n 1)"
office_iface="$(api "$HTTP_URL/api/v1/devices" | jq -r \
  '.[] | select(.name == "办公网关") | .gateway_report.local_networks[] | select(.prefix == "192.168.20.0/24") | .interface_id' | head -n 1)"
[[ -n "$home_iface" && -n "$office_iface" ]]

home_network="$(post_json "$HTTP_URL/api/v1/site-networks" \
  "{\"tenant_id\":\"default\",\"site_id\":\"$home_site\",\"name\":\"家庭局域网\",\"publisher_device_id\":\"$home_device\",\"interface_id\":\"$home_iface\",\"prefix\":\"192.168.10.0/24\"}" | jq -r '.id')"
office_network="$(post_json "$HTTP_URL/api/v1/site-networks" \
  "{\"tenant_id\":\"default\",\"site_id\":\"$office_site\",\"name\":\"办公室局域网\",\"publisher_device_id\":\"$office_device\",\"interface_id\":\"$office_iface\",\"prefix\":\"192.168.20.0/24\"}" | jq -r '.id')"
link="$(post_json "$HTTP_URL/api/v1/site-links" \
  "{\"tenant_id\":\"default\",\"left_site_id\":\"$home_site\",\"left_network_id\":\"$home_network\",\"right_site_id\":\"$office_site\",\"right_network_id\":\"$office_network\"}" | jq -r '.id')"
post_json "$HTTP_URL/api/v1/site-links/$link/router-confirmations/$home_site" '{}' >/dev/null
post_json "$HTTP_URL/api/v1/site-links/$link/router-confirmations/$office_site" '{}' >/dev/null

wait_for "Site Gateway 路由 READY" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 120

curl_terminal() {
  local container="$1"
  local url="$2"
  # 验收终端使用自签名测试证书；生产流量仍按真实证书校验。
  dc exec -T "$container" curl --fail --silent --show-error --insecure --noproxy '*' "$url"
}

echo "验证双向 HTTP/HTTPS 与真实源地址"
home_source="$(curl_terminal office-terminal http://192.168.10.100:8080/source)"
office_source="$(curl_terminal home-terminal http://192.168.20.100:8080/source)"
[[ "$home_source" == *"source=192.168.20.100"* ]]
[[ "$office_source" == *"source=192.168.10.100"* ]]
curl_terminal office-terminal https://192.168.10.100:8443/source | grep -q 'source=192.168.20.100'
curl_terminal home-terminal https://192.168.20.100:8443/source | grep -q 'source=192.168.10.100'
[[ "$(dc exec -T office-terminal curl --fail --silent --insecure --noproxy '*' \
  -o /dev/null -w '%{size_download}' https://192.168.10.100:8443/large)" -ge 8388608 ]]
[[ "$(dc exec -T home-terminal curl --fail --silent --noproxy '*' \
  -o /dev/null -w '%{size_download}' http://192.168.20.100:8080/large)" -ge 8388608 ]]
echo "✓ 双向 HTTP/HTTPS、大文件和真实源 IP 通过"

post_json "$HTTP_URL/api/v1/site-links/$link/disable" '{}' >/dev/null
wait_for "Site Link 关闭" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"disabled\" or .health_status == \"disabled\"'"
if curl_terminal office-terminal http://192.168.10.100:8080/source >/dev/null 2>&1; then
  echo "关闭 Site Link 后仍可访问远端 LAN" >&2
  exit 1
fi
echo "✓ 关闭 Site Link 后 LAN↔LAN 中断"

dc restart home-gateway office-gateway
wait_for "Agent 重启后回到在线" "test \"\$(api '$HTTP_URL/api/v1/devices' | jq -r '[.[] | select(.status == \"online\")] | length')\" -ge 2" 120
wait_for "关闭 Site Link 后 Mesh 仍保持连接" \
  "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select((.name == \"家庭网关\" or .name == \"办公网关\") and .mesh_status == \"connected\")] | length == 2'" 120
wait_for "Agent 重启后没有重复设备记录" \
  "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select(.name == \"家庭网关\" or .name == \"办公网关\")] | length == 2'" 120

post_json "$HTTP_URL/api/v1/site-links/$link/enable" '{}' >/dev/null
wait_for "Site Link 重新启用后恢复 READY" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 180
curl_terminal office-terminal http://192.168.10.100:8080/source | grep -q 'source=192.168.20.100'

dc restart nexo-server
wait_for "Nexo Server 重启后健康" "curl --fail --silent --noproxy '*' '$HTTP_URL/health'" 120
wait_for "Nexo Server 重启后 Site Link 自动收敛" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 180
wait_for "Nexo Server 重启后没有重复设备记录" \
  "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select(.name == \"家庭网关\" or .name == \"办公网关\")] | length == 2'" 120
dc stop nexo-server
sleep 4
dc start nexo-server
wait_for "Headscale/Nexo 暂停后恢复" "curl --fail --silent --noproxy '*' '$HTTP_URL/health'" 120
wait_for "Headscale/Nexo 恢复后 Site Link 自动收敛" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 180
curl_terminal home-terminal http://192.168.20.100:8080/source | grep -q 'source=192.168.10.100'
echo "✓ Agent、Headscale/Nexo Server 重启恢复检查通过"
echo "第一阶段 Linux Docker Site-to-Site 验收通过"
