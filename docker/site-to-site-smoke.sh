#!/usr/bin/env bash
# Linux Docker 验收：从设备入网、Web 批准、路由收敛到双向 TCP/HTTPS。
# Nexo 流程只使用公开 API；Headscale 官方 CLI 仅用于验收节点数量和稳定 ID，
# 不读取 Nexo 或 Headscale 数据库。
set -Eeuo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker/compose.integration.yml}"
HTTP_URL="${NEXO_HTTP_URL:-http://127.0.0.1:19888}"
ADMIN_TOKEN="${NEXO_ADMIN_TOKEN:-integration-admin}"
# 项目名固定，清理动作只能作用于本脚本创建的验收拓扑。
COMPOSE_PROJECT_NAME="nexo-phase1-integration"
export COMPOSE_PROJECT_NAME

if ! command -v docker >/dev/null || ! command -v curl >/dev/null || ! command -v jq >/dev/null; then
  echo "需要安装 docker、curl 和 jq 才能执行 Linux Site-to-Site 验收" >&2
  exit 2
fi

dc() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

cleanup_on_exit() {
  local exit_code=$?
  if ((exit_code != 0)); then
    echo "验收失败，输出测试拓扑状态和 Server 日志" >&2
    dc ps -a >&2 || true
    dc logs --no-color --tail=120 nexo-server home-gateway office-gateway >&2 || true
  fi
  if [[ -n "${HEADSCALE_PID:-}" && "${HEADSCALE_STOPPED:-0}" == "1" ]]; then
    dc exec -T nexo-server sh -c "kill -CONT $HEADSCALE_PID" >/dev/null 2>&1 || true
  fi
  dc down --volumes --remove-orphans >/dev/null 2>&1 || true
  exit "$exit_code"
}

trap cleanup_on_exit EXIT

# 只清理本次验收使用的 Compose 项目，避免旧卷中的 Node/Desired State
# 影响重跑；不会触碰其他项目或仓库文件。
dc down --volumes --remove-orphans >/dev/null 2>&1 || true

api() {
  curl --fail --silent --show-error --noproxy '*' \
    --connect-timeout 3 --max-time 15 \
    -H "x-nexo-admin-token: $ADMIN_TOKEN" "$@"
}

post_json() {
  local url="$1"
  local body="$2"
  curl --fail --silent --show-error --noproxy '*' \
    --connect-timeout 3 --max-time 15 \
    -H "content-type: application/json" \
    -H "x-nexo-admin-token: $ADMIN_TOKEN" \
    -X POST "$url" -d "$body"
}

expect_status() {
  local expected="$1"
  local url="$2"
  local body="$3"
  local actual
  actual="$(curl --silent --show-error --noproxy '*' \
    --connect-timeout 3 --max-time 15 \
    -H "content-type: application/json" \
    -H "x-nexo-admin-token: $ADMIN_TOKEN" \
    -X POST "$url" -d "$body" -o /dev/null -w '%{http_code}')"
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

create_site() {
  post_json "$HTTP_URL/api/v1/sites" \
    "{\"tenant_id\":\"default\",\"name\":\"$1\"}" | jq -r '.id'
}

create_token() {
  local site_id="$1"
  post_json "$HTTP_URL/api/v1/enrollments" \
    "{\"tenant_id\":\"default\",\"site_id\":\"$site_id\",\"ttl_seconds\":1800}" | jq -r '.token'
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

headscale_nodes() {
  dc exec -T nexo-server /usr/local/bin/headscale \
    --config /data/nexo/headscale/config.yaml nodes list --output json
}

headscale_node_ids() {
  headscale_nodes | jq -c '[.[] | (.id // .node_id // empty | tostring)] | sort'
}

headscale_node_count() {
  headscale_node_ids | jq 'length'
}

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

echo "启动 Nexo Server 与 Headscale"
dc up -d nexo-server
wait_for "Nexo Server 健康" "curl --fail --silent --noproxy '*' --connect-timeout 3 --max-time 15 '$HTTP_URL/health'"
home_site="$(create_site 家庭)"
office_site="$(create_site 办公室)"
home_token="$(create_token "$home_site")"
office_token="$(create_token "$office_site")"

echo "启动两个非 privileged Agent Gateway"
export NEXO_HOME_ENROLLMENT_TOKEN="$home_token"
export NEXO_OFFICE_ENROLLMENT_TOKEN="$office_token"
dc up -d home-gateway office-gateway
home_enrollment="$(find_enrollment 家庭网关)"
office_enrollment="$(find_enrollment 办公网关)"
approve "$home_enrollment"
approve "$office_enrollment"
dc up -d home-terminal office-terminal
unset NEXO_HOME_ENROLLMENT_TOKEN NEXO_OFFICE_ENROLLMENT_TOKEN

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

echo "验证默认路由和错误租户会被拒绝"
expect_status 400 "$HTTP_URL/api/v1/site-networks" \
  "{\"tenant_id\":\"default\",\"site_id\":\"$home_site\",\"name\":\"默认路由\",\"publisher_device_id\":\"$home_device\",\"interface_id\":\"$home_iface\",\"prefix\":\"0.0.0.0/0\"}"
expect_status 404 "$HTTP_URL/api/v1/sites" \
  '{"tenant_id":"missing-tenant","name":"错误租户"}'

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

wait_for "Headscale 只有两个预期节点" "test \"\$(headscale_node_count)\" -eq 2" 120
nodes_before="$(headscale_node_ids)"

curl_terminal() {
  local container="$1"
  local url="$2"
  # 验收终端使用自签名测试证书；生产流量仍按真实证书校验。
  dc exec -T "$container" curl --fail --silent --show-error --insecure --noproxy '*' \
    --connect-timeout 3 --max-time 15 "$url"
}

echo "验证双向 HTTP/HTTPS 与真实源地址"
home_source="$(curl_terminal office-terminal http://192.168.10.100:8080/source)"
office_source="$(curl_terminal home-terminal http://192.168.20.100:8080/source)"
[[ "$home_source" == *"source=192.168.20.100"* ]]
[[ "$office_source" == *"source=192.168.10.100"* ]]
curl_terminal office-terminal https://192.168.10.100:8443/source | grep -q 'source=192.168.20.100'
curl_terminal home-terminal https://192.168.20.100:8443/source | grep -q 'source=192.168.10.100'
[[ "$(dc exec -T office-terminal curl --fail --silent --insecure --noproxy '*' \
  --connect-timeout 3 --max-time 30 -o /dev/null -w '%{size_download}' \
  https://192.168.10.100:8443/large)" -ge 8388608 ]]
[[ "$(dc exec -T home-terminal curl --fail --silent --noproxy '*' \
  --connect-timeout 3 --max-time 30 -o /dev/null -w '%{size_download}' \
  http://192.168.20.100:8080/large)" -ge 8388608 ]]
echo "✓ 双向 HTTP/HTTPS、大文件和真实源 IP 通过"

post_json "$HTTP_URL/api/v1/site-links/$link/disable" '{}' >/dev/null
wait_for "Site Link 关闭" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"disabled\"'"
if curl_terminal office-terminal http://192.168.10.100:8080/source >/dev/null 2>&1; then
  echo "关闭 Site Link 后仍可访问远端 LAN" >&2
  exit 1
fi
if curl_terminal home-terminal http://192.168.20.100:8080/source >/dev/null 2>&1; then
  echo "关闭 Site Link 后反向仍可访问远端 LAN" >&2
  exit 1
fi
echo "✓ 关闭 Site Link 后 LAN↔LAN 中断"

dc restart home-gateway
wait_for "家庭 Agent 重启后回到在线" "test \"\$(api '$HTTP_URL/api/v1/devices' | jq -r '[.[] | select(.name == \"家庭网关\" and .status == \"online\")] | length')\" -eq 1" 120
dc restart office-gateway
wait_for "办公室 Agent 重启后回到在线" "test \"\$(api '$HTTP_URL/api/v1/devices' | jq -r '[.[] | select(.name == \"办公网关\" and .status == \"online\")] | length')\" -eq 1" 120
wait_for "关闭 Site Link 后 Mesh 仍保持连接" \
  "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select((.name == \"家庭网关\" or .name == \"办公网关\") and .mesh_status == \"connected\")] | length == 2'" 120
wait_for "Agent 重启后没有重复设备记录" \
  "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select(.name == \"家庭网关\" or .name == \"办公网关\")] | length == 2'" 120
wait_for "Agent 重启后没有重复 Mesh Node" "test \"\$(headscale_node_count)\" -eq 2" 120
[[ "$nodes_before" == "$(headscale_node_ids)" ]]

post_json "$HTTP_URL/api/v1/site-links/$link/enable" '{}' >/dev/null
wait_for "Site Link 重新启用后恢复 READY" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 180
curl_terminal office-terminal http://192.168.10.100:8080/source | grep -q 'source=192.168.20.100'
curl_terminal home-terminal http://192.168.20.100:8080/source | grep -q 'source=192.168.10.100'

dc restart nexo-server
wait_for "Nexo Server 重启后健康" "curl --fail --silent --noproxy '*' '$HTTP_URL/health'" 120
wait_for "Nexo Server 重启后 Site Link 自动收敛" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 180
wait_for "Nexo Server 重启后没有重复设备记录" \
  "api '$HTTP_URL/api/v1/devices' | jq -e '[.[] | select(.name == \"家庭网关\" or .name == \"办公网关\")] | length == 2'" 120
wait_for "Nexo Server 重启后没有重复 Mesh Node" "test \"\$(headscale_node_count)\" -eq 2" 120
[[ "$nodes_before" == "$(headscale_node_ids)" ]]

HEADSCALE_PID="$(headscale_pid)"
echo "重启内置 Headscale 子进程"
dc exec -T nexo-server sh -c "kill -TERM $HEADSCALE_PID"
wait_for "Headscale 子进程重启后组件正常" \
  "test \"\$(api '$HTTP_URL/api/v1/mesh/status' | jq -r '.status')\" = normal" 120
wait_for "Headscale 子进程重启后没有重复 Mesh Node" "test \"\$(headscale_node_count)\" -eq 2" 120
[[ "$nodes_before" == "$(headscale_node_ids)" ]]

HEADSCALE_PID="$(headscale_pid)"
echo "暂时暂停内置 Headscale，验证路由进入重试"
dc exec -T nexo-server sh -c "kill -STOP $HEADSCALE_PID"
HEADSCALE_STOPPED=1
post_json "$HTTP_URL/api/v1/site-links/$link/recheck" '{}' >/dev/null
wait_for "Headscale 不可用时路由进入重试" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"retrying\"'" 60
wait_for "Headscale 不可用时组件状态异常" \
  "test \"\$(api '$HTTP_URL/api/v1/mesh/status' | jq -r '.status')\" != normal" 60
dc exec -T nexo-server sh -c "kill -CONT $HEADSCALE_PID"
HEADSCALE_STOPPED=0
wait_for "Headscale 恢复后组件正常" \
  "test \"\$(api '$HTTP_URL/api/v1/mesh/status' | jq -r '.status')\" = normal" 120
wait_for "Headscale 恢复后 Site Link 自动收敛" \
  "api '$HTTP_URL/api/v1/site-links/$link' | jq -e '.apply_status == \"ready\" and .health_status == \"ready\"'" 180
curl_terminal home-terminal http://192.168.20.100:8080/source | grep -q 'source=192.168.10.100'
echo "✓ Agent、Headscale、Nexo Server 重启及短暂不可用恢复检查通过"
echo "第一阶段 Linux Docker Site-to-Site 验收通过"
