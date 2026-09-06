#!/usr/bin/env bash
# Nexo 真实 Cloudflare ACME 验收。该脚本不会修改 A/AAAA，只允许 Caddy
# 为 DNS-01 挑战临时创建 TXT 记录；不要在普通 CI 或生产业务域名上运行。
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ENVIRONMENT="${1:-}"
DOMAIN="${NEXO_REAL_ACME_DOMAIN:-}"
TOKEN_SOURCE="${NEXO_CLOUDFLARE_TOKEN_FILE:-}"
IMAGE="${NEXO_ACME_IMAGE:-nexo-acme-acceptance:local}"
HTTP_PORT="${NEXO_ACME_HTTP_PORT:-29838}"
PUBLIC_HTTP_PORT="${NEXO_ACME_PUBLIC_HTTP_PORT:-28090}"
HTTPS_PORT="${NEXO_ACME_HTTPS_PORT:-28453}"
BOOTSTRAP_CODE="nexo-acme-bootstrap"
ADMIN_USERNAME="nexo-acme-admin"
ADMIN_PASSWORD="nexo-acme-password-1234"
HTTP_URL="http://127.0.0.1:$HTTP_PORT"
TMP_DIR="$(mktemp -d -t nexo-acme.XXXXXX)"
TOKEN_FILE="$TMP_DIR/cloudflare.token"
COOKIE_JAR="$TMP_DIR/cookies.txt"
CURRENT_CONTAINER=""
CURRENT_VOLUME=""
CSRF_TOKEN=""

usage() {
  echo "用法：NEXO_REAL_ACME_DOMAIN=<domain> NEXO_CLOUDFLARE_TOKEN_FILE=<path> $0 staging|production" >&2
}

cleanup_instance() {
  if [[ -n "$CURRENT_CONTAINER" ]]; then
    # 先给 Caddy 时间撤销仍在进行的 DNS-01 TXT，避免强制删除容器后留下
    # 临时挑战记录。随后只删除本脚本固定命名的容器。
    docker stop --time 30 "$CURRENT_CONTAINER" >/dev/null 2>&1 || true
    docker rm --force "$CURRENT_CONTAINER" >/dev/null 2>&1 || true
  fi
  if [[ -n "$CURRENT_VOLUME" ]]; then
    docker volume rm --force "$CURRENT_VOLUME" >/dev/null 2>&1 || true
  fi
  CURRENT_CONTAINER=""
  CURRENT_VOLUME=""
  CSRF_TOKEN=""
  : >"$COOKIE_JAR"
}

cleanup_on_exit() {
  local exit_code=$?
  if ((exit_code != 0)) && [[ -n "$CURRENT_CONTAINER" ]]; then
    echo "ACME 验收失败，输出 Nexo/Caddy 最近日志：" >&2
    docker logs --tail 160 "$CURRENT_CONTAINER" >&2 || true
  fi
  cleanup_instance
  rm -rf "$TMP_DIR"
  if [[ "${NEXO_ACME_KEEP_IMAGE:-false}" != "true" ]]; then
    docker image rm "$IMAGE" >/dev/null 2>&1 || true
  fi
  exit "$exit_code"
}
trap cleanup_on_exit EXIT

for command in docker curl jq openssl; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "需要安装 $command 才能执行真实 ACME 验收" >&2
    exit 2
  fi
done

if [[ "$ENVIRONMENT" != "staging" && "$ENVIRONMENT" != "production" ]]; then
  usage
  exit 2
fi
if [[ -z "$DOMAIN" || ! "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
  echo "NEXO_REAL_ACME_DOMAIN 不是有效的 DNS 名称" >&2
  exit 2
fi
if [[ ! -f "$TOKEN_SOURCE" || ! -r "$TOKEN_SOURCE" ]]; then
  echo "NEXO_CLOUDFLARE_TOKEN_FILE 不存在或不可读" >&2
  exit 2
fi
if [[ "$ENVIRONMENT" == "production" && "${NEXO_CONFIRM_PRODUCTION_ACME:-}" != "yes" ]]; then
  echo "Production 签发必须显式设置 NEXO_CONFIRM_PRODUCTION_ACME=yes" >&2
  exit 2
fi

install -m 0600 "$TOKEN_SOURCE" "$TOKEN_FILE"
if [[ ! -s "$TOKEN_FILE" ]]; then
  echo "Cloudflare Token 文件为空" >&2
  exit 2
fi

http_curl() {
  curl --silent --show-error --noproxy '*' --connect-timeout 3 --max-time 20 "$@"
}

wait_for() {
  local description="$1"
  local attempts="$2"
  shift 2
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    if "$@" >/dev/null 2>&1; then
      echo "✓ $description"
      return 0
    fi
    sleep 2
  done
  echo "✗ 等待超时：$description" >&2
  return 1
}

api() {
  http_curl --fail --cookie "$COOKIE_JAR" -H "x-nexo-csrf: $CSRF_TOKEN" "$@"
}

request_json_stdin() {
  local method="$1"
  local url="$2"
  http_curl --fail --cookie "$COOKIE_JAR" -H "x-nexo-csrf: $CSRF_TOKEN" \
    -H 'content-type: application/json' -X "$method" "$url" --data-binary @-
}

instance_healthy() {
  http_curl --fail "$HTTP_URL/health"
}

entry_has_status() {
  local expected="$1"
  api "$HTTP_URL/api/v1/settings/public-entry" | jq -e --arg expected "$expected" \
    '.apply_status == $expected'
}

start_instance() {
  local suffix="$1"
  cleanup_instance
  CURRENT_CONTAINER="nexo-cloudflare-acme-$suffix"
  CURRENT_VOLUME="nexo-cloudflare-acme-$suffix-data"
  docker volume create "$CURRENT_VOLUME" >/dev/null
  docker run --detach --name "$CURRENT_CONTAINER" \
    --publish "127.0.0.1:$HTTP_PORT:8280" \
    --publish "127.0.0.1:$PUBLIC_HTTP_PORT:80" \
    --publish "127.0.0.1:$HTTPS_PORT:443" \
    --env "NEXO_ADMIN_TOKEN=$BOOTSTRAP_CODE" \
    --env NEXO_HTTP_ADDR=0.0.0.0:8280 \
    --env NEXO_PUBLIC_BACKEND_ADDR=127.0.0.1:9888 \
    --env NEXO_CONTROL_ADDR=0.0.0.0:9890 \
    --env NEXO_TUNNEL_ADDR=0.0.0.0:9891 \
    --env NEXO_HEADSCALE_ENABLED=true \
    --env NEXO_HEADSCALE_LISTEN_ADDR=127.0.0.1:8281 \
    --env NEXO_HEADSCALE_API_URL=http://127.0.0.1:8281 \
    --env NEXO_HEADSCALE_URL=https://mesh.example.com \
    --env NEXO_CADDY_ENABLED=true \
    --env NEXO_CADDY_BIN=/usr/local/bin/caddy \
    --env NEXO_CADDY_ADMIN_URL=http://127.0.0.1:8290 \
    --env NEXO_DATA_DIR=/data/nexo \
    --env NEXO_WEB_DIR=/opt/nexo/web \
    --volume "$CURRENT_VOLUME:/data/nexo" \
    "$IMAGE" >/dev/null
  wait_for "Nexo Server 健康" 90 instance_healthy
  initialize_admin
}

initialize_admin() {
  local response
  response="$(jq -cn --arg code "$BOOTSTRAP_CODE" --arg username "$ADMIN_USERNAME" \
    --arg password "$ADMIN_PASSWORD" \
    '{bootstrap_code:$code,username:$username,password:$password}' \
    | http_curl --fail --cookie-jar "$COOKIE_JAR" -H 'content-type: application/json' \
      -X POST "$HTTP_URL/api/v1/auth/initialize" --data-binary @-)"
  CSRF_TOKEN="$(jq -r '.csrf_token // empty' <<<"$response")"
  if [[ -z "$CSRF_TOKEN" ]]; then
    echo "管理员初始化未返回 CSRF Token" >&2
    return 1
  fi
}

set_public_entry_disabled() {
  jq -cn --arg domain "$DOMAIN" --arg environment "$ENVIRONMENT" \
    '{base_domain:$domain,https_enabled:false,certificate_mode:"cloudflare",acme_environment:$environment}' \
    | request_json_stdin PUT "$HTTP_URL/api/v1/settings/public-entry" >/dev/null
}

enable_public_entry() {
  jq -cn --arg domain "$DOMAIN" --arg environment "$ENVIRONMENT" \
    '{base_domain:$domain,https_enabled:true,certificate_mode:"cloudflare",acme_environment:$environment}' \
    | request_json_stdin PUT "$HTTP_URL/api/v1/settings/public-entry" >/dev/null
}

upload_invalid_token() {
  jq -cn '{cloudflare_token:"nexo-invalid-cloudflare-token"}' \
    | request_json_stdin POST "$HTTP_URL/api/v1/settings/public-entry/certificate" >/dev/null
}

upload_real_token() {
  jq -n --rawfile token "$TOKEN_FILE" \
    '{cloudflare_token:($token | gsub("[\\r\\n]+$"; ""))}' \
    | request_json_stdin POST "$HTTP_URL/api/v1/settings/public-entry/certificate" >/dev/null
}

assert_not_ready() {
  if entry_has_status READY >/dev/null 2>&1; then
    echo "无效 Token 被错误标记为 READY" >&2
    return 1
  fi
}

certificate_for() {
  local host="$1"
  local destination="$2"
  openssl s_client -connect "127.0.0.1:$HTTPS_PORT" -servername "$host" -showcerts \
    </dev/null 2>/dev/null | openssl x509 -outform PEM >"$destination"
}

verify_https_entry() {
  local insecure=()
  if [[ "$ENVIRONMENT" == "staging" ]]; then
    insecure=(-k)
  fi
  http_curl --fail "${insecure[@]}" \
    --resolve "nexo.$DOMAIN:$HTTPS_PORT:127.0.0.1" \
    "https://nexo.$DOMAIN:$HTTPS_PORT/api/v1/auth/status" \
    | jq -e '.initialized == true' >/dev/null

  local headers
  headers="$(http_curl "${insecure[@]}" --resolve "$DOMAIN:$PUBLIC_HTTP_PORT:127.0.0.1" \
    -D - -o /dev/null "http://$DOMAIN:$PUBLIC_HTTP_PORT/")"
  grep -qi '^HTTP/.* 308' <<<"$headers"
  grep -qi "location: https://nexo.$DOMAIN" <<<"$headers"

  local root_cert="$TMP_DIR/$ENVIRONMENT-root.pem"
  local wildcard_cert="$TMP_DIR/$ENVIRONMENT-wildcard.pem"
  certificate_for "$DOMAIN" "$root_cert"
  certificate_for "nexo.$DOMAIN" "$wildcard_cert"
  openssl x509 -in "$root_cert" -noout -checkhost "$DOMAIN" >/dev/null
  openssl x509 -in "$wildcard_cert" -noout -checkhost "nexo.$DOMAIN" >/dev/null

  local issuer
  issuer="$(openssl x509 -in "$root_cert" -noout -issuer)"
  if [[ "$ENVIRONMENT" == "staging" ]]; then
    grep -Eqi 'staging|fake le intermediate' <<<"$issuer"
  else
    grep -qi "Let's Encrypt" <<<"$issuer"
  fi
}

if [[ "${NEXO_ACME_SKIP_BUILD:-false}" != "true" ]]; then
  echo "构建 Nexo ACME 验收镜像"
  docker build --file "$SCRIPT_DIR/Dockerfile.server" --tag "$IMAGE" "$REPO_DIR"
elif ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "指定跳过构建，但镜像不存在：$IMAGE" >&2
  exit 2
fi

if [[ "$ENVIRONMENT" == "staging" ]]; then
  echo "验证 Cloudflare 边缘响应不会造成证书假 READY"
  start_instance staging-negative
  set_public_entry_disabled
  upload_invalid_token
  enable_public_entry
  assert_not_ready
  sleep 10
  assert_not_ready
  echo "✓ 无效 Token 未进入 READY"
  cleanup_instance
fi

echo "执行 $ENVIRONMENT 真实 DNS-01 签发"
start_instance "$ENVIRONMENT"
set_public_entry_disabled
upload_real_token
enable_public_entry
if [[ "$ENVIRONMENT" == "staging" ]]; then
  wait_for "Staging 证书签发并由本机 Caddy 提供" 210 entry_has_status READY
else
  wait_for "Production 证书签发并由本机 Caddy 提供" 300 entry_has_status READY
fi
verify_https_entry
echo "✓ $ENVIRONMENT 真实 Cloudflare ACME 验收通过"
