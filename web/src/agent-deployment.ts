export type DeploymentMethod = "compose" | "docker";

/** 地址用于 Agent 的 Web/API 请求；禁止 URL 中夹带凭据或被解析器悄悄丢弃的控制字符。 */
export function normalizeAgentServerUrl(value: string): string | null {
  if (/[\u0000-\u001f\u007f]/.test(value)) return null;
  const raw = value.trim();
  if (!/^https?:\/\//i.test(raw) || /[?#\\]/.test(raw)) return null;
  try {
    const url = new URL(raw);
    if (!url.hostname || url.username || url.password) return null;
    return url.href.replace(/\/+$/, "");
  } catch { return null; }
}

// Shell 单引号与 Compose .env 双引号属于不同语法，必须分别转义。
const shellLiteral = (value: string) => `'${value.replace(/'/g, `'"'"'`)}'`;
const envLiteral = (value: string) => JSON.stringify(value.replace(/\$/g, () => "$$"));

/** 两种安装方式跟随官方模板的镜像标签（含 latest）；遇到已有目录/容器即停止，绝不覆盖设备身份。 */
export function agentDeploymentCommand(template: string, serverUrl: string, token: string, method: DeploymentMethod): string {
  const url = normalizeAgentServerUrl(serverUrl);
  if (!url || !token.trim() || /[\u0000-\u001f\u007f]/.test(token)) throw new Error("Server 地址或入网凭证无效，请检查地址或重新生成凭证。");
  const image = template.match(/^\s+image:\s*(\S+)\s*$/m)?.[1];
  const version = image?.match(/:(latest|\d+\.\d+\.\d+(?:-[\w.-]+)?)$/)?.[1];
  if (!image || !version) throw new Error("Agent 部署配置需要 latest 或明确的数字版本。");
  const lines = [
    "bash <<'NEXO_DEPLOY'", "set -euo pipefail", "umask 077",
    `install_dir="$HOME/nexo-agent-${version}"`,
    "docker info >/dev/null",
    ...(method === "compose" ? ["docker compose version >/dev/null"] : []),
    'if [ -e "$install_dir" ] || [ -L "$install_dir" ]; then',
    '  echo "安装目录已存在：$install_dir。请使用原有配置启动 Agent，不要覆盖设备身份。" >&2',
    "  exit 1", "fi",
    'if [ -n "$(docker ps -aq --filter name=\'^/nexo-agent$\')" ]; then',
    "  echo '已存在 nexo-agent 容器，请使用原有配置管理该节点。' >&2", "  exit 1", "fi",
    // mkdir 不带 -p：若检查后目录被其他进程创建，也不能写入已有安装。
    'mkdir "$install_dir"', 'mkdir -p "$install_dir/data/nexo-agent"', 'cd "$install_dir"',
  ];
  if (method === "compose") {
    const env = `TZ=Asia/Shanghai\nNEXO_SERVER_URL=${envLiteral(url)}\nNEXO_ENROLLMENT_TOKEN=${envLiteral(token)}\n`;
    lines.push(`printf '%s' ${shellLiteral(template.replace(/\r\n/g, "\n"))} > compose.agent.yml`, `printf '%s' ${shellLiteral(env)} > .env`, "unset NEXO_SERVER_URL NEXO_ENROLLMENT_TOKEN TZ", "docker compose -f compose.agent.yml pull", "docker compose -f compose.agent.yml up -d");
  } else {
    lines.push(`docker pull ${shellLiteral(image)}`, "docker run -d --name nexo-agent --network host --restart unless-stopped \\", "  --env 'TZ=Asia/Shanghai' \\", `  --env ${shellLiteral(`NEXO_SERVER_URL=${url}`)} \\`, `  --env ${shellLiteral(`NEXO_ENROLLMENT_TOKEN=${token}`)} \\`, '  --volume "$install_dir/data/nexo-agent:/data/nexo-agent" \\', `  ${shellLiteral(image)}`);
  }
  lines.push("echo 'Agent 已启动，请返回管理页面批准入网。'", "NEXO_DEPLOY");
  return lines.join("\n");
}
