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

const shellLiteral = (value: string) => `'${value.replace(/'/g, `'"'"'`)}'`;
/** TOML 保存启动设置；JSON 字符串转义也是 TOML 基本字符串的有效子集。 */
export function agentToml(serverUrl: string, token: string, deviceName = ""): string {
  const url = normalizeAgentServerUrl(serverUrl);
  if (!url || !token.startsWith("nexo_join_") || /[\u0000-\u001f\u007f]/.test(token)) throw new Error("Server 地址或接入密钥无效。");
  return ["# 保存为 ./data/nexo-agent/agent.toml；每台主机使用独立数据目录。", `server_url = ${JSON.stringify(url)}`, `device_name = ${JSON.stringify(deviceName.trim() || "Nexo Agent")}`, "# 接入成功后可手动清空，后续启动复用设备身份。", `enrollment_token = ${JSON.stringify(token)}`, ""].join("\n");
}

/** 一次复制完成配置落盘和启动；子 Shell 隔离选项，引用的 heredoc 禁止凭据和名称被 Shell 展开。
 * 已有配置拒绝覆盖，noclobber 防止检查后意外覆盖；umask 确保含密钥的文件创建时即为 0600。
 */
export function agentDeploymentContent(template: string, serverUrl: string, token: string, method: DeploymentMethod, deviceName = ""): string {
  const toml = agentToml(serverUrl, token, deviceName);
  const image = template.match(/^\s+image:\s*(\S+)\s*$/m)?.[1];
  if (!image || !/:(latest|\d+\.\d+\.\d+(?:-[\w.-]+)?)$/.test(image)) throw new Error("Agent 部署配置需要 latest 或明确的数字版本。");
  const isCompose = method === "compose";
  const files = ["./data/nexo-agent/agent.toml", ...(isCompose ? ["./compose.agent.yml"] : [])];
  const docker = ["docker run -d --name nexo-agent --network host --restart unless-stopped", "--env 'TZ=Asia/Shanghai'", `--volume ${shellLiteral("./data/nexo-agent:/data/nexo-agent")}`, shellLiteral(image)].join(" ");
  return [
    "(", "set -euC", "umask 077",
    "command -v docker >/dev/null 2>&1 || { printf '%s\\n' '请先安装 Docker。' >&2; exit 1; }",
    ...(isCompose ? ["docker compose version >/dev/null"] : []),
    `for file in ${files.map(shellLiteral).join(" ")}; do`,
    '  if [ -e "$file" ] || [ -L "$file" ]; then',
    '    printf \'%s\\n\' "已有配置：$file；已停止，请使用原配置管理 Agent，或在新目录安装。" >&2',
    "    exit 1", "  fi", "done",
    "mkdir -p ./data/nexo-agent",
    "cat > ./data/nexo-agent/agent.toml <<'NEXO_AGENT_TOML'", toml.trimEnd(), "NEXO_AGENT_TOML",
    ...(isCompose ? ["cat > ./compose.agent.yml <<'NEXO_AGENT_COMPOSE'", template.replace(/\r\n/g, "\n").trimEnd(), "NEXO_AGENT_COMPOSE", "docker compose -f ./compose.agent.yml up -d"] : [docker]),
    ")",
  ].join("\n");
}
