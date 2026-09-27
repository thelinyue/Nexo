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
/** TOML 独立保存启动设置；部署命令不携带接入凭据。JSON 字符串转义也是 TOML 基本字符串的有效子集。 */
export function agentToml(serverUrl: string, token: string, deviceName = ""): string {
  const url = normalizeAgentServerUrl(serverUrl);
  if (!url || !token.startsWith("nexo_join_") || /[\u0000-\u001f\u007f]/.test(token)) throw new Error("Server 地址或接入密钥无效。");
  return ["# 保存为 ./data/nexo-agent/agent.toml；每台主机使用独立数据目录。", `server_url = ${JSON.stringify(url)}`, `device_name = ${JSON.stringify(deviceName.trim() || "Nexo Agent")}`, "# 接入成功后可手动清空，后续启动复用设备身份。", `enrollment_token = ${JSON.stringify(token)}`, ""].join("\n");
}

/** Compose 与 Docker 使用相同绑定目录，先保存 TOML 再启动容器。 */
export function agentDeploymentContent(template: string, serverUrl: string, token: string, method: DeploymentMethod, deviceName = ""): string {
  agentToml(serverUrl, token, deviceName);
  const image = template.match(/^\s+image:\s*(\S+)\s*$/m)?.[1];
  if (!image || !/:(latest|\d+\.\d+\.\d+(?:-[\w.-]+)?)$/.test(image)) throw new Error("Agent 部署配置需要 latest 或明确的数字版本。");
  if (method === "compose") return template.replace(/\r\n/g, "\n");
  return ["docker run -d --name nexo-agent --network host --restart unless-stopped", "--env 'TZ=Asia/Shanghai'", `--volume ${shellLiteral("./data/nexo-agent:/data/nexo-agent")}`, shellLiteral(image)].join(" ");
}
