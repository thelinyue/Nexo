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
// JSON 字符串也是合法 YAML 标量；额外转义 $，避免 Compose 对凭据或名称做变量插值。
const composeLiteral = (value: string) => JSON.stringify(value.replace(/\$/g, () => "$$"));

/** Compose 返回原生 YAML，docker run 返回单条命令；连接参数直接传给 Agent，不包装安装脚本。 */
export function agentDeploymentContent(template: string, serverUrl: string, token: string, method: DeploymentMethod, deviceName = ""): string {
  const url = normalizeAgentServerUrl(serverUrl);
  if (!url || !token.startsWith("nexo_join_") || /[\u0000-\u001f\u007f]/.test(token)) throw new Error("Server 地址或接入密钥无效。");
  const image = template.match(/^\s+image:\s*(\S+)\s*$/m)?.[1];
  if (!image || !/:(latest|\d+\.\d+\.\d+(?:-[\w.-]+)?)$/.test(image)) throw new Error("Agent 部署配置需要 latest 或明确的数字版本。");
  const environment = { NEXO_SERVER_URL: url, NEXO_ENROLLMENT_TOKEN: token, NEXO_DEVICE_NAME: deviceName.trim() || "Nexo Agent" };
  if (method === "compose") {
    let config = template.replace(/\r\n/g, "\n");
    for (const [name, value] of Object.entries(environment)) {
      const field = new RegExp(`^([ \\t]*${name}:)[ \\t]*\\$\\{${name}:-\\}[ \\t]*$`, "m");
      if (!field.test(config)) throw new Error(`Agent Compose 模板缺少 ${name} 字段。`);
      config = config.replace(field, (_line, key: string) => `${key} ${composeLiteral(value)}`);
    }
    return config;
  }
  return [
    "docker run -d --name nexo-agent --network host --restart unless-stopped",
    "--env 'TZ=Asia/Shanghai'",
    ...Object.entries(environment).map(([name, value]) => `--env ${shellLiteral(`${name}=${value}`)}`),
    `--volume ${shellLiteral("./data/nexo-agent:/data/nexo-agent")}`,
    shellLiteral(image),
  ].join(" ");
}
