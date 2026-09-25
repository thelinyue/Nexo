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
// JSON 双引号字符串也是合法 YAML 标量；Compose 的 $ 插值需额外转义。
const composeLiteral = (value: string) => JSON.stringify(value.replace(/\$/g, () => "$$"));

/** Compose 返回可保存的配置文件；docker run 返回单条可执行命令。 */
export function agentDeploymentContent(template: string, serverUrl: string, token: string, method: DeploymentMethod): string {
  const url = normalizeAgentServerUrl(serverUrl);
  if (!url || !token.trim() || /[\u0000-\u001f\u007f]/.test(token)) throw new Error("Server 地址或入网凭证无效，请检查地址或重新生成凭证。");
  const image = template.match(/^\s+image:\s*(\S+)\s*$/m)?.[1];
  const version = image?.match(/:(latest|\d+\.\d+\.\d+(?:-[\w.-]+)?)$/)?.[1];
  if (!image || !version) throw new Error("Agent 部署配置需要 latest 或明确的数字版本。");
  if (method === "compose") {
    const config = template.replace(/\r\n/g, "\n");
    const urlField = /^([ \t]*NEXO_SERVER_URL:)[ \t]*\$\{NEXO_SERVER_URL:[^\n}]*\}[ \t]*$/m;
    const tokenField = /^([ \t]*NEXO_ENROLLMENT_TOKEN:)[ \t]*\$\{NEXO_ENROLLMENT_TOKEN:[^\n}]*\}[ \t]*$/m;
    if (!urlField.test(config) || !tokenField.test(config)) throw new Error("Agent Compose 模板缺少地址或入网凭证字段。");
    return config
      .replace(urlField, (_line, key: string) => `${key} ${composeLiteral(url)}`)
      .replace(tokenField, (_line, key: string) => `${key} ${composeLiteral(token)}`);
  }
  return [
    "docker run -d --name nexo-agent --network host --restart unless-stopped",
    "--env 'TZ=Asia/Shanghai'",
    `--env ${shellLiteral(`NEXO_SERVER_URL=${url}`)}`,
    `--env ${shellLiteral(`NEXO_ENROLLMENT_TOKEN=${token}`)}`,
    `--volume "$HOME/nexo-agent-${version}/data/nexo-agent:/data/nexo-agent"`,
    shellLiteral(image),
  ].join(" ");
}
