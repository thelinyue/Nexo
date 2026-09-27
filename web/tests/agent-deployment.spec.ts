import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { agentDeploymentContent, agentToml, normalizeAgentServerUrl } from "../src/agent-deployment";
const template = readFileSync(new URL("../../compose.agent.yml", import.meta.url), "utf8");

test("Server 地址规范化保留 IPv6、端口及路径，拒绝危险或歧义输入", () => {
  expect(normalizeAgentServerUrl(" https://[2001:db8::1]:8280/path/// ")).toBe("https://[2001:db8::1]:8280/path");
  for (const value of ["", "example.com", "ftp://example.com", "https://user:pass@example.com", "https://example.com?x=1", "https://example.com#x", "https://example.com\n/path", "https://example.com\\path"]) expect(normalizeAgentServerUrl(value)).toBeNull();
  for (const token of ["", "   ", "one-time-token", "nexo_join_bad\nvalue"]) expect(() => agentToml("https://example.com", token)).toThrow();
});

test("部署模板不含凭据和 Nexo 环境变量，目录与 TOML 操作说明一致", () => {
  for (const method of ["compose", "docker"] as const) {
    const result = agentDeploymentContent(template, "https://nexo.example.com", "nexo_join_secret", method);
    expect(result).toContain("./data/nexo-agent:/data/nexo-agent");
    expect(result).toContain("host");
    expect(result).not.toContain("nexo_join_secret");
    expect(result).not.toContain("NEXO_");
  }
});

test("镜像标签取自 Compose，支持 latest 与数字版本", () => {
  for (const method of ["compose", "docker"] as const) {
    expect(agentDeploymentContent(template.replace(/nexo-agent:\S+/, "nexo-agent:1.2.3"), "https://example.com", "nexo_join_token", method)).toContain("nexo-agent:1.2.3");
    expect(agentDeploymentContent(template, "https://example.com", "nexo_join_token", method)).toContain("nexo-agent:latest");
    expect(() => agentDeploymentContent(template.replace(/nexo-agent:\S+/, "nexo-agent:dev"), "https://example.com", "nexo_join_token", method)).toThrow();
  }
});

test("生成 TOML 的特殊字符由真实解析器读回，无 Shell 或 Compose 插值", () => {
  const token = "nexo_join_quote'\"\\ $HOME $(touch injected) `literal`";
  const name = "家庭 NAS \"\n多行\t路径\\设备";
  const url = "https://example.com/path/$HOME";
  const text = agentToml(url, token, name);
  const parsed = spawnSync(process.platform === "win32" ? "python" : "python3", ["-X", "utf8", "-c", "import sys,tomllib,json; print(json.dumps(tomllib.loads(sys.stdin.read()),ensure_ascii=False))"], { input: text, encoding: "utf8" });
  expect(parsed.status, parsed.stderr).toBe(0);
  expect(JSON.parse(parsed.stdout)).toEqual({ server_url: url, device_name: name, enrollment_token: token });
});
