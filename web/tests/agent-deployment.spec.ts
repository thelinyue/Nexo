import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { agentDeploymentContent, normalizeAgentServerUrl } from "../src/agent-deployment";
const template = readFileSync(new URL("../../compose.agent.yml", import.meta.url), "utf8");

test("Server 地址规范化保留 IPv6、端口及路径，拒绝危险或歧义输入", () => {
  expect(normalizeAgentServerUrl(" https://[2001:db8::1]:8280/path/// ")).toBe("https://[2001:db8::1]:8280/path");
  for (const value of ["", "example.com", "ftp://example.com", "https://user:pass@example.com", "https://example.com?x=1", "https://example.com#x", "https://example.com\n/path", "https://example.com\\path"]) expect(normalizeAgentServerUrl(value)).toBeNull();
  for (const method of ["compose", "docker"] as const) {
    for (const token of ["", "   ", "one-time-token", "nexo_join_bad\nvalue"]) expect(() => agentDeploymentContent(template, "https://example.com", token, method)).toThrow();
  }
});

test("真实 Compose 与 Shell 保留连接参数，不执行特殊字符或写配置脚本", () => {
  const token = "nexo_join_quote'\"\\ $HOME ${USER} $(touch injected) \u0060touch injected\u0060";
  const name = "家庭 NAS '\"\n$(touch injected)\\设备";
  const url = "https://example.com/path/$HOME";
  const checker = readFileSync(new URL("./agent-deployment-check.py", import.meta.url), "utf8");
  const result = spawnSync(process.platform === "win32" ? "wsl.exe" : "python3", [...(process.platform === "win32" ? ["--exec", "python3"] : []), "-c", checker], {
    input: JSON.stringify({
      compose: agentDeploymentContent(template, url, token, "compose", name),
      command: agentDeploymentContent(template, url, token, "docker", name),
      expected: { NEXO_SERVER_URL: url, NEXO_ENROLLMENT_TOKEN: token, NEXO_DEVICE_NAME: name },
    }), encoding: "utf8", timeout: 30_000,
  });
  expect(result.status, result.stderr || result.error?.message).toBe(0);
});

test("镜像标签取自 Compose，支持 latest 与数字版本，缺少参数的模板拒绝复制", () => {
  for (const method of ["compose", "docker"] as const) {
    expect(agentDeploymentContent(template.replace(/nexo-agent:\S+/, "nexo-agent:1.2.3"), "https://example.com", "nexo_join_token", method)).toContain("nexo-agent:1.2.3");
    expect(agentDeploymentContent(template, "https://example.com", "nexo_join_token", method)).toContain("nexo-agent:latest");
    expect(() => agentDeploymentContent(template.replace(/nexo-agent:\S+/, "nexo-agent:dev"), "https://example.com", "nexo_join_token", method)).toThrow();
  }
  expect(() => agentDeploymentContent(template.replace(/^.*NEXO_SERVER_URL.*$/m, ""), "https://example.com", "nexo_join_token", "compose")).toThrow();
});
