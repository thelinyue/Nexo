import { expect, test } from "@playwright/test";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { agentDeploymentContent, normalizeAgentServerUrl } from "../src/agent-deployment";

const template = readFileSync(new URL("../../compose.agent.yml", import.meta.url), "utf8");
const bash = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "bash";
const composeExecutable = process.env.NEXO_TEST_COMPOSE ?? "docker";
const composePrefix = process.env.NEXO_TEST_COMPOSE ? [] : ["compose"];

test("Server 地址规范化保留 IPv6、端口及路径，拒绝危险或歧义输入", () => {
  expect(normalizeAgentServerUrl(" https://[2001:db8::1]:8280/path/// ")).toBe("https://[2001:db8::1]:8280/path");
  for (const value of ["", "example.com", "ftp://example.com", "https://user:pass@example.com", "https://example.com?x=1", "https://example.com#x", "https://example.com\n/path", "https://example.com\\path"]) expect(normalizeAgentServerUrl(value)).toBeNull();
  for (const token of ["", "   ", "first\necho bad", "bad\rvalue", "bad\0value"]) expect(() => agentDeploymentContent(template, "https://example.com", token, "e-123", "compose")).toThrow();
  expect(() => agentDeploymentContent(template, "https://example.com", "token", "../old-agent", "compose")).toThrow();
});

test("Compose 模式直接生成可保存的配置文件", () => {
  const config = agentDeploymentContent(template, "https://nexo.example.com", "one-time-token", "e-123", "compose");
  expect(config).toMatch(/^name: nexo-agent/m);
  expect(config).toContain('NEXO_SERVER_URL: "https://nexo.example.com"');
  expect(config).toContain('NEXO_ENROLLMENT_TOKEN: "one-time-token"');
  expect(config).toContain("./data/nexo-agent-e-123:/data/nexo-agent");
  expect(config).not.toContain("bash <<");
  expect(config).not.toContain("docker compose up");
  expect(config).not.toContain("${NEXO_SERVER_URL");
  expect(() => agentDeploymentContent(template.replace(/^.*NEXO_ENROLLMENT_TOKEN:.*$/m, ""), "https://example.com", "token", "e-123", "compose")).toThrow();
});

test("镜像标签取自 Compose，支持 latest 与数字版本", () => {
  const numbered = template.replace(/nexo-agent:\S+/, "nexo-agent:1.2.3");
  for (const method of ["compose", "docker"] as const) {
    expect(agentDeploymentContent(numbered, "https://example.com", "token", "e-123", method)).toContain("nexo-agent:1.2.3");
    expect(agentDeploymentContent(template, "https://example.com", "token", "e-123", method)).toContain("nexo-agent:latest");
    expect(() => agentDeploymentContent(template.replace(/nexo-agent:\S+/, "nexo-agent"), "https://example.com", "token", "e-123", method)).toThrow();
  }
  expect(agentDeploymentContent(numbered, "https://example.com", "token", "e-123", "docker")).toContain("nexo-agent-e-123:/data/nexo-agent");
  expect(agentDeploymentContent(template, "https://example.com", "token", "e-456", "docker")).toContain("nexo-agent-e-456:/data/nexo-agent");
});

test("Compose 实际解析生成配置，特殊字符保持原值", () => {
  test.skip(spawnSync(composeExecutable, [...composePrefix, "version"], { timeout: 10000 }).status !== 0, "需要 Docker Compose 或 NEXO_TEST_COMPOSE 指向独立 Compose 程序");
  const root = mkdtempSync(join(tmpdir(), "nexo-agent-config-"));
  const server = "https://example.com/path/'$HOME/`literal`";
  const token = `quote'"\\ $HOME $(touch injected) \`literal\` $$`;
  try {
    writeFileSync(join(root, "compose.yml"), agentDeploymentContent(template, server, token, "e-123", "compose"));
    const parsed = spawnSync(composeExecutable, [...composePrefix, "-f", "compose.yml", "config", "--format", "json"], { cwd: root, encoding: "utf8", timeout: 15000, env: { ...process.env, NEXO_SERVER_URL: "wrong-server", NEXO_ENROLLMENT_TOKEN: "wrong-token" } });
    expect(parsed.stderr).toBe(""); expect(parsed.status).toBe(0);
    const agent = JSON.parse(parsed.stdout).services["nexo-agent"];
    expect(agent.environment.NEXO_SERVER_URL.replace(/\$\$/g, () => "$")).toBe(normalizeAgentServerUrl(server));
    expect(agent.environment.NEXO_ENROLLMENT_TOKEN.replace(/\$\$/g, () => "$")).toBe(token);
    expect(agent.network_mode).toBe("host");
  } finally {
    if (!resolve(root).startsWith(resolve(tmpdir()) + (process.platform === "win32" ? "\\" : "/"))) throw new Error("测试清理路径越界");
    rmSync(root, { recursive: true, force: true });
  }
});

test("docker run 直接命令保留特殊字符且不执行命令替换", () => {
  const root = mkdtempSync(join(tmpdir(), "nexo-agent-run-"));
  const bin = join(root, "bin"); mkdirSync(bin);
  const log = join(root, "args");
  const token = `quote'"\\ $HOME $(touch injected) \`touch injected-too\` $$`;
  const server = "https://example.com/path/'$HOME/`literal`";
  const command = agentDeploymentContent(template, server, token, "e-123", "docker");
  try {
    writeFileSync(join(bin, "docker"), '#!/usr/bin/env bash\nprintf "%s\\0" "$@" > "$NEXO_TEST_LOG"\n', { mode: 0o755 });
    expect(command).toMatch(/^docker run /);
    expect(command).not.toContain("bash <<");
    const result = spawnSync(bash, ["--noprofile", "--norc"], { input: command, encoding: "utf8", timeout: 15000, env: { ...process.env, HOME: root.replace(/\\/g, "/"), PATH: `${bin}${delimiter}${process.env.PATH}`, NEXO_TEST_LOG: log.replace(/\\/g, "/"), MSYS_NO_PATHCONV: "1" } });
    expect(result.error).toBeUndefined(); expect(result.status).toBe(0);
    expect(existsSync(join(root, "injected"))).toBeFalsy();
    expect(existsSync(join(root, "injected-too"))).toBeFalsy();
    const args = readFileSync(log, "utf8").split("\0").filter(Boolean);
    expect(args).toContain(`NEXO_SERVER_URL=${normalizeAgentServerUrl(server)}`);
    expect(args).toContain(`NEXO_ENROLLMENT_TOKEN=${token}`);
    expect(args).toContain("host"); expect(args).toContain("unless-stopped");
    expect(args).toContain("nexo-agent-e-123:/data/nexo-agent");
  } finally {
    if (!resolve(root).startsWith(resolve(tmpdir()) + (process.platform === "win32" ? "\\" : "/"))) throw new Error("测试清理路径越界");
    rmSync(root, { recursive: true, force: true });
  }
});
