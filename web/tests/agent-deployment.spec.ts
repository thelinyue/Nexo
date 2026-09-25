import { expect, test } from "@playwright/test";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { agentDeploymentCommand, normalizeAgentServerUrl } from "../src/agent-deployment";
import type { DeploymentMethod } from "../src/agent-deployment";

const template = readFileSync(new URL("../../compose.agent.yml", import.meta.url), "utf8");
const bash = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "bash";
const composeExecutable = process.env.NEXO_TEST_COMPOSE;

/** 只替换脚本的安装目录进行隔离，保留命令转义、文件写入及 Docker 参数的真实 Bash 执行。 */
function harness(method: DeploymentMethod, token = "normal-token") {
  const root = mkdtempSync(join(tmpdir(), "nexo-agent-command-"));
  const bin = join(root, "bin"); mkdirSync(bin);
  const log = join(root, "calls");
  writeFileSync(join(bin, "docker"), `#!/usr/bin/env bash
printf '%s\\0' --call-- "$@" >> "$NEXO_TEST_LOG"
if [ "$1" = info ] && [ "\${NEXO_TEST_FAILURE:-}" = info ]; then exit 42; fi
if [ "$1" = ps ]; then
  if [ "\${NEXO_TEST_CONTAINER:-}" = yes ]; then echo existing-container; fi
  exit 0
fi
if [ "$1" = compose ] && [ "\${2:-}" = -f ]; then
  printf '%s' "\${NEXO_SERVER_URL-unset}:\${NEXO_ENROLLMENT_TOKEN-unset}" > "$NEXO_TEST_ROOT/ambient"
fi
if { [ "$1" = pull ] || [ "\${4:-}" = pull ]; } && [ "\${NEXO_TEST_FAILURE:-}" = pull ]; then exit 43; fi
`, { mode: 0o755 });
  const server = "https://example.com/path/'$HOME/`literal`";
  const command = agentDeploymentCommand(template, server, token, method);
  expect(command).toMatch(/install_dir="\$HOME\/nexo-agent-/);
  const script = command.replace(/^install_dir=.*$/m, 'install_dir="$NEXO_TEST_ROOT/install"');
  const run = (extra: Record<string,string> = {}) => spawnSync(bash, ["--noprofile", "--norc"], {
    input: script, encoding: "utf8", timeout: 15000,
    env: { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}`, NEXO_TEST_ROOT: root.replace(/\\/g, "/"), NEXO_TEST_LOG: log.replace(/\\/g, "/"), NEXO_SERVER_URL: "wrong-server", NEXO_ENROLLMENT_TOKEN: "wrong-token", MSYS_NO_PATHCONV: "1", ...extra },
  });
  return {
    root, script, server, run,
    calls: () => existsSync(log) ? readFileSync(log, "utf8").split("--call--\0").filter(Boolean).map(call => call.split("\0").filter(Boolean)) : [],
    clean: () => { if (!resolve(root).startsWith(resolve(tmpdir()) + (process.platform === "win32" ? "\\" : "/"))) throw new Error("测试清理路径越界"); rmSync(root, { recursive: true, force: true }); },
  };
}

test("Server 地址规范化保留 IPv6、端口及路径，拒绝危险或歧义输入", () => {
  expect(normalizeAgentServerUrl(" https://[2001:db8::1]:8280/path/// ")).toBe("https://[2001:db8::1]:8280/path");
  for (const value of ["", "example.com", "ftp://example.com", "https://user:pass@example.com", "https://example.com?x=1", "https://example.com#x", "https://example.com\n/path", "https://example.com\\path"]) expect(normalizeAgentServerUrl(value)).toBeNull();
  for (const token of ["", "   ", "first\nNEXO_DEPLOY\necho bad", "bad\rvalue", "bad\0value"]) expect(() => agentDeploymentCommand(template, "https://example.com", token, "compose")).toThrow();
});

test("Agent 镜像独立取自 Compose，支持 latest 与数字版本，拒绝无标签部署", () => {
  const differentVersion = template.replace(/nexo-agent:\S+/, "nexo-agent:1.2.3");
  for (const method of ["compose", "docker"] as const) {
    const command = agentDeploymentCommand(differentVersion, "https://example.com", "token", method);
    expect(command).toContain("nexo-agent:1.2.3"); expect(command).toContain("nexo-agent-1.2.3");
    const latest = agentDeploymentCommand(template.replace(/nexo-agent:\S+/, "nexo-agent:latest"), "https://example.com", "token", method);
    expect(latest).toContain("nexo-agent:latest"); expect(latest).toContain('install_dir="$HOME/nexo-agent-latest"');
    expect(() => agentDeploymentCommand(template.replace(/nexo-agent:\S+/, "nexo-agent"), "https://example.com", "token", method)).toThrow();
  }
});

test("Compose 实际解析生成配置，特殊字符保持原值", () => {
  const executable = composeExecutable ?? "docker";
  const prefix = composeExecutable ? [] : ["compose"];
  test.skip(spawnSync(executable, [...prefix, "version"], { timeout: 10000 }).status !== 0, "需要 Docker Compose 或 NEXO_TEST_COMPOSE 指向独立 Compose 程序");
  const token = `quote'"\\ $HOME $(touch injected) \`literal\` $$`;
  const h = harness("compose", token);
  try {
    expect(h.run().status).toBe(0);
    const resolved = spawnSync(executable, [...prefix, "-f", "compose.agent.yml", "config", "--environment"], { cwd: join(h.root, "install"), encoding: "utf8", timeout: 15000, env: { ...process.env, NEXO_SERVER_URL: undefined, NEXO_ENROLLMENT_TOKEN: undefined, TZ: undefined } });
    expect(resolved.status).toBe(0);
    expect(resolved.stdout.split(/\r?\n/)).toContain(`NEXO_SERVER_URL=${normalizeAgentServerUrl(h.server)}`);
    expect(resolved.stdout.split(/\r?\n/)).toContain(`NEXO_ENROLLMENT_TOKEN=${token}`);
    const parsed = spawnSync(executable, [...prefix, "-f", "compose.agent.yml", "config", "--format", "json"], { cwd: join(h.root, "install"), encoding: "utf8", timeout: 15000, env: { ...process.env, NEXO_SERVER_URL: undefined, NEXO_ENROLLMENT_TOKEN: undefined, TZ: undefined } });
    expect(parsed.stderr).toBe(""); expect(parsed.status).toBe(0);
    const agent = JSON.parse(parsed.stdout).services["nexo-agent"];
    // config 输出是可再次作为 Compose 输入的文档，序列化时会把字面美元符号重新转义为 $$。
    expect(agent.environment.NEXO_SERVER_URL.replace(/\$\$/g, () => "$")).toBe(normalizeAgentServerUrl(h.server));
    expect(agent.environment.NEXO_ENROLLMENT_TOKEN.replace(/\$\$/g, () => "$")).toBe(token);
    expect(agent.environment.TZ).toBe("Asia/Shanghai"); expect(agent.network_mode).toBe("host");
  } finally { h.clean(); }
});

for (const method of ["compose", "docker"] as const) {
  test(`${method} 经 Bash 执行保留特殊字符且不执行命令替换`, () => {
    const token = `quote'"\\ $HOME \\ $(touch injected) \`touch injected-too\` $$`;
    const h = harness(method, token);
    try {
      const result = h.run(); expect(result.error).toBeUndefined(); expect(result.stderr).toBe(""); expect(result.status).toBe(0);
      expect(existsSync(join(h.root, "install/data/nexo-agent"))).toBeTruthy();
      expect(existsSync(join(h.root, "install/injected"))).toBeFalsy(); expect(existsSync(join(h.root, "install/injected-too"))).toBeFalsy();
      const calls = h.calls();
      if (method === "docker") {
        const args = calls.find(call => call[0] === "run")!;
        expect(args).toContain(`NEXO_SERVER_URL=${normalizeAgentServerUrl(h.server)}`); expect(args).toContain(`NEXO_ENROLLMENT_TOKEN=${token}`);
        expect(args).toContain("host"); expect(args).toContain("unless-stopped");
        expect(args.some(arg => arg.endsWith("/install/data/nexo-agent:/data/nexo-agent"))).toBeTruthy();
      } else {
        expect(readFileSync(join(h.root, "install/compose.agent.yml"), "utf8")).toBe(template.replace(/\r\n/g, "\n"));
        expect(readFileSync(join(h.root, "ambient"), "utf8")).toBe("unset:unset");
        const env = readFileSync(join(h.root, "install/.env"), "utf8");
        expect(env).toContain('NEXO_ENROLLMENT_TOKEN="quote'); expect(env).toContain("$$HOME");
        expect(calls.at(-1)).toEqual(["compose", "-f", "compose.agent.yml", "up", "-d"]);
        // Windows ACL 不等价于 POSIX 权限；Linux CI 验证 umask 实际落盘结果。
        if (process.platform !== "win32") expect(statSync(join(h.root, "install/.env")).mode & 0o777).toBe(0o600);
      }
    } finally { h.clean(); }
  });

  test(`${method} 保护已有目录和容器，Docker 不可用或拉取失败时停止`, () => {
    for (const situation of ["directory", "container", "info", "pull"]) {
      const h = harness(method);
      try {
        if (situation === "directory") { mkdirSync(join(h.root, "install")); writeFileSync(join(h.root, "install/identity"), "keep-original"); }
        const result = h.run({ NEXO_TEST_CONTAINER: situation === "container" ? "yes" : "", NEXO_TEST_FAILURE: situation });
        expect(result.status).not.toBe(0);
        expect(h.calls().some(call => call[0] === "run" || call.includes("up"))).toBeFalsy();
        if (situation === "directory") expect(readFileSync(join(h.root, "install/identity"), "utf8")).toBe("keep-original");
        if (["container", "info"].includes(situation)) expect(existsSync(join(h.root, "install"))).toBeFalsy();
      } finally { h.clean(); }
    }
  });
}
