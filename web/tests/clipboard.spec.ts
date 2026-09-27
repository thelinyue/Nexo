import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import { createServer } from "node:https";
import { request } from "node:http";
import { resolve } from "node:path";
import { installApiMocks } from "./api-mocks";

// 固定测试证书只用于本机 HTTPS 验收，不安装信任、不使用生产私钥。
let tlsServer: ReturnType<typeof createServer>;
let httpsBase: string;
test.use({ ignoreHTTPSErrors: true });
test.beforeAll(async () => {
  tlsServer = createServer({
    key: readFileSync(resolve("tests/fixtures/clipboard-test.key")),
    cert: readFileSync(resolve("tests/fixtures/clipboard-test.crt")),
  }, (incoming, outgoing) => {
    const upstream = request({ hostname: "127.0.0.1", port: 4173, path: incoming.url, method: incoming.method, headers: { ...incoming.headers, host: "127.0.0.1:4173" } }, response => {
      outgoing.writeHead(response.statusCode ?? 502, response.headers);
      response.pipe(outgoing);
    });
    upstream.on("error", () => { outgoing.writeHead(502); outgoing.end(); });
    incoming.pipe(upstream);
  });
  await new Promise<void>(done => tlsServer.listen(0, "127.0.0.1", done));
  httpsBase = `https://127.0.0.1:${(tlsServer.address() as { port: number }).port}`;
});
test.afterAll(async () => {
  tlsServer.closeAllConnections();
  await new Promise<void>((done, reject) => tlsServer.close(error => error ? reject(error) : done()));
});

// 不替换 Clipboard API 或 execCommand：从另一个安全页面读回浏览器真实剪贴板。
// 本文件以 --workers=1 运行，避免测试之间争用剪贴板。
for (const transport of ["loopback", "http", "https"]) test(`${transport} 真实复制地址、配置、密钥和设备识别码`, async ({ page, context, browserName }) => {
  test.skip(browserName !== "chromium", "真实剪贴板读取权限使用 Chromium；WebKit 失败反馈另有覆盖");
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: "http://127.0.0.1:4173" });
  const insecure = transport === "http";
  const base = insecure ? "http://copy.example.test:4173" : transport === "https" ? httpsBase : "http://127.0.0.1:4173";
  if (transport === "https") await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: base });
  if (insecure) await page.route(`${base}/**`, async route => {
    const response = await route.fetch({ url: route.request().url().replace("copy.example.test", "127.0.0.1") });
    await route.fulfill({ response });
  });
  const state = await installApiMocks(page);
  const reader = await context.newPage();
  await installApiMocks(reader);
  await reader.goto("http://127.0.0.1:4173/");
  async function readClipboard() {
    await reader.bringToFront();
    const value = await reader.evaluate(() => navigator.clipboard.readText());
    await page.bringToFront();
    return value.replace(/\r\n/g, "\n");
  }
  await page.goto(`${base}/#/services`); await page.bringToFront();
  expect(await page.evaluate(() => isSecureContext)).toBe(!insecure);
  if (insecure) expect(await page.evaluate(() => Boolean(navigator.clipboard))).toBe(false);
  await page.getByRole("button", { name: "复制媒体中心公网地址", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("已复制");
  expect(await readClipboard()).toBe(state.tunnels[0].public_address);

  let linksCreated = 0;
  await page.route("**/api/v1/admin/invitations", route => {
    if (route.request().method() === "POST") { linksCreated++; return route.fulfill({ json: { token: "invite/with+fragment=".repeat(20), expires_at: Date.now()/1000 + 3600 } }); }
    return route.fulfill({ json: [] });
  });
  await page.route("**/api/v1/admin/users/alice/recovery", route => route.fulfill({ json: { token: "recovery/with+fragment=", expires_at: Date.now()/1000 + 3600 } }));
  await page.goto(`${base}/#/users`);
  await page.getByRole("button", { name: "邀请用户" }).click();
  const invitation = page.getByRole("dialog", { name: "邀请链接", exact: true });
  await invitation.getByRole("button", { name: "复制链接" }).click();
  await expect(invitation.getByRole("status")).toHaveText("已复制");
  expect(await readClipboard()).toBe(await invitation.locator("code.token").textContent());
  expect(linksCreated).toBe(1);
  await invitation.getByRole("button", { name: "关闭", exact: true }).click();
  await page.locator(".user-card").filter({ has: page.getByRole("heading", { name: "alice", exact: true }) }).getByRole("button", { name: "更多", exact: true }).click();
  await page.getByRole("button", { name: "重设密码", exact: true }).click();
  const recovery = page.getByRole("dialog", { name: "重设 alice 的密码", exact: true });
  await recovery.getByRole("button", { name: "复制链接" }).click();
  await expect(recovery.getByRole("status")).toHaveText("已复制");
  expect(await readClipboard()).toBe(await recovery.locator("code.token").textContent());
  await recovery.getByRole("button", { name: "关闭", exact: true }).click();
  await page.goto(`${base}/#/agents`);
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "添加 Agent", exact: true });
  await dialog.getByLabel("设备名称（可选）", { exact: true }).fill("家庭 NAS ' $HOME");
  await dialog.getByText("查看部署命令", { exact: true }).click();
  const compose = dialog.getByLabel("Compose 部署命令", { exact: true });
  await expect(compose).toContainText(state.accessKey);
  await dialog.getByRole("button", { name: "复制 Compose 部署命令", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "复制 Compose 部署命令", exact: true }).locator("..").getByRole("status")).toHaveText("已复制");
  expect(await readClipboard()).toBe(await compose.textContent());
  await dialog.getByRole("button", { name: "docker run", exact: true }).click();
  const command = dialog.getByLabel("Docker run 部署命令", { exact: true });
  await dialog.getByRole("button", { name: "复制 Docker run 部署命令", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "复制 Docker run 部署命令", exact: true }).locator("..").getByRole("status")).toHaveText("已复制");
  expect(await readClipboard()).toBe(await command.textContent());
  await dialog.getByText("高级：接入密钥", { exact: true }).click();
  await dialog.getByRole("button", { name: "复制接入密钥", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "复制接入密钥", exact: true }).locator("..").getByRole("status")).toHaveText("已复制");
  expect(await readClipboard()).toBe(state.accessKey);

  await dialog.getByRole("button", { name: "重置接入密钥", exact: true }).click();
  await page.getByRole("dialog", { name: "重置接入密钥？", exact: true }).getByRole("button", { name: "重置密钥", exact: true }).click();
  await expect(command).toContainText("nexo_join_reset-test-key");
  await dialog.getByRole("button", { name: "复制 Docker run 部署命令", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "复制 Docker run 部署命令", exact: true }).locator("..").getByRole("status")).toHaveText("已复制");
  expect(await readClipboard()).toBe(await command.textContent());
  await dialog.getByRole("button", { name: "完成", exact: true }).click();

  await page.goto(`${base}/#/agents/a-1`);
  await page.getByText("设备信息", { exact: true }).click();
  await page.getByRole("button", { name: "复制设备识别码", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("已复制");
  expect(await readClipboard()).toBe("a-1");
  await reader.close();
});
