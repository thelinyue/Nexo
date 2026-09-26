import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

// 不替换 Clipboard API 或 execCommand：从另一个安全页面读回浏览器真实剪贴板。
// 本文件以 --workers=1 运行，避免测试之间争用剪贴板。
for (const insecure of [false, true]) test(`${insecure ? "HTTP 同步回退" : "Clipboard API"}真实复制地址、配置、密钥和设备识别码`, async ({ page, context, browserName }) => {
  test.skip(browserName !== "chromium", "真实剪贴板读取权限使用 Chromium；WebKit 失败反馈另有覆盖");
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: "http://127.0.0.1:4173" });
  const base = insecure ? "http://copy.example.test:4173" : "http://127.0.0.1:4173";
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

  await page.goto(`${base}/#/agents`);
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "添加 Agent", exact: true });
  await dialog.getByLabel("设备名称（可选）", { exact: true }).fill("家庭 NAS ' $HOME");
  const compose = dialog.getByLabel("Compose 配置文件", { exact: true });
  await expect(compose).toContainText(state.accessKey);
  await dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true }).click();
  await expect(dialog.getByRole("status")).toHaveText("Compose 配置文件已复制");
  expect(await readClipboard()).toBe(await compose.textContent());
  await dialog.getByRole("button", { name: "docker run", exact: true }).click();
  const command = dialog.getByLabel("Docker run 命令", { exact: true });
  await dialog.getByRole("button", { name: "复制 Docker run 命令", exact: true }).click();
  await expect(dialog.getByRole("status")).toHaveText("Docker run 命令已复制");
  expect(await readClipboard()).toBe(await command.textContent());
  await dialog.getByText("高级：接入密钥", { exact: true }).click();
  await dialog.getByRole("button", { name: "复制接入密钥", exact: true }).click();
  await expect(dialog.locator(".copy-control [role=status]")).toHaveText("已复制");
  expect(await readClipboard()).toBe(state.accessKey);

  await dialog.getByRole("button", { name: "重置接入密钥", exact: true }).click();
  await page.getByRole("dialog", { name: "重置接入密钥？", exact: true }).getByRole("button", { name: "重置密钥", exact: true }).click();
  await expect(command).toContainText("nexo_join_reset-test-key");
  await dialog.getByRole("button", { name: "复制 Docker run 命令", exact: true }).click();
  await expect(dialog.getByRole("status")).toHaveText("Docker run 命令已复制");
  expect(await readClipboard()).toBe(await command.textContent());
  await dialog.getByRole("button", { name: "完成", exact: true }).click();

  await page.goto(`${base}/#/agents/a-1`);
  await page.getByText("设备信息", { exact: true }).click();
  await page.getByRole("button", { name: "复制设备识别码", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("已复制");
  expect(await readClipboard()).toBe("a-1");
  await reader.close();
});
