import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

async function openEnrollment(page: Page) {
  await page.goto("/#/agents");
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  return page.getByRole("dialog", { name: "添加 Agent", exact: true });
}

async function mockClipboard(page: Page, fail = false) {
  await page.addInitScript(fail => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (value: string) => { if (fail) throw new Error("denied"); (window as any).copiedCommand = value; } } });
    if (fail) document.execCommand = () => false;
  }, fail);
}

test("TOML 填入地址和凭证，Compose 与 docker run 使用相同数据目录，复制不写入浏览器存储", async ({ page }) => {
  await installApiMocks(page); await mockClipboard(page);
  const dialog = await openEnrollment(page);
  expect(await page.evaluate(() => document.activeElement instanceof HTMLInputElement)).toBeFalsy();
  await expect(dialog.getByLabel("Server 地址")).toHaveValue("http://127.0.0.1:4173");
  await expect(dialog.getByRole("button", { name: "复制接入密钥" })).toBeHidden();
  await dialog.getByText("高级：接入密钥", { exact: true }).click();
  await expect(dialog.getByRole("button", { name: "复制接入密钥" })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Docker Compose", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(dialog.getByLabel("Compose 配置文件", { exact: true })).toBeVisible();
  await dialog.getByLabel("Server 地址").fill("https://nexo.example.com/prefix///");
  await dialog.getByLabel("Server 地址").press("Enter");
  expect(await page.evaluate(() => (window as any).copiedCommand)).toBeUndefined();
  await dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true }).click();
  await expect(dialog.getByRole("status")).toHaveText("已复制");
  const compose = await page.evaluate(() => (window as any).copiedCommand as string);
  expect(compose).toMatch(/^name: nexo-agent/m);
  expect(compose).toContain("./data/nexo-agent:/data/nexo-agent");
  expect(compose).not.toContain("NEXO_");
  expect(compose).not.toContain("nexo_join_");
  await dialog.getByRole("button", { name: "复制 Agent TOML" }).click();
  const toml = await page.evaluate(() => (window as any).copiedCommand as string);
  expect(toml).toContain('server_url = "https://nexo.example.com/prefix"');
  expect(toml).toContain('enrollment_token = "nexo_join_shared-test-key"');
  await dialog.getByRole("button", { name: "docker run", exact: true }).click();
  await dialog.getByRole("button", { name: "复制 Docker run 命令", exact: true }).click();
  const docker = await page.evaluate(() => (window as any).copiedCommand as string);
  expect(docker).toContain("docker run -d --name nexo-agent --network host");
  expect(docker).not.toContain("bash <<");
  expect(docker).not.toContain("NEXO_");
  expect(docker).not.toContain("nexo_join_");
  expect(docker).toContain("nexo-agent:/data/nexo-agent");
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain("nexo_join_");
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  await expect(dialog.getByLabel("Agent TOML", { exact: true })).toContainText("nexo_join_shared-test-key");
});

test("失败可重试，无效地址阻止复制，剪贴板失败展开完整命令", async ({ page }) => {
  const state = await installApiMocks(page); await mockClipboard(page, true);
  state.failures.set("POST /api/v1/agent-access-key", "生成失败，请重试");
  const dialog = await openEnrollment(page);
  await expect(dialog.getByRole("alert")).toContainText("生成失败，请重试");
  state.failures.clear();
  await dialog.getByRole("button", { name: "重试", exact: true }).click();
  const copy = dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true });
  await expect(copy).toBeEnabled();
  await dialog.getByLabel("Server 地址").fill("https://user:pass@example.com/?secret=yes");
  await expect(copy).toHaveCount(0);
  await expect(dialog.getByLabel("Server 地址")).toHaveAttribute("aria-invalid", "true");
  await dialog.getByLabel("Server 地址").fill("https://nexo.example.com");
  await copy.click();
  await expect(dialog.getByRole("alert")).toContainText("手动复制");
  await expect(dialog.getByLabel("Compose 配置文件", { exact: true })).toBeVisible();
  await expect(dialog).toBeVisible();
});

test("共享密钥不过期，重置后配置更新且设备保留", async ({ page }) => {
  const state = await installApiMocks(page); await page.clock.install();
  const dialog = await openEnrollment(page);
  const config = dialog.getByLabel("Agent TOML", { exact: true });
  await expect(config).toContainText(state.accessKey);
  await page.clock.fastForward(3601_000);
  await expect(config).toContainText(state.accessKey);
  await dialog.getByText("高级：接入密钥", { exact: true }).click();
  await dialog.getByRole("button", { name: "重置接入密钥", exact: true }).click();
  await page.getByRole("dialog", { name: "重置接入密钥？" }).getByRole("button", { name: "重置密钥", exact: true }).click();
  await expect(config).toContainText("nexo_join_reset-test-key");
  expect(state.devices).toHaveLength(2);
  await dialog.getByRole("button", { name: "完成", exact: true }).click();
  await expect(dialog).toHaveCount(0);
});

test("移动端触控、长命令、横屏与键盘压缩视口", async ({ page }, info) => {
  await installApiMocks(page);
  const dialog = await openEnrollment(page);
  const copy = dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true });
  await expect(copy).toBeEnabled();
  for (const [width, height, name] of [[320, 640, "narrow"], [375, 812, "portrait"], [390, 844, "portrait-large"], [430, 932, "portrait-wide"], [812, 375, "landscape"], [320, 360, "keyboard"]] as const) {
    await page.setViewportSize({ width, height });
    await copy.scrollIntoViewIfNeeded();
    await expect(copy).toBeInViewport();
    await expect(dialog.getByRole("button", { name: "取消", exact: true })).toBeInViewport();
    expect((await copy.boundingBox())!.height).toBeGreaterThanOrEqual(44);
    if (!await dialog.getByRole("button", { name: "复制接入密钥" }).isVisible()) await dialog.getByText("高级：接入密钥", { exact: true }).click();
    for (const button of [dialog.getByRole("button", { name: "Docker Compose", exact: true }), dialog.getByRole("button", { name: "docker run", exact: true }), dialog.getByRole("button", { name: "复制接入密钥" })]) {
      const box = (await button.boundingBox())!; expect(box.height).toBeGreaterThanOrEqual(44); expect(box.width).toBeGreaterThanOrEqual(44);
    }
    const input = dialog.getByLabel("Server 地址");
    await input.fill("invalid"); await input.focus();
    await expect(dialog.getByRole("alert")).toBeInViewport();
    const box = (await input.boundingBox())!;
    const heading = (await dialog.locator(".modal-heading").boundingBox())!;
    const footer = (await dialog.locator(".modal-actions").boundingBox())!;
    expect(box.y).toBeGreaterThanOrEqual(heading.y + heading.height);
    expect(box.y + box.height).toBeLessThanOrEqual(footer.y);
    expect(await dialog.evaluate(e => e.scrollWidth <= e.clientWidth)).toBeTruthy();
    await page.screenshot({ path: info.outputPath(`agent-${name}.png`) });
    await input.fill("https://a-very-long-agent-api-address.example.com/a/very/long/prefix");
    await input.press("Enter");
    if (name === "portrait" || name === "landscape") {
      await dialog.locator(".modal-body").evaluate(element => { element.scrollTop = 0; });
      await page.screenshot({ path: info.outputPath(`agent-${name}-ready.png`) });
    }
  }
  await page.setViewportSize({ width: 375, height: 812 });
  await expect(dialog.getByLabel("Compose 配置文件", { exact: true })).toBeVisible();
  expect(await dialog.evaluate(e => e.scrollWidth <= e.clientWidth)).toBeTruthy();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("agent-command-expanded.png") });
});

test("普通用户使用本人入网接口", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: true, user_id: "alice", workspace_id: "alice-space", role: "tenant", username: "alice", csrf_token: "tenant-csrf" } }));
  const dialog = await openEnrollment(page);
  await expect(dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true })).toBeEnabled();
  expect(state.calls.find(c => c.method === "POST" && c.path.endsWith("/agent-access-key"))?.path).toBe("/api/v1/agent-access-key");
});

test("管理员代管空间时在目标空间生成凭证", async ({ page }) => {
  const state = await installApiMocks(page); const posts: string[] = [];
  const pageErrors: string[] = []; page.on("pageerror", error => pageErrors.push(error.message));
  await page.route("**/api/v1/admin/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/admin/users") return route.fulfill({ json: [{ id: "alice", username: "alice", role: "tenant", workspace_id: "alice-space", workspace_name: "alice 的工作空间", enabled: true, devices: 1, services: 1, domains: 1 }] });
    if (route.request().method() === "POST" && path.endsWith("/agent-access-key")) { posts.push(path); return route.fulfill({ json: { token: "nexo_join_scoped-secret", created_at: 1790000000, updated_at: 1790000000 } }); }
    if (path.endsWith("/devices") || path.endsWith("/tunnels")) return route.fulfill({ json: path.endsWith("/devices") ? state.devices : state.tunnels });
    if (path === "/api/v1/admin/workspaces/alice-space/enrollments") return route.fulfill({ json: [] });
    return route.fallback();
  });
  await page.goto("/#/users");
  await page.getByRole("button", { name: "管理 alice 的空间" }).click();
  await expect(page.locator(".workspace-banner")).toContainText("alice 的工作空间");
  await page.getByRole("link", { name: "设备", exact: true }).click();
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  await expect(page.getByLabel("Agent TOML", { exact: true })).toContainText("nexo_join_scoped-secret");
  expect(posts).toEqual(["/api/v1/admin/workspaces/alice-space/agent-access-key"]);
  expect(pageErrors).toEqual([]);
});
