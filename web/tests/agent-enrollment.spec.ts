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
  }, fail);
}

test("Compose 配置与 docker run 命令自动填入地址和凭证，复制不写入浏览器存储", async ({ page }) => {
  await installApiMocks(page); await mockClipboard(page);
  const dialog = await openEnrollment(page);
  expect(await page.evaluate(() => document.activeElement instanceof HTMLInputElement)).toBeFalsy();
  await expect(dialog.getByLabel("Server 地址")).toHaveValue("http://127.0.0.1:4173");
  await dialog.getByRole("button", { name: "生成凭证", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "复制入网凭证" })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Docker Compose", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(dialog.getByLabel("Compose 配置文件", { exact: true })).toBeVisible();
  await dialog.getByLabel("Server 地址").fill("https://nexo.example.com/prefix///");
  await dialog.getByLabel("Server 地址").press("Enter");
  expect(await page.evaluate(() => (window as any).copiedCommand)).toBeUndefined();
  await dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true }).click();
  await expect(dialog.getByRole("status")).toHaveText("Compose 配置文件已复制");
  const compose = await page.evaluate(() => (window as any).copiedCommand as string);
  expect(compose).toContain("https://nexo.example.com/prefix");
  expect(compose).not.toContain("prefix///");
  expect(compose).toContain("one-time-secret-enrollment-token");
  expect(compose).toMatch(/^name: nexo-agent/m);
  expect(compose).toContain('NEXO_SERVER_URL: "https://nexo.example.com/prefix"');
  expect(compose).toContain('NEXO_ENROLLMENT_TOKEN: "one-time-secret-enrollment-token"');
  expect(compose).toContain("./data/nexo-agent-e-new:/data/nexo-agent");
  expect(compose).not.toContain("bash <<");
  await dialog.getByRole("button", { name: "docker run", exact: true }).click();
  await dialog.getByRole("button", { name: "复制部署命令", exact: true }).click();
  const docker = await page.evaluate(() => (window as any).copiedCommand as string);
  expect(docker).toContain("docker run -d --name nexo-agent --network host");
  expect(docker).not.toContain("bash <<");
  expect(docker).toContain("NEXO_SERVER_URL=https://nexo.example.com/prefix");
  expect(docker).toContain("NEXO_ENROLLMENT_TOKEN=one-time-secret-enrollment-token");
  expect(docker).toContain("nexo-agent-e-new:/data/nexo-agent");
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain("one-time-secret");
  await dialog.getByRole("button", { name: "关闭", exact: true }).click();
  await page.getByRole("button", { name: "放弃修改", exact: true }).click();
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  await expect(page.getByRole("button", { name: "生成凭证", exact: true })).toBeVisible();
  await expect(page.locator(".token")).toHaveCount(0);
});

test("失败可重试，无效地址阻止复制，剪贴板失败展开完整命令", async ({ page }) => {
  const state = await installApiMocks(page); await mockClipboard(page, true);
  state.failures.set("POST /api/v1/enrollments", "生成失败，请重试");
  const dialog = await openEnrollment(page);
  await dialog.getByRole("button", { name: "生成凭证", exact: true }).click();
  await expect(dialog.getByRole("alert")).toHaveText("生成失败，请重试");
  state.failures.clear();
  await dialog.getByRole("button", { name: "生成凭证", exact: true }).click();
  const copy = dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true });
  await expect(copy).toBeEnabled();
  await dialog.getByLabel("Server 地址").fill("https://user:pass@example.com/?secret=yes");
  await expect(copy).toBeDisabled();
  await expect(dialog.getByLabel("Server 地址")).toHaveAttribute("aria-invalid", "true");
  await dialog.getByLabel("Server 地址").fill("https://nexo.example.com");
  await copy.click();
  await expect(dialog.getByRole("alert")).toContainText("长按选择");
  await expect(dialog.getByLabel("Compose 配置文件", { exact: true })).toBeVisible();
  await expect(dialog).toBeVisible();
});

test("缺失凭证禁用复制，过期凭证移除命令并提示重新生成", async ({ page }) => {
  await installApiMocks(page);
  let token: string | null = null;
  await page.route("**/api/v1/enrollments", route => route.request().method() === "POST" ? route.fulfill({ json: { id: "e-new", status: "awaiting_agent", token, expires_at: Math.floor(Date.now()/1000) + 3600 } }) : route.fallback());
  const dialog = await openEnrollment(page);
  await dialog.getByRole("button", { name: "生成凭证", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("未返回凭证");
  await expect(dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true })).toBeDisabled();
  await dialog.getByRole("button", { name: "关闭", exact: true }).click();
  token = "short-lived-token";
  await page.clock.install();
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  await dialog.getByRole("button", { name: "生成凭证", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true })).toBeEnabled();
  await page.clock.fastForward(3601_000);
  await expect(dialog.getByRole("alert")).toContainText("凭证已过期");
  await expect(dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true })).toBeDisabled();
  await expect(dialog.locator(".agent-command")).toHaveCount(0);
});

test("移动端触控、长命令、横屏与键盘压缩视口", async ({ page }, info) => {
  await installApiMocks(page);
  const dialog = await openEnrollment(page);
  await dialog.getByRole("button", { name: "生成凭证", exact: true }).click();
  const copy = dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true });
  await expect(copy).toBeEnabled();
  for (const [width, height, name] of [[320, 640, "narrow"], [375, 812, "portrait"], [390, 844, "portrait-large"], [812, 375, "landscape"], [320, 360, "keyboard"]] as const) {
    await page.setViewportSize({ width, height });
    await expect(copy).toBeInViewport();
    await expect(dialog.getByRole("button", { name: "关闭", exact: true })).toBeInViewport();
    expect((await copy.boundingBox())!.height).toBeGreaterThanOrEqual(48);
    for (const button of [dialog.getByRole("button", { name: "Docker Compose", exact: true }), dialog.getByRole("button", { name: "docker run", exact: true }), dialog.getByRole("button", { name: "复制入网凭证" })]) {
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
  await dialog.getByRole("button", { name: "生成凭证", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "复制 Compose 配置文件", exact: true })).toBeEnabled();
  expect(state.calls.find(c => c.method === "POST" && c.path.endsWith("/enrollments"))?.path).toBe("/api/v1/enrollments");
});

test("管理员代管空间时在目标空间生成凭证", async ({ page }) => {
  const state = await installApiMocks(page); const posts: string[] = [];
  await page.route("**/api/v1/admin/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/admin/users") return route.fulfill({ json: [{ id: "alice", username: "alice", role: "tenant", workspace_id: "alice-space", workspace_name: "alice 的工作空间", enabled: true, devices: 1, services: 1, domains: 1 }] });
    if (route.request().method() === "POST") { posts.push(path); return route.fulfill({ json: { id: "scoped", status: "awaiting_agent", token: "scoped-secret", expires_at: Math.floor(Date.now()/1000) + 3600 } }); }
    return route.fulfill({ json: path.endsWith("/devices") ? state.devices : path.endsWith("/tunnels") ? state.tunnels : [] });
  });
  await page.goto("/#/users");
  await page.getByRole("button", { name: "管理 alice 的空间" }).click();
  await page.evaluate(() => { window.location.hash = "#/agents"; });
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  await page.getByRole("button", { name: "生成凭证", exact: true }).click();
  await expect(page.locator(".token")).toHaveText("scoped-secret");
  expect(posts).toEqual(["/api/v1/admin/workspaces/alice-space/enrollments"]);
});
