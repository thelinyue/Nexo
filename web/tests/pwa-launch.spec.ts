import { expect, test, type Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

/** 只覆盖安装态媒体查询，其余颜色、动态效果偏好继续由浏览器真实实现。 */
async function emulateInstalledPwa(page: Page) {
  await page.addInitScript(() => {
    const nativeMatchMedia = window.matchMedia.bind(window);
    window.matchMedia = query => {
      const result = nativeMatchMedia(query);
      if (query === "(display-mode: standalone)") Object.defineProperty(result, "matches", { configurable: true, value: true });
      return result;
    };
  });
}

test("PWA 慢启动显示连接提示并在认证明确后立即进入", async ({ page }, info) => {
  await emulateInstalledPwa(page);
  const state = await installApiMocks(page);
  state.delay = 1300;
  await page.goto("/#/services");

  const launch = page.locator("#pwa-launch");
  await expect(launch).toBeVisible();
  await expect(launch.locator("img")).toHaveAttribute("alt", "");
  await expect.poll(() => launch.locator("img").evaluate(image => (image as HTMLImageElement).naturalWidth)).toBe(768);
  await expect(page.getByText("正在连接 Nexo…", { exact: true })).toBeVisible({ timeout: 1200 });
  await page.screenshot({ path: info.outputPath(`${info.project.name}-pwa-launch.png`) });
  await expect(launch).toHaveCount(0, { timeout: 1500 });
  await expect(page.locator(".app-shell")).toBeVisible();
});

test("普通浏览器、后台恢复和站内导航不会触发启动层", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "非安装态行为集中验收");
  const state = await installApiMocks(page);
  state.delay = 1100;
  await page.goto("/#/services");
  await expect(page.locator("#pwa-launch")).toBeHidden();
  await expect(page.locator(".app-shell")).toBeVisible();
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await page.goto("/#/agents");
  await expect(page.locator("#pwa-launch")).toBeHidden();
});

test("PWA 请求失败和插画失败都不会遮挡现有界面", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "失败路径集中验收");
  await emulateInstalledPwa(page);
  const state = await installApiMocks(page);
  await page.route("**/brand/pwa-launch.webp", route => route.abort());
  state.failures.set("GET /api/v1/auth/status", "认证服务暂时不可用");
  await page.goto("/");
  await expect(page.locator("#pwa-launch")).toHaveCount(0);
  await expect(page.getByRole("alert")).toContainText("认证服务暂时不可用");
  await expect(page.getByRole("button", { name: "重试" })).toBeVisible();
});

test("PWA 手动刷新按新文档重新显示启动层", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "刷新语义集中验收");
  await emulateInstalledPwa(page);
  const state = await installApiMocks(page);
  await page.goto("/#/services");
  await expect(page.locator("#pwa-launch")).toHaveCount(0);
  state.delay = 600;
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator("#pwa-launch")).toBeVisible();
  await expect(page.locator("#pwa-launch")).toHaveCount(0, { timeout: 1200 });
});

test("PWA 启动后仍由现有认证页面处理未登录与未初始化状态", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "认证流程集中验收");
  await emulateInstalledPwa(page);
  const state = await installApiMocks(page, { anonymous: true });
  await page.goto("/");
  await expect(page.locator("#pwa-launch")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
  state.initialized = false;
  await page.reload();
  await expect(page.locator("#pwa-launch")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
});

test.describe("PWA 离线冷启动", () => {
  test.use({ serviceWorkers: "allow" });
  test("离线重开显示缓存界面并交还网络错误", async ({ page, context }, info) => {
    test.skip(info.project.name !== "desktop-dark", "使用 Chromium Service Worker 验收");
    await emulateInstalledPwa(page);
    await page.goto("/");
    await page.evaluate(async () => {
      await navigator.serviceWorker.ready;
      if (!navigator.serviceWorker.controller) await new Promise<void>(resolve => navigator.serviceWorker.addEventListener("controllerchange", () => resolve(), { once: true }));
    });
    await context.setOffline(true);
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.locator("#pwa-launch")).toBeVisible();
    await expect(page.locator("#pwa-launch")).toHaveCount(0);
    await expect(page.getByRole("alert")).toContainText("无法连接 Nexo");
    await context.setOffline(false);
  });
});
