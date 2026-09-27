import { openServiceEditor } from "./service-actions";
import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const current = (page: import("@playwright/test").Page) => page.locator(".page-slot:not([hidden])");

test("桌面独立详情标签、去重、关闭、刷新和后台轮询", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面标签交互");
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "t-2", name: "备用媒体" });
  await page.goto("/#/services");
  await page.getByLabel("搜索服务").fill("媒体");
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  await expect(page.getByRole("tab", { name: "媒体中心", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "服务", exact: true }).click();
  await expect(page.getByLabel("搜索服务")).toHaveValue("媒体");
  await page.getByRole("link", { name: "备用媒体", exact: true }).click();
  await expect(page.getByRole("tab")).toHaveCount(4);
  for (const close of await page.locator(".workspace-tab .tab-close").all()) {
    await expect(close).toBeVisible();
    const bounds = await close.boundingBox();
    expect(bounds!.width).toBeGreaterThanOrEqual(32);
    expect(bounds!.height).toBeGreaterThanOrEqual(32);
  }
  await page.getByRole("tab", { name: "媒体中心", exact: true }).click();
  await expect(current(page).locator(".service-detail h2")).toHaveText("媒体中心");
  await page.getByRole("tab", { name: "服务", exact: true }).click();
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  await expect(page.getByRole("tab")).toHaveCount(4);
  await expect(page.getByRole("navigation", { name: "面包屑" })).toContainText("服务媒体中心");
  await page.reload();
  await expect(page.getByRole("tab")).toHaveCount(4);
  await expect(page.getByRole("tab", { name: "媒体中心", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.locator(".sidebar").getByRole("link", { name: "设备", exact: true }).click();
  await expect(current(page).locator(".agent-row")).toHaveCount(2);
  state.calls.length = 0;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect.poll(() => state.calls.filter(call => call.path === "/api/v1/devices").length).toBe(1);
  expect(state.calls.filter(call => call.path === "/api/v1/public-domains")).toHaveLength(0);
  await page.getByRole("button", { name: "关闭 设备", exact: true }).click();
  await expect(page).toHaveURL(/#\/services\/t-2$/);
  await page.getByRole("button", { name: "关闭 媒体中心", exact: true }).click();
  await expect(page).toHaveURL(/#\/services\/t-2$/);
  const workspace = await current(page).boundingBox();
  expect(workspace!.x + workspace!.width).toBeCloseTo(page.viewportSize()!.width - 24, 0);
  await page.mouse.move(800, 850);
  await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath("desktop-tabs.png") });
  await current(page).getByRole("button", { name: "编辑服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await expect(editor.getByLabel("服务名称")).toHaveValue("备用媒体");
  await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath("desktop-service-editor.png") });
});

test("首页标签固定，关闭其他页面回到首页，旧空工作区跳转兼容", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面固定首页");
  await installApiMocks(page);
  await page.goto("/#/services");
  await expect(page.getByRole("tab")).toHaveText(["首页", "服务"]);
  await expect(page.getByRole("button", { name: "关闭 首页" })).toHaveCount(0);
  await page.getByRole("tab", { name: "首页", exact: true }).click();
  await page.getByRole("tab", { name: "首页", exact: true }).press("Delete");
  await expect(page.getByRole("tab")).toHaveText(["首页", "服务"]);
  await page.getByRole("tab", { name: "服务", exact: true }).click();
  await openServiceEditor(page);
  await page.evaluate(() => document.querySelector<HTMLButtonElement>('.tab-close[aria-label="关闭 服务"]')!.click());
  await expect(page).toHaveURL(/#\/services$/);
  await expect(page.getByRole("dialog", { name: "创建服务" })).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "关闭 服务", exact: true }).click();
  await expect(page).toHaveURL(/#\/home$/);
  await expect(page.getByRole("tab")).toHaveText(["首页"]);
  await page.reload();
  await expect(page.getByRole("tab")).toHaveText(["首页"]);
  await page.goto("/#/workspace");
  await expect(page).toHaveURL(/#\/home$/);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("navigation", { name: "底部导航" })).toBeVisible();
  await expect(current(page).locator("h1")).toHaveText("首页");
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.getByRole("tab")).toHaveText(["首页"]);
});

test("标签恢复只读取当前用户空间，地址栏优先且不会恢复表单", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面标签存储");
  await installApiMocks(page);
  await page.addInitScript(() => {
    sessionStorage.setItem("nexo:tabs:admin:default", JSON.stringify({ tabs: ["#/services", "#/agents/a-1", "#/domains"], route: "#/domains" }));
    sessionStorage.setItem("nexo:tabs:admin:alice-space", JSON.stringify({ tabs: ["#/services", "#/services/private-resource"], route: "#/services/private-resource" }));
    sessionStorage.setItem("nexo:tabs:alice:default", JSON.stringify({ tabs: ["#/services", "#/services/other-user"], route: "#/services/other-user" }));
  });
  await page.goto("/");
  await expect(page).toHaveURL(/#\/domains$/);
  await expect(page.getByRole("tab")).toHaveCount(4);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator('a[href*="private-resource"],a[href*="other-user"]')).toHaveCount(0);
  await page.goto("/#/agents");
  await expect(page.getByRole("tab", { name: "设备", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("tab")).toHaveCount(5);
});

test("PWA 玻璃底栏在复杂背景和辅助功能偏好下仍可用", async ({ page }, info) => {
  test.skip(info.project.name !== "mobile-light", "材质及断点矩阵只运行一次");
  const state = await installApiMocks(page);
  state.tunnels = Array.from({ length: 12 }, (_, index) => ({ ...state.tunnels[0], id: `t-${index}`, name: `家庭隧道 ${index}` }));
  for (const theme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: theme });
    await page.goto("/#/services");
    await expect(current(page).locator(".service-row")).toHaveCount(12);
    await page.evaluate(() => window.scrollTo(0, 180));
    const nav = page.locator(".bottom-nav");
    await expect(nav).toHaveCSS("border-radius", "999px");
    await expect(nav.getByRole("link", { name: "服务", exact: true })).toHaveAttribute("aria-current", "page");
    await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath(`glass-over-content-${theme}.png`) });
    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
    const last = await current(page).locator(".service-row").last().boundingBox(); const bounds = await nav.boundingBox();
    expect(last!.y + last!.height).toBeLessThanOrEqual(bounds!.y);
  }
  await page.emulateMedia({ contrast: "more", reducedMotion: "reduce" });
  await expect(page.locator(".bottom-nav")).toHaveCSS("backdrop-filter", "none");
  await expect(page.locator('.bottom-nav a[aria-current="page"]')).toHaveCSS("transition-duration", "0s");
  await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath("glass-high-contrast.png") });
  await page.setViewportSize({ width: 900, height: 900 });
  await expect(page.locator(".bottom-nav")).toBeVisible();
  await page.setViewportSize({ width: 901, height: 900 });
  await expect(page.locator(".bottom-nav")).toBeHidden();
  await expect(page.getByRole("tablist")).toBeVisible();
});

test("手机五入口和玻璃底栏、详情返回与我的", async ({ page }, info) => {
  test.skip(info.project.name === "desktop-dark", "手机 App 导航");
  await installApiMocks(page);
  await page.goto("/#/services");
  const nav = page.getByRole("navigation", { name: "底部导航" });
  await expect(nav.getByRole("link")).toHaveText(["首页", "服务", "设备", "域名", "我的"]);
  await expect(page.getByRole("tablist")).toBeHidden();
  await expect(page.getByRole("navigation", { name: "面包屑" })).toBeHidden();
  await page.getByLabel("搜索服务").fill("媒体");
  await nav.getByRole("link", { name: "设备", exact: true }).click();
  await expect(nav).toBeVisible();
  await nav.getByRole("link", { name: "域名", exact: true }).click();
  await expect(nav).toBeVisible();
  await nav.getByRole("link", { name: "服务", exact: true }).click();
  await expect(page.getByLabel("搜索服务")).toHaveValue("媒体");
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  await expect(nav).toBeHidden();
  await page.getByRole("link", { name: "家庭 Agent", exact: true }).click();
  await expect(current(page).locator("h1")).toHaveText("家庭 Agent");
  await page.getByRole("link", { name: "返回", exact: true }).click();
  await expect(page).toHaveURL(/#\/services\/t-1$/);
  await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath("mobile-detail.png") });
  await page.getByRole("link", { name: "返回", exact: true }).click();
  await expect(page.getByLabel("搜索服务")).toHaveValue("媒体");
  await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath("mobile-glass-navigation.png") });
  await nav.getByRole("link", { name: "我的", exact: true }).click();
  await expect(current(page).locator("h1")).toHaveText("我的");
  await expect(nav.getByRole("link", { name: "我的", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(current(page).getByRole("link", { name: "用户管理", exact: true })).toBeVisible();
  await expect(current(page).getByRole("region", { name: "服务端内部证书" })).not.toContainText("读取中");
  await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath("mobile-account.png") });
});

test("空白与已修改表单锁住历史导航，跨断点保持实例", async ({ page }, info) => {
  await installApiMocks(page);
  await page.goto("/#/agents");
  await page.evaluate(() => { window.location.hash = "#/services"; });
  await openServiceEditor(page);
  const editor = page.getByRole("dialog", { name: "创建服务" });
  await page.goBack();
  await expect(page).toHaveURL(/#\/services$/);
  await expect(editor).toBeVisible();
  await expect(page.getByRole("dialog", { name: "放弃未保存的修改？" })).toHaveCount(0);
  await editor.getByLabel("服务名称").fill("跨断点草稿");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.evaluate(() => { window.location.hash = "#/domains"; });
  await expect(page).toHaveURL(/#\/services$/);
  await expect(editor.getByLabel("服务名称")).toHaveValue("跨断点草稿");
  await expect(page.locator(".bottom-nav")).toBeHidden();
  await expect(editor).toHaveCSS("height", "844px");
  await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath("mobile-full-form.png") });
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(editor.getByLabel("服务名称")).toHaveValue("跨断点草稿");
  await editor.locator(".modal-actions").getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "放弃修改", exact: true }).click();
  await page.locator(".sidebar").getByRole("link", { name: "域名", exact: true }).click();
  await expect(page).toHaveURL(/#\/domains$/);
});

test("账号菜单键盘关闭与退出清理标签", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面账号菜单");
  await installApiMocks(page);
  await page.goto("/#/agents");
  const trigger = page.locator(".account-trigger");
  await trigger.click();
  await expect(page.locator(".account-popover")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator(".account-popover")).toBeHidden();
  await expect(trigger).toBeFocused();
  await trigger.click();
  await page.locator(".account-popover").getByRole("link", { name: "账号设置" }).click();
  await expect(page.getByRole("tab", { name: "账号设置" })).toHaveAttribute("aria-selected", "true");
  await current(page).getByRole("button", { name: "退出登录", exact: true }).click();
  await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
  expect(await page.evaluate(() => Object.keys(sessionStorage).filter(key => key.startsWith("nexo:tabs:")))).toEqual([]);
});
