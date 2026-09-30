import { openServiceEditor } from "./service-actions";
import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const current = (page: import("@playwright/test").Page) => page.locator(".page-slot:not([hidden])");

test("页面分包失败保留导航，用户重试后恢复页面", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面导航分包错误恢复");
  await installApiMocks(page);
  await page.route("**/assets/services-*.js", route => route.abort());
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "首页", exact: true })).toBeVisible();
  await page.locator(".sidebar").getByRole("link", { name: "服务", exact: true }).click();
  await expect(current(page).getByRole("alert")).toContainText("页面加载失败");
  await expect(page.locator(".sidebar")).toBeVisible();
  await page.unroute("**/assets/services-*.js");
  await current(page).getByRole("button", { name: "重试", exact: true }).click();
  await expect(current(page).getByRole("heading", { name: "服务", exact: true })).toBeVisible();
});

test("桌面侧栏切换保留筛选，详情关闭和其他页面轮询仍隔离", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面侧栏交互");
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "t-2", name: "备用媒体" });
  await page.goto("/#/services");
  await page.getByLabel("搜索服务").fill("媒体");
  for (const name of ["媒体中心", "备用媒体", "媒体中心"]) {
    await page.getByRole("link", { name, exact: true }).click();
    await expect(page.getByRole("dialog", { name, exact: true })).toBeVisible();
    await expect(page.getByRole("tablist")).toHaveCount(0);
    await expect(page).toHaveURL(/#\/services$/);
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(page.getByLabel("搜索服务")).toHaveValue("媒体");
  }
  await page.reload();
  await expect(current(page).getByRole("heading", { name: "服务", exact: true })).toBeVisible();
  await page.locator(".sidebar").getByRole("link", { name: "设备", exact: true }).click();
  await expect(current(page).locator(".agent-row")).toHaveCount(2);
  state.calls.length = 0;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect.poll(() => state.calls.filter(call => call.path === "/api/v1/devices").length).toBe(1);
  expect(state.calls.filter(call => call.path === "/api/v1/public-domains")).toHaveLength(0);
  await page.locator(".sidebar").getByRole("link", { name: "服务", exact: true }).click();
  await expect(page).toHaveURL(/#\/services$/);
  await page.getByRole("link", { name: "备用媒体", exact: true }).click();
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await expect(editor.getByLabel("服务名称")).toHaveValue("备用媒体");
});

test("侧栏与历史导航保留搜索和滚动，刷新以地址栏为准", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面页面缓存");
  const state = await installApiMocks(page);
  state.tunnels = Array.from({ length: 120 }, (_, index) => ({ ...state.tunnels[0], id: `t-${index}`, name: `媒体 ${index}` }));
  await page.goto("/#/services");
  await page.getByLabel("搜索服务").fill("媒体");
  await page.getByLabel("类型筛选").selectOption("web");
  await page.evaluate(() => window.scrollTo(0, 350));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(350);
  await page.locator(".sidebar").getByRole("link", { name: "设备", exact: true }).click();
  await expect(current(page).getByRole("heading", { name: "设备", exact: true })).toBeFocused();
  await page.goBack();
  await expect(page).toHaveURL(/#\/services$/);
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(350);
  await expect(page.getByLabel("搜索服务")).toHaveValue("媒体");
  await expect(page.getByLabel("类型筛选")).toHaveValue("web");
  await page.goForward();
  await expect(page).toHaveURL(/#\/agents$/);
  await page.reload();
  await expect(current(page).getByRole("heading", { name: "设备", exact: true })).toBeVisible();
  await expect(page.locator(".page-slot")).toHaveCount(1);
  await page.goto("/#/workspace");
  await expect(page).toHaveURL(/#\/home$/);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole("navigation", { name: "底部导航" })).toBeVisible();
  await expect(current(page).locator("h1")).toHaveText("首页");
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.locator(".sidebar-settings")).toHaveCount(1);
  await expect(page.getByRole("tablist")).toHaveCount(0);
});

test("忽略旧页签记录，无路径进入首页且不恢复其他用户资源", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "启动路由兼容");
  await installApiMocks(page);
  await page.addInitScript(() => {
    sessionStorage.setItem("nexo:tabs:admin:default", JSON.stringify({ tabs: ["#/services", "#/agents/a-1", "#/domains"], route: "#/domains" }));
    sessionStorage.setItem("nexo:tabs:admin:alice-space", JSON.stringify({ tabs: ["#/services/private-resource"], route: "#/services/private-resource" }));
  });
  await page.goto("/");
  await expect(page).toHaveURL(/#\/home$/);
  await expect(page.locator(".page-slot")).toHaveCount(1);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator('a[href*="private-resource"]')).toHaveCount(0);
  await page.goto("/#/agents");
  await expect(page.locator(".sidebar").getByRole("link", { name: "设备", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(current(page).getByRole("heading", { name: "设备", exact: true })).toBeVisible();
  expect(await page.evaluate(() => JSON.parse(sessionStorage.getItem("nexo:tabs:admin:default")!).route)).toBe("#/domains");
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
  await expect(page.locator(".sidebar-settings")).toBeVisible();
});

test("手机常用入口与更多列表、详情返回与账号设置", async ({ page }, info) => {
  test.skip(info.project.name === "desktop-dark", "手机 App 导航");
  await installApiMocks(page);
  await page.goto("/#/services");
  const nav = page.getByRole("navigation", { name: "底部导航" });
  await expect(nav.getByRole("link")).toHaveText(["首页", "服务", "设备"]);
  await expect(page.getByRole("tablist")).toBeHidden();
  await expect(page.getByRole("navigation", { name: "面包屑" })).toBeHidden();
  await page.getByLabel("搜索服务").fill("媒体");
  await nav.getByRole("link", { name: "设备", exact: true }).click();
  await expect(nav).toBeVisible();
  await nav.getByRole("button", { name: "更多功能" }).click();
  await page.getByRole("navigation", { name: "更多功能" }).getByRole("link", { name: "域名", exact: true }).click();
  await expect(nav).toBeVisible();
  await nav.getByRole("link", { name: "服务", exact: true }).click();
  await expect(page.getByLabel("搜索服务")).toHaveValue("媒体");
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "媒体中心", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "家庭 Agent", exact: true }).click();
  await expect(current(page).locator("h1")).toHaveText("家庭 Agent");
  await page.getByRole("link", { name: "返回", exact: true }).click();
  await expect(page).toHaveURL(/#\/services$/);
  await expect(page.locator(".application-modal")).toHaveCount(0);
  await expect(page.getByLabel("搜索服务")).toHaveValue("媒体");
  await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath("mobile-glass-navigation.png") });
  await nav.getByRole("button", { name: "更多功能" }).click();
  await page.getByRole("navigation", { name: "更多功能" }).getByRole("link", { name: "账号设置", exact: true }).click();
  await expect(current(page).locator("h1")).toHaveText("我的");
  await expect(nav.getByRole("button", { name: "更多功能" })).toHaveClass("active");
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
  await page.locator(".sidebar-settings").evaluate(element => (element as HTMLAnchorElement).click());
  await expect(page).toHaveURL(/#\/services$/);
  await expect(editor.getByLabel("服务名称")).toHaveValue("跨断点草稿");
  await editor.locator(".modal-actions").getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "放弃修改", exact: true }).click();
  await page.locator(".sidebar").getByRole("link", { name: "域名", exact: true }).click();
  await expect(page).toHaveURL(/#\/domains$/);
});

test("侧栏设置键盘直达本人设置，退出失败可重试且不写入页签记录", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面设置入口");
  const state = await installApiMocks(page);
  await page.goto("/#/agents");
  const settings = page.locator(".sidebar-settings");
  await expect(settings).toHaveAccessibleName("账号设置");
  await expect(settings).toHaveAttribute("title", "账号设置");
  await settings.focus();
  await page.keyboard.press("Enter");
  await expect(current(page).getByRole("heading", { name: "账号设置", exact: true })).toBeVisible();
  await expect(current(page).locator("h1")).toBeFocused();
  await expect(settings).toHaveAttribute("aria-current", "page");
  await current(page).getByRole("link", { name: "登录会话", exact: true }).click();
  await expect(page).toHaveURL(/#\/settings\/sessions$/);
  await expect(settings).toHaveAttribute("aria-current", "page");
  await settings.click();
  await expect(page.locator(".sidebar-settings")).toHaveCount(1);
  await expect(page.locator(".account-trigger,.account-popover")).toHaveCount(0);
  state.failures.set("POST /api/v1/auth/logout", "暂时无法退出，请重试");
  await current(page).getByRole("button", { name: "退出登录", exact: true }).click();
  await expect(current(page).getByRole("alert")).toHaveText("暂时无法退出，请重试");
  await expect(page).toHaveURL(/#\/manage$/);
  state.failures.clear();
  let finishLogout!: () => void;
  const logoutReady = new Promise<void>(resolve => { finishLogout = resolve; });
  await page.route("**/api/v1/auth/logout", async route => { await logoutReady; await route.fulfill({ json: {} }); });
  await current(page).getByRole("button", { name: "退出登录", exact: true }).click();
  await expect(current(page).getByRole("button", { name: "退出中…", exact: true })).toBeDisabled();
  finishLogout();
  await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
  expect(await page.evaluate(() => Object.keys(sessionStorage).filter(key => key.startsWith("nexo:tabs:")))).toEqual([]);
});
