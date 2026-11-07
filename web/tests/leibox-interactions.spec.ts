import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

async function frames(page: Page, count = 3) {
  await page.evaluate(count => new Promise<void>(resolve => {
    const next = () => { if (--count <= 0) resolve(); else requestAnimationFrame(next); };
    requestAnimationFrame(next);
  }), count);
}

async function switchView(page: Page, label: "列表视图" | "图标视图") {
  // 不等待元素稳定，覆盖用户在上一次布局动画结束前再次操作的情况。
  await page.getByRole("button", { name: label, exact: true }).evaluate((button: HTMLButtonElement) => button.click());
  await frames(page);
}

test("手机选中块跟随真实路由，更多连续开关不移动底座和添加按钮", async ({ page }, info) => {
  test.skip(info.project.name === "desktop-dark", "手机底栏动效");
  await installApiMocks(page);
  await page.goto("/#/services");
  const nav = page.getByRole("navigation", { name: "底部导航", exact: true });
  const indicator = nav.locator(".bottom-nav-indicator");
  await expect(indicator).toBeVisible();
  const dock = (await page.locator(".mobile-dock").boundingBox())!;
  const create = (await page.locator(".mobile-create-slot").boundingBox())!;
  await nav.getByRole("link", { name: "设备", exact: true }).evaluate((link: HTMLAnchorElement) => link.click());
  await frames(page);
  await expect(nav).toHaveAttribute("data-moving", "true");
  await expect(nav).toHaveAttribute("data-moving", "false");
  const current = (await nav.getByRole("link", { name: "设备", exact: true }).boundingBox())!;
  const selection = (await indicator.boundingBox())!;
  expect(Math.abs(selection.x - current.x)).toBeLessThan(1);
  expect(Math.abs(selection.width - current.width)).toBeLessThan(1);
  const trigger = nav.getByRole("button", { name: "更多功能", exact: true });
  const menu = page.locator(".mobile-more");
  for (const open of [true, false, true]) {
    await trigger.evaluate((button: HTMLButtonElement) => button.click());
    await frames(page);
    expect(await menu.evaluate(element => element.matches(":popover-open"))).toBe(open);
    expect(await menu.evaluate(element => (element as HTMLElement).inert)).toBe(!open);
    const next = (await page.locator(".mobile-dock").boundingBox())!;
    const nextCreate = (await page.locator(".mobile-create-slot").boundingBox())!;
    expect(Math.abs(next.y - dock.y)).toBeLessThan(1);
    expect(Math.abs(nextCreate.x - create.x)).toBeLessThan(1);
    expect(Math.abs(nextCreate.y - create.y)).toBeLessThan(1);
  }
  await expect(menu).toHaveAttribute("data-moving", "false");
  await menu.getByRole("link", { name: "域名", exact: true }).click();
  await expect(page).toHaveURL(/#\/domains$/);
  await expect(page.getByRole("heading", { level: 1 })).toBeFocused();
  await expect(trigger).toHaveClass("active");
  await expect(nav).toHaveAttribute("data-moving", "false");
  await trigger.click();
  await expect(menu).toHaveCSS("opacity", "1");
  await expect(menu).toHaveAttribute("data-moving", "false");
  await expect(menu).toHaveCSS("backdrop-filter", "none");
  await page.screenshot({ path: info.outputPath("leibox-navigation-more.png"), scale: "css" });
});

test("真实服务元素连续切换，复用 DOM、选择和显示偏好且不写配置", async ({ page }, info) => {
  const state = await installApiMocks(page);
  state.tunnels = Array.from({ length: 8 }, (_, index) => ({ ...state.tunnels[0], id: `morph-${index}`, name: `家庭应用 ${index + 1}` }));
  await page.goto("/#/services");
  const list = page.locator(".service-list");
  await expect(list.locator(".service-row")).toHaveCount(8);
  await page.evaluate(() => {
    const row = document.querySelector(".service-row")!;
    (window as any).leiboxOriginal = { row, icon: row.querySelector(".application-icon"), name: row.querySelector(".service-name") };
  });
  await switchView(page, "图标视图");
  await expect(list).toHaveAttribute("data-moving", "true");
  expect(await list.locator(".application-launch").evaluateAll(elements => elements.some(element => (element as HTMLElement).style.transform !== ""))).toBe(true);
  await switchView(page, "列表视图");
  await switchView(page, "图标视图");
  await expect(list).toHaveAttribute("data-moving", "false");
  expect(await page.evaluate(() => {
    const original = (window as any).leiboxOriginal;
    const row = document.querySelector(".service-row")!;
    return row === original.row && row.querySelector(".application-icon") === original.icon && row.querySelector(".service-name") === original.name;
  })).toBe(true);
  expect(await list.locator(".application-launch,.service-identity").evaluateAll(elements => elements.every(element => !(element as HTMLElement).style.transform))).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(state.calls.filter(call => ["POST", "PUT", "PATCH", "DELETE"].includes(call.method))).toHaveLength(0);
  await page.screenshot({ path: info.outputPath("leibox-service-icons.png"), scale: "css" });
  await page.reload();
  await expect(list).toHaveAttribute("data-view", "icons");
  await switchView(page, "列表视图");
  await expect(list).toHaveAttribute("data-moving", "false");
  await page.screenshot({ path: info.outputPath("leibox-service-list.png"), scale: "css" });
});

test("减少动画和断点变化立即释放 JS 动画，后台页面不继续变换", async ({ page }, info) => {
  const state = await installApiMocks(page);
  state.tunnels = Array.from({ length: 6 }, (_, index) => ({ ...state.tunnels[0], id: `reduce-${index}`, name: `媒体 ${index}` }));
  await page.goto("/#/services");
  const list = page.locator(".service-list");
  await expect(list.locator(".service-row")).toHaveCount(6);
  await switchView(page, "图标视图");
  await expect(list).toHaveAttribute("data-moving", "true");
  await page.emulateMedia({ reducedMotion: "reduce", contrast: "more" });
  await expect(list).toHaveAttribute("data-moving", "false");
  await switchView(page, "列表视图");
  await expect(list).toHaveAttribute("data-moving", "false");
  expect(await list.locator(".application-launch,.service-identity").evaluateAll(elements => elements.every(element => !(element as HTMLElement).style.transform))).toBe(true);
  if (info.project.name !== "desktop-dark") {
    const nav = page.locator(".bottom-nav");
    await nav.getByRole("button", { name: "更多功能", exact: true }).click();
    await expect(nav).toHaveAttribute("data-moving", "false");
    await expect(page.locator(".mobile-more")).toHaveAttribute("data-moving", "false");
    await expect(nav).toHaveCSS("backdrop-filter", "none");
    await page.keyboard.press("Escape");
  }
  await page.emulateMedia({ reducedMotion: "no-preference", contrast: "no-preference" });
  await switchView(page, "图标视图");
  await page.setViewportSize({ width: info.project.name === "desktop-dark" ? 800 : 1000, height: 800 });
  await expect(list).toHaveAttribute("data-moving", "false");
  await switchView(page, "列表视图");
  await page.evaluate(() => { location.hash = "#/agents"; });
  await expect(list).toBeHidden();
  await expect(list).toHaveAttribute("data-moving", "false");
  expect(await list.locator(".application-launch,.service-identity").evaluateAll(elements => elements.every(element => !(element as HTMLElement).style.transform))).toBe(true);
});

test("动画中打开详情及刷新大量服务不留下变换或重复条目", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels = Array.from({ length: 120 }, (_, index) => ({ ...state.tunnels[0], id: `many-${index}`, name: `服务 ${index}` }));
  await page.goto("/#/services");
  const list = page.locator(".service-list");
  await expect(list.locator(".service-row")).toHaveCount(120);
  await switchView(page, "图标视图");
  await list.getByRole("link", { name: "服务 0", exact: true }).evaluate((link: HTMLAnchorElement) => link.click());
  await expect(page.getByRole("dialog", { name: "服务 0", exact: true })).toBeVisible();
  await expect(list).toHaveAttribute("data-moving", "false");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await switchView(page, "列表视图");
  state.tunnels = state.tunnels.slice(1);
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(list.locator(".service-row")).toHaveCount(119);
  await expect(list).toHaveAttribute("data-moving", "false");
  await expect(list.getByRole("link", { name: "服务 0", exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByLabel("搜索服务", { exact: true }).fill("不存在的应用");
  await expect(page.getByRole("heading", { name: "没有匹配的服务", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "清除筛选", exact: true }).click();
  await expect(list.locator(".service-row")).toHaveCount(119);
  await switchView(page, "图标视图");
  await expect(list).toHaveAttribute("data-moving", "false");
});

test("320px 明暗主题、减少透明度与双倍字号仍保留完整操作", async ({ page }, info) => {
  test.skip(info.project.name !== "mobile-light", "窄屏和辅助功能矩阵集中验收");
  await page.setViewportSize({ width: 320, height: 568 });
  const state = await installApiMocks(page);
  state.tunnels = Array.from({ length: 8 }, (_, index) => ({ ...state.tunnels[0], id: `small-${index}`, name: `家庭应用 ${index + 1}` }));
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.goto("/#/services");
  await expect(page.locator(".service-row")).toHaveCount(8);
  await switchView(page, "图标视图");
  await expect(page.locator(".service-list")).toHaveAttribute("data-moving", "false");
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme });
    await page.getByRole("button", { name: "更多功能", exact: true }).click();
    await expect(page.locator(".mobile-more")).toHaveCSS("opacity", "1");
    await expect(page.locator(".mobile-more")).toHaveAttribute("data-moving", "false");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath(`leibox-320-${colorScheme}-more.png`), scale: "css" });
    await page.keyboard.press("Escape");
    await expect(page.locator(".mobile-more")).toBeHidden();
  }
  const session = await page.context().newCDPSession(page);
  await session.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-transparency", value: "reduce" }] });
  expect(await page.evaluate(() => matchMedia("(prefers-reduced-transparency: reduce)").matches)).toBe(true);
  await expect(page.locator(".bottom-nav")).toHaveCSS("backdrop-filter", "none");
  await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
  await switchView(page, "列表视图");
  await expect(page.locator(".service-list")).toHaveAttribute("data-moving", "false");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  for (const item of await page.locator(".bottom-nav > a,.bottom-nav > button").all()) expect((await item.boundingBox())!.width).toBeGreaterThanOrEqual(44);
  await page.screenshot({ path: info.outputPath("leibox-320-large-text-solid.png"), scale: "css" });
  expect(errors).toEqual([]);
});
