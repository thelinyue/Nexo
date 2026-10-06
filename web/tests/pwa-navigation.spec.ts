import { expect, test, type Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const current = (page: Page) => page.locator(".page-slot:not([hidden])");

/** 安装态标记不模拟 iOS 的系统视口；实机上抬仍需主屏幕 PWA 验收。 */
async function installedPwa(page: Page) {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "standalone", { configurable: true, value: true });
  });
}

async function geometry(page: Page) {
  return page.evaluate(() => {
    const nav = document.querySelector(".bottom-nav")!.getBoundingClientRect();
    return { x: scrollX, y: scrollY, navTop: nav.top, navBottom: nav.bottom, viewportTop: visualViewport!.offsetTop, viewportHeight: visualViewport!.height };
  });
}

/** 连续帧检查菜单开关后的稳定位置，避免只检查截图漏掉迟到的焦点滚动。 */
async function expectStable(page: Page, before: Awaited<ReturnType<typeof geometry>>) {
  for (let frame = 0; frame < 8; frame++) {
    await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => resolve())));
    const after = await geometry(page);
    for (const key of Object.keys(before) as (keyof typeof before)[]) expect(Math.abs(after[key] - before[key]), key).toBeLessThanOrEqual(1);
  }
}

test.describe("PWA 手机导航", () => {
  test.beforeEach(async ({ page }, info) => {
    test.skip(info.project.name === "desktop-dark", "触摸导航由移动端项目验收");
    await installedPwa(page);
  });

  for (const role of ["system_admin", "tenant"] as const) {
    test(`${role} 的添加入口位于底栏旁，关闭后保持滚动和焦点`, async ({ page }, info) => {
      const state = await installApiMocks(page);
      state.authRole = role;
      state.devices = Array.from({ length: 30 }, (_, index) => ({ ...state.devices[0], id: `a-${index}`, name: `设备 ${index}` }));
      state.tunnels = Array.from({ length: 40 }, (_, index) => ({ ...state.tunnels[0], id: `t-${index}`, name: `服务 ${index}` }));
      if (info.project.name === "mobile-light") await page.setViewportSize({ width: 320, height: 568 });
      for (const colorScheme of ["light", "dark"] as const) {
        await page.emulateMedia({ colorScheme });
        for (const route of ["services", "agents"] as const) {
          await page.goto(`/#/${route}`);
          await expect(current(page).locator(route === "services" ? ".service-row" : ".agent-row")).toHaveCount(route === "services" ? 40 : 30);
          const header = page.locator(".workspace-topbar .page-header");
          const add = page.locator(".mobile-create-slot").getByRole("button", { name: route === "agents" ? "添加设备" : "添加", exact: true });
          for (const position of [0, 240]) {
            await page.evaluate(value => scrollTo(0, value), position);
            await expect(add).toBeInViewport({ ratio: 1 });
            const button = (await add.boundingBox())!;
            const nav = (await page.locator(".bottom-nav").boundingBox())!;
            if (route === "services") await expect(header.locator("h1")).toHaveCSS("clip-path", "inset(50%)");
            else await expect(header.locator("h1")).toBeVisible();
            await expect(header).toHaveCSS("min-height", "44px");
            expect(button.width).toBe(52);
            expect(button.height).toBe(52);
            expect(button.x - nav.x - nav.width).toBeCloseTo(8, 0);
            expect(button.y + button.height / 2).toBeCloseTo(nav.y + nav.height / 2, 0);
            for (const item of await page.locator(".bottom-nav>a,.bottom-nav>button").all()) expect((await item.boundingBox())!.width).toBeGreaterThanOrEqual(44);
            await expect(add).toHaveCSS("backdrop-filter", "none");
            await expect(header).toHaveCSS("backdrop-filter", "none");
            expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
            const before = await geometry(page);
            expect(before.y).toBe(position);
            if (position === 0 && role === "system_admin") await page.screenshot({ path: info.outputPath(`pwa-add-${route}-${colorScheme}.png`) });
            await add.tap();
            const dialog = page.getByRole("dialog", { name: route === "agents" ? "添加设备" : "添加", exact: true });
            await expect(dialog).toBeVisible();
            await dialog.getByRole("button", { name: /^(取消|关闭)$/ }).click();
            await expect(dialog).toBeHidden();
            await expect(add).toBeFocused();
            await expectStable(page, before);
            // 从恢复的入口用键盘再次打开，确认图标按钮没有丢失焦点样式或激活能力。
            await page.keyboard.press("Enter");
            await expect(dialog).toBeVisible();
            await page.keyboard.press("Escape");
            await expect(dialog).toBeHidden();
            await expect(add).toBeFocused();
            await expect(add).toHaveCSS("outline-style", "solid");
            await expectStable(page, before);
          }
        }
      }
    });
  }

  test("短页面和更多菜单不移动底栏，管理员页面使用独立入口", async ({ page }, info) => {
    await installApiMocks(page);
    await page.goto("/#/agents");
    await expect(current(page).locator(".agent-row")).toHaveCount(2);
    const trigger = page.getByRole("button", { name: "更多功能", exact: true });
    const menu = page.locator(".mobile-more");
    const initial = await geometry(page);
    for (const [name, title] of [["域名", "域名"], ["用户管理", "用户管理"]]) {
      const before = await geometry(page);
      await trigger.tap();
      await expect(menu).toBeVisible();
      await expect(menu.locator("a>span:not(.sr-only)")).toHaveText(["节点", "域名", "用户管理", "服务器设置"]);
      await expect.poll(() => menu.evaluate(element => element.contains(document.activeElement))).toBe(false);
      await expectStable(page, before);
      await menu.getByRole("link", { name, exact: true }).tap();
      await expect(page.getByRole("heading", { level: 1 })).toHaveText(title);
      await expect(page.getByRole("heading", { level: 1 })).toBeFocused();
      await expect(menu).toBeHidden();
      await expectStable(page, initial);
      expect(await page.locator(".app-shell").evaluate(element => element.getBoundingClientRect().height >= innerHeight)).toBe(true);
    }
    await expect(page.locator(".bottom-nav")).toBeVisible();
    await trigger.tap();
    await page.locator(".pwa-account").tap();
    await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
    await expect(page.locator(".bottom-nav")).toBeVisible();
    await page.screenshot({ path: info.outputPath("pwa-account-navigation.png") });
  });

  test("长页面滚动后反复开关更多和切页返回保持位置", async ({ page }) => {
    const state = await installApiMocks(page);
    state.devices = Array.from({ length: 30 }, (_, index) => ({ ...state.devices[0], id: `a-${index}`, name: `设备 ${index}` }));
    await page.goto("/#/agents");
    await expect(current(page).locator(".agent-row")).toHaveCount(30);
    const trigger = page.getByRole("button", { name: "更多功能", exact: true });
    const menu = page.locator(".mobile-more");
    for (const position of [240, "bottom"] as const) {
      await page.evaluate(value => scrollTo(0, value === "bottom" ? document.documentElement.scrollHeight : value), position);
      const before = await geometry(page);
      expect(before.y).toBeGreaterThan(0);
      for (let repeat = 0; repeat < 2; repeat++) {
        await trigger.tap();
        await expect(menu).toBeVisible();
        await expectStable(page, before);
        await trigger.tap();
        await expect(menu).toBeHidden();
        await expectStable(page, before);
      }
      await trigger.tap();
      await expect(menu).toBeVisible();
      // 顶部操作行已移除；点击底部安全留白，避免点到滚动到顶边的设备链接。
      await page.touchscreen.tap(4, page.viewportSize()!.height - 4);
      await expect(menu).toBeHidden();
      await expectStable(page, before);
      await trigger.tap();
      await menu.getByRole("link", { name: "域名", exact: true }).tap();
      await expect(page.getByRole("heading", { level: 1 })).toHaveText("域名");
      await page.locator(".bottom-nav").getByRole("link", { name: "设备", exact: true }).tap();
      await expect(page.getByRole("heading", { level: 1 })).toHaveText("设备");
      await expectStable(page, before);
    }
  });

  test("键盘展开与取消保留可见焦点，导航后焦点交给新页面", async ({ page }) => {
    await installApiMocks(page);
    await page.goto("/#/agents");
    await expect(current(page).locator(".agent-row")).toHaveCount(2);
    const trigger = page.getByRole("button", { name: "更多功能", exact: true });
    const menu = page.locator(".mobile-more");
    await trigger.focus();
    const before = await geometry(page);
    await page.keyboard.press("Enter");
    await expect(menu.getByRole("link", { name: "节点", exact: true })).toBeFocused();
    await expect(menu.getByRole("link", { name: "节点", exact: true })).toHaveCSS("outline-style", "solid");
    await expectStable(page, before);
    await page.keyboard.press("Escape");
    await expect(menu).toBeHidden();
    await expect(trigger).toBeFocused();
    await expectStable(page, before);
    await page.keyboard.press("Enter");
    await expect(menu.getByRole("link", { name: "节点", exact: true })).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(menu.getByRole("link", { name: "域名", exact: true })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("域名");
    await expect(page.getByRole("heading", { level: 1 })).toBeFocused();
    await expectStable(page, before);
  });

  test("普通账号的更多和账号设置均不提供用户管理", async ({ page }) => {
    const state = await installApiMocks(page);
    state.authRole = "tenant";
    await page.goto("/#/manage");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("首页");
    await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
    await expect(current(page).getByRole("link", { name: "用户管理", exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "更多功能", exact: true }).tap();
    await expect(page.locator(".mobile-more").locator("a>span:not(.sr-only)")).toHaveText(["节点", "域名"]);
  });

  test("各页面顶部和更多菜单在明暗主题下不模糊背景", async ({ page }, info) => {
    await installApiMocks(page);
    for (const colorScheme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme });
      for (const route of ["home", "services", "agents", "nodes", "domains", "settings/sessions", "users"]) {
        await page.goto(`/#/${route}`);
        const header = page.locator(".workspace-topbar .page-header");
        await expect(header.locator("h1")).toHaveCSS("clip-path", ["home", "services", "nodes", "users"].includes(route) ? "inset(50%)" : "none");
        await expect(header).toHaveCSS("min-height", "44px");
        await expect(header).toHaveCSS("backdrop-filter", "none");
        for (const button of await header.locator(".icon-button").all()) await expect(button).toHaveCSS("backdrop-filter", "none");
        if (route === "users" || route === "settings/sessions") continue;
        await page.getByRole("button", { name: "更多功能", exact: true }).tap();
        const menu = page.locator(".mobile-more");
        await expect(menu).toBeVisible();
        await expect(menu).toHaveCSS("backdrop-filter", "none");
        await expect(header).toHaveCSS("backdrop-filter", "none");
        const background = await menu.evaluate(element => getComputedStyle(element).backgroundColor);
        expect(background).toMatch(/^rgb\(/);
        if (route === "domains") await page.screenshot({ path: info.outputPath(`pwa-more-${colorScheme}.png`) });
      }
    }
  });
});
