import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const activePage = (page: import("@playwright/test").Page) => page.locator(".page-slot:not([hidden])");

test("页面工具栏从首行开始，桌面账号入口只出现一次", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面布局矩阵");
  const state = await installApiMocks(page);
  const names = ["bit2", "emby", "dockge", "qb", "dc", "lucky", "danmu", "tag", "flowlink", "mp", "ik", "music", "siyuan", "paper", "clash", "onenav", "sing", "v", "ck", "huddletab", "emby2", "bit"];
  state.tunnels = names.map((name, index) => ({ ...state.tunnels[0], id: `t-${index}`, name }));
  for (const theme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: theme });
    for (const width of [901, 1199, 1200, 1440, 2560]) {
      await page.setViewportSize({ width, height: 900 });
      await page.goto("/#/services");
      await expect(activePage(page).locator(".service-row")).toHaveCount(names.length);
      await expect(page.getByRole("tablist")).toHaveCount(0);
      await expect(page.locator(".sidebar-settings")).toHaveCount(1);
      await expect(activePage(page).locator("h1")).toHaveCSS("clip-path", "inset(50%)");
      await expect(activePage(page).locator(".page-header")).toHaveCSS("height", "0px");
      const settings = (await page.locator(".sidebar-settings").boundingBox())!;
      const search = (await page.getByLabel("搜索服务").boundingBox())!;
      const filter = (await page.getByLabel("服务筛选").boundingBox())!;
      const create = (await page.getByRole("button", { name: "创建服务", exact: true }).boundingBox())!;
      const navigationRow = (await page.getByRole("navigation", { name: "主导航" }).getByRole("link").first().boundingBox())!;
      const avatar = (await page.locator(".sidebar-settings img").boundingBox())!;
      expect(settings.x).toBe(navigationRow.x); expect(settings.width).toBe(navigationRow.width);
      expect(settings.height).toBeGreaterThanOrEqual(56);
      expect(avatar.width).toBe(32); expect(avatar.height).toBe(32);
      expect(settings.y + settings.height).toBe(876);
      const searchControl = (await page.locator(".service-toolbar .search").boundingBox())!;
      const contentTop = await activePage(page).evaluate(element => element.getBoundingClientRect().top + parseFloat(getComputedStyle(element).borderTopWidth) + parseFloat(getComputedStyle(element).paddingTop));
      expect(Math.abs(contentTop - searchControl.y)).toBeLessThan(1);
      expect(Math.abs(searchControl.y - create.y)).toBeLessThan(1);
      if (width >= 1200) expect(Math.abs(filter.y - searchControl.y)).toBeLessThan(1);
      else expect(filter.y).toBeGreaterThanOrEqual(search.y + search.height);
      expect(create.x + create.width).toBeLessThanOrEqual(width - 24);
      // 原生 select 会无提示截断选中值，除了页面不溢出，还要给默认标签和箭头留足空间。
      for (const select of await page.locator(".service-filter-control select").all()) {
        expect(await select.evaluate(element => {
          const control = element as HTMLSelectElement; const style = getComputedStyle(control);
          const context = document.createElement("canvas").getContext("2d")!; context.font = style.font;
          return control.clientWidth >= context.measureText(control.selectedOptions[0].text).width + parseFloat(style.paddingLeft) + parseFloat(style.paddingRight) + 20;
        })).toBeTruthy();
      }
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
      await page.screenshot({ path: info.outputPath(`services-${theme}-${width}.png`), animations: "disabled" });
    }
  }
  // 页面缓存保留读屏标题；本人账号菜单只由外壳挂载一次。
  for (const width of [901, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const [route, title] of [["home", "首页"], ["agents", "设备"], ["nodes", "节点"], ["domains", "域名"], ["users", "用户管理"], ["settings/sessions", "登录会话"]]) {
      await page.evaluate(route => { location.hash = `#/${route}`; }, route);
      await expect(activePage(page).getByRole("heading", { level: 1 })).toHaveText(title);
      await expect(activePage(page).locator("h1")).toHaveCSS("clip-path", route === "settings/sessions" ? "none" : "inset(50%)");
      await expect(activePage(page).locator("h1")).toBeFocused();
      await expect(page.locator(".sidebar-settings")).toHaveCount(1);
      await expect(page.locator(".account-menu")).toHaveCount(1);
      if (route !== "settings/sessions") await expect(activePage(page).locator(".page-header")).toHaveCSS("height", "0px");
      await page.screenshot({ path: info.outputPath(`${route.replaceAll("/", "-")}-${width}.png`), animations: "disabled" });
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    }
  }
});

test("长标题保持可读，矮窗口导航独立滚动且账号菜单始终可达", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面侧栏定位");
  const state = await installApiMocks(page);
  state.devices[0].name = "一个非常长的家庭存储设备名称".repeat(8);
  state.tunnels = Array.from({ length: 100 }, (_, index) => ({ ...state.tunnels[0], id: `t-${index}` }));
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: true, user_id: "admin", username: "很长的管理员用户名".repeat(12), role: "system_admin", workspace_id: "default", csrf_token: "test-csrf" } }));
  await page.setViewportSize({ width: 901, height: 900 });
  await page.goto("/#/agents/a-1");
  await expect(activePage(page).getByRole("heading", { level: 1 })).toHaveText(state.devices[0].name);
  await expect(activePage(page).locator("h1")).toHaveCSS("clip-path", "none");
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.locator(".sidebar").getByRole("link", { name: "服务", exact: true }).click();
  const settings = page.locator(".sidebar-settings");
  await expect(settings.locator("img")).toHaveAttribute("data-avatar-role", "admin");
  await expect(settings.locator("strong")).toHaveAttribute("title", "很长的管理员用户名".repeat(12));
  await page.setViewportSize({ width: 901, height: 375 });
  await page.emulateMedia({ contrast: "more", reducedMotion: "reduce" });
  await page.evaluate(() => { document.documentElement.style.fontSize = "24px"; });
  const before = (await settings.boundingBox())!;
  const nav = page.getByRole("navigation", { name: "主导航" });
  expect(await nav.evaluate(element => element.scrollHeight > element.clientHeight)).toBe(true);
  await nav.evaluate(element => { element.scrollTop = element.scrollHeight; });
  await page.evaluate(() => window.scrollTo(0, 200));
  await expect(settings).toBeInViewport({ ratio: 1 });
  expect(await settings.boundingBox()).toEqual(before);
  await nav.getByRole("link").last().focus();
  await page.keyboard.press("Tab");
  await expect(settings).toBeFocused();
  await expect(settings).toHaveCSS("outline-style", "solid");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#\/services$/);
  await expect(settings).toHaveAttribute("data-selected", "true");
  const menu = page.getByRole("menu", { name: "本人账号", exact: true });
  await expect(menu).toBeVisible();
  await expect(menu.locator(".account-menu-identity strong")).toHaveText("很长的管理员用户名".repeat(12));
  const menuBox = (await menu.boundingBox())!;
  // 用户名完整换行后可能高于头像上方的空间；此时约束整个视口并允许菜单内部滚动。
  if (menuBox.height + 8 <= before.y - 16) expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(before.y);
  else expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(page.viewportSize()!.height - 16);
  expect(menuBox.y).toBeGreaterThanOrEqual(16);
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("settings-short-large-text.png"), animations: "disabled" });
});

test("工具栏覆盖空状态、错误、无搜索结果和批量选择", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面状态布局");
  const state = await installApiMocks(page, { empty: true });
  await page.setViewportSize({ width: 901, height: 900 });
  await page.goto("/#/services");
  await expect(activePage(page).locator(".empty")).toBeVisible();
  await expect(activePage(page).locator(".page-toolbar-actions")).toHaveCount(0);
  state.failures.set("GET /api/v1/tunnels", "无法连接服务，请稍后重试");
  await page.reload();
  await expect(activePage(page).getByText("无法连接服务，请稍后重试", { exact: true })).toBeVisible();
  await expect(page.locator(".sidebar-settings")).toBeVisible();
  state.failures.clear();
  state.tunnels = [{ id: "t-1", name: "家庭媒体服务", protocol: "https", local_address: "localhost", local_port: 8096, enabled: true, apply_status: "ready", lan_redirect_enabled: false }];
  await page.reload();
  await page.getByLabel("搜索服务").fill("不存在的服务");
  await expect(activePage(page).locator(".empty")).toBeVisible();
  await page.getByLabel("搜索服务").fill("");
  await page.getByRole("button", { name: "选择", exact: true }).click();
  await expect(page.getByRole("button", { name: "创建服务", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "完成", exact: true })).toBeVisible();
  await expect(activePage(page).getByRole("heading", { level: 1 })).toHaveText("服务");
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
});

test("普通账号直达管理页时仍有标题和账号入口，但不能访问用户管理", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面权限提示");
  const state = await installApiMocks(page); state.authRole = "tenant";
  await page.goto("/#/users");
  await expect(activePage(page).getByRole("heading", { level: 1 })).toHaveText("用户管理");
  await expect(activePage(page).getByRole("alert")).toHaveText("此页面需要管理员权限");
  await expect(page.locator(".sidebar-settings")).toHaveCount(1);
  await expect(page.locator(".sidebar").getByRole("link", { name: "用户管理", exact: true })).toHaveCount(0);
  expect(state.calls.some(call => call.path === "/api/v1/admin/users")).toBe(false);
});
