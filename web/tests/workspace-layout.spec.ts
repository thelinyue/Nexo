import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const activePage = (page: import("@playwright/test").Page) => page.locator(".page-slot:not([hidden])");

test("页面工具栏在桌面各宽度与主题中对齐，账号只出现一次", async ({ page }, info) => {
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
      await expect(page.locator(".account-trigger")).toHaveCount(1);
      const heading = (await activePage(page).locator("h1").boundingBox())!;
      const header = (await activePage(page).locator(".page-header").boundingBox())!;
      const account = (await page.locator(".account-trigger").boundingBox())!;
      const search = (await page.getByLabel("搜索服务").boundingBox())!;
      const filter = (await page.getByLabel("服务筛选").boundingBox())!;
      const create = (await page.getByRole("button", { name: "创建服务", exact: true }).boundingBox())!;
      expect(Math.abs(header.y + header.height / 2 - account.y - account.height / 2)).toBeLessThan(1);
      expect(search.y).toBeGreaterThanOrEqual(header.y + header.height + 12);
      const searchControl = (await page.locator(".service-toolbar .search").boundingBox())!;
      expect(Math.abs(heading.x - searchControl.x)).toBeLessThan(1);
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
  // 切换多个缓存页面后，各页仍只有一个标题和账号入口，DOM 中没有重复的 popover。
  for (const width of [901, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const [route, title] of [["home", "首页"], ["agents", "设备"], ["domains", "域名"], ["users", "用户管理"], ["manage", "账号设置"], ["settings/sessions", "登录会话"]]) {
      await page.evaluate(route => { location.hash = `#/${route}`; }, route);
      await expect(activePage(page).getByRole("heading", { level: 1 })).toHaveText(title);
      await expect(page.locator(".account-trigger")).toHaveCount(1);
      await expect(page.locator("#account-menu")).toHaveCount(1);
      await page.screenshot({ path: info.outputPath(`${route.replaceAll("/", "-")}-${width}.png`), animations: "disabled" });
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    }
  }
});

test("长标题和账号不挤出操作，账号菜单跟随入口且滚动时关闭", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面账号定位");
  const state = await installApiMocks(page);
  state.devices[0].name = "一个非常长的家庭存储设备名称".repeat(8);
  state.tunnels = Array.from({ length: 100 }, (_, index) => ({ ...state.tunnels[0], id: `t-${index}` }));
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: true, user_id: "admin", username: "很长的管理员用户名".repeat(12), role: "system_admin", workspace_id: "default", csrf_token: "test-csrf" } }));
  await page.setViewportSize({ width: 901, height: 900 });
  await page.goto("/#/agents/a-1");
  await expect(activePage(page).getByRole("heading", { level: 1 })).toHaveText(state.devices[0].name);
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.locator(".sidebar").getByRole("link", { name: "服务", exact: true }).click();
  const trigger = page.locator(".account-trigger");
  await trigger.click();
  const menu = page.locator(".account-popover");
  await expect(menu).toBeVisible();
  const triggerBox = (await trigger.boundingBox())!;
  const menuBox = (await menu.boundingBox())!;
  expect(Math.abs(menuBox.x + menuBox.width - triggerBox.x - triggerBox.width)).toBeLessThan(1);
  expect(menuBox.y).toBeGreaterThanOrEqual(triggerBox.y + triggerBox.height);
  await page.evaluate(() => window.scrollTo(0, 200));
  await expect(menu).toBeHidden();
  await page.evaluate(() => window.scrollTo(0, 0));
  await trigger.click();
  await page.setViewportSize({ width: 1199, height: 900 });
  await expect(menu).toBeHidden();
  await page.emulateMedia({ contrast: "more", reducedMotion: "reduce" });
  await trigger.click();
  await expect(menu).toHaveCSS("backdrop-filter", "none");
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
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
  await expect(page.locator(".account-trigger")).toBeVisible();
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
  await expect(page.locator(".account-trigger")).toHaveCount(1);
  await expect(page.locator(".sidebar").getByRole("link", { name: "用户管理", exact: true })).toHaveCount(0);
  expect(state.calls.some(call => call.path === "/api/v1/admin/users")).toBe(false);
});
