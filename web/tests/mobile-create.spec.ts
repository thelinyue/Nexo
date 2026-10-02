import { expect, test, type Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import { openServiceEditor } from "./service-actions";

const current = (page: Page) => page.locator(".page-slot:not([hidden])");
const createSlot = (page: Page) => page.locator(".mobile-create-slot");

for (const installed of [false, true]) {
  test(`${installed ? "PWA" : "手机浏览器"} 四类添加入口紧邻底栏，切页不残留缓存按钮`, async ({ page }, info) => {
    test.skip(info.project.name === "desktop-dark", "移动端入口矩阵");
    if (installed) await page.addInitScript(() => Object.defineProperty(navigator, "standalone", { configurable: true, value: true }));
    await installApiMocks(page);
    await page.route("**/api/v1/nodes/local", route => route.fulfill({ json: { id: "local", name: "内置节点", public_ipv4: "", control_port: 0, approved: true, enabled: true, registered: true, status: "online", latencies: [], services: [], connections: 0 } }));
    const sizes = info.project.name === "mobile-light" ? [[320, 568], [375, 812]] : info.project.name === "mobile-webkit" ? [[390, 844]] : [[812, 375]];
    for (const [width, height] of sizes) {
      await page.setViewportSize({ width, height });
      for (const colorScheme of ["light", "dark"] as const) {
        await page.emulateMedia({ colorScheme });
        await page.goto("/#/services");
        for (const [route, buttonName, dialogName] of [["services", "添加", "添加"], ["agents", "添加设备", "添加设备"], ["domains", "添加 域名", "添加域名"], ["nodes", "添加 节点", "添加节点"]]) {
          // 保留之前访问过的页面，覆盖 Portal 不受祖先 hidden 影响的情况。
          await page.evaluate(value => { location.hash = `#/${value}`; }, route);
          await expect(current(page).locator(".skeleton-list")).toHaveCount(0);
          const add = createSlot(page).getByRole("button", { name: buttonName, exact: true });
          await expect(add).toBeVisible();
          await expect(createSlot(page).getByRole("button")).toHaveCount(1);
          await expect(page.locator(".workspace-topbar .page-header")).toHaveCSS("min-height", "44px");
          const nav = (await page.locator(".bottom-nav").boundingBox())!;
          const button = (await add.boundingBox())!;
          expect(button.width).toBe(52); expect(button.height).toBe(52);
          expect(button.x - nav.x - nav.width).toBeCloseTo(8, 0);
          expect(button.y + button.height / 2).toBeCloseTo(nav.y + nav.height / 2, 0);
          expect(button.x + button.width).toBeLessThanOrEqual(width - 16);
          for (const item of await page.locator(".bottom-nav>a,.bottom-nav>button").all()) expect((await item.boundingBox())!.width).toBeGreaterThanOrEqual(44);
          expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
          if (installed) await page.screenshot({ path: info.outputPath(`${route}-${colorScheme}-${width}.png`), animations: "disabled" });
          const scroll = await page.evaluate(() => scrollY);
          await add.click();
          const dialog = page.getByRole("dialog", { name: dialogName, exact: true });
          await expect(dialog).toBeVisible();
          if (await dialog.evaluate(element => element.classList.contains("full-form"))) await expect(page.locator(".mobile-dock")).toBeHidden();
          await page.keyboard.press("Escape");
          await expect(dialog).toBeHidden();
          await expect(add).toBeFocused();
          expect(await page.evaluate(() => scrollY)).toBe(scroll);
          if (route === "nodes") {
            await expect(current(page).locator(".node-filters").getByRole("button", { name: "节点组", exact: true })).toBeVisible();
            await expect(page.locator(".workspace-topbar .page-header").getByRole("button", { name: "节点组", exact: true })).toHaveCount(0);
            if (width <= 600) {
              const status = (await page.getByLabel("筛选节点", { exact: true }).boundingBox())!;
              const groups = (await page.getByLabel("筛选节点组", { exact: true }).boundingBox())!;
              const manage = (await page.getByRole("button", { name: "节点组", exact: true }).boundingBox())!;
              expect(groups.y).toBe(status.y);
              expect(groups.width).toBeGreaterThanOrEqual(136);
              expect(manage.y).toBeGreaterThanOrEqual(groups.y + groups.height);
            }
            await current(page).getByRole("button", { name: "详情", exact: true }).first().click();
            await expect(page.getByRole("dialog")).toBeVisible();
            await expect(createSlot(page).getByRole("button")).toHaveCount(0);
            await page.keyboard.press("Escape");
            await expect(page.getByRole("dialog")).toBeHidden();
            await expect(add).toBeVisible();
          }
        }
        for (const route of ["home", "settings/sessions", "agents/a-1", "domains/d-1", "users"]) {
          await page.evaluate(value => { location.hash = `#/${value}`; }, route);
          await expect(page.getByRole("heading", { level: 1 })).toBeFocused();
          await expect(createSlot(page).getByRole("button")).toHaveCount(installed && route === "users" ? 1 : 0);
          if (route === "home" || route === "users") {
            const dock = (await page.locator(".mobile-dock").boundingBox())!;
            const nav = (await page.locator(".bottom-nav").boundingBox())!;
            expect(nav.width + (installed && route === "users" ? 60 : 0)).toBe(dock.width);
          } else await expect(page.locator(".mobile-dock")).toBeHidden();
          if (route === "users") {
            await expect(current(page).getByRole("link", { name: "返回", exact: true })).toHaveCount(0);
            await expect(page.getByRole("button", { name: "邀请用户", exact: true })).toBeVisible();
          }
        }
      }
    }
  });
}

test("空态沿用正文添加，服务多选收起底部加号", async ({ page }, info) => {
  test.skip(info.project.name === "desktop-dark", "移动端状态入口");
  const state = await installApiMocks(page, { empty: true });
  state.devices = []; state.domains = []; state.enrollments = [];
  for (const route of ["services", "agents", "domains"]) {
    await page.goto(`/#/${route}`);
    await expect(current(page).locator(".empty")).toBeVisible();
    await expect(createSlot(page).getByRole("button")).toHaveCount(0);
    await expect(current(page).locator(".empty-actions button").first()).toBeVisible();
  }
  state.tunnels = [{ id: "t-1", name: "测试服务", protocol: "tcp", local_address: "localhost", local_port: 22, enabled: true, apply_status: "ready", lan_redirect_enabled: false }];
  await page.goto("/#/services");
  await expect(createSlot(page).getByRole("button")).toHaveCount(1);
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(createSlot(page).getByRole("button")).toHaveCount(0);
  await expect(page.locator(".batch-actions")).toBeVisible();
  await page.getByRole("button", { name: "完成", exact: true }).click();
  await expect(createSlot(page).getByRole("button")).toBeVisible();
});

for (const role of ["system_admin", "tenant"] as const) {
  test(`${role} 的创建草稿跨桌面断点保留，关闭后聚焦当前添加入口`, async ({ page }, info) => {
    test.skip(info.project.name !== "mobile-light", "使用单个项目覆盖两个断点方向");
    const state = await installApiMocks(page); state.authRole = role;
    for (const [from, to] of [[375, 901], [901, 375]]) {
      await page.setViewportSize({ width: from, height: 812 });
      await page.goto("/#/services");
      await openServiceEditor(page);
      const dialog = page.getByRole("dialog", { name: "创建服务", exact: true });
      await dialog.getByLabel("服务名称", { exact: true }).fill("保留创建草稿");
      await page.setViewportSize({ width: to, height: 812 });
      await expect(dialog.getByLabel("服务名称", { exact: true })).toHaveValue("保留创建草稿");
      await page.keyboard.press("Escape");
      await page.getByRole("button", { name: "放弃修改", exact: true }).click();
      await expect(dialog).toBeHidden();
      const add = page.getByRole("button", { name: to <= 900 && role === "system_admin" ? "添加" : "创建服务", exact: true });
      await expect(add).toBeFocused();
    }
  });
}
