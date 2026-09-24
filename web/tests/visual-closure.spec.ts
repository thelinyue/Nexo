import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const cases = [
  ["phone-small", 320, 568], ["phone", 375, 812], ["phone-medium", 390, 844],
  ["phone-large", 430, 932], ["landscape", 812, 375], ["tablet", 768, 1024], ["desktop", 1440, 900],
] as const;

test("所有页面在移动尺寸和明暗主题中无溢出，输出实际截图", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "尺寸矩阵由单个项目执行");
  test.setTimeout(120000);
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "t-2", name: "一个很长很长的家庭内网服务名称", local_address: "2001:db8:abcd:1234:5678:90ab:cdef:1234", apply_status: "failed", apply_error: "无法连接本地目标，请检查 Agent 的网络连接和目标服务端口。" });
  state.tunnels.push({ ...state.tunnels[0], id: "t-3", name: "家庭 NAS", public_address: "https://nas.example.com", local_port: 5000, apply_status: "checking" });
  for (const theme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    for (const [name, width, height] of cases) {
      await page.setViewportSize({ width, height });
      for (const route of ["services", "agents", "manage", "domains", "settings", "settings/sessions", "services/t-2", "agents/a-2"]) {
        await page.goto(`/#/${route}`);
        await expect(page.locator(".page-slot:not([hidden]) h1")).toBeVisible();
        await expect(page.locator(".page-slot:not([hidden]) .skeleton-list")).toHaveCount(0);
        await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
        if (width <= 900) {
          await expect(page.locator(".bottom-nav")).toBeVisible();
          if (route === "services") {
            await expect(page.locator(".service-address code").first()).toHaveCSS("white-space", "nowrap");
            await expect(page.locator(".service-origin code").first()).toHaveCSS("white-space", "nowrap");
            const fab = await page.getByRole("button", { name: "创建服务", exact: true }).boundingBox();
            const nav = await page.locator(".bottom-nav").boundingBox();
            expect(fab!.y + fab!.height).toBeLessThanOrEqual(nav!.y);
            expect(nav!.x).toBeGreaterThanOrEqual(16);
            expect(nav!.x + nav!.width).toBeLessThanOrEqual(width - 16);
            expect(nav!.y + nav!.height).toBeLessThanOrEqual(height - 12);
          }
          if (route === "agents") await expect(page.getByText("离线", { exact: true })).toBeVisible();
        }
        await page.screenshot({ path: testInfo.outputPath(`${name}-${theme}-${route.replaceAll("/", "-")}.png`) });
      }
      await page.goto("/#/services");
      await page.getByRole("button", { name: "创建服务", exact: true }).click();
      const dialog = page.getByRole("dialog", { name: "创建服务" });
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole("button", { name: "保存服务" })).toBeInViewport();
      expect(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth)).toBeTruthy();
      await page.screenshot({ path: testInfo.outputPath(`${name}-${theme}-create.png`) });
      await page.keyboard.press("Escape");
      await page.goto("/#/agents");
      await page.getByRole("button", { name: "批准", exact: true }).click();
      await expect(page.getByRole("dialog").getByRole("button", { name: "确定" })).toBeInViewport();
      await page.screenshot({ path: testInfo.outputPath(`${name}-${theme}-approve.png`) });
      await page.keyboard.press("Escape");
    }
  }
});

test("登录与初始化在各尺寸可用", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "尺寸矩阵由单个项目执行");
  await installApiMocks(page, { anonymous: true, initialize: true });
  for (const [name, width, height] of cases) {
    await page.setViewportSize({ width, height });
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "创建管理员" })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    await page.screenshot({ path: testInfo.outputPath(`${name}-initialize.png`), fullPage: true });
    await page.getByRole("button", { name: "已有管理员账号？登录" }).click();
    await page.screenshot({ path: testInfo.outputPath(`${name}-login.png`), fullPage: true });
  }
});

test("小屏放大文字和关键触控热区", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-light", "只在触控项目中检查");
  await installApiMocks(page);
  await page.setViewportSize({ width: 320, height: 568 });
  for (const route of ["services", "agents", "manage", "domains", "settings", "settings/sessions"]) {
    await page.goto(`/#/${route}`);
    await page.addStyleTag({ content: "html { font-size: 200%; }" });
    await expect(page.locator(".page-slot:not([hidden]) .skeleton-list")).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    const buttons = page.locator(".page-slot:not([hidden]) button:visible");
    for (const button of await buttons.all()) { const box = await button.boundingBox(); expect(box!.height).toBeGreaterThanOrEqual(44); expect(box!.width).toBeGreaterThanOrEqual(44); }
    if (route === "services") {
      await page.getByRole("button", { name: "选择", exact: true }).click();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    }
  }
});
