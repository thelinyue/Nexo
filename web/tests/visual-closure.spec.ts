import { openServiceEditor } from "./service-actions";
import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const cases = [
  ["phone-small", 320, 568], ["phone", 375, 812], ["phone-medium", 390, 844],
  ["phone-large", 430, 932], ["landscape", 812, 375], ["tablet", 768, 1024], ["desktop", 1440, 900],
] as const;

test("应用图标自适应列数，图标访问与名称详情分开", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "布局检查由桌面项目执行");
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "long-address", name: "长地址服务", public_address: `https://${"very-long.".repeat(18)}example.com` });
  for (const width of [1440, 320, 375, 812]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/#/services");
    await page.getByRole("button", { name: "图标视图", exact: true }).click();
    const rows = page.locator(".page-slot:not([hidden]) .service-row");
    await expect(rows).toHaveCount(2);
    const columns = await page.locator(".service-list").evaluate(el => getComputedStyle(el).gridTemplateColumns.split(" ").length);
    if (width === 320) expect(columns).toBe(3);
    if (width === 375) expect(columns).toBe(4);
    const first = (await rows.nth(0).boundingBox())!;
    const second = (await rows.nth(1).boundingBox())!;
    expect(Math.abs(first.y - second.y)).toBeLessThan(1);
    expect(second.x).toBeGreaterThan(first.x + first.width);
    for (const row of await rows.all()) {
      await expect(row.locator(".public-address,.application-card-actions")).toHaveCount(0);
      await expect(row.getByRole("link", { name: /^打开/ })).toBeVisible();
      await expect(row.locator(".service-name")).toBeVisible();
      expect((await row.locator(".service-name").boundingBox())!.height).toBeGreaterThanOrEqual(44);
      expect((await row.boundingBox())!.x + (await row.boundingBox())!.width).toBeLessThanOrEqual(width);
    }
  }
});

test("所有页面在移动尺寸和明暗主题中无溢出，输出实际截图", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "尺寸矩阵由单个项目执行");
  test.setTimeout(120000);
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "t-2", name: "一个很长很长的家庭内网服务名称", local_address: "2001:db8:abcd:1234:5678:90ab:cdef:1234", apply_status: "failed", apply_error: "无法连接本地目标，请检查设备的网络连接和目标服务端口。" });
  state.tunnels.push({ ...state.tunnels[0], id: "t-3", name: "家庭 NAS", public_address: "https://nas.example.com", local_port: 5000, apply_status: "checking" });
  for (const theme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    for (const [name, width, height] of cases) {
      await page.setViewportSize({ width, height });
      for (const route of ["services", "agents", "manage", "domains", "settings", "settings/sessions", "services/t-2", "agents/a-2", "domains/d-1"]) {
        await page.goto(`/#/${route}`);
        if (width <= 900) await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        else { await expect(page.getByRole("heading", { level: 1 })).toBeVisible(); await expect(page.locator(".sidebar-settings")).toBeVisible(); }
        await expect(page.locator(".page-slot:not([hidden]) .skeleton-list")).toHaveCount(0);
        await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
        if (width <= 900) {
          if (!["services", "agents", "domains", "manage", "settings"].includes(route)) await expect(page.locator(".bottom-nav")).toBeHidden();
          else await expect(page.locator(".bottom-nav")).toBeVisible();
          if (route === "services") {
            await expect(page.locator(".page-slot:not([hidden]) .service-name strong").first()).toHaveCSS("-webkit-line-clamp", "2");
            await expect(page.locator(".service-address").first()).toBeHidden();
            const add = (await page.getByRole("button", { name: "添加", exact: true }).boundingBox())!;
            const nav = await page.locator(".bottom-nav").boundingBox();
            await expect(page.locator(".workspace-topbar .page-header")).toHaveCSS("min-height", "44px");
            expect(add.width).toBe(52);
            expect(add.height).toBe(52);
            expect(add.x - nav!.x - nav!.width).toBeCloseTo(8, 0);
            expect(add.y + add.height / 2).toBeCloseTo(nav!.y + nav!.height / 2, 0);
            expect(add.x + add.width).toBeLessThanOrEqual(width - 16);
            expect(nav!.x).toBeGreaterThanOrEqual(16);
            expect(nav!.x + nav!.width).toBeLessThanOrEqual(width - 16);
            expect(nav!.y + nav!.height).toBeLessThanOrEqual(height - 12);
            await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
            const lastRow = await page.locator(".page-slot:not([hidden]) .service-row").last().boundingBox();
            expect(lastRow!.y + lastRow!.height).toBeLessThanOrEqual(nav!.y);
            await page.evaluate(() => window.scrollTo(0, 0));
          }
          if (route === "agents") await expect(page.locator(".page-slot:not([hidden])").getByText("离线", { exact: true })).toBeVisible();
        }
        await page.screenshot({ path: testInfo.outputPath(`${name}-${theme}-${route.replaceAll("/", "-")}.png`) });
        if (route.startsWith("services/")) { await page.keyboard.press("Escape"); await expect(page.locator(".application-modal")).toHaveCount(0); await expect(page).toHaveURL(/#\/services$/); }
      }
      await page.goto("/#/services");
      await openServiceEditor(page);
      const dialog = page.getByRole("dialog", { name: "创建服务" });
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole("button", { name: "保存服务" })).toBeInViewport();
      expect(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth)).toBeTruthy();
      await page.screenshot({ path: testInfo.outputPath(`${name}-${theme}-create.png`) });
      await page.keyboard.press("Escape");
      await page.goto("/#/agents");
      await page.getByRole("button", { name: "批准", exact: true }).click();
      await expect(page.getByRole("dialog").getByRole("button", { name: "批准恢复" })).toBeInViewport();
      await page.screenshot({ path: testInfo.outputPath(`${name}-${theme}-approve.png`) });
      await page.keyboard.press("Escape");
    }
  }
});

test("登录与恢复在各尺寸可用", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "尺寸矩阵由单个项目执行");
  await installApiMocks(page, { anonymous: true });
  for (const [name, width, height] of cases) {
    await page.setViewportSize({ width, height });
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    await page.screenshot({ path: testInfo.outputPath(`${name}-login.png`), fullPage: true });
    await page.getByRole("button", { name: "忘记密码" }).click();
    await expect(page.getByRole("heading", { name: "找回账号" })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath(`${name}-recover.png`), fullPage: true });
  }
});

test("小屏放大文字和关键触控热区", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-light", "只在触控项目中检查");
  await installApiMocks(page);
  await page.setViewportSize({ width: 320, height: 568 });
  for (const route of ["services", "agents", "manage", "domains", "settings", "settings/sessions"]) {
    await page.goto(`/#/${route}`);
    await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
    await expect(page.locator(".page-slot:not([hidden]) .skeleton-list")).toHaveCount(0);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    const buttons = page.locator(".page-slot:not([hidden]) button:visible");
    for (const button of await buttons.all()) { const box = await button.boundingBox(); expect(box!.height).toBeGreaterThanOrEqual(44); expect(box!.width).toBeGreaterThanOrEqual(44); }
    if (route === "services") {
      await page.getByRole("button", { name: "选择", exact: true }).focus();
      await page.getByRole("button", { name: "选择", exact: true }).press("Space");
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
      const label = (await page.locator(".service-row .check").first().boundingBox())!;
      expect(label.width).toBe(44);
      expect(label.height).toBe(44);
      expect(await page.locator(".service-list").evaluate(el => getComputedStyle(el).gridTemplateColumns.split(" ").length)).toBeLessThan(3);
    }
  }
});
