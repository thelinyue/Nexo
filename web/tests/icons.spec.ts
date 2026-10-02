import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("外部图标服务不可用时，导航、操作与状态图标在明暗主题下仍完整显示", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "单项目覆盖桌面、手机及明暗主题");
  const iconRequests: string[] = [];
  await page.route(/^https?:\/\/(?!127\.0\.0\.1(?::|\/))/, route => {
    if (/iconify\.(design|api|net)/.test(new URL(route.request().url()).hostname)) iconRequests.push(route.request().url());
    return route.abort();
  });
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], { icon_id: "border-radius/emby-1.png", apply_status: "failed", apply_error: "无法连接目标服务" });
  for (const width of [1440, 375]) {
    await page.setViewportSize({ width, height: width === 375 ? 812 : 900 });
    for (const colorScheme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
      await page.goto("/#/services");
      const nav = page.locator(width === 375 ? ".bottom-nav" : ".sidebar nav");
      await expect(nav).toBeVisible();
      for (const link of await nav.getByRole("link").all()) {
        await expect(link.locator("svg")).toBeVisible();
        await expect(link.locator("svg")).toHaveAttribute("aria-hidden", "true");
        expect(await link.locator("svg path").count()).toBeGreaterThan(0);
      }
      const card = page.locator(".page-slot:not([hidden]) .service-row").first();
      await expect(card).toBeVisible();
      await expect(card.locator(".application-icon img")).toHaveCount(0);
      await expect(card.locator(".application-icon svg")).toBeVisible();
      const badge = card.locator(".application-status svg");
      await expect(badge).toBeVisible();
      const box = await badge.boundingBox();
      expect(box?.width).toBe(14);
      expect(box?.height).toBe(14);
      await expect(page.getByRole("button", { name: width === 375 ? "添加" : "创建服务", exact: true }).locator("svg")).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
      await page.screenshot({ path: info.outputPath(`services-${width}-${colorScheme}.png`) });
      await page.goto("/#/manage");
      await page.getByRole("menuitem", { name: "修改密码", exact: true }).click();
      const dialog = page.getByRole("dialog", { name: "修改密码" });
      await expect(dialog.getByRole("button", { name: "显示密码" }).locator("svg")).toBeVisible();
      await dialog.getByRole("button", { name: "显示密码" }).click();
      await expect(dialog.getByRole("button", { name: "隐藏密码" }).locator("svg")).toBeVisible();
      await page.screenshot({ path: info.outputPath(`password-${width}-${colorScheme}.png`) });
      await dialog.getByRole("button", { name: "取消", exact: true }).click();
      await expect(dialog).toBeHidden();
    }
  }
  expect(iconRequests).toEqual([]);
});
