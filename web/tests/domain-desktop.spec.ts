import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("域名提交期间锁定取消和关闭，失败后恢复操作并保留输入", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面关闭入口");
  await installApiMocks(page);
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/api/v1/public-domains", async route => {
    if (route.request().method() !== "POST") return route.fallback();
    await pending;
    await route.fulfill({ status: 409, json: { error: "域名已存在" } });
  });
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "添加 域名", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "添加域名", exact: true });
  const input = dialog.getByLabel("域名", { exact: true });
  await input.fill("example.com");
  await dialog.getByRole("button", { name: "添加域名", exact: true }).click();
  try {
    await expect(dialog.getByRole("button", { name: "取消", exact: true })).toBeDisabled();
    await expect(dialog.getByRole("button", { name: "关闭", exact: true })).toBeDisabled();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeVisible();
    await expect(page.getByRole("dialog", { name: "放弃未保存的修改？" })).toHaveCount(0);
  } finally { release(); }
  await expect(dialog.getByRole("alert")).toContainText("域名已存在");
  await expect(input).toHaveValue("example.com");
  await expect(dialog.getByRole("button", { name: "取消", exact: true })).toBeEnabled();
  await expect(dialog.getByRole("button", { name: "关闭", exact: true })).toBeEnabled();
});

for (const colorScheme of ["light", "dark"] as const) {
  for (const viewport of [{ width: 1280, height: 800 }, { width: 1896, height: 940 }]) {
    test(`桌面域名页与短表单 ${colorScheme} ${viewport.width}`, async ({ page }, testInfo) => {
      test.skip(testInfo.project.name !== "desktop-dark", "桌面尺寸与主题在此独立覆盖");
      await page.setViewportSize(viewport);
      await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
      const state = await installApiMocks(page);
      await page.goto("/#/domains");
      const content = page.locator(".page-slot:not([hidden])");
      await expect(content.locator(".domain-row")).toHaveCount(1);
      await expect(content.getByRole("heading", { name: "域名", exact: true })).toBeAttached();
      await expect(content.getByRole("button", { name: "添加 域名", exact: true })).toBeInViewport();
      await page.screenshot({ path: testInfo.outputPath("domains-list.png") });

      state.domains.length = 0;
      await page.reload();
      const empty = content.locator(".empty");
      await expect(empty.getByRole("heading", { name: "还没有域名" })).toBeVisible();
      const bounds = (await empty.boundingBox())!;
      const panel = (await content.boundingBox())!;
      expect(bounds.height).toBeGreaterThan(panel.height * .7);
      expect(await empty.evaluate(element => getComputedStyle(element).borderTopWidth)).toBe("0px");
      const add = content.getByRole("button", { name: "添加 域名", exact: true });
      const action = (await add.boundingBox())!;
      expect(action.width).toBeLessThan(180);
      expect(Math.abs(action.x + action.width / 2 - (panel.x + panel.width / 2))).toBeLessThan(2);
      await page.screenshot({ path: testInfo.outputPath("domains-empty.png") });

      await add.click();
      const dialog = page.getByRole("dialog", { name: "添加域名", exact: true });
      const input = dialog.getByLabel("域名", { exact: true });
      const save = dialog.getByRole("button", { name: "添加域名", exact: true });
      await expect(dialog).toBeVisible();
      const modal = (await dialog.boundingBox())!;
      expect(modal.width).toBeLessThanOrEqual(460);
      expect(modal.height).toBeLessThan(280);
      expect(Math.abs(modal.x + modal.width / 2 - viewport.width / 2)).toBeLessThan(2);
      expect(Math.abs(modal.y + modal.height / 2 - viewport.height / 2)).toBeLessThan(2);
      await expect(input).toBeInViewport();
      await expect(save).toBeInViewport();
      expect((await save.boundingBox())!.width).toBeLessThan(180);
      const title = (await dialog.getByRole("heading", { name: "添加域名" }).boundingBox())!;
      const field = (await dialog.locator(".domain-input-control").boundingBox())!;
      const button = (await save.boundingBox())!;
      const cancel = dialog.getByRole("button", { name: "取消", exact: true });
      await expect(dialog.locator(".modal-heading").getByRole("button", { name: "取消" })).toHaveCount(0);
      await expect(dialog.getByRole("button", { name: "关闭", exact: true })).toBeInViewport();
      const secondary = (await cancel.boundingBox())!;
      expect(Math.abs(secondary.y - button.y)).toBeLessThan(1);
      expect(secondary.x + secondary.width).toBeLessThan(button.x);
      expect(Math.abs(title.x - field.x)).toBeLessThan(1);
      expect(Math.abs(field.x + field.width - button.x - button.width)).toBeLessThan(1);
      await page.screenshot({ path: testInfo.outputPath("domain-add.png") });
      await dialog.screenshot({ path: testInfo.outputPath("domain-add-dialog.png") });

      for (const action of ["取消", "关闭"]) {
        await dialog.getByRole("button", { name: action, exact: true }).click();
        await expect(dialog).toBeHidden();
        await expect(add).toBeFocused();
        await add.click();
        await input.fill("draft.example.com");
        await dialog.getByRole("button", { name: action, exact: true }).click();
        const discard = page.getByRole("dialog", { name: "放弃未保存的修改？" });
        await expect(discard).toBeVisible();
        await discard.getByRole("button", { name: "取消", exact: true }).click();
        await expect(input).toHaveValue("draft.example.com");
        await expect(dialog.getByRole("button", { name: action, exact: true })).toBeFocused();
        await input.fill("");
      }

      await save.click();
      await expect(input).toBeFocused();
      await expect(dialog.getByRole("alert")).toBeInViewport();
      await input.fill("https://example.com/a-long-path");
      await expect(dialog.getByRole("button", { name: "仅使用 example.com" })).toBeInViewport();
      await expect(save).toBeInViewport();
      expect(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth)).toBeTruthy();
      await page.screenshot({ path: testInfo.outputPath("domain-add-correction.png") });
      await input.fill("example.com");
      await page.keyboard.press("Escape");
      const confirmation = page.getByRole("dialog", { name: "放弃未保存的修改？" });
      await expect(confirmation).toBeVisible();
      await confirmation.getByRole("button", { name: "放弃修改", exact: true }).click();
      await expect(dialog).toBeHidden();
      await expect(add).toBeFocused();
      expect(state.calls.filter(call => call.method === "POST")).toHaveLength(0);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    });
  }
}
