import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("名称打开详情浮层，背景与网址不变，关闭恢复焦点", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels = Array.from({ length: 24 }, (_, i) => ({ ...state.tunnels[0], id: `t-${i}`, name: `媒体 ${i}` }));
  await page.goto("/#/services");
  await page.getByLabel("搜索服务").fill("媒体");
  const trigger = page.getByRole("link", { name: "媒体 16", exact: true });
  await trigger.evaluate(el => el.scrollIntoView({ block: "center" }));
  const scroll = await page.evaluate(() => scrollY);
  await trigger.click();
  const modal = page.getByRole("dialog", { name: "媒体 16", exact: true });
  await expect(modal).toHaveCSS("opacity", "1");
  await expect(page).toHaveURL(/#\/services$/);
  const box = (await modal.boundingBox())!;
  expect(box.x).toBeGreaterThanOrEqual(16);
  expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize()!.width - 16);
  expect(box.height).toBeLessThanOrEqual(page.viewportSize()!.height * .85 + 1);
  expect(box.y).toBeGreaterThanOrEqual(0);
  expect(box.y + box.height).toBeLessThanOrEqual(page.viewportSize()!.height);
  await modal.getByRole("button", { name: "关闭", exact: true }).focus();
  await page.keyboard.press("Shift+Tab");
  expect(await modal.evaluate(el => el.contains(document.activeElement))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(modal).toHaveCount(0);
  await expect(trigger).toBeFocused();
  await expect(page.getByLabel("搜索服务")).toHaveValue("媒体");
  expect(await page.evaluate(() => scrollY)).toBeCloseTo(scroll, 0);
});

test("编辑保存与放弃草稿回到详情原滚动位置", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  const detail = page.locator(".application-modal");
  await detail.getByRole("button", { name: "编辑服务" }).scrollIntoViewIfNeeded();
  const scroll = await detail.locator(".modal-body").evaluate(el => el.scrollTop);
  await detail.getByRole("button", { name: "编辑服务" }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await expect(detail).toHaveCount(0);
  await editor.getByLabel("服务名称", { exact: true }).fill("新的名称");
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "放弃修改", exact: true }).click();
  await expect(detail.getByRole("heading", { name: "媒体中心", exact: true })).toBeVisible();
  await expect.poll(() => detail.locator(".modal-body").evaluate(el => el.scrollTop)).toBeCloseTo(scroll, 0);
  await detail.getByRole("button", { name: "编辑服务" }).click();
  await editor.getByLabel("服务名称", { exact: true }).fill("新的名称");
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(detail.getByRole("heading", { name: "新的名称", exact: true })).toBeVisible();
  await expect(detail.getByRole("status")).toHaveText("配置已保存");
});

test("详情继续刷新，编辑暂停刷新，启停错误留在弹窗", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services");
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  const detail = page.locator(".application-modal");
  await expect(detail.locator(".application-summary .status")).toHaveText("运行中");
  state.tunnels[0].apply_status = "checking";
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  // focus 可能与打开详情时的请求重合，允许下一次 5 秒轮询显示新状态。
  await expect(detail.locator(".application-summary .status")).toHaveText("检查中", { timeout: 8000 });
  state.failures.set("POST /api/v1/tunnels/t-1/disable", "暂时无法关闭");
  await detail.getByRole("button", { name: "关闭服务" }).click();
  await expect(detail.getByRole("alert")).toContainText("暂时无法关闭");
  await detail.getByRole("button", { name: "编辑服务" }).click();
  await expect(page.getByRole("dialog", { name: "编辑服务" })).toBeVisible();
  state.calls.length = 0;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await page.waitForTimeout(150);
  expect(state.calls.filter(call => call.method === "GET" && call.path === "/api/v1/tunnels")).toHaveLength(0);
});

test("删除可取消，成功后关闭并恢复列表搜索焦点", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "other", name: "备用" });
  await page.goto("/#/services");
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  const detail = page.locator(".application-modal");
  await detail.getByRole("button", { name: "删除服务" }).click();
  const confirm = page.getByRole("dialog", { name: "删除 媒体中心？" });
  await confirm.getByRole("button", { name: "取消" }).click();
  await expect(detail).toBeVisible();
  await detail.getByRole("button", { name: "删除服务" }).click();
  await confirm.getByRole("button", { name: "删除服务" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "媒体中心", exact: true })).toHaveCount(0);
  await expect(page.getByLabel("搜索服务")).toBeFocused();
});

test("旧详情地址关闭回列表，关联 Agent 导航只执行一次", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services/t-1");
  const detail = page.locator(".application-modal");
  await detail.getByRole("button", { name: "关闭", exact: true }).click();
  await expect(page).toHaveURL(/#\/services$/);
  const list = page.locator('[id="page-%23%2Fservices"]');
  await expect(list).toBeVisible();
  await list.getByRole("link", { name: "媒体中心", exact: true }).click();
  await detail.getByRole("link", { name: "家庭 Agent", exact: true }).click();
  await expect(page).toHaveURL(/#\/agents\/a-1$/);
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("快速关闭、遮罩关闭、减少动画和应用内返回均释放浮层", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/home");
  await page.goto("/#/services");
  const trigger = page.getByRole("link", { name: "媒体中心", exact: true });
  for (const method of ["escape", "backdrop", "back"]) {
    await trigger.click();
    await expect(page.locator("dialog[open]")).toHaveCount(1);
    if (method === "escape") await page.keyboard.press("Escape");
    else if (method === "backdrop") await page.mouse.click(2, 2);
    else await page.goBack();
    await expect(page.locator("dialog[open]")).toHaveCount(0);
    await expect(page).toHaveURL(/#\/services$/);
    await expect(trigger).toBeFocused();
    await page.emulateMedia({ reducedMotion: "reduce" });
  }
});

test("来源被刷新删除后自动关闭，不返回已删除的入口", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "other", name: "备用" });
  await page.goto("/#/services");
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  await expect(page.locator(".application-modal")).toHaveCSS("opacity", "1");
  state.tunnels.splice(0, 1);
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.locator(".application-modal")).toHaveCount(0);
  await expect(page.getByLabel("搜索服务")).toBeFocused();
});

test("长名称、IPv6 与放大字号在小屏和横屏均可操作，缩放后仍能关闭", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "尺寸与字号矩阵集中验收");
  test.setTimeout(60000);
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], { name: "一个很长的家庭媒体服务应用名称", ipv6_direct_enabled: true, apply_status: "failed", apply_error: "无法连接内网服务，请检查 Agent。", direct_status: { status: "configured", address: "2001:db8:1234:5678:abcd:ef00:1234:5678", public_reachability: "unverified" } });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/#/services");
  for (const [width, height] of [[320, 568], [390, 844], [812, 375], [1440, 900]]) {
    await page.setViewportSize({ width, height });
    for (const size of ["100%", "200%"]) {
      await page.evaluate(size => { document.documentElement.style.fontSize = size; }, size);
      await page.getByRole("link", { name: state.tunnels[0].name, exact: true }).click();
      const modal = page.locator(".application-modal");
      await expect(modal).toHaveCSS("opacity", "1");
      expect(await modal.evaluate(el => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
      await expect(modal.getByRole("button", { name: "关闭", exact: true })).toBeInViewport({ ratio: 1 });
      await expect(modal).toContainText("已配置，公网未验证");
      for (const name of ["编辑服务", "关闭服务", "删除服务"]) {
        const button = modal.getByRole("button", { name, exact: true });
        await button.scrollIntoViewIfNeeded();
        await expect(button).toBeInViewport({ ratio: 1 });
      }
      await page.setViewportSize({ width, height: height + 10 });
      await page.keyboard.press("Escape");
      await expect(modal).toHaveCount(0);
      await page.setViewportSize({ width, height });
    }
  }
});
