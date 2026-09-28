import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const widths = [320, 375, 390, 812, 901, 1024, 1199, 1200, 1440, 1920];
const viewportHeight = (width: number) => width === 320 ? 568 : width === 375 ? 812 : width === 390 ? 844 : width === 812 ? 375 : 900;

test("用户在全部断点始终单行，更多菜单信息完整且操作可达", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "尺寸与主题矩阵集中执行");
  const state = await installApiMocks(page);
  state.users.push({ ...state.users[1], id: "long", username: "member_" + "a".repeat(57), enabled: false });
  await page.goto("/#/users");
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    for (const width of widths) {
      await page.setViewportSize({ width, height: viewportHeight(width) });
      const cards = page.locator(".user-card");
      await expect(cards).toHaveCount(3);
      for (const card of await cards.all()) {
        const heading = await card.locator(".user-heading").boundingBox();
        const actions = await card.locator(".user-card-actions").boundingBox();
        expect(Math.abs(heading!.y + heading!.height / 2 - actions!.y - actions!.height / 2)).toBeLessThan(1);
        expect(heading!.x + heading!.width).toBeLessThanOrEqual(actions!.x);
        expect((await card.getByRole("heading").boundingBox())!.width).toBeGreaterThan(16);
        for (const button of await card.getByRole("button").all()) {
          const box = await button.boundingBox();
          expect(box!.width).toBeGreaterThanOrEqual(44);
          expect(box!.height).toBeGreaterThanOrEqual(44);
        }
        const summary = card.locator(".user-resource-summary");
        if (width > 900) {
          await expect(summary).toBeVisible();
          const box = await summary.boundingBox();
          expect(box!.x).toBeGreaterThanOrEqual(heading!.x + heading!.width);
          expect(box!.x + box!.width).toBeLessThanOrEqual(actions!.x);
          expect(Math.abs(box!.y + box!.height / 2 - actions!.y - actions!.height / 2)).toBeLessThan(1);
          await expect(card.locator(".user-resource-mobile")).toBeHidden();
        } else {
          await expect(summary).toBeHidden();
          await expect(card.getByRole("button", { name: /^管理 .+ 的空间$/ })).toHaveText(/资源$/);
        }
        await expect(card.getByText("管理资源", { exact: true })).toHaveCount(0);
      }
      if (width === 375 || width === 1440) await page.screenshot({ path: info.outputPath(`users-${width}-${colorScheme}.png`), fullPage: true });
      const long = cards.last();
      const rowBefore = await long.boundingBox();
      await long.getByRole("button", { name: "更多", exact: true }).click();
      const menu = long.getByRole("dialog");
      await expect(menu).toBeVisible();
      await expect(long.locator(".user-menu-identity strong")).toHaveText(state.users[2].username);
      expect((await long.boundingBox())!.height).toBe(rowBefore!.height);
      const menuBox = await menu.boundingBox();
      expect(menuBox!.x).toBeGreaterThanOrEqual(16);
      expect(menuBox!.x + menuBox!.width).toBeLessThanOrEqual(width - 16);
      expect(menuBox!.y).toBeGreaterThanOrEqual(16);
      expect(menuBox!.y + menuBox!.height).toBeLessThanOrEqual(viewportHeight(width) - 16);
      await expect(long.getByRole("heading")).toHaveCSS("white-space", "nowrap");
      await expect(menu.locator(".user-resources")).toBeVisible();
      if (width === 375 || width === 1440) await page.screenshot({ path: info.outputPath(`user-menu-${width}-${colorScheme}.png`), fullPage: true });
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
      await page.keyboard.press("Escape");
      await expect(menu).toBeHidden();
      await expect(long.getByRole("button", { name: "更多", exact: true })).toBeFocused();
    }
  }
  await page.getByLabel("搜索用户").fill("alice");
  await expect(page.locator(".user-card")).toHaveCount(1);
  await page.getByLabel("搜索用户").fill("");
  await page.getByLabel("用户状态筛选").selectOption("disabled");
  await expect(page.locator(".user-card")).toHaveCount(1);
});

test("桌面主页面填满可用宽度，服务详情不再受固定上限限制", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面宽度矩阵集中执行");
  test.setTimeout(60000);
  await installApiMocks(page);
  for (const width of widths.filter(value => value > 900)) {
    await page.setViewportSize({ width, height: 900 });
    for (const route of ["home", "services", "agents", "domains", "users", "manage", "settings/sessions", "services/t-1", "agents/a-1", "domains/d-1"]) {
      await page.goto(`/#/${route}`);
      const slot = page.locator(".page-slot:not([hidden])");
      await expect(slot.locator(".skeleton-list")).toHaveCount(0);
      const box = await slot.boundingBox();
      expect(box!.x).toBe(232);
      expect(box!.x + box!.width).toBe(width - 24);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
      if (route === "services/t-1") {
        const detail = page.locator(".service-detail");
        await expect(detail).toBeVisible();
        expect((await detail.boundingBox())!.width).toBeLessThanOrEqual(760);
        await page.keyboard.press("Escape");
        await expect(detail).toHaveCount(0);
        await expect(page).toHaveURL(/#\/services$/);
      }
    }
  }
});

test("更多菜单支持键盘、外部关闭和弹窗返回，列表行高保持不变", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/users");
  const row = page.locator(".user-card").last();
  const more = row.getByRole("button", { name: "更多", exact: true });
  const before = await row.boundingBox();
  await more.focus(); await more.press("Enter");
  const menu = row.getByRole("dialog");
  await expect(menu.getByRole("button", { name: "流量限制", exact: true })).toBeFocused();
  expect((await row.boundingBox())!.height).toBe(before!.height);
  await page.getByLabel("搜索用户").click();
  await expect(menu).toBeHidden();
  await more.click();
  await menu.getByRole("button", { name: "修改用户名", exact: true }).click();
  await expect(menu).toBeHidden();
  await page.getByRole("dialog", { name: "修改用户名", exact: true }).getByRole("button", { name: "取消", exact: true }).click();
  await expect(more).toBeFocused();
  expect((await row.boundingBox())!.height).toBe(before!.height);
  await more.click();
  await page.evaluate(() => { location.hash = "#/home"; });
  await expect(menu).toBeHidden();
});

test("登录与注册使用同宽紧凑卡片，短屏可滚动到提交按钮", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "尺寸与主题矩阵集中执行");
  await installApiMocks(page, { anonymous: true });
  await page.route("**/api/v1/auth/invitations/inspect", route => route.fulfill({ json: { expires_at: 1893456000 } }));
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    for (const width of [320, 375, 390, 812, 1440]) {
      await page.setViewportSize({ width, height: viewportHeight(width) });
      for (const kind of ["login", "register"] as const) {
        await page.goto(kind === "login" ? "/" : "/#/invite?token=test-invite");
        const submit = page.getByRole("button", { name: kind === "login" ? "登录" : "创建账号", exact: true });
        await expect(submit).toBeVisible();
        const panel = await page.locator(".auth-panel").boundingBox();
        expect(panel!.width).toBe(Math.min(400, width - 32));
        expect(panel!.x).toBeCloseTo((width - panel!.width) / 2, 0);
        expect(panel!.y + await page.evaluate(() => scrollY)).toBeGreaterThanOrEqual(24);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
        await submit.scrollIntoViewIfNeeded();
        await expect(submit).toBeInViewport();
        await page.getByLabel("用户名", { exact: true }).scrollIntoViewIfNeeded();
        await expect(page.getByLabel("用户名", { exact: true })).toBeInViewport();
        if (width === 375 || width === 1440) await page.screenshot({ path: info.outputPath(`${kind}-${width}-${colorScheme}.png`), fullPage: true });
      }
    }
  }
});

test("登录失败保留输入，同一轮重复提交只发送一次，Enter 可登录", async ({ page }) => {
  const state = await installApiMocks(page, { anonymous: true });
  let finish!: () => void;
  const pending = new Promise<void>(resolve => { finish = resolve; });
  let attempts = 0;
  await page.route("**/api/v1/auth/login", async route => {
    attempts++;
    if (attempts === 1) { await pending; return route.fulfill({ status: 401, json: { error: "用户名或密码错误" } }); }
    state.authenticated = true; return route.fulfill({ json: {} });
  });
  await page.goto("/");
  await page.getByLabel("用户名", { exact: true }).fill("alice");
  await page.getByLabel("密码", { exact: true }).fill("test-password");
  await page.locator(".auth-form").evaluate((form: HTMLFormElement) => { form.requestSubmit(); form.requestSubmit(); });
  await expect.poll(() => attempts).toBe(1);
  await expect(page.getByRole("button", { name: "处理中…" })).toBeDisabled();
  finish();
  await expect(page.getByRole("alert")).toContainText("用户名或密码错误");
  await expect(page.getByLabel("用户名", { exact: true })).toHaveValue("alice");
  await expect(page.getByLabel("密码", { exact: true })).toHaveValue("test-password");
  await page.getByLabel("密码", { exact: true }).press("Enter");
  await expect(page.locator(".home-page")).toBeVisible();
  expect(attempts).toBe(2);
});

test("邀请校验显示加载和失效原因，返回入口可用", async ({ page }) => {
  await installApiMocks(page, { anonymous: true });
  let finish!: () => void;
  const pending = new Promise<void>(resolve => { finish = resolve; });
  await page.route("**/api/v1/auth/invitations/inspect", async route => { await pending; return route.fulfill({ status: 410, json: { error: "邀请已过期，请联系管理员重新邀请" } }); });
  await page.goto("/#/invite?token=expired-invite");
  await expect(page.getByRole("status")).toHaveText("正在验证邀请…");
  await expect(page.getByRole("button", { name: "创建账号" })).toHaveCount(0);
  finish();
  await expect(page.getByRole("alert")).toContainText("邀请已过期");
  await page.getByRole("button", { name: "返回登录" }).click();
  await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
});

test("邀请注册校验密码，阻止重复提交，已有账号可退出后继续", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.route("**/api/v1/auth/logout", route => { state.authenticated = false; return route.fulfill({ json: {} }); });
  await page.route("**/api/v1/auth/invitations/inspect", route => route.fulfill({ json: { expires_at: 1893456000 } }));
  let finish!: () => void;
  const pending = new Promise<void>(resolve => { finish = resolve; });
  let attempts = 0;
  await page.route("**/api/v1/auth/invitations/accept", async route => { attempts++; await pending; state.authenticated = true; return route.fulfill({ json: {} }); });
  await page.goto("/#/invite?token=valid-invite");
  await expect(page.getByText("当前登录为 admin。请退出后继续注册。")).toBeVisible();
  await expect(page.getByLabel("用户名", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "退出当前账号" }).click();
  await page.getByLabel("用户名", { exact: true }).fill("new-user");
  await page.getByLabel("密码", { exact: true }).fill("test-password");
  await page.getByLabel("确认密码", { exact: true }).fill("different-password");
  await page.getByRole("button", { name: "创建账号", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("两次输入的密码不一致");
  expect(attempts).toBe(0);
  await page.getByLabel("确认密码", { exact: true }).fill("test-password");
  await page.locator(".auth-form").evaluate((form: HTMLFormElement) => { form.requestSubmit(); form.requestSubmit(); });
  await expect.poll(() => attempts).toBe(1);
  await expect(page.getByRole("button", { name: "创建中…" })).toBeDisabled();
  finish();
  await expect(page.locator(".home-page")).toBeVisible();
  expect(attempts).toBe(1);
});
