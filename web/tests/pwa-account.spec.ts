import { expect, test, type Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const current = (page: Page) => page.locator(".page-slot:not([hidden])");
const avatar = (page: Page) => page.locator(".pwa-account");
const invite = (page: Page) => page.getByRole("button", { name: "邀请用户", exact: true });
async function installedPwa(page: Page) {
  await page.addInitScript(() => Object.defineProperty(navigator, "standalone", { configurable: true, value: true }));
}

test("PWA 悬浮头像代表本人，键盘进入账号和会话，代管空间不改变身份", async ({ page }) => {
  await installedPwa(page);
  await installApiMocks(page);
  await page.goto("/#/agents");
  await expect(avatar(page)).toBeVisible();
  await expect(avatar(page)).toHaveAttribute("title", "admin");
  await expect(avatar(page).locator(".user-avatar")).toHaveAttribute("data-avatar-role", "admin");
  await expect(avatar(page)).toHaveCSS("width", "44px");
  await expect(avatar(page)).toHaveCSS("height", "44px");
  await expect(avatar(page).locator("img")).toHaveCSS("width", "32px");
  await expect(page.locator(".sidebar-settings")).toHaveCount(0);
  await avatar(page).focus();
  await expect(avatar(page)).toHaveCSS("outline-style", "solid");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("menuitem", { name: "修改密码", exact: true })).toBeFocused();
  await expect(avatar(page)).toHaveAttribute("data-selected", "true");
  await page.getByRole("menuitem", { name: "登录会话", exact: true }).click();
  await expect(page).toHaveURL(/#\/settings\/sessions$/);
  await expect(avatar(page)).toHaveAttribute("data-selected", "true");
  await page.goBack();
  await expect(page).toHaveURL(/#\/agents$/);
  await page.evaluate(() => { location.hash = "#/users"; });
  await expect(current(page).locator(".user-card")).toHaveCount(2);
  await current(page).getByRole("button", { name: "管理 alice 的空间", exact: true }).click();
  await expect(page.locator(".workspace-banner")).toBeVisible();
  await expect(avatar(page)).toHaveAttribute("title", "admin");
  await expect(avatar(page).locator("img")).toHaveAttribute("data-avatar-role", "admin");
  // 首行尺寸由 ResizeObserver 在下一帧回写，等待布局稳定后检查内容未被头像覆盖。
  await expect.poll(async () => {
    const banner = (await page.locator(".workspace-banner").boundingBox())!;
    const account = (await avatar(page).boundingBox())!;
    return banner.y - account.y - account.height;
  }).toBeGreaterThanOrEqual(0);
  if ((page.viewportSize()?.width ?? 0) <= 900) {
    await page.getByRole("button", { name: "更多功能", exact: true }).click();
    await expect(page.locator(".mobile-more a>span:not(.sr-only)")).toHaveText(["节点", "域名", "用户管理", "服务器设置"]);
    await avatar(page).click();
    await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
    await expect(page.locator(".mobile-more")).toBeHidden();
    await expect(page.getByRole("button", { name: "更多功能", exact: true })).not.toHaveClass(/active/);
  }
});

test("PWA 邀请失败可重试，重复点击只请求一次，跨屏后关闭弹窗恢复当前入口焦点", async ({ page }) => {
  await installedPwa(page);
  await installApiMocks(page);
  let attempts = 0; let finish!: () => void;
  const pending = new Promise<void>(resolve => { finish = resolve; });
  await page.route("**/api/v1/admin/invitations", async route => {
    if (route.request().method() !== "POST") return route.fallback();
    expect(route.request().headers()["x-nexo-csrf"]).toBe("test-csrf");
    attempts++;
    if (attempts === 1) return route.fulfill({ status: 500, json: { error: "请稍后重试" } });
    await pending;
    return route.fulfill({ json: { token: "pwa-test-invite", expires_at: Math.floor(Date.now() / 1000) + 3600 } });
  });
  await page.goto("/#/users");
  await page.getByRole("textbox", { name: "搜索用户", exact: true }).fill("admin");
  const desktop = (page.viewportSize()?.width ?? 0) > 900;
  if (desktop) await expect(invite(page)).toHaveText("邀请");
  else {
    await expect(page.locator(".mobile-create-slot").getByRole("button")).toHaveCount(1);
    await expect(invite(page)).toHaveCSS("width", "52px");
    await expect(invite(page)).toHaveCSS("height", "52px");
    await expect(page.locator(".workspace-topbar .page-header")).toHaveCSS("min-height", "44px");
  }
  await invite(page).click();
  await expect(current(page).getByRole("alert")).toContainText("请稍后重试");
  await expect(invite(page)).toBeEnabled();
  await invite(page).evaluate(button => { (button as HTMLButtonElement).click(); (button as HTMLButtonElement).click(); });
  await expect.poll(() => attempts).toBe(2);
  await expect(invite(page)).toBeDisabled();
  await expect(invite(page)).toHaveAttribute("aria-busy", "true");
  await page.setViewportSize(desktop ? { width: 375, height: 812 } : { width: 1440, height: 900 });
  await expect(invite(page)).toBeVisible();
  await expect(invite(page)).toBeDisabled();
  await expect(page.getByRole("textbox", { name: "搜索用户", exact: true })).toHaveValue("admin");
  finish();
  const dialog = page.getByRole("dialog", { name: "邀请链接", exact: true });
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("code")).toContainText("#/invite?token=pwa-test-invite");
  const box = (await avatar(page).boundingBox())!;
  expect(await page.evaluate(({ x, y }) => !document.elementFromPoint(x, y)?.closest(".pwa-account"), { x: box.x + 22, y: box.y + 22 })).toBe(true);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(invite(page)).toBeFocused();
  expect(attempts).toBe(2);
  await avatar(page).click();
  await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
  await expect(page.locator(".mobile-create-slot button")).toHaveCount(desktop ? 1 : 0);
});

test("普通 PWA 用户只拥有本人头像入口，普通浏览器保留原导航和邀请布局", async ({ page }) => {
  const state = await installApiMocks(page); state.authRole = "tenant";
  await installedPwa(page);
  await page.goto("/#/manage");
  await expect(avatar(page)).toBeVisible();
  await expect(avatar(page).locator("img")).toHaveAttribute("data-avatar-role", "user");
  await expect(invite(page)).toHaveCount(0);
  await page.evaluate(() => { location.hash = "#/users"; });
  await expect(current(page).getByRole("alert")).toHaveText("此页面需要管理员权限");
  await expect(invite(page)).toHaveCount(0);
  expect(state.calls.some(call => call.path.startsWith("/api/v1/admin/"))).toBe(false);
  const browserPage = await page.context().newPage();
  await installApiMocks(browserPage);
  await browserPage.goto("/#/users");
  await expect(browserPage.getByRole("button", { name: "账号菜单", exact: true })).toBeVisible();
  await expect(invite(browserPage)).toHaveText("邀请用户");
  await expect(browserPage.locator(".mobile-create-slot button")).toHaveCount(0);
  await browserPage.close();
});

test("悬浮头像遵守服务器草稿与保存保护，保存后可立即进入账号设置", async ({ page }) => {
  await installedPwa(page);
  const state = await installApiMocks(page);
  let finish!: () => void; const pending = new Promise<void>(resolve => { finish = resolve; });
  await page.route("**/api/v1/admin/server-settings", async route => {
    if (route.request().method() !== "PUT") return route.fallback();
    await pending; Object.assign(state.serverSettings, route.request().postDataJSON());
    return route.fulfill({ json: state.serverSettings });
  });
  await page.goto("/#/settings/server");
  const ipv4 = current(page).getByLabel("公网 IPv4", { exact: true });
  await expect(ipv4).toHaveValue("203.0.113.7");
  await ipv4.fill("203.0.113.9");
  await avatar(page).click();
  await page.getByRole("menuitem", { name: "登录会话", exact: true }).click();
  const confirm = page.getByRole("dialog", { name: "放弃未保存的修改？", exact: true });
  await expect(confirm).toBeVisible();
  await expect(page).toHaveURL(/#\/settings\/server$/);
  await confirm.getByRole("button", { name: "取消", exact: true }).click();
  await expect(ipv4).toHaveValue("203.0.113.9");
  expect(await page.evaluate(() => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })))).toBe(true);
  await current(page).getByRole("button", { name: "保存设置", exact: true }).click();
  await expect(current(page).getByRole("button", { name: "保存中…", exact: true })).toBeDisabled();
  await avatar(page).click();
  await page.getByRole("menuitem", { name: "登录会话", exact: true }).click();
  await expect(page).toHaveURL(/#\/settings\/server$/);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  finish();
  await expect(current(page).getByText("设置已保存。", { exact: true })).toBeVisible();
  await avatar(page).click();
  await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
  expect(await page.evaluate(() => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })))).toBe(false);
});

test("display-mode 判断与安装状态变化不重建服务器草稿", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "独立覆盖 display-mode 判断");
  await page.addInitScript(() => {
    const original = window.matchMedia.bind(window); const media = original("(display-mode: standalone)"); let installed = true;
    Object.defineProperty(media, "matches", { get: () => installed });
    window.matchMedia = query => query === "(display-mode: standalone)" ? media : original(query);
    (window as any).setPwaMode = (value: boolean) => { installed = value; media.dispatchEvent(new Event("change")); };
  });
  await installApiMocks(page);
  await page.goto("/#/settings/server");
  await expect(avatar(page)).toBeVisible();
  const ipv4 = current(page).getByLabel("公网 IPv4", { exact: true });
  await ipv4.fill("203.0.113.9");
  await page.evaluate(() => (window as any).setPwaMode(false));
  await expect(avatar(page)).toHaveCount(0);
  await expect(page.locator(".sidebar-settings")).toBeVisible();
  await expect(ipv4).toHaveValue("203.0.113.9");
  await page.evaluate(() => (window as any).setPwaMode(true));
  await expect(avatar(page)).toBeVisible();
  await expect(page.locator(".sidebar-settings")).toHaveCount(0);
  await expect(ipv4).toHaveValue("203.0.113.9");
});

test("PWA 两端浅深色截图与窄屏横屏布局，悬浮头像滚动后稳定", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "尺寸与主题集中验收");
  test.setTimeout(120000);
  await installedPwa(page);
  const state = await installApiMocks(page);
  state.users = Array.from({ length: 24 }, (_, index) => ({ ...state.users[index % 2], id: `user-${index}`, username: `user-${index}` }));
  let username = "一位名字很长的管理员-account-owner";
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: true, user_id: "admin", username, role: "system_admin", workspace_id: "default", csrf_token: "test-csrf" } }));
  for (const theme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    username = "一位名字很长的管理员-account-owner";
    await page.reload();
    for (const [width, height] of [[320, 568], [375, 812], [390, 844], [812, 375], [900, 900], [901, 900], [1200, 900], [1440, 900]]) {
      await page.setViewportSize({ width, height });
      await page.goto("/#/users");
      await expect(current(page).locator(".user-card")).toHaveCount(24);
      await page.evaluate(() => scrollTo(0, 0));
      const first = (await avatar(page).boundingBox())!;
      expect(first.x + first.width).toBeLessThanOrEqual(width - 16);
      expect(first.y).toBe(12);
      const filter = (await page.locator(".workspace-topbar .users-filter").boundingBox())!;
      expect(filter.y).toBe(first.y);
      await page.evaluate(() => scrollTo(0, 160));
      await expect(avatar(page)).toHaveAttribute("title", "一位名字很长的管理员-account-owner");
      expect((await avatar(page).boundingBox())!.y).toBe(first.y);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      if (width <= 900) {
        const button = (await invite(page).boundingBox())!; const nav = (await page.locator(".bottom-nav").boundingBox())!;
        expect(button.width).toBe(52); expect(button.height).toBe(52);
        expect(button.x - nav.x - nav.width).toBeCloseTo(8, 0);
      }
    }
    state.users = [{ ...state.users[0], id: "admin", username: "admin" }, { ...state.users[1], id: "alice", username: "alice" }];
    username = "admin";
    for (const [screen, width, height] of [["mobile", 375, 812], ["desktop", 1440, 900]] as const) {
      await page.setViewportSize({ width, height });
      for (const route of ["users", "settings/sessions", "settings/server"] as const) {
        await page.goto(`/#/${route}`); await page.reload();
        if (route === "users") await expect(current(page).locator(".user-card")).toHaveCount(2);
        else if (route === "settings/sessions") await expect(current(page).locator(".session-row")).toHaveCount(2);
        else await expect(current(page).getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.7");
        await page.evaluate(() => scrollTo(0, 0));
        await page.screenshot({ path: info.outputPath(`pwa-${route === "settings/server" ? "server" : route === "settings/sessions" ? "sessions" : route}-${screen}-${theme}.png`), fullPage: true, animations: "disabled" });
        if (route === "users") {
          await avatar(page).click();
          await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
          await expect(avatar(page)).toHaveAttribute("data-selected", "true");
          await page.screenshot({ path: info.outputPath(`pwa-menu-${screen}-${theme}.png`), animations: "disabled" });
          await page.keyboard.press("Escape");
        }
        if (route === "settings/sessions" && screen === "desktop") {
          const box = (await avatar(page).boundingBox())!;
          await page.screenshot({ path: info.outputPath(`pwa-avatar-${theme}.png`), clip: { x: box.x - 4, y: box.y - 4, width: 52, height: 52 } });
        }
      }
    }
    state.users = Array.from({ length: 24 }, (_, index) => ({ ...state.users[index % 2], id: `user-${index}`, username: `user-${index}` }));
  }
});
