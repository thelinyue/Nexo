import { expect, test, type Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const account = (page: Page) => page.getByRole("button", { name: "账号菜单", exact: true });
const menu = (page: Page) => page.getByRole("menu", { name: "本人账号", exact: true });
async function pwa(page: Page) { await page.addInitScript(() => Object.defineProperty(navigator, "standalone", { configurable: true, value: true })); }

test("头像菜单共用首行，无账号页，支持键盘和会话返回来源", async ({ page }) => {
  await pwa(page); await installApiMocks(page);
  await page.goto("/#/users");
  await expect(account(page)).toBeVisible();
  const first = (await account(page).boundingBox())!;
  const search = (await page.getByRole("textbox", { name: "搜索用户", exact: true }).boundingBox())!;
  expect(search.y + search.height / 2).toBeCloseTo(first.y + first.height / 2, 0);
  if ((page.viewportSize()?.width ?? 0) <= 900) {
    await expect(page.getByLabel("用户状态筛选", { exact: true })).toHaveCSS("width", "72px");
    expect((await page.locator(".user-card").first().boundingBox())!.y).toBeLessThanOrEqual(122);
  }
  await account(page).focus(); await page.keyboard.press("ArrowUp");
  await expect(menu(page).getByRole("menuitem", { name: "退出登录", exact: true })).toBeFocused();
  await page.keyboard.press("Escape"); await expect(account(page)).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(menu(page)).toBeVisible();
  await expect(account(page)).toHaveAttribute("data-selected", "true");
  await expect(menu(page).getByRole("menuitem", { name: "修改密码", exact: true })).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(menu(page).getByRole("menuitem", { name: "登录会话", exact: true })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#\/settings\/sessions$/);
  await expect(page.locator(".session-row")).toHaveCount(2);
  await expect(page.getByRole("heading", { name: "登录会话", exact: true })).toBeFocused();
  await page.getByRole("link", { name: "返回", exact: true }).click();
  await expect(page).toHaveURL(/#\/users$/);
  await page.evaluate(() => { location.hash = "#/agents"; });
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("设备");
  await account(page).click(); await menu(page).getByRole("menuitem", { name: "登录会话", exact: true }).click();
  await page.getByRole("link", { name: "返回", exact: true }).click();
  await expect(page).toHaveURL(/#\/agents$/);
  await expect(page.locator(".account-card,.manage-page")).toHaveCount(0);
});

test("菜单关闭、个人密码弹窗与跨屏焦点恢复不改变代管身份", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/users");
  await page.getByRole("button", { name: "管理 alice 的空间", exact: true }).click();
  await expect(page.locator(".workspace-banner")).toBeVisible();
  await account(page).click();
  await expect(account(page)).toHaveAttribute("data-selected", "true");
  if ((page.viewportSize()?.width ?? 0) > 900) await expect(account(page).locator("img")).toHaveCSS("outline-style", "solid");
  await expect(menu(page).locator(".account-menu-identity strong")).toHaveText("admin");
  await expect(account(page).locator("img")).toHaveAttribute("data-avatar-role", "admin");
  await page.keyboard.press("Escape"); await expect(account(page)).toBeFocused();
  await account(page).click(); await menu(page).getByRole("menuitem", { name: "修改密码", exact: true }).click();
  const password = page.getByRole("dialog", { name: "修改密码", exact: true });
  await expect(password).toBeVisible(); await expect(menu(page)).toBeHidden();
  await expect(password.locator(".modal-workspace")).toHaveCount(0);
  await page.setViewportSize((page.viewportSize()?.width ?? 0) > 900 ? { width: 375, height: 812 } : { width: 1440, height: 900 });
  await password.getByRole("button", { name: "取消", exact: true }).click();
  await expect(account(page)).toBeFocused();
  await account(page).click(); await page.keyboard.press("Tab");
  await expect(menu(page)).toBeHidden();
});

for (const action of ["修改密码", "登录会话", "退出登录"] as const) test(`服务器草稿保护账号菜单的${action}动作`, async ({ page }) => {
  const state = await installApiMocks(page); await page.goto("/#/settings/server");
  const ipv4 = page.getByLabel("公网 IPv4", { exact: true }); await expect(ipv4).toHaveValue("203.0.113.7");
  await ipv4.fill("203.0.113.9");
  await account(page).click(); await expect(page.getByRole("dialog")).toHaveCount(0);
  await menu(page).getByRole("menuitem", { name: action, exact: true }).click();
  const confirm = page.getByRole("dialog", { name: "放弃未保存的修改？", exact: true }); await expect(confirm).toBeVisible();
  await expect(menu(page)).toBeHidden(); await confirm.getByRole("button", { name: "取消", exact: true }).click();
  await expect(ipv4).toHaveValue("203.0.113.9"); await expect(page).toHaveURL(/#\/settings\/server$/);
  expect(state.calls.some(call => ["/api/v1/auth/password", "/api/v1/auth/logout", "/api/v1/auth/sessions"].includes(call.path))).toBe(false);
  await account(page).click(); await menu(page).getByRole("menuitem", { name: action, exact: true }).click();
  await confirm.getByRole("button", { name: "放弃修改", exact: true }).click();
  if (action === "修改密码") await expect(page.getByRole("dialog", { name: "修改密码", exact: true })).toBeVisible();
  else if (action === "登录会话") await expect(page.locator(".session-row")).toHaveCount(2);
  else await expect(page.locator(".app-shell")).toHaveCount(0);
});

test("旧账号链接替换到首页并打开菜单，普通用户没有管理入口", async ({ page }) => {
  const state = await installApiMocks(page); state.authRole = "tenant";
  await page.goto("/#/manage"); await expect(page).toHaveURL(/#\/home$/); await expect(menu(page)).toBeVisible();
  await expect(account(page).locator("img")).toHaveAttribute("data-avatar-role", "user");
  await page.keyboard.press("Escape");
  await page.evaluate(() => { location.hash = "#/settings"; }); await expect(page).toHaveURL(/#\/home$/); await expect(menu(page)).toBeVisible();
  await page.keyboard.press("Escape");
  if ((page.viewportSize()?.width ?? 0) <= 900) {
    await page.getByRole("button", { name: "更多功能", exact: true }).click();
    await expect(page.locator(".mobile-more a>span:not(.sr-only)")).toHaveText(["节点", "域名"]);
  }
  await page.evaluate(() => { location.hash = "#/settings/server"; });
  await expect(page.getByRole("alert")).toHaveText("此页面需要管理员权限");
  expect(state.calls.some(call => call.path.startsWith("/api/v1/admin/"))).toBe(false);
});

test("退出失败可重试，重复点击只请求一次，退出期间所有菜单动作不可执行", async ({ page }) => {
  const state = await installApiMocks(page); state.failures.set("POST /api/v1/auth/logout", "网络暂不可用");
  await page.goto("/#/agents"); await account(page).click(); await menu(page).getByRole("menuitem", { name: "退出登录", exact: true }).click();
  await expect(menu(page).getByRole("alert")).toContainText("退出失败：网络暂不可用");
  state.failures.clear(); let attempts = 0; let finish!: () => void;
  const pending = new Promise<void>(resolve => { finish = resolve; });
  await page.route("**/api/v1/auth/logout", async route => {
    attempts++; expect(route.request().headers()["x-nexo-csrf"]).toBe("test-csrf");
    await pending; await route.fulfill({ json: {} });
  });
  await menu(page).getByRole("menuitem", { name: "退出登录", exact: true }).evaluate(button => { (button as HTMLButtonElement).click(); (button as HTMLButtonElement).click(); });
  await expect.poll(() => attempts).toBe(1); await account(page).click();
  await expect(menu(page).getByRole("menuitem", { name: "退出中…", exact: true })).toBeDisabled();
  await expect(menu(page).getByRole("menuitem", { name: "修改密码", exact: true })).toBeDisabled();
  const sessions = menu(page).getByRole("menuitem", { name: "登录会话", exact: true });
  await expect(sessions).toHaveAttribute("aria-disabled", "true"); await sessions.evaluate(element => (element as HTMLAnchorElement).click());
  await expect(page).toHaveURL(/#\/agents$/); finish(); await expect(page.locator(".app-shell")).toHaveCount(0);
});

test("外部点击保留目标焦点，HTTP 提醒可见，其他弹窗隔离头像菜单", async ({ page }) => {
  await pwa(page); await installApiMocks(page);
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: true, user_id: "admin", username: "admin", role: "system_admin", workspace_id: "default", csrf_token: "test-csrf", local_http_warning: true } }));
  await page.goto("/#/users"); await account(page).click();
  await expect(menu(page).getByRole("status")).toContainText("当前连接未加密");
  await page.getByLabel("搜索用户", { exact: true }).click(); await expect(menu(page)).toBeHidden();
  await expect(page.getByLabel("搜索用户", { exact: true })).toBeFocused();
  await account(page).click(); await menu(page).getByRole("menuitem", { name: "修改密码", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "修改密码", exact: true })).toBeVisible();
  await account(page).evaluate(button => (button as HTMLButtonElement).click()); await expect(menu(page)).toBeHidden();
  await page.keyboard.press("Escape"); await expect(account(page)).toBeFocused();
});

test("字体放大时正文跟随首行高度，跨断点保留搜索和筛选", async ({ page }) => {
  await pwa(page); await installApiMocks(page); await page.goto("/#/users");
  await page.getByLabel("搜索用户", { exact: true }).fill("alice"); await page.getByLabel("用户状态筛选", { exact: true }).selectOption("enabled");
  for (const width of [320, 900, 901, 1440]) {
    await page.setViewportSize({ width, height: 900 }); await expect(page.getByLabel("搜索用户", { exact: true })).toHaveValue("alice");
    await expect(page.getByLabel("用户状态筛选", { exact: true })).toHaveValue("enabled");
    await page.evaluate(() => { document.documentElement.style.fontSize = "150%"; });
    await expect.poll(async () => { const bar = (await page.locator(".workspace-topbar").boundingBox())!; const caption = (await page.locator(".users-caption").boundingBox())!; return caption.y - bar.y - bar.height; }).toBeGreaterThanOrEqual(12);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.evaluate(() => { document.documentElement.style.fontSize = ""; });
  }
});

test("共享首行覆盖服务、节点、标题和长详情名称，仅当前页面投递控件", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "布局矩阵集中执行");
  test.setTimeout(120000);
  await pwa(page); const state = await installApiMocks(page);
  state.devices[0].name = "很长的家庭存储设备名称".repeat(8);
  await page.goto("/#/home");
  for (const theme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    for (const [width, height] of [[320, 568], [812, 375], [900, 900], [901, 900], [1440, 900]]) {
      await page.setViewportSize({ width, height });
      for (const route of ["home", "services", "nodes", "agents", "domains", "agents/a-1"]) {
        await page.evaluate(route => { location.hash = `#/${route}`; }, route);
        const bar = page.locator(".workspace-topbar");
        await expect(bar.locator("h1")).toHaveCount(1);
        await expect(bar.locator("h1")).toHaveText(route === "agents/a-1" ? state.devices[0].name : ({ home: "首页", services: "服务", nodes: "节点", agents: "设备", domains: "域名" } as Record<string, string>)[route]);
        await expect(page.locator(".page-slot:not([hidden]) .skeleton-list")).toHaveCount(0);
        await expect(account(page)).toHaveCount(1);
        await expect(page.locator(".sidebar-settings")).toHaveCount(0);
        await expect.poll(() => page.evaluate(() => {
          const content = document.querySelector<HTMLElement>(".content")!;
          return content.getBoundingClientRect().top + parseFloat(getComputedStyle(content).paddingTop) - document.querySelector(".workspace-topbar")!.getBoundingClientRect().bottom;
        })).toBeCloseTo(12, 1);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        if (route === "services" || route === "nodes") {
          const search = (await bar.locator("input").boundingBox())!;
          const avatar = (await account(page).boundingBox())!;
          expect(search.y + search.height / 2).toBeCloseTo(avatar.y + avatar.height / 2, 0);
          await expect(bar.locator("input")).toHaveCount(1);
        }
        if (route === "agents/a-1") await expect(bar.locator("h1")).toHaveAttribute("title", state.devices[0].name);
        if (width === 320 || width === 901 || width === 1440) await page.screenshot({ path: info.outputPath(`pwa-${route.replaceAll("/", "-")}-${width}-${theme}.png`), animations: "disabled" });
      }
    }
  }
});
