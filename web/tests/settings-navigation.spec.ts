import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

async function openSettings(page: Page, name: string) {
  if (name === "账号设置") return page.getByRole("button", { name: "账号菜单", exact: true }).click();
  if ((page.viewportSize()?.width ?? 0) > 900) await page.locator(".sidebar").getByRole("link", { name, exact: true }).click();
  else {
    await page.getByRole("button", { name: "更多功能", exact: true }).click();
    await page.getByRole("navigation", { name: "更多功能" }).getByRole("link", { name, exact: true }).click();
  }
}

test("账号、用户管理与服务器入口独立，头像账号栏始终代表本人", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/manage");
  await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
  await expect(page).toHaveURL(/#\/home$/);
  await expect(page.locator(".manage-page").getByRole("link", { name: "用户管理", exact: true })).toHaveCount(0);
  expect(state.calls.some(call => call.path === "/api/v1/admin/server-settings" || call.path === "/api/v1/transport-identity")).toBe(false);
  const account = page.getByRole("button", { name: "账号菜单", exact: true });
  await expect(account.locator(".user-avatar")).toHaveAttribute("data-avatar-role", "admin");
  await expect(account.locator(".user-avatar")).toHaveAttribute("width", "32");
  if ((page.viewportSize()?.width ?? 0) > 900) {
    expect((await account.boundingBox())!.height).toBeGreaterThanOrEqual(56);
    await expect(account.locator(".user-avatar")).toHaveCSS("width", "32px");
    await expect(account.locator(".user-avatar")).toHaveCSS("height", "32px");
    await expect(account).toHaveAttribute("data-selected", "true");
  }
  await openSettings(page, "服务器设置");
  await expect(page).toHaveURL(/#\/settings\/server$/);
  await expect(page.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.7");
  await expect(page.getByRole("region", { name: "服务端内部证书" })).toBeVisible();
  await expect(account).not.toHaveAttribute("data-selected", "true");
  await openSettings(page, "用户管理");
  const own = page.locator(".user-card").first();
  await own.getByRole("button", { name: "更多", exact: true }).click();
  await expect(own.getByRole("button", { name: "修改密码", exact: true })).toHaveCount(0);
  await expect(own.getByRole("link", { name: "登录会话", exact: true })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await own.getByRole("button", { name: "管理 admin 的空间", exact: true }).click();
  await expect(page.locator(".workspace-banner")).toBeVisible();
  await expect(account.locator(".user-avatar")).toHaveAttribute("data-avatar-role", "admin");
  await account.click();
  await expect(page.locator(".account-menu-identity strong")).toHaveText("admin");
});

test("普通用户只显示个人入口，直接访问管理员页面不请求管理员数据", async ({ page }) => {
  const state = await installApiMocks(page); state.authRole = "tenant";
  await page.goto("/#/manage");
  await expect(page.getByRole("button", { name: "账号菜单", exact: true }).locator(".user-avatar")).toHaveAttribute("data-avatar-role", "user");
  await expect(page.getByRole("button", { name: "账号菜单", exact: true }).locator(".user-avatar")).toHaveAttribute("data-avatar-role", "user");
  if ((page.viewportSize()?.width ?? 0) > 900) {
    await expect(page.locator(".sidebar").getByRole("link", { name: "服务器设置", exact: true })).toHaveCount(0);
    await expect(page.locator(".sidebar").getByRole("link", { name: "用户管理", exact: true })).toHaveCount(0);
  } else {
    await page.getByRole("button", { name: "更多功能", exact: true }).click();
    await expect(page.locator(".mobile-more a>span:not(.sr-only)")).toHaveText(["节点", "域名"]);
  }
  for (const route of ["#/settings/server", "#/users"]) {
    await page.evaluate(route => { location.hash = route; }, route);
    await expect(page.getByRole("alert")).toHaveText("此页面需要管理员权限");
  }
  expect(state.calls.some(call => call.path.startsWith("/api/v1/admin/") || call.path === "/api/v1/transport-identity")).toBe(false);
});

test("服务器草稿跨断点保留，离页可取消，确认放弃后恢复已保存配置", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/settings/server");
  const ipv4 = page.getByLabel("公网 IPv4", { exact: true });
  await expect(ipv4).toHaveValue("203.0.113.7");
  await ipv4.fill("203.0.113.9");
  expect(await page.evaluate(() => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })))).toBe(true);
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(ipv4).toHaveValue("203.0.113.9");
  await page.setViewportSize({ width: 375, height: 812 });
  await expect(ipv4).toHaveValue("203.0.113.9");
  await page.evaluate(() => { location.hash = "#/manage"; });
  const confirm = page.getByRole("dialog", { name: "放弃未保存的修改？", exact: true });
  await expect(confirm).toBeVisible();
  await expect(page).toHaveURL(/#\/settings\/server$/);
  await page.evaluate(() => { location.hash = "#/users"; });
  await expect(confirm).toBeVisible();
  await confirm.getByRole("button", { name: "取消", exact: true }).click();
  await expect(ipv4).toHaveValue("203.0.113.9");
  await page.evaluate(() => { location.hash = "#/manage"; });
  await confirm.getByRole("button", { name: "放弃修改", exact: true }).click();
  await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
  await openSettings(page, "服务器设置");
  await expect(ipv4).toHaveValue("203.0.113.7");
  expect(state.calls.filter(call => call.method === "PUT")).toHaveLength(0);
});

test("服务器保存期间阻止离页和重复提交，保存后解除刷新保护", async ({ page }) => {
  const state = await installApiMocks(page);
  let finish!: () => void; const pending = new Promise<void>(resolve => { finish = resolve; }); let attempts = 0;
  await page.route("**/api/v1/admin/server-settings", async route => {
    if (route.request().method() !== "PUT") return route.fallback();
    attempts++; await pending;
    Object.assign(state.serverSettings, route.request().postDataJSON());
    return route.fulfill({ json: state.serverSettings });
  });
  await page.goto("/#/settings/server");
  const ipv4 = page.getByLabel("公网 IPv4", { exact: true });
  await expect(ipv4).toHaveValue("203.0.113.7");
  await ipv4.fill("203.0.113.9");
  await page.getByRole("form", { name: "服务器配置" }).evaluate((form: HTMLFormElement) => { form.requestSubmit(); form.requestSubmit(); });
  await expect.poll(() => attempts).toBe(1);
  await expect(page.getByRole("button", { name: "保存中…", exact: true })).toBeDisabled();
  await page.evaluate(() => { location.hash = "#/manage"; });
  await expect(page).toHaveURL(/#\/settings\/server$/);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  finish();
  await expect(page.getByText("设置已保存。", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => !window.dispatchEvent(new Event("beforeunload", { cancelable: true })))).toBe(false);
  await openSettings(page, "账号设置");
  await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
});

test("两端设置页适应窄屏、横屏与双栏，长用户名和浅深色截图", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "尺寸与主题矩阵集中执行");
  test.setTimeout(120000);
  await installApiMocks(page);
  const longUsername = "一位用户名很长的管理员-account-owner";
  let username = longUsername;
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: true, user_id: "admin", username, role: "system_admin", workspace_id: "default", csrf_token: "test-csrf" } }));
  for (const theme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce" });
    for (const width of [320, 375, 390, 812, 900, 901, 1199, 1200, 1440]) {
      username = longUsername;
      await page.setViewportSize({ width, height: width === 812 ? 375 : width <= 900 ? 812 : 900 });
      for (const route of ["manage", "settings/server"]) {
        await page.goto(`/#/${route === "manage" ? "home" : route}`);
        await page.reload();
        if (route === "manage") {
          await page.getByRole("button", { name: "账号菜单", exact: true }).click();
          await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
          const card = await page.getByRole("menu", { name: "本人账号", exact: true }).boundingBox();
          expect(card!.width).toBeLessThanOrEqual(240);
          await page.getByRole("menuitem", { name: "退出登录", exact: true }).scrollIntoViewIfNeeded();
          await expect(page.getByRole("menuitem", { name: "退出登录", exact: true })).toBeInViewport();
          if (width > 900) {
            const name = page.locator(".sidebar-account-name strong");
            await expect(name).toHaveAttribute("title", username);
            await expect(name).toHaveCSS("text-overflow", "ellipsis");
          }
        } else {
          await expect(page.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.7");
          await expect(page.getByRole("region", { name: "服务端内部证书" }).locator("summary")).toContainText("证书有效");
          const form = (await page.locator(".server-settings-form").boundingBox())!;
          const identity = (await page.locator(".server-identity").boundingBox())!;
          if (width >= 1200) expect(identity.x).toBeGreaterThanOrEqual(form.x + form.width);
          else expect(identity.y).toBeGreaterThanOrEqual(form.y + form.height);
        }
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
        if (width === 375 || width === 1440) {
          username = "admin";
          await page.goto(`/#/${route === "manage" ? "home" : route}`);
          await page.reload();
          if (route === "manage") { await page.getByRole("button", { name: "账号菜单", exact: true }).click(); await expect(page.locator(".account-menu-identity strong")).toHaveText("admin"); }
          else {
            await expect(page.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.7");
            await expect(page.locator(".server-identity summary")).toContainText("证书有效");
          }
          await page.evaluate(() => scrollTo(0, 0));
          await page.screenshot({ path: info.outputPath(`${route === "manage" ? "account" : "server"}-${width === 375 ? "mobile" : "desktop"}-${theme}.png`), fullPage: route !== "manage", animations: "disabled" });
          if (route === "manage") await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
          if (width === 1440 && route === "manage") await page.locator(".sidebar-settings").screenshot({ path: info.outputPath(`account-avatar-${theme}.png`) });
        }
      }
    }
    for (const width of [375, 1440]) {
      username = "admin";
      await page.setViewportSize({ width, height: width === 375 ? 812 : 900 });
      await page.goto("/#/users");
      await page.reload();
      await expect(page.locator(".user-card")).toHaveCount(2);
      await expect(page.locator(".user-card").first()).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await page.screenshot({ path: info.outputPath(`users-${width === 375 ? "mobile" : "desktop"}-${theme}.png`), fullPage: true, animations: "disabled" });
    }
  }
});
