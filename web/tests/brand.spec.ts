import { expect, test, type Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import { openServiceEditor } from "./service-actions";

const active = (page: Page) => page.locator(".page-slot:not([hidden])");

/** 读取实际前景和背景验证可读性，防止局部样式覆盖主题按钮文字色。 */
async function contrast(page: Page, selector: string) {
  return page.locator(selector).first().evaluate(element => {
    const style = getComputedStyle(element);
    const luminance = (color: string) => {
      const channels = color.match(/[\d.]+/g)!.slice(0, 3).map(value => {
        const channel = Number(value) / 255;
        return channel <= .04045 ? channel / 12.92 : ((channel + .055) / 1.055) ** 2.4;
      });
      return channels[0] * .2126 + channels[1] * .7152 + channels[2] * .0722;
    };
    const foreground = luminance(style.color), background = luminance(style.backgroundColor);
    return (Math.max(foreground, background) + .05) / (Math.min(foreground, background) + .05);
  });
}

test("暖色主题与六种空状态在明暗页面中可读且操作可达", async ({ page }, info) => {
  test.setTimeout(90000);
  const state = await installApiMocks(page);
  const tunnel = { ...state.tunnels[0] };
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    state.tunnels = [tunnel];
    await page.goto("/#/services");
    // hash 导航不会重新读取登录状态；每套主题从一次真实页面加载开始。
    await page.reload();
    await expect(active(page).locator(".service-row")).toHaveCount(1);
    expect(await contrast(page, ".mobile-create-slot .page-create,.page-slot:not([hidden]) .page-create")).toBeGreaterThanOrEqual(4.5);
    await page.screenshot({ path: info.outputPath(`${colorScheme}-services.png`) });

    await openServiceEditor(page);
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByRole("button", { name: "保存服务", exact: true })).toBeInViewport();
    await page.screenshot({ path: info.outputPath(`${colorScheme}-dialog.png`) });
    await page.getByRole("dialog").getByRole("button", { name: "取消", exact: true }).click();

    state.tunnels = []; state.devices = []; state.domains = []; state.enrollments = []; state.sessions = [];
    for (const [route, kind] of [["services", "services"], ["agents", "agents"], ["domains", "domains"], ["settings/sessions", "sessions"], ["services/deleted", "missing"], ["services", "search"]]) {
      if (kind === "search") state.tunnels = [tunnel];
      await page.goto(`/#/${route}`);
      await page.reload();
      if (kind === "search") await page.getByLabel("搜索服务").fill("找不到的服务");
      const empty = active(page).locator(`.empty[data-kind="${kind}"]`);
      await expect(empty).toBeVisible();
      const art = empty.locator("img");
      await expect(art).toHaveAttribute("alt", "");
      await expect.poll(() => art.evaluate(image => (image as HTMLImageElement).naturalWidth)).toBe(512);
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
      for (const action of await empty.locator(".empty-actions > button,.empty-actions > a").all()) {
        await action.scrollIntoViewIfNeeded();
        await expect(action).toBeInViewport({ ratio: 1 });
        // 浮动底栏也处于视口中，额外检查按钮上下沿的命中元素，避免仅通过可见性断言。
        expect(await action.evaluate(element => {
          const box = element.getBoundingClientRect();
          return [box.top + 3, box.bottom - 3].every(y => element.contains(document.elementFromPoint(box.x + box.width / 2, y)));
        })).toBeTruthy();
      }
      await page.screenshot({ path: info.outputPath(`${colorScheme}-empty-${kind}.png`), fullPage: true });
      if (kind === "missing") { await page.keyboard.press("Escape"); await expect(page.locator(".application-modal")).toHaveCount(0); await expect(page).toHaveURL(/#\/services$/); }
    }
    state.authenticated = false;
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
    await expect.poll(() => page.locator(".brand-icon").evaluate(image => (image as HTMLImageElement).naturalWidth)).toBeGreaterThan(0);
    expect(await contrast(page, ".auth-panel .primary-button")).toBeGreaterThanOrEqual(4.5);
    await page.screenshot({ path: info.outputPath(`${colorScheme}-login.png`) });
    state.authenticated = true;
  }
});

test("插画不改变辅助功能偏好与键盘焦点", async ({ page, context }, info) => {
  test.skip(info.project.name !== "desktop-dark", "辅助功能检查集中执行");
  await installApiMocks(page, { empty: true });
  await page.setViewportSize({ width: 375, height: 812 });
  await page.emulateMedia({ contrast: "more", reducedMotion: "reduce" });
  await page.goto("/#/services");
  await expect(page.locator(".bottom-nav")).toHaveCSS("backdrop-filter", "none");
  await expect(page.locator(".empty-illustration")).toHaveCSS("animation-name", "none");
  await expect(page.locator(".empty-illustration")).toHaveAttribute("aria-hidden", "true");
  const button = page.getByRole("button", { name: "创建服务", exact: true });
  await button.focus();
  await expect(button).toBeFocused();
  await expect(button).toHaveCSS("outline-style", "solid");
  await button.press("Enter");
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "取消", exact: true }).click();
  const session = await context.newCDPSession(page);
  await session.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-transparency", value: "reduce" }] });
  await expect(page.locator(".bottom-nav")).toHaveCSS("backdrop-filter", "none");
  await session.detach();
});

test("主题文字在各层表面保持对比度", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "颜色组合集中验证");
  await installApiMocks(page);
  await page.goto("/#/services");
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme });
    const ratios = await page.evaluate(() => {
      const style = getComputedStyle(document.documentElement);
      const luminance = (token: string) => {
        const hex = style.getPropertyValue(token).trim().slice(1);
        const channels = hex.match(/../g)!.map(value => { const n = parseInt(value, 16) / 255; return n <= .04045 ? n / 12.92 : ((n + .055) / 1.055) ** 2.4; });
        return channels[0] * .2126 + channels[1] * .7152 + channels[2] * .0722;
      };
      return ["--text", "--secondary", "--muted", "--primary"].flatMap(foreground => ["--bg", "--surface", "--surface-soft", "--surface-raised", "--nav-selected"].map(background => {
        const a = luminance(foreground), b = luminance(background);
        return { foreground, background, ratio: (Math.max(a, b) + .05) / (Math.min(a, b) + .05) };
      }));
    });
    for (const item of ratios) expect(item.ratio, `${colorScheme}: ${item.foreground} / ${item.background}`).toBeGreaterThanOrEqual(4.5);
  }
});

test.describe("品牌素材离线加载", () => {
  test.use({ serviceWorkers: "allow" });
  test("PWA 预缓存包含六张插画和图标，断网后仍可读取", async ({ page, context }, info) => {
    test.skip(info.project.name !== "desktop-dark", "使用真实 Chromium Service Worker 验收");
    await page.goto("/");
    await page.evaluate(async () => {
      await navigator.serviceWorker.ready;
      if (!navigator.serviceWorker.controller) await new Promise<void>(resolve => navigator.serviceWorker.addEventListener("controllerchange", () => resolve(), { once: true }));
    });
    const assets = ["services", "agents", "domains", "sessions", "search", "missing"].map(kind => `/illustrations/mole-${kind}.webp`);
    assets.push("/brand/mole-head.webp", "/brand/nexo-banner-light.webp", "/brand/nexo-banner-dark.webp", "/brand/avatar-admin.webp", "/brand/avatar-user.webp", "/brand/pwa-launch.webp", "/pwa-192x192.png", "/pwa-512x512.png", "/pwa-maskable-512x512.png", "/apple-touch-icon.png", "/favicon-16.png", "/favicon-32.png");
    const cached = await page.evaluate(async () => {
      const keys = await caches.keys();
      const requests = await Promise.all(keys.map(async key => (await caches.open(key)).keys()));
      return requests.flat().map(request => new URL(request.url).pathname);
    });
    expect(cached).toEqual(expect.arrayContaining(assets));
    expect(cached.some(path => path.startsWith("/api/"))).toBeFalsy();
    await context.setOffline(true);
    const loaded = await page.evaluate(async assets => Promise.all(assets.map(async asset => {
      const response = await fetch(asset); const blob = await response.blob();
      return response.ok && blob.size > 0 && blob.type.startsWith("image/");
    })), assets);
    expect(loaded.every(Boolean)).toBeTruthy();
    await page.reload();
    await expect.poll(() => page.locator(".brand-icon").evaluate(image => (image as HTMLImageElement).naturalWidth)).toBe(256);
    await context.setOffline(false);
  });
});

test("桌面账号入口显示本人头像，代管空间保留本人身份且列表保持单行", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面品牌入口集中验收");
  const state = await installApiMocks(page);
  state.users[1].username = "alice-with-a-very-long-account-name-for-layout";
  await page.goto("/#/users");

  const banner = page.locator(".sidebar-brand img");
  await expect(banner).toBeVisible();
  await expect(banner).toHaveAttribute("src", "/brand/nexo-banner-light.webp");
  await expect.poll(() => banner.evaluate(image => (image as HTMLImageElement).naturalWidth)).toBe(600);
  await expect(page.locator(".sidebar-settings")).toBeVisible();
  await expect(page.locator(".sidebar-settings .user-avatar")).toHaveAttribute("data-avatar-role", "admin");
  await expect(active(page).locator(".user-card > .user-heading .user-avatar[data-avatar-role=admin]")).toHaveCount(1);
  await expect(active(page).locator(".user-card > .user-heading .user-avatar[data-avatar-role=user]")).toHaveCount(1);
  await expect.poll(() => active(page).locator(".user-card").evaluateAll(rows => rows.every(row => row.getBoundingClientRect().height <= 57))).toBeTruthy();
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("desktop-banner-and-avatars.png"), fullPage: true });

  await page.getByRole("button", { name: /管理 alice-with/ }).click();
  await expect(page.locator(".workspace-banner")).toContainText("alice 的工作空间");
  await page.locator(".sidebar-settings").click();
  await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
  await expect(page.locator(".sidebar-settings .user-avatar")).toHaveAttribute("data-avatar-role", "admin");
  await expect(page.locator(".account-menu-identity strong")).toHaveText("admin");
});

test("普通用户账号入口显示本人头像，菜单显示本人身份", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "角色切换集中验收");
  const state = await installApiMocks(page);
  state.authRole = "tenant";
  await page.goto("/#/manage");
  await expect(page.locator(".sidebar-settings")).toBeVisible();
  await expect(page.locator(".sidebar-settings .user-avatar")).toHaveAttribute("data-avatar-role", "user");
  await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
  await expect(page.locator(".account-menu-identity strong")).toHaveText("admin");
});
