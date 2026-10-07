import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { installApiMocks } from "./api-mocks";
import { openServiceEditor } from "./service-actions";

/** 浏览器禁用 SW 后走普通 HTTP 的检测路径；探测内容使用真实构建入口。 */
async function updateProbe(page: Page) {
  const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");
  const state = { html, status: 200, calls: 0, pending: null as null | (() => void) };
  await page.route("**/index.html?nexo-update-check=1", async route => {
    state.calls++;
    if (state.pending) await new Promise<void>(resolve => { state.pending = resolve; });
    await route.fulfill({ status: state.status, contentType: "text/html", body: state.html });
  });
  return { state, deploy: () => { state.html = html.replace(/(<script[^>]+type="module"[^>]+src=")([^"]+)/, "$1$2?release=next"); } };
}

const notice = (page: Page) => page.getByRole("complementary", { name: "网页更新" });
const check = (page: Page) => page.evaluate(() => window.dispatchEvent(new Event("online")));

test("新版仅提示，支持键盘刷新并保持路由和登录", async ({ page }, info) => {
  await installApiMocks(page); const probe = await updateProbe(page);
  await page.goto("/#/settings/server");
  await expect.poll(() => probe.state.calls).toBeGreaterThan(0);
  await expect(notice(page)).toHaveCount(0);
  await page.evaluate(() => { document.documentElement.dataset.sameDocument = "yes"; });
  probe.deploy(); await check(page);
  await expect(notice(page)).toContainText("网页已更新，刷新后使用新版本。");
  expect(await page.evaluate(() => document.documentElement.dataset.sameDocument)).toBe("yes");
  await expect(page.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.7");
  expect(await notice(page).evaluate(el => { const box = el.getBoundingClientRect(); return box.left >= 0 && box.right <= innerWidth; })).toBeTruthy();
  await page.screenshot({ path: info.outputPath("web-update-notice.png"), animations: "disabled" });
  const refresh = notice(page).getByRole("button", { name: "刷新页面" });
  await refresh.focus(); await refresh.press("Enter");
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.sameDocument)).toBeUndefined();
  await expect(page).toHaveURL(/#\/settings\/server$/);
  await expect(page.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.7");
});

test("错误响应不误报，定时和返回前台检测，隐藏时暂停且合并并发请求", async ({ page }) => {
  await page.clock.install(); await installApiMocks(page); const probe = await updateProbe(page);
  probe.state.html = "<html><body>代理错误</body></html>";
  await page.goto("/#/settings/server");
  await expect.poll(() => probe.state.calls).toBeGreaterThan(0);
  await expect(notice(page)).toHaveCount(0);
  probe.state.status = 503; probe.deploy(); await check(page);
  await expect.poll(() => probe.state.calls).toBeGreaterThan(1);
  await expect(notice(page)).toHaveCount(0);
  await page.evaluate(() => { Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" }); });
  const before = probe.state.calls; await page.clock.fastForward(5 * 60 * 1000); await check(page);
  expect(probe.state.calls).toBe(before);
  probe.state.status = 200;
  await page.evaluate(() => { Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" }); document.dispatchEvent(new Event("visibilitychange")); });
  await expect(notice(page)).toBeVisible();
  probe.state.pending = () => {};
  await page.evaluate(() => { window.dispatchEvent(new Event("focus")); window.dispatchEvent(new Event("online")); document.dispatchEvent(new Event("visibilitychange")); });
  await expect.poll(() => probe.state.calls).toBe(before + 2);
  probe.state.pending?.(); probe.state.pending = null;
  await expect.poll(async () => { await page.clock.fastForward(5 * 60 * 1000); return probe.state.calls; }).toBeGreaterThan(before + 2);
});

test("服务器设置草稿须确认放弃，弹窗和写入期间暂停刷新，失败后可重试", async ({ page }) => {
  const state = await installApiMocks(page); const probe = await updateProbe(page);
  await page.goto("/#/settings/server");
  await page.getByLabel("公网 IPv4", { exact: true }).fill("203.0.113.8");
  probe.deploy(); await check(page); await expect(notice(page)).toBeVisible();
  await notice(page).getByRole("button", { name: "刷新页面" }).click();
  const discard = page.getByRole("dialog", { name: "放弃未保存的修改？" });
  await expect(discard).toBeVisible();
  await discard.getByRole("button", { name: "取消", exact: true }).click();
  await expect(page.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.8");
  let release: (() => void) | undefined;
  await page.route("**/api/v1/admin/server-settings", async route => {
    if (route.request().method() !== "PUT") return route.fallback();
    await new Promise<void>(resolve => { release = resolve; });
    await route.fulfill({ status: 500, json: { error: "保存失败" } });
  });
  await page.getByRole("button", { name: "保存设置", exact: true }).click();
  await expect(notice(page).getByRole("button", { name: "刷新页面" })).toBeDisabled();
  release?.(); await expect(page.getByRole("alert")).toContainText("保存失败");
  await expect(notice(page).getByRole("button", { name: "刷新页面" })).toBeEnabled();
  await notice(page).getByRole("button", { name: "刷新页面" }).click();
  await page.evaluate(() => { document.documentElement.dataset.sameDocument = "yes"; });
  await discard.getByRole("button", { name: "放弃修改", exact: true }).click();
  await expect.poll(() => page.evaluate(() => document.documentElement.dataset.sameDocument)).toBeUndefined();
  await expect(page.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.7");
  expect(state.serverSettings.relay_ipv4).toBe("203.0.113.7");
  await notice(page).getByRole("button", { name: "稍后" }).click();
  await page.goto("/#/services");
  await expect(notice(page)).toHaveCount(0);
  await openServiceEditor(page);
  // 同一新版收起后不重复打扰；下一个新版仍需提示，且弹窗内不允许刷新。
  await check(page); await expect(notice(page)).toHaveCount(0);
  probe.state.html = probe.state.html.replace("release=next", "release=later");
  // 等上一轮合并请求结束再触发；WebKit 的响应读取可能晚于路由 fulfill。
  await expect.poll(async () => { await check(page); return page.locator(".web-update-notice").count(); }).toBe(1);
  await expect(page.locator(".web-update-notice .secondary-button")).toBeDisabled();
});

test("断网点击不刷新，恢复连接后可重新操作", async ({ page, context }) => {
  await installApiMocks(page); const probe = await updateProbe(page);
  await page.goto("/#/settings/server"); probe.deploy(); await check(page);
  await expect(notice(page)).toBeVisible();
  await context.setOffline(true);
  await notice(page).getByRole("button", { name: "刷新页面" }).click();
  await expect(notice(page).getByRole("alert")).toHaveText("网络已断开，请恢复连接后重试。");
  await context.setOffline(false);
  await expect(notice(page).getByRole("button", { name: "刷新页面" })).toBeEnabled();
});
