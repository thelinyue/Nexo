import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { isLanRedirectAddress } from "../src/lan-redirect";
import { installApiMocks } from "./api-mocks";

async function createWebService(page: Page) {
  await page.goto("/#/services");
  await page.getByRole("button", { name: "创建服务", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await dialog.getByRole("radio", { name: "网页服务", exact: true }).check();
  await dialog.getByLabel("服务名称").fill("内网相册");
  await dialog.getByLabel("内网端口").fill("8080");
  await dialog.getByLabel("主机名").fill("photos");
  return dialog;
}

test("内网重定向开关可点击标签及空格切换，减弱动态效果仍有状态反馈", async ({ page }, info) => {
  await installApiMocks(page);
  const dialog = await createWebService(page);
  await dialog.getByLabel("内网地址", { exact: true }).fill("192.168.1.10");
  const toggle = dialog.getByRole("switch", { name: "内网重定向" });
  await expect(toggle).not.toBeChecked();
  const box = await toggle.boundingBox();
  expect(box!.width).toBeGreaterThanOrEqual(44);
  expect(box!.height).toBeGreaterThanOrEqual(44);
  await dialog.getByText("内网重定向", { exact: true }).click();
  await expect(toggle).toBeChecked();
  await toggle.focus();
  await toggle.press("Space");
  await expect(toggle).not.toBeChecked();
  await page.emulateMedia({ reducedMotion: "reduce" });
  await toggle.press("Space");
  await expect(toggle).toBeChecked();
  await expect(dialog.locator(".service-switch-track")).toHaveCSS("transition-duration", "0s");
  await page.screenshot({ path: info.outputPath("redirect-switch-on.png"), animations: "disabled" });
});

test("新建 Web 服务默认关闭内网重定向，旧记录缺失字段也按关闭展示", async ({ page }) => {
  const state = await installApiMocks(page);
  delete state.tunnels[0].lan_redirect_enabled;
  await page.goto("/#/services/t-1");
  await expect(page.locator(".detail-field", { has: page.getByText("内网重定向", { exact: true }) })).toContainText("未开启");
  const dialog = await createWebService(page);
  await expect(dialog.getByRole("switch", { name: "内网重定向" })).not.toBeChecked();
  await expect(dialog.getByLabel("内网地址", { exact: true })).toHaveCount(1);
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).not.toBeVisible();
  const body = state.calls.find(item => item.method === "POST" && item.path === "/api/v1/tunnels")!.body;
  expect(body.lan_redirect_enabled).toBe(false);
  expect(body).not.toHaveProperty("lan_redirect_url");
});

test("重定向仅使用本地目标，修改内网地址和端口后继续启用", async ({ page }) => {
  const state = await installApiMocks(page);
  const dialog = await createWebService(page);
  await dialog.getByLabel("内网地址").fill("192.168.1.10");
  await dialog.getByRole("switch", { name: "内网重定向" }).check();
  await expect(dialog.getByLabel("内网地址", { exact: true })).toHaveCount(1);
  const httpNotice = dialog.getByText("部分浏览器访问 HTTP 域名时无法触发重定向，建议使用 HTTPS。", { exact: true });
  await expect(httpNotice).toHaveCount(0);
  await dialog.getByLabel("公网协议").selectOption("http");
  await expect(httpNotice).toBeVisible();
  await dialog.getByLabel("公网协议").selectOption("https");
  await expect(httpNotice).toHaveCount(0);
  await dialog.getByLabel("主机名").press("Enter");
  await expect(dialog.getByLabel("主机名")).not.toBeFocused();
  await expect(dialog.getByRole("switch", { name: "内网重定向" })).not.toBeFocused();
  expect(state.calls.some(item => item.method === "POST")).toBe(false);
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).not.toBeVisible();
  const body = state.calls.find(item => item.method === "POST" && item.path === "/api/v1/tunnels")!.body;
  expect(body.lan_redirect_enabled).toBe(true);
  expect(body.local_address).toBe("192.168.1.10");
  expect(body.local_port).toBe(8080);
  expect(body).not.toHaveProperty("lan_redirect_url");
  await page.getByRole("link", { name: "内网相册", exact: true }).click();
  await expect(page.locator(".detail-field", { has: page.getByText("内网重定向", { exact: true }) })).toContainText("已开启");
  await expect(page.getByText("内网地址", { exact: true })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "复制内网地址" })).toHaveCount(1);
  await page.getByRole("button", { name: "编辑服务" }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await expect(editor.getByRole("switch", { name: "内网重定向" })).toBeChecked();
  await expect(editor.getByLabel("内网地址")).toHaveValue("192.168.1.10");
  await expect(editor.getByLabel("内网地址", { exact: true })).toHaveCount(1);
  await editor.getByLabel("内网地址").fill("192.168.1.20");
  await editor.getByLabel("内网端口").fill("9090");
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).not.toBeVisible();
  const update = state.calls.find(item => item.method === "PUT")!.body;
  expect(update).toMatchObject({ lan_redirect_enabled: true, local_address: "192.168.1.20", local_port: 9090 });
  expect(update).not.toHaveProperty("lan_redirect_url");
});

test("回环和主机名不能开启，错误定位内网地址且修正为 ULA 后可保存", async ({ page }) => {
  const state = await installApiMocks(page);
  const dialog = await createWebService(page);
  const toggle = dialog.getByRole("switch", { name: "内网重定向" });
  await toggle.check();
  const address = dialog.getByLabel("内网地址");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(address).toBeFocused();
  await expect(address).toHaveAttribute("aria-invalid", "true");
  await expect(dialog.getByRole("alert")).toContainText("回环地址和主机名不能供浏览器直连");
  await toggle.uncheck();
  await expect(dialog.getByRole("alert")).toHaveCount(0);
  await dialog.getByLabel("内网地址").fill("nas.local");
  await toggle.check();
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(address).toBeFocused();
  await expect(dialog.getByRole("alert")).toContainText("回环地址和主机名不能供浏览器直连");
  expect(state.calls.some(item => item.method === "POST")).toBe(false);
  await address.fill("[fd00:abcd::10]");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).not.toBeVisible();
  expect(state.calls.find(item => item.method === "POST")!.body).toMatchObject({ local_address: "[fd00:abcd::10]", lan_redirect_enabled: true });
});

test("关闭重定向后可继续使用回环本地目标", async ({ page }) => {
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], { lan_redirect_enabled: true, local_address: "192.168.1.10" });
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务" }).click();
  const dialog = page.getByRole("dialog", { name: "编辑服务" });
  const toggle = dialog.getByRole("switch", { name: "内网重定向" });
  await expect(toggle).toBeChecked();
  await dialog.getByLabel("内网地址").fill("127.0.0.1");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog.getByLabel("内网地址")).toBeFocused();
  await toggle.uncheck();
  await expect(dialog.getByRole("alert")).toHaveCount(0);
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).not.toBeVisible();
  expect(state.tunnels[0].lan_redirect_enabled).toBe(false);
  expect(state.tunnels[0].local_address).toBe("127.0.0.1");
  await expect(page.getByRole("button", { name: "复制内网地址" })).toHaveCount(1);
  await page.getByRole("button", { name: "编辑服务" }).click();
  await expect(toggle).not.toBeChecked();
  await expect(dialog.getByLabel("内网地址")).toHaveValue("127.0.0.1");
  expect(state.calls.find(item => item.method === "PUT")!.body).not.toHaveProperty("lan_redirect_url");
});

test("切换 TCP 清除内网重定向，重新切回 Web 保持关闭", async ({ page }) => {
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], { lan_redirect_enabled: true, local_address: "192.168.1.10" });
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务" }).click();
  const dialog = page.getByRole("dialog", { name: "编辑服务" });
  await dialog.getByRole("radio", { name: "TCP 服务", exact: true }).check();
  await expect(dialog.getByRole("switch", { name: "内网重定向" })).toHaveCount(0);
  await dialog.getByRole("radio", { name: "网页服务", exact: true }).check();
  await expect(dialog.getByRole("switch", { name: "内网重定向" })).not.toBeChecked();
  await dialog.getByRole("switch", { name: "内网重定向" }).check();
  await expect(dialog.getByLabel("内网地址", { exact: true })).toHaveCount(1);
  await dialog.getByRole("radio", { name: "TCP 服务", exact: true }).check();
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).not.toBeVisible();
  expect(state.tunnels[0].lan_redirect_enabled).toBe(false);
  expect(state.calls.find(item => item.method === "PUT")!.body).not.toHaveProperty("lan_redirect_url");
  await expect(page.getByText("内网重定向", { exact: true })).toHaveCount(0);
});

test("地址修改受未保存保护，保存中禁用控件且请求失败保留输入", async ({ page }) => {
  await installApiMocks(page);
  let releaseRequest = () => {};
  const pending = new Promise<void>(resolve => { releaseRequest = resolve; });
  await page.route("**/api/v1/tunnels/t-1", async route => {
    if (route.request().method() !== "PUT") return route.fallback();
    await pending;
    return route.fulfill({ status: 503, json: { error: "暂时无法保存" } });
  });
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务" }).click();
  const dialog = page.getByRole("dialog", { name: "编辑服务" });
  const toggle = dialog.getByRole("switch", { name: "内网重定向" });
  await toggle.check();
  await dialog.getByLabel("内网地址").fill("10.0.0.4");
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  const discard = page.getByRole("dialog", { name: "放弃未保存的修改？" });
  await expect(discard).toBeVisible();
  await discard.getByRole("button", { name: "取消" }).click();
  await dialog.getByRole("button", { name: "保存服务" }).click();
  try {
    await expect(toggle).toBeDisabled();
    await expect(dialog.getByLabel("内网地址")).toBeDisabled();
    await expect(dialog.getByRole("button", { name: "取消", exact: true })).toBeDisabled();
  } finally { releaseRequest(); }
  await expect(dialog.getByRole("alert")).toHaveText("暂时无法保存");
  await expect(toggle).toBeEnabled();
  await expect(dialog.getByLabel("内网地址")).toHaveValue("10.0.0.4");
});

test("仅显示重定向开关，长 IPv6 本地目标在当前视口内可操作", async ({ page }, testInfo) => {
  const state = await installApiMocks(page);
  const localAddress = "fd12:3456:789a:bcde:1234:5678:90ab:cdef";
  Object.assign(state.tunnels[0], { lan_redirect_enabled: true, local_address: localAddress, local_port: 65535 });
  await page.goto("/#/services/t-1");
  await expect(page.getByText("内网地址", { exact: true })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "复制内网地址" })).toHaveCount(1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("lan-redirect-detail.png"), fullPage: true });
  await page.getByRole("button", { name: "编辑服务" }).click();
  const dialog = page.getByRole("dialog", { name: "编辑服务" });
  await expect(dialog.getByLabel("内网地址", { exact: true })).toHaveCount(1);
  await expect(dialog.getByRole("switch", { name: "内网重定向" })).toBeChecked();
  const input = dialog.getByLabel("内网地址");
  await expect(input).toHaveValue(localAddress);
  await input.focus();
  await input.scrollIntoViewIfNeeded();
  await expect(input).toBeInViewport({ ratio: 1 });
  await expect(dialog.getByRole("button", { name: "保存服务" })).toBeInViewport({ ratio: 1 });
  const bounds = await input.boundingBox();
  const footer = await dialog.locator(".modal-actions").boundingBox();
  expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(footer!.y + 1);
  expect(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath("lan-redirect-editor.png") });
});

test("本地目标必须是完整私网 IP，拒绝 URL 和 IPv4 简写", async ({}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "纯 IP 规则只执行一次");
  for (const input of ["127.0.0.1", "::1", "localhost", "nas.local", "8.8.8.8", "100.64.0.1", "172.32.0.1", "169.254.1.1", "fe80::1", "2001:db8::1", "0.0.0.0", "::", "10.1", "0xa000001", "167772161", "010.0.0.1", "192.168.1.256", "http://192.168.1.2", "user@192.168.1.2", "192.168.1.2:8080", "192.168.1.2/photos", "192.168.1.2?", "192.168.1.2#", "192.168.1.2\\", "192.168.1.2\n", "192.168.1.2\u007f", "[192.168.1.2]", "[[fd00::1]]", "fd00::1]"]) {
    expect(isLanRedirectAddress(input), input).toBe(false);
  }
  for (const input of ["192.168.1.2", "10.0.0.1", "172.16.0.2", "172.31.255.254", "fc00::1", "fd00:abcd::1", "[fd00:abcd::1]", " fd00::1 "]) {
    expect(isLanRedirectAddress(input), input).toBe(true);
  }
});
