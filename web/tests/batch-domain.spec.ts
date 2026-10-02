import { expect, test, type Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

async function openBatchDomain(page: Page) {
  await page.goto("/#/services");
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.getByRole("button", { name: "选择", exact: true }).press("Space");
  await page.getByRole("button", { name: "全选", exact: true }).click();
  await page.getByRole("button", { name: "修改域名", exact: true }).click();
  return page.getByRole("dialog", { name: "批量修改域名", exact: true });
}

test("批量更换根域名保留最新配置，跳过无域名项，同域名不提交，部分失败只重试失败项", async ({ page }, info) => {
  const state = await installApiMocks(page);
  state.domains.push({ ...state.domains[0], id: "d-2", domain: "new.example.com", is_primary: false });
  Object.assign(state.tunnels[0], { public_address: "https://media.example.com:8443", https_port: 8443, icon_id: "border-radius/emby-1.png", origin_protocol: "https", enabled: false, access_mode: "password", ipv6_direct_enabled: true, node_ids: ["local", "node-1"], node_group_id: "group-1", distribution_mode: "manual", preferred_node_id: "node-1" });
  state.tunnels.push(
    { ...state.tunnels[0], id: "t-2", name: "TCP 应用", protocol: "tcp", hostname: "tcp", public_port: 23456, public_address: "tcp.example.com:23456", ipv6_direct_enabled: false, access_mode: "public" },
    { ...state.tunnels[0], id: "proxy", name: "VPS 应用", hostname: "app", public_address: "https://app.example.com:8443", service_mode: "reverse_proxy", device_id: null, http_redirect_enabled: true, ipv6_direct_enabled: false, node_ids: ["local"] },
    { ...state.tunnels[0], id: "udp", name: "无域名 UDP", protocol: "udp", public_domain: null, hostname: null, public_address: "127.0.0.1:23457", public_port: 23457, ipv6_direct_enabled: false },
    { ...state.tunnels[0], id: "same", name: "已使用目标域名", hostname: "existing", public_domain: "new.example.com", public_address: "https://existing.new.example.com:8443" },
    { ...state.tunnels[0], id: "http", name: "HTTP 跳转", protocol: "http", hostname: "redirect", public_address: "http://redirect.example.com:8080", lan_redirect_enabled: true, ipv6_direct_enabled: false },
  );
  const dialog = await openBatchDomain(page);
  await expect(dialog).toContainText("待修改 5 个服务");
  await expect(dialog).toContainText("已跳过 1 个无域名服务");
  await dialog.getByRole("radio", { name: "new.example.com", exact: true }).check();
  await expect(dialog).toContainText("→ https://media.new.example.com:8443");
  await expect(dialog).toContainText("→ tcp.new.example.com:23456");
  await expect(dialog).toContainText("→ http://redirect.new.example.com:8080");
  await page.screenshot({ path: info.outputPath("batch-domain-editor.png"), animations: "disabled" });
  // 模拟弹窗打开后配置被其他操作更新，提交必须以最新列表为准。
  Object.assign(state.tunnels[0], { name: "最新媒体中心", local_port: 9443, local_address: "192.168.1.10" });
  state.failures.set("PUT /api/v1/tunnels/t-2", "该服务域名已被使用");
  await dialog.getByRole("button", { name: "保存修改", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("TCP 应用：该服务域名已被使用");
  await expect(dialog.getByRole("status")).toContainText("已完成 4 / 5 项");
  await expect(dialog.getByRole("radio", { name: "example.com", exact: true })).toBeDisabled();
  const body = state.calls.find(call => call.method === "PUT" && call.path === "/api/v1/tunnels/t-1")!.body;
  expect(body).toMatchObject({ name: "最新媒体中心", local_port: 9443, local_address: "192.168.1.10", public_domain_id: "d-2", hostname: "media", origin_protocol: "https", https_port: 8443, enabled: false, access_mode: "password", ipv6_direct_enabled: true });
  for (const field of ["icon_id", "access_password", "node_ids", "node_group_id", "distribution_mode", "preferred_node_id"]) expect(body).not.toHaveProperty(field);
  expect(state.tunnels[0]).toMatchObject({ icon_id: "border-radius/emby-1.png", node_ids: ["local", "node-1"], node_group_id: "group-1", distribution_mode: "manual", preferred_node_id: "node-1", public_domain: "new.example.com" });
  expect(state.calls.find(call => call.method === "PUT" && call.path === "/api/v1/tunnels/proxy")!.body).toMatchObject({ service_mode: "reverse_proxy", device_id: null, http_redirect_enabled: true, hostname: "app" });
  expect(state.calls.find(call => call.method === "PUT" && call.path === "/api/v1/tunnels/http")!.body).toMatchObject({ lan_redirect_enabled: true, protocol: "http" });
  expect(state.calls.filter(call => call.method === "PUT" && ["/api/v1/tunnels/udp", "/api/v1/tunnels/same"].includes(call.path))).toHaveLength(0);
  state.failures.delete("PUT /api/v1/tunnels/t-2");
  await dialog.getByRole("button", { name: "重试未完成项", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(state.calls.filter(call => call.method === "PUT" && call.path === "/api/v1/tunnels/t-1")).toHaveLength(1);
  expect(state.calls.filter(call => call.method === "PUT" && call.path === "/api/v1/tunnels/t-2")).toHaveLength(2);
  expect(state.calls.find(call => call.method === "PUT" && call.path === "/api/v1/tunnels/t-2")!.body).toMatchObject({ protocol: "tcp", public_port: 23456, hostname: "tcp", public_domain_id: "d-2", origin_protocol: null });
  await expect(page.locator(".batch-actions")).toContainText("已选择 0 项");
  await expect(page.locator(".page-slot:not([hidden])")).toContainText("已保存 5 个服务的域名配置，跳过 1 个无域名服务");
});

test("无可修改项禁用入口；未验证域名不可选择，无可选域名给出指引", async ({ page }) => {
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], { protocol: "udp", public_domain: null, hostname: null });
  await page.goto("/#/services");
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.getByRole("button", { name: "选择", exact: true }).press("Space");
  await page.getByRole("button", { name: "全选", exact: true }).click();
  await expect(page.getByRole("button", { name: "修改域名", exact: true })).toBeDisabled();
  Object.assign(state.tunnels[0], { protocol: "https", public_domain: "example.com", hostname: "media" });
  state.domains[0].verification_status = "pending";
  await page.reload();
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.getByRole("button", { name: "选择", exact: true }).press("Space");
  await page.getByRole("button", { name: "全选", exact: true }).click();
  await page.getByRole("button", { name: "修改域名", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "批量修改域名" });
  await expect(dialog.getByRole("radio")).toHaveCount(0);
  await expect(dialog).toContainText("添加并验证根域名");
  await expect(dialog.getByRole("button", { name: "保存修改" })).toBeDisabled();
});

test("目标域名失效不提交；已删除服务报错，配置变为无域名服务时跳过", async ({ page }) => {
  const state = await installApiMocks(page);
  state.domains.push({ ...state.domains[0], id: "d-2", domain: "new.example.com" });
  state.tunnels.push({ ...state.tunnels[0], id: "deleted", name: "已删除服务" }, { ...state.tunnels[0], id: "unbound", name: "改为无域名服务" });
  const dialog = await openBatchDomain(page);
  await dialog.getByRole("radio", { name: "new.example.com", exact: true }).check();
  const removedDomain = state.domains.pop()!;
  await dialog.getByRole("button", { name: "保存修改" }).click();
  await expect(dialog.getByRole("alert")).toContainText("目标域名已不存在或未完成验证");
  expect(state.calls.filter(call => call.method === "PUT")).toHaveLength(0);
  state.domains.push({ ...removedDomain, verification_status: "pending" });
  await dialog.getByRole("button", { name: "重试未完成项" }).click();
  await expect(dialog.getByRole("alert")).toContainText("目标域名已不存在或未完成验证");
  expect(state.calls.filter(call => call.method === "PUT")).toHaveLength(0);
  state.domains[1].verification_status = "verified";
  state.tunnels = state.tunnels.filter(item => item.id !== "deleted");
  Object.assign(state.tunnels.find(item => item.id === "unbound")!, { protocol: "tcp", public_domain: null, hostname: null });
  await dialog.getByRole("button", { name: "重试未完成项" }).click();
  await expect(dialog.getByRole("alert")).toContainText("已删除服务：服务已不存在");
  await expect(dialog).toContainText("已跳过 1 个无域名服务");
  expect(state.calls.filter(call => call.method === "PUT")).toHaveLength(1);
});

test("缺少 DNS 凭据的失败项保留，允许其他服务完成", async ({ page }) => {
  const state = await installApiMocks(page);
  state.domains.push({ ...state.domains[0], id: "d-2", domain: "new.example.com", credential_configured: false });
  state.tunnels.push({ ...state.tunnels[0], id: "http", name: "HTTP 服务", hostname: "web", protocol: "http" });
  state.failures.set("PUT /api/v1/tunnels/t-1", "请先验证并保存域名的 DNS 凭据");
  const dialog = await openBatchDomain(page);
  await dialog.getByRole("radio", { name: "new.example.com", exact: true }).check();
  await dialog.getByRole("button", { name: "保存修改" }).click();
  await expect(dialog.getByRole("alert")).toContainText("媒体中心：请先验证并保存域名的 DNS 凭据");
  await expect(dialog.getByRole("status")).toContainText("已完成 1 / 2 项");
  expect(state.tunnels.find(item => item.id === "http")!.public_domain).toBe("new.example.com");
});

test("普通用户可修改穿透域名，混合反代选择保持管理员权限边界", async ({ page }) => {
  const state = await installApiMocks(page); state.authRole = "tenant";
  const dialog = await openBatchDomain(page);
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  state.tunnels.push({ ...state.tunnels[0], id: "proxy", name: "反代服务", service_mode: "reverse_proxy", device_id: null });
  await page.reload();
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.getByRole("button", { name: "选择", exact: true }).press("Space");
  await page.getByRole("button", { name: "全选", exact: true }).click();
  await expect(page.getByRole("button", { name: "修改域名", exact: true })).toBeDisabled();
});

test("弹窗键盘选择、布局、提交关闭保护与放弃草稿", async ({ page }, info) => {
  if (info.project.name === "mobile-light") await page.setViewportSize({ width: 320, height: 640 });
  const state = await installApiMocks(page);
  state.domains.push({ ...state.domains[0], id: "d-2", domain: "very-long-home-network-domain-for-small-screens.example.com" });
  const dialog = await openBatchDomain(page);
  const target = dialog.getByRole("radio", { name: state.domains[1].domain, exact: true });
  await target.focus(); await target.press("Space");
  await expect(target).toBeChecked();
  for (const button of await page.locator(".batch-commands button").all()) {
    const box = (await button.boundingBox())!;
    expect(box.width).toBeGreaterThanOrEqual(44);
    expect(box.height).toBeGreaterThanOrEqual(44);
  }
  const box = (await dialog.boundingBox())!;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(page.viewportSize()!.width);
  expect(box.y).toBeGreaterThanOrEqual(0);
  expect(box.y + box.height).toBeLessThanOrEqual(page.viewportSize()!.height + 1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await expect(dialog.getByRole("button", { name: "保存修改" })).toBeInViewport();
  await page.screenshot({ path: info.outputPath("batch-domain-long-domain.png"), animations: "disabled" });
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/api/v1/tunnels/t-1", async route => { await held; await route.fulfill({ status: 503, json: { error: "暂时无法保存" } }); });
  await dialog.getByRole("button", { name: "保存修改" }).click();
  await expect(dialog.getByRole("button", { name: "取消", exact: true })).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeVisible();
  release();
  await expect(dialog.getByRole("alert")).toContainText("暂时无法保存");
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "放弃修改", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("checkbox", { name: "选择媒体中心" })).toBeChecked();
  await expect(page.getByRole("button", { name: "修改域名", exact: true })).toBeFocused();
});
