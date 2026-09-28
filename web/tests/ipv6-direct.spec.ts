import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import { openServiceEditor } from "./service-actions";

test("直连与内网重定向互斥，多个 Agent 地址自动选择并直接保存", async ({ page }, info) => {
  const state = await installApiMocks(page);
  const ipv6 = { supported: true, addresses: ["2001:4860::1", "2400:3200::1"], selected_address: "2001:4860::1" };
  const addressWrites: string[] = [];
  await page.route("**/api/v1/devices/*/ipv6", async route => {
    if (route.request().method() !== "GET") addressWrites.push(route.request().method());
    await route.fulfill({ json: ipv6 });
  });
  await page.goto("/#/services"); await openServiceEditor(page);
  const form = page.getByRole("dialog", { name: "创建服务" });
  await form.getByLabel("服务名称").fill("直连媒体");
  await form.getByLabel("内网地址", { exact: true }).fill("192.168.1.10");
  await form.getByLabel("内网端口").fill("8096");
  await form.getByLabel("主机名").fill("emby");
  await form.getByLabel("HTTPS 端口").fill("9443");
  const direct = form.getByRole("switch", { name: "IPv6 直连" });
  await expect(direct).not.toBeChecked();
  await form.locator("summary", { hasText: "高级设置" }).click();
  const lan = form.getByRole("switch", { name: "内网重定向" });
  await lan.check(); await expect(direct).toBeDisabled(); await lan.uncheck();
  await direct.check(); await expect(lan).toBeDisabled();
  await expect(form.getByRole("status")).toContainText("自动选择公网 IPv6：2001:4860::1");
  await expect(form.getByRole("combobox", { name: "公网 IPv6" })).toHaveCount(0);
  await expect(form.getByText(/IPv4 转发，IPv6 直连/)).toBeVisible();
  await form.screenshot({ path: info.outputPath("ipv6-direct-form.png") });
  await form.getByRole("button", { name: "保存服务" }).click(); await expect(form).toBeHidden();
  expect(state.calls.find(call => call.method === "POST" && call.path.endsWith("/tunnels"))?.body).toMatchObject({ https_port: 9443, ipv6_direct_enabled: true, lan_redirect_enabled: false });
  expect(addressWrites).toEqual([]);
});

test("Agent 暂无公网 IPv6 时可保存并等待自动检测", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.route("**/api/v1/devices/*/ipv6", route => route.fulfill({ json: { supported: true, addresses: [], selected_address: null } }));
  await page.goto("/#/services"); await openServiceEditor(page);
  const form = page.getByRole("dialog", { name: "创建服务" });
  await form.getByLabel("服务名称").fill("等待地址"); await form.getByLabel("内网端口").fill("8096"); await form.getByLabel("主机名").fill("pending");
  await form.getByRole("switch", { name: "IPv6 直连" }).check();
  await expect(form.getByRole("status")).toContainText("等待 Agent 自动检测公网 IPv6");
  await form.getByRole("button", { name: "保存服务" }).click(); await expect(form).toBeHidden();
  expect(state.calls.find(call => call.method === "POST" && call.path.endsWith("/tunnels"))?.body).toMatchObject({ ipv6_direct_enabled: true });
});

test("旧 Agent 阻止开启直连但仍允许普通 HTTPS 转发", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.route("**/api/v1/devices/*/ipv6", route => route.fulfill({ json: { supported: false, addresses: [], selected_address: null } }));
  await page.goto("/#/services"); await openServiceEditor(page);
  const form = page.getByRole("dialog", { name: "创建服务" });
  await form.getByLabel("服务名称").fill("旧 Agent"); await form.getByLabel("内网端口").fill("8096"); await form.getByLabel("主机名").fill("old");
  await form.getByRole("switch", { name: "IPv6 直连" }).check();
  await form.getByRole("button", { name: "保存服务" }).click();
  await expect(form.getByRole("alert")).toContainText("请连接或升级 Agent");
  expect(state.calls.filter(call => call.method === "POST")).toHaveLength(0);
  await form.getByRole("switch", { name: "IPv6 直连" }).uncheck();
  await form.getByRole("button", { name: "保存服务" }).click(); await expect(form).toBeHidden();
});

test("转发额度耗尽与直连未验证状态分别展示", async ({ page }) => {
  const state = await installApiMocks(page);
  const service = state.tunnels[0];
  Object.assign(service, { ipv6_direct_enabled: true, https_port: 9443, apply_status: "checking", apply_error: "本月流量额度已用尽，隧道转发已暂停", direct_status: { status: "configured", address: "2001:4860::1", public_reachability: "unverified", certificate_expires_at: Math.floor(Date.now() / 1000) + 86400 } });
  await page.goto(`/#/services/${service.id}`);
  await expect(page.getByText("已配置，公网未验证", { exact: true })).toBeVisible();
  await page.getByText("技术详情", { exact: true }).click();
  await expect(page.getByText("本月流量额度已用尽，隧道转发已暂停", { exact: true })).toBeVisible();
  await expect(page.getByText(/证书到期：/)).toBeVisible();
});

for (const provider of ["alidns", "tencentcloud"]) test(`${provider} 凭据字段与请求匹配且保存后不回显`, async ({ page }) => {
  const state = await installApiMocks(page); let submitted: Record<string, string> | null = null;
  await page.route("**/api/v1/public-domains/d-1/dns-credential", async route => {
    submitted = route.request().postDataJSON();
    Object.assign(state.domains[0], { certificate_mode: "cloudflare_dns", dns_provider: provider, credential_configured: true });
    await route.fulfill({ json: state.domains[0] });
  });
  await page.goto("/#/domains"); await page.getByRole("button", { name: "配置 example.com", exact: true }).click();
  const form = page.getByRole("dialog", { name: "配置 example.com" });
  await form.getByLabel("证书方式").selectOption("cloudflare_dns"); await form.getByLabel("DNS 服务商").selectOption(provider);
  await form.getByLabel(provider === "alidns" ? "AccessKeyId" : "SecretId", { exact: true }).fill("test-id");
  await form.getByLabel(provider === "alidns" ? "AccessKeySecret" : "SecretKey", { exact: true }).fill("test-secret");
  await form.getByRole("button", { name: "验证并启用" }).click(); await expect(form.getByText(/· 已配置/)).toBeVisible();
  expect(submitted).toEqual(provider === "alidns" ? { provider, access_key_id: "test-id", access_key_secret: "test-secret" } : { provider, secret_id: "test-id", secret_key: "test-secret" });
  await expect(form.locator('input[type="password"]')).toHaveCount(0);
});
