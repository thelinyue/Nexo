import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import { openServiceEditor } from "./service-actions";

test("UDP 与组合服务不依赖域名，表单和详情在小屏可用", async ({ page }, info) => {
  const state = await installApiMocks(page);
  state.domains = [];
  await page.goto("/#/services");
  await openServiceEditor(page);
  const editor = page.getByRole("dialog", { name: "创建服务" });
  await editor.getByLabel("内网协议").selectOption("udp");
  await expect(editor.getByLabel("主机名", { exact: true })).toHaveCount(0);
  await expect(editor.getByText("访问规则", { exact: true })).toHaveCount(0);
  await editor.getByLabel("内网协议").selectOption("tcp_udp");
  await editor.getByLabel("服务名称", { exact: true }).fill("远程桌面");
  await editor.getByLabel("内网地址", { exact: true }).fill("192.168.1.100");
  await editor.getByLabel("内网端口", { exact: true }).fill("3389");
  await editor.locator("summary").filter({ hasText: "公网端口" }).click();
  await editor.getByLabel("公网端口", { exact: true }).fill("20023");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("udp-editor.png") });
  const request = page.waitForRequest(r => r.url().endsWith("/api/v1/tunnels") && r.method() === "POST");
  await editor.getByRole("button", { name: "保存服务" }).click();
  expect((await request).postDataJSON()).toMatchObject({ protocol: "tcp_udp", local_port: 3389, public_port: 20023, hostname: null, public_domain_id: null, access_mode: "public", lan_redirect_enabled: false });
});

test("组合服务展示分协议状态，UDP 地址只复制并支持独立筛选", async ({ page }, info) => {
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], { protocol: "tcp_udp", public_domain: null, public_address: "example.com:20023", apply_status: "partial", apply_error: "UDP 数据通道未连接", protocol_statuses: { tcp: { status: "ready", error_message: null }, udp: { status: "checking", error_message: "UDP 数据通道未连接" } } });
  state.tunnels.push({ ...state.tunnels[0], id: "udp", name: "UDP 应用", protocol: "udp" });
  await page.goto("/#/services");
  await page.getByLabel("类型筛选").selectOption("udp");
  await expect(page.locator(".service-row")).toHaveCount(1);
  await expect(page.locator(".service-row .service-name")).toHaveText("UDP 应用");
  await page.getByLabel("类型筛选").selectOption("tcp_udp");
  await expect(page.locator(".service-row")).toHaveCount(1);
  await expect(page.getByText("部分可用", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  await expect(page.locator(".detail-field", { has: page.locator("dt", { hasText: /^TCP$/ }) }).getByText("运行中")).toBeVisible();
  await expect(page.locator(".detail-field", { has: page.locator("dt", { hasText: /^UDP$/ }) }).getByText("检查中")).toBeVisible();
  await expect(page.getByRole("link", { name: "example.com:20023" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "复制公网地址" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("udp-partial.png") });
  await page.getByRole("button", { name: "编辑服务" }).click();
  await expect(page.getByLabel("内网协议")).toHaveValue("tcp_udp");
});
