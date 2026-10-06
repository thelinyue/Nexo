import { openServiceEditor, selectServiceOption } from "./service-actions";
import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import type { Tunnel } from "../src/ui";

const proxy: Tunnel = { id: "proxy", service_mode: "reverse_proxy", name: "VPS 应用", protocol: "https", origin_protocol: "http", local_address: "127.0.0.1", local_port: 3000, hostname: "app", public_domain: "example.com", public_address: "https://app.example.com", device_id: null, enabled: true, apply_status: "ready", lan_redirect_enabled: false };

test("独立反代入口无需设备，创建服务入口保持内网穿透", async ({ page }, info) => {
  const state = await installApiMocks(page);
  state.tunnels = []; state.devices = [];
  await page.goto("/#/services");
  await expect(page.getByRole("button", { name: "创建服务", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "添加反向代理", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "添加反向代理" });
  await dialog.getByLabel("服务名称").fill("VPS 应用");
  await expect(dialog.getByRole("group", { name: "连接方式", exact: true })).toHaveCount(0);
  await dialog.getByLabel("目标端口").fill("3000");
  await expect(dialog.getByLabel("目标端口")).toHaveValue("3000");
  await expect(dialog.getByRole("combobox", { name: "设备", exact: true })).toHaveCount(0);
  await expect(dialog.getByLabel("内网重定向")).toHaveCount(0);
  await dialog.getByRole("combobox", { name: "目标协议", exact: true }).click();
  await expect(dialog.getByRole("listbox", { name: "目标协议选项" }).getByRole("option")).toHaveText(["HTTP", "HTTPS"]);
  await dialog.getByRole("combobox", { name: "目标协议", exact: true }).press("Escape");
  await dialog.getByLabel("主机名").fill("app");
  await page.screenshot({ path: info.outputPath("reverse-proxy-form.png"), animations: "disabled" });
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).toBeHidden();
  expect(state.calls.find(call => call.method === "POST" && call.path === "/api/v1/tunnels")?.body).toMatchObject({ service_mode: "reverse_proxy", device_id: null, protocol: "https", origin_protocol: "http", local_port: 3000, public_port: null, lan_redirect_enabled: false });
  await expect(page.locator(".page-slot:not([hidden]) .service-row")).toContainText("VPS 应用");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await expect(page.getByRole("button", { name: page.viewportSize()!.width <= 900 ? "添加" : "添加反向代理", exact: true })).toBeInViewport();
  await page.screenshot({ path: info.outputPath("separate-create-actions.png"), animations: "disabled" });
  await openServiceEditor(page);
  const tunnel = page.getByRole("dialog", { name: "创建服务", exact: true });
  await expect(tunnel.getByRole("combobox", { name: "设备", exact: true })).toBeVisible();
  await expect(tunnel.getByLabel("服务名称")).toHaveValue("");
  await expect(tunnel.getByRole("radio", { name: "反向代理", exact: true })).toHaveCount(0);
  await expect(tunnel.getByRole("button", { name: "保存服务", exact: true })).toBeDisabled();

});

test("手机添加入口紧邻底栏，选择类型后进入独立表单", async ({ page }, info) => {
  test.skip(info.project.name === "desktop-dark", "手机操作面板");
  await installApiMocks(page);
  await page.goto("/#/services");
  const add = page.getByRole("button", { name: "添加", exact: true });
  await expect(add).toBeInViewport();
  await expect(page.getByRole("button", { name: "添加反向代理", exact: true })).toHaveCount(0);
  const button = (await add.boundingBox())!;
  const navigation = (await page.locator(".bottom-nav").boundingBox())!;
  expect(button.width).toBe(52);
  expect(button.height).toBe(52);
  expect(button.x - navigation.x - navigation.width).toBeCloseTo(8, 0);
  expect(Math.abs(button.y + button.height / 2 - navigation.y - navigation.height / 2)).toBeLessThanOrEqual(1);
  await add.click();
  const sheet = page.getByRole("dialog", { name: "添加", exact: true });
  for (const name of ["创建服务", "添加反向代理"]) {
    const action = sheet.getByRole("button", { name, exact: true });
    await expect(action).toBeInViewport();
    expect((await action.boundingBox())!.height).toBeGreaterThanOrEqual(44);
  }
  const box = await sheet.boundingBox();
  expect(box!.y + box!.height).toBeCloseTo(page.viewportSize()!.height, 0);
  await page.screenshot({ path: info.outputPath("mobile-create-sheet.png"), animations: "disabled" });
  await page.keyboard.press("Escape");
  await expect(sheet).toBeHidden();
  await expect(add).toBeFocused();
  await add.click();
  await page.mouse.click(10, 10);
  await expect(sheet).toBeHidden();
  await expect(add).toBeFocused();
  await openServiceEditor(page, "reverse_proxy");
  const proxyForm = page.getByRole("dialog", { name: "添加反向代理" });
  await expect(proxyForm.getByRole("combobox", { name: "设备", exact: true })).toHaveCount(0);
  await proxyForm.getByRole("button", { name: "取消", exact: true }).click();
  await expect(add).toBeFocused();
  await openServiceEditor(page);
  await expect(page.getByRole("dialog", { name: "创建服务" }).getByRole("combobox", { name: "设备", exact: true })).toBeVisible();
});

test("反代详情解释已生效，编辑不绑定设备，混合批量操作保持权限边界", async ({ page }, info) => {
  const state = await installApiMocks(page); state.tunnels.push({ ...proxy });
  await page.goto("/#/services/proxy");
  await expect(page.locator(".service-detail")).toContainText("已生效");
  await expect(page.locator(".service-detail")).toContainText("不代表目标服务健康");
  await expect(page.locator(".service-detail")).not.toContainText("设备已连接");
  await expect(page.locator(".service-detail dt").filter({ hasText: /^设备$/ })).toHaveCount(0);
  await page.getByRole("button", { name: "编辑服务" }).click();
  const dialog = page.getByRole("dialog", { name: "编辑服务" });
  await expect(dialog.getByRole("radio", { name: "内网穿透", exact: true })).toHaveCount(0);
  await dialog.getByLabel("目标端口").fill("4000");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).toBeHidden();
  expect(state.calls.find(call => call.method === "PUT")?.body).toMatchObject({ service_mode: "reverse_proxy", device_id: null, local_port: 4000 });
  await expect(page.locator(".application-modal[open]")).toBeVisible();
  await expect(page.locator(".application-modal")).toHaveCSS("opacity", "1");
  await page.keyboard.press("Escape");
  await expect(page.locator(".application-modal")).toHaveCount(0);
  await expect(page).toHaveURL(/#\/services$/);
  const list = page.locator('[id="page-%23%2Fservices"]');
  await expect(list).toBeVisible();
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.getByRole("button", { name: "选择", exact: true }).press("Space");
  await page.getByRole("button", { name: "全选", exact: true }).click();
  await expect(page.getByRole("button", { name: "修改设备", exact: true })).toBeDisabled();
  await expect(page.getByText("选择中包含反向代理，不能修改设备。", { exact: true })).toBeVisible();
  await page.locator(".batch-actions").getByRole("button", { name: "关闭", exact: true }).click();
  await expect(page.locator(".page-slot:not([hidden]) .service-row").filter({ hasText: "VPS 应用" })).toContainText("已停用");
  expect(state.calls.some(call => call.path === "/api/v1/tunnels/batch/disable")).toBeTruthy();
  await page.screenshot({ path: info.outputPath("reverse-proxy-list.png"), animations: "disabled" });
  await page.locator(".batch-actions").getByRole("button", { name: "删除", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "删除服务", exact: true }).click();
  await expect(page.locator(".page-slot:not([hidden]) .service-row")).toHaveCount(0);
  expect(state.calls.some(call => call.path === "/api/v1/tunnels/batch" && call.method === "DELETE")).toBeTruthy();
});

test("纯反代首页不要求接入设备且反代不出现在穿透统计筛选", async ({ page }) => {
  const state = await installApiMocks(page); state.tunnels = [{ ...proxy }]; state.devices = [];
  await page.goto("/#/home");
  await expect(page.locator(".home-summaries")).toContainText("穿透运行 0 · 反代生效 1");
  await expect(page.getByText("接入第一台设备", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "流量筛选", exact: true }).click();
  await page.getByLabel("统计用户", { exact: true }).selectOption("admin");
  await expect(page.getByLabel("统计隧道").locator("option")).toHaveCount(1);
  await expect(page.locator(".traffic-help")).toContainText("不含反向代理");
});

test("普通用户无需设备即可创建和管理授权节点反代", async ({ page }) => {
  const state = await installApiMocks(page); state.authRole = "tenant"; state.devices = []; state.tunnels = [];
  await page.route("**/api/v1/nodes", route => route.fulfill({ json: { nodes: [{ id: "own", name: "我的节点", approved: true, enabled: true, status: "online", reverse_proxy_supported: true, reverse_proxy_selectable: true }] } }));
  await page.goto("/#/services");
  await expect(page.getByRole("heading", { name: "服务", exact: true })).toBeVisible();
  await expect(page.locator(".service-row")).toHaveCount(state.tunnels.length);
  await openServiceEditor(page, "reverse_proxy");
  const dialog = page.getByRole("dialog", { name: "添加反向代理" });
  await expect(dialog.getByRole("combobox", { name: "回源节点", exact: true })).toContainText("我的节点");
  await expect(dialog.getByText("目标地址由所选节点访问，127.0.0.1 表示该节点本机。")).toBeVisible();
  await dialog.getByLabel("服务名称").fill("普通用户应用");
  await dialog.getByLabel("目标端口").fill("3000");
  await dialog.getByLabel("主机名").fill("app");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).toBeHidden();
  expect(state.calls.find(call => call.method === "POST" && call.path === "/api/v1/tunnels")?.body).toMatchObject({ node_ids: ["own"], distribution_mode: "single", device_id: null });
  await page.locator(".service-row").getByRole("link", { name: "普通用户应用", exact: true }).click();
  await expect(page.getByRole("button", { name: "编辑服务", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "关闭服务", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "删除服务", exact: true })).toBeEnabled();
});

test("普通用户仅能选择授权且支持反代的节点，无可选节点禁止保存", async ({ page }) => {
  const state = await installApiMocks(page); state.authRole = "tenant"; state.devices = [];
  await page.route("**/api/v1/nodes", route => route.fulfill({ json: { nodes: [
    { id: "local", name: "内置节点", approved: true, enabled: true, reverse_proxy_supported: true, reverse_proxy_selectable: false },
    { id: "old", name: "旧节点", approved: true, enabled: true, reverse_proxy_supported: false, reverse_proxy_selectable: true },
    { id: "pending", name: "待审批节点", approved: false, enabled: true, reverse_proxy_supported: true, reverse_proxy_selectable: true }
  ] } }));
  await page.goto("/#/services");
  await expect(page.getByRole("heading", { name: "服务", exact: true })).toBeVisible();
  await expect(page.locator(".service-row")).toHaveCount(state.tunnels.length);
  await openServiceEditor(page, "reverse_proxy");
  const dialog = page.getByRole("dialog", { name: "添加反向代理" });
  await expect(dialog.getByText("没有可选节点，请先获得管理员审批、反向代理授权或升级节点。")).toBeVisible();
  await expect(dialog.getByRole("button", { name: "保存服务" })).toBeDisabled();
});

test("反向代理默认强制 HTTPS，切换协议保留选择，编辑读取保存值", async ({ page }) => {
  const state = await installApiMocks(page); state.tunnels = [];
  await page.goto("/#/services");
  await expect(page.getByRole("heading", { name: "服务", exact: true })).toBeVisible();
  await expect(page.locator(".service-row")).toHaveCount(state.tunnels.length);
  await openServiceEditor(page, "reverse_proxy");
  const dialog = page.getByRole("dialog", { name: "添加反向代理" });
  const force = dialog.getByRole("switch", { name: "强制 HTTPS" });
  await expect(force).toBeChecked();
  await force.uncheck();
  await selectServiceOption(dialog.getByRole("combobox", { name: "公网协议", exact: true }), "HTTP");
  await expect(force).toHaveCount(0);
  await selectServiceOption(dialog.getByRole("combobox", { name: "公网协议", exact: true }), "HTTPS");
  await expect(force).not.toBeChecked();
  await dialog.getByLabel("服务名称").fill("跳转应用");
  await dialog.getByLabel("目标端口").fill("3000");
  await dialog.getByLabel("主机名").fill("redirect");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).toBeHidden();
  expect(state.calls.find(call => call.method === "POST" && call.path.endsWith("/tunnels"))?.body).toMatchObject({ http_redirect_enabled: false });
  const created = state.tunnels.find(item => item.name === "跳转应用")!;
  await page.goto(`/#/services/${created.id}`);
  await page.getByRole("button", { name: "编辑服务" }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await expect(editor.getByRole("switch", { name: "强制 HTTPS" })).not.toBeChecked();
  await editor.getByRole("switch", { name: "强制 HTTPS" }).check();
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.calls.find(call => call.method === "PUT")?.body).toMatchObject({ http_redirect_enabled: true });
});

test("管理员在内置节点配置明确分配反代权限", async ({ page }) => {
  const state = await installApiMocks(page);
  const node = { id: "local", name: "内置节点", public_ipv4: "", control_port: 9891, approved: true, enabled: true, registered: true, status: "online", connections: 0, services: [], latencies: [], workspace_ids: [] as string[] };
  await page.route("**/api/v1/nodes", route => route.fulfill({ json: { nodes: [node] } }));
  await page.route("**/api/v1/nodes/local", async route => {
    if (route.request().method() === "PUT") { const body = route.request().postDataJSON(); state.calls.push({ method: "PUT", path: "/api/v1/nodes/local", body }); node.workspace_ids = body.workspace_ids; }
    await route.fulfill({ json: node });
  });
  await page.goto("/#/nodes");
  await page.getByRole("button", { name: /内置节点/ }).click();
  const dialog = page.getByRole("dialog", { name: "内置节点", exact: true });
  await dialog.getByRole("tab", { name: "配置", exact: true }).click();
  await expect(dialog.getByText("为以下工作空间授权内置节点反向代理，包括访问 Server 本机及其可达内网。穿透权限不受影响。")).toBeVisible();
  await dialog.getByRole("checkbox", { name: /alice/ }).check();
  await dialog.getByRole("button", { name: "保存配置", exact: true }).click();
  await expect(dialog).toBeHidden();
  expect(state.calls.find(call => call.method === "PUT" && call.path === "/api/v1/nodes/local")?.body.workspace_ids).toEqual(["alice-space"]);
});
