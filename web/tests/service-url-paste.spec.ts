import { expect, test, type Locator } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import { openServiceEditor, selectServiceOption } from "./service-actions";

const ignoredPartsMessage = "已填入协议、地址和端口，路径、参数和片段不会保存。";

/** 合成粘贴事件不执行默认插入；仅在表单未拦截时补上浏览器文本插入，覆盖普通粘贴行为。 */
async function pasteAddress(input: Locator, value: string) {
  await input.focus();
  return input.evaluate((element, text) => {
    const clipboardData = new DataTransfer();
    clipboardData.setData("text/plain", text);
    const event = new ClipboardEvent("paste", { bubbles: true, cancelable: true, clipboardData });
    if (element.dispatchEvent(event)) document.execCommand("insertText", false, text);
    return event.defaultPrevented;
  }, value);
}

for (const mode of ["tunnel", "reverse_proxy"] as const) {
  test(`创建 ${mode} 粘贴网址，编辑仍只保存连接信息`, async ({ page }) => {
    const state = await installApiMocks(page);
    const direct = mode === "reverse_proxy";
    await page.goto("/#/services");
    if (direct) await expect(page.getByRole("button", { name: page.viewportSize()!.width <= 900 ? "添加" : "添加反向代理", exact: true })).toBeVisible();
    await openServiceEditor(page, mode);
    const dialog = page.getByRole("dialog", { name: direct ? "添加反向代理" : "创建服务", exact: true });
    const addressLabel = direct ? "目标地址" : "内网地址";
    const portLabel = direct ? "目标端口" : "内网端口";
    const protocolLabel = direct ? "目标协议" : "内网协议";
    const address = dialog.getByLabel(addressLabel, { exact: true });
    await dialog.getByLabel("服务名称").fill("网址填充");
    await dialog.getByLabel("主机名").fill("paste");
    await selectServiceOption(dialog.getByRole("combobox", { name: protocolLabel, exact: true }), "HTTPS");
    await dialog.getByLabel(portLabel, { exact: true }).fill("9999");
    // 不选择原地址，成功识别的网址应替换整个字段，而不是拼接到回环地址后面。
    expect(await pasteAddress(address, "\u00a0 http://192.168.10.150:8089/ \u00a0")).toBe(true);
    await expect(address).toHaveValue("192.168.10.150");
    await expect(address).toBeFocused();
    await expect(dialog.getByRole("combobox", { name: protocolLabel, exact: true })).toHaveAttribute("value", "http");
    await expect(dialog.getByLabel(portLabel, { exact: true })).toHaveValue("8089");
    await expect(dialog.getByRole("combobox", { name: "公网协议", exact: true })).toHaveAttribute("value", "https");
    await expect(dialog.getByRole("combobox", { name: "根域名", exact: true })).toHaveAttribute("value", "d-1");
    await expect(dialog.getByText(ignoredPartsMessage)).toHaveCount(0);
    expect(state.calls.filter(call => ["POST", "PUT"].includes(call.method))).toHaveLength(0);
    await dialog.getByRole("button", { name: "保存服务", exact: true }).click();
    await expect(dialog).toBeHidden();
    expect(state.calls.find(call => call.method === "POST" && call.path === "/api/v1/tunnels")?.body).toMatchObject({ service_mode: mode, local_address: "192.168.10.150", origin_protocol: "http", local_port: 8089, protocol: "https", public_domain_id: "d-1", device_id: direct ? null : "a-1" });

    await page.goto("/#/services/t-new");
    await page.getByRole("button", { name: "编辑服务", exact: true }).click();
    const editor = page.getByRole("dialog", { name: "编辑服务", exact: true });
    const editedAddress = editor.getByLabel(addressLabel, { exact: true });
    expect(await pasteAddress(editedAddress, "https://[fd12:3456::150]:8443/web/?token=value#login")).toBe(true);
    await expect(editedAddress).toHaveValue("fd12:3456::150");
    await expect(editedAddress).toBeFocused();
    await expect(editor.getByRole("combobox", { name: protocolLabel, exact: true })).toHaveAttribute("value", "https");
    await expect(editor.getByLabel(portLabel, { exact: true })).toHaveValue("8443");
    await expect(editor.getByRole("status").filter({ hasText: ignoredPartsMessage })).toBeVisible();
    await expect(editor.getByRole("combobox", { name: "公网协议", exact: true })).toHaveAttribute("value", "https");
    expect(state.calls.filter(call => call.method === "PUT")).toHaveLength(0);
    await editor.getByRole("button", { name: "保存服务", exact: true }).click();
    await expect(editor).toBeHidden();
    expect(state.calls.find(call => call.method === "PUT" && call.path === "/api/v1/tunnels/t-new")?.body).toMatchObject({ service_mode: mode, local_address: "fd12:3456::150", origin_protocol: "https", local_port: 8443, protocol: "https", public_domain_id: "d-1", device_id: direct ? null : "a-1" });
  });
}

test("粘贴主机名和 IPv6 网址填入显式或默认端口，公网 HTTP 保持独立", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务", exact: true });
  await selectServiceOption(dialog.getByRole("combobox", { name: "公网协议", exact: true }), "HTTP");
  for (const [url, host, protocol, port] of [
    ["http://nas.local", "nas.local", "http", "80"],
    ["https://nas.local/", "nas.local", "https", "443"],
    ["HTTP://nas.local:80/", "nas.local", "http", "80"],
    ["https://nas.local:443/", "nas.local", "https", "443"],
    ["HTTPS://nas.local:9443/", "nas.local", "https", "9443"],
    ["http://[::1]:8089/", "::1", "http", "8089"],
  ]) {
    await dialog.getByLabel("内网端口", { exact: true }).fill("9999");
    expect(await pasteAddress(dialog.getByLabel("内网地址", { exact: true }), url)).toBe(true);
    await expect(dialog.getByLabel("内网地址", { exact: true })).toHaveValue(host);
    await expect(dialog.getByRole("combobox", { name: "内网协议", exact: true })).toHaveAttribute("value", protocol);
    await expect(dialog.getByLabel("内网端口", { exact: true })).toHaveValue(port);
    await expect(dialog.getByRole("combobox", { name: "公网协议", exact: true })).toHaveAttribute("value", "http");
  }
});

test("路径、参数和片段提示随再次粘贴或手动修改连接字段清除", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务", exact: true });
  const address = dialog.getByLabel("内网地址", { exact: true });
  const message = dialog.getByRole("status").filter({ hasText: ignoredPartsMessage });
  for (const suffix of ["/web/", "/?token=value", "/#login"]) {
    await pasteAddress(address, `http://nas.local:8089${suffix}`);
    await expect(message).toBeVisible();
    await expect(address).toHaveValue("nas.local");
    await pasteAddress(address, "http://nas.local:8089/");
    await expect(message).toHaveCount(0);
  }
  for (const field of ["address", "port", "protocol"]) {
    await pasteAddress(address, "http://nas.local:8089/web/");
    await expect(message).toBeVisible();
    if (field === "address") await address.fill("192.168.1.10");
    else if (field === "port") await dialog.getByLabel("内网端口", { exact: true }).fill("8090");
    else await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "HTTPS");
    await expect(message).toHaveCount(0);
  }
  await pasteAddress(address, "http://nas.local:8089/web/");
  await address.press("ControlOrMeta+A");
  expect(await pasteAddress(address, "192.168.1.10")).toBe(false);
  await expect(address).toHaveValue("192.168.1.10");
  await expect(message).toHaveCount(0);
});

test("普通地址、无效网址和带账号密码的网址保留原生粘贴，手动输入不触发拆分", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务", exact: true });
  const address = dialog.getByLabel("内网地址", { exact: true });
  const protocol = dialog.getByRole("combobox", { name: "内网协议", exact: true });
  await selectServiceOption(protocol, "HTTPS");
  await dialog.getByLabel("内网端口", { exact: true }).fill("9443");
  for (const value of ["192.168.1.50", "nas.local", "fd12:3456::150", "192.168.1.50:8089", "ftp://nas.local:21/", "tcp://nas.local:8089/", "http://", "http://nas.local:0/", "http://nas.local:65536/", "http://nas.local:abc/", "https://user:password@nas.local:8443/"]) {
    await address.fill("");
    expect(await pasteAddress(address, value)).toBe(false);
    await expect(address).toHaveValue(value);
    await expect(protocol).toHaveAttribute("value", "https");
    await expect(dialog.getByLabel("内网端口", { exact: true })).toHaveValue("9443");
  }
  await address.fill("http://192.168.10.150:8089/");
  await expect(address).toHaveValue("http://192.168.10.150:8089/");
  await expect(protocol).toHaveAttribute("value", "https");
  await expect(dialog.getByLabel("内网端口", { exact: true })).toHaveValue("9443");
  expect(state.calls.filter(call => ["POST", "PUT"].includes(call.method))).toHaveLength(0);
});

for (const protocol of ["tcp", "udp", "tcp_udp"]) {
  test(`编辑未绑定域名的 ${protocol} 服务，粘贴网址不会绕过协议限制`, async ({ page }) => {
    const state = await installApiMocks(page);
    Object.assign(state.tunnels[0], { protocol, public_domain: null, hostname: null, public_port: 21000, public_address: "203.0.113.7:21000" });
    await page.goto("/#/services/t-1");
    await page.getByRole("button", { name: "编辑服务", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "编辑服务", exact: true });
    const address = dialog.getByLabel("内网地址", { exact: true });
    expect(await pasteAddress(address, "http://192.168.10.150:8089/")).toBe(true);
    await expect(address).toHaveValue("127.0.0.1");
    await expect(address).toBeFocused();
    await expect(address).toHaveAttribute("aria-invalid", "true");
    await expect(dialog.getByRole("combobox", { name: "内网协议", exact: true })).toHaveAttribute("value", protocol);
    await expect(dialog.getByLabel("内网端口", { exact: true })).toHaveValue("8096");
    await expect(dialog.getByRole("alert")).toContainText("未绑定域名");
    expect(state.calls.filter(call => ["POST", "PUT"].includes(call.method))).toHaveLength(0);
    await address.fill("192.168.10.150");
    await expect(address).not.toHaveAttribute("aria-invalid", "true");
  });
}

test("创建时粘贴网页地址从 TCP 或 UDP 恢复原公网协议", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务", exact: true });
  await selectServiceOption(dialog.getByRole("combobox", { name: "公网协议", exact: true }), "HTTP");
  const protocol = dialog.getByRole("combobox", { name: "内网协议", exact: true });
  for (const label of ["TCP", "UDP", "TCP+UDP"]) {
    await selectServiceOption(protocol, label);
    expect(await pasteAddress(dialog.getByLabel("内网地址", { exact: true }), "https://nas.local:8443/")).toBe(true);
    await expect(protocol).toHaveAttribute("value", "https");
    await expect(dialog.getByRole("combobox", { name: "公网协议", exact: true })).toHaveAttribute("value", "http");
    await expect(dialog.getByLabel("内网端口", { exact: true })).toHaveValue("8443");
  }
  await dialog.getByLabel("服务名称").fill("恢复公网协议");
  await dialog.getByLabel("主机名").fill("restore");
  await dialog.getByRole("button", { name: "保存服务", exact: true }).click();
  await expect(dialog).toBeHidden();
  expect(state.calls.find(call => call.method === "POST")?.body).toMatchObject({ protocol: "http", origin_protocol: "https", local_address: "nas.local", local_port: 8443, public_port: null });
});

test("有效网址填充会清除已修正的地址或端口错误", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务", exact: true });
  const address = dialog.getByLabel("内网地址", { exact: true });
  const port = dialog.getByLabel("内网端口", { exact: true });
  await dialog.getByLabel("服务名称").fill("修正地址");
  await dialog.getByLabel("主机名").fill("correct");
  for (const field of [address, port]) {
    await field.fill("");
    await dialog.getByRole("button", { name: "保存服务", exact: true }).click();
    await expect(field).toHaveAttribute("aria-invalid", "true");
    await pasteAddress(address, "http://192.168.10.150:8089/");
    await expect(field).not.toHaveAttribute("aria-invalid", "true");
    await expect(dialog.getByRole("alert")).toHaveCount(0);
  }
});

test("桌面真实粘贴网址自动填入协议和端口", async ({ page, context }, info) => {
  test.skip(info.project.name !== "desktop-dark", "真实剪贴板使用桌面 Chromium，移动端粘贴事件另有覆盖");
  await installApiMocks(page);
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: "http://127.0.0.1:4173" });
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务", exact: true });
  const address = dialog.getByLabel("内网地址", { exact: true });
  await page.evaluate(() => navigator.clipboard.writeText("http://192.168.10.150:8089/"));
  await address.focus();
  await address.press("ControlOrMeta+V");
  await expect(address).toHaveValue("192.168.10.150");
  await expect(address).toBeFocused();
  await expect(dialog.getByRole("combobox", { name: "内网协议", exact: true })).toHaveAttribute("value", "http");
  await expect(dialog.getByLabel("内网端口", { exact: true })).toHaveValue("8089");
});
