import { openServiceEditor, selectServiceOption } from "./service-actions";
import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

for (const protocol of ["http", "https"]) for (const origin of ["http", "https"]) {
  test(`公网 ${protocol} 与内网 ${origin} 独立保存、回填且切换不改端口`, async ({ page }) => {
    const state = await installApiMocks(page);
    await page.goto("/#/services");
    await openServiceEditor(page);
    const dialog = page.getByRole("dialog", { name: "创建服务" });
    await dialog.getByLabel("服务名称").fill("独立协议");
    await dialog.getByLabel("内网地址", { exact: true }).fill("192.168.1.10");
    await dialog.getByLabel("内网端口").fill("8443");
    await dialog.getByLabel("主机名").fill("independent");
    await selectServiceOption(dialog.getByRole("combobox", { name: "公网协议", exact: true }), (protocol).toUpperCase().replace("_", "+"));
    await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), (origin).toUpperCase().replace("_", "+"));
    await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "TCP");
    await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), (origin).toUpperCase().replace("_", "+"));
    await expect(dialog.getByRole("combobox", { name: "公网协议", exact: true })).toHaveAttribute("value", protocol);
    await expect(dialog.getByRole("combobox", { name: "内网协议", exact: true })).toHaveAttribute("value", origin);
    await expect(dialog.getByLabel("内网端口")).toHaveValue("8443");
    await dialog.getByRole("button", { name: "保存服务" }).click();
    await expect(dialog).toBeHidden();
    expect(state.calls.find(call => call.method === "POST")?.body).toMatchObject({ protocol, origin_protocol: origin, local_port: 8443, public_port: null });
    await page.getByRole("link", { name: "独立协议", exact: true }).click();
    await expect(page.locator(".detail-field", { has: page.getByText("内网地址", { exact: true }) })).toContainText(`${origin}://192.168.1.10:8443`);
    await page.getByRole("button", { name: "编辑服务" }).click();
    const editor = page.getByRole("dialog", { name: "编辑服务" });
    await expect(editor.getByRole("combobox", { name: "公网协议", exact: true })).toHaveAttribute("value", protocol);
    await expect(editor.getByRole("combobox", { name: "内网协议", exact: true })).toHaveAttribute("value", origin);
    const next = origin === "http" ? "https" : "http";
    await selectServiceOption(editor.getByRole("combobox", { name: "内网协议", exact: true }), (next).toUpperCase().replace("_", "+"));
    await editor.getByRole("button", { name: "保存服务" }).click();
    await expect(editor).toBeHidden();
    expect(state.calls.find(call => call.method === "PUT")?.body).toMatchObject({ protocol, origin_protocol: next, local_port: 8443 });
  });
}

for (const protocol of ["tcp", "udp", "tcp_udp"]) {
  test(`${protocol} 从地址行创建并编辑，无域名时不能切换网页协议`, async ({ page }) => {
    const state = await installApiMocks(page);
    state.domains = [];
    await page.goto("/#/services");
    await openServiceEditor(page);
    const dialog = page.getByRole("dialog", { name: "创建服务" });
    await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), (protocol).toUpperCase().replace("_", "+"));
    await dialog.getByLabel("服务名称").fill(`测试 ${protocol}`);
    await dialog.getByLabel("内网地址", { exact: true }).fill("192.168.1.10");
    await dialog.getByLabel("内网端口").fill("8080");
    await expect(dialog.getByRole("combobox", { name: "公网协议", exact: true })).toHaveCount(0);
    await expect(dialog.getByText("高级设置", { exact: true })).toHaveCount(0);
    await dialog.getByRole("button", { name: "保存服务" }).click();
    await expect(dialog).toBeHidden();
    expect(state.calls.find(call => call.method === "POST")?.body).toMatchObject({ protocol, origin_protocol: null, hostname: null, public_domain_id: null, public_port: null, access_mode: "public", lan_redirect_enabled: false });
    await page.getByRole("link", { name: `测试 ${protocol}`, exact: true }).click();
    await page.getByRole("button", { name: "编辑服务" }).click();
    const editor = page.getByRole("dialog", { name: "编辑服务" });
    const select = editor.getByRole("combobox", { name: "内网协议", exact: true });
    await expect(select).toHaveAttribute("value", protocol);
    await select.click();
    const list = editor.getByRole("listbox", { name: "内网协议选项" });
    await expect(list.getByRole("option", { name: "HTTP", exact: true })).toBeDisabled();
    await expect(list.getByRole("option", { name: "HTTPS", exact: true })).toBeDisabled();
    await select.press("Home");
    await expect(list.getByRole("option", { name: "TCP", exact: true })).toHaveAttribute("data-active", "true");
    await select.press("ArrowUp");
    await expect(list.getByRole("option", { name: "TCP", exact: true })).toHaveAttribute("data-active", "true");
    await select.press("End");
    await expect(list.getByRole("option", { name: "TCP+UDP", exact: true })).toHaveAttribute("data-active", "true");
    await select.press("Escape");
    await expect(select).toHaveAttribute("value", protocol);
    await editor.getByLabel("内网端口").fill("9090");
    await editor.getByRole("button", { name: "保存服务" }).click();
    await expect(editor).toBeHidden();
    expect(state.calls.find(call => call.method === "PUT")?.body).toMatchObject({ protocol, origin_protocol: null, local_port: 9090 });
  });
}

test("窄屏两个地址组保持同行，长地址仍可编辑且保存按钮可见", async ({ page }, info) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await dialog.getByLabel("服务名称").fill("家庭 NAS");
  await dialog.getByLabel("内网地址", { exact: true }).fill("192.168.1.10");
  await dialog.getByLabel("内网端口").fill("65535");
  await dialog.getByLabel("主机名").fill("nas");
  for (const width of [page.viewportSize()!.width, 320]) {
    await page.setViewportSize({ width, height: page.viewportSize()!.height });
    for (const selector of [".service-address-input", ".service-public-input"]) {
      const group = dialog.locator(selector);
      const boxes = await group.locator(":scope > input, :scope > select, :scope > .service-select-field").evaluateAll(elements => elements.map(element => { const r = element.getBoundingClientRect(); return { x: r.x, y: r.y, right: r.right, height: r.height }; }));
      expect(boxes).toHaveLength(3);
      for (const box of boxes) {
        expect(Math.abs(box.y - boxes[0].y)).toBeLessThanOrEqual(1);
        expect(box.height).toBeGreaterThanOrEqual(44);
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.right).toBeLessThanOrEqual(width);
      }
      for (let i = 1; i < boxes.length; i++) expect(boxes[i].x).toBeGreaterThanOrEqual(boxes[i - 1].right);
    }
    await expect(dialog.getByRole("button", { name: "保存服务" })).toBeInViewport();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    await page.screenshot({ path: info.outputPath(`compact-web-${width}.png`), animations: "disabled" });
    await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "TCP+UDP");
    const protocol = dialog.getByRole("combobox", { name: "内网协议", exact: true });
    await protocol.focus();
    await expect(protocol).toBeFocused();
    await page.keyboard.press("Tab");
    await expect(dialog.getByLabel("内网地址", { exact: true })).toBeFocused();
    const fits = await protocol.locator(".service-select-name").evaluate(element => element.scrollWidth <= element.clientWidth);
    expect(fits).toBeTruthy();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    await expect(dialog.getByRole("button", { name: "保存服务" })).toBeInViewport();
    await page.screenshot({ path: info.outputPath(`compact-tcp-udp-${width}.png`), animations: "disabled" });
    await selectServiceOption(protocol, "HTTP");
  }
  const address = dialog.getByLabel("内网地址", { exact: true });
  await address.fill("fd12:3456:789a:bcde:1234:5678:90ab:cdef");
  await address.press("End");
  await expect(address).toHaveValue("fd12:3456:789a:bcde:1234:5678:90ab:cdef");
  await expect(address).toBeFocused();
});

test("协议融入内网地址且单域名自动填入，打开表单不抢占输入焦点", async ({ page }, testInfo) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await expect(dialog).toBeVisible();
  expect(await page.evaluate(() => document.activeElement instanceof HTMLInputElement)).toBeFalsy();
  await expect(dialog.getByRole("combobox", { name: "内网协议", exact: true })).toHaveAttribute("value", "http");
  await dialog.getByRole("combobox", { name: "内网协议", exact: true }).click();
  await expect(dialog.getByRole("listbox", { name: "内网协议选项" }).getByRole("option")).toHaveText(["HTTP", "HTTPS", "TCP", "UDP", "TCP+UDP"]);
  await dialog.getByRole("combobox", { name: "内网协议", exact: true }).press("Escape");
  await expect(dialog.getByRole("group", { name: "服务类型", exact: true })).toHaveCount(0);
  await expect(dialog.getByRole("combobox", { name: "公网协议", exact: true })).toHaveAttribute("value", "https");
  await expect(dialog.getByRole("combobox", { name: "内网协议", exact: true })).toHaveAttribute("value", "http");
  await expect(dialog.getByLabel("公网端口", { exact: true })).toBeHidden();
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "HTTP");
  await expect(dialog.getByRole("combobox", { name: "根域名", exact: true })).toContainText("example.com");
  await dialog.getByLabel("主机名").fill("nas");
  await expect(dialog.locator(".service-submit-preview code")).toHaveText("https://nas.example.com");
  await page.screenshot({ path: testInfo.outputPath("https-service-form.png") });
  await page.emulateMedia({ colorScheme: "light" });
  await page.screenshot({ path: testInfo.outputPath("https-service-form-light.png"), animations: "disabled" });
});

test("错误定位到具体字段，折叠的无效端口自动展开，未通过校验不请求接口", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "TCP");
  const save = dialog.getByRole("button", { name: "保存服务" });
  await save.click();
  await expect(dialog.getByLabel("服务名称")).toBeFocused();
  await expect(dialog.getByLabel("服务名称")).toHaveAttribute("aria-invalid", "true");
  await dialog.getByLabel("服务名称").fill("手机创建");
  await dialog.getByLabel("内网端口").fill("65536");
  await save.click();
  await expect(dialog.getByLabel("内网端口")).toBeFocused();
  await expect(dialog.getByRole("alert")).toContainText("1–65535");
  await dialog.getByLabel("内网端口").fill("8080");
  await dialog.locator("summary").click();
  await dialog.getByLabel("公网端口", { exact: true }).fill("19999");
  await dialog.locator("summary").click();
  await save.click();
  await expect(dialog.getByLabel("公网端口", { exact: true })).toBeFocused();
  await expect(dialog.getByRole("alert")).toContainText("20000–29999");
  expect(state.calls.filter(item => item.method === "POST")).toHaveLength(0);
  await dialog.getByLabel("公网端口", { exact: true }).fill("21000");
  await save.click();
  await expect(dialog).not.toBeVisible();
  expect(state.calls.find(item => item.method === "POST")?.body.public_port).toBe(21000);
});

test("键盘下一项不误提交，可视区域缩小后字段和保存按钮仍可见", async ({ page }, testInfo) => {
  const state = await installApiMocks(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await dialog.getByLabel("服务名称").fill("键盘测试");
  await dialog.getByLabel("服务名称").press("Enter");
  await expect(dialog.getByLabel("内网地址")).toBeFocused();
  await dialog.getByLabel("内网地址").press("Enter");
  const port = dialog.getByLabel("内网端口");
  await expect(port).toBeFocused();
  await port.fill("8080");
  await page.setViewportSize({ width: 390, height: 420 });
  await expect.poll(async () => {
    const input = await port.boundingBox();
    const header = await dialog.locator(".modal-heading").boundingBox();
    const footer = await dialog.locator(".modal-actions").boundingBox();
    return Boolean(input && header && footer && input.y >= header.y + header.height && input.y + input.height <= footer.y);
  }).toBeTruthy();
  await expect(dialog.getByRole("button", { name: "保存服务" })).toBeInViewport();
  await page.screenshot({ path: testInfo.outputPath("compact-viewport-service-form.png") });
  await port.press("Enter");
  await expect(port).not.toBeFocused();
  expect(state.calls.filter(item => item.method === "POST")).toHaveLength(0);
});

test("协议切换保留输入，但不提交其他协议的端口；多域名不自动选择", async ({ page }) => {
  const state = await installApiMocks(page);
  state.domains.push({ ...state.domains[0], id: "d-2", domain: "second.example.com", is_primary: false });
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "TCP");
  await dialog.getByLabel("服务名称").fill("Web 服务");
  await dialog.getByLabel("内网端口").fill("8080");
  await dialog.locator("summary").click();
  await dialog.getByLabel("公网端口", { exact: true }).fill("21000");
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "HTTP");
  await expect(dialog.getByRole("combobox", { name: "根域名", exact: true })).toContainText("选择域名");
  await dialog.getByLabel("主机名").fill("nas");
  await dialog.getByRole("combobox", { name: "根域名", exact: true }).click();
  await dialog.getByRole("option", { name: "second.example.com", exact: true }).click();
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "TCP");
  await expect(dialog.getByLabel("公网端口", { exact: true })).toHaveValue("21000");
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "HTTP");
  await expect(dialog.getByLabel("主机名")).toHaveValue("nas");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).not.toBeVisible();
  const body = state.calls.find(item => item.method === "POST")!.body;
  expect(body.public_port).toBeNull();
  expect(body.public_domain_id).toBe("d-2");
});

test("Agent 浮层显示当前选择，离线 Agent 可选择并提交", async ({ page }, testInfo) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  const agent = dialog.getByRole("combobox", { name: "Agent", exact: true });
  await expect(agent).toContainText("家庭 Agent");
  await page.screenshot({ path: testInfo.outputPath("agent-closed.png"), scale: "css", animations: "disabled" });
  await agent.click();
  const list = dialog.getByRole("listbox", { name: "Agent选项" });
  await expect(list.getByRole("option").first()).toHaveAttribute("aria-selected", "true");
  await expect(list.getByRole("option").first()).toContainText("在线");
  await page.screenshot({ path: testInfo.outputPath("agent-open.png"), scale: "css", animations: "disabled" });
  await list.getByRole("option", { name: "备用 Agent 离线", exact: true }).click();
  await expect(list).toBeHidden();
  await expect(agent).toContainText("备用 Agent");
  await expect(agent).toBeFocused();
  await expect(dialog.getByRole("status")).toContainText("Agent 当前离线");
  await dialog.getByLabel("服务名称").fill("备用设备服务");
  await dialog.getByLabel("主机名").fill("backup");
  await dialog.getByLabel("内网端口").fill("8080");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).toBeHidden();
  expect(state.calls.find(call => call.method === "POST" && call.path === "/api/v1/tunnels")?.body.device_id).toBe("a-2");
});

test("两个选择框互斥，键盘确认和取消不误提交或关闭表单", async ({ page }, testInfo) => {
  const state = await installApiMocks(page);
  state.domains.push({ ...state.domains[0], id: "d-2", domain: "second.example.com" });
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  const agent = dialog.getByRole("combobox", { name: "Agent", exact: true });
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "HTTP");
  await dialog.getByLabel("服务名称").fill("键盘选择");
  await dialog.getByLabel("内网端口").fill("8080");
  await dialog.getByLabel("主机名").fill("nas");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  const domain = dialog.getByRole("combobox", { name: "根域名", exact: true });
  const domainList = dialog.getByRole("listbox", { name: "根域名选项" });
  await expect(domain).toBeFocused();
  await expect(domain).toHaveAttribute("aria-invalid", "true");
  await domain.press("Enter");
  await domain.press("End");
  await expect(domainList.getByRole("option").last()).toHaveAttribute("data-active", "true");
  await domain.press("Enter");
  await expect(domainList).toBeHidden();
  await expect(domain).toBeFocused();
  await expect(domain).not.toHaveAttribute("aria-invalid", "true");
  await expect(dialog.locator(".service-submit-preview code")).toHaveText("https://nas.second.example.com");
  await page.screenshot({ path: testInfo.outputPath("domain-closed.png"), scale: "css", animations: "disabled" });
  await domain.click();
  await expect(domainList.getByRole("option", { name: "second.example.com", exact: true })).toHaveAttribute("aria-selected", "true");
  await page.screenshot({ path: testInfo.outputPath("domain-open.png"), scale: "css", animations: "disabled" });
  await agent.click();
  await expect(domainList).toBeHidden();
  await expect(agent).toHaveAttribute("aria-expanded", "true");
  await expect(domain).toHaveAttribute("aria-expanded", "false");
  await agent.press("ArrowDown");
  await agent.press("Escape");
  await expect(agent).toBeFocused();
  await expect(agent).toContainText("家庭 Agent");
  await expect(dialog).toBeVisible();
  await expect(page.getByRole("dialog", { name: "放弃未保存的修改？" })).toHaveCount(0);
  await agent.press("Space");
  await agent.press("End");
  await agent.press("ArrowUp");
  await expect(dialog.getByRole("option").first()).toHaveAttribute("data-active", "true");
  await agent.press("ArrowDown");
  await agent.press("Home");
  await agent.press("Space");
  await expect(agent).toContainText("家庭 Agent");
  await agent.press("ArrowDown");
  await agent.press("Tab");
  await expect(agent).toHaveAttribute("aria-expanded", "false");
  await expect(dialog.getByRole("combobox", { name: "内网协议", exact: true })).toBeFocused();
  await agent.click();
  await dialog.getByLabel("服务名称").click();
  await expect(agent).toHaveAttribute("aria-expanded", "false");
  await expect(dialog.getByLabel("服务名称")).toBeFocused();
  expect(state.calls.filter(call => call.method === "POST")).toHaveLength(0);
});

test("长名称和长域名浮层在窄屏、横屏及低高度视口内可滚动选择", async ({ page }, testInfo) => {
  const state = await installApiMocks(page);
  state.devices = Array.from({ length: 14 }, (_, index) => ({ ...state.devices[0], id: `long-agent-${index}`, name: `家庭存储服务器长名称用于检查窄屏展示${index}` }));
  state.domains = Array.from({ length: 14 }, (_, index) => ({ ...state.domains[0], id: `long-domain-${index}`, domain: `very-long-home-network-domain-for-small-screens-${index}.example.com` }));
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "HTTP");
  for (const viewport of [{ width: 320, height: 568 }, { width: 390, height: 420 }, { width: 812, height: 375 }]) {
    await page.setViewportSize(viewport);
    for (const label of ["Agent", "根域名"]) {
      const trigger = dialog.getByRole("combobox", { name: label, exact: true });
      await trigger.click();
      const list = dialog.getByRole("listbox", { name: `${label}选项` });
      await expect(list).toBeVisible();
      await expect.poll(async () => {
        const box = await list.boundingBox(); const body = await dialog.locator(".modal-body").boundingBox(); const row = await trigger.boundingBox();
        return Boolean(box && body && row && box.y >= body.y && box.y + box.height <= body.y + body.height && box.x >= 0 && box.x + box.width <= viewport.width && (label === "根域名" ? box.width >= row.width : Math.abs(box.width - row.width) <= 1) && box.height >= 48);
      }).toBeTruthy();
      expect(await list.evaluate(element => element.scrollWidth <= element.clientWidth)).toBeTruthy();
      await trigger.press("End");
      await expect(list.getByRole("option").last()).toBeInViewport({ ratio: 1 });
      await page.screenshot({ path: testInfo.outputPath(`${label === "Agent" ? "agent" : "domain"}-${viewport.width}x${viewport.height}.png`), scale: "css", animations: "disabled" });
      await trigger.press("Enter");
      await expect(trigger).toContainText(label === "Agent" ? state.devices[13].name : state.domains[13].domain);
      await expect(list).toBeHidden();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    }
  }
});

test("无 Agent 或域名时指引先取消表单，选择框和保存禁用", async ({ page }) => {
  const state = await installApiMocks(page); state.devices = []; state.domains = [];
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await expect(dialog.getByRole("combobox", { name: "Agent", exact: true })).toBeDisabled();
  await expect(dialog.getByText("请关闭表单，到设备页添加 Agent。", { exact: true })).toBeVisible();
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "HTTP");
  await expect(dialog.getByRole("combobox", { name: "根域名", exact: true })).toBeDisabled();
  await expect(dialog.getByText("网页服务需要域名，请关闭表单后到域名页添加。", { exact: true })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "保存服务" })).toBeDisabled();
});

test("展开中的浮层跟随表单滚动和视口变化", async ({ page }) => {
  const state = await installApiMocks(page);
  state.devices = Array.from({ length: 10 }, (_, index) => ({ ...state.devices[0], id: `agent-${index}`, name: `设备 ${index}` }));
  await page.setViewportSize({ width: 375, height: 568 });
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "HTTP");
  const agent = dialog.getByRole("combobox", { name: "Agent", exact: true });
  const list = dialog.getByRole("listbox", { name: "Agent选项" });
  await agent.click();
  await dialog.locator(".modal-body").evaluate(element => { element.scrollTop += 24; });
  for (const height of [568, 420]) {
    await page.setViewportSize({ width: 375, height });
    await expect.poll(async () => {
      const box = await list.boundingBox(); const row = await agent.boundingBox(); const body = await dialog.locator(".modal-body").boundingBox();
      return Boolean(box && row && body && box.y >= body.y && box.y + box.height <= body.y + body.height && (Math.abs(box.y - row.y - row.height - 6) < 1 || Math.abs(row.y - box.y - box.height - 6) < 1));
    }).toBeTruthy();
  }
  await agent.press("Escape");
  await expect(dialog).toBeVisible();
});

test("保存期间关闭浮层并禁用所有选择框，失败后恢复选择和草稿", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await selectServiceOption(dialog.getByRole("combobox", { name: "内网协议", exact: true }), "HTTP");
  await dialog.getByLabel("服务名称").fill("保存期间");
  await dialog.getByLabel("内网端口").fill("8080");
  await dialog.getByLabel("主机名").fill("nas");
  await page.route("**/api/v1/tunnels", async route => {
    if (route.request().method() !== "POST") return route.fallback();
    await new Promise(resolve => setTimeout(resolve, 600));
    await route.fulfill({ status: 503, json: { error: "暂时无法保存" } });
  });
  await dialog.getByRole("combobox", { name: "选择策略", exact: true }).click();
  await expect(dialog.getByRole("listbox", { name: "选择策略选项" })).toBeVisible();
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog.getByRole("listbox")).toHaveCount(0);
  for (const select of await dialog.getByRole("combobox").all()) await expect(select).toBeDisabled();
  await expect(dialog.getByRole("alert")).toContainText("暂时无法保存");
  await expect(dialog.getByRole("combobox", { name: "Agent", exact: true })).toBeEnabled();
  await expect(dialog.getByRole("combobox", { name: "根域名", exact: true })).toBeEnabled();
  await expect(dialog.getByLabel("服务名称")).toHaveValue("保存期间");
});
