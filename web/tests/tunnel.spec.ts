import { openServiceEditor } from "./service-actions";
import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const visiblePage = (page: import("@playwright/test").Page) => page.locator(".page-slot:not([hidden])");

test("网页类型包含 HTTP 和 HTTPS，内网 IPv6 地址单行展示并完整复制", async ({ page }, info) => {
  const state = await installApiMocks(page);
  const ip = "fd12:3456:789a:bcde:1234:5678:90ab:cdef";
  Object.assign(state.tunnels[0], { origin_protocol: "https", local_address: ip, local_port: 8443 });
  state.tunnels.push({ ...state.tunnels[0], id: "plain", name: "普通网页", protocol: "http", origin_protocol: "http" }, { ...state.tunnels[0], id: "tcp", name: "TCP 应用", protocol: "tcp" });
  await page.goto("/#/services");
  const filter = page.getByLabel("类型筛选");
  await expect(filter.locator("option")).toHaveText(["全部类型", "网页服务", "TCP 服务", "UDP 服务", "TCP+UDP"]);
  await filter.selectOption("web");
  await expect(page.locator(".service-row")).toHaveCount(2);
  await expect(page.locator(".service-title .service-device")).toHaveText(["家庭 Agent", "家庭 Agent"]);
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  const field = page.locator(".detail-field", { has: page.getByText("内网地址", { exact: true }) });
  const code = field.locator("code");
  await expect(code).toHaveText(`https://[${ip}]:8443`);
  await expect(code).toHaveCSS("white-space", "nowrap");
  await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (value: string) => { document.body.dataset.copiedAddress = value; } } }));
  await field.getByRole("button", { name: "复制内网地址" }).click();
  await expect(page.locator("body")).toHaveAttribute("data-copied-address", `https://[${ip}]:8443`);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("compact-service-detail.png"), animations: "disabled" });
  await page.getByRole("button", { name: "编辑服务" }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await expect(editor.getByLabel("内网协议")).toHaveValue("https");
  await expect(editor.getByLabel("内网地址", { exact: true })).toHaveValue(ip);
});

test("五入口导航、旧链接和不存在的详情均可返回", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  const nav = page.locator((page.viewportSize()?.width ?? 0) <= 900 ? ".bottom-nav" : ".sidebar nav");
  await expect(nav.getByRole("link")).toHaveCount(5);
  await nav.getByRole("link", { name: "域名", exact: true }).click();
  await expect(visiblePage(page).locator("h1")).toHaveText("域名");
  await expect(nav.getByRole("link", { name: "域名", exact: true })).toHaveAttribute("aria-current", "page");
  await page.goto("/#/settings");
  await expect(visiblePage(page).locator("h1")).toHaveText((page.viewportSize()?.width ?? 0) <= 900 ? "我的" : "账号设置");
  await page.goto("/#/services/missing");
  await expect(page.getByText("服务不存在", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "返回服务列表" }).click();
  await expect(page.getByRole("link", { name: "媒体中心", exact: true })).toBeVisible();
  await page.goto("/#/overview");
  await expect(visiblePage(page).locator("h1")).toHaveText("首页");
});

test("详情显示完整地址，返回保留搜索与滚动位置", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels = Array.from({ length: 20 }, (_, index) => ({ ...state.tunnels[0], id: `t-${index}`, name: `媒体中心 ${index}` }));
  await page.goto("/#/services");
  await page.getByRole("textbox", { name: "搜索服务" }).fill("媒体");
  const target = page.getByRole("link", { name: "媒体中心 12", exact: true });
  await target.scrollIntoViewIfNeeded();
  const scroll = await page.evaluate(() => window.scrollY);
  await target.click();
  await expect(visiblePage(page).locator("h1")).toHaveText("媒体中心 12");
  await expect(page.locator(".detail-field code").first()).toHaveText(state.tunnels[0].public_address);
  await page.goBack();
  await expect(page.getByRole("textbox", { name: "搜索服务" })).toHaveValue("媒体");
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeCloseTo(scroll, -1);
});

test("服务详情的地址复制和操作区保持紧凑", async ({ page }, testInfo) => {
  await installApiMocks(page);
  await page.goto("/#/services/t-1");
  const detail = page.locator(".service-detail");
  const address = detail.locator(".service-detail-address").first();
  const code = await address.locator("code").boundingBox();
  const copy = await address.getByRole("button", { name: "复制公网地址" }).boundingBox();
  expect(code).not.toBeNull();
  expect(copy).not.toBeNull();
  expect(copy!.x).toBeGreaterThanOrEqual(code!.x + code!.width - 1);
  expect(copy!.y).toBeLessThan(code!.y + code!.height);
  await expect(detail.getByRole("button", { name: "编辑服务" })).toBeVisible();
  await expect(detail.getByRole("button", { name: "关闭服务" })).toBeVisible();
  await expect(detail.getByRole("button", { name: "删除服务" })).toBeVisible();
  if ((page.viewportSize()?.width ?? 0) <= 900) await expect(page.locator(".bottom-nav")).toBeHidden();
  if ((page.viewportSize()?.width ?? 0) <= 600) {
    const meta = detail.locator(".service-detail-meta").first();
    const label = await meta.locator("dt").boundingBox();
    const value = await meta.locator("dd").boundingBox();
    expect(value!.x).toBeGreaterThan(label!.x + label!.width);
    expect(Math.abs(value!.y - label!.y)).toBeLessThan(12);
  }
  await page.screenshot({ path: testInfo.outputPath("service-detail.png") });
});

test("小屏服务详情滚动后仍可操作", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "mobile-light", "只验证最窄的手机布局");
  const state = await installApiMocks(page);
  state.tunnels[0].name = "一个很长很长的家庭内网服务名称";
  state.tunnels[0].apply_status = "failed";
  state.tunnels[0].apply_error = "无法连接本地目标，请检查 Agent 的网络连接和目标服务端口。";
  await page.setViewportSize({ width: 320, height: 568 });
  await page.goto("/#/services/t-1");
  await expect(page.locator(".bottom-nav")).toBeHidden();
  const actions = page.locator(".service-detail-actions");
  await expect(actions).toBeVisible();
  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  for (const name of ["编辑服务", "关闭服务", "删除服务"]) await expect(actions.getByRole("button", { name })).toBeInViewport({ ratio: 1 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: testInfo.outputPath("service-detail-small-bottom.png") });
});

for (const protocol of ["tcp", "http", "https"]) {
  test(`创建 ${protocol} 服务按协议提交且失败保留输入`, async ({ page }) => {
    const state = await installApiMocks(page);
    await page.goto("/#/services");
    await openServiceEditor(page);
    const dialog = page.getByRole("dialog", { name: "创建服务" });
    await dialog.getByLabel("服务名称").fill("新服务");
    await dialog.getByLabel("内网协议").selectOption(protocol === "tcp" ? "tcp" : "http");
    if (protocol !== "tcp") await dialog.getByLabel("公网协议").selectOption(protocol);
    await dialog.getByLabel("内网端口").fill("8080");
    if (protocol !== "tcp") { await dialog.getByLabel("主机名").fill("new"); await dialog.getByRole("combobox", { name: "根域名", exact: true }).click(); await dialog.getByRole("option", { name: "example.com", exact: true }).click(); }
    state.failures.set("POST /api/v1/tunnels", "暂时无法保存");
    await dialog.getByRole("button", { name: "保存服务" }).click();
    await expect(dialog.getByRole("alert")).toContainText("暂时无法保存");
    await expect(dialog.getByLabel("服务名称")).toHaveValue("新服务");
    state.failures.clear();
    await dialog.getByRole("button", { name: "保存服务" }).click();
    await expect(dialog).not.toBeVisible();
    await expect(page.getByRole("link", { name: "新服务", exact: true })).toBeVisible();
    const call = state.calls.filter(item => item.method === "POST" && item.path === "/api/v1/tunnels").at(-1)!;
    expect(call.body.protocol).toBe(protocol);
    expect(call.body.local_port).toBe(8080);
    expect(call.body.public_port).toBeNull();
    expect(call.body.public_domain_id).toBe(protocol === "tcp" ? null : "d-1");
  });
}

test("编辑预填域名，保存不丢失原配置", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务" }).click();
  const dialog = page.getByRole("dialog", { name: "编辑服务" });
  await expect(dialog.getByRole("combobox", { name: "根域名", exact: true })).toContainText("example.com");
  await expect(dialog.getByRole("combobox", { name: "根域名", exact: true })).toBeDisabled();
  await dialog.getByLabel("服务名称").fill("改名的服务");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(visiblePage(page).locator(".service-detail h2")).toHaveText("改名的服务");
  expect(state.calls.find(item => item.method === "PUT")?.body.public_domain_id).toBe("d-1");
});

test("未保存保护、弹层焦点约束与关闭后恢复", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  const create = page.getByRole("button", { name: /^(添加|创建服务)$/ });
  await openServiceEditor(page);
  const editor = page.getByRole("dialog", { name: "创建服务" });
  await editor.getByLabel("服务名称").fill("保留草稿");
  await page.keyboard.press("Escape");
  const confirm = page.getByRole("dialog", { name: "放弃未保存的修改？" });
  await expect(confirm).toBeVisible();
  await confirm.getByRole("button", { name: "取消" }).click();
  await expect(confirm).not.toBeVisible();
  await expect.poll(() => editor.evaluate(el => el.contains(document.activeElement))).toBeTruthy();
  await expect(editor.getByLabel("服务名称")).toHaveValue("保留草稿");
  for (let i = 0; i < 12; i++) { await page.keyboard.press("Tab"); expect(await editor.evaluate(el => el.contains(document.activeElement))).toBeTruthy(); }
  await page.keyboard.press("Escape");
  await confirm.getByRole("button", { name: "放弃修改", exact: true }).click();
  await expect(editor).not.toBeVisible();
  await expect(create).toBeFocused();
});

test("无域名时先关闭表单再配置，不允许跨页保留编辑窗口", async ({ page }) => {
  const state = await installApiMocks(page); state.domains = [];
  await page.goto("/#/services");
  await openServiceEditor(page);
  const editor = page.getByRole("dialog", { name: "创建服务" });
  await editor.getByLabel("服务名称").fill("草稿服务");
  await editor.getByLabel("内网协议").selectOption("http");
  await expect(editor.getByText("网页服务需要域名，请关闭表单后到域名页添加。", { exact: true })).toBeVisible();
  await page.evaluate(() => { window.location.hash = "#/domains"; });
  await expect(page).toHaveURL(/#\/services$/);
  await expect(editor.getByLabel("服务名称")).toHaveValue("草稿服务");
  await editor.getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "放弃修改", exact: true }).click();
  await page.evaluate(() => { window.location.hash = "#/domains"; });
  await page.getByRole("button", { name: "添加 域名", exact: true }).click();
  const add = page.getByRole("dialog", { name: "添加域名" });
  await add.getByLabel("域名", { exact: true }).fill("new.example.com");
  await add.getByRole("button", { name: "添加域名", exact: true }).click();
  await expect(page).toHaveURL(/#\/domains\/d-2$/);
  await expect(page.getByRole("dialog", { name: /^配置 / })).toBeVisible();
});

test("批量操作失败保留整批选择，重试成功后一起更新", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "t-2", name: "备用服务" });
  await page.goto("/#/services");
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.getByRole("button", { name: "选择", exact: true }).press("Space");
  await page.getByRole("checkbox", { name: "选择媒体中心" }).check();
  await page.getByRole("checkbox", { name: "选择备用服务" }).check();
  state.failures.set("POST /api/v1/tunnels/batch/disable", "批量保存失败");
  await page.locator(".batch-actions").getByRole("button", { name: "关闭", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("批量保存失败");
  expect(state.tunnels.every(item => item.enabled)).toBeTruthy();
  state.failures.delete("POST /api/v1/tunnels/batch/disable");
  await page.locator(".batch-actions").getByRole("button", { name: "关闭", exact: true }).click();
  await expect(page.locator(".service-row .status")).toHaveText(["已关闭", "已关闭"]);
  state.failures.set("DELETE /api/v1/tunnels/batch", "删除失败");
  await page.locator(".batch-actions").getByRole("button", { name: "删除", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "删除服务" }).click();
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText("删除失败");
  expect(state.tunnels).toHaveLength(2);
  state.failures.delete("DELETE /api/v1/tunnels/batch");
  await page.getByRole("dialog").getByRole("button", { name: "删除服务" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.locator(".service-row")).toHaveCount(0);
});

test("复制失败有说明，服务启停失败不伪报成功", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", { value: { writeText: () => Promise.reject(new Error("denied")) }, configurable: true });
    document.execCommand = () => false;
  });
  await page.goto("/#/services");
  await page.getByRole("button", { name: "复制媒体中心公网地址" }).click();
  await expect(page.getByRole("alert")).toContainText("无法复制");
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  state.failures.set("POST /api/v1/tunnels/t-1/disable", "关闭失败");
  await page.getByRole("button", { name: "关闭服务", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("关闭失败");
  await expect(page.getByRole("button", { name: "关闭服务", exact: true })).toBeEnabled();
});

test("公网 HTTP 页面可复制服务地址和弹窗内的 Compose 配置", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "验证 Chromium 中非安全上下文的同步复制回退");
  await page.route("http://copy.example.test:4173/**", async route => {
    const response = await route.fetch({ url: route.request().url().replace("copy.example.test", "127.0.0.1") });
    await route.fulfill({ response });
  });
  await page.addInitScript(() => {
    const original = document.execCommand.bind(document);
    document.execCommand = command => {
      if (command === "copy") (window as any).copiedFallback = (document.activeElement as HTMLTextAreaElement).value;
      return original(command);
    };
  });
  const state = await installApiMocks(page);
  await page.goto("http://copy.example.test:4173/#/services");
  expect(await page.evaluate(() => window.isSecureContext)).toBe(false);
  await page.getByRole("button", { name: "复制媒体中心公网地址" }).click();
  await expect(page.getByRole("status")).toHaveText("已复制");
  expect(await page.evaluate(() => (window as any).copiedFallback)).toBe(state.tunnels[0].public_address);

  await page.goto("http://copy.example.test:4173/#/agents");
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "添加 Agent" });
  await dialog.getByRole("button", { name: "复制 Compose 配置", exact: true }).click();
  await expect(dialog.getByRole("status")).toHaveText("已复制");
  expect(await page.evaluate(() => (window as any).copiedFallback)).toContain("nexo_join_shared-test-key");
});

test("Agent 离线可见，批准表单和删除错误可重试", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/agents");
  await expect(page.getByText("离线", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "批准", exact: true }).click();
  const approve = page.getByRole("dialog", { name: "批准恢复 家庭 Agent 的身份？" });
  await approve.getByRole("button", { name: "批准恢复" }).click();
  await expect(approve).not.toBeVisible();
  expect(state.calls.find(item => item.path.endsWith("/approve"))?.body).toEqual({});
  await page.locator(".agent-row").filter({ hasText: "家庭 Agent" }).click();
  await page.getByRole("button", { name: "删除 Agent", exact: true }).click();
  state.failures.set("DELETE /api/v1/devices/a-1", "删除节点失败");
  const confirm = page.getByRole("dialog");
  await confirm.getByRole("button", { name: "删除 Agent", exact: true }).click();
  await expect(confirm.getByRole("alert")).toContainText("删除节点失败");
  state.failures.clear();
  await confirm.getByRole("button", { name: "删除 Agent", exact: true }).click();
  await expect(visiblePage(page).locator("h1")).toHaveText("设备");
});

test("共享接入密钥可复制且不写入浏览器存储", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/agents");
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  await expect(page.locator(".token")).toContainText("nexo_join_");
  await page.getByText("高级：接入密钥", { exact: true }).click();
  await expect(page.getByRole("button", { name: "复制接入密钥" })).toBeVisible();
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(stored).not.toContain("nexo_join_");
});

test("密码错误保留输入，成功后返回登录；会话列表失败可重试", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/settings/sessions");
  await expect(page.getByText("当前会话", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "返回", exact: true }).click();
  await page.getByRole("button", { name: /修改密码/ }).click();
  const dialog = page.getByRole("dialog", { name: "修改密码" });
  await dialog.getByLabel("当前密码").fill("incorrect-password");
  await dialog.getByLabel("新密码").fill("a-new-password-123");
  state.failures.set("POST /api/v1/auth/password", "当前密码错误");
  await dialog.getByRole("button", { name: "更新密码" }).click();
  await expect(dialog.getByRole("alert")).toContainText("当前密码错误");
  await expect(dialog.getByLabel("新密码")).toHaveValue("a-new-password-123");
  state.failures.clear();
  await dialog.getByRole("button", { name: "更新密码" }).click();
  await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
});

test("会话读取失败不显示空列表，吊销当前会话返回登录", async ({ page }) => {
  const state = await installApiMocks(page);
  state.failures.set("GET /api/v1/auth/sessions", "读取会话失败");
  await page.goto("/#/settings/sessions");
  await expect(page.getByRole("alert")).toContainText("读取会话失败");
  await expect(page.getByText("暂无登录会话", { exact: true })).toHaveCount(0);
  state.failures.clear();
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await page.locator(".session-row").filter({ hasText: "当前会话" }).getByRole("button", { name: "结束会话" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "结束会话" }).click();
  await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
});

test("首次读取失败、重试、无结果与空列表互相区分", async ({ page }) => {
  await page.clock.install();
  const state = await installApiMocks(page);
  state.failures.set("GET /api/v1/tunnels", "网络不可用");
  await page.goto("/#/services");
  await expect(page.getByRole("alert")).toContainText("网络不可用");
  await expect(page.getByText("还没有服务", { exact: true })).toHaveCount(0);
  state.failures.clear();
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await page.getByRole("textbox", { name: "搜索服务" }).fill("不存在");
  await expect(page.getByText("没有匹配的服务", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "清除筛选" }).click();
  state.tunnels = [];
  await page.clock.fastForward(5000);
  await expect(page.getByText("还没有服务", { exact: true })).toBeVisible();
});

test("登录使用可自动填充的单栏表单且不再提供网页初始化", async ({ page }) => {
  const state = await installApiMocks(page, { anonymous: true });
  await page.goto("/");
  await expect(page.getByText("创建管理员", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("初始化口令")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "首次安装 Nexo" })).toHaveCount(0);
  await page.getByLabel("用户名", { exact: true }).fill("admin");
  await page.getByLabel("密码", { exact: true }).fill("a-secure-password");
  await expect(page.locator(".auth-panel")).toBeVisible();
  await page.getByRole("button", { name: "登录", exact: true }).click();
  expect(state.calls.some(call => call.path === "/api/v1/auth/initialize")).toBeFalsy();
  expect(state.calls.some(call => call.path === "/api/v1/auth/login")).toBeTruthy();
  await expect(visiblePage(page).locator("h1")).toHaveText("首页");
});

test("浏览器返回不能切走正在编辑的表单", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/manage");
  const nav = page.locator((page.viewportSize()?.width ?? 0) <= 900 ? ".bottom-nav" : ".sidebar nav");
  await nav.getByRole("link", { name: "服务", exact: true }).click();
  await openServiceEditor(page);
  const editor = page.getByRole("dialog", { name: "创建服务" });
  await editor.getByLabel("服务名称").fill("未保存内容");
  await page.goBack();
  await expect(page).toHaveURL(/#\/services$/);
  await expect(editor.getByLabel("服务名称")).toHaveValue("未保存内容");
  await expect(page.getByRole("dialog", { name: "放弃未保存的修改？" })).toHaveCount(0);
  await editor.getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "放弃修改", exact: true }).click();
  await expect(editor).toBeHidden();
});

test("尚无 Agent 时禁止保存并说明如何接入设备", async ({ page }) => {
  const state = await installApiMocks(page); state.devices = [];
  await page.goto("/#/services");
  await openServiceEditor(page);
  const editor = page.getByRole("dialog", { name: "创建服务" });
  await editor.getByLabel("服务名称").fill("等待 Agent 的服务");
  await expect(editor.getByRole("button", { name: "保存服务" })).toBeDisabled();
  await expect(editor.getByText("请关闭表单，到设备页添加 Agent。", { exact: true })).toBeVisible();
  await page.evaluate(() => { window.location.hash = "#/agents"; });
  await expect(page).toHaveURL(/#\/services$/);
  await expect(editor.getByLabel("服务名称")).toHaveValue("等待 Agent 的服务");
});

test("域名操作失败保留表单，删除失败可重试", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "添加 域名", exact: true }).click();
  const add = page.getByRole("dialog", { name: "添加域名" });
  await add.getByLabel("域名", { exact: true }).fill("new.example.com");
  state.failures.set("POST /api/v1/public-domains", "域名已存在");
  await add.getByRole("button", { name: "添加域名", exact: true }).click();
  await expect(add.getByRole("alert")).toContainText("域名已存在");
  await expect(add.getByLabel("域名", { exact: true })).toHaveValue("new.example.com");
  state.failures.clear();
  await add.getByRole("button", { name: "添加域名", exact: true }).click();
  const row = page.locator(".page-slot:not([hidden]) .domain-row").filter({ has: page.getByText("new.example.com", { exact: true }) });
  await expect(page.getByRole("dialog", { name: /^配置 / })).toBeVisible();
  await page.getByRole("dialog", { name: /^配置 / }).getByRole("button", { name: "删除域名", exact: true }).click();
  const confirm = page.getByRole("dialog", { name: /^删除 / });
  state.failures.set("DELETE /api/v1/public-domains/d-2", "域名正在使用");
  await confirm.getByRole("button", { name: "删除域名" }).click();
  await expect(confirm.getByRole("alert")).toContainText("域名正在使用");
  state.failures.clear();
  await confirm.getByRole("button", { name: "删除域名" }).click();
  await expect(row).toHaveCount(0);
});

test("登录失败可重试，已有列表刷新时保持可读", async ({ page }) => {
  await page.clock.install();
  const state = await installApiMocks(page, { anonymous: true });
  state.failures.set("POST /api/v1/auth/login", "用户名或密码错误");
  await page.goto("/");
  await page.getByLabel("用户名", { exact: true }).fill("admin");
  await page.getByLabel("密码", { exact: true }).fill("password");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("用户名或密码错误");
  state.failures.clear();
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(visiblePage(page).locator("h1")).toHaveText("首页");
  await page.evaluate(() => { location.hash = "#/services"; });
  await expect(page.getByRole("link", { name: "媒体中心", exact: true })).toBeVisible();
  state.delay = 600;
  const refreshing = page.waitForRequest("**/api/v1/tunnels");
  const refreshed = page.waitForResponse("**/api/v1/tunnels");
  await page.clock.fastForward(5000);
  await refreshing;
  await expect(page.getByRole("link", { name: "媒体中心", exact: true })).toBeVisible();
  await refreshed;
  await expect(page.getByRole("button", { name: /^刷新/ })).toHaveCount(0);
});

test("连接中断显示重试，不误判为未登录", async ({ page }) => {
  await installApiMocks(page);
  await page.route("**/api/v1/auth/status", route => route.abort("failed"));
  await page.goto("/");
  await expect(page.getByRole("alert")).toContainText("无法连接 Nexo");
  await expect(page.getByRole("button", { name: "登录", exact: true })).toHaveCount(0);
  await page.unroute("**/api/v1/auth/status");
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await expect(visiblePage(page).locator("h1")).toHaveText("首页");
});
