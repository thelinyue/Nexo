import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const visiblePage = (page: import("@playwright/test").Page) => page.locator(".page-slot:not([hidden])");

test("两入口导航、旧链接和不存在的详情均可返回", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  const nav = page.locator((page.viewportSize()?.width ?? 0) <= 900 ? ".bottom-nav" : ".sidebar nav");
  await expect(nav.getByRole("link")).toHaveCount(2);
  await nav.getByRole("link", { name: "管理", exact: true }).click();
  await page.getByRole("link", { name: /域名与证书/ }).click();
  await expect(visiblePage(page).getByRole("heading", { name: "域名与证书" })).toBeVisible();
  await expect(nav.getByRole("link", { name: "管理", exact: true })).toHaveAttribute("aria-current", "page");
  await page.goto("/#/settings");
  await expect(visiblePage(page).getByRole("heading", { name: "管理", exact: true })).toBeVisible();
  await page.goto("/#/services/missing");
  await expect(page.getByText("服务不存在", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: "返回服务列表" }).click();
  await expect(page.getByRole("link", { name: "媒体中心", exact: true })).toBeVisible();
  await page.goto("/#/overview");
  await expect(visiblePage(page).getByRole("heading", { name: "穿透服务" })).toBeVisible();
});

test("详情显示完整地址，返回保留搜索与滚动位置", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels = Array.from({ length: 20 }, (_, index) => ({ ...state.tunnels[0], id: `t-${index}`, name: `媒体中心 ${index}` }));
  await page.goto("/#/services");
  await page.getByRole("textbox", { name: "搜索穿透服务" }).fill("媒体");
  const target = page.getByRole("link", { name: "媒体中心 12", exact: true });
  await target.scrollIntoViewIfNeeded();
  const scroll = await page.evaluate(() => window.scrollY);
  await target.click();
  await expect(page.getByRole("heading", { name: "服务详情" })).toBeVisible();
  await expect(page.locator(".detail-field code").first()).toHaveText(state.tunnels[0].public_address);
  await page.goBack();
  await expect(page.getByRole("textbox", { name: "搜索穿透服务" })).toHaveValue("媒体");
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeCloseTo(scroll, -1);
});

for (const protocol of ["tcp", "http", "https"]) {
  test(`创建 ${protocol} 服务按协议提交且失败保留输入`, async ({ page }) => {
    const state = await installApiMocks(page);
    await page.goto("/#/services");
    await page.getByRole("button", { name: "创建服务", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "创建服务" });
    await dialog.getByLabel("服务名称").fill("新服务");
    await dialog.getByRole("radio", { name: protocol.toUpperCase(), exact: true }).check();
    await dialog.getByLabel("本地端口").fill("8080");
    if (protocol !== "tcp") { await dialog.getByLabel("主机名").fill("new"); await dialog.getByLabel("根域名").selectOption("d-1"); }
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
  await expect(dialog.getByLabel("根域名")).toHaveValue("d-1");
  await expect(dialog.getByLabel("根域名")).toBeDisabled();
  await dialog.getByLabel("服务名称").fill("改名的服务");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(page.getByRole("heading", { name: "改名的服务" })).toBeVisible();
  expect(state.calls.find(item => item.method === "PUT")?.body.public_domain_id).toBe("d-1");
});

test("未保存保护、弹层焦点约束与关闭后恢复", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  const create = page.getByRole("button", { name: "创建服务", exact: true });
  await create.click();
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

test("无域名时跳转配置并恢复服务草稿", async ({ page }) => {
  const state = await installApiMocks(page); state.domains = [];
  await page.goto("/#/services");
  await page.getByRole("button", { name: "创建服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "创建服务" });
  await editor.getByLabel("服务名称").fill("草稿服务");
  await editor.getByRole("radio", { name: "HTTPS", exact: true }).check();
  await editor.getByRole("button", { name: "添加域名", exact: true }).click();
  await page.getByRole("button", { name: "添加 域名", exact: true }).click();
  const add = page.getByRole("dialog", { name: "添加域名" });
  await add.getByLabel("域名", { exact: true }).fill("new.example.com");
  await add.getByRole("button", { name: "添加域名", exact: true }).click();
  await expect(add).not.toBeVisible();
  await page.goBack();
  await expect(editor.getByLabel("服务名称")).toHaveValue("草稿服务");
  await expect(editor.getByRole("radio", { name: "HTTPS", exact: true })).toBeChecked();
  await expect(editor.getByLabel("根域名").getByRole("option", { name: "new.example.com" })).toHaveCount(1);
});

test("批量操作一次确认并逐项呈现失败", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "t-2", name: "备用服务" });
  await page.goto("/#/services");
  await expect(page.getByRole("checkbox")).toHaveCount(0);
  await page.getByRole("button", { name: "选择", exact: true }).click();
  await page.getByRole("checkbox", { name: "选择媒体中心" }).check();
  await page.getByRole("checkbox", { name: "选择备用服务" }).check();
  state.failures.set("POST /api/v1/tunnels/t-2/disable", "节点暂不可达");
  await page.locator(".batch-actions").getByRole("button", { name: "关闭", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("备用服务：节点暂不可达");
  await expect(page.locator(".service-row").filter({ hasText: "媒体中心" }).getByText("已关闭", { exact: true })).toBeVisible();
  state.failures.set("DELETE /api/v1/tunnels/t-2", "删除失败");
  await page.locator(".batch-actions").getByRole("button", { name: "删除", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "删除服务" }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "媒体中心", exact: true })).toHaveCount(0);
  await expect(page.getByRole("alert")).toContainText("备用服务：删除失败");
  await expect(page.getByRole("checkbox", { name: "选择备用服务" })).toBeChecked();
});

test("复制失败有说明，服务启停失败不伪报成功", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.addInitScript(() => Object.defineProperty(navigator, "clipboard", { value: { writeText: () => Promise.reject(new Error("denied")) }, configurable: true }));
  await page.goto("/#/services");
  await page.getByRole("button", { name: "复制媒体中心公网地址" }).click();
  await expect(page.getByRole("alert")).toContainText("无法复制");
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  state.failures.set("POST /api/v1/tunnels/t-1/disable", "关闭失败");
  await page.getByRole("button", { name: "关闭服务", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("关闭失败");
  await expect(page.getByRole("button", { name: "关闭服务", exact: true })).toBeEnabled();
});

test("Agent 离线可见，批准表单和删除错误可重试", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/agents");
  await expect(page.getByText("离线", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "批准", exact: true }).click();
  const approve = page.getByRole("dialog", { name: "批准 Agent 入网" });
  await approve.getByLabel("Agent 名称").fill("办公室 Agent");
  await approve.getByRole("button", { name: "确定" }).click();
  await expect(approve).not.toBeVisible();
  expect(state.calls.find(item => item.path.endsWith("/approve"))?.body.device_name).toBe("办公室 Agent");
  await page.locator(".agent-row").filter({ hasText: "家庭 Agent" }).click();
  await page.getByRole("button", { name: "删除 Agent", exact: true }).click();
  state.failures.set("DELETE /api/v1/devices/a-1", "删除节点失败");
  const confirm = page.getByRole("dialog");
  await confirm.getByRole("button", { name: "删除 Agent", exact: true }).click();
  await expect(confirm.getByRole("alert")).toContainText("删除节点失败");
  state.failures.clear();
  await confirm.getByRole("button", { name: "删除 Agent", exact: true }).click();
  await expect(visiblePage(page).getByRole("heading", { name: "Agent", exact: true })).toBeVisible();
});

test("一次性凭证可复制且不写入浏览器存储", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/agents");
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  await page.getByRole("button", { name: "生成凭证", exact: true }).click();
  await expect(page.locator(".token")).toContainText("one-time-secret");
  await expect(page.getByRole("button", { name: "复制入网凭证" })).toBeVisible();
  const stored = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(stored).not.toContain("one-time-secret");
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
  await expect(page.getByRole("heading", { name: "欢迎回来" })).toBeVisible();
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
  await expect(page.getByRole("heading", { name: "欢迎回来" })).toBeVisible();
});

test("首次读取失败、重试、无结果与空列表互相区分", async ({ page }) => {
  const state = await installApiMocks(page);
  state.failures.set("GET /api/v1/tunnels", "网络不可用");
  await page.goto("/#/services");
  await expect(page.getByRole("alert")).toContainText("网络不可用");
  await expect(page.getByText("还没有穿透服务", { exact: true })).toHaveCount(0);
  state.failures.clear();
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await page.getByRole("textbox", { name: "搜索穿透服务" }).fill("不存在");
  await expect(page.getByText("没有匹配的服务", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "清除筛选" }).click();
  state.tunnels = [];
  await page.getByRole("button", { name: "刷新服务" }).click();
  await expect(page.getByText("还没有穿透服务", { exact: true })).toBeVisible();
});

test("登录和初始化使用可自动填充的单栏表单", async ({ page }) => {
  await installApiMocks(page, { anonymous: true, initialize: true });
  await page.goto("/");
  await page.getByLabel("初始化口令").fill("bootstrap-code");
  await page.getByLabel("用户名", { exact: true }).fill("admin");
  await page.getByLabel("密码", { exact: true }).fill("a-secure-password");
  if ((page.viewportSize()?.width ?? 0) <= 900) await expect(page.locator(".auth-visual")).toBeHidden();
  await page.getByRole("button", { name: "开始使用" }).click();
  await expect(visiblePage(page).getByRole("heading", { name: "穿透服务" })).toBeVisible();
});

test("浏览器返回同样保护未保存的表单", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/manage");
  const nav = page.locator((page.viewportSize()?.width ?? 0) <= 900 ? ".bottom-nav" : ".sidebar nav");
  await nav.getByRole("link", { name: "服务", exact: true }).click();
  await page.getByRole("button", { name: "创建服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "创建服务" });
  await editor.getByLabel("服务名称").fill("未保存内容");
  await page.goBack();
  const confirm = page.getByRole("dialog", { name: "放弃未保存的修改？" });
  await expect(confirm).toBeVisible();
  await confirm.getByRole("button", { name: "放弃修改", exact: true }).click();
  await expect(visiblePage(page).getByRole("heading", { name: "管理", exact: true })).toBeVisible();
  await expect(editor).not.toBeVisible();
});

test("无在线 Agent 时禁止保存，并保留跳转前的草稿", async ({ page }) => {
  const state = await installApiMocks(page); state.devices.forEach(item => { item.status = "offline"; });
  await page.goto("/#/services");
  await page.getByRole("button", { name: "创建服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "创建服务" });
  await editor.getByLabel("服务名称").fill("等待 Agent 的服务");
  await expect(editor.getByRole("button", { name: "保存服务" })).toBeDisabled();
  await editor.getByRole("button", { name: "配置 Agent" }).click();
  await expect(visiblePage(page).getByRole("heading", { name: "Agent", exact: true })).toBeVisible();
  state.devices[0].status = "online";
  await page.goBack();
  await expect(editor.getByLabel("服务名称")).toHaveValue("等待 Agent 的服务");
  await editor.getByLabel("Agent", { exact: true }).selectOption("a-1");
  await expect(editor.getByRole("button", { name: "保存服务" })).toBeEnabled();
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
  const row = page.locator(".domain-row").filter({ has: page.getByText("new.example.com", { exact: true }) });
  await row.getByRole("button", { name: "证书配置", exact: true }).click();
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
  const state = await installApiMocks(page, { anonymous: true });
  state.failures.set("POST /api/v1/auth/login", "用户名或密码错误");
  await page.goto("/");
  await page.getByLabel("用户名", { exact: true }).fill("admin");
  await page.getByLabel("密码", { exact: true }).fill("password");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("用户名或密码错误");
  state.failures.clear();
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page.getByRole("link", { name: "媒体中心", exact: true })).toBeVisible();
  state.delay = 600;
  await page.getByRole("button", { name: "刷新服务" }).click();
  await expect(page.getByRole("link", { name: "媒体中心", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "刷新服务" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "刷新服务" })).toBeEnabled();
});

test("连接中断显示重试，不误判为未登录", async ({ page }) => {
  await installApiMocks(page);
  await page.route("**/api/v1/auth/status", route => route.abort("failed"));
  await page.goto("/");
  await expect(page.getByRole("alert")).toContainText("无法连接 Nexo");
  await expect(page.getByRole("button", { name: "登录", exact: true })).toHaveCount(0);
  await page.unroute("**/api/v1/auth/status");
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await expect(page.getByRole("link", { name: "媒体中心", exact: true })).toBeVisible();
});
