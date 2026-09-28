import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("手机长按进入多选，抬手不跳转，全选限定当前筛选结果", async ({ page }, info) => {
  test.skip(info.project.name === "desktop-dark", "手机长按交互");
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "t-2", name: "备用服务" }, { ...state.tunnels[0], id: "t-3", name: "TCP 服务", protocol: "tcp" });
  await page.goto("/#/services");
  await expect(page.locator(".service-row")).toHaveCount(3);
  await page.getByLabel("类型筛选").selectOption("web");
  const name = page.getByRole("link", { name: "媒体中心", exact: true });
  const box = (await name.boundingBox())!;
  // 使用真实指针按下与抬手，验证长按后的兼容 click 不打开详情。
  await page.mouse.move(box.x + 10, box.y + 15);
  await page.mouse.down();
  await expect(page.getByRole("checkbox", { name: "选择媒体中心" })).toBeChecked();
  await page.mouse.up();
  await expect(page).toHaveURL(/#\/services$/);
  await expect(page.locator(".batch-actions")).toContainText("已选择 1 项");
  await page.getByRole("button", { name: "全选", exact: true }).click();
  await expect(page.locator(".batch-actions")).toContainText("已选择 2 项");
  await expect(page.getByRole("checkbox")).toHaveCount(2);
  await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath("mobile-selection.png") });
  await page.getByRole("button", { name: "取消全选", exact: true }).click();
  await expect(page.locator(".batch-actions")).toContainText("已选择 0 项");
  await name.click();
  await expect(page.getByRole("checkbox", { name: "选择媒体中心" })).toBeChecked();
  await expect(page).toHaveURL(/#\/services$/);
  await page.getByLabel("类型筛选").selectOption("tcp");
  await expect(page.locator(".batch-actions")).toContainText("已选择 0 项");
  await page.getByRole("button", { name: "完成", exact: true }).click();
  await expect(page.locator(".bottom-nav")).toBeVisible();
  await expect(page.getByRole("checkbox")).toHaveCount(0);
  await page.getByRole("link", { name: "TCP 服务", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "TCP 服务", exact: true })).toBeVisible();
});

test("滑动、取消触摸、多指和离开列表取消长按，短按不触发选择", async ({ page }, info) => {
  test.skip(info.project.name === "desktop-dark", "手机手势取消");
  await installApiMocks(page);
  await page.goto("/#/services");
  const row = page.locator(".service-row").first();
  await expect(row).toBeVisible();
  await page.clock.install();
  const down = { pointerId: 1, pointerType: "touch", isPrimary: true, button: 0, clientX: 40, clientY: 200 };
  for (const reason of ["pointermove", "pointercancel", "pointerout", "second-touch", "scroll"]) {
    await row.dispatchEvent("pointerdown", down);
    await page.clock.fastForward(200);
    if (reason === "second-touch") await page.locator(".toolbar").dispatchEvent("pointerdown", { ...down, pointerId: 2, isPrimary: false });
    else if (reason === "scroll") await page.evaluate(() => window.dispatchEvent(new Event("scroll")));
    else await row.dispatchEvent(reason, { ...down, clientY: 220 });
    await page.clock.fastForward(600);
    await expect(page.getByRole("checkbox"), reason).toHaveCount(0);
    await row.dispatchEvent("pointerup", down);
  }
  for (const target of [row.getByRole("link", { name: "打开媒体中心" }), row.getByRole("link", { name: "媒体中心", exact: true })]) {
    await target.dispatchEvent("pointerdown", down);
    await page.clock.fastForward(200);
    await target.dispatchEvent("pointerup", down);
    await expect(page.getByRole("checkbox")).toHaveCount(0);
  }
  await row.dispatchEvent("pointerdown", down);
  await page.evaluate(() => { window.location.hash = "#/agents"; });
  await expect(page).toHaveURL(/#\/agents$/);
  await page.clock.fastForward(600);
  await page.evaluate(() => { window.location.hash = "#/services"; });
  await expect(page.getByRole("checkbox")).toHaveCount(0);
});

test("批量修改 Agent 保留最新配置，部分失败只重试失败项", async ({ page }, info) => {
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], { icon_id: "border-radius/emby-1.png", public_domain: "example.com", origin_protocol: "https", enabled: false, lan_redirect_enabled: true, local_address: "192.168.1.10" });
  state.tunnels.push({ ...state.tunnels[0], id: "t-2", name: "TCP 应用", protocol: "tcp", public_port: 23456, hostname: null, public_domain: null, lan_redirect_enabled: false });
  await page.goto("/#/services");
  const select = page.getByRole("button", { name: "选择", exact: true });
  await select.focus(); await select.press("Space");
  await page.getByRole("button", { name: "全选", exact: true }).click();
  await page.getByRole("button", { name: "修改 Agent", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "批量修改 Agent" });
  await dialog.getByRole("radio", { name: "备用 Agent · 离线", exact: true }).check();
  await expect(dialog).toContainText("Agent 当前离线");
  await page.evaluate(() => { window.location.hash = "#/agents"; });
  await expect(page).toHaveURL(/#\/services$/);
  await page.screenshot({ animations: "disabled", scale: "css", path: info.outputPath("batch-agent-editor.png") });
  // 模拟表单打开后服务配置发生变化，提交必须采用最新值。
  Object.assign(state.tunnels[0], { local_port: 9443, https_port: 8443, name: "最新媒体中心" });
  state.failures.set("PUT /api/v1/tunnels/t-2", "设备暂不可达");
  await dialog.getByRole("button", { name: "保存修改" }).click();
  await expect(dialog.getByRole("alert")).toContainText("TCP 应用：设备暂不可达");
  await expect(dialog.getByRole("status")).toContainText("已完成 1 / 2 项");
  const first = state.calls.find(call => call.method === "PUT" && call.path === "/api/v1/tunnels/t-1")!;
  expect(first.body).toEqual({ device_id: "a-2", name: "最新媒体中心", protocol: "https", origin_protocol: "https", local_address: "192.168.1.10", local_port: 9443, public_port: null, https_port: 8443, ipv6_direct_enabled: false, hostname: "media", public_domain_id: "d-1", enabled: false, lan_redirect_enabled: true });
  const tcp = state.calls.find(call => call.method === "PUT" && call.path === "/api/v1/tunnels/t-2")!;
  expect(tcp.body).toMatchObject({ device_id: "a-2", protocol: "tcp", public_port: 23456, origin_protocol: null, hostname: null, public_domain_id: null, enabled: false, lan_redirect_enabled: false });
  state.failures.delete("PUT /api/v1/tunnels/t-2");
  await dialog.getByRole("button", { name: "重试未完成项" }).click();
  await expect(dialog).toHaveCount(0);
  expect(state.calls.filter(call => call.method === "PUT" && call.path === "/api/v1/tunnels/t-1")).toHaveLength(1);
  expect(state.calls.filter(call => call.method === "PUT" && call.path === "/api/v1/tunnels/t-2")).toHaveLength(2);
  await expect(page.locator(".batch-actions")).toContainText("已选择 0 项");
  expect(state.tunnels.every(item => item.device_id === "a-2")).toBeTruthy();
  expect(state.tunnels.every(item => item.icon_id === "border-radius/emby-1.png")).toBeTruthy();
});

test("批量提交期间禁止关闭，失败后保留选择，放弃修改需要确认", async ({ page }) => {
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], { public_domain: "example.com" });
  await page.goto("/#/services");
  const select = page.getByRole("button", { name: "选择", exact: true });
  await select.focus(); await select.press("Space");
  await page.getByRole("button", { name: "全选", exact: true }).click();
  await page.getByRole("button", { name: "修改 Agent", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "批量修改 Agent" });
  await dialog.getByRole("radio", { name: "备用 Agent · 离线", exact: true }).check();
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/api/v1/tunnels/t-1", async route => { await held; await route.fulfill({ status: 503, json: { error: "暂时无法保存" } }); });
  await dialog.getByRole("button", { name: "保存修改" }).click();
  await expect(dialog.getByRole("button", { name: "取消", exact: true })).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeVisible();
  release();
  await expect(dialog.getByRole("alert")).toContainText("暂时无法保存");
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "放弃修改", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("checkbox", { name: "选择媒体中心" })).toBeChecked();
});
