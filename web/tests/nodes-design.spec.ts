import { expect, test, type Page } from "@playwright/test";
import type { RelayNode } from "../src/nodes";
import { installApiMocks } from "./api-mocks";

/** 使用可变接口数据模拟刷新与操作失败，验证视觉重排不破坏维护边界。 */
async function setup(page: Page) {
  const auth = await installApiMocks(page);
  const now = Math.floor(Date.now() / 1000);
  const base: RelayNode = { id: "hk", name: "香港 VPS", public_ipv4: "203.0.113.10", control_port: 9891, approved: true, enabled: true, registered: true, assigned: true, status: "online", os: "Ubuntu 24.04", architecture: "aarch64", version: "0.2.11", connections: 12, workspace_ids: ["default"], services: [{ id: "t-1", name: "媒体中心", enabled: true, alternatives: [] }], latencies: [{ device_id: "nas", device_name: "家庭 NAS", rtt_ms: 32, checked_at: now, fresh: true, samples: 3 }], events: [{ message: "节点连接已恢复", occurred_at: now }] };
  const state = { nodes: [base, { ...base, id: "jp", name: "日本 VPS", public_ipv4: "203.0.113.11", status: "offline", last_seen: now - 300, latencies: base.latencies.map(item => ({ ...item, fresh: false, checked_at: now - 120 })) }, { ...base, id: "us", name: "美国 VPS", public_ipv4: "203.0.113.12", latencies: [], services: [] }], failure: false, saveFailure: false, reads: 0, writes: [] as { method: string; path: string; body: any }[] };
  await page.route("**/api/v1/nodes**", route => {
    const req = route.request(); const path = new URL(req.url()).pathname;
    if (req.method() !== "GET") {
      state.writes.push({ method: req.method(), path, body: req.postData() ? req.postDataJSON() : null });
      if (state.saveFailure) return route.fulfill({ status: 503, json: { error: "保存失败，请重试" } });
      if (req.method() === "PUT") Object.assign(state.nodes.find(node => path.endsWith(`/${node.id}`))!, req.postDataJSON());
      return route.fulfill({ json: {} });
    }
    state.reads++;
    if (state.failure) return route.fulfill({ status: 503, json: { error: "节点加载失败" } });
    return route.fulfill({ json: path.endsWith("/nodes") ? { nodes: state.nodes, server_version: "0.2.12" } : state.nodes.find(node => path.endsWith(`/${node.id}`)) });
  });
  return { state, auth };
}

async function openDetail(page: Page) {
  await page.getByRole("article", { name: "香港 VPS", exact: true }).getByRole("button", { name: "管理", exact: true }).click();
  return page.getByRole("dialog", { name: "香港 VPS", exact: true });
}

test("批量模式清理筛选和刷新后的选择，只提交仍可更新的节点", async ({ page }) => {
  const { state } = await setup(page);
  let submitted: unknown;
  await page.route("**/api/v1/node-update-jobs", route => {
    if (route.request().method() === "POST") submitted = route.request().postDataJSON();
    return route.fulfill({ json: [] });
  });
  await page.goto("/#/nodes");
  await expect(page.getByRole("checkbox")).toHaveCount(0);
  await page.getByRole("button", { name: "批量更新", exact: true }).click();
  await expect(page.getByLabel("选择 日本 VPS")).toBeDisabled();
  await page.getByLabel("选择 香港 VPS").check();
  await page.getByLabel("选择 美国 VPS").check();
  state.nodes[0].status = "maintenance";
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.getByRole("region", { name: "批量更新选择" })).toContainText("已选择 1 个节点");
  await expect(page.getByLabel("选择 香港 VPS")).not.toBeChecked();
  await page.getByLabel("搜索节点名称或 IP").fill("美国");
  await expect(page.getByRole("button", { name: "继续", exact: true })).toBeDisabled();
  await page.getByLabel("选择 美国 VPS").check();
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await page.getByRole("button", { name: "开始更新", exact: true }).click();
  expect(submitted).toEqual({ node_ids: ["us"], target_version: "0.2.12", accept_interruption: false });
  await expect(page.getByRole("checkbox")).toHaveCount(0);
});

test("详情页签支持键盘、草稿关闭保护和失败重试，实时刷新不覆盖编辑", async ({ page }, info) => {
  const { state } = await setup(page);
  await page.goto("/#/nodes");
  const detail = await openDetail(page);
  await expect(detail.getByRole("tab", { name: "概览", exact: true })).toHaveAttribute("aria-selected", "true");
  await detail.getByText("逐设备延迟（1）").click();
  await detail.getByText("操作记录（1）").click();
  await page.screenshot({ path: info.outputPath("node-overview.png"), animations: "disabled" });
  await detail.getByRole("tab", { name: "概览", exact: true }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(detail.getByRole("tab", { name: "配置", exact: true })).toBeFocused();
  await expect(detail.getByRole("tab", { name: "配置", exact: true })).toHaveAttribute("aria-selected", "true");
  await detail.getByLabel("节点名称", { exact: true }).fill("香港入口新名称");
  state.nodes[0].name = "服务端新名称";
  state.nodes[0].connections = 99;
  const reads = state.reads;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect.poll(() => state.reads).toBeGreaterThan(reads);
  await expect(detail.getByLabel("节点名称", { exact: true })).toHaveValue("香港入口新名称");
  await expect(detail.getByRole("button", { name: "保存配置", exact: true })).toBeInViewport();
  await page.screenshot({ path: info.outputPath("node-config.png"), animations: "disabled" });
  await detail.getByRole("button", { name: "关闭", exact: true }).click();
  const discard = page.getByRole("dialog", { name: "放弃未保存的修改？" });
  await expect(discard).toBeVisible();
  await discard.getByRole("button", { name: "取消", exact: true }).click();
  state.saveFailure = true;
  await detail.getByRole("button", { name: "保存配置", exact: true }).click();
  await expect(detail.getByRole("alert")).toContainText("保存失败");
  await expect(detail.getByLabel("节点名称", { exact: true })).toHaveValue("香港入口新名称");
  state.saveFailure = false;
  await detail.getByRole("button", { name: "保存配置", exact: true }).click();
  await expect(detail).toBeHidden();
  expect(state.writes.at(-1)?.body).toEqual({ name: "香港入口新名称", public_ipv4: "203.0.113.10", control_port: 9891, enabled: true, workspace_ids: ["default"] });
});

test("重启仍需接受中断，移除必须独立确认", async ({ page }, info) => {
  const { state } = await setup(page);
  let restartBody: unknown;
  await page.route("**/api/v1/node-update-jobs", route => {
    if (route.request().method() === "POST") restartBody = route.request().postDataJSON();
    return route.fulfill({ json: [] });
  });
  await page.goto("/#/nodes");
  let detail = await openDetail(page);
  await detail.getByRole("tab", { name: "配置", exact: true }).click();
  await detail.getByRole("button", { name: "重启节点服务", exact: true }).click();
  const restart = page.getByRole("dialog", { name: "重启节点服务", exact: true });
  await expect(restart).toContainText("媒体中心");
  await expect(restart.getByRole("button", { name: "确认重启 Nexo 服务" })).toBeDisabled();
  await restart.getByRole("checkbox").check();
  await expect(restart.getByRole("button", { name: "确认重启 Nexo 服务" })).toBeInViewport();
  await page.screenshot({ path: info.outputPath("node-restart.png") });
  await restart.getByRole("button", { name: "确认重启 Nexo 服务" }).click();
  expect(restartBody).toEqual({ operation: "restart", node_ids: ["hk"], target_version: "0.2.11", accept_interruption: true });
  await expect(detail).toBeHidden();
  detail = await openDetail(page);
  await detail.getByRole("tab", { name: "配置", exact: true }).click();
  await detail.getByRole("button", { name: "移除节点", exact: true }).click();
  const remove = page.getByRole("dialog", { name: "移除节点", exact: true });
  expect(state.writes).toHaveLength(0);
  await remove.getByRole("button", { name: "取消", exact: true }).click();
  await expect(detail.getByRole("button", { name: "移除节点", exact: true })).toBeFocused();
  await detail.getByRole("button", { name: "移除节点", exact: true }).click();
  await remove.getByRole("button", { name: "确认移除", exact: true }).click();
  expect(state.writes).toEqual([{ method: "DELETE", path: "/api/v1/nodes/hk", body: null }]);
});

test("空列表、筛选无结果和请求失败提供不同恢复入口", async ({ page }) => {
  const { state } = await setup(page);
  state.failure = true;
  await page.goto("/#/nodes");
  await expect(page.getByRole("alert")).toContainText("节点加载失败");
  await expect(page.getByRole("heading", { name: "尚未接入节点" })).toHaveCount(0);
  state.failure = false;
  state.nodes = [];
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await expect(page.getByRole("heading", { name: "尚未接入节点" })).toBeVisible();
  await page.getByRole("button", { name: "添加节点", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "添加节点" })).toBeVisible();
  await page.getByRole("button", { name: "关闭", exact: true }).click();
});

test("本地节点支持反代授权配置，窄屏和主题变化不遮挡信息与操作", async ({ page }, info) => {
  const { state } = await setup(page);
  state.nodes.push({ ...state.nodes[0], id: "local", name: "本地入口", public_ipv4: "" });
  await page.goto("/#/nodes");
  await page.getByRole("article", { name: "本地入口", exact: true }).getByRole("button", { name: "详情", exact: true }).click();
  const detail = page.getByRole("dialog", { name: "本地入口", exact: true });
  await expect(detail).toBeVisible();
  await expect(detail.getByRole("tab")).toHaveCount(2);
  await expect(page.getByRole("button", { name: "保存配置" })).toHaveCount(0);
  await page.getByRole("button", { name: "关闭", exact: true }).click();
  await page.getByLabel("搜索节点名称或 IP").fill("不存在");
  await expect(page.getByRole("heading", { name: "没有符合筛选条件的节点" })).toBeVisible();
  await page.getByRole("button", { name: "清除筛选" }).click();
  await expect(page.getByRole("article")).toHaveCount(4);
  await page.screenshot({ path: info.outputPath("node-list.png"), fullPage: true });
  state.nodes[0].name = "家庭与办公室共享的亚洲公网入口超长名称";
  state.nodes[0].error = "无法连接节点，请检查公网地址和防火墙配置。".repeat(4);
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  for (const width of [320, 390]) {
    await page.setViewportSize({ width, height: 740 });
    await page.emulateMedia({ colorScheme: width === 320 ? "dark" : "light", reducedMotion: "reduce", contrast: "more" });
    await expect(page.getByRole("article").first()).toContainText(state.nodes[0].error);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    for (const card of await page.getByRole("article").all()) expect(await card.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath(`node-narrow-${width}.png`), fullPage: true });
  }
});

test("待安装、待审批、凭证过期和更新失败均保留明确状态", async ({ page }, info) => {
  const { state } = await setup(page);
  state.nodes = ["unregistered", "pending", "expired", "maintenance", "disabled"].map((status, i) => ({ ...state.nodes[0], id: `node-${i}`, name: ["等待安装", "等待审批", "凭证过期", "维护失败", "暂停入口"][i], status, registered: !["unregistered", "expired"].includes(status), approved: !["unregistered", "pending", "expired"].includes(status), can_enroll: ["unregistered", "expired"].includes(status), assigned: false, latencies: [], ...(status === "maintenance" ? { update: { stage: "failed", target_version: "0.2.12", error: "安装包下载失败，请检查节点网络。" } } : {}) }));
  await page.goto("/#/nodes");
  for (const status of ["待安装", "待审批", "凭证已过期", "维护中", "已停用"]) await expect(page.locator(".node-status").filter({ hasText: status })).toBeVisible();
  await expect(page.getByRole("article", { name: "维护失败", exact: true })).toContainText("安装包下载失败");
  await page.screenshot({ path: info.outputPath("node-states.png"), fullPage: true });
  await page.getByRole("article", { name: "凭证过期", exact: true }).getByRole("button", { name: "管理", exact: true }).click();
  const detail = page.getByRole("dialog", { name: "凭证过期", exact: true });
  await expect(detail).toContainText("凭证已过期，请重新生成");
  await expect(detail.getByRole("button", { name: "生成新凭证", exact: true })).toBeVisible();
});
