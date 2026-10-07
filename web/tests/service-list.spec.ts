import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import type { NodeEntry } from "../src/ui";

const nodes = [
  { node_id: "hk", node_name: "香港 VPS", healthy: true },
  { node_id: "jp", node_name: "日本 VPS", healthy: true },
];
const entry = (ids: string[], sync_status: NodeEntry["sync_status"] = "synced"): NodeEntry => ({
  entries: ids.map(id => ({ node_id: id, node_name: nodes.find(node => node.node_id === id)!.node_name, ipv4: id === "hk" ? "203.0.113.10" : "203.0.113.11" })),
  sync_status, synced_at: Math.floor(Date.now() / 1000) - 10,
});

async function setup(page: Page) {
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], { name: "Emby", node_ids: ["hk", "jp"], node_statuses: nodes, distribution_mode: "latency", node_selection: { node_id: "hk", reason: "保持当前健康节点" }, node_entry: entry(["hk"]) });
  return state;
}

test("默认列表并记住视图，切换保留搜索筛选与选择且不写服务配置", async ({ page }) => {
  const state = await setup(page);
  state.tunnels.push({ ...state.tunnels[0], id: "second", name: "Emby 备用" }, { ...state.tunnels[0], id: "ssh", name: "SSH", protocol: "tcp" });
  await page.goto("/#/services");
  await expect(page.getByRole("button", { name: "列表视图", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator(".service-list")).toHaveAttribute("data-view", "list");
  await page.getByLabel("搜索服务").fill("Emby");
  await page.getByLabel("类型筛选").selectOption("web");
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.keyboard.press("Enter");
  await page.getByRole("link", { name: "Emby", exact: true }).click();
  await expect(page.getByRole("checkbox", { name: "选择Emby", exact: true })).toBeChecked();
  for (const label of ["图标视图", "列表视图", "图标视图"]) {
    await page.getByRole("button", { name: label, exact: true }).click();
    await expect(page.getByLabel("搜索服务")).toHaveValue("Emby");
    await expect(page.getByLabel("类型筛选")).toHaveValue("web");
    await expect(page.locator(".service-row")).toHaveCount(2);
    await expect(page.getByRole("checkbox", { name: "选择Emby", exact: true })).toBeChecked();
  }
  expect(state.calls.filter(call => ["POST", "PUT", "DELETE"].includes(call.method))).toHaveLength(0);
  await page.reload();
  await expect(page.getByRole("button", { name: "图标视图", exact: true })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "列表视图", exact: true }).focus();
  await page.keyboard.press("Enter");
  await page.reload();
  await expect(page.locator(".service-list")).toHaveAttribute("data-view", "list");
});

test("列表区分已记录入口、切换目标、部分失败及 DNS 分流", async ({ page }) => {
  const state = await setup(page);
  state.tunnels.push(
    { ...state.tunnels[0], id: "switch", name: "切换中", node_selection: { node_id: "jp", reason: "原节点不可用" }, node_entry: entry(["hk"], "pending") },
    { ...state.tunnels[0], id: "partial", name: "部分写入失败", distribution_mode: "dns", node_entry: entry(["hk"], "failed") },
    { ...state.tunnels[0], id: "dns", name: "DNS 分流", distribution_mode: "dns", node_entry: entry(["hk", "jp"]) },
    { ...state.tunnels[0], id: "manual", name: "首选已变更", distribution_mode: "manual", preferred_node_id: "jp", node_entry: entry(["hk"], "pending") },
    { ...state.tunnels[0], id: "waiting", name: "等待选择", node_selection: null, node_entry: entry([], "pending") },
  );
  await page.goto("/#/services");
  const row = (name: string) => page.locator(".service-row").filter({ has: page.getByRole("link", { name, exact: true }) });
  await expect(row("Emby").locator(".service-entry-names")).toHaveText("香港 VPS");
  await expect(row("Emby").locator(".service-modes")).toContainText("内网穿透");
  await expect(row("Emby").locator(".service-modes")).toContainText("回源延迟优先");
  await expect(row("切换中").locator(".service-entry-names")).toHaveText("香港 VPS");
  await expect(row("切换中").locator(".service-entry-hint")).toContainText("待同步");
  await expect(row("切换中").locator(".service-entry-target")).toHaveText("目标：日本 VPS");
  await expect(row("部分写入失败").locator(".service-entry-names")).toHaveText("香港 VPS");
  await expect(row("部分写入失败").locator(".service-entry-hint")).toContainText("同步失败");
  await expect(row("DNS 分流").locator(".service-entry-names")).toHaveText("香港 VPS、日本 VPS");
  await expect(row("首选已变更").locator(".service-entry-target")).toHaveText("目标：日本 VPS");
  await expect(row("首选已变更").locator(".service-modes")).toContainText("主备切换");
  await expect(row("等待选择").locator(".service-entry-names")).toHaveText("等待入口同步");
  await expect(row("等待选择").locator(".service-entry-target")).toHaveText("配置：香港 VPS、日本 VPS");
  expect(state.calls.some(call => call.path.includes("/dns-records") || call.path === "/api/v1/nodes")).toBe(false);
});

test("关闭、反代、旧接口、未知地址和 IPv6 直连都有明确含义", async ({ page }) => {
  const state = await setup(page);
  const old = { ...state.tunnels[0], id: "old", name: "旧接口" };
  delete old.node_entry;
  state.tunnels.push(
    { ...state.tunnels[0], id: "closed", name: "已关闭", enabled: false, node_ids: ["jp"] },
    { ...state.tunnels[0], id: "proxy", name: "博客", service_mode: "reverse_proxy", distribution_mode: "single", node_ids: ["jp"], node_entry: entry([], "unmanaged") },
    old,
    { ...state.tunnels[0], id: "unknown", name: "旧地址", node_entry: { entries: [{ ipv4: "203.0.113.99", node_id: null, node_name: null }], sync_status: "failed", synced_at: null } },
    { ...state.tunnels[0], id: "direct", name: "IPv6 服务", ipv6_direct_enabled: true, apply_status: "checking", node_entry: entry([]), direct_status: { status: "configured", address: "2001:4860::1" } },
  );
  await page.goto("/#/services");
  const row = (name: string) => page.locator(".service-row").filter({ has: page.getByRole("link", { name, exact: true }) });
  await expect(row("已关闭").locator(".service-entry-names")).toHaveText("日本 VPS");
  await expect(row("已关闭").locator(".status")).toHaveText("已关闭");
  await expect(row("博客").locator(".service-modes")).toContainText("反向代理");
  await expect(row("博客").locator(".service-modes")).toContainText("单节点");
  await expect(row("博客").locator(".service-entry-hint")).toHaveText("配置节点");
  await expect(row("旧接口").locator(".service-entry-hint")).toHaveText("入口状态未提供");
  await expect(row("旧地址").locator(".service-entry-names")).toHaveText("203.0.113.99");
  await expect(row("IPv6 服务").locator(".service-entry-names")).toHaveText("暂无可用 IPv4 入口");
  await expect(row("IPv6 服务").locator(".service-entry-hint")).toContainText("IPv4");
  await expect(row("IPv6 服务").locator(".service-direct-label")).toHaveText("IPv6 直连");
});

test("入口刷新后更新，网络失败保留上次确认数据", async ({ page }) => {
  const state = await setup(page);
  await page.goto("/#/services");
  const names = page.locator(".service-entry-names");
  await expect(names).toHaveText("香港 VPS");
  state.tunnels[0].node_entry = entry(["jp"]);
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(names).toHaveText("日本 VPS", { timeout: 8000 });
  state.failures.set("GET /api/v1/tunnels", "网络暂不可用");
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.getByRole("alert")).toContainText("网络暂不可用", { timeout: 8000 });
  await expect(page.getByText(/保留上次数据/)).toBeVisible();
  await expect(names).toHaveText("日本 VPS");
});

test("列表入口直接访问网页，名称和关闭服务保留详情行为", async ({ page, context }) => {
  const state = await setup(page);
  state.tunnels.push({ ...state.tunnels[0], id: "closed", name: "已关闭", enabled: false });
  await context.route("https://media.example.com/**", route => route.fulfill({ contentType: "text/html", body: "<title>Emby</title>" }));
  await page.goto("/#/services");
  const opened = context.waitForEvent("page");
  await page.locator(".service-row").first().locator(".service-entry-names").click();
  const application = await opened;
  await expect(application).toHaveURL(state.tunnels[0].public_address!);
  expect(context.pages()).toHaveLength(2);
  await application.close();
  await page.getByRole("link", { name: "Emby", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: "Emby", exact: true })).toBeVisible();
  expect(context.pages()).toHaveLength(1);
  await page.keyboard.press("Escape");
  const closed = page.locator(".service-row").last();
  await closed.click({ position: { x: 2, y: 2 } });
  expect(context.pages()).toHaveLength(1);
  await closed.getByRole("link", { name: "已关闭", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "已关闭", exact: true })).toBeVisible();
});

test("列表端口复制失败提供整行手动输入，重试与多选保留原行为", async ({ page, context }) => {
  const state = await setup(page);
  state.tunnels.push({ ...state.tunnels[0], id: "ssh", name: "SSH", protocol: "tcp", public_address: "example.com:22000" });
  await page.goto("/#/services");
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async () => { throw new Error("权限拒绝"); } } });
    document.execCommand = () => false;
  });
  await page.getByRole("button", { name: "复制SSH地址", exact: true }).click();
  const manual = page.getByRole("textbox", { name: "手动复制内容" });
  await expect(manual).toHaveValue("example.com:22000");
  const row = page.locator(".service-row").filter({ has: page.getByRole("link", { name: "SSH", exact: true }) });
  expect((await manual.boundingBox())!.width).toBeGreaterThan((await row.boundingBox())!.width * .75);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.evaluate(() => { document.execCommand = () => true; });
  await page.getByRole("button", { name: "再次复制", exact: true }).click();
  await expect(manual).toHaveCount(0);
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.keyboard.press("Enter");
  await row.click({ position: { x: 2, y: 2 } });
  await expect(row.getByRole("checkbox")).toBeChecked();
  expect(context.pages()).toHaveLength(1);
});

test("桌面列对齐、手机紧凑行与长节点名称在各尺寸无溢出", async ({ page }, info) => {
  const state = await setup(page);
  state.tunnels.push({ ...state.tunnels[0], id: "dns", name: "多个节点", distribution_mode: "dns", node_entry: entry(["hk", "jp"]) });
  state.tunnels.push({ ...state.tunnels[0], id: "long", name: "长名称的家庭媒体中心用来检查标题", distribution_mode: "manual", ipv6_direct_enabled: true, node_entry: { ...entry(["hk"]), entries: [{ node_id: "hk", node_name: "香港 VPS 这是一个很长的节点名称以及very-long-node-name-for-layout-testing", ipv4: "203.0.113.10" }] } });
  const sizes = [page.viewportSize()!];
  if (info.project.name === "mobile-light") sizes.push({ width: 320, height: 568 });
  if (info.project.name === "desktop-dark") sizes.push({ width: 1100, height: 800 });
  await page.goto("/#/services");
  for (const size of sizes) {
    await page.setViewportSize(size);
    await expect(page.locator(".service-row")).toHaveCount(3);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    for (const row of await page.locator(".service-row").all()) {
      await expect(row.locator(".service-entry")).toBeVisible();
      await expect(row.locator(".service-modes")).toBeVisible();
      expect(await row.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
    }
    const heading = page.locator(".service-list-heading");
    if (size.width > 900) {
      await expect(heading).toBeVisible();
      for (const [index, selector] of [[1, ".service-entry"], [2, ".service-modes"]] as const) {
        const label = (await heading.locator("span").nth(index).boundingBox())!;
        for (const cell of await page.locator(`.service-row ${selector}`).all()) {
          expect(Math.abs((await cell.boundingBox())!.x - label.x)).toBeLessThan(1);
        }
      }
    } else {
      await expect(heading).toBeHidden();
      expect(await page.locator(".service-name strong").last().evaluate(el => getComputedStyle(el).whiteSpace)).toBe("normal");
    }
    await page.screenshot({ path: info.outputPath(`service-list-${size.width}x${size.height}.png`), animations: "disabled" });
    if (size.width === 320) {
      await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
      const modes = (await page.locator(".service-modes").last().boundingBox())!;
      expect(modes.y + modes.height).toBeLessThan((await page.locator(".mobile-dock").boundingBox())!.y);
      await page.screenshot({ path: info.outputPath("service-list-320-long-name.png"), animations: "disabled" });
    }
  }
  if (info.project.name === "mobile-light") {
    await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await expect(page.locator(".service-entry-names").last()).toBeVisible();
    await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
    const modes = (await page.locator(".service-modes").last().boundingBox())!;
    expect(modes.y + modes.height).toBeLessThan((await page.locator(".mobile-dock").boundingBox())!.y);
    await page.screenshot({ path: info.outputPath("service-list-large-text.png"), animations: "disabled" });
  }
});

test("浏览器禁用本地存储时仍可使用列表和图标视图", async ({ page }) => {
  await setup(page);
  await page.addInitScript(() => Object.defineProperty(window, "localStorage", { get() { throw new DOMException("存储不可用", "SecurityError"); } }));
  await page.goto("/#/services");
  await expect(page.locator(".service-list")).toHaveAttribute("data-view", "list");
  await page.getByRole("button", { name: "图标视图", exact: true }).click();
  await expect(page.locator(".service-list")).toHaveAttribute("data-view", "icons");
});
