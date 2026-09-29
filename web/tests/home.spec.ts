import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("管理员单用户重置可取消、失败可重试且保留趋势", async ({ page }, info) => {
  const state = await installApiMocks(page);
  await page.goto("/");
  await page.getByLabel("统计用户", { exact: true }).selectOption("alice");
  await expect(page.locator(".traffic-usage strong")).toHaveText(["2 KiB", "20 KiB", "200 KiB"]);
  const trend = await page.locator(".traffic-total").innerText();
  await page.getByRole("button", { name: "重置统计", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "重置 alice 的流量统计？", exact: true });
  await expect(dialog).toContainText("趋势历史和实时速率保留");
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  expect(state.trafficResets.size).toBe(0);
  state.failures.set("POST /api/v1/admin/traffic/reset", "保存失败");
  await page.getByRole("button", { name: "重置统计", exact: true }).click();
  await dialog.getByRole("button", { name: "确认重置", exact: true }).click();
  await expect(dialog).toContainText("保存失败");
  expect(state.trafficResets.size).toBe(0);
  await expect(page.locator(".traffic-usage strong")).toHaveText(["2 KiB", "20 KiB", "200 KiB"]);
  state.failures.clear();
  const posted = page.waitForRequest(req => req.method() === "POST" && req.url().endsWith("/traffic/reset"));
  await dialog.getByRole("button", { name: "确认重置", exact: true }).click();
  const request = await posted;
  expect(request.postDataJSON()).toEqual({ user_id: "alice" });
  expect(request.headers()["x-nexo-csrf"]).toBeTruthy();
  await expect(dialog).toHaveCount(0);
  await expect(page.locator(".traffic-usage strong")).toHaveText(["0 B", "0 B", "0 B"]);
  await expect(page.locator(".traffic-usage-section")).toContainText("最近重置于");
  await expect(page.locator(".traffic-total")).toHaveText(trend, { useInnerText: true });
  await expect(page.locator(".traffic-numbers")).toContainText("2 KiB/s");
  await page.getByLabel("统计用户", { exact: true }).selectOption("admin");
  await expect(page.locator(".traffic-usage strong")).toHaveText(["2 KiB", "20 KiB", "200 KiB"]);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: info.outputPath("home-usage-reset.png"), fullPage: true });
});

test("用量切换用户隔离迟到结果，采集不完整明确提示", async ({ page }) => {
  await installApiMocks(page);
  let release!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/api/v1/admin/traffic/usage?user_id=alice", async route => {
    await pending;
    const period = { start: 100, total: { to_origin: 99999999, to_public: 0 }, partial: true };
    await route.fulfill({ json: { timezone: "Asia/Shanghai", sampled_at: 1000, started_at: 500, reset_at: null, reset_users: 0, today: period, week: period, month: period } });
  });
  await page.goto("/");
  const requested = page.waitForRequest("**/api/v1/admin/traffic/usage?user_id=alice");
  await page.getByLabel("统计用户", { exact: true }).selectOption("alice");
  await requested;
  await expect(page.locator(".traffic-usage strong")).toHaveText(["—", "—", "—"]);
  await page.getByLabel("统计用户", { exact: true }).selectOption("");
  release();
  await expect(page.locator(".traffic-usage strong")).toHaveText(["2 KiB", "20 KiB", "200 KiB"]);
  await page.getByLabel("统计用户", { exact: true }).selectOption("alice");
  await expect(page.locator(".traffic-usage small")).toHaveText(["部分时段未采集", "部分时段未采集", "部分时段未采集"]);
  await expect(page.locator(".traffic-usage-section")).toContainText("未采集时段无法补回");
});

test("首页概览、管理员用户与隧道筛选、时间图表和手机导航", async ({ page }, info) => {
  await installApiMocks(page);
  const queries: URL[] = [];
  page.on("request", req => { if (req.url().includes("/traffic/")) queries.push(new URL(req.url())); });
  await page.goto("/");
  await expect(page).toHaveURL(/#\/home$/);
  const panel = page.getByRole("region", { name: "流量监控", exact: true });
  await expect(panel.getByLabel("统计用户", { exact: true })).toHaveValue("");
  await expect(panel.getByLabel("统计隧道")).toHaveCount(0);
  await expect(panel.getByRole("img")).toBeVisible();
  await expect(panel.locator(".traffic-usage strong")).toHaveText(["2 KiB", "20 KiB", "200 KiB"]);
  await expect(panel.getByRole("button", { name: "重置统计", exact: true })).toHaveCount(0);
  await expect(page.locator(".home-summaries")).toContainText("穿透运行 1 · 反代生效 0");
  await expect(page.getByRole("region", { name: "当前空间待处理" })).toContainText("备用 Agent");
  expect(queries.some(url => url.pathname === "/api/v1/admin/traffic/history" && !url.searchParams.has("user_id"))).toBeTruthy();
  await panel.getByLabel("搜索统计用户").fill("alice");
  await panel.getByLabel("统计用户", { exact: true }).selectOption("alice");
  await expect(panel.getByLabel("统计隧道")).toBeVisible();
  await panel.getByLabel("统计隧道").selectOption("t-1");
  await expect.poll(() => queries.some(url => url.searchParams.get("user_id") === "alice" && url.searchParams.get("tunnel_id") === "t-1")).toBeTruthy();
  await panel.getByRole("button", { name: "7 天", exact: true }).click();
  await expect.poll(() => queries.some(url => url.searchParams.get("range") === "7d" && url.searchParams.get("tunnel_id") === "t-1")).toBeTruthy();
  await expect(panel.getByRole("slider")).toHaveAttribute("max", "167");
  expect(queries.filter(url => url.pathname.endsWith("/usage")).every(url => !url.searchParams.has("tunnel_id") && !url.searchParams.has("range"))).toBeTruthy();
  await expect(panel.locator(".traffic-usage strong")).toHaveText(["2 KiB", "20 KiB", "200 KiB"]);
  await panel.getByRole("slider").focus(); await panel.getByRole("slider").press("Home");
  await expect(panel.getByRole("slider")).toHaveValue("0");
  await panel.getByLabel("统计用户", { exact: true }).selectOption("");
  await expect(panel.getByLabel("统计隧道")).toHaveCount(0);
  await expect.poll(() => queries.at(-1)?.searchParams.has("user_id")).toBeFalsy();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: info.outputPath("home-overview.png"), fullPage: true });
  if (info.project.name !== "desktop-dark") {
    await expect(page.getByRole("navigation", { name: "底部导航" }).getByRole("link")).toHaveText(["首页", "服务", "设备", "域名", "我的"]);
  }
});

test("普通用户只请求个人统计，未知数据不显示零，刷新失败保留结果", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: true, user_id: "alice", username: "alice", role: "tenant", workspace_id: "alice" } }));
  state.failures.set("GET /api/v1/traffic/realtime", "统计暂不可用");
  state.failures.set("GET /api/v1/traffic/history", "历史暂不可用");
  state.failures.set("GET /api/v1/traffic/usage", "用量暂不可用");
  await page.goto("/");
  await expect(page.getByLabel("统计用户", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("统计隧道")).toBeVisible();
  await expect(page.locator(".traffic-numbers strong")).toHaveText(["—", "—"]);
  await expect(page.locator(".traffic-total")).toHaveCount(0);
  await expect(page.locator(".traffic-usage strong")).toHaveText(["—", "—", "—"]);
  await expect(page.getByRole("button", { name: "重置统计", exact: true })).toHaveCount(0);
  expect(state.calls.some(call => call.path.startsWith("/api/v1/admin/"))).toBeFalsy();
  state.failures.clear();
  await page.getByLabel("刷新首页").click();
  await expect(page.locator(".traffic-total")).toContainText("时段累计");
  state.failures.set("GET /api/v1/traffic/history", "刷新失败");
  state.failures.set("GET /api/v1/traffic/usage", "用量刷新失败");
  await page.getByLabel("刷新首页").click();
  await expect(page.getByText("刷新失败", { exact: true })).toBeVisible();
  await expect(page.locator(".traffic-usage strong")).toHaveText(["2 KiB", "20 KiB", "200 KiB"]);
  await expect(page.locator(".traffic-total")).toContainText("时段累计");
  await expect(page.locator(".traffic-usage-section").getByText(/保留上次数据/)).toBeVisible();
});

test("切换用户丢弃迟到统计，切走首页停止统计请求", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "竞态与轮询只运行一次");
  const state = await installApiMocks(page);
  let release: (() => void) | undefined;
  const pending = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/api/v1/admin/traffic/realtime?**", async route => {
    if (new URL(route.request().url()).searchParams.get("user_id") !== "alice") return route.fallback();
    await pending;
    await route.fulfill({ json: { sampled_at: Date.now() / 1000, status: "ready", rates: { to_origin: 999999, to_public: 999999 } } });
  });
  await page.goto("/");
  await expect(page.locator(".traffic-numbers")).toContainText("2 KiB/s");
  const requested = page.waitForRequest(req => req.url().includes("/traffic/realtime?") && new URL(req.url()).searchParams.get("user_id") === "alice");
  await page.getByLabel("统计用户", { exact: true }).selectOption("alice");
  await requested;
  await page.getByLabel("统计用户", { exact: true }).selectOption("");
  release!();
  await expect(page.locator(".traffic-numbers")).toContainText("2 KiB/s");
  await page.locator(".sidebar").getByRole("link", { name: "服务", exact: true }).click();
  state.calls.length = 0;
  await page.clock.install(); await page.clock.fastForward(65000);
  expect(state.calls.filter(call => call.path.includes("/traffic/"))).toHaveLength(0);
  await page.locator(".sidebar").getByRole("link", { name: "首页", exact: true }).click();
  await expect(page.locator(".traffic-numbers")).toContainText("2 KiB/s");
  await page.evaluate(() => { Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" }); document.dispatchEvent(new Event("visibilitychange")); });
  state.calls.length = 0; await page.clock.fastForward(65000);
  expect(state.calls.filter(call => call.path.includes("/traffic/"))).toHaveLength(0);
  await page.evaluate(() => { Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" }); document.dispatchEvent(new Event("visibilitychange")); });
  await expect.poll(() => state.calls.filter(call => call.path.includes("/traffic/")).length).toBeGreaterThan(0);
});

test("首页空状态、零流量与缺口、窄屏主题与辅助功能", async ({ page }, info) => {
  test.skip(info.project.name !== "mobile-light", "视觉尺寸矩阵只运行一次");
  const state = await installApiMocks(page, { empty: true }); state.devices = [];
  await page.route("**/api/v1/admin/traffic/history?**", route => route.fulfill({ json: { start: 100, end: 280, step: 60, sampled_at: 280, total: { to_origin: 0, to_public: 0 }, points: [{ at: 100, seconds: 60, covered_seconds: 60, bytes: { to_origin: 0, to_public: 0 }, rates: { to_origin: 0, to_public: 0 } }, { at: 160, seconds: 60, covered_seconds: 0, bytes: { to_origin: 0, to_public: 0 }, rates: null }, { at: 220, seconds: 60, covered_seconds: 60, bytes: { to_origin: 0, to_public: 0 }, rates: { to_origin: 0, to_public: 0 } }] } }));
  await page.goto("/");
  await expect(page.getByRole("link", { name: "创建服务", exact: true })).toBeVisible();
  await page.getByRole("slider").fill("1");
  await expect(page.locator(".chart-reading")).toContainText("此时段未采集");
  await page.getByRole("slider").fill("0");
  await expect(page.locator(".chart-reading")).toContainText("0 B/s");
  for (const theme of ["light", "dark"] as const) for (const [width, height] of [[320, 568], [390, 844], [812, 375], [1440, 900]]) {
    await page.emulateMedia({ colorScheme: theme, reducedMotion: "reduce", contrast: "more" });
    await page.setViewportSize({ width, height });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    await page.screenshot({ path: info.outputPath(`home-${theme}-${width}.png`), fullPage: true });
  }
});
