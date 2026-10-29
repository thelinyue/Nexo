import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("首页呈现完整天眼布局并可打开单服务统计与会话明细", async ({ page }, info) => {
  await installApiMocks(page);
  const errors: string[] = []; page.on("pageerror", error => errors.push(error.message));
  await page.goto("/");
  await expect(page.locator(".eye-kpis").first().locator(".eye-kpi")).toHaveCount(5);
  await expect(page.locator(".eye-kpis").first()).toContainText("742");
  if (page.viewportSize()!.width <= 600) {
    for (const label of ["统计服务类型", "统计协议"]) {
      expect((await page.getByLabel(label, { exact: true }).boundingBox())!.width).toBeGreaterThanOrEqual(120);
    }
  }
  await expect(page.getByRole("heading", {name:"状态码分布",exact:true})).toBeVisible();
  await expect(page.getByRole("heading", {name:"访客画像",exact:true})).toBeVisible();
  await expect(page.getByRole("heading", {name:"TOP 来源国家 / 地区",exact:true})).toBeVisible();
  await expect(page.getByRole("heading", {name:"TOP 域名",exact:true})).toBeVisible();
  const requests = page.getByRole("region", {name:"实时请求流",exact:true});
  await requests.scrollIntoViewIfNeeded(); await expect(requests).toContainText("/media");
  await page.locator(".eye-services").getByRole("button",{name:"媒体中心",exact:true}).click();
  const dialog = page.getByRole("dialog",{name:"媒体中心 · 统计",exact:true}); await expect(dialog).toBeVisible();
  await expect(dialog.locator(".eye-kpis")).toContainText("PV"); await expect(dialog.locator(".eye-kpis")).toContainText("UV");
  await dialog.getByRole("button",{name:"关闭",exact:true}).click(); await expect(dialog).toHaveCount(0);
  await page.locator(".eye-session-details summary").click();
  await expect(page.getByRole("region",{name:"会话明细",exact:true})).toContainText("正常结束");
  expect(errors).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({path:info.outputPath("traffic-eye.png"),fullPage:true});
});

test("协议、服务类型、时间范围可刷新恢复，筛选请求与明细同步", async ({ page }) => {
  await installApiMocks(page); await page.goto("/");
  await page.getByLabel("统计协议",{exact:true}).selectOption("websocket");
  await page.getByLabel("统计服务类型",{exact:true}).selectOption("reverse_proxy");
  await page.getByRole("group", {name:"请求状态筛选",exact:true}).getByRole("button",{name:"5xx",exact:true}).click();
  const sent = page.waitForRequest(req => req.url().includes("/analytics/summary?") && new URL(req.url()).searchParams.get("range") === "90d");
  await page.getByRole("group",{name:"天眼时间范围",exact:true}).getByRole("button",{name:"90天",exact:true}).click();
  const url = new URL((await sent).url()); expect(url.searchParams.get("mode")).toBe("reverse_proxy"); expect(url.searchParams.get("protocol")).toBe("websocket");
  expect(url.searchParams.get("status_class")).toBe("5");
  await page.reload();
  await expect(page.getByLabel("统计协议",{exact:true})).toHaveValue("websocket");
  await expect(page.getByRole("group",{name:"天眼时间范围",exact:true}).getByRole("button",{name:"90天",exact:true})).toHaveAttribute("aria-pressed","true");
});

test("天眼接口失败、恢复和键盘读数保持明确", async ({ page }) => {
  const state=await installApiMocks(page);state.failures.set("GET /api/v1/admin/traffic/analytics/summary","采集暂不可用");
  await page.goto("/"); await expect(page.locator(".eye-dashboard").getByText("采集暂不可用",{exact:false}).first()).toBeVisible();
  await expect(page.locator(".eye-kpis").first()).toContainText("—");
  state.failures.clear(); await page.locator(".eye-dashboard").getByRole("button",{name:"重试",exact:true}).first().click();
  await expect(page.locator(".eye-kpis").first()).toContainText("742");
  const slider=page.getByRole("slider",{name:"查看发往内网趋势时间点",exact:true}).first();await slider.focus();await slider.press("Home");await slider.press("ArrowRight");
  await expect(slider).toHaveAttribute("aria-valuetext",/发往内网/);
});

for (const sessions of [false, true]) {
  test(`${sessions ? "会话" : "请求"}明细支持连续翻页，暂停不阻止翻页和返回最新`, async ({ page }) => {
    await installApiMocks(page);
    await page.route(`**/traffic/analytics/${sessions ? "sessions" : "requests"}?*`, route => {
      const cursor = new URL(route.request().url()).searchParams.get("cursor");
      const index = cursor ? Number(cursor) : 1;
      return route.fulfill({ json: {
        items: [{ id: `entry-${index}`, at: Math.floor(Date.now() / 1000), service: "t-1", name: `第${index}页服务`, node: "local", protocol: sessions ? "tcp" : "https", method: "GET", path: `/page-${index}`, status: 200, duration_ms: 10, to_origin: 10, to_public: 20, source: "", country: "未知", browser: "", reason: "closed" }],
        next_cursor: index < 3 ? String(index + 1) : null, retention_days: 7,
      } });
    });
    await page.goto("/");
    if (sessions) await page.locator(".eye-session-details summary").click();
    const stream = page.getByRole("region", { name: sessions ? "会话明细" : "实时请求流", exact: true });
    await stream.scrollIntoViewIfNeeded();
    await expect(stream).toContainText("第1页服务");
    await stream.getByRole("button", { name: "下一页", exact: true }).click();
    await expect(stream).toContainText("第2页服务");
    await stream.getByRole("button", { name: "下一页", exact: true }).click();
    await expect(stream).toContainText("第3页服务");
    await expect(stream.getByRole("button", { name: "下一页", exact: true })).toBeDisabled();
    await stream.getByRole("button", { name: "暂停显示", exact: true }).click();
    await stream.getByRole("button", { name: "返回最新", exact: true }).click();
    await expect(stream).toContainText("第1页服务");
    await stream.getByRole("button", { name: "暂停显示", exact: true }).click();
    await stream.getByRole("button", { name: "下一页", exact: true }).click();
    await expect(stream).toContainText("第2页服务");
  });
}

test("实时吞吐单独失败时显示错误并支持重试", async ({ page }) => {
  await installApiMocks(page);
  let fail = true;
  await page.route("**/traffic/analytics/summary?*", route => {
    if (fail && new URL(route.request().url()).searchParams.get("range") === "live") {
      return route.fulfill({ status: 503, json: { error: "实时采集暂不可用" } });
    }
    return route.fallback();
  });
  await page.goto("/");
  await expect(page.locator(".eye-kpis").first()).toContainText("742");
  const throughput = page.locator(".eye-throughput").first();
  await expect(throughput).toContainText("实时采集暂不可用");
  fail = false;
  await throughput.getByRole("button", { name: "重试", exact: true }).click();
  await expect(throughput.getByRole("img")).toBeVisible();
  await expect(throughput.getByRole("alert")).toHaveCount(0);
});

test("没有请求的延迟采样点不显示为零毫秒", async ({ page }) => {
  await installApiMocks(page);
  await page.route("**/traffic/analytics/summary?*", async route => {
    const now = Math.floor(Date.now() / 1000);
    const totals = { requests: 0, errors: 0, sessions: 0, duration_ms: 0, session_ms: 0, to_origin: 0, to_public: 0, peak: 0 };
    await route.fulfill({ json: { sampled_at: now, started_at: now - 86400, uptime: 86400, status: "ready", start: now - 60, end: now, step: 60, partial: false, dropped: 0, geo_available: false, totals, qps: 0, active: 0, uv_daily_sum: 0, p50_ms: null, p95_ms: null, series: [{ at: now - 60, covered: true, partial: false, totals, p50_ms: null, p95_ms: null }], services: [], protocols: {}, breakdowns: {} } });
  });
  await page.goto("/");
  const slider = page.getByRole("slider", { name: "查看p50 上界趋势时间点", exact: true });
  await slider.focus();
  // 单点范围不能移动，点选图表也应提供相同的缺失值语义。
  await page.getByRole("img", { name: "p50 上界与p95 上界趋势", exact: true }).click();
  await expect(slider).toHaveAttribute("aria-valuetext", /p50 上界 —.*p95 上界 —/);
});

test("天眼在小屏与放大文字下保留触控热区且不溢出", async ({ page }) => {
  await installApiMocks(page);
  await page.setViewportSize({ width: 320, height: 568 });
  await page.goto("/");
  await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
  await expect(page.locator(".eye-kpis").first()).toContainText("742");
  const stream = page.getByRole("region", { name: "实时请求流", exact: true });
  await stream.scrollIntoViewIfNeeded();
  await expect(stream).toContainText("/media");
  expect((await page.getByLabel("统计服务类型", { exact: true }).boundingBox())!.width).toBeGreaterThanOrEqual(120);
  expect((await page.getByLabel("统计协议", { exact: true }).boundingBox())!.width).toBeGreaterThanOrEqual(120);
  for (const button of await page.locator(".eye-scope-controls button:visible, .eye-dashboard button:visible").all()) {
    const box = (await button.boundingBox())!;
    expect(box.height).toBeGreaterThanOrEqual(44);
    expect(box.width).toBeGreaterThanOrEqual(44);
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
});
