import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("首页默认概览、图内选点与键盘读数跨主题可用", async ({ page }, info) => {
  await installApiMocks(page);
  await page.goto("/");
  const plot = page.locator(".chart-plot");
  const slider = page.getByRole("slider", { name: "查看流量时间点" });
  await expect(plot.getByRole("img")).toBeVisible();
  await expect(page.getByRole("button", { name: "刷新首页", exact: true })).toHaveCount(0);
  await expect(page.getByLabel("统计用户", { exact: true })).toBeHidden();
  await expect(page.locator(".chart-selection")).toHaveCount(0);
  await expect(page.locator(".chart-tooltip")).toHaveCount(0);
  const sliderBox = (await slider.boundingBox())!;
  expect(sliderBox.width).toBe(1); expect(sliderBox.height).toBe(1);
  const bounds = (await plot.boundingBox())!;
  expect(bounds.height).toBe(info.project.name === "desktop-dark" ? 220 : 170);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  if (info.project.name === "desktop-dark") {
    const attention = (await page.locator(".home-attention").boundingBox())!;
    expect(attention.x).toBeGreaterThan(bounds.x + bounds.width);
    expect(bounds.y + bounds.height).toBeLessThan(900);
  } else {
    await expect(page.getByRole("button", { name: "展开", exact: true })).toHaveAttribute("aria-expanded", "false");
    await page.getByRole("button", { name: "展开", exact: true }).click();
    await expect(page.locator(".home-attention-items").getByRole("link", { name: /备用设备/ })).toBeVisible();
    await page.getByRole("button", { name: "收起", exact: true }).click();
  }
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme });
    await page.screenshot({ path: info.outputPath(`home-${colorScheme}.png`), fullPage: true, animations: "disabled" });
  }
  const live = await page.locator(".traffic-numbers").innerText();
  await plot.scrollIntoViewIfNeeded();
  for (const fraction of [0, 1]) {
    const box = (await plot.boundingBox())!;
    const position = { x: fraction ? box.width - 9 : 39, y: 60 };
    if (info.project.name === "desktop-dark") await page.mouse.move(box.x + position.x, box.y + position.y);
    else await plot.tap({ position });
    await expect(page.locator(".chart-tooltip")).toBeVisible();
    const tip = (await page.locator(".chart-tooltip").boundingBox())!;
    expect(tip.x).toBeGreaterThanOrEqual(box.x);
    expect(tip.x + tip.width).toBeLessThanOrEqual(box.x + box.width + 1);
    expect(tip.y + tip.height).toBeLessThanOrEqual(box.y + box.height);
  }
  await page.screenshot({ path: info.outputPath("home-inspect.png"), fullPage: true, animations: "disabled" });
  if (info.project.name === "desktop-dark") await page.mouse.move(0, 0);
  else await page.locator(".traffic-trend-heading h3").tap();
  await expect(page.locator(".chart-tooltip")).toHaveCount(0);
  await expect(page.locator(".chart-selection")).toHaveCount(1);
  await expect(page.locator(".chart-reading")).toContainText("发往内网");
  await expect(page.locator(".traffic-numbers")).toHaveText(live, { useInnerText: true });
  await slider.focus();
  await slider.press("Home");
  await expect(slider).toHaveValue("0");
  await expect(slider).toHaveAttribute("aria-valuetext", /发往内网.*返回公网/);
  await expect(plot).toHaveCSS("outline-style", "solid");
  await slider.press("ArrowRight");
  await expect(slider).toHaveValue("1");
  await slider.press("End");
  await expect(slider).toHaveValue("287");
  await slider.press("Escape");
  await expect(page.locator(".chart-tooltip")).toHaveCount(0);
});

test("渐变不跨越缺口，缺失、部分采集、单点和零流量保持真实读数", async ({ page }) => {
  await installApiMocks(page);
  const sample = (at: number, rate: number | null, covered = 60) => ({ at, seconds: 60, covered_seconds: rate === null ? 0 : covered, bytes: { to_origin: 0, to_public: 0 }, rates: rate === null ? null : { to_origin: rate, to_public: rate } });
  let points = [sample(100, 0), sample(160, 1024), sample(220, null), sample(280, null), sample(340, 0), sample(400, 102400)];
  await page.route("**/api/v1/admin/traffic/history?**", route => route.fulfill({ json: { start: 100, end: 460, step: 60, sampled_at: 460, total: { to_origin: 0, to_public: 0 }, points } }));
  await page.goto("/");
  const plot = page.locator(".chart-plot");
  await expect(plot.getByRole("img")).toBeVisible();
  const width = (await plot.boundingBox())!.width;
  const leftGap = 38 + (width - 46) / 3, rightGap = 38 + (width - 46) / 2;
  const areas = await page.locator(".chart-area").evaluateAll(paths => paths.map(path => { const b = (path as SVGPathElement).getBBox(); return { left: b.x, right: b.x + b.width }; }));
  expect(areas.length).toBe(4);
  expect(areas.every(area => area.right < leftGap || area.left > rightGap)).toBeTruthy();
  const slider = page.getByRole("slider");
  await slider.focus(); await slider.press("Home");
  await expect(slider).toHaveAttribute("aria-valuetext", /0 B\/s/);
  await slider.press("ArrowRight"); await slider.press("ArrowRight");
  await expect(page.locator(".chart-reading")).toContainText("此时段未采集");
  await expect(page.locator(".chart-selected-dot")).toHaveCount(0);
  points = [sample(100, 500, 30)];
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(slider).toHaveAttribute("max", "0");
  await expect(page.locator(".chart-reading")).toContainText("部分时间未采集");
  await expect(plot.locator("circle")).not.toHaveCount(0);
  await expect(page.locator(".chart-area")).toHaveCount(0);
  points = [];
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.locator(".traffic-empty")).toBeVisible();
  await expect(slider).toHaveCount(0);
  await expect(page.locator(".chart-reading")).toHaveCount(0);
});

test("折叠筛选保留对象，用量和实时速率不跟随图内选点", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/");
  const filters = page.getByRole("button", { name: "流量筛选", exact: true });
  await filters.click();
  await page.getByLabel("统计用户", { exact: true }).selectOption("alice");
  await page.getByLabel("统计隧道", { exact: true }).selectOption("t-1");
  await expect(page.locator(".traffic-numbers")).toContainText("2 KiB/s");
  await filters.click();
  await expect(page.getByLabel("统计隧道", { exact: true })).toBeHidden();
  await expect(page.locator(".traffic-filter-heading")).toContainText("alice");
  await expect(page.locator(".traffic-scope-label")).toContainText("媒体中心");
  await page.getByRole("button", { name: "7 天", exact: true }).click();
  await expect(page.locator(".traffic-usage strong")).toHaveText(["2 KiB", "20 KiB", "200 KiB"]);
  await filters.click();
  await expect(page.getByLabel("统计用户", { exact: true })).toHaveValue("alice");
  await expect(page.getByLabel("统计隧道", { exact: true })).toHaveValue("t-1");
});

test("首页窄屏、放大文字及辅助功能偏好不溢出", async ({ page }, info) => {
  test.skip(info.project.name !== "mobile-light", "尺寸矩阵运行一次，其余项目覆盖原生交互");
  await installApiMocks(page);
  await page.goto("/");
  await expect(page.locator(".chart-plot svg")).toBeVisible();
  for (const colorScheme of ["light", "dark"] as const) for (const [width, height] of [[320, 568], [375, 812], [390, 844], [812, 375], [901, 900], [1199, 900], [1200, 900], [1440, 900]]) {
    await page.setViewportSize({ width, height });
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce", contrast: "more" });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    const box = (await page.locator(".chart-plot").boundingBox())!;
    expect(box.height).toBe(width > 900 ? 220 : 170);
  }
  await page.setViewportSize({ width: 320, height: 568 });
  await page.evaluate(() => document.documentElement.style.fontSize = "200%");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("home-large-text.png"), fullPage: true, animations: "disabled" });
});
