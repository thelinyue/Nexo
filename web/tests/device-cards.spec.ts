import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const cards = (page: import("@playwright/test").Page) => page.locator(".page-slot:not([hidden]) .agent-row");

test("设备卡片显示状态、服务、版本和独立提醒，已有名称保留且键盘可进入详情", async ({ page }) => {
  const state = await installApiMocks(page);
  state.enrollments = [];
  state.devices = [
    { id: "old", name: "家庭 Agent", status: "online", tunnel_count: 3, agent_version: "0.2.9", certificate: { status: "expired", expires_at: 1, renew_after: 1, error: null, next_retry_at: null } },
    { id: "current", name: "当前设备", status: "offline", tunnel_count: 0, agent_version: "0.2.14" },
    { id: "newer", name: "较新设备", status: "online", tunnel_count: 1, agent_version: "0.2.18" },
    { id: "unknown", name: "未上报设备", status: "offline", tunnel_count: 0, agent_version: null },
  ];
  await page.goto("/#/agents");
  await expect(cards(page)).toHaveCount(4);
  const old = cards(page).nth(0);
  await expect(old.locator("strong")).toHaveText("家庭 Agent");
  await expect(old.getByText("在线", { exact: true })).toBeVisible();
  await expect(old.locator("dd").first()).toHaveText("3 个");
  await expect(old.locator(".device-version-number")).toHaveText("v0.2.9");
  await expect(old.locator(".device-update-badge")).toBeVisible();
  await expect(old.locator(".device-update-badge")).toHaveAttribute("title", "建议更新至 v0.2.14");
  await expect(old).toContainText("建议更新至 v0.2.14");
  await expect(old).toContainText("证书已过期");
  await expect(cards(page).nth(1).getByText("离线", { exact: true })).toBeVisible();
  await expect(cards(page).nth(1).locator("dd")).toHaveText(["0 个", "v0.2.14"]);
  await expect(cards(page).nth(1)).not.toContainText("建议更新");
  await expect(cards(page).nth(2)).not.toContainText("建议更新");
  await expect(cards(page).nth(3)).toContainText("版本待上报");
  await expect(cards(page).nth(3)).not.toContainText("建议更新");
  await old.focus(); await old.press("Enter");
  await expect(page).toHaveURL(/#\/agents\/old$/);
  const notes = page.getByRole("link", { name: "查看更新说明" });
  await expect(notes).toHaveAttribute("href", state.agentRelease.release_url!);
  await expect(notes).toHaveAttribute("target", "_blank");
});

test("离线设备也提示旧版本，开发版、未知版本和没有正式版本时不误报", async ({ page }) => {
  const state = await installApiMocks(page);
  state.devices = ["0.2.9", "test", "0.2.15-rc.1", "v0.2.14", "0.02.1"].map((version, i) => ({ id: `device-${i}`, name: `设备 ${i}`, status: "offline", tunnel_count: 0, agent_version: version }));
  await page.goto("/#/agents");
  await expect(cards(page).nth(0)).toContainText("建议更新至 v0.2.14");
  for (let i = 1; i < 5; i++) await expect(cards(page).nth(i)).not.toContainText("建议更新");
  await expect(cards(page).nth(1)).toContainText("test");
  state.agentRelease = { version: null, release_url: null };
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.locator(".device-update-badge")).toHaveCount(0);
});

test("版本检查失败可独立重试，恢复后每十五分钟更新且普通设备刷新不重复检查", async ({ page }) => {
  await page.clock.install();
  const state = await installApiMocks(page);
  state.failures.set("GET /api/v1/agent-release", "暂时无法检查设备更新，请稍后重试");
  await page.goto("/#/agents");
  await expect(cards(page)).toHaveCount(2);
  await expect(page.getByRole("alert")).toContainText("暂时无法检查设备更新");
  await expect(page.locator(".device-update-badge")).toHaveCount(0);
  state.failures.clear();
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await expect(cards(page).nth(0)).toContainText("建议更新至 v0.2.14");
  const checks = () => state.calls.filter(call => call.path === "/api/v1/agent-release").length;
  const before = checks();
  await page.clock.fastForward(30_000);
  await expect(cards(page)).toHaveCount(2);
  expect(checks()).toBe(before);
  state.agentRelease.version = "0.2.18";
  await page.clock.fastForward(15 * 60_000);
  await expect(cards(page).nth(0)).toContainText("建议更新至 v0.2.18");
  expect(checks()).toBeGreaterThan(before);
  state.failures.set("GET /api/v1/agent-release", "暂时无法检查设备更新，请稍后重试");
  await page.goto("/#/agents/a-1");
  await expect(page.getByRole("alert")).toContainText("暂时无法检查设备更新");
  await expect(page.getByRole("link", { name: "查看更新说明" })).toHaveCount(0);
});

test("卡片在明暗主题、窄屏和横屏完整展示且没有横向溢出", async ({ page }, info) => {
  const state = await installApiMocks(page);
  state.enrollments = [];
  state.devices[0].name = "很长的家庭存储设备名称".repeat(8);
  state.devices[0].certificate = { status: "retry_wait", expires_at: 1, renew_after: 1, error: null, next_retry_at: 1 };
  state.devices.push({ ...state.devices[0], id: "third", name: "第三台设备" });
  const sizes = info.project.name === "desktop-dark" ? [[1440, 900], [1000, 768], [320, 568], [812, 375]] : [[page.viewportSize()!.width, page.viewportSize()!.height]];
  for (const scheme of ["light", "dark"] as const) for (const [width, height] of sizes) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await page.setViewportSize({ width, height });
    await page.goto("/#/agents");
    await expect(cards(page)).toHaveCount(3);
    await expect(cards(page).nth(0)).toContainText("证书续签待重试");
    const list = page.getByRole("region", { name: "设备列表" });
    const columns = await list.evaluate(element => getComputedStyle(element).gridTemplateColumns.split(" ").length);
    expect(columns).toBe(width > 1200 ? 3 : width > 600 ? 2 : 1);
    await expect(cards(page).nth(0).locator("strong")).toHaveAttribute("title", state.devices[0].name);
    for (const card of await cards(page).all()) expect(await card.evaluate(element => element.scrollWidth <= element.clientWidth)).toBeTruthy();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    await page.screenshot({ path: info.outputPath(`devices-${width}-${scheme}.png`), fullPage: true });
  }
});
