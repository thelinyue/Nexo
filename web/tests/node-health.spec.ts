import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("服务逐节点检查区分健康、失败、兼容、过期和待检查，长错误不溢出", async ({ page }, info) => {
  const state = await installApiMocks(page);
  const now = Math.floor(Date.now() / 1000);
  const message = "入口检查失败，请核对端口和证书";
  const error = message + ": certificate-" + "hostname-mismatch-".repeat(12);
  state.tunnels[0].node_ids = ["ready", "failed", "legacy", "stale", "pending"];
  state.tunnels[0].node_statuses = [
    { node_id: "ready", node_name: "香港 VPS", healthy: true, error: null, checked_at: now, public_probe: { kind: "https", healthy: true, checked_at: now, error: null } },
    // 前两次失败处于撤出防抖期；仍可用的整体状态不能掩盖最近探测错误。
    { node_id: "failed", node_name: "日本 VPS", healthy: true, error: null, checked_at: now, public_probe: { kind: "https", healthy: true, checked_at: now, error } },
    { node_id: "legacy", node_name: "旧版 VPS", healthy: true, error: null, checked_at: now, public_probe: { kind: "tcp", healthy: true, checked_at: now, error: null } },
    { node_id: "stale", node_name: "离线 VPS", healthy: false, error: "等待 Agent 确认目标可连接", checked_at: now - 90, public_probe: { kind: "https", healthy: false, checked_at: now - 90, error: null } },
    { node_id: "pending", node_name: "待检查 VPS", healthy: false, error: null, checked_at: now, public_probe: { kind: "https", healthy: false, checked_at: null, error: null } },
  ];
  await page.goto("/#/services/t-1");
  const detail = page.getByRole("dialog", { name: "媒体中心", exact: true });
  const connections = detail.locator(".service-detail-connections");
  const row = (name: string) => connections.locator(".detail-field").filter({ has: page.locator("dt", { hasText: name }) });
  await expect(row("香港 VPS")).toContainText("HTTPS 检查");
  await expect(row("香港 VPS")).toContainText("健康");
  await expect(row("日本 VPS")).toContainText("检查失败");
  await expect(row("日本 VPS").locator("summary")).toHaveText(message);
  await expect(row("日本 VPS").getByText(error, { exact: true })).toBeHidden();
  await expect(row("旧版 VPS")).toContainText("TCP 检查（兼容）");
  await expect(row("离线 VPS")).toContainText("已过期");
  await expect(row("待检查 VPS")).toContainText("待检查");
  await expect(row("香港 VPS").locator("time")).toHaveAttribute("datetime", new Date(now * 1000).toISOString());
  await expect(row("待检查 VPS").locator("time")).toHaveCount(0);
  expect(await detail.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
  expect(await connections.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
  await row("日本 VPS").scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath("node-public-probe-diagnostics.png") });
  await row("日本 VPS").locator("summary").focus();
  await page.keyboard.press("Enter");
  await expect(row("日本 VPS").getByText(error, { exact: true })).toBeVisible();
  expect(await connections.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath("node-public-probe-error-expanded.png") });
  await detail.getByText("状态说明", { exact: true }).click();
  await expect(detail).toContainText("应用与访问者网络需实际访问验证");
});

test("全部 IPv4 入口失效显示入口不可用，并保留 IPv6 直连状态", async ({ page }, info) => {
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], {
    apply_status: "checking", apply_error: "暂无可用 IPv4 入口", ipv6_direct_enabled: true,
    node_ids: ["failed"],
    node_statuses: [{ node_id: "failed", node_name: "香港 VPS", healthy: false, error: null, checked_at: Math.floor(Date.now() / 1000), public_probe: { kind: "https", healthy: false, checked_at: Math.floor(Date.now() / 1000), error: "公网入口检查超时（3 秒）" } }],
    direct_status: { status: "configured", address: "2001:4860::1", public_reachability: "unverified" },
  });
  await page.goto("/#/services/t-1");
  const detail = page.getByRole("dialog", { name: "媒体中心", exact: true });
  await expect(detail.getByText("暂无可用 IPv4 入口", { exact: true })).toBeVisible();
  await expect(detail).toContainText("已配置，公网未验证");
  await expect(detail).toContainText("2001:4860::1");
  await expect(detail).not.toContainText("域名无法解析");
  expect(await detail.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath("no-ipv4-entry-with-ipv6.png") });
  await detail.getByText("IPv6 直连", { exact: true }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath("ipv6-preserved-without-ipv4.png") });
});
