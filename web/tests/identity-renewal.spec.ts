import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("离线设备显示到期提醒，详情显示失败原因与重试时间", async ({ page }, testInfo) => {
  const state = await installApiMocks(page);
  const now = Math.floor(Date.now()/1000);
  state.devices[1].certificate = { status: "retry_wait", expires_at: now + 2*86400, renew_after: now - 28*86400, error: "保存续签证书失败：磁盘空间不足", next_retry_at: now + 300 };
  await page.goto("/#/agents");
  await expect(page.getByRole("link", { name: /备用 Agent.*证书续签待重试/ })).toBeVisible();
  await page.getByRole("link", { name: /备用 Agent.*证书续签待重试/ }).click();
  const card = page.getByRole("region", { name: "设备内部证书" });
  await expect(card.getByText("保存续签证书失败：磁盘空间不足")).toBeVisible();
  await expect(card.getByText("下次重试", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: testInfo.outputPath("device-renewal.png"), fullPage: true });
  expect(state.calls.filter(call => call.method !== "GET")).toHaveLength(0);
});

test("服务端失败和 CA 到期提醒可见，刷新后清除成功续签的旧错误", async ({ page }) => {
  const state = await installApiMocks(page);
  state.transportIdentity.server.status = "retry_wait";
  state.transportIdentity.server.error = "内部服务端证书续签失败：无法保存身份文件";
  state.transportIdentity.server.next_retry_at = Math.floor(Date.now()/1000) + 60;
  state.transportIdentity.ca_needs_attention = true;
  await page.goto("/#/manage");
  const card = page.getByRole("region", { name: "服务端内部证书" });
  await expect(card.getByText(/内部 CA 需维护/)).toBeVisible();
  await card.locator("summary").click();
  await expect(card.getByText(state.transportIdentity.server.error)).toBeVisible();
  state.transportIdentity.server.status = "valid";
  state.transportIdentity.server.error = null;
  state.transportIdentity.server.next_retry_at = null;
  state.transportIdentity.ca_needs_attention = false;
  await card.getByRole("button", { name: "刷新内部证书" }).click();
  await expect(card.locator("summary")).toContainText("证书有效");
  await expect(card.getByText(/内部 CA 需维护/)).toHaveCount(0);
  await expect(card.getByText(/无法保存身份文件/)).toHaveCount(0);
});
