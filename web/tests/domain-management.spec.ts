import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("列表状态只反映证书和配置，不受服务告警影响", async ({ page }) => {
  const state = await installApiMocks(page);
  const now = Math.floor(Date.now() / 1000);
  const cases = [
    { label: "证书有效", change: { service_warning: "转发尚未就绪" } },
    { label: "待配置", change: { config_status: "disabled" } },
    { label: "待配置", domain: { credential_configured: false }, change: { config_status: "failed", config_error: "缺少 DNS 凭据" } },
    { label: "配置失败", change: { config_status: "failed", config_error: "配置失败的具体原因" } },
    { label: "签发中", change: { certificates: [] } },
    { label: "续期失败", certificate: { error: "续期失败的具体原因", status: "retry_wait" } },
    { label: "签发失败", certificate: { error: "尚未获得证书", status: "failed", expires_at: null, not_before: null } },
    { label: "已过期", certificate: { expires_at: now - 60 } },
  ];
  const original = state.domains[0];
  state.domains = cases.map((item, index) => {
    const domain = structuredClone(original);
    domain.id = `status-${index}`; domain.domain = `status-${index}.example.com`;
    if (item.domain) Object.assign(domain, item.domain);
    Object.assign(domain.runtime!, item.change);
    if (item.certificate) Object.assign(domain.runtime!.certificates[0], item.certificate);
    return domain;
  });
  await page.goto("/#/domains");
  const rows = page.locator(".page-slot:not([hidden]) .domain-compact");
  for (const [index, item] of cases.entries()) await expect(rows.nth(index).locator(".domain-state")).toHaveText(item.label);
  await expect(page.locator(".domain-list")).not.toContainText(/具体原因|转发尚未就绪/);
});

test("单行域名列表支持直接操作，详情按需读取当前域名日志", async ({ page }, info) => {
  const state = await installApiMocks(page);
  state.domains.push({ ...state.domains[0], id: "d-2", domain: "a-very-long-domain-name-for-mobile-layout.example.com", verification_status: "pending" });
  state.domainEvents.push({ id: 2, domain_id: "d-2", summary: "其他域名的事件", occurred_at: Math.floor(Date.now() / 1000) });
  const logRequests: string[] = [];
  page.on("request", request => { if (request.url().includes("public-domain-runtime-events")) logRequests.push(request.url()); });
  for (const width of [320, 375]) {
    await page.setViewportSize({ width, height: 812 });
    await page.goto("/#/domains");
    const rows = page.locator(".page-slot:not([hidden]) .domain-compact");
    await expect(rows).toHaveCount(2);
    for (const row of await rows.all()) {
      const box = (await row.boundingBox())!;
      expect(box.height).toBeLessThanOrEqual(60);
      for (const button of await row.getByRole("button").all()) {
        const bounds = (await button.boundingBox())!;
        expect(bounds.width).toBeGreaterThanOrEqual(44);
        expect(bounds.height).toBeGreaterThanOrEqual(44);
        expect(bounds.x + bounds.width).toBeLessThanOrEqual(width);
      }
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    await expect(rows.last().getByRole("link")).toHaveCSS("text-overflow", "ellipsis");
    await expect(page.getByText("运行日志", { exact: true })).toHaveCount(0);
    await page.screenshot({ path: info.outputPath(`domain-list-${width}.png`) });
  }
  expect(logRequests).toHaveLength(0);
  await page.getByRole("link", { name: "example.com", exact: true }).click();
  const content = page.locator(".page-slot:not([hidden])");
  await expect(content.getByRole("button", { name: "删除 example.com", exact: true })).toBeVisible();
  await expect(content.getByText("解析说明", { exact: true })).toHaveCount(0);
  expect(logRequests).toHaveLength(0);
  await content.getByText("运行日志", { exact: true }).click();
  await expect(content.locator(".domain-events li")).toHaveCount(1);
  await expect(content.locator(".domain-events")).not.toContainText("其他域名的事件");
  expect(logRequests.every(url => new URL(url).searchParams.get("domain_id") === "d-1")).toBeTruthy();
  expect(state.calls.some(call => call.path.endsWith("/access"))).toBeFalsy();
  await page.screenshot({ path: info.outputPath("domain-detail.png") });
});

test("添加后直接打开 DNS 配置，空凭据有明确反馈，保存凭据不写访问解析", async ({ page }, info) => {
  const state = await installApiMocks(page);
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "添加 域名", exact: true }).click();
  const add = page.getByRole("dialog", { name: "添加域名" });
  expect((await add.boundingBox())!.height).toBeLessThan(300);
  await add.getByLabel("域名", { exact: true }).fill("new.example.com");
  await add.getByRole("button", { name: "添加域名", exact: true }).click();
  const config = page.getByRole("dialog", { name: "配置 new.example.com" });
  await expect(config).toBeVisible();
  await expect(config.getByLabel("证书方式")).toHaveCount(0);
  await expect(config.getByRole("region", { name: "域名归属" })).toHaveCount(0);
  await expect(config.getByLabel("API Token")).toBeVisible();
  await expect(config.getByRole("button", { name: "配置解析" })).toBeDisabled();
  await page.screenshot({ path: info.outputPath("dns-credential-form.png") });
  await config.getByRole("button", { name: "验证并启用" }).click();
  await expect(config.getByRole("alert")).toHaveText("请输入 API Token。");
  await expect(config.getByRole("alert")).toBeInViewport();
  await expect(config.getByLabel("API Token")).toBeFocused();
  await config.getByLabel("API Token").fill("cfat_" + "a".repeat(120));
  await config.getByRole("button", { name: "验证并启用" }).click();
  await expect(config.locator(".domain-submit-feedback")).toHaveText("已保存");
  await expect(config.getByRole("button", { name: "配置解析" })).toBeEnabled();
  await expect(config.locator('input[type="password"]')).toHaveCount(0);
  const credentials = (await config.locator(".credential-summary").boundingBox())!;
  const dns = (await config.getByLabel("DNS 解析", { exact: true }).boundingBox())!;
  const advanced = (await config.getByText("高级设置", { exact: true }).boundingBox())!;
  const remove = (await config.getByRole("button", { name: "删除", exact: true }).boundingBox())!;
  const save = (await config.locator(".modal-actions").getByRole("button", { name: "保存", exact: true }).boundingBox())!;
  expect(dns.y - credentials.y - credentials.height).toBeLessThanOrEqual(32);
  expect(advanced.y - dns.y - dns.height).toBeLessThanOrEqual(24);
  expect(Math.abs(remove.y - save.y)).toBeLessThanOrEqual(1);
  expect(remove.x + remove.width).toBeLessThan(save.x);
  await expect(config.getByRole("button", { name: "删除", exact: true })).toBeInViewport();
  expect(remove.width).toBeLessThan(120);
  expect(remove.height).toBeGreaterThanOrEqual(44);
  if ((page.viewportSize()?.width ?? 1440) <= 900 && (page.viewportSize()?.height ?? 900) >= 700) {
    expect((await config.boundingBox())!.height).toBeLessThan(620);
  }
  expect(state.calls.some(call => call.path.endsWith("/dns-records"))).toBeFalsy();
  expect(state.dnsRecords.size).toBe(0);
  await page.screenshot({ path: info.outputPath("dns-credential-saved.png") });
  expect(state.calls.some(call => call.path.endsWith("/access"))).toBeFalsy();
  await config.getByRole("button", { name: "取消", exact: true }).click();
  await page.locator(".page-slot:not([hidden])").getByRole("button", { name: "配置 new.example.com", exact: true }).click();
  await expect(config.getByRole("button", { name: "配置解析" })).toBeEnabled();
});

test("未验证域名列表直接删除，取消、使用中和重试均保留正确状态", async ({ page }) => {
  const state = await installApiMocks(page);
  state.domains[0].verification_status = "pending";
  await page.goto("/#/domains");
  const remove = page.getByRole("button", { name: "删除 example.com", exact: true });
  await remove.click();
  const confirm = page.getByRole("dialog", { name: "删除 example.com？", exact: true });
  await expect(confirm).toContainText("删除后无法恢复。");
  await confirm.getByRole("button", { name: "取消", exact: true }).click();
  expect(state.calls.filter(call => call.method === "DELETE")).toHaveLength(0);
  await remove.click();
  state.failures.set("DELETE /api/v1/public-domains/d-1", "该域名仍被服务「NAS」使用，请先修改或删除关联服务");
  state.failureStatuses.set("DELETE /api/v1/public-domains/d-1", 409);
  await confirm.getByRole("button", { name: "删除", exact: true }).click();
  await expect(confirm.getByRole("alert")).toContainText("NAS");
  expect(state.domains).toHaveLength(1);
  state.failures.clear();
  await confirm.getByRole("button", { name: "删除", exact: true }).click();
  await expect(confirm).toBeHidden();
  await expect(page.getByRole("heading", { name: "还没有域名" })).toBeVisible();
});

test("已有解析器清空保存后重新打开仍使用 Caddy 默认", async ({ page }) => {
  const state = await installApiMocks(page);
  Object.assign(state.domains[0], { certificate_mode: "cloudflare_dns", verification_status: "verified", credential_configured: true, dns_resolvers: ["223.5.5.5:53", "223.6.6.6:53"] });
  await page.route("**/api/v1/public-domains/d-1", async route => {
    const input = route.request().postDataJSON();
    expect(input.dns_resolvers).toEqual([]);
    Object.assign(state.domains[0], input);
    await route.fulfill({ json: state.domains[0] });
  });
  await page.goto("/#/domains");
  const open = page.getByRole("button", { name: "配置 example.com", exact: true });
  await open.click();
  const config = page.getByRole("dialog", { name: "配置 example.com" });
  await config.getByText("高级设置", { exact: true }).click();
  await expect(config.getByLabel("DNS 解析器")).toHaveValue("223.5.5.5:53, 223.6.6.6:53");
  await config.getByLabel("DNS 解析器").fill("");
  await config.locator("details").getByRole("button", { name: "保存", exact: true }).click();
  await expect(config.getByRole("status")).toHaveText("已保存");
  await expect(config.getByLabel("DNS 解析器")).toHaveValue("");
  await config.getByRole("button", { name: "取消", exact: true }).click();
  await open.click();
  await config.getByText("高级设置", { exact: true }).click();
  await expect(config.getByLabel("DNS 解析器")).toHaveValue("");
});
