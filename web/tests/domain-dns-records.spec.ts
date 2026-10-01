import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import type { DnsRecord } from "../src/ui";

const record = (name: string, kind: string, value: string, proxied = false): DnsRecord => ({ id: `${name}-${kind}-${value}`, name, kind, value, ttl: 600, proxied });

test("解析只在预览确认后写入，取消不写入，重复执行复用一致记录", async ({ page }, info) => {
  const state = await installApiMocks(page);
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "配置 example.com", exact: true }).click();
  const config = page.getByRole("dialog", { name: "配置 example.com" });
  const preview = config.getByLabel("解析预览", { exact: true });
  const writeCalls = () => state.calls.filter(call => call.path.endsWith("/dns-records") && call.method === "POST");
  expect(state.calls.some(call => call.path.endsWith("/dns-records"))).toBeFalsy();
  await config.getByRole("button", { name: "配置解析" }).click();
  await expect(preview).toContainText("8.8.8.8");
  await expect(preview.getByText("example.com", { exact: true })).toBeVisible();
  await expect(preview.getByText("*.example.com", { exact: true })).toBeVisible();
  expect(writeCalls()).toHaveLength(0);
  await preview.getByRole("button", { name: "取消", exact: true }).click();
  await expect(preview).toHaveCount(0);
  expect(writeCalls()).toHaveLength(0);
  await config.getByRole("button", { name: "配置解析" }).click();
  await preview.getByRole("button", { name: "确认写入" }).scrollIntoViewIfNeeded();
  await expect(config.locator(".modal-actions")).toBeInViewport();
  expect(await config.evaluate(element => element.scrollWidth <= element.clientWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("dns-preview.png") });
  await preview.getByRole("button", { name: "确认写入" }).click();
  const result = config.getByLabel("解析结果", { exact: true });
  await expect(result.getByRole("status")).toHaveText(["已写入", "已写入"]);
  await expect(result).toContainText("DNS 传播及公网访问尚未验证");
  expect(writeCalls()[0].body.confirm_takeover).toBe(false);
  expect(writeCalls()[0].body.preview.hosts).toHaveLength(2);
  await config.getByRole("button", { name: "配置解析" }).click();
  await expect(preview.getByText("保持不变", { exact: true })).toHaveCount(2);
  await preview.getByRole("button", { name: "确认写入" }).click();
  await expect(result.getByRole("status")).toHaveText(["记录一致", "记录一致"]);
});

test("冲突明确确认接管，A 与 CNAME 被替换，其他类型记录保留", async ({ page }, info) => {
  const state = await installApiMocks(page);
  const other = record("example.com", "AAAA", "2001:4860::1");
  state.dnsRecords.set("example.com", [record("example.com", "A", "1.1.1.1", true), other]);
  state.dnsRecords.set("*.example.com", [record("*.example.com", "CNAME", "previous-site.example.net")]);
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "配置 example.com", exact: true }).click();
  const config = page.getByRole("dialog", { name: "配置 example.com" });
  await config.getByRole("button", { name: "配置解析" }).click();
  const preview = config.getByLabel("解析预览", { exact: true });
  await expect(preview).toContainText("1.1.1.1");
  await expect(preview).toContainText("previous-site.example.net");
  await expect(preview).toContainText("2001:4860::1");
  await expect(preview).toContainText("可能改变原有网站入口");
  await expect(preview.getByRole("button", { name: "确认写入" })).toHaveCount(0);
  const confirm = preview.getByRole("button", { name: "确认接管" });
  await confirm.scrollIntoViewIfNeeded();
  const footer = (await config.locator(".modal-actions").boundingBox())!;
  const bounds = (await confirm.boundingBox())!;
  expect(bounds.y + bounds.height).toBeLessThanOrEqual(footer.y + 1);
  expect(await config.evaluate(element => element.scrollWidth <= element.clientWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("dns-takeover.png") });
  await confirm.click();
  await expect(config.getByLabel("解析结果").getByRole("status")).toHaveText(["已写入", "已写入"]);
  expect(state.calls.find(call => call.path.endsWith("/dns-records") && call.method === "POST")?.body.confirm_takeover).toBe(true);
  expect(state.dnsRecords.get("example.com")).toContainEqual(other);
});

test("预览后记录变化有冲突反馈，重新预览后才能重试", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "配置 example.com", exact: true }).click();
  const config = page.getByRole("dialog", { name: "配置 example.com" });
  await config.getByRole("button", { name: "配置解析" }).click();
  state.dnsRecords.set("example.com", [record("example.com", "A", "9.9.9.9")]);
  state.failures.set("POST /api/v1/public-domains/d-1/dns-records", "解析记录或公网 IPv4 已变化，请重新预览后确认");
  state.failureStatuses.set("POST /api/v1/public-domains/d-1/dns-records", 409);
  await config.getByRole("button", { name: "确认写入" }).click();
  await expect(config.getByRole("alert")).toContainText("请重新预览");
  await expect(config.getByLabel("解析预览")).toHaveCount(0);
  state.failures.clear();
  await config.getByRole("button", { name: "配置解析" }).click();
  await expect(config.getByLabel("解析预览")).toContainText("9.9.9.9");
  await config.getByRole("button", { name: "确认接管" }).click();
  await expect(config.getByLabel("解析结果").getByRole("status")).toHaveText(["已写入", "已写入"]);
});

test("部分失败分别反馈，保留成功主域名，手动重新预览并重试泛域名", async ({ page }, info) => {
  const state = await installApiMocks(page); let fail = true;
  await page.route("**/api/v1/public-domains/d-1/dns-records", async route => {
    if (!fail || route.request().method() !== "POST") return route.fallback();
    state.dnsRecords.set("example.com", [record("example.com", "A", "8.8.8.8")]);
    return route.fulfill({ json: { hosts: [
      { hostname: "example.com", status: "written", error: null },
      { hostname: "*.example.com", status: "failed", error: "写入失败，原记录已恢复，请重新预览后重试" },
    ] } });
  });
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "配置 example.com", exact: true }).click();
  const config = page.getByRole("dialog", { name: "配置 example.com" });
  await config.getByRole("button", { name: "配置解析" }).click();
  await config.getByRole("button", { name: "确认写入" }).click();
  const result = config.getByLabel("解析结果", { exact: true });
  await expect(result.getByRole("status")).toHaveText(["已写入", "写入失败"]);
  await expect(result.getByRole("alert")).toContainText("原记录已恢复");
  await result.scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath("dns-partial-failure.png") });
  fail = false;
  await config.getByRole("button", { name: "配置解析" }).click();
  await expect(config.getByLabel("解析预览")).toContainText("保持不变");
  await config.getByRole("button", { name: "确认写入" }).click();
  await expect(result.getByRole("status")).toHaveText(["记录一致", "已写入"]);
});

test("缺少公网 IPv4 只显示错误，不发送写入请求", async ({ page }) => {
  const state = await installApiMocks(page);
  state.failures.set("GET /api/v1/public-domains/d-1/dns-records", "请管理员在「服务器设置」中填写有效的公网 IPv4");
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "配置 example.com", exact: true }).click();
  const config = page.getByRole("dialog", { name: "配置 example.com" });
  await config.getByRole("button", { name: "配置解析" }).click();
  await expect(config.getByRole("alert")).toContainText("服务器设置");
  expect(state.calls.filter(call => call.path.endsWith("/dns-records") && call.method === "POST")).toHaveLength(0);
});

test("更新凭据会取消旧解析预览，取消更新后仍需手动重新预览", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "配置 example.com", exact: true }).click();
  const config = page.getByRole("dialog", { name: "配置 example.com" });
  const dnsCalls = () => state.calls.filter(call => call.path.endsWith("/dns-records"));
  await config.getByRole("button", { name: "配置解析" }).click();
  await expect(config.getByLabel("解析预览", { exact: true })).toBeVisible();
  await config.getByRole("button", { name: "更新", exact: true }).click();
  await expect(config.getByLabel("解析预览", { exact: true })).toHaveCount(0);
  await expect(config.getByRole("button", { name: "配置解析" })).toBeDisabled();
  await expect(config).toContainText("请先保存或取消凭据更新");
  await config.getByRole("button", { name: "取消更新", exact: true }).click();
  await expect(config.getByRole("button", { name: "配置解析" })).toBeEnabled();
  await expect(config.getByLabel("解析预览", { exact: true })).toHaveCount(0);
  expect(dnsCalls()).toHaveLength(1);
  await config.getByRole("button", { name: "配置解析" }).click();
  await expect(config.getByLabel("解析预览", { exact: true })).toBeVisible();
  expect(dnsCalls()).toHaveLength(2);
  expect(dnsCalls().every(call => call.method === "GET")).toBeTruthy();
});

test("添加域名立即显示处理中，重复提交只发一次，超时保留输入并可重试", async ({ page }, info) => {
  await page.clock.install();
  await installApiMocks(page);
  let release!: () => void; let stalled = true; let posts = 0;
  const pending = new Promise<void>(resolve => { release = resolve; });
  await page.route("**/api/v1/public-domains", async route => {
    if (route.request().method() !== "POST") return route.fallback();
    posts++;
    if (!stalled) return route.fallback();
    await pending;
    return route.fulfill({ status: 503, json: { error: "测试请求已结束" } });
  });
  await page.goto("/#/domains");
  await page.getByRole("button", { name: "添加 域名", exact: true }).click();
  const add = page.getByRole("dialog", { name: "添加域名" });
  await add.getByLabel("域名", { exact: true }).fill("new.example.com");
  await add.getByRole("button", { name: "添加域名", exact: true }).click();
  try {
    await expect(add.getByRole("button", { name: "添加中…" })).toBeDisabled();
    await add.locator("form").evaluate(form => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
    await expect.poll(() => posts).toBe(1);
    await page.screenshot({ path: info.outputPath("domain-save-pending.png") });
    await page.clock.fastForward(15001);
    await expect(add.getByRole("alert")).toContainText("请求超时");
    await expect(add.getByLabel("域名", { exact: true })).toHaveValue("new.example.com");
    await expect(add.getByRole("button", { name: "添加域名", exact: true })).toBeEnabled();
  } finally { release(); }
  stalled = false;
  await add.getByRole("button", { name: "添加域名", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "配置 new.example.com" })).toBeVisible();
  expect(posts).toBe(2);
});
