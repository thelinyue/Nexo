import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const initial = () => ({ management_entry: null as { domain_id: string; hostname: string } | null, public_url: "", public_ips: [] as string[], domains: [{ id: "domain", domain: "example.test" }], caddy_enabled: true, status: "disabled", error: null as string | null });

test("单域名自动选用，多域名显示选择且保存所选域名", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/settings/server");
  await expect(page.getByLabel("公网 IPv4", { exact: true })).toHaveValue("203.0.113.7");
  await page.getByRole("switch", { name: "HTTPS 管理入口" }).check();
  await expect(page.getByRole("combobox", { name: "域名", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "保存设置", exact: true }).click();
  await expect(page.getByText("设置已保存。", { exact: true })).toBeVisible();
  expect(state.serverSettings.management_entry?.domain_id).toBe("d-1");
  state.serverSettings.domains.push({ id: "d-2", domain: "another.test" });
  await page.reload();
  await page.getByRole("combobox", { name: "域名", exact: true }).selectOption("d-2");
  await page.getByRole("button", { name: "保存设置", exact: true }).click();
  await expect(page.getByText("设置已保存。", { exact: true })).toBeVisible();
  expect(state.serverSettings.management_entry?.domain_id).toBe("d-2");
  await expect(page.getByRole("link", { name: "打开管理入口", exact: true })).toHaveCount(0);
  await expect(page.locator(".service-detail-address code")).toHaveText("https://nexo.another.test");
});

test("从 HTTP 保存管理域名，失败保留草稿，状态更新不覆盖输入", async ({ page }, info) => {
  await installApiMocks(page);
  let saved = { ...initial(), public_ips: ["203.0.113.7"] }; let fail = true;
  await page.route("**/api/v1/admin/server-settings", route => {
    if (route.request().method() === "PUT") {
      expect(route.request().headers()["x-nexo-csrf"]).toBe("test-csrf");
      const input = route.request().postDataJSON();
      expect(input).not.toHaveProperty("trusted_proxies");
      expect(input).not.toHaveProperty("public_url");
      if (fail) return route.fulfill({ status: 500, json: { error: "保存失败，请重试" } });
      saved = { ...saved, ...input, public_url: input.management_entry ? `https://${input.management_entry.hostname}.example.test` : "", status: input.management_entry ? "certificate_pending" : "disabled" };
    }
    return route.fulfill({ json: saved });
  });
  await page.goto("/#/settings/server");
  const settingsPage = page.locator(".server-settings-page");
  await expect(settingsPage.getByLabel("可信代理 IP", { exact: true })).toHaveCount(0);
  await settingsPage.getByRole("switch", { name: "HTTPS 管理入口" }).check();
  await expect(settingsPage.getByRole("combobox", { name: "域名", exact: true })).toHaveCount(0);
  await settingsPage.getByLabel("子域名", { exact: true }).fill("manage");
  await expect(settingsPage.getByLabel("公网 IP", { exact: true })).toHaveCount(0);
  await settingsPage.getByRole("button", { name: "保存设置" }).click();
  await expect(settingsPage.getByRole("alert")).toContainText("保存失败");
  await expect(settingsPage.getByLabel("子域名", { exact: true })).toHaveValue("manage");
  expect(saved.management_entry).toBeNull();
  fail = false;
  await settingsPage.getByRole("button", { name: "保存设置" }).click();
  await expect(settingsPage.getByText("设置已保存。", { exact: true })).toBeVisible();
  await expect(settingsPage.getByText("等待证书", { exact: true })).toBeVisible();
  expect(saved.management_entry).toEqual({ domain_id: "domain", hostname: "manage" });
  expect(saved.public_ips).toEqual(["203.0.113.7"]);
  await settingsPage.getByLabel("子域名", { exact: true }).fill("draft");
  saved.status = "ready";
  await expect(settingsPage.getByRole("link", { name: "打开管理入口" })).toHaveAttribute("href", "https://manage.example.test", { timeout: 10000 });
  await expect(settingsPage.getByLabel("子域名", { exact: true })).toHaveValue("draft");
  await settingsPage.getByLabel("子域名", { exact: true }).fill("manage");
  await expect(settingsPage.getByText("原 IP 入口保留", { exact: false })).toBeVisible();
  await page.screenshot({ path: info.outputPath("server-settings-caddy.png"), animations: "disabled" });
  expect(await settingsPage.evaluate(el => el.scrollWidth <= el.clientWidth)).toBeTruthy();
  await page.evaluate(() => { location.hash = "#/manage"; });
  await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
  await page.evaluate(() => { location.hash = "#/settings/server"; });
  await expect(settingsPage).toBeVisible();
  await expect(settingsPage.getByLabel("子域名", { exact: true })).toHaveValue("manage");
  await settingsPage.getByRole("switch", { name: "HTTPS 管理入口" }).uncheck();
  await settingsPage.getByRole("button", { name: "保存设置" }).click();
  await expect(settingsPage.getByRole("link", { name: "打开管理入口" })).toHaveCount(0);
  expect(saved.management_entry).toBeNull();
});

test("读取失败可以重试，Caddy 未启用不能配置入口", async ({ page }) => {
  await installApiMocks(page); let fail = true;
  await page.route("**/api/v1/admin/server-settings", route => {
    expect(route.request().method()).toBe("GET");
    return fail ? route.fulfill({ status: 500, json: { error: "读取失败" } }) : route.fulfill({ json: { ...initial(), caddy_enabled: false } });
  });
  await page.goto("/#/settings/server");
  const settingsPage = page.locator(".server-settings-page");
  await expect(settingsPage.getByRole("alert")).toContainText("读取失败");
  await expect(settingsPage.getByRole("button", { name: "保存设置" })).toBeDisabled();
  fail = false; await settingsPage.getByRole("button", { name: "重试", exact: true }).click();
  await expect(settingsPage.getByRole("switch", { name: "HTTPS 管理入口" })).toBeDisabled();
  await expect(settingsPage.getByRole("alert")).toHaveCount(0);
});

test("手动填写公网 IPv4，校验失败保留草稿，保存回显且不依赖 HTTPS 管理入口", async ({ page }, info) => {
  await installApiMocks(page);
  let saved = { ...initial(), relay_ipv4: "8.8.4.4", public_ips: ["2001:4860::1"], caddy_enabled: false };
  await page.route("**/api/v1/admin/server-settings", route => {
    if (route.request().method() === "PUT") {
      const input = route.request().postDataJSON();
      expect(route.request().headers()["x-nexo-csrf"]).toBe("test-csrf");
      if (input.relay_ipv4 === "10.7.107.175") return route.fulfill({ status: 400, json: { error: "请填写有效的公网 IPv4 地址" } });
      saved = { ...saved, ...input, relay_ipv4: input.relay_ipv4 || "8.8.4.4" };
    }
    return route.fulfill({ json: saved });
  });
  await page.goto("/#/settings/server");
  const settingsPage = page.locator(".server-settings-page");
  const ipv4 = settingsPage.getByLabel("公网 IPv4", { exact: true });
  await expect(ipv4).toHaveValue("8.8.4.4");
  await ipv4.fill("10.7.107.175");
  await settingsPage.getByRole("button", { name: "保存设置" }).click();
  await expect(settingsPage.getByRole("alert")).toContainText("有效的公网 IPv4");
  await expect(ipv4).toHaveValue("10.7.107.175");
  await ipv4.fill("101.36.109.178");
  await settingsPage.getByRole("button", { name: "保存设置" }).click();
  await expect(settingsPage.getByText("设置已保存。", { exact: true })).toBeVisible();
  expect(saved.relay_ipv4).toBe("101.36.109.178");
  expect(saved.public_ips).toEqual(["2001:4860::1"]);
  expect(saved.management_entry).toBeNull();
  await page.evaluate(() => { location.hash = "#/manage"; });
  await expect(page.getByRole("menu", { name: "本人账号", exact: true })).toBeVisible();
  await page.evaluate(() => { location.hash = "#/settings/server"; });
  await expect(settingsPage).toBeVisible();
  await expect(ipv4).toHaveValue("101.36.109.178");
  await expect(settingsPage.getByRole("button", { name: "保存设置" })).toBeDisabled();
  expect(await settingsPage.evaluate(el => el.scrollWidth <= el.clientWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("server-public-ipv4.png"), animations: "disabled" });
  await ipv4.fill("");
  await settingsPage.getByRole("button", { name: "保存设置" }).click();
  await expect(ipv4).toHaveValue("8.8.4.4");
});
