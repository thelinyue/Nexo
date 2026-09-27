import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

const initial = () => ({ management_entry: null as { domain_id: string; hostname: string } | null, public_url: "", public_ips: [] as string[], domains: [{ id: "domain", domain: "example.test" }], caddy_enabled: true, status: "disabled", error: null as string | null });

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
  await page.goto("/#/settings");
  await page.getByRole("button", { name: "服务器设置", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "服务器设置", exact: true });
  await expect(dialog.getByLabel("可信代理 IP", { exact: true })).toHaveCount(0);
  await dialog.getByRole("switch", { name: "HTTPS 管理入口" }).check();
  await expect(dialog.getByRole("combobox", { name: "域名", exact: true })).toHaveValue("domain");
  await dialog.getByLabel("子域名", { exact: true }).fill("manage");
  await expect(dialog.getByLabel("公网 IP", { exact: true })).toHaveCount(0);
  await dialog.getByRole("button", { name: "保存设置" }).click();
  await expect(dialog.getByRole("alert")).toContainText("保存失败");
  await expect(dialog.getByLabel("子域名", { exact: true })).toHaveValue("manage");
  expect(saved.management_entry).toBeNull();
  fail = false;
  await dialog.getByRole("button", { name: "保存设置" }).click();
  await expect(dialog.getByText("设置已保存。", { exact: true })).toBeVisible();
  await expect(dialog.getByText("等待证书", { exact: true })).toBeVisible();
  expect(saved.management_entry).toEqual({ domain_id: "domain", hostname: "manage" });
  expect(saved.public_ips).toEqual(["203.0.113.7"]);
  await dialog.getByLabel("子域名", { exact: true }).fill("draft");
  saved.status = "ready";
  await expect(dialog.getByRole("link", { name: "打开管理入口" })).toHaveAttribute("href", "https://manage.example.test", { timeout: 10000 });
  await expect(dialog.getByLabel("子域名", { exact: true })).toHaveValue("draft");
  await dialog.getByLabel("子域名", { exact: true }).fill("manage");
  await expect(dialog.getByText("已启用强制 HTTPS", { exact: false })).toBeVisible();
  await page.screenshot({ path: info.outputPath("server-settings-caddy.png"), animations: "disabled" });
  expect(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth)).toBeTruthy();
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "服务器设置", exact: true }).click();
  await expect(dialog.getByLabel("子域名", { exact: true })).toHaveValue("manage");
  await dialog.getByRole("switch", { name: "HTTPS 管理入口" }).uncheck();
  await dialog.getByRole("button", { name: "保存设置" }).click();
  await expect(dialog.getByRole("link", { name: "打开管理入口" })).toHaveCount(0);
  expect(saved.management_entry).toBeNull();
});

test("读取失败可以重试，Caddy 未启用不能配置入口", async ({ page }) => {
  await installApiMocks(page); let fail = true;
  await page.route("**/api/v1/admin/server-settings", route => {
    expect(route.request().method()).toBe("GET");
    return fail ? route.fulfill({ status: 500, json: { error: "读取失败" } }) : route.fulfill({ json: { ...initial(), caddy_enabled: false } });
  });
  await page.goto("/#/settings");
  await page.getByRole("button", { name: "服务器设置", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "服务器设置", exact: true });
  await expect(dialog.getByRole("alert")).toContainText("读取失败");
  await expect(dialog.getByRole("button", { name: "保存设置" })).toBeDisabled();
  fail = false; await dialog.getByRole("button", { name: "重试", exact: true }).click();
  await expect(dialog.getByRole("switch", { name: "HTTPS 管理入口" })).toBeDisabled();
  await expect(dialog.getByRole("alert")).toHaveCount(0);
});
