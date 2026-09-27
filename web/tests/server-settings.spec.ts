import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("服务器设置保存失败保留输入，重试成功后重新打开读取已保存值", async ({ page }) => {
  await installApiMocks(page);
  let saved = { public_url: "", trusted_proxies: [] as string[], public_ips: [] as string[] };
  let fail = true;
  await page.route("**/api/v1/admin/server-settings", route => {
    if (route.request().method() === "PUT") {
      expect(route.request().headers()["x-nexo-csrf"]).toBe("test-csrf");
      if (fail) return route.fulfill({ status: 500, json: { error: "保存失败，请重试" } });
      saved = route.request().postDataJSON();
    }
    return route.fulfill({ json: saved });
  });
  await page.goto("/#/settings");
  await page.getByRole("button", { name: "服务器设置", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "服务器设置", exact: true });
  await dialog.getByLabel("管理地址", { exact: true }).fill("https://nexo.example.test");
  await dialog.getByLabel("可信代理 IP", { exact: true }).fill("127.0.0.1，::1");
  await dialog.getByLabel("公网 IP", { exact: true }).fill("203.0.113.7");
  await dialog.getByRole("button", { name: "保存设置" }).click();
  await expect(dialog.getByRole("alert")).toContainText("保存失败");
  await expect(dialog.getByLabel("管理地址", { exact: true })).toHaveValue("https://nexo.example.test");
  expect(saved.public_url).toBe("");
  await expect(dialog.getByRole("status")).toHaveCount(0);
  fail = false;
  await dialog.getByRole("button", { name: "保存设置" }).click();
  await expect(dialog.getByRole("status")).toContainText("已保存并生效");
  expect(saved.trusted_proxies).toEqual(["127.0.0.1", "::1"]);
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "服务器设置", exact: true }).click();
  await expect(dialog.getByLabel("公网 IP", { exact: true })).toHaveValue("203.0.113.7");
});

test("服务器设置读取失败可以重试且不会提交空配置", async ({ page }) => {
  await installApiMocks(page);
  let fail = true;
  await page.route("**/api/v1/admin/server-settings", route => {
    expect(route.request().method()).toBe("GET");
    return fail ? route.fulfill({ status: 500, json: { error: "读取失败" } })
      : route.fulfill({ json: { public_url: "", trusted_proxies: [], public_ips: [] } });
  });
  await page.goto("/#/settings");
  await page.getByRole("button", { name: "服务器设置", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "服务器设置", exact: true });
  await expect(dialog.getByRole("alert")).toContainText("读取失败");
  await expect(dialog.getByRole("button", { name: "保存设置" })).toBeDisabled();
  fail = false;
  await dialog.getByRole("button", { name: "重试", exact: true }).click();
  await expect(dialog.getByLabel("管理地址", { exact: true })).toHaveValue("");
  await expect(dialog.getByRole("alert")).toHaveCount(0);
});
