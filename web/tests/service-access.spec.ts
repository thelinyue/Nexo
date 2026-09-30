import { openServiceEditor, selectServiceOption } from "./service-actions";
import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import { readFileSync } from "node:fs";

test("访问规则默认公开，校验密码并保留内网重定向", async ({ page }, info) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const form = page.getByRole("dialog", { name: "创建服务" });
  await expect(form.getByRole("switch", { name: "内网重定向", includeHidden: true })).toBeHidden();
  await expect(form.getByRole("radio", { name: "认证访问", exact: true, includeHidden: true })).toBeHidden();
  await form.locator("summary", { hasText: "高级设置" }).click();
  await expect(form.getByRole("radio", { name: "公开访问", exact: true })).toBeChecked();
  await expect(form.getByLabel("访问密码", { exact: true })).toHaveCount(0);
  await form.getByLabel("服务名称").fill("认证应用");
  await form.getByLabel("内网地址", { exact: true }).fill("192.168.1.10");
  await form.getByLabel("内网端口").fill("8080");
  await form.getByLabel("主机名").fill("private");
  await form.getByRole("radio", { name: "认证访问", exact: true }).check();
  await form.getByRole("switch", { name: "内网重定向" }).check();
  await expect(form.getByText("内网直达免认证，公网访问需密码", { exact: true })).toBeVisible();
  await selectServiceOption(form.getByRole("combobox", { name: "公网协议", exact: true }), "HTTP");
  await expect(form.getByText("HTTP 不加密，建议使用 HTTPS", { exact: true })).toBeVisible();
  for (const invalid of ["abc", "12345678901234567", "ab c", "中文密码"]) {
    await form.getByLabel("访问密码", { exact: true }).fill(invalid);
    await form.locator("summary", { hasText: "高级设置" }).click();
    await form.getByRole("button", { name: "保存服务" }).click();
    await expect(form.getByLabel("访问密码", { exact: true })).toBeFocused();
    await expect(form.getByRole("alert")).toHaveText("请输入 4–16 位字母、数字或符号，不含空格");
  }
  await form.getByRole("radio", { name: "公开访问", exact: true }).check();
  await expect(form.getByRole("alert")).toHaveCount(0);
  await form.getByRole("radio", { name: "认证访问", exact: true }).check();
  await form.getByLabel("访问密码", { exact: true }).fill("Ab1!");
  await page.screenshot({ path: info.outputPath("access-rule-form.png"), animations: "disabled" });
  await form.getByRole("button", { name: "保存服务" }).click();
  await expect(form).toBeHidden();
  expect(state.calls.find(call => call.method === "POST")?.body).toMatchObject({ access_mode: "password", access_password: "Ab1!", lan_redirect_enabled: true });
  await page.getByRole("link", { name: "认证应用", exact: true }).click();
  await expect(page.locator(".detail-field", { has: page.getByText("访问规则", { exact: true }) })).toContainText("认证访问");
  await page.getByRole("button", { name: "编辑服务" }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await expect(editor.getByLabel("访问密码", { exact: true })).toBeHidden();
  await editor.locator("summary", { hasText: "高级设置" }).focus();
  await editor.locator("summary", { hasText: "高级设置" }).press("Enter");
  await expect(editor.getByLabel("访问密码", { exact: true })).toHaveValue("");
  await expect(editor.getByLabel("访问密码", { exact: true })).toHaveAttribute("placeholder", "留空保留原密码");
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.calls.find(call => call.method === "PUT")?.body).not.toHaveProperty("access_password");
});

test("切换 TCP 清除认证草稿，反向代理支持认证", async ({ page }) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  const form = page.getByRole("dialog");
  await form.locator("summary", { hasText: "高级设置" }).click();
  await form.getByRole("radio", { name: "认证访问", exact: true }).check();
  await form.getByLabel("访问密码", { exact: true }).fill("1234");
  await selectServiceOption(form.getByRole("combobox", { name: "内网协议", exact: true }), "TCP");
  await expect(form.getByRole("radio", { name: "认证访问", exact: true })).toHaveCount(0);
  await selectServiceOption(form.getByRole("combobox", { name: "内网协议", exact: true }), "HTTP");
  await form.locator("summary", { hasText: "高级设置" }).click();
  await expect(form.getByRole("radio", { name: "公开访问", exact: true })).toBeChecked();
  await form.getByRole("button", { name: "取消", exact: true }).click();
  await openServiceEditor(page, "reverse_proxy");
  await expect(form).toHaveAccessibleName("添加反向代理");
  await form.locator("summary", { hasText: "高级设置" }).click();
  await form.getByRole("radio", { name: "认证访问", exact: true }).check();
  await expect(form.getByLabel("访问密码", { exact: true })).toHaveValue("");
  await expect(form.getByRole("switch", { name: "内网重定向" })).toHaveCount(0);
});

test("访客密码页支持错误反馈、键盘提交和原地址回跳", async ({ page }, info) => {
  const html = readFileSync(new URL("../../crates/nexo-server/src/service_access.html", import.meta.url), "utf8").replaceAll("{{SERVICE_NAME}}", "家庭 NAS");
  let attempts = 0;
  await page.route("**/.nexo-access/**", async route => {
    if (route.request().method() === "POST") {
      attempts++;
      expect(route.request().postDataJSON().return_to).toBe("/photos?q=1");
      await route.fulfill({ status: attempts === 1 ? 401 : 200, json: attempts === 1 ? { error: "密码错误，请重试" } : { return_to: "/photos?q=1" } });
    } else await route.fulfill({ contentType: "text/html", body: html });
  });
  await page.route("**/photos?q=1", route => route.fulfill({ body: "已进入应用" }));
  await page.goto("/.nexo-access/?return=%2Fphotos%3Fq%3D1");
  await expect(page.getByRole("heading", { name: "家庭 NAS" })).toBeVisible();
  await page.getByLabel("访问密码").fill("wrong");
  await page.getByLabel("访问密码").press("Enter");
  await expect(page.getByRole("alert")).toHaveText("密码错误，请重试");
  await expect(page.getByLabel("访问密码")).toBeFocused();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("visitor-password-page.png"), animations: "disabled" });
  await page.getByLabel("访问密码").fill("pass!");
  await page.getByRole("button", { name: "访问", exact: true }).click();
  await expect(page).toHaveURL(/\/photos\?q=1$/);
});
