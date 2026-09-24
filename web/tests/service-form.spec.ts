import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("协议直接点选且单域名自动填入，打开表单不抢占输入焦点", async ({ page }, testInfo) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  await page.getByRole("button", { name: "创建服务", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await expect(dialog).toBeVisible();
  expect(await page.evaluate(() => document.activeElement instanceof HTMLInputElement)).toBeFalsy();
  await expect(dialog.getByRole("radio", { name: "TCP", exact: true })).toBeChecked();
  await expect(dialog.getByLabel("公网端口", { exact: true })).toBeHidden();
  await dialog.getByRole("radio", { name: "HTTPS", exact: true }).check();
  await expect(dialog.getByLabel("根域名", { exact: true })).toHaveValue("d-1");
  await dialog.getByLabel("主机名").fill("nas");
  await expect(dialog.locator(".service-submit-preview code")).toHaveText("https://nas.example.com");
  await page.screenshot({ path: testInfo.outputPath("https-service-form.png") });
});

test("错误定位到具体字段，折叠的无效端口自动展开，未通过校验不请求接口", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services");
  await page.getByRole("button", { name: "创建服务", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  const save = dialog.getByRole("button", { name: "保存服务" });
  await save.click();
  await expect(dialog.getByLabel("服务名称")).toBeFocused();
  await expect(dialog.getByLabel("服务名称")).toHaveAttribute("aria-invalid", "true");
  await dialog.getByLabel("服务名称").fill("手机创建");
  await dialog.getByLabel("本地端口").fill("65536");
  await save.click();
  await expect(dialog.getByLabel("本地端口")).toBeFocused();
  await expect(dialog.getByRole("alert")).toContainText("1–65535");
  await dialog.getByLabel("本地端口").fill("8080");
  await dialog.locator("summary").click();
  await dialog.getByLabel("公网端口", { exact: true }).fill("19999");
  await dialog.locator("summary").click();
  await save.click();
  await expect(dialog.getByLabel("公网端口", { exact: true })).toBeFocused();
  await expect(dialog.getByRole("alert")).toContainText("20000–29999");
  expect(state.calls.filter(item => item.method === "POST")).toHaveLength(0);
  await dialog.getByLabel("公网端口", { exact: true }).fill("21000");
  await save.click();
  await expect(dialog).not.toBeVisible();
  expect(state.calls.find(item => item.method === "POST")?.body.public_port).toBe(21000);
});

test("键盘下一项不误提交，可视区域缩小后字段和保存按钮仍可见", async ({ page }, testInfo) => {
  const state = await installApiMocks(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/#/services");
  await page.getByRole("button", { name: "创建服务", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await dialog.getByLabel("服务名称").fill("键盘测试");
  await dialog.getByLabel("服务名称").press("Enter");
  await expect(dialog.getByLabel("本地地址")).toBeFocused();
  await dialog.getByLabel("本地地址").press("Enter");
  const port = dialog.getByLabel("本地端口");
  await expect(port).toBeFocused();
  await port.fill("8080");
  await page.setViewportSize({ width: 390, height: 420 });
  await expect.poll(async () => {
    const input = await port.boundingBox();
    const header = await dialog.locator(".modal-heading").boundingBox();
    const footer = await dialog.locator(".modal-actions").boundingBox();
    return Boolean(input && header && footer && input.y >= header.y + header.height && input.y + input.height <= footer.y);
  }).toBeTruthy();
  await expect(dialog.getByRole("button", { name: "保存服务" })).toBeInViewport();
  await page.screenshot({ path: testInfo.outputPath("compact-viewport-service-form.png") });
  await port.press("Enter");
  await expect(port).not.toBeFocused();
  expect(state.calls.filter(item => item.method === "POST")).toHaveLength(0);
});

test("协议切换保留输入，但不提交其他协议的端口；多域名不自动选择", async ({ page }) => {
  const state = await installApiMocks(page);
  state.domains.push({ ...state.domains[0], id: "d-2", domain: "second.example.com", is_primary: false });
  await page.goto("/#/services");
  await page.getByRole("button", { name: "创建服务", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "创建服务" });
  await dialog.getByLabel("服务名称").fill("Web 服务");
  await dialog.getByLabel("本地端口").fill("8080");
  await dialog.locator("summary").click();
  await dialog.getByLabel("公网端口", { exact: true }).fill("21000");
  await dialog.getByRole("radio", { name: "HTTPS", exact: true }).check();
  await expect(dialog.getByLabel("根域名", { exact: true })).toHaveValue("");
  await dialog.getByLabel("主机名").fill("nas");
  await dialog.getByLabel("根域名", { exact: true }).selectOption("d-2");
  await dialog.getByRole("radio", { name: "TCP", exact: true }).check();
  await expect(dialog.getByLabel("公网端口", { exact: true })).toHaveValue("21000");
  await dialog.getByRole("radio", { name: "HTTPS", exact: true }).check();
  await expect(dialog.getByLabel("主机名")).toHaveValue("nas");
  await dialog.getByRole("button", { name: "保存服务" }).click();
  await expect(dialog).not.toBeVisible();
  const body = state.calls.find(item => item.method === "POST")!.body;
  expect(body.public_port).toBeNull();
  expect(body.public_domain_id).toBe("d-2");
});
