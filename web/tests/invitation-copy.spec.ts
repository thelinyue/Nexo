import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

async function invitation(page: import("@playwright/test").Page) {
  await installApiMocks(page);
  let creations = 0;
  const token = "invite-" + "long-token_+/=".repeat(30);
  await page.route("**/api/v1/admin/invitations", route => {
    if (route.request().method() === "POST") {
      creations++;
      return route.fulfill({ json: { token, expires_at: Date.now() / 1000 + 3600 } });
    }
    return route.fulfill({ json: [] });
  });
  await page.goto("/#/users");
  await page.getByRole("button", { name: "邀请用户" }).click();
  return { dialog: page.getByRole("dialog", { name: "邀请链接", exact: true }), token, creations: () => creations };
}

test("邀请复制被拒绝后，新点击同步重试且保留同一链接", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async () => { throw new DOMException("denied", "NotAllowedError"); } } });
    let attempts = 0;
    document.execCommand = () => ++attempts > 1;
  });
  const { dialog, token, creations } = await invitation(page);
  const expected = await dialog.locator("code.token").textContent();
  await dialog.getByRole("button", { name: "复制链接", exact: true }).click();
  await expect(dialog.getByRole("alert")).toBeVisible();
  await expect(dialog.getByRole("button", { name: "再次复制", exact: true })).toBeVisible();
  await dialog.getByRole("button", { name: "再次复制", exact: true }).click();
  await expect(dialog.getByRole("status")).toHaveText("已复制");
  await expect(dialog.locator("code.token")).toHaveText(expected!);
  expect(creations()).toBe(1);
  expect(await page.evaluate(() => JSON.stringify(localStorage) + JSON.stringify(sessionStorage))).not.toContain(token);
});

test("邀请复制均被禁止时可以选择完整内容且临时节点被移除", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
    document.execCommand = () => false;
  });
  const { dialog, creations } = await invitation(page);
  await dialog.getByRole("button", { name: "复制链接", exact: true }).click();
  const manual = dialog.getByLabel("手动复制内容");
  await expect(manual).toHaveValue((await dialog.locator("code.token").textContent())!);
  await dialog.getByRole("button", { name: "选择全部", exact: true }).click();
  expect(await manual.evaluate((element: HTMLTextAreaElement) => element.value.slice(element.selectionStart, element.selectionEnd))).toBe(await manual.inputValue());
  await expect(manual).toBeInViewport();
  await expect(dialog.locator("textarea[aria-hidden=true]")).toHaveCount(0);
  await expect(dialog.getByRole("status")).toHaveCount(0);
  expect(creations()).toBe(1);
});
