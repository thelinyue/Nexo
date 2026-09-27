import { expect, type Page } from "@playwright/test";

/** 跟随页面的真实入口：手机管理员先选择类型，桌面和普通用户直接创建。 */
export async function openServiceEditor(page: Page, mode: "tunnel" | "reverse_proxy" = "tunnel") {
  const action = mode === "tunnel" ? "创建服务" : "添加反向代理";
  const trigger = page.getByRole("button", { name: /^(添加|创建服务)$/ });
  if (mode === "tunnel") {
    const chooser = await trigger.getAttribute("aria-haspopup") === "dialog";
    await trigger.click();
    if (chooser) {
      await page.getByRole("dialog", { name: "添加", exact: true }).getByRole("button", { name: action, exact: true }).click();
    }
  } else {
    const add = page.getByRole("button", { name: "添加", exact: true });
    if (await add.isVisible()) await add.click();
    await page.getByRole("button", { name: action, exact: true }).click();
  }
  await expect(page.getByRole("dialog", { name: action, exact: true })).toBeVisible();
}
