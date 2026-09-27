import { expect, test, type Page, type TestInfo } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import { openServiceEditor } from "./service-actions";

/** 验证真实业务弹窗及其嵌套确认框，短桌面视口下也不能贴边或遮住固定操作区。 */
async function centered(page: Page, info: TestInfo, name: string) {
  for (const viewport of [{ width: 901, height: 600 }, { width: 1440, height: 900 }]) {
    await page.setViewportSize(viewport);
    const dialogs = page.locator("dialog[open]");
    expect(await dialogs.count()).toBeGreaterThan(0);
    for (const dialog of await dialogs.all()) {
      await expect.poll(async () => {
        const box = (await dialog.boundingBox())!;
        return Math.max(Math.abs(box.x + box.width / 2 - viewport.width / 2), Math.abs(box.y + box.height / 2 - viewport.height / 2));
      }).toBeLessThan(2);
      await expect.poll(async () => {
        const box = (await dialog.boundingBox())!;
        return box.y >= 20 && box.y + box.height <= viewport.height - 20;
      }).toBeTruthy();
      const box = (await dialog.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(20);
      expect(box.y).toBeGreaterThanOrEqual(20);
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width - 20);
      expect(box.y + box.height).toBeLessThanOrEqual(viewport.height - 20);
      expect(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth)).toBeTruthy();
    }
    const top = dialogs.last();
    await expect(top.locator(":scope > .modal-heading")).toBeInViewport();
    await expect(top.locator(".modal-heading").getByRole("button", { name: "取消", exact: true })).toHaveCount(0);
    if (await top.locator(".desktop-modal-close").count()) await expect(top.getByRole("button", { name: "关闭", exact: true })).toBeInViewport();
    const footer = top.locator(":scope > .modal-actions, :scope > .modal-form > .modal-actions");
    if (await footer.count()) await expect(footer).toBeInViewport();
    const cancel = footer.locator(".desktop-modal-cancel");
    if (await cancel.count()) {
      const secondary = (await cancel.boundingBox())!;
      const primary = (await footer.locator(".primary-button").boundingBox())!;
      expect(Math.abs(secondary.y - primary.y)).toBeLessThan(1);
      expect(secondary.x + secondary.width).toBeLessThan(primary.x);
    }
  }
  await page.screenshot({ path: info.outputPath(`${name}.png`) });
}

test.beforeEach(async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "共享桌面弹窗布局，移动布局由原业务测试覆盖");
  await page.emulateMedia({ reducedMotion: "reduce" });
});

test("账号与服务器设置弹窗居中，长表单内部滚动", async ({ page }, info) => {
  await installApiMocks(page);
  await page.route("**/api/v1/admin/server-settings", route => route.fulfill({ json: { management_entry: null, public_url: "", public_ips: [], domains: [{ id: "d", domain: "example.test" }], caddy_enabled: true, status: "disabled", error: null } }));
  await page.goto("/#/manage");
  await page.getByRole("button", { name: "修改密码", exact: true }).click();
  await centered(page, info, "password");
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "服务器设置", exact: true }).click();
  await expect(page.getByRole("switch", { name: "HTTPS 管理入口" })).toBeVisible();
  await page.getByRole("switch", { name: "HTTPS 管理入口" }).check();
  await page.getByText("公网 IP 校验（可选）", { exact: true }).click();
  await centered(page, info, "server-settings");
  await page.setViewportSize({ width: 901, height: 600 });
  const body = page.getByRole("dialog").locator(".modal-body");
  await expect.poll(() => body.evaluate(element => element.scrollHeight > element.clientHeight)).toBeTruthy();
  await body.evaluate(element => { element.scrollTop = element.scrollHeight; });
  await expect(page.getByRole("button", { name: "保存设置" })).toBeInViewport();
  await page.getByRole("switch", { name: "HTTPS 管理入口" }).uncheck();
  await page.keyboard.press("Escape");
  await page.goto("/#/settings/sessions");
  await page.getByRole("button", { name: "结束会话", exact: true }).first().click();
  await centered(page, info, "session-confirm");
});

test("设备接入、密钥确认与身份恢复居中", async ({ page }, info) => {
  await installApiMocks(page);
  await page.goto("/#/agents");
  await page.getByRole("button", { name: "添加 Agent", exact: true }).click();
  await expect(page.getByRole("button", { name: "完成", exact: true })).toBeVisible();
  await centered(page, info, "agent-enrollment");
  await page.getByText("高级：接入密钥", { exact: true }).click();
  await page.getByRole("button", { name: "重置接入密钥", exact: true }).click();
  await centered(page, info, "agent-key-confirm");
  await page.keyboard.press("Escape");
  await page.keyboard.press("Escape");
  await page.goto("/#/agents/a-1");
  await page.locator(".domain-diagnostics").filter({ hasText: "设备证书" }).locator("summary").click();
  await page.getByRole("button", { name: "恢复设备身份", exact: true }).click();
  await centered(page, info, "device-recovery");
});

test("域名证书、解析与删除确认居中", async ({ page }, info) => {
  await installApiMocks(page);
  await page.goto("/#/domains");
  await page.getByRole("button", { name: /^域名解析 / }).click();
  await centered(page, info, "domain-dns");
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "证书配置", exact: true }).click();
  await centered(page, info, "domain-settings");
  await page.getByRole("button", { name: "删除域名", exact: true }).click();
  await centered(page, info, "domain-delete");
});

test("用户编辑、额度、链接与删除弹窗居中", async ({ page }, info) => {
  await installApiMocks(page);
  await page.route("**/api/v1/admin/users/alice/recovery", route => route.fulfill({ json: { token: "test-token", expires_at: 1990000000 } }));
  await page.goto("/#/users");
  const user = page.locator(".user-card").filter({ has: page.getByRole("heading", { name: "alice", exact: true }) });
  for (const action of ["修改用户名", "流量限制", "重设密码", "停用用户", "删除用户"]) {
    await user.getByRole("button", { name: "更多", exact: true }).click();
    await user.getByRole("button", { name: action, exact: true }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await centered(page, info, `user-${action}`);
    await page.keyboard.press("Escape");
  }
});

test("服务表单及会话过期的嵌套弹窗居中", async ({ page }, info) => {
  const state = await installApiMocks(page);
  await page.goto("/#/services");
  await openServiceEditor(page);
  await centered(page, info, "service-create");
  const editor = page.getByRole("dialog", { name: "创建服务", exact: true });
  await editor.getByLabel("服务名称").fill("待保存服务");
  await editor.getByLabel("内网端口").fill("8080");
  await editor.getByLabel("主机名").fill("test");
  state.failures.set("POST /api/v1/tunnels", "登录已过期");
  state.failureStatuses.set("POST /api/v1/tunnels", 401);
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(page.getByRole("dialog", { name: "登录已过期" })).toBeVisible();
  await centered(page, info, "reauth");
  await page.getByRole("button", { name: "退出并放弃当前草稿" }).click();
  await centered(page, info, "abandon-draft");
});
