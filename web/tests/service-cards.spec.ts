import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";
import { openServiceEditor } from "./service-actions";

test.beforeEach(async ({ page }) => { await page.addInitScript(() => localStorage.setItem("nexo.services.view", "icons")); });

test("卡片空白打开网页一次，详情与不可访问服务不触发新窗口", async ({ page, context }) => {
  const state = await installApiMocks(page);
  state.tunnels.push(
    { ...state.tunnels[0], id: "closed", name: "已关闭应用", enabled: false },
    { ...state.tunnels[0], id: "pending", name: "等待配置", public_address: null },
    { ...state.tunnels[0], id: "tcp", name: "SSH", protocol: "tcp", public_address: "example.com:22000" },
  );
  await context.route("https://media.example.com/**", route => route.fulfill({ contentType: "text/html", body: "<title>媒体应用</title>" }));
  await page.goto("/#/services");
  const card = page.locator(".service-row").first();
  await expect(card).toBeVisible();
  const popupPromise = context.waitForEvent("page");
  await card.click({ position: { x: 2, y: 2 } });
  const popup = await popupPromise;
  await expect(popup).toHaveURL(state.tunnels[0].public_address!);
  expect(context.pages()).toHaveLength(2);
  await expect(page).toHaveURL(/#\/services$/);
  await popup.close();
  for (const name of ["已关闭应用", "等待配置", "SSH"]) {
    await page.locator(".service-row").filter({ has: page.getByRole("link", { name, exact: true }) }).click({ position: { x: 2, y: 2 } });
    await expect(page).toHaveURL(/#\/services$/);
    expect(context.pages()).toHaveLength(1);
  }
  await card.getByRole("link", { name: "打开媒体中心" }).focus();
  const keyboardPopup = context.waitForEvent("page");
  await page.keyboard.press("Enter");
  await (await keyboardPopup).close();
  await card.getByRole("link", { name: "媒体中心", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: "媒体中心", exact: true })).toBeVisible();
  await expect(page).toHaveURL(/#\/services$/);
  expect(context.pages()).toHaveLength(1);
});

test("长按卡片空白只进入多选，抬手及再次点击不打开网页", async ({ page, context }, info) => {
  test.skip(info.project.name === "desktop-dark", "手机长按交互");
  await installApiMocks(page);
  await page.goto("/#/services");
  const card = page.locator(".service-row").first();
  const box = (await card.boundingBox())!;
  await page.mouse.move(box.x + 2, box.y + 2);
  await page.mouse.down();
  await expect(card.getByRole("checkbox")).toBeChecked();
  await page.mouse.up();
  await expect(page).toHaveURL(/#\/services$/);
  expect(context.pages()).toHaveLength(1);
  await card.click({ position: { x: 2, y: 2 } });
  await expect(card.getByRole("checkbox")).not.toBeChecked();
  expect(context.pages()).toHaveLength(1);
});

test("选图推荐只改变草稿，保存持久化，恢复默认提交 null", async ({ page }, info) => {
  const state = await installApiMocks(page);
  await page.route("https://cdn.jsdelivr.net/**", route => route.abort());
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await editor.getByLabel("服务名称", { exact: true }).fill("Emby");
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  const picker = editor.getByRole("region", { name: "应用图标", exact: true });
  await expect(picker.locator(".icon-picker-option").first()).toHaveAccessibleName(/使用 emby/);
  await expect(picker.locator(".icon-picker-option")).toHaveCount(24);
  await picker.getByRole("button", { name: "下一页" }).click();
  await expect(picker.locator(".icon-picker-pages")).toContainText("2 /");
  await picker.getByRole("button", { name: "圆形", exact: true }).click();
  await expect(picker.getByRole("button", { name: "圆形", exact: true })).toHaveAttribute("aria-pressed", "true");
  await picker.getByRole("button", { name: "SVG", exact: true }).click();
  await expect(picker.getByRole("status")).toContainText("604 个图标");
  await picker.getByRole("button", { name: "圆角", exact: true }).click();
  await picker.getByLabel("搜索应用图标").fill("not-an-existing-app");
  await expect(picker.getByRole("status")).toContainText("没有匹配");
  await picker.getByLabel("搜索应用图标").fill("emby");
  await page.screenshot({ path: info.outputPath("application-icon-picker.png"), animations: "disabled" });
  await picker.getByRole("button", { name: "使用 emby-1", exact: true }).click();
  await expect(picker).toBeHidden();
  expect(state.calls.filter(call => call.method === "PUT")).toHaveLength(0);
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.tunnels[0].icon_id).toBe("border-radius/emby-1.png");
  await page.reload();
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await picker.getByRole("button", { name: "默认图标", exact: true }).click();
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.tunnels[0].icon_id).toBeNull();
});

test("选择图标后取消需要放弃草稿，创建可选择图标", async ({ page }) => {
  const state = await installApiMocks(page);
  await page.route("https://cdn.jsdelivr.net/**", route => route.abort());
  await page.goto("/#/services");
  await openServiceEditor(page);
  const editor = page.getByRole("dialog", { name: "创建服务", exact: true });
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await editor.getByLabel("搜索应用图标").fill("emby");
  await editor.getByRole("button", { name: "使用 emby-1", exact: true }).click();
  await editor.getByRole("button", { name: "取消", exact: true }).click();
  await page.getByRole("button", { name: "放弃修改", exact: true }).click();
  expect(state.calls.some(call => call.method === "POST" && call.path === "/api/v1/tunnels")).toBe(false);
  await openServiceEditor(page);
  await editor.getByLabel("服务名称", { exact: true }).fill("Emby");
  await editor.getByLabel("内网端口", { exact: true }).fill("8096");
  await editor.getByLabel("主机名", { exact: true }).fill("emby");
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await editor.getByRole("button", { name: "使用 emby-1", exact: true }).click();
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.calls.find(call => call.method === "POST" && call.path === "/api/v1/tunnels")?.body.icon_id).toBe("border-radius/emby-1.png");
});

test("IPv6 直连设备离线时仍能只更换图标", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels[0].ipv6_direct_enabled = true;
  await page.route("https://cdn.jsdelivr.net/**", route => route.abort());
  await page.goto("/#/services/t-1");
  await page.getByRole("button", { name: "编辑服务", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await editor.getByRole("button", { name: "选择应用图标" }).click();
  await editor.getByLabel("搜索应用图标").fill("emby");
  await editor.getByRole("button", { name: "使用 emby-1", exact: true }).click();
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.tunnels[0].icon_id).toBe("border-radius/emby-1.png");
});

test("图标失败、服务关闭与端口服务仍有明确入口，选择模式不跳转", async ({ page }, info) => {
  const state = await installApiMocks(page);
  Object.assign(state.tunnels[0], { name: "Emby", icon_id: "border-radius/emby-1.png" });
  state.tunnels.push(
    { ...state.tunnels[0], id: "closed", name: "已关闭应用", enabled: false },
    { ...state.tunnels[0], id: "pending", name: "等待配置", public_address: null },
    { ...state.tunnels[0], id: "tcp", name: "SSH", protocol: "tcp", icon_id: null, public_address: "example.com:22000" },
    { ...state.tunnels[0], id: "error", name: "很长很长的应用名称用来检查省略效果", apply_status: "failed", apply_error: "无法连接目标，请检查设备和服务端口是否正确。" },
  );
  await page.route("https://cdn.jsdelivr.net/**", route => route.abort());
  await page.goto("/#/services");
  const emby = page.locator(".service-row").filter({ has: page.getByRole("link", { name: "Emby", exact: true }) });
  await expect(emby.locator(".application-icon img")).toHaveCount(0);
  await expect(emby.locator(".application-icon svg")).toBeVisible();
  await expect(emby.getByRole("link", { name: "打开Emby" })).toHaveAttribute("target", "_blank");
  for (const name of ["已关闭应用", "等待配置"]) await expect(page.locator(".service-row").filter({ has: page.getByRole("link", { name, exact: true }) }).getByRole("button", { name: `打开${name}`, exact: true })).toBeDisabled();
  await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async (value: string) => { document.body.dataset.copied = value; } } }));
  await page.getByRole("button", { name: "复制SSH地址", exact: true }).click();
  await expect(page.locator("body")).toHaveAttribute("data-copied", "example.com:22000");
  await page.screenshot({ path: info.outputPath("application-cards.png"), animations: "disabled" });
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.getByRole("button", { name: "选择", exact: true }).press("Space");
  await emby.getByRole("link", { name: "Emby", exact: true }).click();
  await expect(emby.getByRole("checkbox")).toBeChecked();
  await expect(page).toHaveURL(/#\/services$/);
});

test("图标长按只多选，网页、端口和关闭服务均不执行主操作", async ({ page, context }, info) => {
  test.skip(info.project.name === "desktop-dark", "手机长按交互");
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "tcp", name: "SSH", protocol: "tcp" }, { ...state.tunnels[0], id: "closed", name: "已关闭", enabled: false });
  await page.goto("/#/services");
  await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async () => { document.body.dataset.copied = "yes"; } } }));
  for (const name of ["媒体中心", "SSH", "已关闭"]) {
    const row = page.locator(".service-row").filter({ has: page.getByRole("link", { name, exact: true }) });
    const box = (await row.locator(".application-icon").boundingBox())!;
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await expect(row.getByRole("checkbox")).toBeChecked();
    await page.mouse.up();
    await expect(row.getByRole("checkbox")).toBeChecked();
    // 选择模式下的按钮和链接仍由捕获阶段接管，图标中心不会误触角上的复选框。
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect(row.getByRole("checkbox")).not.toBeChecked();
    await row.getByRole("checkbox").focus();
    await page.keyboard.press("Space");
    await expect(row.getByRole("checkbox")).toBeChecked();
    expect(context.pages()).toHaveLength(1);
    await expect(page.locator("body")).not.toHaveAttribute("data-copied", "yes");
    await expect(page).toHaveURL(/#\/services$/);
    await page.getByRole("button", { name: "完成", exact: true }).click();
  }
});

test("端口图标复制失败展开整行，支持手动复制和重试反馈", async ({ page }) => {
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "tcp", name: "SSH", protocol: "tcp", public_address: "example.com:22000" });
  await page.goto("/#/services");
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: async () => { throw new Error("权限拒绝"); } } });
    document.execCommand = () => false;
  });
  await page.getByRole("button", { name: "复制SSH地址" }).click();
  const manual = page.getByRole("textbox", { name: "手动复制内容" });
  await expect(manual).toHaveValue("example.com:22000");
  const grid = (await page.locator(".service-list").boundingBox())!;
  expect((await manual.boundingBox())!.width).toBeGreaterThanOrEqual(grid.width - 2);
  await page.getByRole("button", { name: "选择全部", exact: true }).click();
  expect(await manual.evaluate(el => (el as HTMLTextAreaElement).selectionEnd - (el as HTMLTextAreaElement).selectionStart)).toBe("example.com:22000".length);
  await page.evaluate(() => { document.execCommand = () => true; });
  await page.getByRole("button", { name: "再次复制" }).click();
  await expect(page.getByRole("status")).toHaveText("已复制");
  await expect(manual).toHaveCount(0);
});

test("正常服务无角标，异常和未知状态保留完整可访问文案", async ({ page }) => {
  const state = await installApiMocks(page);
  for (const [value, label] of [["failed", "需处理"], ["partial", "部分可用"], ["checking", "检查中"], ["unexpected", "未知状态：unexpected"]]) {
    state.tunnels.push({ ...state.tunnels[0], id: value, name: label, apply_status: value });
  }
  state.tunnels.push({ ...state.tunnels[0], id: "proxy", name: "反代", service_mode: "reverse_proxy", apply_status: "failed" });
  await page.goto("/#/services");
  await expect(page.locator(".service-row").first().locator(".status")).toHaveCount(0);
  for (const label of ["需处理", "部分可用", "检查中", "未知状态：unexpected", "配置失败"]) {
    const badge = page.locator(".application-status").filter({ hasText: label });
    await expect(badge).toHaveAttribute("title", label);
    await expect(badge.locator("svg")).toBeVisible();
  }
});
