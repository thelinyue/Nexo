import { expect, test } from "@playwright/test";
import { installApiMocks } from "./api-mocks";

test("桌面添加服务属于工具栏，设备识别码可完整复制", async ({ page }, info) => {
  test.skip(info.project.name !== "desktop-dark", "桌面断点与主题集中验收");
  await installApiMocks(page);
  for (const colorScheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
    for (const width of [901, 1024, 1440, 1920]) {
      await page.setViewportSize({ width, height: width === 1024 ? 480 : 900 });
      await page.goto("/#/services");
      const button = page.getByRole("button", { name: "创建服务", exact: true });
      await expect(button).toBeInViewport();
      expect(await button.evaluate(e => getComputedStyle(e).position)).toBe("static");
      const toolbar = await page.locator(".page-slot:not([hidden]) .page-toolbar-actions").boundingBox();
      const box = await button.boundingBox();
      expect(box!.height).toBeGreaterThanOrEqual(44);
      expect(box!.y).toBeGreaterThanOrEqual(toolbar!.y);
      expect(box!.y + box!.height).toBeLessThanOrEqual(toolbar!.y + toolbar!.height);
      const workspace = await page.locator(".page-slot:not([hidden])").boundingBox();
      if (page.viewportSize()!.height < 600) expect(workspace!.y + workspace!.height).toBeGreaterThanOrEqual(page.viewportSize()!.height - 24);
      else expect(workspace!.y + workspace!.height).toBeCloseTo(page.viewportSize()!.height - 24, 0);
      const search = await page.getByLabel("搜索服务").boundingBox();
      expect(Math.abs(search!.y - box!.y)).toBeLessThanOrEqual(2);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
      if (width === 1440) await page.screenshot({ path: info.outputPath(`service-header-${colorScheme}.png`) });
    }
  }
  await page.goto("/#/agents/a-1");
  await page.getByText("设备信息", { exact: true }).click();
  await expect(page.getByRole("button", { name: "复制设备识别码", exact: true })).toBeVisible();
});

test("离线设备可保存配置，打开公网与复制操作分开", async ({ page }) => {
  const state = await installApiMocks(page);
  state.devices[0].status = "offline";
  await page.goto("/#/services");
  const address = page.getByRole("link", { name: "打开媒体中心" });
  await expect(address).toHaveAttribute("href", state.tunnels[0].public_address);
  await expect(address).toHaveAttribute("target", "_blank");
  await expect(page.getByRole("link", { name: "媒体中心", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "媒体中心", exact: true }).click();
  await page.getByRole("button", { name: "编辑服务" }).click();
  const editor = page.getByRole("dialog", { name: "编辑服务" });
  await expect(editor).toContainText("连接恢复后下发");
  await editor.getByLabel("服务名称").fill("离线修改成功");
  await editor.getByRole("button", { name: "保存服务" }).click();
  await expect(editor).toBeHidden();
  expect(state.calls.find(call => call.method === "PUT" && call.path.endsWith("/t-1"))?.body.device_id).toBe("a-1");
  await expect(page.getByRole("status")).toContainText("配置已保存");
});

test("协议、状态和设备筛选组合可清空，空状态按资源给出下一步", async ({ page }) => {
  await page.clock.install();
  const state = await installApiMocks(page);
  state.tunnels.push({ ...state.tunnels[0], id: "t-2", protocol: "tcp", enabled: false, device_id: "a-2", name: "备用服务" });
  await page.goto("/#/services");
  await page.getByLabel("类型筛选").selectOption("tcp");
  await page.getByLabel("服务筛选").selectOption("disabled");
  await page.getByLabel("设备筛选").selectOption("a-2");
  await expect(page.locator(".service-row")).toHaveCount(1);
  await expect(page.locator(".service-row")).toContainText("备用服务");
  await page.getByRole("button", { name: "清除筛选" }).click();
  await expect(page.locator(".service-row")).toHaveCount(2);
  state.tunnels = []; state.devices = []; state.domains = [];
  await page.clock.fastForward(5000);
  await expect(page.getByRole("button", { name: "创建服务", exact: true })).toBeVisible();
  await expect(page.getByLabel("搜索服务")).toBeHidden();
  await expect(page.locator(".page-header").getByRole("button", { name: "创建服务", exact: true })).toBeHidden();
  await expect(page.getByRole("button", { name: "创建服务", exact: true })).toHaveCount(1);
  await expect(page.locator(".batch-actions")).toBeHidden();
});

test("部署命令可直接复制，弹窗显示多台独立设备", async ({ page }, info) => {
  const state = await installApiMocks(page); state.devices = []; state.enrollments = [];
  await page.goto("/#/agents");
  await page.getByRole("button", { name: "添加设备", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "添加设备", exact: true });
  const progress = dialog.getByRole("region", { name: "最近接入设备" });
  await expect(progress).toContainText("等待设备连接");
  state.devices.push({ id: "nas-one-uuid", name: "家庭 NAS", status: "online", tunnel_count: 0, enrolled_at: 1790000001 }, { id: "nas-two-uuid", name: "家庭 NAS", status: "offline", tunnel_count: 0, enrolled_at: 1790000002 });
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(progress.locator("li")).toHaveCount(2);
  await expect(dialog.getByRole("button", { name: "复制 Compose 配置", exact: true })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "批准入网" })).toHaveCount(0);
  expect(state.calls.some(call => call.path.endsWith("/approve"))).toBeFalsy();
  await page.screenshot({ path: info.outputPath("shared-agent-devices.png") });
});

test("服务进入关联域名后返回原服务，手机子页隐藏底栏", async ({ page }, info) => {
  const state = await installApiMocks(page);
  state.tunnels[0].apply_status = "failed";
  state.tunnels[0].apply_error = "证书尚未签发";
  await page.goto("/#/services/t-1");
  await expect(page.locator(".service-public-link")).toHaveAttribute("href", state.tunnels[0].public_address);
  await expect(page.locator(".service-public-link")).toHaveAttribute("target", "_blank");
  await page.getByRole("link", { name: "域名与 DNS" }).click();
  await expect(page).toHaveURL(/#\/domains\/d-1$/);
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("example.com");
  if ((page.viewportSize()?.width ?? 0) <= 900) await expect(page.locator(".bottom-nav")).toBeHidden();
  await page.screenshot({ path: info.outputPath("domain-detail.png") });
  await page.getByRole("link", { name: "返回", exact: true }).click();
  await expect(page).toHaveURL(/#\/services\/t-1$/);
});

test("空服务页只有一个创建入口，删除最后一项后退出批量选择", async ({ page }, info) => {
  await installApiMocks(page);
  await page.goto("/#/services");
  await page.getByRole("button", { name: "选择", exact: true }).focus();
  await page.getByRole("button", { name: "选择", exact: true }).press("Space");
  await page.getByRole("checkbox", { name: "选择媒体中心" }).check();
  await page.locator(".batch-actions").getByRole("button", { name: "删除", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "删除 媒体中心？" })).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "删除服务", exact: true }).click();
  await expect(page.locator(".batch-actions")).toBeHidden();
  await expect(page.getByLabel("搜索服务")).toBeHidden();
  await expect(page.locator(".page-header").getByRole("button", { name: "创建服务", exact: true })).toBeHidden();
  await expect(page.getByRole("button", { name: "创建服务", exact: true })).toHaveCount(1);
  await page.screenshot({ path: info.outputPath("services-empty.png") });
  await page.getByRole("button", { name: "创建服务", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "创建服务", exact: true })).toBeVisible();
});


test("用户列表加载失败可就地重试", async ({ page }) => {
  await installApiMocks(page);
  let failed = true;
  await page.route("**/api/v1/admin/users", route => route.fulfill(failed ? { status: 503, json: { error: "无法加载用户" } } : { json: [{ id: "alice", username: "alice", role: "tenant", enabled: true, workspace_id: "alice-space", workspace_name: "Alice 的空间", devices: 0, services: 0, domains: 0 }] }));
  await page.route("**/api/v1/admin/invitations", route => route.fulfill({ json: [] }));
  await page.goto("/#/users");
  await expect(page.getByRole("alert")).toContainText("无法加载用户");
  failed = false;
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await expect(page.getByRole("heading", { name: "alice", exact: true })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveCount(0);
});

test("普通用户首次接入的空状态只有一个添加入口，手机可直接操作", async ({ page }, info) => {
  const state = await installApiMocks(page, { empty: true });
  state.devices = []; state.domains = []; state.enrollments = [];
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { initialized: true, authenticated: true, user_id: "alice", workspace_id: "default", role: "tenant", username: "alice", csrf_token: "test-csrf" } }));
  if (info.project.name === "mobile-light") await page.setViewportSize({ width: 320, height: 568 });
  await page.goto("/#/services");
  const connect = page.getByRole("link", { name: "接入设备", exact: true });
  await expect(connect).toBeInViewport({ ratio: 1 });
  await page.screenshot({ path: info.outputPath("empty-services.png") });
  await connect.click();
  const addAgent = page.getByRole("button", { name: "添加设备", exact: true });
  await expect(addAgent).toHaveCount(1);
  await expect(addAgent).toBeInViewport({ ratio: 1 });
  await page.screenshot({ path: info.outputPath("empty-agents.png") });
  await addAgent.click();
  await expect(page.getByRole("dialog", { name: "添加设备", exact: true })).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: /^(取消|关闭)$/ }).click();
  await page.goto("/#/domains");
  const addDomain = page.getByRole("button", { name: "添加 域名", exact: true });
  await expect(addDomain).toHaveCount(1);
  await expect(addDomain).toBeInViewport({ ratio: 1 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("empty-domains.png") });
  await addDomain.click();
  await expect(page.getByRole("dialog", { name: "添加域名", exact: true })).toBeVisible();
});

test("会话设备标签兼容旧记录，登录密码显隐保留输入", async ({ page }) => {
  const state = await installApiMocks(page);
  Object.assign(state.sessions[0], { browser: "Safari", os: "iOS / iPadOS", created_at: 1790000000 });
  await page.goto("/#/settings/sessions");
  await expect(page.locator(".session-row").first()).toContainText("Safari · iOS / iPadOS");
  await expect(page.locator(".session-row").first()).toContainText("创建时间");
  await expect(page.locator(".session-row").last()).toContainText("未知设备");
  state.authenticated = false;
  await page.reload();
  const password = page.getByLabel("密码", { exact: true });
  await password.fill("a-valid-password");
  await page.getByRole("button", { name: "显示密码", exact: true }).click();
  await expect(password).toHaveAttribute("type", "text");
  await expect(password).toHaveValue("a-valid-password");
  await page.getByRole("button", { name: "隐藏密码", exact: true }).click();
  await expect(password).toHaveAttribute("type", "password");
});

test("用户搜索与状态筛选组合，启用操作使用普通确认", async ({ page }) => {
  await installApiMocks(page);
  const users = [{ id: "alice", username: "alice", role: "tenant", workspace_name: "Alice 的空间", workspace_id: "alice-space", enabled: false, devices: 0, services: 0, domains: 0 }];
  await page.route("**/api/v1/admin/users", route => route.fulfill({ json: users }));
  await page.route("**/api/v1/admin/invitations", route => route.fulfill({ json: [] }));
  await page.goto("/#/users");
  await page.getByLabel("搜索用户").fill("ALICE");
  await page.getByLabel("用户状态筛选").selectOption("enabled");
  await expect(page.getByText("没有匹配的用户", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "清除筛选" }).click();
  await expect(page.locator(".user-card")).toHaveCount(1);
  await page.getByRole("button", { name: "更多", exact: true }).click();
  await page.getByRole("button", { name: "启用用户", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("button", { name: "启用用户", exact: true })).toHaveClass("primary-button");
  await page.getByRole("dialog").getByRole("button", { name: "取消" }).click();
});
