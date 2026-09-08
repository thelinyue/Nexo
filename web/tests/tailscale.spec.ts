import { expect, test, type Page, type Route } from "@playwright/test";

type Role = "system_admin" | "tenant";

async function json(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function installTailscaleMocks(page: Page, role: Role) {
  let authKeys: unknown[] = [];
  let accessRules: unknown[] = [];
  const devices = [{ id: "access-device", name: "共享设备", mesh_address: "100.64.0.8" }];
  let externalNodes = role === "system_admin"
    ? [{
      node_id: "external-1",
      name: "外部笔记本",
      online: true,
      addresses: ["100.64.0.10"],
      claim_state: "isolated",
      discovered_at: 1890000000,
      last_seen_at: 1890000000,
    }]
    : [];
  let externalRequests = 0;
  let policyPreviewGetRequests = 0;
  let policyPreviewPostRequests = 0;

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (path === "/api/v1/auth/status") {
      await json(route, {
        initialized: true,
        authenticated: true,
        user_id: role === "system_admin" ? "admin-1" : "user-1",
        username: role === "system_admin" ? "admin" : "alice",
        role,
        workspace_id: role === "system_admin" ? "default" : "workspace-user-1",
        channel: "local_http",
        csrf_token: "tailscale-csrf",
        local_http_warning: true,
      });
      return;
    }
    if (path === "/api/v1/devices") { await json(route, [{ ...devices[0], status: "online", mesh_status: "connected", tailscale_ipv4: "100.64.0.8", tailscale_ipv6: "fd7a:115c:a1e0::8" }]); return; }
    if (path === "/api/v1/sites") { await json(route, []); return; }
    if (path === "/api/v1/site-networks") { await json(route, []); return; }
    if (path === "/api/v1/enrollments") { await json(route, []); return; }
    if (path === "/api/v1/mesh/status") { await json(route, { status: "normal", message: "组网运行正常" }); return; }
    if (path === "/api/v1/access-control/workspaces") {
      await json(route, role === "system_admin" ? [{ id: "workspace-user-1", name: "协作者空间" }] : []);
      return;
    }
    if (path === "/api/v1/access-control/rules" && method === "GET") { await json(route, accessRules); return; }
    if (path === "/api/v1/access-control/rules" && method === "POST") {
      const body = request.postDataJSON() as { name: string; target_id: string; protocols: string[]; ports: string[]; ssh_enabled: boolean };
      const rule = {
        id: "access-rule-1",
        owner_workspace_id: "default",
        owner_username: "admin",
        name: body.name,
        target_type: "device",
        target_id: body.target_id,
        target_label: "共享设备",
        protocols: body.protocols,
        ports: body.ports,
        ssh_enabled: body.ssh_enabled,
        enabled: true,
        desired_revision: 1,
        applied_revision: 0,
        apply_status: "pending",
        apply_error: null,
        grants: [{ workspace_id: "workspace-user-1", workspace_name: "协作者空间", status: "accepted", accepted_at: 1890000000 }],
        created_at: 1890000000,
        updated_at: 1890000000,
      };
      accessRules = [rule];
      await json(route, rule, 201);
      return;
    }
    if (path === "/api/v1/access-control/policy/preview" && method === "GET") {
      policyPreviewGetRequests += 1;
      await json(route, { valid: true, grant_count: 1, ssh_rule_count: 0, affected_targets: ["100.64.0.8"], summary: "Headscale Policy 校验通过", error: null });
      return;
    }
    if (path === "/api/v1/access-control/policy/preview" && method === "POST") {
      policyPreviewPostRequests += 1;
      await json(route, { valid: true, grant_count: 2, ssh_rule_count: 0, affected_targets: ["100.64.0.8"], summary: "Headscale Policy 校验通过", error: null });
      return;
    }
    if (path === "/api/v1/mesh/client-config") {
      await json(route, {
        login_server: "https://mesh.example.com",
        browser_authorization_url: null,
        supported_platforms: ["Linux", "Windows", "macOS", "iOS", "Android", "tvOS"],
        notes: [],
      });
      return;
    }
    if (path === "/api/v1/mesh/auth-keys" && method === "GET") { await json(route, authKeys); return; }
    if (path === "/api/v1/mesh/auth-keys" && method === "POST") {
      const body = request.postDataJSON() as { label: string; reusable: boolean; ephemeral: boolean };
      const key = {
        id: "auth-key-1",
        label: body.label,
        key: "tskey-auth-test-only-once",
        login_server: "https://mesh.example.com",
        reusable: body.reusable,
        ephemeral: body.ephemeral,
        expires_at: 1893456000,
        state: "issued",
        created_at: 1890000000,
      };
      authKeys = [{ ...key, key: null }];
      await json(route, key, 201);
      return;
    }
    if (path === "/api/v1/mesh/external-nodes" && method === "GET") {
      externalRequests += 1;
      if (role !== "system_admin") {
        await json(route, { error: "当前账号没有系统管理员权限" }, 403);
      } else {
        await json(route, externalNodes);
      }
      return;
    }
    if (path.startsWith("/api/v1/mesh/external-nodes/") && method === "POST") {
      externalNodes = [];
      await json(route, { id: "claimed-device", name: "外部笔记本", connection_type: "tailscale_client" });
      return;
    }
    if (path === "/api/v1/tunnels" && method === "GET") { await json(route, []); return; }
    if (path === "/api/v1/public-domains") {
      await json(route, { error: "当前账号没有系统设置权限" }, 403);
      return;
    }
    await json(route, []);
  });

  return {
    externalRequestCount: () => externalRequests,
    policyPreviewGetRequestCount: () => policyPreviewGetRequests,
    policyPreviewPostRequestCount: () => policyPreviewPostRequests,
  };
}

test("管理员官方客户端页支持 Auth Key 和隔离节点认领", async ({ page }) => {
  const mock = await installTailscaleMocks(page, "system_admin");
  await page.goto("/#/devices/official");
  await expect(page.getByRole("heading", { name: "官方客户端" }).first()).toBeVisible();
  await expect(page.getByText("由客户端发起", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "打开授权入口" })).toHaveCount(0);
  await expect(page.getByText("Linux、Windows、macOS、iOS、Android、tvOS", { exact: true })).toBeVisible();
  await expect(page.getByText("外部笔记本", { exact: true })).toBeVisible();

  await page.getByLabel("名称").fill("演示客户端");
  await page.getByRole("button", { name: "生成 Auth Key" }).click();
  await expect(page.getByText("tskey-auth-test-only-once", { exact: true })).toBeVisible();
  await expect(page.getByText("只显示这一次", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "认领" }).click();
  await expect(page.getByText("已认领“外部笔记本”，设备已加入当前工作空间", { exact: true })).toBeVisible();
  expect(mock.externalRequestCount()).toBeGreaterThan(0);
});

test("普通用户不读取隔离节点且不能进入实例域名设置", async ({ page }) => {
  const mock = await installTailscaleMocks(page, "tenant");
  await page.goto("/#/devices/official");
  await expect(page.getByRole("heading", { name: "官方客户端" }).first()).toBeVisible();
  await expect(page.getByText("隔离节点", { exact: true })).toHaveCount(0);
  expect(mock.externalRequestCount()).toBe(0);

  await page.goto("/#/public-access/domain");
  await expect(page).toHaveURL(/#\/public-access\/tunnels$/);
  await expect(page.getByRole("heading", { name: "内网穿透" })).toBeVisible();
  await expect(page.getByRole("link", { name: "域名与 HTTPS", exact: true })).toHaveCount(0);
});

test("管理员访问控制页支持结构化规则和移动窄屏布局", async ({ page }) => {
  const mock = await installTailscaleMocks(page, "system_admin");
  await page.goto("/#/access-control");
  await expect(page.getByRole("heading", { name: "访问控制" }).first()).toBeVisible();
  await expect(page.getByText("当前结构化策略", { exact: true })).toBeVisible();
  await expect.poll(() => mock.policyPreviewGetRequestCount()).toBe(1);
  expect(mock.policyPreviewPostRequestCount()).toBe(0);

  await page.getByLabel("规则名称").fill("协作者访问设备");
  await page.locator(".access-rule-form select").nth(1).selectOption("access-device");
  await page.getByText("协作者空间", { exact: true }).last().click();
  await page.getByRole("button", { name: "校验影响" }).click();
  await expect.poll(() => mock.policyPreviewPostRequestCount()).toBe(1);
  await page.getByRole("button", { name: "保存规则" }).click();
  await expect(page.getByText("协作者访问设备", { exact: true })).toBeVisible();
  await expect(page.getByText("协作者空间", { exact: true }).last()).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(await page.evaluate(() => window.innerWidth));
});

test("设备列表对重复组网地址去重并保留双栈地址", async ({ page }) => {
  await installTailscaleMocks(page, "system_admin");
  await page.goto("/#/devices/list");
  const row = page.locator(".device-row").filter({ hasText: "共享设备" });
  await expect(row.getByText("100.64.0.8", { exact: true })).toHaveCount(1);
  await expect(row.getByText("fd7a:115c:a1e0::8", { exact: true })).toHaveCount(1);
});
