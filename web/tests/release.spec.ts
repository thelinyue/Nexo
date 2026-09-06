import { expect, test, type Page, type Route } from "@playwright/test";

type MockOptions = {
  initialized: boolean;
  authenticated: boolean;
};

const dashboardResponses: Record<string, unknown> = {
  "/api/v1/overview": {
    devices: 0,
    running_tunnels: 0,
    mesh_devices: 0,
    current_connections: 0,
  },
  "/api/v1/devices": [],
  "/api/v1/sites": [],
  "/api/v1/enrollments": [],
  "/api/v1/mesh/status": { status: "restricted", message: "等待配置公网组网入口" },
  "/api/v1/site-networks": [],
  "/api/v1/site-links": [],
  "/api/v1/tunnels": [],
  "/api/v1/settings/public-entry": {
    base_domain: null,
    https_enabled: false,
    certificate_mode: "cloudflare",
    acme_environment: "production",
    apply_status: "not_configured",
    apply_error: null,
    certificate_not_before: null,
    certificate_not_after: null,
    certificate_subjects: [],
    dns_check: {},
  },
};

async function fulfillJson(route: Route, body: unknown) {
  await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function installApiMocks(page: Page, options: MockOptions) {
  let initialized = options.initialized;
  let authenticated = options.authenticated;
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/status") {
      await fulfillJson(route, {
        initialized,
        authenticated,
        username: authenticated ? "admin" : null,
        channel: authenticated ? "local_http" : null,
        csrf_token: authenticated ? "release-csrf" : null,
        local_http_warning: true,
      });
      return;
    }
    if (path === "/api/v1/auth/initialize") {
      initialized = true;
      authenticated = true;
      await fulfillJson(route, {
        initialized: true,
        authenticated: true,
        username: "admin",
        channel: "local_http",
        csrf_token: "release-csrf",
        local_http_warning: true,
      });
      return;
    }
    if (path in dashboardResponses) {
      await fulfillJson(route, dashboardResponses[path]);
      return;
    }
    await route.fulfill({ status: 404, contentType: "application/json", body: '{"error":"not mocked"}' });
  });
}

async function expectNoHorizontalOverflow(page: Page) {
  const width = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
  }));
  expect(width.document).toBeLessThanOrEqual(width.viewport);
  expect(width.body).toBeLessThanOrEqual(width.viewport);
}

test("首次初始化流程可用且布局不溢出", async ({ page }) => {
  await installApiMocks(page, { initialized: false, authenticated: false });
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "创建管理员" })).toBeVisible();
  await page.getByLabel("Bootstrap Code").fill("release-bootstrap-code");
  await page.getByLabel("管理员用户名").fill("admin");
  await page.getByLabel("管理员密码").fill("release-test-password");
  await page.getByRole("button", { name: "完成初始化" }).click();

  await expect(page.getByRole("heading", { name: "概览" })).toBeVisible();
  await expect(page.getByText("当前为未加密 HTTP", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});
test("已登录管理界面在桌面和移动视口保持完整", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "概览" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Web 服务与 TCP 端口" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "让网络归于一处" })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("减少动态效果与透明度时保留反馈和可读性", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "该媒体特性通过 Chromium DevTools 模拟");
  const session = await page.context().newCDPSession(page);
  await session.send("Emulation.setEmulatedMedia", {
    features: [
      { name: "prefers-reduced-motion", value: "reduce" },
      { name: "prefers-reduced-transparency", value: "reduce" },
    ],
  });
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/");

  const sidebar = page.locator(".sidebar");
  await expect(sidebar).toBeVisible();
  await expect(sidebar).toHaveCSS("backdrop-filter", "none");
  await expect(page.getByRole("button", { name: "刷新状态" })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});
