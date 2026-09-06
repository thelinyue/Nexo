import { expect, test, type Page, type Route } from "@playwright/test";

type MockOptions = {
  initialized: boolean;
  authenticated: boolean;
  failFirstTunnelCreate?: boolean;
  failFirstNetworkCreate?: boolean;
  failFirstLinkCreate?: boolean;
};

const publicEntry = {
  base_domain: "nexo.example.com",
  https_enabled: true,
  certificate_mode: "cloudflare",
  acme_environment: "production",
  apply_status: "ready",
  apply_error: null,
  certificate_not_before: 1890000000,
  certificate_not_after: 1893456000,
  certificate_subjects: ["*.nexo.example.com"],
  dns_check: { resolved: ["203.0.113.10"] },
};

const seedSites = [
  { id: "site-home", tenant_id: "default", name: "家庭" },
  { id: "site-office", tenant_id: "default", name: "办公室" },
];

const seedDevices = [
  {
    id: "device-home",
    tenant_id: "default",
    site_id: "site-home",
    name: "家庭网关",
    os: "linux",
    architecture: "amd64",
    agent_version: "0.1.2",
    status: "online",
    mesh_status: "connected",
    mesh_address: "100.64.0.2",
    gateway_report: {
      subnet_gateway: "ready",
      site_gateway: "ready",
      local_networks: [{ interface_id: "eth0", prefix: "192.168.1.0/24", gateway_address: "192.168.1.1" }],
    },
  },
  {
    id: "device-office",
    tenant_id: "default",
    site_id: "site-office",
    name: "办公室网关",
    os: "linux",
    architecture: "arm64",
    agent_version: "0.1.2",
    status: "online",
    mesh_status: "connected",
    mesh_address: "100.64.0.3",
    gateway_report: {
      subnet_gateway: "ready",
      site_gateway: "ready",
      local_networks: [{ interface_id: "enp1s0", prefix: "10.20.0.0/24", gateway_address: "10.20.0.1" }],
    },
  },
];

const seedNetworks = [
  {
    id: "network-home", tenant_id: "default", site_id: "site-home", site_name: "家庭", name: "家庭局域网",
    publisher_device_name: "家庭网关", publisher_device_id: "device-home", interface_id: "eth0", gateway_address: "192.168.1.1",
    desired_prefix: "192.168.1.0/24", applied_prefix: "192.168.1.0/24", enabled: true, apply_status: "ready",
    apply_error: null, health_status: "ready", health_error: null,
  },
  {
    id: "network-office", tenant_id: "default", site_id: "site-office", site_name: "办公室", name: "办公室局域网",
    publisher_device_name: "办公室网关", publisher_device_id: "device-office", interface_id: "enp1s0", gateway_address: "10.20.0.1",
    desired_prefix: "10.20.0.0/24", applied_prefix: "10.20.0.0/24", enabled: true, apply_status: "ready",
    apply_error: null, health_status: "ready", health_error: null,
  },
];

const seedTunnel = {
  id: "tunnel-media", tenant_id: "default", device_id: "device-home", device_name: "家庭网关", name: "媒体中心",
  protocol: "http", local_address: "127.0.0.1", local_port: 8096, public_port: null, hostname: "media", origin_protocol: "http",
  origin_tls_server_name: null, origin_tls_verification: "system", service_name: "media", enabled: true, apply_status: "ready",
  apply_error: null, desired_revision: 1, applied_revision: 1, public_address: "https://media.nexo.example.com",
};

async function fulfillJson(route: Route, body: unknown, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

/** 每个测试持有独立的可变服务端快照，使创建、编辑和刷新形成完整闭环。 */
async function installApiMocks(page: Page, options: MockOptions) {
  let initialized = options.initialized;
  let authenticated = options.authenticated;
  let failTunnelCreate = Boolean(options.failFirstTunnelCreate);
  let failNetworkCreate = Boolean(options.failFirstNetworkCreate);
  let failLinkCreate = Boolean(options.failFirstLinkCreate);
  const state = {
    sites: structuredClone(seedSites),
    devices: structuredClone(seedDevices),
    networks: structuredClone(seedNetworks),
    links: [] as Record<string, unknown>[],
    tunnels: [structuredClone(seedTunnel)],
    enrollments: [] as Record<string, unknown>[],
    sessions: [
      { id: "session-current", channel: "local_http", created_at: 1890000000, last_seen_at: 1891000000, expires_at: 1893456000 },
      { id: "session-other", channel: "public_https", created_at: 1889000000, last_seen_at: 1890000000, expires_at: 1893000000 },
    ],
  };

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (path === "/api/v1/auth/status") {
      await fulfillJson(route, { initialized, authenticated, username: authenticated ? "admin" : null, channel: authenticated ? "local_http" : null, csrf_token: authenticated ? "release-csrf" : null, local_http_warning: true });
      return;
    }
    if (path === "/api/v1/auth/initialize" && method === "POST") {
      initialized = true; authenticated = true; await fulfillJson(route, { csrf_token: "release-csrf" }); return;
    }
    if (path === "/api/v1/auth/login" && method === "POST") {
      authenticated = true; await fulfillJson(route, { username: "admin", channel: "local_http", csrf_token: "release-csrf", message: "登录成功" }); return;
    }
    if (path === "/api/v1/auth/logout" && method === "POST") {
      authenticated = false; await fulfillJson(route, { message: "已退出登录" }); return;
    }
    if (path === "/api/v1/auth/session") { await fulfillJson(route, state.sessions[0]); return; }
    if (path === "/api/v1/auth/sessions" && method === "GET") { await fulfillJson(route, state.sessions); return; }
    if (path === "/api/v1/auth/password" && method === "POST") {
      authenticated = false; await fulfillJson(route, { message: "密码已更新，请重新登录" }); return;
    }
    if (path.startsWith("/api/v1/auth/sessions/") && method === "POST") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      state.sessions = state.sessions.filter((session) => session.id !== id);
      await fulfillJson(route, { message: "登录会话已撤销" }); return;
    }
    if (path === "/api/v1/overview") {
      await fulfillJson(route, { devices: state.devices.length, running_tunnels: state.tunnels.filter((item) => item.enabled).length, mesh_devices: 2, current_connections: 2 }); return;
    }
    if (path === "/api/v1/devices") { await fulfillJson(route, state.devices); return; }
    if (path === "/api/v1/sites" && method === "GET") { await fulfillJson(route, state.sites); return; }
    if (path === "/api/v1/enrollments" && method === "GET") { await fulfillJson(route, state.enrollments); return; }
    if (path === "/api/v1/mesh/status") { await fulfillJson(route, { status: "normal", message: "组网运行正常" }); return; }
    if (path === "/api/v1/site-networks" && method === "GET") { await fulfillJson(route, state.networks); return; }
    if (path === "/api/v1/site-links" && method === "GET") { await fulfillJson(route, state.links); return; }
    if (path === "/api/v1/tunnels" && method === "GET") { await fulfillJson(route, state.tunnels); return; }
    if (path === "/api/v1/settings/public-entry" && method === "GET") { await fulfillJson(route, publicEntry); return; }

    if (path === "/api/v1/enrollments" && method === "POST") {
      await fulfillJson(route, { enrollment_id: "enrollment-release", token: "release-one-time-token", expires_at: 1893456000 }); return;
    }
    if (path === "/api/v1/sites" && method === "POST") {
      const body = request.postDataJSON() as { name: string; tenant_id: string };
      state.sites.push({ id: `site-${state.sites.length + 1}`, ...body });
      await fulfillJson(route, state.sites.at(-1), 201); return;
    }
    if (path === "/api/v1/site-networks" && method === "POST") {
      if (failNetworkCreate) { failNetworkCreate = false; await fulfillJson(route, { error: "模拟共享网络创建失败" }, 422); return; }
      const body = request.postDataJSON() as Record<string, string>;
      const site = state.sites.find((item) => item.id === body.site_id)!;
      const device = state.devices.find((item) => item.id === body.publisher_device_id)!;
      const created = { id: `network-${state.networks.length + 1}`, ...body, site_name: site.name, publisher_device_name: device.name, desired_prefix: body.prefix, applied_prefix: null, gateway_address: null, enabled: true, apply_status: "checking", apply_error: null, health_status: "degraded", health_error: null };
      state.networks.push(created); await fulfillJson(route, created, 201); return;
    }
    if (path === "/api/v1/site-links" && method === "POST") {
      if (failLinkCreate) { failLinkCreate = false; await fulfillJson(route, { error: "模拟站点互联创建失败" }, 422); return; }
      const body = request.postDataJSON() as Record<string, string>;
      const left = state.sites.find((item) => item.id === body.left_site_id)!;
      const right = state.sites.find((item) => item.id === body.right_site_id)!;
      const created = { id: "link-created", left_site_name: left.name, right_site_name: right.name, left_network_prefix: "192.168.1.0/24", right_network_prefix: "10.20.0.0/24", static_routes: [], enabled: true, apply_status: "checking", apply_error: null, health_status: "degraded", health_error: null };
      state.links.push(created); await fulfillJson(route, created, 201); return;
    }
    if (path === "/api/v1/tunnels" && method === "POST") {
      if (failTunnelCreate) { failTunnelCreate = false; await fulfillJson(route, { error: "模拟创建失败" }, 422); return; }
      const body = request.postDataJSON() as Record<string, unknown>;
      const device = state.devices.find((item) => item.id === body.device_id)!;
      const created = { ...seedTunnel, ...body, id: `tunnel-${state.tunnels.length + 1}`, device_name: device.name, enabled: true, apply_status: "checking", public_address: null };
      state.tunnels.push(created); await fulfillJson(route, created, 201); return;
    }
    if (/^\/api\/v1\/tunnels\/[^/]+$/.test(path) && method === "PUT") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const body = request.postDataJSON() as Record<string, unknown>;
      const index = state.tunnels.findIndex((item) => item.id === id);
      const device = state.devices.find((item) => item.id === body.device_id)!;
      state.tunnels[index] = { ...state.tunnels[index], ...body, device_name: device.name };
      await fulfillJson(route, state.tunnels[index]); return;
    }
    if (/^\/api\/v1\/tunnels\/[^/]+\/(enable|disable)$/.test(path) && method === "POST") {
      const parts = path.split("/");
      const id = decodeURIComponent(parts.at(-2) ?? "");
      const tunnel = state.tunnels.find((item) => item.id === id)!;
      tunnel.enabled = parts.at(-1) === "enable";
      await fulfillJson(route, tunnel); return;
    }
    await fulfillJson(route, { error: `未模拟接口：${method} ${path}` }, 404);
  });
}

async function expectNoHorizontalOverflow(page: Page) {
  const width = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    document: document.documentElement.scrollWidth,
    body: document.body.scrollWidth,
    offenders: Array.from(document.querySelectorAll<HTMLElement>("body *"))
      .map((element) => ({ element, box: element.getBoundingClientRect() }))
      .filter(({ box }) => box.right > document.documentElement.clientWidth + 1 || box.left < -1)
      .slice(0, 8)
      .map(({ element, box }) => `${element.tagName}.${element.className}:${Math.round(box.left)}-${Math.round(box.right)}`),
  }));
  expect(width.offenders, `横向越界元素：${width.offenders.join(", ")}`).toEqual([]);
  expect(width.document).toBeLessThanOrEqual(width.viewport);
  expect(width.body).toBeLessThanOrEqual(width.viewport);
}

async function navigatePrimary(page: Page, name: string) {
  if ((page.viewportSize()?.width ?? 1440) <= 900) {
    await page.getByRole("button", { name: "打开导航" }).click();
    await page.getByRole("dialog", { name: "移动导航" }).getByRole("link", { name, exact: true }).click();
  } else {
    await page.locator(".sidebar").getByRole("link", { name, exact: true }).click();
  }
}

test("首次初始化后进入独立概览页", async ({ page }) => {
  await installApiMocks(page, { initialized: false, authenticated: false });
  await page.goto("/");
  await page.getByLabel("初始化口令").fill("release-bootstrap-code");
  await page.getByLabel("管理员用户名").fill("admin");
  await page.getByLabel("管理员密码").fill("release-test-password");
  await page.getByRole("button", { name: "完成初始化" }).click();
  await expect(page.locator("main h1")).toHaveText("概览");
  await expect(page).toHaveURL(/#\/overview$/);
  await expect(page.getByText("当前为未加密 HTTP", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "新建公网访问" })).toHaveCount(0);
  await expectNoHorizontalOverflow(page);
});

test("五个一级页面、二级路由与浏览器历史可用", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/overview");
  await expect(page.locator("main h1")).toHaveText("概览");
  await navigatePrimary(page, "设备");
  await expect(page).toHaveURL(/#\/devices\/list$/);
  await expect(page.locator("main h1")).toHaveText("设备");
  await page.getByRole("link", { name: /入网请求/ }).click();
  await expect(page.locator("main h1")).toHaveText("入网请求");
  await navigatePrimary(page, "公网访问");
  await expect(page.locator("main h1")).toHaveText("公网访问");
  await navigatePrimary(page, "网络互联");
  await expect(page.locator("main h1")).toHaveText("站点");
  await page.getByRole("link", { name: /共享网络/ }).click();
  await expect(page.locator("main h1")).toHaveText("共享网络");
  await page.getByRole("link", { name: /站点互联/ }).click();
  await expect(page.locator("main h1")).toHaveText("站点互联");
  await navigatePrimary(page, "设置");
  await expect(page.locator("main h1")).toHaveText("设置");
  await page.goBack();
  await expect(page.locator("main h1")).toHaveText("站点互联");
  await page.goForward();
  await expect(page.locator("main h1")).toHaveText("设置");
  await page.goto("/#/unknown");
  await expect(page).toHaveURL(/#\/overview$/);
  await expect(page.locator("main h1")).toHaveText("概览");
  await expectNoHorizontalOverflow(page);
});

test("添加设备生成最小 Compose 配置", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/devices/enrollments");
  await page.getByRole("button", { name: "添加设备" }).click();
  await page.getByLabel("设备名称").fill("家庭 NAS");
  await page.getByRole("button", { name: "生成设备配置" }).click();
  const compose = await page.getByLabel("Docker Compose 配置").inputValue();
  expect(compose).toContain("ghcr.io/thelinyue/nexo-agent:0.1.2");
  expect(compose.match(/NEXO_[A-Z_]+:/g)).toEqual(["NEXO_SERVER_URL:", "NEXO_ENROLLMENT_TOKEN:"]);
  await page.getByRole("button", { name: "复制 Compose 配置" }).click();
  await expect(page.getByRole("button", { name: "已复制" })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("公网访问新建与编辑均使用表格式弹窗", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, failFirstTunnelCreate: true });
  await page.goto("/#/public-access");
  const createTrigger = page.getByRole("button", { name: "新建公网访问" });
  await createTrigger.click();
  let dialog = page.getByRole("dialog", { name: "新建公网访问" });
  await expect(dialog.getByRole("button", { name: "取消" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(createTrigger).toBeFocused();
  await createTrigger.click();
  dialog = page.getByRole("dialog", { name: "新建公网访问" });
  await expect(dialog.getByLabel("公网协议").locator("option")).toHaveText(["HTTP", "HTTPS", "TCP"]);
  await dialog.getByLabel("显示名称（可选）", { exact: true }).fill("远程终端");
  await dialog.getByLabel("公网协议").selectOption("tcp");
  await expect(dialog.getByLabel("公网端口（可选）")).toBeVisible();
  await expect(dialog.getByLabel("子域名前缀")).toHaveCount(0);
  await dialog.getByLabel("本地地址").fill("service.internal.example.local");
  await dialog.getByLabel("本地端口").fill("70000");
  await dialog.getByRole("button", { name: "创建公网访问" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("本地端口必须在 1-65535 范围内");
  await dialog.getByLabel("本地端口").fill("22");
  await dialog.getByLabel("公网端口（可选）").fill("22022");
  await dialog.getByRole("button", { name: "创建公网访问" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("模拟创建失败");
  await expect(dialog.getByLabel("显示名称（可选）", { exact: true })).toHaveValue("远程终端");
  await dialog.getByRole("button", { name: "创建公网访问" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText("远程终端", { exact: true })).toBeVisible();
  const tunnelRow = page.locator(".tunnel-row").filter({ hasText: "媒体中心" });
  const editTrigger = tunnelRow.getByRole("button", { name: "编辑" });
  await editTrigger.click();
  const editDialog = page.getByRole("dialog", { name: "编辑公网访问" });
  await expect(editDialog.getByLabel("显示名称", { exact: true })).toHaveValue("媒体中心");
  await expect(editDialog.getByLabel("公网协议").locator("option")).toHaveText(["HTTP", "HTTPS", "TCP"]);
  await expect(editDialog.getByLabel("本地服务协议")).toBeVisible();
  await expect(editDialog.getByLabel("本地地址")).toBeVisible();
  await editDialog.getByLabel("显示名称", { exact: true }).fill("家庭媒体库");
  await editDialog.getByRole("button", { name: "保存修改" }).click();
  await expect(editDialog).toBeHidden();
  await expect(page.getByText("家庭媒体库", { exact: true })).toBeVisible();
  await expect(page.locator(".tunnel-row").filter({ hasText: "家庭媒体库" }).getByRole("button", { name: "编辑" })).toBeFocused();
  await expectNoHorizontalOverflow(page);
});

test("共享网络和站点互联通过弹窗创建", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, failFirstNetworkCreate: true, failFirstLinkCreate: true });
  await page.goto("/#/networks/shared");
  const networkTrigger = page.getByRole("button", { name: "新建共享网络" });
  await networkTrigger.click();
  let dialog = page.getByRole("dialog", { name: "新建共享网络" });
  await dialog.getByRole("button", { name: "取消" }).click();
  await expect(networkTrigger).toBeFocused();
  await networkTrigger.click();
  dialog = page.getByRole("dialog", { name: "新建共享网络" });
  await dialog.getByLabel("显示名称", { exact: true }).fill("访客网络");
  await dialog.getByRole("combobox").nth(1).selectOption("device-home");
  await dialog.getByRole("combobox").nth(2).selectOption("eth0|192.168.1.0/24");
  await dialog.getByRole("button", { name: "创建共享网络" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("模拟共享网络创建失败");
  await expect(dialog.getByLabel("显示名称", { exact: true })).toHaveValue("访客网络");
  await dialog.getByRole("button", { name: "创建共享网络" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText("访客网络", { exact: true })).toBeVisible();
  await page.getByRole("link", { name: /站点互联/ }).click();
  const linkTrigger = page.getByRole("button", { name: "新建站点互联" });
  await linkTrigger.click();
  dialog = page.getByRole("dialog", { name: "新建站点互联" });
  await dialog.getByRole("button", { name: "取消" }).click();
  await expect(linkTrigger).toBeFocused();
  await linkTrigger.click();
  dialog = page.getByRole("dialog", { name: "新建站点互联" });
  await dialog.getByRole("combobox").nth(1).selectOption("network-home");
  await dialog.getByRole("combobox").nth(3).selectOption("network-office");
  await dialog.getByRole("button", { name: "建立站点互联" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("模拟站点互联创建失败");
  await expect(dialog.getByRole("combobox").nth(1)).toHaveValue("network-home");
  await expect(dialog.getByRole("combobox").nth(3)).toHaveValue("network-office");
  await dialog.getByRole("button", { name: "建立站点互联" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.locator(".site-link-card")).toContainText("家庭");
  await expect(page.locator(".site-link-card")).toContainText("办公室");
  await expectNoHorizontalOverflow(page);
});

test("站点保持页内创建，设置支持会话撤销与改密重登", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/networks/sites");
  await page.getByRole("button", { name: "新建站点" }).click();
  await page.getByLabel("站点名称").fill("仓库");
  await page.getByRole("button", { name: "创建站点" }).click();
  await expect(page.getByText("仓库", { exact: true })).toBeVisible();
  await navigatePrimary(page, "设置");
  await expect(page.getByRole("button", { name: "当前会话" })).toBeDisabled();
  await page.getByRole("button", { name: "撤销会话", exact: true }).click();
  await expect(page.getByText("公网 HTTPS 会话", { exact: false })).toHaveCount(0);
  await page.getByLabel("当前密码").fill("old-release-password");
  await page.getByLabel("新密码", { exact: true }).fill("new-release-password");
  await page.getByLabel("确认新密码").fill("new-release-password");
  await page.getByRole("button", { name: "更新密码" }).click();
  await expect(page.getByRole("heading", { name: "欢迎回来" })).toBeVisible();
  await expect(page.getByText("密码已更新，请重新登录", { exact: true })).toBeVisible();
});

test("移动抽屉、横竖屏弹窗重排与长地址均无横向溢出", async ({ page }) => {
  test.skip((page.viewportSize()?.width ?? 1440) > 900, "仅验证移动端抽屉与表单重排");
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/overview");
  await page.getByRole("button", { name: "打开导航" }).click();
  const drawer = page.getByRole("dialog", { name: "移动导航" });
  await drawer.getByRole("link", { name: "公网访问" }).click();
  await page.getByRole("button", { name: "新建公网访问" }).click();
  const dialog = page.getByRole("dialog", { name: "新建公网访问" });
  await dialog.getByLabel("本地地址").fill("very-long-internal-service-name.with-many-segments.example.local");
  const labelBox = await dialog.getByText("本地服务", { exact: true }).boundingBox();
  const protocolBox = await dialog.getByLabel("本地服务协议").boundingBox();
  const inputBox = await dialog.getByLabel("本地地址").boundingBox();
  expect(inputBox!.y).toBeGreaterThan(labelBox!.y);
  expect(protocolBox!.x + protocolBox!.width).toBeLessThanOrEqual(inputBox!.x);
  const footerBox = await dialog.locator(".form-footer").boundingBox();
  expect(footerBox!.y + footerBox!.height).toBeLessThanOrEqual(page.viewportSize()!.height + 1);
  await expectNoHorizontalOverflow(page);
});

test("减少动态效果与透明度时保留反馈和可读性", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "该媒体特性通过 Chromium DevTools 模拟");
  const session = await page.context().newCDPSession(page);
  await session.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-reduced-motion", value: "reduce" }, { name: "prefers-reduced-transparency", value: "reduce" }] });
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/overview");
  const material = (page.viewportSize()?.width ?? 1440) <= 900 ? page.locator(".mobile-header") : page.locator(".sidebar");
  await expect(material).toBeVisible();
  await expect(material).toHaveCSS("backdrop-filter", "none");
  await expect(page.getByRole("button", { name: "刷新" })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});
