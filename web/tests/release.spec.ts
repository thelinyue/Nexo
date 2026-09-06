import { expect, test, type Page, type Route } from "@playwright/test";

type MockOptions = {
  initialized: boolean;
  authenticated: boolean;
  failFirstTunnelCreate?: boolean;
  failFirstNetworkCreate?: boolean;
  failFirstLinkCreate?: boolean;
  failFirstPublicEntryUpdate?: boolean;
  failFirstNetworksLoad?: boolean;
  publicEntry?: Partial<typeof publicEntry>;
};

const publicEntry = {
  base_domain: "nexo.example.com" as string | null,
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
  { id: "site-warehouse", tenant_id: "default", name: "仓库" },
];

const seedDevices = [
  {
    id: "device-home",
    tenant_id: "default",
    site_id: "site-home",
    name: "家庭网关",
    os: "linux",
    architecture: "amd64",
    agent_version: "0.1.4",
    status: "online",
    mesh_status: "connected",
    mesh_address: "100.64.0.2",
    last_seen_at: 1893456000,
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
    agent_version: "0.1.4",
    status: "online",
    mesh_status: "connected",
    mesh_address: "100.64.0.3",
    last_seen_at: 1893456000,
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

const seedLinks = [
  {
    id: "link-home-office",
    left_site_id: "site-home",
    right_site_id: "site-office",
    left_network_id: "network-home",
    right_network_id: "network-office",
    left_site_name: "家庭",
    right_site_name: "办公室",
    left_network_prefix: "192.168.1.0/24",
    right_network_prefix: "10.20.0.0/24",
    static_routes: [
      { router_site_id: "site-home", destination_site_id: "site-office", router_site_name: "家庭", destination_site_name: "办公室", destination_prefix: "10.20.0.0/24", next_hop: "192.168.1.2", router_confirmed: false },
      { router_site_id: "site-office", destination_site_id: "site-home", router_site_name: "办公室", destination_site_name: "家庭", destination_prefix: "192.168.1.0/24", next_hop: "10.20.0.2", router_confirmed: false },
    ],
    enabled: true,
    apply_status: "ready",
    apply_error: null,
    health_status: "ready",
    health_error: null,
    route_confirmations: [] as { site_id: string; confirmed_at: number }[],
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
  let failPublicEntryUpdate = Boolean(options.failFirstPublicEntryUpdate);
  let failNetworksLoad = Boolean(options.failFirstNetworksLoad);
  const state = {
    sites: structuredClone(seedSites),
    devices: structuredClone(seedDevices),
    networks: structuredClone(seedNetworks),
    links: structuredClone(seedLinks),
    tunnels: [structuredClone(seedTunnel)],
    enrollments: [] as Record<string, unknown>[],
    sessions: [
      { id: "session-current", channel: "local_http", created_at: 1890000000, last_seen_at: 1891000000, expires_at: 1893456000 },
      { id: "session-other", channel: "public_https", created_at: 1889000000, last_seen_at: 1890000000, expires_at: 1893000000 },
    ],
    publicEntry: { ...structuredClone(publicEntry), ...options.publicEntry },
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
    if (path === "/api/v1/site-networks" && method === "GET") {
      if (failNetworksLoad) { failNetworksLoad = false; await fulfillJson(route, { error: "模拟网络互联加载失败" }, 503); return; }
      await fulfillJson(route, state.networks); return;
    }
    if (path === "/api/v1/site-links" && method === "GET") { await fulfillJson(route, state.links); return; }
    if (path === "/api/v1/tunnels" && method === "GET") { await fulfillJson(route, state.tunnels); return; }
    if (path === "/api/v1/settings/public-entry" && method === "GET") { await fulfillJson(route, state.publicEntry); return; }

    if (path === "/api/v1/enrollments" && method === "POST") {
      await fulfillJson(route, { enrollment_id: "enrollment-release", token: "release-one-time-token", expires_at: 1893456000 }); return;
    }
    if (path === "/api/v1/settings/public-entry" && method === "PUT") {
      if (failPublicEntryUpdate) { failPublicEntryUpdate = false; await fulfillJson(route, { error: "模拟域名与 HTTPS 设置失败" }, 422); return; }
      const body = request.postDataJSON() as Partial<typeof publicEntry>;
      state.publicEntry = { ...state.publicEntry, ...body, apply_status: "configuring", apply_error: null };
      await fulfillJson(route, state.publicEntry); return;
    }
    if (path === "/api/v1/settings/public-entry/certificate" && method === "POST") {
      await fulfillJson(route, state.publicEntry); return;
    }
    if (path === "/api/v1/settings/public-entry/recheck" && method === "POST") {
      state.publicEntry = { ...state.publicEntry, apply_status: "ready", apply_error: null };
      await fulfillJson(route, state.publicEntry); return;
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
      const leftNetwork = state.networks.find((item) => item.id === body.left_network_id)!;
      const rightNetwork = state.networks.find((item) => item.id === body.right_network_id)!;
      const created = {
        id: "link-created", ...body, left_site_name: left.name, right_site_name: right.name,
        left_network_prefix: leftNetwork.desired_prefix, right_network_prefix: rightNetwork.desired_prefix,
        static_routes: [
          { router_site_id: left.id, destination_site_id: right.id, router_site_name: left.name, destination_site_name: right.name, destination_prefix: rightNetwork.desired_prefix, next_hop: "192.168.1.2", router_confirmed: false },
          { router_site_id: right.id, destination_site_id: left.id, router_site_name: right.name, destination_site_name: left.name, destination_prefix: leftNetwork.desired_prefix, next_hop: "10.20.0.2", router_confirmed: false },
        ],
        enabled: true, apply_status: "checking", apply_error: null, health_status: "degraded", health_error: null,
        route_confirmations: [] as { site_id: string; confirmed_at: number }[],
      };
      state.links.push(created); await fulfillJson(route, created, 201); return;
    }
    if (/^\/api\/v1\/site-networks\/[^/]+\/(enable|disable)$/.test(path) && method === "POST") {
      const parts = path.split("/");
      const network = state.networks.find((item) => item.id === decodeURIComponent(parts.at(-2) ?? ""))!;
      network.enabled = parts.at(-1) === "enable";
      network.apply_status = network.enabled ? "checking" : "disabled";
      await fulfillJson(route, network); return;
    }
    if (/^\/api\/v1\/site-links\/[^/]+\/(enable|disable)$/.test(path) && method === "POST") {
      const parts = path.split("/");
      const link = state.links.find((item) => item.id === decodeURIComponent(parts.at(-2) ?? ""))!;
      link.enabled = parts.at(-1) === "enable";
      link.apply_status = link.enabled ? "checking" : "disabled";
      await fulfillJson(route, link); return;
    }
    if (/^\/api\/v1\/site-links\/[^/]+\/recheck$/.test(path) && method === "POST") {
      const link = state.links.find((item) => item.id === decodeURIComponent(path.split("/").at(-2) ?? ""))!;
      link.health_status = "ready";
      link.health_error = null;
      await fulfillJson(route, link); return;
    }
    if (/^\/api\/v1\/site-links\/[^/]+\/router-confirmations\/[^/]+$/.test(path) && method === "POST") {
      const parts = path.split("/");
      const siteId = decodeURIComponent(parts.at(-1) ?? "");
      const link = state.links.find((item) => item.id === decodeURIComponent(parts.at(-3) ?? ""))!;
      const guide = link.static_routes.find((item) => item.router_site_id === siteId)!;
      guide.router_confirmed = true;
      link.route_confirmations.push({ site_id: siteId, confirmed_at: 1893456000 });
      await fulfillJson(route, link); return;
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

async function expectNoGenericRefresh(page: Page) {
  await expect(page.getByRole("button", { name: "刷新", exact: true })).toHaveCount(0);
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
  await expect(page.getByRole("button", { name: "添加穿透服务" })).toHaveCount(0);
  await expectNoHorizontalOverflow(page);
});

test("五个一级页面、二级路由与浏览器历史可用", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/overview");
  await expect(page.locator("main h1")).toHaveText("概览");
  await expectNoGenericRefresh(page);
  await navigatePrimary(page, "设备");
  await expect(page).toHaveURL(/#\/devices\/list$/);
  await expect(page.locator("main h1")).toHaveText("设备");
  await expectNoGenericRefresh(page);
  await page.getByRole("link", { name: /入网请求/ }).click();
  await expect(page.locator("main h1")).toHaveText("入网请求");
  await expectNoGenericRefresh(page);
  await navigatePrimary(page, "公网访问");
  await expect(page).toHaveURL(/#\/public-access\/tunnels$/);
  await expect(page.locator("main h1")).toHaveText("内网穿透");
  await expectNoGenericRefresh(page);
  await expect(page).toHaveTitle("内网穿透 - Nexo");
  if ((page.viewportSize()?.width ?? 1440) <= 900) {
    await page.getByRole("button", { name: "打开导航" }).click();
    const drawer = page.getByRole("dialog", { name: "移动导航" });
    await expect(drawer.getByRole("link", { name: "公网访问" })).toHaveAttribute("aria-current", "page");
    await drawer.getByRole("button", { name: "关闭导航" }).click();
  } else {
    await expect(page.locator(".sidebar").getByRole("link", { name: "公网访问" })).toHaveAttribute("aria-current", "page");
  }
  await page.getByRole("link", { name: "域名与 HTTPS", exact: true }).click();
  await expect(page).toHaveURL(/#\/public-access\/domain$/);
  await expect(page.locator("main h1")).toHaveText("域名与 HTTPS");
  await expectNoGenericRefresh(page);
  await expect(page.getByRole("button", { name: "重新检测", exact: true })).toBeVisible();
  await navigatePrimary(page, "网络互联");
  await expect(page).toHaveURL(/#\/networks$/);
  await expect(page.locator("main h1")).toHaveText("网络互联");
  await expectNoGenericRefresh(page);
  await expect(page.getByRole("navigation", { name: "网络互联页面" })).toHaveCount(0);
  await navigatePrimary(page, "设置");
  await expect(page.locator("main h1")).toHaveText("设置");
  await expectNoGenericRefresh(page);
  await page.goBack();
  await expect(page.locator("main h1")).toHaveText("网络互联");
  await page.goForward();
  await expect(page.locator("main h1")).toHaveText("设置");
  await page.goto("/#/unknown");
  await expect(page).toHaveURL(/#\/overview$/);
  await expect(page.locator("main h1")).toHaveText("概览");
  await expectNoGenericRefresh(page);
  await expectNoHorizontalOverflow(page);
});

test("旧公网访问地址无历史污染地跳转到内网穿透", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/overview");
  await page.goto("/#/public-access");
  await expect(page).toHaveURL(/#\/public-access\/tunnels$/);
  await expect(page.locator("main h1")).toHaveText("内网穿透");
  await expect(page.getByRole("link", { name: "内网穿透", exact: true })).toHaveAttribute("aria-current", "page");
  await page.goBack();
  await expect(page).toHaveURL(/#\/overview$/);
});

test("旧网络互联子路由无历史污染地跳转到统一页面", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  for (const route of ["sites", "shared", "links"]) {
    await page.goto("/#/overview");
    await page.goto(`/#/networks/${route}`);
    await expect(page).toHaveURL(/#\/networks$/);
    await expect(page.locator("main h1")).toHaveText("网络互联");
    await page.goBack();
    await expect(page).toHaveURL(/#\/overview$/);
  }
});

test("网络互联加载失败后可重试且不恢复通用刷新", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, failFirstNetworksLoad: true });
  await page.goto("/#/networks");
  await expect(page.getByRole("alert")).toContainText("模拟网络互联加载失败");
  await expectNoGenericRefresh(page);
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await expect(page.getByRole("button", { name: "展开家庭" })).toBeVisible();
});

test("添加设备生成最小 Compose 配置", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/devices/enrollments");
  await page.getByRole("button", { name: "添加设备" }).click();
  await page.getByLabel("设备名称").fill("家庭 NAS");
  await page.getByRole("button", { name: "生成设备配置" }).click();
  const compose = await page.getByLabel("Docker Compose 配置").inputValue();
  expect(compose).toContain("ghcr.io/thelinyue/nexo-agent:0.1.4");
  expect(compose).toContain("TZ: ${TZ:-Asia/Shanghai}");
  expect(compose.match(/NEXO_[A-Z_]+:/g)).toEqual(["NEXO_SERVER_URL:", "NEXO_ENROLLMENT_TOKEN:"]);
  await page.getByRole("button", { name: "复制 Compose 配置" }).click();
  await expect(page.getByRole("button", { name: "已复制" })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("穿透服务添加与编辑均使用表格式弹窗", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, failFirstTunnelCreate: true });
  await page.goto("/#/public-access/tunnels");
  const createTrigger = page.getByRole("button", { name: "添加穿透服务" });
  await createTrigger.click();
  let dialog = page.getByRole("dialog", { name: "添加穿透服务" });
  await expect(dialog.getByRole("button", { name: "取消" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(createTrigger).toBeFocused();
  await createTrigger.click();
  dialog = page.getByRole("dialog", { name: "添加穿透服务" });
  await expect(dialog.getByLabel("公网协议").locator("option")).toHaveText(["HTTP", "HTTPS", "TCP"]);
  await dialog.getByLabel("显示名称（可选）", { exact: true }).fill("远程终端");
  await dialog.getByLabel("公网协议").selectOption("tcp");
  await expect(dialog.getByLabel("公网端口（可选）")).toBeVisible();
  await expect(dialog.getByLabel("子域名前缀")).toHaveCount(0);
  await dialog.getByLabel("本地地址").fill("service.internal.example.local");
  await dialog.getByLabel("本地端口").fill("70000");
  await dialog.getByRole("button", { name: "添加穿透服务", exact: true }).click();
  await expect(dialog.getByRole("alert")).toHaveText("本地端口必须在 1-65535 范围内");
  await dialog.getByLabel("本地端口").fill("22");
  await dialog.getByLabel("公网端口（可选）").fill("22022");
  await dialog.getByRole("button", { name: "添加穿透服务", exact: true }).click();
  await expect(dialog.getByRole("alert")).toHaveText("模拟创建失败");
  await expect(dialog.getByLabel("显示名称（可选）", { exact: true })).toHaveValue("远程终端");
  await dialog.getByRole("button", { name: "添加穿透服务", exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText("远程终端", { exact: true })).toBeVisible();
  const tunnelRow = page.locator(".tunnel-row").filter({ hasText: "媒体中心" });
  const editTrigger = tunnelRow.getByRole("button", { name: "编辑" });
  await editTrigger.click();
  const editDialog = page.getByRole("dialog", { name: "编辑穿透服务" });
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

test("域名与 HTTPS 设置使用弹窗并安全提交 Cloudflare Token", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, failFirstPublicEntryUpdate: true });
  let secretRequestCount = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/v1/settings/public-entry/certificate") secretRequestCount += 1;
  });
  await page.goto("/#/public-access/domain");

  await expect(page.getByLabel("Cloudflare API Token")).toHaveCount(0);
  const editTrigger = page.getByRole("button", { name: "编辑域名与 HTTPS" });
  await editTrigger.click();
  let dialog = page.getByRole("dialog", { name: "编辑域名与 HTTPS" });
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(editTrigger).toBeFocused();
  await editTrigger.click();
  dialog = page.getByRole("dialog", { name: "编辑域名与 HTTPS" });
  const tokenInput = dialog.getByLabel("Cloudflare API Token", { exact: true });
  await expect(tokenInput).toHaveAttribute("type", "password");
  await tokenInput.fill("  release-cloudflare-token  ");
  await dialog.getByRole("button", { name: "显示 Cloudflare API Token" }).click();
  await expect(tokenInput).toHaveAttribute("type", "text");
  await dialog.getByRole("button", { name: "隐藏 Cloudflare API Token" }).click();

  await dialog.getByRole("button", { name: "保存设置" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("模拟域名与 HTTPS 设置失败");
  await expect(tokenInput).toHaveValue("  release-cloudflare-token  ");
  expect(secretRequestCount).toBe(0);

  const secretRequest = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/v1/settings/public-entry/certificate");
  await dialog.getByRole("button", { name: "保存设置" }).click();
  expect((await secretRequest).postDataJSON()).toMatchObject({ cloudflare_token: "release-cloudflare-token" });
  await expect(dialog).toBeHidden();
  await expect(editTrigger).toBeFocused();
  expect(secretRequestCount).toBe(1);

  await editTrigger.click();
  dialog = page.getByRole("dialog", { name: "编辑域名与 HTTPS" });
  await expect(dialog.getByLabel("Cloudflare API Token", { exact: true })).toHaveValue("");
  await dialog.getByRole("button", { name: "保存设置" }).click();
  await expect(dialog).toBeHidden();
  expect(secretRequestCount).toBe(1);
  await expectNoHorizontalOverflow(page);
});

test("未配置域名与 HTTPS 时通过配置弹窗完成设置", async ({ page }) => {
  await installApiMocks(page, {
    initialized: true,
    authenticated: true,
    publicEntry: { base_domain: null, https_enabled: false, certificate_mode: "none", apply_status: "not_configured", certificate_not_after: null },
  });
  await page.goto("/#/public-access/domain");
  await expect(page.getByText("尚未配置", { exact: true })).toBeVisible();
  await expect(page.getByLabel("根域名")).toHaveCount(0);
  const configureTrigger = page.getByRole("button", { name: "配置域名与 HTTPS" });
  await configureTrigger.click();
  const dialog = page.getByRole("dialog", { name: "配置域名与 HTTPS" });
  await dialog.getByLabel("根域名").fill("edge.example.com");
  await dialog.getByRole("button", { name: "取消" }).click();
  await expect(dialog).toBeHidden();
  await expect(configureTrigger).toBeFocused();

  await configureTrigger.click();
  const reopened = page.getByRole("dialog", { name: "配置域名与 HTTPS" });
  await reopened.getByLabel("根域名").fill("edge.example.com");
  await reopened.getByRole("button", { name: "保存设置" }).click();
  await expect(reopened).toBeHidden();
  await expect(page.getByRole("button", { name: "编辑域名与 HTTPS" })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("网络互联按站点展开、锁定来源并同步呈现双端关系", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, failFirstNetworkCreate: true, failFirstLinkCreate: true });
  await page.goto("/#/networks");
  await expect(page.locator(".network-site-details")).toHaveCount(0);
  await page.getByRole("button", { name: "展开家庭" }).click();
  await page.getByRole("button", { name: "展开办公室" }).click();
  const home = page.locator(".network-site").filter({ has: page.locator(".network-site-identity").getByText("家庭", { exact: true }) });
  const office = page.locator(".network-site").filter({ has: page.locator(".network-site-identity").getByText("办公室", { exact: true }) });
  await expect(page.locator(".network-site-details")).toHaveCount(2);
  await expect(home.locator(".site-link-card")).toHaveCount(1);
  await expect(office.locator(".site-link-card")).toHaveCount(1);
  await expect(home.locator(".route-guide")).toContainText("10.20.0.0/24");
  await expect(home.locator(".route-guide")).not.toContainText("192.168.1.0/24");

  const homeNetwork = home.locator(".network-row").filter({ hasText: "家庭局域网" });
  page.once("dialog", (confirmation) => confirmation.accept());
  await homeNetwork.getByRole("button", { name: "停止共享本地网络" }).click();
  await expect(homeNetwork.getByRole("button", { name: "重新共享本地网络" })).toBeVisible();
  await homeNetwork.getByRole("button", { name: "重新共享本地网络" }).click();
  await expect(homeNetwork.getByRole("button", { name: "停止共享本地网络" })).toBeVisible();

  page.once("dialog", (confirmation) => confirmation.accept());
  await home.locator(".site-link-card").first().getByRole("button", { name: "关闭站点互联" }).click();
  await expect(home.getByRole("button", { name: "重新启用站点互联" })).toBeVisible();
  await home.getByRole("button", { name: "重新启用站点互联" }).click();
  await expect(office.getByRole("button", { name: "关闭站点互联" })).toBeVisible();

  const networkTrigger = home.getByRole("button", { name: "添加共享网络" });
  await networkTrigger.click();
  let dialog = page.getByRole("dialog", { name: "添加共享网络" });
  await expect(dialog.getByLabel("来源站点")).toBeDisabled();
  await expect(dialog.getByLabel("来源站点")).toHaveValue("site-home");
  await dialog.getByRole("button", { name: "取消" }).click();
  await expect(networkTrigger).toBeFocused();
  await networkTrigger.click();
  dialog = page.getByRole("dialog", { name: "添加共享网络" });
  await dialog.getByLabel("显示名称", { exact: true }).fill("访客网络");
  await dialog.getByLabel("网关设备").selectOption("device-home");
  await dialog.getByLabel("本地网络").selectOption("eth0|192.168.1.0/24");
  await dialog.getByRole("button", { name: "创建共享网络" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("模拟共享网络创建失败");
  await expect(dialog.getByLabel("显示名称", { exact: true })).toHaveValue("访客网络");
  await dialog.getByRole("button", { name: "创建共享网络" }).click();
  await expect(dialog).toBeHidden();
  await expect(home.getByText("访客网络", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "收起家庭" })).toBeVisible();

  const linkTrigger = home.getByRole("button", { name: "连接站点" });
  await linkTrigger.click();
  dialog = page.getByRole("dialog", { name: "连接站点" });
  await expect(dialog.getByLabel("来源站点")).toBeDisabled();
  await expect(dialog.getByLabel("来源站点")).toHaveValue("site-home");
  await expect(dialog.getByLabel("目标站点").locator("option")).toHaveText(["选择站点", "办公室"]);
  await dialog.getByRole("button", { name: "取消" }).click();
  await expect(linkTrigger).toBeFocused();
  await linkTrigger.click();
  dialog = page.getByRole("dialog", { name: "连接站点" });
  await dialog.getByLabel("来源共享网络").selectOption("network-home");
  await dialog.getByLabel("目标共享网络").selectOption("network-office");
  await dialog.getByRole("button", { name: "建立站点互联" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("模拟站点互联创建失败");
  await expect(dialog.getByLabel("来源共享网络")).toHaveValue("network-home");
  await expect(dialog.getByLabel("目标共享网络")).toHaveValue("network-office");
  await dialog.getByRole("button", { name: "建立站点互联" }).click();
  await expect(dialog).toBeHidden();
  await expect(home.locator(".site-link-card")).toHaveCount(2);
  await expect(office.locator(".site-link-card")).toHaveCount(2);

  await home.getByRole("button", { name: "确认路由已配置" }).first().click();
  await expect(home.getByRole("button", { name: "确认路由已配置" })).toHaveCount(1);
  await expect(office.getByRole("button", { name: "确认路由已配置" })).toHaveCount(2);
  await home.getByRole("button", { name: "重新检测", exact: true }).first().click();

  await page.getByRole("button", { name: "展开仓库" }).click();
  const warehouse = page.locator(".network-site").filter({ has: page.locator(".network-site-identity").getByText("仓库", { exact: true }) });
  await expect(warehouse.getByRole("button", { name: "添加共享网络" })).toBeDisabled();
  await expect(warehouse.getByRole("button", { name: "连接站点" })).toBeDisabled();
  await expect(warehouse).toContainText("需要本站有一台共享网络能力就绪");
  await expect(warehouse).toContainText("请先为本站添加并启用一个共享网络");
  await expectNoHorizontalOverflow(page);
});

test("站点保持页内创建，设置支持会话撤销与改密重登", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/networks");
  await page.getByRole("button", { name: "新建站点" }).click();
  await page.getByLabel("站点名称").fill("门店");
  await page.getByRole("button", { name: "创建站点" }).click();
  await expect(page.locator(".network-site-identity strong").filter({ hasText: "门店" }).first()).toBeVisible();
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

test("Manifest、PWA 图标与 Service Worker 缓存边界正确", async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "PWA 产物和缓存边界只需验证一次");
  const context = await browser.newContext({ serviceWorkers: "allow", colorScheme: "dark" });
  const page = await context.newPage();
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("http://127.0.0.1:4173/#/overview");

  const manifestHref = await page.locator('link[rel="manifest"]').getAttribute("href");
  expect(manifestHref).toBeTruthy();
  const manifest = await page.evaluate(async (href) => fetch(href!).then((response) => response.json()), manifestHref);
  expect(manifest).toMatchObject({
    name: "Nexo 联巢",
    short_name: "Nexo",
    lang: "zh-CN",
    display: "standalone",
    start_url: "/#/overview",
  });
  expect(manifest.icons).toEqual(expect.arrayContaining([
    expect.objectContaining({ src: "/pwa-192x192.png", sizes: "192x192" }),
    expect.objectContaining({ src: "/pwa-512x512.png", sizes: "512x512" }),
    expect.objectContaining({ src: "/pwa-maskable-512x512.png", purpose: "maskable" }),
  ]));

  for (const icon of ["/pwa-192x192.png", "/pwa-512x512.png", "/pwa-maskable-512x512.png", "/apple-touch-icon.png"]) {
    const response = await context.request.get(`http://127.0.0.1:4173${icon}`);
    expect(response.ok(), `${icon} 应可读取`).toBeTruthy();
    expect(response.headers()["content-type"]).toContain("image/png");
  }

  const serviceWorker = await page.evaluate(async () => {
    const registration = await navigator.serviceWorker.ready;
    if (registration.active?.state !== "activated") {
      await new Promise<void>((resolve) => {
        const worker = registration.active;
        if (!worker || worker.state === "activated") return resolve();
        worker.addEventListener("statechange", () => { if (worker.state === "activated") resolve(); });
      });
    }
    const script = await fetch(registration.active!.scriptURL).then((response) => response.text());
    const cachedUrls = (await Promise.all((await caches.keys()).map(async (key) => (await caches.open(key)).keys())))
      .flat()
      .map((request) => request.url);
    return { active: registration.active?.state, script, cachedUrls };
  });
  expect(serviceWorker.active).toBe("activated");
  expect(serviceWorker.script).toContain("NetworkOnly");
  expect(serviceWorker.cachedUrls.some((url: string) => new URL(url).pathname.startsWith("/api/"))).toBeFalsy();

  try {
    const controlledPage = await context.newPage();
    await controlledPage.goto("http://127.0.0.1:4173/");
    expect(await controlledPage.evaluate(() => Boolean(navigator.serviceWorker.controller))).toBeTruthy();
    await controlledPage.close();
  } finally {
    await context.close();
  }
});

test("鉴权状态断网时显示连接错误并可重试", async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "断网恢复流程只需验证一次");
  const context = await browser.newContext({ serviceWorkers: "block" });
  const page = await context.newPage();
  try {
    await page.route("**/api/v1/auth/status", (route) => route.abort("internetdisconnected"));
    await page.goto("http://127.0.0.1:4173/");
    await expect(page.getByRole("heading", { name: "无法连接 Nexo" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "创建管理员" })).toHaveCount(0);

    await page.unroute("**/api/v1/auth/status");
    await installApiMocks(page, { initialized: true, authenticated: true });
    await page.getByRole("button", { name: "重试" }).click();
    await expect(page.locator("main h1")).toHaveText("概览");
  } finally {
    await context.close();
  }
});

test("桌面、平板与移动目标视口充分利用空间且无横向溢出", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "目标视口矩阵只需串行验证一次");
  await installApiMocks(page, { initialized: true, authenticated: true });
  const viewports = [
    { width: 1366, height: 768 },
    { width: 1440, height: 900 },
    { width: 1920, height: 1080 },
    { width: 2560, height: 1440 },
    { width: 375, height: 812 },
    { width: 430, height: 932 },
    { width: 812, height: 375 },
    { width: 1024, height: 768 },
  ];

  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
    await page.goto("/#/overview");
    await expect(page.locator("main h1")).toHaveText("概览");
    await expectNoHorizontalOverflow(page);
    if (viewport.width > 900) {
      const contentBox = await page.locator(".content").boundingBox();
      const pageBox = await page.locator(".page-transition").boundingBox();
      expect(contentBox!.x).toBe(232);
      expect(Math.abs(contentBox!.width - (viewport.width - 232))).toBeLessThanOrEqual(1);
      expect(pageBox!.width).toBeLessThanOrEqual(1681);
      expect(Math.abs((pageBox!.x + pageBox!.width / 2) - (contentBox!.x + contentBox!.width / 2))).toBeLessThanOrEqual(2);
      if (viewport.width >= 1920) expect(pageBox!.width).toBeGreaterThan(1300);
    }
  }
});

test("Unix 秒按浏览器本地时区显示", async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "跨时区语义只需在一个浏览器项目中验证");
  const cases = [
    { timezoneId: "UTC", expected: "到期：2030年1月1日 00:00" },
    { timezoneId: "Asia/Shanghai", expected: "到期：2030年1月1日 08:00" },
  ];

  for (const { timezoneId, expected } of cases) {
    const context = await browser.newContext({ timezoneId });
    try {
      const page = await context.newPage();
      await installApiMocks(page, { initialized: true, authenticated: true });
      await page.goto("http://127.0.0.1:4173/#/settings");
      await expect(page.locator(".session-row").filter({ hasText: "局域网 HTTP 会话" })).toContainText(expected);
    } finally {
      await context.close();
    }
  }
});

test("移动抽屉、横竖屏弹窗重排与长地址均无横向溢出", async ({ page }) => {
  test.skip((page.viewportSize()?.width ?? 1440) > 900, "仅验证移动端抽屉与表单重排");
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/overview");
  await page.getByRole("button", { name: "打开导航" }).click();
  const drawer = page.getByRole("dialog", { name: "移动导航" });
  await drawer.getByRole("link", { name: "公网访问" }).click();
  await page.getByRole("button", { name: "添加穿透服务" }).click();
  const dialog = page.getByRole("dialog", { name: "添加穿透服务" });
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
  await expect(page.getByRole("link", { name: /内网穿透/ })).toBeVisible();
  await expectNoGenericRefresh(page);
  await page.goto("/#/public-access/domain");
  await expect(page.getByRole("button", { name: "重新检测", exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});
