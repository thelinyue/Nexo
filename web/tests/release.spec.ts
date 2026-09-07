import { expect, test, type Page, type Route } from "@playwright/test";

type MockOptions = {
  initialized: boolean;
  authenticated: boolean;
  tunnels?: Array<typeof seedTunnel>;
  failFirstTunnelCreate?: boolean;
  failFirstTunnelDelete?: boolean;
  tunnelDeleteDelayMs?: number;
  failFirstNetworkCreate?: boolean;
  failFirstLinkCreate?: boolean;
  failFirstPublicEntryUpdate?: boolean;
  failFirstNetworksLoad?: boolean;
  publicEntry?: Partial<typeof publicEntry>;
  publicDomains?: Array<typeof seedPublicDomain>;
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

const seedPublicDomain = {
  id: "domain-primary",
  tenant_id: "default",
  domain: "example.com",
  is_primary: true,
  https_enabled: true,
  certificate_mode: "cloudflare",
  acme_environment: "production",
  apply_status: "ready",
  apply_error: null as string | null,
  error_code: null as string | null,
  dns_check: {
    root: { hostname: "example.com", resolved: ["203.0.113.10"] },
    wildcard: { hostname: "nexo.example.com", probe: "*.example.com", resolved: ["203.0.113.10"] },
  },
  root_certificate: {
    status: "ready", not_before: 1890000000, not_after: 1893456000, renewal_at: 1892304000,
    subjects: ["example.com", "*.example.com"],
  },
  wildcard_certificate: {
    status: "ready", not_before: 1890000000, not_after: 1893456000, renewal_at: 1892304000,
    subjects: ["example.com", "*.example.com"],
  },
  usage_count: 2,
  desired_revision: 4,
  applied_revision: 4,
  retry_after: null as number | null,
  attempt_count: 0,
  next_retry_at: null as number | null,
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
    site_id: "site-home" as string | null,
    name: "家庭网关",
    os: "linux",
    architecture: "amd64",
    agent_version: "0.1.7",
    status: "online",
    mesh_status: "connected",
    mesh_address: "100.64.0.2",
    last_seen_at: 1893456000,
    gateway_report: {
      ipv4_forwarding: true,
      ipv6_forwarding: false,
      subnet_gateway: "ready",
      site_gateway: "ready",
      local_networks: [
        { interface_id: "eth0", prefix: "192.168.1.0/24", gateway_address: "192.168.1.1" },
        { interface_id: "eth1", prefix: "2001:db8:1::/64", gateway_address: "2001:db8:1::1" },
      ],
    },
  },
  {
    id: "device-office",
    tenant_id: "default",
    site_id: "site-office" as string | null,
    name: "办公室网关",
    os: "linux",
    architecture: "arm64",
    agent_version: "0.1.7",
    status: "online",
    mesh_status: "connected",
    mesh_address: "100.64.0.3",
    last_seen_at: 1893456000,
    gateway_report: {
      ipv4_forwarding: true,
      ipv6_forwarding: true,
      subnet_gateway: "ready",
      site_gateway: "ready",
      local_networks: [
        { interface_id: "enp1s0", prefix: "10.20.0.0/24", gateway_address: "10.20.0.1" },
        { interface_id: "enp2s0", prefix: "2001:db8:20::/64", gateway_address: "2001:db8:20::1" },
      ],
    },
  },
  {
    id: "device-v6",
    tenant_id: "default",
    site_id: "site-home" as string | null,
    name: "IPv6 网关",
    os: "linux",
    architecture: "amd64",
    agent_version: "0.1.7",
    status: "online",
    mesh_status: "connected",
    mesh_address: "fd7a:115c:a1e0::4",
    last_seen_at: 1893456000,
    gateway_report: {
      ipv4_forwarding: false,
      ipv6_forwarding: true,
      subnet_gateway: "ready",
      site_gateway: "ready",
      local_networks: [
        { interface_id: "eth0", prefix: "192.168.2.0/24", gateway_address: "192.168.2.1" },
        { interface_id: "eth1", prefix: "2001:db8:2::/64", gateway_address: "2001:db8:2::1" },
      ],
    },
  },
];

const seedNetworks = [
  {
    id: "network-home", tenant_id: "default", site_id: "site-home", site_name: "家庭", name: "家庭局域网",
    publisher_device_name: "家庭网关", publisher_device_id: "device-home", interface_id: "eth0", source: "detected", gateway_address: "192.168.1.1",
    desired_prefix: "192.168.1.0/24", applied_prefix: "192.168.1.0/24", enabled: true, apply_status: "ready",
    apply_error: null, health_status: "ready", health_error: null, deletion_pending: false,
  },
  {
    id: "network-office", tenant_id: "default", site_id: "site-office", site_name: "办公室", name: "办公室局域网",
    publisher_device_name: "办公室网关", publisher_device_id: "device-office", interface_id: "enp1s0", source: "detected", gateway_address: "10.20.0.1",
    desired_prefix: "10.20.0.0/24", applied_prefix: "10.20.0.0/24", enabled: true, apply_status: "ready",
    apply_error: null, health_status: "ready", health_error: null, deletion_pending: false,
  },
  {
    id: "network-office-v6", tenant_id: "default", site_id: "site-office", site_name: "办公室", name: "办公室 IPv6",
    publisher_device_name: "办公室网关", publisher_device_id: "device-office", interface_id: "enp2s0", source: "detected", gateway_address: "2001:db8:20::1",
    desired_prefix: "2001:db8:20::/64", applied_prefix: "2001:db8:20::/64", enabled: true, apply_status: "ready",
    apply_error: null, health_status: "ready", health_error: null, deletion_pending: false,
  },
];

const seedLinks = [
  {
    id: "link-home-office",
    tenant_id: "default",
    left_site_id: "site-home",
    right_site_id: "site-office",
    left_network_id: "network-home",
    right_network_id: "network-office",
    left_site_name: "家庭",
    right_site_name: "办公室",
    left_network_prefix: "192.168.1.0/24",
    right_network_prefix: "10.20.0.0/24",
    left_networks: [{ id: "network-home", name: "家庭局域网", prefix: "192.168.1.0/24", source: "detected", address_family: "ipv4", publisher_device_id: "device-home", publisher_device_name: "家庭网关", gateway_address: "192.168.1.1", apply_status: "ready" }],
    right_networks: [{ id: "network-office", name: "办公室局域网", prefix: "10.20.0.0/24", source: "detected", address_family: "ipv4", publisher_device_id: "device-office", publisher_device_name: "办公室网关", gateway_address: "10.20.0.1", apply_status: "ready" }],
    static_routes: [
      { router_site_id: "site-home", destination_site_id: "site-office", router_site_name: "家庭", destination_site_name: "办公室", destination_prefix: "10.20.0.0/24", next_hop: "192.168.1.2", router_confirmed: false },
      { router_site_id: "site-office", destination_site_id: "site-home", router_site_name: "办公室", destination_site_name: "家庭", destination_prefix: "192.168.1.0/24", next_hop: "10.20.0.2", router_confirmed: false },
    ],
    route_statuses: [
      { network_id: "network-office", router_site_id: "site-home", destination_site_id: "site-office", destination_prefix: "10.20.0.0/24", address_family: "ipv4", device_status: "applied", control_plane_status: "serving", remote_status: "accepted", error: null, checked_at: 1893456000 },
      { network_id: "network-home", router_site_id: "site-office", destination_site_id: "site-home", destination_prefix: "192.168.1.0/24", address_family: "ipv4", device_status: "applied", control_plane_status: "serving", remote_status: "accepted", error: null, checked_at: 1893456000 },
    ],
    enabled: true,
    apply_status: "ready",
    apply_error: null,
    health_status: "ready",
    health_error: null,
    deletion_pending: false,
    route_confirmations: [] as { site_id: string; confirmed_at: number }[],
  },
];

const seedTunnel = {
  id: "tunnel-media", tenant_id: "default", device_id: "device-home" as string | null, device_name: "家庭网关" as string | null, name: "媒体中心",
  protocol: "http" as "tcp" | "http" | "https", local_address: "127.0.0.1", local_port: 8096, public_port: null as number | null, hostname: "media" as string | null, origin_protocol: "http" as "http" | "https" | null,
  origin_tls_server_name: null as string | null, origin_tls_verification: "system", service_name: "media" as string | null, enabled: true, apply_status: "ready",
  apply_error: null as string | null, desired_revision: 1, applied_revision: 1, deletion_pending: false, public_address: "https://media.nexo.example.com" as string | null,
};

async function fulfillJson(route: Route, body: unknown, status = 200) {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });
}

/** 每个测试持有独立的可变服务端快照，使创建、编辑和刷新形成完整闭环。 */
async function installApiMocks(page: Page, options: MockOptions) {
  let initialized = options.initialized;
  let authenticated = options.authenticated;
  let failTunnelCreate = Boolean(options.failFirstTunnelCreate);
  let failTunnelDelete = Boolean(options.failFirstTunnelDelete);
  let failNetworkCreate = Boolean(options.failFirstNetworkCreate);
  let failLinkCreate = Boolean(options.failFirstLinkCreate);
  let failPublicEntryUpdate = Boolean(options.failFirstPublicEntryUpdate);
  let failNetworksLoad = Boolean(options.failFirstNetworksLoad);
  const state = {
    sites: structuredClone(seedSites),
    devices: structuredClone(seedDevices),
    networks: structuredClone(seedNetworks),
    links: structuredClone(seedLinks),
    tunnels: structuredClone(options.tunnels ?? [seedTunnel]),
    enrollments: [] as Record<string, unknown>[],
    sessions: [
      { id: "session-current", channel: "local_http", created_at: 1890000000, last_seen_at: 1891000000, expires_at: 1893456000 },
      { id: "session-other", channel: "public_https", created_at: 1889000000, last_seen_at: 1890000000, expires_at: 1893000000 },
    ],
    publicEntry: { ...structuredClone(publicEntry), ...options.publicEntry },
    publicDomains: structuredClone(options.publicDomains ?? []),
  };
  const supportsPublicDomains = options.publicDomains !== undefined;
  const pendingRefreshes = new Map<string, number>();
  const deviceSnapshot = () => state.devices.map((device) => ({
    ...device,
    tunnel_count: state.tunnels.filter((tunnel) => tunnel.device_id === device.id).length,
  }));

  const finishPendingDeletion = <T extends { id: string; deletion_pending?: boolean }>(kind: string, items: T[]) => {
    for (const item of items) {
      if (!item.deletion_pending) continue;
      const key = `${kind}:${item.id}`;
      const refreshes = (pendingRefreshes.get(key) ?? 0) + 1;
      pendingRefreshes.set(key, refreshes);
      if (refreshes >= 2) items.splice(items.indexOf(item), 1);
    }
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
    if (path === "/api/v1/devices" && method === "GET") { await fulfillJson(route, deviceSnapshot()); return; }
    if (path === "/api/v1/sites" && method === "GET") { await fulfillJson(route, state.sites); return; }
    if (path === "/api/v1/enrollments" && method === "GET") { await fulfillJson(route, state.enrollments); return; }
    if (path === "/api/v1/mesh/status") { await fulfillJson(route, { status: "normal", message: "组网运行正常" }); return; }
    if (path === "/api/v1/site-networks" && method === "GET") {
      if (failNetworksLoad) { failNetworksLoad = false; await fulfillJson(route, { error: "模拟网络互联加载失败" }, 503); return; }
      finishPendingDeletion("network", state.networks);
      await fulfillJson(route, state.networks); return;
    }
    if (path === "/api/v1/site-links" && method === "GET") { finishPendingDeletion("link", state.links); await fulfillJson(route, state.links); return; }
    if (path === "/api/v1/tunnels" && method === "GET") { await fulfillJson(route, state.tunnels); return; }
    if (supportsPublicDomains && path === "/api/v1/public-domains" && method === "GET") {
      await fulfillJson(route, state.publicDomains);
      return;
    }
    if (supportsPublicDomains && path === "/api/v1/public-domains/batch/recheck" && method === "POST") {
      const body = request.postDataJSON() as { ids: string[] };
      const updated = state.publicDomains.filter((domain) => body.ids.includes(domain.id));
      await fulfillJson(route, { updated, skipped: [], message: "已重新检测 " + updated.length + " 个域名" });
      return;
    }
    if (supportsPublicDomains && path === "/api/v1/public-domains/batch/renew" && method === "POST") {
      const body = request.postDataJSON() as { ids: string[] };
      const updated = state.publicDomains.filter((domain) => body.ids.includes(domain.id) && domain.apply_status !== "rate_limited");
      const skipped = state.publicDomains
        .filter((domain) => body.ids.includes(domain.id) && domain.apply_status === "rate_limited")
        .map((domain) => ({ id: domain.id, reason: "CA 限流窗口尚未结束，Caddy 会自动重试" }));
      await fulfillJson(route, { updated, skipped, message: "已请求 Caddy 处理 " + updated.length + " 个域名，限流项将按官方退避自动重试" });
      return;
    }
    if (supportsPublicDomains && /^\/api\/v1\/public-domains\/[^/]+\/(recheck|renew)$/.test(path) && method === "POST") {
      const parts = path.split("/");
      const domain = state.publicDomains.find((item) => item.id === decodeURIComponent(parts.at(-2) ?? ""));
      if (!domain) { await fulfillJson(route, { error: "域名不存在" }, 404); return; }
      if (parts.at(-1) === "renew" && domain.apply_status === "rate_limited") {
        await fulfillJson(route, { error: "CA 限流窗口尚未结束，Caddy 会自动重试" }, 429);
        return;
      }
      await fulfillJson(route, domain);
      return;
    }
    if (supportsPublicDomains && /^\/api\/v1\/public-domains\/[^/]+\/credentials$/.test(path) && method === "POST") {
      const domain = state.publicDomains.find((item) => item.id === decodeURIComponent(path.split("/").at(-2) ?? ""));
      if (!domain) { await fulfillJson(route, { error: "域名不存在" }, 404); return; }
      await fulfillJson(route, domain);
      return;
    }
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
      const created = { id: `network-${state.networks.length + 1}`, ...body, site_name: site.name, publisher_device_name: device.name, desired_prefix: body.prefix, applied_prefix: null, gateway_address: null, enabled: true, apply_status: "checking", apply_error: null, health_status: "degraded", health_error: null, deletion_pending: false };
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
        id: "link-created", tenant_id: "default", ...body, left_site_name: left.name, right_site_name: right.name,
        left_network_prefix: leftNetwork.desired_prefix, right_network_prefix: rightNetwork.desired_prefix,
        left_networks: [{ id: leftNetwork.id, name: leftNetwork.name, prefix: leftNetwork.desired_prefix, source: leftNetwork.source, address_family: leftNetwork.desired_prefix.includes(":") ? "ipv6" : "ipv4", publisher_device_id: leftNetwork.publisher_device_id, publisher_device_name: leftNetwork.publisher_device_name, gateway_address: leftNetwork.gateway_address, apply_status: leftNetwork.apply_status }],
        right_networks: [{ id: rightNetwork.id, name: rightNetwork.name, prefix: rightNetwork.desired_prefix, source: rightNetwork.source, address_family: rightNetwork.desired_prefix.includes(":") ? "ipv6" : "ipv4", publisher_device_id: rightNetwork.publisher_device_id, publisher_device_name: rightNetwork.publisher_device_name, gateway_address: rightNetwork.gateway_address, apply_status: rightNetwork.apply_status }],
        static_routes: [
          { router_site_id: left.id, destination_site_id: right.id, router_site_name: left.name, destination_site_name: right.name, destination_prefix: rightNetwork.desired_prefix, next_hop: "192.168.1.2", router_confirmed: false },
          { router_site_id: right.id, destination_site_id: left.id, router_site_name: right.name, destination_site_name: left.name, destination_prefix: leftNetwork.desired_prefix, next_hop: "10.20.0.2", router_confirmed: false },
        ],
        route_statuses: [
          { network_id: rightNetwork.id, router_site_id: left.id, destination_site_id: right.id, destination_prefix: rightNetwork.desired_prefix, address_family: rightNetwork.desired_prefix.includes(":") ? "ipv6" : "ipv4", device_status: "pending", control_plane_status: "pending", remote_status: "pending", error: null, checked_at: null },
          { network_id: leftNetwork.id, router_site_id: right.id, destination_site_id: left.id, destination_prefix: leftNetwork.desired_prefix, address_family: leftNetwork.desired_prefix.includes(":") ? "ipv6" : "ipv4", device_status: "pending", control_plane_status: "pending", remote_status: "pending", error: null, checked_at: null },
        ],
        enabled: true, apply_status: "checking", apply_error: null, health_status: "degraded", health_error: null, deletion_pending: false,
        route_confirmations: [] as { site_id: string; confirmed_at: number }[],
      };
      state.links.push(created); await fulfillJson(route, created, 201); return;
    }
    if (/^\/api\/v1\/site-links\/[^/]+$/.test(path) && method === "PATCH") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const link = state.links.find((item) => item.id === id);
      if (!link) { await fulfillJson(route, { error: "站点互联不存在" }, 404); return; }
      const body = request.postDataJSON() as { left_network_ids?: string[]; right_network_ids?: string[]; left_network_id?: string; right_network_id?: string; next_hops?: unknown };
      const leftId = body.left_network_ids?.[0] ?? body.left_network_id ?? link.left_network_id;
      const rightId = body.right_network_ids?.[0] ?? body.right_network_id ?? link.right_network_id;
      const leftNetwork = state.networks.find((item) => item.id === leftId)!;
      const rightNetwork = state.networks.find((item) => item.id === rightId)!;
      Object.assign(link, body, {
        left_network_id: leftId,
        right_network_id: rightId,
        left_network_prefix: leftNetwork.desired_prefix,
        right_network_prefix: rightNetwork.desired_prefix,
        apply_status: "checking",
        health_status: "degraded",
        route_confirmations: [],
      });
      await fulfillJson(route, link); return;
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
      const created = { ...seedTunnel, ...body, id: `tunnel-${state.tunnels.length + 1}`, device_name: device.name, enabled: true, apply_status: "checking", deletion_pending: false, public_address: null };
      state.tunnels.push(created); await fulfillJson(route, created, 201); return;
    }
    if (path === "/api/v1/tunnels/batch/device" && method === "PUT") {
      const body = request.postDataJSON() as { tunnel_ids: string[]; device_id: string };
      const target = state.devices.find((item) => item.id === body.device_id);
      if (!target) { await fulfillJson(route, { error: "目标设备不存在" }, 404); return; }
      const seen = new Set<string>();
      const ids = body.tunnel_ids.filter((id) => !seen.has(id) && seen.add(id));
      const updated = [] as typeof state.tunnels;
      const skipped = [] as { id: string; reason: string }[];
      for (const id of ids) {
        const tunnel = state.tunnels.find((item) => item.id === id);
        if (!tunnel) { await fulfillJson(route, { error: `穿透服务 ${id} 不存在` }, 404); return; }
        if (tunnel.device_id === target.id) {
          skipped.push({ id, reason: "已属于目标设备" });
          continue;
        }
        const enabled = Boolean(tunnel.device_id) && tunnel.enabled;
        tunnel.device_id = target.id;
        tunnel.device_name = target.name;
        tunnel.enabled = enabled;
        tunnel.apply_status = enabled ? "checking" : "disabled";
        updated.push(tunnel);
      }
      await fulfillJson(route, { updated, affected_count: updated.length, skipped, message: `已更换 ${updated.length} 个穿透服务的设备，跳过 ${skipped.length} 项` }); return;
    }
    if (/^\/api\/v1\/tunnels\/batch\/(enable|disable)$/.test(path) && method === "POST") {
      const enabled = path.endsWith("/enable");
      const body = request.postDataJSON() as { tunnel_ids: string[] };
      const seen = new Set<string>();
      const ids = body.tunnel_ids.filter((id) => !seen.has(id) && seen.add(id));
      const updated = [] as typeof state.tunnels;
      const skipped = [] as { id: string; reason: string }[];
      for (const id of ids) {
        const tunnel = state.tunnels.find((item) => item.id === id);
        if (!tunnel) { await fulfillJson(route, { error: `穿透服务 ${id} 不存在` }, 404); return; }
        if (enabled && !tunnel.device_id) {
          skipped.push({ id, reason: "未分配设备，请先更换设备" });
          continue;
        }
        if (tunnel.enabled === enabled) {
          skipped.push({ id, reason: enabled ? "已经启用" : "已经停用" });
          continue;
        }
        tunnel.enabled = enabled;
        tunnel.apply_status = enabled ? "checking" : "disabled";
        updated.push(tunnel);
      }
      await fulfillJson(route, { updated, affected_count: updated.length, skipped, message: `已${enabled ? "启用" : "停用"} ${updated.length} 个穿透服务，跳过 ${skipped.length} 项` }); return;
    }
    if (path === "/api/v1/tunnels/batch" && method === "DELETE") {
      const body = request.postDataJSON() as { tunnel_ids: string[] };
      const seen = new Set<string>();
      const ids = body.tunnel_ids.filter((id) => !seen.has(id) && seen.add(id));
      if (ids.some((id) => !state.tunnels.some((tunnel) => tunnel.id === id))) {
        await fulfillJson(route, { error: "穿透服务不存在" }, 404); return;
      }
      state.tunnels = state.tunnels.filter((tunnel) => !ids.includes(tunnel.id));
      await fulfillJson(route, { deleted_ids: ids, affected_count: ids.length, message: `已永久删除 ${ids.length} 个穿透服务，公网入口已停止` }); return;
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
    if (/^\/api\/v1\/site-links\/[^/]+$/.test(path) && method === "DELETE") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const link = state.links.find((item) => item.id === id);
      if (!link) { await fulfillJson(route, { error: "站点互联不存在" }, 404); return; }
      link.enabled = false; link.apply_status = "checking"; link.deletion_pending = true;
      await fulfillJson(route, { deleted: false, pending: true, id, message: "已请求删除站点互联，等待两侧 Agent 与 Headscale 完成路由撤销" }); return;
    }
    if (/^\/api\/v1\/site-networks\/[^/]+$/.test(path) && method === "DELETE") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const network = state.networks.find((item) => item.id === id);
      if (!network) { await fulfillJson(route, { error: "共享网络不存在" }, 404); return; }
      const references = state.links.filter((item) => item.left_network_id === id || item.right_network_id === id).length;
      if (references) { await fulfillJson(route, { error: `共享网络仍被 ${references} 个互联关系引用，请先删除互联关系` }, 409); return; }
      network.enabled = false; network.apply_status = "checking"; network.deletion_pending = true;
      await fulfillJson(route, { deleted: false, pending: true, id, message: "已请求删除共享网络，等待 Agent 与 Headscale 完成路由撤销" }); return;
    }
    if (/^\/api\/v1\/tunnels\/[^/]+$/.test(path) && method === "DELETE") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const index = state.tunnels.findIndex((item) => item.id === id);
      if (index < 0) { await fulfillJson(route, { error: "穿透服务不存在" }, 404); return; }
      if (options.tunnelDeleteDelayMs) {
        await new Promise((resolve) => setTimeout(resolve, options.tunnelDeleteDelayMs));
      }
      if (failTunnelDelete) { failTunnelDelete = false; await fulfillJson(route, { error: "模拟穿透服务删除失败" }, 503); return; }
      state.tunnels.splice(index, 1);
      await fulfillJson(route, { deleted: true, pending: false, id, message: "穿透服务已永久删除" }); return;
    }
    if (/^\/api\/v1\/devices\/[^/]+$/.test(path) && method === "PUT") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const body = request.postDataJSON() as { name: string; site_id: string | null };
      const device = state.devices.find((item) => item.id === id);
      if (!device) { await fulfillJson(route, { error: "设备不存在" }, 404); return; }
      if (body.site_id && !state.sites.some((site) => site.id === body.site_id)) {
        await fulfillJson(route, { error: "目标站点不存在" }, 404); return;
      }
      device.name = body.name;
      device.site_id = body.site_id;
      for (const network of state.networks) {
        if (network.publisher_device_id === id) network.publisher_device_name = device.name;
      }
      for (const tunnel of state.tunnels) {
        if (tunnel.device_id === id) tunnel.device_name = device.name;
      }
      await fulfillJson(route, { ...device, tunnel_count: state.tunnels.filter((tunnel) => tunnel.device_id === device.id).length }); return;
    }
    if (/^\/api\/v1\/devices\/[^/]+$/.test(path) && method === "DELETE") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const tunnelIds = state.tunnels.filter((item) => item.device_id === id).map((item) => item.id);
      const networkCount = state.networks.filter((item) => item.publisher_device_id === id).length;
      if (networkCount) { await fulfillJson(route, { error: "设备仍关联共享网络，请先完成删除" }, 409); return; }
      for (const tunnel of state.tunnels) {
        if (!tunnelIds.includes(tunnel.id)) continue;
        tunnel.device_id = null;
        tunnel.device_name = null;
        tunnel.enabled = false;
        tunnel.apply_status = "disabled";
      }
      state.devices = state.devices.filter((item) => item.id !== id);
      await fulfillJson(route, { deleted: true, pending: false, id, message: `设备已删除，${tunnelIds.length} 个穿透服务已保留为未分配并关闭；原 Agent 需要重新入网才能连接` }); return;
    }
    if (/^\/api\/v1\/sites\/[^/]+$/.test(path) && method === "DELETE") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const dependencies = state.devices.filter((item) => item.site_id === id).length + state.networks.filter((item) => item.site_id === id).length + state.links.filter((item) => item.left_site_id === id || item.right_site_id === id).length;
      if (dependencies) { await fulfillJson(route, { error: "站点仍关联设备、共享网络或互联关系，请按顺序先完成删除" }, 409); return; }
      state.sites = state.sites.filter((item) => item.id !== id);
      await fulfillJson(route, { deleted: true, pending: false, id, message: "站点已删除" }); return;
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

test("穿透服务访问地址支持安全跳转与复制", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await installApiMocks(page, {
    initialized: true,
    authenticated: true,
    tunnels: [
      seedTunnel,
      { ...seedTunnel, id: "tunnel-tcp", name: "远程终端", protocol: "tcp", public_port: 22022, hostname: null, origin_protocol: null, public_address: "公网地址:22022" },
      { ...seedTunnel, id: "tunnel-pending", name: "待生效服务", apply_status: "applying", public_address: null },
      { ...seedTunnel, id: "tunnel-invalid", name: "异常地址", protocol: "https", public_address: "javascript:alert(1)" },
    ],
  });
  await page.goto("/#/public-access/tunnels");

  const webRow = page.locator(".tunnel-row").filter({ hasText: "媒体中心" });
  await expect(webRow.getByText("访问地址", { exact: true })).toBeVisible();
  const webLink = webRow.getByRole("link", { name: "https://media.nexo.example.com" });
  await expect(webLink).toHaveAttribute("href", "https://media.nexo.example.com");
  await expect(webLink).toHaveAttribute("target", "_blank");
  await expect(webLink).toHaveAttribute("rel", "noopener noreferrer");
  await webRow.getByRole("button", { name: "复制媒体中心的访问地址" }).click();
  await expect(webRow.getByRole("button", { name: "媒体中心的访问地址已复制" })).toBeVisible();
  await expect(webRow.getByRole("status")).toHaveText("访问地址已复制");
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe("https://media.nexo.example.com");

  const tcpRow = page.locator(".tunnel-row").filter({ hasText: "远程终端" });
  await expect(tcpRow.getByRole("link")).toHaveCount(0);
  await tcpRow.getByRole("button", { name: "复制远程终端的访问地址" }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe("公网地址:22022");

  const pendingRow = page.locator(".tunnel-row").filter({ hasText: "待生效服务" });
  await expect(pendingRow.getByText("等待配置生效", { exact: true })).toBeVisible();
  await expect(pendingRow.getByRole("link")).toHaveCount(0);
  await expect(pendingRow.getByRole("button", { name: /复制.*访问地址/ })).toHaveCount(0);

  const invalidRow = page.locator(".tunnel-row").filter({ hasText: "异常地址" });
  await expect(invalidRow.getByRole("link")).toHaveCount(0);
  await expectNoHorizontalOverflow(page);
});

test("复制访问地址失败时显示中文错误", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: () => Promise.reject(new Error("denied")) },
    });
  });
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/public-access/tunnels");
  await page.getByRole("button", { name: "复制媒体中心的访问地址" }).click();
  await expect(page.getByRole("alert")).toHaveText("浏览器无法访问剪贴板，请手动选择访问地址复制。");
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
  const sitesTab = page.getByRole("tab", { name: "站点与网段" });
  if ((page.viewportSize()?.width ?? 1440) > 900) await sitesTab.click();
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
  expect(compose).toContain("ghcr.io/thelinyue/nexo-agent:0.1.7");
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

test("穿透服务永久删除支持取消、失败重试与即时移除", async ({ page }) => {
  await installApiMocks(page, {
    initialized: true,
    authenticated: true,
    failFirstTunnelDelete: true,
    tunnelDeleteDelayMs: 250,
  });
  let deleteRequestCount = 0;
  page.on("request", (request) => {
    if (request.method() === "DELETE" && new URL(request.url()).pathname === "/api/v1/tunnels/tunnel-media") {
      deleteRequestCount += 1;
    }
  });
  await page.goto("/#/public-access/tunnels");
  const row = page.locator(".tunnel-row").filter({ hasText: "媒体中心" });
  const deleteTrigger = row.getByRole("button", { name: "删除穿透服务媒体中心" });

  await deleteTrigger.click();
  let dialog = page.getByRole("alertdialog", { name: "删除穿透服务" });
  await expect(dialog).toContainText("设备离线不影响删除；设备下次连接时会自动清理旧配置");
  await expect(dialog.getByRole("button", { name: "取消" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(deleteTrigger).toBeFocused();
  await expect(row).toBeVisible();

  await deleteTrigger.click();
  dialog = page.getByRole("alertdialog", { name: "删除穿透服务" });
  const confirmDelete = dialog.locator('button[type="submit"]');
  await confirmDelete.click();
  await expect(confirmDelete).toHaveText("删除中…");
  await expect(confirmDelete).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("alert")).toHaveText("模拟穿透服务删除失败");
  await expect(row).toBeVisible();
  await expect(confirmDelete).toBeEnabled();
  await confirmDelete.click();

  await expect(dialog).toBeHidden();
  await expect(row).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: "穿透服务已永久删除" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "0 个穿透服务" })).toBeFocused();
  await expect(page.getByText("还没有穿透服务", { exact: true })).toBeVisible();
  expect(deleteRequestCount).toBe(2);
  await expectNoHorizontalOverflow(page);
});

test("内网穿透支持全选半选与四种批量操作", async ({ page }) => {
  const batchTunnels: Array<typeof seedTunnel> = [
    structuredClone(seedTunnel),
    { ...structuredClone(seedTunnel), id: "tunnel-office", device_id: "device-office", device_name: "办公室网关", name: "办公室服务", enabled: false, apply_status: "disabled", public_address: "https://office.nexo.example.com" },
    { ...structuredClone(seedTunnel), id: "tunnel-unassigned", device_id: null, device_name: null, name: "未分配服务", enabled: false, apply_status: "disabled", public_address: null },
  ];
  await installApiMocks(page, { initialized: true, authenticated: true, tunnels: batchTunnels });
  await page.goto("/#/public-access/tunnels");

  const selectAll = page.getByRole("checkbox", { name: "全选穿透服务" });
  const first = page.getByRole("checkbox", { name: "选择穿透服务媒体中心" });
  const second = page.getByRole("checkbox", { name: "选择穿透服务办公室服务" });
  const third = page.getByRole("checkbox", { name: "选择穿透服务未分配服务" });
  const toolbar = page.getByRole("toolbar", { name: "穿透服务批量操作" });
  await first.check();
  await expect(selectAll).not.toBeChecked();
  await expect(selectAll).toHaveJSProperty("indeterminate", true);
  await second.check();
  await third.check();
  await expect(selectAll).toBeChecked();

  await toolbar.getByRole("button", { name: "启用", exact: true }).click();
  await expect(page.getByText("已启用 1 个穿透服务，跳过 2 项", { exact: true })).toBeVisible();
  await expect(first).toBeChecked();
  await expect(second).not.toBeChecked();
  await expect(third).toBeChecked();
  await expect(toolbar.getByText("已选 2 项", { exact: true })).toBeVisible();
  const toolbarHeights = await toolbar.getByRole("button").evaluateAll((buttons) => buttons.map((button) => button.getBoundingClientRect().height));
  expect(toolbarHeights.every((height) => height >= 44)).toBe(true);

  const replaceTrigger = toolbar.getByRole("button", { name: "更换设备", exact: true });
  await replaceTrigger.click();
  const replaceDialog = page.getByRole("dialog", { name: "批量更换设备" });
  await replaceDialog.getByLabel("目标设备").selectOption("device-office");
  await replaceDialog.getByRole("button", { name: "更换设备", exact: true }).click();
  await expect(replaceDialog).toBeHidden();
  await expect(page.getByRole("heading", { name: "3 个穿透服务" })).toBeFocused();
  await expect(page.locator(".tunnel-row").filter({ hasText: "未分配服务" })).toContainText("办公室网关");
  await expect(toolbar).toHaveCount(0);

  await selectAll.check();
  await toolbar.getByRole("button", { name: "停用", exact: true }).click();
  await expect(page.getByText("已停用 2 个穿透服务，跳过 1 项", { exact: true })).toBeVisible();
  await selectAll.check();

  const deleteTrigger = toolbar.getByRole("button", { name: "删除", exact: true });
  await deleteTrigger.click();
  const deleteDialog = page.getByRole("alertdialog", { name: "批量删除穿透服务" });
  await expect(deleteDialog).toContainText("永久删除 3 个穿透服务");
  await deleteDialog.getByRole("button", { name: "永久删除" }).click();
  await expect(deleteDialog).toBeHidden();
  await expect(page.getByRole("heading", { name: "0 个穿透服务" })).toBeFocused();
  await expect(page.getByText("还没有穿透服务", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("已添加设备支持编辑名称与所属站点", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/devices/list");
  const row = page.locator(".device-row").filter({ hasText: "家庭网关" });
  const editTrigger = row.getByRole("button", { name: "编辑设备家庭网关" });
  await editTrigger.click();
  const dialog = page.getByRole("dialog", { name: "编辑设备" });
  await dialog.getByLabel("设备名称").fill("家庭 NAS");
  await dialog.getByLabel("所属站点").selectOption("site-office");
  await dialog.getByRole("button", { name: "保存修改" }).click();
  await expect(dialog).toBeHidden();
  const updatedRow = page.locator(".device-row").filter({ hasText: "家庭 NAS" });
  await expect(updatedRow).toContainText("办公室");
  await expect(updatedRow.getByRole("button", { name: "编辑设备家庭 NAS" })).toBeFocused();
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

test("多域名列表展示证书生命周期并支持批量与手动申请", async ({ page }) => {
  const rateLimitedDomain = {
    ...structuredClone(seedPublicDomain),
    id: "domain-rate-limited",
    domain: "rate.example.com",
    is_primary: false,
    apply_status: "rate_limited",
    apply_error: "CA 返回 HTTP 429",
    error_code: "acme_rate_limited",
    root_certificate: { ...seedPublicDomain.root_certificate, status: "pending", not_before: null, not_after: null, renewal_at: null, subjects: [] },
    wildcard_certificate: { ...seedPublicDomain.wildcard_certificate, status: "pending", not_before: null, not_after: null, renewal_at: null, subjects: [] },
    usage_count: 0,
    retry_after: 1893000000,
    next_retry_at: 1893000000,
    attempt_count: 3,
  };
  const manualDomain = {
    ...structuredClone(seedPublicDomain),
    id: "domain-manual",
    domain: "manual.example.net",
    is_primary: false,
    certificate_mode: "manual",
    root_certificate: { ...seedPublicDomain.root_certificate, renewal_at: null },
    wildcard_certificate: { ...seedPublicDomain.wildcard_certificate, renewal_at: null },
    usage_count: 0,
  };
  await installApiMocks(page, {
    initialized: true,
    authenticated: true,
    publicDomains: [seedPublicDomain, rateLimitedDomain, manualDomain],
  });
  await page.goto("/#/public-access/domain");

  const primaryRow = page.locator(".domain-row").filter({ hasText: "example.com" }).first();
  await expect(primaryRow).toContainText("主域名");
  await expect(primaryRow).toContainText("到期时间");
  await expect(primaryRow).toContainText("预计进入 Caddy 续期窗口");
  const limitedRow = page.locator(".domain-row").filter({ hasText: "rate.example.com" });
  await expect(limitedRow.getByRole("button", { name: "手动申请证书" })).toBeDisabled();
  await limitedRow.locator("summary").click();
  await expect(limitedRow).toContainText("Caddy 正在自动重试");
  await expect(limitedRow).toContainText("下一次尝试");

  await page.getByRole("checkbox", { name: "全选公网域名" }).check();
  const batchRecheck = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/v1/public-domains/batch/recheck");
  await page.getByRole("button", { name: "批量重新检测" }).click();
  expect((await batchRecheck).postDataJSON()).toEqual({ ids: ["domain-primary", "domain-rate-limited", "domain-manual"] });
  await expect(page.getByRole("status")).toContainText("已重新检测 3 个域名");

  const singleRenew = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/v1/public-domains/domain-primary/renew");
  await primaryRow.getByRole("button", { name: "手动申请证书" }).click();
  await singleRenew;
  await expect(page.getByRole("status")).toContainText("已请求 Caddy 处理 example.com 的证书");

  const manualRow = page.locator(".domain-row").filter({ hasText: "manual.example.net" });
  await manualRow.getByRole("button", { name: "更新证书" }).click();
  const dialog = page.getByRole("dialog", { name: "编辑 manual.example.net" });
  await expect(dialog.getByLabel("证书文件")).toBeVisible();
  await expect(dialog.getByLabel("私钥文件")).toBeVisible();
  await dialog.getByRole("button", { name: "取消" }).click();
  await expect(dialog).toBeHidden();
  await expectNoHorizontalOverflow(page);
});

test("网关能力按地址族展示并禁用不可转发网段", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/devices/list");
  await expect(page.locator(".device-row").filter({ hasText: "家庭网关" })).toContainText("共享网络 IPv4 可用");
  await expect(page.locator(".device-row").filter({ hasText: "办公室网关" })).toContainText("共享网络 IPv4/IPv6 可用");
  await expect(page.locator(".device-row").filter({ hasText: "IPv6 网关" })).toContainText("共享网络 IPv6 可用");

  await page.goto("/#/networks");
  const sitesTab = page.getByRole("tab", { name: "站点与网段" });
  if ((page.viewportSize()?.width ?? 1440) > 900) await sitesTab.click();
  await page.getByRole("button", { name: "展开家庭" }).click();
  const home = page.locator(".network-site").filter({ has: page.locator(".network-site-identity").getByText("家庭", { exact: true }) });
  await home.getByRole("button", { name: "添加共享网络" }).click();
  let dialog = page.getByRole("dialog", { name: "添加共享网络" });
  await dialog.getByLabel("网关设备").selectOption("device-home");
  const networkSelect = dialog.getByLabel("本地网络");
  await expect(networkSelect.locator("option")).toHaveText([
    "选择已探测网段",
    "192.168.1.0/24 · eth0",
    "2001:db8:1::/64 · eth1 · 需开启 IPv6 转发",
  ]);
  await expect(networkSelect.locator("option").nth(2)).toHaveAttribute("disabled", "");
  await networkSelect.focus();
  await page.keyboard.press("ArrowDown");
  await expect(networkSelect).toHaveValue("eth0|192.168.1.0/24");
  await page.keyboard.press("ArrowDown");
  await expect(networkSelect).toHaveValue("eth0|192.168.1.0/24");
  await dialog.getByRole("button", { name: "取消" }).click();

  await home.getByRole("button", { name: "添加共享网络" }).click();
  dialog = page.getByRole("dialog", { name: "添加共享网络" });
  await dialog.getByRole("radio", { name: "手动填写" }).click();
  await dialog.getByLabel("显示名称", { exact: true }).fill("访客手动网段");
  await dialog.getByLabel("网关设备").selectOption("device-home");
  const manualCidr = dialog.getByLabel("共享 CIDR");
  await manualCidr.fill("192.168.50.1/33");
  await manualCidr.blur();
  await expect(dialog.locator(".field-error")).toHaveText("不能使用默认路由或无效前缀长度");
  await expect(dialog.getByLabel("显示名称", { exact: true })).toHaveValue("访客手动网段");
  await manualCidr.fill("192.168.50.9/24");
  await manualCidr.blur();
  await dialog.getByRole("button", { name: "创建共享网络" }).click();
  await expect(dialog).toBeHidden();
  await expect(home.getByText("访客手动网段", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("网络互联按站点展开、锁定来源并同步呈现双端关系", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, failFirstNetworkCreate: true, failFirstLinkCreate: true });
  await page.goto("/#/networks");
  const sitesTab = page.getByRole("tab", { name: "站点与网段" });
  if ((page.viewportSize()?.width ?? 1440) > 900) await sitesTab.click();
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
  await dialog.getByLabel("目标站点").selectOption("site-office");
  await dialog.getByLabel("左侧 Site Gateway").selectOption("device-home");
  await dialog.getByLabel("右侧 Site Gateway").selectOption("device-office");
  await dialog.getByRole("button", { name: "下一步" }).click();
  await dialog.locator(".network-checklist").nth(0).getByRole("checkbox").first().check();
  await dialog.locator(".network-checklist").nth(1).getByRole("checkbox").first().check();
  await dialog.getByRole("button", { name: "下一步" }).click();
  await dialog.getByRole("button", { name: "建立站点互联" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("模拟站点互联创建失败");
  await expect(dialog.getByLabel("左侧 IPv4 下一跳")).toHaveValue("192.168.1.1");
  await expect(dialog.getByLabel("右侧 IPv4 下一跳")).toHaveValue("10.20.0.1");
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

test("桌面拓扑支持键盘节点、连线和逐阶段详情", async ({ page }) => {
  test.skip((page.viewportSize()?.width ?? 1440) <= 900, "拓扑只在桌面端呈现");
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/networks");
  const topology = page.locator(".network-topology");
  await expect(topology).toBeVisible();
  const node = page.getByRole("button", { name: "查看站点家庭" });
  await node.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("tab", { name: "站点与网段" })).toHaveAttribute("aria-selected", "true");
  await page.getByRole("tab", { name: "互联拓扑" }).click();
  const link = page.getByRole("button", { name: "查看家庭与办公室的互联" });
  await link.focus();
  await page.keyboard.press("Enter");
  await expect(topology.locator(".topology-detail")).toContainText("设备已发布");
  await expect(topology.locator(".topology-detail")).toContainText("路由服务中");
  await expectNoHorizontalOverflow(page);
});

test("移动端关系列表通过底部面板展示互联状态", async ({ page }) => {
  test.skip((page.viewportSize()?.width ?? 1440) > 900, "仅验证移动端关系列表");
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/networks");
  await expect(page.locator(".network-topology")).toBeHidden();
  const home = page.locator(".network-site").filter({ has: page.locator(".network-site-identity").getByText("家庭", { exact: true }) });
  await home.getByRole("button", { name: "展开家庭" }).click();
  await home.locator(".site-link-card").getByRole("button", { name: "查看详情" }).click();
  const detail = page.locator(".mobile-site-link-detail");
  await expect(detail).toBeVisible();
  await expect(detail).toContainText("设备已发布");
  await expect(detail).toContainText("对端已接受");
  await detail.getByRole("button", { name: "关闭互联详情" }).click();
  await expect(detail).toBeHidden();
  await expectNoHorizontalOverflow(page);
});

test("站点保持页内创建，设置支持会话撤销与改密重登", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/networks");
  await page.getByRole("button", { name: "新建站点" }).click();
  await page.getByLabel("站点名称").fill("门店");
  await page.getByRole("button", { name: "创建站点" }).click();
  const sitesTab = page.getByRole("tab", { name: "站点与网段" });
  if ((page.viewportSize()?.width ?? 1440) > 900) await sitesTab.click();
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

test("取消删除确认时保留设备", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/devices/list");
  const row = page.locator(".device-row").filter({ hasText: "家庭网关" });
  await row.getByRole("button", { name: "删除设备家庭网关" }).click();
  const dialog = page.getByRole("alertdialog", { name: "删除设备" });
  await expect(dialog).toContainText("穿透服务将保留为未分配并关闭");
  await dialog.getByRole("button", { name: "取消" }).click();
  await expect(row).toBeVisible();
});

test("按互联关系到站点的固定顺序完成安全删除", async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "等待删除轮询流程只需在一个浏览器项目中验证");
  await installApiMocks(page, { initialized: true, authenticated: true });
  page.on("dialog", (dialog) => void dialog.accept());
  await page.goto("/#/networks");
  await page.getByRole("tab", { name: "站点与网段" }).click();
  const home = page.locator(".network-site").filter({ has: page.locator(".network-site-identity").getByText("家庭", { exact: true }) });
  await home.getByRole("button", { name: "展开家庭" }).click();

  await home.getByRole("button", { name: "删除站点家庭" }).click();
  await expect(page.getByRole("alert")).toContainText("站点仍关联设备、共享网络或互联关系");
  await home.getByRole("button", { name: "删除共享网络家庭局域网" }).click();
  await expect(page.getByRole("alert")).toContainText("共享网络仍被 1 个互联关系引用");

  await home.getByRole("button", { name: "删除家庭到办公室的站点互联" }).click();
  await expect(page.getByRole("status").filter({ hasText: "已请求删除站点互联" })).toBeVisible();
  await expect(home.getByRole("button", { name: "删除家庭到办公室的站点互联" })).toBeDisabled();
  await expect(home.locator(".site-link-card")).toHaveCount(0, { timeout: 7_000 });

  await home.getByRole("button", { name: "删除共享网络家庭局域网" }).click();
  await expect(home.getByText("等待删除", { exact: true }).first()).toBeVisible();
  await expect(home.locator(".network-row")).toHaveCount(0, { timeout: 7_000 });

  await navigatePrimary(page, "公网访问");
  const tunnelRow = page.locator(".tunnel-row").filter({ hasText: "媒体中心" });
  await tunnelRow.getByRole("button", { name: "删除穿透服务媒体中心" }).click();
  await page.getByRole("alertdialog", { name: "删除穿透服务" }).getByRole("button", { name: "永久删除" }).click();
  await expect(tunnelRow).toHaveCount(0);

  await navigatePrimary(page, "设备");
  const deviceRow = page.locator(".device-row").filter({ hasText: "家庭网关" });
  await deviceRow.getByRole("button", { name: "删除设备家庭网关" }).click();
  await page.getByRole("alertdialog", { name: "删除设备" }).getByRole("button", { name: "永久删除" }).click();
  await expect(deviceRow).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: "设备已删除" })).toBeVisible();
  const ipv6DeviceRow = page.locator(".device-row").filter({ hasText: "IPv6 网关" });
  await ipv6DeviceRow.getByRole("button", { name: "删除设备IPv6 网关" }).click();
  await page.getByRole("alertdialog", { name: "删除设备" }).getByRole("button", { name: "永久删除" }).click();
  await expect(ipv6DeviceRow).toHaveCount(0);

  await navigatePrimary(page, "网络互联");
  await page.getByRole("tab", { name: "站点与网段" }).click();
  const emptyHome = page.locator(".network-site").filter({ has: page.locator(".network-site-identity").getByText("家庭", { exact: true }) });
  await emptyHome.getByRole("button", { name: "删除站点家庭" }).click();
  await expect(emptyHome).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: "站点已删除" })).toBeVisible();
});

test("站点图标居中且删除与展开按钮保持稳定点击区", async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "视口与主题矩阵只需在一个浏览器项目中验证");
  const cases = [
    { viewport: { width: 1440, height: 900 }, isMobile: false },
    { viewport: { width: 375, height: 812 }, isMobile: true },
    { viewport: { width: 812, height: 375 }, isMobile: true },
  ];

  for (const colorScheme of ["light", "dark"] as const) {
    for (const current of cases) {
      const context = await browser.newContext({
        viewport: current.viewport,
        colorScheme,
        isMobile: current.isMobile,
        hasTouch: current.isMobile,
      });
      const page = await context.newPage();
      try {
        await installApiMocks(page, { initialized: true, authenticated: true });
        await page.goto("http://127.0.0.1:4173/#/networks");
        if (!current.isMobile) await page.getByRole("tab", { name: "站点与网段" }).click();
        const home = page.locator(".network-site").filter({ has: page.locator(".network-site-identity").getByText("家庭", { exact: true }) });
        const icon = home.locator(".site-icon");
        const alignment = await icon.evaluate((container) => {
          const svg = container.querySelector("svg")!;
          const outer = container.getBoundingClientRect();
          const inner = svg.getBoundingClientRect();
          return {
            display: getComputedStyle(container).display,
            x: Math.abs((outer.left + outer.width / 2) - (inner.left + inner.width / 2)),
            y: Math.abs((outer.top + outer.height / 2) - (inner.top + inner.height / 2)),
          };
        });
        expect(alignment.display).toBe("grid");
        expect(alignment.x).toBeLessThanOrEqual(1);
        expect(alignment.y).toBeLessThanOrEqual(1);

        for (const button of [
          home.getByRole("button", { name: "删除站点家庭" }),
          home.getByRole("button", { name: "展开家庭" }),
        ]) {
          const box = await button.boundingBox();
          expect(Math.abs((box?.width ?? 0) - 44)).toBeLessThanOrEqual(0.01);
          expect(Math.abs((box?.height ?? 0) - 44)).toBeLessThanOrEqual(0.01);
        }
        const deleteButton = home.getByRole("button", { name: "删除站点家庭" });
        await deleteButton.focus();
        await expect(deleteButton).toBeFocused();
        page.once("dialog", (dialog) => void dialog.dismiss());
        await deleteButton.press("Enter");
        await expect(home).toBeVisible();
        await expectNoHorizontalOverflow(page);
      } finally {
        await context.close();
      }
    }
  }
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
