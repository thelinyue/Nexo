import { expect, test, type Page, type Route } from "@playwright/test";
import { createServer, type AddressInfo } from "node:http";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

async function startPwaUpgradeServer() {
  type Mode = "legacy" | "current";
  let mode: Mode = "legacy";
  const distDir = resolve(process.cwd(), "dist");
  const currentServiceWorker = readFileSync(join(distDir, "sw.js"), "utf8");
  const legacyServiceWorker = `
const CACHE = "nexo-legacy-shell";
self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.add("/")));
});
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  if (event.request.mode === "navigate") {
    event.respondWith(caches.match("/").then((response) => response || fetch(event.request)));
  }
});
`;
  const legacyHtml = `<!doctype html><html><body><main id="legacy">legacy shell</main><script>
navigator.serviceWorker.register("/sw.js").then((registration) => registration.update());
</script></body></html>`;
  const currentOidcHtml = "<!doctype html><html><body><main id=\"oidc-reached\">OIDC server reached</main></body></html>";
  const server = createServer((request, response) => {
    const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
    const pathname = requestUrl.pathname;
    if (pathname === "/sw.js") {
      response.writeHead(200, { "content-type": "application/javascript", "cache-control": "no-store" });
      response.end(mode === "legacy" ? legacyServiceWorker : currentServiceWorker);
      return;
    }
    if (mode === "legacy") {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(legacyHtml);
      return;
    }
    if (pathname === "/api/v1/auth/status") {
      response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      response.end(JSON.stringify({
        initialized: true,
        authenticated: true,
        user_id: "fixture-user",
        username: "fixture",
        role: "system_admin",
        workspace_id: "default",
        channel: "public_https",
        csrf_token: "fixture-csrf",
        local_http_warning: false,
      }));
      return;
    }
    if (pathname === "/oidc/authorize") {
      response.writeHead(200, { "content-type": "text/html" });
      response.end(currentOidcHtml);
      return;
    }
    const filePath = pathname === "/" ? join(distDir, "index.html") : join(distDir, pathname.slice(1));
    if (existsSync(filePath)) {
      const contentType = pathname.endsWith(".js") ? "application/javascript"
        : pathname.endsWith(".css") ? "text/css"
          : pathname.endsWith(".json") ? "application/json"
            : pathname.endsWith(".png") ? "image/png"
              : "text/html";
      response.writeHead(200, { "content-type": contentType });
      response.end(readFileSync(filePath));
      return;
    }
    response.writeHead(404);
    response.end("not found");
  });
  await new Promise<void>((resolveServer) => server.listen(0, "127.0.0.1", resolveServer));
  const address = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${address.port}`,
    setMode: (nextMode: Mode) => { mode = nextMode; },
    close: () => new Promise<void>((resolveServer, reject) => server.close((error) => error ? reject(error) : resolveServer())),
  };
}

type MockOptions = {
  initialized: boolean;
  authenticated: boolean;
  tunnels?: Array<typeof seedTunnel>;
  failFirstTunnelCreate?: boolean;
  failFirstTunnelDelete?: boolean;
  tunnelDeleteDelayMs?: number;
  failFirstNetworkCreate?: boolean;
  failFirstPublicDomainUpdate?: boolean;
  failFirstNetworksLoad?: boolean;
  publicDomains?: Array<typeof seedPublicDomain>;
  meshRenamePending?: boolean;
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
    progress: { stage: "active", attempt_count: 1, last_event_at: 1890000000, next_retry_at: null, error_code: null, error_message: null },
  },
  wildcard_certificate: {
    status: "ready", not_before: 1890000000, not_after: 1893456000, renewal_at: 1892304000,
    subjects: ["example.com", "*.example.com"],
    progress: { stage: "active", attempt_count: 1, last_event_at: 1890000000, next_retry_at: null, error_code: null, error_message: null },
  },
  usage_count: 2,
  desired_revision: 4,
  applied_revision: 4,
  retry_after: null as number | null,
  attempt_count: 0,
  next_retry_at: null as number | null,
  dns_management: { enabled: true, target_ipv4: "203.0.113.10", target_ipv6: null, status: "ready", error: null, version: 1 },
  management_entry: "https://nexo.example.com",
  mesh_entry: "https://mesh.example.com",
  readiness_summary: { status: "ready", root_dns: "ready", wildcard_dns: "ready", https: "ready", management_entry: "ready", mesh_entry: "ready" },
};

const seedDevices = [
  {
    id: "device-home",
    tenant_id: "default",
    name: "家庭网关",
    os: "linux",
    architecture: "amd64",
    agent_version: "0.1.7",
    status: "online",
    connection_type: "nexo_agent",
    mesh_status: "connected",
    mesh_address: "100.64.0.2",
    mesh_name: "home-gateway",
    active_mesh_name: "home-gateway",
    mesh_fqdn: "home-gateway.mesh.example.internal",
    mesh_name_status: "ready",
    last_seen_at: 1893456000,
    gateway_report: {
      ipv4_forwarding: true,
      ipv6_forwarding: false,
      subnet_gateway: "ready",
      local_networks: [
        { interface_id: "eth0", prefix: "192.168.1.0/24", gateway_address: "192.168.1.1" },
        { interface_id: "eth0", prefix: "10.0.0.0/24", gateway_address: "10.0.0.1" },
        { interface_id: "eth1", prefix: "2001:db8:1::/64", gateway_address: "2001:db8:1::1" },
      ],
    },
  },
  {
    id: "device-office",
    tenant_id: "default",
    name: "办公室网关",
    os: "linux",
    architecture: "arm64",
    agent_version: "0.1.7",
    status: "online",
    connection_type: "nexo_agent",
    mesh_status: "connected",
    mesh_address: "100.64.0.3",
    mesh_name: "office-gateway",
    active_mesh_name: "office-gateway",
    mesh_fqdn: "office-gateway.mesh.example.internal",
    mesh_name_status: "ready",
    last_seen_at: 1893456000,
    gateway_report: {
      ipv4_forwarding: true,
      ipv6_forwarding: true,
      subnet_gateway: "ready",
      local_networks: [
        { interface_id: "enp1s0", prefix: "10.20.0.0/24", gateway_address: "10.20.0.1" },
        { interface_id: "enp2s0", prefix: "2001:db8:20::/64", gateway_address: "2001:db8:20::1" },
      ],
    },
  },
  {
    id: "device-v6",
    tenant_id: "default",
    name: "IPv6 网关",
    os: "linux",
    architecture: "amd64",
    agent_version: "0.1.7",
    status: "online",
    connection_type: "nexo_agent",
    mesh_status: "connected",
    mesh_address: "fd7a:115c:a1e0::4",
    mesh_name: "ipv6-gateway",
    active_mesh_name: "ipv6-gateway",
    mesh_fqdn: "ipv6-gateway.mesh.example.internal",
    mesh_name_status: "ready",
    last_seen_at: 1893456000,
    gateway_report: {
      ipv4_forwarding: false,
      ipv6_forwarding: true,
      subnet_gateway: "ready",
      local_networks: [
        { interface_id: "eth0", prefix: "192.168.2.0/24", gateway_address: "192.168.2.1" },
        { interface_id: "eth1", prefix: "2001:db8:2::/64", gateway_address: "2001:db8:2::1" },
      ],
    },
  },
];

const seedNetworks = [
  {
    id:"network-home",tenant_id:"default",name:"家庭局域网",
    publisher_device_name: "家庭网关", publisher_device_id: "device-home", interface_id: "eth0", source: "detected", gateway_address: "192.168.1.1",
    desired_prefix: "192.168.1.0/24", applied_prefix: "192.168.1.0/24", enabled: true, apply_status: "ready",
    apply_error: null, health_status: "ready", health_error: null, deletion_pending: false,
  },
  {
    id:"network-office",tenant_id:"default",name:"办公室局域网",
    publisher_device_name: "办公室网关", publisher_device_id: "device-office", interface_id: "enp1s0", source: "detected", gateway_address: "10.20.0.1",
    desired_prefix: "10.20.0.0/24", applied_prefix: "10.20.0.0/24", enabled: true, apply_status: "ready",
    apply_error: null, health_status: "ready", health_error: null, deletion_pending: false,
  },
  {
    id:"network-office-v6",tenant_id:"default",name:"办公室 IPv6",
    publisher_device_name: "办公室网关", publisher_device_id: "device-office", interface_id: "enp2s0", source: "detected", gateway_address: "2001:db8:20::1",
    desired_prefix: "2001:db8:20::/64", applied_prefix: "2001:db8:20::/64", enabled: true, apply_status: "ready",
    apply_error: null, health_status: "ready", health_error: null, deletion_pending: false,
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
  let failPublicDomainUpdate = Boolean(options.failFirstPublicDomainUpdate);
  let failNetworksLoad = Boolean(options.failFirstNetworksLoad);
  const meshRenamePending = Boolean(options.meshRenamePending);
  const state = {
    devices: structuredClone(seedDevices),
    networks: structuredClone(seedNetworks).map(n=>({...n,status_reason:"ready",updated_at:Math.floor(Date.now()/1000)})),
    tunnels: structuredClone(options.tunnels ?? [seedTunnel]),
    enrollments: [] as Record<string, unknown>[],
    sessions: [
      { id: "session-current", channel: "local_http", created_at: 1890000000, last_seen_at: 1891000000, expires_at: 1893456000 },
      { id: "session-other", channel: "public_https", created_at: 1889000000, last_seen_at: 1890000000, expires_at: 1893000000 },
    ],
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
      await fulfillJson(route, { initialized, authenticated, username: authenticated ? "admin" : null, role: authenticated ? "system_admin" : null, channel: authenticated ? "local_http" : null, csrf_token: authenticated ? "release-csrf" : null, local_http_warning: true });
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
    if (path === "/api/v1/enrollments" && method === "GET") { await fulfillJson(route, state.enrollments); return; }
    if (path === "/api/v1/mesh/status") { await fulfillJson(route, { status: "normal", message: "组网运行正常" }); return; }
    if (path === "/api/v1/mesh/client-config") { await fulfillJson(route, { login_server: "https://mesh.example.com", browser_authorization_url: null, supported_platforms: ["Linux", "Windows", "macOS", "iOS", "Android", "tvOS"], notes: [] }); return; }
    if (path === "/api/v1/mesh/external-nodes") { await fulfillJson(route, []); return; }
    if (path === "/api/v1/mesh/connections") {
      await fulfillJson(route, [{ client_device_id: "device-office", client_device_name: "办公室网关", gateway_device_id: "device-home", gateway_device_name: "家庭网关", site_network_id: "network-home", site_network_prefix: "192.168.1.0/24", connection_type: "direct", updated_at: 1893456000 }]); return;
    }
    if (path === "/api/v1/mesh/connection-checks" && method === "POST") { await fulfillJson(route, { id: "check-1", status: "queued" }, 202); return; }
    if (path === "/api/v1/mesh/connection-checks/check-1" && method === "GET") { await fulfillJson(route, { id: "check-1", status: "succeeded", connection_type: "direct" }); return; }
    if (path === "/api/v1/site-networks" && method === "GET") {
      if (failNetworksLoad) { failNetworksLoad = false; await fulfillJson(route, { error: "模拟网络互联加载失败" }, 503); return; }
      finishPendingDeletion("network", state.networks);
      await fulfillJson(route, state.networks); return;
    }
    if (path === "/api/v1/tunnels" && method === "GET") { await fulfillJson(route, state.tunnels); return; }
    if (supportsPublicDomains && path === "/api/v1/public-domains" && method === "GET") {
      await fulfillJson(route, state.publicDomains);
      return;
    }
    if (supportsPublicDomains && path === "/api/v1/public-domains" && method === "POST") {
      const body = request.postDataJSON() as Record<string, unknown>;
      const created = {
        ...structuredClone(seedPublicDomain),
        ...body,
        id: `domain-${state.publicDomains.length + 1}`,
        domain: String(body.domain),
        is_primary: state.publicDomains.length === 0,
        usage_count: 0,
        dns_management: {
          enabled: Boolean(body.dns_management_enabled),
          target_ipv4: body.dns_target_ipv4 || null,
          target_ipv6: body.dns_target_ipv6 || null,
          status: "pending",
          error: null,
          version: 0,
        },
      } as typeof seedPublicDomain;
      state.publicDomains.push(created);
      await fulfillJson(route, created, 201);
      return;
    }
    const publicDomainMatch = path.match(/^\/api\/v1\/public-domains\/([^/]+)$/);
    if (supportsPublicDomains && publicDomainMatch && method === "PUT") {
      if (failPublicDomainUpdate) { failPublicDomainUpdate = false; await fulfillJson(route, { error: "模拟域名与 HTTPS 设置失败" }, 422); return; }
      const domain = state.publicDomains.find((item) => item.id === decodeURIComponent(publicDomainMatch[1]));
      if (!domain) { await fulfillJson(route, { error: "域名不存在" }, 404); return; }
      const body = request.postDataJSON() as Record<string, unknown>;
      Object.assign(domain, body, {
        dns_management: {
          ...domain.dns_management,
          enabled: Boolean(body.dns_management_enabled),
          target_ipv4: body.dns_target_ipv4 || null,
          target_ipv6: body.dns_target_ipv6 || null,
        },
      });
      await fulfillJson(route, domain);
      return;
    }
    if (supportsPublicDomains && publicDomainMatch && method === "DELETE") {
      state.publicDomains = state.publicDomains.filter((item) => item.id !== decodeURIComponent(publicDomainMatch[1]));
      await fulfillJson(route, { deleted: true, pending: false, id: decodeURIComponent(publicDomainMatch[1]), message: "公网域名已删除" });
      return;
    }
    if (supportsPublicDomains && path === "/api/v1/public-domain-runtime-events" && method === "GET") {
      const selectedDomain = new URL(request.url()).searchParams.get("public_domain_id");
      const events = [
        { id: 3, public_domain_id: "domain-primary", domain: "example.com", level: "error", category: "automatic_certificate", stage: "retry_wait", summary: "证书申请暂未完成，系统将按计划自动重试", error_code: "acme_rate_limited", retry_at: 1893000000, technical_detail: "服务返回 HTTP 429，敏感信息已隐藏", occurred_at: 1892000000 },
        { id: 2, public_domain_id: null, domain: null, level: "info", category: "configuration", stage: null, summary: "域名服务配置已经更新", error_code: null, retry_at: null, technical_detail: null, occurred_at: 1891000000 },
      ].filter((event) => !selectedDomain || event.public_domain_id === selectedDomain);
      await fulfillJson(route, { events, next_cursor: null });
      return;
    }
    if (supportsPublicDomains && path === "/api/v1/public-domain-runtime-events/export" && method === "GET") {
      await route.fulfill({ status: 200, contentType: "application/json", body: "[]" });
      return;
    }
    const dnsPreviewMatch = path.match(/^\/api\/v1\/public-domains\/([^/]+)\/dns\/preview$/);
    if (supportsPublicDomains && dnsPreviewMatch && method === "GET") {
      const domain = state.publicDomains.find((item) => item.id === dnsPreviewMatch[1]);
      if (!domain) { await fulfillJson(route, { error: "域名不存在" }, 404); return; }
      await fulfillJson(route, { domain_id: domain.id, zone_name: domain.domain, has_conflicts: false, changes: [
        { action: "adopt", record_type: "A", name: "@", desired_content: domain.dns_management.target_ipv4, current_content: domain.dns_management.target_ipv4, record_id: "record-root" },
        { action: "adopt", record_type: "A", name: "*", desired_content: domain.dns_management.target_ipv4, current_content: domain.dns_management.target_ipv4, record_id: "record-wildcard" },
      ] });
      return;
    }
    const dnsApplyMatch = path.match(/^\/api\/v1\/public-domains\/([^/]+)\/dns\/apply$/);
    if (supportsPublicDomains && dnsApplyMatch && method === "POST") {
      const domain = state.publicDomains.find((item) => item.id === dnsApplyMatch[1]);
      if (!domain) { await fulfillJson(route, { error: "域名不存在" }, 404); return; }
      await fulfillJson(route, { domain_id: domain.id, zone_name: domain.domain, has_conflicts: false, changes: [] });
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
        .map((domain) => ({ id: domain.id, reason: "CA 限流窗口尚未结束，系统会自动重试" }));
      await fulfillJson(route, { updated, skipped, message: "已请求自动证书服务处理 " + updated.length + " 个域名，限流项将按官方退避自动重试" });
      return;
    }
    if (supportsPublicDomains && /^\/api\/v1\/public-domains\/[^/]+\/(recheck|renew)$/.test(path) && method === "POST") {
      const parts = path.split("/");
      const domain = state.publicDomains.find((item) => item.id === decodeURIComponent(parts.at(-2) ?? ""));
      if (!domain) { await fulfillJson(route, { error: "域名不存在" }, 404); return; }
      if (parts.at(-1) === "renew" && domain.apply_status === "rate_limited") {
        await fulfillJson(route, { error: "CA 限流窗口尚未结束，系统会自动重试" }, 429);
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
    if (supportsPublicDomains && /^\/api\/v1\/public-domains\/[^/]+\/manual-certificate$/.test(path) && method === "DELETE") {
      const domain = state.publicDomains.find((item) => item.id === decodeURIComponent(path.split("/").at(-2) ?? ""));
      if (!domain) { await fulfillJson(route, { error: "域名不存在" }, 404); return; }
      domain.apply_status = "error";
      domain.apply_error = "手动证书已删除，请上传新证书或明确切换到自动证书";
      await fulfillJson(route, domain);
      return;
    }
    if (path === "/api/v1/enrollments" && method === "POST") {
      state.enrollments=[{enrollment_id:"enrollment-release",status:"awaiting_approval",device_name:request.postDataJSON().device_name,os:"linux",architecture:"amd64",agent_version:"0.1.17",expires_at:1893456000}];
      await fulfillJson(route, { enrollment_id: "enrollment-release", token: "release-one-time-token", expires_at: 1893456000 }); return;
    }
    if (path === "/api/v1/enrollments/enrollment-release/approve" && method === "POST") {
      state.enrollments[0].status="consumed";
      await fulfillJson(route,{device_id:"new-agent"});return;
    }
    if (path === "/api/v1/site-networks" && method === "POST") {
      if (failNetworkCreate) { failNetworkCreate = false; await fulfillJson(route, { error: "模拟共享网络创建失败" }, 422); return; }
      const body = request.postDataJSON() as Record<string, string>;
      const device = state.devices.find((item) => item.id === body.publisher_device_id)!;
      const created = { id: `network-${state.networks.length + 1}`, ...body, publisher_device_name: device.name, desired_prefix: body.prefix, applied_prefix: null, gateway_address: null, enabled: true, apply_status: "checking", apply_error: null, health_status: "degraded", health_error: null, deletion_pending: false };
      state.networks.push(created); await fulfillJson(route, created, 201); return;
    }
    if (/^\/api\/v1\/devices\/[^/]+\/shared-networks$/.test(path) && method === "PUT") {
      const deviceId=path.split('/')[4];
      const body=request.postDataJSON();
      for(const item of body.networks) {
        const existing=state.networks.find(n=>n.id===item.id || n.publisher_device_id===deviceId && n.desired_prefix===item.prefix);
        if(existing) { if(existing.enabled !== item.enabled) Object.assign(existing,{enabled:item.enabled,apply_status:"checking",status_reason:"applying"}); }
        else if(item.enabled) state.networks.push({...seedNetworks[0],id:`new-${state.networks.length}`,publisher_device_id:deviceId,name:item.prefix,desired_prefix:item.prefix,interface_id:item.interface_id,apply_status:"checking"});
      }
      await fulfillJson(route,state.networks);return;
    }
    if (/^\/api\/v1\/site-networks\/[^/]+\/(enable|disable)$/.test(path) && method === "POST") {
      const parts = path.split("/");
      const network = state.networks.find((item) => item.id === decodeURIComponent(parts.at(-2) ?? ""))!;
      network.enabled = parts.at(-1) === "enable";
      network.apply_status = network.enabled ? "checking" : "disabled";
      await fulfillJson(route, network); return;
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
        if (!tunnel) { await fulfillJson(route, { error: `公网服务 ${id} 不存在` }, 404); return; }
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
      await fulfillJson(route, { updated, affected_count: updated.length, skipped, message: `已更换 ${updated.length} 个公网服务的设备，跳过 ${skipped.length} 项` }); return;
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
        if (!tunnel) { await fulfillJson(route, { error: `公网服务 ${id} 不存在` }, 404); return; }
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
      await fulfillJson(route, { updated, affected_count: updated.length, skipped, message: `已${enabled ? "启用" : "停用"} ${updated.length} 个公网服务，跳过 ${skipped.length} 项` }); return;
    }
    if (path === "/api/v1/tunnels/batch" && method === "DELETE") {
      const body = request.postDataJSON() as { tunnel_ids: string[] };
      const seen = new Set<string>();
      const ids = body.tunnel_ids.filter((id) => !seen.has(id) && seen.add(id));
      if (ids.some((id) => !state.tunnels.some((tunnel) => tunnel.id === id))) {
        await fulfillJson(route, { error: "公网服务不存在" }, 404); return;
      }
      state.tunnels = state.tunnels.filter((tunnel) => !ids.includes(tunnel.id));
      await fulfillJson(route, { deleted_ids: ids, affected_count: ids.length, message: `已永久删除 ${ids.length} 个公网服务，公网入口已停止` }); return;
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
    if (/^\/api\/v1\/site-networks\/[^/]+$/.test(path) && method === "DELETE") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const network = state.networks.find((item) => item.id === id);
      if (!network) { await fulfillJson(route, { error: "共享网络不存在" }, 404); return; }
      network.enabled = false; network.apply_status = "checking"; network.deletion_pending = true;
      await fulfillJson(route, { deleted: false, pending: true, id, message: "已请求删除共享网络，等待 Agent 与 Headscale 完成路由撤销" }); return;
    }
    if (/^\/api\/v1\/tunnels\/[^/]+$/.test(path) && method === "DELETE") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const index = state.tunnels.findIndex((item) => item.id === id);
      if (index < 0) { await fulfillJson(route, { error: "公网服务不存在" }, 404); return; }
      if (options.tunnelDeleteDelayMs) {
        await new Promise((resolve) => setTimeout(resolve, options.tunnelDeleteDelayMs));
      }
      if (failTunnelDelete) { failTunnelDelete = false; await fulfillJson(route, { error: "模拟公网服务删除失败" }, 503); return; }
      state.tunnels.splice(index, 1);
      await fulfillJson(route, { deleted: true, pending: false, id, message: "公网服务已永久删除" }); return;
    }
    if (/^\/api\/v1\/devices\/[^/]+$/.test(path) && method === "PUT") {
      const id = decodeURIComponent(path.split("/").at(-1) ?? "");
      const body = request.postDataJSON() as { name: string; mesh_name: string };
      const device = state.devices.find((item) => item.id === id);
      if (!device) { await fulfillJson(route, { error: "设备不存在" }, 404); return; }
      const previousActiveMeshName = device.active_mesh_name;
      const previousMeshFqdn = device.mesh_fqdn;
      device.name = body.name;
      device.mesh_name = body.mesh_name;
      device.active_mesh_name = meshRenamePending ? previousActiveMeshName : body.mesh_name;
      device.mesh_fqdn = meshRenamePending ? previousMeshFqdn : `${body.mesh_name}.mesh.example.internal`;
      device.mesh_name_status = meshRenamePending ? "applying" : "ready";
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
      await fulfillJson(route, { deleted: true, pending: false, id, message: `设备已删除，${tunnelIds.length} 个公网服务已保留为未分配并关闭；原 Agent 需要重新入网才能连接` }); return;
    }
    await fulfillJson(route, { error: `未模拟接口：${method} ${path}` }, 404);
  });
}

async function expectNoHorizontalOverflow(page: Page) {
  await page.evaluate(async () => { await Promise.allSettled(document.getAnimations().filter(a=>a.effect?.getComputedTiming().iterations!==Infinity).map(a=>a.finished)); });
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

async function openAdvancedSiteLink(page: Page) {
  await page.getByText("站点互联 · 高级", { exact: true }).click();
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
  await expect(page.getByRole("button", { name: "添加服务" })).toHaveCount(0);
  await expectNoHorizontalOverflow(page);
});

test("统一网络导航与浏览器历史可用", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, publicDomains: [seedPublicDomain] });
  await page.goto("/#/overview");
  await expect(page.locator("main h1")).toHaveText("概览");
  await expectNoGenericRefresh(page);
  await navigatePrimary(page, "设备");
  await expect(page).toHaveURL(/#\/network\/devices$/);
  await expect(page.locator("main h1")).toHaveText("设备");
  await expectNoGenericRefresh(page);
  await navigatePrimary(page, "公网服务");
  await expect(page).toHaveURL(/#\/network\/public$/);
  await expect(page.locator("main h1")).toHaveText("公网服务");
  await expectNoGenericRefresh(page);
  await expect(page).toHaveTitle("公网服务 - Nexo");
  if ((page.viewportSize()?.width ?? 1440) <= 900) {
    await page.getByRole("button", { name: "打开导航" }).click();
    const drawer = page.getByRole("dialog", { name: "移动导航" });
    await expect(drawer.getByRole("link", { name: "公网服务" })).toHaveAttribute("aria-current", "page");
    await drawer.getByRole("button", { name: "关闭导航" }).click();
  } else {
    await expect(page.locator(".sidebar").getByRole("link", { name: "公网服务" })).toHaveAttribute("aria-current", "page");
  }
  await navigatePrimary(page, "网络设置");
  await page.getByRole("link", { name: "域名与 HTTPS" }).click();
  await expect(page).toHaveURL(/#\/network\/settings\/domains$/);
  await expect(page.locator("main h1")).toHaveText("域名与 HTTPS");
  await expectNoGenericRefresh(page);
  await expect(page.getByRole("button", { name: "重新检测", exact: true })).toBeVisible();
  await navigatePrimary(page, "私网访问");
  await expect(page).toHaveURL(/#\/network\/private$/);
  await expect(page.locator("main h1")).toHaveText("私网访问");
  await expectNoGenericRefresh(page);
  await navigatePrimary(page, "访问策略");
  await expect(page).toHaveURL(/#\/network\/access$/);
  await expect(page.locator("main h1")).toHaveText("访问策略");
  await navigatePrimary(page, "网络设置");
  await expect(page).toHaveURL(/#\/network\/settings\/service$/);
  await expect(page.locator("main h1")).toHaveText("组网服务");
  await navigatePrimary(page, "设置");
  await expect(page.locator("main h1")).toHaveText("设置");
  await expectNoGenericRefresh(page);
  await page.goBack();
  await expect(page.locator("main h1")).toHaveText("组网服务");
  await page.goForward();
  await expect(page.locator("main h1")).toHaveText("设置");
  await page.goto("/#/unknown");
  await expect(page).toHaveURL(/#\/overview$/);
  await expect(page.locator("main h1")).toHaveText("概览");
  await expectNoGenericRefresh(page);
  await expectNoHorizontalOverflow(page);
});

test("旧公网访问地址不再兼容并回到概览", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/overview");
  await page.goto("/#/public-access");
  await expect(page).toHaveURL(/#\/overview$/);
  await expect(page.locator("main h1")).toHaveText("概览");
});

test("公网服务访问地址支持安全跳转与复制", async ({ page, context }) => {
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
  await page.goto("/#/network/public");

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
  await page.goto("/#/network/public");
  await page.getByRole("button", { name: "复制媒体中心的访问地址" }).click();
  await expect(page.getByRole("alert")).toHaveText("浏览器无法访问剪贴板，请手动选择访问地址复制。");
});

test("旧网络互联子路由不再兼容", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true });
  for (const route of ["sites", "shared", "links"]) {
    await page.goto("/#/overview");
    await page.goto(`/#/networks/${route}`);
    await expect(page).toHaveURL(/#\/overview$/);
    await expect(page.locator("main h1")).toHaveText("概览");
  }
});

test("网络互联加载失败后可重试且不恢复通用刷新", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, failFirstNetworksLoad: true });
  await page.goto("/#/network/private");
  await expect(page.getByRole("alert")).toContainText("模拟网络互联加载失败");
  await expectNoGenericRefresh(page);
  await page.getByRole("button", { name: "重试", exact: true }).click();
  await expect(page.getByRole("button", { name: "管理子网" }).first()).toBeVisible();
});

test("设备子网一次保存且路径只在详情按客户端显示", async ({page}) => {
  await installApiMocks(page,{initialized:true,authenticated:true});
  await page.goto('/#/network/devices');
  const trigger=page.getByRole('button',{name:'家庭网关',exact:true});
  await trigger.click();
  await page.getByRole('button',{name:'编辑子网'}).click();
  const sheet=page.getByRole('dialog');
  await sheet.getByRole('checkbox',{name:/10\.0\.0\.0\/24/}).check();
  const save=page.waitForRequest(r=>r.url().endsWith('/devices/device-home/shared-networks'));
  await sheet.getByRole('button',{name:'保存',exact:true}).click();
  expect((await save).postDataJSON().networks).toEqual(expect.arrayContaining([expect.objectContaining({prefix:'10.0.0.0/24',enabled:true})]));
  await expect(page.getByRole('dialog',{name:'家庭网关',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'编辑子网'})).toBeFocused();
  await page.getByRole('button',{name:/192\.168\.1\.0\/24/}).click();
  await expect(page.getByText('P2P 直连',{exact:true})).toBeVisible();
  await expect(page.getByText('配置与必要批准已完成；此状态不代表已实测所有家庭服务。')).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("添加设备生成最小 Compose 配置", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await installApiMocks(page, { initialized: true, authenticated: true });
  await page.goto("/#/network/devices");
  await page.getByRole("button", { name: "添加设备" }).click();
  await page.getByRole("tab",{name:"共享网络或发布服务"}).click();
  await page.getByLabel("设备名称").fill("家庭 NAS");
  await page.getByRole("button", { name: "生成设备配置" }).click();
  const compose = await page.getByLabel("Docker Compose 配置").inputValue();
  expect(compose).toContain("ghcr.io/thelinyue/nexo-agent:0.1.17");
  expect(compose).toContain("TZ: ${TZ:-Asia/Shanghai}");
  expect(compose.match(/NEXO_[A-Z_]+:/g)).toEqual(["NEXO_SERVER_URL:", "NEXO_ENROLLMENT_TOKEN:"]);
  await page.getByRole("button", { name: "复制 Compose 配置" }).click();
  await expect(page.getByRole("button", { name: "已复制" })).toBeVisible();
  const sheet=page.getByRole("dialog",{name:"添加设备"});
  await expect(sheet.getByText("待批准",{exact:true})).toBeVisible();
  await expect(sheet.getByRole("button",{name:"完成",exact:true})).toHaveCount(0);
  await sheet.getByRole("button",{name:"批准设备"}).click();
  await expect(sheet.getByText("设备已加入",{exact:true})).toBeVisible();
  await expect(sheet.getByRole("button",{name:"完成",exact:true})).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("设备搜索筛选与详情 Sheet 在目标尺寸保持可操作", async ({page}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "此测试自身覆盖尺寸与主题矩阵");
  test.setTimeout(60000);
  await installApiMocks(page,{initialized:true,authenticated:true,publicDomains:[seedPublicDomain]});
  await page.emulateMedia({reducedMotion:"reduce"});
  for (const colorScheme of ["light","dark"] as const) {
    await page.emulateMedia({colorScheme});
    for (const viewport of [{width:1440,height:900},{width:390,height:844},{width:320,height:568}]) {
      await page.setViewportSize(viewport);
      await page.goto('/#/network/devices');
      await page.getByLabel('搜索设备',{exact:true}).fill('100.64.0.2');
      await expect(page.locator('.unified-device-row')).toHaveCount(1);
      await page.getByLabel('设备类型筛选').selectOption('tailscale_client');
      await expect(page.locator('.unified-device-row')).toHaveCount(0);
      await page.getByLabel('设备类型筛选').selectOption('nexo_agent');
      await page.getByRole('button',{name:'家庭网关',exact:true}).click();
      await expectNoHorizontalOverflow(page);
      await page.screenshot({path:testInfo.outputPath(`device-${viewport.width}-${colorScheme}.png`)});
      await page.getByRole('button',{name:'编辑子网'}).click();
      const sheet=page.getByRole('dialog',{name:'编辑子网'});
      await expect(sheet).toBeVisible();
      for (const button of await sheet.getByRole('button').all()) expect((await button.boundingBox())!.height).toBeGreaterThanOrEqual(44);
      await expectNoHorizontalOverflow(page);
      await page.screenshot({path:testInfo.outputPath(`subnet-${viewport.width}-${colorScheme}.png`)});
      await page.keyboard.press('Escape');
      await expect(page.getByRole('button',{name:'编辑子网'})).toBeFocused();
      await page.keyboard.press('Escape');
      await expect(page.getByRole('button',{name:'家庭网关',exact:true})).toBeFocused();
      await expect(page.getByLabel('搜索设备',{exact:true})).toHaveValue('100.64.0.2');
    }
  }
});

test("公网服务添加与编辑均使用表格式弹窗", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, failFirstTunnelCreate: true, publicDomains: [seedPublicDomain] });
  await page.goto("/#/network/public");
  const createTrigger = page.getByRole("button", { name: "添加服务" });
  await createTrigger.click();
  let dialog = page.getByRole("dialog", { name: "添加服务" });
  await expect(dialog.getByRole("button", { name: "取消" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(createTrigger).toBeFocused();
  await createTrigger.click();
  dialog = page.getByRole("dialog", { name: "添加服务" });
  await expect(dialog.getByLabel("服务类型").locator("option")).toHaveText(["Web 服务", "TCP 服务"]);
  await dialog.getByLabel("显示名称（可选）", { exact: true }).fill("远程终端");
  await dialog.getByLabel("服务类型").selectOption("tcp");
  await dialog.getByText("指定公网端口（可选）",{exact:true}).click();
  await expect(dialog.getByLabel("公网端口（可选）")).toBeVisible();
  await expect(dialog.getByLabel("子域名前缀")).toHaveCount(0);
  await dialog.getByLabel("本地地址").fill("service.internal.example.local");
  await dialog.getByLabel("本地端口").fill("70000");
  await dialog.getByRole("button", { name: "添加服务", exact: true }).click();
  await expect(dialog.getByRole("alert")).toHaveText("本地端口必须在 1-65535 范围内");
  await dialog.getByLabel("本地端口").fill("22");
  await dialog.getByLabel("公网端口（可选）").fill("22022");
  await dialog.getByRole("button", { name: "添加服务", exact: true }).click();
  await expect(dialog.getByRole("alert")).toHaveText("模拟创建失败");
  await expect(dialog.getByLabel("显示名称（可选）", { exact: true })).toHaveValue("远程终端");
  await dialog.getByRole("button", { name: "添加服务", exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText("远程终端", { exact: true })).toBeVisible();
  const tunnelRow = page.locator(".tunnel-row").filter({ hasText: "媒体中心" });
  const editTrigger = tunnelRow.getByRole("button", { name: "查看详情" });
  await editTrigger.click();
  await page.getByRole("button",{name:"编辑",exact:true}).click();
  const editDialog = page.getByRole("dialog", { name: "编辑 媒体中心" });
  await expect(editDialog.getByLabel("显示名称（可选）", { exact: true })).toHaveValue("媒体中心");
  await expect(editDialog.getByLabel("服务类型").locator("option")).toHaveText(["Web 服务", "TCP 服务"]);
  await expect(editDialog.getByLabel("本地服务地址")).toBeVisible();
  await editDialog.getByLabel("显示名称（可选）", { exact: true }).fill("家庭媒体库");
  await editDialog.getByRole("button", { name: "保存修改" }).click();
  await expect(editDialog).toBeHidden();
  await expect(page.getByRole("dialog",{name:"家庭媒体库",exact:true})).toBeVisible();
  await page.keyboard.press("Escape");
  await expectNoHorizontalOverflow(page);
});

test("Web 服务配置域名后恢复创建草稿", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, publicDomains: [] });
  await page.goto("/#/network/public");
  await page.getByRole("button", { name: "添加服务" }).click();
  const sheet = page.getByRole("dialog", { name: "添加服务" });
  await sheet.getByLabel("显示名称（可选）").fill("家庭媒体库");
  await sheet.getByLabel("子域名前缀").fill("media-home");
  await sheet.getByLabel("本地服务地址").fill("http://127.0.0.1:8096");
  await sheet.getByRole("button", { name: "配置域名" }).click();
  await sheet.getByLabel("根域名").fill("home.example.com");
  await sheet.getByRole("button", { name: "添加域名" }).click();
  await expect(sheet.getByLabel("显示名称（可选）")).toHaveValue("家庭媒体库");
  await expect(sheet.getByLabel("子域名前缀")).toHaveValue("media-home");
  await expect(sheet.getByLabel("本地服务地址")).toHaveValue("http://127.0.0.1:8096");
  await expect(sheet.getByLabel("公网域名")).toHaveValue("domain-1");
});

test("公网服务永久删除支持取消、失败重试与即时移除", async ({ page }) => {
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
  await page.goto("/#/network/public");
  const row = page.locator(".tunnel-row").filter({ hasText: "媒体中心" });
  const deleteTrigger = row.getByRole("button", { name: "删除公网服务媒体中心" });

  await deleteTrigger.click();
  let dialog = page.getByRole("alertdialog", { name: "删除公网服务" });
  await expect(dialog).toContainText("设备离线不影响删除；设备下次连接时会自动清理旧配置");
  await expect(dialog.getByRole("button", { name: "取消" })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(deleteTrigger).toBeFocused();
  await expect(row).toBeVisible();

  await deleteTrigger.click();
  dialog = page.getByRole("alertdialog", { name: "删除公网服务" });
  const confirmDelete = dialog.locator('button[type="submit"]');
  await confirmDelete.click();
  await expect(confirmDelete).toHaveText("删除中…");
  await expect(confirmDelete).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("alert")).toHaveText("模拟公网服务删除失败");
  await expect(row).toBeVisible();
  await expect(confirmDelete).toBeEnabled();
  await confirmDelete.click();

  await expect(dialog).toBeHidden();
  await expect(row).toHaveCount(0);
  await expect(page.getByRole("status").filter({ hasText: "公网服务已永久删除" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "0 个公网服务" })).toBeFocused();
  await expect(page.getByText("还没有公网服务", { exact: true })).toBeVisible();
  expect(deleteRequestCount).toBe(2);
  await expectNoHorizontalOverflow(page);
});

test("公网服务支持全选半选与四种批量操作", async ({ page }) => {
  const batchTunnels: Array<typeof seedTunnel> = [
    structuredClone(seedTunnel),
    { ...structuredClone(seedTunnel), id: "tunnel-office", device_id: "device-office", device_name: "办公室网关", name: "办公室服务", enabled: false, apply_status: "disabled", public_address: "https://office.nexo.example.com" },
    { ...structuredClone(seedTunnel), id: "tunnel-unassigned", device_id: null, device_name: null, name: "未分配服务", enabled: false, apply_status: "disabled", public_address: null },
  ];
  await installApiMocks(page, { initialized: true, authenticated: true, tunnels: batchTunnels });
  await page.goto("/#/network/public");

  const selectAll = page.getByRole("checkbox", { name: "全选公网服务" });
  const first = page.getByRole("checkbox", { name: "选择公网服务媒体中心" });
  const second = page.getByRole("checkbox", { name: "选择公网服务办公室服务" });
  const third = page.getByRole("checkbox", { name: "选择公网服务未分配服务" });
  const toolbar = page.getByRole("toolbar", { name: "公网服务批量操作" });
  await first.check();
  await expect(selectAll).not.toBeChecked();
  await expect(selectAll).toHaveJSProperty("indeterminate", true);
  await second.check();
  await third.check();
  await expect(selectAll).toBeChecked();

  await toolbar.getByRole("button", { name: "启用", exact: true }).click();
  await expect(page.getByText("已启用 1 个公网服务，跳过 2 项", { exact: true })).toBeVisible();
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
  await expect(page.getByRole("heading", { name: "3 个公网服务" })).toBeFocused();
  await expect(page.locator(".tunnel-row").filter({ hasText: "未分配服务" })).toContainText("办公室网关");
  await expect(toolbar).toHaveCount(0);

  await selectAll.check();
  await toolbar.getByRole("button", { name: "停用", exact: true }).click();
  await expect(page.getByText("已停用 2 个公网服务，跳过 1 项", { exact: true })).toBeVisible();
  await selectAll.check();

  const deleteTrigger = toolbar.getByRole("button", { name: "删除", exact: true });
  await deleteTrigger.click();
  const deleteDialog = page.getByRole("alertdialog", { name: "批量删除公网服务" });
  await expect(deleteDialog).toContainText("永久删除 3 个公网服务");
  await deleteDialog.getByRole("button", { name: "永久删除" }).click();
  await expect(deleteDialog).toBeHidden();
  await expect(page.getByRole("heading", { name: "0 个公网服务" })).toBeFocused();
  await expect(page.getByText("还没有公网服务", { exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});

test("设备详情同时编辑显示名称和短访问名且不再显示站点", async ({page}) => {
  await installApiMocks(page,{initialized:true,authenticated:true});
  await page.goto('/#/network/devices');
  await page.getByRole('button',{name:'家庭网关',exact:true}).click();
  await page.getByText('设备信息与更多操作',{exact:true}).click();
  await page.getByRole('button',{name:'编辑设备'}).click();
  await page.getByLabel('显示名称').fill('家庭 NAS');
  await page.getByLabel('组网访问名').fill('nas');
  await page.getByRole('button',{name:'保存修改'}).click();
  await expect(page.getByRole('dialog',{name:'家庭 NAS',exact:true})).toBeVisible();
  await expect(page.getByText('nas.mesh.example.internal',{exact:true})).toBeVisible();
  await expect(page.getByLabel('所属站点')).toHaveCount(0);
});

test("设备搜索支持短名和完整域名，访问名更新期间保留旧地址并可复制", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: "http://127.0.0.1:4173" });
  await installApiMocks(page, { initialized: true, authenticated: true, meshRenamePending: true });
  await page.goto("/#/network/devices");
  const search = page.getByRole("textbox", { name: "搜索设备" });
  await search.fill("home-gateway.mesh.example.internal");
  const row = page.locator(".unified-device-row").filter({ hasText: "家庭网关" });
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "家庭网关", exact: true }).click();
  const detail = page.getByRole("dialog", { name: "家庭网关", exact: true });
  await expect(detail.getByText("home-gateway", { exact: true })).toBeVisible();
  await expect(detail.getByText("home-gateway.mesh.example.internal", { exact: true })).toBeVisible();
  await detail.getByRole("button", { name: "复制短访问名" }).click();
  await expect(detail.getByRole("status")).toHaveText("短访问名已复制");
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe("home-gateway");
  await detail.getByRole("button", { name: "复制完整域名" }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe("home-gateway.mesh.example.internal");
  await detail.getByText("设备信息与更多操作", { exact: true }).click();
  await detail.getByRole("button", { name: "编辑设备" }).click();
  await page.getByLabel("显示名称").fill("家庭 NAS");
  await page.getByLabel("组网访问名").fill("nas");
  await page.getByRole("button", { name: "保存修改" }).click();
  const updatedDetail = page.getByRole("dialog").filter({ hasText: "正在更新访问名" });
  await expect(updatedDetail).toContainText("正在更新访问名");
  await expect(updatedDetail).toContainText("home-gateway.mesh.example.internal");
  await expect(updatedDetail).toContainText("nas");
});

test("域名编辑 Sheet 在失败后保留表单并安全提交 Cloudflare Token", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, failFirstPublicDomainUpdate: true, publicDomains: [seedPublicDomain] });
  let secretRequestCount = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/v1/public-domains/domain-primary/credentials") secretRequestCount += 1;
  });
  await page.goto("/#/network/settings/domains");

  await expect(page.getByLabel("Cloudflare API Token")).toHaveCount(0);
  const row = page.locator(".domain-table-item").filter({ hasText: "example.com" });
  const menuTrigger = row.locator('summary[aria-label="更多 example.com 操作"]');
  await menuTrigger.click();
  const editTrigger = row.getByRole("button", { name: "编辑设置" });
  await editTrigger.click();
  let dialog = page.getByRole("dialog", { name: "编辑 example.com" });
  await expect(dialog).toHaveClass(/form-sheet/);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(menuTrigger).toBeFocused();
  await menuTrigger.click();
  await editTrigger.click();
  dialog = page.getByRole("dialog", { name: "编辑 example.com" });
  const tokenInput = dialog.getByLabel("Cloudflare API Token", { exact: true });
  await expect(tokenInput).toHaveAttribute("type", "password");
  await tokenInput.fill("  release-cloudflare-token  ");
  await dialog.getByRole("button", { name: "显示 Cloudflare API Token" }).click();
  await expect(tokenInput).toHaveAttribute("type", "text");
  await dialog.getByRole("button", { name: "隐藏 Cloudflare API Token" }).click();

  await dialog.getByRole("button", { name: "保存修改" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("模拟域名与 HTTPS 设置失败");
  await expect(tokenInput).toHaveValue("  release-cloudflare-token  ");
  expect(secretRequestCount).toBe(0);

  const secretRequest = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/v1/public-domains/domain-primary/credentials");
  await dialog.getByRole("button", { name: "保存修改" }).click();
  expect((await secretRequest).postDataJSON()).toMatchObject({ cloudflare_token: "release-cloudflare-token" });
  await expect(dialog).toBeHidden();
  await expect(menuTrigger).toBeFocused();
  expect(secretRequestCount).toBe(1);

  await menuTrigger.click();
  await editTrigger.click();
  dialog = page.getByRole("dialog", { name: "编辑 example.com" });
  await expect(dialog.getByLabel("Cloudflare API Token", { exact: true })).toHaveValue("");
  await dialog.getByRole("button", { name: "保存修改" }).click();
  await expect(dialog).toBeHidden();
  expect(secretRequestCount).toBe(1);
  await expectNoHorizontalOverflow(page);
});

test("空域名列表可通过添加 Sheet 完成配置", async ({ page }) => {
  await installApiMocks(page, {
    initialized: true,
    authenticated: true,
    publicDomains: [],
  });
  await page.goto("/#/network/settings/domains");
  await expect(page).toHaveURL(/#\/network\/settings\/domains$/);
  await expect(page.getByText("还没有公网域名", { exact: true })).toBeVisible();
  await expect(page.getByLabel("根域名")).toHaveCount(0);
  const configureTrigger = page.getByRole("button", { name: "添加域名" });
  await configureTrigger.click();
  const dialog = page.getByRole("dialog", { name: "添加公网域名" });
  await dialog.getByLabel("根域名").fill("edge.example.com");
  await dialog.getByRole("button", { name: "取消" }).click();
  await expect(dialog).toBeHidden();
  await expect(configureTrigger).toBeFocused();

  await configureTrigger.click();
  const reopened = page.getByRole("dialog", { name: "添加公网域名" });
  await reopened.getByLabel("根域名").fill("edge.example.com");
  await reopened.getByRole("button", { name: "添加域名" }).click();
  await expect(reopened).toBeHidden();
  await expect(page.locator(".domain-table-item").filter({ hasText: "edge.example.com" })).toBeVisible();
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
    root_certificate: { ...seedPublicDomain.root_certificate, status: "pending", not_before: null, not_after: null, renewal_at: null, subjects: [], progress: { stage: "retry_wait", attempt_count: 3, last_event_at: 1892000000, next_retry_at: 1893000000, error_code: "acme_rate_limited", error_message: "CA 返回 HTTP 429" } },
    wildcard_certificate: { ...seedPublicDomain.wildcard_certificate, status: "pending", not_before: null, not_after: null, renewal_at: null, subjects: [], progress: { stage: "waiting_dns", attempt_count: 2, last_event_at: 1892000000, next_retry_at: null, error_code: null, error_message: null } },
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
  await page.goto("/#/network/settings/domains");

  const primaryRow = page.locator(".domain-table-item").filter({ hasText: "example.com" }).first();
  await expect(primaryRow).toContainText("主域名");
  await expect(primaryRow).toContainText("预计续期");
  const limitedRow = page.locator(".domain-table-item").filter({ hasText: "rate.example.com" });
  await expect(limitedRow).toContainText("CA 限流");
  await limitedRow.getByRole("button", { name: /展开 rate.example.com/ }).click();
  await expect(limitedRow).toContainText("系统将在");
  await limitedRow.locator('summary[aria-label="更多 rate.example.com 操作"]').click();
  await expect(limitedRow.getByRole("button", { name: "申请自动证书" })).toBeDisabled();

  if ((page.viewportSize()?.width ?? 1440) > 900) {
    await page.getByRole("checkbox", { name: "全选公网域名" }).check();
  } else {
    await page.getByRole("checkbox", { name: "选择 example.com" }).check();
    await page.getByRole("checkbox", { name: "选择 rate.example.com" }).check();
    await page.getByRole("checkbox", { name: "选择 manual.example.net" }).check();
  }
  const batchRecheck = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/v1/public-domains/batch/recheck");
  await page.locator(".batch-toolbar").getByRole("button", { name: "重新检测" }).click();
  expect((await batchRecheck).postDataJSON()).toEqual({ ids: ["domain-primary", "domain-rate-limited", "domain-manual"] });
  await expect(page.getByRole("status")).toContainText("已重新检测 3 个域名");

  const singleRenew = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/v1/public-domains/domain-primary/renew");
  await primaryRow.locator('summary[aria-label="更多 example.com 操作"]').click();
  await primaryRow.getByRole("button", { name: "申请自动证书" }).click();
  await singleRenew;
  await expect(page.getByRole("status")).toContainText("已提交 example.com 的自动证书申请");

  const manualRow = page.locator(".domain-table-item").filter({ hasText: "manual.example.net" });
  await manualRow.getByRole("button", { name: "更新证书" }).click();
  const dialog = page.getByRole("dialog", { name: "编辑 manual.example.net" });
  await expect(dialog.getByLabel("证书文件")).toBeVisible();
  await expect(dialog.getByLabel("私钥文件")).toBeVisible();
  await dialog.getByRole("button", { name: "取消" }).click();
  await expect(dialog).toBeHidden();
  await expectNoHorizontalOverflow(page);
});

test("DNS 托管先预览再同步并展示真实证书阶段", async ({ page }) => {
  await installApiMocks(page, {
    initialized: true,
    authenticated: true,
    publicDomains: [seedPublicDomain],
  });
  await page.goto("/#/network/settings/domains");

  const row = page.locator(".domain-table-item").filter({ hasText: "example.com" });
  await row.getByRole("button", { name: /展开 example.com/ }).click();
  await expect(row).toContainText("CA 校验");
  await expect(row).toContainText("已签发");
  await expect(row).toContainText("已启用");
  await expect(row).toContainText("SAN");
  await expect(row).toContainText("管理入口：https://nexo.example.com");
  await expect(row).toContainText("Mesh 入口：https://mesh.example.com");

  await row.locator('summary[aria-label="更多 example.com 操作"]').click();
  await row.getByRole("button", { name: "编辑设置" }).click();
  const editor = page.getByRole("dialog", { name: "编辑 example.com" });
  await expect(editor.getByText("ACME 环境")).toHaveCount(0);
  await expect(editor.getByRole("checkbox", { name: "由 Nexo 自动管理 Cloudflare DNS" })).toBeChecked();
  await expect(editor.getByLabel("公网 IPv4")).toHaveValue("203.0.113.10");
  await editor.getByRole("button", { name: "取消" }).click();

  await row.locator('summary[aria-label="更多 example.com 操作"]').click();
  await row.getByRole("button", { name: "同步 DNS" }).click();
  const preview = page.getByRole("dialog", { name: "同步 example.com" });
  await expect(preview).toContainText("接管同值记录");
  await expect(preview).toContainText("A @");
  await expect(preview).toContainText("A *");
  const applyRequest = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/v1/public-domains/domain-primary/dns/apply");
  await preview.getByRole("button", { name: "确认同步 DNS" }).click();
  expect((await applyRequest).postDataJSON()).toEqual({ confirm_conflicts: false });
  await expect(preview).toBeHidden();
  await expectNoHorizontalOverflow(page);
});

test("运行日志使用产品化居中弹窗并支持域名筛选", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, publicDomains: [seedPublicDomain] });
  await page.goto("/#/network/settings/domains");

  const topTrigger = page.getByRole("button", { name: "运行日志", exact: true });
  await topTrigger.click();
  let dialog = page.getByRole("dialog", { name: "域名服务运行日志" });
  await expect(dialog).toHaveClass(/form-sheet/);
  await expect(dialog.locator(".form-dialog-surface")).toHaveClass(/wide/);
  await expect(dialog.getByLabel("域名", { exact: true })).toHaveValue("all");
  await expect(dialog).toContainText("自动证书");
  await expect(dialog).toContainText("配置应用");
  await expect(dialog).not.toContainText(/caddy|logger|secret_dir/i);
  await dialog.getByRole("button", { name: "关闭域名服务运行日志窗口" }).click();
  await expect(topTrigger).toBeFocused();

  const row = page.locator(".domain-table-item").filter({ hasText: "example.com" });
  const filteredRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.pathname === "/api/v1/public-domain-runtime-events" && url.searchParams.get("public_domain_id") === "domain-primary";
  });
  await row.getByRole("button", { name: "查看 example.com 运行日志" }).click();
  await filteredRequest;
  dialog = page.getByRole("dialog", { name: "域名服务运行日志" });
  await expect(dialog.getByLabel("域名", { exact: true })).toHaveValue("domain-primary");
  await expect(dialog).not.toContainText("域名服务配置已经更新");
});

test("自动域名上传手动证书时请求原子启用", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, publicDomains: [seedPublicDomain] });
  await page.goto("/#/network/settings/domains");
  const row = page.locator(".domain-table-item").filter({ hasText: "example.com" });
  await row.locator('summary[aria-label="更多 example.com 操作"]').click();
  await row.getByRole("button", { name: "编辑设置" }).click();
  const editor = page.getByRole("dialog", { name: "编辑 example.com" });
  await editor.getByLabel("签发方式").selectOption("manual");
  await editor.getByLabel("证书文件").setInputFiles({ name: "example.com.pem", mimeType: "text/plain", buffer: Buffer.from("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----") });
  await editor.getByLabel("私钥文件").setInputFiles({ name: "example.com.key", mimeType: "text/plain", buffer: Buffer.from("-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----") });
  const credentialsRequest = page.waitForRequest((request) => new URL(request.url()).pathname === "/api/v1/public-domains/domain-primary/credentials");
  await editor.getByRole("button", { name: "保存修改" }).click();
  expect((await credentialsRequest).postDataJSON()).toMatchObject({
    activate_manual_certificate: true,
    certificate_pem: expect.stringContaining("BEGIN CERTIFICATE"),
    private_key_pem: expect.stringContaining("BEGIN RSA PRIVATE KEY"),
  });
  await expect(editor).toBeHidden();
  await expect(row).toContainText("手动证书");
  await expect(row).toContainText("自动申请已停止");
});

test("删除手动证书后保持手动模式", async ({ page }) => {
  const manualDomain = { ...structuredClone(seedPublicDomain), certificate_mode: "manual" };
  await installApiMocks(page, { initialized: true, authenticated: true, publicDomains: [manualDomain] });
  await page.goto("/#/network/settings/domains");
  const row = page.locator(".domain-table-item").filter({ hasText: "example.com" });
  await row.getByRole("button", { name: "更新证书" }).click();
  const editor = page.getByRole("dialog", { name: "编辑 example.com" });
  page.once("dialog", (confirmation) => void confirmation.accept());
  const deleteRequest = page.waitForRequest((request) => request.method() === "DELETE" && new URL(request.url()).pathname === "/api/v1/public-domains/domain-primary/manual-certificate");
  await editor.getByRole("button", { name: "删除当前手动证书" }).click();
  await deleteRequest;
  await expect(editor).toBeHidden();
  await expect(row).toContainText("手动证书");
  await expect(row).toContainText("自动申请已停止");
  await row.locator('summary[aria-label="更多 example.com 操作"]').click();
  await expect(row.getByRole("button", { name: "申请自动证书" })).toHaveCount(0);
});

test("删除唯一主域名明确关闭公网入口", async ({ page }) => {
  await installApiMocks(page, { initialized: true, authenticated: true, publicDomains: [seedPublicDomain] });
  await page.goto("/#/network/settings/domains");
  const row = page.locator(".domain-table-item").filter({ hasText: "example.com" });
  await row.locator('summary[aria-label="更多 example.com 操作"]').click();
  await row.getByRole("button", { name: "删除域名" }).click();
  const dialog = page.getByRole("alertdialog", { name: "删除 example.com" });
  await expect(dialog).toContainText("Web 服务会保留并解除域名绑定");
  await dialog.getByRole("checkbox").check();
  const deleteRequest = page.waitForRequest((request) => request.method() === "DELETE" && new URL(request.url()).pathname === "/api/v1/public-domains/domain-primary");
  await dialog.getByRole("button", { name: "确认删除" }).click();
  expect((await deleteRequest).postDataJSON()).toEqual({ disable_public_access: true });
  await expect(dialog).toBeHidden();
  await expect(page.getByText("还没有公网域名", { exact: true })).toBeVisible();
});

test("子网编辑分别校验 IPv4 与 IPv6 并保留未保存选择", async ({page}) => {
  await installApiMocks(page,{initialized:true,authenticated:true});
  await page.goto('/#/network/devices');
  await page.getByRole('button',{name:'家庭网关',exact:true}).click();
  await page.getByRole('button',{name:'编辑子网'}).click();
  await expect(page.getByRole('checkbox',{name:/2001:db8:1::/})).toBeDisabled();
  const selected=page.getByRole('checkbox',{name:/10\.0\.0\.0\/24/});
  await selected.check();
  await page.waitForResponse(r=>r.url().endsWith('/api/v1/devices'));
  await expect(selected).toBeChecked();
  page.once('dialog',d=>void d.dismiss());
  await page.keyboard.press('Escape');
  await expect(selected).toBeChecked();
  page.once('dialog',d=>void d.accept());
  await page.getByRole('button',{name:'取消',exact:true}).click();
  await expect(page.getByRole('button',{name:'编辑子网'})).toBeVisible();
});

test("设置支持会话撤销与改密重登", async ({page}) => {
  await installApiMocks(page,{initialized:true,authenticated:true});
  await page.goto('/#/settings');
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
  await page.goto("/#/network/devices");
  const row = page.locator(".unified-device-row").filter({hasText:"家庭网关"});
  await row.getByRole('button',{name:'家庭网关'}).click();
  await page.getByText('设备信息与更多操作',{exact:true}).click();
  await page.getByRole('button',{name:'删除设备',exact:true}).click();
  const dialog = page.getByRole("alertdialog", { name: "删除设备" });
  await expect(dialog).toContainText("公网服务将保留为未分配并关闭");
  await dialog.getByRole("button", { name: "取消" }).click();
  await expect(row).toBeVisible();
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
  expect(serviceWorker.script).toContain("/api/");
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

test("旧版 Worker 遇到 OIDC Ticket 会自动恢复登录路由", async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "Worker 生命周期只需在一个浏览器项目中验证");
  const server = await startPwaUpgradeServer();
  const context = await browser.newContext({ serviceWorkers: "allow" });
  const page = await context.newPage();
  try {
    await page.goto(`${server.url}/?oidc_ticket=upgrade-ticket`);
    await expect(page.locator("#legacy")).toBeVisible();
    await expect.poll(() => page.evaluate(() => navigator.serviceWorker.controller?.scriptURL ?? ""))
      .toContain("/sw.js");

    server.setMode("current");
    await page.evaluate(async () => {
      const registration = await navigator.serviceWorker.ready;
      await registration.update();
    });

    await expect(page.locator("#oidc-reached")).toBeVisible({ timeout: 15_000 });
    expect(new URL(page.url()).pathname).toBe("/oidc/authorize");
    expect(new URL(page.url()).searchParams.get("nexo_login_ticket")).toBe("upgrade-ticket");
  } finally {
    await context.close();
    await server.close();
  }
});

test("普通控制台更新保持 waiting，不强制刷新", async ({ browser }, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-dark", "Worker 生命周期只需在一个浏览器项目中验证");
  const server = await startPwaUpgradeServer();
  const context = await browser.newContext({ serviceWorkers: "allow" });
  const page = await context.newPage();
  try {
    await page.goto(`${server.url}/`);
    await expect(page.locator("#legacy")).toBeVisible();
    const before = await page.evaluate(() => navigator.serviceWorker.controller?.scriptURL ?? "");
    expect(before).toContain("/sw.js");

    server.setMode("current");
    await page.evaluate(async () => {
      const registration = await navigator.serviceWorker.ready;
      await registration.update();
    });
    await expect.poll(() => page.evaluate(async () => {
      const registration = await navigator.serviceWorker.ready;
      return registration.waiting?.state ?? "none";
    }), { timeout: 15_000 }).toBe("installed");
    expect(await page.locator("#legacy").isVisible()).toBeTruthy();
    expect(await page.evaluate(() => navigator.serviceWorker.controller?.scriptURL ?? "")).toBe(before);
  } finally {
    await context.close();
    await server.close();
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
    { width: 390, height: 844 },
    { width: 320, height: 568 },
    { width: 430, height: 932 },
    { width: 812, height: 375 },
    { width: 1024, height: 768 },
  ];
  const networkRoutes = [
    "#/network/devices",
    "#/network/private",
    "#/network/public",
    "#/network/access",
    "#/network/settings/domains",
    "#/network/settings/keys",
    "#/network/settings/service",
  ];

  for (const viewport of viewports) {
    await page.setViewportSize(viewport);
    await page.goto("/#/overview");
    await expect(page.locator("main h1")).toHaveText("概览");
    await expectNoHorizontalOverflow(page);
    if ((viewport.width === 1440 && viewport.height === 900)
      || (viewport.width === 390 && viewport.height === 844)
      || (viewport.width === 320 && viewport.height === 568)) {
      for (const route of networkRoutes) {
        await page.goto(`/${route}`);
        await expect(page.locator("main h1")).toBeVisible();
        await expectNoHorizontalOverflow(page);
      }
    }
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
  await drawer.getByRole("link", { name: "公网服务" }).click();
  await page.getByRole("button", { name: "添加服务" }).click();
  const dialog = page.getByRole("dialog", { name: "添加服务" });
  await dialog.getByLabel("本地服务地址").fill("http://very-long-internal-service-name.with-many-segments.example.local:8800");
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
  if ((page.viewportSize()?.width ?? 1440) <= 900) {
    await page.getByRole("button", { name: "打开导航" }).click();
    const drawer = page.getByRole("dialog", { name: "移动导航" });
    await expect(drawer.getByRole("link", { name: "公网服务", exact: true })).toBeVisible();
    await drawer.getByRole("button", { name: "关闭导航" }).click();
  } else {
    await expect(page.getByRole("link", { name: "公网服务", exact: true })).toBeVisible();
  }
  await expectNoGenericRefresh(page);
  await page.goto("/#/network/settings/domains");
  await expect(page.getByRole("button", { name: "重新检测", exact: true })).toBeVisible();
  await expectNoHorizontalOverflow(page);
});
