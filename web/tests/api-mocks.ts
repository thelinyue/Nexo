import type { Page } from "@playwright/test";
import type { Tunnel, Device, Domain, DomainEvent, Enrollment, TransportIdentity } from "../src/ui";

/** 使用真实接口形状覆盖交互；失败注入用于验证界面不会把请求失败当作成功。 */
export async function installApiMocks(page: Page, options: { empty?: boolean; anonymous?: boolean } = {}) {
  const state = {
    authenticated: !options.anonymous,
    users: [{ id: "admin", username: "admin", role: "system_admin", workspace_id: "default", workspace_name: "admin的工作空间", enabled: true, devices: 2, services: 1, domains: 1 }, { id: "alice", username: "alice", role: "tenant", workspace_id: "alice-space", workspace_name: "alice 的工作空间", enabled: true, devices: 1, services: 1, domains: 0 }],
    accessKey: "nexo_join_shared-test-key",
    tunnels: (options.empty ? [] : [{ id: "t-1", name: "媒体中心", protocol: "https", local_address: "127.0.0.1", local_port: 8096, public_port: null, public_address: "https://media.example.com/a-very-long-public-address", hostname: "media", public_domain: "example.com", device_id: "a-1", device_name: "家庭 Agent", enabled: true, apply_status: "ready", apply_error: null, lan_redirect_enabled: false }] as any[]) as Tunnel[],
    devices: [{ id: "a-1", name: "家庭 Agent", status: "online", os: "Linux", architecture: "amd64", last_seen_at: 1790000000, agent_version: "0.2.0", tunnel_count: 1 }, { id: "a-2", name: "备用 Agent", status: "offline", os: "Linux", agent_version: "0.2.0", tunnel_count: 0 }] as Device[],
    transportIdentity: { server: { status: "valid", expires_at: Math.floor(Date.now()/1000) + 825*86400, renew_after: Math.floor(Date.now()/1000) + 795*86400, error: null, next_retry_at: null }, ca_expires_at: Math.floor(Date.now()/1000) + 3650*86400, ca_needs_attention: false } as TransportIdentity,
    domains: [{ id: "d-1", domain: "example.com", is_primary: true, https_enabled: true, apply_status: "applied", runtime: { config_status: "applied", config_error: null, service_warning: null, checked_at: Math.floor(Date.now() / 1000), certificates: [{ hostname: "example.com", status: "issued", not_before: Math.floor(Date.now() / 1000) - 3600, expires_at: Math.floor(Date.now() / 1000) + 90 * 86400, error: null, next_retry_at: null }] } }] as Domain[],
    domainEvents: [{ id: 1, domain_id: "d-1", summary: "配置已加载", occurred_at: Math.floor(Date.now() / 1000) }] as DomainEvent[],
    enrollments: [{ id: "e-1", kind: "recovery", device_id: "a-1", status: "awaiting_approval", expires_at: 1791000000 }] as Enrollment[],
    failureStatuses: new Map<string, number>(),
    trafficResets: new Map<string, number>(),
    quotas: new Map<string, { monthly_limit_bytes: number | null; used_bytes: number }>(),
    dnsMatches: true,
    dnsChecked: true,
    dnsResolved: true,
    dnsRetriesRemaining: 0,
    dnsNextRetryAt: null as number | null,
    sessions: [{ id: "s-current", last_seen_at: 1790000000, expires_at: 1791000000 }, { id: "s-other", last_seen_at: 1790000000, expires_at: 1791000000 }],
    failures: new Map<string, string>(), calls: [] as { method: string; path: string; body: any }[], delay: 0,
  };
  const access = (domain: string) => ({ expected_addresses: ["203.0.113.10"], checked_at: state.dnsChecked ? Math.floor(Date.now()/1000) : null, next_retry_at: state.dnsNextRetryAt, retries_remaining: state.dnsRetriesRemaining, public_access: "unverified", records: [{ hostname: `media.${domain}`, addresses: state.dnsChecked && state.dnsResolved ? ["203.0.113.10"] : [], status: state.dnsChecked ? state.dnsResolved ? "resolved" : "unresolved" : "unchecked", matches_server: state.dnsChecked && state.dnsResolved ? state.dnsMatches : null, error: state.dnsChecked && !state.dnsResolved ? "未找到 A 或 AAAA 记录" : null }] });
  await page.route("**/api/v1/**", async route => {
    const req = route.request(); const path = new URL(req.url()).pathname; const method = req.method(); const body = req.postData() ? req.postDataJSON() : null;
    state.calls.push({ method, path, body });
    const respond = (value: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
    const failure = state.failures.get(`${method} ${path}`);
    if (failure) { const status = state.failureStatuses.get(`${method} ${path}`) ?? 503; return respond({ error: failure, ...(status === 401 && !path.endsWith("/login") && !path.endsWith("/recover") ? { code: "session_expired" } : {}) }, status); }
    if (state.delay && method === "GET") await new Promise(resolve => setTimeout(resolve, state.delay));
    if (path === "/api/v1/admin/users") return respond(state.users);
    if (path === "/api/v1/admin/invitations") return respond([]);
    if (path.endsWith("/traffic/quota")) {
      const user = new URL(req.url()).searchParams.get("user_id") ?? "alice";
      const quota = state.quotas.get(user) ?? { monthly_limit_bytes: null, used_bytes: 80 * 1024 ** 3 };
      if (method === "PUT") { quota.monthly_limit_bytes = body.monthly_limit_bytes; state.quotas.set(user, quota); }
      const now = Math.floor(Date.now() / 1000);
      return respond({ ...quota, remaining_bytes: quota.monthly_limit_bytes === null ? null : Math.max(0, quota.monthly_limit_bytes - quota.used_bytes), exhausted: quota.monthly_limit_bytes !== null && quota.used_bytes >= quota.monthly_limit_bytes, period_start: now - 20 * 86400, period_end: now + 10 * 86400, started_at: now - 30 * 86400 });
    }
    if (path === "/api/v1/admin/traffic/reset" && method === "POST") {
      const reset_at = Math.floor(Date.now() / 1000);
      state.trafficResets.set(body.user_id, reset_at);
      return respond({ reset_at });
    }
    if (path.endsWith("/traffic/usage")) {
      const now = Math.floor(Date.now() / 1000);
      const user = new URL(req.url()).searchParams.get("user_id");
      const reset_at = state.trafficResets.get(user ?? "") ?? null;
      const period = (days: number, value: number) => ({ start: now - days * 86400, total: { to_origin: reset_at ? 0 : value, to_public: reset_at ? 0 : value }, partial: false });
      return respond({ timezone: "Asia/Shanghai", sampled_at: now, started_at: now - 40 * 86400, reset_at, reset_users: reset_at ? 1 : user ? 0 : state.trafficResets.size, today: period(0, 1024), week: period(3, 10240), month: period(15, 102400) });
    }
    if (path.endsWith("/traffic/realtime")) return respond({ sampled_at: Math.floor(Date.now() / 1000), status: "ready", rates: { to_origin: 2048, to_public: 8192 } });
    if (path.endsWith("/traffic/history")) {
      const range = new URL(req.url()).searchParams.get("range");
      const step = range === "1h" ? 60 : range === "7d" ? 3600 : 300;
      const count = range === "1h" ? 60 : range === "7d" ? 168 : 288;
      const end = Math.floor(Date.now() / 60000) * 60 + 60;
      const points = Array.from({ length: count }, (_, i) => ({ at: end - (count - i) * step, seconds: step, covered_seconds: step, bytes: { to_origin: 2048 * step, to_public: (4096 + Math.sin(i / 5) * 2048) * step }, rates: { to_origin: 2048, to_public: 4096 + Math.sin(i / 5) * 2048 } }));
      return respond({ start: end - count * step, end, step, sampled_at: end - 60, total: { to_origin: 2048 * count * step, to_public: 4096 * count * step }, points });
    }
    const scopedResource = path.match(/^\/api\/v1\/admin\/workspaces\/[^/]+\/(tunnels|devices|public-domains)$/);
    if (scopedResource && method === "GET") return respond(scopedResource[1] === "tunnels" ? state.tunnels : scopedResource[1] === "devices" ? state.devices : state.domains);
    if (path === "/api/v1/auth/status") return respond({ initialized: true, authenticated: state.authenticated, user_id: "admin", workspace_id: "default", role: "system_admin", username: "admin", csrf_token: "test-csrf" });
    if (path === "/api/v1/auth/login") { state.authenticated = true; return respond({ user_id: "admin", workspace_id: "default", role: "system_admin", username: "admin", csrf_token: "test-csrf" }); }
    if (path === "/api/v1/auth/recover") return respond({ username: "admin", message: "密码已更新，请重新登录" });
    if (path === "/api/v1/auth/password" || path === "/api/v1/auth/logout") return respond({});
    if (path === "/api/v1/auth/session") return respond(state.sessions[0]);
    if (path === "/api/v1/auth/sessions") return respond(state.sessions);
    if (path.startsWith("/api/v1/auth/sessions/")) { state.sessions = state.sessions.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    if (path.endsWith("/recovery") && path.startsWith("/api/v1/devices/")) { const invite: Enrollment = { id: "e-recovery", kind: "recovery", device_id: path.split("/")[4], status: "awaiting_agent", token: "recovery-token-for-test", expires_at: Math.floor(Date.now()/1000) + 3600 }; state.enrollments.push(invite); return respond(invite); }
    if (path === "/api/v1/agent-access-key") return respond({ token: state.accessKey, created_at: 1790000000, updated_at: 1790000000 });
    if (path === "/api/v1/agent-access-key/reset") { state.accessKey = "nexo_join_reset-test-key"; return respond({ token: state.accessKey, created_at: 1790000000, updated_at: Math.floor(Date.now()/1000) }); }
    if (path === "/api/v1/devices") return respond(state.devices);
    if (path === "/api/v1/transport-identity") return respond(state.transportIdentity);
    if (path.startsWith("/api/v1/devices/") && method === "DELETE") { state.devices = state.devices.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    if (path === "/api/v1/enrollments" && method === "GET") return respond(state.enrollments);
    if (path.startsWith("/api/v1/enrollments/") && method === "GET") return respond(state.enrollments.find(item => item.id === path.split("/").pop()) ?? { id: path.split("/").pop(), status: "awaiting_agent", expires_at: Math.floor(Date.now()/1000) + 3600 });
    if (path.startsWith("/api/v1/enrollments/") && method === "DELETE") { state.enrollments = state.enrollments.filter(item => item.id !== path.split("/").pop()); return respond({ revoked: true }); }
    if (path.endsWith("/approve")) { const invite = state.enrollments.find(item => item.id === path.split("/").at(-2)); if (invite) Object.assign(invite, { status: "approved", device_id: invite.device_id ?? "a-1" }); return respond(invite ?? {}); }
    if (path.endsWith("/access")) { if (method === "POST") state.dnsChecked = true; return respond(access(state.domains.find(domain => domain.id === path.split("/")[4])?.domain ?? "example.com")); }
    if (path === "/api/v1/public-domains" && method === "GET") return respond(state.domains.map(domain => ({ ...domain, access: access(domain.domain) })));
    if (path === "/api/v1/public-domains" && method === "POST") { const item = { ...body, id: "d-2", is_primary: false, apply_status: "pending", runtime: { config_status: "pending", config_error: null, service_warning: null, checked_at: null, certificates: [] } }; state.domains.push(item); return respond(item, 201); }
    if (path === "/api/v1/public-domain-runtime-events") return respond({ events: state.domainEvents, next_cursor: null });
    if (path.startsWith("/api/v1/public-domains/") && method === "DELETE") { state.domains = state.domains.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    if (path === "/api/v1/tunnels" && method === "GET") return respond(state.tunnels);
    if (path === "/api/v1/tunnels" && method === "POST") { const item = { access_mode: "public", lan_redirect_enabled: false, ...body, id: "t-new", public_address: "new.example.com", public_domain: "example.com", apply_status: "checking" }; delete item.access_password; state.tunnels.push(item); return respond(item, 201); }
    if (path === "/api/v1/tunnels/batch" && method === "DELETE") { state.tunnels = state.tunnels.filter(item => !body.tunnel_ids.includes(item.id)); return respond({ deleted_ids: body.tunnel_ids }); }
    if (/^\/api\/v1\/tunnels\/batch\/(enable|disable)$/.test(path)) { const items = state.tunnels.filter(item => body.tunnel_ids.includes(item.id)); items.forEach(item => Object.assign(item, { enabled: path.endsWith("/enable"), apply_status: path.endsWith("/enable") ? "checking" : "disabled" })); return respond(items); }
    const toggle = path.match(/^\/api\/v1\/tunnels\/([^/]+)\/(enable|disable)$/);
    if (toggle) { const item = state.tunnels.find(item => item.id === toggle[1]); Object.assign(item, { enabled: toggle[2] === "enable", apply_status: toggle[2] === "enable" ? "checking" : "disabled" }); return respond(item); }
    if (path.startsWith("/api/v1/tunnels/") && method === "PUT") { const item = state.tunnels.find(item => item.id === path.split("/").pop()); Object.assign(item, body, { lan_redirect_enabled: ["tcp", "udp", "tcp_udp"].includes(body.protocol) ? false : body.lan_redirect_enabled ?? item.lan_redirect_enabled ?? false }); delete item.access_password; return respond(item); }
    if (path.startsWith("/api/v1/tunnels/") && method === "DELETE") { state.tunnels = state.tunnels.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    return respond({ error: `未模拟的接口 ${method} ${path}` }, 404);
  });
  return state;
}
