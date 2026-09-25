import type { Page } from "@playwright/test";
import type { Device, Domain, DomainEvent, Enrollment, TransportIdentity } from "../src/ui";

/** 使用真实接口形状覆盖交互；失败注入用于验证界面不会把请求失败当作成功。 */
export async function installApiMocks(page: Page, options: { empty?: boolean; anonymous?: boolean; initialize?: boolean } = {}) {
  const state = {
    authenticated: !options.anonymous,
    tunnels: options.empty ? [] : [{ id: "t-1", name: "媒体中心", protocol: "https", local_address: "127.0.0.1", local_port: 8096, public_port: null, public_address: "https://media.example.com/a-very-long-public-address", hostname: "media", public_domain: "example.com", device_id: "a-1", device_name: "家庭 Agent", enabled: true, apply_status: "ready", apply_error: null }] as any[],
    devices: [{ id: "a-1", name: "家庭 Agent", status: "online", os: "Linux", architecture: "amd64", last_seen_at: 1790000000, agent_version: "0.2.0", tunnel_count: 1 }, { id: "a-2", name: "备用 Agent", status: "offline", os: "Linux", agent_version: "0.2.0", tunnel_count: 0 }] as Device[],
    transportIdentity: { server: { status: "valid", expires_at: Math.floor(Date.now()/1000) + 825*86400, renew_after: Math.floor(Date.now()/1000) + 795*86400, error: null, next_retry_at: null }, ca_expires_at: Math.floor(Date.now()/1000) + 3650*86400, ca_needs_attention: false } as TransportIdentity,
    domains: [{ id: "d-1", domain: "example.com", is_primary: true, https_enabled: true, apply_status: "applied", runtime: { config_status: "applied", config_error: null, service_warning: null, checked_at: Math.floor(Date.now() / 1000), certificates: [{ hostname: "example.com", status: "issued", not_before: Math.floor(Date.now() / 1000) - 3600, expires_at: Math.floor(Date.now() / 1000) + 90 * 86400, error: null, next_retry_at: null }] } }] as Domain[],
    domainEvents: [{ id: 1, domain_id: "d-1", summary: "配置已加载", occurred_at: Math.floor(Date.now() / 1000) }] as DomainEvent[],
    enrollments: [{ id: "e-1", kind: "enroll", status: "awaiting_approval", expires_at: 1791000000 }] as Enrollment[],
    failureStatuses: new Map<string, number>(),
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
    if (path === "/api/v1/auth/status") return respond({ initialized: !options.initialize, authenticated: state.authenticated, user_id: "admin", workspace_id: "default", role: "system_admin", username: "admin", csrf_token: "test-csrf" });
    if (path === "/api/v1/auth/login" || path === "/api/v1/auth/initialize") { state.authenticated = true; return respond({ user_id: "admin", workspace_id: "default", role: "system_admin", username: "admin", csrf_token: "test-csrf" }); }
    if (path === "/api/v1/auth/recover") return respond({ username: "admin", message: "密码已更新，请重新登录" });
    if (path === "/api/v1/auth/password" || path === "/api/v1/auth/logout") return respond({});
    if (path === "/api/v1/auth/session") return respond(state.sessions[0]);
    if (path === "/api/v1/auth/sessions") return respond(state.sessions);
    if (path.startsWith("/api/v1/auth/sessions/")) { state.sessions = state.sessions.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    if (path.endsWith("/recovery") && path.startsWith("/api/v1/devices/")) { const invite: Enrollment = { id: "e-recovery", kind: "recovery", device_id: path.split("/")[4], status: "awaiting_agent", token: "recovery-token-for-test", expires_at: Math.floor(Date.now()/1000) + 3600 }; state.enrollments.push(invite); return respond(invite); }
    if (path === "/api/v1/devices") return respond(state.devices);
    if (path === "/api/v1/transport-identity") return respond(state.transportIdentity);
    if (path.startsWith("/api/v1/devices/") && method === "DELETE") { state.devices = state.devices.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    if (path === "/api/v1/enrollments" && method === "GET") return respond(state.enrollments);
    if (path === "/api/v1/enrollments" && method === "POST") return respond({ id: "e-new", status: "awaiting_agent", token: "one-time-secret-enrollment-token", expires_at: Math.floor(Date.now()/1000) + 3600 });
    if (path.startsWith("/api/v1/enrollments/") && method === "DELETE") { state.enrollments = state.enrollments.filter(item => item.id !== path.split("/").pop()); return respond({ revoked: true }); }
    if (path.endsWith("/approve")) { state.enrollments = []; return respond({}); }
    if (path.endsWith("/access")) { if (method === "POST") state.dnsChecked = true; return respond(access(state.domains.find(domain => domain.id === path.split("/")[4])?.domain ?? "example.com")); }
    if (path === "/api/v1/public-domains" && method === "GET") return respond(state.domains.map(domain => ({ ...domain, access: access(domain.domain) })));
    if (path === "/api/v1/public-domains" && method === "POST") { const item = { ...body, id: "d-2", is_primary: false, apply_status: "pending", runtime: { config_status: "pending", config_error: null, service_warning: null, checked_at: null, certificates: [] } }; state.domains.push(item); return respond(item, 201); }
    if (path === "/api/v1/public-domain-runtime-events") return respond({ events: state.domainEvents, next_cursor: null });
    if (path.startsWith("/api/v1/public-domains/") && method === "DELETE") { state.domains = state.domains.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    if (path === "/api/v1/tunnels" && method === "GET") return respond(state.tunnels);
    if (path === "/api/v1/tunnels" && method === "POST") { const item = { ...body, id: "t-new", public_address: "new.example.com", public_domain: "example.com", apply_status: "checking" }; state.tunnels.push(item); return respond(item, 201); }
    const toggle = path.match(/^\/api\/v1\/tunnels\/([^/]+)\/(enable|disable)$/);
    if (toggle) { const item = state.tunnels.find(item => item.id === toggle[1]); Object.assign(item, { enabled: toggle[2] === "enable", apply_status: toggle[2] === "enable" ? "checking" : "disabled" }); return respond(item); }
    if (path.startsWith("/api/v1/tunnels/") && method === "PUT") { const item = state.tunnels.find(item => item.id === path.split("/").pop()); Object.assign(item, body); return respond(item); }
    if (path.startsWith("/api/v1/tunnels/") && method === "DELETE") { state.tunnels = state.tunnels.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    return respond({ error: `未模拟的接口 ${method} ${path}` }, 404);
  });
  return state;
}
