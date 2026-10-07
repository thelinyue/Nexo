import type { Page } from "@playwright/test";
import type { Tunnel, Device, Domain, DomainEvent, Enrollment, TransportIdentity, DnsRecord, DomainDnsPreview } from "../src/ui";

/** 使用真实接口形状覆盖交互；失败注入用于验证界面不会把请求失败当作成功。 */
export async function installApiMocks(page: Page, options: { empty?: boolean; anonymous?: boolean } = {}) {
  const state = {
    authenticated: !options.anonymous,
    initialized: true,
    authRole: "system_admin" as "system_admin" | "tenant",
    sharedIcons: [] as {id: string; name: string; created_at: number; data_url: string}[],
    users: [{ id: "admin", username: "admin", role: "system_admin", workspace_id: "default", workspace_name: "admin的工作空间", enabled: true, devices: 2, services: 1, domains: 1 }, { id: "alice", username: "alice", role: "tenant", workspace_id: "alice-space", workspace_name: "alice 的工作空间", enabled: true, devices: 1, services: 1, domains: 0 }],
    accessKey: "nexo_join_shared-test-key",
    agentRelease: { version: "0.2.14", release_url: "https://github.com/thelinyue/Nexo/releases/tag/v0.2.14" } as { version: string | null; release_url: string | null },
    tunnels: (options.empty ? [] : [{ id: "t-1", name: "媒体中心", protocol: "https", local_address: "127.0.0.1", local_port: 8096, public_port: null, public_address: "https://media.example.com/a-very-long-public-address", hostname: "media", public_domain: "example.com", device_id: "a-1", device_name: "家庭设备", enabled: true, apply_status: "ready", apply_error: null, lan_redirect_enabled: false }] as any[]) as Tunnel[],
    devices: [{ id: "a-1", name: "家庭设备", status: "online", os: "Linux", architecture: "amd64", last_seen_at: 1790000000, agent_version: "0.2.0", tunnel_count: 1 }, { id: "a-2", name: "备用设备", status: "offline", os: "Linux", agent_version: "0.2.0", tunnel_count: 0 }] as Device[],
    transportIdentity: { server: { status: "valid", expires_at: Math.floor(Date.now()/1000) + 825*86400, renew_after: Math.floor(Date.now()/1000) + 795*86400, error: null, next_retry_at: null }, ca_expires_at: Math.floor(Date.now()/1000) + 3650*86400, ca_needs_attention: false } as TransportIdentity,
    serverSettings: { management_entry: null as { domain_id: string; hostname: string } | null, public_url: "", public_ips: ["203.0.113.7"], relay_ipv4: "203.0.113.7", domains: [{ id: "d-1", domain: "example.com" }], caddy_enabled: true, status: "disabled", error: null as string | null },
    domains: [{ id: "d-1", domain: "example.com", is_primary: true, https_enabled: true, certificate_mode: "cloudflare_dns", dns_provider: "cloudflare", credential_configured: true, verification_status: "verified", apply_status: "applied", runtime: { config_status: "applied", config_error: null, service_warning: null, checked_at: Math.floor(Date.now() / 1000), certificates: [{ hostname: "example.com", status: "issued", not_before: Math.floor(Date.now() / 1000) - 3600, expires_at: Math.floor(Date.now() / 1000) + 90 * 86400, error: null, next_retry_at: null }] } }] as Domain[],
    dnsRecords: new Map<string, DnsRecord[]>(),
    domainEvents: [{ id: 1, domain_id: "d-1", summary: "配置已加载", occurred_at: Math.floor(Date.now() / 1000) }] as DomainEvent[],
    enrollments: [{ id: "e-1", kind: "recovery", device_id: "a-1", status: "awaiting_approval", expires_at: 1791000000 }] as Enrollment[],
    failureStatuses: new Map<string, number>(),
    trafficResets: new Map<string, number>(),
    quotas: new Map<string, { monthly_limit_bytes: number | null; used_bytes: number }>(),
    sessions: [{ id: "s-current", last_seen_at: 1790000000, expires_at: 1791000000 }, { id: "s-other", last_seen_at: 1790000000, expires_at: 1791000000 }],
    failures: new Map<string, string>(), calls: [] as { method: string; path: string; body: any }[], delay: 0,
  };
  await page.route("**/api/v1/**", async route => {
    const req = route.request(); const path = new URL(req.url()).pathname; const method = req.method(); const body = req.postData() ? req.postDataJSON() : null;
    state.calls.push({ method, path, body: structuredClone(body) });
    const respond = (value: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
    const saveIcon = () => {
      if (!body?.icon_upload) return;
      const id = `upload/${crypto.randomUUID()}`;
      state.sharedIcons.unshift({ ...body.icon_upload, id, created_at: Math.floor(Date.now()/1000) });
      delete body.icon_upload;
      body.icon_id = id;
    };
    const failure = state.failures.get(`${method} ${path}`);
    if (failure) { const status = state.failureStatuses.get(`${method} ${path}`) ?? 503; return respond({ error: failure, ...(status === 401 && !path.endsWith("/login") && !path.endsWith("/recover") ? { code: "session_expired" } : {}) }, status); }
    if (state.delay && method === "GET") await new Promise(resolve => setTimeout(resolve, state.delay));
    if (path === "/api/v1/service-icons" && method === "GET") return respond(state.sharedIcons.map(({data_url, ...icon}) => icon));
    if (path === "/api/v1/service-icons/preview") {
      if (state.authRole !== "system_admin" && body.url.includes("192.168.")) return respond({error:"内网图片仅允许管理员导入"},400);
      return respond({ name: "链接图标.png", data_url: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAYAAADED76LAAAAFklEQVR4nGMUm5b5nwEPYMInOXwUAAAnjQIk3eIgUgAAAABJRU5ErkJggg==" });
    }
    const sharedIcon = path.match(/^\/api\/v1\/service-icons\/([^/]+)(\/image)?$/);
    if (sharedIcon) {
      const icon = state.sharedIcons.find(icon => icon.id === `upload/${sharedIcon[1]}`);
      if (!icon) return respond({error:"共享图标不存在"},404);
      if (sharedIcon[2]) return route.fulfill({contentType:"image/png",body:Buffer.from(icon.data_url.split(',')[1],"base64")});
      if (method === "DELETE") {
        if (state.authRole !== "system_admin") return respond({error:"此操作需要管理员权限"},403);
        if (state.tunnels.some(tunnel => tunnel.icon_id === icon.id)) return respond({error:"图标正在被服务使用，请先更换这些服务的图标"},409);
        state.sharedIcons = state.sharedIcons.filter(item => item.id !== icon.id); return respond({deleted:true});
      }
    }
    if (path.endsWith("/node-update-jobs")) return respond([]);
    if (path.endsWith("/node-releases")) return respond([{ version: "0.2.12", architectures: ["aarch64", "x86_64"] }]);
    if (path.endsWith("/node-groups")) return respond([]);
    if (path.endsWith("/nodes")) return respond({ nodes: [{ id: "local", name: "内置节点", reverse_proxy_supported: true, reverse_proxy_selectable: true, approved: true, enabled: true, status: "online", latencies: [], services: [], connections: 0 }], server_version: "0.2.12" });
    if (path === "/api/v1/admin/users") return respond(state.users);
    if (path === "/api/v1/admin/invitations") return respond([]);
    if (path === "/api/v1/admin/server-settings") {
      if (method === "PUT") {
        Object.assign(state.serverSettings, body);
        const entry = state.serverSettings.management_entry;
        state.serverSettings.public_url = entry ? `https://${entry.hostname}.${state.serverSettings.domains.find(domain => domain.id === entry.domain_id)?.domain}` : "";
        state.serverSettings.status = entry ? "certificate_pending" : "disabled";
      }
      return respond(state.serverSettings);
    }
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
    if (path === "/api/v1/auth/status") return respond({ initialized: state.initialized, authenticated: state.authenticated, user_id: "admin", workspace_id: "default", role: state.authRole, username: "admin", csrf_token: "test-csrf" });
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
    if (path === "/api/v1/agent-release") return respond(state.agentRelease);
    if (path === "/api/v1/transport-identity") return respond(state.transportIdentity);
    if (path.startsWith("/api/v1/devices/") && method === "DELETE") { state.devices = state.devices.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    if (path === "/api/v1/enrollments" && method === "GET") return respond(state.enrollments);
    if (path.startsWith("/api/v1/enrollments/") && method === "GET") return respond(state.enrollments.find(item => item.id === path.split("/").pop()) ?? { id: path.split("/").pop(), status: "awaiting_agent", expires_at: Math.floor(Date.now()/1000) + 3600 });
    if (path.startsWith("/api/v1/enrollments/") && method === "DELETE") { state.enrollments = state.enrollments.filter(item => item.id !== path.split("/").pop()); return respond({ revoked: true }); }
    if (path.endsWith("/approve")) { const invite = state.enrollments.find(item => item.id === path.split("/").at(-2)); if (invite) Object.assign(invite, { status: "approved", device_id: invite.device_id ?? "a-1" }); return respond(invite ?? {}); }
    if (path === "/api/v1/public-domains" && method === "GET") return respond(state.domains);
    if (path === "/api/v1/public-domains" && method === "POST") { const item = { ...body, id: "d-2", is_primary: false, certificate_mode: "cloudflare_dns", dns_provider: "cloudflare", verification_status: "pending", credential_configured: false, dns_resolvers: [], verification_record: { name: `_nexo-verification.${body.domain}`, value: "new-domain-proof" }, apply_status: "pending", runtime: { config_status: "pending", config_error: null, service_warning: null, checked_at: null, certificates: [] } }; state.domains.push(item); return respond(item, 201); }
    const domainAction = path.match(/^\/api\/v1\/(?:admin\/workspaces\/[^/]+\/)?public-domains\/([^/]+)(?:\/(cloudflare-credential|dns-credential|dns-records))?$/);
    if (domainAction && ["PUT", "PATCH", "GET", "POST"].includes(method)) {
      const domain = state.domains.find(item => item.id === domainAction[1]);
      if (!domain) return respond({ error: "域名不存在" }, 404);
      if (method === "PUT") { Object.assign(domain, { dns_provider: body.provider ?? "cloudflare", credential_configured: true, verification_status: "verified", verification_record: null }); return respond(domain); }
      if (method === "PATCH") { Object.assign(domain, body); return respond(domain); }
      if (domainAction[2] === "dns-records") {
        if (!domain.credential_configured) return respond({ error: "请先验证并保存域名的 DNS 凭据" }, 400);
        if (method === "GET") {
          const preview: DomainDnsPreview = { ipv4: "8.8.8.8", provider: domain.dns_provider ?? "cloudflare", credential_revision: "credential-test.token", hosts: [domain.domain, `*.${domain.domain}`].map(hostname => {
            const existing = state.dnsRecords.get(hostname) ?? [];
            const access = existing.filter(record => ["A", "CNAME"].includes(record.kind));
            return { hostname, existing, blocked: null, action: !access.length ? "create" : access.length === 1 && access[0].kind === "A" && access[0].value === "8.8.8.8" && !access[0].proxied ? "reuse" : "takeover" };
          }) };
          return respond(preview);
        }
        const preview = body.preview as DomainDnsPreview;
        return respond({ hosts: preview.hosts.map(host => {
          state.dnsRecords.set(host.hostname, [...host.existing.filter(record => !["A", "CNAME"].includes(record.kind)), { id: `a-${host.hostname}`, name: host.hostname, kind: "A", value: preview.ipv4, ttl: 600, proxied: false }]);
          return { hostname: host.hostname, status: host.action === "reuse" ? "unchanged" : "written", error: null };
        }) });
      }
    }
    if (path === "/api/v1/public-domain-runtime-events") return respond({ events: state.domainEvents.filter(event => !new URL(req.url()).searchParams.has("domain_id") || event.domain_id === new URL(req.url()).searchParams.get("domain_id")), next_cursor: null });
    if (path.startsWith("/api/v1/public-domains/") && method === "DELETE") { state.domains = state.domains.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    if (path === "/api/v1/tunnels" && method === "GET") return respond(state.tunnels);
    if (path === "/api/v1/tunnels" && method === "POST") { saveIcon(); const item = { access_mode: "public", lan_redirect_enabled: false, ...body, id: "t-new", public_address: "new.example.com", public_domain: state.domains.find(domain => domain.id === body.public_domain_id)?.domain ?? null, apply_status: "checking" }; delete item.access_password; state.tunnels.push(item); return respond(item, 201); }
    if (path === "/api/v1/tunnels/batch" && method === "DELETE") { state.tunnels = state.tunnels.filter(item => !body.tunnel_ids.includes(item.id)); return respond({ deleted_ids: body.tunnel_ids }); }
    if (/^\/api\/v1\/tunnels\/batch\/(enable|disable)$/.test(path)) { const items = state.tunnels.filter(item => body.tunnel_ids.includes(item.id)); items.forEach(item => Object.assign(item, { enabled: path.endsWith("/enable"), apply_status: path.endsWith("/enable") ? "checking" : "disabled" })); return respond(items); }
    const toggle = path.match(/^\/api\/v1\/tunnels\/([^/]+)\/(enable|disable)$/);
    if (toggle) { const item = state.tunnels.find(item => item.id === toggle[1]); Object.assign(item, { enabled: toggle[2] === "enable", apply_status: toggle[2] === "enable" ? "checking" : "disabled" }); return respond(item); }
    if (path.startsWith("/api/v1/tunnels/") && method === "PUT") {
      saveIcon();
      const item = state.tunnels.find(item => item.id === path.split("/").pop())!;
      const domain = state.domains.find(domain => domain.id === body.public_domain_id);
      if (domain && domain.domain !== item.public_domain) {
        item.public_address = item.public_address?.replace(`${item.hostname}.${item.public_domain}`, `${body.hostname}.${domain.domain}`);
        item.public_domain = domain.domain;
      }
      Object.assign(item, body, { lan_redirect_enabled: ["tcp", "udp", "tcp_udp"].includes(body.protocol) ? false : body.lan_redirect_enabled ?? item.lan_redirect_enabled ?? false }); delete item.access_password; return respond(item);
    }
    if (path.startsWith("/api/v1/tunnels/") && method === "DELETE") { state.tunnels = state.tunnels.filter(item => item.id !== path.split("/").pop()); return respond({}); }
    return respond({ error: `未模拟的接口 ${method} ${path}` }, 404);
  });
  return state;
}
