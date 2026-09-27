-- 当前完整结构，仅首次初始化执行。
CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK(role IN ('system_admin','tenant')),
    password_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE TABLE auth_sessions (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_digest TEXT NOT NULL UNIQUE, csrf_digest TEXT NOT NULL,
    created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    browser TEXT, os TEXT
);

CREATE TABLE auth_recovery (id TEXT PRIMARY KEY, recovery_digest TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);

CREATE TABLE devices (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL, os TEXT, architecture TEXT, agent_version TEXT,
    status TEXT NOT NULL DEFAULT 'offline', enrolled_at INTEGER, last_seen_at INTEGER,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);

CREATE TABLE pending_enrollments (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_digest TEXT NOT NULL UNIQUE, status TEXT NOT NULL, expires_at INTEGER NOT NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL, created_at INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'recovery' CHECK(kind='recovery')
);

CREATE TABLE device_identities (device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE, secret_digest TEXT NOT NULL, created_at INTEGER NOT NULL);

CREATE TABLE public_domains (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain TEXT NOT NULL, is_primary INTEGER NOT NULL DEFAULT 0, https_enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    UNIQUE(tenant_id,domain)
);

CREATE TABLE public_domain_runtime_events (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, public_domain_id TEXT, summary TEXT NOT NULL, occurred_at INTEGER NOT NULL);

CREATE TABLE tunnel_applied_states (tunnel_id TEXT PRIMARY KEY REFERENCES tunnels(id) ON DELETE CASCADE, revision INTEGER NOT NULL, status TEXT NOT NULL, error_message TEXT, updated_at INTEGER NOT NULL, protocol_statuses TEXT NOT NULL DEFAULT '{}');

CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, actor_user_id TEXT, event_type TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT, created_at INTEGER NOT NULL);

CREATE TABLE enrollment_requests (
        enrollment_id TEXT PRIMARY KEY REFERENCES pending_enrollments(id) ON DELETE CASCADE,
        csr_pem TEXT NOT NULL, device_name TEXT NOT NULL, os TEXT, architecture TEXT,
        agent_version TEXT NOT NULL, certificate_pem TEXT
    );

CREATE TABLE device_certificates (
        device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
        certificate_pem TEXT, pending_csr_pem TEXT, pending_certificate_pem TEXT,
        retry_failures INTEGER NOT NULL DEFAULT 0, renewal_error TEXT, next_retry_at INTEGER
    );

CREATE TABLE agent_access_keys (
        tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
        token_digest TEXT NOT NULL UNIQUE, encrypted_token BLOB NOT NULL,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
    );

CREATE TABLE agent_registrations (
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        csr_pem TEXT NOT NULL, device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
        certificate_pem TEXT NOT NULL, created_at INTEGER NOT NULL,
        PRIMARY KEY(tenant_id,csr_pem)
    );

CREATE TABLE user_invitations (
        id TEXT PRIMARY KEY, token_digest TEXT NOT NULL UNIQUE,
        created_by TEXT NOT NULL REFERENCES users(id), created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL, used_by TEXT REFERENCES users(id), revoked_at INTEGER
    );

CREATE TABLE service_access_sessions (
        digest TEXT PRIMARY KEY, service_id TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL);

CREATE TABLE "tunnels" (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL, name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK(protocol IN ('tcp','http','https','udp','tcp_udp')), local_address TEXT NOT NULL,
    local_port INTEGER NOT NULL, public_port INTEGER, https_port INTEGER NOT NULL DEFAULT 443 CHECK(https_port BETWEEN 1 AND 65535), hostname TEXT, enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking', apply_error TEXT, apply_revision INTEGER NOT NULL DEFAULT 1,
    origin_protocol TEXT, origin_tls_server_name TEXT, origin_tls_verification TEXT NOT NULL DEFAULT 'system',
    public_domain_id TEXT REFERENCES public_domains(id) ON DELETE SET NULL,
    deleted_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
, http_redirect_enabled INTEGER NOT NULL DEFAULT 0, service_mode TEXT NOT NULL DEFAULT 'tunnel' CHECK(service_mode IN ('tunnel','reverse_proxy')), lan_redirect_enabled INTEGER NOT NULL DEFAULT 0, access_mode TEXT NOT NULL DEFAULT 'public' CHECK(access_mode IN ('public','password')), access_password_hash TEXT, protocol_statuses TEXT NOT NULL DEFAULT '{}');

CREATE TABLE traffic_minutes (
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        tunnel_id TEXT NOT NULL, minute INTEGER NOT NULL,
        to_origin INTEGER NOT NULL, to_public INTEGER NOT NULL,
        PRIMARY KEY(tenant_id,tunnel_id,minute));

CREATE TABLE traffic_coverage (minute INTEGER PRIMARY KEY, seconds REAL NOT NULL);

CREATE TABLE traffic_daily (
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        day INTEGER NOT NULL, to_origin INTEGER NOT NULL, to_public INTEGER NOT NULL,
        PRIMARY KEY(tenant_id,day));

CREATE TABLE traffic_daily_coverage (day INTEGER PRIMARY KEY, seconds REAL NOT NULL);

CREATE TABLE traffic_usage_state (id INTEGER PRIMARY KEY CHECK(id=1), started_at INTEGER NOT NULL);

CREATE TABLE traffic_usage_resets (
        tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE, reset_at INTEGER NOT NULL);

CREATE TABLE traffic_quota_state (
        id INTEGER PRIMARY KEY CHECK(id=1), started_at INTEGER NOT NULL);

CREATE TABLE traffic_quota_limits (
        tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
        monthly_limit_bytes INTEGER CHECK(monthly_limit_bytes>0 AND monthly_limit_bytes<=9007199254740991));

CREATE TABLE traffic_quota_months (
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        month INTEGER NOT NULL, used_bytes INTEGER NOT NULL,
        PRIMARY KEY(tenant_id,month));

CREATE TABLE server_settings (
        id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL
    );

CREATE TABLE domain_settings (
        domain_id TEXT PRIMARY KEY REFERENCES public_domains(id) ON DELETE CASCADE,
        certificate_mode TEXT NOT NULL CHECK(certificate_mode IN ('http01','cloudflare_dns')),
        verified INTEGER NOT NULL DEFAULT 0, verification_token TEXT NOT NULL,
        credential_file TEXT, dns_resolvers TEXT NOT NULL DEFAULT '[]',
        propagation_delay INTEGER, propagation_timeout INTEGER
    );

CREATE INDEX idx_devices_tenant ON devices(tenant_id);

CREATE INDEX idx_enrollments_tenant ON pending_enrollments(tenant_id,status);

CREATE INDEX service_access_sessions_service ON service_access_sessions(service_id);

CREATE INDEX idx_tunnels_tenant ON tunnels(tenant_id,deleted_at);

CREATE UNIQUE INDEX idx_tunnels_tcp_port ON tunnels(public_port) WHERE deleted_at IS NULL AND public_port IS NOT NULL AND protocol IN ('tcp','tcp_udp');

CREATE UNIQUE INDEX idx_tunnels_udp_port ON tunnels(public_port) WHERE deleted_at IS NULL AND public_port IS NOT NULL AND protocol IN ('udp','tcp_udp');

CREATE INDEX traffic_minutes_time ON traffic_minutes(minute);

CREATE TRIGGER revoke_service_access AFTER UPDATE ON tunnels
        WHEN OLD.access_mode IS NOT NEW.access_mode OR OLD.access_password_hash IS NOT NEW.access_password_hash
          OR OLD.hostname IS NOT NEW.hostname OR OLD.public_domain_id IS NOT NEW.public_domain_id
          OR OLD.protocol IS NOT NEW.protocol OR NEW.enabled=0 OR NEW.deleted_at IS NOT NULL
        BEGIN DELETE FROM service_access_sessions WHERE service_id=NEW.id; END;
INSERT INTO tenants(id,name,created_at,enabled) VALUES('default','默认工作空间',unixepoch(),1);
INSERT INTO traffic_usage_state VALUES(1,unixepoch());
INSERT INTO traffic_quota_state VALUES(1,unixepoch());
