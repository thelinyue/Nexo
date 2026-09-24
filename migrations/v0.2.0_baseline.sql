PRAGMA foreign_keys = ON;

CREATE TABLE product_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO product_metadata (key,value) VALUES ('generation','tunnel-only-v1');

CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL);
INSERT INTO tenants (id,name,created_at) VALUES ('default','默认工作空间',unixepoch());
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
    created_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
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
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL, created_at INTEGER NOT NULL
);
CREATE TABLE device_identities (device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE, secret_digest TEXT NOT NULL, created_at INTEGER NOT NULL);

CREATE TABLE public_domains (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain TEXT NOT NULL, is_primary INTEGER NOT NULL DEFAULT 0, https_enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    UNIQUE(tenant_id,domain)
);
CREATE TABLE public_domain_runtime_events (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, public_domain_id TEXT, summary TEXT NOT NULL, occurred_at INTEGER NOT NULL);

CREATE TABLE tunnels (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL, name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK(protocol IN ('tcp','http','https')), local_address TEXT NOT NULL,
    local_port INTEGER NOT NULL, public_port INTEGER, hostname TEXT, enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking', apply_error TEXT, apply_revision INTEGER NOT NULL DEFAULT 1,
    origin_protocol TEXT, origin_tls_server_name TEXT, origin_tls_verification TEXT NOT NULL DEFAULT 'system',
    public_domain_id TEXT REFERENCES public_domains(id) ON DELETE SET NULL,
    deleted_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE tunnel_applied_states (tunnel_id TEXT PRIMARY KEY REFERENCES tunnels(id) ON DELETE CASCADE, revision INTEGER NOT NULL, status TEXT NOT NULL, error_message TEXT, updated_at INTEGER NOT NULL);
CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT, actor_user_id TEXT, event_type TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT, created_at INTEGER NOT NULL);
CREATE INDEX idx_devices_tenant ON devices(tenant_id);
CREATE INDEX idx_enrollments_tenant ON pending_enrollments(tenant_id,status);
CREATE INDEX idx_tunnels_tenant ON tunnels(tenant_id,deleted_at);
CREATE UNIQUE INDEX idx_tunnels_public_port ON tunnels(public_port) WHERE deleted_at IS NULL AND public_port IS NOT NULL;
