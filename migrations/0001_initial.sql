-- Nexo 自有业务数据；Headscale 数据始终由 Headscale 自己管理。
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO schema_migrations (version) VALUES (1);

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 单机自托管首次启动提供一个可用的默认租户；后续 Web 初始化流程可继续扩展。
INSERT OR IGNORE INTO tenants (id, name) VALUES ('default', '默认租户');

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id),
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('system_admin', 'tenant')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sites (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    active_site_gateway_device_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    site_id TEXT REFERENCES sites(id),
    name TEXT NOT NULL,
    os TEXT,
    architecture TEXT,
    agent_version TEXT,
    status TEXT NOT NULL DEFAULT 'offline',
    capabilities_json TEXT NOT NULL DEFAULT '[]',
    enrolled_at TEXT,
    last_seen_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS site_networks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    site_id TEXT NOT NULL REFERENCES sites(id),
    name TEXT NOT NULL,
    publisher_device_id TEXT NOT NULL REFERENCES devices(id),
    interface_id TEXT NOT NULL,
    address_family TEXT NOT NULL CHECK (address_family IN ('ipv4', 'ipv6')),
    source TEXT NOT NULL DEFAULT 'direct_interface',
    current_prefix TEXT,
    last_prefix TEXT,
    follow_prefix_changes INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking',
    apply_revision INTEGER NOT NULL DEFAULT 0,
    apply_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS subnet_access (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    site_network_id TEXT NOT NULL REFERENCES site_networks(id),
    scope TEXT NOT NULL DEFAULT 'tenant_mesh' CHECK (scope = 'tenant_mesh'),
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, site_network_id)
);

CREATE TABLE IF NOT EXISTS site_links (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    left_site_id TEXT NOT NULL REFERENCES sites(id),
    right_site_id TEXT NOT NULL REFERENCES sites(id),
    enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking',
    apply_revision INTEGER NOT NULL DEFAULT 0,
    apply_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (left_site_id < right_site_id),
    UNIQUE (tenant_id, left_site_id, right_site_id)
);

CREATE TABLE IF NOT EXISTS site_link_networks (
    site_link_id TEXT NOT NULL REFERENCES site_links(id) ON DELETE CASCADE,
    site_network_id TEXT NOT NULL REFERENCES site_networks(id) ON DELETE CASCADE,
    side TEXT NOT NULL CHECK (side IN ('left', 'right')),
    PRIMARY KEY (site_link_id, site_network_id)
);

CREATE TABLE IF NOT EXISTS tunnels (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    device_id TEXT NOT NULL REFERENCES devices(id),
    name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'http', 'https')),
    local_address TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    public_port INTEGER,
    hostname TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking',
    apply_revision INTEGER NOT NULL DEFAULT 0,
    apply_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT REFERENCES tenants(id),
    actor_user_id TEXT REFERENCES users(id),
    event_type TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_site_networks_site ON site_networks(site_id);
CREATE INDEX IF NOT EXISTS idx_tunnels_device ON tunnels(device_id);
