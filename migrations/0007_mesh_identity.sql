-- 第一阶段：Nexo 与 Headscale/Tailscale 的稳定身份关系。
-- 这里仅保存 Nexo 自己的映射和 Pre-auth Key 元数据，不读取 Headscale 内部数据库。
CREATE TABLE IF NOT EXISTS mesh_tenant_mappings (
    tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    headscale_user_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'ready', 'failed')),
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mesh_identities (
    nexo_device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    headscale_node_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'ready'
        CHECK (state IN ('enrolling', 'ready', 'mesh_identity_mismatch', 'disabled', 'failed')),
    tailscale_ipv4 TEXT,
    tailscale_ipv6 TEXT,
    hostname TEXT,
    last_verified_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mesh_identities_tenant
    ON mesh_identities (tenant_id);

CREATE TABLE IF NOT EXISTS mesh_enrollment_attempts (
    id TEXT PRIMARY KEY,
    nexo_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    headscale_pre_auth_key_id TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'issued'
        CHECK (state IN ('issued', 'consumed', 'expired', 'revoked', 'failed')),
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mesh_enrollment_attempts_device
    ON mesh_enrollment_attempts (nexo_device_id, created_at DESC);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (7);
