-- 第一阶段：官方 Tailscale 客户端的业务映射。
-- Headscale 仍是节点和密钥的唯一控制面，Nexo 只保存所有权、展示和审批状态。
CREATE TABLE IF NOT EXISTS tailscale_device_metadata (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    registration_method TEXT NOT NULL DEFAULT 'browser'
        CHECK (registration_method IN ('browser', 'auth_key', 'oidc')),
    tags_json TEXT NOT NULL DEFAULT '[]',
    tailscale_ipv4 TEXT,
    tailscale_ipv6 TEXT,
    expires_at INTEGER,
    control_plane_state TEXT NOT NULL DEFAULT 'unknown'
        CHECK (control_plane_state IN ('pending', 'ready', 'isolated', 'revoked', 'unknown')),
    external_node INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS tailscale_external_nodes (
    node_id TEXT PRIMARY KEY,
    node_name TEXT NOT NULL,
    node_json TEXT NOT NULL,
    discovered_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen_at INTEGER NOT NULL DEFAULT (unixepoch()),
    claimed_device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    claim_state TEXT NOT NULL DEFAULT 'isolated'
        CHECK (claim_state IN ('isolated', 'claimed', 'rejected'))
);

CREATE TABLE IF NOT EXISTS tailscale_auth_keys (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    headscale_key_id TEXT NOT NULL UNIQUE,
    key_digest TEXT NOT NULL,
    label TEXT NOT NULL,
    reusable INTEGER NOT NULL DEFAULT 0,
    ephemeral INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'issued'
        CHECK (state IN ('issued', 'used', 'expired', 'revoked', 'unknown')),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    revealed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_tailscale_device_metadata_user
    ON tailscale_device_metadata(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_tailscale_external_nodes_state
    ON tailscale_external_nodes(claim_state, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_tailscale_auth_keys_tenant
    ON tailscale_auth_keys(tenant_id, created_at DESC);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (16);
