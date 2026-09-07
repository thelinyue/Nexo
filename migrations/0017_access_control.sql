-- v0.3：可视化访问控制的结构化规则。
--
-- 规则只保存 Nexo 的所有权和期望状态；Headscale Policy 仍由适配器负责
-- 校验和发布。受让工作空间是直接关系，不允许通过它继续转授权。
CREATE TABLE IF NOT EXISTS mesh_access_rules (
    id TEXT PRIMARY KEY,
    owner_tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    target_type TEXT NOT NULL
        CHECK (target_type IN ('device', 'network', 'exit_node', 'file_share')),
    target_id TEXT NOT NULL,
    protocols_json TEXT NOT NULL DEFAULT '["tcp", "udp"]',
    ports_json TEXT NOT NULL DEFAULT '["*"]',
    ssh_enabled INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    desired_revision INTEGER NOT NULL DEFAULT 1,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    apply_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (apply_status IN ('pending', 'checking', 'applying', 'ready', 'error', 'disabled')),
    apply_error TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (owner_tenant_id, name)
);

CREATE TABLE IF NOT EXISTS mesh_access_grants (
    rule_id TEXT NOT NULL REFERENCES mesh_access_rules(id) ON DELETE CASCADE,
    grantee_tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'accepted'
        CHECK (status IN ('pending', 'accepted', 'revoked')),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    accepted_at INTEGER,
    PRIMARY KEY (rule_id, grantee_tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_mesh_access_rules_owner
    ON mesh_access_rules(owner_tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_mesh_access_grants_tenant
    ON mesh_access_grants(grantee_tenant_id, status);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (17);
