-- v0.1.12：Nexo 账号状态、固定 OIDC 签名密钥和 Headscale OIDC 账号映射。
--
-- 该迁移只从已经完成 v0.1.12 基线（schema_migrations=19）的数据库执行。
-- 私钥受 SQLite 数据文件权限保护，永远不会通过 API、日志或 Web 返回。
DROP TABLE IF EXISTS public_entry_settings;

ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN mesh_revocation_pending INTEGER NOT NULL DEFAULT 0;

CREATE TABLE oidc_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    issuer TEXT,
    private_key_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE mesh_oidc_accounts (
    nexo_user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    workspace_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL UNIQUE,
    headscale_user_id TEXT UNIQUE,
    sync_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (sync_status IN ('pending', 'ready', 'revoked', 'error')),
    last_error TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_mesh_oidc_accounts_workspace
    ON mesh_oidc_accounts(workspace_id, sync_status);
CREATE INDEX idx_users_mesh_revocation
    ON users(mesh_revocation_pending, enabled);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (20);
