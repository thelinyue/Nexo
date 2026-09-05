-- 第二阶段：公网入口、管理员 Session 与 Tunnel Desired/Applied 状态。
-- 所有 Secret 只保存于 Nexo 数据目录下的 0600 文件；SQLite 只保存摘要和元数据。

CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_digest TEXT NOT NULL UNIQUE,
    csrf_digest TEXT NOT NULL,
    channel TEXT NOT NULL CHECK (channel IN ('local_http', 'public_https')),
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_digest ON auth_sessions(session_digest);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id, revoked_at);

CREATE TABLE IF NOT EXISTS auth_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    source TEXT NOT NULL,
    attempted_at INTEGER NOT NULL,
    succeeded INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_window
    ON auth_login_attempts(username, source, attempted_at);

CREATE TABLE IF NOT EXISTS auth_recovery_sessions (
    id TEXT PRIMARY KEY,
    code_digest TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);

CREATE TABLE IF NOT EXISTS public_entry_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    base_domain TEXT,
    https_enabled INTEGER NOT NULL DEFAULT 0,
    certificate_mode TEXT NOT NULL DEFAULT 'none'
        CHECK (certificate_mode IN ('none', 'manual', 'cloudflare')),
    acme_environment TEXT NOT NULL DEFAULT 'production'
        CHECK (acme_environment IN ('staging', 'production')),
    desired_revision INTEGER NOT NULL DEFAULT 0,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    apply_status TEXT NOT NULL DEFAULT 'not_configured'
        CHECK (apply_status IN ('not_configured', 'configuring', 'ready', 'error')),
    apply_error TEXT,
    certificate_not_before INTEGER,
    certificate_not_after INTEGER,
    certificate_subjects_json TEXT NOT NULL DEFAULT '[]',
    dns_check_json TEXT NOT NULL DEFAULT '{}',
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT OR IGNORE INTO public_entry_settings (id, tenant_id)
VALUES (1, 'default');

CREATE TABLE IF NOT EXISTS tunnel_applied_states (
    tunnel_id TEXT PRIMARY KEY REFERENCES tunnels(id) ON DELETE CASCADE,
    applied_revision INTEGER NOT NULL,
    applied_config_json TEXT NOT NULL,
    apply_status TEXT NOT NULL DEFAULT 'checking'
        CHECK (apply_status IN ('disabled', 'checking', 'applying', 'ready', 'retrying', 'failed')),
    apply_error TEXT,
    last_checked_at INTEGER,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Web Service 的 Origin 和用户可见服务名称属于 Tunnel 本身；迁移兼容旧表时
-- 由 Server 的幂等字段检查补齐同名列。
-- SQLite 不允许在 CREATE TABLE 迁移中重复 ADD COLUMN，因此新数据库也由
-- Server 启动时统一执行 ensure_phase2_tunnel_columns。

INSERT OR IGNORE INTO schema_migrations (version) VALUES (10);
