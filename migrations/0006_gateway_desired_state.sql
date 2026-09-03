-- 第三阶段：网关配置的 Desired / Applied 状态边界。
-- Applied 为空并不代表失败，而是等待 Agent 与 Headscale Adapter 应用确认。
CREATE TABLE IF NOT EXISTS gateway_network_states (
    site_network_id TEXT PRIMARY KEY REFERENCES site_networks(id) ON DELETE CASCADE,
    desired_prefix TEXT NOT NULL,
    applied_prefix TEXT,
    desired_revision INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking'
        CHECK (apply_status IN ('disabled', 'checking', 'applying', 'ready', 'retrying', 'failed')),
    apply_error TEXT,
    last_checked_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (6);
