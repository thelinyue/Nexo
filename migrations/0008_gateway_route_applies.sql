-- 第一阶段：逐设备、逐路由的 Desired / Applied 收敛状态。
-- site_link_id 为空时使用空字符串，避免 SQLite NULL 主键语义导致重复状态。
CREATE TABLE IF NOT EXISTS gateway_route_applies (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    network_id TEXT NOT NULL REFERENCES site_networks(id) ON DELETE CASCADE,
    site_link_id TEXT NOT NULL DEFAULT '',
    desired_revision INTEGER NOT NULL DEFAULT 1,
    local_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (local_status IN ('pending', 'applied', 'failed', 'disabled', 'upgrade_required')),
    control_plane_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (control_plane_status IN ('pending', 'discovered', 'approved', 'serving', 'failed', 'disabled')),
    remote_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (remote_status IN ('pending', 'accepted', 'failed', 'disabled')),
    applied_prefix TEXT,
    last_error TEXT,
    last_checked_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, network_id, site_link_id)
);

CREATE TABLE IF NOT EXISTS site_link_route_confirmations (
    site_link_id TEXT NOT NULL REFERENCES site_links(id) ON DELETE CASCADE,
    site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    confirmed_at TEXT NOT NULL,
    PRIMARY KEY (site_link_id, site_id)
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (8);
