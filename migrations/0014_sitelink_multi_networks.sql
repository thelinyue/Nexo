-- 第五阶段：共享网络允许管理员声明手动 CIDR，SiteLink 支持每侧多个网段。
--
-- SQLite 不能直接把已有 NOT NULL 列改为可空，因此重建 site_networks；
-- 复制过程保留旧的 direct_interface 数据和所有 Desired / Applied 状态引用。
CREATE TABLE site_networks_v14 (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    site_id TEXT NOT NULL REFERENCES sites(id),
    name TEXT NOT NULL,
    publisher_device_id TEXT NOT NULL REFERENCES devices(id),
    interface_id TEXT,
    address_family TEXT NOT NULL CHECK (address_family IN ('ipv4', 'ipv6')),
    source TEXT NOT NULL DEFAULT 'direct_interface'
        CHECK (source IN ('direct_interface', 'manual')),
    current_prefix TEXT,
    last_prefix TEXT,
    follow_prefix_changes INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking',
    apply_revision INTEGER NOT NULL DEFAULT 0,
    apply_error TEXT,
    deletion_requested INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO site_networks_v14 (
    id, tenant_id, site_id, name, publisher_device_id, interface_id,
    address_family, source, current_prefix, last_prefix, follow_prefix_changes,
    enabled, apply_status, apply_revision, apply_error, deletion_requested,
    created_at, updated_at
)
SELECT
    id, tenant_id, site_id, name, publisher_device_id, interface_id,
    address_family, source, current_prefix, last_prefix, follow_prefix_changes,
    enabled, apply_status, apply_revision, apply_error, deletion_requested,
    created_at, updated_at
FROM site_networks;

DROP TABLE site_networks;
ALTER TABLE site_networks_v14 RENAME TO site_networks;
CREATE INDEX IF NOT EXISTS idx_site_networks_site ON site_networks(site_id);
CREATE INDEX IF NOT EXISTS idx_site_networks_publisher ON site_networks(publisher_device_id);

ALTER TABLE site_links ADD COLUMN left_ipv4_next_hop TEXT;
ALTER TABLE site_links ADD COLUMN left_ipv6_next_hop TEXT;
ALTER TABLE site_links ADD COLUMN right_ipv4_next_hop TEXT;
ALTER TABLE site_links ADD COLUMN right_ipv6_next_hop TEXT;

INSERT OR IGNORE INTO schema_migrations (version) VALUES (14);
