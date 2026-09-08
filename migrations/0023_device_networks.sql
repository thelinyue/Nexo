-- 普通共享网段直接归属设备；保留网段、身份及公网资源，仅移除站点互联。
DROP TABLE site_link_route_confirmations;
DROP TABLE site_link_networks;
DROP TABLE site_links;
DROP INDEX IF EXISTS idx_site_networks_site;
ALTER TABLE devices DROP COLUMN site_id;
ALTER TABLE pending_enrollments DROP COLUMN site_id;
ALTER TABLE site_networks DROP COLUMN site_id;
DROP TABLE sites;

CREATE TABLE gateway_route_applies_v23 (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    network_id TEXT NOT NULL REFERENCES site_networks(id) ON DELETE CASCADE,
    desired_revision INTEGER NOT NULL DEFAULT 1,
    local_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (local_status IN ('pending', 'applied', 'failed', 'disabled', 'upgrade_required')),
    control_plane_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (control_plane_status IN ('pending', 'discovered', 'approved', 'serving', 'failed', 'disabled')),
    applied_prefix TEXT,
    last_error TEXT,
    last_checked_at TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, network_id)
);
INSERT INTO gateway_route_applies_v23
    SELECT device_id, network_id, desired_revision, local_status,
           control_plane_status, applied_prefix, last_error, last_checked_at, updated_at
    FROM gateway_route_applies WHERE site_link_id = '';
DROP TABLE gateway_route_applies;
ALTER TABLE gateway_route_applies_v23 RENAME TO gateway_route_applies;

-- 升级后重新核对路由与授权，不将旧配置的成功状态当作新配置已应用。
UPDATE gateway_network_states SET desired_revision = desired_revision + 1,
    apply_status = 'checking', applied_prefix = NULL, updated_at = CURRENT_TIMESTAMP;
UPDATE gateway_route_applies SET local_status = 'pending', control_plane_status = 'pending';
UPDATE devices SET capabilities_json = (
    SELECT json_group_array(value) FROM json_each(devices.capabilities_json)
    WHERE value <> 'site_gateway'
);
UPDATE pending_enrollments SET requested_capabilities_json = (
    SELECT json_group_array(value) FROM json_each(pending_enrollments.requested_capabilities_json)
    WHERE value <> 'site_gateway'
) WHERE requested_capabilities_json IS NOT NULL;
-- 未知来源节点仍保持隔离；清除旧快照中不需要保存的密钥明文。
UPDATE tailscale_external_nodes SET node_json = json_remove(node_json, '$.pre_auth_key.key');
INSERT INTO schema_migrations (version) VALUES (23);
