-- 设备显示名称与 MagicDNS 访问名称解耦。
-- mesh_name 是 Nexo 期望应用到 Headscale 的单标签名称；实际已应用名称
-- 仍记录在 mesh_identities.hostname，便于 Headscale 暂时不可用时安全重试。
ALTER TABLE devices ADD COLUMN mesh_name TEXT;

CREATE UNIQUE INDEX idx_devices_mesh_name_ci
    ON devices (LOWER(mesh_name))
    WHERE mesh_name IS NOT NULL AND trim(mesh_name) <> '';

INSERT INTO schema_migrations (version) VALUES (24);
