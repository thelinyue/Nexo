-- 第四阶段：允许设备删除后保留 Tunnel 配置，并进入未分配状态。
-- 具体重建由 Server 在外键关闭的短事务中执行；本脚本只提供新表定义和版本记录。
CREATE TABLE tunnels_new (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'http', 'https')),
    local_address TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    public_port INTEGER,
    hostname TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    apply_status TEXT NOT NULL DEFAULT 'checking',
    apply_error TEXT,
    apply_revision INTEGER NOT NULL DEFAULT 0,
    origin_protocol TEXT,
    origin_tls_server_name TEXT,
    origin_tls_verification TEXT NOT NULL DEFAULT 'system',
    service_name TEXT,
    bridge_socket_path TEXT,
    origin_ca_secret_path TEXT,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    deleted_at INTEGER,
    deletion_requested INTEGER NOT NULL DEFAULT 0,
    deletion_revision INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO tunnels_new (
    id, tenant_id, device_id, name, protocol, local_address, local_port,
    public_port, hostname, enabled, apply_status, apply_error, apply_revision,
    origin_protocol, origin_tls_server_name, origin_tls_verification,
    service_name, bridge_socket_path, origin_ca_secret_path, applied_revision,
    deleted_at, deletion_requested, deletion_revision, created_at, updated_at
)
SELECT
    id, tenant_id, device_id, name, protocol, local_address, local_port,
    public_port, hostname, enabled, apply_status, apply_error, apply_revision,
    origin_protocol, origin_tls_server_name,
    COALESCE(origin_tls_verification, 'system'), service_name, bridge_socket_path,
    origin_ca_secret_path, applied_revision, deleted_at, deletion_requested,
    deletion_revision, created_at, updated_at
FROM tunnels;

DROP TABLE tunnels;
ALTER TABLE tunnels_new RENAME TO tunnels;
CREATE INDEX IF NOT EXISTS idx_tunnels_device ON tunnels(device_id);
CREATE INDEX IF NOT EXISTS idx_tunnels_public_port ON tunnels(public_port);
CREATE INDEX IF NOT EXISTS idx_tunnels_hostname ON tunnels(hostname);
INSERT OR IGNORE INTO schema_migrations (version) VALUES (13);
