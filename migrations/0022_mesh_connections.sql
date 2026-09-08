-- 连接观测只保存脱敏路径类别；不保存公网端点、DERP 区域或命令原始输出。
CREATE TABLE mesh_connection_observations (
    gateway_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    peer_node_id TEXT NOT NULL,
    connection_type TEXT NOT NULL
        CHECK (connection_type IN ('direct', 'peer_relay', 'derp', 'idle', 'unknown')),
    active INTEGER NOT NULL DEFAULT 0,
    observed_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (gateway_device_id, peer_node_id)
);

-- 主动检测任务只接受 Server 从设备身份解析出的可信 Tailscale 地址。
CREATE TABLE mesh_connection_checks (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    gateway_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    site_network_id TEXT NOT NULL REFERENCES site_networks(id) ON DELETE CASCADE,
    target_ip TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    connection_type TEXT,
    error_message TEXT,
    requested_at INTEGER NOT NULL DEFAULT (unixepoch()),
    started_at INTEGER,
    completed_at INTEGER
);

CREATE INDEX idx_mesh_connection_checks_gateway_pending
    ON mesh_connection_checks (gateway_device_id, status, requested_at);
CREATE INDEX idx_mesh_connection_checks_tenant
    ON mesh_connection_checks (tenant_id, requested_at DESC);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (22);
