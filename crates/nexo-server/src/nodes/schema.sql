-- 节点配置属于控制平面；远端节点只取得已授权的服务快照。
CREATE TABLE IF NOT EXISTS relay_nodes (
 id TEXT PRIMARY KEY, owner_tenant TEXT REFERENCES tenants(id), name TEXT NOT NULL,
 public_ipv4 TEXT NOT NULL DEFAULT '', control_port INTEGER NOT NULL DEFAULT 9891,
 approved INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
 certificate_pem TEXT NOT NULL DEFAULT '', token_digest TEXT, token_expires INTEGER,
 os TEXT, architecture TEXT, version TEXT, last_seen INTEGER,
 connections INTEGER NOT NULL DEFAULT 0, maintenance INTEGER NOT NULL DEFAULT 0,
 error TEXT, created_at INTEGER NOT NULL, removed_at INTEGER
);
INSERT OR IGNORE INTO relay_nodes(id,name,approved,created_at) VALUES('local','内置节点',1,unixepoch());
CREATE TABLE IF NOT EXISTS relay_node_grants (
 node_id TEXT NOT NULL REFERENCES relay_nodes(id), tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 PRIMARY KEY(node_id,tenant_id)
);
INSERT OR IGNORE INTO relay_node_grants SELECT 'local',id FROM tenants;
CREATE TABLE IF NOT EXISTS service_nodes (
 service_id TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
 node_id TEXT NOT NULL REFERENCES relay_nodes(id),
 PRIMARY KEY(service_id,node_id)
);
CREATE TABLE IF NOT EXISTS relay_node_events (
 id INTEGER PRIMARY KEY, node_id TEXT NOT NULL REFERENCES relay_nodes(id), actor TEXT,
 message TEXT NOT NULL, occurred_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS relay_service_health (
 node_id TEXT NOT NULL REFERENCES relay_nodes(id), service_id TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,
 revision INTEGER NOT NULL, successes INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
 healthy INTEGER NOT NULL DEFAULT 0, checked_at INTEGER NOT NULL DEFAULT 0, error TEXT,
 public_probe_supported INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(node_id,service_id)
);
CREATE TABLE IF NOT EXISTS node_update_jobs (
 id TEXT PRIMARY KEY, actor TEXT NOT NULL, target_version TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued', accept_interruption INTEGER NOT NULL DEFAULT 0,
 created_at INTEGER NOT NULL, finished_at INTEGER, operation TEXT NOT NULL DEFAULT 'update'
);
CREATE TABLE IF NOT EXISTS node_update_items (
 job_id TEXT NOT NULL REFERENCES node_update_jobs(id), node_id TEXT NOT NULL REFERENCES relay_nodes(id),
 position INTEGER NOT NULL, stage TEXT NOT NULL DEFAULT 'queued', error TEXT,
 started_at INTEGER, finished_at INTEGER, deadline INTEGER, force_disconnect INTEGER NOT NULL DEFAULT 0,attempt INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(job_id,node_id), UNIQUE(job_id,position)
);
CREATE TABLE IF NOT EXISTS relay_dns_records (
 service_id TEXT NOT NULL REFERENCES tunnels(id), domain_id TEXT NOT NULL REFERENCES public_domains(id),
 hostname TEXT NOT NULL, address TEXT NOT NULL, original TEXT, written TEXT,
 PRIMARY KEY(service_id,hostname,address)
);
CREATE TABLE IF NOT EXISTS relay_certificates (
 service_id TEXT PRIMARY KEY REFERENCES tunnels(id), hostname TEXT NOT NULL,
 chain TEXT, expires_at INTEGER, retry_at INTEGER NOT NULL DEFAULT 0, error TEXT
);
CREATE TABLE IF NOT EXISTS relay_budgets (
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL, service_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
 month INTEGER NOT NULL, reserved INTEGER NOT NULL, to_origin INTEGER NOT NULL DEFAULT 0,
 to_public INTEGER NOT NULL DEFAULT 0, finished INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS relay_latency (
 device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,node_id TEXT NOT NULL REFERENCES relay_nodes(id),
 rtt_ms INTEGER NOT NULL, samples INTEGER NOT NULL DEFAULT 1, checked_at INTEGER NOT NULL,
 PRIMARY KEY(device_id,node_id)
);
CREATE TABLE IF NOT EXISTS relay_selection (
 service_id TEXT PRIMARY KEY REFERENCES tunnels(id) ON DELETE CASCADE,node_id TEXT NOT NULL,
 selected_at INTEGER NOT NULL, reason TEXT NOT NULL
);

-- 组分配授予组内节点使用权；组服务还必须持续持有组授权，不能靠旧服务绑定继续转发。
CREATE TABLE IF NOT EXISTS relay_node_groups(id TEXT PRIMARY KEY,name TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS relay_group_members(group_id TEXT NOT NULL REFERENCES relay_node_groups(id) ON DELETE CASCADE,node_id TEXT NOT NULL REFERENCES relay_nodes(id),PRIMARY KEY(group_id,node_id));
CREATE TABLE IF NOT EXISTS relay_group_grants(group_id TEXT NOT NULL REFERENCES relay_node_groups(id) ON DELETE CASCADE,tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,PRIMARY KEY(group_id,tenant_id));
CREATE VIEW IF NOT EXISTS relay_node_authorizations AS
 SELECT node_id,tenant_id FROM relay_node_grants
 UNION SELECT m.node_id,g.tenant_id FROM relay_group_members m JOIN relay_group_grants g ON g.group_id=m.group_id
 UNION SELECT 'local',id FROM tenants;
-- 内置反代授权必须显式保存，不能复用默认授予所有工作空间的穿透授权。
CREATE TABLE IF NOT EXISTS relay_local_proxy_grants(tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE);
CREATE VIEW IF NOT EXISTS relay_proxy_authorizations AS
 SELECT n.id AS node_id,n.owner_tenant AS tenant_id FROM relay_nodes n WHERE n.id!='local' AND n.owner_tenant IS NOT NULL
 UNION SELECT node_id,tenant_id FROM relay_node_authorizations WHERE node_id!='local'
 UNION SELECT 'local',tenant_id FROM relay_local_proxy_grants
 UNION SELECT n.id,u.tenant_id FROM relay_nodes n CROSS JOIN users u WHERE u.role='system_admin' AND u.enabled=1;
DROP VIEW IF EXISTS authorized_service_nodes;
CREATE VIEW authorized_service_nodes AS
 SELECT s.service_id,s.node_id FROM service_nodes s JOIN tunnels t ON t.id=s.service_id
 WHERE (t.service_mode='reverse_proxy' AND EXISTS(SELECT 1 FROM relay_nodes n WHERE n.id=s.node_id AND n.approved=1 AND n.enabled=1 AND n.removed_at IS NULL) AND EXISTS(SELECT 1 FROM relay_proxy_authorizations a WHERE a.node_id=s.node_id AND a.tenant_id=t.tenant_id))
 OR (t.service_mode='tunnel' AND EXISTS(SELECT 1 FROM relay_node_authorizations a WHERE a.node_id=s.node_id AND a.tenant_id=t.tenant_id)
 AND (t.node_group_id IS NULL OR EXISTS(SELECT 1 FROM relay_group_grants g JOIN relay_group_members m ON m.group_id=g.group_id WHERE g.group_id=t.node_group_id AND g.tenant_id=t.tenant_id AND m.node_id=s.node_id)));

CREATE TRIGGER IF NOT EXISTS bind_builtin_node AFTER INSERT ON tunnels BEGIN INSERT OR IGNORE INTO service_nodes(service_id,node_id) VALUES(NEW.id,'local'); END;

CREATE TABLE IF NOT EXISTS relay_public_health(node_id TEXT NOT NULL,service_id TEXT NOT NULL REFERENCES tunnels(id) ON DELETE CASCADE,revision INTEGER NOT NULL,successes INTEGER NOT NULL DEFAULT 0,failures INTEGER NOT NULL DEFAULT 0,healthy INTEGER NOT NULL DEFAULT 0,checked_at INTEGER NOT NULL,probe_kind TEXT NOT NULL DEFAULT 'tcp',address TEXT NOT NULL DEFAULT '',error TEXT,PRIMARY KEY(node_id,service_id));
CREATE TABLE IF NOT EXISTS relay_dns_state(service_id TEXT PRIMARY KEY REFERENCES tunnels(id) ON DELETE CASCADE,revision INTEGER NOT NULL,synced_at INTEGER NOT NULL,error TEXT);

CREATE TABLE IF NOT EXISTS relay_dns_originals(service_id TEXT NOT NULL REFERENCES tunnels(id),domain_id TEXT NOT NULL REFERENCES public_domains(id),hostname TEXT NOT NULL,record TEXT NOT NULL,PRIMARY KEY(service_id,hostname));

CREATE TABLE IF NOT EXISTS relay_selection_pending(service_id TEXT PRIMARY KEY REFERENCES tunnels(id) ON DELETE CASCADE,node_id TEXT NOT NULL,samples INTEGER NOT NULL,checked_at INTEGER NOT NULL);
