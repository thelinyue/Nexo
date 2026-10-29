CREATE TABLE IF NOT EXISTS analytics_state (id INTEGER PRIMARY KEY CHECK(id=1), started_at INTEGER NOT NULL);
INSERT OR IGNORE INTO analytics_state VALUES(1,unixepoch());
CREATE TABLE IF NOT EXISTS analytics_events (
 id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
 service_id TEXT NOT NULL, node_id TEXT NOT NULL, at INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS analytics_events_scope ON analytics_events(tenant_id,service_id,at,id);
CREATE INDEX IF NOT EXISTS analytics_events_time ON analytics_events(at,id);
CREATE TABLE IF NOT EXISTS analytics_hours (
 tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, service_id TEXT NOT NULL,
 node_id TEXT NOT NULL, hour INTEGER NOT NULL, protocol TEXT NOT NULL, status_class INTEGER NOT NULL,
 requests INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0,
 sessions INTEGER NOT NULL DEFAULT 0, duration_ms INTEGER NOT NULL DEFAULT 0, session_ms INTEGER NOT NULL DEFAULT 0,
 to_origin INTEGER NOT NULL DEFAULT 0, to_public INTEGER NOT NULL DEFAULT 0, peak INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant_id,service_id,node_id,hour,protocol,status_class));
CREATE INDEX IF NOT EXISTS analytics_hours_time ON analytics_hours(hour);
CREATE TABLE IF NOT EXISTS analytics_dimensions (
 tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, service_id TEXT NOT NULL,
 hour INTEGER NOT NULL, protocol TEXT NOT NULL, status_class INTEGER NOT NULL, dimension TEXT NOT NULL, value TEXT NOT NULL, count INTEGER NOT NULL,
 PRIMARY KEY(tenant_id,service_id,hour,protocol,status_class,dimension,value));
CREATE TABLE IF NOT EXISTS analytics_visitors (
 tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, service_id TEXT NOT NULL,
 day INTEGER NOT NULL, hour INTEGER NOT NULL, protocol TEXT NOT NULL, status_class INTEGER NOT NULL, visitor TEXT NOT NULL, PRIMARY KEY(tenant_id,service_id,day,hour,protocol,status_class,visitor));
CREATE TABLE IF NOT EXISTS analytics_sources (
 tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, service_id TEXT NOT NULL,
 node_id TEXT NOT NULL, protocol TEXT NOT NULL, at INTEGER NOT NULL, active INTEGER NOT NULL,
 PRIMARY KEY(tenant_id,service_id,node_id,protocol));
CREATE TABLE IF NOT EXISTS analytics_gaps (
 source TEXT PRIMARY KEY, at INTEGER NOT NULL, dropped INTEGER NOT NULL DEFAULT 0, lag_seconds INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS analytics_coverage (
 source TEXT NOT NULL, minute INTEGER NOT NULL, PRIMARY KEY(source,minute));
CREATE TABLE IF NOT EXISTS analytics_ticks (
 source TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(source,at));
CREATE TABLE IF NOT EXISTS analytics_losses (
 source TEXT NOT NULL, minute INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(source,minute));
