-- v0.1.11：保存域名服务的脱敏运行事件，供管理员排查证书、TLS 与代理问题。
-- Secret、请求头、证书正文和访问日志不得写入本表。
CREATE TABLE public_domain_runtime_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    public_domain_id TEXT REFERENCES public_domains(id) ON DELETE CASCADE,
    domain TEXT,
    level TEXT NOT NULL,
    category TEXT NOT NULL,
    stage TEXT,
    summary TEXT NOT NULL,
    error_code TEXT,
    retry_at INTEGER,
    technical_detail TEXT,
    occurred_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_public_domain_runtime_events_tenant_time
    ON public_domain_runtime_events(tenant_id, occurred_at DESC, id DESC);
CREATE INDEX idx_public_domain_runtime_events_domain_time
    ON public_domain_runtime_events(public_domain_id, occurred_at DESC, id DESC);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (19);
