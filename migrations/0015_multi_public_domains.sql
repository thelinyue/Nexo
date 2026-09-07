-- v0.1.7：把单一公网入口扩展为“一个主域名 + 多个附加域名”。
-- Secret 正文仍只保存在 NEXO_DATA_DIR/secrets 下，SQLite 仅保存路径和公开元数据。

CREATE TABLE IF NOT EXISTS public_domains (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    is_primary INTEGER NOT NULL DEFAULT 0,
    https_enabled INTEGER NOT NULL DEFAULT 1,
    certificate_mode TEXT NOT NULL DEFAULT 'cloudflare'
        CHECK (certificate_mode IN ('manual', 'cloudflare')),
    acme_environment TEXT NOT NULL DEFAULT 'production'
        CHECK (acme_environment IN ('staging', 'production')),
    secret_dir TEXT NOT NULL,
    desired_revision INTEGER NOT NULL DEFAULT 0,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    apply_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (apply_status IN ('pending', 'checking', 'configuring', 'ready', 'retrying', 'rate_limited', 'error')),
    apply_error TEXT,
    error_code TEXT,
    dns_check_json TEXT NOT NULL DEFAULT '{}',
    root_certificate_status TEXT NOT NULL DEFAULT 'pending',
    root_certificate_not_before INTEGER,
    root_certificate_not_after INTEGER,
    root_certificate_subjects_json TEXT NOT NULL DEFAULT '[]',
    wildcard_certificate_status TEXT NOT NULL DEFAULT 'pending',
    wildcard_certificate_not_before INTEGER,
    wildcard_certificate_not_after INTEGER,
    wildcard_certificate_subjects_json TEXT NOT NULL DEFAULT '[]',
    retry_after INTEGER,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (tenant_id, domain)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_public_domains_primary
    ON public_domains(tenant_id) WHERE is_primary = 1;
CREATE INDEX IF NOT EXISTS idx_public_domains_tenant
    ON public_domains(tenant_id, updated_at DESC);

ALTER TABLE tunnels ADD COLUMN public_domain_id TEXT REFERENCES public_domains(id);
CREATE INDEX IF NOT EXISTS idx_tunnels_public_domain ON tunnels(public_domain_id);

CREATE TABLE IF NOT EXISTS public_domain_migrations (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    from_domain_id TEXT NOT NULL REFERENCES public_domains(id),
    to_domain_id TEXT NOT NULL REFERENCES public_domains(id),
    status TEXT NOT NULL DEFAULT 'preparing'
        CHECK (status IN ('preparing', 'switching', 'waiting_devices', 'completed', 'failed')),
    desired_revision INTEGER NOT NULL DEFAULT 0,
    total_devices INTEGER NOT NULL DEFAULT 0,
    acknowledged_devices INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    completed_at INTEGER
);

CREATE TABLE IF NOT EXISTS public_domain_migration_devices (
    migration_id TEXT NOT NULL REFERENCES public_domain_migrations(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sent', 'acknowledged', 'failed', 'upgrade_required')),
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    acknowledged_at INTEGER,
    PRIMARY KEY (migration_id, device_id)
);

-- 旧单例入口存在域名时，生成稳定的主域名资源；无域名时保持空配置。
INSERT OR IGNORE INTO public_domains (
    id, tenant_id, domain, is_primary, https_enabled, certificate_mode,
    acme_environment, secret_dir, desired_revision, applied_revision,
    apply_status, apply_error, dns_check_json, root_certificate_status,
    root_certificate_not_before, root_certificate_not_after,
    root_certificate_subjects_json, wildcard_certificate_status,
    wildcard_certificate_not_before, wildcard_certificate_not_after,
    wildcard_certificate_subjects_json, updated_at
)
SELECT
    'legacy-primary-' || tenant_id, tenant_id, base_domain, 1, https_enabled,
    CASE WHEN certificate_mode = 'manual' THEN 'manual' ELSE 'cloudflare' END,
    acme_environment, 'secrets/public-domains/legacy-primary-' || tenant_id, desired_revision,
    applied_revision,
    CASE apply_status
        WHEN 'not_configured' THEN 'pending'
        WHEN 'configuring' THEN 'configuring'
        WHEN 'ready' THEN 'ready'
        WHEN 'error' THEN 'error'
        ELSE 'pending'
    END,
    apply_error, dns_check_json,
    CASE WHEN apply_status = 'ready' THEN 'ready' ELSE 'pending' END,
    certificate_not_before, certificate_not_after, certificate_subjects_json,
    CASE WHEN apply_status = 'ready' THEN 'ready' ELSE 'pending' END,
    certificate_not_before, certificate_not_after, certificate_subjects_json,
    updated_at
FROM public_entry_settings
WHERE base_domain IS NOT NULL AND trim(base_domain) <> '';

UPDATE tunnels
SET public_domain_id = (
    SELECT id FROM public_domains
    WHERE public_domains.tenant_id = tunnels.tenant_id AND is_primary = 1
)
WHERE public_domain_id IS NULL
  AND protocol IN ('http', 'https')
  AND EXISTS (
      SELECT 1 FROM public_domains
      WHERE public_domains.tenant_id = tunnels.tenant_id AND is_primary = 1
  );

INSERT OR IGNORE INTO schema_migrations (version) VALUES (15);
