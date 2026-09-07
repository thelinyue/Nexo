-- v0.1.8：公网域名的 DNS 托管状态和根/泛域名证书阶段。
--
-- Cloudflare 记录只保存公开元数据和 record ID；API Token 继续保存在
-- data/secrets/public-domains/<domain-id>/cloudflare.token，不进入数据库。
ALTER TABLE public_domains ADD COLUMN dns_management_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE public_domains ADD COLUMN dns_target_ipv4 TEXT;
ALTER TABLE public_domains ADD COLUMN dns_target_ipv6 TEXT;
ALTER TABLE public_domains ADD COLUMN dns_management_status TEXT NOT NULL DEFAULT 'disabled'
    CHECK (dns_management_status IN ('disabled', 'pending', 'previewed', 'applying', 'ready', 'drifted', 'conflict', 'error'));
ALTER TABLE public_domains ADD COLUMN dns_management_error TEXT;
ALTER TABLE public_domains ADD COLUMN dns_management_version INTEGER NOT NULL DEFAULT 0;

CREATE TABLE public_domain_dns_records (
    id TEXT PRIMARY KEY,
    public_domain_id TEXT NOT NULL REFERENCES public_domains(id) ON DELETE CASCADE,
    record_type TEXT NOT NULL CHECK (record_type IN ('A', 'AAAA')),
    record_name TEXT NOT NULL CHECK (record_name IN ('@', '*')),
    cloudflare_record_id TEXT,
    last_applied_content TEXT NOT NULL,
    apply_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (apply_status IN ('pending', 'ready', 'drifted', 'error')),
    apply_error TEXT,
    created_by_nexo INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (public_domain_id, record_type, record_name)
);

CREATE TABLE public_domain_certificate_progress (
    public_domain_id TEXT NOT NULL REFERENCES public_domains(id) ON DELETE CASCADE,
    certificate_type TEXT NOT NULL CHECK (certificate_type IN ('root', 'wildcard')),
    stage TEXT NOT NULL DEFAULT 'waiting_configuration'
        CHECK (stage IN ('waiting_configuration', 'presenting_dns', 'waiting_dns', 'validating', 'issued', 'active', 'retry_wait', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    last_event_at INTEGER,
    next_retry_at INTEGER,
    error_code TEXT,
    error_message TEXT,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (public_domain_id, certificate_type)
);

INSERT INTO public_domain_certificate_progress (public_domain_id, certificate_type)
SELECT id, 'root' FROM public_domains;
INSERT INTO public_domain_certificate_progress (public_domain_id, certificate_type)
SELECT id, 'wildcard' FROM public_domains;

-- 正式运行只使用 Production CA；迁移不会自动接管历史 DNS。
UPDATE public_domains SET acme_environment = 'production';
UPDATE public_entry_settings SET acme_environment = 'production';

CREATE INDEX idx_public_domain_dns_records_domain
    ON public_domain_dns_records(public_domain_id);
CREATE INDEX idx_public_domain_certificate_progress_stage
    ON public_domain_certificate_progress(stage, next_retry_at);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (18);
