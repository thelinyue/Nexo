-- 第三阶段：设备入网凭证与设备身份的持久化边界。
-- 入网凭证明文永远不落库；token_digest 仅用于一次性校验。
CREATE TABLE IF NOT EXISTS pending_enrollments (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id),
    site_id TEXT REFERENCES sites(id),
    token_digest TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'awaiting_approval', 'approved', 'consumed', 'expired', 'revoked')
    ),
    expires_at INTEGER NOT NULL,
    device_id TEXT REFERENCES devices(id),
    requested_name TEXT,
    requested_os TEXT,
    requested_architecture TEXT,
    requested_agent_version TEXT,
    requested_capabilities_json TEXT NOT NULL DEFAULT '[]',
    requested_csr_pem TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_at TEXT,
    consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS device_identities (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    certificate_pem TEXT,
    certificate_fingerprint TEXT,
    issued_at TEXT,
    expires_at TEXT,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_pending_enrollments_tenant ON pending_enrollments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pending_enrollments_status ON pending_enrollments(status);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (2);
