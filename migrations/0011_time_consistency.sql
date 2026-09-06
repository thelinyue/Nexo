-- 将参与过期判断的历史 TEXT 字段统一为 Unix 秒整数。
-- 旧版本实际写入的是十进制 Unix 秒，CAST 可在不改变时刻的前提下修复字段亲和性。
CREATE TABLE device_identities_time_v11 (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    certificate_pem TEXT,
    certificate_fingerprint TEXT,
    issued_at TEXT,
    expires_at INTEGER,
    revoked_at TEXT
);

INSERT INTO device_identities_time_v11
    (device_id, certificate_pem, certificate_fingerprint, issued_at, expires_at, revoked_at)
SELECT device_id, certificate_pem, certificate_fingerprint, issued_at,
       CAST(expires_at AS INTEGER), revoked_at
FROM device_identities;

DROP TABLE device_identities;
ALTER TABLE device_identities_time_v11 RENAME TO device_identities;

CREATE TABLE mesh_enrollment_attempts_time_v11 (
    id TEXT PRIMARY KEY,
    nexo_device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    headscale_pre_auth_key_id TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'issued'
        CHECK (state IN ('issued', 'consumed', 'expired', 'revoked', 'failed')),
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO mesh_enrollment_attempts_time_v11
    (id, nexo_device_id, tenant_id, headscale_pre_auth_key_id, expires_at,
     state, last_error, created_at, updated_at)
SELECT id, nexo_device_id, tenant_id, headscale_pre_auth_key_id,
       CAST(expires_at AS INTEGER), state, last_error, created_at, updated_at
FROM mesh_enrollment_attempts;

DROP TABLE mesh_enrollment_attempts;
ALTER TABLE mesh_enrollment_attempts_time_v11 RENAME TO mesh_enrollment_attempts;
CREATE INDEX idx_mesh_enrollment_attempts_device
    ON mesh_enrollment_attempts (nexo_device_id, created_at DESC);

INSERT INTO schema_migrations (version) VALUES (11);
