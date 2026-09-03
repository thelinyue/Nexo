-- 第三阶段：服务端身份 CA。
-- 私钥只用于服务端签发设备证书，不通过 API 返回，也不写入前端。
CREATE TABLE IF NOT EXISTS server_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    ca_certificate_pem TEXT NOT NULL,
    ca_private_key_pem TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (3);
