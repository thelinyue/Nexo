-- 第三阶段：服务端控制通道身份。
-- 该证书由 Nexo 设备 CA 签发，仅用于 mTLS 控制通道的服务端身份。
CREATE TABLE IF NOT EXISTS server_control_identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    certificate_pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (4);
