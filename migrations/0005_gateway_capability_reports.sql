-- 第三阶段：保存 Agent 的网关环境探测结果。
-- 报告是观测值，不等同于已发布路由或已生效的 Desired State。
CREATE TABLE IF NOT EXISTS device_capability_reports (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    report_json TEXT NOT NULL,
    reported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (5);
