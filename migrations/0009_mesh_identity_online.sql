-- 第一阶段：记录 Agent 最近一次组网在线状态。
-- 身份绑定与在线状态分离，避免 Tailscale 暂时断线时被误判为需要重新绑定。
-- 该迁移在 0007 创建表之后执行；Server 启动时会先检查字段，
-- 因而对已经应用过的数据库保持幂等。
ALTER TABLE mesh_identities
    ADD COLUMN online INTEGER NOT NULL DEFAULT 0;

INSERT OR IGNORE INTO schema_migrations (version) VALUES (9);
