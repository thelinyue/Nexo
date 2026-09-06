-- 网络资源删除需要先撤销 Agent 与 Headscale 中的路由，再物理删除业务记录。
-- 两个字段由 apply_resource_deletion_migration 在 PRAGMA 检查后逐列添加，
-- 避免 SQLite 不支持 ADD COLUMN IF NOT EXISTS 导致中断后的迁移无法重跑。
INSERT OR IGNORE INTO schema_migrations (version) VALUES (12);
