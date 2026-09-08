-- 新增组网客户端回程路由后，旧的站点级确认不能覆盖新的路由要求。
-- 只清除可重新生成的确认记录，不触碰站点、设备、节点身份或网络拓扑。
DELETE FROM site_link_route_confirmations;

INSERT OR IGNORE INTO schema_migrations (version) VALUES (21);
