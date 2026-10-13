//! 管理端只承接缓存旧 IP 的反代请求，目标始终来自当前单节点绑定。
//! 不参与 DNS 选择或计量；逐请求复核版本与授权，防止加载失败后旧路由继续转发。
use crate::*;
use std::net::{Ipv4Addr, SocketAddrV4};

/// Caddy 快照中的节点、入口地址和现有配置版本，逐请求与数据库当前绑定比较。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub node_id: String,
    pub address: SocketAddrV4,
    pub revision: i64,
}

pub(crate) fn target(db: &Connection, id: &str, http_port: u16) -> Result<Option<Target>> {
    let row = db.query_row(
        "SELECT n.id,n.public_ipv4,t.apply_revision,CASE WHEN t.protocol='https' THEN t.https_port ELSE ?2 END
         FROM tunnels t JOIN tenants w ON w.id=t.tenant_id
         JOIN public_domains p ON p.id=t.public_domain_id AND p.tenant_id=t.tenant_id
         JOIN domain_settings d ON d.domain_id=p.id
         JOIN authorized_service_nodes s ON s.service_id=t.id JOIN relay_nodes n ON n.id=s.node_id
         WHERE t.id=?1 AND t.service_mode='reverse_proxy' AND t.distribution_mode='single'
           AND t.enabled=1 AND t.deleted_at IS NULL AND w.enabled=1 AND d.verified=1
           AND t.protocol IN ('http','https') AND n.id!='local' AND n.reverse_proxy_supported=1
           AND (t.protocol!='https' OR p.https_enabled=1)
           AND (SELECT COUNT(*) FROM service_nodes WHERE service_id=t.id)=1",
        params![id, http_port],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, u16>(3)?)),
    ).optional()?;
    row.map(|(node_id, ip, revision, port)| {
        Ok(Target {
            node_id,
            address: SocketAddrV4::new(ip.parse::<Ipv4Addr>()?, port),
            revision,
        })
    })
    .transpose()
}

/// 仅要求节点已加载当前入口；不依赖 DNS 发布结果，避免兼容路由与公网探测互相等待。
pub(crate) fn ready(db: &Connection, id: &str, target: &Target) -> Result<bool> {
    if crate::nodes::quota::policy(db, &target.node_id)?.is_some_and(|q| q.exhausted) {
        return Ok(false);
    }
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM relay_nodes n JOIN relay_service_health h ON h.node_id=n.id
         WHERE n.id=?1 AND n.last_seen>?4 AND n.maintenance=0 AND h.service_id=?2
           AND h.revision=?3 AND h.healthy=1 AND h.checked_at>?4)",
        params![target.node_id, id, target.revision, unix_now() - 45],
        |r| r.get(0),
    )?)
}
