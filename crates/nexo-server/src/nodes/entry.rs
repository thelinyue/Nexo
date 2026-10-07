//! 服务入口的只读投影：DNS 写入记录、策略选择和健康候选分别表达已确认事实与当前意图。
//! 选择先于 DNS 写入，部分写入也可能失败；读取接口不触发协调、不改记录，不把候选当成已发布入口。
use super::*;
use std::collections::BTreeSet;

/// 地址只有唯一对应当前绑定中的未删除节点时才附带名称；旧地址保留 IPv4，避免错误归因。
#[derive(Debug, Serialize, Deserialize)]
pub struct RecordedEntry {
    pub ipv4: String,
    pub node_id: Option<String>,
    pub node_name: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    Synced,
    Pending,
    Failed,
    Disabled,
    Unmanaged,
}

/// 同步时间只使用既有完整同步结果；直连记录没有独立 DNS 时间，不能用心跳时间冒充。
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeEntry {
    pub entries: Vec<RecordedEntry>,
    pub sync_status: SyncStatus,
    pub synced_at: Option<i64>,
}

pub fn summary(
    db: &Connection,
    tenant: &str,
    id: &str,
    local_ipv4: Option<Ipv4Addr>,
) -> rusqlite::Result<Option<NodeEntry>> {
    let config = db.query_row("SELECT t.enabled AND w.enabled,t.service_mode,t.protocol,t.apply_revision,t.public_domain_id,t.hostname||'.'||p.domain,t.distribution_mode,t.preferred_node_id,t.ipv6_direct_enabled FROM tunnels t JOIN tenants w ON w.id=t.tenant_id LEFT JOIN public_domains p ON p.id=t.public_domain_id AND p.tenant_id=t.tenant_id WHERE t.id=?1 AND t.tenant_id=?2 AND t.deleted_at IS NULL", params![id,tenant], |r| Ok((r.get::<_,bool>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,String>(6)?,r.get::<_,Option<String>>(7)?,r.get::<_,bool>(8)?))).optional()?;
    let Some((enabled, mode, protocol, revision, domain, host, strategy, preferred, direct)) =
        config
    else {
        return Ok(None);
    };
    let mut result = NodeEntry {
        entries: vec![],
        sync_status: SyncStatus::Unmanaged,
        synced_at: None,
    };
    if !enabled {
        result.sync_status = SyncStatus::Disabled;
        return Ok(Some(result));
    }
    if mode != "tunnel" || !matches!(protocol.as_str(), "http" | "https" | "tcp") {
        return Ok(Some(result));
    }
    let (Some(domain), Some(host)) = (domain, host) else {
        return Ok(Some(result));
    };
    // 当前业务域名的记录才属于本次展示，不能把换域名前的记录或其他工作空间记录混进来。
    let mut query = db.prepare("SELECT written FROM relay_dns_records WHERE service_id=?1 AND domain_id=?2 AND hostname=?3 AND written IS NOT NULL UNION ALL SELECT written FROM direct_dns_records WHERE service_id=?1 AND domain_id=?2 AND hostname=?3 AND kind='A' AND written IS NOT NULL")?;
    let written = query
        .query_map(params![id, domain, host], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut recorded = BTreeSet::new();
    for value in written {
        let record: crate::dns_provider::Record = serde_json::from_str(&value).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })?;
        if record.kind == "A" && record.name == host {
            if let Ok(address) = record.value.parse::<Ipv4Addr>() {
                recorded.insert(address.to_string());
            }
        }
    }
    let mut query = db.prepare("SELECT n.id,n.name,CASE WHEN n.id='local' THEN ?2 ELSE n.public_ipv4 END,EXISTS(SELECT 1 FROM relay_healthy_service_nodes h WHERE h.service_id=s.service_id AND h.node_id=s.node_id) FROM service_nodes s JOIN relay_nodes n ON n.id=s.node_id WHERE s.service_id=?1 AND n.removed_at IS NULL ORDER BY n.id")?;
    let nodes = query
        .query_map(
            params![id, local_ipv4.map(|ip| ip.to_string()).unwrap_or_default()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                ))
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    result.entries = recorded
        .iter()
        .map(|address| {
            let mut matches = nodes.iter().filter(|(_, _, ip, _)| ip == address);
            let unique = matches.next().filter(|_| matches.next().is_none());
            RecordedEntry {
                ipv4: address.clone(),
                node_id: unique.map(|n| n.0.clone()),
                node_name: unique.map(|n| n.1.clone()),
            }
        })
        .collect();

    if super::dns::managed(db, id)? {
        let sync = db
            .query_row(
                "SELECT revision,synced_at,error FROM relay_dns_state WHERE service_id=?1",
                [id],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?;
        result.synced_at = sync
            .as_ref()
            .and_then(|(_, at, _)| (*at > 0).then_some(*at));
        let healthy = nodes
            .iter()
            .filter(|n| n.3 && !n.2.is_empty())
            .collect::<Vec<_>>();
        let selection = db
            .query_row(
                "SELECT node_id FROM relay_selection WHERE service_id=?1",
                [id],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        let selected = match strategy.as_str() {
            "manual" => healthy
                .iter()
                .find(|n| Some(&n.0) == preferred.as_ref())
                .or_else(|| healthy.iter().find(|n| Some(&n.0) == selection.as_ref())),
            "latency" => healthy.iter().find(|n| Some(&n.0) == selection.as_ref()),
            _ => None,
        };
        let mut desired = if matches!(strategy.as_str(), "single" | "dns") {
            healthy.iter().map(|n| n.2.clone()).collect::<BTreeSet<_>>()
        } else {
            selected
                .map(|n| BTreeSet::from([n.2.clone()]))
                .unwrap_or_default()
        };
        // 沿用维护期间保留已有 A 的规则；只读展示不能把维护误报为新的 DNS 切换。
        for (node, _, address, _) in &nodes {
            if super::updates::preserves_dns(db, node, id)?
                && !super::quota::policy(db, node)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?
                    .is_some_and(|q| q.exhausted)
            {
                desired.insert(address.clone());
            }
        }
        let choosing = !healthy.is_empty()
            && matches!(strategy.as_str(), "manual" | "latency")
            && selected.is_none();
        result.sync_status = match sync {
            Some((_, _, Some(_))) => SyncStatus::Failed,
            Some((current, at, None))
                if current == revision && at > 0 && !choosing && recorded == desired =>
            {
                SyncStatus::Synced
            }
            _ => SyncStatus::Pending,
        };
    } else {
        // IPv6 直连的 A 由直连协调器保存。既有记录省略同步时间，保留完整直连 DNS 错误。
        let intended = db.query_row("SELECT intended FROM direct_dns_records WHERE service_id=?1 AND domain_id=?2 AND hostname=?3 AND kind='A'", params![id,domain,host], |r| r.get::<_,String>(0)).optional()?;
        if direct || intended.is_some() {
            let state = db.query_row("SELECT s.revision,s.dns_error,s.published_address,a.selected_address FROM direct_services s JOIN tunnels t ON t.id=s.service_id LEFT JOIN direct_agents a ON a.device_id=t.device_id WHERE s.service_id=?1", [id], |r| Ok((r.get::<_,i64>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<String>>(3)?))).optional()?;
            let address = local_ipv4.map(|ip| ip.to_string());
            let confirmed = address.as_ref().is_some_and(|ip| {
                intended.as_ref() == Some(ip) && recorded == BTreeSet::from([ip.clone()])
            });
            // IPv6 地址选择不会增加服务版本；旧发布地址存在也不代表当前直连 DNS 已同步。
            result.sync_status = if direct && state.as_ref().is_some_and(|s| s.1.is_some()) {
                SyncStatus::Failed
            } else if confirmed
                && (!direct
                    || state.is_some_and(|s| s.0 == revision && s.2.is_some() && s.2 == s.3))
            {
                SyncStatus::Synced
            } else {
                SyncStatus::Pending
            };
        }
    }
    Ok(Some(result))
}

#[cfg(test)]
mod tests;
