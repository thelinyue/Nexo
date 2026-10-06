//! 服务绑定以工作空间授权为准，表单传入的节点列表不构成权限。
use super::*;
use nexo_protocol::nodes::AgentNode;
pub fn ids(db: &Connection, id: &str) -> rusqlite::Result<Vec<String>> {
    db.prepare("SELECT node_id FROM service_nodes WHERE service_id=?1 ORDER BY node_id")?
        .query_map([id], |r| r.get(0))?
        .collect()
}
pub fn prepare(
    db: &Connection,
    tenant: &str,
    id: &str,
    input: &mut TunnelInput,
) -> Result<(), ApiError> {
    let group = match input.node_group_id.as_deref() {
        Some("") => None,
        Some(value) => Some(value.to_owned()),
        None => db
            .query_row("SELECT node_group_id FROM tunnels WHERE id=?1", [id], |r| {
                r.get::<_, Option<String>>(0)
            })
            .optional()
            .map_err(db_error)?
            .flatten(),
    };
    if let Some(group) = &group {
        let allowed=db.query_row("SELECT EXISTS(SELECT 1 FROM relay_group_grants WHERE group_id=?1 AND tenant_id=?2)",params![group,tenant],|r|r.get::<_,bool>(0)).map_err(db_error)?;
        if !allowed {
            return Err(invalid("节点组不存在或未分配给当前工作空间"));
        }
        input.node_ids = Some(super::groups::members(db, group).map_err(db_error)?);
    }
    input.node_group_id = group;
    let existing = ids(db, id).map_err(db_error)?;
    let nodes = input.node_ids.get_or_insert_with(|| {
        if existing.is_empty() {
            vec!["local".into()]
        } else {
            existing
        }
    });
    let previous: Option<String> = db
        .query_row(
            "SELECT distribution_mode FROM tunnels WHERE id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?;
    let mode = input.distribution_mode.get_or_insert_with(|| {
        if let Some(previous) = previous {
            return previous;
        }
        if nodes.len() > 1 {
            "dns".into()
        } else {
            "single".into()
        }
    });
    if !matches!(mode.as_str(), "single" | "dns" | "latency" | "manual")
        || nodes.is_empty()
        || nodes.len() > 16
        || nodes.iter().collect::<std::collections::HashSet<_>>().len() != nodes.len()
        || (matches!(mode.as_str(), "dns" | "latency" | "manual") && nodes.len() < 2)
        || (*mode == "single" && nodes.len() != 1)
    {
        return Err(invalid(
            "单节点需选择一个节点，多节点需选择 2–16 个不同节点",
        ));
    }
    let proxy = input.service_mode.as_deref() == Some("reverse_proxy");
    if proxy && (input.node_group_id.is_some() || *mode != "single" || nodes.len() != 1) {
        return Err(invalid("反向代理只能手动选择一个节点"));
    }
    let remote = nodes.iter().any(|n| n != "local");
    if (remote || *mode == "dns") && (!matches!(input.protocol.as_str(), "http" | "https" | "tcp"))
    {
        return Err(invalid("多 VPS 仅支持 HTTP、HTTPS、TCP 内网穿透"));
    }
    for node in nodes.iter() {
        if proxy {
            authorize_proxy(db, tenant, node)?;
            continue;
        }
        let allowed=db.query_row("SELECT EXISTS(SELECT 1 FROM relay_nodes n WHERE n.id=?1 AND n.approved=1 AND n.enabled=1 AND n.removed_at IS NULL AND (n.id='local' OR EXISTS(SELECT 1 FROM relay_node_authorizations g WHERE g.node_id=n.id AND g.tenant_id=?2)))",params![node,tenant],|r|r.get::<_,bool>(0)).map_err(db_error)?;
        if !allowed {
            return Err(invalid("节点未审批、已停用或未分配给当前工作空间"));
        }
    }
    if remote {
        if !proxy {
            let capable=db.query_row("SELECT EXISTS(SELECT 1 FROM devices WHERE id=?1 AND tenant_id=?2 AND node_capable=1)",params![input.device_id,tenant],|r|r.get::<_,bool>(0)).map_err(db_error)?;
            if !capable {
                return Err(invalid("请先连接支持多节点的新版本设备"));
            }
        }
        let domain = input
            .public_domain_id
            .as_deref()
            .ok_or_else(|| invalid("VPS 节点服务需要配置受管域名"))?;
        let ready=db.query_row("SELECT EXISTS(SELECT 1 FROM public_domains p JOIN domain_settings s ON s.domain_id=p.id WHERE p.id=?1 AND p.tenant_id=?2 AND s.verified=1 AND s.credential_file IS NOT NULL AND (?3!='https' OR s.certificate_mode='cloudflare_dns'))",params![domain,tenant,input.protocol],|r|r.get::<_,bool>(0)).map_err(db_error)?;
        if !ready {
            return Err(invalid("请先验证域名并配置 DNS 凭据，以便自动切换"));
        }
    }
    if *mode == "manual" {
        let previous: Option<String> = db
            .query_row(
                "SELECT preferred_node_id FROM tunnels WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?
            .flatten();
        let preferred = input
            .preferred_node_id
            .get_or_insert_with(|| previous.unwrap_or_else(|| nodes[0].clone()));
        if !nodes.contains(preferred) {
            return Err(invalid("首选节点必须在候选节点中"));
        }
    } else {
        input.preferred_node_id = None;
    }
    nodes.sort();
    Ok(())
}
/// 反代权限和能力由控制器数据决定；节点离线允许保存，未升级则拒绝。
pub fn authorize_proxy(db: &Connection, tenant: &str, node: &str) -> Result<(), ApiError> {
    let allowed = db.query_row("SELECT EXISTS(SELECT 1 FROM relay_nodes n JOIN relay_proxy_authorizations a ON a.node_id=n.id WHERE n.id=?1 AND a.tenant_id=?2 AND n.approved=1 AND n.enabled=1 AND n.removed_at IS NULL)", params![node,tenant], |r| r.get::<_,bool>(0)).map_err(db_error)?;
    if !allowed {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "节点未审批、已停用或未授权当前工作空间使用反向代理",
        ));
    }
    let supported = node == "local"
        || db
            .query_row(
                "SELECT reverse_proxy_supported FROM relay_nodes WHERE id=?1",
                [node],
                |r| r.get::<_, bool>(0),
            )
            .map_err(db_error)?;
    if !supported {
        return Err(invalid("请先升级节点，以支持反向代理"));
    }
    Ok(())
}

/// 删除和停用不依赖节点权限；重新启用必须重新验证，不能利用旧绑定绕过撤权。
pub fn authorize_proxy_enable(db: &Connection, tenant: &str, id: &str) -> Result<(), ApiError> {
    for node in ids(db, id).map_err(db_error)? {
        authorize_proxy(db, tenant, &node)?;
    }
    Ok(())
}

pub fn save(db: &Connection, id: &str, input: &TunnelInput) -> Result<(), ApiError> {
    let previous = ids(db, id).map_err(db_error)?;
    let nodes = input
        .node_ids
        .as_ref()
        .ok_or_else(|| invalid("缺少节点绑定"))?;
    // 成员变化不改变回源版本；仅清理增删节点的状态，重新加入也必须重新验证，不能复用残留样本。
    for node in previous
        .iter()
        .chain(nodes)
        .filter(|node| previous.contains(node) != nodes.contains(node))
    {
        for table in ["relay_service_health", "relay_public_health"] {
            db.execute(
                &format!("DELETE FROM {table} WHERE service_id=?1 AND node_id=?2"),
                params![id, node],
            )
            .map_err(db_error)?;
        }
    }
    db.execute("DELETE FROM service_nodes WHERE service_id=?1", [id])
        .map_err(db_error)?;
    for node in nodes {
        db.execute("INSERT INTO service_nodes VALUES(?1,?2)", params![id, node])
            .map_err(db_error)?;
    }
    db.execute(
        "UPDATE tunnels SET distribution_mode=?2,preferred_node_id=?3,node_group_id=?4 WHERE id=?1",
        params![
            id,
            input.distribution_mode,
            input.preferred_node_id,
            input.node_group_id
        ],
    )
    .map_err(db_error)?;
    Ok(())
}
pub fn agent_nodes(state: &AppState, device: &str) -> Result<Vec<AgentNode>> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let mut q=db.prepare("SELECT n.id,n.public_ipv4,n.control_port,t.id FROM relay_nodes n JOIN authorized_service_nodes s ON s.node_id=n.id JOIN tunnels t ON t.id=s.service_id JOIN relay_node_authorizations g ON g.node_id=n.id AND g.tenant_id=t.tenant_id JOIN tenants w ON w.id=t.tenant_id WHERE t.device_id=?1 AND t.enabled=1 AND t.deleted_at IS NULL AND w.enabled=1 AND n.enabled=1 AND n.approved=1 AND n.removed_at IS NULL AND n.id!='local' ORDER BY n.id,t.id")?;
    let mut result: Vec<AgentNode> = Vec::new();
    for row in q.query_map([device], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, u16>(2)?,
            r.get::<_, String>(3)?,
        ))
    })? {
        let (id, ip, port, service) = row?;
        if let Some(node) = result.iter_mut().find(|n| n.id == id) {
            node.service_ids.push(service);
        } else {
            result.push(AgentNode {
                id: id.clone(),
                endpoint: TunnelDataEndpoint {
                    address: format!("{ip}:{port}"),
                    server_name: id,
                },
                service_ids: vec![service],
            });
        }
    }
    Ok(result)
}
pub fn statuses(db: &Connection, id: &str) -> rusqlite::Result<Value> {
    let mut q=db.prepare("SELECT s.node_id,CASE WHEN ?3 THEN EXISTS(SELECT 1 FROM relay_healthy_service_nodes v WHERE v.service_id=s.service_id AND v.node_id=s.node_id)
        ELSE COALESCE(h.healthy=1 AND h.revision=t.apply_revision AND h.checked_at>?2 AND n.approved=1 AND n.enabled=1 AND n.maintenance=0 AND n.removed_at IS NULL AND (n.id='local' OR n.last_seen>?2) AND EXISTS(SELECT 1 FROM authorized_service_nodes a WHERE a.service_id=s.service_id AND a.node_id=s.node_id),0) END,h.error,h.checked_at,n.name,
        CASE WHEN t.protocol IN ('http','https') AND (n.id='local' OR h.public_probe_supported=1) THEN t.protocol ELSE 'tcp' END,
        p.probe_kind,p.revision=t.apply_revision AND (n.id='local' OR p.address=n.public_ipv4),p.healthy=1 AND p.checked_at>?2,p.checked_at,p.error
        FROM service_nodes s JOIN tunnels t ON t.id=s.service_id JOIN relay_nodes n ON n.id=s.node_id
        LEFT JOIN relay_service_health h ON h.node_id=s.node_id AND h.service_id=s.service_id
        LEFT JOIN relay_public_health p ON p.node_id=s.node_id AND p.service_id=s.service_id WHERE s.service_id=?1 ORDER BY s.node_id")?;
    let rows=q.query_map(params![id,unix_now()-45,super::dns::managed(db,id)?],|r| {
        let kind:String=r.get(5)?;
        let current=r.get::<_,Option<String>>(6)?.as_deref()==Some(kind.as_str()) && r.get::<_,Option<bool>>(7)?.unwrap_or(false);
        Ok(json!({"node_id":r.get::<_,String>(0)?,"node_name":r.get::<_,String>(4)?,"healthy":r.get::<_,bool>(1)?,"error":r.get::<_,Option<String>>(2)?,"checked_at":r.get::<_,Option<i64>>(3)?,"public_probe":{"kind":kind,"healthy":current && r.get::<_,Option<bool>>(8)?.unwrap_or(false),"checked_at":if current { r.get::<_,Option<i64>>(9)? } else { None },"error":if current { r.get::<_,Option<String>>(10)? } else { None }}}))
    })?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(json!(rows))
}
