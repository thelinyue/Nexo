//! 节点组由管理员维护，分配即授权组内节点；成员变更与所有关联服务重绑定在同一事务提交。
//! 端口冲突、首选节点被移出、节点不足或撤销使用中工作空间都会拒绝整次编辑，避免部分生效。
use super::*;

pub fn members(db: &Connection, id: &str) -> rusqlite::Result<Vec<String>> {
    db.prepare("SELECT node_id FROM relay_group_members WHERE group_id=?1 ORDER BY node_id")?
        .query_map([id], |r| r.get(0))?
        .collect()
}
#[derive(Deserialize)]
pub struct Input {
    name: String,
    node_ids: Vec<String>,
    workspace_ids: Vec<String>,
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let actor = require_session(&state, &headers)?;
    let admin = accounts::require_admin(&state, &headers).is_ok();
    let db = state.db.lock().map_err(db_error)?;
    let mut q=db.prepare("SELECT id,name FROM relay_node_groups WHERE ?2 OR EXISTS(SELECT 1 FROM relay_group_grants WHERE group_id=id AND tenant_id=?1) ORDER BY name,id").map_err(db_error)?;
    let rows = q
        .query_map(params![actor.tenant_id, admin], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_error)?;
    let mut result = Vec::new();
    for (id, name) in rows {
        let selectable:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM relay_group_grants WHERE group_id=?1 AND tenant_id=?2)",params![id,actor.tenant_id],|r|r.get(0)).map_err(db_error)?;
        let mut group = json!({"id":id,"name":name,"node_ids":members(&db,&id).map_err(db_error)?,"selectable":selectable});
        if admin {
            group["workspace_ids"] = json!(db
                .prepare(
                    "SELECT tenant_id FROM relay_group_grants WHERE group_id=?1 ORDER BY tenant_id"
                )
                .map_err(db_error)?
                .query_map([&id], |r| r.get::<_, String>(0))
                .map_err(db_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_error)?);
        }
        result.push(group);
    }
    Ok(Json(json!(result)))
}
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> Result<Json<Value>, ApiError> {
    save(&state, &headers, &Uuid::new_v4().to_string(), input, true)?;
    list(State(state), headers).await
}
pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Input>,
) -> Result<Json<Value>, ApiError> {
    save(&state, &headers, &id, input, false)?;
    reverse_proxy::changed(&state, true).await?;
    list(State(state), headers).await
}
fn save(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
    input: Input,
    creating: bool,
) -> Result<(), ApiError> {
    let actor = admin_write(state, headers)?;
    if input.name.trim().is_empty()
        || input.name.chars().count() > 80
        || input.name.chars().any(char::is_control)
    {
        return Err(invalid("节点组名称需为 1–80 个可见字符"));
    }
    if input.node_ids.len() < 2
        || input.node_ids.len() > 16
        || input
            .node_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != input.node_ids.len()
    {
        return Err(invalid("节点组需要 2–16 个不同节点"));
    }
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    if creating {
        tx.execute(
            "INSERT INTO relay_node_groups VALUES(?1,?2,?3)",
            params![id, input.name.trim(), unix_now()],
        )
        .map_err(db_error)?;
    } else if tx
        .execute(
            "UPDATE relay_node_groups SET name=?2 WHERE id=?1",
            params![id, input.name.trim()],
        )
        .map_err(db_error)?
        == 0
    {
        return Err(invalid("节点组不存在"));
    }
    for node in &input.node_ids {
        if !tx.query_row("SELECT EXISTS(SELECT 1 FROM relay_nodes WHERE id=?1 AND approved=1 AND removed_at IS NULL)",[node],|r|r.get::<_,bool>(0)).map_err(db_error)?{return Err(invalid("节点组只能包含已审批的节点"));}
    }
    let mut q = tx
        .prepare("SELECT id,tenant_id FROM tunnels WHERE node_group_id=?1 AND deleted_at IS NULL")
        .map_err(db_error)?;
    let services = q
        .query_map([id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_error)?;
    drop(q);
    if services
        .iter()
        .any(|(_, tenant)| !input.workspace_ids.contains(tenant))
    {
        return Err(invalid(
            "有服务正在使用此节点组，请先调整服务再撤销工作空间分配",
        ));
    }
    tx.execute("DELETE FROM relay_group_members WHERE group_id=?1", [id])
        .map_err(db_error)?;
    for node in &input.node_ids {
        tx.execute(
            "INSERT INTO relay_group_members VALUES(?1,?2)",
            params![id, node],
        )
        .map_err(db_error)?;
    }
    tx.execute("DELETE FROM relay_group_grants WHERE group_id=?1", [id])
        .map_err(db_error)?;
    for tenant in &input.workspace_ids {
        accounts::ensure_workspace_enabled(&tx, tenant)?;
        tx.execute(
            "INSERT OR IGNORE INTO relay_group_grants VALUES(?1,?2)",
            params![id, tenant],
        )
        .map_err(db_error)?;
    }
    for (service, tenant) in services {
        let current = query_tunnels(
            &tx,
            &tenant,
            Some(&service),
            headers,
            state.config.caddy.http_port(),
        )
        .map_err(db_error)?
        .into_iter()
        .next()
        .ok_or_else(missing)?;
        let domain: Option<String> = tx
            .query_row(
                "SELECT public_domain_id FROM tunnels WHERE id=?1",
                [&service],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        let mut value = serde_json::to_value(current).map_err(db_error)?;
        value["public_domain_id"] = json!(domain);
        let mut request: TunnelInput = serde_json::from_value(value).map_err(db_error)?;
        super::services::prepare(&tx, &tenant, &service, &mut request)?;
        prepare_tunnel(&tx, &tenant, &service, &mut request)?;
        https_ports::prepare(state, &tx, &tenant, &service, &mut request)?;
        super::services::save(&tx, &service, &request)?;
        tx.execute("UPDATE tunnels SET apply_revision=apply_revision+1,apply_status='checking',updated_at=?2 WHERE id=?1",params![service,unix_now()]).map_err(db_error)?;
    }
    accounts::audit(
        &tx,
        &actor,
        if creating {
            "node_group_created"
        } else {
            "node_group_updated"
        },
        "node_group",
        id,
    )?;
    tx.commit().map_err(db_error)?;
    Ok(())
}
pub async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let actor = admin_write(&state, &headers)?;
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    if tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tunnels WHERE node_group_id=?1)",
            [&id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(db_error)?
    {
        return Err(invalid("请先解除关联服务与节点组的绑定，再删除节点组"));
    }
    if tx
        .execute("DELETE FROM relay_node_groups WHERE id=?1", [&id])
        .map_err(db_error)?
        == 0
    {
        return Err(invalid("节点组不存在"));
    }
    accounts::audit(&tx, &actor, "node_group_removed", "node_group", &id)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(json!({"removed":true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn membership_changes_rebind_atomically_and_keep_manual_preference() {
        let (state, admin) = crate::tests::domain_fixture();
        {
            let db = state.db.lock().unwrap();
            for (id, ip) in [
                ("a", "203.0.113.10"),
                ("b", "203.0.113.11"),
                ("c", "203.0.113.12"),
            ] {
                db.execute("INSERT INTO relay_nodes(id,name,public_ipv4,approved,created_at) VALUES(?1,?1,?2,1,0)",params![id,ip]).unwrap();
            }
            db.execute("INSERT INTO public_domains(id,tenant_id,domain,created_at,updated_at) VALUES('d','default','groups.test',0,0)",[]).unwrap();
            db.execute("INSERT INTO domain_settings(domain_id,certificate_mode,verified,verification_token,credential_file) VALUES('d','cloudflare_dns',1,'test','unused')",[]).unwrap();
            db.execute("INSERT INTO devices(id,tenant_id,name,node_capable,created_at,updated_at) VALUES('agent','default','NAS',1,0,0)",[]).unwrap();
        }
        let input = |nodes: &[&str]| Input {
            name: "入口组".into(),
            node_ids: nodes.iter().map(|s| s.to_string()).collect(),
            workspace_ids: vec!["default".into()],
        };
        save(&state, &admin, "group", input(&["a", "b"]), true).unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,local_address,local_port,public_port,hostname,public_domain_id,distribution_mode,preferred_node_id,node_group_id,created_at,updated_at) VALUES('s','default','agent','service','tcp','127.0.0.1',80,50001,'service','d','manual','b','group',0,0)",[]).unwrap();
            db.execute("DELETE FROM service_nodes WHERE service_id='s'", [])
                .unwrap();
            db.execute("INSERT INTO service_nodes VALUES('s','a'),('s','b')", [])
                .unwrap();
        }
        save(&state, &admin, "group", input(&["b", "c"]), false).unwrap();
        {
            let db = state.db.lock().unwrap();
            assert_eq!(
                super::super::services::ids(&db, "s").unwrap(),
                vec!["b", "c"]
            );
            assert_eq!(
                db.query_row(
                    "SELECT preferred_node_id FROM tunnels WHERE id='s'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
                "b"
            );
        }
        assert!(save(&state, &admin, "group", input(&["a", "c"]), false).is_err());
        {
            let db = state.db.lock().unwrap();
            assert_eq!(members(&db, "group").unwrap(), vec!["b", "c"]);
            db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,public_port,created_at,updated_at) VALUES('conflict','default','conflict','tcp','127.0.0.1',80,50001,0,0)",[]).unwrap();
            db.execute(
                "UPDATE service_nodes SET node_id='a' WHERE service_id='conflict'",
                [],
            )
            .unwrap();
        }
        assert!(save(&state, &admin, "group", input(&["a", "b"]), false).is_err());
        let db = state.db.lock().unwrap();
        assert_eq!(members(&db, "group").unwrap(), vec!["b", "c"]);
        assert_eq!(
            super::super::services::ids(&db, "s").unwrap(),
            vec!["b", "c"]
        );
        assert_eq!(
            db.query_row("SELECT apply_revision FROM tunnels WHERE id='s'", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
}
