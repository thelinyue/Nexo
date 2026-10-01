//! 更新队列使用 SQLite 事务串行创建；持久阶段必须与节点实际版本核对，不能把断线视为成功。
use super::*;

pub fn version(value: &str) -> Option<(u64, u64, u64)> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|p| {
            p.is_empty()
                || p.len() > 1 && p.starts_with('0')
                || !p.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}
pub fn busy(db: &Connection, node: &str) -> rusqlite::Result<bool> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM node_update_items i JOIN node_update_jobs j ON j.id=i.job_id WHERE i.node_id=?1 AND j.status IN ('queued','running','paused') AND i.stage NOT IN ('complete','skipped','cancelled'))",[node],|r|r.get(0))
}
#[derive(Deserialize)]
pub struct Input {
    node_ids: Vec<String>,
    target_version: String,
    #[serde(default)]
    accept_interruption: bool,
    #[serde(default = "operation")]
    operation: String,
}
fn operation() -> String {
    "update".into()
}
pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> Result<Json<Value>, ApiError> {
    let actor = admin_write(&state, &headers)?;
    if !matches!(input.operation.as_str(), "update" | "restart") {
        return Err(invalid("不支持的维护操作"));
    }
    let target = version(&input.target_version).ok_or_else(|| invalid("只能选择正式数字版本"))?;
    if target > version(env!("CARGO_PKG_VERSION")).unwrap() {
        return Err(invalid("请先升级管理 Server，节点版本不能高于管理 Server"));
    }
    if input.node_ids.is_empty() || input.node_ids.len() > 100 {
        return Err(invalid("请选择 1–100 个节点"));
    }
    let unique = input
        .node_ids
        .iter()
        .collect::<std::collections::HashSet<_>>();
    if unique.len() != input.node_ids.len() {
        return Err(invalid("更新队列不能包含重复节点"));
    }
    let releases = if input.operation == "update" {
        super::releases::catalog().await?
    } else {
        vec![]
    };
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    for id in &input.node_ids {
        if id == "local" {
            return Err(invalid("内置节点随 Server 升级，不支持远程更新"));
        }
        if !visible(&tx, id, &actor.tenant_id, true)? {
            return Err(missing());
        }
        if busy(&tx, id).map_err(db_error)? {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "所选节点已有未结束的维护任务",
            ));
        }
        let (ready,current,arch):(bool,Option<String>,Option<String>)=tx.query_row("SELECT approved=1 AND enabled=1 AND last_seen>?2,version,architecture FROM relay_nodes WHERE id=?1",params![id,unix_now()-45],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(db_error)?;
        if !ready {
            return Err(invalid("只能更新已审批且在线的节点"));
        }
        if !matches!(arch.as_deref(), Some("x86_64" | "aarch64")) {
            return Err(invalid("节点架构不支持原生更新"));
        }
        if input.operation == "update"
            && !releases.iter().any(|release| {
                release.version == input.target_version
                    && arch
                        .as_ref()
                        .is_some_and(|arch| release.architectures.contains(arch))
            })
        {
            return Err(invalid("该版本没有对应架构的官方节点安装包"));
        }
        if input.operation == "update"
            && current
                .as_deref()
                .and_then(version)
                .is_none_or(|v| v >= target)
        {
            return Err(invalid("目标版本必须高于节点当前版本"));
        }
        if input.operation == "restart" && current.as_deref() != Some(input.target_version.as_str())
        {
            return Err(invalid("重启不能同时变更版本"));
        }
        if !input.accept_interruption && !has_alternatives(&tx, id).map_err(db_error)? {
            return Err(invalid("部分服务没有其他健康 VPS 入口，请明确接受更新中断"));
        }
    }
    let id = Uuid::new_v4().to_string();
    tx.execute("INSERT INTO node_update_jobs(id,actor,target_version,accept_interruption,created_at,operation) VALUES(?1,?2,?3,?4,?5,?6)",params![id,actor.user_id,input.target_version,input.accept_interruption,unix_now(),input.operation]).map_err(db_error)?;
    for (position, node) in input.node_ids.iter().enumerate() {
        tx.execute(
            "INSERT INTO node_update_items(job_id,node_id,position) VALUES(?1,?2,?3)",
            params![id, node, position],
        )
        .map_err(db_error)?;
        event(
            &tx,
            node,
            &actor.user_id,
            &format!("加入顺序更新队列，目标 {}", input.target_version),
        )?;
    }
    tx.commit().map_err(db_error)?;
    Ok(Json(json!({"id":id,"status":"queued"})))
}
/// IPv6 直连不计入替代入口；逐服务核对，避免只有部分服务有备用节点时误判可维护。
pub fn alternatives(db: &Connection, node: &str, service: &str) -> rusqlite::Result<Vec<Value>> {
    db.prepare("SELECT n.id,n.name FROM relay_healthy_service_nodes h JOIN relay_nodes n ON n.id=h.node_id WHERE h.service_id=?1 AND n.id!=?2 ORDER BY n.name,n.id")?.query_map(params![service,node],|r|Ok(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?})))?.collect()
}
pub fn has_alternatives(db: &Connection, node: &str) -> rusqlite::Result<bool> {
    let ids=db.prepare("SELECT t.id FROM service_nodes s JOIN tunnels t ON t.id=s.service_id WHERE s.node_id=?1 AND t.enabled=1 AND t.deleted_at IS NULL")?.query_map([node],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    for service in ids {
        if alternatives(db, node, &service)?.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    accounts::require_admin(&state, &headers)?;
    let db = state.db.lock().map_err(db_error)?;
    let mut q=db.prepare("SELECT id,actor,target_version,status,created_at,finished_at FROM node_update_jobs ORDER BY created_at DESC LIMIT 50").map_err(db_error)?;
    let mut jobs=q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"actor":r.get::<_,String>(1)?,"target_version":r.get::<_,String>(2)?,"status":r.get::<_,String>(3)?,"created_at":r.get::<_,i64>(4)?,"finished_at":r.get::<_,Option<i64>>(5)?}))).map_err(db_error)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)?;
    for job in &mut jobs {
        let mut q=db.prepare("SELECT node_id,stage,error,started_at,finished_at FROM node_update_items WHERE job_id=?1 ORDER BY position").map_err(db_error)?;
        job["items"]=json!(q.query_map([job["id"].as_str().unwrap()],|r|Ok(json!({"node_id":r.get::<_,String>(0)?,"stage":r.get::<_,String>(1)?,"error":r.get::<_,Option<String>>(2)?,"started_at":r.get::<_,Option<i64>>(3)?,"finished_at":r.get::<_,Option<i64>>(4)?}))).map_err(db_error)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)?);
    }
    Ok(Json(json!(jobs)))
}
#[derive(Deserialize)]
pub struct Action {
    action: String,
}
pub async fn action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Action>,
) -> Result<Json<Value>, ApiError> {
    let actor = admin_write(&state, &headers)?;
    if !matches!(
        input.action.as_str(),
        "retry" | "skip" | "cancel" | "wait" | "force"
    ) {
        return Err(invalid("不支持的更新操作"));
    }
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    let status = tx
        .query_row(
            "SELECT status FROM node_update_jobs WHERE id=?1",
            [&id],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(missing)?;
    if !matches!(status.as_str(), "paused" | "queued") {
        return Err(invalid("请等待当前更新阶段完成或暂停"));
    }
    let item=tx.query_row("SELECT node_id,stage FROM node_update_items WHERE job_id=?1 AND stage NOT IN ('complete','skipped','cancelled') ORDER BY position LIMIT 1",[&id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional().map_err(db_error)?.ok_or_else(||invalid("任务已经结束"))?;
    if input.action == "retry"
        && matches!(
            item.1.as_str(),
            "installing" | "verifying" | "unknown" | "rollback_failed"
        )
    {
        return Err(invalid(
            "当前安装结果未确认，请先核对节点及本机助手状态，不可重复安装",
        ));
    }
    match input.action.as_str() {
        "cancel" => {
            tx.execute("UPDATE node_update_items SET stage='cancelled',finished_at=?2 WHERE job_id=?1 AND stage NOT IN ('complete','skipped')",params![id,unix_now()]).map_err(db_error)?;
            tx.execute(
                "UPDATE node_update_jobs SET status='cancelled',finished_at=?2 WHERE id=?1",
                params![id, unix_now()],
            )
            .map_err(db_error)?;
        }
        "skip" => {
            tx.execute("UPDATE node_update_items SET stage='skipped',finished_at=?3 WHERE job_id=?1 AND node_id=?2",params![id,item.0,unix_now()]).map_err(db_error)?;
        }
        "wait" | "force" => {
            if item.1 != "draining" {
                return Err(invalid("当前节点不在等待连接排空阶段"));
            }
            tx.execute("UPDATE node_update_items SET deadline=?3,force_disconnect=?4,error=NULL WHERE job_id=?1 AND node_id=?2",params![id,item.0,unix_now()+300,input.action=="force"]).map_err(db_error)?;
        }
        "retry" if item.1 == "restoring" => {
            tx.execute("UPDATE node_update_items SET error=NULL,deadline=?3 WHERE job_id=?1 AND node_id=?2",params![id,item.0,unix_now()+120]).map_err(db_error)?;
            tx.execute(
                "UPDATE relay_nodes SET maintenance=0 WHERE id=?1",
                [&item.0],
            )
            .map_err(db_error)?;
        }
        _ => {
            tx.execute("UPDATE node_update_items SET stage='queued',error=NULL,deadline=NULL,attempt=attempt+1 WHERE job_id=?1 AND node_id=?2",params![id,item.0]).map_err(db_error)?;
        }
    }
    if input.action != "cancel" {
        tx.execute(
            "UPDATE node_update_jobs SET status='queued' WHERE id=?1",
            [&id],
        )
        .map_err(db_error)?;
    }
    if matches!(input.action.as_str(), "cancel" | "skip") {
        if matches!(
            item.1.as_str(),
            "installing" | "verifying" | "unknown" | "rollback_failed"
        ) {
            return Err(invalid("请先确认节点实际版本和健康状态，再结束该维护任务"));
        }
        tx.execute(
            "UPDATE relay_nodes SET maintenance=0 WHERE id=?1",
            [&item.0],
        )
        .map_err(db_error)?;
    }
    event(
        &tx,
        &item.0,
        &actor.user_id,
        &format!("更新队列操作：{}", input.action),
    )?;
    tx.commit().map_err(db_error)?;
    Ok(Json(json!({"accepted":true})))
}

/// 每次节点轮询都核对助手实际状态。数据库只允许最早的未结束任务推进，暂停会阻止后续队列。
pub fn advance(
    state: &AppState,
    node: &str,
    current_version: &str,
    connections: u64,
    report: &nexo_protocol::nodes::UpdateReport,
) -> Result<Option<nexo_protocol::nodes::UpdateCommand>> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let tx = db.unchecked_transaction()?;
    let job:Option<(String,String,String,bool,String)>=tx.query_row("SELECT id,target_version,status,accept_interruption,operation FROM node_update_jobs WHERE status IN ('queued','running','paused') ORDER BY created_at,id LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
    let Some((job, target, status, accept, operation)) = job else {
        return Ok(None);
    };
    let item:Option<(String,String,Option<i64>,bool,i64,i64)>=tx.query_row("SELECT node_id,stage,deadline,force_disconnect,position,attempt FROM node_update_items WHERE job_id=?1 AND stage NOT IN ('complete','skipped','cancelled') ORDER BY position LIMIT 1",[&job],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
    let Some((selected, stage, deadline, force, position, attempt)) = item else {
        tx.execute(
            "UPDATE node_update_jobs SET status='complete',finished_at=?2 WHERE id=?1",
            params![job, unix_now()],
        )?;
        tx.commit()?;
        return Ok(None);
    };
    if selected != node {
        return Ok(None);
    }
    let task_id = format!("{job}-{position}-{attempt}");
    let reported = if report.task_id.as_deref() == Some(&task_id) {
        report.stage.as_str()
    } else {
        "unknown"
    };
    if status == "paused" {
        // 管理进程重启或超时后只核对实际结果；恢复队列仍需管理员点击重试。
        let next = if matches!(stage.as_str(), "installing" | "unknown")
            && reported == "installed"
            && current_version == target
        {
            Some(("verifying", "助手确认安装完成，正在核对服务入口"))
        } else if stage == "verifying" && current_version == target && verified(&tx, node)? {
            Some((
                "restoring",
                "实际版本和服务入口已确认，点击重试恢复 DNS 并继续队列",
            ))
        } else if matches!(reported, "failed" | "rolled_back" | "rollback_failed") {
            Some((reported, "助手已确认维护结果，请核对后重试、跳过或取消"))
        } else {
            None
        };
        if let Some((next, message)) = next {
            tx.execute(
                "UPDATE node_update_items SET stage=?3,error=?4 WHERE job_id=?1 AND node_id=?2",
                params![job, node, next, message],
            )?;
        }
        tx.commit()?;
        return Ok(None);
    }
    let pause = |message: &str| -> Result<()> {
        tx.execute(
            "UPDATE node_update_jobs SET status='paused' WHERE id=?1",
            [&job],
        )?;
        tx.execute(
            "UPDATE node_update_items SET error=?3 WHERE job_id=?1 AND node_id=?2",
            params![job, node, message],
        )?;
        Ok(())
    };
    let transition = |next: &str, deadline: Option<i64>| -> Result<()> {
        tx.execute("UPDATE node_update_items SET stage=?3,deadline=?4,error=NULL,started_at=COALESCE(started_at,?5) WHERE job_id=?1 AND node_id=?2",params![job,node,next,deadline,unix_now()])?;
        Ok(())
    };
    let ttl:i64=tx.query_row("SELECT COALESCE(MAX(CAST(json_extract(r.written,'$.ttl') AS INTEGER)),60) FROM relay_dns_records r JOIN relay_nodes n ON n.public_ipv4=r.address WHERE n.id=?1 AND r.written IS NOT NULL",[node],|r|r.get(0))?;
    let withdraw = || -> Result<()> {
        transition("withdrawing", None)?;
        tx.execute(
            "UPDATE node_update_items SET ttl_seconds=?3 WHERE job_id=?1 AND node_id=?2",
            params![job, node, ttl.max(60)],
        )?;
        tx.execute("UPDATE relay_nodes SET maintenance=1 WHERE id=?1", [node])?;
        Ok(())
    };
    let mut command = None;
    if matches!(reported, "failed" | "rolled_back" | "rollback_failed") {
        transition(reported, None)?;
        pause(
            report
                .error
                .as_deref()
                .unwrap_or("节点维护失败，请检查节点日志"),
        )?;
    } else {
        match stage.as_str() {
            "queued" => {
                if !accept && !has_alternatives(&tx, node)? {
                    pause("服务缺少其他健康 VPS 入口，请调整节点或接受中断后重新创建任务")?;
                } else {
                    tx.execute(
                        "UPDATE node_update_jobs SET status='running' WHERE id=?1",
                        [&job],
                    )?;
                    if operation == "restart" {
                        withdraw()?;
                    } else {
                        transition("downloading", Some(unix_now() + 900))?;
                    }
                }
            }
            "downloading" => {
                if reported == "downloaded" {
                    if !accept && !has_alternatives(&tx, node)? {
                        pause("下载完成，但备用入口已失效，暂停维护")?;
                    } else {
                        withdraw()?;
                    }
                } else if deadline.is_some_and(|d| d < unix_now()) {
                    pause("安装包下载未在预期时间内完成，状态待确认")?;
                } else {
                    command = Some("prepare");
                }
            }
            "withdrawing" => {
                let remaining:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM relay_dns_records r JOIN relay_nodes n ON n.public_ipv4=r.address WHERE n.id=?1 AND r.written IS NOT NULL)",[node],|r|r.get(0))?;
                if !remaining {
                    if deadline.is_none() {
                        let wait:i64=tx.query_row("SELECT ttl_seconds FROM node_update_items WHERE job_id=?1 AND node_id=?2",params![job,node],|r|r.get(0))?;
                        transition("withdrawing", Some(unix_now() + wait))?;
                    } else if deadline.is_some_and(|d| d <= unix_now()) {
                        transition("draining", Some(unix_now() + 300))?;
                    }
                }
            }
            "draining" => {
                if connections == 0 || force {
                    transition("installing", Some(unix_now() + 120))?;
                    tx.execute("DELETE FROM relay_service_health WHERE node_id=?1", [node])?;
                    tx.execute("DELETE FROM relay_public_health WHERE node_id=?1", [node])?;
                    command = Some(if operation == "restart" {
                        "restart"
                    } else {
                        "install"
                    });
                } else if deadline.is_some_and(|d| d <= unix_now()) {
                    pause("连接尚未排空，请选择继续等待、取消或中断连接后更新")?;
                }
            }
            "installing" => {
                if reported == "installed" && current_version == target {
                    transition("verifying", Some(unix_now() + 120))?;
                } else if deadline.is_some_and(|d| d <= unix_now()) {
                    pause("更新结果尚未确认，请核对节点实际版本；未恢复 DNS")?;
                } else if reported == "downloaded" && operation == "update" {
                    // 仅助手确认尚未安装时重发；未知状态等待核对，不能重放重启命令。
                    command = Some("install");
                }
            }
            "verifying" => {
                let unhealthy = !verified(&tx, node)?;
                if !unhealthy && current_version == target {
                    transition("restoring", Some(unix_now() + 120))?;
                    tx.execute("UPDATE relay_nodes SET maintenance=0 WHERE id=?1", [node])?;
                } else if deadline.is_some_and(|d| d <= unix_now()) {
                    pause("新版本已启动，但关联服务尚未恢复健康")?;
                }
            }
            "restoring" => {
                let unhealthy:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM tunnels t JOIN service_nodes s ON s.service_id=t.id LEFT JOIN relay_dns_state d ON d.service_id=t.id WHERE s.node_id=?1 AND t.enabled=1 AND t.deleted_at IS NULL AND (d.service_id IS NULL OR d.error IS NOT NULL OR d.revision!=t.apply_revision OR d.synced_at<?2))",params![node,deadline.unwrap_or(i64::MAX)-120],|r|r.get(0))?;
                if !unhealthy {
                    transition("complete", None)?;
                    tx.execute("INSERT INTO relay_node_events(node_id,actor,message,occurred_at) SELECT ?2,actor,'节点维护完成，版本和服务已验证',?3 FROM node_update_jobs WHERE id=?1",params![job,node,unix_now()])?;
                    tx.execute("UPDATE node_update_items SET finished_at=?3 WHERE job_id=?1 AND node_id=?2",params![job,node,unix_now()])?;
                } else if deadline.is_some_and(|d| d <= unix_now()) {
                    pause("节点已恢复，DNS 更新尚未完成，后续队列暂停")?;
                }
            }
            _ => pause("节点维护阶段需要管理员核对")?,
        }
    }
    tx.commit()?;
    Ok(command.map(|action| nexo_protocol::nodes::UpdateCommand {
        task_id,
        action: action.into(),
        version: target,
        force,
    }))
}

/// 维护后的验证必须同时包含配置版本、Agent 通道及公网探测，旧统计不能视为恢复。
fn verified(db: &Connection, node: &str) -> rusqlite::Result<bool> {
    // 维护节点继续接受检查，但恢复前不能作为 DNS 候选或其他节点的备用入口。
    db.query_row("SELECT NOT EXISTS(SELECT 1 FROM authorized_service_nodes s JOIN tunnels t ON t.id=s.service_id JOIN tenants w ON w.id=t.tenant_id WHERE s.node_id=?1 AND t.enabled=1 AND t.deleted_at IS NULL AND w.enabled=1 AND NOT EXISTS(SELECT 1 FROM relay_ready_service_nodes h WHERE h.service_id=s.service_id AND h.node_id=s.node_id))",[node],|r|r.get(0))
}

/// 节点停止轮询时也要暂停持久任务，重启后根据同一任务状态核对，不能把失联算作成功。
pub fn reconcile(state: &AppState) -> Result<()> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let tx = db.unchecked_transaction()?;
    tx.execute("UPDATE node_update_items SET error='节点失联或维护超时，请核对节点与本机更新助手状态' WHERE job_id IN (SELECT id FROM node_update_jobs WHERE status='running') AND stage NOT IN ('complete','skipped','cancelled','queued') AND ((stage IN ('installing','verifying','restoring','downloading') AND deadline<?1) OR (stage NOT IN ('installing') AND EXISTS(SELECT 1 FROM relay_nodes n WHERE n.id=node_id AND n.last_seen<?1-45)))",[unix_now()])?;
    tx.execute("UPDATE node_update_jobs SET status='paused' WHERE status='running' AND EXISTS(SELECT 1 FROM node_update_items i WHERE i.job_id=id AND i.error IS NOT NULL)",[])?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (AppState, HeaderMap) {
        let (state, admin) = crate::tests::domain_fixture();
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO public_domains(id,tenant_id,domain,created_at,updated_at) VALUES('d','default','test.example',0,0)",[]).unwrap();
            db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,public_port,hostname,public_domain_id,distribution_mode,created_at,updated_at) VALUES('s','default','s','tcp','127.0.0.1',80,50001,'service','d','dns',0,0)",[]).unwrap();
            db.execute("DELETE FROM service_nodes WHERE service_id='s'", [])
                .unwrap();
            for node in ["a", "b"] {
                db.execute("INSERT INTO relay_nodes(id,name,public_ipv4,approved,version,architecture,last_seen,created_at) VALUES(?1,?1,?2,1,'0.2.10','x86_64',?3,0)",params![node,if node=="a"{"203.0.113.10"}else{"203.0.113.11"},unix_now()]).unwrap();
                db.execute("INSERT INTO service_nodes VALUES('s',?1)", [node])
                    .unwrap();
                db.execute("INSERT INTO relay_node_grants VALUES(?1,'default')", [node])
                    .unwrap();
            }
        }
        healthy(&state, "a");
        healthy(&state, "b");
        (state, admin)
    }
    fn healthy(state: &AppState, node: &str) {
        let db = state.db.lock().unwrap();
        for table in ["relay_service_health", "relay_public_health"] {
            db.execute(&format!("INSERT OR REPLACE INTO {table}(node_id,service_id,revision,healthy,checked_at) VALUES(?1,'s',1,1,?2)"),params![node,unix_now()]).unwrap();
        }
        db.execute("UPDATE relay_public_health SET address=(SELECT public_ipv4 FROM relay_nodes WHERE id=?1) WHERE node_id=?1",[node]).unwrap();
        db.execute("INSERT INTO tunnel_applied_states(tunnel_id,revision,status,updated_at) VALUES('s',1,'ready',?1) ON CONFLICT(tunnel_id) DO UPDATE SET updated_at=excluded.updated_at",[unix_now()]).unwrap();
    }
    fn job(state: &AppState) {
        state.db.lock().unwrap().execute_batch("INSERT INTO node_update_jobs(id,actor,target_version,created_at) VALUES('job','u','0.2.11',0); INSERT INTO node_update_items(job_id,node_id,position) VALUES('job','a',0),('job','b',1);").unwrap();
    }
    fn report(stage: &str) -> nexo_protocol::nodes::UpdateReport {
        nexo_protocol::nodes::UpdateReport {
            task_id: Some("job-0-0".into()),
            stage: stage.into(),
            error: None,
        }
    }
    fn stage(state: &AppState) -> (String, String) {
        state.db.lock().unwrap().query_row("SELECT j.status,i.stage FROM node_update_jobs j JOIN node_update_items i ON i.job_id=j.id WHERE j.id='job' AND i.node_id='a'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap()
    }
    fn expired(state: &AppState) {
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE node_update_items SET deadline=?1 WHERE job_id='job' AND node_id='a'",
                [unix_now() - 1],
            )
            .unwrap();
    }
    #[tokio::test]
    async fn rolling_update_waits_for_actual_ttl_and_explicit_drain_decision() {
        let (state, admin) = fixture();
        job(&state);
        let idle = nexo_protocol::nodes::UpdateReport::default();
        assert!(advance(&state, "b", "0.2.10", 0, &idle).unwrap().is_none());
        assert!(advance(&state, "a", "0.2.10", 1, &idle).unwrap().is_none());
        assert_eq!(
            advance(&state, "a", "0.2.10", 1, &idle)
                .unwrap()
                .unwrap()
                .action,
            "prepare"
        );
        state.db.lock().unwrap().execute("INSERT INTO relay_dns_records(service_id,domain_id,hostname,address,written) VALUES('s','d','service.test.example','203.0.113.10',?1)",[json!({"ttl":180}).to_string()]).unwrap();
        advance(&state, "a", "0.2.10", 1, &report("downloaded")).unwrap();
        assert_eq!(stage(&state).1, "withdrawing");
        advance(&state, "a", "0.2.10", 1, &report("downloaded")).unwrap();
        assert!(state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT deadline IS NULL FROM node_update_items WHERE node_id='a'",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
        state
            .db
            .lock()
            .unwrap()
            .execute("DELETE FROM relay_dns_records", [])
            .unwrap();
        advance(&state, "a", "0.2.10", 1, &report("downloaded")).unwrap();
        let deadline: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT deadline FROM node_update_items WHERE node_id='a'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(deadline >= unix_now() + 179);
        expired(&state);
        advance(&state, "a", "0.2.10", 1, &report("downloaded")).unwrap();
        assert_eq!(stage(&state).1, "draining");
        expired(&state);
        assert!(advance(&state, "a", "0.2.10", 1, &report("downloaded"))
            .unwrap()
            .is_none());
        assert_eq!(stage(&state).0, "paused");
        let _ = action(
            State(state.clone()),
            admin.clone(),
            Path("job".into()),
            Json(Action {
                action: "wait".into(),
            }),
        )
        .await
        .unwrap();
        assert!(advance(&state, "a", "0.2.10", 1, &report("downloaded"))
            .unwrap()
            .is_none());
        expired(&state);
        advance(&state, "a", "0.2.10", 1, &report("downloaded")).unwrap();
        let _ = action(
            State(state.clone()),
            admin,
            Path("job".into()),
            Json(Action {
                action: "force".into(),
            }),
        )
        .await
        .unwrap();
        let command = advance(&state, "a", "0.2.10", 1, &report("downloaded"))
            .unwrap()
            .unwrap();
        assert_eq!(command.action, "install");
        assert!(command.force);
        assert!(
            advance(&state, "a", "0.2.10", 0, &idle).unwrap().is_none(),
            "未知助手状态不得盲目重放安装"
        );
        advance(&state, "a", "0.2.11", 0, &report("installed")).unwrap();
        assert_eq!(stage(&state).1, "verifying");
        advance(&state, "a", "0.2.11", 0, &report("installed")).unwrap();
        assert_eq!(stage(&state).1, "verifying", "旧健康记录必须已清除");
        healthy(&state, "a");
        advance(&state, "a", "0.2.11", 0, &report("installed")).unwrap();
        assert_eq!(stage(&state).1, "restoring");
        advance(&state, "a", "0.2.11", 0, &report("installed")).unwrap();
        assert_eq!(stage(&state).1, "restoring", "等待 DNS 恢复确认");
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO relay_dns_state VALUES('s',1,?1,NULL)",
                [unix_now()],
            )
            .unwrap();
        advance(&state, "a", "0.2.11", 0, &report("installed")).unwrap();
        assert_eq!(stage(&state).1, "complete");
        advance(&state, "b", "0.2.10", 0, &idle).unwrap();
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT stage FROM node_update_items WHERE node_id='b'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            "downloading"
        );
    }
    #[tokio::test]
    async fn paused_install_reconciles_actual_state_before_admin_resumes() {
        let (state, admin) = fixture();
        job(&state);
        state.db.lock().unwrap().execute_batch("UPDATE node_update_jobs SET status='running'; UPDATE node_update_items SET stage='installing',deadline=0 WHERE node_id='a'; UPDATE relay_nodes SET maintenance=1 WHERE id='a'; DELETE FROM relay_service_health WHERE node_id='a'; DELETE FROM relay_public_health WHERE node_id='a';").unwrap();
        reconcile(&state).unwrap();
        assert_eq!(stage(&state).0, "paused");
        assert!(advance(&state, "a", "0.2.11", 0, &report("installed"))
            .unwrap()
            .is_none());
        assert_eq!(stage(&state), ("paused".into(), "verifying".into()));
        assert!(advance(&state, "b", "0.2.10", 0, &Default::default())
            .unwrap()
            .is_none());
        healthy(&state, "a");
        advance(&state, "a", "0.2.11", 0, &report("installed")).unwrap();
        assert_eq!(stage(&state), ("paused".into(), "restoring".into()));
        assert!(state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT maintenance FROM relay_nodes WHERE id='a'",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
        let _ = action(
            State(state.clone()),
            admin,
            Path("job".into()),
            Json(Action {
                action: "retry".into(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(stage(&state), ("queued".into(), "restoring".into()));
        assert!(!state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT maintenance FROM relay_nodes WHERE id='a'",
                [],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
    }

    #[test]
    fn maintenance_verification_requires_current_method_address_and_origin() {
        let (state, _) = fixture();
        let db = state.db.lock().unwrap();
        db.execute_batch(
            "UPDATE tunnels SET protocol='http'; UPDATE relay_nodes SET maintenance=1 WHERE id='a'",
        )
        .unwrap();
        assert!(verified(&db, "a").unwrap(), "旧节点仍允许 TCP 兼容检查");
        db.execute(
            "UPDATE relay_service_health SET public_probe_supported=1 WHERE node_id='a'",
            [],
        )
        .unwrap();
        assert!(!verified(&db, "a").unwrap(), "旧 TCP 样本不能验证新节点");
        db.execute(
            "UPDATE relay_public_health SET probe_kind='http' WHERE node_id='a'",
            [],
        )
        .unwrap();
        assert!(verified(&db, "a").unwrap(), "维护状态不阻止恢复前验证");
        db.execute(
            "UPDATE relay_nodes SET public_ipv4='203.0.113.20' WHERE id='a'",
            [],
        )
        .unwrap();
        assert!(!verified(&db, "a").unwrap());
        db.execute(
            "UPDATE relay_public_health SET address='203.0.113.20' WHERE node_id='a'",
            [],
        )
        .unwrap();
        assert!(verified(&db, "a").unwrap());
        db.execute("UPDATE tunnel_applied_states SET status='failed'", [])
            .unwrap();
        assert!(!verified(&db, "a").unwrap());
        db.execute(
            "UPDATE tunnel_applied_states SET status='ready',updated_at=unixepoch()-46",
            [],
        )
        .unwrap();
        assert!(!verified(&db, "a").unwrap());
    }

    #[test]
    fn alternatives_require_authorization_public_health_and_current_revision() {
        let (state, _) = fixture();
        let db = state.db.lock().unwrap();
        assert!(has_alternatives(&db, "a").unwrap());
        db.execute(
            "UPDATE relay_public_health SET healthy=0 WHERE node_id='b'",
            [],
        )
        .unwrap();
        assert!(!has_alternatives(&db, "a").unwrap());
        db.execute(
            "UPDATE relay_public_health SET healthy=1 WHERE node_id='b'",
            [],
        )
        .unwrap();
        db.execute("DELETE FROM relay_node_grants WHERE node_id='b'", [])
            .unwrap();
        assert!(!has_alternatives(&db, "a").unwrap());
        db.execute("INSERT INTO relay_node_grants VALUES('b','default')", [])
            .unwrap();
        db.execute("UPDATE tunnels SET apply_revision=2 WHERE id='s'", [])
            .unwrap();
        assert!(!has_alternatives(&db, "a").unwrap());
    }
    #[tokio::test]
    async fn duplicate_maintenance_is_rejected_and_rollback_pauses_queue() {
        let (state, admin) = fixture();
        job(&state);
        let input = Input {
            node_ids: vec!["a".into()],
            target_version: "0.2.10".into(),
            accept_interruption: false,
            operation: "restart".into(),
        };
        assert_eq!(
            create(State(state.clone()), admin.clone(), Json(input))
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        advance(&state, "a", "0.2.10", 0, &report("rolled_back")).unwrap();
        assert_eq!(stage(&state), ("paused".into(), "rolled_back".into()));
        assert!(advance(&state, "b", "0.2.10", 0, &Default::default())
            .unwrap()
            .is_none());
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE node_update_items SET stage='installing' WHERE node_id='a'",
                [],
            )
            .unwrap();
        for operation in ["retry", "skip", "cancel"] {
            assert!(action(
                State(state.clone()),
                admin.clone(),
                Path("job".into()),
                Json(Action {
                    action: operation.into()
                })
            )
            .await
            .is_err());
            assert_eq!(stage(&state), ("paused".into(), "installing".into()));
        }
    }

    #[test]
    fn versions_reject_paths_and_prereleases() {
        for v in [
            "1.2",
            "1.2.3-beta",
            "01.2.3",
            "../../bin",
            "1.2.3;reboot",
            "1.2.3\n",
        ] {
            assert!(version(v).is_none(), "{v}");
        }
        assert!(version("0.2.12") > version("0.2.9"));
    }
}
