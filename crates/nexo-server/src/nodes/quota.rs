//! 节点额度与用户穿透额度独立。所有节点服务在同一 SQLite 写事务内预留，
//! 回复前落盘；失联预算继续占用，重复累计报告不会重复扣费或返还。
use super::*;
use nexo_protocol::nodes::NodeQuota;

pub const EXHAUSTED: &str = "节点本月流量额度已用尽，转发已暂停";
const MAX_BYTES: u64 = 9_007_199_254_740_991;

pub fn period(now: i64) -> (i64, i64) {
    let date = time::OffsetDateTime::from_unix_timestamp(now + 8 * 3600)
        .expect("有效系统时间")
        .date();
    let start = date.replace_day(1).unwrap();
    let next = (start + time::Duration::days(32)).replace_day(1).unwrap();
    (
        start.midnight().assume_utc().unix_timestamp() - 8 * 3600,
        next.midnight().assume_utc().unix_timestamp() - 8 * 3600,
    )
}

#[derive(Serialize, Debug)]
pub struct View {
    pub monthly_limit_bytes: Option<u64>,
    pub used_bytes: u64,
    pub reserved_bytes: u64,
    pub remaining_bytes: Option<u64>,
    pub period_start: i64,
    pub period_end: i64,
    pub started_at: Option<i64>,
    pub exhausted: bool,
    pub supported: bool,
    pub revision: i64,
}

pub fn view(db: &Connection, node: &str, now: i64) -> Result<View> {
    let supported = db.query_row(
        "SELECT traffic_quota_supported FROM relay_nodes WHERE id=?1",
        [node],
        |r| r.get(0),
    )?;
    let (limit, revision, started): (Option<u64>, i64, Option<i64>) = db.query_row(
        "SELECT monthly_limit_bytes,revision,started_at FROM node_traffic_limits WHERE node_id=?1", [node],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.unwrap_or((None,0,None));
    let (month, end) = period(now);
    let (used,reserved): (u64,u64) = db.query_row(
        "SELECT used_bytes,reserved_bytes FROM node_traffic_months WHERE node_id=?1 AND month=?2", params![node,month],
        |r| Ok((r.get(0)?,r.get(1)?))).optional()?.unwrap_or((0,0));
    Ok(View {
        monthly_limit_bytes: limit,
        used_bytes: used,
        reserved_bytes: reserved,
        remaining_bytes: limit.map(|n| n.saturating_sub(used.saturating_add(reserved))),
        period_start: month,
        period_end: end,
        started_at: started,
        exhausted: limit.is_some_and(|n| used >= n),
        supported,
        revision,
    })
}

pub fn policy(db: &Connection, node: &str) -> Result<Option<NodeQuota>> {
    let v = view(db, node, unix_now())?;
    // 已设置限制的节点即使撤回能力声明也不能回退到不计量转发。
    Ok(
        (v.supported || v.monthly_limit_bytes.is_some()).then_some(NodeQuota {
            revision: v.revision,
            period_start: v.period_start,
            period_end: v.period_end,
            monthly_limit_bytes: v.monthly_limit_bytes,
            exhausted: v.exhausted || !v.supported,
        }),
    )
}

pub fn parse_limit(value: &Value) -> Result<Option<u64>, ApiError> {
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_u64()
        .filter(|n| *n > 0 && *n <= MAX_BYTES)
        .map(Some)
        .ok_or_else(|| invalid("月额度必须为正整数字节数，且不超过安全整数范围"))
}

fn can_manage(
    db: &Connection,
    id: &str,
    actor: &auth::Session,
    admin: bool,
) -> Result<bool, ApiError> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM relay_nodes WHERE id=?1 AND id!='local' AND removed_at IS NULL AND (?3 OR owner_tenant=?2))",params![id,actor.tenant_id,admin],|r|r.get(0)).map_err(db_error)
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<View>, ApiError> {
    let actor = require_session(&state, &headers)?;
    let admin = accounts::require_admin(&state, &headers).is_ok();
    let db = state.db.lock().map_err(db_error)?;
    if id == "local" || !visible(&db, &id, &actor.tenant_id, admin)? {
        return Err(missing());
    }
    Ok(Json(view(&db, &id, unix_now()).map_err(db_error)?))
}

#[derive(Deserialize)]
pub struct Input {
    #[serde(deserialize_with = "required_limit")]
    pub monthly_limit_bytes: Value,
}
fn required_limit<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Value, D::Error> {
    Value::deserialize(deserializer)
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Input>,
) -> Result<Json<View>, ApiError> {
    let actor = require_write(&state, &headers)?;
    let admin = accounts::require_admin(&state, &headers).is_ok();
    let limit = parse_limit(&input.monthly_limit_bytes)?;
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    if !can_manage(&tx, &id, &actor, admin)? {
        return Err(missing());
    }
    let old = view(&tx, &id, unix_now()).map_err(db_error)?;
    if limit.is_some() && !old.supported {
        return Err(invalid("请先升级节点以支持流量计量，再启用限制"));
    }
    if old.monthly_limit_bytes != limit {
        tx.execute("INSERT INTO node_traffic_limits(node_id,monthly_limit_bytes,revision,started_at) VALUES(?1,?2,1,?3) ON CONFLICT(node_id) DO UPDATE SET monthly_limit_bytes=excluded.monthly_limit_bytes,revision=revision+1",params![id,limit,old.started_at]).map_err(db_error)?;
        event(&tx, &id, &actor.user_id, "更新节点月流量限制")?;
        // 恢复时必须重新采集健康结果，不能直接继承额度用尽前的旧样本。
        if old.exhausted {
            tx.execute("DELETE FROM relay_service_health WHERE node_id=?1", [&id])
                .map_err(db_error)?;
            tx.execute("DELETE FROM relay_public_health WHERE node_id=?1", [&id])
                .map_err(db_error)?;
        }
    }
    let result = view(&tx, &id, unix_now()).map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(result))
}

/// 身份来自 mTLS 会话，不接受报告自行指定节点。预留、授权检查和月计数原子提交。
pub fn reserve(
    db: &Connection,
    node: &str,
    service: &str,
    service_revision: i64,
    quota_revision: i64,
    month: i64,
    requested: u32,
) -> Result<(String, u64)> {
    let tx = db.unchecked_transaction()?;
    let q = view(&tx, node, unix_now())?;
    let allowed: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM authorized_service_nodes s JOIN tunnels t ON t.id=s.service_id JOIN relay_nodes n ON n.id=s.node_id JOIN tenants w ON w.id=t.tenant_id WHERE s.node_id=?1 AND t.id=?2 AND t.apply_revision=?3 AND t.enabled=1 AND t.deleted_at IS NULL AND w.enabled=1 AND n.approved=1 AND n.enabled=1 AND n.removed_at IS NULL AND n.traffic_quota_supported=1)",params![node,service,service_revision],|r|r.get(0))?;
    if !allowed || q.exhausted || q.revision != quota_revision || q.period_start != month {
        return Ok((String::new(), 0));
    }
    let amount =
        u64::from(requested)
            .min(256 * 1024)
            .min(q.remaining_bytes.unwrap_or(
                MAX_BYTES.saturating_sub(q.used_bytes.saturating_add(q.reserved_bytes)),
            ));
    if amount == 0 {
        return Ok((String::new(), 0));
    }
    let id = Uuid::new_v4().to_string();
    tx.execute("INSERT INTO node_traffic_budgets(id,node_id,service_id,service_revision,quota_revision,month,reserved) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id,node,service,service_revision,quota_revision,month,amount])?;
    tx.execute("INSERT INTO node_traffic_months(node_id,month,reserved_bytes) VALUES(?1,?2,?3) ON CONFLICT(node_id,month) DO UPDATE SET reserved_bytes=reserved_bytes+excluded.reserved_bytes",params![node,month,amount])?;
    tx.execute("INSERT INTO node_traffic_limits(node_id,started_at) VALUES(?1,?2) ON CONFLICT(node_id) DO UPDATE SET started_at=COALESCE(started_at,excluded.started_at)",params![node,unix_now()])?;
    tx.commit()?;
    Ok((id, amount))
}

/// 接受已撤销策略的最终报告以归还未用预算；只能结算原月份，绝不能返还到新月份。
pub fn settle(
    db: &Connection,
    node: &str,
    id: &str,
    origin: u64,
    public: u64,
    finished: bool,
) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    let (month,reserved,old_origin,old_public,done):(i64,u64,u64,u64,bool) = tx.query_row("SELECT month,reserved,to_origin,to_public,finished FROM node_traffic_budgets WHERE id=?1 AND node_id=?2",params![id,node],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    if done {
        return Ok(());
    }
    anyhow::ensure!(
        origin >= old_origin
            && public >= old_public
            && origin.checked_add(public).is_some_and(|n| n <= reserved),
        "节点流量结算超出预留或发生倒退"
    );
    let delta = origin - old_origin + public - old_public;
    let returned = if finished {
        reserved - origin - public
    } else {
        0
    };
    tx.execute(
        "UPDATE node_traffic_budgets SET to_origin=?2,to_public=?3,finished=?4 WHERE id=?1",
        params![id, origin, public, finished],
    )?;
    tx.execute("UPDATE node_traffic_months SET used_bytes=used_bytes+?3,reserved_bytes=reserved_bytes-?3-?4 WHERE node_id=?1 AND month=?2",params![node,month,delta,returned])?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests;
