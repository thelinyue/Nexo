//! 月额度与可重置统计独立。转发仅持有空间短锁，成功写入才扣减；持久化快照不阻塞网络等待。
use super::*;
use tokio_util::sync::CancellationToken;

const MAX_BYTES: u64 = 9_007_199_254_740_991;
pub const EXHAUSTED: &str = "本月流量额度已用尽，隧道转发已暂停";

fn period(now: i64) -> (i64, i64) {
    let date = time::OffsetDateTime::from_unix_timestamp(now + 8 * 3600)
        .expect("有效的系统时间")
        .date();
    let start = date.replace_day(1).unwrap();
    let next = (start + time::Duration::days(32)).replace_day(1).unwrap();
    (
        start.midnight().assume_utc().unix_timestamp() - 8 * 3600,
        next.midnight().assume_utc().unix_timestamp() - 8 * 3600,
    )
}

/// 每个空间共享一个额度锁，使多隧道、多方向的检查和实际写入原子化。
pub struct Quota(Mutex<QuotaState>);
struct QuotaState {
    limit: Option<u64>,
    started_at: i64,
    months: BTreeMap<i64, u64>,
    month: i64,
    cancel: CancellationToken,
}
impl QuotaState {
    fn used(&self) -> u64 {
        self.months.get(&self.month).copied().unwrap_or(0)
    }
    fn exhausted(&self) -> bool {
        self.limit.is_some_and(|limit| self.used() >= limit)
    }
    fn refresh(&mut self, now: i64) {
        self.month = period(now).0;
        if self.exhausted() {
            self.cancel.cancel();
        } else if self.cancel.is_cancelled() {
            // 已断开的旧连接不会复活；恢复额度仅为后续连接提供新的取消令牌。
            self.cancel = CancellationToken::new();
        }
    }
}
impl Quota {
    /// 与本机写入共用额度锁。先持久化预留再回复 Agent；失联未结算预算保持占用，不能重复花费。
    pub fn reserve_remote(
        &self,
        state: &AppState,
        device: &str,
        service: &str,
        tenant: &str,
        requested: u32,
    ) -> Result<(String, u64)> {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut current = self.0.lock().unwrap_or_else(|e| e.into_inner());
        current.refresh(unix_now());
        let amount = current
            .limit
            .map(|limit| limit.saturating_sub(current.used()))
            .unwrap_or(u64::MAX)
            .min(u64::from(requested).min(1024 * 1024));
        if amount == 0 {
            return Ok((String::new(), 0));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let month = current.month;
        let used = current.used() + amount;
        let tx = db.unchecked_transaction()?;
        tx.execute("INSERT INTO relay_budgets(id,device_id,service_id,tenant_id,month,reserved) VALUES(?1,?2,?3,?4,?5,?6)",params![id,device,service,tenant,month,amount])?;
        tx.execute("INSERT INTO traffic_quota_months VALUES(?1,?2,?3) ON CONFLICT(tenant_id,month) DO UPDATE SET used_bytes=excluded.used_bytes",params![tenant,month,used])?;
        tx.commit()?;
        current.months.insert(month, used);
        Ok((id, amount))
    }
    /// 累计报告可重复发送；仅第一次最终结算归还未用预算，流量统计只增加差值。
    pub fn settle_remote(
        &self,
        state: &AppState,
        device: &str,
        id: &str,
        to_origin: u64,
        to_public: u64,
        finished: bool,
    ) -> Result<()> {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut current = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (tenant,service,month,reserved,old_origin,old_public,done):(String,String,i64,u64,u64,u64,bool)=db.query_row("SELECT tenant_id,service_id,month,reserved,to_origin,to_public,finished FROM relay_budgets WHERE id=?1 AND device_id=?2",params![id,device],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)))?;
        anyhow::ensure!(
            to_origin >= old_origin
                && to_public >= old_public
                && to_origin
                    .checked_add(to_public)
                    .is_some_and(|v| v <= reserved),
            "节点流量结算超出预留或发生倒退"
        );
        if done {
            return Ok(());
        }
        let delta_origin = to_origin - old_origin;
        let delta_public = to_public - old_public;
        let used = current
            .months
            .get(&month)
            .copied()
            .unwrap_or(0)
            .saturating_sub(if finished {
                reserved - to_origin - to_public
            } else {
                0
            });
        let tx = db.unchecked_transaction()?;
        tx.execute(
            "UPDATE relay_budgets SET to_origin=?2,to_public=?3,finished=?4 WHERE id=?1",
            params![id, to_origin, to_public, finished],
        )?;
        tx.execute("INSERT INTO traffic_quota_months VALUES(?1,?2,?3) ON CONFLICT(tenant_id,month) DO UPDATE SET used_bytes=excluded.used_bytes",params![tenant,month,used])?;
        tx.execute("INSERT INTO traffic_minutes VALUES(?1,?2,?3,?4,?5) ON CONFLICT(tenant_id,tunnel_id,minute) DO UPDATE SET to_origin=to_origin+excluded.to_origin,to_public=to_public+excluded.to_public",params![tenant,service,unix_now()/60*60,delta_origin,delta_public])?;
        tx.execute("INSERT INTO traffic_daily VALUES(?1,?2,?3,?4) ON CONFLICT(tenant_id,day) DO UPDATE SET to_origin=to_origin+excluded.to_origin,to_public=to_public+excluded.to_public",params![tenant,super::usage::day_start(unix_now()),delta_origin,delta_public])?;
        tx.commit()?;
        current.months.insert(month, used);
        current.refresh(unix_now());
        // 采样器按统计锁 → DB → 额度锁排序，必须先释放本次持有的后两把锁。
        drop(current);
        drop(db);
        state.tunnel_runtime.traffic.remote_sample(
            &tenant,
            &service,
            Bytes {
                to_origin: delta_origin,
                to_public: delta_public,
            },
        );
        Ok(())
    }
    /// 数据报不可截断。短锁内检查整包预算并同步提交，按实际提交载荷结算；
    /// 与 TCP 写入共用锁，不需要持有跨 await 的预留额度，也不会多并发超支。
    pub fn datagram(
        &self,
        length: usize,
        cancel: &CancellationToken,
        send: impl FnOnce() -> usize,
    ) -> Option<usize> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.refresh(unix_now());
        let remaining = state
            .limit
            .map(|limit| limit.saturating_sub(state.used()))
            .unwrap_or(u64::MAX);
        if cancel.is_cancelled() || remaining == 0 || remaining < length as u64 {
            return None;
        }
        let count = send().min(length);
        let month = state.month;
        *state.months.entry(month).or_default() += count as u64;
        if state.exhausted() {
            state.cancel.cancel();
        }
        Some(count)
    }
    pub fn connection(&self) -> Option<CancellationToken> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.refresh(unix_now());
        (!state.exhausted()).then(|| state.cancel.clone())
    }

    /// poll_write 不执行异步等待。Pending、错误和部分写入只按实际成功字节扣减。
    pub(super) fn write<T: AsyncWrite + Unpin>(
        &self,
        io: &mut T,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
        cancel: &CancellationToken,
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.refresh(unix_now());
        // select! 可先轮询复制分支；在空间锁内再次核对旧令牌，避免提额后旧连接抢用新预算。
        if cancel.is_cancelled() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "流量额度连接已撤销",
            )));
        }
        let remaining = state
            .limit
            .map(|limit| limit.saturating_sub(state.used()))
            .unwrap_or(u64::MAX);
        if remaining == 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                EXHAUSTED,
            )));
        }
        let size = buf.len().min(remaining.min(usize::MAX as u64) as usize);
        let result = Pin::new(io).poll_write(cx, &buf[..size]);
        if let Poll::Ready(Ok(count)) = result {
            let month = state.month;
            *state.months.entry(month).or_default() += count as u64;
            if state.exhausted() {
                state.cancel.cancel();
            }
        }
        result
    }

    fn view(&self, now: i64) -> QuotaView {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.refresh(now);
        QuotaView {
            monthly_limit_bytes: state.limit,
            used_bytes: state.used(),
            remaining_bytes: state.limit.map(|limit| limit.saturating_sub(state.used())),
            period_start: state.month,
            period_end: period(now).1,
            started_at: state.started_at,
            exhausted: state.exhausted(),
        }
    }
}

/// 注册表仅用于建立连接、管理和落盘；数据转发直接持有 Quota，不竞争全局锁。
#[derive(Default)]
pub struct Manager(Mutex<HashMap<String, Arc<Quota>>>);
impl Manager {
    /// 删除事务提交并释放数据库锁后清理，防止已删除用户长期占用内存或保留转发令牌。
    pub fn remove(&self, tenant: &str) {
        if let Some(quota) = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(tenant)
        {
            quota
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .cancel
                .cancel();
        }
    }

    pub fn get(&self, state: &AppState, tenant: &str) -> Result<Arc<Quota>> {
        let mut entries = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(quota) = entries.get(tenant) {
            return Ok(quota.clone());
        }
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let quota = Arc::new(load(&db, tenant)?);
        entries.insert(tenant.into(), quota.clone());
        Ok(quota)
    }

    /// 必须在对外监听之前调用；恢复失败向上传播，不能把未知额度当成无限额。
    pub fn restore(&self, state: &AppState) -> Result<()> {
        let mut entries = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let tenants = db
            .prepare("SELECT id FROM tenants")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for tenant in tenants {
            entries.insert(tenant.clone(), Arc::new(load(&db, &tenant)?));
        }
        Ok(())
    }

    pub(super) fn snapshot_handles(&self) -> Vec<(String, Arc<Quota>)> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(id, q)| (id.clone(), q.clone()))
            .collect()
    }
    /// 调用方先取得句柄，再持有数据库锁读取余额，防止旧快照覆盖已落盘的远端预算。
    pub(super) fn snapshot(entries: &[(String, Arc<Quota>)]) -> Vec<(String, i64, u64)> {
        let mut batch = Vec::new();
        let cutoff = period(unix_now() - 90 * 86400).0;
        for (tenant, quota) in entries.iter() {
            let mut state = quota.0.lock().unwrap_or_else(|e| e.into_inner());
            state.months.retain(|month, _| *month >= cutoff);
            batch.extend(
                state
                    .months
                    .iter()
                    .map(|(month, used)| (tenant.clone(), *month, *used)),
            );
        }
        batch
    }
}

fn load(db: &Connection, tenant: &str) -> Result<Quota> {
    let started_at = db.query_row(
        "SELECT started_at FROM traffic_quota_state WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let limit = db.query_row("SELECT q.monthly_limit_bytes FROM tenants t LEFT JOIN traffic_quota_limits q ON q.tenant_id=t.id WHERE t.id=?1", [tenant], |r| r.get(0))?;
    let months = db
        .prepare("SELECT month,used_bytes FROM traffic_quota_months WHERE tenant_id=?1")?
        .query_map([tenant], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
    let mut state = QuotaState {
        limit,
        started_at,
        months,
        month: period(unix_now()).0,
        cancel: CancellationToken::new(),
    };
    state.refresh(unix_now());
    Ok(Quota(Mutex::new(state)))
}

pub(super) fn flush(db: &Connection, batch: &[(String, i64, u64)], now: i64) -> Result<()> {
    for (tenant, month, used) in batch {
        // 绝对累计值可重复提交；删除空间后迟到的快照不会复活记录。
        db.execute("INSERT INTO traffic_quota_months SELECT id,?2,?3 FROM tenants WHERE id=?1 ON CONFLICT(tenant_id,month) DO UPDATE SET used_bytes=excluded.used_bytes", params![tenant, month, used])?;
    }
    db.execute(
        "DELETE FROM traffic_quota_months WHERE month<?1",
        [period(now - 90 * 86400).0],
    )?;
    Ok(())
}

#[derive(Serialize)]
pub struct QuotaView {
    monthly_limit_bytes: Option<u64>,
    used_bytes: u64,
    remaining_bytes: Option<u64>,
    period_start: i64,
    period_end: i64,
    started_at: i64,
    exhausted: bool,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct QuotaFilter {
    user_id: Option<String>,
}

fn selected(
    state: &AppState,
    headers: &HeaderMap,
    filter: &QuotaFilter,
    admin: bool,
) -> Result<String, ApiError> {
    let selected = scope(
        state,
        headers,
        &Filter {
            user_id: filter.user_id.clone(),
            ..Default::default()
        },
        admin,
    )?;
    selected
        .tenant
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "请选择统计用户"))
}
pub async fn own_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<QuotaFilter>,
) -> Result<Json<QuotaView>, ApiError> {
    let tenant = selected(&state, &headers, &filter, false)?;
    Ok(Json(
        state
            .tunnel_runtime
            .quotas
            .get(&state, &tenant)
            .map_err(db_error)?
            .view(unix_now()),
    ))
}
pub async fn admin_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<QuotaFilter>,
) -> Result<Json<QuotaView>, ApiError> {
    let tenant = selected(&state, &headers, &filter, true)?;
    Ok(Json(
        state
            .tunnel_runtime
            .quotas
            .get(&state, &tenant)
            .map_err(db_error)?
            .view(unix_now()),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateQuota {
    // Value 使缺失字段与显式 null 分开校验，也统一拒绝小数和负数。
    monthly_limit_bytes: serde_json::Value,
}
pub async fn update_quota(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<QuotaFilter>,
    Json(input): Json<UpdateQuota>,
) -> Result<Json<QuotaView>, ApiError> {
    let actor = accounts::require_admin(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    let tenant = selected(&state, &headers, &filter, true)?;
    let limit = if input.monthly_limit_bytes.is_null() {
        None
    } else {
        Some(
            input
                .monthly_limit_bytes
                .as_u64()
                .filter(|value| *value > 0 && *value <= MAX_BYTES)
                .ok_or_else(|| {
                    ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "月额度必须为正整数字节数，且不超过安全整数上限",
                    )
                })?,
        )
    };
    let quota = state
        .tunnel_runtime
        .quotas
        .get(&state, &tenant)
        .map_err(db_error)?;
    {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let tx = db.unchecked_transaction().map_err(db_error)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1 AND tenant_id=?2)",
                params![filter.user_id, tenant],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if !exists {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "用户不存在"));
        }
        tx.execute("INSERT INTO traffic_quota_limits VALUES (?1,?2) ON CONFLICT(tenant_id) DO UPDATE SET monthly_limit_bytes=excluded.monthly_limit_bytes", params![tenant, limit]).map_err(db_error)?;
        accounts::audit(
            &tx,
            &actor,
            "traffic.quota_updated",
            "user",
            filter.user_id.as_deref().unwrap(),
        )?;
        tx.commit().map_err(db_error)?;
        let mut current = quota.0.lock().unwrap_or_else(|e| e.into_inner());
        current.limit = limit;
        current.refresh(unix_now());
    }
    Ok(Json(quota.view(unix_now())))
}

#[cfg(test)]
mod tests;
