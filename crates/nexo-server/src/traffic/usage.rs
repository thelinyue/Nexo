//! 日用量按北京时间归档，与七天趋势独立保留；迁移和分钟落盘共用事务，避免重复累计。
use super::*;

const OFFSET: i64 = 8 * 3600;
const DAILY_RETENTION: i64 = 90 * 86400;

pub(super) fn day_start(at: i64) -> i64 {
    (at + OFFSET).div_euclid(86400) * 86400 - OFFSET
}

pub(super) fn initialize_schema(db: &Connection) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS traffic_daily (
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        day INTEGER NOT NULL, to_origin INTEGER NOT NULL, to_public INTEGER NOT NULL,
        PRIMARY KEY(tenant_id,day));
        CREATE TABLE IF NOT EXISTS traffic_daily_coverage (day INTEGER PRIMARY KEY, seconds REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS traffic_usage_state (id INTEGER PRIMARY KEY CHECK(id=1), started_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS traffic_usage_resets (
        tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE, reset_at INTEGER NOT NULL);")?;
    // 标记和回填同一事务提交。重启只建表，不会把重置前的分钟趋势再次计入用量。
    let initialized: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM traffic_usage_state)",
        [],
        |r| r.get(0),
    )?;
    if !initialized {
        tx.execute("INSERT INTO traffic_daily SELECT tenant_id,(minute+?1)/86400*86400-?1,SUM(to_origin),SUM(to_public) FROM traffic_minutes GROUP BY tenant_id,(minute+?1)/86400", [OFFSET])?;
        tx.execute("INSERT INTO traffic_daily_coverage SELECT (minute+?1)/86400*86400-?1,SUM(seconds) FROM traffic_coverage GROUP BY (minute+?1)/86400", [OFFSET])?;
        tx.execute("INSERT INTO traffic_usage_state SELECT 1,COALESCE(MIN(minute),?1) FROM traffic_coverage", [unix_now()])?;
    }
    tx.commit()?;
    Ok(())
}

pub(super) fn flush(db: &Connection, snapshot: &Snapshot, now: i64) -> Result<()> {
    for ((tenant, day), bytes) in &snapshot.usage_pending {
        db.execute("INSERT INTO traffic_daily VALUES (?1,?2,?3,?4) ON CONFLICT(tenant_id,day) DO UPDATE SET to_origin=to_origin+excluded.to_origin,to_public=to_public+excluded.to_public", params![tenant,day,bytes.to_origin,bytes.to_public])?;
    }
    for (minute, seconds) in &snapshot.coverage {
        db.execute("INSERT INTO traffic_daily_coverage VALUES (?1,?2) ON CONFLICT(day) DO UPDATE SET seconds=MIN(86400,seconds+excluded.seconds)", params![day_start(*minute),seconds.min(60.0)])?;
    }
    let cutoff = day_start(now - DAILY_RETENTION);
    db.execute("DELETE FROM traffic_daily WHERE day<?1", [cutoff])?;
    db.execute("DELETE FROM traffic_daily_coverage WHERE day<?1", [cutoff])?;
    Ok(())
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UsageFilter {
    user_id: Option<String>,
}

#[derive(Serialize)]
pub struct Period {
    start: i64,
    total: Bytes,
    partial: bool,
}

#[derive(Serialize)]
pub struct Usage {
    timezone: &'static str,
    sampled_at: Option<i64>,
    started_at: i64,
    reset_at: Option<i64>,
    reset_users: usize,
    today: Period,
    week: Period,
    month: Period,
}

fn starts(now: i64) -> [i64; 3] {
    let local = time::OffsetDateTime::from_unix_timestamp(now + OFFSET).expect("有效的系统时间");
    let today = day_start(now);
    [
        today,
        today - i64::from(local.weekday().number_days_from_monday()) * 86400,
        today - i64::from(local.day() - 1) * 86400,
    ]
}

/// 用量按真实登录身份选空间，永远不跟随单隧道和曲线时间范围。
fn usage(state: &AppState, scope: Scope, now: i64) -> Result<Json<Usage>, ApiError> {
    let snapshot = state
        .tunnel_runtime
        .traffic
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let started_at = db
        .query_row("SELECT started_at FROM traffic_usage_state", [], |r| {
            r.get(0)
        })
        .map_err(db_error)?;
    let tenants = db
        .prepare("SELECT DISTINCT tenant_id FROM users WHERE (?1 IS NULL OR tenant_id=?1)")
        .map_err(db_error)?
        .query_map([&scope.tenant], |r| r.get::<_, String>(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<HashSet<_>>>()
        .map_err(db_error)?;
    let boundaries = starts(now);
    let earliest = *boundaries.iter().min().unwrap();
    let mut daily: BTreeMap<i64, Bytes> = BTreeMap::new();
    let mut query = db.prepare("SELECT day,SUM(to_origin),SUM(to_public) FROM traffic_daily WHERE day>=?1 AND day<=?2 AND (?3 IS NULL OR tenant_id=?3) AND tenant_id IN (SELECT tenant_id FROM users) GROUP BY day").map_err(db_error)?;
    for row in query
        .query_map(params![earliest, boundaries[0], scope.tenant], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                Bytes {
                    to_origin: r.get(1)?,
                    to_public: r.get(2)?,
                },
            ))
        })
        .map_err(db_error)?
    {
        let (day, bytes) = row.map_err(db_error)?;
        daily.entry(day).or_default().add(bytes);
    }
    for ((tenant, day), bytes) in &snapshot.usage_pending {
        if tenants.contains(tenant) && *day >= earliest && *day <= boundaries[0] {
            daily.entry(*day).or_default().add(*bytes);
        }
    }
    let mut coverage: BTreeMap<i64, f64> = db
        .prepare("SELECT day,seconds FROM traffic_daily_coverage WHERE day>=?1 AND day<=?2")
        .map_err(db_error)?
        .query_map(params![earliest, boundaries[0]], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    for (minute, seconds) in &snapshot.coverage {
        *coverage.entry(day_start(*minute)).or_default() += seconds;
    }
    let resets: Vec<i64> = db.prepare("SELECT reset_at FROM traffic_usage_resets WHERE (?1 IS NULL OR tenant_id=?1) AND tenant_id IN (SELECT tenant_id FROM users)").map_err(db_error)?
        .query_map([&scope.tenant], |r| r.get(0)).map_err(db_error)?
        .collect::<rusqlite::Result<_>>().map_err(db_error)?;
    let period = |start| {
        let mut total = Bytes::default();
        for (_, bytes) in daily.range(start..) {
            total.add(*bytes);
        }
        let covered: f64 = coverage
            .range(start..=boundaries[0])
            .map(|(_, seconds)| seconds.min(86400.0))
            .sum();
        Period {
            start,
            total,
            partial: started_at > start || covered + 6.0 < (now - start) as f64,
        }
    };
    Ok(Json(Usage {
        timezone: "Asia/Shanghai",
        sampled_at: snapshot.sampled_at,
        started_at,
        reset_at: if scope.tenant.is_some() {
            resets.first().copied()
        } else {
            None
        },
        reset_users: resets.iter().filter(|at| **at >= earliest).count(),
        today: period(boundaries[0]),
        week: period(boundaries[1]),
        month: period(boundaries[2]),
    }))
}

pub async fn own_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<UsageFilter>,
) -> Result<Json<Usage>, ApiError> {
    let filter = Filter {
        user_id: filter.user_id,
        ..Default::default()
    };
    usage(&state, scope(&state, &headers, &filter, false)?, unix_now())
}
pub async fn admin_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<UsageFilter>,
) -> Result<Json<Usage>, ApiError> {
    let filter = Filter {
        user_id: filter.user_id,
        ..Default::default()
    };
    usage(&state, scope(&state, &headers, &filter, true)?, unix_now())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetRequest {
    user_id: String,
}

/// 重置只清用量，保留分钟趋势和实时速率。先冻结采样并记录计数边界，再提交数据库事务；
/// 写盘期间释放单隧道计数锁，转发仍能累计新数据。事务失败不改变任何内存用量。
pub async fn admin_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ResetRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = accounts::require_admin(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    let filter = Filter {
        user_id: Some(input.user_id.clone()),
        ..Default::default()
    };
    let scope = scope(&state, &headers, &filter, true)?;
    let tenant = scope.tenant.unwrap();
    let mut snapshot = state
        .tunnel_runtime
        .traffic
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut excluded = BTreeMap::new();
    let reset_at;
    {
        // 同时短暂持有目标空间所有计数锁，确保多条持续连接使用同一个重置边界。
        let guards: Vec<_> = snapshot
            .records
            .iter()
            .filter(|((id, _), _)| id == &tenant)
            .map(|(key, record)| {
                (
                    key,
                    record.meter.0.lock().unwrap_or_else(|e| e.into_inner()),
                )
            })
            .collect();
        reset_at = unix_now();
        for ((id, tunnel), buckets) in &guards {
            for (minute, bytes) in buckets.iter() {
                excluded.insert((id.clone(), tunnel.clone(), *minute), *bytes);
            }
        }
    }
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    // 取锁前用户可能已被删除；必须在写入事务内重新核对，避免迟到请求复活统计。
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1 AND tenant_id=?2)",
            params![input.user_id, tenant],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    if !exists {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "用户不存在"));
    }
    tx.execute("DELETE FROM traffic_daily WHERE tenant_id=?1", [&tenant])
        .map_err(db_error)?;
    tx.execute("INSERT INTO traffic_usage_resets VALUES (?1,?2) ON CONFLICT(tenant_id) DO UPDATE SET reset_at=excluded.reset_at", params![tenant,reset_at]).map_err(db_error)?;
    accounts::audit(&tx, &session, "traffic.usage_reset", "user", &input.user_id)?;
    tx.commit().map_err(db_error)?;
    snapshot.usage_pending.retain(|(id, _), _| id != &tenant);
    snapshot
        .usage_excluded
        .retain(|(id, _, _), _| id != &tenant);
    snapshot.usage_excluded.extend(excluded);
    Ok(Json(serde_json::json!({"reset_at":reset_at})))
}

#[cfg(test)]
mod tests;
