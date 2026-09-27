//! 隧道流量只在 Server 的成功写入处计数，不记录内容，也不包含控制帧与加密开销。
//! 转发只持有单隧道的短临界区；采样、事务落库与查询独立，统计故障不影响转发。
use crate::*;
use axum::extract::Query;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const RETENTION: i64 = 7 * 86400;
pub mod quota;
mod usage;
pub use usage::{admin_reset, admin_usage, own_usage};

pub fn initialize_schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS traffic_minutes (
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        tunnel_id TEXT NOT NULL, minute INTEGER NOT NULL,
        to_origin INTEGER NOT NULL, to_public INTEGER NOT NULL,
        PRIMARY KEY(tenant_id,tunnel_id,minute));
        CREATE INDEX IF NOT EXISTS traffic_minutes_time ON traffic_minutes(minute);
        CREATE TABLE IF NOT EXISTS traffic_coverage (minute INTEGER PRIMARY KEY, seconds REAL NOT NULL);")?;
    usage::initialize_schema(db)?;
    quota::initialize_schema(db)?;
    Ok(())
}

#[derive(Clone, Copy, Default, Serialize)]
pub struct Bytes {
    pub to_origin: u64,
    pub to_public: u64,
}
impl Bytes {
    fn add(&mut self, other: Self) {
        self.to_origin += other.to_origin;
        self.to_public += other.to_public;
    }
}

/// 写入成功即按 UTC 分钟归档，连接退出、取消和半关闭都不会丢掉已经转发的字节。
#[derive(Default)]
pub struct Meter(Mutex<BTreeMap<i64, Bytes>>);
impl Meter {
    fn record(&self, now: i64, origin: bool, count: usize) {
        let mut buckets = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let bytes = buckets.entry(now / 60 * 60).or_default();
        if origin {
            bytes.to_origin += count as u64;
        } else {
            bytes.to_public += count as u64;
        }
    }
}

/// 仅统计 AsyncWrite 实际接收的字节；必须在逻辑流头写完之后包装数据流。
pub struct Counted<T> {
    io: T,
    meter: Arc<Meter>,
    origin: bool,
    quota: Option<(Arc<quota::Quota>, tokio_util::sync::CancellationToken)>,
}
impl<T> Counted<T> {
    pub fn new(io: T, meter: Arc<Meter>, origin: bool) -> Self {
        Self {
            io,
            meter,
            origin,
            quota: None,
        }
    }
    pub fn with_quota(
        mut self,
        quota: Arc<quota::Quota>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Self {
        self.quota = Some((quota, cancel));
        self
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = if let Some((quota, cancel)) = self.quota.clone() {
            quota.write(&mut self.io, cx, buf, &cancel)
        } else {
            Pin::new(&mut self.io).poll_write(cx, buf)
        };
        if let Poll::Ready(Ok(count)) = result {
            self.meter.record(unix_now(), self.origin, count);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

struct Record {
    meter: Arc<Meter>,
    rate: Rates,
}
#[derive(Clone, Copy, Default, Serialize)]
pub struct Rates {
    to_origin: f64,
    to_public: f64,
}
struct Snapshot {
    records: HashMap<(String, String), Record>,
    pending: BTreeMap<(String, String, i64), Bytes>,
    // 日用量独立于趋势待写批次，重置用量时仍可保留原始趋势。
    usage_pending: BTreeMap<(String, i64), Bytes>,
    // 重置时已写入但尚未采样的字节：仅从下一次日用量中扣除，趋势和速率照常采样。
    usage_excluded: BTreeMap<(String, String, i64), Bytes>,
    coverage: BTreeMap<i64, f64>,
    sampled_at: Option<i64>,
    last_wall: f64,
    last_tick: Instant,
    last_flush: i64,
}

/// 采样快照与待写批次共用锁，查询不会重复合并正在提交的批次。
/// 数据库只在采样/查询时访问；转发路径不等待数据库或全局统计锁。
pub struct Collector(Mutex<Snapshot>);
impl Default for Collector {
    fn default() -> Self {
        Self(Mutex::new(Snapshot {
            records: HashMap::new(),
            pending: BTreeMap::new(),
            usage_pending: BTreeMap::new(),
            usage_excluded: BTreeMap::new(),
            coverage: BTreeMap::new(),
            sampled_at: None,
            last_wall: wall_seconds(),
            last_tick: Instant::now(),
            last_flush: unix_now(),
        }))
    }
}
fn wall_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
impl Collector {
    pub fn meter(&self, tenant: &str, tunnel: &str) -> Arc<Meter> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .records
            .entry((tenant.into(), tunnel.into()))
            .or_insert_with(|| Record {
                meter: Arc::new(Meter::default()),
                rate: Rates::default(),
            })
            .meter
            .clone()
    }
    pub fn sample(&self, state: &AppState, flush: bool) -> Result<()> {
        self.sample_at(state, wall_seconds(), Instant::now(), flush)
    }
    fn sample_at(&self, state: &AppState, wall: f64, tick: Instant, flush: bool) -> Result<()> {
        let mut snapshot = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let quota_batch = state.tunnel_runtime.quotas.snapshot();
        let elapsed = tick
            .duration_since(snapshot.last_tick)
            .as_secs_f64()
            .max(0.001);
        let mut batches = Vec::new();
        for ((tenant, tunnel), record) in &mut snapshot.records {
            let buckets =
                std::mem::take(&mut *record.meter.0.lock().unwrap_or_else(|e| e.into_inner()));
            let mut total = Bytes::default();
            for (minute, bytes) in buckets {
                total.add(bytes);
                batches.push(((tenant.clone(), tunnel.clone(), minute), bytes));
            }
            record.rate = Rates {
                to_origin: total.to_origin as f64 / elapsed,
                to_public: total.to_public as f64 / elapsed,
            };
        }
        for (key, bytes) in batches {
            let excluded = snapshot.usage_excluded.remove(&key).unwrap_or_default();
            snapshot
                .usage_pending
                .entry((key.0.clone(), usage::day_start(key.2)))
                .or_default()
                .add(Bytes {
                    to_origin: bytes.to_origin - excluded.to_origin,
                    to_public: bytes.to_public - excluded.to_public,
                });
            snapshot.pending.entry(key).or_default().add(bytes);
        }
        // 墙钟大幅跳变时不把未知时间填成零流量；速率始终使用单调时钟。
        let start = if ((wall - snapshot.last_wall) - elapsed).abs() > 2.0 {
            wall - elapsed
        } else {
            snapshot.last_wall
        };
        let mut cursor = start.max(wall - RETENTION as f64);
        while cursor < wall {
            let minute = (cursor as i64) / 60 * 60;
            let end = wall.min((minute + 60) as f64);
            *snapshot.coverage.entry(minute).or_default() += end - cursor;
            cursor = end;
        }
        snapshot.last_wall = wall;
        snapshot.last_tick = tick;
        snapshot.sampled_at = Some(wall as i64);
        let cutoff = wall as i64 - RETENTION;
        snapshot
            .pending
            .retain(|(_, _, minute), _| *minute >= cutoff / 60 * 60);
        snapshot
            .coverage
            .retain(|minute, _| *minute >= cutoff / 60 * 60);
        // 删除空间后丢弃迟到计数，不能让存活任务复活已删除数据。
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let tenants = db
            .prepare("SELECT id FROM tenants")?
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        snapshot.records.retain(|(tenant, _), record| {
            tenants.contains(tenant)
                && (Arc::strong_count(&record.meter) > 1
                    || record.rate.to_origin > 0.0
                    || record.rate.to_public > 0.0)
        });
        snapshot
            .pending
            .retain(|(tenant, _, _), _| tenants.contains(tenant));
        snapshot
            .usage_pending
            .retain(|(tenant, _), _| tenants.contains(tenant));
        snapshot
            .usage_excluded
            .retain(|(tenant, _, _), _| tenants.contains(tenant));
        if !flush && wall as i64 - snapshot.last_flush < 60 {
            return Ok(());
        }
        let tx = db.unchecked_transaction()?;
        for ((tenant, tunnel, minute), bytes) in &snapshot.pending {
            tx.execute("INSERT INTO traffic_minutes VALUES (?1,?2,?3,?4,?5) ON CONFLICT(tenant_id,tunnel_id,minute) DO UPDATE SET to_origin=to_origin+excluded.to_origin,to_public=to_public+excluded.to_public", params![tenant,tunnel,minute,bytes.to_origin,bytes.to_public])?;
        }
        for (minute, seconds) in &snapshot.coverage {
            tx.execute("INSERT INTO traffic_coverage VALUES (?1,?2) ON CONFLICT(minute) DO UPDATE SET seconds=MIN(60,seconds+excluded.seconds)", params![minute, seconds.min(60.0)])?;
        }
        usage::flush(&tx, &snapshot, wall as i64)?;
        quota::flush(&tx, &quota_batch, wall as i64)?;
        tx.execute(
            "DELETE FROM traffic_minutes WHERE minute<?1",
            [cutoff / 60 * 60],
        )?;
        tx.execute(
            "DELETE FROM traffic_coverage WHERE minute<?1",
            [cutoff / 60 * 60],
        )?;
        tx.commit()?;
        snapshot.pending.clear();
        snapshot.usage_pending.clear();
        snapshot.coverage.clear();
        snapshot.last_flush = wall as i64;
        Ok(())
    }
    pub async fn run(state: AppState) {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(error) = state.tunnel_runtime.traffic.sample(&state, false) {
                tracing::error!("流量统计保存失败，将自动重试：{error:#}");
            }
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    user_id: Option<String>,
    tunnel_id: Option<String>,
    range: Option<String>,
}
struct Scope {
    tenant: Option<String>,
    tunnel: Option<String>,
}
fn scope(
    state: &AppState,
    headers: &HeaderMap,
    filter: &Filter,
    admin: bool,
) -> Result<Scope, ApiError> {
    let session = if admin {
        accounts::require_admin(state, headers)?
    } else {
        auth::require_session(state, headers)?
    };
    if !admin && filter.user_id.is_some() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "个人流量不接受用户筛选",
        ));
    }
    if admin && filter.user_id.is_none() && filter.tunnel_id.is_some() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "请先选择用户再筛选隧道",
        ));
    }
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let tenant = if admin {
        filter
            .user_id
            .as_ref()
            .map(|id| {
                db.query_row("SELECT tenant_id FROM users WHERE id=?1", [id], |r| {
                    r.get::<_, String>(0)
                })
                .optional()
                .map_err(db_error)?
                .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "用户不存在"))
            })
            .transpose()?
    } else {
        Some(session.tenant_id)
    };
    if let Some(tunnel) = &filter.tunnel_id {
        let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels WHERE id=?1 AND tenant_id=?2 AND service_mode='tunnel' AND deleted_at IS NULL)", params![tunnel,tenant], |r| r.get(0)).map_err(db_error)?;
        if !exists {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "隧道不存在"));
        }
    }
    Ok(Scope {
        tenant,
        tunnel: filter.tunnel_id.clone(),
    })
}
impl Scope {
    fn includes(&self, tenant: &str, tunnel: &str) -> bool {
        self.tenant.as_ref().is_none_or(|id| id == tenant)
            && self.tunnel.as_ref().is_none_or(|id| id == tunnel)
    }
}

#[derive(Serialize)]
pub struct Realtime {
    sampled_at: Option<i64>,
    status: &'static str,
    rates: Rates,
}
fn realtime(state: &AppState, scope: Scope) -> Result<Json<Realtime>, ApiError> {
    let snapshot = state
        .tunnel_runtime
        .traffic
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let tenants = db
        .prepare("SELECT DISTINCT tenant_id FROM users WHERE enabled=1")
        .map_err(db_error)?
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<HashSet<_>>>()
        .map_err(db_error)?;
    let mut rates = Rates::default();
    for ((tenant, tunnel), record) in &snapshot.records {
        if tenants.contains(tenant) && scope.includes(tenant, tunnel) {
            rates.to_origin += record.rate.to_origin;
            rates.to_public += record.rate.to_public;
        }
    }
    let status = match snapshot.sampled_at {
        None => "collecting",
        Some(at) if unix_now() - at > 15 => "stale",
        _ => "ready",
    };
    Ok(Json(Realtime {
        sampled_at: snapshot.sampled_at,
        status,
        rates,
    }))
}

#[derive(Serialize)]
pub struct Point {
    at: i64,
    seconds: i64,
    covered_seconds: f64,
    bytes: Bytes,
    rates: Option<Rates>,
}
#[derive(Serialize)]
pub struct History {
    start: i64,
    end: i64,
    step: i64,
    sampled_at: Option<i64>,
    total: Bytes,
    points: Vec<Point>,
}
fn history(state: &AppState, scope: Scope, filter: &Filter) -> Result<Json<History>, ApiError> {
    let (duration, step) = match filter.range.as_deref().unwrap_or("24h") {
        "1h" => (3600, 60),
        "24h" => (86400, 300),
        "7d" => (RETENTION, 3600),
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "时间范围必须为 1h、24h 或 7d",
            ))
        }
    };
    let snapshot = state
        .tunnel_runtime
        .traffic
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // 查询边界按分钟对齐；末分钟包含本次已采集数据，避免未采集的当前秒被画成零。
    let end = snapshot.sampled_at.unwrap_or_else(unix_now) / 60 * 60 + 60;
    let start = end - duration;
    let mut points: Vec<Point> = (start..end)
        .step_by(step as usize)
        .map(|at| Point {
            at,
            seconds: step,
            covered_seconds: 0.0,
            bytes: Bytes::default(),
            rates: None,
        })
        .collect();
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let tenants = db
        .prepare("SELECT DISTINCT tenant_id FROM users")
        .map_err(db_error)?
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<HashSet<_>>>()
        .map_err(db_error)?;
    let mut query = db.prepare("SELECT minute,SUM(to_origin),SUM(to_public) FROM traffic_minutes WHERE minute>=?1 AND minute<?2 AND (?3 IS NULL OR tenant_id=?3) AND (?4 IS NULL OR tunnel_id=?4) AND tenant_id IN (SELECT tenant_id FROM users) GROUP BY minute").map_err(db_error)?;
    for row in query
        .query_map(params![start, end, scope.tenant, scope.tunnel], |r| {
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
        let (minute, bytes) = row.map_err(db_error)?;
        points[((minute - start) / step) as usize].bytes.add(bytes);
    }
    for ((tenant, tunnel, minute), bytes) in &snapshot.pending {
        if *minute >= start
            && *minute < end
            && tenants.contains(tenant)
            && scope.includes(tenant, tunnel)
        {
            points[((minute - start) / step) as usize].bytes.add(*bytes);
        }
    }
    let mut coverage: BTreeMap<i64, f64> = db
        .prepare("SELECT minute,seconds FROM traffic_coverage WHERE minute>=?1 AND minute<?2")
        .map_err(db_error)?
        .query_map(params![start, end], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    for (minute, seconds) in &snapshot.coverage {
        if *minute >= start && *minute < end {
            *coverage.entry(*minute).or_default() += seconds;
        }
    }
    for (minute, seconds) in coverage {
        points[((minute - start) / step) as usize].covered_seconds += seconds.min(60.0);
    }
    let mut total = Bytes::default();
    for point in &mut points {
        total.add(point.bytes);
        if point.covered_seconds > 0.0 {
            point.rates = Some(Rates {
                to_origin: point.bytes.to_origin as f64 / point.covered_seconds,
                to_public: point.bytes.to_public as f64 / point.covered_seconds,
            });
        }
    }
    Ok(Json(History {
        start,
        end,
        step,
        sampled_at: snapshot.sampled_at,
        total,
        points,
    }))
}

pub async fn own_realtime(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Result<Json<Realtime>, ApiError> {
    realtime(&state, scope(&state, &headers, &filter, false)?)
}
pub async fn admin_realtime(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Result<Json<Realtime>, ApiError> {
    realtime(&state, scope(&state, &headers, &filter, true)?)
}
pub async fn own_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Result<Json<History>, ApiError> {
    history(&state, scope(&state, &headers, &filter, false)?, &filter)
}
pub async fn admin_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<Filter>,
) -> Result<Json<History>, ApiError> {
    history(&state, scope(&state, &headers, &filter, true)?, &filter)
}

#[cfg(test)]
mod tests;
