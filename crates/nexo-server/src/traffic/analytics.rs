//! 首页天眼的只读投影。请求事实来自 Caddy，会话事实来自真实转发任务；
//! 观测数据与配额账本独立，重置用量不会删除天眼历史，也不能恢复额度。
use crate::*;
use nexo_core::telemetry::{self, Batch, Event};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn invalid(message: &str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, message)
}

pub fn migrate(db: &Connection) -> Result<()> {
    db.execute_batch(include_str!("analytics.sql"))?;
    Ok(())
}

/// 一批事件与小时聚合共用事务，普通主键负责断线重试去重。
/// 远端上报只能归属当前授权服务；未知、已删除和其他空间的服务不会生成记录。
pub fn ingest(state: &AppState, batch: &Batch, source: &str, device: Option<&str>) -> Result<()> {
    anyhow::ensure!(batch.events.len() <= telemetry::BATCH_SIZE, "统计批次过大");
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let tx = db.unchecked_transaction()?;
    let now = unix_now();
    for e in &batch.events {
        if !valid(e, now) {
            continue;
        }
        let tenant:Option<String>=tx.query_row(
            "SELECT t.tenant_id FROM tunnels t JOIN tenants w ON w.id=t.tenant_id WHERE t.id=?1 AND t.deleted_at IS NULL AND w.enabled=1 AND ((?2 IS NOT NULL AND t.device_id=?2 AND t.ipv6_direct_enabled=1) OR (?2 IS NULL AND EXISTS(SELECT 1 FROM authorized_service_nodes a WHERE a.service_id=t.id AND a.node_id=?3)))",
            params![e.service,device,source],|r|r.get(0)).optional()?;
        let Some(tenant) = tenant else {
            continue;
        };
        let mut e = e.clone();
        e.path = telemetry::clean_path(&e.path);
        // 不允许远端通过白名单字段偷偷传入完整地址或查询串。
        e.source = telemetry::normalize_source(&e.source);
        if !e.visitor.bytes().all(|b| b.is_ascii_hexdigit()) {
            e.visitor.clear();
        }
        let node = if let Some(device) = device {
            format!("direct:{device}")
        } else {
            source.to_owned()
        };
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO analytics_events VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                e.id,
                tenant,
                e.service,
                node,
                e.at,
                e.kind,
                serde_json::to_string(&e)?
            ],
        )?;
        if inserted == 0 {
            continue;
        }
        let http = e.kind == "request";
        let session = e.kind == "session";
        let measured = http || e.kind == "flow";
        let hour = e.at / 3600 * 3600;
        let status_class = if http { e.status / 100 } else { 0 };
        tx.execute("INSERT INTO analytics_hours(tenant_id,service_id,node_id,hour,protocol,status_class,requests,errors,sessions,duration_ms,session_ms,to_origin,to_public,peak) VALUES(?1,?2,?3,?4,?5,?14,?6,?7,?8,?9,?10,?11,?12,?13) ON CONFLICT(tenant_id,service_id,node_id,hour,protocol,status_class) DO UPDATE SET requests=requests+excluded.requests,errors=errors+excluded.errors,sessions=sessions+excluded.sessions,duration_ms=duration_ms+excluded.duration_ms,session_ms=session_ms+excluded.session_ms,to_origin=to_origin+excluded.to_origin,to_public=to_public+excluded.to_public,peak=MAX(peak,excluded.peak)",
            params![tenant,e.service,node,hour,e.protocol,http as i64,(http&&e.status>=400) as i64,session as i64,if http {e.duration_ms}else{0},if session{e.duration_ms}else{0},if measured{e.to_origin}else{0},if measured{e.to_public}else{0},e.peak,status_class])?;
        if e.kind == "flow" {
            tx.execute("INSERT INTO analytics_sources VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(tenant_id,service_id,node_id,protocol) DO UPDATE SET at=MAX(at,excluded.at),active=CASE WHEN excluded.at>=at THEN excluded.active ELSE active END",params![tenant,e.service,node,e.protocol,e.at,e.active])?;
        }
        if http {
            for (dimension, value) in event_dimensions(&e) {
                // 防止攻击者用随机路径/IP 令聚合无限膨胀；同小时超额值归入其他。
                let key = if matches!(dimension, "path" | "source") {
                    let count:i64=tx.query_row("SELECT COUNT(*) FROM analytics_dimensions WHERE tenant_id=?1 AND service_id=?2 AND hour=?3 AND dimension=?4 AND protocol=?6 AND status_class=?7 AND ?5=''",params![tenant,e.service,hour,dimension,"",e.protocol,status_class],|r|r.get(0))?;
                    let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM analytics_dimensions WHERE tenant_id=?1 AND service_id=?2 AND hour=?3 AND dimension=?4 AND protocol=?6 AND status_class=?7 AND value=?5)",params![tenant,e.service,hour,dimension,value,e.protocol,status_class],|r|r.get(0))?;
                    if count >= 256 && !exists {
                        "其他".into()
                    } else {
                        value
                    }
                } else {
                    value
                };
                tx.execute("INSERT INTO analytics_dimensions VALUES(?1,?2,?3,?6,?7,?4,?5,1) ON CONFLICT(tenant_id,service_id,hour,protocol,status_class,dimension,value) DO UPDATE SET count=count+1",params![tenant,e.service,hour,dimension,key,e.protocol,status_class])?;
            }
            if !e.visitor.is_empty() {
                tx.execute(
                    "INSERT OR IGNORE INTO analytics_visitors VALUES(?1,?2,?3,?4,?5,?7,?6)",
                    params![
                        tenant,
                        e.service,
                        telemetry::day(e.at),
                        hour,
                        e.protocol,
                        e.visitor,
                        status_class
                    ],
                )?;
            }
        } else if session {
            tx.execute("INSERT INTO analytics_dimensions VALUES(?1,?2,?3,?5,0,'reason',?4,1) ON CONFLICT(tenant_id,service_id,hour,protocol,status_class,dimension,value) DO UPDATE SET count=count+1",params![tenant,e.service,hour,e.reason,e.protocol])?;
        }
    }
    let source = if let Some(device) = device {
        format!("direct:{device}")
    } else {
        source.to_owned()
    };
    let previous: Option<(i64, u64)> = tx
        .query_row(
            "SELECT at,dropped FROM analytics_gaps WHERE source=?1",
            [&source],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let tick_start = previous
        .map(|v| v.0)
        .filter(|at| now - *at <= 15)
        .unwrap_or(now)
        / 5
        * 5;
    for at in (tick_start..=now / 5 * 5).step_by(5) {
        tx.execute(
            "INSERT OR IGNORE INTO analytics_ticks VALUES(?1,?2)",
            params![source, at],
        )?;
    }
    tx.execute(
        "INSERT OR IGNORE INTO analytics_coverage VALUES(?1,?2)",
        params![source, now / 60 * 60],
    )?;
    let old_dropped = previous.map(|v| v.1).unwrap_or(0);
    let newly_dropped = if batch.dropped >= old_dropped {
        batch.dropped - old_dropped
    } else {
        batch.dropped
    };
    if newly_dropped > 0 {
        tx.execute("INSERT INTO analytics_losses VALUES(?1,?2,?3) ON CONFLICT(source,minute) DO UPDATE SET count=count+excluded.count",params![source,now/60*60,newly_dropped.min(i64::MAX as u64)])?;
    }
    let lag = batch
        .events
        .iter()
        .map(|e| (now - e.at).max(0))
        .max()
        .unwrap_or(0);
    tx.execute("INSERT INTO analytics_gaps VALUES(?1,?2,?3,?4) ON CONFLICT(source) DO UPDATE SET at=excluded.at,dropped=excluded.dropped,lag_seconds=excluded.lag_seconds",params![source,now,batch.dropped.min(i64::MAX as u64),lag])?;
    tx.commit()?;
    Ok(())
}
fn valid(e: &Event, now: i64) -> bool {
    e.id.len() == 32
        && e.id.bytes().all(|b| b.is_ascii_hexdigit())
        && e.service.len() <= 64
        && e.at <= now + 60
        && e.at >= now - 7 * 86400
        && matches!(e.kind.as_str(), "request" | "flow" | "session")
        && matches!(
            e.protocol.as_str(),
            "tcp" | "udp" | "http" | "https" | "websocket"
        )
        && e.path.chars().count() <= 256
        && e.host.len() <= 253
        && e.method.len() <= 16
        && e.visitor.len() <= 64
        && [
            &e.source,
            &e.country,
            &e.operator,
            &e.browser,
            &e.os,
            &e.device,
            &e.reason,
        ]
        .iter()
        .all(|s| s.len() <= 128)
        && e.duration_ms <= 90 * 86400000
        && e.to_origin <= 1_000_000_000_000
        && e.to_public <= 1_000_000_000_000
        && e.active <= 1_000_000
        && e.peak <= 1_000_000
}
const LATENCY: &[u64] = &[
    1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000, 300000, 3600000,
    86400000,
];
fn latency_bucket(ms: u64) -> u64 {
    *LATENCY.iter().find(|&&v| v >= ms).unwrap_or(&86400000)
}

pub async fn collect(state: &AppState) -> Result<()> {
    for _ in 0..16 {
        let batch = state.tunnel_runtime.analytics.batch();
        if batch.events.is_empty() {
            ingest(state, &batch, "local", None)?;
            break;
        }
        ingest(state, &batch, "local", None)?;
        state.tunnel_runtime.analytics.ack(&batch);
        if batch.events.len() < telemetry::BATCH_SIZE {
            break;
        }
    }
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let now = unix_now();
    // 删除任务与查询不持有采集器锁；保留期不依赖管理员访问页面。
    db.execute(
        "DELETE FROM analytics_events WHERE at<?1",
        [now - 7 * 86400],
    )?;
    db.execute(
        "DELETE FROM analytics_hours WHERE hour<?1",
        [now - 90 * 86400],
    )?;
    db.execute(
        "DELETE FROM analytics_dimensions WHERE hour<?1",
        [now - 90 * 86400],
    )?;
    db.execute(
        "DELETE FROM analytics_losses WHERE minute<?1",
        [now - 90 * 86400],
    )?;
    db.execute("DELETE FROM analytics_ticks WHERE at<?1", [now - 3660])?;
    db.execute(
        "DELETE FROM analytics_coverage WHERE minute<?1",
        [now - 90 * 86400],
    )?;
    db.execute(
        "DELETE FROM analytics_visitors WHERE day<?1",
        [telemetry::day(now - 90 * 86400)],
    )?;
    Ok(())
}

#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    pub user_id: Option<String>,
    pub tunnel_id: Option<String>,
    pub range: Option<String>,
    pub status_class: Option<u16>,
    pub protocol: Option<String>,
    pub mode: Option<String>,
    pub cursor: Option<String>,
}
struct Scope {
    tenant: Option<String>,
    service: Option<String>,
    start: i64,
    end: i64,
    step: i64,
    status_class: Option<u16>,
    protocol: Option<String>,
    mode: Option<String>,
}
fn scope(
    state: &AppState,
    headers: &HeaderMap,
    f: &Filter,
    admin: bool,
) -> Result<Scope, ApiError> {
    let session = if admin {
        accounts::require_admin(state, headers)?
    } else {
        auth::require_session(state, headers)?
    };
    if !admin && f.user_id.is_some() {
        return Err(invalid("个人统计不接受用户筛选"));
    }
    let (duration, step) = match f.range.as_deref().unwrap_or("24h") {
        "live" => (60, 5),
        "1h" => (3600, 60),
        "24h" => (86400, 3600),
        "7d" => (7 * 86400, 6 * 3600),
        "30d" => (30 * 86400, 86400),
        "90d" => (90 * 86400, 86400),
        _ => return Err(invalid("统计时间范围无效")),
    };
    if f.protocol
        .as_ref()
        .is_some_and(|p| !matches!(p.as_str(), "tcp" | "udp" | "http" | "https" | "websocket"))
    {
        return Err(invalid("统计协议无效"));
    }
    if f.mode
        .as_ref()
        .is_some_and(|p| !matches!(p.as_str(), "tunnel" | "reverse_proxy"))
    {
        return Err(invalid("服务类型无效"));
    }
    if f.status_class.is_some_and(|v| !(1..=5).contains(&v)) {
        return Err(invalid("状态码分组无效"));
    }
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let tenant = if admin {
        f.user_id
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
    if let Some(id) = &f.tunnel_id {
        let allowed:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels WHERE id=?1 AND (?2 IS NULL OR tenant_id=?2) AND deleted_at IS NULL)",params![id,tenant],|r|r.get(0)).map_err(db_error)?;
        if !allowed {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "服务不存在"));
        }
    }
    let end = unix_now() + 1;
    Ok(Scope {
        tenant,
        service: f.tunnel_id.clone(),
        start: if step >= 3600 {
            (end - duration) / 3600 * 3600
        } else {
            end - duration
        },
        end,
        step,
        status_class: f.status_class,
        protocol: f.protocol.clone(),
        mode: f.mode.clone(),
    })
}
const WHERE:&str=" a.tenant_id IN (SELECT tenant_id FROM users) AND (?1 IS NULL OR a.tenant_id=?1) AND (?2 IS NULL OR a.service_id=?2) AND (?3 IS NULL OR a.protocol=?3) AND (?4 IS NULL OR t.service_mode=?4)";
fn condition(s: &Scope, events: bool) -> String {
    let mut condition = if events {
        WHERE.replace("a.protocol", "json_extract(a.payload,'$.protocol')")
    } else {
        WHERE.to_owned()
    };
    if let Some(class) = s.status_class {
        if events {
            condition.push_str(&format!(
                " AND CAST(json_extract(a.payload,'$.status') AS INTEGER)/100={class}"
            ));
        } else {
            condition.push_str(&format!(" AND a.status_class={class}"));
        }
    }
    condition
}
fn summary(state: &AppState, s: &Scope) -> Result<Value, ApiError> {
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let aggregates = condition(s, false);
    let mut total = Totals::default();
    let mut services = BTreeMap::<String, Value>::new();
    let mut protocols = BTreeMap::<String, u64>::new();
    let mut series = BTreeMap::<i64, Totals>::new();
    let mut dims = BTreeMap::<String, BTreeMap<String, u64>>::new();
    let mut latency_series = BTreeMap::<i64, BTreeMap<u64, u64>>::new();
    for at in (s.start..s.end).step_by(s.step as usize) {
        series.insert(at, Totals::default());
    }
    let mut add = |id: String, name: String, mode: String, protocol: String, at: i64, v: Totals| {
        total.add(&v);
        let bucket = s.start + (at - s.start).max(0) / s.step * s.step;
        series.entry(bucket).or_default().add(&v);
        *protocols.entry(protocol).or_default() += v.requests + v.sessions;
        let entry = services.entry(id.clone()).or_insert_with(
            || json!({"id":id,"name":name,"mode":mode,"requests":0,"bytes":0,"errors":0}),
        );
        entry["requests"] = json!(entry["requests"].as_u64().unwrap() + v.requests);
        entry["bytes"] = json!(entry["bytes"].as_u64().unwrap() + v.to_origin + v.to_public);
        entry["errors"] = json!(entry["errors"].as_u64().unwrap() + v.errors);
    };
    if s.step < 3600 {
        // 实时/一小时窗口按事实的真实时间筛选，不能混入同一小时中较早的事件。
        let sql=format!("SELECT a.payload,COALESCE(t.name,'已删除服务'),COALESCE(t.service_mode,'tunnel') FROM analytics_events a LEFT JOIN tunnels t ON t.id=a.service_id WHERE {} AND a.at>=?5 AND a.at<?6 ORDER BY a.at",condition(s,true));
        for row in db
            .prepare(&sql)
            .map_err(db_error)?
            .query_map(
                params![s.tenant, s.service, s.protocol, s.mode, s.start, s.end],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(db_error)?
        {
            let (payload, name, mode) = row.map_err(db_error)?;
            let e: Event = serde_json::from_str(&payload).map_err(db_error)?;
            let mut v = Totals::default();
            v.event(&e);
            if e.kind == "request" {
                let at = s.start + (e.at - s.start) / s.step * s.step;
                *latency_series
                    .entry(at)
                    .or_default()
                    .entry(latency_bucket(e.duration_ms))
                    .or_default() += 1;
            }
            add(e.service.clone(), name, mode, e.protocol.clone(), e.at, v);
            for (dimension, value) in event_dimensions(&e) {
                *dims
                    .entry(dimension.into())
                    .or_default()
                    .entry(value)
                    .or_default() += 1;
            }
        }
    } else {
        let sql=format!("SELECT a.service_id,COALESCE(t.name,'已删除服务'),COALESCE(t.service_mode,'tunnel'),a.protocol,a.hour,a.requests,a.errors,a.sessions,a.duration_ms,a.to_origin,a.to_public,a.peak,a.session_ms FROM analytics_hours a LEFT JOIN tunnels t ON t.id=a.service_id WHERE {aggregates} AND a.hour>=?5 AND a.hour<?6 ORDER BY a.hour");
        for row in db
            .prepare(&sql)
            .map_err(db_error)?
            .query_map(
                params![s.tenant, s.service, s.protocol, s.mode, s.start, s.end],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, i64>(4)?,
                        Totals {
                            requests: r.get(5)?,
                            errors: r.get(6)?,
                            sessions: r.get(7)?,
                            duration_ms: r.get(8)?,
                            to_origin: r.get(9)?,
                            to_public: r.get(10)?,
                            peak: r.get(11)?,
                            session_ms: r.get(12)?,
                        },
                    ))
                },
            )
            .map_err(db_error)?
        {
            let (id, name, mode, protocol, at, v) = row.map_err(db_error)?;
            add(id, name, mode, protocol, at, v);
        }
        let sql=format!("SELECT a.dimension,a.value,SUM(a.count) FROM analytics_dimensions a LEFT JOIN tunnels t ON t.id=a.service_id WHERE {aggregates} AND a.hour>=?5 AND a.hour<?6 GROUP BY a.dimension,a.value");
        for row in db
            .prepare(&sql)
            .map_err(db_error)?
            .query_map(
                params![s.tenant, s.service, s.protocol, s.mode, s.start, s.end],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, u64>(2)?,
                    ))
                },
            )
            .map_err(db_error)?
        {
            let (dimension, value, n) = row.map_err(db_error)?;
            dims.entry(dimension).or_default().insert(value, n);
        }
    }
    if s.step >= 3600 {
        let sql=format!("SELECT a.hour,a.value,SUM(a.count) FROM analytics_dimensions a LEFT JOIN tunnels t ON t.id=a.service_id WHERE {aggregates} AND a.dimension='latency' AND a.hour>=?5 AND a.hour<?6 GROUP BY a.hour,a.value");
        for row in db
            .prepare(&sql)
            .map_err(db_error)?
            .query_map(
                params![s.tenant, s.service, s.protocol, s.mode, s.start, s.end],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, u64>(2)?,
                    ))
                },
            )
            .map_err(db_error)?
        {
            let (hour, value, n) = row.map_err(db_error)?;
            if let Ok(bound) = value.parse::<u64>() {
                let at = s.start + (hour - s.start) / s.step * s.step;
                *latency_series
                    .entry(at)
                    .or_default()
                    .entry(bound)
                    .or_default() += n;
            }
        }
    }
    let mut breakdown = BTreeMap::<String, Vec<Value>>::new();
    for (dimension, entries) in dims {
        let mut entries: Vec<_> = entries.into_iter().collect();
        entries.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        // 状态码和延迟分位必须使用完整分布；只裁剪展示型排行。
        if !matches!(dimension.as_str(), "status" | "latency") {
            entries.truncate(10);
        }
        breakdown.insert(
            dimension,
            entries
                .into_iter()
                .map(|(label, count)| json!({"label":label,"count":count}))
                .collect(),
        );
    }
    let breakdown = json!(breakdown);
    let p95 = percentile(&breakdown, 0.95);
    let p50 = percentile(&breakdown, 0.5);
    let uv: u64 = if s.step < 3600 {
        db.query_row(&format!("SELECT COUNT(DISTINCT json_extract(a.payload,'$.visitor')) FROM analytics_events a LEFT JOIN tunnels t ON t.id=a.service_id WHERE {} AND a.kind='request' AND a.at>=?5 AND a.at<?6 AND json_extract(a.payload,'$.visitor')!=''",condition(s,true)),params![s.tenant,s.service,s.protocol,s.mode,s.start,s.end],|r|r.get(0)).map_err(db_error)?
    } else {
        db.query_row(&format!("SELECT COUNT(*) FROM (SELECT DISTINCT a.day,a.visitor FROM analytics_visitors a LEFT JOIN tunnels t ON t.id=a.service_id WHERE {aggregates} AND a.hour>=?5 AND a.hour<?6)"),params![s.tenant,s.service,s.protocol,s.mode,s.start,s.end],|r|r.get(0)).map_err(db_error)?
    };
    let active:u64=db.query_row(&format!("SELECT COALESCE(SUM(a.active),0) FROM analytics_sources a LEFT JOIN tunnels t ON t.id=a.service_id WHERE {WHERE} AND a.at>?5"),params![s.tenant,s.service,s.protocol,s.mode,unix_now()-30],|r|r.get(0)).map_err(db_error)?;
    let started: i64 = db
        .query_row(
            "SELECT started_at FROM analytics_state WHERE id=1",
            [],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    let mut services: Vec<_> = services.into_values().collect();
    services.sort_by_key(|v| std::cmp::Reverse(v["bytes"].as_u64().unwrap_or(0)));
    services.truncate(10);
    let source_sql="SELECT DISTINCT a.node_id FROM authorized_service_nodes a JOIN tunnels t ON t.id=a.service_id WHERE (?1 IS NULL OR t.tenant_id=?1) AND (?2 IS NULL OR t.id=?2) AND (?3 IS NULL OR t.protocol=?3 OR (t.protocol IN ('http','https') AND ?3='websocket')) AND (?4 IS NULL OR t.service_mode=?4) AND t.deleted_at IS NULL UNION SELECT DISTINCT 'direct:'||t.device_id FROM tunnels t WHERE t.ipv6_direct_enabled=1 AND (?1 IS NULL OR t.tenant_id=?1) AND (?2 IS NULL OR t.id=?2) AND (?3 IS NULL OR ?3 IN ('http','https','websocket')) AND (?4 IS NULL OR t.service_mode=?4) AND t.deleted_at IS NULL";
    let mut expected = db
        .prepare(source_sql)
        .map_err(db_error)?
        .query_map(params![s.tenant, s.service, s.protocol, s.mode], |r| {
            r.get::<_, String>(0)
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_error)?;
    if expected.is_empty() {
        expected.push("local".into());
    }
    let mut sources = Vec::new();
    let mut coverage = BTreeMap::<i64, u64>::new();
    let mut dropped = 0u64;
    let mut sampled = None;
    let mut lag_seconds = 0i64;
    for source in &expected {
        let last: Option<(i64, u64, i64)> = db
            .query_row(
                "SELECT at,dropped,lag_seconds FROM analytics_gaps WHERE source=?1",
                [source],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(db_error)?;
        if let Some((at, n, lag)) = last {
            lag_seconds = lag_seconds.max(lag);
            let _ = n;
            sampled = Some(sampled.map_or(at, |old: i64| old.min(at)));
        }
        sources.push(json!({"source":source,"sampled_at":last.map(|v|v.0),"status":if last.is_some_and(|v|unix_now()-v.0<=30){"ready"}else{"unavailable"}}));
        dropped+=db.query_row("SELECT COALESCE(SUM(count),0) FROM analytics_losses WHERE source=?1 AND minute>=?2 AND minute<?3",params![source,s.start/60*60,s.end],|r|r.get::<_,u64>(0)).map_err(db_error)?;
        if s.step < 60 {
            let ticks = db
                .prepare("SELECT at FROM analytics_ticks WHERE source=?1 AND at>=?2-5 AND at<?3")
                .map_err(db_error)?
                .query_map(params![source, s.start, s.end], |r| r.get::<_, i64>(0))
                .map_err(db_error)?
                .collect::<rusqlite::Result<std::collections::HashSet<_>>>()
                .map_err(db_error)?;
            for at in series.keys() {
                if ticks.contains(&(at / 5 * 5)) {
                    *coverage.entry(*at).or_default() += 1;
                }
            }
        } else {
            let mut query=db.prepare("SELECT ((MAX(minute,?2)-?2)/?4)*?4+?2,COUNT(*) FROM analytics_coverage WHERE source=?1 AND minute>=?2-60 AND minute<?3 GROUP BY 1").map_err(db_error)?;
            for row in query
                .query_map(params![source, s.start, s.end, s.step], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, u64>(1)?))
                })
                .map_err(db_error)?
            {
                let (at, count) = row.map_err(db_error)?;
                *coverage.entry(at).or_default() += count;
            }
        }
    }
    let slots = if s.step < 60 {
        series.len() as u64
    } else {
        ((s.end - s.start) as u64).div_ceil(60)
    } * expected.len() as u64;
    let coverage_percent = if slots > 0 {
        (coverage.values().sum::<u64>() as f64 / slots as f64 * 100.).min(100.)
    } else {
        0.
    };
    let missing = sources.iter().any(|v| v["status"] != "ready");
    let qps:u64=db.query_row(&format!("SELECT COUNT(*) FROM analytics_events a LEFT JOIN tunnels t ON t.id=a.service_id WHERE {} AND a.kind='request' AND a.at>=?5 AND a.at<?6",condition(s,true)),params![s.tenant,s.service,s.protocol,s.mode,unix_now()-60,unix_now()+1],|r|r.get(0)).map_err(db_error)?;
    Ok(
        json!({"sampled_at":sampled,"started_at":started,"uptime":state.tunnel_runtime.analytics.uptime(),"geo_available":state.tunnel_runtime.analytics.geo_available(),
        "status":if sampled.is_none(){"collecting"}else if missing{"stale"}else{"ready"},"sources":sources,"dropped":dropped,"lag_seconds":lag_seconds,"coverage_percent":coverage_percent,
        "start":s.start,"end":s.end,"step":s.step,"partial":started>s.start||dropped>0||missing||lag_seconds>15||coverage_percent<99.9,
        "totals":total,"qps":qps as f64/60.,"active":active,"uv_daily_sum":uv,"p50_ms":p50,"p95_ms":p95,
        "series":series.into_iter().map(|(at,v)|{let count=coverage.get(&at).copied().unwrap_or(0);let expected=expected.len() as u64*if s.step<60{1}else{(s.step as u64).div_ceil(60)};{
            let histogram=json!({"latency":latency_series.get(&at).map(|m|m.iter().map(|(label,count)|json!({"label":label.to_string(),"count":count})).collect::<Vec<_>>()).unwrap_or_default()});
            json!({"at":at,"covered":count>0,"partial":count<expected,"totals":v,"p50_ms":percentile(&histogram,0.5),"p95_ms":percentile(&histogram,0.95)})
        }}).collect::<Vec<_>>(),"services":services,"protocols":protocols,"breakdowns":breakdown}),
    )
}
fn event_dimensions(e: &Event) -> Vec<(&'static str, String)> {
    if e.kind == "request" {
        vec![
            ("status", e.status.to_string()),
            ("latency", latency_bucket(e.duration_ms).to_string()),
            ("path", e.path.clone()),
            ("source", e.source.clone()),
            ("country", e.country.clone()),
            ("operator", e.operator.clone()),
            ("browser", e.browser.clone()),
            ("os", e.os.clone()),
            ("device", e.device.clone()),
            ("domain", e.host.clone()),
        ]
    } else if e.kind == "session" {
        vec![("reason", e.reason.clone())]
    } else {
        vec![]
    }
}
fn percentile(b: &Value, p: f64) -> Option<u64> {
    let mut buckets: Vec<_> = b["latency"]
        .as_array()?
        .iter()
        .filter_map(|v| {
            Some((
                v["label"].as_str()?.parse::<u64>().ok()?,
                v["count"].as_u64()?,
            ))
        })
        .collect();
    buckets.sort_by_key(|v| v.0);
    let n: u64 = buckets.iter().map(|v| v.1).sum();
    if n == 0 {
        return None;
    }
    let rank = (n as f64 * p).ceil() as u64;
    let mut count = 0;
    for (bound, n) in buckets {
        count += n;
        if count >= rank {
            return Some(bound);
        }
    }
    None
}
#[derive(Default, Serialize)]
struct Totals {
    requests: u64,
    errors: u64,
    sessions: u64,
    duration_ms: u64,
    session_ms: u64,
    to_origin: u64,
    to_public: u64,
    peak: u64,
}
impl Totals {
    fn add(&mut self, v: &Self) {
        self.requests += v.requests;
        self.errors += v.errors;
        self.sessions += v.sessions;
        self.duration_ms += v.duration_ms;
        self.session_ms += v.session_ms;
        self.to_origin += v.to_origin;
        self.to_public += v.to_public;
        self.peak = self.peak.max(v.peak);
    }
    fn event(&mut self, e: &Event) {
        match e.kind.as_str() {
            "request" => {
                self.requests += 1;
                self.errors += (e.status >= 400) as u64;
                self.duration_ms += e.duration_ms;
                self.to_origin += e.to_origin;
                self.to_public += e.to_public;
            }
            "flow" => {
                self.to_origin += e.to_origin;
                self.to_public += e.to_public;
                self.peak = self.peak.max(e.peak);
            }
            "session" => {
                self.sessions += 1;
                self.session_ms += e.duration_ms;
            }
            _ => {}
        }
    }
}
fn details(state: &AppState, s: &Scope, f: &Filter, kind: &str) -> Result<Value, ApiError> {
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let cursor = if let Some(c) = &f.cursor {
        let Some((at, id)) = c.split_once(':') else {
            return Err(invalid("分页游标无效"));
        };
        (
            at.parse::<i64>().map_err(|_| invalid("分页游标无效"))?,
            id.to_owned(),
        )
    } else {
        (s.end, String::from("~"))
    };
    let sql=format!("SELECT a.payload,a.at,a.id,COALESCE(t.name,'已删除服务'),a.node_id FROM analytics_events a LEFT JOIN tunnels t ON t.id=a.service_id WHERE {} AND a.kind=?7 AND a.at>=?5 AND a.at<?9 AND (a.at<?6 OR (a.at=?6 AND a.id<?8)) ORDER BY a.at DESC,a.id DESC LIMIT 51",condition(s,true));
    let mut items: Vec<Value> = db
        .prepare(&sql)
        .map_err(db_error)?
        .query_map(
            params![
                s.tenant,
                s.service,
                s.protocol,
                s.mode,
                s.start.max(unix_now() - 7 * 86400),
                cursor.0,
                kind,
                cursor.1,
                s.end
            ],
            |r| {
                let payload: String = r.get(0)?;
                let mut v: Value = serde_json::from_str(&payload).unwrap_or(Value::Null);
                v["name"] = json!(r.get::<_, String>(3)?);
                v["node"] = json!(r.get::<_, String>(4)?);
                v.as_object_mut().map(|v| v.remove("visitor"));
                Ok(v)
            },
        )
        .map_err(db_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(db_error)?;
    let next = if items.len() > 50 {
        items.truncate(50);
        items
            .last()
            .map(|v| format!("{}:{}", v["at"], v["id"].as_str().unwrap_or("")))
    } else {
        None
    };
    Ok(json!({"items":items,"next_cursor":next,"retention_days":7}))
}
pub async fn own(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(f): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(summary(&state, &scope(&state, &headers, &f, false)?)?))
}
pub async fn admin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(f): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(summary(&state, &scope(&state, &headers, &f, true)?)?))
}
pub async fn own_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(f): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(details(
        &state,
        &scope(&state, &headers, &f, false)?,
        &f,
        "request",
    )?))
}
pub async fn admin_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(f): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(details(
        &state,
        &scope(&state, &headers, &f, true)?,
        &f,
        "request",
    )?))
}
pub async fn own_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(f): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(details(
        &state,
        &scope(&state, &headers, &f, false)?,
        &f,
        "session",
    )?))
}
pub async fn admin_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(f): Query<Filter>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(details(
        &state,
        &scope(&state, &headers, &f, true)?,
        &f,
        "session",
    )?))
}

#[cfg(test)]
mod tests;
