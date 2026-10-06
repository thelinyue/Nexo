//! 公网节点控制平面：接入者只提交节点，管理员审批和分配才授予转发权限。
//! 身份、工作空间授权和维护状态分开保存，离线不等于撤销，删除则明确撤销身份。
use crate::*;
use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
pub mod certificates;
pub mod control;
pub mod dns;
pub mod groups;
pub mod health;
pub mod releases;
pub mod runtime;
pub mod selection;
pub mod services;
#[cfg(test)]
mod tests;
pub mod updates;

pub fn migrate(db: &Connection) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    let proxy_migration = !tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='relay_local_proxy_grants')",
        [],
        |r| r.get::<_, bool>(0),
    )?;
    tx.execute_batch(include_str!("schema.sql"))?;
    if proxy_migration {
        // 已有反代保持可用；只有首次迁移补授权，重启不能复活被撤销的权限。
        tx.execute("INSERT OR IGNORE INTO relay_local_proxy_grants SELECT DISTINCT t.tenant_id FROM tunnels t JOIN service_nodes s ON s.service_id=t.id WHERE t.service_mode='reverse_proxy' AND t.deleted_at IS NULL AND s.node_id='local'", [])?;
    }
    if !tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('devices') WHERE name='node_capable')",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        tx.execute(
            "ALTER TABLE devices ADD COLUMN node_capable INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if !tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tunnels') WHERE name='distribution_mode')",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        tx.execute(
            "ALTER TABLE tunnels ADD COLUMN distribution_mode TEXT NOT NULL DEFAULT 'single'",
            [],
        )?;
        tx.execute(
            "INSERT INTO service_nodes SELECT id,'local' FROM tunnels",
            [],
        )?;
    }
    if !tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tunnels') WHERE name='preferred_node_id')",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        tx.execute("ALTER TABLE tunnels ADD COLUMN preferred_node_id TEXT", [])?;
    }
    if !tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tunnels') WHERE name='node_group_id')",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        tx.execute(
            "ALTER TABLE tunnels ADD COLUMN node_group_id TEXT REFERENCES relay_node_groups(id)",
            [],
        )?;
    }
    // 端口占用改为在服务保存事务中按节点检查；UDP 仍只允许内置节点。
    tx.execute("DROP INDEX IF EXISTS idx_tunnels_tcp_port", [])?;
    for (table, column, definition) in [
        (
            "relay_nodes",
            "reverse_proxy_supported",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "node_update_jobs",
            "operation",
            "TEXT NOT NULL DEFAULT 'update'",
        ),
        ("node_update_items", "attempt", "INTEGER NOT NULL DEFAULT 0"),
        (
            "relay_service_health",
            "public_probe_supported",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "relay_public_health",
            "probe_kind",
            "TEXT NOT NULL DEFAULT 'tcp'",
        ),
        ("relay_public_health", "address", "TEXT NOT NULL DEFAULT ''"),
        ("relay_public_health", "error", "TEXT"),
        (
            "node_update_items",
            "ttl_seconds",
            "INTEGER NOT NULL DEFAULT 60",
        ),
    ] {
        if !tx.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name=?1)"),
            [column],
            |r| r.get::<_, bool>(0),
        )? {
            tx.execute(
                &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
    }
    // DNS、服务诊断和节点维护共用同一综合健康定义，避免只看在线或旧探测样本。
    tx.execute_batch("DROP VIEW IF EXISTS relay_healthy_service_nodes; DROP VIEW IF EXISTS relay_ready_service_nodes; CREATE VIEW relay_ready_service_nodes AS
        SELECT s.service_id,s.node_id,t.apply_revision AS revision,n.maintenance
        FROM authorized_service_nodes s
        JOIN tunnels t ON t.id=s.service_id
        JOIN tenants w ON w.id=t.tenant_id
        JOIN relay_nodes n ON n.id=s.node_id
        JOIN relay_service_health h ON h.node_id=s.node_id AND h.service_id=s.service_id
        JOIN relay_public_health p ON p.node_id=s.node_id AND p.service_id=s.service_id
        LEFT JOIN tunnel_applied_states a ON a.tunnel_id=t.id
        WHERE t.enabled=1 AND t.deleted_at IS NULL AND w.enabled=1
          AND n.approved=1 AND n.enabled=1 AND n.removed_at IS NULL
          AND (t.service_mode!='reverse_proxy' OR n.id='local' OR n.reverse_proxy_supported=1)
          AND (n.id='local' OR n.last_seen>unixepoch()-45)
          AND (t.service_mode='reverse_proxy' OR (a.revision=t.apply_revision AND a.status='ready' AND a.updated_at>unixepoch()-45))
          AND h.healthy=1 AND h.revision=t.apply_revision AND h.checked_at>unixepoch()-45
          AND p.healthy=1 AND p.revision=t.apply_revision AND p.checked_at>unixepoch()-45
          AND (n.id='local' OR p.address=n.public_ipv4)
          AND p.probe_kind=CASE WHEN t.protocol IN ('http','https') AND (n.id='local' OR h.public_probe_supported=1) THEN t.protocol ELSE 'tcp' END;
        CREATE VIEW IF NOT EXISTS relay_healthy_service_nodes AS
        SELECT service_id,node_id,revision FROM relay_ready_service_nodes WHERE maintenance=0;")?;
    tx.commit()?;
    Ok(())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/node-groups",
            get(groups::list).post(groups::create),
        )
        .route(
            "/api/v1/node-groups/{id}",
            put(groups::update).delete(groups::remove),
        )
        .route("/api/v1/node-releases", get(releases::list))
        .route("/api/v1/nodes", get(list).post(create))
        .route(
            "/api/v1/node/install.sh",
            get(|| async {
                (
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/x-shellscript; charset=utf-8",
                    )],
                    include_str!("../../../../docker/install-node.sh"),
                )
            }),
        )
        .route("/api/v1/node/register", post(control::register))
        .route("/api/v1/nodes/{id}", get(detail).put(update).delete(remove))
        .route("/api/v1/nodes/{id}/approve", post(approve))
        .route("/api/v1/nodes/{id}/enrollment", post(renew_enrollment))
        .route(
            "/api/v1/node-update-jobs",
            get(updates::list).post(updates::create),
        )
        .route("/api/v1/node-update-jobs/{id}", post(updates::action))
}

fn admin_write(state: &AppState, headers: &HeaderMap) -> Result<auth::Session, ApiError> {
    let actor = accounts::require_admin(state, headers)?;
    auth::require_csrf(state, headers)?;
    Ok(actor)
}
fn invalid(message: &str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, message)
}
fn missing() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "节点不存在或没有访问权限")
}
fn event(db: &Connection, node: &str, actor: &str, message: &str) -> Result<(), ApiError> {
    db.execute(
        "INSERT INTO relay_node_events(node_id,actor,message,occurred_at) VALUES(?1,?2,?3,?4)",
        params![node, actor, message, unix_now()],
    )
    .map_err(db_error)?;
    Ok(())
}
fn visible(db: &Connection, id: &str, tenant: &str, admin: bool) -> Result<bool, ApiError> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM relay_nodes n WHERE n.id=?1 AND n.removed_at IS NULL AND (?3 OR n.owner_tenant=?2 OR EXISTS(SELECT 1 FROM relay_node_authorizations g WHERE g.node_id=n.id AND g.tenant_id=?2)))",params![id,tenant,admin],|r|r.get(0)).map_err(db_error)
}
fn view(
    state: &AppState,
    db: &Connection,
    id: &str,
    tenant: &str,
    admin: bool,
) -> Result<Value, ApiError> {
    if !visible(db, id, tenant, admin)? {
        return Err(missing());
    }
    let mut result=db.query_row("SELECT id,name,public_ipv4,control_port,approved,enabled,os,architecture,version,last_seen,connections,maintenance,error,owner_tenant,certificate_pem!='' FROM relay_nodes WHERE id=?1",[id],|r|{
        let last=r.get::<_,Option<i64>>(9)?;
        let approved=r.get::<_,bool>(4)?;
        let enabled=r.get::<_,bool>(5)?;
        let maintenance=r.get::<_,bool>(11)?;
        Ok(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"public_ipv4":r.get::<_,String>(2)?,"control_port":r.get::<_,u16>(3)?,"approved":approved,"enabled":enabled,"os":r.get::<_,Option<String>>(6)?,"architecture":r.get::<_,Option<String>>(7)?,"version":if id=="local"{Some(env!("CARGO_PKG_VERSION").to_owned())}else{r.get::<_,Option<String>>(8)?},"last_seen":last,"connections":r.get::<_,u64>(10)?,"maintenance":maintenance,"error":r.get::<_,Option<String>>(12)?,"owner_tenant":r.get::<_,Option<String>>(13)?,"registered":r.get::<_,bool>(14)?,"status":if !enabled{"disabled"}else if !approved{"pending"}else if maintenance{"maintenance"}else if id=="local"||last.is_some_and(|v|v>unix_now()-45){"online"}else{"offline"}}))
    }).map_err(db_error)?;
    let mut query=db.prepare("SELECT t.id,t.name,t.tenant_id,t.enabled FROM tunnels t JOIN service_nodes s ON s.service_id=t.id WHERE s.node_id=?1 AND t.deleted_at IS NULL AND (?3 OR t.tenant_id=?2)").map_err(db_error)?;
    result["services"]=json!(query.query_map(params![id,tenant,admin],|r|Ok(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"tenant_id":r.get::<_,String>(2)?,"enabled":r.get::<_,bool>(3)?}))).map_err(db_error)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)?);
    if id == "local" {
        result["os"] = json!(runtime::operating_system());
        result["architecture"] = json!(std::env::consts::ARCH);
        result["connections"] = json!(state.tunnel_runtime.connection_count());
        result["public_ipv4"] = json!(crate::server_settings::relay_ipv4(state)?
            .map(|ip| ip.to_string())
            .unwrap_or_default());
    }
    if admin {
        for service in result["services"].as_array_mut().unwrap() {
            service["alternatives"] =
                json!(
                    updates::alternatives(db, id, service["id"].as_str().unwrap())
                        .map_err(db_error)?
                );
        }
    }
    result["latencies"] = latencies(db, id, tenant, admin)?;
    // 接入者只能续领未注册申请的凭证；分配授权不授予重置身份的权限。
    let (owner, expires): (Option<String>, Option<i64>) = db
        .query_row(
            "SELECT owner_tenant,token_expires FROM relay_nodes WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(db_error)?;
    result["can_enroll"] = json!(
        id != "local"
            && result["registered"] == false
            && (admin || owner.as_deref() == Some(tenant))
    );
    result["enrollment_expires_at"] = json!(expires);
    result["assigned"] = json!(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM relay_node_authorizations WHERE node_id=?1 AND (?3 OR tenant_id=?2))",
        params![id, tenant, admin], |r| r.get::<_, bool>(0),
    ).map_err(db_error)?);
    result["reverse_proxy_supported"] = json!(
        id == "local"
            || db
                .query_row(
                    "SELECT reverse_proxy_supported FROM relay_nodes WHERE id=?1",
                    [id],
                    |r| r.get::<_, bool>(0)
                )
                .map_err(db_error)?
    );
    result["reverse_proxy_selectable"] = json!(db.query_row("SELECT EXISTS(SELECT 1 FROM relay_proxy_authorizations WHERE node_id=?1 AND tenant_id=?2)", params![id,tenant], |r| r.get::<_,bool>(0)).map_err(db_error)?);
    result["selectable"] = json!(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM relay_node_authorizations WHERE node_id=?1 AND tenant_id=?2)",
        params![id, tenant], |r| r.get::<_, bool>(0),
    ).map_err(db_error)?);
    if id != "local" && result["registered"] == false {
        result["status"] = json!(if expires.is_some_and(|v| v > unix_now()) {
            "unregistered"
        } else {
            "expired"
        });
    }
    let mut q=db.prepare("SELECT i.stage,i.error,j.target_version FROM node_update_items i JOIN node_update_jobs j ON j.id=i.job_id WHERE i.node_id=?1 AND j.status IN ('queued','running','paused') AND i.stage NOT IN ('complete','skipped','cancelled') ORDER BY j.created_at LIMIT 1").map_err(db_error)?;
    result["update"]=q.query_row([id],|r|Ok(json!({"stage":r.get::<_,String>(0)?,"error":r.get::<_,Option<String>>(1)?,"target_version":r.get::<_,String>(2)?}))).optional().map_err(db_error)?.unwrap_or(Value::Null);
    if admin {
        let mut q = db
            .prepare("SELECT tenant_id FROM relay_node_grants WHERE node_id=?1 AND ?1!='local' UNION SELECT tenant_id FROM relay_local_proxy_grants WHERE ?1='local' ORDER BY tenant_id")
            .map_err(db_error)?;
        result["workspace_ids"] = json!(q
            .query_map([id], |r| r.get::<_, String>(0))
            .map_err(db_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db_error)?);
    }
    Ok(result)
}
/// 延迟按设备授权过滤；离线、撤权和超过 45 秒的样本不能被界面误标为实时测量。
fn latencies(db: &Connection, id: &str, tenant: &str, admin: bool) -> Result<Value, ApiError> {
    let mut q=db.prepare("SELECT d.id,d.name,l.rtt_ms,l.checked_at,l.samples, d.status='online' AND l.checked_at>?4 AND n.enabled=1 AND n.approved=1 AND n.maintenance=0 AND (n.id='local' OR n.last_seen>?4) FROM relay_latency l JOIN devices d ON d.id=l.device_id JOIN relay_nodes n ON n.id=l.node_id WHERE l.node_id=?1 AND (?3 OR d.tenant_id=?2) AND EXISTS(SELECT 1 FROM relay_node_authorizations g WHERE g.node_id=n.id AND g.tenant_id=d.tenant_id) ORDER BY d.name,d.id").map_err(db_error)?;
    let samples=q.query_map(params![id,tenant,admin,unix_now()-45],|r|Ok(json!({"device_id":r.get::<_,String>(0)?,"device_name":r.get::<_,String>(1)?,"rtt_ms":r.get::<_,u32>(2)?,"checked_at":r.get::<_,i64>(3)?,"samples":r.get::<_,u32>(4)?,"fresh":r.get::<_,Option<bool>>(5)?.unwrap_or(false)}))).map_err(db_error)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)?;
    Ok(json!(samples))
}
async fn list(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    let session = require_session(&state, &headers)?;
    let admin = accounts::require_admin(&state, &headers).is_ok();
    let db = state.db.lock().map_err(db_error)?;
    let mut q = db
        .prepare("SELECT id FROM relay_nodes WHERE removed_at IS NULL ORDER BY created_at,id")
        .map_err(db_error)?;
    let ids = q
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(db_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_error)?;
    let mut nodes = Vec::new();
    for id in ids {
        if visible(&db, &id, &session.tenant_id, admin)? {
            nodes.push(view(&state, &db, &id, &session.tenant_id, admin)?);
        }
    }
    Ok(Json(
        json!({"nodes":nodes,"server_version":env!("CARGO_PKG_VERSION")}),
    ))
}
async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session = require_session(&state, &headers)?;
    let admin = accounts::require_admin(&state, &headers).is_ok();
    let db = state.db.lock().map_err(db_error)?;
    let mut node = view(&state, &db, &id, &session.tenant_id, admin)?;
    if admin {
        let mut q=db.prepare("SELECT message,occurred_at FROM relay_node_events WHERE node_id=?1 ORDER BY id DESC LIMIT 50").map_err(db_error)?;
        node["events"] = json!(q
            .query_map([id], |r| Ok(
                json!({"message":r.get::<_,String>(0)?,"occurred_at":r.get::<_,i64>(1)?})
            ))
            .map_err(db_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db_error)?);
    }
    Ok(Json(node))
}
#[derive(Deserialize)]
struct Input {
    name: String,
    public_ipv4: String,
    #[serde(default = "default_port")]
    control_port: u16,
    enabled: Option<bool>,
    workspace_ids: Option<Vec<String>>,
}
fn default_port() -> u16 {
    9891
}
fn validate(state: &AppState, input: &Input) -> Result<(), ApiError> {
    if input.name.trim().is_empty()
        || input.name.chars().count() > 80
        || input.name.chars().any(char::is_control)
    {
        return Err(invalid("节点名称需为 1–80 个可见字符"));
    }
    let ip = input
        .public_ipv4
        .parse::<Ipv4Addr>()
        .map_err(|_| invalid("请填写公网 IPv4"))?;
    let a = ip.octets();
    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || a[0] == 0
        || a[0] >= 240
        || (a[0] == 100 && (64..=127).contains(&a[1]))
        || [0, 80, 443, 8282, 8290, state.config.caddy.http_port()].contains(&input.control_port)
    {
        return Err(invalid("节点必须使用公网 IPv4 和有效数据端口"));
    }
    Ok(())
}
async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<Input>,
) -> Result<Json<Value>, ApiError> {
    let session = require_write(&state, &headers)?;
    validate(&state, &input)?;
    if input.workspace_ids.is_some() || input.enabled.is_some() {
        return Err(invalid("申请不能同时授予权限，请由管理员审批分配"));
    }
    let server_url = installation_url(&state)?;
    let id = format!("node-{}", Uuid::new_v4());
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    ensure_unique_endpoint(&tx, &id, &input)?;
    tx.execute("INSERT INTO relay_nodes(id,owner_tenant,name,public_ipv4,control_port,token_digest,token_expires,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![id,session.tenant_id,input.name.trim(),input.public_ipv4,input.control_port,auth::digest(&token),unix_now()+1800,unix_now()]).map_err(db_error)?;
    event(&tx, &id, &session.user_id, "提交 VPS 节点接入申请")?;
    tx.commit().map_err(db_error)?;
    Ok(Json(enrollment(
        &state,
        &id,
        &token,
        &server_url,
        input.control_port,
    )))
}

/// 同一公网地址和数据端口只能对应一个节点身份；在写事务内检查，避免重复申请卡在待安装。
fn ensure_unique_endpoint(db: &Connection, id: &str, input: &Input) -> Result<(), ApiError> {
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM relay_nodes WHERE id!=?1 AND removed_at IS NULL AND public_ipv4=?2 AND control_port=?3)",
        params![id,input.public_ipv4,input.control_port], |r| r.get::<_, bool>(0),
    ).map_err(db_error)? {
        return Err(ApiError::new(StatusCode::CONFLICT, "此公网 IP 和数据端口已被申请或接入，请从节点列表继续安装，或联系管理员"));
    }
    Ok(())
}

/// 统一安装和注册使用的管理地址，提前拒绝无法接入的配置，不消耗凭证。
fn installation_url(state: &AppState) -> Result<String, ApiError> {
    let configured = state.security.settings()?.public_url;
    let url = reqwest::Url::parse(&configured)
        .map_err(|_| invalid("请管理员先配置公网 HTTPS 管理地址，再接入节点"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(invalid(
            "节点接入需要公网 HTTPS 管理地址，不得包含凭据、路径或查询参数",
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn enrollment(state: &AppState, id: &str, token: &str, server_url: &str, data_port: u16) -> Value {
    json!({"id":id,"token":token,"expires_at":unix_now()+1800,"version":releases::current_version(),
        "server_url":server_url,"http_port":state.config.caddy.http_port(),"data_port":data_port})
}

/// 在同一事务内轮换凭证；注册与续领竞争时只有先提交者的状态有效。
async fn renew_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_write(&state, &headers)?;
    let admin = accounts::require_admin(&state, &headers).is_ok();
    let server_url = installation_url(&state)?;
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    let port: u16 = tx.query_row(
        "SELECT control_port FROM relay_nodes WHERE id=?1 AND id!='local' AND removed_at IS NULL AND (?3 OR owner_tenant=?2)",
        params![id,actor.tenant_id,admin], |r| r.get(0),
    ).optional().map_err(db_error)?.ok_or_else(missing)?;
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    if tx.execute(
        "UPDATE relay_nodes SET token_digest=?2,token_expires=?3 WHERE id=?1 AND certificate_pem='' AND approved=0",
        params![id,auth::digest(&token),unix_now()+1800],
    ).map_err(db_error)? == 0 {
        return Err(invalid("节点已注册，不能重新生成接入凭证"));
    }
    event(&tx, &id, &actor.user_id, "重新生成接入凭证，旧凭证已失效")?;
    tx.commit().map_err(db_error)?;
    Ok(Json(enrollment(&state, &id, &token, &server_url, port)))
}
async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let actor = admin_write(&state, &headers)?;
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    if tx.execute("UPDATE relay_nodes SET approved=1 WHERE id=?1 AND removed_at IS NULL AND certificate_pem!=''",[&id]).map_err(db_error)?==0{return Err(invalid("节点尚未完成注册或已移除"));}
    event(
        &tx,
        &id,
        &actor.user_id,
        "批准节点；需分配工作空间后才能转发",
    )?;
    tx.commit().map_err(db_error)?;
    Ok(Json(json!({"approved":true})))
}
async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Input>,
) -> Result<Json<Value>, ApiError> {
    let actor = admin_write(&state, &headers)?;
    if id == "local" {
        {
            let _dns_guard = state.tunnel_runtime.direct.dns_lock.lock().await;
            let db = state.db.lock().map_err(db_error)?;
            let tx = db.unchecked_transaction().map_err(db_error)?;
            if let Some(grants) = input.workspace_ids {
                tx.execute("DELETE FROM relay_local_proxy_grants", [])
                    .map_err(db_error)?;
                for tenant in grants {
                    accounts::ensure_workspace_enabled(&tx, &tenant)?;
                    tx.execute(
                        "INSERT OR IGNORE INTO relay_local_proxy_grants VALUES(?1)",
                        [tenant],
                    )
                    .map_err(db_error)?;
                }
            }
            event(&tx, &id, &actor.user_id, "更新内置节点反向代理授权")?;
            tx.commit().map_err(db_error)?;
        }
        reverse_proxy::changed(&state, false).await?;
        let db = state.db.lock().map_err(db_error)?;
        return Ok(Json(view(&state, &db, &id, &actor.tenant_id, true)?));
    }
    validate(&state, &input)?;
    let _dns_guard = state.tunnel_runtime.direct.dns_lock.lock().await;
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    if !visible(&tx, &id, &actor.tenant_id, true)? {
        return Err(missing());
    }
    ensure_unique_endpoint(&tx, &id, &input)?;
    if updates::busy(&tx, &id).map_err(db_error)? {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "节点正在维护，暂不能修改",
        ));
    }
    if tx.query_row("SELECT EXISTS(SELECT 1 FROM tunnels t JOIN service_nodes s ON s.service_id=t.id WHERE s.node_id=?1 AND t.deleted_at IS NULL AND ((t.protocol='tcp' AND t.public_port=?2) OR (t.protocol='https' AND t.https_port=?2)))", params![id,input.control_port], |r|r.get::<_,bool>(0)).map_err(db_error)? {
        return Err(invalid("节点数据端口与已绑定服务的公网端口冲突"));
    }
    tx.execute("UPDATE relay_nodes SET name=?2,public_ipv4=?3,control_port=?4,enabled=COALESCE(?5,enabled) WHERE id=?1",params![id,input.name.trim(),input.public_ipv4,input.control_port,input.enabled]).map_err(db_error)?;
    if let Some(grants) = input.workspace_ids {
        tx.execute("DELETE FROM relay_node_grants WHERE node_id=?1", [&id])
            .map_err(db_error)?;
        for tenant in grants {
            accounts::ensure_workspace_enabled(&tx, &tenant)?;
            tx.execute(
                "INSERT OR IGNORE INTO relay_node_grants VALUES(?1,?2)",
                params![id, tenant],
            )
            .map_err(db_error)?;
        }
    }
    event(&tx, &id, &actor.user_id, "更新节点配置和授权")?;
    tx.commit().map_err(db_error)?;
    Ok(Json(view(&state, &db, &id, &actor.tenant_id, true)?))
}
async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let actor = admin_write(&state, &headers)?;
    if id == "local" {
        return Err(invalid("内置节点不能移除"));
    }
    let _dns_guard = state.tunnel_runtime.direct.dns_lock.lock().await;
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    if updates::busy(&tx, &id).map_err(db_error)? {
        return Err(ApiError::new(StatusCode::CONFLICT, "请先结束节点维护任务"));
    }
    if tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM relay_group_members WHERE node_id=?1)",
            [&id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(db_error)?
    {
        return Err(invalid("请先将节点移出节点组，再移除节点"));
    }
    if tx.execute("UPDATE relay_nodes SET enabled=0,removed_at=?2,certificate_pem='',token_digest=NULL WHERE id=?1 AND removed_at IS NULL",params![id,unix_now()]).map_err(db_error)?==0{return Err(missing());}
    tx.execute("DELETE FROM service_nodes WHERE node_id=?1", [&id])
        .map_err(db_error)?;
    tx.execute("DELETE FROM relay_node_grants WHERE node_id=?1", [&id])
        .map_err(db_error)?;
    event(
        &tx,
        &id,
        &actor.user_id,
        "移除节点并撤销身份；保留 VPS 上的数据",
    )?;
    tx.commit().map_err(db_error)?;
    Ok(Json(json!({"removed":true})))
}

#[cfg(test)]
mod proxy_permission_tests {
    use super::*;

    #[tokio::test]
    async fn builtin_grant_api_is_admin_only_and_does_not_change_tunnel_grants() {
        let (state, headers) = crate::tests::domain_fixture();
        let input = |ids: Vec<&str>| {
            serde_json::from_value(json!({"name":"内置节点","public_ipv4":"","workspace_ids":ids}))
                .unwrap()
        };
        let Json(result) = update(
            State(state.clone()),
            headers.clone(),
            Path("local".into()),
            Json(input(vec!["default"])),
        )
        .await
        .unwrap();
        assert_eq!(result["workspace_ids"], json!(["default"]));
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE users SET role='tenant' WHERE id='u'", [])
            .unwrap();
        assert!(services::authorize_proxy(&state.db.lock().unwrap(), "default", "local").is_ok());
        assert_eq!(
            update(
                State(state.clone()),
                headers.clone(),
                Path("local".into()),
                Json(input(vec![]))
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE users SET role='system_admin' WHERE id='u'", [])
            .unwrap();
        let _ = update(
            State(state.clone()),
            headers,
            Path("local".into()),
            Json(input(vec![])),
        )
        .await
        .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE users SET role='tenant' WHERE id='u'", [])
            .unwrap();
        let db = state.db.lock().unwrap();
        assert!(services::authorize_proxy(&db, "default", "local").is_err());
        assert!(db.query_row("SELECT EXISTS(SELECT 1 FROM relay_node_authorizations WHERE node_id='local' AND tenant_id='default')",[],|r|r.get::<_,bool>(0)).unwrap());
    }
}
