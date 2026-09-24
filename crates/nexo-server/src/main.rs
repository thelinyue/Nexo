//! Nexo v0.2.0 Server：只负责账号、Agent、域名和内网穿透服务。
//!
//! Agent 通过一次性入网凭证加入，之后使用独立的控制连接接收 Tunnel Desired State。

use std::{
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use clap::{Parser, Subcommand};
use nexo_core::{EnrollmentStatus, EnrollmentToken};
use nexo_protocol::{
    AgentEnrollmentPollRequest, AgentEnrollmentPollResponse, AgentEnrollmentRequest,
    AgentEnrollmentResponse, TunnelDataEndpoint, TunnelDesiredState,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use uuid::Uuid;

mod accounts;
mod auth;
mod caddy;
mod domain_access;
mod domain_runtime;
mod domains;
mod enrollment;
mod identity_runtime;
mod security;
mod transport;
use enrollment::{agent_enroll, agent_poll, approve_enrollment};

#[derive(Debug, Parser)]
#[command(name = "nexo", version, about = "Nexo 联巢内网穿透服务")]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}
#[derive(Debug, Subcommand)]
enum CliCommand {
    BootstrapCode,
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}
#[derive(Debug, Subcommand)]
enum AdminCommand {
    Recover {
        /// 多个管理员时指定要恢复的账号。
        #[arg(long)]
        username: Option<String>,
    },
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: Arc<Mutex<Connection>>,
    pub(crate) security: Arc<security::Security>,
    pub(crate) public_ips: Vec<std::net::IpAddr>,
    pub(crate) data_dir: PathBuf,
    pub(crate) domain_runtime: Arc<domain_runtime::DomainRuntimeManager>,
    pub(crate) domain_access: Arc<domain_access::Runtime>,
    pub(crate) control_addr: String,
    pub(crate) tunnel_endpoint: Option<TunnelDataEndpoint>,
    pub(crate) authority: Arc<identity_runtime::AuthorityRuntime>,
    pub(crate) tunnel_runtime: Arc<transport::Runtime>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ApiErrorBody {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<&'static str>,
}
#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    message: String,
    code: Option<&'static str>,
}
impl ApiError {
    pub(crate) fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            code: None,
        }
    }
    pub(crate) fn session_expired() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "登录已过期，请重新登录".into(),
            code: Some("session_expired"),
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                error: self.message,
                code: self.code,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    service: &'static str,
}
#[derive(Debug, Serialize)]
struct Device {
    id: String,
    tenant_id: String,
    name: String,
    os: Option<String>,
    architecture: Option<String>,
    agent_version: Option<String>,
    status: String,
    enrolled_at: Option<i64>,
    last_seen_at: Option<i64>,
    tunnel_count: i64,
    certificate: identity_runtime::CertificateStatus,
}
#[derive(Debug, Serialize)]
struct Enrollment {
    id: String,
    kind: String,
    tenant_id: String,
    status: String,
    expires_at: i64,
    device_id: Option<String>,
    token: Option<String>,
}
#[derive(Debug, Deserialize)]
struct CreateEnrollment {
    ttl_seconds: Option<i64>,
}
#[derive(Debug, Deserialize)]
struct ApproveEnrollment {
    device_name: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
struct Tunnel {
    id: String,
    tenant_id: String,
    device_id: Option<String>,
    device_name: Option<String>,
    name: String,
    protocol: String,
    local_address: String,
    local_port: u16,
    public_port: Option<u16>,
    hostname: Option<String>,
    enabled: bool,
    apply_status: String,
    apply_error: Option<String>,
    apply_revision: i64,
    public_address: Option<String>,
    public_domain: Option<String>,
    deletion_pending: bool,
}
#[derive(Debug, Deserialize)]
struct TunnelInput {
    device_id: Option<String>,
    name: String,
    protocol: String,
    local_address: String,
    local_port: u16,
    public_port: Option<u16>,
    hostname: Option<String>,
    enabled: Option<bool>,
    public_domain_id: Option<String>,
}
#[derive(Debug, Serialize)]
struct PublicDomain {
    id: String,
    tenant_id: String,
    domain: String,
    is_primary: bool,
    https_enabled: bool,
    apply_status: String,
    runtime: domain_runtime::DomainRuntime,
    access: Option<domain_access::Access>,
    #[serde(flatten)]
    settings: domains::Settings,
}
#[derive(Debug, Deserialize)]
struct DomainInput {
    domain: String,
    https_enabled: Option<bool>,
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();
    let cli = Cli::parse();
    let data_dir =
        PathBuf::from(env::var("NEXO_DATA_DIR").unwrap_or_else(|_| "./data/nexo".to_owned()));
    if matches!(cli.command, Some(CliCommand::BootstrapCode)) {
        println!("{}", auth::read_bootstrap_code(&data_dir)?);
        return Ok(());
    }
    if let Some(CliCommand::Admin {
        command: AdminCommand::Recover { username },
    }) = cli.command
    {
        let (code, username, expires) = auth::create_recovery_code(&data_dir, username.as_deref())?;
        println!("账号：{username}\n一次性恢复码：{code}\n有效期：15 分钟（到期时间戳 {expires}）\n在登录页选择“忘记密码”，输入恢复码和新密码。重新生成会使旧恢复码失效。");
        return Ok(());
    }
    let db_path = data_dir.join("nexo.db");
    fs::create_dir_all(&data_dir)?;
    let is_new = !db_path.exists();
    let connection = Connection::open(&db_path)?;
    initialize_database(&connection, is_new)?;
    auth::ensure_bootstrap_code(&connection, &data_dir)?;
    let identity_path = data_dir.join("transport/identity.json");
    let authority = Arc::new(identity_runtime::AuthorityRuntime::new(
        nexo_tunnel::identity::Authority::load_or_create(&identity_path)?,
        identity_path,
    )?);
    connection.execute("UPDATE devices SET status='offline'", [])?;
    let state = AppState {
        security: Arc::new(security::Security::from_env()?),
        domain_access: Arc::new(domain_access::Runtime::default()),
        public_ips: env::var("NEXO_PUBLIC_IPS")
            .unwrap_or_default()
            .split(',')
            .filter(|v| !v.trim().is_empty())
            .map(|v| v.trim().parse())
            .collect::<std::result::Result<_, _>>()
            .context("NEXO_PUBLIC_IPS 必须是逗号分隔的公网 IP 地址")?,
        authority,
        tunnel_runtime: Arc::new(transport::Runtime::new(
            env::var("NEXO_PUBLIC_BIND")
                .unwrap_or_else(|_| "0.0.0.0".into())
                .parse()
                .context("NEXO_PUBLIC_BIND 必须是 IP 地址")?,
        )),
        db: Arc::new(Mutex::new(connection)),
        domain_runtime: Arc::new(domain_runtime::DomainRuntimeManager::new(
            caddy::CaddyRuntimeConfig::from_env(&data_dir),
        )),
        data_dir,
        control_addr: env::var("NEXO_CONTROL_ADDR").unwrap_or_else(|_| "0.0.0.0:9890".to_owned()),
        tunnel_endpoint: env::var("NEXO_TUNNEL_ENDPOINT")
            .ok()
            .map(|address| TunnelDataEndpoint {
                address,
                server_name: nexo_tunnel::identity::SERVER_NAME.into(),
            }),
    };
    let control_listener = TcpListener::bind(&state.control_addr)
        .await
        .context("无法监听 Agent mTLS 控制端口")?;
    let data_listener =
        TcpListener::bind(env::var("NEXO_TUNNEL_ADDR").unwrap_or_else(|_| "0.0.0.0:9891".into()))
            .await
            .context("无法监听 Tunnel mTLS 数据端口")?;
    let control_task = tokio::spawn(transport::serve(state.clone(), control_listener, false));
    let data_task = tokio::spawn(transport::serve(state.clone(), data_listener, true));
    let transport_task = tokio::spawn(transport::Runtime::run(state.clone()));
    let identity_task = tokio::spawn(identity_runtime::AuthorityRuntime::run(state.clone()));
    let tunnel_runtime = state.tunnel_runtime.clone();
    let http_addr: SocketAddr = env::var("NEXO_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8280".to_owned())
        .parse()
        .context("NEXO_HTTP_ADDR 不是有效地址")?;
    let caddy_task = tokio::spawn(domain_runtime::DomainRuntimeManager::run(state.clone()));
    let dns_task = tokio::spawn(domain_access::Runtime::run(state.clone()));
    let runtime = state.domain_runtime.clone();
    let app = router(state);
    tracing::info!("Nexo 内网穿透服务监听 http://{http_addr}");
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    let serving = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    caddy_task.abort();
    dns_task.abort();
    tunnel_runtime.shutdown().await;
    transport_task.abort();
    identity_task.abort();
    let _ = control_task.await;
    let _ = data_task.await;
    runtime.supervisor.shutdown().await?;
    serving?;
    Ok(())
}

/// Docker 使用 SIGTERM 停止容器；与 Ctrl+C 共用清理流程，回收 Caddy 与 Tunnel 入口。
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("无法监听 SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

fn router(state: AppState) -> Router {
    let routes = Router::new()
        .route("/health", get(health))
        .route("/api/v1/admin/users", get(accounts::list_users))
        .route(
            "/api/v1/admin/users/{id}",
            axum::routing::patch(accounts::update_user).delete(accounts::delete_user),
        )
        .route(
            "/api/v1/admin/users/{id}/recovery",
            post(accounts::create_recovery),
        )
        .route(
            "/api/v1/admin/invitations",
            get(accounts::list_invitations).post(accounts::create_invitation),
        )
        .route(
            "/api/v1/admin/invitations/{id}",
            delete(accounts::revoke_invitation),
        )
        .route(
            "/api/v1/auth/invitations/inspect",
            post(accounts::inspect_invitation),
        )
        .route(
            "/api/v1/auth/invitations/accept",
            post(accounts::accept_invitation),
        )
        .route("/api/v1/auth/status", get(auth::status))
        .route("/api/v1/auth/initialize", post(auth::initialize))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/password", post(auth::change_password))
        .route("/api/v1/auth/recover", post(auth::recover))
        .route("/api/v1/auth/session", get(auth::current_session_info))
        .route("/api/v1/auth/sessions", get(auth::list_sessions))
        .route("/api/v1/auth/sessions/{id}", post(auth::revoke_session))
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/transport-identity", get(transport_identity))
        .route("/api/v1/devices/{id}", delete(delete_device))
        .route(
            "/api/v1/devices/{id}/recovery",
            post(enrollment::create_recovery),
        )
        .route(
            "/api/v1/enrollments",
            get(list_enrollments).post(create_enrollment),
        )
        .route(
            "/api/v1/enrollments/{id}",
            get(get_enrollment).delete(enrollment::cancel_enrollment),
        )
        .route("/api/v1/enrollments/{id}/approve", post(approve_enrollment))
        .route("/api/v1/agent/enroll", post(agent_enroll))
        .route("/api/v1/agent/enroll/{id}/poll", post(agent_poll))
        .route("/api/v1/tunnels", get(list_tunnels).post(create_tunnel))
        .route(
            "/api/v1/tunnels/{id}",
            put(update_tunnel).delete(delete_tunnel),
        )
        .route("/api/v1/tunnels/{id}/enable", post(enable_tunnel))
        .route("/api/v1/tunnels/{id}/disable", post(disable_tunnel))
        .route("/api/v1/tunnels/batch", delete(batch_delete_tunnels))
        .route(
            "/api/v1/public-domains",
            get(list_domains).post(create_domain),
        )
        .route(
            "/api/v1/public-domains/{id}",
            delete(delete_domain).patch(domains::update),
        )
        .route(
            "/api/v1/public-domains/{id}/verification",
            post(domains::verify),
        )
        .route(
            "/api/v1/public-domains/{id}/cloudflare-credential",
            put(domains::set_credential),
        )
        .route(
            "/api/v1/public-domains/{id}/access",
            get(domain_access::instructions).post(domain_access::check),
        )
        .route("/api/v1/public-domain-runtime-events", get(domain_events))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::session_middleware,
        ))
        .with_state(state.clone());
    Router::new()
        .fallback_service(routes)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            accounts::workspace_context,
        ))
        .layer(middleware::from_fn_with_state(state, security::protect))
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        service: "nexo-server",
    })
}

fn initialize_database(connection: &Connection, is_new: bool) -> Result<()> {
    // SQLite 的外键开关属于连接；恢复已有目录时也必须启用，确保删除设备能撤销恢复邀请的绑定。
    connection.pragma_update(None, "foreign_keys", "ON")?;
    if !is_new {
        let generation: Option<String> = connection
            .query_row(
                "SELECT value FROM product_metadata WHERE key='generation'",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("无法读取数据目录版本")?;
        if generation.as_deref() != Some("tunnel-only-v1") {
            anyhow::bail!(
                "检测到旧版 Nexo 数据目录；v0.2.0 仅支持全新安装，请备份后使用空数据目录启动"
            );
        }
        enrollment::initialize_schema(connection)?;
        accounts::initialize_schema(connection)?;
        return domains::initialize_schema(connection);
    }
    connection.execute_batch(include_str!("../../../migrations/v0.2.0_baseline.sql"))?;
    enrollment::initialize_schema(connection)?;
    accounts::initialize_schema(connection)?;
    domains::initialize_schema(connection)
}

fn require_session(state: &AppState, headers: &HeaderMap) -> Result<auth::Session, ApiError> {
    accounts::resource_session(state, headers)
}
fn require_write(state: &AppState, headers: &HeaderMap) -> Result<auth::Session, ApiError> {
    let session = require_session(state, headers)?;
    auth::require_csrf(state, headers)?;
    Ok(session)
}

async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Device>>, ApiError> {
    let session = require_session(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection.prepare("SELECT d.id,d.tenant_id,d.name,d.os,d.architecture,d.agent_version,d.status,d.enrolled_at,d.last_seen_at,(SELECT COUNT(*) FROM tunnels t WHERE t.device_id=d.id AND t.deleted_at IS NULL) FROM devices d WHERE d.tenant_id=?1 ORDER BY d.name").map_err(db_error)?;
    let rows = statement
        .query_map(params![session.tenant_id], |row| {
            Ok(Device {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                name: row.get(2)?,
                os: row.get(3)?,
                architecture: row.get(4)?,
                agent_version: row.get(5)?,
                status: row.get(6)?,
                enrolled_at: row.get(7)?,
                last_seen_at: row.get(8)?,
                tunnel_count: row.get(9)?,
                certificate: identity_runtime::device_status(
                    &connection,
                    &row.get::<_, String>(0)?,
                    unix_now(),
                )
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(error.into()))?,
            })
        })
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    Ok(Json(rows))
}
async fn transport_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    accounts::require_admin(&state, &headers)?;
    Ok(Json(state.authority.status()))
}
async fn delete_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_write(&state, &headers)?;
    {
        let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let tx = connection.unchecked_transaction().map_err(db_error)?;
        tx.execute("UPDATE tunnels SET enabled=0,device_id=NULL,apply_status='disabled',apply_revision=apply_revision+1 WHERE device_id=?1 AND tenant_id=?2",params![id,session.tenant_id]).map_err(db_error)?;
        let removed = tx
            .execute(
                "DELETE FROM devices WHERE id=?1 AND tenant_id=?2",
                params![id, session.tenant_id],
            )
            .map_err(db_error)?;
        if removed == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "设备不存在"));
        }
        accounts::audit(&tx, &session, "device_deleted", "device", &id)?;
        tx.commit().map_err(db_error)?;
    }
    state
        .tunnel_runtime
        .changed(&state)
        .await
        .map_err(db_error)?;
    Ok(Json(serde_json::json!({"deleted":true,"id":id})))
}

async fn list_enrollments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Enrollment>>, ApiError> {
    let session = require_session(&state, &headers)?;
    let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let mut q=connection.prepare("SELECT id,tenant_id,status,expires_at,device_id,kind FROM pending_enrollments WHERE tenant_id=?1 AND status IN ('awaiting_agent','awaiting_approval','approved') AND expires_at>unixepoch() ORDER BY created_at DESC").map_err(db_error)?;
    let rows = q
        .query_map(params![session.tenant_id], |row| {
            Ok(Enrollment {
                id: row.get(0)?,
                kind: row.get(5)?,
                tenant_id: row.get(1)?,
                status: row.get(2)?,
                expires_at: row.get(3)?,
                device_id: row.get(4)?,
                token: None,
            })
        })
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    Ok(Json(rows))
}
async fn create_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateEnrollment>,
) -> Result<Json<Enrollment>, ApiError> {
    let session = require_write(&state, &headers)?;
    let token = EnrollmentToken::generate(unix_now(), input.ttl_seconds.unwrap_or(3600))
        .map_err(db_error)?;
    let id = Uuid::new_v4().to_string();
    let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    accounts::ensure_workspace_enabled(&connection, &session.tenant_id)?;
    let connection = connection.unchecked_transaction().map_err(db_error)?;
    connection.execute("INSERT INTO pending_enrollments (id,tenant_id,token_digest,status,expires_at,created_at) VALUES (?1,?2,?3,'awaiting_agent',?4,?5)",params![id,session.tenant_id,token.digest,token.expires_at,unix_now()]).map_err(db_error)?;
    accounts::audit(
        &connection,
        &session,
        "enrollment_created",
        "enrollment",
        &id,
    )?;
    connection.commit().map_err(db_error)?;
    Ok(Json(Enrollment {
        id,
        kind: "enroll".into(),
        tenant_id: session.tenant_id,
        status: "awaiting_agent".to_owned(),
        expires_at: token.expires_at,
        device_id: None,
        token: Some(token.secret),
    }))
}
async fn get_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Enrollment>, ApiError> {
    let session = require_session(&state, &headers)?;
    let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let row=connection.query_row("SELECT id,tenant_id,CASE WHEN expires_at<=unixepoch() AND status IN ('awaiting_agent','awaiting_approval') THEN 'expired' ELSE status END,expires_at,device_id,kind FROM pending_enrollments WHERE id=?1 AND tenant_id=?2",params![id,session.tenant_id],|row|Ok(Enrollment{id:row.get(0)?,kind:row.get(5)?,tenant_id:row.get(1)?,status:row.get(2)?,expires_at:row.get(3)?,device_id:row.get(4)?,token:None})).optional().map_err(db_error)?.ok_or_else(||ApiError::new(StatusCode::NOT_FOUND,"入网请求不存在"))?;
    Ok(Json(row))
}
async fn list_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Tunnel>>, ApiError> {
    let session = require_session(&state, &headers)?;
    let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    query_tunnels(&connection, &session.tenant_id, None, &headers)
        .map(Json)
        .map_err(db_error)
}
async fn create_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<TunnelInput>,
) -> Result<Json<Tunnel>, ApiError> {
    let session = require_write(&state, &headers)?;
    let id = Uuid::new_v4().to_string();
    {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let db = db.unchecked_transaction().map_err(db_error)?;
        prepare_tunnel(&db, &session.tenant_id, &id, &mut input)?;
        db.execute("INSERT INTO tunnels (id,tenant_id,device_id,name,protocol,local_address,local_port,public_port,hostname,enabled,apply_status,apply_revision,public_domain_id,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'checking',1,?11,?12,?12)",params![id,session.tenant_id,input.device_id,input.name.trim(),input.protocol,input.local_address.trim(),input.local_port,input.public_port,input.hostname,input.enabled.unwrap_or(true),input.public_domain_id,unix_now()]).map_err(db_error)?;
        accounts::audit(&db, &session, "service_created", "service", &id)?;
        db.commit().map_err(db_error)?;
    }
    state
        .tunnel_runtime
        .changed(&state)
        .await
        .map_err(db_error)?;
    read_tunnel(&state, &session.tenant_id, &id, &headers).map(Json)
}
async fn update_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut input): Json<TunnelInput>,
) -> Result<Json<Tunnel>, ApiError> {
    let session = require_write(&state, &headers)?;
    {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let db = db.unchecked_transaction().map_err(db_error)?;
        if !db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels WHERE id=?1 AND tenant_id=?2 AND deleted_at IS NULL)",params![id,session.tenant_id], |r| r.get::<_,bool>(0)).map_err(db_error)? { return Err(ApiError::new(StatusCode::NOT_FOUND,"服务不存在")); }
        prepare_tunnel(&db, &session.tenant_id, &id, &mut input)?;
        db.execute("UPDATE tunnels SET device_id=?1,name=?2,protocol=?3,local_address=?4,local_port=?5,public_port=?6,hostname=?7,enabled=?8,apply_revision=apply_revision+1,apply_status='checking',updated_at=?9,public_domain_id=?12 WHERE id=?10 AND tenant_id=?11 AND deleted_at IS NULL",params![input.device_id,input.name.trim(),input.protocol,input.local_address.trim(),input.local_port,input.public_port,input.hostname,input.enabled.unwrap_or(true),unix_now(),id,session.tenant_id,input.public_domain_id]).map_err(db_error)?;
        accounts::audit(&db, &session, "service_updated", "service", &id)?;
        db.commit().map_err(db_error)?;
    }
    state
        .tunnel_runtime
        .changed(&state)
        .await
        .map_err(db_error)?;
    read_tunnel(&state, &session.tenant_id, &id, &headers).map(Json)
}
async fn delete_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_write(&state, &headers)?;
    {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let db = db.unchecked_transaction().map_err(db_error)?;
        let removed = db.execute("UPDATE tunnels SET deleted_at=?1,enabled=0,apply_status='disabled',apply_revision=apply_revision+1 WHERE id=?2 AND tenant_id=?3 AND deleted_at IS NULL",params![unix_now(),id,session.tenant_id]).map_err(db_error)?;
        if removed == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "服务不存在"));
        }
        accounts::audit(&db, &session, "service_deleted", "service", &id)?;
        db.commit().map_err(db_error)?;
    }
    state
        .tunnel_runtime
        .changed(&state)
        .await
        .map_err(db_error)?;
    Ok(Json(serde_json::json!({"deleted":true,"id":id})))
}
fn read_tunnel(
    state: &AppState,
    tenant: &str,
    id: &str,
    headers: &HeaderMap,
) -> Result<Tunnel, ApiError> {
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    query_tunnels(&db, tenant, Some(id), headers)
        .map_err(db_error)?
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "服务不存在"))
}
async fn enable_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Tunnel>, ApiError> {
    set_tunnel_enabled(state, headers, id, true).await
}
async fn disable_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Tunnel>, ApiError> {
    set_tunnel_enabled(state, headers, id, false).await
}
async fn set_tunnel_enabled(
    state: AppState,
    headers: HeaderMap,
    id: String,
    enabled: bool,
) -> Result<Json<Tunnel>, ApiError> {
    let session = require_write(&state, &headers)?;
    {
        let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let connection = connection.unchecked_transaction().map_err(db_error)?;
        let changed = connection.execute("UPDATE tunnels SET enabled=?1,apply_status=CASE WHEN ?1=1 THEN 'checking' ELSE 'disabled' END,apply_revision=apply_revision+1,updated_at=?2 WHERE id=?3 AND tenant_id=?4 AND deleted_at IS NULL",params![enabled,unix_now(),id,session.tenant_id]).map_err(db_error)?;
        if changed == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "服务不存在"));
        }
        accounts::audit(&connection, &session, "service_toggled", "service", &id)?;
        connection.commit().map_err(db_error)?;
    }
    state
        .tunnel_runtime
        .changed(&state)
        .await
        .map_err(db_error)?;
    read_tunnel(&state, &session.tenant_id, &id, &headers).map(Json)
}

#[derive(Debug, Deserialize)]
struct BatchDelete {
    tunnel_ids: Vec<String>,
}
async fn batch_delete_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BatchDelete>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_write(&state, &headers)?;
    {
        let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let tx = connection.unchecked_transaction().map_err(db_error)?;
        for id in &input.tunnel_ids {
            let changed = tx.execute("UPDATE tunnels SET deleted_at=?1,enabled=0,apply_status='disabled',apply_revision=apply_revision+1 WHERE id=?2 AND tenant_id=?3",params![unix_now(),id,session.tenant_id]).map_err(db_error)?;
            if changed > 0 {
                accounts::audit(&tx, &session, "service_deleted", "service", id)?;
            }
        }
        tx.commit().map_err(db_error)?;
    }
    state
        .tunnel_runtime
        .changed(&state)
        .await
        .map_err(db_error)?;
    Ok(Json(serde_json::json!({"deleted_ids":input.tunnel_ids})))
}

async fn list_domains(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PublicDomain>>, ApiError> {
    let session = require_session(&state, &headers)?;
    let mut domains = {
        let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let mut query = connection.prepare("SELECT id,tenant_id,domain,is_primary,https_enabled FROM public_domains WHERE tenant_id=?1 ORDER BY domain").map_err(db_error)?;
        let rows = query
            .query_map(params![session.tenant_id], |row| {
                Ok(PublicDomain {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    domain: row.get(2)?,
                    is_primary: row.get::<_, i64>(3)? != 0,
                    https_enabled: row.get::<_, i64>(4)? != 0,
                    apply_status: "pending".into(),
                    runtime: domain_runtime::DomainRuntime::pending(true),
                    access: None,
                    settings: domains::load(
                        &connection,
                        &row.get::<_, String>(0)?,
                        &row.get::<_, String>(2)?,
                    )
                    .map_err(|e| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(
                            e.message,
                        )))
                    })?,
                })
            })
            .map_err(db_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?
    };
    // 先释放 SQLite 锁，再读取运行快照，避免与采集任务写日志时发生锁顺序反转。
    for domain in &mut domains {
        domain.runtime = state.domain_runtime.status(&domain.id);
        domain.apply_status = domain.runtime.config_status.clone();
        domain.access = Some(domain_access::snapshot(
            &state,
            &session.tenant_id,
            &domain.id,
        )?);
    }
    Ok(Json(domains))
}
async fn create_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<DomainInput>,
) -> Result<Json<PublicDomain>, ApiError> {
    let session = require_write(&state, &headers)?;
    let domain = normalize_domain(&input.domain)?;
    let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let reserved: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM public_domains p LEFT JOIN domain_settings s ON s.domain_id=p.id WHERE p.domain=?1 AND (p.tenant_id=?2 OR COALESCE(s.verified,1)=1))",
            params![domain,session.tenant_id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if reserved {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "域名已存在，请使用其他域名",
        ));
    }
    let primary: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM public_domains WHERE tenant_id=?1",
            params![session.tenant_id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    let id = Uuid::new_v4().to_string();
    let tx = connection.unchecked_transaction().map_err(db_error)?;
    tx.execute("INSERT INTO public_domains (id,tenant_id,domain,is_primary,https_enabled,apply_status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,'pending',?6,?6)",params![id,session.tenant_id,domain,(primary==0) as i64,input.https_enabled.unwrap_or(true) as i64,unix_now()]).map_err(|error| {
        if matches!(&error, rusqlite::Error::SqliteFailure(code, _) if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE) {
            ApiError::new(StatusCode::CONFLICT, "域名已存在，请使用其他域名")
        } else {
            db_error(error)
        }
    })?;
    domains::create_settings(&tx, &id)?;
    accounts::audit(&tx, &session, "domain_created", "domain", &id)?;
    let settings = domains::load(&tx, &id, &domain)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(PublicDomain {
        id,
        tenant_id: session.tenant_id,
        domain,
        is_primary: primary == 0,
        https_enabled: input.https_enabled.unwrap_or(true),
        apply_status: "pending".to_owned(),
        access: None,
        settings,
        runtime: domain_runtime::DomainRuntime::pending(
            state.domain_runtime.supervisor.config().enabled,
        ),
    }))
}
/// IDNA 规范化后检查 DNS 标签；域名不能携带 URL、端口、通配符或 IP 地址。
fn normalize_domain(value: &str) -> Result<String, ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "请输入有效域名，例如 example.com，不要包含网址前缀、端口或路径",
        )
    };
    let trimmed = value.trim();
    let raw = trimmed.strip_suffix('.').unwrap_or(trimmed);
    let domain = idna::domain_to_ascii_strict(raw)
        .map_err(|_| invalid())?
        .to_ascii_lowercase();
    if domain.len() > 253
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        || domain
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .bytes()
            .all(|c| c.is_ascii_digit())
    {
        return Err(invalid());
    }
    Ok(domain)
}

async fn delete_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_write(&state, &headers)?;
    let mut connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    // 在同一写事务内核对归属和引用，避免检查后有服务绑定，导致删除时引用被置空。
    let tx = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(db_error)?;
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM public_domains WHERE id=?1 AND tenant_id=?2)",
            params![id, session.tenant_id],
            |row| row.get(0),
        )
        .map_err(db_error)?;
    if !exists {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "域名不存在或已被删除"));
    }
    let related = {
        let mut query = tx.prepare("SELECT CASE WHEN tenant_id=?2 THEN name ELSE '其他工作空间服务' END FROM tunnels WHERE public_domain_id=?1 AND deleted_at IS NULL ORDER BY name LIMIT 4").map_err(db_error)?;
        let rows = query
            .query_map(params![id, session.tenant_id], |row| {
                row.get::<_, String>(0)
            })
            .map_err(db_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?
    };
    if !related.is_empty() {
        let names = related
            .iter()
            .take(3)
            .map(|name| format!("「{name}」"))
            .collect::<Vec<_>>()
            .join("、");
        let more = if related.len() > 3 { "等" } else { "" };
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("该域名仍被服务{names}{more}使用，请先修改或删除关联服务"),
        ));
    }
    tx.execute(
        "DELETE FROM public_domains WHERE id=?1 AND tenant_id=?2",
        params![id, session.tenant_id],
    )
    .map_err(db_error)?;
    accounts::audit(&tx, &session, "domain_deleted", "domain", &id)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(serde_json::json!({"deleted":true,"id":id})))
}
async fn domain_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_session(&state, &headers)?;
    let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let mut query = connection.prepare("SELECT id,public_domain_id,summary,occurred_at FROM public_domain_runtime_events WHERE tenant_id=?1 ORDER BY id DESC LIMIT 100").map_err(db_error)?;
    let events = query.query_map(params![session.tenant_id], |row| Ok(serde_json::json!({"id":row.get::<_,i64>(0)?, "domain_id":row.get::<_,Option<String>>(1)?, "summary":row.get::<_,String>(2)?, "occurred_at":row.get::<_,i64>(3)?}))).map_err(db_error)?.collect::<Result<Vec<_>, _>>().map_err(db_error)?;
    Ok(Json(
        serde_json::json!({"events":events,"next_cursor":null}),
    ))
}

fn query_tunnels(
    connection: &Connection,
    tenant: &str,
    only: Option<&str>,
    headers: &HeaderMap,
) -> rusqlite::Result<Vec<Tunnel>> {
    // Host 仅用于当前响应的地址展示，不参与监听或身份校验；不猜测 127.0.0.1 为公网地址。
    let authority = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|host| host.parse::<axum::http::uri::Authority>().ok());
    let sql="SELECT t.id,t.tenant_id,t.device_id,d.name,t.name,t.protocol,t.local_address,t.local_port,t.public_port,t.hostname,t.enabled,t.apply_status,t.apply_error,t.apply_revision,t.public_domain_id,t.deleted_at,p.domain FROM tunnels t LEFT JOIN devices d ON d.id=t.device_id LEFT JOIN public_domains p ON p.id=t.public_domain_id WHERE t.tenant_id=?1 AND t.deleted_at IS NULL AND (?2 IS NULL OR t.id=?2) ORDER BY t.created_at DESC";
    let mut q = connection.prepare(sql)?;
    let rows = q
        .query_map(params![tenant, only], |row| {
            let port: Option<u16> = row.get(8)?;
            let hostname: Option<String> = row.get(9)?;
            let protocol: String = row.get(5)?;
            let public_domain: Option<String> = row.get(16)?;
            let public_address = if protocol == "tcp" {
                port.zip(authority.as_ref())
                    .map(|(port, authority)| format!("{}:{port}", authority.host()))
            } else {
                hostname
                    .as_ref()
                    .zip(public_domain.as_ref())
                    .map(|(host, domain)| format!("{protocol}://{host}.{domain}"))
            };
            Ok(Tunnel {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                device_id: row.get(2)?,
                device_name: row.get(3)?,
                name: row.get(4)?,
                protocol,
                local_address: row.get(6)?,
                local_port: row.get(7)?,
                public_port: port,
                hostname: hostname.clone(),
                enabled: row.get::<_, i64>(10)? != 0,
                apply_status: row.get(11)?,
                apply_error: row.get(12)?,
                apply_revision: row.get(13)?,
                public_address,
                public_domain,
                deletion_pending: false,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
/// 在同一个数据库锁内分配端口并验证归属，防止跨工作空间绑定 Agent/域名或并发抢占端口。
fn prepare_tunnel(
    db: &Connection,
    tenant: &str,
    id: &str,
    input: &mut TunnelInput,
) -> Result<(), ApiError> {
    validate_tunnel(input)?;
    if let Some(device) = &input.device_id {
        let owned: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM devices WHERE id=?1 AND tenant_id=?2)",
                params![device, tenant],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if !owned {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Agent 不存在或不属于当前工作空间",
            ));
        }
    }
    if input.protocol == "tcp" {
        input.hostname = None;
        input.public_domain_id = None;
        if input.public_port.is_none() {
            input.public_port = db.query_row("SELECT public_port FROM tunnels WHERE id=?1 AND tenant_id=?2 AND protocol='tcp'",params![id,tenant],|r|r.get::<_,Option<u16>>(0)).optional().map_err(db_error)?.flatten();
        }
        if input.public_port.is_none() {
            let used = db.prepare("SELECT public_port FROM tunnels WHERE public_port IS NOT NULL AND deleted_at IS NULL").map_err(db_error)?.query_map([], |r|r.get::<_,u16>(0)).map_err(db_error)?.collect::<rusqlite::Result<std::collections::HashSet<_>>>().map_err(db_error)?;
            input.public_port = (20000..=29999).find(|port| !used.contains(port));
        }
        if input.public_port.is_none_or(|port| port == 0) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "没有可用公网端口，请指定有效端口",
            ));
        }
        let occupied: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels WHERE public_port=?1 AND id!=?2 AND deleted_at IS NULL)",params![input.public_port,id],|r|r.get(0)).map_err(db_error)?;
        if occupied {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "公网端口已被其他服务使用",
            ));
        }
    } else {
        input.public_port = None;
        let (domain, https): (String, bool) = db
            .query_row(
                "SELECT domain,https_enabled FROM public_domains WHERE id=?1 AND tenant_id=?2",
                params![input.public_domain_id, tenant],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_error)?
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "请选择当前工作空间的域名"))?;
        let settings = domains::load(
            db,
            input.public_domain_id.as_deref().unwrap_or_default(),
            &domain,
        )?;
        if settings.verification_status != "verified" {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "请先完成域名归属验证",
            ));
        }
        if input.protocol == "https"
            && settings.certificate_mode == "cloudflare_dns"
            && !settings.credential_configured
            && !settings.legacy
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "请先配置 Cloudflare 凭据，或选择 HTTP 验证",
            ));
        }
        if input.protocol == "https" && !https {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "此域名未开启 HTTPS"));
        }
        let host = input.hostname.as_deref().unwrap_or_default().trim();
        if host.is_empty() {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "服务子域名不能为空"));
        }
        let full = normalize_domain(&format!("{host}.{domain}"))?;
        let host = full
            .strip_suffix(&format!(".{domain}"))
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "服务子域名无效"))?
            .to_owned();
        let occupied: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels t JOIN public_domains p ON p.id=t.public_domain_id WHERE t.hostname||'.'||p.domain=?1 AND t.id!=?2 AND t.deleted_at IS NULL) OR EXISTS(SELECT 1 FROM public_domains p LEFT JOIN domain_settings s ON s.domain_id=p.id WHERE p.domain=?1 AND COALESCE(s.verified,1)=1)",params![full,id],|r|r.get(0)).map_err(db_error)?;
        if occupied {
            return Err(ApiError::new(StatusCode::CONFLICT, "该服务域名已被使用"));
        }
        input.hostname = Some(host);
    }
    Ok(())
}
fn validate_tunnel(input: &TunnelInput) -> Result<(), ApiError> {
    if input.name.trim().is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "服务名称不能为空"));
    }
    if !matches!(input.protocol.as_str(), "tcp" | "http" | "https") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "协议必须是 TCP、HTTP 或 HTTPS",
        ));
    }
    if input.local_address.trim().is_empty() || input.local_address.contains(['/', '\\', ' ']) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "本地地址必须是主机名或 IP，不含网址前缀或路径",
        ));
    }
    if input.local_port == 0 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "本地端口无效"));
    }
    Ok(())
}
fn db_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn desired_tunnels(state: &AppState, device_id: &str) -> Result<Vec<TunnelDesiredState>> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let mut q=connection.prepare("SELECT id,protocol,local_address,local_port,hostname,origin_protocol,origin_tls_server_name,origin_tls_verification,apply_revision,enabled FROM tunnels WHERE device_id=?1 AND deleted_at IS NULL AND EXISTS(SELECT 1 FROM tenants w WHERE w.id=tunnels.tenant_id AND w.enabled=1)")?;
    let mapped = q.query_map(params![device_id], |row| {
        Ok(TunnelDesiredState {
            tunnel_id: row.get(0)?,
            protocol: row.get(1)?,
            local_address: row.get(2)?,
            local_port: row.get(3)?,
            hostname: row.get(4)?,
            origin_protocol: row.get(5)?,
            origin_tls_server_name: row.get(6)?,
            origin_tls_verification: row.get(7)?,
            origin_ca_pem: None,
            revision: row.get(8)?,
            enabled: row.get::<_, i64>(9)? != 0,
        })
    })?;
    Ok(mapped.collect::<Result<Vec<_>, _>>()?)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_addresses_use_service_domains_and_preserve_ipv6_brackets() {
        let (state, mut headers) = domain_fixture();
        let db = state.db.lock().unwrap();
        db.execute_batch("INSERT INTO public_domains (id,tenant_id,domain,created_at,updated_at) VALUES ('domain','default','example.com',0,0);
            INSERT INTO tunnels (id,tenant_id,name,protocol,local_address,local_port,public_port,hostname,public_domain_id,created_at,updated_at) VALUES
            ('tcp','default','tcp','tcp','127.0.0.1',1234,20000,NULL,NULL,0,0),
            ('web','default','web','https','127.0.0.1',8080,NULL,'app','domain',0,0);").unwrap();
        headers.insert("host", "[2001:db8::1]:8280".parse().unwrap());
        let tunnels = query_tunnels(&db, "default", None, &headers).unwrap();
        assert_eq!(
            tunnels
                .iter()
                .find(|t| t.id == "tcp")
                .unwrap()
                .public_address
                .as_deref(),
            Some("[2001:db8::1]:20000")
        );
        assert_eq!(
            tunnels
                .iter()
                .find(|t| t.id == "web")
                .unwrap()
                .public_address
                .as_deref(),
            Some("https://app.example.com")
        );
    }

    #[test]
    fn fresh_database_uses_tunnel_only_baseline() {
        let connection = Connection::open_in_memory().expect("应创建内存数据库");
        initialize_database(&connection, true).expect("新数据库应初始化");
        let generation: String = connection
            .query_row(
                "SELECT value FROM product_metadata WHERE key='generation'",
                [],
                |row| row.get(0),
            )
            .expect("应写入产品代际标记");
        assert_eq!(generation, "tunnel-only-v1");
        let old_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('legacy_devices','legacy_routes','legacy_policies')",
                [],
                |row| row.get(0),
            )
            .expect("应能检查旧表");
        assert_eq!(old_tables, 0);
    }

    #[test]
    fn old_generation_is_rejected_with_chinese_message() {
        let connection = Connection::open_in_memory().expect("应创建内存数据库");
        connection
            .execute_batch(
                "CREATE TABLE product_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT INTO product_metadata VALUES ('generation','legacy-v1');",
            )
            .expect("应创建旧代际标记");
        let error = initialize_database(&connection, false).expect_err("旧代际必须拒绝");
        assert!(error.to_string().contains("仅支持全新安装"));
    }

    // 使用真实 SQLite、会话和 CSRF 校验调用处理函数，不以浏览器模拟接口代替删除保护测试。
    #[test]
    fn reopened_database_enforces_foreign_keys_and_keeps_recovery_schema() {
        let connection = Connection::open_in_memory().unwrap();
        initialize_database(&connection, true).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        initialize_database(&connection, false).unwrap();
        assert_eq!(
            connection
                .query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(connection.query_row("SELECT COUNT(*) FROM pragma_table_info('pending_enrollments') WHERE name='kind'",[],|r|r.get::<_,i64>(0)).unwrap(),1);
    }

    pub(super) fn domain_fixture() -> (AppState, HeaderMap) {
        use sha2::{Digest, Sha256};
        let db = Connection::open_in_memory().unwrap();
        initialize_database(&db, true).unwrap();
        db.execute("INSERT INTO users (id,tenant_id,username,role,password_hash,created_at) VALUES ('u','default','admin','system_admin','unused',0)", []).unwrap();
        let digest = |value: &str| hex::encode(Sha256::digest(value.as_bytes()));
        db.execute("INSERT INTO auth_sessions (id,user_id,tenant_id,session_digest,csrf_digest,created_at,last_seen_at,expires_at) VALUES ('s','u','default',?1,?2,0,0,?3)", params![digest("domain-test"), digest("csrf-test"), unix_now() + 3600]).unwrap();
        let state = AppState {
            security: Arc::new(security::Security::default()),
            domain_access: Arc::new(domain_access::Runtime::default()),
            public_ips: vec![],
            authority: Arc::new(
                identity_runtime::AuthorityRuntime::new(
                    nexo_tunnel::identity::Authority::generate().unwrap(),
                    PathBuf::new(),
                )
                .unwrap(),
            ),
            tunnel_runtime: Arc::new(transport::Runtime::new("127.0.0.1".parse().unwrap())),
            db: Arc::new(Mutex::new(db)),
            data_dir: PathBuf::new(),
            domain_runtime: Arc::new(domain_runtime::DomainRuntimeManager::new(
                caddy::CaddyRuntimeConfig {
                    enabled: false,
                    ..caddy::CaddyRuntimeConfig::from_env(PathBuf::new())
                },
            )),
            control_addr: String::new(),
            tunnel_endpoint: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "nexo_session=domain-test".parse().unwrap());
        headers.insert("x-nexo-csrf", "csrf-test".parse().unwrap());
        (state, headers)
    }

    pub(super) async fn add_test_domain(
        state: &AppState,
        headers: &HeaderMap,
        domain: &str,
    ) -> Result<PublicDomain, ApiError> {
        create_domain(
            State(state.clone()),
            headers.clone(),
            Json(DomainInput {
                domain: domain.to_owned(),
                https_enabled: Some(true),
            }),
        )
        .await
        .map(|Json(value)| value)
    }

    #[tokio::test]
    async fn domains_normalize_validate_and_report_duplicates() {
        let (state, headers) = domain_fixture();
        for invalid in [
            "",
            ".",
            "a..com",
            "-a.com",
            "a-.com",
            "a_b.com",
            "https://example.com",
            "example.com:443",
            "example.com/path",
            "*.example.com",
            "127.0.0.1",
            "x.123",
            "user@example.com",
            "a b.com",
            "example.com..",
        ] {
            let error = add_test_domain(&state, &headers, invalid)
                .await
                .unwrap_err();
            assert_eq!(error.status, StatusCode::BAD_REQUEST, "{invalid}");
        }
        let oversized = format!("{}.com", "a".repeat(64));
        assert_eq!(
            add_test_domain(&state, &headers, &oversized)
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
        let created = add_test_domain(&state, &headers, "  EXAMPLE.COM. ")
            .await
            .unwrap();
        assert_eq!(created.domain, "example.com");
        assert_eq!(created.apply_status, "pending");
        let duplicate = add_test_domain(&state, &headers, "example.com")
            .await
            .unwrap_err();
        assert_eq!(duplicate.status, StatusCode::CONFLICT);
        assert!(duplicate.message.contains("域名已存在"));
        let idn = add_test_domain(&state, &headers, "例子.公司")
            .await
            .unwrap();
        assert!(idn.domain.starts_with("xn--"));
        assert_eq!(
            add_test_domain(&state, &headers, &idn.domain)
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        let db = state.db.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM public_domains", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn referenced_domains_cannot_be_deleted_even_when_service_disabled() {
        let (state, headers) = domain_fixture();
        let domain = add_test_domain(&state, &headers, "example.com")
            .await
            .unwrap();
        state.db.lock().unwrap().execute("INSERT INTO tunnels (id,tenant_id,name,protocol,local_address,local_port,enabled,public_domain_id,created_at,updated_at) VALUES ('t','default','家庭 NAS','https','127.0.0.1',8080,0,?1,0,0)", params![domain.id]).unwrap();
        let error = delete_domain(
            State(state.clone()),
            headers.clone(),
            Path(domain.id.clone()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert!(error.message.contains("家庭 NAS"));
        let Json(domains) = list_domains(State(state.clone()), headers.clone())
            .await
            .unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT public_domain_id FROM tunnels WHERE id='t'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            domain.id
        );
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE tunnels SET deleted_at=1 WHERE id='t'", [])
            .unwrap();
        let deleted = delete_domain(
            State(state.clone()),
            headers.clone(),
            Path(domain.id.clone()),
        )
        .await
        .unwrap();
        assert_eq!(deleted.0["deleted"], true);
        assert_eq!(
            delete_domain(State(state.clone()), headers, Path(domain.id))
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn domain_mutations_require_session_csrf_and_ownership() {
        let (state, headers) = domain_fixture();
        let domain = add_test_domain(&state, &headers, "example.com")
            .await
            .unwrap();
        assert_eq!(
            add_test_domain(&state, &HeaderMap::new(), "other.com")
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        let mut bad_csrf = headers.clone();
        bad_csrf.remove("x-nexo-csrf");
        assert_eq!(
            add_test_domain(&state, &bad_csrf, "other.com")
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            delete_domain(State(state.clone()), bad_csrf, Path(domain.id))
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        state.db.lock().unwrap().execute_batch("INSERT INTO tenants(id,name,created_at) VALUES ('other','其他空间',0); INSERT INTO public_domains (id,tenant_id,domain,created_at,updated_at) VALUES ('foreign','other','foreign.com',0,0);").unwrap();
        assert_eq!(
            delete_domain(
                State(state.clone()),
                headers.clone(),
                Path("foreign".into())
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::NOT_FOUND
        );
        let Json(domains) = list_domains(State(state.clone()), headers).await.unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM public_domains", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn domain_list_does_not_imply_legacy_pending_is_running() {
        let (state, headers) = domain_fixture();
        add_test_domain(&state, &headers, "example.com")
            .await
            .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE public_domains SET apply_status='pending'", [])
            .unwrap();
        let Json(domains) = list_domains(State(state), headers).await.unwrap();
        assert_eq!(domains[0].apply_status, "disabled");
        assert_eq!(domains[0].runtime.config_status, "disabled");
    }

    #[tokio::test]
    async fn runtime_events_require_auth_and_are_scoped_to_the_current_tenant() {
        let (state, headers) = domain_fixture();
        state.db.lock().unwrap().execute_batch("INSERT INTO tenants(id,name,created_at) VALUES ('other','其他空间',0); INSERT INTO public_domain_runtime_events (tenant_id,summary,occurred_at) VALUES ('default','配置已加载',1),('other','其他空间的证书错误',2);").unwrap();
        assert_eq!(
            domain_events(State(state.clone()), HeaderMap::new())
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        let events = domain_events(State(state), headers).await.unwrap().0;
        assert_eq!(events["events"].as_array().unwrap().len(), 1);
        assert_eq!(events["events"][0]["summary"], "配置已加载");
    }
}
