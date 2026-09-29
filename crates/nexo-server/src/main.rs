//! Nexo v0.2.0 Server：只负责账号、Agent、域名和内网穿透服务。
//!
//! Agent 通过空间共享密钥加入，之后使用独立的控制连接接收 Tunnel Desired State。

use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, State},
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

mod access_keys;
mod accounts;
mod auth;
mod caddy;
mod config;
mod direct;
mod dns_provider;
mod domain_runtime;
mod domains;
mod enrollment;
mod https_ports;
mod identity_runtime;
mod lan_redirect;
mod nodes;
mod reverse_proxy;
mod security;
mod server_settings;
mod service_access;
mod service_icons;
mod traffic;
mod transport;
use enrollment::{agent_enroll, agent_poll, approve_enrollment};

#[derive(Debug, Parser)]
#[command(name = "nexo", version, about = "Nexo 联巢内网穿透服务")]
struct Cli {
    /// 数据目录；配置、数据库和身份持久化于此。
    #[arg(long, default_value = "./data/nexo", global = true)]
    data_dir: PathBuf,
    /// 默认读取数据目录中的 server.toml。
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<CliCommand>,
}
#[derive(Debug, Subcommand)]
enum CliCommand {
    /// 独立 VPS 节点；首次接入从标准输入读取一次性凭证。
    Node {
        #[arg(long)]
        server_url: Option<String>,
        #[arg(long)]
        enroll: bool,
        #[arg(long)]
        enroll_only: bool,
    },
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
    pub(crate) config: Arc<config::Config>,
    pub(crate) db: Arc<Mutex<Connection>>,
    pub(crate) security: Arc<security::Security>,
    pub(crate) data_dir: PathBuf,
    pub(crate) domain_runtime: Arc<domain_runtime::DomainRuntimeManager>,
    pub(crate) control_addr: String,
    pub(crate) udp_endpoint: Option<TunnelDataEndpoint>,
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
#[derive(Debug, Default, Serialize)]
struct Enrollment {
    id: String,
    kind: String,
    tenant_id: String,
    status: String,
    expires_at: i64,
    device_id: Option<String>,
    token: Option<String>,
    device_name: Option<String>,
    os: Option<String>,
    architecture: Option<String>,
    agent_version: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveEnrollment {}
#[derive(Debug, Serialize, Deserialize)]
struct Tunnel {
    node_group_id: Option<String>,
    preferred_node_id: Option<String>,
    node_selection: serde_json::Value,
    node_ids: Vec<String>,
    distribution_mode: String,
    node_statuses: serde_json::Value,
    icon_id: Option<String>,
    #[serde(default)]
    protocol_statuses: std::collections::BTreeMap<String, nexo_protocol::ProtocolStatus>,
    access_mode: String,
    service_mode: String,
    id: String,
    tenant_id: String,
    device_id: Option<String>,
    device_name: Option<String>,
    name: String,
    protocol: String,
    /// 内网回源协议独立于公网协议；TCP 不使用，网页服务默认 HTTP。
    origin_protocol: Option<String>,
    local_address: String,
    local_port: u16,
    public_port: Option<u16>,
    https_port: u16,
    ipv6_direct_enabled: bool,
    direct_status: serde_json::Value,
    hostname: Option<String>,
    enabled: bool,
    lan_redirect_enabled: bool,
    http_redirect_enabled: bool,
    apply_status: String,
    apply_error: Option<String>,
    apply_revision: i64,
    public_address: Option<String>,
    public_domain: Option<String>,
    deletion_pending: bool,
}
#[derive(Deserialize)]
struct TunnelInput {
    node_group_id: Option<String>,
    preferred_node_id: Option<String>,
    node_ids: Option<Vec<String>>,
    distribution_mode: Option<String>,
    /// 省略保留原图标，显式 null 恢复协议默认图标。
    #[serde(default, deserialize_with = "service_icons::deserialize")]
    icon_id: Option<Option<String>>,
    access_mode: Option<String>,
    access_password: Option<String>,
    service_mode: Option<String>,
    device_id: Option<String>,
    name: String,
    protocol: String,
    /// 内网回源协议独立于公网协议；TCP 不使用，网页服务默认 HTTP。
    origin_protocol: Option<String>,
    local_address: String,
    local_port: u16,
    public_port: Option<u16>,
    https_port: Option<u16>,
    ipv6_direct_enabled: Option<bool>,
    hostname: Option<String>,
    enabled: Option<bool>,
    public_domain_id: Option<String>,
    lan_redirect_enabled: Option<bool>,
    http_redirect_enabled: Option<bool>,
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
    // 按进程所在时区输出毫秒及 UTC 偏移；容器使用 TZ，避免排障时误把 UTC 当成本地时间。
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new(
            "%Y-%m-%d %H:%M:%S%.3f %:z".into(),
        ))
        .with_target(false)
        .compact()
        .init();
    let cli = Cli::parse();
    let data_dir = nexo_core::config::absolute(&cli.data_dir)?;
    if let Some(CliCommand::Node {
        server_url,
        enroll,
        enroll_only,
    }) = &cli.command
    {
        return nodes::runtime::run(
            data_dir,
            server_url.clone(),
            *enroll || *enroll_only,
            *enroll_only,
        )
        .await;
    }
    if let Some(CliCommand::Admin {
        command: AdminCommand::Recover { username },
    }) = cli.command
    {
        let (code, username, expires) = auth::create_recovery_code(&data_dir, username.as_deref())?;
        println!("账号：{username}\n一次性恢复码：{code}\n有效期：15 分钟（到期时间戳 {expires}）\n在登录页选择“忘记密码”，输入恢复码和新密码。重新生成会使旧恢复码失效。");
        return Ok(());
    }
    let config_path =
        nexo_core::config::absolute(&cli.config.unwrap_or_else(|| data_dir.join("server.toml")))?;
    let config = Arc::new(config::Config::load(&config_path)?);
    let db_path = data_dir.join("nexo.db");
    fs::create_dir_all(&data_dir)?;
    let is_new = !db_path.try_exists().context("无法检查数据库文件")?;
    let mut connection = Connection::open(&db_path)?;
    initialize_database(&connection, is_new).context("无法读取当前数据库，原文件已保留")?;
    if let Some((username, password)) = auth::ensure_admin(
        &mut connection,
        Some(&config.admin.username),
        Some(&config.admin.password),
    )
    .context("无法初始化管理员账号")?
    {
        // 标准输出由 Docker 收集到容器日志；随机凭据仅在账号创建成功后输出一次。
        println!("管理员账号已创建\n用户名：{username}\n自动生成的密码：{password}\n密码仅在首次创建时显示，请妥善保存；遗失后可使用 nexo admin recover 恢复账号。");
    }
    let identity_path = data_dir.join("transport/identity.json");
    let authority = Arc::new(identity_runtime::AuthorityRuntime::new(
        nexo_tunnel::identity::Authority::load_or_create(&identity_path)?,
        identity_path,
    )?);
    connection.execute("UPDATE devices SET status='offline'", [])?;
    let state = AppState {
        security: Arc::new(security::Security::new(server_settings::load_for_runtime(
            &connection,
            config.http_addr,
        )?)),
        authority,
        tunnel_runtime: Arc::new(transport::Runtime::new(config.public_bind)),
        db: Arc::new(Mutex::new(connection)),
        domain_runtime: Arc::new(domain_runtime::DomainRuntimeManager::new(
            caddy::CaddyRuntimeConfig::new(&data_dir, &config.caddy),
        )),
        data_dir,
        control_addr: config.control_addr.to_string(),
        udp_endpoint: Some(TunnelDataEndpoint {
            address: config.udp_endpoint.clone(),
            server_name: nexo_tunnel::identity::SERVER_NAME.into(),
        }),
        tunnel_endpoint: (!config.tunnel_endpoint.is_empty()).then(|| TunnelDataEndpoint {
            address: config.tunnel_endpoint.clone(),
            server_name: nexo_tunnel::identity::SERVER_NAME.into(),
        }),
        config: config.clone(),
    };
    state
        .tunnel_runtime
        .quotas
        .restore(&state)
        .context("无法恢复用户流量额度，停止启动以避免绕过限制")?;
    let control_listener = TcpListener::bind(&state.control_addr)
        .await
        .context("无法监听 Agent mTLS 控制端口")?;
    let data_listener = TcpListener::bind(config.tunnel_addr)
        .await
        .context("无法监听 Tunnel mTLS 数据端口")?;
    let udp_state = state.clone();
    let udp_task = tokio::spawn(async move {
        if let Err(error) = transport::udp::serve(udp_state).await {
            tracing::error!("UDP 数据监听停止：{error:#}");
        }
    });
    let control_task = tokio::spawn(transport::serve(state.clone(), control_listener, false));
    let data_task = tokio::spawn(transport::serve(state.clone(), data_listener, true));
    let transport_task = tokio::spawn(transport::Runtime::run(state.clone()));
    let identity_task = tokio::spawn(identity_runtime::AuthorityRuntime::run(state.clone()));
    let tunnel_runtime = state.tunnel_runtime.clone();
    let http_addr = config.http_addr;
    let caddy_task = tokio::spawn(domain_runtime::DomainRuntimeManager::run(state.clone()));
    let traffic_task = tokio::spawn(traffic::Collector::run(state.clone()));
    let traffic_state = state.clone();
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
    tunnel_runtime.shutdown().await;
    transport_task.abort();
    identity_task.abort();
    let _ = control_task.await;
    let _ = data_task.await;
    let _ = udp_task.await;
    tunnel_runtime.finish_transfers().await;
    traffic_task.abort();
    let _ = traffic_task.await;
    if let Err(error) = tunnel_runtime.traffic.sample(&traffic_state, true) {
        tracing::error!("退出时保存流量统计失败：{error:#}");
    }
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
    // 网页目录来自启动配置；缺失资源保持 404。
    // 前端使用 hash 路由，缺失文件保持 404，不能用首页掩盖未知 API 或资源错误。
    let web_dir = state.config.web_dir.clone();
    let routes = Router::new()
        .merge(nodes::routes())
        .route("/health", get(health))
        .route("/api/v1/traffic/realtime", get(traffic::own_realtime))
        .route("/api/v1/traffic/history", get(traffic::own_history))
        .route("/api/v1/traffic/usage", get(traffic::own_usage))
        .route("/api/v1/traffic/quota", get(traffic::quota::own_quota))
        .route(
            "/api/v1/admin/traffic/quota",
            get(traffic::quota::admin_quota).put(traffic::quota::update_quota),
        )
        .route("/api/v1/admin/traffic/usage", get(traffic::admin_usage))
        .route("/api/v1/admin/traffic/reset", post(traffic::admin_reset))
        .route(
            "/api/v1/admin/traffic/realtime",
            get(traffic::admin_realtime),
        )
        .route("/api/v1/admin/traffic/history", get(traffic::admin_history))
        .route(
            "/api/v1/admin/server-settings",
            get(server_settings::get).put(server_settings::update),
        )
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
        .route("/api/v1/enrollments", get(list_enrollments))
        .route(
            "/api/v1/enrollments/{id}",
            get(get_enrollment).delete(enrollment::cancel_enrollment),
        )
        .route("/api/v1/enrollments/{id}/approve", post(approve_enrollment))
        .route(
            "/api/v1/agent-access-key",
            get(access_keys::get).post(access_keys::ensure),
        )
        .route("/api/v1/agent-access-key/reset", post(access_keys::reset))
        .route("/api/v1/agent/register", post(access_keys::register))
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
        .route("/api/v1/tunnels/batch/enable", post(batch_enable_tunnels))
        .route("/api/v1/tunnels/batch/disable", post(batch_disable_tunnels))
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
            "/api/v1/devices/{id}/ipv6",
            get(direct::addresses).put(direct::select),
        )
        .route(
            "/api/v1/public-domains/{id}/dns-credential",
            put(dns_provider::set_credential),
        )
        .route(
            "/api/v1/public-domains/{id}/cloudflare-credential",
            put(domains::set_credential),
        )
        .route("/api/v1/public-domain-runtime-events", get(domain_events))
        .fallback_service(
            Router::new()
                .fallback_service(tower_http::services::ServeDir::new(web_dir).precompressed_gzip())
                .layer(middleware::from_fn(static_asset_headers)),
        )
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

/// gzip 与原文件共用 URL，代理缓存必须按请求编码区分；API 仍由安全中间件禁止缓存。
async fn static_asset_headers(request: axum::extract::Request, next: middleware::Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().append(
        axum::http::header::VARY,
        axum::http::HeaderValue::from_static("Accept-Encoding"),
    );
    response
}

fn initialize_database(connection: &Connection, is_new: bool) -> Result<()> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    if is_new {
        let tx = connection.unchecked_transaction()?;
        tx.execute_batch(include_str!("../../../migrations/schema.sql"))
            .context("无法初始化数据库，已回滚")?;
        tx.commit()?;
    }
    // 先验证当前业务结构，再为现有版本添加强制 HTTPS 字段；不转换旧版 mesh 数据。
    https_ports::migrate(connection)?;
    dns_provider::migrate(connection)?;
    direct::migrate(connection)?;
    service_icons::migrate(connection)?;
    nodes::migrate(connection)?;
    server_settings::load(connection).context("无法读取服务器设置")?;
    connection.prepare("SELECT enabled FROM tenants")?;
    connection.prepare("SELECT service_mode,protocol_statuses,access_mode FROM tunnels")?;
    if !connection.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('tunnels') WHERE name='http_redirect_enabled')", [], |r| r.get::<_, bool>(0))? {
        connection.execute("ALTER TABLE tunnels ADD COLUMN http_redirect_enabled INTEGER NOT NULL DEFAULT 0", [])?;
    }
    Ok(())
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
    // 删除与连接注册互斥，事务提交后立即撤销该设备的控制、数据通道和监听。
    state.tunnel_runtime.remove_workspace(|| {
        let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let tx = connection.unchecked_transaction().map_err(db_error)?;
        tx.execute("UPDATE tunnels SET enabled=0,device_id=NULL,apply_status='disabled',apply_revision=apply_revision+1 WHERE device_id=?1 AND tenant_id=?2",params![id,session.tenant_id]).map_err(db_error)?;
        tx.execute("UPDATE agent_registrations SET certificate_pem='' WHERE device_id=?1 AND tenant_id=?2",params![id,session.tenant_id]).map_err(db_error)?;
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
        Ok((vec![id.clone()], Vec::new()))
    }).await?;
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
    let mut q=connection.prepare("SELECT p.id,p.tenant_id,p.status,p.expires_at,p.device_id,p.kind,r.device_name,r.os,r.architecture,r.agent_version FROM pending_enrollments p LEFT JOIN enrollment_requests r ON r.enrollment_id=p.id WHERE p.tenant_id=?1 AND p.status IN ('awaiting_agent','awaiting_approval','approved') AND p.expires_at>unixepoch() ORDER BY p.created_at DESC").map_err(db_error)?;
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
                device_name: row.get(6)?,
                os: row.get(7)?,
                architecture: row.get(8)?,
                agent_version: row.get(9)?,
            })
        })
        .map_err(db_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_error)?;
    Ok(Json(rows))
}

async fn get_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Enrollment>, ApiError> {
    let session = require_session(&state, &headers)?;
    let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let row=connection.query_row("SELECT p.id,p.tenant_id,CASE WHEN p.expires_at<=unixepoch() AND p.status IN ('awaiting_agent','awaiting_approval') THEN 'expired' ELSE p.status END,p.expires_at,p.device_id,p.kind,r.device_name,r.os,r.architecture,r.agent_version FROM pending_enrollments p LEFT JOIN enrollment_requests r ON r.enrollment_id=p.id WHERE p.id=?1 AND p.tenant_id=?2",params![id,session.tenant_id],|row|Ok(Enrollment{id:row.get(0)?,kind:row.get(5)?,tenant_id:row.get(1)?,status:row.get(2)?,expires_at:row.get(3)?,device_id:row.get(4)?,token:None,device_name:row.get(6)?,os:row.get(7)?,architecture:row.get(8)?,agent_version:row.get(9)?})).optional().map_err(db_error)?.ok_or_else(||ApiError::new(StatusCode::NOT_FOUND,"入网请求不存在"))?;
    Ok(Json(row))
}
async fn list_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Tunnel>>, ApiError> {
    let session = require_session(&state, &headers)?;
    let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    query_tunnels(
        &connection,
        &session.tenant_id,
        None,
        &headers,
        state.config.caddy.http_port(),
    )
    .map(Json)
    .map_err(db_error)
}
async fn create_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut input): Json<TunnelInput>,
) -> Result<Json<Tunnel>, ApiError> {
    let session = require_write(&state, &headers)?;
    let access_hash = service_access::password_hash(&mut input).await?;
    let id = Uuid::new_v4().to_string();
    {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let db = db.unchecked_transaction().map_err(db_error)?;
        reverse_proxy::prepare(&db, &session, &id, &mut input)?;
        nodes::services::prepare(&db, &session.tenant_id, &id, &mut input)?;
        prepare_tunnel(&db, &session.tenant_id, &id, &mut input)?;
        https_ports::prepare(&state, &db, &session.tenant_id, &id, &mut input)?;
        direct::prepare(&db, &session.tenant_id, &id, &mut input)?;
        service_access::prepare(
            &db,
            &session.tenant_id,
            &id,
            &mut input,
            access_hash.as_deref(),
        )?;
        db.execute("INSERT INTO tunnels (id,tenant_id,device_id,name,protocol,local_address,local_port,public_port,hostname,enabled,apply_status,apply_revision,public_domain_id,created_at,updated_at,lan_redirect_enabled,origin_protocol,service_mode,http_redirect_enabled) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'checking',1,?11,?12,?12,?13,?14,?15,?16)",params![id,session.tenant_id,input.device_id,input.name.trim(),input.protocol,input.local_address.trim(),input.local_port,input.public_port,input.hostname,input.enabled.unwrap_or(true),input.public_domain_id,unix_now(),input.lan_redirect_enabled.unwrap_or(false),input.origin_protocol,input.service_mode,input.http_redirect_enabled.unwrap_or(false)]).map_err(db_error)?;
        nodes::services::save(&db, &id, &input)?;
        https_ports::save(&db, &id, &input)?;
        db.execute(
            "UPDATE tunnels SET ipv6_direct_enabled=?2 WHERE id=?1",
            params![id, input.ipv6_direct_enabled.unwrap_or(false)],
        )
        .map_err(db_error)?;
        service_icons::save(&db, &session.tenant_id, &id, &input)?;
        service_access::save(&db, &id, &input, access_hash.as_deref())?;
        accounts::audit(&db, &session, "service_created", "service", &id)?;
        db.commit().map_err(db_error)?;
    }
    reverse_proxy::changed(
        &state,
        input.service_mode.as_deref() != Some(reverse_proxy::MODE),
    )
    .await?;
    read_tunnel(&state, &session.tenant_id, &id, &headers).map(Json)
}
async fn update_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut input): Json<TunnelInput>,
) -> Result<Json<Tunnel>, ApiError> {
    let session = require_write(&state, &headers)?;
    let access_hash = service_access::password_hash(&mut input).await?;
    let runtime_changed;
    {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let db = db.unchecked_transaction().map_err(db_error)?;
        if !db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels WHERE id=?1 AND tenant_id=?2 AND deleted_at IS NULL)",params![id,session.tenant_id], |r| r.get::<_,bool>(0)).map_err(db_error)? { return Err(ApiError::new(StatusCode::NOT_FOUND,"服务不存在")); }
        reverse_proxy::prepare(&db, &session, &id, &mut input)?;
        nodes::services::prepare(&db, &session.tenant_id, &id, &mut input)?;
        prepare_tunnel(&db, &session.tenant_id, &id, &mut input)?;
        https_ports::prepare(&state, &db, &session.tenant_id, &id, &mut input)?;
        input.ipv6_direct_enabled = Some(
            input.ipv6_direct_enabled.unwrap_or(
                db.query_row(
                    "SELECT ipv6_direct_enabled FROM tunnels WHERE id=?1",
                    [&id],
                    |row| row.get(0),
                )
                .map_err(db_error)?,
            ),
        );
        service_access::prepare(
            &db,
            &session.tenant_id,
            &id,
            &mut input,
            access_hash.as_deref(),
        )?;
        // 名称和图标不进入 Agent 或 Caddy 配置；原值重复提交也无需重置应用状态。
        let config_unchanged: bool = db.query_row(
            "SELECT device_id IS ?2 AND protocol=?3 AND local_address=?4 AND local_port=?5 AND public_port IS ?6 AND hostname IS ?7 AND enabled=?8 AND public_domain_id IS ?9 AND lan_redirect_enabled=?10 AND origin_protocol IS ?11 AND service_mode=?12 AND http_redirect_enabled=?13 AND https_port=?14 AND ipv6_direct_enabled=?15 AND access_mode=?16 FROM tunnels WHERE id=?1",
            params![id,input.device_id,input.protocol,input.local_address.trim(),input.local_port,input.public_port,input.hostname,input.enabled.unwrap_or(true),input.public_domain_id,input.lan_redirect_enabled.unwrap_or(false),input.origin_protocol,input.service_mode,input.http_redirect_enabled.unwrap_or(false),input.https_port.unwrap_or(443),input.ipv6_direct_enabled.unwrap_or(false),input.access_mode],
            |row| row.get(0),
        ).map_err(db_error)?;
        runtime_changed = !config_unchanged || access_hash.is_some() || db.query_row("SELECT distribution_mode IS NOT ?2 OR preferred_node_id IS NOT ?3 OR node_group_id IS NOT NULLIF(?4,'') FROM tunnels WHERE id=?1",params![id,input.distribution_mode,input.preferred_node_id,input.node_group_id],|r|r.get::<_,bool>(0)).map_err(db_error)? || nodes::services::ids(&db,&id).map_err(db_error)? != *input.node_ids.as_ref().unwrap();
        if runtime_changed {
            direct::prepare(&db, &session.tenant_id, &id, &mut input)?;
        }
        db.execute("UPDATE tunnels SET device_id=?1,name=?2,protocol=?3,local_address=?4,local_port=?5,public_port=?6,hostname=?7,enabled=?8,apply_revision=apply_revision+?17,apply_status=CASE WHEN ?17 THEN 'checking' ELSE apply_status END,updated_at=?9,public_domain_id=?12,lan_redirect_enabled=?13,origin_protocol=?14,service_mode=?15,http_redirect_enabled=?16 WHERE id=?10 AND tenant_id=?11 AND deleted_at IS NULL",params![input.device_id,input.name.trim(),input.protocol,input.local_address.trim(),input.local_port,input.public_port,input.hostname,input.enabled.unwrap_or(true),unix_now(),id,session.tenant_id,input.public_domain_id,input.lan_redirect_enabled.unwrap_or(false),input.origin_protocol,input.service_mode,input.http_redirect_enabled.unwrap_or(false),runtime_changed]).map_err(db_error)?;
        nodes::services::save(&db, &id, &input)?;
        https_ports::save(&db, &id, &input)?;
        db.execute(
            "UPDATE tunnels SET ipv6_direct_enabled=?2 WHERE id=?1",
            params![id, input.ipv6_direct_enabled.unwrap_or(false)],
        )
        .map_err(db_error)?;
        service_icons::save(&db, &session.tenant_id, &id, &input)?;
        service_access::save(&db, &id, &input, access_hash.as_deref())?;
        accounts::audit(&db, &session, "service_updated", "service", &id)?;
        db.commit().map_err(db_error)?;
    }
    if runtime_changed {
        reverse_proxy::changed(
            &state,
            input.service_mode.as_deref() != Some(reverse_proxy::MODE),
        )
        .await?;
    }
    read_tunnel(&state, &session.tenant_id, &id, &headers).map(Json)
}
async fn delete_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_write(&state, &headers)?;
    let is_proxy;
    {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let db = db.unchecked_transaction().map_err(db_error)?;
        is_proxy = reverse_proxy::existing(&db, &session, &id)?;
        let removed = db.execute("UPDATE tunnels SET deleted_at=?1,enabled=0,apply_status='disabled',apply_revision=apply_revision+1 WHERE id=?2 AND tenant_id=?3 AND deleted_at IS NULL",params![unix_now(),id,session.tenant_id]).map_err(db_error)?;
        if removed == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "服务不存在"));
        }
        accounts::audit(&db, &session, "service_deleted", "service", &id)?;
        db.commit().map_err(db_error)?;
    }
    reverse_proxy::changed(&state, !is_proxy).await?;
    Ok(Json(serde_json::json!({"deleted":true,"id":id})))
}
fn read_tunnel(
    state: &AppState,
    tenant: &str,
    id: &str,
    headers: &HeaderMap,
) -> Result<Tunnel, ApiError> {
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    query_tunnels(
        &db,
        tenant,
        Some(id),
        headers,
        state.config.caddy.http_port(),
    )
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
    let is_proxy;
    let changed;
    {
        let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let connection = connection.unchecked_transaction().map_err(db_error)?;
        is_proxy = reverse_proxy::existing(&connection, &session, &id)?;
        changed = connection.execute("UPDATE tunnels SET enabled=?1,apply_status=CASE WHEN ?1=1 THEN 'checking' ELSE 'disabled' END,apply_revision=apply_revision+1,updated_at=?2 WHERE id=?3 AND tenant_id=?4 AND deleted_at IS NULL AND enabled!=?1",params![enabled,unix_now(),id,session.tenant_id]).map_err(db_error)? > 0;
        if changed {
            accounts::audit(&connection, &session, "service_toggled", "service", &id)?;
        }
        connection.commit().map_err(db_error)?;
    }
    if changed {
        reverse_proxy::changed(&state, !is_proxy).await?;
    }
    read_tunnel(&state, &session.tenant_id, &id, &headers).map(Json)
}

#[derive(Debug, Deserialize)]
struct BatchDelete {
    tunnel_ids: Vec<String>,
}
async fn batch_enable_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BatchDelete>,
) -> Result<Json<Vec<Tunnel>>, ApiError> {
    batch_set_tunnels_enabled(state, headers, input, true).await
}
async fn batch_disable_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BatchDelete>,
) -> Result<Json<Vec<Tunnel>>, ApiError> {
    batch_set_tunnels_enabled(state, headers, input, false).await
}
/// 混合选择时先验证每一项的归属及反代权限，再一次提交，避免越权失败前已修改部分服务。
async fn batch_set_tunnels_enabled(
    state: AppState,
    headers: HeaderMap,
    input: BatchDelete,
    enabled: bool,
) -> Result<Json<Vec<Tunnel>>, ApiError> {
    let session = require_write(&state, &headers)?;
    let mut has_tunnels = false;
    let mut any_changed = false;
    {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let tx = db.unchecked_transaction().map_err(db_error)?;
        for id in &input.tunnel_ids {
            let is_proxy = reverse_proxy::existing(&tx, &session, id)?;
            let changed = tx.execute("UPDATE tunnels SET enabled=?1,apply_status=CASE WHEN ?1=1 THEN 'checking' ELSE 'disabled' END,apply_revision=apply_revision+1,updated_at=?2 WHERE id=?3 AND tenant_id=?4 AND deleted_at IS NULL AND enabled!=?1", params![enabled,unix_now(),id,session.tenant_id]).map_err(db_error)? > 0;
            if changed {
                any_changed = true;
                has_tunnels |= !is_proxy;
                accounts::audit(&tx, &session, "service_toggled", "service", id)?;
            }
        }
        tx.commit().map_err(db_error)?;
    }
    if any_changed {
        reverse_proxy::changed(&state, has_tunnels).await?;
    }
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    Ok(Json(
        query_tunnels(
            &db,
            &session.tenant_id,
            None,
            &headers,
            state.config.caddy.http_port(),
        )
        .map_err(db_error)?
        .into_iter()
        .filter(|item| input.tunnel_ids.contains(&item.id))
        .collect(),
    ))
}
async fn batch_delete_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<BatchDelete>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_write(&state, &headers)?;
    let mut has_tunnels = false;
    {
        let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let tx = connection.unchecked_transaction().map_err(db_error)?;
        for id in &input.tunnel_ids {
            has_tunnels |= !reverse_proxy::existing(&tx, &session, id)?;
        }
        for id in &input.tunnel_ids {
            let changed = tx.execute("UPDATE tunnels SET deleted_at=?1,enabled=0,apply_status='disabled',apply_revision=apply_revision+1 WHERE id=?2 AND tenant_id=?3",params![unix_now(),id,session.tenant_id]).map_err(db_error)?;
            if changed > 0 {
                accounts::audit(&tx, &session, "service_deleted", "service", id)?;
            }
        }
        tx.commit().map_err(db_error)?;
    }
    reverse_proxy::changed(&state, has_tunnels).await?;
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
    server_settings::ensure_host_available(&connection, &domain)?;
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
    server_settings::ensure_domain_unused(&tx, &id)?;
    if tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM direct_dns_records WHERE domain_id=?1 AND kind!='A') OR EXISTS(SELECT 1 FROM relay_dns_records WHERE domain_id=?1) OR EXISTS(SELECT 1 FROM relay_dns_originals WHERE domain_id=?1)",
            [&id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(db_error)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "直连 DNS 记录尚未清理，请完成清理后删除域名",
        ));
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
/// 先按租户和域名筛选日志，再截取最近记录，避免繁忙域名挤掉其他域名的事件。
#[derive(Default, Deserialize)]
struct DomainEventsQuery {
    domain_id: Option<String>,
}

async fn domain_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(filter): Query<DomainEventsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_session(&state, &headers)?;
    let connection = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let mut query = connection.prepare("SELECT id,public_domain_id,summary,occurred_at FROM public_domain_runtime_events WHERE tenant_id=?1 AND (?2 IS NULL OR public_domain_id=?2) ORDER BY id DESC LIMIT 100").map_err(db_error)?;
    let events = query.query_map(params![session.tenant_id, filter.domain_id], |row| Ok(serde_json::json!({"id":row.get::<_,i64>(0)?, "domain_id":row.get::<_,Option<String>>(1)?, "summary":row.get::<_,String>(2)?, "occurred_at":row.get::<_,i64>(3)?}))).map_err(db_error)?.collect::<Result<Vec<_>, _>>().map_err(db_error)?;
    Ok(Json(
        serde_json::json!({"events":events,"next_cursor":null}),
    ))
}

fn query_tunnels(
    connection: &Connection,
    tenant: &str,
    only: Option<&str>,
    headers: &HeaderMap,
    http_port: u16,
) -> rusqlite::Result<Vec<Tunnel>> {
    // Host 仅用于当前响应的地址展示，不参与监听或身份校验；不猜测 127.0.0.1 为公网地址。
    let authority = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|host| host.parse::<axum::http::uri::Authority>().ok());
    let sql="SELECT t.id,t.tenant_id,t.device_id,d.name,t.name,t.protocol,t.local_address,t.local_port,t.public_port,t.hostname,t.enabled,t.apply_status,t.apply_error,t.apply_revision,t.public_domain_id,t.deleted_at,p.domain,t.lan_redirect_enabled,CASE WHEN t.protocol IN ('tcp','udp','tcp_udp') THEN NULL ELSE COALESCE(t.origin_protocol,'http') END,t.service_mode,t.access_mode,t.protocol_statuses,t.http_redirect_enabled,t.https_port,t.ipv6_direct_enabled,t.icon_id FROM tunnels t LEFT JOIN devices d ON d.id=t.device_id LEFT JOIN public_domains p ON p.id=t.public_domain_id WHERE t.tenant_id=?1 AND t.deleted_at IS NULL AND (?2 IS NULL OR t.id=?2) ORDER BY t.created_at DESC";
    let mut q = connection.prepare(sql)?;
    let rows = q
        .query_map(params![tenant, only], |row| {
            let port: Option<u16> = row.get(8)?;
            let hostname: Option<String> = row.get(9)?;
            let protocol: String = row.get(5)?;
            let public_domain: Option<String> = row.get(16)?;
            let https_port: u16 = row.get(23)?;
            let public_address = if protocol=="tcp" && hostname.is_some() && public_domain.is_some() {
                port.map(|port|format!("{}.{}:{port}",hostname.as_deref().unwrap(),public_domain.as_deref().unwrap()))
            } else if nexo_tunnel::udp::is_port(&protocol) {
                port.zip(authority.as_ref())
                    .map(|(port, authority)| format!("{}:{port}", authority.host()))
            } else {
                hostname
                    .as_ref()
                    .zip(public_domain.as_ref())
                    .map(|(host, domain)| {
                        if protocol == "http" && http_port != 80 {
                            format!("http://{host}.{domain}:{http_port}")
                        } else {
                            https_ports::url(&protocol, &format!("{host}.{domain}"), https_port)
                        }
                    })
            };
            Ok(Tunnel {
                node_group_id:connection.query_row("SELECT node_group_id FROM tunnels WHERE id=?1",[row.get::<_,String>(0)?],|r|r.get(0))?,
                preferred_node_id:connection.query_row("SELECT preferred_node_id FROM tunnels WHERE id=?1",[row.get::<_,String>(0)?],|r|r.get(0))?,
                node_selection:connection.query_row("SELECT node_id,reason,selected_at FROM relay_selection WHERE service_id=?1",[row.get::<_,String>(0)?],|r|Ok(serde_json::json!({"node_id":r.get::<_,String>(0)?,"reason":r.get::<_,String>(1)?,"selected_at":r.get::<_,i64>(2)?}))).optional()?.unwrap_or(serde_json::Value::Null),
                node_ids: nodes::services::ids(connection,&row.get::<_,String>(0)?)?,
                distribution_mode: connection.query_row("SELECT distribution_mode FROM tunnels WHERE id=?1",[row.get::<_,String>(0)?],|r|r.get(0))?,
                node_statuses: nodes::services::statuses(connection,&row.get::<_,String>(0)?)?,
                icon_id: row.get(25)?,
                protocol_statuses: serde_json::from_str(&row.get::<_, String>(21)?)
                    .unwrap_or_default(),
                access_mode: row.get(20)?,
                service_mode: row.get(19)?,
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                device_id: row.get(2)?,
                device_name: row.get(3)?,
                name: row.get(4)?,
                protocol,
                origin_protocol: row.get(18)?,
                local_address: row.get(6)?,
                local_port: row.get(7)?,
                public_port: port,
                https_port,
                ipv6_direct_enabled: row.get(24)?,
                direct_status: direct::status(connection, &row.get::<_, String>(0)?),
                hostname: hostname.clone(),
                enabled: row.get::<_, i64>(10)? != 0,
                lan_redirect_enabled: row.get(17)?,
                http_redirect_enabled: row.get(22)?,
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
    // 先确定本次有效回源协议，随后重定向验证、持久化与 Agent 下发使用同一份值。
    // 局部更新省略回源字段时保留已有 HTTPS，避免意外降级。
    input.origin_protocol = if nexo_tunnel::udp::is_port(&input.protocol) {
        None
    } else {
        Some(match input.origin_protocol.take() {
            Some(protocol) => protocol,
            None => db.query_row(
                "SELECT origin_protocol FROM tunnels WHERE id=?1 AND tenant_id=?2 AND deleted_at IS NULL",
                params![id, tenant],
                |row| row.get::<_, Option<String>>(0),
            ).optional().map_err(db_error)?.flatten().unwrap_or_else(|| "http".into()),
        })
    };
    lan_redirect::prepare(db, tenant, id, input)?;
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
    let node_scope = serde_json::to_string(
        &input
            .node_ids
            .clone()
            .unwrap_or_else(|| vec!["local".into()]),
    )
    .map_err(db_error)?;
    if nexo_tunnel::udp::is_port(&input.protocol) {
        if input
            .node_ids
            .as_ref()
            .is_none_or(|nodes| nodes.iter().all(|n| n == "local"))
        {
            input.hostname = None;
            input.public_domain_id = None;
        }
        if input.public_port.is_none() {
            input.public_port = db.query_row("SELECT public_port FROM tunnels WHERE id=?1 AND tenant_id=?2 AND protocol IN ('tcp','udp','tcp_udp')",params![id,tenant],|r|r.get::<_,Option<u16>>(0)).optional().map_err(db_error)?.flatten();
        }
        if input.public_port.is_none() {
            let mut used = db.prepare("SELECT public_port FROM tunnels WHERE public_port IS NOT NULL AND deleted_at IS NULL AND id!=?2 AND (protocol=?1 OR protocol='tcp_udp' OR ?1='tcp_udp') AND (EXISTS(SELECT 1 FROM service_nodes sn WHERE sn.service_id=tunnels.id AND sn.node_id IN (SELECT value FROM json_each(?4))) OR (NOT EXISTS(SELECT 1 FROM service_nodes sn WHERE sn.service_id=tunnels.id) AND EXISTS(SELECT 1 FROM json_each(?4) WHERE value='local')))").map_err(db_error)?.query_map(params![input.protocol,id,0,node_scope], |r|r.get::<_,u16>(0)).map_err(db_error)?.collect::<rusqlite::Result<std::collections::HashSet<_>>>().map_err(db_error)?;
            if input.protocol != "udp" {
                used.extend(db.prepare("SELECT https_port FROM tunnels WHERE protocol='https' AND deleted_at IS NULL AND id!=?1 AND (EXISTS(SELECT 1 FROM service_nodes sn WHERE sn.service_id=tunnels.id AND sn.node_id IN (SELECT value FROM json_each(?4))) OR (NOT EXISTS(SELECT 1 FROM service_nodes sn WHERE sn.service_id=tunnels.id) AND EXISTS(SELECT 1 FROM json_each(?4) WHERE value='local')))").map_err(db_error)?.query_map(params![id,0,0,node_scope],|r|r.get::<_,u16>(0)).map_err(db_error)?.collect::<rusqlite::Result<Vec<_>>>().map_err(db_error)?);
            }
            input.public_port = (20000..=29999).find(|port| !used.contains(port));
        }
        if input.public_port.is_none_or(|port| port == 0) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "没有可用公网端口，请指定有效端口",
            ));
        }
        let occupied: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels WHERE public_port=?1 AND id!=?2 AND deleted_at IS NULL AND (protocol=?3 OR protocol='tcp_udp' OR ?3='tcp_udp') AND (EXISTS(SELECT 1 FROM service_nodes sn WHERE sn.service_id=tunnels.id AND sn.node_id IN (SELECT value FROM json_each(?4))) OR (NOT EXISTS(SELECT 1 FROM service_nodes sn WHERE sn.service_id=tunnels.id) AND EXISTS(SELECT 1 FROM json_each(?4) WHERE value='local'))))",params![input.public_port,id,input.protocol,node_scope],|r|r.get(0)).map_err(db_error)?;
        if occupied {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "公网端口已被其他服务使用",
            ));
        }
    }
    if !nexo_tunnel::udp::is_port(&input.protocol)
        || input
            .node_ids
            .as_ref()
            .is_some_and(|nodes| nodes.iter().any(|n| n != "local"))
    {
        if !nexo_tunnel::udp::is_port(&input.protocol) {
            input.public_port = None;
        }
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
        server_settings::ensure_host_available(db, &full)?;
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
    if !matches!(
        input.protocol.as_str(),
        "tcp" | "udp" | "tcp_udp" | "http" | "https"
    ) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "协议必须是 TCP、UDP、TCP+UDP、HTTP 或 HTTPS",
        ));
    }
    if input
        .origin_protocol
        .as_deref()
        .is_some_and(|value| !matches!(value, "http" | "https"))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "内网协议必须是 HTTP 或 HTTPS",
        ));
    }
    if input.local_address.trim().is_empty() || input.local_address.contains(['/', '\\', ' ']) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "内网地址必须是主机名或 IP，不含网址前缀或路径",
        ));
    }
    if input.local_port == 0 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "内网端口无效"));
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
    let mut q=connection.prepare("SELECT id,protocol,local_address,local_port,hostname,origin_protocol,origin_tls_server_name,origin_tls_verification,apply_revision,enabled FROM tunnels WHERE device_id=?1 AND service_mode='tunnel' AND deleted_at IS NULL AND EXISTS(SELECT 1 FROM tenants w WHERE w.id=tunnels.tenant_id AND w.enabled=1)")?;
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
        let tunnels = query_tunnels(&db, "default", None, &headers, 80).unwrap();
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
    fn current_database_reopens_without_rewriting_and_invalid_data_is_preserved() {
        let db = Connection::open_in_memory().unwrap();
        initialize_database(&db, true).unwrap();
        db.execute("UPDATE tenants SET name='保留设置'", [])
            .unwrap();
        initialize_database(&db, false).unwrap();
        assert_eq!(
            db.query_row("SELECT name FROM tenants", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "保留设置"
        );
        db.execute("DROP TABLE server_settings", []).unwrap();
        assert!(initialize_database(&db, false).is_err());
        assert_eq!(
            db.query_row("SELECT name FROM tenants", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "保留设置"
        );
    }

    #[test]
    fn initialization_failure_rolls_back_all_created_tables() {
        let db = Connection::open_in_memory().unwrap();
        db.execute("CREATE TABLE tunnels(marker TEXT)", []).unwrap();
        assert!(initialize_database(&db, true).is_err());
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }

    /// 测试恢复审批时预置当前设备；不保留旧的新增设备审批入口。
    pub(super) async fn recovery_fixture(state: &AppState, headers: &HeaderMap) -> Enrollment {
        let tenant = auth::require_session(state, headers).unwrap().tenant_id;
        let device = Uuid::new_v4().to_string();
        state.db.lock().unwrap().execute("INSERT INTO devices(id,tenant_id,name,created_at,updated_at) VALUES(?1,?2,'原设备',0,0)", params![device,tenant]).unwrap();
        enrollment::create_recovery(State(state.clone()), headers.clone(), Path(device))
            .await
            .unwrap()
            .0
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
            config: Arc::new(config::Config {
                runtime_dir: std::env::temp_dir().join(format!("nexo-test-{}", Uuid::new_v4())),
                ..Default::default()
            }),
            security: Arc::new(security::Security::default()),
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
                    ..caddy::CaddyRuntimeConfig::new(
                        std::env::temp_dir().join(format!("nexo-domain-test-{}", Uuid::new_v4())),
                        &config::Caddy::default(),
                    )
                },
            )),
            control_addr: String::new(),
            udp_endpoint: None,
            tunnel_endpoint: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert("cookie", "nexo_session=domain-test".parse().unwrap());
        headers.insert("x-nexo-csrf", "csrf-test".parse().unwrap());
        (state, headers)
    }

    #[tokio::test]
    async fn static_gzip_negotiation_varies_cache_and_keeps_api_uncached() {
        use std::future::IntoFuture;
        let root = std::env::temp_dir().join(format!("nexo-static-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("entry.js"), b"plain").unwrap();
        // ServeDir 只负责编码协商，不解压；完整 gzip 内容另由浏览器验收核对。
        fs::write(root.join("entry.js.gz"), b"compressed-fixture").unwrap();
        fs::write(root.join("fallback.js"), b"fallback").unwrap();
        let (mut state, _) = domain_fixture();
        Arc::make_mut(&mut state.config).web_dir = root.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(axum::serve(listener, router(state)).into_future());
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for (encoding, body, compressed) in [
            ("identity", "plain", false),
            ("gzip", "compressed-fixture", true),
            ("gzip;q=0", "plain", false),
        ] {
            let response = client
                .get(format!("{url}/entry.js"))
                .header("Accept-Encoding", encoding)
                .send()
                .await
                .unwrap();
            assert_eq!(response.headers()["vary"], "Accept-Encoding");
            assert_eq!(
                response.headers().get("content-encoding").is_some(),
                compressed
            );
            assert_eq!(response.text().await.unwrap(), body);
        }
        let fallback = client
            .get(format!("{url}/fallback.js"))
            .header("Accept-Encoding", "gzip")
            .send()
            .await
            .unwrap();
        assert!(fallback.headers().get("content-encoding").is_none());
        assert_eq!(fallback.text().await.unwrap(), "fallback");
        let api = client
            .get(format!("{url}/api/v1/auth/status"))
            .send()
            .await
            .unwrap();
        assert!(api.headers()["cache-control"]
            .to_str()
            .unwrap()
            .contains("no-store"));
        server.abort();
        let _ = server.await;
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn metadata_and_unchanged_updates_keep_the_applied_revision() {
        for mode in ["tunnel", "reverse_proxy"] {
            let (state, headers) = domain_fixture();
            state.db.lock().unwrap().execute_batch("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES('domain','default','example.com',0,0,0); INSERT INTO domain_settings(domain_id,verification_token,certificate_mode,verified) VALUES('domain','proof','http01',1); INSERT INTO devices(id,tenant_id,name,created_at,updated_at) VALUES('agent','default','Agent',0,0);").unwrap();
            let make_input = |name: &str, icon: Option<&str>, port: u16| {
                serde_json::from_value::<TunnelInput>(serde_json::json!({
                    "service_mode": mode, "device_id": if mode == "tunnel" { Some("agent") } else { None },
                    "name": name, "icon_id": icon, "protocol": "http", "origin_protocol": "http",
                    "local_address": "127.0.0.1", "local_port": port, "hostname": "media", "public_domain_id": "domain"
                })).unwrap()
            };
            let Json(created) = create_tunnel(
                State(state.clone()),
                headers.clone(),
                Json(make_input("媒体", None, 8096)),
            )
            .await
            .unwrap();
            state
                .db
                .lock()
                .unwrap()
                .execute(
                    "UPDATE tunnels SET apply_status='failed',apply_error='原有错误' WHERE id=?1",
                    [&created.id],
                )
                .unwrap();

            let Json(renamed) = update_tunnel(
                State(state.clone()),
                headers.clone(),
                Path(created.id.clone()),
                Json(make_input("新名称", Some("border-radius/emby-1.png"), 8096)),
            )
            .await
            .unwrap();
            assert_eq!(renamed.name, "新名称");
            assert_eq!(renamed.icon_id.as_deref(), Some("border-radius/emby-1.png"));
            assert_eq!(renamed.apply_revision, created.apply_revision);
            assert_eq!(renamed.apply_status, "failed");
            assert_eq!(renamed.apply_error.as_deref(), Some("原有错误"));

            let Json(unchanged) = update_tunnel(
                State(state.clone()),
                headers.clone(),
                Path(created.id.clone()),
                Json(make_input("新名称", Some("border-radius/emby-1.png"), 8096)),
            )
            .await
            .unwrap();
            assert_eq!(unchanged.apply_revision, created.apply_revision);
            assert_eq!(unchanged.apply_status, "failed");

            let Json(reconfigured) = update_tunnel(
                State(state.clone()),
                headers,
                Path(created.id),
                Json(make_input("新名称", Some("border-radius/emby-1.png"), 8097)),
            )
            .await
            .unwrap();
            assert_eq!(reconfigured.apply_revision, created.apply_revision + 1);
        }
    }

    #[tokio::test]
    async fn offline_direct_agent_does_not_block_icon_update() {
        let (state, headers) = domain_fixture();
        state.db.lock().unwrap().execute_batch("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES('domain','default','example.com',0,0,0); INSERT INTO domain_settings(domain_id,verification_token,certificate_mode,verified) VALUES('domain','proof','http01',1); INSERT INTO devices(id,tenant_id,name,created_at,updated_at) VALUES('agent','default','Agent',0,0);").unwrap();
        let input = |icon: Option<&str>, protocol: &str| {
            serde_json::from_value::<TunnelInput>(serde_json::json!({"service_mode":"tunnel","device_id":"agent","name":"媒体","icon_id":icon,"protocol":protocol,"origin_protocol":"http","local_address":"127.0.0.1","local_port":8096,"hostname":"media","public_domain_id":"domain"})).unwrap()
        };
        let Json(created) = create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(input(None, "http")),
        )
        .await
        .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE tunnels SET protocol='https',ipv6_direct_enabled=1 WHERE id=?1",
                [&created.id],
            )
            .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE public_domains SET https_enabled=1 WHERE id='domain'",
                [],
            )
            .unwrap();
        let mut changed = input(Some("border-radius/emby-1.png"), "https");
        changed.ipv6_direct_enabled = Some(true);
        let Json(updated) = update_tunnel(State(state), headers, Path(created.id), Json(changed))
            .await
            .unwrap();
        assert_eq!(updated.icon_id.as_deref(), Some("border-radius/emby-1.png"));
        assert_eq!(updated.apply_revision, created.apply_revision);
    }

    #[tokio::test]
    async fn repeated_enable_and_batch_disable_do_not_reapply_services() {
        let (state, headers) = domain_fixture();
        state.db.lock().unwrap().execute_batch("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES('domain','default','example.com',0,0,0); INSERT INTO domain_settings(domain_id,verification_token,certificate_mode,verified) VALUES('domain','proof','http01',1);").unwrap();
        let input = || {
            serde_json::from_value::<TunnelInput>(serde_json::json!({"service_mode":"reverse_proxy","name":"媒体","protocol":"http","origin_protocol":"http","local_address":"127.0.0.1","local_port":8096,"hostname":"media","public_domain_id":"domain"})).unwrap()
        };
        let Json(created) = create_tunnel(State(state.clone()), headers.clone(), Json(input()))
            .await
            .unwrap();
        let Json(enabled) = enable_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
        )
        .await
        .unwrap();
        assert_eq!(enabled.apply_revision, created.apply_revision);
        let Json(disabled) = disable_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
        )
        .await
        .unwrap();
        assert_eq!(disabled.apply_revision, created.apply_revision + 1);
        let Json(items) = batch_disable_tunnels(
            State(state.clone()),
            headers,
            Json(BatchDelete {
                tunnel_ids: vec![created.id],
            }),
        )
        .await
        .unwrap();
        assert_eq!(items[0].apply_revision, disabled.apply_revision);
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
            domain_events(
                State(state.clone()),
                HeaderMap::new(),
                Query(DomainEventsQuery::default())
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::UNAUTHORIZED
        );
        let events = domain_events(State(state), headers, Query(DomainEventsQuery::default()))
            .await
            .unwrap()
            .0;
        assert_eq!(events["events"].as_array().unwrap().len(), 1);
        assert_eq!(events["events"][0]["summary"], "配置已加载");
    }
    #[tokio::test]
    async fn domain_event_filter_precedes_limit_and_never_crosses_tenants() {
        let (state, headers) = domain_fixture();
        {
            let db = state.db.lock().unwrap();
            db.execute_batch(
                "INSERT INTO tenants(id,name,created_at) VALUES ('other','其他空间',0);",
            )
            .unwrap();
            db.execute("INSERT INTO public_domain_runtime_events(tenant_id,public_domain_id,summary,occurred_at) VALUES ('default','target','目标事件',1)", []).unwrap();
            for index in 0..105 {
                db.execute("INSERT INTO public_domain_runtime_events(tenant_id,public_domain_id,summary,occurred_at) VALUES ('default','busy','其他域名',?1)", [index]).unwrap();
            }
            db.execute("INSERT INTO public_domain_runtime_events(tenant_id,public_domain_id,summary,occurred_at) VALUES ('other','target','其他空间',2)", []).unwrap();
        }
        let events = domain_events(
            State(state.clone()),
            headers.clone(),
            Query(DomainEventsQuery {
                domain_id: Some("target".into()),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(events["events"].as_array().unwrap().len(), 1);
        assert_eq!(events["events"][0]["summary"], "目标事件");
        let all = domain_events(
            State(state.clone()),
            headers.clone(),
            Query(DomainEventsQuery::default()),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(all["events"].as_array().unwrap().len(), 100);
        let unknown = domain_events(
            State(state),
            headers,
            Query(DomainEventsQuery {
                domain_id: Some("missing".into()),
            }),
        )
        .await
        .unwrap()
        .0;
        assert!(unknown["events"].as_array().unwrap().is_empty());
    }
}
