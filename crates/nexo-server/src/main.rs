//! Nexo Server 启动入口。
//!
//! 当前阶段提供健康检查、概览和设备入网身份 API，并建立 Nexo SQLite 数据库。

use std::{
    collections::HashMap,
    env, fs,
    io::BufReader,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

mod headscale;
mod policy;

use anyhow::{Context, Result};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ipnet::IpNet;
use nexo_core::{
    validate_published_network, ApplyStatus, CapabilityState, DeviceCapability, EnrollmentStatus,
    EnrollmentToken, GatewayCapabilityReason, GatewayCapabilityReport,
};
use nexo_headscale_adapter::{
    HeadscaleAdapter, HeadscaleControlPlane, HeadscaleHttpAdapter, HeadscaleNode,
};
#[cfg(test)]
use nexo_protocol::GatewayRouteApplyResult;
use nexo_protocol::{
    AgentControlMessage, AgentEnrollmentPollRequest, AgentEnrollmentPollResponse,
    AgentEnrollmentRequest, AgentEnrollmentResponse, GatewayApplyAck, GatewayDesiredRoute,
    GatewayDesiredState, GatewayRouteApplyReport, MeshEnrollmentOffer, MeshIdentityReport,
    ServerControlMessage,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio_rustls::{rustls, TlsAcceptor};
use tower_http::services::ServeDir;
use uuid::Uuid;

use headscale::{ApiKeyManager, HeadscaleRuntimeConfig, HeadscaleSupervisor};

const INITIAL_MIGRATION: &str = include_str!("../../../migrations/0001_initial.sql");
const ENROLLMENT_MIGRATION: &str = include_str!("../../../migrations/0002_device_enrollment.sql");
const IDENTITY_MIGRATION: &str = include_str!("../../../migrations/0003_server_identity.sql");
const CONTROL_IDENTITY_MIGRATION: &str =
    include_str!("../../../migrations/0004_control_identity.sql");
const GATEWAY_REPORT_MIGRATION: &str =
    include_str!("../../../migrations/0005_gateway_capability_reports.sql");
const GATEWAY_STATE_MIGRATION: &str =
    include_str!("../../../migrations/0006_gateway_desired_state.sql");
const MESH_IDENTITY_MIGRATION: &str = include_str!("../../../migrations/0007_mesh_identity.sql");
const GATEWAY_ROUTE_APPLY_MIGRATION: &str =
    include_str!("../../../migrations/0008_gateway_route_applies.sql");

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    /// Headscale 适配器通过稳定异步 trait 注入，测试可替换为 Pending 实现。
    headscale: Arc<dyn HeadscaleControlPlane>,
    /// 控制连接需要短暂传递 Pre-auth Key；重启时会从 Headscale API 重新发现。
    mesh_offers: Arc<tokio::sync::Mutex<HashMap<String, MeshEnrollmentOffer>>>,
    /// 串行化组网入网的“查找旧 Key → 创建新 Key → 发布邀请”序列。
    ///
    /// 审批回调和设备首次心跳可能同时触发入网；如果两条路径并发创建
    /// Pre-auth Key，较早的 ACK 可能在数据库中被后一个尝试标记为 revoked，
    /// 进而造成重复 Node 或无法绑定。第一阶段设备数量有限，使用一个小范围
    /// 的全局锁即可消除这条竞态，后续可按设备拆分为细粒度锁。
    mesh_enrollment_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Debug, Serialize)]
struct OverviewResponse {
    devices: i64,
    running_tunnels: i64,
    mesh_devices: i64,
    current_connections: i64,
}

/// 管理界面使用的设备摘要；不返回设备私钥、证书或其他敏感材料。
#[derive(Debug, Serialize)]
struct DeviceResponse {
    id: String,
    tenant_id: String,
    site_id: Option<String>,
    name: String,
    os: Option<String>,
    architecture: Option<String>,
    agent_version: Option<String>,
    status: String,
    capabilities: Vec<DeviceCapability>,
    gateway_report: Option<GatewayCapabilityReport>,
    /// 组网对用户只显示加入进度，不暴露 Headscale Node/API Key。
    mesh_status: String,
    mesh_address: Option<String>,
    last_seen_at: Option<String>,
}

/// 站点目录摘要；Web 只需要用户可读名称和租户归属，不暴露站点内部关系。
#[derive(Debug, Serialize)]
struct SiteResponse {
    id: String,
    tenant_id: String,
    name: String,
}

/// 管理端创建一次性设备入网凭证的请求。
#[derive(Debug, Deserialize)]
struct CreateEnrollmentRequest {
    tenant_id: String,
    site_id: Option<String>,
    ttl_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CreateSiteRequest {
    tenant_id: String,
    name: String,
}

/// 创建凭证的响应。token 仅在本次响应返回，服务端不保存明文。
#[derive(Debug, Serialize)]
struct CreateEnrollmentResponse {
    enrollment_id: String,
    token: String,
    expires_at: i64,
}

/// 可安全展示给管理界面的入网请求状态。
#[derive(Debug, Serialize)]
struct EnrollmentStatusResponse {
    enrollment_id: String,
    status: EnrollmentStatus,
    expires_at: i64,
    device_id: Option<String>,
}

/// 管理界面的入网请求列表项；不返回一次性 token、CSR 或其他敏感材料。
#[derive(Debug, Serialize)]
struct EnrollmentListItem {
    enrollment_id: String,
    status: EnrollmentStatus,
    tenant_id: String,
    site_id: Option<String>,
    device_name: Option<String>,
    os: Option<String>,
    architecture: Option<String>,
    agent_version: Option<String>,
    expires_at: i64,
    device_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct MeshStatusResponse {
    /// 仅返回产品状态：normal/starting/abnormal/version_incompatible。
    status: headscale::MeshComponentStatus,
    message: String,
}

#[derive(Debug, Serialize)]
struct RecheckResponse {
    accepted: bool,
    message: String,
}

/// 身份错配后的显式恢复请求；必须同时提供当前预期 Node ID 和确认标志。
///
/// 该接口不会根据 Agent 当前上报的身份自动改绑，避免被替换的设备静默接管
/// 原有网关路由。恢复完成后仍需重新走一次短时 Pre-auth Key 入网流程。
#[derive(Debug, Deserialize)]
struct RecoverMeshIdentityRequest {
    expected_old_node_id: String,
    confirm: bool,
}

#[derive(Debug, Serialize)]
struct RecoverMeshIdentityResponse {
    accepted: bool,
    device_id: String,
    old_node_id: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct RouteConfirmationResponse {
    site_id: String,
    confirmed_at: String,
}

/// 管理员明确选择要共享的本地网络。
#[derive(Debug, Deserialize)]
struct CreateSiteNetworkRequest {
    tenant_id: String,
    site_id: String,
    name: String,
    publisher_device_id: String,
    interface_id: String,
    prefix: String,
}

/// 共享本地网络的 Desired / Applied 状态。
#[derive(Debug, Serialize)]
struct SiteNetworkResponse {
    id: String,
    tenant_id: String,
    site_id: String,
    site_name: String,
    name: String,
    publisher_device_id: String,
    publisher_device_name: String,
    interface_id: String,
    /// Agent 在本地局域网上的地址；路由器应把远端网段指向该地址。
    gateway_address: Option<String>,
    desired_prefix: String,
    applied_prefix: Option<String>,
    desired_revision: i64,
    enabled: bool,
    apply_status: ApplyStatus,
    apply_error: Option<String>,
    /// 独立于 Desired / Applied 的网关健康状态，避免“设备在线”被误认为路由已生效。
    health_status: GatewayHealthStatus,
    health_error: Option<String>,
}

/// 管理员创建两个站点之间的双向互联期望状态。
#[derive(Debug, Deserialize)]
struct CreateSiteLinkRequest {
    tenant_id: String,
    left_site_id: String,
    left_network_id: String,
    right_site_id: String,
    right_network_id: String,
}

/// 站点互联的应用状态和两侧网段。
#[derive(Debug, Serialize)]
struct SiteLinkResponse {
    id: String,
    tenant_id: String,
    left_site_id: String,
    right_site_id: String,
    left_site_name: String,
    right_site_name: String,
    left_network_id: String,
    right_network_id: String,
    left_network_prefix: String,
    right_network_prefix: String,
    left_gateway_address: Option<String>,
    right_gateway_address: Option<String>,
    static_routes: Vec<StaticRouteGuide>,
    route_confirmations: Vec<RouteConfirmationResponse>,
    enabled: bool,
    apply_status: ApplyStatus,
    apply_error: Option<String>,
    /// 两端网关和站点互联路由的综合健康状态。
    health_status: GatewayHealthStatus,
    health_error: Option<String>,
}

/// 网关健康状态只描述当前链路是否具备可用条件；具体配置版本仍由
/// `apply_status` 和 `desired_revision` 表达，两者不能互相替代。
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GatewayHealthStatus {
    Ready,
    Degraded,
    Failed,
    Disabled,
}

/// 给用户路由器配置静态路由时需要填写的最小信息。
///
/// Nexo 只生成引导，不会登录或修改用户路由器；`next_hop` 缺失时表示旧版
/// Agent 尚未上报本地地址，UI 必须要求用户先确认设备的固定局域网地址。
#[derive(Debug, Serialize, PartialEq, Eq)]
struct StaticRouteGuide {
    router_site_id: String,
    destination_site_id: String,
    router_site_name: String,
    destination_site_name: String,
    destination_prefix: String,
    next_hop: Option<String>,
    /// 用户在该站点路由器上完成配置后的持久化确认。
    router_confirmed: bool,
}

/// 服务端本地 CA 材料。私钥只在服务端内存中短暂使用，绝不通过 API 返回。
struct CaMaterial {
    certificate_pem: String,
    private_key_pem: String,
}

/// mTLS 控制通道的服务端证书材料。私钥只用于内存中的 TLS 配置。
struct ControlIdentityMaterial {
    certificate_pem: String,
    private_key_pem: String,
}

/// 已签发的设备身份，只包含可以交给 Agent 的公钥证书及其摘要。
struct IssuedIdentity {
    certificate_pem: String,
    fingerprint: String,
    expires_at: i64,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("nexo_server=info")
        .init();

    let db_path = database_path()?;
    let connection = Connection::open(&db_path)
        .with_context(|| format!("无法打开 Nexo 数据库：{}", db_path.display()))?;
    connection
        .execute_batch(INITIAL_MIGRATION)
        .context("无法初始化 Nexo 数据库表结构")?;
    connection
        .execute_batch(ENROLLMENT_MIGRATION)
        .context("无法初始化设备入网数据表")?;
    connection
        .execute_batch(IDENTITY_MIGRATION)
        .context("无法初始化服务端身份数据表")?;
    connection
        .execute_batch(CONTROL_IDENTITY_MIGRATION)
        .context("无法初始化控制通道身份数据表")?;
    connection
        .execute_batch(GATEWAY_REPORT_MIGRATION)
        .context("无法初始化网关能力报告数据表")?;
    connection
        .execute_batch(GATEWAY_STATE_MIGRATION)
        .context("无法初始化网关期望状态数据表")?;
    connection
        .execute_batch(MESH_IDENTITY_MIGRATION)
        .context("无法初始化组网身份数据表")?;
    connection
        .execute_batch(GATEWAY_ROUTE_APPLY_MIGRATION)
        .context("无法初始化逐路由应用状态表")?;
    ensure_mesh_identity_online_column(&connection).context("无法初始化组网在线状态字段")?;
    ensure_server_ca(&connection).context("无法初始化服务端设备身份 CA")?;
    ensure_server_control_identity(&connection).context("无法初始化控制通道服务端证书")?;
    let control_tls = build_control_tls_config(&connection).context("无法构建 mTLS 控制通道")?;

    // 官方阶段一镜像通过 NEXO_HEADSCALE_BIN 启用内置 Headscale；本地开发没有
    // 该变量时安全降级为 Pending，不会尝试启动宿主机上未知的 Headscale。
    let data_dir = db_path
        .parent()
        .map(PathBuf::from)
        .context("Nexo 数据库路径缺少父目录")?;
    let headscale_runtime = Arc::new(HeadscaleSupervisor::new(HeadscaleRuntimeConfig::from_env(
        data_dir,
    )));
    let mut api_key_rotation_task: Option<tokio::task::JoinHandle<()>> = None;
    let headscale: Arc<dyn HeadscaleControlPlane> = if headscale_runtime.config().enabled {
        if let Err(error) = headscale_runtime.clone().start().await {
            let _ = headscale_runtime.shutdown().await;
            return Err(error).context("无法启动内置 Headscale");
        }
        if let Err(error) = headscale_runtime
            .wait_until_healthy(std::time::Duration::from_secs(30))
            .await
        {
            let _ = headscale_runtime.shutdown().await;
            return Err(error).context("内置 Headscale 健康检查失败");
        }
        let manager = ApiKeyManager::with_config(
            &headscale_runtime.config().binary,
            headscale_runtime.config().secret_path(),
            headscale_runtime.config().config_path(),
        );
        let (api_key, _) = match manager
            .bootstrap_or_rotate_checked(headscale::unix_now(), &headscale_runtime.config().api_url)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                let _ = headscale_runtime.shutdown().await;
                return Err(error).context("无法初始化 Headscale API Key");
            }
        };
        let adapter = Arc::new(HeadscaleHttpAdapter::new(
            headscale_runtime.config().api_url.clone(),
            api_key,
        )?);
        api_key_rotation_task = Some(spawn_api_key_rotation(
            manager,
            adapter.clone(),
            headscale_runtime.config().api_url.clone(),
        ));
        adapter
    } else if let Ok(api_key) = env::var("NEXO_HEADSCALE_API_KEY") {
        if api_key.trim().is_empty() {
            Arc::new(HeadscaleAdapter)
        } else {
            Arc::new(HeadscaleHttpAdapter::new(
                HeadscaleRuntimeConfig::from_env(db_path.parent().unwrap()).api_url,
                api_key,
            )?)
        }
    } else {
        Arc::new(HeadscaleAdapter)
    };

    let state = AppState {
        db: Arc::new(Mutex::new(connection)),
        headscale,
        mesh_offers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        mesh_enrollment_lock: Arc::new(tokio::sync::Mutex::new(())),
    };
    if let Err(error) = recover_mesh_offers(&state).await {
        tracing::warn!("重启后恢复组网入网邀请失败，将在设备下次连接时重试：{error:#}");
    }
    // 重新启动后不依赖内存任务队列：周期性从 Desired State、稳定身份和
    // Headscale 当前节点状态重新协调，覆盖 Headscale/Server 单独重启场景。
    let mesh_reconciliation_task = spawn_mesh_reconciliation(state.clone());
    schedule_policy_reconcile(&state);
    let control_address: SocketAddr = env::var("NEXO_CONTROL_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9890".to_owned())
        .parse()
        .context("NEXO_CONTROL_ADDR 不是有效的监听地址")?;
    let control_listener = tokio::net::TcpListener::bind(control_address)
        .await
        .with_context(|| format!("无法监听 Nexo mTLS 控制通道：{control_address}"))?;
    tracing::info!("Nexo mTLS 控制通道监听于 {control_address}");
    let control_state = state.clone();
    tokio::spawn(async move {
        if let Err(error) =
            serve_control_listener(control_listener, control_tls, control_state).await
        {
            tracing::error!("Nexo mTLS 控制通道异常退出：{error:#}");
        }
    });
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/sites", get(list_sites).post(create_site))
        .route(
            "/api/v1/enrollments",
            get(list_enrollments).post(create_enrollment),
        )
        .route("/api/v1/enrollments/{id}", get(get_enrollment))
        .route("/api/v1/enrollments/{id}/approve", post(approve_enrollment))
        .route("/api/v1/agent/enroll", post(enroll_agent))
        .route(
            "/api/v1/agent/enroll/{id}/poll",
            post(poll_agent_enrollment),
        )
        .route("/api/v1/mesh/status", get(mesh_status))
        .route(
            "/api/v1/devices/{id}/mesh/recover",
            post(recover_mesh_identity),
        )
        .route(
            "/api/v1/site-networks",
            get(list_site_networks).post(create_site_network),
        )
        .route("/api/v1/site-networks/{id}", get(get_site_network))
        .route(
            "/api/v1/site-networks/{id}/disable",
            post(disable_site_network),
        )
        .route(
            "/api/v1/site-networks/{id}/enable",
            post(enable_site_network),
        )
        .route(
            "/api/v1/site-links",
            get(list_site_links).post(create_site_link),
        )
        .route("/api/v1/site-links/{id}", get(get_site_link))
        .route("/api/v1/site-links/{id}/disable", post(disable_site_link))
        .route("/api/v1/site-links/{id}/enable", post(enable_site_link))
        .route(
            "/api/v1/site-links/{id}/router-confirmations/{site_id}",
            post(confirm_site_link_router),
        )
        .route("/api/v1/site-links/{id}/recheck", post(recheck_site_link))
        .fallback_service(ServeDir::new(
            env::var("NEXO_WEB_DIR").unwrap_or_else(|_| "./web/dist".to_owned()),
        ))
        .with_state(state);

    let address: SocketAddr = env::var("NEXO_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9888".to_owned())
        .parse()
        .context("NEXO_HTTP_ADDR 不是有效的监听地址")?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("无法监听 Nexo API 地址：{address}"))?;
    tracing::info!("Nexo Server 已启动，API 监听于 {address}");
    let shutdown_runtime = headscale_runtime.clone();
    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(async {
            if let Err(error) = wait_for_shutdown_signal().await {
                tracing::warn!("等待 Nexo Server 退出信号失败：{error}");
            }
        })
        .await
        .context("Nexo API 服务异常退出");
    if let Some(task) = api_key_rotation_task {
        task.abort();
        let _ = task.await;
    }
    mesh_reconciliation_task.abort();
    let _ = mesh_reconciliation_task.await;
    shutdown_runtime.shutdown().await?;
    serve_result?;
    Ok(())
}

/// 同时响应本地 Ctrl-C 和 Docker 常用的 SIGTERM，确保关闭前能回收内置
/// Headscale 子进程；Windows 没有统一的 SIGTERM 语义时沿用 Ctrl-C。
async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).context("无法监听 SIGTERM")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("等待 Ctrl-C 失败"),
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("等待 Ctrl-C 失败")
    }
}

fn database_path() -> Result<PathBuf> {
    let root = env::var("NEXO_DATA_DIR").unwrap_or_else(|_| "./data/nexo".to_owned());
    let root = PathBuf::from(root);
    fs::create_dir_all(&root)
        .with_context(|| format!("无法创建 Nexo 数据目录：{}", root.display()))?;
    Ok(root.join("nexo.db"))
}

/// 兼容已经创建过 `mesh_identities` 的旧数据库，为组网身份补充在线状态列。
///
/// SQLite 的 `ALTER TABLE ... ADD COLUMN` 没有跨版本稳定的 `IF NOT EXISTS`
/// 语法，因此先通过 `PRAGMA table_info` 检查，保证 Server 每次重启都幂等。
fn ensure_mesh_identity_online_column(connection: &Connection) -> Result<()> {
    let has_column = {
        let mut statement = connection.prepare("PRAGMA table_info(mesh_identities)")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|name| name == "online")
    };
    if !has_column {
        connection.execute(
            "ALTER TABLE mesh_identities ADD COLUMN online INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    connection.execute(
        "INSERT OR IGNORE INTO schema_migrations (version) VALUES (9)",
        [],
    )?;
    Ok(())
}

/// 在 Server 持续运行期间定期检查并轮换 Headscale API Key。
///
/// 轮换器只拿到内存中的适配器句柄；新 Key 通过健康 API 自检后才由
/// `ApiKeyManager` 原子切换 Secret，适配器随后热切换，旧 Key 再被吊销。
fn spawn_api_key_rotation(
    manager: ApiKeyManager,
    adapter: Arc<HeadscaleHttpAdapter>,
    api_url: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(6 * 60 * 60)).await;
            match manager
                .bootstrap_or_rotate_checked(headscale::unix_now(), &api_url)
                .await
            {
                Ok((api_key, _)) => {
                    if let Err(error) = adapter.replace_api_key(api_key) {
                        tracing::error!("Headscale API Key 热切换失败：{error:#}");
                    } else {
                        tracing::info!("Headscale API Key 检查完成");
                    }
                }
                Err(error) => {
                    tracing::warn!("Headscale API Key 轮换失败，将在下一周期重试：{error:#}");
                }
            }
        }
    })
}

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        service: "nexo-server",
    })
}

async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OverviewResponse>, ApiError> {
    require_admin(&headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let devices = count(&connection, "SELECT COUNT(*) FROM devices")
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备数量"))?;
    let running_tunnels = count(
        &connection,
        "SELECT COUNT(*) FROM tunnels WHERE enabled = 1 AND apply_status = 'ready'",
    )
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取隧道数量"))?;
    let mesh_devices = count(
        &connection,
        "SELECT COUNT(*) FROM devices WHERE capabilities_json LIKE '%mesh%'",
    )
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取组网设备数量"))?;
    let current_connections = count(
        &connection,
        "SELECT COUNT(*) FROM devices WHERE status = 'online'",
    )
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取在线设备数量"))?;
    Ok(Json(OverviewResponse {
        devices,
        running_tunnels,
        mesh_devices,
        current_connections,
    }))
}

/// 返回设备状态和最近一次网关能力报告，供 Web 展示统一的设备模型。
async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceResponse>>, ApiError> {
    require_admin(&headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT d.id, d.tenant_id, d.site_id, d.name, d.os, d.architecture,
                    d.agent_version, d.status, d.capabilities_json, r.report_json,
                    m.state, m.tailscale_ipv4, m.online, d.last_seen_at,
                    (SELECT a.state FROM mesh_enrollment_attempts a
                     WHERE a.nexo_device_id = d.id
                     ORDER BY a.created_at DESC LIMIT 1)
             FROM devices d
             LEFT JOIN device_capability_reports r ON r.device_id = d.id
             LEFT JOIN mesh_identities m ON m.nexo_device_id = d.id
             ORDER BY d.updated_at DESC, d.name ASC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备列表"))?;
    let rows = statement
        .query_map([], |row| {
            let capabilities_json: String = row.get(8)?;
            let report_json: Option<String> = row.get(9)?;
            let mesh_state: Option<String> = row.get(10)?;
            let mesh_online = row.get::<_, Option<i64>>(12)?.unwrap_or_default() != 0;
            let enrollment_state: Option<String> = row.get(14)?;
            let device_status: String = row.get(7)?;
            Ok((DeviceResponse {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                site_id: row.get(2)?,
                name: row.get(3)?,
                os: row.get(4)?,
                architecture: row.get(5)?,
                agent_version: row.get(6)?,
                status: device_status.clone(),
                capabilities: serde_json::from_str(&capabilities_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        8,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                gateway_report: report_json
                    .map(|json| {
                        serde_json::from_str(&json).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                9,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })
                    })
                    .transpose()?,
                mesh_status: match (
                    mesh_state.as_deref().or(enrollment_state.as_deref()),
                    mesh_online && device_status == "online",
                ) {
                    (Some("ready"), true) => "connected".to_owned(),
                    (Some("ready"), false) => "mesh_offline".to_owned(),
                    (Some("mesh_identity_mismatch"), _) => "needs_recovery".to_owned(),
                    (Some("failed"), _) => "failed".to_owned(),
                    (Some("disabled"), _) => "disabled".to_owned(),
                    (Some("enrolling") | Some("issued"), _) => "joining".to_owned(),
                    _ => "not_joined".to_owned(),
                },
                mesh_address: row.get(11)?,
                last_seen_at: row.get(13)?,
            },))
        })
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备列表"))?;
    rows.map(|row| {
        row.map(|(device,)| device).map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "设备数据格式无效，请让 Agent 重新连接",
            )
        })
    })
    .collect::<Result<Vec<_>, _>>()
    .map(Json)
}

/// 返回站点目录，供 Web 创建共享网络和站点互联时选择站点。
async fn list_sites(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SiteResponse>>, ApiError> {
    require_admin(&headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT id, tenant_id, name
             FROM sites
             ORDER BY name ASC, id ASC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点列表"))?;
    let rows = statement
        .query_map([], |row| {
            Ok(SiteResponse {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                name: row.get(2)?,
            })
        })
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点列表"))?;
    rows.map(|row| {
        row.map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "站点数据格式无效"))
    })
    .collect::<Result<Vec<_>, _>>()
    .map(Json)
}

/// 创建一个用户可见站点；Site Gateway 和共享网络都必须归属于站点。
async fn create_site(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSiteRequest>,
) -> Result<Json<SiteResponse>, ApiError> {
    require_admin(&headers)?;
    let tenant_id = request.tenant_id.trim().to_owned();
    let name = request.name.trim().to_owned();
    if tenant_id.is_empty() || name.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "tenant_id 和 name 不能为空",
        ));
    }
    let id = Uuid::new_v4().to_string();
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let tenant_exists: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM tenants WHERE id = ?1",
            [&tenant_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查租户"))?;
    if tenant_exists == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "租户不存在"));
    }
    connection
        .execute(
            "INSERT INTO sites (id, tenant_id, name) VALUES (?1, ?2, ?3)",
            rusqlite::params![id, tenant_id, name],
        )
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "站点名称或站点数据已存在"))?;
    Ok(Json(SiteResponse {
        id,
        tenant_id,
        name,
    }))
}

fn count(connection: &Connection, query: &str) -> Result<i64, StatusCode> {
    connection
        .query_row(query, [], |row| row.get(0))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// 当前 Unix 秒时间，集中封装便于后续替换为可测试时钟。
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// 首次启动时生成并持久化 Nexo 的设备身份 CA；后续启动只读取已有材料。
///
/// CA 私钥属于服务端内部密钥，保存在 Nexo 数据库中但永不进入 API 响应、日志或
/// Web UI。生产部署仍应保护整个数据目录，并限制数据库文件的读取权限。
fn ensure_server_ca(connection: &Connection) -> Result<()> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM server_identity WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    if count > 0 {
        return Ok(());
    }

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Nexo Device CA");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(3650);

    let signing_key = KeyPair::generate()?;
    let certificate = params.self_signed(&signing_key)?;
    connection.execute(
        "INSERT INTO server_identity (id, ca_certificate_pem, ca_private_key_pem)
         VALUES (1, ?1, ?2)",
        rusqlite::params![certificate.pem(), signing_key.serialize_pem()],
    )?;
    Ok(())
}

/// 从数据库读取 CA 材料，供一次设备审批事务签发证书使用。
fn load_server_ca(connection: &Connection) -> Result<CaMaterial> {
    connection
        .query_row(
            "SELECT ca_certificate_pem, ca_private_key_pem
             FROM server_identity WHERE id = 1",
            [],
            |row| {
                Ok(CaMaterial {
                    certificate_pem: row.get(0)?,
                    private_key_pem: row.get(1)?,
                })
            },
        )
        .context("服务端身份 CA 尚未初始化")
}

/// 根据 Agent 自己生成并签名的 CSR 创建设备客户端证书。
///
/// 服务端只接收 CSR 中的公钥，私钥始终留在 Agent；证书用途固定为 TLS 客户端，
/// 不采纳 Agent 自行请求的 CA、服务端用途等危险扩展。
fn issue_device_identity(
    ca: &CaMaterial,
    csr_pem: &str,
    device_id: &str,
) -> Result<IssuedIdentity> {
    let csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .context("设备 CSR 无效或签名校验失败")?;
    let ca_key = KeyPair::from_pem(&ca.private_key_pem).context("服务端 CA 私钥无效")?;
    let issuer =
        Issuer::from_ca_cert_pem(&ca.certificate_pem, ca_key).context("服务端 CA 证书无效")?;
    let mut params = CertificateParams::new(vec![format!("device-{device_id}.nexo")])?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, device_id);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    params.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::minutes(5);
    params.not_after = now + Duration::days(365);
    let certificate = params.signed_by(&csr.public_key, &issuer)?;
    let certificate_der = certificate.der();
    let fingerprint = hex::encode(Sha256::digest(certificate_der.as_ref()));
    Ok(IssuedIdentity {
        certificate_pem: certificate.pem(),
        fingerprint,
        expires_at: params.not_after.unix_timestamp(),
    })
}

/// 首次启动时生成控制通道服务端证书，并由设备 CA 签发。
///
/// 控制通道证书与设备客户端证书分开保存，避免把 CA 自身误当作服务端身份；
/// 默认名称为 `nexo-server`，也可以通过 NEXO_CONTROL_SERVER_NAME 增加部署域名。
fn ensure_server_control_identity(connection: &Connection) -> Result<()> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM server_control_identity WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    if count > 0 {
        return Ok(());
    }
    let ca = load_server_ca(connection)?;
    let ca_key = KeyPair::from_pem(&ca.private_key_pem).context("服务端 CA 私钥无效")?;
    let issuer =
        Issuer::from_ca_cert_pem(&ca.certificate_pem, ca_key).context("服务端 CA 证书无效")?;
    let mut params = CertificateParams::new(control_server_names())?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "Nexo Control Server");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.use_authority_key_identifier_extension = true;
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(825);
    let server_key = KeyPair::generate()?;
    let certificate = params.signed_by(&server_key, &issuer)?;
    connection.execute(
        "INSERT INTO server_control_identity (id, certificate_pem, private_key_pem)
         VALUES (1, ?1, ?2)",
        rusqlite::params![certificate.pem(), server_key.serialize_pem()],
    )?;
    Ok(())
}

fn control_server_names() -> Vec<String> {
    let configured = env::var("NEXO_CONTROL_SERVER_NAME")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let mut names = vec!["nexo-server".to_owned()];
    if let Some(name) = configured {
        if !names.iter().any(|current| current == &name) {
            names.push(name);
        }
    }
    names
}

/// 从数据库读取 mTLS 服务端证书和私钥。
fn load_server_control_identity(connection: &Connection) -> Result<ControlIdentityMaterial> {
    connection
        .query_row(
            "SELECT certificate_pem, private_key_pem
             FROM server_control_identity WHERE id = 1",
            [],
            |row| {
                Ok(ControlIdentityMaterial {
                    certificate_pem: row.get(0)?,
                    private_key_pem: row.get(1)?,
                })
            },
        )
        .context("服务端控制通道身份尚未初始化")
}

fn pem_certificates(pem: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("证书 PEM 格式无效")
}

fn pem_private_key(pem: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut BufReader::new(pem.as_bytes()))
        .context("私钥 PEM 格式无效")?
        .context("私钥 PEM 中未找到私钥")
}

/// 构建要求客户端证书由 Nexo 设备 CA 签发的 mTLS 服务端配置。
fn build_control_tls_config(connection: &Connection) -> Result<Arc<rustls::ServerConfig>> {
    let ca = load_server_ca(connection)?;
    let server = load_server_control_identity(connection)?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in pem_certificates(&ca.certificate_pem)? {
        roots.add(certificate)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let certificate_chain = pem_certificates(&server.certificate_pem)?;
    let private_key = pem_private_key(&server.private_key_pem)?;
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificate_chain, private_key)?;
    Ok(Arc::new(config))
}

/// 接受设备 mTLS 连接。每个连接都在独立任务中处理，断开时不会影响其他设备。
async fn serve_control_listener(
    listener: tokio::net::TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
    state: AppState,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(tls_config);
    tracing::info!("Nexo mTLS 控制通道已监听");
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_control_connection(acceptor, stream, state).await {
                tracing::warn!("设备控制连接 {peer} 已关闭：{error:#}");
            }
        });
    }
}

/// 校验证书指纹与设备声明的一致性，并处理心跳更新。
async fn serve_control_connection(
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    state: AppState,
) -> Result<()> {
    let tls_stream = acceptor.accept(stream).await.context("TLS 握手失败")?;
    let peer_certificate = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .context("设备未提供客户端证书")?;
    let certificate_fingerprint = hex::encode(Sha256::digest(peer_certificate.as_ref()));
    let mut reader = AsyncBufReader::new(tls_stream);
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_line(&mut line),
    )
    .await
    .context("等待设备身份声明超时")??;
    let hello: AgentControlMessage =
        serde_json::from_str(line.trim()).context("设备身份声明格式无效")?;
    let (device_id, agent_version, capabilities, gateway_report, mesh_identity) = match hello {
        AgentControlMessage::Hello {
            device_id,
            agent_version,
            capabilities,
            gateway_report,
            mesh_identity,
        } => (
            device_id,
            agent_version,
            capabilities,
            gateway_report,
            mesh_identity,
        ),
        AgentControlMessage::Heartbeat { .. } => anyhow::bail!("设备必须先发送身份声明"),
        AgentControlMessage::MeshEnrollmentAck { .. }
        | AgentControlMessage::GatewayRouteApplyReport { .. } => {
            anyhow::bail!("设备必须先发送身份声明")
        }
        AgentControlMessage::GatewayApplyAck { .. } => anyhow::bail!("设备必须先发送身份声明"),
    };
    if device_id.trim().is_empty() {
        anyhow::bail!("设备身份声明缺少 device_id");
    }
    let capabilities_json = serde_json::to_string(&capabilities)?;
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let matched: i64 = connection.query_row(
            "SELECT COUNT(*) FROM device_identities
             WHERE device_id = ?1 AND certificate_fingerprint = ?2 AND revoked_at IS NULL",
            rusqlite::params![device_id, certificate_fingerprint],
            |row| row.get(0),
        )?;
        if matched == 0 {
            anyhow::bail!("设备证书与 device_id 不匹配，拒绝控制连接");
        }
        connection.execute(
            "UPDATE devices SET status = 'online', agent_version = ?2,
             capabilities_json = ?3, last_seen_at = CURRENT_TIMESTAMP,
             updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
            rusqlite::params![device_id, agent_version, capabilities_json],
        )?;
        if let Some(report) = gateway_report {
            connection.execute(
                "INSERT INTO device_capability_reports
                 (device_id, report_json, reported_at, updated_at)
                 VALUES (?1, ?2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                 ON CONFLICT(device_id) DO UPDATE SET
                 report_json = excluded.report_json,
                 reported_at = CURRENT_TIMESTAMP,
                 updated_at = CURRENT_TIMESTAMP",
                rusqlite::params![device_id, serde_json::to_string(&report)?],
            )?;
        }
    }
    if let Some(identity) = mesh_identity.as_ref() {
        record_mesh_identity_report(&state, &device_id, identity)?;
    }
    if let Err(error) = ensure_mesh_enrollment_for_device(&state, &device_id).await {
        tracing::warn!(device_id = %device_id, "组网入网协调暂未完成：{error:#}");
    }
    let gateway_state = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        load_gateway_desired_state(&connection, &device_id)?
    };
    let mesh_enrollment = current_mesh_offer(&state, &device_id).await;
    write_control_message(
        reader.get_mut(),
        &ServerControlMessage::HelloAccepted {
            server_time: unix_now(),
            gateway_state,
            mesh_enrollment,
            protocol_features: vec![
                "mesh_enrollment".to_owned(),
                "gateway_route_report".to_owned(),
            ],
        },
    )
    .await?;
    line.clear();
    loop {
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            break;
        }
        let message: AgentControlMessage =
            serde_json::from_str(line.trim()).context("控制消息格式无效")?;
        match message {
            AgentControlMessage::Heartbeat {
                device_id: heartbeat_device_id,
                agent_version: heartbeat_version,
                gateway_report,
                mesh_identity,
            } if heartbeat_device_id == device_id => {
                {
                    let connection = state
                        .db
                        .lock()
                        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                    let matched: i64 = connection.query_row(
                        "SELECT COUNT(*) FROM device_identities
                         WHERE device_id = ?1 AND certificate_fingerprint = ?2
                         AND revoked_at IS NULL",
                        rusqlite::params![device_id, certificate_fingerprint],
                        |row| row.get(0),
                    )?;
                    if matched == 0 {
                        anyhow::bail!("设备身份已撤销或与证书不匹配");
                    }
                    connection.execute(
                        "UPDATE devices SET status = 'online', agent_version = ?2,
                         last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                         WHERE id = ?1",
                        rusqlite::params![device_id, heartbeat_version],
                    )?;
                    if let Some(report) = gateway_report {
                        connection.execute(
                            "INSERT INTO device_capability_reports
                             (device_id, report_json, reported_at, updated_at)
                             VALUES (?1, ?2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                             ON CONFLICT(device_id) DO UPDATE SET
                             report_json = excluded.report_json,
                             reported_at = CURRENT_TIMESTAMP,
                             updated_at = CURRENT_TIMESTAMP",
                            rusqlite::params![device_id, serde_json::to_string(&report)?],
                        )?;
                    }
                }
                if let Some(identity) = mesh_identity.as_ref() {
                    record_mesh_identity_report(&state, &device_id, identity)?;
                }
                let gateway_state = {
                    let connection = state
                        .db
                        .lock()
                        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                    load_gateway_desired_state(&connection, &device_id)?
                };
                if let Err(error) = ensure_mesh_enrollment_for_device(&state, &device_id).await {
                    tracing::debug!(device_id = %device_id, "心跳时组网邀请尚未准备好：{error:#}");
                }
                let mesh_enrollment = current_mesh_offer(&state, &device_id).await;
                write_control_message(
                    reader.get_mut(),
                    &ServerControlMessage::HeartbeatAck {
                        server_time: unix_now(),
                        gateway_state,
                        mesh_enrollment,
                        protocol_features: vec![
                            "mesh_enrollment".to_owned(),
                            "gateway_route_report".to_owned(),
                        ],
                    },
                )
                .await?;
            }
            AgentControlMessage::MeshEnrollmentAck {
                auth_key_id,
                success,
                identity,
                error_message,
            } => {
                let resolved_node_id = if success {
                    state
                        .headscale
                        .find_node_by_pre_auth_key(&auth_key_id)
                        .await?
                        .map(|node| node.id)
                } else {
                    None
                };
                record_mesh_enrollment_ack(
                    &state,
                    &device_id,
                    &auth_key_id,
                    success,
                    identity.as_ref(),
                    error_message.as_deref(),
                    resolved_node_id.as_deref(),
                )?;
                // 无论成功还是失败都移除当前内存邀请：失败会让下一次心跳
                // 先吊销旧 Key 再生成新的短时邀请，避免重复提交同一把已失败的 Key。
                state.mesh_offers.lock().await.remove(&device_id);
                write_control_message(
                    reader.get_mut(),
                    &ServerControlMessage::HeartbeatAck {
                        server_time: unix_now(),
                        gateway_state: None,
                        mesh_enrollment: None,
                        protocol_features: vec![
                            "mesh_enrollment".to_owned(),
                            "gateway_route_report".to_owned(),
                        ],
                    },
                )
                .await?;
            }
            AgentControlMessage::GatewayRouteApplyReport { report } => {
                apply_gateway_route_report(&state, &device_id, &report)?;
                // 只有 Agent 明确确认启用路由已经在本机真实执行成功，才允许
                // 触发 Headscale 批准。关闭路由是撤销操作，即使本地演练模式
                // 没有执行命令，也不能借此批准任何新的前缀；含有失败/升级
                // 路由的混合报告则等待下一次完整成功报告再收敛。
                if report_allows_headscale_reconcile(&report) {
                    let reconcile_state = state.clone();
                    let reconcile_device_id = device_id.clone();
                    tokio::spawn(async move {
                        if let Err(error) =
                            reconcile_headscale_routes(&reconcile_state, &reconcile_device_id).await
                        {
                            tracing::warn!(
                                device_id = %reconcile_device_id,
                                "Headscale 路由收敛失败，将在下次检测重试：{error:#}"
                            );
                        }
                    });
                } else {
                    tracing::debug!(
                        device_id = %device_id,
                        "逐路由报告尚未确认全部本地应用成功，暂不触发 Headscale 批准"
                    );
                }
                write_control_message(
                    reader.get_mut(),
                    &ServerControlMessage::GatewayApplyAccepted {
                        revision: report.revision,
                    },
                )
                .await?;
            }
            AgentControlMessage::GatewayApplyAck { ack } => {
                apply_gateway_ack(&state, &device_id, &ack)?;
                write_control_message(
                    reader.get_mut(),
                    &ServerControlMessage::GatewayApplyAccepted {
                        revision: ack.revision,
                    },
                )
                .await?;
            }
            AgentControlMessage::Heartbeat { .. } => anyhow::bail!("心跳 device_id 与证书不匹配"),
            AgentControlMessage::Hello { .. } => anyhow::bail!("控制通道不能重复发送身份声明"),
        }
        line.clear();
    }
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "UPDATE devices SET status = 'offline', updated_at = CURRENT_TIMESTAMP
         WHERE id = ?1 AND status = 'online'",
        [&device_id],
    )?;
    // 控制连接断开时，已持久化的 Mesh 地址仍可保留用于展示，但在线位必须
    // 立即清零，避免后台路由协调器把离线网关误当成 READY。
    transaction.execute(
        "UPDATE mesh_identities SET online = 0, updated_at = CURRENT_TIMESTAMP
         WHERE nexo_device_id = ?1",
        [&device_id],
    )?;
    refresh_site_link_apply_status(&transaction)?;
    transaction.commit()?;
    Ok(())
}

/// 判断逐路由报告是否足以授权 Headscale 路由收敛。
///
/// 启用路由必须由 Agent 证明本地命令已经成功；关闭路由属于定向撤销，
/// 即使 Agent 处于演练模式也可以继续清理控制平面的 Nexo 前缀。
fn report_allows_headscale_reconcile(report: &GatewayRouteApplyReport) -> bool {
    !report.routes.is_empty()
        && report
            .routes
            .iter()
            .all(|route| !route.enabled || route.local_applied)
}

async fn write_control_message(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    message: &ServerControlMessage,
) -> Result<()> {
    let payload = serde_json::to_string(message)?;
    stream.write_all(payload.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

/// 为一台已认证设备汇总需要应用的网关路由。
///
/// 本函数只读取 Nexo 自己的 Desired State。站点互联时，设备收到的是对
/// 端共享网络的前缀，不会收到 Headscale 数据库记录或 WireGuard 参数。
fn load_gateway_desired_state(
    connection: &Connection,
    device_id: &str,
) -> Result<Option<GatewayDesiredState>> {
    let identity_mismatch = connection
        .query_row(
            "SELECT state FROM mesh_identities WHERE nexo_device_id = ?1",
            [device_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .is_some_and(|state| state == "mesh_identity_mismatch");
    let mut routes = Vec::new();
    {
        let mut statement = connection.prepare(
            "SELECT n.id, g.desired_prefix, g.desired_revision, n.enabled
             FROM site_networks n
             JOIN gateway_network_states g ON g.site_network_id = n.id
             WHERE n.publisher_device_id = ?1",
        )?;
        let rows = statement.query_map([device_id], |row| {
            Ok(GatewayDesiredRoute {
                network_id: row.get(0)?,
                site_link_id: None,
                prefix: row.get(1)?,
                revision: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0 && !identity_mismatch,
            })
        })?;
        for row in rows {
            routes.push(row?);
        }
    }
    {
        let mut statement = connection.prepare(
            "SELECT remote_n.id, l.id, remote_g.desired_prefix, remote_g.desired_revision,
                    l.apply_revision, l.enabled, local_n.enabled, remote_n.enabled
             FROM site_links l
             JOIN site_link_networks local_link ON local_link.site_link_id = l.id
             JOIN site_networks local_n ON local_n.id = local_link.site_network_id
             JOIN site_link_networks remote_link ON remote_link.site_link_id = l.id
                AND remote_link.side <> local_link.side
             JOIN site_networks remote_n ON remote_n.id = remote_link.site_network_id
             JOIN gateway_network_states remote_g ON remote_g.site_network_id = remote_n.id
             WHERE local_n.publisher_device_id = ?1
            ",
        )?;
        let rows = statement.query_map([device_id], |row| {
            let network_revision: i64 = row.get(3)?;
            let link_revision: i64 = row.get(4)?;
            Ok(GatewayDesiredRoute {
                network_id: row.get(0)?,
                site_link_id: Some(row.get(1)?),
                prefix: row.get(2)?,
                revision: network_revision.max(link_revision),
                enabled: row.get::<_, i64>(5)? != 0
                    && row.get::<_, i64>(6)? != 0
                    && row.get::<_, i64>(7)? != 0
                    && !identity_mismatch,
            })
        })?;
        for row in rows {
            routes.push(row?);
        }
    }
    if routes.is_empty() {
        return Ok(None);
    }
    routes.sort_by(|left, right| {
        left.network_id
            .cmp(&right.network_id)
            .then_with(|| left.site_link_id.cmp(&right.site_link_id))
    });
    let revision = routes
        .iter()
        .map(|route| route.revision)
        .max()
        .unwrap_or_default();
    Ok(Some(GatewayDesiredState { revision, routes }))
}

/// 保存 Agent 对网关 Desired State 的确认结果。
///
/// 只有 Agent 明确列出的网络才会进入 `ready`；其他状态不会填充
/// `applied_prefix`，避免“数据库已保存但系统路由未生效”的假成功。
fn apply_gateway_ack(state: &AppState, device_id: &str, ack: &GatewayApplyAck) -> Result<()> {
    if ack.revision < 0 {
        anyhow::bail!("网关应用确认的 revision 不能为负数");
    }
    let status = match ack.status {
        ApplyStatus::Disabled => "disabled",
        ApplyStatus::Checking => "checking",
        ApplyStatus::Applying => "applying",
        ApplyStatus::Ready => "ready",
        ApplyStatus::Retrying => "retrying",
        ApplyStatus::Failed => "failed",
    };
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let transaction = connection.unchecked_transaction()?;
    if ack.status == ApplyStatus::Ready {
        // 旧版 ACK 没有逐路由 local/control-plane/remote 字段；即使它声称
        // ready，也只能标记为 upgrade_required，避免 N-1 Agent 伪造 READY。
        for network_id in &ack.network_ids {
            transaction.execute(
                "UPDATE gateway_network_states
                 SET apply_status = 'checking', applied_prefix = NULL,
                     apply_error = 'Agent 需要升级以报告逐路由应用结果',
                     last_checked_at = CURRENT_TIMESTAMP,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE site_network_id = ?1 AND desired_revision <= ?2
                   AND site_network_id IN
                       (SELECT n.id FROM site_networks n
                        WHERE n.publisher_device_id = ?3)",
                rusqlite::params![network_id, ack.revision, device_id],
            )?;
            transaction.execute(
                "INSERT INTO gateway_route_applies
                 (device_id, network_id, site_link_id, desired_revision, local_status,
                  control_plane_status, remote_status, last_error, last_checked_at,
                  updated_at)
                 VALUES (?1, ?2, '', ?3, 'upgrade_required', 'pending', 'pending',
                         'Agent 需要升级以报告逐路由应用结果', CURRENT_TIMESTAMP,
                         CURRENT_TIMESTAMP)
                 ON CONFLICT(device_id, network_id, site_link_id) DO UPDATE SET
                 local_status = 'upgrade_required', last_error = excluded.last_error,
                 last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP",
                rusqlite::params![device_id, network_id, ack.revision],
            )?;
        }
    } else {
        for network_id in &ack.network_ids {
            transaction.execute(
                "UPDATE gateway_network_states
                 SET apply_status = ?1, applied_prefix = NULL, apply_error = ?2,
                     last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                 WHERE site_network_id = ?3 AND desired_revision <= ?4
                   AND site_network_id IN
                       (SELECT n.id FROM site_networks n
                        WHERE n.publisher_device_id = ?5)",
                rusqlite::params![
                    status,
                    ack.error_message,
                    network_id,
                    ack.revision,
                    device_id
                ],
            )?;
            transaction.execute(
                "UPDATE site_networks
                 SET apply_status = ?1, apply_revision = ?2, apply_error = ?3,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?4 AND id IN
                       (SELECT n.id FROM site_networks n
                        WHERE n.publisher_device_id = ?5)
                   AND EXISTS (SELECT 1 FROM gateway_network_states g
                               WHERE g.site_network_id = site_networks.id
                                 AND g.desired_revision <= ?2)",
                rusqlite::params![
                    status,
                    ack.revision,
                    ack.error_message,
                    network_id,
                    device_id
                ],
            )?;
            transaction.execute(
                "UPDATE site_links SET apply_status = ?1, apply_error = ?2,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id IN (
                     SELECT DISTINCT l.id
                     FROM site_links l
                     JOIN site_link_networks ln ON ln.site_link_id = l.id
                     WHERE ln.site_network_id = ?3 AND l.enabled = 1
                 )",
                rusqlite::params![status, ack.error_message, network_id],
            )?;
        }
    }
    refresh_site_link_apply_status(&transaction)?;
    transaction.commit()?;
    Ok(())
}

/// 根据两侧逐路由状态收敛 Site Gateway；任何一侧缺少本地/远端 ACK 都保持
/// checking，只有两侧全部 serving 且接受远端路由才进入 ready。
fn refresh_site_link_apply_status(transaction: &rusqlite::Transaction<'_>) -> Result<()> {
    transaction.execute_batch(
        "UPDATE site_links
         SET apply_status = CASE
           -- 关闭互联不能依赖共享网络本身的状态：共享网络仍可能继续
           -- 对租户组网开放。只有两侧 Agent 都 ACK 了该 Link 的撤销路由，
           -- 才能把 Link 标记为 DISABLED。
           WHEN enabled = 0 AND NOT EXISTS (
             SELECT 1
             FROM site_link_networks local_link
             JOIN site_networks local_n
               ON local_n.id = local_link.site_network_id
             JOIN site_link_networks remote_link
               ON remote_link.site_link_id = local_link.site_link_id
              AND remote_link.side <> local_link.side
             JOIN site_networks remote_n
               ON remote_n.id = remote_link.site_network_id
             LEFT JOIN gateway_route_applies a
               ON a.device_id = local_n.publisher_device_id
              AND a.network_id = remote_n.id
              AND a.site_link_id = site_links.id
              WHERE local_link.site_link_id = site_links.id
                AND (COALESCE(a.local_status, '') <> 'disabled'
                  OR COALESCE(a.remote_status, '') <> 'disabled'
                  OR COALESCE(a.control_plane_status, '') <> 'disabled')
           ) THEN 'disabled'
           WHEN enabled = 0 THEN 'checking'
           WHEN EXISTS (
             SELECT 1 FROM site_link_networks ln
             JOIN site_networks n ON n.id = ln.site_network_id
             JOIN gateway_network_states g ON g.site_network_id = n.id
             LEFT JOIN mesh_identities m ON m.nexo_device_id = n.publisher_device_id
             WHERE ln.site_link_id = site_links.id
               AND (g.apply_status <> 'ready'
                     OR EXISTS (SELECT 1 FROM devices d
                                WHERE d.id = n.publisher_device_id
                                  AND d.status <> 'online')
                     OR COALESCE(m.state, '') <> 'ready'
                     OR COALESCE(m.online, 0) <> 1
                     OR NOT EXISTS (
                 SELECT 1 FROM gateway_route_applies a
                 WHERE a.device_id = n.publisher_device_id
                   AND a.network_id = n.id
                   AND a.site_link_id = site_links.id
                   AND a.local_status = 'applied'
                   AND a.control_plane_status = 'serving'
                   AND a.remote_status = 'accepted'))
           ) THEN 'checking'
           ELSE 'ready' END,
         apply_error = CASE WHEN enabled = 0 THEN NULL ELSE apply_error END,
         updated_at = CURRENT_TIMESTAMP",
    )?;
    Ok(())
}

async fn current_mesh_offer(state: &AppState, device_id: &str) -> Option<MeshEnrollmentOffer> {
    state.mesh_offers.lock().await.get(device_id).cloned()
}

/// 控制连接建立时恢复或补发组网邀请，避免依赖内存中的一次性任务队列。
async fn ensure_mesh_enrollment_for_device(state: &AppState, device_id: &str) -> Result<()> {
    let _lock = state.mesh_enrollment_lock.lock().await;
    ensure_mesh_enrollment_for_device_locked(state, device_id).await
}

async fn ensure_mesh_enrollment_for_device_locked(state: &AppState, device_id: &str) -> Result<()> {
    if current_mesh_offer(state, device_id).await.is_some() {
        return Ok(());
    }
    let details: Option<(String, String)> = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let identity_state: Option<String> = connection
            .query_row(
                "SELECT state FROM mesh_identities WHERE nexo_device_id = ?1",
                [device_id],
                |row| row.get(0),
            )
            .optional()?;
        if matches!(
            identity_state.as_deref(),
            Some("ready") | Some("mesh_identity_mismatch")
        ) {
            return Ok(());
        }
        connection
            .query_row(
                "SELECT tenant_id, name FROM devices WHERE id = ?1",
                [device_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
    };
    let Some((tenant_id, device_name)) = details else {
        return Ok(());
    };
    let attempt: Option<(String, i64, String)> = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT headscale_pre_auth_key_id, expires_at, state
                 FROM mesh_enrollment_attempts
                 WHERE nexo_device_id = ?1 AND state IN ('issued', 'failed')
                 ORDER BY created_at DESC LIMIT 1",
                [device_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
    };
    if let Some((key_id, expires_at, attempt_state)) = attempt {
        if unix_now() < expires_at {
            let key = state
                .headscale
                .list_pre_auth_keys()
                .await?
                .into_iter()
                .find(|key| key.id == key_id);
            if let Some(key) = key {
                // ACK 可能在 Agent 加入成功后丢失。先用原 Key 查节点并完成绑定，
                // 只有确认没有节点时才吊销并重新发放，避免重启生成重复 Node。
                if key.used {
                    if let Some(node) = state.headscale.find_node_by_pre_auth_key(&key.id).await? {
                        let identity = mesh_identity_from_headscale_node(&node);
                        record_mesh_enrollment_ack(
                            state,
                            device_id,
                            &key.id,
                            true,
                            Some(&identity),
                            None,
                            Some(&node.id),
                        )?;
                        state.mesh_offers.lock().await.remove(device_id);
                        return Ok(());
                    }
                    // Headscale 已标记 Key 为已使用，但暂时还查不到对应
                    // Node 时不能贸然重发，否则可能制造重复组网节点；保留
                    // 当前尝试，等待下一次心跳或重启后的恢复协调。
                    return Err(anyhow::anyhow!(
                        "组网入网密钥已被使用，但暂未找到对应设备节点"
                    ));
                } else if attempt_state == "issued" {
                    if let Some(plaintext) = key.key {
                        state.mesh_offers.lock().await.insert(
                            device_id.to_owned(),
                            MeshEnrollmentOffer {
                                endpoint: env::var("NEXO_MESH_ENDPOINT")
                                    .or_else(|_| env::var("NEXO_HEADSCALE_URL"))
                                    .unwrap_or_else(|_| "http://headscale:8080".to_owned()),
                                auth_key: plaintext,
                                auth_key_id: key.id,
                                hostname: device_name,
                                reset: false,
                                tenant_id: Some(tenant_id),
                            },
                        );
                        return Ok(());
                    }
                } else {
                    // 上一次加入失败但 Key 尚未消费：先吊销旧 Key，再重新
                    // 创建邀请，避免失败路径留下可再次使用的凭证。
                    state
                        .headscale
                        .expire_pre_auth_key(&key.id)
                        .await
                        .with_context(|| format!("失败的组网入网密钥 {} 尚未吊销", key.id))?;
                    let connection = state
                        .db
                        .lock()
                        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                    connection.execute(
                        "UPDATE mesh_enrollment_attempts SET state = 'revoked',
                         last_error = '上一次组网加入失败，已吊销旧密钥',
                         updated_at = CURRENT_TIMESTAMP
                         WHERE nexo_device_id = ?1 AND headscale_pre_auth_key_id = ?2
                           AND state = 'failed'",
                        rusqlite::params![device_id, key_id],
                    )?;
                }
            } else {
                // Headscale 已明确返回成功但列表中没有该 Key，说明它已被
                // 过期/删除；先结束旧尝试，再创建新的短时邀请。
                let connection = state
                    .db
                    .lock()
                    .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                connection.execute(
                    "UPDATE mesh_enrollment_attempts SET state = 'revoked',
                     last_error = 'Headscale 入网密钥已不存在', updated_at = CURRENT_TIMESTAMP
                     WHERE nexo_device_id = ?1 AND headscale_pre_auth_key_id = ?2
                       AND state = ?3",
                    rusqlite::params![device_id, key_id, attempt_state],
                )?;
            }
        } else {
            let connection = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            connection.execute(
                "UPDATE mesh_enrollment_attempts SET state = 'expired',
                 last_error = '组网入网密钥已过期', updated_at = CURRENT_TIMESTAMP
                 WHERE nexo_device_id = ?1 AND headscale_pre_auth_key_id = ?2
                   AND state = ?3",
                rusqlite::params![device_id, key_id, attempt_state],
            )?;
        }
    }
    start_mesh_enrollment_locked(state, device_id, &tenant_id, &device_name, false).await
}

/// 将 Headscale 节点投影为 Nexo 可持久化的运行身份；不把底层 Node 模型返回给 Web。
fn mesh_identity_from_headscale_node(node: &HeadscaleNode) -> MeshIdentityReport {
    MeshIdentityReport {
        node_id: Some(node.id.clone()),
        hostname: Some(node.name.clone()).filter(|name| !name.is_empty()),
        ipv4: node
            .ip_addresses
            .iter()
            .find(|ip| ip.contains('.'))
            .cloned(),
        ipv6: node
            .ip_addresses
            .iter()
            .find(|ip| ip.contains(':'))
            .cloned(),
        online: node.online,
    }
}

/// Server 重启后从 Headscale API 恢复未使用的 Pre-auth Key；若 Key 已消费，
/// 则根据 Key ID 直接完成 Node 绑定，避免生成重复节点。
async fn recover_mesh_offers(state: &AppState) -> Result<()> {
    let keys = state.headscale.list_pre_auth_keys().await?;
    for key in keys {
        let attempt: Option<(String, String, String, i64)> = {
            let connection = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            connection
                .query_row(
                    "SELECT a.nexo_device_id, a.tenant_id, d.name, a.expires_at
                     FROM mesh_enrollment_attempts a JOIN devices d ON d.id = a.nexo_device_id
                     WHERE a.headscale_pre_auth_key_id = ?1 AND a.state = 'issued'",
                    [&key.id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?
        };
        let Some((device_id, tenant_id, device_name, expires_at)) = attempt else {
            continue;
        };
        if key.used {
            if let Some(node) = state.headscale.find_node_by_pre_auth_key(&key.id).await? {
                let identity = mesh_identity_from_headscale_node(&node);
                record_mesh_enrollment_ack(
                    state,
                    &device_id,
                    &key.id,
                    true,
                    Some(&identity),
                    None,
                    Some(&node.id),
                )?;
            }
            continue;
        }
        if unix_now() >= expires_at {
            let connection = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            connection.execute(
                "UPDATE mesh_enrollment_attempts SET state = 'expired',
                 updated_at = CURRENT_TIMESTAMP WHERE headscale_pre_auth_key_id = ?1",
                [&key.id],
            )?;
            continue;
        }
        let Some(plaintext) = key.key else {
            continue;
        };
        state.mesh_offers.lock().await.insert(
            device_id,
            MeshEnrollmentOffer {
                endpoint: env::var("NEXO_MESH_ENDPOINT")
                    .or_else(|_| env::var("NEXO_HEADSCALE_URL"))
                    .unwrap_or_else(|_| "http://headscale:8080".to_owned()),
                auth_key: plaintext,
                auth_key_id: key.id,
                hostname: device_name,
                reset: false,
                tenant_id: Some(tenant_id),
            },
        );
    }
    Ok(())
}

/// 记录 Agent 的 Mesh Enrollment 结果并绑定稳定 Node ID。
///
/// 绑定是单向且不可静默覆盖的：同一 Nexo 设备或另一设备报告不同 Node ID
/// 时进入 `mesh_identity_mismatch`，网关协调器会停止继续应用路由。
fn record_mesh_enrollment_ack(
    state: &AppState,
    device_id: &str,
    auth_key_id: &str,
    success: bool,
    identity: Option<&MeshIdentityReport>,
    error_message: Option<&str>,
    resolved_node_id: Option<&str>,
) -> Result<()> {
    if auth_key_id.trim().is_empty() {
        anyhow::bail!("组网入网确认缺少密钥 ID");
    }
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let transaction = connection.unchecked_transaction()?;
    let attempt: Option<(String, String, String)> = transaction
        .query_row(
            "SELECT id, tenant_id, state FROM mesh_enrollment_attempts
             WHERE nexo_device_id = ?1 AND headscale_pre_auth_key_id = ?2
             ORDER BY created_at DESC LIMIT 1",
            rusqlite::params![device_id, auth_key_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((attempt_id, tenant_id, attempt_state)) = attempt else {
        anyhow::bail!("组网入网密钥不存在或已被替换");
    };
    if attempt_state != "issued" && !(success && attempt_state == "failed") {
        anyhow::bail!("组网入网密钥当前状态为 {attempt_state}，不能重复确认");
    }
    if !success {
        transaction.execute(
            "UPDATE mesh_enrollment_attempts
             SET state = 'failed', last_error = ?1, updated_at = CURRENT_TIMESTAMP
             WHERE id = ?2",
            rusqlite::params![error_message, attempt_id],
        )?;
        transaction.execute(
            "UPDATE mesh_identities SET state = 'failed', last_error = ?1,
             updated_at = CURRENT_TIMESTAMP WHERE nexo_device_id = ?2",
            rusqlite::params![error_message, device_id],
        )?;
        transaction.commit()?;
        return Ok(());
    }
    let identity = identity.context("组网入网成功但缺少 Node 身份")?;
    let reported_node_id = identity
        .node_id
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    // Node ID 必须由 Server 使用 Pre-auth Key 从 Headscale 解析得到；Agent
    // 上报的身份只能用于交叉校验，不能单独成为绑定依据。
    let node_id =
        resolved_node_id.context("组网入网成功但 Headscale 尚未返回 Node；请稍后重新检测")?;
    if let (Some(reported), Some(resolved)) = (reported_node_id, resolved_node_id) {
        if reported != resolved {
            anyhow::bail!("Agent 报告的组网身份与 Pre-auth Key 对应 Node 不一致");
        }
    }
    let existing: Option<(String, String)> = transaction
        .query_row(
            "SELECT headscale_node_id, state FROM mesh_identities WHERE nexo_device_id = ?1",
            [device_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((existing_node_id, existing_state)) = existing {
        if existing_state == "mesh_identity_mismatch" {
            anyhow::bail!("设备仍处于组网身份错配状态，必须先通过明确恢复流程停用旧 Node");
        }
        if existing_node_id != node_id {
            transaction.execute(
                "UPDATE mesh_identities SET state = 'mesh_identity_mismatch',
                 last_error = ?1, updated_at = CURRENT_TIMESTAMP
                 WHERE nexo_device_id = ?2",
                rusqlite::params![
                    format!("当前 Agent 身份为 Node {node_id}，预期为 Node {existing_node_id}"),
                    device_id
                ],
            )?;
            transaction.commit()?;
            tracing::error!(device_id, "检测到组网身份不一致，已停止静默改绑");
            return Ok(());
        }
    } else {
        let same_node: Option<String> = transaction
            .query_row(
                "SELECT nexo_device_id FROM mesh_identities WHERE headscale_node_id = ?1",
                [node_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(other_device_id) = same_node {
            anyhow::bail!("Headscale Node {node_id} 已绑定设备 {other_device_id}");
        }
        transaction.execute(
            "INSERT INTO mesh_identities
             (nexo_device_id, tenant_id, headscale_node_id, state, tailscale_ipv4,
              tailscale_ipv6, hostname, online, last_verified_at, updated_at)
             VALUES (?1, ?2, ?3, 'ready', ?4, ?5, ?6, ?7, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            rusqlite::params![
                device_id,
                tenant_id,
                node_id,
                identity.ipv4,
                identity.ipv6,
                identity.hostname,
                if identity.online { 1 } else { 0 }
            ],
        )?;
    }
    transaction.execute(
        "UPDATE mesh_identities SET state = 'ready', tailscale_ipv4 = ?1,
         tailscale_ipv6 = ?2, hostname = ?3, online = ?4,
         last_verified_at = CURRENT_TIMESTAMP, last_error = NULL,
         updated_at = CURRENT_TIMESTAMP WHERE nexo_device_id = ?5",
        rusqlite::params![
            identity.ipv4,
            identity.ipv6,
            identity.hostname,
            if identity.online { 1 } else { 0 },
            device_id
        ],
    )?;
    transaction.execute(
        "UPDATE mesh_enrollment_attempts SET state = 'consumed', last_error = NULL,
         updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
        [attempt_id],
    )?;
    transaction.commit()?;
    tracing::info!(device_id, node_id, "设备已绑定稳定组网身份");
    Ok(())
}

/// 核对 Agent 在运行中的组网身份；身份一旦偏离已绑定 Node，立即进入错配状态。
///
/// 心跳报告只用于交叉校验，绝不承担首次绑定职责。发现错配时递增所有相关
/// Desired State revision，并把下一次下发改为撤销路由，确保旧身份不会继续作为
/// 网关使用；管理员随后必须通过显式恢复接口停用旧 Node 并重新入网。
fn record_mesh_identity_report(
    state: &AppState,
    device_id: &str,
    identity: &MeshIdentityReport,
) -> Result<()> {
    let reported_node_id = identity
        .node_id
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let transaction = connection.unchecked_transaction()?;
    let current: Option<(String, String, String)> = transaction
        .query_row(
            "SELECT headscale_node_id, tenant_id, state
             FROM mesh_identities WHERE nexo_device_id = ?1",
            [device_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((expected_node_id, tenant_id, state_name)) = current else {
        // 首次入网仍必须经过 Pre-auth Key + Server 解析，不能由心跳直接创建绑定。
        transaction.commit()?;
        return Ok(());
    };

    if state_name == "ready"
        && reported_node_id.is_some_and(|reported| reported != expected_node_id)
    {
        let reported = reported_node_id.unwrap_or_default();
        let message =
            format!("Agent 当前组网身份为 Node {reported}，预期为 Node {expected_node_id}");
        transaction.execute(
            "UPDATE mesh_identities
             SET state = 'mesh_identity_mismatch', last_error = ?1,
                 online = ?2, last_verified_at = CURRENT_TIMESTAMP,
                  updated_at = CURRENT_TIMESTAMP
             WHERE nexo_device_id = ?3",
            rusqlite::params![message, if identity.online { 1 } else { 0 }, device_id],
        )?;
        transaction.execute(
            "UPDATE gateway_network_states
             SET desired_revision = desired_revision + 1,
                 apply_status = 'failed', applied_prefix = NULL, apply_error = ?1,
                 last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
             WHERE site_network_id IN (
                 SELECT id FROM site_networks WHERE publisher_device_id = ?2
             )",
            rusqlite::params![message, device_id],
        )?;
        transaction.execute(
            "UPDATE site_links
             SET apply_revision = apply_revision + 1, apply_status = 'failed',
                 apply_error = ?1, updated_at = CURRENT_TIMESTAMP
             WHERE id IN (
                 SELECT DISTINCT l.id
                 FROM site_links l
                 JOIN site_link_networks ln ON ln.site_link_id = l.id
                 JOIN site_networks n ON n.id = ln.site_network_id
                 WHERE n.publisher_device_id = ?2
             )",
            rusqlite::params![message, device_id],
        )?;
        transaction.execute(
            "UPDATE gateway_route_applies
             SET local_status = 'failed', control_plane_status = 'failed',
                 remote_status = 'failed', applied_prefix = NULL, last_error = ?1,
                 last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
             WHERE device_id = ?2",
            rusqlite::params![message, device_id],
        )?;
        write_audit_event(
            &transaction,
            &tenant_id,
            "MESH_IDENTITY_MISMATCH",
            "device",
            device_id,
        )
        .map_err(|error| anyhow::anyhow!(error.message))?;
        transaction.commit()?;
        tracing::error!(device_id, "检测到运行中的组网身份错配，已停止网关路由");
        return Ok(());
    }

    transaction.execute(
        "UPDATE mesh_identities
         SET tailscale_ipv4 = ?1, tailscale_ipv6 = ?2, hostname = ?3,
             online = ?4, last_verified_at = CURRENT_TIMESTAMP,
             updated_at = CURRENT_TIMESTAMP WHERE nexo_device_id = ?5",
        rusqlite::params![
            identity.ipv4,
            identity.ipv6,
            identity.hostname,
            if identity.online { 1 } else { 0 },
            device_id
        ],
    )?;
    refresh_site_link_apply_status(&transaction)?;
    transaction.commit()?;
    Ok(())
}

/// 保存 Agent 的逐路由真实应用结果。
///
/// 旧版整体 ACK 不会调用此函数，因此缺少逐路由结果时永远不能把
/// `gateway_network_states` 变成 READY；Headscale 的发现/批准/Serving 状态
/// 由后续协调任务单独写入 `control_plane_status`。
fn apply_gateway_route_report(
    state: &AppState,
    device_id: &str,
    report: &GatewayRouteApplyReport,
) -> Result<()> {
    if report.revision < 0 {
        anyhow::bail!("逐路由应用报告的 revision 不能为负数");
    }
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let transaction = connection.unchecked_transaction()?;
    if report.routes.is_empty() {
        transaction.execute(
            "UPDATE gateway_route_applies SET local_status = 'upgrade_required',
             last_error = 'Agent 未提供逐路由应用结果', last_checked_at = CURRENT_TIMESTAMP,
             updated_at = CURRENT_TIMESTAMP WHERE device_id = ?1",
            [device_id],
        )?;
        transaction.commit()?;
        return Ok(());
    }
    for route in &report.routes {
        let site_link_key = route.site_link_id.clone().unwrap_or_default();
        // Agent 上报的每一条路由都必须能在当前 Desired State 中找到；否则不能
        // 让伪造的 network_id/prefix 污染 Applied 状态或触发 Headscale 协调。
        let expected: Option<(String, bool, i64)> = if site_link_key.is_empty() {
            transaction
                .query_row(
                    "SELECT g.desired_prefix, n.enabled, g.desired_revision
                     FROM site_networks n
                     JOIN gateway_network_states g ON g.site_network_id = n.id
                     WHERE n.id = ?1 AND n.publisher_device_id = ?2",
                    rusqlite::params![route.network_id, device_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)? != 0,
                            row.get(2)?,
                        ))
                    },
                )
                .optional()?
        } else {
            transaction
                .query_row(
                    "SELECT remote_g.desired_prefix,
                            (l.enabled <> 0 AND local_n.enabled <> 0 AND remote_n.enabled <> 0),
                            MAX(l.apply_revision, remote_g.desired_revision)
                     FROM site_links l
                     JOIN site_link_networks local_link
                       ON local_link.site_link_id = l.id
                     JOIN site_networks local_n
                       ON local_n.id = local_link.site_network_id
                     JOIN site_link_networks remote_link
                       ON remote_link.site_link_id = l.id
                      AND remote_link.side <> local_link.side
                     JOIN site_networks remote_n
                       ON remote_n.id = remote_link.site_network_id
                     JOIN gateway_network_states remote_g
                       ON remote_g.site_network_id = remote_n.id
                     WHERE l.id = ?1
                       AND l.tenant_id = (SELECT tenant_id FROM devices WHERE id = ?2)
                       AND local_n.publisher_device_id = ?2
                       AND remote_n.id = ?3",
                    rusqlite::params![site_link_key, device_id, route.network_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)? != 0,
                            row.get(2)?,
                        ))
                    },
                )
                .optional()?
        };
        let Some((expected_prefix, expected_enabled, expected_revision)) = expected else {
            anyhow::bail!(
                "设备 {device_id} 上报了未授权的网关路由 {}",
                route.network_id
            );
        };
        if expected_prefix != route.prefix {
            anyhow::bail!(
                "设备 {device_id} 上报的网段 {} 与当前期望 {} 不一致",
                route.prefix,
                expected_prefix
            );
        }
        // 旧 revision 的延迟消息可以安全丢弃；未来 revision 或同 revision
        // 的 enabled 不一致则视为协议错误，避免错误状态覆盖数据库。
        if route.revision < expected_revision {
            continue;
        }
        if route.revision > expected_revision {
            anyhow::bail!(
                "设备 {device_id} 上报了未知的网关 revision {}",
                route.revision
            );
        }
        if route.enabled != expected_enabled {
            anyhow::bail!("设备 {device_id} 上报的网关开关与当前期望不一致");
        }
        let local_status = if !route.enabled {
            "disabled"
        } else if route.local_applied {
            "applied"
        } else {
            if route.error_message.is_some() {
                "failed"
            } else {
                "upgrade_required"
            }
        };
        let control_plane_status = route
            .control_plane_status
            .as_deref()
            .filter(|status| {
                matches!(
                    *status,
                    "pending" | "discovered" | "approved" | "serving" | "failed" | "disabled"
                )
            })
            .unwrap_or("pending");
        let remote_status = if !route.enabled {
            "disabled"
        } else if route.remote_applied {
            "accepted"
        } else {
            "pending"
        };
        transaction.execute(
            "INSERT INTO gateway_route_applies
             (device_id, network_id, site_link_id, desired_revision, local_status,
              control_plane_status, remote_status, applied_prefix, last_error,
              last_checked_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, CURRENT_TIMESTAMP,
                     CURRENT_TIMESTAMP)
             ON CONFLICT(device_id, network_id, site_link_id) DO UPDATE SET
             desired_revision = excluded.desired_revision,
             local_status = excluded.local_status,
             control_plane_status = excluded.control_plane_status,
             remote_status = excluded.remote_status,
             applied_prefix = excluded.applied_prefix,
             last_error = excluded.last_error,
             last_checked_at = CURRENT_TIMESTAMP,
             updated_at = CURRENT_TIMESTAMP",
            rusqlite::params![
                device_id,
                route.network_id,
                site_link_key,
                route.revision,
                local_status,
                control_plane_status,
                remote_status,
                if route.local_applied && route.enabled {
                    Some(route.prefix.as_str())
                } else {
                    None
                },
                route.error_message
            ],
        )?;
        transaction.execute(
            "UPDATE gateway_network_states SET apply_status = ?1,
             applied_prefix = CASE WHEN ?1 = 'ready' THEN desired_prefix ELSE NULL END,
             apply_error = ?2, last_checked_at = CURRENT_TIMESTAMP,
             updated_at = CURRENT_TIMESTAMP
             WHERE site_network_id = ?3 AND desired_revision <= ?4
               AND site_network_id IN
                 (SELECT id FROM site_networks WHERE publisher_device_id = ?5)",
            rusqlite::params![
                if !route.enabled {
                    "disabled"
                } else if route.local_applied {
                    "checking"
                } else {
                    "retrying"
                },
                route.error_message,
                route.network_id,
                route.revision,
                device_id
            ],
        )?;
    }
    refresh_site_link_apply_status(&transaction)?;
    transaction.commit()?;
    Ok(())
}

/// 根据已绑定 Node ID 重新读取 Headscale 节点并收敛 Nexo 所拥有的发布路由。
///
/// HTTP 调用发生在数据库锁之外；返回结果随后写入逐路由控制平面状态，避免
/// “本地命令成功”被误认为 Headscale 已批准并正在提供路由。
async fn reconcile_headscale_routes(state: &AppState, device_id: &str) -> Result<()> {
    let (node_id, desired, owned): (Option<String>, Vec<GatewayRouteApplyInput>, Vec<String>) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let node_id = connection
            .query_row(
                "SELECT headscale_node_id FROM mesh_identities
                 WHERE nexo_device_id = ?1 AND state = 'ready' AND online = 1",
                [device_id],
                |row| row.get(0),
            )
            .optional()?;
        let mut statement = connection.prepare(
            "SELECT n.id, n.publisher_device_id, g.desired_prefix, g.desired_revision,
                    n.enabled,
                    EXISTS (SELECT 1 FROM gateway_route_applies a
                            WHERE a.device_id = n.publisher_device_id
                              AND a.network_id = n.id
                              AND a.site_link_id = ''
                              AND a.desired_revision = g.desired_revision
                              AND a.local_status = 'applied')
             FROM site_networks n
             JOIN gateway_network_states g ON g.site_network_id = n.id
             WHERE n.publisher_device_id = ?1",
        )?;
        let rows = statement.query_map([device_id], |row| {
            Ok(GatewayRouteApplyInput {
                network_id: row.get(0)?,
                prefix: row.get(2)?,
                revision: row.get(3)?,
                enabled: row.get::<_, i64>(4)? != 0,
                local_applied: row.get::<_, i64>(5)? != 0,
            })
        })?;
        let desired: Vec<_> = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let owned = desired.iter().map(|route| route.prefix.clone()).collect();
        (node_id, desired, owned)
    };
    let Some(node_id) = node_id else {
        return Ok(());
    };
    let desired_prefixes: Vec<String> = desired
        .iter()
        // Headscale 只接收 Agent 已真实执行成功、且仍属于当前 revision 的
        // 本地发布网段。没有逐路由 ACK 时即使后台任务运行，也只能保持 Pending。
        .filter(|route| route.enabled && route.local_applied)
        .map(|route| route.prefix.clone())
        .collect();
    // 直接按 Node 调用适配器，即使所有共享网络都已关闭也会发送空的
    // Desired 列表，从而撤销历史 Nexo 前缀并保留非 Nexo 批准路由。
    let node_report = match state
        .headscale
        .reconcile_node_routes(&node_id, &desired_prefixes, &owned)
        .await
    {
        Ok(report) => report,
        Err(error) => {
            let message = format!("Headscale 路由协调失败：{error:#}");
            let connection = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            let transaction = connection.unchecked_transaction()?;
            for route in &desired {
                // Headscale 不可用时，撤销请求也不能提前标记为 disabled；
                // 必须等控制平面实际完成撤销后再进入终态。
                let control_status = "failed";
                // Headscale 暂不可用不等于 Agent 本地命令被撤销；保留已
                // 确认的 local_status，让后台协调器在控制平面恢复后继续
                // 发送同一 Desired Route，而不是把重试条件永久清空。
                let local_status = if !route.enabled {
                    "disabled"
                } else if route.local_applied {
                    "applied"
                } else {
                    "pending"
                };
                let remote_status = if route.enabled { "pending" } else { "disabled" };
                transaction.execute(
                    "INSERT INTO gateway_route_applies
                     (device_id, network_id, site_link_id, desired_revision, local_status,
                      control_plane_status, remote_status, applied_prefix, last_error,
                      last_checked_at, updated_at)
                     VALUES (?1, ?2, '', ?3, ?4, ?5, ?6, NULL, ?7,
                             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                     ON CONFLICT(device_id, network_id, site_link_id) DO UPDATE SET
                     desired_revision = excluded.desired_revision,
                     local_status = excluded.local_status,
                     control_plane_status = excluded.control_plane_status,
                     remote_status = excluded.remote_status,
                     applied_prefix = excluded.applied_prefix,
                     last_error = excluded.last_error,
                     last_checked_at = CURRENT_TIMESTAMP,
                     updated_at = CURRENT_TIMESTAMP",
                    rusqlite::params![
                        device_id,
                        route.network_id,
                        route.revision,
                        local_status,
                        control_status,
                        remote_status,
                        message
                    ],
                )?;
                transaction.execute(
                    "UPDATE gateway_network_states
                     SET apply_status = CASE WHEN ?1 = 'disabled' THEN 'disabled' ELSE 'retrying' END,
                         applied_prefix = NULL, apply_error = CASE WHEN ?1 = 'disabled' THEN NULL ELSE ?2 END,
                         last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                     WHERE site_network_id = ?3
                       AND site_network_id IN
                           (SELECT id FROM site_networks WHERE publisher_device_id = ?4)",
                    rusqlite::params![control_status, message, route.network_id, device_id],
                )?;
            }
            refresh_site_link_apply_status(&transaction)?;
            transaction.commit()?;
            return Err(error);
        }
    };
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let transaction = connection.unchecked_transaction()?;
    for route in &desired {
        let (control_status, error) = if !route.enabled {
            ("disabled", None)
        } else {
            let serving = node_report
                .subnet_routes
                .iter()
                .any(|prefix| prefix == &route.prefix);
            let approved = node_report
                .approved_routes
                .iter()
                .any(|prefix| prefix == &route.prefix);
            if serving {
                ("serving", None)
            } else if approved {
                ("approved", Some("Headscale 已批准，等待节点提供路由"))
            } else if node_report
                .available_routes
                .iter()
                .any(|prefix| prefix == &route.prefix)
            {
                ("discovered", Some("Headscale 已发现路由，等待批准"))
            } else {
                ("pending", Some("Headscale 尚未发现该路由"))
            }
        };
        transaction.execute(
            "INSERT INTO gateway_route_applies
             (device_id, network_id, site_link_id, desired_revision, local_status,
              control_plane_status, remote_status, applied_prefix, last_error,
              last_checked_at, updated_at)
             VALUES (?1, ?2, '', ?3, CASE WHEN ?4 = 'disabled' THEN 'disabled' ELSE 'pending' END,
                     ?4, CASE WHEN ?4 = 'disabled' THEN 'disabled' ELSE 'pending' END,
                     NULL, ?5,
                     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
             ON CONFLICT(device_id, network_id, site_link_id) DO UPDATE SET
             desired_revision = excluded.desired_revision,
             local_status = CASE WHEN excluded.control_plane_status = 'disabled'
                                  THEN 'disabled' ELSE local_status END,
             remote_status = CASE WHEN excluded.control_plane_status = 'disabled'
                                  THEN 'disabled' ELSE remote_status END,
             applied_prefix = CASE WHEN excluded.control_plane_status = 'disabled'
                                   THEN NULL ELSE applied_prefix END,
             control_plane_status = excluded.control_plane_status,
             last_error = excluded.last_error,
             last_checked_at = CURRENT_TIMESTAMP,
             updated_at = CURRENT_TIMESTAMP",
            rusqlite::params![
                device_id,
                route.network_id,
                route.revision,
                control_status,
                error
            ],
        )?;
        transaction.execute(
            "UPDATE gateway_network_states SET apply_status = CASE
                 WHEN ?3 = 0 THEN 'disabled'
                 WHEN EXISTS (SELECT 1 FROM gateway_route_applies a
                              WHERE a.device_id = ?1 AND a.network_id = ?2
                                AND a.site_link_id = '' AND a.local_status = 'applied'
                                AND a.control_plane_status = 'serving')
                 THEN 'ready' ELSE 'checking' END,
             applied_prefix = CASE WHEN ?3 = 0 THEN NULL ELSE applied_prefix END,
             apply_error = CASE WHEN ?3 = 0 THEN NULL ELSE ?4 END,
             last_checked_at = CURRENT_TIMESTAMP,
             updated_at = CURRENT_TIMESTAMP WHERE site_network_id = ?2",
            rusqlite::params![
                device_id,
                route.network_id,
                if route.enabled { 1 } else { 0 },
                error
            ],
        )?;
    }
    // Site Gateway 收到的是“对端网段”。Headscale 的 Serving 状态属于
    // 对端发布节点的本地路由，不能由 Agent 的 accept-routes ACK 伪造；
    // 这里把对端本地路由的控制平面状态投影到当前设备的 site_link 路由行。
    let site_routes: Vec<(String, String, String, i64, bool)> = {
        let mut statement = transaction.prepare(
            "SELECT l.id, remote_n.id, remote_n.publisher_device_id,
                    MAX(l.apply_revision, remote_g.desired_revision),
                    (l.enabled <> 0 AND local_n.enabled <> 0 AND remote_n.enabled <> 0)
             FROM site_links l
             JOIN site_link_networks local_link ON local_link.site_link_id = l.id
             JOIN site_networks local_n ON local_n.id = local_link.site_network_id
             JOIN site_link_networks remote_link
               ON remote_link.site_link_id = l.id
              AND remote_link.side <> local_link.side
             JOIN site_networks remote_n ON remote_n.id = remote_link.site_network_id
             JOIN gateway_network_states remote_g
               ON remote_g.site_network_id = remote_n.id
             WHERE local_n.publisher_device_id = ?1",
        )?;
        let rows = statement.query_map([device_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get::<_, i64>(4)? != 0,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (link_id, remote_network_id, remote_device_id, revision, enabled) in site_routes {
        let remote_route: Option<(String, String, Option<String>)> = transaction
            .query_row(
                "SELECT local_status, control_plane_status, last_error
                 FROM gateway_route_applies
                 WHERE device_id = ?1 AND network_id = ?2 AND site_link_id = ''",
                rusqlite::params![remote_device_id, remote_network_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let (control_status, error): (String, Option<String>) = if !enabled {
            ("disabled".to_owned(), None)
        } else if let Some((local_status, control_status, error)) = remote_route {
            if local_status == "applied" && control_status == "serving" {
                ("serving".to_owned(), None)
            } else if control_status == "failed" {
                ("failed".to_owned(), error)
            } else {
                (control_status, error)
            }
        } else {
            (
                "pending".to_owned(),
                Some("等待对端网关发布本地网络".to_owned()),
            )
        };
        transaction.execute(
            "INSERT INTO gateway_route_applies
             (device_id, network_id, site_link_id, desired_revision, local_status,
              control_plane_status, remote_status, applied_prefix, last_error,
              last_checked_at, updated_at)
             VALUES (?1, ?2, ?3, ?4,
                     CASE WHEN ?5 = 'disabled' THEN 'disabled' ELSE 'pending' END,
                     ?5,
                     CASE WHEN ?5 = 'disabled' THEN 'disabled' ELSE 'pending' END,
                     NULL, ?6,
                     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
             ON CONFLICT(device_id, network_id, site_link_id) DO UPDATE SET
             desired_revision = excluded.desired_revision,
             local_status = CASE WHEN excluded.control_plane_status = 'disabled'
                                  THEN 'disabled' ELSE local_status END,
             control_plane_status = excluded.control_plane_status,
             remote_status = CASE WHEN excluded.control_plane_status = 'disabled'
                                  THEN 'disabled' ELSE remote_status END,
             applied_prefix = CASE WHEN excluded.control_plane_status = 'disabled'
                                   THEN NULL ELSE applied_prefix END,
             last_error = excluded.last_error,
             last_checked_at = CURRENT_TIMESTAMP,
             updated_at = CURRENT_TIMESTAMP",
            rusqlite::params![
                device_id,
                remote_network_id,
                link_id,
                revision,
                control_status,
                error,
            ],
        )?;
    }
    refresh_site_link_apply_status(&transaction)?;
    transaction.commit()?;
    Ok(())
}

/// 从 Nexo Desired State 生成显式 tenant→tenant Grants 并推送 Headscale。
/// 网络关闭时对应前缀从下一版策略中消失，但 Mesh 连接本身不受影响。
async fn reconcile_headscale_policy(state: &AppState) -> Result<()> {
    let grants = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut grants = Vec::new();
        let mut tenant_users = HashMap::new();
        {
            let mut statement = connection.prepare(
                "SELECT tenant_id, headscale_user_id FROM mesh_tenant_mappings
                 WHERE status = 'ready'",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (tenant_id, _user_id) = row?;
                // Headscale Policy 使用用户名称并要求以 `@` 结尾；API 返回的
                // 数字 ID 只适合数据库关联和 Pre-auth Key，不可直接当策略主体。
                // 入网时用户名称由同一规则创建，因此这里保持稳定、可审计的选择器。
                tenant_users.insert(tenant_id.clone(), format!("nexo-{tenant_id}@"));
            }
        }
        let mut statement = connection.prepare(
            "SELECT tenant_id, desired_prefix FROM site_networks n
             JOIN gateway_network_states g ON g.site_network_id = n.id
             WHERE n.enabled = 1",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (tenant_id, prefix) = row?;
            if let Some(source) = tenant_users.get(&tenant_id) {
                grants.push(policy::PolicyGrant {
                    source_tenant: tenant_id.clone(),
                    target_tenant: tenant_id,
                    sources: vec![source.clone()],
                    destinations: vec![prefix],
                });
            }
        }
        let mut statement = connection.prepare(
            "SELECT l.tenant_id, lg.desired_prefix, rg.desired_prefix
             FROM site_links l
             JOIN site_link_networks ln ON ln.site_link_id = l.id AND ln.side = 'left'
             JOIN site_link_networks rn ON rn.site_link_id = l.id AND rn.side = 'right'
             JOIN site_networks left_n ON left_n.id = ln.site_network_id
             JOIN site_networks right_n ON right_n.id = rn.site_network_id
             JOIN gateway_network_states lg ON lg.site_network_id = ln.site_network_id
             JOIN gateway_network_states rg ON rg.site_network_id = rn.site_network_id
             WHERE l.enabled = 1 AND left_n.enabled = 1 AND right_n.enabled = 1",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (tenant_id, left_prefix, right_prefix) = row?;
            if tenant_users.contains_key(&tenant_id) {
                // 一个 Site Link 明确拆成两个方向，便于将来跨租户策略审计和
                // 定向撤销；不使用隐含的全网互通或 `* -> *`。
                grants.push(policy::PolicyGrant {
                    source_tenant: tenant_id.clone(),
                    target_tenant: tenant_id.clone(),
                    sources: vec![left_prefix.clone()],
                    destinations: vec![right_prefix.clone()],
                });
                grants.push(policy::PolicyGrant {
                    source_tenant: tenant_id.clone(),
                    target_tenant: tenant_id,
                    sources: vec![right_prefix],
                    destinations: vec![left_prefix],
                });
            }
        }
        grants
    };
    let document = policy::generate_policy(&grants);
    state.headscale.set_policy(&document).await
}

fn schedule_policy_reconcile(state: &AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(error) = reconcile_headscale_policy(&state).await {
            tracing::warn!("Headscale Policy 收敛失败，将在下次重新检测重试：{error:#}");
        }
    });
}

/// 后台恢复协调器；只读取 Nexo 自己的 Desired State，不在内存中缓存一次性任务。
///
/// 周期较长是为了避免在 Headscale 暂时不可用时形成请求风暴；控制通道收到新
/// revision 时仍会立即触发一次协调，后台任务只负责重启和丢包后的最终收敛。
fn spawn_mesh_reconciliation(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let device_ids = match state.db.lock() {
                Ok(connection) => {
                    let mut statement = match connection.prepare(
                        "SELECT nexo_device_id FROM mesh_identities
                         WHERE state = 'ready' AND online = 1 ORDER BY nexo_device_id",
                    ) {
                        Ok(statement) => statement,
                        Err(error) => {
                            tracing::warn!("后台组网协调读取身份失败：{error:#}");
                            continue;
                        }
                    };
                    let collected = match statement.query_map([], |row| row.get::<_, String>(0)) {
                        Ok(rows) => rows.filter_map(Result::ok).collect::<Vec<_>>(),
                        Err(error) => {
                            tracing::warn!("后台组网协调读取设备失败：{error:#}");
                            continue;
                        }
                    };
                    collected
                }
                Err(_) => {
                    tracing::warn!("后台组网协调无法取得数据库锁");
                    continue;
                }
            };
            for device_id in device_ids {
                if let Err(error) = reconcile_headscale_routes(&state, &device_id).await {
                    tracing::debug!(device_id = %device_id, "后台 Headscale 路由协调将在下周期重试：{error:#}");
                }
            }
            if let Err(error) = reconcile_headscale_policy(&state).await {
                tracing::debug!("后台 Headscale Policy 协调将在下周期重试：{error:#}");
            }
        }
    })
}

#[derive(Debug, Clone)]
struct GatewayRouteApplyInput {
    network_id: String,
    prefix: String,
    revision: i64,
    enabled: bool,
    local_applied: bool,
}

/// 当前开发阶段暂用显式 Bootstrap Token 保护管理端点。
///
/// 后续接入管理员 Session 后会替换这里，不能因为 Web UI 尚未完成就开放
/// 未认证的凭证创建和审批接口。
fn require_admin(headers: &HeaderMap) -> Result<(), ApiError> {
    let configured = env::var("NEXO_ADMIN_TOKEN").map_err(|_| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "尚未配置 NEXO_ADMIN_TOKEN，管理接口暂不可用",
        )
    })?;
    if configured.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "NEXO_ADMIN_TOKEN 不能为空，管理接口暂不可用",
        ));
    }
    let supplied = headers
        .get("x-nexo-admin-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "缺少管理员凭证"))?;
    if supplied != configured {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "管理员凭证无效"));
    }
    Ok(())
}

/// 创建一个 15 分钟（或显式指定时长）的待入网凭证。
async fn create_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateEnrollmentRequest>,
) -> Result<Json<CreateEnrollmentResponse>, ApiError> {
    require_admin(&headers)?;
    if request.tenant_id.trim().is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "tenant_id 不能为空"));
    }
    let ttl_seconds = request.ttl_seconds.unwrap_or(900);
    let now = unix_now();
    let token = EnrollmentToken::generate(now, ttl_seconds)
        .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.to_string()))?;
    let enrollment_id = Uuid::new_v4().to_string();
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let tenant_exists: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM tenants WHERE id = ?1",
            [&request.tenant_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查租户"))?;
    if tenant_exists == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "租户不存在"));
    }
    if let Some(site_id) = &request.site_id {
        let site_exists: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sites WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![site_id, request.tenant_id],
                |row| row.get(0),
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查站点"))?;
        if site_exists == 0 {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "站点不存在或不属于该租户",
            ));
        }
    }
    connection
        .execute(
            "INSERT INTO pending_enrollments
             (id, tenant_id, site_id, token_digest, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                enrollment_id,
                request.tenant_id,
                request.site_id,
                token.digest,
                token.expires_at
            ],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存入网凭证"))?;
    Ok(Json(CreateEnrollmentResponse {
        enrollment_id,
        token: token.secret,
        expires_at: token.expires_at,
    }))
}

/// 返回不含 token 明文的入网请求状态。
async fn get_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<EnrollmentStatusResponse>, ApiError> {
    require_admin(&headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let result = connection.query_row(
        "SELECT status, expires_at, device_id FROM pending_enrollments WHERE id = ?1",
        [&id],
        |row| {
            let status: String = row.get(0)?;
            let expires_at = row.get(1)?;
            let device_id = row.get(2)?;
            Ok((parse_enrollment_status(&status), expires_at, device_id))
        },
    );
    let (mut status, expires_at, device_id) =
        result.map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "入网请求不存在"))?;
    if matches!(
        status,
        EnrollmentStatus::Pending | EnrollmentStatus::AwaitingApproval
    ) && unix_now() >= expires_at
    {
        connection
            .execute(
                "UPDATE pending_enrollments SET status = 'expired' WHERE id = ?1",
                [&id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新入网过期状态")
            })?;
        status = EnrollmentStatus::Expired;
    }
    Ok(Json(EnrollmentStatusResponse {
        enrollment_id: id,
        status,
        expires_at,
        device_id,
    }))
}

/// 返回所有入网请求，供 Web 的“批准设备”列表使用；敏感 token 永不返回。
async fn list_enrollments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<EnrollmentListItem>>, ApiError> {
    require_admin(&headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT id, status, tenant_id, site_id, requested_name, requested_os,
                    requested_architecture, requested_agent_version, expires_at, device_id
             FROM pending_enrollments ORDER BY created_at DESC, id ASC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取入网请求列表"))?;
    let rows = statement
        .query_map([], |row| {
            let status: String = row.get(1)?;
            Ok(EnrollmentListItem {
                enrollment_id: row.get(0)?,
                status: parse_enrollment_status(&status),
                tenant_id: row.get(2)?,
                site_id: row.get(3)?,
                device_name: row.get(4)?,
                os: row.get(5)?,
                architecture: row.get(6)?,
                agent_version: row.get(7)?,
                expires_at: row.get(8)?,
                device_id: row.get(9)?,
            })
        })
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取入网请求列表"))?;
    rows.map(|row| {
        row.map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "入网请求数据格式无效"))
    })
    .collect::<Result<Vec<_>, _>>()
    .map(Json)
}

/// 组网组件状态只返回产品状态，不把 Headscale 名称、版本或 API Key 暴露给 Web。
async fn mesh_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MeshStatusResponse>, ApiError> {
    require_admin(&headers)?;
    let configured_version = env::var("NEXO_HEADSCALE_VERSION")
        .unwrap_or_else(|_| headscale::HEADSCALE_VERSION.to_owned());
    let tailscale_version = env::var("NEXO_TAILSCALE_VERSION")
        .unwrap_or_else(|_| headscale::TAILSCALE_VERSION.to_owned());
    if configured_version != headscale::HEADSCALE_VERSION
        || tailscale_version != headscale::TAILSCALE_VERSION
    {
        return Ok(Json(MeshStatusResponse {
            status: headscale::MeshComponentStatus::VersionIncompatible,
            message: "组网组件版本不兼容，请更新 Nexo Server 镜像".to_owned(),
        }));
    }
    match state.headscale.health().await {
        Ok(true) => Ok(Json(MeshStatusResponse {
            status: headscale::MeshComponentStatus::Normal,
            message: "异地组网服务正常".to_owned(),
        })),
        Ok(false) => Ok(Json(MeshStatusResponse {
            status: headscale::MeshComponentStatus::Abnormal,
            message: "异地组网服务暂不可用".to_owned(),
        })),
        Err(_) => Ok(Json(MeshStatusResponse {
            status: headscale::MeshComponentStatus::Starting,
            message: "异地组网服务正在启动或等待连接".to_owned(),
        })),
    }
}

/// 管理员批准已提交的 Agent 请求，并为其 CSR 签发客户端证书。
async fn approve_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<EnrollmentStatusResponse>, ApiError> {
    require_admin(&headers)?;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始入网审批事务"))?;
    let (
        tenant_id,
        site_id,
        name,
        os,
        architecture,
        agent_version,
        capabilities,
        csr_pem,
        status,
        expires_at,
    ) = transaction
        .query_row(
            "SELECT tenant_id, site_id, requested_name, requested_os,
                    requested_architecture, requested_agent_version,
                    requested_capabilities_json, requested_csr_pem, status, expires_at
             FROM pending_enrollments WHERE id = ?1",
            [&id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "入网请求不存在"))?;
    if status != "awaiting_approval" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "入网请求当前不在待审批状态",
        ));
    }
    if unix_now() >= expires_at {
        transaction
            .execute(
                "UPDATE pending_enrollments SET status = 'expired' WHERE id = ?1",
                [&id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新入网过期状态")
            })?;
        transaction.commit().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交入网过期状态")
        })?;
        return Err(ApiError::new(StatusCode::CONFLICT, "入网请求已过期"));
    }
    let name = name.ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "入网请求缺少设备名称"))?;
    let csr_pem = csr_pem.ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "入网请求缺少设备 CSR，请让 Agent 重新提交",
        )
    })?;
    let device_id = Uuid::new_v4().to_string();
    let ca = load_server_ca(&transaction)
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let identity = issue_device_identity(&ca, &csr_pem, &device_id)
        .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO devices
             (id, tenant_id, site_id, name, os, architecture, agent_version,
              status, capabilities_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8)",
            rusqlite::params![
                device_id,
                tenant_id,
                site_id,
                name,
                os,
                architecture,
                agent_version,
                capabilities,
            ],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法创建设备记录"))?;
    transaction
        .execute(
            "INSERT INTO device_identities
             (device_id, certificate_pem, certificate_fingerprint, issued_at, expires_at)
             VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP, ?4)",
            rusqlite::params![
                device_id,
                identity.certificate_pem,
                identity.fingerprint,
                identity.expires_at,
            ],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存设备身份"))?;
    transaction
        .execute(
            "UPDATE pending_enrollments
             SET status = 'approved', approved_at = CURRENT_TIMESTAMP, device_id = ?2
             WHERE id = ?1 AND status = 'awaiting_approval'",
            rusqlite::params![id, device_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新入网审批状态"))?;
    transaction
        .commit()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交入网审批事务"))?;
    drop(connection);
    // 证书审批与组网入网解耦：Headscale 暂不可用时设备仍可领取 Nexo
    // 证书，UI 显示“组网加入中”，后台任务会继续重试。
    let mesh_state = state.clone();
    let mesh_device_id = device_id.clone();
    let mesh_tenant_id = tenant_id.clone();
    let mesh_name = name.clone();
    tokio::spawn(async move {
        if let Err(error) =
            start_mesh_enrollment(&mesh_state, &mesh_device_id, &mesh_tenant_id, &mesh_name).await
        {
            tracing::warn!(device_id = %mesh_device_id, "无法立即创建组网入网密钥：{error:#}");
        }
    });
    Ok(Json(EnrollmentStatusResponse {
        enrollment_id: id,
        status: EnrollmentStatus::Approved,
        expires_at,
        device_id: Some(device_id),
    }))
}

/// 为已批准设备创建短时、单次、非临时的 Headscale Pre-auth Key。
///
/// 只把 Key ID 写入数据库，明文存放在进程内存的 offer 中；Agent 通过 mTLS
/// 控制连接领取后立即确认，重启恢复时再由 Headscale API 重新发现未使用 Key。
async fn start_mesh_enrollment(
    state: &AppState,
    device_id: &str,
    tenant_id: &str,
    device_name: &str,
) -> Result<()> {
    start_mesh_enrollment_with_reset(state, device_id, tenant_id, device_name, false).await
}

/// 身份恢复专用的重新入网入口；只有显式恢复流程才允许 Agent 清理旧状态。
async fn start_mesh_enrollment_with_reset(
    state: &AppState,
    device_id: &str,
    tenant_id: &str,
    device_name: &str,
    reset: bool,
) -> Result<()> {
    let _lock = state.mesh_enrollment_lock.lock().await;
    start_mesh_enrollment_locked(state, device_id, tenant_id, device_name, reset).await
}

async fn start_mesh_enrollment_locked(
    state: &AppState,
    device_id: &str,
    tenant_id: &str,
    device_name: &str,
    reset: bool,
) -> Result<()> {
    // 审批回调和设备首次心跳可能同时到达；锁内再次检查，避免第二条路径
    // 在第一条路径已经发布邀请后又创建一把新的 Pre-auth Key。
    if current_mesh_offer(state, device_id).await.is_some() {
        return Ok(());
    }
    let user_mapping: Option<String> = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT headscale_user_id FROM mesh_tenant_mappings WHERE tenant_id = ?1
                 AND status = 'ready'",
                [tenant_id],
                |row| row.get(0),
            )
            .optional()?
    };
    let user_id = if let Some(user_id) = user_mapping {
        user_id
    } else {
        let user = state
            .headscale
            .ensure_user(&format!("nexo-{tenant_id}"))
            .await
            .context("Headscale 租户用户尚未准备好")?;
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        connection.execute(
            "INSERT INTO mesh_tenant_mappings
             (tenant_id, headscale_user_id, status, updated_at)
             VALUES (?1, ?2, 'ready', CURRENT_TIMESTAMP)
             ON CONFLICT(tenant_id) DO UPDATE SET
             headscale_user_id = excluded.headscale_user_id,
             status = 'ready', last_error = NULL, updated_at = CURRENT_TIMESTAMP",
            rusqlite::params![tenant_id, user.id],
        )?;
        user.id
    };
    let old_key_ids: Vec<String> = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut statement = connection.prepare(
            "SELECT headscale_pre_auth_key_id FROM mesh_enrollment_attempts
             WHERE nexo_device_id = ?1 AND state = 'issued'",
        )?;
        let ids = statement
            .query_map([device_id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids
    };
    for old_key_id in old_key_ids {
        state
            .headscale
            .expire_pre_auth_key(&old_key_id)
            .await
            .with_context(|| format!("旧组网入网密钥 {old_key_id} 尚未吊销，暂不重发"))?;
    }
    let expires_at = unix_now().saturating_add(15 * 60);
    let expiration = format_headscale_expiration(expires_at.max(0) as u64);
    let key = state
        .headscale
        .create_pre_auth_key(&user_id, &expiration)
        .await
        .context("Headscale 未能创建设备入网密钥")?;
    let plaintext = key
        .key
        .clone()
        .filter(|value| !value.trim().is_empty())
        .context("Headscale 创建密钥响应缺少明文 Key")?;
    let attempt_id = Uuid::new_v4().to_string();
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        connection.execute(
            "UPDATE mesh_enrollment_attempts SET state = 'revoked',
             updated_at = CURRENT_TIMESTAMP WHERE nexo_device_id = ?1 AND state = 'issued'",
            [device_id],
        )?;
        connection.execute(
            "INSERT INTO mesh_enrollment_attempts
             (id, nexo_device_id, tenant_id, headscale_pre_auth_key_id, expires_at, state)
             VALUES (?1, ?2, ?3, ?4, ?5, 'issued')",
            rusqlite::params![attempt_id, device_id, tenant_id, key.id, expires_at],
        )?;
    }
    let offer = MeshEnrollmentOffer {
        endpoint: env::var("NEXO_MESH_ENDPOINT")
            .or_else(|_| env::var("NEXO_HEADSCALE_URL"))
            .unwrap_or_else(|_| "http://headscale:8080".to_owned()),
        auth_key: plaintext,
        auth_key_id: key.id,
        hostname: if device_name.trim().is_empty() {
            format!("nexo-{device_id}")
        } else {
            device_name.to_owned()
        },
        reset,
        tenant_id: Some(tenant_id.to_owned()),
    };
    state
        .mesh_offers
        .lock()
        .await
        .insert(device_id.to_owned(), offer);
    tracing::info!(device_id, "已创建一次性组网入网邀请");
    Ok(())
}

fn format_headscale_expiration(epoch_seconds: u64) -> String {
    // Headscale 接受 RFC3339；这里使用 UTC 的 Unix 秒转换，避免引入额外时间库。
    let date = time::OffsetDateTime::from_unix_timestamp(epoch_seconds as i64)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    date.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "2099-01-01T00:00:00Z".to_owned())
}

/// Agent 使用一次性 token 提交设备信息；提交后进入待审批状态。
async fn enroll_agent(
    State(state): State<AppState>,
    Json(request): Json<AgentEnrollmentRequest>,
) -> Result<Json<AgentEnrollmentResponse>, ApiError> {
    if request.token.trim().is_empty() || request.device_name.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "token 和 device_name 不能为空",
        ));
    }
    let now = unix_now();
    let digest = EnrollmentToken::digest(&request.token);
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let record = connection.query_row(
        "SELECT id, expires_at, status FROM pending_enrollments WHERE token_digest = ?1",
        [&digest],
        |row| {
            let id = row.get::<_, String>(0)?;
            let expires_at = row.get::<_, i64>(1)?;
            let status = row.get::<_, String>(2)?;
            Ok((id, expires_at, status))
        },
    );
    let (enrollment_id, expires_at, status) =
        record.map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "入网凭证无效或已被删除"))?;
    if now >= expires_at {
        connection
            .execute(
                "UPDATE pending_enrollments SET status = 'expired' WHERE id = ?1",
                [&enrollment_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新入网过期状态")
            })?;
        return Err(ApiError::new(StatusCode::GONE, "入网凭证已过期"));
    }
    EnrollmentToken::verify(&request.token, &digest, expires_at, now)
        .map_err(|error| ApiError::new(StatusCode::UNAUTHORIZED, error.to_string()))?;
    if status != "pending" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "入网凭证已被使用或不在可提交状态",
        ));
    }
    let capabilities = serde_json::to_string(&request.capabilities)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "设备能力格式无效"))?;
    let changed = connection
        .execute(
            "UPDATE pending_enrollments SET
             status = 'awaiting_approval', requested_name = ?2,
             requested_os = ?3, requested_architecture = ?4,
             requested_agent_version = ?5, requested_capabilities_json = ?6,
             requested_csr_pem = ?7
             WHERE id = ?1 AND status = 'pending'",
            rusqlite::params![
                enrollment_id,
                request.device_name,
                request.os,
                request.architecture,
                request.agent_version,
                capabilities,
                request.csr_pem,
            ],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存设备入网请求"))?;
    if changed == 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "入网凭证已被其他请求使用",
        ));
    }
    Ok(Json(AgentEnrollmentResponse {
        enrollment_id,
        status: EnrollmentStatus::AwaitingApproval,
        device_id: None,
        server_endpoint: None,
        certificate_pem: None,
        ca_certificate_pem: None,
        message: "设备信息已提交，等待管理员批准；批准后 Agent 将领取设备证书".to_owned(),
    }))
}

/// Agent 在管理员批准后轮询领取设备证书。
///
/// 轮询仍需携带一次性 token，但不会重新执行入网提交；成功领取后 token 立即
/// 标记为 consumed，之后控制通道必须改用设备证书认证。
async fn poll_agent_enrollment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(request): Json<AgentEnrollmentPollRequest>,
) -> Result<Json<AgentEnrollmentPollResponse>, ApiError> {
    if request.token.trim().is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "token 不能为空"));
    }
    let now = unix_now();
    let digest = EnrollmentToken::digest(&request.token);
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let (stored_digest, status, expires_at, device_id) = connection
        .query_row(
            "SELECT token_digest, status, expires_at, device_id
             FROM pending_enrollments WHERE id = ?1",
            [&id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "入网请求不存在"))?;
    if stored_digest != digest {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "入网凭证无效"));
    }
    if now >= expires_at {
        if matches!(status.as_str(), "pending" | "awaiting_approval") {
            connection
                .execute(
                    "UPDATE pending_enrollments SET status = 'expired'
                     WHERE id = ?1 AND status IN ('pending', 'awaiting_approval')",
                    [&id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新入网过期状态")
                })?;
        }
        return Err(ApiError::new(StatusCode::GONE, "入网请求已过期"));
    }
    EnrollmentToken::verify(&request.token, &stored_digest, expires_at, now)
        .map_err(|error| ApiError::new(StatusCode::UNAUTHORIZED, error.to_string()))?;

    match status.as_str() {
        "awaiting_approval" => Ok(Json(AgentEnrollmentPollResponse {
            enrollment_id: id,
            status: EnrollmentStatus::AwaitingApproval,
            device_id: None,
            certificate_pem: None,
            ca_certificate_pem: None,
            message: "设备仍在等待管理员批准".to_owned(),
        })),
        "approved" => {
            let device_id = device_id.ok_or_else(|| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "已批准请求缺少设备身份")
            })?;
            let (certificate_pem, ca_certificate_pem): (String, String) = connection
                .query_row(
                    "SELECT i.certificate_pem, s.ca_certificate_pem
                     FROM device_identities i CROSS JOIN server_identity s
                     WHERE i.device_id = ?1 AND i.revoked_at IS NULL",
                    [&device_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::CONFLICT, "设备身份尚未准备好，请稍后重试")
                })?;
            let changed = connection
                .execute(
                    "UPDATE pending_enrollments
                     SET status = 'consumed', consumed_at = CURRENT_TIMESTAMP
                     WHERE id = ?1 AND status = 'approved'",
                    [&id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法确认身份领取状态")
                })?;
            if changed == 0 {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "设备身份已被领取，请使用已保存的设备证书",
                ));
            }
            Ok(Json(AgentEnrollmentPollResponse {
                enrollment_id: id,
                status: EnrollmentStatus::Approved,
                device_id: Some(device_id),
                certificate_pem: Some(certificate_pem),
                ca_certificate_pem: Some(ca_certificate_pem),
                message: "设备身份已签发，请使用设备证书建立安全连接".to_owned(),
            }))
        }
        "pending" => Err(ApiError::new(
            StatusCode::CONFLICT,
            "Agent 尚未提交设备信息",
        )),
        "consumed" => Err(ApiError::new(
            StatusCode::CONFLICT,
            "设备身份已领取，请使用已保存的设备证书",
        )),
        "expired" => Err(ApiError::new(StatusCode::GONE, "入网请求已过期")),
        "revoked" => Err(ApiError::new(StatusCode::FORBIDDEN, "入网请求已撤销")),
        _ => Err(ApiError::new(StatusCode::CONFLICT, "入网请求状态无效")),
    }
}

/// 创建共享本地网络的 Desired State；不会在 Agent 未确认前伪造 Applied State。
async fn create_site_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSiteNetworkRequest>,
) -> Result<Json<SiteNetworkResponse>, ApiError> {
    require_admin(&headers)?;
    if request.tenant_id.trim().is_empty()
        || request.site_id.trim().is_empty()
        || request.name.trim().is_empty()
        || request.publisher_device_id.trim().is_empty()
        || request.interface_id.trim().is_empty()
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "租户、站点、名称、设备和网卡不能为空",
        ));
    }
    let prefix: IpNet = request
        .prefix
        .parse()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "本地网络地址不是有效 CIDR"))?;
    validate_published_network(prefix).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("本地网络不能共享：{error}"),
        )
    })?;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let site_exists: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sites WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![request.site_id, request.tenant_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查站点"))?;
    if site_exists == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "站点不存在或不属于该租户",
        ));
    }
    ensure_gateway_device(
        &connection,
        &request.tenant_id,
        &request.site_id,
        &request.publisher_device_id,
        &request.interface_id,
        prefix,
        false,
    )?;
    let duplicate: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM gateway_network_states g
             JOIN site_networks n ON n.id = g.site_network_id
             WHERE n.tenant_id = ?1 AND n.site_id = ?2 AND g.desired_prefix = ?3",
            rusqlite::params![request.tenant_id, request.site_id, prefix.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查重复网络"))?;
    if duplicate > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "该站点已经存在相同的共享网络",
        ));
    }
    let id = Uuid::new_v4().to_string();
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始共享网络事务"))?;
    transaction
        .execute(
            "INSERT INTO site_networks
             (id, tenant_id, site_id, name, publisher_device_id, interface_id,
              address_family, source, enabled, apply_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'direct_interface', 1, 'checking')",
            rusqlite::params![
                id,
                request.tenant_id,
                request.site_id,
                request.name,
                request.publisher_device_id,
                request.interface_id,
                if matches!(prefix, IpNet::V4(_)) {
                    "ipv4"
                } else {
                    "ipv6"
                },
            ],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存共享网络"))?;
    transaction
        .execute(
            "INSERT INTO gateway_network_states
             (site_network_id, desired_prefix, apply_status, desired_revision)
             VALUES (?1, ?2, 'checking', 1)",
            rusqlite::params![id, prefix.to_string()],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存网关期望状态"))?;
    write_audit_event(
        &transaction,
        &request.tenant_id,
        "SUBNET_PUBLISHED",
        "site_network",
        &id,
    )?;
    transaction
        .commit()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交共享网络事务"))?;
    schedule_policy_reconcile(&state);
    Ok(Json(read_site_network_response(&connection, &id)?))
}

/// 返回所有共享本地网络，供 Web 统一展示 Subnet Gateway 的应用状态。
async fn list_site_networks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SiteNetworkResponse>>, ApiError> {
    require_admin(&headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let ids = {
        let mut statement = connection
            .prepare(
                "SELECT n.id FROM site_networks n
                 JOIN gateway_network_states g ON g.site_network_id = n.id
                 ORDER BY n.updated_at DESC, n.id ASC",
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取共享网络列表")
            })?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取共享网络列表"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "共享网络数据格式无效")
            })?;
        rows
    };
    ids.iter()
        .map(|id| read_site_network_response(&connection, id))
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

/// 查询共享网络的 Desired / Applied 状态，供 Web 明确显示“正在检查”或失败原因。
async fn get_site_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SiteNetworkResponse>, ApiError> {
    require_admin(&headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    Ok(Json(read_site_network_response(&connection, &id)?))
}

/// 关闭共享本地网络，使 Agent 收到撤销路由的最新 revision。
async fn disable_site_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SiteNetworkResponse>, ApiError> {
    set_site_network_enabled(state, headers, id, false).await
}

/// 重新启用共享本地网络，使 Agent 收到重新发布路由的最新 revision。
async fn enable_site_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SiteNetworkResponse>, ApiError> {
    set_site_network_enabled(state, headers, id, true).await
}

/// 事务性切换共享网络开关，并把关联站点互联退回检查状态。
async fn set_site_network_enabled(
    state: AppState,
    headers: HeaderMap,
    id: String,
    enabled: bool,
) -> Result<Json<SiteNetworkResponse>, ApiError> {
    require_admin(&headers)?;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始共享网络事务"))?;
    let (tenant_id, current_enabled): (String, i64) = transaction
        .query_row(
            "SELECT tenant_id, enabled FROM site_networks WHERE id = ?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "共享网络不存在"))?;
    if (current_enabled != 0) != enabled {
        transaction
            .execute(
                "UPDATE site_networks
                 SET enabled = ?1, apply_status = 'checking', apply_error = NULL,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?2",
                rusqlite::params![if enabled { 1 } else { 0 }, id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新共享网络状态")
            })?;
        transaction
            .execute(
                "UPDATE gateway_network_states
                 SET desired_revision = desired_revision + 1,
                     apply_status = 'checking', applied_prefix = NULL,
                     apply_error = NULL, updated_at = CURRENT_TIMESTAMP
                 WHERE site_network_id = ?1",
                [&id],
            )
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法生成网关撤销 revision",
                )
            })?;
        transaction
            .execute(
                "UPDATE site_links SET apply_status = 'checking', apply_error = NULL,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id IN (
                     SELECT DISTINCT site_link_id FROM site_link_networks
                     WHERE site_network_id = ?1
                 )",
                [&id],
            )
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法刷新关联站点互联状态",
                )
            })?;
        write_audit_event(
            &transaction,
            &tenant_id,
            if enabled {
                "SUBNET_ENABLED"
            } else {
                "SUBNET_REMOVED"
            },
            "site_network",
            &id,
        )?;
    }
    transaction
        .commit()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交共享网络事务"))?;
    schedule_policy_reconcile(&state);
    Ok(Json(read_site_network_response(&connection, &id)?))
}

/// 从 Nexo 数据库读取共享网络的完整 Desired / Applied 状态。
fn read_site_network_response(
    connection: &Connection,
    id: &str,
) -> Result<SiteNetworkResponse, ApiError> {
    let response = connection
        .query_row(
            "SELECT n.id, n.tenant_id, n.site_id, s.name, n.name,
                    n.publisher_device_id, d.name, n.interface_id,
                    g.desired_prefix, g.applied_prefix,
                    g.desired_revision, n.enabled, g.apply_status, g.apply_error
             FROM site_networks n JOIN gateway_network_states g
             ON g.site_network_id = n.id
             JOIN sites s ON s.id = n.site_id
             JOIN devices d ON d.id = n.publisher_device_id
             WHERE n.id = ?1",
            [id],
            |row| {
                Ok(SiteNetworkResponse {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    site_id: row.get(2)?,
                    site_name: row.get(3)?,
                    name: row.get(4)?,
                    publisher_device_id: row.get(5)?,
                    publisher_device_name: row.get(6)?,
                    interface_id: row.get(7)?,
                    gateway_address: None,
                    desired_prefix: row.get(8)?,
                    applied_prefix: row.get(9)?,
                    desired_revision: row.get(10)?,
                    enabled: row.get::<_, i64>(11)? != 0,
                    apply_status: parse_apply_status(&row.get::<_, String>(12)?),
                    apply_error: row.get(13)?,
                    health_status: GatewayHealthStatus::Degraded,
                    health_error: None,
                })
            },
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "共享网络不存在"))
        .and_then(|mut response| {
            response.gateway_address = find_gateway_address(
                connection,
                &response.publisher_device_id,
                &response.interface_id,
                &response.desired_prefix,
            )?;
            let (health_status, health_error) = gateway_network_health(
                connection,
                &response.publisher_device_id,
                &response.interface_id,
                &response.desired_prefix,
                response.enabled,
                response.apply_status,
                response.apply_error.as_deref(),
            )?;
            response.health_status = health_status;
            response.health_error = health_error;
            Ok(response)
        });
    response
}

/// 返回所有站点互联及其双向静态路由引导，供组网页面展示。
async fn list_site_links(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SiteLinkResponse>>, ApiError> {
    require_admin(&headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let ids = {
        let mut statement = connection
            .prepare("SELECT id FROM site_links ORDER BY updated_at DESC, id ASC")
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点互联列表")
            })?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点互联列表"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "站点互联数据格式无效")
            })?;
        ids
    };
    ids.iter()
        .map(|id| read_site_link_response(&connection, id))
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

/// 创建双向站点互联的 Desired State，并在提交前阻止重叠网段。
async fn create_site_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSiteLinkRequest>,
) -> Result<Json<SiteLinkResponse>, ApiError> {
    require_admin(&headers)?;
    if request.tenant_id.trim().is_empty()
        || request.left_site_id.trim().is_empty()
        || request.right_site_id.trim().is_empty()
        || request.left_network_id.trim().is_empty()
        || request.right_network_id.trim().is_empty()
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "租户、两侧站点和共享网络不能为空",
        ));
    }
    if request.left_site_id == request.right_site_id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "站点互联必须选择两个不同站点",
        ));
    }
    let (left_site_id, left_network_id, right_site_id, right_network_id) =
        if request.left_site_id < request.right_site_id {
            (
                request.left_site_id,
                request.left_network_id,
                request.right_site_id,
                request.right_network_id,
            )
        } else {
            (
                request.right_site_id,
                request.right_network_id,
                request.left_site_id,
                request.left_network_id,
            )
        };
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始站点互联事务"))?;
    let left = load_network_for_link(
        &transaction,
        &request.tenant_id,
        &left_network_id,
        &left_site_id,
    )?;
    let right = load_network_for_link(
        &transaction,
        &request.tenant_id,
        &right_network_id,
        &right_site_id,
    )?;
    let left_prefix: IpNet = left
        .prefix
        .parse()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "左侧共享网络数据无效"))?;
    let right_prefix: IpNet = right
        .prefix
        .parse()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "右侧共享网络数据无效"))?;
    if networks_overlap(left_prefix, right_prefix) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!(
                "网络地址冲突：{} 与 {} 使用了重叠的网络地址，暂时无法建立站点间路由",
                left_prefix, right_prefix
            ),
        ));
    }
    ensure_gateway_device(
        &transaction,
        &request.tenant_id,
        &left_site_id,
        &left.device_id,
        &left.interface_id,
        left_prefix,
        true,
    )?;
    ensure_gateway_device(
        &transaction,
        &request.tenant_id,
        &right_site_id,
        &right.device_id,
        &right.interface_id,
        right_prefix,
        true,
    )?;
    let duplicate: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM site_links
             WHERE tenant_id = ?1 AND left_site_id = ?2 AND right_site_id = ?3",
            rusqlite::params![request.tenant_id, left_site_id, right_site_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查重复站点互联"))?;
    if duplicate > 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "两个站点之间已经存在互联",
        ));
    }
    let id = Uuid::new_v4().to_string();
    transaction
        .execute(
            "INSERT INTO site_links
             (id, tenant_id, left_site_id, right_site_id, enabled, apply_status)
             VALUES (?1, ?2, ?3, ?4, 1, 'checking')",
            rusqlite::params![id, request.tenant_id, left_site_id, right_site_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存站点互联"))?;
    transaction
        .execute(
            "INSERT INTO site_link_networks (site_link_id, site_network_id, side)
             VALUES (?1, ?2, 'left'), (?1, ?3, 'right')",
            rusqlite::params![id, left_network_id, right_network_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存站点网络映射"))?;
    write_audit_event(
        &transaction,
        &request.tenant_id,
        "SITE_LINK_CREATED",
        "site_link",
        &id,
    )?;
    transaction
        .commit()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交站点互联事务"))?;
    schedule_policy_reconcile(&state);
    Ok(Json(read_site_link_response(&connection, &id)?))
}

/// 查询站点互联当前应用状态。
async fn get_site_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SiteLinkResponse>, ApiError> {
    require_admin(&headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    Ok(Json(read_site_link_response(&connection, &id)?))
}

/// 关闭站点互联，使两侧 Agent 撤销对端网段路由。
async fn disable_site_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SiteLinkResponse>, ApiError> {
    set_site_link_enabled(state, headers, id, false).await
}

/// 重新启用站点互联，使两侧 Agent 重新收到对端网段路由。
async fn enable_site_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SiteLinkResponse>, ApiError> {
    set_site_link_enabled(state, headers, id, true).await
}

/// 事务性切换站点互联开关，并递增 link revision 作为路由撤销信号。
async fn set_site_link_enabled(
    state: AppState,
    headers: HeaderMap,
    id: String,
    enabled: bool,
) -> Result<Json<SiteLinkResponse>, ApiError> {
    require_admin(&headers)?;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始站点互联事务"))?;
    let (tenant_id, current_enabled): (String, i64) = transaction
        .query_row(
            "SELECT tenant_id, enabled FROM site_links WHERE id = ?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "站点互联不存在"))?;
    if (current_enabled != 0) != enabled {
        transaction
            .execute(
                "UPDATE site_links
                 SET enabled = ?1,
                     apply_revision = MAX(
                         apply_revision,
                         COALESCE((SELECT MAX(g.desired_revision)
                                   FROM site_link_networks ln
                                   JOIN gateway_network_states g
                                     ON g.site_network_id = ln.site_network_id
                                   WHERE ln.site_link_id = site_links.id), 0)
                     ) + 1,
                     apply_status = 'checking', apply_error = NULL,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?2",
                rusqlite::params![if enabled { 1 } else { 0 }, id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新站点互联状态")
            })?;
        write_audit_event(
            &transaction,
            &tenant_id,
            if enabled {
                "SITE_LINK_ENABLED"
            } else {
                "SITE_LINK_REMOVED"
            },
            "site_link",
            &id,
        )?;
    }
    transaction
        .commit()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交站点互联事务"))?;
    schedule_policy_reconcile(&state);
    Ok(Json(read_site_link_response(&connection, &id)?))
}

/// 处理身份错配恢复：先在 Headscale 停用旧 Node，再清理本地绑定并重新发起入网。
///
/// 这是有意设置的高级、破坏性操作。只有管理员明确提交预期旧 Node ID 和
/// `confirm=true` 才会执行；任何 Headscale 调用失败都会保留原绑定，不进入半恢复状态。
async fn recover_mesh_identity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(request): Json<RecoverMeshIdentityRequest>,
) -> Result<Json<RecoverMeshIdentityResponse>, ApiError> {
    require_admin(&headers)?;
    let expected_old_node_id = request.expected_old_node_id.trim().to_owned();
    if expected_old_node_id.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "expected_old_node_id 不能为空",
        ));
    }
    if !request.confirm {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "请明确确认后才能恢复组网身份",
        ));
    }

    let (tenant_id, device_name, current_node_id, identity_state) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT d.tenant_id, d.name, m.headscale_node_id, m.state
                 FROM devices d JOIN mesh_identities m ON m.nexo_device_id = d.id
                 WHERE d.id = ?1",
                [&device_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备组网身份"))?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "设备没有可恢复的组网身份"))?
    };
    if current_node_id != expected_old_node_id {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("预期旧组网身份与当前记录不一致：当前为 Node {current_node_id}"),
        ));
    }
    if identity_state != "mesh_identity_mismatch" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "当前设备没有处于需要恢复的组网身份错配状态",
        ));
    }

    let expiry = format_headscale_expiration(unix_now().max(0) as u64);
    state
        .headscale
        .expire_node(&expected_old_node_id, &expiry)
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("无法停用旧组网节点，恢复未执行：{error:#}"),
            )
        })?;

    {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法开始组网身份恢复事务",
            )
        })?;
        transaction
            .execute(
                "DELETE FROM mesh_identities WHERE nexo_device_id = ?1 AND headscale_node_id = ?2",
                rusqlite::params![device_id, expected_old_node_id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法清理旧组网身份"))?;
        transaction
            .execute(
                "UPDATE mesh_enrollment_attempts
             SET state = 'revoked', last_error = '身份恢复已撤销旧入网尝试',
                 updated_at = CURRENT_TIMESTAMP
             WHERE nexo_device_id = ?1 AND state = 'issued'",
                [&device_id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法撤销旧入网尝试"))?;
        transaction
            .execute(
                "UPDATE gateway_route_applies
             SET local_status = 'pending', control_plane_status = 'pending',
                 remote_status = 'pending', applied_prefix = NULL,
                 last_error = '组网身份已恢复，等待重新加入',
                 last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
             WHERE device_id = ?1",
                [&device_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法重置网关路由状态")
            })?;
        transaction
            .execute(
                "UPDATE gateway_network_states
             SET apply_status = 'checking', applied_prefix = NULL,
                 apply_error = '组网身份已恢复，等待重新加入',
                 last_checked_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
             WHERE site_network_id IN (
                 SELECT id FROM site_networks WHERE publisher_device_id = ?1
             )",
                [&device_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法重置共享网络状态")
            })?;
        transaction
            .execute(
                "UPDATE site_links SET apply_status = 'checking',
                 apply_error = '组网身份已恢复，等待两侧重新加入',
                 updated_at = CURRENT_TIMESTAMP
             WHERE id IN (
                 SELECT DISTINCT l.id
                 FROM site_links l
                 JOIN site_link_networks ln ON ln.site_link_id = l.id
                 JOIN site_networks n ON n.id = ln.site_network_id
                 WHERE n.publisher_device_id = ?1
             )",
                [&device_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法重置站点互联状态")
            })?;
        write_audit_event(
            &transaction,
            &tenant_id,
            "MESH_IDENTITY_RECOVERY",
            "device",
            &device_id,
        )?;
        transaction.commit().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法提交组网身份恢复事务",
            )
        })?;
    }
    state.mesh_offers.lock().await.remove(&device_id);

    let enrollment_state = state.clone();
    let enrollment_device_id = device_id.clone();
    let enrollment_tenant_id = tenant_id.clone();
    let enrollment_name = device_name.clone();
    tokio::spawn(async move {
        if let Err(error) = start_mesh_enrollment_with_reset(
            &enrollment_state,
            &enrollment_device_id,
            &enrollment_tenant_id,
            &enrollment_name,
            true,
        )
        .await
        {
            tracing::warn!(
                device_id = %enrollment_device_id,
                "身份恢复后无法立即创建组网入网密钥：{error:#}"
            );
        }
    });

    Ok(Json(RecoverMeshIdentityResponse {
        accepted: true,
        device_id,
        old_node_id: expected_old_node_id,
        message: "旧组网身份已停用，正在重新邀请设备加入异地组网".to_owned(),
    }))
}

/// 持久化站点一侧“我已完成静态路由配置”的确认。
async fn confirm_site_link_router(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, site_id)): Path<(String, String)>,
) -> Result<Json<SiteLinkResponse>, ApiError> {
    require_admin(&headers)?;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始路由确认事务"))?;
    let tenant_id: String = transaction
        .query_row(
            "SELECT tenant_id FROM site_links
             WHERE id = ?1 AND (left_site_id = ?2 OR right_site_id = ?2)",
            rusqlite::params![id, site_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "站点互联或站点不存在"))?;
    transaction
        .execute(
            "INSERT INTO site_link_route_confirmations (site_link_id, site_id, confirmed_at)
             VALUES (?1, ?2, CURRENT_TIMESTAMP)
             ON CONFLICT(site_link_id, site_id) DO UPDATE SET confirmed_at = CURRENT_TIMESTAMP",
            rusqlite::params![id, site_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存路由确认"))?;
    write_audit_event(
        &transaction,
        &tenant_id,
        "SITE_LINK_ROUTER_CONFIRMED",
        "site_link",
        &id,
    )?;
    transaction
        .commit()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交路由确认"))?;
    Ok(Json(read_site_link_response(&connection, &id)?))
}

/// 触发一次可重复的 Mesh/能力/路由重新协调，不以单次 ping 宣称 LAN 已可达。
async fn recheck_site_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<RecheckResponse>, ApiError> {
    require_admin(&headers)?;
    let device_ids: Vec<String> = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let mut statement = connection
            .prepare(
                "SELECT n.publisher_device_id
                 FROM site_link_networks ln JOIN site_networks n
                   ON n.id = ln.site_network_id
                 WHERE ln.site_link_id = ?1",
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点互联设备")
            })?;
        let ids = statement
            .query_map([id.as_str()], |row| row.get(0))
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "站点互联不存在"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "站点互联设备数据无效")
            })?;
        ids
    };
    if device_ids.is_empty() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "站点互联不存在"));
    }
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .execute(
                "UPDATE site_links SET apply_status = 'checking', apply_error = NULL,
                 updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
                [&id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法刷新站点互联状态")
            })?;
    }
    for device_id in device_ids {
        let reconcile_state = state.clone();
        tokio::spawn(async move {
            if let Err(error) =
                ensure_mesh_enrollment_for_device(&reconcile_state, &device_id).await
            {
                tracing::debug!(device_id = %device_id, "重新检测时组网入网尚未准备好：{error:#}");
            }
            if let Err(error) = reconcile_headscale_routes(&reconcile_state, &device_id).await {
                tracing::warn!(device_id = %device_id, "重新检测组网路由失败：{error:#}");
            }
        });
    }
    Ok(Json(RecheckResponse {
        accepted: true,
        message: "已开始重新检测组网、能力和路由状态".to_owned(),
    }))
}

/// 从 Nexo 数据库读取站点互联的完整状态。
fn read_site_link_response(
    connection: &Connection,
    id: &str,
) -> Result<SiteLinkResponse, ApiError> {
    let (
        id,
        tenant_id,
        left_site_id,
        right_site_id,
        left_site_name,
        right_site_name,
        left_network_id,
        right_network_id,
        left_network_prefix,
        right_network_prefix,
        left_device_id,
        right_device_id,
        enabled,
        apply_status,
        apply_error,
    ) = connection
        .query_row(
            "SELECT l.id, l.tenant_id, l.left_site_id, l.right_site_id,
                    ls.name, rs.name,
                    ln.site_network_id, rn.site_network_id,
                    lg.desired_prefix, rg.desired_prefix,
                    lg_network.publisher_device_id, rg_network.publisher_device_id,
                    l.enabled, l.apply_status, l.apply_error
             FROM site_links l
             JOIN sites ls ON ls.id = l.left_site_id
             JOIN sites rs ON rs.id = l.right_site_id
             JOIN site_link_networks ln ON ln.site_link_id = l.id AND ln.side = 'left'
             JOIN site_link_networks rn ON rn.site_link_id = l.id AND rn.side = 'right'
             JOIN site_networks lg_network ON lg_network.id = ln.site_network_id
             JOIN gateway_network_states lg ON lg.site_network_id = lg_network.id
             JOIN site_networks rg_network ON rg_network.id = rn.site_network_id
             JOIN gateway_network_states rg ON rg.site_network_id = rg_network.id
             WHERE l.id = ?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, i64>(12)? != 0,
                    parse_apply_status(&row.get::<_, String>(13)?),
                    row.get::<_, Option<String>>(14)?,
                ))
            },
        )
        .map_err(|error| {
            tracing::debug!(error = %error, "读取站点互联路由引导失败");
            ApiError::new(StatusCode::NOT_FOUND, "站点互联不存在")
        })?;
    let left_gateway_address = find_gateway_address(
        connection,
        &left_device_id,
        &find_network_interface(connection, &left_network_id)?,
        &left_network_prefix,
    )?;
    let right_gateway_address = find_gateway_address(
        connection,
        &right_device_id,
        &find_network_interface(connection, &right_network_id)?,
        &right_network_prefix,
    )?;
    let left_confirmation = site_link_route_confirmation(connection, &id, &left_site_id)?;
    let right_confirmation = site_link_route_confirmation(connection, &id, &right_site_id)?;
    let static_routes = vec![
        StaticRouteGuide {
            router_site_id: left_site_id.clone(),
            destination_site_id: right_site_id.clone(),
            router_site_name: left_site_name.clone(),
            destination_site_name: right_site_name.clone(),
            destination_prefix: right_network_prefix.clone(),
            next_hop: left_gateway_address.clone(),
            router_confirmed: left_confirmation.is_some(),
        },
        StaticRouteGuide {
            router_site_id: right_site_id.clone(),
            destination_site_id: left_site_id.clone(),
            router_site_name: right_site_name.clone(),
            destination_site_name: left_site_name.clone(),
            destination_prefix: left_network_prefix.clone(),
            next_hop: right_gateway_address.clone(),
            router_confirmed: right_confirmation.is_some(),
        },
    ];
    let route_confirmations = [
        left_confirmation.map(|confirmed_at| RouteConfirmationResponse {
            site_id: left_site_id.clone(),
            confirmed_at,
        }),
        right_confirmation.map(|confirmed_at| RouteConfirmationResponse {
            site_id: right_site_id.clone(),
            confirmed_at,
        }),
    ]
    .into_iter()
    .flatten()
    .collect();
    let (health_status, health_error) = site_link_health(
        connection,
        &id,
        (
            &left_device_id,
            &find_network_interface(connection, &left_network_id)?,
            &left_network_prefix,
        ),
        (
            &right_device_id,
            &find_network_interface(connection, &right_network_id)?,
            &right_network_prefix,
        ),
        enabled,
        apply_status,
        apply_error.as_deref(),
    )?;
    Ok(SiteLinkResponse {
        id,
        tenant_id,
        left_site_id,
        right_site_id,
        left_site_name,
        right_site_name,
        left_network_id,
        right_network_id,
        left_network_prefix,
        right_network_prefix,
        left_gateway_address,
        right_gateway_address,
        static_routes,
        route_confirmations,
        enabled,
        apply_status,
        apply_error,
        health_status,
        health_error,
    })
}

fn site_link_route_confirmation(
    connection: &Connection,
    link_id: &str,
    site_id: &str,
) -> Result<Option<String>, ApiError> {
    connection
        .query_row(
            "SELECT confirmed_at FROM site_link_route_confirmations
             WHERE site_link_id = ?1 AND site_id = ?2",
            rusqlite::params![link_id, site_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取静态路由确认"))
}

/// 读取共享网络绑定的网卡名称，用于从能力报告中找到对应的 Agent 地址。
fn find_network_interface(connection: &Connection, network_id: &str) -> Result<String, ApiError> {
    connection
        .query_row(
            "SELECT interface_id FROM site_networks WHERE id = ?1",
            [network_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "站点共享网络不存在"))
}

/// 从最近一次能力报告读取指定网卡和网段对应的 Agent 局域网地址。
fn find_gateway_address(
    connection: &Connection,
    device_id: &str,
    interface_id: &str,
    prefix: &str,
) -> Result<Option<String>, ApiError> {
    let report_json: Option<String> = connection
        .query_row(
            "SELECT report_json FROM device_capability_reports WHERE device_id = ?1",
            [device_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备能力报告"))?;
    let Some(report_json) = report_json else {
        return Ok(None);
    };
    let report: GatewayCapabilityReport = serde_json::from_str(&report_json).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "设备网关能力报告格式无效",
        )
    })?;
    let prefix_text = prefix;
    let prefix = prefix_text
        .parse::<IpNet>()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "共享网络前缀格式无效"))?;
    Ok(report
        .local_networks
        .iter()
        .find(|network| network.interface_id == interface_id && network.prefix == prefix_text)
        .and_then(|network| {
            let address = network
                .gateway_address
                .as_deref()?
                .parse::<std::net::IpAddr>()
                .ok()?;
            prefix.contains(&address).then(|| address.to_string())
        }))
}

/// 计算共享网络自身的健康状态。
///
/// 健康状态只使用 Nexo 已经拥有的观测值：设备在线状态、最近能力报告、本地网段
/// 是否仍然存在，以及 Desired / Applied 应用阶段；不会把一次成功的 CLI 调用
/// 推断成 Headscale 已批准，也不会主动探测或修改用户的局域网。
fn gateway_network_health(
    connection: &Connection,
    device_id: &str,
    interface_id: &str,
    prefix: &str,
    enabled: bool,
    apply_status: ApplyStatus,
    apply_error: Option<&str>,
) -> Result<(GatewayHealthStatus, Option<String>), ApiError> {
    if !enabled || apply_status == ApplyStatus::Disabled {
        return Ok((GatewayHealthStatus::Disabled, None));
    }
    if apply_status == ApplyStatus::Failed {
        return Ok((
            GatewayHealthStatus::Failed,
            Some(apply_error.unwrap_or("共享网络应用失败").to_owned()),
        ));
    }
    let (device_health, device_error) =
        inspect_gateway_device(connection, device_id, interface_id, prefix, false)?;
    if device_health == GatewayHealthStatus::Failed {
        return Ok((device_health, device_error));
    }
    if device_health == GatewayHealthStatus::Degraded {
        return Ok((device_health, device_error));
    }
    if apply_status == ApplyStatus::Ready {
        let ready: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM gateway_route_applies
                 WHERE device_id = ?1 AND network_id = (
                   SELECT id FROM site_networks WHERE publisher_device_id = ?1
                   AND interface_id = ?2 AND id IN (
                     SELECT site_network_id FROM gateway_network_states
                     WHERE desired_prefix = ?3)
                 ) AND site_link_id = '' AND local_status = 'applied'
                 AND control_plane_status = 'serving'",
                rusqlite::params![device_id, interface_id, prefix],
                |row| row.get(0),
            )
            .unwrap_or_default();
        if ready > 0 {
            Ok((GatewayHealthStatus::Ready, None))
        } else {
            Ok((
                GatewayHealthStatus::Degraded,
                Some("等待 Headscale 路由批准并提供服务".to_owned()),
            ))
        }
    } else {
        Ok((
            GatewayHealthStatus::Degraded,
            Some("等待设备确认共享网络已生效".to_owned()),
        ))
    }
}

/// 计算站点互联的综合健康状态；两侧任一网关异常都会反映到互联状态。
fn site_link_health(
    connection: &Connection,
    link_id: &str,
    left: (&str, &str, &str),
    right: (&str, &str, &str),
    enabled: bool,
    apply_status: ApplyStatus,
    apply_error: Option<&str>,
) -> Result<(GatewayHealthStatus, Option<String>), ApiError> {
    if !enabled || apply_status == ApplyStatus::Disabled {
        return Ok((GatewayHealthStatus::Disabled, None));
    }
    if apply_status == ApplyStatus::Failed {
        return Ok((
            GatewayHealthStatus::Failed,
            Some(apply_error.unwrap_or("站点互联应用失败").to_owned()),
        ));
    }
    let (left_health, left_error) =
        inspect_gateway_device(connection, left.0, left.1, left.2, true)?;
    let (right_health, right_error) =
        inspect_gateway_device(connection, right.0, right.1, right.2, true)?;
    if left_health == GatewayHealthStatus::Failed {
        return Ok((left_health, left_error));
    }
    if right_health == GatewayHealthStatus::Failed {
        return Ok((right_health, right_error));
    }
    // 离线是比“尚未加入组网”更直接的可处理原因；先显示离线一侧，
    // 避免左侧仍在等待组网时遮蔽右侧已经断开的事实。
    if left_health == GatewayHealthStatus::Degraded
        && left_error.as_deref() == Some("网关设备当前不在线")
    {
        return Ok((left_health, left_error));
    }
    if right_health == GatewayHealthStatus::Degraded
        && right_error.as_deref() == Some("网关设备当前不在线")
    {
        return Ok((right_health, right_error));
    }
    if left_health == GatewayHealthStatus::Degraded {
        return Ok((left_health, left_error));
    }
    if right_health == GatewayHealthStatus::Degraded {
        return Ok((right_health, right_error));
    }
    if apply_status == ApplyStatus::Ready {
        let confirmed: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM site_link_route_confirmations
                 WHERE site_link_id = ?1",
                [link_id],
                |row| row.get(0),
            )
            .unwrap_or_default();
        if confirmed < 2 {
            return Ok((
                GatewayHealthStatus::Degraded,
                Some("等待两侧完成静态路由配置确认".to_owned()),
            ));
        }
        let route_ready: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM gateway_route_applies a
                 JOIN site_link_networks ln ON ln.site_link_id = ?1
                 WHERE a.network_id = ln.site_network_id
                   AND a.site_link_id = ?1 AND a.local_status = 'applied'
                   AND a.control_plane_status = 'serving' AND a.remote_status = 'accepted'",
                [link_id],
                |row| row.get(0),
            )
            .unwrap_or_default();
        if route_ready >= 2 {
            Ok((GatewayHealthStatus::Ready, None))
        } else {
            Ok((
                GatewayHealthStatus::Degraded,
                Some("等待两侧设备接受远端网络路由".to_owned()),
            ))
        }
    } else {
        Ok((
            GatewayHealthStatus::Degraded,
            Some("等待两侧设备确认站点互联已生效".to_owned()),
        ))
    }
}

/// 检查单台网关设备是否仍具备指定能力和本地网段。
fn inspect_gateway_device(
    connection: &Connection,
    device_id: &str,
    interface_id: &str,
    prefix: &str,
    site_gateway: bool,
) -> Result<(GatewayHealthStatus, Option<String>), ApiError> {
    let row = connection
        .query_row(
            "SELECT d.status, r.report_json, m.state, m.online
             FROM devices d
             LEFT JOIN device_capability_reports r ON r.device_id = d.id
             LEFT JOIN mesh_identities m ON m.nexo_device_id = d.id
             WHERE d.id = ?1",
            [device_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?.unwrap_or_default() != 0,
                ))
            },
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取网关健康状态"))?;
    let Some((status, report_json, mesh_state, mesh_online)) = row else {
        return Ok((
            GatewayHealthStatus::Failed,
            Some("网关设备不存在".to_owned()),
        ));
    };
    if mesh_state.as_deref() == Some("mesh_identity_mismatch") {
        return Ok((
            GatewayHealthStatus::Failed,
            Some("组网身份与已绑定设备不一致，请执行恢复".to_owned()),
        ));
    }
    if status != "online" {
        return Ok((
            GatewayHealthStatus::Degraded,
            Some("网关设备当前不在线".to_owned()),
        ));
    }
    if mesh_state.as_deref() != Some("ready") {
        return Ok((
            GatewayHealthStatus::Degraded,
            Some("等待设备加入异地组网".to_owned()),
        ));
    }
    if !mesh_online {
        return Ok((
            GatewayHealthStatus::Degraded,
            Some("设备尚未连接异地组网".to_owned()),
        ));
    }
    let Some(report_json) = report_json else {
        return Ok((
            GatewayHealthStatus::Degraded,
            Some("等待 Agent 上报最新网关能力".to_owned()),
        ));
    };
    let report: GatewayCapabilityReport = serde_json::from_str(&report_json).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "设备网关能力报告格式无效",
        )
    })?;
    let (capability, reason) = if site_gateway {
        (report.site_gateway, report.site_gateway_reason)
    } else {
        (report.subnet_gateway, report.subnet_gateway_reason)
    };
    if capability == CapabilityState::Unavailable {
        return Ok((
            GatewayHealthStatus::Failed,
            Some(gateway_capability_message(reason)),
        ));
    }
    if !report
        .local_networks
        .iter()
        .any(|network| network.interface_id == interface_id && network.prefix == prefix)
    {
        return Ok((
            GatewayHealthStatus::Failed,
            Some("设备已不再发现该本地网络".to_owned()),
        ));
    }
    Ok((GatewayHealthStatus::Ready, None))
}

/// 将 Agent 能力报告中的结构化原因转换成普通用户可以直接处理的提示。
fn gateway_capability_message(reason: Option<GatewayCapabilityReason>) -> String {
    match reason {
        Some(GatewayCapabilityReason::MissingNetAdmin) => "设备缺少网络管理权限".to_owned(),
        Some(GatewayCapabilityReason::TunNotAvailable) => "设备无法访问虚拟网络接口".to_owned(),
        Some(GatewayCapabilityReason::IpForwardingDisabled) => "设备未开启 IP 转发".to_owned(),
        Some(GatewayCapabilityReason::NoLocalSubnet) => "设备没有可共享的本地网络".to_owned(),
        Some(GatewayCapabilityReason::UnsupportedPlatform) => "当前设备平台不支持网关".to_owned(),
        None => "设备暂不具备所需的网关能力".to_owned(),
    }
}

/// 站点互联两侧选中的共享网络及其网关设备。
struct LinkNetwork {
    prefix: String,
    device_id: String,
    interface_id: String,
}

fn load_network_for_link(
    connection: &rusqlite::Transaction<'_>,
    tenant_id: &str,
    network_id: &str,
    site_id: &str,
) -> Result<LinkNetwork, ApiError> {
    connection
        .query_row(
            "SELECT g.desired_prefix, n.publisher_device_id, n.interface_id
             FROM gateway_network_states g JOIN site_networks n
             ON n.id = g.site_network_id
             WHERE g.site_network_id = ?1 AND n.tenant_id = ?2 AND n.site_id = ?3
             AND n.enabled = 1",
            rusqlite::params![network_id, tenant_id, site_id],
            |row| {
                Ok(LinkNetwork {
                    prefix: row.get(0)?,
                    device_id: row.get(1)?,
                    interface_id: row.get(2)?,
                })
            },
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "站点共享网络不存在或不属于指定站点"))
}

/// 校验网关设备归属、在线状态和 Agent 最近上报的能力报告。
fn ensure_gateway_device(
    connection: &Connection,
    tenant_id: &str,
    site_id: &str,
    device_id: &str,
    interface_id: &str,
    prefix: IpNet,
    require_online: bool,
) -> Result<(), ApiError> {
    let result = connection.query_row(
        "SELECT d.status, d.capabilities_json, r.report_json FROM devices d
         LEFT JOIN device_capability_reports r ON r.device_id = d.id
         WHERE d.id = ?1 AND d.tenant_id = ?2 AND d.site_id = ?3",
        rusqlite::params![device_id, tenant_id, site_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        },
    );
    let (status, capabilities_json, report_json) = result
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "网关设备不存在或不属于指定站点"))?;
    if require_online && status != "online" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "网关设备当前不在线，暂时无法建立站点互联",
        ));
    }
    let capabilities: Vec<DeviceCapability> =
        serde_json::from_str(&capabilities_json).map_err(|_| {
            ApiError::new(
                StatusCode::CONFLICT,
                "设备能力声明无效，请让 Agent 重新连接",
            )
        })?;
    let required_capability = if require_online {
        DeviceCapability::SiteGateway
    } else {
        DeviceCapability::SubnetGateway
    };
    if !capabilities.contains(&required_capability) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("设备未声明所需网关能力：{required_capability:?}"),
        ));
    }
    let report_json = report_json.ok_or_else(|| {
        ApiError::new(
            StatusCode::CONFLICT,
            "设备尚未上报网关能力，请等待设备连接后重试",
        )
    })?;
    let report: GatewayCapabilityReport = serde_json::from_str(&report_json).map_err(|_| {
        ApiError::new(
            StatusCode::CONFLICT,
            "设备网关能力报告无效，请让 Agent 重新连接",
        )
    })?;
    if report.subnet_gateway != CapabilityState::Ready {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!(
                "设备不具备可用的共享本地网络能力：{:?}",
                report.subnet_gateway_reason
            ),
        ));
    }
    if require_online && report.site_gateway != CapabilityState::Ready {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!(
                "设备不具备可用的站点网关能力：{:?}",
                report.site_gateway_reason
            ),
        ));
    }
    if !report.local_networks.iter().any(|network| {
        network.interface_id == interface_id
            && network
                .prefix
                .parse::<IpNet>()
                .map(|detected| detected == prefix)
                .unwrap_or(false)
    }) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "设备最近探测到的本地网络与请求不一致",
        ));
    }
    Ok(())
}

fn write_audit_event(
    connection: &rusqlite::Transaction<'_>,
    tenant_id: &str,
    event_type: &str,
    resource_type: &str,
    resource_id: &str,
) -> Result<(), ApiError> {
    connection
        .execute(
            "INSERT INTO audit_events
             (tenant_id, event_type, resource_type, resource_id)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![tenant_id, event_type, resource_type, resource_id],
        )
        .map(|_| ())
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法写入操作审计"))
}

fn parse_apply_status(status: &str) -> ApplyStatus {
    match status {
        "disabled" => ApplyStatus::Disabled,
        "applying" => ApplyStatus::Applying,
        "ready" => ApplyStatus::Ready,
        "retrying" => ApplyStatus::Retrying,
        "failed" => ApplyStatus::Failed,
        _ => ApplyStatus::Checking,
    }
}

fn networks_overlap(left: IpNet, right: IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        (IpNet::V6(left), IpNet::V6(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        _ => false,
    }
}

fn parse_enrollment_status(status: &str) -> EnrollmentStatus {
    match status {
        "awaiting_approval" => EnrollmentStatus::AwaitingApproval,
        "approved" => EnrollmentStatus::Approved,
        "consumed" => EnrollmentStatus::Consumed,
        "expired" => EnrollmentStatus::Expired,
        "revoked" => EnrollmentStatus::Revoked,
        _ => EnrollmentStatus::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use nexo_core::{DetectedLocalNetwork, DeviceCapability};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    fn admin_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-nexo-admin-token", HeaderValue::from_static("test-admin"));
        headers
    }

    fn test_state() -> AppState {
        let connection = Connection::open_in_memory().expect("应打开内存数据库");
        connection
            .execute_batch(INITIAL_MIGRATION)
            .expect("应初始化基础表");
        connection
            .execute_batch(ENROLLMENT_MIGRATION)
            .expect("应初始化入网表");
        connection
            .execute_batch(IDENTITY_MIGRATION)
            .expect("应初始化身份表");
        connection
            .execute_batch(CONTROL_IDENTITY_MIGRATION)
            .expect("应初始化控制通道身份表");
        connection
            .execute_batch(GATEWAY_REPORT_MIGRATION)
            .expect("应初始化网关能力报告表");
        connection
            .execute_batch(GATEWAY_STATE_MIGRATION)
            .expect("应初始化网关期望状态表");
        connection
            .execute_batch(MESH_IDENTITY_MIGRATION)
            .expect("应初始化组网身份表");
        connection
            .execute_batch(GATEWAY_ROUTE_APPLY_MIGRATION)
            .expect("应初始化逐路由应用状态表");
        ensure_mesh_identity_online_column(&connection).expect("应初始化组网在线状态字段");
        ensure_server_ca(&connection).expect("应初始化测试 CA");
        ensure_server_control_identity(&connection).expect("应初始化测试控制证书");
        connection
            .execute(
                "INSERT INTO tenants (id, name) VALUES ('tenant-1', '测试租户')",
                [],
            )
            .expect("应创建测试租户");
        AppState {
            db: Arc::new(Mutex::new(connection)),
            headscale: Arc::new(HeadscaleAdapter),
            mesh_offers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            mesh_enrollment_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    #[tokio::test]
    async fn overview_requires_admin_token() {
        env::set_var("NEXO_ADMIN_TOKEN", "test-admin");
        let state = test_state();
        let error = overview(State(state.clone()), HeaderMap::new())
            .await
            .expect_err("概览不应在缺少管理员凭证时开放");
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);

        let response = overview(State(state), admin_headers())
            .await
            .expect("管理员应能读取概览")
            .0;
        assert_eq!(response.devices, 0);
        assert_eq!(response.current_connections, 0);
    }

    #[test]
    fn route_report_requires_real_local_apply_before_headscale_reconcile() {
        let enabled_route = GatewayRouteApplyResult {
            network_id: "network-a".to_owned(),
            site_link_id: None,
            prefix: "192.168.10.0/24".to_owned(),
            revision: 1,
            enabled: true,
            local_applied: false,
            control_plane_status: None,
            remote_applied: false,
            error_message: None,
        };
        assert!(!report_allows_headscale_reconcile(
            &GatewayRouteApplyReport {
                revision: 1,
                routes: vec![enabled_route.clone()],
                mesh_identity: None,
            }
        ));
        assert!(report_allows_headscale_reconcile(
            &GatewayRouteApplyReport {
                revision: 1,
                routes: vec![GatewayRouteApplyResult {
                    local_applied: true,
                    ..enabled_route
                }],
                mesh_identity: None,
            }
        ));
        assert!(report_allows_headscale_reconcile(
            &GatewayRouteApplyReport {
                revision: 2,
                routes: vec![GatewayRouteApplyResult {
                    network_id: "network-a".to_owned(),
                    site_link_id: None,
                    prefix: "192.168.10.0/24".to_owned(),
                    revision: 2,
                    enabled: false,
                    local_applied: false,
                    control_plane_status: None,
                    remote_applied: false,
                    error_message: None,
                }],
                mesh_identity: None,
            }
        ));
    }

    #[tokio::test]
    async fn enrollment_request_can_be_submitted_and_approved_once() {
        env::set_var("NEXO_ADMIN_TOKEN", "test-admin");
        let state = test_state();
        let created = create_enrollment(
            State(state.clone()),
            admin_headers(),
            Json(CreateEnrollmentRequest {
                tenant_id: "tenant-1".to_owned(),
                site_id: None,
                ttl_seconds: Some(900),
            }),
        )
        .await
        .expect("管理员应能创建入网凭证")
        .0;

        let token = created.token.clone();
        let agent_key = KeyPair::generate().expect("应生成测试 Agent 私钥");
        let mut csr_params =
            CertificateParams::new(vec!["agent.nexo".to_owned()]).expect("应创建测试 CSR 参数");
        csr_params.distinguished_name = DistinguishedName::new();
        csr_params
            .distinguished_name
            .push(DnType::CommonName, "测试 NAS");
        let csr_pem = csr_params
            .serialize_request(&agent_key)
            .expect("应生成测试 CSR")
            .pem()
            .expect("应编码测试 CSR");
        let submitted = enroll_agent(
            State(state.clone()),
            Json(AgentEnrollmentRequest {
                token,
                device_name: "测试 NAS".to_owned(),
                os: Some("linux".to_owned()),
                architecture: Some("amd64".to_owned()),
                agent_version: "0.1.0".to_owned(),
                capabilities: vec![DeviceCapability::Tunnel],
                csr_pem: Some(csr_pem),
            }),
        )
        .await
        .expect("Agent 应能提交入网请求")
        .0;
        assert_eq!(submitted.status, EnrollmentStatus::AwaitingApproval);

        let replay = enroll_agent(
            State(state.clone()),
            Json(AgentEnrollmentRequest {
                token: created.token.clone(),
                device_name: "重复请求".to_owned(),
                os: None,
                architecture: None,
                agent_version: "0.1.0".to_owned(),
                capabilities: vec![DeviceCapability::Tunnel],
                csr_pem: None,
            }),
        )
        .await
        .expect_err("一次性凭证不应接受第二次提交");
        assert_eq!(replay.status, StatusCode::CONFLICT);

        let approved = approve_enrollment(
            State(state.clone()),
            admin_headers(),
            Path(submitted.enrollment_id.clone()),
        )
        .await
        .expect("管理员应能批准入网请求")
        .0;
        assert_eq!(approved.status, EnrollmentStatus::Approved);
        assert!(approved.device_id.is_some());

        let delivered = poll_agent_enrollment(
            State(state.clone()),
            Path(submitted.enrollment_id.clone()),
            Json(AgentEnrollmentPollRequest {
                token: created.token.clone(),
            }),
        )
        .await
        .expect("Agent 应能领取设备身份")
        .0;
        assert_eq!(delivered.status, EnrollmentStatus::Approved);
        assert!(delivered.certificate_pem.is_some());
        assert!(delivered.ca_certificate_pem.is_some());

        let delivered_again = poll_agent_enrollment(
            State(state.clone()),
            Path(submitted.enrollment_id.clone()),
            Json(AgentEnrollmentPollRequest {
                token: created.token,
            }),
        )
        .await
        .expect_err("设备身份不应被重复领取");
        assert_eq!(delivered_again.status, StatusCode::CONFLICT);

        let devices = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row("SELECT COUNT(*) FROM devices", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("应能查询设备");
        assert_eq!(devices, 1);
    }

    #[test]
    fn control_tls_configuration_requires_server_and_device_ca_material() {
        let state = test_state();
        let connection = state.db.lock().expect("数据库锁应可用");
        let config = build_control_tls_config(&connection).expect("应能构建 mTLS 配置");
        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    fn mesh_identity_mismatch_stops_gateway_and_revokes_next_revision() {
        let state = test_state();
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute_batch(
                    "INSERT INTO sites (id, tenant_id, name) VALUES ('site-a', 'tenant-1', '家庭');
                     INSERT INTO devices
                        (id, tenant_id, site_id, name, status, capabilities_json)
                        VALUES ('device-a', 'tenant-1', 'site-a', '家庭网关', 'online',
                                '[\"subnet_gateway\"]');
                     INSERT INTO mesh_identities
                        (nexo_device_id, tenant_id, headscale_node_id, state)
                        VALUES ('device-a', 'tenant-1', '17', 'ready');
                     INSERT INTO site_networks
                        (id, tenant_id, site_id, name, publisher_device_id, interface_id,
                         address_family, current_prefix)
                        VALUES ('network-a', 'tenant-1', 'site-a', '家庭 LAN', 'device-a',
                                'eth0', 'ipv4', '192.168.10.0/24');
                     INSERT INTO gateway_network_states
                        (site_network_id, desired_prefix, desired_revision, apply_status)
                        VALUES ('network-a', '192.168.10.0/24', 1, 'ready');",
                )
                .expect("应创建身份错配测试数据");
        }
        record_mesh_identity_report(
            &state,
            "device-a",
            &MeshIdentityReport {
                node_id: Some("18".to_owned()),
                hostname: Some("replacement".to_owned()),
                ipv4: Some("100.64.0.18".to_owned()),
                ipv6: None,
                online: true,
            },
        )
        .expect("身份错配应能被记录");
        let connection = state.db.lock().expect("数据库锁应可用");
        let (identity_state, network_state, revision): (String, String, i64) = connection
            .query_row(
                "SELECT m.state, g.apply_status, g.desired_revision
                 FROM mesh_identities m JOIN gateway_network_states g
                   ON g.site_network_id = 'network-a'
                 WHERE m.nexo_device_id = 'device-a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("应能读取身份错配后的状态");
        assert_eq!(identity_state, "mesh_identity_mismatch");
        assert_eq!(network_state, "failed");
        assert_eq!(revision, 2);
        let desired = load_gateway_desired_state(&connection, "device-a")
            .expect("应能生成身份错配后的撤销配置")
            .expect("仍应下发撤销路由");
        assert!(!desired.routes[0].enabled);
    }

    #[test]
    fn gateway_desired_state_contains_local_and_remote_routes() {
        let state = test_state();
        let connection = state.db.lock().expect("数据库锁应可用");
        connection
            .execute_batch(
                "INSERT INTO sites (id, tenant_id, name) VALUES
                    ('site-a', 'tenant-1', '家庭'),
                    ('site-b', 'tenant-1', '办公室');
                 INSERT INTO devices
                    (id, tenant_id, site_id, name, status, capabilities_json)
                    VALUES
                    ('device-a', 'tenant-1', 'site-a', '家庭网关', 'online',
                     '[\"subnet_gateway\",\"site_gateway\"]'),
                    ('device-b', 'tenant-1', 'site-b', '办公室网关', 'online',
                     '[\"subnet_gateway\",\"site_gateway\"]');
                 INSERT INTO site_networks
                    (id, tenant_id, site_id, name, publisher_device_id, interface_id,
                     address_family, current_prefix)
                    VALUES
                    ('network-a', 'tenant-1', 'site-a', '家庭 LAN', 'device-a', 'eth0',
                     'ipv4', '192.168.10.0/24'),
                    ('network-b', 'tenant-1', 'site-b', '办公室 LAN', 'device-b', 'eth0',
                     'ipv4', '192.168.20.0/24');
                 INSERT INTO gateway_network_states
                    (site_network_id, desired_prefix, desired_revision)
                    VALUES
                    ('network-a', '192.168.10.0/24', 1),
                    ('network-b', '192.168.20.0/24', 2);
                 INSERT INTO site_links (id, tenant_id, left_site_id, right_site_id)
                    VALUES ('link-a-b', 'tenant-1', 'site-a', 'site-b');
                 INSERT INTO site_link_networks (site_link_id, site_network_id, side)
                    VALUES ('link-a-b', 'network-a', 'left'),
                           ('link-a-b', 'network-b', 'right');",
            )
            .expect("应创建网关 Desired State 测试数据");

        let state_for_device = load_gateway_desired_state(&connection, "device-a")
            .expect("应能汇总设备网关 Desired State")
            .expect("设备应收到网关配置");
        assert_eq!(state_for_device.revision, 2);
        assert_eq!(state_for_device.routes.len(), 2);
        assert_eq!(state_for_device.routes[0].network_id, "network-a");
        assert_eq!(state_for_device.routes[0].site_link_id, None);
        assert_eq!(state_for_device.routes[1].network_id, "network-b");
        assert_eq!(
            state_for_device.routes[1].site_link_id.as_deref(),
            Some("link-a-b")
        );
    }

    #[test]
    fn gateway_apply_ack_updates_applied_state_only_for_confirmed_networks() {
        let state = test_state();
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute_batch(
                    "INSERT INTO sites (id, tenant_id, name) VALUES ('site-a', 'tenant-1', '家庭');
                     INSERT INTO devices
                        (id, tenant_id, site_id, name, status, capabilities_json)
                        VALUES ('device-a', 'tenant-1', 'site-a', '家庭网关', 'online',
                                '[\"subnet_gateway\"]');
                     INSERT INTO site_networks
                        (id, tenant_id, site_id, name, publisher_device_id, interface_id,
                         address_family, current_prefix)
                        VALUES ('network-a', 'tenant-1', 'site-a', '家庭 LAN', 'device-a',
                                'eth0', 'ipv4', '192.168.10.0/24');
                     INSERT INTO gateway_network_states
                        (site_network_id, desired_prefix, desired_revision)
                        VALUES ('network-a', '192.168.10.0/24', 1);",
                )
                .expect("应创建网关 ACK 测试数据");
        }
        apply_gateway_ack(
            &state,
            "device-a",
            &GatewayApplyAck {
                revision: 1,
                status: ApplyStatus::Checking,
                network_ids: vec!["network-a".to_owned()],
                applied_network_ids: Vec::new(),
                error_message: None,
            },
        )
        .expect("checking ACK 应能保存");
        let status: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status FROM gateway_network_states WHERE site_network_id = 'network-a'",
                [],
                |row| row.get(0),
            )
            .expect("应能读取网关状态");
        assert_eq!(status, "checking");

        apply_gateway_ack(
            &state,
            "device-a",
            &GatewayApplyAck {
                revision: 1,
                status: ApplyStatus::Ready,
                network_ids: vec!["network-a".to_owned()],
                applied_network_ids: vec!["network-a".to_owned()],
                error_message: None,
            },
        )
        .expect("ready ACK 应能保存");
        let (status, applied): (String, Option<String>) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status, applied_prefix
                 FROM gateway_network_states WHERE site_network_id = 'network-a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("应能读取已应用网关状态");
        assert_eq!(status, "checking");
        assert_eq!(applied, None);
        let network_status: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status FROM site_networks WHERE id = 'network-a'",
                [],
                |row| row.get(0),
            )
            .expect("应能读取共享网络用户状态");
        assert_eq!(network_status, "checking");

        apply_gateway_ack(
            &state,
            "device-a",
            &GatewayApplyAck {
                revision: 0,
                status: ApplyStatus::Checking,
                network_ids: vec!["network-a".to_owned()],
                applied_network_ids: Vec::new(),
                error_message: None,
            },
        )
        .expect("旧 revision ACK 应被安全忽略");
        let status: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status FROM gateway_network_states WHERE site_network_id = 'network-a'",
                [],
                |row| row.get(0),
            )
            .expect("应能读取旧 ACK 后的状态");
        assert_eq!(status, "checking");
    }

    #[tokio::test]
    async fn disabling_site_network_increments_revision_and_publishes_revoke_route() {
        env::set_var("NEXO_ADMIN_TOKEN", "test-admin");
        let state = test_state();
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute_batch(
                    "INSERT INTO sites (id, tenant_id, name) VALUES ('site-a', 'tenant-1', '家庭');
                     INSERT INTO devices
                        (id, tenant_id, site_id, name, status, capabilities_json)
                        VALUES ('device-a', 'tenant-1', 'site-a', '家庭网关', 'online',
                                '[\"subnet_gateway\"]');
                     INSERT INTO site_networks
                        (id, tenant_id, site_id, name, publisher_device_id, interface_id,
                         address_family, current_prefix)
                        VALUES ('network-a', 'tenant-1', 'site-a', '家庭 LAN', 'device-a',
                                'eth0', 'ipv4', '192.168.10.0/24');
                     INSERT INTO gateway_network_states
                        (site_network_id, desired_prefix, desired_revision, apply_status)
                        VALUES ('network-a', '192.168.10.0/24', 1, 'ready');",
                )
                .expect("应创建关闭网关测试数据");
        }

        let disabled = disable_site_network(
            State(state.clone()),
            admin_headers(),
            Path("network-a".to_owned()),
        )
        .await
        .expect("管理员应能关闭共享网络")
        .0;
        assert!(!disabled.enabled);
        assert_eq!(disabled.desired_revision, 2);
        assert_eq!(disabled.apply_status, ApplyStatus::Checking);

        let desired = {
            let connection = state.db.lock().expect("数据库锁应可用");
            load_gateway_desired_state(&connection, "device-a")
                .expect("应能加载撤销 Desired State")
                .expect("关闭后的撤销路由仍需下发")
        };
        assert_eq!(desired.revision, 2);
        assert_eq!(desired.routes.len(), 1);
        assert!(!desired.routes[0].enabled);
        assert_eq!(desired.routes[0].network_id, "network-a");

        apply_gateway_ack(
            &state,
            "device-a",
            &GatewayApplyAck {
                revision: 2,
                status: ApplyStatus::Disabled,
                network_ids: vec!["network-a".to_owned()],
                applied_network_ids: Vec::new(),
                error_message: None,
            },
        )
        .expect("Agent 应能确认网关路由已撤销");
        let applied_status: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status FROM site_networks WHERE id = 'network-a'",
                [],
                |row| row.get(0),
            )
            .expect("应能读取撤销后的用户状态");
        assert_eq!(applied_status, "disabled");

        let repeated =
            disable_site_network(State(state), admin_headers(), Path("network-a".to_owned()))
                .await
                .expect("重复关闭应保持幂等")
                .0;
        assert_eq!(repeated.desired_revision, 2);
    }

    #[tokio::test]
    async fn disabling_site_link_uses_revision_newer_than_network_revision() {
        env::set_var("NEXO_ADMIN_TOKEN", "test-admin");
        let state = test_state();
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute_batch(
                    "INSERT INTO sites (id, tenant_id, name) VALUES
                        ('site-a', 'tenant-1', '家庭'),
                        ('site-b', 'tenant-1', '办公室');
                     INSERT INTO devices
                        (id, tenant_id, site_id, name, status, capabilities_json)
                        VALUES
                        ('device-a', 'tenant-1', 'site-a', '家庭网关', 'online',
                         '[\"site_gateway\"]'),
                        ('device-b', 'tenant-1', 'site-b', '办公室网关', 'online',
                         '[\"site_gateway\"]');
                     INSERT INTO site_networks
                        (id, tenant_id, site_id, name, publisher_device_id, interface_id,
                         address_family, current_prefix)
                        VALUES
                        ('network-a', 'tenant-1', 'site-a', '家庭 LAN', 'device-a', 'eth0',
                         'ipv4', '192.168.10.0/24'),
                        ('network-b', 'tenant-1', 'site-b', '办公室 LAN', 'device-b', 'eth0',
                         'ipv4', '192.168.20.0/24');
                     INSERT INTO gateway_network_states
                        (site_network_id, desired_prefix, desired_revision)
                        VALUES
                        ('network-a', '192.168.10.0/24', 1),
                        ('network-b', '192.168.20.0/24', 1);
                     INSERT INTO site_links (id, tenant_id, left_site_id, right_site_id)
                        VALUES ('link-a-b', 'tenant-1', 'site-a', 'site-b');
                     INSERT INTO site_link_networks (site_link_id, site_network_id, side)
                        VALUES ('link-a-b', 'network-a', 'left'),
                               ('link-a-b', 'network-b', 'right');",
                )
                .expect("应创建站点互联关闭测试数据");
        }

        let disabled = disable_site_link(
            State(state.clone()),
            admin_headers(),
            Path("link-a-b".to_owned()),
        )
        .await
        .expect("管理员应能关闭站点互联")
        .0;
        assert!(!disabled.enabled);
        assert_eq!(disabled.apply_status, ApplyStatus::Checking);

        let connection = state.db.lock().expect("数据库锁应可用");
        let desired = load_gateway_desired_state(&connection, "device-a")
            .expect("应能加载站点互联撤销 Desired State")
            .expect("关闭后的互联撤销路由仍需下发");
        assert_eq!(desired.revision, 2);
        let remote_route = desired
            .routes
            .iter()
            .find(|route| route.site_link_id.as_deref() == Some("link-a-b"))
            .expect("应保留站点互联撤销路由");
        assert!(!remote_route.enabled);
        assert_eq!(remote_route.revision, 2);
        drop(connection);

        // 共享网络本身仍可保持启用，因此 Link 的 DISABLED 只能由两侧
        // Agent 对该 Link 撤销路由的逐项 ACK 推进，不能读取网络总状态推断。
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute_batch(
                    "INSERT INTO gateway_route_applies
                        (device_id, network_id, site_link_id, desired_revision,
                         local_status, control_plane_status, remote_status)
                     VALUES
                        ('device-a', 'network-b', 'link-a-b', 2,
                         'disabled', 'disabled', 'disabled'),
                        ('device-b', 'network-a', 'link-a-b', 2,
                         'disabled', 'disabled', 'disabled');",
                )
                .expect("应保存两侧 Link 撤销 ACK");
            let transaction = connection
                .unchecked_transaction()
                .expect("应开始 Link 状态收敛事务");
            refresh_site_link_apply_status(&transaction).expect("应收敛 Link 撤销状态");
            transaction.commit().expect("应提交 Link 撤销状态");
        }
        let link_status: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status FROM site_links WHERE id = 'link-a-b'",
                [],
                |row| row.get(0),
            )
            .expect("应能读取 Link 撤销状态");
        assert_eq!(link_status, "disabled");
    }

    #[tokio::test]
    async fn control_channel_marks_authenticated_device_online() {
        env::set_var("NEXO_ADMIN_TOKEN", "test-admin");
        let state = test_state();
        let created = create_enrollment(
            State(state.clone()),
            admin_headers(),
            Json(CreateEnrollmentRequest {
                tenant_id: "tenant-1".to_owned(),
                site_id: None,
                ttl_seconds: Some(900),
            }),
        )
        .await
        .expect("管理员应能创建入网凭证")
        .0;
        let agent_key = KeyPair::generate().expect("应生成测试 Agent 私钥");
        let mut csr_params =
            CertificateParams::new(vec!["agent.nexo".to_owned()]).expect("应创建测试 CSR 参数");
        csr_params.distinguished_name = DistinguishedName::new();
        csr_params
            .distinguished_name
            .push(DnType::CommonName, "控制通道设备");
        let csr_pem = csr_params
            .serialize_request(&agent_key)
            .expect("应生成测试 CSR")
            .pem()
            .expect("应编码测试 CSR");
        let _ = enroll_agent(
            State(state.clone()),
            Json(AgentEnrollmentRequest {
                token: created.token.clone(),
                device_name: "控制通道设备".to_owned(),
                os: Some("linux".to_owned()),
                architecture: Some("amd64".to_owned()),
                agent_version: "0.1.0".to_owned(),
                capabilities: vec![nexo_core::DeviceCapability::Tunnel],
                csr_pem: Some(csr_pem),
            }),
        )
        .await
        .expect("Agent 应能提交入网请求");
        let approved = approve_enrollment(
            State(state.clone()),
            admin_headers(),
            Path(created.enrollment_id.clone()),
        )
        .await
        .expect("管理员应能批准设备")
        .0;
        let device_id = approved.device_id.expect("审批应返回设备 ID");
        let (device_certificate_pem, ca_certificate_pem) = {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .query_row(
                    "SELECT i.certificate_pem, s.ca_certificate_pem
                     FROM device_identities i CROSS JOIN server_identity s
                     WHERE i.device_id = ?1",
                    [&device_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .expect("应能读取测试证书")
        };
        let mut roots = rustls::RootCertStore::empty();
        for certificate in pem_certificates(&ca_certificate_pem).expect("CA 应有效") {
            roots.add(certificate).expect("CA 应能加入信任根");
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                pem_certificates(&device_certificate_pem).expect("设备证书应有效"),
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(agent_key.serialize_der()),
                ),
            )
            .expect("应能构建客户端 mTLS 配置");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("应能监听测试端口");
        let address = listener.local_addr().expect("应能读取测试端口");
        let server_config = {
            let connection = state.db.lock().expect("数据库锁应可用");
            build_control_tls_config(&connection).expect("应能构建服务端 mTLS 配置")
        };
        let task = tokio::spawn(serve_control_listener(
            listener,
            server_config,
            state.clone(),
        ));
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::pki_types::ServerName::try_from("nexo-server".to_owned())
            .expect("测试服务名应有效");
        let stream = TcpStream::connect(address).await.expect("应能连接测试端口");
        let tls_stream = connector
            .connect(server_name, stream)
            .await
            .expect("设备应能完成 mTLS 握手");
        let mut reader = AsyncBufReader::new(tls_stream);
        let hello = AgentControlMessage::Hello {
            device_id: device_id.clone(),
            agent_version: "0.1.0".to_owned(),
            capabilities: vec![nexo_core::DeviceCapability::Tunnel],
            gateway_report: None,
            mesh_identity: None,
        };
        reader
            .get_mut()
            .write_all(format!("{}\n", serde_json::to_string(&hello).unwrap()).as_bytes())
            .await
            .expect("应能发送身份声明");
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("应能读取身份确认");
        let response: ServerControlMessage =
            serde_json::from_str(line.trim()).expect("身份确认格式应有效");
        assert!(matches!(
            response,
            ServerControlMessage::HelloAccepted { .. }
        ));
        let heartbeat = AgentControlMessage::Heartbeat {
            device_id: device_id.clone(),
            agent_version: "0.1.0".to_owned(),
            gateway_report: None,
            mesh_identity: None,
        };
        reader
            .get_mut()
            .write_all(format!("{}\n", serde_json::to_string(&heartbeat).unwrap()).as_bytes())
            .await
            .expect("应能发送心跳");
        line.clear();
        reader.read_line(&mut line).await.expect("应能读取心跳确认");
        let response: ServerControlMessage =
            serde_json::from_str(line.trim()).expect("心跳确认格式应有效");
        assert!(matches!(
            response,
            ServerControlMessage::HeartbeatAck { .. }
        ));
        let status: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT status FROM devices WHERE id = ?1",
                [&device_id],
                |row| row.get(0),
            )
            .expect("应能读取设备状态");
        assert_eq!(status, "online");
        let devices = list_devices(State(state.clone()), admin_headers())
            .await
            .expect("管理员应能读取设备摘要")
            .0;
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, device_id);
        assert_eq!(devices[0].status, "online");
        assert!(devices[0].gateway_report.is_none());
        drop(reader);
        task.abort();
    }

    #[tokio::test]
    async fn gateway_desired_state_rejects_overlapping_site_networks() {
        env::set_var("NEXO_ADMIN_TOKEN", "test-admin");
        let state = test_state();
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute_batch(
                    "INSERT INTO sites (id, tenant_id, name) VALUES
                        ('site-a', 'tenant-1', '家庭'),
                        ('site-b', 'tenant-1', '办公室');
                     INSERT INTO devices
                        (id, tenant_id, site_id, name, status, capabilities_json)
                        VALUES
                        ('device-a', 'tenant-1', 'site-a', '家庭网关', 'online',
                         '[\"subnet_gateway\",\"site_gateway\"]'),
                        ('device-b', 'tenant-1', 'site-b', '办公室网关', 'online',
                         '[\"subnet_gateway\",\"site_gateway\"]');",
                )
                .expect("应创建测试站点和设备");
            let report_a = GatewayCapabilityReport {
                platform: "linux".to_owned(),
                tun_available: true,
                net_admin_available: true,
                ipv4_forwarding: true,
                ipv6_forwarding: true,
                local_networks: vec![DetectedLocalNetwork {
                    interface_id: "eth0".to_owned(),
                    prefix: "192.168.10.0/24".to_owned(),
                    gateway_address: Some("192.168.10.2".to_owned()),
                }],
                subnet_gateway: CapabilityState::Ready,
                subnet_gateway_reason: None,
                site_gateway: CapabilityState::Ready,
                site_gateway_reason: None,
            };
            let report_b = GatewayCapabilityReport {
                local_networks: vec![
                    DetectedLocalNetwork {
                        interface_id: "eth0".to_owned(),
                        prefix: "192.168.20.0/24".to_owned(),
                        gateway_address: Some("192.168.20.2".to_owned()),
                    },
                    DetectedLocalNetwork {
                        interface_id: "eth0".to_owned(),
                        prefix: "192.168.10.0/24".to_owned(),
                        gateway_address: Some("192.168.20.2".to_owned()),
                    },
                ],
                ..report_a.clone()
            };
            connection
                .execute(
                    "INSERT INTO device_capability_reports (device_id, report_json)
                     VALUES (?1, ?2), (?3, ?4)",
                    rusqlite::params![
                        "device-a",
                        serde_json::to_string(&report_a).unwrap(),
                        "device-b",
                        serde_json::to_string(&report_b).unwrap(),
                    ],
                )
                .expect("应保存网关能力报告");
        }
        let sites = list_sites(State(state.clone()), admin_headers())
            .await
            .expect("管理员应能读取站点目录")
            .0;
        assert_eq!(
            sites
                .iter()
                .map(|site| site.name.as_str())
                .collect::<Vec<_>>(),
            ["办公室", "家庭"]
        );
        let left = create_site_network(
            State(state.clone()),
            admin_headers(),
            Json(CreateSiteNetworkRequest {
                tenant_id: "tenant-1".to_owned(),
                site_id: "site-a".to_owned(),
                name: "家庭网络".to_owned(),
                publisher_device_id: "device-a".to_owned(),
                interface_id: "eth0".to_owned(),
                prefix: "192.168.10.0/24".to_owned(),
            }),
        )
        .await
        .expect("应创建家庭共享网络")
        .0;
        let right = create_site_network(
            State(state.clone()),
            admin_headers(),
            Json(CreateSiteNetworkRequest {
                tenant_id: "tenant-1".to_owned(),
                site_id: "site-b".to_owned(),
                name: "办公室网络".to_owned(),
                publisher_device_id: "device-b".to_owned(),
                interface_id: "eth0".to_owned(),
                prefix: "192.168.20.0/24".to_owned(),
            }),
        )
        .await
        .expect("应创建办公室共享网络")
        .0;
        let networks = list_site_networks(State(state.clone()), admin_headers())
            .await
            .expect("管理员应能读取共享网络列表")
            .0;
        assert_eq!(networks.len(), 2);
        assert!(networks
            .iter()
            .all(|network| network.health_status == GatewayHealthStatus::Degraded));
        assert!(networks
            .iter()
            .all(|network| network.health_error.as_deref() == Some("等待设备加入异地组网")));
        assert_eq!(
            networks
                .iter()
                .find(|network| network.id == left.id)
                .map(|network| (
                    network.site_name.as_str(),
                    network.publisher_device_name.as_str(),
                    network.gateway_address.as_deref(),
                )),
            Some(("家庭", "家庭网关", Some("192.168.10.2")))
        );
        let link = create_site_link(
            State(state.clone()),
            admin_headers(),
            Json(CreateSiteLinkRequest {
                tenant_id: "tenant-1".to_owned(),
                left_site_id: "site-a".to_owned(),
                left_network_id: left.id.clone(),
                right_site_id: "site-b".to_owned(),
                right_network_id: right.id.clone(),
            }),
        )
        .await
        .expect("不重叠的站点网络应能创建互联")
        .0;
        assert_eq!(link.apply_status, ApplyStatus::Checking);
        assert_eq!(link.health_status, GatewayHealthStatus::Degraded);
        assert_eq!(link.health_error.as_deref(), Some("等待设备加入异地组网"));
        assert_eq!(link.left_site_name, "家庭");
        assert_eq!(link.right_site_name, "办公室");
        assert_eq!(link.left_network_prefix, "192.168.10.0/24");
        assert_eq!(link.right_network_prefix, "192.168.20.0/24");
        assert_eq!(link.left_gateway_address.as_deref(), Some("192.168.10.2"));
        assert_eq!(link.right_gateway_address.as_deref(), Some("192.168.20.2"));
        assert_eq!(
            link.static_routes,
            vec![
                StaticRouteGuide {
                    router_site_id: "site-a".to_owned(),
                    destination_site_id: "site-b".to_owned(),
                    router_site_name: "家庭".to_owned(),
                    destination_site_name: "办公室".to_owned(),
                    destination_prefix: "192.168.20.0/24".to_owned(),
                    next_hop: Some("192.168.10.2".to_owned()),
                    router_confirmed: false,
                },
                StaticRouteGuide {
                    router_site_id: "site-b".to_owned(),
                    destination_site_id: "site-a".to_owned(),
                    router_site_name: "办公室".to_owned(),
                    destination_site_name: "家庭".to_owned(),
                    destination_prefix: "192.168.10.0/24".to_owned(),
                    next_hop: Some("192.168.20.2".to_owned()),
                    router_confirmed: false,
                },
            ]
        );
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute(
                    "UPDATE devices SET status = 'offline' WHERE id = 'device-b'",
                    [],
                )
                .expect("应能模拟远端网关离线");
        }
        let degraded_link =
            get_site_link(State(state.clone()), admin_headers(), Path(link.id.clone()))
                .await
                .expect("离线网关仍应返回站点互联状态")
                .0;
        assert_eq!(degraded_link.apply_status, ApplyStatus::Checking);
        assert_eq!(degraded_link.health_status, GatewayHealthStatus::Degraded);
        assert_eq!(
            degraded_link.health_error.as_deref(),
            Some("网关设备当前不在线")
        );
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute(
                    "UPDATE devices SET status = 'online' WHERE id = 'device-b'",
                    [],
                )
                .expect("应恢复测试网关在线状态");
        }
        let links = list_site_links(State(state.clone()), admin_headers())
            .await
            .expect("管理员应能读取站点互联列表")
            .0;
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].id, link.id);

        let conflict = create_site_network(
            State(state.clone()),
            admin_headers(),
            Json(CreateSiteNetworkRequest {
                tenant_id: "tenant-1".to_owned(),
                site_id: "site-b".to_owned(),
                name: "冲突网络".to_owned(),
                publisher_device_id: "device-b".to_owned(),
                interface_id: "eth0".to_owned(),
                prefix: "192.168.10.0/24".to_owned(),
            }),
        )
        .await
        .expect("测试设备应能报告第二个本地网络")
        .0;
        let error = create_site_link(
            State(state),
            admin_headers(),
            Json(CreateSiteLinkRequest {
                tenant_id: "tenant-1".to_owned(),
                left_site_id: "site-a".to_owned(),
                left_network_id: left.id,
                right_site_id: "site-b".to_owned(),
                right_network_id: conflict.id,
            }),
        )
        .await
        .expect_err("重叠网段不应建立站点互联");
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert!(error.message.contains("网络地址冲突"));
    }
}
