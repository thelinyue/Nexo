//! Nexo Server 启动入口。
//!
//! 当前阶段提供健康检查、概览和设备入网身份 API，并建立 Nexo SQLite 数据库。

use std::{
    env, fs,
    io::BufReader,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

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
    EnrollmentToken, GatewayCapabilityReport,
};
use nexo_protocol::{
    AgentControlMessage, AgentEnrollmentPollRequest, AgentEnrollmentPollResponse,
    AgentEnrollmentRequest, AgentEnrollmentResponse, GatewayApplyAck, GatewayDesiredRoute,
    GatewayDesiredState, ServerControlMessage,
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
use uuid::Uuid;

const INITIAL_MIGRATION: &str = include_str!("../../../migrations/0001_initial.sql");
const ENROLLMENT_MIGRATION: &str = include_str!("../../../migrations/0002_device_enrollment.sql");
const IDENTITY_MIGRATION: &str = include_str!("../../../migrations/0003_server_identity.sql");
const CONTROL_IDENTITY_MIGRATION: &str =
    include_str!("../../../migrations/0004_control_identity.sql");
const GATEWAY_REPORT_MIGRATION: &str =
    include_str!("../../../migrations/0005_gateway_capability_reports.sql");
const GATEWAY_STATE_MIGRATION: &str =
    include_str!("../../../migrations/0006_gateway_desired_state.sql");

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
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
    last_seen_at: Option<String>,
}

/// 管理端创建一次性设备入网凭证的请求。
#[derive(Debug, Deserialize)]
struct CreateEnrollmentRequest {
    tenant_id: String,
    site_id: Option<String>,
    ttl_seconds: Option<i64>,
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
    name: String,
    publisher_device_id: String,
    interface_id: String,
    /// Agent 在本地局域网上的地址；路由器应把远端网段指向该地址。
    gateway_address: Option<String>,
    desired_prefix: String,
    applied_prefix: Option<String>,
    desired_revision: i64,
    enabled: bool,
    apply_status: ApplyStatus,
    apply_error: Option<String>,
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
    enabled: bool,
    apply_status: ApplyStatus,
    apply_error: Option<String>,
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
    ensure_server_ca(&connection).context("无法初始化服务端设备身份 CA")?;
    ensure_server_control_identity(&connection).context("无法初始化控制通道服务端证书")?;
    let control_tls = build_control_tls_config(&connection).context("无法构建 mTLS 控制通道")?;

    let state = AppState {
        db: Arc::new(Mutex::new(connection)),
    };
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
        .route("/api/v1/enrollments", post(create_enrollment))
        .route("/api/v1/enrollments/{id}", get(get_enrollment))
        .route("/api/v1/enrollments/{id}/approve", post(approve_enrollment))
        .route("/api/v1/agent/enroll", post(enroll_agent))
        .route(
            "/api/v1/agent/enroll/{id}/poll",
            post(poll_agent_enrollment),
        )
        .route("/api/v1/site-networks", post(create_site_network))
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
        .with_state(state);

    let address: SocketAddr = env::var("NEXO_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9888".to_owned())
        .parse()
        .context("NEXO_HTTP_ADDR 不是有效的监听地址")?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("无法监听 Nexo API 地址：{address}"))?;
    tracing::info!("Nexo Server 已启动，API 监听于 {address}");
    axum::serve(listener, app)
        .await
        .context("Nexo API 服务异常退出")?;
    Ok(())
}

fn database_path() -> Result<PathBuf> {
    let root = env::var("NEXO_DATA_DIR").unwrap_or_else(|_| "./data/nexo".to_owned());
    let root = PathBuf::from(root);
    fs::create_dir_all(&root)
        .with_context(|| format!("无法创建 Nexo 数据目录：{}", root.display()))?;
    Ok(root.join("nexo.db"))
}

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        service: "nexo-server",
    })
}

async fn overview(State(state): State<AppState>) -> Result<Json<OverviewResponse>, StatusCode> {
    let connection = state
        .db
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let devices = count(&connection, "SELECT COUNT(*) FROM devices")?;
    let running_tunnels = count(
        &connection,
        "SELECT COUNT(*) FROM tunnels WHERE enabled = 1 AND apply_status = 'ready'",
    )?;
    let mesh_devices = count(
        &connection,
        "SELECT COUNT(*) FROM devices WHERE capabilities_json LIKE '%mesh%'",
    )?;
    let current_connections = count(
        &connection,
        "SELECT COUNT(*) FROM devices WHERE status = 'online'",
    )?;
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
                    d.last_seen_at
             FROM devices d
             LEFT JOIN device_capability_reports r ON r.device_id = d.id
             ORDER BY d.updated_at DESC, d.name ASC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备列表"))?;
    let rows = statement
        .query_map([], |row| {
            let capabilities_json: String = row.get(8)?;
            let report_json: Option<String> = row.get(9)?;
            Ok((DeviceResponse {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                site_id: row.get(2)?,
                name: row.get(3)?,
                os: row.get(4)?,
                architecture: row.get(5)?,
                agent_version: row.get(6)?,
                status: row.get(7)?,
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
                last_seen_at: row.get(10)?,
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
    let (device_id, agent_version, capabilities, gateway_report) = match hello {
        AgentControlMessage::Hello {
            device_id,
            agent_version,
            capabilities,
            gateway_report,
        } => (device_id, agent_version, capabilities, gateway_report),
        AgentControlMessage::Heartbeat { .. } => anyhow::bail!("设备必须先发送身份声明"),
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
    let gateway_state = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        load_gateway_desired_state(&connection, &device_id)?
    };
    write_control_message(
        reader.get_mut(),
        &ServerControlMessage::HelloAccepted {
            server_time: unix_now(),
            gateway_state,
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
                let gateway_state = {
                    let connection = state
                        .db
                        .lock()
                        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                    load_gateway_desired_state(&connection, &device_id)?
                };
                write_control_message(
                    reader.get_mut(),
                    &ServerControlMessage::HeartbeatAck {
                        server_time: unix_now(),
                        gateway_state,
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
    connection.execute(
        "UPDATE devices SET status = 'offline', updated_at = CURRENT_TIMESTAMP
         WHERE id = ?1 AND status = 'online'",
        [&device_id],
    )?;
    Ok(())
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
                enabled: row.get::<_, i64>(3)? != 0,
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
                    && row.get::<_, i64>(7)? != 0,
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
        for network_id in &ack.applied_network_ids {
            transaction.execute(
                "UPDATE gateway_network_states
                 SET apply_status = 'ready', applied_prefix = desired_prefix,
                     apply_error = NULL, last_checked_at = CURRENT_TIMESTAMP,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE site_network_id = ?1 AND desired_revision <= ?2
                   AND site_network_id IN
                       (SELECT n.id FROM site_networks n
                        WHERE n.publisher_device_id = ?3)",
                rusqlite::params![network_id, ack.revision, device_id],
            )?;
            transaction.execute(
                "UPDATE site_networks
                 SET apply_status = 'ready', apply_revision = ?1,
                     apply_error = NULL, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?2 AND id IN
                       (SELECT n.id FROM site_networks n
                        WHERE n.publisher_device_id = ?3)
                   AND EXISTS (SELECT 1 FROM gateway_network_states g
                               WHERE g.site_network_id = site_networks.id
                                 AND g.desired_revision <= ?1)",
                rusqlite::params![ack.revision, network_id, device_id],
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
    transaction.commit()?;
    Ok(())
}

/// 第三阶段暂用显式 Bootstrap Token 保护管理端点。
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
    Ok(Json(EnrollmentStatusResponse {
        enrollment_id: id,
        status: EnrollmentStatus::Approved,
        expires_at,
        device_id: Some(device_id),
    }))
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
    Ok(Json(read_site_network_response(&connection, &id)?))
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
    Ok(Json(read_site_network_response(&connection, &id)?))
}

/// 从 Nexo 数据库读取共享网络的完整 Desired / Applied 状态。
fn read_site_network_response(
    connection: &Connection,
    id: &str,
) -> Result<SiteNetworkResponse, ApiError> {
    connection
        .query_row(
            "SELECT n.id, n.tenant_id, n.site_id, n.name, n.publisher_device_id,
                    n.interface_id, g.desired_prefix, g.applied_prefix,
                    g.desired_revision, n.enabled, g.apply_status, g.apply_error
             FROM site_networks n JOIN gateway_network_states g
             ON g.site_network_id = n.id WHERE n.id = ?1",
            [id],
            |row| {
                Ok(SiteNetworkResponse {
                    id: row.get(0)?,
                    tenant_id: row.get(1)?,
                    site_id: row.get(2)?,
                    name: row.get(3)?,
                    publisher_device_id: row.get(4)?,
                    interface_id: row.get(5)?,
                    gateway_address: None,
                    desired_prefix: row.get(6)?,
                    applied_prefix: row.get(7)?,
                    desired_revision: row.get(8)?,
                    enabled: row.get::<_, i64>(9)? != 0,
                    apply_status: parse_apply_status(&row.get::<_, String>(10)?),
                    apply_error: row.get(11)?,
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
            Ok(response)
        })
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
    Ok(Json(read_site_link_response(&connection, &id)?))
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
    let static_routes = vec![
        StaticRouteGuide {
            router_site_id: left_site_id.clone(),
            destination_site_id: right_site_id.clone(),
            router_site_name: left_site_name.clone(),
            destination_site_name: right_site_name.clone(),
            destination_prefix: right_network_prefix.clone(),
            next_hop: left_gateway_address.clone(),
        },
        StaticRouteGuide {
            router_site_id: right_site_id.clone(),
            destination_site_id: left_site_id.clone(),
            router_site_name: right_site_name.clone(),
            destination_site_name: left_site_name.clone(),
            destination_prefix: left_network_prefix.clone(),
            next_hop: right_gateway_address.clone(),
        },
    ];
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
        enabled,
        apply_status,
        apply_error,
    })
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
        }
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
        assert_eq!(status, "ready");
        assert_eq!(applied.as_deref(), Some("192.168.10.0/24"));
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
        assert_eq!(network_status, "ready");

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
        assert_eq!(status, "ready");
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
                },
                StaticRouteGuide {
                    router_site_id: "site-b".to_owned(),
                    destination_site_id: "site-a".to_owned(),
                    router_site_name: "办公室".to_owned(),
                    destination_site_name: "家庭".to_owned(),
                    destination_prefix: "192.168.10.0/24".to_owned(),
                    next_hop: Some("192.168.20.2".to_owned()),
                },
            ]
        );
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
