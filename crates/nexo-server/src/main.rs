//! Nexo Server 启动入口。
//!
//! 当前阶段提供健康检查、概览和设备入网身份 API，并建立 Nexo SQLite 数据库。

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    env, fs,
    io::BufReader,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

mod auth;
mod caddy;
mod headscale;
mod oidc;
mod policy;

use anyhow::{Context, Result};
use axum::{
    extract::{connect_info::Connected, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    serve::{IncomingStream, Listener},
    Json, Router,
};
use clap::{Parser, Subcommand};
use ipnet::IpNet;
use nexo_core::{
    forwarding_enabled_for_prefix, validate_published_network, ApplyStatus, CapabilityState,
    DeviceCapability, EnrollmentStatus, EnrollmentToken, GatewayCapabilityReason,
    GatewayCapabilityReport,
};
use nexo_headscale_adapter::{
    HeadscaleAdapter, HeadscaleAuthKeyOptions, HeadscaleControlPlane, HeadscaleHttpAdapter,
    HeadscaleNode, PolicyCheckError,
};
#[cfg(test)]
use nexo_protocol::GatewayRouteApplyResult;
use nexo_protocol::{
    AgentControlMessage, AgentEnrollmentPollRequest, AgentEnrollmentPollResponse,
    AgentEnrollmentRequest, AgentEnrollmentResponse, GatewayApplyAck, GatewayDesiredRoute,
    GatewayDesiredState, GatewayRouteApplyReport, MeshEnrollmentOffer, MeshIdentityReport,
    ServerControlMessage, TunnelApplyResult, TunnelDataEndpoint, TunnelDesiredState,
};
use nexo_tunnel::{
    configure_tunnel_tcp_keepalive, into_tokio_io, new_outbound, write_logical_header,
    LogicalStreamHeader,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader as AsyncBufReader,
};
use tokio_rustls::{rustls, TlsAcceptor};
use tokio_util::sync::CancellationToken;
use tower_http::services::ServeDir;
use uuid::Uuid;
use x509_parser::{extensions::GeneralName, pem::parse_x509_pem};

use headscale::{ApiKeyManager, HeadscaleRuntimeConfig, HeadscaleSupervisor};

#[derive(Debug, Parser)]
#[command(name = "nexo", version, about = "Nexo 联巢服务端管理命令")]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// 输出尚未使用的首次初始化口令。
    BootstrapCode,
    /// 管理员本地维护命令。
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// 创建一次性 Web 恢复码；新密码只在恢复页面输入。
    Recover,
}

// v0.1.12 是当前唯一支持的数据库基线。历史 SQL 文件仍保留在仓库中供发布审计，
// 运行时只执行这一份收敛后的初始结构；已有数据库不会重新执行历史迁移。
const V012_BASELINE_MIGRATION: &str = include_str!("../../../migrations/v0.1.12_baseline.sql");
const OIDC_ACCOUNTS_MIGRATION: &str = include_str!("../../../migrations/0020_oidc_accounts.sql");

#[derive(Clone)]
pub(crate) struct AppState {
    db: Arc<Mutex<Connection>>,
    /// Nexo 数据目录同时承载认证 Secret、运行时 Socket 和独立组件状态。
    pub(crate) data_dir: PathBuf,
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
    /// 每台 Agent 只保留一条当前数据会话；新 mTLS 会话会取消旧会话，
    /// 避免重连后两个 Yamux 驱动器同时接受公网连接。
    tunnel_sessions: Arc<tokio::sync::Mutex<HashMap<String, TunnelSessionHandle>>>,
    /// 动态公网入口的监听任务，重启后从 SQLite Desired State 恢复。
    ///
    /// 任务自然退出时会用令牌校验后再移除自己，避免旧任务结束时误删
    /// 同一 Tunnel 已经重新建立的新监听。
    public_listener_tasks: Arc<Mutex<HashMap<String, PublicListenerTask>>>,
    /// 已经进入双向转发阶段的连接，按 Tunnel 分组保存取消令牌。
    ///
    /// 停止监听只能拒绝新连接；删除服务时还必须主动结束已经建立的连接，
    /// 否则旧公网会话可能一直访问 Agent 本地服务，直到任一端自行断开。
    active_tunnel_connections: Arc<Mutex<HashMap<String, HashMap<Uuid, CancellationToken>>>>,
    /// Caddy 故障只影响公网 Web Service，不影响 Nexo Core 或 TCP Tunnel。
    caddy: Arc<caddy::CaddySupervisor>,
    /// Headscale 的公网登录地址由公网入口设置驱动；Supervisor 自己负责重启
    /// 独立子进程，避免 Server 进程内保留过期的配置快照。
    headscale_runtime: Arc<HeadscaleSupervisor>,
    /// OIDC 授权码、短期令牌和固定签名密钥的服务端状态。
    pub(crate) oidc: Arc<oidc::OidcRuntime>,
}

/// Server 向单台 Agent 数据会话请求打开一个逻辑流。
///
/// TCP Tunnel 和 Caddy Web Service 共用同一条 mTLS/Yamux 数据面；这里用
/// 一个小型 IO trait 把公网 TCP 与 Unix Socket 统一起来，避免为两种入口
/// 复制整套逻辑流和背压处理。
trait PublicTunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> PublicTunnelIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

struct ServerTunnelCommand {
    tunnel_id: String,
    connection_id: String,
    socket: Box<dyn PublicTunnelIo>,
    /// 连接许可贯穿逻辑流生命周期，转发结束后自动归还。
    permit: tokio::sync::OwnedSemaphorePermit,
}

/// 公网监听任务的可撤销登记。
///
/// 只保存 `AbortHandle` 而不保存 JoinHandle，允许任务在自然退出时清理
/// 自己的登记，同时保留停止入口的即时撤销能力。令牌用于保护重启竞态。
struct PublicListenerTask {
    token: Uuid,
    abort: tokio::task::AbortHandle,
}

/// 一条 Agent Tunnel 数据会话的控制句柄。
///
/// `sender` 用于向 Yamux 驱动器提交新逻辑流，`cancel` 用于在同一设备
/// 建立新 mTLS 会话时立即停止旧驱动器。两者必须成对保存，单独替换
/// Sender 会让旧连接继续存活并造成公网连接随机落到旧会话。
struct TunnelSessionHandle {
    sender: tokio::sync::mpsc::Sender<ServerTunnelCommand>,
    cancel: CancellationToken,
    /// Yamux 最大流数之外再保留显式连接许可，便于在进入队列前拒绝过载。
    connection_permits: Arc<tokio::sync::Semaphore>,
}

/// 为 Caddy 专用的 loopback 管理后端提供 TLS listener。
///
/// `axum::serve` 的 listener 接口要求在接受错误时自行重试，因此这里同时
/// 处理 TCP 接受和 TLS 握手失败。后端只绑定 127.0.0.1，证书由 Nexo 自己的
/// 控制身份签发；Caddy 通过 loopback 回源并跳过内部证书校验，外部客户端
/// 无法直接访问这个端口。
struct PublicBackendTlsListener {
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
}

/// Caddy 回源专用的连接信息类型。
///
/// Axum 为内置 TCP listener 提供了 `SocketAddr` 的连接信息实现；TLS
/// listener 是自定义类型，不能直接复用外部 trait 实现，因此用本地类型
/// 保留 loopback 标记，供认证中间件区分 Caddy HTTPS 与 LAN HTTP。
#[derive(Clone, Copy, Debug)]
pub(crate) struct PublicBackendPeer(pub(crate) SocketAddr);

impl Connected<IncomingStream<'_, PublicBackendTlsListener>> for PublicBackendPeer {
    fn connect_info(stream: IncomingStream<'_, PublicBackendTlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl Listener for PublicBackendTlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = match self.listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::error!("Caddy 管理后端接受连接失败，将稍后重试：{error}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            match self.acceptor.accept(stream).await {
                Ok(tls_stream) => return (tls_stream, address),
                Err(error) => {
                    // 远端握手失败不应终止管理后端，下一次连接仍可正常服务。
                    tracing::warn!("Caddy 管理后端 TLS 握手失败，已忽略连接：{error}");
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.listener.local_addr()
    }
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

/// 公网 Tunnel 的用户可见状态；不返回 Agent 证书、Caddy 配置或 Secret。
#[derive(Debug, Serialize)]
struct TunnelResponse {
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
    origin_protocol: Option<String>,
    origin_tls_server_name: Option<String>,
    origin_tls_verification: String,
    service_name: Option<String>,
    enabled: bool,
    apply_status: String,
    apply_error: Option<String>,
    desired_revision: i64,
    applied_revision: i64,
    deletion_pending: bool,
    public_address: Option<String>,
    /// Web Service 所属的公网域名；TCP Tunnel 没有域名绑定。
    public_domain_id: Option<String>,
    public_domain: Option<String>,
}

/// 删除接口统一返回同步完成或等待外部撤销两种状态。
#[derive(Debug, Serialize)]
struct DeleteResponse {
    deleted: bool,
    pending: bool,
    id: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct TunnelBatchIdsRequest {
    tunnel_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TunnelBatchDeviceRequest {
    tunnel_ids: Vec<String>,
    device_id: String,
}

#[derive(Debug, Serialize)]
struct BatchSkippedItem {
    id: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct BatchTunnelResponse {
    updated: Vec<TunnelResponse>,
    affected_count: usize,
    skipped: Vec<BatchSkippedItem>,
    message: String,
}

#[derive(Debug, Serialize)]
struct BatchTunnelDeleteResponse {
    deleted_ids: Vec<String>,
    affected_count: usize,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CreateTunnelRequest {
    tenant_id: String,
    device_id: String,
    name: String,
    protocol: String,
    local_address: String,
    local_port: u16,
    public_port: Option<u16>,
    hostname: Option<String>,
    origin_protocol: Option<String>,
    origin_tls_server_name: Option<String>,
    origin_tls_verification: Option<String>,
    /// 仅在 `custom_ca` 校验方式下使用；正文只写入该 Tunnel 的 0600 Secret。
    #[serde(alias = "custom_ca_pem")]
    origin_ca_pem: Option<String>,
    service_name: Option<String>,
    /// Web Service 使用的域名资源；为空时使用当前主域名。
    #[serde(default)]
    public_domain_id: Option<String>,
}

type UpdateTunnelRequest = CreateTunnelRequest;

#[derive(Debug, Serialize)]
struct PrimaryDomainStatus {
    base_domain: Option<String>,
    https_enabled: bool,
    certificate_mode: String,
    acme_environment: String,
    desired_revision: i64,
    applied_revision: i64,
    apply_status: String,
    apply_error: Option<String>,
    certificate_not_before: Option<i64>,
    certificate_not_after: Option<i64>,
    certificate_subjects: Vec<String>,
    dns_check: serde_json::Value,
}

/// 多域名资源的用户可见状态；任何 Secret 正文都不会通过 API 返回。
#[derive(Debug, Serialize, Clone)]
struct PublicDomainResponse {
    id: String,
    tenant_id: String,
    domain: String,
    is_primary: bool,
    https_enabled: bool,
    certificate_mode: String,
    acme_environment: String,
    apply_status: String,
    apply_error: Option<String>,
    error_code: Option<String>,
    dns_check: serde_json::Value,
    root_certificate: CertificateStatusResponse,
    wildcard_certificate: CertificateStatusResponse,
    usage_count: i64,
    desired_revision: i64,
    applied_revision: i64,
    retry_after: Option<i64>,
    attempt_count: i64,
    next_retry_at: Option<i64>,
    dns_management: DnsManagementResponse,
    management_entry: Option<String>,
    mesh_entry: Option<String>,
    readiness_summary: PublicDomainReadinessSummary,
}

/// 聚合列表所需的入口就绪状态，避免不同客户端各自推导出不一致结论。
#[derive(Debug, Serialize, Clone)]
struct PublicDomainReadinessSummary {
    status: String,
    root_dns: String,
    wildcard_dns: String,
    https: String,
    management_entry: String,
    mesh_entry: String,
}

#[derive(Debug, Serialize, Clone)]
struct CertificateStatusResponse {
    status: String,
    not_before: Option<i64>,
    not_after: Option<i64>,
    /// Caddy 通常在到期前约 30 天进入自动续期窗口；这是预计时间，
    /// 不是对 CA 或 Caddy 后台调度的硬承诺。
    renewal_at: Option<i64>,
    subjects: Vec<String>,
    progress: CertificateProgressResponse,
}

#[derive(Debug, Serialize, Clone)]
struct CertificateProgressResponse {
    stage: String,
    attempt_count: i64,
    last_event_at: Option<i64>,
    next_retry_at: Option<i64>,
    error_code: Option<String>,
    error_message: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct DnsManagementResponse {
    enabled: bool,
    target_ipv4: Option<String>,
    target_ipv6: Option<String>,
    status: String,
    error: Option<String>,
    version: i64,
}

#[derive(Debug, Deserialize)]
struct CreatePublicDomainRequest {
    domain: String,
    #[serde(default = "default_true")]
    https_enabled: bool,
    #[serde(default = "default_cloudflare")]
    certificate_mode: String,
    #[serde(default)]
    dns_management_enabled: bool,
    #[serde(default)]
    dns_target_ipv4: Option<String>,
    #[serde(default)]
    dns_target_ipv6: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdatePublicDomainRequest {
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    https_enabled: Option<bool>,
    #[serde(default)]
    certificate_mode: Option<String>,
    #[serde(default)]
    dns_management_enabled: Option<bool>,
    #[serde(default)]
    dns_target_ipv4: Option<Option<String>>,
    #[serde(default)]
    dns_target_ipv6: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
struct ApplyManagedDnsRequest {
    #[serde(default)]
    confirm_conflicts: bool,
}

#[derive(Debug, Serialize, Clone)]
struct ManagedDnsChange {
    action: String,
    record_type: String,
    name: String,
    desired_content: String,
    current_content: Option<String>,
    record_id: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct ManagedDnsPreviewResponse {
    domain_id: String,
    zone_name: String,
    changes: Vec<ManagedDnsChange>,
    has_conflicts: bool,
}

#[derive(Debug, Deserialize)]
struct ManagedDnsBatchRequest {
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    confirm_conflicts: bool,
}

#[derive(Debug, Deserialize)]
struct ReleaseManagedDnsRequest {
    #[serde(default)]
    delete_created_records: bool,
}

#[derive(Debug, Deserialize)]
struct PublicDomainSecretRequest {
    #[serde(default)]
    cloudflare_token: Option<String>,
    #[serde(default)]
    certificate_pem: Option<String>,
    #[serde(default)]
    private_key_pem: Option<String>,
    /// 上传证书校验成功后原子切换为手动模式；失败时继续保留自动证书。
    #[serde(default)]
    activate_manual_certificate: bool,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct RuntimeEventQuery {
    public_domain_id: Option<String>,
    level: Option<String>,
    category: Option<String>,
    since: Option<i64>,
    cursor: Option<i64>,
    limit: Option<usize>,
    search: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct RuntimeEventResponse {
    id: i64,
    public_domain_id: Option<String>,
    domain: Option<String>,
    level: String,
    category: String,
    stage: Option<String>,
    summary: String,
    error_code: Option<String>,
    retry_at: Option<i64>,
    technical_detail: Option<String>,
    occurred_at: i64,
}

#[derive(Debug, Serialize)]
struct RuntimeEventPage {
    events: Vec<RuntimeEventResponse>,
    next_cursor: Option<i64>,
}

fn read_public_domain_runtime_events(
    connection: &Connection,
    tenant_id: &str,
    query: &RuntimeEventQuery,
    maximum: usize,
) -> Result<RuntimeEventPage, ApiError> {
    let limit = query.limit.unwrap_or(50).clamp(1, maximum);
    let domain_id = query
        .public_domain_id
        .as_deref()
        .filter(|value| !value.is_empty());
    let level = query.level.as_deref().filter(|value| !value.is_empty());
    let category = query.category.as_deref().filter(|value| !value.is_empty());
    let search = query
        .search
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let mut statement = connection
        .prepare(
            "SELECT id, public_domain_id, domain, level, category, stage, summary,
                    error_code, retry_at, technical_detail, occurred_at
             FROM public_domain_runtime_events
             WHERE tenant_id = ?1
               AND (?2 IS NULL OR public_domain_id = ?2)
               AND (?3 IS NULL OR level = ?3)
               AND (?4 IS NULL OR category = ?4)
               AND (?5 IS NULL OR occurred_at >= ?5)
               AND (?6 IS NULL OR id < ?6)
               AND (?7 IS NULL OR lower(summary) LIKE '%' || lower(?7) || '%'
                    OR lower(COALESCE(domain, '')) LIKE '%' || lower(?7) || '%'
                    OR lower(COALESCE(technical_detail, '')) LIKE '%' || lower(?7) || '%')
             ORDER BY id DESC LIMIT ?8",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取域名服务日志"))?;
    let mut events = statement
        .query_map(
            rusqlite::params![
                tenant_id,
                domain_id,
                level,
                category,
                query.since,
                query.cursor,
                search,
                i64::try_from(limit + 1).unwrap_or(101),
            ],
            |row| {
                Ok(RuntimeEventResponse {
                    id: row.get(0)?,
                    public_domain_id: row.get(1)?,
                    domain: row.get(2)?,
                    level: row.get(3)?,
                    category: row.get(4)?,
                    stage: row.get(5)?,
                    summary: row.get(6)?,
                    error_code: row.get(7)?,
                    retry_at: row.get(8)?,
                    technical_detail: row.get(9)?,
                    occurred_at: row.get(10)?,
                })
            },
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法查询域名服务日志"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法解析域名服务日志"))?;
    let next_cursor = (events.len() > limit)
        .then(|| events.get(limit - 1).map(|event| event.id))
        .flatten();
    events.truncate(limit);
    Ok(RuntimeEventPage {
        events,
        next_cursor,
    })
}

async fn list_public_domain_runtime_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RuntimeEventQuery>,
) -> Result<Json<RuntimeEventPage>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    Ok(Json(read_public_domain_runtime_events(
        &connection,
        &tenant_id,
        &query,
        100,
    )?))
}

async fn export_public_domain_runtime_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(mut query): Query<RuntimeEventQuery>,
) -> Result<Response, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    query.limit = Some(1_000);
    let page = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        read_public_domain_runtime_events(&connection, &tenant_id, &query, 1_000)?
    };
    let body = serde_json::to_vec_pretty(&page.events)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法导出域名服务日志"))?;
    Ok((
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=domain-runtime-events.json",
            ),
        ],
        body,
    )
        .into_response())
}

#[derive(Debug, Deserialize)]
struct MakePrimaryRequest {
    #[serde(default)]
    confirm: bool,
}

#[derive(Debug, Deserialize)]
struct PublicDomainBatchRequest {
    #[serde(default)]
    ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PublicDomainBatchResponse {
    updated: Vec<PublicDomainResponse>,
    skipped: Vec<BatchSkippedItem>,
    message: String,
}

#[derive(Debug, Serialize, Clone)]
struct PublicDomainMigrationResponse {
    id: String,
    from_domain_id: String,
    to_domain_id: String,
    status: String,
    total_devices: i64,
    acknowledged_devices: i64,
    last_error: Option<String>,
    created_at: i64,
    updated_at: i64,
}

fn default_true() -> bool {
    true
}

fn default_cloudflare() -> String {
    "cloudflare".to_owned()
}

#[derive(Debug, Deserialize)]
struct TunnelOriginCaRequest {
    #[serde(alias = "custom_ca_pem", alias = "origin_ca_pem")]
    ca_pem: String,
}

/// 手动证书可展示的元数据；不保存证书正文、私钥或其他 Secret。
#[derive(Debug, Clone)]
struct CertificateMetadata {
    not_before: i64,
    not_after: i64,
    subjects: Vec<String>,
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
    /// 官方客户端与 Nexo Agent 共用一张设备表，但只有 Agent 设备可承载
    /// Nexo Tunnel 或网关 Desired State。
    connection_type: String,
    owner_user_id: Option<String>,
    owner_username: Option<String>,
    registration_method: Option<String>,
    tags: Vec<String>,
    tailscale_ipv4: Option<String>,
    tailscale_ipv6: Option<String>,
    expires_at: Option<i64>,
    control_plane_state: Option<String>,
    last_seen_at: Option<i64>,
    /// 供删除确认窗说明设备删除后的 Tunnel 处置方式。
    tunnel_count: i64,
}

#[derive(Debug, Deserialize)]
struct UpdateDeviceRequest {
    name: String,
    site_id: Option<String>,
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
    /// Web 预先指定的展示名称；旧客户端省略时继续使用 Agent 上报的主机名。
    device_name: Option<String>,
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

#[derive(Debug, Deserialize)]
struct CreateTailscaleAuthKeyRequest {
    label: String,
    #[serde(default)]
    reusable: bool,
    #[serde(default)]
    ephemeral: bool,
    ttl_seconds: Option<i64>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TailscaleAuthKeyResponse {
    id: String,
    label: String,
    key: Option<String>,
    login_server: String,
    reusable: bool,
    ephemeral: bool,
    expires_at: i64,
    state: String,
    created_at: i64,
}

#[derive(Debug, Serialize)]
struct TailscaleExternalNodeResponse {
    node_id: String,
    name: String,
    online: bool,
    addresses: Vec<String>,
    claim_state: String,
    discovered_at: i64,
    last_seen_at: i64,
}

#[derive(Debug, Serialize)]
struct TailscaleClientConfigResponse {
    login_server: String,
    /// Headscale 的授权地址必须由客户端在登录时带注册上下文生成，不能拼接
    /// 一个无效的固定 `/register` 页面。
    browser_authorization_url: Option<String>,
    supported_platforms: Vec<String>,
    notes: Vec<String>,
}

/// 可视化访问规则的写入参数；用户只提交结构化字段，不能直接提交 HuJSON。
#[derive(Debug, Deserialize, Clone)]
struct AccessRuleRequest {
    name: String,
    target_type: String,
    target_id: String,
    #[serde(default)]
    protocols: Vec<String>,
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    ssh_enabled: bool,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    grantee_workspace_ids: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
struct AccessGrantResponse {
    workspace_id: String,
    workspace_name: String,
    status: String,
    accepted_at: Option<i64>,
}

#[derive(Debug, Serialize, Clone)]
struct AccessRuleResponse {
    id: String,
    owner_workspace_id: String,
    owner_username: String,
    name: String,
    target_type: String,
    target_id: String,
    target_label: String,
    protocols: Vec<String>,
    ports: Vec<String>,
    ssh_enabled: bool,
    enabled: bool,
    desired_revision: i64,
    applied_revision: i64,
    apply_status: String,
    apply_error: Option<String>,
    grants: Vec<AccessGrantResponse>,
    created_at: i64,
    updated_at: i64,
}

#[derive(Debug, Serialize)]
struct AccessPolicyPreviewResponse {
    status: AccessPolicyPreviewStatus,
    valid: bool,
    grant_count: usize,
    ssh_rule_count: usize,
    affected_targets: Vec<String>,
    summary: String,
    error: Option<String>,
}

/// Headscale 策略校验的三态结果；`valid` 字段继续保留，兼容旧版 Web 调用方。
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AccessPolicyPreviewStatus {
    Valid,
    Invalid,
    Unavailable,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Clone)]
struct AccessWorkspaceResponse {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize, Default)]
struct ClaimTailscaleNodeRequest {
    name: Option<String>,
}

#[derive(Debug, Serialize)]
struct RouteConfirmationResponse {
    site_id: String,
    confirmed_at: i64,
}

/// 管理员明确选择要共享的本地网络。
#[derive(Debug, Deserialize)]
struct CreateSiteNetworkRequest {
    tenant_id: String,
    site_id: String,
    name: String,
    publisher_device_id: String,
    /// 旧版请求仍传入字符串；手动模式允许省略或传空字符串。
    #[serde(default)]
    interface_id: String,
    prefix: String,
    /// API 使用 detected/manual；数据库沿用 direct_interface/manual。
    #[serde(default)]
    source: SiteNetworkSourceRequest,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum SiteNetworkSourceRequest {
    #[default]
    Detected,
    Manual,
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
    interface_id: Option<String>,
    source: String,
    /// Agent 在本地局域网上的地址；路由器应把远端网段指向该地址。
    gateway_address: Option<String>,
    desired_prefix: String,
    applied_prefix: Option<String>,
    desired_revision: i64,
    enabled: bool,
    apply_status: ApplyStatus,
    apply_error: Option<String>,
    deletion_pending: bool,
    /// 独立于 Desired / Applied 的网关健康状态，避免“设备在线”被误认为路由已生效。
    health_status: GatewayHealthStatus,
    health_error: Option<String>,
}

/// 管理员创建两个站点之间的双向互联期望状态。
#[derive(Debug, Deserialize)]
struct CreateSiteLinkRequest {
    tenant_id: String,
    left_site_id: String,
    left_network_ids: Vec<String>,
    right_site_id: String,
    right_network_ids: Vec<String>,
    #[serde(default)]
    next_hops: SiteLinkNextHops,
}

/// 按站点和地址族保存静态路由下一跳。下一跳只接受 Agent 最近一次
/// 能力报告中的 LAN 地址，服务端不会替用户路由器写入配置。
#[derive(Debug, Clone, Default, Deserialize)]
struct SiteLinkNextHops {
    #[serde(default)]
    left: SiteLinkFamilyNextHops,
    #[serde(default)]
    right: SiteLinkFamilyNextHops,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct SiteLinkFamilyNextHops {
    #[serde(default)]
    ipv4: Option<String>,
    #[serde(default)]
    ipv6: Option<String>,
}

impl SiteLinkNextHops {
    fn value(&self, side: &str, family: &str) -> Option<String> {
        match (side, family) {
            ("left", "ipv4") => self.left.ipv4.clone(),
            ("left", "ipv6") => self.left.ipv6.clone(),
            ("right", "ipv4") => self.right.ipv4.clone(),
            ("right", "ipv6") => self.right.ipv6.clone(),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct UpdateSiteLinkRequest {
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    left_network_ids: Option<Vec<String>>,
    #[serde(default)]
    right_network_ids: Option<Vec<String>>,
    #[serde(default)]
    next_hops: SiteLinkNextHops,
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
    left_gateway_address: Option<String>,
    right_gateway_address: Option<String>,
    left_networks: Vec<SiteLinkNetworkSummary>,
    right_networks: Vec<SiteLinkNetworkSummary>,
    static_routes: Vec<StaticRouteGuide>,
    route_statuses: Vec<SiteLinkRouteStatus>,
    route_confirmations: Vec<RouteConfirmationResponse>,
    enabled: bool,
    apply_status: ApplyStatus,
    apply_error: Option<String>,
    deletion_pending: bool,
    /// 两端网关和站点互联路由的综合健康状态。
    health_status: GatewayHealthStatus,
    health_error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct SiteLinkNetworkSummary {
    id: String,
    name: String,
    prefix: String,
    source: String,
    address_family: String,
    publisher_device_id: String,
    publisher_device_name: String,
    gateway_address: Option<String>,
    apply_status: ApplyStatus,
}

/// 单条远端网段在设备发布、控制端服务和对端接受阶段的聚合状态。
#[derive(Debug, Serialize, Clone)]
struct SiteLinkRouteStatus {
    network_id: String,
    router_site_id: String,
    destination_site_id: String,
    destination_prefix: String,
    address_family: String,
    device_status: String,
    control_plane_status: String,
    remote_status: String,
    error: Option<String>,
    checked_at: Option<i64>,
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
        .with_timer(tracing_subscriber::fmt::time::ChronoLocal::rfc_3339())
        .with_env_filter("nexo_server=info")
        .init();

    if let Some(command) = Cli::parse().command {
        return run_cli_command(command);
    }

    let db_path = database_path()?;
    let connection = Connection::open(&db_path)
        .with_context(|| format!("无法打开 Nexo 数据库：{}", db_path.display()))?;
    initialize_v012_database(&connection).context("无法初始化或检查 Nexo 数据库基线")?;
    apply_oidc_accounts_migration(&connection).context("无法初始化 OIDC 账号映射数据结构")?;
    ensure_server_ca(&connection).context("无法初始化服务端设备身份 CA")?;
    ensure_server_control_identity(&connection).context("无法初始化控制通道服务端证书")?;
    let data_dir = db_path
        .parent()
        .map(PathBuf::from)
        .context("Nexo 数据库路径缺少父目录")?;
    let oidc =
        Arc::new(oidc::OidcRuntime::initialize(&connection).context("无法初始化 OIDC 签名密钥")?);
    if let Err(error) = oidc.sync_issuer_from_database(&connection) {
        tracing::error!("无法初始化 OIDC issuer：{error:#}");
        return Err(error);
    }
    auth::ensure_bootstrap_code(&connection, &data_dir)
        .context("无法初始化管理员 Bootstrap Secret")?;
    let control_tls = build_control_tls_config(&connection).context("无法构建 mTLS 控制通道")?;
    // Caddy 回源使用独立的服务端 TLS 配置，不要求 Caddy 提供设备客户端证书。
    // 配置异常只会使公网管理入口不可用，不能阻止 LAN 管理、设备注册或 Tunnel 启动。
    let public_backend_tls = match build_public_backend_tls_config(&connection) {
        Ok(config) => Some(config),
        Err(error) => {
            tracing::warn!("无法构建 Caddy 管理后端 TLS，公网管理入口暂不可用：{error:#}");
            None
        }
    };

    // 官方阶段一镜像通过 NEXO_HEADSCALE_BIN 启用内置 Headscale；本地开发没有
    // 该变量时安全降级为 Pending，不会尝试启动宿主机上未知的 Headscale。
    let mut headscale_config = HeadscaleRuntimeConfig::from_env(data_dir.clone());
    headscale_config.oidc_issuer = oidc.issuer();
    let headscale_runtime = Arc::new(HeadscaleSupervisor::new(headscale_config));
    let mut api_key_rotation_task: Option<tokio::task::JoinHandle<()>> = None;
    let headscale: Arc<dyn HeadscaleControlPlane> = if headscale_runtime.config().enabled {
        if let Err(error) = headscale_runtime.clone().start().await {
            tracing::error!("内置 Headscale 尚未启动，组网进入等待状态：{error:#}");
        }
        let manager = ApiKeyManager::with_config(
            &headscale_runtime.config().binary,
            headscale_runtime.config().secret_path(),
            headscale_runtime.config().config_path(),
        );
        let adapter = Arc::new(HeadscaleHttpAdapter::new_unconfigured(
            headscale_runtime.config().api_url.clone(),
        )?);
        if let Ok(Some((api_key, _))) = manager.read() {
            if let Err(error) = adapter.replace_api_key(api_key) {
                tracing::warn!(
                    "读取已有 Headscale API Key 失败，组网将等待重新 Bootstrap：{error:#}"
                );
            }
        }
        api_key_rotation_task = Some(spawn_api_key_bootstrap(
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
        data_dir: data_dir.clone(),
        headscale,
        mesh_offers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        mesh_enrollment_lock: Arc::new(tokio::sync::Mutex::new(())),
        tunnel_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        public_listener_tasks: Arc::new(Mutex::new(HashMap::new())),
        active_tunnel_connections: Arc::new(Mutex::new(HashMap::new())),
        caddy: Arc::new(caddy::CaddySupervisor::new(
            caddy::CaddyRuntimeConfig::from_env(data_dir.clone()),
        )),
        headscale_runtime: headscale_runtime.clone(),
        oidc,
    };
    sync_headscale_server_url(&state).await;
    restore_public_tunnel_listeners(&state).await;
    if let Err(error) = write_caddy_startup_config(&state) {
        tracing::warn!("无法生成 Caddy 启动配置，公网 Web 服务将在恢复后重试：{error:#}");
    }
    if let Err(error) = state.caddy.clone().start().await {
        tracing::warn!("Caddy 启动协调失败，公网 Web 服务暂不可用：{error:#}");
    }
    reconcile_caddy_config_best_effort(&state).await;
    let caddy_reconciliation_task = spawn_caddy_reconciliation(state.clone());
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
    let tunnel_tls = control_tls.clone();
    tokio::spawn(async move {
        if let Err(error) =
            serve_control_listener(control_listener, control_tls, control_state).await
        {
            tracing::error!("Nexo mTLS 控制通道异常退出：{error:#}");
        }
    });
    let tunnel_listener_task = match env::var("NEXO_TUNNEL_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9891".to_owned())
        .parse::<SocketAddr>()
    {
        Ok(address) => match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => {
                let tunnel_state = state.clone();
                Some(tokio::spawn(async move {
                    if let Err(error) =
                        serve_tunnel_listener(listener, tunnel_tls, tunnel_state).await
                    {
                        tracing::error!("Tunnel 数据通道异常退出：{error:#}");
                    }
                }))
            }
            Err(error) => {
                tracing::error!("无法监听 Tunnel 数据通道，公网 TCP 暂不可用：{error}");
                None
            }
        },
        Err(error) => {
            tracing::error!("NEXO_TUNNEL_ADDR 不是有效地址，公网 TCP 暂不可用：{error}");
            None
        }
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/auth/status", get(auth::auth_status))
        .route("/api/v1/auth/session", get(auth::current_session_info))
        .route("/api/v1/auth/initialize", post(auth::initialize))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/password", post(auth::change_password))
        .route("/api/v1/auth/sessions", get(auth::list_sessions))
        .route("/api/v1/auth/sessions/{id}", post(auth::revoke_session))
        .route("/api/v1/auth/recover", post(auth::recover))
        .route("/api/v1/users/{id}/disable", post(auth::disable_user))
        .route("/api/v1/users/{id}/enable", post(auth::enable_user))
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route("/oidc/authorize", get(oidc::authorize))
        .route("/oidc/token", post(oidc::token))
        .route("/oidc/userinfo", get(oidc::userinfo))
        .route("/oidc/jwks.json", get(oidc::jwks))
        .route(
            "/api/v1/users",
            get(auth::list_users).post(auth::create_user),
        )
        .route(
            "/api/v1/public-domains",
            get(list_public_domains).post(create_public_domain),
        )
        .route(
            "/api/v1/public-domains/{id}",
            put(update_public_domain).delete(delete_public_domain),
        )
        .route(
            "/api/v1/public-domains/{id}/credentials",
            post(upload_public_domain_credentials),
        )
        .route(
            "/api/v1/public-domains/{id}/manual-certificate",
            delete(delete_public_domain_manual_certificate),
        )
        .route(
            "/api/v1/public-domains/{id}/recheck",
            post(recheck_public_domain),
        )
        .route(
            "/api/v1/public-domains/{id}/make-primary",
            post(make_public_domain_primary),
        )
        .route(
            "/api/v1/public-domains/{id}/renew",
            post(renew_public_domain),
        )
        .route(
            "/api/v1/public-domains/{id}/dns/preview",
            get(preview_public_domain_dns),
        )
        .route(
            "/api/v1/public-domains/{id}/dns/apply",
            post(apply_public_domain_dns),
        )
        .route(
            "/api/v1/public-domains/{id}/dns/managed-records",
            delete(release_public_domain_dns),
        )
        .route(
            "/api/v1/public-domains/batch/dns/apply",
            post(batch_apply_public_domain_dns),
        )
        .route(
            "/api/v1/public-domains/batch/recheck",
            post(batch_recheck_public_domains),
        )
        .route(
            "/api/v1/public-domains/batch/renew",
            post(batch_renew_public_domains),
        )
        .route(
            "/api/v1/public-domain-migrations/{id}",
            get(get_public_domain_migration),
        )
        .route(
            "/api/v1/public-domain-runtime-events",
            get(list_public_domain_runtime_events),
        )
        .route(
            "/api/v1/public-domain-runtime-events/export",
            get(export_public_domain_runtime_events),
        )
        .route("/api/v1/tunnels", get(list_tunnels).post(create_tunnel))
        .route(
            "/api/v1/tunnels/batch/device",
            put(batch_update_tunnel_device),
        )
        .route("/api/v1/tunnels/batch/enable", post(batch_enable_tunnels))
        .route("/api/v1/tunnels/batch/disable", post(batch_disable_tunnels))
        .route("/api/v1/tunnels/batch", delete(batch_delete_tunnels))
        .route(
            "/api/v1/tunnels/{id}",
            get(get_tunnel).put(update_tunnel).delete(delete_tunnel),
        )
        .route("/api/v1/tunnels/{id}/enable", post(enable_tunnel))
        .route("/api/v1/tunnels/{id}/disable", post(disable_tunnel))
        .route("/api/v1/tunnels/{id}/recheck", post(recheck_tunnel))
        .route(
            "/api/v1/tunnels/{id}/origin-ca",
            post(upload_tunnel_origin_ca),
        )
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/devices", get(list_devices))
        .route(
            "/api/v1/devices/{id}",
            put(update_device).delete(delete_device),
        )
        .route("/api/v1/sites", get(list_sites).post(create_site))
        .route("/api/v1/sites/{id}", delete(delete_site))
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
            "/api/v1/access-control/rules",
            get(list_access_rules).post(create_access_rule),
        )
        .route(
            "/api/v1/access-control/workspaces",
            get(list_access_control_workspaces),
        )
        .route(
            "/api/v1/access-control/rules/{id}",
            put(update_access_rule).delete(delete_access_rule),
        )
        .route(
            "/api/v1/access-control/policy/preview",
            get(current_access_policy_preview).post(preview_access_policy),
        )
        .route(
            "/api/v1/mesh/auth-keys",
            get(list_tailscale_auth_keys).post(create_tailscale_auth_key),
        )
        .route("/api/v1/mesh/client-config", get(tailscale_client_config))
        .route(
            "/api/v1/mesh/auth-keys/{id}/revoke",
            post(revoke_tailscale_auth_key),
        )
        .route(
            "/api/v1/mesh/external-nodes",
            get(list_tailscale_external_nodes),
        )
        .route(
            "/api/v1/mesh/external-nodes/{node_id}/claim",
            post(claim_tailscale_external_node),
        )
        .route(
            "/api/v1/devices/{id}/mesh/recover",
            post(recover_mesh_identity),
        )
        .route(
            "/api/v1/site-networks",
            get(list_site_networks).post(create_site_network),
        )
        .route(
            "/api/v1/site-networks/{id}",
            get(get_site_network).delete(delete_site_network),
        )
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
        .route(
            "/api/v1/site-links/{id}",
            get(get_site_link)
                .patch(update_site_link)
                .delete(delete_site_link),
        )
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::session_middleware,
        ))
        .with_state(state.clone());

    // LAN 管理入口与 Caddy 专用的 loopback 后端共用同一套 API 路由。
    // 后端只绑定本机，外部设备无法绕过 Caddy 直接取得公网 HTTPS Session。
    let backend_task = if let Some(public_backend_tls) = public_backend_tls {
        match env::var("NEXO_PUBLIC_BACKEND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:9888".to_owned())
            .parse::<SocketAddr>()
        {
            Ok(backend_address) => match tokio::net::TcpListener::bind(backend_address).await {
                Ok(listener) => {
                    let backend_app = app.clone();
                    let backend_listener = PublicBackendTlsListener {
                        listener,
                        acceptor: TlsAcceptor::from(public_backend_tls),
                    };
                    Some(tokio::spawn(async move {
                        if let Err(error) = axum::serve(
                            backend_listener,
                            backend_app.into_make_service_with_connect_info::<PublicBackendPeer>(),
                        )
                        .with_graceful_shutdown(async {
                            if let Err(error) = wait_for_shutdown_signal().await {
                                tracing::warn!("等待 Caddy 管理后端退出信号失败：{error}");
                            }
                        })
                        .await
                        {
                            tracing::warn!("Caddy 管理后端异常退出，公网管理入口暂不可用：{error}");
                        }
                    }))
                }
                Err(error) => {
                    tracing::warn!(
                        "无法监听 Caddy 专用管理后端 {backend_address}，公网管理入口暂不可用：{error}"
                    );
                    None
                }
            },
            Err(error) => {
                tracing::warn!(
                    "NEXO_PUBLIC_BACKEND_ADDR 不是有效地址，公网管理后端未启动：{error}"
                );
                None
            }
        }
    } else {
        None
    };

    let address: SocketAddr = env::var("NEXO_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8280".to_owned())
        .parse()
        .context("NEXO_HTTP_ADDR 不是有效的监听地址")?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("无法监听 Nexo API 地址：{address}"))?;
    tracing::info!("Nexo Server 已启动，API 监听于 {address}");
    let shutdown_runtime = headscale_runtime.clone();
    let serve_result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
    caddy_reconciliation_task.abort();
    let _ = caddy_reconciliation_task.await;
    if let Some(task) = tunnel_listener_task {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = backend_task {
        task.abort();
        let _ = task.await;
    }
    if let Ok(mut tasks) = state.public_listener_tasks.lock() {
        for (_, task) in tasks.drain() {
            task.abort.abort();
        }
    }
    shutdown_runtime.shutdown().await?;
    state.caddy.shutdown().await?;
    serve_result?;
    Ok(())
}

/// 本地管理命令直接复用同一套迁移，不依赖运行中的 HTTP 端口或管理员 Session。
fn run_cli_command(command: CliCommand) -> Result<()> {
    let db_path = database_path()?;
    let connection = Connection::open(&db_path)
        .with_context(|| format!("无法打开 Nexo 数据库：{}", db_path.display()))?;
    initialize_v012_database(&connection)?;
    apply_oidc_accounts_migration(&connection)?;
    let data_dir = db_path.parent().context("Nexo 数据库路径缺少父目录")?;
    match command {
        CliCommand::BootstrapCode => {
            // CLI 可能在 Server 首次启动前执行；沿用服务启动的同一初始化路径，
            // 确保 Secret 已生成后再读取，避免首次运行因文件尚不存在而失败。
            auth::ensure_bootstrap_code(&connection, data_dir)
                .context("无法初始化管理员 Bootstrap Secret")?;
            println!("{}", auth::read_bootstrap_code(data_dir)?);
        }
        CliCommand::Admin {
            command: AdminCommand::Recover,
        } => {
            let code = auth::issue_recovery_code(&connection)?;
            println!("恢复页面：http://127.0.0.1:8280/recover");
            println!("Recovery Code（10 分钟内有效，仅可使用一次）：{code}");
        }
    }
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

/// 创建全新安装的 v0.1.12 基线，或验证现有数据库已经完成该基线。
///
/// 只有完全没有 `schema_migrations` 的数据库会执行基线 SQL。任何已经存在
/// 但没有版本 19 的数据库都被视为旧版本/不完整数据库并拒绝启动，避免新代码
/// 误把历史结构当作当前结构继续补丁。
fn initialize_v012_database(connection: &Connection) -> Result<()> {
    let has_migrations_table: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'
         )",
        [],
        |row| row.get(0),
    )?;
    if !has_migrations_table {
        connection
            .execute_batch(V012_BASELINE_MIGRATION)
            .context("无法创建 v0.1.12 数据库基线")?;
    }
    let has_v012: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 19)",
            [],
            |row| row.get(0),
        )
        .map_err(|error| anyhow::anyhow!("无法读取 Nexo 数据库迁移版本：{error}"))?;
    if !has_v012 {
        anyhow::bail!(
            "数据库版本过旧或未完成迁移；当前版本只支持全新安装或从 v0.1.12 升级，请先升级到 v0.1.12"
        );
    }
    connection.execute_batch("PRAGMA foreign_keys = ON")?;
    Ok(())
}

/// 从 v0.1.12 基线一次性建立账号状态和 OIDC 映射；此后的启动只检查版本号，
/// 不再重新执行旧版本的启动期兼容补丁。
fn apply_oidc_accounts_migration(connection: &Connection) -> Result<()> {
    let applied = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 20)",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if applied {
        return Ok(());
    }
    let has_v012: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 19)",
        [],
        |row| row.get(0),
    )?;
    if !has_v012 {
        anyhow::bail!("数据库版本过旧或未完成迁移；OIDC 账号迁移要求先升级到 v0.1.12");
    }
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(OIDC_ACCOUNTS_MIGRATION)?;
    transaction.commit()?;
    Ok(())
}

/// 在 Server 持续运行期间定期检查并轮换 Headscale API Key。
///
/// 轮换器只拿到内存中的适配器句柄；新 Key 通过健康 API 自检后才由
/// `ApiKeyManager` 原子切换 Secret，适配器随后热切换，旧 Key 再被吊销。
fn spawn_api_key_bootstrap(
    manager: ApiKeyManager,
    adapter: Arc<HeadscaleHttpAdapter>,
    api_url: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut delay = std::time::Duration::from_secs(1);
        loop {
            match manager
                .bootstrap_or_rotate_checked(headscale::unix_now(), &api_url)
                .await
            {
                Ok((api_key, _)) => {
                    if let Err(error) = adapter.replace_api_key(api_key) {
                        tracing::error!("Headscale API Key 热切换失败：{error:#}");
                    } else {
                        tracing::info!("Headscale API Key 检查完成");
                        delay = std::time::Duration::from_secs(6 * 60 * 60);
                    }
                }
                Err(error) => {
                    tracing::warn!("Headscale API Key 初始化/轮换失败，将自动重试：{error:#}");
                    delay = delay
                        .saturating_mul(2)
                        .min(std::time::Duration::from_secs(120));
                }
            }
            tokio::time::sleep(delay).await;
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
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let devices = count_for_tenant(
        &connection,
        "SELECT COUNT(*) FROM devices WHERE tenant_id = ?1",
        &tenant_id,
    )
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备数量"))?;
    let running_tunnels = count_for_tenant(
        &connection,
        "SELECT COUNT(*) FROM tunnels WHERE tenant_id = ?1 AND enabled = 1 AND apply_status = 'ready'",
        &tenant_id,
    )
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取隧道数量"))?;
    let mesh_devices = count_for_tenant(
        &connection,
        "SELECT COUNT(*) FROM devices WHERE tenant_id = ?1 AND capabilities_json LIKE '%mesh%'",
        &tenant_id,
    )
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取组网设备数量"))?;
    let current_connections = count_for_tenant(
        &connection,
        "SELECT COUNT(*) FROM devices WHERE tenant_id = ?1 AND status = 'online'",
        &tenant_id,
    )
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取在线设备数量"))?;
    Ok(Json(OverviewResponse {
        devices,
        running_tunnels,
        mesh_devices,
        current_connections,
    }))
}

/// 查询所有公网访问配置；已删除记录不会再出现在管理界面。
async fn list_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TunnelResponse>>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(&tunnel_query(
            "WHERE t.deleted_at IS NULL AND t.tenant_id = ?1
             ORDER BY t.updated_at DESC, t.name ASC",
        ))
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取穿透服务列表"))?;
    let rows = statement
        .query_map([tenant_id], tunnel_response_from_row)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取穿透服务列表"))?;
    rows.map(|row| {
        row.map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "穿透服务数据格式无效"))
    })
    .collect::<Result<Vec<_>, _>>()
    .map(Json)
}

async fn get_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TunnelResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            &tunnel_query("WHERE t.id = ?1 AND t.tenant_id = ?2 AND t.deleted_at IS NULL"),
            rusqlite::params![id, tenant_id],
            tunnel_response_from_row,
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "穿透服务不存在"))
}

async fn create_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTunnelRequest>,
) -> Result<Json<TunnelResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let normalized = normalize_tunnel_request(&state, request)?;
    ensure_tenant_scope(&normalized.tenant_id, &tenant_id)?;
    let id = Uuid::new_v4().to_string();
    let bridge_socket_path = if matches!(normalized.protocol.as_str(), "http" | "https") {
        Some(tunnel_bridge_socket_path(&state.data_dir, &id))
    } else {
        None
    };
    let mut secret_rollbacks = Vec::new();
    let origin_ca_path = if normalized.origin_tls_verification == "custom_ca" {
        let ca = normalized.origin_ca_pem.as_deref().ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "选择自定义证书校验时必须提供该 Web 服务的 CA",
            )
        })?;
        let path = tunnel_origin_ca_path(&state.data_dir, &id);
        capture_secret_rollback(&mut secret_rollbacks, &path);
        write_secret_file(&path, ca)?;
        Some(path)
    } else {
        None
    };
    let (public_port, audit_tenant, audit_protocol) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let public_port = allocate_public_port(
            &connection,
            normalized.public_port,
            &normalized.protocol,
            None,
            false,
        )?;
        let revision = 1_i64;
        let audit_tenant = normalized.tenant_id.clone();
        let audit_protocol = normalized.protocol.clone();
        connection
            .execute(
                "INSERT INTO tunnels
             (id, tenant_id, device_id, name, protocol, local_address, local_port,
             public_port, hostname, enabled, apply_status, apply_revision,
              origin_protocol, origin_tls_server_name, origin_tls_verification,
               service_name, bridge_socket_path, origin_ca_secret_path, public_domain_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, 'checking', ?10,
                     ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                rusqlite::params![
                    id,
                    normalized.tenant_id,
                    normalized.device_id,
                    normalized.name,
                    normalized.protocol,
                    normalized.local_address,
                    normalized.local_port,
                    public_port,
                    normalized.hostname,
                    revision,
                    normalized.origin_protocol,
                    normalized.origin_tls_server_name,
                    normalized.origin_tls_verification,
                    normalized.service_name,
                    bridge_socket_path
                        .as_ref()
                        .map(|path| path.to_string_lossy().to_string()),
                    origin_ca_path
                        .as_ref()
                        .map(|path| path.to_string_lossy().to_string()),
                    normalized.public_domain_id,
                ],
            )
            .map_err(|error| {
                tracing::error!("保存公网访问配置失败：{error}");
                ApiError::new(StatusCode::CONFLICT, "穿透服务与现有记录冲突")
            })?;
        connection
            .execute(
                "INSERT INTO tunnel_applied_states
             (tunnel_id, applied_revision, applied_config_json, apply_status, updated_at)
             VALUES (?1, 0, '{}', 'checking', unixepoch())",
                [&id],
            )
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法创建穿透服务应用状态",
                )
            })?;
        (public_port, audit_tenant, audit_protocol)
    };
    if normalized.protocol == "tcp" {
        if let Some(port) = public_port {
            start_public_tunnel_listener(state.clone(), id.clone(), port).await;
        }
    } else if let Some(path) = bridge_socket_path {
        start_public_web_listener(state.clone(), id.clone(), path).await;
    }
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .execute(
                "INSERT INTO audit_events
                 (tenant_id, event_type, resource_type, resource_id, detail_json)
                 VALUES (?1, 'tunnel_created', 'tunnel', ?2, ?3)",
                rusqlite::params![
                    audit_tenant,
                    id,
                    serde_json::json!({ "protocol": audit_protocol }).to_string()
                ],
            )
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法写入穿透服务审计记录",
                )
            })?;
    }
    reconcile_caddy_config_best_effort(&state).await;
    let response = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                &tunnel_query("WHERE t.id = ?1 AND t.tenant_id = ?2 AND t.deleted_at IS NULL"),
                rusqlite::params![id, tenant_id],
                tunnel_response_from_row,
            )
            .map(Json)
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取新建穿透服务"))
    };
    if response.is_ok() {
        for rollback in &mut secret_rollbacks {
            rollback.commit();
        }
    }
    response
}

async fn update_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateTunnelRequest>,
) -> Result<Json<TunnelResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let normalized = normalize_tunnel_request(&state, request)?;
    ensure_tenant_scope(&normalized.tenant_id, &tenant_id)?;
    let new_protocol = normalized.protocol.clone();
    let bridge_socket_path = if matches!(new_protocol.as_str(), "http" | "https") {
        Some(tunnel_bridge_socket_path(&state.data_dir, &id))
    } else {
        None
    };
    let (public_port, revision, old_origin_ca_path, was_enabled) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let old: (i64, String, String, Option<u16>, Option<String>, bool, i64) = connection
            .query_row(
                "SELECT apply_revision, tenant_id, protocol, public_port, origin_ca_secret_path,
                        enabled, deletion_requested
                 FROM tunnels WHERE id = ?1 AND deleted_at IS NULL",
                [&id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "穿透服务不存在"))?;
        if old.1 != normalized.tenant_id {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "穿透服务不属于当前租户",
            ));
        }
        if old.6 != 0 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "穿透服务正在等待删除，不能再编辑",
            ));
        }
        let requested_port = normalized.public_port.or_else(|| {
            (new_protocol == "tcp" && old.2 == "tcp")
                .then_some(old.3)
                .flatten()
        });
        // 更新同一个 TCP Tunnel 时，旧监听器仍然占着宿主机端口。
        // 只有确认该监听器确实属于当前 Tunnel，才跳过 bind 检查；若监听器
        // 已经异常退出，则继续走真实宿主机占用检查，避免吞掉外部冲突。
        let current_listener_owned =
            old.2 == "tcp" && requested_port == old.3 && public_listener_is_active(&state, &id);
        let public_port = allocate_public_port(
            &connection,
            requested_port,
            &new_protocol,
            Some(&id),
            current_listener_owned,
        )?;
        let revision = old.0.saturating_add(1).max(1);
        (public_port, revision, old.4, old.5)
    };
    let mut secret_rollbacks = Vec::new();
    let requested_origin_ca_path = normalized
        .origin_ca_pem
        .as_ref()
        .map(|_| tunnel_origin_ca_path(&state.data_dir, &id));
    if let Some(path) = requested_origin_ca_path.as_ref() {
        capture_secret_rollback(&mut secret_rollbacks, path);
        if let Some(ca) = normalized.origin_ca_pem.as_deref() {
            write_secret_file(path, ca)?;
        }
    }
    if let Some(old_path) = old_origin_ca_path.as_deref() {
        capture_secret_rollback(&mut secret_rollbacks, std::path::Path::new(old_path));
    }
    let origin_ca_path = if normalized.origin_tls_verification == "custom_ca" {
        let path = requested_origin_ca_path
            .clone()
            .or_else(|| old_origin_ca_path.clone().map(PathBuf::from))
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "选择自定义证书校验时必须提供该 Web 服务的 CA",
                )
            })?;
        if !path.is_file() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "自定义 CA Secret 不存在，请重新上传该 Web 服务的 CA",
            ));
        }
        Some(path)
    } else {
        None
    };
    stop_public_tunnel_listener(&state, &id);
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .execute(
                "UPDATE tunnels SET device_id = ?1, name = ?2, protocol = ?3,
                 local_address = ?4, local_port = ?5, public_port = ?6, hostname = ?7,
                  origin_protocol = ?8, origin_tls_server_name = ?9,
                   origin_tls_verification = ?10, service_name = ?11,
                   bridge_socket_path = ?12, origin_ca_secret_path = ?13,
                   public_domain_id = ?14, enabled = ?15, deletion_requested = 0,
                   deletion_revision = NULL, apply_status = ?16, apply_error = NULL,
                  apply_revision = ?17, updated_at = CURRENT_TIMESTAMP
                  WHERE id = ?18 AND tenant_id = ?19 AND deleted_at IS NULL",
                rusqlite::params![
                    normalized.device_id,
                    normalized.name,
                    normalized.protocol,
                    normalized.local_address,
                    normalized.local_port,
                    public_port,
                    normalized.hostname,
                    normalized.origin_protocol,
                    normalized.origin_tls_server_name,
                    normalized.origin_tls_verification,
                    normalized.service_name,
                    bridge_socket_path
                        .as_ref()
                        .map(|path| path.to_string_lossy().to_string()),
                    origin_ca_path
                        .as_ref()
                        .map(|path| path.to_string_lossy().to_string()),
                    normalized.public_domain_id,
                    i64::from(was_enabled),
                    if was_enabled { "checking" } else { "disabled" },
                    revision,
                    id,
                    tenant_id,
                ],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新穿透服务"))?;
    }
    if let Some(old_path) = old_origin_ca_path.as_deref() {
        let keep_old_path = origin_ca_path
            .as_deref()
            .is_some_and(|path| path == std::path::Path::new(old_path));
        if !keep_old_path {
            if let Err(error) = fs::remove_file(old_path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(tunnel_id = %id, "无法清理旧 Web 服务 CA Secret：{error}");
                }
            }
        }
    }
    if was_enabled {
        if new_protocol == "tcp" {
            if let Some(port) = public_port {
                start_public_tunnel_listener(state.clone(), id.clone(), port).await;
            }
        } else if let Some(path) = bridge_socket_path {
            start_public_web_listener(state.clone(), id.clone(), path).await;
        }
    }
    reconcile_caddy_config_best_effort(&state).await;
    let response = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                &tunnel_query("WHERE t.id = ?1 AND t.tenant_id = ?2 AND t.deleted_at IS NULL"),
                rusqlite::params![id, tenant_id],
                tunnel_response_from_row,
            )
            .map(Json)
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法读取更新后的穿透服务",
                )
            })
    };
    if response.is_ok() {
        for rollback in &mut secret_rollbacks {
            rollback.commit();
        }
    }
    response
}

/// 为单个 Web Service 上传自定义 CA。Secret 路径由 Server 生成并与
/// Tunnel 绑定，用户不能通过请求体控制文件名或让其他服务复用该 CA。
async fn upload_tunnel_origin_ca(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<TunnelOriginCaRequest>,
) -> Result<Json<TunnelResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let ca = request.ca_pem.trim();
    if !ca.contains("BEGIN CERTIFICATE") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "自定义 CA 证书格式无效",
        ));
    }
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        ensure_tunnel_not_deleting(&connection, &id, &tenant_id)?;
        let exists: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM tunnels
                 WHERE id = ?1 AND tenant_id = ?2 AND deleted_at IS NULL
                   AND protocol IN ('http', 'https')",
                rusqlite::params![id, tenant_id],
                |row| row.get(0),
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查 Web 服务"))?;
        if exists == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "Web 服务不存在"));
        }
    }
    let path = tunnel_origin_ca_path(&state.data_dir, &id);
    let mut secret_rollbacks = Vec::new();
    capture_secret_rollback(&mut secret_rollbacks, &path);
    write_secret_file(&path, ca)?;
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let changed = connection
            .execute(
                "UPDATE tunnels SET origin_ca_secret_path = ?1,
                 origin_tls_verification = 'custom_ca', apply_status = 'checking',
                 apply_error = NULL, apply_revision = apply_revision + 1,
                 updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?2 AND tenant_id = ?3 AND deleted_at IS NULL
                   AND protocol IN ('http', 'https')",
                rusqlite::params![path.to_string_lossy(), id, tenant_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存 Web 服务 CA")
            })?;
        if changed == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "Web 服务不存在"));
        }
    }
    reconcile_caddy_config_best_effort(&state).await;
    let response = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                &tunnel_query("WHERE t.id = ?1 AND t.tenant_id = ?2 AND t.deleted_at IS NULL"),
                rusqlite::params![id, tenant_id],
                tunnel_response_from_row,
            )
            .map(Json)
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "Web 服务不存在"))
    };
    if response.is_ok() {
        for rollback in &mut secret_rollbacks {
            rollback.commit();
        }
    }
    response
}

async fn delete_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let (origin_ca_path, bridge_socket_path) = {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法开始穿透服务删除事务",
            )
        })?;
        let paths = transaction
            .query_row(
                "SELECT origin_ca_secret_path, bridge_socket_path FROM tunnels
                 WHERE id = ?1 AND tenant_id = ?2 AND deleted_at IS NULL",
                rusqlite::params![id, tenant_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取穿透服务"))?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "穿透服务不存在"))?;
        transaction
            .execute(
                "DELETE FROM tunnel_applied_states WHERE tunnel_id = ?1",
                [&id],
            )
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法删除穿透服务应用状态",
                )
            })?;
        write_audit_event(&transaction, &tenant_id, "TUNNEL_DELETED", "tunnel", &id)?;
        let deleted = transaction
            .execute(
                "DELETE FROM tunnels
                 WHERE id = ?1 AND tenant_id = ?2 AND deleted_at IS NULL",
                rusqlite::params![id, tenant_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法删除穿透服务记录")
            })?;
        if deleted != 1 {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "穿透服务删除结果不一致",
            ));
        }
        transaction.commit().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法提交穿透服务删除事务",
            )
        })?;
        paths
    };
    // 数据库提交后立即撤销公网数据面。Agent 下一次收到不含该项的完整快照时，
    // 会清理内存中的旧配置，因此设备是否在线不影响服务端永久删除。
    stop_public_tunnel_listener(&state, &id);
    stop_active_tunnel_connections(&state, &id);
    cleanup_tunnel_files(&id, origin_ca_path, bridge_socket_path);
    reconcile_caddy_config_best_effort(&state).await;
    tracing::info!(tunnel_id = %id, "穿透服务已永久删除");
    Ok(Json(DeleteResponse {
        deleted: true,
        pending: false,
        id,
        message: "穿透服务已永久删除".to_owned(),
    }))
}

/// 批量 Tunnel 操作只接受去重后的非空 ID；先在内存中固定顺序，后续事务和
/// 返回结果都沿用这个顺序，避免重复 ID 造成部分提交或前端计数漂移。
fn normalize_batch_tunnel_ids(ids: Vec<String>) -> Result<Vec<String>, ApiError> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::with_capacity(ids.len());
    for id in ids {
        let id = id.trim().to_owned();
        if id.is_empty() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "穿透服务 ID 不能为空",
            ));
        }
        if seen.insert(id.clone()) {
            normalized.push(id);
        }
    }
    if normalized.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "至少选择一个穿透服务",
        ));
    }
    Ok(normalized)
}

/// 批量操作的数据库快照。所有记录先在同一个事务中校验租户、存在性和删除
/// 状态，再执行任何写入；这样跨租户或缺失 ID 不会留下半完成的批量结果。
#[derive(Debug, Clone)]
struct BatchTunnelRecord {
    id: String,
    device_id: Option<String>,
    protocol: String,
    public_port: Option<u16>,
    enabled: bool,
    origin_ca_secret_path: Option<String>,
    bridge_socket_path: Option<String>,
}

// 批量读取只在事务内部使用这个行形状；命名别名让字段顺序集中在查询处，
// 也避免把复杂元组类型散落到后续批量操作逻辑中。
type BatchTunnelRow = (
    String,
    Option<String>,
    String,
    Option<i64>,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<i64>,
);

fn load_batch_tunnel_records(
    transaction: &rusqlite::Transaction<'_>,
    tenant_id: &str,
    tunnel_ids: &[String],
) -> Result<Vec<BatchTunnelRecord>, ApiError> {
    let mut records = Vec::with_capacity(tunnel_ids.len());
    for id in tunnel_ids {
        let row: Option<BatchTunnelRow> = transaction
            .query_row(
                "SELECT tenant_id, device_id, protocol, public_port, enabled,
                        deletion_requested, origin_ca_secret_path, bridge_socket_path,
                        deleted_at
                 FROM tunnels WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取穿透服务"))?;
        let Some((
            record_tenant_id,
            device_id,
            protocol,
            public_port,
            enabled,
            deletion_requested,
            origin_ca_secret_path,
            bridge_socket_path,
            deleted_at,
        )) = row
        else {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                format!("穿透服务 {id} 不存在"),
            ));
        };
        if record_tenant_id != tenant_id {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "穿透服务不属于当前租户",
            ));
        }
        if deleted_at.is_some() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                format!("穿透服务 {id} 已删除，不能批量操作"),
            ));
        }
        if deletion_requested != 0 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                format!("穿透服务 {id} 正在等待删除，不能批量操作"),
            ));
        }
        records.push(BatchTunnelRecord {
            id: id.clone(),
            device_id,
            protocol,
            public_port: public_port.and_then(|value| u16::try_from(value).ok()),
            enabled: enabled != 0,
            origin_ca_secret_path,
            bridge_socket_path,
        });
    }
    Ok(records)
}

fn read_tunnel_response(
    connection: &Connection,
    tunnel_id: &str,
    tenant_id: &str,
) -> Result<TunnelResponse, ApiError> {
    connection
        .query_row(
            &tunnel_query("WHERE t.id = ?1 AND t.tenant_id = ?2 AND t.deleted_at IS NULL"),
            rusqlite::params![tunnel_id, tenant_id],
            tunnel_response_from_row,
        )
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法读取更新后的穿透服务",
            )
        })
}

fn batch_response_tunnels(
    connection: &Connection,
    tenant_id: &str,
    updated_ids: &[String],
) -> Result<Vec<TunnelResponse>, ApiError> {
    updated_ids
        .iter()
        .map(|id| read_tunnel_response(connection, id, tenant_id))
        .collect()
}

/// 批量更换设备保留每条 Tunnel 的原有开关状态；未分配项始终保持关闭，
/// 迁移设备时先停止旧数据面连接，随后由新的 Desired State 重新收敛。
async fn batch_update_tunnel_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TunnelBatchDeviceRequest>,
) -> Result<Json<BatchTunnelResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let tunnel_ids = normalize_batch_tunnel_ids(request.tunnel_ids)?;
    let target_device_id = request.device_id.trim().to_owned();
    if target_device_id.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "目标设备不能为空"));
    }

    let (records, updated_ids, skipped) = {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法开始批量更换设备事务",
            )
        })?;
        let target_tenant: Option<String> = transaction
            .query_row(
                "SELECT tenant_id FROM devices WHERE id = ?1",
                [&target_device_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取目标设备"))?;
        let Some(target_tenant) = target_tenant else {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "目标设备不存在"));
        };
        if target_tenant != tenant_id {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "目标设备不属于当前租户",
            ));
        }
        let records = load_batch_tunnel_records(&transaction, &tenant_id, &tunnel_ids)?;
        let mut updated_ids = Vec::new();
        let mut skipped = Vec::new();
        for record in &records {
            if record.device_id.as_deref() == Some(target_device_id.as_str()) {
                skipped.push(BatchSkippedItem {
                    id: record.id.clone(),
                    reason: "已属于目标设备".to_owned(),
                });
                continue;
            }
            let enabled = record.device_id.is_some() && record.enabled;
            let apply_status = if enabled { "checking" } else { "disabled" };
            transaction
                .execute(
                    "UPDATE tunnels SET device_id = ?1, enabled = ?2,
                     apply_status = ?3, apply_error = NULL,
                     apply_revision = apply_revision + 1,
                     updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?4 AND tenant_id = ?5 AND deleted_at IS NULL",
                    rusqlite::params![
                        target_device_id,
                        i64::from(enabled),
                        apply_status,
                        record.id,
                        tenant_id
                    ],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更换穿透服务设备")
                })?;
            transaction
                .execute(
                    "UPDATE tunnel_applied_states
                     SET apply_status = ?1, apply_error = NULL, updated_at = unixepoch()
                     WHERE tunnel_id = ?2",
                    rusqlite::params![apply_status, record.id],
                )
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "无法更新穿透服务应用状态",
                    )
                })?;
            write_audit_event(
                &transaction,
                &tenant_id,
                "TUNNEL_DEVICE_CHANGED",
                "tunnel",
                &record.id,
            )?;
            updated_ids.push(record.id.clone());
        }
        transaction.commit().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法提交批量更换设备事务",
            )
        })?;
        (records, updated_ids, skipped)
    };

    for record in records
        .iter()
        .filter(|record| updated_ids.contains(&record.id))
    {
        stop_public_tunnel_listener(&state, &record.id);
        stop_active_tunnel_connections(&state, &record.id);
        let enabled = record.device_id.is_some() && record.enabled;
        if !enabled {
            continue;
        }
        if record.protocol == "tcp" {
            if let Some(port) = record.public_port {
                start_public_tunnel_listener(state.clone(), record.id.clone(), port).await;
            }
        } else {
            let path = record
                .bridge_socket_path
                .clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| tunnel_bridge_socket_path(&state.data_dir, &record.id));
            if let Err(error) = persist_bridge_socket_path(&state, &record.id, &path) {
                tracing::warn!(tunnel_id = %record.id, "保存批量更换后的 Web Service Socket 路径失败：{error:#}");
            }
            start_public_web_listener(state.clone(), record.id.clone(), path).await;
        }
    }
    if !updated_ids.is_empty() {
        reconcile_caddy_config_best_effort(&state).await;
    }
    let updated = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        batch_response_tunnels(&connection, &tenant_id, &updated_ids)?
    };
    let message = format!(
        "已更换 {} 个穿透服务的设备，跳过 {} 项",
        updated.len(),
        skipped.len()
    );
    Ok(Json(BatchTunnelResponse {
        updated,
        affected_count: updated_ids.len(),
        skipped,
        message,
    }))
}

/// 批量启用只跳过已启用和未分配项；缺失、跨租户或正在删除的 ID 会让整个
/// 请求失败。数据库先统一提交，监听器和 Caddy 在提交后各自只收敛一次。
async fn batch_enable_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TunnelBatchIdsRequest>,
) -> Result<Json<BatchTunnelResponse>, ApiError> {
    batch_set_tunnels_enabled(state, headers, request.tunnel_ids, true).await
}

async fn batch_disable_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TunnelBatchIdsRequest>,
) -> Result<Json<BatchTunnelResponse>, ApiError> {
    batch_set_tunnels_enabled(state, headers, request.tunnel_ids, false).await
}

async fn batch_set_tunnels_enabled(
    state: AppState,
    headers: HeaderMap,
    requested_ids: Vec<String>,
    enabled: bool,
) -> Result<Json<BatchTunnelResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let tunnel_ids = normalize_batch_tunnel_ids(requested_ids)?;
    let records = {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法开始批量切换穿透服务事务",
            )
        })?;
        let records = load_batch_tunnel_records(&transaction, &tenant_id, &tunnel_ids)?;
        let mut updated_ids = Vec::new();
        let mut skipped = Vec::new();
        for record in &records {
            if enabled && record.device_id.is_none() {
                skipped.push(BatchSkippedItem {
                    id: record.id.clone(),
                    reason: "未分配设备，请先更换设备".to_owned(),
                });
                continue;
            }
            if record.enabled == enabled {
                skipped.push(BatchSkippedItem {
                    id: record.id.clone(),
                    reason: if enabled {
                        "已经启用"
                    } else {
                        "已经停用"
                    }
                    .to_owned(),
                });
                continue;
            }
            transaction
                .execute(
                    "UPDATE tunnels SET enabled = ?1, apply_status = ?2,
                     apply_error = NULL, apply_revision = apply_revision + 1,
                     updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?3 AND tenant_id = ?4 AND deleted_at IS NULL",
                    rusqlite::params![
                        i64::from(enabled),
                        if enabled { "checking" } else { "disabled" },
                        record.id,
                        tenant_id
                    ],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新穿透服务开关")
                })?;
            transaction
                .execute(
                    "UPDATE tunnel_applied_states
                     SET apply_status = ?1, apply_error = NULL, updated_at = unixepoch()
                     WHERE tunnel_id = ?2",
                    rusqlite::params![if enabled { "checking" } else { "disabled" }, record.id],
                )
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "无法更新穿透服务应用状态",
                    )
                })?;
            write_audit_event(
                &transaction,
                &tenant_id,
                if enabled {
                    "TUNNEL_ENABLED"
                } else {
                    "TUNNEL_DISABLED"
                },
                "tunnel",
                &record.id,
            )?;
            updated_ids.push(record.id.clone());
        }
        transaction.commit().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法提交批量切换穿透服务事务",
            )
        })?;
        (records, updated_ids, skipped)
    };
    let (records, updated_ids, skipped) = records;

    for record in records
        .iter()
        .filter(|record| updated_ids.contains(&record.id))
    {
        if enabled {
            if record.protocol == "tcp" {
                if let Some(port) = record.public_port {
                    start_public_tunnel_listener(state.clone(), record.id.clone(), port).await;
                }
            } else {
                let path = record
                    .bridge_socket_path
                    .clone()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| tunnel_bridge_socket_path(&state.data_dir, &record.id));
                if let Err(error) = persist_bridge_socket_path(&state, &record.id, &path) {
                    tracing::warn!(tunnel_id = %record.id, "保存批量启用后的 Web Service Socket 路径失败：{error:#}");
                }
                start_public_web_listener(state.clone(), record.id.clone(), path).await;
            }
        } else {
            stop_public_tunnel_listener(&state, &record.id);
            stop_active_tunnel_connections(&state, &record.id);
        }
    }
    if !updated_ids.is_empty() {
        reconcile_caddy_config_best_effort(&state).await;
    }
    let updated = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        batch_response_tunnels(&connection, &tenant_id, &updated_ids)?
    };
    let operation = if enabled { "启用" } else { "停用" };
    let message = format!(
        "已{} {} 个穿透服务，跳过 {} 项",
        operation,
        updated.len(),
        skipped.len()
    );
    Ok(Json(BatchTunnelResponse {
        updated,
        affected_count: updated_ids.len(),
        skipped,
        message,
    }))
}

/// 批量删除在一个事务中移除所有业务状态和审计记录，提交后统一停止数据面、
/// 清理 Secret/Socket，再只触发一次 Caddy 配置收敛。
async fn batch_delete_tunnels(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TunnelBatchIdsRequest>,
) -> Result<Json<BatchTunnelDeleteResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let tunnel_ids = normalize_batch_tunnel_ids(request.tunnel_ids)?;
    let (deleted_ids, cleanups) = {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法开始批量删除穿透服务事务",
            )
        })?;
        let records = load_batch_tunnel_records(&transaction, &tenant_id, &tunnel_ids)?;
        for record in &records {
            transaction
                .execute(
                    "DELETE FROM tunnel_applied_states WHERE tunnel_id = ?1",
                    [&record.id],
                )
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "无法删除穿透服务应用状态",
                    )
                })?;
            write_audit_event(
                &transaction,
                &tenant_id,
                "TUNNEL_DELETED",
                "tunnel",
                &record.id,
            )?;
            let deleted = transaction
                .execute(
                    "DELETE FROM tunnels
                     WHERE id = ?1 AND tenant_id = ?2 AND deleted_at IS NULL",
                    rusqlite::params![record.id, tenant_id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法删除穿透服务记录")
                })?;
            if deleted != 1 {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    format!("穿透服务 {} 删除结果不一致", record.id),
                ));
            }
        }
        transaction.commit().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法提交批量删除穿透服务事务",
            )
        })?;
        let cleanups = records
            .iter()
            .map(|record| {
                (
                    record.id.clone(),
                    record.origin_ca_secret_path.clone(),
                    record.bridge_socket_path.clone(),
                )
            })
            .collect::<Vec<_>>();
        (tunnel_ids, cleanups)
    };

    for (tunnel_id, origin_ca_path, bridge_socket_path) in cleanups {
        stop_public_tunnel_listener(&state, &tunnel_id);
        stop_active_tunnel_connections(&state, &tunnel_id);
        cleanup_tunnel_files(&tunnel_id, origin_ca_path, bridge_socket_path);
    }
    reconcile_caddy_config_best_effort(&state).await;
    tracing::info!(deleted_count = deleted_ids.len(), "批量删除穿透服务已完成");
    Ok(Json(BatchTunnelDeleteResponse {
        affected_count: deleted_ids.len(),
        message: format!(
            "已永久删除 {} 个穿透服务，公网入口已停止",
            deleted_ids.len()
        ),
        deleted_ids,
    }))
}

async fn enable_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TunnelResponse>, ApiError> {
    set_tunnel_enabled(state, headers, id, true).await
}

async fn disable_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TunnelResponse>, ApiError> {
    set_tunnel_enabled(state, headers, id, false).await
}

async fn recheck_tunnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<TunnelResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        ensure_tunnel_not_deleting(&connection, &id, &tenant_id)?;
        let changed = connection
            .execute(
                "UPDATE tunnels SET apply_status = 'checking', apply_error = NULL,
                 updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?1 AND tenant_id = ?2 AND deleted_at IS NULL",
                rusqlite::params![id, tenant_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法重新检测穿透服务")
            })?;
        if changed == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "穿透服务不存在"));
        }
    }
    reconcile_caddy_config_best_effort(&state).await;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            &tunnel_query("WHERE t.id = ?1 AND t.tenant_id = ?2 AND t.deleted_at IS NULL"),
            rusqlite::params![id, tenant_id],
            tunnel_response_from_row,
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取穿透服务状态"))
}

fn ensure_tunnel_not_deleting(
    connection: &Connection,
    id: &str,
    tenant_id: &str,
) -> Result<(), ApiError> {
    let deletion_requested = connection
        .query_row(
            "SELECT deletion_requested FROM tunnels
             WHERE id = ?1 AND tenant_id = ?2 AND deleted_at IS NULL",
            rusqlite::params![id, tenant_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取穿透服务"))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "穿透服务不存在"))?;
    if deletion_requested != 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "穿透服务正在等待删除，不能重复操作",
        ));
    }
    Ok(())
}

async fn set_tunnel_enabled(
    state: AppState,
    headers: HeaderMap,
    id: String,
    enabled: bool,
) -> Result<Json<TunnelResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let (protocol, public_port) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let (device_id, protocol, public_port, deletion_requested): (
            Option<String>,
            String,
            Option<u16>,
            i64,
        ) = connection
            .query_row(
                "SELECT device_id, protocol, public_port, deletion_requested FROM tunnels
                  WHERE id = ?1 AND tenant_id = ?2 AND deleted_at IS NULL",
                rusqlite::params![id, tenant_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取穿透服务"))?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "穿透服务不存在"))?;
        if deletion_requested != 0 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "穿透服务正在等待删除，不能再修改开关",
            ));
        }
        if enabled && device_id.is_none() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "穿透服务尚未分配设备，请先选择设备后再启用",
            ));
        }
        let changed = connection
            .execute(
                "UPDATE tunnels SET enabled = ?1, apply_status = ?2,
                 apply_error = NULL, deletion_requested = 0, deletion_revision = NULL,
                 apply_revision = apply_revision + 1,
                 updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?3 AND tenant_id = ?4 AND deleted_at IS NULL",
                rusqlite::params![
                    i64::from(enabled),
                    if enabled { "checking" } else { "disabled" },
                    id,
                    tenant_id
                ],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新穿透服务开关")
            })?;
        if changed == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "穿透服务不存在"));
        }
        (protocol, public_port)
    };
    if enabled {
        if protocol == "tcp" {
            if let Some(port) = public_port {
                start_public_tunnel_listener(state.clone(), id.clone(), port).await;
            }
        } else {
            let path = tunnel_bridge_socket_path(&state.data_dir, &id);
            if let Err(error) = persist_bridge_socket_path(&state, &id, &path) {
                tracing::warn!(tunnel_id = %id, "保存 Web Service Socket 路径失败：{error:#}");
            }
            start_public_web_listener(state.clone(), id.clone(), path).await;
        }
    } else {
        stop_public_tunnel_listener(&state, &id);
        stop_active_tunnel_connections(&state, &id);
    }
    reconcile_caddy_config_best_effort(&state).await;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            &tunnel_query("WHERE t.id = ?1 AND t.tenant_id = ?2 AND t.deleted_at IS NULL"),
            rusqlite::params![id, tenant_id],
            tunnel_response_from_row,
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取穿透服务状态"))
}

struct NormalizedTunnelRequest {
    tenant_id: String,
    device_id: String,
    name: String,
    protocol: String,
    local_address: String,
    local_port: u16,
    public_port: Option<u16>,
    hostname: Option<String>,
    origin_protocol: Option<String>,
    origin_tls_server_name: Option<String>,
    origin_tls_verification: String,
    origin_ca_pem: Option<String>,
    service_name: Option<String>,
    public_domain_id: Option<String>,
}

/// 校验公网访问输入；所有规则在服务端执行，浏览器表单不是真源。
fn normalize_tunnel_request(
    state: &AppState,
    request: CreateTunnelRequest,
) -> Result<NormalizedTunnelRequest, ApiError> {
    let tenant_id = request.tenant_id.trim().to_owned();
    let device_id = request.device_id.trim().to_owned();
    let name = request.name.trim().to_owned();
    let protocol = request.protocol.trim().to_ascii_lowercase();
    let local_address = request.local_address.trim().to_owned();
    if tenant_id.is_empty() || device_id.is_empty() || name.is_empty() || local_address.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "tenant_id、device_id、name 和本地地址不能为空",
        ));
    }
    if !matches!(protocol.as_str(), "tcp" | "http" | "https") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "穿透服务类型只能是 TCP、HTTP 或 HTTPS",
        ));
    }
    if request.local_port == 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "本地端口必须在 1-65535 范围内",
        ));
    }
    if local_address.parse::<std::net::IpAddr>().is_err() && !is_dns_name(&local_address) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "本地地址不是有效的 IP 或主机名",
        ));
    }
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let valid_device: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM devices WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![device_id, tenant_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查设备归属"))?;
    if valid_device == 0 {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "设备不存在或不属于当前租户",
        ));
    }
    let public_domain_id = if matches!(protocol.as_str(), "http" | "https") {
        let requested = request
            .public_domain_id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty());
        let selected = if let Some(id) = requested {
            Some(id.to_owned())
        } else {
            connection
                .query_row(
                    "SELECT id FROM public_domains WHERE tenant_id = ?1 AND is_primary = 1",
                    [&tenant_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取主域名"))?
        };
        let Some(id) = selected else {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "请先配置一个公网域名，再创建 Web 服务",
            ));
        };
        let exists: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM public_domains WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| row.get(0),
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查公网域名归属")
            })?;
        if exists == 0 {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "公网域名不存在或不属于当前租户",
            ));
        }
        Some(id)
    } else {
        None
    };
    drop(connection);

    let hostname = request
        .hostname
        .map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    if matches!(protocol.as_str(), "http" | "https") {
        let Some(hostname) = hostname.as_deref() else {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Web 服务必须填写访问名称",
            ));
        };
        // Caddy 的泛域名证书只覆盖一级标签；允许多级输入会生成
        // `a.b.example.com`，既超出证书覆盖范围，也让用户误以为配置成功。
        if !is_dns_label(hostname) || hostname == "nexo" || hostname == "mesh" {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "访问名称不是有效的子域名，且 nexo、mesh 为系统名称",
            ));
        }
    } else if hostname.is_some() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "TCP 访问不使用子域名",
        ));
    }
    let origin_protocol = if matches!(protocol.as_str(), "http" | "https") {
        let value = request
            .origin_protocol
            .unwrap_or_else(|| "http".to_owned())
            .trim()
            .to_ascii_lowercase();
        if !matches!(value.as_str(), "http" | "https") {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "本地服务协议只能是 HTTP 或 HTTPS",
            ));
        }
        Some(value)
    } else {
        None
    };
    let origin_tls_verification = request
        .origin_tls_verification
        .unwrap_or_else(|| "system".to_owned())
        .trim()
        .to_ascii_lowercase();
    if !matches!(
        origin_tls_verification.as_str(),
        "system" | "custom_ca" | "insecure"
    ) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "本地 HTTPS 证书校验方式无效",
        ));
    }
    if origin_protocol.as_deref() != Some("https") && origin_tls_verification != "system" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "只有 HTTPS 本地服务可以选择证书校验方式",
        ));
    }
    if origin_tls_verification == "insecure" {
        tracing::warn!("公网 Web 服务跳过本地 HTTPS 证书校验；请仅在高级设置中使用");
    }
    let origin_ca_pem = request
        .origin_ca_pem
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if let Some(ca) = origin_ca_pem.as_deref() {
        if !ca.contains("BEGIN CERTIFICATE") {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "自定义 CA 证书格式无效",
            ));
        }
        if origin_tls_verification != "custom_ca" {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "只有选择自定义证书校验时才能提供自定义 CA",
            ));
        }
    }
    let service_name = request
        .service_name
        .or_else(|| hostname.clone())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    Ok(NormalizedTunnelRequest {
        tenant_id,
        device_id,
        name,
        protocol,
        local_address,
        local_port: request.local_port,
        public_port: request.public_port,
        hostname,
        origin_protocol,
        origin_tls_server_name: request
            .origin_tls_server_name
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
        origin_tls_verification,
        origin_ca_pem,
        service_name,
        public_domain_id,
    })
}

fn allocate_public_port(
    connection: &Connection,
    requested: Option<u16>,
    protocol: &str,
    exclude_tunnel_id: Option<&str>,
    allow_current_listener: bool,
) -> Result<Option<u16>, ApiError> {
    if protocol != "tcp" {
        if requested.is_some() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "Web 服务不使用公网 TCP 端口",
            ));
        }
        return Ok(None);
    }
    if let Some(port) = requested {
        if !(20_000..=29_999).contains(&port) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "公网 TCP 端口必须位于 20000-29999",
            ));
        }
        if !public_port_available(connection, port, exclude_tunnel_id, allow_current_listener)? {
            return Err(ApiError::new(StatusCode::CONFLICT, "公网 TCP 端口已被占用"));
        }
        return Ok(Some(port));
    }
    for port in 20_000..=29_999 {
        if public_port_available(connection, port, exclude_tunnel_id, false)? {
            return Ok(Some(port));
        }
    }
    Err(ApiError::new(StatusCode::CONFLICT, "公网 TCP 端口段已用尽"))
}

fn public_port_available(
    connection: &Connection,
    port: u16,
    exclude_tunnel_id: Option<&str>,
    allow_current_listener: bool,
) -> Result<bool, ApiError> {
    let in_database: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM tunnels
             WHERE public_port = ?1 AND deleted_at IS NULL
               AND (?2 IS NULL OR id <> ?2)",
            rusqlite::params![port, exclude_tunnel_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查公网端口"))?;
    if in_database > 0 {
        return Ok(false);
    }
    if allow_current_listener {
        return Ok(true);
    }
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port));
    Ok(listener.is_ok())
}

fn is_dns_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.starts_with('.') || value.ends_with('.') {
        return false;
    }
    value.split('.').all(is_dns_label)
}

/// 校验单个 DNS 标签；Web Service 的 hostname 必须使用这一层级，
/// 这样 `*.base_domain` 证书可以覆盖所有用户服务而不产生隐性证书错误。
fn is_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

fn tunnel_query(filter: &str) -> String {
    format!(
        "SELECT t.id, t.tenant_id, t.device_id, d.name, t.name, t.protocol,
                t.local_address, t.local_port, t.public_port, t.hostname,
                t.origin_protocol, t.origin_tls_server_name,
                COALESCE(t.origin_tls_verification, 'system'), t.service_name,
                t.enabled, t.apply_status, t.apply_error, t.apply_revision,
                t.applied_revision, t.deletion_requested, t.public_domain_id,
         COALESCE(pd.domain, primary_domain.domain)
         FROM tunnels t LEFT JOIN devices d ON d.id = t.device_id
         LEFT JOIN public_domains pd ON pd.id = t.public_domain_id
         LEFT JOIN public_domains primary_domain
           ON primary_domain.tenant_id = t.tenant_id AND primary_domain.is_primary = 1 {filter}"
    )
}

fn tunnel_response_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TunnelResponse> {
    let local_port: i64 = row.get(7)?;
    let public_port: Option<i64> = row.get(8)?;
    let public_domain_id: Option<String> = row.get(20)?;
    let base_domain: Option<String> = row.get(21)?;
    let protocol: String = row.get(5)?;
    let hostname: Option<String> = row.get(9)?;
    let public_address = match (
        protocol.as_str(),
        hostname.as_deref(),
        base_domain.as_deref(),
        public_port,
    ) {
        ("tcp", _, _, Some(port)) => Some(format!("公网地址:{port}")),
        ("http", Some(host), Some(domain), _) => Some(format!("http://{host}.{domain}")),
        ("https", Some(host), Some(domain), _) => Some(format!("https://{host}.{domain}")),
        _ => None,
    };
    Ok(TunnelResponse {
        id: row.get(0)?,
        tenant_id: row.get(1)?,
        device_id: row.get(2)?,
        device_name: row.get(3)?,
        name: row.get(4)?,
        protocol,
        local_address: row.get(6)?,
        local_port: u16::try_from(local_port).unwrap_or_default(),
        public_port: public_port.and_then(|port| u16::try_from(port).ok()),
        hostname,
        origin_protocol: row.get(10)?,
        origin_tls_server_name: row.get(11)?,
        origin_tls_verification: row.get(12)?,
        service_name: row.get(13)?,
        enabled: row.get::<_, i64>(14)? != 0,
        apply_status: row.get(15)?,
        apply_error: row.get(16)?,
        desired_revision: row.get(17)?,
        applied_revision: row.get(18)?,
        deletion_pending: row.get::<_, i64>(19)? != 0,
        public_address,
        public_domain_id,
        public_domain: base_domain,
    })
}

async fn seed_public_domain_migration_offers(state: &AppState) {
    let device_ids = match state.db.lock() {
        Ok(connection) => connection
            .prepare("SELECT id FROM devices WHERE status = 'online'")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    for device_id in device_ids {
        if let Err(error) = ensure_mesh_enrollment_for_device(state, &device_id).await {
            tracing::warn!(device_id = %device_id, "主域名迁移邀请暂未生成，将在设备下次心跳重试：{error:#}");
        }
    }
}

/// 检测公网入口根域名和泛域名记录。
///
/// DNS 检测只读取解析结果，不会修改 DNS 服务商记录。顶层 `resolved`
/// 和 `error` 继续保留给旧版 Web UI；`root`、`wildcard` 则让新界面能够
/// 明确区分两个入口的检查结果。
async fn lookup_public_dns(hostname: &str) -> std::result::Result<Vec<String>, String> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((hostname, 443)),
    )
    .await
    {
        Ok(Ok(addresses)) => {
            let mut resolved = addresses
                .map(|address| address.ip().to_string())
                .collect::<Vec<_>>();
            resolved.sort();
            resolved.dedup();
            Ok(resolved)
        }
        Ok(Err(error)) => Err(format!("DNS 解析失败：{error}")),
        Err(_) => Err("DNS 检测超时".to_owned()),
    }
}

/// DNS 不能查询字面量 `*.domain`；使用 Nexo 固定入口作为通配记录的
/// 实际探针，同时在报告中保留 `*.domain` 作为用户可识别的目标说明。
fn wildcard_dns_probe_hostname(domain: &str) -> String {
    format!("nexo.{domain}")
}

fn build_dns_check(
    domain: &str,
    root: std::result::Result<Vec<String>, String>,
    wildcard: std::result::Result<Vec<String>, String>,
) -> serde_json::Value {
    let root_value = match &root {
        Ok(addresses) => serde_json::json!({
            "hostname": domain,
            "resolved": addresses,
        }),
        Err(error) => serde_json::json!({
            "hostname": domain,
            "resolved": [],
            "error": error,
        }),
    };
    let wildcard_hostname = format!("*.{domain}");
    let wildcard_probe = wildcard_dns_probe_hostname(domain);
    let wildcard_value = match &wildcard {
        Ok(addresses) => serde_json::json!({
            "hostname": wildcard_probe,
            "probe": wildcard_hostname,
            "resolved": addresses,
        }),
        Err(error) => serde_json::json!({
            "hostname": wildcard_probe,
            "probe": wildcard_hostname,
            "resolved": [],
            "error": error,
        }),
    };

    let mut resolved = root.clone().unwrap_or_default();
    resolved.extend(wildcard.clone().unwrap_or_default());
    resolved.sort();
    resolved.dedup();
    let errors = [root.err(), wildcard.err()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let mut result = serde_json::Map::new();
    result.insert("resolved".to_owned(), serde_json::json!(resolved));
    if !errors.is_empty() {
        result.insert("error".to_owned(), serde_json::json!(errors.join("；")));
    }
    result.insert("root".to_owned(), root_value);
    result.insert("wildcard".to_owned(), wildcard_value);
    serde_json::Value::Object(result)
}

/// 只有根域名和泛域名检查都返回解析结果时，才把资源视为可承担主入口。
/// 兼容旧版只保存顶层 `resolved` 的检查结果；新版本优先使用分项结果。
fn public_domain_dns_ready(serialized: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(serialized) else {
        return false;
    };
    let has_records = |item: Option<&serde_json::Value>| {
        item.and_then(|value| value.get("resolved"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|records| !records.is_empty())
            && item
                .and_then(|value| value.get("error"))
                .is_none_or(serde_json::Value::is_null)
    };
    match (value.get("root"), value.get("wildcard")) {
        (Some(root), Some(wildcard)) => has_records(Some(root)) && has_records(Some(wildcard)),
        _ => {
            value
                .get("resolved")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|records| !records.is_empty())
                && value.get("error").is_none()
        }
    }
}

fn read_primary_domain_status(connection: &Connection) -> rusqlite::Result<PrimaryDomainStatus> {
    let row = connection
        .query_row(
            "SELECT domain, https_enabled, certificate_mode, acme_environment,
                    desired_revision, applied_revision, apply_status, apply_error,
                    root_certificate_not_before, root_certificate_not_after,
                    root_certificate_subjects_json, dns_check_json
             FROM public_domains WHERE is_primary = 1
             ORDER BY updated_at DESC LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .optional()?;
    let Some((
        domain,
        https_enabled,
        certificate_mode,
        acme_environment,
        desired_revision,
        applied_revision,
        apply_status,
        apply_error,
        certificate_not_before,
        certificate_not_after,
        subjects,
        dns,
    )) = row
    else {
        return Ok(PrimaryDomainStatus {
            base_domain: None,
            https_enabled: false,
            certificate_mode: "none".to_owned(),
            acme_environment: "production".to_owned(),
            desired_revision: 0,
            applied_revision: 0,
            apply_status: "NOT_CONFIGURED".to_owned(),
            apply_error: None,
            certificate_not_before: None,
            certificate_not_after: None,
            certificate_subjects: Vec::new(),
            dns_check: serde_json::json!({}),
        });
    };
    Ok(PrimaryDomainStatus {
        base_domain: Some(domain),
        https_enabled,
        certificate_mode,
        acme_environment,
        desired_revision,
        applied_revision,
        apply_status: primary_domain_status_label(&apply_status),
        apply_error,
        certificate_not_before,
        certificate_not_after,
        certificate_subjects: serde_json::from_str(&subjects).unwrap_or_default(),
        dns_check: serde_json::from_str(&dns).unwrap_or_else(|_| serde_json::json!({})),
    })
}

fn primary_domain_status_label(status: &str) -> String {
    match status {
        "not_configured" => "NOT_CONFIGURED",
        "pending" | "checking" | "configuring" | "retrying" | "rate_limited" => "CONFIGURING",
        "ready" => "READY",
        "error" => "ERROR",
        _ => "ERROR",
    }
    .to_owned()
}

/// 规范化用户输入的公网域名。用户只能提供根域名，`nexo`、`mesh` 等
/// 系统前缀由 Server 保留，绝不从请求中拼接到内部路由。
fn normalize_public_domain(value: &str) -> Result<String, ApiError> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if !is_dns_name(&domain) || domain == "nexo" || domain == "mesh" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "根域名不是有效的 DNS 名称",
        ));
    }
    Ok(domain)
}

fn domain_secret_dir(state: &AppState, id: &str) -> PathBuf {
    state
        .data_dir
        .join("secrets")
        .join("public-domains")
        .join(id)
}

fn public_domain_ready_from_row(
    _apply_status: &str,
    https_enabled: bool,
    root_status: &str,
    wildcard_status: &str,
) -> bool {
    !https_enabled
        || (root_status.eq_ignore_ascii_case("ready")
            && wildcard_status.eq_ignore_ascii_case("ready"))
}

fn public_domain_response_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PublicDomainResponse> {
    let root_subjects: String = row.get(12)?;
    let wildcard_subjects: String = row.get(16)?;
    let apply_status: String = row.get(7)?;
    let https_enabled = row.get::<_, i64>(4)? != 0;
    let automatic_renewal = row.get::<_, String>(5)?.eq_ignore_ascii_case("cloudflare");
    let root_not_before = row.get(13)?;
    let root_not_after = row.get(14)?;
    let wildcard_not_before = row.get(17)?;
    let wildcard_not_after = row.get(18)?;
    let id = row.get(0)?;
    let tenant_id = row.get(1)?;
    let domain: String = row.get(2)?;
    let is_primary = row.get::<_, i64>(3)? != 0;
    let dns_check: serde_json::Value =
        serde_json::from_str(&row.get::<_, String>(10)?).unwrap_or_else(|_| serde_json::json!({}));
    let root_certificate_status: String = row.get(11)?;
    let wildcard_certificate_status: String = row.get(15)?;
    let dns_part_status = |part: &str| {
        let value = dns_check.get(part);
        if value
            .and_then(|item| item.get("resolved"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|records| !records.is_empty())
            && value
                .and_then(|item| item.get("error"))
                .is_none_or(serde_json::Value::is_null)
        {
            "ready"
        } else if value.and_then(|item| item.get("error")).is_some() {
            "error"
        } else {
            "pending"
        }
    };
    let root_dns = dns_part_status("root").to_owned();
    let wildcard_dns = dns_part_status("wildcard").to_owned();
    let https_ready = public_domain_ready_from_row(
        &apply_status,
        https_enabled,
        &root_certificate_status,
        &wildcard_certificate_status,
    );
    let management_entry = (is_primary && https_enabled).then(|| format!("https://nexo.{domain}"));
    let mesh_entry = (is_primary && https_enabled).then(|| format!("https://mesh.{domain}"));
    Ok(PublicDomainResponse {
        id,
        tenant_id,
        domain,
        is_primary,
        https_enabled,
        certificate_mode: row.get(5)?,
        acme_environment: row.get(6)?,
        apply_status: apply_status.clone(),
        apply_error: row.get(8)?,
        error_code: row.get(9)?,
        dns_check,
        root_certificate: CertificateStatusResponse {
            status: root_certificate_status,
            not_before: root_not_before,
            not_after: root_not_after,
            renewal_at: automatic_renewal
                .then(|| estimated_caddy_renewal(root_not_before, root_not_after))
                .flatten(),
            subjects: serde_json::from_str(&root_subjects).unwrap_or_default(),
            progress: CertificateProgressResponse {
                stage: row.get(31)?,
                attempt_count: row.get(32)?,
                last_event_at: row.get(33)?,
                next_retry_at: row.get(34)?,
                error_code: row.get(35)?,
                error_message: row.get(36)?,
            },
        },
        wildcard_certificate: CertificateStatusResponse {
            status: wildcard_certificate_status,
            not_before: wildcard_not_before,
            not_after: wildcard_not_after,
            renewal_at: automatic_renewal
                .then(|| estimated_caddy_renewal(wildcard_not_before, wildcard_not_after))
                .flatten(),
            subjects: serde_json::from_str(&wildcard_subjects).unwrap_or_default(),
            progress: CertificateProgressResponse {
                stage: row.get(37)?,
                attempt_count: row.get(38)?,
                last_event_at: row.get(39)?,
                next_retry_at: row.get(40)?,
                error_code: row.get(41)?,
                error_message: row.get(42)?,
            },
        },
        retry_after: row.get(19)?,
        attempt_count: row.get(20)?,
        next_retry_at: row.get(21)?,
        desired_revision: row.get(22)?,
        applied_revision: row.get(23)?,
        usage_count: row.get(24)?,
        dns_management: DnsManagementResponse {
            enabled: row.get::<_, i64>(25)? != 0,
            target_ipv4: row.get(26)?,
            target_ipv6: row.get(27)?,
            status: row.get(28)?,
            error: row.get(29)?,
            version: row.get(30)?,
        },
        management_entry: management_entry.clone(),
        mesh_entry: mesh_entry.clone(),
        readiness_summary: PublicDomainReadinessSummary {
            status: apply_status,
            root_dns: root_dns.clone(),
            wildcard_dns: wildcard_dns.clone(),
            https: if https_ready { "ready" } else { "pending" }.to_owned(),
            management_entry: if !is_primary {
                "not_applicable"
            } else if https_ready && root_dns == "ready" {
                "ready"
            } else {
                "pending"
            }
            .to_owned(),
            mesh_entry: if !is_primary {
                "not_applicable"
            } else if https_ready && wildcard_dns == "ready" {
                "ready"
            } else {
                "pending"
            }
            .to_owned(),
        },
    })
}

/// 计算 Caddy 自动续期窗口的预计开始时间。
///
/// Caddy 的自动 HTTPS 维护会在证书生命周期进入最后约三分之一时续期，
/// 但具体调度仍由 Caddy 和 CA 决定，所以这个时间只用于界面提示，不作为
/// Server 自建 ACME 重试器的触发点。手动证书由调用方直接返回 `None`。
fn estimated_caddy_renewal(not_before: Option<i64>, not_after: Option<i64>) -> Option<i64> {
    let (not_before, not_after) = (not_before?, not_after?);
    let lifetime = not_after.checked_sub(not_before)?;
    (lifetime > 0).then(|| not_before.saturating_add(lifetime.saturating_mul(2) / 3))
}
// 集中在此处可以避免前端看到错位的证书状态。
fn public_domain_query_ordered(filter: &str) -> String {
    format!(
        "SELECT p.id, p.tenant_id, p.domain, p.is_primary, p.https_enabled,
                p.certificate_mode, p.acme_environment, p.apply_status,
                p.apply_error, p.error_code, p.dns_check_json,
                p.root_certificate_status, p.root_certificate_subjects_json,
                p.root_certificate_not_before, p.root_certificate_not_after,
                p.wildcard_certificate_status, p.wildcard_certificate_subjects_json,
                p.wildcard_certificate_not_before, p.wildcard_certificate_not_after,
                p.retry_after, p.attempt_count, p.next_retry_at,
                p.desired_revision, p.applied_revision,
                (SELECT COUNT(*) FROM tunnels t
                 WHERE t.public_domain_id = p.id AND t.deleted_at IS NULL
                   AND t.protocol IN ('http', 'https')) AS usage_count,
                p.dns_management_enabled, p.dns_target_ipv4, p.dns_target_ipv6,
                p.dns_management_status, p.dns_management_error,
                p.dns_management_version,
                COALESCE((SELECT stage FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'root'), 'waiting_configuration'),
                COALESCE((SELECT attempt_count FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'root'), 0),
                (SELECT last_event_at FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'root'),
                (SELECT next_retry_at FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'root'),
                (SELECT error_code FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'root'),
                (SELECT error_message FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'root'),
                COALESCE((SELECT stage FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'wildcard'), 'waiting_configuration'),
                COALESCE((SELECT attempt_count FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'wildcard'), 0),
                (SELECT last_event_at FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'wildcard'),
                (SELECT next_retry_at FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'wildcard'),
                (SELECT error_code FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'wildcard'),
                (SELECT error_message FROM public_domain_certificate_progress
                    WHERE public_domain_id = p.id AND certificate_type = 'wildcard')
         FROM public_domains p {filter}"
    )
}

#[derive(Debug)]
struct ManagedDnsDomainConfig {
    domain: String,
    target_ipv4: Option<String>,
    target_ipv6: Option<String>,
    token: String,
}

fn cloudflare_api_base() -> String {
    std::env::var("NEXO_CLOUDFLARE_API_BASE")
        .unwrap_or_else(|_| "https://api.cloudflare.com/client/v4".to_owned())
        .trim_end_matches('/')
        .to_owned()
}

fn load_managed_dns_config(
    state: &AppState,
    tenant_id: &str,
    id: &str,
) -> Result<ManagedDnsDomainConfig, ApiError> {
    let (domain, enabled, ipv4, ipv6, secret_dir): (
        String,
        bool,
        Option<String>,
        Option<String>,
        String,
    ) = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?
        .query_row(
            "SELECT domain, dns_management_enabled, dns_target_ipv4,
                    dns_target_ipv6, secret_dir
             FROM public_domains WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![id, tenant_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "域名不存在"))?;
    if !enabled {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "请先启用“由 Nexo 自动管理 DNS”并保存目标地址",
        ));
    }
    let token_path = if PathBuf::from(&secret_dir).is_absolute() {
        PathBuf::from(secret_dir)
    } else {
        state.data_dir.join(secret_dir)
    }
    .join("cloudflare.token");
    let token = fs::read_to_string(token_path)
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "请先配置 Cloudflare API Token"))?;
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "Cloudflare API Token 为空",
        ));
    }
    Ok(ManagedDnsDomainConfig {
        domain,
        target_ipv4: ipv4,
        target_ipv6: ipv6,
        token,
    })
}

async fn cloudflare_json(
    method: reqwest::Method,
    url: String,
    token: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, ApiError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法初始化 Cloudflare 客户端",
            )
        })?;
    let mut request = client.request(method, url).bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.map_err(|error| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Cloudflare 请求失败：{error}"),
        )
    })?;
    let status = response.status();
    let value = response
        .json::<serde_json::Value>()
        .await
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "Cloudflare 返回了无法解析的响应"))?;
    let success = value
        .get("success")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(status.is_success());
    if !status.is_success() || !success {
        let details = value
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .map(|errors| {
                errors
                    .iter()
                    .filter_map(|error| error.get("message").and_then(serde_json::Value::as_str))
                    .collect::<Vec<_>>()
                    .join("；")
            })
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Cloudflare API 拒绝了操作：{details}"),
        ));
    }
    Ok(value)
}

async fn build_managed_dns_preview(
    state: &AppState,
    tenant_id: &str,
    id: &str,
) -> Result<(ManagedDnsPreviewResponse, ManagedDnsDomainConfig, String), ApiError> {
    let config = load_managed_dns_config(state, tenant_id, id)?;
    let base = cloudflare_api_base();
    let zones = reqwest::Client::new()
        .get(format!("{base}/zones"))
        .bearer_auth(&config.token)
        .query(&[("name", config.domain.as_str())])
        .send()
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("无法查询 Cloudflare Zone：{error}"),
            )
        })?;
    let zones_status = zones.status();
    let zones = zones
        .json::<serde_json::Value>()
        .await
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "Cloudflare Zone 响应格式无效"))?;
    if !zones_status.is_success()
        || !zones
            .get("success")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    {
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "Cloudflare Token 无法读取该域名的 Zone，请检查 Zone DNS 权限",
        ));
    }
    let zone = zones
        .get("result")
        .and_then(serde_json::Value::as_array)
        .and_then(|zones| {
            zones.iter().find(|zone| {
                zone.get("name").and_then(serde_json::Value::as_str) == Some(config.domain.as_str())
            })
        })
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Cloudflare 中未找到同名 Zone"))?;
    let zone_id = zone
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_GATEWAY, "Cloudflare Zone 缺少 ID"))?
        .to_owned();
    let records = cloudflare_json(
        reqwest::Method::GET,
        format!("{base}/zones/{zone_id}/dns_records?per_page=100"),
        &config.token,
        None,
    )
    .await?;
    let records = records
        .get("result")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let changes = plan_managed_dns_changes(
        &config.domain,
        config.target_ipv4.as_deref(),
        config.target_ipv6.as_deref(),
        &records,
    );
    let has_conflicts = changes.iter().any(|change| change.action == "replace");
    Ok((
        ManagedDnsPreviewResponse {
            domain_id: id.to_owned(),
            zone_name: config.domain.clone(),
            changes,
            has_conflicts,
        },
        config,
        zone_id,
    ))
}

/// 根据 Cloudflare 当前快照生成纯预览，不修改任何记录。相同内容会接管
/// record ID；缺失项创建；地址、类型或代理状态不同都必须显式确认替换。
fn plan_managed_dns_changes(
    domain: &str,
    target_ipv4: Option<&str>,
    target_ipv6: Option<&str>,
    records: &[serde_json::Value],
) -> Vec<ManagedDnsChange> {
    let mut desired = Vec::new();
    if let Some(ipv4) = target_ipv4 {
        desired.push(("A", ipv4));
    }
    if let Some(ipv6) = target_ipv6 {
        desired.push(("AAAA", ipv6));
    }
    let mut changes = Vec::new();
    for (record_type, content) in desired {
        for (record_name, fqdn) in [("@", domain.to_owned()), ("*", format!("*.{domain}"))] {
            let matches = records
                .iter()
                .filter(|record| {
                    record.get("name").and_then(serde_json::Value::as_str) == Some(fqdn.as_str())
                })
                .collect::<Vec<_>>();
            let exact = matches.iter().find(|record| {
                record.get("type").and_then(serde_json::Value::as_str) == Some(record_type)
            });
            // A 与 AAAA 可以在同一名称共存；只有同类型记录或 CNAME 才是
            // 当前目标的替换对象，不能为了新增双栈记录误删另一个地址族。
            let current = exact.copied().or_else(|| {
                matches.iter().find_map(|record| {
                    (record.get("type").and_then(serde_json::Value::as_str) == Some("CNAME"))
                        .then_some(*record)
                })
            });
            let same = exact.is_some_and(|record| {
                record.get("content").and_then(serde_json::Value::as_str) == Some(content)
                    && record.get("proxied").and_then(serde_json::Value::as_bool) == Some(false)
            });
            let action = if same {
                "adopt"
            } else if current.is_some() {
                "replace"
            } else {
                "create"
            };
            changes.push(ManagedDnsChange {
                action: action.to_owned(),
                record_type: record_type.to_owned(),
                name: record_name.to_owned(),
                desired_content: content.to_owned(),
                current_content: current.and_then(|record| {
                    record
                        .get("content")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                }),
                record_id: current.and_then(|record| {
                    record
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                }),
            });
        }
    }
    changes
}

async fn preview_public_domain_dns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ManagedDnsPreviewResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let (preview, _, _) = build_managed_dns_preview(&state, &tenant_id, &id).await?;
    state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?
        .execute(
            "UPDATE public_domains SET dns_management_status = ?1,
             dns_management_error = NULL, updated_at = unixepoch()
             WHERE id = ?2 AND tenant_id = ?3",
            rusqlite::params![
                if preview.has_conflicts {
                    "conflict"
                } else {
                    "previewed"
                },
                id,
                tenant_id
            ],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存 DNS 预览状态"))?;
    Ok(Json(preview))
}

fn record_managed_dns_error(state: &AppState, tenant_id: &str, id: &str, error: &ApiError) {
    let status = if error.status == StatusCode::CONFLICT {
        "conflict"
    } else {
        "error"
    };
    if let Ok(connection) = state.db.lock() {
        if let Err(update_error) = connection.execute(
            "UPDATE public_domains SET dns_management_status = ?1,
             dns_management_error = ?2, updated_at = unixepoch()
             WHERE id = ?3 AND tenant_id = ?4",
            rusqlite::params![
                status,
                truncate_error_message(&error.message),
                id,
                tenant_id
            ],
        ) {
            tracing::warn!("无法保存 DNS 托管错误：{update_error}");
        }
    }
}

async fn apply_managed_dns(
    state: &AppState,
    tenant_id: &str,
    id: &str,
    confirm_conflicts: bool,
) -> Result<ManagedDnsPreviewResponse, ApiError> {
    let (preview, config, zone_id) = build_managed_dns_preview(state, tenant_id, id).await?;
    if preview.has_conflicts && !confirm_conflicts {
        let conflicts = preview
            .changes
            .iter()
            .filter(|change| change.action == "replace")
            .map(|change| {
                format!(
                    "{} {}：{} → {}",
                    change.record_type,
                    change.name,
                    change.current_content.as_deref().unwrap_or("空"),
                    change.desired_content
                )
            })
            .collect::<Vec<_>>()
            .join("；");
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("DNS 记录存在冲突，请确认后替换：{conflicts}"),
        ));
    }
    let base = cloudflare_api_base();
    let mut consumed_record_ids = std::collections::HashSet::new();
    for change in &preview.changes {
        let fqdn = if change.name == "@" {
            config.domain.clone()
        } else {
            format!("*.{}", config.domain)
        };
        let payload = serde_json::json!({
            "type": change.record_type,
            "name": fqdn,
            "content": change.desired_content,
            "ttl": 1,
            "proxied": false,
        });
        let (record_id, created_by_nexo) =
            match (change.action.as_str(), change.record_id.as_deref()) {
                ("adopt", Some(record_id)) => (record_id.to_owned(), false),
                ("replace", Some(record_id))
                    if consumed_record_ids.insert(record_id.to_owned()) =>
                {
                    let result = cloudflare_json(
                        reqwest::Method::PUT,
                        format!("{base}/zones/{zone_id}/dns_records/{record_id}"),
                        &config.token,
                        Some(payload),
                    )
                    .await?;
                    (
                        result
                            .get("result")
                            .and_then(|item| item.get("id"))
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or(record_id)
                            .to_owned(),
                        false,
                    )
                }
                _ => {
                    let result = cloudflare_json(
                        reqwest::Method::POST,
                        format!("{base}/zones/{zone_id}/dns_records"),
                        &config.token,
                        Some(payload),
                    )
                    .await?;
                    let record_id = result
                        .get("result")
                        .and_then(|item| item.get("id"))
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            ApiError::new(
                                StatusCode::BAD_GATEWAY,
                                "Cloudflare 创建记录后未返回 record ID",
                            )
                        })?;
                    (record_id.to_owned(), true)
                }
            };
        state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?
            .execute(
                "INSERT INTO public_domain_dns_records
                 (id, public_domain_id, record_type, record_name, cloudflare_record_id,
                  last_applied_content, apply_status, created_by_nexo, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'ready', ?7, unixepoch())
                 ON CONFLICT(public_domain_id, record_type, record_name) DO UPDATE SET
                  cloudflare_record_id = excluded.cloudflare_record_id,
                  last_applied_content = excluded.last_applied_content,
                  apply_status = 'ready', apply_error = NULL,
                  created_by_nexo = CASE
                    WHEN public_domain_dns_records.created_by_nexo = 1 THEN 1
                    ELSE excluded.created_by_nexo END,
                  updated_at = unixepoch()",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    id,
                    change.record_type,
                    change.name,
                    record_id,
                    change.desired_content,
                    i64::from(created_by_nexo)
                ],
            )
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DNS 已应用但无法保存 record ID",
                )
            })?;
    }
    state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?
        .execute(
            "UPDATE public_domains SET dns_management_status = 'ready',
             dns_management_error = NULL,
             dns_management_version = dns_management_version + 1,
             updated_at = unixepoch() WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![id, tenant_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存 DNS 托管状态"))?;
    Ok(preview)
}

async fn apply_public_domain_dns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<ApplyManagedDnsRequest>,
) -> Result<Json<ManagedDnsPreviewResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    match apply_managed_dns(&state, &tenant_id, &id, request.confirm_conflicts).await {
        Ok(preview) => Ok(Json(preview)),
        Err(error) => {
            record_managed_dns_error(&state, &tenant_id, &id, &error);
            Err(error)
        }
    }
}

async fn batch_apply_public_domain_dns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ManagedDnsBatchRequest>,
) -> Result<Json<Vec<ManagedDnsPreviewResponse>>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let mut applied = Vec::new();
    for id in request.ids {
        match apply_managed_dns(&state, &tenant_id, &id, request.confirm_conflicts).await {
            Ok(preview) => applied.push(preview),
            Err(error) => {
                record_managed_dns_error(&state, &tenant_id, &id, &error);
                return Err(error);
            }
        }
    }
    Ok(Json(applied))
}

async fn release_public_domain_dns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<ReleaseManagedDnsRequest>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    if !request.delete_created_records {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "未确认删除 Nexo 创建的 DNS 记录；关闭托管默认会保留记录",
        ));
    }
    let (_, config, zone_id) = build_managed_dns_preview(&state, &tenant_id, &id).await?;
    let tracked = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?
        .prepare(
            "SELECT id, record_type, record_name, cloudflare_record_id, last_applied_content
             FROM public_domain_dns_records
             WHERE public_domain_id = ?1 AND created_by_nexo = 1",
        )
        .and_then(|mut statement| {
            statement
                .query_map([&id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取受管 DNS 记录"))?;
    let base = cloudflare_api_base();
    for (tracked_id, record_type, record_name, record_id, last_content) in tracked {
        let Some(record_id) = record_id else { continue };
        let current = cloudflare_json(
            reqwest::Method::GET,
            format!("{base}/zones/{zone_id}/dns_records/{record_id}"),
            &config.token,
            None,
        )
        .await?;
        let current = current.get("result").cloned().unwrap_or_default();
        let expected_name = if record_name == "@" {
            config.domain.clone()
        } else {
            format!("*.{}", config.domain)
        };
        let still_matches = current.get("type").and_then(serde_json::Value::as_str)
            == Some(record_type.as_str())
            && current.get("name").and_then(serde_json::Value::as_str)
                == Some(expected_name.as_str())
            && current.get("content").and_then(serde_json::Value::as_str)
                == Some(last_content.as_str())
            && current.get("proxied").and_then(serde_json::Value::as_bool) == Some(false);
        if !still_matches {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                format!(
                    "{record_type} {record_name} 已在 Cloudflare 中被修改，为避免误删已停止操作"
                ),
            ));
        }
        cloudflare_json(
            reqwest::Method::DELETE,
            format!("{base}/zones/{zone_id}/dns_records/{record_id}"),
            &config.token,
            None,
        )
        .await?;
        state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?
            .execute(
                "DELETE FROM public_domain_dns_records WHERE id = ?1",
                [&tracked_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法清理 DNS 跟踪记录")
            })?;
    }
    Ok(Json(DeleteResponse {
        deleted: true,
        pending: false,
        id,
        message: "已删除仍与最后应用内容一致的 Nexo 创建记录；接管的历史记录已保留".to_owned(),
    }))
}

async fn list_public_domains(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PublicDomainResponse>>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(&public_domain_query_ordered(
            "WHERE p.tenant_id = ?1 ORDER BY p.is_primary DESC, p.domain ASC",
        ))
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取域名列表"))?;
    let rows = statement
        .query_map([tenant_id], public_domain_response_from_row)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取域名列表"))?;
    rows.map(|row| {
        row.map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "域名状态数据格式无效"))
    })
    .collect::<Result<Vec<_>, _>>()
    .map(Json)
}

fn validate_public_domain_options(
    domain: &str,
    https_enabled: bool,
    certificate_mode: &str,
) -> Result<(), ApiError> {
    if !https_enabled {
        return Ok(());
    }
    if !matches!(certificate_mode, "manual" | "cloudflare") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "证书模式只能是 manual 或 cloudflare",
        ));
    }
    if domain.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "启用 HTTPS 前必须填写根域名",
        ));
    }
    Ok(())
}

/// DNS 托管目标必须由管理员明确填写；不从网卡或请求来源猜测公网地址。
fn normalize_dns_targets(
    enabled: bool,
    ipv4: Option<&str>,
    ipv6: Option<&str>,
) -> Result<(Option<String>, Option<String>), ApiError> {
    let ipv4 = ipv4
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<std::net::Ipv4Addr>().map(|ip| ip.to_string()))
        .transpose()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "DNS 托管 IPv4 地址无效"))?;
    let ipv6 = ipv6
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<std::net::Ipv6Addr>().map(|ip| ip.to_string()))
        .transpose()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "DNS 托管 IPv6 地址无效"))?;
    if enabled && ipv4.is_none() && ipv6.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "启用 DNS 托管时必须填写公网 IPv4 或 IPv6 地址",
        ));
    }
    Ok((ipv4, ipv6))
}

async fn create_public_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreatePublicDomainRequest>,
) -> Result<Json<PublicDomainResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let domain = normalize_public_domain(&request.domain)?;
    let mode = request.certificate_mode.trim().to_ascii_lowercase();
    validate_public_domain_options(&domain, request.https_enabled, &mode)?;
    let (dns_ipv4, dns_ipv6) = normalize_dns_targets(
        request.dns_management_enabled,
        request.dns_target_ipv4.as_deref(),
        request.dns_target_ipv6.as_deref(),
    )?;
    let id = Uuid::new_v4().to_string();
    let secret_dir = domain_secret_dir(&state, &id);
    let is_primary = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM public_domains WHERE tenant_id = ?1",
                [&tenant_id],
                |row| row.get(0),
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查现有域名"))?;
        connection
            .execute(
                "INSERT INTO public_domains
                 (id, tenant_id, domain, is_primary, https_enabled, certificate_mode,
                  acme_environment, secret_dir, apply_status, dns_management_enabled,
                  dns_target_ipv4, dns_target_ipv6, dns_management_status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'production', ?7, 'pending',
                         ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    id,
                    tenant_id,
                    domain,
                    i64::from(count == 0),
                    i64::from(request.https_enabled),
                    mode,
                    secret_dir.to_string_lossy().to_string(),
                    i64::from(request.dns_management_enabled),
                    dns_ipv4,
                    dns_ipv6,
                    if request.dns_management_enabled {
                        "pending"
                    } else {
                        "disabled"
                    },
                ],
            )
            .map_err(|error| {
                tracing::error!("保存公网域名失败：{error}");
                ApiError::new(StatusCode::CONFLICT, "域名已存在或保存失败")
            })?;
        connection
            .execute(
                "INSERT INTO public_domain_certificate_progress
                 (public_domain_id, certificate_type) VALUES (?1, 'root'), (?1, 'wildcard')",
                [&id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法初始化证书进度"))?;
        count == 0
    };
    if is_primary {
        tracing::info!(domain = %domain, "已创建首个公网域名并设为主域名");
    }
    reconcile_caddy_config_best_effort(&state).await;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            &public_domain_query_ordered("WHERE p.id = ?1 AND p.tenant_id = ?2"),
            rusqlite::params![id, tenant_id],
            public_domain_response_from_row,
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取新建域名"))
}

async fn update_public_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdatePublicDomainRequest>,
) -> Result<Json<PublicDomainResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let current: (
            String,
            bool,
            bool,
            String,
            String,
            i64,
            bool,
            Option<String>,
            Option<String>,
        ) = connection
            .query_row(
                "SELECT domain, is_primary, https_enabled, certificate_mode,
                    acme_environment, (SELECT COUNT(*) FROM tunnels t
                     WHERE t.public_domain_id = public_domains.id AND t.deleted_at IS NULL),
                    dns_management_enabled, dns_target_ipv4, dns_target_ipv6
             FROM public_domains WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get::<_, i64>(2)? != 0,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get::<_, i64>(6)? != 0,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "域名不存在"))?;
        let next_domain = request
            .domain
            .as_deref()
            .map(normalize_public_domain)
            .transpose()?
            .unwrap_or_else(|| current.0.clone());
        if next_domain != current.0 && (current.1 || current.5 > 0) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "主域名或已被服务使用的域名不能直接改名，请新建域名后使用迁移流程",
            ));
        }
        let https_enabled = request.https_enabled.unwrap_or(current.2);
        let mode = request
            .certificate_mode
            .unwrap_or_else(|| current.3.clone())
            .trim()
            .to_ascii_lowercase();
        validate_public_domain_options(&next_domain, https_enabled, &mode)?;
        let dns_enabled = request.dns_management_enabled.unwrap_or(current.6);
        let requested_ipv4 = request
            .dns_target_ipv4
            .as_ref()
            .and_then(|value| value.as_deref())
            .or(current.7.as_deref());
        let requested_ipv6 = request
            .dns_target_ipv6
            .as_ref()
            .and_then(|value| value.as_deref())
            .or(current.8.as_deref());
        let (dns_ipv4, dns_ipv6) =
            normalize_dns_targets(dns_enabled, requested_ipv4, requested_ipv6)?;
        let reset_certificates = next_domain != current.0 || mode != current.3;
        let revision = connection
            .query_row(
                "SELECT desired_revision FROM public_domains WHERE id = ?1",
                [&id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_default()
            .saturating_add(1);
        connection
            .execute(
                "UPDATE public_domains SET domain = ?1, https_enabled = ?2,
             certificate_mode = ?3, acme_environment = 'production', desired_revision = ?4,
             apply_status = 'checking', apply_error = NULL, error_code = NULL,
             root_certificate_status = CASE WHEN ?7 = 1 THEN 'pending' ELSE root_certificate_status END,
             wildcard_certificate_status = CASE WHEN ?7 = 1 THEN 'pending' ELSE wildcard_certificate_status END,
             root_certificate_not_before = CASE WHEN ?7 = 1 THEN NULL ELSE root_certificate_not_before END,
             root_certificate_not_after = CASE WHEN ?7 = 1 THEN NULL ELSE root_certificate_not_after END,
             wildcard_certificate_not_before = CASE WHEN ?7 = 1 THEN NULL ELSE wildcard_certificate_not_before END,
             wildcard_certificate_not_after = CASE WHEN ?7 = 1 THEN NULL ELSE wildcard_certificate_not_after END,
             root_certificate_subjects_json = CASE WHEN ?7 = 1 THEN '[]' ELSE root_certificate_subjects_json END,
             wildcard_certificate_subjects_json = CASE WHEN ?7 = 1 THEN '[]' ELSE wildcard_certificate_subjects_json END,
             dns_management_enabled = ?8, dns_target_ipv4 = ?9, dns_target_ipv6 = ?10,
             dns_management_status = CASE WHEN ?8 = 1 THEN 'pending' ELSE 'disabled' END,
             dns_management_error = NULL,
             updated_at = unixepoch() WHERE id = ?5 AND tenant_id = ?6",
                rusqlite::params![
                    next_domain,
                    i64::from(https_enabled),
                    mode,
                    revision,
                    id,
                    tenant_id,
                    i64::from(reset_certificates),
                    i64::from(dns_enabled),
                    dns_ipv4,
                    dns_ipv6,
                ],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存域名设置"))?;
        if reset_certificates {
            connection
                .execute(
                    "UPDATE public_domain_certificate_progress
                     SET stage = 'waiting_configuration', attempt_count = 0,
                         last_event_at = NULL, next_retry_at = NULL,
                         error_code = NULL, error_message = NULL, updated_at = unixepoch()
                     WHERE public_domain_id = ?1",
                    [&id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法重置证书进度")
                })?;
        }
        revision
    };
    reconcile_caddy_config_best_effort(&state).await;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            &public_domain_query_ordered("WHERE p.id = ?1 AND p.tenant_id = ?2"),
            rusqlite::params![id, tenant_id],
            public_domain_response_from_row,
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取域名设置"))
}

#[derive(Debug, Deserialize, Default)]
struct DeletePublicDomainRequest {
    replacement_domain_id: Option<String>,
    #[serde(default)]
    disable_public_access: bool,
}

async fn delete_public_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<DeletePublicDomainRequest>>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let request = body.map(|Json(value)| value).unwrap_or_default();
    let replacement = request.replacement_domain_id.as_deref();
    let (secret_dir, usage, is_primary) = {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始域名删除事务")
        })?;
        let row: (String, i64, bool) = transaction
            .query_row(
                "SELECT secret_dir,
                        (SELECT COUNT(*) FROM tunnels t WHERE t.public_domain_id = public_domains.id AND t.deleted_at IS NULL),
                        is_primary FROM public_domains
                 WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? != 0)),
            )
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "域名不存在"))?;
        let domain_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM public_domains WHERE tenant_id = ?1",
                [&tenant_id],
                |count_row| count_row.get(0),
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查域名数量"))?;
        if row.2 && domain_count > 1 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "主域名不能直接删除，请先切换主域名",
            ));
        }
        if row.2 && !request.disable_public_access {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "删除唯一主域名会停用公网入口，请确认后重试",
            ));
        }
        let active_migration: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM public_domain_migrations
                 WHERE (from_domain_id = ?1 OR to_domain_id = ?1)
                   AND status <> 'completed'",
                [&id],
                |migration_row| migration_row.get(0),
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查域名迁移状态")
            })?;
        if active_migration > 0 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "域名仍被未完成的主域名迁移依赖，所有设备确认前不能删除",
            ));
        }
        if row.1 > 0 && !row.2 {
            let Some(target) = replacement else {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "域名仍被服务使用，请选择替代域名",
                ));
            };
            if target == id {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "替代域名不能与待删除域名相同",
                ));
            }
            let target_ready: Option<(String, String, String, String, String, i64)> = transaction
                .query_row(
                    "SELECT domain, apply_status, root_certificate_status,
                            wildcard_certificate_status,
                            dns_check_json,
                            (SELECT COUNT(*) FROM tunnels t WHERE t.public_domain_id = public_domains.id AND t.deleted_at IS NULL)
                     FROM public_domains WHERE id = ?1 AND tenant_id = ?2",
                    rusqlite::params![target, tenant_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查替代域名"))?;
            let Some((_, status, root_status, wildcard_status, dns_check, _)) = target_ready else {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "替代域名不存在"));
            };
            if !status.eq_ignore_ascii_case("ready")
                || !root_status.eq_ignore_ascii_case("ready")
                || !wildcard_status.eq_ignore_ascii_case("ready")
            {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "替代域名尚未 READY，不能迁移服务",
                ));
            }
            if !public_domain_dns_ready(&dns_check) {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "替代域名的根域名和泛域名 DNS 检查尚未全部通过",
                ));
            }
            let conflict: i64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM tunnels old
                     JOIN tunnels target ON target.public_domain_id = ?1
                       AND target.hostname = old.hostname
                       AND target.deleted_at IS NULL
                     WHERE old.public_domain_id = ?2 AND old.deleted_at IS NULL
                       AND old.protocol IN ('http', 'https')",
                    rusqlite::params![target, id],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查服务名称冲突")
                })?;
            if conflict > 0 {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "替代域名存在同名服务，请先处理冲突",
                ));
            }
            transaction
                .execute(
                    "UPDATE tunnels SET public_domain_id = ?1, updated_at = CURRENT_TIMESTAMP
                     WHERE public_domain_id = ?2 AND deleted_at IS NULL",
                    rusqlite::params![target, id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法迁移域名服务")
                })?;
        }
        if row.2 {
            transaction
                .execute(
                    "UPDATE tunnels SET public_domain_id = NULL, updated_at = CURRENT_TIMESTAMP
                     WHERE public_domain_id = ?1 AND deleted_at IS NULL
                       AND protocol IN ('http', 'https')",
                    [&id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法解除服务域名绑定")
                })?;
            transaction
                .execute(
                    "UPDATE public_domains SET https_enabled = 0,
                     certificate_mode = 'cloudflare', apply_status = 'ready', apply_error = NULL,
                     root_certificate_status = 'pending', wildcard_certificate_status = 'pending',
                     root_certificate_not_before = NULL, root_certificate_not_after = NULL,
                     wildcard_certificate_not_before = NULL, wildcard_certificate_not_after = NULL,
                     root_certificate_subjects_json = '[]', wildcard_certificate_subjects_json = '[]',
                     dns_check_json = '{}', desired_revision = desired_revision + 1,
                     updated_at = unixepoch() WHERE tenant_id = ?1 AND is_primary = 1",
                    [&tenant_id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法停用公网入口")
                })?;
        }
        // 已完成迁移只是历史记录，不应继续通过外键阻止旧域名删除；进行中的
        // 迁移已在上方拒绝，删除任务会级联清理逐设备状态。
        transaction
            .execute(
                "DELETE FROM public_domain_migrations
                 WHERE (from_domain_id = ?1 OR to_domain_id = ?1) AND status = 'completed'",
                [&id],
            )
            .map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法清理已完成的域名迁移记录",
                )
            })?;
        transaction
            .execute(
                "DELETE FROM public_domains WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法删除域名记录"))?;
        transaction.commit().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交域名删除事务")
        })?;
        (row.0, row.1, row.2)
    };
    let secret_dir = {
        let path = PathBuf::from(secret_dir);
        if path.is_absolute() {
            path
        } else {
            state.data_dir.join(path)
        }
    };
    if let Err(error) = fs::remove_dir_all(&secret_dir) {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(domain_id = %id, "域名 Secret 目录清理失败：{error}");
        }
    }
    reconcile_caddy_config_best_effort(&state).await;
    if is_primary {
        sync_headscale_server_url(&state).await;
    }
    tracing::info!(domain_id = %id, usage, "公网域名已删除");
    Ok(Json(DeleteResponse {
        deleted: true,
        pending: false,
        id,
        message: "公网域名已删除".to_owned(),
    }))
}

async fn upload_public_domain_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<PublicDomainSecretRequest>,
) -> Result<Json<PublicDomainResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let (domain, mode) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT domain, certificate_mode FROM public_domains WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "域名不存在"))?
    };
    // 先完成全部模式和证书校验，再触碰 Secret 文件。这样即使同一请求还
    // 携带 Cloudflare Token，证书错误也不会留下部分生效的凭据。
    let certificate_metadata = match mode.as_str() {
        "cloudflare" => {
            if request.certificate_pem.is_some() || request.private_key_pem.is_some() {
                if !request.activate_manual_certificate {
                    return Err(ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "上传手动证书时必须明确启用手动证书模式",
                    ));
                }
                match (
                    request.certificate_pem.as_deref(),
                    request.private_key_pem.as_deref(),
                ) {
                    (Some(certificate), Some(private_key)) => {
                        Some(validate_certificate_pair_for_domain(
                            certificate,
                            private_key,
                            Some(&domain),
                        )?)
                    }
                    _ => {
                        return Err(ApiError::new(
                            StatusCode::BAD_REQUEST,
                            "证书和私钥必须同时提供",
                        ))
                    }
                }
            } else {
                None
            }
        }
        "manual" => {
            match (
                request.certificate_pem.as_deref(),
                request.private_key_pem.as_deref(),
            ) {
                (Some(certificate), Some(private_key)) => Some(
                    validate_certificate_pair_for_domain(certificate, private_key, Some(&domain))?,
                ),
                (None, None) => None,
                _ => {
                    return Err(ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "证书和私钥必须同时提供",
                    ));
                }
            }
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "证书模式无效，请先保存域名设置",
            ));
        }
    };
    if request.activate_manual_certificate && certificate_metadata.is_none() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "启用手动证书时必须同时提供证书和私钥",
        ));
    }
    if request
        .cloudflare_token
        .as_deref()
        .is_some_and(|token| token.trim().is_empty())
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Cloudflare Token 不能为空",
        ));
    }

    let directory = domain_secret_dir(&state, &id);
    let mut secret_rollbacks = Vec::new();
    // Cloudflare Token 同时服务于自动证书 DNS-01 和可选 DNS 托管，
    // 因此它不再与证书来源绑定；手动证书域名也可以保存 Token。
    if let Some(token) = request.cloudflare_token.as_deref() {
        let path = directory.join("cloudflare.token");
        capture_secret_rollback(&mut secret_rollbacks, &path);
        write_secret_file(&path, token)?;
    }
    let uploaded_certificate = if let (Some(certificate), Some(private_key), Some(metadata)) = (
        request.certificate_pem.as_deref(),
        request.private_key_pem.as_deref(),
        certificate_metadata.as_ref(),
    ) {
        let certificate_path = directory.join("certificate.pem");
        let private_key_path = directory.join("private-key.pem");
        capture_secret_rollback(&mut secret_rollbacks, &certificate_path);
        capture_secret_rollback(&mut secret_rollbacks, &private_key_path);
        write_secret_file(&certificate_path, certificate)?;
        write_secret_file(&private_key_path, private_key)?;
        Some((
            metadata.not_before,
            metadata.not_after,
            serde_json::to_string(&metadata.subjects).unwrap_or_else(|_| "[]".to_owned()),
        ))
    } else {
        None
    };
    {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始凭据状态事务")
        })?;
        if let Some((not_before, not_after, subjects)) = uploaded_certificate.as_ref() {
            transaction
                .execute(
                    "UPDATE public_domains SET certificate_mode = CASE WHEN ?1 = 1 THEN 'manual' ELSE certificate_mode END,
                     root_certificate_status = 'ready', wildcard_certificate_status = 'ready',
                     root_certificate_not_before = ?2, root_certificate_not_after = ?3,
                     wildcard_certificate_not_before = ?2, wildcard_certificate_not_after = ?3,
                     root_certificate_subjects_json = ?4, wildcard_certificate_subjects_json = ?4,
                     apply_status = 'checking', apply_error = NULL, error_code = NULL,
                     desired_revision = desired_revision + 1, updated_at = unixepoch()
                     WHERE id = ?5 AND tenant_id = ?6",
                    rusqlite::params![
                        i64::from(request.activate_manual_certificate),
                        not_before,
                        not_after,
                        subjects,
                        id,
                        tenant_id
                    ],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存证书元数据")
                })?;
            transaction
                .execute(
                    "UPDATE public_domain_certificate_progress
                     SET stage = 'active', last_event_at = unixepoch(), next_retry_at = NULL,
                         error_code = NULL, error_message = NULL, updated_at = unixepoch()
                     WHERE public_domain_id = ?1",
                    [&id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存证书进度")
                })?;
        }
        if request.activate_manual_certificate {
            transaction
                .execute(
                    "UPDATE public_domains SET certificate_mode = 'manual',
                     desired_revision = desired_revision + 1, updated_at = unixepoch()
                     WHERE tenant_id = ?1 AND domain = ?2",
                    rusqlite::params![tenant_id, domain],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新主域名证书模式")
                })?;
        }
        transaction
            .execute(
                "UPDATE public_domains SET apply_status = 'checking', apply_error = NULL,
                 error_code = NULL, desired_revision = desired_revision + 1,
                 updated_at = unixepoch() WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新证书应用状态")
            })?;
        transaction.commit().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交凭据状态事务")
        })?;
    }
    reconcile_caddy_config_best_effort(&state).await;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let response = connection
        .query_row(
            &public_domain_query_ordered("WHERE p.id = ?1 AND p.tenant_id = ?2"),
            rusqlite::params![id, tenant_id],
            public_domain_response_from_row,
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取域名证书状态"));
    if response.is_ok() {
        for rollback in &mut secret_rollbacks {
            rollback.commit();
        }
    }
    response
}

async fn delete_public_domain_manual_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<PublicDomainResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let domain = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT domain FROM public_domains WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "域名不存在"))?
    };
    let directory = domain_secret_dir(&state, &id);
    let certificate_path = directory.join("certificate.pem");
    let private_key_path = directory.join("private-key.pem");
    let mut rollbacks = vec![
        SecretFileRollback::capture(&certificate_path),
        SecretFileRollback::capture(&private_key_path),
    ];
    for path in [&certificate_path, &private_key_path] {
        if let Err(error) = fs::remove_file(path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法删除手动证书文件",
                ));
            }
        }
    }
    {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法开始手动证书删除事务",
            )
        })?;
        transaction
            .execute(
                "UPDATE public_domains SET root_certificate_status = 'pending',
                 wildcard_certificate_status = 'pending', root_certificate_not_before = NULL,
                 root_certificate_not_after = NULL, wildcard_certificate_not_before = NULL,
                 wildcard_certificate_not_after = NULL, root_certificate_subjects_json = '[]',
                 wildcard_certificate_subjects_json = '[]', apply_status = 'error',
                 apply_error = '手动证书已删除，请上传新证书或明确切换到自动证书',
                 error_code = 'manual_certificate_missing', desired_revision = desired_revision + 1,
                 updated_at = unixepoch() WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新手动证书状态")
            })?;
        transaction
            .execute(
                "UPDATE public_domain_certificate_progress SET stage = 'waiting_configuration',
                 last_event_at = unixepoch(), next_retry_at = NULL,
                 error_code = 'manual_certificate_missing',
                 error_message = '手动证书已删除，自动申请保持关闭', updated_at = unixepoch()
                 WHERE public_domain_id = ?1",
                [&id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新证书进度"))?;
        transaction
            .execute(
                "UPDATE public_domains SET root_certificate_not_before = NULL,
                 root_certificate_not_after = NULL, wildcard_certificate_not_before = NULL,
                 wildcard_certificate_not_after = NULL, root_certificate_subjects_json = '[]',
                 wildcard_certificate_subjects_json = '[]', root_certificate_status = 'error',
                 wildcard_certificate_status = 'error', apply_status = 'error',
                 apply_error = '手动证书已删除，请重新配置证书',
                 desired_revision = desired_revision + 1, updated_at = unixepoch()
                 WHERE tenant_id = ?1 AND domain = ?2",
                rusqlite::params![tenant_id, domain],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新主域名证书状态")
            })?;
        transaction.commit().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法提交手动证书删除事务",
            )
        })?;
    }
    for rollback in &mut rollbacks {
        rollback.commit();
    }
    reconcile_caddy_config_best_effort(&state).await;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            &public_domain_query_ordered("WHERE p.id = ?1 AND p.tenant_id = ?2"),
            rusqlite::params![id, tenant_id],
            public_domain_response_from_row,
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取域名证书状态"))
}

async fn recheck_public_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<PublicDomainResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let (
        domain,
        https_enabled,
        is_primary,
        certificate_mode,
        previous_retry_after,
        dns_management_enabled,
    ) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT domain, https_enabled, is_primary, certificate_mode, retry_after,
                        dns_management_enabled
                 FROM public_domains WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get::<_, i64>(2)? != 0,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, i64>(5)? != 0,
                    ))
                },
            )
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "域名不存在"))?
    };
    let root = lookup_public_dns(&domain).await;
    let wildcard = lookup_public_dns(&wildcard_dns_probe_hostname(&domain)).await;
    let dns = build_dns_check(&domain, root, wildcard);
    // 页面轮询只读检查 Cloudflare 漂移，不在后台覆盖用户手工修改。
    let managed_dns_check = if dns_management_enabled {
        match build_managed_dns_preview(&state, &tenant_id, &id).await {
            Ok((preview, _, _))
                if preview
                    .changes
                    .iter()
                    .all(|change| change.action == "adopt") =>
            {
                ("ready".to_owned(), None)
            }
            Ok(_) => (
                "drifted".to_owned(),
                Some("Cloudflare 记录与 Nexo 目标不一致，请查看预览后手动同步".to_owned()),
            ),
            Err(error) => ("error".to_owned(), Some(error.message)),
        }
    } else {
        ("disabled".to_owned(), None)
    };
    let tls_ready = !https_enabled || !is_primary || probe_public_https(&domain).await;
    let manual_certificate_metadata = if https_enabled
        && certificate_mode.eq_ignore_ascii_case("manual")
    {
        let certificate_path = domain_secret_dir(&state, &id).join("certificate.pem");
        let private_key_path = domain_secret_dir(&state, &id).join("private-key.pem");
        match (
            fs::read_to_string(certificate_path),
            fs::read_to_string(private_key_path),
        ) {
            (Ok(certificate), Ok(private_key)) => {
                validate_certificate_pair_for_domain(&certificate, &private_key, Some(&domain)).ok()
            }
            _ => None,
        }
    } else {
        None
    };
    let root_certificate_metadata = if https_enabled {
        if certificate_mode.eq_ignore_ascii_case("manual") {
            manual_certificate_metadata.clone()
        } else {
            find_caddy_certificate_metadata(&state.data_dir, &domain)
        }
    } else {
        None
    };
    let wildcard_certificate_metadata = if https_enabled {
        if certificate_mode.eq_ignore_ascii_case("manual") {
            manual_certificate_metadata
        } else {
            find_caddy_certificate_metadata(&state.data_dir, &format!("*.{domain}"))
        }
    } else {
        None
    };
    let now = unix_now();
    let certificate_status = |metadata: &Option<CertificateMetadata>| {
        if !https_enabled
            || metadata
                .as_ref()
                .is_some_and(|item| item.not_before <= now && item.not_after > now)
        {
            "ready"
        } else if metadata.as_ref().is_some_and(|item| item.not_after <= now) {
            "expired"
        } else {
            "pending"
        }
    };
    let root_certificate_status = certificate_status(&root_certificate_metadata);
    let wildcard_certificate_status = certificate_status(&wildcard_certificate_metadata);
    let certificate_ready = !https_enabled
        || (root_certificate_status == "ready" && wildcard_certificate_status == "ready");
    let certificate_expired =
        root_certificate_status == "expired" || wildcard_certificate_status == "expired";
    let rate_limited =
        !certificate_ready && previous_retry_after.is_some_and(|retry_after| retry_after > now);
    let apply_status = if !https_enabled || (certificate_ready && tls_ready) {
        "ready"
    } else if rate_limited {
        "rate_limited"
    } else {
        "retrying"
    };
    let apply_error = if apply_status == "ready" {
        None
    } else if rate_limited {
        Some("CA 限流窗口尚未结束，自动证书服务将按官方退避重试")
    } else if certificate_expired {
        Some("证书已过期，自动证书服务将按既定规则续期")
    } else {
        Some("根域名或泛域名证书尚未签发，系统将自动重试")
    };
    let error_code = if apply_status == "ready" {
        None
    } else if rate_limited {
        Some("acme_rate_limited")
    } else if certificate_expired {
        Some("certificate_expired")
    } else {
        Some("certificate_pending")
    };
    // Caddy 自己维护 ACME 指数退避；重新检测只读取当前窗口，不伪造一个
    // “60 秒后必定重试”的时间，避免 UI 诱导用户反复点击申请。
    let next_retry_at = (apply_status == "rate_limited")
        .then(|| previous_retry_after.filter(|retry_after| *retry_after > now))
        .flatten();
    let certificate_json = |metadata: &Option<CertificateMetadata>| {
        metadata
            .as_ref()
            .and_then(|item| serde_json::to_string(&item.subjects).ok())
    };
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .execute(
                "UPDATE public_domains SET dns_check_json = ?1,
             root_certificate_status = ?2, wildcard_certificate_status = ?3,
             apply_status = ?4,
             apply_error = CASE WHEN ?4 = 'ready' THEN NULL ELSE COALESCE(apply_error, ?5) END,
             error_code = CASE WHEN ?4 = 'ready' THEN NULL ELSE COALESCE(error_code, ?6) END,
             root_certificate_not_before = ?7, root_certificate_not_after = ?8,
             root_certificate_subjects_json = COALESCE(?9, '[]'),
             wildcard_certificate_not_before = ?10, wildcard_certificate_not_after = ?11,
             wildcard_certificate_subjects_json = COALESCE(?12, '[]'),
             retry_after = ?13, next_retry_at = ?13,
             dns_management_status = ?14, dns_management_error = ?15,
             updated_at = unixepoch() WHERE id = ?16 AND tenant_id = ?17",
                rusqlite::params![
                    dns.to_string(),
                    root_certificate_status,
                    wildcard_certificate_status,
                    apply_status,
                    apply_error,
                    error_code,
                    root_certificate_metadata
                        .as_ref()
                        .map(|metadata| metadata.not_before),
                    root_certificate_metadata
                        .as_ref()
                        .map(|metadata| metadata.not_after),
                    certificate_json(&root_certificate_metadata),
                    wildcard_certificate_metadata
                        .as_ref()
                        .map(|metadata| metadata.not_before),
                    wildcard_certificate_metadata
                        .as_ref()
                        .map(|metadata| metadata.not_after),
                    certificate_json(&wildcard_certificate_metadata),
                    next_retry_at,
                    managed_dns_check.0,
                    managed_dns_check.1,
                    id,
                    tenant_id,
                ],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存 DNS 检查结果")
            })?;
        for (certificate_type, certificate_status) in [
            ("root", root_certificate_status),
            ("wildcard", wildcard_certificate_status),
        ] {
            connection
                .execute(
                    "UPDATE public_domain_certificate_progress SET
                     stage = CASE WHEN ?1 = 'ready' THEN 'active'
                         WHEN ?2 = 'rate_limited' THEN 'retry_wait'
                         WHEN stage IN ('active', 'issued') THEN 'waiting_configuration'
                         ELSE stage END,
                     next_retry_at = ?3,
                     last_event_at = CASE WHEN ?1 = 'ready' THEN unixepoch() ELSE last_event_at END,
                     error_code = CASE WHEN ?1 = 'ready' THEN NULL ELSE error_code END,
                     error_message = CASE WHEN ?1 = 'ready' THEN NULL ELSE error_message END,
                     updated_at = unixepoch()
                     WHERE public_domain_id = ?4 AND certificate_type = ?5",
                    rusqlite::params![
                        certificate_status,
                        apply_status,
                        next_retry_at,
                        id,
                        certificate_type
                    ],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存证书进度")
                })?;
        }
    }
    reconcile_caddy_config_best_effort(&state).await;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            &public_domain_query_ordered("WHERE p.id = ?1 AND p.tenant_id = ?2"),
            rusqlite::params![id, tenant_id],
            public_domain_response_from_row,
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取 DNS 检查结果"))
}

/// 请求 Caddy 立即重新处理指定域名的自动 HTTPS 配置。
///
/// 这不是绕过 CA 限流的自建 ACME 客户端；仍由 Caddy 负责签发、指数退避
/// 和续期。若服务器记录的 Retry-After 尚未到期，接口明确返回 429，前端
/// 只展示下一次允许时间。
async fn renew_public_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<PublicDomainResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let result = renew_public_domains(&state, &tenant_id, std::slice::from_ref(&id)).await?;
    result
        .updated
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "当前域名暂时不能立即申请证书"))
        .map(Json)
}

async fn batch_recheck_public_domains(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PublicDomainBatchRequest>,
) -> Result<Json<PublicDomainBatchResponse>, ApiError> {
    let _tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let ids = normalize_public_domain_ids(request.ids)?;
    let mut updated = Vec::new();
    let mut skipped = Vec::new();
    for id in ids {
        match recheck_public_domain(State(state.clone()), headers.clone(), Path(id.clone())).await {
            Ok(Json(value)) => updated.push(value),
            Err(error) => skipped.push(BatchSkippedItem {
                id,
                reason: error.message,
            }),
        }
    }
    Ok(Json(PublicDomainBatchResponse {
        message: format!("已重新检测 {} 个域名", updated.len()),
        updated,
        skipped,
    }))
}

async fn batch_renew_public_domains(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PublicDomainBatchRequest>,
) -> Result<Json<PublicDomainBatchResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let ids = normalize_public_domain_ids(request.ids)?;
    let result = renew_public_domains(&state, &tenant_id, &ids).await?;
    Ok(Json(result))
}

fn normalize_public_domain_ids(ids: Vec<String>) -> Result<Vec<String>, ApiError> {
    let mut seen = HashSet::new();
    let ids = ids
        .into_iter()
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .filter(|id| seen.insert(id.clone()))
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "至少选择一个域名"));
    }
    Ok(ids)
}

async fn renew_public_domains(
    state: &AppState,
    tenant_id: &str,
    ids: &[String],
) -> Result<PublicDomainBatchResponse, ApiError> {
    let now = unix_now();
    let mut skipped = Vec::new();
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        for id in ids {
            let row: Option<(Option<i64>, String, bool)> = connection
                .query_row(
                    "SELECT retry_after, certificate_mode, https_enabled FROM public_domains
                     WHERE id = ?1 AND tenant_id = ?2",
                    rusqlite::params![id, tenant_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? != 0)),
                )
                .optional()
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查域名续期状态")
                })?;
            let Some((retry_after, mode, https_enabled)) = row else {
                skipped.push(BatchSkippedItem {
                    id: id.clone(),
                    reason: "域名不存在".to_owned(),
                });
                continue;
            };
            if mode.eq_ignore_ascii_case("manual") {
                skipped.push(BatchSkippedItem {
                    id: id.clone(),
                    reason: "手动证书需要上传新的证书和私钥".to_owned(),
                });
                continue;
            }
            if !https_enabled {
                skipped.push(BatchSkippedItem {
                    id: id.clone(),
                    reason: "该域名未启用 HTTPS，无需申请证书".to_owned(),
                });
                continue;
            }
            if retry_after.is_some_and(|retry| retry > now) {
                skipped.push(BatchSkippedItem {
                    id: id.clone(),
                    reason: "CA 限流窗口尚未结束，系统会自动重试".to_owned(),
                });
                continue;
            }
            connection
                .execute(
                    "UPDATE public_domains SET apply_status = 'checking', apply_error = NULL,
                     error_code = NULL, retry_after = NULL, next_retry_at = NULL,
                     attempt_count = attempt_count + 1, desired_revision = desired_revision + 1,
                     updated_at = unixepoch() WHERE id = ?1 AND tenant_id = ?2",
                    rusqlite::params![id, tenant_id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新域名续期任务")
                })?;
            connection
                .execute(
                    "UPDATE public_domain_certificate_progress
                     SET stage = 'waiting_configuration', attempt_count = attempt_count + 1,
                         last_event_at = unixepoch(), next_retry_at = NULL,
                         error_code = NULL, error_message = NULL, updated_at = unixepoch()
                     WHERE public_domain_id = ?1",
                    [id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新证书申请进度")
                })?;
        }
    }
    reconcile_caddy_config_best_effort(state).await;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut updated = Vec::new();
    for id in ids {
        if skipped.iter().any(|item| item.id == *id) {
            continue;
        }
        if let Ok(domain) = connection.query_row(
            &public_domain_query_ordered("WHERE p.id = ?1 AND p.tenant_id = ?2"),
            rusqlite::params![id, tenant_id],
            public_domain_response_from_row,
        ) {
            updated.push(domain);
        }
    }
    Ok(PublicDomainBatchResponse {
        message: format!(
            "已请求自动证书服务处理 {} 个域名，限流项将按官方退避自动重试",
            updated.len()
        ),
        updated,
        skipped,
    })
}

async fn make_public_domain_primary(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<MakePrimaryRequest>,
) -> Result<Json<PublicDomainMigrationResponse>, ApiError> {
    if !request.confirm {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "请确认主域名切换影响后再提交",
        ));
    }
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let migration = {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始主域名切换事务")
        })?;
        let target: (String, bool, String, String, String, String) = transaction
            .query_row(
                "SELECT domain, is_primary, apply_status, root_certificate_status,
                        wildcard_certificate_status, dns_check_json FROM public_domains
                 WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "域名不存在"))?;
        if target.1 {
            return Err(ApiError::new(StatusCode::CONFLICT, "该域名已经是主域名"));
        }
        if !public_domain_ready_from_row("ready", true, &target.3, &target.4)
            || !target.2.eq_ignore_ascii_case("ready")
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "根域名和泛域名证书必须全部 READY 后才能设为主域名",
            ));
        }
        if !public_domain_dns_ready(&target.5) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "根域名和泛域名 DNS 检查必须全部通过后才能设为主域名",
            ));
        }
        let source: (String, String) = transaction
            .query_row(
                "SELECT id, domain FROM public_domains WHERE tenant_id = ?1 AND is_primary = 1",
                [&tenant_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ApiError::new(StatusCode::CONFLICT, "当前没有可迁移的主域名"))?;
        let conflict: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM tunnels source
                 JOIN tunnels target ON target.public_domain_id = ?1
                    AND target.hostname = source.hostname AND target.deleted_at IS NULL
                 WHERE source.public_domain_id = ?2 AND source.deleted_at IS NULL
                   AND source.protocol IN ('http', 'https')",
                rusqlite::params![id, source.0],
                |row| row.get(0),
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查服务名称冲突")
            })?;
        if conflict > 0 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "目标域名存在同名服务，主域名切换已阻止",
            ));
        }
        let migration_id = Uuid::new_v4().to_string();
        let total_devices: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM devices WHERE tenant_id = ?1",
                [&tenant_id],
                |row| row.get(0),
            )
            .unwrap_or_default();
        transaction
            .execute(
                "UPDATE public_domains SET is_primary = 0 WHERE id = ?1",
                [&source.0],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新旧主域名状态")
            })?;
        transaction.execute("UPDATE public_domains SET is_primary = 1, desired_revision = desired_revision + 1 WHERE id = ?1", [&id])
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法设置新主域名"))?;
        transaction
            .execute(
                "UPDATE public_domains SET apply_status = 'checking', apply_error = NULL,
                 desired_revision = desired_revision + 1, updated_at = unixepoch()
                 WHERE id = ?2 AND tenant_id = ?3",
                rusqlite::params![target.0, id, tenant_id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新兼容域名投影")
            })?;
        transaction.execute("UPDATE tunnels SET public_domain_id = ?1, updated_at = CURRENT_TIMESTAMP WHERE public_domain_id = ?2 AND deleted_at IS NULL AND protocol IN ('http', 'https')", rusqlite::params![id, source.0])
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法迁移 Web 服务域名"))?;
        let migration_status = if total_devices == 0 {
            "completed"
        } else {
            "switching"
        };
        transaction.execute("INSERT INTO public_domain_migrations (id, tenant_id, from_domain_id, to_domain_id, status, total_devices, completed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, CASE WHEN ?5 = 'completed' THEN unixepoch() ELSE NULL END)", rusqlite::params![migration_id, tenant_id, source.0, id, migration_status, total_devices])
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法创建主域名迁移任务"))?;
        let mut devices = transaction
            .prepare("SELECT id FROM devices WHERE tenant_id = ?1")
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备列表"))?;
        let ids = devices
            .query_map([&tenant_id], |row| row.get::<_, String>(0))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备列表"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "设备列表数据格式无效")
            })?;
        drop(devices);
        for device_id in ids {
            transaction.execute("INSERT INTO public_domain_migration_devices (migration_id, device_id, status) VALUES (?1, ?2, 'pending')", rusqlite::params![migration_id, device_id])
                .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法记录设备迁移状态"))?;
        }
        transaction
            .commit()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交主域名切换"))?;
        (migration_id, source.0, id, total_devices)
    };
    sync_headscale_server_url(&state).await;
    seed_public_domain_migration_offers(&state).await;
    reconcile_caddy_config_best_effort(&state).await;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            "SELECT id, from_domain_id, to_domain_id, status, total_devices,
                    acknowledged_devices, last_error, created_at, updated_at
             FROM public_domain_migrations WHERE id = ?1",
            [&migration.0],
            |row| {
                Ok(PublicDomainMigrationResponse {
                    id: row.get(0)?,
                    from_domain_id: row.get(1)?,
                    to_domain_id: row.get(2)?,
                    status: row.get(3)?,
                    total_devices: row.get(4)?,
                    acknowledged_devices: row.get(5)?,
                    last_error: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取主域名迁移任务"))
}

async fn get_public_domain_migration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<PublicDomainMigrationResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            "SELECT id, from_domain_id, to_domain_id, status, total_devices,
                    acknowledged_devices, last_error, created_at, updated_at
             FROM public_domain_migrations WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![id, tenant_id],
            |row| {
                Ok(PublicDomainMigrationResponse {
                    id: row.get(0)?,
                    from_domain_id: row.get(1)?,
                    to_domain_id: row.get(2)?,
                    status: row.get(3)?,
                    total_devices: row.get(4)?,
                    acknowledged_devices: row.get(5)?,
                    last_error: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            },
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "主域名迁移任务不存在"))
}

/// 读取公网入口和 Web Service Desired State，生成一份完整的 Caddy 配置。
///
/// Caddy 不直接读取 SQLite；Nexo 先把用户可见配置转换为受限的内部
/// Socket 路由，再通过 Admin API 应用，保证数据库和边缘组件之间有清晰
/// 的 Desired/Applied 边界。
fn load_caddy_desired_config(state: &AppState) -> Result<(PrimaryDomainStatus, serde_json::Value)> {
    load_caddy_desired_config_with_readiness(state, None)
}

/// 从同一份 Desired State 生成 Caddy 配置；`https_ready_override` 用于
/// 在本轮证书探测成功后立即重建带 308 跳转的配置，避免必须等待下一次
/// 后台协调才把“证书已就绪”反映到实际边缘路由。
fn load_caddy_desired_config_with_readiness(
    state: &AppState,
    https_ready_override: Option<bool>,
) -> Result<(PrimaryDomainStatus, serde_json::Value)> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let entry = read_primary_domain_status(&connection)?;
    let tenant_id: String = connection.query_row(
        "SELECT tenant_id FROM public_domains WHERE is_primary = 1
         ORDER BY updated_at DESC LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let mut domain_statement = connection.prepare(
        "SELECT id, domain, is_primary, https_enabled, certificate_mode,
                acme_environment, secret_dir, apply_status,
                root_certificate_status, wildcard_certificate_status
         FROM public_domains WHERE tenant_id = ?1 ORDER BY is_primary DESC, domain ASC",
    )?;
    let domains = domain_statement
        .query_map([tenant_id.clone()], |row| {
            let id: String = row.get(0)?;
            let secret_dir: String = row.get(6)?;
            let is_primary = row.get::<_, i64>(2)? != 0;
            // “立即就绪”只用于本轮刚刚完成探测的主域名；附加域名仍
            // 必须依据各自的证书状态，避免一次主域名探测误开全部路由。
            let ready = if is_primary {
                https_ready_override.unwrap_or_else(|| {
                    public_domain_ready_from_row(
                        &row.get::<_, String>(7).unwrap_or_default(),
                        row.get::<_, i64>(3).unwrap_or_default() != 0,
                        &row.get::<_, String>(8).unwrap_or_default(),
                        &row.get::<_, String>(9).unwrap_or_default(),
                    )
                })
            } else {
                public_domain_ready_from_row(
                    &row.get::<_, String>(7).unwrap_or_default(),
                    row.get::<_, i64>(3).unwrap_or_default() != 0,
                    &row.get::<_, String>(8).unwrap_or_default(),
                    &row.get::<_, String>(9).unwrap_or_default(),
                )
            };
            let token_env = (row.get::<_, String>(4)? == "cloudflare")
                .then(|| format!("{{env.NEXO_CLOUDFLARE_TOKEN_{}}}", caddy_env_suffix(&id)));
            Ok(caddy::CaddyDomain {
                id,
                domain: row.get(1)?,
                https_enabled: row.get::<_, i64>(3)? != 0,
                certificate_mode: row.get(4)?,
                acme_environment: row.get(5)?,
                secret_dir: if PathBuf::from(&secret_dir).is_absolute() {
                    PathBuf::from(&secret_dir)
                } else {
                    state.data_dir.join(&secret_dir)
                },
                manual_certificate_available: {
                    let path = if PathBuf::from(&secret_dir).is_absolute() {
                        PathBuf::from(&secret_dir)
                    } else {
                        state.data_dir.join(&secret_dir)
                    };
                    path.join("certificate.pem").is_file() && path.join("private-key.pem").is_file()
                },
                token_env,
                https_ready: ready,
                system_entry: is_primary,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut statement = connection.prepare(
        "SELECT id, hostname, protocol, bridge_socket_path, enabled, public_domain_id
         FROM tunnels
         WHERE tenant_id = ?1 AND deleted_at IS NULL AND protocol IN ('http', 'https')",
    )?;
    let mut tunnels = statement
        .query_map([tenant_id.clone()], |row| {
            let tunnel_id: String = row.get(0)?;
            let bridge = row.get::<_, Option<String>>(3)?.unwrap_or_else(|| {
                tunnel_bridge_socket_path(&state.data_dir, &tunnel_id)
                    .to_string_lossy()
                    .to_string()
            });
            Ok(caddy::CaddyBoundTunnel {
                domain_id: row.get::<_, Option<String>>(5)?.unwrap_or_else(|| {
                    domains
                        .first()
                        .map(|domain| domain.id.clone())
                        .unwrap_or_default()
                }),
                tunnel: caddy::CaddyTunnel {
                    hostname: row.get(1)?,
                    protocol: row.get(2)?,
                    bridge_socket: bridge,
                    enabled: row.get::<_, i64>(4)? != 0,
                },
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    // 主域名迁移完成前，旧域名仍需作为服务别名可达。Tunnel 的规范绑定
    // 已切换到新域名，这里只在 Caddy Desired State 中复制一份路由，
    // 不改变数据库中的最终归属；所有设备 ACK 后别名自然消失。
    let mut caddy_domains = domains.clone();
    let mut migration_statement = connection.prepare(
        "SELECT from_domain_id, to_domain_id FROM public_domain_migrations
         WHERE tenant_id = ?1 AND status <> 'completed'",
    )?;
    let active_migrations = migration_statement
        .query_map([tenant_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (from_id, to_id) in active_migrations {
        let Some(from_domain) = domains.iter().find(|domain| domain.id == from_id) else {
            continue;
        };
        let Some(to_domain) = domains.iter().find(|domain| domain.id == to_id) else {
            continue;
        };
        if let Some(domain) = caddy_domains.iter_mut().find(|domain| domain.id == from_id) {
            domain.system_entry = true;
        }
        let aliases = tunnels
            .iter()
            .filter(|tunnel| tunnel.domain_id == to_domain.id)
            .cloned()
            .map(|mut tunnel| {
                tunnel.domain_id = from_domain.id.clone();
                tunnel
            })
            .collect::<Vec<_>>();
        tunnels.extend(aliases);
    }
    let config = caddy::build_multi_caddy_config(
        &caddy_domains,
        &tunnels,
        &state.data_dir.join("caddy-storage"),
    );
    Ok((entry, config))
}

fn caddy_env_suffix(id: &str) -> String {
    id.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>()
        .to_ascii_uppercase()
}

fn update_primary_domain_apply_state(
    state: &AppState,
    status: &str,
    error: Option<&str>,
    applied_revision: Option<i64>,
) -> Result<()> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    connection.execute(
        "UPDATE public_domains
         SET apply_status = ?1, apply_error = ?2,
             applied_revision = COALESCE(?3, applied_revision), updated_at = unixepoch()
         WHERE is_primary = 1",
        rusqlite::params![status, error, applied_revision],
    )?;
    Ok(())
}

/// 将公网入口的根域名转换为 Headscale 对外登录地址。
///
/// 只有 HTTPS 入口具备正式组网资格，因此没有域名或未启用 HTTPS 时切换到
/// 显式的内部地址，并由 `mesh_application_allowed_with_connection` 阻止新的
/// 组网应用；这样不会因为用户尚未完成证书配置而破坏现有 Nexo 管理入口。
async fn sync_headscale_server_url(state: &AppState) {
    let oidc_issuer = match state.db.lock() {
        Ok(connection) => match state.oidc.sync_issuer_from_database(&connection) {
            Ok(issuer) => issuer,
            Err(error) => {
                tracing::warn!("无法同步固定 OIDC issuer：{error:#}");
                None
            }
        },
        Err(_) => None,
    };
    if let Err(error) = state
        .headscale_runtime
        .update_oidc_issuer(oidc_issuer)
        .await
    {
        tracing::warn!("Headscale OIDC 配置同步失败：{error:#}");
    }
    let entry = match state.db.lock() {
        Ok(connection) => read_primary_domain_status(&connection).ok(),
        Err(_) => None,
    };
    let Some(entry) = entry else {
        tracing::warn!("无法读取公网入口，Headscale 登录地址暂不更新");
        return;
    };
    let endpoint = match (
        entry.https_enabled,
        entry.base_domain.filter(|value| !value.trim().is_empty()),
    ) {
        (true, Some(domain)) => format!("https://mesh.{domain}"),
        // 公网入口关闭后不保留旧域名，避免 Agent 重启时继续尝试已经
        // 不可用的地址。正式环境应显式设置内部可达地址；集成测试会
        // 通过 NEXO_MESH_INTERNAL_URL 提供容器网络地址。
        _ => state.headscale_runtime.config().internal_server_url(),
    };
    if let Err(error) = state.headscale_runtime.update_server_url(endpoint).await {
        tracing::warn!("Headscale 登录地址同步失败，新的设备入网将保持受限：{error:#}");
    }
}

/// 尝试应用最新 Caddy Desired State；边缘组件失败只记录状态，不阻塞
/// Nexo Core、LAN 管理或 TCP Tunnel 的请求。
async fn reconcile_caddy_config_best_effort(state: &AppState) {
    let result = async {
        let caddy_events = state.caddy.drain_log_events().await;
        if !caddy_events.is_empty() {
            apply_caddy_log_events(state, &caddy_events)?;
        }
        let (entry, config) = load_caddy_desired_config(state)?;
        if !state.caddy.config().enabled {
            state.caddy.write_startup_config(&config)?;
            let (status, message) = if entry.https_enabled {
                ("error", Some("域名与 HTTPS 尚未启用"))
            } else {
                ("not_configured", None)
            };
            update_primary_domain_apply_state(state, status, message, None)?;
            return Ok::<(), anyhow::Error>(());
        }
        state.caddy.apply_json(&config).await?;
        sync_caddy_certificate_metadata(state)?;
        update_public_domain_apply_states(state, None)?;
        let certificate_ready = public_certificate_material_ready(state, &entry).await;
        let (status, message) = if !entry.https_enabled {
            ("not_configured", None)
        } else if certificate_ready {
            ("ready", None)
        } else {
            ("configuring", Some("正在等待证书材料或 ACME 签发"))
        };
        // `load_caddy_desired_config` 读取的是上一次数据库状态；本轮首次
        // 应用成功后才知道证书已经 READY，因此需要立刻再应用一份带
        // HTTPS 跳转的配置，而不是把 308 留给 15 秒后的后台周期。
        if status == "ready"
            && entry.https_enabled
            && !entry.apply_status.eq_ignore_ascii_case("ready")
        {
            let (_, ready_config) = load_caddy_desired_config_with_readiness(state, Some(true))?;
            state.caddy.apply_json(&ready_config).await?;
        }
        update_primary_domain_apply_state(state, status, message, Some(entry.desired_revision))?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        tracing::warn!("Caddy 配置应用失败，已保留上一份配置：{error:#}");
        if let Err(update_error) = update_primary_domain_apply_state(
            state,
            "error",
            Some(&truncate_error_message(&format!("{error:#}"))),
            None,
        ) {
            tracing::warn!("无法保存 Caddy 应用错误：{update_error:#}");
        }
        if let Err(update_error) =
            update_public_domain_apply_states(state, Some(&format!("{error:#}")))
        {
            tracing::warn!("无法保存多域名 Caddy 错误：{update_error:#}");
        }
    }
    refresh_all_tunnel_readiness(state).await;
}

/// 将 Caddy 日志投影为根域名/泛域名的阶段轨迹。Server 不会自行发起
/// ACME 订单；这里只记录 Caddy 已公开的阶段、错误和下次尝试时间。
fn apply_caddy_log_events(state: &AppState, events: &[caddy::CaddyLogEvent]) -> Result<()> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let tenant_id: String = connection
        .query_row(
            "SELECT tenant_id FROM public_domains WHERE is_primary = 1
             ORDER BY updated_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .context("无法读取公网域名租户")?;
    let mut domains = connection
        .prepare("SELECT id, domain FROM public_domains WHERE tenant_id = ?1")?
        .query_map([&tenant_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    // 优先匹配较长的域名，避免 `app.example.com` 被错误归到 `example.com`。
    domains.sort_by_key(|(_, domain)| std::cmp::Reverse(domain.len()));
    for event in events {
        let normalized_identifier = event
            .identifier
            .as_deref()
            .map(|identifier| identifier.trim().trim_end_matches('.').to_ascii_lowercase());
        let lower_message = event.message.to_ascii_lowercase();
        let related_domain = domains.iter().find(|(_, domain)| {
            normalized_identifier.as_ref().is_some_and(|identifier| {
                identifier == domain
                    || identifier == &format!("*.{domain}")
                    || identifier.ends_with(&format!(".{domain}"))
            }) || lower_message.contains(domain.as_str())
        });
        persist_public_domain_runtime_event(state, &connection, &tenant_id, related_domain, event)?;
        let Some(stage) = event.certificate_stage() else {
            continue;
        };
        let retry_at = event
            .retry_after_secs
            .map(|seconds| unix_now().saturating_add(i64::try_from(seconds).unwrap_or(i64::MAX)));
        for (id, domain) in domains.iter().filter(|(_, domain)| {
            normalized_identifier.as_ref().is_some_and(|identifier| {
                identifier == domain || identifier == &format!("*.{domain}")
            }) || lower_message.contains(domain.as_str())
        }) {
            let wildcard_identifier = format!("*.{domain}");
            let certificate_type = if normalized_identifier.as_deref()
                == Some(wildcard_identifier.as_str())
                || lower_message.contains(&wildcard_identifier)
            {
                "wildcard"
            } else {
                "root"
            };
            let is_error = matches!(stage, "retry_wait" | "failed");
            connection.execute(
                "UPDATE public_domain_certificate_progress
                 SET stage = ?1,
                     attempt_count = attempt_count + CASE
                         WHEN ?1 IN ('waiting_configuration', 'presenting_dns') THEN 1 ELSE 0 END,
                     last_event_at = unixepoch(), next_retry_at = ?2,
                     error_code = CASE WHEN ?3 = 1 THEN ?4 ELSE NULL END,
                     error_message = CASE WHEN ?3 = 1 THEN ?5 ELSE NULL END,
                     updated_at = unixepoch()
                 WHERE public_domain_id = ?6 AND certificate_type = ?7",
                rusqlite::params![
                    stage,
                    retry_at,
                    i64::from(is_error),
                    if event.is_rate_limited() {
                        "acme_rate_limited"
                    } else {
                        "acme_failed"
                    },
                    truncate_error_message(&event.message),
                    id,
                    certificate_type,
                ],
            )?;
            if !is_error {
                continue;
            }
            let rate_limited = event.is_rate_limited();
            connection.execute(
                "UPDATE public_domains SET apply_status = ?1,
                 apply_error = ?2, error_code = ?3, retry_after = ?4,
                 next_retry_at = ?4, attempt_count = attempt_count + 1,
                 updated_at = unixepoch() WHERE id = ?5 AND tenant_id = ?6",
                rusqlite::params![
                    if rate_limited {
                        "rate_limited"
                    } else {
                        "retrying"
                    },
                    truncate_error_message(&event.message),
                    if rate_limited {
                        "acme_rate_limited"
                    } else {
                        "acme_failed"
                    },
                    retry_at,
                    id,
                    tenant_id,
                ],
            )?;
        }
    }
    prune_public_domain_runtime_events(&connection, &tenant_id)?;
    Ok(())
}

/// 把底层组件事件翻译为产品可理解的运行日志。原文仅作为脱敏后的技术详情
/// 保存，界面无需理解底层 logger 或组件名称也能判断下一步。
fn persist_public_domain_runtime_event(
    state: &AppState,
    connection: &Connection,
    tenant_id: &str,
    related_domain: Option<&(String, String)>,
    event: &caddy::CaddyLogEvent,
) -> Result<()> {
    let logger = event
        .logger
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let message = event.message.to_ascii_lowercase();
    let level = match event
        .level
        .as_deref()
        .unwrap_or("info")
        .to_ascii_lowercase()
        .as_str()
    {
        "error" => "error",
        "warn" | "warning" => "warning",
        "debug" => "debug",
        _ => "info",
    };
    let category = if logger.contains("reverse_proxy") || message.contains("upstream") {
        "reverse_proxy"
    } else if logger.contains("dns")
        || message.contains("cloudflare")
        || message.contains("propagation")
    {
        "dns_validation"
    } else if logger.contains("acme")
        || logger.contains("tls.obtain")
        || message.contains("certificate")
    {
        "automatic_certificate"
    } else if logger.contains("tls") || message.contains("handshake") {
        "https"
    } else if logger.contains("admin") || logger.contains("config") || message.contains("config") {
        "configuration"
    } else if logger.contains("storage") {
        "certificate_storage"
    } else {
        "service_runtime"
    };
    let stage = event.certificate_stage();
    let summary = match (category, stage) {
        (_, Some("retry_wait")) => "证书申请暂未完成，系统将按计划自动重试",
        (_, Some("presenting_dns")) => "正在创建证书校验所需的 DNS 记录",
        (_, Some("waiting_dns")) => "正在等待证书校验记录完成传播",
        (_, Some("validating")) => "证书颁发机构正在验证域名",
        (_, Some("issued")) => "证书已经签发",
        (_, Some("active")) => "证书已经加载并启用",
        ("reverse_proxy", _) => "反向代理暂时无法连接内部服务",
        ("configuration", _) if level == "error" => "域名服务配置应用失败",
        ("configuration", _) => "域名服务配置已经更新",
        ("certificate_storage", _) => "证书存储发生异常",
        ("https", _) => "HTTPS 连接发生异常",
        _ if level == "error" => "域名服务运行异常",
        _ => "域名服务运行状态已更新",
    };
    let retry_at = event
        .retry_after_secs
        .map(|seconds| unix_now().saturating_add(i64::try_from(seconds).unwrap_or(i64::MAX)));
    let technical_detail = redact_runtime_detail(state, &event.message);
    connection.execute(
        "INSERT INTO public_domain_runtime_events
         (tenant_id, public_domain_id, domain, level, category, stage, summary,
          error_code, retry_at, technical_detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            tenant_id,
            related_domain.map(|item| item.0.as_str()),
            related_domain.map(|item| item.1.as_str()),
            level,
            category,
            stage,
            summary,
            event.status_code.map(|code| format!("http_{code}")),
            retry_at,
            technical_detail,
        ],
    )?;
    Ok(())
}

fn redact_runtime_detail(state: &AppState, value: &str) -> String {
    let mut redacted = value.to_owned();
    let mut token_paths = Vec::new();
    let domain_root = state.data_dir.join("secrets").join("public-domains");
    if let Ok(entries) = fs::read_dir(domain_root) {
        token_paths.extend(
            entries
                .flatten()
                .map(|entry| entry.path().join("cloudflare.token")),
        );
    }
    for token in token_paths
        .into_iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
    {
        redacted = redacted.replace(&token, "[敏感信息已隐藏]");
    }
    let lower = redacted.to_ascii_lowercase();
    if [
        "authorization",
        "cookie",
        "api_token",
        "api token",
        "bearer ",
        "headscale key",
        "preauthkey",
        "begin certificate",
        "private key-----",
        "begin private key",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return "[敏感信息已隐藏]".to_owned();
    }
    // 技术详情仍面向最终用户，因此隐藏部署目录与底层实现名称。中文摘要和
    // 产品化分类已经保留了排障所需的上下文。
    for path in [
        state.data_dir.display().to_string(),
        state.data_dir.display().to_string().replace('\\', "/"),
    ] {
        if path.len() > 2 && path != "." {
            redacted = redacted.replace(&path, "[内部路径]");
        }
    }
    redacted = replace_ascii_case_insensitive(&redacted, "caddy", "域名服务");
    redacted = redacted
        .split_whitespace()
        .map(|part| {
            let unquoted = part.trim_matches(['\"', '\'', '(', ')', '[', ']', '{', '}', ',']);
            let bytes = unquoted.as_bytes();
            let windows_path =
                bytes.len() > 2 && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/');
            if unquoted.starts_with('/') || unquoted.starts_with("file://") || windows_path {
                "[内部路径]"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    truncate_error_message(&redacted)
}

fn replace_ascii_case_insensitive(value: &str, needle: &str, replacement: &str) -> String {
    let mut result = value.to_owned();
    loop {
        let lower = result.to_ascii_lowercase();
        let Some(index) = lower.find(needle) else {
            break;
        };
        result.replace_range(index..index + needle.len(), replacement);
    }
    result
}

fn prune_public_domain_runtime_events(connection: &Connection, tenant_id: &str) -> Result<()> {
    connection.execute(
        "DELETE FROM public_domain_runtime_events
         WHERE tenant_id = ?1 AND occurred_at < unixepoch() - 604800",
        [tenant_id],
    )?;
    let domain_ids = connection
        .prepare("SELECT id FROM public_domains WHERE tenant_id = ?1")?
        .query_map([tenant_id], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for domain_id in domain_ids {
        connection.execute(
            "DELETE FROM public_domain_runtime_events WHERE public_domain_id = ?1
             AND id NOT IN (SELECT id FROM public_domain_runtime_events
                 WHERE public_domain_id = ?1 ORDER BY occurred_at DESC, id DESC LIMIT 500)",
            [&domain_id],
        )?;
    }
    connection.execute(
        "DELETE FROM public_domain_runtime_events WHERE tenant_id = ?1 AND public_domain_id IS NULL
         AND id NOT IN (SELECT id FROM public_domain_runtime_events
             WHERE tenant_id = ?1 AND public_domain_id IS NULL
             ORDER BY occurred_at DESC, id DESC LIMIT 500)",
        [tenant_id],
    )?;
    Ok(())
}

/// 将 Caddy 配置应用结果投影到每个域名。429/Retry-After 由 Caddy 自己
/// 决定，这里只记录可读状态和一个保守的刷新时间，避免 UI 误导用户反复
/// 立即申请；真正的 ACME 退避仍完全交给 Caddy。
fn update_public_domain_apply_states(state: &AppState, error: Option<&str>) -> Result<()> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let tenant_id: String = connection
        .query_row(
            "SELECT tenant_id FROM public_domains WHERE is_primary = 1
             ORDER BY updated_at DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .context("无法读取公网域名租户")?;
    if let Some(error) = error {
        let lower = error.to_ascii_lowercase();
        let rate_limited = lower.contains("429")
            || lower.contains("rate limit")
            || lower.contains("too many certificates");
        let retry_after = rate_limited.then(|| unix_now().saturating_add(60 * 60));
        connection.execute(
            "UPDATE public_domains SET apply_status = ?1, apply_error = ?2,
             error_code = ?3, retry_after = ?4, next_retry_at = ?4,
             updated_at = unixepoch() WHERE tenant_id = ?5",
            rusqlite::params![
                if rate_limited {
                    "rate_limited"
                } else {
                    "error"
                },
                truncate_error_message(error),
                if rate_limited {
                    Some("acme_rate_limited")
                } else {
                    Some("caddy_apply_failed")
                },
                retry_after,
                tenant_id,
            ],
        )?;
        return Ok(());
    }
    connection.execute(
        "UPDATE public_domains SET apply_status = CASE
             WHEN https_enabled = 0 THEN 'ready'
             WHEN retry_after IS NOT NULL AND retry_after > unixepoch() THEN 'rate_limited'
             WHEN root_certificate_status = 'ready' AND wildcard_certificate_status = 'ready' THEN 'ready'
             WHEN apply_status = 'retrying' THEN 'retrying'
             ELSE 'configuring' END,
         apply_error = CASE WHEN root_certificate_status = 'ready'
             AND wildcard_certificate_status = 'ready' THEN NULL ELSE apply_error END,
         error_code = CASE WHEN root_certificate_status = 'ready'
             AND wildcard_certificate_status = 'ready' THEN NULL ELSE error_code END,
         applied_revision = desired_revision, updated_at = unixepoch()
         WHERE tenant_id = ?1",
        [&tenant_id],
    )?;
    Ok(())
}

/// 从 Caddy 持久化 storage 同步自动证书的公开元数据。
///
/// Caddy 的 ACME 维护器在后台签发和续期，Server 不另起重试器；每次
/// 配置协调时分别扫描根域名和泛域名叶子证书。Caddy 会为两类标识维护
/// 独立证书，不能要求一张证书同时包含两类 SAN。
fn sync_caddy_certificate_metadata(state: &AppState) -> Result<()> {
    let domains = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut statement = connection.prepare(
            "SELECT id, domain FROM public_domains
             WHERE https_enabled = 1 AND certificate_mode = 'cloudflare'",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let now = unix_now();
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    for (id, domain) in domains {
        let root = find_caddy_certificate_metadata(&state.data_dir, &domain);
        let wildcard = find_caddy_certificate_metadata(&state.data_dir, &format!("*.{domain}"));
        let status = |metadata: &Option<CertificateMetadata>| {
            if metadata
                .as_ref()
                .is_some_and(|item| item.not_before <= now && item.not_after > now)
            {
                "ready"
            } else if metadata.as_ref().is_some_and(|item| item.not_after <= now) {
                "expired"
            } else {
                "pending"
            }
        };
        let root_status = status(&root);
        let wildcard_status = status(&wildcard);
        let metadata_fields = |metadata: &Option<CertificateMetadata>| {
            (
                metadata.as_ref().map(|item| item.not_before),
                metadata.as_ref().map(|item| item.not_after),
                metadata
                    .as_ref()
                    .and_then(|item| serde_json::to_string(&item.subjects).ok())
                    .unwrap_or_else(|| "[]".to_owned()),
            )
        };
        let (root_not_before, root_not_after, root_subjects) = metadata_fields(&root);
        let (wildcard_not_before, wildcard_not_after, wildcard_subjects) =
            metadata_fields(&wildcard);
        let all_ready = root_status == "ready" && wildcard_status == "ready";
        connection.execute(
            "UPDATE public_domains SET
             root_certificate_status = ?1, wildcard_certificate_status = ?2,
             root_certificate_not_before = ?3, root_certificate_not_after = ?4,
             root_certificate_subjects_json = ?5,
             wildcard_certificate_not_before = ?6, wildcard_certificate_not_after = ?7,
             wildcard_certificate_subjects_json = ?8,
             apply_status = CASE WHEN ?9 = 1 THEN 'ready'
                 WHEN retry_after IS NOT NULL AND retry_after > unixepoch() THEN 'rate_limited'
                 ELSE 'retrying' END,
             apply_error = CASE WHEN ?9 = 1 THEN NULL
                 ELSE COALESCE(apply_error, '根域名或泛域名证书尚未签发，Caddy 将自动重试') END,
             error_code = CASE WHEN ?9 = 1 THEN NULL
                 ELSE COALESCE(error_code, 'certificate_pending') END,
             updated_at = unixepoch() WHERE id = ?10",
            rusqlite::params![
                root_status,
                wildcard_status,
                root_not_before,
                root_not_after,
                root_subjects,
                wildcard_not_before,
                wildcard_not_after,
                wildcard_subjects,
                i64::from(all_ready),
                id,
            ],
        )?;
        for (certificate_type, certificate_status) in
            [("root", root_status), ("wildcard", wildcard_status)]
        {
            connection.execute(
                "UPDATE public_domain_certificate_progress
                 SET stage = CASE WHEN ?1 = 'ready' THEN 'active'
                         WHEN ?1 = 'expired' THEN 'retry_wait'
                         WHEN stage IN ('active', 'issued') THEN 'waiting_configuration'
                         ELSE stage END,
                     last_event_at = CASE WHEN ?1 = 'ready' THEN unixepoch() ELSE last_event_at END,
                     error_code = CASE WHEN ?1 = 'ready' THEN NULL ELSE error_code END,
                     error_message = CASE WHEN ?1 = 'ready' THEN NULL ELSE error_message END,
                     updated_at = unixepoch()
                 WHERE public_domain_id = ?2 AND certificate_type = ?3",
                rusqlite::params![certificate_status, id, certificate_type],
            )?;
        }
    }
    Ok(())
}

async fn public_certificate_material_ready(state: &AppState, entry: &PrimaryDomainStatus) -> bool {
    let primary = state.db.lock().ok().and_then(|connection| {
        connection
            .query_row(
                "SELECT id, domain, https_enabled, certificate_mode,
                        root_certificate_not_after
                 FROM public_domains WHERE is_primary = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)? != 0,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten()
    });
    let Some((id, domain, https_enabled, mode, not_after)) = primary else {
        return !entry.https_enabled;
    };
    if !https_enabled {
        return true;
    }
    let secret_dir = domain_secret_dir(state, &id);
    match mode.as_str() {
        "manual" => {
            secret_dir.join("certificate.pem").is_file()
                && secret_dir.join("private-key.pem").is_file()
                && not_after.is_some_and(|timestamp| timestamp > unix_now())
        }
        // Cloudflare 模式的证书由 Caddy 异步申请；只有实际完成一次
        // HTTPS 握手后才进入 READY，避免“Token 文件存在”被误报为证书已签发。
        "cloudflare" => {
            secret_dir.join("cloudflare.token").is_file() && probe_public_https(&domain).await
        }
        _ => false,
    }
}

/// 生成本机 Caddy 证书探测目标。
///
/// 公网域名可能经过 Cloudflare 代理，直接按公网 DNS 访问只能证明边缘节点
/// 提供了证书，不能证明当前 Nexo 实例已经完成签发。因此连接地址必须固定为
/// Server 回环地址，同时保留公网主机名用于 HTTP Host 和 TLS SNI。
fn public_https_probe_target(domain: &str) -> (String, String, SocketAddr) {
    let host = format!("nexo.{domain}");
    let url = format!("https://{host}/api/v1/auth/status");
    (host, url, SocketAddr::from(([127, 0, 0, 1], 443)))
}

/// 仅用于判断本机 Caddy 是否已经实际提供 HTTPS 证书；请求不会携带管理凭据。
/// Staging 证书可能不受系统 CA 信任，因此这里允许无效证书，但不改变
/// Caddy 对外的证书校验策略。
async fn probe_public_https(domain: &str) -> bool {
    let (host, url, address) = public_https_probe_target(domain);
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, address)
        .build()
    else {
        return false;
    };
    client
        .get(url)
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

fn truncate_error_message(message: &str) -> String {
    const MAX: usize = 512;
    let message = message.trim();
    if message.len() <= MAX {
        message.to_owned()
    } else {
        message[..MAX].to_owned()
    }
}

/// 解析并校验证书链的第一张叶子证书，确保它未过期且私钥确实匹配。
///
/// 公网入口还要求证书同时覆盖根域名和泛域名。这里只保存可公开展示的
/// 时间与 SAN 元数据，证书正文和私钥仍由调用方写入 0600 Secret 文件。
fn validate_certificate_pair_for_domain(
    certificate: &str,
    private_key: &str,
    expected_domain: Option<&str>,
) -> Result<CertificateMetadata, ApiError> {
    let metadata = parse_certificate_metadata(certificate, true)?;
    if private_key.contains("BEGIN ENCRYPTED PRIVATE KEY") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "暂不支持带密码的私钥，请提供未加密的 PEM 私钥",
        ));
    }
    let certificate_chain = pem_certificates(certificate).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "证书格式无效，请提供完整的 PEM 证书链",
        )
    })?;
    let private_key = pem_private_key(private_key).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "私钥格式无效，支持未加密的 PKCS#1、PKCS#8 或 SEC1 PEM 私钥",
        )
    })?;
    // Rustls 与实际 HTTPS 服务使用同一套密钥解析和匹配校验，可接受 Caddy
    // 支持的常见 PEM 私钥格式，也避免只靠算法特定公钥字节比较造成误判。
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificate_chain, private_key)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "证书与私钥不匹配"))?;
    if let Some(domain) = expected_domain {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let wildcard = format!("*.{domain}");
        if !metadata.subjects.iter().any(|subject| subject == &domain)
            || !metadata.subjects.iter().any(|subject| subject == &wildcard)
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "证书必须同时覆盖根域名和泛域名",
            ));
        }
    }
    Ok(metadata)
}

/// 读取证书公开元数据。自动申请的证书没有私钥可供 Server 校验，
/// 因此这里只解析 Caddy storage 中的叶子证书，并由调用方检查 SAN。
fn parse_certificate_metadata(
    certificate: &str,
    require_valid: bool,
) -> Result<CertificateMetadata, ApiError> {
    let (_, pem) = parse_x509_pem(certificate.as_bytes()).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "证书格式无效，请提供 PEM X.509 证书",
        )
    })?;
    if pem.label != "CERTIFICATE" {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "证书格式无效"));
    }
    let parsed = pem
        .parse_x509()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "证书内容无法解析"))?;
    if require_valid && !parsed.validity().is_valid() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "证书已经过期或尚未生效",
        ));
    }
    let subjects = parsed
        .subject_alternative_name()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "证书域名扩展无效"))?
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(value) => Some(value.to_ascii_lowercase()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(CertificateMetadata {
        not_before: parsed.validity().not_before.timestamp(),
        not_after: parsed.validity().not_after.timestamp(),
        subjects,
    })
}

/// 从 Caddy file_system storage 找到覆盖根域名与泛域名的最新证书。
/// Caddy 的目录布局由发行版维护，因此不依赖固定的文件名，只读取
/// `.crt`/`.pem` 文件并以 SAN 判断归属；找不到时保留原有状态。
fn find_caddy_certificate_metadata(
    data_dir: &FsPath,
    identifier: &str,
) -> Option<CertificateMetadata> {
    let mut pending = vec![data_dir.join("caddy-storage")];
    let mut latest = None;
    let identifier = identifier.trim().trim_end_matches('.').to_ascii_lowercase();
    while let Some(path) = pending.pop() {
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                if entry_path
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .contains("staging")
                {
                    continue;
                }
                pending.push(entry_path);
                continue;
            }
            let is_certificate = entry_path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    matches!(extension.to_ascii_lowercase().as_str(), "crt" | "pem")
                });
            if !is_certificate {
                continue;
            }
            let Ok(contents) = fs::read_to_string(&entry_path) else {
                continue;
            };
            let Ok(metadata) = parse_certificate_metadata(&contents, false) else {
                continue;
            };
            if metadata
                .subjects
                .iter()
                .any(|subject| subject == &identifier)
            {
                let replace = latest.as_ref().is_none_or(|current: &CertificateMetadata| {
                    metadata.not_after > current.not_after
                });
                if replace {
                    latest = Some(metadata);
                }
            }
        }
    }
    latest
}

/// 覆盖 Secret 前保存的本地快照。
///
/// Secret 文件和 SQLite 更新不是同一个事务；请求后续步骤失败时，
/// 该守卫在离开作用域时恢复原内容，避免数据库指向一份不存在或半写入
/// 的凭据。恢复失败只记录中文诊断，不把 Secret 内容写入日志。
struct SecretFileRollback {
    path: PathBuf,
    previous: Option<Vec<u8>>,
    committed: bool,
}

impl SecretFileRollback {
    fn capture(path: &std::path::Path) -> Self {
        Self {
            path: path.to_path_buf(),
            previous: fs::read(path).ok(),
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for SecretFileRollback {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        match self.previous.as_deref() {
            Some(previous) => {
                if let Err(error) = write_secret_bytes(&self.path, previous) {
                    tracing::error!(
                        path = %self.path.display(),
                        "Secret 回滚失败，需人工检查凭据文件：{error}"
                    );
                }
            }
            None => {
                if let Err(error) = fs::remove_file(&self.path) {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        tracing::error!(
                            path = %self.path.display(),
                            "无法清理失败请求留下的 Secret：{error}"
                        );
                    }
                }
            }
        }
    }
}

fn capture_secret_rollback(rollbacks: &mut Vec<SecretFileRollback>, path: &std::path::Path) {
    if !rollbacks.iter().any(|rollback| rollback.path == path) {
        rollbacks.push(SecretFileRollback::capture(path));
    }
}

fn write_secret_bytes(path: &std::path::Path, value: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Secret 路径无效"))?;
    fs::create_dir_all(parent)?;
    set_secret_directory_permissions(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    if let Err(error) = fs::write(&temporary, value) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    #[cfg(unix)]
    if let Err(error) = {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
    } {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

/// Secret 目录只允许 Nexo 进程所属用户访问；文件本身由上面的原子写入
/// 固定为 0600。Windows 沿用 NTFS ACL，不在这里伪造 Unix 权限位。
fn set_secret_directory_permissions(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn write_secret_file(path: &std::path::Path, value: &str) -> Result<(), ApiError> {
    if value.trim().is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Secret 不能为空"));
    }
    write_secret_bytes(path, value.as_bytes()).map_err(|error| {
        let message = match error.kind() {
            std::io::ErrorKind::PermissionDenied => "无法设置或写入 Secret 文件",
            std::io::ErrorKind::NotFound => "无法创建 Secret 目录",
            _ => "无法原子替换 Secret 文件",
        };
        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    })
}

/// 返回设备状态和最近一次网关能力报告，供 Web 展示统一的设备模型。
async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceResponse>>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    list_devices_for_tenant(&connection, &tenant_id).map(Json)
}

fn list_devices_for_tenant(
    connection: &Connection,
    tenant_id: &str,
) -> Result<Vec<DeviceResponse>, ApiError> {
    let mut statement = connection
        .prepare(
            "SELECT d.id, d.tenant_id, d.site_id, d.name, d.os, d.architecture,
                    d.agent_version, d.status, d.capabilities_json, r.report_json,
                    m.state, m.tailscale_ipv4, m.online, unixepoch(d.last_seen_at),
                    (SELECT a.state FROM mesh_enrollment_attempts a
                     WHERE a.nexo_device_id = d.id
                     ORDER BY a.created_at DESC LIMIT 1)
                    ,(SELECT COUNT(*) FROM tunnels t
                      WHERE t.device_id = d.id AND t.deleted_at IS NULL),
                    tm.user_id, tm.registration_method, tm.tags_json,
                    tm.tailscale_ipv4, tm.tailscale_ipv6, tm.expires_at,
                    tm.control_plane_state,
                    (SELECT u.username FROM users u WHERE u.id = tm.user_id)
             FROM devices d
             LEFT JOIN device_capability_reports r ON r.device_id = d.id
             LEFT JOIN mesh_identities m ON m.nexo_device_id = d.id
             LEFT JOIN tailscale_device_metadata tm ON tm.device_id = d.id
             WHERE d.tenant_id = ?1
             ORDER BY d.updated_at DESC, d.name ASC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备列表"))?;
    let rows = statement
        .query_map([tenant_id], device_response_from_row)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备列表"))?;
    rows.map(|row| {
        row.map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "设备数据格式无效，请让 Agent 重新连接",
            )
        })
    })
    .collect::<Result<Vec<_>, _>>()
}

fn device_response_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceResponse> {
    let capabilities_json: String = row.get(8)?;
    let report_json: Option<String> = row.get(9)?;
    let mesh_state: Option<String> = row.get(10)?;
    let mesh_online = row.get::<_, Option<i64>>(12)?.unwrap_or_default() != 0;
    let enrollment_state: Option<String> = row.get(14)?;
    let device_status: String = row.get(7)?;
    let owner_user_id: Option<String> = row.get(16)?;
    let registration_method: Option<String> = row.get(17)?;
    let tags_json: String = row
        .get::<_, Option<String>>(18)?
        .unwrap_or_else(|| "[]".to_owned());
    Ok(DeviceResponse {
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
        connection_type: if registration_method.is_some() {
            "tailscale_client".to_owned()
        } else {
            "nexo_agent".to_owned()
        },
        owner_user_id,
        owner_username: row.get(23)?,
        registration_method,
        tags: serde_json::from_str(&tags_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                18,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        tailscale_ipv4: row
            .get::<_, Option<String>>(19)?
            .or(row.get::<_, Option<String>>(11)?),
        tailscale_ipv6: row.get(20)?,
        expires_at: row.get(21)?,
        control_plane_state: row.get(22)?,
        last_seen_at: row.get(13)?,
        tunnel_count: row.get(15)?,
    })
}

/// 返回站点目录，供 Web 创建共享网络和站点互联时选择站点。
async fn list_sites(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SiteResponse>>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT id, tenant_id, name
             FROM sites
             WHERE tenant_id = ?1
             ORDER BY name ASC, id ASC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点列表"))?;
    let rows = statement
        .query_map([tenant_id], |row| {
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
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
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
    ensure_tenant_scope(&tenant_id, &session_tenant)?;
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

/// 更新设备的用户可见资料；组网身份名称与设备名称保持同一套稳定规则。
async fn update_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateDeviceRequest>,
) -> Result<Json<DeviceResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let name = request.name.trim().to_owned();
    if name.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "设备名称不能为空"));
    }
    let site_id = request
        .site_id
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    let (old_name, old_site_id, node_id) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let current = connection
            .query_row(
                "SELECT d.name, d.site_id, m.headscale_node_id
                 FROM devices d
                 LEFT JOIN mesh_identities m ON m.nexo_device_id = d.id
                 WHERE d.id = ?1 AND d.tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备资料"))?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "设备不存在"))?;

        if let Some(target_site_id) = site_id.as_deref() {
            let exists: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sites WHERE id = ?1 AND tenant_id = ?2",
                    rusqlite::params![target_site_id, tenant_id],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查目标站点")
                })?;
            if exists == 0 {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "目标站点不存在"));
            }
        }
        if current.1 != site_id {
            let has_network: i64 = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM site_networks WHERE publisher_device_id = ?1)",
                    [&id],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查设备共享网络")
                })?;
            let is_gateway: i64 = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sites WHERE active_site_gateway_device_id = ?1)",
                    [&id],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查设备站点网关")
                })?;
            if has_network != 0 || is_gateway != 0 {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "设备正在承载共享网络或站点网关，暂不能更换所属站点，请先解除相关配置",
                ));
            }
        }
        (current.0, current.1, current.2)
    };

    let renamed_node = if old_name != name {
        if let Some(node_id) = node_id.as_deref() {
            let hostname = mesh_hostname(&tenant_id, &name, &id);
            state
                .headscale
                .rename_node(node_id, &hostname)
                .await
                .map_err(|error| {
                    tracing::warn!(device_id = %id, headscale_node_id = %node_id, "无法同步设备组网访问名：{error:#}");
                    ApiError::new(
                        StatusCode::BAD_GATEWAY,
                        "暂时无法同步设备组网访问名，设备资料尚未修改，请稍后重试",
                    )
                })?;
            Some(hostname)
        } else {
            None
        }
    } else {
        None
    };

    {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始设备编辑事务")
        })?;
        let current: Option<(String, Option<String>)> = transaction
            .query_row(
                "SELECT name, site_id FROM devices WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法复核设备资料"))?;
        let Some((current_name, current_site)) = current else {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "设备不存在"));
        };
        if current_name != old_name || current_site != old_site_id {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "设备资料在编辑期间发生变化，请刷新后重试",
            ));
        }
        if current_site != site_id {
            let has_network: i64 = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM site_networks WHERE publisher_device_id = ?1)",
                    [&id],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法复核设备共享网络")
                })?;
            let is_gateway: i64 = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sites WHERE active_site_gateway_device_id = ?1)",
                    [&id],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法复核设备站点网关")
                })?;
            if has_network != 0 || is_gateway != 0 {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "设备正在承载共享网络或站点网关，暂不能更换所属站点，请先解除相关配置",
                ));
            }
        }
        let changed = transaction
            .execute(
                "UPDATE devices SET name = ?1, site_id = ?2, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?3 AND tenant_id = ?4",
                rusqlite::params![name, site_id, id, tenant_id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新设备资料"))?;
        if changed != 1 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "设备不存在"));
        }
        if let Some(hostname) = renamed_node.as_ref() {
            transaction
                .execute(
                    "UPDATE mesh_identities SET hostname = ?1, updated_at = CURRENT_TIMESTAMP
                     WHERE nexo_device_id = ?2",
                    rusqlite::params![hostname, id],
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存设备组网访问名")
                })?;
        }
        write_audit_event(&transaction, &tenant_id, "DEVICE_UPDATED", "device", &id)?;
        transaction.commit().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交设备编辑事务")
        })?;
    }

    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            "SELECT d.id, d.tenant_id, d.site_id, d.name, d.os, d.architecture,
                    d.agent_version, d.status, d.capabilities_json, r.report_json,
                    m.state, m.tailscale_ipv4, m.online, unixepoch(d.last_seen_at),
                    (SELECT a.state FROM mesh_enrollment_attempts a
                     WHERE a.nexo_device_id = d.id
                     ORDER BY a.created_at DESC LIMIT 1),
                    (SELECT COUNT(*) FROM tunnels t
                     WHERE t.device_id = d.id AND t.deleted_at IS NULL),
                     tm.user_id, tm.registration_method, tm.tags_json,
                     tm.tailscale_ipv4, tm.tailscale_ipv6, tm.expires_at,
                     tm.control_plane_state,
                     (SELECT u.username FROM users u WHERE u.id = tm.user_id)
             FROM devices d
             LEFT JOIN device_capability_reports r ON r.device_id = d.id
             LEFT JOIN mesh_identities m ON m.nexo_device_id = d.id
             LEFT JOIN tailscale_device_metadata tm ON tm.device_id = d.id
             WHERE d.id = ?1 AND d.tenant_id = ?2",
            rusqlite::params![id, tenant_id],
            device_response_from_row,
        )
        .map(Json)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "设备不存在"))
}

/// 删除空站点；设备和网络拓扑属于显式业务资源，存在任一依赖时都拒绝级联。
async fn delete_site(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始站点删除事务"))?;
    let (name, device_count, network_count, link_count): (String, i64, i64, i64) = transaction
        .query_row(
            "SELECT s.name,
                        (SELECT COUNT(*) FROM devices d WHERE d.site_id = s.id),
                        (SELECT COUNT(*) FROM site_networks n WHERE n.site_id = s.id),
                        (SELECT COUNT(*) FROM site_links l
                         WHERE l.left_site_id = s.id OR l.right_site_id = s.id)
                 FROM sites s WHERE s.id = ?1 AND s.tenant_id = ?2",
            rusqlite::params![id, tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查站点依赖"))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "站点不存在"))?;
    if let Some(message) = delete_dependency_message(
        "站点",
        &[
            ("台设备", device_count),
            ("个共享网络", network_count),
            ("个互联关系", link_count),
        ],
    ) {
        tracing::warn!(site_id = %id, "拒绝删除站点：{message}");
        return Err(ApiError::new(StatusCode::CONFLICT, message));
    }
    // 未完成的入网请求只是站点内部凭证，不应让一个已经没有业务资源的站点
    // 永久无法删除；随站点删除一并作废，旧 token 此后无法再换取设备证书。
    transaction
        .execute("DELETE FROM pending_enrollments WHERE site_id = ?1", [&id])
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法作废站点入网请求"))?;
    write_audit_event(&transaction, &tenant_id, "SITE_DELETED", "site", &id)?;
    transaction
        .execute(
            "DELETE FROM sites WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![id, tenant_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法删除站点"))?;
    transaction
        .commit()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交站点删除事务"))?;
    tracing::info!(site_id = %id, site_name = %name, "站点已删除");
    Ok(Json(DeleteResponse {
        deleted: true,
        pending: false,
        id,
        message: "站点已删除".to_owned(),
    }))
}

/// 删除设备前先撤销 Headscale 凭证和节点，再清理本地身份链。
///
/// 外部撤销失败时保留本地记录，避免管理界面声称设备已删除但旧节点仍可继续
/// 参与组网。Tunnel 会保留为未分配并关闭；共享网络和活动站点网关仍需
/// 先解除，避免删除设备后留下不可解释的网关拓扑。
async fn delete_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let (name, node_id, pre_auth_key_ids, tunnel_ids) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let (name, node_id, network_count, gateway_count): (String, Option<String>, i64, i64) =
            connection
                .query_row(
                    "SELECT d.name, m.headscale_node_id,
                        (SELECT COUNT(*) FROM site_networks n
                         WHERE n.publisher_device_id = d.id),
                        (SELECT COUNT(*) FROM sites s
                         WHERE s.active_site_gateway_device_id = d.id)
                 FROM devices d
                 LEFT JOIN mesh_identities m ON m.nexo_device_id = d.id
                 WHERE d.id = ?1 AND d.tenant_id = ?2",
                    rusqlite::params![id, tenant_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查设备依赖"))?
                .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "设备不存在"))?;
        if let Some(message) = delete_dependency_message(
            "设备",
            &[
                ("个共享网络", network_count),
                ("个活动站点网关", gateway_count),
            ],
        ) {
            tracing::warn!(device_id = %id, "拒绝删除设备：{message}");
            return Err(ApiError::new(StatusCode::CONFLICT, message));
        }
        let mut statement = connection
            .prepare(
                "SELECT headscale_pre_auth_key_id FROM mesh_enrollment_attempts
                 WHERE nexo_device_id = ?1 AND state = 'issued'",
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备入网密钥")
            })?;
        let pre_auth_key_ids = statement
            .query_map([&id], |row| row.get::<_, String>(0))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备入网密钥"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "设备入网密钥数据无效")
            })?;
        let mut tunnel_statement = connection
            .prepare(
                "SELECT id FROM tunnels
                 WHERE device_id = ?1 AND deleted_at IS NULL",
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备穿透服务")
            })?;
        let tunnel_ids = tunnel_statement
            .query_map([&id], |row| row.get::<_, String>(0))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取设备穿透服务"))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "设备穿透服务数据无效")
            })?;
        (name, node_id, pre_auth_key_ids, tunnel_ids)
    };

    for key_id in &pre_auth_key_ids {
        state.headscale.expire_pre_auth_key(key_id).await.map_err(|error| {
            tracing::warn!(device_id = %id, key_id = %key_id, "无法吊销设备入网密钥：{error:#}");
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "暂时无法吊销设备入网密钥，设备尚未删除，请稍后重试",
            )
        })?;
    }
    if let Some(node_id) = node_id.as_deref() {
        state.headscale.delete_node(node_id).await.map_err(|error| {
            tracing::warn!(device_id = %id, headscale_node_id = %node_id, "无法删除设备组网节点：{error:#}");
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "暂时无法删除设备组网节点，设备尚未删除，请稍后重试",
            )
        })?;
    }

    {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始设备删除事务")
        })?;
        let network_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM site_networks WHERE publisher_device_id = ?1",
                [&id],
                |row| row.get(0),
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法复核设备依赖"))?;
        let gateway_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM sites WHERE active_site_gateway_device_id = ?1",
                [&id],
                |row| row.get(0),
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法复核设备站点网关")
            })?;
        if let Some(message) = delete_dependency_message(
            "设备",
            &[
                ("个共享网络", network_count),
                ("个活动站点网关", gateway_count),
            ],
        ) {
            tracing::warn!(device_id = %id, "复核时拒绝删除设备：{message}");
            return Err(ApiError::new(StatusCode::CONFLICT, message));
        }
        let exists: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM devices WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| row.get(0),
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法复核设备"))?;
        if exists == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "设备不存在"));
        }
        for (sql, message) in [
            (
                "DELETE FROM gateway_route_applies WHERE device_id = ?1",
                "无法清理设备路由状态",
            ),
            (
                "DELETE FROM device_capability_reports WHERE device_id = ?1",
                "无法清理设备能力报告",
            ),
            (
                "DELETE FROM mesh_enrollment_attempts WHERE nexo_device_id = ?1",
                "无法清理设备组网入网记录",
            ),
            (
                "DELETE FROM mesh_identities WHERE nexo_device_id = ?1",
                "无法清理设备组网身份",
            ),
            (
                "DELETE FROM device_identities WHERE device_id = ?1",
                "无法撤销设备证书",
            ),
            (
                "DELETE FROM pending_enrollments WHERE device_id = ?1",
                "无法清理设备入网请求",
            ),
        ] {
            transaction
                .execute(sql, [&id])
                .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, message))?;
        }
        // 设备删除不再丢弃 Tunnel 配置；先关闭并解除归属，用户可稍后重新分配设备。
        for tunnel_id in &tunnel_ids {
            transaction
                .execute(
                    "UPDATE tunnels SET device_id = NULL, enabled = 0,
                     apply_status = 'disabled', apply_error = '设备已删除，请重新分配设备',
                     deletion_requested = 0, deletion_revision = NULL,
                     apply_revision = apply_revision + 1, updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?1 AND device_id = ?2 AND deleted_at IS NULL",
                    rusqlite::params![tunnel_id, id],
                )
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "无法解除设备与穿透服务的关联",
                    )
                })?;
            transaction
                .execute(
                    "UPDATE tunnel_applied_states
                     SET apply_status = 'disabled',
                         apply_error = '设备已删除，请重新分配设备',
                         updated_at = unixepoch()
                     WHERE tunnel_id = ?1",
                    [tunnel_id],
                )
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "无法更新穿透服务应用状态",
                    )
                })?;
            write_audit_event(
                &transaction,
                &tenant_id,
                "TUNNEL_UNASSIGNED",
                "tunnel",
                tunnel_id,
            )?;
        }
        refresh_site_link_apply_status(&transaction).map_err(|error| {
            tracing::error!(device_id = %id, "删除设备时刷新互联状态失败：{error:#}");
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法刷新站点互联状态")
        })?;
        write_audit_event(&transaction, &tenant_id, "DEVICE_DELETED", "device", &id)?;
        transaction
            .execute(
                "DELETE FROM devices WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法删除设备"))?;
        transaction.commit().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交设备删除事务")
        })?;
    }
    state.mesh_offers.lock().await.remove(&id);
    if let Some(session) = state.tunnel_sessions.lock().await.remove(&id) {
        session.cancel.cancel();
    }
    for tunnel_id in &tunnel_ids {
        stop_public_tunnel_listener(&state, tunnel_id);
        stop_active_tunnel_connections(&state, tunnel_id);
    }
    if !tunnel_ids.is_empty() {
        reconcile_caddy_config_best_effort(&state).await;
    }
    tracing::info!(device_id = %id, device_name = %name, "设备身份与本地记录已删除");
    Ok(Json(DeleteResponse {
        deleted: true,
        pending: false,
        id,
        message: if tunnel_ids.is_empty() {
            "设备已删除，原 Agent 需要重新入网才能连接".to_owned()
        } else {
            format!(
                "设备已删除，{} 个穿透服务已保留为未分配并关闭；原 Agent 需要重新入网才能连接",
                tunnel_ids.len()
            )
        },
    }))
}

fn delete_dependency_message(subject: &str, dependencies: &[(&str, i64)]) -> Option<String> {
    let details = dependencies
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(label, count)| format!("{count} {label}"))
        .collect::<Vec<_>>();
    (!details.is_empty()).then(|| {
        format!(
            "{subject}仍关联{}，请按互联关系、共享网络、穿透服务的顺序先完成删除",
            details.join("、")
        )
    })
}

fn count_for_tenant(
    connection: &Connection,
    query: &str,
    tenant_id: &str,
) -> Result<i64, StatusCode> {
    connection
        .query_row(query, [tenant_id], |row| row.get(0))
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

/// 构建 Caddy 回源专用的服务端 TLS 配置。
///
/// 这个 listener 只用于本机 loopback，故不要求客户端证书；设备控制通道仍
/// 使用上面的 mTLS 配置。两者共享同一张稳定的服务端证书，避免额外生成和
/// 持久化第二套身份材料。
fn build_public_backend_tls_config(connection: &Connection) -> Result<Arc<rustls::ServerConfig>> {
    let server = load_server_control_identity(connection)?;
    let certificate_chain = pem_certificates(&server.certificate_pem)?;
    let private_key = pem_private_key(&server.private_key_pem)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
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
        | AgentControlMessage::GatewayRouteApplyReport { .. }
        | AgentControlMessage::TunnelApplyReport { .. } => {
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
    let runtime_mesh_allowed = mesh_application_allowed(&state).await;
    let gateway_state = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        load_gateway_desired_state_with_mesh_allowed(&connection, &device_id, runtime_mesh_allowed)?
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
                "tunnel_desired_state".to_owned(),
            ],
            tunnels: load_tunnel_desired_state(&state, &device_id)?,
            tunnel_endpoint: tunnel_endpoint_from_env(),
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
                let runtime_mesh_allowed = mesh_application_allowed(&state).await;
                let gateway_state = {
                    let connection = state
                        .db
                        .lock()
                        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                    load_gateway_desired_state_with_mesh_allowed(
                        &connection,
                        &device_id,
                        runtime_mesh_allowed,
                    )?
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
                            "tunnel_desired_state".to_owned(),
                        ],
                        tunnels: load_tunnel_desired_state(&state, &device_id)?,
                        tunnel_endpoint: tunnel_endpoint_from_env(),
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
                // Agent 已经执行成功时，Node 绑定仍必须由 Server 通过
                // Pre-auth Key 从 Headscale 交叉解析。Headscale 暂时不可用或
                // 尚未完成落库都属于可重试状态，不能让一次 API 错误打掉 mTLS
                // 控制连接；下一次心跳/后台协调会继续使用同一把 Key 检查。
                let resolved_node_id = if success {
                    match state
                        .headscale
                        .find_node_by_pre_auth_key(&auth_key_id)
                        .await
                    {
                        Ok(Some(node)) => Some(node.id),
                        Ok(None) => {
                            let message = "Headscale 尚未返回该入网密钥对应的节点";
                            tracing::warn!(device_id = %device_id, auth_key_id = %auth_key_id, "{message}");
                            record_mesh_enrollment_retry(
                                &state,
                                &device_id,
                                &auth_key_id,
                                message,
                            )?;
                            None
                        }
                        Err(error) => {
                            let message =
                                format!("Headscale 暂时不可用，组网入网将在后台重试：{error:#}");
                            tracing::warn!(device_id = %device_id, "{message}");
                            record_mesh_enrollment_retry(
                                &state,
                                &device_id,
                                &auth_key_id,
                                &message,
                            )?;
                            None
                        }
                    }
                } else {
                    None
                };
                let binding_pending = success && resolved_node_id.is_none();
                if !binding_pending {
                    record_mesh_enrollment_ack(
                        &state,
                        &device_id,
                        &auth_key_id,
                        success,
                        identity.as_ref(),
                        error_message.as_deref(),
                        resolved_node_id.as_deref(),
                    )?;
                }
                record_public_domain_migration_ack(
                    &state,
                    &device_id,
                    success,
                    error_message.as_deref(),
                )?;
                // 无论绑定是否已完成都移除当前内存邀请。成功但 Headscale
                // 尚未可查询时，下一次心跳会检查同一把已消费 Key；保留邀请
                // 会让 Agent 重复执行 Tailscale up，反而把可恢复状态变成失败。
                state.mesh_offers.lock().await.remove(&device_id);
                // 入网 ACK 仍然占用同一条控制连接。这里必须返回当前完整
                // Desired State，不能用空的 HeartbeatAck 覆盖 Agent 已保存的
                // Tunnel 列表；空列表只有在数据库确实没有 Tunnel 时才有意义。
                let runtime_mesh_allowed = mesh_application_allowed(&state).await;
                let gateway_state = {
                    let connection = state
                        .db
                        .lock()
                        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                    load_gateway_desired_state_with_mesh_allowed(
                        &connection,
                        &device_id,
                        runtime_mesh_allowed,
                    )?
                };
                write_control_message(
                    reader.get_mut(),
                    &ServerControlMessage::HeartbeatAck {
                        server_time: unix_now(),
                        gateway_state,
                        mesh_enrollment: None,
                        protocol_features: vec![
                            "mesh_enrollment".to_owned(),
                            "gateway_route_report".to_owned(),
                            "tunnel_desired_state".to_owned(),
                        ],
                        tunnels: load_tunnel_desired_state(&state, &device_id)?,
                        tunnel_endpoint: tunnel_endpoint_from_env(),
                    },
                )
                .await?;
            }
            AgentControlMessage::GatewayRouteApplyReport { report } => {
                apply_gateway_route_report(&state, &device_id, &report)?;
                // 启用路由必须由 Agent 明确确认成功或失败；成功前缀可以独立
                // 批准，失败前缀则从 Nexo 所有的批准列表撤销。没有结果的旧
                // Agent 报告仍不能触发任何新的 Headscale 变更。
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
                        "逐路由报告尚未给出可收敛的本地结果，暂不触发 Headscale 变更"
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
            AgentControlMessage::TunnelApplyReport { results } => {
                apply_tunnel_results(&state, &device_id, &results)?;
                let readiness_state = state.clone();
                let readiness_device_id = device_id.clone();
                tokio::spawn(async move {
                    refresh_tunnel_readiness(&readiness_state, &readiness_device_id).await;
                });
                write_control_message(
                    reader.get_mut(),
                    &ServerControlMessage::TunnelApplyAccepted {
                        tunnel_ids: results.into_iter().map(|result| result.tunnel_id).collect(),
                    },
                )
                .await?;
            }
            AgentControlMessage::Heartbeat { .. } => anyhow::bail!("心跳 device_id 与证书不匹配"),
            AgentControlMessage::Hello { .. } => anyhow::bail!("控制通道不能重复发送身份声明"),
        }
        line.clear();
    }
    {
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
    }
    // 控制面离线后立即重新汇总公网入口；即使数据面连接还未结束，
    // Tunnel 也不能继续保持 READY 或接受新的公网逻辑流。
    refresh_tunnel_readiness(&state, &device_id).await;
    Ok(())
}

/// 判断逐路由报告是否足以授权 Headscale 路由收敛。
///
/// 启用路由必须由 Agent 给出本地成功或明确失败；成功前缀可独立批准，失败
/// 前缀和关闭路由可独立撤销。没有错误也没有成功证据的结果仍需等待。
fn report_allows_headscale_reconcile(report: &GatewayRouteApplyReport) -> bool {
    !report.routes.is_empty()
        && report
            .routes
            .iter()
            .all(|route| !route.enabled || route.local_applied || route.error_message.is_some())
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

/// 接受 Agent 的 Tunnel mTLS 数据会话。证书指纹决定设备归属，任何未注册
/// 或已撤销证书都会在进入 Yamux 前被拒绝。
async fn serve_tunnel_listener(
    listener: tokio::net::TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
    state: AppState,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(tls_config);
    tracing::info!("Nexo Tunnel TLS 数据通道已监听");
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_tunnel_connection(acceptor, stream, state).await {
                tracing::warn!("Tunnel 数据连接 {peer} 已关闭：{error:#}");
            }
        });
    }
}

async fn serve_tunnel_connection(
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    state: AppState,
) -> Result<()> {
    configure_tunnel_tcp_keepalive(&stream).context("无法配置 Tunnel TCP 保活")?;
    let tls_stream =
        tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(stream))
            .await
            .context("Tunnel TLS 握手超时")?
            .context("Tunnel TLS 握手失败")?;
    let peer_certificate = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .context("Tunnel 数据连接缺少设备证书")?;
    let fingerprint = hex::encode(Sha256::digest(peer_certificate.as_ref()));
    let device_id = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT device_id FROM device_identities
                 WHERE certificate_fingerprint = ?1 AND revoked_at IS NULL",
                [&fingerprint],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .context("Tunnel 设备证书未注册或已撤销")?
    };
    let (sender, receiver) = tokio::sync::mpsc::channel(nexo_tunnel::DEFAULT_MAX_STREAMS);
    let session_sender = sender.clone();
    let cancel = CancellationToken::new();
    let connection_permits = Arc::new(tokio::sync::Semaphore::new(
        nexo_tunnel::DEFAULT_MAX_STREAMS,
    ));
    let replaced = state.tunnel_sessions.lock().await.insert(
        device_id.clone(),
        TunnelSessionHandle {
            sender,
            cancel: cancel.clone(),
            connection_permits,
        },
    );
    if let Some(previous) = replaced {
        previous.cancel.cancel();
        tracing::info!(device_id = %device_id, "Tunnel 新数据会话已接管旧会话");
    }
    let readiness_state = state.clone();
    let readiness_device_id = device_id.clone();
    tokio::spawn(async move {
        refresh_tunnel_readiness(&readiness_state, &readiness_device_id).await;
    });
    let mut connection = nexo_tunnel::yamux_connection(tls_stream, yamux::Mode::Server);
    let result = serve_tunnel_session(&mut connection, receiver, cancel, &state, &device_id)
        .await
        .with_context(|| format!("设备 {device_id} 的 Tunnel 数据会话异常"));
    // 旧会话退出时不能误删刚刚建立的新会话；Sender::same_channel 用来确认
    // 当前 Map 中仍然是本连接对应的通道。
    let mut sessions = state.tunnel_sessions.lock().await;
    if sessions
        .get(&device_id)
        .is_some_and(|active| active.sender.same_channel(&session_sender))
    {
        sessions.remove(&device_id);
    }
    let readiness_state = state.clone();
    let readiness_device_id = device_id.to_owned();
    tokio::spawn(async move {
        refresh_tunnel_readiness(&readiness_state, &readiness_device_id).await;
    });
    result
}

/// 单个 Agent 会话的 Yamux 驱动器。控制面只通过 channel 请求打开流，
/// 这样数据桥接任务不会并发操作同一个 Yamux Connection。
async fn serve_tunnel_session<T>(
    connection: &mut yamux::Connection<T>,
    mut receiver: tokio::sync::mpsc::Receiver<ServerTunnelCommand>,
    cancel: CancellationToken,
    state: &AppState,
    device_id: &str,
) -> Result<()>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!(device_id, "旧 Tunnel 数据会话已被新会话取消");
                break;
            }
            command = receiver.recv() => {
                let Some(command) = command else { break };
                let allowed = {
                    let db = state.db.lock().map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                    db.query_row(
                        "SELECT COUNT(*) FROM tunnels WHERE id = ?1 AND device_id = ?2
                         AND protocol IN ('tcp', 'http', 'https') AND enabled = 1
                         AND deleted_at IS NULL
                         AND EXISTS (SELECT 1 FROM devices d
                                    WHERE d.id = tunnels.device_id AND d.status = 'online')",
                        rusqlite::params![command.tunnel_id, device_id],
                        |row| row.get::<_, i64>(0),
                    )? > 0
                };
                if !allowed {
                    tracing::warn!(device_id, "收到已关闭或不属于设备的 Tunnel 请求");
                    continue;
                }
                let stream = match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    new_outbound(connection),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        return Err(anyhow::anyhow!("无法打开 Tunnel Yamux 逻辑流：{error}"));
                    }
                    Err(_) => {
                        tracing::warn!(device_id, "Tunnel 逻辑流建立超时，已拒绝该连接");
                        continue;
                    }
                };
                let tunnel_id = command.tunnel_id.clone();
                let header = LogicalStreamHeader::new(command.tunnel_id, command.connection_id)
                    .map_err(|error| anyhow::anyhow!("Tunnel 逻辑流首部无效：{error}"))?;
                let mut stream_io = into_tokio_io(stream);
                write_logical_header(&mut stream_io, &header)
                    .await
                    .map_err(|error| anyhow::anyhow!("无法发送 Tunnel 逻辑流首部：{error}"))?;
                let connection_token = Uuid::new_v4();
                let connection_cancel = CancellationToken::new();
                register_active_tunnel_connection(
                    state,
                    &tunnel_id,
                    connection_token,
                    connection_cancel.clone(),
                );
                let connection_state = state.clone();
                tokio::spawn(async move {
                    let _permit = command.permit;
                    let mut socket = command.socket;
                    tokio::select! {
                        _ = connection_cancel.cancelled() => {
                            tracing::debug!(tunnel_id = %tunnel_id, "Tunnel 连接因服务删除而结束");
                        }
                        result = tokio::io::copy_bidirectional(&mut socket, &mut stream_io) => {
                            if let Err(error) = result {
                                tracing::debug!(tunnel_id = %tunnel_id, "Tunnel 连接转发结束：{error}");
                            }
                        }
                    }
                    remove_active_tunnel_connection(
                        &connection_state,
                        &tunnel_id,
                        connection_token,
                    );
                });
            }
            inbound = nexo_tunnel::next_inbound(connection) => {
                match inbound {
                    Ok(Some(_stream)) => tracing::warn!(device_id, "忽略 Agent 发起的反向 Tunnel 流"),
                    Ok(None) => break,
                    Err(error) => return Err(anyhow::anyhow!("Yamux 数据会话失败：{error}")),
                }
            }
        }
    }
    Ok(())
}

/// Server 重启后从 SQLite 恢复公网监听，不依赖内存中的一次性任务队列。
async fn restore_public_tunnel_listeners(state: &AppState) {
    let tunnels = match state.db.lock() {
        Ok(connection) => {
            let mut statement = match connection.prepare(
                "SELECT id, protocol, public_port, bridge_socket_path
                 FROM tunnels WHERE enabled = 1 AND deleted_at IS NULL",
            ) {
                Ok(statement) => statement,
                Err(error) => {
                    tracing::warn!("恢复公网访问监听失败：{error}");
                    return;
                }
            };
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<u16>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .map(|rows| rows.filter_map(Result::ok).collect::<Vec<_>>())
                .unwrap_or_default()
        }
        Err(_) => {
            tracing::warn!("恢复公网 TCP 监听时无法取得数据库锁");
            return;
        }
    };
    for (tunnel_id, protocol, public_port, bridge_socket_path) in tunnels {
        if protocol == "tcp" {
            if let Some(port) = public_port {
                start_public_tunnel_listener(state.clone(), tunnel_id, port).await;
            }
        } else if matches!(protocol.as_str(), "http" | "https") {
            let path = bridge_socket_path
                .map(PathBuf::from)
                .unwrap_or_else(|| tunnel_bridge_socket_path(&state.data_dir, &tunnel_id));
            if let Err(error) = persist_bridge_socket_path(state, &tunnel_id, &path) {
                tracing::warn!(tunnel_id = %tunnel_id, "保存 Web Service Socket 路径失败：{error:#}");
                continue;
            }
            start_public_web_listener(state.clone(), tunnel_id, path).await;
        }
    }
}

async fn start_public_tunnel_listener(state: AppState, tunnel_id: String, port: u16) {
    {
        let Ok(tasks) = state.public_listener_tasks.lock() else {
            return;
        };
        if tasks.contains_key(&tunnel_id) {
            return;
        }
    }
    let listener =
        match tokio::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).await {
            Ok(listener) => listener,
            Err(error) => {
                tracing::warn!(tunnel_id = %tunnel_id, port, "无法监听公网 TCP 端口：{error}");
                if let Ok(connection) = state.db.lock() {
                    let _ = connection.execute(
                    "UPDATE tunnels SET apply_status = 'failed', apply_error = ?1 WHERE id = ?2",
                    rusqlite::params![format!("公网端口 {port} 无法监听"), tunnel_id],
                );
                }
                return;
            }
        };
    let task_state = state.clone();
    let task_tunnel_id = tunnel_id.clone();
    let task_token = Uuid::new_v4();
    let task = tokio::spawn(async move {
        loop {
            let (socket, peer) = match listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    tracing::warn!(tunnel_id = %task_tunnel_id, "公网 TCP 监听已停止：{error}");
                    break;
                }
            };
            let device_id = match task_state.db.lock() {
                Ok(connection) => connection
                    .query_row(
                        "SELECT device_id FROM tunnels WHERE id = ?1 AND enabled = 1 AND deleted_at IS NULL",
                        [&task_tunnel_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .unwrap_or_default(),
                Err(_) => None,
            };
            let Some(device_id) = device_id else {
                drop(socket);
                continue;
            };
            let sender = task_state
                .tunnel_sessions
                .lock()
                .await
                .get(&device_id)
                .and_then(|session| {
                    let permit = session
                        .connection_permits
                        .clone()
                        .try_acquire_owned()
                        .ok()?;
                    Some((session.sender.clone(), permit))
                });
            let Some((sender, permit)) = sender else {
                tracing::debug!(
                    tunnel_id = %task_tunnel_id,
                    %peer,
                    "Agent Tunnel 数据会话不可用或已达到并发上限，已拒绝连接"
                );
                drop(socket);
                continue;
            };
            let command = ServerTunnelCommand {
                tunnel_id: task_tunnel_id.clone(),
                connection_id: Uuid::new_v4().to_string(),
                socket: Box::new(socket),
                permit,
            };
            match sender.try_send(command) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(
                        tunnel_id = %task_tunnel_id,
                        "Tunnel 请求队列已满，已拒绝公网连接"
                    );
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    tracing::debug!(tunnel_id = %task_tunnel_id, "Agent Tunnel 会话已断开");
                }
            }
        }
        remove_public_listener_task(&task_state, &task_tunnel_id, task_token);
    });
    let abort = task.abort_handle();
    if let Ok(mut tasks) = state.public_listener_tasks.lock() {
        tasks.insert(
            tunnel_id,
            PublicListenerTask {
                token: task_token,
                abort,
            },
        );
    }
}

/// 为 HTTP/HTTPS Web Service 建立只绑定数据目录的 Unix Socket。
///
/// Caddy 只能通过这个本地 Socket 进入 Nexo Tunnel；Server 不会暴露内部
/// Origin 端口，Agent 仍会依据 Desired State 连接自己的本地服务。
#[cfg(unix)]
async fn start_public_web_listener(state: AppState, tunnel_id: String, path: PathBuf) {
    use tokio::net::UnixListener;

    {
        let Ok(tasks) = state.public_listener_tasks.lock() else {
            return;
        };
        if tasks.contains_key(&tunnel_id) {
            return;
        }
    }
    if let Err(error) = fs::remove_file(&path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(tunnel_id = %tunnel_id, "无法清理旧 Web Service Socket：{error}");
            return;
        }
    }
    let Some(parent) = path.parent() else {
        tracing::warn!(tunnel_id = %tunnel_id, "Web Service Socket 路径无效");
        return;
    };
    if let Err(error) = fs::create_dir_all(parent) {
        tracing::warn!(tunnel_id = %tunnel_id, "无法创建 Web Service Socket 目录：{error}");
        return;
    }
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::warn!(tunnel_id = %tunnel_id, "无法监听 Web Service Socket：{error}");
            return;
        }
    };
    set_socket_permissions(&path);
    let task_state = state.clone();
    let task_tunnel_id = tunnel_id.clone();
    let task_path = path.clone();
    let task_token = Uuid::new_v4();
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(value) => value,
                Err(error) => {
                    tracing::warn!(tunnel_id = %task_tunnel_id, "Web Service Socket 已停止：{error}");
                    break;
                }
            };
            let device_id = match task_state.db.lock() {
                Ok(connection) => connection
                    .query_row(
                        "SELECT device_id FROM tunnels WHERE id = ?1
                         AND protocol IN ('http', 'https') AND enabled = 1 AND deleted_at IS NULL",
                        [&task_tunnel_id],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .unwrap_or_default(),
                Err(_) => None,
            };
            let Some(device_id) = device_id else {
                continue;
            };
            let sender = task_state
                .tunnel_sessions
                .lock()
                .await
                .get(&device_id)
                .and_then(|session| {
                    let permit = session
                        .connection_permits
                        .clone()
                        .try_acquire_owned()
                        .ok()?;
                    Some((session.sender.clone(), permit))
                });
            let Some((sender, permit)) = sender else {
                tracing::debug!(
                    tunnel_id = %task_tunnel_id,
                    "Agent Web Service 数据会话不可用或已达到并发上限，已拒绝连接"
                );
                continue;
            };
            let command = ServerTunnelCommand {
                tunnel_id: task_tunnel_id.clone(),
                connection_id: Uuid::new_v4().to_string(),
                socket: Box::new(socket),
                permit,
            };
            match sender.try_send(command) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    tracing::warn!(tunnel_id = %task_tunnel_id, "Web Service 请求队列已满，已拒绝公网连接");
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    tracing::debug!(tunnel_id = %task_tunnel_id, "Agent Web Service 数据会话已断开");
                }
            }
        }
        let _ = fs::remove_file(task_path);
        remove_public_listener_task(&task_state, &task_tunnel_id, task_token);
    });
    let abort = task.abort_handle();
    if let Ok(mut tasks) = state.public_listener_tasks.lock() {
        tasks.insert(
            tunnel_id,
            PublicListenerTask {
                token: task_token,
                abort,
            },
        );
    }
}

#[cfg(not(unix))]
async fn start_public_web_listener(_state: AppState, tunnel_id: String, _path: PathBuf) {
    tracing::warn!(tunnel_id = %tunnel_id, "当前平台不支持 Web Service Unix Socket");
}

fn tunnel_bridge_socket_path(data_dir: &std::path::Path, tunnel_id: &str) -> PathBuf {
    data_dir.join("tunnels").join(format!("{tunnel_id}.sock"))
}

/// 每个 Web Service 独立的 CA Secret；文件名只使用服务端生成的 UUID，
/// 避免用户输入参与路径拼接，也防止不同服务之间意外共享信任根。
fn tunnel_origin_ca_path(data_dir: &std::path::Path, tunnel_id: &str) -> PathBuf {
    data_dir
        .join("secrets")
        .join("origins")
        .join(format!("{tunnel_id}.ca.pem"))
}

fn persist_bridge_socket_path(
    state: &AppState,
    tunnel_id: &str,
    path: &std::path::Path,
) -> Result<()> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    connection.execute(
        "UPDATE tunnels SET bridge_socket_path = ?1 WHERE id = ?2",
        rusqlite::params![path.to_string_lossy(), tunnel_id],
    )?;
    Ok(())
}

#[cfg(unix)]
fn set_socket_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o660)) {
        tracing::warn!("无法限制 Web Service Socket 权限：{error}");
    }
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn set_socket_permissions(_path: &std::path::Path) {}

fn stop_public_tunnel_listener(state: &AppState, tunnel_id: &str) {
    if let Ok(mut tasks) = state.public_listener_tasks.lock() {
        if let Some(task) = tasks.remove(tunnel_id) {
            task.abort.abort();
        }
    }
}

/// 登记一条正在转发的公网连接，使永久删除可以中止已有会话。
fn register_active_tunnel_connection(
    state: &AppState,
    tunnel_id: &str,
    token: Uuid,
    cancel: CancellationToken,
) {
    if let Ok(mut connections) = state.active_tunnel_connections.lock() {
        connections
            .entry(tunnel_id.to_owned())
            .or_default()
            .insert(token, cancel);
    }
}

/// 连接自然结束时只移除自身令牌，不能影响同一服务的其他并发连接。
fn remove_active_tunnel_connection(state: &AppState, tunnel_id: &str, token: Uuid) {
    if let Ok(mut connections) = state.active_tunnel_connections.lock() {
        let remove_group = connections.get_mut(tunnel_id).is_some_and(|entries| {
            entries.remove(&token);
            entries.is_empty()
        });
        if remove_group {
            connections.remove(tunnel_id);
        }
    }
}

/// 永久删除穿透服务时取消该服务的全部活动转发，不影响同设备其他服务。
fn stop_active_tunnel_connections(state: &AppState, tunnel_id: &str) {
    let entries = state
        .active_tunnel_connections
        .lock()
        .ok()
        .and_then(|mut connections| connections.remove(tunnel_id));
    for cancel in entries
        .into_iter()
        .flat_map(|entries| entries.into_values())
    {
        cancel.cancel();
    }
}

/// 删除穿透服务关联的 CA 与 Unix Socket；记录已经提交删除时不再回滚，
/// 但保留明确中文日志，便于部署者定位数据目录权限或文件占用问题。
fn cleanup_tunnel_files(
    tunnel_id: &str,
    origin_ca_path: Option<String>,
    bridge_socket_path: Option<String>,
) {
    for path in [origin_ca_path, bridge_socket_path].into_iter().flatten() {
        if let Err(error) = fs::remove_file(&path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(tunnel_id, path, "删除穿透服务 CA 或 Socket 失败：{error}");
            }
        }
    }
}

/// 判断当前 Tunnel 是否仍登记着自己的公网监听器。只用于更新时识别
/// “自占用”端口；真正的外部占用仍由 `TcpListener::bind` 负责检查。
fn public_listener_is_active(state: &AppState, tunnel_id: &str) -> bool {
    state
        .public_listener_tasks
        .lock()
        .map(|tasks| tasks.contains_key(tunnel_id))
        .unwrap_or(false)
}

/// 监听任务自然退出时只移除仍属于自己的登记。
///
/// 停止后立即重新监听是合法操作；旧任务随后完成清理时不能把新任务从
/// 表中删除，因此必须比较启动时生成的令牌。
fn remove_public_listener_task(state: &AppState, tunnel_id: &str, token: Uuid) {
    if let Ok(mut tasks) = state.public_listener_tasks.lock() {
        if tasks.get(tunnel_id).is_some_and(|task| task.token == token) {
            tasks.remove(tunnel_id);
        }
    }
}

/// 在控制连接已经检查过 Caddy/公网入口后复用同一份网关 Desired State。
///
/// 纯数据库版本保留给迁移和单元测试；运行时调用方传入的值还会叠加
/// Caddy 健康状态，确保公网组网入口异常时不会继续下发新的网关路由。
#[cfg(test)]
fn load_gateway_desired_state(
    connection: &Connection,
    device_id: &str,
) -> Result<Option<GatewayDesiredState>> {
    load_gateway_desired_state_with_mesh_allowed(
        connection,
        device_id,
        mesh_application_allowed_with_connection(connection),
    )
}

fn load_gateway_desired_state_with_mesh_allowed(
    connection: &Connection,
    device_id: &str,
    mesh_allowed: bool,
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
                enabled: row.get::<_, i64>(3)? != 0 && !identity_mismatch && mesh_allowed,
            })
        })?;
        for row in rows {
            routes.push(row?);
        }
    }
    {
        let mut statement = connection.prepare(
            "SELECT DISTINCT remote_n.id, l.id, remote_g.desired_prefix, remote_g.desired_revision,
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
                    && !identity_mismatch
                    && mesh_allowed,
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

/// 汇总一台设备当前全部公网访问 Desired State。
///
/// 关闭项和待删除项仍会下发一次，便于 Agent 清理本地连接；删除协调器
/// 只在当前 revision 的关闭 ACK 到达后清理数据库和 Secret。
fn load_tunnel_desired_state(state: &AppState, device_id: &str) -> Result<Vec<TunnelDesiredState>> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let mut statement = connection.prepare(
        "SELECT id, protocol, local_address, local_port, hostname,
                origin_protocol, origin_tls_server_name, origin_tls_verification,
                origin_ca_secret_path, apply_revision, enabled
         FROM tunnels
         WHERE device_id = ?1 AND deleted_at IS NULL
         ORDER BY id ASC",
    )?;
    let rows = statement.query_map([device_id], |row| {
        let port: i64 = row.get(3)?;
        let verification: Option<String> = row.get(7)?;
        let ca_path: Option<String> = row.get(8)?;
        let origin_ca_pem = if verification.as_deref() == Some("custom_ca") {
            ca_path
                .as_deref()
                .and_then(|path| fs::read_to_string(path).ok())
                .filter(|pem| !pem.trim().is_empty())
        } else {
            None
        };
        Ok(TunnelDesiredState {
            tunnel_id: row.get(0)?,
            protocol: row.get(1)?,
            local_address: row.get(2)?,
            local_port: u16::try_from(port).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
            hostname: row.get(4)?,
            origin_protocol: row.get(5)?,
            origin_tls_server_name: row.get(6)?,
            origin_tls_verification: verification,
            origin_ca_pem,
            revision: row.get(9)?,
            enabled: row.get::<_, i64>(10)? != 0,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

/// Agent 对 Tunnel 的实际 ACK 只更新对应设备和 revision，旧 ACK 不能覆盖新配置。
///
/// 成功 ACK 才能推进 Applied revision/config；失败 ACK 只更新错误状态，
/// 保留上一份可用 Applied 配置。旧版本已经下发的删除 revision 仍可在这里
/// 收敛；新版本的删除接口会直接移除记录，迟到 ACK 因查询不到记录而被忽略。
fn apply_tunnel_results(
    state: &AppState,
    device_id: &str,
    results: &[TunnelApplyResult],
) -> Result<()> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let transaction = connection.unchecked_transaction()?;
    let mut cleanups = Vec::new();
    for result in results {
        let Some((
            current_revision,
            enabled,
            protocol,
            local_address,
            local_port,
            hostname,
            origin_protocol,
            origin_tls_server_name,
            origin_tls_verification,
            deletion_requested,
            deletion_revision,
            origin_ca_path,
            bridge_socket_path,
            row_applied_revision,
            current_apply_status,
            tunnel_tenant_id,
        )) = transaction
            .query_row(
                "SELECT apply_revision, enabled, protocol, local_address, local_port, hostname,
                        origin_protocol, origin_tls_server_name, origin_tls_verification,
                        deletion_requested, deletion_revision,
                        origin_ca_secret_path, bridge_socket_path,
                        applied_revision, apply_status, tenant_id
                 FROM tunnels WHERE id = ?1 AND device_id = ?2 AND deleted_at IS NULL",
                rusqlite::params![result.tunnel_id, device_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)? != 0,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, i64>(9)? != 0,
                        row.get::<_, Option<i64>>(10)?,
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, String>(14)?,
                        row.get::<_, String>(15)?,
                    ))
                },
            )
            .optional()?
        else {
            continue;
        };
        if result.revision != current_revision {
            tracing::debug!(
                tunnel_id = %result.tunnel_id,
                reported_revision = result.revision,
                current_revision,
                "忽略过期 Tunnel ACK"
            );
            continue;
        }
        // Agent 只证明了本地 Origin 探测结果；公网数据会话、监听器和 Caddy
        // 的实际状态由 Server 侧后续汇总，不能在这里直接宣称 Tunnel ready。
        let repeated_ready_ack = enabled
            && result.applied
            && result.revision == row_applied_revision
            && current_apply_status == "ready";
        let status = if !enabled {
            "disabled"
        } else if repeated_ready_ack {
            "ready"
        } else if result.applied {
            "checking"
        } else {
            match result.status.as_str() {
                "retrying" => "retrying",
                "failed" => "failed",
                _ => "retrying",
            }
        };
        if result.applied {
            let config = serde_json::json!({
                "protocol": protocol,
                "local_address": local_address,
                "local_port": local_port,
                "hostname": hostname,
                "enabled": enabled,
                "origin_protocol": origin_protocol,
                "origin_tls_server_name": origin_tls_server_name,
                "origin_tls_verification": origin_tls_verification,
            });
            transaction.execute(
                "INSERT INTO tunnel_applied_states
                 (tunnel_id, applied_revision, applied_config_json, apply_status, apply_error, last_checked_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, unixepoch(), unixepoch())
                 ON CONFLICT(tunnel_id) DO UPDATE SET
                 applied_revision = excluded.applied_revision,
                 applied_config_json = excluded.applied_config_json,
                 apply_status = excluded.apply_status,
                 apply_error = excluded.apply_error,
                 last_checked_at = excluded.last_checked_at,
                 updated_at = excluded.updated_at",
                rusqlite::params![
                    result.tunnel_id,
                    result.revision,
                    config.to_string(),
                    status,
                    result.error_message
                ],
            )?;
            transaction.execute(
                "UPDATE tunnels SET apply_status = ?1, apply_error = ?2,
                 applied_revision = ?3, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?4 AND device_id = ?5",
                rusqlite::params![
                    status,
                    result.error_message,
                    result.revision,
                    result.tunnel_id,
                    device_id
                ],
            )?;

            if !enabled && deletion_requested && deletion_revision == Some(result.revision) {
                transaction.execute(
                    "DELETE FROM tunnel_applied_states WHERE tunnel_id = ?1",
                    [&result.tunnel_id],
                )?;
                transaction.execute(
                    "INSERT INTO audit_events (tenant_id, event_type, resource_type, resource_id)
                     VALUES (?1, 'TUNNEL_DELETED', 'tunnel', ?2)",
                    rusqlite::params![tunnel_tenant_id, result.tunnel_id],
                )?;
                let deleted = transaction.execute(
                    "DELETE FROM tunnels
                     WHERE id = ?1 AND device_id = ?2 AND deleted_at IS NULL
                       AND deletion_requested = 1 AND deletion_revision = ?3
                       AND enabled = 0",
                    rusqlite::params![result.tunnel_id, device_id, result.revision],
                )?;
                if deleted > 0 {
                    cleanups.push((result.tunnel_id.clone(), origin_ca_path, bridge_socket_path));
                }
            }
        } else {
            // 失败只覆盖状态和错误，不触碰 applied_revision/applied_config_json。
            // 新建记录尚未有 Applied 配置时，使用空基线等待下一次成功 ACK。
            transaction.execute(
                "INSERT INTO tunnel_applied_states
                 (tunnel_id, applied_revision, applied_config_json, apply_status, apply_error, last_checked_at, updated_at)
                 VALUES (?1, 0, '{}', ?2, ?3, unixepoch(), unixepoch())
                 ON CONFLICT(tunnel_id) DO UPDATE SET
                 apply_status = excluded.apply_status,
                 apply_error = excluded.apply_error,
                 last_checked_at = excluded.last_checked_at,
                 updated_at = excluded.updated_at",
                rusqlite::params![result.tunnel_id, status, result.error_message],
            )?;
            transaction.execute(
                "UPDATE tunnels SET apply_status = ?1, apply_error = ?2,
                 updated_at = CURRENT_TIMESTAMP WHERE id = ?3 AND device_id = ?4",
                rusqlite::params![status, result.error_message, result.tunnel_id, device_id],
            )?;
        }
    }
    transaction.commit()?;
    for (tunnel_id, origin_ca_path, bridge_socket_path) in cleanups {
        stop_public_tunnel_listener(state, &tunnel_id);
        stop_active_tunnel_connections(state, &tunnel_id);
        cleanup_tunnel_files(&tunnel_id, origin_ca_path, bridge_socket_path);
    }
    Ok(())
}

/// 一条 Web Tunnel 实际使用的公网域名状态。
///
/// 多域名上线后，Tunnel 的 HTTPS 状态必须来自显式绑定的域名资源或租户主域名；
/// 这里把两者收敛为同一份只读状态，再交给纯判定函数处理。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TunnelPublicDomainState {
    domain: Option<String>,
    https_enabled: bool,
    certificate_mode: Option<String>,
    apply_status: Option<String>,
    apply_error: Option<String>,
    desired_revision: i64,
    applied_revision: i64,
    root_certificate_status: Option<String>,
    wildcard_certificate_status: Option<String>,
    /// 只有旧版单例投影使用该字段。多域名记录始终通过根/泛域名状态判断。
    legacy_ready: bool,
}

/// 解析一条 Tunnel 应使用的公网域名。
///
/// `public_domain_id` 是用户的显式选择；没有显式选择时才使用同租户主域名。
/// 显式 ID 无效时不能静默回退到主域名，否则会让用户访问到错误的服务入口。
fn resolve_tunnel_public_domain_state(
    public_domain_id: Option<&str>,
    primary_domain_id: Option<&str>,
    domains: &HashMap<String, TunnelPublicDomainState>,
    legacy_state: Option<&TunnelPublicDomainState>,
) -> TunnelPublicDomainState {
    if let Some(domain_id) = public_domain_id {
        return domains.get(domain_id).cloned().unwrap_or_default();
    }
    if let Some(primary_id) = primary_domain_id {
        return domains.get(primary_id).cloned().unwrap_or_default();
    }
    legacy_state.cloned().unwrap_or_default()
}

/// 判断域名服务是否已经满足 Web Tunnel 的公网就绪门槛。
///
/// 返回 `None` 表示域名服务已就绪；返回值中的状态和错误直接写入 Tunnel
/// 状态。HTTP 只要求域名路由配置已经应用，即使同域名的 HTTPS 证书仍在
/// 申请也不能阻塞 HTTP；HTTPS 才要求根证书和泛域名证书均为 READY。
fn evaluate_tunnel_public_readiness(
    protocol: &str,
    public_domain: &TunnelPublicDomainState,
) -> Option<(String, String)> {
    if public_domain.domain.is_none() {
        return Some((
            "checking".to_owned(),
            "穿透服务尚未绑定可用公网域名".to_owned(),
        ));
    }

    let route_config_ready = public_domain.desired_revision == public_domain.applied_revision
        && public_domain.apply_status.as_deref() != Some("error");
    if !route_config_ready {
        let status = match public_domain.apply_status.as_deref() {
            Some("error" | "retrying" | "rate_limited") => "retrying",
            _ => "checking",
        };
        let message = public_domain
            .apply_error
            .clone()
            .unwrap_or_else(|| "公网路由配置正在应用".to_owned());
        return Some((status.to_owned(), message));
    }

    if protocol != "https" {
        return None;
    }

    if !public_domain.https_enabled {
        return Some(("checking".to_owned(), "绑定域名尚未启用 HTTPS".to_owned()));
    }

    let certificate_ready = if public_domain.legacy_ready {
        public_domain.apply_status.as_deref() == Some("ready")
    } else {
        public_domain.root_certificate_status.as_deref() == Some("ready")
            && public_domain.wildcard_certificate_status.as_deref() == Some("ready")
    };
    if !certificate_ready {
        let message = if public_domain.certificate_mode.as_deref() == Some("manual") {
            "手动证书尚未加载".to_owned()
        } else {
            "等待 HTTPS 证书生效".to_owned()
        };
        return Some(("checking".to_owned(), message));
    }

    None
}

/// 汇总一条 Tunnel 是否真正可用。
///
/// Agent ACK 只代表它能连接本地 Origin；只有数据面会话、Server 监听器、
/// 实际绑定域名的路由配置、证书状态和反向代理健康检查都满足时，才把用户
/// 可见状态改为 `ready`。这条边界避免“数据库保存成功”被误报成公网入口已经
/// 可以访问，同时避免无关主域名状态阻塞附加域名。
async fn refresh_tunnel_readiness(state: &AppState, device_id: &str) {
    let data_session = state.tunnel_sessions.lock().await.contains_key(device_id);
    let caddy_healthy = state.caddy.healthy().await;
    let listener_ids = state
        .public_listener_tasks
        .lock()
        .map(|tasks| {
            tasks
                .keys()
                .cloned()
                .collect::<std::collections::HashSet<_>>()
        })
        .unwrap_or_default();
    let snapshot = {
        let connection = match state.db.lock() {
            Ok(connection) => connection,
            Err(_) => {
                tracing::warn!(device_id = %device_id, "检查 Tunnel 状态时数据库锁不可用");
                return;
            }
        };
        let device_online = connection
            .query_row(
                "SELECT status FROM devices WHERE id = ?1",
                [device_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten()
            .is_some_and(|status| status == "online");
        let tenant_id = connection
            .query_row(
                "SELECT tenant_id FROM tunnels
                 WHERE device_id = ?1 AND deleted_at IS NULL LIMIT 1",
                [device_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .ok()
            .flatten();
        let mut domain_states = HashMap::new();
        let mut primary_domain_id = None;
        if let Some(tenant_id) = tenant_id.as_deref() {
            let mut domain_statement = match connection.prepare(
                "SELECT id, domain, is_primary, https_enabled, certificate_mode,
                        apply_status, apply_error, desired_revision, applied_revision,
                        root_certificate_status, wildcard_certificate_status
                 FROM public_domains WHERE tenant_id = ?1",
            ) {
                Ok(statement) => statement,
                Err(error) => {
                    tracing::warn!(device_id = %device_id, "读取绑定域名状态失败：{error}");
                    return;
                }
            };
            let rows = match domain_statement.query_map([tenant_id], |row| {
                let id: String = row.get(0)?;
                let is_primary = row.get::<_, i64>(2)? != 0;
                let state = TunnelPublicDomainState {
                    domain: row.get(1)?,
                    https_enabled: row.get::<_, i64>(3)? != 0,
                    certificate_mode: row.get(4)?,
                    apply_status: row.get(5)?,
                    apply_error: row.get(6)?,
                    desired_revision: row.get(7)?,
                    applied_revision: row.get(8)?,
                    root_certificate_status: row.get(9)?,
                    wildcard_certificate_status: row.get(10)?,
                    legacy_ready: false,
                };
                Ok((id, is_primary, state))
            }) {
                Ok(rows) => rows,
                Err(error) => {
                    tracing::warn!(device_id = %device_id, "读取绑定域名状态失败：{error}");
                    return;
                }
            };
            for row in rows {
                match row {
                    Ok((id, is_primary, state)) => {
                        if is_primary {
                            primary_domain_id = Some(id.clone());
                        }
                        domain_states.insert(id, state);
                    }
                    Err(error) => {
                        tracing::warn!(device_id = %device_id, "解析绑定域名状态失败：{error}");
                        return;
                    }
                }
            }
        }
        let legacy_state = if domain_states.is_empty() {
            tenant_id.as_deref().and_then(|tenant_id| {
                connection
                    .query_row(
                        "SELECT domain, https_enabled, certificate_mode, apply_status,
                                apply_error, desired_revision, applied_revision,
                                root_certificate_status, wildcard_certificate_status
                         FROM public_domains WHERE is_primary = 1 AND tenant_id = ?1",
                        [tenant_id],
                        |row| {
                            let apply_status: String = row.get(3)?;
                            let desired_revision: i64 = row.get(5)?;
                            let applied_revision: i64 = row.get(6)?;
                            Ok(TunnelPublicDomainState {
                                domain: row.get(0)?,
                                https_enabled: row.get::<_, i64>(1)? != 0,
                                certificate_mode: row.get(2)?,
                                apply_status: Some(apply_status.clone()),
                                apply_error: row.get(4)?,
                                desired_revision,
                                applied_revision,
                                root_certificate_status: row.get(7)?,
                                wildcard_certificate_status: row.get(8)?,
                                legacy_ready: false,
                            })
                        },
                    )
                    .optional()
                    .ok()
                    .flatten()
            })
        } else {
            None
        };
        let mut statement = match connection.prepare(
            "SELECT t.id, t.protocol, t.enabled, t.apply_revision, t.applied_revision,
                     t.apply_status, t.apply_error,
                     COALESCE(a.applied_revision, 0), COALESCE(a.apply_status, 'checking'),
                     a.apply_error, t.deletion_requested, t.public_domain_id
             FROM tunnels t
             LEFT JOIN tunnel_applied_states a ON a.tunnel_id = t.id
             WHERE t.device_id = ?1 AND t.deleted_at IS NULL",
        ) {
            Ok(statement) => statement,
            Err(error) => {
                tracing::warn!(device_id = %device_id, "读取 Tunnel 应用状态失败：{error}");
                return;
            }
        };
        let tunnels = statement
            .query_map([device_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, i64>(10)? != 0,
                    row.get::<_, Option<String>>(11)?,
                ))
            })
            .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
            .unwrap_or_default();
        let tunnels = tunnels
            .into_iter()
            .map(
                |(
                    tunnel_id,
                    protocol,
                    enabled,
                    desired_tunnel_revision,
                    previous_applied_revision,
                    current_status,
                    current_error,
                    agent_revision,
                    agent_status,
                    agent_error,
                    deletion_requested,
                    public_domain_id,
                )| {
                    let public_domain = resolve_tunnel_public_domain_state(
                        public_domain_id.as_deref(),
                        primary_domain_id.as_deref(),
                        &domain_states,
                        legacy_state.as_ref(),
                    );
                    (
                        tunnel_id,
                        protocol,
                        enabled,
                        desired_tunnel_revision,
                        previous_applied_revision,
                        current_status,
                        current_error,
                        agent_revision,
                        agent_status,
                        agent_error,
                        deletion_requested,
                        public_domain,
                    )
                },
            )
            .collect::<Vec<_>>();
        (tunnels, device_online)
    };
    let (tunnels, device_online) = snapshot;
    let connection = match state.db.lock() {
        Ok(connection) => connection,
        Err(_) => return,
    };
    for (
        tunnel_id,
        protocol,
        enabled,
        desired_tunnel_revision,
        _previous_applied_revision,
        current_status,
        current_error,
        agent_revision,
        agent_status,
        agent_error,
        deletion_requested,
        public_domain,
    ) in tunnels
    {
        if !enabled {
            let pending_delete =
                deletion_requested && desired_tunnel_revision > _previous_applied_revision;
            let _ = connection.execute(
                "UPDATE tunnels SET apply_status = ?1, apply_error = ?2,
                 updated_at = CURRENT_TIMESTAMP WHERE id = ?3",
                rusqlite::params![
                    if pending_delete {
                        "applying"
                    } else {
                        "disabled"
                    },
                    pending_delete.then_some("等待设备确认删除"),
                    tunnel_id
                ],
            );
            continue;
        }
        let agent_applied = agent_revision == desired_tunnel_revision
            && matches!(agent_status.as_str(), "checking" | "ready")
            && current_status != "retrying"
            && current_status != "failed";
        let (status, error, applied) = if current_status == "failed" {
            ("failed".to_owned(), current_error.or(agent_error), false)
        } else if !agent_applied {
            (
                if matches!(agent_status.as_str(), "retrying" | "failed") {
                    agent_status
                } else {
                    "checking".to_owned()
                },
                agent_error.or(current_error),
                false,
            )
        } else if !device_online {
            (
                "checking".to_owned(),
                Some("等待 Agent 控制连接".to_owned()),
                false,
            )
        } else if !data_session {
            (
                "checking".to_owned(),
                Some("等待 Agent Tunnel 数据连接".to_owned()),
                false,
            )
        } else if !listener_ids.contains(&tunnel_id) {
            (
                "checking".to_owned(),
                Some("穿透服务监听尚未生效".to_owned()),
                false,
            )
        } else if !caddy_healthy && matches!(protocol.as_str(), "http" | "https") {
            (
                "retrying".to_owned(),
                Some("Web 穿透服务暂时不可用".to_owned()),
                false,
            )
        } else if matches!(protocol.as_str(), "http" | "https") {
            if let Some((status, error)) =
                evaluate_tunnel_public_readiness(&protocol, &public_domain)
            {
                (status, Some(error), false)
            } else {
                ("ready".to_owned(), None, true)
            }
        } else {
            ("ready".to_owned(), None, true)
        };
        let _ = connection.execute(
            "UPDATE tunnels SET apply_status = ?1, apply_error = ?2,
             applied_revision = CASE WHEN ?3 = 1 THEN apply_revision ELSE applied_revision END,
             updated_at = CURRENT_TIMESTAMP WHERE id = ?4 AND device_id = ?5",
            rusqlite::params![status, error, i64::from(applied), tunnel_id, device_id],
        );
    }
}

/// 对 Caddy/数据会话变化触发一次完整 Tunnel 状态收敛。
async fn refresh_all_tunnel_readiness(state: &AppState) {
    let device_ids = match state.db.lock() {
        Ok(connection) => connection
            .prepare(
                "SELECT DISTINCT device_id FROM tunnels
                 WHERE device_id IS NOT NULL AND deleted_at IS NULL",
            )
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .and_then(|rows| rows.collect::<rusqlite::Result<Vec<_>>>())
            })
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    for device_id in device_ids {
        refresh_tunnel_readiness(state, &device_id).await;
    }
}

/// Agent 只拿到数据通道地址和证书名称，不接触 Caddy/Admin/Headscale 内部端口。
fn tunnel_endpoint_from_env() -> Option<TunnelDataEndpoint> {
    let address = env::var("NEXO_TUNNEL_ENDPOINT").ok()?.trim().to_owned();
    if address.is_empty() {
        return None;
    }
    Some(TunnelDataEndpoint {
        address,
        server_name: env::var("NEXO_TUNNEL_SERVER_NAME")
            .unwrap_or_else(|_| "nexo-server".to_owned()),
    })
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
            -- 关闭后的终态必须同时满足：两侧当前 revision 都有逐路由
            -- ACK，且本地、控制平面、远端接受状态全部已撤销。不能用
            -- 旧 revision 或后台投影的默认值提前宣称 DISABLED。
            WHEN enabled = 0
             AND EXISTS (
              SELECT 1
              FROM site_link_networks local_link
              JOIN site_networks local_n
                ON local_n.id = local_link.site_network_id
              JOIN site_link_networks remote_link
                ON remote_link.site_link_id = local_link.site_link_id
               AND remote_link.side <> local_link.side
              JOIN site_networks remote_n
                ON remote_n.id = remote_link.site_network_id
              JOIN gateway_route_applies a
                ON a.device_id = local_n.publisher_device_id
               AND a.network_id = remote_n.id
               AND a.site_link_id = site_links.id
               AND a.desired_revision >= site_links.apply_revision
             )
             AND NOT EXISTS (
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
               AND a.desired_revision >= site_links.apply_revision
               WHERE local_link.site_link_id = site_links.id
                 AND (COALESCE(a.local_status, '') <> 'disabled'
                   OR COALESCE(a.remote_status, '') <> 'disabled'
                   OR COALESCE(a.control_plane_status, '') <> 'disabled')
            ) THEN 'disabled'
            WHEN enabled = 0 THEN 'checking'
            WHEN EXISTS (
              SELECT 1
              FROM site_link_networks ln
              JOIN gateway_network_states g
                ON g.site_network_id = ln.site_network_id
              WHERE ln.site_link_id = site_links.id
                AND g.apply_status = 'retrying'
            ) THEN 'retrying'
            WHEN EXISTS (
              SELECT 1
              FROM site_link_networks local_link
              JOIN site_networks local_n
                ON local_n.id = local_link.site_network_id
              JOIN gateway_network_states local_g
                ON local_g.site_network_id = local_n.id
              JOIN devices d
                ON d.id = local_n.publisher_device_id
              LEFT JOIN mesh_identities m
                ON m.nexo_device_id = local_n.publisher_device_id
              JOIN site_link_networks remote_link
                ON remote_link.site_link_id = local_link.site_link_id
               AND remote_link.side <> local_link.side
              JOIN site_networks remote_n
                ON remote_n.id = remote_link.site_network_id
              WHERE local_link.site_link_id = site_links.id
                AND (local_g.apply_status <> 'ready'
                      OR d.status <> 'online'
                      OR COALESCE(m.state, '') <> 'ready'
                      OR COALESCE(m.online, 0) <> 1
                      OR NOT EXISTS (
                  SELECT 1
                  FROM gateway_route_applies a
                  WHERE a.device_id = local_n.publisher_device_id
                    AND a.network_id = remote_n.id
                    AND a.site_link_id = site_links.id
                    AND a.local_status = 'applied'
                    AND a.control_plane_status = 'serving'
                   AND a.remote_status = 'accepted'))
           ) THEN 'checking'
           ELSE 'ready' END,
         apply_error = CASE WHEN enabled = 0 THEN NULL ELSE apply_error END,
         updated_at = CURRENT_TIMESTAMP",
    )?;
    finalize_requested_resource_deletions(transaction)?;
    Ok(())
}

/// 在同一事务内检查网络资源的三段撤销证据并完成物理删除。
///
/// `local_status` 和 `remote_status` 来自 Agent 对当前 Desired revision 的 ACK，
/// `control_plane_status` 只能由 Server 完成 Headscale 协调后写入。先清理 Link，
/// 再清理 Network，保证映射和路由状态不会反向绕过固定的删除顺序。
fn finalize_requested_resource_deletions(transaction: &rusqlite::Transaction<'_>) -> Result<()> {
    let completed_links: Vec<(String, String)> = {
        let mut statement = transaction.prepare(
            "SELECT l.id, l.tenant_id
             FROM site_links l
             WHERE l.deletion_requested = 1 AND l.enabled = 0
               AND EXISTS (SELECT 1 FROM site_link_networks ln
                           WHERE ln.site_link_id = l.id AND ln.side = 'left')
               AND EXISTS (SELECT 1 FROM site_link_networks ln
                           WHERE ln.site_link_id = l.id AND ln.side = 'right')
               AND NOT EXISTS (
                 SELECT 1
                 FROM site_link_networks local_link
                 JOIN site_networks local_n ON local_n.id = local_link.site_network_id
                 JOIN site_link_networks remote_link
                   ON remote_link.site_link_id = local_link.site_link_id
                  AND remote_link.side <> local_link.side
                 JOIN site_networks remote_n ON remote_n.id = remote_link.site_network_id
                 LEFT JOIN gateway_route_applies a
                   ON a.device_id = local_n.publisher_device_id
                  AND a.network_id = remote_n.id
                  AND a.site_link_id = l.id
                 WHERE local_link.site_link_id = l.id
                   AND (a.desired_revision IS NULL OR a.desired_revision <> l.apply_revision
                     OR a.local_status <> 'disabled'
                     OR a.control_plane_status <> 'disabled'
                     OR a.remote_status <> 'disabled')
               )",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (link_id, tenant_id) in completed_links {
        transaction.execute(
            "DELETE FROM gateway_route_applies WHERE site_link_id = ?1",
            [&link_id],
        )?;
        transaction.execute(
            "DELETE FROM site_link_route_confirmations WHERE site_link_id = ?1",
            [&link_id],
        )?;
        transaction.execute(
            "DELETE FROM site_link_networks WHERE site_link_id = ?1",
            [&link_id],
        )?;
        transaction.execute(
            "INSERT INTO audit_events (tenant_id, event_type, resource_type, resource_id)
             VALUES (?1, 'SITE_LINK_DELETED', 'site_link', ?2)",
            rusqlite::params![tenant_id, link_id],
        )?;
        transaction.execute(
            "DELETE FROM site_links WHERE id = ?1 AND deletion_requested = 1",
            [&link_id],
        )?;
    }

    let completed_networks: Vec<(String, String)> = {
        let mut statement = transaction.prepare(
            "SELECT n.id, n.tenant_id
             FROM site_networks n
             JOIN gateway_network_states g ON g.site_network_id = n.id
             WHERE n.deletion_requested = 1 AND n.enabled = 0
               AND NOT EXISTS (SELECT 1 FROM site_link_networks ln
                               WHERE ln.site_network_id = n.id)
               AND EXISTS (
                 SELECT 1 FROM gateway_route_applies a
                 WHERE a.device_id = n.publisher_device_id
                   AND a.network_id = n.id AND a.site_link_id = ''
                   AND a.desired_revision = g.desired_revision
                   AND a.local_status = 'disabled'
                   AND a.control_plane_status = 'disabled'
                   AND a.remote_status = 'disabled'
               )",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (network_id, tenant_id) in completed_networks {
        transaction.execute(
            "DELETE FROM subnet_access WHERE site_network_id = ?1",
            [&network_id],
        )?;
        transaction.execute(
            "DELETE FROM gateway_route_applies WHERE network_id = ?1",
            [&network_id],
        )?;
        transaction.execute(
            "DELETE FROM gateway_network_states WHERE site_network_id = ?1",
            [&network_id],
        )?;
        transaction.execute(
            "INSERT INTO audit_events (tenant_id, event_type, resource_type, resource_id)
             VALUES (?1, 'SITE_NETWORK_DELETED', 'site_network', ?2)",
            rusqlite::params![tenant_id, network_id],
        )?;
        transaction.execute(
            "DELETE FROM site_networks WHERE id = ?1 AND deletion_requested = 1",
            [&network_id],
        )?;
    }
    Ok(())
}

async fn current_mesh_offer(state: &AppState, device_id: &str) -> Option<MeshEnrollmentOffer> {
    let allowed = mesh_application_allowed(state).await;
    if !allowed {
        return None;
    }
    state.mesh_offers.lock().await.get(device_id).cloned()
}

/// 控制连接建立时恢复或补发组网邀请，避免依赖内存中的一次性任务队列。
async fn ensure_mesh_enrollment_for_device(state: &AppState, device_id: &str) -> Result<()> {
    let _lock = state.mesh_enrollment_lock.lock().await;
    ensure_mesh_enrollment_for_device_locked(state, device_id).await
}

async fn ensure_mesh_enrollment_for_device_locked(state: &AppState, device_id: &str) -> Result<()> {
    let mesh_allowed = mesh_application_allowed(state).await;
    if !mesh_allowed {
        // HTTPS 被关闭或 Caddy 尚未应用成功时，不能把此前暂存的明文
        // Pre-auth Key 再发给 Agent。恢复 HTTPS 后会从 Headscale API
        // 重新发现未消费的 Key，并沿用同一个稳定主机名。
        state.mesh_offers.lock().await.remove(device_id);
        return Err(anyhow::anyhow!(mesh_restriction_message()));
    }
    if current_mesh_offer(state, device_id).await.is_some() {
        return Ok(());
    }
    // 主域名切换复用同一条 mTLS 控制通道。即使设备已经有旧的 Mesh
    // 身份，也必须收到一次性新 Key 并 ACK，不能仅修改数据库中的地址。
    if ensure_public_domain_migration_offer(state, device_id).await? {
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
                                endpoint: state.headscale_runtime.server_url(),
                                auth_key: plaintext,
                                auth_key_id: key.id,
                                hostname: mesh_hostname(&tenant_id, &device_name, device_id),
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

/// 为尚未确认主域名迁移的设备生成一次性 Headscale Key。
///
/// 该流程刻意复用现有 MeshEnrollmentOffer：旧 Agent 可以继续解析消息，
/// 新 Agent 收到 `reset=true` 后执行完整 `tailscale up`。设备身份仍由
/// Server 通过 mTLS 证书和 Headscale Key 双向校验。
async fn ensure_public_domain_migration_offer(state: &AppState, device_id: &str) -> Result<bool> {
    let details: Option<(String, String, String)> = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT m.id, m.tenant_id, d.name
                 FROM public_domain_migrations m
                 JOIN public_domain_migration_devices md ON md.migration_id = m.id
                 JOIN devices d ON d.id = md.device_id
                 WHERE md.device_id = ?1 AND md.status IN ('pending', 'failed', 'sent')
                   AND m.status IN ('switching', 'waiting_devices')
                 ORDER BY m.created_at ASC LIMIT 1",
                [device_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
    };
    let Some((migration_id, tenant_id, device_name)) = details else {
        return Ok(false);
    };
    if current_mesh_offer(state, device_id).await.is_none() {
        start_mesh_enrollment_locked(state, device_id, &tenant_id, &device_name, true).await?;
    }
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    connection.execute(
        "UPDATE public_domain_migration_devices SET status = 'sent', attempts = attempts + 1,
         last_error = NULL WHERE migration_id = ?1 AND device_id = ?2
           AND status IN ('pending', 'failed')",
        rusqlite::params![migration_id, device_id],
    )?;
    Ok(true)
}

/// Mesh ACK 成功后推进主域名迁移；只有全部设备 ACK 才允许后续删除旧域名。
fn record_public_domain_migration_ack(
    state: &AppState,
    device_id: &str,
    success: bool,
    error_message: Option<&str>,
) -> Result<()> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let status = if success { "acknowledged" } else { "failed" };
    connection.execute(
        "UPDATE public_domain_migration_devices
         SET status = ?1, last_error = ?2,
             acknowledged_at = CASE WHEN ?3 = 1 THEN unixepoch() ELSE acknowledged_at END
         WHERE device_id = ?4 AND status IN ('pending', 'sent', 'failed')
           AND migration_id IN (
             SELECT id FROM public_domain_migrations
             WHERE status IN ('switching', 'waiting_devices'))",
        rusqlite::params![status, error_message, i64::from(success), device_id],
    )?;
    let migration_ids = {
        let mut statement = connection.prepare(
            "SELECT id FROM public_domain_migrations
             WHERE status IN ('switching', 'waiting_devices')
               AND id IN (SELECT migration_id FROM public_domain_migration_devices WHERE device_id = ?1)",
        )?;
        let ids = statement
            .query_map([device_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids
    };
    let mut completed_any = false;
    for migration_id in migration_ids {
        let acknowledged: i64 = connection.query_row(
            "SELECT COUNT(*) FROM public_domain_migration_devices
             WHERE migration_id = ?1 AND status = 'acknowledged'",
            [&migration_id],
            |row| row.get(0),
        )?;
        let total: i64 = connection.query_row(
            "SELECT total_devices FROM public_domain_migrations WHERE id = ?1",
            [&migration_id],
            |row| row.get(0),
        )?;
        let completed = total > 0 && acknowledged >= total;
        completed_any |= completed;
        connection.execute(
            "UPDATE public_domain_migrations SET acknowledged_devices = ?1,
             status = ?2, last_error = CASE WHEN ?3 = 1 THEN NULL ELSE ?4 END,
             updated_at = unixepoch(), completed_at = CASE WHEN ?3 = 1 THEN unixepoch() ELSE completed_at END
             WHERE id = ?5",
            rusqlite::params![acknowledged, if completed { "completed" } else { "waiting_devices" }, i64::from(completed), error_message, migration_id],
        )?;
    }
    drop(connection);
    if completed_any {
        let state = state.clone();
        tokio::spawn(async move { reconcile_caddy_config_best_effort(&state).await });
    }
    Ok(())
}

/// 生成只供 Tailscale 使用的稳定 DNS 主机名。
///
/// 设备显示名可以是中文或包含标点，但 Tailscale 只接受 ASCII DNS 标签。
/// 因此这里把租户和设备名称分别规范化，并始终附加设备 ID 短后缀，避免
/// 同名设备依赖 Headscale 的隐式冲突后缀。该名称只进入 Mesh Enrollment，
/// Web 仍然显示用户设置的原始设备名称。
fn mesh_hostname(tenant_id: &str, device_name: &str, device_id: &str) -> String {
    const MAX_LABEL_LENGTH: usize = 63;

    let tenant_slug = dns_label_slug(tenant_id);
    let device_slug = dns_label_slug(device_name);
    let tenant_slug = if tenant_slug.is_empty() {
        "tenant"
    } else {
        tenant_slug.as_str()
    };
    let device_slug = if device_slug.is_empty() {
        "device"
    } else {
        device_slug.as_str()
    };
    let id_suffix = dns_label_slug(device_id)
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(32)
        .collect::<String>();
    let id_suffix = if id_suffix.is_empty() {
        "node".to_owned()
    } else {
        id_suffix
    };

    // 先保留 ID 后缀，再截断用户输入，确保长名称不会丢掉稳定唯一部分。
    let prefix = format!("{tenant_slug}-{device_slug}");
    let prefix_length = MAX_LABEL_LENGTH.saturating_sub(id_suffix.len() + 1);
    let prefix = prefix
        .chars()
        .take(prefix_length)
        .collect::<String>()
        .trim_end_matches('-')
        .to_owned();
    format!("{prefix}-{id_suffix}")
}

/// 把任意用户文本压缩为 DNS 标签可接受的 ASCII 片段。
fn dns_label_slug(value: &str) -> String {
    let mut slug = String::new();
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_matches('-').to_owned()
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
    let mesh_allowed = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        mesh_application_allowed_with_connection(&connection)
    };
    if !mesh_allowed {
        // 不在内存中恢复旧 Offer；正式 HTTPS 恢复后，设备下一次心跳会
        // 重新执行同一份 Desired State 协调。
        return Ok(());
    }
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
            device_id.clone(),
            MeshEnrollmentOffer {
                endpoint: state.headscale_runtime.server_url(),
                auth_key: plaintext,
                auth_key_id: key.id,
                hostname: mesh_hostname(&tenant_id, &device_name, &device_id),
                reset: false,
                tenant_id: Some(tenant_id),
            },
        );
    }
    Ok(())
}

/// Headscale 暂时不可用时只记录待重试原因，不改变一次性 Key 的 `issued`
/// 状态。这样已被 Tailscale 消费但尚未能查询到 Node 的 Key 不会被错误吊销，
/// 也不会因为控制连接重连而生成重复的 Headscale Node。
fn record_mesh_enrollment_retry(
    state: &AppState,
    device_id: &str,
    auth_key_id: &str,
    message: &str,
) -> Result<()> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    connection.execute(
        "UPDATE mesh_enrollment_attempts
         SET last_error = ?1, updated_at = CURRENT_TIMESTAMP
         WHERE nexo_device_id = ?2 AND headscale_pre_auth_key_id = ?3
           AND state = 'issued'",
        rusqlite::params![truncate_error_message(message), device_id, auth_key_id],
    )?;
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

    // tailscaled 重启初期可能返回 NodeID=0 且 Online=false；这只是本地
    // 守护进程尚未完成注册，不代表身份已经改变。等它上线后再执行严格比对。
    if state_name == "ready"
        && identity.online
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
    let mesh_allowed = mesh_application_allowed_with_connection(&transaction);
    // 身份错配后，服务端会把所有网关 Desired Route 屏蔽为禁用。报告中的
    // `enabled=false` 是撤销动作，不应再被“网络本身仍启用”这一字段拒绝，
    // 否则控制通道会在撤销完成前反复断开，Mesh 也无法保持在线供恢复使用。
    let identity_mismatch = transaction
        .query_row(
            "SELECT state FROM mesh_identities WHERE nexo_device_id = ?1",
            [device_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .is_some_and(|state| state == "mesh_identity_mismatch");
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
        let Some((expected_prefix, mut expected_enabled, expected_revision)) = expected else {
            anyhow::bail!(
                "设备 {device_id} 上报了未授权的网关路由 {}",
                route.network_id
            );
        };
        if identity_mismatch {
            expected_enabled = false;
        }
        if !mesh_allowed {
            // 正式 HTTPS 未就绪时，Server 下发的所有网关路由都是撤销
            // Desired State；Agent 的关闭 ACK 仍然需要被接受并持久化。
            expected_enabled = false;
        }
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
            tracing::warn!(
                device_id = %device_id,
                network_id = %route.network_id,
                site_link_id = %site_link_key,
                reported_revision = route.revision,
                expected_revision,
                reported_enabled = route.enabled,
                expected_enabled,
                "设备上报的网关开关与当前期望不一致，将拒绝本次控制消息"
            );
            anyhow::bail!("设备 {device_id} 上报的网关开关与当前期望不一致");
        }
        let local_status = if !route.enabled {
            "disabled"
        } else if route.local_applied {
            "applied"
        } else if route.error_message.is_some() {
            "failed"
        } else {
            "upgrade_required"
        };
        // Agent 无法证明 Headscale 已撤销路由。关闭 ACK 只确认本地状态，
        // 控制平面的 disabled 必须等服务端实际调用 Headscale 后再写入。
        let control_plane_status = if !route.enabled {
            "pending"
        } else {
            route
                .control_plane_status
                .as_deref()
                .filter(|status| {
                    matches!(
                        *status,
                        "pending" | "discovered" | "approved" | "serving" | "failed" | "disabled"
                    )
                })
                .unwrap_or("pending")
        };
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
    let runtime_mesh_allowed = mesh_application_allowed(state).await;
    let (node_id, desired, owned): (Option<String>, Vec<GatewayRouteApplyInput>, Vec<String>) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mesh_allowed =
            runtime_mesh_allowed && mesh_application_allowed_with_connection(&connection);
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
                enabled: row.get::<_, i64>(4)? != 0 && mesh_allowed,
                local_applied: row.get::<_, i64>(5)? != 0,
            })
        })?;
        let desired: Vec<_> = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let owned = desired
            .iter()
            .map(|route| route.prefix.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
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
        .collect::<BTreeSet<_>>()
        .into_iter()
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
    let mesh_allowed = mesh_application_allowed_with_connection(&transaction);
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
                row.get::<_, i64>(4)? != 0 && mesh_allowed,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (link_id, remote_network_id, remote_device_id, revision, enabled) in site_routes {
        // 关闭 Link 时，必须先看到当前 revision 的 Agent 撤销 ACK，才允许
        // 把控制平面状态推进到 disabled。旧 revision 的行只能继续显示检查中。
        let current_route: Option<(String, String, String, Option<String>)> = transaction
            .query_row(
                "SELECT local_status, control_plane_status, remote_status, last_error
                 FROM gateway_route_applies
                 WHERE device_id = ?1 AND network_id = ?2 AND site_link_id = ?3
                   AND desired_revision >= ?4",
                rusqlite::params![device_id, remote_network_id, link_id, revision],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
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
            match current_route {
                Some((local_status, _, remote_status, _))
                    if local_status == "disabled" && remote_status == "disabled" =>
                {
                    // Agent 已确认撤销本地和远端接受状态；当前函数刚完成
                    // Headscale API 检查，因此现在才可确认控制平面已撤销。
                    ("disabled".to_owned(), None)
                }
                Some((_, control_status, _, error)) => (control_status, error),
                None => (
                    "pending".to_owned(),
                    Some("等待 Agent 确认撤销站点路由".to_owned()),
                ),
            }
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

fn tenant_policy_selector(tenant_id: &str) -> String {
    format!("group:nexo-workspace-{tenant_id}")
}

/// 为每个工作空间生成 Headscale Policy 用户组。
///
/// OIDC 账号使用 `issuer/sub@` 作为组成员，只有显式的 Auth Key 机器身份
/// 才允许继续使用 `nexo-<workspace>@`；用户名本身不参与授权主键。
fn workspace_policy_groups(connection: &Connection) -> Result<BTreeMap<String, Vec<String>>> {
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT a.workspace_id, a.provider_id
         FROM mesh_oidc_accounts a
         JOIN users u ON u.id = a.nexo_user_id
         WHERE u.enabled = 1 AND a.sync_status <> 'revoked'
         ORDER BY a.workspace_id, a.provider_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (workspace_id, provider_id) = row?;
        let selector = if provider_id.contains('@') {
            provider_id
        } else {
            format!("{provider_id}@")
        };
        groups
            .entry(tenant_policy_selector(&workspace_id))
            .or_default()
            .push(selector);
    }
    let mut statement = connection.prepare(
        "SELECT DISTINCT tenant_id FROM mesh_tenant_mappings
         WHERE status = 'ready'
         UNION
         SELECT DISTINCT d.tenant_id FROM devices d
         JOIN tailscale_device_metadata tm ON tm.device_id = d.id
         WHERE tm.registration_method = 'auth_key'
         ORDER BY tenant_id",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    for row in rows {
        let workspace_id = row?;
        groups
            .entry(tenant_policy_selector(&workspace_id))
            .or_default()
            .push(format!("nexo-{workspace_id}@"));
    }
    for members in groups.values_mut() {
        members.sort();
        members.dedup();
    }
    Ok(groups)
}

fn generate_policy_document(
    connection: &Connection,
    grants: &[policy::PolicyGrant],
) -> Result<String> {
    let groups = workspace_policy_groups(connection)?;
    Ok(policy::generate_policy_with_groups(&groups, grants))
}

/// 计算当前工作空间可以展示的策略摘要；完整 Policy 仍由 Server 统一校验，
/// 但目标地址不能把其他工作空间的数据暴露到管理页面。
fn visible_policy_preview_stats(
    grants: &[policy::PolicyGrant],
    tenant_id: &str,
) -> (usize, usize, Vec<String>) {
    let mut affected_targets = BTreeSet::new();
    let mut grant_count = 0;
    let mut ssh_rule_count = 0;
    for grant in grants
        .iter()
        .filter(|grant| grant.source_tenant == tenant_id || grant.target_tenant == tenant_id)
    {
        grant_count += 1;
        if grant.ssh {
            ssh_rule_count += 1;
        }
        affected_targets.extend(grant.destinations.iter().cloned());
    }
    (
        grant_count,
        ssh_rule_count,
        affected_targets.into_iter().collect(),
    )
}

/// 将结构化访问规则解析成 Headscale Grant 目标。
///
/// 设备目标优先使用当前已同步的 Tailscale 地址；共享网络使用 Agent
/// 已确认的期望前缀。地址尚未出现时跳过该条 Grant，保持“已保存但等待
/// 设备状态”的可见性，而不会错误地放大为整个用户空间。
fn access_rule_target(
    connection: &Connection,
    owner_tenant_id: &str,
    target_type: &str,
    target_id: &str,
) -> Result<(Vec<String>, String)> {
    match target_type {
        "device" => {
            let record: Option<(String, Option<String>, Option<String>)> = connection
                .query_row(
                    "SELECT d.name, tm.tailscale_ipv4, tm.tailscale_ipv6
                     FROM devices d
                     LEFT JOIN tailscale_device_metadata tm ON tm.device_id = d.id
                     WHERE d.id = ?1 AND d.tenant_id = ?2",
                    rusqlite::params![target_id, owner_tenant_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((name, ipv4, ipv6)) = record else {
                return Ok((Vec::new(), "设备不存在".to_owned()));
            };
            let destinations = [ipv4, ipv6]
                .into_iter()
                .flatten()
                .filter(|value| !value.trim().is_empty())
                .collect();
            Ok((destinations, name))
        }
        "network" => {
            let record: Option<(String, Option<String>)> = connection
                .query_row(
                    "SELECT n.name, COALESCE(g.desired_prefix, n.current_prefix, n.last_prefix)
                     FROM site_networks n
                     LEFT JOIN gateway_network_states g ON g.site_network_id = n.id
                     WHERE n.id = ?1 AND n.tenant_id = ?2 AND n.enabled = 1",
                    rusqlite::params![target_id, owner_tenant_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            Ok(record
                .map(
                    |(name, prefix)| match prefix.filter(|value| !value.trim().is_empty()) {
                        Some(prefix) => (vec![prefix], name),
                        None => (Vec::new(), name),
                    },
                )
                .unwrap_or_else(|| (Vec::new(), "共享网络不存在".to_owned())))
        }
        "exit_node" => Ok((vec![target_id.to_owned()], "Exit Node".to_owned())),
        "file_share" => Ok((vec![target_id.to_owned()], "文件共享".to_owned())),
        _ => Ok((Vec::new(), "未知目标".to_owned())),
    }
}

/// 从旧版共享网络/SiteLink 和 v0.3 访问规则生成同一份显式 Policy。
///
/// 受让人只作为直接 Source 写入；这里不会读取其他规则再递归展开，因而
/// A 授权 B、B 授权 C 不会自动产生 A→C。
fn build_policy_grants(connection: &Connection) -> Result<Vec<policy::PolicyGrant>> {
    let mut grants = Vec::new();
    let tenant_users: HashMap<String, String> = workspace_policy_groups(connection)?
        .into_keys()
        .filter_map(|group| {
            let tenant_id = group.strip_prefix("group:nexo-workspace-")?.to_owned();
            Some((tenant_id, group))
        })
        .collect();

    // 同一工作空间的设备默认互联。地址来自 Nexo 自己保存的同步投影，
    // 不读取 Headscale 数据库；尚未同步地址的设备会在下一次同步后加入。
    let mut tenant_device_addresses: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT d.tenant_id, tm.tailscale_ipv4, tm.tailscale_ipv6
         FROM devices d JOIN tailscale_device_metadata tm ON tm.device_id = d.id
         WHERE tm.control_plane_state = 'ready'",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    for row in rows {
        let (tenant_id, ipv4, ipv6) = row?;
        let addresses = tenant_device_addresses.entry(tenant_id).or_default();
        for address in [ipv4, ipv6].into_iter().flatten() {
            if !address.trim().is_empty() {
                addresses.insert(address);
            }
        }
    }
    let mut statement = connection.prepare(
        "SELECT tenant_id, tailscale_ipv4, tailscale_ipv6
         FROM mesh_identities WHERE state = 'ready'",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    for row in rows {
        let (tenant_id, ipv4, ipv6) = row?;
        let addresses = tenant_device_addresses.entry(tenant_id).or_default();
        for address in [ipv4, ipv6].into_iter().flatten() {
            if !address.trim().is_empty() {
                addresses.insert(address);
            }
        }
    }
    for (tenant_id, addresses) in tenant_device_addresses {
        if let Some(source) = tenant_users.get(&tenant_id) {
            if !addresses.is_empty() {
                grants.push(policy::PolicyGrant {
                    source_tenant: tenant_id.clone(),
                    target_tenant: tenant_id,
                    sources: vec![source.clone()],
                    destinations: addresses.into_iter().collect(),
                    protocols: Vec::new(),
                    ports: vec!["*".to_owned()],
                    ssh: false,
                });
            }
        }
    }

    let mut tenant_prefixes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
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
        tenant_prefixes.entry(tenant_id).or_default().insert(prefix);
    }
    for (tenant_id, prefixes) in tenant_prefixes {
        if let Some(source) = tenant_users.get(&tenant_id) {
            for prefix in prefixes {
                grants.push(policy::PolicyGrant {
                    source_tenant: tenant_id.clone(),
                    target_tenant: tenant_id.clone(),
                    sources: vec![source.clone()],
                    destinations: vec![prefix],
                    protocols: Vec::new(),
                    ports: vec!["*".to_owned()],
                    ssh: false,
                });
            }
        }
    }

    let mut link_prefixes: BTreeMap<(String, String), (BTreeSet<String>, BTreeSet<String>)> =
        BTreeMap::new();
    let mut statement = connection.prepare(
        "SELECT l.id, l.tenant_id, ln.side, g.desired_prefix
         FROM site_links l
         JOIN site_link_networks ln ON ln.site_link_id = l.id
         JOIN site_networks n ON n.id = ln.site_network_id AND n.enabled = 1
         JOIN gateway_network_states g ON g.site_network_id = n.id
         WHERE l.enabled = 1",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    for row in rows {
        let (link_id, tenant_id, side, prefix) = row?;
        let entry = link_prefixes.entry((tenant_id, link_id)).or_default();
        if side == "left" {
            entry.0.insert(prefix);
        } else {
            entry.1.insert(prefix);
        }
    }
    for ((tenant_id, _link_id), (left_prefixes, right_prefixes)) in link_prefixes {
        if !tenant_users.contains_key(&tenant_id) {
            continue;
        }
        let left_prefixes: Vec<String> = left_prefixes.into_iter().collect();
        let right_prefixes: Vec<String> = right_prefixes.into_iter().collect();
        grants.push(policy::PolicyGrant {
            source_tenant: tenant_id.clone(),
            target_tenant: tenant_id.clone(),
            sources: left_prefixes.clone(),
            destinations: right_prefixes.clone(),
            protocols: Vec::new(),
            ports: vec!["*".to_owned()],
            ssh: false,
        });
        grants.push(policy::PolicyGrant {
            source_tenant: tenant_id.clone(),
            target_tenant: tenant_id,
            sources: right_prefixes,
            destinations: left_prefixes,
            protocols: Vec::new(),
            ports: vec!["*".to_owned()],
            ssh: false,
        });
    }

    let mut statement = connection.prepare(
        "SELECT r.owner_tenant_id, r.target_type, r.target_id, r.protocols_json,
                r.ports_json, r.ssh_enabled, g.grantee_tenant_id
         FROM mesh_access_rules r
         JOIN mesh_access_grants g ON g.rule_id = r.id AND g.status = 'accepted'
         WHERE r.enabled = 1
         ORDER BY r.id, g.grantee_tenant_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)? != 0,
            row.get::<_, String>(6)?,
        ))
    })?;
    for row in rows {
        let (owner_tenant, target_type, target_id, protocols_json, ports_json, ssh, grantee) = row?;
        let (destinations, _) =
            access_rule_target(connection, &owner_tenant, &target_type, &target_id)?;
        if destinations.is_empty() {
            continue;
        }
        let protocols = serde_json::from_str::<Vec<String>>(&protocols_json).unwrap_or_default();
        let ports = serde_json::from_str::<Vec<String>>(&ports_json).unwrap_or_default();
        grants.push(policy::PolicyGrant {
            source_tenant: grantee.clone(),
            target_tenant: owner_tenant,
            sources: vec![tenant_policy_selector(&grantee)],
            destinations,
            protocols,
            ports,
            ssh,
        });
    }
    Ok(grants)
}

type AccessRuleNormalized = (String, String, String, Vec<String>, Vec<String>);
type AccessRuleRecord = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    String,
    Option<String>,
    i64,
    i64,
);

/// 访问控制只保存结构化字段；这里统一做输入归一化，避免前端可以通过
/// 重复协议、空端口或未知目标类型扩大最终 Headscale Policy。
fn normalize_access_rule_request(
    request: &AccessRuleRequest,
) -> Result<AccessRuleNormalized, ApiError> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 128 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "访问规则名称不能为空且不能超过 128 个字符",
        ));
    }
    let target_type = request.target_type.trim().to_ascii_lowercase();
    if !matches!(
        target_type.as_str(),
        "device" | "network" | "exit_node" | "file_share"
    ) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "访问规则目标类型无效",
        ));
    }
    let target_id = request.target_id.trim();
    if target_id.is_empty() || target_id.len() > 256 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "访问规则目标不能为空且不能超过 256 个字符",
        ));
    }
    let protocols = request
        .protocols
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if protocols
        .iter()
        .any(|protocol| !matches!(protocol.as_str(), "tcp" | "udp" | "icmp"))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "访问规则协议只能是 TCP、UDP 或 ICMP",
        ));
    }
    let protocols = deduplicate_strings(protocols);
    let ports = deduplicate_strings(
        request
            .ports
            .iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect(),
    );
    if ports.iter().any(|port| !valid_policy_port(port)) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "访问规则端口必须是 *、单个端口或端口范围",
        ));
    }
    Ok((
        name.to_owned(),
        target_type,
        target_id.to_owned(),
        if protocols.is_empty() {
            vec!["tcp".to_owned(), "udp".to_owned()]
        } else {
            protocols
        },
        if ports.is_empty() {
            vec!["*".to_owned()]
        } else {
            ports
        },
    ))
}

fn deduplicate_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn valid_policy_port(value: &str) -> bool {
    if value == "*" {
        return true;
    }
    let mut parts = value.split('-');
    let Some(start) = parts.next() else {
        return false;
    };
    let end = parts.next().unwrap_or(start);
    if parts.next().is_some() {
        return false;
    }
    let parse = |item: &str| item.parse::<u16>().ok().filter(|port| *port > 0);
    match (parse(start), parse(end)) {
        (Some(start), Some(end)) => start <= end,
        _ => false,
    }
}

fn normalized_access_grantees(owner_tenant_id: &str, requested_ids: &[String]) -> Vec<String> {
    let mut ids = deduplicate_strings(
        requested_ids
            .iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect(),
    );
    ids.retain(|id| id != owner_tenant_id);
    ids
}

/// 在访问规则落库前生成包含候选规则的完整 Policy，并调用 Headscale
/// `policy/check`。这里只做语法和语义校验，不改变当前已生效策略。
#[allow(clippy::too_many_arguments)]
async fn check_access_rule_candidate(
    state: &AppState,
    owner_tenant_id: &str,
    target_type: &str,
    target_id: &str,
    protocols: &[String],
    ports: &[String],
    ssh: bool,
    grantees: &[String],
) -> Result<(), ApiError> {
    let document = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let (destinations, label) =
            access_rule_target(&connection, owner_tenant_id, target_type, target_id).map_err(
                |error| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("无法读取访问规则目标：{error:#}"),
                    )
                },
            )?;
        if destinations.is_empty() {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                format!("目标“{label}”尚未提供可写入策略的地址"),
            ));
        }
        let mut grants = build_policy_grants(&connection).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("无法生成当前访问策略：{error:#}"),
            )
        })?;
        let sources = if grantees.is_empty() {
            vec![tenant_policy_selector(owner_tenant_id)]
        } else {
            grantees
                .iter()
                .map(|tenant_id| tenant_policy_selector(tenant_id))
                .collect()
        };
        grants.push(policy::PolicyGrant {
            source_tenant: owner_tenant_id.to_owned(),
            target_tenant: owner_tenant_id.to_owned(),
            sources,
            destinations,
            protocols: protocols.to_owned(),
            ports: ports.to_owned(),
            ssh,
        });
        generate_policy_document(&connection, &grants).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("无法生成带工作空间用户组的策略：{error:#}"),
            )
        })?
    };
    state
        .headscale
        .check_policy(&document)
        .await
        .map_err(policy_check_api_error)
}

/// 把 Headscale 的底层校验错误转换为管理页面可理解的响应。
///
/// 连接地址、英文网络栈和鉴权细节只写服务端日志；页面只需要知道是策略
/// 内容无效，还是组网服务暂时不可用，避免把容器内部地址暴露给用户。
fn policy_check_api_error(error: PolicyCheckError) -> ApiError {
    let status = if error.is_rejected() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let message = error.user_message();
    if error.is_rejected() {
        tracing::warn!("Headscale 明确拒绝策略内容：{error}");
    } else {
        tracing::error!("Headscale 策略校验服务不可用：{error}");
    }
    ApiError::new(status, message)
}

/// 将策略校验结果映射为稳定的三态 JSON 字段和用户文案。
fn policy_preview_result(
    check: std::result::Result<(), PolicyCheckError>,
) -> (AccessPolicyPreviewStatus, bool, String, Option<String>) {
    match check {
        Ok(()) => (
            AccessPolicyPreviewStatus::Valid,
            true,
            "Headscale Policy 校验通过".to_owned(),
            None,
        ),
        Err(error) if error.is_rejected() => {
            let message = error.user_message();
            tracing::warn!("Headscale 明确拒绝策略内容：{error}");
            (
                AccessPolicyPreviewStatus::Invalid,
                false,
                "策略内容有误".to_owned(),
                Some(message),
            )
        }
        Err(error) => {
            tracing::error!("Headscale 策略校验服务不可用：{error}");
            (
                AccessPolicyPreviewStatus::Unavailable,
                false,
                "组网服务暂不可用，请稍后重新校验".to_owned(),
                Some("组网服务暂不可用，请稍后重新校验".to_owned()),
            )
        }
    }
}

fn access_rule_response(
    connection: &Connection,
    tenant_id: &str,
    id: &str,
) -> Result<AccessRuleResponse, ApiError> {
    let row: Option<AccessRuleRecord> = connection
        .query_row(
            "SELECT r.id, r.owner_tenant_id, COALESCE(u.username, ''), r.name,
                    r.target_type, r.target_id, r.protocols_json, r.ports_json,
                    r.ssh_enabled, r.enabled, r.desired_revision, r.applied_revision,
                    r.apply_status, r.apply_error, r.created_at, r.updated_at
             FROM mesh_access_rules r
             LEFT JOIN users u ON u.id = r.owner_user_id
             WHERE r.id = ?1 AND r.owner_tenant_id = ?2",
            rusqlite::params![id, tenant_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取访问规则"))?;
    let Some((
        id,
        owner_workspace_id,
        owner_username,
        name,
        target_type,
        target_id,
        protocols_json,
        ports_json,
        ssh_enabled,
        enabled,
        desired_revision,
        applied_revision,
        apply_status,
        apply_error,
        created_at,
        updated_at,
    )) = row
    else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "访问规则不存在"));
    };
    let target_label =
        access_rule_target(connection, &owner_workspace_id, &target_type, &target_id)
            .map(|(_, label)| label)
            .unwrap_or_else(|_| target_id.clone());
    let mut statement = connection
        .prepare(
            "SELECT g.grantee_tenant_id, COALESCE(t.name, g.grantee_tenant_id),
                    g.status, g.accepted_at
             FROM mesh_access_grants g
             LEFT JOIN tenants t ON t.id = g.grantee_tenant_id
             WHERE g.rule_id = ?1 ORDER BY g.grantee_tenant_id",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取访问授权"))?;
    let grants = statement
        .query_map([&id], |row| {
            Ok(AccessGrantResponse {
                workspace_id: row.get(0)?,
                workspace_name: row.get(1)?,
                status: row.get(2)?,
                accepted_at: row.get(3)?,
            })
        })
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取访问授权"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "访问授权数据格式无效"))?;
    Ok(AccessRuleResponse {
        id,
        owner_workspace_id,
        owner_username,
        name,
        target_type,
        target_id,
        target_label,
        protocols: serde_json::from_str(&protocols_json).unwrap_or_default(),
        ports: serde_json::from_str(&ports_json).unwrap_or_default(),
        ssh_enabled: ssh_enabled != 0,
        enabled: enabled != 0,
        desired_revision,
        applied_revision,
        apply_status,
        apply_error,
        grants,
        created_at,
        updated_at,
    })
}

async fn list_access_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AccessRuleResponse>>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT id FROM mesh_access_rules
             WHERE owner_tenant_id = ?1 ORDER BY updated_at DESC, id ASC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取访问规则列表"))?;
    let ids = statement
        .query_map([&tenant_id], |row| row.get::<_, String>(0))
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取访问规则列表"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "访问规则列表数据格式无效",
            )
        })?;
    ids.iter()
        .map(|id| access_rule_response(&connection, &tenant_id, id))
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
}

async fn list_access_control_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AccessWorkspaceResponse>>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT id, name FROM tenants
             WHERE id <> ?1 ORDER BY name ASC, id ASC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取工作空间列表"))?;
    let rows = statement
        .query_map([&tenant_id], |row| {
            Ok(AccessWorkspaceResponse {
                id: row.get(0)?,
                name: row.get(1)?,
            })
        })
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取工作空间列表"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "工作空间数据格式无效"))
        .map(Json)
}

async fn create_access_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AccessRuleRequest>,
) -> Result<Json<AccessRuleResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let user_id = auth::current_user_id(&state, &headers)?;
    let (name, target_type, target_id, protocols, ports) = normalize_access_rule_request(&request)?;
    let grantees = normalized_access_grantees(&tenant_id, &request.grantee_workspace_ids);
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let (_, target_label) =
            access_rule_target(&connection, &tenant_id, &target_type, &target_id)
                .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, format!("{error:#}")))?;
        if matches!(target_type.as_str(), "device" | "network")
            && (target_label == "设备不存在" || target_label == "共享网络不存在")
        {
            return Err(ApiError::new(StatusCode::NOT_FOUND, target_label));
        }
        for grantee in &grantees {
            let exists: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM tenants WHERE id = ?1",
                    [grantee],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查授权工作空间")
                })?;
            if exists == 0 {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "授权工作空间不存在"));
            }
        }
    }
    check_access_rule_candidate(
        &state,
        &tenant_id,
        &target_type,
        &target_id,
        &protocols,
        &ports,
        request.ssh_enabled,
        &grantees,
    )
    .await?;
    let id = Uuid::new_v4().to_string();
    {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let (_, target_label) =
            access_rule_target(&connection, &tenant_id, &target_type, &target_id)
                .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, format!("{error:#}")))?;
        if matches!(target_type.as_str(), "device" | "network")
            && (target_label == "设备不存在" || target_label == "共享网络不存在")
        {
            return Err(ApiError::new(StatusCode::NOT_FOUND, target_label));
        }
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始访问规则事务")
        })?;
        transaction
            .execute(
                "INSERT INTO mesh_access_rules
                 (id, owner_tenant_id, owner_user_id, name, target_type, target_id,
                  protocols_json, ports_json, ssh_enabled, enabled, apply_status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'checking')",
                rusqlite::params![
                    id,
                    tenant_id,
                    user_id,
                    name,
                    target_type,
                    target_id,
                    serde_json::to_string(&protocols).unwrap_or_else(|_| "[]".to_owned()),
                    serde_json::to_string(&ports).unwrap_or_else(|_| "[]".to_owned()),
                    i64::from(request.ssh_enabled),
                    i64::from(request.enabled),
                ],
            )
            .map_err(|error| {
                tracing::error!("保存访问规则失败：{error}");
                ApiError::new(StatusCode::CONFLICT, "访问规则名称已存在或保存失败")
            })?;
        insert_access_rule_grants(&transaction, &id, &tenant_id, &grantees)?;
        write_audit_event(
            &transaction,
            &tenant_id,
            "ACCESS_RULE_CREATED",
            "access_rule",
            &id,
        )?;
        transaction.commit().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交访问规则事务")
        })?;
    }
    schedule_policy_reconcile(&state);
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    access_rule_response(&connection, &tenant_id, &id).map(Json)
}

fn insert_access_rule_grants(
    transaction: &rusqlite::Transaction<'_>,
    rule_id: &str,
    owner_tenant_id: &str,
    requested_ids: &[String],
) -> Result<(), ApiError> {
    let mut ids = deduplicate_strings(
        requested_ids
            .iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect(),
    );
    ids.retain(|id| id != owner_tenant_id);
    for grantee in ids {
        let exists: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM tenants WHERE id = ?1",
                [&grantee],
                |row| row.get(0),
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查授权工作空间")
            })?;
        if exists == 0 {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                format!("授权工作空间 {} 不存在", grantee),
            ));
        }
        transaction
            .execute(
                "INSERT INTO mesh_access_grants
                 (rule_id, grantee_tenant_id, status, accepted_at)
                 VALUES (?1, ?2, 'accepted', unixepoch())",
                rusqlite::params![rule_id, grantee],
            )
            .map_err(|_| ApiError::new(StatusCode::CONFLICT, "访问授权已存在或保存失败"))?;
    }
    Ok(())
}

async fn update_access_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<AccessRuleRequest>,
) -> Result<Json<AccessRuleResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let (name, target_type, target_id, protocols, ports) = normalize_access_rule_request(&request)?;
    let grantees = normalized_access_grantees(&tenant_id, &request.grantee_workspace_ids);
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let (_, target_label) =
            access_rule_target(&connection, &tenant_id, &target_type, &target_id)
                .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, format!("{error:#}")))?;
        if matches!(target_type.as_str(), "device" | "network")
            && (target_label == "设备不存在" || target_label == "共享网络不存在")
        {
            return Err(ApiError::new(StatusCode::NOT_FOUND, target_label));
        }
        for grantee in &grantees {
            let exists: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM tenants WHERE id = ?1",
                    [grantee],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查授权工作空间")
                })?;
            if exists == 0 {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "授权工作空间不存在"));
            }
        }
    }
    check_access_rule_candidate(
        &state,
        &tenant_id,
        &target_type,
        &target_id,
        &protocols,
        &ports,
        request.ssh_enabled,
        &grantees,
    )
    .await?;
    {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始访问规则事务")
        })?;
        let changed = transaction
            .execute(
                "UPDATE mesh_access_rules SET name = ?1, target_type = ?2, target_id = ?3,
                 protocols_json = ?4, ports_json = ?5, ssh_enabled = ?6, enabled = ?7,
                 desired_revision = desired_revision + 1, apply_status = 'checking',
                 apply_error = NULL, updated_at = unixepoch()
                 WHERE id = ?8 AND owner_tenant_id = ?9",
                rusqlite::params![
                    name,
                    target_type,
                    target_id,
                    serde_json::to_string(&protocols).unwrap_or_else(|_| "[]".to_owned()),
                    serde_json::to_string(&ports).unwrap_or_else(|_| "[]".to_owned()),
                    i64::from(request.ssh_enabled),
                    i64::from(request.enabled),
                    id,
                    tenant_id,
                ],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新访问规则"))?;
        if changed == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "访问规则不存在"));
        }
        transaction
            .execute("DELETE FROM mesh_access_grants WHERE rule_id = ?1", [&id])
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新访问授权"))?;
        insert_access_rule_grants(&transaction, &id, &tenant_id, &grantees)?;
        write_audit_event(
            &transaction,
            &tenant_id,
            "ACCESS_RULE_UPDATED",
            "access_rule",
            &id,
        )?;
        transaction.commit().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交访问规则事务")
        })?;
    }
    schedule_policy_reconcile(&state);
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    access_rule_response(&connection, &tenant_id, &id).map(Json)
}

async fn delete_access_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let changed = connection
        .execute(
            "UPDATE mesh_access_rules SET enabled = 0, desired_revision = desired_revision + 1,
             apply_status = 'checking', apply_error = NULL, updated_at = unixepoch()
             WHERE id = ?1 AND owner_tenant_id = ?2",
            rusqlite::params![id, tenant_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法撤销访问规则"))?;
    if changed == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "访问规则不存在"));
    }
    let transaction = connection.unchecked_transaction().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "无法开始访问规则审计事务",
        )
    })?;
    write_audit_event(
        &transaction,
        &tenant_id,
        "ACCESS_RULE_DELETED",
        "access_rule",
        &id,
    )?;
    transaction.commit().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "无法提交访问规则审计事务",
        )
    })?;
    schedule_policy_reconcile(&state);
    Ok(Json(DeleteResponse {
        deleted: false,
        pending: true,
        id,
        message: "访问规则已撤销，Headscale Policy 将在后台收敛；失败时会保留重试状态".to_owned(),
    }))
}

/// 校验当前已经保存的完整策略；编辑中的候选规则由下面的 POST 接口处理。
async fn current_access_policy_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AccessPolicyPreviewResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let (document, grant_count, ssh_rule_count, affected_targets) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let grants = build_policy_grants(&connection).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("无法生成当前访问策略：{error:#}"),
            )
        })?;
        let (grant_count, ssh_rule_count, affected_targets) =
            visible_policy_preview_stats(&grants, &tenant_id);
        let document = generate_policy_document(&connection, &grants).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("无法生成带工作空间用户组的策略：{error:#}"),
            )
        })?;
        (document, grant_count, ssh_rule_count, affected_targets)
    };
    let check = state.headscale.check_policy(&document).await;
    let (status, valid, summary, error) = policy_preview_result(check);
    Ok(Json(AccessPolicyPreviewResponse {
        status,
        valid,
        grant_count,
        ssh_rule_count,
        affected_targets,
        summary,
        error,
    }))
}

/// 校验编辑中的候选访问规则；不会改变当前已生效策略。
async fn preview_access_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AccessRuleRequest>,
) -> Result<Json<AccessPolicyPreviewResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let (_, target_type, target_id, protocols, ports) = normalize_access_rule_request(&request)?;
    let grantees = normalized_access_grantees(&tenant_id, &request.grantee_workspace_ids);
    let (destinations, target_label) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        access_rule_target(&connection, &tenant_id, &target_type, &target_id)
            .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, format!("{error:#}")))?
    };
    if destinations.is_empty() {
        return Ok(Json(AccessPolicyPreviewResponse {
            status: AccessPolicyPreviewStatus::Invalid,
            valid: false,
            grant_count: 0,
            ssh_rule_count: 0,
            affected_targets: vec![target_label],
            summary: "目标尚未提供可写入 Policy 的地址".to_owned(),
            error: Some("请先让设备或共享网络完成同步".to_owned()),
        }));
    }
    let (document, grant_count, ssh_rule_count) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        for grantee in &grantees {
            let exists: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM tenants WHERE id = ?1",
                    [grantee],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查授权工作空间")
                })?;
            if exists == 0 {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "授权工作空间不存在"));
            }
        }
        let mut grants = build_policy_grants(&connection).map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("无法生成当前访问策略：{error:#}"),
            )
        })?;
        let sources = if grantees.is_empty() {
            vec![tenant_policy_selector(&tenant_id)]
        } else {
            grantees
                .iter()
                .map(|tenant_id| tenant_policy_selector(tenant_id))
                .collect()
        };
        grants.push(policy::PolicyGrant {
            source_tenant: tenant_id.clone(),
            target_tenant: tenant_id,
            sources,
            destinations: destinations.clone(),
            protocols,
            ports,
            ssh: request.ssh_enabled,
        });
        let grant_count = grants.len();
        let ssh_rule_count = grants.iter().filter(|grant| grant.ssh).count();
        (
            generate_policy_document(&connection, &grants).map_err(|error| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("无法生成带工作空间用户组的策略：{error:#}"),
                )
            })?,
            grant_count,
            ssh_rule_count,
        )
    };
    let check = state.headscale.check_policy(&document).await;
    let (status, valid, summary, error) = policy_preview_result(check);
    Ok(Json(AccessPolicyPreviewResponse {
        status,
        valid,
        grant_count,
        ssh_rule_count,
        affected_targets: destinations,
        summary,
        error,
    }))
}

/// 从 Nexo Desired State 生成显式 tenant→tenant Grants 并推送 Headscale。
/// 网络关闭时对应前缀从下一版策略中消失，但 Mesh 连接本身不受影响。
fn mark_policy_reconcile_error(connection: &Connection, message: &str) -> Result<()> {
    connection.execute(
        "UPDATE mesh_access_rules
         SET apply_status = 'error', apply_error = ?, updated_at = unixepoch()
         WHERE desired_revision > applied_revision OR apply_status IN ('checking', 'error')",
        [message],
    )?;
    Ok(())
}

fn policy_reconcile_error_message(error: &PolicyCheckError) -> String {
    if error.is_rejected() {
        error.user_message()
    } else {
        "组网服务暂不可用，策略将在服务恢复后自动重试".to_owned()
    }
}

async fn reconcile_headscale_policy(state: &AppState) -> Result<()> {
    let (document, rule_ids) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let grants = build_policy_grants(&connection)?;
        let mut statement = connection.prepare(
            "SELECT id FROM mesh_access_rules
             WHERE desired_revision > applied_revision OR apply_status IN ('checking', 'error')",
        )?;
        let rule_ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        (generate_policy_document(&connection, &grants)?, rule_ids)
    };
    if let Err(error) = state.headscale.check_policy(&document).await {
        let message = policy_reconcile_error_message(&error);
        if error.is_rejected() {
            tracing::warn!("后台 Headscale Policy 内容校验未通过：{error}");
        } else {
            tracing::error!("后台 Headscale Policy 校验服务不可用：{error}");
        }
        if let Ok(connection) = state.db.lock() {
            let _ = mark_policy_reconcile_error(&connection, &message);
        }
        return Err(anyhow::Error::new(error));
    }
    if let Err(error) = state.headscale.set_policy(&document).await {
        tracing::error!("后台 Headscale Policy 发布失败，将在服务恢复后重试：{error:#}");
        if let Ok(connection) = state.db.lock() {
            let _ = mark_policy_reconcile_error(
                &connection,
                "组网服务暂不可用，策略将在服务恢复后自动重试",
            );
        }
        return Err(error);
    }
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    for rule_id in rule_ids {
        connection.execute(
            "UPDATE mesh_access_rules
            SET applied_revision = desired_revision,
                 apply_status = CASE WHEN enabled = 1 THEN 'ready' ELSE 'disabled' END,
                 apply_error = NULL,
                 updated_at = unixepoch() WHERE id = ?1",
            [&rule_id],
        )?;
    }
    Ok(())
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
            if let Err(error) = auth::reconcile_pending_mesh_revocations(&state).await {
                tracing::debug!("后台账号组网撤销将在下周期重试：{error:#}");
            }
            if let Err(error) = sync_oidc_nodes(&state).await {
                tracing::debug!("后台 OIDC 节点归属将在下周期重试：{error:#}");
            }
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

fn write_caddy_startup_config(state: &AppState) -> Result<()> {
    let (_, config) = load_caddy_desired_config(state)?;
    state.caddy.write_startup_config(&config)
}

/// Caddy 或 Server 重启后从 SQLite 重新应用 Desired State；任务本身不保存
/// 用户配置，短暂失败只会进入下一轮重试并保留上一份 Applied 配置。
fn spawn_caddy_reconciliation(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            reconcile_caddy_config_best_effort(&state).await;
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

fn ensure_tenant_scope(requested: &str, session_tenant: &str) -> Result<(), ApiError> {
    if requested == session_tenant {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "请求租户与当前管理员会话不匹配",
        ))
    }
}

/// 第二阶段生产组网的唯一放行边界。
///
/// Headscale 的内部 HTTP 地址只能供 Nexo/Caddy 使用；设备真正加入组网时
/// 必须通过已经生效的 HTTPS `mesh.<domain>` 入口。Linux 集成拓扑没有公开域名，
/// 只能显式设置 `NEXO_MESH_ALLOW_INSECURE=true`，该开关不在生产 Compose 中提供。
fn mesh_insecure_override() -> bool {
    env::var("NEXO_MESH_ALLOW_INSECURE")
        .ok()
        .is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
}

fn mesh_application_allowed_with_connection(connection: &Connection) -> bool {
    if mesh_insecure_override() {
        return true;
    }
    connection
        .query_row(
            "SELECT https_enabled, domain, apply_status
             FROM public_domains WHERE is_primary = 1
             ORDER BY updated_at DESC LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? != 0,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .ok()
        .is_some_and(|(https_enabled, domain, status)| {
            https_enabled
                && domain.is_some_and(|value| !value.trim().is_empty())
                && status == "ready"
        })
}

/// 运行时组网资格在数据库 Desired State 之外再确认 Caddy 入口健康度。
///
/// Caddy 停止时 LAN 管理和 TCP Tunnel 仍然应该继续服务，但新的 Mesh
/// Enrollment 与网关路由应用必须暂停；集成测试的内部 Mesh 开关显式绕过
/// 公网入口检查，不改变生产默认安全边界。
async fn mesh_application_allowed(state: &AppState) -> bool {
    let database_allowed = state
        .db
        .lock()
        .ok()
        .is_some_and(|connection| mesh_application_allowed_with_connection(&connection));
    if !database_allowed || mesh_insecure_override() {
        return database_allowed;
    }
    state.caddy.healthy().await
}

fn mesh_restriction_message() -> &'static str {
    "域名与 HTTPS 尚未就绪，新的组网加入和网关应用已暂停"
}

/// 创建一个 15 分钟（或显式指定时长）的待入网凭证。
async fn create_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateEnrollmentRequest>,
) -> Result<Json<CreateEnrollmentResponse>, ApiError> {
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
    if request.tenant_id.trim().is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "tenant_id 不能为空"));
    }
    ensure_tenant_scope(request.tenant_id.trim(), &session_tenant)?;
    let device_name = request
        .device_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    if request.device_name.is_some() && device_name.is_none() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "设备名称不能为空"));
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
             (id, tenant_id, site_id, token_digest, expires_at, requested_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                enrollment_id,
                request.tenant_id,
                request.site_id,
                token.digest,
                token.expires_at,
                device_name,
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
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let result = connection.query_row(
        "SELECT status, expires_at, device_id FROM pending_enrollments
         WHERE id = ?1 AND tenant_id = ?2",
        rusqlite::params![id, tenant_id],
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
                "UPDATE pending_enrollments SET status = 'expired'
                 WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
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
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT id, status, tenant_id, site_id, requested_name, requested_os,
                    requested_architecture, requested_agent_version, expires_at, device_id
             FROM pending_enrollments
             WHERE tenant_id = ?1
             ORDER BY created_at DESC, id ASC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取入网请求列表"))?;
    let rows = statement
        .query_map([tenant_id], |row| {
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
    // 普通用户也需要看到自己工作空间的组网组件状态；真正的全局配置
    // 仍由认证中间件和系统管理员接口边界保护。
    auth::admin_tenant_id(&state, &headers)?;
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
    let mesh_allowed = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        mesh_application_allowed_with_connection(&connection)
    };
    if !mesh_allowed {
        return Ok(Json(MeshStatusResponse {
            status: headscale::MeshComponentStatus::Restricted,
            message: mesh_restriction_message().to_owned(),
        }));
    }
    // 正式 HTTPS 已标记 READY 后，仍需确认 Caddy Admin API 可响应；否则
    // `mesh.<domain>` 入口不可用，但 LAN 管理和 TCP Tunnel 不应被连带停止。
    if !mesh_insecure_override() && !state.caddy.healthy().await {
        return Ok(Json(MeshStatusResponse {
            status: headscale::MeshComponentStatus::Restricted,
            message: "公网 HTTPS 入口暂不可用，异地组网入口受限".to_owned(),
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

/// 返回官方客户端所需的登录服务器地址和平台清单。浏览器授权流程由
/// Tailscale 客户端发起，Headscale 会根据本次登录生成带上下文的授权地址。
async fn tailscale_client_config(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TailscaleClientConfigResponse>, ApiError> {
    auth::admin_tenant_id(&state, &headers)?;
    let login_server = state.headscale_runtime.server_url();
    Ok(Json(TailscaleClientConfigResponse {
        browser_authorization_url: None,
        login_server,
        supported_platforms: ["Linux", "Windows", "macOS", "iOS", "Android", "tvOS"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        notes: vec![
            "请在官方 Tailscale 客户端填写登录服务器并开始连接，客户端会打开一次性授权页面"
                .to_owned(),
            "授权完成后，设备会先进入隔离列表，认领后才加入当前工作空间".to_owned(),
        ],
    }))
}

/// 创建官方 Tailscale Auth Key。明文只在本次响应返回，数据库只保存摘要；
/// `reusable`、`ephemeral` 和标签原样交给 Headscale 官方 API。
async fn create_tailscale_auth_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTailscaleAuthKeyRequest>,
) -> Result<Json<TailscaleAuthKeyResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let user_id = auth::current_user_id(&state, &headers)?;
    let label = request.label.trim().to_owned();
    if label.is_empty() || label.len() > 80 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Auth Key 名称不能为空且不能超过 80 个字符",
        ));
    }
    if request
        .tags
        .iter()
        .any(|tag| tag.trim().is_empty() || tag.len() > 128)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "标签不能为空且不能超过 128 个字符",
        ));
    }
    let ttl_seconds =
        request
            .ttl_seconds
            .unwrap_or(if request.ephemeral { 86_400 } else { 604_800 });
    if !(60..=2_592_000).contains(&ttl_seconds) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Auth Key 有效期必须在 1 分钟到 30 天之间",
        ));
    }
    let expires_at = unix_now().saturating_add(ttl_seconds);
    let headscale_user_id = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT headscale_user_id FROM mesh_tenant_mappings WHERE tenant_id = ?1 AND status = 'ready'",
                [&tenant_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取组网用户映射"))?
    };
    let headscale_user_id = if let Some(id) = headscale_user_id {
        id
    } else {
        let user = state
            .headscale
            .ensure_user(&format!("nexo-{tenant_id}"))
            .await
            .map_err(|error| {
                ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    format!("无法创建 Headscale 用户：{error:#}"),
                )
            })?;
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .execute(
                "INSERT INTO mesh_tenant_mappings (tenant_id, headscale_user_id, status)
                 VALUES (?1, ?2, 'ready')
                 ON CONFLICT(tenant_id) DO UPDATE SET headscale_user_id = excluded.headscale_user_id,
                 status = 'ready', updated_at = CURRENT_TIMESTAMP",
                rusqlite::params![tenant_id, user.id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存组网用户映射"))?;
        user.id
    };
    let expiration = format_headscale_expiration(expires_at.max(0) as u64);
    let key = state
        .headscale
        .create_pre_auth_key_with_options(
            &headscale_user_id,
            &HeadscaleAuthKeyOptions {
                reusable: request.reusable,
                ephemeral: request.ephemeral,
                expiration,
                acl_tags: request.tags.clone(),
            },
        )
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("无法创建 Headscale Auth Key：{error:#}"),
            )
        })?;
    let plaintext = key.key.clone().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "Headscale 未返回 Auth Key 明文，已停止发布",
        )
    })?;
    let id = Uuid::new_v4().to_string();
    let now = unix_now();
    let key_digest = hex::encode(Sha256::digest(plaintext.as_bytes()));
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .execute(
            "INSERT INTO tailscale_auth_keys
             (id, tenant_id, user_id, headscale_key_id, key_digest, label, reusable, ephemeral, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                id,
                tenant_id,
                user_id,
                key.id,
                key_digest,
                label,
                i64::from(request.reusable),
                i64::from(request.ephemeral),
                expires_at,
            ],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存 Auth Key 元数据"))?;
    tracing::info!("已创建官方客户端 Auth Key（明文仅返回本次响应）");
    Ok(Json(TailscaleAuthKeyResponse {
        id,
        label,
        key: Some(plaintext),
        login_server: state.headscale_runtime.server_url(),
        reusable: request.reusable,
        ephemeral: request.ephemeral,
        expires_at,
        state: "issued".to_owned(),
        created_at: now,
    }))
}

async fn list_tailscale_auth_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TailscaleAuthKeyResponse>>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    // 过期状态在读取时惰性收敛，避免 UI 继续把已经不能使用的密钥显示为
    // issued；Headscale 仍是实际凭证状态的最终来源，Nexo 只维护展示投影。
    connection
        .execute(
            "UPDATE tailscale_auth_keys SET state = 'expired'
             WHERE tenant_id = ?1 AND state = 'issued' AND expires_at <= unixepoch()",
            [&tenant_id],
        )
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法更新 Auth Key 过期状态",
            )
        })?;
    let mut statement = connection
        .prepare(
            "SELECT id, label, reusable, ephemeral, expires_at, state, created_at
             FROM tailscale_auth_keys WHERE tenant_id = ?1 ORDER BY created_at DESC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取 Auth Key 列表"))?;
    let rows = statement
        .query_map([tenant_id], |row| {
            Ok(TailscaleAuthKeyResponse {
                id: row.get(0)?,
                label: row.get(1)?,
                key: None,
                login_server: String::new(),
                reusable: row.get::<_, i64>(2)? != 0,
                ephemeral: row.get::<_, i64>(3)? != 0,
                expires_at: row.get(4)?,
                state: row.get(5)?,
                created_at: row.get(6)?,
            })
        })
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取 Auth Key 列表"))?;
    rows.map(|row| {
        row.map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Auth Key 数据格式无效"))
    })
    .collect::<Result<Vec<_>, _>>()
    .map(Json)
}

async fn revoke_tailscale_auth_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<RecheckResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let key_id: String = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT headscale_key_id FROM tailscale_auth_keys WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取 Auth Key"))?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Auth Key 不存在"))?
    };
    state
        .headscale
        .expire_pre_auth_key(&key_id)
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("无法吊销 Auth Key：{error:#}"),
            )
        })?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .execute(
            "UPDATE tailscale_auth_keys SET state = 'revoked' WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![id, tenant_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存 Auth Key 状态"))?;
    Ok(Json(RecheckResponse {
        accepted: true,
        message: "Auth Key 已吊销".to_owned(),
    }))
}

/// 从 Headscale 官方节点 API 同步未知节点。未知节点只进入隔离表，
/// 在管理员明确认领前不会得到 Nexo 工作空间访问权限。
/// OIDC 节点在进入隔离表前会依据稳定 providerId 自动归属到 Nexo 账号。
async fn sync_oidc_nodes(state: &AppState) -> Result<()> {
    let nodes = state.headscale.list_nodes().await?;
    let mut changed = false;
    for node in nodes {
        let Some(headscale_user) = node.user.as_ref() else {
            continue;
        };
        let Some(provider_id) = headscale_user
            .provider_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        else {
            continue;
        };
        let account: Option<(String, String)> = {
            let connection = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            connection
                .query_row(
                    "SELECT a.nexo_user_id, a.workspace_id
                     FROM mesh_oidc_accounts a
                     JOIN users u ON u.id = a.nexo_user_id
                     WHERE a.provider_id = ?1 AND u.enabled = 1",
                    [provider_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
        };
        let Some((user_id, workspace_id)) = account else {
            continue;
        };
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let transaction = connection.unchecked_transaction()?;
        let duplicate_account: Option<String> = transaction
            .query_row(
                "SELECT nexo_user_id FROM mesh_oidc_accounts
                 WHERE headscale_user_id = ?1 AND nexo_user_id <> ?2",
                rusqlite::params![headscale_user.id, user_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(other_user_id) = duplicate_account {
            tracing::error!(
                node_id = %node.id,
                user_id = %user_id,
                other_user_id = %other_user_id,
                "Headscale OIDC 用户 ID 同时映射到多个 Nexo 账号，节点保持隔离"
            );
            continue;
        }
        transaction.execute(
            "UPDATE mesh_oidc_accounts
             SET headscale_user_id = ?1, sync_status = 'ready', last_error = NULL,
                 updated_at = unixepoch()
             WHERE nexo_user_id = ?2",
            rusqlite::params![headscale_user.id, user_id],
        )?;
        let existing: Option<(String, String)> = transaction
            .query_row(
                "SELECT nexo_device_id, tenant_id FROM mesh_identities
                 WHERE headscale_node_id = ?1",
                [&node.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((device_id, existing_workspace_id)) = existing {
            if existing_workspace_id != workspace_id {
                tracing::error!(
                    node_id = %node.id,
                    workspace_id = %workspace_id,
                    existing_workspace_id = %existing_workspace_id,
                    "OIDC 节点已绑定其他工作空间，拒绝静默改绑"
                );
                continue;
            }
            update_headscale_node_projection(&transaction, &device_id, &node)?;
            transaction.commit()?;
            changed = true;
            continue;
        }

        let device_id = Uuid::new_v4().to_string();
        let device_name = if node.name.trim().is_empty() {
            format!("oidc-node-{}", node.id)
        } else {
            node.name.clone()
        };
        transaction.execute(
            "INSERT INTO devices
             (id, tenant_id, name, os, architecture, status, capabilities_json,
              enrolled_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'unknown', 'unknown', ?4, '[]', CURRENT_TIMESTAMP,
                     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            rusqlite::params![
                device_id,
                workspace_id,
                device_name,
                if node.online { "online" } else { "offline" }
            ],
        )?;
        let tags_json = serde_json::to_string(&node.tags)?;
        let ipv4 = node
            .ip_addresses
            .iter()
            .find(|value| value.contains('.'))
            .cloned();
        let ipv6 = node
            .ip_addresses
            .iter()
            .find(|value| value.contains(':'))
            .cloned();
        transaction.execute(
            "INSERT INTO tailscale_device_metadata
             (device_id, user_id, registration_method, tags_json, tailscale_ipv4,
              tailscale_ipv6, expires_at, control_plane_state, external_node,
              created_at, updated_at)
             VALUES (?1, ?2, 'oidc', ?3, ?4, ?5, ?6, 'ready', 0, unixepoch(), unixepoch())",
            rusqlite::params![
                device_id,
                user_id,
                tags_json,
                ipv4,
                ipv6,
                parse_headscale_expiration(node.expiry.as_deref())
            ],
        )?;
        transaction.execute(
            "INSERT INTO mesh_identities
             (nexo_device_id, tenant_id, headscale_node_id, state, tailscale_ipv4,
              tailscale_ipv6, hostname, online, last_verified_at, updated_at)
             VALUES (?1, ?2, ?3, 'ready', ?4, ?5, ?6, ?7, unixepoch(), unixepoch())",
            rusqlite::params![
                device_id,
                workspace_id,
                node.id,
                ipv4,
                ipv6,
                node.name,
                i64::from(node.online)
            ],
        )?;
        transaction.execute(
            "UPDATE tailscale_external_nodes
             SET claimed_device_id = ?1, claim_state = 'claimed', last_seen_at = unixepoch()
             WHERE node_id = ?2",
            rusqlite::params![device_id, node.id],
        )?;
        transaction.commit()?;
        tracing::info!(
            node_id = %node.id,
            user_id = %user_id,
            workspace_id = %workspace_id,
            "OIDC 节点已自动归属 Nexo 工作空间"
        );
        changed = true;
    }
    if changed {
        schedule_policy_reconcile(state);
    }
    Ok(())
}

fn update_headscale_node_projection(
    transaction: &rusqlite::Transaction<'_>,
    device_id: &str,
    node: &HeadscaleNode,
) -> rusqlite::Result<()> {
    let ipv4 = node
        .ip_addresses
        .iter()
        .find(|value| value.contains('.'))
        .cloned();
    let ipv6 = node
        .ip_addresses
        .iter()
        .find(|value| value.contains(':'))
        .cloned();
    let tags_json = serde_json::to_string(&node.tags).unwrap_or_else(|_| "[]".to_owned());
    transaction.execute(
        "UPDATE mesh_identities
         SET tailscale_ipv4 = COALESCE(?1, tailscale_ipv4),
             tailscale_ipv6 = COALESCE(?2, tailscale_ipv6),
             hostname = COALESCE(NULLIF(?3, ''), hostname), online = ?4,
             last_verified_at = unixepoch(), updated_at = unixepoch()
         WHERE nexo_device_id = ?5",
        rusqlite::params![ipv4, ipv6, node.name, i64::from(node.online), device_id],
    )?;
    transaction.execute(
        "UPDATE tailscale_device_metadata
         SET tags_json = ?1, tailscale_ipv4 = COALESCE(?2, tailscale_ipv4),
             tailscale_ipv6 = COALESCE(?3, tailscale_ipv6), expires_at = ?4,
             control_plane_state = 'ready', updated_at = unixepoch()
         WHERE device_id = ?5 AND registration_method = 'oidc'",
        rusqlite::params![
            tags_json,
            ipv4,
            ipv6,
            parse_headscale_expiration(node.expiry.as_deref()),
            device_id
        ],
    )?;
    Ok(())
}

async fn sync_tailscale_external_nodes(state: &AppState) -> Result<()> {
    sync_oidc_nodes(state).await?;
    let nodes = state.headscale.list_nodes().await?;
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    for node in nodes {
        let known: Option<String> = connection
            .query_row(
                "SELECT nexo_device_id FROM mesh_identities WHERE headscale_node_id = ?1",
                [&node.id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(device_id) = known {
            let ipv4 = node
                .ip_addresses
                .iter()
                .find(|value| value.contains('.'))
                .cloned();
            let ipv6 = node
                .ip_addresses
                .iter()
                .find(|value| value.contains(':'))
                .cloned();
            let tags_json = serde_json::to_string(&node.tags)?;
            let expires_at = parse_headscale_expiration(node.expiry.as_deref());
            connection.execute(
                "UPDATE mesh_identities SET online = ?1,
                 tailscale_ipv4 = COALESCE(?2, tailscale_ipv4),
                 tailscale_ipv6 = COALESCE(?3, tailscale_ipv6),
                 updated_at = CURRENT_TIMESTAMP WHERE nexo_device_id = ?4",
                rusqlite::params![i64::from(node.online), ipv4, ipv6, device_id],
            )?;
            connection.execute(
                "UPDATE tailscale_device_metadata
                 SET tags_json = ?1,
                     tailscale_ipv4 = COALESCE(?2, tailscale_ipv4),
                     tailscale_ipv6 = COALESCE(?3, tailscale_ipv6),
                     expires_at = ?4,
                     updated_at = unixepoch()
                 WHERE device_id = ?5",
                rusqlite::params![tags_json, ipv4, ipv6, expires_at, device_id],
            )?;
            continue;
        }
        let node_json = serde_json::to_string(&node)?;
        connection.execute(
            "INSERT INTO tailscale_external_nodes
             (node_id, node_name, node_json, discovered_at, last_seen_at, claim_state)
             VALUES (?1, ?2, ?3, unixepoch(), unixepoch(), 'isolated')
             ON CONFLICT(node_id) DO UPDATE SET node_name = excluded.node_name,
             node_json = excluded.node_json, last_seen_at = unixepoch()",
            rusqlite::params![node.id, node.name, node_json],
        )?;
    }
    Ok(())
}

async fn list_tailscale_external_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TailscaleExternalNodeResponse>>, ApiError> {
    // 未知节点没有工作空间归属，只有全局管理员可以查看并决定认领目标。
    // 普通用户不能通过这个实例级列表探测其他用户的设备或抢先认领节点。
    auth::authorize_admin(&state, &headers)?;
    sync_tailscale_external_nodes(&state)
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("同步 Headscale 节点失败：{error:#}"),
            )
        })?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT node_id, node_name, node_json, claim_state, discovered_at, last_seen_at
             FROM tailscale_external_nodes WHERE claim_state = 'isolated'
             ORDER BY last_seen_at DESC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取外部节点"))?;
    let rows = statement
        .query_map([], |row| {
            let node_json: String = row.get(2)?;
            let node: HeadscaleNode = serde_json::from_str(&node_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            Ok(TailscaleExternalNodeResponse {
                node_id: row.get(0)?,
                name: row.get(1)?,
                online: node.online,
                addresses: node.ip_addresses,
                claim_state: row.get(3)?,
                discovered_at: row.get(4)?,
                last_seen_at: row.get(5)?,
            })
        })
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取外部节点"))?;
    rows.map(|row| {
        row.map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "外部节点数据格式无效"))
    })
    .collect::<Result<Vec<_>, _>>()
    .map(Json)
}

async fn claim_tailscale_external_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
    body: Option<Json<ClaimTailscaleNodeRequest>>,
) -> Result<Json<DeviceResponse>, ApiError> {
    // 认领会把外部节点绑定到当前工作空间，属于全局归属决策，不能由普通
    // 用户通过伪造请求体或切换 Header 抢占其他工作空间的节点。
    auth::authorize_admin(&state, &headers)?;
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let owner_user_id = auth::current_user_id(&state, &headers)?;
    let requested_name = body
        .and_then(|Json(value)| value.name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let node = state
        .headscale
        .list_nodes()
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("无法读取 Headscale 节点：{error:#}"),
            )
        })?
        .into_iter()
        .find(|node| node.id == node_id)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Headscale 节点不存在"))?;
    let mapped_headscale_user_id = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT headscale_user_id FROM mesh_tenant_mappings
                 WHERE tenant_id = ?1 AND status = 'ready'",
                [&tenant_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取组网用户映射"))?
    };
    let headscale_user_id = if let Some(user_id) = mapped_headscale_user_id {
        user_id
    } else {
        state
            .headscale
            .ensure_user(&format!("nexo-{tenant_id}"))
            .await
            .map_err(|error| {
                ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    format!("无法创建 Headscale 用户：{error:#}"),
                )
            })?
            .id
    };
    let device_id = Uuid::new_v4().to_string();
    let device_name = requested_name.unwrap_or_else(|| {
        if node.name.trim().is_empty() {
            format!("官方客户端-{}", node.id)
        } else {
            node.name.clone()
        }
    });
    let ipv4 = node
        .ip_addresses
        .iter()
        .find(|value| value.contains('.'))
        .cloned();
    let ipv6 = node
        .ip_addresses
        .iter()
        .find(|value| value.contains(':'))
        .cloned();
    let tags_json = serde_json::to_string(&node.tags).map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("无法保存官方客户端标签：{error}"),
        )
    })?;
    let expires_at = parse_headscale_expiration(node.expiry.as_deref());
    let now = unix_now();
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection.unchecked_transaction().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "无法开始外部节点认领事务",
        )
    })?;
    let already_claimed: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM mesh_identities WHERE headscale_node_id = ?1",
            [&node.id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查节点归属"))?;
    if already_claimed > 0 {
        return Err(ApiError::new(StatusCode::CONFLICT, "该节点已经被认领"));
    }
    transaction
        .execute(
            "INSERT INTO mesh_tenant_mappings (tenant_id, headscale_user_id, status)
             VALUES (?1, ?2, 'ready')
             ON CONFLICT(tenant_id) DO UPDATE SET headscale_user_id = excluded.headscale_user_id,
             status = 'ready', updated_at = CURRENT_TIMESTAMP",
            rusqlite::params![tenant_id, headscale_user_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存组网用户映射"))?;
    transaction
        .execute(
            "INSERT INTO devices (id, tenant_id, name, os, architecture, status, capabilities_json, enrolled_at, updated_at)
             VALUES (?1, ?2, ?3, 'unknown', 'unknown', ?4, '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            rusqlite::params![device_id, tenant_id, device_name, if node.online { "online" } else { "offline" }],
        )
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "无法创建官方客户端设备"))?;
    transaction
        .execute(
            "INSERT INTO tailscale_device_metadata
             (device_id, user_id, registration_method, tags_json, tailscale_ipv4, tailscale_ipv6,
              expires_at, control_plane_state, external_node, created_at, updated_at)
             VALUES (?1, ?2, 'browser', ?3, ?4, ?5, ?6, 'ready', 1, ?7, ?7)",
            rusqlite::params![
                device_id,
                owner_user_id,
                tags_json,
                ipv4,
                ipv6,
                expires_at,
                now
            ],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存官方客户端归属"))?;
    transaction
        .execute(
            "INSERT INTO mesh_identities
             (nexo_device_id, tenant_id, headscale_node_id, state, tailscale_ipv4, online)
             VALUES (?1, ?2, ?3, 'ready', ?4, ?5)",
            rusqlite::params![device_id, tenant_id, node.id, ipv4, i64::from(node.online)],
        )
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "无法绑定官方客户端组网身份"))?;
    transaction
        .execute(
            "UPDATE tailscale_external_nodes SET claimed_device_id = ?1, claim_state = 'claimed', last_seen_at = unixepoch()
             WHERE node_id = ?2",
            rusqlite::params![device_id, node.id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新外部节点认领状态"))?;
    transaction.commit().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "无法提交外部节点认领事务",
        )
    })?;
    schedule_policy_reconcile(&state);
    let response = list_devices_for_tenant(&connection, &tenant_id)?;
    response
        .into_iter()
        .find(|device| device.id == device_id)
        .map(Json)
        .ok_or_else(|| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "认领成功但无法读取设备"))
}

/// 管理员批准已提交的 Agent 请求，并为其 CSR 签发客户端证书。
async fn approve_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<EnrollmentStatusResponse>, ApiError> {
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
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
             FROM pending_enrollments WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![id, session_tenant],
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
    if !mesh_application_allowed(state).await {
        return Err(anyhow::anyhow!(mesh_restriction_message()));
    }
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
        endpoint: state.headscale_runtime.server_url(),
        auth_key: plaintext,
        auth_key_id: key.id,
        hostname: mesh_hostname(tenant_id, device_name, device_id),
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

pub(crate) fn format_headscale_expiration(epoch_seconds: u64) -> String {
    // Headscale 接受 RFC3339；这里使用 UTC 的 Unix 秒转换，避免引入额外时间库。
    let date = time::OffsetDateTime::from_unix_timestamp(epoch_seconds as i64)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    date.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "2099-01-01T00:00:00Z".to_owned())
}

/// 将 Headscale 节点的 RFC3339 过期时间投影为 Web 使用的 Unix 秒；
/// 无效或缺失的值保持为空，不能用猜测时间覆盖真实状态。
fn parse_headscale_expiration(value: Option<&str>) -> Option<i64> {
    value
        .and_then(|value| {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
        })
        .map(|date| date.unix_timestamp())
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
             status = 'awaiting_approval', requested_name = COALESCE(requested_name, ?2),
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
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
    if request.tenant_id.trim().is_empty()
        || request.site_id.trim().is_empty()
        || request.name.trim().is_empty()
        || request.publisher_device_id.trim().is_empty()
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "租户、站点、名称和设备不能为空",
        ));
    }
    let prefix: IpNet = request
        .prefix
        .parse()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "本地网络地址不是有效 CIDR"))?;
    let prefix = prefix.trunc();
    validate_published_network(prefix).map_err(|error| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("本地网络不能共享：{error}"),
        )
    })?;
    ensure_tenant_scope(request.tenant_id.trim(), &session_tenant)?;
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
    let is_manual = request.source == SiteNetworkSourceRequest::Manual;
    if !is_manual && request.interface_id.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "自动探测模式必须选择已探测的网卡",
        ));
    }
    let gateway_requirement = GatewayDeviceRequirement {
        tenant_id: &request.tenant_id,
        site_id: &request.site_id,
        device_id: &request.publisher_device_id,
        interface_id: (!is_manual).then_some(request.interface_id.trim()),
        prefix,
        require_online: false,
        require_detected_network: !is_manual,
    };
    ensure_gateway_device(&connection, &gateway_requirement)?;
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
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, 'checking')",
            rusqlite::params![
                id,
                request.tenant_id,
                request.site_id,
                request.name,
                request.publisher_device_id,
                if is_manual {
                    None::<String>
                } else {
                    Some(request.interface_id.trim().to_owned())
                },
                if matches!(prefix, IpNet::V4(_)) {
                    "ipv4"
                } else {
                    "ipv6"
                },
                if is_manual {
                    "manual"
                } else {
                    "direct_interface"
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
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let ids = {
        let mut statement = connection
            .prepare(
                "SELECT n.id FROM site_networks n
                 JOIN gateway_network_states g ON g.site_network_id = n.id
                 WHERE n.tenant_id = ?1
                 ORDER BY n.updated_at DESC, n.id ASC",
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取共享网络列表")
            })?;
        let rows = statement
            .query_map([tenant_id], |row| row.get::<_, String>(0))
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
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let response = read_site_network_response(&connection, &id)?;
    ensure_tenant_scope(&response.tenant_id, &tenant_id)?;
    Ok(Json(response))
}

/// 请求删除共享网络：先发布新的关闭 revision，待 Agent 与 Headscale 均确认
/// 撤销后，由 `finalize_requested_resource_deletions` 在状态事务内物理删除。
async fn delete_site_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
    let (publisher_device_id, revision, already_pending) =
        {
            let mut connection = state
                .db
                .lock()
                .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
            let transaction = connection.transaction().map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法开始共享网络删除事务",
                )
            })?;
            let (tenant_id, publisher_device_id, current_revision, deletion_requested, link_count):
            (String, String, i64, i64, i64) = transaction
            .query_row(
                "SELECT n.tenant_id, n.publisher_device_id, g.desired_revision,
                        n.deletion_requested,
                        (SELECT COUNT(*) FROM site_link_networks ln
                         WHERE ln.site_network_id = n.id)
                 FROM site_networks n
                 JOIN gateway_network_states g ON g.site_network_id = n.id
                 WHERE n.id = ?1 AND n.tenant_id = ?2",
                rusqlite::params![id, session_tenant],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查共享网络"))?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "共享网络不存在"))?;
            if link_count > 0 {
                let message = format!("共享网络仍被 {link_count} 个互联关系引用，请先删除互联关系");
                tracing::warn!(network_id = %id, "拒绝删除共享网络：{message}");
                return Err(ApiError::new(StatusCode::CONFLICT, message));
            }
            if deletion_requested != 0 {
                transaction.commit().map_err(|_| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "无法提交共享网络删除状态",
                    )
                })?;
                (publisher_device_id, current_revision, true)
            } else {
                let revision = current_revision.saturating_add(1).max(1);
                transaction
                    .execute(
                        "UPDATE site_networks
                     SET enabled = 0, deletion_requested = 1,
                         apply_status = 'checking', apply_error = '等待路由撤销确认',
                         updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?1 AND tenant_id = ?2",
                        rusqlite::params![id, session_tenant],
                    )
                    .map_err(|_| {
                        ApiError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "无法保存共享网络删除请求",
                        )
                    })?;
                transaction
                    .execute(
                        "UPDATE gateway_network_states
                     SET desired_revision = ?1, apply_status = 'checking', applied_prefix = NULL,
                         apply_error = '等待 Agent 与 Headscale 确认路由撤销',
                         updated_at = CURRENT_TIMESTAMP
                     WHERE site_network_id = ?2",
                        rusqlite::params![revision, id],
                    )
                    .map_err(|_| {
                        ApiError::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "无法生成共享网络关闭 revision",
                        )
                    })?;
                write_audit_event(
                    &transaction,
                    &tenant_id,
                    "SITE_NETWORK_DELETE_REQUESTED",
                    "site_network",
                    &id,
                )?;
                transaction.commit().map_err(|_| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "无法提交共享网络删除事务",
                    )
                })?;
                (publisher_device_id, revision, false)
            }
        };
    schedule_policy_reconcile(&state);
    tracing::info!(network_id = %id, device_id = %publisher_device_id, revision, "共享网络已进入等待删除状态");
    Ok(Json(DeleteResponse {
        deleted: false,
        pending: true,
        id,
        message: if already_pending {
            "共享网络正在等待 Agent 与 Headscale 完成路由撤销".to_owned()
        } else {
            "已请求删除共享网络，等待 Agent 与 Headscale 完成路由撤销".to_owned()
        },
    }))
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
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始共享网络事务"))?;
    let (tenant_id, current_enabled, deletion_requested): (String, i64, i64) = transaction
        .query_row(
            "SELECT tenant_id, enabled, deletion_requested FROM site_networks
             WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![id, session_tenant],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "共享网络不存在"))?;
    if deletion_requested != 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "共享网络正在等待删除，不能再修改开关",
        ));
    }
    if (current_enabled != 0) != enabled {
        transaction
            .execute(
                "UPDATE site_networks
                 SET enabled = ?1, apply_status = 'checking', apply_error = NULL,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?2 AND tenant_id = ?3",
                rusqlite::params![if enabled { 1 } else { 0 }, id, session_tenant],
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
                    n.publisher_device_id, d.name, n.interface_id, n.source,
                    g.desired_prefix, g.applied_prefix,
                    g.desired_revision, n.enabled, g.apply_status, g.apply_error,
                    n.deletion_requested
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
                    source: if row.get::<_, String>(8)? == "manual" {
                        "manual".to_owned()
                    } else {
                        "detected".to_owned()
                    },
                    gateway_address: None,
                    desired_prefix: row.get(9)?,
                    applied_prefix: row.get(10)?,
                    desired_revision: row.get(11)?,
                    enabled: row.get::<_, i64>(12)? != 0,
                    apply_status: parse_apply_status(&row.get::<_, String>(13)?),
                    apply_error: row.get(14)?,
                    deletion_pending: row.get::<_, i64>(15)? != 0,
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
                response.interface_id.as_deref(),
                &response.desired_prefix,
            )?;
            let health_input = GatewayNetworkHealthInput {
                device_id: &response.publisher_device_id,
                interface_id: response.interface_id.as_deref(),
                prefix: &response.desired_prefix,
                enabled: response.enabled,
                apply_status: response.apply_status,
                apply_error: response.apply_error.as_deref(),
                require_detected_network: response.source == "detected",
            };
            let (health_status, health_error) = gateway_network_health(connection, &health_input)?;
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
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let ids = {
        let mut statement = connection
            .prepare(
                "SELECT id FROM site_links
                 WHERE tenant_id = ?1
                 ORDER BY updated_at DESC, id ASC",
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点互联列表")
            })?;
        let ids = statement
            .query_map([tenant_id], |row| row.get::<_, String>(0))
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

fn normalized_network_ids(ids: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for id in ids.iter().map(|id| id.trim()).filter(|id| !id.is_empty()) {
        if !result.iter().any(|existing| existing == id) {
            result.push(id.to_owned());
        }
    }
    result
}

#[derive(Debug, Default, Clone)]
struct ResolvedNextHops {
    ipv4: Option<String>,
    ipv6: Option<String>,
}

fn families(networks: &[LinkNetwork]) -> BTreeSet<String> {
    networks
        .iter()
        .map(|network| network.address_family.clone())
        .collect()
}

/// 读取一侧的多个共享网络，并验证它们确实由同一个 Site Gateway 发布。
fn load_networks_for_link(
    connection: &rusqlite::Transaction<'_>,
    tenant_id: &str,
    network_ids: &[String],
    site_id: &str,
) -> Result<Vec<LinkNetwork>, ApiError> {
    if network_ids.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "每侧至少选择一个共享网络",
        ));
    }
    let mut networks = Vec::with_capacity(network_ids.len());
    for network_id in network_ids {
        networks.push(load_network_for_link(
            connection, tenant_id, network_id, site_id,
        )?);
    }
    let device_id = networks[0].device_id.clone();
    if networks
        .iter()
        .any(|network| network.device_id != device_id)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "同一侧的共享网络必须由同一台 Site Gateway 发布",
        ));
    }
    Ok(networks)
}

fn parse_next_hop(value: &str, family: &str) -> Result<std::net::IpAddr, ApiError> {
    let address = value.trim().parse::<std::net::IpAddr>().map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("{family} 下一跳不是有效 IP 地址"),
        )
    })?;
    let matches_family = matches!(
        (family, address),
        ("ipv4", std::net::IpAddr::V4(_)) | ("ipv6", std::net::IpAddr::V6(_))
    );
    if !matches_family {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("{family} 下一跳的地址族不匹配"),
        ));
    }
    Ok(address)
}

/// 下一跳必须是该网关最新能力报告中的 LAN 地址；缺少显式输入时仅为兼容
/// 旧单网段请求，自动取同地址族的第一条已上报地址。
fn resolve_next_hops(
    connection: &rusqlite::Transaction<'_>,
    side: &str,
    device_id: &str,
    required_families: &BTreeSet<String>,
    request: &SiteLinkNextHops,
) -> Result<ResolvedNextHops, ApiError> {
    let report_json: Option<String> = connection
        .query_row(
            "SELECT report_json FROM device_capability_reports WHERE device_id = ?1",
            [device_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取网关地址报告"))?;
    let report: GatewayCapabilityReport = report_json
        .ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "网关尚未上报可用的 LAN 地址"))
        .and_then(|json| {
            serde_json::from_str(&json)
                .map_err(|_| ApiError::new(StatusCode::CONFLICT, "网关地址报告格式无效"))
        })?;
    let mut result = ResolvedNextHops::default();
    for family in required_families {
        let provided = request.value(side, family);
        let candidate = provided.or_else(|| {
            report.local_networks.iter().find_map(|network| {
                let address = network
                    .gateway_address
                    .as_deref()?
                    .parse::<std::net::IpAddr>()
                    .ok()?;
                let same_family = matches!(
                    (family.as_str(), address),
                    ("ipv4", std::net::IpAddr::V4(_)) | ("ipv6", std::net::IpAddr::V6(_))
                );
                same_family.then(|| address.to_string())
            })
        });
        let candidate = candidate.ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                format!("{side}侧缺少 {family} 下一跳，请填写网关最新 LAN 地址"),
            )
        })?;
        let address = parse_next_hop(&candidate, family)?;
        let reported = report.local_networks.iter().any(|network| {
            network
                .gateway_address
                .as_deref()
                .and_then(|value| value.parse::<std::net::IpAddr>().ok())
                == Some(address)
        });
        if !reported {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                format!("{side}侧下一跳必须来自网关最近上报的 LAN 地址"),
            ));
        }
        match family.as_str() {
            "ipv4" => result.ipv4 = Some(address.to_string()),
            "ipv6" => result.ipv6 = Some(address.to_string()),
            _ => unreachable!("数据库地址族只有 ipv4/ipv6"),
        }
    }
    Ok(result)
}

/// 校验一条 SiteLink 的全部网段、地址族和下一跳，并返回规范化结果。
fn validate_site_link_selection(
    connection: &rusqlite::Transaction<'_>,
    tenant_id: &str,
    left_site_id: &str,
    left_network_ids: &[String],
    right_site_id: &str,
    right_network_ids: &[String],
    next_hops: &SiteLinkNextHops,
) -> Result<
    (
        Vec<LinkNetwork>,
        Vec<LinkNetwork>,
        ResolvedNextHops,
        ResolvedNextHops,
    ),
    ApiError,
> {
    let left = load_networks_for_link(connection, tenant_id, left_network_ids, left_site_id)?;
    let right = load_networks_for_link(connection, tenant_id, right_network_ids, right_site_id)?;
    let left_families = families(&left);
    let right_families = families(&right);
    if left_families != right_families {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "两侧共享网络的 IPv4/IPv6 地址族集合必须一致",
        ));
    }
    for local in &left {
        let prefix = local.prefix.parse::<IpNet>().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "左侧共享网络数据无效")
        })?;
        let gateway_requirement = GatewayDeviceRequirement {
            tenant_id,
            site_id: left_site_id,
            device_id: &local.device_id,
            interface_id: local.interface_id.as_deref(),
            prefix,
            require_online: true,
            require_detected_network: local.source != "manual",
        };
        ensure_gateway_device(connection, &gateway_requirement)?;
        for remote in &right {
            let remote_prefix = remote.prefix.parse::<IpNet>().map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "右侧共享网络数据无效")
            })?;
            if networks_overlap(prefix, remote_prefix) {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    format!(
                        "网络地址冲突：{} 与 {} 使用了重叠的网络地址",
                        prefix, remote_prefix
                    ),
                ));
            }
        }
    }
    for network in &right {
        let prefix = network.prefix.parse::<IpNet>().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "右侧共享网络数据无效")
        })?;
        let gateway_requirement = GatewayDeviceRequirement {
            tenant_id,
            site_id: right_site_id,
            device_id: &network.device_id,
            interface_id: network.interface_id.as_deref(),
            prefix,
            require_online: true,
            require_detected_network: network.source != "manual",
        };
        ensure_gateway_device(connection, &gateway_requirement)?;
    }
    let left_hops = resolve_next_hops(
        connection,
        "left",
        &left[0].device_id,
        &left_families,
        next_hops,
    )?;
    let right_hops = resolve_next_hops(
        connection,
        "right",
        &right[0].device_id,
        &right_families,
        next_hops,
    )?;
    Ok((left, right, left_hops, right_hops))
}

/// 创建双向站点互联的 Desired State，并在提交前阻止重叠网段。
async fn create_site_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateSiteLinkRequest>,
) -> Result<Json<SiteLinkResponse>, ApiError> {
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
    if request.tenant_id.trim().is_empty()
        || request.left_site_id.trim().is_empty()
        || request.right_site_id.trim().is_empty()
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "租户和两侧站点不能为空",
        ));
    }
    ensure_tenant_scope(request.tenant_id.trim(), &session_tenant)?;
    if request.left_site_id == request.right_site_id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "站点互联必须选择两个不同站点",
        ));
    }
    let mut left_network_ids = normalized_network_ids(&request.left_network_ids);
    let mut right_network_ids = normalized_network_ids(&request.right_network_ids);
    if left_network_ids.is_empty() || right_network_ids.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "两侧至少选择一个共享网络",
        ));
    }
    let mut left_site_id = request.left_site_id.clone();
    let mut right_site_id = request.right_site_id.clone();
    let mut left_hop = ResolvedNextHops {
        ipv4: request.next_hops.value("left", "ipv4"),
        ipv6: request.next_hops.value("left", "ipv6"),
    };
    let mut right_hop = ResolvedNextHops {
        ipv4: request.next_hops.value("right", "ipv4"),
        ipv6: request.next_hops.value("right", "ipv6"),
    };
    if left_site_id > right_site_id {
        std::mem::swap(&mut left_site_id, &mut right_site_id);
        std::mem::swap(&mut left_network_ids, &mut right_network_ids);
        std::mem::swap(&mut left_hop, &mut right_hop);
    }
    let mut canonical_hops = SiteLinkNextHops::default();
    canonical_hops.left.ipv4 = left_hop.ipv4;
    canonical_hops.left.ipv6 = left_hop.ipv6;
    canonical_hops.right.ipv4 = right_hop.ipv4;
    canonical_hops.right.ipv6 = right_hop.ipv6;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始站点互联事务"))?;
    let (left, right, left_hops, right_hops) = validate_site_link_selection(
        &transaction,
        &request.tenant_id,
        &left_site_id,
        &left_network_ids,
        &right_site_id,
        &right_network_ids,
        &canonical_hops,
    )?;
    let duplicate: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM site_links WHERE tenant_id = ?1 AND left_site_id = ?2 AND right_site_id = ?3",
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
             (id, tenant_id, left_site_id, right_site_id, left_ipv4_next_hop,
              left_ipv6_next_hop, right_ipv4_next_hop, right_ipv6_next_hop,
              enabled, apply_status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, 'checking')",
            rusqlite::params![
                id,
                request.tenant_id,
                left_site_id,
                right_site_id,
                left_hops.ipv4,
                left_hops.ipv6,
                right_hops.ipv4,
                right_hops.ipv6,
            ],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存站点互联"))?;
    for network in left {
        transaction
            .execute(
                "INSERT INTO site_link_networks (site_link_id, site_network_id, side) VALUES (?1, ?2, 'left')",
                rusqlite::params![id, network.id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存左侧网络映射"))?;
    }
    for network in right {
        transaction
            .execute(
                "INSERT INTO site_link_networks (site_link_id, site_network_id, side) VALUES (?1, ?2, 'right')",
                rusqlite::params![id, network.id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存右侧网络映射"))?;
    }
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

/// 事务式替换 SiteLink 两侧网段和下一跳。站点本身来自已有关系，编辑不会
/// 改变拓扑端点；任何网段变化都会清除旧确认并提升 revision。
async fn update_site_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<UpdateSiteLinkRequest>,
) -> Result<Json<SiteLinkResponse>, ApiError> {
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
    let tenant_id = request
        .tenant_id
        .as_deref()
        .filter(|tenant| !tenant.trim().is_empty())
        .unwrap_or(&session_tenant)
        .to_owned();
    ensure_tenant_scope(&tenant_id, &session_tenant)?;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection.transaction().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "无法开始站点互联编辑事务",
        )
    })?;
    let (left_site_id, right_site_id, old_revision, deletion_requested): (
        String,
        String,
        i64,
        i64,
    ) = transaction
        .query_row(
            "SELECT left_site_id, right_site_id, apply_revision, deletion_requested
             FROM site_links WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![id, tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点互联"))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "站点互联不存在"))?;
    if deletion_requested != 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "站点互联正在等待删除，不能编辑",
        ));
    }
    let existing_ids = |side: &str| -> Result<Vec<String>, ApiError> {
        let mut statement = transaction
            .prepare("SELECT site_network_id FROM site_link_networks WHERE site_link_id = ?1 AND side = ?2 ORDER BY site_network_id")
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点网络映射"))?;
        let values = statement
            .query_map(rusqlite::params![id, side], |row| row.get(0))
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点网络映射"))?
            .collect::<rusqlite::Result<Vec<String>>>()
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "站点网络映射格式无效")
            })?;
        Ok(values)
    };
    let left_existing = existing_ids("left")?;
    let right_existing = existing_ids("right")?;
    let left_ids = request
        .left_network_ids
        .as_deref()
        .map(normalized_network_ids)
        .unwrap_or(left_existing);
    let right_ids = request
        .right_network_ids
        .as_deref()
        .map(normalized_network_ids)
        .unwrap_or(right_existing);
    let (left, right, left_hops, right_hops) = validate_site_link_selection(
        &transaction,
        &tenant_id,
        &left_site_id,
        &left_ids,
        &right_site_id,
        &right_ids,
        &request.next_hops,
    )?;
    let network_revision: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(g.desired_revision), 0)
             FROM site_link_networks ln JOIN gateway_network_states g
               ON g.site_network_id = ln.site_network_id WHERE ln.site_link_id = ?1",
            [&id],
            |row| row.get(0),
        )
        .unwrap_or_default();
    let revision = old_revision.max(network_revision).saturating_add(1).max(1);
    transaction
        .execute(
            "UPDATE site_links SET left_ipv4_next_hop = ?1, left_ipv6_next_hop = ?2,
             right_ipv4_next_hop = ?3, right_ipv6_next_hop = ?4,
             apply_revision = ?5, apply_status = 'checking', apply_error = NULL,
             updated_at = CURRENT_TIMESTAMP WHERE id = ?6 AND tenant_id = ?7",
            rusqlite::params![
                left_hops.ipv4,
                left_hops.ipv6,
                right_hops.ipv4,
                right_hops.ipv6,
                revision,
                id,
                tenant_id,
            ],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存站点互联下一跳"))?;
    transaction
        .execute(
            "DELETE FROM site_link_networks WHERE site_link_id = ?1",
            [&id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法替换站点网络映射"))?;
    for network in left {
        transaction.execute(
            "INSERT INTO site_link_networks (site_link_id, site_network_id, side) VALUES (?1, ?2, 'left')",
            rusqlite::params![id, network.id],
        ).map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存左侧网络映射"))?;
    }
    for network in right {
        transaction.execute(
            "INSERT INTO site_link_networks (site_link_id, site_network_id, side) VALUES (?1, ?2, 'right')",
            rusqlite::params![id, network.id],
        ).map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存右侧网络映射"))?;
    }
    transaction
        .execute(
            "DELETE FROM gateway_route_applies WHERE site_link_id = ?1",
            [&id],
        )
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法清理旧的互联路由确认",
            )
        })?;
    transaction
        .execute(
            "DELETE FROM site_link_route_confirmations WHERE site_link_id = ?1",
            [&id],
        )
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法清理旧的静态路由确认",
            )
        })?;
    write_audit_event(
        &transaction,
        &tenant_id,
        "SITE_LINK_UPDATED",
        "site_link",
        &id,
    )?;
    transaction.commit().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "无法提交站点互联编辑事务",
        )
    })?;
    schedule_policy_reconcile(&state);
    Ok(Json(read_site_link_response(&connection, &id)?))
}

/// 查询站点互联当前应用状态。
async fn get_site_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SiteLinkResponse>, ApiError> {
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let response = read_site_link_response(&connection, &id)?;
    ensure_tenant_scope(&response.tenant_id, &tenant_id)?;
    Ok(Json(response))
}

/// 请求删除站点互联：生成高于两侧网络 revision 的关闭版本。两侧 Agent
/// 和 Headscale 都确认当前版本已撤销后，状态事务会自动清理映射与确认记录。
async fn delete_site_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<DeleteResponse>, ApiError> {
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
    let (revision, already_pending) = {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法开始站点互联删除事务",
            )
        })?;
        let (tenant_id, current_revision, network_revision, deletion_requested): (
            String,
            i64,
            i64,
            i64,
        ) = transaction
            .query_row(
                "SELECT l.tenant_id, l.apply_revision,
                        COALESCE((SELECT MAX(g.desired_revision)
                                  FROM site_link_networks ln
                                  JOIN gateway_network_states g
                                    ON g.site_network_id = ln.site_network_id
                                  WHERE ln.site_link_id = l.id), 0),
                        l.deletion_requested
                 FROM site_links l WHERE l.id = ?1 AND l.tenant_id = ?2",
                rusqlite::params![id, session_tenant],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查站点互联"))?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "站点互联不存在"))?;
        if deletion_requested != 0 {
            transaction.commit().map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法提交站点互联删除状态",
                )
            })?;
            (current_revision, true)
        } else {
            let revision = current_revision
                .max(network_revision)
                .saturating_add(1)
                .max(1);
            transaction
                .execute(
                    "UPDATE site_links
                     SET enabled = 0, deletion_requested = 1, apply_revision = ?1,
                         apply_status = 'checking', apply_error = '等待两侧路由撤销确认',
                         updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?2 AND tenant_id = ?3",
                    rusqlite::params![revision, id, session_tenant],
                )
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "无法保存站点互联删除请求",
                    )
                })?;
            write_audit_event(
                &transaction,
                &tenant_id,
                "SITE_LINK_DELETE_REQUESTED",
                "site_link",
                &id,
            )?;
            transaction.commit().map_err(|_| {
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法提交站点互联删除事务",
                )
            })?;
            (revision, false)
        }
    };
    schedule_policy_reconcile(&state);
    tracing::info!(site_link_id = %id, revision, "站点互联已进入等待删除状态");
    Ok(Json(DeleteResponse {
        deleted: false,
        pending: true,
        id,
        message: if already_pending {
            "站点互联正在等待两侧 Agent 与 Headscale 完成路由撤销".to_owned()
        } else {
            "已请求删除站点互联，等待两侧 Agent 与 Headscale 完成路由撤销".to_owned()
        },
    }))
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
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始站点互联事务"))?;
    let (tenant_id, current_enabled, deletion_requested): (String, i64, i64) = transaction
        .query_row(
            "SELECT tenant_id, enabled, deletion_requested FROM site_links
             WHERE id = ?1 AND tenant_id = ?2",
            rusqlite::params![id, session_tenant],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "站点互联不存在"))?;
    if deletion_requested != 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "站点互联正在等待删除，不能再修改开关",
        ));
    }
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
                 WHERE id = ?2 AND tenant_id = ?3",
                rusqlite::params![if enabled { 1 } else { 0 }, id, session_tenant],
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
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
    {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        if !mesh_application_allowed_with_connection(&connection) {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                mesh_restriction_message(),
            ));
        }
    }
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
                 WHERE d.id = ?1 AND d.tenant_id = ?2",
                rusqlite::params![device_id, session_tenant],
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
    let session_tenant = auth::admin_tenant_id(&state, &headers)?;
    let mut connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始路由确认事务"))?;
    let (tenant_id, deletion_requested): (String, i64) = transaction
        .query_row(
            "SELECT tenant_id, deletion_requested FROM site_links
             WHERE id = ?1 AND tenant_id = ?3
               AND (left_site_id = ?2 OR right_site_id = ?2)",
            rusqlite::params![id, site_id, session_tenant],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "站点互联或站点不存在"))?;
    if deletion_requested != 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "站点互联正在等待删除，不能再确认静态路由",
        ));
    }
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
    let tenant_id = auth::admin_tenant_id(&state, &headers)?;
    let device_ids: Vec<String> = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let deletion_requested = connection
            .query_row(
                "SELECT deletion_requested FROM site_links
                 WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点互联"))?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "站点互联不存在"))?;
        if deletion_requested != 0 {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "站点互联正在等待删除，不能重复检测",
            ));
        }
        let mut statement = connection
            .prepare(
                "SELECT n.publisher_device_id
                 FROM site_link_networks ln JOIN site_networks n
                   ON n.id = ln.site_network_id
                 WHERE ln.site_link_id = ?1 AND n.tenant_id = ?2",
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取站点互联设备")
            })?;
        let ids = statement
            .query_map(rusqlite::params![id.as_str(), tenant_id], |row| row.get(0))
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
                 updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?1 AND tenant_id = ?2",
                rusqlite::params![id, tenant_id],
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
        left_ipv4_next_hop,
        left_ipv6_next_hop,
        right_ipv4_next_hop,
        right_ipv6_next_hop,
        enabled,
        apply_status,
        apply_error,
        deletion_pending,
    ) = connection
        .query_row(
            "SELECT l.id, l.tenant_id, l.left_site_id, l.right_site_id,
                    ls.name, rs.name, l.left_ipv4_next_hop, l.left_ipv6_next_hop,
                    l.right_ipv4_next_hop, l.right_ipv6_next_hop, l.enabled,
                    l.apply_status, l.apply_error, l.deletion_requested
             FROM site_links l JOIN sites ls ON ls.id = l.left_site_id
             JOIN sites rs ON rs.id = l.right_site_id WHERE l.id = ?1",
            [id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, i64>(10)? != 0,
                    parse_apply_status(&row.get::<_, String>(11)?),
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, i64>(13)? != 0,
                ))
            },
        )
        .map_err(|error| {
            tracing::debug!(error = %error, "读取站点互联路由引导失败");
            ApiError::new(StatusCode::NOT_FOUND, "站点互联不存在")
        })?;
    let read_side = |side: &str| -> Result<Vec<SiteLinkNetworkSummary>, ApiError> {
        let mut statement = connection
            .prepare(
                "SELECT n.id, n.name, g.desired_prefix, n.source, n.address_family,
                        n.publisher_device_id, d.name, g.apply_status, n.interface_id
                 FROM site_link_networks ln
                 JOIN site_networks n ON n.id = ln.site_network_id
                 JOIN devices d ON d.id = n.publisher_device_id
                 JOIN gateway_network_states g ON g.site_network_id = n.id
                 WHERE ln.site_link_id = ?1 AND ln.side = ?2 ORDER BY n.id",
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取互联网段"))?;
        let rows = statement
            .query_map(rusqlite::params![id, side], |row| {
                let network_id: String = row.get(0)?;
                let device_id: String = row.get(5)?;
                let prefix: String = row.get(2)?;
                let interface_id: Option<String> = row.get(8)?;
                let gateway_address =
                    find_gateway_address(connection, &device_id, interface_id.as_deref(), &prefix)
                        .unwrap_or(None);
                Ok(SiteLinkNetworkSummary {
                    id: network_id,
                    name: row.get(1)?,
                    prefix,
                    source: if row.get::<_, String>(3)? == "manual" {
                        "manual".to_owned()
                    } else {
                        "detected".to_owned()
                    },
                    address_family: row.get(4)?,
                    publisher_device_id: device_id,
                    publisher_device_name: row.get(6)?,
                    gateway_address,
                    apply_status: parse_apply_status(&row.get::<_, String>(7)?),
                })
            })
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取互联网段"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "互联网络数据格式无效"))
    };
    let left_networks = read_side("left")?;
    let right_networks = read_side("right")?;
    if left_networks.is_empty() || right_networks.is_empty() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "站点互联缺少两侧网段"));
    }
    let hop_for = |side: &str, family: &str| -> Option<String> {
        match (side, family) {
            ("left", "ipv4") => left_ipv4_next_hop.clone(),
            ("left", "ipv6") => left_ipv6_next_hop.clone(),
            ("right", "ipv4") => right_ipv4_next_hop.clone(),
            ("right", "ipv6") => right_ipv6_next_hop.clone(),
            _ => None,
        }
    };
    let gateway_for_family =
        |networks: &[SiteLinkNetworkSummary], family: &str| -> Option<String> {
            networks
                .iter()
                .find(|network| network.address_family == family)
                .and_then(|network| network.gateway_address.clone())
        };
    let left_gateway_address = left_networks
        .iter()
        .find_map(|network| network.gateway_address.clone())
        .or_else(|| hop_for("left", &left_networks[0].address_family));
    let right_gateway_address = right_networks
        .iter()
        .find_map(|network| network.gateway_address.clone())
        .or_else(|| hop_for("right", &right_networks[0].address_family));
    let left_confirmation = site_link_route_confirmation(connection, &id, &left_site_id)?;
    let right_confirmation = site_link_route_confirmation(connection, &id, &right_site_id)?;
    let mut static_routes = Vec::new();
    for network in &right_networks {
        static_routes.push(StaticRouteGuide {
            router_site_id: left_site_id.clone(),
            destination_site_id: right_site_id.clone(),
            router_site_name: left_site_name.clone(),
            destination_site_name: right_site_name.clone(),
            destination_prefix: network.prefix.clone(),
            next_hop: hop_for("left", &network.address_family)
                .or_else(|| gateway_for_family(&left_networks, &network.address_family)),
            router_confirmed: left_confirmation.is_some(),
        });
    }
    for network in &left_networks {
        static_routes.push(StaticRouteGuide {
            router_site_id: right_site_id.clone(),
            destination_site_id: left_site_id.clone(),
            router_site_name: right_site_name.clone(),
            destination_site_name: left_site_name.clone(),
            destination_prefix: network.prefix.clone(),
            next_hop: hop_for("right", &network.address_family)
                .or_else(|| gateway_for_family(&right_networks, &network.address_family)),
            router_confirmed: right_confirmation.is_some(),
        });
    }
    let route_statuses = read_site_link_route_statuses(
        connection,
        &id,
        &left_site_id,
        &right_site_id,
        &left_networks,
        &right_networks,
    )?;
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
        (&left_networks, &left_site_id),
        (&right_networks, &right_site_id),
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
        left_gateway_address,
        right_gateway_address,
        left_networks,
        right_networks,
        static_routes,
        route_statuses,
        route_confirmations,
        enabled,
        apply_status,
        apply_error,
        deletion_pending,
        health_status,
        health_error,
    })
}

/// 将数据库中的逐路由应用记录聚合成 UI 可直接展示的阶段状态；按目标
/// 网段去重，避免多网段站点因本地网段数量产生笛卡尔积重复行。
fn read_site_link_route_statuses(
    connection: &Connection,
    link_id: &str,
    left_site_id: &str,
    right_site_id: &str,
    left_networks: &[SiteLinkNetworkSummary],
    right_networks: &[SiteLinkNetworkSummary],
) -> Result<Vec<SiteLinkRouteStatus>, ApiError> {
    type RouteApplyRow = (String, String, String, Option<String>, Option<i64>);
    let mut statuses = Vec::new();
    let mut append = |router_site_id: &str,
                      destination_site_id: &str,
                      local_networks: &[SiteLinkNetworkSummary],
                      remote_networks: &[SiteLinkNetworkSummary]|
     -> Result<(), ApiError> {
        let device_id = local_networks
            .first()
            .map(|network| network.publisher_device_id.as_str())
            .unwrap_or_default();
        for remote in remote_networks {
            let row: Option<RouteApplyRow> = connection
                .query_row(
                    "SELECT local_status, control_plane_status, remote_status, last_error,
                            unixepoch(last_checked_at)
                     FROM gateway_route_applies
                     WHERE device_id = ?1 AND network_id = ?2 AND site_link_id = ?3",
                    rusqlite::params![device_id, remote.id, link_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取逐路由状态")
                })?;
            let (device_status, control_plane_status, remote_status, error, checked_at) = row
                .unwrap_or_else(|| {
                    (
                        "pending".to_owned(),
                        "pending".to_owned(),
                        "pending".to_owned(),
                        Some("等待设备发布该远端网段".to_owned()),
                        None,
                    )
                });
            statuses.push(SiteLinkRouteStatus {
                network_id: remote.id.clone(),
                router_site_id: router_site_id.to_owned(),
                destination_site_id: destination_site_id.to_owned(),
                destination_prefix: remote.prefix.clone(),
                address_family: remote.address_family.clone(),
                device_status,
                control_plane_status,
                remote_status,
                error,
                checked_at,
            });
        }
        Ok(())
    };
    append(left_site_id, right_site_id, left_networks, right_networks)?;
    append(right_site_id, left_site_id, right_networks, left_networks)?;
    Ok(statuses)
}

fn site_link_route_confirmation(
    connection: &Connection,
    link_id: &str,
    site_id: &str,
) -> Result<Option<i64>, ApiError> {
    connection
        .query_row(
            "SELECT unixepoch(confirmed_at) FROM site_link_route_confirmations
             WHERE site_link_id = ?1 AND site_id = ?2",
            rusqlite::params![link_id, site_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取静态路由确认"))
}

/// 读取共享网络绑定的网卡名称，用于从能力报告中找到对应的 Agent 地址。
fn find_network_interface(
    connection: &Connection,
    network_id: &str,
) -> Result<Option<String>, ApiError> {
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
    interface_id: Option<&str>,
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
    // Linux 接口编号可能在容器重启后交换（例如控制网与 LAN 的 eth0/eth1），
    // CIDR 才是用户选择的稳定标识。优先沿用原接口，找不到时按同一网段回退。
    let network = report
        .local_networks
        .iter()
        .find(|network| {
            interface_id.is_some_and(|interface| network.interface_id == interface)
                && network.prefix == prefix_text
        })
        .or_else(|| {
            report
                .local_networks
                .iter()
                .find(|network| network.prefix == prefix_text)
        });
    Ok(network.and_then(|network| {
        let address = network
            .gateway_address
            .as_deref()?
            .parse::<std::net::IpAddr>()
            .ok()?;
        prefix.contains(&address).then(|| address.to_string())
    }))
}

/// 共享网络健康检查的输入快照。
///
/// 自动探测网络会额外要求网卡和 CIDR 仍出现在 Agent 报告中；手动网络只
/// 使用设备、组网、转发和控制端状态。将两种模式放进同一快照，避免调用者
/// 在不同路径上遗漏这条产品边界。
struct GatewayNetworkHealthInput<'a> {
    device_id: &'a str,
    interface_id: Option<&'a str>,
    prefix: &'a str,
    enabled: bool,
    apply_status: ApplyStatus,
    apply_error: Option<&'a str>,
    require_detected_network: bool,
}

/// 计算共享网络自身的健康状态。
///
/// 健康状态只使用 Nexo 已经拥有的观测值：设备在线状态、最近能力报告、本地网段
/// 是否仍然存在，以及 Desired / Applied 应用阶段；不会把一次成功的 CLI 调用
/// 推断成 Headscale 已批准，也不会主动探测或修改用户的局域网。
fn gateway_network_health(
    connection: &Connection,
    input: &GatewayNetworkHealthInput<'_>,
) -> Result<(GatewayHealthStatus, Option<String>), ApiError> {
    if input.apply_status == ApplyStatus::Failed {
        return Ok((
            GatewayHealthStatus::Failed,
            Some(input.apply_error.unwrap_or("共享网络应用失败").to_owned()),
        ));
    }
    // `enabled=false` 只表示 Desired State 已关闭；撤销仍可能在 Agent
    // 或 Headscale 中进行。只有完整应用状态进入 Disabled 才能对外宣称关闭。
    if input.apply_status == ApplyStatus::Disabled {
        return Ok((GatewayHealthStatus::Disabled, None));
    }
    if input.enabled && !mesh_application_allowed_with_connection(connection) {
        return Ok((
            GatewayHealthStatus::Degraded,
            Some(mesh_restriction_message().to_owned()),
        ));
    }
    let (device_health, device_error) = inspect_gateway_device(
        connection,
        input.device_id,
        input.interface_id,
        input.prefix,
        false,
        input.require_detected_network,
    )?;
    if device_health == GatewayHealthStatus::Failed {
        return Ok((device_health, device_error));
    }
    if device_health == GatewayHealthStatus::Degraded {
        return Ok((device_health, device_error));
    }
    if input.apply_status == ApplyStatus::Ready {
        let ready: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM gateway_route_applies
                 WHERE device_id = ?1 AND network_id = (
                   SELECT id FROM site_networks WHERE publisher_device_id = ?1
                   AND (?2 IS NULL OR interface_id = ?2) AND id IN (
                     SELECT site_network_id FROM gateway_network_states
                     WHERE desired_prefix = ?3)
                 ) AND site_link_id = '' AND local_status = 'applied'
                 AND control_plane_status = 'serving'",
                rusqlite::params![input.device_id, input.interface_id, input.prefix],
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
    left: (&[SiteLinkNetworkSummary], &str),
    right: (&[SiteLinkNetworkSummary], &str),
    enabled: bool,
    apply_status: ApplyStatus,
    apply_error: Option<&str>,
) -> Result<(GatewayHealthStatus, Option<String>), ApiError> {
    if apply_status == ApplyStatus::Failed {
        return Ok((
            GatewayHealthStatus::Failed,
            Some(apply_error.unwrap_or("站点互联应用失败").to_owned()),
        ));
    }
    // Link 关闭后仍需等待两侧路由撤销 ACK；在此之前继续显示检查中，
    // 避免 UI 或验收脚本把旧内核路由误认为已经清理。
    if apply_status == ApplyStatus::Disabled {
        return Ok((GatewayHealthStatus::Disabled, None));
    }
    if enabled && !mesh_application_allowed_with_connection(connection) {
        return Ok((
            GatewayHealthStatus::Degraded,
            Some(mesh_restriction_message().to_owned()),
        ));
    }
    let inspect_side = |networks: &[SiteLinkNetworkSummary]| -> Result<(GatewayHealthStatus, Option<String>), ApiError> {
        let mut degraded = None;
        for network in networks {
            let interface_id = find_network_interface(connection, &network.id)?;
            let (health, error) = inspect_gateway_device(
                connection,
                &network.publisher_device_id,
                interface_id.as_deref(),
                &network.prefix,
                true,
                network.source == "detected",
            )?;
            if health == GatewayHealthStatus::Failed {
                return Ok((health, error));
            }
            if health == GatewayHealthStatus::Degraded && degraded.is_none() {
                degraded = Some(error);
            }
        }
        Ok(degraded
            .map(|error| (GatewayHealthStatus::Degraded, error))
            .unwrap_or((GatewayHealthStatus::Ready, None)))
    };
    let (left_health, left_error) = inspect_side(left.0)?;
    let (right_health, right_error) = inspect_side(right.0)?;
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
        let routes_ready = |local: &[SiteLinkNetworkSummary],
                            remote: &[SiteLinkNetworkSummary]|
         -> Result<bool, ApiError> {
            let device_id = local
                .first()
                .map(|network| network.publisher_device_id.as_str())
                .unwrap_or_default();
            for network in remote {
                let ready: bool = connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM gateway_route_applies
                      WHERE device_id = ?1 AND network_id = ?2 AND site_link_id = ?3
                        AND local_status = 'applied' AND control_plane_status = 'serving'
                        AND remote_status = 'accepted')",
                        rusqlite::params![device_id, network.id, link_id],
                        |row| row.get(0),
                    )
                    .unwrap_or(false);
                if !ready {
                    return Ok(false);
                }
            }
            Ok(true)
        };
        if routes_ready(left.0, right.0)? && routes_ready(right.0, left.0)? {
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
    _interface_id: Option<&str>,
    prefix: &str,
    site_gateway: bool,
    require_detected_network: bool,
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
    if capability == CapabilityState::Unavailable
        && reason != Some(GatewayCapabilityReason::IpForwardingDisabled)
    {
        return Ok((
            GatewayHealthStatus::Failed,
            Some(gateway_capability_message(reason)),
        ));
    }
    let parsed_prefix = prefix
        .parse::<IpNet>()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "共享网络前缀格式无效"))?;
    if let Some(message) = gateway_forwarding_error(&report, parsed_prefix) {
        return Ok((GatewayHealthStatus::Failed, Some(message)));
    }
    if require_detected_network
        && !report
            .local_networks
            .iter()
            .any(|network| network.prefix == prefix)
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

/// 按目标网段地址族返回精确的宿主机转发缺失原因。
fn gateway_forwarding_error(report: &GatewayCapabilityReport, prefix: IpNet) -> Option<String> {
    if forwarding_enabled_for_prefix(report.ipv4_forwarding, report.ipv6_forwarding, prefix) {
        return None;
    }
    let family = if matches!(prefix, IpNet::V4(_)) {
        "IPv4"
    } else {
        "IPv6"
    };
    Some(format!("设备未开启 {family} 转发"))
}

/// 站点互联两侧选中的共享网络及其网关设备。
struct LinkNetwork {
    id: String,
    prefix: String,
    device_id: String,
    interface_id: Option<String>,
    source: String,
    address_family: String,
}

/// 创建或更新 SiteLink 时对单侧网关的校验输入。
///
/// 设备归属、能力报告和地址族转发必须在同一处复核；调用方只负责把
/// 站点关系中的网络快照转换为这个结构，避免不同 API 路径出现校验漂移。
struct GatewayDeviceRequirement<'a> {
    tenant_id: &'a str,
    site_id: &'a str,
    device_id: &'a str,
    interface_id: Option<&'a str>,
    prefix: IpNet,
    require_online: bool,
    require_detected_network: bool,
}

fn load_network_for_link(
    connection: &rusqlite::Transaction<'_>,
    tenant_id: &str,
    network_id: &str,
    site_id: &str,
) -> Result<LinkNetwork, ApiError> {
    connection
        .query_row(
            "SELECT n.id, g.desired_prefix, n.publisher_device_id,
                    n.interface_id, n.source, n.address_family
             FROM gateway_network_states g JOIN site_networks n
             ON n.id = g.site_network_id
             WHERE g.site_network_id = ?1 AND n.tenant_id = ?2 AND n.site_id = ?3
             AND n.enabled = 1 AND n.deletion_requested = 0",
            rusqlite::params![network_id, tenant_id, site_id],
            |row| {
                Ok(LinkNetwork {
                    id: row.get(0)?,
                    prefix: row.get(1)?,
                    device_id: row.get(2)?,
                    interface_id: row.get(3)?,
                    source: row.get(4)?,
                    address_family: row.get(5)?,
                })
            },
        )
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "站点共享网络不存在或不属于指定站点"))
}

/// 校验网关设备归属、在线状态和 Agent 最近上报的能力报告。
fn ensure_gateway_device(
    connection: &Connection,
    requirement: &GatewayDeviceRequirement<'_>,
) -> Result<(), ApiError> {
    let result = connection.query_row(
        "SELECT d.status, d.capabilities_json, r.report_json FROM devices d
         LEFT JOIN device_capability_reports r ON r.device_id = d.id
         WHERE d.id = ?1 AND d.tenant_id = ?2 AND d.site_id = ?3",
        rusqlite::params![
            requirement.device_id,
            requirement.tenant_id,
            requirement.site_id
        ],
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
    if requirement.require_online && status != "online" {
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
    let required_capability = if requirement.require_online {
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
    if report.subnet_gateway != CapabilityState::Ready
        && report.subnet_gateway_reason != Some(GatewayCapabilityReason::IpForwardingDisabled)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            gateway_capability_message(report.subnet_gateway_reason),
        ));
    }
    if requirement.require_online
        && report.site_gateway != CapabilityState::Ready
        && report.site_gateway_reason != Some(GatewayCapabilityReason::IpForwardingDisabled)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            gateway_capability_message(report.site_gateway_reason),
        ));
    }
    if requirement.require_detected_network
        && !report.local_networks.iter().any(|network| {
            requirement
                .interface_id
                .is_some_and(|interface| network.interface_id == interface)
                && network
                    .prefix
                    .parse::<IpNet>()
                    .map(|detected| detected.trunc() == requirement.prefix.trunc())
                    .unwrap_or(false)
        })
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "设备最近探测到的本地网络与请求不一致",
        ));
    }
    if let Some(message) = gateway_forwarding_error(&report, requirement.prefix) {
        return Err(ApiError::new(StatusCode::CONFLICT, message));
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

    #[test]
    fn legacy_enrollment_request_without_web_name_remains_compatible() {
        let request: CreateEnrollmentRequest =
            serde_json::from_str(r#"{"tenant_id":"default","site_id":null,"ttl_seconds":900}"#)
                .expect("旧版创建入网请求应继续解析");
        assert!(request.device_name.is_none());
    }
    use axum::http::HeaderValue;
    use nexo_core::{DetectedLocalNetwork, DeviceCapability};
    use nexo_headscale_adapter::{HeadscalePreAuthKey, HeadscaleUser};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    fn admin_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("nexo_local_session=test-session"),
        );
        headers
    }

    #[allow(dead_code)]
    fn tenant_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("nexo_local_session=tenant-session"),
        );
        headers
    }

    /// 为权限测试创建第二个普通用户和独立 Session；测试只依赖 Session
    /// 摘要，不需要执行真实密码哈希流程。
    #[allow(dead_code)]
    fn insert_tenant_session(state: &AppState) {
        let connection = state.db.lock().expect("数据库锁应可用");
        connection
            .execute_batch(
                "INSERT OR IGNORE INTO tenants (id, name) VALUES ('tenant-2', '第二工作空间');
                 INSERT OR IGNORE INTO users (id, tenant_id, username, role, password_hash)
                 VALUES ('user-2', 'tenant-2', 'test-user', 'tenant', 'test-hash');",
            )
            .expect("应创建普通用户夹具");
        let session_digest = hex::encode(Sha256::digest(b"tenant-session"));
        let csrf_digest = hex::encode(Sha256::digest(b"tenant-csrf"));
        let session_now = unix_now();
        connection
            .execute(
                "INSERT OR REPLACE INTO auth_sessions
                 (id, user_id, tenant_id, session_digest, csrf_digest, channel,
                  created_at, last_seen_at, expires_at, revoked_at)
                 VALUES ('tenant-session-row', 'user-2', 'tenant-2', ?1, ?2, 'local_http',
                         ?3, ?3, ?4, NULL)",
                rusqlite::params![
                    session_digest,
                    csrf_digest,
                    session_now,
                    session_now + 7 * 24 * 60 * 60
                ],
            )
            .expect("应创建普通用户登录状态");
    }

    /// 官方客户端测试专用的 Headscale 边界：记录密钥吊销并返回可控节点，
    /// 用来验证 Nexo 的生命周期和外部节点隔离，而不连接真实服务。
    #[allow(dead_code)]
    #[derive(Default)]
    struct OfficialClientHeadscale {
        expired_keys: Mutex<Vec<String>>,
        nodes: Mutex<Vec<HeadscaleNode>>,
        next_key: Mutex<u64>,
        checked_policies: Mutex<Vec<String>>,
        published_policies: Mutex<Vec<String>>,
        fail_policy_check: Mutex<bool>,
        policy_check_error: Mutex<Option<PolicyCheckError>>,
        fail_policy_set: Mutex<bool>,
    }

    #[async_trait::async_trait]
    impl HeadscaleControlPlane for OfficialClientHeadscale {
        async fn reconcile_routes(
            &self,
            routes: &[nexo_headscale_adapter::RouteAdvertisement],
        ) -> Result<nexo_headscale_adapter::RouteApplyReport> {
            HeadscaleAdapter.reconcile_routes(routes).await
        }

        async fn ensure_user(&self, name: &str) -> Result<HeadscaleUser> {
            Ok(HeadscaleUser {
                id: format!("hs-{name}"),
                name: name.to_owned(),
                ..Default::default()
            })
        }

        async fn create_pre_auth_key_with_options(
            &self,
            _user_id: &str,
            options: &HeadscaleAuthKeyOptions,
        ) -> Result<HeadscalePreAuthKey> {
            let mut next = self.next_key.lock().expect("应分配测试 Auth Key 编号");
            *next += 1;
            let id = format!("key-{next}");
            Ok(HeadscalePreAuthKey {
                id: id.clone(),
                key: Some(format!("tskey-auth-{next}")),
                used: false,
                expiration: Some(options.expiration.clone()),
            })
        }

        async fn expire_pre_auth_key(&self, key_id: &str) -> Result<()> {
            self.expired_keys
                .lock()
                .expect("应记录测试 Auth Key 吊销")
                .push(key_id.to_owned());
            Ok(())
        }

        async fn list_nodes(&self) -> Result<Vec<HeadscaleNode>> {
            Ok(self
                .nodes
                .lock()
                .expect("应读取测试 Headscale 节点")
                .clone())
        }

        async fn check_policy(&self, policy: &str) -> std::result::Result<(), PolicyCheckError> {
            if let Some(error) = self
                .policy_check_error
                .lock()
                .expect("应读取测试 Policy 错误")
                .clone()
            {
                return Err(error);
            }
            if *self
                .fail_policy_check
                .lock()
                .expect("应读取测试 Policy 校验开关")
            {
                return Err(PolicyCheckError::Unavailable {
                    detail: "测试模拟 Policy 校验失败".to_owned(),
                });
            }
            self.checked_policies
                .lock()
                .expect("应记录测试 Policy 校验")
                .push(policy.to_owned());
            Ok(())
        }

        async fn set_policy(&self, policy: &str) -> Result<()> {
            if *self
                .fail_policy_set
                .lock()
                .expect("应读取测试 Policy 发布开关")
            {
                anyhow::bail!("测试模拟 Policy 发布失败");
            }
            self.published_policies
                .lock()
                .expect("应记录测试 Policy 发布")
                .push(policy.to_owned());
            Ok(())
        }
    }

    /// 删除测试专用的 Headscale 边界：记录外部撤销调用，并可精确模拟失败。
    /// 这样可以验证“外部身份未撤销时本地记录不得删除”，而不连接真实服务。
    #[derive(Default)]
    struct DeletionHeadscale {
        expired_keys: Mutex<Vec<String>>,
        deleted_nodes: Mutex<Vec<String>>,
        renamed_nodes: Mutex<Vec<(String, String)>>,
        fail_key_expiration: bool,
        fail_node_deletion: bool,
        fail_node_rename: bool,
    }

    #[async_trait::async_trait]
    impl HeadscaleControlPlane for DeletionHeadscale {
        async fn reconcile_routes(
            &self,
            routes: &[nexo_headscale_adapter::RouteAdvertisement],
        ) -> Result<nexo_headscale_adapter::RouteApplyReport> {
            HeadscaleAdapter.reconcile_routes(routes).await
        }

        async fn expire_pre_auth_key(&self, key_id: &str) -> Result<()> {
            if self.fail_key_expiration {
                anyhow::bail!("测试模拟 Pre-auth Key 吊销失败");
            }
            self.expired_keys
                .lock()
                .expect("Headscale Key 调用记录应可写")
                .push(key_id.to_owned());
            Ok(())
        }

        async fn delete_node(&self, node_id: &str) -> Result<()> {
            if self.fail_node_deletion {
                anyhow::bail!("测试模拟 Headscale Node 删除失败");
            }
            self.deleted_nodes
                .lock()
                .expect("Headscale Node 调用记录应可写")
                .push(node_id.to_owned());
            Ok(())
        }

        async fn rename_node(&self, node_id: &str, new_name: &str) -> Result<HeadscaleNode> {
            if self.fail_node_rename {
                anyhow::bail!("测试模拟 Headscale Node 重命名失败");
            }
            self.renamed_nodes
                .lock()
                .expect("Headscale Node 重命名调用记录应可写")
                .push((node_id.to_owned(), new_name.to_owned()));
            Ok(HeadscaleNode {
                id: node_id.to_owned(),
                name: new_name.to_owned(),
                ..HeadscaleNode::default()
            })
        }
    }

    #[tokio::test]
    async fn workspace_scope_isolated_and_admin_can_switch_workspace() {
        let state = test_state();
        insert_tenant_session(&state);
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO devices (id, tenant_id, name, status)
                 VALUES ('tenant-one-device', 'tenant-1', '管理员设备', 'online'),
                        ('tenant-two-device', 'tenant-2', '普通用户设备', 'online');",
            )
            .expect("应创建跨工作空间设备夹具");

        let own_devices = list_devices(State(state.clone()), tenant_headers())
            .await
            .expect("普通用户应能读取自己的设备")
            .0;
        assert_eq!(
            own_devices
                .iter()
                .map(|device| device.id.as_str())
                .collect::<Vec<_>>(),
            vec!["tenant-two-device"]
        );

        let cross_workspace = update_device(
            State(state.clone()),
            tenant_headers(),
            Path("tenant-one-device".to_owned()),
            Json(UpdateDeviceRequest {
                name: "不应修改".to_owned(),
                site_id: None,
            }),
        )
        .await
        .expect_err("普通用户不得修改其他工作空间设备");
        assert_eq!(cross_workspace.status, StatusCode::NOT_FOUND);

        let mut switched_headers = admin_headers();
        switched_headers.insert("x-nexo-workspace", HeaderValue::from_static("tenant-2"));
        let switched_devices = list_devices(State(state), switched_headers)
            .await
            .expect("系统管理员应能切换工作空间")
            .0;
        assert_eq!(switched_devices[0].id, "tenant-two-device");
    }

    #[tokio::test]
    async fn tailscale_auth_key_is_one_time_visible_and_expires_on_read() {
        let headscale = Arc::new(OfficialClientHeadscale::default());
        let state = test_state_with_headscale(headscale.clone());
        let created = create_tailscale_auth_key(
            State(state.clone()),
            admin_headers(),
            Json(CreateTailscaleAuthKeyRequest {
                label: "测试密钥".to_owned(),
                reusable: true,
                ephemeral: true,
                ttl_seconds: Some(600),
                tags: vec!["tag:team".to_owned()],
            }),
        )
        .await
        .expect("应创建官方客户端 Auth Key")
        .0;
        let plaintext = created.key.clone().expect("创建响应应包含一次性明文");
        let (digest, stored_state): (String, String) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT key_digest, state FROM tailscale_auth_keys WHERE id = ?1",
                [&created.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("应读取 Auth Key 摘要");
        assert_eq!(digest, hex::encode(Sha256::digest(plaintext.as_bytes())));
        assert_ne!(digest, plaintext);
        assert_eq!(stored_state, "issued");

        let listed = list_tailscale_auth_keys(State(state.clone()), admin_headers())
            .await
            .expect("应读取 Auth Key 列表")
            .0;
        assert_eq!(listed[0].key, None);

        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute(
                "INSERT INTO tailscale_auth_keys
                 (id, tenant_id, headscale_key_id, key_digest, label, expires_at, state)
                 VALUES ('expired-key', 'tenant-1', 'expired-headscale-key', 'digest',
                         '已过期', ?1, 'issued')",
                [unix_now() - 1],
            )
            .expect("应创建过期 Auth Key 夹具");
        let listed = list_tailscale_auth_keys(State(state.clone()), admin_headers())
            .await
            .expect("应惰性收敛过期状态")
            .0;
        assert_eq!(
            listed
                .iter()
                .find(|key| key.id == "expired-key")
                .map(|key| key.state.as_str()),
            Some("expired")
        );

        let _revoked = revoke_tailscale_auth_key(
            State(state.clone()),
            admin_headers(),
            Path(created.id.clone()),
        )
        .await
        .expect("应吊销 Auth Key");
        assert_eq!(
            *headscale.expired_keys.lock().expect("应读取吊销记录"),
            vec!["key-1".to_owned()]
        );
        let revoked_state: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT state FROM tailscale_auth_keys WHERE id = ?1",
                [&created.id],
                |row| row.get(0),
            )
            .expect("应读取吊销后的状态");
        assert_eq!(revoked_state, "revoked");
    }

    #[tokio::test]
    async fn external_nodes_are_admin_only_and_claimed_into_selected_workspace() {
        let headscale = Arc::new(OfficialClientHeadscale {
            nodes: Mutex::new(vec![HeadscaleNode {
                id: "external-node-1".to_owned(),
                name: "外部笔记本".to_owned(),
                online: true,
                ip_addresses: vec!["100.64.0.10".to_owned(), "fd7a::10".to_owned()],
                ..HeadscaleNode::default()
            }]),
            ..OfficialClientHeadscale::default()
        });
        let state = test_state_with_headscale(headscale);
        insert_tenant_session(&state);

        let ordinary_list = list_tailscale_external_nodes(State(state.clone()), tenant_headers())
            .await
            .expect_err("普通用户不得读取实例级隔离节点");
        assert_eq!(ordinary_list.status, StatusCode::FORBIDDEN);
        let admin_list = list_tailscale_external_nodes(State(state.clone()), admin_headers())
            .await
            .expect("系统管理员应能同步隔离节点")
            .0;
        assert_eq!(admin_list.len(), 1);

        let ordinary_claim = claim_tailscale_external_node(
            State(state.clone()),
            tenant_headers(),
            Path("external-node-1".to_owned()),
            None,
        )
        .await
        .expect_err("普通用户不得认领隔离节点");
        assert_eq!(ordinary_claim.status, StatusCode::FORBIDDEN);

        let claimed = claim_tailscale_external_node(
            State(state.clone()),
            admin_headers(),
            Path("external-node-1".to_owned()),
            Some(Json(ClaimTailscaleNodeRequest {
                name: Some("已确认笔记本".to_owned()),
            })),
        )
        .await
        .expect("管理员应能认领隔离节点")
        .0;
        assert_eq!(claimed.name, "已确认笔记本");
        assert_eq!(claimed.connection_type, "tailscale_client");
        assert_eq!(claimed.owner_username.as_deref(), Some("test-admin"));
        let ownership: (String, String, String) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT d.tenant_id, tm.user_id, e.claim_state
                 FROM devices d
                 JOIN tailscale_device_metadata tm ON tm.device_id = d.id
                 JOIN tailscale_external_nodes e ON e.claimed_device_id = d.id
                 WHERE d.id = ?1",
                [&claimed.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("应保存认领后的所有权");
        assert_eq!(
            ownership,
            (
                "tenant-1".to_owned(),
                "user-1".to_owned(),
                "claimed".to_owned()
            )
        );
    }

    #[tokio::test]
    async fn access_rule_checks_policy_and_keeps_grants_direct() {
        let headscale = Arc::new(OfficialClientHeadscale::default());
        let state = test_state_with_headscale(headscale.clone());
        insert_tenant_session(&state);
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute_batch(
                    "INSERT INTO mesh_tenant_mappings
                     (tenant_id, headscale_user_id, status)
                     VALUES ('tenant-1', 'hs-tenant-1', 'ready'),
                            ('tenant-2', 'hs-tenant-2', 'ready');",
                )
                .expect("应创建测试工作空间组网映射");
            connection
                .execute(
                    "INSERT INTO devices (id, tenant_id, name, status)
                     VALUES ('access-device', 'tenant-1', '共享设备', 'online')",
                    [],
                )
                .expect("应创建访问控制设备");
            connection
                .execute(
                    "INSERT INTO tailscale_device_metadata
                     (device_id, user_id, registration_method, tailscale_ipv4, control_plane_state)
                     VALUES ('access-device', 'user-1', 'browser', '100.64.0.8', 'ready')",
                    [],
                )
                .expect("应创建访问控制设备元数据");
        }

        let created = create_access_rule(
            State(state.clone()),
            admin_headers(),
            Json(AccessRuleRequest {
                name: "协作者访问设备".to_owned(),
                target_type: "device".to_owned(),
                target_id: "access-device".to_owned(),
                protocols: vec!["tcp".to_owned()],
                ports: vec!["22".to_owned()],
                ssh_enabled: true,
                enabled: true,
                grantee_workspace_ids: vec!["tenant-2".to_owned()],
            }),
        )
        .await
        .expect("有效访问规则应保存")
        .0;
        assert_eq!(created.grants.len(), 1);
        assert_eq!(created.grants[0].workspace_id, "tenant-2");

        let checked = headscale
            .checked_policies
            .lock()
            .expect("应读取 Policy 校验记录")
            .clone();
        assert!(checked.iter().any(|document| {
            document.contains("nexo-tenant-2@") && document.contains("100.64.0.8")
        }));

        let connection = state.db.lock().expect("数据库锁应可用");
        let document =
            policy::generate_policy(&build_policy_grants(&connection).expect("应生成访问策略"));
        let parsed: serde_json::Value =
            serde_json::from_str(&document).expect("策略应是 JSON 文档");
        let grant = parsed["grants"]
            .as_array()
            .and_then(|grants| {
                grants
                    .iter()
                    .find(|grant| grant["src"][0] == "group:nexo-workspace-tenant-2")
            })
            .expect("应有一条直接授权");
        assert_eq!(grant["src"][0], "group:nexo-workspace-tenant-2");
        assert_eq!(grant["dst"][0], "100.64.0.8");
        assert!(parsed["grants"].as_array().is_some_and(|grants| {
            grants
                .iter()
                .any(|grant| grant["src"][0] == "group:nexo-workspace-tenant-1")
        }));
        assert!(document.contains("autogroup:nonroot"));
        assert!(!document.contains("nexo-tenant-3@"));
    }

    #[tokio::test]
    async fn current_policy_preview_checks_saved_policy_without_placeholder_target() {
        let headscale = Arc::new(OfficialClientHeadscale::default());
        let state = test_state_with_headscale(headscale.clone());
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute(
                    "INSERT INTO devices (id, tenant_id, name, status)
                     VALUES ('current-policy-device', 'tenant-1', '当前策略设备', 'online')",
                    [],
                )
                .expect("应创建当前策略设备");
            connection
                .execute(
                    "INSERT INTO tailscale_device_metadata
                     (device_id, user_id, registration_method, tailscale_ipv4, control_plane_state)
                     VALUES ('current-policy-device', 'user-1', 'browser', '100.64.0.11', 'ready')",
                    [],
                )
                .expect("应创建当前策略设备地址");
            connection
                .execute(
                    "INSERT INTO mesh_access_rules
                     (id, owner_tenant_id, owner_user_id, name, target_type, target_id,
                      protocols_json, ports_json, enabled, desired_revision, applied_revision,
                      apply_status)
                     VALUES ('current-policy-rule', 'tenant-1', 'user-1', '当前规则', 'device',
                             'current-policy-device', '[\"tcp\"]', '[\"443\"]', 1, 1, 1, 'ready')",
                    [],
                )
                .expect("应创建当前策略规则");
            connection
                .execute(
                    "INSERT INTO mesh_access_grants
                     (rule_id, grantee_tenant_id, status, accepted_at)
                     VALUES ('current-policy-rule', 'tenant-1', 'accepted', unixepoch())",
                    [],
                )
                .expect("应创建当前策略授权");
        }

        let preview = current_access_policy_preview(State(state.clone()), admin_headers())
            .await
            .expect("当前策略应能通过 Headscale 校验")
            .0;
        assert!(preview.valid);
        assert_eq!(preview.grant_count, 1);
        assert_eq!(preview.affected_targets, vec!["100.64.0.11"]);
        let checked = headscale
            .checked_policies
            .lock()
            .expect("应读取当前策略校验记录")
            .clone();
        assert!(checked
            .iter()
            .any(|document| { document.contains("100.64.0.11") && !document.contains("preview") }));

        *headscale
            .policy_check_error
            .lock()
            .expect("应设置测试 Policy 拒绝响应") = Some(PolicyCheckError::Rejected {
            status: 400,
            detail: "host not defined in policy".to_owned(),
        });
        let rejected = current_access_policy_preview(State(state.clone()), admin_headers())
            .await
            .expect("Headscale 拒绝应作为预览结果返回")
            .0;
        assert!(!rejected.valid);
        assert_eq!(rejected.status, AccessPolicyPreviewStatus::Invalid);
        assert_eq!(rejected.summary, "策略内容有误");
        assert!(rejected
            .error
            .as_deref()
            .is_some_and(|message| message.contains("host not defined")));

        *headscale
            .policy_check_error
            .lock()
            .expect("应清除测试 Policy 拒绝响应") = None;
        *headscale
            .fail_policy_check
            .lock()
            .expect("应设置测试 Policy 服务不可用开关") = true;
        let unavailable = current_access_policy_preview(State(state), admin_headers())
            .await
            .expect("Headscale 服务不可用应作为预览结果返回")
            .0;
        assert_eq!(unavailable.status, AccessPolicyPreviewStatus::Unavailable);
        assert_eq!(unavailable.summary, "组网服务暂不可用，请稍后重新校验");
        assert_eq!(
            unavailable.error.as_deref(),
            Some("组网服务暂不可用，请稍后重新校验")
        );
    }

    #[tokio::test]
    async fn access_rule_policy_check_failure_does_not_persist_rule() {
        let headscale = Arc::new(OfficialClientHeadscale::default());
        *headscale
            .fail_policy_check
            .lock()
            .expect("应设置测试 Policy 校验开关") = true;
        let state = test_state_with_headscale(headscale);
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute(
                    "INSERT INTO devices (id, tenant_id, name, status)
                     VALUES ('check-failure-device', 'tenant-1', '校验失败设备', 'online')",
                    [],
                )
                .expect("应创建校验失败设备");
            connection
                .execute(
                    "INSERT INTO tailscale_device_metadata
                     (device_id, user_id, registration_method, tailscale_ipv4, control_plane_state)
                     VALUES ('check-failure-device', 'user-1', 'browser', '100.64.0.9', 'ready')",
                    [],
                )
                .expect("应创建校验失败设备元数据");
        }
        let error = create_access_rule(
            State(state.clone()),
            admin_headers(),
            Json(AccessRuleRequest {
                name: "不应保存".to_owned(),
                target_type: "device".to_owned(),
                target_id: "check-failure-device".to_owned(),
                protocols: vec!["tcp".to_owned()],
                ports: vec!["443".to_owned()],
                ssh_enabled: false,
                enabled: true,
                grantee_workspace_ids: Vec::new(),
            }),
        )
        .await
        .expect_err("Policy 校验失败时不应保存规则");
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        let count: i64 = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT COUNT(*) FROM mesh_access_rules WHERE name = '不应保存'",
                [],
                |row| row.get(0),
            )
            .expect("应读取规则数量");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn access_rule_revoke_retains_error_and_retries_to_disabled() {
        let headscale = Arc::new(OfficialClientHeadscale::default());
        let state = test_state_with_headscale(headscale.clone());
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute(
                    "INSERT INTO mesh_access_rules
                     (id, owner_tenant_id, owner_user_id, name, target_type, target_id,
                      protocols_json, ports_json, enabled, desired_revision, applied_revision,
                      apply_status)
                     VALUES ('retry-rule', 'tenant-1', 'user-1', '待重试规则', 'file_share',
                             '100.64.0.20', '[\"tcp\"]', '[\"22\"]', 0, 2, 1, 'checking')",
                    [],
                )
                .expect("应创建待重试规则");
        }

        *headscale
            .fail_policy_set
            .lock()
            .expect("应设置测试 Policy 发布开关") = true;
        let error = reconcile_headscale_policy(&state)
            .await
            .expect_err("Policy 发布失败时应返回错误");
        assert!(error.to_string().contains("测试模拟 Policy 发布失败"));
        let (status, apply_error): (String, Option<String>) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status, apply_error FROM mesh_access_rules WHERE id = 'retry-rule'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("应读取失败状态");
        assert_eq!(status, "error");
        assert!(apply_error.is_some());

        *headscale
            .fail_policy_set
            .lock()
            .expect("应更新测试 Policy 发布开关") = false;
        reconcile_headscale_policy(&state)
            .await
            .expect("修复 Headscale 后应能重试发布");
        let (status, applied_revision, apply_error): (String, i64, Option<String>) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status, applied_revision, apply_error
                 FROM mesh_access_rules WHERE id = 'retry-rule'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("应读取重试后的状态");
        assert_eq!(status, "disabled");
        assert_eq!(applied_revision, 2);
        assert_eq!(apply_error, None);
    }

    #[tokio::test]
    async fn access_rule_target_is_scoped_to_current_workspace() {
        let state = test_state();
        insert_tenant_session(&state);
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute(
                "INSERT INTO devices (id, tenant_id, name, status)
                 VALUES ('tenant-one-device', 'tenant-1', '管理员设备', 'online')",
                [],
            )
            .expect("应创建其他工作空间设备");
        let error = create_access_rule(
            State(state),
            tenant_headers(),
            Json(AccessRuleRequest {
                name: "越权规则".to_owned(),
                target_type: "device".to_owned(),
                target_id: "tenant-one-device".to_owned(),
                protocols: vec!["tcp".to_owned()],
                ports: vec!["22".to_owned()],
                ssh_enabled: false,
                enabled: true,
                grantee_workspace_ids: Vec::new(),
            }),
        )
        .await
        .expect_err("普通用户不能把其他工作空间设备作为目标");
        assert_eq!(error.status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn public_https_probe_keeps_sni_and_targets_local_caddy() {
        let (host, url, address) = public_https_probe_target("nexo-test.example.com");
        assert_eq!(host, "nexo.nexo-test.example.com");
        assert_eq!(url, "https://nexo.nexo-test.example.com/api/v1/auth/status");
        assert_eq!(address, SocketAddr::from(([127, 0, 0, 1], 443)));
    }

    #[test]
    fn caddy_renewal_estimate_uses_last_third_of_certificate_lifetime() {
        let start = 1_000_i64;
        let end = 91_000_i64;
        assert_eq!(
            estimated_caddy_renewal(Some(start), Some(end)),
            Some(61_000)
        );
        assert_eq!(estimated_caddy_renewal(None, Some(end)), None);
        assert_eq!(estimated_caddy_renewal(Some(end), Some(start)), None);
    }

    #[test]
    fn primary_domain_requires_root_and_wildcard_dns_records() {
        let ready = serde_json::json!({
            "root": {"resolved": ["192.0.2.10"]},
            "wildcard": {"resolved": ["192.0.2.10"]}
        });
        assert!(public_domain_dns_ready(&ready.to_string()));
        let missing_wildcard = serde_json::json!({
            "root": {"resolved": ["192.0.2.10"]},
            "wildcard": {"resolved": [], "error": "未解析"}
        });
        assert!(!public_domain_dns_ready(&missing_wildcard.to_string()));
        let legacy = serde_json::json!({"resolved": ["192.0.2.10"]});
        assert!(public_domain_dns_ready(&legacy.to_string()));
    }

    fn manual_certificate_fixture(
        subjects: &[&str],
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> (String, String) {
        let key = KeyPair::generate().expect("应生成测试私钥");
        let mut params = CertificateParams::new(
            subjects
                .iter()
                .map(|item| (*item).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("应创建测试证书参数");
        params.not_before = not_before;
        params.not_after = not_after;
        let certificate = params.self_signed(&key).expect("应签发测试证书");
        (certificate.pem(), key.serialize_pem())
    }

    #[test]
    fn rustls_private_key_parser_accepts_pkcs1_pkcs8_and_sec1_containers() {
        let cases = [
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMAECAQ==\n-----END RSA PRIVATE KEY-----\n",
                "pkcs1",
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nMAECAQ==\n-----END PRIVATE KEY-----\n",
                "pkcs8",
            ),
            (
                "-----BEGIN EC PRIVATE KEY-----\nMAECAQ==\n-----END EC PRIVATE KEY-----\n",
                "sec1",
            ),
        ];
        for (pem, expected) in cases {
            let parsed = pem_private_key(pem).expect("应识别受支持的 PEM 私钥容器");
            let actual = match parsed {
                rustls::pki_types::PrivateKeyDer::Pkcs1(_) => "pkcs1",
                rustls::pki_types::PrivateKeyDer::Pkcs8(_) => "pkcs8",
                rustls::pki_types::PrivateKeyDer::Sec1(_) => "sec1",
                _ => "unknown",
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn manual_certificate_validation_reports_key_san_and_validity_errors() {
        let now = OffsetDateTime::now_utc();
        let (certificate, private_key) = manual_certificate_fixture(
            &["example.com", "*.example.com"],
            now - Duration::days(1),
            now + Duration::days(30),
        );
        validate_certificate_pair_for_domain(&certificate, &private_key, Some("example.com"))
            .expect("有效的 PKCS#8 测试证书应通过校验");

        let (_, other_key) = manual_certificate_fixture(
            &["example.com", "*.example.com"],
            now - Duration::days(1),
            now + Duration::days(30),
        );
        assert_eq!(
            validate_certificate_pair_for_domain(&certificate, &other_key, Some("example.com"))
                .expect_err("不匹配私钥必须被拒绝")
                .message,
            "证书与私钥不匹配"
        );
        assert_eq!(
            validate_certificate_pair_for_domain(
                &certificate,
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\ntest\n-----END ENCRYPTED PRIVATE KEY-----",
                Some("example.com"),
            )
            .expect_err("加密私钥必须被拒绝")
            .message,
            "暂不支持带密码的私钥，请提供未加密的 PEM 私钥"
        );

        let (wrong_san, wrong_san_key) = manual_certificate_fixture(
            &["other.example.com", "*.other.example.com"],
            now - Duration::days(1),
            now + Duration::days(30),
        );
        assert_eq!(
            validate_certificate_pair_for_domain(&wrong_san, &wrong_san_key, Some("example.com"))
                .expect_err("错误 SAN 必须被拒绝")
                .message,
            "证书必须同时覆盖根域名和泛域名"
        );

        let (expired, expired_key) = manual_certificate_fixture(
            &["example.com", "*.example.com"],
            now - Duration::days(30),
            now - Duration::days(1),
        );
        assert_eq!(
            validate_certificate_pair_for_domain(&expired, &expired_key, Some("example.com"))
                .expect_err("过期证书必须被拒绝")
                .message,
            "证书已经过期或尚未生效"
        );
    }

    #[test]
    fn secret_file_rollback_restores_previous_content_and_removes_new_file() {
        let root = std::env::temp_dir().join(format!("nexo-secret-rollback-{}", Uuid::new_v4()));
        let existing = root.join("existing.pem");
        let created = root.join("created.pem");
        write_secret_file(&existing, "previous").expect("应写入旧 Secret");
        {
            let mut rollbacks = Vec::new();
            capture_secret_rollback(&mut rollbacks, &existing);
            capture_secret_rollback(&mut rollbacks, &created);
            write_secret_file(&existing, "replacement").expect("应替换 Secret");
            write_secret_file(&created, "temporary").expect("应创建 Secret");
        }
        assert_eq!(
            fs::read_to_string(&existing).expect("应读取回滚内容"),
            "previous"
        );
        assert!(!created.exists(), "失败请求新建的 Secret 应被删除");
        fs::remove_dir_all(root).expect("应清理测试目录");
    }

    #[tokio::test]
    async fn deleting_only_primary_domain_requires_confirmation_and_preserves_tunnel() {
        let root = std::env::temp_dir().join(format!("nexo-domain-delete-{}", Uuid::new_v4()));
        let mut state = test_state();
        state.data_dir = root.clone();
        state.caddy = Arc::new(caddy::CaddySupervisor::new(
            caddy::CaddyRuntimeConfig::from_env(root.clone()),
        ));
        state.headscale_runtime = Arc::new(HeadscaleSupervisor::new(
            HeadscaleRuntimeConfig::from_env(root.clone()),
        ));
        insert_test_tunnel(&state, true);
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute(
                    "INSERT INTO public_domains
                     (id, tenant_id, domain, is_primary, certificate_mode, secret_dir, apply_status)
                     VALUES ('domain-primary', 'tenant-1', 'example.com', 1, 'manual',
                             'secrets/public-domains/domain-primary', 'ready')",
                    [],
                )
                .expect("应创建唯一主域名");
            connection
                .execute(
                    "UPDATE tunnels SET protocol = 'http', hostname = 'media',
                     public_domain_id = 'domain-primary' WHERE id = 'tunnel-1'",
                    [],
                )
                .expect("应绑定 Web 穿透服务");
        }
        let secret_dir = root.join("secrets/public-domains/domain-primary");
        write_secret_file(&secret_dir.join("certificate.pem"), "certificate")
            .expect("应创建测试凭据");

        let error = delete_public_domain(
            State(state.clone()),
            admin_headers(),
            Path("domain-primary".to_owned()),
            Some(Json(DeletePublicDomainRequest::default())),
        )
        .await
        .expect_err("未确认关闭公网入口时必须拒绝删除");
        assert_eq!(error.status, StatusCode::CONFLICT);

        let _ = delete_public_domain(
            State(state.clone()),
            admin_headers(),
            Path("domain-primary".to_owned()),
            Some(Json(DeletePublicDomainRequest {
                replacement_domain_id: None,
                disable_public_access: true,
            })),
        )
        .await
        .expect("明确确认后应删除唯一主域名");

        let connection = state.db.lock().expect("数据库锁应可用");
        assert_eq!(
            connection
                .query_row(
                    "SELECT enabled, public_domain_id FROM tunnels WHERE id = 'tunnel-1'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .expect("Web 穿透服务应保留"),
            (1, None)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM public_domains WHERE tenant_id = 'tenant-1'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("主域名记录应已删除"),
            0
        );
        drop(connection);
        assert!(
            !secret_dir.exists(),
            "相对 Secret 目录应按数据目录解析并清理"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tunnel_list_query_keeps_public_domain_columns_aligned() {
        let state = test_state();
        insert_test_tunnel(&state, true);
        let connection = state.db.lock().expect("数据库锁应可用");
        let response = connection
            .query_row(
                &tunnel_query("WHERE t.id = 'tunnel-1'"),
                [],
                tunnel_response_from_row,
            )
            .expect("历史 Tunnel 查询必须返回完整 22 列");
        assert_eq!(response.id, "tunnel-1");
        assert_eq!(response.public_domain_id, None);
    }

    #[test]
    fn runtime_event_query_uses_stable_cursor_and_tenant_scope() {
        let state = test_state();
        let connection = state.db.lock().expect("数据库锁应可用");
        connection
            .execute_batch(
                "INSERT INTO public_domain_runtime_events
                    (tenant_id, level, category, summary, occurred_at)
                 VALUES
                    ('tenant-1', 'info', 'configuration', '较早事件', 100),
                    ('tenant-1', 'warning', 'dns_validation', 'DNS 等待', 200),
                    ('tenant-1', 'error', 'https', '最新错误', 300);",
            )
            .expect("应创建运行日志夹具");
        let first = read_public_domain_runtime_events(
            &connection,
            "tenant-1",
            &RuntimeEventQuery {
                limit: Some(1),
                ..RuntimeEventQuery::default()
            },
            100,
        )
        .expect("应读取第一页");
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].summary, "最新错误");
        let second = read_public_domain_runtime_events(
            &connection,
            "tenant-1",
            &RuntimeEventQuery {
                cursor: first.next_cursor,
                limit: Some(1),
                ..RuntimeEventQuery::default()
            },
            100,
        )
        .expect("应读取第二页");
        assert_eq!(second.events[0].summary, "DNS 等待");
        assert!(read_public_domain_runtime_events(
            &connection,
            "tenant-2",
            &RuntimeEventQuery::default(),
            100,
        )
        .expect("跨租户查询应返回空集合")
        .events
        .is_empty());
    }

    #[test]
    fn caddy_certificate_scan_finds_root_and_wildcard_independently() {
        let root = std::env::temp_dir().join(format!("nexo-cert-scan-{}", Uuid::new_v4()));
        let storage = root
            .join("caddy-storage")
            .join("certificates")
            .join("production");
        fs::create_dir_all(&storage).expect("应创建证书测试目录");
        for (name, subject) in [
            ("root.crt", "example.com"),
            ("wildcard.crt", "*.example.com"),
        ] {
            let key = KeyPair::generate().expect("应生成测试私钥");
            let certificate = CertificateParams::new(vec![subject.to_owned()])
                .expect("应创建测试证书参数")
                .self_signed(&key)
                .expect("应签发测试证书");
            fs::write(storage.join(name), certificate.pem()).expect("应写入测试证书");
        }
        let root_metadata =
            find_caddy_certificate_metadata(&root, "example.com").expect("应找到根域名证书");
        let wildcard_metadata =
            find_caddy_certificate_metadata(&root, "*.example.com").expect("应找到泛域名证书");
        assert_eq!(root_metadata.subjects, vec!["example.com"]);
        assert_eq!(wildcard_metadata.subjects, vec!["*.example.com"]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn managed_dns_preview_adopts_creates_and_blocks_conflicts() {
        let records = vec![
            serde_json::json!({"id":"root-a","type":"A","name":"example.com","content":"192.0.2.10","proxied":false}),
            serde_json::json!({"id":"wild-a","type":"A","name":"*.example.com","content":"192.0.2.99","proxied":false}),
        ];
        let changes = plan_managed_dns_changes(
            "example.com",
            Some("192.0.2.10"),
            Some("2001:db8::10"),
            &records,
        );
        assert_eq!(changes.len(), 4, "双栈只应规划 @ 和 * 各两条记录");
        assert_eq!(changes[0].action, "adopt");
        assert_eq!(changes[1].action, "replace");
        assert!(changes
            .iter()
            .filter(|change| change.record_type == "AAAA")
            .all(|change| change.action == "create"));
        assert!(changes
            .iter()
            .all(|change| matches!(change.name.as_str(), "@" | "*")));
    }

    #[test]
    fn empty_database_creates_the_complete_v012_baseline() {
        let connection = Connection::open_in_memory().expect("应打开空测试数据库");
        initialize_v012_database(&connection).expect("空数据库应创建 v0.1.12 Baseline");

        let version: i64 = connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("应读取 Baseline 版本");
        assert_eq!(version, 19);
        for table in [
            "auth_sessions",
            "gateway_route_applies",
            "public_domains",
            "public_domain_runtime_events",
            "tailscale_device_metadata",
        ] {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
                     )",
                    [table],
                    |row| row.get(0),
                )
                .expect("应检查 Baseline 表");
            assert!(exists, "Baseline 应包含表 {table}");
        }
        let online: bool = connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('mesh_identities') WHERE name = 'online'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("应检查组网在线字段");
        assert!(online, "online 字段必须直接属于 Baseline");
        assert!(connection
            .prepare("SELECT origin_protocol, deletion_requested FROM tunnels")
            .is_ok());
    }

    #[test]
    fn database_without_v012_marker_is_rejected_without_compatibility_patching() {
        let connection = Connection::open_in_memory().expect("应打开旧版测试数据库");
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
                 INSERT INTO schema_migrations (version) VALUES (18);",
            )
            .expect("应创建旧版迁移标记");

        let error =
            initialize_v012_database(&connection).expect_err("没有版本 19 的数据库必须拒绝启动");
        assert!(error.to_string().contains("先升级到 v0.1.12"));
        assert!(connection
            .prepare("SELECT online FROM mesh_identities")
            .is_err());
    }

    #[test]
    fn v012_upgrade_applies_oidc_migration_and_removes_legacy_projection() {
        let connection = Connection::open_in_memory().expect("应打开 v0.1.12 测试数据库");
        initialize_v012_database(&connection).expect("应创建 v0.1.12 Baseline");
        connection
            .execute(
                "INSERT INTO public_domains
                 (id, tenant_id, domain, is_primary, secret_dir)
                 VALUES ('domain-1', 'default', 'example.com', 1, 'secrets/domain-1')",
                [],
            )
            .expect("应写入 v0.1.12 域名数据");
        let legacy_projection_before: bool = connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_master
                     WHERE type = 'table' AND name = 'public_entry_settings'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("Baseline 应保留 0010 公网入口投影");
        assert!(legacy_projection_before);
        apply_oidc_accounts_migration(&connection).expect("v0.1.12 应能执行 OIDC 迁移");

        let domain_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM public_domains WHERE id = 'domain-1'",
                [],
                |row| row.get(0),
            )
            .expect("域名数据应保持完整");
        assert_eq!(domain_count, 1);
        let legacy_projection: bool = connection
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_master
                     WHERE type = 'table' AND name = 'public_entry_settings'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("应检查旧公网入口投影");
        assert!(!legacy_projection);
        assert!(connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 20)",
                [],
                |row| row.get::<_, bool>(0),
            )
            .expect("应记录 OIDC 迁移版本"));
    }

    fn test_state() -> AppState {
        test_state_with_headscale(Arc::new(HeadscaleAdapter))
    }

    fn test_state_with_headscale(headscale: Arc<dyn HeadscaleControlPlane>) -> AppState {
        let connection = Connection::open_in_memory().expect("应打开内存数据库");
        connection
            .execute_batch(V012_BASELINE_MIGRATION)
            .expect("应初始化 v0.1.12 单一 Baseline");
        apply_oidc_accounts_migration(&connection).expect("应初始化 OIDC 账号映射结构");
        ensure_server_ca(&connection).expect("应初始化测试 CA");
        ensure_server_control_identity(&connection).expect("应初始化测试控制证书");
        connection
            .execute(
                "INSERT INTO tenants (id, name) VALUES ('tenant-1', '测试租户')",
                [],
            )
            .expect("应创建测试租户");
        connection
            .execute(
                "INSERT INTO users (id, tenant_id, username, role, password_hash)
                 VALUES ('user-1', 'tenant-1', 'test-admin', 'system_admin', 'test-hash')",
                [],
            )
            .expect("应创建测试管理员");
        let oidc =
            Arc::new(oidc::OidcRuntime::initialize(&connection).expect("应初始化测试 OIDC 状态"));
        let session_digest = hex::encode(Sha256::digest(b"test-session"));
        let csrf_digest = hex::encode(Sha256::digest(b"test-csrf"));
        let session_now = unix_now();
        connection
            .execute(
                "INSERT INTO auth_sessions
                 (id, user_id, tenant_id, session_digest, csrf_digest, channel,
                  created_at, last_seen_at, expires_at)
                 VALUES ('session-1', 'user-1', 'tenant-1', ?1, ?2, 'local_http',
                         ?3, ?3, ?4)",
                rusqlite::params![
                    session_digest,
                    csrf_digest,
                    session_now,
                    session_now + 7 * 24 * 60 * 60
                ],
            )
            .expect("应创建测试登录状态");
        AppState {
            db: Arc::new(Mutex::new(connection)),
            data_dir: PathBuf::from("."),
            headscale,
            mesh_offers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            mesh_enrollment_lock: Arc::new(tokio::sync::Mutex::new(())),
            tunnel_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            public_listener_tasks: Arc::new(Mutex::new(HashMap::new())),
            active_tunnel_connections: Arc::new(Mutex::new(HashMap::new())),
            caddy: Arc::new(caddy::CaddySupervisor::new(
                caddy::CaddyRuntimeConfig::from_env(PathBuf::from(".")),
            )),
            headscale_runtime: Arc::new(HeadscaleSupervisor::new(
                HeadscaleRuntimeConfig::from_env(PathBuf::from(".")),
            )),
            oidc,
        }
    }

    fn insert_test_tunnel(state: &AppState, enabled: bool) {
        let connection = state.db.lock().expect("数据库锁应可用");
        connection
            .execute(
                "INSERT INTO devices (id, tenant_id, name, capabilities_json)
                 VALUES ('tunnel-device', 'tenant-1', 'Tunnel 测试设备', '[\"tunnel\"]')",
                [],
            )
            .expect("应创建 Tunnel 测试设备");
        connection
            .execute(
                "INSERT INTO tunnels
                 (id, tenant_id, device_id, name, protocol, local_address, local_port,
                  public_port, enabled, apply_status, apply_revision, applied_revision)
                 VALUES ('tunnel-1', 'tenant-1', 'tunnel-device', '测试公网访问', 'tcp',
                         '127.0.0.1', 8800, NULL, ?1, ?2, 3, 3)",
                rusqlite::params![
                    i64::from(enabled),
                    if enabled { "ready" } else { "disabled" }
                ],
            )
            .expect("应创建 Tunnel 测试记录");
        connection
            .execute(
                "INSERT INTO tunnel_applied_states
                 (tunnel_id, applied_revision, applied_config_json, apply_status)
                 VALUES ('tunnel-1', 3, '{}', ?1)",
                [if enabled { "ready" } else { "disabled" }],
            )
            .expect("应创建 Tunnel 应用状态");
    }

    /// 批量 Tunnel 测试夹具：同时覆盖已启用、已停用和未分配服务。
    fn insert_batch_tunnel_fixture(state: &AppState) {
        let connection = state.db.lock().expect("数据库锁应可用");
        connection
            .execute_batch(
                r#"
                INSERT INTO devices (id, tenant_id, name, capabilities_json)
                VALUES
                    ('batch-device-a', 'tenant-1', '批量设备 A', '["tunnel"]'),
                    ('batch-device-b', 'tenant-1', '批量设备 B', '["tunnel"]');
                INSERT INTO tunnels
                    (id, tenant_id, device_id, name, protocol, local_address, local_port,
                     enabled, apply_status, apply_revision, applied_revision)
                VALUES
                    ('batch-enabled', 'tenant-1', 'batch-device-a', '批量已启用', 'tcp',
                     '127.0.0.1', 8801, 1, 'ready', 1, 1),
                    ('batch-disabled', 'tenant-1', 'batch-device-a', '批量已停用', 'tcp',
                     '127.0.0.1', 8802, 0, 'disabled', 2, 2),
                    ('batch-unassigned', 'tenant-1', NULL, '批量未分配', 'tcp',
                     '127.0.0.1', 8803, 0, 'disabled', 3, 3);
                INSERT INTO tunnel_applied_states
                    (tunnel_id, applied_revision, applied_config_json, apply_status)
                VALUES
                    ('batch-enabled', 1, '{}', 'ready'),
                    ('batch-disabled', 2, '{}', 'disabled'),
                    ('batch-unassigned', 3, '{}', 'disabled');
                "#,
            )
            .expect("应创建批量 Tunnel 测试夹具");
    }

    fn insert_gateway_deletion_fixture(state: &AppState) {
        state
            .db
            .lock()
            .expect("数据库锁应可用")
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
                    (site_network_id, desired_prefix, desired_revision, apply_status)
                    VALUES
                    ('network-a', '192.168.10.0/24', 4, 'ready'),
                    ('network-b', '192.168.20.0/24', 4, 'ready');
                 INSERT INTO site_links
                    (id, tenant_id, left_site_id, right_site_id, apply_revision, apply_status)
                    VALUES ('link-a-b', 'tenant-1', 'site-a', 'site-b', 4, 'ready');
                 INSERT INTO site_link_networks (site_link_id, site_network_id, side)
                    VALUES ('link-a-b', 'network-a', 'left'),
                           ('link-a-b', 'network-b', 'right');",
            )
            .expect("应创建网络资源删除测试数据");
    }

    fn finalize_resource_deletions_for_test(state: &AppState) {
        let connection = state.db.lock().expect("数据库锁应可用");
        let transaction = connection
            .unchecked_transaction()
            .expect("应开始删除收敛事务");
        finalize_requested_resource_deletions(&transaction).expect("删除状态应能收敛");
        transaction.commit().expect("应提交删除收敛事务");
    }

    #[test]
    fn mesh_hostname_is_dns_safe_stable_and_unique_for_same_names() {
        let chinese = mesh_hostname(
            "default",
            "家庭网关",
            "550e8400-e29b-41d4-a716-446655440000",
        );
        assert_eq!(chinese, "default-device-550e8400e29b41d4a716446655440000");
        assert_eq!(
            chinese,
            mesh_hostname(
                "default",
                "家庭网关",
                "550e8400-e29b-41d4-a716-446655440000"
            )
        );

        let first = mesh_hostname(
            "Tenant One",
            "Home NAS",
            "00000000-0000-0000-0000-000000000001",
        );
        let second = mesh_hostname(
            "Tenant One",
            "Home NAS",
            "00000000-0000-0000-0000-000000000002",
        );
        assert_eq!(
            first,
            "tenant-one-home-nas-00000000000000000000000000000001"
        );
        assert_ne!(first, second);
        for hostname in [first, second] {
            assert!(hostname.len() <= 63);
            assert!(hostname
                .chars()
                .all(|character| character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || character == '-'));
            assert!(hostname.chars().next().is_some_and(|character| character
                .is_ascii_lowercase()
                || character.is_ascii_digit()));
            assert!(hostname.chars().last().is_some_and(|character| character
                .is_ascii_lowercase()
                || character.is_ascii_digit()));
        }

        let empty = mesh_hostname("", "!@#", "");
        assert_eq!(empty, "tenant-device-node");

        let long = mesh_hostname(
            &"Tenant".repeat(30),
            &"Display Name".repeat(30),
            "550e8400-e29b-41d4-a716-446655440000",
        );
        assert!(long.len() <= 63);
        assert!(long.ends_with("-550e8400e29b41d4a716446655440000"));
    }

    #[test]
    fn dns_check_keeps_legacy_fields_and_reports_root_and_wildcard() {
        let report = build_dns_check(
            "example.com",
            Ok(vec!["192.0.2.10".to_owned()]),
            Err("泛域名未解析".to_owned()),
        );
        assert_eq!(report["resolved"], serde_json::json!(["192.0.2.10"]));
        assert_eq!(report["root"]["hostname"], "example.com");
        assert_eq!(report["wildcard"]["hostname"], "nexo.example.com");
        assert_eq!(report["wildcard"]["probe"], "*.example.com");
        assert_eq!(report["wildcard"]["error"], "泛域名未解析");
        assert!(report["error"].as_str().unwrap().contains("泛域名未解析"));
    }

    #[test]
    fn wildcard_dns_probe_uses_a_concrete_hostname() {
        assert_eq!(
            wildcard_dns_probe_hostname("example.com"),
            "nexo.example.com"
        );
    }

    #[test]
    fn client_config_does_not_publish_a_fixed_registration_url() {
        let response = TailscaleClientConfigResponse {
            login_server: "https://mesh.example.com".to_owned(),
            browser_authorization_url: None,
            supported_platforms: Vec::new(),
            notes: Vec::new(),
        };
        let serialized = serde_json::to_value(response).expect("客户端配置应可序列化");
        assert_eq!(
            serialized["browser_authorization_url"],
            serde_json::Value::Null
        );
    }

    #[tokio::test]
    async fn unassigned_tunnel_cannot_be_enabled_individually() {
        let state = test_state();
        insert_batch_tunnel_fixture(&state);
        let error = set_tunnel_enabled(
            state.clone(),
            admin_headers(),
            "batch-unassigned".to_owned(),
            true,
        )
        .await
        .expect_err("未分配 Tunnel 不得单独启用");
        assert_eq!(error.status, StatusCode::CONFLICT);
        let state_after: (i64, String) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT enabled, apply_status FROM tunnels WHERE id = 'batch-unassigned'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("应读取未分配 Tunnel 状态");
        assert_eq!(state_after, (0, "disabled".to_owned()));
    }

    #[tokio::test]
    async fn batch_delete_commits_all_records_and_cleans_files_once() {
        let state = test_state();
        insert_batch_tunnel_fixture(&state);
        let ca_path = std::env::temp_dir().join(format!("nexo-batch-{}.ca.pem", Uuid::new_v4()));
        let socket_path = std::env::temp_dir().join(format!("nexo-batch-{}.sock", Uuid::new_v4()));
        fs::write(&ca_path, b"test-ca").expect("应创建测试 CA 文件");
        fs::write(&socket_path, b"test-socket").expect("应创建测试 Socket 文件");
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute(
                "UPDATE tunnels SET origin_ca_secret_path = ?1, bridge_socket_path = ?2
                 WHERE id = 'batch-enabled'",
                rusqlite::params![ca_path.to_string_lossy(), socket_path.to_string_lossy()],
            )
            .expect("应保存测试文件路径");

        let response = batch_delete_tunnels(
            State(state.clone()),
            admin_headers(),
            Json(TunnelBatchIdsRequest {
                tunnel_ids: vec![
                    "batch-enabled".to_owned(),
                    "batch-disabled".to_owned(),
                    "batch-enabled".to_owned(),
                ],
            }),
        )
        .await
        .expect("批量删除应成功")
        .0;
        assert_eq!(response.affected_count, 2);
        assert_eq!(
            response.deleted_ids,
            vec!["batch-enabled", "batch-disabled"]
        );
        assert!(!ca_path.exists());
        assert!(!socket_path.exists());
        let remaining: (i64, i64, i64) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM tunnels WHERE id IN ('batch-enabled', 'batch-disabled')),
                    (SELECT COUNT(*) FROM tunnel_applied_states
                     WHERE tunnel_id IN ('batch-enabled', 'batch-disabled')),
                    (SELECT COUNT(*) FROM audit_events
                     WHERE event_type = 'TUNNEL_DELETED'
                       AND resource_id IN ('batch-enabled', 'batch-disabled'))",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("应检查批量删除结果");
        assert_eq!(remaining, (0, 0, 2));
        let unassigned_remaining: i64 = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT COUNT(*) FROM tunnels WHERE id = 'batch-unassigned'",
                [],
                |row| row.get(0),
            )
            .expect("未选中的 Tunnel 应保留");
        assert_eq!(unassigned_remaining, 1);
    }

    #[test]
    fn repeated_successful_tunnel_ack_keeps_ready_state() {
        let state = test_state();
        insert_test_tunnel(&state, true);
        let success = TunnelApplyResult {
            tunnel_id: "tunnel-1".to_owned(),
            revision: 3,
            applied: true,
            status: "checking".to_owned(),
            error_message: None,
        };

        apply_tunnel_results(&state, "tunnel-device", std::slice::from_ref(&success))
            .expect("相同 revision 的成功 ACK 应被接受");
        let ready: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status FROM tunnels WHERE id = 'tunnel-1'",
                [],
                |row| row.get(0),
            )
            .expect("应读取 Tunnel 状态");
        assert_eq!(ready, "ready");

        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute(
                "UPDATE tunnels SET apply_revision = 4 WHERE id = 'tunnel-1'",
                [],
            )
            .expect("应模拟新配置 revision");
        apply_tunnel_results(
            &state,
            "tunnel-device",
            &[TunnelApplyResult {
                revision: 4,
                ..success
            }],
        )
        .expect("新 revision 的成功 ACK 应被接受");
        let checking: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status FROM tunnels WHERE id = 'tunnel-1'",
                [],
                |row| row.get(0),
            )
            .expect("应读取新配置状态");
        assert_eq!(checking, "checking");
    }

    #[tokio::test]
    async fn api_time_fields_are_unix_seconds() {
        let state = test_state();
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute_batch(
                    "INSERT INTO sites (id, tenant_id, name) VALUES
                         ('site-a', 'tenant-1', '甲站点'),
                         ('site-b', 'tenant-1', '乙站点');
                     INSERT INTO devices (id, tenant_id, name, last_seen_at)
                         VALUES ('device-time', 'tenant-1', '时间测试设备', '2030-01-01 00:00:00');
                     INSERT INTO site_links (id, tenant_id, left_site_id, right_site_id)
                         VALUES ('link-time', 'tenant-1', 'site-a', 'site-b');
                     INSERT INTO site_link_route_confirmations
                         (site_link_id, site_id, confirmed_at)
                         VALUES ('link-time', 'site-a', '2030-01-01 00:00:00');",
                )
                .expect("应创建 API 时间测试数据");
        }

        let devices = list_devices(State(state.clone()), admin_headers())
            .await
            .expect("应读取设备列表")
            .0;
        let device = devices
            .iter()
            .find(|device| device.id == "device-time")
            .expect("应返回时间测试设备");
        assert_eq!(device.last_seen_at, Some(1_893_456_000));
        assert_eq!(
            site_link_route_confirmation(
                &state.db.lock().expect("数据库锁应可用"),
                "link-time",
                "site-a",
            )
            .expect("应读取静态路由确认时间"),
            Some(1_893_456_000)
        );
    }

    #[test]
    fn explicitly_bound_manual_domain_ignores_pending_primary_projection() {
        let mut domains = HashMap::new();
        domains.insert(
            "domain-primary".to_owned(),
            TunnelPublicDomainState {
                domain: Some("primary.example.com".to_owned()),
                https_enabled: true,
                certificate_mode: Some("cloudflare".to_owned()),
                apply_status: Some("configuring".to_owned()),
                desired_revision: 4,
                applied_revision: 4,
                root_certificate_status: Some("pending".to_owned()),
                wildcard_certificate_status: Some("pending".to_owned()),
                ..TunnelPublicDomainState::default()
            },
        );
        domains.insert(
            "domain-manual".to_owned(),
            TunnelPublicDomainState {
                domain: Some("manual.example.com".to_owned()),
                https_enabled: true,
                certificate_mode: Some("manual".to_owned()),
                apply_status: Some("ready".to_owned()),
                desired_revision: 7,
                applied_revision: 7,
                root_certificate_status: Some("ready".to_owned()),
                wildcard_certificate_status: Some("ready".to_owned()),
                ..TunnelPublicDomainState::default()
            },
        );
        let legacy = TunnelPublicDomainState {
            domain: Some("legacy.example.com".to_owned()),
            https_enabled: true,
            apply_status: Some("configuring".to_owned()),
            ..TunnelPublicDomainState::default()
        };

        let resolved = resolve_tunnel_public_domain_state(
            Some("domain-manual"),
            Some("domain-primary"),
            &domains,
            Some(&legacy),
        );

        assert_eq!(resolved.domain.as_deref(), Some("manual.example.com"));
        assert_eq!(evaluate_tunnel_public_readiness("https", &resolved), None);
    }

    #[test]
    fn unassigned_tunnel_follows_primary_domain_state() {
        let mut domains = HashMap::new();
        domains.insert(
            "domain-primary".to_owned(),
            TunnelPublicDomainState {
                domain: Some("primary.example.com".to_owned()),
                https_enabled: true,
                certificate_mode: Some("manual".to_owned()),
                apply_status: Some("ready".to_owned()),
                desired_revision: 3,
                applied_revision: 3,
                root_certificate_status: Some("pending".to_owned()),
                wildcard_certificate_status: Some("pending".to_owned()),
                ..TunnelPublicDomainState::default()
            },
        );
        let resolved =
            resolve_tunnel_public_domain_state(None, Some("domain-primary"), &domains, None);

        assert_eq!(resolved.domain.as_deref(), Some("primary.example.com"));
        assert_eq!(
            evaluate_tunnel_public_readiness("https", &resolved),
            Some(("checking".to_owned(), "手动证书尚未加载".to_owned()))
        );
    }

    #[test]
    fn http_tunnel_does_not_wait_for_unrelated_certificate() {
        let state = TunnelPublicDomainState {
            domain: Some("web.example.com".to_owned()),
            https_enabled: true,
            certificate_mode: Some("cloudflare".to_owned()),
            apply_status: Some("configuring".to_owned()),
            desired_revision: 9,
            applied_revision: 9,
            root_certificate_status: Some("pending".to_owned()),
            wildcard_certificate_status: Some("pending".to_owned()),
            ..TunnelPublicDomainState::default()
        };

        assert_eq!(evaluate_tunnel_public_readiness("http", &state), None);
    }

    #[test]
    fn https_tunnel_waits_for_route_revision_before_certificate_state() {
        let state = TunnelPublicDomainState {
            domain: Some("web.example.com".to_owned()),
            https_enabled: true,
            certificate_mode: Some("manual".to_owned()),
            apply_status: Some("checking".to_owned()),
            desired_revision: 10,
            applied_revision: 9,
            root_certificate_status: Some("ready".to_owned()),
            wildcard_certificate_status: Some("ready".to_owned()),
            ..TunnelPublicDomainState::default()
        };

        assert_eq!(
            evaluate_tunnel_public_readiness("https", &state),
            Some(("checking".to_owned(), "公网路由配置正在应用".to_owned()))
        );
    }

    #[test]
    fn https_tunnel_reports_missing_manual_certificate() {
        let state = TunnelPublicDomainState {
            domain: Some("web.example.com".to_owned()),
            https_enabled: true,
            certificate_mode: Some("manual".to_owned()),
            apply_status: Some("ready".to_owned()),
            desired_revision: 2,
            applied_revision: 2,
            root_certificate_status: Some("ready".to_owned()),
            wildcard_certificate_status: Some("pending".to_owned()),
            ..TunnelPublicDomainState::default()
        };

        assert_eq!(
            evaluate_tunnel_public_readiness("https", &state),
            Some(("checking".to_owned(), "手动证书尚未加载".to_owned()))
        );
    }

    #[test]
    fn automatic_https_domain_requires_root_and_wildcard_certificates() {
        let state = TunnelPublicDomainState {
            domain: Some("web.example.com".to_owned()),
            https_enabled: true,
            certificate_mode: Some("cloudflare".to_owned()),
            apply_status: Some("ready".to_owned()),
            desired_revision: 5,
            applied_revision: 5,
            root_certificate_status: Some("ready".to_owned()),
            wildcard_certificate_status: Some("pending".to_owned()),
            ..TunnelPublicDomainState::default()
        };

        assert_eq!(
            evaluate_tunnel_public_readiness("https", &state),
            Some(("checking".to_owned(), "等待 HTTPS 证书生效".to_owned()))
        );
    }

    #[test]
    fn legacy_projection_is_used_without_multi_domain_records() {
        let legacy = TunnelPublicDomainState {
            domain: Some("legacy.example.com".to_owned()),
            https_enabled: true,
            apply_status: Some("ready".to_owned()),
            desired_revision: 2,
            applied_revision: 2,
            legacy_ready: true,
            ..TunnelPublicDomainState::default()
        };
        let resolved =
            resolve_tunnel_public_domain_state(None, None, &HashMap::new(), Some(&legacy));

        assert_eq!(resolved, legacy);
        assert_eq!(evaluate_tunnel_public_readiness("https", &resolved), None);
    }

    #[tokio::test]
    async fn missing_tunnel_data_session_downgrades_ready_entry() {
        let state = test_state();
        insert_test_tunnel(&state, true);
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute(
                "UPDATE devices SET status = 'online' WHERE id = 'tunnel-device'",
                [],
            )
            .expect("应模拟在线控制连接");

        refresh_tunnel_readiness(&state, "tunnel-device").await;
        let (status, error): (String, Option<String>) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status, apply_error FROM tunnels WHERE id = 'tunnel-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("应读取断线后的 Tunnel 状态");
        assert_eq!(status, "checking");
        assert_eq!(error.as_deref(), Some("等待 Agent Tunnel 数据连接"));
    }

    #[tokio::test]
    async fn listener_cleanup_does_not_remove_a_replacement_task() {
        let state = test_state();
        let old = tokio::spawn(std::future::pending::<()>());
        let old_token = Uuid::new_v4();
        let replacement = tokio::spawn(std::future::pending::<()>());
        let replacement_token = Uuid::new_v4();
        {
            let mut tasks = state.public_listener_tasks.lock().unwrap();
            tasks.insert(
                "tunnel-1".to_owned(),
                PublicListenerTask {
                    token: replacement_token,
                    abort: replacement.abort_handle(),
                },
            );
        }
        remove_public_listener_task(&state, "tunnel-1", old_token);
        assert!(state
            .public_listener_tasks
            .lock()
            .unwrap()
            .contains_key("tunnel-1"));
        remove_public_listener_task(&state, "tunnel-1", replacement_token);
        assert!(!state
            .public_listener_tasks
            .lock()
            .unwrap()
            .contains_key("tunnel-1"));
        old.abort();
        replacement.abort();
    }

    #[tokio::test]
    async fn deleting_tunnel_is_immediate_when_device_is_offline() {
        let mut state = test_state();
        let data_dir = std::env::temp_dir().join(format!("nexo-tunnel-delete-{}", Uuid::new_v4()));
        fs::create_dir_all(&data_dir).expect("应创建穿透服务删除测试目录");
        state.data_dir = data_dir.clone();
        insert_test_tunnel(&state, true);

        let ca_path = data_dir.join("origin.ca.pem");
        let socket_path = data_dir.join("bridge.sock");
        fs::write(&ca_path, "test-ca").expect("应创建测试 CA");
        fs::write(&socket_path, "test-socket").expect("应创建测试 Socket");
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute(
                "UPDATE tunnels SET origin_ca_secret_path = ?1, bridge_socket_path = ?2
                 WHERE id = 'tunnel-1'",
                rusqlite::params![ca_path.to_string_lossy(), socket_path.to_string_lossy()],
            )
            .expect("应保存测试清理路径");

        let listener = tokio::spawn(std::future::pending::<()>());
        state.public_listener_tasks.lock().unwrap().insert(
            "tunnel-1".to_owned(),
            PublicListenerTask {
                token: Uuid::new_v4(),
                abort: listener.abort_handle(),
            },
        );
        let connection_cancel = CancellationToken::new();
        register_active_tunnel_connection(
            &state,
            "tunnel-1",
            Uuid::new_v4(),
            connection_cancel.clone(),
        );

        let response = delete_tunnel(
            State(state.clone()),
            admin_headers(),
            Path("tunnel-1".to_owned()),
        )
        .await
        .expect("离线设备上的穿透服务也应立即删除")
        .0;

        assert!(response.deleted);
        assert!(!response.pending);
        assert_eq!(response.message, "穿透服务已永久删除");
        let connection = state.db.lock().expect("数据库锁应可用");
        let tunnel_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM tunnels WHERE id = 'tunnel-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let applied_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM tunnel_applied_states WHERE tunnel_id = 'tunnel-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let audit_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM audit_events
                 WHERE event_type = 'TUNNEL_DELETED' AND resource_id = 'tunnel-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection);
        assert_eq!(tunnel_count, 0);
        assert_eq!(applied_count, 0);
        assert_eq!(audit_count, 1);
        let desired = load_tunnel_desired_state(&state, "tunnel-device").unwrap();
        assert!(desired.is_empty());
        assert!(connection_cancel.is_cancelled());
        assert!(!state
            .public_listener_tasks
            .lock()
            .unwrap()
            .contains_key("tunnel-1"));
        assert!(!ca_path.exists());
        assert!(!socket_path.exists());
        let _ = fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn disabling_tunnel_updates_state_and_publishes_disabled_desired_state() {
        let state = test_state();
        insert_test_tunnel(&state, true);

        let disabled = disable_tunnel(
            State(state.clone()),
            admin_headers(),
            Path("tunnel-1".to_owned()),
        )
        .await
        .expect("管理员应能关闭公网访问")
        .0;

        assert!(!disabled.enabled);
        assert_eq!(disabled.apply_status, "disabled");
        assert_eq!(disabled.desired_revision, 4);
        let desired = load_tunnel_desired_state(&state, "tunnel-device")
            .expect("关闭后的 Tunnel Desired State 应可读取");
        assert_eq!(desired.len(), 1);
        assert!(!desired[0].enabled);
        assert_eq!(desired[0].revision, 4);
    }

    #[tokio::test]
    async fn updating_disabled_tunnel_keeps_it_disabled() {
        let state = test_state();
        insert_test_tunnel(&state, false);

        let updated = update_tunnel(
            State(state.clone()),
            admin_headers(),
            Path("tunnel-1".to_owned()),
            Json(CreateTunnelRequest {
                tenant_id: "tenant-1".to_owned(),
                device_id: "tunnel-device".to_owned(),
                name: "修改后的公网访问".to_owned(),
                protocol: "tcp".to_owned(),
                local_address: "127.0.0.1".to_owned(),
                local_port: 9900,
                public_port: None,
                hostname: None,
                origin_protocol: None,
                origin_tls_server_name: None,
                origin_tls_verification: Some("system".to_owned()),
                origin_ca_pem: None,
                service_name: None,
                public_domain_id: None,
            }),
        )
        .await
        .expect("管理员应能编辑已关闭的公网访问")
        .0;

        assert_eq!(updated.name, "修改后的公网访问");
        assert!(!updated.enabled);
        assert_eq!(updated.apply_status, "disabled");
        assert_eq!(updated.desired_revision, 4);
        assert!(!state
            .public_listener_tasks
            .lock()
            .expect("监听器登记应可读取")
            .contains_key("tunnel-1"));
    }

    #[tokio::test]
    async fn updating_enabled_tunnel_restarts_application() {
        let state = test_state();
        insert_test_tunnel(&state, true);

        let updated = update_tunnel(
            State(state.clone()),
            admin_headers(),
            Path("tunnel-1".to_owned()),
            Json(CreateTunnelRequest {
                tenant_id: "tenant-1".to_owned(),
                device_id: "tunnel-device".to_owned(),
                name: "继续启用的公网访问".to_owned(),
                protocol: "tcp".to_owned(),
                local_address: "127.0.0.1".to_owned(),
                local_port: 9900,
                public_port: None,
                hostname: None,
                origin_protocol: None,
                origin_tls_server_name: None,
                origin_tls_verification: Some("system".to_owned()),
                origin_ca_pem: None,
                service_name: None,
                public_domain_id: None,
            }),
        )
        .await
        .expect("管理员应能编辑启用中的公网访问")
        .0;

        assert!(updated.enabled);
        assert_eq!(updated.apply_status, "checking");
        assert_eq!(updated.desired_revision, 4);
        assert!(state
            .public_listener_tasks
            .lock()
            .expect("监听器登记应可读取")
            .contains_key("tunnel-1"));
    }

    #[tokio::test]
    async fn deleted_tunnel_no_longer_blocks_device_deletion() {
        let state = test_state();
        insert_test_tunnel(&state, true);

        let _ = delete_tunnel(
            State(state.clone()),
            admin_headers(),
            Path("tunnel-1".to_owned()),
        )
        .await
        .expect("穿透服务应立即永久删除");
        let repeated = delete_tunnel(
            State(state.clone()),
            admin_headers(),
            Path("tunnel-1".to_owned()),
        )
        .await
        .expect_err("永久删除后重复请求应返回未找到");
        assert_eq!(repeated.status, StatusCode::NOT_FOUND);

        let _ = delete_device(
            State(state),
            admin_headers(),
            Path("tunnel-device".to_owned()),
        )
        .await
        .expect("穿透服务删除完成后应立即允许删除设备");
    }

    #[tokio::test]
    async fn site_deletion_enforces_tenant_scope_and_reports_all_dependencies() {
        let state = test_state();
        insert_gateway_deletion_fixture(&state);
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO tenants (id, name) VALUES ('tenant-2', '其他租户');
                 INSERT INTO sites (id, tenant_id, name)
                    VALUES ('site-other', 'tenant-2', '其他租户站点');",
            )
            .expect("应创建其他租户站点");

        let hidden = delete_site(
            State(state.clone()),
            admin_headers(),
            Path("site-other".to_owned()),
        )
        .await
        .expect_err("当前租户不应删除其他租户站点");
        assert_eq!(hidden.status, StatusCode::NOT_FOUND);

        let dependency = delete_site(
            State(state.clone()),
            admin_headers(),
            Path("site-a".to_owned()),
        )
        .await
        .expect_err("仍有业务依赖的站点不应删除");
        assert_eq!(dependency.status, StatusCode::CONFLICT);
        assert!(dependency.message.contains("1 台设备"));
        assert!(dependency.message.contains("1 个共享网络"));
        assert!(dependency.message.contains("1 个互联关系"));
    }

    #[tokio::test]
    async fn empty_site_deletion_revokes_unfinished_enrollments() {
        let state = test_state();
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO sites (id, tenant_id, name)
                    VALUES ('site-empty', 'tenant-1', '空站点');
                 INSERT INTO pending_enrollments
                    (id, tenant_id, site_id, token_digest, status, expires_at)
                    VALUES ('enrollment-empty', 'tenant-1', 'site-empty',
                            'empty-token-digest', 'pending', 1893456000);",
            )
            .expect("应创建空站点与未完成入网请求");

        let response = delete_site(
            State(state.clone()),
            admin_headers(),
            Path("site-empty".to_owned()),
        )
        .await
        .expect("空站点应可删除")
        .0;
        assert!(response.deleted);
        assert!(!response.pending);
        let remaining: (i64, i64) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM sites WHERE id = 'site-empty'),
                    (SELECT COUNT(*) FROM pending_enrollments
                     WHERE id = 'enrollment-empty')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("应检查站点和入网请求已清理");
        assert_eq!(remaining, (0, 0));
    }

    #[tokio::test]
    async fn online_device_deletion_revokes_headscale_and_local_identity_state() {
        let headscale = Arc::new(DeletionHeadscale::default());
        let state = test_state_with_headscale(headscale.clone());
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO sites (id, tenant_id, name)
                    VALUES ('site-device', 'tenant-1', '设备站点');
                 INSERT INTO devices
                    (id, tenant_id, site_id, name, status, capabilities_json)
                    VALUES ('device-delete', 'tenant-1', 'site-device', '在线设备',
                            'online', '[\"tunnel\"]');
                 INSERT INTO device_identities
                    (device_id, certificate_pem, certificate_fingerprint, expires_at)
                    VALUES ('device-delete', 'certificate', 'fingerprint', 1893456000);
                 INSERT INTO mesh_identities
                    (nexo_device_id, tenant_id, headscale_node_id, state, online)
                    VALUES ('device-delete', 'tenant-1', 'node-17', 'ready', 1);
                 INSERT INTO mesh_enrollment_attempts
                    (id, nexo_device_id, tenant_id, headscale_pre_auth_key_id,
                     expires_at, state)
                    VALUES ('attempt-delete', 'device-delete', 'tenant-1', 'key-17',
                            1893456000, 'issued');
                 INSERT INTO device_capability_reports (device_id, report_json)
                    VALUES ('device-delete', '{}');
                 INSERT INTO pending_enrollments
                    (id, tenant_id, token_digest, status, expires_at, device_id)
                    VALUES ('pending-delete', 'tenant-1', 'pending-delete-digest',
                            'approved', 1893456000, 'device-delete');",
            )
            .expect("应创建设备身份清理测试数据");
        state.mesh_offers.lock().await.insert(
            "device-delete".to_owned(),
            MeshEnrollmentOffer {
                auth_key: "test-key".to_owned(),
                auth_key_id: "key-17".to_owned(),
                endpoint: "https://mesh.example.com".to_owned(),
                hostname: "device-delete".to_owned(),
                reset: false,
                tenant_id: Some("tenant-1".to_owned()),
            },
        );
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let session_cancel = CancellationToken::new();
        state.tunnel_sessions.lock().await.insert(
            "device-delete".to_owned(),
            TunnelSessionHandle {
                sender,
                cancel: session_cancel.clone(),
                connection_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            },
        );

        let response = delete_device(
            State(state.clone()),
            admin_headers(),
            Path("device-delete".to_owned()),
        )
        .await
        .expect("在线设备应在撤销外部身份后删除")
        .0;
        assert!(response.deleted);
        assert!(session_cancel.is_cancelled());
        assert_eq!(
            *headscale.expired_keys.lock().expect("应读取 Key 撤销调用"),
            vec!["key-17".to_owned()]
        );
        assert_eq!(
            *headscale
                .deleted_nodes
                .lock()
                .expect("应读取 Node 删除调用"),
            vec!["node-17".to_owned()]
        );
        assert!(!state.mesh_offers.lock().await.contains_key("device-delete"));

        let remaining: (i64, i64, i64, i64, i64, i64) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM devices WHERE id = 'device-delete'),
                    (SELECT COUNT(*) FROM device_identities WHERE device_id = 'device-delete'),
                    (SELECT COUNT(*) FROM mesh_identities
                     WHERE nexo_device_id = 'device-delete'),
                    (SELECT COUNT(*) FROM mesh_enrollment_attempts
                     WHERE nexo_device_id = 'device-delete'),
                    (SELECT COUNT(*) FROM device_capability_reports
                     WHERE device_id = 'device-delete'),
                    (SELECT COUNT(*) FROM pending_enrollments
                     WHERE device_id = 'device-delete')",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("应检查本地设备身份链已清理");
        assert_eq!(remaining, (0, 0, 0, 0, 0, 0));
    }

    #[tokio::test]
    async fn deleting_device_unassigns_and_disables_tunnels_without_losing_config() {
        let state = test_state();
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                r#"
                INSERT INTO devices (id, tenant_id, name, status, capabilities_json)
                    VALUES ('device-with-tunnel', 'tenant-1', '承载设备', 'offline', '[]');
                INSERT INTO tunnels
                    (id, tenant_id, device_id, name, protocol, local_address, local_port,
                     public_port, hostname, enabled, apply_status, apply_revision,
                     origin_protocol, service_name, bridge_socket_path, origin_ca_secret_path,
                     applied_revision, deletion_requested, deletion_revision)
                    VALUES ('device-tunnel', 'tenant-1', 'device-with-tunnel', '保留服务', 'https',
                            '10.0.0.8', 8443, NULL, 'retained', 1, 'ready', 4,
                            'https', 'retained-service', 'tunnels/retained.sock',
                            'secrets/retained.ca.pem', 4, 1, 4);
                INSERT INTO tunnel_applied_states
                    (tunnel_id, applied_revision, applied_config_json, apply_status, apply_error)
                    VALUES ('device-tunnel', 4, '{"retained":true}', 'ready', NULL);
                "#,
            )
            .expect("应创建设备 Tunnel 删除夹具");

        let response = delete_device(
            State(state.clone()),
            admin_headers(),
            Path("device-with-tunnel".to_owned()),
        )
        .await
        .expect("设备删除不应被 Tunnel 阻止")
        .0;
        assert!(response.message.contains("1 个穿透服务"));
        type RetainedTunnel = (
            Option<String>,
            i64,
            String,
            i64,
            Option<u16>,
            Option<String>,
            String,
            i64,
        );
        let retained: RetainedTunnel = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT device_id, enabled, apply_status, deletion_requested,
                            public_port, hostname, local_address, local_port
                     FROM tunnels WHERE id = 'device-tunnel'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .expect("应读取设备删除后的 Tunnel");
        assert_eq!(
            retained,
            (
                None,
                0,
                "disabled".to_owned(),
                0,
                None,
                Some("retained".to_owned()),
                "10.0.0.8".to_owned(),
                8443,
            )
        );
        let applied: (String, Option<String>) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_status, apply_error FROM tunnel_applied_states
                 WHERE tunnel_id = 'device-tunnel'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("Tunnel 应用状态应保留并关闭");
        assert_eq!(
            applied,
            (
                "disabled".to_owned(),
                Some("设备已删除，请重新分配设备".to_owned())
            )
        );
        let audit_count: i64 = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT COUNT(*) FROM audit_events
                 WHERE event_type = 'TUNNEL_UNASSIGNED' AND resource_id = 'device-tunnel'",
                [],
                |row| row.get(0),
            )
            .expect("应记录 Tunnel 解除归属审计");
        assert_eq!(audit_count, 1);
    }

    #[tokio::test]
    async fn active_site_gateway_still_blocks_device_deletion() {
        let state = test_state();
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO sites (id, tenant_id, name, active_site_gateway_device_id)
                    VALUES ('gateway-site', 'tenant-1', '网关站点', 'gateway-device');
                 INSERT INTO devices (id, tenant_id, site_id, name, status)
                    VALUES ('gateway-device', 'tenant-1', 'gateway-site', '活动网关', 'online');",
            )
            .expect("应创建活动站点网关夹具");
        let error = delete_device(
            State(state.clone()),
            admin_headers(),
            Path("gateway-device".to_owned()),
        )
        .await
        .expect_err("活动站点网关仍应阻止设备删除");
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert!(error.message.contains("1 个活动站点网关"));
        let remains: (i64, Option<String>) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM devices WHERE id = 'gateway-device'),
                    (SELECT active_site_gateway_device_id FROM sites WHERE id = 'gateway-site')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("应检查活动网关依赖未改变");
        assert_eq!(remains, (1, Some("gateway-device".to_owned())));
    }

    #[tokio::test]
    async fn device_edit_renames_headscale_and_rolls_back_on_failure() {
        let headscale = Arc::new(DeletionHeadscale::default());
        let state = test_state_with_headscale(headscale.clone());
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO sites (id, tenant_id, name) VALUES ('edit-site', 'tenant-1', '编辑站点');
                 INSERT INTO devices (id, tenant_id, site_id, name, status)
                    VALUES ('edit-device', 'tenant-1', 'edit-site', '旧名称', 'online');
                 INSERT INTO mesh_identities
                    (nexo_device_id, tenant_id, headscale_node_id, state, hostname)
                    VALUES ('edit-device', 'tenant-1', 'edit-node', 'ready', 'old-host');",
            )
            .expect("应创建设备编辑夹具");
        let updated = update_device(
            State(state.clone()),
            admin_headers(),
            Path("edit-device".to_owned()),
            Json(UpdateDeviceRequest {
                name: "新名称".to_owned(),
                site_id: Some("edit-site".to_owned()),
            }),
        )
        .await
        .expect("设备改名应成功")
        .0;
        assert_eq!(updated.name, "新名称");
        let expected_hostname = mesh_hostname("tenant-1", "新名称", "edit-device");
        assert_eq!(
            *headscale
                .renamed_nodes
                .lock()
                .expect("应读取 Headscale 改名记录"),
            vec![("edit-node".to_owned(), expected_hostname.clone())]
        );
        let local: (String, String) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT d.name, m.hostname FROM devices d
                 JOIN mesh_identities m ON m.nexo_device_id = d.id
                 WHERE d.id = 'edit-device'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("应读取改名后的本地资料");
        assert_eq!(local, ("新名称".to_owned(), expected_hostname));

        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO sites (id, tenant_id, name) VALUES ('blocked-site', 'tenant-1', '依赖站点');
                 INSERT INTO site_networks
                    (id, tenant_id, site_id, name, publisher_device_id, interface_id,
                     address_family, current_prefix)
                    VALUES ('edit-network', 'tenant-1', 'edit-site', '编辑网络',
                            'edit-device', 'eth0', 'ipv4', '192.168.50.0/24');",
            )
            .expect("应创建跨站点依赖夹具");
        let dependency = update_device(
            State(state.clone()),
            admin_headers(),
            Path("edit-device".to_owned()),
            Json(UpdateDeviceRequest {
                name: "再次改名".to_owned(),
                site_id: Some("blocked-site".to_owned()),
            }),
        )
        .await
        .expect_err("承载共享网络的设备不得跨站点移动");
        assert_eq!(dependency.status, StatusCode::CONFLICT);
        assert!(dependency.message.contains("共享网络"));

        let failing_headscale = Arc::new(DeletionHeadscale {
            fail_node_rename: true,
            ..DeletionHeadscale::default()
        });
        let failing_state = test_state_with_headscale(failing_headscale);
        failing_state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO devices (id, tenant_id, name, status)
                    VALUES ('rename-failure-device', 'tenant-1', '保持旧名', 'online');
                 INSERT INTO mesh_identities
                    (nexo_device_id, tenant_id, headscale_node_id, state, hostname)
                    VALUES ('rename-failure-device', 'tenant-1', 'rename-failure-node',
                            'ready', 'old-host');",
            )
            .expect("应创建改名失败夹具");
        let rename_error = update_device(
            State(failing_state.clone()),
            admin_headers(),
            Path("rename-failure-device".to_owned()),
            Json(UpdateDeviceRequest {
                name: "不应落库".to_owned(),
                site_id: None,
            }),
        )
        .await
        .expect_err("Headscale 改名失败时设备资料不得修改");
        assert_eq!(rename_error.status, StatusCode::BAD_GATEWAY);
        let unchanged_name: String = failing_state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT name FROM devices WHERE id = 'rename-failure-device'",
                [],
                |row| row.get(0),
            )
            .expect("应检查改名失败后的本地资料");
        assert_eq!(unchanged_name, "保持旧名");
    }

    #[tokio::test]
    async fn headscale_failure_keeps_local_device_record() {
        let headscale = Arc::new(DeletionHeadscale {
            fail_node_deletion: true,
            ..DeletionHeadscale::default()
        });
        let state = test_state_with_headscale(headscale);
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO devices (id, tenant_id, name, status)
                    VALUES ('device-failed', 'tenant-1', '撤销失败设备', 'online');
                 INSERT INTO mesh_identities
                    (nexo_device_id, tenant_id, headscale_node_id, state)
                    VALUES ('device-failed', 'tenant-1', 'node-failed', 'ready');",
            )
            .expect("应创建 Headscale 失败测试设备");

        let error = delete_device(
            State(state.clone()),
            admin_headers(),
            Path("device-failed".to_owned()),
        )
        .await
        .expect_err("Headscale 停用失败时不得删除本地记录");
        assert_eq!(error.status, StatusCode::BAD_GATEWAY);
        let remaining: (i64, i64) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM devices WHERE id = 'device-failed'),
                    (SELECT COUNT(*) FROM mesh_identities
                     WHERE nexo_device_id = 'device-failed')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("应检查失败后本地数据仍保留");
        assert_eq!(remaining, (1, 1));
    }

    #[tokio::test]
    async fn network_deletion_obeys_order_and_waits_for_exact_revision() {
        let state = test_state();
        insert_gateway_deletion_fixture(&state);

        let device_dependency = delete_device(
            State(state.clone()),
            admin_headers(),
            Path("device-a".to_owned()),
        )
        .await
        .expect_err("共享网络仍存在时不得删除发布设备");
        assert_eq!(device_dependency.status, StatusCode::CONFLICT);
        assert!(device_dependency.message.contains("1 个共享网络"));

        let network_dependency = delete_site_network(
            State(state.clone()),
            admin_headers(),
            Path("network-a".to_owned()),
        )
        .await
        .expect_err("互联关系仍存在时不得删除共享网络");
        assert_eq!(network_dependency.status, StatusCode::CONFLICT);
        assert!(network_dependency.message.contains("1 个互联关系"));

        let first_link = delete_site_link(
            State(state.clone()),
            admin_headers(),
            Path("link-a-b".to_owned()),
        )
        .await
        .expect("站点互联应进入等待删除")
        .0;
        let repeated_link = delete_site_link(
            State(state.clone()),
            admin_headers(),
            Path("link-a-b".to_owned()),
        )
        .await
        .expect("重复删除站点互联应保持幂等")
        .0;
        assert!(first_link.pending && repeated_link.pending);
        let link_revision: i64 = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT apply_revision FROM site_links WHERE id = 'link-a-b'",
                [],
                |row| row.get(0),
            )
            .expect("应读取 Link 删除 revision");
        assert_eq!(link_revision, 5);

        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO gateway_route_applies
                    (device_id, network_id, site_link_id, desired_revision,
                     local_status, control_plane_status, remote_status)
                 VALUES
                    ('device-a', 'network-b', 'link-a-b', 4,
                     'disabled', 'disabled', 'disabled'),
                    ('device-b', 'network-a', 'link-a-b', 4,
                     'disabled', 'disabled', 'disabled');",
            )
            .expect("应写入旧 Link revision 的撤销状态");
        finalize_resource_deletions_for_test(&state);
        let old_link_remaining: i64 = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT COUNT(*) FROM site_links WHERE id = 'link-a-b'",
                [],
                |row| row.get(0),
            )
            .expect("应检查旧 revision 未提前删除 Link");
        assert_eq!(old_link_remaining, 1);

        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute(
                "UPDATE gateway_route_applies SET desired_revision = 5
                 WHERE site_link_id = 'link-a-b'",
                [],
            )
            .expect("应推进 Link 到当前删除 revision");
        finalize_resource_deletions_for_test(&state);
        let link_remaining: i64 = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT COUNT(*) FROM site_links WHERE id = 'link-a-b'",
                [],
                |row| row.get(0),
            )
            .expect("应检查 Link 已完成删除");
        assert_eq!(link_remaining, 0);

        let first_network = delete_site_network(
            State(state.clone()),
            admin_headers(),
            Path("network-a".to_owned()),
        )
        .await
        .expect("共享网络应进入等待删除")
        .0;
        let repeated_network = delete_site_network(
            State(state.clone()),
            admin_headers(),
            Path("network-a".to_owned()),
        )
        .await
        .expect("重复删除共享网络应保持幂等")
        .0;
        assert!(first_network.pending && repeated_network.pending);
        let network_revision: i64 = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT desired_revision FROM gateway_network_states
                 WHERE site_network_id = 'network-a'",
                [],
                |row| row.get(0),
            )
            .expect("应读取共享网络删除 revision");
        assert_eq!(network_revision, 5);

        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute(
                "INSERT INTO gateway_route_applies
                    (device_id, network_id, site_link_id, desired_revision,
                     local_status, control_plane_status, remote_status)
                 VALUES ('device-a', 'network-a', '', 4,
                         'disabled', 'disabled', 'disabled')",
                [],
            )
            .expect("应写入旧 Network revision 的撤销状态");
        finalize_resource_deletions_for_test(&state);
        let old_network_remaining: i64 = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT COUNT(*) FROM site_networks WHERE id = 'network-a'",
                [],
                |row| row.get(0),
            )
            .expect("应检查旧 revision 未提前删除共享网络");
        assert_eq!(old_network_remaining, 1);

        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute(
                "UPDATE gateway_route_applies SET desired_revision = 5
                 WHERE device_id = 'device-a' AND network_id = 'network-a'
                   AND site_link_id = ''",
                [],
            )
            .expect("应推进 Network 到当前删除 revision");
        finalize_resource_deletions_for_test(&state);
        let network_remaining: i64 = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT COUNT(*) FROM site_networks WHERE id = 'network-a'",
                [],
                |row| row.get(0),
            )
            .expect("应检查共享网络已完成删除");
        assert_eq!(network_remaining, 0);

        let audit_counts: (i64, i64, i64, i64) = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM audit_events
                     WHERE event_type = 'SITE_LINK_DELETE_REQUESTED'),
                    (SELECT COUNT(*) FROM audit_events
                     WHERE event_type = 'SITE_LINK_DELETED'),
                    (SELECT COUNT(*) FROM audit_events
                     WHERE event_type = 'SITE_NETWORK_DELETE_REQUESTED'),
                    (SELECT COUNT(*) FROM audit_events
                     WHERE event_type = 'SITE_NETWORK_DELETED')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("应读取网络资源删除审计");
        assert_eq!(audit_counts, (1, 1, 1, 1));
    }

    #[tokio::test]
    async fn overview_requires_admin_session() {
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

    #[tokio::test]
    async fn bootstrap_code_cannot_authorize_management_api() {
        let state = test_state();
        {
            let connection = state.db.lock().unwrap();
            connection.execute("DELETE FROM auth_sessions", []).unwrap();
            connection.execute("DELETE FROM users", []).unwrap();
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-nexo-admin-token", HeaderValue::from_static("test-admin"));
        let error = overview(State(state), headers)
            .await
            .expect_err("Bootstrap Code 不应拥有普通管理 API 权限");
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn gateway_api_rejects_default_routes_and_unknown_tenants() {
        let state = test_state();
        for prefix in ["0.0.0.0/0", "::/0"] {
            let error = create_site_network(
                State(state.clone()),
                admin_headers(),
                Json(CreateSiteNetworkRequest {
                    tenant_id: "default".to_owned(),
                    site_id: "site-missing".to_owned(),
                    name: "默认路由".to_owned(),
                    publisher_device_id: "device-missing".to_owned(),
                    interface_id: "eth0".to_owned(),
                    prefix: prefix.to_owned(),
                    source: SiteNetworkSourceRequest::Detected,
                }),
            )
            .await
            .expect_err("默认路由不应进入网关 Desired State");
            assert_eq!(error.status, StatusCode::BAD_REQUEST);
            assert!(error.message.contains("默认路由"));
        }

        let error = create_site(
            State(state),
            admin_headers(),
            Json(CreateSiteRequest {
                tenant_id: "missing-tenant".to_owned(),
                name: "错误租户".to_owned(),
            }),
        )
        .await
        .expect_err("不存在的租户不应创建站点");
        assert_eq!(error.status, StatusCode::NOT_FOUND);
        assert_eq!(error.message, "租户不存在");
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
        assert!(report_allows_headscale_reconcile(
            &GatewayRouteApplyReport {
                revision: 3,
                routes: vec![
                    GatewayRouteApplyResult {
                        network_id: "network-v4".to_owned(),
                        site_link_id: None,
                        prefix: "192.168.10.0/24".to_owned(),
                        revision: 3,
                        enabled: true,
                        local_applied: true,
                        control_plane_status: None,
                        remote_applied: false,
                        error_message: None,
                    },
                    GatewayRouteApplyResult {
                        network_id: "network-v6".to_owned(),
                        site_link_id: None,
                        prefix: "2001:db8:10::/64".to_owned(),
                        revision: 3,
                        enabled: true,
                        local_applied: false,
                        control_plane_status: None,
                        remote_applied: false,
                        error_message: Some("设备未开启 IPv6 转发".to_owned()),
                    },
                ],
                mesh_identity: None,
            }
        ));
    }

    #[tokio::test]
    async fn shared_network_admission_and_health_are_checked_per_address_family() {
        let state = test_state();
        let mut report = GatewayCapabilityReport {
            platform: "linux".to_owned(),
            tun_available: true,
            net_admin_available: true,
            ipv4_forwarding: true,
            ipv6_forwarding: false,
            local_networks: vec![
                DetectedLocalNetwork {
                    interface_id: "eth0".to_owned(),
                    prefix: "192.168.10.0/24".to_owned(),
                    gateway_address: Some("192.168.10.2".to_owned()),
                },
                DetectedLocalNetwork {
                    interface_id: "eth1".to_owned(),
                    prefix: "2001:db8:10::/64".to_owned(),
                    gateway_address: Some("2001:db8:10::2".to_owned()),
                },
            ],
            subnet_gateway: CapabilityState::Ready,
            subnet_gateway_reason: None,
            site_gateway: CapabilityState::Ready,
            site_gateway_reason: None,
        };
        {
            let connection = state.db.lock().expect("数据库锁应可用");
            connection
                .execute_batch(
                    "INSERT INTO sites (id, tenant_id, name)
                        VALUES ('site-family', 'tenant-1', '双栈站点');
                     INSERT INTO devices
                        (id, tenant_id, site_id, name, status, capabilities_json)
                        VALUES ('device-family', 'tenant-1', 'site-family', '双栈网关',
                                'online', '[\"subnet_gateway\",\"site_gateway\"]');
                     INSERT INTO mesh_identities
                        (nexo_device_id, tenant_id, headscale_node_id, state, online)
                        VALUES ('device-family', 'tenant-1', '42', 'ready', 1);",
                )
                .expect("应创建地址族测试设备");
            connection
                .execute(
                    "INSERT INTO device_capability_reports (device_id, report_json)
                     VALUES ('device-family', ?1)",
                    [serde_json::to_string(&report).unwrap()],
                )
                .expect("应保存 IPv4-only 能力报告");
        }

        let _ = create_site_network(
            State(state.clone()),
            admin_headers(),
            Json(CreateSiteNetworkRequest {
                tenant_id: "tenant-1".to_owned(),
                site_id: "site-family".to_owned(),
                name: "IPv4 LAN".to_owned(),
                publisher_device_id: "device-family".to_owned(),
                interface_id: "eth0".to_owned(),
                prefix: "192.168.10.0/24".to_owned(),
                source: SiteNetworkSourceRequest::Detected,
            }),
        )
        .await
        .expect("IPv4-only 设备应能共享 IPv4 网络");
        let error = create_site_network(
            State(state.clone()),
            admin_headers(),
            Json(CreateSiteNetworkRequest {
                tenant_id: "tenant-1".to_owned(),
                site_id: "site-family".to_owned(),
                name: "IPv6 LAN".to_owned(),
                publisher_device_id: "device-family".to_owned(),
                interface_id: "eth1".to_owned(),
                prefix: "2001:db8:10::/64".to_owned(),
                source: SiteNetworkSourceRequest::Detected,
            }),
        )
        .await
        .expect_err("IPv4-only 设备不应共享 IPv6 网络");
        assert_eq!(error.message, "设备未开启 IPv6 转发");

        report.ipv4_forwarding = false;
        report.ipv6_forwarding = true;
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute(
                "UPDATE device_capability_reports SET report_json = ?1
                 WHERE device_id = 'device-family'",
                [serde_json::to_string(&report).unwrap()],
            )
            .expect("应切换为 IPv6-only 能力报告");
        let _ = create_site_network(
            State(state.clone()),
            admin_headers(),
            Json(CreateSiteNetworkRequest {
                tenant_id: "tenant-1".to_owned(),
                site_id: "site-family".to_owned(),
                name: "IPv6 LAN".to_owned(),
                publisher_device_id: "device-family".to_owned(),
                interface_id: "eth1".to_owned(),
                prefix: "2001:db8:10::/64".to_owned(),
                source: SiteNetworkSourceRequest::Detected,
            }),
        )
        .await
        .expect("IPv6-only 设备应能共享 IPv6 网络");

        let (health, message) = inspect_gateway_device(
            &state.db.lock().expect("数据库锁应可用"),
            "device-family",
            Some("eth0"),
            "192.168.10.0/24",
            false,
            true,
        )
        .expect("应计算现有 IPv4 网络健康状态");
        assert_eq!(health, GatewayHealthStatus::Failed);
        assert_eq!(message.as_deref(), Some("设备未开启 IPv4 转发"));
    }

    #[tokio::test]
    async fn site_link_rejects_networks_from_different_address_families() {
        let state = test_state();
        state
            .db
            .lock()
            .expect("数据库锁应可用")
            .execute_batch(
                "INSERT INTO sites (id, tenant_id, name) VALUES
                    ('site-v4', 'tenant-1', 'IPv4 站点'),
                    ('site-v6', 'tenant-1', 'IPv6 站点');
                 INSERT INTO devices
                    (id, tenant_id, site_id, name, status, capabilities_json) VALUES
                    ('device-v4', 'tenant-1', 'site-v4', 'IPv4 网关', 'online',
                     '[\"subnet_gateway\",\"site_gateway\"]'),
                    ('device-v6', 'tenant-1', 'site-v6', 'IPv6 网关', 'online',
                     '[\"subnet_gateway\",\"site_gateway\"]');
                 INSERT INTO site_networks
                    (id, tenant_id, site_id, name, publisher_device_id, interface_id,
                     address_family, current_prefix) VALUES
                    ('network-v4', 'tenant-1', 'site-v4', 'IPv4 LAN', 'device-v4', 'eth0',
                     'ipv4', '192.168.10.0/24'),
                    ('network-v6', 'tenant-1', 'site-v6', 'IPv6 LAN', 'device-v6', 'eth0',
                     'ipv6', '2001:db8:20::/64');
                 INSERT INTO gateway_network_states
                    (site_network_id, desired_prefix, desired_revision) VALUES
                    ('network-v4', '192.168.10.0/24', 1),
                    ('network-v6', '2001:db8:20::/64', 1);",
            )
            .expect("应创建异族站点网络");

        let error = create_site_link(
            State(state),
            admin_headers(),
            Json(CreateSiteLinkRequest {
                tenant_id: "tenant-1".to_owned(),
                left_site_id: "site-v4".to_owned(),
                left_network_ids: vec!["network-v4".to_owned()],
                right_site_id: "site-v6".to_owned(),
                right_network_ids: vec!["network-v6".to_owned()],
                next_hops: SiteLinkNextHops::default(),
            }),
        )
        .await
        .expect_err("跨地址族站点互联必须被拒绝");
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.message, "两侧共享网络的 IPv4/IPv6 地址族集合必须一致");
    }

    #[tokio::test]
    async fn enrollment_request_can_be_submitted_and_approved_once() {
        let state = test_state();
        let created = create_enrollment(
            State(state.clone()),
            admin_headers(),
            Json(CreateEnrollmentRequest {
                tenant_id: "tenant-1".to_owned(),
                site_id: None,
                ttl_seconds: Some(900),
                device_name: Some("Web 指定 NAS".to_owned()),
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
                device_name: "容器主机名".to_owned(),
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
        let approved_device_id = approved.device_id.clone().expect("审批应返回设备 ID");
        let approved_name: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT name FROM devices WHERE id = ?1",
                [&approved_device_id],
                |row| row.get(0),
            )
            .expect("应能读取设备名称");
        assert_eq!(approved_name, "Web 指定 NAS");

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
        let state = test_state();
        let created = create_enrollment(
            State(state.clone()),
            admin_headers(),
            Json(CreateEnrollmentRequest {
                tenant_id: "tenant-1".to_owned(),
                site_id: None,
                ttl_seconds: Some(900),
                device_name: None,
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
        let fallback_name: String = state
            .db
            .lock()
            .expect("数据库锁应可用")
            .query_row(
                "SELECT name FROM devices WHERE id = ?1",
                [&device_id],
                |row| row.get(0),
            )
            .expect("应能读取使用 Agent 主机名的设备");
        assert_eq!(fallback_name, "控制通道设备");
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
                source: SiteNetworkSourceRequest::Detected,
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
                source: SiteNetworkSourceRequest::Detected,
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
        assert!(networks.iter().all(|network| {
            network.health_error.as_deref()
                == Some("域名与 HTTPS 尚未就绪，新的组网加入和网关应用已暂停")
        }));
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
                left_network_ids: vec![left.id.clone()],
                right_site_id: "site-b".to_owned(),
                right_network_ids: vec![right.id.clone()],
                next_hops: SiteLinkNextHops::default(),
            }),
        )
        .await
        .expect("不重叠的站点网络应能创建互联")
        .0;
        assert_eq!(link.apply_status, ApplyStatus::Checking);
        assert_eq!(link.health_status, GatewayHealthStatus::Degraded);
        assert_eq!(
            link.health_error.as_deref(),
            Some("域名与 HTTPS 尚未就绪，新的组网加入和网关应用已暂停")
        );
        assert_eq!(link.left_site_name, "家庭");
        assert_eq!(link.right_site_name, "办公室");
        assert_eq!(
            link.left_networks
                .first()
                .map(|network| network.prefix.as_str()),
            Some("192.168.10.0/24")
        );
        assert_eq!(
            link.right_networks
                .first()
                .map(|network| network.prefix.as_str()),
            Some("192.168.20.0/24")
        );
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
            Some("域名与 HTTPS 尚未就绪，新的组网加入和网关应用已暂停")
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
                source: SiteNetworkSourceRequest::Detected,
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
                left_network_ids: vec![left.id],
                right_site_id: "site-b".to_owned(),
                right_network_ids: vec![conflict.id],
                next_hops: SiteLinkNextHops::default(),
            }),
        )
        .await
        .expect_err("重叠网段不应建立站点互联");
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert!(error.message.contains("网络地址冲突"));
    }
}
