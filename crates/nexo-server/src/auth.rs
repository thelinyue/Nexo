//! Nexo 管理认证边界。
//!
//! 认证状态只保存在服务端：Session ID、CSRF Token 和恢复码都只以摘要形式
//! 写入 SQLite。LAN HTTP 与公网 HTTPS 使用不同的 Session 通道，避免一个
//! 未加密入口的 Cookie 被误用于公网安全入口。

use std::{fs, net::IpAddr, path::Path};

use argon2::{
    password_hash::{
        rand_core::{OsRng, RngCore},
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use axum::{
    extract::{connect_info::ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{unix_now, ApiError, AppState, PublicBackendPeer};

const BOOTSTRAP_FILE: &str = "bootstrap.code";
const SESSION_IDLE_SECONDS: i64 = 24 * 60 * 60;
const SESSION_ABSOLUTE_SECONDS: i64 = 7 * 24 * 60 * 60;
const RECOVERY_SECONDS: i64 = 10 * 60;
const LOGIN_WINDOW_SECONDS: i64 = 15 * 60;
const LOGIN_FAILURE_LIMIT: i64 = 5;

pub const LOCAL_SESSION_COOKIE: &str = "nexo_local_session";
pub const HTTPS_SESSION_COOKIE: &str = "nexo_secure_session";
pub const LOCAL_CSRF_COOKIE: &str = "nexo_local_csrf";
pub const HTTPS_CSRF_COOKIE: &str = "nexo_secure_csrf";
pub const SESSION_AUTH_HEADER: &str = "x-nexo-session-authenticated";
const PUBLIC_ENTRY_HEADER: &str = "x-nexo-public-entry";

/// Session 所属的入口通道；两个通道的凭据永远不能交叉使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionChannel {
    LocalHttp,
    PublicHttps,
}

impl SessionChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalHttp => "local_http",
            Self::PublicHttps => "public_https",
        }
    }

    fn session_cookie(self) -> &'static str {
        match self {
            Self::LocalHttp => LOCAL_SESSION_COOKIE,
            Self::PublicHttps => HTTPS_SESSION_COOKIE,
        }
    }

    fn csrf_cookie(self) -> &'static str {
        match self {
            Self::LocalHttp => LOCAL_CSRF_COOKIE,
            Self::PublicHttps => HTTPS_CSRF_COOKIE,
        }
    }

    fn secure(self) -> bool {
        matches!(self, Self::PublicHttps)
    }
}

/// 中间件验证后的请求身份。业务处理器仍通过现有 `require_admin` 边界读取。
#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub user_id: String,
    pub tenant_id: String,
    pub session_id: String,
    pub session_digest: String,
    pub csrf_digest: String,
    pub channel: SessionChannel,
}

#[derive(Debug, Deserialize)]
pub struct InitializeRequest {
    pub bootstrap_code: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct RecoverRequest {
    pub recovery_code: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthStatusResponse {
    pub initialized: bool,
    pub authenticated: bool,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub role: Option<String>,
    /// 内部工作空间 ID；普通用户固定绑定自己的空间，管理员可通过
    /// `x-nexo-workspace` 选择要管理的空间。
    pub workspace_id: Option<String>,
    pub channel: Option<String>,
    pub csrf_token: Option<String>,
    pub local_http_warning: bool,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub channel: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user_id: String,
    pub username: String,
    pub role: String,
    pub workspace_id: String,
    pub channel: String,
    pub csrf_token: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub role: String,
    pub workspace_id: String,
    pub created_at: i64,
    pub enabled: bool,
    pub mesh_revocation_pending: bool,
}

#[derive(Debug, Serialize)]
pub struct RecoveryResponse {
    pub message: String,
}

/// 首次启动准备一次性初始化口令。明文只存在 Secret 文件，初始化完成后删除。
pub fn ensure_bootstrap_code(
    connection: &rusqlite::Connection,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let users: i64 = connection.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
    let path = data_dir.join(BOOTSTRAP_FILE);
    if users > 0 {
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|error| anyhow::anyhow!("无法清理已失效的 Bootstrap Secret：{error}"))?;
        }
        return Ok(());
    }
    if path.exists() {
        return Ok(());
    }
    fs::create_dir_all(data_dir)?;
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let code = hex::encode(bytes);
    let temporary = data_dir.join(format!(".{BOOTSTRAP_FILE}.{}.tmp", std::process::id()));
    fs::write(&temporary, code.as_bytes())?;
    set_private_permissions(&temporary)?;
    fs::rename(&temporary, &path)?;
    set_private_permissions(&path)?;
    // 明文只写入 0600 Secret 文件；日志、诊断和 Web API 永远不显示口令。
    tracing::warn!("Nexo 尚未初始化；Bootstrap Code 已保存到受限 Secret 文件，请使用 `nexo bootstrap-code` 在本机读取");
    Ok(())
}

/// 本地恢复 CLI 读取尚未使用的 Bootstrap Code；初始化后文件不存在。
pub fn read_bootstrap_code(data_dir: &Path) -> anyhow::Result<String> {
    let path = data_dir.join(BOOTSTRAP_FILE);
    let code = fs::read_to_string(&path).map_err(|error| {
        anyhow::anyhow!("无法读取 Bootstrap Code，请确认 Nexo 仍未初始化：{error}")
    })?;
    let code = code.trim().to_owned();
    if code.is_empty() {
        anyhow::bail!("Bootstrap Code 为空");
    }
    Ok(code)
}

/// 所有 HTTP 请求先经过这里；外部伪造的认证标记会被删除，只有有效 Session
/// 才能重新注入，因此旧处理器不能被普通客户端通过 Header 绕过认证。
pub async fn session_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    request.headers_mut().remove(SESSION_AUTH_HEADER);
    // 只有来自 loopback 的反向代理才能声明公网 HTTPS 通道。LAN 客户端即使
    // 伪造 X-Forwarded-Proto，也只能得到本地 HTTP Session。
    // 普通 LAN listener 即使被本机客户端访问，也使用 `ConnectInfo<SocketAddr>`；
    // 只有专用的 TLS 回源 listener 才会注入 `PublicBackendPeer`。不能仅凭
    // 远端地址是 loopback 就信任公网转发头，否则本机请求可以伪造 HTTPS 通道，
    // 让两个独立 Session Cookie 失去隔离。
    let loopback_proxy = request
        .extensions()
        .get::<ConnectInfo<PublicBackendPeer>>()
        .is_some_and(|info| {
            let peer = (info.0).0;
            peer.ip().is_loopback()
        });
    let channel = if loopback_proxy {
        request_channel(request.headers())
    } else {
        // 这些 Header 只能由本机 Caddy 注入。先删除再交给后续处理器，避免
        // 处理器再次调用 request_channel 时接受外部伪造的 HTTPS 通道。
        request.headers_mut().remove("x-forwarded-proto");
        request.headers_mut().remove(PUBLIC_ENTRY_HEADER);
        SessionChannel::LocalHttp
    };
    if let Some(session) = load_session(&state, request.headers(), channel) {
        request.extensions_mut().insert(session);
        request
            .headers_mut()
            .insert(SESSION_AUTH_HEADER, HeaderValue::from_static("1"));
    }
    let path = request.uri().path();
    if is_admin_only_path(path) {
        if let Some(session) = load_session(&state, request.headers(), channel) {
            if !session_is_system_admin(&state, &session) {
                return ApiError::new(StatusCode::FORBIDDEN, "当前账号没有系统设置权限")
                    .into_response();
            }
        }
    }
    let unsafe_method = !matches!(
        request.method(),
        &axum::http::Method::GET | &axum::http::Method::HEAD | &axum::http::Method::OPTIONS
    );
    let auth_public_path = matches!(
        path,
        "/api/v1/auth/status"
            | "/api/v1/auth/initialize"
            | "/api/v1/auth/login"
            | "/api/v1/auth/recover"
    );
    let agent_path = path.starts_with("/api/v1/agent/");
    if unsafe_method
        && !auth_public_path
        && !agent_path
        && load_session(&state, request.headers(), channel).is_some()
    {
        if let Err(error) = require_csrf(&state, request.headers()) {
            return error.into_response();
        }
    }
    next.run(request).await
}

/// 由 Caddy 写入的内部标记只在 loopback 代理链路上有效；未经过 Caddy 的请求
/// 永远按 LAN HTTP 处理，避免客户端自行伪造 HTTPS Session 通道。
pub fn request_channel(headers: &HeaderMap) -> SessionChannel {
    let is_https = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("https"));
    let is_public = headers
        .get(PUBLIC_ENTRY_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "1");
    if is_https && is_public {
        SessionChannel::PublicHttps
    } else {
        SessionChannel::LocalHttp
    }
}

/// 校验当前请求的 CSRF Header。GET/HEAD 等只读请求不需要调用此函数。
pub fn require_csrf(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let channel = request_channel(headers);
    let session = load_session(state, headers, channel)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "登录状态已失效，请重新登录"))?;
    let supplied = headers
        .get("x-nexo-csrf")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "缺少安全校验，请刷新页面后重试"))?;
    if digest(supplied) != session.csrf_digest {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "安全校验无效，请刷新页面后重试",
        ));
    }
    Ok(())
}

/// 管理 API 的统一授权边界。
///
/// Bootstrap Code 只属于初始化接口，不能作为普通管理 API 的长期凭证。
/// 所有业务请求都必须携带当前入口对应的有效管理员 Session。
pub fn authorize_admin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let channel = request_channel(headers);
    let session = load_session(state, headers, channel)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "请先登录管理员账号"))?;
    if session_is_system_admin(state, &session) {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "当前账号没有系统管理员权限",
        ))
    }
}

/// 返回当前 Session 的工作空间。
///
/// 管理接口不能相信请求体里的 `tenant_id`，必须以登录 Session 的租户作为
/// 作用域。保留这个独立函数让只读接口也能复用同一条授权边界，避免出现
/// “已经登录但列表读到了其他租户数据”的旁路。
pub fn admin_tenant_id(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let channel = request_channel(headers);
    let Some(session) = load_session(state, headers, channel) else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "请先登录管理员账号",
        ));
    };
    // 读取这两个字段同时表达授权边界：Session 必须仍属于记录中的租户，
    // 摘要只用于服务端审计和吊销，不向客户端回显。
    let _session_scope = (&session.tenant_id, &session.session_digest);
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let identity: Option<(String, String)> = connection
        .query_row(
            "SELECT role, COALESCE(tenant_id, '') FROM users WHERE id = ?1",
            [&session.user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取当前账号身份"))?;
    let Some((role, tenant_id)) = identity else {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "当前账号不存在"));
    };
    if tenant_id != session.tenant_id {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "登录空间已失效，请重新登录",
        ));
    }
    if role == "system_admin" {
        if let Some(workspace) = headers
            .get("x-nexo-workspace")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let exists: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM tenants WHERE id = ?1",
                    [workspace],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查管理空间")
                })?;
            if exists == 0 {
                return Err(ApiError::new(StatusCode::NOT_FOUND, "管理空间不存在"));
            }
            return Ok(workspace.to_owned());
        }
    }
    Ok(session.tenant_id)
}

/// 判断当前 Session 是否属于全局系统管理员；角色读取集中在这里，避免
/// 普通业务处理器把请求体中的角色或工作空间当成授权依据。
fn session_is_system_admin(state: &AppState, session: &AuthenticatedSession) -> bool {
    state
        .db
        .lock()
        .ok()
        .and_then(|connection| {
            connection
                .query_row(
                    "SELECT role FROM users WHERE id = ?1 AND tenant_id = ?2",
                    params![session.user_id, session.tenant_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .ok()
                .flatten()
        })
        .is_some_and(|role| role == "system_admin")
}

fn user_identity(state: &AppState, user_id: &str, tenant_id: &str) -> Option<(String, String)> {
    state.db.lock().ok().and_then(|connection| {
        connection
            .query_row(
                "SELECT role, COALESCE(tenant_id, '') FROM users WHERE id = ?1 AND tenant_id = ?2",
                params![user_id, tenant_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .ok()
            .flatten()
    })
}

/// 这些接口包含实例级 Secret、域名和边缘组件配置，只允许系统管理员。
/// 设备、穿透和网络互联接口仍由 `admin_tenant_id` 按工作空间隔离。
fn is_admin_only_path(path: &str) -> bool {
    path.starts_with("/api/v1/settings/")
        || path.starts_with("/api/v1/public-domains")
        || path.starts_with("/api/v1/public-domain-migrations")
        || path == "/api/v1/users"
        || path.starts_with("/api/v1/users/")
}

/// 系统管理员创建普通用户。每个用户同时得到稳定的内部工作空间，
/// Headscale 用户在第一次官方客户端入网时按需创建。
pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    authorize_admin(&state, &headers)?;
    validate_username(&request.username)?;
    validate_password(&request.password)?;
    let username = request.username.trim().to_owned();
    let user_id = uuid::Uuid::new_v4().to_string();
    let workspace_id = format!("workspace-{user_id}");
    let password_hash = hash_password(&request.password)
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let now = unix_now();
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .unchecked_transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始用户创建事务"))?;
    transaction
        .execute(
            "INSERT INTO tenants (id, name) VALUES (?1, ?2)",
            params![workspace_id, username],
        )
        .map_err(|error| {
            tracing::warn!("创建普通用户工作空间失败：{error}");
            ApiError::new(StatusCode::CONFLICT, "用户工作空间已存在")
        })?;
    transaction
        .execute(
            "INSERT INTO users (id, tenant_id, username, role, password_hash)
             VALUES (?1, ?2, ?3, 'tenant', ?4)",
            params![user_id, workspace_id, username, password_hash],
        )
        .map_err(|error| {
            tracing::warn!("创建普通用户账号失败：{error}");
            ApiError::new(StatusCode::CONFLICT, "用户名已存在")
        })?;
    transaction
        .execute(
            "INSERT INTO audit_events (tenant_id, actor_user_id, event_type, resource_type, resource_id, detail_json)
             VALUES (?1, NULL, 'user_created', 'user', ?2, '{}')",
            params![workspace_id, user_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法写入用户审计记录"))?;
    transaction
        .commit()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交用户创建事务"))?;
    Ok(Json(UserResponse {
        id: user_id,
        username,
        role: "tenant".to_owned(),
        workspace_id,
        created_at: now,
        enabled: true,
        mesh_revocation_pending: false,
    }))
}

/// 管理员查看用户目录；密码摘要、Session 和 Headscale 凭证永不返回。
pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserResponse>>, ApiError> {
    authorize_admin(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT id, username, role, COALESCE(tenant_id, ''), created_at,
                    enabled, mesh_revocation_pending
             FROM users ORDER BY role ASC, username ASC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取用户列表"))?;
    let rows = statement
        .query_map([], |row| {
            Ok(UserResponse {
                id: row.get(0)?,
                username: row.get(1)?,
                role: row.get(2)?,
                workspace_id: row.get(3)?,
                created_at: row.get(4)?,
                enabled: row.get::<_, i64>(5)? != 0,
                mesh_revocation_pending: row.get::<_, i64>(6)? != 0,
            })
        })
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取用户列表"))?;
    rows.map(|row| {
        row.map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "用户数据格式无效"))
    })
    .collect::<Result<Vec<_>, _>>()
    .map(Json)
}

pub async fn auth_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let initialized = user_count(&connection)? > 0;
    drop(connection);
    let channel = request_channel(&headers);
    let session = load_session(&state, &headers, channel);
    let (csrf_token, set_csrf_cookie) = if let Some(session) = session.as_ref() {
        match cookie_value(&headers, channel.csrf_cookie()) {
            Some(token) if digest(&token) == session.csrf_digest => (Some(token), false),
            _ => {
                let token = random_token();
                let connection = state.db.lock().map_err(|_| {
                    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用")
                })?;
                connection
                    .execute(
                        "UPDATE auth_sessions SET csrf_digest = ?1
                         WHERE session_digest = ?2 AND revoked_at IS NULL",
                        params![digest(&token), session.session_digest],
                    )
                    .map_err(|_| {
                        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法刷新安全校验")
                    })?;
                (Some(token), true)
            }
        }
    } else {
        (None, false)
    };
    let (session_user_id, session_role, session_workspace) = session
        .as_ref()
        .and_then(|session| user_identity(&state, &session.user_id, &session.tenant_id))
        .map_or((None, None, None), |(role, workspace)| {
            (
                session.as_ref().map(|value| value.user_id.clone()),
                Some(role),
                Some(workspace),
            )
        });
    let mut response = Json(AuthStatusResponse {
        initialized,
        authenticated: session.is_some(),
        user_id: session_user_id,
        username: session
            .as_ref()
            .and_then(|session| username(&state, &session.user_id)),
        role: session_role,
        workspace_id: session_workspace,
        channel: session.map(|session| session.channel.as_str().to_owned()),
        csrf_token: csrf_token.clone(),
        local_http_warning: matches!(channel, SessionChannel::LocalHttp),
    })
    .into_response();
    if set_csrf_cookie {
        if let Some(token) = csrf_token.as_deref() {
            set_cookie(
                &mut response,
                channel.csrf_cookie(),
                token,
                channel.secure(),
                false,
            );
        }
    }
    Ok(response)
}

/// 返回当前入口对应的 Session 摘要。这里只返回数据库生成的记录 ID 和
/// 生命周期信息，不回显 Cookie 中的原始 Session Token。
pub async fn current_session_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let session = current_session(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            "SELECT id, channel, created_at, last_seen_at, expires_at
             FROM auth_sessions
             WHERE session_digest = ?1 AND channel = ?2 AND revoked_at IS NULL",
            params![session.session_digest, session.channel.as_str()],
            |row| {
                Ok(SessionResponse {
                    id: row.get(0)?,
                    channel: row.get(1)?,
                    created_at: row.get(2)?,
                    last_seen_at: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取当前登录状态"))?
        .map(Json)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "登录状态已失效，请重新登录"))
}

pub async fn initialize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<InitializeRequest>,
) -> Result<Response, ApiError> {
    if !matches!(request_channel(&headers), SessionChannel::LocalHttp) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "首个管理员只能通过 LAN 管理入口初始化",
        ));
    }
    validate_username(&request.username)?;
    validate_password(&request.password)?;
    let expected = read_bootstrap_code(&state.data_dir)
        .map_err(|error| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    if !constant_time_equal(
        expected.as_bytes(),
        request.bootstrap_code.trim().as_bytes(),
    ) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Bootstrap Code 无效",
        ));
    }
    let password_hash = hash_password(&request.password)
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let user_id = uuid::Uuid::new_v4().to_string();
    let now = unix_now();
    let (session, csrf_token) = {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        if user_count(&connection)? > 0 {
            return Err(ApiError::new(StatusCode::CONFLICT, "Nexo 已经完成初始化"));
        }
        let transaction = connection
            .transaction()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始初始化事务"))?;
        transaction
            .execute(
                "INSERT INTO users (id, tenant_id, username, role, password_hash)
                 VALUES (?1, 'default', ?2, 'system_admin', ?3)",
                params![user_id, request.username.trim(), password_hash],
            )
            .map_err(|_| ApiError::new(StatusCode::CONFLICT, "管理员用户名已存在"))?;
        transaction
            .execute(
                "INSERT INTO audit_events (tenant_id, actor_user_id, event_type, resource_type, detail_json)
                 VALUES ('default', ?1, 'admin_initialized', 'user', ?2)",
                params![user_id, "{}"],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法写入初始化审计记录"))?;
        transaction
            .commit()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交初始化事务"))?;
        let created = create_session(
            &connection,
            &user_id,
            "default",
            SessionChannel::LocalHttp,
            now,
        )
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
        (created.0, created.1)
    };
    let bootstrap_path = state.data_dir.join(BOOTSTRAP_FILE);
    if let Err(error) = fs::remove_file(&bootstrap_path) {
        if error.kind() != std::io::ErrorKind::NotFound {
            // 数据库事务已经提交，不能假装 Secret 已经销毁。返回明确错误并
            // 记录路径，管理员可据此修复数据目录权限后再清理残留凭据。
            tracing::error!(
                path = %bootstrap_path.display(),
                "首个管理员已创建，但 Bootstrap Secret 未能销毁"
            );
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "管理员已创建，但 Bootstrap Secret 未能销毁，请检查数据目录权限",
            ));
        }
    }
    Ok(auth_response(
        session,
        csrf_token,
        request.username.trim(),
        "system_admin",
        "管理员初始化完成",
    ))
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let channel = request_channel(&headers);
    let source = source_label(&headers);
    if too_many_attempts(&state, &request.username, &source)? {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "登录失败次数过多，请 15 分钟后重试",
        ));
    }
    let record = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT id, tenant_id, role, password_hash, enabled FROM users
                 WHERE username = ?1",
                [&request.username],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)? != 0,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取管理员账号"))?
    };
    let Some((user_id, tenant_id, role, password_hash, enabled)) = record else {
        record_login_attempt(&state, &request.username, &source, false)?;
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "用户名或密码错误"));
    };
    let valid = verify_password(&password_hash, &request.password);
    record_login_attempt(&state, &request.username, &source, valid)?;
    if !valid {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "用户名或密码错误"));
    }
    if !enabled {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "当前账号已停用，请联系系统管理员",
        ));
    }
    let (session, csrf_token) = {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        revoke_channel_sessions(&connection, &user_id, channel)
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法轮换旧登录状态"))?;
        create_session(&connection, &user_id, &tenant_id, channel, unix_now())
            .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
    };
    Ok(auth_response(
        session,
        csrf_token,
        &request.username,
        &role,
        "登录成功",
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let channel = request_channel(&headers);
    if let Some(raw) = cookie_value(&headers, channel.session_cookie()) {
        let connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        connection
            .execute(
                "UPDATE auth_sessions SET revoked_at = ?1 WHERE session_digest = ?2 AND revoked_at IS NULL",
                params![unix_now(), digest(&raw)],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法注销登录状态"))?;
    }
    let mut response = Json(RecoveryResponse {
        message: "已退出登录".to_owned(),
    })
    .into_response();
    clear_cookie(&mut response, channel.session_cookie(), channel.secure());
    clear_cookie(&mut response, channel.csrf_cookie(), channel.secure());
    Ok(response)
}

/// 停用账号时先原子关闭 Nexo 登录面，再尽力过期该账号的 OIDC 节点。
/// Headscale 暂时不可用时保留 `mesh_revocation_pending`，由后台协调器重试。
pub async fn disable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<RecoveryResponse>, ApiError> {
    authorize_admin(&state, &headers)?;
    let id = id.trim().to_owned();
    if id.is_empty() {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "用户 ID 不能为空"));
    }
    {
        let mut connection = state
            .db
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
        let transaction = connection.transaction().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始账号停用事务")
        })?;
        let changed = transaction
            .execute(
                "UPDATE users SET enabled = 0, mesh_revocation_pending = 1 WHERE id = ?1",
                [&id],
            )
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法停用账号"))?;
        if changed == 0 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "用户不存在"));
        }
        transaction
            .execute(
                "UPDATE auth_sessions SET revoked_at = ?1
                 WHERE user_id = ?2 AND revoked_at IS NULL",
                params![unix_now(), id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法吊销账号登录状态")
            })?;
        transaction
            .execute(
                "UPDATE mesh_oidc_accounts
                 SET sync_status = 'pending', last_error = '账号已停用', updated_at = unixepoch()
                 WHERE nexo_user_id = ?1",
                [&id],
            )
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法记录组网撤销状态")
            })?;
        transaction.commit().map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交账号停用事务")
        })?;
    }
    match revoke_user_mesh(&state, &id).await {
        Ok(()) => Ok(Json(RecoveryResponse {
            message: "账号已停用，登录状态和组网节点已撤销".to_owned(),
        })),
        Err(error) => {
            tracing::warn!(user_id = %id, "账号已停用，但组网节点将在 Headscale 恢复后自动撤销：{error:#}");
            Ok(Json(RecoveryResponse {
                message: "账号已停用，组网节点撤销将在服务恢复后自动完成".to_owned(),
            }))
        }
    }
}

/// 启用账号只恢复 Nexo 登录资格，不复活被停用时过期的旧 OIDC 节点。
pub async fn enable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<RecoveryResponse>, ApiError> {
    authorize_admin(&state, &headers)?;
    let id = id.trim().to_owned();
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let changed = connection
        .execute("UPDATE users SET enabled = 1 WHERE id = ?1", [&id])
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法启用账号"))?;
    if changed == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "用户不存在"));
    }
    Ok(Json(RecoveryResponse {
        message: "账号已启用，请重新进行组网登录".to_owned(),
    }))
}

async fn revoke_user_mesh(state: &AppState, user_id: &str) -> anyhow::Result<()> {
    let mapping: Option<(String, Option<String>)> = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT provider_id, headscale_user_id FROM mesh_oidc_accounts
                 WHERE nexo_user_id = ?1",
                [user_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
    };
    let Some((provider_id, headscale_user_id)) = mapping else {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        connection.execute(
            "UPDATE users SET mesh_revocation_pending = 0 WHERE id = ?1",
            [user_id],
        )?;
        return Ok(());
    };
    let nodes = state.headscale.list_nodes().await?;
    for node in nodes {
        let matches_user = node.user.as_ref().is_some_and(|user| {
            user.provider_id.as_deref() == Some(provider_id.as_str())
                || headscale_user_id.as_deref() == Some(user.id.as_str())
        });
        if matches_user {
            state
                .headscale
                .expire_node(
                    &node.id,
                    &super::format_headscale_expiration(super::unix_now().max(0) as u64),
                )
                .await?;
        }
    }
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    connection.execute(
        "UPDATE users SET mesh_revocation_pending = 0 WHERE id = ?1",
        [user_id],
    )?;
    connection.execute(
        "UPDATE mesh_oidc_accounts SET sync_status = 'revoked', last_error = NULL, updated_at = unixepoch()
         WHERE nexo_user_id = ?1",
        [user_id],
    )?;
    Ok(())
}

/// 后台协调器重试停用账号的 Headscale 节点撤销；每个账号独立失败，避免
/// 一个暂时不可用的节点阻塞其他账号的撤销任务。
pub async fn reconcile_pending_mesh_revocations(state: &AppState) -> anyhow::Result<()> {
    let user_ids = {
        let connection = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut statement = connection
            .prepare("SELECT id FROM users WHERE mesh_revocation_pending = 1 ORDER BY id")?;
        let user_ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        user_ids
    };
    let mut first_error = None;
    for user_id in user_ids {
        if let Err(error) = revoke_user_mesh(state, &user_id).await {
            tracing::warn!(user_id = %user_id, "停用账号的组网节点撤销失败，将继续重试：{error:#}");
            first_error.get_or_insert(error);
        }
    }
    if let Some(error) = first_error {
        Err(error)
    } else {
        Ok(())
    }
}

pub async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<Json<RecoveryResponse>, ApiError> {
    require_csrf(&state, &headers)?;
    validate_password(&request.new_password)?;
    let channel = request_channel(&headers);
    let session = load_session(&state, &headers, channel)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "登录状态已失效，请重新登录"))?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let current_hash: String = connection
        .query_row(
            "SELECT password_hash FROM users WHERE id = ?1",
            [&session.user_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "管理员账号不存在"))?;
    if !verify_password(&current_hash, &request.current_password) {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "当前密码错误"));
    }
    let new_hash = hash_password(&request.new_password)
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    connection
        .execute(
            "UPDATE users SET password_hash = ?1 WHERE id = ?2",
            params![new_hash, session.user_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法保存新密码"))?;
    connection
        .execute(
            "UPDATE auth_sessions SET revoked_at = ?1 WHERE user_id = ?2 AND revoked_at IS NULL",
            params![unix_now(), session.user_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法吊销旧登录状态"))?;
    Ok(Json(RecoveryResponse {
        message: "密码已更新，请重新登录".to_owned(),
    }))
}

pub async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let session = current_session(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT id, channel, created_at, last_seen_at, expires_at
             FROM auth_sessions WHERE user_id = ?1 AND revoked_at IS NULL
             ORDER BY last_seen_at DESC",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取登录状态"))?;
    let rows = statement
        .query_map([session.user_id], |row| {
            Ok(SessionResponse {
                id: row.get(0)?,
                channel: row.get(1)?,
                created_at: row.get(2)?,
                last_seen_at: row.get(3)?,
                expires_at: row.get(4)?,
            })
        })
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取登录状态"))?;
    rows.map(|row| {
        row.map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "登录状态数据无效"))
    })
    .collect::<Result<Vec<_>, _>>()
    .map(Json)
}

pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<RecoveryResponse>, ApiError> {
    require_csrf(&state, &headers)?;
    let current = current_session(&state, &headers)?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .execute(
            "UPDATE auth_sessions SET revoked_at = ?1 WHERE id = ?2 AND user_id = ?3",
            params![unix_now(), id, current.user_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法吊销登录状态"))?;
    Ok(Json(RecoveryResponse {
        message: "登录状态已吊销".to_owned(),
    }))
}

pub async fn recover(
    State(state): State<AppState>,
    Json(request): Json<RecoverRequest>,
) -> Result<Json<RecoveryResponse>, ApiError> {
    validate_password(&request.new_password)?;
    let now = unix_now();
    let new_hash = hash_password(&request.new_password)
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let transaction = connection
        .unchecked_transaction()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法开始恢复事务"))?;
    // 恢复码必须在同一事务内以条件 UPDATE 抢占。先 SELECT 再 UPDATE
    // 会让两个并发恢复请求同时通过检查，破坏“一次性”安全边界。
    let recovery_digest = digest(request.recovery_code.trim());
    let recovery_id: Option<String> = transaction
        .query_row(
            "SELECT id FROM auth_recovery_sessions
             WHERE code_digest = ?1 AND used_at IS NULL AND expires_at > ?2",
            params![recovery_digest, now],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取恢复状态"))?;
    let Some(recovery_id) = recovery_id else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "恢复码无效或已过期",
        ));
    };
    let claimed = transaction
        .execute(
            "UPDATE auth_recovery_sessions
             SET used_at = ?1
             WHERE id = ?2 AND used_at IS NULL AND expires_at > ?1",
            params![now, recovery_id],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法标记恢复码"))?;
    if claimed != 1 {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "恢复码无效或已使用",
        ));
    }
    let changed = transaction
        .execute(
            "UPDATE users SET password_hash = ?1 WHERE role = 'system_admin'",
            [&new_hash],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法更新管理员密码"))?;
    if changed == 0 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "当前没有可恢复的管理员账号",
        ));
    }
    transaction
        .execute(
            "UPDATE auth_sessions SET revoked_at = ?1 WHERE revoked_at IS NULL",
            [now],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法吊销现有登录状态"))?;
    transaction
        .execute(
            "INSERT INTO audit_events (tenant_id, event_type, resource_type, detail_json)
             VALUES ('default', 'admin_recovered', 'user', '{}')",
            [],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法写入恢复审计记录"))?;
    transaction
        .commit()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法提交恢复事务"))?;
    Ok(Json(RecoveryResponse {
        message: "管理员密码已恢复，请重新登录".to_owned(),
    }))
}

/// 本地 CLI 创建一次性恢复码；不接收命令行密码，避免 shell history 和进程表泄露。
pub fn issue_recovery_code(connection: &rusqlite::Connection) -> anyhow::Result<String> {
    let users: i64 = connection.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
    if users == 0 {
        anyhow::bail!("Nexo 尚未初始化，请先完成管理员初始化");
    }
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let code = hex::encode(bytes);
    connection.execute(
        "DELETE FROM auth_recovery_sessions WHERE used_at IS NOT NULL OR expires_at <= ?1",
        [unix_now()],
    )?;
    connection.execute(
        "INSERT INTO auth_recovery_sessions (id, code_digest, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            uuid::Uuid::new_v4().to_string(),
            digest(&code),
            unix_now(),
            unix_now() + RECOVERY_SECONDS
        ],
    )?;
    Ok(code)
}

fn current_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthenticatedSession, ApiError> {
    load_session(state, headers, request_channel(headers))
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "登录状态已失效，请重新登录"))
}

/// 业务层需要把官方客户端归属到当前账号时使用；不会返回 Cookie 或摘要。
pub fn current_user_id(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    Ok(current_session(state, headers)?.user_id)
}

fn load_session(
    state: &AppState,
    headers: &HeaderMap,
    channel: SessionChannel,
) -> Option<AuthenticatedSession> {
    let raw = cookie_value(headers, channel.session_cookie())?;
    let session_digest = digest(&raw);
    let now = unix_now();
    let connection = state.db.lock().ok()?;
    let record = connection
        .query_row(
            "SELECT s.id, s.user_id, s.tenant_id, s.csrf_digest, s.created_at,
                    s.last_seen_at, s.expires_at, s.revoked_at
             FROM auth_sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.session_digest = ?1 AND s.channel = ?2 AND u.enabled = 1",
            params![session_digest, channel.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            },
        )
        .optional()
        .ok()??;
    let (id, user_id, tenant_id, csrf_digest, created_at, last_seen_at, expires_at, revoked_at) =
        record;
    if revoked_at.is_some()
        || expires_at <= now
        || last_seen_at.saturating_add(SESSION_IDLE_SECONDS) <= now
        || created_at.saturating_add(SESSION_ABSOLUTE_SECONDS) <= now
    {
        let _ = connection.execute(
            "UPDATE auth_sessions SET revoked_at = ?1 WHERE session_digest = ?2",
            params![now, session_digest],
        );
        return None;
    }
    let _ = connection.execute(
        "UPDATE auth_sessions SET last_seen_at = ?1 WHERE session_digest = ?2",
        params![now, session_digest],
    );
    Some(AuthenticatedSession {
        user_id,
        tenant_id,
        session_id: id,
        session_digest,
        csrf_digest,
        channel,
    })
}

fn create_session(
    connection: &rusqlite::Connection,
    user_id: &str,
    tenant_id: &str,
    channel: SessionChannel,
    now: i64,
) -> anyhow::Result<(AuthenticatedSession, String)> {
    let session_id = random_token();
    let session_digest = digest(&session_id);
    let csrf_token = random_token();
    let csrf_digest = digest(&csrf_token);
    let expires_at = now + SESSION_ABSOLUTE_SECONDS;
    connection.execute(
        "INSERT INTO auth_sessions
         (id, user_id, tenant_id, session_digest, csrf_digest, channel, created_at, last_seen_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8)",
        params![uuid::Uuid::new_v4().to_string(), user_id, tenant_id, session_digest, csrf_digest, channel.as_str(), now, expires_at],
    )?;
    Ok((
        AuthenticatedSession {
            user_id: user_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            session_id: session_id.clone(),
            session_digest,
            csrf_digest,
            channel,
        },
        csrf_token,
    ))
}

fn auth_response(
    session: AuthenticatedSession,
    csrf_token: String,
    username: &str,
    role: &str,
    message: &str,
) -> Response {
    let mut response = Json(AuthResponse {
        user_id: session.user_id.clone(),
        username: username.to_owned(),
        role: role.to_owned(),
        workspace_id: session.tenant_id.clone(),
        channel: session.channel.as_str().to_owned(),
        csrf_token: csrf_token.clone(),
        message: message.to_owned(),
    })
    .into_response();
    // Session 和 CSRF Cookie 与 JSON 响应一起提交，客户端无需保存 Session ID。
    set_cookie(
        &mut response,
        session.channel.session_cookie(),
        &session.session_id,
        session.channel.secure(),
        true,
    );
    set_cookie(
        &mut response,
        session.channel.csrf_cookie(),
        &csrf_token,
        session.channel.secure(),
        false,
    );
    response
}

fn username(state: &AppState, user_id: &str) -> Option<String> {
    let connection = state.db.lock().ok()?;
    connection
        .query_row(
            "SELECT username FROM users WHERE id = ?1",
            [user_id],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()
}

fn user_count(connection: &rusqlite::Connection) -> Result<i64, ApiError> {
    connection
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "无法读取管理员初始化状态",
            )
        })
}

fn validate_username(username: &str) -> Result<(), ApiError> {
    let length = username.chars().count();
    if length < 2 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "用户名至少需要 2 个字符",
        ));
    }
    if username.chars().any(char::is_whitespace) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "用户名不能包含空白字符",
        ));
    }
    let mut at_count = 0;
    for (index, character) in username.chars().enumerate() {
        if index == 0 && !character.is_alphabetic() {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "用户名必须以字母开头",
            ));
        }
        if character == '@' {
            at_count += 1;
            if at_count > 1 {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "用户名最多只能包含一个 @",
                ));
            }
            continue;
        }
        if !(character.is_alphanumeric() || matches!(character, '-' | '.' | '_')) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "用户名只能包含字母、数字、连字符、点号、下划线和一个 @",
            ));
        }
    }
    if username.ends_with('@') {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "用户名不能以 @ 结尾",
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<(), ApiError> {
    let length = password.chars().count();
    if !(12..=1024).contains(&length) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "密码长度必须为 12-1024 个字符",
        ));
    }
    Ok(())
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|error| anyhow::anyhow!("无法生成密码摘要：{error}"))?
        .to_string())
}

fn verify_password(encoded: &str, password: &str) -> bool {
    PasswordHash::new(encoded).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

fn too_many_attempts(state: &AppState, username: &str, source: &str) -> Result<bool, ApiError> {
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let since = unix_now() - LOGIN_WINDOW_SECONDS;
    connection
        .query_row(
            "SELECT COUNT(*) FROM auth_login_attempts
             WHERE username = ?1 AND source = ?2 AND succeeded = 0 AND attempted_at > ?3",
            params![username, source, since],
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count >= LOGIN_FAILURE_LIMIT)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法检查登录限制"))
}

fn record_login_attempt(
    state: &AppState,
    username: &str,
    source: &str,
    succeeded: bool,
) -> Result<(), ApiError> {
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .execute(
            "INSERT INTO auth_login_attempts (username, source, attempted_at, succeeded)
             VALUES (?1, ?2, ?3, ?4)",
            params![username, source, unix_now(), i64::from(succeeded)],
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法记录登录结果"))?;
    Ok(())
}

fn revoke_channel_sessions(
    connection: &rusqlite::Connection,
    user_id: &str,
    channel: SessionChannel,
) -> rusqlite::Result<usize> {
    connection.execute(
        "UPDATE auth_sessions SET revoked_at = ?1
         WHERE user_id = ?2 AND channel = ?3 AND revoked_at IS NULL",
        params![unix_now(), user_id, channel.as_str()],
    )
}

fn source_label(headers: &HeaderMap) -> String {
    // 只有本机 Caddy 注入的公网入口标记才允许使用 X-Forwarded-For。
    // LAN 请求中的该 Header 可由客户端任意伪造，统一归入 local，避免
    // 攻击者通过轮换伪造地址绕过登录失败限流。
    if request_channel(headers) != SessionChannel::PublicHttps {
        return "local".to_owned();
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| value.parse::<IpAddr>().is_ok())
        .unwrap_or("local")
        .to_owned()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|part| {
                let (key, value) = part.trim().split_once('=')?;
                (key == name).then(|| value.to_owned())
            })
        })
}

fn set_cookie(response: &mut Response, name: &str, value: &str, secure: bool, http_only: bool) {
    let mut cookie = format!("{name}={value}; Path=/; SameSite=Lax");
    if secure {
        cookie.push_str("; Secure");
    }
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn clear_cookie(response: &mut Response, name: &str, secure: bool) {
    let mut cookie = format!("{name}=; Path=/; Max-Age=0; SameSite=Lax");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie.push_str("; HttpOnly");
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn set_private_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{caddy, headscale, AppState, HeadscaleAdapter};
    use axum::http::header::SET_COOKIE;
    use rusqlite::Connection;
    use std::sync::Arc;

    fn test_state() -> AppState {
        let connection = Connection::open_in_memory().expect("应打开认证测试数据库");
        connection
            .execute_batch(
                "CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL);
                 CREATE TABLE users (
                    id TEXT PRIMARY KEY, tenant_id TEXT, username TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL, password_hash TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    mesh_revocation_pending INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE oidc_settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1), issuer TEXT,
                    private_key_pem TEXT NOT NULL, public_key_pem TEXT NOT NULL,
                    key_id TEXT NOT NULL
                 );
                 CREATE TABLE auth_sessions (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
                    session_digest TEXT NOT NULL UNIQUE, csrf_digest TEXT NOT NULL,
                    channel TEXT NOT NULL, created_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER
                 );
                 CREATE TABLE auth_login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
                    source TEXT NOT NULL, attempted_at INTEGER NOT NULL, succeeded INTEGER NOT NULL
                 );
                 CREATE TABLE auth_recovery_sessions (
                    id TEXT PRIMARY KEY, code_digest TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER
                 );
                 CREATE TABLE audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT,
                    actor_user_id TEXT, event_type TEXT NOT NULL,
                    resource_type TEXT NOT NULL, detail_json TEXT NOT NULL
                 );
                 INSERT INTO tenants (id, name) VALUES ('default', '默认租户');
                 INSERT INTO users (id, tenant_id, username, role, password_hash)
                 VALUES ('user-1', 'default', 'admin', 'system_admin', 'not-used');",
            )
            .expect("应创建认证测试表");
        let data_dir = std::env::temp_dir().join(format!("nexo-auth-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("应创建认证 Secret 测试目录");
        let oidc = Arc::new(
            crate::oidc::OidcRuntime::initialize(&connection).expect("应初始化认证测试 OIDC 状态"),
        );
        AppState {
            db: Arc::new(std::sync::Mutex::new(connection)),
            data_dir: data_dir.clone(),
            headscale: Arc::new(HeadscaleAdapter),
            mesh_offers: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            mesh_enrollment_lock: Arc::new(tokio::sync::Mutex::new(())),
            tunnel_sessions: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            public_listener_tasks: Arc::new(
                std::sync::Mutex::new(std::collections::HashMap::new()),
            ),
            active_tunnel_connections: Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            caddy: Arc::new(caddy::CaddySupervisor::new(
                caddy::CaddyRuntimeConfig::from_env(data_dir.clone()),
            )),
            headscale_runtime: Arc::new(headscale::HeadscaleSupervisor::new(
                headscale::HeadscaleRuntimeConfig::from_env(data_dir),
            )),
            oidc,
        }
    }

    fn session_headers(channel: SessionChannel, session_id: &str, csrf: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let cookie = match channel {
            SessionChannel::LocalHttp => format!("{LOCAL_SESSION_COOKIE}={session_id}"),
            SessionChannel::PublicHttps => format!("{HTTPS_SESSION_COOKIE}={session_id}"),
        };
        headers.insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
        if let Some(csrf) = csrf {
            headers.insert("x-nexo-csrf", HeaderValue::from_str(csrf).unwrap());
        }
        headers
    }

    #[test]
    fn session_channels_are_isolated_and_cookie_flags_are_explicit() {
        let state = test_state();
        let (local, local_csrf) = {
            let connection = state.db.lock().unwrap();
            create_session(
                &connection,
                "user-1",
                "default",
                SessionChannel::LocalHttp,
                unix_now(),
            )
            .unwrap()
        };
        let (public, public_csrf) = {
            let connection = state.db.lock().unwrap();
            create_session(
                &connection,
                "user-1",
                "default",
                SessionChannel::PublicHttps,
                unix_now(),
            )
            .unwrap()
        };
        assert!(load_session(
            &state,
            &session_headers(SessionChannel::LocalHttp, &local.session_id, None),
            SessionChannel::LocalHttp
        )
        .is_some());
        assert!(load_session(
            &state,
            &session_headers(SessionChannel::LocalHttp, &local.session_id, None),
            SessionChannel::PublicHttps
        )
        .is_none());

        let local_response = auth_response(local, local_csrf, "admin", "system_admin", "ok");
        let local_cookies = local_response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert!(local_cookies
            .iter()
            .any(|value| value.starts_with(LOCAL_SESSION_COOKIE)
                && value.contains("HttpOnly")
                && !value.contains("Secure")));
        assert!(local_cookies
            .iter()
            .any(|value| value.starts_with(LOCAL_CSRF_COOKIE) && !value.contains("HttpOnly")));

        let public_response = auth_response(public, public_csrf, "admin", "system_admin", "ok");
        let public_cookies = public_response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert!(public_cookies
            .iter()
            .any(|value| value.starts_with(HTTPS_SESSION_COOKIE)
                && value.contains("Secure")
                && value.contains("HttpOnly")));
    }

    #[test]
    fn expired_session_is_revoked_and_csrf_requires_matching_token() {
        let state = test_state();
        let (expired, _) = {
            let connection = state.db.lock().unwrap();
            create_session(
                &connection,
                "user-1",
                "default",
                SessionChannel::LocalHttp,
                unix_now() - SESSION_IDLE_SECONDS - 1,
            )
            .unwrap()
        };
        assert!(load_session(
            &state,
            &session_headers(SessionChannel::LocalHttp, &expired.session_id, None),
            SessionChannel::LocalHttp
        )
        .is_none());
        let revoked: Option<i64> = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT revoked_at FROM auth_sessions WHERE session_digest = ?1",
                [digest(&expired.session_id)],
                |row| row.get(0),
            )
            .unwrap();
        assert!(revoked.is_some());

        let (session, csrf) = {
            let connection = state.db.lock().unwrap();
            create_session(
                &connection,
                "user-1",
                "default",
                SessionChannel::LocalHttp,
                unix_now(),
            )
            .unwrap()
        };
        let headers = session_headers(SessionChannel::LocalHttp, &session.session_id, Some(&csrf));
        assert!(require_csrf(&state, &headers).is_ok());
        let mut wrong = headers.clone();
        wrong.insert("x-nexo-csrf", HeaderValue::from_static("wrong"));
        assert_eq!(
            require_csrf(&state, &wrong).unwrap_err().status,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn recovery_code_is_single_use_and_revokes_sessions() {
        let state = test_state();
        let password_hash = hash_password("初始管理员密码123").unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE users SET password_hash = ?1", [&password_hash])
            .unwrap();
        let (_session, _csrf) = {
            let connection = state.db.lock().unwrap();
            create_session(
                &connection,
                "user-1",
                "default",
                SessionChannel::LocalHttp,
                unix_now(),
            )
            .unwrap()
        };
        let code = issue_recovery_code(&state.db.lock().unwrap()).unwrap();
        let _ = recover(
            State(state.clone()),
            Json(RecoverRequest {
                recovery_code: code.clone(),
                new_password: "恢复后的管理员密码123".to_owned(),
            }),
        )
        .await
        .expect("有效恢复码应能更新密码");
        let second = recover(
            State(state.clone()),
            Json(RecoverRequest {
                recovery_code: code,
                new_password: "再次尝试的新密码1234".to_owned(),
            }),
        )
        .await
        .expect_err("恢复码只能使用一次");
        assert_eq!(second.status, StatusCode::UNAUTHORIZED);
        let active_sessions: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM auth_sessions WHERE revoked_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(active_sessions, 0);
    }

    #[test]
    fn login_source_ignores_spoofed_forwarded_for_on_lan() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.10"));
        assert_eq!(source_label(&headers), "local");
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        headers.insert(PUBLIC_ENTRY_HEADER, HeaderValue::from_static("1"));
        assert_eq!(source_label(&headers), "198.51.100.10");
    }

    #[test]
    fn password_length_uses_characters_and_not_utf8_bytes() {
        assert!(validate_password("联巢联巢联巢联巢联巢联巢").is_ok());
        assert_eq!(
            validate_password("联巢联巢联巢").unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn username_validation_matches_headscale_acceptance_rules() {
        for username in [
            "linyue",
            "ab-1._2",
            "linyue@example",
            "用户1",
            &"a".repeat(64),
            &"a".repeat(65),
        ] {
            assert!(
                validate_username(username).is_ok(),
                "应接受用户名 {username}"
            );
        }
        for username in [
            "",
            "a",
            "1linyue",
            "-linyue",
            "linyue@@example",
            "linyue@",
            "lin yue",
            "linyue/mesh",
        ] {
            assert!(
                validate_username(username).is_err(),
                "应拒绝用户名 {username}"
            );
        }
    }

    #[test]
    fn bootstrap_code_is_created_when_cli_runs_before_server() {
        let connection = Connection::open_in_memory().expect("应打开 Bootstrap 测试数据库");
        connection
            .execute_batch(
                "CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT,
                    username TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    password_hash TEXT NOT NULL
                );",
            )
            .expect("应创建 Bootstrap 测试表");
        let data_dir =
            std::env::temp_dir().join(format!("nexo-bootstrap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("应创建 Bootstrap Secret 测试目录");

        ensure_bootstrap_code(&connection, &data_dir).expect("首次 CLI 应生成 Bootstrap Secret");
        let code = read_bootstrap_code(&data_dir).expect("生成后应能读取 Bootstrap Code");
        assert!(!code.is_empty());

        std::fs::remove_dir_all(data_dir).expect("应清理 Bootstrap Secret 测试目录");
    }
}
