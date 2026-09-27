//! Nexo 本地账号与会话认证。
//!
//! v0.2.0 只保留本地登录。会话摘要、CSRF 摘要和密码哈希进入 SQLite，
//! 浏览器只持有随机 Cookie；Agent 控制通道不复用 Web 会话。

use std::path::Path;

use argon2::{
    password_hash::{
        rand_core::{OsRng, RngCore},
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{security::RequestSecurity, unix_now, ApiError, AppState};

#[cfg(test)]
pub(crate) static PASSWORD_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const SESSION_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize)]
pub struct AuthStatusResponse {
    pub initialized: bool,
    pub authenticated: bool,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub role: Option<String>,
    pub workspace_id: Option<String>,
    pub channel: Option<String>,
    pub csrf_token: Option<String>,
    pub local_http_warning: bool,
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
pub struct SessionResponse {
    pub browser: Option<String>,
    pub os: Option<String>,
    pub id: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub expires_at: i64,
}
#[derive(Debug, Serialize)]
pub struct RecoveryResponse {
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub tenant_id: String,
    pub csrf: String,
}

/// 仅空账号库创建管理员。立即事务串行化首次启动，已有账号时不校验或覆盖配置。
/// 返回值仅包含自动生成的凭据，由启动入口在提交成功后输出；显式密码不会回传。
pub fn ensure_admin(
    connection: &mut rusqlite::Connection,
    username: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<Option<(String, String)>> {
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let exists: bool =
        transaction.query_row("SELECT EXISTS(SELECT 1 FROM users)", [], |row| row.get(0))?;
    if exists {
        // 数据库只有密码哈希，重启不能再次显示明文；在容器日志中说明跳过原因及恢复入口。
        tracing::info!("已有账号，跳过管理员初始化；初始账号密码配置不会覆盖已有账号，密码不会再次打印。遗失密码可使用 nexo admin recover 恢复账号。");
        return Ok(None);
    }
    let username = username
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("admin");
    validate_username(username).map_err(|error| {
        anyhow::anyhow!(
            "admin.username / NEXO_ADMIN_USERNAME 配置无效：{}",
            error.message
        )
    })?;
    let generated = password.is_none_or(str::is_empty);
    let password = if generated {
        let mut bytes = [0_u8; 24];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| anyhow::anyhow!("无法生成管理员密码：系统安全随机源不可用"))?;
        hex::encode(bytes)
    } else {
        password.unwrap().to_owned()
    };
    validate_password(&password).map_err(|error| {
        anyhow::anyhow!(
            "admin.password / NEXO_ADMIN_PASSWORD 配置无效：{}",
            error.message
        )
    })?;
    let hash = hash_password(&password)?;
    transaction.execute(
        "INSERT INTO users (id, tenant_id, username, role, password_hash, enabled, created_at) VALUES (?1,'default',?2,'system_admin',?3,1,?4)",
        params![Uuid::new_v4().to_string(), username, hash, unix_now()],
    )?;
    transaction.commit()?;
    if !generated {
        tracing::info!("管理员账号已创建，用户名：{username}；使用指定密码，不输出密码明文。请清除 server.toml 或 NEXO_ADMIN_PASSWORD 中的初始密码。");
    }
    Ok(generated.then(|| (username.to_owned(), password)))
}

pub async fn session_middleware(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if let Some(session) = load_session(&state, request.headers()) {
        request.extensions_mut().insert(session);
    }
    next.run(request).await
}

pub fn require_session(state: &AppState, headers: &HeaderMap) -> Result<Session, ApiError> {
    load_session(state, headers).ok_or_else(ApiError::session_expired)
}

pub fn require_csrf(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let session = require_session(state, headers)?;
    let provided = headers
        .get("x-nexo-csrf")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if digest(provided) != session.csrf {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "缺少安全校验，请刷新页面后重试",
        ));
    }
    Ok(())
}

pub async fn login(
    State(state): State<AppState>,
    Extension(security): Extension<RequestSecurity>,
    headers: HeaderMap,
    Json(input): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    if input.username.len() > 256 || input.password.len() > 1024 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "用户名或密码过长"));
    }
    if !state.security.allow(
        format!("account:{}", input.username.trim().to_lowercase()),
        10,
        unix_now(),
    ) {
        return Err(crate::security::limited());
    }
    if input.password.len() > 1024 {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "用户名或密码错误"));
    }
    let row = {
        let connection = state.db.lock().map_err(|_| internal("数据库锁不可用"))?;
        connection
            .query_row(
                "SELECT id,tenant_id,password_hash,enabled FROM users WHERE username=?1",
                [input.username.trim()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(internal)?
    };
    let Some((user_id, tenant_id, hash, enabled)) = row else {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "用户名或密码错误"));
    };
    let checked_hash = hash.clone();
    if enabled == 0
        || !password_work(move || verify_password(&input.password, &checked_hash)).await?
    {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "用户名或密码错误"));
    }
    let connection = state.db.lock().map_err(|_| internal("数据库锁不可用"))?;
    // 密码检查期间可能发生恢复、改密或改名；再次确认登录名及凭据，避免旧身份创建新会话。
    let current: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1 AND password_hash=?2 AND enabled=1 AND username=?3)",
            params![user_id, hash, input.username.trim()],
            |r| r.get(0),
        )
        .map_err(internal)?;
    if !current {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "账号凭据已更新，请重新登录",
        ));
    }
    let (session, csrf) = create_session(&connection, &user_id, &tenant_id, unix_now(), &headers)
        .map_err(internal)?;
    Ok(auth_response(
        StatusCode::OK,
        &session,
        &csrf,
        "登录成功",
        security.secure,
    ))
}

pub async fn status(
    State(state): State<AppState>,
    Extension(security): Extension<RequestSecurity>,
    headers: HeaderMap,
) -> Result<Json<AuthStatusResponse>, ApiError> {
    // 会话读取也会获取数据库锁，必须在状态查询持锁前完成，避免登录后刷新死锁。
    let session = load_session(&state, &headers);
    let connection = state.db.lock().map_err(|_| internal("数据库锁不可用"))?;
    let initialized: i64 = connection
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(internal)?;
    let Some(session) = session else {
        return Ok(Json(AuthStatusResponse {
            initialized: initialized > 0,
            authenticated: false,
            user_id: None,
            username: None,
            role: None,
            workspace_id: None,
            channel: None,
            csrf_token: None,
            local_http_warning: !security.secure,
        }));
    };
    let identity = connection
        .query_row(
            "SELECT username, role FROM users WHERE id = ?1",
            params![session.user_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(internal)?;
    let Some((username, role)) = identity else {
        return Ok(Json(AuthStatusResponse {
            initialized: initialized > 0,
            authenticated: false,
            user_id: None,
            username: None,
            role: None,
            workspace_id: None,
            channel: None,
            csrf_token: None,
            local_http_warning: !security.secure,
        }));
    };
    let csrf = cookie(&headers, "nexo_csrf");
    Ok(Json(AuthStatusResponse {
        initialized: true,
        authenticated: true,
        user_id: Some(session.user_id),
        username: Some(username),
        role: Some(role),
        workspace_id: Some(session.tenant_id),
        channel: Some(
            if security.secure {
                "https"
            } else {
                "local_http"
            }
            .to_owned(),
        ),
        csrf_token: csrf,
        local_http_warning: !security.secure,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_csrf(&state, &headers)?;
    if let Some(raw) = cookie(&headers, "nexo_session") {
        let connection = state.db.lock().map_err(|_| internal("数据库锁不可用"))?;
        connection
            .execute(
                "DELETE FROM auth_sessions WHERE session_digest = ?1",
                params![digest(&raw)],
            )
            .map_err(internal)?;
    }
    Ok(clear_cookie_response())
}

pub async fn current_session_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let session = require_session(&state, &headers)?;
    let connection = state.db.lock().map_err(|_| internal("数据库锁不可用"))?;
    let row = connection.query_row("SELECT id, created_at, last_seen_at, expires_at, browser, os FROM auth_sessions WHERE session_digest = ?1", params![digest(cookie(&headers, "nexo_session").as_deref().unwrap_or_default())], |row| Ok(SessionResponse { id: row.get(0)?, created_at: row.get(1)?, last_seen_at: row.get(2)?, expires_at: row.get(3)?, browser: row.get(4)?, os: row.get(5)? })).map_err(internal)?;
    let _ = session;
    Ok(Json(row))
}

pub async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let session = require_session(&state, &headers)?;
    let connection = state.db.lock().map_err(|_| internal("数据库锁不可用"))?;
    let mut query = connection.prepare("SELECT id, created_at, last_seen_at, expires_at, browser, os FROM auth_sessions WHERE user_id = ?1 ORDER BY last_seen_at DESC").map_err(internal)?;
    let rows = query
        .query_map(params![session.user_id], |row| {
            Ok(SessionResponse {
                id: row.get(0)?,
                created_at: row.get(1)?,
                last_seen_at: row.get(2)?,
                expires_at: row.get(3)?,
                browser: row.get(4)?,
                os: row.get(5)?,
            })
        })
        .map_err(internal)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(internal)?;
    Ok(Json(rows))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<RecoveryResponse>, ApiError> {
    let session = require_session(&state, &headers)?;
    require_csrf(&state, &headers)?;
    let connection = state.db.lock().map_err(|_| internal("数据库锁不可用"))?;
    connection
        .execute(
            "DELETE FROM auth_sessions WHERE id = ?1 AND user_id = ?2",
            params![id, session.user_id],
        )
        .map_err(internal)?;
    Ok(Json(RecoveryResponse {
        message: "会话已吊销".to_owned(),
    }))
}

pub async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ChangePasswordRequest>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &headers)?;
    require_csrf(&state, &headers)?;
    validate_password(&input.new_password)?;
    if !state
        .security
        .allow(format!("password:{}", session.user_id), 10, unix_now())
    {
        return Err(crate::security::limited());
    }
    let old: String = state
        .db
        .lock()
        .map_err(|_| internal("数据库锁不可用"))?
        .query_row(
            "SELECT password_hash FROM users WHERE id=?1",
            [&session.user_id],
            |r| r.get(0),
        )
        .map_err(internal)?;
    let previous = old.clone();
    let hash = password_work(move || {
        if input.current_password.len() > 1024
            || !verify_password(&input.current_password, &previous)
        {
            return Ok(None);
        }
        hash_password(&input.new_password).map(Some)
    })
    .await?
    .map_err(internal)?
    .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "当前密码错误"))?;
    let connection = state.db.lock().map_err(|_| internal("数据库锁不可用"))?;
    let tx = connection.unchecked_transaction().map_err(internal)?;
    if tx
        .execute(
            "UPDATE users SET password_hash=?1 WHERE id=?2 AND password_hash=?3",
            params![hash, session.user_id, old],
        )
        .map_err(internal)?
        != 1
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "账号凭据已更新，请重新登录",
        ));
    }
    tx.execute(
        "DELETE FROM auth_sessions WHERE user_id=?1",
        [&session.user_id],
    )
    .map_err(internal)?;
    tx.execute("DELETE FROM auth_recovery WHERE id=?1", [&session.user_id])
        .map_err(internal)?;
    tx.commit().map_err(internal)?;
    Ok(clear_cookie_response())
}

/// 恢复码只由拥有 Server 数据目录权限的人在本机生成；数据库只保存摘要。
/// id 绑定具体管理员，重新生成撤销旧码，不允许一次恢复修改全部管理员密码。
pub fn create_recovery_code(
    data_dir: &Path,
    username: Option<&str>,
) -> anyhow::Result<(String, String, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        data_dir.join("nexo.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    let mut query = connection.prepare("SELECT id,username FROM users WHERE role='system_admin' AND enabled=1 AND (?1 IS NULL OR username=?1)")?;
    let users = query
        .query_map([username], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    anyhow::ensure!(
        users.len() == 1,
        "未找到唯一管理员；请用 --username 指定已启用的管理员账号"
    );
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let code = hex::encode(bytes);
    let expires = unix_now() + 900;
    let tx = connection.unchecked_transaction()?;
    tx.execute("DELETE FROM auth_recovery WHERE id=?1", [&users[0].0])?;
    tx.execute(
        "INSERT INTO auth_recovery(id,recovery_digest,expires_at,used) VALUES (?1,?2,?3,0)",
        params![users[0].0, digest(&code), expires],
    )?;
    tx.commit()?;
    Ok((code, users[0].1.clone(), expires))
}

pub async fn recover(
    State(state): State<AppState>,
    Json(input): Json<RecoverRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_password(&input.new_password)?;
    let code_digest = digest(input.recovery_code.trim());
    let (user, username) = {
        let connection = state.db.lock().map_err(|_| internal("数据库锁不可用"))?;
        recovery_user(&connection, &code_digest)?
    };
    let hash = password_work(move || hash_password(&input.new_password))
        .await?
        .map_err(internal)?;
    let connection = state.db.lock().map_err(|_| internal("数据库锁不可用"))?;
    let tx = connection.unchecked_transaction().map_err(internal)?;
    // 校验与消费在同一事务里再次执行；并发请求和生成新码都不能复用旧码。
    let (current, _) = recovery_user(&tx, &code_digest)?;
    if current != user {
        return Err(invalid_recovery());
    }
    tx.execute(
        "UPDATE users SET password_hash=?1 WHERE id=?2",
        params![hash, user],
    )
    .map_err(internal)?;
    tx.execute("UPDATE auth_recovery SET used=1 WHERE id=?1", [&user])
        .map_err(internal)?;
    tx.execute("DELETE FROM auth_sessions WHERE user_id=?1", [&user])
        .map_err(internal)?;
    tx.execute("INSERT INTO audit_events(tenant_id,event_type,resource_type,resource_id,created_at) SELECT tenant_id,'account_recovered','user',id,?1 FROM users WHERE id=?2", params![unix_now(),user]).map_err(internal)?;
    tx.commit().map_err(internal)?;
    Ok(Json(
        serde_json::json!({"message":"密码已更新，请重新登录","username":username}),
    ))
}
fn invalid_recovery() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "恢复码无效、已使用或已过期")
}
fn recovery_user(
    connection: &rusqlite::Connection,
    digest: &str,
) -> Result<(String, String), ApiError> {
    connection.query_row("SELECT u.id,u.username FROM auth_recovery r JOIN users u ON u.id=r.id WHERE r.recovery_digest=?1 AND r.expires_at>?2 AND r.used=0 AND u.enabled=1",
        params![digest,unix_now()], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(internal)?.ok_or_else(invalid_recovery)
}

/// Argon2 不占用数据库锁或异步工作线程，并限制并发内存开销。
pub(crate) async fn password_work<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, ApiError> {
    static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let permit = SLOTS
        .try_acquire()
        .map_err(|_| crate::security::limited())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(internal)
}

fn load_session(state: &AppState, headers: &HeaderMap) -> Option<Session> {
    let raw = cookie(headers, "nexo_session")?;
    let connection = state.db.lock().ok()?;
    connection.query_row("SELECT s.user_id, s.tenant_id, s.csrf_digest FROM auth_sessions s JOIN users u ON u.id=s.user_id AND u.enabled=1 WHERE s.session_digest = ?1 AND s.expires_at > ?2", params![digest(&raw), unix_now()], |row| Ok(Session { user_id: row.get(0)?, tenant_id: row.get(1)?, csrf: row.get(2)? })).optional().ok().flatten()
}

/// User-Agent 仅映射到固定展示标签，不保存原始内容，不用于认证、授权或设备身份判断。
fn session_labels(headers: &HeaderMap) -> (Option<&'static str>, Option<&'static str>) {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let browser = if ua.contains("Edg/") || ua.contains("EdgiOS/") || ua.contains("EdgA/") {
        Some("Edge")
    } else if ua.contains("Firefox/") || ua.contains("FxiOS/") {
        Some("Firefox")
    } else if ua.contains("Chrome/") || ua.contains("CriOS/") {
        Some("Chrome")
    } else if ua.contains("Safari/") {
        Some("Safari")
    } else {
        None
    };
    let os = if ua.contains("iPhone") || ua.contains("iPad") {
        Some("iOS / iPadOS")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Macintosh") {
        Some("macOS")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    };
    (browser, os)
}

pub(crate) fn create_session(
    connection: &rusqlite::Connection,
    user_id: &str,
    tenant_id: &str,
    now: i64,
    headers: &HeaderMap,
) -> anyhow::Result<(String, String)> {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let raw = hex::encode(bytes);
    let mut csrf_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut csrf_bytes);
    let csrf = hex::encode(csrf_bytes);
    let (browser, os) = session_labels(headers);
    connection.execute("INSERT INTO auth_sessions (id,user_id,tenant_id,session_digest,csrf_digest,created_at,last_seen_at,expires_at,browser,os) VALUES (?1,?2,?3,?4,?5,?6,?6,?7,?8,?9)", params![Uuid::new_v4().to_string(), user_id, tenant_id, digest(&raw), digest(&csrf), now, now + SESSION_SECONDS, browser, os])?;
    Ok((raw, csrf))
}

pub(crate) fn auth_response(
    status: StatusCode,
    raw: &str,
    csrf: &str,
    message: &str,
    secure: bool,
) -> Response {
    let secure_flag = if secure { "; Secure" } else { "" };
    let body = serde_json::json!({"authenticated":true,"message":message,"csrf_token":csrf,"channel":if secure { "https" } else { "local_http" }});
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "nexo_session={raw}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_SECONDS}{secure_flag}"
        ))
        .unwrap(),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "nexo_csrf={csrf}; SameSite=Lax; Path=/; Max-Age={SESSION_SECONDS}{secure_flag}"
        ))
        .unwrap(),
    );
    response
}
fn clear_cookie_response() -> Response {
    let mut response = Json(serde_json::json!({"message":"已退出登录"})).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static("nexo_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static("nexo_csrf=; SameSite=Lax; Path=/; Max-Age=0"),
    );
    response
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|item| item.strip_prefix(&format!("{name}=")).map(str::to_owned))
}
pub(crate) fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}
pub(crate) fn hash_password(value: &str) -> anyhow::Result<String> {
    Argon2::default()
        .hash_password(value.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}
pub(crate) fn verify_password(value: &str, hash: &str) -> bool {
    PasswordHash::new(hash).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(value.as_bytes(), &parsed)
            .is_ok()
    })
}
pub(crate) fn validate_username(value: &str) -> Result<(), ApiError> {
    if value.trim().len() < 2 || value.trim().len() > 64 {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "用户名长度必须为 2-64 个字符",
        ))
    } else {
        Ok(())
    }
}
pub(crate) fn validate_password(value: &str) -> Result<(), ApiError> {
    if value.chars().count() < 6 || value.len() > 1024 {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "密码至少需要 6 个字符，且不超过 1024 字节",
        ))
    } else {
        Ok(())
    }
}
fn internal(error: impl std::fmt::Display) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
#[cfg(test)]
mod tests {
    #[test]
    fn passwords_use_character_minimum_and_byte_maximum() {
        assert!(super::validate_password("12345").is_err());
        assert!(super::validate_password("123456").is_ok());
        assert!(super::validate_password("中文密码六个").is_ok());
        assert!(super::validate_password(&"a".repeat(1024)).is_ok());
        assert!(super::validate_password(&"a".repeat(1025)).is_err());
        assert!(super::validate_password(&"中".repeat(342)).is_err());
    }
    use super::*;
    use std::{
        fs,
        sync::{Arc, Mutex},
    };

    #[test]
    fn admin_initialization_defaults_and_explicit_credentials() {
        for (username, password, expected_username) in [
            (None, None, "admin"),
            (Some(""), Some(""), "admin"),
            (Some(" \t "), None, "admin"),
            (Some(" owner "), None, "owner"),
            (None, Some(" explicit-password-1234 "), "admin"),
            (Some(" owner "), Some("explicit-password-1234"), "owner"),
        ] {
            let mut db = rusqlite::Connection::open_in_memory().unwrap();
            crate::initialize_database(&db, true).unwrap();
            let generated = ensure_admin(&mut db, username, password).unwrap();
            let actual_password = if let Some(password) = password.filter(|value| !value.is_empty())
            {
                assert!(generated.is_none(), "显式密码不应回传用于打印");
                password.to_owned()
            } else {
                let (name, password) = generated.expect("自动密码应在提交后返回");
                assert_eq!(name, expected_username);
                assert_eq!(password.len(), 48);
                assert!(password.bytes().all(|byte| byte.is_ascii_hexdigit()));
                password
            };
            let (name, role, tenant, enabled, hash): (String, String, String, i64, String) = db
                .query_row(
                    "SELECT username,role,tenant_id,enabled,password_hash FROM users",
                    [],
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
                .unwrap();
            assert_eq!(name, expected_username);
            assert_eq!(role, "system_admin");
            assert_eq!(tenant, "default");
            assert_eq!(enabled, 1);
            assert!(hash.starts_with("$argon2"));
            assert!(verify_password(&actual_password, &hash));
            assert!(!verify_password("wrong-password", &hash));
        }
    }

    #[test]
    fn admin_initialization_rejects_invalid_config_without_creating_accounts() {
        for (username, password, variable) in [
            (
                "a".to_owned(),
                "valid-password-1234".to_owned(),
                "admin.username",
            ),
            (
                "a".repeat(65),
                "valid-password-1234".to_owned(),
                "admin.username",
            ),
            ("admin".to_owned(), "12345".to_owned(), "admin.password"),
            ("admin".to_owned(), "a".repeat(1025), "admin.password"),
        ] {
            let mut db = rusqlite::Connection::open_in_memory().unwrap();
            crate::initialize_database(&db, true).unwrap();
            let error = ensure_admin(&mut db, Some(&username), Some(&password))
                .unwrap_err()
                .to_string();
            assert!(error.contains(variable));
            assert!(!error.contains(&password));
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                0
            );
            assert!(
                ensure_admin(&mut db, None, None).unwrap().is_some(),
                "配置修正后可以重新初始化"
            );
        }
    }

    #[test]
    fn admin_initialization_preserves_existing_accounts_even_with_invalid_config() {
        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        crate::initialize_database(&db, true).unwrap();
        ensure_admin(&mut db, Some("owner"), Some("original-password-1234")).unwrap();
        let original: (String, String) = db
            .query_row("SELECT id,password_hash FROM users", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        for (username, password) in [
            (None, None),
            (Some("new-owner"), Some("replacement-password")),
            (Some("x"), Some("invalid")),
        ] {
            assert!(ensure_admin(&mut db, username, password).unwrap().is_none());
            let current: (String, String, String) = db
                .query_row("SELECT id,username,password_hash FROM users", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .unwrap();
            assert_eq!(
                current,
                (original.0.clone(), "owner".into(), original.1.clone())
            );
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
        db.execute("UPDATE users SET role='tenant'", []).unwrap();
        assert!(
            ensure_admin(&mut db, None, None).unwrap().is_none(),
            "只要存在账号就不能重新初始化"
        );
    }

    #[tokio::test]
    async fn session_labels_preserve_existing_sessions_and_only_store_known_labels() {
        let (state, headers) = crate::tests::domain_fixture();
        let original = current_session_info(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0;
        assert!(original.browser.is_none());
        {
            let db = state.db.lock().unwrap();
            let mut client = HeaderMap::new();
            client.insert(
                header::USER_AGENT,
                HeaderValue::from_static(
                    "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537.36 Edg/130.0",
                ),
            );
            let (raw, _) = create_session(&db, "u", "default", unix_now(), &client).unwrap();
            let labels: (String, String) = db
                .query_row(
                    "SELECT browser,os FROM auth_sessions WHERE session_digest=?1",
                    [digest(&raw)],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(labels, ("Edge".into(), "Windows".into()));
            client.insert(
                header::USER_AGENT,
                HeaderValue::from_static("untrusted-device-name<script>"),
            );
            assert_eq!(session_labels(&client), (None, None));
        }
        let current = current_session_info(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0;
        assert_eq!(original.id, current.id);
        let sessions = list_sessions(State(state), headers).await.unwrap().0;
        assert!(sessions
            .iter()
            .any(|session| session.browser.as_deref() == Some("Edge")));
    }

    #[tokio::test]
    async fn recovery_is_targeted_expiring_single_use_and_revokes_sessions_atomically() {
        let _guard = PASSWORD_TEST_LOCK.lock().await;
        let (mut state, _) = crate::tests::domain_fixture();
        let directory =
            std::env::temp_dir().join(format!("nexo-account-recovery-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let database = directory.join("nexo.db");
        state
            .db
            .lock()
            .unwrap()
            .execute("VACUUM INTO ?1", [database.to_str().unwrap()])
            .unwrap();
        state.db = Arc::new(Mutex::new(rusqlite::Connection::open(&database).unwrap()));
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO users(id,tenant_id,username,role,password_hash,created_at) VALUES('other','default','other-admin','system_admin','untouched',0)",[]).unwrap();
            create_session(&db, "other", "default", unix_now(), &HeaderMap::new()).unwrap();
        }
        assert!(create_recovery_code(&directory, None).is_err());
        let (expired, _, _) = create_recovery_code(&directory, Some("admin")).unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE auth_recovery SET expires_at=0", [])
            .unwrap();
        assert_eq!(
            recover(
                State(state.clone()),
                Json(RecoverRequest {
                    recovery_code: expired,
                    new_password: "a-safe-new-password".into()
                })
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::UNAUTHORIZED
        );
        let (old, _, _) = create_recovery_code(&directory, Some("admin")).unwrap();
        let (code, _, _) = create_recovery_code(&directory, Some("admin")).unwrap();
        assert!(recover(
            State(state.clone()),
            Json(RecoverRequest {
                recovery_code: old,
                new_password: "a-safe-new-password".into()
            })
        )
        .await
        .is_err());
        let first = recover(
            State(state.clone()),
            Json(RecoverRequest {
                recovery_code: code.clone(),
                new_password: "a-safe-new-password".into(),
            }),
        );
        let second = recover(
            State(state.clone()),
            Json(RecoverRequest {
                recovery_code: code,
                new_password: "a-safe-new-password".into(),
            }),
        );
        let (first, second) = tokio::join!(first, second);
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        {
            let db = state.db.lock().unwrap();
            let hash: String = db
                .query_row("SELECT password_hash FROM users WHERE id='u'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert!(verify_password("a-safe-new-password", &hash));
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM auth_sessions WHERE user_id='u'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM auth_sessions WHERE user_id='other'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                1
            );
            assert_eq!(
                db.query_row(
                    "SELECT password_hash FROM users WHERE id='other'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
                "untouched"
            );
        }
        assert!(login(
            State(state.clone()),
            Extension(RequestSecurity { secure: false }),
            HeaderMap::new(),
            Json(LoginRequest {
                username: "admin".into(),
                password: "old-password".into()
            })
        )
        .await
        .is_err());
        assert!(login(
            State(state.clone()),
            Extension(RequestSecurity { secure: true }),
            HeaderMap::new(),
            Json(LoginRequest {
                username: "admin".into(),
                password: "a-safe-new-password".into()
            })
        )
        .await
        .is_ok());
        drop(state);
        fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn session_mutations_require_csrf_and_https_cookies_are_secure() {
        let (state, mut headers) = crate::tests::domain_fixture();
        headers.remove("x-nexo-csrf");
        assert_eq!(
            logout(State(state.clone()), headers.clone())
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            revoke_session(State(state), headers, axum::extract::Path("s".into()))
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        for secure in [false, true] {
            let response = auth_response(StatusCode::OK, "test-session", "test-csrf", "ok", secure);
            for cookie in response.headers().get_all(header::SET_COOKIE) {
                assert_eq!(cookie.to_str().unwrap().contains("; Secure"), secure);
            }
        }
    }
}
