//! 邀请制账号与管理员空间访问。登录身份始终不变，资源空间只在管理员入口中切换。
use crate::*;
use axum::{body::Body, http::Request, middleware::Next};

const WORKSPACE_HEADER: &str = "x-nexo-internal-workspace";

pub fn initialize_schema(db: &Connection) -> Result<()> {
    let has_enabled: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tenants') WHERE name='enabled')",
        [],
        |r| r.get(0),
    )?;
    if !has_enabled {
        db.execute_batch("ALTER TABLE tenants ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;")?;
    }
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS user_invitations (
        id TEXT PRIMARY KEY, token_digest TEXT NOT NULL UNIQUE,
        created_by TEXT NOT NULL REFERENCES users(id), created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL, used_by TEXT REFERENCES users(id), revoked_at INTEGER
    );",
    )?;
    Ok(())
}

pub fn require_admin(state: &AppState, headers: &HeaderMap) -> Result<auth::Session, ApiError> {
    let session = auth::require_session(state, headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let allowed: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1 AND role='system_admin' AND enabled=1)",
            [&session.user_id],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    if !allowed {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "此操作需要管理员权限"));
    }
    Ok(session)
}

/// 外层中间件先清除客户端伪造的内部标记，再把明确的管理员路径交给原资源路由。
/// 不改 Cookie、会话或用户 ID，因此账号安全接口不会意外操作被管理的用户。
pub async fn workspace_context(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    request.headers_mut().remove(WORKSPACE_HEADER);
    let path = request.uri().path().to_owned();
    if let Some(rest) = path.strip_prefix("/api/v1/admin/workspaces/") {
        let Some((workspace, resource)) = rest.split_once('/') else {
            return ApiError::new(StatusCode::NOT_FOUND, "工作空间入口不存在").into_response();
        };
        let kind = resource.split('/').next().unwrap_or_default();
        if !matches!(
            kind,
            "devices"
                | "enrollments"
                | "tunnels"
                | "public-domains"
                | "public-domain-runtime-events"
        ) {
            return ApiError::new(StatusCode::NOT_FOUND, "工作空间资源不存在").into_response();
        }
        if let Err(error) = require_admin(&state, request.headers()) {
            return error.into_response();
        }
        let exists = state
            .db
            .lock()
            .ok()
            .and_then(|db| {
                db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM tenants WHERE id=?1)",
                    [workspace],
                    |r| r.get::<_, bool>(0),
                )
                .ok()
            })
            .unwrap_or(false);
        if !exists {
            return ApiError::new(StatusCode::NOT_FOUND, "工作空间不存在").into_response();
        }
        let Ok(value) = axum::http::HeaderValue::from_str(workspace) else {
            return ApiError::new(StatusCode::BAD_REQUEST, "工作空间无效").into_response();
        };
        request.headers_mut().insert(WORKSPACE_HEADER, value);
        let query = request
            .uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        let Ok(uri) = format!("/api/v1/{resource}{query}").parse() else {
            return ApiError::new(StatusCode::BAD_REQUEST, "资源地址无效").into_response();
        };
        *request.uri_mut() = uri;
    }
    next.run(request).await
}

pub fn resource_session(state: &AppState, headers: &HeaderMap) -> Result<auth::Session, ApiError> {
    let mut session = auth::require_session(state, headers)?;
    if let Some(workspace) = headers.get(WORKSPACE_HEADER).and_then(|v| v.to_str().ok()) {
        require_admin(state, headers)?;
        session.tenant_id = workspace.to_owned();
    }
    Ok(session)
}

pub fn audit(
    db: &Connection,
    session: &auth::Session,
    event: &str,
    kind: &str,
    id: &str,
) -> Result<(), ApiError> {
    db.execute("INSERT INTO audit_events(tenant_id,actor_user_id,event_type,resource_type,resource_id,created_at) VALUES (?1,?2,?3,?4,?5,?6)", params![session.tenant_id,session.user_id,event,kind,id,unix_now()]).map_err(db_error)?;
    Ok(())
}

/// 停用空间仍可由管理员查看和编辑，但不能再签发或批准设备入网凭证。
pub fn ensure_workspace_enabled(db: &Connection, tenant: &str) -> Result<(), ApiError> {
    let enabled: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tenants WHERE id=?1 AND enabled=1)",
            [tenant],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    if !enabled {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "用户已停用，请先启用再办理设备入网",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
pub struct UserSummary {
    id: String,
    username: String,
    role: String,
    workspace_id: String,
    workspace_name: String,
    enabled: bool,
    created_at: i64,
    devices: i64,
    services: i64,
    domains: i64,
}
pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserSummary>>, ApiError> {
    require_admin(&state, &headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let mut query = db
        .prepare(
            "SELECT u.id,u.username,u.role,u.tenant_id,t.name,u.enabled,u.created_at,
        (SELECT COUNT(*) FROM devices WHERE tenant_id=u.tenant_id),
        (SELECT COUNT(*) FROM tunnels WHERE tenant_id=u.tenant_id AND deleted_at IS NULL),
        (SELECT COUNT(*) FROM public_domains WHERE tenant_id=u.tenant_id)
        FROM users u JOIN tenants t ON t.id=u.tenant_id ORDER BY u.created_at,u.username",
        )
        .map_err(db_error)?;
    let rows = query
        .query_map([], |r| {
            Ok(UserSummary {
                id: r.get(0)?,
                username: r.get(1)?,
                role: r.get(2)?,
                workspace_id: r.get(3)?,
                workspace_name: r.get(4)?,
                enabled: r.get(5)?,
                created_at: r.get(6)?,
                devices: r.get(7)?,
                services: r.get(8)?,
                domains: r.get(9)?,
            })
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_error)?;
    Ok(Json(rows))
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct UserUpdate {
    enabled: Option<bool>,
    username: Option<String>,
    role: Option<String>,
}
pub async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UserUpdate>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut actor = require_admin(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    if input.role.is_some() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "系统只有一位管理员，不支持修改角色",
        ));
    }
    if let Some(username) = &input.username {
        auth::validate_username(username)?;
    }
    let (username, enabled, renamed, status_changed) = {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let tx = db.unchecked_transaction().map_err(db_error)?;
        let (tenant, role, old_name, old_enabled): (String, String, String, bool) = tx
            .query_row(
                "SELECT tenant_id,role,username,enabled FROM users WHERE id=?1",
                [&id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(db_error)?
            .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "用户不存在"))?;
        if role == "system_admin" && (input.enabled.is_some() || actor.user_id != id) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "管理员只能修改自己的用户名，不能启停管理员",
            ));
        }
        let username = input
            .username
            .as_deref()
            .map(str::trim)
            .unwrap_or(&old_name)
            .to_owned();
        let enabled = input.enabled.unwrap_or(old_enabled);
        let renamed = username != old_name;
        let status_changed = enabled != old_enabled;
        actor.tenant_id = tenant.clone();
        if renamed {
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND id!=?2)",
                    params![username, id],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            if exists {
                return Err(ApiError::new(StatusCode::CONFLICT, "用户名已被使用"));
            }
            // 只同步系统生成的普通用户空间名称，保留 ID 和已有自定义名称。
            if role == "tenant" {
                tx.execute(
                    "UPDATE tenants SET name=?1 WHERE id=?2 AND name=?3",
                    params![
                        format!("{username}的工作空间"),
                        tenant,
                        format!("{old_name}的工作空间")
                    ],
                )
                .map_err(db_error)?;
            }
        }
        tx.execute(
            "UPDATE users SET username=?1,enabled=?2 WHERE id=?3",
            params![username, enabled, id],
        )
        .map_err(db_error)?;
        if status_changed {
            tx.execute(
                "UPDATE tenants SET enabled=?1 WHERE id=?2",
                params![enabled, tenant],
            )
            .map_err(db_error)?;
        }
        if renamed || (status_changed && !enabled) {
            tx.execute("DELETE FROM auth_sessions WHERE user_id=?1", [&id])
                .map_err(db_error)?;
            tx.execute("DELETE FROM auth_recovery WHERE id=?1", [&id])
                .map_err(db_error)?;
        }
        if status_changed && !enabled {
            // 协调器先从连接表移除被撤销会话，旧连接退出回调不会再写状态；在同一事务内标记离线。
            tx.execute(
                "UPDATE devices SET status='offline' WHERE tenant_id=?1",
                [&tenant],
            )
            .map_err(db_error)?;
            tx.execute("UPDATE pending_enrollments SET status='revoked' WHERE tenant_id=?1 AND status!='consumed'", [&tenant]).map_err(db_error)?;
        }
        if renamed {
            audit(&tx, &actor, "user_renamed", "user", &id)?;
        }
        if status_changed {
            audit(
                &tx,
                &actor,
                if enabled {
                    "user_enabled"
                } else {
                    "user_disabled"
                },
                "user",
                &id,
            )?;
        }
        tx.commit().map_err(db_error)?;
        (username, enabled, renamed, status_changed)
    };
    // 同步关闭监听和已有流；不修改各服务原有开关，恢复账号后可准确恢复。
    if status_changed {
        state
            .tunnel_runtime
            .changed(&state)
            .await
            .map_err(db_error)?;
    }
    Ok(Json(
        serde_json::json!({"id":id,"username":username,"enabled":enabled,"reauthenticate":renamed && actor.user_id == id}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteUser {
    confirm_username: String,
}

/// 先取得配置与连接协调锁，再在单个事务中删除归属数据；旧快照不能在删除之后恢复入口。
pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<DeleteUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    let _config_guard = state.domain_runtime.reconcile_lock.lock().await;
    state
        .tunnel_runtime
        .remove_workspace(|| {
            // 等锁期间会话可能已因管理员改名而撤销，提交前必须重新鉴权。
            let mut actor = require_admin(&state, &headers)?;
            auth::require_csrf(&state, &headers)?;
            let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
            let tx = db.unchecked_transaction().map_err(db_error)?;
            let (tenant, role, username): (String, String, String) = tx
                .query_row(
                    "SELECT tenant_id,role,username FROM users WHERE id=?1",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
                .map_err(db_error)?
                .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "用户不存在或已被删除"))?;
            if role == "system_admin" || actor.user_id == id {
                return Err(ApiError::new(StatusCode::FORBIDDEN, "不能删除管理员账号"));
            }
            if input.confirm_username != username {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "确认用户名不匹配，请刷新用户信息后重试",
                ));
            }
            // 当前产品一人一空间；异常的共享空间数据不能级联误删其他账号。
            let shared: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id=?1 AND id!=?2)",
                    params![tenant, id],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            if shared {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "此工作空间仍关联其他账号，不能删除",
                ));
            }
            let devices = tx
                .prepare("SELECT id FROM devices WHERE tenant_id=?1")
                .map_err(db_error)?
                .query_map([&tenant], |r| r.get::<_, String>(0))
                .map_err(db_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_error)?;
            let services = tx
                .prepare("SELECT id FROM tunnels WHERE tenant_id=?1")
                .map_err(db_error)?
                .query_map([&tenant], |r| r.get::<_, String>(0))
                .map_err(db_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(db_error)?;
            actor.tenant_id = tenant.clone();
            audit(&tx, &actor, "user_deleted", "user", &id)?;
            // used_by 是外键；删除已消费的邀请而非置空，防止旧链接复活。
            tx.execute(
                "DELETE FROM user_invitations WHERE used_by=?1 OR created_by=?1",
                [&id],
            )
            .map_err(db_error)?;
            tx.execute("DELETE FROM auth_recovery WHERE id=?1", [&id])
                .map_err(db_error)?;
            tx.execute("DELETE FROM tenants WHERE id=?1", [&tenant])
                .map_err(db_error)?;
            tx.commit().map_err(db_error)?;
            Ok((devices, services))
        })
        .await?;
    let complete = match crate::domain_runtime::reconcile_locked(&state).await {
        Ok(complete) => complete,
        Err(error) => {
            tracing::warn!("账号已删除，Caddy 配置和凭据清理将继续重试：{error:#}");
            false
        }
    };
    Ok(Json(
        serde_json::json!({"deleted":true,"id":id,"cleanup_pending":!complete,"message":if complete {"用户及其资源已删除"} else {"用户及其资源已删除，公网配置和凭据清理正在重试"}}),
    ))
}

pub async fn create_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut actor = require_admin(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    let token = EnrollmentToken::generate(unix_now(), 900).map_err(db_error)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    actor.tenant_id = db
        .query_row(
            "SELECT tenant_id FROM users WHERE id=?1 AND role='tenant' AND enabled=1",
            [&id],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "只能为已启用的普通用户生成恢复链接",
            )
        })?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    tx.execute("INSERT INTO auth_recovery(id,recovery_digest,expires_at,used) VALUES (?1,?2,?3,0) ON CONFLICT(id) DO UPDATE SET recovery_digest=excluded.recovery_digest,expires_at=excluded.expires_at,used=0",params![id,token.digest,token.expires_at]).map_err(db_error)?;
    audit(&tx, &actor, "recovery_created", "user", &id)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(
        serde_json::json!({"token":token.secret,"expires_at":token.expires_at}),
    ))
}

#[derive(Serialize)]
pub struct Invitation {
    id: String,
    created_at: i64,
    expires_at: i64,
    status: String,
    username: Option<String>,
}
pub async fn list_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Invitation>>, ApiError> {
    require_admin(&state, &headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let mut query = db.prepare("SELECT i.id,i.created_at,i.expires_at,CASE WHEN i.used_by IS NOT NULL THEN 'used' WHEN i.revoked_at IS NOT NULL THEN 'revoked' WHEN i.expires_at<=?1 THEN 'expired' ELSE 'pending' END,u.username FROM user_invitations i LEFT JOIN users u ON u.id=i.used_by ORDER BY i.created_at DESC LIMIT 100").map_err(db_error)?;
    let rows = query
        .query_map([unix_now()], |r| {
            Ok(Invitation {
                id: r.get(0)?,
                created_at: r.get(1)?,
                expires_at: r.get(2)?,
                status: r.get(3)?,
                username: r.get(4)?,
            })
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_error)?;
    Ok(Json(rows))
}
pub async fn create_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let actor = require_admin(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    let token = EnrollmentToken::generate(unix_now(), 7 * 24 * 3600).map_err(db_error)?;
    let id = Uuid::new_v4().to_string();
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    tx.execute("INSERT INTO user_invitations(id,token_digest,created_by,created_at,expires_at) VALUES (?1,?2,?3,?4,?5)",params![id,token.digest,actor.user_id,unix_now(),token.expires_at]).map_err(db_error)?;
    audit(&tx, &actor, "invitation_created", "invitation", &id)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(
        serde_json::json!({"id":id,"token":token.secret,"expires_at":token.expires_at}),
    ))
}
pub async fn revoke_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let actor = require_admin(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    db.execute(
        "UPDATE user_invitations SET revoked_at=?1 WHERE id=?2 AND used_by IS NULL",
        params![unix_now(), id],
    )
    .map_err(db_error)?;
    audit(&db, &actor, "invitation_revoked", "invitation", &id)?;
    Ok(Json(serde_json::json!({"revoked":true})))
}

#[derive(Deserialize)]
pub struct InspectInvitation {
    token: String,
}
#[derive(Deserialize)]
pub struct AcceptInvitation {
    token: String,
    username: String,
    password: String,
}
fn valid_invitation(db: &Connection, token: &str) -> Result<(String, i64), ApiError> {
    if token.len() > 256 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "邀请链接无效"));
    }
    db.query_row("SELECT id,expires_at FROM user_invitations WHERE token_digest=?1 AND used_by IS NULL AND revoked_at IS NULL AND expires_at>?2",params![EnrollmentToken::digest(token),unix_now()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(db_error)?.ok_or_else(||ApiError::new(StatusCode::BAD_REQUEST,"邀请链接已失效、已使用或已过期"))
}
pub async fn inspect_invitation(
    State(state): State<AppState>,
    Json(input): Json<InspectInvitation>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let (_, expires) = valid_invitation(&db, &input.token)?;
    Ok(Json(serde_json::json!({"expires_at":expires})))
}
pub async fn accept_invitation(
    State(state): State<AppState>,
    axum::Extension(security): axum::Extension<security::RequestSecurity>,
    headers: HeaderMap,
    Json(input): Json<AcceptInvitation>,
) -> Result<Response, ApiError> {
    if auth::require_session(&state, &headers).is_ok() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "请先退出当前账号，再接受邀请",
        ));
    }
    auth::validate_username(&input.username)?;
    auth::validate_password(&input.password)?;
    {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        valid_invitation(&db, &input.token)?;
    }
    let hash = auth::password_work(move || auth::hash_password(&input.password))
        .await?
        .map_err(db_error)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    let (invitation, _) = valid_invitation(&tx, &input.token)?;
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username=?1)",
            [input.username.trim()],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    if exists {
        return Err(ApiError::new(StatusCode::CONFLICT, "用户名已被使用"));
    }
    let user = Uuid::new_v4().to_string();
    let tenant = Uuid::new_v4().to_string();
    let now = unix_now();
    tx.execute(
        "INSERT INTO tenants(id,name,created_at) VALUES (?1,?2,?3)",
        params![tenant, format!("{}的工作空间", input.username.trim()), now],
    )
    .map_err(db_error)?;
    tx.execute("INSERT INTO users(id,tenant_id,username,role,password_hash,enabled,created_at) VALUES (?1,?2,?3,'tenant',?4,1,?5)",params![user,tenant,input.username.trim(),hash,now]).map_err(db_error)?;
    tx.execute(
        "UPDATE user_invitations SET used_by=?1 WHERE id=?2",
        params![user, invitation],
    )
    .map_err(db_error)?;
    let (session, csrf) = auth::create_session(&tx, &user, &tenant, now).map_err(db_error)?;
    audit(
        &tx,
        &auth::Session {
            user_id: user,
            tenant_id: tenant,
            csrf: String::new(),
        },
        "account_created",
        "invitation",
        &invitation,
    )?;
    tx.commit().map_err(db_error)?;
    Ok(auth::auth_response(
        StatusCode::CREATED,
        &session,
        &csrf,
        "账号创建成功",
        security.secure,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{json, Value};

    pub(crate) fn add_user(state: &AppState, id: &str) -> HeaderMap {
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO tenants(id,name,created_at) VALUES (?1,?1,0)",
            [id],
        )
        .unwrap();
        db.execute("INSERT INTO users(id,tenant_id,username,role,password_hash,created_at) VALUES (?1,?1,?1,'tenant','unused',0)", [id]).unwrap();
        let (cookie, csrf) = auth::create_session(&db, id, id, unix_now()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("cookie", format!("nexo_session={cookie}").parse().unwrap());
        headers.insert("x-nexo-csrf", csrf.parse().unwrap());
        headers
    }

    // 通过真实 HTTP Router 检查内部空间头清除和 URI 重写，不能用直接调用处理器代替边界测试。
    async fn serve(state: AppState) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        (url, task)
    }

    #[tokio::test]
    async fn router_enforces_workspace_boundaries_and_keeps_admin_actor() {
        let (state, admin) = crate::tests::domain_fixture();
        let alice = add_user(&state, "alice");
        let bob = add_user(&state, "bob");
        for (headers, name) in [(&alice, "alice.test"), (&bob, "bob.test")] {
            crate::tests::add_test_domain(&state, headers, name)
                .await
                .unwrap();
        }
        let (url, task) = serve(state.clone()).await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let own: Value = client
            .get(format!("{url}/api/v1/public-domains"))
            .headers(alice.clone())
            .header(WORKSPACE_HEADER, "bob")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(own.as_array().unwrap().len(), 1);
        assert_eq!(own[0]["domain"], "alice.test");
        let path = format!("{url}/api/v1/admin/workspaces/bob/public-domains");
        assert_eq!(
            client
                .get(&path)
                .headers(alice.clone())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let other: Value = client
            .get(&path)
            .headers(admin.clone())
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(other[0]["domain"], "bob.test");
        let body = json!({"domain":"admin-managed.test"});
        let created = client
            .post(&path)
            .headers(admin.clone())
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        {
            let db = state.db.lock().unwrap();
            let (actor, tenant): (String, String) = db.query_row("SELECT actor_user_id,tenant_id FROM audit_events WHERE event_type='domain_created' ORDER BY id DESC LIMIT 1", [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
            assert_eq!((actor.as_str(), tenant.as_str()), ("u", "bob"));
        }
        let info: Value = client
            .get(format!("{url}/api/v1/auth/status"))
            .headers(admin.clone())
            .header(WORKSPACE_HEADER, "bob")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(info["user_id"], "u");
        assert_eq!(info["workspace_id"], "default");
        assert_eq!(
            client
                .post(format!("{url}/api/v1/admin/workspaces/bob/auth/password"))
                .headers(admin.clone())
                .json(&json!({}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            client
                .get(format!("{url}/api/v1/admin/users"))
                .headers(bob)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut no_csrf = admin;
        no_csrf.remove("x-nexo-csrf");
        assert_eq!(
            client
                .post(&path)
                .headers(no_csrf)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let foreign_id = other[0]["id"].as_str().unwrap();
        assert_eq!(
            client
                .patch(format!("{url}/api/v1/public-domains/{foreign_id}"))
                .headers(alice)
                .json(&json!({"certificate_mode":"http01"}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        task.abort();
    }

    #[tokio::test]
    async fn invitation_is_expiring_revocable_and_single_use_under_concurrency() {
        let _guard = auth::PASSWORD_TEST_LOCK.lock().await;
        let (state, headers) = crate::tests::domain_fixture();
        let Json(invite) = create_invitation(State(state.clone()), headers.clone())
            .await
            .unwrap();
        assert!((invite["expires_at"].as_i64().unwrap() - unix_now() - 7 * 86400).abs() <= 1);
        let token = invite["token"].as_str().unwrap().to_owned();
        let (url, task) = serve(state.clone()).await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let accept = |username: &str| {
            client
                .post(format!("{url}/api/v1/auth/invitations/accept"))
                .json(
                    &json!({"token":token,"username":username,"password":"correct-horse-battery"}),
                )
                .send()
        };
        let (a, b) = tokio::join!(accept("alice"), accept("bob"));
        assert_eq!(
            [a.unwrap().status(), b.unwrap().status()]
                .iter()
                .filter(|s| **s == StatusCode::CREATED)
                .count(),
            1
        );
        {
            let db = state.db.lock().unwrap();
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM users WHERE role='tenant'", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap(),
                1
            );
            assert!(valid_invitation(&db, &token).is_err());
        }

        let Json(invite) = create_invitation(State(state.clone()), headers.clone())
            .await
            .unwrap();
        let _ = revoke_invitation(
            State(state.clone()),
            headers.clone(),
            Path(invite["id"].as_str().unwrap().into()),
        )
        .await
        .unwrap();
        assert!(
            valid_invitation(&state.db.lock().unwrap(), invite["token"].as_str().unwrap()).is_err()
        );
        let Json(invite) = create_invitation(State(state.clone()), headers)
            .await
            .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE user_invitations SET expires_at=0 WHERE id=?1",
                [invite["id"].as_str().unwrap()],
            )
            .unwrap();
        assert!(
            valid_invitation(&state.db.lock().unwrap(), invite["token"].as_str().unwrap()).is_err()
        );
        task.abort();
    }

    #[tokio::test]
    async fn disabling_revokes_sessions_and_enrollment_without_losing_service_flags() {
        let (state, admin) = crate::tests::domain_fixture();
        let alice = add_user(&state, "alice");
        let Json(invite) = create_enrollment(
            State(state.clone()),
            alice.clone(),
            Json(CreateEnrollment { ttl_seconds: None }),
        )
        .await
        .unwrap();
        let Json(recovery) =
            create_recovery(State(state.clone()), admin.clone(), Path("alice".into()))
                .await
                .unwrap();
        assert!((recovery["expires_at"].as_i64().unwrap() - unix_now() - 900).abs() <= 1);
        state.db.lock().unwrap().execute_batch("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,enabled,created_at,updated_at) VALUES ('a','alice','on','tcp','127.0.0.1',1,1,0,0),('b','alice','off','tcp','127.0.0.1',1,0,0,0);").unwrap();
        state.db.lock().unwrap().execute("INSERT INTO devices(id,tenant_id,name,status,created_at,updated_at) VALUES ('agent','alice','agent','online',0,0)",[]).unwrap();
        let _ = update_user(
            State(state.clone()),
            admin.clone(),
            Path("alice".into()),
            Json(UserUpdate {
                enabled: Some(false),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert!(auth::require_session(&state, &alice).is_err());
        {
            let db = state.db.lock().unwrap();
            assert_eq!(
                db.query_row(
                    "SELECT status FROM pending_enrollments WHERE id=?1",
                    [invite.id],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
                "revoked"
            );
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM auth_recovery WHERE id='alice'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
            assert_eq!(
                db.query_row(
                    "SELECT SUM(enabled) FROM tunnels WHERE tenant_id='alice'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                1
            );
            assert!(ensure_workspace_enabled(&db, "alice").is_err());
            assert_eq!(
                db.query_row("SELECT status FROM devices WHERE id='agent'", [], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
                "offline"
            );
        }
        let _ = update_user(
            State(state.clone()),
            admin.clone(),
            Path("alice".into()),
            Json(UserUpdate {
                enabled: Some(true),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert!(auth::require_session(&state, &alice).is_err());
        assert!(ensure_workspace_enabled(&state.db.lock().unwrap(), "alice").is_ok());
        assert!(update_user(
            State(state),
            admin,
            Path("u".into()),
            Json(UserUpdate {
                enabled: Some(false),
                ..Default::default()
            })
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn renaming_keeps_resources_and_revokes_only_changed_accounts() {
        let _guard = auth::PASSWORD_TEST_LOCK.lock().await;
        let (state, admin) = crate::tests::domain_fixture();
        let alice = add_user(&state, "alice");
        let bob = add_user(&state, "bob");
        let hash = auth::hash_password("safe-test-password").unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute("UPDATE users SET password_hash=?1", [&hash])
                .unwrap();
            db.execute(
                "UPDATE tenants SET name='alice的工作空间' WHERE id='alice'",
                [],
            )
            .unwrap();
        }
        let domain = crate::tests::add_test_domain(&state, &alice, "rename.test")
            .await
            .unwrap();
        let _ = create_recovery(State(state.clone()), admin.clone(), Path("alice".into()))
            .await
            .unwrap();
        let (url, task) = serve(state.clone()).await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let patch = |id: &str, headers: HeaderMap, body: Value| {
            client
                .patch(format!("{url}/api/v1/admin/users/{id}"))
                .headers(headers)
                .json(&body)
                .send()
        };
        assert_eq!(
            patch("alice", bob.clone(), json!({"username":"hijacked"}))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut no_csrf = admin.clone();
        no_csrf.remove("x-nexo-csrf");
        assert_eq!(
            patch("alice", no_csrf, json!({"username":"new-alice"}))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        for body in [json!({"role":"system_admin"}), json!({"username":"x"})] {
            assert_eq!(
                patch("alice", admin.clone(), body).await.unwrap().status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            patch("alice", admin.clone(), json!({"username":"bob"}))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            patch("u", admin.clone(), json!({"enabled":true}))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            patch("alice", admin.clone(), json!({"username":" alice "}))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(auth::require_session(&state, &alice).is_ok());
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM auth_recovery WHERE id='alice'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        let response = patch("alice", admin.clone(), json!({"username":"new-alice"}))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.json::<Value>().await.unwrap()["reauthenticate"],
            false
        );
        assert!(auth::require_session(&state, &alice).is_err());
        assert!(auth::require_session(&state, &bob).is_ok());
        {
            let db = state.db.lock().unwrap();
            assert_eq!(
                db.query_row(
                    "SELECT tenant_id FROM public_domains WHERE id=?1",
                    [&domain.id],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
                "alice"
            );
            assert_eq!(
                db.query_row("SELECT name FROM tenants WHERE id='alice'", [], |r| r
                    .get::<_, String>(0))
                    .unwrap(),
                "new-alice的工作空间"
            );
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM auth_recovery WHERE id='alice'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
        }
        for (username, expected) in [
            ("alice", StatusCode::UNAUTHORIZED),
            ("new-alice", StatusCode::OK),
        ] {
            assert_eq!(
                client
                    .post(format!("{url}/api/v1/auth/login"))
                    .json(&json!({"username":username,"password":"safe-test-password"}))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                expected
            );
        }
        let response = patch("u", admin.clone(), json!({"username":"owner"}))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.json::<Value>().await.unwrap()["reauthenticate"],
            true
        );
        assert!(auth::require_session(&state, &admin).is_err());
        assert!(auth::require_session(&state, &bob).is_ok());
        assert_eq!(
            client
                .post(format!("{url}/api/v1/auth/login"))
                .json(&json!({"username":"owner","password":"safe-test-password"}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        task.abort();
    }

    #[tokio::test]
    async fn deletion_checks_confirmation_and_cascades_without_reviving_invites() {
        let (state, admin) = crate::tests::domain_fixture();
        let alice = add_user(&state, "alice");
        let bob = add_user(&state, "bob");
        let domain = crate::tests::add_test_domain(&state, &alice, "delete.test")
            .await
            .unwrap();
        let invite = create_invitation(State(state.clone()), admin.clone())
            .await
            .unwrap()
            .0;
        let pending = create_enrollment(
            State(state.clone()),
            alice.clone(),
            Json(CreateEnrollment { ttl_seconds: None }),
        )
        .await
        .unwrap()
        .0;
        let _ = create_recovery(State(state.clone()), admin.clone(), Path("alice".into()))
            .await
            .unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE user_invitations SET used_by='alice' WHERE id=?1",
                [invite["id"].as_str().unwrap()],
            )
            .unwrap();
            db.execute_batch("INSERT INTO devices(id,tenant_id,name,created_at,updated_at) VALUES('a','alice','Agent',0,0); INSERT INTO device_identities VALUES('a','secret',0); INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('t','alice','a','service','tcp','127.0.0.1',80,0,0); INSERT INTO tunnel_applied_states VALUES('t',1,'ready',NULL,0);").unwrap();
            db.execute("INSERT INTO public_domain_runtime_events(tenant_id,public_domain_id,summary,occurred_at) VALUES('alice',?1,'loaded',0)", [&domain.id]).unwrap();
        }
        let (url, task) = serve(state.clone()).await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let delete = |id: &str, headers: HeaderMap, name: &str| {
            client
                .delete(format!("{url}/api/v1/admin/users/{id}"))
                .headers(headers)
                .json(&json!({"confirm_username":name}))
                .send()
        };
        assert_eq!(
            delete("u", admin.clone(), "admin").await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            delete("alice", bob.clone(), "alice")
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut no_csrf = admin.clone();
        no_csrf.remove("x-nexo-csrf");
        assert_eq!(
            delete("alice", no_csrf, "alice").await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            delete("alice", admin.clone(), "wrong")
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let _ = update_user(
            State(state.clone()),
            admin.clone(),
            Path("alice".into()),
            Json(UserUpdate {
                username: Some("renamed".into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            delete("alice", admin.clone(), "alice")
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        let (a, b) = tokio::join!(
            delete("alice", admin.clone(), "renamed"),
            delete("alice", admin.clone(), "renamed")
        );
        let statuses = [a.unwrap().status(), b.unwrap().status()];
        assert!(statuses.contains(&StatusCode::OK) && statuses.contains(&StatusCode::NOT_FOUND));
        assert!(auth::require_session(&state, &alice).is_err());
        assert!(auth::require_session(&state, &bob).is_ok());
        assert!(auth::require_session(&state, &admin).is_ok());
        let db = state.db.lock().unwrap();
        for table in [
            "devices",
            "device_identities",
            "tunnels",
            "tunnel_applied_states",
            "public_domains",
            "domain_settings",
            "public_domain_runtime_events",
            "pending_enrollments",
            "auth_recovery",
            "user_invitations",
        ] {
            assert_eq!(
                db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{table}"
            );
        }
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM tenants", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(db.query_row("SELECT COUNT(*) FROM audit_events WHERE event_type='user_deleted' AND tenant_id='alice' AND actor_user_id='u'",[],|r|r.get::<_,i64>(0)).unwrap(),1);
        assert!(valid_invitation(&db, invite["token"].as_str().unwrap()).is_err());
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM pending_enrollments WHERE id=?1",
                [pending.id],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        task.abort();
    }
}
