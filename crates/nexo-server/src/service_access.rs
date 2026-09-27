//! 服务公网入口的密码认证，与管理账号、Agent 身份和内网跳转完全独立。
//! Caddy 先处理内网导航跳转，再调用本机认证接口；同出口 IP 不授予代理访问权。

use crate::{auth, db_error, unix_now, ApiError, AppState, TunnelInput};
use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const PREFIX: &str = "/.nexo-access/";
const COOKIE: &str = "nexo_access_";
const LIFETIME: i64 = 86400;

pub fn validate_password(password: &str) -> Result<(), ApiError> {
    if !(4..=16).contains(&password.len()) || !password.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "请输入 4–16 位字母、数字或符号，不含空格",
        ));
    }
    Ok(())
}

/// 明文在进入事务前取走；Argon2 不占用 SQLite 锁和异步工作线程。
pub async fn password_hash(input: &mut TunnelInput) -> Result<Option<String>, ApiError> {
    let Some(password) = input.access_password.take().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    validate_password(&password)?;
    auth::password_work(move || auth::hash_password(&password))
        .await?
        .map(Some)
        .map_err(db_error)
}

pub fn prepare(
    db: &Connection,
    tenant: &str,
    id: &str,
    input: &mut TunnelInput,
    hash: Option<&str>,
) -> Result<(), ApiError> {
    let previous = db.query_row("SELECT access_mode,access_password_hash FROM tunnels WHERE id=?1 AND tenant_id=?2 AND deleted_at IS NULL", params![id,tenant], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?))).optional().map_err(db_error)?;
    let mode = input
        .access_mode
        .as_deref()
        .unwrap_or_else(|| previous.as_ref().map(|p| p.0.as_str()).unwrap_or("public"));
    if !matches!(mode, "public" | "password") {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "访问规则无效"));
    }
    if mode == "password" {
        if nexo_tunnel::udp::is_port(&input.protocol) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "TCP/UDP 服务不支持认证访问",
            ));
        }
        if hash.is_none() && previous.as_ref().and_then(|p| p.1.as_ref()).is_none() {
            return Err(ApiError::new(StatusCode::BAD_REQUEST, "请设置访问密码"));
        }
    }
    input.access_mode = Some(mode.to_owned());
    Ok(())
}

pub fn save(
    db: &Connection,
    id: &str,
    input: &TunnelInput,
    hash: Option<&str>,
) -> Result<(), ApiError> {
    db.execute("UPDATE tunnels SET access_mode=?2,access_password_hash=CASE WHEN ?2='public' THEN NULL ELSE COALESCE(?3,access_password_hash) END WHERE id=?1", params![id,input.access_mode,hash]).map_err(db_error)?;
    Ok(())
}

#[derive(Clone)]
struct AccessState {
    db: Arc<Mutex<Connection>>,
    security: Arc<crate::security::Security>,
}

/// 只监听随机 loopback 端口；不挂到管理 API，也不信任公网自行提交的服务标识。
/// 任务只持有数据库和限流器，避免 AppState 与运行时循环引用；运行时释放时终止监听。
pub struct Runtime {
    pub address: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Runtime {
    pub async fn start(state: &AppState) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        let app = Router::new()
            .route("/check", get(check))
            .route("/.nexo-access/", get(page))
            .route("/.nexo-access/login", post(login))
            .fallback(|| async { StatusCode::NOT_FOUND })
            .layer(DefaultBodyLimit::max(2048))
            .layer(axum::middleware::map_response(|response: Response| async {
                protected(response)
            }))
            .with_state(AccessState {
                db: state.db.clone(),
                security: state.security.clone(),
            });
        let task = tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, app).await {
                tracing::error!("访问认证监听失败：{error}");
            }
        });
        Ok(Self { address, task })
    }
}

/// 每次从数据库读取有效服务及现有配置版本；不缓存密码或授权，防止规则变更滞后。
struct Service {
    id: String,
    name: String,
    mode: String,
    hash: Option<String>,
    origin: String,
    revision: i64,
}
fn value<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}
fn service(db: &Connection, headers: &HeaderMap) -> Result<Service, ApiError> {
    let id = value(headers, "x-nexo-access-service");
    let result = db.query_row("SELECT t.id,t.name,t.access_mode,t.access_password_hash,t.protocol,t.hostname || '.' || p.domain,t.apply_revision FROM tunnels t JOIN public_domains p ON p.id=t.public_domain_id JOIN tenants w ON w.id=t.tenant_id WHERE t.id=?1 AND t.enabled=1 AND t.deleted_at IS NULL AND w.enabled=1 AND t.protocol IN ('http','https')", [id], |r| Ok((Service { id:r.get(0)?,name:r.get(1)?,mode:r.get(2)?,hash:r.get(3)?,origin:String::new(),revision:r.get(6)? },r.get::<_,String>(4)?,r.get::<_,String>(5)?))).optional().map_err(db_error)?;
    let Some((mut service, protocol, host)) = result else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "服务不可用"));
    };
    // 检查当前域名，防止配置加载失败时旧 Caddy 路由继续使用新服务的认证。
    if value(headers, "x-nexo-access-host") != host
        || value(headers, "x-nexo-access-proto") != protocol
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "服务不可用"));
    }
    let authority = value(headers, "x-nexo-access-authority");
    let parsed = authority
        .parse::<axum::http::uri::Authority>()
        .map_err(db_error)?;
    if parsed.host() != host {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "访问地址无效"));
    }
    service.origin = format!("{protocol}://{authority}");
    Ok(service)
}
fn cookie_name(service: &Service) -> String {
    format!("{COOKIE}{}", service.id.replace('-', ""))
}
fn authenticated(
    db: &Connection,
    headers: &HeaderMap,
    service: &Service,
) -> Result<bool, ApiError> {
    let name = cookie_name(service);
    let raw = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|v| v.trim().strip_prefix(&format!("{name}=")));
    let Some(raw) = raw else { return Ok(false) };
    db.query_row("SELECT EXISTS(SELECT 1 FROM service_access_sessions WHERE digest=?1 AND service_id=?2 AND expires_at>?3)", params![auth::digest(raw),service.id,unix_now()], |r| r.get(0)).map_err(db_error)
}
fn protected(mut response: Response) -> Response {
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"));
    response
}
fn redirect(location: &str) -> Response {
    protected((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}
async fn check(State(state): State<AccessState>, headers: HeaderMap) -> Response {
    protected(check_inner(&state, &headers).unwrap_or_else(IntoResponse::into_response))
}
fn check_inner(state: &AccessState, headers: &HeaderMap) -> Result<Response, ApiError> {
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let service = service(&db, headers)?;
    if service.mode == "public" || authenticated(&db, headers, &service)? {
        let clean = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .map(str::trim)
            .filter(|v| !v.split('=').next().unwrap_or("").starts_with(COOKIE))
            .collect::<Vec<_>>()
            .join("; ");
        return Ok((StatusCode::NO_CONTENT, [("x-nexo-upstream-cookie", clean)]).into_response());
    }
    // 非安全 HTTP 来源通常没有 Fetch Metadata；HTML Accept 仅用于选择密码页响应，
    // 不授予权限，也不放宽内网重定向条件。有明确 fetch/WebSocket 元数据时不回退。
    let navigation = (value(headers, "sec-fetch-mode") == "navigate"
        && value(headers, "sec-fetch-dest") == "document")
        || (value(headers, "sec-fetch-mode").is_empty()
            && value(headers, "sec-fetch-dest").is_empty()
            && value(headers, "accept")
                .split(',')
                .any(|v| v.trim().split(';').next() == Some("text/html")));
    if matches!(value(headers, "x-nexo-access-method"), "GET" | "HEAD")
        && navigation
        && value(headers, "upgrade").is_empty()
    {
        let target = safe_return(value(headers, "x-nexo-access-uri"));
        let query: String = reqwest::Url::parse("http://local/")
            .unwrap()
            .query_pairs_mut()
            .append_pair("return", &target)
            .finish()
            .query()
            .unwrap()
            .to_owned();
        return Ok(redirect(&format!("{PREFIX}?{query}")));
    }
    Ok((StatusCode::UNAUTHORIZED, "请先输入访问密码").into_response())
}
fn safe_return(input: &str) -> String {
    if !input.starts_with('/')
        || input.starts_with("//")
        || input.contains(['\\', '\r', '\n'])
        || input.starts_with(PREFIX)
    {
        return "/".into();
    }
    let base = reqwest::Url::parse("http://local/").unwrap();
    match base.join(input) {
        Ok(url) if url.origin() == base.origin() && !url.path().starts_with(PREFIX) => format!(
            "{}{}",
            url.path(),
            url.query().map(|q| format!("?{q}")).unwrap_or_default()
        ),
        _ => "/".into(),
    }
}
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
#[derive(Deserialize)]
struct ReturnPath {
    #[serde(default, rename = "return")]
    path: String,
}
async fn page(
    State(state): State<AccessState>,
    Query(target): Query<ReturnPath>,
    headers: HeaderMap,
) -> Response {
    let result = (|| {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let service = service(&db, &headers)?;
        if service.mode == "public" || authenticated(&db, &headers, &service)? {
            return Ok(redirect(&safe_return(&target.path)));
        }
        let html =
            include_str!("service_access.html").replace("{{SERVICE_NAME}}", &escape(&service.name));
        Ok::<_, ApiError>(Html(html).into_response())
    })();
    protected(result.unwrap_or_else(IntoResponse::into_response))
}
#[derive(Deserialize)]
struct Login {
    password: String,
    #[serde(default)]
    return_to: String,
}
async fn login(
    State(state): State<AccessState>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> Response {
    protected(
        login_inner(&state, &headers, input)
            .await
            .unwrap_or_else(IntoResponse::into_response),
    )
}
async fn login_inner(
    state: &AccessState,
    headers: &HeaderMap,
    input: Login,
) -> Result<Response, ApiError> {
    let initial = {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        service(&db, headers)?
    };
    if value(headers, "origin") != initial.origin {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "请求来源不匹配"));
    }
    if !state.security.allow(
        format!(
            "service-access:{}:{}",
            initial.id,
            value(headers, "x-nexo-access-ip")
        ),
        20,
        unix_now(),
    ) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "尝试过多，请稍后再试",
        ));
    }
    validate_password(&input.password)?;
    let hash = initial.hash.clone().unwrap_or_default();
    let valid = auth::password_work(move || auth::verify_password(&input.password, &hash)).await?;
    if !valid || initial.mode != "password" {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "密码错误，请重试"));
    }
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let raw = hex::encode(bytes);
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let current = service(&db, headers)?;
    if current.hash != initial.hash
        || current.mode != initial.mode
        || current.origin != initial.origin
        || current.revision != initial.revision
    {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "密码已更新，请重试",
        ));
    }
    let tx = db.unchecked_transaction().map_err(db_error)?;
    tx.execute(
        "DELETE FROM service_access_sessions WHERE expires_at<=?1",
        [unix_now()],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO service_access_sessions(digest,service_id,expires_at) VALUES(?1,?2,?3)",
        params![auth::digest(&raw), current.id, unix_now() + LIFETIME],
    )
    .map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    let mut response = Json(json!({"return_to":safe_return(&input.return_to)})).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{}={raw}; Path=/; HttpOnly; SameSite=Lax; Max-Age={LIFETIME}{}",
            cookie_name(&current),
            if current.origin.starts_with("https://") {
                "; Secure"
            } else {
                ""
            }
        ))
        .unwrap(),
    );
    Ok(response)
}

/// 复用 Caddy forward_auth 的响应接管方式：2xx 继续原请求，其他状态直接返回访客。
/// 元数据全部覆盖；校验使用 GET，不消耗原 POST 请求体。认证 Cookie 不转发到目标应用。
pub fn handlers(address: &str, id: &str) -> (Value, Value) {
    let headers = json!({"request":{"set":{
        "X-Nexo-Access-Service":[id], "X-Nexo-Access-Host":["{http.request.host}"],
        "X-Nexo-Access-Authority":["{http.request.hostport}"], "X-Nexo-Access-Proto":["{http.request.scheme}"],
        "X-Nexo-Access-Ip":["{http.request.remote.host}"], "X-Nexo-Access-Method":["{http.request.method}"],
        "X-Nexo-Access-Uri":["{http.request.uri}"]}}});
    let endpoint =
        json!({"handler":"reverse_proxy","upstreams":[{"dial":address}],"headers":headers});
    let mut check = endpoint.clone();
    check["rewrite"] = json!({"method":"GET","uri":"/check"});
    check["handle_response"] = json!([{"match":{"status_code":[2]},"routes":[{"handle":[{"handler":"headers","request":{"set":{"Cookie":["{http.reverse_proxy.header.X-Nexo-Upstream-Cookie}"]},"delete":["X-Nexo-Access-*","X-Nexo-Upstream-Cookie"]}}]}]}]);
    (endpoint, check)
}

#[cfg(test)]
mod tests;
