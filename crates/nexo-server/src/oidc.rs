//! Nexo 为内置 Headscale 提供的 OpenID Connect Provider。
//!
//! 这里实现的是 Headscale 0.29.3 使用的 Authorization Code 流程：授权请求
//! 经过现有 Nexo 登录页完成认证，授权码和短期 Access Token 只存在有界内存中，
//! RSA 密钥与固定 issuer 持久化在 SQLite。OIDC 不读取或修改 Headscale 数据库，
//! 节点归属由后台根据 `issuer/sub` 映射完成。

use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
};

use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use oxide_auth::code_grant::extensions::Pkce;
use oxide_auth::endpoint::QueryParameter;
use oxide_auth_axum::OAuthRequest;
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
    RsaPrivateKey,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{auth, unix_now, ApiError, AppState};

const CLIENT_ID: &str = "headscale";
const AUTHORIZATION_CODE_SECONDS: i64 = 60;
const ACCESS_TOKEN_SECONDS: i64 = 300;
const LOGIN_TICKET_SECONDS: i64 = 600;
const MAX_AUTHORIZATION_CODES: usize = 1024;
const MAX_ACCESS_TOKENS: usize = 2048;
const MAX_LOGIN_TICKETS: usize = 1024;

#[derive(Debug, Clone)]
pub struct OidcRuntime {
    key: Arc<OidcKeyMaterial>,
    issuer: Arc<RwLock<Option<String>>>,
    authorization_codes: Arc<Mutex<HashMap<String, AuthorizationCode>>>,
    access_tokens: Arc<Mutex<HashMap<String, AccessToken>>>,
    login_tickets: Arc<Mutex<HashMap<String, LoginTicket>>>,
}

#[derive(Debug, Clone)]
struct OidcKeyMaterial {
    private_key_pem: String,
    key_id: String,
    modulus: String,
    exponent: String,
}

#[derive(Debug, Clone)]
struct AuthorizationCode {
    user_id: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    nonce: String,
    pkce_method: String,
    expires_at: i64,
}

#[derive(Debug, Clone)]
struct AccessToken {
    user_id: String,
    client_id: String,
    expires_at: i64,
}

#[derive(Debug, Clone)]
struct LoginTicket {
    request: AuthorizeRequest,
    expires_at: i64,
}

#[derive(Debug, Clone)]
struct AuthorizeRequest {
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
}

#[derive(Debug, Serialize)]
pub struct DiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<&'static str>,
    subject_types_supported: Vec<&'static str>,
    id_token_signing_alg_values_supported: Vec<&'static str>,
    scopes_supported: Vec<&'static str>,
    claims_supported: Vec<&'static str>,
    code_challenge_methods_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct JwksResponse {
    keys: Vec<JsonWebKey>,
}

#[derive(Debug, Serialize)]
struct JsonWebKey {
    kty: &'static str,
    use_: &'static str,
    alg: &'static str,
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    id_token: String,
    scope: String,
}

#[derive(Debug, Serialize)]
struct UserInfoResponse {
    sub: String,
    preferred_username: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: i64,
    exp: i64,
    nonce: String,
    preferred_username: String,
    name: String,
}

impl OidcRuntime {
    /// 从数据库加载固定的 RSA 密钥；首次安装只生成一次，后续重启绝不轮换。
    pub fn initialize(connection: &Connection) -> Result<Self> {
        let row: Option<(String, String, String, Option<String>)> = connection
            .query_row(
                "SELECT private_key_pem, public_key_pem, key_id, issuer
                 FROM oidc_settings WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let (key, issuer) = if let Some((private_key_pem, public_key_pem, key_id, issuer)) = row {
            let public_key =
                rsa::RsaPublicKey::from_pkcs1_pem(&public_key_pem).context("OIDC 公钥格式无效")?;
            (
                OidcKeyMaterial {
                    private_key_pem,
                    key_id,
                    modulus: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                    exponent: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
                },
                issuer,
            )
        } else {
            let mut random = OsRng;
            let private_key =
                RsaPrivateKey::new(&mut random, 2048).context("无法生成 OIDC RSA 签名密钥")?;
            let public_key = private_key.to_public_key();
            let private_key_pem = private_key
                .to_pkcs8_pem(LineEnding::LF)
                .context("无法编码 OIDC 私钥")?
                .to_string();
            let public_key_pem = public_key
                .to_pkcs1_pem(LineEnding::LF)
                .context("无法编码 OIDC 公钥")?
                .to_string();
            let key_id = hex::encode(Sha256::digest(public_key_pem.as_bytes()))[..16].to_owned();
            connection.execute(
                "INSERT INTO oidc_settings
                 (id, private_key_pem, public_key_pem, key_id)
                 VALUES (1, ?1, ?2, ?3)",
                params![private_key_pem, public_key_pem, key_id],
            )?;
            (
                OidcKeyMaterial {
                    private_key_pem,
                    key_id,
                    modulus: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                    exponent: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
                },
                None,
            )
        };
        Ok(Self {
            key: Arc::new(key),
            issuer: Arc::new(RwLock::new(issuer)),
            authorization_codes: Arc::new(Mutex::new(HashMap::new())),
            access_tokens: Arc::new(Mutex::new(HashMap::new())),
            login_tickets: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// issuer 首次从当前主域名确定，之后只从 oidc_settings 读取，域名迁移不会改变它。
    pub fn sync_issuer_from_database(&self, connection: &Connection) -> Result<Option<String>> {
        let current: Option<String> = connection
            .query_row("SELECT issuer FROM oidc_settings WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()?
            .flatten();
        if let Some(issuer) = current {
            self.set_issuer(issuer.clone())?;
            return Ok(Some(issuer));
        }
        let domain: Option<String> = connection
            .query_row(
                "SELECT domain FROM public_domains
                 WHERE is_primary = 1 AND https_enabled = 1
                 ORDER BY updated_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(domain) = domain.filter(|value| !value.trim().is_empty()) else {
            return Ok(None);
        };
        let issuer = format!("https://nexo.{}", domain.trim_end_matches('.'));
        validate_issuer(&issuer).map_err(|error| anyhow::anyhow!(error.message))?;
        connection.execute(
            "UPDATE oidc_settings SET issuer = ?1, updated_at = unixepoch() WHERE id = 1 AND issuer IS NULL",
            [&issuer],
        )?;
        self.set_issuer(issuer.clone())?;
        Ok(Some(issuer))
    }

    pub fn issuer(&self) -> Option<String> {
        self.issuer.read().ok().and_then(|value| value.clone())
    }

    fn set_issuer(&self, issuer: String) -> Result<()> {
        let mut value = self
            .issuer
            .write()
            .map_err(|_| anyhow::anyhow!("OIDC issuer 锁不可用"))?;
        *value = Some(issuer);
        Ok(())
    }

    fn issue_login_ticket(&self, request: AuthorizeRequest) -> Result<String, ApiError> {
        let ticket = random_token();
        let now = unix_now();
        let mut tickets = self
            .login_tickets
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "OIDC 登录状态不可用"))?;
        tickets.retain(|_, value| value.expires_at > now);
        if tickets.len() >= MAX_LOGIN_TICKETS {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "OIDC 登录请求过多，请稍后重试",
            ));
        }
        tickets.insert(
            ticket.clone(),
            LoginTicket {
                request,
                expires_at: now + LOGIN_TICKET_SECONDS,
            },
        );
        Ok(ticket)
    }

    fn take_login_ticket(&self, ticket: &str) -> Option<AuthorizeRequest> {
        let now = unix_now();
        let mut tickets = self.login_tickets.lock().ok()?;
        let value = tickets.remove(ticket)?;
        (value.expires_at > now).then_some(value.request)
    }

    fn issue_code(&self, code: String, value: AuthorizationCode) -> Result<(), ApiError> {
        let mut codes = self
            .authorization_codes
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "OIDC 授权状态不可用"))?;
        let now = unix_now();
        codes.retain(|_, item| item.expires_at > now);
        if codes.len() >= MAX_AUTHORIZATION_CODES {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "OIDC 授权请求过多，请稍后重试",
            ));
        }
        codes.insert(code, value);
        Ok(())
    }

    fn take_code(&self, code: &str) -> Option<AuthorizationCode> {
        let now = unix_now();
        let mut codes = self.authorization_codes.lock().ok()?;
        let value = codes.remove(code)?;
        (value.expires_at > now).then_some(value)
    }

    fn issue_access_token(&self, token: String, value: AccessToken) -> Result<(), ApiError> {
        let mut tokens = self
            .access_tokens
            .lock()
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "OIDC 令牌状态不可用"))?;
        let now = unix_now();
        tokens.retain(|_, item| item.expires_at > now);
        if tokens.len() >= MAX_ACCESS_TOKENS {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "OIDC 令牌请求过多，请稍后重试",
            ));
        }
        tokens.insert(token, value);
        Ok(())
    }

    fn access_token(&self, token: &str) -> Option<AccessToken> {
        let now = unix_now();
        let mut tokens = self.access_tokens.lock().ok()?;
        let value = tokens.get(token)?.clone();
        if value.expires_at <= now {
            tokens.remove(token);
            None
        } else {
            Some(value)
        }
    }
}

/// OIDC Discovery；issuer 尚未因公网主域名确定时返回中文可读的服务不可用错误。
pub async fn discovery(State(state): State<AppState>) -> Result<Json<DiscoveryResponse>, ApiError> {
    let issuer = current_issuer(&state)?;
    Ok(Json(DiscoveryResponse {
        authorization_endpoint: format!("{issuer}/oidc/authorize"),
        token_endpoint: format!("{issuer}/oidc/token"),
        userinfo_endpoint: format!("{issuer}/oidc/userinfo"),
        jwks_uri: format!("{issuer}/oidc/jwks.json"),
        issuer,
        response_types_supported: vec!["code"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: vec!["RS256"],
        scopes_supported: vec!["openid", "profile"],
        claims_supported: vec!["sub", "preferred_username", "name"],
        code_challenge_methods_supported: vec!["S256"],
        token_endpoint_auth_methods_supported: vec!["none"],
    }))
}

/// JWKS 只暴露公钥参数；私钥仅用于服务端签发 ID Token。
pub async fn jwks(State(state): State<AppState>) -> Result<Response, ApiError> {
    let response = Json(JwksResponse {
        keys: vec![JsonWebKey {
            kty: "RSA",
            use_: "sig",
            alg: "RS256",
            kid: state.oidc.key.key_id.clone(),
            n: state.oidc.key.modulus.clone(),
            e: state.oidc.key.exponent.clone(),
        }],
    })
    .into_response();
    Ok(no_store(response))
}

/// Headscale 发起授权时只接受严格的客户端、回调、scope 和 PKCE 参数。
pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: OAuthRequest,
) -> Result<Response, ApiError> {
    let ticket = oauth_value(&request, "nexo_login_ticket");
    let authorize_request = if let Some(ticket) = ticket {
        state.oidc.take_login_ticket(&ticket).ok_or_else(|| {
            ApiError::new(StatusCode::BAD_REQUEST, "OIDC 登录请求已失效，请重新连接")
        })?
    } else {
        let request = parse_authorize_request(&request)?;
        validate_authorize_request(&state, &request).await?;
        if auth::current_user_id(&state, &headers).is_err() {
            let ticket = state.oidc.issue_login_ticket(request)?;
            let location = format!("/?oidc_ticket={}", percent_encode(&ticket));
            return Ok(Redirect::temporary(&location).into_response());
        }
        request
    };
    validate_authorize_request(&state, &authorize_request).await?;
    let user_id = auth::current_user_id(&state, &headers)?;
    let (username, enabled) = user_identity(&state, &user_id)?;
    if !enabled {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "当前账号已停用，不能使用组网登录",
        ));
    }
    ensure_oidc_account(&state, &user_id)?;
    let code = random_token();
    let now = unix_now();
    let pkce = Pkce::required();
    let pkce_value = pkce
        .challenge(
            Some(Cow::Borrowed(
                authorize_request.code_challenge_method.as_str(),
            )),
            Some(Cow::Borrowed(authorize_request.code_challenge.as_str())),
        )
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "PKCE S256 参数无效"))?
        .and_then(|value| value.private_value().ok().flatten().map(str::to_owned))
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "必须提供 PKCE S256 参数"))?;
    state.oidc.issue_code(
        code.clone(),
        AuthorizationCode {
            user_id,
            client_id: authorize_request.client_id,
            redirect_uri: authorize_request.redirect_uri.clone(),
            scope: authorize_request.scope,
            nonce: authorize_request.nonce,
            pkce_method: pkce_value,
            expires_at: now + AUTHORIZATION_CODE_SECONDS,
        },
    )?;
    let mut location = format!(
        "{}?code={}",
        authorize_request.redirect_uri,
        percent_encode(&code)
    );
    if let Some(state_value) = authorize_request.state {
        location.push_str("&state=");
        location.push_str(&percent_encode(&state_value));
    }
    tracing::info!(username = %username, "OIDC 登录已完成，授权码已签发");
    Ok(Redirect::temporary(&location).into_response())
}

/// Authorization Code 只能兑换一次；错误的 verifier 也会消费授权码。
pub async fn token(
    State(state): State<AppState>,
    request: OAuthRequest,
) -> Result<Response, ApiError> {
    let grant_type = oauth_value(&request, "grant_type")
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "缺少 grant_type"))?;
    if grant_type != "authorization_code" {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "只支持 authorization_code",
        ));
    }
    let client_id = oauth_value(&request, "client_id")
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "缺少 client_id"))?;
    let code = oauth_value(&request, "code")
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "缺少 authorization code"))?;
    let redirect_uri = oauth_value(&request, "redirect_uri")
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "缺少 redirect_uri"))?;
    let verifier = oauth_value(&request, "code_verifier")
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "缺少 PKCE code_verifier"))?;
    if client_id != CLIENT_ID || !valid_pkce_value(&verifier) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "OIDC 客户端或 PKCE 参数无效",
        ));
    }
    let code_value = state
        .oidc
        .take_code(&code)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "授权码无效、已使用或已过期"))?;
    if code_value.client_id != client_id || code_value.redirect_uri != redirect_uri {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "授权码客户端或回调地址不匹配",
        ));
    }
    let pkce = Pkce::required();
    pkce.verify(
        Some(oxide_auth::primitives::grant::Value::private(Some(
            code_value.pkce_method,
        ))),
        Some(Cow::Borrowed(verifier.as_str())),
    )
    .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "PKCE code_verifier 校验失败"))?;
    let (username, enabled) = user_identity(&state, &code_value.user_id)?;
    if !enabled {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "当前账号已停用，不能兑换 OIDC 令牌",
        ));
    }
    ensure_oidc_account(&state, &code_value.user_id)?;
    let token = random_token();
    let now = unix_now();
    state.oidc.issue_access_token(
        token.clone(),
        AccessToken {
            user_id: code_value.user_id.clone(),
            client_id,
            expires_at: now + ACCESS_TOKEN_SECONDS,
        },
    )?;
    let id_token = sign_id_token(
        &state,
        &code_value.user_id,
        &username,
        &code_value.nonce,
        now,
    )?;
    let response = Json(TokenResponse {
        access_token: token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_SECONDS,
        id_token,
        scope: code_value.scope,
    })
    .into_response();
    Ok(no_store(response))
}

/// Headscale 用 UserInfo 再次检查账号状态，停用后短期令牌也立即失效。
pub async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = bearer_token(&headers)?;
    let access = state
        .oidc
        .access_token(&token)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "OIDC Access Token 无效或已过期"))?;
    if access.client_id != CLIENT_ID {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "OIDC Access Token 客户端无效",
        ));
    }
    let (username, enabled) = user_identity(&state, &access.user_id)?;
    if !enabled {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "当前账号已停用"));
    }
    let response = Json(UserInfoResponse {
        sub: access.user_id,
        preferred_username: username.clone(),
        name: username,
    })
    .into_response();
    Ok(no_store(response))
}

fn parse_authorize_request(request: &OAuthRequest) -> Result<AuthorizeRequest, ApiError> {
    let required = |name: &str| {
        oauth_value(request, name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, format!("缺少 OIDC 参数 {name}")))
    };
    Ok(AuthorizeRequest {
        client_id: required("client_id")?,
        redirect_uri: required("redirect_uri")?,
        scope: required("scope")?,
        state: oauth_value(request, "state"),
        nonce: required("nonce")?,
        code_challenge: required("code_challenge")?,
        code_challenge_method: required("code_challenge_method")?,
    })
}

async fn validate_authorize_request(
    state: &AppState,
    request: &AuthorizeRequest,
) -> Result<(), ApiError> {
    if request.client_id != CLIENT_ID {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "OIDC client_id 无效",
        ));
    }
    if request.code_challenge_method != "S256" || !valid_pkce_value(&request.code_challenge) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "OIDC 只支持 PKCE S256",
        ));
    }
    if !request
        .scope
        .split_whitespace()
        .any(|scope| scope == "openid")
        || request
            .scope
            .split_whitespace()
            .any(|scope| !matches!(scope, "openid" | "profile"))
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "OIDC scope 必须包含 openid，且只支持 profile",
        ));
    }
    if request.nonce.len() > 512 || request.nonce.chars().any(char::is_whitespace) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "OIDC nonce 无效"));
    }
    let allowed = allowed_redirect_uris(state)?;
    if !allowed.iter().any(|value| value == &request.redirect_uri) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "OIDC redirect_uri 不在允许列表中",
        ));
    }
    current_issuer(state)?;
    Ok(())
}

fn allowed_redirect_uris(state: &AppState) -> Result<Vec<String>, ApiError> {
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let mut statement = connection
        .prepare(
            "SELECT domain FROM public_domains WHERE is_primary = 1
             UNION
             SELECT d.domain FROM public_domain_migrations m
             JOIN public_domains d ON d.id IN (m.from_domain_id, m.to_domain_id)
             WHERE m.status IN ('preparing', 'switching', 'waiting_devices')",
        )
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取 OIDC 回调域名"))?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取 OIDC 回调域名"))?;
    let domains = rows
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "OIDC 回调域名数据无效"))?;
    Ok(domains
        .into_iter()
        .map(|domain| {
            format!(
                "https://mesh.{}/oidc/callback",
                domain.trim_end_matches('.')
            )
        })
        .collect())
}

fn current_issuer(state: &AppState) -> Result<String, ApiError> {
    state.oidc.issuer().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "OIDC issuer 尚未就绪，请先配置并启用 HTTPS 主域名",
        )
    })
}

fn user_identity(state: &AppState, user_id: &str) -> Result<(String, bool), ApiError> {
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    connection
        .query_row(
            "SELECT username, enabled FROM users WHERE id = ?1",
            [user_id],
            |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
        )
        .optional()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法读取 Nexo 账号"))?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Nexo 账号不存在"))
}

fn ensure_oidc_account(state: &AppState, user_id: &str) -> Result<(), ApiError> {
    let issuer = current_issuer(state)?;
    let provider_id = format!("{issuer}/{user_id}");
    let connection = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let workspace_id: String = connection
        .query_row(
            "SELECT COALESCE(tenant_id, 'default') FROM users WHERE id = ?1 AND enabled = 1",
            [user_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::new(StatusCode::FORBIDDEN, "当前账号不可使用 OIDC"))?;
    connection
        .execute(
            "INSERT INTO mesh_oidc_accounts
             (nexo_user_id, workspace_id, provider_id, sync_status, last_error, updated_at)
             VALUES (?1, ?2, ?3, 'pending', NULL, unixepoch())
             ON CONFLICT(nexo_user_id) DO UPDATE SET
             workspace_id = excluded.workspace_id,
             provider_id = excluded.provider_id,
             sync_status = CASE WHEN mesh_oidc_accounts.sync_status = 'revoked'
                                THEN 'pending' ELSE mesh_oidc_accounts.sync_status END,
             last_error = NULL, updated_at = unixepoch()",
            params![user_id, workspace_id, provider_id],
        )
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "OIDC 账号映射已被其他账号占用"))?;
    Ok(())
}

fn sign_id_token(
    state: &AppState,
    user_id: &str,
    username: &str,
    nonce: &str,
    now: i64,
) -> Result<String, ApiError> {
    let issuer = current_issuer(state)?;
    let claims = IdTokenClaims {
        iss: issuer,
        sub: user_id.to_owned(),
        aud: CLIENT_ID.to_owned(),
        iat: now,
        exp: now + ACCESS_TOKEN_SECONDS,
        nonce: nonce.to_owned(),
        preferred_username: username.to_owned(),
        name: username.to_owned(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(state.oidc.key.key_id.clone());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(state.oidc.key.private_key_pem.as_bytes())
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "OIDC 签名密钥不可用"))?,
    )
    .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "无法签发 OIDC ID Token"))
}

fn oauth_value(request: &OAuthRequest, name: &str) -> Option<String> {
    request
        .query()
        .and_then(|value| value.unique_value(name))
        .or_else(|| request.body().and_then(|value| value.unique_value(name)))
        .map(Cow::into_owned)
}

fn bearer_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "缺少 Bearer Access Token"))?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Bearer Access Token 格式无效"))
}

fn valid_pkce_value(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
}

fn validate_issuer(issuer: &str) -> Result<(), ApiError> {
    if !(issuer.starts_with("https://") && issuer.len() > "https://".len())
        || issuer.ends_with('/')
        || issuer.chars().any(char::is_whitespace)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "OIDC issuer 必须是无尾斜杠的 HTTPS 地址",
        ));
    }
    Ok(())
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
