//! 公网管理入口的边界：仅信任指定代理的单值协议头，认证请求限流，API 禁止缓存。
//! 不信任 X-Forwarded-For；同一代理后的登录共享 IP 配额，避免伪造地址绕过限流。
use crate::{unix_now, ApiError, AppState};
use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, RwLock},
};

#[derive(Clone, Copy, Default)]
/// 只由请求中间件设置，认证处理器不直接采信浏览器提供的协议头。
pub struct RequestSecurity {
    pub secure: bool,
}

#[derive(Default)]
/// 公网地址、可信代理和有界尝试计数共用一份进程状态；不同 API 使用独立的配额键。
pub struct Security {
    pub(crate) configuration: RwLock<crate::server_settings::Settings>,
    attempts: Mutex<HashMap<String, (u32, i64)>>,
}

impl Security {
    pub fn new(settings: crate::server_settings::Settings) -> Self {
        Self {
            configuration: RwLock::new(settings),
            ..Default::default()
        }
    }

    /// 每次请求只读取一份完整快照；保存设置不重置认证限流计数。
    pub fn settings(&self) -> Result<crate::server_settings::Settings, ApiError> {
        self.configuration
            .read()
            .map(|value| value.clone())
            .map_err(|_| crate::db_error("服务器设置锁不可用"))
    }

    /// 配额在校验前占用，防止并发失败请求穿透；过期条目清理且容量有界。
    pub fn allow(&self, key: String, limit: u32, now: i64) -> bool {
        let Ok(mut attempts) = self.attempts.lock() else {
            return false;
        };
        attempts.retain(|_, (_, until)| *until > now);
        if !attempts.contains_key(&key) && attempts.len() >= 4096 {
            return false;
        }
        let entry = attempts.entry(key).or_insert((0, now + 300));
        if entry.0 >= limit {
            return false;
        }
        entry.0 += 1;
        true
    }
}

pub async fn protect(
    State(state): State<AppState>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|v| v.0.ip());
    let settings = match state.security.settings() {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let secure = settings.secure(peer, request.headers());
    let path = request.uri().path();
    if path.starts_with("/api/") {
        if !settings.managed && settings.public_url.starts_with("https://") && !secure {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "管理入口要求 HTTPS，请检查可信反向代理配置",
            )
            .into_response();
        }
        if !matches!(
            *request.method(),
            axum::http::Method::GET | axum::http::Method::HEAD
        ) {
            // 浏览器跨站写入在认证前拒绝；无 Origin 的本机 CLI 仍由 Token/CSRF 验证。
            if let Some(origin) = request.headers().get(header::ORIGIN) {
                let expected = if !settings.managed && !settings.public_url.is_empty() {
                    settings.public_url.clone()
                } else {
                    format!(
                        "{}://{}",
                        if secure { "https" } else { "http" },
                        request
                            .headers()
                            .get(header::HOST)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                    )
                };
                if origin.to_str().ok() != Some(expected.as_str()) {
                    return ApiError::new(
                        StatusCode::FORBIDDEN,
                        "请求来源不匹配，请从管理入口重新打开页面",
                    )
                    .into_response();
                }
            }
        }
        if request.method() == axum::http::Method::POST
            && matches!(
                path,
                "/api/v1/auth/login"
                    | "/api/v1/auth/recover"
                    | "/api/v1/auth/invitations/inspect"
                    | "/api/v1/auth/invitations/accept"
            )
            && !state.security.allow(format!("ip:{peer:?}"), 20, unix_now())
        {
            return limited().into_response();
        }
    }
    let api = path.starts_with("/api/");
    request.extensions_mut().insert(RequestSecurity { secure });
    let mut response = next.run(request).await;
    if api {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("same-origin"));
    response
}

pub fn limited() -> ApiError {
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "尝试次数过多，请 5 分钟后重试",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    #[test]
    fn forwarded_https_requires_trusted_peer_and_single_value() {
        let security = crate::server_settings::Settings {
            trusted_proxies: vec!["127.0.0.1".parse().unwrap()],
            ..Default::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(!security.secure(Some("192.0.2.1".parse().unwrap()), &headers));
        assert!(security.secure(Some("127.0.0.1".parse().unwrap()), &headers));
        headers.append("x-forwarded-proto", HeaderValue::from_static("http"));
        assert!(!security.secure(Some("127.0.0.1".parse().unwrap()), &headers));
    }
    #[test]
    fn attempts_are_bounded_and_expire() {
        let security = Security::default();
        for _ in 0..5 {
            assert!(security.allow("account:admin".into(), 5, 100));
        }
        assert!(!security.allow("account:admin".into(), 5, 101));
        assert!(security.allow("account:admin".into(), 5, 400));
    }
}
