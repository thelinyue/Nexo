//! 公网管理入口的边界：仅信任指定代理的单值协议头，认证请求限流，API 禁止缓存。
//! 不信任 X-Forwarded-For；同一代理后的登录共享 IP 配额，避免伪造地址绕过限流。
use crate::{unix_now, ApiError, AppState};
use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
};

#[derive(Clone, Copy, Default)]
/// 只由请求中间件设置，认证处理器不直接采信浏览器提供的协议头。
pub struct RequestSecurity {
    pub secure: bool,
}

#[derive(Default)]
/// 公网地址、可信代理和有界尝试计数共用一份进程状态；不同 API 使用独立的配额键。
pub struct Security {
    pub public_origin: Option<String>,
    trusted_proxies: Vec<IpAddr>,
    attempts: Mutex<HashMap<String, (u32, i64)>>,
}

impl Security {
    pub fn from_env() -> anyhow::Result<Self> {
        let origin = std::env::var("NEXO_PUBLIC_URL")
            .ok()
            .filter(|v| !v.is_empty());
        let public_origin = origin
            .map(|value| -> anyhow::Result<String> {
                let url = reqwest::Url::parse(&value)?;
                anyhow::ensure!(
                    matches!(url.scheme(), "http" | "https")
                        && url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.path() == "/"
                        && url.query().is_none()
                        && url.fragment().is_none(),
                    "NEXO_PUBLIC_URL 必须是管理入口地址，不含账号、路径或参数"
                );
                Ok(url.origin().ascii_serialization())
            })
            .transpose()?;
        let trusted_proxies = std::env::var("NEXO_TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .filter(|v| !v.trim().is_empty())
            .map(|v| v.trim().parse())
            .collect::<Result<Vec<IpAddr>, _>>()?;
        Ok(Self {
            public_origin,
            trusted_proxies,
            ..Default::default()
        })
    }

    fn secure(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> bool {
        peer.is_some_and(|ip| self.trusted_proxies.contains(&ip))
            && headers.get_all("x-forwarded-proto").iter().count() == 1
            && headers
                .get("x-forwarded-proto")
                .is_some_and(|v| v == "https")
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
    let secure = state.security.secure(peer, request.headers());
    let path = request.uri().path();
    if path.starts_with("/api/") {
        if state
            .security
            .public_origin
            .as_ref()
            .is_some_and(|v| v.starts_with("https://"))
            && !secure
        {
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
                let expected = state.security.public_origin.clone().unwrap_or_else(|| {
                    format!(
                        "{}://{}",
                        if secure { "https" } else { "http" },
                        request
                            .headers()
                            .get(header::HOST)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                    )
                });
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
                    | "/api/v1/auth/initialize"
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
    #[test]
    fn forwarded_https_requires_trusted_peer_and_single_value() {
        let security = Security {
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
