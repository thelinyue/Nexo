//! 平台级服务器设置：数据库持久化后整体替换运行时快照，限流计数独立保留。
use crate::{accounts, auth, db_error, ApiError, AppState};
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    Extension, Json,
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// 三项设置作为整体保存；空地址和空列表表示未配置，IP 在反序列化时验证。
pub struct Settings {
    pub public_url: String,
    pub trusted_proxies: Vec<IpAddr>,
    pub public_ips: Vec<IpAddr>,
}

impl Settings {
    /// 固定管理来源只接受完整 origin；IP 使用精确地址，不支持网段和主机名。
    fn normalize(mut self) -> Result<Self, ApiError> {
        self.public_url = self.public_url.trim().to_owned();
        if !self.public_url.is_empty() {
            let message = "管理地址必须是 http:// 或 https:// 地址，不含账号、路径或参数";
            let url = reqwest::Url::parse(&self.public_url).map_err(|_| bad_input(message))?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(bad_input(message));
            }
            self.public_url = url.origin().ascii_serialization();
        }
        if self.trusted_proxies.len() > 64 || self.public_ips.len() > 64 {
            return Err(bad_input("每组 IP 地址最多填写 64 个"));
        }
        self.trusted_proxies.sort();
        self.trusted_proxies.dedup();
        self.public_ips.sort();
        self.public_ips.dedup();
        Ok(self)
    }

    pub fn secure(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> bool {
        peer.is_some_and(|ip| self.trusted_proxies.contains(&ip))
            && headers.get_all("x-forwarded-proto").iter().count() == 1
            && headers
                .get("x-forwarded-proto")
                .is_some_and(|v| v == "https")
    }
}

fn bad_input(message: &str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, message)
}

pub fn load(db: &Connection) -> anyhow::Result<Settings> {
    let stored: Option<String> = db
        .query_row("SELECT value FROM server_settings WHERE id=1", [], |r| {
            r.get(0)
        })
        .optional()?;
    let settings: Settings = stored
        .map(|value| serde_json::from_str(&value))
        .transpose()?
        .unwrap_or_default();
    settings
        .normalize()
        .map_err(|error| anyhow::anyhow!("服务器设置无效：{}", error.message))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Settings>, ApiError> {
    accounts::require_admin(&state, &headers)?;
    Ok(Json(state.security.settings()?))
}

/// 先用候选配置验证当前入口，再持久化并发布；不允许把浏览器切到尚未验证的地址。
/// 写锁覆盖数据库提交和快照替换，避免并发保存导致磁盘与内存顺序不一致。
pub async fn update(
    State(state): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    input: Result<Json<Settings>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Settings>, ApiError> {
    accounts::require_admin(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    let Json(input) = input.map_err(|error| ApiError::new(error.status(), "服务器设置格式不正确；可信代理 IP 和公网 IP 必须是 IPv4/IPv6 地址列表，不支持 CIDR 或域名"))?;
    let settings = input.normalize()?;
    let secure = settings.secure(
        peer.map(|Extension(ConnectInfo(address))| address.ip()),
        &headers,
    );
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let origin = reqwest::Url::parse(&format!(
        "{}://{host}",
        if secure { "https" } else { "http" }
    ))
    .map(|url| url.origin().ascii_serialization())
    .unwrap_or_default();
    // 即使未固定管理地址，也不能撤销当前 HTTPS 连接所需的代理信任，否则后续浏览器写入会被来源校验拒绝。
    if (!settings.public_url.is_empty() && settings.public_url != origin)
        || headers
            .get("origin")
            .is_some_and(|value| value.to_str().ok() != Some(origin.as_str()))
    {
        return Err(bad_input("请先从所填管理地址打开页面；HTTPS 入口还需填写正确的可信代理 IP，并由代理覆盖 X-Forwarded-Proto 为 https"));
    }
    let mut current = state
        .security
        .configuration
        .write()
        .map_err(|_| db_error("服务器设置锁不可用"))?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    db.execute("INSERT INTO server_settings(id,value) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
        [serde_json::to_string(&settings).map_err(db_error)?]).map_err(db_error)?;
    *current = settings.clone();
    Ok(Json(settings))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn settings_commit_before_publish_preserve_limits_and_require_admin_csrf() {
        let (state, mut headers) = crate::tests::domain_fixture();
        headers.insert("host", "127.0.0.1:8280".parse().unwrap());
        let candidate = || {
            Ok(Json(Settings {
                public_url: "http://127.0.0.1:8280/".into(),
                public_ips: vec!["203.0.113.1".parse().unwrap()],
                trusted_proxies: vec![],
            }))
        };
        assert!(state
            .security
            .allow("login:test".into(), 1, crate::unix_now()));
        let _ = update(State(state.clone()), None, headers.clone(), candidate())
            .await
            .unwrap();
        assert_eq!(
            load(&state.db.lock().unwrap()).unwrap().public_url,
            "http://127.0.0.1:8280"
        );
        assert!(!state
            .security
            .allow("login:test".into(), 1, crate::unix_now()));
        state.db.lock().unwrap().execute_batch("CREATE TRIGGER deny_settings BEFORE UPDATE ON server_settings BEGIN SELECT RAISE(ABORT,'test write failure'); END;").unwrap();
        let mut changed = candidate().unwrap().0;
        changed.public_ips.clear();
        assert!(update(
            State(state.clone()),
            None,
            headers.clone(),
            Ok(Json(changed))
        )
        .await
        .is_err());
        assert_eq!(state.security.settings().unwrap().public_ips.len(), 1);
        assert_eq!(load(&state.db.lock().unwrap()).unwrap().public_ips.len(), 1);
        let mut missing = headers.clone();
        missing.remove("x-nexo-csrf");
        assert_eq!(
            update(State(state.clone()), None, missing, candidate())
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE users SET role='tenant'", [])
            .unwrap();
        assert_eq!(
            get(State(state.clone()), headers.clone())
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            update(State(state), None, headers, candidate())
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
    }
}
