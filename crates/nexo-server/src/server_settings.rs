//! 管理入口与内置 Caddy 共用持久配置；旧入口规则仅在管理员显式保存后切换。
use crate::{accounts, auth, db_error, ApiError, AppState};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// 管理入口只引用已验证域名；独立于服务和管理员当前代管的工作空间。
pub struct ManagementEntry {
    pub domain_id: String,
    pub hostname: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
/// 保留旧字段用于安全读取既有配置；managed 区分显式保存的新模式和旧强制入口。
pub struct Settings {
    pub public_url: String,
    pub trusted_proxies: Vec<IpAddr>,
    pub public_ips: Vec<IpAddr>,
    pub management_entry: Option<ManagementEntry>,
    pub managed: bool,
}

impl Settings {
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
        let managed_host = !self.managed
            || (self.management_entry.is_some()
                && headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|host| self.public_url == format!("https://{host}")));
        managed_host
            && peer.is_some_and(|ip| self.trusted_proxies.contains(&ip))
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
        .map_err(|e| anyhow::anyhow!("服务器设置无效：{}", e.message))
}

/// 启动监听地址改变时重新计算自动信任；不让上次保存的端口或地址决定本次回源。
pub fn load_for_runtime(db: &Connection, http_addr: SocketAddr) -> anyhow::Result<Settings> {
    let mut settings = load(db)?;
    if settings.managed {
        settings.trusted_proxies = if settings.management_entry.is_some() {
            vec![upstream(http_addr).ip()]
        } else {
            vec![]
        };
    }
    Ok(settings)
}

pub fn upstream(mut address: SocketAddr) -> SocketAddr {
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() {
            IpAddr::from([127, 0, 0, 1])
        } else {
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        });
    }
    address
}

pub fn ensure_host_available(db: &Connection, hostname: &str) -> Result<(), ApiError> {
    let settings = load(db).map_err(db_error)?;
    if settings.management_entry.is_some() && settings.public_url == format!("https://{hostname}") {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "此域名已用于管理入口，请先更换或关闭管理入口",
        ));
    }
    Ok(())
}

pub fn ensure_domain_unused(db: &Connection, id: &str) -> Result<(), ApiError> {
    if load(db)
        .map_err(db_error)?
        .management_entry
        .is_some_and(|entry| entry.domain_id == id)
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "此域名正用于管理入口，请先更换或关闭管理入口",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub management_entry: Option<ManagementEntry>,
    #[serde(default)]
    pub public_ips: Vec<IpAddr>,
}
#[derive(Debug, Serialize)]
pub struct DomainChoice {
    id: String,
    domain: String,
}
#[derive(Debug, Serialize)]
pub struct Response {
    management_entry: Option<ManagementEntry>,
    public_url: String,
    public_ips: Vec<IpAddr>,
    domains: Vec<DomainChoice>,
    caddy_enabled: bool,
    status: &'static str,
    error: Option<String>,
}

fn response(state: &AppState, tenant: &str) -> Result<Response, ApiError> {
    let settings = state.security.settings()?;
    let domains = {
        let db = state.db.lock().map_err(db_error)?;
        let mut query = db.prepare("SELECT p.id,p.domain FROM public_domains p JOIN domain_settings s ON s.domain_id=p.id WHERE p.tenant_id=?1 AND p.https_enabled=1 AND s.verified=1 ORDER BY p.domain").map_err(db_error)?;
        let rows = query
            .query_map([tenant], |r| {
                Ok(DomainChoice {
                    id: r.get(0)?,
                    domain: r.get(1)?,
                })
            })
            .map_err(db_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db_error)?;
        rows
    };
    let enabled = state.domain_runtime.supervisor.config().enabled;
    let mut status = "disabled";
    let mut error = None;
    if let Some(entry) = &settings.management_entry {
        let runtime = state.domain_runtime.status(&entry.domain_id);
        let host = settings.public_url.trim_start_matches("https://");
        let target = format!("http://{}", upstream(state.config.http_addr));
        let certificate = runtime.certificates.iter().find(|cert| {
            cert.hostname == host
                || cert.hostname.strip_prefix("*.").is_some_and(|suffix| {
                    host.split_once('.').is_some_and(|(_, rest)| rest == suffix)
                })
        });
        if !enabled {
            status = "failed";
            error = Some("内置 Caddy 未启用，请修改启动配置".into());
        } else if let Some(message) = runtime.config_error {
            status = "failed";
            error = Some(message);
        } else if runtime.config_status != "applied"
            || runtime.loaded_routes.get(&settings.public_url) != Some(&target)
        {
            status = "pending";
        } else if certificate.is_some_and(|cert| {
            cert.not_before.is_some_and(|t| t <= crate::unix_now())
                && cert.expires_at.is_some_and(|t| t > crate::unix_now())
        }) {
            status = "ready";
        } else {
            status = "certificate_pending";
            error = certificate.and_then(|cert| cert.error.clone());
        }
    }
    Ok(Response {
        management_entry: settings.management_entry,
        public_url: settings.public_url,
        public_ips: settings.public_ips,
        domains,
        caddy_enabled: enabled,
        status,
        error,
    })
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Response>, ApiError> {
    let session = accounts::require_admin(&state, &headers)?;
    response(&state, &session.tenant_id).map(Json)
}

/// 可从 HTTP 原入口保存。配置落库与内存发布保持一致，证书和路由由现有 Caddy 协调器异步收敛。
pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    input: Result<Json<Input>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Response>, ApiError> {
    let session = accounts::require_admin(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    let Json(input) = input.map_err(|e| {
        ApiError::new(
            e.status(),
            "设置格式不正确；公网 IP 必须是 IPv4/IPv6 地址列表",
        )
    })?;
    let _guard = state.domain_runtime.reconcile_lock.lock().await;
    {
        // 和旧实现保持相同锁顺序：运行设置写锁先于数据库锁。
        let mut current = state.security.configuration.write().map_err(db_error)?;
        let db = state.db.lock().map_err(db_error)?;
        let tx = db.unchecked_transaction().map_err(db_error)?;
        let mut settings = Settings {
            managed: true,
            public_ips: input.public_ips,
            management_entry: input.management_entry,
            ..Default::default()
        };
        if let Some(entry) = &mut settings.management_entry {
            if !state.domain_runtime.supervisor.config().enabled {
                return Err(bad_input("请先在启动配置中启用内置 Caddy"));
            }
            let domain: String = tx.query_row("SELECT p.domain FROM public_domains p JOIN domain_settings s ON s.domain_id=p.id WHERE p.id=?1 AND p.tenant_id=?2 AND p.https_enabled=1 AND s.verified=1", params![entry.domain_id, session.tenant_id], |r| r.get(0)).optional().map_err(db_error)?.ok_or_else(|| bad_input("请选择自己空间内已验证并启用 HTTPS 的域名"))?;
            let options = crate::domains::load(&tx, &entry.domain_id, &domain)?;
            if options.certificate_mode == "cloudflare_dns" && !options.credential_configured {
                return Err(bad_input(
                    "请先配置域名的 Cloudflare 凭据，或选择 HTTP 验证",
                ));
            }
            entry.hostname = entry.hostname.trim().to_ascii_lowercase();
            if entry.hostname.is_empty() || entry.hostname.contains('.') {
                return Err(bad_input("请输入单层子域名，例如 nexo"));
            }
            let host = crate::normalize_domain(&format!("{}.{}", entry.hostname, domain))?;
            entry.hostname = host
                .strip_suffix(&format!(".{domain}"))
                .ok_or_else(|| bad_input("子域名无效"))?
                .into();
            if entry.hostname.contains('.') {
                return Err(bad_input("请输入单层子域名，例如 nexo"));
            }
            let occupied: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM tunnels t JOIN public_domains p ON p.id=t.public_domain_id WHERE t.deleted_at IS NULL AND t.hostname||'.'||p.domain=?1) OR EXISTS(SELECT 1 FROM public_domains WHERE domain=?1)", [&host], |r| r.get(0)).map_err(db_error)?;
            if occupied {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "此地址已被服务或域名使用，请选择其他子域名",
                ));
            }
            settings.public_url = format!("https://{host}");
            settings.trusted_proxies = vec![upstream(state.config.http_addr).ip()];
        }
        let settings = settings.normalize()?;
        tx.execute("INSERT INTO server_settings(id,value) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET value=excluded.value", [serde_json::to_string(&settings).map_err(db_error)?]).map_err(db_error)?;
        accounts::audit(&tx, &session, "server_settings_updated", "server", "1")?;
        tx.commit().map_err(db_error)?;
        *current = settings;
    }
    let sync_error = crate::domain_runtime::reconcile_locked(&state).await.err();
    let mut result = response(&state, &session.tenant_id)?;
    if let Some(error) = sync_error {
        tracing::error!("管理入口配置已保存，Caddy 同步失败：{error:#}");
        result.status = "failed";
        result.error = Some("配置已保存，Caddy 同步失败，将自动重试".into());
    }
    Ok(Json(result))
}

#[cfg(test)]
#[path = "server_settings_tests.rs"]
mod tests;
