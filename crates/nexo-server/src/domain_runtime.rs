//! Caddy 与域名管理的连接层：配置由数据库生成，证书只读取 Caddy 的日志和公开证书文件。
//! 不实现 ACME 客户端，不自行调度续期或重试，也不把配置加载成功当作穿透服务可访问。

use crate::{
    caddy::{self, CaddyRuntimeConfig, CaddySupervisor},
    unix_now, AppState,
};
use anyhow::{Context, Result};
use rusqlite::params;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use x509_parser::{extensions::GeneralName, pem::parse_x509_pem};

#[derive(Debug, Clone, Serialize)]
pub struct CertificateStatus {
    pub hostname: String,
    pub status: String,
    pub not_before: Option<i64>,
    pub expires_at: Option<i64>,
    pub error: Option<String>,
    pub next_retry_at: Option<i64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct DomainRuntime {
    pub config_status: String,
    pub config_error: Option<String>,
    pub service_warning: Option<String>,
    pub checked_at: Option<i64>,
    pub certificates: Vec<CertificateStatus>,
    #[serde(skip)]
    pub loaded_routes: HashMap<String, String>,
}
impl DomainRuntime {
    pub fn pending(enabled: bool) -> Self {
        Self {
            config_status: if enabled { "pending" } else { "disabled" }.into(),
            config_error: None,
            service_warning: None,
            checked_at: None,
            certificates: Vec::new(),
            loaded_routes: HashMap::new(),
        }
    }
}

/// 仅保存本次进程观测到的运行状态；重启后重新从 Caddy 查询，不沿用数据库中的旧成功标记。
pub struct DomainRuntimeManager {
    pub supervisor: Arc<CaddySupervisor>,
    statuses: Mutex<HashMap<String, DomainRuntime>>,
    /// 配置快照、删除和凭据回收共用协调锁，禁止把删除前的快照重新加载。
    pub(crate) reconcile_lock: tokio::sync::Mutex<()>,
}
impl DomainRuntimeManager {
    pub fn new(config: CaddyRuntimeConfig) -> Self {
        Self {
            supervisor: Arc::new(CaddySupervisor::new(config)),
            statuses: Mutex::new(HashMap::new()),
            reconcile_lock: tokio::sync::Mutex::new(()),
        }
    }
    pub fn status(&self, id: &str) -> DomainRuntime {
        self.statuses
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .cloned()
            .unwrap_or_else(|| DomainRuntime::pending(self.supervisor.config().enabled))
    }
    pub async fn run(state: AppState) {
        let startup_guard = state.domain_runtime.reconcile_lock.lock().await;
        let supervisor = state.domain_runtime.supervisor.clone();
        let start = build_config(supervisor.config(), &[])
            .and_then(|config| supervisor.write_startup_config(&config));
        if let Err(error) = start {
            supervisor.record_process_error(&format!("{error:#}")).await;
            tracing::error!("Caddy 启动配置无效：{error:#}");
        } else if let Err(error) = supervisor.clone().start().await {
            supervisor.record_process_error(&format!("{error:#}")).await;
            tracing::error!("Caddy 启动失败：{error:#}");
        }
        drop(startup_guard);
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            if let Err(error) = reconcile(&state).await {
                tracing::error!("读取 Caddy 域名配置失败：{error:#}");
            }
        }
    }
}

#[derive(Debug, Clone)]
struct DomainSpec {
    id: String,
    tenant_id: String,
    name: String,
    https: bool,
    token_reference: Option<String>,
    certificate_mode: String,
    dns: crate::domains::DnsSettings,
    services: Vec<WebService>,
}
#[derive(Debug, Clone)]
struct WebService {
    hostname: String,
    protocol: String,
    upstream: Option<String>,
}
impl DomainSpec {
    fn subjects(&self) -> Vec<String> {
        if !self.https {
            return Vec::new();
        }
        if self.certificate_mode == "http01" {
            let mut hosts = vec![self.name.clone()];
            hosts.extend(
                self.services
                    .iter()
                    .filter(|s| s.protocol == "https")
                    .map(|s| s.hostname.clone()),
            );
            hosts.sort();
            hosts.dedup();
            return hosts;
        }
        // 根域名不能由泛域名覆盖；子域名按父域共享证书，缺少 DNS 凭据也不回退单域名签发。
        let mut hosts = vec![self.name.clone(), format!("*.{}", self.name)];
        hosts.extend(
            self.services
                .iter()
                .filter(|service| service.protocol == "https")
                .filter_map(|service| service.hostname.split_once('.'))
                .map(|(_, parent)| format!("*.{parent}")),
        );
        hosts.sort();
        hosts.dedup();
        hosts
    }
}

fn specifications(
    state: &AppState,
    upstreams: &HashMap<String, String>,
) -> Result<Vec<DomainSpec>> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let settings = state.domain_runtime.supervisor.config();
    let tokens = caddy::read_domain_tokens(&settings.cloudflare_token_root);
    let global_dns = std::env::var("NEXO_CLOUDFLARE_API_TOKEN").is_ok_and(|v| !v.trim().is_empty());
    let mut query = connection.prepare(
        "SELECT p.id,p.tenant_id,p.domain,p.https_enabled FROM public_domains p JOIN tenants w ON w.id=p.tenant_id LEFT JOIN domain_settings s ON s.domain_id=p.id WHERE w.enabled=1 AND COALESCE(s.verified,1)=1 ORDER BY p.domain,p.id",
    )?;
    let mut domains = query
        .query_map([], |row| {
            Ok(DomainSpec {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                name: row.get(2)?,
                https: row.get::<_, i64>(3)? != 0,
                token_reference: None,
                certificate_mode: "cloudflare_dns".into(),
                dns: crate::domains::DnsSettings::default(),
                services: Vec::new(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for domain in &mut domains {
        let options = crate::domains::load(&connection, &domain.id, &domain.name)
            .map_err(|e| anyhow::anyhow!(e.message))?;
        domain.certificate_mode = options.certificate_mode;
        domain.dns = options.dns;
        if domain.certificate_mode == "cloudflare_dns" {
            let path = if let Some(file) = options.credential_file {
                Some(crate::domains::credential_path(
                    &settings.cloudflare_token_root,
                    &domain.id,
                    &file,
                )?)
            } else {
                let own = tokens
                    .iter()
                    .find(|(id, _)| id == &domain.id)
                    .map(|(_, token)| token.clone());
                let admin: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM users WHERE tenant_id=?1 AND role='system_admin')",
                    [&domain.tenant_id],
                    |r| r.get(0),
                )?;
                let legacy = own.or_else(|| {
                    (options.legacy && admin && global_dns)
                        .then(|| std::env::var("NEXO_CLOUDFLARE_API_TOKEN").unwrap_or_default())
                });
                legacy
                    .map(|token| {
                        caddy::snapshot_token(&settings.cloudflare_token_root, &domain.id, &token)
                    })
                    .transpose()?
            };
            domain.token_reference = path.map(|path| format!("{{file.{}}}", path.display()));
        }
        let mut services = connection.prepare("SELECT id,hostname,protocol FROM tunnels WHERE public_domain_id=?1 AND tenant_id=?2 AND enabled=1 AND deleted_at IS NULL AND protocol IN ('http','https')")?;
        domain.services = services
            .query_map(params![domain.id, domain.tenant_id], |row| {
                let id: String = row.get(0)?;
                let hostname: Option<String> = row.get(1)?;
                Ok(WebService {
                    hostname: format!("{}.{}", hostname.unwrap_or_default(), domain.name),
                    protocol: row.get(2)?,
                    upstream: upstreams.get(&id).cloned(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
    }
    Ok(domains)
}

fn admin_listen(settings: &CaddyRuntimeConfig) -> Result<String> {
    let url = reqwest::Url::parse(&settings.admin_url)?;
    let ip: IpAddr = url
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .parse()
        .context("Caddy 管理接口必须使用本机回环 IP")?;
    anyhow::ensure!(
        ip.is_loopback()
            && url.scheme() == "http"
            && url.username().is_empty()
            && url.password().is_none()
            && matches!(url.path(), "" | "/")
            && url.query().is_none(),
        "Caddy 管理接口只允许本机回环 HTTP 地址"
    );
    Ok(SocketAddr::new(ip, url.port_or_known_default().unwrap_or(8290)).to_string())
}

/// 只发布显式域名；未知主机返回 404。没有可信 Tunnel socket 时明确返回 503，不连接 Agent 的私网地址。
fn build_config(settings: &CaddyRuntimeConfig, domains: &[DomainSpec]) -> Result<Value> {
    let mut http = Vec::new();
    let mut https = Vec::new();
    let mut subjects = Vec::new();
    let mut policies = Vec::new();
    let mut claimed = HashSet::new();
    for domain in domains {
        anyhow::ensure!(
            crate::normalize_domain(&domain.name).is_ok(),
            "域名格式无效，请修改域名配置"
        );
        anyhow::ensure!(
            claimed.insert(domain.name.clone()),
            "存在重复的公网域名，请检查域名配置"
        );
        let root_route = json!({"match":[{"host":[domain.name]}],"handle":[{"handler":"static_response","status_code":404}]});
        if domain.https {
            https.push(root_route);
        } else {
            http.push(root_route);
        }
        for service in &domain.services {
            anyhow::ensure!(
                crate::normalize_domain(&service.hostname).is_ok()
                    && claimed.insert(service.hostname.clone()),
                "服务主机名无效或重复，请检查服务配置"
            );
            if service.protocol == "https" && !domain.https {
                continue;
            }
            let handler = if let Some(upstream) = &service.upstream {
                json!({"handler":"reverse_proxy","upstreams":[{"dial":upstream}],"stream_close_delay":300000000000_u64})
            } else {
                json!({"handler":"static_response","status_code":503,"body":"服务转发通道尚未就绪"})
            };
            let route = json!({"match":[{"host":[service.hostname]}],"handle":[handler]});
            if service.protocol == "https" {
                https.push(route);
            } else {
                http.push(route);
            }
        }
        let domain_subjects = domain.subjects();
        if !domain_subjects.is_empty() {
            if domain.certificate_mode == "http01" {
                policies.push(json!({"subjects":domain_subjects,"issuers":[{"module":"acme","challenges":{"tls-alpn":{"disabled":true}}}]}));
            } else if let Some(token) = &domain.token_reference {
                let mut dns = json!({"provider":{"name":"cloudflare","api_token":token}});
                if !domain.dns.dns_resolvers.is_empty() {
                    dns["resolvers"] = json!(domain.dns.dns_resolvers);
                }
                if let Some(seconds) = domain.dns.dns_propagation_delay_seconds {
                    dns["propagation_delay"] = json!(u64::from(seconds) * 1_000_000_000);
                }
                if let Some(seconds) = domain.dns.dns_propagation_timeout_seconds {
                    dns["propagation_timeout"] = json!(u64::from(seconds) * 1_000_000_000);
                }
                policies.push(json!({"subjects":domain_subjects,"issuers":[{"module":"acme","challenges":{"dns":dns}}]}));
            }
            subjects.extend(domain_subjects);
        }
    }
    // Caddy 无匹配路由时默认返回空的 200；显式兜底，避免未知域名被误认为服务正常。
    let not_found = json!({"handle":[{"handler":"static_response","status_code":404}]});
    http.push(not_found.clone());
    if !https.is_empty() {
        https.push(not_found);
    }
    let mut servers = serde_json::Map::new();
    if !domains.is_empty() {
        servers.insert("http".into(),json!({"listen":[settings.http_listen],"automatic_https":{"disable":true},"routes":http}));
    }
    if !https.is_empty() {
        // 仅由 tls.certificates.automate 管理根域名和泛域名；关闭从路由发现证书的入口，
        // 防止新增服务或缺少 DNS 凭据时为具体子域名单独签发。续期和重试仍由 Caddy 执行。
        servers.insert("https".into(),json!({"listen":[settings.https_listen],"automatic_https":{"disable":true},"routes":https,"tls_connection_policies":[{}]}));
    }
    let mut config = json!({"admin":{"listen":admin_listen(settings)?},"storage":{"module":"file_system","root":settings.storage_root},"apps":{"http":{"servers":servers},"pki":{"certificate_authorities":{"local":{"install_trust":false}}}}});
    if !subjects.is_empty() {
        config["apps"]["tls"] =
            json!({"certificates":{"automate":subjects},"automation":{"policies":policies}});
    }
    Ok(config)
}
async fn reconcile(state: &AppState) -> Result<()> {
    let _guard = state.domain_runtime.reconcile_lock.lock().await;
    reconcile_locked(state).await.map(|_| ())
}

/// 调用方必须持有 reconcile_lock；返回 false 表示配置或专属凭据仍待下一轮清理。
pub(crate) async fn reconcile_locked(state: &AppState) -> Result<bool> {
    let upstreams = state.tunnel_runtime.web_upstreams().await;
    let specs = specifications(state, &upstreams)?;
    let manager = &state.domain_runtime;
    let supervisor = &manager.supervisor;
    let settings = supervisor.config();
    if !settings.enabled {
        let mut statuses = manager.statuses.lock().unwrap_or_else(|p| p.into_inner());
        *statuses = specs
            .iter()
            .map(|d| (d.id.clone(), DomainRuntime::pending(false)))
            .collect();
        drop(statuses);
        cleanup_deleted_credentials(state, &Value::Null)?;
        return Ok(true);
    }
    let desired = build_config(settings, &specs);
    let config_result = match desired {
        Ok(config) => match supervisor.current_config().await {
            Ok(current)
                if current == config && !supervisor.credentials_changed(&config).await? =>
            {
                Ok(())
            }
            Ok(_) => supervisor.apply_json(&config).await,
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    let config_error = config_result
        .err()
        .map(|e| caddy::redact(&format!("{e:#}"), &settings.cloudflare_token_root));
    let cleanup_complete = if config_error.is_none() {
        // 再读实际配置；只有运行配置与持久化配置都不再引用时，才能删除凭据。
        let current = supervisor.current_config().await?;
        match cleanup_deleted_credentials(state, &current) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!("已删除域名的凭据尚未清理，将自动重试：{error:#}");
                false
            }
        }
    } else {
        false
    };
    let now = unix_now();
    let events = supervisor.drain_log_events().await;
    let metadata = read_certificates(&settings.storage_root);
    let mut statuses = manager.statuses.lock().unwrap_or_else(|p| p.into_inner());
    statuses.retain(|id, _| specs.iter().any(|s| &s.id == id));
    for domain in &specs {
        let config_error = config_error
            .as_deref()
            .map(|error| tenant_error(error, &specs, &domain.tenant_id));
        let runtime = statuses
            .entry(domain.id.clone())
            .or_insert_with(|| DomainRuntime::pending(true));
        let next_status = if config_error.is_some() {
            "failed"
        } else {
            "applied"
        };
        if runtime.config_status != next_status || runtime.config_error != config_error {
            save_event(
                state,
                domain,
                &format!(
                    "配置{}{}",
                    if config_error.is_some() {
                        "加载失败："
                    } else {
                        "已加载"
                    },
                    config_error.as_deref().unwrap_or("")
                ),
                now,
            )?;
        }
        runtime.config_status = next_status.into();
        runtime.config_error = config_error.clone();
        runtime.loaded_routes = if config_error.is_none() {
            domain
                .services
                .iter()
                .filter(|service| service.protocol != "https" || domain.https)
                .filter_map(|service| {
                    service.upstream.as_ref().map(|upstream| {
                        (
                            format!("{}://{}", service.protocol, service.hostname),
                            upstream.clone(),
                        )
                    })
                })
                .collect()
        } else {
            HashMap::new()
        };
        runtime.checked_at = Some(now);
        runtime.service_warning = domain
            .services
            .iter()
            .any(|s| s.upstream.is_none())
            .then(|| "服务转发通道尚未就绪；证书状态不代表服务可访问。".into());
        let subjects = domain.subjects();
        runtime
            .certificates
            .retain(|c| subjects.contains(&c.hostname));
        for host in subjects {
            if !runtime.certificates.iter().any(|c| c.hostname == host) {
                runtime.certificates.push(CertificateStatus {
                    hostname: host,
                    status: "pending".into(),
                    not_before: None,
                    expires_at: None,
                    error: None,
                    next_retry_at: None,
                });
            }
        }
        for event in &events {
            if event
                .logger
                .as_deref()
                .is_some_and(|name| !name.starts_with("tls") && !name.starts_with("http.acme"))
            {
                continue;
            }
            let Some(cert) = runtime
                .certificates
                .iter_mut()
                .find(|c| event.identifier.as_deref() == Some(&c.hostname))
            else {
                continue;
            };
            let Some(stage) = event.certificate_stage() else {
                continue;
            };
            cert.status = stage.into();
            let message = tenant_error(&event.message, &specs, &domain.tenant_id);
            cert.error = matches!(stage, "failed" | "retry_wait").then(|| message.clone());
            let occurred_at = event.occurred_at.unwrap_or(now);
            cert.next_retry_at = event
                .retry_after_secs
                .map(|delay| occurred_at.saturating_add(delay.min(i64::MAX as u64) as i64));
            save_event(
                state,
                domain,
                &format!("{}：{}", cert.hostname, message),
                occurred_at,
            )?;
        }
        for cert in &mut runtime.certificates {
            let found = metadata
                .iter()
                .filter(|m| m.subjects.iter().any(|s| covers(s, &cert.hostname)))
                .max_by_key(|m| m.expires_at);
            observe_certificate(cert, found, now);
        }
    }
    Ok(cleanup_complete)
}

/// 孤立的域名凭据目录本身就是重试依据，重启后继续扫描；不新增清理任务表。
fn cleanup_deleted_credentials(state: &AppState, current: &Value) -> Result<()> {
    let settings = state.domain_runtime.supervisor.config();
    if !settings.cloudflare_token_root.exists() {
        return Ok(());
    }
    let root = fs::canonicalize(&settings.cloudflare_token_root)?;
    let mut configs = vec![current.clone()];
    for path in [&settings.applied_path, &settings.config_path] {
        match fs::read(path) {
            Ok(bytes) => configs.push(
                serde_json::from_slice(&bytes).context("无法确认 Caddy 旧配置引用，保留凭据")?,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let mut pending = false;
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let id = entry.file_name().to_string_lossy().into_owned();
        if uuid::Uuid::parse_str(&id).is_err() || !entry.file_type()?.is_dir() {
            continue;
        }
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM public_domains WHERE id=?1)",
            [&id],
            |r| r.get(0),
        )?;
        if exists {
            continue;
        }
        let directory = fs::canonicalize(entry.path())?;
        anyhow::ensure!(
            directory.parent() == Some(root.as_path()),
            "凭据目录超出允许清理的范围"
        );
        if configs
            .iter()
            .any(|config| references_credentials(config, &directory))
        {
            pending = true;
            continue;
        }
        fs::remove_dir_all(directory).context("无法删除已失效的域名凭据目录")?;
    }
    anyhow::ensure!(!pending, "Caddy 旧配置仍引用已删除域名的凭据，暂时保留");
    Ok(())
}

fn references_credentials(value: &Value, directory: &Path) -> bool {
    match value {
        Value::String(value) => value
            .strip_prefix("{file.")
            .and_then(|v| v.strip_suffix('}'))
            .and_then(|v| Path::new(v).parent())
            .and_then(|p| fs::canonicalize(p).ok())
            .is_some_and(|parent| parent == directory),
        Value::Array(values) => values.iter().any(|v| references_credentials(v, directory)),
        Value::Object(values) => values
            .values()
            .any(|v| references_credentials(v, directory)),
        _ => false,
    }
}

/// Caddy 共用一个配置；全局加载错误不能把其他工作空间的域名带入当前账号的诊断。
fn tenant_error(error: &str, specs: &[DomainSpec], tenant_id: &str) -> String {
    let mut names = specs
        .iter()
        .filter(|domain| domain.tenant_id != tenant_id)
        .flat_map(|domain| {
            std::iter::once(domain.name.as_str()).chain(
                domain
                    .services
                    .iter()
                    .map(|service| service.hostname.as_str()),
            )
        })
        .collect::<Vec<_>>();
    names.sort_by_key(|name| std::cmp::Reverse(name.len()));
    names.into_iter().fold(error.to_owned(), |message, name| {
        message.replace(name, "[其他工作空间域名]")
    })
}
fn observe_certificate(
    cert: &mut CertificateStatus,
    found: Option<&CertificateMetadata>,
    now: i64,
) {
    if let Some(found) = found {
        if cert
            .expires_at
            .is_some_and(|previous| found.expires_at > previous)
        {
            cert.status = "issued".into();
            cert.error = None;
            cert.next_retry_at = None;
        }
        cert.not_before = Some(found.not_before);
        cert.expires_at = Some(found.expires_at);
        // 已有证书与续期失败可以同时存在，保留续期错误和 Caddy 给出的重试时间。
        if found.expires_at <= now {
            cert.status = "expired".into();
        } else if found.not_before > now {
            cert.status = "not_yet_valid".into();
        } else if !matches!(cert.status.as_str(), "renewing" | "failed" | "retry_wait") {
            cert.status = "issued".into();
        }
    } else {
        cert.not_before = None;
        cert.expires_at = None;
        if cert.status == "issued" {
            cert.status = "pending".into();
        }
    }
}

fn save_event(state: &AppState, domain: &DomainSpec, summary: &str, now: i64) -> Result<()> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    connection.execute("INSERT INTO public_domain_runtime_events (tenant_id,public_domain_id,summary,occurred_at) VALUES (?1,?2,?3,?4)", params![domain.tenant_id, domain.id, summary, now])?;
    // 每个域名保留最近 100 条公开诊断，避免自动续期日志无限增长。
    connection.execute("DELETE FROM public_domain_runtime_events WHERE public_domain_id=?1 AND id NOT IN (SELECT id FROM public_domain_runtime_events WHERE public_domain_id=?1 ORDER BY id DESC LIMIT 100)", params![domain.id])?;
    Ok(())
}
#[derive(Debug)]
struct CertificateMetadata {
    subjects: Vec<String>,
    not_before: i64,
    expires_at: i64,
}
fn covers(subject: &str, hostname: &str) -> bool {
    subject == hostname
        || subject.strip_prefix("*.").is_some_and(|suffix| {
            hostname
                .split_once('.')
                .is_some_and(|(_, rest)| rest == suffix)
        })
}
/// 只扫描公开证书，不读取私钥；拒绝跟随符号链接，避免越过 Caddy storage。
fn read_certificates(root: &Path) -> Vec<CertificateMetadata> {
    let mut paths = vec![root.join("certificates")];
    let mut result = Vec::new();
    while let Some(path) = paths.pop() {
        let Ok(entries) = fs::read_dir(path) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                paths.push(entry.path());
                continue;
            }
            if entry.path().extension().and_then(|v| v.to_str()) != Some("crt") {
                continue;
            }
            let Ok(bytes) = fs::read(entry.path()) else {
                continue;
            };
            let Ok((_, pem)) = parse_x509_pem(&bytes) else {
                continue;
            };
            let Ok(cert) = pem.parse_x509() else {
                continue;
            };
            let subjects = cert
                .subject_alternative_name()
                .ok()
                .flatten()
                .map(|san| {
                    san.value
                        .general_names
                        .iter()
                        .filter_map(|name| {
                            if let GeneralName::DNSName(value) = name {
                                Some(value.to_ascii_lowercase())
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            result.push(CertificateMetadata {
                subjects,
                not_before: cert.validity().not_before.timestamp(),
                expires_at: cert.validity().not_after.timestamp(),
            });
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn settings(root: &Path) -> CaddyRuntimeConfig {
        CaddyRuntimeConfig {
            binary: PathBuf::from("caddy"),
            config_path: root.join("config.json"),
            applied_path: root.join("applied.json"),
            cloudflare_token_root: root.join("tokens"),
            storage_root: root.join("storage"),
            admin_url: "http://127.0.0.1:8290".into(),
            enabled: true,
            http_listen: ":80".into(),
            https_listen: ":443".into(),
        }
    }
    fn domain() -> DomainSpec {
        DomainSpec {
            id: "d".into(),
            tenant_id: "default".into(),
            name: "example.com".into(),
            https: true,
            token_reference: None,
            certificate_mode: "cloudflare_dns".into(),
            dns: crate::domains::DnsSettings::default(),
            services: vec![WebService {
                hostname: "nas.example.com".into(),
                protocol: "https".into(),
                upstream: None,
            }],
        }
    }
    #[test]
    fn routes_share_wildcard_without_dns_credentials_and_do_not_fake_a_working_tunnel() {
        let cfg = build_config(&settings(Path::new("test")), &[domain()]).unwrap();
        assert_eq!(cfg["admin"]["listen"], "127.0.0.1:8290");
        assert_eq!(
            cfg["apps"]["tls"]["certificates"]["automate"],
            json!(["*.example.com", "example.com"])
        );
        assert_eq!(
            cfg["apps"]["http"]["servers"]["https"]["automatic_https"]["disable"],
            true
        );
        assert_eq!(
            cfg["apps"]["http"]["servers"]["https"]["routes"][1]["handle"][0]["status_code"],
            503
        );
        assert!(!cfg.to_string().contains("mesh."));
        assert!(!cfg.to_string().contains("local_address"));
        assert_eq!(
            cfg["apps"]["pki"]["certificate_authorities"]["local"]["install_trust"],
            false
        );
    }
    #[test]
    fn dns_credentials_remain_placeholders_and_http_only_has_no_certificates() {
        let mut d = domain();
        d.token_reference = Some("{env.NEXO_CLOUDFLARE_TOKEN_D}".into());
        let cfg = build_config(&settings(Path::new("test")), &[d.clone()]).unwrap();
        assert_eq!(
            cfg["apps"]["tls"]["certificates"]["automate"],
            json!(["*.example.com", "example.com"])
        );
        assert_eq!(
            cfg["apps"]["http"]["servers"]["https"]["automatic_https"]["disable"],
            true
        );
        assert_eq!(
            cfg["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["challenges"]["dns"]
                ["provider"]["api_token"],
            "{env.NEXO_CLOUDFLARE_TOKEN_D}"
        );
        assert_eq!(
            cfg["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["challenges"]["dns"]
                ["resolvers"],
            json!(["223.5.5.5:53", "223.6.6.6:53"])
        );
        d.https = false;
        let cfg = build_config(&settings(Path::new("test")), &[d]).unwrap();
        assert!(cfg["apps"]["tls"].is_null());
        assert!(cfg["apps"]["http"]["servers"]["https"].is_null());
    }
    #[test]
    fn sibling_services_reuse_wildcards_at_each_domain_level() {
        let mut d = domain();
        d.services.extend([
            WebService {
                hostname: "media.example.com".into(),
                protocol: "https".into(),
                upstream: None,
            },
            WebService {
                hostname: "a.team.example.com".into(),
                protocol: "https".into(),
                upstream: None,
            },
            WebService {
                hostname: "b.team.example.com".into(),
                protocol: "https".into(),
                upstream: None,
            },
            WebService {
                hostname: "a.http-only.example.com".into(),
                protocol: "http".into(),
                upstream: None,
            },
        ]);
        // 无凭据和有凭据的证书范围一致，不能回退为逐个服务签发。
        for token in [None, Some("{env.NEXO_CLOUDFLARE_TOKEN_D}".into())] {
            d.token_reference = token;
            let cfg = build_config(&settings(Path::new("test")), &[d.clone()]).unwrap();
            assert_eq!(
                cfg["apps"]["tls"]["certificates"]["automate"],
                json!(["*.example.com", "*.team.example.com", "example.com"])
            );
            for service in d
                .services
                .iter()
                .filter(|service| service.protocol == "https")
            {
                assert!(d
                    .subjects()
                    .iter()
                    .any(|subject| covers(subject, &service.hostname)));
                assert!(!d.subjects().contains(&service.hostname));
            }
            let subjects = d.subjects();
            d.services.push(WebService {
                hostname: "next.team.example.com".into(),
                protocol: "https".into(),
                upstream: None,
            });
            assert_eq!(d.subjects(), subjects);
            d.services.pop();
        }
    }
    #[test]
    fn config_rejects_external_admin_and_conflicting_hosts() {
        let mut cfg = settings(Path::new("test"));
        cfg.admin_url = "http://0.0.0.0:8290".into();
        assert!(build_config(&cfg, &[]).is_err());
        cfg.admin_url = "http://127.0.0.1:8290".into();
        assert!(build_config(&cfg, &[domain(), domain()]).is_err());
        assert!(!covers("*.example.com", "a.b.example.com"));
        assert!(covers("*.example.com", "nas.example.com"));
        let mut other = domain();
        other.tenant_id = "other".into();
        let public = tenant_error(
            "配置错误：nas.example.com / example.com",
            &[other],
            "default",
        );
        assert!(!public.contains("example.com"));
    }
    #[test]
    fn expiry_and_renewal_failures_are_independent_and_new_certificate_clears_old_error() {
        let mut cert = CertificateStatus {
            hostname: "example.com".into(),
            status: "retry_wait".into(),
            error: Some("CA 限流".into()),
            next_retry_at: Some(150),
            not_before: Some(1),
            expires_at: Some(200),
        };
        let old = CertificateMetadata {
            subjects: vec!["example.com".into()],
            not_before: 1,
            expires_at: 200,
        };
        observe_certificate(&mut cert, Some(&old), 100);
        assert_eq!(cert.status, "retry_wait");
        assert!(cert.error.is_some());
        observe_certificate(&mut cert, Some(&old), 201);
        assert_eq!(cert.status, "expired");
        let renewed = CertificateMetadata {
            subjects: vec!["example.com".into()],
            not_before: 190,
            expires_at: 400,
        };
        observe_certificate(&mut cert, Some(&renewed), 201);
        assert_eq!(cert.status, "issued");
        assert!(cert.error.is_none());
        assert!(cert.next_retry_at.is_none());
    }

    #[tokio::test]
    async fn deletion_waits_for_inflight_config_and_removes_the_last_snapshot() {
        use axum::{
            extract::Json,
            routing::{get, post},
            Router,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        let root =
            std::env::temp_dir().join(format!("nexo-delete-config-{}", uuid::Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = settings(&root);
        cfg.admin_url = format!("http://{}", listener.local_addr().unwrap());
        let current = Arc::new(tokio::sync::Mutex::new(json!({})));
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let loads = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/config/",
                get({
                    let current = current.clone();
                    move || {
                        let current = current.clone();
                        async move { Json(current.lock().await.clone()) }
                    }
                }),
            )
            .route(
                "/load",
                post({
                    let current = current.clone();
                    let started = started.clone();
                    let release = release.clone();
                    let loads = loads.clone();
                    move |Json(config): Json<Value>| {
                        let current = current.clone();
                        let started = started.clone();
                        let release = release.clone();
                        let loads = loads.clone();
                        async move {
                            if loads.fetch_add(1, Ordering::SeqCst) == 0 {
                                started.notify_one();
                                release.notified().await;
                            }
                            *current.lock().await = config;
                            axum::http::StatusCode::OK
                        }
                    }
                }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let (mut state, admin) = crate::tests::domain_fixture();
        state.domain_runtime = Arc::new(DomainRuntimeManager::new(cfg.clone()));
        let alice = crate::accounts::tests::add_user(&state, "alice");
        let domain = crate::tests::add_test_domain(&state, &alice, "deleted.test")
            .await
            .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE domain_settings SET verified=1 WHERE domain_id=?1",
                [&domain.id],
            )
            .unwrap();
        let pending_config = tokio::spawn({
            let state = state.clone();
            async move {
                reconcile(&state).await.unwrap();
            }
        });
        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .unwrap();
        let deletion = tokio::spawn({
            let state = state.clone();
            async move {
                crate::accounts::delete_user(
                    axum::extract::State(state),
                    admin,
                    axum::extract::Path("alice".into()),
                    Json(serde_json::from_value(json!({"confirm_username":"alice"})).unwrap()),
                )
                .await
                .unwrap()
                .0
            }
        });
        // 删除正在等待旧加载；并发产生的入网凭证也必须随最终事务消失。
        let pending = crate::create_enrollment(
            axum::extract::State(state.clone()),
            alice,
            Json(crate::CreateEnrollment { ttl_seconds: None }),
        )
        .await
        .unwrap()
        .0;
        release.notify_one();
        pending_config.await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), deletion)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result["deleted"], true);
        assert_eq!(result["cleanup_pending"], false);
        assert_eq!(loads.load(Ordering::SeqCst), 2);
        assert!(!current.lock().await.to_string().contains("deleted.test"));
        assert!(!fs::read_to_string(&cfg.applied_path)
            .unwrap()
            .contains("deleted.test"));
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM pending_enrollments WHERE id=?1",
                    [pending.id],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        server.abort();
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    #[ignore = "需要 NEXO_TEST_CADDY_BIN；只在本机随机端口使用 Caddy 内部 CA，不安装系统信任"]
    async fn real_caddy_reuses_wildcards_and_keeps_last_good_config() {
        let binary = std::env::var_os("NEXO_TEST_CADDY_BIN").expect("请提供测试 Caddy 二进制");
        let root =
            std::env::temp_dir().join(format!("nexo-caddy-integration-{}", uuid::Uuid::new_v4()));
        let port = || {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut cfg = settings(&root);
        cfg.binary = binary.into();
        cfg.admin_url = format!("http://127.0.0.1:{}", port());
        cfg.http_listen = format!("127.0.0.1:{}", port());
        cfg.https_listen = format!("127.0.0.1:{}", port());
        let https_address: SocketAddr = cfg.https_listen.parse().unwrap();
        let (mut state, headers) = crate::tests::domain_fixture();
        state.data_dir = root.clone();
        state.domain_runtime = Arc::new(DomainRuntimeManager::new(cfg.clone()));
        let supervisor = &state.domain_runtime.supervisor;
        supervisor
            .write_startup_config(&build_config(&cfg, &[]).unwrap())
            .unwrap();
        supervisor.clone().start().await.unwrap();
        let domain = crate::tests::add_test_domain(&state, &headers, "caddy-integration.localhost")
            .await
            .unwrap();
        // 本机测试显式置入已验证的旧 DNS 模式，仅让 .localhost 走 Caddy 内部 CA。
        state.db.lock().unwrap().execute("UPDATE domain_settings SET verified=1,certificate_mode='cloudflare_dns',legacy=1 WHERE domain_id=?1",[&domain.id]).unwrap();
        let add_service = |hostname: &str| {
            state.db.lock().unwrap().execute(
                "INSERT INTO tunnels (id,tenant_id,name,protocol,local_address,local_port,hostname,public_domain_id,created_at,updated_at) VALUES (?1,'default',?1,'https','127.0.0.1',8080,?1,?2,0,0)",
                params![hostname, domain.id],
            ).unwrap();
        };
        add_service("nas");
        add_service("a.team");
        // 模拟已有逐个子域名签发的配置，确认切换后旧证书文件不会妨碍泛域名复用。
        let mut legacy =
            build_config(&cfg, &specifications(&state, &HashMap::new()).unwrap()).unwrap();
        legacy["apps"]["tls"]["certificates"]["automate"] = json!([
            "caddy-integration.localhost",
            "nas.caddy-integration.localhost",
            "a.team.caddy-integration.localhost"
        ]);
        supervisor.apply_json(&legacy).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        while read_certificates(&cfg.storage_root).len() < 3 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "旧配置未完成签发：{:?}",
                supervisor.drain_log_events().await
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        loop {
            reconcile(&state).await.unwrap();
            let status = state.domain_runtime.status(&domain.id);
            if status.config_status == "applied"
                && status.certificates.len() == 3
                && status.certificates.iter().all(|c| c.status == "issued")
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Caddy 未在时限内签发：{status:?}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let status = state.domain_runtime.status(&domain.id);
        assert!(status.certificates[0].expires_at.unwrap() > unix_now());
        let root_pem = fs::read(cfg.storage_root.join("pki/authorities/local/root.crt")).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .tls_info(true)
            .add_root_certificate(reqwest::Certificate::from_pem(&root_pem).unwrap())
            .resolve("caddy-integration.localhost", https_address)
            .resolve("nas.caddy-integration.localhost", https_address)
            .resolve("media.caddy-integration.localhost", https_address)
            .resolve("a.team.caddy-integration.localhost", https_address)
            .resolve("b.team.caddy-integration.localhost", https_address)
            .build()
            .unwrap();
        let response = client
            .get(format!(
                "https://caddy-integration.localhost:{}/",
                https_address.port()
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        let mut peer_certificates = Vec::new();
        let before_certificates = read_certificates(&cfg.storage_root).len();
        // 同父域增加服务只更新路由；TLS 实际返回的 DER 必须与原服务相同。
        for (index, hostname) in ["nas", "a.team", "media", "b.team"].iter().enumerate() {
            if index == 2 {
                add_service("media");
                add_service("b.team");
                reconcile(&state).await.unwrap();
            }
            let response = client
                .get(format!(
                    "https://{hostname}.caddy-integration.localhost:{}/",
                    https_address.port()
                ))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
            let der = response
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .unwrap()
                .peer_certificate()
                .unwrap()
                .to_vec();
            let (_, certificate) = x509_parser::parse_x509_certificate(&der).unwrap();
            let expected = if hostname.contains('.') {
                "*.team.caddy-integration.localhost"
            } else {
                "*.caddy-integration.localhost"
            };
            let san = certificate.subject_alternative_name().unwrap().unwrap();
            assert_eq!(
                san.value.general_names,
                vec![GeneralName::DNSName(expected)]
            );
            peer_certificates.push(der);
        }
        assert_eq!(peer_certificates[0], peer_certificates[2]);
        assert_eq!(peer_certificates[1], peer_certificates[3]);
        let certificates = read_certificates(&cfg.storage_root);
        assert_eq!(certificates.len(), before_certificates);
        assert!(!certificates.iter().any(|cert| cert
            .subjects
            .iter()
            .any(|name| name == "media.caddy-integration.localhost"
                || name == "b.team.caddy-integration.localhost")));
        assert_eq!(
            state.domain_runtime.status(&domain.id).certificates.len(),
            3
        );
        let before = supervisor.current_config().await.unwrap();
        let mut invalid = before.clone();
        invalid["apps"]["invalid_nexo_module"] = json!({});
        assert!(supervisor.apply_json(&invalid).await.is_err());
        assert_eq!(supervisor.current_config().await.unwrap(), before);
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&cfg.applied_path).unwrap()).unwrap(),
            before
        );
        let event_count: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM public_domain_runtime_events",
                [],
                |row| row.get(0),
            )
            .unwrap();
        reconcile(&state).await.unwrap();
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM public_domain_runtime_events",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            event_count
        );
        let events = crate::domain_events(axum::extract::State(state.clone()), headers)
            .await
            .unwrap();
        assert!(events.0["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["summary"].as_str().unwrap().contains("配置已加载")));
        supervisor.shutdown().await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        reconcile(&state).await.unwrap();
        let stopped = state.domain_runtime.status(&domain.id);
        assert_eq!(stopped.config_status, "failed");
        assert!(stopped.config_error.unwrap().contains("无法连接 Caddy"));
        assert_eq!(
            stopped.certificates[0].expires_at,
            status.certificates[0].expires_at
        );
        // root 是本测试生成的唯一临时目录，退出后清理证书和子进程配置。
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn certificate_modes_and_dns_options_stay_per_domain() {
        let mut dns = domain();
        dns.token_reference = Some("{file./private/token}".into());
        dns.dns = crate::domains::DnsSettings {
            dns_resolvers: vec!["1.1.1.1:53".into()],
            dns_propagation_delay_seconds: Some(15),
            dns_propagation_timeout_seconds: Some(90),
        };
        dns.services[0].upstream = Some("127.0.0.1:18080".into());
        let mut http = domain();
        http.name = "other.test".into();
        http.certificate_mode = "http01".into();
        http.services[0].hostname = "nas.other.test".into();
        let config = build_config(&settings(Path::new("test")), &[dns, http]).unwrap();
        let policies = &config["apps"]["tls"]["automation"]["policies"];
        let challenge = &policies[0]["issuers"][0]["challenges"]["dns"];
        assert_eq!(challenge["provider"]["api_token"], "{file./private/token}");
        assert_eq!(challenge["resolvers"], json!(["1.1.1.1:53"]));
        assert_eq!(challenge["propagation_delay"], 15_000_000_000_u64);
        assert_eq!(challenge["propagation_timeout"], 90_000_000_000_u64);
        assert_eq!(
            policies[1]["subjects"],
            json!(["nas.other.test", "other.test"])
        );
        assert!(policies[1]["issuers"][0]["challenges"]["dns"].is_null());
        assert_eq!(
            config["apps"]["http"]["servers"]["https"]["routes"][1]["handle"][0]
                ["stream_close_delay"],
            300_000_000_000_u64
        );
        assert!(config["apps"]["http"]["servers"]["https"]["protocols"].is_null());
    }

    #[tokio::test]
    #[ignore = "需要带 Cloudflare 模块的 NEXO_TEST_CADDY_BIN；不触发公网证书或 DNS 操作"]
    async fn real_caddy_reloads_file_credentials_and_keeps_applied_on_failure() {
        let binary = std::env::var_os("NEXO_TEST_CADDY_BIN").expect("请提供测试 Caddy 二进制");
        let root = std::env::temp_dir().join(format!("nexo-caddy-hot-{}", uuid::Uuid::new_v4()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut cfg = settings(&root);
        cfg.binary = binary.into();
        cfg.admin_url = format!("http://127.0.0.1:{port}");
        let supervisor = Arc::new(CaddySupervisor::new(cfg.clone()));
        let mut config = build_config(&cfg, &[]).unwrap();
        supervisor.write_startup_config(&config).unwrap();
        supervisor.clone().start().await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while supervisor.current_config().await.is_err() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let id = uuid::Uuid::new_v4().to_string();
        let original = crate::domains::write_credential(
            &cfg.cloudflare_token_root,
            &id,
            &format!("cfut_{}", "a".repeat(100)),
        )
        .unwrap();
        let path =
            crate::domains::credential_path(&cfg.cloudflare_token_root, &id, &original).unwrap();
        // 只装配 provider，不配置 automate 或 HTTPS 路由，因此不会访问 Cloudflare/ACME。
        config["apps"]["tls"] = json!({"automation":{"policies":[{"subjects":["hot-reload.example.test"],"issuers":[{"module":"acme","challenges":{"dns":{"provider":{"name":"cloudflare","api_token":format!("{{file.{}}}",path.display())}}}}]}]}});
        supervisor.apply_json(&config).await.unwrap();
        assert!(!supervisor.credentials_changed(&config).await.unwrap());
        fs::write(&path, format!("cfat_{}", "b".repeat(128))).unwrap();
        assert!(supervisor.credentials_changed(&config).await.unwrap());
        supervisor.apply_json(&config).await.unwrap();
        assert!(!supervisor.credentials_changed(&config).await.unwrap());
        fs::write(&path, "invalid-test-token").unwrap();
        let error = supervisor
            .apply_json(&config)
            .await
            .expect_err("相同 JSON 必须重新读取文件并拒绝无效凭据");
        assert!(!error.to_string().contains("invalid-test-token"));
        fs::write(&path, format!("cfat_{}", "b".repeat(128))).unwrap();
        let candidate =
            crate::domains::write_credential(&cfg.cloudflare_token_root, &id, "invalid-candidate")
                .unwrap();
        let candidate_path =
            crate::domains::credential_path(&cfg.cloudflare_token_root, &id, &candidate).unwrap();
        let mut rejected = config.clone();
        rejected["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["challenges"]["dns"]
            ["provider"]["api_token"] = json!(format!("{{file.{}}}", candidate_path.display()));
        assert!(supervisor.apply_json(&rejected).await.is_err());
        assert_eq!(supervisor.current_config().await.unwrap(), config);
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&cfg.applied_path).unwrap()).unwrap(),
            config
        );
        supervisor.write_startup_config(&rejected).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&cfg.config_path).unwrap()).unwrap(),
            config
        );
        let (mut state, headers) = crate::tests::domain_fixture();
        state.domain_runtime = Arc::new(DomainRuntimeManager::new(cfg.clone()));
        let other = crate::tests::add_test_domain(&state, &headers, "retained.test")
            .await
            .unwrap();
        crate::domains::write_credential(&cfg.cloudflare_token_root, &other.id, &"c".repeat(40))
            .unwrap();
        // 域名数据已删除，但失败加载仍保留原配置：不能提前销毁其凭据。
        assert!(
            cleanup_deleted_credentials(&state, &supervisor.current_config().await.unwrap())
                .is_err()
        );
        assert!(path.exists() && candidate_path.exists());
        supervisor.shutdown().await.unwrap();
        let restarted = state.domain_runtime.supervisor.clone();
        let empty = build_config(&cfg, &[]).unwrap();
        restarted.write_startup_config(&empty).unwrap();
        restarted.clone().start().await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while restarted.current_config().await.is_err() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            cleanup_deleted_credentials(&state, &restarted.current_config().await.unwrap())
                .is_err()
        );
        assert!(path.exists());
        restarted.apply_json(&empty).await.unwrap();
        // 运行配置已移除引用，但磁盘 Applied 未更新时依然保留；两者均更新才清理。
        fs::write(&cfg.applied_path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(
            cleanup_deleted_credentials(&state, &restarted.current_config().await.unwrap())
                .is_err()
        );
        restarted.apply_json(&empty).await.unwrap();
        cleanup_deleted_credentials(&state, &restarted.current_config().await.unwrap()).unwrap();
        assert!(!path.exists() && !candidate_path.exists());
        assert!(cfg.cloudflare_token_root.join(&other.id).exists());
        restarted.shutdown().await.unwrap();
    }
}
