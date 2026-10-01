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
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use x509_parser::{extensions::GeneralName, pem::parse_x509_pem};

#[cfg(test)]
#[path = "domain_runtime_reverse_proxy_tests.rs"]
mod reverse_proxy_tests;
#[cfg(test)]
#[path = "service_access/caddy_tests.rs"]
mod service_access_tests;

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
    pub service_errors: HashMap<String, String>,
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
            service_errors: HashMap::new(),
            checked_at: None,
            certificates: Vec::new(),
            loaded_routes: HashMap::new(),
        }
    }
}

/// 仅保存本次进程观测到的运行状态；重启后重新从 Caddy 查询，不沿用数据库中的旧成功标记。
pub struct DomainRuntimeManager {
    access_runtime: tokio::sync::OnceCell<crate::service_access::Runtime>,
    pub supervisor: Arc<CaddySupervisor>,
    statuses: Mutex<HashMap<String, DomainRuntime>>,
    /// 配置快照、删除和凭据回收共用协调锁，禁止把删除前的快照重新加载。
    pub(crate) reconcile_lock: tokio::sync::Mutex<()>,
}
impl DomainRuntimeManager {
    pub fn new(config: CaddyRuntimeConfig) -> Self {
        Self {
            supervisor: Arc::new(CaddySupervisor::new(config)),
            access_runtime: tokio::sync::OnceCell::new(),
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
    dns_provider: Option<Value>,
    dns: crate::domains::DnsSettings,
    services: Vec<WebService>,
}
#[derive(Debug, Clone)]
struct WebService {
    relay_probe_revision: Option<i64>,
    https_port: u16,
    management: bool,
    http_redirect_enabled: bool,
    id: String,
    hostname: String,
    protocol: String,
    upstream: Option<String>,
    lan_redirect: Option<LanRedirect>,
}
/// 重定向仅存在于当前已认证 Agent 的出口快照中；离线或未开启的服务不生成规则。
#[derive(Debug, Clone)]
struct LanRedirect {
    public_ipv4: Ipv4Addr,
    origin: String,
}
impl DomainSpec {
    fn subjects(&self) -> Vec<String> {
        if !self.https {
            return Vec::new();
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
    agent_public_ipv4s: &HashMap<String, Ipv4Addr>,
) -> Result<Vec<DomainSpec>> {
    let connection = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let settings = state.domain_runtime.supervisor.config();
    let mut query = connection.prepare(
        "SELECT p.id,p.tenant_id,p.domain,p.https_enabled FROM public_domains p JOIN tenants w ON w.id=p.tenant_id JOIN domain_settings s ON s.domain_id=p.id WHERE w.enabled=1 AND s.verified=1 ORDER BY p.domain,p.id",
    )?;
    let mut domains = query
        .query_map([], |row| {
            Ok(DomainSpec {
                id: row.get(0)?,
                tenant_id: row.get(1)?,
                name: row.get(2)?,
                https: row.get::<_, i64>(3)? != 0,
                token_reference: None,
                dns_provider: None,
                dns: crate::domains::DnsSettings::default(),
                services: Vec::new(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for domain in &mut domains {
        let options = crate::domains::load(&connection, &domain.id, &domain.name)
            .map_err(|e| anyhow::anyhow!(e.message))?;
        domain.dns_provider =
            if options.credential_configured && options.dns_provider != "cloudflare" {
                Some(crate::dns_provider::caddy_config(
                    &connection,
                    &settings.cloudflare_token_root,
                    &domain.id,
                )?)
            } else {
                None
            };
        domain.dns = options.dns;
        let path = options
            .credential_file
            .map(|file| {
                crate::domains::credential_path(&settings.cloudflare_token_root, &domain.id, &file)
            })
            .transpose()?;
        domain.token_reference = path.map(|path| format!("{{file.{}}}", path.display()));
        let mut services = connection.prepare("SELECT id,hostname,protocol,device_id,lan_redirect_enabled,local_address,local_port,origin_protocol,service_mode,http_redirect_enabled,https_port,apply_revision FROM tunnels WHERE public_domain_id=?1 AND tenant_id=?2 AND enabled=1 AND deleted_at IS NULL AND protocol IN ('http','https') AND EXISTS(SELECT 1 FROM authorized_service_nodes sn WHERE sn.service_id=tunnels.id AND sn.node_id='local')")?;
        let mut rows = services.query(params![domain.id, domain.tenant_id])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let hostname: Option<String> = row.get(1)?;
            let device_id: Option<String> = row.get(3)?;
            let direct = row.get::<_, String>(8)? == crate::reverse_proxy::MODE;
            let redirect_enabled: bool = row.get::<_, bool>(4)? && !direct;
            // 只按本服务绑定的设备查询，其他 Agent 的公网出口不能授权此服务跳转。
            let public_ipv4 = device_id
                .as_ref()
                .and_then(|id| agent_public_ipv4s.get(id))
                .copied();
            let lan_redirect = if let (true, Some(public_ipv4)) = (redirect_enabled, public_ipv4) {
                let local_address: String = row.get(5)?;
                let local_port: u16 = row.get(6)?;
                let origin_protocol: Option<String> = row.get(7)?;
                // 每轮根据当前本地目标生成地址；公网 HTTPS 不代表回源也使用 HTTPS。
                let origin = crate::lan_redirect::target_url(
                    &local_address,
                    local_port,
                    origin_protocol.as_deref(),
                )
                .map_err(|error| anyhow::anyhow!(error.message))?;
                Some(LanRedirect {
                    public_ipv4,
                    origin,
                })
            } else {
                None
            };
            domain.services.push(WebService {
                relay_probe_revision: if !direct && crate::nodes::dns::managed(&connection, &id)? {
                    Some(row.get(11)?)
                } else {
                    None
                },
                https_port: row.get(10)?,
                management: false,
                http_redirect_enabled: direct && row.get(9)?,
                hostname: format!("{}.{}", hostname.unwrap_or_default(), domain.name),
                protocol: row.get(2)?,
                upstream: if direct {
                    Some(crate::reverse_proxy::target(
                        row.get::<_, Option<String>>(7)?
                            .as_deref()
                            .unwrap_or("http"),
                        &row.get::<_, String>(5)?,
                        row.get(6)?,
                    ))
                } else {
                    upstreams.get(&id).cloned()
                },
                id,
                lan_redirect,
            });
        }
    }
    // 管理入口只增加专用路由，不伪造普通服务，沿用所选域名的证书策略。
    let management = crate::server_settings::load(&connection)?.management_entry;
    if let Some(entry) = management {
        if let Some(domain) = domains
            .iter_mut()
            .find(|domain| domain.id == entry.domain_id)
        {
            domain.services.push(WebService {
                relay_probe_revision: None,
                https_port: 443,
                management: true,
                http_redirect_enabled: true,
                id: "management".into(),
                hostname: format!("{}.{}", entry.hostname, domain.name),
                protocol: "https".into(),
                upstream: Some(format!(
                    "http://{}",
                    crate::server_settings::upstream(state.config.http_addr)
                )),
                lan_redirect: None,
            });
        }
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

/// URL 只用于 Server 直连；隧道入口仍是已认证的本地 socket，保持原有回源方式。
fn proxy_handler(upstream: &str) -> Result<Value> {
    let mut handler = json!({"handler":"reverse_proxy","upstreams":[{"dial":upstream}],"stream_close_delay":300000000000_u64});
    if upstream.starts_with("http://") || upstream.starts_with("https://") {
        let url = reqwest::Url::parse(upstream)?;
        let host = url.host_str().context("反代目标缺少主机名")?;
        handler["upstreams"][0]["dial"] = json!(format!(
            "{host}:{}",
            url.port_or_known_default().context("反代目标缺少端口")?
        ));
        // Caddy 新版本 HTTPS 回源可能重写 Host；显式保留用户访问的公网主机名。
        handler["headers"] = json!({"request":{"set":{"Host":["{http.request.hostport}"]}}});
        if url.scheme() == "https" {
            handler["transport"] =
                json!({"protocol":"http","tls":{"server_name":host.trim_matches(['[', ']'])}});
        }
    }
    Ok(handler)
}

/// 只跳到配置中的域名，保留原方法与 URI；禁止缓存以便关闭和换域名后立即恢复。
pub(crate) fn https_redirect(hostname: &str, port: u16) -> Value {
    let origin = crate::https_ports::url("https", hostname, port);
    json!({"match":[{"host":[hostname]}],"handle":[{"handler":"static_response","status_code":307,"headers":{"Location":[format!("{origin}{{http.request.uri}}")],"Cache-Control":["no-store"]}}],"terminal":true})
}

/// 只发布显式域名；未知主机返回 404。没有可信 Tunnel socket 时明确返回 503，不连接 Agent 的私网地址。
fn build_config(settings: &CaddyRuntimeConfig, domains: &[DomainSpec]) -> Result<Value> {
    let mut http = Vec::new();
    let mut https: std::collections::BTreeMap<u16, Vec<Value>> = std::collections::BTreeMap::new();
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
            https.entry(443).or_default().push(root_route);
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
            let mut handler = if let Some(upstream) = &service.upstream {
                proxy_handler(upstream)?
            } else {
                json!({"handler":"static_response","status_code":503,"body":"服务转发通道尚未就绪"})
            };
            if service.protocol == "https" && service.http_redirect_enabled {
                http.push(https_redirect(&service.hostname, service.https_port));
            }
            if service.management {
                // 明确覆盖协议头，不采信访问者自行传入的值。
                handler["headers"]["request"]["set"]["X-Forwarded-Proto"] = json!(["https"]);
                https.entry(443).or_default().push(json!({"match":[{"host":[service.hostname]}],"handle":[handler],"terminal":true}));
                continue;
            }
            let (access_endpoint, access_check) =
                crate::service_access::handlers(&settings.access_address, &service.id);
            let route =
                json!({"match":[{"host":[service.hostname]}],"handle":[access_check,handler]});
            let routes = if service.protocol == "https" {
                https.entry(service.https_port).or_default()
            } else {
                &mut http
            };
            if let Some(revision) = service.relay_probe_revision {
                routes.push(crate::nodes::health::route(
                    &service.hostname,
                    "local",
                    &service.id,
                    revision,
                ));
            }
            if let Some(redirect) = &service.lan_redirect {
                routes.push(crate::lan_redirect::route(
                    &service.id,
                    &service.hostname,
                    redirect.public_ipv4,
                    &redirect.origin,
                ));
            }
            routes.push(json!({"match":[{"host":[service.hostname],"path":["/.nexo-access/*"]}],"handle":[access_endpoint],"terminal":true}));
            routes.push(route);
        }
        let domain_subjects = domain.subjects();
        if !domain_subjects.is_empty() {
            if let Some(token) = &domain.token_reference {
                let mut dns = json!({"provider":domain.dns_provider.clone().unwrap_or_else(||json!({"name":"cloudflare","api_token":token}))});
                if !domain.dns.dns_resolvers.is_empty() {
                    dns["resolvers"] = json!(domain.dns.dns_resolvers);
                }
                if let Some(seconds) = domain.dns.dns_propagation_delay_seconds {
                    dns["propagation_delay"] = json!(u64::from(seconds) * 1_000_000_000);
                }
                if let Some(seconds) = domain.dns.dns_propagation_timeout_seconds {
                    dns["propagation_timeout"] = json!(u64::from(seconds) * 1_000_000_000);
                }
                policies.push(json!({"subjects":domain_subjects,"issuers":[{"module":"acme","challenges":{"dns":dns,"http":{"disabled":true},"tls-alpn":{"disabled":true}}}]}));
                // 没有 DNS 凭据的域名不加入 automate，避免 Caddy 使用默认 ACME issuer。
                subjects.extend(domain_subjects);
            }
        }
    }
    // Caddy 无匹配路由时默认返回空的 200；显式兜底，避免未知域名被误认为服务正常。
    let not_found = json!({"handle":[{"handler":"static_response","status_code":404}]});
    http.push(not_found.clone());
    for routes in https.values_mut() {
        routes.push(not_found.clone());
    }
    let mut servers = serde_json::Map::new();
    if !domains.is_empty() {
        servers.insert("http".into(),json!({"listen":[settings.http_listen],"automatic_https":{"disable":true},"routes":http}));
    }
    // 每个端口只安装属于它的路由，避免同一主机在未选择的端口仍然可访问。
    for (port, routes) in https {
        let (name, listen) = if port == 443 {
            ("https".to_owned(), settings.https_listen.clone())
        } else {
            let (address, _) = settings
                .https_listen
                .rsplit_once(':')
                .context("HTTPS 监听地址无效")?;
            (format!("https_{port}"), format!("{address}:{port}"))
        };
        // 必须在 TLS 包装之前识别明文 HTTP，让同端口访问跳转到保留原 URI 的 HTTPS 地址。
        servers.insert(name, json!({"listen":[listen],"listener_wrappers":[{"wrapper":"http_redirect"},{"wrapper":"tls"}],"automatic_https":{"disable":true},"routes":routes,"tls_connection_policies":[{}]}));
    }
    let mut config = json!({"admin":{"listen":admin_listen(settings)?},"storage":{"module":"file_system","root":settings.storage_root},"apps":{"http":{"servers":servers},"pki":{"certificate_authorities":{"local":{"install_trust":false}}}}});
    if !subjects.is_empty() {
        config["apps"]["tls"] =
            json!({"certificates":{"automate":subjects},"automation":{"policies":policies}});
    }
    Ok(config)
}
/// 已由当前 Caddy 持有的监听可复用；新监听只做本机占用检查，不发起公网连接。
fn available_ports(
    settings: &CaddyRuntimeConfig,
    specs: &[DomainSpec],
    current: &Value,
) -> (Vec<DomainSpec>, HashMap<String, String>) {
    let mut ports = HashMap::<u16, Option<String>>::new();
    let mut errors = HashMap::new();
    let mut available = specs.to_vec();
    for domain in &mut available {
        domain.services.retain(|service| {
            if service.protocol != "https" || service.https_port == 443 {
                return true;
            }
            let port = service.https_port;
            let error = ports.entry(port).or_insert_with(|| {
                let prefix = settings
                    .https_listen
                    .rsplit_once(':')
                    .map(|(p, _)| p)
                    .unwrap_or("");
                let listen = format!("{prefix}:{port}");
                let already_listening =
                    current["apps"]["http"]["servers"]
                        .as_object()
                        .is_some_and(|servers| {
                            servers.values().any(|server| {
                                server["listen"]
                                    .as_array()
                                    .is_some_and(|addresses| addresses.contains(&json!(listen)))
                            })
                        });
                if already_listening {
                    return None;
                }
                let address = if listen.starts_with(':') {
                    format!("0.0.0.0{listen}")
                } else {
                    listen
                };
                std::net::TcpListener::bind(address)
                    .err()
                    .map(|e| format!("HTTPS 公网端口 {port} 无法监听：{e}"))
            });
            if let Some(error) = error {
                errors.insert(service.id.clone(), error.clone());
                false
            } else {
                true
            }
        });
    }
    (available, errors)
}

pub(crate) async fn reconcile(state: &AppState) -> Result<()> {
    let _guard = state.domain_runtime.reconcile_lock.lock().await;
    reconcile_locked(state).await.map(|_| ())
}

/// 调用方必须持有 reconcile_lock；返回 false 表示配置或专属凭据仍待下一轮清理。
pub(crate) async fn reconcile_locked(state: &AppState) -> Result<bool> {
    let upstreams = state.tunnel_runtime.web_upstreams().await;
    let agent_public_ipv4s = state.tunnel_runtime.agent_public_ipv4s().await;
    let specs = specifications(state, &upstreams, &agent_public_ipv4s)?;
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
    let access = manager
        .access_runtime
        .get_or_try_init(|| crate::service_access::Runtime::start(state))
        .await?;
    let mut settings_with_access = settings.clone();
    settings_with_access.access_address = access.address.clone();
    // 新端口被其他程序占用时，只撤下该端口的服务；其他入口仍可正常应用配置。
    let current = supervisor.current_config().await;
    let (available_specs, service_errors) = available_ports(
        &settings_with_access,
        &specs,
        current.as_ref().unwrap_or(&Value::Null),
    );
    let desired = build_config(&settings_with_access, &available_specs);
    // 一轮协调复用真实读取的配置；发生加载后重新读取，清理不得使用候选配置。
    let config_result = match (desired, current) {
        (Ok(config), Ok(current)) => {
            if current == config && !supervisor.credentials_changed(&config).await? {
                Ok(current)
            } else {
                match supervisor.apply_json(&config).await {
                    Ok(()) => supervisor.current_config().await,
                    Err(error) => Err(error),
                }
            }
        }
        (Err(error), _) | (_, Err(error)) => Err(error),
    };
    let config_error = config_result
        .as_ref()
        .err()
        .map(|e| caddy::redact(&format!("{e:#}"), &settings.cloudflare_token_root));
    let cleanup_complete = if let Ok(current) = &config_result {
        // 运行配置与持久化配置都不再引用时，才能删除凭据。
        match cleanup_deleted_credentials(state, current) {
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
                            crate::https_ports::url(
                                &service.protocol,
                                &service.hostname,
                                service.https_port,
                            ),
                            upstream.clone(),
                        )
                    })
                })
                .collect()
        } else {
            HashMap::new()
        };
        runtime.service_errors = domain
            .services
            .iter()
            .filter_map(|s| service_errors.get(&s.id).map(|e| (s.id.clone(), e.clone())))
            .collect();
        for service in &domain.services {
            if service_errors.contains_key(&service.id) {
                runtime.loaded_routes.remove(&crate::https_ports::url(
                    &service.protocol,
                    &service.hostname,
                    service.https_port,
                ));
            }
        }
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
            if domain.token_reference.is_none() {
                cert.status = "pending".into();
                cert.error = Some("请先验证并保存域名的 DNS 凭据".into());
                cert.not_before = None;
                cert.expires_at = None;
                cert.next_retry_at = None;
                continue;
            }
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

    #[test]
    fn reverse_proxy_status_wait_does_not_block_database() {
        let (state, _) = crate::tests::domain_fixture();
        state.db.lock().unwrap().execute_batch("INSERT INTO public_domains(id,tenant_id,domain,created_at,updated_at) VALUES('domain','default','example.com',0,0);
            INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,hostname,public_domain_id,service_mode,created_at,updated_at) VALUES('proxy','default','proxy','http','127.0.0.1',3000,'app','domain','reverse_proxy',0,0);").unwrap();
        // 模拟 Caddy 正持有状态锁并准备写事件；反代等待状态时必须释放数据库。
        let statuses = state.domain_runtime.statuses.lock().unwrap();
        let (started, ready) = std::sync::mpsc::channel();
        let refresh_state = state.clone();
        let refresh = std::thread::spawn(move || {
            started.send(()).unwrap();
            crate::reverse_proxy::refresh_status(&refresh_state)
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let (send, receive) = std::sync::mpsc::channel();
        let reader_state = state.clone();
        let reader = std::thread::spawn(move || {
            let db = reader_state.db.lock().unwrap();
            let value: i64 = db.query_row("SELECT 1", [], |row| row.get(0)).unwrap();
            let _ = send.send(value);
        });
        let database_responded = receive.recv_timeout(Duration::from_secs(1));
        if database_responded == Ok(1) {
            state.db.lock().unwrap().execute("UPDATE tunnels SET apply_revision=apply_revision+1,apply_status='checking',apply_error='new configuration' WHERE id='proxy'", []).unwrap();
        }
        drop(statuses);
        refresh.join().unwrap().unwrap();
        reader.join().unwrap();
        assert_eq!(
            database_responded.ok(),
            Some(1),
            "反代等待域名状态时阻塞数据库，可能导致启动死锁"
        );
        let error: String = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT apply_error FROM tunnels WHERE id='proxy'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            error, "new configuration",
            "旧快照不得覆盖等待期间的新配置状态"
        );
    }

    fn settings(root: &Path) -> CaddyRuntimeConfig {
        CaddyRuntimeConfig {
            access_address: "127.0.0.1:0".into(),
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
            dns_provider: None,
            id: "d".into(),
            tenant_id: "default".into(),
            name: "example.com".into(),
            https: true,
            token_reference: Some("{file./test/token}".into()),
            dns: crate::domains::DnsSettings::default(),
            services: vec![WebService {
                relay_probe_revision: None,
                https_port: 443,
                management: false,
                http_redirect_enabled: false,
                id: "nas".into(),
                hostname: "nas.example.com".into(),
                protocol: "https".into(),
                upstream: None,
                lan_redirect: None,
            }],
        }
    }
    #[test]
    fn management_route_reuses_certificates_without_service_access_and_forces_https() {
        let mut domain = domain();
        domain.services[0].management = true;
        domain.services[0].http_redirect_enabled = true;
        domain.services[0].upstream = Some("http://127.0.0.1:8280".into());
        let cfg = build_config(&settings(Path::new("test")), &[domain.clone()]).unwrap();
        let http = &cfg["apps"]["http"]["servers"]["http"]["routes"];
        assert_eq!(http[0]["handle"][0]["status_code"], 307);
        assert_eq!(
            http[0]["handle"][0]["headers"]["Location"],
            json!(["https://nas.example.com{http.request.uri}"])
        );
        let route = &cfg["apps"]["http"]["servers"]["https"]["routes"][1];
        assert_eq!(route["handle"].as_array().unwrap().len(), 1);
        assert_eq!(
            route["handle"][0]["headers"]["request"]["set"]["X-Forwarded-Proto"],
            json!(["https"])
        );
        assert!(!cfg.to_string().contains("/.nexo-access/"));
        assert_eq!(
            cfg["apps"]["tls"]["certificates"]["automate"],
            json!(["*.example.com", "example.com"])
        );
    }

    #[test]
    fn routes_share_wildcard_and_do_not_fake_a_working_tunnel() {
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
            cfg["apps"]["http"]["servers"]["https"]["routes"][2]["handle"][1]["status_code"],
            503
        );
        assert!(!cfg.to_string().contains("mesh."));
        assert!(!cfg.to_string().contains("local_address"));
        assert_eq!(
            cfg["apps"]["pki"]["certificate_authorities"]["local"]["install_trust"],
            false
        );
    }

    #[tokio::test]
    async fn lan_redirect_uses_the_bound_agent_and_current_local_target() {
        let (state, headers) = crate::tests::domain_fixture();
        let domain = crate::tests::add_test_domain(&state, &headers, "lan.test")
            .await
            .unwrap();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE domain_settings SET verified=1 WHERE domain_id=?1",
                [&domain.id],
            )
            .unwrap();
            for id in ["first", "second", "offline"] {
                db.execute("INSERT INTO devices (id,tenant_id,name,created_at,updated_at) VALUES (?1,'default',?1,0,0)", [id]).unwrap();
                db.execute("INSERT INTO tunnels (id,tenant_id,device_id,name,protocol,local_address,local_port,hostname,public_domain_id,lan_redirect_enabled,created_at,updated_at) VALUES (?1,'default',?1,?1,'https','192.168.1.10',8080,?1,?2,1,0,0)", params![id, domain.id]).unwrap();
            }
        }
        let addresses = HashMap::from([
            ("first".into(), "8.8.8.8".parse().unwrap()),
            ("second".into(), "1.1.1.1".parse().unwrap()),
            ("unbound".into(), "9.9.9.9".parse().unwrap()),
        ]);
        let specs = specifications(&state, &HashMap::new(), &addresses).unwrap();
        let services = &specs[0].services;
        let find = |id: &str| services.iter().find(|service| service.id == id).unwrap();
        assert_eq!(
            find("first").lan_redirect.as_ref().unwrap().public_ipv4,
            addresses["first"]
        );
        assert_eq!(
            find("second").lan_redirect.as_ref().unwrap().public_ipv4,
            addresses["second"]
        );
        assert!(find("offline").lan_redirect.is_none());
        assert!(!build_config(&settings(Path::new("test")), &specs)
            .unwrap()
            .to_string()
            .contains("9.9.9.9"));
        let location = |specs: &[DomainSpec], id: &str| {
            let config = build_config(&settings(Path::new("test")), specs).unwrap();
            let route_id = format!("{}{id}", caddy::LAN_REDIRECT_ROUTE_PREFIX);
            let routes = config["apps"]["http"]["servers"]["https"]["routes"]
                .as_array()
                .unwrap();
            let route = routes
                .iter()
                .find(|route| route["@id"] == route_id)
                .unwrap();
            route["handle"][0]["headers"]["Location"][0]
                .as_str()
                .unwrap()
                .to_owned()
        };
        // 公网 HTTPS 服务默认仍按 HTTP 回源；地址和协议修改都直接反映到下一轮配置。
        assert_eq!(
            location(&specs, "first"),
            "http://192.168.1.10:8080{http.request.uri}"
        );
        for (address, port, protocol, expected) in [
            (
                "192.168.2.30",
                9090,
                None,
                "http://192.168.2.30:9090{http.request.uri}",
            ),
            (
                "fd00::25",
                8443,
                Some("https"),
                "https://[fd00::25]:8443{http.request.uri}",
            ),
        ] {
            state.db.lock().unwrap().execute(
                "UPDATE tunnels SET local_address=?1,local_port=?2,origin_protocol=?3 WHERE id='first'",
                params![address, port, protocol],
            ).unwrap();
            let specs = specifications(&state, &HashMap::new(), &addresses).unwrap();
            assert_eq!(location(&specs, "first"), expected);
            assert_eq!(
                location(&specs, "second"),
                "http://192.168.1.10:8080{http.request.uri}"
            );
        }

        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE tunnels SET lan_redirect_enabled=0 WHERE id='first'",
                [],
            )
            .unwrap();
        let specs = specifications(&state, &HashMap::new(), &addresses).unwrap();
        assert!(specs[0]
            .services
            .iter()
            .find(|s| s.id == "first")
            .unwrap()
            .lan_redirect
            .is_none());
        let specs = specifications(&state, &HashMap::new(), &HashMap::new()).unwrap();
        assert!(specs[0].services.iter().all(|s| s.lan_redirect.is_none()));
    }

    #[test]
    fn startup_removes_redirects_and_blocks_restored_proxies_until_reconciled() {
        let root = std::env::temp_dir().join(format!(
            "nexo-caddy-redirect-startup-{}",
            uuid::Uuid::new_v4()
        ));
        let cfg = settings(&root);
        let mut d = domain();
        d.services[0].upstream = Some("127.0.0.1:18080".into());
        d.services[0].lan_redirect = Some(LanRedirect {
            public_ipv4: "8.8.8.8".parse().unwrap(),
            origin: "http://192.168.1.10:8080".into(),
        });
        let applied = build_config(&cfg, &[d.clone()]).unwrap();
        fs::create_dir_all(&root).unwrap();
        fs::write(&cfg.applied_path, serde_json::to_vec(&applied).unwrap()).unwrap();
        let supervisor = CaddySupervisor::new(cfg.clone());
        supervisor
            .write_startup_config(&json!({"invalid_desired":true}))
            .unwrap();
        d.services[0].lan_redirect = None;
        let startup: Value = serde_json::from_slice(&fs::read(&cfg.config_path).unwrap()).unwrap();
        assert_eq!(startup["apps"]["tls"], applied["apps"]["tls"]);
        assert!(!startup.to_string().contains("reverse_proxy"));
        assert!(!startup
            .to_string()
            .contains(caddy::LAN_REDIRECT_ROUTE_PREFIX));
        assert!(startup.to_string().contains("503"));
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&cfg.applied_path).unwrap()).unwrap(),
            applied
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dns_credentials_remain_placeholders_and_http_only_has_no_certificates() {
        let mut d = domain();
        d.token_reference = Some("{file./credential-test.token}".into());
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
            "{file./credential-test.token}"
        );
        assert!(
            cfg["apps"]["tls"]["automation"]["policies"][0]["issuers"][0]["challenges"]["dns"]
                .get("resolvers")
                .is_none()
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
                relay_probe_revision: None,
                https_port: 443,
                management: false,
                http_redirect_enabled: false,
                id: "media".into(),
                hostname: "media.example.com".into(),
                protocol: "https".into(),
                upstream: None,
                lan_redirect: None,
            },
            WebService {
                relay_probe_revision: None,
                https_port: 443,
                management: false,
                http_redirect_enabled: false,
                id: "a.team".into(),
                hostname: "a.team.example.com".into(),
                protocol: "https".into(),
                upstream: None,
                lan_redirect: None,
            },
            WebService {
                relay_probe_revision: None,
                https_port: 443,
                management: false,
                http_redirect_enabled: false,
                id: "b.team".into(),
                hostname: "b.team.example.com".into(),
                protocol: "https".into(),
                upstream: None,
                lan_redirect: None,
            },
            WebService {
                relay_probe_revision: None,
                https_port: 443,
                management: false,
                http_redirect_enabled: false,
                id: "http-only".into(),
                hostname: "a.http-only.example.com".into(),
                protocol: "http".into(),
                upstream: None,
                lan_redirect: None,
            },
        ]);
        // 无凭据保持待配置；有凭据时共享各层级泛域证书，不逐个服务签发。
        for token in [None, Some("{file./credential-test.token}".into())] {
            d.token_reference = token;
            let cfg = build_config(&settings(Path::new("test")), &[d.clone()]).unwrap();
            assert_eq!(
                cfg["apps"]["tls"]["certificates"]["automate"],
                if d.token_reference.is_some() {
                    json!(["*.example.com", "*.team.example.com", "example.com"])
                } else {
                    Value::Null
                }
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
                relay_probe_revision: None,
                https_port: 443,
                management: false,
                http_redirect_enabled: false,
                id: "next.team".into(),
                hostname: "next.team.example.com".into(),
                protocol: "https".into(),
                upstream: None,
                lan_redirect: None,
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
    async fn coordination_reuses_config_and_recovers_after_admin_failure() {
        use axum::{
            extract::ConnectInfo,
            routing::{get, post},
            Json, Router,
        };
        use std::{
            net::SocketAddr,
            sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        let root = std::env::temp_dir().join(format!("nexo-config-reuse-{}", uuid::Uuid::new_v4()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let current = Arc::new(tokio::sync::Mutex::new(json!({})));
        let reads = Arc::new(AtomicUsize::new(0));
        let loads = Arc::new(AtomicUsize::new(0));
        let failed = Arc::new(AtomicBool::new(false));
        let peers = Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new()));
        let app = Router::new()
            .route(
                "/config/",
                get({
                    let (current, reads, failed, peers) = (
                        current.clone(),
                        reads.clone(),
                        failed.clone(),
                        peers.clone(),
                    );
                    move |ConnectInfo(peer): ConnectInfo<SocketAddr>| {
                        let (current, reads, failed, peers) = (
                            current.clone(),
                            reads.clone(),
                            failed.clone(),
                            peers.clone(),
                        );
                        async move {
                            reads.fetch_add(1, Ordering::SeqCst);
                            peers.lock().await.insert(peer);
                            let status = if failed.load(Ordering::SeqCst) {
                                axum::http::StatusCode::SERVICE_UNAVAILABLE
                            } else {
                                axum::http::StatusCode::OK
                            };
                            (status, Json(current.lock().await.clone()))
                        }
                    }
                }),
            )
            .route(
                "/load",
                post({
                    let (current, loads) = (current.clone(), loads.clone());
                    move |Json(config): Json<Value>| {
                        let (current, loads) = (current.clone(), loads.clone());
                        async move {
                            loads.fetch_add(1, Ordering::SeqCst);
                            *current.lock().await = config;
                            axum::http::StatusCode::OK
                        }
                    }
                }),
            );
        let mut cfg = settings(&root);
        cfg.admin_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let (mut state, _) = crate::tests::domain_fixture();
        state.domain_runtime = Arc::new(DomainRuntimeManager::new(cfg));
        assert!(reconcile_locked(&state).await.unwrap());
        assert_eq!(reads.load(Ordering::SeqCst), 2, "加载后确认实际配置");
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert!(reconcile_locked(&state).await.unwrap());
        assert_eq!(reads.load(Ordering::SeqCst), 3, "稳定轮次只读一次");
        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert_eq!(peers.lock().await.len(), 1, "Admin 连接池复用 TCP 连接");
        failed.store(true, Ordering::SeqCst);
        assert!(
            !reconcile_locked(&state).await.unwrap(),
            "读取失败不得清理凭据"
        );
        failed.store(false, Ordering::SeqCst);
        *current.lock().await = json!({});
        assert!(reconcile_locked(&state).await.unwrap());
        assert_eq!(loads.load(Ordering::SeqCst), 2, "外部配置丢失后重新加载");
        server.abort();
        let _ = server.await;
        if root.exists() {
            fs::remove_dir_all(root).unwrap();
        }
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
        let pending = crate::tests::recovery_fixture(&state, &alice).await;
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
    async fn real_caddy_redirects_only_navigation_and_discards_old_session_rules() {
        use axum::{extract::Request, Router};
        use reqwest::{Method, StatusCode};

        let binary = std::env::var_os("NEXO_TEST_CADDY_BIN").expect("请提供测试 Caddy 二进制");
        let root =
            std::env::temp_dir().join(format!("nexo-caddy-lan-redirect-{}", uuid::Uuid::new_v4()));
        let port = || {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        };
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            axum::serve(
                upstream,
                Router::new().fallback(|request: Request| async move {
                    (
                        [("x-test-upstream", "true")],
                        format!("{} {}", request.method(), request.uri()),
                    )
                }),
            )
            .await
            .unwrap();
        });
        let mut cfg = settings(&root);
        cfg.binary = binary.into();
        cfg.admin_url = format!("http://127.0.0.1:{}", port());
        cfg.http_listen = format!("127.0.0.1:{}", port());
        cfg.https_listen = format!("127.0.0.1:{}", port());
        let http_address: SocketAddr = cfg.http_listen.parse().unwrap();
        let https_address: SocketAddr = cfg.https_listen.parse().unwrap();
        let origin = "http://192.168.1.10:8080";
        let mut d = domain();
        d.name = "lan-redirect.localhost".into();
        d.services[0].hostname = "nas.lan-redirect.localhost".into();
        d.services[0].upstream = Some(upstream_address.to_string());
        // 本机集成测试直接构造来源快照；生产入口只允许 transport 验证后的公网 IPv4。
        d.services[0].lan_redirect = Some(LanRedirect {
            public_ipv4: Ipv4Addr::LOCALHOST,
            origin: origin.into(),
        });
        let mut http_service = d.services[0].clone();
        http_service.id = "http".into();
        http_service.hostname = "http.lan-redirect.localhost".into();
        http_service.protocol = "http".into();
        d.services.push(http_service);
        let mut other_service = d.services[0].clone();
        other_service.id = "other".into();
        other_service.hostname = "other.lan-redirect.localhost".into();
        other_service.lan_redirect.as_mut().unwrap().public_ipv4 = "8.8.8.8".parse().unwrap();
        d.services.push(other_service);
        let (mut access_state, _) = crate::tests::domain_fixture();
        access_state.domain_runtime = Arc::new(DomainRuntimeManager::new(cfg.clone()));
        {
            let db = access_state.db.lock().unwrap();
            db.execute("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES('access-domain','default','lan-redirect.localhost',1,0,0)", []).unwrap();
            for service in &d.services {
                let hostname = service
                    .hostname
                    .strip_suffix(".lan-redirect.localhost")
                    .unwrap();
                db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,hostname,public_domain_id,created_at,updated_at) VALUES(?1,'default',?1,?2,'127.0.0.1',8080,?3,'access-domain',0,0)", params![service.id,service.protocol,hostname]).unwrap();
            }
        }
        let access_runtime = crate::service_access::Runtime::start(&access_state)
            .await
            .unwrap();
        cfg.access_address = access_runtime.address.clone();
        let make_config = |d: DomainSpec| {
            let mut config = build_config(&cfg, &[d]).unwrap();
            config["apps"]["tls"]["automation"]["policies"] =
                json!([{"issuers":[{"module":"internal"}]}]);
            config
        };
        let enabled = make_config(d.clone());
        let supervisor = Arc::new(CaddySupervisor::new(cfg.clone()));
        supervisor.write_startup_config(&enabled).unwrap();
        supervisor.clone().start().await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        while supervisor.current_config().await.is_err()
            || read_certificates(&cfg.storage_root).len() < 2
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "Caddy 未就绪：{:?}",
                supervisor.drain_log_events().await
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let root_pem = fs::read(cfg.storage_root.join("pki/authorities/local/root.crt")).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .add_root_certificate(reqwest::Certificate::from_pem(&root_pem).unwrap())
            .resolve("nas.lan-redirect.localhost", https_address)
            .resolve("http.lan-redirect.localhost", http_address)
            .resolve("other.lan-redirect.localhost", https_address)
            .build()
            .unwrap();
        let uri = "/photos/a%2Fb/%E4%B8%AD?next=%2Fhome%3Fa%3D1&name=a+b&raw=%252F";
        let https_url = format!(
            "https://nas.lan-redirect.localhost:{}{uri}",
            https_address.port()
        );
        let http_url = format!(
            "http://http.lan-redirect.localhost:{}{uri}",
            http_address.port()
        );
        let other_url = format!(
            "https://other.lan-redirect.localhost:{}{uri}",
            https_address.port()
        );
        let navigation = |method: Method, url: &str| {
            client
                .request(method, url)
                .header("Sec-Fetch-Mode", "navigate")
                .header("Sec-Fetch-Dest", "document")
        };
        for url in [&https_url, &http_url] {
            for method in [Method::GET, Method::HEAD] {
                let response = navigation(method, url).send().await.unwrap();
                assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
                assert_eq!(response.headers()["location"], format!("{origin}{uri}"));
                assert_eq!(response.headers()["cache-control"], "no-store");
                assert!(!response.headers().contains_key("x-test-upstream"));
            }
        }
        // 同一浏览器来源不能匹配另一台 Agent；伪造转发头也不能替代真实连接来源。
        let response = navigation(Method::GET, &other_url)
            .header("X-Forwarded-For", "8.8.8.8")
            .header("X-Real-IP", "8.8.8.8")
            .header("Forwarded", "for=8.8.8.8")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), format!("GET {uri}"));
        for request in [
            client.get(&https_url),
            client
                .get(&https_url)
                .header("Sec-Fetch-Mode", "cors")
                .header("Sec-Fetch-Dest", "empty"),
            client.get(&https_url).header("Sec-Fetch-Mode", "navigate"),
            client
                .get(&https_url)
                .header("Sec-Fetch-Mode", "navigate")
                .header("Sec-Fetch-Dest", "iframe"),
            navigation(Method::GET, &https_url)
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket"),
            client
                .get(&https_url)
                .header("Sec-Fetch-Mode", "websocket")
                .header("Sec-Fetch-Dest", "empty")
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket"),
            navigation(Method::POST, &https_url).body("kept on tunnel"),
            navigation(Method::PUT, &https_url).body("kept on tunnel"),
            navigation(Method::DELETE, &https_url),
        ] {
            let response = request.send().await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["x-test-upstream"], "true");
            assert!(!response.headers().contains_key("location"));
        }
        let mut disabled = d.clone();
        for service in &mut disabled.services {
            service.lan_redirect = None;
        }
        let disabled = make_config(disabled);
        supervisor.apply_json(&disabled).await.unwrap();
        let response = navigation(Method::GET, &https_url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), format!("GET {uri}"));
        supervisor.apply_json(&enabled).await.unwrap();
        let mut rejected = disabled.clone();
        rejected["apps"]["invalid_nexo_module"] = json!({});
        assert!(supervisor.apply_json(&rejected).await.is_err());
        assert_eq!(
            navigation(Method::GET, &https_url)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::TEMPORARY_REDIRECT
        );
        supervisor.shutdown().await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while supervisor.current_config().await.is_ok() {
            assert!(tokio::time::Instant::now() < deadline, "Caddy 未停止");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let restarted = Arc::new(CaddySupervisor::new(cfg.clone()));
        restarted
            .write_startup_config(&build_config(&cfg, &[]).unwrap())
            .unwrap();
        restarted.clone().start().await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while restarted.current_config().await.is_err() {
            assert!(tokio::time::Instant::now() < deadline, "Caddy 未重新启动");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let restored = restarted.current_config().await.unwrap();
        assert!(!restored.to_string().contains("reverse_proxy"));
        assert!(!restored
            .to_string()
            .contains(caddy::LAN_REDIRECT_ROUTE_PREFIX));
        let response = navigation(Method::GET, &https_url).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        restarted.apply_json(&disabled).await.unwrap();
        assert_eq!(
            navigation(Method::GET, &https_url)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&cfg.applied_path).unwrap()).unwrap(),
            disabled
        );
        restarted.shutdown().await.unwrap();
        upstream_task.abort();
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
        // start 返回时管理接口必须已经就绪，首轮协调不能产生虚假的配置失败事件。
        supervisor.current_config().await.unwrap();
        let domain = crate::tests::add_test_domain(&state, &headers, "caddy-integration.localhost")
            .await
            .unwrap();
        // 本机夹具预置内部 CA 证书和合法私有文件引用，不依赖缺少凭据的签发回退。
        let credential = crate::domains::write_credential(
            &cfg.cloudflare_token_root,
            &domain.id,
            &format!("cfat_{}", "a".repeat(100)),
        )
        .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE domain_settings SET verified=1,credential_file=?2 WHERE domain_id=?1",
                params![domain.id, credential],
            )
            .unwrap();
        let mut seed = build_config(&cfg, &[]).unwrap();
        seed["apps"]["tls"] = json!({"certificates":{"automate":["caddy-integration.localhost","nas.caddy-integration.localhost","a.team.caddy-integration.localhost","*.caddy-integration.localhost","*.team.caddy-integration.localhost"]},"automation":{"policies":[{"issuers":[{"module":"internal"}]}]}});
        supervisor.apply_json(&seed).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        while read_certificates(&cfg.storage_root).len() < 5 {
            assert!(tokio::time::Instant::now() < deadline, "内部测试证书未就绪");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for directory in fs::read_dir(cfg.storage_root.join("certificates/local")).unwrap() {
            let source = directory.unwrap().path();
            let target = cfg
                .storage_root
                .join("certificates/acme-v02.api.letsencrypt.org-directory")
                .join(source.file_name().unwrap());
            fs::create_dir_all(&target).unwrap();
            for entry in fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
            }
        }
        let add_service = |hostname: &str| {
            state.db.lock().unwrap().execute(
                "INSERT INTO tunnels (id,tenant_id,name,protocol,local_address,local_port,hostname,public_domain_id,created_at,updated_at) VALUES (?1,'default',?1,'https','127.0.0.1',8080,?1,?2,0,0)",
                params![hostname, domain.id],
            ).unwrap();
        };
        add_service("nas");
        add_service("a.team");
        // 模拟已有逐个子域名签发的配置，确认切换后旧证书文件不会妨碍泛域名复用。
        let mut individual = build_config(
            &cfg,
            &specifications(&state, &HashMap::new(), &HashMap::new()).unwrap(),
        )
        .unwrap();
        individual["apps"]["tls"]["certificates"]["automate"] = json!([
            "caddy-integration.localhost",
            "nas.caddy-integration.localhost",
            "a.team.caddy-integration.localhost"
        ]);
        supervisor.apply_json(&individual).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        while read_certificates(&cfg.storage_root).len() < 3 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "逐域名配置未完成签发：{:?}",
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
        let events = crate::domain_events(
            axum::extract::State(state.clone()),
            headers,
            axum::extract::Query(crate::DomainEventsQuery::default()),
        )
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
    fn dns_options_stay_per_domain_and_missing_credentials_never_fall_back() {
        let mut dns = domain();
        dns.token_reference = Some("{file./private/token}".into());
        dns.dns = crate::domains::DnsSettings {
            dns_resolvers: vec!["1.1.1.1:53".into()],
            dns_propagation_delay_seconds: Some(15),
            dns_propagation_timeout_seconds: Some(90),
        };
        dns.services[0].upstream = Some("127.0.0.1:18080".into());
        let mut missing = domain();
        missing.name = "other.test".into();
        missing.token_reference = None;
        missing.services[0].hostname = "nas.other.test".into();
        let config = build_config(&settings(Path::new("test")), &[dns, missing.clone()]).unwrap();
        let policies = &config["apps"]["tls"]["automation"]["policies"];
        let challenge = &policies[0]["issuers"][0]["challenges"]["dns"];
        assert_eq!(challenge["provider"]["api_token"], "{file./private/token}");
        assert_eq!(challenge["resolvers"], json!(["1.1.1.1:53"]));
        assert_eq!(challenge["propagation_delay"], 15_000_000_000_u64);
        assert_eq!(challenge["propagation_timeout"], 90_000_000_000_u64);
        assert_eq!(policies.as_array().unwrap().len(), 1);
        assert_eq!(
            config["apps"]["tls"]["certificates"]["automate"],
            json!(["*.example.com", "example.com"])
        );
        assert_eq!(
            policies[0]["issuers"][0]["challenges"]["http"]["disabled"],
            true
        );
        assert_eq!(
            policies[0]["issuers"][0]["challenges"]["tls-alpn"]["disabled"],
            true
        );
        assert!(
            build_config(&settings(Path::new("test")), &[missing]).unwrap()["apps"]["tls"]
                .is_null()
        );
        assert_eq!(
            config["apps"]["http"]["servers"]["https"]["routes"][2]["handle"][1]
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
        config["apps"]["tls"] = json!({"automation":{"policies":[{"subjects":["hot-reload.example.test"],"issuers":[{"module":"acme","challenges":{"http":{"disabled":true},"tls-alpn":{"disabled":true},"dns":{"provider":{"name":"cloudflare","api_token":format!("{{file.{}}}",path.display())}}}}]}]}});
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
    #[test]
    fn custom_https_ports_isolate_routes_and_redirects() {
        let cfg = settings(Path::new("/tmp/nexo-ports"));
        let mut domain = domain();
        domain.services[0].https_port = 9443;
        domain.services[0].http_redirect_enabled = true;
        let config = build_config(&cfg, &[domain]).unwrap();
        let servers = &config["apps"]["http"]["servers"];
        assert_eq!(servers["https_9443"]["listen"], json!([":9443"]));
        assert!(!servers["https"]["routes"]
            .to_string()
            .contains("nas.example.com"));
        assert!(servers["https_9443"]["routes"]
            .to_string()
            .contains("nas.example.com"));
        assert!(servers["http"]["routes"]
            .to_string()
            .contains("https://nas.example.com:9443"));
    }

    #[test]
    fn occupied_custom_port_only_removes_affected_services() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut cfg = settings(Path::new("/tmp/nexo-ports"));
        cfg.https_listen = "127.0.0.1:443".into();
        let mut domain = domain();
        let mut blocked = domain.services[0].clone();
        blocked.id = "blocked".into();
        blocked.hostname = "blocked.example.com".into();
        blocked.https_port = occupied.local_addr().unwrap().port();
        domain.services.push(blocked);
        let (available, errors) = available_ports(&cfg, &[domain], &Value::Null);
        assert_eq!(available[0].services.len(), 1);
        assert!(errors.contains_key("blocked"));
        assert!(errors["blocked"].contains("无法监听"));
    }
}
