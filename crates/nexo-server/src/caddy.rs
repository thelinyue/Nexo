//! Caddy 公网入口 Supervisor 与结构化配置生成。
//!
//! Caddy 是独立的边缘组件：它负责 HTTP/HTTPS 终止和 Web Service 路由，
//! 但不能成为 Nexo Core、LAN 管理或 TCP Tunnel 的启动前置。配置始终先
//! 通过 Admin API 校验，成功后才原子替换 Applied 文件；失败时继续保留
//! 上一份可用配置。

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::{
    process::{Child, Command},
    sync::{Mutex, Notify},
};

pub const CADDY_VERSION: &str = "2.11.4";
pub const XCADDY_VERSION: &str = "0.4.7";
pub const CLOUDFLARE_MODULE_VERSION: &str = "0.2.4";
const ACME_STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Clone)]
pub struct CaddyRuntimeConfig {
    pub binary: PathBuf,
    pub config_path: PathBuf,
    pub applied_path: PathBuf,
    /// Cloudflare Token 的唯一明文来源。配置文件只保存环境变量占位符，
    /// Supervisor 启动 Caddy 时再从这个 0600 文件注入子进程环境。
    pub cloudflare_token_path: PathBuf,
    pub admin_url: String,
    pub enabled: bool,
}

impl CaddyRuntimeConfig {
    pub fn from_env(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let binary = env::var_os("NEXO_CADDY_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("caddy"));
        let enabled = env::var("NEXO_CADDY_ENABLED")
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        Self {
            binary,
            config_path: data_dir.join("caddy").join("config.json"),
            applied_path: data_dir.join("caddy").join("applied.json"),
            cloudflare_token_path: data_dir
                .join("secrets")
                .join("public-entry")
                .join("cloudflare.token"),
            admin_url: env::var("NEXO_CADDY_ADMIN_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8290".to_owned()),
            enabled,
        }
    }
}

#[derive(Debug)]
pub struct CaddySupervisor {
    config: CaddyRuntimeConfig,
    child: Arc<Mutex<Option<Child>>>,
    stopping: Arc<AtomicBool>,
    notify: Arc<Notify>,
    restart_requested: Arc<AtomicBool>,
    /// 只保存 Token 摘要，用于检测 Secret 更新；绝不把明文写入状态或日志。
    token_digest: Arc<Mutex<Option<String>>>,
}

impl CaddySupervisor {
    pub fn new(config: CaddyRuntimeConfig) -> Self {
        Self {
            config,
            child: Arc::new(Mutex::new(None)),
            stopping: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            restart_requested: Arc::new(AtomicBool::new(false)),
            token_digest: Arc::new(Mutex::new(None)),
        }
    }

    pub fn config(&self) -> &CaddyRuntimeConfig {
        &self.config
    }

    /// 启动独立 Caddy 子进程；二进制或 Admin 不可用时只影响 Web Service。
    pub async fn start(self: Arc<Self>) -> Result<()> {
        if !self.config.enabled {
            tracing::info!(
                version = CADDY_VERSION,
                xcaddy = XCADDY_VERSION,
                cloudflare = CLOUDFLARE_MODULE_VERSION,
                "Caddy 公网入口未启用"
            );
            return Ok(());
        }
        if let Some(parent) = self.config.config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !self.config.config_path.exists() {
            // Caddy 启动时必须有一份有效 JSON；真正的 Desired State 会在
            // Admin API 可用后再次原子应用，失败不会覆盖 Applied 文件。
            atomic_write(
                &self.config.config_path,
                br#"{"admin":{"listen":"127.0.0.1:8290"},"apps":{"http":{"servers":{}}}}"#,
            )?;
        }
        self.stopping.store(false, Ordering::SeqCst);
        self.restart_requested.store(false, Ordering::SeqCst);
        // Supervisor 监控循环必须在首次 spawn 失败时也启动；否则二进制
        // 暂时不可用的容器永远不会自动恢复，只能依赖人工重启 Nexo。
        let first_spawn = self.spawn_once().await;
        let supervisor = self.clone();
        tokio::spawn(async move { supervisor.monitor_loop().await });
        if let Err(error) = first_spawn {
            tracing::error!(
                "Caddy 未能启动，公网 Web 服务暂不可用；Nexo 核心仍继续运行：{error:#}"
            );
        }
        Ok(())
    }

    async fn spawn_once(&self) -> Result<()> {
        let mut command = Command::new(&self.config.binary);
        // Caddy 的 JSON 配置只包含 `{env.NEXO_CLOUDFLARE_API_TOKEN}`，
        // 避免把 Token 写入配置、命令行参数、日志或 SQLite。文件不存在时
        // 不注入变量，让 Caddy 明确报告证书材料尚未准备好。
        let token_digest = if let Ok(token) = fs::read_to_string(&self.config.cloudflare_token_path)
        {
            let token = token.trim();
            if !token.is_empty() {
                command.env("NEXO_CLOUDFLARE_API_TOKEN", token);
                Some(hex::encode(Sha256::digest(token.as_bytes())))
            } else {
                None
            }
        } else {
            None
        };
        // JSON 是 Caddy 原生配置格式；只有非原生格式才需要指定适配器。
        let child = command
            .args([
                "run",
                "--config",
                self.config.config_path.to_string_lossy().as_ref(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("无法启动 Caddy：{}", self.config.binary.display()))?;
        *self.child.lock().await = Some(child);
        *self.token_digest.lock().await = token_digest;
        tracing::info!(version = CADDY_VERSION, "Caddy 子进程已启动");
        Ok(())
    }

    async fn monitor_loop(&self) {
        let mut attempt = 0_u32;
        while !self.stopping.load(Ordering::SeqCst) {
            let child = self.child.lock().await.take();
            let Some(mut child) = child else {
                let delay =
                    Duration::from_secs((2_u64.saturating_mul(1 << attempt.min(6))).min(120));
                attempt = attempt.saturating_add(1);
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {},
                    _ = self.notify.notified() => {
                        if self.stopping.load(Ordering::SeqCst) {
                            break;
                        }
                        if self.restart_requested.swap(false, Ordering::SeqCst) {
                            continue;
                        }
                        break;
                    },
                }
                if self.stopping.load(Ordering::SeqCst) {
                    break;
                }
                if let Err(error) = self.spawn_once().await {
                    tracing::error!("Caddy 重启失败，将继续退避：{error:#}");
                }
                continue;
            };
            enum MonitorSignal {
                Exited(std::io::Result<std::process::ExitStatus>),
                Restart,
                Stop,
            }
            let signal = tokio::select! {
                result = child.wait() => MonitorSignal::Exited(result),
                _ = self.notify.notified() => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    if self.stopping.load(Ordering::SeqCst) {
                        MonitorSignal::Stop
                    } else if self.restart_requested.swap(false, Ordering::SeqCst) {
                        MonitorSignal::Restart
                    } else {
                        MonitorSignal::Stop
                    }
                }
            };
            match signal {
                MonitorSignal::Stop => break,
                MonitorSignal::Restart => {
                    attempt = 0;
                    continue;
                }
                MonitorSignal::Exited(result) => {
                    if self.stopping.load(Ordering::SeqCst) {
                        break;
                    }
                    tracing::warn!("Caddy 子进程已退出，将自动重启：{:?}", result);
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }

    /// 在 Caddy 尚未启动时写入启动配置；不会伪造 Applied State。
    ///
    /// 如果上一份 Applied 配置存在，优先用它启动 Caddy，再由协调器把
    /// SQLite 中的 Desired State 通过 Admin API 应用。这样 Server 重启时
    /// 不会因为一次尚未验证的新配置覆盖掉上一份可用边缘配置。
    pub fn write_startup_config(&self, config: &Value) -> Result<()> {
        let body = match fs::read(&self.config.applied_path) {
            Ok(applied) if serde_json::from_slice::<Value>(&applied).is_ok() => applied,
            Ok(_) => {
                tracing::warn!(
                    path = %self.config.applied_path.display(),
                    "上一份 Caddy Applied 配置不是有效 JSON，将使用当前 Desired State"
                );
                serde_json::to_vec(config)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                serde_json::to_vec(config)?
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "无法读取上一份 Caddy Applied 配置：{}",
                        self.config.applied_path.display()
                    )
                });
            }
        };
        atomic_write(&self.config.config_path, &body)
    }

    /// 通过 Caddy Admin API 原子加载 JSON；失败时 Applied 文件和运行配置都不变。
    pub async fn apply_json(&self, config: &Value) -> Result<()> {
        let body = serde_json::to_vec(config)?;
        let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
        // Admin API 的加载和两个落盘文件不是同一个文件系统事务。先记住
        // 旧文件，若落盘在加载成功后失败，就把运行中的 Caddy 回滚到旧
        // 配置并恢复文件，避免重启后读取一份并未确认的 Applied 状态。
        let old_config = fs::read(&self.config.config_path).ok();
        let old_applied = fs::read(&self.config.applied_path).ok();
        post_config(&client, &self.config.admin_url, &body).await?;
        let persist_result = atomic_write(&self.config.config_path, &body)
            .and_then(|_| atomic_write(&self.config.applied_path, &body));
        if let Err(error) = persist_result {
            if let Some(previous) = old_config.as_deref() {
                if let Err(rollback_error) =
                    post_config(&client, &self.config.admin_url, previous).await
                {
                    tracing::error!(
                        "Caddy 配置文件写入失败且运行配置回滚失败，公网 Web 服务状态需要人工检查：{rollback_error:#}"
                    );
                }
                if let Err(restore_error) = atomic_write(&self.config.config_path, previous) {
                    tracing::error!("无法恢复 Caddy 配置文件：{restore_error:#}");
                }
            } else if let Err(restore_error) = fs::remove_file(&self.config.config_path) {
                if restore_error.kind() != std::io::ErrorKind::NotFound {
                    tracing::error!("无法清理失败的 Caddy 配置文件：{restore_error}");
                }
            }
            restore_optional_file(&self.config.applied_path, old_applied.as_deref());
            return Err(error).context("Caddy 已加载配置，但 Applied 文件保存失败，已尝试回滚");
        }
        if self.token_changed().await {
            // 环境变量只能在 Caddy 新进程启动时注入；Admin API 已验证结构后，
            // 请求 Supervisor 用新的 0600 Secret 重启，避免 Cloudflare Token
            // 更新后仍由旧进程继续申请证书。
            self.restart_requested.store(true, Ordering::SeqCst);
            self.notify.notify_one();
        }
        Ok(())
    }

    async fn token_changed(&self) -> bool {
        let current = fs::read_to_string(&self.config.cloudflare_token_path)
            .ok()
            .map(|token| token.trim().to_owned())
            .filter(|token| !token.is_empty())
            .map(|token| hex::encode(Sha256::digest(token.as_bytes())));
        let mut previous = self.token_digest.lock().await;
        if *previous == current {
            return false;
        }
        *previous = current;
        true
    }

    /// 通过 Caddy Admin API 检查边缘进程是否仍可用。
    ///
    /// Caddy 停止只会让公网 Web Service 和正式组网入口受限；调用方不应
    /// 因此停止 Nexo Core 或 TCP Tunnel。
    pub async fn healthy(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        let Ok(client) = Client::builder().timeout(Duration::from_secs(3)).build() else {
            return false;
        };
        client
            .get(format!(
                "{}/config/",
                self.config.admin_url.trim_end_matches('/')
            ))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.stopping.store(true, Ordering::SeqCst);
        self.restart_requested.store(false, Ordering::SeqCst);
        self.notify.notify_one();
        let mut child = self.child.lock().await;
        if let Some(process) = child.as_mut() {
            process.kill().await.context("无法停止 Caddy")?;
            let _ = process.wait().await;
        }
        *child = None;
        Ok(())
    }
}

/// 根据当前数据库 Desired State 生成 Caddy JSON。系统名称和内部桥接地址
/// 固定为受保护值，用户只能控制服务域名和 Origin。
#[allow(dead_code)]
pub fn build_caddy_config(
    base_domain: Option<&str>,
    https_enabled: bool,
    certificate_mode: &str,
    tunnels: &[CaddyTunnel],
    secret_dir: &Path,
) -> Value {
    build_caddy_config_with_environment_and_readiness(
        base_domain,
        https_enabled,
        certificate_mode,
        "production",
        tunnels,
        secret_dir,
        true,
    )
}

/// 按 Desired State 生成 Caddy JSON；ACME staging 只切换签发目录，
/// 不改变 HTTPS 路由或 Secret 处理方式。
#[allow(dead_code)]
pub fn build_caddy_config_with_environment(
    base_domain: Option<&str>,
    https_enabled: bool,
    certificate_mode: &str,
    acme_environment: &str,
    tunnels: &[CaddyTunnel],
    secret_dir: &Path,
) -> Value {
    build_caddy_config_with_environment_and_readiness(
        base_domain,
        https_enabled,
        certificate_mode,
        acme_environment,
        tunnels,
        secret_dir,
        true,
    )
}

/// 按 Desired State 生成 Caddy JSON，并由 `https_ready` 控制是否暴露
/// 会把用户导向 HTTPS 的明文跳转。证书申请/校验尚未完成时仍可让 Caddy
/// 维持其它路由，但不会把根域名或 HTTPS Web Service 指向尚不可用的入口。
pub fn build_caddy_config_with_environment_and_readiness(
    base_domain: Option<&str>,
    https_enabled: bool,
    certificate_mode: &str,
    acme_environment: &str,
    tunnels: &[CaddyTunnel],
    secret_dir: &Path,
    https_ready: bool,
) -> Value {
    let Some(domain) = base_domain.filter(|domain| !domain.is_empty()) else {
        return empty_config();
    };
    let http_tunnels = tunnels
        .iter()
        .filter(|tunnel| tunnel.enabled && tunnel.protocol == "http")
        .filter_map(|tunnel| tunnel_route(tunnel, domain));
    let https_tunnels = tunnels
        .iter()
        .filter(|tunnel| tunnel.enabled && tunnel.protocol == "https")
        .filter_map(|tunnel| tunnel_route(tunnel, domain));
    let wildcard_hosts = tunnels
        .iter()
        .filter(|tunnel| tunnel.enabled && tunnel.protocol == "https")
        .filter_map(|tunnel| {
            tunnel
                .hostname
                .as_deref()
                .map(|hostname| format!("{hostname}.{domain}"))
        })
        .chain([format!("nexo.{domain}"), format!("mesh.{domain}")])
        .collect::<Vec<_>>();

    let mut http_routes = Vec::new();
    let mut https_routes = Vec::new();
    // 明文 Web Service 始终只监听 80；即使同时启用 HTTPS，也不能被全局
    // 的 HTTPS 跳转规则吞掉。HTTPS Web Service 的明文请求单独跳到同名主机。
    http_routes.extend(http_tunnels);
    if https_enabled {
        // 启用正式 HTTPS 后，只有证书和 Caddy 状态都 READY 时，80 才做
        // 明确跳转；不会把尚不可用的 HTTPS 入口发布给用户。
        if https_ready {
            http_routes.push(json!({
                "match": [{"host": [domain]}],
                "handle": [{"handler": "static_response", "status_code": 308,
                    "headers": {"Location": [format!("https://nexo.{domain}")]}}]
            }));
            http_routes.push(redirect_route(
                &format!("nexo.{domain}"),
                &format!("https://nexo.{domain}"),
            ));
            http_routes.push(redirect_route(
                &format!("mesh.{domain}"),
                &format!("https://mesh.{domain}"),
            ));
            http_routes.extend(
                tunnels
                    .iter()
                    .filter(|tunnel| tunnel.enabled && tunnel.protocol == "https")
                    .filter_map(|tunnel| https_redirect_route(tunnel, domain)),
            );
        }
        https_routes.push(system_route(domain, "nexo", "127.0.0.1:9888", true, true));
        https_routes.push(system_route(domain, "mesh", "127.0.0.1:8281", false, false));
        https_routes.push(redirect_route(domain, &format!("https://nexo.{domain}")));
        https_routes.extend(https_tunnels);
        if certificate_mode == "cloudflare" {
            // 显式的泛域名路由让 Caddy 实际管理 `*.domain` 证书；精确服务
            // 路由仍排在前面，未知子域名只返回 404，不会暴露内部服务。
            https_routes.push(json!({
                "match": [{"host": [format!("*.{domain}")]}],
                "handle": [{"handler": "static_response", "status_code": 404}]
            }));
        }
    } else {
        http_routes.push(system_route(domain, "nexo", "127.0.0.1:9888", true, true));
        // Headscale 的正式组网入口只允许 HTTPS；没有证书时不向公网暴露
        // Mesh 控制平面，设备仍可在测试开关下使用内部地址。
    }
    let mut servers = serde_json::Map::new();
    servers.insert(
        "http".to_owned(),
        json!({
            "listen": [":80"],
            "automatic_https": {"disable": true},
            "routes": http_routes
        }),
    );
    if https_enabled {
        let mut https_server = json!({ "listen": [":443"], "routes": https_routes });
        if certificate_mode == "manual" {
            https_server["tls_connection_policies"] = json!([{
                "certificate_selection": { "any_tag": ["nexo-manual"] }
            }]);
            https_server["automatic_https"] = json!({ "disable": true });
        } else if certificate_mode == "cloudflare" {
            // `nexo`、`mesh` 和各 Web Service 都由同一张泛域名证书覆盖，
            // 避免为每个子域名分别创建 ACME 订单。
            https_server["automatic_https"] = json!({
                "skip_certificates": wildcard_hosts
            });
        }
        servers.insert("https".to_owned(), https_server);
    }
    let mut config = json!({
        "admin": { "listen": "127.0.0.1:8290" },
        "apps": { "http": { "servers": servers } }
    });
    if https_enabled && certificate_mode == "manual" {
        config["apps"]["tls"] = json!({
            "certificates": { "load_files": [{
                "certificate": secret_dir.join("certificate.pem"),
                "key": secret_dir.join("private-key.pem"),
                "tags": ["nexo-manual"]
            }] }
        });
    } else if https_enabled && certificate_mode == "cloudflare" {
        let mut issuer = json!({ "module": "acme", "challenges": {
            "dns": { "provider": { "name": "cloudflare",
                "api_token": "{env.NEXO_CLOUDFLARE_API_TOKEN}" } }
        } });
        if acme_environment.eq_ignore_ascii_case("staging") {
            issuer["ca"] = json!(ACME_STAGING_DIRECTORY);
        }
        config["apps"]["tls"] = json!({
            "automation": { "policies": [{
                "subjects": [domain, format!("*.{domain}")],
                "issuers": [issuer]
            }] }
        });
    }
    config
}

fn empty_config() -> Value {
    json!({
        "admin": { "listen": "127.0.0.1:8290" },
        "apps": { "http": { "servers": {} } }
    })
}

fn system_route(
    domain: &str,
    name: &str,
    upstream: &str,
    public_entry: bool,
    tls_upstream: bool,
) -> Value {
    let host = format!("{name}.{domain}");
    let mut route = json!({
        "match": [{"host": [host]}],
        "handle": [{"handler": "reverse_proxy", "upstreams": [{"dial": upstream}]}]
    });
    if tls_upstream {
        // 9888 仅监听 loopback，证书是 Nexo 内部身份而不是公网域名；
        // Caddy 与 Nexo 之间仍使用 TLS，但不需要对本机证书做公网校验。
        route["handle"][0]["transport"] = json!({
            "protocol": "http",
            "tls": {"insecure_skip_verify": true}
        });
    }
    if public_entry {
        route["handle"][0]["headers"] = json!({
            "request": {"set": {"X-Nexo-Public-Entry": ["1"]}}
        });
    }
    route
}

fn tunnel_route(tunnel: &CaddyTunnel, domain: &str) -> Option<Value> {
    let hostname = tunnel.hostname.as_deref()?;
    let upstream = format!("unix//{}", tunnel.bridge_socket);
    // Web Service 桥接 Socket 只承载已经由 Agent 建立好的 HTTP 流。
    // Origin 的 HTTPS 握手发生在 Agent 到本地服务之间，不能再让 Caddy
    // 对 Unix Socket 重复发起 TLS，否则会把明文桥接误当成 TLS Origin。
    let handler = json!({
        "handler": "reverse_proxy",
        "upstreams": [{"dial": upstream}],
        "transport": {"protocol": "http"}
    });
    Some(json!({
        "match": [{"host": [format!("{hostname}.{domain}")]}],
        "handle": [handler]
    }))
}

fn https_redirect_route(tunnel: &CaddyTunnel, domain: &str) -> Option<Value> {
    let hostname = tunnel.hostname.as_deref()?;
    let host = format!("{hostname}.{domain}");
    Some(json!({
        "match": [{"host": [host.clone()]}],
        "handle": [{
            "handler": "static_response",
            "status_code": 308,
            "headers": {"Location": [format!("https://{host}")]}
        }]
    }))
}

fn redirect_route(host: &str, location: &str) -> Value {
    json!({
        "match": [{"host": [host]}],
        "handle": [{
            "handler": "static_response",
            "status_code": 308,
            "headers": {"Location": [location]}
        }]
    })
}

#[derive(Debug, Clone)]
pub struct CaddyTunnel {
    pub hostname: Option<String>,
    pub bridge_socket: String,
    pub protocol: String,
    pub enabled: bool,
}

async fn post_config(client: &Client, admin_url: &str, body: &[u8]) -> Result<()> {
    let response = client
        .post(format!("{}/load", admin_url.trim_end_matches('/')))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_vec())
        .send()
        .await
        .context("Caddy Admin API 请求失败")?;
    if !response.status().is_success() {
        let status = response.status();
        let detail = response.text().await.unwrap_or_default();
        anyhow::bail!("Caddy 拒绝配置：HTTP {} {}", status, truncate(&detail));
    }
    Ok(())
}

fn atomic_write(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path.parent().context("Caddy 配置路径缺少父目录")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    fs::write(&temporary, body)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn restore_optional_file(path: &Path, body: Option<&[u8]>) {
    match body {
        Some(body) => {
            if let Err(error) = atomic_write(path, body) {
                tracing::error!(path = %path.display(), "无法恢复 Caddy Applied 文件：{error:#}");
            }
        }
        None => {
            if let Err(error) = fs::remove_file(path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::error!(path = %path.display(), "无法清理失败的 Caddy Applied 文件：{error}");
                }
            }
        }
    }
}

fn truncate(value: &str) -> String {
    const MAX: usize = 512;
    let value = value.trim();
    if value.len() <= MAX {
        value.to_owned()
    } else {
        format!("{}…", &value[..MAX])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_keeps_admin_on_loopback_and_requests_wildcard_certificate() {
        let config = build_caddy_config(
            Some("example.com"),
            true,
            "cloudflare",
            &[],
            Path::new("/data/secrets"),
        );
        assert_eq!(config["admin"]["listen"], "127.0.0.1:8290");
        let text = config.to_string();
        assert!(text.contains("*.example.com"));
        assert!(text.contains("{env.NEXO_CLOUDFLARE_API_TOKEN}"));
        assert_eq!(
            config["apps"]["http"]["servers"]["https"]["automatic_https"]["skip_certificates"],
            json!(["nexo.example.com", "mesh.example.com"])
        );
        let routes = config["apps"]["http"]["servers"]["https"]["routes"]
            .as_array()
            .expect("HTTPS 路由应为数组");
        let wildcard = routes
            .iter()
            .find(|route| route["match"][0]["host"][0] == "*.example.com")
            .expect("应生成泛域名兜底路由");
        assert_eq!(wildcard["handle"][0]["status_code"], 404);
    }

    #[test]
    fn system_management_route_uses_tls_to_loopback_backend() {
        let config = build_caddy_config(
            Some("example.com"),
            false,
            "none",
            &[],
            Path::new("/data/secrets"),
        );
        let routes = config["apps"]["http"]["servers"]["http"]["routes"]
            .as_array()
            .expect("HTTP 路由应为数组");
        let route = routes
            .iter()
            .find(|route| route["match"][0]["host"][0] == "nexo.example.com")
            .expect("应生成 Nexo 管理入口");
        assert_eq!(route["handle"][0]["transport"]["protocol"], "http");
        assert_eq!(
            route["handle"][0]["transport"]["tls"]["insecure_skip_verify"],
            true
        );
    }

    #[test]
    fn no_domain_generates_no_public_server() {
        let config = build_caddy_config(None, false, "none", &[], Path::new("/tmp"));
        assert!(config["apps"]["http"]["servers"]
            .as_object()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn http_and_https_services_are_kept_on_their_public_protocol() {
        let config = build_caddy_config(
            Some("example.com"),
            true,
            "manual",
            &[
                CaddyTunnel {
                    hostname: Some("plain".to_owned()),
                    bridge_socket: "/data/tunnels/plain.sock".to_owned(),
                    protocol: "http".to_owned(),
                    enabled: true,
                },
                CaddyTunnel {
                    hostname: Some("secure".to_owned()),
                    bridge_socket: "/data/tunnels/secure.sock".to_owned(),
                    protocol: "https".to_owned(),
                    enabled: true,
                },
            ],
            Path::new("/data/secrets"),
        );
        let text = config.to_string();
        assert!(text.contains("plain.example.com"));
        assert!(text.contains("secure.example.com"));
        // Origin TLS 只由 Agent 处理；Caddy 到每个 Unix Socket 始终是明文 HTTP。
        let secure_route = config["apps"]["http"]["servers"]["https"]["routes"]
            .as_array()
            .expect("HTTPS 路由应为数组")
            .iter()
            .find(|route| route["match"][0]["host"][0] == "secure.example.com")
            .expect("应生成 HTTPS Web Service 路由");
        assert_eq!(
            secure_route["handle"][0]["transport"],
            json!({"protocol": "http"})
        );
        let route_text = secure_route.to_string();
        assert!(!route_text.contains("insecure_skip_verify"));
        assert!(!route_text.contains("origin.local"));
        assert!(!route_text.contains("\"ca\""));
    }

    #[test]
    fn https_redirects_wait_until_entry_is_ready() {
        let config = build_caddy_config_with_environment_and_readiness(
            Some("example.com"),
            true,
            "manual",
            "production",
            &[],
            Path::new("/data/secrets"),
            false,
        );
        let routes = config["apps"]["http"]["servers"]["http"]["routes"]
            .as_array()
            .expect("HTTP 路由应为数组");
        assert!(routes.iter().all(|route| {
            route["match"][0]["host"][0] != "example.com"
                && route["match"][0]["host"][0] != "nexo.example.com"
        }));
        assert!(routes.iter().all(|route| {
            route["handle"][0]["headers"]["Location"][0]
                .as_str()
                .is_none_or(|location| !location.starts_with("https://"))
        }));
    }

    #[test]
    fn startup_prefers_valid_applied_configuration() {
        let root = std::env::temp_dir().join(format!("nexo-caddy-{}", uuid::Uuid::new_v4()));
        let config = CaddyRuntimeConfig {
            binary: PathBuf::from("caddy"),
            config_path: root.join("config.json"),
            applied_path: root.join("applied.json"),
            cloudflare_token_path: root.join("cloudflare.token"),
            admin_url: "http://127.0.0.1:8290".to_owned(),
            enabled: true,
        };
        fs::create_dir_all(&root).expect("应创建 Caddy 测试目录");
        let applied = json!({"marker": "applied"});
        fs::write(&config.applied_path, serde_json::to_vec(&applied).unwrap())
            .expect("应写入 Applied 测试文件");
        CaddySupervisor::new(config.clone())
            .write_startup_config(&json!({"marker": "desired"}))
            .expect("应写入启动配置");
        let persisted: Value =
            serde_json::from_slice(&fs::read(&config.config_path).expect("应读取启动配置"))
                .expect("启动配置应为 JSON");
        assert_eq!(persisted["marker"], "applied");
        let _ = fs::remove_dir_all(root);
    }
}
