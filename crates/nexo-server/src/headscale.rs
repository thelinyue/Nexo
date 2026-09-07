//! Headscale 子进程、配置和 API Key 生命周期管理。
//!
//! Headscale 是成熟的控制平面，Nexo 只负责把它作为独立子进程监督，所有业务
//! 交互仍通过官方 HTTP API。密钥明文只存在 `0600` Secret 文件和进程内存中。

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    process::{Child, Command},
    sync::{Mutex, Notify},
};

pub const HEADSCALE_VERSION: &str = "0.29.3";
pub const TAILSCALE_VERSION: &str = "1.102.3";
const DEFAULT_DERP_MAP_URL: &str = "https://controlplane.tailscale.com/derpmap/default";
const API_KEY_LIFETIME_SECONDS: u64 = 90 * 24 * 60 * 60;
const API_KEY_ROTATE_BEFORE_SECONDS: u64 = 14 * 24 * 60 * 60;

/// 产品层只展示这些状态；二进制版本和真实错误进入诊断日志。
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MeshComponentStatus {
    Normal,
    Starting,
    Abnormal,
    /// Headscale 本身可用，但正式 HTTPS 入口或 Caddy 尚未就绪；
    /// 设备可以保留 Nexo 控制连接，新的组网应用会被暂停。
    Restricted,
    VersionIncompatible,
}

/// Supervisor 运行时配置。官方镜像通过环境变量指定内置 Headscale 路径；
/// 本地开发没有该变量时不会尝试启动未知的宿主进程。
#[derive(Debug, Clone)]
pub struct HeadscaleRuntimeConfig {
    pub binary: PathBuf,
    pub data_dir: PathBuf,
    pub listen_addr: String,
    /// Server 进程访问 Headscale REST API 的内部地址。
    pub api_url: String,
    /// 下发给 Agent 的组网登录地址；可以与内部 API 地址不同。
    pub server_url: String,
    /// Nexo OIDC 的固定 issuer；为空时表示公网主域名尚未就绪。
    pub oidc_issuer: Option<String>,
    /// MagicDNS 为节点生成的内部后缀；不向 Web 暴露 Headscale 配置细节。
    pub dns_base_domain: String,
    /// 集成测试可启用内置 DERP，验证无法直连时的真实数据面。
    /// 生产环境默认关闭，继续使用官方 DERP Map。
    pub embedded_derp_enabled: bool,
    pub enabled: bool,
}

impl HeadscaleRuntimeConfig {
    pub fn from_env(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let binary = env::var_os("NEXO_HEADSCALE_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("headscale"));
        let enabled = env::var("NEXO_HEADSCALE_ENABLED")
            .map(|value| value.eq_ignore_ascii_case("true"))
            .unwrap_or_else(|_| env::var_os("NEXO_HEADSCALE_BIN").is_some());
        Self {
            binary,
            data_dir,
            listen_addr: env::var("NEXO_HEADSCALE_LISTEN_ADDR")
                .unwrap_or_else(|_| "127.0.0.1:8281".to_owned()),
            api_url: env::var("NEXO_HEADSCALE_API_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8281".to_owned()),
            server_url: env::var("NEXO_HEADSCALE_URL")
                .unwrap_or_else(|_| "http://nexo-server:8281".to_owned()),
            oidc_issuer: env::var("NEXO_OIDC_ISSUER").ok(),
            dns_base_domain: env::var("NEXO_MESH_DNS_BASE_DOMAIN")
                .unwrap_or_else(|_| "mesh.nexo.internal".to_owned()),
            embedded_derp_enabled: env::var("NEXO_HEADSCALE_EMBEDDED_DERP_ENABLED")
                .map(|value| value.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            enabled,
        }
    }

    pub fn config_path(&self) -> PathBuf {
        self.data_dir.join("headscale").join("config.yaml")
    }

    pub fn secret_path(&self) -> PathBuf {
        self.data_dir.join("headscale").join("nexo-api-key.secret")
    }

    /// 返回 Agent 在没有正式公网入口时使用的内部登录地址。
    ///
    /// 生产部署通过 `NEXO_MESH_INTERNAL_URL` 指定宿主机或 LAN 可达地址；
    /// 未配置时使用 Headscale API 地址作为保守回退。
    pub fn internal_server_url(&self) -> String {
        env::var("NEXO_MESH_INTERNAL_URL")
            .unwrap_or_else(|_| self.api_url.clone())
            .trim_end_matches('/')
            .to_owned()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiKeySecret {
    api_key: String,
    expires_at: u64,
}

/// API Key 文件管理器；不会把明文写入 SQLite、普通导出或日志。
#[derive(Debug, Clone)]
pub struct ApiKeyManager {
    binary: PathBuf,
    secret_path: PathBuf,
    config_path: PathBuf,
}

impl ApiKeyManager {
    /// 使用 Supervisor 生成的配置文件执行本地 CLI，避免依赖容器内默认路径。
    pub fn with_config(
        binary: impl Into<PathBuf>,
        secret_path: impl Into<PathBuf>,
        config_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            binary: binary.into(),
            secret_path: secret_path.into(),
            config_path: config_path.into(),
        }
    }

    pub fn read(&self) -> Result<Option<(String, u64)>> {
        if !self.secret_path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&self.secret_path).with_context(|| {
            format!(
                "无法读取 Headscale API Key Secret：{}",
                self.secret_path.display()
            )
        })?;
        let secret: ApiKeySecret =
            serde_json::from_str(&raw).context("Headscale API Key Secret 格式无效")?;
        if secret.api_key.trim().is_empty() {
            return Err(anyhow!("Headscale API Key Secret 为空"));
        }
        Ok(Some((secret.api_key, secret.expires_at)))
    }

    pub fn needs_rotation(expires_at: u64, now: u64) -> bool {
        expires_at <= now.saturating_add(API_KEY_ROTATE_BEFORE_SECONDS)
    }

    pub fn write_atomic(&self, api_key: &str, expires_at: u64) -> Result<()> {
        if api_key.trim().is_empty() {
            return Err(anyhow!("不能保存空 Headscale API Key"));
        }
        let parent = self
            .secret_path
            .parent()
            .context("Headscale Secret 路径缺少父目录")?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".nexo-api-key.{}.tmp", std::process::id()));
        let body = serde_json::to_vec(&ApiKeySecret {
            api_key: api_key.to_owned(),
            expires_at,
        })?;
        fs::write(&temporary, body)?;
        set_private_permissions(&temporary)?;
        fs::rename(&temporary, &self.secret_path).with_context(|| {
            format!(
                "无法原子切换 Headscale API Key Secret：{}",
                self.secret_path.display()
            )
        })?;
        set_private_permissions(&self.secret_path)?;
        Ok(())
    }

    /// 创建或轮换 API Key，并先用新 Key 调用一次需要鉴权的节点 API。
    ///
    /// 新 Key 未通过自检时不会切换 Secret；通过后才原子写入，再尽力吊销旧
    /// Key，保证运行中的 HTTP 适配器不会先拿到一个不可用凭证。
    pub async fn bootstrap_or_rotate_checked(
        &self,
        now: u64,
        api_url: &str,
    ) -> Result<(String, u64)> {
        let current = self.read()?;
        if let Some((api_key, expires_at)) = &current {
            if !Self::needs_rotation(*expires_at, now) {
                return Ok((api_key.clone(), *expires_at));
            }
            tracing::info!("Headscale API Key 剩余有效期不足 14 天，开始轮换");
        }
        let (new_key, new_expiry) = self.create_key(now).await?;
        if let Err(error) = self.check_new_key(api_url, &new_key).await {
            // CLI 创建成功但 HTTP 自检失败时，不能把这把永远不会写入
            // Secret 的 Key 留在 Headscale 中；吊销失败只影响清理，原始
            // 自检错误仍返回给后台重试器。
            if let Err(expire_error) = self.expire_key(&new_key).await {
                tracing::warn!("Headscale 临时 API Key 清理失败：{expire_error:#}");
            }
            return Err(error);
        }
        self.write_atomic(&new_key, new_expiry)?;
        if let Some((old_key, _)) = current {
            if let Err(error) = self.expire_key(&old_key).await {
                tracing::warn!("旧 Headscale API Key 吊销失败，新 Key 已切换：{error:#}");
            }
        }
        Ok((new_key, new_expiry))
    }

    async fn check_new_key(&self, api_url: &str, api_key: &str) -> Result<()> {
        // `/api/v1/health` 对未鉴权请求也可能返回 200，不能证明新 Key 可用；
        // 节点列表即使为空也会经过 Bearer 鉴权，是更可靠的自检入口。
        let endpoint = format!("{}/api/v1/node", api_url.trim_end_matches('/'));
        let response = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?
            .get(endpoint)
            .bearer_auth(api_key)
            .send()
            .await
            .context("Headscale 新 API Key 自检请求失败")?;
        if !response.status().is_success() {
            anyhow::bail!(
                "Headscale 新 API Key 鉴权自检失败（HTTP {}）",
                response.status()
            );
        }
        Ok(())
    }

    async fn create_key(&self, now: u64) -> Result<(String, u64)> {
        let output = Command::new(&self.binary)
            .args(["--config", self.config_path.to_string_lossy().as_ref()])
            .args(["apikeys", "create", "--expiration", "2160h"])
            .output()
            .await
            .with_context(|| {
                format!(
                    "无法执行 Headscale API Key 创建命令：{}",
                    self.binary.display()
                )
            })?;
        if !output.status.success() {
            return Err(anyhow!(
                "Headscale API Key 创建失败（退出码 {:?}）",
                output.status.code()
            ));
        }
        let api_key = parse_cli_secret(&output.stdout)
            .or_else(|| parse_cli_secret(&output.stderr))
            .context("Headscale API Key 创建命令未返回密钥")?;
        Ok((api_key, now.saturating_add(API_KEY_LIFETIME_SECONDS)))
    }

    async fn expire_key(&self, api_key: &str) -> Result<()> {
        // Headscale 0.29.x 通过 `--prefix` 接受完整 key 或 key prefix；
        // 完整 key 只作为子进程参数传递，不会写入 Nexo 日志。
        let output = Command::new(&self.binary)
            .args(["--config", self.config_path.to_string_lossy().as_ref()])
            .args(["apikeys", "expire", "--prefix", api_key])
            .output()
            .await
            .context("无法执行 Headscale API Key 吊销命令")?;
        if !output.status.success() {
            return Err(anyhow!("Headscale API Key 吊销命令失败"));
        }
        Ok(())
    }
}

/// 子进程 Supervisor：生成配置、启动、健康等待、指数退避重启和关闭。
pub struct HeadscaleSupervisor {
    config: HeadscaleRuntimeConfig,
    /// 根域名修改后会更新 Headscale 的登录地址；其余启动参数保持不变。
    server_url: Arc<RwLock<String>>,
    oidc_issuer: Arc<RwLock<Option<String>>>,
    child: Arc<Mutex<Option<Child>>>,
    stopping: Arc<AtomicBool>,
    shutdown_notify: Arc<Notify>,
    restart_requested: Arc<AtomicBool>,
}

impl std::fmt::Debug for HeadscaleSupervisor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeadscaleSupervisor")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl HeadscaleSupervisor {
    pub fn new(config: HeadscaleRuntimeConfig) -> Self {
        Self {
            server_url: Arc::new(RwLock::new(config.server_url.clone())),
            oidc_issuer: Arc::new(RwLock::new(config.oidc_issuer.clone())),
            config,
            child: Arc::new(Mutex::new(None)),
            stopping: Arc::new(AtomicBool::new(false)),
            shutdown_notify: Arc::new(Notify::new()),
            restart_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn config(&self) -> &HeadscaleRuntimeConfig {
        &self.config
    }

    /// 读取当前写入 Headscale 配置的登录地址；公网域名更新后，后续
    /// Mesh Enrollment 必须使用这份状态，而不能继续读取旧环境变量。
    pub fn server_url(&self) -> String {
        self.server_url
            .read()
            .map(|value| value.clone())
            .unwrap_or_else(|_| self.config.server_url.clone())
    }

    pub fn write_config(&self) -> Result<()> {
        let server_url = self
            .server_url
            .read()
            .map_err(|_| anyhow!("Headscale 公网地址锁不可用"))?
            .clone();
        self.write_config_with_server_url(&server_url)
    }

    fn write_config_with_server_url(&self, server_url: &str) -> Result<()> {
        let headscale_dir = self.config.data_dir.join("headscale");
        fs::create_dir_all(&headscale_dir)?;
        let database_path = headscale_dir.join("headscale.db");
        let noise_key_path = headscale_dir.join("noise_private.key");
        let unix_socket_path = headscale_dir.join("headscale.sock");
        let derp_config = render_derp_config(
            self.config.embedded_derp_enabled,
            &headscale_dir.join("derp_server_private.key"),
        );
        let oidc_issuer = self
            .oidc_issuer
            .read()
            .map_err(|_| anyhow!("Headscale OIDC issuer 锁不可用"))?
            .clone();
        let oidc_config = oidc_issuer
            .as_deref()
            .map(|issuer| {
                format!(
                    "oidc:\n  issuer: {}\n  client_id: headscale\n  client_secret: \"\"\n  use_expiry_from_token: false\n  scope: [\"openid\", \"profile\"]\n  pkce:\n    enabled: true\n    method: S256\n",
                    yaml_quote(issuer)
                )
            })
            .unwrap_or_default();
        let content = format!(
            "server_url: {server_url}\nlisten_addr: {listen}\nmetrics_listen_addr: 127.0.0.1:9090\n# Caddy 与 Headscale 在同一容器内，只有回环反代可以提交真实客户端 IP。\ntrusted_proxies:\n  - 127.0.0.1/32\n  - ::1/128\nnoise:\n  private_key_path: {noise}\nprefixes:\n  v4: 100.64.0.0/10\n  v6: fd7a:115c:a1e0::/48\nderp:\n{derp_config}\n  update_frequency: 3h\ndatabase:\n  type: sqlite\n  sqlite:\n    path: {database}\npolicy:\n  # Headscale 0.29.x 只有 database 模式支持通过官方 API 更新策略。\n  mode: database\nnode:\n  expiry: 0\n{oidc_config}dns:\n  magic_dns: true\n  base_domain: {dns_domain}\n  override_local_dns: true\n  nameservers:\n    # Headscale 0.29.x 在 override_local_dns 开启时要求至少一个上游 DNS。\n    # MagicDNS 仍负责 mesh.nexo.internal，其他名称交给这些公共解析器。\n    global:\n      - 1.1.1.1\n      - 1.0.0.1\n      - 2606:4700:4700::1111\n      - 2606:4700:4700::1001\n    split: {{}}\n  search_domains: []\n  extra_records: []\nunix_socket: {unix_socket}\nunix_socket_permission: \"0600\"\nlog:\n  level: info\n",
            server_url = yaml_quote(server_url),
            listen = yaml_quote(&self.config.listen_addr),
            noise = yaml_quote(&noise_key_path.to_string_lossy()),
            database = yaml_quote(&database_path.to_string_lossy()),
            dns_domain = yaml_quote(&self.config.dns_base_domain),
            unix_socket = yaml_quote(&unix_socket_path.to_string_lossy()),
            oidc_config = oidc_config,
        );
        let temporary = self.config.config_path().with_extension("yaml.tmp");
        fs::write(&temporary, content)?;
        fs::rename(temporary, self.config.config_path())?;
        Ok(())
    }

    /// 根域名修改后同步 Headscale 的设备登录地址。
    ///
    /// Headscale 只在启动时读取 `server_url`，因此先写入配置，再通知
    /// Supervisor 优雅重启子进程。重启期间 Nexo HTTP 与 TCP Tunnel 不受影响。
    pub async fn update_server_url(&self, server_url: impl Into<String>) -> Result<()> {
        let server_url = server_url.into().trim_end_matches('/').to_owned();
        if !(server_url.starts_with("https://") || server_url.starts_with("http://")) {
            return Err(anyhow!("Headscale 公网地址必须使用 HTTP 或 HTTPS"));
        }
        if server_url.len() <= 8 {
            return Err(anyhow!("Headscale 公网地址不能为空"));
        }
        {
            let mut current = self
                .server_url
                .write()
                .map_err(|_| anyhow!("Headscale 公网地址锁不可用"))?;
            if *current == server_url {
                return Ok(());
            }
            *current = server_url;
        }
        self.write_config()?;
        if self.config.enabled {
            self.restart_requested.store(true, Ordering::SeqCst);
            self.shutdown_notify.notify_one();
        }
        Ok(())
    }

    /// 更新 Headscale 使用的 OIDC issuer。已有 issuer 只能保持不变，避免
    /// 主域名迁移把现有 OIDC 用户的 providerId 变成另一套身份。
    pub async fn update_oidc_issuer(&self, issuer: Option<String>) -> Result<()> {
        let issuer = issuer.map(|value| value.trim_end_matches('/').to_owned());
        {
            let mut current = self
                .oidc_issuer
                .write()
                .map_err(|_| anyhow!("Headscale OIDC issuer 锁不可用"))?;
            match (&*current, &issuer) {
                (Some(existing), Some(next)) if existing != next => {
                    return Err(anyhow!(
                        "Headscale OIDC issuer 已固定为 {existing}，不能改为 {next}"
                    ));
                }
                (Some(_), None) => return Ok(()),
                _ => *current = issuer,
            }
        }
        self.write_config()?;
        if self.config.enabled {
            self.restart_requested.store(true, Ordering::SeqCst);
            self.shutdown_notify.notify_one();
        }
        Ok(())
    }

    /// 启动已配置的 Headscale；未启用时返回 None，方便本地开发运行 Server。
    pub async fn start(self: Arc<Self>) -> Result<MeshComponentStatus> {
        if !self.config.enabled {
            return Ok(MeshComponentStatus::Starting);
        }
        self.write_config()?;
        self.stopping.store(false, Ordering::SeqCst);
        self.restart_requested.store(false, Ordering::SeqCst);
        // 首次启动失败不能拖垮 Nexo Core；监控循环会以指数退避重试，
        // 让 LAN 管理、Agent 注册和公网 TCP Tunnel 先继续提供服务。
        if let Err(error) = self.spawn_once().await {
            tracing::error!("Headscale 首次启动失败，将在后台自动重试：{error:#}");
        }
        let supervisor = self.clone();
        tokio::spawn(async move {
            supervisor.monitor_loop().await;
        });
        Ok(MeshComponentStatus::Starting)
    }

    async fn spawn_once(&self) -> Result<()> {
        let child = Command::new(&self.config.binary)
            .args([
                "serve",
                "--config",
                self.config.config_path().to_string_lossy().as_ref(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| {
                format!(
                    "无法启动 Headscale 子进程：{}",
                    self.config.binary.display()
                )
            })?;
        let mut guard = self.child.lock().await;
        *guard = Some(child);
        tracing::info!(version = HEADSCALE_VERSION, "Headscale 子进程已启动");
        Ok(())
    }

    async fn monitor_loop(&self) {
        let mut attempt = 0_u32;
        while !self.stopping.load(Ordering::SeqCst) {
            // 不要在等待子进程期间持有 Mutex，否则 shutdown 无法取得锁来发送 kill。
            let mut child = {
                let mut guard = self.child.lock().await;
                guard.take()
            };
            let Some(mut child) = child.take() else {
                if self.stopping.load(Ordering::SeqCst) {
                    break;
                }
                attempt = attempt.saturating_add(1);
                let delay = supervisor_backoff(attempt);
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = self.shutdown_notify.notified() => {
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
                    tracing::error!("Headscale 启动重试失败：{error:#}");
                } else {
                    attempt = 0;
                }
                continue;
            };
            enum MonitorSignal {
                Exited(std::io::Result<std::process::ExitStatus>),
                Restart,
                Stop,
            }
            let signal = tokio::select! {
                status = child.wait() => MonitorSignal::Exited(status),
                _ = self.shutdown_notify.notified() => {
                    if let Err(error) = stop_child_gracefully(&mut child).await {
                        tracing::warn!("停止 Headscale 子进程失败：{error:#}");
                    }
                    if self.stopping.load(Ordering::SeqCst) {
                        MonitorSignal::Stop
                    } else if self.restart_requested.swap(false, Ordering::SeqCst) {
                        MonitorSignal::Restart
                    } else {
                        MonitorSignal::Stop
                    }
                }
            };
            let MonitorSignal::Exited(status) = signal else {
                if matches!(signal, MonitorSignal::Stop) {
                    break;
                }
                attempt = 0;
                continue;
            };
            if self.stopping.load(Ordering::SeqCst) {
                break;
            }
            attempt = attempt.saturating_add(1);
            let delay = supervisor_backoff(attempt);
            match status {
                Ok(exit) => tracing::error!(?exit, "Headscale 子进程退出，将在退避后重启"),
                Err(error) => {
                    tracing::error!("等待 Headscale 子进程失败，将在退避后重启：{error:#}")
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = self.shutdown_notify.notified() => break,
            }
            if self.stopping.load(Ordering::SeqCst) {
                break;
            }
            if let Err(error) = self.spawn_once().await {
                tracing::error!("Headscale 重启失败：{error:#}");
            } else {
                attempt = 0;
            }
        }
    }

    /// 优雅停止子进程，避免 Nexo 退出时留下孤儿 Headscale。
    pub async fn shutdown(&self) -> Result<()> {
        self.stopping.store(true, Ordering::SeqCst);
        self.restart_requested.store(false, Ordering::SeqCst);
        // `notify_one` 会保留一个 permit，即使 Supervisor 尚未进入 select；
        // 使用 notify_waiters 可能在这个竞态窗口丢失关闭信号。
        self.shutdown_notify.notify_one();
        let mut guard = self.child.lock().await;
        if let Some(child) = guard.as_mut() {
            stop_child_gracefully(child)
                .await
                .context("无法停止 Headscale 子进程")?;
        }
        *guard = None;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn wait_until_healthy(&self, timeout: Duration) -> Result<()> {
        let started = std::time::Instant::now();
        while started.elapsed() < timeout {
            // Headscale 0.29.x 的 HTTP health 端点也要求 Bearer API Key，
            // 但首次启动时 Key 尚未创建。官方 CLI 通过 Unix Socket 检查
            // 同一进程，更适合用来判断 Supervisor 是否可以继续 Bootstrap。
            let health = tokio::time::timeout(
                Duration::from_secs(3),
                Command::new(&self.config.binary)
                    .args([
                        "--config",
                        self.config.config_path().to_string_lossy().as_ref(),
                        "health",
                    ])
                    .output(),
            )
            .await;
            if matches!(health, Ok(Ok(output)) if output.status.success()) {
                return Ok(());
            }
            if self.stopping.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Err(anyhow!("Headscale 健康检查在 {:?} 内未通过", timeout))
    }
}

/// 先请求 Headscale 正常退出，避免数据库/Unix Socket 在服务端关闭时留下
/// 不完整状态；只有进程在短时间内没有退出，才回退到强制终止并回收子进程。
async fn stop_child_gracefully(child: &mut Child) -> Result<()> {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // `kill` 只向当前 Headscale 子进程发送 SIGTERM，不影响同一容器中的
        // 其他进程；等待超时后再使用 Tokio 的强制终止作为最后兜底。
        let signal_result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if signal_result == 0 {
            match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                Ok(status) => {
                    status?;
                    return Ok(());
                }
                Err(_) => tracing::warn!("Headscale 未在 5 秒内响应 SIGTERM，将强制终止"),
            }
        }
    }

    child.kill().await?;
    let _ = child.wait().await?;
    Ok(())
}

pub fn supervisor_backoff(attempt: u32) -> Duration {
    let exponent = attempt.saturating_sub(1).min(6);
    Duration::from_secs((2_u64.saturating_mul(1 << exponent)).min(120))
}

fn parse_cli_secret(output: &[u8]) -> Option<String> {
    String::from_utf8_lossy(output)
        .lines()
        .map(str::trim)
        .rev()
        .find(|line| !line.is_empty() && !line.contains(' ') && !line.contains('\t'))
        .map(str::to_owned)
}

fn yaml_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn render_derp_config(embedded_enabled: bool, private_key_path: &Path) -> String {
    if embedded_enabled {
        format!(
            "  # 仅供集成测试使用：DERP 通过现有 HTTPS 入口提供，STUN 监听测试网络。\n  server:\n    enabled: true\n    region_id: 900\n    region_code: nexo-integration\n    region_name: Nexo Integration\n    verify_clients: true\n    stun_listen_addr: 0.0.0.0:3478\n    private_key_path: {}\n    automatically_add_embedded_derp_region: true\n  urls: []\n  paths: []\n  auto_update_enabled: false",
            yaml_quote(&private_key_path.to_string_lossy())
        )
    } else {
        format!(
            "  server:\n    enabled: false\n  # 使用官方默认地图提供 NAT 穿透回退；可达节点优先走 WireGuard 直连。\n  urls:\n    - {}\n  paths: []\n  auto_update_enabled: true",
            yaml_quote(DEFAULT_DERP_MAP_URL)
        )
    }
}

fn set_private_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_starts_at_fourteen_days() {
        let now = 1_000_000;
        assert!(!ApiKeyManager::needs_rotation(
            now + 14 * 24 * 60 * 60 + 1,
            now
        ));
        assert!(ApiKeyManager::needs_rotation(now + 14 * 24 * 60 * 60, now));
    }

    #[test]
    fn backoff_is_bounded_and_exponential() {
        assert_eq!(supervisor_backoff(1), Duration::from_secs(2));
        assert_eq!(supervisor_backoff(3), Duration::from_secs(8));
        assert_eq!(supervisor_backoff(99), Duration::from_secs(120));
    }

    #[test]
    fn cli_secret_parser_does_not_accept_spaced_output() {
        assert_eq!(parse_cli_secret(b"API key: hskey-abc\n"), None);
        assert_eq!(
            parse_cli_secret(b"hskey-abc\n"),
            Some("hskey-abc".to_owned())
        );
    }

    #[test]
    fn production_derp_config_uses_official_map_and_auto_update() {
        let sources = render_derp_config(false, Path::new("/unused"));
        assert!(sources.contains("enabled: false"));
        assert!(sources.contains(DEFAULT_DERP_MAP_URL));
        assert!(sources.contains("paths: []"));
        assert!(sources.contains("auto_update_enabled: true"));
    }

    #[test]
    fn integration_derp_config_enables_embedded_server_without_external_map() {
        let sources = render_derp_config(true, Path::new("/data/nexo/headscale/derp.key"));
        assert!(sources.contains("enabled: true"));
        assert!(sources.contains("stun_listen_addr: 0.0.0.0:3478"));
        assert!(sources.contains("private_key_path: '/data/nexo/headscale/derp.key'"));
        assert!(sources.contains("urls: []"));
        assert!(sources.contains("auto_update_enabled: false"));
        assert!(!sources.contains(DEFAULT_DERP_MAP_URL));
    }

    #[test]
    fn generated_config_trusts_only_loopback_reverse_proxy() {
        let root = std::env::temp_dir().join(format!("nexo-headscale-{}", uuid::Uuid::new_v4()));
        let config = HeadscaleRuntimeConfig {
            binary: PathBuf::from("headscale"),
            data_dir: root.clone(),
            listen_addr: "127.0.0.1:8281".to_owned(),
            api_url: "http://127.0.0.1:8281".to_owned(),
            server_url: "https://mesh.example.com".to_owned(),
            oidc_issuer: Some("https://nexo.example.com".to_owned()),
            dns_base_domain: "mesh.nexo.internal".to_owned(),
            embedded_derp_enabled: false,
            enabled: false,
        };
        HeadscaleSupervisor::new(config)
            .write_config()
            .expect("应生成 Headscale 配置");
        let content =
            fs::read_to_string(root.join("headscale").join("config.yaml")).expect("应读取配置");
        assert!(content.contains("trusted_proxies:\n  - 127.0.0.1/32\n  - ::1/128"));
        let _ = fs::remove_dir_all(root);
    }
}
