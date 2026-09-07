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
    io::{AsyncBufReadExt, AsyncRead, BufReader},
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
    /// 多域名 Secret 根目录；Supervisor 会把每个域名的 Token 以独立
    /// 环境变量注入 Caddy，避免不同 Cloudflare 账号互相覆盖。
    pub cloudflare_token_root: PathBuf,
    /// Caddy 自动 HTTPS 的持久化 storage 根目录，包含 ACME 账号、证书
    /// 和续期状态；容器重建后必须保持不变。
    pub storage_root: PathBuf,
    pub admin_url: String,
    pub enabled: bool,
}

/// Caddy JSON 日志中与 ACME 生命周期有关的公开字段。
///
/// 日志解析只保留状态和域名标识，不保存 Token、证书正文或完整日志正文；
/// `message` 也会在进入数据库前由 Server 截断，避免错误详情无限增长。
#[derive(Debug, Clone, Default)]
pub struct CaddyLogEvent {
    pub level: Option<String>,
    pub message: String,
    pub identifier: Option<String>,
    pub status_code: Option<u16>,
    pub retry_after_secs: Option<u64>,
}

impl CaddyLogEvent {
    pub fn is_rate_limited(&self) -> bool {
        self.status_code == Some(429)
            || self.message.to_ascii_lowercase().contains("rate limit")
            || self
                .message
                .to_ascii_lowercase()
                .contains("too many certificates")
            || self.message.to_ascii_lowercase().contains("retry-after")
    }

    /// 将 Caddy 可观察日志映射为离散阶段，不伪造 Caddy 未提供的百分比。
    pub fn certificate_stage(&self) -> Option<&'static str> {
        let message = self.message.to_ascii_lowercase();
        if self.is_rate_limited()
            || self.retry_after_secs.is_some()
            || message.contains("will retry")
            || message.contains("retrying in")
        {
            return Some("retry_wait");
        }
        if message.contains("presenting") && message.contains("challenge") {
            return Some("presenting_dns");
        }
        if message.contains("propagation") || message.contains("dns record") {
            return Some("waiting_dns");
        }
        if message.contains("validating")
            || message.contains("authorization")
            || message.contains("challenge accepted")
        {
            return Some("validating");
        }
        if message.contains("certificate obtained") || message.contains("downloaded certificate") {
            return Some("issued");
        }
        if message.contains("certificate loaded")
            || message.contains("finished cleaning storage units")
        {
            return Some("active");
        }
        if message.contains("obtaining certificate") || message.contains("acme client") {
            return Some("waiting_configuration");
        }
        if self.level.as_deref() == Some("error")
            || self.status_code.is_some_and(|code| code >= 400)
        {
            return Some("failed");
        }
        None
    }
}

/// 解析 Caddy 默认 JSON 日志；纯文本日志也会保留为可读事件，便于用户
/// 在没有 jq 等工具时仍能看到中文状态提示。未知字段全部忽略。
pub fn parse_caddy_log_line(line: &str) -> Option<CaddyLogEvent> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        let message = line.to_owned();
        let event = CaddyLogEvent {
            status_code: parse_status_code(&message),
            retry_after_secs: parse_retry_after(&message),
            identifier: None,
            level: None,
            message,
        };
        return Some(event);
    };
    let object = value.as_object()?;
    let summary = object
        .get("msg")
        .and_then(Value::as_str)
        .or_else(|| object.get("message").and_then(Value::as_str));
    let detail = object.get("error").and_then(|value| {
        value.as_str().or_else(|| {
            value.as_object().and_then(|error| {
                error
                    .get("message")
                    .and_then(Value::as_str)
                    .or_else(|| error.get("msg").and_then(Value::as_str))
            })
        })
    });
    // Caddy 的 `msg` 往往只是“获取证书失败”，真正的 Cloudflare/ACME
    // 原因在 `error`。两者都保留，避免 UI 被笼统摘要覆盖。
    let message = match (summary, detail) {
        (Some(summary), Some(detail)) if summary != detail => format!("{summary}：{detail}"),
        (Some(summary), _) => summary.to_owned(),
        (_, Some(detail)) => detail.to_owned(),
        _ => line.to_owned(),
    };
    let identifier = ["identifier", "domain", "host"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
        .map(str::to_owned);
    let status_code = ["status", "status_code", "statusCode"]
        .iter()
        .find_map(|key| object.get(*key).and_then(parse_u16_value))
        .or_else(|| parse_status_code(&message));
    let retry_after_secs = ["retry_after", "retry-after", "retryAfter", "retrying_in"]
        .iter()
        .find_map(|key| object.get(*key).and_then(parse_u64_value))
        .or_else(|| parse_retry_after(&message));
    Some(CaddyLogEvent {
        level: object
            .get("level")
            .and_then(Value::as_str)
            .map(str::to_owned),
        message,
        identifier,
        status_code,
        retry_after_secs,
    })
}

fn parse_u16_value(value: &Value) -> Option<u16> {
    value
        .as_u64()
        .and_then(|number| u16::try_from(number).ok())
        .or_else(|| value.as_str()?.parse().ok())
}

fn parse_u64_value(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_f64().map(|number| number.ceil() as u64))
        .or_else(|| parse_duration_seconds(value.as_str()?))
}

fn parse_duration_seconds(value: &str) -> Option<u64> {
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds);
    }
    let mut total = 0u64;
    let mut number = String::new();
    let mut parsed = false;
    for character in value.chars() {
        if character.is_ascii_digit() {
            number.push(character);
            continue;
        }
        let multiplier = match character {
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => continue,
        };
        let amount = number.parse::<u64>().ok()?;
        total = total.saturating_add(amount.saturating_mul(multiplier));
        number.clear();
        parsed = true;
    }
    parsed.then_some(total)
}

fn parse_status_code(message: &str) -> Option<u16> {
    message
        .split(|character: char| !character.is_ascii_digit())
        .find_map(|part| {
            let value = part.parse::<u16>().ok()?;
            (value == 429 || (400..=599).contains(&value)).then_some(value)
        })
}

fn parse_retry_after(message: &str) -> Option<u64> {
    let lower = message.to_ascii_lowercase();
    for marker in ["retry-after", "retry_after", "retry after", "retry in"] {
        let Some(index) = lower.find(marker) else {
            continue;
        };
        if let Some(value) = lower[index + marker.len()..]
            .split(|character: char| !character.is_ascii_digit())
            .find_map(|part| part.parse::<u64>().ok())
        {
            return Some(value);
        }
    }
    None
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
            cloudflare_token_root: data_dir.join("secrets").join("public-domains"),
            storage_root: data_dir.join("caddy-storage"),
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
    /// 日志读取任务只把结构化事件放入短队列，Server 协调周期负责消费。
    log_events: Arc<Mutex<Vec<CaddyLogEvent>>>,
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
            log_events: Arc::new(Mutex::new(Vec::new())),
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
        fs::create_dir_all(&self.config.storage_root).with_context(|| {
            format!(
                "无法创建 Caddy 持久化目录：{}",
                self.config.storage_root.display()
            )
        })?;
        set_private_directory(&self.config.storage_root).with_context(|| {
            format!(
                "无法设置 Caddy 持久化目录权限：{}",
                self.config.storage_root.display()
            )
        })?;
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
        // 多域名模式为每个 Secret 目录注入独立变量。目录名来自 Server
        // 生成的 UUID，不接受用户输入，因此不会产生可注入的环境变量名。
        let mut domain_token_digests = Vec::new();
        for (id, token) in read_domain_tokens(&self.config.cloudflare_token_root) {
            let env_name = format!(
                "NEXO_CLOUDFLARE_TOKEN_{}",
                sanitize_env_suffix(&id.to_ascii_uppercase())
            );
            command.env(&env_name, &token);
            domain_token_digests.push((env_name, hex::encode(Sha256::digest(token.as_bytes()))));
        }
        // JSON 是 Caddy 原生配置格式；只有非原生格式才需要指定适配器。
        let mut child = command
            .args([
                "run",
                "--config",
                self.config.config_path.to_string_lossy().as_ref(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("无法启动 Caddy：{}", self.config.binary.display()))?;
        if let Some(stdout) = child.stdout.take() {
            spawn_caddy_log_reader(stdout, Arc::clone(&self.log_events), "stdout");
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_caddy_log_reader(stderr, Arc::clone(&self.log_events), "stderr");
        }
        *self.child.lock().await = Some(child);
        // 旧单例摘要与多域名摘要共同参与重启检测；摘要本身不含 Secret。
        let mut digest = token_digest.unwrap_or_default();
        for (name, value) in domain_token_digests {
            digest.push('|');
            digest.push_str(&name);
            digest.push('=');
            digest.push_str(&value);
        }
        *self.token_digest.lock().await = (!digest.is_empty()).then_some(digest);
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
        let legacy = fs::read_to_string(&self.config.cloudflare_token_path)
            .ok()
            .map(|token| token.trim().to_owned())
            .filter(|token| !token.is_empty())
            .map(|token| hex::encode(Sha256::digest(token.as_bytes())));
        let mut digest = legacy.unwrap_or_default();
        for (id, token) in read_domain_tokens(&self.config.cloudflare_token_root) {
            digest.push('|');
            digest.push_str(&format!(
                "NEXO_CLOUDFLARE_TOKEN_{}",
                sanitize_env_suffix(&id.to_ascii_uppercase())
            ));
            digest.push('=');
            digest.push_str(&hex::encode(Sha256::digest(token.as_bytes())));
        }
        let current = (!digest.is_empty()).then_some(digest);
        let mut previous = self.token_digest.lock().await;
        if *previous == current {
            return false;
        }
        *previous = current;
        true
    }

    /// 取出最近一轮协调前累积的 Caddy 事件。队列本身不跨重启持久化，
    /// 真正需要恢复的证书/ACME 状态仍由 Caddy storage 负责。
    pub async fn drain_log_events(&self) -> Vec<CaddyLogEvent> {
        let mut events = self.log_events.lock().await;
        std::mem::take(&mut *events)
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

fn spawn_caddy_log_reader<R>(
    reader: R,
    events: Arc<Mutex<Vec<CaddyLogEvent>>>,
    stream: &'static str,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        loop {
            let line = match lines.next_line().await {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(stream, "读取 Caddy 日志失败：{error}");
                    break;
                }
            };
            let Some(event) = parse_caddy_log_line(&line) else {
                continue;
            };
            if event.is_rate_limited() {
                tracing::warn!(
                    stream,
                    identifier = event.identifier.as_deref().unwrap_or("未知域名"),
                    "Caddy 报告 CA 限流：{}",
                    event.message
                );
            } else if event.level.as_deref() == Some("error") {
                tracing::error!(
                    stream,
                    identifier = event.identifier.as_deref().unwrap_or("未知域名"),
                    "Caddy 证书处理错误：{}",
                    event.message
                );
            }
            let mut queue = events.lock().await;
            if queue.len() >= 128 {
                queue.remove(0);
            }
            queue.push(event);
        }
    });
}

fn sanitize_env_suffix(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

/// 以稳定顺序读取各域名 Token，保证 Supervisor 的环境摘要不会因为
/// `read_dir` 返回顺序变化而误判凭据已更新并反复重启 Caddy。
fn read_domain_tokens(root: &Path) -> Vec<(String, String)> {
    let Ok(mut entries) = fs::read_dir(root).map(|entries| entries.flatten().collect::<Vec<_>>())
    else {
        return Vec::new();
    };
    entries.sort_by_key(|left| left.file_name());
    entries
        .into_iter()
        .filter_map(|entry| {
            let id = entry.file_name().to_string_lossy().to_string();
            let token = fs::read_to_string(entry.path().join("cloudflare.token"))
                .ok()?
                .trim()
                .to_owned();
            (!token.is_empty()).then_some((id, token))
        })
        .collect()
}

fn set_private_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
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
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32", "::1/128"]},
            "trusted_proxies_strict": 1,
            "routes": http_routes
        }),
    );
    if https_enabled {
        let mut https_server = json!({
            "listen": [":443"],
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32", "::1/128"]},
            "trusted_proxies_strict": 1,
            "routes": https_routes
        });
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
            }] },
            "certificates": { "automate": [domain, format!("*.{domain}")] }
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
    if name == "mesh" {
        // Headscale 官方反代要求回传真实客户端 IP；Caddy reverse_proxy
        // 默认保留 POST 和任意 Upgrade 值（包括 tailscale-control-protocol），
        // 这里只覆盖由客户端伪造的地址头。
        route["handle"][0]["headers"] = json!({
            "request": {
                "set": {
                    "True-Client-IP": ["{http.request.remote.host}"],
                    "X-Real-IP": ["{http.request.remote.host}"]
                }
            }
        });
    } else if public_entry {
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

/// 一个域名及其证书策略；每个域名都独立配置 DNS Provider 和 Secret。
#[derive(Debug, Clone)]
pub struct CaddyDomain {
    pub id: String,
    pub domain: String,
    pub https_enabled: bool,
    pub certificate_mode: String,
    pub acme_environment: String,
    pub secret_dir: PathBuf,
    pub token_env: Option<String>,
    pub https_ready: bool,
    /// 只有主域名或迁移期间保留旧别名的域名才暴露 `nexo`、`mesh`
    /// 和根域名入口；附加域名只承载显式绑定的 Web Service。
    pub system_entry: bool,
}

/// 绑定到具体域名的 Web Service。TCP Tunnel 不进入 Caddy 路由，因此
/// 这里仅承载 HTTP/HTTPS 服务的 Socket 和公开子域名前缀。
#[derive(Debug, Clone)]
pub struct CaddyBoundTunnel {
    /// 使用数据库稳定 ID 绑定域名，避免把 ID 与可变的 DNS 名称混用后
    /// 静默过滤全部服务路由。
    pub domain_id: String,
    pub tunnel: CaddyTunnel,
}

/// 生成多域名 Caddy JSON。系统入口在每个保留域名上都保留，便于主域名
/// 迁移期间旧地址继续可达；只有主域名会被 Headscale 作为规范登录地址使用。
pub fn build_multi_caddy_config(
    domains: &[CaddyDomain],
    tunnels: &[CaddyBoundTunnel],
    storage_root: &Path,
) -> Value {
    if domains.is_empty() {
        return json!({
            "admin": { "listen": "127.0.0.1:8290" },
            "storage": { "module": "file_system", "root": storage_root },
            "apps": { "http": { "servers": {} } }
        });
    }
    let mut http_routes = Vec::new();
    let mut https_routes = Vec::new();
    let mut policies = Vec::new();
    let mut automatic_subjects = Vec::new();
    let mut manual_certificates = Vec::new();
    for domain in domains {
        let name = domain.domain.as_str();
        let bound = tunnels.iter().filter(|item| item.domain_id == domain.id);
        let http_services = bound
            .clone()
            .filter(|item| item.tunnel.enabled && item.tunnel.protocol == "http");
        let https_services =
            bound.filter(|item| item.tunnel.enabled && item.tunnel.protocol == "https");
        http_routes.extend(
            http_services
                .clone()
                .filter_map(|item| tunnel_route(&item.tunnel, name)),
        );
        if domain.https_enabled {
            if domain.https_ready {
                if domain.system_entry {
                    http_routes.push(json!({
                        "match": [{"host": [name]}],
                        "handle": [{"handler": "static_response", "status_code": 308,
                            "headers": {"Location": [format!("https://nexo.{name}")]}}]
                    }));
                    http_routes.push(redirect_route(
                        &format!("nexo.{name}"),
                        &format!("https://nexo.{name}"),
                    ));
                    http_routes.push(redirect_route(
                        &format!("mesh.{name}"),
                        &format!("https://mesh.{name}"),
                    ));
                }
                http_routes.extend(
                    https_services
                        .clone()
                        .filter_map(|item| https_redirect_route(&item.tunnel, name)),
                );
            }
            if domain.system_entry {
                https_routes.push(system_route(name, "nexo", "127.0.0.1:9888", true, true));
                https_routes.push(system_route(name, "mesh", "127.0.0.1:8281", false, false));
                https_routes.push(redirect_route(name, &format!("https://nexo.{name}")));
            }
            https_routes.extend(https_services.filter_map(|item| tunnel_route(&item.tunnel, name)));
            https_routes.push(json!({
                "match": [{"host": [format!("*.{name}")]}],
                "handle": [{"handler": "static_response", "status_code": 404}]
            }));
            if domain.certificate_mode == "cloudflare" {
                policies.push(domain_tls_policy(domain));
                automatic_subjects.push(domain.domain.clone());
                automatic_subjects.push(format!("*.{}", domain.domain));
            }
            if domain.certificate_mode == "manual" {
                manual_certificates.push(json!({
                    "certificate": domain.secret_dir.join("certificate.pem"),
                    "key": domain.secret_dir.join("private-key.pem"),
                    "tags": [format!("nexo-manual-{}", domain.id)]
                }));
            }
        } else if domain.system_entry {
            http_routes.push(system_route(name, "nexo", "127.0.0.1:9888", true, true));
        }
    }
    let mut servers = serde_json::Map::new();
    servers.insert(
        "http".to_owned(),
        json!({
            "listen": [":80"], "automatic_https": {"disable": true},
            "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32", "::1/128"]},
            "trusted_proxies_strict": 1, "routes": http_routes
        }),
    );
    if !https_routes.is_empty() {
        servers.insert(
            "https".to_owned(),
            json!({
                "listen": [":443"],
                "trusted_proxies": {"source": "static", "ranges": ["127.0.0.1/32", "::1/128"]},
                "trusted_proxies_strict": 1,
                "routes": https_routes
            }),
        );
    }
    let mut config = json!({
        "admin": { "listen": "127.0.0.1:8290" },
        "storage": { "module": "file_system", "root": storage_root },
        "apps": { "http": { "servers": servers } }
    });
    if !policies.is_empty() {
        config["apps"]["tls"] = json!({
            "automation": { "policies": policies },
            "certificates": { "automate": automatic_subjects }
        });
    }
    if !manual_certificates.is_empty() {
        config["apps"]["tls"]["certificates"]["load_files"] = json!(manual_certificates);
    }
    config
}

fn domain_tls_policy(domain: &CaddyDomain) -> Value {
    let subjects = vec![domain.domain.clone(), format!("*.{}", domain.domain)];
    let mut issuer = json!({
        "module": "acme",
        "challenges": {"dns": {"provider": {"name": "cloudflare",
            "api_token": domain.token_env.as_deref().unwrap_or("{env.NEXO_CLOUDFLARE_API_TOKEN}")}}}
    });
    if domain.acme_environment.eq_ignore_ascii_case("staging") {
        issuer["ca"] = json!(ACME_STAGING_DIRECTORY);
    }
    json!({ "subjects": subjects, "issuers": [issuer] })
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
    fn parses_caddy_rate_limit_log_and_retry_after() {
        let event = parse_caddy_log_line(
            r#"{"level":"error","msg":"could not obtain certificate: HTTP 429; Retry-After: 120","identifier":"*.example.com","status_code":429}"#,
        )
        .expect("JSON 日志应能解析");
        assert_eq!(event.identifier.as_deref(), Some("*.example.com"));
        assert_eq!(event.status_code, Some(429));
        assert_eq!(event.retry_after_secs, Some(120));
        assert!(event.is_rate_limited());
    }

    #[test]
    fn keeps_detailed_acme_error_and_parses_caddy_retrying_in() {
        let event = parse_caddy_log_line(
            r#"{"level":"error","msg":"could not get certificate","error":"cloudflare: authentication error for *.example.com","identifier":"*.example.com","retrying_in":"2m30s"}"#,
        )
        .expect("Caddy ACME 日志应能解析");
        assert!(event.message.contains("could not get certificate"));
        assert!(event.message.contains("cloudflare: authentication error"));
        assert_eq!(event.retry_after_secs, Some(150));
        assert_eq!(event.certificate_stage(), Some("retry_wait"));
    }

    #[test]
    fn parses_plain_caddy_error_without_exposing_unknown_fields() {
        let event = parse_caddy_log_line("certificate request failed: HTTP 503")
            .expect("纯文本日志应保留为事件");
        assert_eq!(event.status_code, Some(503));
        assert!(!event.is_rate_limited());
    }

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
            config["apps"]["tls"]["certificates"]["automate"],
            json!(["example.com", "*.example.com"])
        );
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
    fn headscale_route_sets_trusted_client_headers_without_rewriting_upgrade() {
        let config = build_multi_caddy_config(
            &[CaddyDomain {
                id: "primary".to_owned(),
                domain: "example.com".to_owned(),
                https_enabled: true,
                certificate_mode: "manual".to_owned(),
                acme_environment: "production".to_owned(),
                secret_dir: PathBuf::from("/data/secrets/primary"),
                token_env: None,
                https_ready: true,
                system_entry: true,
            }],
            &[],
            Path::new("/data/nexo/caddy-storage"),
        );
        let route = config["apps"]["http"]["servers"]["https"]["routes"]
            .as_array()
            .expect("HTTPS 路由应为数组")
            .iter()
            .find(|route| route["match"][0]["host"][0] == "mesh.example.com")
            .expect("应生成 Headscale mesh 路由");
        let handler = &route["handle"][0];
        assert_eq!(
            handler["headers"]["request"]["set"]["True-Client-IP"][0],
            "{http.request.remote.host}"
        );
        assert_eq!(
            handler["headers"]["request"]["set"]["X-Real-IP"][0],
            "{http.request.remote.host}"
        );
        // 不手动重写 Upgrade/Connection；Caddy 官方 reverse_proxy 会
        // 自动转发自定义的 tailscale-control-protocol 升级请求和 POST。
        assert!(handler.get("headers").is_some());
        assert!(handler.get("transport").is_none());
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
            cloudflare_token_root: root.join("public-domains"),
            storage_root: root.join("caddy-storage"),
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

    #[test]
    fn multi_domain_config_keeps_independent_tls_policies_and_manual_files() {
        let config = build_multi_caddy_config(
            &[
                CaddyDomain {
                    id: "domain-a".to_owned(),
                    domain: "a.example.com".to_owned(),
                    https_enabled: true,
                    certificate_mode: "cloudflare".to_owned(),
                    acme_environment: "production".to_owned(),
                    secret_dir: PathBuf::from("/data/secrets/domain-a"),
                    token_env: Some("{env.NEXO_CLOUDFLARE_TOKEN_DOMAIN_A}".to_owned()),
                    https_ready: true,
                    system_entry: true,
                },
                CaddyDomain {
                    id: "domain-b".to_owned(),
                    domain: "b.example.com".to_owned(),
                    https_enabled: true,
                    certificate_mode: "manual".to_owned(),
                    acme_environment: "production".to_owned(),
                    secret_dir: PathBuf::from("/data/secrets/domain-b"),
                    token_env: None,
                    https_ready: true,
                    system_entry: false,
                },
            ],
            &[CaddyBoundTunnel {
                domain_id: "domain-b".to_owned(),
                tunnel: CaddyTunnel {
                    hostname: Some("app".to_owned()),
                    bridge_socket: "/data/tunnels/app.sock".to_owned(),
                    protocol: "https".to_owned(),
                    enabled: true,
                },
            }],
            Path::new("/data/nexo/caddy-storage"),
        );
        assert_eq!(config["storage"]["root"], json!("/data/nexo/caddy-storage"));
        assert_eq!(
            config["apps"]["http"]["servers"]["http"]["trusted_proxies_strict"],
            json!(1),
            "Caddy 2.11 原生 JSON 使用整数表示严格代理解析开关"
        );
        assert_eq!(
            config["apps"]["http"]["servers"]["https"]["trusted_proxies_strict"],
            json!(1)
        );
        let policies = config["apps"]["tls"]["automation"]["policies"]
            .as_array()
            .expect("Cloudflare 域名应生成独立 TLS policy");
        assert_eq!(policies.len(), 1);
        assert_eq!(
            policies[0]["subjects"],
            json!(["a.example.com", "*.a.example.com"])
        );
        assert_eq!(
            policies[0]["issuers"][0]["challenges"]["dns"]["provider"]["api_token"],
            "{env.NEXO_CLOUDFLARE_TOKEN_DOMAIN_A}"
        );
        assert_eq!(
            config["apps"]["tls"]["certificates"]["automate"],
            json!(["a.example.com", "*.a.example.com"]),
            "自动证书主题和手动证书文件必须同时保留"
        );
        let certificate_path = config["apps"]["tls"]["certificates"]["load_files"][0]
            ["certificate"]
            .as_str()
            .expect("手动证书路径应为字符串")
            .replace('\\', "/");
        assert_eq!(certificate_path, "/data/secrets/domain-b/certificate.pem");
        assert!(config.to_string().contains("app.b.example.com"));
        let routes = config["apps"]["http"]["servers"]["https"]["routes"]
            .as_array()
            .expect("HTTPS 路由应为数组");
        let exact = routes
            .iter()
            .position(|route| route["match"][0]["host"] == json!(["app.b.example.com"]))
            .expect("绑定服务应生成精确路由");
        let fallback = routes
            .iter()
            .position(|route| route["match"][0]["host"] == json!(["*.b.example.com"]))
            .expect("域名应生成泛域名 404 兜底");
        assert!(exact < fallback, "精确服务路由必须位于泛域名兜底之前");
    }
}
