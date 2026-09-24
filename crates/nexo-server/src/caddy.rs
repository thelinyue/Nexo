//! Caddy 公网入口 Supervisor 与结构化配置生成。
//!
//! Caddy 是独立的边缘组件：它负责 HTTP/HTTPS 终止和 Web Service 路由，
//! 但不能成为账号管理或 TCP Tunnel 的启动前置。配置始终先
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
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, BufReader},
    process::{Child, Command},
    sync::{Mutex, Notify},
};

pub const CADDY_VERSION: &str = "2.11.4";
pub const XCADDY_VERSION: &str = "0.4.7";
pub const CLOUDFLARE_MODULE_VERSION: &str = "0.2.4";

#[derive(Debug, Clone)]
pub struct CaddyRuntimeConfig {
    pub binary: PathBuf,
    pub config_path: PathBuf,
    pub applied_path: PathBuf,
    /// 按域名隔离的 Secret 根目录；Caddy 通过文件占位引用读取，配置与日志不保存明文。
    pub cloudflare_token_root: PathBuf,
    /// Caddy 自动 HTTPS 的持久化 storage 根目录，包含 ACME 账号、证书
    /// 和续期状态；容器重建后必须保持不变。
    pub storage_root: PathBuf,
    pub admin_url: String,
    pub enabled: bool,
    pub http_listen: String,
    pub https_listen: String,
}

/// Caddy JSON 日志中与 ACME 生命周期有关的公开字段。
///
/// 日志解析只保留状态和域名标识，不保存 Token、证书正文或完整日志正文；
/// `message` 也会在进入数据库前由 Server 截断，避免错误详情无限增长。
#[derive(Debug, Clone, Default)]
pub struct CaddyLogEvent {
    pub level: Option<String>,
    pub logger: Option<String>,
    pub message: String,
    pub identifier: Option<String>,
    pub status_code: Option<u16>,
    pub retry_after_secs: Option<u64>,
    pub occurred_at: Option<i64>,
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
        if self.level.as_deref() == Some("error")
            || self.status_code.is_some_and(|code| code >= 400)
        {
            return Some("failed");
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
        if message.contains("certificate obtained")
            || message.contains("downloaded certificate")
            || message.contains("certificate renewed")
        {
            return Some("issued");
        }
        if message.contains("certificate loaded") {
            return Some("active");
        }
        if message.contains("renewing certificate") {
            return Some("renewing");
        }
        if message.contains("obtaining certificate") || message.contains("acme client") {
            return Some("waiting_configuration");
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
            logger: None,
            occurred_at: None,
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
        _ => "Caddy 运行事件".to_owned(),
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
        logger: object
            .get("logger")
            .and_then(Value::as_str)
            .map(str::to_owned),
        message,
        identifier,
        status_code,
        retry_after_secs,
        occurred_at: object.get("ts").and_then(Value::as_f64).map(|ts| ts as i64),
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
    // 错误中的 :443 等端口不是 HTTP 状态码，不能把普通验证进度误判为失败。
    let lower = message.to_ascii_lowercase();
    [
        "http ",
        "http/1.1 ",
        "http/2 ",
        "status ",
        "status:",
        "status_code:",
    ]
    .iter()
    .find_map(|marker| {
        let index = lower.find(marker)? + marker.len();
        let code = lower[index..]
            .trim_start()
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse::<u16>()
            .ok()?;
        (400..=599).contains(&code).then_some(code)
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
            .unwrap_or(true);
        Self {
            binary,
            config_path: data_dir.join("caddy").join("config.json"),
            applied_path: data_dir.join("caddy").join("applied.json"),
            cloudflare_token_root: data_dir.join("secrets").join("public-domains"),
            storage_root: data_dir.join("caddy-storage"),
            admin_url: env::var("NEXO_CADDY_ADMIN_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8290".to_owned()),
            enabled,
            http_listen: env::var("NEXO_CADDY_HTTP_LISTEN").unwrap_or_else(|_| ":80".into()),
            https_listen: env::var("NEXO_CADDY_HTTPS_LISTEN").unwrap_or_else(|_| ":443".into()),
        }
    }
}

#[derive(Debug)]
pub struct CaddySupervisor {
    config: CaddyRuntimeConfig,
    child: Arc<Mutex<Option<Child>>>,
    stopping: Arc<AtomicBool>,
    notify: Arc<Notify>,
    /// 只保存 Token 摘要，用于检测 Secret 更新；绝不把明文写入状态或日志。
    token_digest: Arc<Mutex<Option<String>>>,
    /// 日志读取任务只把结构化事件放入短队列，Server 协调周期负责消费。
    log_events: Arc<Mutex<Vec<CaddyLogEvent>>>,
    /// 保存无法启动、端口占用等进程错误，管理接口不可达时仍能提供具体原因。
    process_error: Arc<Mutex<Option<String>>>,
}

impl CaddySupervisor {
    pub fn new(config: CaddyRuntimeConfig) -> Self {
        Self {
            config,
            child: Arc::new(Mutex::new(None)),
            stopping: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            token_digest: Arc::new(Mutex::new(None)),
            log_events: Arc::new(Mutex::new(Vec::new())),
            process_error: Arc::new(Mutex::new(None)),
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
        // Supervisor 监控循环必须在首次 spawn 失败时也启动；否则二进制
        // 暂时不可用的容器永远不会自动恢复，只能依赖人工重启 Nexo。
        let first_spawn = self.spawn_once().await;
        let supervisor = self.clone();
        tokio::spawn(async move { supervisor.monitor_loop().await });
        if let Err(error) = first_spawn {
            self.record_process_error(&format!("{error:#}")).await;
            tracing::error!(
                "Caddy 未能启动，公网 Web 服务暂不可用；Nexo 核心仍继续运行：{error:#}"
            );
        }
        Ok(())
    }

    async fn spawn_once(&self) -> Result<()> {
        let mut command = Command::new(&self.config.binary);
        // JSON 是 Caddy 原生配置格式；只有非原生格式才需要指定适配器。
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let mut child = command
            .args([
                "run",
                "--config",
                self.config.config_path.to_string_lossy().as_ref(),
            ])
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("无法启动 Caddy：{}", self.config.binary.display()))?;
        if let Some(stdout) = child.stdout.take() {
            spawn_caddy_log_reader(
                stdout,
                Arc::clone(&self.log_events),
                "stdout",
                self.config.cloudflare_token_root.clone(),
                self.process_error.clone(),
            );
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_caddy_log_reader(
                stderr,
                Arc::clone(&self.log_events),
                "stderr",
                self.config.cloudflare_token_root.clone(),
                self.process_error.clone(),
            );
        }
        *self.child.lock().await = Some(child);
        let loaded = fs::read(&self.config.config_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        *self.token_digest.lock().await = loaded
            .as_ref()
            .and_then(|value| credential_signature(value).ok())
            .flatten();
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
                        break;
                    },
                }
                if self.stopping.load(Ordering::SeqCst) {
                    break;
                }
                if let Err(error) = self.spawn_once().await {
                    self.record_process_error(&format!("{error:#}")).await;
                    tracing::error!("Caddy 重启失败，将继续退避：{error:#}");
                }
                continue;
            };
            enum MonitorSignal {
                Exited(std::io::Result<std::process::ExitStatus>),
                Stop,
            }
            let signal = tokio::select! {
                result = child.wait() => MonitorSignal::Exited(result),
                _ = self.notify.notified() => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    MonitorSignal::Stop
                }
            };
            match signal {
                MonitorSignal::Stop => break,
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
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()?;
        // Admin API 的加载和两个落盘文件不是同一个文件系统事务。先记住
        // 旧文件，若落盘在加载成功后失败，就把运行中的 Caddy 回滚到旧
        // 配置并恢复文件，避免重启后读取一份并未确认的 Applied 状态。
        let old_config = fs::read(&self.config.config_path).ok();
        let old_applied = fs::read(&self.config.applied_path).ok();
        post_config(
            &client,
            &self.config.admin_url,
            &body,
            &self.config.cloudflare_token_root,
        )
        .await?;
        let persist_result = atomic_write(&self.config.config_path, &body)
            .and_then(|_| atomic_write(&self.config.applied_path, &body));
        if let Err(error) = persist_result {
            if let Some(previous) = old_config.as_deref() {
                if let Err(rollback_error) = post_config(
                    &client,
                    &self.config.admin_url,
                    previous,
                    &self.config.cloudflare_token_root,
                )
                .await
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
        // 只有实际加载和落盘都成功后才记录凭据状态，失败的变化会在下一轮继续重试。
        *self.token_digest.lock().await = credential_signature(config)?;
        Ok(())
    }

    pub async fn credentials_changed(&self, config: &Value) -> Result<bool> {
        Ok(*self.token_digest.lock().await != credential_signature(config)?)
    }

    /// 取出最近一轮协调前累积的 Caddy 事件。队列本身不跨重启持久化，
    /// 真正需要恢复的证书/ACME 状态仍由 Caddy storage 负责。
    pub async fn drain_log_events(&self) -> Vec<CaddyLogEvent> {
        let mut events = self.log_events.lock().await;
        std::mem::take(&mut *events)
    }

    /// 通过 Caddy Admin API 检查边缘进程是否仍可用。
    ///
    /// Caddy 停止只会让公网 Web 服务受限；调用方不应
    /// 因此停止 Nexo Core 或 TCP Tunnel。
    pub async fn current_config(&self) -> Result<Value> {
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()?;
        let result = client
            .get(format!(
                "{}/config/",
                self.config.admin_url.trim_end_matches('/')
            ))
            .send()
            .await
            .context("无法连接 Caddy 管理接口");
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                return Err(match self.process_error.lock().await.clone() {
                    Some(reason) => error.context(reason),
                    None => error,
                });
            }
        };
        let config = response.error_for_status()?.json().await?;
        *self.process_error.lock().await = None;
        Ok(config)
    }

    pub async fn record_process_error(&self, message: &str) {
        *self.process_error.lock().await =
            Some(redact(message, &self.config.cloudflare_token_root));
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.stopping.store(true, Ordering::SeqCst);
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
    token_root: PathBuf,
    process_error: Arc<Mutex<Option<String>>>,
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
            let Some(mut event) = parse_caddy_log_line(&line) else {
                continue;
            };
            event.message = redact(&event.message, &token_root);
            if event.message.starts_with("Error:") {
                *process_error.lock().await = Some(event.message.clone());
            }
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

/// 手工维护的旧 cloudflare.token 转成不可覆盖的候选文件，避免更新失败后重启丢失旧凭据。
pub fn snapshot_token(root: &Path, id: &str, token: &str) -> Result<PathBuf> {
    if let Ok(files) = fs::read_dir(root.join(id)) {
        for file in files.flatten() {
            let name = file.file_name().to_string_lossy().to_string();
            if name.starts_with("credential-")
                && fs::read_to_string(file.path()).is_ok_and(|value| value == token)
            {
                return crate::domains::credential_path(root, id, &name);
            }
        }
    }
    let name = crate::domains::write_credential(root, id, token)?;
    crate::domains::credential_path(root, id, &name)
}

fn credential_signature(config: &Value) -> Result<Option<String>> {
    fn collect(value: &Value, files: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    if key == "api_token" {
                        if let Some(path) = value
                            .as_str()
                            .and_then(|s| s.strip_prefix("{file."))
                            .and_then(|s| s.strip_suffix('}'))
                        {
                            files.push(path.to_owned());
                        }
                    } else {
                        collect(value, files);
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    collect(value, files);
                }
            }
            _ => {}
        }
    }
    let mut files = Vec::new();
    collect(config, &mut files);
    files.sort();
    files.dedup();
    if files.is_empty() {
        return Ok(None);
    }
    let mut digest = Sha256::new();
    for path in files {
        digest.update(path.as_bytes());
        digest.update(fs::read(&path).context("无法读取 Caddy 凭据文件")?);
    }
    Ok(Some(hex::encode(digest.finalize())))
}

/// 兼容已有的按域名凭据文件；转换为文件引用后通过 Admin API 热加载。
pub fn read_domain_tokens(root: &Path) -> Vec<(String, String)> {
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

async fn post_config(
    client: &Client,
    admin_url: &str,
    body: &[u8],
    token_root: &Path,
) -> Result<()> {
    let response = client
        .post(format!("{}/load", admin_url.trim_end_matches('/')))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::CACHE_CONTROL, "must-revalidate")
        .body(body.to_vec())
        .send()
        .await
        .context("Caddy Admin API 请求失败")?;
    if !response.status().is_success() {
        let status = response.status();
        let detail = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "Caddy 拒绝配置：HTTP {} {}",
            status,
            redact(&detail, token_root)
        );
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
        format!("{}…", value.chars().take(MAX).collect::<String>())
    }
}

/// 只向页面暴露裁剪、脱敏后的诊断；候选与回滚凭据也必须一并脱敏。
pub fn redact(message: &str, token_root: &Path) -> String {
    let mut value = message.to_owned();
    if let Ok(directories) = fs::read_dir(token_root) {
        for directory in directories.flatten() {
            if let Ok(files) = fs::read_dir(directory.path()) {
                for file in files
                    .flatten()
                    .filter(|f| f.path().extension().is_some_and(|e| e == "token"))
                {
                    if let Ok(token) = fs::read_to_string(file.path()) {
                        let token = token.trim();
                        if !token.is_empty() {
                            value = value.replace(token, "[已隐藏凭据]");
                        }
                    }
                }
            }
        }
    }
    if let Ok(token) = env::var("NEXO_CLOUDFLARE_API_TOKEN") {
        if !token.is_empty() {
            value = value.replace(&token, "[已隐藏凭据]");
        }
    }
    truncate(&value)
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
    fn challenge_errors_are_failures_and_retry_uses_log_timestamp() {
        let event = parse_caddy_log_line(r#"{"level":"error","logger":"tls.obtain","msg":"could not get certificate","error":"DNS propagation: authorization failed","identifier":"example.com","ts":1790000000.25}"#).unwrap();
        assert_eq!(event.certificate_stage(), Some("failed"));
        assert_eq!(event.occurred_at, Some(1790000000));
        assert_eq!(
            parse_status_code("validating https://example.com:443"),
            None
        );
    }

    #[test]
    fn credentials_are_removed_before_truncating_unicode_errors() {
        let root = env::temp_dir().join(format!("nexo-redaction-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("domain")).unwrap();
        fs::write(
            root.join("domain/cloudflare.token"),
            "secret-cloudflare-token",
        )
        .unwrap();
        let error = format!("{}secret-cloudflare-token 验证失败", "错".repeat(500));
        let public = redact(&error, &root);
        assert!(!public.contains("secret"));
        assert!(public.contains("[已隐藏凭据]"));
        fs::remove_file(root.join("domain/cloudflare.token")).unwrap();
        fs::remove_dir(root.join("domain")).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
