//! Nexo Agent 启动入口。
//!
//! Agent 不绑定固定服务端。首次入网时通过环境变量指定目标地址和一次性
//! token，完成请求后继续作为常驻进程运行；后续控制通道会复用同一配置。

use std::{
    collections::HashMap,
    env, fs,
    io::BufReader,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use clap::Parser;
use get_if_addrs::{get_if_addrs, IfAddr};
use ipnet::IpNet;
use nexo_core::{
    validate_published_network, ApplyStatus, CapabilityState, DetectedLocalNetwork,
    DeviceCapability, GatewayCapabilityReason, GatewayCapabilityReport,
};
use nexo_protocol::{
    AgentControlMessage, AgentEnrollmentPollRequest, AgentEnrollmentPollResponse,
    AgentEnrollmentRequest, AgentEnrollmentResponse, GatewayApplyAck, GatewayDesiredState,
    GatewayRouteApplyReport, GatewayRouteApplyResult, MeshEnrollmentOffer, MeshIdentityReport,
    ServerControlMessage, TunnelApplyResult, TunnelDesiredState,
};
use nexo_tunnel::{into_tokio_io, next_inbound, read_logical_header, yamux_connection};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command as TokioCommand};
use tokio::sync::Mutex as AsyncMutex;
use tokio_rustls::{rustls, TlsConnector};

/// Agent 只提供版本查询；运行配置继续通过容器环境变量传入，避免同时维护
/// CLI 与环境变量两套部署接口。
#[derive(Debug, Parser)]
#[command(name = "nexo-agent", version, about = "Nexo 联巢设备代理")]
struct Cli {}

/// Agent 运行时所需的最小配置，避免把服务端地址写死在二进制中。
/// Agent 的启动配置；服务端地址和控制通道地址均可在容器环境变量中指定。
#[derive(Clone)]
struct AgentRuntimeConfig {
    server_url: String,
    control_addr: Option<String>,
    control_server_name: String,
    enrollment_token: Option<String>,
    device_name: String,
    capabilities: Vec<DeviceCapability>,
    state_dir: PathBuf,
    /// 是否允许 Agent 执行本机 Tailscale 命令；默认关闭，避免部署后意外改动宿主机网络。
    tailscale_apply_enabled: bool,
    /// Tailscale 可执行文件路径；容器内通常为 `tailscale`，也支持显式绝对路径。
    tailscale_bin: String,
    /// tailscaled 可执行文件路径；二进制与 Agent 分开提供，便于升级和诊断。
    tailscaled_bin: String,
    /// 是否由 Agent 负责拉起 tailscaled。网关镜像默认开启，普通设备可关闭。
    tailscaled_enabled: bool,
    /// 公网 Tunnel 数据连接地址；为空时只运行控制面和组网能力。
    tunnel_addr: Option<String>,
    tunnel_server_name: String,
}

impl AgentRuntimeConfig {
    fn from_environment() -> Result<Self> {
        let server_url = env::var("NEXO_SERVER_URL")
            .context("未配置 NEXO_SERVER_URL，Agent 无法知道要加入哪个 Nexo Server")?;
        let server_url = server_url.trim_end_matches('/').to_owned();
        if server_url.is_empty() {
            anyhow::bail!("NEXO_SERVER_URL 不能为空");
        }
        let device_name = env::var("NEXO_DEVICE_NAME")
            .unwrap_or_else(|_| env::var("HOSTNAME").unwrap_or_else(|_| "Nexo Agent".to_owned()));
        let capabilities = parse_capabilities(
            &env::var("NEXO_AGENT_CAPABILITIES").unwrap_or_else(|_| "tunnel".to_owned()),
        )?;
        let state_dir = PathBuf::from(
            env::var("NEXO_STATE_DIR").unwrap_or_else(|_| "./data/nexo-agent".to_owned()),
        );
        let control_addr = env::var("NEXO_CONTROL_ADDR")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let control_server_name =
            env::var("NEXO_CONTROL_SERVER_NAME").unwrap_or_else(|_| "nexo-server".to_owned());
        let tailscale_apply_enabled = env::var("NEXO_TAILSCALE_APPLY")
            .ok()
            .map(|value| parse_bool_env(&value))
            .unwrap_or(false);
        let tailscale_bin = env::var("NEXO_TAILSCALE_BIN")
            .unwrap_or_else(|_| "tailscale".to_owned())
            .trim()
            .to_owned();
        if tailscale_bin.is_empty() {
            anyhow::bail!("NEXO_TAILSCALE_BIN 不能为空");
        }
        let tailscaled_bin = env::var("NEXO_TAILSCALED_BIN")
            .unwrap_or_else(|_| "tailscaled".to_owned())
            .trim()
            .to_owned();
        if tailscaled_bin.is_empty() {
            anyhow::bail!("NEXO_TAILSCALED_BIN 不能为空");
        }
        let tailscaled_enabled = env::var("NEXO_TAILSCALED_ENABLED")
            .ok()
            .map(|value| parse_bool_env(&value))
            .unwrap_or(tailscale_apply_enabled);
        let tunnel_addr = env::var("NEXO_TUNNEL_ADDR")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let tunnel_server_name =
            env::var("NEXO_TUNNEL_SERVER_NAME").unwrap_or_else(|_| control_server_name.clone());
        Ok(Self {
            server_url,
            control_addr,
            control_server_name,
            enrollment_token: env::var("NEXO_ENROLLMENT_TOKEN")
                .ok()
                .filter(|token| !token.trim().is_empty()),
            device_name,
            capabilities,
            state_dir,
            tailscale_apply_enabled,
            tailscale_bin,
            tailscaled_bin,
            tailscaled_enabled,
            tunnel_addr,
            tunnel_server_name,
        })
    }
}

/// 读取布尔型环境变量；无法识别的值按关闭处理，避免误启用系统命令。
fn parse_bool_env(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// 生成 Tailscale CLI 的本地控制 Socket 全局参数。
///
/// `TS_SOCKET` 不是所有版本的 CLI 都会读取；显式传入官方支持的
/// `--socket=<path>`，确保 Agent 调用的是自己启动的 tailscaled。
fn tailscale_socket_arg(socket: &std::path::Path) -> String {
    format!("--socket={}", socket.display())
}

/// Agent 内置的 tailscaled 子进程管理器。
///
/// Tailscale Linux 二进制仍作为镜像中的独立文件提供，不编译进 Nexo Agent；
/// 网关模式只授予 TUN 与 NET_ADMIN，关闭时不会触碰宿主机网络配置。
struct TailscaleDaemon {
    child: Arc<AsyncMutex<Option<Child>>>,
    socket: PathBuf,
}

impl std::fmt::Debug for TailscaleDaemon {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TailscaleDaemon")
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl TailscaleDaemon {
    async fn start(config: &AgentRuntimeConfig) -> Result<Option<Self>> {
        if !config.tailscaled_enabled {
            return Ok(None);
        }
        fs::create_dir_all(&config.state_dir).with_context(|| {
            format!(
                "无法创建 Tailscale 状态目录：{}",
                config.state_dir.display()
            )
        })?;
        let socket = config.state_dir.join("tailscaled.sock");
        let state = config.state_dir.join("tailscaled.state");
        let child = TokioCommand::new(&config.tailscaled_bin)
            .args([
                "--state",
                state.to_string_lossy().as_ref(),
                "--socket",
                socket.to_string_lossy().as_ref(),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .with_context(|| format!("无法启动 tailscaled：{}", config.tailscaled_bin))?;
        let daemon = Self {
            child: Arc::new(AsyncMutex::new(Some(child))),
            socket,
        };
        if let Err(error) = daemon.wait_until_ready().await {
            // tailscaled 已经启动但未能建立控制 Socket 时立即回收子进程，
            // 避免 Agent 启动失败后留下孤儿守护进程占用 TUN/状态文件。
            let _ = daemon.shutdown().await;
            return Err(error);
        }
        tracing::info!(version = "1.102.3", "tailscaled 已启动");
        Ok(Some(daemon))
    }

    /// 等待本地控制 Socket 出现，避免 Agent 在 tailscaled 尚未监听时立即执行
    /// `tailscale up`，将一次正常启动误判为组网失败。
    async fn wait_until_ready(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.socket.exists() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!(
            "tailscaled 未在 10 秒内创建控制 Socket：{}",
            self.socket.display()
        )
    }

    async fn shutdown(&self) -> Result<()> {
        let mut child = self.child.lock().await;
        if let Some(process) = child.as_mut() {
            // `Child::kill` 在 Unix 上发送 SIGKILL，可能来不及把节点密钥和
            // 网络状态完整写回持久卷。优先发送 SIGTERM 让 tailscaled 自己
            // 收尾；只有它在短时间内没有退出时才使用强制终止兜底。
            #[cfg(unix)]
            if let Some(pid) = process.id() {
                let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
                if result != 0 {
                    tracing::warn!(pid, "无法向 tailscaled 发送优雅退出信号，将等待其自行退出");
                }
            }
            #[cfg(not(unix))]
            process.kill().await.context("无法停止 tailscaled")?;

            let exited = tokio::time::timeout(Duration::from_secs(5), process.wait()).await;
            if !matches!(exited, Ok(Ok(_))) {
                tracing::warn!("tailscaled 未在 5 秒内退出，将强制终止");
                process.kill().await.context("无法强制停止 tailscaled")?;
                process.wait().await.context("无法等待 tailscaled 退出")?;
            }
        }
        *child = None;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter("nexo_agent=info")
        .init();

    let config = AgentRuntimeConfig::from_environment()?;
    let tailscale_daemon = TailscaleDaemon::start(&config).await?;
    // 先检查身份材料是否完整，再决定是否允许生成新的设备私钥；残缺的
    // 证书/私钥组合必须显式修复，不能静默拼接成另一套身份。
    let mut identity_ready = identity_is_persisted(&config)?;
    let key_pair = load_or_create_key(&config)?;
    let mut stop_after_enrollment = false;
    if identity_ready {
        tracing::info!("已加载本地设备身份，跳过一次性入网凭证提交");
    } else if let Some(token) = &config.enrollment_token {
        let response = enroll(&config, token, &key_pair).await?;
        tracing::info!(
            enrollment_id = %response.enrollment_id,
            status = ?response.status,
            "设备入网请求已提交：{}",
            response.message
        );
        if response.status == nexo_core::EnrollmentStatus::AwaitingApproval {
            if let Some(approved) =
                wait_for_approval(&config, token, &response.enrollment_id).await?
            {
                persist_identity(&config, &approved)?;
                identity_ready = true;
                tracing::info!("设备身份已保存，后续连接将使用 mTLS 客户端证书");
            } else {
                tracing::info!("Agent 在领取设备身份前退出");
                stop_after_enrollment = true;
            }
        }
    } else {
        tracing::info!("未提供 NEXO_ENROLLMENT_TOKEN，Agent 等待后续配置");
    }
    tracing::info!("Nexo Agent 已启动，目标服务端：{}", config.server_url);
    let run_result = if stop_after_enrollment {
        Ok(())
    } else if identity_ready && config.control_addr.is_some() {
        run_control_loop(&config, &key_pair).await
    } else {
        if config.control_addr.is_none() {
            tracing::info!("未配置 NEXO_CONTROL_ADDR，暂不建立 mTLS 控制通道");
        }
        wait_for_shutdown_signal()
            .await
            .context("Agent 等待退出信号失败")
    };
    tracing::info!("Nexo Agent 正在退出");
    if let Some(daemon) = tailscale_daemon {
        daemon.shutdown().await?;
    }
    run_result?;
    Ok(())
}

/// 同时响应本地 Ctrl-C 和 Docker 常用的 SIGTERM，确保退出前能回收
/// Agent 自己启动的 tailscaled 子进程。
async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate()).context("无法监听 SIGTERM")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("等待 Ctrl-C 失败"),
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("等待 Ctrl-C 失败")
    }
}

/// 判断 Agent 是否已经完成过身份领取，避免容器重启时重放已消费 token。
fn identity_is_persisted(config: &AgentRuntimeConfig) -> Result<bool> {
    let paths = [
        config.state_dir.join("device-key.pem"),
        config.state_dir.join("device-cert.pem"),
        config.state_dir.join("server-ca.pem"),
        config.state_dir.join("device-id"),
    ];
    let present = paths.iter().filter(|path| path.exists()).count();
    if present == 0 {
        return Ok(false);
    }
    if present != paths.len() {
        anyhow::bail!(
            "Agent 身份材料不完整，请检查持久化目录：{}",
            config.state_dir.display()
        );
    }
    Ok(true)
}

fn load_or_create_key(config: &AgentRuntimeConfig) -> Result<KeyPair> {
    fs::create_dir_all(&config.state_dir)
        .with_context(|| format!("无法创建 Agent 身份目录：{}", config.state_dir.display()))?;
    let path = config.state_dir.join("device-key.pem");
    if path.exists() {
        let pem = fs::read_to_string(&path)
            .with_context(|| format!("无法读取 Agent 私钥：{}", path.display()))?;
        set_private_permissions(&path)
            .with_context(|| format!("无法保护 Agent 私钥：{}", path.display()))?;
        return KeyPair::from_pem(&pem).context("Agent 私钥格式无效");
    }
    let key_pair = KeyPair::generate().context("无法生成 Agent 设备私钥")?;
    write_private_file(&path, key_pair.serialize_pem().as_bytes())
        .with_context(|| format!("无法原子保存 Agent 私钥：{}", path.display()))?;
    Ok(key_pair)
}

/// 用 Agent 本地私钥生成 CSR；私钥不会离开 Agent 容器。
fn create_csr(config: &AgentRuntimeConfig, key_pair: &KeyPair) -> Result<String> {
    let mut params = CertificateParams::new(vec!["agent.nexo".to_owned()])?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, config.device_name.clone());
    params
        .serialize_request(key_pair)
        .context("无法生成 Agent 设备 CSR")?
        .pem()
        .context("无法编码 Agent 设备 CSR")
}

async fn enroll(
    config: &AgentRuntimeConfig,
    token: &str,
    key_pair: &KeyPair,
) -> Result<AgentEnrollmentResponse> {
    let request = AgentEnrollmentRequest {
        token: token.to_owned(),
        device_name: config.device_name.clone(),
        os: Some(env::consts::OS.to_owned()),
        architecture: Some(env::consts::ARCH.to_owned()),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: config.capabilities.clone(),
        csr_pem: Some(create_csr(config, key_pair)?),
    };
    let endpoint = format!("{}/api/v1/agent/enroll", config.server_url);
    let response = reqwest::Client::new()
        .post(endpoint)
        .json(&request)
        .send()
        .await
        .context("无法连接 Nexo Server 入网接口")?;
    let status = response.status();
    let body = response
        .text()
        .await
        .context("无法读取 Nexo Server 入网响应")?;
    if !status.is_success() {
        anyhow::bail!("Nexo Server 拒绝设备入网（HTTP {status}）：{body}");
    }
    serde_json::from_str(&body).context("Nexo Server 返回了无法识别的入网响应")
}

/// 轮询管理员审批结果；审批前只返回状态，审批后一次性领取证书链。
async fn wait_for_approval(
    config: &AgentRuntimeConfig,
    token: &str,
    enrollment_id: &str,
) -> Result<Option<AgentEnrollmentPollResponse>> {
    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            result = &mut shutdown => {
                result?;
                return Ok(None);
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {}
        }
        let endpoint = format!(
            "{}/api/v1/agent/enroll/{}/poll",
            config.server_url, enrollment_id
        );
        let result = reqwest::Client::new()
            .post(endpoint)
            .json(&AgentEnrollmentPollRequest {
                token: token.to_owned(),
            })
            .send()
            .await;
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!("无法连接 Nexo Server，3 秒后重试：{}", error);
                continue;
            }
        };
        let status = response.status();
        let body = response
            .text()
            .await
            .context("无法读取 Nexo Server 审批响应")?;
        if !status.is_success() {
            anyhow::bail!("Nexo Server 返回审批错误（HTTP {status}）：{body}");
        }
        let approval: AgentEnrollmentPollResponse =
            serde_json::from_str(&body).context("Nexo Server 返回了无法识别的审批响应")?;
        tracing::info!("设备审批状态：{}", approval.message);
        match approval.status {
            nexo_core::EnrollmentStatus::Approved => return Ok(Some(approval)),
            nexo_core::EnrollmentStatus::AwaitingApproval => {}
            nexo_core::EnrollmentStatus::Expired | nexo_core::EnrollmentStatus::Revoked => {
                anyhow::bail!("设备入网无法完成：{}", approval.message)
            }
            _ => anyhow::bail!("设备入网返回了意外状态：{:?}", approval.status),
        }
    }
}

fn persist_identity(
    config: &AgentRuntimeConfig,
    approval: &AgentEnrollmentPollResponse,
) -> Result<()> {
    let certificate_pem = approval
        .certificate_pem
        .as_deref()
        .context("审批响应缺少设备证书")?;
    let ca_certificate_pem = approval
        .ca_certificate_pem
        .as_deref()
        .context("审批响应缺少服务端 CA 证书")?;
    let device_id = approval
        .device_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("审批响应缺少设备 ID")?;
    let files = [
        (
            config.state_dir.join("device-cert.pem"),
            certificate_pem.as_bytes(),
        ),
        (
            config.state_dir.join("server-ca.pem"),
            ca_certificate_pem.as_bytes(),
        ),
        (config.state_dir.join("device-id"), device_id.as_bytes()),
    ];
    let previous = files
        .iter()
        .map(|(path, _)| read_optional_file(path))
        .collect::<Result<Vec<_>>>()?;
    let write_result = files
        .iter()
        .try_for_each(|(path, value)| write_private_file(path, value));
    if let Err(error) = write_result {
        // 三份材料共同组成一次身份领取；任一文件失败都恢复旧快照，避免
        // 下次启动把半套证书当成已入网状态。
        let mut restore_errors = Vec::new();
        for ((path, _), old) in files.iter().zip(previous.iter()) {
            if let Err(restore_error) = restore_optional_file(path, old.as_deref()) {
                restore_errors.push(format!("{}: {restore_error}", path.display()));
            }
        }
        if !restore_errors.is_empty() {
            tracing::error!(
                "Agent 身份材料写入失败且回滚不完整：{}",
                restore_errors.join("；")
            );
        }
        return Err(error).context("无法完整保存 Agent 身份材料");
    }
    Ok(())
}

/// 读取一个可选的身份材料快照；除不存在外的错误都必须中止写入，避免
/// 回滚时把不可读文件误判成“原来不存在”。
fn read_optional_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("无法读取身份材料快照：{}", path.display()))
        }
    }
}

/// 原子写入 Agent 私钥、证书和设备 ID，并在 Unix 上固定为 0600。
fn write_private_file(path: &Path, value: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "身份材料路径缺少父目录")
    })?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        std::process::id()
    ));
    if let Err(error) = fs::write(&temporary, value) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = set_private_permissions(&temporary) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = replace_private_file(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    set_private_permissions(path)
}

fn replace_private_file(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    match fs::rename(temporary, destination) {
        Ok(()) => Ok(()),
        // Unix 的 rename 会替换目标；Windows 不允许覆盖已有文件，使用同一目录
        // 临时文件并删除旧文件后切换，仍避免半写入内容被读到。
        Err(error) if cfg!(windows) && error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(destination)?;
            fs::rename(temporary, destination)
        }
        Err(error) => Err(error),
    }
}

fn restore_optional_file(path: &Path, previous: Option<&[u8]>) -> std::io::Result<()> {
    match previous {
        Some(value) => write_private_file(path, value),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        },
    }
}

fn set_private_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// 使用已保存的设备证书持续连接任意 Nexo Server 的 mTLS 控制通道。
///
/// 控制通道断开后按固定间隔重连；不把一次性入网 token 带入该通道。
async fn run_control_loop(config: &AgentRuntimeConfig, key_pair: &KeyPair) -> Result<()> {
    let control_addr = config
        .control_addr
        .as_deref()
        .context("NEXO_CONTROL_ADDR 未配置")?;
    let device_id = fs::read_to_string(config.state_dir.join("device-id"))
        .context("无法读取 Agent 设备 ID")?
        .trim()
        .to_owned();
    if device_id.is_empty() {
        anyhow::bail!("Agent 设备 ID 为空");
    }
    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);
    let desired_tunnels = Arc::new(AsyncMutex::new(HashMap::<
        String,
        nexo_protocol::TunnelDesiredState,
    >::new()));
    // 数据面先以环境变量作为兼容初始值；正式地址由 Server 控制响应下发，
    // 这样同一个 Agent 可以在不改容器配置的情况下切换到当前入口。
    let tunnel_endpoint = Arc::new(AsyncMutex::new(config.tunnel_addr.clone().map(|address| {
        nexo_protocol::TunnelDataEndpoint {
            address,
            server_name: config.tunnel_server_name.clone(),
        }
    })));
    let tunnel_task = {
        let tunnel_config = config.clone();
        let tunnel_key = key_pair.serialize_pem();
        let tunnel_desired = desired_tunnels.clone();
        let tunnel_endpoint_state = tunnel_endpoint.clone();
        Some(tokio::spawn(async move {
            run_tunnel_data_loop(
                tunnel_config,
                tunnel_key,
                tunnel_endpoint_state,
                tunnel_desired,
            )
            .await;
        }))
    };
    loop {
        match control_session(
            config,
            key_pair,
            control_addr,
            &device_id,
            &desired_tunnels,
            &tunnel_endpoint,
        )
        .await
        {
            Ok(()) => tracing::warn!("Nexo mTLS 控制连接已断开，5 秒后重连"),
            Err(error) => tracing::warn!("Nexo mTLS 控制连接失败，5 秒后重试：{error:#}"),
        }
        // 控制面失联后立即清空本地允许列表；数据面可能因为网络抖动
        // 继续存活，但在重新拿到最新 Desired State 前不能接受公网连接。
        clear_desired_tunnels(&desired_tunnels).await;
        tokio::select! {
            result = &mut shutdown => {
                result?;
                if let Some(task) = &tunnel_task {
                    task.abort();
                }
                return Ok(());
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
        }
    }
}

/// 建立一次控制会话，先发送身份声明，随后每 15 秒发送心跳。
async fn control_session(
    config: &AgentRuntimeConfig,
    key_pair: &KeyPair,
    control_addr: &str,
    device_id: &str,
    desired_tunnels: &Arc<AsyncMutex<HashMap<String, nexo_protocol::TunnelDesiredState>>>,
    tunnel_endpoint: &Arc<AsyncMutex<Option<nexo_protocol::TunnelDataEndpoint>>>,
) -> Result<()> {
    let connector = build_tls_connector(config, key_pair)?;
    let server_name = ServerName::try_from(config.control_server_name.clone())
        .map_err(|_| anyhow::anyhow!("NEXO_CONTROL_SERVER_NAME 不是有效的 DNS 名称"))?;
    let stream = TcpStream::connect(control_addr)
        .await
        .with_context(|| format!("无法连接 Nexo 控制地址：{control_addr}"))?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("Nexo mTLS 握手失败")?;
    let mut reader = AsyncBufReader::new(tls_stream);
    let gateway_report = detect_gateway_capabilities();
    let mesh_identity = query_optional_mesh_identity(config).await;
    write_agent_message(
        reader.get_mut(),
        &AgentControlMessage::Hello {
            device_id: device_id.to_owned(),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: config.capabilities.clone(),
            gateway_report: Some(gateway_report.clone()),
            mesh_identity,
        },
    )
    .await?;
    let response = read_control_response(&mut reader).await?;
    apply_server_tunnel_endpoint(tunnel_endpoint, &response).await;
    let mut last_gateway_state = None;
    let mut last_gateway_status = None;
    let mut gateway_confirmation_pending = false;
    let mut gateway_retry_attempt = 0;
    let mut gateway_retry_at = None;
    let mut last_gateway_report = Some(gateway_report.clone());
    match response {
        ServerControlMessage::HelloAccepted {
            gateway_state: Some(gateway_state),
            mesh_enrollment,
            protocol_features,
            tunnels,
            ..
        } => {
            replace_desired_tunnels(desired_tunnels, &tunnels).await;
            if let Some(offer) = mesh_enrollment {
                apply_mesh_enrollment_offer(&mut reader, config, &offer).await?;
            }
            let applier = TailscaleRouteApplier::from_config(config);
            let execution = apply_gateway_desired_state_with_execution(
                &gateway_state,
                &applier,
                Some(&gateway_report),
            );
            let GatewayApplyExecution { ack, local_applied } = execution;
            last_gateway_status = Some(ack.status);
            update_gateway_retry_state(
                ack.status,
                &mut gateway_retry_attempt,
                &mut gateway_retry_at,
            );
            write_agent_message(
                reader.get_mut(),
                &AgentControlMessage::GatewayApplyAck { ack: ack.clone() },
            )
            .await?;
            match read_control_response(&mut reader).await? {
                ServerControlMessage::GatewayApplyAccepted { revision }
                    if revision == ack.revision => {}
                ServerControlMessage::Error { message } => {
                    anyhow::bail!("服务端拒绝网关应用确认：{message}")
                }
                _ => anyhow::bail!("服务端返回了无效的网关应用确认响应"),
            }
            if protocol_features
                .iter()
                .any(|feature| feature == "gateway_route_report")
            {
                send_gateway_route_report(&mut reader, &gateway_state, &ack, local_applied).await?;
            }
            if protocol_features
                .iter()
                .any(|feature| feature == "tunnel_desired_state")
            {
                send_tunnel_apply_report(&mut reader, &tunnels, config).await?;
            }
            gateway_confirmation_pending =
                !matches!(ack.status, ApplyStatus::Failed | ApplyStatus::Retrying);
            last_gateway_state = Some(gateway_state);
        }
        ServerControlMessage::HelloAccepted {
            gateway_state: None,
            mesh_enrollment,
            protocol_features,
            tunnels,
            ..
        } => {
            replace_desired_tunnels(desired_tunnels, &tunnels).await;
            if let Some(offer) = mesh_enrollment {
                apply_mesh_enrollment_offer(&mut reader, config, &offer).await?;
            }
            if protocol_features
                .iter()
                .any(|feature| feature == "tunnel_desired_state")
            {
                send_tunnel_apply_report(&mut reader, &tunnels, config).await?;
            }
        }
        ServerControlMessage::Error { message } => anyhow::bail!("服务端拒绝控制连接：{message}"),
        ServerControlMessage::HeartbeatAck { .. } => {
            anyhow::bail!("服务端在身份声明前返回了心跳确认")
        }
        ServerControlMessage::GatewayApplyAccepted { .. } => {
            anyhow::bail!("服务端在身份声明前返回了网关确认")
        }
        ServerControlMessage::TunnelApplyAccepted { .. } => {
            anyhow::bail!("服务端在身份声明前返回了 Tunnel 确认")
        }
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        let heartbeat_gateway_report = detect_gateway_capabilities();
        let heartbeat_mesh_identity = query_optional_mesh_identity(config).await;
        write_agent_message(
            reader.get_mut(),
            &AgentControlMessage::Heartbeat {
                device_id: device_id.to_owned(),
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                gateway_report: Some(heartbeat_gateway_report.clone()),
                mesh_identity: heartbeat_mesh_identity,
            },
        )
        .await?;
        let heartbeat_response = read_control_response(&mut reader).await?;
        apply_server_tunnel_endpoint(tunnel_endpoint, &heartbeat_response).await;
        match heartbeat_response {
            ServerControlMessage::HeartbeatAck {
                gateway_state: Some(gateway_state),
                mesh_enrollment,
                protocol_features,
                tunnels,
                ..
            } if should_apply_gateway_state(
                &gateway_state,
                last_gateway_state.as_ref(),
                last_gateway_status,
                gateway_retry_at,
                gateway_confirmation_pending,
                last_gateway_report.as_ref() != Some(&heartbeat_gateway_report),
            ) =>
            {
                let confirms_same_state = last_gateway_state.as_ref() == Some(&gateway_state);
                replace_desired_tunnels(desired_tunnels, &tunnels).await;
                if let Some(offer) = mesh_enrollment {
                    apply_mesh_enrollment_offer(&mut reader, config, &offer).await?;
                }
                let applier = TailscaleRouteApplier::from_config(config);
                let execution = apply_gateway_desired_state_with_execution(
                    &gateway_state,
                    &applier,
                    Some(&heartbeat_gateway_report),
                );
                let GatewayApplyExecution { ack, local_applied } = execution;
                last_gateway_status = Some(ack.status);
                update_gateway_retry_state(
                    ack.status,
                    &mut gateway_retry_attempt,
                    &mut gateway_retry_at,
                );
                write_agent_message(
                    reader.get_mut(),
                    &AgentControlMessage::GatewayApplyAck { ack: ack.clone() },
                )
                .await?;
                match read_control_response(&mut reader).await? {
                    ServerControlMessage::GatewayApplyAccepted { revision }
                        if revision == ack.revision => {}
                    ServerControlMessage::Error { message } => {
                        anyhow::bail!("服务端拒绝网关应用确认：{message}")
                    }
                    _ => anyhow::bail!("服务端返回了无效的网关应用确认响应"),
                }
                if protocol_features
                    .iter()
                    .any(|feature| feature == "gateway_route_report")
                {
                    send_gateway_route_report(&mut reader, &gateway_state, &ack, local_applied)
                        .await?;
                }
                if protocol_features
                    .iter()
                    .any(|feature| feature == "tunnel_desired_state")
                {
                    send_tunnel_apply_report(&mut reader, &tunnels, config).await?;
                }
                gateway_confirmation_pending = !confirms_same_state
                    && !matches!(ack.status, ApplyStatus::Failed | ApplyStatus::Retrying);
                last_gateway_state = Some(gateway_state);
            }
            ServerControlMessage::HeartbeatAck {
                gateway_state: None,
                mesh_enrollment,
                protocol_features,
                tunnels,
                ..
            } => {
                replace_desired_tunnels(desired_tunnels, &tunnels).await;
                if let Some(offer) = mesh_enrollment {
                    apply_mesh_enrollment_offer(&mut reader, config, &offer).await?;
                }
                if protocol_features
                    .iter()
                    .any(|feature| feature == "tunnel_desired_state")
                {
                    send_tunnel_apply_report(&mut reader, &tunnels, config).await?;
                }
            }
            ServerControlMessage::HeartbeatAck {
                gateway_state: Some(_),
                mesh_enrollment,
                protocol_features,
                tunnels,
                ..
            } => {
                replace_desired_tunnels(desired_tunnels, &tunnels).await;
                if let Some(offer) = mesh_enrollment {
                    apply_mesh_enrollment_offer(&mut reader, config, &offer).await?;
                }
                if protocol_features
                    .iter()
                    .any(|feature| feature == "tunnel_desired_state")
                {
                    send_tunnel_apply_report(&mut reader, &tunnels, config).await?;
                }
            }
            ServerControlMessage::Error { message } => anyhow::bail!("服务端拒绝心跳：{message}"),
            ServerControlMessage::HelloAccepted { .. } => {
                anyhow::bail!("服务端重复返回身份确认")
            }
            ServerControlMessage::GatewayApplyAccepted { .. } => {
                anyhow::bail!("服务端在心跳期间返回了网关确认")
            }
            ServerControlMessage::TunnelApplyAccepted { .. } => {
                anyhow::bail!("服务端在心跳期间返回了 Tunnel 确认")
            }
        }
        last_gateway_report = Some(heartbeat_gateway_report);
    }
}

async fn replace_desired_tunnels(
    desired: &Arc<AsyncMutex<HashMap<String, nexo_protocol::TunnelDesiredState>>>,
    tunnels: &[nexo_protocol::TunnelDesiredState],
) {
    let mut guard = desired.lock().await;
    guard.clear();
    guard.extend(
        tunnels
            .iter()
            .cloned()
            .map(|tunnel| (tunnel.tunnel_id.clone(), tunnel)),
    );
}

/// 清空控制面失联期间的公网访问白名单。
///
/// 数据通道与控制通道是两条可独立重连的连接；如果只关闭控制连接而
/// 保留旧 HashMap，Agent 会在服务端已经撤销 Tunnel 后继续连接本地 Origin。
async fn clear_desired_tunnels(
    desired: &Arc<AsyncMutex<HashMap<String, nexo_protocol::TunnelDesiredState>>>,
) {
    desired.lock().await.clear();
}

/// Agent Tunnel 数据会话的重连循环。控制面只更新允许访问的 Desired State，
/// 数据面断开后按退避重连，不把公网监听暴露在 Agent 容器上。
async fn run_tunnel_data_loop(
    config: AgentRuntimeConfig,
    key_pem: String,
    endpoint: Arc<AsyncMutex<Option<nexo_protocol::TunnelDataEndpoint>>>,
    desired: Arc<AsyncMutex<HashMap<String, nexo_protocol::TunnelDesiredState>>>,
) {
    let key_pair = match KeyPair::from_pem(&key_pem) {
        Ok(key_pair) => key_pair,
        Err(error) => {
            tracing::error!("无法加载 Tunnel 数据通道客户端私钥：{error}");
            return;
        }
    };
    let mut attempt = 0_u32;
    loop {
        let Some(current_endpoint) = endpoint.lock().await.clone() else {
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        };
        let address = current_endpoint.address;
        let stream =
            match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&address)).await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    attempt = attempt.saturating_add(1);
                    let delay =
                        Duration::from_secs((2_u64.saturating_mul(1 << attempt.min(5))).min(60));
                    tracing::debug!("Tunnel 数据通道连接失败，{delay:?} 后重试：{error}");
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(_) => {
                    attempt = attempt.saturating_add(1);
                    let delay =
                        Duration::from_secs((2_u64.saturating_mul(1 << attempt.min(5))).min(60));
                    tracing::debug!("Tunnel 数据通道连接超时，{delay:?} 后重试");
                    tokio::time::sleep(delay).await;
                    continue;
                }
            };
        let connector = match build_tls_connector(&config, &key_pair) {
            Ok(connector) => connector,
            Err(error) => {
                tracing::error!("无法构建 Tunnel mTLS 客户端：{error:#}");
                return;
            }
        };
        let server_name =
            match ServerName::try_from(if current_endpoint.server_name.trim().is_empty() {
                config.tunnel_server_name.clone()
            } else {
                current_endpoint.server_name.clone()
            }) {
                Ok(name) => name,
                Err(_) => {
                    tracing::error!("NEXO_TUNNEL_SERVER_NAME 不是有效的 DNS 名称");
                    return;
                }
            };
        let tls_stream = match tokio::time::timeout(
            Duration::from_secs(10),
            connector.connect(server_name, stream),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                tracing::debug!("Tunnel mTLS 握手失败，将重试：{error}");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(_) => {
                tracing::debug!("Tunnel mTLS 握手超时，将重试");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        attempt = 0;
        let mut connection = yamux_connection(tls_stream, yamux::Mode::Client);
        tracing::info!("Tunnel 数据通道已连接：{address}");
        loop {
            match next_inbound(&mut connection).await {
                Ok(Some(stream)) => {
                    let desired = desired.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_tunnel_stream(stream, desired).await {
                            tracing::debug!("Tunnel 逻辑流已关闭：{error:#}");
                        }
                    });
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::debug!("Tunnel Yamux 会话异常：{error}");
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// 从控制面更新数据通道入口；无效或空地址只记录为受限状态，
/// 保留上一份可用地址，避免一次错误响应让已建立的 Tunnel 立即失联。
async fn apply_server_tunnel_endpoint(
    endpoint: &Arc<AsyncMutex<Option<nexo_protocol::TunnelDataEndpoint>>>,
    response: &ServerControlMessage,
) {
    let next = match response {
        ServerControlMessage::HelloAccepted {
            tunnel_endpoint, ..
        }
        | ServerControlMessage::HeartbeatAck {
            tunnel_endpoint, ..
        } => tunnel_endpoint.as_ref(),
        _ => None,
    };
    let Some(next) = next else {
        return;
    };
    if next.address.trim().is_empty() || next.server_name.trim().is_empty() {
        tracing::warn!("服务端下发的数据通道地址无效，继续使用上一份地址");
        return;
    }
    let mut current = endpoint.lock().await;
    if current.as_ref() != Some(next) {
        tracing::info!("已更新 Tunnel 数据通道入口");
        *current = Some(next.clone());
    }
}

async fn handle_tunnel_stream(
    stream: yamux::Stream,
    desired: Arc<AsyncMutex<HashMap<String, nexo_protocol::TunnelDesiredState>>>,
) -> Result<()> {
    let mut stream_io = into_tokio_io(stream);
    let header = read_logical_header(&mut stream_io)
        .await
        .map_err(|error| anyhow::anyhow!("Tunnel 逻辑流首部无效：{error}"))?;
    let tunnel = desired.lock().await.get(&header.tunnel_id).cloned();
    let Some(tunnel) = tunnel else {
        anyhow::bail!("Tunnel 未在当前 Desired State 中");
    };
    if !tunnel.enabled {
        anyhow::bail!("Tunnel 已关闭");
    }
    if !matches!(tunnel.protocol.as_str(), "tcp" | "http" | "https") {
        anyhow::bail!("Tunnel 协议不受支持");
    }
    match connect_origin(&tunnel).await? {
        OriginConnection::Plain(mut local) => {
            tokio::io::copy_bidirectional(&mut local, &mut stream_io)
                .await
                .context("Tunnel 本地转发失败")?;
        }
        OriginConnection::Tls(mut local) => {
            tokio::io::copy_bidirectional(&mut local, &mut stream_io)
                .await
                .context("HTTPS Origin Tunnel 转发失败")?;
        }
    }
    Ok(())
}

/// 在兼容旧版整体 ACK 后追加逐路由结果。旧 Server 会忽略未知消息前无法
/// 返回确认，因此只在收到整体 ACK 后发送，确保 N-1 Agent/Server 仍可通信。
async fn send_gateway_route_report(
    reader: &mut AsyncBufReader<tokio_rustls::client::TlsStream<TcpStream>>,
    state: &GatewayDesiredState,
    ack: &GatewayApplyAck,
    local_apply_succeeded: bool,
) -> Result<()> {
    let report = GatewayRouteApplyReport {
        revision: state.revision,
        routes: state
            .routes
            .iter()
            .map(|route| GatewayRouteApplyResult {
                network_id: route.network_id.clone(),
                site_link_id: route.site_link_id.clone(),
                prefix: route.prefix.clone(),
                revision: route.revision,
                enabled: route.enabled,
                // 只有执行器明确报告本机命令成功，才允许报告本地成功；
                // 演练模式、开关关闭或具体命令失败都必须保持 false。
                local_applied: local_apply_succeeded
                    && !matches!(ack.status, ApplyStatus::Failed | ApplyStatus::Retrying),
                control_plane_status: None,
                // Site Gateway 使用 --accept-routes=true 且关闭 SNAT；Tailscale
                // set 成功后即可确认本地已接受远端路由，Headscale serving 仍由 Server
                // 单独核对。
                remote_applied: route.site_link_id.is_some()
                    && local_apply_succeeded
                    && !matches!(ack.status, ApplyStatus::Failed | ApplyStatus::Retrying),
                error_message: ack.error_message.clone(),
            })
            .collect(),
        mesh_identity: None,
    };
    write_agent_message(
        reader.get_mut(),
        &AgentControlMessage::GatewayRouteApplyReport { report },
    )
    .await?;
    match read_control_response(reader).await? {
        ServerControlMessage::GatewayApplyAccepted { revision } if revision == state.revision => {
            Ok(())
        }
        ServerControlMessage::Error { message } => {
            anyhow::bail!("服务端拒绝逐路由应用报告：{message}")
        }
        _ => anyhow::bail!("服务端返回了无效的逐路由应用确认响应"),
    }
}

/// 对服务端下发的 Tunnel Desired State 做真实本地探测。
///
/// 这里只确认 Agent 能否连接本地 Origin，不会因为“收到配置”就伪造
/// `ready`；公网监听和 Caddy 状态由 Server 侧另行确认。
async fn send_tunnel_apply_report(
    reader: &mut AsyncBufReader<tokio_rustls::client::TlsStream<TcpStream>>,
    tunnels: &[TunnelDesiredState],
    _config: &AgentRuntimeConfig,
) -> Result<()> {
    let mut results = Vec::with_capacity(tunnels.len());
    for tunnel in tunnels {
        if !tunnel.enabled {
            results.push(TunnelApplyResult {
                tunnel_id: tunnel.tunnel_id.clone(),
                revision: tunnel.revision,
                applied: true,
                status: "disabled".to_owned(),
                error_message: None,
            });
            continue;
        }
        let probe = tokio::time::timeout(Duration::from_secs(5), connect_origin(tunnel)).await;
        match probe {
            Ok(Ok(stream)) => {
                drop(stream);
                results.push(TunnelApplyResult {
                    tunnel_id: tunnel.tunnel_id.clone(),
                    revision: tunnel.revision,
                    applied: true,
                    status: "ready".to_owned(),
                    error_message: None,
                });
            }
            Ok(Err(error)) => {
                // `connect_origin` 的错误会包含本地目标和 TLS 阶段，
                // 直接回传给管理界面即可；不会包含任何 Secret 明文。
                let message = format!("本地服务暂时无法连接：{error:#}");
                results.push(TunnelApplyResult {
                    tunnel_id: tunnel.tunnel_id.clone(),
                    revision: tunnel.revision,
                    applied: false,
                    status: "retrying".to_owned(),
                    error_message: Some(message),
                });
            }
            Err(_) => {
                let message = "本地服务连接超时".to_owned();
                results.push(TunnelApplyResult {
                    tunnel_id: tunnel.tunnel_id.clone(),
                    revision: tunnel.revision,
                    applied: false,
                    status: "retrying".to_owned(),
                    error_message: Some(message),
                });
            }
        }
    }
    if results.is_empty() {
        return Ok(());
    }
    write_agent_message(
        reader.get_mut(),
        &AgentControlMessage::TunnelApplyReport {
            results: results.clone(),
        },
    )
    .await?;
    match read_control_response(reader).await? {
        ServerControlMessage::TunnelApplyAccepted { tunnel_ids } => {
            let accepted: std::collections::HashSet<_> = tunnel_ids.into_iter().collect();
            if accepted.len() != results.len() {
                anyhow::bail!("服务端只接受了部分 Tunnel 应用结果");
            }
        }
        ServerControlMessage::Error { message } => {
            anyhow::bail!("服务端拒绝 Tunnel 应用结果：{message}")
        }
        _ => anyhow::bail!("服务端返回了无效的 Tunnel 应用确认响应"),
    }
    Ok(())
}

/// Agent 到本地 Origin 的连接形态。Web Service 的 HTTP 请求始终由 Caddy
/// 以明文写入 Nexo Unix Socket；只有这里根据 Desired State 对 HTTPS Origin
/// 建立 TLS，避免把公网入口证书和用户本地服务证书混在同一层处理。
enum OriginConnection {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

/// 连接并（按需）完成本地 Origin TLS 握手。握手成功后才算 Agent 的
/// Tunnel 应用成功，因而 Web UI 不会把“只收到配置”显示为已生效。
async fn connect_origin(tunnel: &TunnelDesiredState) -> Result<OriginConnection> {
    let target = format_tcp_target(&tunnel.local_address, tunnel.local_port);
    let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&target))
        .await
        .with_context(|| format!("连接本地 Tunnel 服务超时：{target}"))??;
    let origin_protocol =
        tunnel
            .origin_protocol
            .as_deref()
            .unwrap_or(if tunnel.protocol == "https" {
                "https"
            } else {
                "http"
            });
    if origin_protocol != "https" {
        return Ok(OriginConnection::Plain(stream));
    }

    let connector = build_origin_tls_connector(tunnel)?;
    let server_name = origin_server_name(tunnel)?;
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await
    .context("本地 HTTPS Origin TLS 握手超时")?
    .context("本地 HTTPS Origin TLS 握手失败")?;
    Ok(OriginConnection::Tls(Box::new(tls_stream)))
}

fn origin_server_name(tunnel: &TunnelDesiredState) -> Result<ServerName<'static>> {
    let value = tunnel
        .origin_tls_server_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&tunnel.local_address)
        .trim()
        .trim_end_matches('.')
        .to_owned();
    if let Ok(address) = value.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(address.into()));
    }
    ServerName::try_from(value).map_err(|_| anyhow::anyhow!("HTTPS Origin Server Name 无效"))
}

/// 构建 HTTPS Origin 校验器。system 模式读取容器操作系统的 CA bundle，
/// custom_ca 只使用服务端通过 mTLS 下发的单个 Web Service CA；insecure
/// 是显式高级选项，只跳过证书链校验而仍保留 TLS 握手签名校验。
fn build_origin_tls_connector(tunnel: &TunnelDesiredState) -> Result<TlsConnector> {
    let verification = tunnel
        .origin_tls_verification
        .as_deref()
        .unwrap_or("system");
    if verification == "insecure" {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = SkipOriginCertificateVerification(provider);
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        return Ok(TlsConnector::from(Arc::new(config)));
    }

    let certificates = if verification == "custom_ca" {
        let pem = tunnel
            .origin_ca_pem
            .as_deref()
            .filter(|pem| !pem.trim().is_empty())
            .context("HTTPS Origin 缺少自定义 CA")?;
        parse_certificates(pem).context("HTTPS Origin 自定义 CA 格式无效")?
    } else if verification == "system" {
        load_system_root_certificates()?
    } else {
        anyhow::bail!("HTTPS Origin 证书校验方式不受支持：{verification}");
    };
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .context("HTTPS Origin CA 证书无法加入信任库")?;
    }
    if roots.is_empty() {
        anyhow::bail!("HTTPS Origin CA 信任库为空");
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Linux 容器通常把系统 CA 放在 `/etc/ssl/certs/ca-certificates.crt`；
/// 同时尊重 SSL_CERT_FILE 与 RHEL 系路径，便于在不同发行版中保持 system
/// 校验语义。找不到任何有效证书时明确失败，而不是静默降级到不安全模式。
fn load_system_root_certificates() -> Result<Vec<CertificateDer<'static>>> {
    let mut paths = Vec::new();
    if let Some(path) = env::var_os("SSL_CERT_FILE") {
        paths.push(PathBuf::from(path));
    }
    paths.extend([
        PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
        PathBuf::from("/etc/pki/tls/certs/ca-bundle.crt"),
    ]);
    let mut certificates = Vec::new();
    for path in paths {
        let Ok(pem) = fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(mut parsed) = parse_certificates(&pem) {
            certificates.append(&mut parsed);
        }
        if !certificates.is_empty() {
            break;
        }
    }
    if certificates.is_empty() {
        anyhow::bail!("无法读取操作系统 CA 证书，请改用自定义 CA 或检查容器 CA 包");
    }
    Ok(certificates)
}

/// `insecure` 仅是用户明确选择的本地 Origin 高级选项；TLS 内部签名仍
/// 交给 rustls 当前 crypto provider 验证，避免把损坏的握手误当成成功。
#[derive(Debug)]
struct SkipOriginCertificateVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipOriginCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// 使用一次性 Headscale Key 加入组网，并通过 mTLS 回报可交叉校验的运行身份。
///
/// Agent 不把 Headscale Node/API Key 暴露到 UI；Key 只存在本函数栈帧，发送确认
/// 后立即释放。Node ID 由 Server 根据 Key ID 从 Headscale API 解析并绑定。
async fn apply_mesh_enrollment_offer(
    reader: &mut AsyncBufReader<tokio_rustls::client::TlsStream<TcpStream>>,
    config: &AgentRuntimeConfig,
    offer: &MeshEnrollmentOffer,
) -> Result<()> {
    let result = if !config.tailscale_apply_enabled {
        Err(anyhow::anyhow!("Agent 未启用组网客户端执行"))
    } else {
        let socket = config.state_dir.join("tailscaled.sock");
        let mut command = TokioCommand::new(&config.tailscale_bin);
        command
            .env("TS_SOCKET", &socket)
            .arg(tailscale_socket_arg(&socket))
            .args(mesh_enrollment_command_args(offer));
        if offer.reset {
            // 身份恢复由管理员明确确认后才会设置 reset；首次入网不会触碰
            // Agent 已保存的 Tailscale 状态，避免误删正常组网连接。
            command.arg("--reset");
        }
        let output = command.output().await.with_context(|| {
            format!("无法执行 Tailscale 组网加入命令：{}", config.tailscale_bin)
        })?;
        if output.status.success() {
            Ok(query_tailscale_identity(config).await?)
        } else {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            Err(anyhow::anyhow!(
                "Tailscale 组网加入失败（退出码 {:?}）：{}",
                output.status.code(),
                if detail.is_empty() {
                    "命令未返回错误详情"
                } else {
                    &detail
                }
            ))
        }
    };
    let (success, identity, error_message) = match result {
        Ok(identity) => (true, Some(identity), None),
        Err(error) => {
            let message = redact_enrollment_secret(&format!("{error:#}"), &offer.auth_key);
            tracing::warn!("组网加入失败，服务端将按退避策略重试：{}", message);
            (false, None, Some(message))
        }
    };
    write_agent_message(
        reader.get_mut(),
        &AgentControlMessage::MeshEnrollmentAck {
            auth_key_id: offer.auth_key_id.clone(),
            success,
            identity,
            error_message,
        },
    )
    .await?;
    // Server 会返回一个普通 ACK；不把响应内容传给 UI，也不会记录密钥。
    let _ = read_control_response(reader).await?;
    Ok(())
}

/// 生成首次组网加入命令的固定参数。
///
/// `tailscale up` 会同时建立普通 Mesh 和站点网关所需的基础策略。关闭
/// Subnet Route SNAT 可以保留真实 LAN 源地址；Subnet Gateway 在收到实际
/// Desired State 后会通过 `tailscale set` 恢复适合自身能力的策略。
fn mesh_enrollment_command_args(offer: &MeshEnrollmentOffer) -> Vec<String> {
    vec![
        "up".to_owned(),
        "--login-server".to_owned(),
        offer.endpoint.clone(),
        "--auth-key".to_owned(),
        offer.auth_key.clone(),
        "--hostname".to_owned(),
        offer.hostname.clone(),
        "--accept-dns=true".to_owned(),
        "--accept-routes=true".to_owned(),
        "--snat-subnet-routes=false".to_owned(),
    ]
}

/// 防止 Tailscale CLI 异常输出意外回显一次性入网密钥。
fn redact_enrollment_secret(message: &str, auth_key: &str) -> String {
    if auth_key.trim().is_empty() {
        message.to_owned()
    } else {
        message.replace(auth_key, "<redacted>")
    }
}

/// 组合本地 TCP 目标地址；IPv6 必须使用方括号包裹，避免把地址中的冒号
/// 误解析为端口分隔符。Server 侧只接受 IP 或 DNS 名称，因此无需支持带端口
/// 的用户输入，所有端口都来自已校验的 `u16` 字段。
fn format_tcp_target(address: &str, port: u16) -> String {
    if address.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

async fn query_tailscale_identity(config: &AgentRuntimeConfig) -> Result<MeshIdentityReport> {
    let socket = config.state_dir.join("tailscaled.sock");
    let ipv4 = query_tailscale_value(config, &socket, &["ip", "-4"]).await;
    let ipv6 = query_tailscale_value(config, &socket, &["ip", "-6"]).await;
    let status = TokioCommand::new(&config.tailscale_bin)
        .env("TS_SOCKET", &socket)
        .arg(tailscale_socket_arg(&socket))
        .args(["status", "--json"])
        .output()
        .await;
    let (node_id, hostname, online) = status
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| serde_json::from_slice::<serde_json::Value>(&output.stdout).ok())
        .map(|json| {
            let self_node = json.get("Self").unwrap_or(&json);
            let online = self_node
                .get("Online")
                .and_then(serde_json::Value::as_bool)
                .or_else(|| {
                    json.get("BackendState")
                        .and_then(serde_json::Value::as_str)
                        .map(|state| state.eq_ignore_ascii_case("running"))
                })
                .unwrap_or(false);
            (
                // Tailscale 的 `Self.NodeID` 与 Headscale REST 的数字 Node ID
                // 对应；`Self.ID` 是稳定节点密钥标识，不能拿来冒充 Headscale ID。
                self_node
                    .get("NodeID")
                    .and_then(parse_tailscale_node_id)
                    .or_else(|| self_node.get("ID").and_then(parse_tailscale_node_id)),
                self_node
                    .get("HostName")
                    .or_else(|| self_node.get("DNSName"))
                    .and_then(|value| value.as_str())
                    .map(str::to_owned),
                online,
            )
        })
        .unwrap_or((None, None, false));
    Ok(MeshIdentityReport {
        node_id,
        hostname,
        ipv4,
        ipv6,
        online,
    })
}

/// 从 Tailscale 状态 JSON 提取可与 Headscale Node ID 交叉校验的字符串。
/// 不接受空值或 `n...` 形式的稳定节点密钥标识，避免误报身份错配。
fn parse_tailscale_node_id(value: &serde_json::Value) -> Option<String> {
    if let Some(number) = value.as_u64() {
        return (number > 0).then(|| number.to_string());
    }
    value
        .as_str()
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && value != &"0"
                && value.chars().all(|character| character.is_ascii_digit())
        })
        .map(str::to_owned)
}

/// 组网客户端暂时未启动时不发送“全为空”的报告，避免覆盖服务端保存的
/// 最近一次有效地址；首次入网仍由 Mesh Enrollment ACK 完成身份绑定。
async fn query_optional_mesh_identity(config: &AgentRuntimeConfig) -> Option<MeshIdentityReport> {
    if !config.tailscale_apply_enabled || !config.tailscaled_enabled {
        return None;
    }
    query_tailscale_identity(config)
        .await
        .ok()
        .filter(|identity| {
            identity.online
                || identity.node_id.is_some()
                || identity.ipv4.is_some()
                || identity.ipv6.is_some()
                || identity.hostname.is_some()
        })
}

async fn query_tailscale_value(
    config: &AgentRuntimeConfig,
    socket: &std::path::Path,
    args: &[&str],
) -> Option<String> {
    TokioCommand::new(&config.tailscale_bin)
        .env("TS_SOCKET", socket)
        .arg(tailscale_socket_arg(socket))
        .args(args)
        .output()
        .await
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            (!value.is_empty()).then_some(value)
        })
}

/// 判断本次心跳是否需要重新应用网关状态。
///
/// Desired State 内容变化必须立即应用；相同内容只有在退避时间到达后才重试，
/// 避免 Tailscale 或宿主机暂时故障时每个心跳都重复执行系统命令。运行时健康
/// 门控可能在不修改数据库 revision 的情况下暂停再恢复路由，因此不能只比较 revision。
/// 成功应用后的下一次心跳会再确认一次，覆盖 Server 重启时并发状态投影可能
/// 覆盖单次逐路由 ACK 的窗口；确认成功后不会继续重复执行系统命令。
fn should_apply_gateway_state(
    state: &GatewayDesiredState,
    last_state: Option<&GatewayDesiredState>,
    last_status: Option<ApplyStatus>,
    retry_at: Option<Instant>,
    confirmation_pending: bool,
    capabilities_changed: bool,
) -> bool {
    if last_state != Some(state) {
        return true;
    }
    if confirmation_pending {
        return true;
    }
    if capabilities_changed && last_status == Some(ApplyStatus::Failed) {
        return true;
    }
    if !last_status.is_some_and(|status| matches!(status, ApplyStatus::Retrying)) {
        return false;
    }
    retry_at.is_none_or(|deadline| Instant::now() >= deadline)
}

/// 根据应用结果更新失败重试计划。
///
/// 退避从 5 秒开始，最多 5 分钟；抖动最多占当前基础延迟的 25%，
/// 让多个 Agent 在同一时刻失败时不会同时轰击服务端或本机 Tailscale。
fn update_gateway_retry_state(
    status: ApplyStatus,
    attempt: &mut u32,
    retry_at: &mut Option<Instant>,
) {
    if !matches!(status, ApplyStatus::Retrying) {
        *attempt = 0;
        *retry_at = None;
        return;
    }
    *attempt = attempt.saturating_add(1);
    let delay = gateway_retry_delay(*attempt, retry_jitter_seconds(*attempt));
    *retry_at = Some(Instant::now() + delay);
    tracing::warn!(
        attempt = *attempt,
        retry_after_seconds = delay.as_secs(),
        "网关应用失败，将按退避计划重试"
    );
}

/// 计算指数退避时长；attempt 从 1 开始，结果被限制在最大值以内。
fn gateway_retry_delay(attempt: u32, jitter_seconds: u64) -> Duration {
    const BASE_SECONDS: u64 = 5;
    const MAX_SECONDS: u64 = 300;
    let exponent = attempt.saturating_sub(1).min(6);
    let base = BASE_SECONDS
        .saturating_mul(1_u64 << exponent)
        .min(MAX_SECONDS);
    Duration::from_secs((base + jitter_seconds.min(base / 4)).min(MAX_SECONDS))
}

/// 生成低成本的进程内抖动，不引入新的随机数依赖。
fn retry_jitter_seconds(attempt: u32) -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u64)
        .unwrap_or_default();
    let base_seconds = gateway_retry_delay(attempt, 0).as_secs();
    let jitter_window = (base_seconds / 4).max(1);
    nanos.wrapping_add(u64::from(attempt)) % (jitter_window + 1)
}

/// 网关路由执行器的稳定边界。
///
/// 计划和执行分离，便于测试，也避免后续把 Tailscale CLI 细节泄漏到
/// 控制协议。执行成功只代表本机命令被接受，不代表 Headscale 已批准路由。
trait GatewayRouteApplier {
    /// 返回是否确实执行了本机命令；演练/未启用模式必须返回 false。
    fn apply(&self, plan: &TailscaleRoutePlan) -> Result<bool>;
}

/// Tailscale CLI 执行器；只有显式设置 NEXO_TAILSCALE_APPLY=true 才会运行命令。
///
/// Nexo 负责传入完整的网关参数，避免把 Exit Node、默认路由等能力混入命令。
struct TailscaleRouteApplier {
    enabled: bool,
    binary: String,
    socket: Option<PathBuf>,
}

impl TailscaleRouteApplier {
    /// 根据 Agent 启动配置创建执行器；默认使用演练模式。
    fn from_config(config: &AgentRuntimeConfig) -> Self {
        Self {
            enabled: config.tailscale_apply_enabled,
            binary: config.tailscale_bin.clone(),
            socket: if config.tailscaled_enabled {
                Some(config.state_dir.join("tailscaled.sock"))
            } else {
                None
            },
        }
    }
}

impl GatewayRouteApplier for TailscaleRouteApplier {
    fn apply(&self, plan: &TailscaleRoutePlan) -> Result<bool> {
        if !self.enabled {
            tracing::info!("Tailscale 命令执行未启用，仅生成网关应用计划");
            return Ok(false);
        }
        let mut command = Command::new(&self.binary);
        if let Some(socket) = &self.socket {
            command.env("TS_SOCKET", socket);
            command.arg(tailscale_socket_arg(socket));
        }
        command.args(tailscale_command_args(plan));
        let output = command
            .output()
            .with_context(|| format!("无法执行 Tailscale 命令：{}", self.binary))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let detail = if stderr.is_empty() { stdout } else { stderr };
            anyhow::bail!(
                "Tailscale 网关配置失败（退出码 {:?}）：{}",
                output.status.code(),
                if detail.is_empty() {
                    "命令未返回错误详情"
                } else {
                    &detail
                }
            );
        }
        tracing::info!("Tailscale 网关参数已应用，等待 Headscale 路由批准");
        Ok(true)
    }
}

/// 生成固定顺序的 Tailscale 参数，便于审计和单元测试。
fn tailscale_command_args(plan: &TailscaleRoutePlan) -> Vec<String> {
    let mut args = vec![
        "set".to_owned(),
        format!("--advertise-routes={}", plan.advertise_routes.join(",")),
        format!("--accept-routes={}", plan.accept_routes),
    ];
    if let Some(snat_subnet_routes) = plan.snat_subnet_routes {
        args.push(format!("--snat-subnet-routes={snat_subnet_routes}"));
    }
    args
}

/// 测试用的无副作用执行器，也对应默认关闭真实 CLI 时的行为。
#[cfg(test)]
struct NoopGatewayRouteApplier;

#[cfg(test)]
impl GatewayRouteApplier for NoopGatewayRouteApplier {
    fn apply(&self, _plan: &TailscaleRoutePlan) -> Result<bool> {
        Ok(true)
    }
}

/// 处理服务端下发的网关 Desired State（测试和演练模式入口）。
#[cfg(test)]
fn apply_gateway_desired_state(
    state: &GatewayDesiredState,
    applier: &dyn GatewayRouteApplier,
) -> GatewayApplyAck {
    apply_gateway_desired_state_with_report(state, applier, None)
}

/// 处理服务端下发的网关 Desired State。
///
/// 执行器成功后，启用路由仍返回 `checking`：Headscale 的批准状态尚未进入
/// 本地 ACK 链路。全部关闭时返回 `disabled`，让服务端清空 Applied State。
#[cfg(test)]
fn apply_gateway_desired_state_with_report(
    state: &GatewayDesiredState,
    applier: &dyn GatewayRouteApplier,
    gateway_report: Option<&GatewayCapabilityReport>,
) -> GatewayApplyAck {
    apply_gateway_desired_state_with_execution(state, applier, gateway_report).ack
}

/// 网关应用的内部结果；除了兼容旧版整体 ACK，还保留执行器的真实成功标志。
///
/// 这个标志不能从 `tailscale_apply_enabled` 推断：开关开启并不代表命令已经
/// 成功执行，只有执行器返回 `Ok(true)` 时才允许后续逐路由报告触发 Headscale。
struct GatewayApplyExecution {
    ack: GatewayApplyAck,
    local_applied: bool,
}

fn apply_gateway_desired_state_with_execution(
    state: &GatewayDesiredState,
    applier: &dyn GatewayRouteApplier,
    gateway_report: Option<&GatewayCapabilityReport>,
) -> GatewayApplyExecution {
    let network_ids: Vec<String> = state
        .routes
        .iter()
        .map(|route| route.network_id.clone())
        .collect();
    let plan = match build_tailscale_route_plan(state) {
        Ok(plan) => plan,
        Err(error) => {
            let error_message = format!("服务端下发的网关网络无效：{error}");
            tracing::error!("{}", error_message);
            return GatewayApplyExecution {
                ack: GatewayApplyAck {
                    revision: state.revision,
                    status: ApplyStatus::Failed,
                    network_ids,
                    applied_network_ids: Vec::new(),
                    error_message: Some(error_message),
                },
                local_applied: false,
            };
        }
    };
    if let Some(report) = gateway_report {
        if let Some(error_message) = gateway_capability_error(state, report) {
            tracing::error!("{}", error_message);
            return GatewayApplyExecution {
                ack: GatewayApplyAck {
                    revision: state.revision,
                    status: ApplyStatus::Failed,
                    network_ids,
                    applied_network_ids: Vec::new(),
                    error_message: Some(error_message),
                },
                local_applied: false,
            };
        }
    }
    let local_applied = match applier.apply(&plan) {
        Ok(applied) => applied,
        Err(error) => {
            let error_message = format!("Tailscale 网关应用失败：{error:#}");
            tracing::error!("{}", error_message);
            return GatewayApplyExecution {
                ack: GatewayApplyAck {
                    revision: state.revision,
                    status: ApplyStatus::Retrying,
                    network_ids,
                    applied_network_ids: Vec::new(),
                    error_message: Some(error_message),
                },
                local_applied: false,
            };
        }
    };
    if !state.routes.iter().any(|route| route.enabled) {
        tracing::info!(
            revision = state.revision,
            route_count = state.routes.len(),
            "已收到网关路由撤销配置"
        );
        return GatewayApplyExecution {
            ack: GatewayApplyAck {
                revision: state.revision,
                status: ApplyStatus::Disabled,
                network_ids,
                applied_network_ids: Vec::new(),
                error_message: None,
            },
            local_applied,
        };
    }
    tracing::info!(
        revision = state.revision,
        route_count = state.routes.len(),
        advertise_routes = ?plan.advertise_routes,
        accept_routes = plan.accept_routes,
        snat_subnet_routes = ?plan.snat_subnet_routes,
        "网关 Tailscale 参数已应用，等待 Headscale 路由批准"
    );
    GatewayApplyExecution {
        ack: GatewayApplyAck {
            revision: state.revision,
            status: ApplyStatus::Checking,
            network_ids,
            // 旧 ACK 不承载 Headscale/逐路由状态，不能让 Server 进入 READY。
            applied_network_ids: Vec::new(),
            error_message: None,
        },
        local_applied,
    }
}

/// 在真实应用前再次核对能力，避免设备运行环境变化后仍执行高权限路由操作。
fn gateway_capability_error(
    state: &GatewayDesiredState,
    report: &GatewayCapabilityReport,
) -> Option<String> {
    for route in state.routes.iter().filter(|route| route.enabled) {
        let (capability, reason, label) = if route.site_link_id.is_some() {
            (report.site_gateway, report.site_gateway_reason, "站点互联")
        } else {
            (
                report.subnet_gateway,
                report.subnet_gateway_reason,
                "共享本地网络",
            )
        };
        if capability != CapabilityState::Ready {
            let reason = reason
                .map(gateway_reason_message)
                .unwrap_or("本机当前不满足网关运行条件");
            return Some(format!("{label}无法应用：{reason}"));
        }
    }
    None
}

/// 将内部能力探测原因翻译为可直接展示给用户的中文说明。
fn gateway_reason_message(reason: GatewayCapabilityReason) -> &'static str {
    match reason {
        GatewayCapabilityReason::MissingNetAdmin => "缺少网络管理权限",
        GatewayCapabilityReason::TunNotAvailable => "系统没有可用的 TUN 设备",
        GatewayCapabilityReason::IpForwardingDisabled => "系统未开启 IP 转发",
        GatewayCapabilityReason::NoLocalSubnet => "没有检测到可共享的本地网络",
        GatewayCapabilityReason::UnsupportedPlatform => "当前平台不支持网关能力",
    }
}

/// Agent 交给 Tailscale CLI/本地 API 适配器的最小应用计划。
///
/// 计划只包含 Nexo 已确认的本地发布网段和站点互联是否需要接收远端路由，
/// 不会把 Exit Node 或默认路由混入其中。
#[derive(Debug, PartialEq, Eq)]
struct TailscaleRoutePlan {
    advertise_routes: Vec<String>,
    accept_routes: bool,
    /// 站点互联关闭 SNAT，普通共享网络恢复 Tailscale 默认的 SNAT 行为。
    snat_subnet_routes: Option<bool>,
}

/// 将 Nexo 语义路由转换为 Tailscale 适配器所需的参数。
fn build_tailscale_route_plan(state: &GatewayDesiredState) -> Result<TailscaleRoutePlan> {
    let mut advertise_routes = Vec::new();
    let mut accept_routes = false;
    for route in &state.routes {
        let prefix = route
            .prefix
            .parse::<IpNet>()
            .with_context(|| format!("前缀 {} 不是有效 CIDR", route.prefix))?;
        validate_published_network(prefix)
            .with_context(|| format!("前缀 {} 不允许发布", route.prefix))?;
        if !route.enabled {
            continue;
        }
        if route.site_link_id.is_some() {
            accept_routes = true;
        } else {
            advertise_routes.push(route.prefix.clone());
        }
    }
    advertise_routes.sort();
    advertise_routes.dedup();
    Ok(TailscaleRoutePlan {
        advertise_routes,
        accept_routes,
        snat_subnet_routes: Some(!accept_routes),
    })
}

fn build_tls_connector(config: &AgentRuntimeConfig, key_pair: &KeyPair) -> Result<TlsConnector> {
    let ca_pem = fs::read_to_string(config.state_dir.join("server-ca.pem"))
        .context("无法读取 Nexo Server CA 证书")?;
    let certificate_pem = fs::read_to_string(config.state_dir.join("device-cert.pem"))
        .context("无法读取 Agent 设备证书")?;
    let ca_certificates = parse_certificates(&ca_pem)?;
    let client_certificates = parse_certificates(&certificate_pem)?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in ca_certificates {
        roots.add(certificate)?;
    }
    let private_key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_pair.serialize_der(),
    ));
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_certificates, private_key)?;
    Ok(TlsConnector::from(Arc::new(tls_config)))
}

fn parse_certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("证书 PEM 格式无效")
}

async fn write_agent_message(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    message: &AgentControlMessage,
) -> Result<()> {
    let payload = serde_json::to_string(message)?;
    stream.write_all(payload.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

async fn read_control_response(
    reader: &mut AsyncBufReader<tokio_rustls::client::TlsStream<TcpStream>>,
) -> Result<ServerControlMessage> {
    let mut line = String::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_line(&mut line),
    )
    .await
    .context("等待 Nexo Server 控制响应超时")??;
    if read == 0 {
        anyhow::bail!("Nexo Server 已关闭控制连接");
    }
    serde_json::from_str(line.trim()).context("Nexo Server 控制响应格式无效")
}

fn parse_capabilities(raw: &str) -> Result<Vec<DeviceCapability>> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| match value {
            "tunnel" => Ok(DeviceCapability::Tunnel),
            "mesh" => Ok(DeviceCapability::Mesh),
            "subnet_gateway" => Ok(DeviceCapability::SubnetGateway),
            "site_gateway" => Ok(DeviceCapability::SiteGateway),
            other => anyhow::bail!("NEXO_AGENT_CAPABILITIES 包含未知能力：{other}"),
        })
        .collect()
}

/// 探测 Agent 是否具备发布本地网络和执行站点转发所需的基础条件。
///
/// 探测只读系统状态，不会自动开启 TUN、修改 capability 或写入宿主机 sysctl。
fn detect_gateway_capabilities() -> GatewayCapabilityReport {
    let local_networks = detect_local_networks();
    let tun_available = cfg!(target_os = "linux") && std::path::Path::new("/dev/net/tun").exists();
    let net_admin_available = cfg!(target_os = "linux") && detect_net_admin();
    let ipv4_forwarding =
        cfg!(target_os = "linux") && read_linux_flag("/proc/sys/net/ipv4/ip_forward");
    let ipv6_forwarding =
        cfg!(target_os = "linux") && read_linux_flag("/proc/sys/net/ipv6/conf/all/forwarding");
    let reason = gateway_unavailable_reason(
        tun_available,
        net_admin_available,
        ipv4_forwarding,
        ipv6_forwarding,
        &local_networks,
    );
    let state = match reason {
        Some(_) => CapabilityState::Unavailable,
        None => CapabilityState::Ready,
    };
    GatewayCapabilityReport {
        platform: env::consts::OS.to_owned(),
        tun_available,
        net_admin_available,
        ipv4_forwarding,
        ipv6_forwarding,
        local_networks,
        subnet_gateway: state,
        subnet_gateway_reason: reason,
        site_gateway: state,
        site_gateway_reason: reason,
    }
}

fn gateway_unavailable_reason(
    tun_available: bool,
    net_admin_available: bool,
    ipv4_forwarding: bool,
    ipv6_forwarding: bool,
    local_networks: &[DetectedLocalNetwork],
) -> Option<GatewayCapabilityReason> {
    if !cfg!(target_os = "linux") {
        return Some(GatewayCapabilityReason::UnsupportedPlatform);
    }
    if !tun_available {
        return Some(GatewayCapabilityReason::TunNotAvailable);
    }
    if !net_admin_available {
        return Some(GatewayCapabilityReason::MissingNetAdmin);
    }
    if local_networks.is_empty() {
        return Some(GatewayCapabilityReason::NoLocalSubnet);
    }
    if !ipv4_forwarding
        && local_networks.iter().any(|network| {
            network
                .prefix
                .parse::<IpNet>()
                .is_ok_and(|prefix| matches!(prefix, IpNet::V4(_)))
        })
    {
        return Some(GatewayCapabilityReason::IpForwardingDisabled);
    }
    if !ipv6_forwarding
        && local_networks.iter().any(|network| {
            network
                .prefix
                .parse::<IpNet>()
                .is_ok_and(|prefix| matches!(prefix, IpNet::V6(_)))
        })
    {
        return Some(GatewayCapabilityReason::IpForwardingDisabled);
    }
    None
}

fn detect_local_networks() -> Vec<DetectedLocalNetwork> {
    let interfaces = match get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(error) => {
            tracing::warn!("无法读取本地网卡地址，网关能力暂标记为不可用：{}", error);
            return Vec::new();
        }
    };
    interfaces
        .into_iter()
        .filter_map(|interface| {
            let (ip, netmask) = match interface.addr {
                IfAddr::V4(address) => (address.ip.into(), address.netmask.into()),
                IfAddr::V6(address) => (address.ip.into(), address.netmask.into()),
            };
            // 能力报告中的 prefix 必须是规范网络地址，而不是带主机位的
            // `192.168.10.2/24`；否则服务端无法和用户选择的 CIDR 精确匹配。
            let prefix = IpNet::with_netmask(ip, netmask).ok()?.trunc();
            if validate_published_network(prefix).is_err() {
                return None;
            }
            Some(DetectedLocalNetwork {
                interface_id: interface.name,
                prefix: prefix.to_string(),
                gateway_address: Some(ip.to_string()),
            })
        })
        .collect()
}

fn read_linux_flag(path: &str) -> bool {
    fs::read_to_string(path)
        .map(|value| value.trim() == "1")
        .unwrap_or(false)
}

fn detect_net_admin() -> bool {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(status) => status,
        Err(_) => return false,
    };
    let effective = match status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
    {
        Some(value) => value.trim(),
        None => return false,
    };
    u64::from_str_radix(effective, 16)
        .map(|capabilities| capabilities & (1 << 12) != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_probe_reports_missing_tun_before_other_requirements() {
        let reason = gateway_unavailable_reason(false, false, false, false, &[]);
        if cfg!(target_os = "linux") {
            assert_eq!(reason, Some(GatewayCapabilityReason::TunNotAvailable));
        } else {
            assert_eq!(reason, Some(GatewayCapabilityReason::UnsupportedPlatform));
        }
    }

    #[test]
    fn gateway_probe_requires_forwarding_for_ipv4_networks() {
        let networks = vec![DetectedLocalNetwork {
            interface_id: "eth0".to_owned(),
            prefix: "192.168.10.0/24".to_owned(),
            gateway_address: None,
        }];
        let reason = gateway_unavailable_reason(true, true, false, true, &networks);
        if cfg!(target_os = "linux") {
            assert_eq!(reason, Some(GatewayCapabilityReason::IpForwardingDisabled));
        } else {
            assert_eq!(reason, Some(GatewayCapabilityReason::UnsupportedPlatform));
        }
    }

    #[test]
    fn gateway_probe_accepts_ready_linux_baseline() {
        let networks = vec![DetectedLocalNetwork {
            interface_id: "eth0".to_owned(),
            prefix: "192.168.10.0/24".to_owned(),
            gateway_address: None,
        }];
        let reason = gateway_unavailable_reason(true, true, true, true, &networks);
        if cfg!(target_os = "linux") {
            assert_eq!(reason, None);
        } else {
            assert_eq!(reason, Some(GatewayCapabilityReason::UnsupportedPlatform));
        }
    }

    #[test]
    fn gateway_apply_ack_keeps_routes_checking_until_adapter_is_connected() {
        let state = GatewayDesiredState {
            revision: 3,
            routes: vec![nexo_protocol::GatewayDesiredRoute {
                network_id: "network-a".to_owned(),
                site_link_id: None,
                prefix: "192.168.10.0/24".to_owned(),
                revision: 3,
                enabled: true,
            }],
        };
        let ack = apply_gateway_desired_state(&state, &NoopGatewayRouteApplier);
        assert_eq!(ack.revision, 3);
        assert_eq!(ack.status, ApplyStatus::Checking);
        assert_eq!(ack.network_ids, vec!["network-a"]);
        assert!(ack.applied_network_ids.is_empty());
        assert!(ack.error_message.is_none());
    }

    #[test]
    fn gateway_apply_ack_rejects_invalid_route_before_future_system_changes() {
        let state = GatewayDesiredState {
            revision: 4,
            routes: vec![nexo_protocol::GatewayDesiredRoute {
                network_id: "network-invalid".to_owned(),
                site_link_id: None,
                prefix: "0.0.0.0/0".to_owned(),
                revision: 4,
                enabled: true,
            }],
        };
        let ack = apply_gateway_desired_state(&state, &NoopGatewayRouteApplier);
        assert_eq!(ack.status, ApplyStatus::Failed);
        assert_eq!(ack.network_ids, vec!["network-invalid"]);
        assert!(ack.applied_network_ids.is_empty());
        assert!(ack.error_message.is_some());
    }

    #[test]
    fn gateway_apply_ack_marks_all_disabled_routes_as_disabled() {
        let state = GatewayDesiredState {
            revision: 5,
            routes: vec![nexo_protocol::GatewayDesiredRoute {
                network_id: "network-closed".to_owned(),
                site_link_id: None,
                prefix: "192.168.10.0/24".to_owned(),
                revision: 5,
                enabled: false,
            }],
        };
        let ack = apply_gateway_desired_state(&state, &NoopGatewayRouteApplier);
        assert_eq!(ack.status, ApplyStatus::Disabled);
        assert_eq!(ack.network_ids, vec!["network-closed"]);
        assert!(ack.applied_network_ids.is_empty());
        assert!(ack.error_message.is_none());
    }

    #[test]
    fn tailscale_route_plan_keeps_site_routing_bidirectional_without_snat() {
        let state = GatewayDesiredState {
            revision: 6,
            routes: vec![
                nexo_protocol::GatewayDesiredRoute {
                    network_id: "local".to_owned(),
                    site_link_id: None,
                    prefix: "192.168.10.0/24".to_owned(),
                    revision: 6,
                    enabled: true,
                },
                nexo_protocol::GatewayDesiredRoute {
                    network_id: "remote".to_owned(),
                    site_link_id: Some("link-a-b".to_owned()),
                    prefix: "192.168.20.0/24".to_owned(),
                    revision: 6,
                    enabled: true,
                },
                nexo_protocol::GatewayDesiredRoute {
                    network_id: "old".to_owned(),
                    site_link_id: None,
                    prefix: "192.168.30.0/24".to_owned(),
                    revision: 5,
                    enabled: false,
                },
            ],
        };
        let plan = build_tailscale_route_plan(&state).expect("应生成站点网关应用计划");
        assert_eq!(plan.advertise_routes, vec!["192.168.10.0/24"]);
        assert!(plan.accept_routes);
        assert_eq!(plan.snat_subnet_routes, Some(false));
    }

    #[test]
    fn disabled_tailscale_executor_does_not_require_binary() {
        let applier = TailscaleRouteApplier {
            enabled: false,
            binary: "this-command-should-not-run".to_owned(),
            socket: None,
        };
        let plan = TailscaleRoutePlan {
            advertise_routes: vec!["192.168.10.0/24".to_owned()],
            accept_routes: false,
            snat_subnet_routes: None,
        };
        applier
            .apply(&plan)
            .expect("关闭执行开关时不应尝试查找 Tailscale");
    }

    #[test]
    fn parse_bool_env_only_accepts_explicit_true_values() {
        assert!(parse_bool_env("true"));
        assert!(parse_bool_env(" ON "));
        assert!(parse_bool_env("1"));
        assert!(!parse_bool_env("false"));
        assert!(!parse_bool_env("enabled"));
    }

    #[test]
    fn transient_zero_tailscale_node_id_is_not_reported_as_identity() {
        assert_eq!(parse_tailscale_node_id(&serde_json::json!(0)), None);
        assert_eq!(parse_tailscale_node_id(&serde_json::json!("0")), None);
        assert_eq!(
            parse_tailscale_node_id(&serde_json::json!(2)),
            Some("2".to_owned())
        );
    }

    #[test]
    fn enrollment_error_redacts_one_time_secret() {
        let message =
            redact_enrollment_secret("tailscale failed for hskey-secret-123", "hskey-secret-123");
        assert_eq!(message, "tailscale failed for <redacted>");
    }

    #[test]
    fn tcp_target_formats_ipv4_and_dns_without_brackets() {
        assert_eq!(format_tcp_target("127.0.0.1", 8808), "127.0.0.1:8808");
        assert_eq!(
            format_tcp_target("origin.internal", 443),
            "origin.internal:443"
        );
    }

    #[test]
    fn tcp_target_wraps_ipv6_literals() {
        assert_eq!(format_tcp_target("::1", 8808), "[::1]:8808");
        assert_eq!(format_tcp_target("2001:db8::10", 443), "[2001:db8::10]:443");
    }

    #[test]
    fn tailscale_command_args_are_limited_to_gateway_flags() {
        let plan = TailscaleRoutePlan {
            advertise_routes: vec!["192.168.10.0/24".to_owned(), "192.168.30.0/24".to_owned()],
            accept_routes: true,
            snat_subnet_routes: Some(false),
        };
        assert_eq!(
            tailscale_command_args(&plan),
            vec![
                "set",
                "--advertise-routes=192.168.10.0/24,192.168.30.0/24",
                "--accept-routes=true",
                "--snat-subnet-routes=false",
            ]
        );
    }

    #[test]
    fn mesh_enrollment_disables_subnet_route_snat() {
        let offer = MeshEnrollmentOffer {
            endpoint: "https://mesh.example.com".to_owned(),
            auth_key: "one-time-key".to_owned(),
            auth_key_id: "key-id".to_owned(),
            hostname: "default-gateway-ab12".to_owned(),
            reset: false,
            tenant_id: Some("default".to_owned()),
        };
        assert_eq!(
            mesh_enrollment_command_args(&offer),
            vec![
                "up",
                "--login-server",
                "https://mesh.example.com",
                "--auth-key",
                "one-time-key",
                "--hostname",
                "default-gateway-ab12",
                "--accept-dns=true",
                "--accept-routes=true",
                "--snat-subnet-routes=false",
            ]
        );
    }

    #[test]
    fn tailscale_socket_arg_uses_supported_global_flag() {
        assert_eq!(
            tailscale_socket_arg(std::path::Path::new("/data/nexo-agent/tailscaled.sock")),
            "--socket=/data/nexo-agent/tailscaled.sock"
        );
    }

    #[test]
    fn tailscale_executor_failure_is_reported_as_retrying_ack() {
        let state = GatewayDesiredState {
            revision: 7,
            routes: vec![nexo_protocol::GatewayDesiredRoute {
                network_id: "network-a".to_owned(),
                site_link_id: None,
                prefix: "192.168.10.0/24".to_owned(),
                revision: 7,
                enabled: true,
            }],
        };
        let applier = TailscaleRouteApplier {
            enabled: true,
            binary: "__nexo_missing_tailscale_binary__".to_owned(),
            socket: None,
        };
        let ack = apply_gateway_desired_state(&state, &applier);
        assert_eq!(ack.status, ApplyStatus::Retrying);
        assert!(ack
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("Tailscale 网关应用失败")));
    }

    #[test]
    fn gateway_retry_delay_is_exponential_and_capped() {
        assert_eq!(gateway_retry_delay(1, 0), Duration::from_secs(5));
        assert_eq!(gateway_retry_delay(2, 0), Duration::from_secs(10));
        assert_eq!(gateway_retry_delay(3, 2), Duration::from_secs(22));
        assert_eq!(gateway_retry_delay(99, 99), Duration::from_secs(300));
    }

    #[test]
    fn gateway_retry_state_resets_after_non_retry_status() {
        let mut attempt = 4;
        let mut retry_at = Some(Instant::now());
        update_gateway_retry_state(ApplyStatus::Checking, &mut attempt, &mut retry_at);
        assert_eq!(attempt, 0);
        assert!(retry_at.is_none());
    }

    #[test]
    fn gateway_retry_waits_until_deadline_for_same_revision() {
        let state = GatewayDesiredState {
            revision: 8,
            routes: Vec::new(),
        };
        assert!(!should_apply_gateway_state(
            &state,
            Some(&state),
            Some(ApplyStatus::Retrying),
            Some(Instant::now() + Duration::from_secs(60)),
            false,
            false,
        ));
        assert!(should_apply_gateway_state(
            &state,
            Some(&state),
            Some(ApplyStatus::Retrying),
            Some(Instant::now() - Duration::from_secs(1)),
            false,
            false,
        ));
        assert!(should_apply_gateway_state(
            &state,
            None,
            Some(ApplyStatus::Checking),
            None,
            false,
            false,
        ));
        assert!(should_apply_gateway_state(
            &state,
            Some(&state),
            Some(ApplyStatus::Failed),
            None,
            false,
            true,
        ));
    }

    #[test]
    fn gateway_reapplies_when_runtime_gate_changes_same_revision() {
        let disabled = GatewayDesiredState {
            revision: 8,
            routes: vec![nexo_protocol::GatewayDesiredRoute {
                network_id: "network-a".to_owned(),
                site_link_id: None,
                prefix: "192.168.10.0/24".to_owned(),
                revision: 8,
                enabled: false,
            }],
        };
        let mut enabled = disabled.clone();
        enabled.routes[0].enabled = true;

        assert!(should_apply_gateway_state(
            &enabled,
            Some(&disabled),
            Some(ApplyStatus::Disabled),
            None,
            false,
            false,
        ));
    }

    #[test]
    fn gateway_reapplies_once_when_confirmation_is_pending() {
        let state = GatewayDesiredState {
            revision: 8,
            routes: Vec::new(),
        };
        assert!(should_apply_gateway_state(
            &state,
            Some(&state),
            Some(ApplyStatus::Checking),
            None,
            true,
            false,
        ));
        assert!(!should_apply_gateway_state(
            &state,
            Some(&state),
            Some(ApplyStatus::Checking),
            None,
            false,
            false,
        ));
    }

    #[test]
    fn gateway_apply_rechecks_capability_before_running_applier() {
        let state = GatewayDesiredState {
            revision: 9,
            routes: vec![nexo_protocol::GatewayDesiredRoute {
                network_id: "network-a".to_owned(),
                site_link_id: None,
                prefix: "192.168.10.0/24".to_owned(),
                revision: 9,
                enabled: true,
            }],
        };
        let report = GatewayCapabilityReport {
            platform: "linux".to_owned(),
            tun_available: true,
            net_admin_available: true,
            ipv4_forwarding: false,
            ipv6_forwarding: true,
            local_networks: vec![],
            subnet_gateway: CapabilityState::Unavailable,
            subnet_gateway_reason: Some(GatewayCapabilityReason::IpForwardingDisabled),
            site_gateway: CapabilityState::Unavailable,
            site_gateway_reason: Some(GatewayCapabilityReason::IpForwardingDisabled),
        };
        let ack = apply_gateway_desired_state_with_report(
            &state,
            &NoopGatewayRouteApplier,
            Some(&report),
        );
        assert_eq!(ack.status, ApplyStatus::Failed);
        assert_eq!(
            ack.error_message.as_deref(),
            Some("共享本地网络无法应用：系统未开启 IP 转发")
        );
    }
}
