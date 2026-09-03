//! Nexo Agent 启动入口。
//!
//! Agent 不绑定固定服务端。首次入网时通过环境变量指定目标地址和一次性
//! token，完成请求后继续作为常驻进程运行；后续控制通道会复用同一配置。

use std::{
    env, fs,
    io::BufReader,
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use get_if_addrs::{get_if_addrs, IfAddr};
use ipnet::IpNet;
use nexo_core::{
    validate_published_network, ApplyStatus, CapabilityState, DetectedLocalNetwork,
    DeviceCapability, GatewayCapabilityReason, GatewayCapabilityReport,
};
use nexo_protocol::{
    AgentControlMessage, AgentEnrollmentPollRequest, AgentEnrollmentPollResponse,
    AgentEnrollmentRequest, AgentEnrollmentResponse, GatewayApplyAck, GatewayDesiredState,
    ServerControlMessage,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};

/// Agent 运行时所需的最小配置，避免把服务端地址写死在二进制中。
/// Agent 的启动配置；服务端地址和控制通道地址均可在容器环境变量中指定。
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("nexo_agent=info")
        .init();

    let config = AgentRuntimeConfig::from_environment()?;
    let key_pair = load_or_create_key(&config)?;
    let mut identity_ready = identity_is_persisted(&config)?;
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
                return Ok(());
            }
        }
    } else {
        tracing::info!("未提供 NEXO_ENROLLMENT_TOKEN，Agent 等待后续配置");
    }
    tracing::info!("Nexo Agent 已启动，目标服务端：{}", config.server_url);
    if identity_ready && config.control_addr.is_some() {
        run_control_loop(&config, &key_pair).await?;
    } else {
        if config.control_addr.is_none() {
            tracing::info!("未配置 NEXO_CONTROL_ADDR，暂不建立 mTLS 控制通道");
        }
        tokio::signal::ctrl_c()
            .await
            .context("Agent 等待退出信号失败")?;
    }
    tracing::info!("Nexo Agent 正在退出");
    Ok(())
}

/// 判断 Agent 是否已经完成过身份领取，避免容器重启时重放已消费 token。
fn identity_is_persisted(config: &AgentRuntimeConfig) -> Result<bool> {
    let paths = [
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
        return KeyPair::from_pem(&pem).context("Agent 私钥格式无效");
    }
    let key_pair = KeyPair::generate().context("无法生成 Agent 设备私钥")?;
    fs::write(&path, key_pair.serialize_pem())
        .with_context(|| format!("无法保存 Agent 私钥：{}", path.display()))?;
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
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(None),
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
    fs::write(config.state_dir.join("device-cert.pem"), certificate_pem)
        .context("无法保存 Agent 设备证书")?;
    fs::write(config.state_dir.join("server-ca.pem"), ca_certificate_pem)
        .context("无法保存 Nexo Server CA 证书")?;
    if let Some(device_id) = &approval.device_id {
        fs::write(config.state_dir.join("device-id"), device_id)
            .context("无法保存 Agent 设备 ID")?;
    }
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
    loop {
        match control_session(config, key_pair, control_addr, &device_id).await {
            Ok(()) => tracing::warn!("Nexo mTLS 控制连接已断开，5 秒后重连"),
            Err(error) => tracing::warn!("Nexo mTLS 控制连接失败，5 秒后重试：{error:#}"),
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
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
    write_agent_message(
        reader.get_mut(),
        &AgentControlMessage::Hello {
            device_id: device_id.to_owned(),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: config.capabilities.clone(),
            gateway_report: Some(gateway_report.clone()),
        },
    )
    .await?;
    let response = read_control_response(&mut reader).await?;
    let mut last_gateway_revision = None;
    let mut last_gateway_status = None;
    let mut gateway_retry_attempt = 0;
    let mut gateway_retry_at = None;
    let mut last_gateway_report = Some(gateway_report.clone());
    match response {
        ServerControlMessage::HelloAccepted {
            gateway_state: Some(gateway_state),
            ..
        } => {
            let applier = TailscaleRouteApplier::from_config(config);
            let ack = apply_gateway_desired_state_with_report(
                &gateway_state,
                &applier,
                Some(&gateway_report),
            );
            last_gateway_revision = Some(ack.revision);
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
        }
        ServerControlMessage::HelloAccepted {
            gateway_state: None,
            ..
        } => {}
        ServerControlMessage::Error { message } => anyhow::bail!("服务端拒绝控制连接：{message}"),
        ServerControlMessage::HeartbeatAck { .. } => {
            anyhow::bail!("服务端在身份声明前返回了心跳确认")
        }
        ServerControlMessage::GatewayApplyAccepted { .. } => {
            anyhow::bail!("服务端在身份声明前返回了网关确认")
        }
    }
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        let heartbeat_gateway_report = detect_gateway_capabilities();
        write_agent_message(
            reader.get_mut(),
            &AgentControlMessage::Heartbeat {
                device_id: device_id.to_owned(),
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
                gateway_report: Some(heartbeat_gateway_report.clone()),
            },
        )
        .await?;
        match read_control_response(&mut reader).await? {
            ServerControlMessage::HeartbeatAck {
                gateway_state: Some(gateway_state),
                ..
            } if should_apply_gateway_state(
                &gateway_state,
                last_gateway_revision,
                last_gateway_status,
                gateway_retry_at,
                last_gateway_report.as_ref() != Some(&heartbeat_gateway_report),
            ) =>
            {
                let applier = TailscaleRouteApplier::from_config(config);
                let ack = apply_gateway_desired_state_with_report(
                    &gateway_state,
                    &applier,
                    Some(&heartbeat_gateway_report),
                );
                last_gateway_revision = Some(ack.revision);
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
            }
            ServerControlMessage::HeartbeatAck {
                gateway_state: None,
                ..
            } => {}
            ServerControlMessage::HeartbeatAck {
                gateway_state: Some(_),
                ..
            } => {}
            ServerControlMessage::Error { message } => anyhow::bail!("服务端拒绝心跳：{message}"),
            ServerControlMessage::HelloAccepted { .. } => {
                anyhow::bail!("服务端重复返回身份确认")
            }
            ServerControlMessage::GatewayApplyAccepted { .. } => {
                anyhow::bail!("服务端在心跳期间返回了网关确认")
            }
        }
        last_gateway_report = Some(heartbeat_gateway_report);
    }
}

/// 判断本次心跳是否需要重新应用网关状态。
///
/// 新 revision 必须立即应用；相同 revision 只有在退避时间到达后才重试，
/// 避免 Tailscale 或宿主机暂时故障时每个心跳都重复执行系统命令。
fn should_apply_gateway_state(
    state: &GatewayDesiredState,
    last_revision: Option<i64>,
    last_status: Option<ApplyStatus>,
    retry_at: Option<Instant>,
    capabilities_changed: bool,
) -> bool {
    if last_revision != Some(state.revision) {
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
    fn apply(&self, plan: &TailscaleRoutePlan) -> Result<()>;
}

/// Tailscale CLI 执行器；只有显式设置 NEXO_TAILSCALE_APPLY=true 才会运行命令。
///
/// Nexo 负责传入完整的网关参数，避免把 Exit Node、默认路由等能力混入命令。
struct TailscaleRouteApplier {
    enabled: bool,
    binary: String,
}

impl TailscaleRouteApplier {
    /// 根据 Agent 启动配置创建执行器；默认使用演练模式。
    fn from_config(config: &AgentRuntimeConfig) -> Self {
        Self {
            enabled: config.tailscale_apply_enabled,
            binary: config.tailscale_bin.clone(),
        }
    }
}

impl GatewayRouteApplier for TailscaleRouteApplier {
    fn apply(&self, plan: &TailscaleRoutePlan) -> Result<()> {
        if !self.enabled {
            tracing::info!("Tailscale 命令执行未启用，仅生成网关应用计划");
            return Ok(());
        }
        let mut command = Command::new(&self.binary);
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
        Ok(())
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
    fn apply(&self, _plan: &TailscaleRoutePlan) -> Result<()> {
        Ok(())
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
fn apply_gateway_desired_state_with_report(
    state: &GatewayDesiredState,
    applier: &dyn GatewayRouteApplier,
    gateway_report: Option<&GatewayCapabilityReport>,
) -> GatewayApplyAck {
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
            return GatewayApplyAck {
                revision: state.revision,
                status: ApplyStatus::Failed,
                network_ids,
                applied_network_ids: Vec::new(),
                error_message: Some(error_message),
            };
        }
    };
    if let Some(report) = gateway_report {
        if let Some(error_message) = gateway_capability_error(state, report) {
            tracing::error!("{}", error_message);
            return GatewayApplyAck {
                revision: state.revision,
                status: ApplyStatus::Failed,
                network_ids,
                applied_network_ids: Vec::new(),
                error_message: Some(error_message),
            };
        }
    }
    if let Err(error) = applier.apply(&plan) {
        let error_message = format!("Tailscale 网关应用失败：{error:#}");
        tracing::error!("{}", error_message);
        return GatewayApplyAck {
            revision: state.revision,
            status: ApplyStatus::Retrying,
            network_ids,
            applied_network_ids: Vec::new(),
            error_message: Some(error_message),
        };
    }
    if !state.routes.iter().any(|route| route.enabled) {
        tracing::info!(
            revision = state.revision,
            route_count = state.routes.len(),
            "已收到网关路由撤销配置"
        );
        return GatewayApplyAck {
            revision: state.revision,
            status: ApplyStatus::Disabled,
            network_ids,
            applied_network_ids: Vec::new(),
            error_message: None,
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
    GatewayApplyAck {
        revision: state.revision,
        status: ApplyStatus::Checking,
        network_ids,
        applied_network_ids: Vec::new(),
        error_message: None,
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
            let prefix = IpNet::with_netmask(ip, netmask).ok()?;
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
            Some(8),
            Some(ApplyStatus::Retrying),
            Some(Instant::now() + Duration::from_secs(60)),
            false,
        ));
        assert!(should_apply_gateway_state(
            &state,
            Some(8),
            Some(ApplyStatus::Retrying),
            Some(Instant::now() - Duration::from_secs(1)),
            false,
        ));
        assert!(should_apply_gateway_state(
            &state,
            Some(7),
            Some(ApplyStatus::Checking),
            None,
            false,
        ));
        assert!(should_apply_gateway_state(
            &state,
            Some(8),
            Some(ApplyStatus::Failed),
            None,
            true,
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
