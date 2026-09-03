//! Nexo Agent 启动入口。
//!
//! Agent 不绑定固定服务端。首次入网时通过环境变量指定目标地址和一次性
//! token，完成请求后继续作为常驻进程运行；后续控制通道会复用同一配置。

use std::{env, fs, io::BufReader, path::PathBuf, sync::Arc};

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
        })
    }
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
    write_agent_message(
        reader.get_mut(),
        &AgentControlMessage::Hello {
            device_id: device_id.to_owned(),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: config.capabilities.clone(),
            gateway_report: Some(detect_gateway_capabilities()),
        },
    )
    .await?;
    let response = read_control_response(&mut reader).await?;
    let mut last_gateway_revision = None;
    match response {
        ServerControlMessage::HelloAccepted {
            gateway_state: Some(gateway_state),
            ..
        } => {
            let ack = apply_gateway_desired_state(&gateway_state);
            last_gateway_revision = Some(ack.revision);
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
        write_agent_message(
            reader.get_mut(),
            &AgentControlMessage::Heartbeat {
                device_id: device_id.to_owned(),
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            },
        )
        .await?;
        match read_control_response(&mut reader).await? {
            ServerControlMessage::HeartbeatAck {
                gateway_state: Some(gateway_state),
                ..
            } if last_gateway_revision != Some(gateway_state.revision) => {
                let ack = apply_gateway_desired_state(&gateway_state);
                last_gateway_revision = Some(ack.revision);
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
    }
}

/// 处理服务端下发的网关 Desired State。
///
/// 当前 Agent 只完成协议接收和状态回传，真正的 Tailscale 路由应用会在
/// 后续适配器接入后填充；因此这里明确返回 `checking`，绝不宣称路由已生效。
fn apply_gateway_desired_state(state: &GatewayDesiredState) -> GatewayApplyAck {
    let network_ids: Vec<String> = state
        .routes
        .iter()
        .map(|route| route.network_id.clone())
        .collect();
    if let Some(invalid_route) = state.routes.iter().find(|route| {
        route
            .prefix
            .parse::<IpNet>()
            .map(|prefix| validate_published_network(prefix).is_err())
            .unwrap_or(true)
    }) {
        let error_message = format!("服务端下发的网关网络无效：{}", invalid_route.prefix);
        tracing::error!("{}", error_message);
        return GatewayApplyAck {
            revision: state.revision,
            status: ApplyStatus::Failed,
            network_ids,
            applied_network_ids: Vec::new(),
            error_message: Some(error_message),
        };
    }
    tracing::info!(
        revision = state.revision,
        route_count = state.routes.len(),
        "已收到网关配置，等待 Tailscale 路由适配器应用"
    );
    GatewayApplyAck {
        revision: state.revision,
        status: ApplyStatus::Checking,
        network_ids,
        applied_network_ids: Vec::new(),
        error_message: None,
    }
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
            }],
        };
        let ack = apply_gateway_desired_state(&state);
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
            }],
        };
        let ack = apply_gateway_desired_state(&state);
        assert_eq!(ack.status, ApplyStatus::Failed);
        assert_eq!(ack.network_ids, vec!["network-invalid"]);
        assert!(ack.applied_network_ids.is_empty());
        assert!(ack.error_message.is_some());
    }
}
