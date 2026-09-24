//! Agent 持久化设备身份，通过 mTLS 接收完整服务配置，并以 Yamux 承载真实双向流量。
//! 公网 HTTPS 在 Caddy 终止；本地默认使用普通 TCP/HTTP，明确配置 HTTPS 回源时校验证书。
use anyhow::{Context, Result};
use clap::Parser;
use futures_util::StreamExt;
use nexo_protocol::{
    AgentControlMessage, AgentEnrollmentPollRequest, AgentEnrollmentRequest,
    AgentEnrollmentResponse, ServerControlMessage, TunnelApplyResult, TunnelDataEndpoint,
    TunnelDesiredState,
};
use nexo_tunnel::identity::{self, write_message, MAX_CONTROL_FRAME, SERVER_NAME};
use rcgen::{CertificateParams, KeyPair};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpStream, sync::watch, task::JoinSet};
use tokio_rustls::TlsConnector;
use tokio_util::codec::{FramedRead, LinesCodec};
mod certificate;

#[derive(Debug, Parser)]
#[command(name = "nexo-agent", about = "Nexo 内网穿透 Agent")]
struct Config {
    /// 使用恢复凭证替换本机身份；审批和落盘成功后退出，再按正常方式启动 Agent。
    #[arg(long)]
    recover_identity: bool,
    #[arg(long, default_value = "")]
    server_url: String,
    #[arg(long, default_value = "")]
    enrollment_token: String,
    #[arg(long, default_value = "Nexo Agent")]
    device_name: String,
    #[arg(long, default_value=env!("CARGO_PKG_VERSION"))]
    agent_version: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct DeviceIdentity {
    server_url: String,
    device_id: String,
    certificate_pem: String,
    ca_pem: String,
    key_pem: String,
    #[serde(default)]
    pending_key: Option<EnrollmentKey>,
    #[serde(default)]
    renewal_retry: identity::RenewalRetry,
}
#[derive(Clone, Serialize, Deserialize)]
struct EnrollmentKey {
    key_pem: String,
    csr_pem: String,
}
#[derive(Clone, PartialEq, Eq)]
struct Desired {
    endpoint: TunnelDataEndpoint,
    tunnels: Vec<TunnelDesiredState>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();
    let mut config = Config::parse();
    if config.server_url.is_empty() {
        config.server_url = env::var("NEXO_SERVER_URL").context("NEXO_SERVER_URL 不能为空")?;
    }
    config.server_url = config.server_url.trim_end_matches('/').into();
    if config.enrollment_token.is_empty() {
        config.enrollment_token = env::var("NEXO_ENROLLMENT_TOKEN").unwrap_or_default();
    }
    if config.device_name == "Nexo Agent" {
        config.device_name = env::var("NEXO_DEVICE_NAME").unwrap_or(config.device_name);
    }
    let directory =
        PathBuf::from(env::var("NEXO_STATE_DIR").unwrap_or_else(|_| "./data/nexo-agent".into()));
    let mut identity = load_identity(&config, &directory).await?;
    if config.recover_identity {
        tracing::info!(device_id = %identity.device_id, "设备身份已恢复，原设备 ID 和服务绑定保留；请正常启动 Agent");
        return Ok(());
    }
    let address =
        env::var("NEXO_CONTROL_ENDPOINT").unwrap_or(endpoint_address(&config.server_url, 9890)?);
    loop {
        let result = run_control(
            &config,
            &mut identity,
            &directory.join("identity.json"),
            &address,
        )
        .await;
        if let Err(error) = result {
            tracing::warn!("Agent 控制连接结束，3 秒后重连：{error:#}");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// 身份落盘后不再使用一次性 Token；响应丢失时复用原 CSR，避免生成第二个设备。
async fn load_identity(config: &Config, directory: &std::path::Path) -> Result<DeviceIdentity> {
    let path = directory.join("identity.json");
    let previous = fs::read(&path);
    let expected_device = if config.recover_identity {
        // 允许恢复损坏/丢失的文件；仍可读取时，防止把另一台设备的恢复凭证用到此目录。
        previous
            .as_ref()
            .ok()
            .and_then(|bytes| serde_json::from_slice::<DeviceIdentity>(bytes).ok())
            .map(|identity| (identity.server_url, identity.device_id))
    } else {
        None
    };
    if !config.recover_identity {
        match previous {
            Ok(bytes) => {
                let identity: DeviceIdentity =
                    serde_json::from_slice(&bytes).context("Agent 身份文件损坏，请恢复备份")?;
                anyhow::ensure!(
                    identity.server_url == config.server_url,
                    "持久身份属于其他 Server，请为新 Server 使用独立的 Agent 数据目录"
                );
                return Ok(identity);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("无法读取 Agent 身份"),
        }
    }
    anyhow::ensure!(
        !config.enrollment_token.trim().is_empty(),
        "首次入网需要 NEXO_ENROLLMENT_TOKEN"
    );
    let request_path = directory.join(if config.recover_identity {
        "recovery-key.json"
    } else {
        "enrollment-key.json"
    });
    let material: EnrollmentKey = match fs::read(&request_path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("待入网的设备私钥损坏")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let key = KeyPair::generate()?;
            let csr = CertificateParams::new(vec!["agent.nexo".into()])?
                .serialize_request(&key)?
                .pem()?;
            let material = EnrollmentKey {
                key_pem: key.serialize_pem(),
                csr_pem: csr,
            };
            identity::write_private_file(&request_path, &serde_json::to_vec(&material)?)?;
            material
        }
        Err(error) => return Err(error).context("无法读取待入网设备私钥"),
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()?;
    let response = client
        .post(format!("{}/api/v1/agent/enroll", config.server_url))
        .json(&AgentEnrollmentRequest {
            token: config.enrollment_token.clone(),
            device_name: config.device_name.clone(),
            os: Some(env::consts::OS.into()),
            architecture: Some(env::consts::ARCH.into()),
            agent_version: config.agent_version.clone(),
            csr_pem: Some(material.csr_pem),
        })
        .send()
        .await
        .context("无法连接 Server 入网接口")?;
    let first: AgentEnrollmentResponse =
        decode_response(response, &config.enrollment_token).await?;
    if config.recover_identity {
        let target = first
            .device_id
            .as_ref()
            .context("这不是设备恢复凭证，请从原 Agent 的详情页生成恢复凭证")?;
        if let Some((server, device)) = expected_device {
            anyhow::ensure!(
                server == config.server_url && &device == target,
                "恢复凭证与此目录保存的原设备不一致，请核对 Server 和 Agent"
            );
        }
    } else {
        anyhow::ensure!(
            first.device_id.is_none(),
            "这是设备恢复凭证，请使用 --recover-identity 完成恢复"
        );
    }
    tracing::info!("已提交入网申请，等待管理员批准");
    loop {
        let response = client
            .post(format!(
                "{}/api/v1/agent/enroll/{}/poll",
                config.server_url, first.enrollment_id
            ))
            .json(&AgentEnrollmentPollRequest {
                token: config.enrollment_token.clone(),
            })
            .send()
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!("无法查询审批结果：{error}");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
        };
        let result: nexo_protocol::AgentEnrollmentPollResponse =
            decode_response(response, &config.enrollment_token).await?;
        match result.status {
            nexo_core::EnrollmentStatus::Approved => {
                if config.recover_identity {
                    anyhow::ensure!(
                        result.device_id == first.device_id,
                        "恢复结果的设备 ID 与申请不一致"
                    );
                }
                let identity = DeviceIdentity {
                    server_url: config.server_url.clone(),
                    device_id: result.device_id.context("批准响应缺少设备 ID")?,
                    certificate_pem: result.certificate_pem.context("批准响应缺少设备证书")?,
                    ca_pem: result.ca_certificate_pem.context("批准响应缺少 CA")?,
                    key_pem: material.key_pem,
                    pending_key: None,
                    renewal_retry: Default::default(),
                };
                // 写入前检查证书与本机私钥匹配，不能把另一台 Agent 的身份当成成功。
                identity::client_config(
                    &identity.ca_pem,
                    &identity.certificate_pem,
                    &identity.key_pem,
                )?;
                anyhow::ensure!(
                    identity::certificate_info(&identity.certificate_pem)?.0 == identity.device_id,
                    "批准证书与设备 ID 不一致，未替换本机身份"
                );
                identity::write_private_file(&path, &serde_json::to_vec(&identity)?)?;
                fs::remove_file(&request_path)?;
                return Ok(identity);
            }
            nexo_core::EnrollmentStatus::Pending
            | nexo_core::EnrollmentStatus::AwaitingApproval => {}
            _ => anyhow::bail!("入网无法继续：{}", result.message),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
async fn decode_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    token: &str,
) -> Result<T> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        let safe = body.replace(token, "[凭据已隐藏]");
        anyhow::bail!(
            "Server 拒绝入网请求（HTTP {status}）：{}",
            safe.chars().take(512).collect::<String>()
        );
    }
    serde_json::from_str(&body).context("Server 入网响应格式无效")
}
fn endpoint_address(url: &str, port: u16) -> Result<String> {
    let url = reqwest::Url::parse(url).context("Server URL 无效")?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "Server URL 必须使用 HTTP 或 HTTPS"
    );
    let host = url
        .host_str()
        .context("Server URL 缺少主机名")?
        .trim_matches(['[', ']']);
    Ok(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}
async fn connect_tls(
    connector: &TlsConnector,
    endpoint: &TunnelDataEndpoint,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&endpoint.address),
    )
    .await
    .context("连接 Server 超时")??;
    nexo_tunnel::configure_tunnel_tcp_keepalive(&stream)?;
    let name = rustls::pki_types::ServerName::try_from(endpoint.server_name.clone())
        .context("Server TLS 名称无效")?;
    Ok(
        tokio::time::timeout(Duration::from_secs(10), connector.connect(name, stream))
            .await
            .context("Server mTLS 握手超时")??,
    )
}

async fn run_control(
    config: &Config,
    identity: &mut DeviceIdentity,
    identity_path: &std::path::Path,
    address: &str,
) -> Result<()> {
    let device = identity.device_id.clone();
    let connector = TlsConnector::from(identity::client_config(
        &identity.ca_pem,
        &identity.certificate_pem,
        &identity.key_pem,
    )?);
    let stream = connect_tls(
        &connector,
        &TunnelDataEndpoint {
            address: address.into(),
            server_name: SERVER_NAME.into(),
        },
    )
    .await?;
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = FramedRead::new(read, LinesCodec::new_with_max_length(MAX_CONTROL_FRAME));
    write_message(
        &mut write,
        &AgentControlMessage::Hello {
            device_id: device.clone(),
            agent_version: config.agent_version.clone(),
        },
    )
    .await?;
    let fallback = TunnelDataEndpoint {
        address: env::var("NEXO_TUNNEL_ENDPOINT")
            .unwrap_or(endpoint_address(&config.server_url, 9891)?),
        server_name: SERVER_NAME.into(),
    };
    let (desired, receiver) = watch::channel(Desired {
        endpoint: fallback.clone(),
        tunnels: Vec::new(),
    });
    let mut data_tasks = JoinSet::new();
    let (connectors, connector_updates) = watch::channel(connector);
    let mut probes = JoinSet::new();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    let deadline = tokio::time::sleep(Duration::from_secs(45));
    tokio::pin!(deadline);
    let mut accepted = false;
    let mut renewal_deadline: Option<i64> = None;
    loop {
        tokio::select! {
            _ = &mut deadline => anyhow::bail!("Server 控制响应超时"),
            _ = heartbeat.tick(), if accepted => {
                write_message(&mut write,&AgentControlMessage::Heartbeat { device_id: device.clone(),agent_version:config.agent_version.clone() }).await?;
                let now = certificate::now();
                if renewal_deadline.is_some_and(|deadline| deadline <= now) {
                    renewal_deadline = None;
                    let report = certificate::failed(identity,identity_path,"等待续签响应超时",None);
                    write_message(&mut write,&report).await?;
                }
                if renewal_deadline.is_none() {
                    match certificate::request(identity,identity_path,now) {
                        Ok(Some(message)) => { renewal_deadline = Some(now + 30); write_message(&mut write,&message).await?; }
                        Ok(None) => {},
                        Err(error) => {
                            let report = certificate::failed(identity,identity_path,&format!("准备设备续签失败：{error:#}"),None);
                            write_message(&mut write,&report).await?;
                        }
                    }
                }
            },
            Some(result) = probes.join_next(), if !probes.is_empty() => {
                if let Ok(results) = result { write_message(&mut write,&AgentControlMessage::TunnelApplyReport { results }).await?; }
            },
            Some(result) = data_tasks.join_next(), if !data_tasks.is_empty() => { result?; anyhow::bail!("数据连接任务意外停止"); },
            incoming = lines.next() => {
                let line = incoming.context("Server 控制通道已关闭")??;
                deadline.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(45));
                match serde_json::from_str::<ServerControlMessage>(&line)? {
                    ServerControlMessage::HelloAccepted { tunnels,tunnel_endpoint,.. } | ServerControlMessage::HeartbeatAck { tunnels,tunnel_endpoint,.. } => {
                        let next = Desired { endpoint: tunnel_endpoint.unwrap_or_else(||fallback.clone()),tunnels:tunnels.clone() };
                        if *desired.borrow() != next { desired.send_replace(next); }
                        if !accepted { accepted=true; data_tasks.spawn(run_data(connector_updates.clone(),receiver.clone())); }
                        probes.abort_all();
                        probes.spawn(probe_tunnels(tunnels));
                    },
                    ServerControlMessage::TunnelApplyAccepted { .. } => {},
                    ServerControlMessage::CertificateRenewed { certificate_pem } => {
                        renewal_deadline = None;
                        match certificate::install(identity,identity_path,&certificate_pem) {
                            Ok(connector) => {
                                connectors.send_replace(connector);
                                write_message(&mut write,&AgentControlMessage::CertificateInstalled { certificate_pem }).await?;
                                tracing::info!("设备证书已续签并保存，设备 ID、服务绑定及现有连接保持不变");
                            }
                            Err(error) => {
                                let report = certificate::failed(identity,identity_path,&format!("保存续签证书失败：{error:#}"),None);
                                write_message(&mut write,&report).await?;
                            }
                        }
                    },
                    ServerControlMessage::CertificateRenewalFailed { message,next_retry_at } => {
                        renewal_deadline = None;
                        let _ = certificate::failed(identity,identity_path,&message,Some(next_retry_at));
                    },
                    ServerControlMessage::Error { message } => anyhow::bail!("Server 拒绝请求：{message}"),
                }
            }
        }
    }
}

/// Yamux 重连独立于心跳；每个逻辑流依照当前完整快照核对 ID 和版本，不接受服务端任意目标地址。
async fn run_data(
    connectors: watch::Receiver<TlsConnector>,
    mut desired: watch::Receiver<Desired>,
) {
    let mut delay = 1;
    loop {
        let endpoint = desired.borrow_and_update().endpoint.clone();
        let connector = connectors.borrow().clone();
        let connected = connect_tls(&connector, &endpoint).await;
        match connected {
            Ok(stream) => {
                delay = 1;
                tracing::info!("Tunnel 数据通道已连接");
                let mut connection = nexo_tunnel::yamux_connection(stream, yamux::Mode::Client);
                let mut tasks = JoinSet::new();
                loop {
                    tokio::select! {
                        Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                    change = desired.changed() => { if change.is_err() { return; } else if desired.borrow().endpoint != endpoint { break; } },
                        inbound=nexo_tunnel::next_inbound(&mut connection) => match inbound {
                            Ok(Some(stream)) => { let snapshot=desired.clone(); tasks.spawn(async move { if let Err(error)=forward(stream,snapshot).await { tracing::debug!("Tunnel 逻辑流结束：{error:#}"); } }); },
                            Ok(None) => break,
                            Err(error) => { tracing::warn!("Tunnel 数据通道断开：{error}"); break; }
                        }
                    }
                }
            }
            Err(error) => tracing::warn!("Tunnel 数据连接失败，将自动重试：{error:#}"),
        }
        tokio::select! { _=tokio::time::sleep(Duration::from_secs(delay))=>{}, result=desired.changed()=>if result.is_err(){return;} }
        delay = (delay * 2).min(30);
    }
}
async fn forward(stream: yamux::Stream, mut desired: watch::Receiver<Desired>) -> Result<()> {
    let mut stream = nexo_tunnel::into_tokio_io(stream);
    let header = tokio::time::timeout(
        Duration::from_secs(10),
        nexo_tunnel::read_logical_header(&mut stream),
    )
    .await??;
    let tunnel = desired
        .borrow_and_update()
        .tunnels
        .iter()
        .find(|t| t.tunnel_id == header.tunnel_id && t.revision == header.revision && t.enabled)
        .cloned()
        .context("逻辑流不属于当前启用的配置")?;
    let transfer = async {
        let mut local = connect_origin(&tunnel).await?;
        tokio::io::copy_bidirectional(&mut local, &mut stream).await?;
        anyhow::Ok(())
    };
    tokio::pin!(transfer);
    loop {
        tokio::select! {
            result=&mut transfer=>return result,
            changed=desired.changed()=>{
                changed.context("控制配置已关闭")?;
                if !desired.borrow_and_update().tunnels.iter().any(|current|current==&tunnel && current.enabled) { anyhow::bail!("服务配置已修改或停用"); }
            }
        }
    }
}
trait OriginIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> OriginIo for T {}
async fn connect_origin(tunnel: &TunnelDesiredState) -> Result<Box<dyn OriginIo>> {
    anyhow::ensure!(
        matches!(tunnel.protocol.as_str(), "tcp" | "http" | "https"),
        "服务协议不受支持"
    );
    let address = tunnel.local_address.trim_matches(['[', ']']);
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((address, tunnel.local_port)),
    )
    .await
    .context("连接本地服务超时")?
    .context("无法连接本地服务")?;
    // 公网 HTTPS 不等于本地 HTTPS，只有明确的回源配置才建立第二层 TLS。
    if tunnel.protocol == "tcp" || tunnel.origin_protocol.as_deref().unwrap_or("http") == "http" {
        return Ok(Box::new(stream));
    }
    anyhow::ensure!(
        tunnel.origin_protocol.as_deref() == Some("https"),
        "本地回源协议无效"
    );
    let roots = match tunnel
        .origin_tls_verification
        .as_deref()
        .unwrap_or("system")
    {
        "custom_ca" => identity::roots(
            tunnel
                .origin_ca_pem
                .as_deref()
                .context("本地 HTTPS 缺少自定义 CA")?,
        )?,
        "system" => {
            let mut roots = rustls::RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                roots.add(cert)?;
            }
            anyhow::ensure!(
                !roots.is_empty(),
                "无法加载系统 CA，不能验证本地 HTTPS 证书"
            );
            roots
        }
        _ => anyhow::bail!("本地 HTTPS 证书校验方式不受支持"),
    };
    let connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let name = rustls::pki_types::ServerName::try_from(
        tunnel
            .origin_tls_server_name
            .as_deref()
            .unwrap_or(address)
            .to_owned(),
    )
    .context("本地 HTTPS TLS 名称无效")?;
    Ok(Box::new(
        tokio::time::timeout(Duration::from_secs(5), connector.connect(name, stream))
            .await
            .context("本地 HTTPS 握手超时")?
            .context("本地 HTTPS 证书验证失败")?,
    ))
}
async fn probe_tunnels(tunnels: Vec<TunnelDesiredState>) -> Vec<TunnelApplyResult> {
    let mut tasks = JoinSet::new();
    let permits = Arc::new(tokio::sync::Semaphore::new(16));
    for tunnel in tunnels {
        let permits = permits.clone();
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await.expect("探测许可未关闭");
            let result = if tunnel.enabled {
                connect_origin(&tunnel).await.map(|_| ())
            } else {
                Ok(())
            };
            TunnelApplyResult {
                tunnel_id: tunnel.tunnel_id,
                revision: tunnel.revision,
                applied: result.is_ok(),
                status: if !tunnel.enabled {
                    "disabled"
                } else if result.is_ok() {
                    "ready"
                } else {
                    "failed"
                }
                .into(),
                error_message: result.err().map(|error| format!("{error:#}")),
            }
        });
    }
    let mut results = Vec::new();
    while let Some(Ok(result)) = tasks.join_next().await {
        results.push(result);
    }
    results
}
