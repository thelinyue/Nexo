//! mTLS 控制连接与 Yamux 数据面。公网端口/本机 Web 入口只打开已分配的服务，
//! 每次开流再次校验设备、租户、配置版本；停用、修改和删除会取消既有连接。
use crate::{desired_tunnels, unix_now, AppState};
use anyhow::{Context, Result};
use futures_util::StreamExt;
use nexo_protocol::{AgentControlMessage, ServerControlMessage, TunnelApplyResult};
use nexo_tunnel::{
    identity::{write_message, MAX_CONTROL_FRAME},
    LogicalStreamHeader,
};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_util::{
    codec::{FramedRead, LinesCodec},
    sync::CancellationToken,
};

trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TunnelIo for T {}
type BoxIo = Box<dyn TunnelIo>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Service {
    id: String,
    device: String,
    revision: i64,
    protocol: String,
    port: Option<u16>,
}
struct Listener {
    service: Service,
    upstream: Option<String>,
    path: Option<PathBuf>,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}
struct OpenStream {
    service: Service,
    socket: BoxIo,
    cancel: CancellationToken,
    _permit: OwnedSemaphorePermit,
}
#[derive(Clone)]
struct DataSession {
    sender: mpsc::Sender<OpenStream>,
    cancel: CancellationToken,
    permits: Arc<Semaphore>,
}
struct ControlSession {
    sender: mpsc::Sender<ServerControlMessage>,
    cancel: CancellationToken,
}
#[derive(Default)]
struct Connections {
    data: HashMap<String, DataSession>,
    control: HashMap<String, ControlSession>,
    listeners: HashMap<String, Listener>,
}

/// 监听器与连接的拥有者：协调串行化，连接任务使用取消令牌，不靠数据库标记假装关闭。
pub struct Runtime {
    bind: IpAddr,
    connections: Mutex<Connections>,
    reconcile_lock: Mutex<()>,
    pub stop: CancellationToken,
}
impl Runtime {
    pub fn new(bind: IpAddr) -> Self {
        Self {
            bind,
            connections: Mutex::new(Connections::default()),
            reconcile_lock: Mutex::new(()),
            stop: CancellationToken::new(),
        }
    }

    pub async fn run(state: AppState) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = state.tunnel_runtime.stop.cancelled() => break,
                _ = interval.tick() => if let Err(error) = state.tunnel_runtime.reconcile(&state).await { tracing::error!("Tunnel 状态协调失败：{error:#}"); }
            }
        }
    }

    /// API 修改后立即重建/关闭入口，再推送完整快照；空快照同样会撤销 Agent 上的旧服务。
    pub async fn changed(&self, state: &AppState) -> Result<()> {
        self.reconcile(state).await?;
        let connections = self.connections.lock().await;
        for (device, session) in &connections.control {
            let message = ServerControlMessage::HeartbeatAck {
                server_time: unix_now(),
                tunnels: desired_tunnels(state, device)?,
                tunnel_endpoint: state.tunnel_endpoint.clone(),
            };
            if session.sender.try_send(message).is_err() {
                session.cancel.cancel();
            }
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        self.stop.cancel();
        let _guard = self.reconcile_lock.lock().await;
        let mut connections = self.connections.lock().await;
        for (_, listener) in connections.listeners.drain() {
            stop_listener(listener).await;
        }
        for (_, session) in connections.control.drain() {
            session.cancel.cancel();
        }
        for (_, session) in connections.data.drain() {
            session.cancel.cancel();
        }
    }

    /// 身份恢复是显式撤销：与连接注册串行化，提交新身份后取消旧控制和数据通道。
    pub async fn replace_identity<T>(
        &self,
        device: &str,
        change: impl FnOnce() -> Result<T, crate::ApiError>,
    ) -> Result<T, crate::ApiError> {
        let mut connections = self.connections.lock().await;
        let result = change()?;
        if let Some(session) = connections.control.remove(device) {
            session.cancel.cancel();
        }
        if let Some(session) = connections.data.remove(device) {
            session.cancel.cancel();
        }
        Ok(result)
    }

    /// 删除事务与连接注册、监听协调互斥。提交后关闭该空间全部连接，不依赖下一轮心跳或重载。
    pub async fn remove_workspace(
        &self,
        change: impl FnOnce() -> Result<(Vec<String>, Vec<String>), crate::ApiError>,
    ) -> Result<(), crate::ApiError> {
        let _guard = self.reconcile_lock.lock().await;
        let mut connections = self.connections.lock().await;
        let (devices, services) = change()?;
        for device in &devices {
            if let Some(session) = connections.control.remove(device) {
                session.cancel.cancel();
            }
            if let Some(session) = connections.data.remove(device) {
                session.cancel.cancel();
            }
        }
        let listeners = connections
            .listeners
            .iter()
            .filter(|(id, listener)| {
                services.contains(id) || devices.contains(&listener.service.device)
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in listeners {
            if let Some(listener) = connections.listeners.remove(&id) {
                stop_listener(listener).await;
            }
        }
        Ok(())
    }

    /// Caddy 只取得本次进程真实建立的入口；没有在线数据会话时生成明确的 503 路由。
    pub async fn web_upstreams(&self) -> HashMap<String, String> {
        let connections = self.connections.lock().await;
        connections
            .listeners
            .iter()
            .filter_map(|(id, listener)| {
                (connections.data.contains_key(&listener.service.device)
                    && connections.control.contains_key(&listener.service.device)
                    && !listener.task.is_finished())
                .then(|| {
                    listener
                        .upstream
                        .as_ref()
                        .map(|upstream| (id.clone(), upstream.clone()))
                })
                .flatten()
            })
            .collect()
    }

    pub async fn reconcile(&self, state: &AppState) -> Result<()> {
        let _guard = self.reconcile_lock.lock().await;
        let (wanted, devices) = {
            let db = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            let mut query = db.prepare("SELECT t.id,t.device_id,t.apply_revision,t.protocol,t.public_port FROM tunnels t JOIN devices d ON d.id=t.device_id AND d.tenant_id=t.tenant_id JOIN tenants w ON w.id=t.tenant_id AND w.enabled=1 WHERE t.enabled=1 AND t.deleted_at IS NULL")?;
            let services = query
                .query_map([], |r| {
                    Ok(Service {
                        id: r.get(0)?,
                        device: r.get(1)?,
                        revision: r.get(2)?,
                        protocol: r.get(3)?,
                        port: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let devices = db
                .prepare("SELECT d.id FROM devices d JOIN tenants w ON w.id=d.tenant_id WHERE w.enabled=1")?
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            (services, devices)
        };
        let mut connections = self.connections.lock().await;
        connections.control.retain(|id, session| {
            if !devices.contains(id) {
                session.cancel.cancel();
                false
            } else {
                true
            }
        });
        connections.data.retain(|id, session| {
            if !devices.contains(id) {
                session.cancel.cancel();
                false
            } else {
                true
            }
        });
        let stale = connections
            .listeners
            .iter()
            .filter(|(_, listener)| {
                listener.task.is_finished() || !wanted.contains(&listener.service)
            })
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in stale {
            if let Some(listener) = connections.listeners.remove(&id) {
                stop_listener(listener).await;
            }
        }
        let mut failures = HashMap::new();
        for service in wanted {
            if connections.listeners.contains_key(&service.id) {
                continue;
            }
            match self.listen(state, service.clone()).await {
                Ok(listener) => {
                    connections.listeners.insert(service.id, listener);
                }
                Err(error) => {
                    failures.insert(service.id, format!("无法建立服务入口：{error:#}"));
                }
            }
        }
        let listeners = connections
            .listeners
            .iter()
            .map(|(id, listener)| (id.clone(), listener.upstream.clone()))
            .collect::<HashMap<_, _>>();
        let online = connections.control.keys().cloned().collect::<Vec<_>>();
        let data = connections.data.keys().cloned().collect::<Vec<_>>();
        drop(connections);
        refresh_status(state, &listeners, &online, &data, &failures)?;
        Ok(())
    }

    async fn listen(&self, state: &AppState, service: Service) -> Result<Listener> {
        let cancel = self.stop.child_token();
        if service.protocol == "tcp" {
            let listener =
                TcpListener::bind((self.bind, service.port.context("TCP 服务没有公网端口")?))
                    .await?;
            let task = tcp_listener(state.clone(), service.clone(), listener, cancel.clone());
            return Ok(Listener {
                service,
                upstream: None,
                path: None,
                cancel,
                task,
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, PermissionsExt};
            let directory = state.data_dir.join("tunnel-sockets");
            std::fs::create_dir_all(&directory)?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let path = directory.join(format!("{}.sock", service.id));
            if let Ok(metadata) = std::fs::symlink_metadata(&path) {
                anyhow::ensure!(
                    metadata.file_type().is_socket(),
                    "服务入口路径不是 socket，拒绝覆盖"
                );
                std::fs::remove_file(&path)?;
            }
            let listener = tokio::net::UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            let task_state = state.clone();
            let task_service = service.clone();
            let task_cancel = cancel.clone();
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = task_cancel.cancelled() => break,
                        accepted = listener.accept() => match accepted {
                            Ok((socket, _)) => handoff(&task_state, &task_service, Box::new(socket), &task_cancel).await,
                            Err(error) => { tracing::warn!("Web Tunnel 监听停止：{error}"); break; }
                        }
                    }
                }
            });
            Ok(Listener {
                service,
                upstream: Some(format!("unix/{}", path.display())),
                path: Some(path),
                cancel,
                task,
            })
        }
        #[cfg(not(unix))]
        {
            // Windows 没有 Tokio UnixListener，使用仅限本机的随机端口；不发布内部入口到公网。
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let upstream = listener.local_addr()?.to_string();
            let task = tcp_listener(state.clone(), service.clone(), listener, cancel.clone());
            Ok(Listener {
                service,
                upstream: Some(upstream),
                path: None,
                cancel,
                task,
            })
        }
    }
}

async fn stop_listener(listener: Listener) {
    listener.cancel.cancel();
    listener.task.abort();
    let _ = listener.task.await;
    if let Some(path) = listener.path {
        let _ = std::fs::remove_file(path);
    }
}
fn tcp_listener(
    state: AppState,
    service: Service,
    listener: TcpListener,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                accepted = listener.accept() => match accepted {
                    Ok((socket, _)) => handoff(&state, &service, Box::new(socket), &cancel).await,
                    Err(error) => { tracing::warn!("TCP Tunnel 监听停止：{error}"); break; }
                }
            }
        }
    })
}
async fn handoff(state: &AppState, service: &Service, socket: BoxIo, cancel: &CancellationToken) {
    let connections = state.tunnel_runtime.connections.lock().await;
    let Some(session) = connections.data.get(&service.device) else {
        return;
    };
    let Ok(permit) = session.permits.clone().try_acquire_owned() else {
        return;
    };
    let _ = session.sender.try_send(OpenStream {
        service: service.clone(),
        socket,
        cancel: cancel.child_token(),
        _permit: permit,
    });
}

fn ensure_device_enabled(db: &rusqlite::Connection, device: &str) -> Result<()> {
    let enabled: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM devices d JOIN tenants w ON w.id=d.tenant_id WHERE d.id=?1 AND w.enabled=1)", [device], |r| r.get(0))?;
    anyhow::ensure!(enabled, "设备所属账号已停用或设备已删除");
    Ok(())
}

fn authenticated_device(
    state: &AppState,
    stream: &TlsStream<TcpStream>,
) -> Result<(String, String)> {
    let cert = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .context("连接缺少 Agent 证书")?;
    let fingerprint = hex::encode(Sha256::digest(cert.as_ref()));
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|_| anyhow::anyhow!("设备证书无效"))?;
    let device = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        .context("设备证书缺少身份")?
        .to_owned();
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    ensure_device_enabled(&db, &device)?;
    crate::identity_runtime::accept_certificate(&db, &device, &fingerprint)?;
    Ok((device, fingerprint))
}

/// 控制与数据端口都强制 mTLS；握手成功只证明 CA 信任，仍需查询本机注册身份。
pub async fn serve(state: AppState, listener: TcpListener, data: bool) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = state.tunnel_runtime.stop.cancelled() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            incoming = listener.accept() => {
                let (socket, peer) = incoming?; let acceptor = TlsAcceptor::from(state.authority.server_config()); let state = state.clone();
                tasks.spawn(async move {
                    let result: Result<()> = async {
                        nexo_tunnel::configure_tunnel_tcp_keepalive(&socket)?;
                        let stream = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket)).await.context("Agent TLS 握手超时")??;
                        let (device, fingerprint) = authenticated_device(&state, &stream)?;
                        if data { data_session(state, stream, device, fingerprint).await } else { control_session(state, stream, device, fingerprint).await }
                    }.await;
                    if let Err(error) = result { tracing::warn!(%peer, "Agent 连接结束：{error:#}"); }
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn control_session(
    state: AppState,
    stream: TlsStream<TcpStream>,
    device: String,
    mut fingerprint: String,
) -> Result<()> {
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = FramedRead::new(read, LinesCodec::new_with_max_length(MAX_CONTROL_FRAME));
    let first = tokio::time::timeout(Duration::from_secs(10), lines.next())
        .await?
        .context("Agent 未发送 Hello")??;
    let AgentControlMessage::Hello {
        device_id,
        agent_version,
    } = serde_json::from_str(&first)?
    else {
        anyhow::bail!("Agent 首帧必须是 Hello");
    };
    anyhow::ensure!(device_id == device, "Agent ID 与客户端证书不一致");
    let cancel = state.tunnel_runtime.stop.child_token();
    let (sender, mut receiver) = mpsc::channel(8);
    {
        let mut connections = state.tunnel_runtime.connections.lock().await;
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        ensure_device_enabled(&db, &device)?;
        crate::identity_runtime::accept_certificate(&db, &device, &fingerprint)?;
        if let Some(previous) = connections.control.insert(
            device.clone(),
            ControlSession {
                sender: sender.clone(),
                cancel: cancel.clone(),
            },
        ) {
            previous.cancel.cancel();
        }
        db.execute(
            "UPDATE devices SET status='online',agent_version=?1,last_seen_at=?2 WHERE id=?3",
            params![agent_version, unix_now(), device],
        )?;
    }
    let result: Result<()> = async {
        write_message(&mut write, &ServerControlMessage::HelloAccepted { server_time: unix_now(), tunnels: desired_tunnels(&state, &device)?, tunnel_endpoint: state.tunnel_endpoint.clone() }).await?;
        let deadline = tokio::time::sleep(Duration::from_secs(45)); tokio::pin!(deadline);
        loop { tokio::select! {
            _ = cancel.cancelled() => break,
            _ = &mut deadline => anyhow::bail!("Agent 心跳超时"),
            command = receiver.recv() => { let Some(command) = command else { break; }; write_message(&mut write, &command).await?; },
            incoming = lines.next() => {
                let line = incoming.context("Agent 控制通道已断开")??;
                deadline.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(45));
                match serde_json::from_str::<AgentControlMessage>(&line)? {
                    AgentControlMessage::Heartbeat { device_id, agent_version } => {
                        anyhow::ensure!(device_id == device, "心跳设备 ID 与证书不一致");
                        state.db.lock().map_err(|_| anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE devices SET last_seen_at=?1,agent_version=?2 WHERE id=?3", params![unix_now(),agent_version,device])?;
                        write_message(&mut write, &ServerControlMessage::HeartbeatAck { server_time: unix_now(), tunnels: desired_tunnels(&state, &device)?, tunnel_endpoint: state.tunnel_endpoint.clone() }).await?;
                    }
                    AgentControlMessage::TunnelApplyReport { results } => {
                        let ids = apply_results(&state, &device, results)?;
                        write_message(&mut write, &ServerControlMessage::TunnelApplyAccepted { tunnel_ids: ids }).await?;
                    }
                    AgentControlMessage::RenewCertificate { csr_pem } => {
                        let response = match crate::identity_runtime::renew_device(&state, &device, &fingerprint, &csr_pem, unix_now()) {
                            Ok(certificate_pem) => ServerControlMessage::CertificateRenewed { certificate_pem },
                            Err(error) => {
                                let message = format!("设备证书续签失败：{error:#}");
                                let next_retry_at = crate::identity_runtime::renewal_failed(&state,&device,&message,None)?;
                                ServerControlMessage::CertificateRenewalFailed { message,next_retry_at }
                            }
                        };
                        write_message(&mut write, &response).await?;
                    }
                    AgentControlMessage::CertificateInstalled { certificate_pem } => {
                        let digest = crate::identity_runtime::fingerprint(&certificate_pem)?;
                        let db = state.db.lock().map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                        crate::identity_runtime::accept_certificate(&db,&device,&digest)?;
                        fingerprint = digest;
                    }
                    AgentControlMessage::CertificateRenewalFailed { error,next_retry_at } => {
                        crate::identity_runtime::renewal_failed(&state,&device,&error,Some(next_retry_at))?;
                    }
                    AgentControlMessage::Hello { .. } => anyhow::bail!("不能重复发送 Hello"),
                }
            }
        } }
        Ok(())
    }.await;
    let mut connections = state.tunnel_runtime.connections.lock().await;
    if connections
        .control
        .get(&device)
        .is_some_and(|current| current.sender.same_channel(&sender))
    {
        connections.control.remove(&device);
        if let Some(session) = connections.data.remove(&device) {
            session.cancel.cancel();
        }
        state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?
            .execute("UPDATE devices SET status='offline' WHERE id=?1", [&device])?;
    }
    result
}

fn apply_results(
    state: &AppState,
    device: &str,
    results: Vec<TunnelApplyResult>,
) -> Result<Vec<String>> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let tx = db.unchecked_transaction()?;
    let mut accepted = Vec::new();
    for report in results {
        if !matches!(report.status.as_str(), "ready" | "failed" | "disabled") {
            continue;
        }
        let changed = tx.execute("INSERT INTO tunnel_applied_states (tunnel_id,revision,status,error_message,updated_at) SELECT id,?1,?2,?3,?4 FROM tunnels WHERE id=?5 AND device_id=?6 AND apply_revision=?1 AND deleted_at IS NULL AND (enabled=1 OR ?2='disabled') ON CONFLICT(tunnel_id) DO UPDATE SET revision=excluded.revision,status=excluded.status,error_message=excluded.error_message,updated_at=excluded.updated_at", params![report.revision,if report.applied { report.status.as_str() } else { "failed" },report.error_message.map(|s| s.chars().take(512).collect::<String>()),unix_now(),report.tunnel_id,device])?;
        if changed > 0 {
            accepted.push(report.tunnel_id);
        }
    }
    tx.commit()?;
    Ok(accepted)
}

fn allowed(state: &AppState, service: &Service, device: &str) -> Result<bool> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels t JOIN devices d ON d.id=t.device_id AND d.tenant_id=t.tenant_id JOIN tenants w ON w.id=t.tenant_id AND w.enabled=1 WHERE t.id=?1 AND t.device_id=?2 AND t.apply_revision=?3 AND t.enabled=1 AND t.deleted_at IS NULL AND d.status='online')", params![service.id,device,service.revision], |r| r.get(0))?)
}

async fn data_session(
    state: AppState,
    stream: TlsStream<TcpStream>,
    device: String,
    fingerprint: String,
) -> Result<()> {
    let (sender, mut receiver) = mpsc::channel::<OpenStream>(nexo_tunnel::DEFAULT_MAX_STREAMS);
    let cancel = state.tunnel_runtime.stop.child_token();
    {
        let mut connections = state.tunnel_runtime.connections.lock().await;
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        ensure_device_enabled(&db, &device)?;
        crate::identity_runtime::accept_certificate(&db, &device, &fingerprint)?;
        let previous = connections.data.insert(
            device.clone(),
            DataSession {
                sender: sender.clone(),
                cancel: cancel.clone(),
                permits: Arc::new(Semaphore::new(nexo_tunnel::DEFAULT_MAX_STREAMS)),
            },
        );
        if let Some(previous) = previous {
            previous.cancel.cancel();
        }
    }
    let mut connection = nexo_tunnel::yamux_connection(stream, yamux::Mode::Server);
    let mut copies = JoinSet::new();
    let result: Result<()> = async { loop { tokio::select! {
        _ = cancel.cancelled() => break,
        Some(_) = copies.join_next(), if !copies.is_empty() => {},
        command = receiver.recv() => {
            let Some(mut command) = command else { break; };
            if command.cancel.is_cancelled() || !allowed(&state, &command.service, &device)? { continue; }
            let stream = tokio::time::timeout(Duration::from_secs(10), nexo_tunnel::new_outbound(&mut connection)).await.context("Tunnel 开流超时")??;
            copies.spawn(async move {
                let mut stream = nexo_tunnel::into_tokio_io(stream);
                let transfer = async {
                    let header = LogicalStreamHeader::new(&command.service.id, uuid::Uuid::new_v4().to_string(), command.service.revision)?;
                    tokio::time::timeout(Duration::from_secs(10), nexo_tunnel::write_logical_header(&mut stream, &header)).await??;
                    tokio::io::copy_bidirectional(&mut command.socket, &mut stream).await?;
                    anyhow::Ok(())
                };
                tokio::select! { _ = command.cancel.cancelled() => {}, result = transfer => if let Err(error) = result { tracing::debug!("Tunnel 转发结束：{error:#}"); } }
            });
        }
        inbound = nexo_tunnel::next_inbound(&mut connection) => match inbound? {
            Some(_) => anyhow::bail!("Agent 不允许主动打开服务端逻辑流"),
            None => break,
        }
    } } Ok(()) }.await;
    copies.abort_all();
    while copies.join_next().await.is_some() {}
    let mut connections = state.tunnel_runtime.connections.lock().await;
    if connections
        .data
        .get(&device)
        .is_some_and(|current| current.sender.same_channel(&sender))
    {
        connections.data.remove(&device);
    }
    result
}

/// 本地探测、数据会话、公网监听与 Caddy/TLS 全部满足时，才在服务页显示正常。
fn refresh_status(
    state: &AppState,
    listeners: &HashMap<String, Option<String>>,
    online: &[String],
    data: &[String],
    failures: &HashMap<String, String>,
) -> Result<()> {
    let rows = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut query = db.prepare("SELECT t.id,t.device_id,(t.enabled AND EXISTS(SELECT 1 FROM tenants w WHERE w.id=t.tenant_id AND w.enabled=1)),t.protocol,t.apply_revision,a.revision,a.status,a.error_message,t.public_domain_id,t.hostname,p.domain FROM tunnels t LEFT JOIN tunnel_applied_states a ON a.tunnel_id=t.id LEFT JOIN public_domains p ON p.id=t.public_domain_id AND p.tenant_id=t.tenant_id WHERE t.deleted_at IS NULL")?;
        let rows = query
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, bool>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Option<i64>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                    r.get::<_, Option<String>>(9)?,
                    r.get::<_, Option<String>>(10)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (
        id,
        device,
        enabled,
        protocol,
        revision,
        applied_revision,
        applied_status,
        applied_error,
        domain_id,
        hostname,
        domain_name,
    ) in rows
    {
        let (status, error) = if !enabled {
            ("disabled", None)
        } else if let Some(error) = failures.get(&id) {
            ("failed", Some(error.clone()))
        } else if device
            .as_ref()
            .is_none_or(|device| !online.contains(device))
        {
            ("checking", Some("Agent 未连接控制通道".into()))
        } else if device.as_ref().is_none_or(|device| !data.contains(device)) {
            ("checking", Some("Agent 数据通道未连接".into()))
        } else if !listeners.contains_key(&id) {
            ("failed", Some("服务入口尚未建立".into()))
        } else if applied_revision != Some(revision) {
            ("checking", Some("等待 Agent 应用当前配置".into()))
        } else if applied_status.as_deref() != Some("ready") {
            (
                "failed",
                Some(applied_error.unwrap_or_else(|| "本地服务无法连接".into())),
            )
        } else if protocol != "tcp" {
            let runtime = state
                .domain_runtime
                .status(domain_id.as_deref().unwrap_or_default());
            let host = format!(
                "{}.{}",
                hostname.unwrap_or_default(),
                domain_name.unwrap_or_default()
            );
            if runtime.config_status != "applied" {
                (
                    "checking",
                    Some(
                        runtime
                            .config_error
                            .unwrap_or_else(|| "等待 Caddy 加载配置".into()),
                    ),
                )
            } else if runtime.loaded_routes.get(&format!("{protocol}://{host}"))
                != listeners.get(&id).and_then(Option::as_ref)
            {
                ("checking", Some("等待 Caddy 更新服务入口".into()))
            } else if protocol == "https" {
                let now = unix_now();
                let certificate = runtime.certificates.iter().find(|cert| {
                    (cert.hostname == host
                        || cert.hostname.strip_prefix("*.").is_some_and(|suffix| {
                            host.split_once('.').is_some_and(|(_, rest)| rest == suffix)
                        }))
                        && cert.expires_at.is_some_and(|expiry| expiry > now)
                        && cert.not_before.is_some_and(|start| start <= now)
                });
                if certificate.is_some() {
                    ("ready", None)
                } else {
                    ("checking", Some("等待 HTTPS 证书签发或续期".into()))
                }
            } else {
                ("ready", None)
            }
        } else {
            ("ready", None)
        };
        state.db.lock().map_err(|_| anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE tunnels SET apply_status=?1,apply_error=?2 WHERE id=?3 AND apply_revision=?4 AND deleted_at IS NULL", params![status,error,id,revision])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_tunnel, TunnelInput};
    use axum::{extract::State, Json};

    fn populate(state: &AppState) {
        state.db.lock().unwrap().execute_batch("INSERT INTO tenants(id,name,created_at) VALUES ('other','other',0);
        INSERT INTO devices (id,tenant_id,name,status,created_at,updated_at) VALUES ('mine','default','mine','online',0,0),('foreign','other','foreign','online',0,0);
        INSERT INTO tunnels (id,tenant_id,device_id,name,protocol,local_address,local_port,enabled,apply_revision,created_at,updated_at) VALUES ('own','default','mine','own','tcp','127.0.0.1',1234,1,2,0,0),('foreign','other','foreign','foreign','tcp','127.0.0.1',1234,1,1,0,0);").unwrap();
    }
    #[test]
    fn reports_cannot_cross_device_boundary_or_overwrite_a_newer_revision() {
        let (state, _) = crate::tests::domain_fixture();
        populate(&state);
        let report = |id: &str, revision| TunnelApplyResult {
            tunnel_id: id.into(),
            revision,
            applied: true,
            status: "ready".into(),
            error_message: None,
        };
        let accepted = apply_results(
            &state,
            "mine",
            vec![report("foreign", 1), report("own", 1), report("own", 2)],
        )
        .unwrap();
        assert_eq!(accepted, vec!["own"]);
        let db = state.db.lock().unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM tunnel_applied_states", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT revision FROM tunnel_applied_states WHERE tunnel_id='own'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
    }
    #[tokio::test]
    async fn foreign_agent_is_rejected_and_port_conflicts_remain_visible() {
        let (state, headers) = crate::tests::domain_fixture();
        populate(&state);
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = occupied.local_addr().unwrap().port();
        let input = |device: &str| TunnelInput {
            device_id: Some(device.into()),
            name: "test".into(),
            protocol: "tcp".into(),
            local_address: "127.0.0.1".into(),
            local_port: 1234,
            public_port: Some(port),
            hostname: None,
            enabled: Some(true),
            public_domain_id: None,
        };
        assert_eq!(
            create_tunnel(
                State(state.clone()),
                headers.clone(),
                Json(input("foreign"))
            )
            .await
            .unwrap_err()
            .status,
            axum::http::StatusCode::BAD_REQUEST
        );
        let created = create_tunnel(State(state.clone()), headers, Json(input("mine")))
            .await
            .unwrap()
            .0;
        assert_eq!(created.apply_status, "failed");
        assert!(created.apply_error.unwrap().contains("无法建立服务入口"));
        drop(occupied);
        state.tunnel_runtime.reconcile(&state).await.unwrap();
        assert!(state
            .tunnel_runtime
            .connections
            .lock()
            .await
            .listeners
            .contains_key(&created.id));
        state.tunnel_runtime.shutdown().await;
    }
}
