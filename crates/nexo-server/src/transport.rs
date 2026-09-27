//! mTLS 控制连接与 Yamux 数据面。公网端口/本机 Web 入口只打开已分配的服务，
//! 每次开流再次校验设备、租户、配置版本；停用、修改和删除会取消既有连接。
pub mod udp;
use crate::{desired_tunnels, unix_now, AppState};
use anyhow::{Context, Result};
use futures_util::StreamExt;
use nexo_protocol::{AgentControlMessage, ServerControlMessage, TunnelApplyResult};
use nexo_tunnel::{identity::MAX_CONTROL_FRAME, LogicalStreamHeader};
use rusqlite::params;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
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
    task::TaskTracker,
};

trait TunnelIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TunnelIo for T {}
type BoxIo = Box<dyn TunnelIo>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Service {
    id: String,
    tenant: String,
    device: String,
    revision: i64,
    protocol: String,
    port: Option<u16>,
}
struct Listener {
    service: Service,
    upstream: Option<String>,
    path: Option<(PathBuf, std::fs::Metadata)>,
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
    // 仅在 mTLS、设备身份和 Hello 全部通过后记录；连接替换或撤销时随会话清理。
    public_ipv4: Option<Ipv4Addr>,
    direct_capable: bool,
}
#[derive(Default)]
struct Connections {
    udp: HashMap<String, Arc<nexo_tunnel::udp::Peer>>,
    udp_listeners: HashMap<String, Listener>,
    data: HashMap<String, DataSession>,
    control: HashMap<String, ControlSession>,
    listeners: HashMap<String, Listener>,
}

/// 监听器与连接的拥有者：协调串行化，连接任务使用取消令牌，不靠数据库标记假装关闭。
pub struct Runtime {
    pub direct: crate::direct::Runtime,
    udp_budget: nexo_tunnel::udp::Budget,
    pub traffic: crate::traffic::Collector,
    pub quotas: crate::traffic::quota::Manager,
    transfers: TaskTracker,
    bind: IpAddr,
    connections: Mutex<Connections>,
    reconcile_lock: Mutex<()>,
    pub stop: CancellationToken,
}
impl Runtime {
    pub fn new(bind: IpAddr) -> Self {
        Self {
            udp_budget: Default::default(),
            direct: Default::default(),
            traffic: crate::traffic::Collector::default(),
            quotas: crate::traffic::quota::Manager::default(),
            transfers: TaskTracker::new(),
            bind,
            connections: Mutex::new(Connections::default()),
            reconcile_lock: Mutex::new(()),
            stop: CancellationToken::new(),
        }
    }

    pub async fn run(state: AppState) {
        let _dns = tokio::spawn(crate::direct::dns::run(state.clone()));
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = state.tunnel_runtime.stop.cancelled() => break,
                _ = interval.tick() => if let Err(error) = state.tunnel_runtime.reconcile(&state).await { tracing::error!("Tunnel 状态协调失败：{error:#}"); }
            }
        }
    }

    pub async fn direct_session(&self, device: &str) -> Option<CancellationToken> {
        self.connections
            .lock()
            .await
            .control
            .get(device)
            .filter(|s| s.direct_capable && !s.cancel.is_cancelled())
            .map(|s| s.cancel.clone())
    }

    /// API 修改后立即重建/关闭入口，再推送完整快照；空快照同样会撤销 Agent 上的旧服务。
    pub async fn changed(&self, state: &AppState) -> Result<()> {
        self.reconcile(state).await?;
        let connections = self.connections.lock().await;
        for (device, session) in &connections.control {
            let message = ServerControlMessage::HeartbeatAck {
                capabilities: vec![nexo_protocol::direct::CAPABILITY.into()],
                server_time: unix_now(),
                tunnels: desired_tunnels(state, device)?,
                tunnel_endpoint: state.tunnel_endpoint.clone(),
                udp_endpoint: state.udp_endpoint.clone(),
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
        for (_, listener) in connections.udp_listeners.drain() {
            stop_listener(listener).await;
        }
        for (_, peer) in connections.udp.drain() {
            peer.connection.close(0u32.into(), b"shutdown");
        }
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

    /// 数据会话已退出后，等待其被取消的子转发任务真正释放，再保存最后一批流量。
    /// JoinSet 的 Drop 只请求取消，不等待完成，不能直接作为最终计数已经稳定的依据。
    pub async fn finish_transfers(&self) {
        self.transfers.close();
        self.transfers.wait().await;
    }

    /// 身份恢复是显式撤销：与连接注册串行化，提交新身份后取消旧控制和数据通道。
    pub async fn replace_identity<T>(
        &self,
        device: &str,
        change: impl FnOnce() -> Result<T, crate::ApiError>,
    ) -> Result<T, crate::ApiError> {
        let mut connections = self.connections.lock().await;
        let result = change()?;
        udp::disconnect(&mut connections, device);
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
            udp::disconnect(&mut connections, device);
            if let Some(session) = connections.control.remove(device) {
                session.cancel.cancel();
            }
            if let Some(session) = connections.data.remove(device) {
                session.cancel.cancel();
            }
        }
        let udp_ids = connections
            .udp_listeners
            .iter()
            .filter(|(id, l)| services.contains(id) || devices.contains(&l.service.device))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in udp_ids {
            if let Some(l) = connections.udp_listeners.remove(&id) {
                stop_listener(l).await;
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

    /// 按设备提供当前控制连接的真实公网出口；不使用转发头，也不持久化离线出口。
    pub async fn agent_public_ipv4s(&self) -> HashMap<String, Ipv4Addr> {
        self.connections
            .lock()
            .await
            .control
            .iter()
            .filter(|(_, session)| !session.cancel.is_cancelled() && !session.sender.is_closed())
            .filter_map(|(device, session)| session.public_ipv4.map(|ip| (device.clone(), ip)))
            .collect()
    }

    pub async fn reconcile(&self, state: &AppState) -> Result<()> {
        let _guard = self.reconcile_lock.lock().await;
        let (wanted, devices) = {
            let db = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            let mut query = db.prepare("SELECT t.id,t.device_id,t.apply_revision,t.protocol,t.public_port,t.tenant_id FROM tunnels t JOIN devices d ON d.id=t.device_id AND d.tenant_id=t.tenant_id JOIN tenants w ON w.id=t.tenant_id AND w.enabled=1 WHERE t.service_mode='tunnel' AND t.enabled=1 AND t.deleted_at IS NULL")?;
            let services = query
                .query_map([], |r| {
                    Ok(Service {
                        id: r.get(0)?,
                        tenant: r.get(5)?,
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
        let udp_stale = connections
            .udp
            .keys()
            .filter(|id| !devices.contains(id) || !connections.control.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>();
        for id in udp_stale {
            udp::disconnect(&mut connections, &id);
        }
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
        let udp_failures = udp::reconcile(state, &mut connections, &wanted).await;
        let mut failures = HashMap::new();
        for service in wanted.iter().filter(|s| s.protocol != "udp").cloned() {
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
        let tcp_states = refresh_status(state, &listeners, &online, &data, &failures)?;
        udp::refresh_status(state, &udp_failures, tcp_states).await?;
        crate::reverse_proxy::refresh_status(state)?;
        Ok(())
    }

    async fn listen(&self, state: &AppState, service: Service) -> Result<Listener> {
        let cancel = self.stop.child_token();
        if matches!(service.protocol.as_str(), "tcp" | "tcp_udp") {
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
            let directory = state.config.runtime_dir.join("tunnel-sockets");
            // 每个实例使用独占运行目录；拒绝目录符号链接，避免把临时入口写入其他位置。
            use std::os::unix::fs::DirBuilderExt;
            for dir in [&state.config.runtime_dir, &directory] {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)?;
                anyhow::ensure!(
                    std::fs::symlink_metadata(dir)?.file_type().is_dir(),
                    "运行目录必须是普通目录，不能是符号链接"
                );
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
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
                path: Some((path.clone(), std::fs::symlink_metadata(&path)?)),
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
    #[cfg(unix)]
    if let Some((path, created)) = listener.path {
        use std::os::unix::fs::MetadataExt;
        // 只删除本监听器创建的节点；路径若被替换，不接管也不删除替代文件。
        if std::fs::symlink_metadata(&path)
            .is_ok_and(|current| current.dev() == created.dev() && current.ino() == created.ino())
        {
            let _ = std::fs::remove_file(path);
        }
    }
    #[cfg(not(unix))]
    let _ = listener.path;
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
    match state.tunnel_runtime.quotas.get(state, &service.tenant) {
        Ok(quota) if quota.connection().is_some() => {}
        Ok(_) => return,
        Err(error) => {
            tracing::error!("无法读取流量额度，拒绝转发：{error:#}");
            return;
        }
    }
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

/// 同出口仅是内网的近似判定，非公网或原生 IPv6 来源不参与，避免共享/保留网段误判。
fn public_ipv4(peer: IpAddr) -> Option<Ipv4Addr> {
    let ip = match peer {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => ip.to_ipv4_mapped()?,
    };
    let [a, b, c, _] = ip.octets();
    let reserved = a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19));
    (!reserved
        && !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_documentation()
        && !ip.is_multicast())
    .then_some(ip)
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
    authenticated_certificate(state, cert.as_ref())
}
fn authenticated_certificate(state: &AppState, cert: &[u8]) -> Result<(String, String)> {
    let fingerprint = hex::encode(Sha256::digest(cert));
    let (_, parsed) =
        x509_parser::parse_x509_certificate(cert).map_err(|_| anyhow::anyhow!("设备证书无效"))?;
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
                let (socket, peer) = incoming?; let mut tls_config = (*state.authority.server_config()).clone();
                if data { tls_config.alpn_protocols = vec![nexo_protocol::direct::ALPN.to_vec()]; }
                let acceptor = TlsAcceptor::from(Arc::new(tls_config)); let state = state.clone();
                tasks.spawn(async move {
                    let result: Result<()> = async {
                        nexo_tunnel::configure_tunnel_tcp_keepalive(&socket)?;
                        let stream = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket)).await.context("Agent TLS 握手超时")??;
                        let (device, fingerprint) = authenticated_device(&state, &stream)?;
                        if data && stream.get_ref().1.alpn_protocol()==Some(nexo_protocol::direct::ALPN) { crate::direct::session(state,stream,device,fingerprint).await } else if data { data_session(state, stream, device, fingerprint).await } else { control_session(state, stream, device, fingerprint, peer.ip()).await }
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
    peer: IpAddr,
) -> Result<()> {
    let mut diagnostics = nexo_tunnel::control_diagnostics::ControlDiagnostics::default();
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = FramedRead::new(read, LinesCodec::new_with_max_length(MAX_CONTROL_FRAME));
    let first = tokio::time::timeout(Duration::from_secs(10), lines.next())
        .await?
        .context("Agent 未发送 Hello")??;
    diagnostics.received();
    let AgentControlMessage::Hello {
        capabilities,
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
        db.execute(
            "UPDATE devices SET status='online',agent_version=?1,last_seen_at=?2 WHERE id=?3",
            params![agent_version, unix_now(), device],
        )?;
        if let Some(previous) = connections.control.insert(
            device.clone(),
            ControlSession {
                sender: sender.clone(),
                cancel: cancel.clone(),
                public_ipv4: public_ipv4(peer),
                direct_capable: capabilities
                    .iter()
                    .any(|v| v == nexo_protocol::direct::CAPABILITY),
            },
        ) {
            previous.cancel.cancel();
            udp::disconnect(&mut connections, &device);
        }
    }
    let result: Result<()> = async {
        diagnostics.send(&mut write, &ServerControlMessage::HelloAccepted { capabilities: vec![nexo_protocol::direct::CAPABILITY.into()], server_time: unix_now(), tunnels: desired_tunnels(&state, &device)?, tunnel_endpoint: state.tunnel_endpoint.clone(), udp_endpoint: state.udp_endpoint.clone() }).await?;
        let deadline = tokio::time::sleep(Duration::from_secs(45)); tokio::pin!(deadline);
        loop { tokio::select! {
            _ = cancel.cancelled() => break,
            _ = &mut deadline => anyhow::bail!("Agent 心跳超时（45 秒）"),
            command = receiver.recv() => { let Some(command) = command else { break; }; diagnostics.send(&mut write, &command).await?; },
            incoming = lines.next() => {
                let line = incoming.context("Agent 控制通道已断开")??;
                diagnostics.received();
                deadline.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(45));
                match serde_json::from_str::<AgentControlMessage>(&line)? {
                    AgentControlMessage::Heartbeat { device_id, agent_version } => {
                        anyhow::ensure!(device_id == device, "心跳设备 ID 与证书不一致");
                        state.db.lock().map_err(|_| anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE devices SET last_seen_at=?1,agent_version=?2 WHERE id=?3", params![unix_now(),agent_version,device])?;
                        diagnostics.send(&mut write, &ServerControlMessage::HeartbeatAck { capabilities: vec![nexo_protocol::direct::CAPABILITY.into()], server_time: unix_now(), tunnels: desired_tunnels(&state, &device)?, tunnel_endpoint: state.tunnel_endpoint.clone(), udp_endpoint: state.udp_endpoint.clone() }).await?;
                    }
                    AgentControlMessage::TunnelApplyReport { results } => {
                        let ids = apply_results(&state, &device, results)?;
                        diagnostics.send(&mut write, &ServerControlMessage::TunnelApplyAccepted { tunnel_ids: ids }).await?;
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
                        diagnostics.send(&mut write, &response).await?;
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
        udp::disconnect(&mut connections, &device);
        if let Some(session) = connections.data.remove(&device) {
            session.cancel.cancel();
        }
        state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?
            .execute("UPDATE devices SET status='offline' WHERE id=?1", [&device])?;
    }
    result.with_context(|| {
        format!("Server 控制通道诊断：device_id={device} peer={peer}；{diagnostics}")
    })
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
    for mut report in results {
        report.protocol_statuses.retain(|protocol, status| {
            protocol == "udp" && matches!(status.status.as_str(), "ready" | "failed" | "disabled")
        });
        for status in report.protocol_statuses.values_mut() {
            status.error_message = status
                .error_message
                .take()
                .map(|message| message.chars().take(512).collect());
        }
        if !matches!(report.status.as_str(), "ready" | "failed" | "disabled") {
            continue;
        }
        let changed = tx.execute("INSERT INTO tunnel_applied_states (tunnel_id,revision,status,error_message,updated_at) SELECT id,?1,?2,?3,?4 FROM tunnels WHERE service_mode='tunnel' AND id=?5 AND device_id=?6 AND apply_revision=?1 AND deleted_at IS NULL AND (enabled=1 OR ?2='disabled') ON CONFLICT(tunnel_id) DO UPDATE SET revision=excluded.revision,status=excluded.status,error_message=excluded.error_message,updated_at=excluded.updated_at", params![report.revision,if report.applied { report.status.as_str() } else { "failed" },report.error_message.map(|s| s.chars().take(512).collect::<String>()),unix_now(),report.tunnel_id,device])?;
        if changed > 0 {
            tx.execute(
                "UPDATE tunnel_applied_states SET protocol_statuses=?1 WHERE tunnel_id=?2",
                params![
                    serde_json::to_string(&report.protocol_statuses)?,
                    report.tunnel_id
                ],
            )?;
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
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels t JOIN devices d ON d.id=t.device_id AND d.tenant_id=t.tenant_id JOIN tenants w ON w.id=t.tenant_id AND w.enabled=1 WHERE t.service_mode='tunnel' AND t.id=?1 AND t.device_id=?2 AND t.apply_revision=?3 AND t.enabled=1 AND t.deleted_at IS NULL AND d.status='online')", params![service.id,device,service.revision], |r| r.get(0))?)
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
            let quota = state.tunnel_runtime.quotas.get(&state, &command.service.tenant)?;
            let Some(quota_cancel) = quota.connection() else { continue; };
            let stream = tokio::time::timeout(Duration::from_secs(10), nexo_tunnel::new_outbound(&mut connection)).await.context("Tunnel 开流超时")??;
            let meter = state.tunnel_runtime.traffic.meter(&command.service.tenant, &command.service.id);
            copies.spawn(state.tunnel_runtime.transfers.track_future(async move {
                let mut stream = nexo_tunnel::into_tokio_io(stream);
                let transfer = async {
                    let header = LogicalStreamHeader::new(&command.service.id, uuid::Uuid::new_v4().to_string(), command.service.revision)?;
                    tokio::time::timeout(Duration::from_secs(10), nexo_tunnel::write_logical_header(&mut stream, &header)).await??;
                    let mut stream = crate::traffic::Counted::new(stream, meter.clone(), true).with_quota(quota.clone(), quota_cancel.clone());
                    let mut socket = crate::traffic::Counted::new(&mut command.socket, meter, false).with_quota(quota, quota_cancel.clone());
                    tokio::io::copy_bidirectional(&mut socket, &mut stream).await?;
                    anyhow::Ok(())
                };
                tokio::select! { _ = command.cancel.cancelled() => {}, _ = quota_cancel.cancelled() => {}, result = transfer => if let Err(error) = result { tracing::debug!("Tunnel 转发结束：{error:#}"); } }
            }));
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
) -> Result<HashMap<String, (i64, nexo_protocol::ProtocolStatus)>> {
    let rows = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut query = db.prepare("SELECT t.id,t.device_id,(t.enabled AND EXISTS(SELECT 1 FROM tenants w WHERE w.id=t.tenant_id AND w.enabled=1)),t.protocol,t.apply_revision,a.revision,a.status,a.error_message,t.public_domain_id,t.hostname,p.domain,t.tenant_id,t.https_port FROM tunnels t LEFT JOIN tunnel_applied_states a ON a.tunnel_id=t.id LEFT JOIN public_domains p ON p.id=t.public_domain_id AND p.tenant_id=t.tenant_id WHERE t.service_mode='tunnel' AND t.deleted_at IS NULL")?;
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
                    r.get::<_, String>(11)?,
                    r.get::<_, u16>(12)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let mut combined = HashMap::new();
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
        tenant,
        https_port,
    ) in rows
    {
        let (status, error) = if !enabled {
            ("disabled", None)
        } else if state
            .tunnel_runtime
            .quotas
            .get(state, &tenant)?
            .connection()
            .is_none()
        {
            ("checking", Some(crate::traffic::quota::EXHAUSTED.into()))
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
        } else if !nexo_tunnel::udp::is_port(&protocol) {
            let runtime = state
                .domain_runtime
                .status(domain_id.as_deref().unwrap_or_default());
            let host = format!(
                "{}.{}",
                hostname.unwrap_or_default(),
                domain_name.unwrap_or_default()
            );
            if let Some(error) = runtime.service_errors.get(&id) {
                ("failed", Some(error.clone()))
            } else if runtime.config_status != "applied" {
                (
                    "checking",
                    Some(
                        runtime
                            .config_error
                            .unwrap_or_else(|| "等待 Caddy 加载配置".into()),
                    ),
                )
            } else if runtime
                .loaded_routes
                .get(&crate::https_ports::url(&protocol, &host, https_port))
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
        // 组合服务只写入聚合后的状态，避免两次落库之间短暂把部分可用误报为全部可用。
        if nexo_tunnel::udp::has_udp(&protocol) {
            combined.insert(
                id,
                (
                    revision,
                    nexo_protocol::ProtocolStatus {
                        status: status.into(),
                        error_message: error,
                    },
                ),
            );
            continue;
        }
        state.db.lock().map_err(|_| anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE tunnels SET apply_status=?1,apply_error=?2,protocol_statuses='{}' WHERE id=?3 AND apply_revision=?4 AND deleted_at IS NULL", params![status,error,id,revision])?;
    }
    Ok(combined)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[tokio::test]
    async fn socket_cleanup_preserves_replaced_files_and_rejects_links() {
        use std::os::unix::fs::symlink;
        let (state, _) = crate::tests::domain_fixture();
        let service = Service {
            id: "test".into(),
            tenant: "default".into(),
            device: "device".into(),
            revision: 1,
            protocol: "http".into(),
            port: None,
        };
        let directory = state.config.runtime_dir.join("tunnel-sockets");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("test.sock");
        std::fs::write(&path, "keep").unwrap();
        assert!(state
            .tunnel_runtime
            .listen(&state, service.clone())
            .await
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(&path).unwrap();
        let target = directory.join("target");
        std::fs::write(&target, "keep").unwrap();
        symlink(&target, &path).unwrap();
        assert!(state
            .tunnel_runtime
            .listen(&state, service.clone())
            .await
            .is_err());
        assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
        std::fs::remove_file(&path).unwrap();
        let listener = state
            .tunnel_runtime
            .listen(&state, service.clone())
            .await
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "replacement").unwrap();
        stop_listener(listener).await;
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        std::fs::remove_file(&path).unwrap();
        let listener = state.tunnel_runtime.listen(&state, service).await.unwrap();
        stop_listener(listener).await;
        assert!(!path.exists());
        std::fs::remove_file(target).unwrap();
        std::fs::remove_dir(directory).unwrap();
        std::fs::remove_dir(&state.config.runtime_dir).unwrap();
    }
    use super::*;
    use crate::{create_tunnel, TunnelInput};
    use axum::{extract::State, Json};
    use nexo_tunnel::identity::write_message;
    use tokio::io::{AsyncBufReadExt, BufReader};

    type ClientStream = tokio_rustls::client::TlsStream<TcpStream>;

    fn test_client_config(state: &AppState, device: &str) -> Arc<rustls::ClientConfig> {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let certificate = state.authority.issue_device(&csr, device).unwrap();
        state.db.lock().unwrap().execute(
            "INSERT INTO device_identities (device_id,secret_digest,created_at) VALUES (?1,?2,0)",
            params![device, crate::identity_runtime::fingerprint(&certificate).unwrap()],
        ).unwrap();
        nexo_tunnel::identity::client_config(
            &state.authority.ca_pem(),
            &certificate,
            &key.serialize_pem(),
        )
        .unwrap()
    }

    // 使用真实 mTLS 和生产控制循环，仅替换 accept 的来源地址以模拟不同公网出口。
    async fn test_control_connection(
        state: &AppState,
        config: Arc<rustls::ClientConfig>,
        peer: &str,
    ) -> (ClientStream, JoinHandle<Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = state.clone();
        let peer = peer.parse().unwrap();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await?;
            let stream = TlsAcceptor::from(state.authority.server_config())
                .accept(socket)
                .await?;
            let (device, fingerprint) = authenticated_device(&state, &stream)?;
            control_session(state, stream, device, fingerprint, peer).await
        });
        let client = tokio::time::timeout(Duration::from_secs(3), async {
            tokio_rustls::TlsConnector::from(config)
                .connect(
                    nexo_tunnel::identity::SERVER_NAME.try_into().unwrap(),
                    TcpStream::connect(address).await.unwrap(),
                )
                .await
                .unwrap()
        })
        .await
        .unwrap();
        (client, task)
    }

    async fn test_hello(client: &mut ClientStream, device: &str) {
        write_message(
            client,
            &AgentControlMessage::Hello {
                capabilities: vec![],
                device_id: device.into(),
                agent_version: "test".into(),
            },
        )
        .await
        .unwrap();
        let mut response = String::new();
        tokio::time::timeout(
            Duration::from_secs(3),
            BufReader::new(client).read_line(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            serde_json::from_str::<ServerControlMessage>(&response).unwrap(),
            ServerControlMessage::HelloAccepted { .. }
        ));
    }

    #[tokio::test]
    async fn heartbeat_timeout_keeps_io_diagnostics_and_disconnects_device() {
        let (state, _) = crate::tests::domain_fixture();
        populate(&state);
        let config = test_client_config(&state, "mine");
        let (mut client, task) = test_control_connection(&state, config, "8.8.8.8").await;
        test_hello(&mut client, "mine").await;
        // 保持 TLS 连接但不发送心跳，走生产环境的 45 秒超时和清理路径。
        let error = tokio::time::timeout(Duration::from_secs(50), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("Agent 心跳超时（45 秒）"), "{detail}");
        assert!(detail.contains("device_id=mine peer=8.8.8.8"), "{detail}");
        assert!(
            detail.contains("最后接收：[") && detail.contains("最后发送：["),
            "{detail}"
        );
        assert_eq!(detail.matches("累计 1 条").count(), 2, "{detail}");
        assert!(state.tunnel_runtime.agent_public_ipv4s().await.is_empty());
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row("SELECT status FROM devices WHERE id='mine'", [], |r| r
                    .get::<_, String>(
                    0
                ))
                .unwrap(),
            "offline"
        );
        drop(client);
    }

    #[tokio::test]
    async fn direct_alpn_requires_capable_control_and_keeps_data_stream_restrictions() {
        use nexo_protocol::direct::{
            Request as DirectRequest, Response as DirectResponse, ALPN, CAPABILITY,
        };
        let (state, _) = crate::tests::domain_fixture();
        populate(&state);
        let config = test_client_config(&state, "mine");
        let (mut control, control_task) =
            test_control_connection(&state, config.clone(), "8.8.8.8").await;
        write_message(
            &mut control,
            &AgentControlMessage::Hello {
                device_id: "mine".into(),
                agent_version: "test".into(),
                capabilities: vec![CAPABILITY.into()],
            },
        )
        .await
        .unwrap();
        let mut line = String::new();
        BufReader::new(&mut control)
            .read_line(&mut line)
            .await
            .unwrap();
        assert!(state.tunnel_runtime.direct_session("mine").await.is_some());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve(state.clone(), listener, true));
        for management in [false, true] {
            let mut tls = (*config).clone();
            if management {
                tls.alpn_protocols = vec![ALPN.to_vec()];
            }
            let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
                .connect(
                    nexo_tunnel::identity::SERVER_NAME.try_into().unwrap(),
                    TcpStream::connect(address).await.unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                stream.get_ref().1.alpn_protocol(),
                if management { Some(ALPN) } else { None }
            );
            let mut mux = nexo_tunnel::yamux_connection(stream, yamux::Mode::Client);
            let outbound = nexo_tunnel::new_outbound(&mut mux).await.unwrap();
            let driver = tokio::spawn(async move { nexo_tunnel::next_inbound(&mut mux).await });
            let mut stream = nexo_tunnel::into_tokio_io(outbound);
            let sent = write_message(
                &mut stream,
                &DirectRequest::Sync {
                    addresses: vec!["2001:4860::1".into()],
                    reports: vec![],
                },
            )
            .await;
            let mut reply = String::new();
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                BufReader::new(&mut stream).read_line(&mut reply),
            )
            .await
            .unwrap();
            if management {
                sent.unwrap();
                result.unwrap();
                assert!(matches!(
                    serde_json::from_str::<DirectResponse>(&reply).unwrap(),
                    DirectResponse::Services { .. }
                ));
                assert_eq!(
                    state
                        .db
                        .lock()
                        .unwrap()
                        .query_row(
                            "SELECT selected_address FROM direct_agents WHERE device_id='mine'",
                            [],
                            |r| r.get::<_, String>(0)
                        )
                        .unwrap(),
                    "2001:4860::1"
                );
                state
                    .tunnel_runtime
                    .direct_session("mine")
                    .await
                    .unwrap()
                    .cancel();
                assert!(tokio::time::timeout(Duration::from_secs(3), driver)
                    .await
                    .is_ok());
            } else {
                assert!(
                    result.is_err() || reply.is_empty(),
                    "普通数据通道不得接受 Agent 主动管理流"
                );
                driver.abort();
            }
        }
        drop(control);
        let _ = test_session_finished(control_task).await;
        state.tunnel_runtime.stop.cancel();
        server.await.unwrap().unwrap();
    }

    async fn test_session_finished(task: JoinHandle<Result<()>>) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
    }

    #[test]
    fn agent_exit_requires_public_ipv4_and_normalizes_mapped_addresses() {
        for address in [
            "0.0.0.0",
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.1.2",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.19.255.254",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::8.8.8.8",
            "fc00::1",
            "2001:4860::8888",
            "::ffff:192.168.1.2",
            "::ffff:100.64.0.1",
        ] {
            assert_eq!(public_ipv4(address.parse().unwrap()), None, "{address}");
        }
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.0.1.1",
            "198.17.255.255",
            "198.20.0.1",
            "223.255.255.254",
        ] {
            assert_eq!(
                public_ipv4(address.parse().unwrap()),
                Some(address.parse().unwrap()),
                "{address}"
            );
        }
        assert_eq!(
            public_ipv4("::ffff:8.8.8.8".parse().unwrap()),
            Some("8.8.8.8".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn exit_is_unavailable_until_certificate_identity_and_hello_are_accepted() {
        let (state, _) = crate::tests::domain_fixture();
        populate(&state);
        let config = test_client_config(&state, "mine");
        let (mut client, task) = test_control_connection(&state, config.clone(), "8.8.8.8").await;
        assert!(state.tunnel_runtime.agent_public_ipv4s().await.is_empty());
        write_message(
            &mut client,
            &AgentControlMessage::Hello {
                capabilities: vec![],
                device_id: "foreign".into(),
                agent_version: "test".into(),
            },
        )
        .await
        .unwrap();
        assert!(test_session_finished(task).await.is_err());
        assert!(state.tunnel_runtime.agent_public_ipv4s().await.is_empty());
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE device_identities SET secret_digest='revoked' WHERE device_id='mine'",
                [],
            )
            .unwrap();
        let (_client, task) = test_control_connection(&state, config, "8.8.8.8").await;
        assert!(test_session_finished(task).await.is_err());
        assert!(state.tunnel_runtime.agent_public_ipv4s().await.is_empty());
    }

    #[tokio::test]
    async fn new_exit_survives_old_connection_cleanup_and_disconnect_only_removes_its_device() {
        let (state, _) = crate::tests::domain_fixture();
        populate(&state);
        let config = test_client_config(&state, "mine");
        let foreign = test_client_config(&state, "foreign");
        let (mut old, old_task) = test_control_connection(&state, config.clone(), "8.8.8.8").await;
        test_hello(&mut old, "mine").await;
        let (mut other, other_task) = test_control_connection(&state, foreign, "9.9.9.9").await;
        test_hello(&mut other, "foreign").await;
        let (mut new, new_task) = test_control_connection(&state, config, "::ffff:1.1.1.1").await;
        test_hello(&mut new, "mine").await;
        test_session_finished(old_task).await.unwrap();
        assert_eq!(
            state.tunnel_runtime.agent_public_ipv4s().await,
            HashMap::from([
                ("mine".into(), "1.1.1.1".parse().unwrap()),
                ("foreign".into(), "9.9.9.9".parse().unwrap()),
            ])
        );
        drop(new);
        assert!(test_session_finished(new_task).await.is_err());
        assert_eq!(
            state.tunnel_runtime.agent_public_ipv4s().await,
            HashMap::from([("foreign".into(), "9.9.9.9".parse().unwrap())])
        );
        state.tunnel_runtime.shutdown().await;
        test_session_finished(other_task).await.unwrap();
        assert!(state.tunnel_runtime.agent_public_ipv4s().await.is_empty());
    }

    #[tokio::test]
    async fn failed_registration_preserves_the_existing_session_and_exit() {
        let (state, _) = crate::tests::domain_fixture();
        populate(&state);
        let config = test_client_config(&state, "mine");
        let (mut old, old_task) = test_control_connection(&state, config.clone(), "8.8.8.8").await;
        test_hello(&mut old, "mine").await;
        state.db.lock().unwrap().execute_batch(
            "CREATE TRIGGER fail_online BEFORE UPDATE OF status ON devices WHEN NEW.status='online' BEGIN SELECT RAISE(ABORT,'test write failure'); END;",
        ).unwrap();
        let (mut new, new_task) = test_control_connection(&state, config, "1.1.1.1").await;
        write_message(
            &mut new,
            &AgentControlMessage::Hello {
                capabilities: vec![],
                device_id: "mine".into(),
                agent_version: "test".into(),
            },
        )
        .await
        .unwrap();
        assert!(test_session_finished(new_task).await.is_err());
        assert_eq!(
            state.tunnel_runtime.agent_public_ipv4s().await,
            HashMap::from([("mine".into(), "8.8.8.8".parse().unwrap())])
        );
        assert!(!old_task.is_finished());
        state.tunnel_runtime.shutdown().await;
        test_session_finished(old_task).await.unwrap();
    }

    async fn test_udp_connection(
        state: &AppState,
        config: &rustls::ClientConfig,
    ) -> (quinn::Endpoint, quinn::Endpoint, quinn::Connection) {
        let server = quinn::Endpoint::server(
            nexo_tunnel::udp::server_config(&state.authority.server_config()).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(nexo_tunnel::udp::client_config(config).unwrap());
        let (outgoing, incoming) = tokio::join!(
            client
                .connect(
                    server.local_addr().unwrap(),
                    nexo_tunnel::identity::SERVER_NAME
                )
                .unwrap(),
            async { server.accept().await.unwrap().await.unwrap() }
        );
        let certs = incoming
            .peer_identity()
            .unwrap()
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .unwrap();
        let (device, _) = authenticated_certificate(state, certs[0].as_ref()).unwrap();
        state
            .tunnel_runtime
            .connections
            .lock()
            .await
            .udp
            .insert(device, nexo_tunnel::udp::Peer::new(incoming));
        (server, client, outgoing.unwrap())
    }

    #[test]
    fn current_agent_receives_all_protocols() {
        let (state, _) = crate::tests::domain_fixture();
        populate(&state);
        state.db.lock().unwrap().execute_batch("UPDATE tunnels SET protocol='tcp_udp' WHERE id='own'; INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('udp','default','mine','udp','udp','localhost',1234,0,0)").unwrap();
        let new = desired_tunnels(&state, "mine").unwrap();
        assert_eq!(new.len(), 2);
        assert!(new.iter().any(|t| t.protocol == "tcp_udp"));
    }

    #[test]
    fn combined_status_is_not_published_before_udp_is_aggregated() {
        let (state, _) = crate::tests::domain_fixture();
        populate(&state);
        state.db.lock().unwrap().execute_batch("UPDATE tunnels SET protocol='tcp_udp',apply_status='partial' WHERE id='own'; INSERT INTO tunnel_applied_states(tunnel_id,revision,status,updated_at) VALUES('own',2,'ready',0)").unwrap();
        let listeners = HashMap::from([("own".into(), None)]);
        let statuses = refresh_status(
            &state,
            &listeners,
            &["mine".into()],
            &["mine".into()],
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(statuses["own"].1.status, "ready");
        let persisted: String = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT apply_status FROM tunnels WHERE id='own'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            persisted, "partial",
            "不能将 TCP 检查结果单独发布为组合服务状态"
        );
    }

    #[tokio::test]
    async fn cancellation_identity_recovery_and_removed_ownership_revoke_exits() {
        for reason in ["cancel", "identity", "workspace", "device", "tenant"] {
            let (state, _) = crate::tests::domain_fixture();
            populate(&state);
            let config = test_client_config(&state, "mine");
            let (mut client, task) =
                test_control_connection(&state, config.clone(), "8.8.8.8").await;
            test_hello(&mut client, "mine").await;
            let (_udp_server, _udp_client, udp_connection) =
                test_udp_connection(&state, &config).await;
            assert_eq!(state.tunnel_runtime.agent_public_ipv4s().await.len(), 1);
            match reason {
                "cancel" => state.tunnel_runtime.connections.lock().await.control["mine"]
                    .cancel
                    .cancel(),
                "identity" => state
                    .tunnel_runtime
                    .replace_identity("mine", || Ok(()))
                    .await
                    .unwrap(),
                "workspace" => state
                    .tunnel_runtime
                    .remove_workspace(|| {
                        state
                            .db
                            .lock()
                            .unwrap()
                            .execute("DELETE FROM tenants WHERE id='default'", [])
                            .unwrap();
                        Ok((vec!["mine".into()], vec!["own".into()]))
                    })
                    .await
                    .unwrap(),
                "device" | "tenant" => {
                    let query = if reason == "device" {
                        "DELETE FROM devices WHERE id='mine'"
                    } else {
                        "UPDATE tenants SET enabled=0 WHERE id='default'"
                    };
                    state.db.lock().unwrap().execute(query, []).unwrap();
                    state.tunnel_runtime.reconcile(&state).await.unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                state.tunnel_runtime.agent_public_ipv4s().await.is_empty(),
                "{reason}"
            );
            test_session_finished(task).await.unwrap();
            tokio::time::timeout(Duration::from_secs(3), udp_connection.closed())
                .await
                .expect("撤销必须关闭 UDP 通道");
            assert!(!state
                .tunnel_runtime
                .connections
                .lock()
                .await
                .udp
                .contains_key("mine"));
            state.tunnel_runtime.shutdown().await;
        }
    }

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
            protocol_statuses: Default::default(),
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
            https_port: None,
            ipv6_direct_enabled: None,
            http_redirect_enabled: None,
            access_mode: None,
            access_password: None,
            service_mode: None,
            device_id: Some(device.into()),
            name: "test".into(),
            protocol: "tcp".into(),
            origin_protocol: None,
            local_address: "127.0.0.1".into(),
            local_port: 1234,
            public_port: Some(port),
            hostname: None,
            enabled: Some(true),
            public_domain_id: None,
            lan_redirect_enabled: None,
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
