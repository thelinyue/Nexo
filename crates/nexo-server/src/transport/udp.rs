//! QUIC 身份会话和公网 UDP 监听。使用父运行时的同一把协调锁处理身份替换与入口撤销。
use super::*;
use nexo_tunnel::udp::{self, Packet, Peer, IDLE, MAX_PAYLOAD, MAX_SESSIONS};
use std::net::SocketAddr;
use tokio::{io::AsyncReadExt, net::UdpSocket};

pub async fn serve(state: AppState) -> Result<()> {
    let address = state.config.udp_addr;
    let endpoint = quinn::Endpoint::server(
        udp::server_config(&state.authority.server_config())?,
        address,
    )
    .context("无法监听 UDP 数据端口")?;
    let mut tasks = JoinSet::new();
    let mut timer = tokio::time::interval(Duration::from_secs(30));
    let permits = Arc::new(Semaphore::new(64));
    loop {
        tokio::select! {
            _=state.tunnel_runtime.stop.cancelled()=>break,
            _=timer.tick()=>endpoint.set_server_config(Some(udp::server_config(&state.authority.server_config())?)),
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            incoming=endpoint.accept()=>{
                let Some(incoming)=incoming else{break;};let Ok(permit)=permits.clone().try_acquire_owned() else{incoming.refuse();continue;};
                let state=state.clone();tasks.spawn(async move {
                    let result=async {
                        let connection=tokio::time::timeout(Duration::from_secs(10),incoming).await??;
                        drop(permit);
                        let identity=connection.peer_identity().context("UDP 连接缺少设备证书")?.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().map_err(|_|anyhow::anyhow!("UDP 身份类型无效"))?;
                        let certificate=identity.first().context("UDP 设备证书为空")?;
                        let peer=Peer::new(connection);
                        let device={
                            let mut connections=state.tunnel_runtime.connections.lock().await;
                            let (device,_)=authenticated_certificate(&state,certificate.as_ref())?;
                            anyhow::ensure!(connections.control.get(&device).is_some_and(|s|!s.cancel.is_cancelled()),"UDP 连接缺少有效控制会话");
                            if let Some(previous)=connections.udp.insert(device.clone(),peer.clone()){previous.connection.close(0u32.into(),b"replaced");}
                            device
                        };
                        let result=tokio::select!{result=peer.receive()=>result,_=peer.connection.accept_bi()=>Err(anyhow::anyhow!("设备不允许主动创建 UDP 会话"))};
                        peer.connection.close(0u32.into(),b"closed");
                        let mut connections=state.tunnel_runtime.connections.lock().await;
                        if connections.udp.get(&device).is_some_and(|p|Arc::ptr_eq(p,&peer)){connections.udp.remove(&device);}
                        result
                    }.await;
                    if let Err(error)=result{tracing::warn!("UDP 数据连接结束：{error:#}");}
                });
            }
        }
    }
    endpoint.close(0u32.into(), b"shutdown");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub(super) fn disconnect(connections: &mut Connections, device: &str) {
    if let Some(peer) = connections.udp.remove(device) {
        peer.connection.close(0u32.into(), b"identity revoked");
    }
}
pub(super) async fn reconcile(
    state: &AppState,
    connections: &mut Connections,
    wanted: &[Service],
) -> HashMap<String, String> {
    let stale = connections
        .udp_listeners
        .iter()
        .filter(|(_, l)| l.task.is_finished() || !wanted.contains(&l.service))
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    for id in stale {
        if let Some(l) = connections.udp_listeners.remove(&id) {
            stop_listener(l).await;
        }
    }
    let mut failures = HashMap::new();
    for service in wanted.iter().filter(|s| udp::has_udp(&s.protocol)) {
        if connections.udp_listeners.contains_key(&service.id) {
            continue;
        }
        let result = async {
            let socket = Arc::new(
                UdpSocket::bind((
                    state.tunnel_runtime.bind,
                    service.port.context("UDP 服务没有公网端口")?,
                ))
                .await?,
            );
            let cancel = state.tunnel_runtime.stop.child_token();
            let task = tokio::spawn(listener(
                state.clone(),
                service.clone(),
                socket,
                cancel.clone(),
            ));
            anyhow::Ok(Listener {
                service: service.clone(),
                upstream: None,
                path: None,
                cancel,
                task,
            })
        }
        .await;
        match result {
            Ok(l) => {
                connections.udp_listeners.insert(service.id.clone(), l);
            }
            Err(error) => {
                failures.insert(
                    service.id.clone(),
                    format!("UDP 公网端口监听失败：{error:#}"),
                );
            }
        }
    }
    failures
}

async fn listener(
    state: AppState,
    service: Service,
    socket: Arc<UdpSocket>,
    cancel: CancellationToken,
) {
    let mut clients: HashMap<SocketAddr, mpsc::Sender<Packet>> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0; 65_536];
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if let Ok(address)=result{clients.remove(&address);}},
            received=socket.recv_from(&mut buffer)=>{
                let (size,address)=match received {
                    Ok(value)=>value,
                    Err(error) if matches!(error.kind(),std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::Interrupted)=>continue,
                    Err(error)=>{tracing::warn!("UDP 公网监听停止：{error}");break;}
                };if size>MAX_PAYLOAD{continue;}
                let Some(packet)=state.tunnel_runtime.udp_budget.packet(&buffer[..size]) else{continue;};
                if let Some(client)=clients.get(&address){let _=client.try_send(packet);continue;}
                if clients.len()>=MAX_SESSIONS {udp::warn_dropped("公网 UDP 会话数量达到上限");continue;}
                let peer={state.tunnel_runtime.connections.lock().await.udp.get(&service.device).cloned()};
                let Some(peer)=peer.filter(|p|p.connection.close_reason().is_none()) else{continue;};
                if !allowed(&state,&service,&service.device).unwrap_or(false){continue;}
                let (tx,rx)=mpsc::channel(16);let _=tx.try_send(packet);clients.insert(address,tx);
                let state=state.clone();let service=service.clone();let socket=socket.clone();let cancel=cancel.clone();
                let transfers=state.tunnel_runtime.clone();
                tasks.spawn(transfers.transfers.track_future(async move {
                    tokio::select!{_=cancel.cancelled()=>{},result=forward(state,service,socket,address,peer,rx)=>if let Err(error)=result{tracing::debug!("UDP 公网会话结束：{error:#}");}}
                    address
                }));
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn forward(
    state: AppState,
    service: Service,
    socket: Arc<UdpSocket>,
    address: SocketAddr,
    peer: Arc<Peer>,
    mut packets: mpsc::Receiver<Packet>,
) -> Result<()> {
    let quota = state.tunnel_runtime.quotas.get(&state, &service.tenant)?;
    let quota_cancel = quota.connection().context("UDP 流量额度不足")?;
    let meter = state
        .tunnel_runtime
        .traffic
        .meter(&service.tenant, &service.id);
    let id = peer.next_id();
    let mut route = peer.register(id)?;
    let (mut send, mut recv) =
        tokio::time::timeout(Duration::from_secs(10), peer.connection.open_bi()).await??;
    let header = LogicalStreamHeader::new(&service.id, id.to_string(), service.revision)?;
    tokio::time::timeout(Duration::from_secs(10), async {
        nexo_tunnel::write_logical_header(&mut send, &header).await?;
        anyhow::ensure!(recv.read_u8().await? == 1, "设备拒绝 UDP 会话");
        anyhow::Ok(())
    })
    .await??;
    let idle = tokio::time::sleep(IDLE);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _=quota_cancel.cancelled()=>return Ok(()),
            _=&mut idle=>return Ok(()),
            _=recv.read_u8()=>return Ok(()),
            packet=packets.recv()=>{
                let Some(packet)=packet else{return Ok(());};
                if let Some(count)=quota.datagram(packet.bytes.len(),&quota_cancel,||peer.send(id,&packet.bytes).0){meter.record(unix_now(),true,count);}
                idle.as_mut().reset(tokio::time::Instant::now()+IDLE);
            },
            packet=route.receiver.recv()=>{
                let Some(packet)=packet else{return Ok(());};
                if let Some(count)=quota.datagram(packet.bytes.len(),&quota_cancel,||socket.try_send_to(&packet.bytes,address).unwrap_or(0)){meter.record(unix_now(),false,count);}
                idle.as_mut().reset(tokio::time::Instant::now()+IDLE);
            }
        }
    }
}

/// TCP 状态沿用原检查；UDP 不做虚假的 connect 健康探测，组合服务分别聚合。
pub(super) async fn refresh_status(
    state: &AppState,
    failures: &HashMap<String, String>,
    mut tcp_states: HashMap<String, (i64, nexo_protocol::ProtocolStatus)>,
) -> Result<()> {
    use nexo_protocol::ProtocolStatus;
    use std::collections::BTreeMap;
    let connections = state.tunnel_runtime.connections.lock().await;
    let rows = {
        let db = state.db.lock().unwrap();
        let mut q=db.prepare("SELECT t.id,t.device_id,t.protocol,t.enabled AND w.enabled,t.apply_revision,t.tenant_id,a.revision,a.protocol_statuses FROM tunnels t JOIN tenants w ON w.id=t.tenant_id LEFT JOIN tunnel_applied_states a ON a.tunnel_id=t.id WHERE t.protocol IN ('udp','tcp_udp') AND t.deleted_at IS NULL")?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<i64>>(6)?,
                    r.get::<_, Option<String>>(7)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let mut updates = Vec::new();
    for (id, device, protocol, enabled, revision, tenant, applied_revision, reports) in rows {
        let reports: BTreeMap<String, ProtocolStatus> =
            serde_json::from_str(reports.as_deref().unwrap_or("{}")).unwrap_or_default();
        let control = device.as_ref().and_then(|id| connections.control.get(id));
        let udp_error = if !enabled {
            None
        } else if state
            .tunnel_runtime
            .quotas
            .get(state, &tenant)?
            .connection()
            .is_none()
        {
            Some(crate::traffic::quota::EXHAUSTED.to_owned())
        } else if control.is_none() {
            Some("设备未连接控制通道".into())
        } else if let Some(error) = failures.get(&id) {
            Some(error.clone())
        } else if !connections.udp_listeners.contains_key(&id) {
            Some("UDP 公网入口尚未建立".into())
        } else if !device.as_ref().is_some_and(|d| {
            connections
                .udp
                .get(d)
                .is_some_and(|p| p.connection.close_reason().is_none())
        }) {
            Some("UDP 数据通道未连接，请检查 UDP 数据端口".into())
        } else if applied_revision != Some(revision) {
            Some("等待设备应用 UDP 配置".into())
        } else {
            match reports.get("udp") {
                Some(r) if r.status == "ready" => None,
                Some(r) => Some(
                    r.error_message
                        .clone()
                        .unwrap_or_else(|| "UDP 配置未就绪".into()),
                ),
                None => Some("等待设备应用 UDP 配置".into()),
            }
        };
        let udp = ProtocolStatus {
            status: if !enabled {
                "disabled"
            } else if udp_error.is_none() {
                "ready"
            } else if failures.contains_key(&id)
                || (applied_revision == Some(revision)
                    && reports.get("udp").is_some_and(|r| r.status == "failed"))
            {
                "failed"
            } else {
                "checking"
            }
            .into(),
            error_message: udp_error,
        };
        let mut statuses = BTreeMap::new();
        statuses.insert("udp".to_owned(), udp);
        if protocol == "tcp_udp" {
            statuses.insert(
                "tcp".into(),
                tcp_states
                    .remove(&id)
                    .filter(|(version, _)| *version == revision)
                    .map(|(_, status)| status)
                    .unwrap_or(ProtocolStatus {
                        status: "checking".into(),
                        error_message: Some("等待 TCP 配置协调".into()),
                    }),
            );
        }
        let ready = statuses.values().filter(|s| s.status == "ready").count();
        let status = if !enabled {
            "disabled"
        } else if ready == statuses.len() {
            "ready"
        } else if ready > 0 {
            "partial"
        } else if statuses.values().any(|s| s.status == "failed") {
            "failed"
        } else {
            "checking"
        };
        let errors = statuses
            .iter()
            .filter_map(|(p, s)| {
                s.error_message
                    .as_ref()
                    .map(|e| format!("{}：{e}", p.to_uppercase()))
            })
            .collect::<Vec<_>>();
        let error = if errors.is_empty() {
            None
        } else {
            Some(errors.join("；"))
        };
        updates.push(super::StatusUpdate {
            id,
            revision,
            status: status.into(),
            error,
            protocols: Some(serde_json::to_string(&statuses)?),
        });
    }
    super::save_statuses(state, updates)?;
    Ok(())
}
