//! UDP 通道独立重连；每个会话只使用控制快照授权的目标，更新快照立即关闭旧 socket。
use super::*;
use nexo_tunnel::udp::{self, Peer, IDLE, MAX_PAYLOAD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn run(connectors: watch::Receiver<TlsConnector>, mut desired: watch::Receiver<Desired>) {
    let mut delay = 1;
    loop {
        // 没有启用 UDP 服务时不建立 QUIC，TCP 用户无需放行额外端口或承受重试告警。
        let endpoint = {
            let snapshot = desired.borrow_and_update();
            snapshot.udp_endpoint.clone().filter(|_| {
                snapshot
                    .tunnels
                    .iter()
                    .any(|t| t.enabled && udp::has_udp(&t.protocol))
            })
        };
        if endpoint.is_none() {
            if desired.changed().await.is_err() {
                return;
            }
            continue;
        }
        if let Some(endpoint) = endpoint {
            let connector = connectors.borrow().clone();
            let result = connection(&connector, &endpoint, desired.clone()).await;
            if let Err(error) = result {
                tracing::warn!("UDP 数据通道结束，将自动重试：{error:#}");
            } else {
                delay = 1;
            }
        }
        tokio::select! {_=tokio::time::sleep(Duration::from_secs(delay))=>{}, change=desired.changed()=>if change.is_err(){return;}}
        delay = (delay * 2).min(30);
    }
}
async fn connection(
    connector: &TlsConnector,
    target: &TunnelDataEndpoint,
    mut desired: watch::Receiver<Desired>,
) -> Result<()> {
    let address = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host(&target.address),
    )
    .await??
    .next()
    .context("UDP 服务端地址解析结果为空")?;
    let mut endpoint = quinn::Endpoint::client(
        if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?,
    )?;
    endpoint.set_default_client_config(udp::client_config(connector.config())?);
    let connection = tokio::time::timeout(
        Duration::from_secs(10),
        endpoint.connect(address, &target.server_name)?,
    )
    .await??;
    let peer = Peer::new(connection);
    let receive = peer.receive();
    tokio::pin!(receive);
    let mut sessions = JoinSet::new();
    tracing::info!("UDP 数据通道已连接");
    let result=async {loop {tokio::select! {
        result=&mut receive=>return result,
        change=desired.changed()=>{if change.is_err() || desired.borrow().udp_endpoint.as_ref()!=Some(target) || !desired.borrow().tunnels.iter().any(|t| t.enabled && udp::has_udp(&t.protocol)){return Ok(());}},
        Some(_)=sessions.join_next(),if !sessions.is_empty()=>{},
        incoming=peer.connection.accept_bi()=>{
            let (send,recv)=incoming?;let peer=peer.clone();let snapshot=desired.clone();
            sessions.spawn(async move {if let Err(error)=session(peer,send,recv,snapshot).await {tracing::debug!("UDP 会话结束：{error:#}");}});
        }
    }}}.await;
    peer.connection.close(0u32.into(), b"UDP connection ended");
    sessions.abort_all();
    while sessions.join_next().await.is_some() {}
    result
}
async fn session(
    peer: Arc<Peer>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    mut desired: watch::Receiver<Desired>,
) -> Result<()> {
    let header = tokio::time::timeout(
        Duration::from_secs(10),
        nexo_tunnel::read_logical_header(&mut recv),
    )
    .await??;
    let tunnel = desired
        .borrow_and_update()
        .tunnels
        .iter()
        .find(|t| {
            t.tunnel_id == header.tunnel_id
                && t.revision == header.revision
                && t.enabled
                && udp::has_udp(&t.protocol)
        })
        .cloned()
        .context("UDP 会话不属于当前配置")?;
    let mut route = peer.register(header.connection_id.parse()?)?;
    let socket = udp::origin(&tunnel.local_address, tunnel.local_port).await?;
    send.write_u8(1).await?;
    send.flush().await?;
    let idle = tokio::time::sleep(IDLE);
    tokio::pin!(idle);
    let mut buffer = vec![0u8; 65_536];
    loop {
        tokio::select! {
            _=&mut idle=>return Ok(()),
            _=recv.read_u8()=>return Ok(()),
            change=desired.changed()=>{if change.is_err() || !desired.borrow().tunnels.contains(&tunnel){return Ok(());}},
            packet=route.receiver.recv()=>{
                let Some(packet)=packet else {return Ok(());};
                tokio::select! {
                    result=socket.send(&packet.bytes)=>{result?;},
                    _=recv.read_u8()=>return Ok(()),
                    change=desired.changed()=>{if change.is_err() || !desired.borrow().tunnels.contains(&tunnel){return Ok(());}}
                }
                idle.as_mut().reset(tokio::time::Instant::now()+IDLE);
            },
            received=socket.recv(&mut buffer)=>{let size=received?;if size<=MAX_PAYLOAD{let _=peer.send(route.id,&buffer[..size]);}idle.as_mut().reset(tokio::time::Instant::now()+IDLE);}
        }
    }
}
