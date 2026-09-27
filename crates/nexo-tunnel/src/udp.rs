//! UDP 的 QUIC 数据面：可靠流只确认会话，应用载荷不重传。
//! 所有接收队列共用字节预算，避免按会话数量预留大缓冲；重组有独立上限和期限。
use anyhow::{Context, Result};
use bytes::Bytes;
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

pub const ALPN: &[u8] = b"nexo-udp/1";
pub const MAX_PAYLOAD: usize = 65_507;
pub const MAX_SESSIONS: usize = 1024;
pub const BUFFER_BYTES: usize = 8 * 1024 * 1024;
pub const IDLE: Duration = Duration::from_secs(300);
const HEADER: usize = 20;
const EXPIRY: Duration = Duration::from_secs(2);

/// 高频 UDP 丢包不能逐包刷日志；资源压力提示全进程最多每 30 秒输出一次。
pub fn warn_dropped(reason: &str) {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let last = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(last) >= 30
        && LAST
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        tracing::warn!("UDP 数据报已丢弃：{reason}；请检查流量、并发会话和网络状态");
    }
}

pub fn has_udp(protocol: &str) -> bool {
    matches!(protocol, "udp" | "tcp_udp")
}
pub fn is_port(protocol: &str) -> bool {
    matches!(protocol, "tcp" | "udp" | "tcp_udp")
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config.datagram_receive_buffer_size(Some(BUFFER_BYTES));
    config.datagram_send_buffer_size(BUFFER_BYTES);
    config.max_concurrent_bidi_streams((MAX_SESSIONS as u32).into());
    config.max_concurrent_uni_streams(0_u32.into());
    config.keep_alive_interval(Some(Duration::from_secs(15)));
    config.max_idle_timeout(Some(Duration::from_secs(45).try_into().unwrap()));
    Arc::new(config)
}
pub fn server_config(tls: &rustls::ServerConfig) -> Result<quinn::ServerConfig> {
    let mut tls = tls.clone();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport());
    Ok(config)
}
pub fn client_config(tls: &rustls::ClientConfig) -> Result<quinn::ClientConfig> {
    let mut tls = tls.clone();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.enable_early_data = false;
    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    config.transport_config(transport());
    Ok(config)
}

/// 包拥有预算许可，离开队列并完成消费后自动释放，取消任务不会泄漏额度。
pub struct Packet {
    pub bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}
#[derive(Clone)]
/// 所有会话按实际排队字节共用额度，空队列不占用载荷内存。
pub struct Budget(Arc<Semaphore>);
impl Default for Budget {
    fn default() -> Self {
        Self(Arc::new(Semaphore::new(BUFFER_BYTES)))
    }
}
impl Budget {
    pub fn packet(&self, bytes: &[u8]) -> Option<Packet> {
        if bytes.len() > MAX_PAYLOAD {
            return None;
        }
        let permit = self
            .0
            .clone()
            .try_acquire_many_owned(bytes.len().max(1) as u32)
            .inspect_err(|_| {
                warn_dropped("共享接收缓冲已满");
            })
            .ok()?;
        Some(Packet {
            bytes: bytes.to_vec(),
            _permit: permit,
        })
    }
}

struct Assembly {
    bytes: Vec<u8>,
    seen: Vec<bool>,
    count: usize,
    created: Instant,
}
/// 每个会话缓存最近交付过的包号；重复片不能把同一 UDP 包交付两次。
#[derive(Default)]
struct Reassembly {
    packets: HashMap<(u64, u64), Assembly>,
    delivered: HashMap<u64, VecDeque<u64>>,
    used: usize,
}
impl Reassembly {
    fn expire(&mut self, now: Instant) {
        self.packets.retain(|_, p| {
            if now.duration_since(p.created) >= EXPIRY {
                self.used -= p.bytes.len() * 2;
                false
            } else {
                true
            }
        });
    }
    fn remove(&mut self, session: u64) {
        self.delivered.remove(&session);
        self.packets.retain(|(s, _), p| {
            if *s == session {
                self.used -= p.bytes.len() * 2;
                false
            } else {
                true
            }
        });
    }
    fn push(&mut self, frame: &[u8], now: Instant) -> Option<(u64, Vec<u8>)> {
        if frame.len() < HEADER {
            return None;
        }
        let session = u64::from_be_bytes(frame[..8].try_into().ok()?);
        let message = u64::from_be_bytes(frame[8..16].try_into().ok()?);
        let total = u16::from_be_bytes(frame[16..18].try_into().ok()?) as usize;
        let offset = u16::from_be_bytes(frame[18..20].try_into().ok()?) as usize;
        let part = &frame[HEADER..];
        if total > MAX_PAYLOAD || offset + part.len() > total || (total != 0 && part.is_empty()) {
            return None;
        }
        if self
            .delivered
            .get(&session)
            .is_some_and(|ids| ids.contains(&message))
        {
            return None;
        }
        let key = (session, message);
        if !self.packets.contains_key(&key) {
            if self.used + total * 2 > BUFFER_BYTES || self.packets.len() >= MAX_SESSIONS * 4 {
                warn_dropped("分片重组缓冲已满");
                return None;
            }
            self.used += total * 2;
            self.packets.insert(
                key,
                Assembly {
                    bytes: vec![0; total],
                    seen: vec![false; total],
                    count: 0,
                    created: now,
                },
            );
        }
        let packet = self.packets.get_mut(&key)?;
        if packet.bytes.len() != total {
            return None;
        }
        for (i, byte) in part.iter().enumerate() {
            let index = offset + i;
            if !packet.seen[index] {
                packet.seen[index] = true;
                packet.bytes[index] = *byte;
                packet.count += 1;
            } else if packet.bytes[index] != *byte {
                return None;
            }
        }
        if packet.count != total {
            return None;
        }
        let packet = self.packets.remove(&key)?;
        self.used -= total * 2;
        let ids = self.delivered.entry(session).or_default();
        ids.push_back(message);
        if ids.len() > 128 {
            ids.pop_front();
        }
        Some((session, packet.bytes))
    }
}

/// 每条已认证 QUIC 连接一个分发器；只接收已确认会话的数据，未知包不分配重组缓存。
pub struct Peer {
    pub connection: quinn::Connection,
    routes: Mutex<HashMap<u64, mpsc::Sender<Packet>>>,
    assembly: Mutex<Reassembly>,
    budget: Budget,
    serial: AtomicU64,
    send_lock: Mutex<()>,
}
impl Peer {
    pub fn new(connection: quinn::Connection) -> Arc<Self> {
        Arc::new(Self {
            connection,
            routes: Mutex::new(HashMap::new()),
            assembly: Mutex::new(Reassembly::default()),
            budget: Budget::default(),
            serial: AtomicU64::new(1),
            send_lock: Mutex::new(()),
        })
    }
    pub fn next_id(&self) -> u64 {
        self.serial.fetch_add(1, Ordering::Relaxed)
    }
    pub fn register(self: &Arc<Self>, id: u64) -> Result<Route> {
        let mut routes = self.routes.lock().unwrap();
        anyhow::ensure!(
            routes.len() < MAX_SESSIONS && !routes.contains_key(&id),
            "UDP 会话数量超限或标识重复"
        );
        let (tx, rx) = mpsc::channel(16);
        routes.insert(id, tx);
        Ok(Route {
            id,
            receiver: rx,
            peer: self.clone(),
        })
    }
    pub async fn receive(&self) -> Result<()> {
        let mut timer = tokio::time::interval(EXPIRY);
        loop {
            tokio::select! {
                _=timer.tick()=>self.assembly.lock().unwrap().expire(Instant::now()),
                frame=self.connection.read_datagram()=>{
                    let frame=frame?;
                    if frame.len()<HEADER {continue;}
                    let id=u64::from_be_bytes(frame[..8].try_into().unwrap());
                    let routes=self.routes.lock().unwrap();
                    let Some(route)=routes.get(&id) else {continue;};
                    if let Some((_,payload))=self.assembly.lock().unwrap().push(&frame,Instant::now()) {
                        if let Some(packet)=self.budget.packet(&payload) {if route.try_send(packet).is_err(){warn_dropped("会话接收队列已满或关闭");}}
                    }
                }
            }
        }
    }
    /// 返回实际提交的载荷字节。部分分片已提交后出错不能退还整包流量。
    pub fn send(&self, session: u64, payload: &[u8]) -> (usize, Result<()>) {
        let _guard = self.send_lock.lock().unwrap();
        let result = (|| -> Result<Vec<Bytes>> {
            anyhow::ensure!(payload.len() <= MAX_PAYLOAD, "UDP 数据报超过 65507 字节");
            let size = self
                .connection
                .max_datagram_size()
                .context("对端未启用 QUIC DATAGRAM")?;
            frames(session, self.next_id(), payload, size)
        })();
        let frames = match result {
            Ok(frames) => frames,
            Err(e) => return (0, Err(e)),
        };
        let mut sent = 0;
        for frame in frames {
            let size = frame.len() - HEADER;
            // 共用发送锁使检查与提交连续，避免 Quinn 满队列时挤掉旧包。
            if self.connection.datagram_send_buffer_space() < frame.len() {
                warn_dropped("QUIC 发送队列已满");
                return (sent, Err(anyhow::anyhow!("UDP 发送队列已满")));
            }
            match self.connection.send_datagram(frame) {
                Ok(()) => sent += size,
                Err(e) => return (sent, Err(e.into())),
            }
        }
        (sent, Ok(()))
    }
}
pub struct Route {
    pub id: u64,
    pub receiver: mpsc::Receiver<Packet>,
    peer: Arc<Peer>,
}
impl Drop for Route {
    fn drop(&mut self) {
        self.peer.routes.lock().unwrap().remove(&self.id);
        self.peer.assembly.lock().unwrap().remove(self.id);
    }
}
fn frames(session: u64, message: u64, payload: &[u8], mtu: usize) -> Result<Vec<Bytes>> {
    anyhow::ensure!(
        payload.len() <= MAX_PAYLOAD && mtu > HEADER,
        "UDP 数据报或 QUIC 容量无效"
    );
    let mut frames = Vec::new();
    let chunk = mtu - HEADER;
    for offset in (0..payload.len().max(1)).step_by(chunk) {
        let end = (offset + chunk).min(payload.len());
        let mut frame = Vec::with_capacity(HEADER + end - offset);
        frame.extend_from_slice(&session.to_be_bytes());
        frame.extend_from_slice(&message.to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(offset as u16).to_be_bytes());
        frame.extend_from_slice(&payload[offset..end]);
        frames.push(Bytes::from(frame));
    }
    Ok(frames)
}

pub async fn origin(address: &str, port: u16) -> Result<tokio::net::UdpSocket> {
    let target = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((address.trim_matches(['[', ']']), port)),
    )
    .await??
    .next()
    .context("UDP 内网地址解析结果为空")?;
    let socket = tokio::net::UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(target).await?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn quic_mutual_tls_datagrams_and_ipv6_origin() {
        use crate::identity;
        use rcgen::{CertificateParams, KeyPair};
        let authority = identity::Authority::generate().unwrap();
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(vec!["agent.nexo".into()])
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let cert = authority.issue_device(&csr, "test-agent").unwrap();
        let tls = identity::client_config(&authority.ca_pem, &cert, &key.serialize_pem()).unwrap();
        let server = quinn::Endpoint::server(
            server_config(&authority.server_config().unwrap()).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_config(&tls).unwrap());
        let (connected, accepted) = tokio::join!(
            client
                .connect(server.local_addr().unwrap(), identity::SERVER_NAME)
                .unwrap(),
            async { server.accept().await.unwrap().await.unwrap() }
        );
        let left = Peer::new(connected.unwrap());
        let right = Peer::new(accepted);
        let mut route = right.register(42).unwrap();
        let receive = tokio::spawn({
            let right = right.clone();
            async move { right.receive().await }
        });
        let data = vec![7; MAX_PAYLOAD];
        assert!(left.send(42, &data).1.is_ok());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), route.receiver.recv())
                .await
                .unwrap()
                .unwrap()
                .bytes,
            data
        );
        // 未注册会话的数据不会触发分配；IPv6 目标使用独立 IPv6 socket。
        assert!(left.send(99, b"unknown").1.is_ok());
        let echo = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let socket = origin("[::1]", echo.local_addr().unwrap().port())
            .await
            .unwrap();
        socket.send(b"v6").await.unwrap();
        let mut buffer = [0; 16];
        let (size, address) = echo.recv_from(&mut buffer).await.unwrap();
        echo.send_to(&buffer[..size], address).await.unwrap();
        assert_eq!(socket.recv(&mut buffer).await.unwrap(), 2);
        left.connection.close(0u32.into(), b"test complete");
        let _ = receive.await;
    }
    #[tokio::test]
    async fn quic_rejects_missing_device_certificate() {
        use crate::identity;
        let authority = identity::Authority::generate().unwrap();
        let server = quinn::Endpoint::server(
            server_config(&authority.server_config().unwrap()).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(identity::roots(&authority.ca_pem).unwrap())
            .with_no_client_auth();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_config(&tls).unwrap());
        let connecting = client
            .connect(server.local_addr().unwrap(), identity::SERVER_NAME)
            .unwrap();
        let (_, result) = tokio::join!(connecting, async { server.accept().await.unwrap().await });
        assert!(result.is_err());
    }
    #[test]
    fn reassembly_memory_is_bounded_and_session_removal_frees_it() {
        let mut r = Reassembly::default();
        let now = Instant::now();
        for message in 0..200 {
            let f = frames(1, message, &vec![1; MAX_PAYLOAD], 1200).unwrap();
            assert!(r.push(&f[0], now).is_none());
        }
        assert!(r.used <= BUFFER_BYTES);
        assert!(r.packets.len() < 200);
        r.remove(1);
        assert_eq!(r.used, 0);
        assert!(r.packets.is_empty());
    }
    #[test]
    fn datagrams_preserve_boundaries_and_deduplicate() {
        for size in [0, 1, 1200, MAX_PAYLOAD] {
            let data = vec![42; size];
            let frames = frames(1, 2, &data, 1200).unwrap();
            let mut reassembly = Reassembly::default();
            let now = Instant::now();
            let mut outputs = vec![];
            for frame in frames.iter().rev().chain(frames.iter()) {
                if let Some((_, p)) = reassembly.push(frame, now) {
                    outputs.push(p);
                }
            }
            assert_eq!(outputs, vec![data]);
            assert_eq!(reassembly.used, 0);
        }
    }
    #[test]
    fn missing_fragments_expire_and_invalid_lengths_are_rejected() {
        let mut r = Reassembly::default();
        let now = Instant::now();
        let f = frames(1, 1, &vec![7; 4000], 1200).unwrap();
        assert!(r.push(&f[0], now).is_none());
        assert!(r.used > 0);
        r.expire(now + EXPIRY);
        assert_eq!(r.used, 0);
        assert!(r.push(&[0; 19], now).is_none());
        assert!(frames(1, 1, &vec![0; MAX_PAYLOAD + 1], 1200).is_err());
    }
    #[test]
    fn shared_queue_budget_is_released_on_drop() {
        let budget = Budget::default();
        let mut packets = vec![];
        while let Some(p) = budget.packet(&vec![0; MAX_PAYLOAD]) {
            packets.push(p);
        }
        assert!(packets.len() < 130);
        drop(packets);
        assert!(budget.packet(&vec![0; MAX_PAYLOAD]).is_some());
    }
}
