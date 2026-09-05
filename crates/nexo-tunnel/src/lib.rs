//! Nexo 公网 Tunnel 的数据面协议基础。
//!
//! 数据通道固定为 TLS（由 Server/Agent 负责 mTLS）之上的 Yamux。Yamux
//! 负责多路复用，第一帧使用长度前缀 JSON 携带受限的 Tunnel/连接标识，
//! 后续字节原样转发到 Agent 本地 TCP 服务。这里不实现 UDP、TLS passthrough
//! 或应用层认证，避免把公网访问入口和网络组网边界混在一起。

use std::task::Poll;

use futures_util::future::poll_fn;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
pub const DEFAULT_MAX_STREAMS: usize = 128;
pub const DEFAULT_MAX_CONNECTION_WINDOW: usize = 64 * 1024 * 1024;

/// 公网访问模式；HTTP/HTTPS 的应用层终止由 Caddy 完成，数据面仍是 TCP。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProtocol {
    Tcp,
    Http,
    Https,
}

impl TunnelProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// Yamux 逻辑流建立后的首部；长度和字符集都在发送/接收两侧校验。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogicalStreamHeader {
    pub version: u8,
    pub tunnel_id: String,
    pub connection_id: String,
}

impl LogicalStreamHeader {
    pub fn new(
        tunnel_id: impl Into<String>,
        connection_id: impl Into<String>,
    ) -> Result<Self, HeaderError> {
        let header = Self {
            version: PROTOCOL_VERSION,
            tunnel_id: tunnel_id.into(),
            connection_id: connection_id.into(),
        };
        header.validate()?;
        Ok(header)
    }

    pub fn validate(&self) -> Result<(), HeaderError> {
        if self.version != PROTOCOL_VERSION {
            return Err(HeaderError::UnsupportedVersion(self.version));
        }
        validate_identifier("Tunnel ID", &self.tunnel_id)?;
        validate_identifier("连接 ID", &self.connection_id)?;
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HeaderError {
    #[error("Tunnel 协议版本不受支持：{0}")]
    UnsupportedVersion(u8),
    #[error("{0} 不能为空")]
    EmptyIdentifier(&'static str),
    #[error("{0} 过长")]
    IdentifierTooLong(&'static str),
    #[error("{0} 含有不安全字符")]
    InvalidIdentifier(&'static str),
    #[error("逻辑流首部超过限制")]
    TooLarge,
    #[error("逻辑流首部 JSON 无效")]
    InvalidJson,
}

fn validate_identifier(label: &'static str, value: &str) -> Result<(), HeaderError> {
    if value.is_empty() {
        return Err(HeaderError::EmptyIdentifier(label));
    }
    if value.len() > 256 {
        return Err(HeaderError::IdentifierTooLong(label));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(HeaderError::InvalidIdentifier(label));
    }
    Ok(())
}

/// 写入 u32 大端长度 + JSON 首部；不允许大于 8 KiB 的客户端首部。
pub async fn write_logical_header<W>(
    writer: &mut W,
    header: &LogicalStreamHeader,
) -> Result<(), HeaderError>
where
    W: AsyncWrite + Unpin,
{
    header.validate()?;
    let payload = serde_json::to_vec(header).map_err(|_| HeaderError::InvalidJson)?;
    if payload.len() > MAX_HEADER_BYTES {
        return Err(HeaderError::TooLarge);
    }
    writer
        .write_u32(payload.len() as u32)
        .await
        .map_err(|_| HeaderError::InvalidJson)?;
    writer
        .write_all(&payload)
        .await
        .map_err(|_| HeaderError::InvalidJson)?;
    writer.flush().await.map_err(|_| HeaderError::InvalidJson)
}

/// 读取并校验逻辑流首部；长度先验收，避免对端用大长度触发内存分配。
pub async fn read_logical_header<R>(reader: &mut R) -> Result<LogicalStreamHeader, HeaderError>
where
    R: AsyncRead + Unpin,
{
    let length = reader
        .read_u32()
        .await
        .map_err(|_| HeaderError::InvalidJson)? as usize;
    if length == 0 || length > MAX_HEADER_BYTES {
        return Err(HeaderError::TooLarge);
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|_| HeaderError::InvalidJson)?;
    let header: LogicalStreamHeader =
        serde_json::from_slice(&payload).map_err(|_| HeaderError::InvalidJson)?;
    header.validate()?;
    Ok(header)
}

/// 创建受限 Yamux 配置，给每条数据连接设置并发和窗口上限。
pub fn yamux_config() -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(DEFAULT_MAX_STREAMS);
    config.set_max_connection_receive_window(Some(DEFAULT_MAX_CONNECTION_WINDOW));
    config.set_split_send_size(16 * 1024);
    config
}

/// 把 Tokio TCP/TLS IO 转换为 Yamux 使用的 futures IO。
pub fn yamux_connection<T>(stream: T, mode: yamux::Mode) -> yamux::Connection<Compat<T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    yamux::Connection::new(stream.compat(), yamux_config(), mode)
}

/// 等待一个入站 Yamux 逻辑流。
pub async fn next_inbound<T>(
    connection: &mut yamux::Connection<T>,
) -> yamux::Result<Option<yamux::Stream>>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    poll_fn(|context| match connection.poll_next_inbound(context) {
        Poll::Ready(Some(Ok(stream))) => Poll::Ready(Ok(Some(stream))),
        Poll::Ready(Some(Err(error))) => Poll::Ready(Err(error)),
        Poll::Ready(None) => Poll::Ready(Ok(None)),
        Poll::Pending => Poll::Pending,
    })
    .await
}

/// 打开一个出站 Yamux 逻辑流；Yamux 自带的窗口更新提供背压。
pub async fn new_outbound<T>(connection: &mut yamux::Connection<T>) -> yamux::Result<yamux::Stream>
where
    T: futures_io::AsyncRead + futures_io::AsyncWrite + Unpin,
{
    poll_fn(|context| connection.poll_new_outbound(context)).await
}

/// 把 Yamux Stream 暴露为 Tokio IO，便于 `copy_bidirectional` 做半关闭转发。
pub fn into_tokio_io(stream: yamux::Stream) -> Compat<yamux::Stream> {
    stream.compat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn logical_header_round_trip_is_length_bounded() {
        let (mut left, mut right) = duplex(4096);
        let header = LogicalStreamHeader::new("tunnel-1", "conn-1").unwrap();
        let expected = header.clone();
        let writer = tokio::spawn(async move {
            write_logical_header(&mut left, &header).await.unwrap();
        });
        let decoded = read_logical_header(&mut right).await.unwrap();
        writer.await.unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn invalid_identifiers_are_rejected() {
        assert_eq!(
            LogicalStreamHeader::new("", "connection").unwrap_err(),
            HeaderError::EmptyIdentifier("Tunnel ID")
        );
        assert_eq!(
            LogicalStreamHeader::new("tunnel/1", "connection").unwrap_err(),
            HeaderError::InvalidIdentifier("Tunnel ID")
        );
    }

    #[test]
    fn protocol_names_are_stable() {
        assert_eq!(TunnelProtocol::Tcp.as_str(), "tcp");
        assert_eq!(TunnelProtocol::Https.as_str(), "https");
    }
}
