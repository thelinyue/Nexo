//! TLS、Yamux 与逻辑流之上的公网隧道实现占位。

/// 公网隧道协议类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelProtocol {
    Tcp,
    Http,
    Https,
}
