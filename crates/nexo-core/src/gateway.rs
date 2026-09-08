use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// 网关能力当前是否可以由 Agent 应用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Ready,
    Unavailable,
}

/// 网关能力探测失败的结构化原因，供 Web 翻译成普通用户文案。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GatewayCapabilityReason {
    MissingNetAdmin,
    TunNotAvailable,
    IpForwardingDisabled,
    NoLocalSubnet,
    UnsupportedPlatform,
}

/// Agent 发现的一条本地直连网络。只有用户明确选择后才允许发布。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedLocalNetwork {
    pub interface_id: String,
    pub prefix: String,
    /// Agent 在该局域网接口上的观测地址；未取得地址时为空。
    /// 只用于网络诊断，普通子网共享使用 SNAT，不要求用户配置回程路由。
    #[serde(default)]
    pub gateway_address: Option<String>,
}

/// Agent 承载普通共享子网所需的环境能力报告。
///
/// 该报告只描述探测结果，不代表已经发布路由；发布仍必须经过服务端
/// Desired State、Agent Apply 和 Applied State 确认流程。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayCapabilityReport {
    pub platform: String,
    pub tun_available: bool,
    pub net_admin_available: bool,
    pub ipv4_forwarding: bool,
    pub ipv6_forwarding: bool,
    pub local_networks: Vec<DetectedLocalNetwork>,
    pub subnet_gateway: CapabilityState,
    pub subnet_gateway_reason: Option<GatewayCapabilityReason>,
}

/// 判断指定网段所需的地址族是否已经开启内核转发。
///
/// Tailscale 按实际广告路由的地址族检查转发能力；IPv4 与 IPv6 互不构成
/// 前置条件。调用方仍需单独校验 TUN、NET_ADMIN 和本地网段等基础能力。
pub fn forwarding_enabled_for_prefix(
    ipv4_forwarding: bool,
    ipv6_forwarding: bool,
    prefix: IpNet,
) -> bool {
    match prefix {
        IpNet::V4(_) => ipv4_forwarding,
        IpNet::V6(_) => ipv6_forwarding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_is_checked_per_address_family() {
        let ipv4: IpNet = "192.168.10.0/24".parse().unwrap();
        let ipv6: IpNet = "2001:db8:10::/64".parse().unwrap();

        assert!(forwarding_enabled_for_prefix(true, false, ipv4));
        assert!(!forwarding_enabled_for_prefix(true, false, ipv6));
        assert!(!forwarding_enabled_for_prefix(false, true, ipv4));
        assert!(forwarding_enabled_for_prefix(false, true, ipv6));
    }
}
