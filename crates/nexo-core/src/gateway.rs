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
    /// Agent 在该局域网接口上的地址，供静态路由引导显示下一跳。
    ///
    /// 旧 Agent 的能力报告没有这个字段，因此使用 `Option` 并允许反序列化缺省值；
    /// 地址缺失时 Nexo 只能提示用户自行确认下一跳，不能猜测或自动修改路由器。
    #[serde(default)]
    pub gateway_address: Option<String>,
}

/// Subnet Gateway 与 Site Gateway 的环境能力报告。
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
    pub site_gateway: CapabilityState,
    pub site_gateway_reason: Option<GatewayCapabilityReason>,
}
