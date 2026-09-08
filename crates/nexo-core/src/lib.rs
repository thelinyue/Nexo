//! Nexo 的领域模型与业务规则。

mod enrollment;
mod gateway;
mod network;

pub use enrollment::{EnrollmentError, EnrollmentStatus, EnrollmentToken, PendingEnrollment};
pub use gateway::{
    forwarding_enabled_for_prefix, CapabilityState, DetectedLocalNetwork, GatewayCapabilityReason,
    GatewayCapabilityReport,
};
pub use network::{validate_published_network, NetworkError};
use serde::{Deserialize, Serialize};

/// 配置应用状态，明确区分期望状态和实际状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus {
    Disabled,
    Checking,
    Applying,
    Ready,
    Retrying,
    Failed,
}

/// 设备能力集合。底层能力会在 UI 中转换为普通用户能理解的名称。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceCapability {
    Tunnel,
    Mesh,
    SubnetGateway,
}

/// 设备在 Nexo 管理界面的用户可见状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Pending,
    Offline,
    Online,
    Degraded,
}

/// 网络地址族，状态和路由均按地址族独立记录。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

/// 工作空间中由用户明确选择、设备承载的局域网。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteNetwork {
    pub id: String,
    pub tenant_id: String,

    pub name: String,
    pub publisher_device_id: String,
    pub interface_id: String,
    pub family: AddressFamily,
    pub prefix: String,
    pub enabled: bool,
}

/// 配置应用的三态结果，避免数据库状态与 Agent 实际状态混淆。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    pub revision: i64,
    pub status: ApplyStatus,
    pub error_message: Option<String>,
}
