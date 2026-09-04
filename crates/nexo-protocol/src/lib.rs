//! Server 与 Agent 之间的稳定协议边界。

use serde::{Deserialize, Serialize};

use nexo_core::{ApplyStatus, DeviceCapability, EnrollmentStatus, GatewayCapabilityReport};

/// Agent 向服务端报告的心跳消息。
///
/// 网关能力报告可选，便于旧 Agent 继续连接；新 Agent 会在每次心跳
/// 重新探测宿主机环境，避免服务端长期使用过期的能力快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub device_id: String,
    pub agent_version: String,
    #[serde(default)]
    pub gateway_report: Option<GatewayCapabilityReport>,
    /// 可选的当前组网身份；缺少时服务端继续使用已持久化身份，
    /// 但不会据此把设备重新绑定到另一个节点。
    #[serde(default)]
    pub mesh_identity: Option<MeshIdentityReport>,
}

/// Agent 启动时报告的能力，服务端据此决定可下发的配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapabilities {
    pub capabilities: Vec<DeviceCapability>,
    pub agent_version: String,
}

/// 服务端向 Agent 下发的期望配置版本。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesiredRevision {
    pub revision: i64,
    pub payload_json: String,
}

/// Agent 应用完成后的确认消息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyAck {
    pub revision: i64,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Agent 需要应用的一条网关路由。
///
/// `network_id` 始终指向 Nexo 自己的共享网络记录；站点互联场景另外带有
/// `site_link_id`，这样 Agent 不需要理解 Headscale 的节点或路由模型。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayDesiredRoute {
    pub network_id: String,
    pub site_link_id: Option<String>,
    pub prefix: String,
    pub revision: i64,
    /// 路由是否仍应保留；false 用于把之前发布的网段撤销。
    #[serde(default = "default_route_enabled")]
    pub enabled: bool,
}

/// 兼容旧 Agent：旧协议没有 enabled 字段时按“继续保留路由”处理。
fn default_route_enabled() -> bool {
    true
}

/// 服务端根据设备所属站点汇总出的网关 Desired State。
///
/// 该消息只表达“应该让设备可达哪些网段”，不携带 Tailscale/Headscale
/// 内部参数；真正的系统路由变更仍由 Agent 后续接入的适配器完成。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayDesiredState {
    pub revision: i64,
    pub routes: Vec<GatewayDesiredRoute>,
}

/// 服务端为已批准设备下发的一次性组网入网材料。
///
/// `auth_key` 只在已经建立的 mTLS 控制通道中短暂传递，Agent 不应写入日志；
/// 服务端数据库仅保存 `auth_key_id`，不会保存明文密钥。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshEnrollmentOffer {
    pub endpoint: String,
    pub auth_key: String,
    pub auth_key_id: String,
    pub hostname: String,
    /// 身份恢复时要求 Agent 清理本地旧组网状态；普通首次入网保持 false。
    #[serde(default)]
    pub reset: bool,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// Agent 上报的稳定组网身份。Node ID 是服务端绑定的唯一依据，地址和主机名
/// 仅用于运行状态展示及交叉校验，不能触发静默改绑。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshIdentityReport {
    pub node_id: Option<String>,
    pub hostname: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub online: bool,
}

/// 一条 Desired Route 的真实本地/远端应用结果。
///
/// `local_applied` 只有 Agent 实际执行 Tailscale 命令成功后才能为 true；
/// 生成计划或命令未启用时必须保持 false。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayRouteApplyResult {
    pub network_id: String,
    pub site_link_id: Option<String>,
    pub prefix: String,
    pub revision: i64,
    pub enabled: bool,
    pub local_applied: bool,
    #[serde(default)]
    pub control_plane_status: Option<String>,
    #[serde(default)]
    pub remote_applied: bool,
    #[serde(default)]
    pub error_message: Option<String>,
}

/// Agent 对每条路由的逐项确认。旧版 Agent 不发送此消息时，服务端保持
/// “需要升级/正在检查”状态，不会触发 Headscale 批准或 READY。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayRouteApplyReport {
    pub revision: i64,
    pub routes: Vec<GatewayRouteApplyResult>,
    #[serde(default)]
    pub mesh_identity: Option<MeshIdentityReport>,
}

/// Agent 对网关 Desired State 的应用确认。
///
/// V1 Agent 尚未接入 Tailscale 路由执行器时会返回 `checking`，并保持
/// `applied_network_ids` 为空；这表示配置已收到但没有伪造为已生效。
/// `network_ids` 用于让服务端只更新本次 ACK 对应的 Desired State，避免旧
/// revision 的确认覆盖后来创建的网络。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewayApplyAck {
    pub revision: i64,
    pub status: ApplyStatus,
    pub network_ids: Vec<String>,
    pub applied_network_ids: Vec<String>,
    pub error_message: Option<String>,
}

/// Agent 建立 mTLS 控制通道后发送的身份声明。
///
/// 设备证书才是认证依据；这里的 device_id 只用于服务端查找设备并校验
/// 证书指纹是否与已批准的设备身份匹配。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHello {
    pub device_id: String,
    pub agent_version: String,
    pub capabilities: Vec<DeviceCapability>,
    pub gateway_report: Option<GatewayCapabilityReport>,
    #[serde(default)]
    pub mesh_identity: Option<MeshIdentityReport>,
}

/// 控制通道上 Agent 可以发送的消息。使用显式 type 字段保持协议可扩展。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentControlMessage {
    Hello {
        device_id: String,
        agent_version: String,
        capabilities: Vec<DeviceCapability>,
        #[serde(default)]
        gateway_report: Option<GatewayCapabilityReport>,
        #[serde(default)]
        mesh_identity: Option<MeshIdentityReport>,
    },
    Heartbeat {
        device_id: String,
        agent_version: String,
        #[serde(default)]
        gateway_report: Option<GatewayCapabilityReport>,
        #[serde(default)]
        mesh_identity: Option<MeshIdentityReport>,
    },
    /// 组网入网结果；字段全部可选/可空以便服务端安全处理旧 Agent。
    MeshEnrollmentAck {
        auth_key_id: String,
        success: bool,
        #[serde(default)]
        identity: Option<MeshIdentityReport>,
        #[serde(default)]
        error_message: Option<String>,
    },
    /// 逐路由真实应用结果，替代旧版只汇报整体状态的 ACK。
    GatewayRouteApplyReport {
        report: GatewayRouteApplyReport,
    },
    GatewayApplyAck {
        ack: GatewayApplyAck,
    },
}

/// 服务端对控制通道消息的响应。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerControlMessage {
    HelloAccepted {
        server_time: i64,
        gateway_state: Option<GatewayDesiredState>,
        #[serde(default)]
        mesh_enrollment: Option<MeshEnrollmentOffer>,
        #[serde(default)]
        protocol_features: Vec<String>,
    },
    HeartbeatAck {
        server_time: i64,
        gateway_state: Option<GatewayDesiredState>,
        #[serde(default)]
        mesh_enrollment: Option<MeshEnrollmentOffer>,
        #[serde(default)]
        protocol_features: Vec<String>,
    },
    GatewayApplyAccepted {
        revision: i64,
    },
    Error {
        message: String,
    },
}

/// Agent 使用一次性凭证提交的入网请求。
///
/// Agent 上传的 CSR；服务端只使用其中已验证的公钥签发客户端证书，私钥不会上传。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollmentRequest {
    pub token: String,
    pub device_name: String,
    pub os: Option<String>,
    pub architecture: Option<String>,
    pub agent_version: String,
    pub capabilities: Vec<DeviceCapability>,
    pub csr_pem: Option<String>,
}

/// 服务端返回的入网处理结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollmentResponse {
    pub enrollment_id: String,
    pub status: EnrollmentStatus,
    pub device_id: Option<String>,
    pub server_endpoint: Option<String>,
    pub certificate_pem: Option<String>,
    pub ca_certificate_pem: Option<String>,
    pub message: String,
}

/// Agent 查询一次性入网请求的后续结果。
///
/// token 只作为领取批准结果的短期凭证使用；服务端在成功返回证书后立即
/// 将请求标记为 consumed，后续控制通道改用设备证书认证。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollmentPollRequest {
    pub token: String,
}

/// Agent 领取审批结果时服务端返回的身份材料。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollmentPollResponse {
    pub enrollment_id: String,
    pub status: EnrollmentStatus,
    pub device_id: Option<String>,
    pub certificate_pem: Option<String>,
    pub ca_certificate_pem: Option<String>,
    pub message: String,
}

/// 管理员批准设备后，服务端下发的身份材料。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentApproval {
    pub enrollment_id: String,
    pub device_id: String,
    pub certificate_pem: String,
    pub ca_certificate_pem: String,
    pub expires_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_control_messages_round_trip_without_losing_revision() {
        let desired = GatewayDesiredState {
            revision: 7,
            routes: vec![GatewayDesiredRoute {
                network_id: "network-a".to_owned(),
                site_link_id: Some("link-a-b".to_owned()),
                prefix: "192.168.20.0/24".to_owned(),
                revision: 7,
                enabled: true,
            }],
        };
        let response = ServerControlMessage::HelloAccepted {
            server_time: 123,
            gateway_state: Some(desired.clone()),
            mesh_enrollment: None,
            protocol_features: Vec::new(),
        };
        let encoded = serde_json::to_string(&response).expect("控制响应应能序列化");
        let decoded: ServerControlMessage =
            serde_json::from_str(&encoded).expect("控制响应应能反序列化");
        assert!(matches!(
            decoded,
            ServerControlMessage::HelloAccepted {
                gateway_state: Some(state),
                ..
            } if state == desired
        ));

        let ack = AgentControlMessage::GatewayApplyAck {
            ack: GatewayApplyAck {
                revision: 7,
                status: ApplyStatus::Checking,
                network_ids: vec!["network-a".to_owned()],
                applied_network_ids: Vec::new(),
                error_message: None,
            },
        };
        let encoded = serde_json::to_string(&ack).expect("网关 ACK 应能序列化");
        let decoded: AgentControlMessage =
            serde_json::from_str(&encoded).expect("网关 ACK 应能反序列化");
        assert!(matches!(
            decoded,
            AgentControlMessage::GatewayApplyAck { .. }
        ));
    }

    #[test]
    fn heartbeat_without_gateway_report_remains_compatible() {
        let message: AgentControlMessage = serde_json::from_str(
            r#"{"type":"heartbeat","device_id":"device-a","agent_version":"0.1.0"}"#,
        )
        .expect("旧 Agent 心跳格式应仍可解析");
        assert!(matches!(
            message,
            AgentControlMessage::Heartbeat {
                gateway_report: None,
                ..
            }
        ));
    }

    #[test]
    fn old_server_response_without_mesh_fields_remains_compatible() {
        let response: ServerControlMessage = serde_json::from_str(
            r#"{"type":"hello_accepted","server_time":1,"gateway_state":null}"#,
        )
        .expect("旧 Server 响应缺少组网字段时仍应可解析");
        assert!(matches!(
            response,
            ServerControlMessage::HelloAccepted {
                mesh_enrollment: None,
                protocol_features,
                ..
            } if protocol_features.is_empty()
        ));
    }

    #[test]
    fn old_gateway_report_without_local_address_remains_compatible() {
        let report: GatewayCapabilityReport = serde_json::from_str(
            r#"{
                "platform":"linux",
                "tun_available":true,
                "net_admin_available":true,
                "ipv4_forwarding":true,
                "ipv6_forwarding":true,
                "local_networks":[{"interface_id":"eth0","prefix":"192.168.10.0/24"}],
                "subnet_gateway":"ready",
                "subnet_gateway_reason":null,
                "site_gateway":"ready",
                "site_gateway_reason":null
            }"#,
        )
        .expect("旧版网关能力报告应仍可解析");
        assert_eq!(
            report.local_networks[0].gateway_address, None,
            "旧版报告缺少地址时不得猜测下一跳"
        );
    }
}
