//! Nexo Server 与 Agent 之间的 Tunnel 专用控制协议。
//!
//! 协议刻意只描述入网身份、心跳和 Tunnel Desired State，不携带路由
//! 控制平面概念。Agent 身份负责认证，
//! TCP 数据通过 mTLS + Yamux 承载，UDP 数据通过独立 QUIC DATAGRAM 承载。

use nexo_core::EnrollmentStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHello {
    pub device_id: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub device_id: String,
    pub agent_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelDesiredState {
    pub tunnel_id: String,
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub origin_protocol: Option<String>,
    #[serde(default)]
    pub origin_tls_server_name: Option<String>,
    #[serde(default)]
    pub origin_tls_verification: Option<String>,
    #[serde(default)]
    pub origin_ca_pem: Option<String>,
    pub revision: i64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// 分协议应用结果；UDP 的 ready 只证明目标解析和 socket 配置成功，不证明应用健康。
pub struct ProtocolStatus {
    pub status: String,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelApplyResult {
    pub protocol_statuses: std::collections::BTreeMap<String, ProtocolStatus>,
    pub tunnel_id: String,
    pub revision: i64,
    pub applied: bool,
    pub status: String,
    #[serde(default)]
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelDataEndpoint {
    pub address: String,
    pub server_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentControlMessage {
    Hello {
        #[serde(default)]
        capabilities: Vec<String>,
        device_id: String,
        agent_version: String,
    },
    Heartbeat {
        device_id: String,
        agent_version: String,
    },
    TunnelApplyReport {
        results: Vec<TunnelApplyResult>,
    },
    RenewCertificate {
        csr_pem: String,
    },
    CertificateInstalled {
        certificate_pem: String,
    },
    CertificateRenewalFailed {
        error: String,
        next_retry_at: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerControlMessage {
    HelloAccepted {
        #[serde(default)]
        capabilities: Vec<String>,
        server_time: i64,
        tunnels: Vec<TunnelDesiredState>,
        #[serde(default)]
        tunnel_endpoint: Option<TunnelDataEndpoint>,
        #[serde(default)]
        udp_endpoint: Option<TunnelDataEndpoint>,
    },
    HeartbeatAck {
        #[serde(default)]
        capabilities: Vec<String>,
        server_time: i64,
        tunnels: Vec<TunnelDesiredState>,
        #[serde(default)]
        tunnel_endpoint: Option<TunnelDataEndpoint>,
        #[serde(default)]
        udp_endpoint: Option<TunnelDataEndpoint>,
    },
    TunnelApplyAccepted {
        tunnel_ids: Vec<String>,
    },
    CertificateRenewed {
        certificate_pem: String,
    },
    CertificateRenewalFailed {
        message: String,
        next_retry_at: i64,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollmentRequest {
    pub token: String,
    pub device_name: String,
    pub os: Option<String>,
    pub architecture: Option<String>,
    pub agent_version: String,
    pub csr_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollmentResponse {
    pub enrollment_id: String,
    pub status: EnrollmentStatus,
    pub device_id: Option<String>,
    pub certificate_pem: Option<String>,
    pub ca_certificate_pem: Option<String>,
    pub message: String,
}

/// 共享接入密钥只授权新设备注册；返回的独立身份用于后续 mTLS，不提供接管已有设备的参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRegistrationResponse {
    pub device_id: String,
    pub certificate_pem: String,
    pub ca_certificate_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollmentPollRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnrollmentPollResponse {
    pub enrollment_id: String,
    pub status: EnrollmentStatus,
    pub device_id: Option<String>,
    pub certificate_pem: Option<String>,
    pub ca_certificate_pem: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentApproval {
    pub enrollment_id: String,
    pub device_id: String,
    pub certificate_pem: String,
    pub ca_certificate_pem: String,
    pub expires_at: i64,
}

pub mod direct;
