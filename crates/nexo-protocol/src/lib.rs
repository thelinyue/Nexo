//! Nexo Server 与 Agent 之间的 Tunnel 专用控制协议。
//!
//! 协议刻意只描述入网身份、心跳和 Tunnel Desired State，不携带路由
//! 控制平面概念。Agent 身份负责认证，
//! Tunnel 数据仍通过独立的 mTLS + Yamux 通道承载。

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
pub struct TunnelApplyResult {
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
        server_time: i64,
        #[serde(default)]
        tunnels: Vec<TunnelDesiredState>,
        #[serde(default)]
        tunnel_endpoint: Option<TunnelDataEndpoint>,
    },
    HeartbeatAck {
        server_time: i64,
        #[serde(default)]
        tunnels: Vec<TunnelDesiredState>,
        #[serde(default)]
        tunnel_endpoint: Option<TunnelDataEndpoint>,
    },
    TunnelApplyAccepted {
        #[serde(default)]
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
    pub csr_pem: Option<String>,
}

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
