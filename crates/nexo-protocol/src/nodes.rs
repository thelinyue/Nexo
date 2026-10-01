//! VPS 节点协议。控制面只下发授权快照，节点不持有控制器 CA 私钥或 DNS 凭据。
use crate::TunnelDataEndpoint;
use serde::{Deserialize, Serialize};
pub const CAPABILITY: &str = "relay_nodes_v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentNode {
    pub id: String,
    pub endpoint: TunnelDataEndpoint,
    pub service_ids: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    pub id: String,
    pub tenant: String,
    pub device: String,
    pub revision: i64,
    pub protocol: String,
    pub port: u16,
    pub hostname: Option<String>,
    /// HTTP 入口及 HTTPS 跳转入口使用同一公网端口，旧快照默认 80。
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    pub https_port: u16,
    pub access_mode: String,
    pub http_redirect: bool,
    #[serde(default)]
    pub lan_redirect_url: Option<String>,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentIdentity {
    pub id: String,
    pub certificates: Vec<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    #[serde(default)]
    pub data_port: u16,
    pub services: Vec<Service>,
    pub agents: Vec<AgentIdentity>,
    pub accepting: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub id: String,
    pub revision: i64,
    pub ready: bool,
    pub error: Option<String>,
    /// 旧节点省略此字段时继续使用 TCP 检查，支持后不得因 HTTP/TLS 失败降级。
    #[serde(default)]
    pub public_probe_supported: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UpdateReport {
    pub task_id: Option<String>,
    pub stage: String,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Poll {
        version: String,
        os: String,
        architecture: String,
        connections: u64,
        services: Vec<ServiceHealth>,
        update: UpdateReport,
    },
    Access {
        request_id: u64,
        service_id: String,
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    State {
        snapshot: Snapshot,
        command: Option<UpdateCommand>,
    },
    Access {
        request_id: u64,
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    },
    Error {
        message: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateCommand {
    pub task_id: String,
    pub action: String,
    pub version: String,
    pub force: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Register {
    pub token: String,
    pub csr: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Registered {
    pub id: String,
    pub certificate: String,
    pub ca: String,
    pub control_endpoint: String,
    pub data_port: u16,
}

fn default_http_port() -> u16 {
    80
}
