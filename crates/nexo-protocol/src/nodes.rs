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
    /// 省略目标时保持旧版 Agent 穿透；反代由节点 Caddy 直接访问目标 URL。
    #[serde(default)]
    pub reverse_proxy_target: Option<String>,
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
    /// 缺省表示旧控制器；支持计量的控制器即使不限额也下发独立月周期。
    #[serde(default)]
    pub traffic_quota: Option<NodeQuota>,
    #[serde(default)]
    pub data_port: u16,
    pub services: Vec<Service>,
    pub agents: Vec<AgentIdentity>,
    pub accepting: bool,
}
/// 节点只持有额度策略；用量以控制器持久化的预算和累计结算为准。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeQuota {
    pub revision: i64,
    pub period_start: i64,
    pub period_end: i64,
    pub monthly_limit_bytes: Option<u64>,
    pub exhausted: bool,
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
        #[serde(default)]
        traffic_quota_supported: bool,
        /// 旧节点缺省为 false，控制器绝不向其下发直接回源服务。
        #[serde(default)]
        reverse_proxy_supported: bool,
        version: String,
        os: String,
        architecture: String,
        connections: u64,
        services: Vec<ServiceHealth>,
        update: UpdateReport,
    },
    Budget {
        request_id: u64,
        service_id: String,
        service_revision: i64,
        quota_revision: i64,
        month: i64,
        bytes: u32,
    },
    Usage {
        grant_id: String,
        to_origin: u64,
        to_public: u64,
        finished: bool,
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
    Budget {
        request_id: u64,
        grant_id: String,
        bytes: u64,
    },
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
