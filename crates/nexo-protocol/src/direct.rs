//! IPv6 直连管理协议只承载配置、证书和小型认证请求，绝不承载应用媒体数据。
use serde::{Deserialize, Serialize};

pub const CAPABILITY: &str = "ipv6-direct-v1";
pub const ALPN: &[u8] = b"nexo-direct/1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    pub tunnel: crate::TunnelDesiredState,
    pub hostname: String,
    pub port: u16,
    pub ipv6: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub address: String,
    pub service_id: String,
    pub revision: i64,
    pub ready: bool,
    pub error: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Sync {
        addresses: Vec<String>,
        reports: Vec<Report>,
    },
    Certificate {
        service_id: String,
        revision: i64,
        csr_pem: String,
    },
    Access {
        service_id: String,
        revision: i64,
        path: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Services {
        services: Vec<Service>,
    },
    Certificate {
        chain: Option<String>,
        error: Option<String>,
        retry_at: Option<i64>,
    },
    Access {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Error {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    #[test]
    fn old_hello_and_server_snapshots_have_no_direct_capability() {
        let hello: crate::AgentControlMessage =
            serde_json::from_str(r#"{"type":"hello","device_id":"old","agent_version":"0.2.8"}"#)
                .unwrap();
        let crate::AgentControlMessage::Hello { capabilities, .. } = hello else {
            panic!()
        };
        assert!(capabilities.is_empty());
        let reply: crate::ServerControlMessage =
            serde_json::from_str(r#"{"type":"hello_accepted","server_time":0,"tunnels":[]}"#)
                .unwrap();
        let crate::ServerControlMessage::HelloAccepted { capabilities, .. } = reply else {
            panic!()
        };
        assert!(capabilities.is_empty());
    }
}
