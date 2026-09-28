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
    /// 新 Server 提供域名证书；缺省为旧版 CSR 流程，支持两端分别升级。
    #[serde(default)]
    pub domain_certificate: bool,
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
    DomainCertificate {
        service_id: String,
        revision: i64,
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
    /// 仅通过设备 mTLS 通道传输，不得记录或经管理 API 返回私钥。
    DomainCertificate {
        chain: String,
        key_pem: String,
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
    fn old_service_snapshot_uses_csr_instead_of_domain_certificate_request() {
        let service: super::Service = serde_json::from_value(serde_json::json!({
            "hostname":"emby.example.com", "ipv6":"2001:4860::1", "port":9444,
            "tunnel":{"tunnel_id":"media", "protocol":"https", "local_address":"127.0.0.1",
                "local_port":8096, "revision":1, "enabled":true}
        }))
        .unwrap();
        assert!(!service.domain_certificate);
    }

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
