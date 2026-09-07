//! Nexo 到 Headscale Policy 的显式 Grant 生成器。
//!
//! 输入以 tenant→tenant 为边界，即使阶段一只有 default tenant，也不使用
//! `* -> *` 或“无 Policy 默认全网互通”。输出是 Headscale 接受的 JSON/HUJSON
//! 子集，可直接通过官方 `/api/v1/policy` 接口更新。

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PolicyGrant {
    pub source_tenant: String,
    pub target_tenant: String,
    pub sources: Vec<String>,
    pub destinations: Vec<String>,
    /// 为空或包含 `*` 时允许目标上的所有协议/端口。
    pub protocols: Vec<String>,
    pub ports: Vec<String>,
    /// 是否同时生成一条 Tailscale SSH 接受规则。
    pub ssh: bool,
}

#[derive(Debug, Serialize)]
struct PolicyGrantDocument<'a> {
    src: &'a [String],
    dst: &'a [String],
    /// Grants 必须明确声明网络层能力；`*` 仅表示目标上的所有端口，
    /// 不等于开放未列出的源或目标。
    ip: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PolicySshGrantDocument<'a> {
    action: &'static str,
    src: &'a [String],
    dst: &'a [String],
    users: [&'static str; 1],
}

#[derive(Debug, Serialize)]
struct PolicyDocument<'a> {
    grants: Vec<PolicyGrantDocument<'a>>,
    ssh: Vec<PolicySshGrantDocument<'a>>,
}

fn grant_protocols(grant: &PolicyGrant) -> Vec<String> {
    let protocols: Vec<String> = grant
        .protocols
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| matches!(value.as_str(), "tcp" | "udp" | "icmp"))
        .collect();
    let ports: Vec<String> = grant
        .ports
        .iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect();
    if protocols.is_empty() || ports.is_empty() {
        return vec!["*".to_owned()];
    }
    if ports.iter().any(|port| port == "*") {
        return protocols
            .iter()
            .map(|protocol| format!("{protocol}:*"))
            .collect();
    }
    protocols
        .iter()
        .flat_map(|protocol| ports.iter().map(move |port| format!("{protocol}:{port}")))
        .collect()
}

/// 生成只包含显式 Grant 的最小策略文档。
pub fn generate_policy(grants: &[PolicyGrant]) -> String {
    let mut ssh = Vec::new();
    let grants = grants
        .iter()
        .filter(|grant| {
            !grant.source_tenant.trim().is_empty()
                && !grant.target_tenant.trim().is_empty()
                && !grant.sources.is_empty()
                && !grant.destinations.is_empty()
        })
        .map(|grant| {
            if grant.ssh {
                ssh.push(PolicySshGrantDocument {
                    action: "accept",
                    src: &grant.sources,
                    dst: &grant.destinations,
                    users: ["autogroup:nonroot"],
                });
            }
            PolicyGrantDocument {
                src: &grant.sources,
                dst: &grant.destinations,
                ip: grant_protocols(grant),
            }
        })
        .collect();
    serde_json::to_string_pretty(&PolicyDocument { grants, ssh }).expect("策略结构应始终可序列化")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_explicit_and_never_uses_global_wildcard() {
        let policy = generate_policy(&[PolicyGrant {
            source_tenant: "default".to_owned(),
            target_tenant: "default".to_owned(),
            sources: vec!["user:42".to_owned()],
            destinations: vec!["192.168.10.0/24".to_owned()],
            protocols: Vec::new(),
            ports: vec!["*".to_owned()],
            ssh: false,
        }]);
        assert!(policy.contains("user:42"));
        assert!(policy.contains("192.168.10.0/24"));
        assert!(policy.contains("\"ip\""));
        assert!(policy.contains("\"*\""));
    }

    #[test]
    fn empty_policy_is_not_allow_all() {
        assert_eq!(
            generate_policy(&[]),
            "{\n  \"grants\": [],\n  \"ssh\": []\n}"
        );
    }

    #[test]
    fn policy_restricts_protocol_and_port_without_widening_targets() {
        let policy = generate_policy(&[PolicyGrant {
            source_tenant: "owner".to_owned(),
            target_tenant: "guest".to_owned(),
            sources: vec!["nexo-guest@".to_owned()],
            destinations: vec!["100.64.0.8".to_owned()],
            protocols: vec!["tcp".to_owned()],
            ports: vec!["22".to_owned(), "443".to_owned()],
            ssh: true,
        }]);
        assert!(policy.contains("tcp:22"));
        assert!(policy.contains("tcp:443"));
        assert!(policy.contains("autogroup:nonroot"));
        assert!(!policy.contains("udp:22"));
    }

    #[test]
    fn wildcard_ports_stay_within_selected_protocols() {
        let policy = generate_policy(&[PolicyGrant {
            source_tenant: "owner".to_owned(),
            target_tenant: "owner".to_owned(),
            sources: vec!["nexo-owner@".to_owned()],
            destinations: vec!["100.64.0.8".to_owned()],
            protocols: vec!["tcp".to_owned()],
            ports: vec!["*".to_owned()],
            ssh: false,
        }]);
        assert!(policy.contains("tcp:*"));
        assert!(!policy.contains("\"*\""));
    }
}
