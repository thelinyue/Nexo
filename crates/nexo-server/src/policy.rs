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
}

#[derive(Debug, Serialize)]
struct PolicyDocument<'a> {
    grants: Vec<PolicyGrantDocument<'a>>,
}

#[derive(Debug, Serialize)]
struct PolicyGrantDocument<'a> {
    src: &'a [String],
    dst: &'a [String],
    /// Grants 必须明确声明网络层能力；`*` 仅表示目标上的所有端口，
    /// 不等于开放未列出的源或目标。
    ip: [&'static str; 1],
}

/// 生成只包含显式 Grant 的最小策略文档。
pub fn generate_policy(grants: &[PolicyGrant]) -> String {
    let grants = grants
        .iter()
        .filter(|grant| {
            !grant.source_tenant.trim().is_empty()
                && !grant.target_tenant.trim().is_empty()
                && !grant.sources.is_empty()
                && !grant.destinations.is_empty()
        })
        .map(|grant| PolicyGrantDocument {
            src: &grant.sources,
            dst: &grant.destinations,
            ip: ["*"],
        })
        .collect();
    serde_json::to_string_pretty(&PolicyDocument { grants }).expect("策略结构应始终可序列化")
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
        }]);
        assert!(policy.contains("user:42"));
        assert!(policy.contains("192.168.10.0/24"));
        assert!(policy.contains("\"ip\""));
        assert!(policy.contains("\"*\""));
    }

    #[test]
    fn empty_policy_is_not_allow_all() {
        assert_eq!(generate_policy(&[]), "{\n  \"grants\": []\n}");
    }
}
