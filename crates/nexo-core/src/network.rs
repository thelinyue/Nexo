use ipnet::IpNet;
use std::str::FromStr;
use thiserror::Error;

/// 发布局域网前的安全校验错误。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkError {
    #[error("不能发布未指定的网络地址")]
    Unspecified,
    #[error("不能发布默认路由")]
    DefaultRoute,
    #[error("不能发布回环或链路本地网络")]
    LocalOnly,
    #[error("不能发布组播网络")]
    Multicast,
    #[error("不能发布 Nexo 组网覆盖网段")]
    OverlayNetwork,
}

/// 校验用户从 Agent 网卡快照中选择的网络前缀。
///
/// V1 不接受任意手工输入的路由，只允许后续由接口快照证明其为直连网络。
pub fn validate_published_network(prefix: IpNet) -> Result<(), NetworkError> {
    let network = prefix.network();
    if prefix.prefix_len() == 0 {
        return Err(NetworkError::DefaultRoute);
    }
    if network.is_unspecified() {
        return Err(NetworkError::Unspecified);
    }
    let is_link_local = match network {
        std::net::IpAddr::V4(address) => address.is_link_local(),
        std::net::IpAddr::V6(address) => address.is_unicast_link_local(),
    };
    if network.is_loopback() || is_link_local {
        return Err(NetworkError::LocalOnly);
    }
    if network.is_multicast() {
        return Err(NetworkError::Multicast);
    }
    let tailscale_ipv4 = IpNet::from_str("100.64.0.0/10").expect("固定覆盖网段有效");
    let tailscale_ipv6 = IpNet::from_str("fd7a:115c:a1e0::/48").expect("固定覆盖网段有效");
    if networks_overlap(prefix, tailscale_ipv4) || networks_overlap(prefix, tailscale_ipv6) {
        return Err(NetworkError::OverlayNetwork);
    }
    Ok(())
}

fn networks_overlap(left: IpNet, right: IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        (IpNet::V6(left), IpNet::V6(right)) => {
            left.contains(&right.network()) || right.contains(&left.network())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn rejects_default_route() {
        let network = IpNet::from_str("0.0.0.0/0").unwrap();
        assert_eq!(
            validate_published_network(network),
            Err(NetworkError::DefaultRoute)
        );
    }

    #[test]
    fn rejects_ipv6_default_route() {
        let network = IpNet::from_str("::/0").unwrap();
        assert_eq!(
            validate_published_network(network),
            Err(NetworkError::DefaultRoute)
        );
    }

    #[test]
    fn accepts_private_lan() {
        let network = IpNet::from_str("192.168.10.0/24").unwrap();
        assert!(validate_published_network(network).is_ok());
    }
}
