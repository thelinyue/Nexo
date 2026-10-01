//! 公网检查只验证指定节点的业务入口；回源连通仍使用 Agent 的受认证报告。
//! 不访问应用接口、不跟随重定向，也不以其他节点或 NAS 的 DNS 结果替代目标地址。
use super::*;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

pub const PROBE_PATH: &str = "/.nexo-relay/probe";

/// 回显配置标识用于识别错端口、错路由和迟到的 Caddy 配置，不包含身份凭据。
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProbeIdentity {
    pub node_id: String,
    pub service_id: String,
    pub revision: i64,
}

pub fn route(host: &str, node: &str, service: &str, revision: i64) -> Value {
    let body = json!({"node_id":node,"service_id":service,"revision":revision}).to_string();
    json!({"match":[{"host":[host],"path":[PROBE_PATH],"method":["GET"]}],"handle":[{"handler":"static_response","status_code":200,"body":body,"headers":{"Content-Type":["application/json"],"Cache-Control":["no-store"]}}],"terminal":true})
}

/// 一个探测目标绑定节点地址及服务版本；网络等待后的结果必须再次核对这些字段。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub node: String,
    pub address: String,
    pub kind: String,
}

pub async fn probe(
    target: &Target,
    host: &str,
    port: u16,
    service: &str,
    revision: i64,
) -> Result<()> {
    probe_with_roots(target, host, port, service, revision, &[]).await
}

// 生产入口固定使用默认 CA 信任；本机 Caddy 测试显式注入内部 CA，绝不关闭证书校验。
pub(crate) async fn probe_with_roots(
    target: &Target,
    host: &str,
    port: u16,
    service: &str,
    revision: i64,
    roots: &[reqwest::Certificate],
) -> Result<()> {
    let operation = async {
        anyhow::ensure!(!target.address.is_empty(), "请配置节点公网 IPv4");
        let ip: Ipv4Addr = target
            .address
            .parse()
            .context("公网入口不是有效 IPv4 地址")?;
        if target.kind == "tcp" {
            tokio::net::TcpStream::connect((ip, port))
                .await
                .context("公网 TCP 入口连接失败")?;
            return Ok(());
        }
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .resolve(host, SocketAddr::new(ip.into(), port));
        for root in roots {
            builder = builder.add_root_certificate(root.clone());
        }
        let mut url = reqwest::Url::parse(&format!("{}://{host}{PROBE_PATH}", target.kind))?;
        url.set_port(Some(port))
            .map_err(|_| anyhow::anyhow!("公网探测端口无效"))?;
        let mut response = builder
            .build()?
            .get(url)
            .send()
            .await
            .context("入口检查失败，请核对端口和证书")?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::OK,
            "公网探测入口返回 {}，未确认服务",
            response.status().as_u16()
        );
        anyhow::ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= 1024),
            "公网探测响应超过 1 KiB"
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.context("公网探测响应读取失败")? {
            anyhow::ensure!(body.len() + chunk.len() <= 1024, "公网探测响应超过 1 KiB");
            body.extend_from_slice(&chunk);
        }
        let found: ProbeIdentity = serde_json::from_slice(&body).context("公网探测响应格式无效")?;
        anyhow::ensure!(
            found
                == ProbeIdentity {
                    node_id: target.node.clone(),
                    service_id: service.into(),
                    revision
                },
            "公网探测节点、服务或配置版本不匹配"
        );
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(3), operation)
        .await
        .context("公网入口检查超时（3 秒）")?
}

/// 地址、检查方式、版本或样本有效期变化时重新累计，不能继承 TCP 检查的健康状态。
pub fn record(
    db: &Connection,
    target: &Target,
    service: &str,
    revision: i64,
    error: Option<&str>,
    now: i64,
) -> Result<()> {
    db.execute("INSERT INTO relay_public_health(node_id,service_id,revision,successes,failures,checked_at,probe_kind,address,error)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
        ON CONFLICT(node_id,service_id) DO UPDATE SET
        healthy=CASE WHEN revision!=excluded.revision OR probe_kind!=excluded.probe_kind OR address!=excluded.address OR checked_at<=excluded.checked_at-45 THEN 0 ELSE healthy END,
        successes=CASE WHEN excluded.successes=1 THEN CASE WHEN revision=excluded.revision AND probe_kind=excluded.probe_kind AND address=excluded.address AND checked_at>excluded.checked_at-45 THEN MIN(successes+1,3) ELSE 1 END ELSE 0 END,
        failures=CASE WHEN excluded.failures=1 THEN CASE WHEN revision=excluded.revision AND probe_kind=excluded.probe_kind AND address=excluded.address AND checked_at>excluded.checked_at-45 THEN MIN(failures+1,3) ELSE 1 END ELSE 0 END,
        revision=excluded.revision,checked_at=excluded.checked_at,probe_kind=excluded.probe_kind,address=excluded.address,error=excluded.error",
        params![target.node,service,revision,error.is_none() as i64,error.is_some() as i64,now,target.kind,target.address,error])?;
    db.execute("UPDATE relay_public_health SET healthy=CASE WHEN successes>=3 THEN 1 WHEN failures>=3 THEN 0 ELSE healthy END WHERE node_id=?1 AND service_id=?2",params![target.node,service])?;
    Ok(())
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
