//! 每个多节点服务使用精确 SAN 证书，私钥保存在控制器私有文件；绝不分发覆盖其他主机的泛域名私钥。
use super::*;
use instant_acme::{
    AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy,
};
use std::time::Duration;
pub async fn ensure(state: &AppState, id: &str) -> Result<()> {
    let (host, due) = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let host:Option<String>=db.query_row("SELECT t.hostname||'.'||p.domain FROM tunnels t JOIN public_domains p ON p.id=t.public_domain_id WHERE t.id=?1 AND t.protocol='https' AND t.enabled=1 AND t.deleted_at IS NULL AND EXISTS(SELECT 1 FROM service_nodes s WHERE s.service_id=t.id AND s.node_id!='local')",[id],|r|r.get(0)).optional()?;
        let Some(host) = host else {
            return Ok(());
        };
        db.execute("INSERT INTO relay_certificates(service_id,hostname) VALUES(?1,?2) ON CONFLICT(service_id) DO UPDATE SET hostname=excluded.hostname,chain=NULL,expires_at=NULL,retry_at=0,error=NULL WHERE hostname!=excluded.hostname",params![id,host])?;
        let due:bool=db.query_row("SELECT COALESCE(expires_at,0)<?2 AND retry_at<=?3 FROM relay_certificates WHERE service_id=?1",params![id,unix_now()+30*86400,unix_now()],|r|r.get(0))?;
        (host, due)
    };
    if !due {
        return Ok(());
    }
    let mut jobs = state.tunnel_runtime.direct.jobs.lock().await;
    if jobs.len() >= 4 || !jobs.insert(id.to_owned()) {
        return Ok(());
    }
    let state = state.clone();
    let id = id.to_owned();
    tokio::spawn(async move {
        let result = issue(&state, &id, &host).await;
        if let Err(error) = result {
            if let Ok(db) = state.db.lock() {
                let _ = db.execute(
                    "UPDATE relay_certificates SET retry_at=?2,error=?3 WHERE service_id=?1",
                    params![id, unix_now() + 3600, error.to_string()],
                );
            }
        }
        state.tunnel_runtime.direct.jobs.lock().await.remove(&id);
    });
    Ok(())
}
async fn issue(state: &AppState, id: &str, host: &str) -> Result<()> {
    let key_path = state
        .data_dir
        .join("nodes/certificates")
        .join(id)
        .join("key.pem");
    let key = if key_path.exists() {
        rcgen::KeyPair::from_pem(&fs::read_to_string(&key_path)?)?
    } else {
        let key = rcgen::KeyPair::generate()?;
        nexo_tunnel::identity::write_private_file(&key_path, key.serialize_pem().as_bytes())?;
        key
    };
    let mut params = rcgen::CertificateParams::new(vec![host.to_owned()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key)?;
    let account = crate::direct::certificates::account(state).await?;
    let domain = crate::direct::dns::domain_id(state, id)?;
    let zone = crate::direct::dns::zone(state, &domain).await?;
    let ids = [Identifier::Dns(host.to_owned())];
    let mut order = account.new_order(&NewOrder::new(&ids)).await?;
    let challenge_name = format!("_acme-challenge.{host}");
    let result = tokio::time::timeout(Duration::from_secs(900), async {
        let mut authorizations = order.authorizations();
        while let Some(auth) = authorizations.next().await {
            let mut auth = auth?;
            if auth.status == AuthorizationStatus::Valid {
                continue;
            }
            anyhow::ensure!(
                auth.status == AuthorizationStatus::Pending,
                "节点证书授权失败"
            );
            let mut challenge = auth
                .challenge(ChallengeType::Dns01)
                .context("CA 不支持 DNS 验证")?;
            let value = challenge.key_authorization().dns_value();
            crate::direct::dns::ensure(state, &zone, id, &domain, &challenge_name, "TXT", &value)
                .await?;
            let (resolvers, delay, timeout) = {
                let db = state
                    .db
                    .lock()
                    .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                let root: String = db.query_row(
                    "SELECT domain FROM public_domains WHERE id=?1",
                    [&domain],
                    |r| r.get(0),
                )?;
                let options = crate::domains::load(&db, &domain, &root)
                    .map_err(|e| anyhow::anyhow!(e.message))?;
                (
                    options.dns.dns_resolvers,
                    options.dns.dns_propagation_delay_seconds.unwrap_or(0),
                    options.dns.dns_propagation_timeout_seconds.unwrap_or(300),
                )
            };
            if delay > 0 {
                tokio::time::sleep(Duration::from_secs(delay.into())).await;
            }
            let mut config = hickory_resolver::config::ResolverConfig::new();
            for address in resolvers {
                let address: std::net::SocketAddr = address.parse().or_else(|_| {
                    address
                        .parse::<std::net::IpAddr>()
                        .map(|ip| std::net::SocketAddr::new(ip, 53))
                })?;
                config.add_name_server(hickory_resolver::config::NameServerConfig::new(
                    address,
                    hickory_resolver::config::Protocol::Udp,
                ));
            }
            let resolver = if config.name_servers().is_empty() {
                hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()?
            } else {
                hickory_resolver::TokioAsyncResolver::tokio(config, Default::default())
            };
            tokio::time::timeout(Duration::from_secs(timeout.into()), async {
                loop {
                    resolver.clear_cache();
                    if resolver
                        .txt_lookup(&challenge_name)
                        .await
                        .is_ok_and(|lookup| {
                            lookup
                                .iter()
                                .any(|txt| txt.txt_data().concat() == value.as_bytes())
                        })
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            })
            .await
            .context("节点证书 DNS 验证传播超时")?;
            challenge.set_ready().await?;
        }
        let retry = RetryPolicy::new().timeout(Duration::from_secs(300));
        anyhow::ensure!(
            order.poll_ready(&retry).await? == OrderStatus::Ready,
            "节点证书订单未就绪"
        );
        order.finalize_csr(csr.der()).await?;
        anyhow::Ok(order.poll_certificate(&retry).await?)
    })
    .await
    .map_err(|_| anyhow::anyhow!("节点证书签发超时"))
    .and_then(|v| v);
    let cleanup = crate::direct::dns::withdraw(state, &zone, id, &challenge_name, "TXT").await;
    let chain = result?;
    cleanup?;
    let expiry = nexo_tunnel::identity::validate_https_certificate(
        &chain,
        &key.serialize_pem(),
        host,
        unix_now(),
    )?;
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    db.execute("UPDATE relay_certificates SET chain=?3,expires_at=?4,retry_at=0,error=NULL WHERE service_id=?1 AND hostname=?2",params![id,host,chain,expiry])?;
    Ok(())
}
pub fn material(
    state: &AppState,
    db: &Connection,
    id: &str,
    host: &str,
) -> Result<Option<(String, String)>> {
    let chain:Option<String>=db.query_row("SELECT chain FROM relay_certificates WHERE service_id=?1 AND hostname=?2 AND expires_at>?3",params![id,host,unix_now()],|r|r.get(0)).optional()?.flatten();
    let Some(chain) = chain else {
        return Ok(None);
    };
    let key = fs::read_to_string(
        state
            .data_dir
            .join("nodes/certificates")
            .join(id)
            .join("key.pem"),
    )?;
    nexo_tunnel::identity::validate_https_certificate(&chain, &key, host, unix_now())?;
    Ok(Some((chain, key)))
}
