//! 公网证书由 Server 完成 DNS-01；只接受服务精确主机名的 CSR，不接收 Agent 私钥。
use super::*;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use std::time::Duration;
use x509_parser::prelude::FromDer;

pub async fn request(
    state: &AppState,
    device: &str,
    service: &Service,
    csr: String,
) -> Result<DirectResponse> {
    anyhow::ensure!(csr.len() <= 16384, "证书请求过大");
    let parsed = rcgen::CertificateSigningRequestParams::from_pem(&csr).context("CSR 签名无效")?;
    anyhow::ensure!(
        parsed.params.subject_alt_names.len() == 1
            && matches!(&parsed.params.subject_alt_names[0],rcgen::SanType::DnsName(name) if name.as_str()==service.hostname),
        "CSR 必须且只能包含绑定服务的主机名"
    );
    // CA 同时校验 CN 与 SAN，不能把含库默认名称或其他域名的请求提交给 CA。
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr.as_bytes())?;
    let (_, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)?;
    anyhow::ensure!(
        request
            .certification_request_info
            .subject
            .iter_common_name()
            .all(|name| name.as_str().is_ok_and(|name| name == service.hostname)),
        "CSR Common Name 必须为空或与绑定服务主机名一致，请升级 Agent 后重试"
    );
    let id = &service.tunnel.tunnel_id;
    let (chain, retry, error, renew) = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        db.execute("INSERT INTO direct_certificates(service_id,device_id,hostname,csr) VALUES(?1,?2,?3,?4) ON CONFLICT(service_id) DO UPDATE SET device_id=excluded.device_id,hostname=excluded.hostname,csr=excluded.csr,chain=NULL,expires_at=NULL,renew_at=NULL,order_url=NULL,next_retry_at=0,error=NULL WHERE direct_certificates.device_id!=excluded.device_id OR direct_certificates.hostname!=excluded.hostname OR direct_certificates.csr!=excluded.csr",params![id,device,service.hostname,csr])?;
        db.query_row("SELECT CASE WHEN expires_at>?2 THEN chain ELSE NULL END,next_retry_at,error,COALESCE(renew_at,0)<=?2 FROM direct_certificates WHERE service_id=?1",params![id,unix_now()],|r|Ok((r.get::<_,Option<String>>(0)?,r.get::<_,i64>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,bool>(3)?)))?
    };
    if renew && retry <= unix_now() {
        let mut jobs = state.tunnel_runtime.direct.jobs.lock().await;
        if jobs.len() < 4 && jobs.insert(id.clone()) {
            let state = state.clone();
            let device = device.to_owned();
            let service = service.clone();
            let id = id.clone();
            tokio::spawn(async move {
                let result = tokio::time::timeout(
                    Duration::from_secs(900),
                    issue(&state, &device, &service, &csr),
                )
                .await
                .map_err(|_| anyhow::anyhow!("证书签发超时，将保留有效旧证书"))
                .and_then(|v| v);
                if let Err(error) = result {
                    let message = format!("证书签发未完成：{error}");
                    if let Ok(db) = state.db.lock() {
                        let _ = db.execute("UPDATE direct_certificates SET error=?1,next_retry_at=?2 WHERE service_id=?3 AND csr=?4",params![message,unix_now()+3600,id,csr]);
                    }
                }
                state.tunnel_runtime.direct.jobs.lock().await.remove(&id);
            });
        }
    }
    Ok(DirectResponse::Certificate {
        chain,
        error,
        retry_at: Some(retry.max(unix_now() + 15)),
    })
}

async fn account(state: &AppState) -> Result<Account> {
    let mut cached = state.tunnel_runtime.direct.account.lock().await;
    if let Some(account) = cached.as_ref() {
        return Ok(account.clone());
    }
    let path = state.data_dir.join("direct-acme-account.json");
    let account = match std::fs::read(&path) {
        Ok(bytes) => {
            let saved: serde_json::Value = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                saved["directory"].as_str() == Some(state.config.direct.acme_directory.as_str()),
                "ACME 目录与持久账户不一致，请恢复原目录或使用独立测试数据目录"
            );
            Account::builder()?
                .from_credentials(serde_json::from_value(saved)?)
                .await?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (account, credentials) = Account::builder()?
                .create(
                    &NewAccount {
                        contact: &[],
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    state.config.direct.acme_directory.clone(),
                    None,
                )
                .await?;
            nexo_tunnel::identity::write_private_file(&path, &serde_json::to_vec(&credentials)?)?;
            account
        }
        Err(error) => return Err(error.into()),
    };
    *cached = Some(account.clone());
    Ok(account)
}

async fn issue(state: &AppState, device: &str, service: &Service, csr: &str) -> Result<()> {
    let id = &service.tunnel.tunnel_id;
    let revision = service.tunnel.revision;
    super::service(state, device, id, revision)?;
    let account = account(state).await?;
    let domain = dns::domain_id(state, id)?;
    let zone = dns::zone(state, &domain).await?;
    let previous: Option<String> = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?
        .query_row(
            "SELECT order_url FROM direct_certificates WHERE service_id=?1 AND csr=?2",
            params![id, csr],
            |r| r.get(0),
        )?;
    let identifiers = [Identifier::Dns(service.hostname.clone())];
    let mut order = match previous {
        Some(url) => account.order(url).await?,
        None => account.new_order(&NewOrder::new(&identifiers)).await?,
    };
    if order.state().status == OrderStatus::Invalid {
        dns::withdraw(
            state,
            &zone,
            id,
            &format!("_acme-challenge.{}", service.hostname),
            "TXT",
        )
        .await?;
        order = account.new_order(&NewOrder::new(&identifiers)).await?;
    }
    state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE direct_certificates SET order_url=?1,next_retry_at=?2 WHERE service_id=?3 AND csr=?4",params![order.url(),unix_now()+3600,id,csr])?;
    let challenge_name = format!("_acme-challenge.{}", service.hostname);
    let mut authorizations = order.authorizations();
    while let Some(auth) = authorizations.next().await {
        let mut auth = auth?;
        if auth.status == AuthorizationStatus::Valid {
            continue;
        }
        anyhow::ensure!(
            auth.status == AuthorizationStatus::Pending,
            "证书域名验证失败"
        );
        let mut challenge = auth
            .challenge(ChallengeType::Dns01)
            .context("CA 不支持 DNS-01")?;
        let value = challenge.key_authorization().dns_value();
        super::service(state, device, id, revision)?;
        dns::ensure(state, &zone, id, &domain, &challenge_name, "TXT", &value).await?;
        // 等待 DNS 实际解析到本次值，而不是仅等待提供商 API 返回成功。
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
                super::service(state, device, id, revision)?;
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
                    return anyhow::Ok(());
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        })
        .await
        .context("DNS 验证记录传播超时")??;
        challenge.set_ready().await?;
    }
    let retry = RetryPolicy::new().timeout(Duration::from_secs(300));
    if matches!(
        order.state().status,
        OrderStatus::Pending | OrderStatus::Ready
    ) {
        anyhow::ensure!(
            order.poll_ready(&retry).await? == OrderStatus::Ready,
            "证书订单未就绪"
        );
        let csr_der = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            csr.lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<String>(),
        )?;
        super::service(state, device, id, revision)?;
        order.finalize_csr(&csr_der).await?;
    }
    let chain = order.poll_certificate(&retry).await?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain.as_bytes())
        .map_err(|_| anyhow::anyhow!("CA 返回的证书无效"))?;
    let cert = pem.parse_x509()?;
    let expires = cert.validity().not_after.timestamp();
    let start = cert.validity().not_before.timestamp();
    super::service(state, device, id, revision)?;
    state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE direct_certificates SET chain=?1,expires_at=?2,renew_at=?3,order_url=NULL,next_retry_at=0,error=NULL WHERE service_id=?4 AND csr=?5",params![chain,expires,expires-(expires-start)/3,id,csr])?;
    dns::withdraw(state, &zone, id, &challenge_name, "TXT").await?;
    Ok(())
}
