//! DNS 写入前保存原值与意图，重启后按记录 ID/精确内容继续；停用不删除 IPv4 入口。
use super::*;
use crate::dns_provider::{Record, Zone};

pub async fn zone(state: &AppState, domain_id: &str) -> Result<Zone> {
    #[cfg(test)]
    if let Some(zone) = state.tunnel_runtime.direct.test_zone.lock().await.clone() {
        return Ok(zone);
    }
    let (credential, domain) = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let credential = crate::dns_provider::load(
            &db,
            &state
                .domain_runtime
                .supervisor
                .config()
                .cloudflare_token_root,
            domain_id,
        )?;
        let domain: String = db.query_row(
            "SELECT domain FROM public_domains WHERE id=?1",
            [domain_id],
            |r| r.get(0),
        )?;
        (credential, domain)
    };
    Zone::discover(credential, &domain).await
}

pub fn domain_id(state: &AppState, id: &str) -> Result<String> {
    Ok(state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?
        .query_row(
            "SELECT public_domain_id FROM tunnels WHERE id=?1",
            [id],
            |r| r.get(0),
        )?)
}

/// 首次只接管匹配 Server 的访问记录；TXT 可以与其他签发任务的值共存。
pub async fn ensure(
    state: &AppState,
    zone: &Zone,
    service_id: &str,
    domain_id: &str,
    host: &str,
    kind: &str,
    value: &str,
) -> Result<()> {
    let _guard = state.tunnel_runtime.direct.dns_lock.lock().await;
    let records = zone.records(host).await?;
    anyhow::ensure!(
        !records.iter().any(|r| r.kind == "CNAME" || r.proxied),
        "DNS 存在 CNAME 或代理记录，请先改为直接解析"
    );
    let journal: Option<(Option<String>,Option<String>,String)> = state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.query_row("SELECT original,written,intended FROM direct_dns_records WHERE service_id=?1 AND hostname=?2 AND kind=?3",params![service_id,host,kind],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let mut expected: Option<Record> = None;
    if let Some((_, written, intended)) = &journal {
        expected = written
            .as_ref()
            .map(|v| serde_json::from_str(v))
            .transpose()?;
        if let Some(previous) = &expected {
            let found = records
                .iter()
                .find(|r| r.id == previous.id)
                .context("受管 DNS 记录已被外部删除，请核对后重新配置")?;
            let interrupted = Record {
                value: intended.clone(),
                ..previous.clone()
            };
            anyhow::ensure!(
                found == previous || found == &interrupted,
                "受管 DNS 记录已被外部修改，未覆盖"
            );
            expected = Some(found.clone());
        } else {
            let matches = records
                .iter()
                .filter(|r| r.kind == kind && r.value == *intended)
                .collect::<Vec<_>>();
            anyhow::ensure!(matches.len() <= 1, "DNS 写入恢复存在歧义，请人工核对");
            expected = matches.first().map(|r| (*r).clone());
        }
    } else if kind != "TXT" {
        let matches = records
            .iter()
            .filter(|r| r.kind == kind)
            .collect::<Vec<_>>();
        anyhow::ensure!(matches.len() <= 1, "此主机名存在多条访问记录，请先核对");
        expected = matches.first().map(|r| (*r).clone());
        if let Some(record) = &expected {
            let mut servers = state
                .security
                .settings()
                .map_err(|e| anyhow::anyhow!(e.message))?
                .public_ips;
            if let Some(ip) = state.config.direct.relay_ipv4 {
                servers.push(ip.into());
            }
            anyhow::ensure!(
                record
                    .value
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|v| servers.contains(&v)),
                "现有访问记录不属于已配置的 Server，未覆盖"
            );
        }
    }
    if kind != "TXT" {
        anyhow::ensure!(
            !records
                .iter()
                .any(|r| r.kind == kind && expected.as_ref().is_none_or(|e| e.id != r.id)),
            "此主机名新增了外部访问记录，未覆盖"
        );
    }
    if journal.is_none() {
        state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.execute("INSERT INTO direct_dns_records(service_id,domain_id,hostname,kind,original,written,intended) VALUES(?1,?2,?3,?4,?5,?5,?6)",params![service_id,domain_id,host,kind,expected.as_ref().map(serde_json::to_string).transpose()?,value])?;
    } else {
        state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE direct_dns_records SET intended=?1 WHERE service_id=?2 AND hostname=?3 AND kind=?4",params![value,service_id,host,kind])?;
    }
    let desired = match expected {
        Some(record) => Record {
            value: value.into(),
            ..record
        },
        None => Record {
            id: String::new(),
            name: host.into(),
            kind: kind.into(),
            value: value.into(),
            ttl: 600,
            proxied: false,
        },
    };
    let written = if records.iter().any(|r| r == &desired) {
        desired
    } else {
        zone.write(&desired).await?
    };
    state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE direct_dns_records SET written=?1 WHERE service_id=?2 AND hostname=?3 AND kind=?4",params![serde_json::to_string(&written)?,service_id,host,kind])?;
    Ok(())
}

pub async fn withdraw(
    state: &AppState,
    zone: &Zone,
    id: &str,
    host: &str,
    kind: &str,
) -> Result<()> {
    let _guard = state.tunnel_runtime.direct.dns_lock.lock().await;
    let row: Option<(Option<String>,Option<String>,String)> = state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.query_row("SELECT original,written,intended FROM direct_dns_records WHERE service_id=?1 AND hostname=?2 AND kind=?3",params![id,host,kind],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let Some((original, written, intended)) = row else {
        return Ok(());
    };
    let records = zone.records(host).await?;
    let written: Option<Record> = written.map(|v| serde_json::from_str(&v)).transpose()?;
    let original: Option<Record> = original.map(|v| serde_json::from_str(&v)).transpose()?;
    let found = if let Some(written) = &written {
        let found = records.iter().find(|r| r.id == written.id);
        if let Some(found) = found {
            // 上一轮已恢复原值但尚未清理日志，重试只删除日志。
            if original.as_ref() == Some(found) {
                None
            } else {
                let interrupted = Record {
                    value: intended.clone(),
                    ..written.clone()
                };
                anyhow::ensure!(
                    found == written || found == &interrupted,
                    "DNS 已被外部修改，未撤销"
                );
                Some(found)
            }
        } else {
            None
        }
    } else {
        let matches = records
            .iter()
            .filter(|r| r.kind == kind && r.value == intended)
            .collect::<Vec<_>>();
        anyhow::ensure!(matches.len() <= 1, "DNS 清理恢复存在歧义");
        matches.first().copied()
    };
    if let Some(found) = found {
        if let Some(original) = original {
            zone.write(&Record {
                id: found.id.clone(),
                ..original
            })
            .await?;
        } else {
            zone.remove(found).await?;
        }
    }
    state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?
        .execute(
            "DELETE FROM direct_dns_records WHERE service_id=?1 AND hostname=?2 AND kind=?3",
            params![id, host, kind],
        )?;
    Ok(())
}

pub async fn run(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
    loop {
        tokio::select! {
            _ = state.tunnel_runtime.stop.cancelled()=>break,
            _ = interval.tick()=>{
                if let Err(error) = reconcile(&state).await {tracing::warn!("直连 DNS 协调失败，将重试：{error}");}
            }
        }
    }
}
pub async fn reconcile(state: &AppState) -> Result<()> {
    let rows = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut query = db.prepare("SELECT t.id,t.device_id,t.apply_revision FROM tunnels t WHERE t.ipv6_direct_enabled=1 AND t.enabled=1 AND t.deleted_at IS NULL")?;
        let rows = query
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let mut active = HashSet::new();
    for (id, device, revision) in rows {
        let Ok(service) = service(state, &device, &id, revision) else {
            continue;
        };
        let ready: bool = state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.query_row("SELECT EXISTS(SELECT 1 FROM direct_services s JOIN direct_certificates c ON c.service_id=s.service_id WHERE s.service_id=?1 AND s.revision=?2 AND s.ready=1 AND s.reported_at>?3 AND c.expires_at>?4 AND c.device_id=?5 AND c.hostname=?6)",params![id,revision,unix_now()-45,unix_now(),device,service.hostname],|r|r.get(0))?;
        if !ready {
            continue;
        }
        active.insert((id.clone(), service.hostname.clone()));
        let result = async {
            let domain = domain_id(state, &id)?;
            let zone = zone(state, &domain).await?;
            let ipv4 = state
                .config
                .direct
                .relay_ipv4
                .map(std::net::IpAddr::V4)
                .or_else(|| {
                    state
                        .security
                        .settings()
                        .ok()?
                        .public_ips
                        .into_iter()
                        .find(|ip| ip.is_ipv4())
                })
                .context("请在 Server 的 [direct].relay_ipv4 填写用于转发的公网 IPv4")?
                .to_string();
            ensure(state, &zone, &id, &domain, &service.hostname, "A", &ipv4).await?;
            // 网络请求期间配置可能已被撤销；在写 AAAA 前再次核验当前版本。
            super::service(state, &device, &id, revision)?;
            ensure(
                state,
                &zone,
                &id,
                &domain,
                &service.hostname,
                "AAAA",
                &service.ipv6,
            )
            .await?;
            anyhow::Ok(())
        }
        .await;
        let error = result.err().map(|e| e.to_string());
        state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE direct_services SET dns_error=?1,published_address=CASE WHEN ?1 IS NULL THEN ?2 ELSE published_address END WHERE service_id=?3",params![error,service.ipv6,id])?;
        if state.config.direct.probe_enabled {
            let due = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?
                .query_row(
                    "SELECT COALESCE(probed_at,0)<?2 FROM direct_services WHERE service_id=?1",
                    params![id, unix_now() - 30],
                    |r| r.get::<_, bool>(0),
                )?;
            if due {
                let result = probe(&service).await;
                let error = result.err().map(|e| e.to_string());
                state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE direct_services SET probe_status=?1,probe_error=?2,probed_at=?3 WHERE service_id=?4",params![if error.is_none(){"verified"}else{"unverified"},error,unix_now(),id])?;
            }
        }
    }
    let journals = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut query = db.prepare(
            "SELECT service_id,domain_id,hostname FROM direct_dns_records WHERE kind='AAAA'",
        )?;
        let rows = query
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (id, domain, host) in journals {
        if active.contains(&(id.clone(), host.clone())) {
            continue;
        }
        let result = async {
            let zone = zone(state, &domain).await?;
            withdraw(state, &zone, &id, &host, "AAAA").await
        }
        .await;
        let error = result.err().map(|e| e.to_string());
        if let Some(error) = &error {
            tracing::warn!(service_id=%id,"直连 AAAA 清理未完成，将重试：{error}");
        }
        state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE direct_services SET dns_error=?1,published_address=CASE WHEN ?1 IS NULL THEN NULL ELSE published_address END WHERE service_id=?2",params![error,id])?;
    }
    // 签发失败、超时或重启留下的 TXT 与活动任务分开清理，不能删除其他 ACME 客户端的值。
    let leftovers = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut query = db.prepare(
            "SELECT service_id,domain_id,hostname FROM direct_dns_records WHERE kind='TXT'",
        )?;
        let rows = query
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (id, domain, host) in leftovers {
        if state.tunnel_runtime.direct.jobs.lock().await.contains(&id) {
            continue;
        }
        let result = async {
            let zone = zone(state, &domain).await?;
            withdraw(state, &zone, &id, &host, "TXT").await
        }
        .await;
        if let Err(error) = result {
            tracing::warn!("直连验证 TXT 清理未完成，将重试：{error}");
        }
    }
    Ok(())
}

/// 固定目标 IPv6，保留域名/SNI 和证书校验；失败仅用于诊断，不改变 DNS。
async fn probe(service: &Service) -> Result<()> {
    let operation = async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .resolve(
                &service.hostname,
                std::net::SocketAddr::new(service.ipv6.parse()?, service.port),
            )
            .build()?;
        let mut response = client
            .get(format!(
                "{}/.nexo-direct/probe",
                crate::https_ports::url("https", &service.hostname, service.port)
            ))
            .send()
            .await
            .context("Server 未能连接目标 IPv6；也可能是 Server 出口不可用")?;
        anyhow::ensure!(response.status().is_success(), "IPv6 探测入口返回异常状态");
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(body.len() + chunk.len() <= 256, "IPv6 探测响应异常");
            body.extend(chunk);
        }
        anyhow::ensure!(
            body == format!("{}:{}", service.tunnel.tunnel_id, service.tunnel.revision).as_bytes(),
            "IPv6 探测服务身份不匹配"
        );
        anyhow::Ok(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), operation)
        .await
        .context("IPv6 公网探测超时，可达性未验证")?
}
