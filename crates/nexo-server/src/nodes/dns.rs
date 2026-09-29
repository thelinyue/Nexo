//! A 记录按集合协调；与 IPv6 直连共用写锁，AAAA 继续由直连状态驱动。
//! 原值和最后写入值用于外部修改保护，网络失败留下意图供下一轮恢复。
use super::*;
use crate::dns_provider::Record;
use std::{collections::HashSet, time::Duration};

pub fn managed(db: &Connection, id: &str) -> rusqlite::Result<bool> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM service_nodes WHERE service_id=?1 AND node_id!='local') OR EXISTS(SELECT 1 FROM relay_dns_records WHERE service_id=?1) OR EXISTS(SELECT 1 FROM relay_dns_originals WHERE service_id=?1)",[id],|r|r.get(0))
}
pub async fn run(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {_=state.tunnel_runtime.stop.cancelled()=>break,_=tick.tick()=>{if let Err(error)=reconcile(&state).await{tracing::warn!("多节点 DNS 协调未完成：{error}");}}}
    }
}
pub async fn reconcile(state: &AppState) -> Result<()> {
    super::updates::reconcile(state)?;
    let ids = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut q=db.prepare("SELECT DISTINCT t.id FROM tunnels t WHERE EXISTS(SELECT 1 FROM service_nodes s WHERE s.service_id=t.id AND s.node_id!='local') OR EXISTS(SELECT 1 FROM relay_dns_records r WHERE r.service_id=t.id) OR EXISTS(SELECT 1 FROM relay_dns_originals r WHERE r.service_id=t.id)")?;
        let v = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        v
    };
    for id in ids {
        if let Err(error) = super::certificates::ensure(state, &id).await {
            tracing::warn!(service=%id,"节点证书检查失败：{error}");
        }
        if let Err(error) = sync(state, &id).await {
            let db = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            db.execute(
                "UPDATE tunnels SET apply_error=?2 WHERE id=?1",
                params![id, format!("DNS 更新失败：{error}")],
            )?;
            db.execute("INSERT INTO relay_dns_state VALUES(?1,0,0,?2) ON CONFLICT(service_id) DO UPDATE SET error=excluded.error",params![id,error.to_string()])?;
        }
    }
    Ok(())
}
pub async fn sync(state: &AppState, id: &str) -> Result<()> {
    cleanup_obsolete(state, id).await?;
    let (domain, host, enabled, revision, protocol, port, entries) = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let (domain,host,enabled,revision,protocol,port):(String,String,bool,i64,String,u16)=db.query_row("SELECT p.id,t.hostname||'.'||p.domain,t.enabled=1 AND t.deleted_at IS NULL AND w.enabled=1,t.apply_revision,t.protocol,CASE WHEN t.protocol='tcp' THEN t.public_port WHEN t.protocol='https' THEN t.https_port ELSE ?2 END FROM tunnels t JOIN public_domains p ON p.id=t.public_domain_id JOIN tenants w ON w.id=t.tenant_id WHERE t.id=?1",params![id,state.config.caddy.http_port()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
        let mut q=db.prepare("SELECT n.id,n.public_ipv4,n.approved=1 AND n.enabled=1 AND n.removed_at IS NULL AND (n.id='local' OR (n.last_seen>?2 AND EXISTS(SELECT 1 FROM relay_node_authorizations g WHERE g.node_id=n.id AND g.tenant_id=t.tenant_id))),COALESCE(h.healthy=1 AND h.revision=t.apply_revision AND h.checked_at>?2,0),n.maintenance FROM authorized_service_nodes s JOIN relay_nodes n ON n.id=s.node_id JOIN tunnels t ON t.id=s.service_id LEFT JOIN relay_service_health h ON h.node_id=n.id AND h.service_id=s.service_id WHERE s.service_id=?1")?;
        let entries = q
            .query_map(params![id, unix_now() - 45], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, bool>(2)?,
                    r.get::<_, bool>(3)?,
                    r.get::<_, bool>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        (domain, host, enabled, revision, protocol, port, entries)
    };
    if !enabled {
        return Ok(());
    }
    let mut probes = Vec::new();
    for (node, mut ip, available, reported, maintenance) in entries {
        if !available || !reported {
            continue;
        }
        if node == "local" {
            ip = crate::server_settings::relay_ipv4(state)
                .map_err(|e| anyhow::anyhow!(e.message))?
                .context("请配置内置节点公网 IPv4")?
                .to_string();
        }
        // 单服务最多 16 个节点并发探测，避免多个故障节点串行超时拖慢健康入口。
        probes.push(async move {
            let ready = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::TcpStream::connect(format!("{ip}:{port}")),
            )
            .await
            .is_ok_and(|v| v.is_ok());
            (node, ip, maintenance, ready)
        });
    }
    let mut candidates = Vec::new();
    for (node, ip, maintenance, ready) in futures_util::future::join_all(probes).await {
        let healthy = {
            let db = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            db.execute("INSERT INTO relay_public_health(node_id,service_id,revision,successes,failures,checked_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(node_id,service_id) DO UPDATE SET healthy=CASE WHEN revision!=excluded.revision OR checked_at<=excluded.checked_at-45 THEN 0 ELSE healthy END,successes=CASE WHEN excluded.successes=1 THEN CASE WHEN revision=excluded.revision AND checked_at>excluded.checked_at-45 THEN MIN(successes+1,3) ELSE 1 END ELSE 0 END,failures=CASE WHEN excluded.failures=1 THEN CASE WHEN revision=excluded.revision AND checked_at>excluded.checked_at-45 THEN MIN(failures+1,3) ELSE 1 END ELSE 0 END,revision=excluded.revision,checked_at=excluded.checked_at",params![node,id,revision,ready as i64,(!ready) as i64,unix_now()])?;
            db.execute("UPDATE relay_public_health SET healthy=CASE WHEN successes>=3 THEN 1 WHEN failures>=3 THEN 0 ELSE healthy END WHERE node_id=?1 AND service_id=?2",params![node,id])?;
            db.query_row(
                "SELECT healthy FROM relay_public_health WHERE node_id=?1 AND service_id=?2",
                params![node, id],
                |r| r.get::<_, bool>(0),
            )?
        };
        if healthy && !maintenance {
            let latency = {
                let db = state
                    .db
                    .lock()
                    .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
                db.query_row("SELECT l.rtt_ms FROM relay_latency l JOIN tunnels t ON t.device_id=l.device_id WHERE t.id=?1 AND l.node_id=?2 AND l.checked_at>?3 AND l.samples>=3",params![id,node,unix_now()-45],|r|r.get::<_,u32>(0)).optional()?
            };
            candidates.push(super::selection::Candidate {
                id: node,
                address: ip,
                latency,
            });
        }
    }
    let desired = super::selection::select(state, id, candidates)?
        .into_iter()
        .map(|n| n.address)
        .collect::<HashSet<_>>();
    let zone = crate::direct::dns::zone(state, &domain).await?;
    let _guard = state.tunnel_runtime.direct.dns_lock.lock().await;
    // 取锁和网络探测期间可能发生编辑；旧协调结果不能写入新服务配置。
    {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let current: i64 = db.query_row(
            "SELECT apply_revision FROM tunnels WHERE id=?1",
            [id],
            |r| r.get(0),
        )?;
        anyhow::ensure!(current == revision, "服务已修改，稍后重试 DNS");
    }
    let records = zone.records(&host).await?;
    anyhow::ensure!(
        !records.iter().any(|r| r.kind == "CNAME" || r.proxied),
        "域名存在 CNAME 或代理记录，请先整理 DNS"
    );
    // 将原直连单 A 的归属移交给集合协调器，保留原始恢复信息。
    {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let old:Option<(Option<String>,Option<String>)>=db.query_row("SELECT original,written FROM direct_dns_records WHERE service_id=?1 AND hostname=?2 AND kind='A'",params![id,host],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((original, Some(written))) = old {
            let record: Record = serde_json::from_str(&written)?;
            anyhow::ensure!(
                records.iter().any(|r| r == &record),
                "原直连 A 已被外部修改，未接管"
            );
            let tx = db.unchecked_transaction()?;
            if let Some(original) = &original {
                tx.execute(
                    "INSERT OR IGNORE INTO relay_dns_originals VALUES(?1,?2,?3,?4)",
                    params![id, domain, host, original],
                )?;
            }
            tx.execute("INSERT OR IGNORE INTO relay_dns_records(service_id,domain_id,hostname,address,original,written) VALUES(?1,?2,?3,?4,?5,?6)",params![id,domain,host,record.value,original,written])?;
            tx.execute(
                "DELETE FROM direct_dns_records WHERE service_id=?1 AND hostname=?2 AND kind='A'",
                params![id, host],
            )?;
            tx.commit()?;
        }
    }
    let journals = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut q = db.prepare(
            "SELECT address,written FROM relay_dns_records WHERE service_id=?1 AND hostname=?2",
        )?;
        let rows = q
            .query_map(params![id, host], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for record in records.iter().filter(|r| r.kind == "A") {
        let owned = journals.iter().any(|(address, written)| {
            written
                .as_ref()
                .and_then(|s| serde_json::from_str::<Record>(s).ok())
                .is_some_and(|v| v == *record)
                || (written.is_none() && address == &record.value && record.ttl == 60)
        });
        anyhow::ensure!(owned, "存在非 Nexo 管理的 A 记录，请先核对后移除，未覆盖");
    }
    for address in &desired {
        let saved = journals
            .iter()
            .find(|(a, _)| a == address)
            .and_then(|(_, v)| v.as_ref())
            .map(|s| serde_json::from_str::<Record>(s))
            .transpose()?;
        if let Some(saved) = saved {
            anyhow::ensure!(
                records.iter().any(|r| r == &saved),
                "受管 A 记录被外部修改或删除，未覆盖"
            );
            continue;
        }
        state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.execute("INSERT OR IGNORE INTO relay_dns_records(service_id,domain_id,hostname,address) VALUES(?1,?2,?3,?4)",params![id,domain,host,address])?;
        let matches = records
            .iter()
            .filter(|r| r.kind == "A" && r.value == *address && r.ttl == 60)
            .collect::<Vec<_>>();
        anyhow::ensure!(matches.len() <= 1, "DNS 记录恢复存在歧义");
        let record = if let Some(record) = matches.first() {
            (*record).clone()
        } else {
            zone.write(&Record {
                id: String::new(),
                name: host.clone(),
                kind: "A".into(),
                value: address.clone(),
                ttl: 60,
                proxied: false,
            })
            .await?
        };
        state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?.execute("UPDATE relay_dns_records SET written=?4 WHERE service_id=?1 AND hostname=?2 AND address=?3",params![id,host,address,serde_json::to_string(&record)?])?;
    }
    for (address, written) in journals {
        if desired.contains(&address) {
            continue;
        }
        if let Some(written) = written {
            let written: Record = serde_json::from_str(&written)?;
            if let Some(found) = records.iter().find(|r| r.id == written.id) {
                anyhow::ensure!(*found == written, "受管 A 记录已被外部修改，未撤销");
                zone.remove(&written).await?;
            }
        }
        state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?
            .execute(
                "DELETE FROM relay_dns_records WHERE service_id=?1 AND hostname=?2 AND address=?3",
                params![id, host, address],
            )?;
    }
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    db.execute("INSERT INTO relay_dns_state VALUES(?1,?2,?3,NULL) ON CONFLICT(service_id) DO UPDATE SET revision=excluded.revision,synced_at=excluded.synced_at,error=NULL",params![id,revision,unix_now()])?;
    db.execute(
        "UPDATE tunnels SET apply_error=NULL WHERE id=?1 AND apply_error LIKE 'DNS 更新失败：%'",
        [id],
    )?;
    let _ = protocol;
    Ok(())
}

/// 旧主机名与停用服务必须先清理归属；仅恢复曾接管的原值，外部修改保持不动并报错。
async fn cleanup_obsolete(state: &AppState, id: &str) -> Result<()> {
    let obsolete = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut q=db.prepare("SELECT DISTINCT r.domain_id,r.hostname FROM (SELECT service_id,domain_id,hostname FROM relay_dns_records UNION SELECT service_id,domain_id,hostname FROM relay_dns_originals) r JOIN tunnels t ON t.id=r.service_id LEFT JOIN public_domains p ON p.id=t.public_domain_id WHERE r.service_id=?1 AND (t.deleted_at IS NOT NULL OR t.enabled=0 OR NOT EXISTS(SELECT 1 FROM tenants w WHERE w.id=t.tenant_id AND w.enabled=1) OR r.hostname IS NOT t.hostname||'.'||p.domain OR r.domain_id IS NOT t.public_domain_id)")?;
        let rows = q
            .query_map([id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (domain, host) in obsolete {
        let zone = crate::direct::dns::zone(state, &domain).await?;
        let _guard = state.tunnel_runtime.direct.dns_lock.lock().await;
        let journals = {
            let db = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            let mut q = db.prepare(
                "SELECT address,written FROM relay_dns_records WHERE service_id=?1 AND hostname=?2",
            )?;
            let rows = q
                .query_map(params![id, host], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let records = zone.records(&host).await?;
        for (address, written) in &journals {
            let saved = written
                .as_ref()
                .map(|v| serde_json::from_str::<Record>(v))
                .transpose()?;
            let matches = records
                .iter()
                .filter(|record| {
                    saved.as_ref().map_or(
                        record.kind == "A" && record.value == *address && record.ttl == 60,
                        |saved| record.id == saved.id,
                    )
                })
                .collect::<Vec<_>>();
            anyhow::ensure!(matches.len() <= 1, "旧 A 记录清理存在歧义");
            if let Some(record) = matches.first() {
                anyhow::ensure!(
                    saved.as_ref().is_none_or(|saved| saved == *record),
                    "旧 A 记录已被外部修改，未清理"
                );
                zone.remove(record).await?;
            }
        }
        let original: Option<String> = {
            let db = state
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
            db.query_row(
                "SELECT record FROM relay_dns_originals WHERE service_id=?1 AND hostname=?2",
                params![id, host],
                |r| r.get(0),
            )
            .optional()?
        };
        if let Some(original) = original {
            let original: Record = serde_json::from_str(&original)?;
            let now = zone.records(&host).await?;
            if !now.iter().any(|r| {
                r.kind == original.kind
                    && r.name == original.name
                    && r.value == original.value
                    && r.ttl == original.ttl
                    && r.proxied == original.proxied
            }) {
                anyhow::ensure!(
                    !now.iter().any(|r| r.kind == "A" || r.kind == "CNAME"),
                    "原始 A 记录恢复遇到外部记录，未覆盖"
                );
                zone.write(&Record {
                    id: String::new(),
                    ..original
                })
                .await?;
            }
        }
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let tx = db.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM relay_dns_records WHERE service_id=?1 AND hostname=?2",
            params![id, host],
        )?;
        tx.execute(
            "DELETE FROM relay_dns_originals WHERE service_id=?1 AND hostname=?2",
            params![id, host],
        )?;
        tx.commit()?;
    }
    Ok(())
}
