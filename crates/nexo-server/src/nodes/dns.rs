//! A 记录按集合协调；与 IPv6 直连共用写锁，AAAA 继续由直连状态驱动。
//! 原值和最后写入值用于外部修改保护，网络失败留下意图供下一轮恢复。
use super::*;
use crate::dns_provider::Record;
use std::{collections::HashSet, time::Duration};

// 已配置 DNS 凭据的内置服务也维护独立 A，避免沿用指向其他节点的泛域名。
// DNS 状态记录保存管理意图；新接管和历史恢复只处理启用中的域名穿透，已有记录仍独立进入停用清理。
// 首次接管不包含 IPv6 直连服务，其 A/AAAA 继续由直连协调器管理。
const MANAGED_SERVICES: &str = "SELECT t.id FROM tunnels t WHERE
    EXISTS(SELECT 1 FROM service_nodes s WHERE s.service_id=t.id AND s.node_id!='local')
    OR EXISTS(SELECT 1 FROM relay_dns_records r WHERE r.service_id=t.id)
    OR EXISTS(SELECT 1 FROM relay_dns_originals r WHERE r.service_id=t.id)
    OR (t.enabled=1 AND t.deleted_at IS NULL AND t.service_mode='tunnel'
        AND t.protocol IN ('http','https','tcp') AND t.public_domain_id IS NOT NULL
        AND t.hostname IS NOT NULL AND t.hostname!=''
        AND EXISTS(SELECT 1 FROM tenants w WHERE w.id=t.tenant_id AND w.enabled=1)
        AND (EXISTS(SELECT 1 FROM relay_dns_state d WHERE d.service_id=t.id)
            OR (t.ipv6_direct_enabled=0
                AND EXISTS(SELECT 1 FROM authorized_service_nodes s WHERE s.service_id=t.id AND s.node_id='local')
                AND EXISTS(SELECT 1 FROM public_domains p JOIN domain_settings d ON d.domain_id=p.id
                    WHERE p.id=t.public_domain_id AND p.tenant_id=t.tenant_id
                        AND d.verified=1 AND d.credential_file IS NOT NULL))))";

pub fn managed(db: &Connection, id: &str) -> rusqlite::Result<bool> {
    db.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM ({MANAGED_SERVICES}) WHERE id=?1)"),
        [id],
        |r| r.get(0),
    )
}

/// 快照只保留决定入口资格的配置与状态，不比较每次心跳都会更新的时间戳。
#[derive(PartialEq, Eq)]
struct Entry {
    target: super::health::Target,
    eligible: bool,
    maintenance: bool,
}

#[derive(PartialEq, Eq)]
struct Snapshot {
    domain: String,
    host: String,
    enabled: bool,
    revision: i64,
    protocol: String,
    port: u16,
    entries: Vec<Entry>,
}

fn snapshot(state: &AppState, id: &str) -> Result<Snapshot> {
    let local = local_address(state)?;
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    snapshot_from_db(state, id, &local, &db)
}

fn local_address(state: &AppState) -> Result<String> {
    Ok(crate::server_settings::relay_ipv4(state)
        .map_err(|e| anyhow::anyhow!(e.message))?
        .map(|ip| ip.to_string())
        .unwrap_or_default())
}

fn snapshot_from_db(state: &AppState, id: &str, local: &str, db: &Connection) -> Result<Snapshot> {
    let (domain,host,enabled,revision,protocol,port):(String,String,bool,i64,String,u16)=db.query_row("SELECT p.id,t.hostname||'.'||p.domain,t.enabled=1 AND t.deleted_at IS NULL AND w.enabled=1,t.apply_revision,t.protocol,CASE WHEN t.protocol='tcp' THEN t.public_port WHEN t.protocol='https' THEN t.https_port ELSE ?2 END FROM tunnels t JOIN public_domains p ON p.id=t.public_domain_id JOIN tenants w ON w.id=t.tenant_id WHERE t.id=?1",params![id,state.config.caddy.http_port()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
    let mut q=db.prepare("SELECT n.id,n.public_ipv4,COALESCE(n.approved=1 AND n.enabled=1 AND n.removed_at IS NULL AND (n.id='local' OR n.last_seen>?2) AND h.healthy=1 AND h.revision=t.apply_revision AND h.checked_at>?2 AND a.revision=t.apply_revision AND a.status='ready' AND a.updated_at>?2,0),COALESCE(h.public_probe_supported,0),n.maintenance FROM authorized_service_nodes s JOIN relay_nodes n ON n.id=s.node_id JOIN tunnels t ON t.id=s.service_id LEFT JOIN relay_service_health h ON h.node_id=n.id AND h.service_id=s.service_id LEFT JOIN tunnel_applied_states a ON a.tunnel_id=t.id WHERE s.service_id=?1 ORDER BY n.id")?;
    let entries = q
        .query_map(params![id, unix_now() - 45], |r| {
            let node: String = r.get(0)?;
            let supported: bool = r.get(3)?;
            Ok(Entry {
                target: super::health::Target {
                    address: if node == "local" {
                        local.to_owned()
                    } else {
                        r.get(1)?
                    },
                    kind: if matches!(protocol.as_str(), "http" | "https")
                        && (node == "local" || supported)
                    {
                        protocol.clone()
                    } else {
                        "tcp".into()
                    },
                    node,
                },
                eligible: r.get(2)?,
                maintenance: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Snapshot {
        domain,
        host,
        enabled,
        revision,
        protocol,
        port,
        entries,
    })
}

/// DNS 网络等待后同时复核配置与所选入口的综合健康，过期或被清除的样本不能继续发布。
fn publication_current(
    state: &AppState,
    id: &str,
    observed: &Snapshot,
    selected: &[super::selection::Candidate],
) -> Result<bool> {
    let local = local_address(state)?;
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    if snapshot_from_db(state, id, &local, &db)? != *observed {
        return Ok(false);
    }
    let mut query = db.prepare("SELECT EXISTS(SELECT 1 FROM relay_healthy_service_nodes WHERE service_id=?1 AND node_id=?2)")?;
    for node in selected {
        if !query.query_row(params![id, node.id], |r| r.get::<_, bool>(0))? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub async fn run(state: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
        let mut q = db.prepare(MANAGED_SERVICES)?;
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
    let observed = snapshot(state, id)?;
    if !observed.enabled {
        return Ok(());
    }
    // 最多 16 个入口并发探测；网络等待期间不占用 DNS 或数据库写锁。
    let probes = observed
        .entries
        .iter()
        .filter(|e| e.eligible)
        .map(|entry| async {
            let error = super::health::probe(
                &entry.target,
                &observed.host,
                observed.port,
                id,
                observed.revision,
            )
            .await
            .err()
            .map(|e| format!("{e:#}"));
            (&entry.target, error)
        });
    let results = futures_util::future::join_all(probes).await;
    let _guard = state.tunnel_runtime.direct.dns_lock.lock().await;
    let local = local_address(state)?;
    let domain = &observed.domain;
    let host = &observed.host;
    let revision = observed.revision;
    let candidates = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        // 复核与探测结果落库共用数据库锁，撤权或新报告不能插入两者之间。
        if snapshot_from_db(state, id, &local, &db)? != observed {
            return Ok(());
        }
        let mut candidates = Vec::new();
        for (target, error) in results {
            super::health::record(&db, target, id, revision, error.as_deref(), unix_now())?;
            let healthy = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM relay_healthy_service_nodes WHERE node_id=?1 AND service_id=?2)",
                params![target.node, id],
                |r| r.get::<_, bool>(0),
            )?;
            if healthy {
                let latency = db.query_row("SELECT l.rtt_ms FROM relay_latency l JOIN tunnels t ON t.device_id=l.device_id WHERE t.id=?1 AND l.node_id=?2 AND l.checked_at>?3 AND l.samples>=3",params![id,target.node,unix_now()-45],|r|r.get::<_,u32>(0)).optional()?;
                candidates.push(super::selection::Candidate {
                    id: target.node.clone(),
                    address: target.address.clone(),
                    latency,
                });
            }
        }
        candidates
    };
    let selected = super::selection::select(state, id, candidates)?;
    let desired = selected
        .iter()
        .map(|n| n.address.clone())
        .collect::<HashSet<_>>();
    let zone = crate::direct::dns::zone(state, domain).await?;
    if !publication_current(state, id, &observed, &selected)? {
        return Ok(());
    }
    let records = zone.records(host).await?;
    if !publication_current(state, id, &observed, &selected)? {
        return Ok(());
    }
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
        if !publication_current(state, id, &observed, &selected)? {
            return Ok(());
        }
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
                name: host.to_owned(),
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
        if !publication_current(state, id, &observed, &selected)? {
            return Ok(());
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
    Ok(())
}

fn obsolete_hosts(state: &AppState, id: &str) -> Result<Vec<(String, String)>> {
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
    Ok(rows)
}

/// 旧主机名与停用服务必须先清理归属；仅恢复曾接管的原值，外部修改保持不动并报错。
async fn cleanup_obsolete(state: &AppState, id: &str) -> Result<()> {
    for (domain, host) in obsolete_hosts(state, id)? {
        let zone = crate::direct::dns::zone(state, &domain).await?;
        let _guard = state.tunnel_runtime.direct.dns_lock.lock().await;
        if !obsolete_hosts(state, id)?.contains(&(domain.clone(), host.clone())) {
            continue;
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
        let records = zone.records(&host).await?;
        if !obsolete_hosts(state, id)?.contains(&(domain.clone(), host.clone())) {
            continue;
        }
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
            if !obsolete_hosts(state, id)?.contains(&(domain.clone(), host.clone())) {
                continue;
            }
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
