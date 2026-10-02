//! 独立节点使用已有 mTLS 控制监听器；先匹配已登记的叶证书，再接收节点报告。
use super::*;
use futures_util::StreamExt;
use nexo_protocol::nodes::{self as wire, Request, Response, Snapshot};
use nexo_tunnel::identity;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_util::codec::{FramedRead, LinesCodec};

pub async fn register(
    State(state): State<AppState>,
    Json(input): Json<wire::Register>,
) -> Result<Json<wire::Registered>, ApiError> {
    if input.token.len() > 128 || input.csr.len() > 16384 {
        return Err(invalid("接入请求无效"));
    }
    let url = reqwest::Url::parse(&installation_url(&state)?).map_err(db_error)?;
    let endpoint = format!(
        "{}:{}",
        url.host_str().ok_or_else(|| invalid("管理地址无效"))?,
        state.config.control_addr.port()
    );
    let db = state.db.lock().map_err(db_error)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    let (id,port)=tx.query_row("SELECT id,control_port FROM relay_nodes WHERE token_digest=?1 AND token_expires>?2 AND removed_at IS NULL AND certificate_pem=''",params![auth::digest(&input.token),unix_now()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,u16>(1)?))).optional().map_err(db_error)?.ok_or_else(||invalid("接入凭证无效、已使用或已过期"))?;
    let certificate = state
        .authority
        .issue_node(&input.csr, &id)
        .map_err(db_error)?;
    tx.execute("UPDATE relay_nodes SET certificate_pem=?2,token_digest=NULL,token_expires=NULL WHERE id=?1",params![id,certificate]).map_err(db_error)?;
    event(&tx, &id, &id, "节点身份已登记，等待审批和分配")?;
    tx.commit().map_err(db_error)?;
    Ok(Json(wire::Registered {
        id,
        certificate,
        ca: state.authority.ca_pem(),
        control_endpoint: endpoint,
        data_port: port,
    }))
}
pub fn peer_id(stream: &TlsStream<TcpStream>) -> Option<String> {
    let cert = stream.get_ref().1.peer_certificates()?.first()?;
    let (_, cert) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let id = cert
        .subject()
        .iter_common_name()
        .next()?
        .as_str()
        .ok()?
        .to_owned();
    id.starts_with("node-").then_some(id)
}
fn authorized(state: &AppState, id: &str, der: &[u8]) -> Result<()> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let pem: String = db.query_row(
        "SELECT certificate_pem FROM relay_nodes WHERE id=?1 AND removed_at IS NULL",
        [id],
        |r| r.get(0),
    )?;
    anyhow::ensure!(
        identity::certificates(&pem)?
            .first()
            .is_some_and(|v| v.as_ref() == der),
        "节点身份已撤销或证书不匹配"
    );
    Ok(())
}
pub async fn session(state: AppState, stream: TlsStream<TcpStream>, id: String) -> Result<()> {
    let cert = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|v| v.first())
        .context("缺少节点证书")?
        .as_ref()
        .to_vec();
    authorized(&state, &id, &cert)?;
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = FramedRead::new(
        read,
        LinesCodec::new_with_max_length(identity::MAX_CONTROL_FRAME),
    );
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let deadline = tokio::time::sleep(Duration::from_secs(45));
    tokio::pin!(deadline);
    let mut last = None;
    loop {
        tokio::select! {
            _=state.tunnel_runtime.stop.cancelled()=>break,
            _=&mut deadline=>anyhow::bail!("节点心跳超时（45 秒）"),
            _=tick.tick()=>{
                authorized(&state,&id,&cert)?;
                let snapshot=snapshot(&state,&id)?;
                if last.as_ref()!=Some(&snapshot){identity::write_message(&mut write,&Response::State{snapshot:snapshot.clone(),command:None}).await?;last=Some(snapshot);}
            },
            incoming=lines.next()=>{
                let line=incoming.context("节点控制通道断开")??;
                authorized(&state,&id,&cert)?;
                let request:Request=serde_json::from_str(&line)?;
                match request{
                    Request::Poll{version,os,architecture,connections,services,update}=>{
                        anyhow::ensure!(version.len()<64&&os.len()<128&&architecture.len()<32&&services.len()<10000,"节点报告过大");
                        deadline.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(45));
                        {
                            let db=state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?;
                            db.execute("UPDATE relay_nodes SET version=?2,os=?3,architecture=?4,connections=?5,last_seen=?6 WHERE id=?1",params![id,version,os,architecture,connections.min(i64::MAX as u64),unix_now()])?;
                            for report in services {
                                record_health(&db, &id, report, unix_now())?;
                            }
                        }
                        let command=super::updates::advance(&state,&id,&version,connections,&update)?;
                        let next=snapshot(&state,&id)?;
                        identity::write_message(&mut write,&Response::State{snapshot:next.clone(),command}).await?;last=Some(next);
                    },
                    Request::Access{request_id,service_id,method:_,path,headers,body}=>{
                        let authorized=snapshot(&state,&id)?.services.into_iter().find(|s|s.id==service_id).context("节点未获此服务认证权限")?;
                        let response=crate::service_access::remote_request(&state,&authorized.id,authorized.hostname.as_deref().context("缺少服务域名")?,&authorized.protocol,path,headers,body.into_bytes()).await;
                        let response=match response{
                            Ok(nexo_protocol::direct::Response::Access{status,headers,body})=>Response::Access{request_id,status,headers,body:String::from_utf8(body)?},
                            _=>Response::Access{request_id,status:503,headers:vec![],body:"认证暂不可用".into()},
                        };
                        identity::write_message(&mut write,&response).await?;
                    }
                }
            }
        }
    }
    Ok(())
}
/// 新配置及超过授权时限的旧样本必须重新累计三次成功，不能继承此前健康状态。
fn record_health(db: &Connection, node: &str, report: wire::ServiceHealth, now: i64) -> Result<()> {
    let origin_ready: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM tunnel_applied_states WHERE tunnel_id=?1 AND revision=?2 AND status='ready' AND updated_at>?3)", params![report.id, report.revision, now-45], |r| r.get(0))?;
    if !origin_ready {
        // 回源与节点分开检查：等待新回源报告不算节点故障，也不消耗未变节点的成功样本。
        // 回源未确认时仍不采纳节点报告；综合健康视图继续要求当前版本、有效期与回源 ready。
        return Ok(());
    }
    let valid: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM authorized_service_nodes s JOIN tunnels t ON t.id=s.service_id WHERE s.node_id=?1 AND s.service_id=?2 AND t.apply_revision=?3 AND t.enabled=1 AND t.deleted_at IS NULL)", params![node,report.id,report.revision], |r|r.get(0))?;
    if valid {
        // 支持声明变化即丢弃公网旧样本，升级后不能继承 TCP 的连续成功次数。
        db.execute("DELETE FROM relay_public_health WHERE node_id=?1 AND service_id=?2 AND EXISTS(SELECT 1 FROM relay_service_health h WHERE h.node_id=?1 AND h.service_id=?2 AND h.public_probe_supported!=?3)",params![node,report.id,report.public_probe_supported])?;
        db.execute("INSERT INTO relay_service_health(node_id,service_id,revision,successes,failures,checked_at,error,public_probe_supported) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(node_id,service_id) DO UPDATE SET revision=excluded.revision,healthy=CASE WHEN revision!=excluded.revision OR checked_at<=excluded.checked_at-45 THEN 0 ELSE healthy END,successes=CASE WHEN excluded.successes=1 THEN CASE WHEN revision=excluded.revision AND checked_at>excluded.checked_at-45 THEN MIN(successes+1,3) ELSE 1 END ELSE 0 END,failures=CASE WHEN excluded.failures=1 THEN CASE WHEN revision=excluded.revision AND checked_at>excluded.checked_at-45 THEN MIN(failures+1,3) ELSE 1 END ELSE 0 END,checked_at=excluded.checked_at,error=excluded.error,public_probe_supported=excluded.public_probe_supported",params![node,report.id,report.revision,report.ready as i64,(!report.ready) as i64,now,report.error.map(|s|s.chars().take(500).collect::<String>()),report.public_probe_supported])?;
        db.execute("UPDATE relay_service_health SET healthy=CASE WHEN successes>=3 THEN 1 WHEN failures>=3 THEN 0 ELSE healthy END WHERE node_id=?1 AND service_id=?2",params![node,report.id])?;
    }
    Ok(())
}

pub fn snapshot(state: &AppState, node: &str) -> Result<Snapshot> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let (enabled,maintenance):(bool,bool)=db.query_row("SELECT approved=1 AND enabled=1 AND removed_at IS NULL,maintenance FROM relay_nodes WHERE id=?1",[node],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if !enabled {
        return Ok(Snapshot::default());
    }
    let mut q=db.prepare("SELECT t.id,t.tenant_id,t.device_id,t.apply_revision,t.protocol,COALESCE(t.public_port,0),t.hostname||'.'||p.domain,t.https_port,t.access_mode,t.http_redirect_enabled FROM authorized_service_nodes s JOIN tunnels t ON t.id=s.service_id JOIN devices d ON d.id=t.device_id JOIN tenants w ON w.id=t.tenant_id LEFT JOIN public_domains p ON p.id=t.public_domain_id JOIN relay_node_authorizations g ON g.node_id=s.node_id AND g.tenant_id=t.tenant_id WHERE s.node_id=?1 AND t.enabled=1 AND t.deleted_at IS NULL AND w.enabled=1 AND d.status='online' AND d.node_capable=1 AND t.protocol IN ('http','https','tcp')")?;
    let mut services = q
        .query_map([node], |r| {
            Ok(wire::Service {
                id: r.get(0)?,
                tenant: r.get(1)?,
                device: r.get(2)?,
                revision: r.get(3)?,
                protocol: r.get(4)?,
                port: r.get(5)?,
                hostname: r.get(6)?,
                http_port: state.config.caddy.http_port(),
                https_port: r.get(7)?,
                access_mode: r.get(8)?,
                http_redirect: r.get(9)?,
                lan_redirect_url: None,
                certificate: None,
                private_key: None,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for service in &mut services {
        let (redirect, address, port, protocol): (bool,String,u16,Option<String>)=db.query_row("SELECT lan_redirect_enabled,local_address,local_port,origin_protocol FROM tunnels WHERE id=?1",[&service.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
        if redirect {
            service.lan_redirect_url = Some(
                crate::lan_redirect::target_url(&address, port, protocol.as_deref())
                    .map_err(|e| anyhow::anyhow!(e.message))?,
            );
        }
        if service.protocol == "https" {
            if let Some((chain, key)) = super::certificates::material(
                state,
                &db,
                &service.id,
                service.hostname.as_deref().context("服务域名缺失")?,
            )? {
                service.certificate = Some(chain);
                service.private_key = Some(key);
            }
        }
    }
    let mut agents = Vec::new();
    for service in &services {
        if agents
            .iter()
            .any(|a: &wire::AgentIdentity| a.id == service.device)
        {
            continue;
        }
        let (pem,pending):(String,Option<String>)=db.query_row("SELECT certificate_pem,pending_certificate_pem FROM device_certificates WHERE device_id=?1",[&service.device],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let mut certificates = vec![pem];
        if let Some(pending) = pending {
            certificates.push(pending);
        }
        agents.push(wire::AgentIdentity {
            id: service.device.clone(),
            certificates,
        });
    }
    let stage:Option<String>=db.query_row("SELECT i.stage FROM node_update_items i JOIN node_update_jobs j ON j.id=i.job_id WHERE i.node_id=?1 AND j.status IN ('running','paused') AND i.stage NOT IN ('complete','skipped','cancelled') ORDER BY j.created_at LIMIT 1",[node],|r|r.get(0)).optional()?;
    // DNS 撤出期间继续服务旧缓存，排空阶段仅拒绝新连接，不撤销现有流。
    let accepting = !maintenance || matches!(stage.as_deref(), Some("withdrawing" | "verifying"));
    let data_port = db.query_row(
        "SELECT control_port FROM relay_nodes WHERE id=?1",
        [node],
        |r| r.get(0),
    )?;
    Ok(Snapshot {
        data_port,
        services,
        agents,
        accepting,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn unchanged_entry_waits_for_current_origin_without_resetting_node_samples() {
        let (state, headers, mut input, checked) = crate::service_update_tests::fixture();
        input.local_port += 1;
        let _ = update_tunnel(
            State(state.clone()),
            headers,
            Path("service".into()),
            Json(input),
        )
        .await
        .unwrap();
        let db = state.db.lock().unwrap();
        let report = |revision| wire::ServiceHealth {
            id: "service".into(),
            revision,
            ready: true,
            error: None,
            public_probe_supported: true,
        };
        record_health(&db, "b", report(2), checked + 1).unwrap();
        assert!(db.query_row("SELECT revision=2 AND successes=3 AND healthy=0 AND checked_at=?1 FROM relay_service_health WHERE service_id='service' AND node_id='b'", [checked], |r| r.get::<_,bool>(0)).unwrap());
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM relay_healthy_service_nodes WHERE service_id='service'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        db.execute(
            "UPDATE tunnel_applied_states SET revision=2,updated_at=?1 WHERE tunnel_id='service'",
            [checked + 1],
        )
        .unwrap();
        record_health(&db, "b", report(2), checked + 1).unwrap();
        assert_eq!(db.query_row("SELECT COUNT(*) FROM relay_healthy_service_nodes WHERE service_id='service' AND node_id='b'", [], |r| r.get::<_,i64>(0)).unwrap(), 1);
        record_health(&db, "b", report(1), checked + 2).unwrap();
        assert_eq!(db.query_row("SELECT checked_at FROM relay_service_health WHERE service_id='service' AND node_id='b'", [], |r| r.get::<_,i64>(0)).unwrap(), checked + 1);
    }

    #[test]
    fn capability_changes_clear_public_samples_without_changing_identity() {
        let (state, _) = crate::tests::domain_fixture();
        let db = state.db.lock().unwrap();
        db.execute_batch("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('s','default','s','http','127.0.0.1',80,0,0);
            UPDATE relay_nodes SET certificate_pem='same-identity' WHERE id='local';").unwrap();
        db.execute("INSERT INTO tunnel_applied_states(tunnel_id,revision,status,updated_at) VALUES('s',1,'ready',?1)",[unix_now()]).unwrap();
        for supported in [false, true, false] {
            if !supported {
                db.execute("INSERT OR REPLACE INTO relay_public_health(node_id,service_id,revision,healthy,successes,checked_at) VALUES('local','s',1,1,3,?1)",[unix_now()]).unwrap();
            }
            record_health(
                &db,
                "local",
                wire::ServiceHealth {
                    id: "s".into(),
                    revision: 1,
                    ready: true,
                    error: None,
                    public_probe_supported: supported,
                },
                unix_now(),
            )
            .unwrap();
            if supported {
                assert_eq!(
                    db.query_row("SELECT COUNT(*) FROM relay_public_health", [], |r| r
                        .get::<_, i64>(0))
                        .unwrap(),
                    0
                );
            }
        }
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM relay_public_health", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            db.query_row(
                "SELECT certificate_pem FROM relay_nodes WHERE id='local'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "same-identity"
        );
    }

    #[test]
    fn health_requires_three_samples_after_revision_change_or_expiry() {
        let (state, _) = crate::tests::domain_fixture();
        let db = state.db.lock().unwrap();
        db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('s','default','s','tcp','127.0.0.1',80,0,0)",[]).unwrap();
        let now = unix_now();
        let report = |revision, ready, time| {
            db.execute("INSERT INTO tunnel_applied_states(tunnel_id,revision,status,updated_at) VALUES('s',?1,'ready',?2) ON CONFLICT(tunnel_id) DO UPDATE SET revision=excluded.revision,updated_at=excluded.updated_at",params![revision,time]).unwrap();
            record_health(
                &db,
                "local",
                wire::ServiceHealth {
                    public_probe_supported: false,
                    id: "s".into(),
                    revision,
                    ready,
                    error: None,
                },
                time,
            )
            .unwrap();
            db.query_row(
                "SELECT healthy FROM relay_service_health WHERE service_id='s'",
                [],
                |r| r.get::<_, bool>(0),
            )
            .unwrap()
        };
        assert!(!report(1, true, now));
        assert!(!report(1, true, now + 10));
        assert!(report(1, true, now + 20));
        assert!(report(1, false, now + 30));
        assert!(report(1, false, now + 40));
        assert!(!report(1, false, now + 50));
        for offset in [60, 70, 80] {
            report(1, true, now + offset);
        }
        db.execute("UPDATE tunnels SET apply_revision=2 WHERE id='s'", [])
            .unwrap();
        assert!(!report(2, true, now + 90));
        assert!(!report(2, true, now + 100));
        assert!(report(2, true, now + 110));
        assert!(!report(2, true, now + 156));
        assert!(!report(2, true, now + 166));
        assert!(report(2, true, now + 176));
    }
}
