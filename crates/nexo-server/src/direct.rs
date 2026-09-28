//! IPv6 直连的控制与授权边界：所有操作从设备证书反查租户和服务，不相信 Agent 提交的归属。
use crate::*;
use futures_util::StreamExt;
use nexo_protocol::direct::{Report, Request, Response as DirectResponse, Service};
use std::{collections::HashSet, net::Ipv6Addr};
use tokio_util::codec::{FramedRead, LinesCodec};

pub mod certificates;
pub mod dns;
mod domain_certificate;

/// 单进程共享签发任务与 DNS 写入锁，避免证书任务和撤销任务争用同一记录。
#[derive(Default)]
pub struct Runtime {
    #[cfg(test)]
    pub test_zone: tokio::sync::Mutex<Option<crate::dns_provider::Zone>>,
    pub account: tokio::sync::Mutex<Option<instant_acme::Account>>,
    pub jobs: tokio::sync::Mutex<HashSet<String>>,
    pub dns_lock: tokio::sync::Mutex<()>,
}

pub fn migrate(db: &Connection) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    if !tx.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('tunnels') WHERE name='ipv6_direct_enabled')", [], |r|r.get::<_,bool>(0))? {
        tx.execute("ALTER TABLE tunnels ADD COLUMN ipv6_direct_enabled INTEGER NOT NULL DEFAULT 0", [])?;
    }
    tx.execute_batch("CREATE TABLE IF NOT EXISTS direct_agents(device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,addresses TEXT NOT NULL DEFAULT '[]',selected_address TEXT,last_seen INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS direct_services(service_id TEXT PRIMARY KEY REFERENCES tunnels(id) ON DELETE CASCADE,revision INTEGER NOT NULL,ready INTEGER NOT NULL DEFAULT 0,error TEXT,dns_error TEXT,published_address TEXT,reported_at INTEGER NOT NULL DEFAULT 0,probe_status TEXT NOT NULL DEFAULT 'unverified',probe_error TEXT,probed_at INTEGER);
      CREATE TABLE IF NOT EXISTS direct_certificates(service_id TEXT PRIMARY KEY REFERENCES tunnels(id) ON DELETE CASCADE,device_id TEXT NOT NULL,hostname TEXT NOT NULL,csr TEXT NOT NULL,chain TEXT,expires_at INTEGER,renew_at INTEGER,order_url TEXT,next_retry_at INTEGER NOT NULL DEFAULT 0,error TEXT);
      CREATE TABLE IF NOT EXISTS direct_dns_records(service_id TEXT NOT NULL,domain_id TEXT NOT NULL,hostname TEXT NOT NULL,kind TEXT NOT NULL,original TEXT,written TEXT,intended TEXT NOT NULL,PRIMARY KEY(service_id,hostname,kind));")?;
    tx.commit()?;
    Ok(())
}

pub fn public_address(address: &str) -> bool {
    address.parse::<Ipv6Addr>().is_ok_and(|ip| {
        ip.segments()[0] & 0xe000 == 0x2000
            && !(ip.segments()[0] == 0x2001 && ip.segments()[1] == 0xdb8)
    })
}

pub fn prepare(
    db: &Connection,
    tenant: &str,
    id: &str,
    input: &mut TunnelInput,
) -> Result<(), ApiError> {
    let enabled = input.ipv6_direct_enabled.unwrap_or(
        db.query_row(
            "SELECT ipv6_direct_enabled FROM tunnels WHERE id=?1 AND tenant_id=?2",
            params![id, tenant],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?
        .unwrap_or(false),
    );
    input.ipv6_direct_enabled = Some(enabled);
    if !enabled {
        return Ok(());
    }
    if input.protocol != "https"
        || input.service_mode.as_deref() != Some("tunnel")
        || input.device_id.is_none()
        || input.lan_redirect_enabled == Some(true)
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IPv6 直连仅支持绑定 Agent 的 HTTPS 穿透服务，请先关闭内网重定向",
        ));
    }
    let capable: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM direct_agents WHERE device_id=?1 AND last_seen>?2)",
            params![input.device_id, unix_now() - 45],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    if !capable {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "请先连接支持 IPv6 直连的新版本 Agent",
        ));
    }
    let configured: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM domain_settings WHERE domain_id=?1 AND verified=1 AND certificate_mode='cloudflare_dns' AND credential_file IS NOT NULL)",[&input.public_domain_id],|r|r.get(0)).map_err(db_error)?;
    if !configured {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "IPv6 直连要求先配置 DNS 验证凭据",
        ));
    }
    Ok(())
}

pub fn service(state: &AppState, device: &str, id: &str, revision: i64) -> Result<Service> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let (host,port,address): (String,u16,Option<String>) = db.query_row("SELECT t.hostname||'.'||p.domain,t.https_port,a.selected_address FROM tunnels t JOIN devices d ON d.id=t.device_id AND d.tenant_id=t.tenant_id AND d.status='online' JOIN tenants w ON w.id=t.tenant_id AND w.enabled=1 JOIN public_domains p ON p.id=t.public_domain_id AND p.tenant_id=t.tenant_id JOIN domain_settings s ON s.domain_id=p.id JOIN direct_agents a ON a.device_id=d.id WHERE t.id=?1 AND t.device_id=?2 AND t.apply_revision=?3 AND t.enabled=1 AND t.deleted_at IS NULL AND t.ipv6_direct_enabled=1 AND t.protocol='https' AND t.service_mode='tunnel' AND t.lan_redirect_enabled=0 AND p.https_enabled=1 AND s.verified=1 AND s.certificate_mode='cloudflare_dns' AND s.credential_file IS NOT NULL AND a.last_seen>?4",params![id,device,revision,unix_now()-45],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).context("直连服务不存在、已变更或无权访问")?;
    let address = address.context("Agent 尚无可用公网 IPv6 地址，等待自动检测")?;
    anyhow::ensure!(public_address(&address), "Agent IPv6 地址无效");
    drop(db);
    let tunnel = desired_tunnels(state, device)?
        .into_iter()
        .find(|t| t.tunnel_id == id && t.revision == revision && t.enabled)
        .context("服务配置已撤销")?;
    Ok(Service {
        tunnel,
        hostname: host,
        port,
        ipv6: address,
        domain_certificate: true,
    })
}

fn sync(
    state: &AppState,
    device: &str,
    addresses: Vec<String>,
    reports: Vec<Report>,
) -> Result<Vec<Service>> {
    anyhow::ensure!(
        addresses.len() <= 64 && reports.len() <= 1024,
        "直连报告数量过多"
    );
    let mut addresses = addresses
        .into_iter()
        .filter(|v| public_address(v))
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let tx = db.unchecked_transaction()?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT selected_address FROM direct_agents WHERE device_id=?1",
                [device],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        // 优先保留仍有效的地址，避免候选顺序变化导致监听和 DNS 抖动。
        // 首次连接或旧地址失效时，从已排序的公网候选中自动换选；就绪报告仍须匹配新地址。
        let selected = previous
            .clone()
            .filter(|v| addresses.contains(v))
            .or_else(|| addresses.first().cloned());
        tx.execute("INSERT INTO direct_agents(device_id,addresses,selected_address,last_seen) VALUES(?1,?2,?3,?4) ON CONFLICT(device_id) DO UPDATE SET addresses=excluded.addresses,selected_address=excluded.selected_address,last_seen=excluded.last_seen",params![device,serde_json::to_string(&addresses)?,selected,unix_now()])?;
        if previous != selected {
            tx.execute("UPDATE direct_services SET ready=0,probe_status='unverified' WHERE service_id IN (SELECT id FROM tunnels WHERE device_id=?1)",[device])?;
        }
        for report in reports {
            tx.execute("INSERT INTO direct_services(service_id,revision,ready,error,reported_at) SELECT id,?2,?3,?4,?5 FROM tunnels WHERE id=?1 AND device_id=?6 AND apply_revision=?2 AND ipv6_direct_enabled=1 AND deleted_at IS NULL ON CONFLICT(service_id) DO UPDATE SET probe_status=CASE WHEN direct_services.revision!=excluded.revision OR excluded.ready=0 THEN 'unverified' ELSE direct_services.probe_status END,revision=excluded.revision,ready=excluded.ready,error=excluded.error,reported_at=excluded.reported_at",params![report.service_id,report.revision,report.ready && selected.as_deref()==Some(report.address.as_str()),report.error.map(|e|e.chars().take(512).collect::<String>()),unix_now(),device])?;
        }
        tx.commit()?;
    }
    let desired = desired_tunnels(state, device)?;
    Ok(desired
        .iter()
        .filter_map(|t| service(state, device, &t.tunnel_id, t.revision).ok())
        .collect())
}

/// 专用 ALPN 上允许 Agent 主动开管理流；每条流再次检查身份，不能访问数据面。
pub async fn session(
    state: AppState,
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    device: String,
    fingerprint: String,
) -> Result<()> {
    let cancel = state
        .tunnel_runtime
        .direct_session(&device)
        .await
        .context("请先建立已认证的控制连接")?;
    let mut connection = nexo_tunnel::yamux_connection(stream, yamux::Mode::Server);
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            incoming = nexo_tunnel::next_inbound(&mut connection) => {
                let Some(stream) = incoming? else {break;};
                anyhow::ensure!(tasks.len() < 64,"直连管理并发请求过多");
                let state = state.clone(); let device = device.clone(); let fingerprint = fingerprint.clone();
                tasks.spawn(async move {
                    let mut stream = nexo_tunnel::into_tokio_io(stream);
                    let operation = async {
                        let mut reader = FramedRead::new(&mut stream,LinesCodec::new_with_max_length(128*1024));
                        let line = reader.next().await.context("管理请求为空")??;
                        let request: Request = serde_json::from_str(&line)?;
                        drop(reader);
                        { let db = state.db.lock().map_err(|_|anyhow::anyhow!("数据库锁不可用"))?; identity_runtime::accept_certificate(&db,&device,&fingerprint)?; }
                        let response = match handle(&state,&device,request).await {
                            Ok(value) => value,
                            Err(error) => DirectResponse::Error {message:error.to_string()},
                        };
                        nexo_tunnel::identity::write_message(&mut stream,&response).await
                    };
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(15),operation).await;
                });
            }
        }
    }
    tasks.abort_all();
    Ok(())
}
async fn handle(state: &AppState, device: &str, request: Request) -> Result<DirectResponse> {
    match request {
        Request::Sync { addresses, reports } => Ok(DirectResponse::Services {
            services: sync(state, device, addresses, reports)?,
        }),
        Request::Certificate {
            service_id,
            revision,
            csr_pem,
        } => {
            let service = service(state, device, &service_id, revision)?;
            certificates::request(state, device, &service, csr_pem).await
        }
        Request::DomainCertificate {
            service_id,
            revision,
        } => domain_certificate::request(state, device, &service_id, revision),
        Request::Access {
            service_id,
            revision,
            path,
            headers,
            body,
        } => {
            let service = service(state, device, &service_id, revision)?;
            crate::service_access::direct_request(state, &service, path, headers, body).await
        }
    }
}

pub async fn addresses(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_session(&state, &headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let row: Option<(String,Option<String>,i64)> = db.query_row("SELECT a.addresses,a.selected_address,a.last_seen FROM direct_agents a JOIN devices d ON d.id=a.device_id WHERE d.id=?1 AND d.tenant_id=?2",params![device,session.tenant_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db_error)?;
    Ok(Json(match row {
        Some((addresses, selected, seen)) => {
            serde_json::json!({"addresses":serde_json::from_str::<Vec<String>>(&addresses).unwrap_or_default(),"selected_address":selected,"supported":seen>unix_now()-45})
        }
        None => serde_json::json!({"addresses":[],"selected_address":null,"supported":false}),
    }))
}
#[derive(Deserialize)]
pub struct Selection {
    address: String,
}
pub async fn select(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device): Path<String>,
    Json(input): Json<Selection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_write(&state, &headers)?;
    {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let tx = db.unchecked_transaction().map_err(db_error)?;
        let raw: String = tx.query_row("SELECT a.addresses FROM direct_agents a JOIN devices d ON d.id=a.device_id WHERE d.id=?1 AND d.tenant_id=?2",params![device,session.tenant_id],|r|r.get(0)).map_err(|_|ApiError::new(StatusCode::NOT_FOUND,"Agent 尚未报告直连能力"))?;
        if !serde_json::from_str::<Vec<String>>(&raw)
            .unwrap_or_default()
            .contains(&input.address)
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "请选择 Agent 当前有效的公网 IPv6",
            ));
        }
        tx.execute(
            "UPDATE direct_agents SET selected_address=?1 WHERE device_id=?2",
            params![input.address, device],
        )
        .map_err(db_error)?;
        tx.execute("UPDATE tunnels SET apply_revision=apply_revision+1 WHERE device_id=?1 AND ipv6_direct_enabled=1",[&device]).map_err(db_error)?;
        tx.commit().map_err(db_error)?;
    }
    state
        .tunnel_runtime
        .changed(&state)
        .await
        .map_err(db_error)?;
    addresses(State(state), headers, Path(device)).await
}

pub fn status(db: &Connection, id: &str) -> serde_json::Value {
    db.query_row("SELECT t.ipv6_direct_enabled AND t.enabled AND t.deleted_at IS NULL AND EXISTS(SELECT 1 FROM tenants WHERE id=t.tenant_id AND enabled=1),a.selected_address,a.last_seen,s.ready,s.error,s.dns_error,s.published_address,c.expires_at,c.error,s.revision=t.apply_revision AND s.reported_at>strftime('%s','now')-45,s.probe_status,s.probe_error FROM tunnels t LEFT JOIN direct_agents a ON a.device_id=t.device_id LEFT JOIN direct_services s ON s.service_id=t.id LEFT JOIN direct_certificates c ON c.service_id=t.id WHERE t.id=?1",[id],|r| {
        let enabled: bool = r.get(0)?;
        let address: Option<String> = r.get(1)?;
        let online = r.get::<_,Option<i64>>(2)?.is_some_and(|v|v>unix_now()-45);
        let ready = enabled && online && r.get::<_,Option<bool>>(3)?==Some(true) && r.get::<_,Option<bool>>(9)?==Some(true);
        let expiry: Option<i64> = r.get(7)?;
        let published: Option<String> = r.get(6)?;
        Ok(serde_json::json!({"status":if !enabled {"disabled"} else if !online {"offline"} else if address.is_none() {"address_required"} else if ready && r.get::<_,Option<String>>(5)?.is_none() && published==address && expiry.is_some_and(|e|e>unix_now()) {"configured"} else {"pending"},"address":address,"ready":ready,"error":r.get::<_,Option<String>>(4)?,"dns_error":r.get::<_,Option<String>>(5)?,"published_address":published,"certificate_expires_at":expiry,"certificate_error":r.get::<_,Option<String>>(8)?,"public_reachability":r.get::<_,Option<String>>(10)?.unwrap_or_else(||"unverified".into()),"probe_error":r.get::<_,Option<String>>(11)?}))
    }).unwrap_or_else(|_|serde_json::json!({"status":"pending"}))
}

#[cfg(test)]
pub(crate) mod tests;
