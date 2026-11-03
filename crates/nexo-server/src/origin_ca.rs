//! 每个穿透服务独立配置回源证书验证，不修改设备或其他服务的系统信任库。

use crate::*;

const MAX_CA_PEM_BYTES: usize = 16 * 1024;

pub fn migrate(db: &Connection) -> Result<()> {
    if !db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tunnels') WHERE name='origin_ca_pem')",
        [],
        |row| row.get::<_, bool>(0),
    )? {
        db.execute("ALTER TABLE tunnels ADD COLUMN origin_ca_pem TEXT", [])?;
    }
    Ok(())
}

pub fn prepare(
    db: &Connection,
    tenant: &str,
    id: &str,
    input: &mut TunnelInput,
) -> Result<(), ApiError> {
    let previous: Option<(String, Option<String>)> = db
        .query_row(
            "SELECT origin_tls_verification,origin_ca_pem FROM tunnels WHERE id=?1 AND tenant_id=?2 AND deleted_at IS NULL",
            params![id, tenant],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db_error)?;
    let (old_mode, old_ca) = previous.unwrap_or_else(|| ("system".into(), None));
    let explicit_mode = input.origin_tls_verification.is_some();
    let mut mode = input.origin_tls_verification.take().unwrap_or(old_mode);
    let supplied_ca = input.origin_ca_pem.take();
    let ca = supplied_ca.clone().unwrap_or(old_ca);
    if mode == "custom_ca" {
        if input.service_mode.as_deref() != Some("tunnel")
            || (explicit_mode && input.origin_protocol.as_deref() != Some("https"))
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "自定义回源 CA 仅适用于 HTTPS 内网穿透",
            ));
        }
        let pem = ca
            .as_deref()
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "请提供受信任的 CA 证书"))?;
        validate(pem)?;
        input.origin_ca_pem = Some(Some(pem.trim().to_owned()));
    } else if mode == "insecure_skip_verify" {
        if input.service_mode.as_deref() != Some("tunnel")
            || (explicit_mode && input.origin_protocol.as_deref() != Some("https"))
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "仅 HTTPS 内网穿透可以跳过回源证书验证",
            ));
        }
        if matches!(supplied_ca, Some(Some(_))) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "跳过证书验证时不使用自定义 CA",
            ));
        }
        // 切走 HTTPS 后清除不安全选项，避免旧客户端再次切回时隐式跳过验证。
        if input.origin_protocol.as_deref() != Some("https") {
            mode = "system".into();
        }
        input.origin_ca_pem = Some(None);
    } else if mode == "system" {
        if matches!(supplied_ca, Some(Some(_))) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "系统证书校验不使用自定义 CA",
            ));
        }
        input.origin_ca_pem = Some(None);
    } else {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "回源证书校验方式无效",
        ));
    }
    input.origin_tls_verification = Some(mode);
    Ok(())
}

fn validate(pem: &str) -> Result<(), ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "请填写有效的 PEM 公钥证书，不要包含私钥",
        )
    };
    if pem.len() > MAX_CA_PEM_BYTES {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "回源 CA 证书不能超过 16 KiB",
        ));
    }
    let mut rest = pem.trim();
    if rest.is_empty() {
        return Err(invalid());
    }
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    // 只接受证书块，避免误把私钥或其他内容保存到服务配置并下发设备。
    while !rest.is_empty() {
        if !rest.starts_with(BEGIN) {
            return Err(invalid());
        }
        let end = rest.find(END).ok_or_else(invalid)? + END.len();
        let block = &rest[..end];
        nexo_tunnel::identity::roots(block).map_err(|_| invalid())?;
        rest = rest[end..].trim_start();
    }
    Ok(())
}

pub fn save(db: &Connection, tenant: &str, id: &str, input: &TunnelInput) -> Result<(), ApiError> {
    db.execute(
        "UPDATE tunnels SET origin_tls_verification=?1,origin_ca_pem=?2 WHERE id=?3 AND tenant_id=?4",
        params![input.origin_tls_verification, input.origin_ca_pem.as_ref().and_then(|value| value.as_ref()), id, tenant],
    )
    .map_err(db_error)?;
    Ok(())
}

pub fn check_snapshot(
    state: &AppState,
    db: &Connection,
    device: Option<&str>,
) -> Result<(), ApiError> {
    let Some(device) = device else { return Ok(()) };
    let tunnels = desired_tunnels_from_db(db, device).map_err(db_error)?;
    if !tunnels.iter().any(|tunnel| tunnel.origin_ca_pem.is_some()) {
        return Ok(());
    }
    // 直连响应有独立的 128 KiB 接收上限。包含已停用的服务并按最长 IPv6 和修订号估算，
    // 避免稍后启用服务或 IPv6 地址变化时，证书累积使整个设备的直连配置无法下发。
    let mut query = db.prepare("SELECT t.id,t.hostname||'.'||p.domain,t.https_port FROM tunnels t JOIN public_domains p ON p.id=t.public_domain_id WHERE t.device_id=?1 AND t.deleted_at IS NULL AND t.ipv6_direct_enabled=1 AND t.protocol='https' AND t.service_mode='tunnel'").map_err(db_error)?;
    let direct_services = query
        .query_map([device], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (row.get::<_, String>(1)?, row.get::<_, u16>(2)?),
            ))
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<std::collections::HashMap<_, _>>>()
        .map_err(db_error)?;
    let direct_snapshot = nexo_protocol::direct::Response::Services {
        analytics_supported: true,
        services: tunnels
            .iter()
            .filter_map(|tunnel| {
                let (hostname, port) = direct_services.get(&tunnel.tunnel_id)?;
                let mut tunnel = tunnel.clone();
                tunnel.revision = i64::MAX;
                tunnel.enabled = false;
                Some(nexo_protocol::direct::Service {
                    tunnel,
                    hostname: hostname.clone(),
                    port: *port,
                    ipv6: "2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff".into(),
                    domain_certificate: true,
                })
            })
            .collect(),
    };
    if serde_json::to_vec(&direct_snapshot)
        .map_err(db_error)?
        .len()
        > nexo_protocol::direct::MAX_FRAME_SIZE
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "设备的 IPv6 直连配置过大，无法下发；请减少直连服务或证书数量",
        ));
    }
    // Agent 接收完整快照；证书累积超过控制帧上限会令该设备的全部服务失联。
    let message = nexo_protocol::ServerControlMessage::HelloAccepted {
        nodes: nodes::services::agent_nodes_from_db(db, device).map_err(db_error)?,
        capabilities: vec![
            nexo_protocol::direct::CAPABILITY.into(),
            nexo_protocol::nodes::CAPABILITY.into(),
        ],
        server_time: unix_now(),
        tunnels,
        tunnel_endpoint: state.tunnel_endpoint.clone(),
        udp_endpoint: state.udp_endpoint.clone(),
    };
    if serde_json::to_vec(&message).map_err(db_error)?.len()
        > nexo_tunnel::identity::MAX_CONTROL_FRAME
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "设备服务配置过大，无法下发；请减少此设备的服务或证书数量",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_adds_ca_without_changing_existing_services() {
        let db = Connection::open_in_memory().unwrap();
        initialize_database(&db, true).unwrap();
        db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('old','default','old','https','127.0.0.1',8006,0,0)", []).unwrap();
        db.execute("ALTER TABLE tunnels DROP COLUMN origin_ca_pem", [])
            .unwrap();
        migrate(&db).unwrap();
        migrate(&db).unwrap();
        let saved: (String, Option<String>) = db
            .query_row(
                "SELECT origin_tls_verification,origin_ca_pem FROM tunnels WHERE id='old'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(saved, ("system".into(), None));
    }

    #[test]
    fn pem_validation_accepts_only_bounded_public_certificates() {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .pem();
        assert!(validate(&cert).is_ok());
        assert!(validate(&format!("{cert}\n{cert}")).is_ok());
        for pem in [
            String::new(),
            "not a certificate".into(),
            format!("{cert}\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"),
            format!("{cert}\nextra text"),
            cert.repeat(MAX_CA_PEM_BYTES / cert.len() + 1),
        ] {
            assert_eq!(validate(&pem).unwrap_err().status, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn insecure_option_is_not_available_to_reverse_proxy() {
        let db = Connection::open_in_memory().unwrap();
        initialize_database(&db, true).unwrap();
        let mut input: TunnelInput = serde_json::from_value(serde_json::json!({
            "name":"proxy", "protocol":"https", "origin_protocol":"https",
            "service_mode":"reverse_proxy", "origin_tls_verification":"insecure_skip_verify",
            "local_address":"127.0.0.1", "local_port":8006
        }))
        .unwrap();
        let error = prepare(&db, "default", "new", &mut input).unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("仅 HTTPS 内网穿透"));
    }

    #[test]
    fn oversized_agent_snapshot_is_rejected_before_commit() {
        let (state, _) = crate::tests::domain_fixture();
        let db = state.db.lock().unwrap();
        db.execute("INSERT INTO devices(id,tenant_id,name,created_at,updated_at) VALUES('agent','default','Agent',0,0)", []).unwrap();
        let mut cert = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        cert.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let pem = cert
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .repeat(20);
        assert!(pem.len() <= MAX_CA_PEM_BYTES);
        for index in 0..200 {
            db.execute("INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,origin_protocol,origin_tls_verification,origin_ca_pem,local_address,local_port,created_at,updated_at) VALUES(?1,'default','agent','test','https','https','custom_ca',?2,'127.0.0.1',8006,0,0)", params![format!("s{index}"), pem]).unwrap();
        }
        let error = check_snapshot(&state, &db, Some("agent"))
            .expect_err("oversized snapshot must be rejected");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn oversized_ipv6_direct_snapshot_is_rejected_before_commit() {
        let (state, _) = crate::tests::domain_fixture();
        let db = state.db.lock().unwrap();
        db.execute("INSERT INTO devices(id,tenant_id,name,created_at,updated_at) VALUES('agent','default','Agent',0,0)", []).unwrap();
        db.execute("INSERT INTO public_domains(id,tenant_id,domain,created_at,updated_at) VALUES('domain','default','example.test',0,0)", []).unwrap();
        let mut cert = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        cert.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = cert
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap()
            .pem();
        let pem = cert.repeat(MAX_CA_PEM_BYTES / cert.len());
        assert!(pem.len() * 10 > nexo_protocol::direct::MAX_FRAME_SIZE);
        for index in 0..10 {
            db.execute("INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,origin_protocol,origin_tls_verification,origin_ca_pem,local_address,local_port,hostname,public_domain_id,ipv6_direct_enabled,created_at,updated_at) VALUES(?1,'default','agent','test','https','https','custom_ca',?2,'127.0.0.1',8006,?1,'domain',1,0,0)", params![format!("s{index}"), pem]).unwrap();
        }
        let error = check_snapshot(&state, &db, Some("agent"))
            .expect_err("oversized direct snapshot must be rejected");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);

        // 预留已停用的直连服务，避免稍后启用时才导致设备直连配置超限。
        db.execute("UPDATE tunnels SET enabled=0", []).unwrap();
        assert!(check_snapshot(&state, &db, Some("agent")).is_err());
        db.execute("UPDATE tunnels SET origin_tls_verification='system',origin_ca_pem=NULL WHERE id IN ('s0','s1','s2')", []).unwrap();
        assert!(check_snapshot(&state, &db, Some("agent")).is_ok());
    }
}
