//! HTTPS 公网端口属于服务；默认端口保留既有监听配置，自定义端口共享 Caddy 按域名分流。
use crate::*;

pub fn url(protocol: &str, host: &str, port: u16) -> String {
    if protocol == "https" && port != 443 {
        format!("https://{host}:{port}")
    } else {
        format!("{protocol}://{host}")
    }
}

pub fn migrate(db: &Connection) -> Result<()> {
    let tx = db.unchecked_transaction()?;
    if !tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tunnels') WHERE name='https_port')",
        [],
        |r| r.get::<_, bool>(0),
    )? {
        tx.execute("ALTER TABLE tunnels ADD COLUMN https_port INTEGER NOT NULL DEFAULT 443 CHECK(https_port BETWEEN 1 AND 65535)", [])?;
    }
    tx.execute_batch("CREATE TRIGGER IF NOT EXISTS revoke_service_access_port AFTER UPDATE OF https_port ON tunnels WHEN OLD.https_port IS NOT NEW.https_port BEGIN DELETE FROM service_access_sessions WHERE service_id=NEW.id; END;")?;
    tx.commit()?;
    Ok(())
}

/// 与服务保存处于同一事务；省略字段保留原值，协议切换只暂停使用而不丢弃端口。
pub fn prepare(
    state: &AppState,
    db: &Connection,
    tenant: &str,
    id: &str,
    input: &mut TunnelInput,
) -> Result<(), ApiError> {
    let port = match input.https_port {
        Some(port) => port,
        None => db
            .query_row(
                "SELECT https_port FROM tunnels WHERE id=?1 AND tenant_id=?2",
                params![id, tenant],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?
            .unwrap_or(443),
    };
    if port == 0 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "HTTPS 公网端口必须在 1–65535 之间",
        ));
    }
    input.https_port = Some(port);
    let node_scope = serde_json::to_string(
        &input
            .node_ids
            .clone()
            .unwrap_or_else(|| vec!["local".into()]),
    )
    .map_err(db_error)?;
    if matches!(
        input.protocol.as_str(),
        "http" | "https" | "tcp" | "tcp_udp"
    ) {
        let entry_port = if input.protocol == "https" {
            port
        } else if input.protocol == "http" {
            state.config.caddy.http_port()
        } else {
            input.public_port.unwrap_or(0)
        };
        let reserved:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM relay_nodes WHERE id!='local' AND id IN (SELECT value FROM json_each(?1)) AND (control_port=?2 OR ?2 IN (0,8282,8290) OR (?2 IN (80,443) OR ?2=?4) AND ?3 IN ('tcp','tcp_udp')))", params![node_scope,entry_port,input.protocol,state.config.caddy.http_port()], |r|r.get(0)).map_err(db_error)?;
        if reserved {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "公网端口与节点的系统监听冲突",
            ));
        }
    }
    let remote = input
        .node_ids
        .as_ref()
        .is_some_and(|nodes| nodes.iter().any(|n| n != "local"));
    if remote && (input.protocol == "http" || input.http_redirect_enabled == Some(true)) {
        let http_port = state.config.caddy.http_port();
        let conflict: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM relay_nodes WHERE id IN (SELECT value FROM json_each(?1)) AND control_port=?2) OR EXISTS(SELECT 1 FROM tunnels t JOIN service_nodes s ON s.service_id=t.id WHERE t.id!=?3 AND t.deleted_at IS NULL AND s.node_id IN (SELECT value FROM json_each(?1)) AND ((t.protocol IN ('tcp','tcp_udp') AND t.public_port=?2) OR (t.protocol='https' AND t.https_port=?2)))", params![node_scope,http_port,id], |r|r.get(0)).map_err(db_error)?;
        if [0, 443, 8282, 8290].contains(&http_port)
            || conflict
            || (input.protocol == "https" && port == http_port)
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "HTTP 公网端口与节点已有监听冲突",
            ));
        }
    }
    if input.protocol == "https" {
        let config = &state.config;
        let caddy = &config.caddy;
        let listen_port = |address: &str| {
            address
                .rsplit(':')
                .next()
                .and_then(|p| p.parse::<u16>().ok())
        };
        let admin_port = reqwest::Url::parse(&caddy.admin_url)
            .ok()
            .and_then(|u| u.port_or_known_default());
        let local = input
            .node_ids
            .as_ref()
            .is_none_or(|nodes| nodes.iter().any(|n| n == "local"));
        let remote = input
            .node_ids
            .as_ref()
            .is_some_and(|nodes| nodes.iter().any(|n| n != "local"));
        if (local
            && ([
                Some(config.http_addr.port()),
                Some(config.control_addr.port()),
                Some(config.tunnel_addr.port()),
                listen_port(&caddy.http_listen),
                admin_port,
            ]
            .contains(&Some(port))
                || (port != 443 && listen_port(&caddy.https_listen) == Some(port))))
            || (remote && [80, 8282, 8290, state.config.caddy.http_port()].contains(&port))
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "HTTPS 公网端口与服务器已有监听冲突",
            ));
        }
        let occupied: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels WHERE id!=?1 AND deleted_at IS NULL AND protocol IN ('tcp','tcp_udp') AND public_port=?2 AND (EXISTS(SELECT 1 FROM service_nodes sn WHERE sn.service_id=tunnels.id AND sn.node_id IN (SELECT value FROM json_each(?4))) OR (NOT EXISTS(SELECT 1 FROM service_nodes sn WHERE sn.service_id=tunnels.id) AND EXISTS(SELECT 1 FROM json_each(?4) WHERE value='local'))))", params![id, port,0,node_scope], |r| r.get(0)).map_err(db_error)?;
        if occupied {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "HTTPS 公网端口已被 TCP 服务占用",
            ));
        }
    } else if matches!(input.protocol.as_str(), "tcp" | "tcp_udp") {
        let occupied: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels WHERE id!=?1 AND deleted_at IS NULL AND protocol='https' AND https_port=?2 AND (EXISTS(SELECT 1 FROM service_nodes sn WHERE sn.service_id=tunnels.id AND sn.node_id IN (SELECT value FROM json_each(?4))) OR (NOT EXISTS(SELECT 1 FROM service_nodes sn WHERE sn.service_id=tunnels.id) AND EXISTS(SELECT 1 FROM json_each(?4) WHERE value='local'))))", params![id, input.public_port,0,node_scope], |r| r.get(0)).map_err(db_error)?;
        if occupied {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "公网端口已被 HTTPS 服务占用",
            ));
        }
    }
    Ok(())
}

pub fn save(db: &Connection, id: &str, input: &TunnelInput) -> Result<(), ApiError> {
    db.execute(
        "UPDATE tunnels SET https_port=?2 WHERE id=?1",
        params![id, input.https_port.unwrap_or(443)],
    )
    .map_err(db_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::Path;
    use serde_json::json;

    #[test]
    fn custom_node_http_port_is_reserved_and_https_can_use_8443() {
        let (mut state, _) = crate::tests::domain_fixture();
        Arc::make_mut(&mut state.config).caddy.http_listen = ":8080".into();
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO relay_nodes(id,name,approved,created_at) VALUES('remote','remote',1,0)",
            [],
        )
        .unwrap();
        let input = |protocol: &str, port: u16| {
            serde_json::from_value::<TunnelInput>(json!({
            "name":"test","protocol":protocol,"local_address":"localhost","local_port":8096,
            "https_port":port,"public_port":port,"node_ids":["remote"],"http_redirect_enabled":true
        })).unwrap()
        };
        assert!(prepare(&state, &db, "default", "new", &mut input("https", 8443)).is_ok());
        for protocol in ["https", "tcp"] {
            assert_eq!(
                prepare(&state, &db, "default", "new", &mut input(protocol, 8080))
                    .unwrap_err()
                    .status,
                StatusCode::CONFLICT
            );
        }
        assert!(prepare(&state, &db, "default", "new", &mut input("http", 443)).is_ok());
        db.execute(
            "UPDATE relay_nodes SET control_port=8080 WHERE id='remote'",
            [],
        )
        .unwrap();
        assert_eq!(
            prepare(&state, &db, "default", "new", &mut input("http", 443))
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn ports_roundtrip_preserve_revoke_and_reject_conflicts() {
        let (state, headers) = crate::tests::domain_fixture();
        let domain = crate::tests::add_test_domain(&state, &headers, "ports.test")
            .await
            .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE domain_settings SET verified=1,credential_file='credential-00000000-0000-4000-8000-000000000002.token' WHERE domain_id=?1",
                [&domain.id],
            )
            .unwrap();
        let body = |host: &str, port: Option<u16>| {
            serde_json::from_value::<TunnelInput>(json!({"service_mode":"reverse_proxy","name":host,"protocol":"https","local_address":"127.0.0.1","local_port":8096,"hostname":host,"public_domain_id":domain.id,"https_port":port})).unwrap()
        };
        let first = create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(body("emby", Some(9443))),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            first.public_address.as_deref(),
            Some("https://emby.ports.test:9443")
        );
        let _ = create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(body("photos", Some(9443))),
        )
        .await
        .unwrap();
        let updated = update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(first.id.clone()),
            Json(body("emby", None)),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(updated.https_port, 9443);
        state.db.lock().unwrap().execute("INSERT INTO service_access_sessions(digest,service_id,expires_at) VALUES('session',?1,9999999999)", [&first.id]).unwrap();
        let changed = update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(first.id.clone()),
            Json(body("emby", Some(443))),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            changed.public_address.as_deref(),
            Some("https://emby.ports.test")
        );
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM service_access_sessions", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        for port in [0, 80, 8280, 9890, 9891, 8290] {
            assert!(
                create_tunnel(
                    State(state.clone()),
                    headers.clone(),
                    Json(body("blocked", Some(port)))
                )
                .await
                .is_err(),
                "{port}"
            );
        }
        state.db.lock().unwrap().execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,public_port,created_at,updated_at) VALUES('tcp','default','tcp','tcp','127.0.0.1',80,24443,0,0)", []).unwrap();
        assert!(create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(body("blocked", Some(24443)))
        )
        .await
        .is_err());
    }

    #[test]
    fn migration_keeps_existing_rows_and_is_repeatable() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE tunnels(id TEXT); CREATE TABLE service_access_sessions(service_id TEXT); INSERT INTO tunnels VALUES('existing');").unwrap();
        migrate(&db).unwrap();
        migrate(&db).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT https_port FROM tunnels WHERE id='existing'",
                [],
                |r| r.get::<_, u16>(0)
            )
            .unwrap(),
            443
        );
    }
}
