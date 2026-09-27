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
        if [
            Some(config.http_addr.port()),
            Some(config.control_addr.port()),
            Some(config.tunnel_addr.port()),
            listen_port(&caddy.http_listen),
            admin_port,
        ]
        .contains(&Some(port))
            || (port != 443 && listen_port(&caddy.https_listen) == Some(port))
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "HTTPS 公网端口与服务器已有监听冲突",
            ));
        }
        let occupied: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels WHERE id!=?1 AND deleted_at IS NULL AND protocol IN ('tcp','tcp_udp') AND public_port=?2)", params![id, port], |r| r.get(0)).map_err(db_error)?;
        if occupied {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "HTTPS 公网端口已被 TCP 服务占用",
            ));
        }
    } else if matches!(input.protocol.as_str(), "tcp" | "tcp_udp") {
        let occupied: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels WHERE id!=?1 AND deleted_at IS NULL AND protocol='https' AND https_port=?2)", params![id, input.public_port], |r| r.get(0)).map_err(db_error)?;
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
                "UPDATE domain_settings SET verified=1 WHERE domain_id=?1",
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
