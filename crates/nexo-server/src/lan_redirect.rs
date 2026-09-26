//! 内网跳转复用本地目标，只保存开关；回环地址和主机名不能作为访客的直连目标。

use crate::{ApiError, TunnelInput};
use axum::http::StatusCode;
use reqwest::Url;
use rusqlite::{params, Connection, OptionalExtension};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// 旧服务一律关闭；仅增量添加开关，不改变本地目标和既有访问路径。
pub fn initialize_schema(db: &Connection) -> anyhow::Result<()> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tunnels') WHERE name='lan_redirect_enabled')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        db.execute_batch(
            "ALTER TABLE tunnels ADD COLUMN lan_redirect_enabled INTEGER NOT NULL DEFAULT 0",
        )?;
    }
    Ok(())
}

/// 每次由真实回源协议、IP 和端口生成地址，公网 HTTPS 不代表本地应用也提供 HTTPS。
pub fn target_url(
    local_address: &str,
    local_port: u16,
    origin_protocol: Option<&str>,
) -> Result<String, ApiError> {
    let invalid = || {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "内网重定向要求本地地址为可直接访问的私有 IP，不能使用回环地址、主机名或公网 IP",
        )
    };
    let address = local_address.trim();
    let ip = if let Some(host) = address
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        host.parse::<Ipv6Addr>().map(IpAddr::V6)
    } else {
        address.parse::<IpAddr>()
    }
    .map_err(|_| invalid())?;
    let private = match ip {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    };
    if !private {
        return Err(invalid());
    }
    if local_port == 0 {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "本地端口无效"));
    }
    let protocol = origin_protocol.unwrap_or("http");
    if !matches!(protocol, "http" | "https") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "本地回源协议不支持内网重定向",
        ));
    }
    let url = Url::parse(&format!("{protocol}://{}", SocketAddr::new(ip, local_port)))
        .map_err(|_| invalid())?;
    Ok(url.origin().ascii_serialization())
}

/// 与服务写入共用事务和租户条件。省略开关时保留原值，开启时验证更新后的本地目标。
pub fn prepare(
    db: &Connection,
    tenant: &str,
    id: &str,
    input: &mut TunnelInput,
) -> Result<(), ApiError> {
    if input.protocol == "tcp" {
        if input.lan_redirect_enabled == Some(true) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "TCP 服务不支持内网重定向",
            ));
        }
        input.lan_redirect_enabled = Some(false);
        return Ok(());
    }
    let (previous_enabled, origin_protocol) = db.query_row(
        "SELECT lan_redirect_enabled,origin_protocol FROM tunnels WHERE id=?1 AND tenant_id=?2 AND deleted_at IS NULL",
        params![id, tenant],
        |row| Ok((row.get::<_, bool>(0)?, row.get::<_, Option<String>>(1)?)),
    ).optional().map_err(crate::db_error)?.unwrap_or((false, None));
    let enabled = input.lan_redirect_enabled.unwrap_or(previous_enabled);
    if enabled {
        target_url(
            &input.local_address,
            input.local_port,
            origin_protocol.as_deref(),
        )?;
    }
    input.lan_redirect_enabled = Some(enabled);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Path, State},
        http::HeaderMap,
        Json,
    };
    use serde_json::{json, Value};

    async fn web_fixture() -> (crate::AppState, HeaderMap, Value) {
        let (state, headers) = crate::tests::domain_fixture();
        let domain = crate::tests::add_test_domain(&state, &headers, "example.com")
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
        let body = json!({
            "name":"nas", "protocol":"http", "local_address":"192.168.1.10",
            "local_port":8080, "hostname":"nas", "public_domain_id":domain.id,
        });
        (state, headers, body)
    }

    #[test]
    fn target_follows_the_local_ip_port_and_origin_protocol() {
        for (address, port, protocol, expected) in [
            ("192.168.1.10", 8080, None, "http://192.168.1.10:8080"),
            ("10.0.0.1", 80, None, "http://10.0.0.1"),
            ("172.16.0.1", 443, Some("https"), "https://172.16.0.1"),
            (
                "FD00::1234",
                8443,
                Some("https"),
                "https://[fd00::1234]:8443",
            ),
            ("[fd00::1234]", 8080, None, "http://[fd00::1234]:8080"),
        ] {
            assert_eq!(target_url(address, port, protocol).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_local_targets_that_cannot_identify_a_private_destination() {
        for address in [
            "",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "100.64.0.1",
            "172.32.0.1",
            "8.8.8.8",
            "localhost",
            "nas.local",
            "::1",
            "::",
            "fe80::1",
            "2001:db8::1",
            "::ffff:192.168.1.1",
            "http://192.168.1.1",
            "192.168.1.1:8080",
            "192.168.1.1/app",
            "10.1",
            "0xa000001",
            "167772161",
            "010.0.0.1",
            "[10.0.0.1]",
            "[[fd00::1]]",
        ] {
            assert!(target_url(address, 8080, None).is_err(), "{address:?}");
        }
        assert!(target_url("192.168.1.1", 0, None).is_err());
        assert!(target_url("192.168.1.1", 8080, Some("ftp")).is_err());
    }

    #[test]
    fn existing_database_gets_a_disabled_switch_and_preserves_it_on_reopen() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!("../../../migrations/v0.2.0_baseline.sql"))
            .unwrap();
        db.execute("INSERT INTO tunnels (id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES ('existing','default','nas','http','127.0.0.1',8080,0,0)", []).unwrap();
        crate::initialize_database(&db, false).unwrap();
        let enabled = || {
            db.query_row(
                "SELECT lan_redirect_enabled FROM tunnels WHERE id='existing'",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap()
        };
        assert!(!enabled());
        db.execute("UPDATE tunnels SET lan_redirect_enabled=1,local_address='192.168.1.10' WHERE id='existing'", []).unwrap();
        crate::initialize_database(&db, false).unwrap();
        assert!(enabled());
    }

    #[tokio::test]
    async fn api_persists_only_the_switch_and_validates_the_updated_local_target() {
        let (state, headers, mut body) = web_fixture().await;
        let Json(created) = crate::create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(serde_json::from_value(body.clone()).unwrap()),
        )
        .await
        .unwrap();
        assert!(!created.lan_redirect_enabled);
        assert!(serde_json::to_value(&created)
            .unwrap()
            .get("lan_redirect_url")
            .is_none());

        body["lan_redirect_enabled"] = json!(true);
        let Json(enabled) = crate::update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
            Json(serde_json::from_value(body.clone()).unwrap()),
        )
        .await
        .unwrap();
        assert!(enabled.lan_redirect_enabled);
        body.as_object_mut().unwrap().remove("lan_redirect_enabled");
        body["local_address"] = json!("10.0.0.8");
        body["local_port"] = json!(9000);
        let Json(changed) = crate::update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
            Json(serde_json::from_value(body.clone()).unwrap()),
        )
        .await
        .unwrap();
        assert!(changed.lan_redirect_enabled);
        assert_eq!(changed.local_address, "10.0.0.8");
        assert_eq!(changed.local_port, 9000);

        body["local_address"] = json!("127.0.0.1");
        let error = crate::update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
            Json(serde_json::from_value(body.clone()).unwrap()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            crate::read_tunnel(&state, "default", &created.id, &headers)
                .unwrap()
                .local_address,
            "10.0.0.8"
        );
        body["lan_redirect_enabled"] = json!(false);
        let Json(disabled) = crate::update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
            Json(serde_json::from_value(body.clone()).unwrap()),
        )
        .await
        .unwrap();
        assert!(!disabled.lan_redirect_enabled);
        assert_eq!(disabled.local_address, "127.0.0.1");
        body["protocol"] = json!("tcp");
        let Json(tcp) = crate::update_tunnel(
            State(state.clone()),
            headers,
            Path(created.id),
            Json(serde_json::from_value(body).unwrap()),
        )
        .await
        .unwrap();
        assert!(!tcp.lan_redirect_enabled);
    }

    #[tokio::test]
    async fn api_rejects_invalid_enabling_and_keeps_authorization_boundaries() {
        let (state, headers, mut body) = web_fixture().await;
        body["lan_redirect_enabled"] = json!(true);
        for address in ["127.0.0.1", "nas.local", "8.8.8.8"] {
            body["local_address"] = json!(address);
            assert_eq!(
                crate::create_tunnel(
                    State(state.clone()),
                    headers.clone(),
                    Json(serde_json::from_value(body.clone()).unwrap())
                )
                .await
                .unwrap_err()
                .status,
                StatusCode::BAD_REQUEST
            );
        }
        body["local_address"] = json!("fd00::10");
        body["protocol"] = json!("tcp");
        assert_eq!(
            crate::create_tunnel(
                State(state.clone()),
                headers.clone(),
                Json(serde_json::from_value(body.clone()).unwrap())
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
        body["protocol"] = json!("http");
        let Json(created) = crate::create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(serde_json::from_value(body.clone()).unwrap()),
        )
        .await
        .unwrap();
        assert!(created.lan_redirect_enabled);
        let mut without_csrf = headers.clone();
        without_csrf.remove("x-nexo-csrf");
        assert_eq!(
            crate::update_tunnel(
                State(state.clone()),
                without_csrf,
                Path(created.id.clone()),
                Json(serde_json::from_value(body.clone()).unwrap())
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        state.db.lock().unwrap().execute_batch(
            "INSERT INTO tenants(id,name,created_at) VALUES ('other','other',0);
            INSERT INTO tunnels (id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES ('foreign','other','foreign','http','127.0.0.1',8080,0,0);",
        ).unwrap();
        assert_eq!(
            crate::update_tunnel(
                State(state.clone()),
                headers.clone(),
                Path("foreign".into()),
                Json(serde_json::from_value(body).unwrap())
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            crate::list_tunnels(State(state.clone()), headers)
                .await
                .unwrap()
                .0
                .len(),
            1
        );
    }
}
