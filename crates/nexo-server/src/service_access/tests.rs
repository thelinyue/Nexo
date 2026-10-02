use super::*;
use crate::{create_tunnel, update_tunnel};
use axum::extract::Path;
const DOMAIN: &str = "00000000-0000-4000-8000-000000000001";

fn fixture() -> (AppState, HeaderMap) {
    let (state, headers) = crate::tests::domain_fixture();
    state.db.lock().unwrap().execute("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES(?1,'default','example.com',1,0,0)", [DOMAIN]).unwrap();
    state.db.lock().unwrap().execute("INSERT INTO domain_settings(domain_id,verification_token,certificate_mode,verified,credential_file) VALUES(?1,'test-proof','cloudflare_dns',1,'credential-00000000-0000-4000-8000-000000000002.token')", [DOMAIN]).unwrap();
    (state, headers)
}
fn input(mode: Option<&str>, password: Option<&str>) -> TunnelInput {
    serde_json::from_value(json!({"service_mode":"reverse_proxy","name":"家庭应用","protocol":"http","local_address":"127.0.0.1","local_port":3000,"hostname":"app","public_domain_id":DOMAIN,"access_mode":mode,"access_password":password})).unwrap()
}
fn request_headers(id: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        ("x-nexo-access-service", id),
        ("x-nexo-access-host", "app.example.com"),
        ("x-nexo-access-authority", "app.example.com"),
        ("x-nexo-access-proto", "http"),
        ("x-nexo-access-ip", "1.2.3.4"),
        ("x-nexo-access-method", "GET"),
        ("x-nexo-access-uri", "/photos?a=1"),
        ("origin", "http://app.example.com"),
    ] {
        headers.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    headers
}
fn access_state(state: &AppState) -> AccessState {
    AccessState {
        default_https_port: 443,
        db: state.db.clone(),
        security: state.security.clone(),
    }
}

#[test]
fn password_and_return_validation() {
    for p in ["abcd", "aB1!", "1234567890123456"] {
        assert!(validate_password(p).is_ok());
    }
    for p in ["", "abc", "12345678901234567", "abcd ", "中abcd", "ab\nc"] {
        assert!(validate_password(p).is_err());
    }
    for url in [
        "https://evil.test",
        "//evil.test",
        "/\\evil.test",
        "/.nexo-access/",
        "/a/../.nexo-access/login",
        "/\r\nevil",
    ] {
        assert_eq!(safe_return(url), "/");
    }
    assert_eq!(safe_return("/photos/a%2Fb?q=%2F"), "/photos/a%2Fb?q=%2F");
}

#[tokio::test]
async fn api_default_password_changes_and_tcp_rejection() {
    let _guard = auth::PASSWORD_TEST_LOCK.lock().await;
    let (state, headers) = fixture();
    let created = create_tunnel(
        State(state.clone()),
        headers.clone(),
        Json(input(None, None)),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(created.access_mode, "public");
    let update = |data| {
        update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
            Json(data),
        )
    };
    assert_eq!(
        update(input(Some("password"), None))
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    let saved = update(input(Some("password"), Some("pass!")))
        .await
        .unwrap()
        .0;
    assert_eq!(saved.access_mode, "password");
    assert!(!serde_json::to_string(&saved).unwrap().contains("pass!"));
    let old_hash: String = state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT access_password_hash FROM tunnels WHERE id=?1",
            [&created.id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(auth::verify_password("pass!", &old_hash));
    assert_eq!(
        update(input(None, Some(""))).await.unwrap().0.access_mode,
        "password"
    );
    let mut tcp = input(Some("password"), None);
    tcp.protocol = "tcp".into();
    tcp.service_mode = None;
    assert!(prepare(
        &state.db.lock().unwrap(),
        "default",
        &created.id,
        &mut tcp,
        None
    )
    .is_err());
    let _ = update(input(Some("public"), None)).await.unwrap();
    assert!(state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT access_password_hash IS NULL FROM tunnels WHERE id=?1",
            [&created.id],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    assert!(update(input(Some("password"), None)).await.is_err());
    let mut invalid = input(Some("unsupported"), None);
    assert!(prepare(
        &state.db.lock().unwrap(),
        "default",
        &created.id,
        &mut invalid,
        None
    )
    .is_err());
}

#[tokio::test]
async fn access_updates_keep_forwarding_revision_and_public_health() {
    let _guard = auth::PASSWORD_TEST_LOCK.lock().await;
    for service_mode in ["tunnel", "reverse_proxy"] {
        let (state, admin) = fixture();
        state.db.lock().unwrap().execute_batch("INSERT INTO devices(id,tenant_id,name,node_capable,created_at,updated_at) VALUES('agent','default','Agent',1,0,0);
            INSERT INTO device_certificates(device_id,certificate_pem) VALUES('agent','test-certificate');
            INSERT INTO relay_nodes(id,name,public_ipv4,approved,created_at) VALUES('node-test','测试入口','203.0.113.10',1,0);
            INSERT INTO relay_node_grants VALUES('node-test','default');").unwrap();
        let make_input = |mode, password| {
            let mut data = input(Some(mode), password);
            data.service_mode = Some(service_mode.into());
            if service_mode == "tunnel" {
                data.device_id = Some("agent".into());
                data.node_ids = Some(vec!["local".into(), "node-test".into()]);
                data.distribution_mode = Some("dns".into());
            }
            data
        };
        let created = create_tunnel(
            State(state.clone()),
            admin.clone(),
            Json(make_input("public", None)),
        )
        .await
        .unwrap()
        .0;
        let checked_at = unix_now() - 1;
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE devices SET status='online',last_seen_at=?1 WHERE id='agent'",
                [checked_at],
            )
            .unwrap();
            db.execute(
                "UPDATE relay_nodes SET last_seen=?1 WHERE id='node-test'",
                [checked_at],
            )
            .unwrap();
            db.execute(
                "UPDATE tunnels SET apply_status='ready',apply_error=NULL WHERE id=?1",
                [&created.id],
            )
            .unwrap();
            db.execute("INSERT INTO tunnel_applied_states(tunnel_id,revision,status,updated_at) VALUES(?1,?2,'ready',?3)", params![created.id,created.apply_revision,checked_at]).unwrap();
            for node in ["local", "node-test"] {
                db.execute("INSERT OR REPLACE INTO relay_service_health(node_id,service_id,revision,successes,healthy,checked_at,public_probe_supported) VALUES(?1,?2,?3,3,1,?4,1)", params![node,created.id,created.apply_revision,checked_at]).unwrap();
                db.execute("INSERT INTO relay_public_health(node_id,service_id,revision,successes,healthy,checked_at,probe_kind,address) VALUES(?1,?2,?3,3,1,?4,'http',?5)", params![node,created.id,created.apply_revision,checked_at,if node == "local" { "" } else { "203.0.113.10" }]).unwrap();
            }
            db.execute(
                "INSERT INTO relay_dns_state VALUES(?1,?2,?3,NULL)",
                params![created.id, created.apply_revision, checked_at],
            )
            .unwrap();
        }
        let desired = crate::desired_tunnels(&state, "agent").unwrap();
        let access = access_state(&state);
        let mut visitor = request_headers(&created.id);
        assert_eq!(
            check_inner(&access, &visitor).unwrap().status(),
            StatusCode::NO_CONTENT
        );

        // 公开转认证、密码轮换和恢复公开都只改变认证；节点继续同步规则，健康样本不重新累计。
        for (mode, password, expected) in [
            ("password", Some("pass!"), StatusCode::UNAUTHORIZED),
            ("password", Some("new!"), StatusCode::UNAUTHORIZED),
            ("public", None, StatusCode::NO_CONTENT),
        ] {
            state.db.lock().unwrap().execute("INSERT INTO service_access_sessions(digest,service_id,expires_at) VALUES(?1,?2,?3)", params![auth::digest("old-session"),created.id,unix_now()+3600]).unwrap();
            visitor.insert(
                header::COOKIE,
                format!("nexo_access_{}=old-session", created.id.replace('-', ""))
                    .parse()
                    .unwrap(),
            );
            assert_eq!(
                check_inner(&access, &visitor).unwrap().status(),
                StatusCode::NO_CONTENT
            );
            let updated = update_tunnel(
                State(state.clone()),
                admin.clone(),
                Path(created.id.clone()),
                Json(make_input(mode, password)),
            )
            .await
            .unwrap()
            .0;
            assert_eq!(updated.access_mode, mode);
            assert_eq!(updated.apply_revision, created.apply_revision);
            assert_eq!(updated.apply_status, "ready");
            assert_eq!(updated.apply_error, None);
            assert_eq!(crate::desired_tunnels(&state, "agent").unwrap(), desired);
            assert_eq!(check_inner(&access, &visitor).unwrap().status(), expected);
            {
                let db = state.db.lock().unwrap();
                assert_eq!(
                    db.query_row(
                        "SELECT COUNT(*) FROM service_access_sessions WHERE service_id=?1",
                        [&created.id],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                    0
                );
                for table in ["relay_service_health", "relay_public_health"] {
                    assert_eq!(db.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE service_id=?1 AND revision=?2 AND successes=3 AND healthy=1 AND checked_at=?3 AND error IS NULL"), params![created.id,created.apply_revision,checked_at], |r| r.get::<_, i64>(0)).unwrap(), 2);
                }
                assert!(db.query_row("SELECT revision=?2 AND synced_at=?3 AND error IS NULL FROM relay_dns_state WHERE service_id=?1", params![created.id,created.apply_revision,checked_at], |r| r.get::<_, bool>(0)).unwrap());
            }
            if service_mode == "tunnel" {
                let snapshot = crate::nodes::control::snapshot(&state, "node-test").unwrap();
                assert_eq!(snapshot.services.len(), 1);
                assert_eq!(snapshot.services[0].access_mode, mode);
                assert_eq!(snapshot.services[0].revision, created.apply_revision);
            }
            if let Some(password) = password {
                let logged = login_inner(
                    &access,
                    &visitor,
                    Login {
                        password: password.into(),
                        return_to: "/".into(),
                    },
                )
                .await
                .unwrap();
                visitor.insert(
                    header::COOKIE,
                    logged.headers()[header::SET_COOKIE]
                        .to_str()
                        .unwrap()
                        .split(';')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap(),
                );
                assert_eq!(
                    check_inner(&access, &visitor).unwrap().status(),
                    StatusCode::NO_CONTENT
                );
                if password == "new!" {
                    assert_eq!(
                        login_inner(
                            &access,
                            &visitor,
                            Login {
                                password: "pass!".into(),
                                return_to: "/".into()
                            }
                        )
                        .await
                        .unwrap_err()
                        .status,
                        StatusCode::UNAUTHORIZED
                    );
                }
            }
        }
        // 认证与目标地址同时变化时，仍按网络配置更新重新应用，不能跳过真实连通性检查。
        let mut changed = make_input("password", Some("final!"));
        changed.local_port = 3001;
        let updated = update_tunnel(State(state.clone()), admin, Path(created.id), Json(changed))
            .await
            .unwrap()
            .0;
        assert_eq!(updated.access_mode, "password");
        assert_eq!(updated.apply_revision, created.apply_revision + 1);
        assert_ne!(updated.apply_status, "ready");
    }
}

#[tokio::test]
async fn auth_cookie_isolated_expiring_revoked_and_not_forwarded() {
    let _guard = auth::PASSWORD_TEST_LOCK.lock().await;
    let (state, admin) = fixture();
    let created = create_tunnel(
        State(state.clone()),
        admin.clone(),
        Json(input(Some("password"), Some("pass!"))),
    )
    .await
    .unwrap()
    .0;
    let access = access_state(&state);
    let mut headers = request_headers(&created.id);
    assert_eq!(
        check_inner(&access, &headers).unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    headers.insert("accept", "text/html,application/xhtml+xml".parse().unwrap());
    assert_eq!(
        check_inner(&access, &headers).unwrap().status(),
        StatusCode::SEE_OTHER
    );
    headers.insert("sec-fetch-mode", "cors".parse().unwrap());
    assert_eq!(
        check_inner(&access, &headers).unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    headers.remove("accept");
    headers.insert("sec-fetch-mode", "navigate".parse().unwrap());
    headers.insert("sec-fetch-dest", "document".parse().unwrap());
    let response = check_inner(&access, &headers).unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .contains("return=%2Fphotos%3Fa%3D1"));
    let mut foreign = headers.clone();
    foreign.insert("origin", "https://evil.test".parse().unwrap());
    assert_eq!(
        login_inner(
            &access,
            &foreign,
            Login {
                password: "pass!".into(),
                return_to: "/".into()
            }
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        login_inner(
            &access,
            &headers,
            Login {
                password: "wrong".into(),
                return_to: "/".into()
            }
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::UNAUTHORIZED
    );
    let logged = login_inner(
        &access,
        &headers,
        Login {
            password: "pass!".into(),
            return_to: "//evil.test".into(),
        },
    )
    .await
    .unwrap();
    let cookie = logged.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("HttpOnly; SameSite=Lax; Max-Age=86400"));
    assert!(!cookie.contains("Domain="));
    assert!(!cookie.contains("Secure"));
    let cookie = cookie.split(';').next().unwrap().to_owned();
    headers.insert(
        header::COOKIE,
        format!("app=kept; {cookie}; nexo_access_other=secret")
            .parse()
            .unwrap(),
    );
    let allowed = check_inner(&access, &headers).unwrap();
    assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
    assert_eq!(allowed.headers()["x-nexo-upstream-cookie"], "app=kept");
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE service_access_sessions SET expires_at=0", [])
        .unwrap();
    assert_eq!(
        check_inner(&access, &headers).unwrap().status(),
        StatusCode::SEE_OTHER
    );
    let logged = login_inner(
        &access,
        &headers,
        Login {
            password: "pass!".into(),
            return_to: "/".into(),
        },
    )
    .await
    .unwrap();
    headers.insert(
        header::COOKIE,
        logged.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .parse()
            .unwrap(),
    );
    let _ = update_tunnel(
        State(state.clone()),
        admin,
        Path(created.id.clone()),
        Json(input(None, Some("new!"))),
    )
    .await
    .unwrap();
    assert_eq!(
        check_inner(&access, &headers).unwrap().status(),
        StatusCode::SEE_OTHER
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
}

#[tokio::test]
async fn rate_limit_and_host_checks() {
    let _guard = auth::PASSWORD_TEST_LOCK.lock().await;
    let (state, admin) = fixture();
    let created = create_tunnel(
        State(state.clone()),
        admin,
        Json(input(Some("password"), Some("pass!"))),
    )
    .await
    .unwrap()
    .0;
    let access = access_state(&state);
    let mut headers = request_headers(&created.id);
    for _ in 0..20 {
        assert!(state.security.allow(
            format!("service-access:{}:1.2.3.4", created.id),
            20,
            unix_now()
        ));
    }
    assert_eq!(
        login_inner(
            &access,
            &headers,
            Login {
                password: "pass!".into(),
                return_to: "/".into()
            }
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::TOO_MANY_REQUESTS
    );
    headers.insert("x-nexo-access-host", "other.example.com".parse().unwrap());
    assert_eq!(
        check_inner(&access, &headers).unwrap_err().status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn schema_revokes_sessions_on_all_service_mutations() {
    let (state, admin) = fixture();
    let created = create_tunnel(State(state.clone()), admin, Json(input(None, None)))
        .await
        .unwrap()
        .0;
    let db = state.db.lock().unwrap();
    for mutation in [
        "hostname='new'",
        "protocol='https'",
        "enabled=0",
        "enabled=1,access_mode='password',access_password_hash='changed'",
        "deleted_at=1",
    ] {
        db.execute(
            "INSERT INTO service_access_sessions VALUES('token',?1,9999999999)",
            [&created.id],
        )
        .unwrap();
        db.execute(
            &format!("UPDATE tunnels SET {mutation} WHERE id=?1"),
            [&created.id],
        )
        .unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM service_access_sessions", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn https_authority_must_match_service_port() {
    let (state, headers) = fixture();
    let mut data = input(None, None);
    data.protocol = "https".into();
    data.https_port = Some(9443);
    let created = create_tunnel(State(state.clone()), headers, Json(data))
        .await
        .unwrap()
        .0;
    let access = access_state(&state);
    let mut request = request_headers(&created.id);
    request.insert("x-nexo-access-proto", "https".parse().unwrap());
    assert!(check_inner(&access, &request).is_err());
    request.insert(
        "x-nexo-access-authority",
        "app.example.com:9443".parse().unwrap(),
    );
    assert_eq!(
        check_inner(&access, &request).unwrap().status(),
        StatusCode::NO_CONTENT
    );
    request.insert(
        "x-nexo-access-authority",
        "app.example.com:443".parse().unwrap(),
    );
    assert!(check_inner(&access, &request).is_err());
}
