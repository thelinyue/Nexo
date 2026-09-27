use super::*;
use crate::{create_tunnel, update_tunnel};
use axum::extract::Path;

fn fixture() -> (AppState, HeaderMap) {
    let (state, headers) = crate::tests::domain_fixture();
    state.db.lock().unwrap().execute("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES('domain','default','example.com',1,0,0)", []).unwrap();
    (state, headers)
}
fn input(mode: Option<&str>, password: Option<&str>) -> TunnelInput {
    serde_json::from_value(json!({"service_mode":"reverse_proxy","name":"家庭应用","protocol":"http","local_address":"127.0.0.1","local_port":3000,"hostname":"app","public_domain_id":"domain","access_mode":mode,"access_password":password})).unwrap()
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
async fn api_default_compatibility_password_changes_and_tcp_rejection() {
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
async fn schema_is_idempotent_and_revokes_all_service_mutations() {
    let (state, admin) = fixture();
    let created = create_tunnel(State(state.clone()), admin, Json(input(None, None)))
        .await
        .unwrap()
        .0;
    let db = state.db.lock().unwrap();
    initialize_schema(&db).unwrap();
    initialize_schema(&db).unwrap();
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
