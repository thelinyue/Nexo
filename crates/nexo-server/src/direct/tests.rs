use super::*;
use serde_json::json;

pub(crate) fn fixture() -> (AppState, String) {
    let (state, _) = crate::tests::domain_fixture();
    let domain = Uuid::new_v4().to_string();
    let db = state.db.lock().unwrap();
    db.execute("INSERT INTO devices(id,tenant_id,name,status,created_at,updated_at) VALUES('agent','default','NAS','online',0,0),('other','default','other','online',0,0)",[]).unwrap();
    db.execute("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES(?1,'default','direct.test',1,0,0)",[&domain]).unwrap();
    db.execute("INSERT INTO domain_settings(domain_id,certificate_mode,verified,verification_token) VALUES(?1,'cloudflare_dns',1,'proof')",[&domain]).unwrap();
    let file = crate::domains::write_credential(
        &state
            .domain_runtime
            .supervisor
            .config()
            .cloudflare_token_root,
        &domain,
        "test-token",
    )
    .unwrap();
    db.execute(
        "UPDATE domain_settings SET credential_file=?1 WHERE domain_id=?2",
        params![file, domain],
    )
    .unwrap();
    db.execute("INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,local_address,local_port,hostname,public_domain_id,https_port,ipv6_direct_enabled,created_at,updated_at) VALUES('media','default','agent','媒体','https','127.0.0.1',8096,'emby',?1,9443,1,0,0)",[&domain]).unwrap();
    drop(db);
    sync(&state, "agent", vec!["2001:4860::123".into()], vec![]).unwrap();
    (state, domain)
}

#[test]
fn ipv6_candidates_exclude_nonpublic_and_require_explicit_multiple_selection() {
    for ip in [
        "::",
        "::1",
        "fe80::1",
        "fd00::1",
        "ff02::1",
        "2001:db8::1",
        "::ffff:8.8.8.8",
        "1.2.3.4",
    ] {
        assert!(!public_address(ip), "{ip}");
    }
    let (state, _) = fixture();
    assert_eq!(
        service(&state, "agent", "media", 1).unwrap().ipv6,
        "2001:4860::123"
    );
    sync(
        &state,
        "agent",
        vec!["2001:4860::124".into(), "2400:3200::1".into()],
        vec![],
    )
    .unwrap();
    assert!(service(&state, "agent", "media", 1).is_err());
    sync(&state, "agent", vec!["2400:3200::1".into()], vec![]).unwrap();
    assert_eq!(
        service(&state, "agent", "media", 1).unwrap().ipv6,
        "2400:3200::1"
    );
}

#[tokio::test]
async fn authority_device_revision_and_csr_boundaries_fail_closed() {
    let (state, _) = fixture();
    assert!(service(&state, "other", "media", 1).is_err());
    assert!(service(&state, "agent", "media", 2).is_err());
    let svc = service(&state, "agent", "media", 1).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    for names in [
        vec!["other.direct.test"],
        vec!["emby.direct.test", "other.direct.test"],
        vec!["*.direct.test"],
    ] {
        let csr =
            rcgen::CertificateParams::new(names.into_iter().map(str::to_owned).collect::<Vec<_>>())
                .unwrap()
                .serialize_request(&key)
                .unwrap()
                .pem()
                .unwrap();
        assert!(certificates::request(&state, "agent", &svc, csr)
            .await
            .is_err());
    }
    let request = |authority: &str| Request::Access {
        service_id: "media".into(),
        revision: 1,
        path: "/check".into(),
        headers: vec![
            ("x-nexo-access-authority".into(), authority.into()),
            ("x-nexo-access-method".into(), "GET".into()),
        ],
        body: vec![],
    };
    let DirectResponse::Access { status, .. } =
        handle(&state, "agent", request("emby.direct.test:9443"))
            .await
            .unwrap()
    else {
        panic!()
    };
    assert_eq!(status, 204);
    let DirectResponse::Access { status, .. } =
        handle(&state, "agent", request("emby.direct.test:443"))
            .await
            .unwrap()
    else {
        panic!()
    };
    assert_eq!(status, 400);
    assert!(handle(&state, "other", request("emby.direct.test:9443"))
        .await
        .is_err());
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE tenants SET enabled=0 WHERE id='default'", [])
        .unwrap();
    assert!(handle(&state, "agent", request("emby.direct.test:9443"))
        .await
        .is_err());
}

#[test]
fn old_ready_report_cannot_publish_changed_address_or_revision() {
    let (state, _) = fixture();
    let report = |address: &str, revision| Report {
        address: address.into(),
        service_id: "media".into(),
        revision,
        ready: true,
        error: None,
    };
    sync(
        &state,
        "agent",
        vec!["2001:4860::124".into()],
        vec![report("2001:4860::123", 1)],
    )
    .unwrap();
    assert_eq!(status(&state.db.lock().unwrap(), "media")["ready"], false);
    sync(
        &state,
        "agent",
        vec!["2001:4860::124".into()],
        vec![report("2001:4860::124", 1)],
    )
    .unwrap();
    assert_eq!(status(&state.db.lock().unwrap(), "media")["ready"], true);
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE tunnels SET apply_revision=2 WHERE id='media'", [])
        .unwrap();
    sync(
        &state,
        "agent",
        vec!["2001:4860::124".into()],
        vec![report("2001:4860::124", 1)],
    )
    .unwrap();
    assert_eq!(status(&state.db.lock().unwrap(), "media")["ready"], false);
    assert_eq!(
        status(&state.db.lock().unwrap(), "media")["public_reachability"],
        "unverified"
    );
}

#[tokio::test]
async fn direct_login_shares_existing_service_session_and_revocation() {
    let _guard = crate::auth::PASSWORD_TEST_LOCK.lock().await;
    let (state, _) = fixture();
    let hash = auth::hash_password("pass!").unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE tunnels SET access_mode='password',access_password_hash=?1 WHERE id='media'",
            [hash],
        )
        .unwrap();
    let svc = service(&state, "agent", "media", 1).unwrap();
    let headers = vec![
        (
            "x-nexo-access-authority".into(),
            "emby.direct.test:9443".into(),
        ),
        ("origin".into(), "https://emby.direct.test:9443".into()),
        ("x-nexo-access-ip".into(), "2001:4860::5".into()),
        ("x-nexo-access-method".into(), "POST".into()),
    ];
    let response = crate::service_access::direct_request(
        &state,
        &svc,
        "/.nexo-access/login".into(),
        headers.clone(),
        serde_json::to_vec(&json!({"password":"pass!","return_to":"/videos"})).unwrap(),
    )
    .await
    .unwrap();
    let DirectResponse::Access {
        status,
        headers: login,
        ..
    } = response
    else {
        panic!()
    };
    assert_eq!(status, 200);
    let cookie = login
        .iter()
        .find(|(k, _)| k == "set-cookie")
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut headers = headers;
    headers.push(("cookie".into(), cookie));
    let DirectResponse::Access { status, .. } = crate::service_access::direct_request(
        &state,
        &svc,
        "/check".into(),
        headers.clone(),
        vec![],
    )
    .await
    .unwrap() else {
        panic!()
    };
    assert_eq!(status, 204);
    // 真实本机认证 HTTP 接口读取同一会话，证明切换转发路径不需要再次登录。
    let access = crate::service_access::Runtime::start(&state).await.unwrap();
    let mut request = reqwest::Client::new().get(format!("http://{}/check", access.address));
    for (k, v) in &headers {
        request = request.header(k, v);
    }
    let response = request
        .header("x-nexo-access-service", "media")
        .header("x-nexo-access-host", "emby.direct.test")
        .header("x-nexo-access-proto", "https")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE tunnels SET https_port=8443 WHERE id='media'", [])
        .unwrap();
    assert_eq!(
        state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM service_access_sessions", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
