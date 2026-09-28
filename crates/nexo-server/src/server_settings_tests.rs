use super::*;

fn candidate() -> Result<Json<Input>, axum::extract::rejection::JsonRejection> {
    Ok(Json(Input {
        relay_ipv4: None,
        management_entry: None,
        public_ips: vec!["203.0.113.1".parse().unwrap()],
    }))
}

#[tokio::test]
async fn commit_before_publish_preserves_limits_and_requires_admin_csrf() {
    let (state, headers) = crate::tests::domain_fixture();
    assert!(state
        .security
        .allow("login:test".into(), 1, crate::unix_now()));
    let _ = update(State(state.clone()), headers.clone(), candidate())
        .await
        .unwrap();
    assert!(load(&state.db.lock().unwrap()).unwrap().managed);
    assert!(!state
        .security
        .allow("login:test".into(), 1, crate::unix_now()));
    state.db.lock().unwrap().execute_batch("CREATE TRIGGER deny_settings BEFORE UPDATE ON server_settings BEGIN SELECT RAISE(ABORT,'test write failure'); END;").unwrap();
    let input = Ok(Json(Input {
        relay_ipv4: None,
        management_entry: None,
        public_ips: vec![],
    }));
    assert!(update(State(state.clone()), headers.clone(), input)
        .await
        .is_err());
    assert_eq!(state.security.settings().unwrap().public_ips.len(), 1);
    assert_eq!(load(&state.db.lock().unwrap()).unwrap().public_ips.len(), 1);
    let mut missing = headers.clone();
    missing.remove("x-nexo-csrf");
    assert_eq!(
        update(State(state.clone()), missing, candidate())
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE users SET role='tenant'", [])
        .unwrap();
    assert_eq!(
        get(State(state.clone()), headers.clone())
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        update(State(state), headers, candidate())
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn http_can_configure_management_with_conflict_and_ownership_checks() {
    let (mut state, mut headers) = crate::tests::domain_fixture();
    let mut cfg = crate::caddy::CaddyRuntimeConfig::new(
        &state.config.runtime_dir,
        &crate::config::Caddy::default(),
    );
    cfg.admin_url = "http://127.0.0.1:0".into();
    state.domain_runtime =
        std::sync::Arc::new(crate::domain_runtime::DomainRuntimeManager::new(cfg));
    let domain = crate::tests::add_test_domain(&state, &headers, "example.test")
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
    headers.insert("host", "192.0.2.1:8280".parse().unwrap());
    headers.insert("origin", "http://192.0.2.1:8280".parse().unwrap());
    let entry = || {
        Ok(Json(Input {
            relay_ipv4: None,
            management_entry: Some(ManagementEntry {
                domain_id: domain.id.clone(),
                hostname: "nexo".into(),
            }),
            public_ips: vec![],
        }))
    };
    let response = update(State(state.clone()), headers.clone(), entry())
        .await
        .unwrap()
        .0;
    assert_eq!(response.public_url, "https://nexo.example.test");
    assert_eq!(response.status, "failed"); // Caddy 未运行，不能把落库当作路由已生效。
    let saved = state.security.settings().unwrap();
    assert_eq!(
        saved.trusted_proxies,
        vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
    );
    {
        let db = state.db.lock().unwrap();
        assert!(ensure_host_available(&db, "nexo.example.test").is_err());
        assert!(ensure_domain_unused(&db, &domain.id).is_err());
    }
    let mut https_headers = headers.clone();
    https_headers.insert("host", "nexo.example.test".parse().unwrap());
    https_headers.insert("x-forwarded-proto", "https".parse().unwrap());
    assert!(saved.secure(Some("127.0.0.1".parse().unwrap()), &https_headers));
    assert!(!saved.secure(Some("192.0.2.1".parse().unwrap()), &https_headers));
    https_headers.insert("host", "other.example.test".parse().unwrap());
    assert!(!saved.secure(Some("127.0.0.1".parse().unwrap()), &https_headers));
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE domain_settings SET verified=0 WHERE domain_id=?1",
            [&domain.id],
        )
        .unwrap();
    assert!(update(State(state.clone()), headers.clone(), entry())
        .await
        .is_err());
    assert!(state
        .security
        .settings()
        .unwrap()
        .management_entry
        .is_some());
    let _ = update(State(state.clone()), headers, candidate())
        .await
        .unwrap();
    assert!(state
        .security
        .settings()
        .unwrap()
        .management_entry
        .is_none());
    assert!(ensure_domain_unused(&state.db.lock().unwrap(), &domain.id).is_ok());
}

#[test]
fn legacy_settings_and_incremental_migration_do_not_change_existing_behavior() {
    let (state, _) = crate::tests::domain_fixture();
    let db = state.db.lock().unwrap();
    db.execute("INSERT INTO server_settings VALUES(1,?1)", [r#"{"public_url":"https://old.example.test","trusted_proxies":["127.0.0.1"],"public_ips":[]}"#]).unwrap();
    let settings = load_for_runtime(&db, "0.0.0.0:9000".parse().unwrap()).unwrap();
    assert!(!settings.managed);
    assert_eq!(settings.public_url, "https://old.example.test");
    db.execute("ALTER TABLE tunnels DROP COLUMN http_redirect_enabled", [])
        .unwrap();
    crate::initialize_database(&db, false).unwrap();
    crate::initialize_database(&db, false).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('tunnels') WHERE name='http_redirect_enabled'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        upstream("[::]:9000".parse().unwrap()).to_string(),
        "[::1]:9000"
    );
}

#[tokio::test]
async fn manual_relay_ipv4_persists_overrides_toml_and_rejects_invalid_input() {
    let (mut state, headers) = crate::tests::domain_fixture();
    std::sync::Arc::make_mut(&mut state.config)
        .direct
        .relay_ipv4 = Some("8.8.4.4".parse().unwrap());
    assert_eq!(
        get(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0
            .relay_ipv4,
        Some("8.8.4.4".parse().unwrap())
    );
    let input = |address: Option<&str>| {
        Ok(Json(Input {
            management_entry: None,
            public_ips: vec!["2001:4860::1".parse().unwrap()],
            relay_ipv4: address.map(str::to_owned),
        }))
    };
    let _ = update(
        State(state.clone()),
        headers.clone(),
        input(Some(" 101.36.109.178 ")),
    )
    .await
    .unwrap();
    let ip = Some("101.36.109.178".parse().unwrap());
    assert_eq!(relay_ipv4(&state).unwrap(), ip);
    assert_eq!(load(&state.db.lock().unwrap()).unwrap().relay_ipv4, ip);
    // 旧客户端省略字段时不能清除页面配置。
    let _ = update(State(state.clone()), headers.clone(), input(None))
        .await
        .unwrap();
    assert_eq!(relay_ipv4(&state).unwrap(), ip);
    for invalid in [
        "10.7.107.175",
        "127.0.0.1",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "2001:4860::1",
        "example.com",
        "101.36.109.178:9444",
    ] {
        assert_eq!(
            update(State(state.clone()), headers.clone(), input(Some(invalid)))
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(relay_ipv4(&state).unwrap(), ip);
    }
    let mut no_csrf = headers.clone();
    no_csrf.remove("x-nexo-csrf");
    assert_eq!(
        update(State(state.clone()), no_csrf, input(Some("1.1.1.1")))
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    let _ = update(State(state.clone()), headers.clone(), input(Some("")))
        .await
        .unwrap();
    assert_eq!(
        relay_ipv4(&state).unwrap(),
        Some("8.8.4.4".parse().unwrap())
    );
    assert_eq!(load(&state.db.lock().unwrap()).unwrap().relay_ipv4, None);
}
