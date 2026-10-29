use super::*;

fn fixture() -> (AppState, HeaderMap) {
    let (state, headers) = crate::tests::domain_fixture();
    state.db.lock().unwrap().execute_batch("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('web','default','网页','https','127.0.0.1',8080,0,0),('tcp','default','TCP','tcp','127.0.0.1',22,0,0);
        INSERT INTO tenants(id,name,created_at) VALUES('other','其他',0);
        INSERT INTO users(id,tenant_id,username,role,password_hash,created_at) VALUES('other','other','other','tenant','unused',0);
        INSERT INTO relay_node_grants VALUES('local','other');
        INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('private','other','其他空间服务','http','127.0.0.1',80,0,0);").unwrap();
    (state, headers)
}
fn event(service: &str, at: i64, status: u16) -> Event {
    Event {
        id: Uuid::new_v4().simple().to_string(),
        service: service.into(),
        at,
        kind: "request".into(),
        protocol: "https".into(),
        host: "app.example.com".into(),
        method: "GET".into(),
        path: "/data?token=secret".into(),
        status,
        duration_ms: 123,
        to_origin: 20,
        to_public: 100,
        visitor: "a".repeat(64),
        source: "203.0.113.0/24".into(),
        country: "未知".into(),
        browser: "Chrome".into(),
        os: "Windows".into(),
        device: "电脑/其他".into(),
        ..Default::default()
    }
}

#[test]
fn ingestion_is_idempotent_and_summary_protocols_and_details_remain_scoped() {
    let (state, headers) = fixture();
    let now = unix_now();
    let mut ws = event("web", now - 2, 101);
    ws.protocol = "websocket".into();
    let batch = Batch {
        events: vec![
            event("web", now - 4, 200),
            event("web", now - 3, 503),
            ws,
            event("private", now - 1, 200),
        ],
        dropped: 2,
    };
    ingest(&state, &batch, "local", None).unwrap();
    ingest(&state, &batch, "local", None).unwrap();
    let own_scope = scope(
        &state,
        &headers,
        &Filter {
            range: Some("1h".into()),
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let v = summary(&state, &own_scope).unwrap();
    assert_eq!(v["totals"]["requests"], 3);
    assert_eq!(v["totals"]["to_public"], 300);
    assert_eq!(v["dropped"], 2);
    assert_eq!(v["p95_ms"], 250);
    let status_scope = scope(
        &state,
        &headers,
        &Filter {
            status_class: Some(5),
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let only_errors = summary(&state, &status_scope).unwrap();
    assert_eq!(only_errors["totals"]["requests"], 1);
    assert_eq!(only_errors["breakdowns"]["status"][0]["label"], "503");
    assert_eq!(
        details(&state, &status_scope, &Filter::default(), "request").unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let filtered = scope(
        &state,
        &headers,
        &Filter {
            protocol: Some("websocket".into()),
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let ws = summary(&state, &filtered).unwrap();
    assert_eq!(ws["totals"]["requests"], 1);
    assert_eq!(ws["breakdowns"]["status"][0]["label"], "101");
    let d = details(&state, &own_scope, &Filter::default(), "request").unwrap();
    assert_eq!(d["items"].as_array().unwrap().len(), 3);
    assert!(d["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v.get("visitor").is_none() && v["path"] == "/data"));
    assert!(!d.to_string().contains("secret"));
    assert!(scope(
        &state,
        &headers,
        &Filter {
            tunnel_id: Some("private".into()),
            ..Default::default()
        },
        false
    )
    .is_err());
    assert!(scope(
        &state,
        &headers,
        &Filter {
            user_id: Some("other".into()),
            ..Default::default()
        },
        false
    )
    .is_err());
    let admin = scope(&state, &headers, &Filter::default(), true).unwrap();
    assert_eq!(summary(&state, &admin).unwrap()["totals"]["requests"], 4);
    ingest(
        &state,
        &Batch {
            events: vec![event("web", now, 200)],
            dropped: 0,
        },
        "unassigned-node",
        None,
    )
    .unwrap();
    assert_eq!(
        summary(&state, &own_scope).unwrap()["totals"]["requests"],
        3
    );
}

#[test]
fn live_window_excludes_old_requests_from_totals_rankings_and_distributions() {
    let (state, headers) = fixture();
    let mut old = event("web", unix_now() - 120, 503);
    old.path = "/old".into();
    let mut fresh = event("web", unix_now() - 1, 200);
    fresh.path = "/fresh".into();
    ingest(
        &state,
        &Batch {
            events: vec![old, fresh],
            dropped: 0,
        },
        "local",
        None,
    )
    .unwrap();
    let s = scope(
        &state,
        &headers,
        &Filter {
            range: Some("live".into()),
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let v = summary(&state, &s).unwrap();
    assert_eq!(v["totals"]["requests"], 1);
    assert_eq!(v["services"][0]["requests"], 1);
    assert_eq!(v["breakdowns"]["path"][0]["label"], "/fresh");
    assert_eq!(v["totals"]["errors"], 0);
}

#[tokio::test]
async fn no_traffic_heartbeat_is_ready_and_cleanup_preserves_aggregates() {
    let (state, headers) = fixture();
    collect(&state).await.unwrap();
    let s = scope(&state, &headers, &Filter::default(), false).unwrap();
    let v = summary(&state, &s).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["totals"]["requests"], 0);
    let e = event("web", unix_now() - 6 * 86400, 200);
    ingest(
        &state,
        &Batch {
            events: vec![e],
            dropped: 0,
        },
        "local",
        None,
    )
    .unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE analytics_events SET at=?1",
            [unix_now() - 8 * 86400],
        )
        .unwrap();
    collect(&state).await.unwrap();
    let db = state.db.lock().unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM analytics_events", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT SUM(requests) FROM analytics_hours", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn pagination_has_stable_ties_and_never_leaks_another_space() {
    let (state, headers) = fixture();
    let batch = Batch {
        events: (0..60).map(|_| event("web", unix_now() - 1, 200)).collect(),
        dropped: 0,
    };
    ingest(&state, &batch, "local", None).unwrap();
    let s = scope(&state, &headers, &Filter::default(), false).unwrap();
    let first = details(&state, &s, &Filter::default(), "request").unwrap();
    assert_eq!(first["items"].as_array().unwrap().len(), 50);
    let next = details(
        &state,
        &s,
        &Filter {
            cursor: Some(first["next_cursor"].as_str().unwrap().into()),
            ..Default::default()
        },
        "request",
    )
    .unwrap();
    assert_eq!(next["items"].as_array().unwrap().len(), 10);
    let ids: std::collections::HashSet<_> = first["items"]
        .as_array()
        .unwrap()
        .iter()
        .chain(next["items"].as_array().unwrap())
        .map(|v| v["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 60);
}

#[tokio::test]
#[ignore = "需要 NEXO_TEST_CADDY 指向真实 Caddy 二进制"]
async fn real_caddy_access_log_reaches_private_queue() {
    let binary = std::env::var_os("NEXO_TEST_CADDY").expect("设置 NEXO_TEST_CADDY");
    let root = tempfile::tempdir().unwrap();
    let admin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let admin_address = admin.local_addr().unwrap();
    drop(admin);
    let public = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = public.local_addr().unwrap();
    drop(public);
    let settings = crate::config::Caddy {
        binary: binary.into(),
        admin_url: format!("http://{admin_address}"),
        ..Default::default()
    };
    let caddy = Arc::new(crate::caddy::CaddySupervisor::new(
        crate::caddy::CaddyRuntimeConfig::new(root.path(), &settings),
    ));
    let hub = Arc::new(telemetry::Hub::default());
    caddy.set_analytics(hub.clone());
    let mut config = json!({"admin":{"listen":admin_address.to_string()},"apps":{"http":{"servers":{"public":{"listen":[address.to_string()],"automatic_https":{"disable":true},"routes":[{"match":[{"host":["app.example.com"]}],"handle":[{"handler":"static_response","body":"hello"}]}]}}}}});
    telemetry::configure(&mut config, &[("app.example.com".into(), "web".into())]);
    caddy.write_startup_config(&config).unwrap();
    caddy.clone().start().await.unwrap();
    caddy.apply_json(&config).await.unwrap();
    let response = reqwest::Client::new()
        .get(format!("http://{address}/api/items?token=private"))
        .header("Host", "app.example.com")
        .header("Cookie", "password=private")
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "hello");
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let b = hub.batch();
            if let Some(e) = b.events.into_iter().find(|e| e.kind == "request") {
                break e;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    caddy.shutdown().await.unwrap();
    let e = event.unwrap();
    assert_eq!(e.service, "web");
    assert_eq!(e.path, "/api/items");
    assert_eq!(e.to_public, 5);
    assert!(!serde_json::to_string(&e).unwrap().contains("private"));
}
