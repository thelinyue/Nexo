use super::*;
use serde_json::json;
const DOMAIN: &str = "00000000-0000-4000-8000-000000000001";

fn input(host: &str) -> TunnelInput {
    serde_json::from_value(json!({"service_mode":"reverse_proxy","name":"VPS 应用","protocol":"http","origin_protocol":"http","local_address":"127.0.0.1","local_port":3000,"hostname":host,"public_domain_id":DOMAIN})).unwrap()
}

fn fixture() -> (AppState, HeaderMap) {
    let (state, headers) = crate::tests::domain_fixture();
    state.db.lock().unwrap().execute("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES(?1,'default','example.com',1,0,0)", [DOMAIN]).unwrap();
    state.db.lock().unwrap().execute("INSERT INTO domain_settings(domain_id,verification_token,certificate_mode,verified,credential_file) VALUES(?1,'test-proof','cloudflare_dns',1,'credential-00000000-0000-4000-8000-000000000002.token')", [DOMAIN]).unwrap();
    (state, headers)
}

#[tokio::test]
async fn direct_crud_without_agents_preserves_mode_and_domain_uniqueness() {
    let (state, headers) = fixture();
    let Json(created) = create_tunnel(State(state.clone()), headers.clone(), Json(input("app")))
        .await
        .unwrap();
    assert_eq!(created.service_mode, MODE);
    assert!(created.device_id.is_none());
    assert!(!created.apply_error.unwrap().contains("Agent"));
    assert!(state.tunnel_runtime.web_upstreams().await.is_empty());
    let mut old_client = input("app");
    old_client.service_mode = None;
    old_client.local_port = 4000;
    let Json(updated) = update_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(created.id.clone()),
        Json(old_client),
    )
    .await
    .unwrap();
    assert_eq!(updated.service_mode, MODE);
    assert_eq!(updated.local_port, 4000);
    let mut switched = input("app");
    switched.service_mode = Some("tunnel".into());
    assert_eq!(
        update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
            Json(switched)
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::BAD_REQUEST
    );
    let mut duplicate = input("app");
    duplicate.service_mode = None;
    assert_eq!(
        create_tunnel(State(state.clone()), headers.clone(), Json(duplicate))
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    let Json(disabled) = disable_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(created.id.clone()),
    )
    .await
    .unwrap();
    assert_eq!(disabled.apply_status, "disabled");
    let Json(enabled) = enable_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(created.id.clone()),
    )
    .await
    .unwrap();
    assert!(enabled.enabled);
    let _ = delete_tunnel(State(state.clone()), headers.clone(), Path(created.id))
        .await
        .unwrap();
    assert!(list_tunnels(State(state.clone()), headers.clone())
        .await
        .unwrap()
        .0
        .is_empty());
    let _ = create_tunnel(State(state), headers, Json(input("app")))
        .await
        .unwrap();
}

#[tokio::test]
async fn ordinary_user_requires_explicit_builtin_grant_and_revocation_is_atomic() {
    let (state, headers) = fixture();
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE users SET role='tenant' WHERE id='u'", [])
        .unwrap();
    assert_eq!(
        create_tunnel(State(state.clone()), headers.clone(), Json(input("denied")))
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    state
        .db
        .lock()
        .unwrap()
        .execute("INSERT INTO relay_local_proxy_grants VALUES('default')", [])
        .unwrap();
    let proxy = create_tunnel(State(state.clone()), headers.clone(), Json(input("app")))
        .await
        .unwrap()
        .0;
    let other = create_tunnel(State(state.clone()), headers.clone(), Json(input("other")))
        .await
        .unwrap()
        .0;
    let mut update = input("app");
    update.local_port = 4000;
    assert_eq!(
        update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(proxy.id.clone()),
            Json(update)
        )
        .await
        .unwrap()
        .0
        .local_port,
        4000
    );
    let _ = disable_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
    )
    .await
    .unwrap();
    let _ = enable_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
    )
    .await
    .unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM relay_local_proxy_grants", [])
        .unwrap();
    changed(&state, false).await.unwrap();
    assert_eq!(
        read_tunnel(&state, "default", &proxy.id, &headers)
            .unwrap()
            .apply_status,
        "failed"
    );
    assert_eq!(
        enable_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(proxy.id.clone())
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        batch_set_tunnels_enabled(
            state.clone(),
            headers.clone(),
            BatchDelete {
                tunnel_ids: vec![other.id.clone(), proxy.id.clone()]
            },
            true
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::FORBIDDEN
    );
    assert!(
        read_tunnel(&state, "default", &proxy.id, &headers)
            .unwrap()
            .enabled
    );
    // 失去节点授权仍能停用和删除自己的服务；其他工作空间的对象始终不可访问。
    let _ = disable_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        batch_set_tunnels_enabled(
            state.clone(),
            headers.clone(),
            BatchDelete {
                tunnel_ids: vec![other.id.clone(), "foreign".into()]
            },
            false
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::NOT_FOUND
    );
    assert!(
        read_tunnel(&state, "default", &other.id, &headers)
            .unwrap()
            .enabled
    );
    let _ = batch_delete_tunnels(
        State(state.clone()),
        headers.clone(),
        Json(BatchDelete {
            tunnel_ids: vec![proxy.id, other.id],
        }),
    )
    .await
    .unwrap();
    assert!(list_tunnels(State(state.clone()), headers.clone())
        .await
        .unwrap()
        .0
        .is_empty());
    let mut no_csrf = headers;
    no_csrf.remove("x-nexo-csrf");
    assert_eq!(
        create_tunnel(State(state), no_csrf, Json(input("csrf")))
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn owned_and_shared_nodes_support_direct_proxy_without_agent() {
    let (state, headers) = fixture();
    {
        let db = state.db.lock().unwrap();
        db.execute("UPDATE users SET role='tenant' WHERE id='u'", [])
            .unwrap();
        db.execute("INSERT INTO relay_nodes(id,owner_tenant,name,public_ipv4,approved,reverse_proxy_supported,last_seen,created_at) VALUES('own','default','我的节点','203.0.113.10',1,1,?1,0),('shared',NULL,'共享节点','203.0.113.11',1,1,?1,0)",[unix_now()]).unwrap();
    }
    let mut own = input("app");
    own.node_ids = Some(vec!["own".into()]);
    let proxy = create_tunnel(State(state.clone()), headers.clone(), Json(own))
        .await
        .unwrap()
        .0;
    assert_eq!(proxy.node_ids, vec!["own"]);
    assert_ne!(proxy.apply_status, "ready");
    let snapshot = nodes::control::snapshot(&state, "own").unwrap();
    assert!(snapshot.agents.is_empty());
    assert_eq!(snapshot.services.len(), 1);
    assert_eq!(
        snapshot.services[0].reverse_proxy_target.as_deref(),
        Some("http://127.0.0.1:3000")
    );
    assert!(snapshot.services[0].device.is_empty());
    let mut shared = input("app");
    shared.node_ids = Some(vec!["shared".into()]);
    assert_eq!(
        update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(proxy.id.clone()),
            Json(shared)
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::FORBIDDEN
    );
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO relay_node_grants VALUES('shared','default')",
            [],
        )
        .unwrap();
    let mut shared = input("app");
    shared.node_ids = Some(vec!["shared".into()]);
    let _ = update_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
        Json(shared),
    )
    .await
    .unwrap();
    assert!(nodes::control::snapshot(&state, "own")
        .unwrap()
        .services
        .is_empty());
    assert_eq!(
        nodes::control::snapshot(&state, "shared")
            .unwrap()
            .services
            .len(),
        1
    );
    state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM relay_node_grants WHERE node_id='shared'", [])
        .unwrap();
    assert!(nodes::control::snapshot(&state, "shared")
        .unwrap()
        .services
        .is_empty());
    let mut own = input("app");
    own.node_ids = Some(vec!["own".into()]);
    let _ = update_tunnel(State(state.clone()), headers, Path(proxy.id), Json(own))
        .await
        .unwrap();
}

#[tokio::test]
async fn proxy_node_validation_rejects_unapproved_disabled_old_and_multiple_nodes() {
    let (state, headers) = fixture();
    state.db.lock().unwrap().execute_batch("UPDATE users SET role='tenant' WHERE id='u'; INSERT INTO relay_nodes(id,owner_tenant,name,approved,enabled,reverse_proxy_supported,created_at) VALUES('pending','default','待审批',0,1,1,0),('disabled','default','停用',1,0,1,0),('old','default','旧版',1,1,0,0);").unwrap();
    for (node, status) in [
        ("pending", StatusCode::FORBIDDEN),
        ("disabled", StatusCode::FORBIDDEN),
        ("old", StatusCode::BAD_REQUEST),
    ] {
        let mut value = input(node);
        value.node_ids = Some(vec![node.into()]);
        assert_eq!(
            create_tunnel(State(state.clone()), headers.clone(), Json(value))
                .await
                .unwrap_err()
                .status,
            status
        );
        assert!(nodes::control::snapshot(&state, node)
            .unwrap()
            .services
            .is_empty());
    }
    let mut value = input("multi");
    value.node_ids = Some(vec!["pending".into(), "old".into()]);
    value.distribution_mode = Some("dns".into());
    assert_eq!(
        create_tunnel(State(state), headers, Json(value))
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn migration_preserves_existing_builtin_proxy_without_regranting_on_restart() {
    let (state, headers) = fixture();
    let _ = create_tunnel(State(state.clone()), headers, Json(input("app")))
        .await
        .unwrap();
    let db = state.db.lock().unwrap();
    db.execute_batch(
        "DROP TABLE relay_local_proxy_grants; UPDATE users SET role='tenant' WHERE id='u';",
    )
    .unwrap();
    nodes::migrate(&db).unwrap();
    assert!(nodes::services::authorize_proxy(&db, "default", "local").is_ok());
    db.execute("DELETE FROM relay_local_proxy_grants", [])
        .unwrap();
    nodes::migrate(&db).unwrap();
    assert_eq!(
        nodes::services::authorize_proxy(&db, "default", "local")
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn admin_mixed_batch_is_atomic_and_direct_services_are_not_traffic_filters() {
    let (state, headers) = fixture();
    let proxy = create_tunnel(State(state.clone()), headers.clone(), Json(input("proxy")))
        .await
        .unwrap()
        .0;
    let mut value = input("tunnel");
    value.service_mode = None;
    let tunnel = create_tunnel(State(state.clone()), headers.clone(), Json(value))
        .await
        .unwrap()
        .0;
    let ids = vec![proxy.id.clone(), tunnel.id.clone()];
    for enabled in [false, true] {
        let Json(items) = batch_set_tunnels_enabled(
            state.clone(),
            headers.clone(),
            BatchDelete {
                tunnel_ids: ids.clone(),
            },
            enabled,
        )
        .await
        .unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|item| item.enabled == enabled));
    }
    assert_eq!(
        batch_set_tunnels_enabled(
            state.clone(),
            headers.clone(),
            BatchDelete {
                tunnel_ids: vec![proxy.id.clone(), "foreign".into()]
            },
            false
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::NOT_FOUND
    );
    assert!(list_tunnels(State(state.clone()), headers.clone())
        .await
        .unwrap()
        .0
        .iter()
        .all(|item| item.enabled));
    let filter = serde_json::from_value(json!({"tunnel_id":proxy.id})).unwrap();
    assert!(crate::traffic::own_realtime(
        State(state.clone()),
        headers.clone(),
        axum::extract::Query(filter)
    )
    .await
    .is_err());
    let _ = batch_delete_tunnels(
        State(state.clone()),
        headers.clone(),
        Json(BatchDelete { tunnel_ids: ids }),
    )
    .await
    .unwrap();
    assert!(list_tunnels(State(state), headers)
        .await
        .unwrap()
        .0
        .is_empty());
}

#[tokio::test]
async fn invalid_direct_combinations_targets_and_foreign_domains_are_rejected() {
    let (state, headers) = fixture();
    for patch in [
        json!({"protocol":"tcp"}),
        json!({"device_id":"device"}),
        json!({"public_port":22000}),
        json!({"lan_redirect_enabled":true}),
        json!({"service_mode":"unknown"}),
    ] {
        let mut value = json!({"service_mode":"reverse_proxy","name":"test","protocol":"http","local_address":"127.0.0.1","local_port":3000,"hostname":"app","public_domain_id":DOMAIN});
        value
            .as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        assert_eq!(
            create_tunnel(
                State(state.clone()),
                headers.clone(),
                Json(serde_json::from_value(value).unwrap())
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
    }
    for address in [
        "http://localhost",
        "localhost:3000",
        "user@localhost",
        "localhost/path",
        "localhost?x",
        "localhost#x",
        "",
        "a b",
    ] {
        let mut value = input("app");
        value.local_address = address.into();
        assert_eq!(
            create_tunnel(State(state.clone()), headers.clone(), Json(value))
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST,
            "{address}"
        );
    }
    for (i, address) in ["::1", "[::1]", "127.0.0.1", "app.internal"]
        .iter()
        .enumerate()
    {
        let mut value = input(&format!("app{i}"));
        value.local_address = address.to_string();
        let _ = create_tunnel(State(state.clone()), headers.clone(), Json(value))
            .await
            .unwrap();
    }
    state.db.lock().unwrap().execute_batch("INSERT INTO tenants(id,name,created_at) VALUES('other','other',0); INSERT INTO public_domains(id,tenant_id,domain,created_at,updated_at) VALUES('foreign','other','other.example',0,0);").unwrap();
    let mut value = input("foreign");
    value.public_domain_id = Some("foreign".into());
    assert_eq!(
        create_tunnel(State(state.clone()), headers.clone(), Json(value))
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE tunnels SET tenant_id='other' WHERE hostname='app0'",
            [],
        )
        .unwrap();
    let foreign: String = state
        .db
        .lock()
        .unwrap()
        .query_row("SELECT id FROM tunnels WHERE hostname='app0'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        delete_tunnel(State(state), headers, Path(foreign))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
}

#[test]
fn current_database_keeps_tunnels_on_restart() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(include_str!("../../../../migrations/schema.sql"))
        .unwrap();
    db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('old','default','old','http','127.0.0.1',80,0,0)", []).unwrap();
    initialize_database(&db, false).unwrap();
    initialize_database(&db, false).unwrap();
    assert_eq!(
        db.query_row("SELECT service_mode FROM tunnels WHERE id='old'", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "tunnel"
    );
}

#[tokio::test]
async fn force_https_defaults_for_new_proxy_and_preserves_edits() {
    let (state, headers) = crate::tests::domain_fixture();
    let domain = crate::tests::add_test_domain(&state, &headers, "redirect.example.test")
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
    let mut value = input("app");
    value.public_domain_id = Some(domain.id.clone());
    value.protocol = "https".into();
    let created = create_tunnel(State(state.clone()), headers.clone(), Json(value))
        .await
        .unwrap()
        .0;
    assert!(created.http_redirect_enabled);
    let mut value = input("app");
    value.public_domain_id = Some(domain.id.clone());
    value.http_redirect_enabled = Some(false);
    let edited = update_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(created.id.clone()),
        Json(value),
    )
    .await
    .unwrap()
    .0;
    assert!(!edited.http_redirect_enabled);
    let mut value = input("app");
    value.public_domain_id = Some(domain.id);
    value.protocol = "https".into();
    let edited = update_tunnel(State(state), headers, Path(created.id), Json(value))
        .await
        .unwrap()
        .0;
    assert!(!edited.http_redirect_enabled);
}

#[tokio::test]
async fn group_authorization_allows_one_member_and_revocation_removes_its_snapshot() {
    let (state, headers) = fixture();
    state.db.lock().unwrap().execute_batch("UPDATE users SET role='tenant' WHERE id='u'; INSERT INTO relay_nodes(id,name,public_ipv4,approved,reverse_proxy_supported,created_at) VALUES('member','组成员','203.0.113.12',1,1,0); INSERT INTO relay_node_groups VALUES('group','已授权组',0); INSERT INTO relay_group_members VALUES('group','member'); INSERT INTO relay_group_grants VALUES('group','default');").unwrap();
    let mut value = input("group");
    value.node_ids = Some(vec!["member".into()]);
    let _ = create_tunnel(State(state.clone()), headers, Json(value))
        .await
        .unwrap();
    assert_eq!(
        nodes::control::snapshot(&state, "member")
            .unwrap()
            .services
            .len(),
        1
    );
    state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM relay_group_grants", [])
        .unwrap();
    assert!(nodes::control::snapshot(&state, "member")
        .unwrap()
        .services
        .is_empty());
}
