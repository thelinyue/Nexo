use super::*;
use serde_json::json;

fn input(host: &str) -> TunnelInput {
    serde_json::from_value(json!({"service_mode":"reverse_proxy","name":"VPS 应用","protocol":"http","origin_protocol":"http","local_address":"127.0.0.1","local_port":3000,"hostname":host,"public_domain_id":"domain"})).unwrap()
}

fn fixture() -> (AppState, HeaderMap) {
    let (state, headers) = crate::tests::domain_fixture();
    state.db.lock().unwrap().execute("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES('domain','default','example.com',1,0,0)", []).unwrap();
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
async fn every_direct_mutation_requires_admin_and_batch_failure_rolls_back() {
    let (state, headers) = fixture();
    let proxy = create_tunnel(State(state.clone()), headers.clone(), Json(input("app")))
        .await
        .unwrap()
        .0;
    let mut tunnel = input("tunnel");
    tunnel.service_mode = None;
    let tunnel = create_tunnel(State(state.clone()), headers.clone(), Json(tunnel))
        .await
        .unwrap()
        .0;
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE users SET role='tenant' WHERE id='u'", [])
        .unwrap();
    assert_eq!(
        create_tunnel(State(state.clone()), headers.clone(), Json(input("other")))
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    for explicit in [None, Some("tunnel".into()), Some(MODE.into())] {
        let mut update = input("app");
        update.service_mode = explicit;
        assert_eq!(
            update_tunnel(
                State(state.clone()),
                headers.clone(),
                Path(proxy.id.clone()),
                Json(update)
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(
        disable_tunnel(
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
        delete_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(proxy.id.clone())
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::FORBIDDEN
    );
    for enabled in [true, false] {
        assert_eq!(
            batch_set_tunnels_enabled(
                state.clone(),
                headers.clone(),
                BatchDelete {
                    tunnel_ids: vec![tunnel.id.clone(), proxy.id.clone()]
                },
                enabled
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        assert!(list_tunnels(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0
            .iter()
            .all(|item| item.enabled));
    }
    assert_eq!(
        batch_delete_tunnels(
            State(state.clone()),
            headers.clone(),
            Json(BatchDelete {
                tunnel_ids: vec![tunnel.id, proxy.id]
            })
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        list_tunnels(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0
            .len(),
        2
    );
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
        let mut value = json!({"service_mode":"reverse_proxy","name":"test","protocol":"http","local_address":"127.0.0.1","local_port":3000,"hostname":"app","public_domain_id":"domain"});
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
fn existing_database_upgrade_keeps_old_tunnels_and_is_repeatable() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(include_str!("../../../../migrations/v0.2.0_baseline.sql"))
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
