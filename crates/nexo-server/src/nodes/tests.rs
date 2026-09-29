use super::*;

fn tenant(state: &AppState, id: &str) -> HeaderMap {
    let db = state.db.lock().unwrap();
    db.execute(
        "INSERT INTO tenants(id,name,created_at) VALUES(?1,?1,0)",
        [id],
    )
    .unwrap();
    db.execute("INSERT INTO users(id,tenant_id,username,role,password_hash,created_at) VALUES(?1,?1,?1,'tenant','unused',0)",[id]).unwrap();
    let (cookie, csrf) = auth::create_session(&db, id, id, unix_now(), &HeaderMap::new()).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("cookie", format!("nexo_session={cookie}").parse().unwrap());
    headers.insert("x-nexo-csrf", csrf.parse().unwrap());
    headers
}
fn nodes(state: &AppState) {
    let db = state.db.lock().unwrap();
    for (id, ip) in [
        ("hk", "203.0.113.10"),
        ("jp", "203.0.113.11"),
        ("us", "203.0.113.12"),
    ] {
        db.execute("INSERT INTO relay_nodes(id,name,public_ipv4,approved,last_seen,created_at) VALUES(?1,?1,?2,1,?3,0)",params![id,ip,unix_now()]).unwrap();
    }
}

#[tokio::test]
async fn groups_enforce_admin_and_scope_and_supply_members() {
    let (state, admin) = crate::tests::domain_fixture();
    let alice = tenant(&state, "alice");
    let bob = tenant(&state, "bob");
    nodes(&state);
    let input = || {
        serde_json::from_value(
            json!({"name":"亚洲入口","node_ids":["hk","jp"],"workspace_ids":["alice"]}),
        )
        .unwrap()
    };
    assert_eq!(
        groups::create(State(state.clone()), alice.clone(), Json(input()))
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    let result = groups::create(State(state.clone()), admin, Json(input()))
        .await
        .unwrap()
        .0;
    let id = result[0]["id"].as_str().unwrap();
    assert_eq!(
        groups::list(State(state.clone()), alice.clone())
            .await
            .unwrap()
            .0[0]["name"],
        "亚洲入口"
    );
    assert_eq!(
        groups::list(State(state.clone()), bob.clone())
            .await
            .unwrap()
            .0,
        json!([])
    );
    let visible = list(State(state.clone()), alice).await.unwrap().0;
    assert_eq!(visible["nodes"].as_array().unwrap().len(), 3); // 包含内置节点
    assert_eq!(
        list(State(state.clone()), bob).await.unwrap().0["nodes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let db = state.db.lock().unwrap();
    assert_eq!(groups::members(&db, id).unwrap(), vec!["hk", "jp"]);
    assert_eq!(db.query_row("SELECT COUNT(*) FROM relay_node_authorizations WHERE node_id='hk' AND tenant_id='alice'",[],|r|r.get::<_,i64>(0)).unwrap(),1);
}

#[test]
fn latency_filters_other_workspaces_and_marks_stale_and_revoked() {
    let (state, _) = crate::tests::domain_fixture();
    tenant(&state, "alice");
    tenant(&state, "bob");
    nodes(&state);
    let db = state.db.lock().unwrap();
    for id in ["alice", "bob"] {
        db.execute("INSERT INTO devices(id,tenant_id,name,status,created_at,updated_at) VALUES(?1,?1,?1,'online',0,0)",[id]).unwrap();
        db.execute("INSERT INTO relay_node_grants VALUES('hk',?1)", [id])
            .unwrap();
        db.execute(
            "INSERT INTO relay_latency(device_id,node_id,rtt_ms,checked_at) VALUES(?1,'hk',32,?2)",
            params![id, unix_now()],
        )
        .unwrap();
    }
    let data = latencies(&db, "hk", "alice", false).unwrap();
    assert_eq!(data.as_array().unwrap().len(), 1);
    assert_eq!(data[0]["device_id"], "alice");
    assert_eq!(data[0]["fresh"], true);
    db.execute(
        "UPDATE relay_latency SET checked_at=?1 WHERE device_id='alice'",
        [unix_now() - 46],
    )
    .unwrap();
    assert_eq!(
        latencies(&db, "hk", "alice", false).unwrap()[0]["fresh"],
        false
    );
    db.execute("DELETE FROM relay_node_grants WHERE tenant_id='alice'", [])
        .unwrap();
    assert_eq!(latencies(&db, "hk", "alice", false).unwrap(), json!([]));
}

#[test]
fn migration_does_not_rebind_revoked_services_to_local() {
    let (state, _) = crate::tests::domain_fixture();
    let db = state.db.lock().unwrap();
    db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('s','default','s','tcp','127.0.0.1',80,0,0)",[]).unwrap();
    assert_eq!(services::ids(&db, "s").unwrap(), vec!["local"]);
    db.execute("DELETE FROM service_nodes WHERE service_id='s'", [])
        .unwrap();
    migrate(&db).unwrap();
    assert!(services::ids(&db, "s").unwrap().is_empty());
}

#[tokio::test]
async fn enrollment_is_single_use_and_maintenance_requires_admin() {
    let (state, admin) = crate::tests::domain_fixture();
    state.security.configuration.write().unwrap().public_url = "https://manage.example".into();
    let alice = tenant(&state, "alice");
    let bob = tenant(&state, "bob");
    let input =
        || serde_json::from_value(json!({"name":"申请节点","public_ipv4":"8.8.8.8"})).unwrap();
    let created = create(State(state.clone()), alice.clone(), Json(input()))
        .await
        .unwrap()
        .0;
    let id = created["id"].as_str().unwrap();
    assert!(
        approve(State(state.clone()), admin.clone(), Path(id.into()))
            .await
            .is_err()
    );
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    let registration = || nexo_protocol::nodes::Register {
        token: created["token"].as_str().unwrap().into(),
        csr: csr.clone(),
    };
    let registered = control::register(State(state.clone()), Json(registration()))
        .await
        .unwrap()
        .0;
    assert_eq!(registered.id, id);
    assert!(
        control::register(State(state.clone()), Json(registration()))
            .await
            .is_err()
    );
    assert!(control::snapshot(&state, id).unwrap().services.is_empty());
    assert_eq!(
        approve(State(state.clone()), alice.clone(), Path(id.into()))
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        update(
            State(state.clone()),
            alice.clone(),
            Path(id.into()),
            Json(input())
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        remove(State(state.clone()), alice, Path(id.into()))
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        detail(State(state.clone()), bob, Path(id.into()))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let _ = approve(State(state.clone()), admin.clone(), Path(id.into()))
        .await
        .unwrap();
    assert!(
        control::snapshot(&state, id).unwrap().services.is_empty(),
        "审批不等于分配工作空间"
    );
    let _ = remove(State(state.clone()), admin, Path(id.into()))
        .await
        .unwrap();
    let db = state.db.lock().unwrap();
    assert!(db
        .query_row(
            "SELECT certificate_pem='' AND token_digest IS NULL FROM relay_nodes WHERE id=?1",
            [id],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
}

#[tokio::test]
async fn enrollment_can_resume_without_changing_identity_or_permissions() {
    let (mut state, admin) = crate::tests::domain_fixture();
    Arc::make_mut(&mut state.config).caddy.http_listen = ":8080".into();
    state.security.configuration.write().unwrap().public_url = "http://manage.example".into();
    let alice = tenant(&state, "alice");
    let bob = tenant(&state, "bob");
    let input = || {
        serde_json::from_value(
            json!({"name":"恢复安装","public_ipv4":"8.8.8.8","control_port":9892}),
        )
        .unwrap()
    };
    assert!(create(State(state.clone()), alice.clone(), Json(input()))
        .await
        .is_err());
    assert_eq!(
        state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM relay_nodes WHERE id!='local'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    state.security.configuration.write().unwrap().public_url =
        "https://manage.example:8443/".into();
    let first = create(State(state.clone()), alice.clone(), Json(input()))
        .await
        .unwrap()
        .0;
    let id = first["id"].as_str().unwrap();
    assert_eq!(
        create(State(state.clone()), alice.clone(), Json(input()))
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(first["server_url"], "https://manage.example:8443");
    assert_eq!(first["http_port"], 8080);
    assert_eq!(first["data_port"], 9892);
    assert_eq!(
        detail(State(state.clone()), alice.clone(), Path(id.into()))
            .await
            .unwrap()
            .0["status"],
        "unregistered"
    );
    // 即使获分配此节点，也不能续领另一工作空间申请的凭证。
    state
        .db
        .lock()
        .unwrap()
        .execute("INSERT INTO relay_node_grants VALUES(?1,'bob')", [id])
        .unwrap();
    assert_eq!(
        detail(State(state.clone()), bob.clone(), Path(id.into()))
            .await
            .unwrap()
            .0["can_enroll"],
        false
    );
    assert_eq!(
        renew_enrollment(State(state.clone()), bob, Path(id.into()))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let mut without_csrf = alice.clone();
    without_csrf.remove("x-nexo-csrf");
    assert!(
        renew_enrollment(State(state.clone()), without_csrf, Path(id.into()))
            .await
            .is_err()
    );
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE relay_nodes SET token_expires=0 WHERE id=?1", [id])
        .unwrap();
    assert_eq!(
        detail(State(state.clone()), alice.clone(), Path(id.into()))
            .await
            .unwrap()
            .0["status"],
        "expired"
    );
    let key = rcgen::KeyPair::generate().unwrap();
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let registration = |token: &Value| nexo_protocol::nodes::Register {
        token: token.as_str().unwrap().into(),
        csr: csr.clone(),
    };
    assert!(
        control::register(State(state.clone()), Json(registration(&first["token"])))
            .await
            .is_err()
    );
    let second = renew_enrollment(State(state.clone()), alice.clone(), Path(id.into()))
        .await
        .unwrap()
        .0;
    let third = renew_enrollment(State(state.clone()), admin.clone(), Path(id.into()))
        .await
        .unwrap()
        .0;
    assert_ne!(second["token"], third["token"]);
    assert!(
        control::register(State(state.clone()), Json(registration(&second["token"])))
            .await
            .is_err()
    );
    let registered = control::register(State(state.clone()), Json(registration(&third["token"])))
        .await
        .unwrap()
        .0;
    assert_eq!(registered.id, id);
    assert_eq!(registered.data_port, 9892);
    assert_eq!(registered.control_endpoint, "manage.example:9890");
    let pending = detail(State(state.clone()), alice.clone(), Path(id.into()))
        .await
        .unwrap()
        .0;
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["can_enroll"], false);
    assert_eq!(pending["assigned"], false);
    assert!(!pending
        .to_string()
        .contains(third["token"].as_str().unwrap()));
    assert!(
        renew_enrollment(State(state.clone()), alice.clone(), Path(id.into()))
            .await
            .is_err()
    );
    assert!(
        renew_enrollment(State(state.clone()), admin.clone(), Path(id.into()))
            .await
            .is_err()
    );
    assert!(control::snapshot(&state, id).unwrap().services.is_empty());
    let _ = approve(State(state.clone()), admin.clone(), Path(id.into()))
        .await
        .unwrap();
    let _ = update(State(state.clone()), admin.clone(), Path(id.into()), Json(serde_json::from_value(json!({"name":"恢复安装","public_ipv4":"8.8.8.8","control_port":9892,"workspace_ids":["alice"]})).unwrap())).await.unwrap();
    assert_eq!(
        detail(State(state.clone()), alice, Path(id.into()))
            .await
            .unwrap()
            .0["assigned"],
        true
    );
    let _ = remove(State(state.clone()), admin.clone(), Path(id.into()))
        .await
        .unwrap();
    assert!(renew_enrollment(State(state), admin, Path(id.into()))
        .await
        .is_err());
}
