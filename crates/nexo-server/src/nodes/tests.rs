use super::*;

pub(super) fn tenant(state: &AppState, id: &str) -> HeaderMap {
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

#[tokio::test]
async fn removal_of_group_detaches_other_users_services_and_keeps_only_independent_grants() {
    let (state, admin) = crate::tests::domain_fixture();
    let alice = tenant(&state, "alice");
    nodes(&state);
    {
        let db = state.db.lock().unwrap();
        db.execute_batch("INSERT INTO relay_node_groups VALUES('g','亚洲入口',0);
            INSERT INTO relay_group_members VALUES('g','hk'),('g','jp');
            INSERT INTO relay_group_grants VALUES('g','alice');
            INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,node_group_id,enabled,created_at,updated_at)
            VALUES('s','alice','媒体中心','tcp','127.0.0.1',80,'g',1,0,0),
                  ('archive','alice','历史记录','tcp','127.0.0.1',80,'g',0,0,0),
                  ('other','default','备用服务','tcp','127.0.0.1',80,'g',1,0,0);
            UPDATE tunnels SET deleted_at=1 WHERE id='archive';
            INSERT INTO relay_group_grants VALUES('g','default');
            INSERT INTO relay_node_grants VALUES('jp','default');
            DELETE FROM service_nodes WHERE service_id IN ('s','other');
            INSERT INTO service_nodes VALUES('s','hk'),('s','jp'),('other','hk'),('other','jp');
            UPDATE tunnels SET distribution_mode='manual',preferred_node_id='hk' WHERE id IN ('s','other');").unwrap();
    }
    let delete = |headers| groups::remove(State(state.clone()), headers, Path("g".into()));
    assert_eq!(
        delete(alice).await.unwrap_err().status,
        StatusCode::FORBIDDEN
    );
    let mut no_csrf = admin.clone();
    no_csrf.remove("x-nexo-csrf");
    assert!(delete(no_csrf).await.is_err());
    assert_eq!(delete(admin).await.unwrap().0["removed"], true);
    let db = state.db.lock().unwrap();
    assert!(services::ids(&db, "s").unwrap().is_empty());
    assert!(services::authorize_enable(&db, "alice", "s", false).is_err());
    let mut edit: TunnelInput = serde_json::from_value(
        json!({"name":"媒体中心","protocol":"tcp","local_address":"127.0.0.1","local_port":80}),
    )
    .unwrap();
    assert!(services::prepare(&db, "alice", "s", &mut edit).is_err());
    assert_eq!(services::ids(&db, "other").unwrap(), vec!["jp"]);
    assert!(db.query_row("SELECT node_group_id IS NULL AND enabled=0 AND deleted_at IS NULL FROM tunnels WHERE id='s'", [], |r| r.get::<_,bool>(0)).unwrap());
    assert!(db.query_row("SELECT enabled=1 AND distribution_mode='single' AND preferred_node_id IS NULL FROM tunnels WHERE id='other'", [], |r| r.get::<_,bool>(0)).unwrap());
    assert!(db
        .query_row(
            "SELECT deleted_at=1 AND node_group_id IS NULL FROM tunnels WHERE id='archive'",
            [],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    assert!(groups::members(&db, "g").unwrap().is_empty());
    assert!(!visible(&db, "hk", "alice", false).unwrap());
    assert!(visible(&db, "hk", "default", true).unwrap());
}

#[tokio::test]
async fn removal_of_offline_node_checks_groups_before_revoking_identity() {
    use std::future::IntoFuture;
    let (state, admin) = crate::tests::domain_fixture();
    nodes(&state);
    {
        let db = state.db.lock().unwrap();
        db.execute_batch("UPDATE relay_nodes SET certificate_pem='old',last_seen=0 WHERE id='jp';
            INSERT INTO relay_node_groups VALUES('asia','亚洲入口',0),('backup','备用组',0);
            INSERT INTO relay_group_members VALUES('asia','hk'),('asia','jp'),('asia','us'),('backup','hk'),('backup','jp');
            INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,node_group_id,distribution_mode,preferred_node_id,created_at,updated_at)
            VALUES('s','default','媒体中心','tcp','127.0.0.1',80,'asia','manual','jp',0,0);
            DELETE FROM service_nodes WHERE service_id='s';
            INSERT INTO service_nodes VALUES('s','hk'),('s','jp'),('s','us');").unwrap();
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api/v1/nodes/jp", listener.local_addr().unwrap());
    let server = tokio::spawn(axum::serve(listener, router(state.clone())).into_future());
    let client = reqwest::Client::builder()
        .no_proxy()
        .default_headers(admin)
        .build()
        .unwrap();
    let delete = || client.delete(&url).send();
    let conflict = delete().await.unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert!(conflict.text().await.unwrap().contains("备用组"));
    {
        let db = state.db.lock().unwrap();
        assert_eq!(
            groups::members(&db, "asia").unwrap(),
            vec!["hk", "jp", "us"]
        );
        db.execute("INSERT INTO relay_group_members VALUES('backup','us')", [])
            .unwrap();
    }
    {
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO relay_group_grants VALUES('asia','default')",
            [],
        )
        .unwrap();
        db.execute_batch("INSERT INTO node_update_jobs(id,actor,target_version,status,created_at) VALUES('job','u','1','paused',0);
            INSERT INTO node_update_items(job_id,node_id,position,stage) VALUES('job','jp',0,'unknown');").unwrap();
    }
    assert_eq!(delete().await.unwrap().status(), StatusCode::CONFLICT);
    state
        .db
        .lock()
        .unwrap()
        .execute_batch(
            "UPDATE node_update_jobs SET status='cancelled' WHERE id='job';
        UPDATE relay_nodes SET last_seen=unixepoch() WHERE id='jp';",
        )
        .unwrap();
    // 确认框显示离线后又收到心跳，删除必须重新核实在线状态。
    let conflict = delete().await.unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert!(conflict.text().await.unwrap().contains("节点仍在线"));
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE relay_nodes SET last_seen=0 WHERE id='jp'", [])
        .unwrap();
    let response = delete().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.json::<Value>().await.unwrap()["removed"], true);
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    server.abort();
    let db = state.db.lock().unwrap();
    assert_eq!(groups::members(&db, "asia").unwrap(), vec!["hk", "us"]);
    assert_eq!(groups::members(&db, "backup").unwrap(), vec!["hk", "us"]);
    assert_eq!(services::ids(&db, "s").unwrap(), vec!["hk", "us"]);
    assert!(db.query_row("SELECT node_group_id='asia' AND distribution_mode='latency' AND preferred_node_id IS NULL FROM tunnels WHERE id='s'", [], |r| r.get::<_,bool>(0)).unwrap());
    assert!(db
        .query_row(
            "SELECT removed_at IS NOT NULL AND certificate_pem='' FROM relay_nodes WHERE id='jp'",
            [],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
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
    assert_eq!(first["version"], releases::current_version());
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
    assert_eq!(third["version"], first["version"]);
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
