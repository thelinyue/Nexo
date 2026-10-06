use super::*;

fn fixture() -> (AppState, String, i64) {
    let (state, _) = crate::tests::domain_fixture();
    let month = period(unix_now()).0;
    {
        let db = state.db.lock().unwrap();
        db.execute_batch("INSERT INTO relay_nodes(id,name,approved,traffic_quota_supported,created_at) VALUES('metered','计量节点',1,1,0);
            INSERT INTO relay_node_grants VALUES('metered','default');
            INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('s','default','服务','tcp','127.0.0.1',80,0,0);
            INSERT INTO service_nodes VALUES('s','metered');
            INSERT INTO node_traffic_limits(node_id,monthly_limit_bytes,revision) VALUES('metered',1000,1);").unwrap();
    }
    (state, "metered".into(), month)
}

#[test]
fn simultaneous_reservations_cannot_overspend_and_final_reports_are_idempotent() {
    let (state, node, month) = fixture();
    let db = state.db.lock().unwrap();
    let (a, n) = reserve(&db, &node, "s", 1, 1, month, 700).unwrap();
    assert_eq!(n, 700);
    let (b, n) = reserve(&db, &node, "s", 1, 1, month, 700).unwrap();
    assert_eq!(n, 300);
    assert_eq!(reserve(&db, &node, "s", 1, 1, month, 1).unwrap().1, 0);
    settle(&db, &node, &a, 100, 200, false).unwrap();
    settle(&db, &node, &a, 100, 200, false).unwrap();
    let q = view(&db, &node, unix_now()).unwrap();
    assert_eq!((q.used_bytes, q.reserved_bytes), (300, 700));
    assert!(!q.exhausted);
    settle(&db, &node, &a, 100, 200, true).unwrap();
    settle(&db, &node, &a, 100, 200, true).unwrap();
    assert_eq!(view(&db, &node, unix_now()).unwrap().reserved_bytes, 300);
    settle(&db, &node, &b, 0, 300, true).unwrap();
    assert_eq!(view(&db, &node, unix_now()).unwrap().used_bytes, 600);
    assert!(settle(&db, "local", &a, 100, 200, true).is_err());
}

#[test]
fn stale_policy_service_and_month_are_rejected_and_pending_survives_reload() {
    let (state, node, month) = fixture();
    let db = state.db.lock().unwrap();
    for (service_rev, quota_rev, m) in [(2, 1, month), (1, 2, month), (1, 1, month - 1)] {
        assert_eq!(
            reserve(&db, &node, "s", service_rev, quota_rev, m, 100)
                .unwrap()
                .1,
            0
        );
    }
    let (id, _) = reserve(&db, &node, "s", 1, 1, month, 1000).unwrap();
    // 重新迁移模拟控制器重启，不能清理未结算占用。
    super::super::migrate(&db).unwrap();
    assert_eq!(view(&db, &node, unix_now()).unwrap().reserved_bytes, 1000);
    assert_eq!(reserve(&db, &node, "s", 1, 1, month, 1).unwrap().1, 0);
    assert!(settle(&db, &node, &id, 1001, 0, true).is_err());
    settle(&db, &node, &id, 400, 600, true).unwrap();
    assert!(view(&db, &node, unix_now()).unwrap().exhausted);
    db.execute("UPDATE node_traffic_limits SET monthly_limit_bytes=NULL,revision=revision+1 WHERE node_id=?1",[&node]).unwrap();
    assert!(!view(&db, &node, unix_now()).unwrap().exhausted);
}

#[test]
fn beijing_months_and_old_reports_do_not_restore_new_month() {
    let at = time::OffsetDateTime::parse(
        "2026-01-31T15:59:59Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp();
    let jan = period(at);
    let feb = period(at + 1);
    assert_eq!(jan.1, feb.0);
    assert_ne!(jan.0, feb.0);
    let (state, node, month) = fixture();
    let db = state.db.lock().unwrap();
    let (id, _) = reserve(&db, &node, "s", 1, 1, month, 700).unwrap();
    let next = period(period(unix_now()).1).0;
    db.execute(
        "INSERT INTO node_traffic_months VALUES(?1,?2,20,30)",
        params![node, next],
    )
    .unwrap();
    settle(&db, &node, &id, 5, 10, true).unwrap();
    let q = view(&db, &node, next).unwrap();
    assert_eq!((q.used_bytes, q.reserved_bytes), (20, 30));
    for invalid in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!("100"),
        json!(MAX_BYTES + 1),
    ] {
        assert!(parse_limit(&invalid).is_err());
    }
}

#[tokio::test]
async fn owner_and_admin_can_manage_but_grantees_cannot_and_csrf_is_required() {
    let (state, admin) = crate::tests::domain_fixture();
    let owner = super::super::tests::tenant(&state, "owner");
    let grantee = super::super::tests::tenant(&state, "grantee");
    let other = super::super::tests::tenant(&state, "other");
    state.db.lock().unwrap().execute_batch("INSERT INTO relay_nodes(id,name,owner_tenant,approved,traffic_quota_supported,created_at) VALUES('own','自己的节点','owner',1,1,0); INSERT INTO relay_node_grants VALUES('own','grantee');").unwrap();
    let input = || {
        Json(Input {
            monthly_limit_bytes: json!(1000),
        })
    };
    let result = update(
        State(state.clone()),
        owner.clone(),
        Path("own".into()),
        input(),
    )
    .await
    .unwrap()
    .0;
    assert_eq!(result.monthly_limit_bytes, Some(1000));
    assert_eq!(
        get(State(state.clone()), grantee.clone(), Path("own".into()))
            .await
            .unwrap()
            .0
            .monthly_limit_bytes,
        Some(1000)
    );
    assert_eq!(
        update(State(state.clone()), grantee, Path("own".into()), input())
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(State(state.clone()), other, Path("own".into()))
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    let mut no_csrf = owner;
    no_csrf.remove("x-nexo-csrf");
    assert_eq!(
        update(State(state.clone()), no_csrf, Path("own".into()), input())
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    let _ = update(
        State(state.clone()),
        admin.clone(),
        Path("own".into()),
        Json(Input {
            monthly_limit_bytes: Value::Null,
        }),
    )
    .await
    .unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE relay_nodes SET traffic_quota_supported=0 WHERE id='own'",
            [],
        )
        .unwrap();
    assert_eq!(
        update(
            State(state.clone()),
            admin.clone(),
            Path("own".into()),
            input()
        )
        .await
        .unwrap_err()
        .status,
        StatusCode::BAD_REQUEST
    );
    assert!(update(State(state), admin, Path("local".into()), input())
        .await
        .is_err());
    assert!(serde_json::from_value::<Input>(json!({})).is_err());
}

#[test]
fn node_and_user_quotas_are_independent_and_exhausted_nodes_leave_healthy_candidates() {
    let (state, node, month) = fixture();
    {
        let db = state.db.lock().unwrap();
        db.execute_batch("INSERT INTO traffic_quota_limits VALUES('default',1); INSERT INTO node_traffic_months VALUES('metered',0,0,0);").unwrap();
        let (id, n) = reserve(&db, &node, "s", 1, 1, month, 1000).unwrap();
        assert_eq!(n, 1000);
        settle(&db, &node, &id, 400, 600, true).unwrap();
        // 用户额度保持原值，节点额度不会写入用户统计或额度表。
        assert_eq!(
            db.query_row(
                "SELECT monthly_limit_bytes FROM traffic_quota_limits WHERE tenant_id='default'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM traffic_quota_months", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
        db.execute(
            "UPDATE relay_nodes SET last_seen=?1 WHERE id='metered'",
            [unix_now()],
        )
        .unwrap();
        db.execute("INSERT INTO tunnel_applied_states(tunnel_id,revision,status,updated_at) VALUES('s',1,'ready',?1)",[unix_now()]).unwrap();
        for id in ["local", "metered"] {
            db.execute("INSERT INTO relay_service_health(node_id,service_id,revision,healthy,checked_at) VALUES(?1,'s',1,1,?2)",params![id,unix_now()]).unwrap();
            db.execute("INSERT INTO relay_public_health(node_id,service_id,revision,healthy,checked_at,address) VALUES(?1,'s',1,1,?2,'')",params![id,unix_now()]).unwrap();
        }
        assert_eq!(db.query_row("SELECT COUNT(*) FROM relay_healthy_service_nodes WHERE service_id='s' AND node_id='metered'",[],|r|r.get::<_,u64>(0)).unwrap(),0);
        assert_eq!(db.query_row("SELECT COUNT(*) FROM relay_healthy_service_nodes WHERE service_id='s' AND node_id='local'",[],|r|r.get::<_,u64>(0)).unwrap(),1);
        assert_eq!(
            super::super::selection::choose(
                "manual",
                Some("metered"),
                Some(("metered", 0)),
                unix_now(),
                &[super::super::selection::Candidate {
                    id: "local".into(),
                    address: "127.0.0.1".into(),
                    latency: None
                }]
            )
            .unwrap()
            .0
            .id,
            "local"
        );
    }
    assert!(super::super::control::snapshot(&state, &node)
        .unwrap()
        .services
        .is_empty());
}

#[test]
fn committed_pending_budget_survives_closing_and_reopening_sqlite() {
    let path = std::env::temp_dir().join(format!("nexo-node-quota-{}.sqlite", Uuid::new_v4()));
    let month = period(unix_now()).0;
    let id;
    {
        let db = Connection::open(&path).unwrap();
        initialize_database(&db, true).unwrap();
        db.execute_batch("INSERT INTO relay_nodes(id,name,approved,traffic_quota_supported,created_at) VALUES('metered','节点',1,1,0);
            INSERT INTO relay_node_grants VALUES('metered','default');
            INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('s','default','服务','tcp','127.0.0.1',80,0,0);
            INSERT INTO service_nodes VALUES('s','metered');
            INSERT INTO node_traffic_limits(node_id,monthly_limit_bytes,revision) VALUES('metered',1000,1);").unwrap();
        (id, _) = reserve(&db, "metered", "s", 1, 1, month, 900).unwrap();
        settle(&db, "metered", &id, 100, 200, false).unwrap();
    }
    {
        let db = Connection::open(&path).unwrap();
        initialize_database(&db, false).unwrap();
        let q = view(&db, "metered", unix_now()).unwrap();
        assert_eq!(
            (q.used_bytes, q.reserved_bytes, q.remaining_bytes),
            (300, 600, Some(100))
        );
        assert_eq!(
            reserve(&db, "metered", "s", 1, 1, month, 900).unwrap().1,
            100
        );
        settle(&db, "metered", &id, 100, 200, true).unwrap();
        settle(&db, "metered", &id, 100, 200, true).unwrap();
        assert_eq!(
            view(&db, "metered", unix_now()).unwrap().reserved_bytes,
            100
        );
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn concurrent_services_share_one_atomic_node_limit() {
    let (state, node, month) = fixture();
    state.db.lock().unwrap().execute_batch("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,service_mode,created_at,updated_at) VALUES('proxy','default','反代','http','127.0.0.1',80,'reverse_proxy',0,0); INSERT INTO service_nodes VALUES('proxy','metered');").unwrap();
    let threads = (0..8)
        .map(|i| {
            let state = state.clone();
            let node = node.clone();
            std::thread::spawn(move || {
                reserve(
                    &state.db.lock().unwrap(),
                    &node,
                    if i % 2 == 0 { "s" } else { "proxy" },
                    1,
                    1,
                    month,
                    300,
                )
                .unwrap()
                .1
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        threads.into_iter().map(|t| t.join().unwrap()).sum::<u64>(),
        1000
    );
}

#[tokio::test]
async fn creation_preset_is_atomic_and_does_not_grant_node_administration() {
    let (state, _) = crate::tests::domain_fixture();
    state.security.configuration.write().unwrap().public_url = "https://manage.example".into();
    let owner = super::super::tests::tenant(&state, "owner");
    let input = |limit| {
        serde_json::from_value(
            json!({"name":"自建节点","public_ipv4":"8.8.8.8","monthly_limit_bytes":limit}),
        )
        .unwrap()
    };
    assert!(
        super::super::create(State(state.clone()), owner.clone(), Json(input(0)))
            .await
            .is_err()
    );
    assert_eq!(
        state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM relay_nodes WHERE owner_tenant='owner'",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    let created = super::super::create(State(state.clone()), owner.clone(), Json(input(1000)))
        .await
        .unwrap()
        .0;
    let id = created["id"].as_str().unwrap();
    let detail = super::super::detail(State(state.clone()), owner.clone(), Path(id.into()))
        .await
        .unwrap()
        .0;
    assert_eq!(detail["can_manage_quota"], true);
    assert_eq!(detail["traffic_quota"]["monthly_limit_bytes"], 1000);
    assert_eq!(detail["traffic_quota"]["supported"], false);
    assert_eq!(
        super::super::approve(State(state), owner, Path(id.into()))
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
}
