use super::*;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) fn sample(state: &AppState, seconds: u64, flush: bool) -> Result<()> {
    let snapshot = state.tunnel_runtime.traffic.0.lock().unwrap();
    let wall = snapshot.last_wall + seconds as f64;
    let tick = snapshot.last_tick + Duration::from_secs(seconds);
    drop(snapshot);
    state
        .tunnel_runtime
        .traffic
        .sample_at(state, wall, tick, flush)
}
fn all() -> Scope {
    Scope {
        tenant: None,
        tunnel: None,
    }
}

#[tokio::test]
async fn forwarding_counts_live_bytes_and_preserves_cancelled_transfer() {
    let (state, _) = crate::tests::domain_fixture();
    let meter = state.tunnel_runtime.traffic.meter("default", "stream");
    let (mut public, socket) = tokio::io::duplex(8);
    let (mut origin, stream) = tokio::io::duplex(8);
    let mut socket = Counted::new(socket, meter.clone(), false);
    let mut stream = Counted::new(stream, meter, true);
    let task =
        tokio::spawn(async move { tokio::io::copy_bidirectional(&mut socket, &mut stream).await });
    public.write_all(b"request").await.unwrap();
    let mut received = [0; 7];
    origin.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"request");
    origin.write_all(b"response").await.unwrap();
    let mut received = [0; 8];
    public.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"response");
    sample(&state, 5, false).unwrap();
    assert!(!task.is_finished(), "长连接尚未关闭也必须有统计");
    let live = realtime(&state, all()).unwrap().0;
    assert_eq!(live.rates.to_origin, 1.4);
    assert_eq!(live.rates.to_public, 1.6);
    task.abort();
    let _ = task.await;
    sample(&state, 5, true).unwrap();
    let result = history(&state, all(), &Filter::default()).unwrap().0;
    assert_eq!(result.total.to_origin, 7);
    assert_eq!(result.total.to_public, 8);
    assert_eq!(realtime(&state, all()).unwrap().0.rates.to_origin, 0.0);
}

#[test]
fn failed_flush_retries_without_duplicates_and_restart_keeps_history() {
    let (state, _) = crate::tests::domain_fixture();
    let meter = state.tunnel_runtime.traffic.meter("default", "t");
    meter.record(unix_now(), true, 100);
    state.db.lock().unwrap().execute_batch("CREATE TRIGGER fail_traffic BEFORE INSERT ON traffic_minutes BEGIN SELECT RAISE(ABORT,'模拟写盘失败'); END;").unwrap();
    assert!(sample(&state, 5, true).is_err());
    assert_eq!(
        history(&state, all(), &Filter::default())
            .unwrap()
            .0
            .total
            .to_origin,
        100
    );
    meter.record(unix_now(), false, 50);
    state
        .db
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_traffic")
        .unwrap();
    sample(&state, 5, true).unwrap();
    sample(&state, 5, true).unwrap();
    let result = history(&state, all(), &Filter::default()).unwrap().0;
    assert_eq!((result.total.to_origin, result.total.to_public), (100, 50));
    let mut restarted = state.clone();
    restarted.tunnel_runtime = Arc::new(transport::Runtime::new("127.0.0.1".parse().unwrap()));
    let result = history(&restarted, all(), &Filter::default()).unwrap().0;
    assert_eq!((result.total.to_origin, result.total.to_public), (100, 50));
    assert_eq!(realtime(&restarted, all()).unwrap().0.status, "collecting");
}

#[test]
fn history_distinguishes_idle_from_gaps_aggregates_ranges_and_cleans_expiry() {
    let (state, _) = crate::tests::domain_fixture();
    let now = unix_now() / 60 * 60;
    {
        let db = state.db.lock().unwrap();
        for (minute, count) in [(now - 120, 10), (now, 20), (now - RETENTION - 120, 1000)] {
            db.execute(
                "INSERT INTO traffic_minutes VALUES ('default','t',?1,?2,0)",
                params![minute, count],
            )
            .unwrap();
            db.execute("INSERT INTO traffic_coverage VALUES (?1,60)", [minute])
                .unwrap();
        }
        db.execute("INSERT INTO traffic_coverage VALUES (?1,60)", [now - 180])
            .unwrap();
    }
    let filter = Filter {
        range: Some("1h".into()),
        ..Default::default()
    };
    let result = history(&state, all(), &filter).unwrap().0;
    assert_eq!(result.total.to_origin, 30);
    assert_eq!(result.points.len(), 60);
    assert!(result
        .points
        .iter()
        .find(|p| p.at == now - 60)
        .unwrap()
        .rates
        .is_none());
    assert_eq!(
        result
            .points
            .iter()
            .find(|p| p.at == now - 180)
            .unwrap()
            .rates
            .unwrap()
            .to_origin,
        0.0
    );
    for (range, count) in [("24h", 288), ("7d", 168)] {
        let result = history(
            &state,
            all(),
            &Filter {
                range: Some(range.into()),
                ..Default::default()
            },
        )
        .unwrap()
        .0;
        assert_eq!(result.total.to_origin, 30);
        assert_eq!(result.points.len(), count);
    }
    sample(&state, 5, true).unwrap();
    assert_eq!(
        state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM traffic_minutes WHERE minute<?1",
                [now - RETENTION],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn concurrent_meters_and_deleted_workspaces_do_not_resurrect_statistics() {
    let (state, _) = crate::tests::domain_fixture();
    crate::accounts::tests::add_user(&state, "alice");
    let meter = state.tunnel_runtime.traffic.meter("alice", "t");
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let meter = &meter;
            scope.spawn(move || {
                for _ in 0..1000 {
                    meter.record(unix_now(), true, 3);
                }
            });
        }
    });
    sample(&state, 5, true).unwrap();
    assert_eq!(
        history(&state, all(), &Filter::default())
            .unwrap()
            .0
            .total
            .to_origin,
        24000
    );
    state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM tenants WHERE id='alice'", [])
        .unwrap();
    meter.record(unix_now(), true, 50);
    sample(&state, 5, true).unwrap();
    assert_eq!(
        history(&state, all(), &Filter::default())
            .unwrap()
            .0
            .total
            .to_origin,
        0
    );
}

#[tokio::test]
async fn router_enforces_personal_admin_and_tunnel_boundaries() {
    let (state, admin) = crate::tests::domain_fixture();
    let alice = crate::accounts::tests::add_user(&state, "alice");
    let bob = crate::accounts::tests::add_user(&state, "bob");
    {
        let db = state.db.lock().unwrap();
        for (id, tenant) in [("ta", "alice"), ("tb", "bob")] {
            db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES (?1,?2,?1,'tcp','localhost',80,0,0)",params![id,tenant]).unwrap();
        }
        db.execute("INSERT INTO users(id,tenant_id,username,role,password_hash,created_at) VALUES ('alias','alice','alias','tenant','unused',0)",[]).unwrap();
    }
    for (tenant, tunnel, count) in [
        ("default", "admin-t", 5),
        ("alice", "ta", 10),
        ("bob", "tb", 20),
    ] {
        state
            .tunnel_runtime
            .traffic
            .meter(tenant, tunnel)
            .record(unix_now(), true, count);
    }
    sample(&state, 5, true).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server_state = state.clone();
    let task = tokio::spawn(async move {
        axum::serve(listener, router(server_state)).await.unwrap();
    });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for suffix in ["realtime", "history"] {
        for (headers, path, status) in [
            (&alice, format!("/api/v1/admin/traffic/{suffix}"), 403),
            (&alice, format!("/api/v1/traffic/{suffix}?user_id=bob"), 400),
            (
                &alice,
                format!("/api/v1/traffic/{suffix}?workspace_id=bob"),
                400,
            ),
            (
                &alice,
                format!("/api/v1/traffic/{suffix}?tunnel_id=tb"),
                404,
            ),
            (
                &admin,
                format!("/api/v1/admin/traffic/{suffix}?tunnel_id=ta"),
                400,
            ),
            (
                &admin,
                format!("/api/v1/admin/traffic/{suffix}?user_id=alice&tunnel_id=tb"),
                404,
            ),
            (
                &admin,
                format!("/api/v1/admin/traffic/{suffix}?user_id=missing"),
                404,
            ),
            (
                &admin,
                format!("/api/v1/admin/workspaces/bob/traffic/{suffix}"),
                404,
            ),
        ] {
            assert_eq!(
                client
                    .get(format!("{url}{path}"))
                    .headers(headers.clone())
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .as_u16(),
                status,
                "{path}"
            );
        }
    }
    for (headers, path, count) in [
        (&alice, "/api/v1/traffic/history", 10),
        (&bob, "/api/v1/traffic/history", 20),
        (&admin, "/api/v1/traffic/history", 5),
        (&admin, "/api/v1/admin/traffic/history", 35),
        (
            &admin,
            "/api/v1/admin/traffic/history?user_id=alice&tunnel_id=ta",
            10,
        ),
    ] {
        let body: Value = client
            .get(format!("{url}{path}"))
            .headers(headers.clone())
            .header("x-nexo-internal-workspace", "bob")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(body["total"]["to_origin"], count, "{path}");
    }
    // 改名与停用不删除历史，停用后不再显示实时转发速率。
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE users SET enabled=0,username='renamed' WHERE id='bob'",
            [],
        )
        .unwrap();
    let value: Value = client
        .get(format!("{url}/api/v1/admin/traffic/realtime?user_id=bob"))
        .headers(admin.clone())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(value["rates"]["to_origin"], 0.0);
    let value: Value = client
        .get(format!("{url}/api/v1/admin/traffic/history?user_id=bob"))
        .headers(admin.clone())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(value["total"]["to_origin"], 20);
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE tunnels SET deleted_at=1 WHERE id='tb'", [])
        .unwrap();
    assert_eq!(
        history(&state, all(), &Filter::default())
            .unwrap()
            .0
            .total
            .to_origin,
        35
    );
    task.abort();
}
