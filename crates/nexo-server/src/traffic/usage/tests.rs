use super::*;
use crate::traffic::tests::sample;

fn all() -> Scope {
    Scope {
        tenant: None,
        tunnel: None,
    }
}
fn selected(tenant: &str) -> Scope {
    Scope {
        tenant: Some(tenant.into()),
        tunnel: None,
    }
}
fn timestamp(year: i32, month: u8, day: u8, hour: u8) -> i64 {
    time::Date::from_calendar_date(year, month.try_into().unwrap(), day)
        .unwrap()
        .with_hms(hour, 0, 0)
        .unwrap()
        .assume_utc()
        .unix_timestamp()
        - OFFSET
}

#[test]
fn calendar_uses_beijing_monday_month_year_and_leap_boundaries() {
    for (now, week, month) in [
        (
            timestamp(2026, 9, 28, 0),
            timestamp(2026, 9, 28, 0),
            timestamp(2026, 9, 1, 0),
        ),
        (
            timestamp(2027, 1, 1, 0),
            timestamp(2026, 12, 28, 0),
            timestamp(2027, 1, 1, 0),
        ),
        (
            timestamp(2024, 2, 29, 23),
            timestamp(2024, 2, 26, 0),
            timestamp(2024, 2, 1, 0),
        ),
        (
            timestamp(2024, 3, 1, 0),
            timestamp(2024, 2, 26, 0),
            timestamp(2024, 3, 1, 0),
        ),
    ] {
        assert_eq!(starts(now), [day_start(now), week, month]);
    }
    let midnight = timestamp(2026, 10, 1, 0);
    assert_eq!(day_start(midnight - 1), midnight - 86400);
    assert_eq!(day_start(midnight), midnight);
}

#[test]
fn migration_backfills_once_and_month_survives_minute_retention() {
    let (state, _) = crate::tests::domain_fixture();
    let now = timestamp(2026, 9, 26, 12);
    let old = timestamp(2026, 9, 2, 12);
    {
        let db = state.db.lock().unwrap();
        db.execute("DELETE FROM traffic_usage_state", []).unwrap();
        db.execute(
            "INSERT INTO traffic_minutes VALUES ('default','old-tunnel',?1,120,80)",
            [old],
        )
        .unwrap();
        db.execute("INSERT INTO traffic_coverage VALUES (?1,60)", [old])
            .unwrap();
        initialize_schema(&db).unwrap();
        initialize_schema(&db).unwrap();
    }
    let result = usage(&state, all(), now).unwrap().0;
    assert_eq!(result.month.total.to_origin, 120);
    assert_eq!(result.month.total.to_public, 80);
    assert_eq!(result.today.total.to_origin, 0);
    assert!(result.month.partial);
    let tick = state.tunnel_runtime.traffic.0.lock().unwrap().last_tick + Duration::from_secs(5);
    state
        .tunnel_runtime
        .traffic
        .sample_at(&state, now as f64, tick, true)
        .unwrap();
    assert_eq!(
        state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM traffic_minutes", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        usage(&state, all(), now).unwrap().0.month.total.to_origin,
        120
    );
    let mut restarted = state.clone();
    restarted.tunnel_runtime = Arc::new(transport::Runtime::new("127.0.0.1".parse().unwrap()));
    assert_eq!(
        usage(&restarted, all(), now)
            .unwrap()
            .0
            .month
            .total
            .to_public,
        80
    );
}

#[test]
fn daily_flush_failure_is_atomic_and_pending_is_counted_once() {
    let (state, _) = crate::tests::domain_fixture();
    crate::accounts::tests::add_user(&state, "alice");
    let now = unix_now();
    let meter = state.tunnel_runtime.traffic.meter("alice", "t");
    meter.record(now, true, 100);
    state.db.lock().unwrap().execute_batch("CREATE TRIGGER fail_daily BEFORE INSERT ON traffic_daily BEGIN SELECT RAISE(ABORT,'模拟写盘失败'); END;").unwrap();
    assert!(sample(&state, 5, true).is_err());
    assert_eq!(
        usage(&state, all(), now).unwrap().0.today.total.to_origin,
        100
    );
    assert_eq!(
        state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM traffic_minutes", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        0
    );
    meter.record(now, false, 50);
    state
        .db
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_daily")
        .unwrap();
    sample(&state, 5, true).unwrap();
    sample(&state, 5, true).unwrap();
    let result = usage(&state, all(), now).unwrap().0;
    assert_eq!(
        (result.today.total.to_origin, result.today.total.to_public),
        (100, 50)
    );
    assert_eq!(result.week.total.to_origin, 100);
    state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM tenants WHERE id='alice'", [])
        .unwrap();
    assert_eq!(
        usage(&state, all(), now).unwrap().0.month.total.to_origin,
        0
    );
}

#[tokio::test]
async fn reset_preserves_history_handles_unsampled_bytes_failure_and_restart() {
    let (state, admin) = crate::tests::domain_fixture();
    crate::accounts::tests::add_user(&state, "alice");
    let now = unix_now();
    let meter = state.tunnel_runtime.traffic.meter("alice", "a");
    let other = state.tunnel_runtime.traffic.meter("default", "b");
    other.record(now, true, 7);
    meter.record(now, true, 100);
    sample(&state, 5, true).unwrap();
    meter.record(now, true, 20);
    sample(&state, 5, false).unwrap();
    meter.record(now, false, 30);
    state.db.lock().unwrap().execute_batch("CREATE TRIGGER fail_reset BEFORE INSERT ON audit_events WHEN NEW.event_type='traffic.usage_reset' BEGIN SELECT RAISE(ABORT,'模拟审计失败'); END;").unwrap();
    assert!(admin_reset(
        State(state.clone()),
        admin.clone(),
        Json(ResetRequest {
            user_id: "alice".into()
        })
    )
    .await
    .is_err());
    assert_eq!(
        usage(&state, selected("alice"), now)
            .unwrap()
            .0
            .today
            .total
            .to_origin,
        120
    );
    state
        .db
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_reset")
        .unwrap();
    let _ = admin_reset(
        State(state.clone()),
        admin.clone(),
        Json(ResetRequest {
            user_id: "alice".into(),
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        usage(&state, selected("alice"), now)
            .unwrap()
            .0
            .today
            .total
            .to_origin,
        0
    );
    // 同一条连接、同一分钟仍在转发；重复重置后只应统计最后一次重置以后的字节。
    meter.record(now, false, 10);
    let _ = admin_reset(
        State(state.clone()),
        admin,
        Json(ResetRequest {
            user_id: "alice".into(),
        }),
    )
    .await
    .unwrap();
    meter.record(now, true, 3);
    meter.record(now, false, 4);
    sample(&state, 5, true).unwrap();
    let result = usage(&state, selected("alice"), now).unwrap().0;
    assert_eq!(
        (result.today.total.to_origin, result.today.total.to_public),
        (3, 4)
    );
    assert!(result.reset_at.is_some());
    let total = usage(&state, all(), now).unwrap().0;
    assert_eq!(total.reset_users, 1);
    assert_eq!(total.today.total.to_origin, 10);
    let history = history(&state, selected("alice"), &Filter::default())
        .unwrap()
        .0;
    assert_eq!(
        (history.total.to_origin, history.total.to_public),
        (123, 44)
    );
    assert_eq!(
        realtime(&state, selected("alice"))
            .unwrap()
            .0
            .rates
            .to_public,
        8.8
    );
    initialize_schema(&state.db.lock().unwrap()).unwrap();
    let mut restarted = state.clone();
    restarted.tunnel_runtime = Arc::new(transport::Runtime::new("127.0.0.1".parse().unwrap()));
    assert_eq!(
        usage(&restarted, selected("alice"), now)
            .unwrap()
            .0
            .month
            .total
            .to_public,
        4
    );
    assert_eq!(state.db.lock().unwrap().query_row("SELECT COUNT(*) FROM audit_events WHERE event_type='traffic.usage_reset' AND resource_id='alice'", [], |r| r.get::<_, u32>(0)).unwrap(),2);
}

#[tokio::test]
async fn usage_and_reset_router_enforce_real_identity_csrf_and_user_scope() {
    let (state, admin) = crate::tests::domain_fixture();
    let alice = crate::accounts::tests::add_user(&state, "alice");
    crate::accounts::tests::add_user(&state, "bob");
    state.db.lock().unwrap().execute("INSERT INTO users(id,tenant_id,username,role,password_hash,created_at) VALUES ('alias','alice','alias','tenant','unused',0)",[]).unwrap();
    for (tenant, count) in [("default", 5), ("alice", 10), ("bob", 20)] {
        state
            .tunnel_runtime
            .traffic
            .meter(tenant, "t")
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
    for (headers, path, status, count) in [
        (&alice, "/api/v1/traffic/usage", 200, 10),
        (&admin, "/api/v1/traffic/usage", 200, 5),
        (&admin, "/api/v1/admin/traffic/usage", 200, 35),
        (&admin, "/api/v1/admin/traffic/usage?user_id=alice", 200, 10),
        (&alice, "/api/v1/admin/traffic/usage", 403, 0),
        (&alice, "/api/v1/traffic/usage?user_id=bob", 400, 0),
        (&alice, "/api/v1/traffic/usage?workspace_id=bob", 400, 0),
        (
            &admin,
            "/api/v1/admin/traffic/usage?user_id=missing",
            404,
            0,
        ),
        (&admin, "/api/v1/admin/traffic/usage?tunnel_id=t", 400, 0),
        (&admin, "/api/v1/admin/workspaces/bob/traffic/usage", 404, 0),
    ] {
        let response = client
            .get(format!("{url}{path}"))
            .headers(headers.clone())
            .header("x-nexo-internal-workspace", "bob")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status, "{path}");
        if status == 200 {
            assert_eq!(
                response.json::<serde_json::Value>().await.unwrap()["today"]["total"]["to_origin"],
                count
            );
        }
    }
    let mut no_csrf = admin.clone();
    no_csrf.remove("x-nexo-csrf");
    for (headers, body, status) in [
        (&alice, serde_json::json!({"user_id":"alice"}), 403),
        (&no_csrf, serde_json::json!({"user_id":"alice"}), 403),
        (&admin, serde_json::json!({"user_id":"missing"}), 404),
        (&admin, serde_json::json!({}), 422),
        (
            &admin,
            serde_json::json!({"user_id":"alice","workspace_id":"bob"}),
            422,
        ),
        (&admin, serde_json::json!({"user_id":"alice"}), 200),
    ] {
        let response = client
            .post(format!("{url}/api/v1/admin/traffic/reset"))
            .headers(headers.clone())
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), status, "{body}");
    }
    assert_eq!(
        usage(&state, selected("alice"), unix_now())
            .unwrap()
            .0
            .today
            .total
            .to_origin,
        0
    );
    assert_eq!(
        usage(&state, all(), unix_now())
            .unwrap()
            .0
            .today
            .total
            .to_origin,
        25
    );
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
