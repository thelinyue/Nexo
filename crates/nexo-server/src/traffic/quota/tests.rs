use super::*;
use crate::traffic::tests::sample;
use serde_json::json;
use std::future::IntoFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn set_limit(quota: &Quota, limit: Option<u64>) {
    let mut state = quota.0.lock().unwrap();
    state.limit = limit;
    state.refresh(unix_now());
}

#[tokio::test]
async fn udp_atomic_budget_retains_partial_submission_and_shares_tcp_consumption() {
    let (state, _) = crate::tests::domain_fixture();
    let quota = state.tunnel_runtime.quotas.get(&state, "default").unwrap();
    set_limit(&quota, Some(100));
    let token = quota.connection().unwrap();
    assert_eq!(
        quota.datagram(101, &token, || panic!("余额不足不能发送部分数据报")),
        None
    );
    assert_eq!(quota.datagram(80, &token, || 30), Some(30));
    assert_eq!(quota.datagram(70, &token, || 0), Some(0));
    assert_eq!(quota.view(unix_now()).used_bytes, 30);
    let mut sink = tokio::io::sink();
    let mut cx = TaskContext::from_waker(std::task::Waker::noop());
    assert!(matches!(
        quota.write(&mut sink, &mut cx, &[0; 20], &token),
        Poll::Ready(Ok(20))
    ));
    assert_eq!(
        quota.datagram(60, &token, || panic!("TCP 已消费预算")),
        None
    );
    assert_eq!(quota.datagram(50, &token, || 50), Some(50));
    assert!(token.is_cancelled());
    assert_eq!(quota.view(unix_now()).used_bytes, 100);
    set_limit(&quota, Some(200));
    assert_eq!(quota.datagram(1, &token, || panic!("旧会话不得复活")), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_tunnels_and_both_directions_share_exact_budget() {
    let (state, _) = crate::tests::domain_fixture();
    let quota = state.tunnel_runtime.quotas.get(&state, "default").unwrap();
    set_limit(&quota, Some(12_345));
    let idle_connection = quota.connection().unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..24 {
        let meter = state
            .tunnel_runtime
            .traffic
            .meter("default", &index.to_string());
        let quota = quota.clone();
        let cancel = idle_connection.clone();
        tasks.spawn(async move {
            let mut writer =
                Counted::new(tokio::io::sink(), meter, index % 2 == 0).with_quota(quota, cancel);
            let mut written = 0;
            while let Ok(count) = writer.write(&[0; 1000]).await {
                written += count;
            }
            written
        });
    }
    let mut written = 0;
    while let Some(result) = tasks.join_next().await {
        written += result.unwrap();
    }
    assert_eq!(written, 12_345);
    assert!(idle_connection.is_cancelled());
    assert!(quota.connection().is_none());
    assert_eq!(quota.view(unix_now()).used_bytes, 12_345);
    sample(&state, 5, false).unwrap();
    let history = history(
        &state,
        Scope {
            tenant: Some("default".into()),
            tunnel: None,
        },
        &Filter::default(),
    )
    .unwrap()
    .0;
    assert_eq!(history.total.to_origin + history.total.to_public, 12_345);
    set_limit(&quota, Some(20_000));
    assert!(!quota.connection().unwrap().is_cancelled());
    assert!(idle_connection.is_cancelled(), "恢复额度不能复活旧连接");
    assert_eq!(quota.view(unix_now()).remaining_bytes, Some(7_655));
    let meter = state.tunnel_runtime.traffic.meter("default", "old");
    let mut old_writer =
        Counted::new(tokio::io::sink(), meter, true).with_quota(quota.clone(), idle_connection);
    assert!(old_writer.write_all(b"old connection").await.is_err());
    assert_eq!(quota.view(unix_now()).used_bytes, 12_345);
    crate::accounts::tests::add_user(&state, "bob");
    let other = state.tunnel_runtime.quotas.get(&state, "bob").unwrap();
    set_limit(&quota, Some(1));
    let meter = state.tunnel_runtime.traffic.meter("bob", "other");
    Counted::new(tokio::io::sink(), meter, false)
        .with_quota(other.clone(), other.connection().unwrap())
        .write_all(b"other user")
        .await
        .unwrap();
    assert_eq!(other.view(unix_now()).used_bytes, 10);
}

#[tokio::test]
async fn partial_pending_failed_and_empty_writes_only_charge_success() {
    let (state, _) = crate::tests::domain_fixture();
    let quota = state.tunnel_runtime.quotas.get(&state, "default").unwrap();
    set_limit(&quota, Some(5));
    let token = quota.connection().unwrap();
    let (mut writer, mut reader) = tokio::io::duplex(3);
    let mut cx = TaskContext::from_waker(std::task::Waker::noop());
    assert!(matches!(
        quota.write(&mut writer, &mut cx, b"123456", &token),
        Poll::Ready(Ok(3))
    ));
    assert!(quota
        .write(&mut writer, &mut cx, b"123", &token)
        .is_pending());
    assert_eq!(quota.view(unix_now()).used_bytes, 3);
    let mut buffer = [0; 3];
    reader.read_exact(&mut buffer).await.unwrap();
    drop(reader);
    assert!(matches!(
        quota.write(&mut writer, &mut cx, b"123", &token),
        Poll::Ready(Err(_))
    ));
    assert_eq!(quota.view(unix_now()).used_bytes, 3);
    let mut sink = tokio::io::sink();
    assert!(matches!(
        quota.write(&mut sink, &mut cx, b"123", &token),
        Poll::Ready(Ok(2))
    ));
    assert!(matches!(
        quota.write(&mut sink, &mut cx, b"", &token),
        Poll::Ready(Ok(0))
    ));
    assert!(quota.connection().is_none());
}

#[test]
fn beijing_month_rollover_retains_previous_consumption_and_renews_token() {
    let (state, _) = crate::tests::domain_fixture();
    let quota = state.tunnel_runtime.quotas.get(&state, "default").unwrap();
    let midnight = time::Date::from_calendar_date(2028, time::Month::March, 1)
        .unwrap()
        .midnight()
        .assume_utc()
        .unix_timestamp()
        - 8 * 3600;
    let previous = period(midnight - 1);
    assert_eq!(previous.1, midnight);
    assert_eq!(previous.1 - previous.0, 29 * 86400);
    let mut inner = quota.0.lock().unwrap();
    inner.limit = Some(10);
    inner.months.insert(previous.0, 10);
    inner.refresh(midnight - 1);
    let old = inner.cancel.clone();
    assert!(old.is_cancelled());
    inner.refresh(midnight);
    assert!(!inner.exhausted());
    assert!(!inner.cancel.is_cancelled());
    assert_eq!(inner.used(), 0);
    assert_eq!(inner.months[&previous.0], 10);
    inner.refresh(midnight - 1);
    assert!(inner.exhausted(), "时钟回拨不能再次赠送相同月份额度");
}

#[tokio::test]
async fn persistence_retry_restart_delete_and_no_history_backfill() {
    let (state, _) = crate::tests::domain_fixture();
    crate::accounts::tests::add_user(&state, "alice");
    let now = unix_now();
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO traffic_daily VALUES ('alice',?1,100,200)",
            [usage::day_start(now)],
        )
        .unwrap();
    let quota = state.tunnel_runtime.quotas.get(&state, "alice").unwrap();
    assert_eq!(quota.view(now).used_bytes, 0, "额度不能复制可重置的旧统计");
    let meter = state
        .tunnel_runtime
        .traffic
        .meter("alice", "deleted-tunnel");
    let mut writer = Counted::new(tokio::io::sink(), meter, true)
        .with_quota(quota.clone(), quota.connection().unwrap());
    writer.write_all(b"1234567").await.unwrap();
    state.db.lock().unwrap().execute_batch("CREATE TRIGGER fail_quota BEFORE INSERT ON traffic_quota_months BEGIN SELECT RAISE(ABORT,'模拟额度写盘失败'); END;").unwrap();
    assert!(sample(&state, 5, true).is_err());
    writer.write_all(b"890").await.unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_quota")
        .unwrap();
    sample(&state, 5, true).unwrap();
    sample(&state, 5, true).unwrap();
    let restarted = Manager::default();
    restarted.restore(&state).unwrap();
    assert_eq!(
        restarted.get(&state, "alice").unwrap().view(now).used_bytes,
        10
    );
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE users SET username='renamed',enabled=0 WHERE id='alice'",
            [],
        )
        .unwrap();
    assert_eq!(quota.view(now).used_bytes, 10);
    state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM tenants WHERE id='alice'", [])
        .unwrap();
    writer.write_all(b"late").await.unwrap();
    sample(&state, 5, true).unwrap();
    let count: i64 = state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM traffic_quota_months WHERE tenant_id='alice'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    state
        .db
        .lock()
        .unwrap()
        .execute_batch("DROP TABLE traffic_quota_limits")
        .unwrap();
    assert!(
        Manager::default().restore(&state).is_err(),
        "读取失败不能降级无限额度"
    );
}

#[tokio::test]
async fn router_enforces_scope_csrf_updates_and_reset_independence() {
    let (state, admin) = crate::tests::domain_fixture();
    let alice = crate::accounts::tests::add_user(&state, "alice");
    crate::accounts::tests::add_user(&state, "bob");
    let quota = state.tunnel_runtime.quotas.get(&state, "alice").unwrap();
    let meter = state.tunnel_runtime.traffic.meter("alice", "t");
    Counted::new(tokio::io::sink(), meter, true)
        .with_quota(quota.clone(), quota.connection().unwrap())
        .write_all(&[0; 80])
        .await
        .unwrap();
    sample(&state, 5, false).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(axum::serve(listener, router(state.clone())).into_future());
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for (headers, path, status, used) in [
        (&alice, "/api/v1/traffic/quota", 200, 80),
        (&admin, "/api/v1/traffic/quota", 200, 0),
        (&admin, "/api/v1/admin/traffic/quota?user_id=alice", 200, 80),
        (&admin, "/api/v1/admin/traffic/quota?user_id=bob", 200, 0),
        (&alice, "/api/v1/admin/traffic/quota?user_id=alice", 403, 0),
        (&alice, "/api/v1/traffic/quota?user_id=bob", 400, 0),
        (&alice, "/api/v1/traffic/quota?workspace_id=bob", 400, 0),
        (&alice, "/api/v1/traffic/quota?tunnel_id=t", 400, 0),
        (&admin, "/api/v1/admin/traffic/quota", 400, 0),
        (
            &admin,
            "/api/v1/admin/traffic/quota?user_id=missing",
            404,
            0,
        ),
    ] {
        let result = client
            .get(format!("{url}{path}"))
            .headers(headers.clone())
            .header("x-nexo-internal-workspace", "bob")
            .send()
            .await
            .unwrap();
        assert_eq!(result.status().as_u16(), status, "{path}");
        if status == 200 {
            assert_eq!(
                result.json::<serde_json::Value>().await.unwrap()["used_bytes"],
                used
            );
        }
    }
    let path = format!("{url}/api/v1/admin/traffic/quota?user_id=alice");
    let mut no_csrf = admin.clone();
    no_csrf.remove("x-nexo-csrf");
    for (headers, value, status) in [
        (&alice, json!(100), 403),
        (&no_csrf, json!(100), 403),
        (&admin, json!(0), 400),
        (&admin, json!(-1), 400),
        (&admin, json!(1.5), 400),
        (&admin, json!(MAX_BYTES + 1), 400),
        (&admin, json!("100"), 400),
        (&admin, json!(100), 200),
    ] {
        let result = client
            .put(&path)
            .headers(headers.clone())
            .json(&json!({"monthly_limit_bytes":value}))
            .send()
            .await
            .unwrap();
        assert_eq!(result.status().as_u16(), status, "{value}");
    }
    assert_eq!(quota.view(unix_now()).remaining_bytes, Some(20));
    state.db.lock().unwrap().execute_batch("CREATE TRIGGER fail_limit BEFORE INSERT ON traffic_quota_limits BEGIN SELECT RAISE(ABORT,'模拟配置写盘失败'); END;").unwrap();
    let result = client
        .put(&path)
        .headers(admin.clone())
        .json(&json!({"monthly_limit_bytes":50}))
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(quota.view(unix_now()).monthly_limit_bytes, Some(100));
    assert!(!quota.view(unix_now()).exhausted);
    state
        .db
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_limit")
        .unwrap();

    let result = client
        .post(format!("{url}/api/v1/admin/traffic/reset"))
        .headers(admin.clone())
        .json(&json!({"user_id":"alice"}))
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    assert_eq!(quota.view(unix_now()).remaining_bytes, Some(20));
    let old = quota.connection().unwrap();
    for (limit, blocked) in [(Some(50), true), (Some(100), false), (None, false)] {
        let result = client
            .put(&path)
            .headers(admin.clone())
            .json(&json!({"monthly_limit_bytes":limit}))
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(quota.view(unix_now()).exhausted, blocked);
    }
    assert!(old.is_cancelled());
    assert!(!quota.connection().unwrap().is_cancelled());
    assert_eq!(quota.view(unix_now()).used_bytes, 80);
    let result = client
        .put(&path)
        .headers(admin.clone())
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let count: i64 = state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM audit_events WHERE event_type='traffic.quota_updated'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 4);
    let connection = quota.connection().unwrap();
    let result = client
        .delete(format!("{url}/api/v1/admin/users/alice"))
        .headers(admin.clone())
        .json(&json!({"confirm_username":"alice"}))
        .send()
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    assert!(connection.is_cancelled());
    assert!(state.tunnel_runtime.quotas.get(&state, "alice").is_err());
    let result = client.get(&path).headers(admin).send().await.unwrap();
    assert_eq!(result.status(), StatusCode::NOT_FOUND);
    task.abort();
}

#[test]
fn remote_reservations_share_local_quota_and_settle_once() {
    let (state, _) = crate::tests::domain_fixture();
    let quota = state.tunnel_runtime.quotas.get(&state, "default").unwrap();
    set_limit(&quota, Some(1000));
    let token = quota.connection().unwrap();
    assert_eq!(quota.datagram(100, &token, || 100), Some(100));
    let grants = std::thread::scope(|scope| {
        let jobs = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    quota
                        .reserve_remote(&state, "agent", "s", "default", 200)
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        jobs.into_iter()
            .map(|job| job.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(grants.iter().map(|(_, bytes)| bytes).sum::<u64>(), 900);
    assert_eq!(quota.view(unix_now()).used_bytes, 1000);
    assert!(quota.connection().is_none());
    let grant = grants.iter().find(|(_, bytes)| *bytes == 200).unwrap();
    assert!(quota
        .settle_remote(&state, "other", &grant.0, 50, 30, true)
        .is_err());
    quota
        .settle_remote(&state, "agent", &grant.0, 50, 30, false)
        .unwrap();
    assert_eq!(
        quota.view(unix_now()).used_bytes,
        1000,
        "未确认归还不能重分配"
    );
    quota
        .settle_remote(&state, "agent", &grant.0, 50, 30, true)
        .unwrap();
    quota
        .settle_remote(&state, "agent", &grant.0, 50, 30, true)
        .unwrap();
    assert_eq!(quota.view(unix_now()).used_bytes, 880);
    assert!(quota
        .settle_remote(&state, "agent", &grant.0, 201, 30, true)
        .is_err());
    state.tunnel_runtime.traffic.sample(&state, true).unwrap();
    assert!(
        state.tunnel_runtime.traffic.0.lock().unwrap().records[&("default".into(), "s".into())]
            .rate
            .to_origin
            > 0.0
    );
    let db = state.db.lock().unwrap();
    assert_eq!(
        db.query_row(
            "SELECT SUM(to_origin+to_public) FROM traffic_minutes WHERE tenant_id='default'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        80
    );
    assert_eq!(
        db.query_row(
            "SELECT SUM(to_origin+to_public) FROM traffic_daily WHERE tenant_id='default'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        80
    );
    assert_eq!(
        db.query_row(
            "SELECT used_bytes FROM traffic_quota_months WHERE tenant_id='default'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        880
    );
}
