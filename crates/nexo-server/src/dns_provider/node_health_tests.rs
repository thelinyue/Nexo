//! 固定本机 IPv4 与模拟 DNS 验证协调闭环，不把公网或应用健康计入本机验收。
use super::*;
use crate::{nodes, unix_now, AppState};
use axum::http::{HeaderMap, StatusCode};
use tokio::sync::Notify;

type Gate = (Arc<Notify>, Arc<Notify>);

struct Fixture {
    state: AppState,
    dns: Dns,
    body: Arc<Mutex<Value>>,
    gate: Arc<Mutex<Option<Gate>>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    async fn new() -> Self {
        let (mut state, _) = crate::tests::domain_fixture();
        let (zone, dns, dns_task) = mock().await;
        *state.tunnel_runtime.direct.test_zone.lock().await = Some(zone);
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        Arc::make_mut(&mut state.config).caddy.http_listen = format!(":{port}");
        let body = Arc::new(Mutex::new(
            json!({"node_id":"b","service_id":"s","revision":1}),
        ));
        let gate = Arc::new(Mutex::new(None::<Gate>));
        let served = body.clone();
        let pending = gate.clone();
        let app = Router::new().fallback(move |headers: HeaderMap, uri: Uri| {
            let served = served.clone();
            let pending = pending.clone();
            async move {
                assert_eq!(headers["host"], format!("emby.direct.test:{port}"));
                assert_eq!(
                    uri.path(),
                    nodes::health::PROBE_PATH,
                    "不能请求应用或登录接口"
                );
                let gate = pending.lock().unwrap().take();
                if let Some((started, release)) = gate {
                    started.notify_one();
                    release.notified().await;
                }
                (StatusCode::OK, Json(served.lock().unwrap().clone()))
            }
        });
        let probe_task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        {
            let db = state.db.lock().unwrap();
            db.execute_batch("INSERT INTO public_domains(id,tenant_id,domain,created_at,updated_at) VALUES('d','default','direct.test',0,0);
                INSERT INTO devices(id,tenant_id,name,status,created_at,updated_at) VALUES('agent','default','NAS','online',0,0);
                INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,local_address,local_port,hostname,public_domain_id,distribution_mode,created_at,updated_at) VALUES('s','default','agent','service','http','127.0.0.1',8096,'emby','d','dns',0,0);
                DELETE FROM service_nodes WHERE service_id='s';").unwrap();
            db.execute("INSERT INTO tunnel_applied_states(tunnel_id,revision,status,updated_at) VALUES('s',1,'ready',?1)",[unix_now()]).unwrap();
            for (id, ip, supported) in [("a", "127.0.0.1", false), ("b", "127.0.0.2", true)] {
                db.execute("INSERT INTO relay_nodes(id,name,public_ipv4,approved,last_seen,created_at) VALUES(?1,?1,?2,1,?3,0)",rusqlite::params![id,ip,unix_now()]).unwrap();
                db.execute("INSERT INTO relay_node_grants VALUES(?1,'default')", [id])
                    .unwrap();
                db.execute("INSERT INTO service_nodes VALUES('s',?1)", [id])
                    .unwrap();
                db.execute("INSERT INTO relay_service_health(node_id,service_id,revision,healthy,checked_at,public_probe_supported) VALUES(?1,'s',1,1,?2,?3)",rusqlite::params![id,unix_now(),supported]).unwrap();
            }
        }
        dns.records
            .lock()
            .unwrap()
            .push(record("AAAA", "2001:4860::1"));
        Self {
            state,
            dns,
            body,
            gate,
            tasks: vec![dns_task, probe_task],
        }
    }

    async fn sync(&self) {
        nodes::dns::sync(&self.state, "s").await.unwrap();
    }

    fn addresses(&self) -> Vec<String> {
        let records = self.dns.records.lock().unwrap();
        assert!(records
            .iter()
            .any(|r| r.kind == "AAAA" && r.value == "2001:4860::1"));
        assert!(records
            .iter()
            .filter(|r| r.kind == "A")
            .all(|r| r.ttl == 60));
        let mut addresses: Vec<_> = records
            .iter()
            .filter(|r| r.kind == "A")
            .map(|r| r.value.clone())
            .collect();
        addresses.sort();
        addresses
    }

    fn health(&self) -> Value {
        nodes::services::statuses(&self.state.db.lock().unwrap(), "s").unwrap()
    }
}

#[tokio::test]
async fn completed_node_update_does_not_publish_failed_origin() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM service_nodes WHERE node_id='b'", [])
        .unwrap();
    for _ in 0..3 {
        fixture.sync().await;
    }
    assert_eq!(fixture.addresses(), ["127.0.0.1"]);
    fixture.state.db.lock().unwrap().execute_batch("INSERT INTO node_update_jobs(id,actor,target_version,status,accept_interruption,created_at) VALUES('maintenance','u','0.2.20','running',1,unixepoch());
        INSERT INTO node_update_items(job_id,node_id,position,stage,deadline) VALUES('maintenance','a',0,'verifying',unixepoch()+120);
        UPDATE relay_nodes SET maintenance=1 WHERE id='a';
        UPDATE tunnel_applied_states SET status='failed',error_message='Connection refused';").unwrap();
    let report = nexo_protocol::nodes::UpdateReport {
        task_id: Some("maintenance-0-0".into()),
        stage: "installed".into(),
        error: None,
    };
    for _ in 0..3 {
        assert!(
            nodes::updates::advance(&fixture.state, "a", "0.2.20", 0, &report)
                .unwrap()
                .is_none()
        );
    }
    assert!(fixture
        .state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT status='complete' FROM node_update_jobs WHERE id='maintenance'",
            [],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    fixture.sync().await;
    assert!(
        fixture.addresses().is_empty(),
        "节点安装成功不能恢复故障服务的 A"
    );
    assert_eq!(fixture.health()[0]["healthy"], false);
}

#[tokio::test]
async fn single_entry_maintenance_does_not_require_dns_provider_availability() {
    let fixture = Fixture::new().await;
    fixture
        .state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM service_nodes WHERE node_id='b'", [])
        .unwrap();
    for _ in 0..3 {
        fixture.sync().await;
    }
    let original = fixture.dns.records.lock().unwrap().clone();
    fixture.state.db.lock().unwrap().execute_batch("INSERT INTO node_update_jobs(id,actor,target_version,status,accept_interruption,created_at) VALUES('maintenance','u','0.2.20','running',1,unixepoch());
        INSERT INTO node_update_items(job_id,node_id,position,stage,ttl_seconds) VALUES('maintenance','a',0,'installing',0);
        UPDATE relay_nodes SET maintenance=1,last_seen=0 WHERE id='a';
        DELETE FROM relay_service_health WHERE node_id='a'; DELETE FROM relay_public_health WHERE node_id='a';").unwrap();
    fixture.tasks[0].abort();
    fixture.sync().await;
    fixture
        .state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE node_update_jobs SET status='paused'", [])
        .unwrap();
    fixture.sync().await;
    assert_eq!(*fixture.dns.records.lock().unwrap(), original);
    assert!(fixture
        .state
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT error IS NULL FROM relay_dns_state WHERE service_id='s'",
            [],
            |r| r.get::<_, bool>(0)
        )
        .unwrap());
    assert_eq!(
        fixture.health()[0]["healthy"],
        false,
        "保留 DNS 不能把停机节点标为健康"
    );
}

#[tokio::test]
async fn maintenance_keeps_single_entry_dns_but_withdraws_shared_entries_and_honors_revocation() {
    let fixture = Fixture::new().await;
    for _ in 0..3 {
        fixture.sync().await;
    }
    {
        let db = fixture.state.db.lock().unwrap();
        db.execute_batch("INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,local_address,local_port,hostname,public_domain_id,created_at,updated_at) SELECT 'single',tenant_id,device_id,'single',protocol,local_address,local_port,'single',public_domain_id,0,0 FROM tunnels WHERE id='s';
            DELETE FROM service_nodes WHERE service_id='single'; INSERT INTO service_nodes VALUES('single','a');
            INSERT INTO tunnel_applied_states(tunnel_id,revision,status,updated_at) VALUES('single',1,'ready',unixepoch());
            INSERT INTO relay_service_health(node_id,service_id,revision,healthy,checked_at) VALUES('a','single',1,1,unixepoch());").unwrap();
    }
    for _ in 0..3 {
        nodes::dns::sync(&fixture.state, "single").await.unwrap();
    }
    let original = fixture
        .dns
        .records
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.name == "single.direct.test" && r.kind == "A")
        .unwrap()
        .clone();
    {
        let db = fixture.state.db.lock().unwrap();
        db.execute_batch("INSERT INTO node_update_jobs(id,actor,target_version,status,accept_interruption,created_at) VALUES('maintenance','u','0.2.20','running',1,unixepoch());
            INSERT INTO node_update_items(job_id,node_id,position,stage,ttl_seconds) VALUES('maintenance','a',0,'installing',60);
            UPDATE relay_nodes SET maintenance=1,last_seen=0 WHERE id='a';
            DELETE FROM relay_service_health WHERE node_id='a'; DELETE FROM relay_public_health WHERE node_id='a';").unwrap();
    }
    fixture.sync().await;
    nodes::dns::sync(&fixture.state, "single").await.unwrap();
    {
        let records = fixture.dns.records.lock().unwrap();
        assert!(
            records.contains(&original),
            "单入口的记录及 ID 必须保持不变"
        );
        assert!(!records
            .iter()
            .any(|r| r.name == "emby.direct.test" && r.kind == "A" && r.value == "127.0.0.1"));
        assert!(records
            .iter()
            .any(|r| r.name == "emby.direct.test" && r.kind == "A" && r.value == "127.0.0.2"));
    }
    fixture
        .state
        .db
        .lock()
        .unwrap()
        .execute("DELETE FROM relay_node_grants WHERE node_id='a'", [])
        .unwrap();
    nodes::dns::sync(&fixture.state, "single").await.unwrap();
    assert!(!fixture
        .dns
        .records
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.name == "single.direct.test" && r.kind == "A"));
    assert!(fixture
        .dns
        .records
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.kind == "AAAA"));
}

#[tokio::test]
async fn mixed_nodes_reject_wrong_identity_withdraw_after_three_failures_and_recover() {
    let fixture = Fixture::new().await;
    fixture.body.lock().unwrap()["service_id"] = json!("wrong");
    for _ in 0..3 {
        fixture.sync().await;
    }
    assert_eq!(fixture.addresses(), ["127.0.0.1"]);
    let statuses = fixture.health();
    assert_eq!(statuses[0]["public_probe"]["kind"], "tcp");
    assert_eq!(statuses[1]["public_probe"]["kind"], "http");
    assert!(statuses[1]["public_probe"]["error"]
        .as_str()
        .unwrap()
        .contains("不匹配"));
    assert_eq!(statuses[1]["healthy"], false);
    fixture.body.lock().unwrap()["service_id"] = json!("s");
    for sample in 1..=3 {
        fixture.sync().await;
        assert_eq!(fixture.addresses().len(), if sample == 3 { 2 } else { 1 });
    }
    fixture.body.lock().unwrap()["revision"] = json!(2);
    for sample in 1..=3 {
        fixture.sync().await;
        assert_eq!(fixture.addresses().len(), if sample == 3 { 1 } else { 2 });
    }
    fixture.body.lock().unwrap()["revision"] = json!(1);
    for sample in 1..=3 {
        fixture.sync().await;
        assert_eq!(fixture.addresses().len(), if sample == 3 { 2 } else { 1 });
    }
    assert_eq!(fixture.health()[1]["public_probe"]["error"], Value::Null);
}

#[tokio::test]
async fn a_local_node_without_ipv4_does_not_block_other_entries_or_withdrawal() {
    let fixture = Fixture::new().await;
    assert!(crate::server_settings::relay_ipv4(&fixture.state)
        .unwrap()
        .is_none());
    for _ in 0..3 {
        fixture.sync().await;
    }
    {
        let db = fixture.state.db.lock().unwrap();
        db.execute("INSERT INTO service_nodes VALUES('s','local')", [])
            .unwrap();
        db.execute("INSERT INTO relay_service_health(node_id,service_id,revision,healthy,checked_at) VALUES('local','s',1,1,?1)", [unix_now()]).unwrap();
    }
    fixture.sync().await;
    assert_eq!(fixture.addresses(), ["127.0.0.1", "127.0.0.2"]);
    fixture
        .state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE relay_nodes SET enabled=0 WHERE id!='local'", [])
        .unwrap();
    fixture.sync().await;
    assert!(fixture.addresses().is_empty());
    let local = fixture
        .health()
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["node_id"] == "local")
        .unwrap()
        .clone();
    assert_eq!(local["healthy"], false);
    assert!(local["public_probe"]["error"]
        .as_str()
        .unwrap()
        .contains("IPv4"));
}

#[tokio::test]
async fn origin_failure_expiration_and_upgrade_are_shared_by_dns_status_and_alternatives() {
    let fixture = Fixture::new().await;
    for _ in 0..3 {
        fixture.sync().await;
    }
    for sql in [
        "UPDATE tunnel_applied_states SET status='failed'",
        "UPDATE tunnel_applied_states SET status='ready',updated_at=unixepoch()-46",
        "UPDATE tunnel_applied_states SET updated_at=unixepoch(); UPDATE relay_service_health SET checked_at=unixepoch()-46",
        "UPDATE relay_service_health SET checked_at=unixepoch(); UPDATE relay_nodes SET last_seen=unixepoch()-46 WHERE id!='local'",
    ] {
        fixture.state.db.lock().unwrap().execute_batch(sql).unwrap();
        fixture.sync().await;
        assert!(fixture.addresses().is_empty());
        assert!(fixture.health().as_array().unwrap().iter().all(|s|s["healthy"]==false));
        assert!(nodes::updates::alternatives(&fixture.state.db.lock().unwrap(), "a", "s").unwrap().is_empty());
    }
    fixture.state.db.lock().unwrap().execute_batch("UPDATE relay_nodes SET last_seen=unixepoch(); UPDATE relay_service_health SET public_probe_supported=1 WHERE node_id='a'").unwrap();
    fixture.sync().await;
    // a 的端口可连，但它得到 b 的身份；旧 TCP 健康不能继承，也不能自动降级。
    assert_eq!(fixture.addresses(), ["127.0.0.2"]);
    let health = fixture.health();
    assert_eq!(health[0]["public_probe"]["kind"], "http");
    assert_eq!(health[0]["healthy"], false);
    assert_eq!(
        fixture
            .state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT successes FROM relay_public_health WHERE node_id='a'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
    fixture
        .state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE relay_nodes SET maintenance=1 WHERE id='b'", [])
        .unwrap();
    fixture.sync().await;
    assert!(fixture.addresses().is_empty());
    assert_eq!(fixture.health()[1]["healthy"], false);
    assert!(
        nodes::updates::alternatives(&fixture.state.db.lock().unwrap(), "a", "s")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        fixture
            .state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM relay_ready_service_nodes WHERE node_id='b'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1,
        "维护节点可接受新检查，不能进入入口集合"
    );
}

#[tokio::test]
async fn changes_during_a_probe_discard_samples_before_persistence_or_dns() {
    for sql in [
        "UPDATE tunnels SET apply_revision=2 WHERE id='s'",
        "UPDATE relay_nodes SET public_ipv4='127.0.0.3' WHERE id='b'",
        "DELETE FROM relay_node_grants WHERE node_id='b'",
        "UPDATE relay_service_health SET public_probe_supported=0 WHERE node_id='b'",
    ] {
        let fixture = Fixture::new().await;
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *fixture.gate.lock().unwrap() = Some((started.clone(), release.clone()));
        let state = fixture.state.clone();
        let checking = tokio::spawn(async move { nodes::dns::sync(&state, "s").await });
        tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        {
            let _guard = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                fixture.state.tunnel_runtime.direct.dns_lock.lock(),
            )
            .await
            .unwrap();
            fixture.state.db.lock().unwrap().execute_batch(sql).unwrap();
        }
        release.notify_one();
        checking.await.unwrap().unwrap();
        assert!(fixture.addresses().is_empty());
        assert_eq!(
            fixture
                .state
                .db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM relay_public_health", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn health_changes_during_dns_read_prevent_publication() {
    for sql in [
        "UPDATE tunnel_applied_states SET status='failed'",
        "UPDATE relay_public_health SET checked_at=unixepoch()-46",
        "DELETE FROM relay_public_health",
    ] {
        let fixture = Fixture::new().await;
        for _ in 0..2 {
            fixture.sync().await;
        }
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *fixture.dns.read_gate.lock().unwrap() = Some((started.clone(), release.clone()));
        let state = fixture.state.clone();
        let checking = tokio::spawn(async move { nodes::dns::sync(&state, "s").await });
        tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        fixture.state.db.lock().unwrap().execute_batch(sql).unwrap();
        release.notify_one();
        checking.await.unwrap().unwrap();
        assert!(
            fixture.addresses().is_empty(),
            "等待 DNS 时失效的样本不能发布：{sql}"
        );
    }
}
