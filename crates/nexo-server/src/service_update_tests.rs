//! 编辑只使发生变化的链路失效；复用样本不能刷新时间戳或绕过当前配置与授权。
use crate::*;
const DOMAIN: &str = "00000000-0000-4000-8000-000000000001";
const OTHER_DOMAIN: &str = "00000000-0000-4000-8000-000000000003";

pub(super) fn fixture() -> (AppState, HeaderMap, TunnelInput, i64) {
    let (state, headers) = tests::domain_fixture();
    let checked = unix_now() - 1;
    {
        let db = state.db.lock().unwrap();
        for id in ["agent", "other"] {
            db.execute("INSERT INTO devices(id,tenant_id,name,node_capable,status,last_seen_at,created_at,updated_at) VALUES(?1,'default',?1,1,'online',?2,0,0)", params![id,checked]).unwrap();
            db.execute(
                "INSERT INTO device_certificates(device_id,certificate_pem) VALUES(?1,'test')",
                [id],
            )
            .unwrap();
        }
        for (id, ip) in [
            ("a", "203.0.113.10"),
            ("b", "203.0.113.11"),
            ("c", "203.0.113.12"),
        ] {
            db.execute("INSERT INTO relay_nodes(id,name,public_ipv4,approved,last_seen,created_at) VALUES(?1,?1,?2,1,?3,0)", params![id,ip,checked]).unwrap();
            db.execute("INSERT INTO relay_node_grants VALUES(?1,'default')", [id])
                .unwrap();
        }
        for id in [DOMAIN, OTHER_DOMAIN] {
            db.execute("INSERT INTO public_domains(id,tenant_id,domain,created_at,updated_at) VALUES(?1,'default',?1||'.test',0,0)", [id]).unwrap();
            db.execute("INSERT INTO domain_settings(domain_id,verification_token,certificate_mode,verified,credential_file) VALUES(?1,'test','cloudflare_dns',1,'credential-00000000-0000-4000-8000-000000000002.token')", [id]).unwrap();
        }
        db.execute_batch("INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,origin_protocol,local_address,local_port,hostname,public_domain_id,apply_status,distribution_mode,created_at,updated_at) VALUES('service','default','agent','测试','http','http','192.168.1.2',8080,'app','00000000-0000-4000-8000-000000000001','ready','dns',0,0);
            DELETE FROM service_nodes WHERE service_id='service';
            INSERT INTO service_nodes VALUES('service','a'),('service','b');
            INSERT INTO relay_node_groups VALUES('group','组',0);
            INSERT INTO relay_group_members VALUES('group','a'),('group','b');
            INSERT INTO relay_group_grants VALUES('group','default');").unwrap();
        db.execute("INSERT INTO tunnel_applied_states(tunnel_id,revision,status,updated_at) VALUES('service',1,'ready',?1)", [checked]).unwrap();
        db.execute(
            "INSERT INTO relay_dns_state VALUES('service',1,?1,NULL)",
            [checked],
        )
        .unwrap();
        for (node, address) in [
            ("a", "203.0.113.10"),
            ("b", "203.0.113.11"),
            ("c", "203.0.113.12"),
        ] {
            db.execute("INSERT INTO relay_service_health(node_id,service_id,revision,successes,healthy,checked_at,public_probe_supported) VALUES(?1,'service',1,3,1,?2,1)", params![node,checked]).unwrap();
            db.execute("INSERT INTO relay_public_health(node_id,service_id,revision,successes,healthy,checked_at,probe_kind,address) VALUES(?1,'service',1,3,1,?2,'http',?3)", params![node,checked,address]).unwrap();
        }
    }
    let input = serde_json::from_value(serde_json::json!({"name":"测试","device_id":"agent","protocol":"http","origin_protocol":"http","local_address":"192.168.1.2","local_port":8080,"hostname":"app","public_domain_id":DOMAIN,"node_ids":["a","b"],"distribution_mode":"dns"})).unwrap();
    (state, headers, input, checked)
}

async fn edit(state: &AppState, headers: HeaderMap, input: TunnelInput) -> Tunnel {
    update_tunnel(
        State(state.clone()),
        headers,
        Path("service".into()),
        Json(input),
    )
    .await
    .unwrap()
    .0
}

fn sample(db: &Connection, table: &str, node: &str) -> (i64, i64, bool, i64) {
    db.query_row(&format!("SELECT revision,successes,healthy,checked_at FROM {table} WHERE service_id='service' AND node_id=?1"), [node], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap()
}

#[tokio::test]
async fn selection_edits_preserve_checks_and_applied_configuration() {
    for change in ["latency", "manual", "group"] {
        let (state, headers, mut input, checked) = fixture();
        let desired = desired_tunnels(&state, "agent").unwrap();
        let snapshot = nodes::control::snapshot(&state, "b").unwrap();
        if change == "group" {
            input.node_group_id = Some("group".into());
        } else {
            input.distribution_mode = Some(change.into());
            input.preferred_node_id = Some("b".into());
        }
        let updated = edit(&state, headers, input).await;
        assert_eq!(updated.apply_revision, 1, "{change}");
        assert_eq!(desired_tunnels(&state, "agent").unwrap(), desired);
        assert_eq!(nodes::control::snapshot(&state, "b").unwrap(), snapshot);
        let db = state.db.lock().unwrap();
        for table in ["relay_service_health", "relay_public_health"] {
            assert_eq!(sample(&db, table, "b"), (1, 3, true, checked));
        }
        assert!(db.query_row("SELECT revision=1 AND updated_at=?1 FROM tunnel_applied_states WHERE tunnel_id='service'", [checked], |r| r.get::<_,bool>(0)).unwrap());
    }
}

#[tokio::test]
async fn membership_edits_only_check_new_nodes() {
    let (state, headers, mut input, checked) = fixture();
    input.node_ids = Some(vec!["b".into(), "c".into()]);
    let updated = edit(&state, headers.clone(), input).await;
    assert_eq!(updated.apply_revision, 1);
    let db = state.db.lock().unwrap();
    for table in ["relay_service_health", "relay_public_health"] {
        assert_eq!(sample(&db, table, "b"), (1, 3, true, checked));
        assert_eq!(db.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE service_id='service' AND node_id IN ('a','c')"), [], |r| r.get::<_,i64>(0)).unwrap(), 0);
    }
}

#[tokio::test]
async fn origin_edits_preserve_public_samples_and_require_current_origin() {
    for field in ["address", "port", "protocol", "device"] {
        let (state, headers, mut input, checked) = fixture();
        match field {
            "address" => input.local_address = "192.168.1.3".into(),
            "port" => input.local_port = 8081,
            "protocol" => input.origin_protocol = Some("https".into()),
            _ => input.device_id = Some("other".into()),
        }
        let updated = edit(&state, headers, input).await;
        assert_eq!(updated.apply_revision, 2);
        let db = state.db.lock().unwrap();
        assert_eq!(
            sample(&db, "relay_public_health", "b"),
            (2, 3, true, checked),
            "{field}"
        );
        assert_eq!(
            db.query_row(
                "SELECT revision FROM tunnel_applied_states WHERE tunnel_id='service'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM relay_healthy_service_nodes WHERE service_id='service'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn public_edits_invalidate_entry_without_rechecking_unchanged_origin() {
    for field in ["host", "domain", "protocol"] {
        let (state, headers, mut input, checked) = fixture();
        match field {
            "host" => input.hostname = Some("new".into()),
            "domain" => input.public_domain_id = Some(OTHER_DOMAIN.into()),
            _ => input.protocol = "https".into(),
        }
        let updated = edit(&state, headers, input).await;
        assert_eq!(updated.apply_revision, 2);
        let db = state.db.lock().unwrap();
        assert_ne!(sample(&db, "relay_public_health", "b").0, 2, "{field}");
        assert!(db.query_row("SELECT revision=2 AND status='ready' AND updated_at=?1 FROM tunnel_applied_states WHERE tunnel_id='service'", [checked], |r| r.get::<_,bool>(0)).unwrap());
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM relay_healthy_service_nodes WHERE service_id='service'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn redirect_edits_keep_network_samples() {
    let (state, headers, mut input, checked) = fixture();
    input.lan_redirect_enabled = Some(true);
    let updated = edit(&state, headers, input).await;
    assert_eq!(updated.apply_revision, 1);
    assert!(updated.lan_redirect_enabled);
    assert!(nodes::control::snapshot(&state, "b").unwrap().services[0]
        .lan_redirect_url
        .is_some());
    let db = state.db.lock().unwrap();
    assert_eq!(
        sample(&db, "relay_public_health", "b"),
        (1, 3, true, checked)
    );
}

#[tokio::test]
async fn reused_samples_keep_failure_and_expiry() {
    for field in ["expiry", "failure"] {
        let (state, headers, mut input, checked) = fixture();
        let old = if field == "expiry" {
            checked - 60
        } else {
            checked
        };
        {
            let db = state.db.lock().unwrap();
            db.execute("UPDATE relay_public_health SET checked_at=?1,healthy=?2,successes=?3,failures=?4,error=?5 WHERE service_id='service'", params![old,field != "failure",if field == "failure" {0} else {3},if field == "failure" {3} else {0},if field == "failure" {Some("入口失败")} else {None}]).unwrap();
        }
        input.local_port += 1;
        edit(&state, headers, input).await;
        let db = state.db.lock().unwrap();
        assert_eq!(
            sample(&db, "relay_public_health", "b"),
            (
                2,
                if field == "failure" { 0 } else { 3 },
                field != "failure",
                old
            )
        );
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM relay_healthy_service_nodes WHERE service_id='service'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        if field == "failure" {
            assert!(db.query_row("SELECT error='入口失败' AND failures=3 FROM relay_public_health WHERE service_id='service' AND node_id='b'", [], |r| r.get::<_,bool>(0)).unwrap());
        }
    }
}

#[tokio::test]
async fn port_edits_only_invalidate_the_active_public_entry() {
    for protocol in ["http", "https", "tcp"] {
        let (state, headers, mut input, checked) = fixture();
        input.protocol = protocol.into();
        input.https_port = Some(9443);
        {
            let db = state.db.lock().unwrap();
            db.execute("UPDATE tunnels SET protocol=?1,public_port=?2,origin_protocol=?3 WHERE id='service'", params![protocol,if protocol == "tcp" {Some(25000)} else {None},if protocol == "tcp" {None} else {Some("http")}]).unwrap();
        }
        if protocol == "tcp" {
            input.public_port = Some(25001);
            input.origin_protocol = None;
        }
        let updated = edit(&state, headers, input).await;
        let db = state.db.lock().unwrap();
        let revision = if protocol == "http" { 1 } else { 2 };
        assert_eq!(updated.apply_revision, revision);
        assert_eq!(
            sample(&db, "relay_public_health", "b"),
            (1, 3, true, checked)
        );
        assert!(db.query_row("SELECT revision=?1 AND updated_at=?2 FROM tunnel_applied_states WHERE tunnel_id='service'", params![revision,checked], |r| r.get::<_,bool>(0)).unwrap());
    }
}

#[tokio::test]
async fn ipv6_toggle_keeps_ipv4_samples_and_rejects_old_direct_state() {
    for enable in [true, false] {
        let (state, headers, mut input, checked) = fixture();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "UPDATE tunnels SET protocol='https',ipv6_direct_enabled=?1 WHERE id='service'",
                [!enable],
            )
            .unwrap();
            db.execute("INSERT INTO direct_agents(device_id,addresses,selected_address,last_seen) VALUES('agent','[\"2001:4860::123\"]','2001:4860::123',?1)", [checked]).unwrap();
            db.execute("INSERT INTO direct_services(service_id,revision,ready,reported_at,probe_status) VALUES('service',1,1,?1,'verified')", [checked]).unwrap();
            db.execute(
                "UPDATE relay_public_health SET probe_kind='https' WHERE service_id='service'",
                [],
            )
            .unwrap();
        }
        input.protocol = "https".into();
        input.ipv6_direct_enabled = Some(enable);
        let updated = edit(&state, headers, input).await;
        assert_eq!(updated.apply_revision, 2);
        assert_eq!(updated.ipv6_direct_enabled, enable);
        let db = state.db.lock().unwrap();
        assert_eq!(
            sample(&db, "relay_public_health", "b"),
            (2, 3, true, checked)
        );
        assert_eq!(
            db.query_row(
                "SELECT revision FROM tunnel_applied_states WHERE tunnel_id='service'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        assert_eq!(
            db.query_row(
                "SELECT revision FROM direct_services WHERE service_id='service'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }
}

#[tokio::test]
async fn https_redirect_keeps_checks_and_http_preference_is_only_saved() {
    for protocol in ["http", "https"] {
        let (state, headers, mut input, checked) = fixture();
        {
            let db = state.db.lock().unwrap();
            db.execute("UPDATE tunnels SET service_mode='reverse_proxy',device_id=NULL,protocol=?1,distribution_mode='single' WHERE id='service'", [protocol]).unwrap();
            db.execute_batch("DELETE FROM service_nodes WHERE service_id='service'; INSERT INTO service_nodes VALUES('service','local');
                INSERT INTO relay_public_health SELECT 'local',service_id,revision,successes,failures,healthy,checked_at,probe_kind,address,error FROM relay_public_health WHERE node_id='b';").unwrap();
        }
        input.service_mode = Some("reverse_proxy".into());
        input.device_id = None;
        input.protocol = protocol.into();
        input.node_ids = Some(vec!["local".into()]);
        input.distribution_mode = Some("single".into());
        input.http_redirect_enabled = Some(true);
        let updated = edit(&state, headers, input).await;
        assert_eq!(updated.apply_revision, 1);
        assert!(updated.http_redirect_enabled);
        assert_eq!(
            sample(&state.db.lock().unwrap(), "relay_public_health", "local"),
            (1, 3, true, checked)
        );
    }
}

#[tokio::test]
async fn simultaneous_origin_and_entry_changes_require_both_checks() {
    let (state, headers, mut input, _) = fixture();
    input.local_port += 1;
    input.hostname = Some("new".into());
    let updated = edit(&state, headers, input).await;
    assert_eq!(updated.apply_revision, 2);
    let db = state.db.lock().unwrap();
    assert_eq!(sample(&db, "relay_public_health", "b").0, 1);
    assert_eq!(
        db.query_row(
            "SELECT revision FROM tunnel_applied_states WHERE tunnel_id='service'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}
