use super::*;

const DOMAIN: &str = "00000000-0000-4000-8000-000000000001";
const HOST: &str = "app.00000000-0000-4000-8000-000000000001.test";
const A: &str = "203.0.113.10";
const B: &str = "203.0.113.11";
const LOCAL: &str = "203.0.113.9";

fn fixture() -> AppState {
    crate::service_update_tests::fixture().0
}

fn written(address: &str) -> String {
    json!({"id":address,"name":HOST,"kind":"A","value":address,"ttl":60,"proxied":false})
        .to_string()
}

fn record(db: &Connection, address: &str) {
    db.execute("INSERT INTO relay_dns_records(service_id,domain_id,hostname,address,written) VALUES('service',?1,?2,?3,?4)", params![DOMAIN,HOST,address,written(address)]).unwrap();
}

fn read(db: &Connection) -> NodeEntry {
    summary(db, "default", "service", Some(LOCAL.parse().unwrap()))
        .unwrap()
        .unwrap()
}

#[test]
fn recorded_entries_are_not_filtered_by_current_health_and_reads_do_not_write() {
    let state = fixture();
    let db = state.db.lock().unwrap();
    record(&db, A);
    record(&db, B);
    let changes = db.total_changes();
    let entry = read(&db);
    assert_eq!(entry.sync_status, SyncStatus::Synced);
    assert!(entry.synced_at.is_some());
    assert_eq!(
        entry
            .entries
            .iter()
            .map(|e| e.node_id.as_deref())
            .collect::<Vec<_>>(),
        [Some("a"), Some("b")]
    );
    assert_eq!(db.total_changes(), changes);

    db.execute(
        "UPDATE relay_service_health SET healthy=0 WHERE node_id='b'",
        [],
    )
    .unwrap();
    let entry = read(&db);
    assert_eq!(entry.sync_status, SyncStatus::Pending);
    assert_eq!(entry.entries.len(), 2, "撤出前的已写记录仍是最近确认的入口");
}

#[test]
fn selection_before_dns_write_keeps_the_previous_recorded_entry() {
    let state = fixture();
    let db = state.db.lock().unwrap();
    db.execute(
        "UPDATE tunnels SET distribution_mode='latency' WHERE id='service'",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO relay_selection VALUES('service','a',unixepoch(),'old')",
        [],
    )
    .unwrap();
    record(&db, A);
    assert_eq!(read(&db).sync_status, SyncStatus::Synced);
    db.execute(
        "UPDATE relay_selection SET node_id='b' WHERE service_id='service'",
        [],
    )
    .unwrap();
    let changes = db.total_changes();
    let entry = read(&db);
    assert_eq!(entry.sync_status, SyncStatus::Pending);
    assert_eq!(entry.entries[0].node_id.as_deref(), Some("a"));
    assert_eq!(db.total_changes(), changes, "读取不能再次运行选择策略");
}

#[test]
fn policy_and_membership_changes_are_detected_without_a_revision_change() {
    let state = fixture();
    let db = state.db.lock().unwrap();
    record(&db, A);
    record(&db, B);
    assert_eq!(read(&db).sync_status, SyncStatus::Synced);
    db.execute(
        "UPDATE tunnels SET distribution_mode='manual',preferred_node_id='b' WHERE id='service'",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO relay_selection VALUES('service','a',unixepoch(),'old')",
        [],
    )
    .unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Pending);
    db.execute("DELETE FROM relay_dns_records WHERE address=?1", [A])
        .unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Synced);
    db.execute(
        "UPDATE tunnels SET preferred_node_id='a' WHERE id='service'",
        [],
    )
    .unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Pending);
    db.execute(
        "UPDATE tunnels SET distribution_mode='dns' WHERE id='service'",
        [],
    )
    .unwrap();
    db.execute(
        "DELETE FROM service_nodes WHERE node_id='a' AND service_id='service'",
        [],
    )
    .unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Synced);
    assert_eq!(
        db.query_row(
            "SELECT apply_revision FROM tunnels WHERE id='service'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn partial_write_failure_keeps_recorded_addresses_and_previous_complete_sync_time() {
    let state = fixture();
    let db = state.db.lock().unwrap();
    record(&db, A);
    let at = read(&db).synced_at;
    db.execute("INSERT INTO relay_dns_records(service_id,domain_id,hostname,address) VALUES('service',?1,?2,?3)", params![DOMAIN,HOST,B]).unwrap();
    assert_eq!(
        read(&db).sync_status,
        SyncStatus::Pending,
        "部分写入不能沿用上次整组成功状态"
    );
    db.execute(
        "UPDATE relay_dns_state SET error='DNS 服务商暂不可用' WHERE service_id='service'",
        [],
    )
    .unwrap();
    let entry = read(&db);
    assert_eq!(entry.sync_status, SyncStatus::Failed);
    assert_eq!(entry.entries.len(), 1, "未确认写入的意图不是已记录入口");
    assert_eq!(entry.synced_at, at);
    db.execute(
        "UPDATE relay_dns_records SET written=?1 WHERE address=?2",
        params![written(B), B],
    )
    .unwrap();
    assert_eq!(
        read(&db).sync_status,
        SyncStatus::Failed,
        "地址齐全不能覆盖完整同步的失败"
    );
}

#[test]
fn only_the_current_hostname_domain_and_written_records_are_displayed() {
    let state = fixture();
    let db = state.db.lock().unwrap();
    record(&db, A);
    db.execute("INSERT INTO relay_dns_records(service_id,domain_id,hostname,address) VALUES('service',?1,?2,?3)", params![DOMAIN,HOST,B]).unwrap();
    db.execute("INSERT INTO relay_dns_records(service_id,domain_id,hostname,address,written) VALUES('service',?1,'previous.test',?2,?3)", params![DOMAIN,B,written(B)]).unwrap();
    db.execute("INSERT INTO relay_dns_records(service_id,domain_id,hostname,address,written) VALUES('service','00000000-0000-4000-8000-000000000003',?1,'203.0.113.12',?2)", params![HOST,written("203.0.113.12")]).unwrap();
    assert_eq!(read(&db).entries.len(), 1);
    db.execute("UPDATE tunnels SET hostname='new' WHERE id='service'", [])
        .unwrap();
    let entry = read(&db);
    assert!(entry.entries.is_empty());
    assert_eq!(entry.sync_status, SyncStatus::Pending);
}

#[test]
fn changed_removed_or_ambiguous_nodes_fall_back_to_the_recorded_ipv4() {
    let state = fixture();
    let db = state.db.lock().unwrap();
    record(&db, A);
    db.execute(
        "UPDATE relay_nodes SET public_ipv4='203.0.113.30' WHERE id='a'",
        [],
    )
    .unwrap();
    let entry = read(&db);
    assert_eq!(entry.entries[0].ipv4, A);
    assert!(entry.entries[0].node_name.is_none());
    db.execute(
        "UPDATE relay_nodes SET public_ipv4=?1 WHERE id IN ('a','b')",
        [A],
    )
    .unwrap();
    assert!(read(&db).entries[0].node_id.is_none());
    db.execute("UPDATE relay_nodes SET public_ipv4=?1 WHERE id='b'", [B])
        .unwrap();
    db.execute(
        "UPDATE relay_nodes SET removed_at=unixepoch() WHERE id='a'",
        [],
    )
    .unwrap();
    assert!(read(&db).entries[0].node_name.is_none());
}

#[test]
fn api_projection_preserves_workspace_isolation() {
    let state = fixture();
    let db = state.db.lock().unwrap();
    record(&db, A);
    assert!(summary(&db, "other", "service", None).unwrap().is_none());
    let headers = HeaderMap::new();
    assert!(crate::query_tunnels(&db, "other", None, &headers, 80, None)
        .unwrap()
        .is_empty());
    let rows = crate::query_tunnels(&db, "default", Some("service"), &headers, 80, None).unwrap();
    assert_eq!(rows[0].node_entry.as_ref().unwrap().entries[0].ipv4, A);
}

#[test]
fn ipv6_direct_ipv4_records_are_included_without_fabricating_a_dns_timestamp() {
    let state = fixture();
    let db = state.db.lock().unwrap();
    db.execute_batch("UPDATE tunnels SET ipv6_direct_enabled=1 WHERE id='service'; DELETE FROM service_nodes WHERE service_id='service'; INSERT INTO service_nodes VALUES('service','local'); DELETE FROM relay_dns_state WHERE service_id='service'; INSERT INTO direct_agents(device_id,selected_address) VALUES('agent','2001:4860::1'); INSERT INTO direct_services(service_id,revision,published_address,reported_at) VALUES('service',1,'2001:4860::1',unixepoch());").unwrap();
    db.execute("INSERT INTO direct_dns_records(service_id,domain_id,hostname,kind,written,intended) VALUES('service',?1,?2,'A',?3,?4)", params![DOMAIN,HOST,written(LOCAL),LOCAL]).unwrap();
    let entry = read(&db);
    assert_eq!(entry.sync_status, SyncStatus::Synced);
    assert_eq!(entry.entries[0].node_id.as_deref(), Some("local"));
    assert!(entry.synced_at.is_none());
    db.execute(
        "UPDATE direct_agents SET selected_address='2001:4860::2' WHERE device_id='agent'",
        [],
    )
    .unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Pending);
    assert_eq!(read(&db).entries[0].ipv4, LOCAL);
    db.execute(
        "UPDATE direct_services SET published_address='2001:4860::2' WHERE service_id='service'",
        [],
    )
    .unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Synced);
    db.execute(
        "UPDATE direct_services SET dns_error='AAAA 写入失败' WHERE service_id='service'",
        [],
    )
    .unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Failed);
    assert_eq!(read(&db).entries.len(), 1);
    db.execute(
        "UPDATE direct_services SET dns_error=NULL,revision=0 WHERE service_id='service'",
        [],
    )
    .unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Pending);
}

#[test]
fn non_managed_proxy_and_disabled_services_do_not_infer_an_active_dns_entry() {
    let state = fixture();
    let db = state.db.lock().unwrap();
    record(&db, A);
    db.execute(
        "UPDATE tunnels SET service_mode='reverse_proxy' WHERE id='service'",
        [],
    )
    .unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Unmanaged);
    assert!(read(&db).entries.is_empty());
    db.execute("UPDATE tunnels SET enabled=0 WHERE id='service'", [])
        .unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Disabled);
    db.execute_batch("UPDATE tunnels SET enabled=1,service_mode='tunnel' WHERE id='service'; DELETE FROM relay_dns_records; DELETE FROM relay_dns_state; DELETE FROM service_nodes WHERE service_id='service'; INSERT INTO service_nodes VALUES('service','local'); UPDATE domain_settings SET credential_file=NULL;").unwrap();
    assert_eq!(read(&db).sync_status, SyncStatus::Unmanaged);
}

#[test]
fn maintenance_preserved_records_are_not_reported_as_a_new_pending_switch() {
    let state = fixture();
    let db = state.db.lock().unwrap();
    record(&db, A);
    db.execute_batch("UPDATE relay_nodes SET maintenance=1 WHERE id='a'; UPDATE relay_service_health SET healthy=0 WHERE node_id='b'; INSERT INTO node_update_jobs(id,actor,target_version,status,created_at) VALUES('job','u','0.2.21','running',0); INSERT INTO node_update_items(job_id,node_id,position,stage) VALUES('job','a',0,'installing');").unwrap();
    assert!(super::super::updates::preserves_dns(&db, "a", "service").unwrap());
    assert_eq!(read(&db).sync_status, SyncStatus::Synced);
    db.execute(
        "INSERT INTO node_traffic_limits(node_id,monthly_limit_bytes) VALUES('a',1)",
        [],
    )
    .unwrap();
    assert_eq!(
        read(&db).sync_status,
        SyncStatus::Pending,
        "维护保留不能覆盖额度停用"
    );
    assert_eq!(read(&db).entries[0].ipv4, A);
}
