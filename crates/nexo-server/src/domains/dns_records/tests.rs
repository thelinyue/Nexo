use super::*;
use crate::dns_provider::Credential;
use axum::{
    body::Bytes,
    http::{Method, Uri},
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

/// 三种服务商的本地 HTTP 桩走真实适配器，故障注入发生在指定记录的删除请求。
#[derive(Clone, Default)]
struct Dns {
    records: Arc<Mutex<Vec<Record>>>,
    writes: Arc<AtomicUsize>,
    next_id: Arc<AtomicUsize>,
    fail_delete: Arc<Mutex<Option<String>>>,
    external_change: Arc<Mutex<Option<Record>>>,
}
async fn provider(
    State(dns): State<Dns>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
    body: Bytes,
) -> Json<Value> {
    let cloudflare = uri.path().starts_with("/client/v4/");
    let tencent = headers.contains_key("x-tc-action");
    let params: BTreeMap<String, String> = if cloudflare || tencent {
        BTreeMap::new()
    } else {
        reqwest::Url::parse(&format!("http://local/?{}", String::from_utf8_lossy(&body)))
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect()
    };
    let payload: Value =
        if cloudflare && method != Method::GET && method != Method::DELETE || tencent {
            serde_json::from_slice(&body).unwrap()
        } else {
            Value::Null
        };
    let action = if cloudflare {
        match method {
            Method::GET => "list",
            Method::DELETE => "remove",
            _ => "write",
        }
    } else {
        let name = if tencent {
            headers["x-tc-action"].to_str().unwrap()
        } else {
            &params["Action"]
        };
        match name {
            "DescribeRecordList" | "DescribeDomainRecords" => "list",
            "DeleteRecord" | "DeleteDomainRecord" => "remove",
            _ => "write",
        }
    };
    let id = if cloudflare {
        uri.path().rsplit('/').next().unwrap().to_owned()
    } else if tencent {
        payload["RecordId"]
            .as_u64()
            .map(|v| v.to_string())
            .unwrap_or_default()
    } else {
        params.get("RecordId").cloned().unwrap_or_default()
    };
    let relative = if cloudflare {
        if action == "list" {
            reqwest::Url::parse(&format!("http://local{uri}"))
                .unwrap()
                .query_pairs()
                .find(|(k, _)| k == "name")
                .unwrap()
                .1
                .into_owned()
        } else {
            payload["name"].as_str().unwrap_or_default().into()
        }
    } else if tencent {
        payload[if action == "list" {
            "Subdomain"
        } else {
            "SubDomain"
        }]
        .as_str()
        .unwrap_or_default()
        .into()
    } else {
        params
            .get(if action == "list" { "RRKeyWord" } else { "RR" })
            .cloned()
            .unwrap_or_default()
    };
    let hostname = if cloudflare {
        relative.clone()
    } else if relative == "@" {
        "direct.test".into()
    } else {
        format!("{relative}.direct.test")
    };
    if !cloudflare && !tencent {
        assert!(params.contains_key("Signature"));
    }
    if tencent {
        assert!(headers["authorization"]
            .to_str()
            .unwrap()
            .starts_with("TC3-HMAC-SHA256 "));
    }
    if action != "list" {
        dns.writes.fetch_add(1, Ordering::SeqCst);
    }
    let mut records = dns.records.lock().unwrap();
    if action == "remove" && dns.fail_delete.lock().unwrap().as_ref() == Some(&id) {
        *dns.fail_delete.lock().unwrap() = None;
        if let Some(external) = dns.external_change.lock().unwrap().take() {
            records.retain(|r| r.id != external.id);
            records.push(external);
        }
        return Json(if cloudflare {
            json!({"success":false})
        } else if tencent {
            json!({"Response":{"Error":{"Code":"FailedOperation"}}})
        } else {
            json!({"Code":"FailedOperation"})
        });
    }
    let rows: Vec<_> = records.iter().filter(|r|r.name==hostname).map(|r| {
        let rr = if r.name == "direct.test" { "@" } else { r.name.strip_suffix(".direct.test").unwrap() };
        if cloudflare { json!({"id":r.id,"name":r.name,"type":r.kind,"content":r.value,"ttl":r.ttl,"proxied":r.proxied}) }
        else if tencent { json!({"RecordId":r.id.parse::<u64>().unwrap(),"Name":rr,"Type":r.kind,"Value":r.value,"TTL":r.ttl}) }
        else { json!({"RecordId":r.id,"RR":rr,"Type":r.kind,"Value":r.value,"TTL":r.ttl}) }
    }).collect();
    let id = if action == "write" {
        let id = if id.is_empty() || cloudflare && method == Method::POST {
            (1000 + dns.next_id.fetch_add(1, Ordering::SeqCst)).to_string()
        } else {
            id
        };
        let record = Record {
            id: id.clone(),
            name: hostname,
            kind: if cloudflare {
                payload["type"].as_str().unwrap().into()
            } else if tencent {
                payload["RecordType"].as_str().unwrap().into()
            } else {
                params["Type"].clone()
            },
            value: if cloudflare {
                payload["content"].as_str().unwrap().into()
            } else if tencent {
                payload["Value"].as_str().unwrap().into()
            } else {
                params["Value"].clone()
            },
            ttl: if cloudflare {
                payload["ttl"].as_u64().unwrap() as u32
            } else if tencent {
                payload["TTL"].as_u64().unwrap() as u32
            } else {
                params["TTL"].parse().unwrap()
            },
            proxied: cloudflare && payload["proxied"] == true,
        };
        records.retain(|r| r.id != id);
        records.push(record);
        id
    } else {
        if action == "remove" {
            records.retain(|r| r.id != id);
        }
        id
    };
    Json(if cloudflare {
        json!({"success":true,"result":if action=="list" {json!(rows)} else {json!({"id":id})}})
    } else if tencent {
        json!({"Response":if action=="list" {json!({"RecordList":rows})} else {json!({"RecordId":id.parse::<u64>().unwrap()})}})
    } else if action == "list" {
        json!({"DomainRecords":{"Record":rows}})
    } else {
        json!({"RecordId":id})
    })
}

fn credential(name: &str) -> Credential {
    match name {
        "cloudflare" => Credential::Cloudflare {
            token: "test".into(),
        },
        "alidns" => Credential::Alidns {
            access_key_id: "test".into(),
            access_key_secret: "secret".into(),
        },
        _ => Credential::Tencentcloud {
            secret_id: "test".into(),
            secret_key: "secret".into(),
        },
    }
}
async fn fixture(
    name: &str,
) -> (
    AppState,
    HeaderMap,
    String,
    Dns,
    tokio::task::JoinHandle<()>,
) {
    let (state, headers) = crate::tests::domain_fixture();
    let id = crate::tests::add_test_domain(&state, &headers, "direct.test")
        .await
        .unwrap()
        .id;
    state.db.lock().unwrap().execute("UPDATE domain_settings SET verified=1,credential_file='test',dns_provider=?2 WHERE domain_id=?1",params![id,name]).unwrap();
    state.security.configuration.write().unwrap().relay_ipv4 = Some("8.8.8.8".parse().unwrap());
    let dns = Dns::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(provider).with_state(dns.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    *state.tunnel_runtime.direct.test_zone.lock().await =
        Some(Zone::mock(credential(name), endpoint));
    (state, headers, id, dns, task)
}
fn record(id: &str, hostname: &str, kind: &str, value: &str) -> Record {
    Record {
        id: id.into(),
        name: hostname.into(),
        kind: kind.into(),
        value: value.into(),
        ttl: 600,
        proxied: false,
    }
}
async fn preview_for(state: &AppState, headers: &HeaderMap, id: &str) -> Preview {
    preview(State(state.clone()), headers.clone(), Path(id.into()))
        .await
        .unwrap()
        .0
}
async fn write(
    state: &AppState,
    headers: &HeaderMap,
    id: &str,
    value: Preview,
    confirm: bool,
) -> Result<ApplyResult, ApiError> {
    apply(
        State(state.clone()),
        headers.clone(),
        Path(id.into()),
        Json(ApplyInput {
            preview: value,
            confirm_takeover: confirm,
        }),
    )
    .await
    .map(|v| v.0)
}

#[tokio::test]
async fn providers_create_apex_and_wildcard_once_without_touching_other_records() {
    for name in ["cloudflare", "alidns", "tencentcloud"] {
        let (state, headers, id, dns, task) = fixture(name).await;
        let untouched = vec![
            record("1", "direct.test", "AAAA", "2001:4860::1"),
            record("2", "direct.test", "TXT", "proof"),
            record("3", "direct.test", "MX", "mail.direct.test"),
            record("4", "emby.direct.test", "A", "9.9.9.9"),
        ];
        *dns.records.lock().unwrap() = untouched.clone();
        let value = preview_for(&state, &headers, &id).await;
        assert_eq!(dns.writes.load(Ordering::SeqCst), 0);
        let result = write(&state, &headers, &id, value, false).await.unwrap();
        assert!(result.hosts.iter().all(|h| h.status == "written"));
        let current = dns.records.lock().unwrap().clone();
        for item in &untouched {
            assert!(current.contains(item));
        }
        for host in ["direct.test", "*.direct.test"] {
            assert!(current
                .iter()
                .any(|r| r.name == host && r.kind == "A" && r.value == "8.8.8.8" && !r.proxied));
        }
        let value = preview_for(&state, &headers, &id).await;
        let count = dns.writes.load(Ordering::SeqCst);
        assert!(write(&state, &headers, &id, value, false)
            .await
            .unwrap()
            .hosts
            .iter()
            .all(|h| h.status == "unchanged"));
        assert_eq!(dns.writes.load(Ordering::SeqCst), count);
        let _ = crate::delete_domain(State(state), headers, Path(id))
            .await
            .unwrap();
        assert_eq!(*dns.records.lock().unwrap(), current);
        task.abort();
    }
}

#[tokio::test]
async fn providers_require_confirmation_before_replacing_cname_and_multiple_a_records() {
    for name in ["cloudflare", "alidns", "tencentcloud"] {
        let (state, headers, id, dns, task) = fixture(name).await;
        *dns.records.lock().unwrap() = vec![
            record("1", "direct.test", "CNAME", "old.example.com"),
            record("2", "*.direct.test", "A", "1.1.1.1"),
            record("3", "*.direct.test", "A", "9.9.9.9"),
        ];
        let value = preview_for(&state, &headers, &id).await;
        assert_eq!(
            write(&state, &headers, &id, value.clone(), false)
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        assert_eq!(dns.writes.load(Ordering::SeqCst), 0);
        assert!(write(&state, &headers, &id, value, true)
            .await
            .unwrap()
            .hosts
            .iter()
            .all(|h| h.status == "written"));
        let records = dns.records.lock().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .all(|r| r.kind == "A" && r.value == "8.8.8.8"));
        assert_eq!(
            records.iter().find(|r| r.name == "direct.test").unwrap().id,
            "1"
        );
        task.abort();
    }
}

#[tokio::test]
async fn stale_preview_address_credentials_or_provider_never_writes() {
    for name in ["cloudflare", "alidns", "tencentcloud"] {
        let (state, headers, id, dns, task) = fixture(name).await;
        let value = preview_for(&state, &headers, &id).await;
        dns.records
            .lock()
            .unwrap()
            .push(record("1", "direct.test", "A", "1.1.1.1"));
        assert_eq!(
            write(&state, &headers, &id, value, false)
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        let value = preview_for(&state, &headers, &id).await;
        state.security.configuration.write().unwrap().relay_ipv4 = Some("9.9.9.9".parse().unwrap());
        assert_eq!(
            write(&state, &headers, &id, value, true)
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        let value = preview_for(&state, &headers, &id).await;
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE domain_settings SET credential_file='replacement' WHERE domain_id=?1",
                [&id],
            )
            .unwrap();
        assert_eq!(
            write(&state, &headers, &id, value, true)
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        let value = preview_for(&state, &headers, &id).await;
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE domain_settings SET dns_provider='changed' WHERE domain_id=?1",
                [&id],
            )
            .unwrap();
        assert_eq!(
            write(&state, &headers, &id, value, true)
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        assert_eq!(dns.writes.load(Ordering::SeqCst), 0);
        task.abort();
    }
}

#[tokio::test]
async fn partial_failure_restores_the_failed_host_and_keeps_the_successful_host() {
    for name in ["cloudflare", "alidns", "tencentcloud"] {
        let (state, headers, id, dns, task) = fixture(name).await;
        let mut original = record("1", "*.direct.test", "A", "1.1.1.1");
        original.proxied = name == "cloudflare";
        let extra = record("2", "*.direct.test", "A", "9.9.9.9");
        *dns.records.lock().unwrap() = vec![original.clone(), extra.clone()];
        *dns.fail_delete.lock().unwrap() = Some("2".into());
        let result = write(
            &state,
            &headers,
            &id,
            preview_for(&state, &headers, &id).await,
            true,
        )
        .await
        .unwrap();
        assert_eq!(result.hosts[0].status, "written");
        assert_eq!(result.hosts[1].status, "failed");
        assert!(result.hosts[1].error.as_deref().unwrap().contains("已恢复"));
        let records = dns.records.lock().unwrap().clone();
        assert!(records.contains(&original));
        assert!(records.contains(&extra));
        assert!(records
            .iter()
            .any(|r| r.name == "direct.test" && r.value == "8.8.8.8"));
        let journal: String = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT original FROM domain_dns_operations WHERE hostname='*.direct.test'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(serde_json::from_str::<Vec<Record>>(&journal)
            .unwrap()
            .contains(&original));
        let result = write(
            &state,
            &headers,
            &id,
            preview_for(&state, &headers, &id).await,
            true,
        )
        .await
        .unwrap();
        assert_eq!(result.hosts[0].status, "unchanged");
        assert_eq!(result.hosts[1].status, "written");
        task.abort();
    }
}

#[tokio::test]
async fn failure_does_not_restore_over_external_changes() {
    for name in ["cloudflare", "alidns", "tencentcloud"] {
        let (state, headers, id, dns, task) = fixture(name).await;
        *dns.records.lock().unwrap() = vec![
            record("1", "*.direct.test", "A", "1.1.1.1"),
            record("2", "*.direct.test", "A", "9.9.9.9"),
        ];
        let external = record("1", "*.direct.test", "A", "4.4.4.4");
        *dns.fail_delete.lock().unwrap() = Some("2".into());
        *dns.external_change.lock().unwrap() = Some(external.clone());
        let result = write(
            &state,
            &headers,
            &id,
            preview_for(&state, &headers, &id).await,
            true,
        )
        .await
        .unwrap();
        assert!(result.hosts[1].error.as_deref().unwrap().contains("未覆盖"));
        assert!(dns.records.lock().unwrap().contains(&external));
        task.abort();
    }
}

#[tokio::test]
async fn cloudflare_keeps_unmanaged_proxy_records_and_requires_manual_resolution() {
    let (state, headers, id, dns, task) = fixture("cloudflare").await;
    let mut other = record("1", "direct.test", "AAAA", "2001:4860::1");
    other.proxied = true;
    dns.records.lock().unwrap().push(other.clone());
    let value = preview_for(&state, &headers, &id).await;
    assert!(value.hosts[0].blocked.is_some());
    assert_eq!(
        write(&state, &headers, &id, value, true)
            .await
            .unwrap_err()
            .status,
        StatusCode::CONFLICT
    );
    assert_eq!(dns.writes.load(Ordering::SeqCst), 0);
    assert_eq!(*dns.records.lock().unwrap(), vec![other]);
    task.abort();
}

#[tokio::test]
async fn credentials_public_ipv4_csrf_and_workspace_are_required() {
    let (state, headers, id, dns, task) = fixture("cloudflare").await;
    let value = preview_for(&state, &headers, &id).await;
    let mut no_csrf = headers.clone();
    no_csrf.remove("x-nexo-csrf");
    assert_eq!(
        write(&state, &no_csrf, &id, value.clone(), false)
            .await
            .unwrap_err()
            .status,
        StatusCode::FORBIDDEN
    );
    let mut other = headers.clone();
    other.insert("x-nexo-internal-workspace", "other".parse().unwrap());
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO tenants(id,name,created_at) VALUES('other','other',0)",
            [],
        )
        .unwrap();
    assert_eq!(
        write(&state, &other, &id, value.clone(), false)
            .await
            .unwrap_err()
            .status,
        StatusCode::NOT_FOUND
    );
    state.security.configuration.write().unwrap().relay_ipv4 = None;
    assert_eq!(
        write(&state, &headers, &id, value.clone(), false)
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    state.security.configuration.write().unwrap().relay_ipv4 = Some("8.8.8.8".parse().unwrap());
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE domain_settings SET credential_file=NULL WHERE domain_id=?1",
            [&id],
        )
        .unwrap();
    assert_eq!(
        write(&state, &headers, &id, value, false)
            .await
            .unwrap_err()
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(dns.writes.load(Ordering::SeqCst), 0);
    task.abort();
}
