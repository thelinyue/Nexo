use super::*;
use axum::{
    body::Bytes,
    extract::State,
    http::{Method, Uri},
    Json, Router,
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Dns {
    records: Arc<Mutex<Vec<Record>>>,
}
async fn cloudflare(State(dns): State<Dns>, method: Method, uri: Uri, body: Bytes) -> Json<Value> {
    let mut records = dns.records.lock().unwrap();
    let id = uri.path().rsplit('/').next().unwrap();
    let result = if method == Method::GET {
        let url = reqwest::Url::parse(&format!("http://local{uri}")).unwrap();
        let host = url
            .query_pairs()
            .find(|(k, _)| k == "name")
            .unwrap()
            .1
            .into_owned();
        Value::Array(records.iter().filter(|r|r.name==host).map(|r|json!({"id":r.id,"name":r.name,"type":r.kind,"content":r.value,"ttl":r.ttl,"proxied":r.proxied})).collect())
    } else if method == Method::DELETE {
        records.retain(|r| r.id != id);
        json!({"id":id})
    } else {
        let v: Value = serde_json::from_slice(&body).unwrap();
        let id = if method == Method::POST {
            uuid::Uuid::new_v4().to_string()
        } else {
            id.into()
        };
        records.retain(|r| r.id != id);
        records.push(Record {
            id: id.clone(),
            name: v["name"].as_str().unwrap().into(),
            kind: v["type"].as_str().unwrap().into(),
            value: v["content"].as_str().unwrap().into(),
            ttl: v["ttl"].as_u64().unwrap() as u32,
            proxied: v["proxied"] == true,
        });
        json!({"id":id})
    };
    Json(json!({"success":true,"result":result}))
}
async fn mock() -> (Zone, Dns, tokio::task::JoinHandle<()>) {
    let dns = Dns::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(cloudflare).with_state(dns.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        Zone::mock(
            Credential::Cloudflare {
                token: "test".into(),
            },
            endpoint,
        ),
        dns,
        task,
    )
}
fn record(kind: &str, value: &str) -> Record {
    Record {
        id: uuid::Uuid::new_v4().to_string(),
        name: "emby.direct.test".into(),
        kind: kind.into(),
        value: value.into(),
        ttl: 600,
        proxied: false,
    }
}

#[tokio::test]
async fn journal_restores_owned_aaaa_retains_explicit_a_and_preserves_foreign_txt() {
    use crate::direct::dns::{ensure, withdraw};
    let (mut state, _) = crate::tests::domain_fixture();
    Arc::make_mut(&mut state.config).direct.relay_ipv4 = Some("192.0.2.10".parse().unwrap());
    let (zone, dns, task) = mock().await;
    // A wildcard cannot be the IPv4 fallback once a specific AAAA exists.
    let mut wildcard = record("A", "192.0.2.10");
    wildcard.name = "*.direct.test".into();
    dns.records.lock().unwrap().push(wildcard);
    ensure(
        &state,
        &zone,
        "s",
        "d",
        "emby.direct.test",
        "A",
        "192.0.2.10",
    )
    .await
    .unwrap();
    ensure(
        &state,
        &zone,
        "s",
        "d",
        "emby.direct.test",
        "AAAA",
        "2001:4860::1",
    )
    .await
    .unwrap();
    ensure(
        &state,
        &zone,
        "s",
        "d",
        "emby.direct.test",
        "AAAA",
        "2001:4860::2",
    )
    .await
    .unwrap();
    withdraw(&state, &zone, "s", "emby.direct.test", "AAAA")
        .await
        .unwrap();
    let current = zone.records("emby.direct.test").await.unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].kind, "A");
    let mut original = record("AAAA", "2001:4860::10");
    // Use a journal captured before shutdown to exercise restoration independently of settings APIs.
    original.value = "2001:4860::10".into();
    let mut written = original.clone();
    written.value = "2001:4860::2".into();
    dns.records.lock().unwrap().push(written.clone());
    state.db.lock().unwrap().execute("INSERT INTO direct_dns_records VALUES('restore','d','emby.direct.test','AAAA',?1,?2,'2001:4860::2')",rusqlite::params![serde_json::to_string(&original).unwrap(),serde_json::to_string(&written).unwrap()]).unwrap();
    withdraw(&state, &zone, "restore", "emby.direct.test", "AAAA")
        .await
        .unwrap();
    assert!(zone
        .records("emby.direct.test")
        .await
        .unwrap()
        .contains(&original));
    let txt = "_acme-challenge.emby.direct.test";
    let mut foreign = record("TXT", "another-acme-client");
    foreign.name = txt.into();
    dns.records.lock().unwrap().push(foreign.clone());
    ensure(&state, &zone, "s", "d", txt, "TXT", "our-value")
        .await
        .unwrap();
    withdraw(&state, &zone, "s", txt, "TXT").await.unwrap();
    assert_eq!(zone.records(txt).await.unwrap(), vec![foreign]);
    task.abort();
}

#[tokio::test]
async fn dns_conflicts_and_crash_recovery_never_overwrite_external_edits() {
    use crate::direct::dns::{ensure, withdraw};
    let (state, _) = crate::tests::domain_fixture();
    let (zone, dns, task) = mock().await;
    let host = "emby.direct.test";
    let mut foreign = record("CNAME", "other.test");
    dns.records.lock().unwrap().push(foreign.clone());
    assert!(
        ensure(&state, &zone, "s", "d", host, "AAAA", "2001:4860::1")
            .await
            .is_err()
    );
    foreign.kind = "A".into();
    foreign.proxied = true;
    *dns.records.lock().unwrap() = vec![foreign];
    assert!(
        ensure(&state, &zone, "s", "d", host, "AAAA", "2001:4860::1")
            .await
            .is_err()
    );
    dns.records.lock().unwrap().clear();
    ensure(&state, &zone, "s", "d", host, "AAAA", "2001:4860::1")
        .await
        .unwrap();
    // Simulate provider success followed by a process crash before journal completion.
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE direct_dns_records SET intended='2001:4860::2'", [])
        .unwrap();
    dns.records.lock().unwrap()[0].value = "2001:4860::2".into();
    ensure(&state, &zone, "s", "d", host, "AAAA", "2001:4860::2")
        .await
        .unwrap();
    dns.records.lock().unwrap()[0].value = "2001:4860::3".into();
    assert!(
        ensure(&state, &zone, "s", "d", host, "AAAA", "2001:4860::4")
            .await
            .is_err()
    );
    assert!(withdraw(&state, &zone, "s", host, "AAAA").await.is_err());
    assert_eq!(zone.records(host).await.unwrap()[0].value, "2001:4860::3");
    assert!(zone.records("unrelated.test").await.is_err());
    task.abort();
}

#[tokio::test]
async fn aliyun_and_tencent_requests_use_signed_provider_protocols() {
    use axum::http::HeaderMap;
    async fn rpc(headers: HeaderMap, body: Bytes) -> Json<Value> {
        if headers.contains_key("x-tc-action") {
            assert!(headers["authorization"]
                .to_str()
                .unwrap()
                .starts_with("TC3-HMAC-SHA256 Credential=test-id/"));
            let payload: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(payload["Domain"], "direct.test");
            assert_eq!(payload["Subdomain"], "emby");
            Json(
                json!({"Response":{"RecordList":[{"RecordId":123,"Name":"emby","Type":"AAAA","Value":"2001:4860::1","TTL":600}]}}),
            )
        } else {
            let params =
                reqwest::Url::parse(&format!("http://local/?{}", String::from_utf8_lossy(&body)))
                    .unwrap()
                    .query_pairs()
                    .into_owned()
                    .collect::<BTreeMap<_, _>>();
            assert_eq!(params["Action"], "DescribeDomainRecords");
            assert_eq!(params["RRKeyWord"], "emby");
            assert!(params.contains_key("Signature"));
            Json(
                json!({"DomainRecords":{"Record":[{"RecordId":"123","RR":"emby","Type":"AAAA","Value":"2001:4860::1","TTL":600}]}}),
            )
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(rpc))
            .await
            .unwrap();
    });
    for credential in [
        Credential::Alidns {
            access_key_id: "test-id".into(),
            access_key_secret: "secret".into(),
        },
        Credential::Tencentcloud {
            secret_id: "test-id".into(),
            secret_key: "secret".into(),
        },
    ] {
        let records = Zone::mock(credential, endpoint.clone())
            .records("emby.direct.test")
            .await
            .unwrap();
        assert_eq!(records[0].id, "123");
        assert_eq!(records[0].value, "2001:4860::1");
    }
    task.abort();
}

#[tokio::test]
#[ignore = "需要包含三种 DNS 模块的 NEXO_TEST_CADDY_BIN；不创建公网订单"]
async fn real_caddy_loads_each_provider_private_file_configuration() {
    let binary = std::env::var_os("NEXO_TEST_CADDY_BIN").unwrap();
    let (state, _) = crate::tests::domain_fixture();
    let root = std::env::temp_dir().join(format!("nexo-provider-{}", uuid::Uuid::new_v4()));
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let mut cfg =
        crate::caddy::CaddyRuntimeConfig::new(root.clone(), &crate::config::Caddy::default());
    cfg.binary = binary.into();
    cfg.admin_url = format!("http://127.0.0.1:{port}");
    let supervisor = Arc::new(crate::caddy::CaddySupervisor::new(cfg.clone()));
    let mut config = json!({"admin":{"listen":format!("127.0.0.1:{port}")},"apps":{}});
    supervisor.write_startup_config(&config).unwrap();
    supervisor.clone().start().await.unwrap();
    for _ in 0..50 {
        if supervisor.current_config().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for credential in [
        Credential::Cloudflare {
            token: format!("cfut_{}", "a".repeat(100)),
        },
        Credential::Alidns {
            access_key_id: "id".into(),
            access_key_secret: "secret".into(),
        },
        Credential::Tencentcloud {
            secret_id: "id".into(),
            secret_key: "secret".into(),
        },
    ] {
        let id = uuid::Uuid::new_v4().to_string();
        let file = if let Credential::Cloudflare { token } = &credential {
            crate::domains::write_credential(&cfg.cloudflare_token_root, &id, token).unwrap()
        } else {
            let mut fields = BTreeMap::new();
            for (key, value) in serde_json::to_value(&credential)
                .unwrap()
                .as_object()
                .unwrap()
            {
                if key != "provider" {
                    fields.insert(
                        key.clone(),
                        crate::domains::write_credential(
                            &cfg.cloudflare_token_root,
                            &id,
                            value.as_str().unwrap(),
                        )
                        .unwrap(),
                    );
                }
            }
            crate::domains::write_credential(
                &cfg.cloudflare_token_root,
                &id,
                &serde_json::to_string(&StoredCredential { fields }).unwrap(),
            )
            .unwrap()
        };
        let provider = {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO public_domains(id,tenant_id,domain,created_at,updated_at) VALUES(?1,'default',?2,0,0)",rusqlite::params![id,format!("{}.test",credential.name())]).unwrap();
            db.execute("INSERT INTO domain_settings(domain_id,certificate_mode,verified,verification_token,credential_file,dns_provider) VALUES(?1,'cloudflare_dns',1,'proof',?2,?3)",rusqlite::params![id,file,credential.name()]).unwrap();
            caddy_config(&db, &cfg.cloudflare_token_root, &id).unwrap()
        };
        config["apps"]["tls"] = json!({"automation":{"policies":[{"subjects":["no-issuance.test"],"issuers":[{"module":"acme","challenges":{"dns":{"provider":provider}}}]}]}});
        supervisor.apply_json(&config).await.unwrap();
        assert_eq!(
            supervisor.current_config().await.unwrap()["apps"]["tls"],
            config["apps"]["tls"]
        );
    }
    supervisor.shutdown().await.unwrap();
}

/// 本机 ACME 与权威 DNS 桩只替换外部服务，实际执行订单、TXT 传播、CSR 签发与撤销。
#[tokio::test]
async fn acme_dns01_issues_agent_csr_and_keeps_valid_chain_during_renewal_failure() {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use hickory_resolver::proto::{
        op::{Message, MessageType},
        rr::{rdata::TXT, RData, Record as DnsRecord},
    };
    #[derive(Clone)]
    struct Acme {
        base: String,
        ready: Arc<Mutex<bool>>,
        chain: Arc<Mutex<Option<String>>>,
    }
    async fn acme(State(state): State<Acme>, uri: Uri, body: Bytes) -> axum::response::Response {
        let payload = if body.is_empty() {
            json!({})
        } else {
            let envelope: Value = serde_json::from_slice(&body).unwrap();
            let raw = URL_SAFE_NO_PAD
                .decode(envelope["payload"].as_str().unwrap())
                .unwrap();
            if raw.is_empty() {
                json!({})
            } else {
                serde_json::from_slice(&raw).unwrap()
            }
        };
        let endpoint = |path: &str| format!("{}{path}", state.base);
        let order = || json!({"status":if state.chain.lock().unwrap().is_some(){"valid"}else if *state.ready.lock().unwrap(){"ready"}else{"pending"},"identifiers":[{"type":"dns","value":"emby.direct.test"}],"authorizations":[endpoint("/auth")],"finalize":endpoint("/finalize"),"certificate":endpoint("/certificate")});
        let (status, value) = match uri.path() {
            "/directory" => (
                200,
                json!({"newNonce":endpoint("/nonce"),"newAccount":endpoint("/account"),"newOrder":endpoint("/new-order")}),
            ),
            "/nonce" => (200, json!({})),
            "/account" => (201, json!({"status":"valid","orders":endpoint("/orders")})),
            "/new-order" => {
                *state.ready.lock().unwrap() = false;
                *state.chain.lock().unwrap() = None;
                (201, order())
            }
            "/order" => (200, order()),
            "/auth" => (
                200,
                json!({"identifier":{"type":"dns","value":"emby.direct.test"},"status":if *state.ready.lock().unwrap(){"valid"}else{"pending"},"challenges":[{"type":"dns-01","url":endpoint("/challenge"),"status":"pending","token":"local-challenge"}]}),
            ),
            "/challenge" => {
                *state.ready.lock().unwrap() = true;
                (
                    200,
                    json!({"type":"dns-01","url":endpoint("/challenge"),"status":"valid","token":"local-challenge"}),
                )
            }
            "/finalize" => {
                let der = URL_SAFE_NO_PAD
                    .decode(payload["csr"].as_str().unwrap())
                    .unwrap();
                let pem = format!(
                    "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
                    STANDARD.encode(der)
                );
                let request = rcgen::CertificateSigningRequestParams::from_pem(&pem).unwrap();
                assert!(
                    request
                        .params
                        .distinguished_name
                        .get(&rcgen::DnType::CommonName)
                        .is_none(),
                    "公网 CSR 不得带有 rcgen 默认 CN"
                );
                let mut params = rcgen::CertificateParams::default();
                params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                let key = rcgen::KeyPair::generate().unwrap();
                let ca = params.self_signed(&key).unwrap();
                let issuer = rcgen::Issuer::from_ca_cert_pem(&ca.pem(), key).unwrap();
                *state.chain.lock().unwrap() = Some(format!(
                    "{}{}",
                    request.signed_by(&issuer).unwrap().pem(),
                    ca.pem()
                ));
                (200, order())
            }
            "/certificate" => {
                return axum::response::Response::builder()
                    .header("content-type", "application/pem-certificate-chain")
                    .body(axum::body::Body::from(
                        state.chain.lock().unwrap().clone().unwrap(),
                    ))
                    .unwrap()
            }
            other => panic!("未知 ACME 路径 {other}"),
        };
        axum::response::Response::builder()
            .status(status)
            .header(
                "Replay-Nonce",
                URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()),
            )
            .header(
                "Location",
                endpoint(if uri.path() == "/account" {
                    "/account/1"
                } else {
                    "/order"
                }),
            )
            .header("content-type", "application/json")
            .body(axum::body::Body::from(value.to_string()))
            .unwrap()
    }
    let (mut state, domain) = crate::direct::tests::fixture();
    let root = std::env::temp_dir().join(format!("nexo-acme-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    state.data_dir = root;
    let (zone, dns, dns_api) = mock().await;
    *state.tunnel_runtime.direct.test_zone.lock().await = Some(zone);
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = socket.local_addr().unwrap().to_string();
    let dns_records = dns.clone();
    let dns_task = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..len]).unwrap();
            let mut reply = Message::new();
            reply
                .set_id(request.id())
                .set_message_type(MessageType::Response)
                .set_authoritative(true)
                .set_recursion_desired(true)
                .set_recursion_available(true);
            for query in request.queries() {
                reply.add_query(query.clone());
                for record in dns_records.records.lock().unwrap().iter().filter(|r| {
                    r.kind == "TXT" && format!("{}.", r.name) == query.name().to_string()
                }) {
                    reply.add_answer(DnsRecord::from_rdata(
                        query.name().clone(),
                        1,
                        RData::TXT(TXT::new(vec![record.value.clone()])),
                    ));
                }
            }
            socket
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE domain_settings SET dns_resolvers=?1,propagation_timeout=10 WHERE domain_id=?2",
            rusqlite::params![json!([resolver]).to_string(), domain],
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    Arc::make_mut(&mut state.config).direct.acme_directory = format!("{base}/directory");
    let app = Router::new().fallback(acme).with_state(Acme {
        base,
        ready: Default::default(),
        chain: Default::default(),
    });
    let ca_task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let http: hyper_util::client::legacy::Client<_, instant_acme::BodyWrapper<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let (account, _) = instant_acme::Account::builder_with_http(Box::new(http))
        .create(
            &instant_acme::NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            state.config.direct.acme_directory.clone(),
            None,
        )
        .await
        .unwrap();
    *state.tunnel_runtime.direct.account.lock().await = Some(account);
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["emby.direct.test".into()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    let service = crate::direct::service(&state, "agent", "media", 1).unwrap();
    crate::direct::certificates::request(&state, "agent", &service, csr.clone())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if state.tunnel_runtime.direct.jobs.lock().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let response = crate::direct::certificates::request(&state, "agent", &service, csr.clone())
        .await
        .unwrap();
    let nexo_protocol::direct::Response::Certificate {
        chain: Some(chain),
        error: None,
        ..
    } = response
    else {
        let error: Option<String> = state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT error FROM direct_certificates", [], |r| r.get(0))
            .unwrap();
        panic!("证书签发失败 {error:?}")
    };
    let private = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            nexo_tunnel::identity::certificates(&chain).unwrap(),
            private,
        )
        .unwrap();
    assert!(
        dns.records.lock().unwrap().is_empty(),
        "签发后必须撤销本次 TXT"
    );
    Arc::make_mut(&mut state.config).direct.relay_ipv4 = Some("192.0.2.10".parse().unwrap());
    state.db.lock().unwrap().execute("INSERT INTO direct_services(service_id,revision,ready,reported_at) VALUES('media',1,1,?1)",[crate::unix_now()]).unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute("INSERT INTO traffic_quota_limits VALUES('default',1)", [])
        .unwrap();
    let quota = state.tunnel_runtime.quotas.get(&state, "default").unwrap();
    let token = quota.connection().unwrap();
    assert_eq!(quota.datagram(1, &token, || 1), Some(1));
    assert!(quota.connection().is_none());
    crate::direct::dns::reconcile(&state).await.unwrap();
    assert_eq!(
        crate::direct::status(&state.db.lock().unwrap(), "media")["status"],
        "configured"
    );
    assert_eq!(dns.records.lock().unwrap().len(), 2);
    // 页面填写的公网 IPv4 优先于启动配置，下一轮 DNS 协调直接更新 A，无需重启。
    state.security.configuration.write().unwrap().relay_ipv4 = Some("8.8.8.8".parse().unwrap());
    crate::direct::dns::reconcile(&state).await.unwrap();
    assert_eq!(
        dns.records
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.kind == "A")
            .unwrap()
            .value,
        "8.8.8.8"
    );
    assert!(
        crate::direct::service(&state, "agent", "media", 1).is_ok(),
        "转发额度耗尽不得停止直连"
    );
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE direct_certificates SET renew_at=0,next_retry_at=?1,error='模拟续期失败'",
            [crate::unix_now() + 3600],
        )
        .unwrap();
    let nexo_protocol::direct::Response::Certificate {
        chain: Some(kept),
        error: Some(_),
        ..
    } = crate::direct::certificates::request(&state, "agent", &service, csr)
        .await
        .unwrap()
    else {
        panic!("续期失败丢失了有效证书")
    };
    assert_eq!(kept, chain);
    state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE tunnels SET enabled=0 WHERE id='media'", [])
        .unwrap();
    crate::direct::dns::reconcile(&state).await.unwrap();
    assert_eq!(dns.records.lock().unwrap().len(), 1);
    assert_eq!(dns.records.lock().unwrap()[0].kind, "A");
    assert_eq!(
        crate::direct::status(&state.db.lock().unwrap(), "media")["status"],
        "disabled"
    );
    dns_api.abort();
    dns_task.abort();
    ca_task.abort();
}
