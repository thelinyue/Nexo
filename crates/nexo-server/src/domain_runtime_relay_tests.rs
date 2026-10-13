use super::*;
use crate::service_access;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DOMAIN: &str = "00000000-0000-4000-8000-000000000001";

fn fixture() -> AppState {
    let (state, _) = crate::tests::domain_fixture();
    let now = unix_now();
    {
        let db = state.db.lock().unwrap();
        db.execute("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES(?1,'default','relay.localhost',1,0,0)", [DOMAIN]).unwrap();
        db.execute("INSERT INTO domain_settings(domain_id,verification_token,certificate_mode,verified) VALUES(?1,'proof','cloudflare_dns',1)", [DOMAIN]).unwrap();
        db.execute_batch("INSERT INTO relay_nodes(id,name,public_ipv4,approved,reverse_proxy_supported,traffic_quota_supported,created_at) VALUES('remote','独立节点','8.8.4.4',1,1,1,0);
            INSERT INTO relay_node_grants VALUES('remote','default');
            INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,hostname,public_domain_id,service_mode,created_at,updated_at) VALUES('relay','default','反代','https','127.0.0.1',3000,'app','00000000-0000-4000-8000-000000000001','reverse_proxy',0,0);
            DELETE FROM service_nodes WHERE service_id='relay'; INSERT INTO service_nodes VALUES('relay','remote');").unwrap();
        db.execute(
            "UPDATE relay_nodes SET last_seen=?1 WHERE id='remote'",
            [now],
        )
        .unwrap();
        db.execute("INSERT INTO relay_service_health(node_id,service_id,revision,healthy,checked_at) VALUES('remote','relay',1,1,?1)", [now]).unwrap();
    }
    state
}

#[test]
fn relay_routes_use_node_ip_and_business_sni_without_local_health_or_origin() {
    let state = fixture();
    let specs = specifications(&state, &HashMap::new(), &HashMap::new()).unwrap();
    assert_eq!(specs[0].services.len(), 1);
    let config = build_config(state.domain_runtime.supervisor.config(), &specs).unwrap();
    let routes = config["apps"]["http"]["servers"]["https"]["routes"]
        .as_array()
        .unwrap();
    let route = routes
        .iter()
        .find(|r| {
            r["match"][0]["host"][0] == "app.relay.localhost" && r["match"][0]["path"].is_null()
        })
        .unwrap();
    let proxy = &route["handle"][1];
    assert_eq!(proxy["upstreams"][0]["dial"], "8.8.4.4:443");
    assert_eq!(
        proxy["transport"]["tls"]["server_name"],
        "app.relay.localhost"
    );
    assert!(proxy["transport"]["tls"]["insecure_skip_verify"].is_null());
    assert!(proxy["stream_close_delay"].is_null());
    assert!(!config.to_string().contains("127.0.0.1:3000"));
    assert!(!config
        .to_string()
        .contains(crate::nodes::health::PROBE_PATH));
    state
        .db
        .lock()
        .unwrap()
        .execute_batch("UPDATE users SET role='tenant'; DELETE FROM relay_node_grants;")
        .unwrap();
    assert!(
        specifications(&state, &HashMap::new(), &HashMap::new()).unwrap()[0]
            .services
            .is_empty()
    );
}

fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 两个独立 Caddy 模拟旧管理端入口和当前节点入口，DNS 固定到各自回环地址。
/// 仅测试配置将数据库中的公网 IP 映射至回环地址，内部 CA 只在测试客户端和测试上游中信任。
#[tokio::test]
#[ignore = "需要 NEXO_TEST_CADDY_BIN；两个真实 Caddy，只访问本机"]
async fn real_caddy_relay_old_ip_tls_password_websocket_and_stale_config() {
    let _guard = crate::auth::PASSWORD_TEST_LOCK.lock().await;
    let root = tempfile::tempdir().unwrap();
    let mut state = fixture();
    let mut cfg = CaddyRuntimeConfig::new(
        root.path().join("manager"),
        &crate::config::Caddy::default(),
    );
    cfg.binary = std::env::var_os("NEXO_TEST_CADDY_BIN")
        .expect("请设置 Caddy 路径")
        .into();
    cfg.enabled = true;
    cfg.admin_url = format!("http://127.0.0.1:{}", port());
    cfg.http_listen = format!("127.0.0.1:{}", port());
    cfg.https_listen = format!("127.0.0.1:{}", port());
    // 根域使用默认 HTTPS 监听，业务入口使用独立端口，避免两个 Caddy server 重复监听。
    let https_port = port();
    let http_port: u16 = cfg.http_listen.rsplit(':').next().unwrap().parse().unwrap();
    let mut app_config = crate::config::Config::default();
    app_config.caddy.http_listen = cfg.http_listen.clone();
    state.config = Arc::new(app_config);
    state.domain_runtime = Arc::new(DomainRuntimeManager::new(cfg.clone()));
    let access = service_access::Runtime::start(&state).await.unwrap();
    cfg.access_address = access.address.clone();
    let credential = crate::domains::write_credential(
        &cfg.cloudflare_token_root,
        DOMAIN,
        &format!("cfat_{}", "a".repeat(100)),
    )
    .unwrap();
    {
        let db = state.db.lock().unwrap();
        db.execute(
            "UPDATE domain_settings SET credential_file=?1 WHERE domain_id=?2",
            params![credential, DOMAIN],
        )
        .unwrap();
        db.execute(
            "UPDATE tunnels SET https_port=?1 WHERE id='relay'",
            [https_port],
        )
        .unwrap();
    }
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        while let Ok((stream, _)) = origin.accept().await {
            tokio::spawn(async move {
                let _ = reverse_proxy_tests::echo_origin(stream, "node-origin").await;
            });
        }
    });
    let mut node_cfg =
        CaddyRuntimeConfig::new(root.path().join("node"), &crate::config::Caddy::default());
    node_cfg.binary = cfg.binary.clone();
    node_cfg.enabled = true;
    node_cfg.admin_url = format!("http://127.0.0.1:{}", port());
    node_cfg.http_listen = format!("127.0.0.2:{http_port}");
    node_cfg.https_listen = format!("127.0.0.2:{}", port());
    node_cfg.access_address = access.address.clone();
    let internal_ca = |mut config: Value| {
        config["apps"]["pki"] =
            json!({"certificate_authorities":{"local":{"install_trust":false}}});
        config["apps"]["tls"]["automation"]["policies"] =
            json!([{"issuers":[{"module":"internal"}]}]);
        config
    };
    let specs = || specifications(&state, &HashMap::new(), &HashMap::new()).unwrap();
    let node_config = || {
        let mut domains = specs();
        domains[0].services[0].relay = None;
        domains[0].services[0].upstream = Some(format!("http://{origin_address}"));
        internal_ca(build_config(&node_cfg, &domains).unwrap())
    };
    let node = Arc::new(CaddySupervisor::new(node_cfg.clone()));
    node.write_startup_config(&node_config()).unwrap();
    node.clone().start().await.unwrap();
    let node_ca = node_cfg.storage_root.join("pki/authorities/local/root.crt");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while read_certificates(&node_cfg.storage_root).len() < 2
        || node.current_config().await.is_err()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "节点 Caddy 未就绪：{:?}",
            node.drain_log_events().await
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let manager_config = || {
        let mut config = internal_ca(build_config(&cfg, &specs()).unwrap());
        for server in config["apps"]["http"]["servers"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            for route in server["routes"].as_array_mut().unwrap() {
                if let Some(handlers) = route["handle"].as_array_mut() {
                    for handler in handlers {
                        if handler["upstreams"][0]["dial"]
                            .as_str()
                            .is_some_and(|dial| dial.starts_with("8.8.4.4:"))
                        {
                            let port = handler["upstreams"][0]["dial"]
                                .as_str()
                                .unwrap()
                                .rsplit(':')
                                .next()
                                .unwrap()
                                .to_owned();
                            handler["upstreams"][0]["dial"] = json!(format!("127.0.0.2:{port}"));
                            if !handler["transport"]["tls"].is_null() {
                                handler["transport"]["tls"]["ca"] =
                                    json!({"provider":"file","pem_files":[node_ca]});
                            }
                        }
                    }
                }
            }
        }
        config
    };
    let manager = Arc::new(CaddySupervisor::new(cfg.clone()));
    manager.write_startup_config(&manager_config()).unwrap();
    manager.clone().start().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while read_certificates(&cfg.storage_root).len() < 2 || manager.current_config().await.is_err()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "管理端 Caddy 未就绪：{:?}",
            manager.drain_log_events().await
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let client = |ip: &str| {
        reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .pool_max_idle_per_host(0)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .add_root_certificate(
                reqwest::Certificate::from_pem(
                    &fs::read(cfg.storage_root.join("pki/authorities/local/root.crt")).unwrap(),
                )
                .unwrap(),
            )
            .add_root_certificate(
                reqwest::Certificate::from_pem(&fs::read(&node_ca).unwrap()).unwrap(),
            )
            .resolve(
                "app.relay.localhost",
                format!("{ip}:{https_port}").parse().unwrap(),
            )
            .build()
            .unwrap()
    };
    let old_ip = client("127.0.0.1");
    let direct = client("127.0.0.2");
    let base = format!("https://app.relay.localhost:{https_port}");
    for client in [&old_ip, &direct] {
        let response = client
            .post(format!("{base}/a%2Fb?q=%2F"))
            .header("Cookie", "app=kept")
            .header("X-Nexo-Access-Relay-Node", "forged")
            .body("payload-original")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200, "{}", response.text().await.unwrap());
        let body = response.text().await.unwrap();
        assert!(body.contains("POST /a%2Fb?q=%2F"), "{body}");
        assert!(
            body.contains("payload-original") && body.contains("app=kept"),
            "{body}"
        );
        assert!(
            body.to_lowercase()
                .contains(&format!("host: app.relay.localhost:{https_port}")),
            "{body}"
        );
        assert!(!body.to_lowercase().contains("x-nexo-access"), "{body}");
    }
    // 上游证书主机名必须匹配；修改 SNI 后应失败，不能静默跳过校验。
    let good = manager_config();
    let mut wrong_sni = good.clone();
    for server in wrong_sni["apps"]["http"]["servers"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        for route in server["routes"].as_array_mut().unwrap() {
            if let Some(handlers) = route["handle"].as_array_mut() {
                for handler in handlers {
                    if !handler["transport"]["tls"].is_null() {
                        handler["transport"]["tls"]["server_name"] = json!("wrong.invalid");
                    }
                }
            }
        }
    }
    manager.apply_json(&wrong_sni).await.unwrap();
    assert_eq!(old_ip.get(&base).send().await.unwrap().status(), 502);
    manager.apply_json(&good).await.unwrap();
    let hash = crate::auth::hash_password("pass!").unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE tunnels SET access_mode='password',access_password_hash=?1 WHERE id='relay'",
            [hash],
        )
        .unwrap();
    assert_eq!(
        old_ip
            .post(&base)
            .body("denied")
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let page = old_ip
        .get(format!("{base}/.nexo-access/"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let login = old_ip
        .post(format!("{base}/.nexo-access/login"))
        .header("Origin", &base)
        .json(&json!({"password":"pass!","return_to":"/photos"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200, "{}", login.text().await.unwrap());
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    for client in [&old_ip, &direct] {
        let body = client
            .post(&base)
            .header("Cookie", format!("app=kept; {cookie}"))
            .body("authenticated-body")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            body.contains("authenticated-body") && body.contains("app=kept"),
            "{body}"
        );
        assert!(!body.contains("nexo_access_"), "{body}");
    }
    // 保留加载中的旧配置；授权变化必须逐请求阻断，而不是等待下一轮 Caddy 重载。
    for (change, restore, expected) in [
        ("UPDATE relay_service_health SET healthy=0", "UPDATE relay_service_health SET healthy=1", 503),
        ("UPDATE relay_nodes SET maintenance=1 WHERE id='remote'", "UPDATE relay_nodes SET maintenance=0 WHERE id='remote'", 503),
        ("UPDATE tunnels SET apply_revision=2 WHERE id='relay'", "UPDATE tunnels SET apply_revision=1 WHERE id='relay'", 503),
        ("UPDATE relay_nodes SET public_ipv4='8.8.8.8' WHERE id='remote'", "UPDATE relay_nodes SET public_ipv4='8.8.4.4' WHERE id='remote'", 503),
        ("UPDATE tunnels SET enabled=0 WHERE id='relay'", "UPDATE tunnels SET enabled=1 WHERE id='relay'", 404),
        ("UPDATE tunnels SET deleted_at=unixepoch() WHERE id='relay'", "UPDATE tunnels SET deleted_at=NULL WHERE id='relay'", 404),
        ("UPDATE users SET role='tenant'; DELETE FROM relay_node_grants", "INSERT INTO relay_node_grants VALUES('remote','default'); UPDATE users SET role='system_admin'", 404),
        ("INSERT INTO node_traffic_limits(node_id,monthly_limit_bytes) VALUES('remote',1); INSERT INTO node_traffic_months(node_id,month,used_bytes) VALUES('remote',unixepoch(strftime('%Y-%m-01','now','+8 hours'),'-8 hours'),1)", "DELETE FROM node_traffic_limits; DELETE FROM node_traffic_months", 503),
    ] {
        state.db.lock().unwrap().execute_batch(change).unwrap();
        assert_eq!(old_ip.get(&base).header("Cookie", &cookie).send().await.unwrap().status().as_u16(), expected, "{change}");
        state.db.lock().unwrap().execute_batch(restore).unwrap();
    }
    // HTTP 与 WebSocket 同样经过两层入口；密码 Cookie 仍必须由最终入口清理。
    state
        .db
        .lock()
        .unwrap()
        .execute_batch("UPDATE tunnels SET protocol='http' WHERE id='relay'")
        .unwrap();
    node.apply_json(&node_config()).await.unwrap();
    manager.apply_json(&manager_config()).await.unwrap();
    let http_address = format!("127.0.0.1:{http_port}");
    // 停用和协议变更会按既有触发器撤销会话；HTTP 场景必须重新登录。
    let plain = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let login = plain
        .post(format!("http://{http_address}/.nexo-access/login"))
        .header("Host", "app.relay.localhost")
        .header("Origin", "http://app.relay.localhost")
        .json(&json!({"password":"pass!"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200, "{}", login.text().await.unwrap());
    let cookie = login.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut ws = tokio::net::TcpStream::connect(&http_address).await.unwrap();
    ws.write_all(format!("GET /ws HTTP/1.1\r\nHost: app.relay.localhost\r\nCookie: {cookie}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(ws.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap();
    assert!(
        head.contains("101 Switching Protocols"),
        "WebSocket 握手失败：{head}"
    );
    ws.write_all(&[0x81, 0x82, 1, 2, 3, 4, b'o' ^ 1, b'k' ^ 2])
        .await
        .unwrap();
    let mut echoed = [0; 4];
    ws.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, [0x81, 2, b'o', b'k']);
    // 模拟新配置被 Caddy 拒绝后，原路由仍在运行，撤权检查必须继续起作用。
    let mut rejected = manager_config();
    rejected["apps"]["http"]["servers"]["http"]["routes"][0]["handle"] =
        json!([{"handler":"unknown-module"}]);
    assert!(manager.apply_json(&rejected).await.is_err());
    state
        .db
        .lock()
        .unwrap()
        .execute_batch("UPDATE users SET role='tenant'; DELETE FROM relay_node_grants")
        .unwrap();
    assert_eq!(
        plain
            .get(format!("http://{http_address}/"))
            .header("Host", "app.relay.localhost")
            .header("Cookie", &cookie)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    manager.apply_json(&manager_config()).await.unwrap();
    let mut closed = Vec::new();
    // 允许 Caddy 发送 WebSocket 关闭帧，或底层连接直接结束/重置。
    let _ = tokio::time::timeout(Duration::from_secs(5), ws.read_to_end(&mut closed))
        .await
        .expect("撤销兼容路由后旧 WebSocket 未关闭");
    assert_eq!(
        plain
            .get(format!("http://{http_address}/"))
            .header("Host", "unknown.relay.localhost")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    manager.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    origin_task.abort();
}
