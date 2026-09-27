use super::*;
use crate::service_access;
use axum::http::StatusCode;

/// 使用真实 Caddy、独立本机端口和内部 CA，验证认证前后原请求及 Cookie 的边界。
#[tokio::test]
#[ignore = "需要 NEXO_TEST_CADDY_BIN；只访问本机，不安装系统证书"]
async fn real_caddy_access_password_cookie_proxy_and_lan_priority() {
    let _guard = crate::auth::PASSWORD_TEST_LOCK.lock().await;
    let root = std::env::temp_dir().join(format!("nexo-access-{}", uuid::Uuid::new_v4()));
    let (state, _) = crate::tests::domain_fixture();
    let hash = crate::auth::hash_password("pass!").unwrap();
    {
        let db = state.db.lock().unwrap();
        db.execute("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES('domain','default','access.localhost',1,0,0)",[]).unwrap();
        for (id, protocol, mode) in [
            ("web", "https", "password"),
            ("plain", "http", "password"),
            ("public", "https", "public"),
        ] {
            db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,hostname,public_domain_id,access_mode,access_password_hash,created_at,updated_at) VALUES(?1,'default',?1,?2,'127.0.0.1',3000,?1,'domain',?3,?4,0,0)",params![id,protocol,mode,hash]).unwrap();
        }
    }
    let access = service_access::Runtime::start(&state).await.unwrap();
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = origin.local_addr().unwrap().to_string();
    let origin_task = tokio::spawn(async move {
        while let Ok((stream, _)) = origin.accept().await {
            tokio::spawn(async move {
                let _ = super::reverse_proxy_tests::echo_origin(stream, "origin").await;
            });
        }
    });
    let port = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let mut cfg = CaddyRuntimeConfig::new(&root, &crate::config::Caddy::default());
    cfg.binary = std::env::var_os("NEXO_TEST_CADDY_BIN").unwrap().into();
    cfg.enabled = true;
    cfg.admin_url = format!("http://127.0.0.1:{}", port());
    cfg.http_listen = format!("127.0.0.1:{}", port());
    cfg.https_listen = format!("127.0.0.1:{}", port());
    cfg.access_address = access.address.clone();
    let http: SocketAddr = cfg.http_listen.parse().unwrap();
    let https: SocketAddr = format!("127.0.0.1:{}", port()).parse().unwrap();
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE tunnels SET https_port=?1 WHERE protocol='https'",
            [https.port()],
        )
        .unwrap();
    let mut domain = DomainSpec {
        id: "domain".into(),
        tenant_id: "default".into(),
        name: "access.localhost".into(),
        https: true,
        token_reference: None,
        dns_provider: None,
        certificate_mode: "http01".into(),
        dns: Default::default(),
        services: Vec::new(),
    };
    for (id, protocol) in [("web", "https"), ("plain", "http"), ("public", "https")] {
        domain.services.push(WebService {
            https_port: https.port(),
            management: false,
            http_redirect_enabled: false,
            id: id.into(),
            hostname: format!("{id}.access.localhost"),
            protocol: protocol.into(),
            upstream: Some(upstream.clone()),
            lan_redirect: None,
        });
    }
    let config = |domain: DomainSpec| {
        let mut value = build_config(&cfg, &[domain]).unwrap();
        value["apps"]["tls"]["automation"]["policies"] =
            json!([{"issuers":[{"module":"internal"}]}]);
        value
    };
    let supervisor = Arc::new(CaddySupervisor::new(cfg.clone()));
    supervisor
        .write_startup_config(&config(domain.clone()))
        .unwrap();
    supervisor.clone().start().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    while read_certificates(&cfg.storage_root).len() < 3
        || supervisor.current_config().await.is_err()
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{:?}",
            supervisor.drain_log_events().await
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let cert = fs::read(cfg.storage_root.join("pki/authorities/local/root.crt")).unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .pool_max_idle_per_host(0)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .add_root_certificate(reqwest::Certificate::from_pem(&cert).unwrap())
        .resolve("web.access.localhost", https)
        .resolve("public.access.localhost", https)
        .resolve("plain.access.localhost", http)
        .build()
        .unwrap();
    for (id, protocol, port) in [
        ("web", "https", https.port()),
        ("plain", "http", http.port()),
    ] {
        let base = format!("{protocol}://{id}.access.localhost:{port}");
        let url = format!("{base}/photos/a%2Fb?q=%2F");
        let unauth = client
            .get(&url)
            .header("X-Nexo-Access-Service", "public")
            .header("X-Forwarded-For", "127.0.0.1")
            .send()
            .await
            .unwrap();
        assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);
        let navigation = client
            .get(&url)
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Dest", "document")
            .send()
            .await
            .unwrap();
        assert_eq!(navigation.status(), StatusCode::SEE_OTHER);
        assert!(navigation.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("/.nexo-access/?return="));
        let legacy_navigation = client
            .get(&url)
            .header("Accept", "text/html,application/xhtml+xml")
            .send()
            .await
            .unwrap();
        assert_eq!(legacy_navigation.status(), StatusCode::SEE_OTHER);
        let oversized = client
            .post(format!("{base}/.nexo-access/login"))
            .header("Origin", &base)
            .json(&json!({"password":"x".repeat(3000)}))
            .send()
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(oversized.headers()["cache-control"], "no-store");
        let page = client
            .get(format!("{base}/.nexo-access/"))
            .send()
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        assert!(page.text().await.unwrap().contains("输入密码以访问"));
        let denied = client
            .post(format!("{base}/.nexo-access/login"))
            .header("Origin", "http://evil.test")
            .json(&json!({"password":"pass!"}))
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let login = client
            .post(format!("{base}/.nexo-access/login"))
            .header("Origin", &base)
            .json(&json!({"password":"pass!","return_to":"/photos/a%2Fb?q=%2F"}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            login.status(),
            StatusCode::OK,
            "{}",
            login.text().await.unwrap()
        );
        let set_cookie = login.headers()["set-cookie"].to_str().unwrap().to_owned();
        assert_eq!(set_cookie.contains("Secure"), protocol == "https");
        let cookie = set_cookie.split(';').next().unwrap();
        let other = if id == "web" {
            format!("http://plain.access.localhost:{}/", http.port())
        } else {
            format!("https://web.access.localhost:{}/", https.port())
        };
        assert_eq!(
            client
                .get(other)
                .header("Cookie", cookie)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let body = client
            .post(&url)
            .header("Cookie", format!("app=kept; {cookie}"))
            .header("Authorization", "Bearer application-token")
            .header("X-Nexo-Access-Service", "forged")
            .body("payload-original")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(body.contains("POST /photos/a%2Fb?q=%2F"), "{body}");
        assert!(body.contains("payload-original"), "{body}");
        assert!(body.contains("app=kept"), "{body}");
        assert!(body.contains("Bearer application-token"), "{body}");
        assert!(!body.contains("nexo_access_"), "{body}");
        assert!(!body.to_lowercase().contains("x-nexo-access"), "{body}");
        let cross = client
            .get(format!("https://public.access.localhost:{}/", https.port()))
            .header("Cookie", cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(cross.status(), StatusCode::OK);
        let ws = client
            .get(&url)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .unwrap();
        assert_eq!(ws.status(), StatusCode::UNAUTHORIZED);
        let ws = client
            .get(&url)
            .header("Cookie", cookie)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .send()
            .await
            .unwrap();
        assert_eq!(ws.status(), StatusCode::SWITCHING_PROTOCOLS);
        state.db.lock().unwrap().execute("UPDATE tunnels SET access_password_hash=access_password_hash || 'revoked' WHERE id=?1",[id]).unwrap();
        assert_eq!(
            client
                .get(&url)
                .header("Cookie", cookie)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    // 同出口只允许导航跳转；API 和 WebSocket 仍须认证。认证故障不妨碍内网直达。
    domain.services[0].lan_redirect = Some(LanRedirect {
        public_ipv4: Ipv4Addr::LOCALHOST,
        origin: "http://192.168.1.10:8080".into(),
    });
    supervisor
        .apply_json(&config(domain.clone()))
        .await
        .unwrap();
    let url = format!("https://web.access.localhost:{}/photos?q=1", https.port());
    let nav = || {
        client
            .get(&url)
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Dest", "document")
    };
    let jumped = nav().send().await.unwrap();
    assert_eq!(jumped.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        jumped.headers()["location"],
        "http://192.168.1.10:8080/photos?q=1"
    );
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    drop(access);
    assert_eq!(
        nav().send().await.unwrap().status(),
        StatusCode::TEMPORARY_REDIRECT
    );
    assert!(client
        .get(&url)
        .send()
        .await
        .unwrap()
        .status()
        .is_server_error());
    supervisor.shutdown().await.unwrap();
    origin_task.abort();
    let _ = fs::remove_dir_all(root);
}
