use super::*;
use crate::{reverse_proxy, *};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
const DOMAIN: &str = "00000000-0000-4000-8000-000000000001";

#[test]
fn direct_tls_keeps_host_and_verifies_target_while_tunnels_keep_socket_transport() {
    let direct = proxy_handler("https://origin.internal:8443").unwrap();
    assert_eq!(direct["upstreams"][0]["dial"], "origin.internal:8443");
    assert_eq!(direct["transport"]["tls"]["server_name"], "origin.internal");
    assert!(direct["transport"]["tls"]["insecure_skip_verify"].is_null());
    assert_eq!(
        direct["headers"]["request"]["set"]["Host"],
        json!(["{http.request.hostport}"])
    );
    assert_eq!(
        proxy_handler("http://[::1]:8080").unwrap()["upstreams"][0]["dial"],
        "[::1]:8080"
    );
    assert!(proxy_handler("127.0.0.1:10000").unwrap()["transport"].is_null());
}

/// 测试上游回显原始 HTTP 请求；WebSocket 握手后解码一帧并返回，验证真实升级后的双向通道。
pub(super) async fn echo_origin<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    label: &str,
) -> anyhow::Result<()> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await?);
    }
    let request = String::from_utf8(head)?;
    if request.to_ascii_lowercase().contains("upgrade: websocket") {
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await?;
        let opcode = stream.read_u8().await?;
        let length = stream.read_u8().await?;
        let mut mask = [0; 4];
        stream.read_exact(&mut mask).await?;
        let mut payload = vec![0; usize::from(length & 127)];
        stream.read_exact(&mut payload).await?;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        stream.write_all(&[opcode, payload.len() as u8]).await?;
        stream.write_all(&payload).await?;
    } else {
        let length = request
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|s| s.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await?;
        let response = format!("{label}\n{request}{}", String::from_utf8_lossy(&body));
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                )
                .as_bytes(),
            )
            .await?;
    }
    stream.shutdown().await?;
    Ok(())
}

fn input(port: u16, origin: &str) -> TunnelInput {
    serde_json::from_value(json!({"service_mode":"reverse_proxy","name":"VPS 应用","protocol":"https","origin_protocol":origin,"local_address":"127.0.0.1","local_port":port,"hostname":"app","public_domain_id":DOMAIN})).unwrap()
}

#[tokio::test]
#[ignore = "需要 NEXO_TEST_CADDY_BIN；随机本机端口与内部 CA，不安装系统信任"]
async fn real_caddy_direct_proxy_lifecycle_tls_websocket_and_quota_isolation() {
    let root = std::env::temp_dir().join(format!("nexo-direct-proxy-{}", uuid::Uuid::new_v4()));
    let port = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let mut cfg = CaddyRuntimeConfig::new(root.clone(), &crate::config::Caddy::default());
    cfg.enabled = true;
    cfg.binary = std::env::var_os("NEXO_TEST_CADDY_BIN")
        .expect("请设置测试 Caddy 路径")
        .into();
    cfg.admin_url = format!("http://127.0.0.1:{}", port());
    cfg.http_listen = format!("127.0.0.1:{}", port());
    cfg.https_listen = format!("127.0.0.1:{}", port());
    let http_address: SocketAddr = cfg.http_listen.parse().unwrap();
    let https_address: SocketAddr = cfg.https_listen.parse().unwrap();
    let (mut state, headers) = crate::tests::domain_fixture();
    state.domain_runtime = Arc::new(DomainRuntimeManager::new(cfg.clone()));
    let api_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_address = api_listener.local_addr().unwrap();
    state.config = Arc::new(crate::config::Config {
        http_addr: api_address,
        ..Default::default()
    });
    let app = crate::router(state.clone());
    let api_task = tokio::spawn(async move {
        axum::serve(
            api_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    state
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE users SET password_hash=?1 WHERE id='u'",
            [crate::auth::hash_password("test-password-1234").unwrap()],
        )
        .unwrap();
    // localhost 由 Caddy 内部 CA 管理，无公网 DNS 或 ACME 副作用。
    let credential = crate::domains::write_credential(
        &cfg.cloudflare_token_root,
        DOMAIN,
        &format!("cfat_{}", "a".repeat(100)),
    )
    .unwrap();
    state.db.lock().unwrap().execute("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES(?1,'default','reverse.localhost',1,0,0)", [DOMAIN]).unwrap();
    state.db.lock().unwrap().execute("INSERT INTO domain_settings(domain_id,certificate_mode,verified,verification_token,credential_file) VALUES(?1,'cloudflare_dns',1,'test-proof',?2)", params![DOMAIN,credential]).unwrap();
    let supervisor = state.domain_runtime.supervisor.clone();
    supervisor
        .write_startup_config(&build_config(&cfg, &[]).unwrap())
        .unwrap();
    supervisor.clone().start().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while supervisor.current_config().await.is_err() {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // 独立测试预置根域和泛域证书；正常 DNS 配置使用已有证书，不访问公共 CA。
    let mut local_ca = build_config(&cfg, &[]).unwrap();
    local_ca["apps"]["tls"] = json!({"certificates":{"automate":["reverse.localhost","*.reverse.localhost"]},"automation":{"policies":[{"issuers":[{"module":"internal"}]}]}});
    supervisor.apply_json(&local_ca).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while read_certificates(&cfg.storage_root).len() < 2 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // DNS issuer 从 ACME 存储读取已有证书；保留 Caddy 的泛域文件命名。
    for directory in fs::read_dir(cfg.storage_root.join("certificates/local")).unwrap() {
        let source = directory.unwrap().path();
        let target = cfg
            .storage_root
            .join("certificates/acme-v02.api.letsencrypt.org-directory")
            .join(source.file_name().unwrap());
        fs::create_dir_all(&target).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
        }
    }
    let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let origin_task = tokio::spawn(async move {
        while let Ok((stream, _)) = origin.accept().await {
            tokio::spawn(async move {
                let _ = echo_origin(stream, "first").await;
            });
        }
    });
    let proxy = create_tunnel(
        State(state.clone()),
        headers.clone(),
        Json(input(origin_port, "http")),
    )
    .await
    .unwrap()
    .0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        reconcile(&state).await.unwrap();
        reverse_proxy::refresh_status(&state).unwrap();
        if read_tunnel(&state, "default", &proxy.id, &headers)
            .unwrap()
            .apply_status
            == "ready"
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{:?}",
            supervisor.drain_log_events().await
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let pem = fs::read(cfg.storage_root.join("pki/authorities/local/root.crt")).unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .add_root_certificate(reqwest::Certificate::from_pem(&pem).unwrap())
        .resolve("app.reverse.localhost", https_address)
        .resolve("manage.reverse.localhost", https_address)
        .build()
        .unwrap();
    let url = format!("https://app.reverse.localhost:{}", https_address.port());
    // 配置已加载不代表 Caddy 已完成证书缓存切换，等待真实 TLS 入口后再检查代理请求。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .get(&url)
            .send()
            .await
            .is_ok_and(|r| r.status() == 200)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "HTTPS 测试入口未就绪：{:?}",
            supervisor.drain_log_events().await
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let response = client
        .post(format!("{url}/a%2Fb?x=a+b&y=%2F"))
        .header("X-Forwarded-For", "6.6.6.6")
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let text = response.text().await.unwrap().to_ascii_lowercase();
    assert!(text.contains("post /a%2fb?x=a+b&y=%2f"));
    assert!(text.contains("payload"));
    assert!(text.contains(&format!(
        "host: app.reverse.localhost:{}",
        https_address.port()
    )));
    assert!(text.contains("x-forwarded-proto: https"));
    assert!(!text.contains("6.6.6.6"));
    // 默认重定向保留 URI，关闭后 HTTP 不能偷偷变成明文代理。
    let no_redirect = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let redirect = no_redirect
        .post(format!("http://{http_address}/a%2Fb?x=a+b&y=%2F"))
        .header("Host", "app.reverse.localhost")
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(redirect.status(), 307);
    assert_eq!(
        redirect.headers()["location"],
        "https://app.reverse.localhost/a%2Fb?x=a+b&y=%2F"
    );
    assert_eq!(redirect.headers()["cache-control"], "no-store");
    let mut unforced = input(origin_port, "http");
    unforced.http_redirect_enabled = Some(false);
    let _ = update_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
        Json(unforced),
    )
    .await
    .unwrap();
    assert_eq!(
        no_redirect
            .get(format!("http://{http_address}/"))
            .header("Host", "app.reverse.localhost")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let mut forced = input(origin_port, "http");
    forced.http_redirect_enabled = Some(true);
    let _ = update_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
        Json(forced),
    )
    .await
    .unwrap();
    // 真实 HTTP 原入口保存管理配置，再经过真实 Caddy TLS 验证登录、安全 Cookie 和双入口写入。
    let settings_url = format!("http://{api_address}/api/v1/admin/server-settings");
    let management_body =
        json!({"management_entry":{"domain_id":DOMAIN,"hostname":"manage"},"public_ips":[]});
    let saved = no_redirect
        .put(&settings_url)
        .headers(headers.clone())
        .header("Origin", format!("http://{api_address}"))
        .json(&management_body)
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 200, "{}", saved.text().await.unwrap());
    let management_url = format!("https://manage.reverse.localhost:{}", https_address.port());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .get(format!("{management_url}/health"))
            .header("Host", "manage.reverse.localhost")
            .send()
            .await
            .is_ok_and(|r| r.status() == 200)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "管理 HTTPS 未就绪：{:?}",
            supervisor.drain_log_events().await
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let login = client
        .post(format!("{management_url}/api/v1/auth/login"))
        .header("Host", "manage.reverse.localhost")
        .header("Origin", "https://manage.reverse.localhost")
        .header("X-Forwarded-Proto", "http")
        .json(&json!({"username":"admin","password":"test-password-1234"}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);
    assert!(login
        .headers()
        .get_all("set-cookie")
        .iter()
        .all(|v| v.to_str().unwrap().contains("; Secure")));
    let https_saved = client
        .put(format!("{management_url}/api/v1/admin/server-settings"))
        .headers(headers.clone())
        .header("Host", "manage.reverse.localhost")
        .header("Origin", "https://manage.reverse.localhost")
        .json(&management_body)
        .send()
        .await
        .unwrap();
    assert_eq!(https_saved.status(), 200);
    let status = https_saved.json::<Value>().await.unwrap();
    assert_eq!(status["status"], "ready");
    let forbidden = client
        .put(format!("{management_url}/api/v1/admin/server-settings"))
        .headers(headers.clone())
        .header("Host", "manage.reverse.localhost")
        .header("Origin", "https://attacker.invalid")
        .json(&management_body)
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), 403);
    let redirect = no_redirect
        .get(format!("http://{http_address}/#/manage"))
        .header("Host", "manage.reverse.localhost")
        .send()
        .await
        .unwrap();
    assert_eq!(redirect.status(), 307);
    let direct = no_redirect
        .get(format!("http://{api_address}/api/v1/auth/status"))
        .headers(headers.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(direct.status(), 200);
    assert_eq!(
        direct.json::<Value>().await.unwrap()["local_http_warning"],
        true
    );
    // TCP 上的真实 WebSocket 握手与帧经过相同反代目标。
    let mut plain = input(origin_port, "http");
    plain.protocol = "http".into();
    let _ = update_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
        Json(plain),
    )
    .await
    .unwrap();
    let mut ws = tokio::net::TcpStream::connect(http_address).await.unwrap();
    ws.write_all(b"GET /ws HTTP/1.1\r\nHost: app.reverse.localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(ws.read_u8().await.unwrap());
    }
    assert!(String::from_utf8(head)
        .unwrap()
        .contains("101 Switching Protocols"));
    ws.write_all(&[0x81, 0x82, 1, 2, 3, 4, b'o' ^ 1, b'k' ^ 2])
        .await
        .unwrap();
    let mut echoed = [0; 4];
    ws.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, [0x81, 2, b'o', b'k']);
    drop(ws);
    // HTTPS 目标必须校验证书：相同地址/端口仅改变协议也必须触发重载。
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let cert_path = root.join("test-origin.crt");
    fs::write(&cert_path, cert.cert.pem()).unwrap();
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let tls = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let origin_tls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_port = origin_tls.local_addr().unwrap().port();
    let tls_task = tokio::spawn(async move {
        while let Ok((stream, _)) = origin_tls.accept().await {
            let tls = tls.clone();
            tokio::spawn(async move {
                if let Ok(stream) = tls.accept(stream).await {
                    let _ = echo_origin(stream, "second").await;
                }
            });
        }
    });
    let _ = update_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
        Json(input(tls_port, "https")),
    )
    .await
    .unwrap();
    assert_eq!(client.get(&url).send().await.unwrap().status(), 502);
    // 只给测试 Caddy 配置加入本测试 CA；产品配置仍使用系统信任，不引入跳过校验开关。
    let mut trusted = supervisor.current_config().await.unwrap();
    let routes = trusted["apps"]["http"]["servers"]["https"]["routes"]
        .as_array_mut()
        .unwrap();
    let handler = &mut routes
        .iter_mut()
        .find(|r| {
            r["match"][0]["host"][0] == "app.reverse.localhost" && r["match"][0]["path"].is_null()
        })
        .unwrap()["handle"][1];
    handler["transport"]["tls"]["root_ca_pem_files"] = json!([cert_path]);
    supervisor.apply_json(&trusted).await.unwrap();
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let text = response.text().await.unwrap();
    assert!(text.starts_with("second"));
    assert!(text
        .to_ascii_lowercase()
        .contains("host: app.reverse.localhost:"));
    let _ = update_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
        Json(input(origin_port, "http")),
    )
    .await
    .unwrap();
    // 额度耗尽且没有 Agent，直连仍正常；周期性的隧道刷新不能覆盖反代状态。
    state.db.lock().unwrap().execute_batch("INSERT INTO traffic_quota_limits VALUES('default',1); INSERT INTO traffic_quota_months VALUES('default',unixepoch(strftime('%Y-%m-01','now','+8 hours'),'-8 hours'),1);").unwrap();
    assert!(state
        .tunnel_runtime
        .quotas
        .get(&state, "default")
        .unwrap()
        .connection()
        .is_none());
    state.tunnel_runtime.reconcile(&state).await.unwrap();
    assert_eq!(
        read_tunnel(&state, "default", &proxy.id, &headers)
            .unwrap()
            .apply_status,
        "ready"
    );
    assert_eq!(client.get(&url).send().await.unwrap().status(), 200);
    let _ = disable_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
    )
    .await
    .unwrap();
    // 服务停用后通过 HTTP 入口验证路由已撤销，共享泛域证书仍保留。
    let removed = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{http_address}/"))
        .header("Host", "app.reverse.localhost")
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 404);
    let _ = enable_tunnel(
        State(state.clone()),
        headers.clone(),
        Path(proxy.id.clone()),
    )
    .await
    .unwrap();
    assert_eq!(client.get(&url).send().await.unwrap().status(), 200);
    supervisor.shutdown().await.unwrap();
    let restarted = Arc::new(CaddySupervisor::new(cfg));
    restarted.clone().start().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .get(&url)
            .send()
            .await
            .is_ok_and(|r| r.status() == 200)
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    origin_task.abort();
    origin_task.await.ok();
    assert_eq!(client.get(&url).send().await.unwrap().status(), 502);
    // 新 manager 接管已恢复的 Caddy，验证 API 删除真实撤销路由。
    let _ = delete_tunnel(State(state.clone()), headers.clone(), Path(proxy.id))
        .await
        .unwrap();
    // 删除服务只撤销路由，共享泛域证书仍保留。
    let removed = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{http_address}/"))
        .header("Host", "app.reverse.localhost")
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 404);
    let disabled = no_redirect
        .put(&settings_url)
        .headers(headers.clone())
        .header("Origin", format!("http://{api_address}"))
        .json(&json!({"management_entry":null,"public_ips":[]}))
        .send()
        .await
        .unwrap();
    assert_eq!(disabled.status(), 200);
    assert_eq!(
        no_redirect
            .get(format!("http://{http_address}/"))
            .header("Host", "manage.reverse.localhost")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    api_task.abort();
    api_task.await.ok();
    restarted.shutdown().await.unwrap();
    tls_task.abort();
    tls_task.await.ok();
    fs::remove_dir_all(root).unwrap();
}
