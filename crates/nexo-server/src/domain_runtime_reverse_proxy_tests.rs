use super::*;
use crate::{reverse_proxy, *};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    serde_json::from_value(json!({"service_mode":"reverse_proxy","name":"VPS 应用","protocol":"https","origin_protocol":origin,"local_address":"127.0.0.1","local_port":port,"hostname":"app","public_domain_id":"domain"})).unwrap()
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
    // localhost 由 Caddy 内部 CA 管理，无公网 DNS 或 ACME 副作用。
    state.db.lock().unwrap().execute("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES('domain','default','reverse.localhost',1,0,0)", []).unwrap();
    state.db.lock().unwrap().execute("INSERT INTO domain_settings(domain_id,certificate_mode,verified,verification_token) VALUES('domain','http01',1,'test-proof')", []).unwrap();
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
    // 独立测试预置内部 CA 证书；生产仍使用正常 HTTP-01 设置，不依赖缺失凭据的回退。
    let mut local_ca = build_config(&cfg, &[]).unwrap();
    local_ca["apps"]["tls"] = json!({"certificates":{"automate":["reverse.localhost","app.reverse.localhost"]},"automation":{"policies":[{"issuers":[{"module":"internal"}]}]}});
    supervisor.apply_json(&local_ca).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while read_certificates(&cfg.storage_root).len() < 2 {
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // HTTP-01 从 ACME 的存储命名空间加载已有证书；夹具复制内部 CA 证书，避免访问公共 CA。
    for host in ["reverse.localhost", "app.reverse.localhost"] {
        let source = cfg.storage_root.join("certificates/local").join(host);
        let target = cfg
            .storage_root
            .join("certificates/acme-v02.api.letsencrypt.org-directory")
            .join(host);
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
        .build()
        .unwrap();
    let url = format!("https://app.reverse.localhost:{}", https_address.port());
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
    // HTTP-01 的停用服务不会继续自动管理该主机证书；通过 HTTP 入口验证路由已撤销。
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
    let _ = delete_tunnel(State(state.clone()), headers, Path(proxy.id))
        .await
        .unwrap();
    // HTTP-01 的停用服务不会继续自动管理该主机证书；通过 HTTP 入口验证路由已撤销。
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
    restarted.shutdown().await.unwrap();
    tls_task.abort();
    tls_task.await.ok();
    fs::remove_dir_all(root).unwrap();
}
