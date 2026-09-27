use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn service(port: u16) -> Service {
    Service {
        hostname: "media.direct.test".into(),
        ipv6: "::1".into(),
        port,
        tunnel: TunnelDesiredState {
            tunnel_id: "media".into(),
            protocol: "https".into(),
            hostname: Some("media".into()),
            local_address: "127.0.0.1".into(),
            local_port: 8096,
            origin_protocol: Some("http".into()),
            origin_tls_server_name: None,
            origin_tls_verification: None,
            origin_ca_pem: None,
            revision: 1,
            enabled: true,
        },
    }
}
fn desired(service: &Service) -> Desired {
    Desired {
        endpoint: TunnelDataEndpoint {
            address: "127.0.0.1:9891".into(),
            server_name: "nexo-server".into(),
        },
        udp_endpoint: None,
        tunnels: vec![service.tunnel.clone()],
    }
}
#[test]
fn linux_addresses_exclude_temporary_deprecated_and_nonpublic() {
    let raw="20014860000000000000000000000001 02 40 00 80 eth0\n20014860000000000000000000000002 02 40 00 81 eth0\n20014860000000000000000000000003 02 40 00 a0 eth0\n20014860000000000000000000000004 02 40 00 c0 eth0\nfe800000000000000000000000000001 02 40 20 80 eth0\n20010db8000000000000000000000001 02 40 00 80 eth0";
    assert_eq!(parse_addresses(raw), vec!["2001:4860::1"]);
}
#[test]
fn local_key_survives_port_changes_and_corruption_is_not_overwritten() {
    let root = tempfile::tempdir().unwrap();
    let mut svc = service(9443);
    let first = key(root.path(), &svc).unwrap();
    svc.port = 8443;
    assert_eq!(first.key_pem, key(root.path(), &svc).unwrap().key_pem);
    fs::write(root.path().join("request.json"), "corrupt").unwrap();
    assert!(key(root.path(), &svc).is_err());
    assert_eq!(
        fs::read_to_string(root.path().join("request.json")).unwrap(),
        "corrupt"
    );
}

#[tokio::test]
async fn forwarder_closes_existing_stream_on_revision_change() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut svc = service(9443);
    svc.tunnel.local_port = listener.local_addr().unwrap().port();
    let (send, watch) = watch::channel(desired(&svc));
    let forward = Forwarder::start(&svc, watch).await.unwrap();
    let mut client = TcpStream::connect(&forward.address).await.unwrap();
    let (mut upstream, _) = listener.accept().await.unwrap();
    upstream.write_all(b"stream").await.unwrap();
    let mut data = [0; 6];
    client.read_exact(&mut data).await.unwrap();
    let mut next = desired(&svc);
    next.tunnels[0].revision += 1;
    send.send(next).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut data))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
}

#[tokio::test]
async fn direct_forwarder_verifies_https_origin_before_transferring_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut svc = service(9443);
    svc.tunnel.local_port = listener.local_addr().unwrap().port();
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![svc.hostname.clone()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    svc.tunnel.origin_protocol = Some("https".into());
    svc.tunnel.origin_tls_server_name = Some(svc.hostname.clone());
    svc.tunnel.origin_tls_verification = Some("custom_ca".into());
    svc.tunnel.origin_ca_pem = Some(cert.pem());
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        )
        .unwrap();
    let task = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        for _ in 0..2 {
            let (socket, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(socket).await {
                let mut bytes = [0; 4];
                tls.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"ping");
                tls.write_all(b"pong").await.unwrap();
            }
        }
    });
    let (_send, watch) = watch::channel(desired(&svc));
    let forward = Forwarder::start(&svc, watch).await.unwrap();
    let mut client = TcpStream::connect(&forward.address).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut bytes = [0; 4];
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"pong");
    svc.tunnel.origin_tls_server_name = Some("wrong.direct.test".into());
    assert!(
        connect_origin(&svc.tunnel).await.is_err(),
        "不可忽略回源 TLS 主机名不匹配"
    );
    task.await.unwrap();
}

#[tokio::test]
#[ignore = "需要 NEXO_TEST_CADDY_BIN；仅使用本地测试证书，不操作公网 DNS"]
async fn real_caddy_direct_range_upload_upgrade_authorization_and_revoke() {
    let binary = std::env::var_os("NEXO_TEST_CADDY_BIN").expect("测试 Caddy 路径");
    let root = tempfile::tempdir().unwrap();
    let reserve = std::net::TcpListener::bind("[::1]:0").unwrap();
    let port = reserve.local_addr().unwrap().port();
    drop(reserve);
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut svc = service(port);
    svc.tunnel.local_port = origin.local_addr().unwrap().port();
    let origin_task = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            let (mut socket, _) = origin.accept().await.unwrap();
            tasks.spawn(async move {
                let mut header=Vec::new();let mut byte=[0];
                while !header.ends_with(b"\r\n\r\n") {if socket.read_exact(&mut byte).await.is_err(){return;}header.push(byte[0]);}
                let header=String::from_utf8(header).unwrap();
                if header.starts_with("GET /ws ") {
                    socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
                    let (mut read,mut write)=socket.split();let _=tokio::io::copy(&mut read,&mut write).await;
                } else if header.starts_with("POST /upload ") {
                    let size:usize=header.lines().find_map(|l|l.to_ascii_lowercase().strip_prefix("content-length:").map(|v|v.trim().parse().unwrap())).unwrap();
                    let mut bytes=vec![0;size];socket.read_exact(&mut bytes).await.unwrap();assert!(bytes.iter().all(|b|*b==42));
                    socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nuploaded").await.unwrap();
                } else {
                    assert!(header.to_ascii_lowercase().contains("range: bytes=2-4"));
                    socket.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 2-4/10\r\nContent-Length: 3\r\nConnection: close\r\n\r\n234").await.unwrap();
                }
            });
        }
    });
    let (send, watch) = watch::channel(desired(&svc));
    let forward = Forwarder::start(&svc, watch).await.unwrap();
    let directory = root.path().join("media");
    fs::create_dir_all(&directory).unwrap();
    let saved = key(&directory, &svc).unwrap();
    let cert = CertificateParams::new(vec![svc.hostname.clone()])
        .unwrap()
        .self_signed(&KeyPair::from_pem(&saved.key_pem).unwrap())
        .unwrap();
    fs::write(directory.join("chain.pem"), cert.pem()).unwrap();
    let (sender, mut receiver) = mpsc::channel::<(Request, RpcReply)>(64);
    let denied = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let deny = denied.clone();
    let rpc = tokio::spawn(async move {
        while let Some((request, reply)) = receiver.recv().await {
            let Request::Access {
                service_id,
                revision,
                headers,
                body,
                ..
            } = request
            else {
                panic!("只允许认证流量")
            };
            assert_eq!(service_id, "media");
            assert_eq!(revision, 1);
            assert!(body.is_empty());
            assert!(headers.iter().any(|(k, v)| k == "x-nexo-access-authority"
                && v == &format!("media.direct.test:{port}")));
            let _ = reply.send(Ok(Response::Access {
                status: if deny.load(std::sync::atomic::Ordering::SeqCst) {
                    403
                } else {
                    204
                },
                headers: vec![("X-Nexo-Upstream-Cookie".into(), String::new())],
                body: vec![],
            }));
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth = listener.local_addr().unwrap().to_string();
    let access = Access {
        client: Client { sender },
        services: Arc::new(Mutex::new(HashMap::from([("media".into(), svc.clone())]))),
    };
    let auth_task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(authorize).with_state(access),
        )
        .await
        .unwrap();
    });
    let mut process = Process::start(root.path(), Path::new(&binary))
        .await
        .unwrap();
    let config = configuration(
        root.path(),
        &[(svc.clone(), forward.address.clone())],
        &auth,
    );
    process.apply(config.clone()).await.unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
        .resolve(&svc.hostname, format!("[::1]:{port}").parse().unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let base = format!("https://{}:{port}", svc.hostname);
    let response = client
        .get(format!("{base}/video"))
        .header("Range", "bytes=2-4")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 206);
    assert_eq!(response.headers()["content-range"], "bytes 2-4/10");
    assert_eq!(response.text().await.unwrap(), "234");
    assert_eq!(
        client
            .post(format!("{base}/upload"))
            .body(vec![42; 1024 * 1024])
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "uploaded"
    );
    let response = client
        .get(format!("{base}/ws"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 101);
    let mut upgraded = response.upgrade().await.unwrap();
    upgraded.write_all(b"ping").await.unwrap();
    let mut data = [0; 4];
    upgraded.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"ping");
    denied.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        client
            .get(format!("{base}/video"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .get(format!("{base}/video"))
            .header("Host", "unknown.direct.test")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    send.send(Desired {
        tunnels: vec![],
        ..desired(&svc)
    })
    .unwrap();
    let end = tokio::time::timeout(Duration::from_secs(3), upgraded.read(&mut data))
        .await
        .unwrap();
    assert!(matches!(end, Ok(0) | Err(_)));
    // JSON 不变时仍必须强制 Caddy 重读更新后的证书/私钥文件。
    let replacement_key = KeyPair::generate().unwrap();
    let replacement = CertificateParams::new(vec![svc.hostname.clone()])
        .unwrap()
        .self_signed(&replacement_key)
        .unwrap();
    fs::write(directory.join("key.pem"), replacement_key.serialize_pem()).unwrap();
    fs::write(directory.join("chain.pem"), replacement.pem()).unwrap();
    process.reload = true;
    process.apply(config.clone()).await.unwrap();
    let renewed = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(replacement.pem().as_bytes()).unwrap())
        .resolve(&svc.hostname, format!("[::1]:{port}").parse().unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    assert_eq!(
        renewed
            .get(format!("{base}/.nexo-direct/probe"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "media:1"
    );
    process.child.kill().await.unwrap();
    assert!(process.apply(config).await.is_err());
    rpc.abort();
    auth_task.abort();
    origin_task.abort();
}
