//! 使用真实回环连接验证回源协议与证书边界，不修改机器信任库。
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn tunnel(port: u16, origin: &str) -> TunnelDesiredState {
    serde_json::from_value(serde_json::json!({
        "tunnel_id":"origin-test", "protocol":"https", "local_address":"127.0.0.1",
        "local_port":port, "origin_protocol":origin, "revision":1, "enabled":true,
    }))
    .unwrap()
}

#[tokio::test]
async fn edit_push_only_connects_changed_origins_and_periodic_checks_continue() {
    let unchanged = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let changed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first = tunnel(unchanged.local_addr().unwrap().port(), "http");
    let mut second = first.clone();
    second.tunnel_id = "changed-origin".into();
    let previous = vec![first.clone(), second.clone()];
    let mut entry_edit = first.clone();
    entry_edit.protocol = "http".into();
    entry_edit.hostname = Some("new".into());
    entry_edit.revision += 1;
    second.local_port = changed.local_addr().unwrap().port();
    second.revision += 1;
    let next = vec![entry_edit, second];
    let results = probe_tunnels(origin_checks(&previous, &next, false)).await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].tunnel_id, "changed-origin");
    assert!(results[0].applied);
    tokio::time::timeout(Duration::from_secs(1), changed.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), unchanged.accept())
            .await
            .is_err()
    );
    let results = probe_tunnels(origin_checks(&next, &next, true)).await;
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|result| result.applied));
    tokio::time::timeout(Duration::from_secs(1), unchanged.accept())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn disabled_edit_reports_without_connecting_and_tls_edits_are_checked() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old = tunnel(listener.local_addr().unwrap().port(), "https");
    let mut disabled = old.clone();
    disabled.enabled = false;
    let results = probe_tunnels(origin_checks(
        std::slice::from_ref(&old),
        &[disabled],
        false,
    ))
    .await;
    assert_eq!(results[0].status, "disabled");
    assert!(
        tokio::time::timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    let mut changed = old.clone();
    changed.origin_tls_verification = Some("custom_ca".into());
    let results = probe_tunnels(origin_checks(&[old], &[changed], false)).await;
    assert_eq!(results.len(), 1);
    assert!(!results[0].applied);
    assert!(results[0]
        .error_message
        .as_deref()
        .unwrap()
        .contains("自定义 CA"));
}

#[tokio::test]
async fn in_flight_origin_result_survives_entry_edit_but_rejects_changed_target() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let measured = tunnel(listener.local_addr().unwrap().port(), "http");
    let results = probe_tunnels(vec![measured.clone()]).await;
    let mut current = measured.clone();
    current.revision += 1;
    current.hostname = Some("new".into());
    current.protocol = "http".into();
    let reports = current_origin_reports(
        std::slice::from_ref(&measured),
        results.clone(),
        std::slice::from_ref(&current),
    );
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].revision, current.revision);
    assert!(reports[0].applied);
    current.local_address = "127.0.0.2".into();
    assert!(
        current_origin_reports(std::slice::from_ref(&measured), results.clone(), &[current])
            .is_empty()
    );
    assert!(current_origin_reports(&[measured], results, &[]).is_empty());
}

#[tokio::test]
async fn public_https_can_use_plain_http_origin() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let desired = tunnel(listener.local_addr().unwrap().port(), "http");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"GET ");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let mut stream = connect_origin(&desired).await.unwrap();
    stream.write_all(b"GET ").await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.ends_with("\r\n\r\nok"));
    server.await.unwrap();
}

#[tokio::test]
async fn https_origin_verifies_trust_and_ip_identity() {
    let key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &key);
    let server_key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .signed_by(&server_key, &issuer)
        .unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut desired = tunnel(listener.local_addr().unwrap().port(), "https");
    let server = tokio::spawn(async move {
        for _ in 0..4 {
            let (stream, _) = listener.accept().await.unwrap();
            if let Ok(mut stream) = acceptor.accept(stream).await {
                let mut request = [0; 4];
                if stream.read_exact(&mut request).await.is_ok() {
                    assert_eq!(&request, b"GET ");
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await
                        .unwrap();
                    stream.shutdown().await.unwrap();
                }
            }
        }
    });
    // 默认系统 CA 不信任临时自签 CA，必须明确失败。
    let error = connect_origin(&desired)
        .await
        .err()
        .expect("不可信证书不能连接成功");
    assert!(error.to_string().contains("证书验证失败"));
    // 用既有自定义 CA 能力为测试连接建立信任，不改动全局系统证书。
    desired.origin_tls_verification = Some("custom_ca".into());
    desired.origin_ca_pem = Some(ca.pem());
    let mut stream = connect_origin(&desired).await.unwrap();
    stream.write_all(b"GET ").await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.ends_with("\r\n\r\nok"));
    desired.origin_tls_server_name = Some("wrong.example.com".into());
    let error = connect_origin(&desired)
        .await
        .err()
        .expect("证书名称不匹配不能连接成功");
    assert!(error.to_string().contains("证书验证失败"));
    // 明确选择跳过验证时，不需要 CA，证书名称不匹配也只影响该服务。
    desired.origin_tls_verification = Some("insecure_skip_verify".into());
    desired.origin_ca_pem = None;
    let mut stream = connect_origin(&desired).await.unwrap();
    stream.write_all(b"GET ").await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.ends_with("\r\n\r\nok"));
    server.await.unwrap();
}

#[tokio::test]
async fn insecure_origin_accepts_expired_certificate_on_tls12_and_tls13() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["other.example.com".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        let config = rustls::ServerConfig::builder_with_protocol_versions(&[version])
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut desired = tunnel(listener.local_addr().unwrap().port(), "https");
        desired.origin_tls_verification = Some("custom_ca".into());
        desired.origin_ca_pem = Some(cert.pem());
        let server = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            for _ in 0..2 {
                let (socket, _) = listener.accept().await.unwrap();
                if let Ok(mut stream) = acceptor.accept(socket).await {
                    let mut data = [0; 4];
                    stream.read_exact(&mut data).await.unwrap();
                    assert_eq!(&data, b"ping");
                    stream.write_all(b"pong").await.unwrap();
                }
            }
        });
        assert!(connect_origin(&desired).await.is_err());
        desired.origin_tls_verification = Some("insecure_skip_verify".into());
        desired.origin_ca_pem = None;
        let mut stream = connect_origin(&desired).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut data = [0; 4];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"pong");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn insecure_origin_still_rejects_invalid_tls_handshake_signature() {
    #[derive(Debug)]
    struct WrongKeyResolver(Arc<rustls::sign::CertifiedKey>);
    impl rustls::server::ResolvesServerCert for WrongKeyResolver {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let cert_key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .self_signed(&cert_key)
            .unwrap();
        let wrong_key = KeyPair::generate().unwrap();
        let wrong_der =
            rustls::pki_types::PrivatePkcs8KeyDer::from(wrong_key.serialize_der()).into();
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&wrong_der).unwrap();
        // 故意让证书和签名密钥不一致，验证跳过身份检查不会跳过 TLS 握手签名检查。
        let certified = rustls::sign::CertifiedKey::new(vec![cert.der().clone()], signing_key);
        let config = rustls::ServerConfig::builder_with_protocol_versions(&[version])
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(WrongKeyResolver(Arc::new(certified))));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut desired = tunnel(listener.local_addr().unwrap().port(), "https");
        desired.origin_tls_verification = Some("insecure_skip_verify".into());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(socket)
                .await
                .is_err()
        });
        let error = connect_origin(&desired)
            .await
            .err()
            .expect("无效握手签名不能连接成功");
        assert!(
            format!("{error:#}")
                .to_ascii_lowercase()
                .contains("signature"),
            "{error:#}"
        );
        assert!(server.await.unwrap());
    }
}

#[tokio::test]
async fn insecure_origin_still_requires_a_tls_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut desired = tunnel(listener.local_addr().unwrap().port(), "https");
    desired.origin_tls_verification = Some("insecure_skip_verify".into());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = [0; 5];
        stream.read_exact(&mut hello).await.unwrap();
        assert_eq!(hello[0], 22, "客户端仍须先发送 TLS ClientHello");
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
    });
    let error = connect_origin(&desired)
        .await
        .err()
        .expect("明文 HTTP 不能冒充 HTTPS");
    assert!(error.to_string().contains("HTTPS 握手失败"));
    server.await.unwrap();
}

#[tokio::test]
async fn private_https_origin_supports_websocket_upgrade_and_frames() {
    let key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &key);
    let server_key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .signed_by(&server_key, &issuer)
        .unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut desired = tunnel(listener.local_addr().unwrap().port(), "https");
    desired.origin_tls_verification = Some("custom_ca".into());
    desired.origin_ca_pem = Some(ca.pem());
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
                assert!(request.len() < 4096);
            }
            assert!(String::from_utf8(request)
                .unwrap()
                .contains("Upgrade: websocket"));
            stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
            let mut frame = [0; 10];
            stream.read_exact(&mut frame).await.unwrap();
            assert_eq!(&frame, b"\x81\x84\x01\x02\x03\x04qkmc");
            stream.write_all(b"\x81\x04pong").await.unwrap();
        }
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        for mode in ["custom_ca", "insecure_skip_verify"] {
            desired.origin_tls_verification = Some(mode.into());
            if mode == "insecure_skip_verify" {
                desired.origin_ca_pem = None;
            }
            let mut stream = connect_origin(&desired).await.unwrap();
            stream.write_all(b"GET /console HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap();
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                response.push(stream.read_u8().await.unwrap());
                assert!(response.len() < 4096);
            }
            assert!(String::from_utf8(response).unwrap().contains("101 Switching Protocols"));
            stream.write_all(b"\x81\x84\x01\x02\x03\x04qkmc").await.unwrap();
            let mut frame = [0; 6];
            stream.read_exact(&mut frame).await.unwrap();
            assert_eq!(&frame, b"\x81\x04pong");
        }
        server.await.unwrap();
    }).await.expect("WebSocket 测试超时");
}

#[tokio::test]
async fn https_origin_accepts_explicitly_trusted_self_signed_certificate() {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut desired = tunnel(listener.local_addr().unwrap().port(), "https");
    desired.origin_tls_verification = Some("custom_ca".into());
    desired.origin_ca_pem = Some(cert.pem());
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await
            .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        connect_origin(&desired).await.unwrap();
        server.await.unwrap();
    })
    .await
    .expect("HTTPS 测试超时");
}
#[tokio::test]
async fn stream_compression_negotiates_and_falls_back_to_the_old_data_listener() {
    let dir = tempfile::tempdir().unwrap();
    let authority = identity::Authority::load_or_create(&dir.path().join("identity.json")).unwrap();
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(vec!["agent.nexo".into()])
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let cert = authority.issue_device(&csr, "agent").unwrap();
    let connector = TlsConnector::from(
        identity::client_config(&authority.ca_pem, &cert, &key.serialize_pem()).unwrap(),
    );
    for alpn in [nexo_tunnel::compression::ALPN, nexo_protocol::direct::ALPN] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = TunnelDataEndpoint {
            address: listener.local_addr().unwrap().to_string(),
            server_name: SERVER_NAME.into(),
        };
        let mut config = authority.server_config().unwrap();
        Arc::make_mut(&mut config).alpn_protocols = vec![alpn.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let expected = (alpn == nexo_tunnel::compression::ALPN).then_some(alpn);
        let server = tokio::spawn(async move {
            if expected.is_none() {
                let (first, _) = listener.accept().await.unwrap();
                assert!(acceptor.accept(first).await.is_err());
            }
            let (incoming, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(incoming).await.unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), expected);
        });
        let tls = connect_data_tls(&connector, &endpoint).await.unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), expected);
        server.await.unwrap();
    }
}
