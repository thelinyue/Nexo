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
        for _ in 0..3 {
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
    server.await.unwrap();
}
