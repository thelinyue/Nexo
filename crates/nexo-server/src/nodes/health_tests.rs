use super::*;
use axum::{
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
    routing::get,
    Router,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const HOST: &str = "relay.probe.test";

fn target(kind: &str) -> Target {
    Target {
        node: "node-a".into(),
        address: "127.0.0.1".into(),
        kind: kind.into(),
    }
}

fn body() -> String {
    json!({"node_id":"node-a","service_id":"service","revision":1}).to_string()
}

async fn http_server(status: StatusCode, body: String) -> (u16, tokio::task::JoinHandle<()>) {
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let app = Router::new().route(
        PROBE_PATH,
        get(move |headers: HeaderMap, uri: Uri| {
            let body = body.clone();
            async move {
                assert_eq!(headers["host"], format!("{HOST}:{port}"));
                assert_eq!(uri.path(), PROBE_PATH);
                (status, [("location", "/business")], body).into_response()
            }
        }),
    );
    let task = tokio::spawn(async move {
        axum::serve(socket, app).await.unwrap();
    });
    (port, task)
}

#[tokio::test]
async fn http_checks_host_identity_status_and_body_limit() {
    let (port, task) = http_server(StatusCode::OK, body()).await;
    probe(&target("http"), HOST, port, "service", 1)
        .await
        .unwrap();
    for (node, service, revision) in [
        ("wrong", "service", 1),
        ("node-a", "wrong", 1),
        ("node-a", "service", 2),
    ] {
        let mut checked = target("http");
        checked.node = node.into();
        assert!(probe(&checked, HOST, port, service, revision)
            .await
            .unwrap_err()
            .to_string()
            .contains("不匹配"));
    }
    task.abort();
    for (status, content) in [
        (StatusCode::FOUND, body()),
        (StatusCode::UNAUTHORIZED, body()),
        (StatusCode::NOT_FOUND, body()),
        (StatusCode::INTERNAL_SERVER_ERROR, body()),
        (StatusCode::OK, "x".repeat(1025)),
        (StatusCode::OK, "{}".into()),
    ] {
        let (port, task) = http_server(status, content).await;
        assert!(probe(&target("http"), HOST, port, "service", 1)
            .await
            .is_err());
        task.abort();
    }
}

#[tokio::test]
async fn tls_requires_a_trusted_certificate_for_the_business_hostname() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let generated = rcgen::generate_simple_self_signed(vec![HOST.into()]).unwrap();
    let root = reqwest::Certificate::from_pem(generated.cert.pem().as_bytes()).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![generated.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = socket.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(socket).await {
                    let mut request = [0; 4096];
                    if stream.read(&mut request).await.is_ok() {
                        let body = body();
                        let response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                }
            });
        }
    });
    probe_with_roots(
        &target("https"),
        HOST,
        port,
        "service",
        1,
        std::slice::from_ref(&root),
    )
    .await
    .unwrap();
    assert!(probe(&target("https"), HOST, port, "service", 1)
        .await
        .is_err());
    assert!(probe_with_roots(
        &target("https"),
        "other.probe.test",
        port,
        "service",
        1,
        &[root]
    )
    .await
    .is_err());
    task.abort();
}

#[tokio::test]
async fn tcp_acceptance_does_not_imply_http_or_tls_health() {
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = socket.accept().await {
            drop(stream);
        }
    });
    probe(&target("tcp"), HOST, port, "service", 1)
        .await
        .unwrap();
    assert!(probe(&target("http"), HOST, port, "service", 1)
        .await
        .is_err());
    assert!(probe(&target("https"), HOST, port, "service", 1)
        .await
        .is_err());
    task.abort();
}

#[tokio::test]
async fn a_stalled_response_is_bounded_by_the_total_timeout() {
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = socket.accept().await.unwrap();
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).await.unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n{")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
    let started = tokio::time::Instant::now();
    assert!(probe(&target("http"), HOST, port, "service", 1)
        .await
        .is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
    task.abort();
}

#[test]
fn recovery_failure_and_changes_reset_public_samples() {
    let (state, _) = crate::tests::domain_fixture();
    let db = state.db.lock().unwrap();
    db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('service','default','service','tcp','127.0.0.1',80,0,0)",[]).unwrap();
    let now = unix_now();
    let healthy = || {
        db.query_row(
            "SELECT healthy FROM relay_public_health WHERE service_id='service'",
            [],
            |r| r.get::<_, bool>(0),
        )
        .unwrap()
    };
    let mut checked = target("tcp");
    for i in 0..3 {
        record(&db, &checked, "service", 1, None, now + i).unwrap();
        assert_eq!(healthy(), i == 2);
    }
    for i in 0..3 {
        record(&db, &checked, "service", 1, Some("连接失败"), now + 3 + i).unwrap();
        assert_eq!(healthy(), i < 2);
    }
    for (kind, address, revision, time) in [
        ("http", "127.0.0.1", 1, now + 6),
        ("http", "127.0.0.2", 1, now + 9),
        ("http", "127.0.0.2", 2, now + 12),
        ("http", "127.0.0.2", 2, now + 90),
    ] {
        checked.kind = kind.into();
        checked.address = address.into();
        for i in 0..3 {
            record(&db, &checked, "service", revision, None, time + i).unwrap();
            assert_eq!(healthy(), i == 2);
        }
    }
}

#[test]
fn legacy_report_and_additive_migration_preserve_identity() {
    let old: nexo_protocol::nodes::ServiceHealth =
        serde_json::from_value(json!({"id":"s","revision":1,"ready":true,"error":null})).unwrap();
    assert!(!old.public_probe_supported);
    let (state, _) = crate::tests::domain_fixture();
    let db = state.db.lock().unwrap();
    db.execute(
        "UPDATE relay_nodes SET certificate_pem='preserved-node-identity' WHERE id='local'",
        [],
    )
    .unwrap();
    db.execute_batch("DROP VIEW relay_healthy_service_nodes; DROP VIEW relay_ready_service_nodes; ALTER TABLE relay_service_health DROP COLUMN public_probe_supported; ALTER TABLE relay_public_health DROP COLUMN probe_kind; ALTER TABLE relay_public_health DROP COLUMN address; ALTER TABLE relay_public_health DROP COLUMN error;").unwrap();
    super::super::migrate(&db).unwrap();
    super::super::migrate(&db).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT certificate_pem FROM relay_nodes WHERE id='local'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        "preserved-node-identity"
    );
    assert!(db
        .prepare("SELECT public_probe_supported FROM relay_service_health")
        .is_ok());
    assert!(db
        .prepare("SELECT probe_kind,address,error FROM relay_public_health")
        .is_ok());
}
