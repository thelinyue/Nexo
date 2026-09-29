use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn csr(key: &rcgen::KeyPair) -> String {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serialize_request(key).unwrap().pem().unwrap()
}

/// 两个真实 mTLS/Yamux 入口共用 Agent 身份；撤销其中一个不得取消另一个的存量流。
#[tokio::test]
async fn two_mtls_nodes_isolate_revocation_and_existing_streams() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let authority = identity::Authority::generate().unwrap();
    let agent_key = rcgen::KeyPair::generate().unwrap();
    let agent_cert = authority.issue_device(&csr(&agent_key), "agent").unwrap();
    let connector = TlsConnector::from(
        identity::client_config(&authority.ca_pem, &agent_cert, &agent_key.serialize_pem())
            .unwrap(),
    );
    let service: wire::Service = serde_json::from_value(json!({"id":"s","tenant":"default","device":"agent","revision":1,"protocol":"tcp","port":50001,"hostname":null,"https_port":443,"access_mode":"public","http_redirect":false,"certificate":null,"private_key":null})).unwrap();
    let mut runtimes = Vec::new();
    let mut tasks = JoinSet::new();
    let mut visitors = Vec::new();
    for _ in 0..2 {
        let id = format!("node-{}", Uuid::new_v4());
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = authority.issue_node(&csr(&key), &id).unwrap();
        let acceptor = TlsAcceptor::from(
            identity::node_server_config(&authority.ca_pem, &cert, &key.serialize_pem()).unwrap(),
        );
        let (snapshot, _) = watch::channel(Snapshot {
            data_port: 0,
            services: vec![service.clone()],
            agents: vec![wire::AgentIdentity {
                id: "agent".into(),
                certificates: vec![agent_cert.clone()],
            }],
            accepting: true,
        });
        let runtime = Arc::new(Runtime {
            snapshot,
            sessions: Default::default(),
            connections: Default::default(),
            health: Default::default(),
            access: Default::default(),
            configured: AtomicBool::new(false),
            stop: CancellationToken::new(),
            caddy: Default::default(),
        });
        let node = runtime.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tasks.spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _ = data_session(node, acceptor, socket).await;
        });
        let stream = connector
            .connect(
                rustls::pki_types::ServerName::try_from(id).unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        tasks.spawn(async move {
            let mut connection = nexo_tunnel::yamux_connection(stream, yamux::Mode::Client);
            let mut copies = JoinSet::new();
            loop {
                tokio::select! {
                    inbound = nexo_tunnel::next_inbound(&mut connection) => match inbound {
                        Ok(Some(stream)) => { copies.spawn(async move {
                            let mut stream = nexo_tunnel::into_tokio_io(stream);
                            let header = nexo_tunnel::read_logical_header(&mut stream).await.unwrap();
                            assert_eq!(header.tunnel_id, "s"); assert_eq!(header.revision, 1);
                            let (mut read, mut write) = tokio::io::split(stream);
                            let _ = tokio::io::copy(&mut read, &mut write).await;
                        }); },
                        _ => break,
                    },
                    _ = copies.join_next(), if !copies.is_empty() => {},
                }
            }
        });
        let sender = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(session) = runtime.sessions.lock().await.get("agent") {
                    break session.sender.clone();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let visitor = TcpStream::connect(public.local_addr().unwrap())
            .await
            .unwrap();
        let (socket, _) = public.accept().await.unwrap();
        sender
            .send(Open {
                service: service.clone(),
                socket,
                cancel: CancellationToken::new(),
            })
            .await
            .unwrap();
        visitors.push(visitor);
        runtimes.push(runtime);
    }
    for visitor in &mut visitors {
        visitor.write_all(b"ping").await.unwrap();
        let mut bytes = [0; 4];
        tokio::time::timeout(Duration::from_secs(3), visitor.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"ping");
    }
    runtimes[0].snapshot.send_replace(Snapshot::default());
    let result = tokio::time::timeout(Duration::from_secs(3), visitors[0].read(&mut [0; 4]))
        .await
        .unwrap();
    assert!(
        result.is_err() || result.unwrap() == 0,
        "撤权必须终止既有流"
    );
    visitors[1].write_all(b"live").await.unwrap();
    let mut bytes = [0; 4];
    tokio::time::timeout(Duration::from_secs(3), visitors[1].read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"live");
    assert_eq!(runtimes[1].connections.load(Ordering::Relaxed), 1);
}
