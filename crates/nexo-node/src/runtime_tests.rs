use super::*;
use std::sync::Mutex;

#[path = "../../test-support/echo_origin.rs"]
mod origin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn csr(key: &rcgen::KeyPair) -> String {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serialize_request(key).unwrap().pem().unwrap()
}

pub(super) struct Meter {
    policy: wire::NodeQuota,
    pub(super) used_bytes: u64,
    grants: HashMap<String, u64>,
}

impl Meter {
    fn set_limit(&mut self, limit: Option<u64>) {
        self.policy.revision += 1;
        self.policy.monthly_limit_bytes = limit;
        self.refresh();
    }

    fn refresh(&mut self) {
        self.policy.exhausted = self
            .policy
            .monthly_limit_bytes
            .is_some_and(|limit| self.used_bytes >= limit);
    }

    pub(super) fn reserved_bytes(&self) -> u64 {
        self.grants.values().sum()
    }
}

/// 通过与控制器相同的请求和响应测试节点的预算泵；持久账本由 Server 单测及真实进程烟测覆盖。
pub(super) async fn attach_meter(
    runtime: &Arc<Runtime>,
    service: &wire::Service,
) -> (Arc<Mutex<Meter>>, tokio::task::JoinHandle<()>) {
    let now = unix_now();
    let policy = wire::NodeQuota {
        revision: 1,
        period_start: now,
        period_end: now + 3600,
        monthly_limit_bytes: Some(10 * 1024 * 1024),
        exhausted: false,
    };
    runtime
        .snapshot
        .send_modify(|snapshot| snapshot.traffic_quota = Some(policy.clone()));
    let meter = Arc::new(Mutex::new(Meter {
        policy,
        used_bytes: 0,
        grants: HashMap::new(),
    }));
    let (sender, mut requests) = mpsc::channel::<Access>(32);
    let (reports, mut usage) = mpsc::unbounded_channel();
    *runtime.access.lock().await = Some(sender);
    *runtime.usage.lock().await = Some(reports);
    let controller = meter.clone();
    let service = service.clone();
    let snapshot = runtime.snapshot.clone();
    let task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        loop {
            tokio::select! {
                Some(call) = requests.recv() => {
                    let reply = match call.request {
                        wire::Request::Budget { request_id, service_id, service_revision, quota_revision, month, bytes } => {
                            let mut meter = controller.lock().unwrap();
                            assert_eq!(service_id, service.id);
                            assert_eq!(service_revision, service.revision);
                            assert_eq!(month, meter.policy.period_start);
                            let limit = meter.policy.monthly_limit_bytes.unwrap_or(u64::MAX);
                            let available = limit.saturating_sub(meter.used_bytes + meter.reserved_bytes());
                            let mut grant_id = String::new();
                            let bytes = if meter.policy.revision == quota_revision {
                                available.min(u64::from(bytes))
                            } else {
                                0
                            };
                            if bytes != 0 {
                                grant_id = Uuid::new_v4().to_string();
                                meter.grants.insert(grant_id.clone(), bytes);
                            }
                            wire::Response::Budget { request_id, grant_id, bytes }
                        }
                        _ => wire::Response::Access { request_id: 0, status: 403, headers: vec![], body: "测试拒绝访问".into() },
                    };
                    let _ = call.reply.send(reply);
                }
                Some(wire::Request::Usage { grant_id, to_origin, to_public, finished }) = usage.recv() => {
                    let mut meter = controller.lock().unwrap();
                    assert!(finished);
                    let reserved = meter.grants.remove(&grant_id).unwrap();
                    let used = to_origin + to_public;
                    assert!(used <= reserved);
                    meter.used_bytes += used;
                    meter.refresh();
                }
                _ = tick.tick() => {
                    let policy = Some(controller.lock().unwrap().policy.clone());
                    snapshot.send_if_modified(|state| {
                        if state.traffic_quota == policy { return false; }
                        state.traffic_quota = policy;
                        true
                    });
                }
            }
        }
    });
    (meter, task)
}

/// 两个真实 mTLS/Yamux 入口共用 Agent 身份；撤销其中一个不得取消另一个的存量流。
#[tokio::test]
async fn two_mtls_nodes_isolate_revocation_and_existing_streams() {
    mtls_scenario(false).await;
}
#[tokio::test]
async fn metered_mtls_nodes_count_both_directions_and_isolate_revocation() {
    mtls_scenario(true).await;
}
async fn mtls_scenario(metered: bool) {
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
    let mut meters = Vec::new();
    for _ in 0..2 {
        let id = format!("node-{}", Uuid::new_v4());
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = authority.issue_node(&csr(&key), &id).unwrap();
        let acceptor = TlsAcceptor::from(
            identity::node_server_config(&authority.ca_pem, &cert, &key.serialize_pem()).unwrap(),
        );
        let (snapshot, _) = watch::channel(Snapshot {
            traffic_quota: None,
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
            analytics: Default::default(),
            sessions: Default::default(),
            connections: Default::default(),
            health: Default::default(),
            access: Default::default(),
            usage: Default::default(),
            configured: AtomicBool::new(false),
            stop: CancellationToken::new(),
            caddy: Default::default(),
        });
        if metered {
            let (state, task) = attach_meter(&runtime, &service).await;
            meters.push(state);
            tasks.spawn(async move {
                let _ = task.await;
            });
        }
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
        let session = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(session) = runtime.sessions.lock().await.get("agent") {
                    break session.clone();
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
        session
            .open(&service, socket, &CancellationToken::new())
            .await;
        visitors.push(visitor);
        runtimes.push(runtime);
    }
    for (visitor, runtime) in visitors.iter_mut().zip(&runtimes) {
        visitor.write_all(b"ping").await.unwrap();
        let mut bytes = [0; 4];
        tokio::time::timeout(Duration::from_secs(3), visitor.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"ping");
        assert_eq!(
            runtime.sessions.lock().await["agent"]
                .permits
                .available_permits(),
            nexo_tunnel::FORWARDING_SLOTS - 1,
            "已建立的节点转发仍应持有名额"
        );
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
    if metered {
        tokio::time::sleep(Duration::from_millis(350)).await;
        assert_eq!(meters[1].lock().unwrap().used_bytes, 16);
        assert_eq!(meters[0].lock().unwrap().used_bytes, 8);
    }
}

/// 独立节点的真实 Caddy 在没有任何 Agent 会话时直接回源，并验证入口撤销和 TLS。
#[tokio::test]
#[ignore = "需要 NEXO_CADDY_BINARY；只访问本机"]
async fn real_caddy_node_reverse_proxy_without_agent_tls_websocket_and_revocation() {
    proxy_scenario(false).await;
}
#[tokio::test]
#[ignore = "需要 NEXO_CADDY_BINARY；只访问本机"]
async fn real_caddy_metered_proxy_tls_websocket_exhaustion_and_recovery() {
    proxy_scenario(true).await;
}
async fn proxy_scenario(metered: bool) {
    let port = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let http_port = port();
    let https_port = port();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        loop {
            let (stream, _) = origin.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = origin::echo_origin(stream, "node-origin").await;
            });
        }
    });
    let key = rcgen::KeyPair::generate().unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["app.localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let service:wire::Service=serde_json::from_value(json!({"id":"proxy","tenant":"default","device":"","revision":1,"protocol":"https","port":0,"hostname":"app.localhost","http_port":http_port,"https_port":https_port,"access_mode":"public","http_redirect":true,"certificate":certificate.pem(),"private_key":key.serialize_pem(),"reverse_proxy_target":format!("http://127.0.0.1:{origin_port}")})).unwrap();
    let (snapshot, _) = watch::channel(Snapshot {
        traffic_quota: None,
        data_port: 0,
        services: vec![service.clone()],
        agents: vec![],
        accepting: true,
    });
    let runtime = Arc::new(Runtime {
        snapshot,
        analytics: Default::default(),
        sessions: Default::default(),
        connections: Default::default(),
        health: Default::default(),
        access: Default::default(),
        usage: Default::default(),
        configured: AtomicBool::new(false),
        stop: CancellationToken::new(),
        caddy: Default::default(),
    });
    let meter = if metered {
        let (state, task) = attach_meter(&runtime, &service).await;
        tasks.spawn(async move {
            task.await?;
            anyhow::Ok(())
        });
        Some(state)
    } else {
        None
    };
    let directory = tempfile::tempdir().unwrap();
    let node = runtime.clone();
    tasks.spawn(listeners(
        node,
        directory.path().to_owned(),
        "test-node".into(),
    ));
    let client = nexo_core::http_client_builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_backend_rustls()
        .tls_certs_only([reqwest::Certificate::from_pem(certificate.pem().as_bytes()).unwrap()])
        .resolve(
            "app.localhost",
            (std::net::Ipv4Addr::LOCALHOST, https_port).into(),
        )
        .build()
        .unwrap();
    let base = format!("https://app.localhost:{https_port}");
    let result:Result<()>=async {
        tokio::time::timeout(Duration::from_secs(20),async {
            loop {
                if runtime.health.lock().await.iter().any(|s|s.id=="proxy"&&s.ready) {break;}
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await?;
        anyhow::ensure!(runtime.sessions.lock().await.is_empty(),"反代不得依赖 Agent");
        let response=client.post(format!("{base}/path/a%2Fb?q=%2F")).header("X-Nexo-Access-Forged","secret").body("original-body").send().await?;
        anyhow::ensure!(response.status()==200,"反代请求失败");
        let echo=response.text().await?;
        anyhow::ensure!(echo.contains("POST /path/a%2Fb?q=%2F") && echo.contains("original-body"),"原请求未保留");
        anyhow::ensure!(echo.contains(&format!("app.localhost:{https_port}")) && !echo.to_lowercase().contains("x-nexo-access-forged"),"Host 或认证头边界不正确");
        let redirected=client.post(format!("http://127.0.0.1:{http_port}/path?q=1")).header("Host","app.localhost").send().await?;
        anyhow::ensure!(redirected.status()==307 && redirected.headers()["location"]==format!("{base}/path?q=1"),"HTTPS 跳转未保留请求地址");
        // 真实 WebSocket 握手和双向数据；TLS 在前一个请求中已验证。
        let mut plain=service.clone();plain.protocol="http".into();plain.http_redirect=false;
        runtime.configured.store(false,Ordering::Release);
        let quota_policy=runtime.snapshot.borrow().traffic_quota.clone();
        runtime.snapshot.send_replace(Snapshot { traffic_quota: quota_policy,services:vec![plain.clone()],agents:vec![],data_port:0,accepting:true});
        tokio::time::timeout(Duration::from_secs(5),async {loop {if runtime.configured.load(Ordering::Acquire) {break;}tokio::time::sleep(Duration::from_millis(25)).await;}}).await?;
        let mut socket=TcpStream::connect(("127.0.0.1",http_port)).await?;
        socket.write_all(b"GET /ws HTTP/1.1\r\nHost: app.localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await?;
        let mut head=Vec::new();while !head.ends_with(b"\r\n\r\n") {head.push(socket.read_u8().await?);}
        anyhow::ensure!(String::from_utf8(head)?.contains("101"),"WebSocket 握手失败");
        socket.write_all(&[0x81,0x84,0,0,0,0,b'p',b'i',b'n',b'g']).await?;
        let mut frame=[0;6];socket.read_exact(&mut frame).await?;
        anyhow::ensure!(&frame[2..]==b"ping","WebSocket 数据未回显");
        drop(socket);
        if let Some(meter)=&meter {
            tokio::time::sleep(Duration::from_millis(350)).await;
            let used=meter.lock().unwrap().used_bytes;
            anyhow::ensure!(used>0,"反向代理未计量");
            let limit=used+1_500_000;
            meter.lock().unwrap().set_limit(Some(limit));
            tokio::time::timeout(Duration::from_secs(3),async {loop {if runtime.snapshot.borrow().traffic_quota.as_ref().is_some_and(|q|q.revision==2){break;}tokio::time::sleep(Duration::from_millis(20)).await;}}).await?;
            let response=client.post(format!("http://127.0.0.1:{http_port}/large")).header("Host","app.localhost").body("x".repeat(1_048_576)).send().await;
            anyhow::ensure!(response.is_err() || response.unwrap().bytes().await.is_err(),"超额长下载没有中断");
            tokio::time::timeout(Duration::from_secs(5),async {loop {if meter.lock().unwrap().policy.exhausted{break;}tokio::time::sleep(Duration::from_millis(20)).await;}}).await.context("等待节点额度用尽超时")?;
            {
                let meter = meter.lock().unwrap();
                anyhow::ensure!(meter.used_bytes == limit && meter.reserved_bytes() == 0, "节点额度超支或结算不完整");
            }
            anyhow::ensure!(client.get(format!("http://127.0.0.1:{http_port}/")).header("Host","app.localhost").send().await?.status().is_server_error(),"用尽后仍允许新请求");
            meter.lock().unwrap().set_limit(None);
            tokio::time::timeout(Duration::from_secs(3),async {loop {if runtime.snapshot.borrow().traffic_quota.as_ref().is_some_and(|q|q.revision==3){break;}tokio::time::sleep(Duration::from_millis(20)).await;}}).await?;
            anyhow::ensure!(client.get(format!("http://127.0.0.1:{http_port}/")).header("Host","app.localhost").send().await?.status()==200,"解除额度没有恢复入口");
        }
        // 自签名 HTTPS 回源必须拒绝，不能为了节点直连关闭证书校验。
        let mut tls_origin=service.clone();tls_origin.id="tls-origin".into();tls_origin.http_redirect=false;
        plain.reverse_proxy_target=Some(format!("https://127.0.0.1:{https_port}"));
        runtime.configured.store(false,Ordering::Release);
        let quota_policy=runtime.snapshot.borrow().traffic_quota.clone();
        runtime.snapshot.send_replace(Snapshot { traffic_quota: quota_policy,services:vec![plain,tls_origin],agents:vec![],data_port:0,accepting:true});
        tokio::time::timeout(Duration::from_secs(5),async {loop {if runtime.configured.load(Ordering::Acquire) {break;}tokio::time::sleep(Duration::from_millis(25)).await;}}).await?;
        anyhow::ensure!(client.get(format!("http://127.0.0.1:{http_port}/")).header("Host","app.localhost").send().await?.status().is_server_error(),"不应信任未验证的 HTTPS 回源");
        // 新证书损坏使 Caddy 保留旧配置时，旧入口仍必须按最新快照拒绝业务请求。
        let mut invalid=service.clone();invalid.id="invalid".into();invalid.hostname=Some("invalid.localhost".into());invalid.certificate=Some("invalid certificate".into());invalid.private_key=Some("invalid key".into());
        runtime.configured.store(false,Ordering::Release);
        let quota_policy=runtime.snapshot.borrow().traffic_quota.clone();
        runtime.snapshot.send_replace(Snapshot { traffic_quota: quota_policy,services:vec![invalid],agents:vec![],data_port:0,accepting:true});
        tokio::time::timeout(Duration::from_secs(5),async {loop {if runtime.health.lock().await.iter().any(|s|s.id=="invalid"&&!s.ready) {break;}tokio::time::sleep(Duration::from_millis(25)).await;}}).await?;
        anyhow::ensure!(client.get(format!("http://127.0.0.1:{http_port}/")).header("Host","app.localhost").send().await?.status().is_server_error(),"Caddy 配置失败后不应沿用已撤销的业务授权");
        runtime.configured.store(false,Ordering::Release);
        runtime.snapshot.send_replace(Snapshot::default());
        tokio::time::timeout(Duration::from_secs(5),async {loop {if runtime.health.lock().await.is_empty() && runtime.configured.load(Ordering::Acquire) {break;}tokio::time::sleep(Duration::from_millis(25)).await;}}).await?;
        let revoked=client.get(format!("http://127.0.0.1:{http_port}/")).header("Host","app.localhost").send().await;
        anyhow::ensure!(revoked.is_err() || revoked.unwrap().status()!=200,"撤权后仍在转发");
        Ok(())
    }.await;
    runtime.stop.cancel();
    if let Some(caddy) = runtime.caddy.lock().await.take() {
        caddy.shutdown().await.unwrap();
    }
    tasks.abort_all();
    result.unwrap();
}
