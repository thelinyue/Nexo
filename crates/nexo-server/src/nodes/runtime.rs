//! 原生 VPS 数据面。仅内存持有控制器授权快照；冷启动及失联均不会从旧磁盘配置开放业务。
use super::*;
use futures_util::StreamExt;
use nexo_protocol::nodes::{self as wire, Snapshot};
use nexo_tunnel::{identity, LogicalStreamHeader};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch, Mutex as AsyncMutex},
    task::JoinSet,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::{
    codec::{FramedRead, LinesCodec},
    sync::CancellationToken,
};

#[derive(serde::Serialize, Deserialize)]
struct NodeIdentity {
    server_url: String,
    id: String,
    certificate: String,
    ca: String,
    key: String,
    control_endpoint: String,
    data_port: u16,
}
struct Open {
    service: wire::Service,
    socket: TcpStream,
    cancel: CancellationToken,
}
#[derive(Clone)]
struct Session {
    public_ipv4: Option<Ipv4Addr>,
    sender: mpsc::Sender<Open>,
    cancel: CancellationToken,
}
/// 所有监听和会话受同一个快照约束；更新配置会取消旧服务的已有连接。
struct Runtime {
    snapshot: watch::Sender<Snapshot>,
    sessions: AsyncMutex<HashMap<String, Session>>,
    connections: Arc<AtomicU64>,
    health: AsyncMutex<Vec<wire::ServiceHealth>>,
    access: AsyncMutex<Option<mpsc::Sender<Access>>>,
    configured: AtomicBool,
    stop: CancellationToken,
    caddy: AsyncMutex<Option<Arc<crate::caddy::CaddySupervisor>>>,
}
struct Access {
    request: wire::Request,
    reply: tokio::sync::oneshot::Sender<wire::Response>,
}
struct Listener {
    service: wire::Service,
    cancel: CancellationToken,
    port: u16,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

pub async fn run(
    directory: PathBuf,
    server_url: Option<String>,
    enroll: bool,
    enroll_only: bool,
) -> Result<()> {
    let path = directory.join("node-identity.json");
    let identity: NodeIdentity = if path.exists() {
        serde_json::from_slice(&fs::read(&path)?)?
    } else {
        anyhow::ensure!(enroll, "请先使用一键安装命令接入节点");
        let server_url = server_url.context("首次接入缺少 --server-url")?;
        let url = reqwest::Url::parse(&server_url)?;
        anyhow::ensure!(
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "管理地址必须是 HTTPS，不得包含凭据或查询参数"
        );
        let mut token = String::new();
        std::io::stdin().read_line(&mut token)?;
        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&key)?.pem()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let response = client
            .post(format!(
                "{}/api/v1/node/register",
                server_url.trim_end_matches('/')
            ))
            .json(&wire::Register {
                token: token.trim().into(),
                csr,
            })
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "节点注册失败（HTTP {}），请检查接入凭证与管理地址",
            response.status()
        );
        let registered: wire::Registered = response.json().await?;
        let result = NodeIdentity {
            server_url,
            id: registered.id,
            certificate: registered.certificate,
            ca: registered.ca,
            key: key.serialize_pem(),
            control_endpoint: registered.control_endpoint,
            data_port: registered.data_port,
        };
        identity::node_server_config(&result.ca, &result.certificate, &result.key)?;
        identity::write_private_file(&path, &serde_json::to_vec(&result)?)?;
        result
    };
    if enroll_only {
        return Ok(());
    }
    let identity = Arc::new(identity);
    let (snapshot, _) = watch::channel(Snapshot::default());
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
    let mut tasks = JoinSet::new();
    tasks.spawn(control(runtime.clone(), identity.clone()));
    tasks.spawn(data(runtime.clone(), identity.clone()));
    tasks.spawn(listeners(runtime.clone(), directory, identity.id.clone()));
    let health = runtime.clone();
    let instance = uuid::Uuid::new_v4().to_string();
    tasks.spawn(async move {
        let socket = TcpListener::bind("127.0.0.1:8282").await?;
        axum::serve(
            socket,
            Router::new().route(
                "/health",
                get(move || {
                    let r = health.clone();
                    let instance = instance.clone();
                    async move {
                        let ready = r.configured.load(Ordering::Acquire)
                            && r.access.lock().await.is_some()
                            && r.health.lock().await.iter().all(|s| s.ready)
                            && r.caddy.lock().await.is_some();
                        (
                            if ready {
                                StatusCode::OK
                            } else {
                                StatusCode::SERVICE_UNAVAILABLE
                            },
                            axum::Json(
                                json!({"version":env!("CARGO_PKG_VERSION"),"instance":instance}),
                            ),
                        )
                    }
                }),
            ),
        )
        .await?;
        anyhow::Ok(())
    });
    let result = tokio::select! {
        _=crate::shutdown_signal()=>Ok(()),
        result=tasks.join_next()=>match result {Some(Ok(result))=>result,Some(Err(error))=>Err(error.into()),None=>Err(anyhow::anyhow!("节点任务为空"))}
    };
    runtime.snapshot.send_replace(Snapshot::default());
    runtime.stop.cancel();
    if let Some(caddy) = runtime.caddy.lock().await.take() {
        if let Err(error) = caddy.shutdown().await {
            tracing::warn!("节点 Caddy 关闭未完成：{error:#}");
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}
async fn control(runtime: Arc<Runtime>, identity: Arc<NodeIdentity>) -> Result<()> {
    loop {
        let result = control_session(&runtime, &identity).await;
        // 不复用上一条管理连接的授权；管理通道恢复后重新下发完整快照。
        runtime.configured.store(false, Ordering::Release);
        runtime.snapshot.send_replace(Snapshot::default());
        *runtime.access.lock().await = None;
        if let Err(error) = result {
            tracing::warn!("节点管理连接中断，将重新连接：{error:#}");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
async fn control_session(runtime: &Arc<Runtime>, saved: &NodeIdentity) -> Result<()> {
    let tls = TlsConnector::from(identity::client_config(
        &saved.ca,
        &saved.certificate,
        &saved.key,
    )?);
    let socket = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&saved.control_endpoint),
    )
    .await??;
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        tls.connect(
            rustls::pki_types::ServerName::try_from(identity::SERVER_NAME.to_owned())?,
            socket,
        ),
    )
    .await??;
    let (read, mut write) = tokio::io::split(stream);
    let mut lines = FramedRead::new(
        read,
        LinesCodec::new_with_max_length(identity::MAX_CONTROL_FRAME),
    );
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    let (sender, mut access) = mpsc::channel::<Access>(32);
    *runtime.access.lock().await = Some(sender);
    let mut requests = HashMap::new();
    let mut sequence = 0u64;
    let deadline = tokio::time::sleep(Duration::from_secs(45));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _=&mut deadline=>anyhow::bail!("管理 Server 45 秒未响应，停止转发"),
            Some(mut call)=access.recv()=>{
                sequence=sequence.wrapping_add(1);
                if let wire::Request::Access{request_id,..}=&mut call.request{*request_id=sequence;}
                requests.retain(|_,reply:&mut tokio::sync::oneshot::Sender<wire::Response>|!reply.is_closed());
                if requests.len()>=64{continue;}
                tokio::time::timeout_at(deadline.deadline(), identity::write_message(&mut write,&call.request)).await.context("节点管理通道发送超时，停止转发")??;
                requests.insert(sequence,call.reply);
            },
            _=interval.tick()=>{
                let services=runtime.health.lock().await.clone();
                tokio::time::timeout_at(deadline.deadline(), identity::write_message(&mut write,&wire::Request::Poll{version:env!("CARGO_PKG_VERSION").into(),os:operating_system(),architecture:std::env::consts::ARCH.into(),connections:runtime.connections.load(Ordering::Relaxed),services,update:update_report()})).await.context("节点管理通道发送超时，停止转发")??;
            },
            line=lines.next()=>{
                let line=line.context("管理连接关闭")??;
                deadline.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(45));
                match serde_json::from_str::<wire::Response>(&line)?{
                    wire::Response::State{snapshot,command}=>{if let Some(command)=command{submit_update(command)?;}runtime.snapshot.send_if_modified(|old|if *old!=snapshot{runtime.configured.store(false,Ordering::Release);*old=snapshot;true}else{false});},
                    wire::Response::Error{message}=>anyhow::bail!("控制器拒绝：{message}"),
                    response@wire::Response::Access{request_id,..}=>{if let Some(reply)=requests.remove(&request_id){let _=reply.send(response);}},
                }
            }
        }
    }
}
async fn data(runtime: Arc<Runtime>, saved: Arc<NodeIdentity>) -> Result<()> {
    let mut listener = TcpListener::bind(("0.0.0.0", saved.data_port))
        .await
        .context("节点数据端口被占用")?;
    let acceptor = TlsAcceptor::from(identity::node_server_config(
        &saved.ca,
        &saved.certificate,
        &saved.key,
    )?);
    let mut tasks = JoinSet::new();
    let mut snapshot = runtime.snapshot.subscribe();
    loop {
        tokio::select! {
            change=snapshot.changed()=>{
                change?;let port=snapshot.borrow_and_update().data_port;
                if port!=0 && port!=listener.local_addr()?.port(){listener=TcpListener::bind(("0.0.0.0",port)).await.context("新的节点数据端口被占用")?;}
            },
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            incoming=listener.accept()=>{
                let (socket,_)=incoming?;let acceptor=acceptor.clone();let runtime=runtime.clone();
                tasks.spawn(async move{if let Err(error)=data_session(runtime,acceptor,socket).await{tracing::debug!("节点 Agent 连接结束：{error:#}");}});
            }
        }
    }
}
fn agent_for(snapshot: &Snapshot, cert: &[u8]) -> Option<String> {
    snapshot
        .agents
        .iter()
        .find(|agent| {
            agent.certificates.iter().any(|pem| {
                identity::certificates(pem)
                    .is_ok_and(|chain| chain.first().is_some_and(|v| v.as_ref() == cert))
            })
        })
        .map(|v| v.id.clone())
}
async fn data_session(
    runtime: Arc<Runtime>,
    acceptor: TlsAcceptor,
    socket: TcpStream,
) -> Result<()> {
    let public_ipv4 = match socket.peer_addr()?.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped(),
    };
    nexo_tunnel::configure_tunnel_tcp_keepalive(&socket)?;
    let stream = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket)).await??;
    let cert = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|v| v.first())
        .context("缺少 Agent 证书")?
        .as_ref()
        .to_vec();
    let mut snapshot = runtime.snapshot.subscribe();
    let device = agent_for(&snapshot.borrow(), &cert).context("Agent 未获此节点授权")?;
    let (sender, mut receiver) = mpsc::channel::<Open>(nexo_tunnel::DEFAULT_MAX_STREAMS);
    let cancel = CancellationToken::new();
    if let Some(old) = runtime.sessions.lock().await.insert(
        device.clone(),
        Session {
            public_ipv4,
            sender: sender.clone(),
            cancel: cancel.clone(),
        },
    ) {
        old.cancel.cancel();
    }
    let mut connection = nexo_tunnel::yamux_connection(stream, yamux::Mode::Server);
    let mut copies = JoinSet::new();
    let result:Result<()>=async{loop{tokio::select!{
        _=cancel.cancelled()=>break,
        changed=snapshot.changed()=>{changed?;anyhow::ensure!(agent_for(&snapshot.borrow(),&cert).as_deref()==Some(&device),"Agent 授权已撤销");},
        Some(_)=copies.join_next(),if !copies.is_empty()=>{},
        request=receiver.recv()=>{
            let Some(mut request)=request else{break;};
            if request.cancel.is_cancelled()||!snapshot.borrow().services.contains(&request.service){continue;}
            let stream=tokio::time::timeout(Duration::from_secs(10),nexo_tunnel::new_outbound(&mut connection)).await??;
            let count=runtime.connections.clone();count.fetch_add(1,Ordering::Relaxed);
            copies.spawn(async move{
                struct Count(Arc<AtomicU64>);impl Drop for Count{fn drop(&mut self){self.0.fetch_sub(1,Ordering::Relaxed);}}
                let _count=Count(count);let mut stream=nexo_tunnel::into_tokio_io(stream);
                let transfer=async{
                    nexo_tunnel::write_logical_header(&mut stream,&LogicalStreamHeader::new(&request.service.id,Uuid::new_v4().to_string(),request.service.revision)?).await?;
                    tokio::io::copy_bidirectional(&mut stream,&mut request.socket).await?;anyhow::Ok(())
                };
                tokio::select!{_=request.cancel.cancelled()=>{},result=transfer=>if let Err(error)=result{tracing::debug!("节点转发结束：{error:#}");}}
            });
        },
        inbound=nexo_tunnel::next_inbound(&mut connection)=>match inbound?{None=>break,Some(stream)=>{
            copies.spawn(async move{
                let mut stream=nexo_tunnel::into_tokio_io(stream);
                if let Ok(Ok(header))=tokio::time::timeout(Duration::from_secs(3),nexo_tunnel::read_logical_header(&mut stream)).await{
                    if header.tunnel_id=="node-probe"&&header.revision==1{let _=tokio::io::AsyncWriteExt::write_all(&mut stream,&[1]).await;}
                }
            });
        }}
    }}Ok(())}.await;
    copies.abort_all();
    while copies.join_next().await.is_some() {}
    let mut sessions = runtime.sessions.lock().await;
    if sessions
        .get(&device)
        .is_some_and(|v| v.sender.same_channel(&sender))
    {
        sessions.remove(&device);
    }
    result
}
async fn listeners(runtime: Arc<Runtime>, directory: PathBuf, node_id: String) -> Result<()> {
    let access_listener = TcpListener::bind("127.0.0.1:0").await?;
    let access_address = access_listener.local_addr()?.to_string();
    let app = Router::new()
        .fallback(access_request)
        .layer(axum::extract::DefaultBodyLimit::max(2048))
        .with_state(runtime.clone());
    let mut local_tasks = JoinSet::new();
    local_tasks.spawn(async move { axum::serve(access_listener, app).await });
    let settings = crate::config::Caddy {
        binary: std::env::var("NEXO_CADDY_BINARY")
            .unwrap_or_else(|_| "caddy".into())
            .into(),
        ..Default::default()
    };
    let caddy = Arc::new(crate::caddy::CaddySupervisor::new(
        crate::caddy::CaddyRuntimeConfig::new(&directory, &settings),
    ));
    let empty = json!({"admin":{"listen":"127.0.0.1:8290"},"apps":{"http":{"servers":{}}}});
    caddy.write_startup_config(&empty)?;
    caddy.clone().start().await?;
    *runtime.caddy.lock().await = Some(caddy.clone());
    let mut snapshot = runtime.snapshot.subscribe();
    let mut listeners: HashMap<String, Listener> = HashMap::new();
    let mut applied = Value::Null;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {_=runtime.stop.cancelled()=>return Ok(()),_=tick.tick()=>{},changed=snapshot.changed()=>{changed?;}}
        let next = snapshot.borrow_and_update().clone();
        let stale = listeners
            .iter()
            .filter(|(_, l)| !next.services.contains(&l.service))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in stale {
            if let Some(listener) = listeners.remove(&id) {
                listener.cancel.cancel();
                listener.task.abort();
            }
        }
        let mut health = Vec::new();
        let mut servers = serde_json::Map::new();
        let mut certificates = Vec::<Value>::new();
        for service in &next.services {
            let mut error = None;
            if service.protocol == "https"
                && (service.certificate.is_none() || service.private_key.is_none())
            {
                error = Some("服务证书尚未就绪".to_owned());
            }
            if !listeners.contains_key(&service.id) && error.is_none() {
                let addr = if service.protocol == "tcp" {
                    format!("0.0.0.0:{}", service.port)
                } else {
                    "127.0.0.1:0".into()
                };
                match TcpListener::bind(addr).await {
                    Ok(listener) => {
                        let port = listener.local_addr()?.port();
                        let cancel = CancellationToken::new();
                        let served = service.clone();
                        let rt = runtime.clone();
                        let stop = cancel.clone();
                        let task = tokio::spawn(async move {
                            loop {
                                tokio::select! {
                                    _=stop.cancelled()=>break,
                                    incoming=listener.accept()=>{
                                        let Ok((socket,_))=incoming else{break;};
                                        if !rt.snapshot.borrow().accepting{continue;}
                                        if let Some(session)=rt.sessions.lock().await.get(&served.device){let _=session.sender.try_send(Open{service:served.clone(),socket,cancel:stop.clone()});}
                                    }
                                }
                            }
                        });
                        listeners.insert(
                            service.id.clone(),
                            Listener {
                                service: service.clone(),
                                cancel,
                                port,
                                task,
                            },
                        );
                    }
                    Err(e) => error = Some(format!("入口监听失败：{e}")),
                }
            }
            if let Some(listener) = listeners.get(&service.id) {
                if service.protocol != "tcp" {
                    let host = service.hostname.clone().context("网页服务缺少域名")?;
                    {
                        let port = if service.protocol == "https" {
                            service.https_port
                        } else {
                            service.http_port
                        };
                        let server=servers.entry(format!("port_{port}")).or_insert_with(||json!({"listen":[format!(":{port}")],"automatic_https":{"disable":true},"routes":[]}));
                        if service.protocol == "https" {
                            server["tls_connection_policies"] = json!([{}]);
                            let root = directory.join("certificates").join(&service.id);
                            identity::write_private_file(
                                &root.join("chain.pem"),
                                service.certificate.as_ref().unwrap().as_bytes(),
                            )?;
                            identity::write_private_file(
                                &root.join("key.pem"),
                                service.private_key.as_ref().unwrap().as_bytes(),
                            )?;
                            certificates.push(json!({"certificate":root.join("chain.pem"),"key":root.join("key.pem")}));
                        }
                        let (endpoint, check) =
                            crate::service_access::handlers(&access_address, &service.id);
                        let routes = server["routes"].as_array_mut().unwrap();
                        routes.push(super::health::route(
                            &host,
                            &node_id,
                            &service.id,
                            service.revision,
                        ));
                        if let Some(origin) = &service.lan_redirect_url {
                            if let Some(ip) = runtime
                                .sessions
                                .lock()
                                .await
                                .get(&service.device)
                                .and_then(|s| s.public_ipv4)
                            {
                                routes.push(crate::lan_redirect::route(
                                    &service.id,
                                    &host,
                                    ip,
                                    origin,
                                ));
                            }
                        }
                        routes.push(json!({"match":[{"host":[host],"path":["/.nexo-access/*"]}],"handle":[endpoint],"terminal":true}));
                        let mut handlers = Vec::new();
                        if service.access_mode == "password" {
                            handlers.push(check);
                        }
                        handlers.push(json!({"handler":"reverse_proxy","upstreams":[{"dial":format!("127.0.0.1:{}",listener.port)}],"headers":{"request":{"delete":["X-Nexo-Access-*","X-Nexo-Upstream-Cookie"]}}}));
                        routes.push(
                            json!({"match":[{"host":[host]}],"handle":handlers,"terminal":true}),
                        );
                    }
                    if service.protocol == "https" && service.http_redirect {
                        let http=servers.entry(format!("port_{}", service.http_port)).or_insert_with(||json!({"listen":[format!(":{}", service.http_port)],"automatic_https":{"disable":true},"routes":[]}));
                        http["routes"].as_array_mut().unwrap().push(
                            crate::domain_runtime::https_redirect(&host, service.https_port),
                        );
                    }
                }
            }
            if !runtime.sessions.lock().await.contains_key(&service.device) {
                error = Some("等待 Agent 数据连接".into());
            }
            health.push(wire::ServiceHealth {
                public_probe_supported: matches!(service.protocol.as_str(), "http" | "https"),
                id: service.id.clone(),
                revision: service.revision,
                ready: error.is_none(),
                error,
            });
        }
        let config = json!({"admin":{"listen":"127.0.0.1:8290"},"apps":{"http":{"servers":servers},"tls":{"certificates":{"load_files":certificates}}}});
        if applied != config {
            match caddy.apply_json(&config).await {
                Ok(()) => applied = config,
                Err(error) => {
                    for item in &mut health {
                        item.ready = false;
                        item.error = Some(format!("Caddy 配置失败：{error}"));
                    }
                }
            }
        }
        *runtime.health.lock().await = health;
        if *runtime.snapshot.borrow() == next {
            runtime.configured.store(true, Ordering::Release);
        }
    }
}
async fn access_request(
    State(runtime): State<Arc<Runtime>>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let result: Result<axum::response::Response> = async {
        let (parts, body) = request.into_parts();
        let service_id = parts
            .headers
            .get("x-nexo-access-service")
            .and_then(|v| v.to_str().ok())
            .context("缺少服务标识")?
            .to_owned();
        anyhow::ensure!(
            runtime
                .snapshot
                .borrow()
                .services
                .iter()
                .any(|s| s.id == service_id),
            "服务授权已撤销"
        );
        let headers = parts
            .headers
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_owned())))
            .collect();
        let body = String::from_utf8(axum::body::to_bytes(body, 2048).await?.to_vec())?;
        let (reply, receive) = tokio::sync::oneshot::channel();
        runtime
            .access
            .lock()
            .await
            .as_ref()
            .context("管理认证连接不可用")?
            .try_send(Access {
                request: wire::Request::Access {
                    request_id: 0,
                    service_id,
                    method: parts.method.to_string(),
                    path: parts.uri.to_string(),
                    headers,
                    body,
                },
                reply,
            })
            .map_err(|_| anyhow::anyhow!("认证请求繁忙"))?;
        let wire::Response::Access {
            status,
            headers,
            body,
            ..
        } = tokio::time::timeout(Duration::from_secs(10), receive).await??
        else {
            anyhow::bail!("认证响应无效");
        };
        let mut response = axum::response::Response::builder().status(status);
        for (key, value) in headers {
            response = response.header(key, value);
        }
        Ok(response.body(axum::body::Body::from(body))?)
    }
    .await;
    result.unwrap_or_else(|_| (StatusCode::SERVICE_UNAVAILABLE, "访问认证暂不可用").into_response())
}

/// 更新助手由 systemd 独立运行；节点只能投递固定动作，不能控制可执行路径或下载地址。
fn submit_update(command: wire::UpdateCommand) -> Result<()> {
    anyhow::ensure!(
        matches!(command.action.as_str(), "prepare" | "install" | "restart")
            && super::updates::version(&command.version).is_some()
            && command.task_id.len() <= 100
            && command
                .task_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "节点更新指令无效"
    );
    let inbox = PathBuf::from("/var/lib/nexo-node-update/inbox");
    let path = inbox.join("request.json");
    let data = serde_json::to_vec(&command)?;
    if fs::read(&path).ok().as_deref() == Some(data.as_slice()) {
        return Ok(());
    }
    identity::write_private_file(&inbox.join("request.tmp"), &data)?;
    fs::rename(inbox.join("request.tmp"), path)?;
    Ok(())
}
fn update_report() -> wire::UpdateReport {
    fs::read("/var/lib/nexo-node-update/status.json")
        .ok()
        .filter(|v| v.len() <= 16384)
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or_default()
}
pub(super) fn operating_system() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|value| value.trim_matches('"').chars().take(120).collect())
            })
        })
        .unwrap_or_else(|| std::env::consts::OS.into())
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
