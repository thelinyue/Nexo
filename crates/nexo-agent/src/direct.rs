//! Agent 公网入口：TLS 由独立 Caddy 终止，应用字节仅在 NAS 本机转发，授权经专用 mTLS 管理连接。
use super::*;
use axum::{
    body::{to_bytes, Body},
    extract::{Request as HttpRequest, State},
    response::Response as HttpResponse,
    Router,
};
use nexo_protocol::direct::{Report, Request, Response, Service, ALPN};
use serde_json::{json, Value};
use std::{collections::HashMap, net::Ipv6Addr, path::Path, process::Stdio};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot, Mutex},
};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
mod tests;

type RpcReply = oneshot::Sender<Result<Response>>;
/// 有界 RPC 队列隔离逐请求授权与配置协调；超时或断线拒绝访问。
#[derive(Clone)]
struct Client {
    sender: mpsc::Sender<(Request, RpcReply)>,
}
impl Client {
    async fn call(&self, request: Request) -> Result<Response> {
        let (send, receive) = oneshot::channel();
        self.sender
            .try_send((request, send))
            .map_err(|_| anyhow::anyhow!("直连管理通道繁忙或断开"))?;
        let response = tokio::time::timeout(Duration::from_secs(12), receive)
            .await
            .context("直连管理响应超时")??;
        match response? {
            Response::Error { message } => anyhow::bail!(message),
            response => Ok(response),
        }
    }
}

async fn connection(
    connector: TlsConnector,
    endpoint: TunnelDataEndpoint,
    mut requests: mpsc::Receiver<(Request, RpcReply)>,
) -> Result<()> {
    let mut config = (**connector.config()).clone();
    config.alpn_protocols = vec![ALPN.to_vec()];
    let stream = connect_tls(&TlsConnector::from(Arc::new(config)), &endpoint).await?;
    anyhow::ensure!(
        stream.get_ref().1.alpn_protocol() == Some(ALPN),
        "Server 未协商直连管理协议"
    );
    let mut mux = nexo_tunnel::yamux_connection(stream, yamux::Mode::Client);
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            command=requests.recv()=>{
                let Some((request,reply))=command else {return Ok(());};
                anyhow::ensure!(tasks.len()<64,"直连管理并发请求过多");
                let stream=tokio::time::timeout(Duration::from_secs(5),nexo_tunnel::new_outbound(&mut mux)).await??;
                tasks.spawn(async move {
                    let operation=async {
                        let mut stream=nexo_tunnel::into_tokio_io(stream);
                        identity::write_message(&mut stream,&request).await?;
                        let mut reader=FramedRead::new(stream,LinesCodec::new_with_max_length(128*1024));
                        let line=reader.next().await.context("直连管理响应为空")??;
                        Ok(serde_json::from_str(&line)?)
                    };
                    let response=tokio::time::timeout(Duration::from_secs(12),operation).await.map_err(|_|anyhow::anyhow!("直连管理响应超时")).and_then(|v|v);
                    let _=reply.send(response);
                });
            }
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            incoming=nexo_tunnel::next_inbound(&mut mux)=>{incoming?;anyhow::bail!("直连管理连接已关闭或收到未请求的逻辑流");}
        }
    }
}

/// Linux 标记用于排除临时、DAD 未完成、重复及废弃地址，避免把短寿命隐私地址发布到 DNS。
fn addresses() -> Result<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        let raw = fs::read_to_string("/proc/net/if_inet6").context("无法读取网络接口 IPv6 地址")?;
        Ok(parse_addresses(&raw))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(Vec::new())
    }
}
#[cfg(any(target_os = "linux", test))]
fn parse_addresses(raw: &str) -> Vec<String> {
    let mut result = Vec::new();
    for line in raw.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 6 {
            continue;
        }
        let flags = u32::from_str_radix(fields[4], 16).unwrap_or(u32::MAX);
        if flags & (0x01 | 0x08 | 0x20 | 0x40) != 0 {
            continue;
        }
        let Ok(value) = u128::from_str_radix(fields[0], 16) else {
            continue;
        };
        let ip = Ipv6Addr::from(value);
        if public_address(ip) {
            result.push(ip.to_string());
        }
    }
    result.sort();
    result.dedup();
    result
}
#[cfg(any(target_os = "linux", test))]
fn public_address(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xe000 == 0x2000
        && !(ip.segments()[0] == 0x2001 && ip.segments()[1] == 0xdb8)
}

#[derive(Clone)]
struct Access {
    client: Client,
    services: Arc<Mutex<HashMap<String, Service>>>,
}
async fn authorize(State(state): State<Access>, request: HttpRequest) -> HttpResponse {
    let result = async {
        let id = request
            .headers()
            .get("x-nexo-access-service")
            .and_then(|v| v.to_str().ok())
            .context("缺少服务标识")?;
        let service = state
            .services
            .lock()
            .await
            .get(id)
            .cloned()
            .context("服务入口已撤销")?;
        let path = request.uri().to_string();
        anyhow::ensure!(
            path == "/check" || path.starts_with("/.nexo-access/"),
            "认证路径无效"
        );
        let headers = request
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_owned(), v.to_owned()))
            })
            .collect();
        let body = to_bytes(request.into_body(), 2048).await?.to_vec();
        let Response::Access {
            status,
            headers,
            body,
        } = state
            .client
            .call(Request::Access {
                service_id: service.tunnel.tunnel_id,
                revision: service.tunnel.revision,
                path,
                headers,
                body,
            })
            .await?
        else {
            anyhow::bail!("认证响应类型错误");
        };
        let mut response = HttpResponse::builder().status(status);
        for (key, value) in headers {
            response = response.header(key, value);
        }
        anyhow::Ok(response.body(Body::from(body))?)
    }
    .await;
    result.unwrap_or_else(|_| {
        HttpResponse::builder()
            .status(503)
            .header("Cache-Control", "no-store")
            .body(Body::from("暂时无法验证访问权限，请稍后重试"))
            .unwrap()
    })
}

/// 运行配置失效时 Drop 立即取消所有回源连接；Caddy 热加载本身不会关闭已升级的连接。
struct Forwarder {
    address: String,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Forwarder {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
impl Forwarder {
    async fn start(service: &Service, mut desired: watch::Receiver<Desired>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?.to_string();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let tunnel = service.tunnel.clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    _=stop.cancelled()=>break,
                    changed=desired.changed()=>{
                        if changed.is_err() || !desired.borrow_and_update().tunnels.contains(&tunnel) {break;}
                    }
                    Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                    incoming=listener.accept(),if tasks.len()<128=>{
                        let Ok((mut socket,_))=incoming else {break;};let tunnel=tunnel.clone();
                        tasks.spawn(async move {if let Ok(mut origin)=connect_origin(&tunnel).await {let _=tokio::io::copy_bidirectional(&mut socket,&mut origin).await;}});
                    }
                }
            }
            tasks.abort_all();
        });
        Ok(Self {
            address,
            cancel,
            task,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Key {
    hostname: String,
    key_pem: String,
    csr_pem: String,
}
fn key(root: &Path, service: &Service) -> Result<Key> {
    let path = root.join("request.json");
    let saved = match fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("无法读取已有直连私钥，未覆盖"),
    };
    if let Some(bytes) = saved {
        let mut key: Key =
            serde_json::from_slice(&bytes).context("直连私钥存储无效，请恢复备份")?;
        if key.hostname == service.hostname {
            let request = rcgen::CertificateSigningRequestParams::from_pem(&key.csr_pem)
                .context("已有直连 CSR 无效，未覆盖私钥")?;
            // v0.2.9 的默认 CN 会被公网 CA 拒绝；保留原私钥，仅重签并持久化 CSR。
            if request
                .params
                .distinguished_name
                .get(&rcgen::DnType::CommonName)
                == Some(&rcgen::DnValue::Utf8String("rcgen self signed cert".into()))
            {
                key.csr_pem = public_csr(&service.hostname, &KeyPair::from_pem(&key.key_pem)?)?;
                identity::write_private_file(&path, &serde_json::to_vec(&key)?)?;
            }
            identity::write_private_file(&root.join("key.pem"), key.key_pem.as_bytes())?;
            return Ok(key);
        }
    }
    let key = KeyPair::generate()?;
    let csr = public_csr(&service.hostname, &key)?;
    let key = Key {
        hostname: service.hostname.clone(),
        key_pem: key.serialize_pem(),
        csr_pem: csr,
    };
    identity::write_private_file(&path, &serde_json::to_vec(&key)?)?;
    identity::write_private_file(&root.join("key.pem"), key.key_pem.as_bytes())?;
    Ok(key)
}

fn public_csr(hostname: &str, key: &KeyPair) -> Result<String> {
    let mut params = CertificateParams::new(vec![hostname.to_owned()])?;
    // 公网证书只使用 SAN，清除 rcgen 默认的自签证书 CN。
    params.distinguished_name = rcgen::DistinguishedName::new();
    Ok(params.serialize_request(key)?.pem()?)
}

/// 两端升级后复用域名证书；旧 Server 未声明支持时沿用 CSR，避免独立升级中断直连。
async fn sync_certificate(client: &Client, directory: &Path, service: &Service) -> Result<bool> {
    let (chain, key_pem) = if service.domain_certificate {
        let Response::DomainCertificate { chain, key_pem } = client
            .call(Request::DomainCertificate {
                service_id: service.tunnel.tunnel_id.clone(),
                revision: service.tunnel.revision,
            })
            .await?
        else {
            anyhow::bail!("域名证书响应类型错误");
        };
        (chain, key_pem)
    } else {
        let key = key(directory, service)?;
        let Response::Certificate { chain, error, .. } = client
            .call(Request::Certificate {
                service_id: service.tunnel.tunnel_id.clone(),
                revision: service.tunnel.revision,
                csr_pem: key.csr_pem,
            })
            .await?
        else {
            anyhow::bail!("证书响应类型错误");
        };
        (
            chain.context(error.unwrap_or_else(|| "等待 DNS 验证与证书签发".into()))?,
            key.key_pem,
        )
    };
    install_certificate(directory, &service.hostname, &chain, &key_pem)
}

/// 先校验再替换，错误响应不覆盖可用文件；证书或私钥变化均要求 Caddy 重新加载。
fn install_certificate(directory: &Path, hostname: &str, chain: &str, key: &str) -> Result<bool> {
    identity::validate_https_certificate(chain, key, hostname, certificate::now())?;
    let mut changed = false;
    for (name, value) in [("key.pem", key), ("chain.pem", chain)] {
        let path = directory.join(name);
        if fs::read(&path).ok().as_deref() != Some(value.as_bytes()) {
            identity::write_private_file(&path, value.as_bytes())?;
            changed = true;
        }
    }
    Ok(changed)
}

/// Agent 专用 Caddy 子进程，只绑定选定 IPv6；退出和热加载失败不得报告就绪。
struct Process {
    child: tokio::process::Child,
    admin: String,
    client: reqwest::Client,
    last: Value,
    reload: bool,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}
impl Process {
    async fn start(root: &Path, binary: &Path) -> Result<Self> {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
        let address = reservation.local_addr()?;
        let config = json!({"admin":{"listen":address.to_string()},"storage":{"module":"file_system","root":root.join("storage")},"apps":{}});
        let path = root.join("caddy.json");
        identity::write_private_file(&path, &serde_json::to_vec(&config)?)?;
        drop(reservation);
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("caddy.log"))?;
        let mut command = tokio::process::Command::new(binary);
        command
            .args(["run", "--config"])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let child = command
            .spawn()
            .context("无法启动直连 Caddy，请检查 Agent 安装及 caddy_binary 配置")?;
        let mut process = Self {
            child,
            admin: format!("http://{address}"),
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()?,
            last: Value::Null,
            reload: false,
        };
        for _ in 0..50 {
            anyhow::ensure!(
                process.child.try_wait()?.is_none(),
                "直连 Caddy 已退出，请查看 direct/caddy.log"
            );
            if process
                .client
                .get(format!("{}/config/", process.admin))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return Ok(process);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!("直连 Caddy 管理接口启动超时")
    }
    async fn apply(&mut self, mut config: Value) -> Result<()> {
        config["admin"] = json!({"listen":self.admin.trim_start_matches("http://")});
        anyhow::ensure!(
            self.child.try_wait()?.is_none(),
            "直连 Caddy 已退出，请查看 direct/caddy.log"
        );
        if config == self.last && !self.reload {
            return Ok(());
        }
        let response = self
            .client
            .post(format!("{}/load", self.admin))
            .header("Cache-Control", "must-revalidate")
            .json(&config)
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "直连入口加载失败，请检查端口占用与 direct/caddy.log"
        );
        self.last = config;
        self.reload = false;
        Ok(())
    }
}

fn configuration(root: &Path, services: &[(Service, String)], access: &str) -> Value {
    let mut servers = serde_json::Map::new();
    let mut certificates = Vec::new();
    for (service, upstream) in services {
        let id = &service.tunnel.tunnel_id;
        certificates.push(json!({"certificate":root.join(id).join("chain.pem"),"key":root.join(id).join("key.pem")}));
        let name = format!("{}:{}", service.ipv6, service.port);
        let server=servers.entry(name).or_insert_with(||json!({"listen":[format!("[{}]:{}",service.ipv6,service.port)],"protocols":["h1","h2"],"automatic_https":{"disable":true},"tls_connection_policies":[{}],"routes":[]}));
        let headers = json!({"request":{"set":{"X-Nexo-Access-Service":[id],"X-Nexo-Access-Authority":["{http.request.hostport}"],"X-Nexo-Access-Ip":["{http.request.remote.host}"],"X-Nexo-Access-Method":["{http.request.method}"],"X-Nexo-Access-Uri":["{http.request.uri}"]}}});
        let endpoint =
            json!({"handler":"reverse_proxy","upstreams":[{"dial":access}],"headers":headers});
        let mut check = endpoint.clone();
        // Caddy 默认保留原查询串；显式清空认证子请求的查询，避免 /check?v=... 被拒绝。
        // reverse_proxy 的 rewrite 只作用于子请求，Emby 收到的业务参数保持原样。
        check["rewrite"] = json!({"method":"GET","uri":"/check?"});
        check["handle_response"] = json!([{"match":{"status_code":[2]},"routes":[{"handle":[{"handler":"headers","request":{"set":{"Cookie":["{http.reverse_proxy.header.X-Nexo-Upstream-Cookie}"]},"delete":["X-Nexo-Access-*","X-Nexo-Upstream-Cookie"]}}]}]}]);
        let routes = server["routes"].as_array_mut().unwrap();
        routes.push(json!({"match":[{"host":[service.hostname],"path":["/.nexo-direct/probe"],"method":["GET"]}],"handle":[{"handler":"static_response","body":format!("{}:{}",id,service.tunnel.revision),"headers":{"Cache-Control":["no-store"]}}],"terminal":true}));
        routes.push(json!({"match":[{"host":[service.hostname],"path":["/.nexo-access/*"]}],"handle":[endpoint],"terminal":true}));
        routes.push(json!({"match":[{"host":[service.hostname]}],"handle":[check,{"handler":"reverse_proxy","upstreams":[{"dial":upstream}]}],"terminal":true}));
    }
    for server in servers.values_mut() {
        server["routes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"handle":[{"handler":"static_response","status_code":404}]}));
    }
    json!({"storage":{"module":"file_system","root":root.join("storage")},"apps":{"http":{"servers":servers},"tls":{"certificates":{"load_files":certificates}}}})
}

pub async fn run(
    binary: PathBuf,
    root: PathBuf,
    connectors: watch::Receiver<TlsConnector>,
    mut desired: watch::Receiver<Desired>,
) {
    loop {
        let result = session(&binary, &root, connectors.clone(), desired.clone()).await;
        if let Err(error) = result {
            tracing::warn!("IPv6 直连暂不可用，原隧道继续工作：{error}");
        }
        tokio::select! {_=tokio::time::sleep(Duration::from_secs(5))=>{},changed=desired.changed()=>if changed.is_err(){return;}}
    }
}
async fn session(
    binary: &Path,
    root: &Path,
    mut connectors: watch::Receiver<TlsConnector>,
    mut desired: watch::Receiver<Desired>,
) -> Result<()> {
    fs::create_dir_all(root)?;
    let (sender, receiver) = mpsc::channel(64);
    let client = Client { sender };
    let endpoint = desired.borrow().endpoint.clone();
    let connector = connectors.borrow().clone();
    let mut tasks = JoinSet::new();
    tasks.spawn(connection(connector, endpoint.clone(), receiver));
    let access = Access {
        client: client.clone(),
        services: Arc::new(Mutex::new(HashMap::new())),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let auth_address = listener.local_addr()?.to_string();
    let app = Router::new().fallback(authorize).with_state(access.clone());
    tasks.spawn(async move {
        axum::serve(listener, app).await?;
        Ok(())
    });
    let mut process: Option<Process> = None;
    let mut running = HashMap::<String, (Service, Forwarder)>::new();
    let mut reports = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            Some(result)=tasks.join_next()=>{result??;anyhow::bail!("直连运行任务已停止");}
            _=connectors.changed()=>return Ok(()),
            changed=desired.changed()=>{
                changed.context("控制通道已关闭")?;
                if desired.borrow().endpoint!=endpoint {return Ok(());}
                // 先关闭失效的本地回源，即使 Caddy 仍持有旧路由也无法继续访问应用。
                running.retain(|_,(service,_)|desired.borrow().tunnels.contains(&service.tunnel));
                access.services.lock().await.retain(|_,service|desired.borrow().tunnels.contains(&service.tunnel));
                tick.reset_immediately();
            }
            _=tick.tick()=>{
                // 整轮协调有上限，管理通道故障时不能因逐服务等待而保留旧连接。
                tokio::time::timeout(Duration::from_secs(35), async {
                let addresses=addresses()?;
                let Response::Services {services}=client.call(Request::Sync {addresses:addresses.clone(),reports:std::mem::take(&mut reports)}).await? else {anyhow::bail!("直连配置响应错误");};
                running.retain(|_,(service,_)|services.contains(service) && addresses.contains(&service.ipv6));
                let mut loaded=Vec::new();let mut allowed=HashMap::new();
                for service in services {
                    let id=service.tunnel.tunnel_id.clone();
                    let result=async {
                        anyhow::ensure!(id.len()<=64 && id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'),"直连服务 ID 无效");
                        anyhow::ensure!(addresses.contains(&service.ipv6) && desired.borrow().tunnels.contains(&service.tunnel),"直连配置不属于当前有效控制快照");
                        let directory=root.join(&id);fs::create_dir_all(&directory)?;
                        if sync_certificate(&client,&directory,&service).await? {
                            if let Some(caddy)=process.as_mut() {caddy.reload=true;}
                        }
                        if !running.contains_key(&id) {
                            let listen=format!("[{}]:{}",service.ipv6,service.port);
                            let owned=process.as_ref().is_some_and(|p|p.last["apps"]["http"]["servers"].as_object().is_some_and(|servers|servers.values().any(|v|v["listen"].as_array().is_some_and(|a|a.contains(&json!(listen))))));
                            if !owned {let probe=std::net::TcpListener::bind((service.ipv6.parse::<Ipv6Addr>()?,service.port)).context("Agent HTTPS 端口已被占用或 IPv6 地址失效")?;drop(probe);}
                            // 本地回源成功后才上报 ready；连接失败不能发布 AAAA。
                            connect_origin(&service.tunnel).await?;
                            running.insert(id.clone(),(service.clone(),Forwarder::start(&service,desired.clone()).await?));
                        }
                        anyhow::Ok(())
                    }.await;
                    if let Err(error)=result {running.remove(&id);reports.push(Report {address:service.ipv6.clone(),service_id:id,revision:service.tunnel.revision,ready:false,error:Some(error.to_string())});continue;}
                    loaded.push((service.clone(),running[&id].1.address.clone()));allowed.insert(id,service);
                }
                *access.services.lock().await=allowed;
                if process.as_mut().is_some_and(|p|p.child.try_wait().ok().flatten().is_some()) {process=None;}
                if !loaded.is_empty() && process.is_none() {
                    match Process::start(root,binary).await {
                        Ok(caddy)=>process=Some(caddy),
                        Err(error)=>{
                            running.clear();access.services.lock().await.clear();
                            for (s,_) in &loaded {reports.push(Report {address:s.ipv6.clone(),service_id:s.tunnel.tunnel_id.clone(),revision:s.tunnel.revision,ready:false,error:Some(error.to_string())});}
                        }
                    }
                }
                if let Some(caddy)=process.as_mut() {
                    let result=caddy.apply(configuration(root,&loaded,&auth_address)).await;
                    if let Err(error)=result {
                        running.clear();access.services.lock().await.clear();
                        for (s,_) in &loaded {reports.push(Report {address:s.ipv6.clone(),service_id:s.tunnel.tunnel_id.clone(),revision:s.tunnel.revision,ready:false,error:Some(error.to_string())});}
                    } else {
                        for (s,_) in &loaded {reports.push(Report {address:s.ipv6.clone(),service_id:s.tunnel.tunnel_id.clone(),revision:s.tunnel.revision,ready:true,error:None});}
                    }
                }
                if loaded.is_empty() {process=None;}
                anyhow::Ok(())
                }).await.context("直连配置协调超时，已关闭旧入口")??;
            }
        }
    }
}
