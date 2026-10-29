//! 各公网入口共用的脱敏观测。原始 IP、请求头和查询串只在解析栈内存在，
//! 队列及跨进程上报只包含白名单字段；采集失败不改变业务转发结果。
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, VecDeque},
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const CAPACITY: usize = 8192;
pub const BATCH_SIZE: usize = 64;
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn day(at: i64) -> i64 {
    (at + 28800).div_euclid(86400) * 86400 - 28800
}
fn id() -> String {
    let mut bytes = [0; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// 一个事件只属于一个服务。控制器从已认证节点/设备反查空间，绝不相信上报的租户标识。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Event {
    pub id: String,
    pub service: String,
    pub at: i64,
    pub kind: String,
    pub protocol: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub duration_ms: u64,
    pub to_origin: u64,
    pub to_public: u64,
    pub visitor: String,
    pub source: String,
    pub country: String,
    pub operator: String,
    pub browser: String,
    pub os: String,
    pub device: String,
    pub active: u64,
    pub peak: u64,
    pub reason: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Batch {
    pub events: Vec<Event>,
    pub dropped: u64,
}

#[derive(Debug, Default)]
struct Counters {
    origin: AtomicU64,
    public: AtomicU64,
    active: AtomicU64,
    peak: AtomicU64,
}
#[derive(Debug, Default)]
struct Queue {
    events: VecDeque<Event>,
    dropped: u64,
    flows: BTreeMap<(String, String), (Arc<Counters>, u64, u64)>,
}
/// 队列有上限；batch/ack 使断线重试复用事件主键，控制器的唯一约束保证不会重复计数。
/// 生产入口持久化随机隐私密钥，按天派生访客摘要；不同入口的 UV 仍为近似值。
#[derive(Debug)]
pub struct Hub {
    queue: Mutex<Queue>,
    secret: [u8; 32],
    geo: Option<maxminddb::Reader<Vec<u8>>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
    started: Instant,
}
impl Default for Hub {
    fn default() -> Self {
        let mut secret = [0; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        let geo = std::env::var_os("NEXO_GEOIP_DATABASE")
            .and_then(|p| maxminddb::Reader::open_readfile(p).ok());
        let asn = std::env::var_os("NEXO_GEOIP_ASN_DATABASE")
            .and_then(|p| maxminddb::Reader::open_readfile(p).ok());
        Self {
            queue: Mutex::new(Queue::default()),
            secret,
            geo,
            asn,
            started: Instant::now(),
        }
    }
}
impl Hub {
    /// 隐私密钥与节点身份同目录持久化，普通重启不会令当天 UV 重复。
    pub fn persistent(directory: &std::path::Path) -> anyhow::Result<Self> {
        use std::io::Write;
        std::fs::create_dir_all(directory)?;
        let path = directory.join("analytics.key");
        let mut hub = Self::default();
        if path.exists() {
            hub.secret = std::fs::read(path)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("统计隐私密钥长度无效"))?;
        } else {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path)?;
            file.write_all(&hub.secret)?;
            file.sync_all()?;
        }
        Ok(hub)
    }
    pub fn uptime(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
    pub fn geo_available(&self) -> bool {
        self.geo.is_some()
    }
    pub fn push(&self, event: Event) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        Self::append(&mut q, event);
    }
    fn append(q: &mut Queue, event: Event) {
        if q.events.len() == CAPACITY {
            q.dropped = q.dropped.saturating_add(1);
        } else {
            q.events.push_back(event);
        }
    }
    pub fn batch(&self) -> Batch {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let mut samples = Vec::new();
        for ((service, protocol), (counts, old_origin, old_public)) in &mut q.flows {
            let origin = counts.origin.load(Ordering::Relaxed);
            let public = counts.public.load(Ordering::Relaxed);
            let active = counts.active.load(Ordering::Relaxed);
            let peak = counts.peak.swap(active, Ordering::Relaxed).max(active);
            samples.push(Event {
                id: id(),
                service: service.clone(),
                protocol: protocol.clone(),
                at: now(),
                kind: "flow".into(),
                to_origin: origin - *old_origin,
                to_public: public - *old_public,
                active,
                peak,
                ..Default::default()
            });
            *old_origin = origin;
            *old_public = public;
        }
        q.flows
            .retain(|_, (c, _, _)| c.active.load(Ordering::Relaxed) > 0);
        for event in samples {
            Self::append(&mut q, event);
        }
        Batch {
            events: q.events.iter().take(BATCH_SIZE).cloned().collect(),
            dropped: q.dropped,
        }
    }
    pub fn ack(&self, batch: &Batch) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        for event in &batch.events {
            if q.events.front().is_some_and(|e| e.id == event.id) {
                q.events.pop_front();
            }
        }
    }
    pub fn session(self: &Arc<Self>, service: &str, protocol: &str) -> Session {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let counts = q
            .flows
            .entry((service.into(), protocol.into()))
            .or_default()
            .0
            .clone();
        let active = counts.active.fetch_add(1, Ordering::Relaxed) + 1;
        counts.peak.fetch_max(active, Ordering::Relaxed);
        Session {
            hub: self.clone(),
            service: service.into(),
            protocol: protocol.into(),
            counts,
            origin: 0,
            public: 0,
            started: Instant::now(),
            reason: "cancelled".into(),
        }
    }
    /// 接入 Caddy 完成日志；不解析任意应用载荷，不把长连接完成耗时解释为首字节延迟。
    pub fn access_line(&self, line: &str) -> bool {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            return false;
        };
        let Some(service) = v["logger"]
            .as_str()
            .and_then(|s| s.strip_prefix("http.log.access.nexo_"))
        else {
            return false;
        };
        if service.is_empty() || service.len() > 64 {
            return true;
        }
        let request = &v["request"];
        let path = clean_path(request["uri"].as_str().unwrap_or("/"));
        if path.starts_with("/.nexo-") {
            return true;
        }
        let at = v["ts"].as_f64().unwrap_or(now() as f64) as i64;
        let raw = request["remote_ip"].as_str().unwrap_or("");
        let ip = raw.parse::<IpAddr>().ok().map(|ip| match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        });
        let source = ip.map(mask_ip).unwrap_or_else(|| "未知".into());
        let ua = request["headers"]["User-Agent"][0]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase();
        let browser = if ua.contains("edg/") {
            "Edge"
        } else if ua.contains("firefox/") {
            "Firefox"
        } else if ua.contains("chrome/") {
            "Chrome"
        } else if ua.contains("safari/") {
            "Safari"
        } else {
            "其他"
        };
        let os = if ua.contains("android") {
            "Android"
        } else if ua.contains("iphone") || ua.contains("ipad") {
            "iOS"
        } else if ua.contains("windows") {
            "Windows"
        } else if ua.contains("mac os") {
            "macOS"
        } else if ua.contains("linux") {
            "Linux"
        } else {
            "其他"
        };
        let device = if ua.contains("bot") || ua.contains("spider") {
            "机器人"
        } else if ua.contains("ipad") || ua.contains("tablet") {
            "平板"
        } else if ua.contains("mobile") || ua.contains("iphone") {
            "手机"
        } else {
            "电脑/其他"
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret).expect("固定长度密钥");
        mac.update(format!("{}|{}|{}|{}", day(at), raw, browser, os).as_bytes());
        let visitor = if ip.is_some() {
            hex::encode(mac.finalize().into_bytes())
        } else {
            String::new()
        };
        let country = ip
            .and_then(|ip| self.geo.as_ref()?.lookup::<Value>(ip).ok())
            .and_then(|v| {
                v["country"]["names"]["zh-CN"]
                    .as_str()
                    .or_else(|| v["country"]["iso_code"].as_str())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "未知".into());
        let operator = ip
            .and_then(|ip| self.asn.as_ref()?.lookup::<Value>(ip).ok())
            .and_then(|v| {
                v["autonomous_system_organization"]
                    .as_str()
                    .map(|s| limited(s, 96))
            })
            .unwrap_or_else(|| "未知".into());
        let protocol = if v["status"].as_u64() == Some(101) {
            "websocket"
        } else if request["tls"].is_object() {
            "https"
        } else {
            "http"
        };
        self.push(Event {
            id: id(),
            service: service.into(),
            at,
            kind: "request".into(),
            protocol: protocol.into(),
            host: limited(request["host"].as_str().unwrap_or(""), 253),
            method: limited(request["method"].as_str().unwrap_or(""), 16),
            path,
            status: v["status"].as_u64().unwrap_or(0).min(599) as u16,
            duration_ms: (v["duration"].as_f64().unwrap_or(0.).max(0.) * 1000.).min(90. * 86400000.)
                as u64,
            to_origin: v["bytes_read"].as_u64().unwrap_or(0),
            to_public: v["size"].as_u64().unwrap_or(0),
            visitor,
            source,
            country,
            operator,
            browser: browser.into(),
            os: os.into(),
            device: device.into(),
            ..Default::default()
        });
        true
    }
}
pub fn limited(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}
pub fn clean_path(s: &str) -> String {
    limited(s.split(['?', '#']).next().unwrap_or("/"), 256)
}
pub fn mask_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => {
            let b = v.octets();
            format!("{}.{}.{}.0/24", b[0], b[1], b[2])
        }
        IpAddr::V6(v) => {
            let b = v.segments();
            format!("{:x}:{:x}:{:x}::/48", b[0], b[1], b[2])
        }
    }
}
pub fn normalize_source(value: &str) -> String {
    value
        .parse::<ipnet::IpNet>()
        .map(|net| mask_ip(net.addr()))
        .unwrap_or_else(|_| "未知".into())
}

/// 一个真实 TCP/UDP 公网会话的生命周期。Drop 覆盖任务取消，显式结束可设置可理解的原因。
pub struct Session {
    hub: Arc<Hub>,
    service: String,
    protocol: String,
    counts: Arc<Counters>,
    origin: u64,
    public: u64,
    started: Instant,
    reason: String,
}
impl Session {
    pub fn record(&mut self, origin: bool, count: usize) {
        if origin {
            self.origin += count as u64;
            self.counts
                .origin
                .fetch_add(count as u64, Ordering::Relaxed);
        } else {
            self.public += count as u64;
            self.counts
                .public
                .fetch_add(count as u64, Ordering::Relaxed);
        }
    }
    pub fn finish(&mut self, reason: &str) {
        self.reason = reason.into();
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.counts.active.fetch_sub(1, Ordering::Relaxed);
        self.hub.push(Event {
            id: id(),
            service: self.service.clone(),
            at: now(),
            kind: "session".into(),
            protocol: self.protocol.clone(),
            duration_ms: self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            to_origin: self.origin,
            to_public: self.public,
            reason: self.reason.clone(),
            ..Default::default()
        });
    }
}

/// 给已知服务配置独立访问日志；未知主机和内部探测不进入统计。
/// stdout 专供内存采集，不写原始访问日志文件；普通诊断日志继续走 stderr。
pub fn configure(config: &mut Value, hosts: &[(String, String)]) {
    if let Some(servers) = config["apps"]["http"]["servers"].as_object_mut() {
        let names: serde_json::Map<String, Value> = hosts
            .iter()
            .map(|(host, id)| (host.clone(), json!([format!("nexo_{id}")])))
            .collect();
        for server in servers.values_mut() {
            server["logs"] = json!({"logger_names":names,"skip_unmapped_hosts":true});
        }
    }
    config["logging"]["logs"]["nexo_access"] = json!({"writer":{"output":"stdout"},"include":["http.log.access"],
        "encoder":{"format":"filter","wrap":{"format":"json"},"fields":{
            "request>uri":{"filter":"regexp","regexp":"[?#].*$","value":""},
            "request>headers>Cookie":{"filter":"delete"},"request>headers>Authorization":{"filter":"delete"},
            "request>headers>Proxy-Authorization":{"filter":"delete"},"resp_headers":{"filter":"delete"}}}});
    config["logging"]["logs"]["default"]["exclude"] = json!(["http.log.access"]);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn log(at: i64) -> String {
        json!({"logger":"http.log.access.nexo_service","ts":at,"status":201,"duration":0.025,"size":2048,"bytes_read":30,
        "request":{"host":"app.example.com","method":"POST","uri":"/api/items?token=secret#private","remote_ip":"203.0.113.9","headers":{"Cookie":["secret"],"User-Agent":["Mozilla Windows Chrome/100.0"]},"tls":{}}}).to_string()
    }

    /// 使用 MaxMind 官方测试库验证真实 MMDB 解码；配置降级放入子进程，避免环境变量污染并行测试。
    #[test]
    #[ignore = "需要官方 GeoIP2-Country-Test.mmdb 和 GeoLite2-ASN-Test.mmdb 环境变量"]
    fn real_mmdb_classification_and_unavailable_database_fallback() {
        let hub = Hub::default();
        let fallback = std::env::var_os("NEXO_TEST_GEOIP_FALLBACK").is_some();
        assert_eq!(hub.geo_available(), !fallback);
        for (ip, source, country, operator) in [
            ("81.2.69.160", "81.2.69.0/24", "英国", "未知"),
            ("2001:218::1", "2001:218:0::/48", "日本", "未知"),
            ("1.0.0.1", "1.0.0.0/24", "未知", "Google Inc."),
            (
                "2001:1700::1",
                "2001:1700:0::/48",
                "未知",
                "Sunrise Communications AG",
            ),
            ("::ffff:81.2.69.160", "81.2.69.0/24", "英国", "未知"),
            ("127.0.0.1", "127.0.0.0/24", "未知", "未知"),
        ] {
            let mut line: Value = serde_json::from_str(&log(now())).unwrap();
            line["request"]["remote_ip"] = json!(ip);
            assert!(hub.access_line(&line.to_string()));
            let batch = hub.batch();
            let e = &batch.events[0];
            assert_eq!(e.source, source);
            assert_eq!(e.country, if fallback { "未知" } else { country }, "{ip}");
            assert_eq!(e.operator, if fallback { "未知" } else { operator }, "{ip}");
            assert!(!e.visitor.is_empty());
            hub.ack(&batch);
        }
        if fallback {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let invalid = root.path().join("invalid.mmdb");
        std::fs::write(&invalid, b"not a database").unwrap();
        for path in [None, Some(root.path().join("missing.mmdb")), Some(invalid)] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--ignored",
                    "--exact",
                    "telemetry::tests::real_mmdb_classification_and_unavailable_database_fallback",
                ])
                .env("NEXO_TEST_GEOIP_FALLBACK", "1")
                .env_remove("NEXO_GEOIP_DATABASE")
                .env_remove("NEXO_GEOIP_ASN_DATABASE");
            if let Some(path) = path {
                child
                    .env("NEXO_GEOIP_DATABASE", &path)
                    .env("NEXO_GEOIP_ASN_DATABASE", path);
            }
            let result = child.output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stdout)
            );
        }
    }
    #[test]
    fn access_events_strip_secrets_and_keep_daily_pseudonyms_stable_after_restart() {
        let root = tempfile::tempdir().unwrap();
        let hub = Hub::persistent(root.path()).unwrap();
        assert!(hub.access_line(&log(now())));
        assert!(hub.access_line(&log(now())));
        let first = hub.batch();
        assert_eq!(first.events[0].visitor, first.events[1].visitor);
        let e = &first.events[0];
        assert_eq!(e.path, "/api/items");
        assert_eq!(e.source, "203.0.113.0/24");
        assert_eq!(e.protocol, "https");
        assert_eq!(e.duration_ms, 25);
        let persisted = serde_json::to_string(e).unwrap();
        for private in ["203.0.113.9", "secret", "Cookie", "token="] {
            assert!(!persisted.contains(private));
        }
        let reopened = Hub::persistent(root.path()).unwrap();
        reopened.access_line(&log(now()));
        assert_eq!(reopened.batch().events[0].visitor, e.visitor);
        reopened.access_line(&log(now() + 86400));
        assert_ne!(reopened.batch().events[1].visitor, e.visitor);
        hub.ack(&first);
        assert!(hub.batch().events.is_empty());
    }
    #[test]
    fn session_bytes_and_cancelled_drop_are_sampled_once() {
        let hub = Arc::new(Hub::default());
        let mut a = hub.session("tcp", "tcp");
        let b = hub.session("tcp", "tcp");
        a.record(true, 23);
        a.record(false, 17);
        let first = hub.batch();
        let flow = first.events.iter().find(|e| e.kind == "flow").unwrap();
        assert_eq!(
            (flow.active, flow.peak, flow.to_origin, flow.to_public),
            (2, 2, 23, 17)
        );
        hub.ack(&first);
        a.record(false, 7);
        a.finish("closed");
        drop(a);
        drop(b);
        let end = hub.batch();
        assert_eq!(end.events.iter().filter(|e| e.kind == "session").count(), 2);
        assert_eq!(
            end.events
                .iter()
                .filter(|e| e.kind == "flow")
                .map(|e| e.to_public)
                .sum::<u64>(),
            7
        );
        assert!(end.events.iter().any(|e| e.reason == "cancelled"));
        hub.ack(&end);
        assert!(hub.batch().events.is_empty());
    }
    #[test]
    fn bounded_queue_preserves_retry_ids_and_reports_drops() {
        let hub = Hub::default();
        for _ in 0..CAPACITY + 3 {
            hub.push(Event {
                id: id(),
                ..Default::default()
            });
        }
        let first = hub.batch();
        assert_eq!(first.events.len(), BATCH_SIZE);
        assert_eq!(first.dropped, 3);
        assert_eq!(first.events[0].id, hub.batch().events[0].id);
        hub.ack(&first);
        hub.ack(&first);
        assert_eq!(
            hub.queue.lock().unwrap().events.len(),
            CAPACITY - BATCH_SIZE
        );
        assert_eq!(hub.batch().dropped, 3);
    }
    #[test]
    fn probes_and_unknown_loggers_are_excluded() {
        let hub = Hub::default();
        let line = log(now()).replace("/api/items?token=secret#private", "/.nexo-health/probe");
        assert!(hub.access_line(&line));
        assert!(hub.batch().events.is_empty());
        assert!(!hub.access_line("not json"));
        assert!(
            !hub.access_line(&log(now()).replace("http.log.access.nexo_service", "http.log.error"))
        );
    }
}
