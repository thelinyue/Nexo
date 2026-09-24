//! 域名归属和自助证书配置。归属验证始终使用 Server DNS，不能信任用户自定义的签发解析器。
use crate::*;
use serde_json::{json, Value};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path as FsPath,
    time::Duration,
};

fn default_dns_resolvers() -> Vec<String> {
    vec!["223.5.5.5:53".into(), "223.6.6.6:53".into()]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsSettings {
    #[serde(default = "default_dns_resolvers")]
    pub dns_resolvers: Vec<String>,
    pub dns_propagation_delay_seconds: Option<u32>,
    pub dns_propagation_timeout_seconds: Option<u32>,
}
impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            dns_resolvers: default_dns_resolvers(),
            dns_propagation_delay_seconds: None,
            dns_propagation_timeout_seconds: None,
        }
    }
}
impl DnsSettings {
    fn validate(&mut self) -> Result<(), ApiError> {
        if self.dns_resolvers.len() > 4 {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "最多配置 4 个 DNS 解析器",
            ));
        }
        let mut normalized = Vec::new();
        for entry in &self.dns_resolvers {
            let value = entry.trim();
            let socket = value
                .parse::<IpAddr>()
                .map(|ip| SocketAddr::new(ip, 53))
                .or_else(|_| value.parse::<SocketAddr>())
                .map_err(|_| {
                    ApiError::new(
                        StatusCode::BAD_REQUEST,
                        "DNS 解析器必须是 IPv4/IPv6 地址，可附加端口；IPv6 带端口时使用方括号",
                    )
                })?;
            if socket.port() == 0 || socket.ip().is_unspecified() || socket.ip().is_multicast() {
                return Err(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "DNS 解析器地址或端口无效",
                ));
            }
            let value = socket.to_string();
            if !normalized.contains(&value) {
                normalized.push(value);
            }
        }
        if self.dns_propagation_delay_seconds.is_some_and(|n| n > 120)
            || self
                .dns_propagation_timeout_seconds
                .is_some_and(|n| n == 0 || n > 600)
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "DNS 传播等待应为 0–120 秒，传播超时应为 1–600 秒",
            ));
        }
        self.dns_resolvers = if normalized.is_empty() {
            default_dns_resolvers()
        } else {
            normalized
        };
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Settings {
    pub certificate_mode: String,
    pub verification_status: String,
    pub verification_record: Option<Value>,
    pub credential_configured: bool,
    #[serde(flatten)]
    pub dns: DnsSettings,
    #[serde(skip)]
    pub credential_file: Option<String>,
    #[serde(skip)]
    pub legacy: bool,
}
#[derive(Deserialize)]
pub struct SettingsInput {
    pub certificate_mode: String,
    #[serde(flatten)]
    pub dns: DnsSettings,
}
#[derive(Deserialize)]
pub struct CredentialInput {
    pub token: String,
}

pub fn initialize_schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS domain_settings (
        domain_id TEXT PRIMARY KEY REFERENCES public_domains(id) ON DELETE CASCADE,
        certificate_mode TEXT NOT NULL CHECK(certificate_mode IN ('http01','cloudflare_dns')),
        verified INTEGER NOT NULL DEFAULT 0, verification_token TEXT NOT NULL,
        credential_file TEXT, dns_resolvers TEXT NOT NULL DEFAULT '[]',
        propagation_delay INTEGER, propagation_timeout INTEGER, legacy INTEGER NOT NULL DEFAULT 0
    );
    INSERT OR IGNORE INTO domain_settings(domain_id,certificate_mode,verified,verification_token,legacy)
        SELECT id,'cloudflare_dns',1,'',1 FROM public_domains;")?;
    Ok(())
}

pub fn load(db: &Connection, id: &str, domain: &str) -> Result<Settings, ApiError> {
    let row=db.query_row("SELECT certificate_mode,verified,verification_token,credential_file,dns_resolvers,propagation_delay,propagation_timeout,legacy FROM domain_settings WHERE domain_id=?1",[id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,String>(4)?,r.get::<_,Option<u32>>(5)?,r.get::<_,Option<u32>>(6)?,r.get::<_,bool>(7)?))).optional().map_err(db_error)?;
    let (mode, verified, token, file, resolvers, delay, timeout, legacy) =
        row.unwrap_or_else(|| {
            (
                "cloudflare_dns".into(),
                true,
                String::new(),
                None,
                "[]".into(),
                None,
                None,
                true,
            )
        });
    let mut dns_resolvers: Vec<String> = serde_json::from_str(&resolvers).map_err(db_error)?;
    // 新域名和已有空配置统一使用阿里云公共 DNS，仅用于证书验证，不改变归属验证的信任来源。
    if dns_resolvers.is_empty() {
        dns_resolvers = default_dns_resolvers();
    }
    Ok(Settings {
        certificate_mode: mode,
        verification_status: if verified { "verified" } else { "pending" }.into(),
        verification_record: (!verified)
            .then(|| json!({"name":format!("_nexo-verification.{domain}"),"value":token})),
        credential_configured: file.is_some(),
        credential_file: file,
        dns: DnsSettings {
            dns_resolvers,
            dns_propagation_delay_seconds: delay,
            dns_propagation_timeout_seconds: timeout,
        },
        legacy,
    })
}

pub fn create_settings(db: &Connection, id: &str) -> Result<(), ApiError> {
    let proof = EnrollmentToken::generate(unix_now(), 3600).map_err(db_error)?;
    db.execute("INSERT INTO domain_settings(domain_id,certificate_mode,verified,verification_token) VALUES (?1,'http01',0,?2)",params![id,proof.secret]).map_err(db_error)?;
    Ok(())
}
fn owned(db: &Connection, tenant: &str, id: &str) -> Result<String, ApiError> {
    db.query_row(
        "SELECT domain FROM public_domains WHERE id=?1 AND tenant_id=?2",
        params![id, tenant],
        |r| r.get(0),
    )
    .optional()
    .map_err(db_error)?
    .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "域名不存在"))
}

/// 在写事务内占用域名范围；未验证记录不能抢占其他用户域名，父子域也不能跨空间重叠。
fn claim(db: &Connection, tenant: &str, id: &str, domain: &str) -> Result<(), ApiError> {
    let mut query=db.prepare("SELECT p.domain FROM public_domains p LEFT JOIN domain_settings s ON s.domain_id=p.id WHERE p.tenant_id!=?1 AND COALESCE(s.verified,1)=1").map_err(db_error)?;
    for existing in query
        .query_map([tenant], |r| r.get::<_, String>(0))
        .map_err(db_error)?
    {
        let existing = existing.map_err(db_error)?;
        if domain == existing
            || domain.ends_with(&format!(".{existing}"))
            || existing.ends_with(&format!(".{domain}"))
        {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "此域名范围已被其他工作空间使用",
            ));
        }
    }
    // 同一空间的父域也不能覆盖已发布的具体服务地址。
    let collision:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM tunnels t JOIN public_domains p ON p.id=t.public_domain_id WHERE t.deleted_at IS NULL AND t.hostname||'.'||p.domain=?1)",[domain],|r|r.get(0)).map_err(db_error)?;
    if collision {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "此域名已作为服务地址使用",
        ));
    }
    db.execute(
        "UPDATE domain_settings SET verified=1 WHERE domain_id=?1",
        [id],
    )
    .map_err(db_error)?;
    Ok(())
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(mut input): Json<SettingsInput>,
) -> Result<Json<Settings>, ApiError> {
    let session = require_write(&state, &headers)?;
    if !matches!(input.certificate_mode.as_str(), "http01" | "cloudflare_dns") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "请选择 HTTP 验证或 Cloudflare DNS 验证",
        ));
    }
    input.dns.validate()?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let domain = owned(&db, &session.tenant_id, &id)?;
    let current = load(&db, &id, &domain)?;
    if input.certificate_mode == "cloudflare_dns"
        && !current.credential_configured
        && !current.legacy
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "请先验证并保存 Cloudflare Token，再保存 DNS 证书配置",
        ));
    }
    let tx = db.unchecked_transaction().map_err(db_error)?;
    tx.execute("UPDATE domain_settings SET certificate_mode=?1,dns_resolvers=?2,propagation_delay=?3,propagation_timeout=?4 WHERE domain_id=?5",params![input.certificate_mode,serde_json::to_string(&input.dns.dns_resolvers).map_err(db_error)?,input.dns.dns_propagation_delay_seconds,input.dns.dns_propagation_timeout_seconds,id]).map_err(db_error)?;
    accounts::audit(&tx, &session, "domain_settings_updated", "domain", &id)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(load(&db, &id, &domain)?))
}

pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Settings>, ApiError> {
    let session = require_write(&state, &headers)?;
    if !state
        .security
        .allow(format!("domain-proof:{}", session.user_id), 20, unix_now())
    {
        return Err(security::limited());
    }
    let (domain, settings) = {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let domain = owned(&db, &session.tenant_id, &id)?;
        let settings = load(&db, &id, &domain)?;
        (domain, settings)
    };
    if settings.verification_status == "verified" {
        return Ok(Json(settings));
    }
    let expected = settings
        .verification_record
        .as_ref()
        .and_then(|r| r["value"].as_str())
        .unwrap_or_default();
    let resolver = hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "无法读取 Server DNS 配置"))?;
    let records = tokio::time::timeout(
        Duration::from_secs(8),
        resolver.txt_lookup(format!("_nexo-verification.{domain}")),
    )
    .await
    .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "域名归属检查超时，请稍后重试"))?
    .map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "尚未查询到归属 TXT 记录，请核对记录并等待 DNS 生效",
        )
    })?;
    let matches = records
        .iter()
        .any(|r| r.txt_data().concat() == expected.as_bytes());
    if !matches {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "TXT 记录与当前工作空间的验证值不一致",
        ));
    }
    require_write(&state, &headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    owned(&db, &session.tenant_id, &id)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    claim(&tx, &session.tenant_id, &id, &domain)?;
    accounts::audit(&tx, &session, "domain_verified", "domain", &id)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(load(&db, &id, &domain)?))
}

/// 文件名由 Server 生成；凭据不能成为表达式，也不能向 Caddy 注入任意文件路径。
pub fn valid_token(token: &str) -> bool {
    let legacy = (35..=50).contains(&token.len());
    let modern = token
        .strip_prefix("cfut_")
        .or_else(|| token.strip_prefix("cfat_"))
        .is_some_and(|s| (32..=256).contains(&s.len()));
    (legacy || modern)
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

async fn cloudflare_json(response: reqwest::Response) -> Result<Value, ApiError> {
    if !response.status().is_success() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Cloudflare 拒绝操作，请检查 Token 的 Zone Read、DNS Edit 权限及域名范围",
        ));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|_| ApiError::new(StatusCode::BAD_GATEWAY, "Cloudflare 返回了无法识别的响应"))?;
    if body["success"] != true {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Cloudflare 操作失败，请核对 Token 权限",
        ));
    }
    Ok(body)
}

/// 通过实际创建并删除归属 TXT 检查 Zone Read 和 DNS Edit；不改用户的 A/AAAA 访问解析。
async fn verify_cloudflare(token: &str, domain: &str, proof: &str) -> Result<(), ApiError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(db_error)?;
    let mut zone_name = domain;
    let zone = loop {
        let response = client
            .get("https://api.cloudflare.com/client/v4/zones")
            .bearer_auth(token)
            .query(&[("name", zone_name)])
            .send()
            .await
            .map_err(|_| {
                ApiError::new(StatusCode::BAD_GATEWAY, "无法连接 Cloudflare，请稍后重试")
            })?;
        let body = cloudflare_json(response).await?;
        if let Some(id) = body["result"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["name"].as_str() == Some(zone_name)))
            .and_then(|r| r["id"].as_str())
        {
            break id.to_owned();
        }
        let Some((_, parent)) = zone_name.split_once('.') else {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "此 Token 无权管理所填域名",
            ));
        };
        zone_name = parent;
    };
    let url = format!("https://api.cloudflare.com/client/v4/zones/{zone}/dns_records");
    let response=client.post(&url).bearer_auth(token).json(&json!({"type":"TXT","name":format!("_nexo-verification.{domain}"),"content":proof,"ttl":120})).send().await.map_err(|_|ApiError::new(StatusCode::BAD_GATEWAY,"Cloudflare DNS 写入失败，请稍后重试"))?;
    let record = cloudflare_json(response).await?;
    let id = record["result"]["id"]
        .as_str()
        .ok_or_else(|| ApiError::new(StatusCode::BAD_GATEWAY, "Cloudflare 未返回验证记录 ID"))?;
    let response = client
        .delete(format!("{url}/{id}"))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "验证记录清理失败，请在 Cloudflare 清理归属 TXT 后重试",
            )
        })?;
    cloudflare_json(response).await?;
    Ok(())
}

pub async fn set_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<CredentialInput>,
) -> Result<Json<Settings>, ApiError> {
    let session = require_write(&state, &headers)?;
    if !state.security.allow(
        format!("domain-credential:{}", session.user_id),
        10,
        unix_now(),
    ) {
        return Err(security::limited());
    }
    let token = input.token.trim();
    if !valid_token(token) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Cloudflare Token 格式无效，请粘贴完整 Token",
        ));
    }
    let (domain, proof) = {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let domain = owned(&db, &session.tenant_id, &id)?;
        let proof: String = db
            .query_row(
                "SELECT verification_token FROM domain_settings WHERE domain_id=?1",
                [&id],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        (domain, proof)
    };
    let proof = if proof.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        proof
    };
    verify_cloudflare(token, &domain, &proof).await?;
    // 网络检查之后重新鉴权：管理员可能在检查期间停用了该账号。
    let session_now = require_write(&state, &headers)?;
    if session_now.tenant_id != session.tenant_id {
        return Err(ApiError::session_expired());
    }
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    owned(&db, &session.tenant_id, &id)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    claim(&tx, &session.tenant_id, &id, &domain)?;
    let file = write_credential(
        &state
            .domain_runtime
            .supervisor
            .config()
            .cloudflare_token_root,
        &id,
        token,
    )
    .map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "无法安全保存 Cloudflare 凭据",
        )
    })?;
    tx.execute("UPDATE domain_settings SET credential_file=?1,certificate_mode='cloudflare_dns' WHERE domain_id=?2",params![file,id]).map_err(db_error)?;
    accounts::audit(&tx, &session, "domain_credential_updated", "domain", &id)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(load(&db, &id, &domain)?))
}

/// 不覆盖 Applied 配置引用的 Secret；即使新配置失败或进程意外退出，旧凭据仍可用于恢复。
pub fn write_credential(root: &FsPath, id: &str, token: &str) -> Result<String> {
    anyhow::ensure!(Uuid::parse_str(id).is_ok(), "域名 ID 无效");
    let directory = root.join(id);
    fs::create_dir_all(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    }
    let name = format!("credential-{}.token", Uuid::new_v4());
    let path = directory.join(&name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let mut file = options.open(&path)?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    Ok(name)
}

pub fn credential_path(root: &FsPath, id: &str, file: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        Uuid::parse_str(id).is_ok()
            && file.starts_with("credential-")
            && file.ends_with(".token")
            && file.len() == 53
            && !file.contains(['/', '\\']),
        "凭据引用无效"
    );
    let path = root.join(id).join(file);
    Ok(if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn new_dns_mode_requires_a_domain_credential() {
        let (state, headers) = crate::tests::domain_fixture();
        let domain = crate::tests::add_test_domain(&state, &headers, "no-token.test")
            .await
            .unwrap();
        assert_eq!(
            load(&state.db.lock().unwrap(), &domain.id, &domain.domain)
                .unwrap()
                .dns
                .dns_resolvers,
            ["223.5.5.5:53", "223.6.6.6:53"]
        );
        let error = update(
            State(state.clone()),
            headers,
            Path(domain.id.clone()),
            Json(SettingsInput {
                certificate_mode: "cloudflare_dns".into(),
                dns: DnsSettings::default(),
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            load(&state.db.lock().unwrap(), &domain.id, &domain.domain)
                .unwrap()
                .certificate_mode,
            "http01"
        );
    }
    #[test]
    fn tokens_match_cloudflare_module_and_cannot_inject_placeholders() {
        for token in [
            "a".repeat(40),
            format!("cfut_{}", "a".repeat(256)),
            format!("cfat_{}", "a".repeat(100)),
        ] {
            assert!(valid_token(&token));
        }
        for token in [
            "{file./etc/passwd}".to_owned(),
            "cfut_short".into(),
            format!("cfut_{}", "a".repeat(257)),
            "a".repeat(51),
            format!("{}\n", "a".repeat(40)),
        ] {
            assert!(!valid_token(&token));
        }
    }
    #[test]
    fn dns_values_are_bounded_and_normalized() {
        let mut value = DnsSettings {
            dns_resolvers: vec![
                "1.1.1.1".into(),
                "1.1.1.1:53".into(),
                "[2606:4700:4700::1111]:5353".into(),
            ],
            dns_propagation_delay_seconds: Some(10),
            dns_propagation_timeout_seconds: Some(60),
        };
        value.validate().unwrap();
        assert_eq!(value.dns_resolvers.len(), 2);
        assert_eq!(value.dns_resolvers[0], "1.1.1.1:53");
        for resolver in ["https://dns.example.com", "1.1.1.1:0", "0.0.0.0"] {
            value.dns_resolvers = vec![resolver.into()];
            assert!(value.validate().is_err());
        }
        value.dns_resolvers.clear();
        value.validate().unwrap();
        assert_eq!(value.dns_resolvers, ["223.5.5.5:53", "223.6.6.6:53"]);
        value.dns_propagation_timeout_seconds = Some(0);
        assert!(value.validate().is_err());
    }
    #[tokio::test]
    async fn unverified_domains_do_not_reserve_ranges_and_verified_ranges_cannot_overlap() {
        let (state, admin) = crate::tests::domain_fixture();
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "INSERT INTO tenants(id,name,created_at) VALUES ('other','other',0)",
                [],
            )
            .unwrap();
        }
        let first = crate::tests::add_test_domain(&state, &admin, "example.test")
            .await
            .unwrap();
        assert_eq!(
            load(&state.db.lock().unwrap(), &first.id, &first.domain)
                .unwrap()
                .verification_status,
            "pending"
        );
        let mut other = admin.clone();
        other.insert("x-nexo-internal-workspace", "other".parse().unwrap());
        let second = crate::tests::add_test_domain(&state, &other, "example.test")
            .await
            .unwrap();
        let child = crate::tests::add_test_domain(&state, &admin, "sub.example.test")
            .await
            .unwrap();
        let db = state.db.lock().unwrap();
        claim(&db, "other", &second.id, &second.domain).unwrap();
        assert_eq!(
            claim(&db, "default", &first.id, &first.domain)
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            claim(&db, "default", &child.id, &child.domain)
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        let settings = load(&db, &first.id, &first.domain).unwrap();
        assert_eq!(settings.certificate_mode, "http01");
        assert_eq!(settings.verification_status, "pending");
    }
    #[test]
    fn new_credentials_never_overwrite_the_previous_applied_file() {
        let root = std::env::temp_dir().join(format!("nexo-token-{}", Uuid::new_v4()));
        let id = Uuid::new_v4().to_string();
        let first = write_credential(&root, &id, &"a".repeat(40)).unwrap();
        let second = write_credential(&root, &id, &"b".repeat(40)).unwrap();
        assert_ne!(first, second);
        let path = credential_path(&root, &id, &first).unwrap();
        assert!(path.is_absolute());
        assert_eq!(fs::read_to_string(&path).unwrap(), "a".repeat(40));
        assert!(credential_path(&root, &id, "../../private.token").is_err());
        assert!(
            !crate::caddy::redact(&format!("{} {}", "a".repeat(40), "b".repeat(40)), &root)
                .contains(&"a".repeat(40))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
