//! DNS 提供商适配：记录 ID 和精确值用于撤销，错误不包含凭据或提供商原始响应。
use anyhow::{Context, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Duration};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credential {
    Cloudflare {
        token: String,
    },
    Alidns {
        access_key_id: String,
        access_key_secret: String,
    },
    Tencentcloud {
        secret_id: String,
        secret_key: String,
    },
}
impl Credential {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Cloudflare { .. } => "cloudflare",
            Self::Alidns { .. } => "alidns",
            Self::Tencentcloud { .. } => "tencentcloud",
        }
    }
    pub fn validate(&self) -> Result<()> {
        let values = match self {
            Self::Cloudflare { token } => vec![token],
            Self::Alidns {
                access_key_id,
                access_key_secret,
            } => vec![access_key_id, access_key_secret],
            Self::Tencentcloud {
                secret_id,
                secret_key,
            } => vec![secret_id, secret_key],
        };
        anyhow::ensure!(
            values.iter().all(|v| !v.is_empty()
                && v.len() <= 512
                && v.bytes().all(|b| b.is_ascii_graphic())),
            "DNS 凭据格式无效"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Record {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub value: String,
    pub ttl: u32,
    pub proxied: bool,
}

/// 一个已验证的 DNS Zone；仅接受该 Zone 内的完整主机名。
#[derive(Clone)]
pub struct Zone {
    client: reqwest::Client,
    credential: Credential,
    pub name: String,
    id: String,
    #[cfg(test)]
    endpoint: Option<String>,
}

/// 只保存字段到私有文件的引用；Caddy 直接读取各字段，普通 API 从不返回秘密。
#[derive(Serialize, Deserialize)]
struct StoredCredential {
    fields: BTreeMap<String, String>,
}

pub fn migrate(db: &rusqlite::Connection) -> Result<()> {
    if !db.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('domain_settings') WHERE name='dns_provider')", [], |r| r.get::<_, bool>(0))? {
        db.execute("ALTER TABLE domain_settings ADD COLUMN dns_provider TEXT NOT NULL DEFAULT 'cloudflare'", [])?;
    }
    Ok(())
}

pub fn load(db: &rusqlite::Connection, root: &std::path::Path, id: &str) -> Result<Credential> {
    let (provider, file): (String, Option<String>) = db.query_row(
        "SELECT dns_provider,credential_file FROM domain_settings WHERE domain_id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let path = crate::domains::credential_path(root, id, &file.context("请先配置 DNS 凭据")?)?;
    let stored = std::fs::read_to_string(path).context("DNS 凭据文件不可读")?;
    if provider == "cloudflare" {
        return Ok(Credential::Cloudflare { token: stored });
    }
    let refs: StoredCredential = serde_json::from_str(&stored).context("DNS 凭据引用格式错误")?;
    let mut value = json!({"provider":provider});
    for (key, file) in refs.fields {
        value[&key] = json!(std::fs::read_to_string(crate::domains::credential_path(
            root, id, &file
        )?)
        .context("DNS 凭据文件不可读")?);
    }
    serde_json::from_value(value).context("DNS 凭据类型错误")
}

pub fn caddy_config(db: &rusqlite::Connection, root: &std::path::Path, id: &str) -> Result<Value> {
    let (provider, file): (String, Option<String>) = db.query_row(
        "SELECT dns_provider,credential_file FROM domain_settings WHERE domain_id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let path = crate::domains::credential_path(root, id, &file.context("DNS 凭据尚未配置")?)?;
    if provider == "cloudflare" {
        return Ok(json!({"name":"cloudflare","api_token":format!("{{file.{}}}",path.display())}));
    }
    let refs: StoredCredential = serde_json::from_slice(&std::fs::read(path)?)?;
    let mut config = json!({"name":provider});
    for (key, file) in refs.fields {
        // TencentCloud 的 Go JSON 字段与 Caddyfile 字段名不同。
        let field = match (provider.as_str(), key.as_str()) {
            ("tencentcloud", "secret_id") => "SecretId",
            ("tencentcloud", "secret_key") => "SecretKey",
            _ => key.as_str(),
        };
        config[field] = json!(format!(
            "{{file.{}}}",
            crate::domains::credential_path(root, id, &file)?.display()
        ));
    }
    Ok(config)
}

pub fn ensure_switch(db: &rusqlite::Connection, id: &str, provider: &str) -> Result<()> {
    let current: String = db.query_row(
        "SELECT dns_provider FROM domain_settings WHERE domain_id=?1",
        [id],
        |r| r.get(0),
    )?;
    if current != provider {
        let active:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM direct_dns_records WHERE domain_id=?1 AND kind!='A') OR EXISTS(SELECT 1 FROM relay_dns_records WHERE domain_id=?1) OR EXISTS(SELECT 1 FROM relay_dns_originals WHERE domain_id=?1) OR EXISTS(SELECT 1 FROM tunnels WHERE public_domain_id=?1 AND ipv6_direct_enabled=1 AND deleted_at IS NULL)",[id],|r|r.get(0))?;
        anyhow::ensure!(!active, "请先关闭直连并完成 DNS 清理，再更换 DNS 提供商");
        // A 记录留在 DNS；提供商变更后旧 ID 无效，下次按 Server 地址重新确认归属。
        db.execute(
            "DELETE FROM direct_dns_records WHERE domain_id=?1 AND kind='A'",
            [id],
        )?;
    }
    Ok(())
}

pub async fn set_credential(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::Json(input): axum::Json<Credential>,
) -> Result<axum::Json<crate::domains::Settings>, crate::ApiError> {
    use crate::*;
    let session = require_write(&state, &headers)?;
    input
        .validate()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "DNS 凭据格式无效"))?;
    if !state.security.allow(
        format!("domain-credential:{}", session.user_id),
        10,
        unix_now(),
    ) {
        return Err(security::limited());
    }
    let domain = domains::owned(
        &*state.db.lock().map_err(|_| db_error("数据库锁不可用"))?,
        &session.tenant_id,
        &id,
    )?;
    let zone = Zone::discover(input.clone(), &domain)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, e.to_string()))?;
    let proof = Record {
        id: String::new(),
        name: format!("_nexo-verification.{domain}"),
        kind: "TXT".into(),
        value: uuid::Uuid::new_v4().to_string(),
        ttl: 600,
        proxied: false,
    };
    let created = zone
        .write(&proof)
        .await
        .map_err(|e| ApiError::new(StatusCode::BAD_GATEWAY, e.to_string()))?;
    zone.remove(&created).await.map_err(|_| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "DNS 权限已验证，但临时 TXT 清理失败，请清理 _nexo-verification 记录后重试",
        )
    })?;
    let _dns_guard = state.tunnel_runtime.direct.dns_lock.lock().await;
    let session = require_write(&state, &headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    domains::owned(&db, &session.tenant_id, &id)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    domains::claim(&tx, &session.tenant_id, &id, &domain)?;
    ensure_switch(&tx, &id, input.name())
        .map_err(|e| ApiError::new(StatusCode::CONFLICT, e.to_string()))?;
    let root = &state
        .domain_runtime
        .supervisor
        .config()
        .cloudflare_token_root;
    let file = if let Credential::Cloudflare { token } = &input {
        domains::write_credential(root, &id, token).map_err(db_error)?
    } else {
        let value = serde_json::to_value(&input).map_err(db_error)?;
        let mut fields = BTreeMap::new();
        for (key, value) in value.as_object().unwrap() {
            if key != "provider" {
                fields.insert(
                    key.clone(),
                    domains::write_credential(root, &id, value.as_str().unwrap())
                        .map_err(db_error)?,
                );
            }
        }
        domains::write_credential(
            root,
            &id,
            &serde_json::to_string(&StoredCredential { fields }).map_err(db_error)?,
        )
        .map_err(db_error)?
    };
    tx.execute("UPDATE domain_settings SET credential_file=?1,dns_provider=?2,certificate_mode='cloudflare_dns' WHERE domain_id=?3",rusqlite::params![file,input.name(),id]).map_err(db_error)?;
    accounts::audit(&tx, &session, "domain_credential_updated", "domain", &id)?;
    tx.commit().map_err(db_error)?;
    Ok(axum::Json(domains::load(&db, &id, &domain)?))
}
fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
fn mac(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut signer = Hmac::<Sha256>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
    signer.update(bytes);
    signer.finalize().into_bytes().to_vec()
}
impl Zone {
    fn endpoint(&self, url: &str) -> String {
        #[cfg(test)]
        if let Some(base) = &self.endpoint {
            let url = reqwest::Url::parse(url).expect("static provider URL");
            return format!("{base}{}", url.path());
        }
        url.into()
    }
    #[cfg(test)]
    pub(crate) fn mock(credential: Credential, endpoint: String) -> Self {
        Self {
            client: reqwest::Client::builder().no_proxy().build().unwrap(),
            credential,
            name: "direct.test".into(),
            id: "zone".into(),
            endpoint: Some(endpoint),
        }
    }

    pub async fn discover(credential: Credential, domain: &str) -> Result<Self> {
        credential.validate()?;
        let mut zone = Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()?,
            credential,
            name: domain.into(),
            id: String::new(),
            #[cfg(test)]
            endpoint: None,
        };
        loop {
            let found = match &zone.credential {
                Credential::Cloudflare { token } => {
                    let response = zone
                        .client
                        .get("https://api.cloudflare.com/client/v4/zones")
                        .bearer_auth(token)
                        .query(&[("name", &zone.name)])
                        .send()
                        .await
                        .context("无法连接 Cloudflare")?;
                    let data = Self::cloudflare(response).await?;
                    data.as_array()
                        .and_then(|v| v.iter().find(|v| v["name"] == zone.name))
                        .and_then(|v| v["id"].as_str())
                        .map(str::to_owned)
                }
                Credential::Alidns { .. } => zone
                    .rpc("DescribeDomainInfo", json!({"DomainName":zone.name}))
                    .await
                    .ok()
                    .and_then(|v| v["DomainId"].as_str().map(str::to_owned)),
                Credential::Tencentcloud { .. } => zone
                    .rpc("DescribeDomain", json!({"Domain":zone.name}))
                    .await
                    .ok()
                    .and_then(|v| v["DomainInfo"]["Id"].as_u64().map(|v| v.to_string())),
            };
            if let Some(id) = found {
                zone.id = id;
                return Ok(zone);
            }
            let (_, parent) = zone
                .name
                .split_once('.')
                .context("凭据无权管理该域名或 DNS 服务商不可用")?;
            zone.name = parent.to_owned();
        }
    }
    fn relative(&self, host: &str) -> Result<String> {
        if host == self.name {
            return Ok("@".into());
        }
        host.strip_suffix(&format!(".{}", self.name))
            .map(str::to_owned)
            .context("DNS 记录不属于已验证域名")
    }
    async fn cloudflare(response: reqwest::Response) -> Result<Value> {
        let success = response.status().is_success();
        let value: Value = response.json().await.context("Cloudflare 响应格式错误")?;
        anyhow::ensure!(
            success && value["success"] == true,
            "Cloudflare DNS 请求失败，请检查权限、配额和记录冲突"
        );
        Ok(value["result"].clone())
    }
    async fn rpc(&self, action: &str, payload: Value) -> Result<Value> {
        let response = match &self.credential {
            Credential::Alidns {
                access_key_id,
                access_key_secret,
            } => {
                let mut params = BTreeMap::<String, String>::new();
                for (k, v) in payload.as_object().context("DNS 请求格式错误")? {
                    params.insert(
                        k.clone(),
                        v.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| v.to_string()),
                    );
                }
                let now = time::OffsetDateTime::now_utc();
                let timestamp = format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                    now.year(),
                    u8::from(now.month()),
                    now.day(),
                    now.hour(),
                    now.minute(),
                    now.second()
                );
                for (k, v) in [
                    ("Action", action.to_owned()),
                    ("Version", "2015-01-09".into()),
                    ("Format", "JSON".into()),
                    ("AccessKeyId", access_key_id.clone()),
                    ("SignatureMethod", "HMAC-SHA1".into()),
                    ("SignatureVersion", "1.0".into()),
                    ("SignatureNonce", uuid::Uuid::new_v4().to_string()),
                    ("Timestamp", timestamp),
                ] {
                    params.insert(k.into(), v);
                }
                let canonical = params
                    .iter()
                    .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
                    .collect::<Vec<_>>()
                    .join("&");
                let mut signer =
                    Hmac::<sha1::Sha1>::new_from_slice(format!("{access_key_secret}&").as_bytes())?;
                signer.update(format!("POST&%2F&{}", encode(&canonical)).as_bytes());
                params.insert(
                    "Signature".into(),
                    base64::engine::general_purpose::STANDARD
                        .encode(signer.finalize().into_bytes()),
                );
                self.client
                    .post(self.endpoint("https://alidns.aliyuncs.com/"))
                    .form(&params)
                    .send()
                    .await
                    .context("无法连接阿里云 DNS")?
            }
            Credential::Tencentcloud {
                secret_id,
                secret_key,
            } => {
                let now = time::OffsetDateTime::now_utc();
                let date = format!(
                    "{:04}-{:02}-{:02}",
                    now.year(),
                    u8::from(now.month()),
                    now.day()
                );
                let timestamp = now.unix_timestamp();
                let body = serde_json::to_string(&payload)?;
                let canonical = format!("POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:dnspod.tencentcloudapi.com\n\ncontent-type;host\n{:x}",Sha256::digest(body.as_bytes()));
                let scope = format!("{date}/dnspod/tc3_request");
                let to_sign = format!(
                    "TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{:x}",
                    Sha256::digest(canonical.as_bytes())
                );
                let date_key = mac(format!("TC3{secret_key}").as_bytes(), date.as_bytes());
                let service_key = mac(&date_key, b"dnspod");
                let signature =
                    hex::encode(mac(&mac(&service_key, b"tc3_request"), to_sign.as_bytes()));
                self.client.post(self.endpoint("https://dnspod.tencentcloudapi.com/")).header("Content-Type","application/json; charset=utf-8").header("X-TC-Action",action).header("X-TC-Version","2021-03-23").header("X-TC-Timestamp",timestamp.to_string()).header("Authorization",format!("TC3-HMAC-SHA256 Credential={secret_id}/{scope}, SignedHeaders=content-type;host, Signature={signature}")).body(body).send().await.context("无法连接腾讯云 DNSPod")?
            }
            _ => anyhow::bail!("DNS 提供商请求类型不匹配"),
        };
        let success = response.status().is_success();
        let body: Value = response.json().await.context("DNS 服务商响应格式错误")?;
        if action == "DescribeRecordList"
            && matches!(
                body["Response"]["Error"]["Code"].as_str(),
                Some("ResourceNotFound.NoDataOfRecord")
                    | Some("ResourceNotFound.NoDataOfRecordList")
            )
        {
            return Ok(json!({"RecordList":[]}));
        }
        anyhow::ensure!(
            success && body["Code"].is_null() && body["Response"]["Error"].is_null(),
            "DNS 请求失败，请检查权限、配额和记录冲突"
        );
        Ok(if body["Response"].is_object() {
            body["Response"].clone()
        } else {
            body
        })
    }
    pub async fn records(&self, host: &str) -> Result<Vec<Record>> {
        let relative = self.relative(host)?;
        let mut result = Vec::new();
        let mut page = 1;
        loop {
            let rows = match &self.credential {
                Credential::Cloudflare {token} => {
                    let r = self.client.get(self.endpoint(&format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records",self.id))).bearer_auth(token).query(&[("name",host.to_owned()),("page",page.to_string()),("per_page","100".into())]).send().await.context("Cloudflare DNS 查询失败")?;
                    Self::cloudflare(r).await?
                }
                Credential::Alidns {..} => self.rpc("DescribeDomainRecords",json!({"DomainName":self.name,"PageNumber":page,"PageSize":100,"RRKeyWord":relative,"SearchMode":"EXACT"})).await?["DomainRecords"]["Record"].clone(),
                Credential::Tencentcloud {..} => self.rpc("DescribeRecordList",json!({"Domain":self.name,"Subdomain":relative,"Offset":(page-1)*100,"Limit":100})).await?["RecordList"].clone(),
            };
            let rows = rows.as_array().context("DNS 记录响应无效")?;
            for row in rows {
                let (id, name, kind, value, ttl) = match &self.credential {
                    Credential::Cloudflare { .. } => (
                        row["id"].as_str().unwrap_or_default().to_owned(),
                        row["name"].as_str().unwrap_or_default(),
                        &row["type"],
                        &row["content"],
                        &row["ttl"],
                    ),
                    Credential::Alidns { .. } => (
                        row["RecordId"].as_str().unwrap_or_default().to_owned(),
                        row["RR"].as_str().unwrap_or_default(),
                        &row["Type"],
                        &row["Value"],
                        &row["TTL"],
                    ),
                    Credential::Tencentcloud { .. } => (
                        row["RecordId"].as_u64().unwrap_or_default().to_string(),
                        row["Name"].as_str().unwrap_or_default(),
                        &row["Type"],
                        &row["Value"],
                        &row["TTL"],
                    ),
                };
                if name != host && name != relative {
                    continue;
                }
                anyhow::ensure!(!id.is_empty(), "DNS 记录 ID 无效");
                result.push(Record {
                    id,
                    name: host.into(),
                    kind: kind.as_str().context("DNS 类型缺失")?.into(),
                    value: value.as_str().context("DNS 值缺失")?.into(),
                    ttl: ttl.as_u64().unwrap_or(600) as u32,
                    proxied: row["proxied"] == true,
                });
            }
            if rows.len() < 100 {
                break;
            }
            page += 1;
            anyhow::ensure!(page <= 100, "DNS 记录数量过多，请缩小配置范围");
        }
        Ok(result)
    }
    pub async fn write(&self, record: &Record) -> Result<Record> {
        anyhow::ensure!(!record.proxied, "访问记录必须使用直接解析");
        self.write_record(record).await
    }
    /// 仅供一次性解析失败时恢复服务商读取的原值；正常写入仍禁止启用代理。
    pub async fn restore(&self, record: &Record) -> Result<Record> {
        self.write_record(record).await
    }
    async fn write_record(&self, record: &Record) -> Result<Record> {
        let relative = self.relative(&record.name)?;
        let create = record.id.is_empty();
        let id = match &self.credential {
            Credential::Cloudflare { token } => {
                let url = format!(
                    "https://api.cloudflare.com/client/v4/zones/{}/dns_records{}",
                    self.id,
                    if create {
                        String::new()
                    } else {
                        format!("/{}", record.id)
                    }
                );
                let url = self.endpoint(&url);
                let builder = if create {
                    self.client.post(url)
                } else {
                    self.client.put(url)
                };
                let r = builder.bearer_auth(token).json(&json!({"name":record.name,"type":record.kind,"content":record.value,"ttl":record.ttl,"proxied":record.proxied})).send().await.context("Cloudflare DNS 写入失败")?;
                Self::cloudflare(r).await?["id"]
                    .as_str()
                    .context("DNS 写入未返回 ID")?
                    .to_owned()
            }
            Credential::Alidns { .. } => {
                let mut payload =
                    json!({"RR":relative,"Type":record.kind,"Value":record.value,"TTL":record.ttl});
                if create {
                    payload["DomainName"] = json!(self.name);
                } else {
                    payload["RecordId"] = json!(record.id);
                }
                self.rpc(
                    if create {
                        "AddDomainRecord"
                    } else {
                        "UpdateDomainRecord"
                    },
                    payload,
                )
                .await?["RecordId"]
                    .as_str()
                    .context("DNS 写入未返回 ID")?
                    .into()
            }
            Credential::Tencentcloud { .. } => {
                let mut payload = json!({"Domain":self.name,"SubDomain":relative,"RecordType":record.kind,"RecordLine":"默认","Value":record.value,"TTL":record.ttl});
                if !create {
                    payload["RecordId"] = json!(record.id.parse::<u64>()?);
                }
                self.rpc(
                    if create {
                        "CreateRecord"
                    } else {
                        "ModifyRecord"
                    },
                    payload,
                )
                .await?["RecordId"]
                    .as_u64()
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| record.id.clone())
            }
        };
        anyhow::ensure!(!id.is_empty(), "DNS 写入未返回记录 ID");
        Ok(Record {
            id,
            ..record.clone()
        })
    }
    /// 删除前再次核对 ID、类型、内容及代理标记；外部修改后禁止盲删。
    pub async fn remove(&self, record: &Record) -> Result<()> {
        let current = self.records(&record.name).await?;
        let Some(found) = current.iter().find(|r| r.id == record.id) else {
            return Ok(());
        };
        anyhow::ensure!(found == record, "DNS 记录已被外部修改，请人工核对");
        match &self.credential {
            Credential::Cloudflare { token } => {
                Self::cloudflare(
                    self.client
                        .delete(self.endpoint(&format!(
                            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
                            self.id, record.id
                        )))
                        .bearer_auth(token)
                        .send()
                        .await
                        .context("DNS 清理失败")?,
                )
                .await?;
            }
            Credential::Alidns { .. } => {
                self.rpc("DeleteDomainRecord", json!({"RecordId":record.id}))
                    .await?;
            }
            Credential::Tencentcloud { .. } => {
                self.rpc(
                    "DeleteRecord",
                    json!({"Domain":self.name,"RecordId":record.id.parse::<u64>()?}),
                )
                .await?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
