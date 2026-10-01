//! 主域名和泛域名的访问解析只由用户操作写入，不参与 DDNS 或后台协调。
//! 预览使用服务商真实记录；写前再次比较，失败恢复也只处理本次已确认的改动。
use crate::dns_provider::{Record, Zone};
use crate::*;
use std::net::Ipv4Addr;

/// 预览同时作为确认请求中的期望值；目标地址和主机名始终由 Server 重新计算。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Preview {
    pub ipv4: Ipv4Addr,
    pub provider: String,
    // 凭据文件每次保存都会产生新 ID，用现有引用核对预览，不返回密钥内容。
    pub credential_revision: String,
    pub hosts: Vec<HostPreview>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HostPreview {
    pub hostname: String,
    pub existing: Vec<Record>,
    pub action: String,
    pub blocked: Option<String>,
}
#[derive(Deserialize)]
pub struct ApplyInput {
    pub preview: Preview,
    #[serde(default)]
    pub confirm_takeover: bool,
}
#[derive(Debug, Serialize)]
pub struct ApplyResult {
    pub hosts: Vec<HostResult>,
}
#[derive(Debug, Serialize)]
pub struct HostResult {
    pub hostname: String,
    pub status: String,
    pub error: Option<String>,
}

struct Configuration {
    domain: String,
    settings: super::Settings,
    ipv4: Ipv4Addr,
}

fn context(state: &AppState, tenant: &str, id: &str) -> Result<Configuration, ApiError> {
    let (domain, settings) = {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        let domain = super::owned(&db, tenant, id)?;
        let settings = super::load(&db, id, &domain)?;
        (domain, settings)
    };
    if settings.verification_status != "verified" || !settings.credential_configured {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "请先验证并保存域名的 DNS 凭据",
        ));
    }
    let ipv4 = crate::server_settings::relay_ipv4(state)?
        .and_then(|ip| crate::transport::public_ipv4(ip.into()))
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "请管理员在「服务器设置」中填写有效的公网 IPv4",
            )
        })?;
    Ok(Configuration {
        domain,
        settings,
        ipv4,
    })
}

fn unchanged_context(
    state: &AppState,
    tenant: &str,
    id: &str,
    expected: &Configuration,
) -> Result<(), ApiError> {
    let current = context(state, tenant, id)?;
    if current.domain != expected.domain
        || current.ipv4 != expected.ipv4
        || current.settings.dns_provider != expected.settings.dns_provider
        || current.settings.credential_file != expected.settings.credential_file
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "域名、DNS 凭据或公网 IPv4 已变化，请重新预览解析",
        ));
    }
    Ok(())
}

fn access_record(record: &Record) -> bool {
    matches!(record.kind.as_str(), "A" | "CNAME")
}
fn sorted(mut records: Vec<Record>) -> Vec<Record> {
    records.sort_by(|a, b| a.id.cmp(&b.id));
    records
}
async fn read_preview(zone: &Zone, current: &Configuration) -> anyhow::Result<Preview> {
    let mut hosts = Vec::new();
    for hostname in [current.domain.clone(), format!("*.{}", current.domain)] {
        let existing = sorted(zone.records(&hostname).await?);
        let access: Vec<_> = existing.iter().filter(|r| access_record(r)).collect();
        let action = if access.is_empty() {
            "create"
        } else if access.len() == 1
            && access[0].kind == "A"
            && access[0].value == current.ipv4.to_string()
            && !access[0].proxied
        {
            "reuse"
        } else {
            "takeover"
        };
        let blocked = existing
            .iter()
            .any(|r| !access_record(r) && r.proxied)
            .then(|| "其他记录启用了 DNS 代理，请先在服务商处理；本次不会修改 AAAA 等记录".into());
        hosts.push(HostPreview {
            hostname,
            existing,
            action: action.into(),
            blocked,
        });
    }
    Ok(Preview {
        ipv4: current.ipv4,
        provider: current.settings.dns_provider.clone(),
        credential_revision: current.settings.credential_file.clone().unwrap_or_default(),
        hosts,
    })
}

pub async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Preview>, ApiError> {
    let session = require_session(&state, &headers)?;
    let current = context(&state, &session.tenant_id, &id)?;
    let zone = crate::direct::dns::zone(&state, &id)
        .await
        .map_err(provider_error)?;
    let value = read_preview(&zone, &current)
        .await
        .map_err(provider_error)?;
    let after = require_session(&state, &headers)?;
    if after.tenant_id != session.tenant_id {
        return Err(ApiError::session_expired());
    }
    unchanged_context(&state, &session.tenant_id, &id, &current)?;
    Ok(Json(value))
}
fn provider_error(error: anyhow::Error) -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, error.to_string())
}

pub async fn apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ApplyInput>,
) -> Result<Json<ApplyResult>, ApiError> {
    let session = require_write(&state, &headers)?;
    let _guard = state.tunnel_runtime.direct.dns_lock.lock().await;
    let current = context(&state, &session.tenant_id, &id)?;
    let zone = crate::direct::dns::zone(&state, &id)
        .await
        .map_err(provider_error)?;
    let latest = read_preview(&zone, &current)
        .await
        .map_err(provider_error)?;
    let after = require_write(&state, &headers)?;
    if after.tenant_id != session.tenant_id {
        return Err(ApiError::session_expired());
    }
    unchanged_context(&state, &session.tenant_id, &id, &current)?;
    if latest != input.preview {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "解析记录或公网 IPv4 已变化，请重新预览后确认",
        ));
    }
    if let Some(host) = latest.hosts.iter().find(|h| h.blocked.is_some()) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("{}：{}", host.hostname, host.blocked.as_deref().unwrap()),
        ));
    }
    if latest.hosts.iter().any(|h| h.action == "takeover") && !input.confirm_takeover {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "现有解析需要接管，请核对预览并明确确认接管",
        ));
    }
    let mut hosts = Vec::new();
    for host in latest.hosts {
        let attempt = write_host(&state, &headers, &session, &id, &zone, &current, &host).await;
        let (status, error) = match attempt {
            Ok(status) => (status.into(), None),
            Err(error) => ("failed".into(), Some(error.to_string())),
        };
        hosts.push(HostResult {
            hostname: host.hostname,
            status,
            error,
        });
    }
    Ok(Json(ApplyResult { hosts }))
}

/// 每一步记录原值与实际返回值，回滚前比较整个主机名快照，外部新增和编辑都不能被覆盖。
#[derive(Clone, Serialize)]
struct Change {
    before: Option<Record>,
    after: Option<Record>,
}
fn save_changes(state: &AppState, operation: &str, changes: &[Change]) -> anyhow::Result<()> {
    state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?
        .execute(
            "UPDATE domain_dns_operations SET changes=?2 WHERE id=?1",
            params![operation, serde_json::to_string(changes)?],
        )?;
    Ok(())
}
fn expected_records(original: &[Record], changes: &[Change]) -> Vec<Record> {
    let mut expected = original.to_vec();
    for change in changes {
        if let Some(before) = &change.before {
            expected.retain(|r| r.id != before.id);
        }
        if let Some(after) = &change.after {
            expected.push(after.clone());
        }
    }
    sorted(expected)
}
fn check_write(
    state: &AppState,
    headers: &HeaderMap,
    tenant: &str,
    id: &str,
    current: &Configuration,
) -> anyhow::Result<()> {
    let session = require_write(state, headers).map_err(|e| anyhow::anyhow!(e.message))?;
    anyhow::ensure!(
        session.tenant_id == tenant,
        "当前工作空间已变化，请重新预览"
    );
    unchanged_context(state, tenant, id, current).map_err(|e| anyhow::anyhow!(e.message))
}

async fn write_host(
    state: &AppState,
    headers: &HeaderMap,
    session: &auth::Session,
    id: &str,
    zone: &Zone,
    current: &Configuration,
    host: &HostPreview,
) -> anyhow::Result<&'static str> {
    check_write(state, headers, &session.tenant_id, id, current)?;
    anyhow::ensure!(
        sorted(zone.records(&host.hostname).await?) == host.existing,
        "解析记录已变化，请重新预览后确认"
    );
    if host.action == "reuse" {
        return Ok("unchanged");
    }
    let operation = Uuid::new_v4().to_string();
    {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let tx = db.unchecked_transaction()?;
        tx.execute("INSERT INTO domain_dns_operations(id,domain_id,hostname,original,created_at) VALUES(?1,?2,?3,?4,?5)", params![operation,id,host.hostname,serde_json::to_string(&host.existing)?,unix_now()])?;
        accounts::audit(&tx, session, "domain_dns_configured", "domain", id)
            .map_err(|e| anyhow::anyhow!(e.message))?;
        tx.commit()?;
    }
    // 优先保留已有正确 A，再选其他 A/CNAME 原地更新，避免先删唯一入口造成空窗。
    let keeper = host
        .existing
        .iter()
        .find(|r| r.kind == "A" && r.value == current.ipv4.to_string() && !r.proxied)
        .or_else(|| host.existing.iter().find(|r| r.kind == "A"))
        .or_else(|| host.existing.iter().find(|r| r.kind == "CNAME"));
    let desired = Record {
        id: keeper.map(|r| r.id.clone()).unwrap_or_default(),
        name: host.hostname.clone(),
        kind: "A".into(),
        value: current.ipv4.to_string(),
        ttl: keeper.map(|r| r.ttl).unwrap_or(600),
        proxied: false,
    };
    let mut changes = Vec::new();
    let attempt: anyhow::Result<()> = async {
        check_write(state, headers, &session.tenant_id, id, current)?;
        anyhow::ensure!(
            sorted(zone.records(&host.hostname).await?) == host.existing,
            "解析记录已变化，请重新预览后确认"
        );
        let written = if keeper == Some(&desired) {
            desired.clone()
        } else {
            let written = zone.write(&desired).await?;
            changes.push(Change {
                before: keeper.cloned(),
                after: Some(written.clone()),
            });
            save_changes(state, &operation, &changes)?;
            written
        };
        for record in host
            .existing
            .iter()
            .filter(|r| access_record(r) && r.id != written.id)
        {
            check_write(state, headers, &session.tenant_id, id, current)?;
            anyhow::ensure!(
                sorted(zone.records(&host.hostname).await?)
                    == expected_records(&host.existing, &changes),
                "解析记录已被外部修改，停止写入"
            );
            zone.remove(record).await?;
            changes.push(Change {
                before: Some(record.clone()),
                after: None,
            });
            save_changes(state, &operation, &changes)?;
        }
        let actual = sorted(zone.records(&host.hostname).await?);
        anyhow::ensure!(
            actual == expected_records(&host.existing, &changes),
            "写入结果与预期不一致，请核对服务商记录"
        );
        let access: Vec<_> = actual.iter().filter(|r| access_record(r)).collect();
        anyhow::ensure!(
            access.len() == 1
                && access[0].kind == "A"
                && access[0].value == desired.value
                && !access[0].proxied,
            "服务商尚未返回唯一的直接 A 记录，请重新预览"
        );
        Ok(())
    }
    .await;
    let error = match attempt {
        Ok(()) => None,
        Err(error) => {
            let recovery = restore_host(state, zone, &operation, host, &mut changes).await;
            Some(match recovery {
                Ok(()) => format!("写入失败：{error}；本次已确认的改动已恢复，请重新预览后重试"),
                Err(recovery) => {
                    format!("写入失败：{error}；恢复未完成：{recovery}。请核对服务商记录后重新预览")
                }
            })
        }
    };
    state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?
        .execute(
            "UPDATE domain_dns_operations SET status=?2,error=?3 WHERE id=?1",
            params![
                operation,
                if error.is_some() { "failed" } else { "written" },
                error
            ],
        )?;
    if let Some(error) = error {
        anyhow::bail!(error);
    }
    Ok("written")
}

async fn restore_host(
    state: &AppState,
    zone: &Zone,
    operation: &str,
    host: &HostPreview,
    changes: &mut Vec<Change>,
) -> anyhow::Result<()> {
    let steps = changes.clone();
    anyhow::ensure!(
        sorted(zone.records(&host.hostname).await?) == expected_records(&host.existing, changes),
        "记录已变化或写入结果无法确认，未覆盖现有解析"
    );
    for change in steps.into_iter().rev() {
        anyhow::ensure!(
            sorted(zone.records(&host.hostname).await?)
                == expected_records(&host.existing, changes),
            "记录已被外部修改，停止恢复"
        );
        let restored = if let Some(original) = &change.before {
            let mut original = original.clone();
            if change.after.is_none() {
                original.id.clear();
            }
            Some(zone.restore(&original).await?)
        } else {
            zone.remove(change.after.as_ref().context("缺少本次写入的记录")?)
                .await?;
            None
        };
        changes.push(Change {
            before: change.after,
            after: restored,
        });
        save_changes(state, operation, changes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
