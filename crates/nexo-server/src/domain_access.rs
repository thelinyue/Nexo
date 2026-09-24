//! 后台自动检查域名解析，页面只读取快照；手动重试与后台任务共用结果和并发限制。
//! DNS 结果来自 Server 的解析器；既不等同于外网可达，也不代替 Caddy 的证书状态。
use crate::*;
use futures_util::{stream, StreamExt};
use std::{collections::HashMap, net::IpAddr, time::Duration};

const RETRY_INTERVAL_SECS: i64 = 5 * 60;
const MAX_RETRIES: u8 = 3;

#[derive(Clone, Debug, Serialize)]
pub struct Access {
    domain: String,
    expected_addresses: Vec<IpAddr>,
    records: Vec<Record>,
    checked_at: Option<i64>,
    next_retry_at: Option<i64>,
    retries_remaining: u8,
    public_access: &'static str,
}
#[derive(Clone, Debug, Serialize)]
struct Record {
    hostname: String,
    addresses: Vec<IpAddr>,
    status: &'static str,
    matches_server: Option<bool>,
    error: Option<String>,
}

/// 配置变化时检查一次；未解析时每 5 分钟重试，最多 3 次，成功或耗尽次数后停止查询。
/// 同一域名串行检查，整个进程最多并发 8 次查询；不会改变穿透或 Caddy 的运行状态。
pub struct Runtime {
    entries: Mutex<HashMap<String, Arc<Entry>>>,
    queries: tokio::sync::Semaphore,
}
#[derive(Default)]
struct Entry {
    result: Mutex<Option<Access>>,
    refresh: tokio::sync::Mutex<()>,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            queries: tokio::sync::Semaphore::new(8),
        }
    }
}
impl Runtime {
    fn entry(&self, id: &str) -> Arc<Entry> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(id.into())
            .or_default()
            .clone()
    }
    fn status(&self, id: &str, current: Access) -> Access {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let cached = entries.get(id).and_then(|entry| {
            entry
                .result
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        });
        // 服务域名增删后立即撤下旧结论，下一轮后台检查会重新解析，不能把旧快照冒充新配置的结果。
        cached
            .filter(|value| {
                value.domain == current.domain
                    && value.expected_addresses == current.expected_addresses
                    && value
                        .records
                        .iter()
                        .map(|r| &r.hostname)
                        .eq(current.records.iter().map(|r| &r.hostname))
            })
            .unwrap_or(current)
    }
    async fn refresh(
        &self,
        state: &AppState,
        tenant: &str,
        id: &str,
        force: bool,
    ) -> Result<Access, ApiError> {
        let entry = self.entry(id);
        let _guard = entry.refresh.lock().await;
        let mut access = load(state, tenant, id)?;
        let cached = self.status(id, access.clone());
        if !force
            && cached.checked_at.is_some()
            && cached.next_retry_at.is_none_or(|at| at > unix_now())
        {
            return Ok(cached);
        }
        let expected = &access.expected_addresses;
        access.records = stream::iter(access.records)
            .map(|record| async move {
                let _permit = self
                    .queries
                    .acquire()
                    .await
                    .expect("DNS 查询信号量不会关闭");
                resolve(record, expected).await
            })
            .buffered(8)
            .collect()
            .await;
        let checked_at = unix_now();
        access.checked_at = Some(checked_at);
        // IP 不一致可能来自 CDN，只有无法解析才安排重试；手动检查不重置已经用掉的次数。
        if access
            .records
            .iter()
            .any(|record| record.status == "unresolved")
        {
            access.retries_remaining = if cached.checked_at.is_none() {
                MAX_RETRIES
            } else if force {
                cached.retries_remaining
            } else {
                cached.retries_remaining.saturating_sub(1)
            };
            if access.retries_remaining > 0 {
                access.next_retry_at = Some(checked_at + RETRY_INTERVAL_SECS);
            }
        } else {
            access.retries_remaining = 0;
        }
        *entry.result.lock().unwrap_or_else(|p| p.into_inner()) = Some(access.clone());
        Ok(access)
    }
    async fn refresh_all(state: &AppState) -> Result<(), ApiError> {
        let domains = {
            let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
            let mut query = db
                .prepare("SELECT id,tenant_id FROM public_domains ORDER BY id")
                .map_err(db_error)?;
            let rows = query
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(db_error)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_error)?
        };
        state
            .domain_access
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|id, _| domains.iter().any(|(current, _)| current == id));
        let mut checks = stream::iter(domains)
            .map(|(id, tenant)| async move {
                if let Err(error) = state
                    .domain_access
                    .refresh(state, &tenant, &id, false)
                    .await
                {
                    if error.status != StatusCode::NOT_FOUND {
                        tracing::error!("自动检查域名解析失败：{error:?}");
                    }
                }
            })
            .buffer_unordered(4);
        while checks.next().await.is_some() {}
        Ok(())
    }
    pub async fn run(state: AppState) {
        // 定期发现数据库中的域名变化和到期重试；已有成功结果不会因此重新查询 DNS。
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(error) = Self::refresh_all(&state).await {
                tracing::error!("读取域名解析检查配置失败：{error:?}");
            }
        }
    }
}

pub fn snapshot(state: &AppState, tenant: &str, id: &str) -> Result<Access, ApiError> {
    Ok(state.domain_access.status(id, load(state, tenant, id)?))
}

fn load(state: &AppState, tenant: &str, id: &str) -> Result<Access, ApiError> {
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let domain: String = db
        .query_row(
            "SELECT domain FROM public_domains WHERE id=?1 AND tenant_id=?2",
            params![id, tenant],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "域名不存在"))?;
    let mut hosts = vec![domain.clone()];
    let mut query=db.prepare("SELECT DISTINCT hostname FROM tunnels WHERE public_domain_id=?1 AND tenant_id=?2 AND protocol!='tcp' AND hostname IS NOT NULL AND hostname!='' AND deleted_at IS NULL ORDER BY hostname").map_err(db_error)?;
    for name in query
        .query_map(params![id, tenant], |r| r.get::<_, String>(0))
        .map_err(db_error)?
    {
        let hostname = format!("{}.{}", name.map_err(db_error)?, domain);
        if !hosts.contains(&hostname) {
            hosts.push(hostname);
        }
    }
    Ok(Access {
        domain,
        expected_addresses: state.public_ips.clone(),
        records: hosts
            .into_iter()
            .map(|hostname| Record {
                hostname,
                addresses: vec![],
                status: "unchecked",
                matches_server: None,
                error: None,
            })
            .collect(),
        checked_at: None,
        next_retry_at: None,
        retries_remaining: MAX_RETRIES,
        public_access: "unverified",
    })
}

pub async fn instructions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Access>, ApiError> {
    let session = require_session(&state, &headers)?;
    Ok(Json(snapshot(&state, &session.tenant_id, &id)?))
}
pub async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Access>, ApiError> {
    let session = require_write(&state, &headers)?;
    if !state
        .security
        .allow(format!("dns:{}", session.user_id), 30, unix_now())
    {
        return Err(security::limited());
    }
    // 先检查归属再分配运行条目，避免任意 ID 留下无效缓存。
    load(&state, &session.tenant_id, &id)?;
    Ok(Json(
        state
            .domain_access
            .refresh(&state, &session.tenant_id, &id, true)
            .await?,
    ))
}

async fn resolve(mut record: Record, expected: &[IpAddr]) -> Record {
    match tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((record.hostname.as_str(), 0)),
    )
    .await
    {
        Ok(Ok(addresses)) => {
            record.addresses = addresses.map(|v| v.ip()).collect();
            record.addresses.sort();
            record.addresses.dedup();
            record.status = if record.addresses.is_empty() {
                "unresolved"
            } else {
                "resolved"
            };
            if !expected.is_empty() && !record.addresses.is_empty() {
                // 全部解析地址都应属于已配置的 Server，避免一个错误 AAAA 被正确 A 掩盖。
                record.matches_server = Some(
                    record
                        .addresses
                        .iter()
                        .all(|address| expected.contains(address)),
                );
            }
            if record.addresses.is_empty() {
                record.error = Some("未找到 A 或 AAAA 记录，请检查 DNS 配置并等待生效".into());
            }
        }
        Ok(Err(_)) => {
            record.status = "unresolved";
            record.error = Some("Server 未能解析此域名，请检查 DNS 记录及服务器的解析器".into());
        }
        Err(_) => {
            record.status = "unresolved";
            record.error = Some("DNS 查询超时，请稍后重试".into());
        }
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn background_dns_stops_after_success_and_waits_for_scheduled_retries() {
        let (state, headers) = crate::tests::domain_fixture();
        let domain = crate::tests::add_test_domain(&state, &headers, "test.localhost")
            .await
            .unwrap();
        // 测试使用系统回环域名，不依赖公网 DNS 或修改系统时间。
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE public_domains SET domain='localhost' WHERE id=?1",
                [&domain.id],
            )
            .unwrap();
        assert!(snapshot(&state, "default", &domain.id)
            .unwrap()
            .checked_at
            .is_none());
        let task = tokio::spawn(Runtime::run(state.clone()));
        tokio::time::timeout(Duration::from_secs(10), async {
            while snapshot(&state, "default", &domain.id)
                .unwrap()
                .checked_at
                .is_none()
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        let _ = task.await;
        let domains = crate::list_domains(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0;
        let automatic = domains[0].access.as_ref().unwrap();
        assert_eq!(automatic.records[0].status, "resolved");
        assert_eq!(automatic.public_access, "unverified");
        assert!(automatic.next_retry_at.is_none());
        assert_eq!(automatic.retries_remaining, 0);
        let entry = state.domain_access.entry(&domain.id);
        // 即使成功结果已过去一天，扫描和 GET 也不能再次发起 DNS 查询。
        let previous = unix_now() - 86400;
        entry.result.lock().unwrap().as_mut().unwrap().checked_at = Some(previous);
        Runtime::refresh_all(&state).await.unwrap();
        assert_eq!(
            snapshot(&state, "default", &domain.id).unwrap().checked_at,
            Some(previous)
        );
        let recent = unix_now() - 10;
        {
            let mut result = entry.result.lock().unwrap();
            let cached = result.as_mut().unwrap();
            cached.checked_at = Some(recent);
            cached.next_retry_at = Some(unix_now() + RETRY_INTERVAL_SECS);
            cached.retries_remaining = MAX_RETRIES;
            cached.records[0].status = "unresolved";
            cached.records[0].addresses.clear();
            cached.records[0].error = Some("DNS 查询超时，请稍后重试".into());
        }
        // 尚未到重试时间时，刷新页面和后台扫描只读取快照。
        Runtime::refresh_all(&state).await.unwrap();
        let cached = instructions(State(state.clone()), headers, Path(domain.id.clone()))
            .await
            .unwrap()
            .0;
        assert_eq!(cached.checked_at, Some(recent));
        assert_eq!(cached.records[0].status, "unresolved");
        entry.result.lock().unwrap().as_mut().unwrap().next_retry_at = Some(unix_now() - 1);
        Runtime::refresh_all(&state).await.unwrap();
        let retried = snapshot(&state, "default", &domain.id).unwrap();
        assert_eq!(retried.records[0].status, "resolved");
        assert!(retried.records[0].error.is_none());
        assert!(!retried.records[0].addresses.is_empty());
        assert!(retried.next_retry_at.is_none());
        assert_eq!(retried.retries_remaining, 0);
    }

    #[tokio::test]
    async fn unresolved_dns_has_three_retries_and_config_changes_restart_checks() {
        let (state, headers) = crate::tests::domain_fixture();
        let domain = crate::tests::add_test_domain(&state, &headers, "test.localhost")
            .await
            .unwrap();
        // 内嵌空字符使系统解析器立即拒绝，稳定模拟解析失败，不访问公网 DNS。
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE public_domains SET domain=?1 WHERE id=?2",
                params!["invalid\0dns", domain.id],
            )
            .unwrap();
        Runtime::refresh_all(&state).await.unwrap();
        let first = snapshot(&state, "default", &domain.id).unwrap();
        assert_eq!(first.records[0].status, "unresolved");
        assert_eq!(first.retries_remaining, 3);
        assert_eq!(first.next_retry_at, first.checked_at.map(|at| at + 300));
        let entry = state.domain_access.entry(&domain.id);
        for remaining in [2, 1, 0] {
            entry.result.lock().unwrap().as_mut().unwrap().next_retry_at = Some(unix_now() - 1);
            Runtime::refresh_all(&state).await.unwrap();
            let retried = snapshot(&state, "default", &domain.id).unwrap();
            assert_eq!(retried.retries_remaining, remaining);
            assert_eq!(retried.next_retry_at.is_some(), remaining > 0);
        }
        let previous = unix_now() - 86400;
        entry.result.lock().unwrap().as_mut().unwrap().checked_at = Some(previous);
        Runtime::refresh_all(&state).await.unwrap();
        assert_eq!(
            snapshot(&state, "default", &domain.id).unwrap().checked_at,
            Some(previous)
        );
        let manual = check(
            State(state.clone()),
            headers.clone(),
            Path(domain.id.clone()),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(manual.retries_remaining, 0);
        assert!(manual.next_retry_at.is_none());
        assert!(manual.checked_at.unwrap() > previous);
        // 配置变化后立即撤销旧结论，重新启动一次检查。
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE public_domains SET domain='localhost' WHERE id=?1",
                [&domain.id],
            )
            .unwrap();
        assert!(snapshot(&state, "default", &domain.id)
            .unwrap()
            .checked_at
            .is_none());
        Runtime::refresh_all(&state).await.unwrap();
        let recovered = snapshot(&state, "default", &domain.id).unwrap();
        assert_eq!(recovered.records[0].status, "resolved");
        assert!(recovered.next_retry_at.is_none());
        assert_eq!(recovered.retries_remaining, 0);
    }

    #[tokio::test]
    async fn resolved_cdn_addresses_do_not_schedule_retries() {
        let (mut state, headers) = crate::tests::domain_fixture();
        state.public_ips = vec!["203.0.113.10".parse().unwrap()];
        let domain = crate::tests::add_test_domain(&state, &headers, "test.localhost")
            .await
            .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE public_domains SET domain='localhost' WHERE id=?1",
                [&domain.id],
            )
            .unwrap();
        Runtime::refresh_all(&state).await.unwrap();
        let checked = snapshot(&state, "default", &domain.id).unwrap();
        assert_eq!(checked.records[0].status, "resolved");
        assert_eq!(checked.records[0].matches_server, Some(false));
        assert!(checked.next_retry_at.is_none());
        assert_eq!(checked.retries_remaining, 0);
    }

    #[tokio::test]
    async fn service_changes_invalidate_dns_snapshot_and_deleted_domains_are_pruned() {
        let (state, headers) = crate::tests::domain_fixture();
        let domain = crate::tests::add_test_domain(&state, &headers, "test.localhost")
            .await
            .unwrap();
        let mut cached = load(&state, "default", &domain.id).unwrap();
        cached.checked_at = Some(unix_now());
        *state.domain_access.entry(&domain.id).result.lock().unwrap() = Some(cached);
        state.db.lock().unwrap().execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,hostname,public_domain_id,created_at,updated_at) VALUES('dns-test','default','测试','http','localhost',80,'media',?1,0,0)", [&domain.id]).unwrap();
        let changed = snapshot(&state, "default", &domain.id).unwrap();
        assert!(changed.checked_at.is_none());
        assert_eq!(changed.records.len(), 2);
        assert_eq!(changed.records[1].hostname, "media.test.localhost");
        state
            .db
            .lock()
            .unwrap()
            .execute("DELETE FROM public_domains WHERE id=?1", [&domain.id])
            .unwrap();
        Runtime::refresh_all(&state).await.unwrap();
        assert!(state.domain_access.entries.lock().unwrap().is_empty());
        assert_eq!(
            snapshot(&state, "default", &domain.id).unwrap_err().status,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn access_checks_require_csrf_and_domain_ownership() {
        let (state, headers) = crate::tests::domain_fixture();
        let domain = crate::tests::add_test_domain(&state, &headers, "example.com")
            .await
            .unwrap();
        let mut missing_csrf = headers.clone();
        missing_csrf.remove("x-nexo-csrf");
        assert_eq!(
            check(State(state.clone()), missing_csrf, Path(domain.id.clone()))
                .await
                .err()
                .unwrap()
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            instructions(
                State(state.clone()),
                HeaderMap::new(),
                Path(domain.id.clone())
            )
            .await
            .err()
            .unwrap()
            .status,
            StatusCode::UNAUTHORIZED
        );
        {
            let db = state.db.lock().unwrap();
            db.execute(
                "INSERT INTO tenants(id,name,created_at) VALUES('other','其他空间',0)",
                [],
            )
            .unwrap();
            db.execute(
                "UPDATE public_domains SET tenant_id='other' WHERE id=?1",
                [&domain.id],
            )
            .unwrap();
        }
        assert_eq!(
            instructions(State(state), headers, Path(domain.id))
                .await
                .err()
                .unwrap()
                .status,
            StatusCode::NOT_FOUND
        );
    }
    #[tokio::test]
    async fn dns_resolution_does_not_claim_public_reachability() {
        let record = resolve(
            Record {
                hostname: "localhost".into(),
                addresses: vec![],
                status: "unchecked",
                matches_server: None,
                error: None,
            },
            &[],
        )
        .await;
        assert_eq!(record.status, "resolved");
        assert_eq!(record.matches_server, None);
        assert!(!record.addresses.is_empty());
    }
}
