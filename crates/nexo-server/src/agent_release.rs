//! 设备更新提示只读取官方正式发布及其组件清单，不把服务端版本当成客户端版本。
use crate::*;
use std::{future::Future, time::Duration};
use tokio::{sync::Mutex as AsyncMutex, time::Instant};

const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Release {
    version: Option<String>,
    release_url: Option<String>,
}

/// 所有空间共享公开版本信息；异步锁合并并发查询，不持有数据库锁或持久化发布状态。
#[derive(Default)]
pub(crate) struct Catalog {
    cached: AsyncMutex<Option<(Instant, Release)>>,
}

impl Catalog {
    async fn load(&self, fetch: impl Future<Output = Result<Release>>) -> Result<Release> {
        let mut cached = self.cached.lock().await;
        if let Some((checked, release)) = cached.as_ref() {
            if checked.elapsed() < CACHE_TTL {
                return Ok(release.clone());
            }
        }
        // 查询失败不更新时间，也不以过期缓存冒充最新正式版。
        let release = fetch.await?;
        *cached = Some((Instant::now(), release.clone()));
        Ok(release)
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

#[derive(Deserialize)]
struct Manifest {
    version: String,
    components: Vec<String>,
}

fn candidates(releases: Vec<GithubRelease>) -> Vec<String> {
    let mut versions: Vec<_> = releases
        .into_iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            let version = release.tag_name.strip_prefix('v')?;
            nodes::updates::version(version).map(|parsed| (parsed, version.to_owned()))
        })
        .collect();
    versions.sort_by_key(|(parsed, _)| std::cmp::Reverse(*parsed));
    versions.dedup();
    versions.into_iter().map(|(_, version)| version).collect()
}

/// 清单必须与正式标签一致；未知或缺失清单不能被静默跳过，否则会误报较旧版本为最新。
fn includes_agent(version: &str, manifest: Manifest) -> Result<bool> {
    anyhow::ensure!(manifest.version == version, "官方发布清单与版本标签不一致");
    Ok(manifest
        .components
        .iter()
        .any(|component| component == "agent"))
}

async fn fetch() -> Result<Release> {
    let client = reqwest::Client::builder()
        .timeout(QUERY_TIMEOUT)
        .user_agent("Nexo-device-version")
        .build()?;
    fetch_from(
        &client,
        "https://api.github.com/repos/thelinyue/Nexo/releases",
        "https://raw.githubusercontent.com/thelinyue/Nexo",
    )
    .await
}

// 地址仅由官方调用方或本地 HTTP 测试提供，不接受浏览器传入的版本源。
async fn fetch_from(
    client: &reqwest::Client,
    releases_url: &str,
    source_url: &str,
) -> Result<Release> {
    let mut releases = Vec::new();
    // GitHub 按发布日期分页，补发历史版本可能排在前面，因此收齐后再按数字版本排序。
    for page in 1.. {
        let batch: Vec<GithubRelease> = client
            .get(format!("{releases_url}?per_page=100&page={page}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let finished = batch.len() < 100;
        releases.extend(batch);
        if finished {
            break;
        }
    }
    for version in candidates(releases) {
        let manifest: Manifest = client
            .get(format!("{source_url}/v{version}/release-manifest.json"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if includes_agent(&version, manifest)? {
            return Ok(Release {
                release_url: Some(format!(
                    "https://github.com/thelinyue/Nexo/releases/tag/v{version}"
                )),
                version: Some(version),
            });
        }
    }
    Ok(Release::default())
}

pub(crate) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Release>, ApiError> {
    require_session(&state, &headers)?;
    // 总超时包含等待并发查询的锁以及所有分页、清单请求。
    let result = tokio::time::timeout(QUERY_TIMEOUT, state.agent_releases.load(fetch())).await;
    match result {
        Ok(Ok(release)) => Ok(Json(release)),
        _ => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "暂时无法检查设备更新，请稍后重试",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str) -> Release {
        Release {
            version: Some(version.into()),
            release_url: Some(format!(
                "https://github.com/thelinyue/Nexo/releases/tag/v{version}"
            )),
        }
    }

    #[test]
    fn stable_versions_follow_components_in_numeric_order() {
        let data = serde_json::from_value(serde_json::json!([
            {"tag_name":"v0.2.9","draft":false,"prerelease":false},
            {"tag_name":"v0.2.18","draft":false,"prerelease":true},
            {"tag_name":"v0.2.19","draft":true,"prerelease":false},
            {"tag_name":"v0.2.20-rc.1","draft":false,"prerelease":false},
            {"tag_name":"v0.2.14","draft":false,"prerelease":false},
            {"tag_name":"v0.2.17","draft":false,"prerelease":false}
        ]))
        .unwrap();
        assert_eq!(candidates(data), ["0.2.17", "0.2.14", "0.2.9"]);
        assert!(!includes_agent(
            "0.2.17",
            Manifest {
                version: "0.2.17".into(),
                components: vec!["server".into()]
            }
        )
        .unwrap());
        assert!(includes_agent(
            "0.2.14",
            Manifest {
                version: "0.2.14".into(),
                components: vec!["server".into(), "agent".into()]
            }
        )
        .unwrap());
        assert!(includes_agent(
            "0.2.14",
            Manifest {
                version: "0.2.13".into(),
                components: vec!["agent".into()]
            }
        )
        .is_err());
        assert!(candidates(Vec::new()).is_empty());
    }

    #[tokio::test]
    async fn cache_expires_and_failures_do_not_replace_confirmed_versions() {
        let catalog = Catalog::default();
        assert_eq!(
            catalog.load(async { Ok(release("0.2.14")) }).await.unwrap(),
            release("0.2.14")
        );
        assert_eq!(
            catalog
                .load(async { anyhow::bail!("缓存有效时不应读取网络") })
                .await
                .unwrap(),
            release("0.2.14")
        );
        catalog.cached.lock().await.as_mut().unwrap().0 = Instant::now() - CACHE_TTL;
        assert!(catalog
            .load(async { anyhow::bail!("清单读取失败") })
            .await
            .is_err());
        assert_eq!(
            catalog.cached.lock().await.as_ref().unwrap().1,
            release("0.2.14")
        );
        assert_eq!(
            catalog.load(async { Ok(release("0.2.18")) }).await.unwrap(),
            release("0.2.18")
        );
    }

    #[tokio::test]
    async fn authenticated_users_share_catalog_but_anonymous_requests_are_rejected() {
        let (state, headers) = crate::tests::domain_fixture();
        state
            .agent_releases
            .load(async { Ok(release("0.2.14")) })
            .await
            .unwrap();
        assert_eq!(
            list(State(state.clone()), headers.clone()).await.unwrap().0,
            release("0.2.14")
        );
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE users SET role='tenant' WHERE id='u'", [])
            .unwrap();
        assert_eq!(
            list(State(state.clone()), headers).await.unwrap().0,
            release("0.2.14")
        );
        assert_eq!(
            list(State(state), HeaderMap::new())
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn http_catalog_paginates_skips_server_only_and_reports_manifest_failures() {
        use axum::http::Uri;
        use std::sync::atomic::{AtomicBool, Ordering};
        let calls = Arc::new(Mutex::new(Vec::new()));
        let failed = Arc::new(AtomicBool::new(false));
        let empty = Arc::new(AtomicBool::new(false));
        let app = Router::new().fallback({
            let calls = calls.clone(); let failed = failed.clone(); let empty = empty.clone();
            move |uri: Uri| {
                let calls = calls.clone(); let failed = failed.clone(); let empty = empty.clone();
                async move {
                    let path = uri.path();
                    calls.lock().unwrap().push(path.to_owned());
                    if path == "/releases" {
                        if empty.load(Ordering::Relaxed) { return Json(serde_json::json!([])).into_response(); }
                        if uri.query().unwrap().ends_with("page=1") {
                            let mut values = vec![serde_json::json!({"tag_name":"v0.2.9","draft":false,"prerelease":false}); 98];
                            values.push(serde_json::json!({"tag_name":"v0.2.17","draft":false,"prerelease":false}));
                            values.push(serde_json::json!({"tag_name":"v0.2.18","draft":false,"prerelease":true}));
                            return Json(values).into_response();
                        }
                        return Json(serde_json::json!([{"tag_name":"v0.2.14","draft":false,"prerelease":false}])).into_response();
                    }
                    if failed.load(Ordering::Relaxed) { return StatusCode::NOT_FOUND.into_response(); }
                    let version = if path.starts_with("/v0.2.17/") { "0.2.17" } else { "0.2.14" };
                    Json(serde_json::json!({"version":version,"components":if version=="0.2.17"{vec!["server"]}else{vec!["server","agent"]}})).into_response()
                }
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        let url = format!("{base}/releases");
        assert_eq!(
            fetch_from(&client, &url, &base).await.unwrap(),
            release("0.2.14")
        );
        assert_eq!(
            *calls.lock().unwrap(),
            [
                "/releases",
                "/releases",
                "/v0.2.17/release-manifest.json",
                "/v0.2.14/release-manifest.json"
            ]
        );
        failed.store(true, Ordering::Relaxed);
        calls.lock().unwrap().clear();
        assert!(fetch_from(&client, &url, &base).await.is_err());
        assert!(!calls
            .lock()
            .unwrap()
            .iter()
            .any(|path| path.starts_with("/v0.2.14/")));
        empty.store(true, Ordering::Relaxed);
        assert_eq!(
            fetch_from(&client, &url, &base).await.unwrap(),
            Release::default()
        );
        task.abort();
    }
}
