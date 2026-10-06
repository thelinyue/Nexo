//! 节点版本独立于管理端：只列出当前清单支持的正式节点版本，避免 Web 更新触发节点升级。
use super::*;

#[derive(Deserialize)]
struct Manifest {
    node_version: String,
}

/// 清单保留最近一次实际发布的节点版本；仅管理端变化时不得随项目版本递增。
pub fn current_version() -> String {
    let manifest: Manifest =
        serde_json::from_str(include_str!("../../../../release-manifest.json"))
            .expect("发布清单缺少有效的节点版本");
    manifest.node_version
}

#[derive(Serialize, Clone)]
pub struct Release {
    pub version: String,
    pub architectures: Vec<String>,
}

pub async fn catalog() -> Result<Vec<Release>, ApiError> {
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(db_error)?
        .get("https://api.github.com/repos/thelinyue/Nexo/releases?per_page=100")
        .header("User-Agent", "Nexo-node-manager")
        .send()
        .await
        .map_err(|_| invalid("暂时无法读取官方版本目录，请稍后重试"))?;
    if !response.status().is_success() {
        return Err(invalid("官方版本目录暂不可用，请稍后重试"));
    }
    let data: Vec<Value> = response.json().await.map_err(db_error)?;
    Ok(parse(data, &current_version()))
}
fn parse(data: Vec<Value>, node_version: &str) -> Vec<Release> {
    let maximum = super::updates::version(node_version).expect("发布清单中的节点版本格式无效");
    let mut releases: Vec<Release> = data
        .into_iter()
        .filter_map(|release| {
            if release["draft"].as_bool() != Some(false)
                || release["prerelease"].as_bool() != Some(false)
            {
                return None;
            }
            let tag = release["tag_name"].as_str()?.strip_prefix('v')?;
            if super::updates::version(tag)? > maximum {
                return None;
            }
            let assets = release["assets"].as_array()?;
            if !assets.iter().any(|asset| asset["name"] == "SHA256SUMS") {
                return None;
            }
            let architectures = ["x86_64", "aarch64"]
                .into_iter()
                .filter(|arch| {
                    assets.iter().any(|asset| {
                        asset["name"] == format!("nexo-node-{tag}-linux-{arch}.tar.gz")
                    })
                })
                .map(str::to_owned)
                .collect::<Vec<_>>();
            (!architectures.is_empty()).then(|| Release {
                version: tag.into(),
                architectures,
            })
        })
        .collect();
    releases.sort_by_key(|release| std::cmp::Reverse(super::updates::version(&release.version)));
    releases
}
pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Release>>, ApiError> {
    require_session(&state, &headers)?;
    Ok(Json(catalog().await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, architectures: &[&str]) -> Value {
        let mut assets = vec![json!({"name":"SHA256SUMS"})];
        assets.extend(
            architectures
                .iter()
                .map(|arch| json!({"name":format!("nexo-node-{tag}-linux-{arch}.tar.gz")})),
        );
        json!({"tag_name":format!("v{tag}"),"draft":false,"prerelease":false,"assets":assets})
    }

    #[test]
    fn server_only_release_does_not_offer_new_node_version() {
        // 即使历史发布误附了节点包，也不能因管理端版本提高而提示节点更新。
        let releases = parse(
            vec![
                release("0.2.19", &["x86_64", "aarch64"]),
                release("0.2.18", &["x86_64", "aarch64"]),
            ],
            "0.2.18",
        );
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].version, "0.2.18");
    }

    #[test]
    fn node_code_release_offers_supported_architectures_in_version_order() {
        let mut draft = release("0.2.20", &["x86_64"]);
        draft["draft"] = json!(true);
        let mut prerelease = release("0.2.20", &["x86_64"]);
        prerelease["prerelease"] = json!(true);
        let mut unchecked = release("0.2.20", &["x86_64"]);
        unchecked["assets"] = json!([{"name":"nexo-node-0.2.20-linux-x86_64.tar.gz"}]);
        let releases = parse(
            vec![
                release("0.2.18", &["x86_64", "aarch64"]),
                release("0.2.20", &["x86_64"]),
                release("0.2.21", &["x86_64", "aarch64"]),
                release("0.2.20-rc.1", &["x86_64"]),
                draft,
                prerelease,
                unchecked,
            ],
            "0.2.20",
        );
        assert_eq!(releases.len(), 2);
        assert_eq!(releases[0].version, "0.2.20");
        assert_eq!(releases[0].architectures, ["x86_64"]);
        assert_eq!(releases[1].version, "0.2.18");
    }

    #[test]
    fn manifest_node_version_matches_release_scope() {
        let manifest: Value =
            serde_json::from_str(include_str!("../../../../release-manifest.json")).unwrap();
        let node = current_version();
        assert!(
            super::super::updates::version(&node).unwrap()
                <= super::super::updates::version(env!("CARGO_PKG_VERSION")).unwrap()
        );
        assert_eq!(
            manifest["components"]
                .as_array()
                .unwrap()
                .contains(&json!("node")),
            manifest["version"] == node
        );
    }
}
