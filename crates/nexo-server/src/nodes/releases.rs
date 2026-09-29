//! 版本目录只读取官方正式发布；安装器另行按发行文件校验，不接受客户端提供下载地址。
use super::*;
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
    Ok(parse(data))
}
fn parse(data: Vec<Value>) -> Vec<Release> {
    let maximum = super::updates::version(env!("CARGO_PKG_VERSION")).unwrap();
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
