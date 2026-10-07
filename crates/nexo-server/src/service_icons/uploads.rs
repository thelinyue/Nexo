//! 共享图片只在服务提交时入库；预览不写磁盘，所有空间共用目录。
//! 文件写入与 SQLite 无法共用事务，由待提交对象负责失败补偿；图标引用和删除共用数据库锁。
use crate::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use image::{ImageFormat, ImageReader};
use std::{
    io::Cursor,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

const MAX_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
pub struct Upload {
    pub name: String,
    pub data_url: String,
}

#[derive(Serialize)]
pub struct Icon {
    id: String,
    name: String,
    created_at: i64,
}

fn bad(message: &str) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, message)
}
fn file_error(error: impl std::fmt::Display) -> ApiError {
    tracing::error!("共享图标文件操作失败：{error}");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "无法读写图标目录，请检查存储空间和目录权限",
    )
}
fn name(value: &str) -> String {
    let value: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    if value.is_empty() {
        "自定义图标".into()
    } else {
        value
    }
}
fn path(state: &AppState, id: &str) -> Result<PathBuf, ApiError> {
    let id = Uuid::parse_str(id).map_err(|_| bad("图标编号无效"))?;
    Ok(state
        .data_dir
        .join("service-icons")
        .join(format!("{id}.png")))
}

/// 解码器同时限制尺寸与内存；不采信扩展名或 HTTP Content-Type。
fn normalize(bytes: &[u8]) -> Result<Vec<u8>, ApiError> {
    if bytes.len() > MAX_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "图片不能超过 2 MB",
        ));
    }
    let format = image::guess_format(bytes).map_err(|_| bad("请选择 PNG、JPG 或 WebP 图片"))?;
    if !matches!(
        format,
        ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP
    ) {
        return Err(bad("请选择 PNG、JPG 或 WebP 图片"));
    }
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(4096);
    limits.max_image_height = Some(4096);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|_| bad("图片损坏或尺寸超过 4096 × 4096 像素"))?;
    let image = if image.width() > 256 || image.height() > 256 {
        image.thumbnail(256, 256)
    } else {
        image
    };
    let mut output = Cursor::new(Vec::new());
    image
        .write_to(&mut output, ImageFormat::Png)
        .map_err(file_error)?;
    Ok(output.into_inner())
}
fn decode(data_url: &str) -> Result<Vec<u8>, ApiError> {
    let (prefix, encoded) = data_url
        .split_once(',')
        .ok_or_else(|| bad("图片数据无效"))?;
    let expected = match prefix {
        "data:image/png;base64" => ImageFormat::Png,
        "data:image/jpeg;base64" => ImageFormat::Jpeg,
        "data:image/webp;base64" => ImageFormat::WebP,
        _ => return Err(bad("请选择 PNG、JPG 或 WebP 图片")),
    };
    if encoded.len() > MAX_BYTES.div_ceil(3) * 4 {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "图片不能超过 2 MB",
        ));
    }
    let bytes = STANDARD.decode(encoded).map_err(|_| bad("图片数据无效"))?;
    if image::guess_format(&bytes).ok() != Some(expected) {
        return Err(bad("图片内容与格式不符"));
    }
    normalize(&bytes)
}

/// Drop 仅清理尚未提交的本次图片，绝不删除已经进入共享库的图片。
pub struct PendingUpload {
    id: String,
    name: String,
    path: PathBuf,
    committed: bool,
}
impl PendingUpload {
    pub fn register(&self, db: &Connection) -> Result<(), ApiError> {
        db.execute(
            "INSERT INTO service_icons(id,name,created_at) VALUES(?1,?2,?3)",
            params![self.id, self.name, unix_now()],
        )
        .map_err(db_error)?;
        Ok(())
    }
    pub fn commit(&mut self) {
        self.committed = true;
    }
}
impl Drop for PendingUpload {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = fs::remove_file(&self.path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::error!("保存失败后的图标清理失败：{error}");
                }
            }
        }
    }
}
pub async fn prepare(
    state: &AppState,
    input: &mut TunnelInput,
) -> Result<Option<PendingUpload>, ApiError> {
    let Some(upload) = input.icon_upload.take() else {
        return Ok(None);
    };
    if input.icon_id.is_some() {
        return Err(bad("上传图片和选择已有图标不能同时提交"));
    }
    let id = Uuid::new_v4().to_string();
    let target = path(state, &id)?;
    let pending = tokio::task::spawn_blocking(move || {
        let bytes = decode(&upload.data_url)?;
        fs::create_dir_all(target.parent().unwrap()).map_err(file_error)?;
        let pending = PendingUpload {
            id,
            name: name(&upload.name),
            path: target,
            committed: false,
        };
        // 写入对象先建立，部分写入失败时也能由 Drop 清理。
        fs::write(&pending.path, bytes).map_err(file_error)?;
        Ok::<_, ApiError>(pending)
    })
    .await
    .map_err(file_error)??;
    input.icon_id = Some(Some(format!("upload/{}", pending.id)));
    Ok(Some(pending))
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Icon>>, ApiError> {
    auth::require_session(&state, &headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let mut query = db
        .prepare("SELECT id,name,created_at FROM service_icons ORDER BY created_at DESC,id")
        .map_err(db_error)?;
    let icons = query
        .query_map([], |r| {
            Ok(Icon {
                id: format!("upload/{}", r.get::<_, String>(0)?),
                name: r.get(1)?,
                created_at: r.get(2)?,
            })
        })
        .map_err(db_error)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db_error)?;
    Ok(Json(icons))
}
pub async fn image(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    auth::require_session(&state, &headers)?;
    let target = path(&state, &id)?;
    // 与删除串行，避免先检查元数据后文件被另一个请求移走。
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    if !db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM service_icons WHERE id=?1)",
            [&id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(db_error)?
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "共享图标不存在"));
    }
    let bytes = fs::read(target).map_err(file_error)?;
    Ok(([(axum::http::header::CONTENT_TYPE, "image/png")], bytes).into_response())
}
pub async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = accounts::require_admin(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    let target = path(&state, &id)?;
    let staged = target.with_extension("deleting");
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    if !tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM service_icons WHERE id=?1)",
            [&id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(db_error)?
    {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "共享图标不存在"));
    }
    if tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tunnels WHERE icon_id=?1 AND deleted_at IS NULL)",
            [format!("upload/{id}")],
            |r| r.get::<_, bool>(0),
        )
        .map_err(db_error)?
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "图标正在被服务使用，请先更换这些服务的图标",
        ));
    }
    tx.execute("DELETE FROM service_icons WHERE id=?1", [&id])
        .map_err(db_error)?;
    accounts::audit(&tx, &session, "service_icon_deleted", "service_icon", &id)?;
    fs::rename(&target, &staged).map_err(file_error)?;
    if let Err(error) = tx.commit() {
        fs::rename(&staged, &target).map_err(file_error)?;
        return Err(db_error(error));
    }
    // 数据库已提交时不可伪装成未删除；残留暂存文件只记录清理错误。
    if let Err(error) = fs::remove_file(staged) {
        tracing::error!("图标已删除，但暂存文件清理失败：{error}");
    }
    Ok(Json(serde_json::json!({"deleted":true})))
}

/// 内网导入只对管理员开放；即使管理员也不能访问主机回环、元数据和其他特殊地址。
fn allowed_ip(ip: IpAddr, admin: bool) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            if ip.is_private() {
                return admin;
            }
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 127
                || a >= 224
                || (a == 169 && b == 254)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(ip) = ip.to_ipv4_mapped() {
                return allowed_ip(ip.into(), admin);
            }
            let s = ip.segments();
            if s[0] & 0xfe00 == 0xfc00 {
                return admin;
            }
            // 只允许全球单播；排除文档、隧道转换及协议保留段。
            s[0] & 0xe000 == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}
fn parse_url(value: &str) -> Result<reqwest::Url, ApiError> {
    let mut url = reqwest::Url::parse(value.trim())
        .map_err(|_| bad("请输入有效的 HTTP 或 HTTPS 图片链接"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(bad("图片链接仅支持不含账号密码的 HTTP 或 HTTPS 地址"));
    }
    url.set_fragment(None);
    Ok(url)
}
async fn download(mut url: reqwest::Url, admin: bool) -> Result<Vec<u8>, ApiError> {
    for hop in 0..=3 {
        let host = url
            .host_str()
            .ok_or_else(|| bad("图片链接缺少主机地址"))?
            .trim_matches(['[', ']'])
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| bad("图片链接端口无效"))?;
        let addresses: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|_| bad("无法解析图片链接的主机地址"))?
                .collect()
        };
        if addresses.is_empty()
            || addresses
                .iter()
                .any(|address| !allowed_ip(address.ip(), admin))
        {
            return Err(bad(
                "图片地址不可访问；内网图片仅允许管理员导入，回环和特殊地址不受支持",
            ));
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&host, &addresses)
            .build()
            .map_err(|error| {
                tracing::error!("图片下载客户端初始化失败：{error}");
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "无法初始化图片下载，请检查服务器运行环境",
                )
            })?;
        let mut response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|_| bad("图片下载失败，请检查地址、网络和 HTTPS 证书"))?;
        if response.status().is_redirection() {
            if hop == 3 {
                return Err(bad("图片链接重定向次数过多"));
            }
            let location = response
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| bad("图片重定向地址无效"))?;
            url = parse_url(
                url.join(location)
                    .map_err(|_| bad("图片重定向地址无效"))?
                    .as_str(),
            )?;
            continue;
        }
        if !response.status().is_success() {
            return Err(bad("图片链接未返回成功响应"));
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_BYTES as u64)
        {
            return Err(bad("图片不能超过 2 MB"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| bad("图片下载中断，请重试"))?
        {
            if bytes.len() + chunk.len() > MAX_BYTES {
                return Err(bad("图片不能超过 2 MB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        return Ok(bytes);
    }
    unreachable!()
}
#[derive(Deserialize)]
pub struct PreviewInput {
    url: String,
}
pub async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<PreviewInput>,
) -> Result<Json<Upload>, ApiError> {
    auth::require_session(&state, &headers)?;
    auth::require_csrf(&state, &headers)?;
    let admin = accounts::require_admin(&state, &headers).is_ok();
    let url = parse_url(&input.url)?;
    let label = name(
        url.path_segments()
            .and_then(|mut s| s.next_back())
            .unwrap_or("自定义图标"),
    );
    let bytes = tokio::time::timeout(Duration::from_secs(10), download(url, admin))
        .await
        .map_err(|_| bad("图片下载超时，请重试"))??;
    let png = tokio::task::spawn_blocking(move || normalize(&bytes))
        .await
        .map_err(file_error)??;
    Ok(Json(Upload {
        name: label,
        data_url: format!("data:image/png;base64,{}", STANDARD.encode(png)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn png(width: u32, height: u32) -> Vec<u8> {
        let image = image::RgbaImage::from_pixel(width, height, image::Rgba([12, 40, 80, 100]));
        let mut bytes = Cursor::new(Vec::new());
        image.write_to(&mut bytes, ImageFormat::Png).unwrap();
        bytes.into_inner()
    }
    fn upload() -> Upload {
        Upload {
            name: "媒体图标.png".into(),
            data_url: format!("data:image/png;base64,{}", STANDARD.encode(png(320, 160))),
        }
    }
    fn input() -> TunnelInput {
        serde_json::from_value(json!({"service_mode":"reverse_proxy","name":"Emby","protocol":"http","origin_protocol":"http","local_address":"127.0.0.1","local_port":8096,"hostname":"emby","public_domain_id":"domain"})).unwrap()
    }
    fn fixture() -> (AppState, HeaderMap, tempfile::TempDir) {
        let (mut state, headers) = super::super::tests::fixture();
        let directory = tempfile::tempdir().unwrap();
        state.data_dir = directory.path().into();
        (state, headers, directory)
    }

    #[test]
    fn image_validation_scales_and_preserves_alpha() {
        let bytes = decode(&upload().data_url).unwrap();
        let result = image::load_from_memory(&bytes).unwrap().into_rgba8();
        assert_eq!(result.dimensions(), (256, 128));
        assert_eq!(result.get_pixel(0, 0)[3], 100);
        for (format, prefix) in [(ImageFormat::Jpeg, "jpeg"), (ImageFormat::WebP, "webp")] {
            let image = image::RgbImage::from_pixel(4, 2, image::Rgb([1, 2, 3]));
            let mut bytes = Cursor::new(Vec::new());
            image.write_to(&mut bytes, format).unwrap();
            assert!(decode(&format!(
                "data:image/{prefix};base64,{}",
                STANDARD.encode(bytes.into_inner())
            ))
            .is_ok());
        }
        assert!(decode("data:image/png;base64,bm90IGEgcG5n").is_err());
        assert!(decode(&upload().data_url.replace("image/png", "image/jpeg")).is_err());
        assert!(normalize(b"<svg xmlns='http://www.w3.org/2000/svg'/>").is_err());
        assert!(normalize(b"GIF89a").is_err());
        assert!(normalize(&vec![0; MAX_BYTES + 1]).is_err());
        assert!(normalize(&png(4097, 1)).is_err());
        let mut corrupt = png(10, 10);
        corrupt.truncate(25);
        assert!(normalize(&corrupt).is_err());
    }
    #[test]
    fn address_policy_rejects_special_addresses_for_everyone() {
        for address in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.169.254",
            "100.100.100.200",
            "198.18.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "2002:7f00:1::",
            "64:ff9b::7f00:1",
        ] {
            let ip = address.parse().unwrap();
            assert!(!allowed_ip(ip, false), "{address}");
            assert!(!allowed_ip(ip, true), "{address}");
        }
        for address in [
            "192.168.10.20",
            "10.1.1.1",
            "172.16.1.1",
            "fd00::1",
            "::ffff:192.168.1.1",
        ] {
            let ip = address.parse().unwrap();
            assert!(!allowed_ip(ip, false));
            assert!(allowed_ip(ip, true));
        }
        for address in ["8.8.8.8", "2001:4860:4860::8888"] {
            assert!(allowed_ip(address.parse().unwrap(), false));
        }
        for url in [
            "file:///etc/passwd",
            "http://user:password@example.com/image.png",
            "ftp://example.com/icon.png",
        ] {
            assert!(parse_url(url).is_err());
        }
    }
    #[tokio::test]
    async fn upload_commit_reuse_rollback_and_delete_permissions() {
        let (state, headers, _directory) = fixture();
        let mut draft = input();
        draft.icon_upload = Some(upload());
        let created = create_tunnel(State(state.clone()), headers.clone(), Json(draft))
            .await
            .unwrap()
            .0;
        let shared = list(State(state.clone()), headers.clone()).await.unwrap().0;
        assert_eq!(shared.len(), 1);
        assert_eq!(created.icon_id, Some(shared[0].id.clone()));
        let id = shared[0].id.strip_prefix("upload/").unwrap().to_string();
        let file = path(&state, &id).unwrap();
        assert!(file.is_file());
        assert!(
            image(State(state.clone()), headers.clone(), Path(id.clone()))
                .await
                .is_ok()
        );
        assert_eq!(
            image(State(state.clone()), HeaderMap::new(), Path(id.clone()))
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            delete(State(state.clone()), headers.clone(), Path(id.clone()))
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );

        // 其他空间可绑定同一个共享图标，但无权更新原服务。
        state
            .db
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO tenants(id,name,created_at) VALUES('foreign','其他空间',0);",
            )
            .unwrap();
        let mut foreign = headers.clone();
        foreign.insert("x-nexo-internal-workspace", "foreign".parse().unwrap());
        assert_eq!(
            list(State(state.clone()), foreign.clone())
                .await
                .unwrap()
                .0
                .len(),
            1
        );
        let mut other = input();
        other.name = "SSH".into();
        other.protocol = "tcp".into();
        other.service_mode = Some("tunnel".into());
        other.public_domain_id = None;
        other.hostname = None;
        other.origin_protocol = None;
        other.icon_id = Some(created.icon_id.clone());
        // 服务保存校验本身不区分共享图标的来源空间。
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('other','foreign','其他服务','tcp','127.0.0.1',22,0,0)", []).unwrap();
            super::super::save(&db, "foreign", "other", &other).unwrap();
        }
        let mut invalid = input();
        invalid.icon_upload = Some(upload());
        invalid.local_port = 0;
        assert!(update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
            Json(invalid)
        )
        .await
        .is_err());
        assert_eq!(fs::read_dir(file.parent().unwrap()).unwrap().count(), 1);
        assert_eq!(
            list(State(state.clone()), headers.clone())
                .await
                .unwrap()
                .0
                .len(),
            1
        );
        let mut conflicting = input();
        conflicting.icon_upload = Some(upload());
        conflicting.icon_id = Some(None);
        assert!(
            create_tunnel(State(state.clone()), headers.clone(), Json(conflicting))
                .await
                .is_err()
        );

        let mut reset = input();
        reset.icon_id = Some(None);
        let before: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT apply_revision FROM tunnels WHERE id=?1",
                [&created.id],
                |r| r.get(0),
            )
            .unwrap();
        let _ = update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
            Json(reset),
        )
        .await
        .unwrap();
        let after: i64 = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT apply_revision FROM tunnels WHERE id=?1",
                [&created.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            delete(State(state.clone()), headers.clone(), Path(id.clone()))
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE tunnels SET deleted_at=1 WHERE id='other'", [])
            .unwrap();
        let mut no_csrf = headers.clone();
        no_csrf.remove("x-nexo-csrf");
        assert_eq!(
            delete(State(state.clone()), no_csrf, Path(id.clone()))
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE users SET role='tenant' WHERE id='u'", [])
            .unwrap();
        assert_eq!(
            delete(State(state.clone()), headers.clone(), Path(id.clone()))
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE users SET role='system_admin' WHERE id='u'", [])
            .unwrap();
        let _ = delete(State(state.clone()), headers.clone(), Path(id.clone()))
            .await
            .unwrap();
        assert!(!file.exists());
        assert!(list(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0
            .is_empty());
        assert_eq!(
            image(State(state.clone()), headers, Path(id))
                .await
                .unwrap_err()
                .status,
            StatusCode::NOT_FOUND
        );
    }
    #[tokio::test]
    async fn preview_requires_auth_and_never_persists_rejected_urls() {
        let (state, headers, _directory) = fixture();
        let input = || {
            Json(PreviewInput {
                url: "http://127.0.0.1/icon.png".into(),
            })
        };
        assert_eq!(
            preview(State(state.clone()), HeaderMap::new(), input())
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        let mut no_csrf = headers.clone();
        no_csrf.remove("x-nexo-csrf");
        assert_eq!(
            preview(State(state.clone()), no_csrf, input())
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        assert!(preview(State(state.clone()), headers.clone(), input())
            .await
            .is_err());
        assert!(!state.data_dir.join("service-icons").exists());
        assert!(list(State(state.clone()), headers)
            .await
            .unwrap()
            .0
            .is_empty());
    }
    #[tokio::test]
    async fn pending_files_are_cleaned_when_service_is_not_committed() {
        let (state, headers, _directory) = fixture();
        let mut draft = input();
        draft.icon_upload = Some(upload());
        let pending = prepare(&state, &mut draft).await.unwrap().unwrap();
        assert!(pending.path.is_file());
        let target = pending.path.clone();
        drop(pending);
        assert!(!target.exists());
        // 同样覆盖文件写入失败，不能留下共享记录。
        let directory = state.data_dir.join("service-icons");
        fs::remove_dir(&directory).unwrap();
        fs::write(&directory, b"blocked").unwrap();
        let mut draft = input();
        draft.icon_upload = Some(upload());
        assert!(
            create_tunnel(State(state.clone()), headers.clone(), Json(draft))
                .await
                .is_err()
        );
        assert!(list(State(state), headers).await.unwrap().0.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn binding_and_deletion_cannot_leave_a_missing_reference() {
        let (state, headers, _directory) = fixture();
        let created = create_tunnel(State(state.clone()), headers.clone(), Json(input()))
            .await
            .unwrap()
            .0;
        let id = Uuid::new_v4().to_string();
        let target = path(&state, &id).unwrap();
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, png(8, 8)).unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO service_icons(id,name,created_at) VALUES(?1,'并发图标',0)",
                [&id],
            )
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let update = {
            let state = state.clone();
            let headers = headers.clone();
            let barrier = barrier.clone();
            let id = id.clone();
            let tunnel_id = created.id.clone();
            tokio::spawn(async move {
                let mut draft = input();
                draft.icon_id = Some(Some(format!("upload/{id}")));
                barrier.wait().await;
                update_tunnel(State(state), headers, Path(tunnel_id), Json(draft)).await
            })
        };
        let remove = {
            let state = state.clone();
            let headers = headers.clone();
            let barrier = barrier.clone();
            let id = id.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                delete(State(state), headers, Path(id)).await
            })
        };
        let (updated, deleted) = tokio::join!(update, remove);
        let updated = updated.unwrap();
        let deleted = deleted.unwrap();
        let current: Option<String> = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT icon_id FROM tunnels WHERE id=?1",
                [&created.id],
                |r| r.get(0),
            )
            .unwrap();
        if updated.is_ok() {
            assert_eq!(deleted.unwrap_err().status, StatusCode::CONFLICT);
            assert_eq!(current, Some(format!("upload/{id}")));
            assert!(target.is_file());
        } else {
            assert!(deleted.is_ok());
            assert_eq!(current, None);
            assert!(!target.exists());
        }
    }

    #[tokio::test]
    async fn failed_delete_commit_restores_the_image_and_catalog_entry() {
        let (state, headers, _directory) = fixture();
        let mut draft = input();
        draft.icon_upload = Some(upload());
        let mut pending = prepare(&state, &mut draft).await.unwrap().unwrap();
        {
            let db = state.db.lock().unwrap();
            pending.register(&db).unwrap();
            pending.commit();
            // 延迟外键约束在提交时失败，覆盖图片已暂存后的恢复分支。
            db.execute_batch("CREATE TABLE delete_guard(icon_id TEXT REFERENCES service_icons(id) DEFERRABLE INITIALLY DEFERRED)").unwrap();
            db.execute(
                "INSERT INTO delete_guard(icon_id) VALUES(?1)",
                [&pending.id],
            )
            .unwrap();
        }
        assert!(delete(
            State(state.clone()),
            headers.clone(),
            Path(pending.id.clone())
        )
        .await
        .is_err());
        assert!(pending.path.is_file());
        assert!(!pending.path.with_extension("deleting").exists());
        assert_eq!(
            list(State(state.clone()), headers.clone())
                .await
                .unwrap()
                .0
                .len(),
            1
        );
        state
            .db
            .lock()
            .unwrap()
            .execute("DELETE FROM delete_guard", [])
            .unwrap();
        let _ = delete(State(state), headers, Path(pending.id.clone()))
            .await
            .unwrap();
        assert!(!pending.path.exists());
    }

    /// 用测试机自身的内网地址提供图片，验证真实 HTTP 下载；生产接口绝不放开回环地址。
    #[tokio::test]
    #[ignore = "需要 NEXO_ICON_TEST_LAN_IP 指定测试机自身可访问的私有 IPv4"]
    async fn lan_http_preview_download_limits_redirects_and_save_round_trip() {
        use axum::{body::Body, response::Redirect};
        let ip: std::net::Ipv4Addr = std::env::var("NEXO_ICON_TEST_LAN_IP")
            .expect("需要测试机自身的内网 IP")
            .parse()
            .unwrap();
        assert!(ip.is_private());
        let bytes = png(320, 160);
        let source = Router::new()
            .route(
                "/image",
                get(move || {
                    let bytes = bytes.clone();
                    async move { ([(axum::http::header::CONTENT_TYPE, "image/png")], bytes) }
                }),
            )
            .route("/redirect", get(|| async { Redirect::temporary("/image") }))
            .route(
                "/blocked",
                get(|| async { Redirect::temporary("http://127.0.0.1:9/image") }),
            )
            .route("/loop", get(|| async { Redirect::temporary("/loop") }))
            .route("/large", get(|| async { vec![0u8; MAX_BYTES + 1] }))
            .route(
                "/stream-large",
                get(|| async {
                    Body::from_stream(futures_util::stream::iter([
                        Ok::<_, std::io::Error>(vec![0u8; MAX_BYTES]),
                        Ok(vec![0u8; 1]),
                    ]))
                }),
            )
            .route(
                "/slow",
                get(|| async {
                    tokio::time::sleep(Duration::from_secs(20)).await;
                    "slow"
                }),
            )
            .route("/svg", get(|| async { "<svg/>" }));
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let source_task = tokio::spawn(async move {
            axum::serve(listener, source).await.unwrap();
        });
        let (state, headers, _directory) = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let routes = router(state.clone());
        let api_task = tokio::spawn(async move {
            axum::serve(listener, routes).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .default_headers(headers.clone())
            .build()
            .unwrap();
        let preview_url = format!("{base}/api/v1/service-icons/preview");
        let response = client
            .post(&preview_url)
            .json(&json!({"url":format!("http://{address}/redirect")}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let uploaded: Upload = response.json().await.unwrap();
        assert_eq!(
            image::load_from_memory(&decode(&uploaded.data_url).unwrap())
                .unwrap()
                .width(),
            256
        );
        assert!(list(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0
            .is_empty());
        assert!(!state.data_dir.join("service-icons").exists());
        for route in ["blocked", "loop", "large", "stream-large", "slow", "svg"] {
            let response = client
                .post(&preview_url)
                .json(&json!({"url":format!("http://{address}/{route}")}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{route}");
        }
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE users SET role='tenant' WHERE id='u'", [])
            .unwrap();
        assert_eq!(
            client
                .post(&preview_url)
                .json(&json!({"url":format!("http://{address}/image")}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE users SET role='system_admin' WHERE id='u'", [])
            .unwrap();
        let mut value = json!({"service_mode":"reverse_proxy","name":"链接图片","protocol":"http","origin_protocol":"http","local_address":"127.0.0.1","local_port":8096,"hostname":"link-icon","public_domain_id":"domain","icon_upload":uploaded});
        let response = client
            .post(format!("{base}/api/v1/tunnels"))
            .json(&value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let tunnel: serde_json::Value = response.json().await.unwrap();
        let id = tunnel["icon_id"]
            .as_str()
            .unwrap()
            .strip_prefix("upload/")
            .unwrap();
        assert_eq!(
            client
                .get(format!("{base}/api/v1/service-icons/{id}/image"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // 原图 Base64 会超过 Axum 默认 2 MiB 请求体限制，创建和更新路由均须接受。
        let mut original = png(8, 8);
        original.resize(MAX_BYTES, 0);
        value["icon_upload"] = json!({"name":"较大原图","data_url":format!("data:image/png;base64,{}",STANDARD.encode(original))});
        assert!(serde_json::to_vec(&value).unwrap().len() > MAX_BYTES);
        let response = client
            .put(format!(
                "{base}/api/v1/tunnels/{}",
                tunnel["id"].as_str().unwrap()
            ))
            .json(&value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        value["hostname"] = json!("large-icon");
        let response = client
            .post(format!("{base}/api/v1/tunnels"))
            .json(&value)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            list(State(state.clone()), headers.clone())
                .await
                .unwrap()
                .0
                .len(),
            3
        );
        // 重开数据库后，图片仍从同一持久化目录读取。
        let database = state.data_dir.join("restored.db");
        state
            .db
            .lock()
            .unwrap()
            .execute("VACUUM INTO ?1", [database.to_str().unwrap()])
            .unwrap();
        let mut restored = state.clone();
        let db = Connection::open(database).unwrap();
        initialize_database(&db, false).unwrap();
        restored.db = Arc::new(Mutex::new(db));
        assert!(image(State(restored), headers, Path(id.to_owned()))
            .await
            .is_ok());
        source_task.abort();
        api_task.abort();
    }
}
