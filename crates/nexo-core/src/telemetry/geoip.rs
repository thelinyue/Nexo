use anyhow::{ensure, Context, Result};
use flate2::read::MultiGzDecoder;
use maxminddb::{path, Reader};
use reqwest::{Client, StatusCode};
use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};
use time::{Date, OffsetDateTime};
use tokio_util::task::AbortOnDropHandle;

const DOWNLOAD_ROOT: &str = "https://download.db-ip.com/free";
const FILE_PREFIX: &str = "dbip-country-lite-";
const MAX_ARCHIVE: usize = 16 * 1024 * 1024;
const MAX_DATABASE: usize = 32 * 1024 * 1024;

#[derive(Debug)]
struct Database {
    reader: Reader<Vec<u8>>,
    month: String,
}

/// 每个采集端使用自己的持久缓存。手动指定库时完全由管理员维护。
#[derive(Debug)]
pub(super) struct CountryLookup {
    cache: Option<PathBuf>,
    active: RwLock<Option<Database>>,
}

impl CountryLookup {
    pub(super) fn open(configured: Option<&OsStr>, data_dir: Option<&Path>) -> Self {
        if let Some(path) = configured {
            let active = match Reader::open_readfile(path) {
                Ok(reader) => Some(Database {
                    reader,
                    month: String::new(),
                }),
                Err(error) => {
                    tracing::warn!(%error, "无法加载 NEXO_GEOIP_DATABASE，请检查 MMDB 文件及读取权限");
                    None
                }
            };
            return Self {
                cache: None,
                active: RwLock::new(active),
            };
        }
        let cache = data_dir.map(|path| path.join("geoip"));
        let active = cache.as_deref().and_then(|path| match load_cache(path) {
            Ok(database) => database,
            Err(error) => {
                tracing::warn!(%error, "无法读取 GeoIP 缓存，请检查数据目录权限");
                None
            }
        });
        Self {
            cache,
            active: RwLock::new(active),
        }
    }

    pub(super) fn available(&self) -> bool {
        self.active.read().unwrap().is_some()
    }

    pub(super) fn country(&self, ip: IpAddr) -> Option<String> {
        let active = self.active.read().unwrap();
        let record = active.as_ref()?.reader.lookup(ip).ok()?;
        // 热路径只解码实际展示的字段，保留中文名优先及国家码回退。
        record
            .decode_path::<&str>(&path!["country", "names", "zh-CN"])
            .ok()?
            .filter(|name| !name.is_empty() && name.len() <= 128)
            .or_else(|| {
                record
                    .decode_path(&path!["country", "iso_code"])
                    .ok()
                    .flatten()
            })
            .map(str::to_owned)
    }

    pub(super) fn start(self: &Arc<Self>) -> Option<AbortOnDropHandle<()>> {
        self.cache.as_ref()?;
        let lookup = self.clone();
        Some(AbortOnDropHandle::new(tokio::spawn(async move {
            let client = crate::http_client_builder()
                .user_agent(concat!("Nexo/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(60))
                .redirect(reqwest::redirect::Policy::none())
                .build();
            let client = match client {
                Ok(client) => client,
                Err(error) => {
                    tracing::warn!(%error, "GeoIP 下载客户端初始化失败，请检查网络配置");
                    return;
                }
            };
            loop {
                if let Err(error) = lookup
                    .refresh(&client, DOWNLOAD_ROOT, OffsetDateTime::now_utc().date())
                    .await
                {
                    tracing::warn!(error = %format_args!("{error:#}"), "GeoIP 更新失败，将使用可用缓存并在 24 小时后重试");
                }
                tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
            }
        })))
    }

    async fn refresh(&self, client: &Client, root: &str, today: Date) -> Result<()> {
        let Some(cache) = &self.cache else {
            return Ok(());
        };
        let mut month = month_name(today);
        let previous = self
            .active
            .read()
            .unwrap()
            .as_ref()
            .map(|db| db.month.clone());
        if previous.as_ref().is_some_and(|cached| cached >= &month) {
            return Ok(());
        }
        let mut archive = download(client, root, &month).await?;
        if archive.is_none() && previous.is_none() {
            let last_month = today
                .replace_day(1)?
                .previous_day()
                .context("无法计算上个月")?;
            month = month_name(last_month);
            archive = download(client, root, &month).await?;
        }
        let Some(archive) = archive else {
            // 月初可能还没有新库。有可用缓存时等下次例行检查。
            ensure!(previous.is_some(), "DB-IP 尚未提供可下载的月度国家库");
            return Ok(());
        };

        let cache = cache.clone();
        let database = tokio::task::spawn_blocking(move || {
            let database = save(&cache, month, &archive)?;
            if let Some(previous) = previous {
                match fs::remove_file(database_path(&cache, &previous)) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        tracing::warn!(%error, "无法清理旧 GeoIP 缓存");
                    }
                    _ => {}
                }
            }
            Ok::<_, anyhow::Error>(database)
        })
        .await??;
        let month = database.month.clone();
        *self.active.write().unwrap() = Some(database);
        tracing::info!(%month, "已加载 DB-IP 国家／地区数据库");
        Ok(())
    }
}

fn month_name(date: Date) -> String {
    format!("{:04}-{:02}", date.year(), u8::from(date.month()))
}

fn database_path(cache: &Path, month: &str) -> PathBuf {
    cache.join(format!("{FILE_PREFIX}{month}.mmdb"))
}

fn load_cache(cache: &Path) -> Result<Option<Database>> {
    let entries = match fs::read_dir(cache) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut months: Vec<_> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let month = name
                .to_str()?
                .strip_prefix(FILE_PREFIX)?
                .strip_suffix(".mmdb")?;
            let (year, number) = month.split_once('-')?;
            (year.len() == 4
                && number.len() == 2
                && year.bytes().all(|byte| byte.is_ascii_digit())
                && ("01"..="12").contains(&number)
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && entry.file_type().ok()?.is_file())
            .then(|| month.to_owned())
        })
        .collect();
    months.sort_unstable_by(|a, b| b.cmp(a));
    for month in months {
        let reader = File::open(database_path(cache, &month))
            .map_err(anyhow::Error::from)
            .and_then(read_database_bytes)
            .and_then(open_managed);
        match reader {
            Ok(reader) => return Ok(Some(Database { reader, month })),
            Err(error) => {
                tracing::warn!(%month, %error, "GeoIP 缓存无法读取，将尝试旧版本或重新下载")
            }
        }
    }
    Ok(None)
}

async fn download(client: &Client, root: &str, month: &str) -> Result<Option<Vec<u8>>> {
    let mut response = client
        .get(format!("{root}/{FILE_PREFIX}{month}.mmdb.gz"))
        .send()
        .await
        .context("无法连接 DB-IP 下载服务")?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    ensure!(
        response.status().is_success(),
        "DB-IP 返回 HTTP {}",
        response.status()
    );
    ensure!(
        response.content_length().unwrap_or_default() <= MAX_ARCHIVE as u64,
        "GeoIP 下载文件超过大小上限"
    );
    let mut archive = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            archive.len() + chunk.len() <= MAX_ARCHIVE,
            "GeoIP 下载文件超过大小上限"
        );
        archive.extend_from_slice(&chunk);
    }
    Ok(Some(archive))
}

fn read_database_bytes(input: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input
        .take(MAX_DATABASE as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_DATABASE, "GeoIP 数据库超过大小上限");
    Ok(bytes)
}

fn open_managed(bytes: Vec<u8>) -> Result<Reader<Vec<u8>>> {
    let reader = Reader::from_source(bytes).context("无法解析 GeoIP MMDB")?;
    ensure!(
        reader.metadata().database_type == "DBIP-Country-Lite",
        "下载内容不是 DB-IP Country Lite 数据库"
    );
    Ok(reader)
}

fn save(cache: &Path, month: String, archive: &[u8]) -> Result<Database> {
    let bytes =
        read_database_bytes(MultiGzDecoder::new(archive)).context("无法解压 GeoIP 数据库")?;
    fs::create_dir_all(cache).context("无法创建 GeoIP 缓存目录")?;
    let mut temp = tempfile::NamedTempFile::new_in(cache).context("无法创建 GeoIP 临时文件")?;
    temp.write_all(&bytes).context("无法写入 GeoIP 临时文件")?;
    let reader = open_managed(bytes)?;
    // 先完成解码和持久化，再覆盖磁盘路径与查询使用的 reader。
    temp.as_file()
        .sync_all()
        .context("无法同步 GeoIP 临时文件")?;
    temp.persist(database_path(cache, &month))
        .context("无法替换 GeoIP 缓存文件")?;
    Ok(Database { reader, month })
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Month;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::TcpListener,
        task::JoinHandle,
    };

    async fn fixture(
        replies: Vec<(&'static str, &'static str, Vec<u8>)>,
    ) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            for (month, status, body) in replies {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut line = String::new();
                socket.read_line(&mut line).await.unwrap();
                assert_eq!(
                    line,
                    format!("GET /{FILE_PREFIX}{month}.mmdb.gz HTTP/1.1\r\n")
                );
                loop {
                    line.clear();
                    let bytes = socket.read_line(&mut line).await.unwrap();
                    if bytes == 0 || line == "\r\n" {
                        break;
                    }
                }
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let socket = socket.get_mut();
                socket.write_all(head.as_bytes()).await.unwrap();
                socket.write_all(&body).await.unwrap();
            }
        });
        (url, task)
    }

    #[tokio::test]
    #[ignore = "需要官方 DB-IP Country Lite gzip，请设置 NEXO_TEST_DBIP_GZIP"]
    async fn updates_and_reopens_real_country_cache() {
        let archive = fs::read(std::env::var_os("NEXO_TEST_DBIP_GZIP").unwrap()).unwrap();
        let data = tempfile::tempdir().unwrap();
        let cache = data.path().join("geoip");
        let lookup = CountryLookup::open(None, Some(data.path()));
        let client = crate::http_client_builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let ipv4 = "8.8.8.8".parse().unwrap();
        let ipv6 = "2001:4860:4860::8888".parse().unwrap();
        let january = Date::from_calendar_date(2026, Month::January, 2).unwrap();
        assert!(!lookup.available());

        let (url, server) = fixture(vec![
            ("2026-01", "404 Not Found", vec![]),
            ("2025-12", "200 OK", archive.clone()),
            ("2026-01", "200 OK", b"bad gzip".to_vec()),
            ("2026-01", "200 OK", archive),
        ])
        .await;
        lookup.refresh(&client, &url, january).await.unwrap();
        assert!(database_path(&cache, "2025-12").is_file());
        assert_eq!(lookup.country(ipv4).as_deref(), Some("美国"));
        let ipv6_country = lookup.country(ipv6).unwrap();
        assert_ne!(ipv6_country, "未知");
        assert!(lookup.country("127.0.0.1".parse().unwrap()).is_none());

        assert!(lookup.refresh(&client, &url, january).await.is_err());
        assert_eq!(lookup.country(ipv4).as_deref(), Some("美国"));
        assert!(database_path(&cache, "2025-12").is_file());
        assert!(!database_path(&cache, "2026-01").exists());

        lookup.refresh(&client, &url, january).await.unwrap();
        server.await.unwrap();
        let current = database_path(&cache, "2026-01");
        assert!(current.is_file());
        assert!(!database_path(&cache, "2025-12").exists());
        lookup.refresh(&client, &url, january).await.unwrap();
        let restarted = CountryLookup::open(None, Some(data.path()));
        assert_eq!(
            restarted.country(ipv6).as_deref(),
            Some(ipv6_country.as_str())
        );
        let manually_configured = Arc::new(CountryLookup::open(
            Some(current.as_os_str()),
            Some(data.path()),
        ));
        assert!(manually_configured.start().is_none());
        assert_eq!(manually_configured.country(ipv4).as_deref(), Some("美国"));
        let unavailable_override = Arc::new(CountryLookup::open(
            Some(OsStr::new("missing.mmdb")),
            Some(data.path()),
        ));
        assert!(unavailable_override.start().is_none());
        assert!(!unavailable_override.available());

        let hub = Arc::new(super::super::Hub {
            geo: manually_configured,
            ..Default::default()
        });
        drop(hub.session("t", "tcp", Some("::ffff:8.8.8.8".parse().unwrap())));
        drop(hub.session("u", "udp", Some(ipv6)));
        let batch = hub.batch();
        assert_eq!(batch.events[0].source, "8.8.8.0/24");
        assert_eq!(batch.events[0].country, "美国");
        assert_eq!(batch.events[1].source, "2001:4860:4860::/48");
        assert_eq!(batch.events[1].country, ipv6_country);
    }
}
