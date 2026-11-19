//! Nexo 的共享领域类型。

use std::{
    sync::LazyLock,
    time::{SystemTime, UNIX_EPOCH},
};

pub mod config;
pub mod enrollment;
pub mod telemetry;

pub use enrollment::{EnrollmentError, EnrollmentStatus, EnrollmentToken, PendingEnrollment};

/// 与隧道共用 ring。升级 reqwest 后仍使用内置公共 CA，避免各平台的本机证书改变信任范围。
pub fn http_client_builder() -> reqwest::ClientBuilder {
    static PUBLIC_TLS: LazyLock<rustls::ClientConfig> = LazyLock::new(|| {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // reqwest 接收预配 TLS 时由调用方提供 ALPN，保留 HTTP/1.1 Upgrade 行为。
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls
    });
    reqwest::Client::builder().tls_backend_preconfigured(PUBLIC_TLS.clone())
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}
