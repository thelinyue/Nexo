//! Tunnel 身份只服务于 Server/Agent mTLS，与 Caddy 公网证书分离。
//! Agent 私钥在本机生成，Server 只签 CSR 公钥；两端启动时复用持久身份。

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path, sync::Arc};
use time::{Duration, OffsetDateTime};

pub const SERVER_NAME: &str = "nexo-server";
pub const MAX_CONTROL_FRAME: usize = 1024 * 1024;
pub const RENEW_BEFORE: i64 = 30 * 86400;

/// 续签失败使用有上限的退避；持久化后重启不会绕过重试时间。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RenewalRetry {
    pub failures: u32,
    pub error: Option<String>,
    pub next_retry_at: Option<i64>,
}
impl RenewalRetry {
    pub fn failed(&mut self, now: i64, error: &str) {
        self.failures = self.failures.saturating_add(1);
        self.error = Some(error.chars().take(512).collect());
        self.next_retry_at =
            Some(now + (30_i64 * (1_i64 << self.failures.saturating_sub(1).min(7))).min(3600));
    }
    pub fn ready(&self, now: i64) -> bool {
        self.next_retry_at.is_none_or(|next| next <= now)
    }
}

pub fn certificate_info(pem: &str) -> Result<(String, i64)> {
    let certs = certificates(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|_| anyhow::anyhow!("身份 X.509 证书无效"))?;
    let name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        .unwrap_or_default()
        .to_owned();
    Ok((name, cert.validity().not_after.timestamp()))
}

/// 私有 CA 和服务端身份作为一个文件原子落盘，避免重启生成另一套信任根。
#[derive(Clone, Serialize, Deserialize)]
pub struct Authority {
    pub ca_pem: String,
    ca_key: String,
    server_pem: String,
    server_key: String,
}

impl Authority {
    pub fn server_expires_at(&self) -> Result<i64> {
        Ok(certificate_info(&self.server_pem)?.1)
    }
    pub fn ca_expires_at(&self) -> Result<i64> {
        Ok(certificate_info(&self.ca_pem)?.1)
    }

    /// 使用原 CA 签发新的服务端密钥和证书，先落盘后替换内存，保留 Agent 的信任根。
    pub fn renew_server(&self, path: &Path, now: i64) -> Result<Self> {
        let mut next = self.clone();
        let issuer = Issuer::from_ca_cert_pem(&self.ca_pem, KeyPair::from_pem(&self.ca_key)?)?;
        let mut params = CertificateParams::new(vec![SERVER_NAME.into()])?;
        params.use_authority_key_identifier_extension = true;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = OffsetDateTime::from_unix_timestamp(now)? - Duration::minutes(5);
        params.not_after =
            OffsetDateTime::from_unix_timestamp((now + 825 * 86400).min(self.ca_expires_at()?))?;
        anyhow::ensure!(
            params.not_after.unix_timestamp() > now + RENEW_BEFORE,
            "内部 CA 即将到期，请管理员更换信任根"
        );
        let key = KeyPair::generate()?;
        next.server_pem = params.signed_by(&key, &issuer)?.pem();
        next.server_key = key.serialize_pem();
        next.server_config()?;
        write_private_file(path, &serde_json::to_vec(&next)?)?;
        Ok(next)
    }
    pub fn generate() -> Result<Self> {
        let now = OffsetDateTime::now_utc();
        let mut ca = CertificateParams::new(Vec::<String>::new())?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(DnType::CommonName, "Nexo Device CA");
        ca.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        ca.not_before = now - Duration::days(1);
        ca.not_after = now + Duration::days(3650);
        let key = KeyPair::generate()?;
        let ca_pem = ca.self_signed(&key)?.pem();
        let ca_key = key.serialize_pem();
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, key)?;
        let mut server = CertificateParams::new(vec![SERVER_NAME.into()])?;
        server.use_authority_key_identifier_extension = true;
        server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server.not_before = now - Duration::days(1);
        server.not_after = now + Duration::days(825);
        let key = KeyPair::generate()?;
        Ok(Self {
            ca_pem,
            ca_key,
            server_pem: server.signed_by(&key, &issuer)?.pem(),
            server_key: key.serialize_pem(),
        })
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .context("Tunnel 身份文件无效，请恢复备份；不会自动重建 CA"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate()?;
                write_private_file(path, &serde_json::to_vec(&identity)?)?;
                Ok(identity)
            }
            Err(error) => Err(error).context("无法读取 Tunnel 服务端身份"),
        }
    }

    pub fn issue_device(&self, csr: &str, device_id: &str) -> Result<String> {
        let request = CertificateSigningRequestParams::from_pem(csr)
            .context("设备 CSR 无效或签名校验失败")?;
        let issuer = Issuer::from_ca_cert_pem(&self.ca_pem, KeyPair::from_pem(&self.ca_key)?)?;
        // 忽略请求的扩展，仅签发指定设备的客户端证书，不允许 Agent 请求 CA 权限。
        let mut params = CertificateParams::new(vec![format!("device-{device_id}.nexo")])?;
        params.use_authority_key_identifier_extension = true;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, device_id);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        let expiry =
            (OffsetDateTime::now_utc().unix_timestamp() + 365 * 86400).min(self.ca_expires_at()?);
        anyhow::ensure!(
            expiry > OffsetDateTime::now_utc().unix_timestamp() + RENEW_BEFORE,
            "内部 CA 即将到期，请管理员更换信任根"
        );
        params.not_after = OffsetDateTime::from_unix_timestamp(expiry)?;
        Ok(params.signed_by(&request.public_key, &issuer)?.pem())
    }

    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let verifier =
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots(&self.ca_pem)?))
                .build()?;
        Ok(Arc::new(
            rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(
                    certificates(&self.server_pem)?,
                    private_key(&self.server_key)?,
                )?,
        ))
    }
}

pub fn validate_csr(csr: &str) -> Result<()> {
    anyhow::ensure!(csr.len() <= 16384, "设备 CSR 过长");
    CertificateSigningRequestParams::from_pem(csr).context("设备 CSR 无效或签名校验失败")?;
    Ok(())
}

pub fn certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certificates =
        rustls_pemfile::certs(&mut pem.as_bytes()).collect::<std::io::Result<Vec<_>>>()?;
    anyhow::ensure!(!certificates.is_empty(), "证书 PEM 为空或格式无效");
    Ok(certificates)
}
fn private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_bytes())?.context("私钥 PEM 格式无效")
}
pub fn roots(pem: &str) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certificates(pem)? {
        roots.add(cert)?;
    }
    Ok(roots)
}
pub fn client_config(ca: &str, cert: &str, key: &str) -> Result<Arc<rustls::ClientConfig>> {
    Ok(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots(ca)?)
            .with_client_auth_cert(certificates(cert)?, private_key(key)?)?,
    ))
}

/// 原子保存身份，Unix 在打开临时文件时即限制为 0600，避免私钥短暂可被其他用户读取。
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("身份文件缺少父目录")?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let temporary = path.with_extension("tmp");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path).context("无法原子保存身份文件")?;
    #[cfg(unix)]
    fs::File::open(parent)?
        .sync_all()
        .context("无法同步身份目录")?;
    Ok(())
}

pub async fn write_message<W: tokio::io::AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut bytes = serde_json::to_vec(value)?;
    anyhow::ensure!(bytes.len() <= MAX_CONTROL_FRAME, "控制消息超过大小限制");
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renewal_backoff_is_bounded_and_restorable() {
        let mut retry = RenewalRetry::default();
        for delay in [30, 60, 120, 240, 480, 960, 1920, 3600, 3600] {
            retry.failed(1000, "存储暂不可用");
            assert_eq!(retry.next_retry_at, Some(1000 + delay));
            assert!(!retry.ready(1000 + delay - 1));
            retry = serde_json::from_slice(&serde_json::to_vec(&retry).unwrap()).unwrap();
            assert!(retry.ready(1000 + delay));
        }
    }
}
