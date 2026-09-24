//! 内部身份续签：CA 保持不变，设备新证书分为“已签发”和“已安装”，不修改设备或服务记录。
use crate::{unix_now, AppState};
use anyhow::{Context, Result};
use nexo_tunnel::identity::{self, Authority, RenewalRetry, RENEW_BEFORE};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug, Serialize)]
pub struct CertificateStatus {
    pub status: &'static str,
    pub expires_at: Option<i64>,
    pub renew_after: Option<i64>,
    pub error: Option<String>,
    pub next_retry_at: Option<i64>,
}
fn status(expiry: Option<i64>, retry: &RenewalRetry, now: i64) -> CertificateStatus {
    CertificateStatus {
        status: if expiry.is_none() {
            "unknown"
        } else if expiry.is_some_and(|expiry| expiry <= now) {
            "expired"
        } else if retry.error.is_some() {
            "retry_wait"
        } else if expiry.is_some_and(|expiry| expiry <= now + RENEW_BEFORE) {
            "expiring"
        } else {
            "valid"
        },
        expires_at: expiry,
        renew_after: expiry.map(|expiry| expiry - RENEW_BEFORE),
        error: retry.error.clone(),
        next_retry_at: retry.next_retry_at,
    }
}

struct AuthorityState {
    authority: Authority,
    tls: Arc<rustls::ServerConfig>,
    retry: RenewalRetry,
}
#[derive(Serialize, Deserialize)]
struct SavedRenewal {
    certificate_expires_at: i64,
    retry: RenewalRetry,
}
/// TLS 配置按新连接读取快照，续签无需关闭监听器或现有 Tunnel 流。
pub struct AuthorityRuntime {
    inner: Mutex<AuthorityState>,
    path: PathBuf,
}
impl AuthorityRuntime {
    pub fn new(authority: Authority, path: PathBuf) -> Result<Self> {
        let retry = std::fs::read(path.with_file_name("renewal.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<SavedRenewal>(&bytes).ok())
            // 证书保存后若进程在清理重试记录前退出，不能把旧证书的错误套到新证书上。
            .filter(|saved| {
                authority.server_expires_at().ok() == Some(saved.certificate_expires_at)
            })
            .map(|saved| saved.retry)
            .unwrap_or_default();
        Ok(Self {
            inner: Mutex::new(AuthorityState {
                tls: authority.server_config()?,
                authority,
                retry,
            }),
            path,
        })
    }
    pub fn ca_pem(&self) -> String {
        self.inner.lock().unwrap().authority.ca_pem.clone()
    }
    pub fn issue_device(&self, csr: &str, device: &str) -> Result<String> {
        self.inner
            .lock()
            .unwrap()
            .authority
            .issue_device(csr, device)
    }
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        self.inner.lock().unwrap().tls.clone()
    }
    pub fn status(&self) -> serde_json::Value {
        let inner = self.inner.lock().unwrap();
        let now = unix_now();
        let ca_expiry = inner.authority.ca_expires_at().ok();
        serde_json::json!({ "server": status(inner.authority.server_expires_at().ok(), &inner.retry, now),
            "ca_expires_at": ca_expiry, "ca_needs_attention": ca_expiry.is_none_or(|expiry| expiry <= now + 180 * 86400) })
    }
    fn renew_if_due(&self, now: i64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.authority.server_expires_at()? > now + RENEW_BEFORE || !inner.retry.ready(now) {
            return Ok(());
        }
        match inner.authority.renew_server(&self.path, now) {
            Ok(next) => {
                inner.tls = next.server_config()?;
                inner.authority = next;
                inner.retry = RenewalRetry::default();
                tracing::info!("内部服务端证书已续签，现有连接继续运行");
            }
            Err(error) => {
                inner
                    .retry
                    .failed(now, &format!("内部服务端证书续签失败：{error:#}"));
                tracing::warn!("{}", inner.retry.error.as_deref().unwrap_or_default());
            }
        }
        if let Err(error) = identity::write_private_file(
            &self.path.with_file_name("renewal.json"),
            &serde_json::to_vec(&SavedRenewal {
                certificate_expires_at: inner.authority.server_expires_at()?,
                retry: inner.retry.clone(),
            })?,
        ) {
            tracing::warn!("无法保存服务端证书重试状态：{error:#}");
        }
        Ok(())
    }
    pub async fn run(state: AppState) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = state.tunnel_runtime.stop.cancelled() => break,
                _ = interval.tick() => if let Err(error) = state.authority.renew_if_due(unix_now()) { tracing::error!("内部证书检查失败：{error:#}"); }
            }
        }
    }
}

pub fn initialize_schema(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS device_certificates (
        device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
        certificate_pem TEXT, pending_csr_pem TEXT, pending_certificate_pem TEXT,
        retry_failures INTEGER NOT NULL DEFAULT 0, renewal_error TEXT, next_retry_at INTEGER
    );
    INSERT OR IGNORE INTO device_certificates (device_id,certificate_pem)
        SELECT p.device_id,r.certificate_pem FROM pending_enrollments p JOIN enrollment_requests r ON r.enrollment_id=p.id
        WHERE p.device_id IS NOT NULL AND r.certificate_pem IS NOT NULL;")?;
    Ok(())
}
pub fn fingerprint(pem: &str) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        identity::certificates(pem)?[0].as_ref(),
    )))
}

/// 只允许仍注册的当前证书或本次待安装证书认证；收到新证书的 mTLS 握手也可补上丢失的安装确认。
pub fn accept_certificate(db: &Connection, device: &str, digest: &str) -> Result<()> {
    let row: Option<(String, Option<String>)> = db.query_row("SELECT i.secret_digest,c.pending_certificate_pem FROM device_identities i JOIN devices d ON d.id=i.device_id LEFT JOIN device_certificates c ON c.device_id=i.device_id WHERE i.device_id=?1", [device], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    let (active, pending) = row.context("Agent 证书未注册或设备已被删除")?;
    if active == digest {
        return Ok(());
    }
    let pending = pending
        .filter(|pem| fingerprint(pem).is_ok_and(|pending| pending == digest))
        .context("Agent 证书已被替换或未注册")?;
    let tx = db.unchecked_transaction()?;
    tx.execute(
        "UPDATE device_identities SET secret_digest=?1 WHERE device_id=?2",
        params![digest, device],
    )?;
    tx.execute("UPDATE device_certificates SET certificate_pem=?1,pending_csr_pem=NULL,pending_certificate_pem=NULL,retry_failures=0,renewal_error=NULL,next_retry_at=NULL WHERE device_id=?2", params![pending,device])?;
    tx.commit()?;
    Ok(())
}

pub fn device_status(db: &Connection, device: &str, now: i64) -> Result<CertificateStatus> {
    let row: Option<(Option<String>, Option<String>, Option<i64>)> = db.query_row("SELECT certificate_pem,renewal_error,next_retry_at FROM device_certificates WHERE device_id=?1", [device], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let (cert, error, next_retry_at) = row.unwrap_or_default();
    let expiry = cert
        .and_then(|pem| identity::certificate_info(&pem).ok())
        .map(|info| info.1);
    Ok(status(
        expiry,
        &RenewalRetry {
            failures: 0,
            error,
            next_retry_at,
        },
        now,
    ))
}

/// 续签不接受请求方传入设备 ID：归属来自已认证控制连接，CSR 仅提供新公钥。
pub fn renew_device(
    state: &AppState,
    device: &str,
    authenticated: &str,
    csr: &str,
    now: i64,
) -> Result<String> {
    identity::validate_csr(csr)?;
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let (active, cert, pending_csr, pending_cert, retry): (String,String,Option<String>,Option<String>,Option<i64>) = db.query_row("SELECT i.secret_digest,c.certificate_pem,c.pending_csr_pem,c.pending_certificate_pem,c.next_retry_at FROM device_identities i JOIN device_certificates c ON c.device_id=i.device_id WHERE i.device_id=?1", [device], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    anyhow::ensure!(
        active == authenticated,
        "续签连接的证书已被替换，请重新连接"
    );
    let expiry = identity::certificate_info(&cert)?.1;
    anyhow::ensure!(expiry > now, "设备证书已过期，请联系管理员恢复设备身份");
    anyhow::ensure!(expiry <= now + RENEW_BEFORE, "设备证书尚未进入续签时间");
    anyhow::ensure!(retry.is_none_or(|retry| retry <= now), "尚未到续签重试时间");
    if pending_csr.as_deref() == Some(csr) {
        if let Some(pem) = pending_cert.filter(|pem| {
            identity::certificate_info(pem).is_ok_and(|(_, expiry)| expiry > now + RENEW_BEFORE)
        }) {
            return Ok(pem);
        }
    }
    let certificate = state.authority.issue_device(csr, device)?;
    db.execute("UPDATE device_certificates SET pending_csr_pem=?1,pending_certificate_pem=?2,renewal_error=NULL,next_retry_at=NULL WHERE device_id=?3", params![csr,certificate,device])?;
    Ok(certificate)
}

pub fn renewal_failed(
    state: &AppState,
    device: &str,
    error: &str,
    reported_retry: Option<i64>,
) -> Result<i64> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let failures: u32 = db.query_row(
        "SELECT retry_failures FROM device_certificates WHERE device_id=?1",
        [device],
        |r| r.get(0),
    )?;
    let now = unix_now();
    let mut retry = RenewalRetry {
        failures,
        ..Default::default()
    };
    retry.failed(now, error);
    if let Some(next) = reported_retry {
        retry.next_retry_at = Some(next.clamp(now + 30, now + 3600));
    }
    db.execute("UPDATE device_certificates SET retry_failures=?1,renewal_error=?2,next_retry_at=?3 WHERE device_id=?4", params![retry.failures,retry.error,retry.next_retry_at,device])?;
    Ok(retry.next_retry_at.unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn device(state: &AppState) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["device-mine.nexo".into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mine");
        params.not_after = time_from_now(5 * 86400);
        // 此单元测试直接调用已经通过 mTLS 的持久化层；真实链校验另由进程验收覆盖。
        let cert = params.self_signed(&key).unwrap().pem();
        let digest = fingerprint(&cert).unwrap();
        let db = state.db.lock().unwrap();
        db.execute("INSERT INTO devices (id,tenant_id,name,created_at,updated_at) VALUES ('mine','default','same-device',0,0)", []).unwrap();
        db.execute(
            "INSERT INTO device_identities VALUES ('mine',?1,0)",
            [&digest],
        )
        .unwrap();
        db.execute(
            "INSERT INTO device_certificates (device_id,certificate_pem) VALUES ('mine',?1)",
            [&cert],
        )
        .unwrap();
        db.execute("INSERT INTO tunnels (id,tenant_id,device_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES ('service','default','mine','same-service','tcp','127.0.0.1',80,0,0)", []).unwrap();
        let csr = CertificateParams::new(vec!["unused.nexo".into()])
            .unwrap()
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();
        (digest, csr)
    }
    fn time_from_now(seconds: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(unix_now() + seconds).unwrap()
    }

    #[test]
    fn renewal_retries_preserve_identity_until_install_and_revoke_old_certificate() {
        let (state, _) = crate::tests::domain_fixture();
        let (old, csr) = device(&state);
        let now = unix_now();
        assert!(renew_device(&state, "mine", "foreign-fingerprint", &csr, now).is_err());
        assert!(renew_device(&state, "mine", &old, &csr, now + 6 * 86400).is_err());
        let next = renew_device(&state, "mine", &old, &csr, now).unwrap();
        assert_eq!(next, renew_device(&state, "mine", &old, &csr, now).unwrap());
        let digest = fingerprint(&next).unwrap();
        assert_ne!(digest, old);
        let db = state.db.lock().unwrap();
        accept_certificate(&db, "mine", &old).unwrap();
        assert!(accept_certificate(&db, "foreign", &digest).is_err());
        // 模拟安装确认丢失后，Agent 重启直接使用新证书进行 mTLS 认证。
        accept_certificate(&db, "mine", &digest).unwrap();
        assert!(accept_certificate(&db, "mine", &old).is_err());
        assert_eq!(
            db.query_row(
                "SELECT device_id FROM tunnels WHERE id='service'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "mine"
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(device_status(&db, "mine", now).unwrap().status, "valid");
        db.execute(
            "UPDATE tunnels SET device_id=NULL WHERE device_id='mine'",
            [],
        )
        .unwrap();
        db.execute("DELETE FROM devices WHERE id='mine'", [])
            .unwrap();
        assert!(accept_certificate(&db, "mine", &digest).is_err());
    }

    #[test]
    fn device_failures_are_persisted_and_early_retries_are_rejected() {
        let (state, _) = crate::tests::domain_fixture();
        let (old, csr) = device(&state);
        let next = renewal_failed(&state, "mine", "磁盘已满", None).unwrap();
        assert!(renew_device(&state, "mine", &old, &csr, unix_now()).is_err());
        let db = state.db.lock().unwrap();
        let snapshot = device_status(&db, "mine", unix_now()).unwrap();
        assert_eq!(snapshot.status, "retry_wait");
        assert_eq!(snapshot.next_retry_at, Some(next));
        assert_eq!(snapshot.error.as_deref(), Some("磁盘已满"));
    }

    #[test]
    fn server_write_failure_keeps_old_tls_and_retry_survives_restart() {
        let directory = std::env::temp_dir().join(format!("nexo-renewal-{}", uuid::Uuid::new_v4()));
        let path = directory.join("identity.json");
        let authority = Authority::load_or_create(&path).unwrap();
        let ca = authority.ca_pem.clone();
        let due = authority.server_expires_at().unwrap() - RENEW_BEFORE;
        let runtime = AuthorityRuntime::new(authority, path.clone()).unwrap();
        let old_tls = runtime.server_config();
        std::fs::create_dir(path.with_extension("tmp")).unwrap();
        runtime.renew_if_due(due).unwrap();
        assert!(Arc::ptr_eq(&old_tls, &runtime.server_config()));
        let runtime =
            AuthorityRuntime::new(Authority::load_or_create(&path).unwrap(), path.clone()).unwrap();
        assert_eq!(
            runtime.inner.lock().unwrap().retry.next_retry_at,
            Some(due + 30)
        );
        std::fs::remove_dir(path.with_extension("tmp")).unwrap();
        runtime.renew_if_due(due + 29).unwrap();
        assert_eq!(
            runtime
                .inner
                .lock()
                .unwrap()
                .authority
                .server_expires_at()
                .unwrap(),
            due + RENEW_BEFORE
        );
        runtime.renew_if_due(due + 30).unwrap();
        assert_eq!(runtime.ca_pem(), ca);
        assert!(
            runtime
                .inner
                .lock()
                .unwrap()
                .authority
                .server_expires_at()
                .unwrap()
                > due + RENEW_BEFORE
        );
        assert!(runtime.inner.lock().unwrap().retry.error.is_none());
        assert!(
            Authority::load_or_create(&path)
                .unwrap()
                .server_expires_at()
                .unwrap()
                > due + RENEW_BEFORE
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
