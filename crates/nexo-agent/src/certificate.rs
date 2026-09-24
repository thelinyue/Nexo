//! 续签沿用设备 ID，但生成新的本地私钥；待签 CSR 与旧身份一起保存，失败或重启可重试。
use super::{DeviceIdentity, EnrollmentKey};
use anyhow::Result;
use nexo_protocol::AgentControlMessage;
use nexo_tunnel::identity::{self, RenewalRetry, RENEW_BEFORE};
use rcgen::{CertificateParams, KeyPair};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_rustls::TlsConnector;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn request(
    identity: &mut DeviceIdentity,
    path: &Path,
    now: i64,
) -> Result<Option<AgentControlMessage>> {
    let expiry = identity::certificate_info(&identity.certificate_pem)?.1;
    if expiry > now + RENEW_BEFORE || !identity.renewal_retry.ready(now) {
        return Ok(None);
    }
    anyhow::ensure!(expiry > now, "设备证书已过期，请联系管理员恢复设备身份");
    if identity.pending_key.is_none() {
        let key = KeyPair::generate()?;
        identity.pending_key = Some(EnrollmentKey {
            csr_pem: CertificateParams::new(vec!["agent.nexo".into()])?
                .serialize_request(&key)?
                .pem()?,
            key_pem: key.serialize_pem(),
        });
    }
    identity.renewal_retry.next_retry_at = Some(now + 30);
    identity::write_private_file(path, &serde_json::to_vec(identity)?)?;
    Ok(Some(AgentControlMessage::RenewCertificate {
        csr_pem: identity.pending_key.as_ref().unwrap().csr_pem.clone(),
    }))
}

/// 写盘成功后才发布新 TLS 配置；失败保留旧证书及待签私钥，不能提前确认服务端撤销旧证书。
pub fn install(
    identity: &mut DeviceIdentity,
    path: &Path,
    certificate: &str,
) -> Result<TlsConnector> {
    let key = identity
        .pending_key
        .as_ref()
        .map(|key| key.key_pem.as_str())
        .unwrap_or(&identity.key_pem);
    let (device, expiry) = identity::certificate_info(certificate)?;
    anyhow::ensure!(
        device == identity.device_id && expiry > now() + RENEW_BEFORE,
        "续签证书的设备或有效期不符合要求"
    );
    let connector =
        TlsConnector::from(identity::client_config(&identity.ca_pem, certificate, key)?);
    let mut next = identity.clone();
    next.key_pem = key.into();
    next.certificate_pem = certificate.into();
    next.pending_key = None;
    next.renewal_retry = RenewalRetry::default();
    identity::write_private_file(path, &serde_json::to_vec(&next)?)?;
    *identity = next;
    Ok(connector)
}
pub fn failed(
    identity: &mut DeviceIdentity,
    path: &Path,
    error: &str,
    retry_at: Option<i64>,
) -> AgentControlMessage {
    let now = now();
    identity.renewal_retry.failed(now, error);
    if let Some(next) = retry_at {
        identity.renewal_retry.next_retry_at = Some(next.max(now + 30));
    }
    if let Err(error) = serde_json::to_vec(identity)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| identity::write_private_file(path, &bytes))
    {
        tracing::warn!("无法保存设备证书重试状态：{error:#}");
    }
    tracing::warn!("设备证书续签失败，将自动重试：{error}");
    AgentControlMessage::CertificateRenewalFailed {
        error: identity.renewal_retry.error.clone().unwrap_or_default(),
        next_retry_at: identity.renewal_retry.next_retry_at.unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_key_survives_restart_and_failed_install_preserves_old_identity() {
        let directory = std::env::temp_dir().join(format!(
            "nexo-agent-renewal-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = directory.join("identity.json");
        let authority = identity::Authority::generate().unwrap();
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(vec!["agent.nexo".into()])
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let old_cert = authority.issue_device(&csr, "same-id").unwrap();
        let mut agent = DeviceIdentity {
            device_id: "same-id".into(),
            server_url: "https://server.example".into(),
            certificate_pem: old_cert.clone(),
            ca_pem: authority.ca_pem.clone(),
            key_pem: key.serialize_pem(),
            pending_key: None,
            renewal_retry: Default::default(),
        };
        let due = identity::certificate_info(&old_cert).unwrap().1 - RENEW_BEFORE;
        assert!(request(&mut agent, &path, due - 1).unwrap().is_none());
        let AgentControlMessage::RenewCertificate { csr_pem } =
            request(&mut agent, &path, due).unwrap().unwrap()
        else {
            panic!("缺少续签请求");
        };
        let mut restored: DeviceIdentity =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(request(&mut restored, &path, due + 1).unwrap().is_none());
        let AgentControlMessage::RenewCertificate { csr_pem: retry_csr } =
            request(&mut restored, &path, due + 30).unwrap().unwrap()
        else {
            panic!("缺少重试请求");
        };
        assert_eq!(csr_pem, retry_csr);
        let new_cert = authority.issue_device(&csr_pem, "same-id").unwrap();
        let wrong_device = authority.issue_device(&csr_pem, "foreign-id").unwrap();
        assert!(install(&mut restored, &path, &wrong_device).is_err());
        let before = std::fs::read(&path).unwrap();
        std::fs::create_dir(path.with_extension("tmp")).unwrap();
        assert!(install(&mut restored, &path, &new_cert).is_err());
        assert_eq!(restored.certificate_pem, old_cert);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_dir(path.with_extension("tmp")).unwrap();
        install(&mut restored, &path, &new_cert).unwrap();
        assert_eq!(restored.device_id, "same-id");
        assert_eq!(restored.server_url, agent.server_url);
        assert_ne!(restored.key_pem, agent.key_pem);
        assert!(restored.pending_key.is_none());
        let installed: DeviceIdentity =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(installed.certificate_pem, new_cert);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
