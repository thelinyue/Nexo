//! 复用 Caddy 管理的域名证书；只向绑定服务的已认证设备下发，不另建 ACME 订单。
use super::*;
use nexo_tunnel::identity;
use std::{fs, path::Path};

pub(super) fn request(
    state: &AppState,
    device: &str,
    id: &str,
    revision: i64,
) -> Result<DirectResponse> {
    // 主机名及域名归属从数据库解析，禁止 Agent 指定域名或存储路径。
    let service = super::service(state, device, id, revision)?;
    let domain: String = state.db.lock().map_err(|_| anyhow::anyhow!("数据库锁不可用"))?
        .query_row("SELECT p.domain FROM tunnels t JOIN public_domains p ON p.id=t.public_domain_id AND p.tenant_id=t.tenant_id WHERE t.id=?1", [id], |r| r.get(0))?;
    let (chain, key_pem, expires) = load(
        &state.domain_runtime.supervisor.config().storage_root,
        &domain,
        &service.hostname,
    )?;
    // 文件读取期间配置可能改变；返回私钥之前再次确认设备、租户与版本。
    super::service(state, device, id, revision)?;
    state.db.lock().map_err(|_| anyhow::anyhow!("数据库锁不可用"))?.execute(
        "INSERT INTO direct_certificates(service_id,device_id,hostname,csr,chain,expires_at) VALUES(?1,?2,?3,'',?4,?5) ON CONFLICT(service_id) DO UPDATE SET device_id=excluded.device_id,hostname=excluded.hostname,csr='',chain=excluded.chain,expires_at=excluded.expires_at,renew_at=NULL,order_url=NULL,next_retry_at=0,error=NULL",
        params![id,device,service.hostname,chain,expires])?;
    Ok(DirectResponse::DomainCertificate { chain, key_pem })
}

/// Caddy FileStorage 按签发机构/证书名保存。只读当前域名的泛域名文件，拒绝符号链接、
/// 测试 CA、跨域 SAN 和不匹配的密钥；续期写入中途不完整的文件留待下一轮协调。
fn load(root: &Path, domain: &str, hostname: &str) -> Result<(String, String, i64)> {
    let (_, suffix) = hostname.split_once('.').context("服务主机名无效")?;
    anyhow::ensure!(
        suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && (suffix == domain || suffix.ends_with(&format!(".{domain}"))),
        "证书域名无效"
    );
    // 与 Server Caddy 的逐层泛域名策略一致，多级主机名使用其直接父域证书。
    let wildcard = format!("*.{suffix}");
    let name = format!("wildcard_.{suffix}");
    let storage = root.join("certificates");
    let mut found = None;
    if fs::symlink_metadata(&storage).is_ok_and(|m| m.is_dir() && !m.is_symlink()) {
        for issuer in fs::read_dir(&storage)?.flatten() {
            let issuer_name = issuer.file_name().to_string_lossy().into_owned();
            if !issuer.file_type().is_ok_and(|kind| kind.is_dir())
                || issuer_name == "local"
                || issuer_name.contains("staging")
            {
                continue;
            }
            let directory = issuer.path().join(&name);
            if !fs::symlink_metadata(&directory).is_ok_and(|m| m.is_dir() && !m.is_symlink()) {
                continue;
            }
            let certificate = directory.join(format!("{name}.crt"));
            let key = directory.join(format!("{name}.key"));
            if [&certificate, &key]
                .iter()
                .any(|p| !fs::symlink_metadata(p).is_ok_and(|m| m.is_file() && !m.is_symlink()))
            {
                continue;
            }
            let candidate = (|| -> Result<_> {
                let chain = fs::read_to_string(&certificate)?;
                let (_, pem) = x509_parser::pem::parse_x509_pem(chain.as_bytes())?;
                let cert = pem.parse_x509()?;
                let san = cert.subject_alternative_name()?.context("证书缺少 SAN")?;
                // 分发泛域名私钥意味着授予该域的 TLS 身份，不能连带授予其他域。
                anyhow::ensure!(san.value.general_names.iter().any(|n| matches!(n, x509_parser::extensions::GeneralName::DNSName(v) if *v == wildcard)), "证书不包含当前泛域名");
                anyhow::ensure!(san.value.general_names.iter().all(|n| matches!(n, x509_parser::extensions::GeneralName::DNSName(v) if *v == wildcard || *v == suffix)), "证书包含其他域名，不能下发");
                let key_pem = fs::read_to_string(&key)?;
                let expires =
                    identity::validate_https_certificate(&chain, &key_pem, hostname, unix_now())?;
                Ok((chain, key_pem, expires))
            })();
            if let Ok(candidate) = candidate {
                if found
                    .as_ref()
                    .is_none_or(|(_, _, expires)| candidate.2 > *expires)
                {
                    found = Some(candidate);
                }
            }
        }
    }
    found.context("域名泛域名证书尚未就绪或证书与私钥无效，请查看「域名」中的证书状态")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn save(
        state: &AppState,
        names: Vec<String>,
        not_before: i64,
        expires: i64,
    ) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(names).unwrap();
        params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before).unwrap();
        params.not_after = time::OffsetDateTime::from_unix_timestamp(expires).unwrap();
        let chain = params.self_signed(&key).unwrap().pem();
        let path = state
            .domain_runtime
            .supervisor
            .config()
            .storage_root
            .join("certificates/acme-v02.api.letsencrypt.org-directory/wildcard_.direct.test");
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("wildcard_.direct.test.crt"), &chain).unwrap();
        fs::write(path.join("wildcard_.direct.test.key"), key.serialize_pem()).unwrap();
        (chain, key.serialize_pem())
    }

    #[tokio::test]
    async fn rename_reuses_domain_certificate_and_renewal_is_picked_up_without_acme() {
        let (state, _) = super::super::tests::fixture();
        let now = unix_now();
        let first = save(&state, vec!["*.direct.test".into()], now - 60, now + 86400);
        let get = |revision| {
            let DirectResponse::DomainCertificate { chain, key_pem } =
                request(&state, "agent", "media", revision).unwrap()
            else {
                panic!()
            };
            (chain, key_pem)
        };
        assert_eq!(get(1), first);
        state.db.lock().unwrap().execute("UPDATE tunnels SET hostname='emby1',https_port=9444,apply_revision=2 WHERE id='media'", []).unwrap();
        assert_eq!(get(2), first);
        let renewed = save(&state, vec!["*.direct.test".into()], now - 10, now + 172800);
        assert_eq!(get(2), renewed);
        let (host, expiry, order, csr): (String, i64, Option<String>, String) = state.db.lock().unwrap().query_row(
            "SELECT hostname,expires_at,order_url,csr FROM direct_certificates WHERE service_id='media'", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(host, "emby1.direct.test");
        assert_eq!(expiry, now + 172800);
        assert!(order.is_none() && csr.is_empty());
        assert!(state.tunnel_runtime.direct.jobs.lock().await.is_empty());
        assert!(state.tunnel_runtime.direct.account.lock().await.is_none());
    }

    #[test]
    fn certificate_key_is_not_returned_to_other_devices_stale_revisions_or_tenants() {
        let (state, domain) = super::super::tests::fixture();
        save(
            &state,
            vec!["*.direct.test".into()],
            unix_now() - 60,
            unix_now() + 86400,
        );
        assert!(request(&state, "other", "media", 1).is_err());
        assert!(request(&state, "agent", "media", 2).is_err());
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO tenants(id,name,created_at) VALUES('other','其他空间',0)",
                [],
            )
            .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE public_domains SET tenant_id='other' WHERE id=?1",
                [&domain],
            )
            .unwrap();
        assert!(request(&state, "agent", "media", 1).is_err());
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE public_domains SET tenant_id='default' WHERE id=?1",
                [&domain],
            )
            .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE tenants SET enabled=0 WHERE id='default'", [])
            .unwrap();
        assert!(request(&state, "agent", "media", 1).is_err());
    }

    #[test]
    fn unavailable_expired_cross_domain_and_mismatched_certificates_are_rejected() {
        let (state, _) = super::super::tests::fixture();
        let now = unix_now();
        assert!(request(&state, "agent", "media", 1).is_err());
        for (names, start, end) in [
            (vec!["*.direct.test"], now - 120, now - 60),
            (vec!["*.direct.test"], now + 60, now + 86400),
            (vec!["*.direct.test", "*.other.test"], now - 60, now + 86400),
            (vec!["emby.direct.test"], now - 60, now + 86400),
        ] {
            save(
                &state,
                names.into_iter().map(str::to_owned).collect(),
                start,
                end,
            );
            assert!(request(&state, "agent", "media", 1).is_err());
        }
        save(&state, vec!["*.direct.test".into()], now - 60, now + 86400);
        let path = state.domain_runtime.supervisor.config().storage_root
            .join("certificates/acme-v02.api.letsencrypt.org-directory/wildcard_.direct.test/wildcard_.direct.test.key");
        fs::write(path, rcgen::KeyPair::generate().unwrap().serialize_pem()).unwrap();
        assert!(request(&state, "agent", "media", 1).is_err());
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM direct_certificates", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn nested_hostname_reuses_its_own_wildcard_without_matching_parent_wildcard() {
        let (state, _) = super::super::tests::fixture();
        let expected = save(
            &state,
            vec!["*.nested.direct.test".into()],
            unix_now() - 60,
            unix_now() + 86400,
        );
        let issuer = state
            .domain_runtime
            .supervisor
            .config()
            .storage_root
            .join("certificates/acme-v02.api.letsencrypt.org-directory");
        let nested = issuer.join("wildcard_.nested.direct.test");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("wildcard_.nested.direct.test.crt"), &expected.0).unwrap();
        fs::write(nested.join("wildcard_.nested.direct.test.key"), &expected.1).unwrap();
        save(
            &state,
            vec!["*.direct.test".into()],
            unix_now() - 60,
            unix_now() + 86400,
        );
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE tunnels SET hostname='emby.nested' WHERE id='media'",
                [],
            )
            .unwrap();
        let DirectResponse::DomainCertificate { chain, key_pem } =
            request(&state, "agent", "media", 1).unwrap()
        else {
            panic!()
        };
        assert_eq!((chain, key_pem), expected);
        assert!(load(&issuer, "other.test", "emby.nested.direct.test").is_err());
    }
}
