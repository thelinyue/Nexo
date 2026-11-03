//! 回源 TLS 配置按服务独立生效，不影响 Agent 与 Server 的身份认证。

use anyhow::{Context, Result};
use nexo_protocol::TunnelDesiredState;
use nexo_tunnel::identity;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;

pub fn client_config(tunnel: &TunnelDesiredState) -> Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder();
    match tunnel
        .origin_tls_verification
        .as_deref()
        .unwrap_or("system")
    {
        "insecure_skip_verify" => Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipOriginVerification(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))))
            .with_no_client_auth()),
        mode => {
            let roots = match mode {
                "custom_ca" => identity::roots(
                    tunnel
                        .origin_ca_pem
                        .as_deref()
                        .context("本地 HTTPS 缺少自定义 CA")?,
                )?,
                "system" => {
                    let mut roots = rustls::RootCertStore::empty();
                    let native = rustls_native_certs::load_native_certs();
                    for cert in native.certs {
                        roots.add(cert)?;
                    }
                    anyhow::ensure!(
                        !roots.is_empty(),
                        "无法加载系统 CA，不能验证本地 HTTPS 证书"
                    );
                    roots
                }
                _ => anyhow::bail!("本地 HTTPS 证书校验方式不受支持"),
            };
            Ok(builder.with_root_certificates(roots).with_no_client_auth())
        }
    }
}

/// 仅用于用户明确选择跳过验证的 HTTPS 回源；不验证来源和名称，但仍验证 TLS 握手签名。
#[derive(Debug)]
struct SkipOriginVerification(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipOriginVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
