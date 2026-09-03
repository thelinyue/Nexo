//! 设备入网凭证与审批状态。
//!
//! 这里仅负责可复用的领域规则。凭证明文只在创建时返回给调用方，数据库
//! 以及日志中只保存摘要，避免服务端持久化可直接入网的秘密。

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// 设备入网请求在服务端的生命周期。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentStatus {
    Pending,
    AwaitingApproval,
    Approved,
    Consumed,
    Expired,
    Revoked,
}

/// 等待设备使用的一次性入网凭证。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentToken {
    /// 只应在创建响应中展示一次的明文凭证。
    pub secret: String,
    /// 可以安全写入数据库的摘要。
    pub digest: String,
    /// Unix 秒时间戳。
    pub expires_at: i64,
}

/// 入网凭证校验失败的原因。
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EnrollmentError {
    #[error("入网凭证有效期必须大于 0 秒")]
    InvalidTtl,
    #[error("入网凭证已过期")]
    Expired,
    #[error("入网凭证不匹配")]
    InvalidToken,
}

impl EnrollmentToken {
    /// 生成一个 256 位随机的一次性凭证。
    pub fn generate(now: i64, ttl_seconds: i64) -> Result<Self, EnrollmentError> {
        if ttl_seconds <= 0 {
            return Err(EnrollmentError::InvalidTtl);
        }

        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let secret = URL_SAFE_NO_PAD.encode(bytes);
        Ok(Self {
            digest: Self::digest(&secret),
            secret,
            expires_at: now.saturating_add(ttl_seconds),
        })
    }

    /// 根据明文凭证计算持久化摘要。
    pub fn digest(secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// 校验凭证摘要与有效期。
    pub fn verify(
        secret: &str,
        expected_digest: &str,
        expires_at: i64,
        now: i64,
    ) -> Result<(), EnrollmentError> {
        if now >= expires_at {
            return Err(EnrollmentError::Expired);
        }
        if Self::digest(secret) != expected_digest {
            return Err(EnrollmentError::InvalidToken);
        }
        Ok(())
    }
}

/// 数据库中的待入网请求视图，不包含凭证明文。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEnrollment {
    pub id: String,
    pub tenant_id: String,
    pub site_id: Option<String>,
    pub status: EnrollmentStatus,
    pub expires_at: i64,
    pub device_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_can_be_verified_without_persisting_secret() {
        let token = EnrollmentToken::generate(100, 900).expect("应生成凭证");
        assert!(!token.secret.is_empty());
        assert_ne!(token.secret, token.digest);
        assert!(
            EnrollmentToken::verify(&token.secret, &token.digest, token.expires_at, 100).is_ok()
        );
    }

    #[test]
    fn token_expires_and_rejects_other_secret() {
        let token = EnrollmentToken::generate(100, 1).expect("应生成凭证");
        assert_eq!(
            EnrollmentToken::verify(&token.secret, &token.digest, token.expires_at, 101),
            Err(EnrollmentError::Expired)
        );
        assert_eq!(
            EnrollmentToken::verify("other", &token.digest, token.expires_at, 100),
            Err(EnrollmentError::InvalidToken)
        );
    }
}
