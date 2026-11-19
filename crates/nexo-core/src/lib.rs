//! Nexo 的共享领域类型。

use std::time::{SystemTime, UNIX_EPOCH};

pub mod config;
pub mod enrollment;
pub mod telemetry;

pub use enrollment::{EnrollmentError, EnrollmentStatus, EnrollmentToken, PendingEnrollment};

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}
