//! Nexo 的共享领域类型。

pub mod config;
pub mod enrollment;

pub use enrollment::{EnrollmentError, EnrollmentStatus, EnrollmentToken, PendingEnrollment};
