//! Headscale 稳定 API 的适配边界。
//!
//! 业务层只依赖这里的 Nexo 语义模型，不直接读取 Headscale 数据库。

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Nexo 请求 Headscale 允许某台设备发布的本地网络。
///
/// `device_id` 和 `network_id` 都是 Nexo 自有标识；适配器内部再将其
/// 映射到 Headscale 的节点和路由对象，避免上层绑定 Headscale 数据结构。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteAdvertisement {
    pub device_id: String,
    pub network_id: String,
    pub prefix: String,
}

/// Headscale 路由申请当前是否已达到可用状态。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteApplyState {
    Ready,
    Pending,
}

/// 适配器返回给 Nexo 的最小结果，不暴露 Headscale 原始响应。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteApplyReport {
    pub state: RouteApplyState,
    pub message: String,
}

/// Headscale 控制平面适配器的稳定边界。
///
/// 后续实现可以通过 Headscale 官方 API 或稳定命令行接口完成申请；
/// 禁止通过读取或改写 Headscale 内部 SQLite 数据库实现该接口。
pub trait HeadscaleControlPlane: Send + Sync {
    fn reconcile_routes(&self, routes: &[RouteAdvertisement]) -> Result<RouteApplyReport>;
}

/// 当前尚未配置 Headscale API 的适配器实现。
///
/// 它故意返回 `pending` 而不是 `ready`，让上层 UI 保持“正在应用”的诚实
/// 状态；真正的 HTTP/API 实现接入后可替换该类型，而不改变控制协议。
#[derive(Debug, Default)]
pub struct HeadscaleAdapter;

impl HeadscaleControlPlane for HeadscaleAdapter {
    fn reconcile_routes(&self, routes: &[RouteAdvertisement]) -> Result<RouteApplyReport> {
        let message = if routes.is_empty() {
            "没有需要申请的共享网络".to_owned()
        } else {
            "Headscale API 尚未配置，路由申请等待适配器接入".to_owned()
        };
        Ok(RouteApplyReport {
            state: if routes.is_empty() {
                RouteApplyState::Ready
            } else {
                RouteApplyState::Pending
            },
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unconfigured_adapter_never_claims_route_ready() {
        let adapter = HeadscaleAdapter;
        let report = adapter
            .reconcile_routes(&[RouteAdvertisement {
                device_id: "device-a".to_owned(),
                network_id: "network-a".to_owned(),
                prefix: "192.168.10.0/24".to_owned(),
            }])
            .expect("占位适配器应返回可展示的 Pending 结果");
        assert_eq!(report.state, RouteApplyState::Pending);
    }
}
