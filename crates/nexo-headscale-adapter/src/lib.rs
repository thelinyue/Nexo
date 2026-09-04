//! Headscale 0.29.3 的稳定 HTTP 适配边界。
//!
//! Nexo 业务层只依赖这里定义的节点、路由和一次性密钥语义，绝不读取或改写
//! Headscale 内部数据库。所有请求都显式携带 Bearer API Key，便于在 Server
//! 中轮换密钥而不泄漏到日志和 Web API。

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use reqwest::{Client, Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

/// Nexo 请求 Headscale 允许某台设备发布的本地网络。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteAdvertisement {
    pub device_id: String,
    pub network_id: String,
    pub prefix: String,
    /// 稳定 Headscale Node ID。None 只能产生 Pending，不能伪造 READY。
    #[serde(default)]
    pub headscale_node_id: Option<String>,
}

/// Headscale 路由申请当前是否已达到可用状态。
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteApplyState {
    Ready,
    Pending,
    Failed,
}

/// 适配器返回给 Nexo 的最小结果，不暴露 Headscale 原始响应。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteApplyReport {
    pub state: RouteApplyState,
    pub message: String,
    #[serde(default)]
    pub node_reports: Vec<NodeRouteReport>,
}

/// 单个 Headscale 节点的路由收敛结果。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRouteReport {
    pub node_id: String,
    pub available_routes: Vec<String>,
    pub approved_routes: Vec<String>,
    pub subnet_routes: Vec<String>,
    pub approved: bool,
    pub serving: bool,
    pub error_message: Option<String>,
}

/// Headscale 节点的 Nexo 所需投影。未知字段由 serde 忽略，兼容小版本响应。
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HeadscaleNode {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub online: bool,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    #[serde(default)]
    pub approved_routes: Vec<String>,
    #[serde(default)]
    pub available_routes: Vec<String>,
    #[serde(default)]
    pub subnet_routes: Vec<String>,
    #[serde(default)]
    pub pre_auth_key: Option<HeadscalePreAuthKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HeadscalePreAuthKey {
    pub id: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub used: bool,
    #[serde(default)]
    pub expiration: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HeadscaleUser {
    pub id: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListNodesResponse {
    #[serde(default)]
    nodes: Vec<HeadscaleNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetNodeResponse {
    node: Option<HeadscaleNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatePreAuthKeyRequest<'a> {
    user: &'a str,
    reusable: bool,
    ephemeral: bool,
    expiration: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    acl_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatePreAuthKeyResponse {
    pre_auth_key: HeadscalePreAuthKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListPreAuthKeysResponse {
    #[serde(default)]
    pre_auth_keys: Vec<HeadscalePreAuthKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListUsersResponse {
    #[serde(default)]
    users: Vec<HeadscaleUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateUserRequest<'a> {
    name: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateUserResponse {
    user: Option<HeadscaleUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApproveRoutesRequest {
    routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApproveRoutesResponse {
    node: Option<HeadscaleNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    #[serde(default)]
    database_connectivity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetPolicyRequest<'a> {
    policy: &'a str,
}

/// Headscale 官方 REST API 客户端。
#[derive(Clone)]
pub struct HeadscaleHttpAdapter {
    client: Client,
    base_url: String,
    /// 轮换期间由 Server 原子替换；所有 Clone 共享同一把读写锁。
    api_key: Arc<RwLock<String>>,
}

impl std::fmt::Debug for HeadscaleHttpAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeadscaleHttpAdapter")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl HeadscaleHttpAdapter {
    /// 创建适配器；API Key 只保存在进程内存中，Debug 输出会脱敏。
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Result<Self> {
        Self::with_client(
            Client::builder().timeout(Duration::from_secs(10)).build()?,
            base_url,
            api_key,
        )
    }

    /// 注入 Client 便于集成测试和自定义超时策略。
    pub fn with_client(
        client: Client,
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if base_url.is_empty() {
            return Err(anyhow!("Headscale 地址不能为空"));
        }
        let api_key = api_key.into();
        if api_key.trim().is_empty() {
            return Err(anyhow!("Headscale API Key 不能为空"));
        }
        Ok(Self {
            client,
            base_url,
            api_key: Arc::new(RwLock::new(api_key)),
        })
    }

    /// 热切换运行中的 API Key；明文不出现在 Debug、日志或 Web 响应中。
    pub fn replace_api_key(&self, api_key: impl Into<String>) -> Result<()> {
        let api_key = api_key.into();
        if api_key.trim().is_empty() {
            return Err(anyhow!("Headscale API Key 不能为空"));
        }
        let mut guard = self
            .api_key
            .write()
            .map_err(|_| anyhow!("Headscale API Key 锁不可用"))?;
        *guard = api_key;
        Ok(())
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let api_key = self
            .api_key
            .read()
            .map(|key| key.clone())
            .unwrap_or_default();
        self.client
            .request(method, format!("{}{}", self.base_url, path))
            .bearer_auth(api_key)
            .header(reqwest::header::ACCEPT, "application/json")
    }

    async fn send_json<T: for<'de> Deserialize<'de>>(
        &self,
        request: RequestBuilder,
        operation: &str,
    ) -> Result<T> {
        let response = request
            .send()
            .await
            .with_context(|| format!("Headscale {operation} 请求失败"))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Headscale {operation} 返回 HTTP {status}: {}",
                truncate_error(&body)
            ));
        }
        response
            .json::<T>()
            .await
            .with_context(|| format!("Headscale {operation} 响应格式无效"))
    }

    async fn send_empty(&self, request: RequestBuilder, operation: &str) -> Result<()> {
        let response = request
            .send()
            .await
            .with_context(|| format!("Headscale {operation} 请求失败"))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Headscale {operation} 返回 HTTP {status}: {}",
                truncate_error(&body)
            ));
        }
        Ok(())
    }

    pub async fn health(&self) -> Result<bool> {
        let response: HealthResponse = self
            .send_json(self.request(Method::GET, "/api/v1/health"), "健康检查")
            .await?;
        Ok(response.database_connectivity)
    }

    pub async fn list_nodes(&self) -> Result<Vec<HeadscaleNode>> {
        let response: ListNodesResponse = self
            .send_json(self.request(Method::GET, "/api/v1/node"), "读取节点")
            .await?;
        Ok(response.nodes)
    }

    pub async fn get_node(&self, node_id: &str) -> Result<Option<HeadscaleNode>> {
        let path = format!("/api/v1/node/{}", urlencoding(node_id));
        let response: GetNodeResponse = self
            .send_json(self.request(Method::GET, &path), "读取节点详情")
            .await?;
        Ok(response.node)
    }

    /// Headscale 的批准接口替换完整列表，因此调用方必须先读取节点再合并。
    pub async fn approve_routes(&self, node_id: &str, routes: &[String]) -> Result<HeadscaleNode> {
        let path = format!("/api/v1/node/{}/approve_routes", urlencoding(node_id));
        let response: ApproveRoutesResponse = self
            .send_json(
                self.request(Method::POST, &path)
                    .json(&ApproveRoutesRequest {
                        routes: routes.to_vec(),
                    }),
                "批准节点路由",
            )
            .await?;
        response
            .node
            .ok_or_else(|| anyhow!("Headscale 批准路由响应缺少节点"))
    }

    pub async fn create_pre_auth_key(
        &self,
        user_id: &str,
        expiration: &str,
    ) -> Result<HeadscalePreAuthKey> {
        let response: CreatePreAuthKeyResponse = self
            .send_json(
                self.request(Method::POST, "/api/v1/preauthkey")
                    .json(&CreatePreAuthKeyRequest {
                        user: user_id,
                        reusable: false,
                        ephemeral: false,
                        expiration,
                        acl_tags: Vec::new(),
                    }),
                "创建设备入网密钥",
            )
            .await?;
        Ok(response.pre_auth_key)
    }

    pub async fn list_pre_auth_keys(&self) -> Result<Vec<HeadscalePreAuthKey>> {
        let response: ListPreAuthKeysResponse = self
            .send_json(
                self.request(Method::GET, "/api/v1/preauthkey"),
                "读取设备入网密钥",
            )
            .await?;
        Ok(response.pre_auth_keys)
    }

    pub async fn ensure_user(&self, name: &str) -> Result<HeadscaleUser> {
        let users: ListUsersResponse = self
            .send_json(self.request(Method::GET, "/api/v1/user"), "读取组网用户")
            .await?;
        if let Some(user) = users.users.into_iter().find(|user| user.name == name) {
            return Ok(user);
        }
        let response: CreateUserResponse = self
            .send_json(
                self.request(Method::POST, "/api/v1/user")
                    .json(&CreateUserRequest { name }),
                "创建组网用户",
            )
            .await?;
        response
            .user
            .ok_or_else(|| anyhow!("Headscale 创建用户响应缺少用户"))
    }

    pub async fn expire_pre_auth_key(&self, key_id: &str) -> Result<()> {
        self.send_empty(
            self.request(Method::POST, "/api/v1/preauthkey/expire")
                .json(&serde_json::json!({ "id": key_id })),
            "吊销设备入网密钥",
        )
        .await
    }

    pub async fn delete_pre_auth_key(&self, key_id: &str) -> Result<()> {
        let query = [("id", key_id)];
        self.send_empty(
            self.request(Method::DELETE, "/api/v1/preauthkey")
                .query(&query),
            "删除设备入网密钥",
        )
        .await
    }

    /// 将旧 Node 的过期时间设置为当前时间，作为显式身份恢复的一部分。
    ///
    /// 这里使用 Headscale 官方的 expire 接口而不是删除节点：保留节点记录有利于
    /// 审计和故障排查，同时阻止旧设备继续作为有效的组网身份参与路由。
    pub async fn expire_node(&self, node_id: &str, expiry: &str) -> Result<()> {
        let path = format!("/api/v1/node/{}/expire", urlencoding(node_id));
        self.send_empty(
            self.request(Method::POST, &path)
                .query(&[("expiry", expiry)]),
            "停用旧组网节点",
        )
        .await
    }

    pub async fn set_policy(&self, policy: &str) -> Result<()> {
        self.send_empty(
            self.request(Method::PUT, "/api/v1/policy")
                .json(&SetPolicyRequest { policy }),
            "更新组网策略",
        )
        .await
    }

    /// 将 Headscale 当前完整批准列表与 Nexo 期望列表合并。
    /// 非 Nexo 前缀永远保留；只有明确列在 `nexo_owned_prefixes` 中的前缀才会被撤销。
    pub fn merge_approved_routes(
        current: &[String],
        desired: &[String],
        nexo_owned_prefixes: &[String],
    ) -> Vec<String> {
        let owned: BTreeSet<&str> = nexo_owned_prefixes.iter().map(String::as_str).collect();
        let desired: BTreeSet<&str> = desired.iter().map(String::as_str).collect();
        let mut merged: BTreeSet<String> = current
            .iter()
            .filter(|prefix| !owned.contains(prefix.as_str()))
            .cloned()
            .collect();
        merged.extend(desired.into_iter().map(str::to_owned));
        merged.into_iter().collect()
    }

    /// 对一组 Nexo Desired Routes 执行逐节点读取、合并和批准。
    pub async fn reconcile_node_routes(
        &self,
        node_id: &str,
        desired_prefixes: &[String],
        nexo_owned_prefixes: &[String],
    ) -> Result<NodeRouteReport> {
        let node = self
            .get_node(node_id)
            .await?
            .ok_or_else(|| anyhow!("Headscale 节点 {node_id} 不存在"))?;
        let desired: BTreeSet<&str> = desired_prefixes.iter().map(String::as_str).collect();
        // Headscale 的批准接口会替换完整列表；在节点尚未发布某个 Desired
        // 前缀时先返回 Pending，避免把尚未发现的路由误当成已批准，或让控制
        // 平面因为未知前缀直接返回错误。已经批准/提供服务的前缀可继续收敛。
        let unavailable = desired.iter().find(|prefix| {
            !node.available_routes.iter().any(|value| value == **prefix)
                && !node.approved_routes.iter().any(|value| value == **prefix)
                && !node.subnet_routes.iter().any(|value| value == **prefix)
        });
        if let Some(prefix) = unavailable {
            return Ok(NodeRouteReport {
                node_id: node_id.to_owned(),
                available_routes: node.available_routes,
                approved_routes: node.approved_routes,
                subnet_routes: node.subnet_routes,
                approved: false,
                serving: false,
                error_message: Some(format!("Headscale 尚未发现路由 {prefix}")),
            });
        }
        let merged = Self::merge_approved_routes(
            &node.approved_routes,
            desired_prefixes,
            nexo_owned_prefixes,
        );
        let approved_node = self.approve_routes(node_id, &merged).await?;
        let serving = desired.iter().all(|prefix| {
            approved_node
                .subnet_routes
                .iter()
                .any(|candidate| candidate == prefix)
        });
        Ok(NodeRouteReport {
            node_id: node_id.to_owned(),
            available_routes: approved_node.available_routes.clone(),
            approved_routes: approved_node.approved_routes.clone(),
            subnet_routes: approved_node.subnet_routes.clone(),
            approved: desired
                .iter()
                .all(|prefix| approved_node.approved_routes.iter().any(|v| v == prefix)),
            serving,
            error_message: None,
        })
    }
}

/// Headscale 控制平面的稳定异步边界，Server 可用 Mock 实现替换真实 HTTP。
#[async_trait]
pub trait HeadscaleControlPlane: Send + Sync {
    async fn health(&self) -> Result<bool> {
        Err(anyhow!("Headscale 健康 API 尚未配置"))
    }

    async fn reconcile_routes(&self, routes: &[RouteAdvertisement]) -> Result<RouteApplyReport>;

    /// 以单个稳定 Node 为边界执行路由收敛。`nexo_owned_prefixes` 包含历史上
    /// 由 Nexo 发布的全部前缀，即使当前 Desired 为空也能定向撤销而不影响其他系统。
    async fn reconcile_node_routes(
        &self,
        _node_id: &str,
        _desired_prefixes: &[String],
        _nexo_owned_prefixes: &[String],
    ) -> Result<NodeRouteReport> {
        Err(anyhow!("Headscale 节点路由 API 尚未配置"))
    }

    async fn list_nodes(&self) -> Result<Vec<HeadscaleNode>> {
        Err(anyhow!("Headscale 节点 API 尚未配置"))
    }

    async fn find_node_by_pre_auth_key(&self, _key_id: &str) -> Result<Option<HeadscaleNode>> {
        Err(anyhow!("Headscale 节点 API 尚未配置"))
    }

    /// 为设备创建单次 Pre-auth Key；不支持的实现必须返回错误，Server 会保持 Pending。
    async fn ensure_user(&self, _name: &str) -> Result<HeadscaleUser> {
        Err(anyhow!("Headscale 用户 API 尚未配置"))
    }

    async fn create_pre_auth_key(
        &self,
        _user_id: &str,
        _expiration: &str,
    ) -> Result<HeadscalePreAuthKey> {
        Err(anyhow!("Headscale Pre-auth Key API 尚未配置"))
    }

    async fn list_pre_auth_keys(&self) -> Result<Vec<HeadscalePreAuthKey>> {
        Err(anyhow!("Headscale Pre-auth Key API 尚未配置"))
    }

    async fn expire_pre_auth_key(&self, _key_id: &str) -> Result<()> {
        Err(anyhow!("Headscale Pre-auth Key API 尚未配置"))
    }

    async fn expire_node(&self, _node_id: &str, _expiry: &str) -> Result<()> {
        Err(anyhow!("Headscale 节点停用 API 尚未配置"))
    }

    async fn set_policy(&self, _policy: &str) -> Result<()> {
        Err(anyhow!("Headscale Policy API 尚未配置"))
    }
}

#[async_trait]
impl HeadscaleControlPlane for HeadscaleHttpAdapter {
    async fn health(&self) -> Result<bool> {
        HeadscaleHttpAdapter::health(self).await
    }

    async fn reconcile_routes(&self, routes: &[RouteAdvertisement]) -> Result<RouteApplyReport> {
        if routes.is_empty() {
            return Ok(RouteApplyReport {
                state: RouteApplyState::Ready,
                message: "没有需要申请的共享网络".to_owned(),
                node_reports: Vec::new(),
            });
        }
        let mut grouped: BTreeMap<String, Vec<&RouteAdvertisement>> = BTreeMap::new();
        for route in routes {
            let Some(node_id) = route.headscale_node_id.as_deref() else {
                return Ok(RouteApplyReport {
                    state: RouteApplyState::Pending,
                    message: format!("设备 {} 尚未绑定组网身份", route.device_id),
                    node_reports: Vec::new(),
                });
            };
            grouped.entry(node_id.to_owned()).or_default().push(route);
        }
        let mut reports = Vec::new();
        for (node_id, node_routes) in grouped {
            let desired: Vec<String> = node_routes.iter().map(|r| r.prefix.clone()).collect();
            let owned = desired.clone();
            reports.push(
                HeadscaleHttpAdapter::reconcile_node_routes(self, &node_id, &desired, &owned)
                    .await
                    .with_context(|| format!("节点 {node_id} 路由收敛失败"))?,
            );
        }
        let ready = reports
            .iter()
            .all(|report| report.approved && report.serving);
        Ok(RouteApplyReport {
            state: if ready {
                RouteApplyState::Ready
            } else {
                RouteApplyState::Pending
            },
            message: if ready {
                "Headscale 路由已批准并提供服务".to_owned()
            } else {
                "Headscale 已收到路由，等待节点提供服务".to_owned()
            },
            node_reports: reports,
        })
    }

    async fn reconcile_node_routes(
        &self,
        node_id: &str,
        desired_prefixes: &[String],
        nexo_owned_prefixes: &[String],
    ) -> Result<NodeRouteReport> {
        HeadscaleHttpAdapter::reconcile_node_routes(
            self,
            node_id,
            desired_prefixes,
            nexo_owned_prefixes,
        )
        .await
    }

    async fn ensure_user(&self, name: &str) -> Result<HeadscaleUser> {
        HeadscaleHttpAdapter::ensure_user(self, name).await
    }

    async fn list_nodes(&self) -> Result<Vec<HeadscaleNode>> {
        HeadscaleHttpAdapter::list_nodes(self).await
    }

    async fn find_node_by_pre_auth_key(&self, key_id: &str) -> Result<Option<HeadscaleNode>> {
        Ok(self.list_nodes().await?.into_iter().find(|node| {
            node.pre_auth_key
                .as_ref()
                .is_some_and(|key| key.id == key_id)
        }))
    }

    async fn create_pre_auth_key(
        &self,
        user_id: &str,
        expiration: &str,
    ) -> Result<HeadscalePreAuthKey> {
        HeadscaleHttpAdapter::create_pre_auth_key(self, user_id, expiration).await
    }

    async fn list_pre_auth_keys(&self) -> Result<Vec<HeadscalePreAuthKey>> {
        HeadscaleHttpAdapter::list_pre_auth_keys(self).await
    }

    async fn expire_pre_auth_key(&self, key_id: &str) -> Result<()> {
        HeadscaleHttpAdapter::expire_pre_auth_key(self, key_id).await
    }

    async fn expire_node(&self, node_id: &str, expiry: &str) -> Result<()> {
        HeadscaleHttpAdapter::expire_node(self, node_id, expiry).await
    }

    async fn set_policy(&self, policy: &str) -> Result<()> {
        HeadscaleHttpAdapter::set_policy(self, policy).await
    }
}

/// 未配置 Headscale 时使用的明确 Pending 实现；绝不宣称路由已生效。
#[derive(Debug, Default)]
pub struct HeadscaleAdapter;

#[async_trait]
impl HeadscaleControlPlane for HeadscaleAdapter {
    async fn reconcile_routes(&self, routes: &[RouteAdvertisement]) -> Result<RouteApplyReport> {
        Ok(RouteApplyReport {
            state: if routes.is_empty() {
                RouteApplyState::Ready
            } else {
                RouteApplyState::Pending
            },
            message: if routes.is_empty() {
                "没有需要申请的共享网络".to_owned()
            } else {
                "Headscale API 尚未配置，路由申请等待适配器接入".to_owned()
            },
            node_reports: Vec::new(),
        })
    }
}

fn truncate_error(body: &str) -> String {
    const MAX: usize = 512;
    let body = body.trim();
    if body.len() <= MAX {
        body.to_owned()
    } else {
        format!("{}…", &body[..MAX])
    }
}

/// 节点 ID 来自 Headscale API 的数字字符串；仅允许 URL 安全字符，拒绝路径注入。
fn urlencoding(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn merge_keeps_non_nexo_routes_and_replaces_owned_routes() {
        let merged = HeadscaleHttpAdapter::merge_approved_routes(
            &["10.0.0.0/24".to_owned(), "192.168.10.0/24".to_owned()],
            &["192.168.20.0/24".to_owned()],
            &["192.168.10.0/24".to_owned()],
        );
        assert_eq!(merged, vec!["10.0.0.0/24", "192.168.20.0/24"]);
    }

    #[test]
    fn adapter_requires_non_empty_bearer_key() {
        assert!(HeadscaleHttpAdapter::new("http://headscale", "").is_err());
        let adapter = HeadscaleHttpAdapter::new("http://headscale/", "secret").unwrap();
        assert_eq!(adapter.base_url, "http://headscale");
    }

    #[tokio::test]
    async fn unconfigured_adapter_never_claims_route_ready() {
        let report = HeadscaleAdapter
            .reconcile_routes(&[RouteAdvertisement {
                device_id: "device-a".to_owned(),
                network_id: "network-a".to_owned(),
                prefix: "192.168.10.0/24".to_owned(),
                headscale_node_id: None,
            }])
            .await
            .expect("占位适配器应返回可展示的 Pending 结果");
        assert_eq!(report.state, RouteApplyState::Pending);
    }

    #[tokio::test]
    async fn http_adapter_sends_bearer_auth_to_health_api() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("测试 HTTP 监听器应能启动");
        let address = listener.local_addr().expect("测试监听器应有地址");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("应接受测试请求");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await.expect("应能读取测试请求");
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).expect("请求应是 HTTP 文本");
            assert!(request
                .to_ascii_lowercase()
                .contains("authorization: bearer test-secret"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 29\r\n\r\n{\"databaseConnectivity\":true}",
                )
                .await
                .expect("应返回健康响应");
        });
        let adapter = HeadscaleHttpAdapter::new(format!("http://{address}"), "test-secret")
            .expect("测试适配器应能创建");
        assert!(adapter.health().await.expect("健康请求应成功"));
        server.await.expect("测试 HTTP 服务应完成");
    }
}
