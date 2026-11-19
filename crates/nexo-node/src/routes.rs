//! Server 与独立节点共用的 Caddy 业务路由，输入来自各自已授权的配置。

use anyhow::{Context, Result};
use serde_json::{json, Value};

pub fn public_url(protocol: &str, host: &str, port: u16) -> String {
    if protocol == "https" && port != 443 {
        format!("https://{host}:{port}")
    } else {
        format!("{protocol}://{host}")
    }
}

/// 直连回源使用 URL；穿透回源仍走已认证的本地 socket。
pub fn proxy_handler(upstream: &str) -> Result<Value> {
    let mut handler = json!({"handler":"reverse_proxy","upstreams":[{"dial":upstream}],"stream_close_delay":300000000000_u64});
    if upstream.starts_with("http://") || upstream.starts_with("https://") {
        let url = reqwest::Url::parse(upstream)?;
        let host = url.host_str().context("反代目标缺少主机名")?;
        handler["upstreams"][0]["dial"] = json!(format!(
            "{host}:{}",
            url.port_or_known_default().context("反代目标缺少端口")?
        ));
        // Caddy 新版本 HTTPS 回源可能重写 Host；显式保留用户访问的公网主机名。
        handler["headers"] = json!({"request":{"set":{"Host":["{http.request.hostport}"]}}});
        if url.scheme() == "https" {
            handler["transport"] =
                json!({"protocol":"http","tls":{"server_name":host.trim_matches(['[', ']'])}});
        }
    }
    Ok(handler)
}

/// 只跳到配置中的域名，保留原方法与 URI；禁止缓存以便关闭和换域名后立即恢复。
pub fn https_redirect(hostname: &str, port: u16) -> Value {
    let origin = public_url("https", hostname, port);
    json!({"match":[{"host":[hostname]}],"handle":[{"handler":"static_response","status_code":307,"headers":{"Location":[format!("{origin}{{http.request.uri}}")],"Cache-Control":["no-store"]}}],"terminal":true})
}

/// 内置及远端入口只按真实 socket 来源匹配 Agent 出口，禁止采信访客转发头。
/// 仅跳转页面导航，保留 API、WebSocket 和非幂等请求的穿透路径，并禁用缓存。
pub fn lan_redirect(
    id: &str,
    host: &str,
    public_ipv4: std::net::Ipv4Addr,
    origin: &str,
) -> serde_json::Value {
    serde_json::json!({
        "@id": format!("{}{}", crate::caddy::LAN_REDIRECT_ROUTE_PREFIX, id),
        "match": [{"host": [host], "remote_ip": {"ranges": [format!("{public_ipv4}/32")]},
            "method": ["GET", "HEAD"], "header": {"Sec-Fetch-Mode": ["navigate"], "Sec-Fetch-Dest": ["document"]},
            "not": [{"header": {"Upgrade": ["*"]}}]}],
        "handle": [{"handler": "static_response", "status_code": 307,
            "headers": {"Location": [format!("{origin}{{http.request.uri}}")], "Cache-Control": ["no-store"]}}],
        "terminal": true
    })
}

/// 复用 Caddy forward_auth 的响应接管方式：2xx 继续原请求，其他状态直接返回访客。
/// 元数据全部覆盖；校验使用 GET，不消耗原 POST 请求体。认证 Cookie 不转发到目标应用。
pub fn access_handlers(address: &str, id: &str) -> (Value, Value) {
    let headers = json!({"request":{"set":{
        "X-Nexo-Access-Service":[id], "X-Nexo-Access-Host":["{http.request.host}"],
        "X-Nexo-Access-Authority":["{http.request.hostport}"], "X-Nexo-Access-Proto":["{http.request.scheme}"],
        "X-Nexo-Access-Ip":["{http.request.remote.host}"], "X-Nexo-Access-Method":["{http.request.method}"],
        "X-Nexo-Access-Uri":["{http.request.uri}"]}}});
    let endpoint =
        json!({"handler":"reverse_proxy","upstreams":[{"dial":address}],"headers":headers});
    let mut check = endpoint.clone();
    check["rewrite"] = json!({"method":"GET","uri":"/check"});
    check["handle_response"] = json!([{"match":{"status_code":[2]},"routes":[{"handle":[{"handler":"headers","request":{"set":{"Cookie":["{http.reverse_proxy.header.X-Nexo-Upstream-Cookie}"]},"delete":["X-Nexo-Access-*","X-Nexo-Upstream-Cookie"]}}]}]}]);
    (endpoint, check)
}

pub const PROBE_PATH: &str = "/.nexo-relay/probe";

/// 回显配置标识用于识别错端口、错路由和迟到的 Caddy 配置，不包含身份凭据。
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProbeIdentity {
    pub node_id: String,
    pub service_id: String,
    pub revision: i64,
}

pub fn probe_route(host: &str, node: &str, service: &str, revision: i64) -> Value {
    let body = json!({"node_id":node,"service_id":service,"revision":revision}).to_string();
    json!({"match":[{"host":[host],"path":[PROBE_PATH],"method":["GET"]}],"handle":[{"handler":"static_response","status_code":200,"body":body,"headers":{"Content-Type":["application/json"],"Cache-Control":["no-store"]}}],"terminal":true})
}
