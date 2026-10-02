//! 反代只复用服务存储与域名入口，不参与 Agent 状态、监听或穿透额度。
use crate::*;

pub const MODE: &str = "reverse_proxy";

/// 使用同一事务中的真实登录用户校验权限，不能把被管理工作空间当作操作者。
fn authorize(db: &Connection, session: &auth::Session, mode: &str) -> Result<(), ApiError> {
    if mode == MODE {
        let admin: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1 AND role='system_admin' AND enabled=1)",
            [&session.user_id], |r| r.get(0),
        ).map_err(db_error)?;
        if !admin {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "反向代理仅允许管理员管理",
            ));
        }
    }
    Ok(())
}

pub fn existing(db: &Connection, session: &auth::Session, id: &str) -> Result<bool, ApiError> {
    let mode: String = db
        .query_row(
            "SELECT service_mode FROM tunnels WHERE id=?1 AND tenant_id=?2 AND deleted_at IS NULL",
            params![id, session.tenant_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "服务不存在"))?;
    authorize(db, session, &mode)?;
    Ok(mode == MODE)
}

/// 局部更新省略字段时保留原模式；绝不能通过删除 Agent 绑定隐式创建反代。
pub fn prepare(
    db: &Connection,
    session: &auth::Session,
    id: &str,
    input: &mut TunnelInput,
) -> Result<(), ApiError> {
    let previous: Option<String> = db
        .query_row(
            "SELECT service_mode FROM tunnels WHERE id=?1 AND tenant_id=?2 AND deleted_at IS NULL",
            params![id, session.tenant_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?;
    let mode = input
        .service_mode
        .clone()
        .or(previous.clone())
        .unwrap_or_else(|| "tunnel".into());
    // 先检查原对象权限，避免通过修改模式绕过管理员限制。
    if let Some(previous) = &previous {
        authorize(db, session, previous)?;
    }
    authorize(db, session, &mode)?;
    if !matches!(mode.as_str(), "tunnel" | MODE) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "服务模式无效"));
    }
    if previous.as_ref().is_some_and(|value| value != &mode) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "服务模式创建后不可修改，请重新创建服务",
        ));
    }
    if mode == MODE {
        if !matches!(input.protocol.as_str(), "http" | "https")
            || input.device_id.is_some()
            || input.public_port.is_some()
            || input.lan_redirect_enabled == Some(true)
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "反向代理只支持 HTTP/HTTPS，不能绑定设备、公网端口或内网重定向",
            ));
        }
        // 用 URL 解析器验证主机，防止地址字段注入路径、凭据、查询串或额外端口。
        let address = input.local_address.trim();
        let host = address.trim_matches(['[', ']']);
        let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let url = reqwest::Url::parse(&format!("http://{authority}:{}", input.local_port))
            .map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "目标地址必须是 IP 或主机名，不含协议、端口或路径",
                )
            })?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none()
            || address.contains(['/', '\\', '@', '?', '#'])
        {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "目标地址必须是 IP 或主机名，不含协议、端口或路径",
            ));
        }
        input.local_address = url.host_str().unwrap().trim_matches(['[', ']']).to_owned();
        input.lan_redirect_enabled = Some(false);
    }
    // 创建默认强制 HTTPS；局部更新保留选择，HTTP 模式只暂存此偏好。
    input.http_redirect_enabled = Some(if mode == MODE {
        match input.http_redirect_enabled {
            Some(value) => value,
            None => db
                .query_row(
                    "SELECT http_redirect_enabled FROM tunnels WHERE id=?1 AND tenant_id=?2",
                    params![id, session.tenant_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(db_error)?
                .unwrap_or(true),
        }
    } else {
        if input.http_redirect_enabled == Some(true) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "强制 HTTPS 仅支持反向代理",
            ));
        }
        false
    });
    input.service_mode = Some(mode);
    Ok(())
}

pub fn target(protocol: &str, address: &str, port: u16) -> String {
    let host = address.trim_matches(['[', ']']);
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    format!("{protocol}://{host}:{port}")
}

/// 直连变更只同步域名配置；混合批次仅在包含穿透时通知 Agent。
pub async fn changed(state: &AppState, has_tunnels: bool) -> Result<(), ApiError> {
    if has_tunnels {
        state
            .tunnel_runtime
            .changed(state)
            .await
            .map_err(db_error)?;
    }
    domain_runtime::reconcile(state).await.map_err(db_error)?;
    refresh_status(state).map_err(db_error)
}

/// “ready”在反代中只表示当前目标路由和公网证书已生效，不探测业务健康。
pub fn refresh_status(state: &AppState) -> Result<()> {
    // Caddy 持有域名状态锁时会写数据库事件；读取状态前必须释放数据库锁，避免反向等待。
    let rows = {
        let db = state
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
        let mut query = db.prepare("SELECT t.id,t.enabled AND w.enabled,t.protocol,t.hostname,p.domain,t.public_domain_id,t.origin_protocol,t.local_address,t.local_port,t.https_port,t.apply_revision FROM tunnels t JOIN tenants w ON w.id=t.tenant_id LEFT JOIN public_domains p ON p.id=t.public_domain_id AND p.tenant_id=t.tenant_id WHERE t.service_mode='reverse_proxy' AND t.deleted_at IS NULL")?;
        let rows = query
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, Option<String>>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, u16>(8)?,
                    r.get::<_, u16>(9)?,
                    r.get::<_, i64>(10)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let mut updates = Vec::new();
    for (
        id,
        enabled,
        protocol,
        hostname,
        domain,
        domain_id,
        origin,
        address,
        port,
        https_port,
        revision,
    ) in rows
    {
        let runtime = state
            .domain_runtime
            .status(domain_id.as_deref().unwrap_or_default());
        let host = format!(
            "{}.{}",
            hostname.unwrap_or_default(),
            domain.unwrap_or_default()
        );
        let expected = target(origin.as_deref().unwrap_or("http"), &address, port);
        let (status, error) = if !enabled {
            ("disabled", None)
        } else if let Some(error) = runtime.service_errors.get(&id) {
            ("failed", Some(error.clone()))
        } else if let Some(error) = runtime.config_error {
            ("failed", Some(error))
        } else if runtime.config_status != "applied"
            || runtime
                .loaded_routes
                .get(&crate::https_ports::url(&protocol, &host, https_port))
                != Some(&expected)
        {
            ("checking", Some("等待 Caddy 加载当前反向代理配置".into()))
        } else if protocol == "https"
            && !runtime.certificates.iter().any(|cert| {
                (cert.hostname == host
                    || cert.hostname.strip_prefix("*.").is_some_and(|suffix| {
                        host.split_once('.').is_some_and(|(_, rest)| rest == suffix)
                    }))
                    && cert.expires_at.is_some_and(|at| at > unix_now())
                    && cert.not_before.is_some_and(|at| at <= unix_now())
            })
        {
            ("checking", Some("等待 HTTPS 证书签发或续期".into()))
        } else {
            ("ready", None)
        };
        // 状态读取期间配置可能改变；只回写仍属于本次快照且未删除的服务。
        updates.push(crate::transport::StatusUpdate {
            id,
            revision,
            status: status.into(),
            error,
            protocols: None,
        });
    }
    crate::transport::save_statuses(state, updates)?;
    Ok(())
}

#[cfg(test)]
mod tests;
