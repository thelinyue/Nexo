//! 设备子网编辑：只修改本次展示并提交的行，未提交资源保持原样。
//! 所有校验与写入位于同一事务，运行配置由现有控制通道异步收敛。
use super::*;

#[derive(Deserialize)]
pub(super) struct SelectionRequest {
    networks: Vec<Selection>,
}

#[derive(Deserialize)]
struct Selection {
    id: Option<String>,
    interface_id: Option<String>,
    prefix: String,
    enabled: bool,
}

fn database_error(error: rusqlite::Error) -> ApiError {
    tracing::error!("保存设备子网失败：{error}");
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "无法保存设备子网，请稍后重试",
    )
}

/// 原因只使用可信设备快照及应用状态，不解析可能变化的错误文案。
pub(super) fn status_reason(
    db: &Connection,
    network: &SiteNetworkResponse,
) -> Result<&'static str, ApiError> {
    if network.apply_status == ApplyStatus::Disabled {
        return Ok("disabled");
    }
    let (online, report): (bool, Option<String>) = db.query_row(
        "SELECT d.status = 'online', r.report_json FROM devices d LEFT JOIN device_capability_reports r ON r.device_id = d.id WHERE d.id = ?1",
        [&network.publisher_device_id], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(database_error)?;
    if !online {
        return Ok("device_offline");
    }
    if !network.enabled {
        return Ok("disabling");
    }
    if let Some(report) =
        report.and_then(|value| serde_json::from_str::<GatewayCapabilityReport>(&value).ok())
    {
        if let Ok(prefix) = network.desired_prefix.parse::<IpNet>() {
            if gateway_forwarding_error(&report, prefix).is_some() {
                return Ok(if prefix.addr().is_ipv4() {
                    "ipv4_forwarding_disabled"
                } else {
                    "ipv6_forwarding_disabled"
                });
            }
        }
        if network.source == "detected"
            && !report
                .local_networks
                .iter()
                .any(|item| item.prefix == network.desired_prefix)
        {
            return Ok("network_missing");
        }
    }
    if network.apply_status == ApplyStatus::Failed
        || network.health_status == GatewayHealthStatus::Failed
    {
        return Ok("apply_failed");
    }
    if network.apply_status == ApplyStatus::Ready
        && network.health_status == GatewayHealthStatus::Ready
    {
        return Ok("ready");
    }
    Ok("applying")
}

pub(super) async fn save(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(request): Json<SelectionRequest>,
) -> Result<Json<Vec<SiteNetworkResponse>>, ApiError> {
    let tenant = auth::admin_tenant_id(&state, &headers)?;
    let mut db = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let tx = db.transaction().map_err(database_error)?;
    let is_client: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tailscale_device_metadata WHERE device_id = d.id)
         FROM devices d WHERE d.id = ?1 AND d.tenant_id = ?2",
            rusqlite::params![device_id, tenant],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "设备不存在"))?;
    if is_client {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "请选择 Nexo Agent 承载共享网段",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut ids = Vec::new();
    for item in request.networks {
        let prefix = item
            .prefix
            .parse::<IpNet>()
            .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "网段不是有效 CIDR"))?
            .trunc();
        validate_published_network(prefix)
            .map_err(|error| ApiError::new(StatusCode::BAD_REQUEST, error.to_string()))?;
        let existing: Option<(String, String, Option<String>, String, bool, bool)> = if let Some(
            id,
        ) = &item.id
        {
            let row = tx.query_row(
                "SELECT n.id, g.desired_prefix, n.interface_id, n.source, n.enabled, n.deletion_requested
                 FROM site_networks n JOIN gateway_network_states g ON g.site_network_id = n.id
                 WHERE n.id = ?1 AND n.publisher_device_id = ?2 AND n.tenant_id = ?3",
                rusqlite::params![id, device_id, tenant],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
            ).optional().map_err(database_error)?;
            Some(row.ok_or_else(|| {
                ApiError::new(StatusCode::NOT_FOUND, "共享网段不存在或不属于该设备")
            })?)
        } else {
            // 重复提交首次创建请求时复用已有 ID，避免网络重试生成重复资源。
            tx.query_row(
                "SELECT n.id, g.desired_prefix, n.interface_id, n.source, n.enabled, n.deletion_requested
                 FROM site_networks n JOIN gateway_network_states g ON g.site_network_id = n.id
                 WHERE n.publisher_device_id = ?1 AND n.tenant_id = ?2 AND g.desired_prefix = ?3",
                rusqlite::params![device_id, tenant, prefix.to_string()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
            ).optional().map_err(database_error)?
        };
        let id = existing
            .as_ref()
            .map(|row| row.0.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        if !seen.insert(prefix.to_string()) {
            return Err(ApiError::new(StatusCode::CONFLICT, "提交的网段重复"));
        }
        if let Some(row) = &existing {
            if row.1 != prefix.to_string() || row.5 {
                return Err(ApiError::new(
                    StatusCode::CONFLICT,
                    "网段已变化或正在删除，请刷新后重试",
                ));
            }
        }
        if existing.is_none() && !item.enabled {
            continue;
        }
        let changed = existing.as_ref().is_none_or(|row| row.4 != item.enabled);
        if item.enabled && changed {
            let interface = existing
                .as_ref()
                .and_then(|row| row.2.as_deref())
                .or(item.interface_id.as_deref());
            let detected = existing.as_ref().is_none_or(|row| row.3 != "manual");
            ensure_gateway_device(
                &tx,
                &GatewayDeviceRequirement {
                    tenant_id: &tenant,
                    device_id: &device_id,
                    interface_id: interface,
                    prefix,
                    require_online: false,
                    require_detected_network: detected,
                },
            )?;
            let mut query = tx.prepare("SELECT g.desired_prefix FROM site_networks n JOIN gateway_network_states g ON g.site_network_id = n.id WHERE n.tenant_id = ?1 AND n.id <> ?2 AND n.deletion_requested = 0").map_err(database_error)?;
            for value in query
                .query_map(rusqlite::params![tenant, id], |row| row.get::<_, String>(0))
                .map_err(database_error)?
            {
                let other = value
                    .map_err(database_error)?
                    .parse::<IpNet>()
                    .map_err(|_| {
                        ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "已保存网段格式无效")
                    })?;
                if networks_overlap(prefix, other) {
                    return Err(ApiError::new(
                        StatusCode::CONFLICT,
                        "网段与已有共享网段重叠",
                    ));
                }
            }
        }
        if existing.is_none() {
            tx.execute("INSERT INTO site_networks (id, tenant_id, name, publisher_device_id, interface_id, address_family, source, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'direct_interface', 1)", rusqlite::params![id, tenant, prefix.to_string(), device_id, item.interface_id, if prefix.addr().is_ipv4() { "ipv4" } else { "ipv6" }]).map_err(database_error)?;
            tx.execute("INSERT INTO gateway_network_states (site_network_id, desired_prefix, desired_revision) VALUES (?1, ?2, 1)", rusqlite::params![id, prefix.to_string()]).map_err(database_error)?;
            tx.execute("INSERT INTO subnet_access (id, tenant_id, site_network_id, scope, enabled) VALUES (?1, ?2, ?3, 'tenant_mesh', 1)", rusqlite::params![Uuid::new_v4().to_string(), tenant, id]).map_err(database_error)?;
        } else if changed {
            tx.execute("UPDATE site_networks SET enabled = ?1, apply_status = 'checking', apply_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?2", rusqlite::params![item.enabled, id]).map_err(database_error)?;
            tx.execute("UPDATE gateway_network_states SET desired_revision = desired_revision + 1, apply_status = 'checking', applied_prefix = NULL, apply_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE site_network_id = ?1", [&id]).map_err(database_error)?;
        }
        if changed {
            write_audit_event(
                &tx,
                &tenant,
                if item.enabled {
                    "SUBNET_ENABLED"
                } else {
                    "SUBNET_DISABLED"
                },
                "site_network",
                &id,
            )?;
        }
        ids.push(id);
    }
    tx.commit().map_err(database_error)?;
    let result = ids
        .iter()
        .map(|id| read_site_network_response(&db, id))
        .collect::<Result<Vec<_>, _>>()?;
    schedule_policy_reconcile(&state);
    Ok(Json(result))
}

pub(super) async fn recheck(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SiteNetworkResponse>, ApiError> {
    let tenant = auth::admin_tenant_id(&state, &headers)?;
    let mut db = state
        .db
        .lock()
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "数据库锁不可用"))?;
    let tx = db.transaction().map_err(database_error)?;
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM site_networks WHERE id = ?1 AND tenant_id = ?2)",
            rusqlite::params![id, tenant],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    if !exists {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "共享网段不存在"));
    }
    tx.execute("UPDATE gateway_network_states SET desired_revision = desired_revision + 1, apply_status = 'checking', apply_error = NULL, applied_prefix = NULL, updated_at = CURRENT_TIMESTAMP WHERE site_network_id = ?1",[&id]).map_err(database_error)?;
    tx.execute(
        "UPDATE site_networks SET updated_at = CURRENT_TIMESTAMP WHERE id = ?1",
        [&id],
    )
    .map_err(database_error)?;
    write_audit_event(&tx, &tenant, "SUBNET_RECHECK", "site_network", &id)?;
    tx.commit().map_err(database_error)?;
    schedule_policy_reconcile(&state);
    Ok(Json(read_site_network_response(&db, &id)?))
}
