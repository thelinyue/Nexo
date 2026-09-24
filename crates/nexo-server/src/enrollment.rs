//! 入网审批绑定 Agent 的 CSR。一次性 Token 只能认领同一份公钥，客户端私钥不离开 Agent。
use crate::*;
use nexo_tunnel::identity::validate_csr;

/// 这是现有 Tunnel 数据目录的增量表；旧 mesh 数据仍由 initialize_database 拒绝。
pub fn initialize_schema(connection: &Connection) -> Result<()> {
    let has_kind: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('pending_enrollments') WHERE name='kind')",
        [],
        |r| r.get(0),
    )?;
    if !has_kind {
        connection.execute_batch(
            "ALTER TABLE pending_enrollments ADD COLUMN kind TEXT NOT NULL DEFAULT 'enroll';",
        )?;
    }
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS enrollment_requests (
        enrollment_id TEXT PRIMARY KEY REFERENCES pending_enrollments(id) ON DELETE CASCADE,
        csr_pem TEXT NOT NULL, device_name TEXT NOT NULL, os TEXT, architecture TEXT,
        agent_version TEXT NOT NULL, certificate_pem TEXT
    );",
    )?;
    crate::identity_runtime::initialize_schema(connection)
}

pub(crate) async fn agent_enroll(
    State(state): State<AppState>,
    Json(input): Json<AgentEnrollmentRequest>,
) -> Result<Json<AgentEnrollmentResponse>, ApiError> {
    let csr = input.csr_pem.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "Agent 必须提供设备 CSR，请升级 Agent 后重试",
        )
    })?;
    validate_csr(csr).map_err(|e| ApiError::new(StatusCode::BAD_REQUEST, e.to_string()))?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    let row = tx
        .query_row(
            "SELECT id,status,expires_at,kind,device_id FROM pending_enrollments WHERE token_digest=?1 AND EXISTS(SELECT 1 FROM tenants w WHERE w.id=pending_enrollments.tenant_id AND w.enabled=1)",
            [EnrollmentToken::digest(&input.token)],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "入网凭证无效"))?;
    if row.2 <= unix_now() {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "入网凭证已过期"));
    }
    if row.3 == "recovery" && row.4.is_none() {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "原设备已删除，恢复凭证已失效",
        ));
    }
    if !matches!(
        row.1.as_str(),
        "awaiting_agent" | "awaiting_approval" | "approved" | "consumed"
    ) {
        return Err(ApiError::new(StatusCode::CONFLICT, "入网凭证不可使用"));
    }
    let previous: Option<String> = tx
        .query_row(
            "SELECT csr_pem FROM enrollment_requests WHERE enrollment_id=?1",
            [&row.0],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?;
    if previous.as_deref().is_some_and(|previous| previous != csr) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "入网凭证已由其他 Agent 认领，请生成新凭证",
        ));
    }
    if previous.is_none() {
        if row.1 != "awaiting_agent" {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "此入网请求缺少设备身份，请重新入网",
            ));
        }
        tx.execute("INSERT INTO enrollment_requests (enrollment_id,csr_pem,device_name,os,architecture,agent_version) VALUES (?1,?2,?3,?4,?5,?6)", params![row.0,csr,input.device_name,input.os,input.architecture,input.agent_version]).map_err(db_error)?;
        tx.execute(
            "UPDATE pending_enrollments SET status='awaiting_approval' WHERE id=?1",
            [&row.0],
        )
        .map_err(db_error)?;
    }
    tx.commit().map_err(db_error)?;
    // 即使响应丢失，仍可用原 CSR 和未过期 Token 领取同一张公开证书，绝不创建第二个身份。
    Ok(Json(AgentEnrollmentResponse {
        enrollment_id: row.0,
        status: EnrollmentStatus::AwaitingApproval,
        device_id: if row.3 == "recovery" { row.4 } else { None },
        server_endpoint: None,
        certificate_pem: None,
        ca_certificate_pem: None,
        message: "入网请求已接收，请在所属工作空间批准".into(),
    }))
}

pub(crate) async fn approve_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ApproveEnrollment>,
) -> Result<Json<Enrollment>, ApiError> {
    let session = require_write(&state, &headers)?;
    let target: Option<String> = {
        let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
        db.query_row("SELECT device_id FROM pending_enrollments WHERE id=?1 AND tenant_id=?2 AND kind='recovery'",params![id,session.tenant_id], |r| r.get(0))
            .optional().map_err(db_error)?.flatten()
    };
    let result = if let Some(device) = target {
        // 证书切换与断开旧连接共享连接锁；握手后的二次校验也使用此锁，消除旧身份抢先注册的窗口。
        state
            .tunnel_runtime
            .replace_identity(&device, || approve(&state, &session, id, input))
            .await?
    } else {
        approve(&state, &session, id, input)?
    };
    Ok(Json(result))
}

fn approve(
    state: &AppState,
    session: &auth::Session,
    id: String,
    input: ApproveEnrollment,
) -> Result<Enrollment, ApiError> {
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    accounts::ensure_workspace_enabled(&db, &session.tenant_id)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    let (status, expires, kind, target): (String, i64, String, Option<String>) = tx.query_row(
        "SELECT status,expires_at,kind,device_id FROM pending_enrollments WHERE id=?1 AND tenant_id=?2",
        params![id,session.tenant_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))
        .optional().map_err(db_error)?.ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND,"入网请求不存在"))?;
    if expires <= unix_now() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "入网凭证已过期，请重新生成",
        ));
    }
    if status != "awaiting_approval" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "请等待 Agent 提交设备身份后再批准",
        ));
    }
    let recovery = kind == "recovery";
    let device = if recovery {
        target.ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "原设备已删除，不能恢复身份"))?
    } else {
        Uuid::new_v4().to_string()
    };
    let csr: String = tx
        .query_row(
            "SELECT csr_pem FROM enrollment_requests WHERE enrollment_id=?1",
            [&id],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    let cert = state
        .authority
        .issue_device(&csr, &device)
        .map_err(db_error)?;
    let fingerprint = identity_runtime::fingerprint(&cert).map_err(db_error)?;
    if recovery {
        let changed = tx
            .execute(
                "UPDATE devices SET status='offline',updated_at=?1 WHERE id=?2 AND tenant_id=?3",
                params![unix_now(), device, session.tenant_id],
            )
            .map_err(db_error)?;
        if changed != 1 {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "原设备不存在"));
        }
        // 服务主键、设备绑定和启停状态保持不变，只重新要求 Agent 上报应用结果。
        tx.execute("DELETE FROM tunnel_applied_states WHERE tunnel_id IN (SELECT id FROM tunnels WHERE device_id=?1)",[&device]).map_err(db_error)?;
        tx.execute("UPDATE tunnels SET apply_revision=apply_revision+1,apply_status=CASE WHEN enabled=1 THEN 'checking' ELSE 'disabled' END WHERE device_id=?1 AND deleted_at IS NULL",[&device]).map_err(db_error)?;
    } else {
        let name = input.device_name.filter(|v| !v.trim().is_empty());
        tx.execute("INSERT INTO devices (id,tenant_id,name,os,architecture,agent_version,status,enrolled_at,created_at,updated_at) SELECT ?1,?2,COALESCE(?3,device_name),os,architecture,agent_version,'offline',?4,?4,?4 FROM enrollment_requests WHERE enrollment_id=?5",params![device,session.tenant_id,name,unix_now(),id]).map_err(db_error)?;
    }
    tx.execute("INSERT INTO device_identities (device_id,secret_digest,created_at) VALUES (?1,?2,?3) ON CONFLICT(device_id) DO UPDATE SET secret_digest=excluded.secret_digest,created_at=excluded.created_at",params![device,fingerprint,unix_now()]).map_err(db_error)?;
    tx.execute("INSERT INTO device_certificates (device_id,certificate_pem) VALUES (?1,?2) ON CONFLICT(device_id) DO UPDATE SET certificate_pem=excluded.certificate_pem,pending_csr_pem=NULL,pending_certificate_pem=NULL,retry_failures=0,renewal_error=NULL,next_retry_at=NULL",params![device,cert]).map_err(db_error)?;
    tx.execute(
        "UPDATE enrollment_requests SET certificate_pem=?1 WHERE enrollment_id=?2",
        params![cert, id],
    )
    .map_err(db_error)?;
    tx.execute(
        "UPDATE pending_enrollments SET status='approved',device_id=?1 WHERE id=?2",
        params![device, id],
    )
    .map_err(db_error)?;
    tx.execute("INSERT INTO audit_events(tenant_id,actor_user_id,event_type,resource_type,resource_id,created_at) VALUES (?1,?2,?3,'device',?4,?5)",params![session.tenant_id,session.user_id,if recovery {"identity_recovered"} else {"enrollment_approved"},device,unix_now()]).map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(Enrollment {
        id,
        kind,
        tenant_id: session.tenant_id.clone(),
        status: "approved".into(),
        expires_at: expires,
        device_id: Some(device),
        token: None,
    })
}

/// 恢复邀请绑定已存在的设备；再次生成撤销未完成的旧邀请，批准前不改动现有身份。
pub(crate) async fn create_recovery(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device): Path<String>,
) -> Result<Json<Enrollment>, ApiError> {
    let session = require_write(&state, &headers)?;
    let token = EnrollmentToken::generate(unix_now(), 3600).map_err(db_error)?;
    let id = Uuid::new_v4().to_string();
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    accounts::ensure_workspace_enabled(&db, &session.tenant_id)?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    let exists: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id=?1 AND tenant_id=?2)",
            params![device, session.tenant_id],
            |r| r.get(0),
        )
        .map_err(db_error)?;
    if !exists {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "设备不存在"));
    }
    tx.execute(
        "UPDATE pending_enrollments SET status='revoked' WHERE device_id=?1 AND kind='recovery'",
        [&device],
    )
    .map_err(db_error)?;
    tx.execute("INSERT INTO pending_enrollments(id,tenant_id,token_digest,status,expires_at,device_id,created_at,kind) VALUES (?1,?2,?3,'awaiting_agent',?4,?5,?6,'recovery')",params![id,session.tenant_id,token.digest,token.expires_at,device,unix_now()]).map_err(db_error)?;
    accounts::audit(&tx, &session, "device_recovery_created", "device", &device)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(Enrollment {
        id,
        kind: "recovery".into(),
        tenant_id: session.tenant_id,
        status: "awaiting_agent".into(),
        expires_at: token.expires_at,
        device_id: Some(device),
        token: Some(token.secret),
    }))
}

pub(crate) async fn cancel_enrollment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let session = require_write(&state, &headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let changed=db.execute("UPDATE pending_enrollments SET status='revoked' WHERE id=?1 AND tenant_id=?2 AND status IN ('awaiting_agent','awaiting_approval')",params![id,session.tenant_id]).map_err(db_error)?;
    if changed != 1 {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "请求已批准、已撤销或不存在，请刷新列表",
        ));
    }
    Ok(Json(serde_json::json!({"revoked":true})))
}

pub(crate) async fn agent_poll(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(input): Json<AgentEnrollmentPollRequest>,
) -> Result<Json<AgentEnrollmentPollResponse>, ApiError> {
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let row = db.query_row("SELECT p.status,p.device_id,p.expires_at,r.certificate_pem FROM pending_enrollments p LEFT JOIN enrollment_requests r ON r.enrollment_id=p.id WHERE p.id=?1 AND p.token_digest=?2 AND EXISTS(SELECT 1 FROM tenants w WHERE w.id=p.tenant_id AND w.enabled=1)", params![id,EnrollmentToken::digest(&input.token)], |r| Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,i64>(2)?,r.get::<_,Option<String>>(3)?))).optional().map_err(db_error)?.ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED,"入网请求无效"))?;
    if row.2 <= unix_now() {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "入网凭证已过期"));
    }
    let approved =
        matches!(row.0.as_str(), "approved" | "consumed") && row.1.is_some() && row.3.is_some();
    if approved {
        db.execute(
            "UPDATE pending_enrollments SET status='consumed' WHERE id=?1",
            [&id],
        )
        .map_err(db_error)?;
    } else if !matches!(row.0.as_str(), "awaiting_agent" | "awaiting_approval") {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "设备身份已失效，请重新入网",
        ));
    }
    Ok(Json(AgentEnrollmentPollResponse {
        enrollment_id: id,
        status: if approved {
            EnrollmentStatus::Approved
        } else {
            EnrollmentStatus::AwaitingApproval
        },
        device_id: if approved { row.1 } else { None },
        certificate_pem: if approved { row.3 } else { None },
        ca_certificate_pem: approved.then(|| state.authority.ca_pem()),
        message: if approved {
            "Agent 已批准"
        } else {
            "等待管理员批准"
        }
        .into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(token: &str) -> AgentEnrollmentRequest {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::new(vec!["agent.nexo".into()])
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        AgentEnrollmentRequest {
            token: token.into(),
            device_name: "测试设备".into(),
            os: Some("test".into()),
            architecture: None,
            agent_version: "test".into(),
            csr_pem: Some(csr),
        }
    }

    #[tokio::test]
    async fn enrollment_binds_csr_and_response_retries_reuse_one_identity() {
        let (state, headers) = crate::tests::domain_fixture();
        let invite = create_enrollment(
            State(state.clone()),
            headers.clone(),
            Json(CreateEnrollment {
                ttl_seconds: Some(3600),
            }),
        )
        .await
        .unwrap()
        .0;
        let token = invite.token.unwrap();
        let input = request(&token);
        let _ = agent_enroll(State(state.clone()), Json(input.clone()))
            .await
            .unwrap();
        let rejected = agent_enroll(State(state.clone()), Json(request(&token)))
            .await
            .unwrap_err();
        assert_eq!(rejected.status, StatusCode::CONFLICT);
        let approval = approve_enrollment(
            State(state.clone()),
            headers,
            Path(invite.id.clone()),
            Json(ApproveEnrollment { device_name: None }),
        )
        .await
        .unwrap()
        .0;
        let first = agent_poll(
            State(state.clone()),
            Path(invite.id.clone()),
            Json(AgentEnrollmentPollRequest {
                token: token.clone(),
            }),
        )
        .await
        .unwrap()
        .0;
        // 丢失响应的重试只能返回原证书，不能新建身份或替换公钥。
        let _ = agent_enroll(State(state.clone()), Json(input))
            .await
            .unwrap();
        let second = agent_poll(
            State(state.clone()),
            Path(invite.id.clone()),
            Json(AgentEnrollmentPollRequest {
                token: token.clone(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(first.device_id, approval.device_id);
        assert_eq!(first.certificate_pem, second.certificate_pem);
        assert!(first.certificate_pem.is_some());
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE pending_enrollments SET expires_at=0 WHERE id=?1",
                [&invite.id],
            )
            .unwrap();
        assert_eq!(
            agent_poll(
                State(state),
                Path(invite.id),
                Json(AgentEnrollmentPollRequest { token })
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn approval_requires_csr_and_unexpired_owned_invitation() {
        let (state, headers) = crate::tests::domain_fixture();
        let invite = create_enrollment(
            State(state.clone()),
            headers.clone(),
            Json(CreateEnrollment {
                ttl_seconds: Some(3600),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            approve_enrollment(
                State(state.clone()),
                headers.clone(),
                Path(invite.id.clone()),
                Json(ApproveEnrollment { device_name: None })
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::CONFLICT
        );
        let mut invalid = request(invite.token.as_deref().unwrap());
        invalid.csr_pem = Some("invalid".into());
        assert_eq!(
            agent_enroll(State(state.clone()), Json(invalid))
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
        let _ = agent_enroll(
            State(state.clone()),
            Json(request(invite.token.as_deref().unwrap())),
        )
        .await
        .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE pending_enrollments SET expires_at=0 WHERE id=?1",
                [&invite.id],
            )
            .unwrap();
        assert_eq!(
            approve_enrollment(
                State(state.clone()),
                headers,
                Path(invite.id),
                Json(ApproveEnrollment { device_name: None })
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM device_identities", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn recovery_preserves_device_and_services_and_rejects_revoked_keys() {
        let (state, headers) = crate::tests::domain_fixture();
        let invite = create_enrollment(
            State(state.clone()),
            headers.clone(),
            Json(CreateEnrollment {
                ttl_seconds: Some(3600),
            }),
        )
        .await
        .unwrap()
        .0;
        let token = invite.token.unwrap();
        let _ = agent_enroll(State(state.clone()), Json(request(&token)))
            .await
            .unwrap();
        let original = approve_enrollment(
            State(state.clone()),
            headers.clone(),
            Path(invite.id.clone()),
            Json(ApproveEnrollment {
                device_name: Some("原设备".into()),
            }),
        )
        .await
        .unwrap()
        .0;
        let device = original.device_id.unwrap();
        let old = agent_poll(
            State(state.clone()),
            Path(invite.id),
            Json(AgentEnrollmentPollRequest { token }),
        )
        .await
        .unwrap()
        .0
        .certificate_pem
        .unwrap();
        {
            let db = state.db.lock().unwrap();
            for (id, enabled) in [("enabled-service", 1), ("disabled-service", 0)] {
                db.execute("INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,local_address,local_port,enabled,created_at,updated_at) VALUES(?1,'default',?2,'服务','tcp','127.0.0.1',9,?3,0,0)",params![id,device,enabled]).unwrap();
            }
        }
        let first = create_recovery(State(state.clone()), headers.clone(), Path(device.clone()))
            .await
            .unwrap()
            .0;
        let invite = create_recovery(State(state.clone()), headers.clone(), Path(device.clone()))
            .await
            .unwrap()
            .0;
        assert!(
            agent_enroll(State(state.clone()), Json(request(&first.token.unwrap())))
                .await
                .is_err()
        );
        let token = invite.token.unwrap();
        let submitted = agent_enroll(State(state.clone()), Json(request(&token)))
            .await
            .unwrap()
            .0;
        assert_eq!(submitted.device_id.as_deref(), Some(device.as_str()));
        identity_runtime::accept_certificate(
            &state.db.lock().unwrap(),
            &device,
            &identity_runtime::fingerprint(&old).unwrap(),
        )
        .unwrap();
        let approved = approve_enrollment(
            State(state.clone()),
            headers.clone(),
            Path(invite.id.clone()),
            Json(ApproveEnrollment {
                device_name: Some("不应重命名".into()),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(approved.device_id.as_deref(), Some(device.as_str()));
        let issued = agent_poll(
            State(state.clone()),
            Path(invite.id),
            Json(AgentEnrollmentPollRequest { token }),
        )
        .await
        .unwrap()
        .0;
        {
            let db = state.db.lock().unwrap();
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            assert_eq!(
                db.query_row("SELECT name FROM devices WHERE id=?1", [&device], |r| {
                    r.get::<_, String>(0)
                })
                .unwrap(),
                "原设备"
            );
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM tunnels WHERE device_id=?1",
                    [&device],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                2
            );
            assert_eq!(
                db.query_row(
                    "SELECT SUM(enabled) FROM tunnels WHERE device_id=?1",
                    [&device],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                1
            );
            assert!(identity_runtime::accept_certificate(
                &db,
                &device,
                &identity_runtime::fingerprint(&old).unwrap()
            )
            .is_err());
            identity_runtime::accept_certificate(
                &db,
                &device,
                &identity_runtime::fingerprint(&issued.certificate_pem.unwrap()).unwrap(),
            )
            .unwrap();
        }
        let invite = create_recovery(State(state.clone()), headers.clone(), Path(device.clone()))
            .await
            .unwrap()
            .0;
        let _ = cancel_enrollment(State(state.clone()), headers.clone(), Path(invite.id))
            .await
            .unwrap();
        assert!(
            agent_enroll(State(state.clone()), Json(request(&invite.token.unwrap())))
                .await
                .is_err()
        );
        let invite = create_recovery(State(state.clone()), headers, Path(device.clone()))
            .await
            .unwrap()
            .0;
        state
            .db
            .lock()
            .unwrap()
            .execute("DELETE FROM devices WHERE id=?1", [&device])
            .unwrap();
        assert!(
            agent_enroll(State(state), Json(request(&invite.token.unwrap())))
                .await
                .is_err()
        );
    }
}
