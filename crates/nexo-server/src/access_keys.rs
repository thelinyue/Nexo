//! 空间共享密钥只负责接入授权，设备身份仍由独立私钥和证书认证。
//! 密钥可再次读取，因此使用 AEAD 加密；注册记录在设备删除后保留空绑定，防止旧 CSR 重放复活。
use crate::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use nexo_protocol::AgentRegistrationResponse;
use rand::{rngs::OsRng, RngCore};

pub fn initialize_schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS agent_access_keys (
        tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
        token_digest TEXT NOT NULL UNIQUE, encrypted_token BLOB NOT NULL,
        created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS agent_registrations (
        tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        csr_pem TEXT NOT NULL, device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
        certificate_pem TEXT NOT NULL, created_at INTEGER NOT NULL,
        PRIMARY KEY(tenant_id,csr_pem)
    );",
    )?;
    Ok(())
}

#[derive(Serialize)]
pub(crate) struct AccessKey {
    token: String,
    created_at: i64,
    updated_at: i64,
}

/// 调用者持有数据库锁：首次生成和重置串行化，主密钥落盘失败不会提交不可解密的数据。
fn cipher(state: &AppState, db: &Connection) -> Result<ChaCha20Poly1305> {
    let path = state.data_dir.join("secrets/agent-access.key");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let count: i64 =
                db.query_row("SELECT COUNT(*) FROM agent_access_keys", [], |r| r.get(0))?;
            anyhow::ensure!(
                count == 0,
                "接入密钥加密文件缺失，请从 Server 数据备份恢复 secrets/agent-access.key"
            );
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            nexo_tunnel::identity::write_private_file(&path, &key)?;
            key.to_vec()
        }
        Err(error) => return Err(error).context("无法读取接入密钥加密文件"),
    };
    ChaCha20Poly1305::new_from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("接入密钥加密文件损坏，请恢复 Server 数据备份"))
}

fn read_key(
    state: &AppState,
    db: &Connection,
    tenant: &str,
) -> Result<Option<AccessKey>, ApiError> {
    let row: Option<(Vec<u8>, i64, i64)> = db.query_row(
        "SELECT encrypted_token,created_at,updated_at FROM agent_access_keys WHERE tenant_id=?1",
        [tenant], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(db_error)?;
    let Some((bytes, created_at, updated_at)) = row else {
        return Ok(None);
    };
    if bytes.len() < 12 {
        return Err(db_error("接入密钥密文损坏"));
    }
    let plain = cipher(state, db)
        .map_err(db_error)?
        .decrypt(
            Nonce::from_slice(&bytes[..12]),
            Payload {
                msg: &bytes[12..],
                aad: tenant.as_bytes(),
            },
        )
        .map_err(|_| db_error("无法解密接入密钥，请核对 Server 数据与加密文件备份"))?;
    let token = String::from_utf8(plain).map_err(|_| db_error("接入密钥密文损坏"))?;
    Ok(Some(AccessKey {
        token,
        created_at,
        updated_at,
    }))
}

pub(crate) async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Option<AccessKey>>, ApiError> {
    let session = require_session(&state, &headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    accounts::ensure_workspace_enabled(&db, &session.tenant_id)?;
    Ok(Json(read_key(&state, &db, &session.tenant_id)?))
}

pub(crate) async fn ensure(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AccessKey>, ApiError> {
    save(&state, &headers, false).map(Json)
}

pub(crate) async fn reset(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AccessKey>, ApiError> {
    save(&state, &headers, true).map(Json)
}

fn save(state: &AppState, headers: &HeaderMap, reset: bool) -> Result<AccessKey, ApiError> {
    let session = require_write(state, headers)?;
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    accounts::ensure_workspace_enabled(&db, &session.tenant_id)?;
    if !reset {
        if let Some(key) = read_key(state, &db, &session.tenant_id)? {
            return Ok(key);
        }
    }
    let cipher = cipher(state, &db).map_err(db_error)?;
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let token = format!("nexo_join_{}", hex::encode(secret));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: token.as_bytes(),
                aad: session.tenant_id.as_bytes(),
            },
        )
        .map_err(|_| db_error("无法加密接入密钥"))?;
    let mut bytes = nonce.to_vec();
    bytes.extend(encrypted);
    let tx = db.unchecked_transaction().map_err(db_error)?;
    tx.execute("INSERT INTO agent_access_keys(tenant_id,token_digest,encrypted_token,created_at,updated_at) VALUES(?1,?2,?3,?4,?4)
        ON CONFLICT(tenant_id) DO UPDATE SET token_digest=excluded.token_digest,encrypted_token=excluded.encrypted_token,updated_at=excluded.updated_at",
        params![session.tenant_id,EnrollmentToken::digest(&token),bytes,unix_now()]).map_err(db_error)?;
    accounts::audit(
        &tx,
        &session,
        if reset {
            "agent_access_key_reset"
        } else {
            "agent_access_key_created"
        },
        "workspace",
        &session.tenant_id,
    )?;
    tx.commit().map_err(db_error)?;
    read_key(state, &db, &session.tenant_id)?.ok_or_else(|| db_error("接入密钥未保存"))
}

/// 密钥验证、重复申请检查与身份创建在同一事务中完成，重置或停用不会在检查后插入竞争窗口。
pub(crate) async fn register(
    State(state): State<AppState>,
    Json(input): Json<AgentEnrollmentRequest>,
) -> Result<Json<AgentRegistrationResponse>, ApiError> {
    if !input.token.starts_with("nexo_join_") {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "请使用空间接入密钥",
        ));
    }
    let csr = input
        .csr_pem
        .as_deref()
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "设备 CSR 不能为空"))?;
    nexo_tunnel::identity::validate_csr(csr)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "设备 CSR 无效"))?;
    if input.device_name.len() > 256
        || input.agent_version.len() > 128
        || input.os.as_ref().is_some_and(|v| v.len() > 128)
        || input.architecture.as_ref().is_some_and(|v| v.len() > 128)
    {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "设备资料过长"));
    }
    let db = state.db.lock().map_err(|_| db_error("数据库锁不可用"))?;
    let tx = db.unchecked_transaction().map_err(db_error)?;
    let tenant: String = tx.query_row("SELECT k.tenant_id FROM agent_access_keys k JOIN tenants t ON t.id=k.tenant_id WHERE k.token_digest=?1 AND t.enabled=1",
        [EnrollmentToken::digest(&input.token)], |r| r.get(0)).optional().map_err(db_error)?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED,"接入密钥无效或空间已停用"))?;
    let previous: Option<(Option<String>, String)> = tx.query_row("SELECT device_id,certificate_pem FROM agent_registrations WHERE tenant_id=?1 AND csr_pem=?2",
        params![tenant,csr], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(db_error)?;
    if let Some((device, certificate_pem)) = previous {
        let device_id = device.ok_or_else(|| {
            ApiError::new(StatusCode::CONFLICT, "此设备已删除，原注册申请不可再次使用")
        })?;
        // 只重发仍在使用的初始证书；恢复或续签后不能借旧 CSR 回滚设备身份。
        let fingerprint = identity_runtime::fingerprint(&certificate_pem).map_err(db_error)?;
        let current: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM device_identities WHERE device_id=?1 AND secret_digest=?2)", params![device_id,fingerprint], |r| r.get(0)).map_err(db_error)?;
        if !current {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "设备身份已更新，请使用现有数据目录或从设备详情恢复身份",
            ));
        }
        return Ok(Json(AgentRegistrationResponse {
            device_id,
            certificate_pem,
            ca_certificate_pem: state.authority.ca_pem(),
        }));
    }
    let device_id = Uuid::new_v4().to_string();
    let certificate_pem = state
        .authority
        .issue_device(csr, &device_id)
        .map_err(db_error)?;
    let fingerprint = identity_runtime::fingerprint(&certificate_pem).map_err(db_error)?;
    let name = if input.device_name.trim().is_empty() {
        "Nexo Agent"
    } else {
        input.device_name.trim()
    };
    tx.execute("INSERT INTO devices(id,tenant_id,name,os,architecture,agent_version,status,enrolled_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,'offline',?7,?7,?7)", params![device_id,tenant,name,input.os,input.architecture,input.agent_version,unix_now()]).map_err(db_error)?;
    tx.execute(
        "INSERT INTO device_identities(device_id,secret_digest,created_at) VALUES(?1,?2,?3)",
        params![device_id, fingerprint, unix_now()],
    )
    .map_err(db_error)?;
    tx.execute(
        "INSERT INTO device_certificates(device_id,certificate_pem) VALUES(?1,?2)",
        params![device_id, certificate_pem],
    )
    .map_err(db_error)?;
    tx.execute("INSERT INTO agent_registrations(tenant_id,csr_pem,device_id,certificate_pem,created_at) VALUES(?1,?2,?3,?4,?5)",params![tenant,csr,device_id,certificate_pem,unix_now()]).map_err(db_error)?;
    tx.execute("INSERT INTO audit_events(tenant_id,event_type,resource_type,resource_id,created_at) VALUES(?1,'agent_registered','device',?2,?3)",params![tenant,device_id,unix_now()]).map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(Json(AgentRegistrationResponse {
        device_id,
        certificate_pem,
        ca_certificate_pem: state.authority.ca_pem(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (AppState, HeaderMap) {
        let (mut state, headers) = crate::tests::domain_fixture();
        state.data_dir = std::env::temp_dir().join(format!("nexo-access-test-{}", Uuid::new_v4()));
        (state, headers)
    }
    fn registration(token: &str) -> AgentEnrollmentRequest {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::new(vec!["agent.nexo".into()])
            .unwrap()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        AgentEnrollmentRequest {
            token: token.into(),
            device_name: "同名设备".into(),
            os: Some("test".into()),
            architecture: None,
            agent_version: "test".into(),
            csr_pem: Some(csr),
        }
    }

    #[tokio::test]
    async fn shared_key_is_encrypted_reusable_and_scoped() {
        let (state, headers) = fixture();
        let first = ensure(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0;
        let second = ensure(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0;
        assert_eq!(first.token, second.token);
        let encrypted: Vec<u8> = state
            .db
            .lock()
            .unwrap()
            .query_row("SELECT encrypted_token FROM agent_access_keys", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(!encrypted
            .windows(first.token.len())
            .any(|v| v == first.token.as_bytes()));
        let (a, b) = tokio::join!(
            register(State(state.clone()), Json(registration(&first.token))),
            register(State(state.clone()), Json(registration(&first.token)))
        );
        assert_ne!(a.unwrap().0.device_id, b.unwrap().0.device_id);
        let db = state.db.lock().unwrap();
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM devices WHERE tenant_id='default'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
        db.execute(
            "INSERT INTO tenants(id,name,created_at) VALUES('other','other',0)",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO agent_access_keys SELECT 'other', 'different',encrypted_token,created_at,updated_at FROM agent_access_keys WHERE tenant_id='default'",[]).unwrap();
        assert!(read_key(&state, &db, "other").is_err()); // AEAD 附加数据防止空间间密文调包。
    }

    #[tokio::test]
    async fn registration_retry_and_deleted_identity_cannot_resurrect() {
        let (state, headers) = fixture();
        let token = ensure(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0
            .token;
        let input = registration(&token);
        let (a, b) = tokio::join!(
            register(State(state.clone()), Json(input.clone())),
            register(State(state.clone()), Json(input.clone()))
        );
        let a = a.unwrap().0;
        let b = b.unwrap().0;
        assert_eq!(a.device_id, b.device_id);
        assert_eq!(a.certificate_pem, b.certificate_pem);
        let _ = delete_device(State(state.clone()), headers, Path(a.device_id.clone()))
            .await
            .unwrap();
        assert_eq!(
            register(State(state.clone()), Json(input))
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        let new = register(State(state.clone()), Json(registration(&token)))
            .await
            .unwrap()
            .0;
        assert_ne!(a.device_id, new.device_id);
        let db = state.db.lock().unwrap();
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM agent_registrations WHERE device_id IS NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn reset_rejects_old_key_but_keeps_device_identity_and_disable_blocks_join() {
        let (state, headers) = fixture();
        let old = ensure(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0
            .token;
        let device = register(State(state.clone()), Json(registration(&old)))
            .await
            .unwrap()
            .0;
        let key = reset(State(state.clone()), headers).await.unwrap().0.token;
        assert_ne!(old, key);
        assert_eq!(
            register(State(state.clone()), Json(registration(&old)))
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
        {
            let db = state.db.lock().unwrap();
            identity_runtime::accept_certificate(
                &db,
                &device.device_id,
                &identity_runtime::fingerprint(&device.certificate_pem).unwrap(),
            )
            .unwrap();
            db.execute("UPDATE tenants SET enabled=0 WHERE id='default'", [])
                .unwrap();
        }
        assert_eq!(
            register(State(state.clone()), Json(registration(&key)))
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn key_reads_survive_backup_restore_and_missing_master_key_fails_closed() {
        let (state, headers) = fixture();
        let key = ensure(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0
            .token;
        let path = state.data_dir.join("secrets/agent-access.key");
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(get(State(state.clone()), headers.clone()).await.is_err());
        assert!(reset(State(state.clone()), headers.clone()).await.is_err());
        assert!(!path.exists());
        nexo_tunnel::identity::write_private_file(&path, &bytes).unwrap();
        assert_eq!(
            get(State(state.clone()), headers)
                .await
                .unwrap()
                .0
                .unwrap()
                .token,
            key
        );
    }

    #[tokio::test]
    async fn key_mutations_require_csrf_and_legacy_tokens_are_not_accepted() {
        let (state, mut headers) = fixture();
        headers.remove("x-nexo-csrf");
        assert_eq!(
            ensure(State(state.clone()), headers.clone())
                .await
                .err()
                .unwrap()
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            reset(State(state.clone()), headers)
                .await
                .err()
                .unwrap()
                .status,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            register(State(state), Json(registration("legacy-token")))
                .await
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn router_scopes_shared_keys_and_records_the_real_admin_actor() {
        let (state, admin) = fixture();
        let alice = accounts::tests::add_user(&state, "alice");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = router(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let own: serde_json::Value = client
            .post(format!("{url}/api/v1/agent-access-key"))
            .headers(alice.clone())
            .header("x-nexo-internal-workspace", "default")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let scoped = format!("{url}/api/v1/admin/workspaces/alice/agent-access-key");
        let managed: serde_json::Value = client
            .get(&scoped)
            .headers(admin.clone())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(own["token"], managed["token"]);
        assert_eq!(
            client
                .get(format!(
                    "{url}/api/v1/admin/workspaces/default/agent-access-key"
                ))
                .headers(alice)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let response = client
            .post(format!("{scoped}/reset"))
            .headers(admin)
            .send()
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let reset: serde_json::Value = response.error_for_status().unwrap().json().await.unwrap();
        assert_ne!(reset["token"], own["token"]);
        let db = state.db.lock().unwrap();
        let audit:(String,String)=db.query_row("SELECT actor_user_id,tenant_id FROM audit_events WHERE event_type='agent_access_key_reset'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(audit, ("u".into(), "alice".into()));
        db.execute("DELETE FROM tenants WHERE id='alice'", [])
            .unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM agent_access_keys", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        task.abort();
    }

    #[tokio::test]
    async fn dedicated_recovery_keeps_shared_device_binding_and_invalidates_registration_retry() {
        let (state, headers) = fixture();
        let key = ensure(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0
            .token;
        let original = registration(&key);
        let device = register(State(state.clone()), Json(original.clone()))
            .await
            .unwrap()
            .0;
        let invitation = enrollment::create_recovery(
            State(state.clone()),
            headers.clone(),
            Path(device.device_id.clone()),
        )
        .await
        .unwrap()
        .0;
        let _ = enrollment::agent_enroll(
            State(state.clone()),
            Json(registration(invitation.token.as_ref().unwrap())),
        )
        .await
        .unwrap();
        let recovered = enrollment::approve_enrollment(
            State(state.clone()),
            headers,
            Path(invitation.id),
            Json(ApproveEnrollment { device_name: None }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(
            recovered.device_id.as_deref(),
            Some(device.device_id.as_str())
        );
        assert_eq!(
            register(State(state.clone()), Json(original))
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
                .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
