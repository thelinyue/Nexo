//! 应用图标只是服务展示元数据；仅允许内置 HD-Icons 目录中的相对路径。
//! 区分省略与 null，确保旧客户端和批量换设备不会清除用户已选图标。

use crate::*;
use std::{collections::HashSet, sync::OnceLock};

pub fn deserialize<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(Some)
}

pub fn migrate(db: &Connection) -> Result<()> {
    if !db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('tunnels') WHERE name='icon_id')",
        [],
        |row| row.get::<_, bool>(0),
    )? {
        db.execute("ALTER TABLE tunnels ADD COLUMN icon_id TEXT", [])?;
    }
    Ok(())
}

pub fn save(db: &Connection, tenant: &str, id: &str, input: &TunnelInput) -> Result<(), ApiError> {
    let Some(icon) = &input.icon_id else {
        return Ok(());
    };
    static CATALOG: OnceLock<HashSet<String>> = OnceLock::new();
    let catalog = CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../../../web/src/data/hd-icons.json"))
            .expect("内置应用图标目录格式错误")
    });
    if icon.as_ref().is_some_and(|icon| !catalog.contains(icon)) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "请选择图标目录中的应用图标",
        ));
    }
    db.execute(
        "UPDATE tunnels SET icon_id=?1 WHERE id=?2 AND tenant_id=?3 AND deleted_at IS NULL",
        params![icon, id, tenant],
    )
    .map_err(db_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn input(icon: Option<serde_json::Value>) -> TunnelInput {
        let mut value = json!({"service_mode":"reverse_proxy","name":"Emby","protocol":"http","origin_protocol":"http","local_address":"127.0.0.1","local_port":8096,"hostname":"emby","public_domain_id":"domain"});
        if let Some(icon) = icon {
            value["icon_id"] = icon;
        }
        serde_json::from_value(value).unwrap()
    }

    fn fixture() -> (AppState, HeaderMap) {
        let (state, headers) = crate::tests::domain_fixture();
        state.db.lock().unwrap().execute_batch("INSERT INTO public_domains(id,tenant_id,domain,https_enabled,created_at,updated_at) VALUES('domain','default','example.com',0,0,0); INSERT INTO domain_settings(domain_id,verification_token,certificate_mode,verified) VALUES('domain','proof','http01',1);").unwrap();
        (state, headers)
    }

    #[test]
    fn existing_database_migration_preserves_services_and_is_repeatable() {
        let db = Connection::open_in_memory().unwrap();
        initialize_database(&db, true).unwrap();
        db.execute("ALTER TABLE tunnels DROP COLUMN icon_id", [])
            .unwrap();
        db.execute("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,created_at,updated_at) VALUES('old','default','旧服务','tcp','127.0.0.1',80,0,0)", []).unwrap();
        initialize_database(&db, false).unwrap();
        initialize_database(&db, false).unwrap();
        let (name, icon): (String, Option<String>) = db
            .query_row("SELECT name,icon_id FROM tunnels WHERE id='old'", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(name, "旧服务");
        assert_eq!(icon, None);
    }

    #[tokio::test]
    async fn icon_round_trip_omission_reset_and_invalid_update_rollback() {
        let (state, headers) = fixture();
        let Json(created) = create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(input(Some(json!("border-radius/emby-1.png")))),
        )
        .await
        .unwrap();
        assert_eq!(created.icon_id.as_deref(), Some("border-radius/emby-1.png"));
        let Json(list) = list_tunnels(State(state.clone()), headers.clone())
            .await
            .unwrap();
        assert_eq!(list[0].icon_id, created.icon_id);
        let mut old_client = input(None);
        old_client.local_port = 8097;
        let Json(updated) = update_tunnel(
            State(state.clone()),
            headers.clone(),
            Path(created.id.clone()),
            Json(old_client),
        )
        .await
        .unwrap();
        assert_eq!(updated.icon_id, created.icon_id);
        for invalid in [
            "https://example.com/icon.svg",
            "../emby.png",
            "border-radius/missing.png",
        ] {
            assert_eq!(
                update_tunnel(
                    State(state.clone()),
                    headers.clone(),
                    Path(created.id.clone()),
                    Json(input(Some(json!(invalid))))
                )
                .await
                .unwrap_err()
                .status,
                StatusCode::BAD_REQUEST
            );
            let Json(list) = list_tunnels(State(state.clone()), headers.clone())
                .await
                .unwrap();
            assert_eq!(list[0].icon_id, created.icon_id);
            assert_eq!(list[0].local_port, 8097);
        }
        let Json(reset) = update_tunnel(
            State(state.clone()),
            headers,
            Path(created.id),
            Json(input(Some(serde_json::Value::Null))),
        )
        .await
        .unwrap();
        assert_eq!(reset.icon_id, None);
    }

    #[tokio::test]
    async fn invalid_create_rolls_back_and_icon_writes_require_ownership_and_csrf() {
        let (state, headers) = fixture();
        assert_eq!(
            create_tunnel(
                State(state.clone()),
                headers.clone(),
                Json(input(Some(json!("invalid"))))
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::BAD_REQUEST
        );
        assert!(list_tunnels(State(state.clone()), headers.clone())
            .await
            .unwrap()
            .0
            .is_empty());
        let Json(created) = create_tunnel(State(state.clone()), headers.clone(), Json(input(None)))
            .await
            .unwrap();
        let mut no_csrf = headers.clone();
        no_csrf.remove("x-nexo-csrf");
        assert_eq!(
            update_tunnel(
                State(state.clone()),
                no_csrf,
                Path(created.id.clone()),
                Json(input(Some(json!("border-radius/emby-1.png"))))
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::FORBIDDEN
        );
        state
            .db
            .lock()
            .unwrap()
            .execute_batch(
                "INSERT INTO tenants(id,name,created_at) VALUES('foreign','其他空间',0);",
            )
            .unwrap();
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "UPDATE tunnels SET tenant_id='foreign' WHERE id=?1",
                [&created.id],
            )
            .unwrap();
        assert_eq!(
            update_tunnel(
                State(state.clone()),
                headers,
                Path(created.id.clone()),
                Json(input(Some(json!("border-radius/emby-1.png"))))
            )
            .await
            .unwrap_err()
            .status,
            StatusCode::NOT_FOUND
        );
        let icon: Option<String> = state
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT icon_id FROM tunnels WHERE id=?1",
                [&created.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(icon, None);
    }
}
