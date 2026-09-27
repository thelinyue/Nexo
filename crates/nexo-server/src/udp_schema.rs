//! 原地扩展现有表，保留认证字段、子表和撤销触发器，不修改历史安装脚本。
use anyhow::{Context, Result};
use rusqlite::Connection;

pub fn initialize(db: &Connection) -> Result<()> {
    let sql: String = db.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='tunnels'",
        [],
        |r| r.get(0),
    )?;
    if !sql.contains("'udp'") {
        let updated = sql.replace(
            "('tcp','http','https')",
            "('tcp','http','https','udp','tcp_udp')",
        );
        anyhow::ensure!(updated != sql, "无法识别服务协议约束，停止升级以保留原数据");
        let create = updated.replacen(
            "CREATE TABLE tunnels",
            "CREATE TABLE tunnels_udp_upgrade",
            1,
        );
        anyhow::ensure!(create != updated, "无法识别服务表定义");
        let objects=db.prepare("SELECT sql FROM sqlite_schema WHERE tbl_name='tunnels' AND type IN ('index','trigger') AND sql IS NOT NULL AND name!='idx_tunnels_public_port'")?.query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        // SQLite 在事务内不允许切换外键；关闭仅限启动迁移窗口，退出无论成功失败都恢复。
        db.pragma_update(None, "foreign_keys", "OFF")?;
        let result = (|| -> Result<()> {
            let tx = db.unchecked_transaction()?;
            tx.execute_batch(&create)?;
            tx.execute_batch("INSERT INTO tunnels_udp_upgrade SELECT * FROM tunnels; DROP TABLE tunnels; ALTER TABLE tunnels_udp_upgrade RENAME TO tunnels;")?;
            for object in objects {
                tx.execute_batch(&object)?;
            }
            tx.execute_batch("CREATE UNIQUE INDEX idx_tunnels_tcp_port ON tunnels(public_port) WHERE deleted_at IS NULL AND public_port IS NOT NULL AND protocol IN ('tcp','tcp_udp'); CREATE UNIQUE INDEX idx_tunnels_udp_port ON tunnels(public_port) WHERE deleted_at IS NULL AND public_port IS NOT NULL AND protocol IN ('udp','tcp_udp');")?;
            let invalid: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
                [],
                |r| r.get(0),
            )?;
            anyhow::ensure!(!invalid, "UDP 升级外键检查失败，已回滚");
            tx.commit()?;
            Ok(())
        })();
        db.pragma_update(None, "foreign_keys", "ON")?;
        result.context("UDP 服务数据升级失败")?;
    }
    for table in ["tunnels", "tunnel_applied_states"] {
        let exists:bool=db.query_row(&format!("SELECT EXISTS(SELECT 1 FROM pragma_table_info('{table}') WHERE name='protocol_statuses')"),[],|r|r.get(0))?;
        if !exists {
            db.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN protocol_statuses TEXT NOT NULL DEFAULT '{{}}'"
            ))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_upgrade_rolls_back_and_restores_foreign_keys() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!("../../../migrations/v0.2.0_baseline.sql"))
            .unwrap();
        db.pragma_update(None, "foreign_keys", "OFF").unwrap();
        db.execute_batch("INSERT INTO tunnel_applied_states VALUES('missing',1,'ready',NULL,0)")
            .unwrap();
        assert!(initialize(&db).is_err());
        let sql: String = db
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE name='tunnels'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!sql.contains("'udp'"));
        assert_eq!(
            db.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='idx_tunnels_public_port'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn service_api_allocates_per_protocol_and_rejects_overlap() {
        use crate::*;
        use serde_json::json;
        let (state, headers) = crate::tests::domain_fixture();
        let input = |protocol: &str, port: Option<u16>| {
            serde_json::from_value(json!({"name":protocol,"protocol":protocol,"local_address":"127.0.0.1","local_port":3389,"public_port":port})).unwrap()
        };
        let tcp = create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(input("tcp", None)),
        )
        .await
        .unwrap()
        .0;
        let udp = create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(input("udp", tcp.public_port)),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(tcp.public_port, udp.public_port);
        assert!(udp.origin_protocol.is_none());
        let err = create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(input("tcp_udp", tcp.public_port)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status, StatusCode::CONFLICT);
        let combined = create_tunnel(
            State(state.clone()),
            headers.clone(),
            Json(input("tcp_udp", None)),
        )
        .await
        .unwrap()
        .0;
        assert_ne!(combined.public_port, tcp.public_port);
        for protocol in ["tcp", "udp"] {
            assert_eq!(
                create_tunnel(
                    State(state.clone()),
                    headers.clone(),
                    Json(input(protocol, combined.public_port))
                )
                .await
                .unwrap_err()
                .status,
                StatusCode::CONFLICT
            );
        }
        state.tunnel_runtime.shutdown().await;
    }
    #[test]
    fn upgrade_preserves_children_columns_and_triggers() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(include_str!("../../../migrations/v0.2.0_baseline.sql"))
            .unwrap();
        crate::service_access::initialize_schema(&db).unwrap();
        db.execute_batch("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,public_port,created_at,updated_at) VALUES('t','default','ssh','tcp','localhost',22,20022,0,0); INSERT INTO tunnel_applied_states VALUES('t',1,'ready',NULL,0); INSERT INTO service_access_sessions VALUES('s','t',100);").unwrap();
        initialize(&db).unwrap();
        initialize(&db).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM service_access_sessions", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM tunnel_applied_states", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        db.execute_batch("INSERT INTO tunnels(id,tenant_id,name,protocol,local_address,local_port,public_port,created_at,updated_at) VALUES('u','default','udp','udp','localhost',22,20022,0,0);").unwrap();
        assert!(db
            .execute("UPDATE tunnels SET protocol='tcp_udp' WHERE id='u'", [])
            .is_err());
        db.execute("UPDATE tunnels SET enabled=0 WHERE id='t'", [])
            .unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM service_access_sessions", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
