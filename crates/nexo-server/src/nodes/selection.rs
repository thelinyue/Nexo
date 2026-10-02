//! 自动选择依据 Agent 实测 RTT。健康切换优先；延迟优化需有稳定样本、最小改善和驻留时间。
use super::*;
#[derive(Clone, Debug)]
pub struct Candidate {
    pub id: String,
    pub address: String,
    pub latency: Option<u32>,
}
pub fn choose<'a>(
    mode: &str,
    preferred: Option<&str>,
    current: Option<(&str, i64)>,
    now: i64,
    candidates: &'a [Candidate],
) -> Option<(&'a Candidate, &'static str)> {
    if candidates.is_empty() {
        return None;
    }
    let active = current.and_then(|(id, _)| candidates.iter().find(|n| n.id == id));
    if mode == "manual" {
        if let Some(selected) = candidates.iter().find(|n| Some(n.id.as_str()) == preferred) {
            return Some((selected, "手动首选节点健康"));
        }
    }
    let best = candidates
        .iter()
        .min_by_key(|n| (n.latency.unwrap_or(u32::MAX), &n.id))
        .unwrap();
    let Some(active) = active else {
        return Some((best, "原节点不可用，切换健康备用节点"));
    };
    if mode == "manual" {
        return Some((active, "首选节点不可用，保持健康备用节点"));
    }
    if let (Some(best_rtt), Some(current_rtt)) = (best.latency, active.latency) {
        if current.is_some_and(|(_, at)| now - at >= 60)
            && best_rtt.saturating_add(10) <= current_rtt
            && u64::from(best_rtt) * 100 <= u64::from(current_rtt) * 80
        {
            return Some((best, "设备延迟持续改善，切换低延迟节点"));
        }
    } else if best.latency.is_some()
        && active.latency.is_none()
        && current.is_some_and(|(_, at)| now - at >= 60)
    {
        return Some((best, "选择具有有效延迟测量的节点"));
    }
    Some((active, "保持当前健康节点，避免频繁切换"))
}
pub fn select(state: &AppState, id: &str, candidates: Vec<Candidate>) -> Result<Vec<Candidate>> {
    let db = state
        .db
        .lock()
        .map_err(|_| anyhow::anyhow!("数据库锁不可用"))?;
    let (mode, preferred): (String, Option<String>) = db.query_row(
        "SELECT distribution_mode,preferred_node_id FROM tunnels WHERE id=?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if !matches!(mode.as_str(), "latency" | "manual") {
        return Ok(candidates);
    }
    let current: Option<(String, i64)> = db
        .query_row(
            "SELECT node_id,selected_at FROM relay_selection WHERE service_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let selected = choose(
        &mode,
        preferred.as_deref(),
        current.as_ref().map(|(id, at)| (id.as_str(), *at)),
        unix_now(),
        &candidates,
    );
    if let Some((node, reason)) = selected {
        if mode == "latency"
            && current
                .as_ref()
                .is_some_and(|(id, _)| id != &node.id && candidates.iter().any(|n| &n.id == id))
        {
            let sampled:i64=db.query_row("SELECT COALESCE(MAX(l.checked_at),0) FROM relay_latency l JOIN tunnels t ON t.device_id=l.device_id WHERE t.id=?1 AND l.node_id=?2",params![id,node.id],|r|r.get(0))?;
            db.execute("INSERT INTO relay_selection_pending VALUES(?1,?2,1,?3) ON CONFLICT(service_id) DO UPDATE SET samples=CASE WHEN node_id!=excluded.node_id THEN 1 WHEN checked_at<excluded.checked_at THEN samples+1 ELSE samples END,node_id=excluded.node_id,checked_at=excluded.checked_at",params![id,node.id,sampled])?;
            let streak: i64 = db.query_row(
                "SELECT samples FROM relay_selection_pending WHERE service_id=?1",
                [id],
                |r| r.get(0),
            )?;
            if streak < 3 {
                let active = candidates
                    .iter()
                    .find(|n| Some(&n.id) == current.as_ref().map(|(id, _)| id))
                    .unwrap();
                return Ok(vec![active.clone()]);
            }
        }
        db.execute(
            "DELETE FROM relay_selection_pending WHERE service_id=?1",
            [id],
        )?;
        db.execute("INSERT INTO relay_selection VALUES(?1,?2,?3,?4) ON CONFLICT(service_id) DO UPDATE SET selected_at=CASE WHEN node_id!=excluded.node_id THEN excluded.selected_at ELSE selected_at END,node_id=excluded.node_id,reason=excluded.reason",params![id,node.id,unix_now(),reason])?;
        return Ok(vec![node.clone()]);
    }
    Ok(vec![])
}
#[cfg(test)]
mod tests {
    use super::*;
    fn nodes() -> Vec<Candidate> {
        vec![
            Candidate {
                id: "a".into(),
                address: "1".into(),
                latency: Some(100),
            },
            Candidate {
                id: "b".into(),
                address: "2".into(),
                latency: Some(40),
            },
        ]
    }
    #[test]
    fn latency_waits_for_dwell_and_manual_restores_primary() {
        let n = nodes();
        assert_eq!(
            choose("latency", None, Some(("a", 100)), 140, &n)
                .unwrap()
                .0
                .id,
            "a"
        );
        assert_eq!(
            choose("latency", None, Some(("a", 100)), 160, &n)
                .unwrap()
                .0
                .id,
            "b"
        );
        assert_eq!(
            choose("manual", Some("a"), Some(("b", 100)), 110, &n)
                .unwrap()
                .0
                .id,
            "a"
        );
        assert_eq!(
            choose("manual", Some("a"), Some(("a", 100)), 110, &n[1..])
                .unwrap()
                .0
                .id,
            "b"
        );
    }
    #[test]
    fn latency_switch_counts_distinct_samples_not_repeated_reconciliation() {
        let (state, _) = crate::tests::domain_fixture();
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO devices(id,tenant_id,name,created_at,updated_at) VALUES('agent','default','NAS',0,0)",[]).unwrap();
            db.execute(
                "INSERT INTO relay_nodes(id,name,created_at) VALUES('b','b',0)",
                [],
            )
            .unwrap();
            db.execute("INSERT INTO tunnels(id,tenant_id,device_id,name,protocol,local_address,local_port,distribution_mode,created_at,updated_at) VALUES('s','default','agent','s','tcp','127.0.0.1',80,'latency',0,0)",[]).unwrap();
            db.execute(
                "INSERT INTO relay_selection VALUES('s','a',?1,'existing')",
                [unix_now() - 120],
            )
            .unwrap();
            db.execute("INSERT INTO relay_latency(device_id,node_id,rtt_ms,checked_at) VALUES('agent','b',40,?1)",[unix_now()]).unwrap();
        }
        for _ in 0..4 {
            assert_eq!(select(&state, "s", nodes()).unwrap()[0].id, "a");
        }
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE relay_latency SET checked_at=checked_at+1", [])
            .unwrap();
        assert_eq!(select(&state, "s", nodes()).unwrap()[0].id, "a");
        state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE relay_latency SET checked_at=checked_at+1", [])
            .unwrap();
        assert_eq!(select(&state, "s", nodes()).unwrap()[0].id, "b");
        assert_eq!(
            select(&state, "s", vec![nodes()[0].clone()]).unwrap()[0].id,
            "a",
            "当前节点故障必须立即选择健康备用，不能等待优化驻留期"
        );
    }

    #[test]
    fn small_improvements_do_not_flap() {
        let mut n = nodes();
        n[1].latency = Some(95);
        assert_eq!(
            choose("latency", None, Some(("a", 0)), 200, &n)
                .unwrap()
                .0
                .id,
            "a"
        );
        assert!(choose("latency", None, None, 200, &[]).is_none());
    }
}
