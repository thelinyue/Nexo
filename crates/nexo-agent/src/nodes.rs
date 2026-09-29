//! 每个 VPS 使用独立重连任务和服务子集。父管理通道退出时 JoinSet 取消全部远端数据连接。
use super::*;
use std::collections::HashMap;

pub async fn run(
    connectors: watch::Receiver<TlsConnector>,
    mut desired: watch::Receiver<Desired>,
    budget: node_budget::Client,
) {
    let mut sessions: HashMap<String, (watch::Sender<Desired>, tokio::task::AbortHandle)> =
        HashMap::new();
    let mut tasks = JoinSet::new();
    loop {
        let snapshot = desired.borrow_and_update().clone();
        sessions.retain(|id, (_, task)| {
            if snapshot.nodes.iter().any(|n| &n.id == id) {
                true
            } else {
                task.abort();
                false
            }
        });
        for node in &snapshot.nodes {
            let next = Desired {
                endpoint: node.endpoint.clone(),
                udp_endpoint: None,
                nodes: vec![],
                tunnels: snapshot
                    .tunnels
                    .iter()
                    .filter(|t| node.service_ids.contains(&t.tunnel_id))
                    .cloned()
                    .collect(),
            };
            if let Some((sender, _)) = sessions.get(&node.id) {
                sender.send_if_modified(|v| {
                    if *v != next {
                        *v = next;
                        true
                    } else {
                        false
                    }
                });
            } else {
                let (sender, receiver) = watch::channel(next);
                let task = tasks.spawn(run_data(
                    connectors.clone(),
                    receiver,
                    Some((budget.clone(), node.id.clone())),
                ));
                sessions.insert(node.id.clone(), (sender, task));
            }
        }
        tokio::select! {
            change=desired.changed()=>if change.is_err(){return;},
            Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if let Err(error)=result{if !error.is_cancelled(){tracing::error!("节点连接任务异常：{error}");}}}
        }
    }
}
