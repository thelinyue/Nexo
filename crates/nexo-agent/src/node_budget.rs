//! 节点数据在 Agent 端扣减中央预留预算，不信任 VPS 自报流量。预算不能跨逻辑流重用。
use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot},
};
pub struct Request {
    pub node: String,
    pub service: String,
    pub revision: i64,
    pub bytes: u32,
    pub reply: oneshot::Sender<(String, u64)>,
}
#[derive(Clone)]
pub struct Client {
    pub requests: mpsc::Sender<Request>,
    pub reports: mpsc::UnboundedSender<AgentControlMessage>,
}
struct Grant {
    id: String,
    remaining: u64,
    origin: u64,
    public: u64,
    client: Client,
}
impl Drop for Grant {
    fn drop(&mut self) {
        let _ = self.client.reports.send(AgentControlMessage::NodeUsage {
            grant_id: self.id.clone(),
            to_origin: self.origin,
            to_public: self.public,
            finished: true,
        });
    }
}
impl Grant {
    async fn acquire(
        client: &Client,
        node: &str,
        tunnel: &TunnelDesiredState,
        bytes: u32,
    ) -> Result<Self> {
        let (reply, receive) = oneshot::channel();
        client
            .requests
            .send(Request {
                node: node.into(),
                service: tunnel.tunnel_id.clone(),
                revision: tunnel.revision,
                bytes,
                reply,
            })
            .await?;
        let (id, bytes) = tokio::time::timeout(Duration::from_secs(15), receive).await??;
        anyhow::ensure!(bytes > 0, "工作空间转发额度已用尽或节点授权已撤销");
        Ok(Self {
            id,
            remaining: bytes,
            origin: 0,
            public: 0,
            client: client.clone(),
        })
    }
}
/// 每个方向持有至多 256 KiB 的预算，避免每个 16 KiB 数据块都等待控制器往返。
/// 空闲 250 ms 即归还未消费部分；取消时 Drop 仍按累计成功写入结算。
async fn pump<R, W>(
    mut read: R,
    mut write: W,
    client: &Client,
    node: &str,
    tunnel: &TunnelDesiredState,
    to_origin: bool,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16384];
    let mut grant: Option<Grant> = None;
    loop {
        let n = tokio::select! {
            value=read.read(&mut buffer)=>value?,
            _=tokio::time::sleep(Duration::from_millis(250)),if grant.is_some()=>{grant.take();continue;}
        };
        if n == 0 {
            write.shutdown().await?;
            return Ok(());
        }
        let mut offset = 0;
        while offset < n {
            if grant.as_ref().is_none_or(|g| g.remaining == 0) {
                grant.take();
                grant = Some(Grant::acquire(client, node, tunnel, 256 * 1024).await?);
            }
            let credit = grant.as_mut().unwrap();
            let count = (n - offset).min(credit.remaining as usize);
            let written = write.write(&buffer[offset..offset + count]).await?;
            anyhow::ensure!(written > 0, "节点转发写入中断");
            credit.remaining -= written as u64;
            if to_origin {
                credit.origin += written as u64;
            } else {
                credit.public += written as u64;
            }
            offset += written;
        }
    }
}
pub async fn copy<A, B>(
    local: &mut A,
    stream: &mut B,
    client: Client,
    node: &str,
    tunnel: &TunnelDesiredState,
) -> Result<()>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + ?Sized,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (local_read, local_write) = tokio::io::split(local);
    let (remote_read, remote_write) = tokio::io::split(stream);
    tokio::try_join!(
        pump(remote_read, local_write, &client, node, tunnel, true),
        pump(local_read, remote_write, &client, node, tunnel, false)
    )?;
    Ok(())
}
