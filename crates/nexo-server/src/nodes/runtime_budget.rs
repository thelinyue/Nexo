//! 节点本机两条业务路径共用预算泵；每次成功写入才消耗，取消时 Drop 提交最终累计量。
//! 预算只保存在当前连接内，不写回本机磁盘；控制器已持久化的未结算占用不会因重启消失。
use super::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

struct Grant {
    id: String,
    remaining: u64,
    origin: u64,
    public: u64,
    reports: mpsc::UnboundedSender<wire::Request>,
}
impl Drop for Grant {
    fn drop(&mut self) {
        let _ = self.reports.send(wire::Request::Usage {
            grant_id: self.id.clone(),
            to_origin: self.origin,
            to_public: self.public,
            finished: true,
        });
    }
}

async fn acquire(runtime: &Runtime, service: &wire::Service, q: &wire::NodeQuota) -> Result<Grant> {
    let reports = runtime
        .usage
        .lock()
        .await
        .clone()
        .context("节点流量结算通道不可用")?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let (reply, receive) = tokio::sync::oneshot::channel();
            let sender = runtime
                .access
                .lock()
                .await
                .clone()
                .context("节点额度控制通道不可用")?;
            sender
                .send(Access {
                    request: wire::Request::Budget {
                        request_id: 0,
                        service_id: service.id.clone(),
                        service_revision: service.revision,
                        quota_revision: q.revision,
                        month: q.period_start,
                        bytes: 256 * 1024,
                    },
                    reply,
                })
                .await?;
            let wire::Response::Budget {
                grant_id, bytes, ..
            } = receive.await?
            else {
                anyhow::bail!("节点预算响应无效");
            };
            if bytes > 0 {
                return Ok(Grant {
                    id: grant_id,
                    remaining: bytes,
                    origin: 0,
                    public: 0,
                    reports,
                });
            }
            // 另一个方向或连接可能正在归还预算。零可用不等于实际耗尽，不能提前断流。
            // 真正耗尽、策略变更和撤权由 copy 的快照监听取消；失联占用则限时失败。
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("节点流量预算暂不可用，转发已停止")?
}

/// 每方向最多预留 256 KiB；空闲 250 ms 归还，流式下载和 WebSocket 不需要整包缓存。
async fn pump<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut read: R,
    mut write: W,
    runtime: &Runtime,
    service: &wire::Service,
    q: &wire::NodeQuota,
    to_origin: bool,
) -> Result<()> {
    let mut buffer = [0u8; 16384];
    let mut grant: Option<Grant> = None;
    loop {
        let n = tokio::select! {
            result=read.read(&mut buffer)=>result?,
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
                grant = Some(acquire(runtime, service, q).await?);
            }
            let credit = grant.as_mut().unwrap();
            let count = (n - offset).min(credit.remaining as usize);
            let written = write.write(&buffer[offset..offset + count]).await?;
            anyhow::ensure!(written > 0, "节点计量转发写入中断");
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

/// 服务、额度修订或月份变化立即取消旧流；预留占满只拒绝新的预算，不取消有效预算。
pub(super) async fn copy<A: AsyncRead + AsyncWrite + Unpin, B: AsyncRead + AsyncWrite + Unpin>(
    public: &mut A,
    origin: &mut B,
    runtime: Arc<Runtime>,
    service: &wire::Service,
) -> Result<()> {
    let mut snapshot = runtime.snapshot.subscribe();
    let initial = snapshot.borrow().clone();
    anyhow::ensure!(initial.services.contains(service), "节点服务授权已撤销");
    let quota = initial.traffic_quota.clone();
    let invalidated = async {
        loop {
            if let Some(q) = &quota {
                let wait = (q.period_end - unix_now()).max(0) as u64;
                tokio::select! {result=snapshot.changed()=>result?,_=tokio::time::sleep(Duration::from_secs(wait))=>return anyhow::Ok(())}
            } else {
                snapshot.changed().await?;
            }
            let next = snapshot.borrow_and_update();
            if !next.services.contains(service) || next.traffic_quota != quota {
                return Ok(());
            }
        }
    };
    let transfer = async {
        if let Some(q) = &quota {
            anyhow::ensure!(!q.exhausted, "节点本月流量额度已用尽");
            let (public_read, public_write) = tokio::io::split(public);
            let (origin_read, origin_write) = tokio::io::split(origin);
            tokio::try_join!(
                pump(public_read, origin_write, &runtime, service, q, true),
                pump(origin_read, public_write, &runtime, service, q, false)
            )?;
        } else {
            tokio::io::copy_bidirectional(public, origin).await?;
        }
        anyhow::Ok(())
    };
    tokio::select! {result=transfer=>result,result=invalidated=>{result?;anyhow::bail!("节点流量策略或服务授权已更新，关闭旧连接")}}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    /// 首次 Pending 不消耗预算，之后只成功写入两个字节，再模拟网络失败。
    struct PartialWriter(usize);
    impl AsyncWrite for PartialWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0 += 1;
            match self.0 {
                1 => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                2 => Poll::Ready(Ok(buf.len().min(2))),
                _ => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "测试连接失败",
                ))),
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn pending_partial_and_failed_writes_only_charge_successful_bytes_in_both_directions() {
        let service:wire::Service=serde_json::from_value(json!({"id":"s","tenant":"default","device":"agent","revision":1,"protocol":"http","port":0,"https_port":443,"access_mode":"public","http_redirect":false})).unwrap();
        let (snapshot, _) = watch::channel(Snapshot {
            services: vec![service.clone()],
            accepting: true,
            ..Default::default()
        });
        let runtime = Arc::new(Runtime {
            snapshot,
            sessions: Default::default(),
            connections: Default::default(),
            health: Default::default(),
            access: Default::default(),
            usage: Default::default(),
            configured: AtomicBool::new(false),
            stop: CancellationToken::new(),
            caddy: Default::default(),
        });
        let (state, controller) = super::super::tests::attach_meter(&runtime, &service).await;
        let q = runtime.snapshot.borrow().traffic_quota.clone().unwrap();
        let (a, b) = tokio::join!(
            pump(
                std::io::Cursor::new(b"hello"),
                PartialWriter(0),
                &runtime,
                &service,
                &q,
                true
            ),
            pump(
                std::io::Cursor::new(b"world"),
                PartialWriter(0),
                &runtime,
                &service,
                &q,
                false
            )
        );
        assert!(a.is_err() && b.is_err());
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let view = super::super::super::quota::view(
                    &state.db.lock().unwrap(),
                    "metered",
                    unix_now(),
                )
                .unwrap();
                if view.reserved_bytes == 0 && view.used_bytes == 4 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        controller.abort();
    }
}
