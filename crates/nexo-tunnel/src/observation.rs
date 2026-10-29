//! 不改变流的背压、半关闭和取消语义，仅在成功写入后更新会话观测。
use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub type Session = Arc<Mutex<nexo_core::telemetry::Session>>;
pub struct Observed<T> {
    io: T,
    session: Option<Session>,
    origin: bool,
}
impl<T> Observed<T> {
    pub fn new(io: T, session: Option<Session>, origin: bool) -> Self {
        Self {
            io,
            session,
            origin,
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for Observed<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Observed<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            if let Some(session) = &self.session {
                session
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .record(self.origin, n);
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
pub fn finish(session: &Option<Session>, reason: &str) {
    if let Some(s) = session {
        s.lock().unwrap_or_else(|e| e.into_inner()).finish(reason);
    }
}
