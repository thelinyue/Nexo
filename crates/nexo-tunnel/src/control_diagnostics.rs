//! 两端共用的控制通道诊断，不改变心跳、超时或重连行为。

use std::fmt;

use anyhow::Result;
use serde::Serialize;
use tokio::{io::AsyncWrite, time::Instant};

/// 只记录完整消息的收发，不保存含证书或凭据的正文。
/// UTC 时间用于跨主机对照，单调时钟用于计算间隔，避免系统校时干扰。
/// 发送成功仅指本地写入及 flush 完成，不代表对端已接收或处理。
#[derive(Default)]
pub struct ControlDiagnostics {
    sent: Activity,
    received: Activity,
}

#[derive(Default)]
struct Activity {
    last: Option<(time::OffsetDateTime, Instant)>,
    count: u64,
}

impl Activity {
    fn record(&mut self) {
        self.last = Some((time::OffsetDateTime::now_utc(), Instant::now()));
        self.count += 1;
    }
}

impl fmt::Display for Activity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.last {
            Some((at, instant)) => write!(
                f,
                "{at}，距今 {} 毫秒，累计 {} 条",
                instant.elapsed().as_millis(),
                self.count
            ),
            None => f.write_str("无，累计 0 条"),
        }
    }
}

impl ControlDiagnostics {
    pub fn received(&mut self) {
        self.received.record();
    }

    /// 失败或被取消的写入不覆盖最后一次成功发送记录。
    pub async fn send<W: AsyncWrite + Unpin, T: Serialize>(
        &mut self,
        writer: &mut W,
        value: &T,
    ) -> Result<()> {
        crate::identity::write_message(writer, value).await?;
        self.sent.record();
        Ok(())
    }
}

impl fmt::Display for ControlDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "最后接收：[{}]；最后发送：[{}]",
            self.received, self.sent
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn buffered_write_with_failed_flush_is_not_counted_as_sent() {
        let mut diagnostics = ControlDiagnostics::default();
        let (writer, reader) = tokio::io::duplex(128);
        let mut writer = tokio::io::BufWriter::new(writer);
        drop(reader);
        assert!(diagnostics.send(&mut writer, &"heartbeat").await.is_err());
        assert!(diagnostics.sent.last.is_none());
        assert_eq!(diagnostics.sent.count, 0);
    }

    #[tokio::test]
    async fn failed_send_preserves_last_success_and_diagnostics_never_include_payload() {
        let mut diagnostics = ControlDiagnostics::default();
        assert_eq!(
            diagnostics.to_string(),
            "最后接收：[无，累计 0 条]；最后发送：[无，累计 0 条]"
        );
        let (mut writer, mut reader) = tokio::io::duplex(128);
        diagnostics
            .send(&mut writer, &"private-certificate")
            .await
            .unwrap();
        let mut bytes = [0; 22];
        reader.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"\"private-certificate\"\n");
        let sent = diagnostics.sent.last;
        drop(reader);
        assert!(diagnostics
            .send(&mut writer, &"secret-token")
            .await
            .is_err());
        assert_eq!(diagnostics.sent.last, sent);
        assert_eq!(diagnostics.sent.count, 1);
        diagnostics.received();
        assert_eq!(diagnostics.received.count, 1);
        let output = diagnostics.to_string();
        assert!(output.contains("距今"));
        assert!(!output.contains("private-certificate"));
        assert!(!output.contains("secret-token"));
    }
}
