use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 测试上游回显原始 HTTP 请求；WebSocket 握手后解码一帧并返回，验证真实升级后的双向通道。
pub(crate) async fn echo_origin<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    label: &str,
) -> anyhow::Result<()> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await?);
    }
    let request = String::from_utf8(head)?;
    if request.to_ascii_lowercase().contains("upgrade: websocket") {
        stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await?;
        let opcode = stream.read_u8().await?;
        let length = stream.read_u8().await?;
        let mut mask = [0; 4];
        stream.read_exact(&mut mask).await?;
        let mut payload = vec![0; usize::from(length & 127)];
        stream.read_exact(&mut payload).await?;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        stream.write_all(&[opcode, payload.len() as u8]).await?;
        stream.write_all(&payload).await?;
    } else {
        let length = request
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .and_then(|s| s.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await?;
        let response = format!("{label}\n{request}{}", String::from_utf8_lossy(&body));
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                )
                .as_bytes(),
            )
            .await?;
    }
    stream.shutdown().await?;
    Ok(())
}
