//! 每条授权逻辑流独立压缩，明文长度限制同时约束解码和配额计量。
use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{self as tokio_io, AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};
use tokio_util::{
    codec::{Decoder, Encoder, FramedRead, FramedWrite},
    io::{CopyToBytes, SinkWriter, StreamReader},
};

pub const ALPN: &[u8] = b"nexo-stream-deflate-v1";
const BLOCK: usize = 16 * 1024;
const HEADER: usize = 4;

/// 使用两个大端长度区分原始块与独立 DEFLATE 块。压缩收益不足时直接发送原始块。
#[derive(Default)]
struct Encode {
    compressor: Option<Compress>,
    scratch: Vec<u8>,
}

impl Encoder<Bytes> for Encode {
    type Error = io::Error;

    fn encode(&mut self, plain: Bytes, output: &mut BytesMut) -> io::Result<()> {
        if plain.is_empty() {
            return Ok(());
        }
        if plain.len() > BLOCK {
            return Err(invalid_block());
        }
        let mut body = plain.as_ref();
        if plain.len() >= 64 {
            let compressor = self
                .compressor
                .get_or_insert_with(|| Compress::new(Compression::fast(), false));
            compressor.reset();
            self.scratch.resize(plain.len() - 1, 0);
            if compressor
                .compress(&plain, &mut self.scratch, FlushCompress::Finish)
                .map_err(io::Error::other)?
                == Status::StreamEnd
            {
                body = &self.scratch[..compressor.total_out() as usize];
            }
        }
        output.reserve(HEADER + body.len());
        output.put_u16(body.len() as u16);
        output.put_u16(plain.len() as u16);
        output.extend_from_slice(body);
        Ok(())
    }
}

#[derive(Default)]
struct Decode(Option<Decompress>);

impl Decoder for Decode {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, input: &mut BytesMut) -> io::Result<Option<Bytes>> {
        if input.len() < HEADER {
            return Ok(None);
        }
        let mut lengths = &input[..HEADER];
        let size = lengths.get_u16() as usize;
        let expected = lengths.get_u16() as usize;
        if size == 0 || size > expected || expected > BLOCK {
            return Err(invalid_block());
        }
        if input.len() < HEADER + size {
            return Ok(None);
        }
        input.advance(HEADER);
        let body = input.split_to(size).freeze();
        if size == expected {
            return Ok(Some(body));
        }
        let decoder = self.0.get_or_insert_with(|| Decompress::new(false));
        decoder.reset(false);
        let mut plain = vec![0; expected + 1];
        let status = decoder
            .decompress(&body, &mut plain, FlushDecompress::Finish)
            .map_err(|_| invalid_block())?;
        if status != Status::StreamEnd
            || decoder.total_in() as usize != size
            || decoder.total_out() as usize != expected
        {
            return Err(invalid_block());
        }
        plain.truncate(expected);
        Ok(Some(plain.into()))
    }
}

fn invalid_block() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "隧道压缩数据块无效")
}

type Reader<S> = StreamReader<FramedRead<ReadHalf<S>, Decode>, Bytes>;
type Writer<S> = SinkWriter<CopyToBytes<FramedWrite<WriteHalf<S>, Encode>>>;
type Framed<S> = tokio_io::Join<Reader<S>, Writer<S>>;

enum Stream<S> {
    Plain(S),
    Compressed(Box<Framed<S>>),
}

pub fn wrap<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    compressed: bool,
) -> impl AsyncRead + AsyncWrite + Unpin {
    if compressed {
        let (read, write) = tokio_io::split(stream);
        Stream::Compressed(Box::new(tokio_io::join(
            StreamReader::new(FramedRead::new(read, Decode::default())),
            SinkWriter::new(CopyToBytes::new(FramedWrite::new(write, Encode::default()))),
        )))
    } else {
        Stream::Plain(stream)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Compressed(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Compressed(stream) => {
                Pin::new(stream).poll_write(cx, &buf[..buf.len().min(BLOCK)])
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Compressed(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Compressed(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn compresses_repeated_data_and_rejects_invalid_frames() {
        let mut encoder = Encode::default();
        let mut decoder = Decode::default();
        let mut wire = BytesMut::new();
        let repeated = Bytes::from(vec![b'z'; BLOCK]);
        encoder.encode(repeated.clone(), &mut wire).unwrap();
        assert!(wire.len() < BLOCK / 10);
        let mut partial = wire.split_to(HEADER);
        assert!(decoder.decode(&mut partial).unwrap().is_none());
        partial.unsplit(wire);
        assert_eq!(decoder.decode(&mut partial).unwrap(), Some(repeated));
        assert!(partial.is_empty());

        let plain = Bytes::from((0..128).collect::<Vec<u8>>());
        encoder.encode(plain.clone(), &mut partial).unwrap();
        assert_eq!(partial.len(), HEADER + plain.len());
        assert_eq!(decoder.decode(&mut partial).unwrap(), Some(plain));

        let mut oversized = BytesMut::from(&[0, 1, 0xff, 0xff][..]);
        assert_eq!(
            decoder.decode(&mut oversized).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut corrupt = BytesMut::from(&[0, 1, 0, 2, 0xff][..]);
        assert_eq!(
            decoder.decode(&mut corrupt).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn small_responses_flush_and_half_close_preserves_the_other_direction() {
        for compressed in [false, true] {
            let (left, right) = tokio_io::duplex(512);
            let mut left = wrap(left, compressed);
            let mut right = wrap(right, compressed);
            let payload = vec![42; BLOCK + 10];
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                tokio::join!(
                    async {
                        left.write_all(&payload).await.unwrap();
                        left.flush().await.unwrap();
                        let mut response = [0; 4];
                        left.read_exact(&mut response).await.unwrap();
                        assert_eq!(&response, b"pong");
                        left.shutdown().await.unwrap();
                        assert_eq!(left.read_u8().await.unwrap(), 7);
                    },
                    async {
                        let mut received = vec![0; payload.len()];
                        right.read_exact(&mut received).await.unwrap();
                        assert_eq!(received, payload);
                        right.write_all(b"pong").await.unwrap();
                        right.flush().await.unwrap();
                        assert_eq!(right.read(&mut received).await.unwrap(), 0);
                        right.write_u8(7).await.unwrap();
                        right.shutdown().await.unwrap();
                    }
                );
            })
            .await
            .unwrap();
        }
    }
}
