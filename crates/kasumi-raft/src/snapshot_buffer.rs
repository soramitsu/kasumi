use std::{
    io::{self, Cursor, SeekFrom},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

/// In-memory snapshot transfer with a hard per-group byte cap, including seeks.
/// This prevents a peer from growing a snapshot indefinitely through small chunks.
#[derive(Debug)]
pub struct SnapshotBuffer {
    cursor: Cursor<Vec<u8>>,
    limit: u64,
}

impl SnapshotBuffer {
    pub fn new(limit: u64) -> Self {
        Self {
            cursor: Cursor::new(Vec::new()),
            limit,
        }
    }

    pub fn from_bytes(bytes: Vec<u8>, limit: u64) -> io::Result<Self> {
        if bytes.len() as u64 > limit {
            return Err(io::Error::other("snapshot exceeds byte limit"));
        }
        Ok(Self {
            cursor: Cursor::new(bytes),
            limit,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.cursor.get_ref()
    }
}

impl AsyncRead for SnapshotBuffer {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.cursor).poll_read(cx, buf)
    }
}

impl AsyncWrite for SnapshotBuffer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self
            .cursor
            .position()
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.limit)
        {
            return Poll::Ready(Err(io::Error::other("snapshot exceeds byte limit")));
        }
        Pin::new(&mut self.cursor).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.cursor).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.cursor).poll_shutdown(cx)
    }
}

impl AsyncSeek for SnapshotBuffer {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let position = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.cursor.position()) + i128::from(offset),
            SeekFrom::End(offset) => self.cursor.get_ref().len() as i128 + i128::from(offset),
        };
        if position < 0 || position > i128::from(self.limit) {
            return Err(io::Error::other("snapshot seek outside byte limit"));
        }
        self.cursor.set_position(position as u64);
        Ok(())
    }
    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.cursor.position()))
    }
}
