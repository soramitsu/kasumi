use kasumi_store::{EncryptedSpool, SnapshotImage};
use std::{
    future::Future,
    io::{self, Read, Seek, SeekFrom, Write},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

const WORKSPACE: usize = 64 << 10;
#[derive(Debug)]
enum Backing {
    Receiving(EncryptedSpool),
    Captured(SnapshotImage),
}
#[derive(Debug)]
enum Pending {
    Read(tokio::task::JoinHandle<io::Result<Vec<u8>>>),
    Write(tokio::task::JoinHandle<io::Result<usize>>),
    Flush(tokio::task::JoinHandle<io::Result<()>>),
}

/// Encrypted transfer storage. Each disk/crypto task owns at most 64 KiB of
/// transfer workspace; no filesystem operation blocks the async executor.
#[derive(Debug)]
pub struct SnapshotBuffer {
    backing: Arc<Mutex<Backing>>,
    length: Arc<AtomicU64>,
    limit: u64,
    position: u64,
    pending: Option<Pending>,
}
impl SnapshotBuffer {
    pub fn new(disk: &Arc<kasumi_store::ScratchDisk>, limit: u64) -> io::Result<Self> {
        Ok(Self {
            backing: Arc::new(Mutex::new(Backing::Receiving(EncryptedSpool::new(
                disk, limit,
            )?))),
            length: Arc::new(AtomicU64::new(0)),
            limit,
            position: 0,
            pending: None,
        })
    }
    pub fn from_image(image: SnapshotImage) -> Self {
        Self {
            length: Arc::new(AtomicU64::new(image.len())),
            limit: image.len(),
            backing: Arc::new(Mutex::new(Backing::Captured(image))),
            position: 0,
            pending: None,
        }
    }
    pub fn from_bytes(
        disk: &Arc<kasumi_store::ScratchDisk>,
        bytes: Vec<u8>,
        limit: u64,
    ) -> io::Result<Self> {
        if bytes.len() as u64 > limit {
            return Err(io::Error::other("snapshot exceeds byte limit"));
        }
        Ok(Self::from_image(
            SnapshotImage::from_bytes(disk, &bytes).map_err(io::Error::other)?,
        ))
    }
    pub fn len(&self) -> u64 {
        self.length.load(Ordering::Acquire)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn into_image(self) -> anyhow::Result<SnapshotImage> {
        anyhow::ensure!(
            self.pending.is_none(),
            "snapshot transfer work has not drained"
        );
        let backing = Arc::try_unwrap(self.backing)
            .map_err(|_| anyhow::anyhow!("snapshot still has a worker"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("snapshot storage poisoned"))?;
        match backing {
            Backing::Receiving(spool) => SnapshotImage::freeze(spool),
            Backing::Captured(image) => Ok(image),
        }
    }
    pub(crate) fn image(&self) -> anyhow::Result<SnapshotImage> {
        match &*self
            .backing
            .lock()
            .map_err(|_| anyhow::anyhow!("snapshot storage poisoned"))?
        {
            Backing::Captured(image) => Ok(image.clone()),
            _ => anyhow::bail!("receiving snapshot is not frozen"),
        }
    }
}
fn joined<T>(result: Result<io::Result<T>, tokio::task::JoinError>) -> io::Result<T> {
    result.map_err(io::Error::other)?
}
impl AsyncRead for SnapshotBuffer {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pending.is_none() {
            if buffer.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            let count = buffer.remaining().min(WORKSPACE);
            let backing = self.backing.clone();
            let position = self.position;
            self.pending = Some(Pending::Read(tokio::task::spawn_blocking(move || {
                let mut bytes = vec![0; count];
                let count = match &mut *backing
                    .lock()
                    .map_err(|_| io::Error::other("snapshot storage poisoned"))?
                {
                    Backing::Receiving(spool) => {
                        spool.seek(SeekFrom::Start(position))?;
                        spool.read(&mut bytes)?
                    }
                    Backing::Captured(image) => {
                        let mut reader = image.reader();
                        reader.seek(SeekFrom::Start(position))?;
                        reader.read(&mut bytes)?
                    }
                };
                bytes.truncate(count);
                Ok(bytes)
            })));
        }
        let Some(Pending::Read(task)) = &mut self.pending else {
            return Poll::Ready(Err(io::Error::other("snapshot operation still pending")));
        };
        match Pin::new(task).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                let bytes = joined(result)?;
                let count = bytes.len().min(buffer.remaining());
                buffer.put_slice(&bytes[..count]);
                self.position += count as u64;
                Poll::Ready(Ok(()))
            }
        }
    }
}
impl AsyncWrite for SnapshotBuffer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending.is_none() {
            if self
                .position
                .checked_add(bytes.len() as u64)
                .is_none_or(|n| n > self.limit)
            {
                return Poll::Ready(Err(io::Error::other("snapshot exceeds byte limit")));
            }
            let bytes = bytes[..bytes.len().min(WORKSPACE)].to_vec();
            let backing = self.backing.clone();
            let position = self.position;
            let length = self.length.clone();
            self.pending = Some(Pending::Write(tokio::task::spawn_blocking(move || {
                let mut backing = backing
                    .lock()
                    .map_err(|_| io::Error::other("snapshot storage poisoned"))?;
                let Backing::Receiving(spool) = &mut *backing else {
                    return Err(io::Error::other("captured snapshot is immutable"));
                };
                spool.seek(SeekFrom::Start(position))?;
                let count = spool.write(&bytes)?;
                length.store(spool.len(), Ordering::Release);
                Ok(count)
            })));
        }
        let Some(Pending::Write(task)) = &mut self.pending else {
            return Poll::Ready(Err(io::Error::other("snapshot operation still pending")));
        };
        match Pin::new(task).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                let count = joined(result)?;
                self.position += count as u64;
                Poll::Ready(Ok(count))
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending.is_none() {
            let backing = self.backing.clone();
            self.pending =
                Some(Pending::Flush(tokio::task::spawn_blocking(
                    move || match &mut *backing
                        .lock()
                        .map_err(|_| io::Error::other("snapshot storage poisoned"))?
                    {
                        Backing::Receiving(spool) => spool.flush(),
                        _ => Ok(()),
                    },
                )));
        }
        let Some(Pending::Flush(task)) = &mut self.pending else {
            return Poll::Ready(Err(io::Error::other("snapshot operation still pending")));
        };
        match Pin::new(task).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                Poll::Ready(joined(result))
            }
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
impl AsyncSeek for SnapshotBuffer {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        if self.pending.is_some() {
            return Err(io::Error::other("snapshot operation still pending"));
        }
        let position = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.len()) {
            return Err(io::Error::other("snapshot seek outside existing stream"));
        }
        self.position = position as u64;
        Ok(())
    }
    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.position))
    }
}
