//! One canonical node-file envelope. The discriminator and checksum are not
//! authentication: the caller supplies the expected installed identity before
//! redb may repair the recognized payload. Tenant authentication follows later.
use crate::private_files::{self, FileIdentity};
use anyhow::{Context, Result, ensure};
use parking_lot::RwLock;
use redb::StorageBackend;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

const HEADER_BYTES: usize = 4096;
const CHECKSUM_AT: usize = HEADER_BYTES - 32;
const MAGIC: &[u8; 16] = b"KASUMI-NODE-0001";
const PREPARED: u8 = 1;
const READY: u8 = 2;

#[derive(Clone, Copy)]
enum HeaderUse {
    Reopen,
    Cleanup,
}

/// Physical descriptor custody only. The caller must independently establish
/// permanent stop, issuer drain and worker/storage drain before deleting a file.
/// Retain this guard through exact unlink and parent directory synchronization.
pub struct NodeFileCleanup {
    _owner: Arc<NodeFile>,
    identity: FileIdentity,
}
impl NodeFileCleanup {
    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }
}

pub(crate) struct NodeFile {
    // Closing redb removes the actual descriptor even if an internal reader
    // retains its backend Arc. Already-running descriptor operations drain
    // under this lock before exclusive file ownership is released.
    file: RwLock<Option<File>>,
    parent: File,
    path: PathBuf,
    id: Uuid,
}

impl NodeFile {
    pub(crate) fn create_new(path: &Path, id: Uuid) -> Result<Arc<Self>> {
        ensure!(!id.is_nil(), "node store identity is nil");
        let file = options().create_new(true).open(path)?;
        let owner = Self::own(path, file, id)?;
        owner.prepare()?;
        Ok(owner)
    }

    pub(crate) fn initialize_owned_empty(
        path: &Path,
        identity: &FileIdentity,
        id: Uuid,
    ) -> Result<Arc<Self>> {
        ensure!(!id.is_nil(), "node store identity is nil");
        let owner = Self::own(path, options().open(path)?, id)?;
        {
            let guard = owner.file.read();
            let file = present(&guard)?;
            ensure!(
                &private_files::descriptor_identity(file)? == identity,
                "prepared node file identity differs"
            );
            ensure!(
                file.metadata()?.len() == 0,
                "prepared node file is not empty"
            );
        }
        owner.prepare()?;
        Ok(owner)
    }

    pub(crate) fn open_existing(path: &Path, expected_id: Uuid) -> Result<Arc<Self>> {
        ensure!(!expected_id.is_nil(), "node store identity is nil");
        let owner = Self::own(path, options().open(path)?, expected_id)?;
        {
            let guard = owner.file.read();
            let file = present(&guard)?;
            let length = file.metadata()?.len();
            ensure!(
                length > HEADER_BYTES as u64 && length <= i64::MAX as u64,
                "existing node payload length is invalid"
            );
            let mut bytes = [0; HEADER_BYTES];
            file.read_exact_at(&mut bytes, 0)?;
            validate_header(&bytes, expected_id, HeaderUse::Reopen)?;
        }
        Ok(owner)
    }

    pub(crate) fn claim_cleanup(path: &Path, expected_id: Uuid) -> Result<NodeFileCleanup> {
        ensure!(!expected_id.is_nil(), "node store identity is nil");
        let owner = Self::own(path, options().open(path)?, expected_id)?;
        let identity = {
            let guard = owner.file.read();
            let file = present(&guard)?;
            let length = file.metadata()?.len();
            ensure!(
                length >= HEADER_BYTES as u64 && length <= i64::MAX as u64,
                "node cleanup envelope length is invalid"
            );
            let mut bytes = [0; HEADER_BYTES];
            file.read_exact_at(&mut bytes, 0)?;
            validate_header(&bytes, expected_id, HeaderUse::Cleanup)?;
            private_files::descriptor_identity(file)?
        };
        Ok(NodeFileCleanup {
            _owner: owner,
            identity,
        })
    }

    fn own(path: &Path, file: File, id: Uuid) -> Result<Arc<Self>> {
        // No unsupported-lock fallback. Validation and every later payload I/O
        // use this one descriptor; no unlock/reopen handoff occurs.
        file.try_lock()
            .context("node file is already owned or cannot be locked")?;
        private_files::descriptor_identity(&file)?;
        let path = std::fs::canonicalize(path)?;
        ensure!(
            private_files::file_identity(&path)? == private_files::descriptor_identity(&file)?,
            "node file path changed while opening"
        );
        let parent = File::open(path.parent().context("node file parent is absent")?)?;
        Ok(Arc::new(Self {
            file: RwLock::new(Some(file)),
            parent,
            path,
            id,
        }))
    }

    fn prepare(&self) -> Result<()> {
        let guard = self.file.read();
        let file = present(&guard)?;
        ensure!(
            file.metadata()?.len() == 0,
            "node initialization requires an empty inode"
        );
        file.write_all_at(&header(self.id, PREPARED), 0)?;
        file.sync_all()?;
        self.parent.sync_all()?;
        Ok(())
    }

    pub(crate) fn publish_ready(&self) -> Result<()> {
        let guard = self.file.read();
        let file = present(&guard)?;
        ensure!(
            file.metadata()?.len() > HEADER_BYTES as u64,
            "node payload is absent"
        );
        // The initialized redb tables are durable before a ready discriminator
        // can authorize later recovery. A failure here is an uncertain create;
        // it never authorizes truncation, recreation, or adoption on retry.
        file.sync_all()?;
        file.write_all_at(&header(self.id, READY), 0)?;
        file.sync_all()?;
        self.parent.sync_all()?;
        Ok(())
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn backend(self: &Arc<Self>) -> NodeBackend {
        NodeBackend(self.clone())
    }
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
}

fn header(id: Uuid, state: u8) -> [u8; HEADER_BYTES] {
    let mut bytes = [0; HEADER_BYTES];
    bytes[..16].copy_from_slice(MAGIC);
    bytes[16..32].copy_from_slice(id.as_bytes());
    bytes[32] = state;
    let digest = Sha256::digest(&bytes[..CHECKSUM_AT]);
    bytes[CHECKSUM_AT..].copy_from_slice(&digest);
    bytes
}

fn validate_header(bytes: &[u8; HEADER_BYTES], expected: Uuid, use_for: HeaderUse) -> Result<()> {
    ensure!(&bytes[..16] == MAGIC, "unsupported node file format");
    ensure!(
        &bytes[16..32] == expected.as_bytes(),
        "installed node store identity differs"
    );
    ensure!(
        bytes[32] == READY || (matches!(use_for, HeaderUse::Cleanup) && bytes[32] == PREPARED),
        "node file initialization is incomplete or unsupported"
    );
    ensure!(
        bytes[33..CHECKSUM_AT].iter().all(|byte| *byte == 0),
        "unsupported node header fields"
    );
    ensure!(
        bytes[CHECKSUM_AT..] == Sha256::digest(&bytes[..CHECKSUM_AT])[..],
        "node header checksum differs"
    );
    Ok(())
}

fn present(file: &Option<File>) -> io::Result<&File> {
    file.as_ref()
        .ok_or_else(|| io::Error::other("node file is closed"))
}

fn physical_end(offset: u64, length: u64) -> io::Result<u64> {
    offset
        .checked_add(length)
        .and_then(|end| end.checked_add(HEADER_BYTES as u64))
        .filter(|end| *end <= i64::MAX as u64)
        .ok_or_else(|| io::Error::other("node payload offset exceeds supported file bounds"))
}

pub(crate) struct NodeBackend(Arc<NodeFile>);
impl std::fmt::Debug for NodeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeBackend")
            .field("id", &self.0.id)
            .finish_non_exhaustive()
    }
}
impl StorageBackend for NodeBackend {
    fn len(&self) -> io::Result<u64> {
        let guard = self.0.file.read();
        let length = present(&guard)?.metadata()?.len();
        if length > i64::MAX as u64 {
            return Err(io::Error::other("node file exceeds supported offsets"));
        }
        length
            .checked_sub(HEADER_BYTES as u64)
            .ok_or_else(|| io::Error::other("node header was truncated"))
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        physical_end(offset, u64::try_from(out.len()).map_err(io::Error::other)?)?;
        let guard = self.0.file.read();
        present(&guard)?.read_exact_at(out, physical_end(offset, 0)?)
    }

    fn set_len(&self, length: u64) -> io::Result<()> {
        let physical = physical_end(length, 0)?;
        let guard = self.0.file.read();
        present(&guard)?.set_len(physical)
    }

    fn sync_data(&self) -> io::Result<()> {
        let guard = self.0.file.read();
        present(&guard)?.sync_data()
    }

    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let end = physical_end(
            offset,
            u64::try_from(bytes.len()).map_err(io::Error::other)?,
        )?;
        let guard = self.0.file.read();
        let file = present(&guard)?;
        if end > file.metadata()?.len() {
            return Err(io::Error::other("node write exceeds the allocated payload"));
        }
        file.write_all_at(bytes, physical_end(offset, 0)?)
    }

    fn close(&self) -> io::Result<()> {
        drop(self.0.file.write().take());
        Ok(())
    }
}

#[cfg(test)]
mod tests;
