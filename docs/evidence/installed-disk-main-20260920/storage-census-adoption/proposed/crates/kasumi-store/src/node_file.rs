//! One canonical node-file envelope. The discriminator and checksum are not
//! authentication: the caller supplies the expected installed identity before
//! redb may repair the recognized payload. Tenant authentication follows later.
use crate::{DiskWork, NodeDisk, NodeDiskFile, private_files::FileIdentity};
use anyhow::{Result, ensure};
use parking_lot::RwLock;
use redb::{AdmissionError, OwnerFailed, StorageAdmission, StorageBackend};
use sha2::{Digest, Sha256};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

const HEADER_BYTES: usize = 4096;
const CHECKSUM_AT: usize = HEADER_BYTES - 32;
const MAGIC: &[u8; 16] = b"KASUMI-NODE-0001";
const PREPARED: u8 = 1;
const READY: u8 = 2;

#[cfg(test)]
type AfterWriteCheck = Box<dyn FnOnce() + Send>;

#[derive(Clone, Copy)]
enum HeaderUse {
    Reopen,
    Cleanup,
}

/// Physical descriptor custody only. The caller must independently establish
/// permanent stop, issuer drain and worker/storage drain before deleting a file.
/// Retain this guard through exact unlink and parent directory synchronization.
pub struct NodeFileCleanup {
    owner: Arc<NodeFile>,
    identity: FileIdentity,
}
impl NodeFileCleanup {
    pub fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    /// Delete only this recognized, exclusively owned physical file. The
    /// installed owner verifies the binding, unlinks it and syncs the parent
    /// before returning any capacity. Authorization and worker drain are the
    /// caller's independent prerequisites.
    pub fn delete(self) -> Result<()> {
        let owner = Arc::try_unwrap(self.owner)
            .map_err(|_| anyhow::anyhow!("node cleanup owner is still retained"))?;
        let file = owner
            .file
            .into_inner()
            .ok_or_else(|| anyhow::anyhow!("node cleanup descriptor is closed"))?;
        Ok(owner.disk.delete_file(file)?)
    }
}

pub(crate) struct NodeFile {
    // Closing redb removes the actual descriptor even if an internal reader
    // retains its backend Arc. Already-running descriptor operations drain
    // under this lock before exclusive file ownership is released.
    file: RwLock<Option<NodeDiskFile>>,
    disk: Arc<NodeDisk>,
    path: PathBuf,
    id: Uuid,
    #[cfg(test)]
    after_write_check: parking_lot::Mutex<Option<AfterWriteCheck>>,
}

impl NodeFile {
    /// Concrete backing charged by the fixed storage registration before this
    /// prepared NodeFile and its path/backend allocations are constructed.
    pub(crate) fn prepared_backing_bytes(path: &Path) -> io::Result<u64> {
        use crate::disk_memory::{add, allocation, arc};
        add(
            add(
                arc::<Self>()?,
                allocation::<u8>(
                    u64::try_from(path.as_os_str().len())
                        .map_err(|_| io::ErrorKind::InvalidInput)?,
                )?,
            )?,
            allocation::<NodeBackend>(1)?,
        )
    }

    /// Allocation only. The exact empty descriptor owner is published in the
    /// storage census before `acquire_prepared` may perform any filesystem I/O.
    pub(crate) fn retained_prepared(path: &Path, id: Uuid, disk: Arc<NodeDisk>) -> Arc<Self> {
        Arc::new(Self {
            file: RwLock::new(None),
            disk,
            path: path.to_owned(),
            id,
            #[cfg(test)]
            after_write_check: Default::default(),
        })
    }

    pub(crate) fn acquire_prepared(
        &self,
        mode: &crate::storage_opening::NodeOpeningMode,
    ) -> Result<()> {
        use crate::storage_opening::NodeOpeningMode;
        ensure!(!self.id.is_nil(), "node store identity is nil");
        let (root, relative) = self.disk.binding(&self.path)?;
        let file = match mode {
            NodeOpeningMode::Create => {
                self.disk
                    .create_file(root, relative, DiskWork::Foreground)?
            }
            NodeOpeningMode::OwnedEmpty(_) | NodeOpeningMode::Existing => {
                self.disk.open_file(root, relative)?
            }
        };
        // No validation, callback or envelope operation precedes actual custody.
        *self.file.write() = Some(file);
        {
            let guard = self.file.read();
            let file = present(&guard)?;
            file.check_owner()?;
            match mode {
                NodeOpeningMode::OwnedEmpty(identity) => {
                    ensure!(
                        &file.identity()? == identity,
                        "prepared node file identity differs"
                    );
                    ensure!(file.observed_len()? == 0, "prepared node file is not empty");
                }
                NodeOpeningMode::Existing => {
                    let length = file.observed_len()?;
                    ensure!(
                        length > HEADER_BYTES as u64 && length <= i64::MAX as u64,
                        "existing node payload length is invalid"
                    );
                    let mut bytes = [0; HEADER_BYTES];
                    file.read_exact_at(&mut bytes, 0)?;
                    validate_header(&bytes, self.id, HeaderUse::Reopen)?;
                }
                NodeOpeningMode::Create => {}
            }
        }
        if !matches!(mode, NodeOpeningMode::Existing) {
            self.prepare()?;
        }
        Ok(())
    }
    pub(crate) fn create_new(path: &Path, id: Uuid, disk: Arc<NodeDisk>) -> Result<Arc<Self>> {
        ensure!(!id.is_nil(), "node store identity is nil");
        let (root, relative) = disk.binding(path)?;
        let file = disk.create_file(root, relative, DiskWork::Foreground)?;
        let owner = Self::own(path, file, id, disk)?;
        owner.prepare()?;
        Ok(owner)
    }

    pub(crate) fn initialize_owned_empty(
        path: &Path,
        identity: &FileIdentity,
        id: Uuid,
        disk: Arc<NodeDisk>,
    ) -> Result<Arc<Self>> {
        ensure!(!id.is_nil(), "node store identity is nil");
        let (root, relative) = disk.binding(path)?;
        let owner = Self::own(path, disk.open_file(root, relative)?, id, disk)?;
        {
            let guard = owner.file.read();
            let file = present(&guard)?;
            ensure!(
                &file.identity()? == identity,
                "prepared node file identity differs"
            );
            ensure!(file.observed_len()? == 0, "prepared node file is not empty");
        }
        owner.prepare()?;
        Ok(owner)
    }

    pub(crate) fn open_existing(
        path: &Path,
        expected_id: Uuid,
        disk: Arc<NodeDisk>,
    ) -> Result<Arc<Self>> {
        ensure!(!expected_id.is_nil(), "node store identity is nil");
        let (root, relative) = disk.binding(path)?;
        let owner = Self::own(path, disk.open_file(root, relative)?, expected_id, disk)?;
        {
            let guard = owner.file.read();
            let file = present(&guard)?;
            let length = file.observed_len()?;
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

    pub(crate) fn claim_cleanup(
        path: &Path,
        expected_id: Uuid,
        disk: Arc<NodeDisk>,
    ) -> Result<NodeFileCleanup> {
        ensure!(!expected_id.is_nil(), "node store identity is nil");
        let (root, relative) = disk.binding(path)?;
        let owner = Self::own(path, disk.open_file(root, relative)?, expected_id, disk)?;
        let identity = {
            let guard = owner.file.read();
            let file = present(&guard)?;
            let length = file.observed_len()?;
            ensure!(
                length >= HEADER_BYTES as u64 && length <= i64::MAX as u64,
                "node cleanup envelope length is invalid"
            );
            let mut bytes = [0; HEADER_BYTES];
            file.read_exact_at(&mut bytes, 0)?;
            validate_header(&bytes, expected_id, HeaderUse::Cleanup)?;
            file.identity()?
        };
        Ok(NodeFileCleanup { owner, identity })
    }

    fn own(path: &Path, file: NodeDiskFile, id: Uuid, disk: Arc<NodeDisk>) -> Result<Arc<Self>> {
        // NodeDisk acquired this exact descriptor and every current ancestor.
        // Envelope validation and all redb I/O retain that same physical owner.
        file.check_owner()?;
        Ok(Arc::new(Self {
            file: RwLock::new(Some(file)),
            disk,
            path: path.to_owned(),
            id,
            #[cfg(test)]
            after_write_check: Default::default(),
        }))
    }

    fn prepare(&self) -> Result<()> {
        let guard = self.file.read();
        let file = present(&guard)?;
        ensure!(
            file.observed_len()? == 0,
            "node initialization requires an empty inode"
        );
        file.reserve_growth(0, HEADER_BYTES as u64, DiskWork::Foreground)?;
        file.grow_reserved(HEADER_BYTES as u64)?;
        file.write_all_at(&header(self.id, PREPARED), 0)?;
        file.sync_all_and_parent()?;
        Ok(())
    }

    pub(crate) fn publish_ready(&self) -> Result<()> {
        let guard = self.file.read();
        let file = present(&guard)?;
        ensure!(
            file.observed_len()? > HEADER_BYTES as u64,
            "node payload is absent"
        );
        // The initialized redb tables are durable before a ready discriminator
        // can authorize later recovery. A failure here is an uncertain create;
        // it never authorizes truncation, recreation, or adoption on retry.
        file.sync_all()?;
        file.write_all_at(&header(self.id, READY), 0)?;
        file.sync_all_and_parent()?;
        Ok(())
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn disk(&self) -> &Arc<NodeDisk> {
        &self.disk
    }

    pub(crate) fn backend(self: &Arc<Self>) -> NodeBackend {
        NodeBackend(self.clone())
    }
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

fn present(file: &Option<NodeDiskFile>) -> io::Result<&NodeDiskFile> {
    file.as_ref()
        .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
}

fn physical_end(offset: u64, length: u64) -> io::Result<u64> {
    offset
        .checked_add(length)
        .and_then(|end| end.checked_add(HEADER_BYTES as u64))
        .filter(|end| *end <= i64::MAX as u64)
        .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}

pub(crate) struct NodeBackend(Arc<NodeFile>);
impl std::fmt::Debug for NodeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeFile")
            .field("id", &self.id)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl StorageAdmission for NodeFile {
    fn check_owner(&self) -> std::result::Result<(), OwnerFailed> {
        let guard = self.file.read();
        present(&guard)
            .and_then(NodeDiskFile::check_owner)
            .map_err(|_| OwnerFailed)
    }

    fn reserve_growth(
        &self,
        current_len: u64,
        requested_len: u64,
    ) -> std::result::Result<(), AdmissionError> {
        let outcome = (|| -> io::Result<()> {
            let current = physical_end(current_len, 0)?;
            let requested = physical_end(requested_len, 0)?;
            let guard = self.file.read();
            present(&guard)?.reserve_growth(current, requested, DiskWork::Foreground)
        })();
        match outcome {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::StorageFull => {
                Err(AdmissionError::CapacityDenied)
            }
            Err(_) => {
                self.disk.fail();
                Err(AdmissionError::OwnerFailed)
            }
        }
    }

    fn settle_growth(&self, actual_len: u64) -> std::result::Result<(), OwnerFailed> {
        let outcome = (|| -> io::Result<()> {
            let actual = physical_end(actual_len, 0)?;
            let guard = self.file.read();
            present(&guard)?.settle_growth(actual)
        })();
        outcome.map_err(|_| {
            self.disk.fail();
            OwnerFailed
        })
    }

    fn owner_failed(&self) {
        self.disk.fail();
    }
}

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
        let length = present(&guard)?.observed_len()?;
        if length > i64::MAX as u64 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        length
            .checked_sub(HEADER_BYTES as u64)
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let end = physical_end(offset, out.len() as u64)?;
        let guard = self.0.file.read();
        let file = present(&guard)?;
        // read_exact_at accepts empty buffers beyond EOF; the backend contract
        // requires the complete range check even when no bytes are requested.
        if end > file.observed_len()? {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        file.read_exact_at(out, physical_end(offset, 0)?)
    }

    fn set_len(&self, length: u64) -> io::Result<()> {
        let physical = physical_end(length, 0)?;
        // Drain checked reads/writes before changing their admitted extent. A
        // shared lock permits shrink between a write's range check and pwrite,
        // after which that write can silently extend the truncated payload.
        let mut guard = self.0.file.write();
        let file = guard.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        let current = file.observed_len()?;
        if physical < current {
            // redb has already made the reduced extent's winning header
            // durable. Complete the retained promise accounting before the
            // exclusive, synchronized physical shrink credits any bytes.
            file.settle_growth(current)?;
            file.shrink(physical)
        } else {
            file.grow_reserved(physical)
        }
    }

    fn sync_data(&self) -> io::Result<()> {
        let guard = self.0.file.read();
        present(&guard)?.sync_all()
    }

    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let end = physical_end(offset, bytes.len() as u64)?;
        let guard = self.0.file.read();
        let file = present(&guard)?;
        if end > file.observed_len()? {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        #[cfg(test)]
        if let Some(pause) = self.0.after_write_check.lock().take() {
            pause();
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
