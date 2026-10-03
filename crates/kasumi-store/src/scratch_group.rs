//! Bounded, anonymous encrypted files for one ephemeral native KV group.
//!
//! Names exist only in this admitted directory. Every physical file owns its
//! own random encryption key and exact ScratchDisk extent charge; no plaintext
//! root, directory page, key or value is written to a temporary pathname.

use crate::{DiskMemoryLease, EncryptedSpool, RetainedSpool, ScratchDisk};
use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, BackendNativeDisposition, FileKind, GroupFile,
    OwnerFailed, ROOT_FILE_NAME, ROOT_SLOT_BYTES, RootSlot, SegmentGroupBackend, StorageAdmission,
};
use std::ffi::OsStr;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};

// Anonymous files cannot be closed and later reopened. A fixed descriptor
// ceiling is therefore part of this scratch owner, independent of row count.
pub(super) const MAX_FILES: usize = 256;
const FILE_MEMORY_BYTES: u64 = (2 * crate::spool::NATIVE_BLOCK) as u64
    + 40
    + 3 * crate::disk_memory::ALLOCATION_ALLOWANCE
    + 32;

struct FileOwner {
    file: Option<GroupFile>,
    spool: RetainedSpool,
    // The key and both crypto buffers retire before their resident credit.
    _memory: DiskMemoryLease,
}

struct State {
    disk: Arc<ScratchDisk>,
    limit: u64,
    root: Option<FileOwner>,
    files: [Option<FileOwner>; MAX_FILES],
    // A census releases the state lock around caller code. This monotonic
    // witness detects all namespace changes, including same-slot/name reuse.
    namespace_epoch: u64,
    failed: bool,
    close_entered: bool,
    transaction: Option<claim::GroupTransaction>,
}

impl State {
    fn check(&mut self) -> io::Result<()> {
        if self.failed || self.close_entered {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.root
            .as_mut()
            .and_then(|root| root.spool.spool())
            .ok_or(io::ErrorKind::BrokenPipe)?
            .check_owner()
    }

    fn fail(&mut self) {
        self.failed = true;
        if let Some(spool) = self.root.as_mut().and_then(|root| root.spool.spool()) {
            spool.owner_failed();
        }
        for file in self.files.iter_mut().flatten() {
            if let Some(spool) = file.spool.spool() {
                spool.owner_failed();
            }
        }
    }

    fn total(&mut self) -> io::Result<u64> {
        let mut bytes = self
            .root
            .as_mut()
            .and_then(|root| root.spool.spool())
            .ok_or(io::ErrorKind::BrokenPipe)?
            .len();
        for file in self.files.iter_mut().flatten() {
            let spool = file.spool.spool().ok_or(io::ErrorKind::BrokenPipe)?;
            bytes = bytes
                .checked_add(spool.len())
                .ok_or(io::ErrorKind::StorageFull)?;
        }
        Ok(bytes)
    }

    fn position(&self, file: GroupFile) -> io::Result<usize> {
        self.files
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.file == Some(file)))
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    fn spool(&mut self, file: GroupFile) -> io::Result<&mut EncryptedSpool> {
        let index = self.position(file)?;
        self.files[index]
            .as_mut()
            .and_then(|entry| entry.spool.spool())
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }

    fn admit_length(&mut self, old: u64, new: u64) -> io::Result<()> {
        let total = self.total()?;
        if total
            .checked_sub(old)
            .and_then(|n| n.checked_add(new))
            .is_none_or(|n| n > self.limit)
        {
            return Err(io::ErrorKind::StorageFull.into());
        }
        Ok(())
    }

    fn close(
        &mut self,
        root_sync: impl FnOnce(&mut EncryptedSpool) -> io::Result<()>,
    ) -> BackendCloseOutcome {
        if self.close_entered {
            return BackendCloseOutcome::retained(io::ErrorKind::BrokenPipe.into());
        }
        if self
            .transaction
            .as_ref()
            .is_some_and(|transaction| transaction.entered)
        {
            return BackendCloseOutcome::retained(io::ErrorKind::BrokenPipe.into());
        }
        if self.transaction.is_some()
            && let Err(error) = self.cancel_pristine()
        {
            self.fail();
            return BackendCloseOutcome::retained(error);
        }
        self.close_entered = true;
        if let Some(root) = self.root.as_mut() {
            let outcome = root.spool.close_with(root_sync);
            if outcome.native_disposition() != BackendNativeDisposition::Drained {
                return outcome;
            }
            drop(self.root.take());
        }
        for slot in &mut self.files {
            if let Some(file) = slot.as_mut() {
                let outcome = file.spool.close();
                if outcome.native_disposition() != BackendNativeDisposition::Drained {
                    return outcome;
                }
                drop(slot.take());
            }
        }
        BackendCloseOutcome::drained(Ok(()))
    }
}

pub(crate) struct Owner {
    state: Mutex<Option<State>>,
    // Closing files does not deallocate the retained Arc or its fixed slots.
    // Keep that charge until this exact owner itself retires.
    memory: Option<DiskMemoryLease>,
    admission: Arc<dyn crate::NodeDiskMemoryAdmission>,
}

impl std::fmt::Debug for Owner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("encrypted scratch group owner")
    }
}

impl Owner {
    pub(crate) fn new(disk: &Arc<ScratchDisk>, limit: u64) -> io::Result<Arc<Self>> {
        if limit < (2 * ROOT_SLOT_BYTES) as u64 {
            return Err(io::ErrorKind::StorageFull.into());
        }
        let memory = disk
            .memory()
            .clone()
            .reserve_installed(crate::disk_memory::add(
                crate::disk_memory::arc::<Self>()?,
                crate::disk_memory::add(
                    64 << 10, // serialized spool resize zero-fill workspace
                    crate::disk_memory::add(
                        crate::disk_memory::size::<claim::GroupTransaction>()?,
                        crate::disk_memory::arc::<super::ScratchTableDatabase>()?,
                    )?,
                )?, // prepared claim plus the one enclosing scratch table facade
            )?)?;
        let root = Self::file(disk, limit, None)?;
        Ok(Arc::new(Self {
            state: Mutex::new(Some(State {
                disk: disk.clone(),
                limit,
                root: Some(root),
                files: [const { None }; MAX_FILES],
                namespace_epoch: 0,
                failed: false,
                close_entered: false,
                transaction: None,
            })),
            memory: Some(memory),
            admission: disk.memory().clone(),
        }))
    }

    fn file(disk: &Arc<ScratchDisk>, limit: u64, file: Option<GroupFile>) -> io::Result<FileOwner> {
        let memory = disk.memory().clone().reserve_installed(FILE_MEMORY_BYTES)?;
        let spool = EncryptedSpool::new_native(disk, limit)?.retain();
        Ok(FileOwner {
            file,
            spool,
            _memory: memory,
        })
    }

    fn with<T>(&self, operation: impl FnOnce(&mut State) -> io::Result<T>) -> io::Result<T> {
        let mut guard = self.state.lock().map_err(|poisoned| {
            if let Some(state) = poisoned.into_inner().as_mut() {
                state.fail();
            }
            io::Error::from(io::ErrorKind::Other)
        })?;
        let state = guard.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        state.check()?;
        let result = operation(state);
        if result.is_err()
            && result.as_ref().is_err_and(|e| {
                state
                    .transaction
                    .as_ref()
                    .is_some_and(|transaction| transaction.entered)
                    || !matches!(
                        e.kind(),
                        io::ErrorKind::StorageFull
                            | io::ErrorKind::OutOfMemory
                            | io::ErrorKind::NotFound
                            | io::ErrorKind::AlreadyExists
                    )
            })
        {
            state.fail();
        }
        match result {
            Ok(value) => {
                state.check()?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn close(&self) -> BackendCloseOutcome {
        self.close_with_root(EncryptedSpool::sync_all)
    }

    pub(crate) fn close_with_root(
        &self,
        sync: impl FnOnce(&mut EncryptedSpool) -> io::Result<()>,
    ) -> BackendCloseOutcome {
        let mut guard = self.state.lock().unwrap_or_else(|poisoned| {
            let mut guard = poisoned.into_inner();
            if let Some(state) = guard.as_mut() {
                state.fail();
            }
            guard
        });
        let Some(state) = guard.as_mut() else {
            return BackendCloseOutcome::drained(Ok(()));
        };
        let outcome = state.close(sync);
        if outcome.native_disposition() == BackendNativeDisposition::Drained {
            drop(guard.take());
        }
        outcome
    }

    #[cfg(test)]
    pub(crate) fn with_root<T>(&self, inspect: impl FnOnce(&mut RetainedSpool) -> T) -> T {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        inspect(&mut guard.as_mut().unwrap().root.as_mut().unwrap().spool)
    }

    #[cfg(test)]
    pub(crate) fn with_file<T>(
        &self,
        file: GroupFile,
        inspect: impl FnOnce(&mut RetainedSpool) -> T,
    ) -> T {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let state = guard.as_mut().unwrap();
        let index = state.position(file).unwrap();
        inspect(&mut state.files[index].as_mut().unwrap().spool)
    }

    #[cfg(test)]
    pub(super) fn drained(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(|p| p.into_inner());
        if let Some(mut retained) = state.take()
            && retained
                .close(EncryptedSpool::sync_all)
                .native_disposition()
                != BackendNativeDisposition::Drained
        {
            // No exact drain proof exists. Preserve every undrained file,
            // key, buffer and lease; never use ordinary Drop as proof.
            std::mem::forget(retained);
            std::mem::forget(self.memory.take());
        }
    }
}

impl StorageAdmission for Owner {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.with(|_| Ok(())).map_err(|_| OwnerFailed)
    }
    fn reserve_workspace(
        &self,
        bytes: u64,
    ) -> Result<Box<dyn kasumi_kv::ResidentLease>, AdmissionError> {
        // This admission performs no native effect. The transaction may already
        // own a durable private prefix that Core must finish and prove aborted
        // after a capacity refusal. Generic `with` fences any error after that
        // prefix was entered, which would replace the refusal with BrokenPipe
        // during rollback. Keep the lock and distinguish only the provider's
        // explicit capacity result; owner checks and other failures still fence.
        let mut guard = self.state.lock().map_err(|poisoned| {
            if let Some(state) = poisoned.into_inner().as_mut() {
                state.fail();
            }
            AdmissionError::OwnerFailed
        })?;
        let state = guard.as_mut().ok_or(AdmissionError::OwnerFailed)?;
        state.check().map_err(|_| {
            state.fail();
            AdmissionError::OwnerFailed
        })?;
        let bytes = crate::disk_memory::add(
            bytes,
            crate::disk_memory::allocation::<DiskMemoryLease>(1).map_err(|_| {
                state.fail();
                AdmissionError::OwnerFailed
            })?,
        )
        .map_err(|_| {
            state.fail();
            AdmissionError::OwnerFailed
        })?;
        let lease = match state.disk.memory().clone().reserve_installed(bytes) {
            Ok(lease) => lease,
            Err(error) if error.kind() == io::ErrorKind::OutOfMemory => {
                state.check().map_err(|_| {
                    state.fail();
                    AdmissionError::OwnerFailed
                })?;
                return Err(AdmissionError::CapacityDenied);
            }
            Err(_) => {
                state.fail();
                return Err(AdmissionError::OwnerFailed);
            }
        };
        state.check().map_err(|_| {
            state.fail();
            AdmissionError::OwnerFailed
        })?;
        Ok(Box::new(lease))
    }

    fn quote_cache_memory(
        &self,
        credit_bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, AdmissionError> {
        self.admission
            .quote_cache_memory(credit_bytes)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::OutOfMemory {
                    AdmissionError::CapacityDenied
                } else {
                    AdmissionError::OwnerFailed
                }
            })
    }

    fn reserve_cache_memory(
        self: Arc<Self>,
        credit_bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryLease, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let lease = self
            .admission
            .clone()
            .reserve_cache_memory(credit_bytes)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::OutOfMemory {
                    AdmissionError::CapacityDenied
                } else {
                    self.owner_failed();
                    AdmissionError::OwnerFailed
                }
            })?;
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        Ok(lease)
    }

    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        self.with(|state| {
            if current != state.total()? || requested < current {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if requested > state.limit {
                return Err(io::ErrorKind::StorageFull.into());
            }
            Ok(())
        })
        .map_err(|error| {
            if error.kind() == io::ErrorKind::StorageFull {
                AdmissionError::CapacityDenied
            } else {
                AdmissionError::OwnerFailed
            }
        })
    }
    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        self.with(|state| {
            if actual != state.total()? {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(())
        })
        .map_err(|_| OwnerFailed)
    }
    fn owner_failed(&self) {
        if let Some(state) = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_mut()
        {
            state.fail();
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Backend(pub(crate) Arc<Owner>);

impl SegmentGroupBackend for Backend {
    // Explicit real scratch quota and descriptor corridor.
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> Result<(), kasumi_kv::TransactionReserveError> {
        self.reserve_plan(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.finish_plan(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.cancel_plan(group_id, batch_seq)
    }
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.0.with(|state| {
            let offset = if slot == RootSlot::A {
                0
            } else {
                ROOT_SLOT_BYTES as u64
            };
            let spool = state
                .root
                .as_mut()
                .unwrap()
                .spool
                .spool()
                .ok_or(io::ErrorKind::BrokenPipe)?;
            out.fill(0);
            let present = spool
                .len()
                .saturating_sub(offset)
                .min(ROOT_SLOT_BYTES as u64) as usize;
            if present != 0 {
                spool.seek(SeekFrom::Start(offset))?;
                spool.read_exact(&mut out[..present])?;
            }
            Ok(())
        })
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.0.with(|state| {
            let offset = if slot == RootSlot::A {
                0
            } else {
                ROOT_SLOT_BYTES as u64
            };
            let old = state
                .root
                .as_mut()
                .unwrap()
                .spool
                .spool()
                .ok_or(io::ErrorKind::BrokenPipe)?
                .len();
            let end = old.max(offset + ROOT_SLOT_BYTES as u64);
            state.admit_length(old, end)?;
            state.claim_root_growth(end)?;
            let spool = state.root.as_mut().unwrap().spool.spool().unwrap();
            spool.reserve_growth(old, end)?;
            if offset > old {
                spool.resize(offset)?;
            }
            spool.seek(SeekFrom::Start(offset))?;
            spool.write_all(bytes)
        })
    }
    fn sync_root(&self) -> io::Result<()> {
        self.0.with(|state| {
            state
                .root
                .as_mut()
                .unwrap()
                .spool
                .spool()
                .ok_or(io::ErrorKind::BrokenPipe)?
                .sync_all()
        })
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        let epoch = self.0.with(|state| Ok(state.namespace_epoch))?;
        let mut visit = |name: &OsStr| {
            // CheckedGroup checks this same admission owner around callbacks;
            // invoking it under our mutex would deadlock at the root entry.
            let result = visitor(name);
            let current = self.0.with(|state| Ok(state.namespace_epoch))?;
            if current != epoch {
                return Err(io::ErrorKind::Interrupted.into());
            }
            result
        };
        visit(OsStr::new(ROOT_FILE_NAME))?;
        let mut slot = 0;
        while slot < MAX_FILES {
            let (current, entry) = self.0.with(|state| {
                let next = state.files[slot..]
                    .iter_mut()
                    .enumerate()
                    .find_map(|(offset, entry)| entry.as_mut().map(|entry| (slot + offset, entry)));
                let entry = match next {
                    Some((index, entry)) => {
                        entry
                            .spool
                            .spool()
                            .ok_or(io::ErrorKind::BrokenPipe)?
                            .check_owner()?;
                        Some((index, entry.file.unwrap()))
                    }
                    None => None,
                };
                Ok((state.namespace_epoch, entry))
            })?;
            if current != epoch {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let Some((index, file)) = entry else { break };
            slot = index + 1;
            let mut name = [0u8; 23];
            for (index, byte) in name[..16].iter_mut().enumerate() {
                *byte = b"0123456789abcdef"[((file.id >> (4 * (15 - index))) & 15) as usize];
            }
            let suffix: &[u8] = match file.kind {
                FileKind::Segment => b".kvseg",
                FileKind::Checkpoint => b".kvckpt",
                FileKind::Directory => b".kvdir",
            };
            name[16..16 + suffix.len()].copy_from_slice(suffix);
            visit(OsStr::new(
                std::str::from_utf8(&name[..16 + suffix.len()]).unwrap(),
            ))?;
        }
        let current = self.0.with(|state| Ok(state.namespace_epoch))?;
        if current != epoch {
            return Err(io::ErrorKind::Interrupted.into());
        }
        Ok(())
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.0.with(|state| Ok(state.position(file).is_ok()))
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.0.with(|state| {
            if state.transaction.is_some() {
                return state.create_claimed(file);
            }
            if file.id == 0 || file.id == u64::MAX {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            if state.position(file).is_ok() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            let index = state
                .files
                .iter()
                .position(Option::is_none)
                .ok_or(io::ErrorKind::StorageFull)?;
            let epoch = state
                .namespace_epoch
                .checked_add(1)
                .ok_or(io::ErrorKind::Other)?;
            let owner = Owner::file(&state.disk, state.limit, Some(file))?;
            state.files[index] = Some(owner);
            state.namespace_epoch = epoch;
            Ok(())
        })
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.0.with(|state| Ok(state.spool(file)?.len()))
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.with(|state| {
            let spool = state.spool(file)?;
            spool.seek(SeekFrom::Start(at))?;
            spool.read_exact(out)
        })
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.with(|state| {
            let old = state.spool(file)?.len();
            if at > old {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let end = at
                .checked_add(bytes.len() as u64)
                .ok_or(io::ErrorKind::StorageFull)?
                .max(old);
            state.admit_length(old, end)?;
            state.claim_growth(file, end)?;
            let spool = state.spool(file)?;
            spool.reserve_growth(old, end)?;
            spool.seek(SeekFrom::Start(at))?;
            spool.write_all(bytes)
        })
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.0.with(|state| {
            if state.transaction.is_some() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let old = state.spool(file)?.len();
            state.admit_length(old, length)?;
            state.spool(file)?.resize(length)
        })
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.0.with(|state| state.spool(file)?.sync_all())
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.0.with(|state| {
            if state.transaction.is_some() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let Ok(index) = state.position(file) else {
                return Ok(());
            };
            let epoch = state
                .namespace_epoch
                .checked_add(1)
                .ok_or(io::ErrorKind::Other)?;
            let outcome = state.files[index].as_mut().unwrap().spool.close();
            let (result, disposition) = outcome.into_parts();
            if disposition == BackendNativeDisposition::Drained {
                drop(state.files[index].take());
                state.namespace_epoch = epoch;
            } else {
                state.fail();
            }
            result
        })
    }
    fn sync_names(&self) -> io::Result<()> {
        self.0.with(|_| Ok(()))
    }
    fn close(&self) -> BackendCloseOutcome {
        self.0.close()
    }
}

#[path = "scratch_group_claim.rs"]
mod claim;
