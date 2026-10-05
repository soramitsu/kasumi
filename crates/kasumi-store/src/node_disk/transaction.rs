//! Inline transaction rights owned by the existing group. State holds aggregate
//! promises; abandonment fences them until an accepted census. There is no
//! independent registry, cleanup allocation, or destructor refund.
use super::{AccountedInode, DiskWork, Identity, NamespaceBinding, NodeDisk, NodeDiskPhase, State};
use std::{io, sync::Arc};

pub(crate) struct TransactionSpace {
    disk: Arc<NodeDisk>,
    parent: Identity,
    binding: NamespaceBinding,
    bytes: u64,
    files: u64,
    free_descriptors: u32,
    live_descriptors: u32,
    entered: bool,
    active: bool,
}
/// Minted only while a complete claim transfers one counted file right.
/// The permit grants no caller-chosen quota bypass and is consumed with the
/// exact PreparedFile attempt, including its failed native outcome.
pub(super) struct FileCreationPermit {
    parent: Identity,
}
impl FileCreationPermit {
    pub(super) fn check_parent(&self, state: &State, parent: Identity) -> io::Result<()> {
        if parent != self.parent
            || state
                .accounted
                .get(&parent)
                .and_then(AccountedInode::directory)
                .is_none_or(|entry| !entry.transaction_claimed)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
}

impl NodeDisk {
    pub(crate) fn transaction_range_bytes(
        &self,
        range: &kasumi_kv::FileSpaceRange,
        envelope: u64,
    ) -> io::Result<u64> {
        range.validate()?;
        if range.count == 0 {
            return Ok(0);
        }
        let bytes = range
            .count
            .checked_mul(envelope)
            .and_then(|n| n.checked_add(range.total_len))
            .ok_or(io::ErrorKind::StorageFull)?;
        let sum = super::rounded(bytes, self.unit)?;
        let rounding = (range.count - 1)
            .checked_mul(self.unit)
            .ok_or(io::ErrorKind::StorageFull)?;
        let standing = super::rounded(
            self.config
                .file_allocation_policy
                .maximum_extra_extent_bytes,
            self.unit,
        )?
        .checked_mul(range.count)
        .ok_or(io::ErrorKind::StorageFull)?;
        sum.checked_add(rounding)
            .and_then(|n| n.checked_add(standing))
            .ok_or_else(|| io::ErrorKind::StorageFull.into())
    }

    /// Reserve all unassigned rights atomically. Existing cache descriptors
    /// count toward the requested peak; they are already charged live owners.
    pub(crate) fn reserve_transaction_space(
        self: &Arc<Self>,
        parent: (u64, u64),
        bytes: u64,
        files: u64,
        descriptor_peak: u32,
        live_descriptors: u32,
    ) -> io::Result<TransactionSpace> {
        let mut state = self.lock_state();
        if state.phase != NodeDiskPhase::Open || live_descriptors > descriptor_peak {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let parent = Identity(parent.0, parent.1);
        let directory = state
            .accounted
            .get(&parent)
            .and_then(AccountedInode::directory)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if !directory.settled || directory.transaction_claimed {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let binding = directory.binding;
        let children = directory
            .children
            .checked_add(files)
            .and_then(|n| n.checked_add(super::batch::reserved_children(&state, binding)))
            .ok_or(io::ErrorKind::StorageFull)?;
        let reserved_files = state
            .transaction_files
            .checked_add(files)
            .ok_or(io::ErrorKind::StorageFull)?;
        let free_descriptors = descriptor_peak - live_descriptors;
        let reserved_descriptors = state
            .transaction_descriptors
            .checked_add(free_descriptors)
            .ok_or(io::ErrorKind::StorageFull)?;
        let witnesses = state
            .transaction_witnesses
            .checked_add(1)
            .ok_or(io::ErrorKind::StorageFull)?;
        if children > self.config.directory_policy.max_entries
            || state
                .files
                .checked_add(reserved_files)
                .and_then(|n| n.checked_add(u64::from(super::batch::reserved_files(&state))))
                .is_none_or(|n| n > self.config.max_persistent_files)
            || state
                .open_files
                .checked_add(reserved_descriptors)
                .and_then(|n| n.checked_add(super::batch::reserved_files(&state)))
                .is_none_or(|n| n > self.config.max_open_files)
        {
            return Err(io::ErrorKind::StorageFull.into());
        }
        let ledger = usize::try_from(reserved_files)
            .ok()
            .and_then(|n| {
                n.checked_add(
                    super::batch::reserved_entries(&state)
                        .checked_sub(usize::try_from(state.transaction_files).ok()?)?,
                )
            })
            .ok_or(io::ErrorKind::OutOfMemory)?;
        state
            .namespace_generation
            .checked_add(ledger as u64)
            .ok_or(io::ErrorKind::StorageFull)?;
        state.accounted.try_reserve(ledger)?;
        let live = usize::try_from(reserved_descriptors)
            .ok()
            .and_then(|n| n.checked_add(super::batch::reserved_files(&state) as usize))
            .ok_or(io::ErrorKind::OutOfMemory)?;
        state.live.try_reserve(live)?;
        // No physical effect and no surviving provisional allocation precedes
        // this final quota transition. Every subsequent assignment is infallible.
        self.reserve(&mut state, bytes, DiskWork::Foreground)?;
        state.transaction_files = reserved_files;
        state.transaction_descriptors = reserved_descriptors;
        state.transaction_witnesses = witnesses;
        state
            .accounted
            .get_mut(&parent)
            .and_then(AccountedInode::directory_mut)
            .expect("validated transaction directory")
            .transaction_children = files;
        state
            .accounted
            .get_mut(&parent)
            .and_then(AccountedInode::directory_mut)
            .expect("validated transaction directory")
            .transaction_claimed = true;
        Ok(TransactionSpace {
            disk: self.clone(),
            parent,
            binding,
            bytes,
            files,
            free_descriptors,
            live_descriptors,
            entered: false,
            active: true,
        })
    }
}
impl TransactionSpace {
    pub(super) fn check(&self, disk: &Arc<NodeDisk>, state: &State) -> io::Result<()> {
        if !self.active
            || !Arc::ptr_eq(&self.disk, disk)
            || state.phase != NodeDiskPhase::Open
            || state
                .accounted
                .get(&self.parent)
                .and_then(AccountedInode::directory)
                .is_none_or(|entry| {
                    entry.binding != self.binding
                        || !entry.settled
                        || !entry.transaction_claimed
                        || entry.transaction_children != self.files
                })
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
    pub(super) fn check_parent(&self, parent: NamespaceBinding) -> io::Result<()> {
        if parent != self.binding {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
    pub(super) fn consume_descriptor(
        &mut self,
        disk: &Arc<NodeDisk>,
        state: &mut State,
    ) -> io::Result<()> {
        self.check(disk, state)?;
        let free = self
            .free_descriptors
            .checked_sub(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        let all = state
            .transaction_descriptors
            .checked_sub(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        let live = self
            .live_descriptors
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.free_descriptors = free;
        self.live_descriptors = live;
        state.transaction_descriptors = all;
        // A failed descriptor preparation after this transfer stays unknown;
        // the caller fences rather than reconstituting a right from absence.
        self.entered = true;
        Ok(())
    }
    pub(super) fn consume_file(
        &mut self,
        disk: &Arc<NodeDisk>,
        state: &mut State,
        bytes: u64,
    ) -> io::Result<FileCreationPermit> {
        self.check(disk, state)?;
        let files = self
            .files
            .checked_sub(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        let all = state
            .transaction_files
            .checked_sub(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        let remaining = self
            .bytes
            .checked_sub(bytes)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.files = files;
        self.bytes = remaining;
        state.transaction_files = all;
        state
            .accounted
            .get_mut(&self.parent)
            .and_then(AccountedInode::directory_mut)
            .expect("validated transaction directory")
            .transaction_children = files;
        self.entered = true;
        Ok(FileCreationPermit {
            parent: self.parent,
        })
    }
    pub(super) fn consume_growth(
        &mut self,
        disk: &Arc<NodeDisk>,
        state: &State,
        bytes: u64,
    ) -> io::Result<()> {
        self.check(disk, state)?;
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.entered = true;
        Ok(())
    }
    /// The group calls this only after the exact slot's native owner and heap
    /// registration have positively closed. A failed close never returns rights.
    pub(crate) fn descriptor_closed(&mut self) -> io::Result<()> {
        let mut state = self.disk.lock_state();
        self.check(&self.disk, &state)?;
        let live = self
            .live_descriptors
            .checked_sub(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        let free = self
            .free_descriptors
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        let all = state
            .transaction_descriptors
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.live_descriptors = live;
        self.free_descriptors = free;
        state.transaction_descriptors = all;
        Ok(())
    }
    pub(crate) fn enter_effect(&mut self) {
        self.entered = true;
    }
    pub(crate) fn pristine(&self) -> bool {
        self.active && !self.entered
    }
    /// The group has positively settled every touched exact file before finish.
    /// Live descriptor slots become ordinary owners; only unused rights refund.
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        self.release(false)
    }
    pub(crate) fn cancel(&mut self) -> io::Result<()> {
        self.release(true)
    }
    fn release(&mut self, pristine: bool) -> io::Result<()> {
        let mut state = self.disk.lock_state();
        self.check(&self.disk, &state)?;
        if pristine && self.entered {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let files = state
            .transaction_files
            .checked_sub(self.files)
            .ok_or(io::ErrorKind::InvalidData)?;
        let descriptors = state
            .transaction_descriptors
            .checked_sub(self.free_descriptors)
            .ok_or(io::ErrorKind::InvalidData)?;
        let witnesses = state
            .transaction_witnesses
            .checked_sub(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        let bytes = state
            .bytes
            .checked_sub(self.bytes)
            .ok_or(io::ErrorKind::InvalidData)?;
        let pending = state
            .pending
            .checked_sub(self.bytes)
            .ok_or(io::ErrorKind::InvalidData)?;
        let mut device = self.disk.device.lock();
        let shared = device
            .checked_sub(self.bytes)
            .ok_or(io::ErrorKind::InvalidData)?;
        if !device.admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        device
            .set_pending(shared)
            .inspect_err(|_| state.phase = NodeDiskPhase::Failed)?;
        state.bytes = bytes;
        state.pending = pending;
        state.transaction_files = files;
        state.transaction_descriptors = descriptors;
        state.transaction_witnesses = witnesses;
        state
            .accounted
            .get_mut(&self.parent)
            .and_then(AccountedInode::directory_mut)
            .expect("validated transaction directory")
            .transaction_children = 0;
        state
            .accounted
            .get_mut(&self.parent)
            .and_then(AccountedInode::directory_mut)
            .expect("validated transaction directory")
            .transaction_claimed = false;
        self.active = false;
        Ok(())
    }
}
impl Drop for TransactionSpace {
    fn drop(&mut self) {
        if self.active {
            let mut state = self.disk.lock_state();
            // Aggregate rights survive abandonment. An accepted census can
            // reconcile only after every external witness and native owner drains.
            state.transaction_witnesses = state
                .transaction_witnesses
                .checked_sub(1)
                .expect("registered transaction witness");
            self.disk.fail_locked(&mut state);
        }
    }
}

#[cfg(test)]
mod tests;
