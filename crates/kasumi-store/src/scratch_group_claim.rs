//! One bounded claim in the existing scratch group; no independent census.
use super::*;
use crate::{
    scratch_disk::transaction::{ReserveFailure, TransactionSpace},
    spool::claim::PreparedSpool,
};
use kasumi_kv::{FileSpaceRange, TransactionReserveError, TransactionSpacePlan};

struct PreparedFile {
    file: GroupFile,
    spool: PreparedSpool,
    memory: Option<DiskMemoryLease>,
}
pub(super) struct GroupTransaction {
    plan: TransactionSpacePlan,
    prepared: [Option<PreparedFile>; MAX_FILES],
    space: Option<TransactionSpace>,
    created: [u64; 2],
    lengths: [u64; 2],
    pub(super) entered: bool,
}
impl GroupTransaction {
    fn matches(&self, group: [u8; 16], batch: u64) -> bool {
        self.plan.group_id == group && self.plan.batch_seq == batch
    }
    fn range(&self, file: GroupFile) -> io::Result<(usize, FileSpaceRange)> {
        match file.kind {
            FileKind::Segment => Ok((0, self.plan.new_segments)),
            FileKind::Directory => Ok((1, self.plan.new_directories)),
            FileKind::Checkpoint => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
    fn growth(&mut self, file: GroupFile, current: u64, end: u64) -> io::Result<()> {
        if let Some(existing) = self
            .plan
            .segment
            .into_iter()
            .chain(self.plan.directory)
            .find(|entry| entry.file == file)
        {
            if current < existing.initial_len || end < current || end > existing.maximum_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
        } else {
            let (index, range) = self.range(file)?;
            let offset = file
                .id
                .checked_sub(range.first_id)
                .ok_or(io::ErrorKind::InvalidData)?;
            if offset >= self.created[index]
                || range.maximum_len(file.id).is_none_or(|max| end > max)
                || end < current
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.lengths[index] = self.lengths[index]
                .checked_add(end - current)
                .filter(|length| *length <= range.total_len)
                .ok_or(io::ErrorKind::InvalidData)?;
        }
        self.entered = true;
        Ok(())
    }
}
fn range_bytes(disk: &ScratchDisk, range: FileSpaceRange) -> Result<u64, ReserveFailure> {
    range.validate()?;
    if range.count == 0 {
        return Ok(0);
    }
    // Sum ceil(n_i/BLOCK) <= ceil(sum(n_i)/BLOCK)+count-1. Add per-file
    // filesystem rounding, then cap by the individual maxima when tighter.
    let slots = range
        .total_len
        .div_ceil(crate::spool::NATIVE_BLOCK as u64)
        .checked_add(range.count - 1)
        .ok_or(ReserveFailure::Capacity)?;
    let aggregate = disk
        .transaction_rounded(
            slots
                .checked_mul(crate::spool::NATIVE_SLOT)
                .ok_or(ReserveFailure::Capacity)?,
        )
        .map_err(|_| ReserveFailure::Capacity)?
        .checked_add(
            (range.count - 1)
                .checked_mul(disk.transaction_allocation_unit())
                .ok_or(ReserveFailure::Capacity)?,
        )
        .ok_or(ReserveFailure::Capacity)?;
    let full = disk
        .transaction_rounded(EncryptedSpool::transaction_ciphertext_len(range.full_len)?)
        .map_err(|_| ReserveFailure::Capacity)?;
    let last = disk
        .transaction_rounded(EncryptedSpool::transaction_ciphertext_len(range.last_len)?)
        .map_err(|_| ReserveFailure::Capacity)?;
    let maxima = full
        .checked_mul(range.count - 1)
        .and_then(|n| n.checked_add(last));
    Ok(maxima.map_or(aggregate, |maxima| maxima.min(aggregate)))
}
impl State {
    fn reserve_plan(&mut self, plan: &TransactionSpacePlan) -> Result<(), ReserveFailure> {
        plan.validate()?;
        if self.transaction.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = plan
            .new_segments
            .count
            .checked_add(plan.new_directories.count)
            .ok_or(ReserveFailure::Capacity)?;
        self.namespace_epoch
            .checked_add(count)
            .ok_or(io::ErrorKind::InvalidData)?;
        let count = usize::try_from(count).map_err(|_| ReserveFailure::Capacity)?;
        if count > self.files.iter().filter(|slot| slot.is_none()).count() {
            return Err(ReserveFailure::Capacity);
        }
        let root_length = self.validate_plan_root(plan)?;
        let root_end = (2 * ROOT_SLOT_BYTES) as u64;
        if root_length > root_end {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut logical = self
            .total()?
            .checked_add(root_end - root_length)
            .ok_or(ReserveFailure::Capacity)?;
        let mut bytes = {
            let root = self.root.as_mut().unwrap().spool.spool().unwrap();
            self.disk
                .transaction_rounded(EncryptedSpool::transaction_ciphertext_len(root_end)?)
                .map_err(|_| ReserveFailure::Capacity)?
                .saturating_sub(root.transaction_charged_bytes())
        };
        for existing in plan.segment.into_iter().chain(plan.directory) {
            let disk = self.disk.clone();
            let spool = self.spool(existing.file)?;
            spool.transaction_clean()?;
            if spool.len() != existing.initial_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            logical = logical
                .checked_add(existing.maximum_len - existing.initial_len)
                .ok_or(ReserveFailure::Capacity)?;
            bytes = bytes
                .checked_add(
                    disk.transaction_rounded(EncryptedSpool::transaction_ciphertext_len(
                        existing.maximum_len,
                    )?)
                    .map_err(|_| ReserveFailure::Capacity)?
                    .saturating_sub(spool.transaction_charged_bytes()),
                )
                .ok_or(ReserveFailure::Capacity)?;
        }
        for (range, kind) in [
            (plan.new_segments, FileKind::Segment),
            (plan.new_directories, FileKind::Directory),
        ] {
            logical = logical
                .checked_add(range.total_len)
                .ok_or(ReserveFailure::Capacity)?;
            bytes = bytes
                .checked_add(range_bytes(&self.disk, range)?)
                .ok_or(ReserveFailure::Capacity)?;
            // The native selected root authenticates never-reused identifiers;
            // independently reject every actual occupied key in the range.
            for entry in self.files.iter().flatten() {
                let file = entry.file.expect("non-root group file");
                if file.kind == kind && range.maximum_len(file.id).is_some() {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
            }
        }
        if logical > self.limit {
            return Err(ReserveFailure::Capacity);
        }
        let mut transaction = GroupTransaction {
            plan: *plan,
            prepared: std::array::from_fn(|_| None),
            space: None,
            created: [0; 2],
            lengths: [0; 2],
            entered: false,
        };
        let mut at = 0;
        for (range, kind) in [
            (plan.new_segments, FileKind::Segment),
            (plan.new_directories, FileKind::Directory),
        ] {
            for offset in 0..range.count {
                let file = GroupFile {
                    kind,
                    id: range
                        .first_id
                        .checked_add(offset)
                        .ok_or(io::ErrorKind::InvalidInput)?,
                };
                let memory = self
                    .disk
                    .memory()
                    .clone()
                    .reserve_installed(FILE_MEMORY_BYTES)
                    .map_err(ReserveFailure::memory)?;
                let spool = PreparedSpool::new(&self.disk, self.limit)?;
                transaction.prepared[at] = Some(PreparedFile {
                    file,
                    spool,
                    memory: Some(memory),
                });
                at += 1;
            }
        }
        // Final fallible admission after all buffers/slots and root observations.
        // Installation after this transition is one infallible ownership move.
        transaction.space = Some(self.disk.reserve_transaction_space(bytes, count as u64)?);
        self.transaction = Some(transaction);
        Ok(())
    }
    /// The selected-root observation is complete before preparing any new file.
    /// Only its scalar length escapes; decoded roots, both slot buffers and the
    /// exact validation lease retire together before the file-buffer grants.
    fn validate_plan_root(&mut self, plan: &TransactionSpacePlan) -> Result<u64, ReserveFailure> {
        let validation_bytes = crate::disk_memory::add(
            kasumi_kv::TRANSACTION_SPACE_ROOTS_HEAP_BYTES,
            (2 * ROOT_SLOT_BYTES) as u64,
        )?;
        let _validation = self
            .disk
            .memory()
            .clone()
            .reserve_installed(validation_bytes)
            .map_err(ReserveFailure::memory)?;
        let mut a = [0; ROOT_SLOT_BYTES];
        let mut b = [0; ROOT_SLOT_BYTES];
        let root = self
            .root
            .as_mut()
            .unwrap()
            .spool
            .spool()
            .ok_or(io::ErrorKind::BrokenPipe)?;
        root.transaction_clean()?;
        let root_length = root.len();
        for (at, out) in [(0, &mut a), (ROOT_SLOT_BYTES as u64, &mut b)] {
            let present = root_length.saturating_sub(at).min(ROOT_SLOT_BYTES as u64) as usize;
            if present != 0 {
                root.seek(SeekFrom::Start(at))?;
                root.read_exact(&mut out[..present])?;
            }
        }
        if let Err(error) = kasumi_kv::validate_transaction_space_roots(plan, &a, &b) {
            // Caller plan mismatches do not invalidate healthy storage. Actual
            // protected-root corruption does, retaining the exact CoreError.
            if matches!(error, kasumi_kv::CoreError::Corrupt(_)) {
                self.fail();
            }
            return Err(io::Error::other(error).into());
        }
        Ok(root_length)
    }
    pub(super) fn create_claimed(&mut self, file: GroupFile) -> io::Result<()> {
        if self.position(file).is_ok() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let slot = self
            .files
            .iter()
            .position(Option::is_none)
            .ok_or(io::ErrorKind::InvalidData)?;
        let epoch = self
            .namespace_epoch
            .checked_add(1)
            .ok_or(io::ErrorKind::Other)?;
        let transaction = self.transaction.as_mut().expect("active claim");
        let (kind, range) = transaction.range(file)?;
        if range.maximum_len(file.id).is_none()
            || range.first_id.checked_add(transaction.created[kind]) != Some(file.id)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let pending = transaction
            .prepared
            .iter_mut()
            .flatten()
            .find(|entry| entry.file == file)
            .ok_or(io::ErrorKind::InvalidData)?;
        transaction.entered = true;
        let spool = pending
            .spool
            .acquire(transaction.space.as_mut().expect("installed space"))?;
        self.files[slot] = Some(FileOwner {
            file: Some(file),
            spool: spool.retain(),
            _memory: pending.memory.take().expect("prepared installed memory"),
        });
        transaction.created[kind] += 1;
        self.namespace_epoch = epoch;
        Ok(())
    }
    pub(super) fn claim_growth(&mut self, file: GroupFile, end: u64) -> io::Result<()> {
        let Some(_) = self.transaction else {
            return Ok(());
        };
        let position = self.position(file)?;
        let spool = self.files[position]
            .as_mut()
            .unwrap()
            .spool
            .spool()
            .ok_or(io::ErrorKind::BrokenPipe)?;
        let transaction = self.transaction.as_mut().unwrap();
        transaction.growth(file, spool.len(), end)?;
        spool.reserve_claimed_growth(transaction.space.as_mut().unwrap(), end)
    }
    pub(super) fn claim_root_growth(&mut self, end: u64) -> io::Result<()> {
        let Some(transaction) = self.transaction.as_mut() else {
            return Ok(());
        };
        if end > (2 * ROOT_SLOT_BYTES) as u64 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        transaction.entered = true;
        self.root
            .as_mut()
            .unwrap()
            .spool
            .spool()
            .ok_or(io::ErrorKind::BrokenPipe)?
            .reserve_claimed_growth(transaction.space.as_mut().unwrap(), end)
    }
    pub(super) fn cancel_pristine(&mut self) -> io::Result<()> {
        let transaction = self
            .transaction
            .as_mut()
            .ok_or(io::ErrorKind::InvalidInput)?;
        if transaction.entered
            || transaction
                .prepared
                .iter()
                .flatten()
                .any(|file| file.spool.acquired())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        transaction.space.as_mut().unwrap().finish()?;
        drop(self.transaction.take());
        Ok(())
    }
    fn finish_plan(&mut self, group: [u8; 16], batch: u64) -> io::Result<()> {
        let transaction = self
            .transaction
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?;
        if !transaction.matches(group, batch)
            || transaction
                .prepared
                .iter()
                .flatten()
                .any(|file| file.spool.acquired())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let plan = transaction.plan;
        let created = transaction.created;
        let lengths = transaction.lengths;
        let mut seen = [0_u64; 2];
        let mut totals = [0_u64; 2];
        for entry in self.files.iter_mut().flatten() {
            let file = entry.file.unwrap();
            let existing = plan
                .segment
                .into_iter()
                .chain(plan.directory)
                .find(|entry| entry.file == file);
            let range = match file.kind {
                FileKind::Segment => Some((0, plan.new_segments)),
                FileKind::Directory => Some((1, plan.new_directories)),
                FileKind::Checkpoint => None,
            };
            let fresh = range.filter(|(_, range)| range.maximum_len(file.id).is_some());
            if existing.is_none() && fresh.is_none() {
                continue;
            }
            let spool = entry.spool.spool().ok_or(io::ErrorKind::BrokenPipe)?;
            let length = spool.len();
            if let Some(existing) = existing {
                if length < existing.initial_len || length > existing.maximum_len {
                    return Err(io::ErrorKind::InvalidData.into());
                }
            } else if let Some((kind, range)) = fresh {
                if file.id - range.first_id >= created[kind]
                    || length < range.minimum_len
                    || length > range.maximum_len(file.id).unwrap()
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                seen[kind] += 1;
                totals[kind] = totals[kind]
                    .checked_add(length)
                    .ok_or(io::ErrorKind::InvalidData)?;
            }
            spool.sync_all()?;
            spool.settle_growth(length)?;
        }
        if seen != created
            || totals != lengths
            || totals[0] > plan.new_segments.total_len
            || totals[1] > plan.new_directories.total_len
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let root = self
            .root
            .as_mut()
            .unwrap()
            .spool
            .spool()
            .ok_or(io::ErrorKind::BrokenPipe)?;
        root.sync_all()?;
        root.settle_growth(root.len())?;
        self.transaction
            .as_mut()
            .unwrap()
            .space
            .as_mut()
            .unwrap()
            .finish()?;
        drop(self.transaction.take());
        Ok(())
    }
}
impl Backend {
    pub(super) fn reserve_plan(
        &self,
        plan: &TransactionSpacePlan,
    ) -> Result<(), TransactionReserveError> {
        // Reservation is a read-only preflight until its final infallible owner
        // installation. Malformed caller plans do not fence healthy storage.
        // Each actual root/stat/decrypt operation still owns its normal failure
        // handling; only explicit capacity paths carry ReserveFailure::Capacity.
        let mut guard = self.0.state.lock().map_err(|poisoned| {
            if let Some(state) = poisoned.into_inner().as_mut() {
                state.fail();
            }
            TransactionReserveError::Failed(io::ErrorKind::Other.into())
        })?;
        let state = guard
            .as_mut()
            .ok_or_else(|| TransactionReserveError::Failed(io::ErrorKind::BrokenPipe.into()))?;
        state.check().map_err(TransactionReserveError::Failed)?;
        let result = state.reserve_plan(plan);
        if !state.disk.transaction_ready() {
            state.fail();
            return match result {
                Err(ReserveFailure::Failed(error)) => Err(TransactionReserveError::Failed(error)),
                _ => Err(TransactionReserveError::Failed(io::ErrorKind::Other.into())),
            };
        }
        result.map_err(Into::into)
    }

    pub(super) fn finish_plan(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.0.with(|state| state.finish_plan(group, batch))
    }
    pub(super) fn cancel_plan(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.0.with(|state| {
            if !state
                .transaction
                .as_ref()
                .is_some_and(|transaction| transaction.matches(group, batch))
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            state.cancel_pristine()
        })
    }
}

#[cfg(test)]
#[path = "scratch_group_claim_tests.rs"]
mod tests;
