//! Finite physical-space claims acquired by native commit before private writes
//! and retained until explicit pristine cancellation or positive settlement.
use super::*;
use kasumi_kv::{FileSpaceRange, TransactionReserveError, TransactionSpacePlan};

pub(super) struct GroupTransaction {
    pub(super) space: crate::node_disk::TransactionSpace,
    plan: TransactionSpacePlan,
    created: [u64; 2],
    lengths: [u64; 2],
}
impl GroupTransaction {
    fn range(&self, file: GroupFile) -> io::Result<(usize, FileSpaceRange)> {
        match file.kind {
            GroupFileKind::Segment => Ok((0, self.plan.new_segments)),
            GroupFileKind::Directory => Ok((1, self.plan.new_directories)),
            GroupFileKind::Checkpoint => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
    pub(super) fn authorize_create(&mut self, file: GroupFile) -> io::Result<()> {
        let (index, range) = self.range(file)?;
        if range.maximum_len(file.id).is_none()
            || range.first_id.checked_add(self.created[index]) != Some(file.id)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.created[index] = self.created[index]
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.space.enter_effect();
        Ok(())
    }
    fn authorize_growth(
        &mut self,
        file: GroupFile,
        current: u64,
        requested: u64,
    ) -> io::Result<()> {
        let maximum = self
            .plan
            .segment
            .into_iter()
            .chain(self.plan.directory)
            .find(|existing| existing.file == file)
            .map(|existing| existing.maximum_len);
        if let Some(maximum) = maximum {
            if requested <= maximum {
                return Ok(());
            }
            return Err(io::ErrorKind::InvalidData.into());
        }
        let (index, range) = self.range(file)?;
        let offset = file
            .id
            .checked_sub(range.first_id)
            .ok_or(io::ErrorKind::InvalidData)?;
        if offset >= self.created[index]
            || range
                .maximum_len(file.id)
                .is_none_or(|limit| requested > limit)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let delta = requested.saturating_sub(current);
        let length = self.lengths[index]
            .checked_add(delta)
            .filter(|length| *length <= range.total_len)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.lengths[index] = length;
        Ok(())
    }
    fn matches(&self, group_id: [u8; 16], batch_seq: u64) -> bool {
        self.plan.group_id == group_id && self.plan.batch_seq == batch_seq
    }
}
impl NodeSegmentGroup {
    pub(super) fn reserve_transaction_plan(
        &self,
        plan: &TransactionSpacePlan,
    ) -> std::result::Result<(), TransactionReserveError> {
        self.reserve_transaction_inner(plan).map_err(|error| {
            // Only this pre-effect corridor mints routine capacity. Observation
            // failures latch their owner and preserve the original io::Error.
            if !self.failed.load(Ordering::Acquire)
                && self.disk.snapshot().phase == crate::NodeDiskPhase::Open
                && matches!(
                    error.kind(),
                    io::ErrorKind::StorageFull | io::ErrorKind::OutOfMemory
                )
            {
                TransactionReserveError::CapacityDenied
            } else {
                TransactionReserveError::Failed(error)
            }
        })
    }
    fn reserve_transaction_inner(&self, plan: &TransactionSpacePlan) -> io::Result<()> {
        self.require_healthy()?;
        plan.validate()?;
        let mut guard = self.state.write();
        let (resources, slots) = guard.open_mut()?;
        if resources.transaction.is_some() || resources.growth_target.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let files = plan
            .new_segments
            .count
            .checked_add(plan.new_directories.count)
            .ok_or(io::ErrorKind::StorageFull)?;
        // Every future create advances this owner-local namespace counter.
        // Promise the complete range before any observation or claim transfer,
        // so exhaustion cannot reject a later file after earlier effects.
        resources
            .namespace_epoch
            .checked_add(files)
            .ok_or(io::ErrorKind::StorageFull)?;
        let validation_bytes = crate::disk_memory::add(
            kasumi_kv::TRANSACTION_SPACE_ROOTS_HEAP_BYTES,
            (2 * ROOT_SLOT_BYTES) as u64,
        )?;
        let _validation = self
            .disk
            .memory()
            .clone()
            .reserve_installed(validation_bytes)?;
        let mut a = [0; ROOT_SLOT_BYTES];
        let mut b = [0; ROOT_SLOT_BYTES];
        let root = resources.root()?;
        self.effect(root.read_exact_at(&mut a, root_offset(RootSlot::A)))?;
        self.effect(root.read_exact_at(&mut b, root_offset(RootSlot::B)))?;
        if let Err(error) = kasumi_kv::validate_transaction_space_roots(plan, &a, &b) {
            // Invalid caller plans leave healthy storage usable. Corruption in
            // the actual protected images invalidates the owner, and the exact
            // native error remains the source of the returned failure.
            if matches!(
                (error).rejected_cause(),
                Some(kasumi_kv::CoreErrorCause::Corrupt(_))
            ) {
                self.fence();
            }
            return Err(io::Error::other(error));
        }
        for (range, kind) in [
            (plan.new_segments, GroupFileKind::Segment),
            (plan.new_directories, GroupFileKind::Directory),
        ] {
            if range.count != 0 && range.first_id <= resources.high_water[kind.index()] {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        let mut bytes = self
            .disk
            .transaction_range_bytes(&plan.new_segments, HEADER_BYTES as u64)?;
        bytes = bytes
            .checked_add(
                self.disk
                    .transaction_range_bytes(&plan.new_directories, HEADER_BYTES as u64)?,
            )
            .ok_or(io::ErrorKind::StorageFull)?;
        for existing in plan.segment.into_iter().chain(plan.directory) {
            let position = resources
                .position(existing.file)
                .ok_or(io::ErrorKind::InvalidInput)?;
            if resources.entries[position].envelope != Envelope::Complete {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let index = self.cached(resources, slots, position)?;
            let handle = slots[index]
                .handle
                .as_ref()
                .expect("cached transaction tail");
            let initial = physical(existing.initial_len, 0)?;
            // A prior ordinary operation may have synchronized without releasing
            // its unused growth. Settle it before quoting this transaction.
            self.effect(handle.settle_growth(initial))?;
            slots[index].dirty.store(false, Ordering::Release);
            bytes = bytes
                .checked_add(
                    handle.transaction_growth_quote(initial, physical(existing.maximum_len, 0)?)?,
                )
                .ok_or(io::ErrorKind::StorageFull)?;
        }
        let additional = usize::try_from(files).map_err(|_| io::ErrorKind::OutOfMemory)?;
        self.reserve_entries(resources, additional)?;
        let peak = u32::try_from(slots.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let live = u32::try_from(slots.iter().filter(|slot| slot.handle.is_some()).count())
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        let parent = self.effect(resources.directory()?.verified_identity())?;
        let space = self
            .disk
            .reserve_transaction_space(parent, bytes, files, peak, live)?;
        resources.transaction = Some(GroupTransaction {
            space,
            plan: *plan,
            created: [0; 2],
            lengths: [0; 2],
        });
        Ok(())
    }
    pub(super) fn cancel_transaction_plan(
        &self,
        group_id: [u8; 16],
        batch_seq: u64,
    ) -> io::Result<()> {
        self.require_healthy()?;
        let mut guard = self.state.write();
        let (resources, _) = guard.open_mut()?;
        let transaction = resources
            .transaction
            .as_mut()
            .ok_or(io::ErrorKind::InvalidInput)?;
        if !transaction.matches(group_id, batch_seq) || !transaction.space.pristine() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        transaction.space.cancel()?;
        drop(resources.transaction.take());
        Ok(())
    }
    pub(super) fn finish_transaction_plan(
        &self,
        group_id: [u8; 16],
        batch_seq: u64,
    ) -> io::Result<()> {
        self.require_healthy()?;
        let mut guard = self.state.write();
        let (resources, slots) = guard.open_mut()?;
        let transaction = resources
            .transaction
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?;
        if !transaction.matches(group_id, batch_seq) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let plan = transaction.plan;
        let created = transaction.created;
        // Visit only the two existing tails and the actually created prefixes.
        // Historical group membership does not enlarge per-transaction work.
        for existing in plan.segment.into_iter().chain(plan.directory) {
            self.settle_transaction_file(resources, slots, existing.file, existing.initial_len)?;
        }
        for (kind, range, count) in [
            (GroupFileKind::Segment, plan.new_segments, created[0]),
            (GroupFileKind::Directory, plan.new_directories, created[1]),
        ] {
            for offset in 0..count {
                let id = range
                    .first_id
                    .checked_add(offset)
                    .ok_or(io::ErrorKind::InvalidData)?;
                self.settle_transaction_file(
                    resources,
                    slots,
                    GroupFile { kind, id },
                    range.minimum_len,
                )?;
            }
        }
        self.effect(resources.root()?.sync_all())?;
        self.effect(resources.directory()?.sync_all())?;
        self.effect(
            resources
                .transaction
                .as_mut()
                .expect("active transaction")
                .space
                .finish(),
        )?;
        drop(resources.transaction.take());
        Ok(())
    }
    fn settle_transaction_file(
        &self,
        resources: &mut Resources,
        slots: &mut [Slot],
        file: GroupFile,
        minimum: u64,
    ) -> io::Result<()> {
        let position = self.effect(
            resources
                .position(file)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData)),
        )?;
        if resources.entries[position].envelope != Envelope::Complete {
            self.fence();
            return Err(io::ErrorKind::InvalidData.into());
        }
        let index = self.cached(resources, slots, position)?;
        let handle = slots[index]
            .handle
            .as_ref()
            .expect("cached transaction file");
        let actual = self.effect(handle.observed_len())?;
        if actual < physical(minimum, 0)? {
            self.fence();
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.effect(handle.settle_growth(actual))?;
        slots[index].dirty.store(false, Ordering::Release);
        Ok(())
    }

    pub(super) fn grow_in_transaction(
        &self,
        resources: &mut Resources,
        handle: &NodeDiskFile,
        file: GroupFile,
        current: u64,
        requested: u64,
    ) -> io::Result<()> {
        let Some(transaction) = resources.transaction.as_mut() else {
            return self.grow(handle, current, requested);
        };
        let logical_current = current.saturating_sub(HEADER_BYTES as u64);
        let logical_requested = requested.saturating_sub(HEADER_BYTES as u64);
        self.effect(transaction.authorize_growth(file, logical_current, logical_requested))?;
        if requested <= current {
            transaction.space.enter_effect();
            return Ok(());
        }
        self.effect(handle.reserve_transaction_growth(&mut transaction.space, current, requested))
    }
    pub(super) fn write_transaction_file(
        &self,
        file: GroupFile,
        at: u64,
        bytes: &[u8],
    ) -> io::Result<bool> {
        self.require_healthy()?;
        let mut guard = self.state.write();
        let (resources, slots) = guard.open_mut()?;
        if resources.transaction.is_none() {
            return Ok(false);
        }
        let position = resources.position(file).ok_or(io::ErrorKind::NotFound)?;
        let index = self.cached(resources, slots, position)?;
        let handle = slots[index]
            .handle
            .as_ref()
            .expect("cached transaction file");
        let current = self.effect(handle.observed_len())?;
        let logical = current.saturating_sub(HEADER_BYTES as u64);
        if at > logical {
            self.fence();
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.complete_envelope(resources, slots, position, index)?;
        let slot = &slots[index];
        let handle = slot.handle.as_ref().expect("cached transaction file");
        let current = self.effect(handle.observed_len())?;
        self.grow_in_transaction(resources, handle, file, current, physical(at, bytes.len())?)?;
        slot.dirty.store(true, Ordering::Release);
        self.effect(handle.write_all_at(bytes, physical(at, 0)?))?;
        Ok(true)
    }
}
