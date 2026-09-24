//! Prepared directory custody and affected-parent namespace accounting.
//! File and directory owners share actual retained parent custody. Every
//! namespace effect still requires its own prepared, admitted transition.
use super::{
    AccountedDirectory, AccountedInode, DiskWork, Identity, NodeDisk, NodeDiskPhase, State, census,
    directory,
};
use std::{ffi::CString, fs::File, io, os::unix::fs::MetadataExt};

/// Embedded in an admitted file or non-root directory owner. Preparation is unregistered;
/// its original parent's registration funds the transfer until actual close.
/// No destructor here locks State: FileOwner retires resources before credit.
pub(super) struct RetainedParent {
    file: Option<File>,
    identity: Identity,
    ancestors: Box<[Identity]>,
    registered: bool,
}
impl RetainedParent {
    pub(super) fn prepare(
        disk: &NodeDisk,
        state: &State,
        root: &str,
        names: &[CString],
    ) -> io::Result<Self> {
        let (file, ancestors) = directory::file_parent(disk, state, root, names)?;
        let identity = *ancestors.last().ok_or(io::ErrorKind::InvalidData)?;
        Ok(Self {
            file: Some(file),
            identity,
            ancestors,
            registered: false,
        })
    }
    pub(super) fn prepared(identity: Identity, ancestors: Box<[Identity]>) -> Self {
        Self {
            file: None,
            identity,
            ancestors,
            registered: false,
        }
    }
    pub(super) fn observe_ancestor(&mut self, index: usize, identity: Identity) {
        self.ancestors[index] = identity;
    }
    pub(super) fn finish_prepared(&mut self, identity: Identity, file: File) {
        assert_eq!(self.ancestors.last(), Some(&identity));
        self.identity = identity;
        self.set_descriptor(file);
    }
    pub(super) fn set_descriptor(&mut self, file: File) {
        assert!(
            self.file.is_none(),
            "prepared parent descriptor is installed once"
        );
        self.file = Some(file);
    }
    /// Compare every retained ancestor and the actual parent descriptor. This
    /// deliberately does not require the affected parent's pre-effect extent:
    /// the prepared transition owns that snapshot until explicit settlement.
    pub(super) fn verify(&self, root: &census::Root, names: &[CString]) -> io::Result<()> {
        root.verify_nonallocating()?;
        if self.ancestors.len() != names.len() + 1 || self.ancestors[0] != root.identity {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut current = root.file.try_clone()?;
        for (index, name) in names.iter().enumerate() {
            let child = census::open_at(&current, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let metadata = child.metadata()?;
            census::directory_nonallocating(&metadata)?;
            if metadata.dev() != root.identity.0
                || Identity::of(&metadata) != self.ancestors[index + 1]
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            current = child;
        }
        let retained = self.file().metadata()?;
        census::directory_nonallocating(&retained)?;
        if Identity::of(&current.metadata()?) != self.identity
            || Identity::of(&retained) != self.identity
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
    pub(super) fn file(&self) -> &File {
        self.file.as_ref().expect("retained parent descriptor")
    }
    pub(super) fn identity(&self) -> Identity {
        self.identity
    }
    pub(super) fn ancestors(&self) -> &[Identity] {
        &self.ancestors
    }
    pub(super) fn register(&mut self, _disk: &NodeDisk, state: &mut State) -> io::Result<()> {
        self.register_in(&mut state.accounted)
    }
    pub(super) fn register_in(
        &mut self,
        accounted: &mut super::fixed_map::Banks<AccountedInode>,
    ) -> io::Result<()> {
        // The concrete file/directory-owner quota and envelope fund this parent.
        // Counting it again as an independent owner would reduce those quotas.
        if self.registered {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let entry = accounted
            .get_mut(&self.identity)
            .and_then(AccountedInode::directory_mut)
            .ok_or(io::ErrorKind::InvalidData)?;
        let next = entry
            .live_handles
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        entry.live_handles = next;
        self.registered = true;
        Ok(())
    }
    pub(super) fn take_descriptor(&mut self) -> Option<File> {
        self.file.take()
    }
    /// Move the scalar registration across the resources' scope boundary.
    /// Actual FD and ancestor allocation destruction precede returned credit.
    pub(super) fn retire(self) -> Option<Identity> {
        let Self {
            file,
            identity,
            ancestors,
            registered,
        } = self;
        drop(file);
        drop(ancestors);
        registered.then_some(identity)
    }
}

pub(super) fn can_retire_parent(state: &State, identity: Identity) -> bool {
    state
        .accounted
        .get(&identity)
        .and_then(AccountedInode::directory)
        .is_some_and(|entry| entry.live_handles != 0)
}
pub(super) fn retire_parent(state: &mut State, identity: Identity) {
    let entry = state
        .accounted
        .get_mut(&identity)
        .and_then(AccountedInode::directory_mut)
        .expect("validated parent registration");
    entry.live_handles -= 1;
}

#[derive(Clone, Copy)]
struct Change {
    identity: Identity,
    before: AccountedDirectory,
    children: u64,
}
/// Inline plan: preparation and all fallible arithmetic precede the effect.
/// The caller owns State serialization and actual descriptors until settlement.
#[derive(Clone, Copy)]
pub(super) struct ParentTransition {
    generation: u64,
    changes: [Option<Change>; 2],
}
impl ParentTransition {
    pub(super) fn prepare(
        disk: &NodeDisk,
        state: &mut State,
        first: (Identity, i8),
        second: Option<(Identity, i8)>,
        growth_work: Option<DiskWork>,
    ) -> io::Result<Self> {
        let prepared = Self::preflight(disk, state, first, second, growth_work)?;
        prepared.activate(state);
        Ok(prepared)
    }

    /// Validate without invalidating the old ledger. Directory creation reserves
    /// its complete child allowance after this preflight, then activates both
    /// the parent plan and its already-owned pending operation without a gap.
    pub(super) fn preflight(
        disk: &NodeDisk,
        state: &mut State,
        first: (Identity, i8),
        second: Option<(Identity, i8)>,
        growth_work: Option<DiskWork>,
    ) -> io::Result<Self> {
        if state.phase == NodeDiskPhase::Failed || !disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        let generation = state
            .namespace_generation
            .checked_add(1)
            .ok_or(io::ErrorKind::StorageFull)?;
        if let Some(work) = growth_work {
            // Full parent allowances were promised by census. This checks the
            // unchanged node/work/floor policy before consuming those promises.
            disk.reserve(state, 0, work)?;
        } else {
            // Cleanup may proceed above the configured extent limit or paused,
            // but it may not spend a shared promise without physical headroom.
            let promises = disk.device.lock();
            let needed = promises
                .checked_add(promises.minimum_free_bytes())
                .ok_or(io::ErrorKind::StorageFull)?;
            if disk.available()? < needed {
                return Err(io::ErrorKind::StorageFull.into());
            }
        }
        let mut inputs = [Some(first), second];
        if let Some((identity, delta)) = second
            && identity == first.0
        {
            inputs = [
                Some((
                    identity,
                    first
                        .1
                        .checked_add(delta)
                        .ok_or(io::ErrorKind::InvalidData)?,
                )),
                None,
            ];
        }
        let mut changes = [None, None];
        for (slot, input) in changes.iter_mut().zip(inputs) {
            let Some((identity, delta)) = input else {
                continue;
            };
            let before = *state
                .accounted
                .get(&identity)
                .and_then(AccountedInode::directory)
                .ok_or(io::ErrorKind::InvalidData)?;
            if !before.settled {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let children = before
                .children
                .checked_add_signed(i64::from(delta))
                .ok_or(io::ErrorKind::InvalidData)?;
            if delta > 0
                && (children > disk.config.directory_policy.max_entries
                    || before.bytes > disk.config.directory_policy.extent_bytes)
            {
                return Err(io::ErrorKind::StorageFull.into());
            }
            *slot = Some(Change {
                identity,
                before,
                children,
            });
        }
        Ok(Self {
            generation,
            changes,
        })
    }

    pub(super) fn activate(&self, state: &mut State) {
        for change in self.changes.iter().flatten() {
            state
                .accounted
                .get_mut(&change.identity)
                .and_then(AccountedInode::directory_mut)
                .expect("prepared parent")
                .settled = false;
        }
    }

    /// Only a definite no-effect result may restore the original snapshots.
    /// The actual retained descriptors must still match both original extents.
    pub(super) fn unchanged(
        self,
        disk: &NodeDisk,
        state: &mut State,
        parents: &[&RetainedParent],
    ) -> io::Result<()> {
        for change in self.changes.iter().flatten() {
            let parent = parents
                .iter()
                .find(|parent| parent.identity == change.identity)
                .ok_or(io::ErrorKind::InvalidData)?;
            let metadata = parent.file().metadata()?;
            if Identity::of(&metadata) != change.identity
                || metadata.len() != change.before.len
                || census::directory_extent(&metadata)?
                    != change
                        .before
                        .bytes
                        .checked_sub(change.before.pending)
                        .ok_or(io::ErrorKind::InvalidData)?
            {
                disk.fail_locked(state);
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        for change in self.changes.iter().flatten() {
            let entry = state
                .accounted
                .get_mut(&change.identity)
                .and_then(AccountedInode::directory_mut)
                .expect("prepared parent");
            *entry = AccountedDirectory {
                live_handles: entry.live_handles,
                ..change.before
            };
        }
        Ok(())
    }

    /// Called only after affected directory fsyncs and exact ancestry checks.
    /// Observed allocation materializes the already-held promise. An observed
    /// excess is fully recorded and fences admission; it never becomes a pass.
    pub(super) fn settle(
        self,
        disk: &NodeDisk,
        state: &mut State,
        parents: &[&RetainedParent],
    ) -> io::Result<()> {
        let mut observations = [None, None];
        for (slot, change) in observations.iter_mut().zip(self.changes.iter()) {
            let Some(change) = change else { continue };
            let parent = parents
                .iter()
                .find(|parent| parent.identity == change.identity)
                .ok_or(io::ErrorKind::InvalidData)?;
            *slot = Some((change.identity, parent.file().metadata()?));
        }
        self.settle_observed(disk, state, observations)
    }

    /// The observations are taken from the operation's retained descriptors
    /// under the same State guard. This separates borrows without taking the
    /// unresolved operation out of its custody slot during fallible work.
    pub(super) fn settle_observed(
        self,
        disk: &NodeDisk,
        state: &mut State,
        observations: [Option<(Identity, std::fs::Metadata)>; 2],
    ) -> io::Result<()> {
        let mut updated = [None, None];
        let mut bytes = state.bytes;
        let mut pending = state.pending;
        let mut directory_bytes = state.directory_bytes;
        let mut promises = disk.device.lock();
        let mut shared = *promises;
        let mut exceeded = false;
        for (slot, change) in updated.iter_mut().zip(self.changes.iter()) {
            let Some(change) = change else { continue };
            let (_, metadata) = observations
                .iter()
                .flatten()
                .find(|(identity, _)| *identity == change.identity)
                .ok_or(io::ErrorKind::InvalidData)?;
            census::directory_nonallocating(&metadata)?;
            if Identity::of(&metadata) != change.identity {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let observed = census::directory_extent(&metadata)?;
            let charged = change.before.bytes.max(observed);
            let new_pending = charged
                .checked_sub(observed)
                .ok_or(io::ErrorKind::InvalidData)?;
            let old_observed = change
                .before
                .bytes
                .checked_sub(change.before.pending)
                .ok_or(io::ErrorKind::InvalidData)?;
            bytes = bytes
                .checked_sub(change.before.bytes)
                .and_then(|v| v.checked_add(charged))
                .ok_or(io::ErrorKind::InvalidData)?;
            pending = pending
                .checked_sub(change.before.pending)
                .and_then(|v| v.checked_add(new_pending))
                .ok_or(io::ErrorKind::InvalidData)?;
            shared = shared
                .checked_sub(change.before.pending)
                .and_then(|v| v.checked_add(new_pending))
                .ok_or(io::ErrorKind::InvalidData)?;
            directory_bytes = directory_bytes
                .checked_sub(old_observed)
                .and_then(|v| v.checked_add(observed))
                .ok_or(io::ErrorKind::InvalidData)?;
            exceeded |= observed > change.before.bytes;
            *slot = Some((
                change.identity,
                AccountedDirectory {
                    bytes: charged,
                    pending: new_pending,
                    len: metadata.len(),
                    children: change.children,
                    settled: observed <= change.before.bytes,
                    ..change.before
                },
            ));
        }
        promises.set_pending(shared)?;
        state.namespace_generation = self.generation;
        state.bytes = bytes;
        state.pending = pending;
        state.directory_bytes = directory_bytes;
        for (identity, entry) in updated.into_iter().flatten() {
            let current = state
                .accounted
                .get_mut(&identity)
                .and_then(AccountedInode::directory_mut)
                .expect("prepared parent");
            *current = AccountedDirectory {
                live_handles: current.live_handles,
                ..entry
            };
        }
        if exceeded {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "namespace/tests.rs"]
mod tests;
