//! One bounded, retained admission for a complete namespace operation.
//! The witness never owns the reservation; State retains it through abandonment.
use super::{AccountedInode, DiskWork, NamespaceBinding, NodeDisk, NodeDiskPhase, State};
use std::{ffi::CString, io, mem::MaybeUninit, path::Path, sync::Arc};

/// Three missing session directories, two permanent terminal reserves, and the
/// current object. This is an operation shape, not a replacement resource quota.
pub(crate) const MAX_NAMESPACE_PARTS: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NamespacePartKind {
    Directory,
    File { length: u64 },
}

pub(crate) struct NamespacePart<'a> {
    pub root: &'a str,
    pub relative: &'a Path,
    pub kind: NamespacePartKind,
}

enum Backing {
    Directory(Arc<MaybeUninit<super::directory::DirectoryOwner>>),
    File(Arc<MaybeUninit<super::file::FileOwner>>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Progress {
    Reserved,
    Transferred,
}

struct Part {
    // Exact names remain retained even after allocation/extent custody transfers.
    root: String,
    _names: Box<[CString]>,
    binding: NamespaceBinding,
    parent: NamespaceBinding,
    kind: NamespacePartKind,
    bytes: u64,
    backing: Option<Backing>,
    progress: Progress,
}

pub(super) struct BatchRecord {
    id: u64,
    work: DiskWork,
    pub(super) witness_live: bool,
    parts: [Option<Part>; MAX_NAMESPACE_PARTS],
}

impl BatchRecord {
    fn reserved(&self) -> impl Iterator<Item = &Part> {
        self.parts
            .iter()
            .flatten()
            .filter(|p| p.progress == Progress::Reserved)
    }
    pub(super) fn reserved_files(&self) -> u32 {
        self.reserved()
            .filter(|p| matches!(p.kind, NamespacePartKind::File { .. }))
            .count() as u32
    }
    pub(super) fn reserved_directories(&self) -> u32 {
        self.reserved()
            .filter(|p| p.kind == NamespacePartKind::Directory)
            .count() as u32
    }
    pub(super) fn reserved_entries(&self) -> usize {
        self.reserved().count()
    }
    pub(super) fn reserved_children(&self, parent: NamespaceBinding) -> u64 {
        self.reserved().filter(|p| p.parent == parent).count() as u64
    }
}

/// Sole witness. No Clone; every effect needs mutable access to the witness.
pub(crate) struct NamespaceAdmission {
    disk: Arc<NodeDisk>,
    id: u64,
    active: bool,
}

impl Drop for NamespaceAdmission {
    fn drop(&mut self) {
        if self.active {
            let mut state = self.disk.lock_state();
            // A completed census may already have retired this exact record.
            if let Some(batch) = state.namespace_batch.as_mut().filter(|b| b.id == self.id) {
                batch.witness_live = false;
                self.disk.fail_locked(&mut state);
            }
        }
    }
}

impl NamespaceAdmission {
    pub(super) fn same_disk(&self, disk: &Arc<NodeDisk>) -> bool {
        self.active && Arc::ptr_eq(&self.disk, disk)
    }

    fn part_mut<'a>(
        &self,
        state: &'a mut State,
        root: &str,
        binding: NamespaceBinding,
    ) -> io::Result<&'a mut Part> {
        if !self.active || state.phase != NodeDiskPhase::Open {
            return Err(io::ErrorKind::InvalidData.into());
        }
        state
            .namespace_batch
            .as_mut()
            .filter(|b| b.id == self.id)
            .and_then(|b| {
                b.parts
                    .iter_mut()
                    .flatten()
                    .find(|p| p.root == root && p.binding == binding)
            })
            .filter(|p| p.progress == Progress::Reserved)
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }

    pub(super) fn work(&self, state: &State) -> io::Result<DiskWork> {
        state
            .namespace_batch
            .as_ref()
            .filter(|b| b.id == self.id)
            .map(|b| b.work)
            .ok_or_else(|| io::ErrorKind::InvalidInput.into())
    }

    /// Called under the same State guard retained through preparation/effect.
    /// Transfer removes a future slot only when its actual operation takes over.
    pub(super) fn take_file(
        &mut self,
        state: &mut State,
        root: &str,
        binding: NamespaceBinding,
    ) -> io::Result<(Arc<MaybeUninit<super::file::FileOwner>>, u64, u64)> {
        let part = self.part_mut(state, root, binding)?;
        let NamespacePartKind::File { length } = part.kind else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        let Some(Backing::File(allocation)) = part.backing.take() else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        part.progress = Progress::Transferred;
        Ok((allocation, part.bytes, length))
    }

    pub(super) fn take_directory(
        &mut self,
        state: &mut State,
        root: &str,
        binding: NamespaceBinding,
    ) -> io::Result<Arc<MaybeUninit<super::directory::DirectoryOwner>>> {
        let part = self.part_mut(state, root, binding)?;
        if part.kind != NamespacePartKind::Directory {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let Some(Backing::Directory(allocation)) = part.backing.take() else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        part.progress = Progress::Transferred;
        Ok(allocation)
    }

    /// Every promised inode must be present and durably settled at its complete
    /// admitted length before the operation can shed its retained plan backing.
    pub(crate) fn finish(mut self) -> io::Result<()> {
        let mut state = self.disk.lock_state();
        if state.phase != NodeDiskPhase::Open || !self.disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let batch = state
            .namespace_batch
            .as_ref()
            .filter(|b| b.id == self.id)
            .ok_or(io::ErrorKind::InvalidInput)?;
        for part in batch.parts.iter().flatten() {
            if part.progress != Progress::Transferred || part.backing.is_some() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let entry = state
                .accounted
                .values()
                .find(|e| e.binding() == part.binding)
                .ok_or(io::ErrorKind::InvalidData)?;
            let valid = match (part.kind, entry) {
                (NamespacePartKind::Directory, AccountedInode::Directory(entry)) => entry.settled,
                (NamespacePartKind::File { length }, AccountedInode::File(entry)) => {
                    entry.settled && entry.actual_len == length && entry.reserved_len == length
                }
                _ => false,
            };
            if !valid {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        drop(state.namespace_batch.take());
        self.active = false;
        Ok(())
    }

    /// A pristine plan has made no descriptor or namespace effect. Retire actual
    /// names and all preallocated owner control blocks before returning credit.
    #[cfg(test)]
    pub(crate) fn cancel(mut self) -> io::Result<()> {
        let mut state = self.disk.lock_state();
        let batch = state
            .namespace_batch
            .as_ref()
            .filter(|b| b.id == self.id)
            .ok_or(io::ErrorKind::InvalidInput)?;
        let mut credit = 0_u64;
        for part in batch.parts.iter().flatten() {
            if part.progress != Progress::Reserved {
                return Err(io::ErrorKind::InvalidData.into());
            }
            credit = credit
                .checked_add(part.bytes)
                .ok_or(io::ErrorKind::InvalidData)?;
        }
        let bytes = state
            .bytes
            .checked_sub(credit)
            .ok_or(io::ErrorKind::InvalidData)?;
        let pending = state
            .pending
            .checked_sub(credit)
            .ok_or(io::ErrorKind::InvalidData)?;
        let mut device = self.disk.device.lock();
        let shared = device
            .checked_sub(credit)
            .ok_or(io::ErrorKind::InvalidData)?;
        // No physical effect exists. Destroy actual allocations before any
        // shared or local credit. Keep the scalar record if accounting rejects.
        for part in state
            .namespace_batch
            .as_mut()
            .expect("validated batch")
            .parts
            .iter_mut()
            .flatten()
        {
            drop(part.backing.take());
            drop(std::mem::take(&mut part.root));
            drop(std::mem::take(&mut part._names));
        }
        if let Err(error) = device.set_pending(shared) {
            state.phase = NodeDiskPhase::Failed;
            device.fail_owner();
            return Err(error);
        }
        drop(state.namespace_batch.take());
        state.bytes = bytes;
        state.pending = pending;
        self.active = false;
        Ok(())
    }
}

pub(super) fn reserved_files(state: &State) -> u32 {
    state
        .namespace_batch
        .as_ref()
        .map_or(0, BatchRecord::reserved_files)
}
pub(super) fn reserved_directories(state: &State) -> u32 {
    state
        .namespace_batch
        .as_ref()
        .map_or(0, BatchRecord::reserved_directories)
}
pub(super) fn reserved_entries(state: &State) -> usize {
    state
        .namespace_batch
        .as_ref()
        .map_or(0, BatchRecord::reserved_entries)
}
pub(super) fn reserved_binding(state: &State, binding: NamespaceBinding) -> bool {
    state
        .namespace_batch
        .as_ref()
        .is_some_and(|b| b.reserved().any(|p| p.binding == binding))
}
pub(super) fn reserved_children(state: &State, parent: NamespaceBinding) -> u64 {
    state
        .namespace_batch
        .as_ref()
        .map_or(0, |b| b.reserved_children(parent))
}

/// A single physical namespace mutation lane. After the existing State lock,
/// claim contention returns WouldBlock. This bounds admitted path work; worker,
/// ciphertext and stack admission require their own caller envelope.
/// The witness lives from classification through final immutable publication.
pub(super) struct ClaimRecord {
    id: u64,
    binding: NamespaceBinding,
    pub(super) witness_live: bool,
}
pub(crate) struct NamespaceClaim {
    disk: Arc<NodeDisk>,
    id: u64,
    binding: NamespaceBinding,
}
impl Drop for NamespaceClaim {
    fn drop(&mut self) {
        let mut state = self.disk.lock_state();
        if state
            .namespace_claim
            .as_ref()
            .is_none_or(|claim| claim.id != self.id || claim.binding != self.binding)
        {
            return;
        }
        if state.phase == NodeDiskPhase::Open
            && state.namespace_batch.is_none()
            && state.pending_directory.is_none()
        {
            // Session put declares this witness before its owned paths and
            // directory/file owners, which retire before this lane is credited.
            // Returned errors and caller-owned inputs have separate lifetimes.
            state.namespace_claim = None;
        } else {
            state
                .namespace_claim
                .as_mut()
                .expect("matching claim")
                .witness_live = false;
            self.disk.fail_locked(&mut state);
        }
    }
}

impl NodeDisk {
    pub(super) fn claim_binding_namespace(
        self: &Arc<Self>,
        state: &mut State,
        binding: NamespaceBinding,
    ) -> io::Result<NamespaceClaim> {
        if state.phase != NodeDiskPhase::Open || !self.device.lock().admission_ready() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if state.namespace_claim.is_some()
            || state.namespace_batch.is_some()
            || state.pending_directory.is_some()
        {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let id = state
            .namespace_batch_generation
            .checked_add(1)
            .ok_or(io::ErrorKind::StorageFull)?;
        state.namespace_batch_generation = id;
        state.namespace_claim = Some(ClaimRecord {
            id,
            binding,
            witness_live: true,
        });
        Ok(NamespaceClaim {
            disk: self.clone(),
            id,
            binding,
        })
    }

    /// Admit the complete finite missing set. Callers resolve existing enrolled
    /// prefixes first; a missing parent must appear earlier as a directory part.
    pub(crate) fn admit_namespace(
        self: &Arc<Self>,
        requests: &[NamespacePart<'_>],
        work: DiskWork,
    ) -> io::Result<NamespaceAdmission> {
        self.admit_namespace_inner(requests, work, None)
    }

    pub(crate) fn admit_claimed_namespace(
        self: &Arc<Self>,
        claim: &NamespaceClaim,
        requests: &[NamespacePart<'_>],
        work: DiskWork,
    ) -> io::Result<NamespaceAdmission> {
        if !Arc::ptr_eq(self, &claim.disk) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.admit_namespace_inner(requests, work, Some(claim.id))
    }

    fn admit_namespace_inner(
        self: &Arc<Self>,
        requests: &[NamespacePart<'_>],
        work: DiskWork,
        claim: Option<u64>,
    ) -> io::Result<NamespaceAdmission> {
        let mut state = self.lock_state();
        if state.namespace_claim.as_ref().map(|claim| claim.id) != claim {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if state.namespace_batch.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if state.phase != NodeDiskPhase::Open
            || state.pending_directory.is_some()
            || requests.is_empty()
            || requests.len() > MAX_NAMESPACE_PARTS
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Reject logical owner/cardinality shortages before allocating any
        // future Arc. The installed owner envelopes fund only available H/D slots.
        let files = requests
            .iter()
            .filter(|part| matches!(part.kind, NamespacePartKind::File { .. }))
            .count() as u32;
        let directories = requests
            .iter()
            .filter(|part| part.kind == NamespacePartKind::Directory)
            .count() as u32;
        let roots = u64::try_from(self.roots.len()).map_err(|_| io::ErrorKind::InvalidData)?;
        if state
            .files
            .checked_add(u64::from(files))
            .is_none_or(|n| n > self.config.max_persistent_files)
            || state
                .directories
                .checked_sub(roots)
                .and_then(|n| n.checked_add(u64::from(directories)))
                .is_none_or(|n| n > self.config.max_persistent_subdirectories)
            || state
                .open_files
                .checked_add(files)
                .is_none_or(|n| n > self.config.max_open_files)
            || state
                .open_directories
                .checked_add(directories)
                .is_none_or(|n| n > self.config.max_open_directories)
        {
            return Err(io::ErrorKind::StorageFull.into());
        }
        let id = state
            .namespace_batch_generation
            .checked_add(1)
            .ok_or(io::ErrorKind::StorageFull)?;
        let mut record = BatchRecord {
            id,
            work,
            witness_live: true,
            parts: std::array::from_fn(|_| None),
        };
        let mut bytes = 0_u64;
        for (index, request) in requests.iter().enumerate() {
            let root = self
                .roots
                .get(request.root)
                .ok_or(io::ErrorKind::InvalidInput)?;
            let names = super::directory::names(
                request.relative,
                self.config.max_depth,
                self.config.max_name_bytes,
            )?;
            if names.is_empty() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let mut binding = NamespaceBinding::root(root.identity);
            let mut parent = binding;
            for name in &names {
                parent = binding;
                binding = binding.child(name);
            }
            if state.accounted.values().any(|e| e.binding() == binding)
                || record.parts.iter().flatten().any(|p| p.binding == binding)
            {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            let parent_enrolled = state.accounted.values().find(|e| e.binding() == parent);
            match parent_enrolled {
                Some(AccountedInode::Directory(entry)) if entry.settled => (),
                None if record
                    .parts
                    .iter()
                    .flatten()
                    .any(|p| p.binding == parent && p.kind == NamespacePartKind::Directory) => {}
                _ => return Err(io::ErrorKind::InvalidData.into()),
            }
            let count = parent_enrolled
                .and_then(AccountedInode::directory)
                .map_or(0, |e| e.children)
                .checked_add(
                    record
                        .parts
                        .iter()
                        .flatten()
                        .filter(|p| p.parent == parent)
                        .count() as u64,
                )
                .and_then(|n| n.checked_add(1))
                .ok_or(io::ErrorKind::StorageFull)?;
            if count > self.config.directory_policy.max_entries {
                return Err(io::ErrorKind::StorageFull.into());
            }
            let (part_bytes, backing) = match request.kind {
                NamespacePartKind::Directory => (
                    self.config.directory_policy.extent_bytes,
                    Backing::Directory(Arc::new_uninit()),
                ),
                NamespacePartKind::File { length } => {
                    if length > i64::MAX as u64 {
                        return Err(io::ErrorKind::InvalidInput.into());
                    }
                    (
                        super::rounded(length, self.unit)?,
                        Backing::File(Arc::new_uninit()),
                    )
                }
            };
            bytes = bytes
                .checked_add(part_bytes)
                .ok_or(io::ErrorKind::StorageFull)?;
            record.parts[index] = Some(Part {
                root: request.root.to_owned(),
                _names: names,
                binding,
                parent,
                kind: request.kind,
                bytes: part_bytes,
                backing: Some(backing),
                progress: Progress::Reserved,
            });
        }
        state.accounted.try_reserve(requests.len())?;
        state.live.try_reserve(files as usize)?;
        // All bounded names and actual owner Arc backing exist before aggregate
        // byte admission and before the first future native descriptor effect.
        self.reserve(&mut state, bytes, work)?;
        state.namespace_batch_generation = id;
        state.namespace_batch = Some(record);
        Ok(NamespaceAdmission {
            disk: self.clone(),
            id,
            active: true,
        })
    }
}

#[cfg(test)]
mod tests;
