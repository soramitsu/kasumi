//! Multi-file NodeDisk owner for one segmented kv log.
//!
//! The store path of a group is one enrolled directory. It holds
//! `root.kvroot` and create-only segment and checkpoint files spelled exactly
//! as the kv group contract names them. Every file begins with a 4 KiB
//! envelope under `KASUMI-NODE-SEG1` that binds it to the installed store
//! identity, its kind and its identifier; the kv bytes follow. The root
//! envelope carries the Prepared/Ready discriminator and is followed by the
//! two kv root slots. Like the single-file envelope, the discriminator and
//! checksum are not authentication: the caller supplies the expected
//! installed identity before any recognized payload is served.
//!
//! A data file is created empty through `NodeDisk::create_file`, which
//! synchronizes the new name. Its envelope is written and synchronized before
//! the first kv byte, so after any crash a data file either carries its exact
//! envelope or holds at most 4 KiB of a prefix of it, each byte zero or as
//! written. Only the next kv mutation completes such an interrupted envelope;
//! reopen never writes. Any other image, including the single-file node
//! envelope, the single-file kv image, another installation's envelope, a
//! subdirectory or an unparsable name, fails closed before any mutation.
//! Identifiers come from the kv root's durable intents; this owner refuses an
//! identifier at or below the highest one it has observed for that kind.
//!
//! At most `cache` data descriptors are open at once besides the root.
//! Eviction settles and closes the least recently used descriptor that holds
//! no admitted growth; a failed close keeps that exact owner in its slot,
//! never dropped or reused, and fences the group. Unlink consumes the exact
//! verified owner through `NodeDisk::delete_file`, which credits space only
//! after the confirmed unlink and parent synchronization; an uncertain unlink
//! leaves the charge and owner with NodeDisk. Any uncertain effect latches the
//! group and its NodeDisk as failed until every owner drains, a fresh census
//! is accepted and the group reopens strictly.
use super::{FailedCloseReport, FailedFileTransfer, FailedFileWitness};
use crate::node_disk::NodeDiskCloseOutcome;
use crate::storage_census::{StorageOwnerKind, StoragePayload};
use crate::storage_opening::NodeOpeningMode;
use crate::{
    CensusCancellation, DiskMemoryLease, DiskWork, NodeDisk, NodeDiskDirectory, NodeDiskEntryKind,
    NodeDiskFile, private_files::FileIdentity,
};
use anyhow::{Context, Result, ensure};
use kasumi_kv::{
    AdmissionError, BackendCloseEntry, BackendCloseOutcome, BackendNativeDisposition, OwnerFailed,
    StorageAdmission,
};
use parking_lot::{RwLock, RwLockWriteGuard};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CString, OsString},
    io,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use uuid::Uuid;

const HEADER_BYTES: usize = 4096;
// Every field and the checksum share the first 512-byte sector, so rewriting
// Prepared as Ready is one sector write: a torn rewrite leaves either
// complete image, never a checksum that matches neither.
const CHECKSUM_AT: usize = 48;
const CHECKSUM_END: usize = CHECKSUM_AT + 32;
const MAGIC: &[u8; 16] = b"KASUMI-NODE-SEG1";
const PREPARED: u8 = 1;
const READY: u8 = 2;
const ROOT_KIND: u8 = 1;
const SEGMENT_KIND: u8 = 2;
const CHECKPOINT_KIND: u8 = 3;
/// The kv root holds two fixed superblock slots after the root envelope.
pub(crate) const ROOT_SLOT_BYTES: usize = 4096;
const ROOT_FILE_BYTES: u64 = (HEADER_BYTES + 2 * ROOT_SLOT_BYTES) as u64;
pub(crate) const ROOT_FILE_NAME: &str = "root.kvroot";
/// Bounds the fixed descriptor cache; NodeDisk still enforces its own budget.
pub(crate) const MAX_CACHED_FILES: usize = 4096;
// A listing restarts only when another owner's namespace effect raced it.
const LIST_ATTEMPTS: usize = 8;

/// A group file kind. The spelling mirrors the kv group contract exactly, so
/// the directory listing is the kv census input without translation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum GroupFileKind {
    Segment,
    Checkpoint,
}
impl GroupFileKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Segment => ".kvseg",
            Self::Checkpoint => ".kvckpt",
        }
    }
    fn envelope_kind(self) -> u8 {
        match self {
            Self::Segment => SEGMENT_KIND,
            Self::Checkpoint => CHECKPOINT_KIND,
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Segment => 0,
            Self::Checkpoint => 1,
        }
    }
}

/// One owned data file. Identifier zero is never allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct GroupFile {
    pub(crate) kind: GroupFileKind,
    pub(crate) id: u64,
}
impl GroupFile {
    pub(crate) const fn segment(id: u64) -> Self {
        Self {
            kind: GroupFileKind::Segment,
            id,
        }
    }
    pub(crate) const fn checkpoint(id: u64) -> Self {
        Self {
            kind: GroupFileKind::Checkpoint,
            id,
        }
    }
    /// Sixteen lowercase hexadecimal digits: an identifier has one spelling.
    pub(crate) fn file_name(self) -> String {
        format!("{:016x}{}", self.id, self.kind.suffix())
    }
    pub(crate) fn parse_name(name: &str) -> Option<Self> {
        let (digits, kind) =
            if let Some(digits) = name.strip_suffix(GroupFileKind::Segment.suffix()) {
                (digits, GroupFileKind::Segment)
            } else {
                (
                    name.strip_suffix(GroupFileKind::Checkpoint.suffix())?,
                    GroupFileKind::Checkpoint,
                )
            };
        if digits.len() != 16
            || !digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        let id = u64::from_str_radix(digits, 16).ok()?;
        (id != 0).then_some(Self { kind, id })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootSlot {
    A,
    B,
}
impl RootSlot {
    fn offset(self) -> u64 {
        let index = match self {
            Self::A => 0,
            Self::B => 1,
        };
        (HEADER_BYTES + index * ROOT_SLOT_BYTES) as u64
    }
}

fn envelope(id: Uuid, kind: u8, state: u8, file_id: u64) -> [u8; HEADER_BYTES] {
    let mut bytes = [0; HEADER_BYTES];
    bytes[..16].copy_from_slice(MAGIC);
    bytes[16..32].copy_from_slice(id.as_bytes());
    bytes[32] = kind;
    bytes[33] = state;
    bytes[40..48].copy_from_slice(&file_id.to_le_bytes());
    let digest = Sha256::digest(&bytes[..CHECKSUM_AT]);
    bytes[CHECKSUM_AT..CHECKSUM_END].copy_from_slice(&digest);
    bytes
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Return the recognized state of an exact envelope of this file.
fn validate_envelope(
    bytes: &[u8; HEADER_BYTES],
    id: Uuid,
    kind: u8,
    file_id: u64,
) -> io::Result<u8> {
    if &bytes[..16] != MAGIC {
        return Err(invalid("unsupported segment group file format"));
    }
    if bytes[CHECKSUM_AT..CHECKSUM_END] != Sha256::digest(&bytes[..CHECKSUM_AT])[..] {
        return Err(invalid("segment group envelope checksum differs"));
    }
    if &bytes[16..32] != id.as_bytes() {
        return Err(invalid("installed node store identity differs"));
    }
    if bytes[32] != kind || bytes[40..48] != file_id.to_le_bytes() {
        return Err(invalid("segment group envelope names another file"));
    }
    if bytes[34..40].iter().any(|byte| *byte != 0)
        || bytes[CHECKSUM_END..].iter().any(|byte| *byte != 0)
    {
        return Err(invalid("unsupported segment group envelope fields"));
    }
    Ok(bytes[33])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Envelope {
    Complete,
    /// At most one envelope of a prefix of this file's own envelope, each byte
    /// zero or as written. Its kv length is zero.
    Interrupted,
}

/// Classify a data file's envelope through its verified descriptor.
fn inspect(handle: &NodeDiskFile, id: Uuid, file: GroupFile) -> io::Result<Envelope> {
    let len = handle.observed_len()?;
    if len > i64::MAX as u64 {
        return Err(invalid("segment group file length is invalid"));
    }
    let mut bytes = [0; HEADER_BYTES];
    let visible = len.min(HEADER_BYTES as u64) as usize;
    handle.read_exact_at(&mut bytes[..visible], 0)?;
    let kind = file.kind.envelope_kind();
    let recognized = if visible == HEADER_BYTES {
        match validate_envelope(&bytes, id, kind, file.id) {
            Ok(READY) => return Ok(Envelope::Complete),
            Ok(_) => Err(invalid("segment group file state is unsupported")),
            Err(error) => Err(error),
        }
    } else {
        Err(invalid("segment group file envelope is incomplete"))
    };
    let expected = envelope(id, kind, READY, file.id);
    if len <= HEADER_BYTES as u64
        && bytes[..visible]
            .iter()
            .zip(expected)
            .all(|(&byte, expected)| byte == 0 || byte == expected)
    {
        return Ok(Envelope::Interrupted);
    }
    recognized
}

fn physical(at: u64, len: usize) -> io::Result<u64> {
    at.checked_add(len as u64)
        .and_then(|end| end.checked_add(HEADER_BYTES as u64))
        .filter(|end| *end <= i64::MAX as u64)
        .ok_or_else(|| io::ErrorKind::InvalidInput.into())
}

struct Entry {
    file: GroupFile,
    envelope: Envelope,
    // Recorded at the first verified acquisition. A later acquisition through
    // the same name must reach this exact inode.
    identity: FileIdentity,
    slot: Option<usize>,
}

/// One fixed descriptor cache cell. A failed close keeps its exact owner here
/// until failed-owner transfer; the cell is never reused while it does.
#[derive(Default)]
struct Slot {
    file: Option<GroupFile>,
    handle: Option<NodeDiskFile>,
    used: AtomicU64,
    // Written or grown since the last settlement; closing requires settlement.
    dirty: AtomicBool,
    failed: bool,
}

struct Resources {
    directory: Option<NodeDiskDirectory>,
    root: Option<NodeDiskFile>,
    root_failed: bool,
    entries: Vec<Entry>,
    // Admits the entry table's current capacity.
    charge: Option<DiskMemoryLease>,
    high_water: [u64; 2],
    // The file holding growth admitted through `StorageAdmission`. Its slot is
    // pinned until that growth settles.
    growth_target: Option<GroupFile>,
    // Close entered or acquisition failed: only close and failed-owner
    // transfer remain.
    sealed: bool,
}
impl Resources {
    fn position(&self, file: GroupFile) -> Option<usize> {
        self.entries
            .binary_search_by_key(&file, |entry| entry.file)
            .ok()
    }
    fn directory(&self) -> io::Result<&NodeDiskDirectory> {
        self.directory
            .as_ref()
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }
    fn root(&self) -> io::Result<&NodeDiskFile> {
        self.root
            .as_ref()
            .ok_or_else(|| io::ErrorKind::BrokenPipe.into())
    }
}

enum Phase {
    Prepared,
    Acquiring,
    Open(Resources),
    Closed,
    FailedTransferred,
}

struct GroupState {
    phase: Phase,
    slots: Box<[Slot]>,
    // Receipts of failed owners moved into NodeDisk custody, one per slot plus
    // the root, admitted with the group backing.
    transfers: Vec<FailedFileTransfer>,
}
impl GroupState {
    fn open(&self) -> io::Result<&Resources> {
        match &self.phase {
            Phase::Open(resources) if !resources.sealed => Ok(resources),
            _ => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
    fn open_mut(&mut self) -> io::Result<(&mut Resources, &mut [Slot])> {
        match &mut self.phase {
            Phase::Open(resources) if !resources.sealed => Ok((resources, &mut self.slots)),
            _ => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

/// The terminal witnesses of every failed-close owner the group retains.
pub(crate) struct GroupFailedWitness(Vec<(Option<usize>, FailedFileWitness)>);

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GroupFault {
    /// Report failure after NodeDisk created and synchronized the empty name.
    CreateAfterEffect,
    /// Write only this many envelope bytes, then report failure.
    TornEnvelope(usize),
    /// Report failure after the confirmed unlink and parent synchronization.
    UnlinkAfterEffect,
    /// Fail a directory synchronization before it is entered.
    NamesBeforeEffect,
}

#[derive(Clone, Copy)]
enum Acquisition<'a> {
    Opening(&'a NodeOpeningMode),
    Cleanup,
}

/// Physical descriptor custody only. The caller must independently establish
/// permanent stop, issuer drain and worker/storage drain before deleting a
/// group. Retain this guard through every exact unlink.
pub(crate) struct NodeSegmentGroupCleanup {
    owner: Arc<NodeSegmentGroup>,
}
impl NodeSegmentGroupCleanup {
    /// Unlink every data file, then the root, then the empty directory, each
    /// through its verified owner with its parent synchronization. A failure
    /// fences the group and its disk; after a fresh census the names that
    /// remain are claimed again.
    pub(crate) fn delete(self) -> Result<()> {
        let owner = &self.owner;
        let mut guard = owner.state.write();
        let (resources, slots) = guard.open_mut()?;
        while let Some(last) = resources.entries.len().checked_sub(1) {
            owner.unlink_entry(resources, slots, last)?;
        }
        if let Some(root) = resources.root.take() {
            owner.effect(owner.disk.delete_file(root))?;
        }
        let directory = resources
            .directory
            .take()
            .context("segment group directory is not owned")?;
        owner.effect(directory.remove_if_empty())?;
        guard.phase = Phase::Closed;
        Ok(())
    }
}

pub(crate) struct NodeSegmentGroup {
    // Descriptor operations run under the shared lock; cache changes, create,
    // unlink, shrink and close take it exclusively, so an evicted or closed
    // descriptor has no running operation.
    state: RwLock<GroupState>,
    disk: Arc<NodeDisk>,
    path: PathBuf,
    id: Uuid,
    failed: AtomicBool,
    clock: AtomicU64,
    #[cfg(test)]
    fault: parking_lot::Mutex<Option<GroupFault>>,
}

impl std::fmt::Debug for NodeSegmentGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeSegmentGroup")
            .field("id", &self.id)
            .field("path", &self.path)
            .field("failed", &self.failed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl NodeSegmentGroup {
    /// Concrete backing charged before this prepared group and its fixed
    /// descriptor cache are constructed. The entry table is charged as it
    /// grows; open descriptors are NodeDisk's own admitted owners.
    pub(crate) fn prepared_backing_bytes(path: &Path, cache: usize) -> io::Result<u64> {
        use crate::disk_memory::{add, allocation, arc, overflow};
        if cache == 0 || cache > MAX_CACHED_FILES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let cache = u64::try_from(cache).map_err(|_| overflow())?;
        add(
            add(
                arc::<Self>()?,
                allocation::<u8>(u64::try_from(path.as_os_str().len()).map_err(|_| overflow())?)?,
            )?,
            add(
                allocation::<Slot>(cache)?,
                allocation::<FailedFileTransfer>(add(cache, 1)?)?,
            )?,
        )
    }

    /// Allocation only; no filesystem effect precedes `acquire_prepared`.
    fn prepared(path: &Path, id: Uuid, disk: Arc<NodeDisk>, cache: usize) -> Self {
        let slots = (0..cache).map(|_| Slot::default()).collect();
        Self {
            state: RwLock::new(GroupState {
                phase: Phase::Prepared,
                slots,
                transfers: Vec::with_capacity(cache + 1),
            }),
            disk,
            path: path.to_owned(),
            id,
            failed: AtomicBool::new(false),
            clock: AtomicU64::new(0),
            #[cfg(test)]
            fault: parking_lot::Mutex::new(None),
        }
    }

    /// Allocation only, after `prepared_backing_bytes` was admitted.
    pub(crate) fn retained_prepared(
        path: &Path,
        id: Uuid,
        disk: Arc<NodeDisk>,
        cache: usize,
    ) -> Arc<Self> {
        Arc::new(Self::prepared(path, id, disk, cache))
    }

    /// Charge and publish the prepared group as its own census owner before
    /// any filesystem effect. The census retains it until close drains every
    /// descriptor or its failed owners' transfer is accepted by a census.
    pub(crate) fn register(
        path: &Path,
        id: Uuid,
        disk: Arc<NodeDisk>,
        cache: usize,
    ) -> io::Result<crate::storage_census::StorageRegistration<Self>> {
        if id.is_nil() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let provider = disk.memory().clone();
        let backing = Self::prepared_backing_bytes(path, cache)?;
        provider
            .storage_census()
            .register(provider.clone(), backing, || {
                Self::prepared(path, id, disk, cache)
            })
    }

    pub(crate) fn acquire_prepared(&self, mode: &NodeOpeningMode) -> Result<()> {
        self.acquire(Acquisition::Opening(mode))
    }

    /// Claim an exact recognized Prepared or Ready group, or the empty
    /// directory an interrupted cleanup left behind, for independently
    /// authorized cleanup. Every entry is verified before any is deleted;
    /// no kv open, initialization or repair takes place.
    pub(crate) fn claim_cleanup(
        path: &Path,
        expected_id: Uuid,
        disk: Arc<NodeDisk>,
        cache: usize,
    ) -> Result<NodeSegmentGroupCleanup> {
        Self::prepared_backing_bytes(path, cache)?;
        let owner = Self::retained_prepared(path, expected_id, disk, cache);
        if let Err(error) = owner.acquire(Acquisition::Cleanup) {
            // Every descriptor the refused claim acquired drains explicitly.
            let closed = owner.close();
            return Err(match closed.into_result() {
                Ok(()) => error,
                Err(close) => error.context(close),
            });
        }
        Ok(NodeSegmentGroupCleanup { owner })
    }

    fn acquire(&self, acquisition: Acquisition<'_>) -> Result<()> {
        ensure!(!self.id.is_nil(), "node store identity is nil");
        let mut guard = self
            .state
            .try_write()
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        ensure!(
            matches!(guard.phase, Phase::Prepared),
            "segment group acquisition already entered"
        );
        // The phase changes before any descriptor effect. Failure or unwind
        // cannot make an absent descriptor authorize a second acquisition.
        guard.phase = Phase::Acquiring;
        let (root, relative) = self.disk.binding(&self.path)?;
        let directory = match acquisition {
            Acquisition::Opening(NodeOpeningMode::Create) => {
                let name = relative
                    .file_name()
                    .context("segment group path has no final component")?;
                let name = CString::new(name.as_bytes())?;
                let parent = relative.parent().unwrap_or(Path::new(""));
                self.disk
                    .open_directory(root, parent)?
                    .create_child(&name, DiskWork::Foreground)?
            }
            Acquisition::Opening(NodeOpeningMode::OwnedEmpty(_) | NodeOpeningMode::Existing)
            | Acquisition::Cleanup => {
                // Read-only classification only. A single-file store at this
                // path is refused before NodeDisk opens it as a directory,
                // which would fence the whole owner for a mismatched kind.
                let metadata = std::fs::symlink_metadata(&self.path)?;
                ensure!(
                    metadata.is_dir(),
                    "segment group path is not a directory; the single-file node format is unsupported"
                );
                self.disk.open_directory(root, relative)?
            }
        };
        // Custody precedes validation, so every acquired descriptor stays
        // owned by this group until its explicit close.
        guard.phase = Phase::Open(Resources {
            directory: Some(directory),
            root: None,
            root_failed: false,
            entries: Vec::new(),
            charge: None,
            high_water: [0; 2],
            growth_target: None,
            sealed: true,
        });
        let GroupState { phase, slots, .. } = &mut *guard;
        let Phase::Open(resources) = phase else {
            unreachable!("installed group resources")
        };
        let root_path = relative.join(ROOT_FILE_NAME);
        match acquisition {
            Acquisition::Opening(NodeOpeningMode::Create) => {
                resources.root = Some(self.disk.create_file(
                    root,
                    &root_path,
                    DiskWork::Foreground,
                )?);
                self.prepare_root(resources)?;
            }
            Acquisition::Opening(NodeOpeningMode::OwnedEmpty(identity)) => {
                let listed = self.list()?;
                ensure!(
                    listed.len() == 1
                        && listed[0].0.as_bytes() == ROOT_FILE_NAME.as_bytes()
                        && listed[0].1 == NodeDiskEntryKind::File,
                    "prepared segment group directory holds other entries"
                );
                resources.root = Some(self.disk.open_file(root, &root_path)?);
                let file = resources.root()?;
                file.check_owner()?;
                ensure!(
                    &file.identity()? == identity,
                    "prepared segment group root identity differs"
                );
                self.prepare_root(resources)?;
            }
            Acquisition::Opening(NodeOpeningMode::Existing) => {
                resources.root = Some(self.disk.open_file(root, &root_path)?);
                self.verify_root(resources, &[READY])?;
                self.census(resources, slots)?;
            }
            Acquisition::Cleanup => {
                // Only an interrupted cleanup leaves an empty directory; it
                // holds nothing to recognize or to lose.
                if !self.list()?.is_empty() {
                    resources.root = Some(self.disk.open_file(root, &root_path)?);
                    self.verify_root(resources, &[PREPARED, READY])?;
                    self.census(resources, slots)?;
                }
            }
        }
        resources.sealed = false;
        Ok(())
    }

    fn prepare_root(&self, resources: &Resources) -> Result<()> {
        let file = resources.root()?;
        ensure!(
            file.observed_len()? == 0,
            "segment group initialization requires an empty root inode"
        );
        file.reserve_growth(0, ROOT_FILE_BYTES, DiskWork::Foreground)?;
        file.grow_reserved(ROOT_FILE_BYTES)?;
        file.write_all_at(&envelope(self.id, ROOT_KIND, PREPARED, 0), 0)?;
        file.sync_all_and_parent()?;
        Ok(())
    }

    fn verify_root(&self, resources: &Resources, states: &[u8]) -> Result<u8> {
        let file = resources.root()?;
        file.check_owner()?;
        ensure!(
            file.observed_len()? == ROOT_FILE_BYTES,
            "segment group root length is invalid"
        );
        let mut bytes = [0; HEADER_BYTES];
        file.read_exact_at(&mut bytes, 0)?;
        let state = validate_envelope(&bytes, self.id, ROOT_KIND, 0)?;
        ensure!(
            states.contains(&state),
            "segment group initialization is incomplete or unsupported"
        );
        Ok(state)
    }

    /// Verify every directory entry before any is served: the root, then each
    /// data file's name, inode and envelope. The cache stays bounded, so a
    /// group of any size reopens through at most `cache` descriptors.
    fn census(&self, resources: &mut Resources, slots: &mut [Slot]) -> Result<()> {
        let mut files = Vec::new();
        let mut root = false;
        for (name, kind) in self.list()? {
            ensure!(
                kind == NodeDiskEntryKind::File,
                "segment group directory holds a subdirectory"
            );
            if name.as_bytes() == ROOT_FILE_NAME.as_bytes() {
                root = true;
                continue;
            }
            let file = name
                .to_str()
                .ok()
                .and_then(GroupFile::parse_name)
                .context("segment group directory holds an entry that is not a group file")?;
            files.try_reserve(1)?;
            files.push(file);
        }
        ensure!(root, "segment group root file is missing");
        files.sort_unstable();
        self.reserve_entries(resources, files.len())?;
        for file in files {
            let slot = self.free_slot(resources, slots)?;
            let identity = self.load(slots, slot, file)?;
            let envelope = inspect(
                slots[slot].handle.as_ref().expect("loaded descriptor"),
                self.id,
                file,
            )?;
            resources.entries.push(Entry {
                file,
                envelope,
                identity,
                slot: Some(slot),
            });
            let high = &mut resources.high_water[file.kind.index()];
            *high = (*high).max(file.id);
        }
        Ok(())
    }

    /// Durably mark the group Ready once the kv engine published its first
    /// root. A failure is an uncertain create; it never authorizes truncation,
    /// recreation or adoption on retry.
    pub(crate) fn publish_ready(&self) -> Result<()> {
        let guard = self.state.write();
        let resources = guard.open()?;
        self.verify_root(resources, &[PREPARED])?;
        let file = resources.root()?;
        let mut slot = [0; ROOT_SLOT_BYTES];
        let mut published = false;
        for root_slot in [RootSlot::A, RootSlot::B] {
            file.read_exact_at(&mut slot, root_slot.offset())?;
            published |= slot.iter().any(|byte| *byte != 0);
        }
        ensure!(published, "segment group root is unpublished");
        let outcome = (|| {
            file.sync_all()?;
            file.write_all_at(&envelope(self.id, ROOT_KIND, READY, 0), 0)?;
            file.sync_all_and_parent()
        })();
        Ok(self.effect(outcome)?)
    }

    pub(crate) fn disk(&self) -> &Arc<NodeDisk> {
        &self.disk
    }

    #[cfg(test)]
    pub(crate) fn inject(&self, fault: GroupFault) {
        *self.fault.lock() = Some(fault);
    }

    #[cfg(test)]
    fn faulted(&self, fault: GroupFault) -> bool {
        let mut armed = self.fault.lock();
        if *armed == Some(fault) {
            *armed = None;
            return true;
        }
        false
    }

    #[cfg(test)]
    fn torn_envelope(&self) -> Option<usize> {
        let mut armed = self.fault.lock();
        if let Some(GroupFault::TornEnvelope(bytes)) = *armed {
            *armed = None;
            return Some(bytes);
        }
        None
    }

    /// Open data descriptors, excluding the root.
    #[cfg(test)]
    pub(crate) fn cached_files(&self) -> usize {
        self.state
            .read()
            .slots
            .iter()
            .filter(|slot| slot.handle.is_some())
            .count()
    }

    #[cfg(test)]
    pub(crate) fn retained_failed_files(&self) -> usize {
        let guard = self.state.read();
        let root = match &guard.phase {
            Phase::Open(resources) => usize::from(resources.root_failed),
            _ => 0,
        };
        root + guard.slots.iter().filter(|slot| slot.failed).count()
    }

    fn fence(&self) {
        self.failed.store(true, Ordering::Release);
        self.disk.fail();
    }

    /// Every error after an effect was entered leaves its outcome unknown.
    fn effect<T>(&self, result: io::Result<T>) -> io::Result<T> {
        result.inspect_err(|_| self.fence())
    }

    fn require_healthy(&self) -> io::Result<()> {
        if self.failed.load(Ordering::Acquire) {
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }

    fn binding(&self) -> io::Result<(&str, &Path)> {
        self.disk
            .binding(&self.path)
            .map_err(|_| io::ErrorKind::InvalidInput.into())
    }

    fn tick(&self) -> u64 {
        self.clock.fetch_add(1, Ordering::Relaxed)
    }

    /// Admit the entry table's growth before it allocates. Denial is a
    /// recoverable capacity result with no effect.
    fn reserve_entries(&self, resources: &mut Resources, additional: usize) -> io::Result<()> {
        let needed = resources
            .entries
            .len()
            .checked_add(additional)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        if needed <= resources.entries.capacity() {
            return Ok(());
        }
        let capacity = needed
            .max(resources.entries.capacity().saturating_mul(2))
            .max(16);
        let bytes = crate::disk_memory::allocation::<Entry>(
            u64::try_from(capacity).map_err(|_| io::ErrorKind::OutOfMemory)?,
        )?;
        let charge = self.disk.memory().clone().reserve_installed(bytes)?;
        resources
            .entries
            .try_reserve_exact(capacity - resources.entries.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        // The previous charge covered the allocation this reservation replaced.
        resources.charge = Some(charge);
        Ok(())
    }

    /// A vacant cache cell, closing the least recently used unpinned
    /// descriptor when every cell is occupied.
    fn free_slot(&self, resources: &mut Resources, slots: &mut [Slot]) -> io::Result<usize> {
        if let Some(index) = slots
            .iter()
            .position(|slot| slot.handle.is_none() && !slot.failed)
        {
            return Ok(index);
        }
        let victim = slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| {
                !slot.failed && slot.handle.is_some() && slot.file != resources.growth_target
            })
            .min_by_key(|(_, slot)| slot.used.load(Ordering::Relaxed))
            .map(|(index, _)| index)
            .ok_or(io::ErrorKind::StorageFull)?;
        self.evict(resources, &mut slots[victim])?;
        Ok(victim)
    }

    fn evict(&self, resources: &mut Resources, slot: &mut Slot) -> io::Result<()> {
        let handle = slot.handle.as_mut().expect("occupied cache cell");
        if slot.dirty.load(Ordering::Acquire) {
            // Closing needs a settled extent. This synchronizes the file and
            // credits only growth it did not use.
            let settled = handle
                .observed_len()
                .and_then(|len| handle.settle_growth(len));
            self.effect(settled)?;
            slot.dirty.store(false, Ordering::Release);
        }
        match handle.close_attested() {
            NodeDiskCloseOutcome::NotEntered(error) => Err(error),
            NodeDiskCloseOutcome::Entered(Ok(())) => {
                let file = slot.file.take().expect("occupied cache cell");
                slot.handle = None;
                if let Some(position) = resources.position(file) {
                    resources.entries[position].slot = None;
                }
                Ok(())
            }
            NodeDiskCloseOutcome::Entered(Err(error)) => {
                // The exact owner and its original outcome stay in this cell.
                slot.failed = true;
                self.fence();
                Err(error)
            }
        }
    }

    /// Open one data file into a vacant cell and bind its inode.
    fn load(&self, slots: &mut [Slot], index: usize, file: GroupFile) -> io::Result<FileIdentity> {
        let (root, relative) = self.binding()?;
        let handle = match self.disk.open_file(root, &relative.join(file.file_name())) {
            Ok(handle) => handle,
            // Descriptor and ledger budgets are checked before any effect.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::StorageFull | io::ErrorKind::OutOfMemory
                ) =>
            {
                return Err(error);
            }
            Err(error) => {
                self.fence();
                return Err(error);
            }
        };
        let slot = &mut slots[index];
        slot.file = Some(file);
        slot.handle = Some(handle);
        slot.used.store(self.tick(), Ordering::Relaxed);
        slot.dirty.store(false, Ordering::Release);
        let handle = slot.handle.as_ref().expect("loaded descriptor");
        self.effect(handle.check_owner().and_then(|()| handle.identity()))
    }

    /// The cell holding this recorded file's verified descriptor.
    fn cached(
        &self,
        resources: &mut Resources,
        slots: &mut [Slot],
        position: usize,
    ) -> io::Result<usize> {
        if let Some(index) = resources.entries[position].slot {
            slots[index].used.store(self.tick(), Ordering::Relaxed);
            return Ok(index);
        }
        let file = resources.entries[position].file;
        let index = self.free_slot(resources, slots)?;
        let identity = self.load(slots, index, file)?;
        let envelope = inspect(
            slots[index].handle.as_ref().expect("loaded descriptor"),
            self.id,
            file,
        );
        // Only this owner changes names and envelopes, so a reacquired file
        // must be the same inode in the same recorded state.
        let entry = &mut resources.entries[position];
        if identity != entry.identity || envelope.as_ref().ok() != Some(&entry.envelope) {
            self.fence();
            return Err(envelope
                .err()
                .unwrap_or_else(|| invalid("segment group file was substituted")));
        }
        entry.slot = Some(index);
        Ok(index)
    }

    /// Write and synchronize this file's envelope before any kv byte.
    fn complete_envelope(
        &self,
        resources: &mut Resources,
        slots: &mut [Slot],
        position: usize,
        index: usize,
    ) -> io::Result<()> {
        let entry = &mut resources.entries[position];
        if entry.envelope == Envelope::Complete {
            return Ok(());
        }
        let handle = slots[index].handle.as_ref().expect("cached descriptor");
        let current = self.effect(handle.observed_len())?;
        self.grow(handle, current, HEADER_BYTES as u64)?;
        slots[index].dirty.store(true, Ordering::Release);
        let bytes = envelope(
            self.id,
            entry.file.kind.envelope_kind(),
            READY,
            entry.file.id,
        );
        #[cfg(test)]
        if let Some(torn) = self.torn_envelope() {
            let written = handle.write_all_at(&bytes[..torn.min(HEADER_BYTES)], 0);
            self.fence();
            written?;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.effect(
            handle
                .write_all_at(&bytes, 0)
                .and_then(|()| handle.sync_all()),
        )?;
        entry.envelope = Envelope::Complete;
        Ok(())
    }

    /// Admit growth of one descriptor before its effect. Capacity denial has
    /// no effect; any other failure leaves NodeDisk accounting uncertain.
    fn grow(&self, handle: &NodeDiskFile, current: u64, requested: u64) -> io::Result<()> {
        if requested <= current {
            return Ok(());
        }
        match handle.reserve_growth(current, requested, DiskWork::Foreground) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::StorageFull => Err(error),
            Err(error) => {
                self.fence();
                Err(error)
            }
        }
    }

    /// Run a descriptor operation under the shared lock. A cache miss or an
    /// interrupted envelope that `complete` must finish takes the exclusive
    /// lock once and downgrades, so no eviction can intervene.
    fn with_file<R>(
        &self,
        file: GroupFile,
        complete: bool,
        operation: impl FnOnce(Envelope, &Slot, &NodeDiskFile) -> io::Result<R>,
    ) -> io::Result<R> {
        self.require_healthy()?;
        {
            let guard = self.state.read();
            let resources = guard.open()?;
            let position = resources.position(file).ok_or(io::ErrorKind::NotFound)?;
            let entry = &resources.entries[position];
            if let Some(index) = entry.slot
                && (!complete || entry.envelope == Envelope::Complete)
            {
                let slot = &guard.slots[index];
                if let Some(handle) = slot.handle.as_ref()
                    && !slot.failed
                {
                    slot.used.store(self.tick(), Ordering::Relaxed);
                    return operation(entry.envelope, slot, handle);
                }
            }
        }
        let mut guard = self.state.write();
        self.require_healthy()?;
        let (resources, slots) = guard.open_mut()?;
        let position = resources.position(file).ok_or(io::ErrorKind::NotFound)?;
        let index = self.cached(resources, slots, position)?;
        if complete {
            self.complete_envelope(resources, slots, position, index)?;
        }
        let guard = RwLockWriteGuard::downgrade(guard);
        let resources = guard.open()?;
        let slot = &guard.slots[index];
        operation(
            resources.entries[position].envelope,
            slot,
            slot.handle.as_ref().expect("cached descriptor"),
        )
    }

    fn with_root<R>(
        &self,
        operation: impl FnOnce(&NodeDiskFile) -> io::Result<R>,
    ) -> io::Result<R> {
        self.require_healthy()?;
        let guard = self.state.read();
        operation(guard.open()?.root()?)
    }

    pub(crate) fn read_root(
        &self,
        slot: RootSlot,
        out: &mut [u8; ROOT_SLOT_BYTES],
    ) -> io::Result<()> {
        self.with_root(|root| self.effect(root.read_exact_at(out, slot.offset())))
    }

    pub(crate) fn write_root(
        &self,
        slot: RootSlot,
        bytes: &[u8; ROOT_SLOT_BYTES],
    ) -> io::Result<()> {
        self.with_root(|root| self.effect(root.write_all_at(bytes, slot.offset())))
    }

    pub(crate) fn sync_root(&self) -> io::Result<()> {
        self.with_root(|root| self.effect(root.sync_all()))
    }

    /// Every entry of the group directory in any order, including the root.
    /// The listing must equal this owner's record of its names; any other
    /// entry is a foreign change and fences the group.
    pub(crate) fn entries(&self) -> io::Result<Vec<OsString>> {
        self.require_healthy()?;
        // Exclusive: none of this owner's own namespace effects can race.
        let guard = self.state.write();
        let resources = guard.open()?;
        // A busy or unfunded listing has no effect. Any other cursor failure
        // is a verification failure that NodeDisk has already latched.
        let listed = self.list().inspect_err(|error| {
            if !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::StorageFull | io::ErrorKind::OutOfMemory
            ) {
                self.fence();
            }
        })?;
        let mut names = Vec::new();
        names
            .try_reserve_exact(listed.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let mut root = false;
        let mut recorded = 0;
        for (name, kind) in listed {
            let known = kind == NodeDiskEntryKind::File
                && if name.as_bytes() == ROOT_FILE_NAME.as_bytes() {
                    root = true;
                    true
                } else {
                    name.to_str()
                        .ok()
                        .and_then(GroupFile::parse_name)
                        .is_some_and(|file| resources.position(file).is_some())
                };
            if !known {
                self.fence();
                return Err(invalid("segment group directory holds a foreign entry"));
            }
            recorded += usize::from(name.as_bytes() != ROOT_FILE_NAME.as_bytes());
            names.push(OsString::from_vec(name.into_bytes()));
        }
        if !root || recorded != resources.entries.len() {
            self.fence();
            return Err(invalid("segment group directory lost a recorded entry"));
        }
        Ok(names)
    }

    /// One complete bounded pass over the enrolled directory. A cursor that
    /// another owner's namespace effect interrupted restarts from the start.
    fn list(&self) -> io::Result<Vec<(CString, NodeDiskEntryKind)>> {
        let (root, relative) = self.binding()?;
        let cancel = CensusCancellation::default();
        for _ in 0..LIST_ATTEMPTS {
            let mut listed = Vec::new();
            let mut cursor = self.disk.open_directory(root, relative)?.cursor(&cancel)?;
            let complete = loop {
                match cursor.next(&cancel) {
                    Ok(Some(entry)) => {
                        listed
                            .try_reserve(1)
                            .map_err(|_| io::ErrorKind::OutOfMemory)?;
                        listed.push((entry.name().to_owned(), entry.kind()));
                    }
                    Ok(None) => break true,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break false,
                    Err(error) => return Err(error),
                }
            };
            cursor.close()?;
            if complete {
                return Ok(listed);
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    pub(crate) fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.require_healthy()?;
        Ok(self.state.read().open()?.position(file).is_some())
    }

    /// Create an empty private file under a fresh identifier. NodeDisk
    /// synchronizes the name before success; the envelope follows with the
    /// first kv mutation.
    pub(crate) fn create(&self, file: GroupFile) -> io::Result<()> {
        if file.id == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.require_healthy()?;
        let mut guard = self.state.write();
        let (resources, slots) = guard.open_mut()?;
        let position = match resources
            .entries
            .binary_search_by_key(&file, |entry| entry.file)
        {
            Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
            Err(position) => position,
        };
        // An identifier is never reused, even after its file was unlinked.
        if file.id <= resources.high_water[file.kind.index()] {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        self.reserve_entries(resources, 1)?;
        let index = self.free_slot(resources, slots)?;
        let (root, relative) = self.binding()?;
        let handle = match self.disk.create_file(
            root,
            &relative.join(file.file_name()),
            DiskWork::Foreground,
        ) {
            Ok(handle) => handle,
            // File, ledger, extent and namespace-claim checks precede the
            // create.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::StorageFull
                        | io::ErrorKind::OutOfMemory
                        | io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(error);
            }
            Err(error) => {
                // Includes a foreign name at a fresh identifier.
                resources.high_water[file.kind.index()] = file.id;
                self.fence();
                return Err(error);
            }
        };
        resources.high_water[file.kind.index()] = file.id;
        let slot = &mut slots[index];
        slot.file = Some(file);
        slot.handle = Some(handle);
        slot.used.store(self.tick(), Ordering::Relaxed);
        slot.dirty.store(false, Ordering::Release);
        let identity = self.effect(slot.handle.as_ref().expect("created").identity())?;
        resources.entries.insert(
            position,
            Entry {
                file,
                envelope: Envelope::Interrupted,
                identity,
                slot: Some(index),
            },
        );
        #[cfg(test)]
        if self.faulted(GroupFault::CreateAfterEffect) {
            self.fence();
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }

    pub(crate) fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.with_file(file, false, |envelope, _, handle| match envelope {
            Envelope::Interrupted => Ok(0),
            Envelope::Complete => self
                .effect(handle.observed_len())?
                .checked_sub(HEADER_BYTES as u64)
                .ok_or_else(|| invalid("segment group file lost its envelope")),
        })
    }

    pub(crate) fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        let end = physical(at, out.len())?;
        self.with_file(file, false, |envelope, _, handle| {
            if envelope == Envelope::Interrupted {
                return if at == 0 && out.is_empty() {
                    Ok(())
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
            // Empty reads beyond EOF are range errors too.
            if end > self.effect(handle.observed_len())? {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.effect(handle.read_exact_at(out, physical(at, 0)?))
        })
    }

    /// Append to or overwrite below the current length. Growth is admitted
    /// before the effect; a capacity denial leaves the file unchanged.
    pub(crate) fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        let start = physical(at, 0)?;
        let end = physical(at, bytes.len())?;
        // Refuse a hole before an interrupted envelope is completed.
        if at > self.len(file)? {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.with_file(file, true, |_, slot, handle| {
            let current = self.effect(handle.observed_len())?;
            if start > current {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            self.grow(handle, current, end)?;
            slot.dirty.store(true, Ordering::Release);
            self.effect(handle.write_all_at(bytes, start))
        })
    }

    pub(crate) fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        let requested = physical(length, 0)?;
        self.require_healthy()?;
        let mut guard = self.state.write();
        let (resources, slots) = guard.open_mut()?;
        let position = resources.position(file).ok_or(io::ErrorKind::NotFound)?;
        if length == 0 && resources.entries[position].envelope == Envelope::Interrupted {
            return Ok(());
        }
        let index = self.cached(resources, slots, position)?;
        self.complete_envelope(resources, slots, position, index)?;
        let slot = &mut slots[index];
        let handle = slot.handle.as_mut().expect("cached descriptor");
        let current = self.effect(handle.observed_len())?;
        if requested < current {
            // Drain checked reads and writes (exclusive lock) before the
            // synchronized shrink; unused promises settle first.
            if resources.growth_target == Some(file) {
                resources.growth_target = None;
            }
            self.effect(handle.settle_growth(current))?;
            slot.dirty.store(false, Ordering::Release);
            self.effect(handle.shrink(requested))
        } else {
            self.grow(handle, current, requested)?;
            slot.dirty.store(true, Ordering::Release);
            self.effect(handle.grow_reserved(requested))
        }
    }

    pub(crate) fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.with_file(file, false, |_, _, handle| self.effect(handle.sync_all()))
    }

    /// Remove the exact owned name and synchronize the parent. An absent
    /// name is complete once its parent synchronization succeeds. Only
    /// success lets the caller credit the file's space or forget it.
    pub(crate) fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.require_healthy()?;
        let mut guard = self.state.write();
        let (resources, slots) = guard.open_mut()?;
        let Some(position) = resources.position(file) else {
            #[cfg(test)]
            if self.faulted(GroupFault::NamesBeforeEffect) {
                self.fence();
                return Err(io::ErrorKind::Other.into());
            }
            return self.effect(resources.directory()?.sync_all());
        };
        self.unlink_entry(resources, slots, position)
    }

    fn unlink_entry(
        &self,
        resources: &mut Resources,
        slots: &mut [Slot],
        position: usize,
    ) -> io::Result<()> {
        let file = resources.entries[position].file;
        let index = self.cached(resources, slots, position)?;
        let slot = &mut slots[index];
        let handle = slot.handle.take().expect("cached descriptor");
        slot.file = None;
        slot.dirty.store(false, Ordering::Release);
        resources.entries[position].slot = None;
        if resources.growth_target == Some(file) {
            resources.growth_target = None;
        }
        // NodeDisk consumes the sole verified owner. On failure it keeps the
        // owner and every charge, and the recorded name stays until a census.
        self.effect(self.disk.delete_file(handle))?;
        resources.entries.remove(position);
        #[cfg(test)]
        if self.faulted(GroupFault::UnlinkAfterEffect) {
            self.fence();
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }

    /// Synchronize the group directory alone.
    pub(crate) fn sync_names(&self) -> io::Result<()> {
        self.require_healthy()?;
        let guard = self.state.read();
        #[cfg(test)]
        if self.faulted(GroupFault::NamesBeforeEffect) {
            self.fence();
            return Err(io::ErrorKind::Other.into());
        }
        self.effect(guard.open()?.directory()?.sync_all())
    }

    /// One-shot native drain of every owned descriptor. A failed close keeps
    /// its exact owner; a repeat reports each retained owner's first outcome
    /// without entering native close again. Only `NotEntered` may be retried.
    pub(crate) fn close(&self) -> BackendCloseOutcome {
        let Some(mut guard) = self.state.try_write() else {
            return BackendCloseOutcome::not_entered(io::ErrorKind::WouldBlock.into());
        };
        let GroupState { phase, slots, .. } = &mut *guard;
        let resources = match phase {
            Phase::Prepared | Phase::Acquiring | Phase::Closed => {
                // Acquisition held this lock until it installed resources or
                // returned; no descriptor escaped into an unopened group.
                *phase = Phase::Closed;
                return BackendCloseOutcome::drained(Ok(()));
            }
            Phase::FailedTransferred => {
                return BackendCloseOutcome::drained(Err(io::ErrorKind::BrokenPipe.into()));
            }
            Phase::Open(resources) => resources,
        };
        resources.sealed = true;
        let mut first = None;
        let mut retained = false;
        for slot in slots.iter_mut() {
            let Some(handle) = slot.handle.as_mut() else {
                continue;
            };
            let dirty = slot.dirty.load(Ordering::Acquire);
            if close_owned(handle, dirty, &mut slot.failed, &mut first, &mut retained) {
                slot.handle = None;
                slot.file = None;
                slot.dirty.store(false, Ordering::Release);
            }
        }
        if let Some(root) = resources.root.as_mut()
            && close_owned(
                root,
                false,
                &mut resources.root_failed,
                &mut first,
                &mut retained,
            )
        {
            resources.root = None;
        }
        for entry in &mut resources.entries {
            entry.slot = entry.slot.filter(|index| slots[*index].handle.is_some());
        }
        // The directory holds only an enrolled read/sync descriptor.
        drop(resources.directory.take());
        match first {
            None => {
                *phase = Phase::Closed;
                BackendCloseOutcome::drained(Ok(()))
            }
            Some(error) if retained => BackendCloseOutcome::retained(error),
            Some(error) => BackendCloseOutcome::drained(Err(error)),
        }
    }

    /// Witnesses of every retained failed-close owner, once each has
    /// positively drained natively and its disk is failed.
    pub(crate) fn failed_close_witness(&self) -> io::Result<GroupFailedWitness> {
        let guard = self.state.try_read().ok_or(io::ErrorKind::WouldBlock)?;
        let Phase::Open(resources) = &guard.phase else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        if !resources.sealed {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut witnesses = Vec::new();
        for (index, slot) in guard.slots.iter().enumerate() {
            if let Some(handle) = &slot.handle {
                if !slot.failed {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                witnesses.push((Some(index), handle.failed_close_witness()?));
            }
        }
        if let Some(root) = &resources.root {
            if !resources.root_failed {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            witnesses.push((None, root.failed_close_witness()?));
        }
        if witnesses.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(GroupFailedWitness(witnesses))
    }

    pub(crate) fn with_failed_close_reports(
        &self,
        witness: &GroupFailedWitness,
        mut observe: impl FnMut(&FailedCloseReport<'_>),
    ) -> io::Result<()> {
        let guard = self.state.try_read().ok_or(io::ErrorKind::WouldBlock)?;
        let Phase::Open(resources) = &guard.phase else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        for (custody, witness) in &witness.0 {
            let handle = match custody {
                Some(index) => guard.slots[*index].handle.as_ref(),
                None => resources.root.as_ref(),
            }
            .ok_or(io::ErrorKind::InvalidInput)?;
            handle.with_failed_close_report(witness, &mut observe)?;
        }
        Ok(())
    }

    /// Move every witnessed failed owner into NodeDisk's admitted custody.
    /// `Ok(false)` is pre-effect contention: owners already moved stay moved
    /// and a later call with a fresh witness continues.
    pub(crate) fn transfer_failed(&self, witness: &GroupFailedWitness) -> io::Result<bool> {
        let Some(mut guard) = self.state.try_write() else {
            return Ok(false);
        };
        let GroupState {
            phase,
            slots,
            transfers,
        } = &mut *guard;
        let Phase::Open(resources) = phase else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        if !resources.sealed
            || slots
                .iter()
                .any(|slot| slot.handle.is_some() && !slot.failed)
            || (resources.root.is_some() && !resources.root_failed)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for (custody, witness) in &witness.0 {
            let (handle, cleared) = match custody {
                Some(index) => {
                    let slot = slots.get_mut(*index).ok_or(io::ErrorKind::InvalidInput)?;
                    (&mut slot.handle, &mut slot.failed)
                }
                None => (&mut resources.root, &mut resources.root_failed),
            };
            let Some(file) = handle.as_mut() else {
                continue;
            };
            match file.transfer_failed(witness)? {
                Some(receipt) => {
                    if transfers.len() == transfers.capacity() {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    transfers.push(receipt);
                    // The transferred owner is inert; NodeDisk custody retains
                    // its descriptors, charges and original outcomes.
                    *handle = None;
                    *cleared = false;
                }
                None => return Ok(false),
            }
        }
        if slots.iter().any(|slot| slot.handle.is_some()) || resources.root.is_some() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for slot in slots.iter_mut() {
            slot.file = None;
        }
        *phase = Phase::FailedTransferred;
        Ok(true)
    }

    /// Every transferred owner was retired by an accepted NodeDisk census.
    pub(crate) fn failed_transfer_accepted(&self) -> bool {
        let Some(guard) = self.state.try_read() else {
            return false;
        };
        matches!(guard.phase, Phase::FailedTransferred)
            && guard
                .transfers
                .iter()
                .all(|transfer| self.disk.accepted_failure_transfer(transfer))
    }
}

/// Close one owned descriptor once and report whether it drained cleanly.
/// A failed attempt stays with its exact owner, which alone can attest a
/// completed native drain; an unattested one is retained.
fn close_owned(
    handle: &mut NodeDiskFile,
    dirty: bool,
    failed: &mut bool,
    first: &mut Option<io::Error>,
    retained: &mut bool,
) -> bool {
    if dirty
        && !*failed
        && let Err(error) = handle
            .observed_len()
            .and_then(|len| handle.settle_growth(len))
    {
        first.get_or_insert(error);
    }
    match handle.close_attested() {
        NodeDiskCloseOutcome::NotEntered(error) => {
            *retained = true;
            first.get_or_insert(error);
            false
        }
        NodeDiskCloseOutcome::Entered(Ok(())) => true,
        NodeDiskCloseOutcome::Entered(Err(error)) => {
            *failed = true;
            if handle.failed_close_witness().is_err() {
                *retained = true;
            }
            first.get_or_insert(error);
            false
        }
    }
}

impl StoragePayload for NodeSegmentGroup {
    const KIND: StorageOwnerKind = StorageOwnerKind::SegmentGroup;
    /// Close without waiting. A busy, failed or retained close keeps this
    /// exact owner and its descriptors in the census; failed owners retire
    /// only after their transfer was accepted by a fresh disk census.
    fn drive(&self) -> bool {
        let outcome = self.close();
        if outcome.entry() == BackendCloseEntry::Entered
            && outcome.native_disposition() == BackendNativeDisposition::Drained
            && outcome.into_result().is_ok()
        {
            return true;
        }
        self.failed_transfer_accepted()
    }
}

impl StorageAdmission for NodeSegmentGroup {
    /// A failed check of the root descriptor is an owner failure: the group
    /// and its disk stay failed until every owner drains and a census reopens
    /// them, even if the original inode later reappears.
    fn check_owner(&self) -> std::result::Result<(), OwnerFailed> {
        self.require_healthy().map_err(|_| OwnerFailed)?;
        let guard = self.state.read();
        let root = guard
            .open()
            .and_then(|resources| resources.root())
            .map_err(|_| OwnerFailed)?;
        root.check_owner().map_err(|_| {
            self.fence();
            OwnerFailed
        })
    }

    fn reserve_workspace(
        &self,
        bytes: u64,
    ) -> std::result::Result<Box<dyn kasumi_kv::ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        // The provider accounts for its own reservation token. This addition
        // admits the returned trait-object box before constructing it.
        let bytes = crate::disk_memory::add(
            bytes,
            crate::disk_memory::allocation::<crate::DiskMemoryLease>(1)
                .map_err(|_| AdmissionError::CapacityDenied)?,
        )
        .map_err(|_| AdmissionError::CapacityDenied)?;
        let lease = self
            .disk
            .memory()
            .clone()
            .reserve_installed(bytes)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::OutOfMemory {
                    AdmissionError::CapacityDenied
                } else {
                    self.fence();
                    AdmissionError::OwnerFailed
                }
            })?;
        Ok(Box::new(lease))
    }

    /// Admit growth of the newest segment, the only file the segmented writer
    /// appends to, from `current` to `requested` kv bytes. Its descriptor
    /// stays cached until `settle_growth`. Denial has no effect.
    fn reserve_growth(
        &self,
        current: u64,
        requested: u64,
    ) -> std::result::Result<(), AdmissionError> {
        let outcome = (|| -> io::Result<()> {
            self.require_healthy()?;
            let mut guard = self.state.write();
            let (resources, slots) = guard.open_mut()?;
            let position = resources
                .entries
                .iter()
                .rposition(|entry| entry.file.kind == GroupFileKind::Segment)
                .ok_or(io::ErrorKind::StorageFull)?;
            let file = resources.entries[position].file;
            if resources.growth_target.is_some_and(|target| target != file) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let index = self.cached(resources, slots, position)?;
            let handle = slots[index].handle.as_ref().expect("cached descriptor");
            let actual = self.effect(handle.observed_len())?;
            let logical = match resources.entries[position].envelope {
                Envelope::Interrupted => 0,
                Envelope::Complete => actual
                    .checked_sub(HEADER_BYTES as u64)
                    .ok_or_else(|| invalid("segment group file lost its envelope"))?,
            };
            if logical != current || requested < current {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            self.grow(handle, actual, physical(requested, 0)?)?;
            slots[index].dirty.store(true, Ordering::Release);
            resources.growth_target = Some(file);
            Ok(())
        })();
        match outcome {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::StorageFull => {
                Err(AdmissionError::CapacityDenied)
            }
            Err(_) => {
                self.fence();
                Err(AdmissionError::OwnerFailed)
            }
        }
    }

    /// Synchronize the admitted file and credit growth it did not use.
    fn settle_growth(&self, actual: u64) -> std::result::Result<(), OwnerFailed> {
        let outcome = (|| -> io::Result<()> {
            self.require_healthy()?;
            let mut guard = self.state.write();
            let (resources, slots) = guard.open_mut()?;
            let Some(file) = resources.growth_target else {
                return Ok(());
            };
            let position = resources.position(file).ok_or(io::ErrorKind::NotFound)?;
            let index = self.cached(resources, slots, position)?;
            let handle = slots[index].handle.as_ref().expect("cached descriptor");
            let observed = handle.observed_len()?;
            let expected = match resources.entries[position].envelope {
                Envelope::Interrupted if actual == 0 => observed,
                Envelope::Interrupted => return Err(io::ErrorKind::InvalidInput.into()),
                Envelope::Complete => physical(actual, 0)?,
            };
            handle.settle_growth(expected)?;
            slots[index].dirty.store(false, Ordering::Release);
            resources.growth_target = None;
            Ok(())
        })();
        outcome.map_err(|_| {
            self.fence();
            OwnerFailed
        })
    }

    fn owner_failed(&self) {
        self.fence();
    }
}

#[cfg(test)]
#[path = "segment_group_tests.rs"]
mod tests;
