//! Multi-file NodeDisk owner for one segmented kv log.
//!
//! The store path of a group is one enrolled directory. It holds
//! `root.kvroot` and create-only segment, checkpoint and directory-arena files
//! spelled exactly as the kv group contract names them. Every file begins with a 4 KiB
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
use super::{FailedCloseReport, FailedFileTransfer};
use crate::node_disk::NodeDiskCloseOutcome;
use crate::storage_census::{StorageOwnerKind, StoragePayload};
use crate::storage_opening::{NodeGroupIdentity, NodeOpeningMode};
use crate::{
    CensusCancellation, DiskMemoryLease, DiskWork, NodeDisk, NodeDiskDirectory, NodeDiskEntryKind,
    NodeDiskFile, private_files::FileIdentity,
};
use anyhow::{Context, Result, ensure};
use kasumi_kv::{
    AdmissionError, BackendCloseEntry, BackendCloseOutcome, BackendNativeDisposition,
    FileKind as GroupFileKind, GroupFile, OwnerFailed, ROOT_FILE_NAME, ROOT_SLOT_BYTES, RootSlot,
    SegmentGroupBackend, StorageAdmission,
};
use parking_lot::{RwLock, RwLockWriteGuard};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString, OsStr},
    io,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use uuid::Uuid;

mod transaction;
#[cfg(test)]
#[path = "segment_group/transaction_tests.rs"]
mod transaction_tests;

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
const DIRECTORY_KIND: u8 = 4;
const ROOT_FILE_BYTES: u64 = (HEADER_BYTES + 2 * ROOT_SLOT_BYTES) as u64;
/// Bounds the fixed descriptor cache; NodeDisk still enforces its own budget.
pub(crate) const MAX_CACHED_FILES: usize = 4096;
// A listing restarts only when another owner's namespace effect raced it.
const LIST_ATTEMPTS: usize = 8;

// Temporary test-utils diagnostics: the exact result/error and all native
// ownership transitions are unchanged. No event state or payload is retained.
#[cfg(feature = "test-utils")]
macro_rules! acquisition_stage {
    ($stage:literal, $operation:expr) => {{
        let result = $operation;
        if result.is_err() {
            report_acquisition_stage($stage);
        }
        result
    }};
}
#[cfg(not(feature = "test-utils"))]
macro_rules! acquisition_stage {
    ($stage:literal, $operation:expr) => {
        $operation
    };
}
#[cfg(feature = "test-utils")]
#[cold]
#[inline(never)]
fn report_acquisition_stage(stage: &'static str) {
    use std::io::Write;
    // A diagnostic write failure must not replace the original storage error.
    let _ = writeln!(
        std::io::stderr().lock(),
        "physical acquisition failed: stage={stage}"
    );
}

/// Store envelopes add the installed identity around the shared native files.
/// Keep the on-disk envelope tags private to this owner.
trait EnvelopeFileKind {
    fn envelope_kind(self) -> u8;
    fn index(self) -> usize;
}
impl EnvelopeFileKind for GroupFileKind {
    fn envelope_kind(self) -> u8 {
        match self {
            Self::Segment => SEGMENT_KIND,
            Self::Checkpoint => CHECKPOINT_KIND,
            Self::Directory => DIRECTORY_KIND,
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Segment => 0,
            Self::Checkpoint => 1,
            Self::Directory => 2,
        }
    }
}

fn root_offset(slot: RootSlot) -> u64 {
    let index = match slot {
        RootSlot::A => 0,
        RootSlot::B => 1,
    };
    (HEADER_BYTES + index * ROOT_SLOT_BYTES) as u64
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
    high_water: [u64; 3],
    // A listing retains only this scalar while callbacks run without our lock.
    // Checked increments prevent a same-owner namespace mutation from making
    // an old cursor/count appear current again.
    namespace_epoch: u64,
    // The file holding growth admitted through `StorageAdmission`. Its slot is
    // pinned until that growth settles.
    growth_target: Option<GroupFile>,
    transaction: Option<transaction::GroupTransaction>,
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

// Keep the prepared and entered ownership state in the group's preadmitted
// backing; switching phases must not allocate a separate fallible Box.
#[allow(clippy::large_enum_variant)]
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
// A prepared, unique allocation prevents address reuse even if a witness
// outlives the group. It contains no second list of physical file owners.
struct GroupWitnessOwner {
    // A directly owned group retains its fixed backing through the last
    // witness, even after the group itself is dropped. Registered groups use
    // their census charge and refuse disposal while a witness survives.
    backing: Option<DiskMemoryLease>,
}
struct GroupWitnessIdentity(Option<Arc<GroupWitnessOwner>>);
impl GroupWitnessIdentity {
    fn new() -> Self {
        Self(Some(Arc::new(GroupWitnessOwner { backing: None })))
    }
    fn arc(&self) -> &Arc<GroupWitnessOwner> {
        self.0.as_ref().expect("live witness identity")
    }
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.arc(), other.arc())
    }
    fn has_witnesses(&self) -> bool {
        Arc::strong_count(self.arc()) != 1
    }
}
impl Clone for GroupWitnessIdentity {
    fn clone(&self) -> Self {
        Self(Some(self.arc().clone()))
    }
}
impl Drop for GroupWitnessIdentity {
    fn drop(&mut self) {
        if let Some(identity) = self.0.take()
            && let Some(owner) = Arc::into_inner(identity)
        {
            // into_inner retires the control allocation before this backing
            // can return its resident credit. No Weak identity escapes.
            drop(owner);
        }
    }
}
pub(crate) struct GroupFailedWitness {
    owner: GroupWitnessIdentity,
}

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
pub struct NodeSegmentGroupCleanup {
    owner: Arc<NodeSegmentGroup>,
}
impl NodeSegmentGroupCleanup {
    /// Exact verified physical identities, while this guard owns the group.
    pub fn identity(&self) -> Result<NodeGroupIdentity> {
        self.owner.identity()
    }

    /// The retained directory identity remains available after an interrupted
    /// prior cleanup has already removed the root file.
    pub fn directory_identity(&self) -> Result<crate::private_files::DirectoryIdentity> {
        let guard = self.owner.state.read();
        Ok(crate::private_files::DirectoryIdentity::from_verified(
            guard.open()?.directory()?.verified_identity()?,
        ))
    }

    pub fn root_identity(&self) -> Result<Option<FileIdentity>> {
        let guard = self.owner.state.read();
        guard
            .open()?
            .root
            .as_ref()
            .map(NodeDiskFile::identity)
            .transpose()
            .map_err(Into::into)
    }

    /// Unlink every data file, then the root, then the empty directory, each
    /// through its verified owner with its parent synchronization. A failure
    /// fences the group and its disk; after a fresh census the names that
    /// remain are claimed again.
    pub fn delete(self) -> Result<()> {
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
    witness_owner: GroupWitnessIdentity,
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
                add(
                    allocation::<FailedFileTransfer>(add(cache, 1)?)?,
                    arc::<GroupWitnessOwner>()?,
                )?,
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
            witness_owner: GroupWitnessIdentity::new(),
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

    pub(crate) fn owned_prepared(
        path: &Path,
        id: Uuid,
        disk: Arc<NodeDisk>,
        cache: usize,
    ) -> io::Result<Arc<Self>> {
        if id.is_nil() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let backing = disk
            .memory()
            .clone()
            .reserve_installed(Self::prepared_backing_bytes(path, cache)?)?;
        let mut owner = Self::prepared(path, id, disk, cache);
        Arc::get_mut(owner.witness_owner.0.as_mut().expect("prepared identity"))
            .expect("unpublished identity")
            .backing = Some(backing);
        Ok(Arc::new(owner))
    }

    /// Charge and publish the prepared group as its own census owner before
    /// any filesystem effect. The census retains it until close drains every
    /// descriptor or its failed owners' transfer is accepted by a census.
    #[cfg(test)]
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
        let owner = Self::owned_prepared(path, expected_id, disk, cache)?;
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
                match std::fs::symlink_metadata(&self.path) {
                    Ok(metadata) if !metadata.is_dir() => {
                        // Validate actual enrolled ancestry before deciding
                        // whether this unsupported image is a legacy file or
                        // replacement of a native directory. The latter must
                        // enter the canonical failed-owner path below.
                        let parent = self
                            .disk
                            .open_directory(root, relative.parent().unwrap_or(Path::new("")))?;
                        parent.verified_identity()?;
                        ensure!(
                            self.disk.enrolled_name_kind(root, relative)?
                                == Some(NodeDiskEntryKind::Directory),
                            "segment group path is not a directory; the single-file node format is unsupported"
                        );
                    }
                    Ok(_) => {}
                    // The installed directory walk distinguishes an unknown
                    // absent final name from disappearance of an enrolled name.
                    // Skipping it here would hide physical owner failure from
                    // other databases sharing that same installed disk.
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
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
            high_water: [0; 3],
            namespace_epoch: 0,
            growth_target: None,
            transaction: None,
            sealed: true,
        });
        let GroupState { phase, slots, .. } = &mut *guard;
        let Phase::Open(resources) = phase else {
            unreachable!("installed group resources")
        };
        if let Acquisition::Opening(NodeOpeningMode::OwnedEmpty(identity)) = acquisition {
            ensure!(
                crate::private_files::DirectoryIdentity::from_verified(
                    resources
                        .directory
                        .as_ref()
                        .context("group directory missing")?
                        .verified_identity()?
                ) == identity.directory,
                "prepared segment group directory identity differs"
            );
        }
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
                let (count, only_root) = self.listing_summary()?;
                ensure!(
                    count == 1 && only_root,
                    "prepared segment group directory holds other entries"
                );
                resources.root = Some(self.disk.open_file(root, &root_path)?);
                let file = resources.root()?;
                file.check_owner()?;
                ensure!(
                    file.identity()? == identity.root,
                    "prepared segment group root identity differs"
                );
                self.prepare_root(resources)?;
            }
            Acquisition::Opening(NodeOpeningMode::Existing) => {
                resources.root = Some(acquisition_stage!(
                    "existing-root-open",
                    self.disk.open_file(root, &root_path)
                )?);
                acquisition_stage!(
                    "existing-root-verify",
                    self.verify_root(resources, &[READY])
                )?;
                acquisition_stage!("existing-census", self.census(resources, slots))?;
            }
            Acquisition::Cleanup => {
                // Only an interrupted cleanup leaves an empty directory; it
                // holds nothing to recognize or to lose.
                if self.listing_summary()?.0 != 0 {
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
        let mut root = false;
        self.visit_listing(&mut |name, kind| {
            if kind != NodeDiskEntryKind::File {
                return Err(invalid("segment group directory holds a subdirectory"));
            }
            if name.to_bytes() == ROOT_FILE_NAME.as_bytes() {
                if root {
                    return Err(invalid("segment group root was listed twice"));
                }
                root = true;
                return Ok(());
            }
            let file = name
                .to_str()
                .ok()
                .and_then(GroupFile::parse_name)
                .ok_or_else(|| {
                    invalid("segment group directory holds an entry that is not a group file")
                })?;
            let position = resources
                .entries
                .binary_search_by_key(&file, |entry| entry.file)
                .err()
                .ok_or_else(|| invalid("segment group file was listed twice"))?;
            acquisition_stage!("census-entry-admission", self.reserve_entries(resources, 1))?;
            let slot =
                acquisition_stage!("census-descriptor-slot", self.free_slot(resources, slots))?;
            let identity =
                acquisition_stage!("census-data-load", self.load(resources, slots, slot, file))?;
            let envelope = acquisition_stage!(
                "census-data-envelope",
                inspect(
                    slots[slot].handle.as_ref().expect("loaded descriptor"),
                    self.id,
                    file,
                )
            )?;
            resources.entries.insert(
                position,
                Entry {
                    file,
                    envelope,
                    identity,
                    slot: Some(slot),
                },
            );
            let high = &mut resources.high_water[file.kind.index()];
            *high = (*high).max(file.id);
            Ok(())
        })?;
        ensure!(root, "segment group root file is missing");
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
            file.read_exact_at(&mut slot, root_offset(root_slot))?;
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

    pub(crate) fn identity(&self) -> Result<NodeGroupIdentity> {
        let guard = self.state.read();
        let Phase::Open(resources) = &guard.phase else {
            anyhow::bail!("segment group is not acquired");
        };
        Ok(NodeGroupIdentity {
            directory: crate::private_files::DirectoryIdentity::from_verified(
                resources
                    .directory
                    .as_ref()
                    .context("group directory missing")?
                    .verified_identity()?,
            ),
            root: resources.root()?.identity()?,
        })
    }

    pub(crate) fn disk(&self) -> &Arc<NodeDisk> {
        &self.disk
    }

    #[cfg(test)]
    pub(crate) fn with_state_read<R>(&self, operation: impl FnOnce() -> R) -> R {
        let _guard = self.state.read();
        operation()
    }

    #[cfg(test)]
    pub(crate) fn root_handle(&self) -> NodeDiskFile {
        self.state.read().open().unwrap().root().unwrap().clone()
    }

    #[cfg(test)]
    pub(crate) fn retained_file_custody(&self) -> Option<(usize, Option<usize>)> {
        let guard = self.state.read();
        let Phase::Open(resources) = &guard.phase else {
            return None;
        };
        let file = guard
            .slots
            .iter()
            .find_map(|slot| slot.handle.as_ref())
            .or(resources.root.as_ref())?;
        Some((file.close_owner_address()?, file.close_error_address()))
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
                if let Some(transaction) = resources.transaction.as_mut() {
                    self.effect(transaction.space.descriptor_closed())?;
                }
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
    fn load(
        &self,
        resources: &mut Resources,
        slots: &mut [Slot],
        index: usize,
        file: GroupFile,
    ) -> io::Result<FileIdentity> {
        let (root, relative) = self.binding()?;
        let path = relative.join(file.file_name());
        let opened = match resources.transaction.as_mut() {
            Some(transaction) => {
                self.disk
                    .open_transaction_file(&mut transaction.space, root, &path, false)
            }
            None => self.disk.open_file(root, &path),
        };
        let handle = match opened {
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
        let identity = self.load(resources, slots, index, file)?;
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
        let file = resources.entries[position].file;
        if resources.entries[position].envelope == Envelope::Complete {
            return Ok(());
        }
        let handle = slots[index].handle.as_ref().expect("cached descriptor");
        let current = self.effect(handle.observed_len())?;
        self.grow_in_transaction(resources, handle, file, current, HEADER_BYTES as u64)?;
        slots[index].dirty.store(true, Ordering::Release);
        let bytes = envelope(self.id, file.kind.envelope_kind(), READY, file.id);
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
        resources.entries[position].envelope = Envelope::Complete;
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
        self.with_root(|root| self.effect(root.read_exact_at(out, root_offset(slot))))
    }

    pub(crate) fn write_root(
        &self,
        slot: RootSlot,
        bytes: &[u8; ROOT_SLOT_BYTES],
    ) -> io::Result<()> {
        self.require_healthy()?;
        let mut guard = self.state.write();
        let (resources, _) = guard.open_mut()?;
        if let Some(transaction) = resources.transaction.as_mut() {
            transaction.space.enter_effect();
        }
        self.effect(resources.root()?.write_all_at(bytes, root_offset(slot)))
    }

    pub(crate) fn sync_root(&self) -> io::Result<()> {
        self.with_root(|root| self.effect(root.sync_all()))
    }

    /// Stream through one bounded native cursor without holding our lock
    /// across callbacks. A scalar epoch and NodeDisk's namespace generation
    /// reject raced passes; no callback is replayed or name list retained.
    pub(crate) fn visit_entries(
        &self,
        visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>,
    ) -> io::Result<()> {
        self.require_healthy()?;
        let (epoch, expected) = {
            let guard = self.state.read();
            let resources = guard.open()?;
            self.effect(resources.root()?.check_owner())?;
            (resources.namespace_epoch, resources.entries.len())
        };
        let mut root = false;
        let mut recorded = 0;
        self.visit_listing(&mut |name, kind| {
            self.check_listing_session(epoch)?;
            let known = {
                let guard = self.state.read();
                let resources = guard.open()?;
                if resources.namespace_epoch != epoch {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                kind == NodeDiskEntryKind::File
                    && if name.to_bytes() == ROOT_FILE_NAME.as_bytes() {
                        let fresh = !root;
                        root = true;
                        fresh
                    } else {
                        name.to_str()
                            .ok()
                            .and_then(GroupFile::parse_name)
                            .is_some_and(|file| resources.position(file).is_some())
                    }
            };
            if !known {
                self.fence();
                return Err(invalid("segment group directory holds a foreign entry"));
            }
            recorded += usize::from(name.to_bytes() != ROOT_FILE_NAME.as_bytes());
            let outcome = visitor(OsStr::from_bytes(name.to_bytes()));
            let current = self.check_listing_session(epoch);
            outcome.and(current)
        })?;
        self.check_listing_session(epoch)?;
        if !root || recorded != expected {
            self.fence();
            return Err(invalid("segment group directory lost a recorded entry"));
        }
        Ok(())
    }

    fn check_listing_session(&self, epoch: u64) -> io::Result<()> {
        self.require_healthy()?;
        let guard = self.state.read();
        let resources = guard.open()?;
        if resources.namespace_epoch != epoch {
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.effect(resources.root()?.check_owner())
    }

    /// Test-only collection convenience. The native boundary streams names.
    #[cfg(test)]
    fn entries(&self) -> io::Result<Vec<std::ffi::OsString>> {
        let mut names = Vec::new();
        self.visit_entries(&mut |name| {
            names.push(name.to_owned());
            Ok(())
        })?;
        Ok(names)
    }

    /// One pass with only the NodeDisk cursor's bounded native workspace.
    /// Callback errors are caller decisions and do not fence the owner; read
    /// and close failures preserve NodeDisk's exact failure/drain behavior.
    fn visit_listing(
        &self,
        visitor: &mut dyn FnMut(&CStr, NodeDiskEntryKind) -> io::Result<()>,
    ) -> io::Result<()> {
        let (root, relative) = self.binding()?;
        let cancel = CensusCancellation::default();
        let mut cursor = acquisition_stage!(
            "listing-cursor-open",
            self.disk
                .open_directory(root, relative)
                .and_then(|directory| directory.cursor(&cancel))
        )
        .inspect_err(|error| self.listing_error(error))?;
        let outcome = loop {
            match acquisition_stage!("listing-cursor-next", cursor.next(&cancel)) {
                Ok(Some(entry)) => {
                    if let Err(error) = visitor(entry.name(), entry.kind()) {
                        break Err(error);
                    }
                }
                Ok(None) => break Ok(()),
                Err(error) => {
                    self.listing_error(&error);
                    break Err(error);
                }
            }
        };
        // An independent close failure takes precedence and fences the owner
        // even when a callback chose to stop the otherwise healthy pass.
        acquisition_stage!("listing-cursor-close", self.effect(cursor.close()))?;
        outcome
    }

    fn listing_error(&self, error: &io::Error) {
        if !matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::StorageFull | io::ErrorKind::OutOfMemory
        ) {
            self.fence();
        }
    }

    /// Scalar-only classification can safely restart after a raced cursor.
    fn listing_summary(&self) -> io::Result<(usize, bool)> {
        for _ in 0..LIST_ATTEMPTS {
            let mut count = 0usize;
            let mut only_root = true;
            let outcome = self.visit_listing(&mut |name, kind| {
                count = count.checked_add(1).ok_or(io::ErrorKind::OutOfMemory)?;
                only_root &=
                    kind == NodeDiskEntryKind::File && name.to_bytes() == ROOT_FILE_NAME.as_bytes();
                Ok(())
            });
            match outcome {
                Ok(()) => return Ok((count, only_root)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
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
        let next_epoch = resources
            .namespace_epoch
            .checked_add(1)
            .ok_or(io::ErrorKind::Other)?;
        if let Some(transaction) = resources.transaction.as_mut() {
            self.effect(transaction.authorize_create(file))?;
            if resources.entries.len() == resources.entries.capacity() {
                self.fence();
                return Err(io::ErrorKind::InvalidData.into());
            }
        } else {
            self.reserve_entries(resources, 1)?;
        }
        let index = self.free_slot(resources, slots)?;
        let (root, relative) = self.binding()?;
        let path = relative.join(file.file_name());
        let created = match resources.transaction.as_mut() {
            Some(transaction) => {
                self.disk
                    .open_transaction_file(&mut transaction.space, root, &path, true)
            }
            None => self.disk.create_file(root, &path, DiskWork::Foreground),
        };
        let handle = match created {
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
        resources.namespace_epoch = next_epoch;
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
        if self.write_transaction_file(file, at, bytes)? {
            return Ok(());
        }
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
            if resources.transaction.is_some() {
                self.fence();
                return Err(io::ErrorKind::InvalidData.into());
            }
            // Drain checked reads and writes (exclusive lock) before the
            // synchronized shrink; unused promises settle first.
            if resources.growth_target == Some(file) {
                resources.growth_target = None;
            }
            self.effect(handle.settle_growth(current))?;
            slot.dirty.store(false, Ordering::Release);
            self.effect(handle.shrink(requested))
        } else {
            self.grow_in_transaction(resources, handle, file, current, requested)?;
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
        if resources.transaction.is_some() {
            self.fence();
            return Err(io::ErrorKind::InvalidData.into());
        }
        let next_epoch = resources
            .namespace_epoch
            .checked_add(1)
            .ok_or(io::ErrorKind::Other)?;
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
        resources.namespace_epoch = next_epoch;
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
        // Abandoning an unfinished claim retains every unassigned promise in
        // NodeDisk and fences it. Normal exact descriptor drain/transfer remains
        // available; only an accepted census may reconcile the retained credit.
        drop(resources.transaction.take());
        let mut first = None;
        let mut retained = false;
        let mut retryable = true;
        for slot in slots.iter_mut() {
            let Some(handle) = slot.handle.as_mut() else {
                continue;
            };
            let dirty = slot.dirty.load(Ordering::Acquire);
            if close_owned(
                handle,
                dirty,
                &mut slot.failed,
                &mut first,
                &mut retained,
                &mut retryable,
            ) {
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
                &mut retryable,
            )
        {
            resources.root = None;
        }
        for entry in &mut resources.entries {
            entry.slot = entry.slot.filter(|index| slots[*index].handle.is_some());
        }
        // Positive drains are final and have already removed their handles.
        // If every remaining handle proved pre-entry contention, the next
        // close resumes only those owners; no native close is repeated.
        if retained && retryable {
            return BackendCloseOutcome::not_entered(first.expect("retained close error"));
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
        validate_failed_handles(resources, &guard.slots)?;
        // Sealing forbids acquisition, replacement and any ordinary operation.
        // Every remaining owner has just proved its terminal positive drain;
        // only exact transfers can subsequently remove members of this set.
        Ok(GroupFailedWitness {
            owner: self.witness_owner.clone(),
        })
    }

    pub(crate) fn with_failed_close_reports(
        &self,
        witness: &GroupFailedWitness,
        mut observe: impl FnMut(&FailedCloseReport<'_>),
    ) -> io::Result<()> {
        if !witness.owner.same(&self.witness_owner) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let guard = self.state.try_read().ok_or(io::ErrorKind::WouldBlock)?;
        let Phase::Open(resources) = &guard.phase else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        validate_failed_handles(resources, &guard.slots)?;
        for handle in guard
            .slots
            .iter()
            .filter_map(|slot| slot.handle.as_ref())
            .chain(resources.root.as_ref())
        {
            let actual = handle.failed_close_witness()?;
            handle.with_failed_close_report(&actual, &mut observe)?;
        }
        Ok(())
    }

    /// Move every witnessed failed owner into NodeDisk's admitted custody.
    /// `Ok(false)` is transfer contention: owners already moved stay moved,
    /// and the same exact witness continues only its still-owned handles.
    pub(crate) fn transfer_failed(&self, witness: &GroupFailedWitness) -> io::Result<bool> {
        if !witness.owner.same(&self.witness_owner) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
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
        for slot in slots.iter_mut() {
            if !transfer_failed_handle(&mut slot.handle, &mut slot.failed, transfers)? {
                return Ok(false);
            }
        }
        if !transfer_failed_handle(&mut resources.root, &mut resources.root_failed, transfers)? {
            return Ok(false);
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

// No lower witness or callback is created before the entire current set has
// proved the required drain. The group read lock forbids membership changes.
fn validate_failed_handles(resources: &Resources, slots: &[Slot]) -> io::Result<()> {
    if !resources.sealed {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let mut count = 0;
    for slot in slots {
        if let Some(handle) = &slot.handle {
            if !slot.failed {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            handle.failed_close_witness()?;
            count += 1;
        }
    }
    if let Some(root) = &resources.root {
        if !resources.root_failed {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        root.failed_close_witness()?;
        count += 1;
    }
    if count == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}

fn transfer_failed_handle(
    handle: &mut Option<NodeDiskFile>,
    failed: &mut bool,
    transfers: &mut Vec<FailedFileTransfer>,
) -> io::Result<bool> {
    let Some(file) = handle.as_mut() else {
        return Ok(true);
    };
    // The group witness previously proved the sealed owner. A busy NodeDisk
    // gate now only postpones this same transfer; it cannot enroll a new file.
    let actual = match file.failed_close_witness() {
        Ok(actual) => actual,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(error) => return Err(error),
    };
    if transfers.len() == transfers.capacity() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let Some(receipt) = file.transfer_failed(&actual)? else {
        return Ok(false);
    };
    transfers.push(receipt);
    *handle = None;
    *failed = false;
    Ok(true)
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
    retryable: &mut bool,
) -> bool {
    if dirty
        && !*failed
        && let Err(error) = handle
            .observed_len()
            .and_then(|len| handle.settle_growth(len))
    {
        *retryable = false;
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
            *retryable = false;
            *failed = true;
            if handle.failed_close_witness().is_err() {
                *retained = true;
            }
            first.get_or_insert(error);
            false
        }
    }
}

/// The installed owner is the native backend itself. Both sides use exactly
/// the same file/slot types and byte offsets; the envelope is owned here.
impl SegmentGroupBackend for NodeSegmentGroup {
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
        self.reserve_transaction_plan(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.finish_transaction_plan(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.cancel_transaction_plan(group_id, batch_seq)
    }
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        NodeSegmentGroup::read_root(self, slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        NodeSegmentGroup::write_root(self, slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        NodeSegmentGroup::sync_root(self)
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        NodeSegmentGroup::visit_entries(self, visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        NodeSegmentGroup::exists(self, file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        NodeSegmentGroup::create(self, file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        NodeSegmentGroup::len(self, file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        NodeSegmentGroup::read(self, file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        NodeSegmentGroup::write(self, file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        NodeSegmentGroup::set_len(self, file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        NodeSegmentGroup::sync(self, file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        NodeSegmentGroup::unlink(self, file)
    }
    fn sync_names(&self) -> io::Result<()> {
        NodeSegmentGroup::sync_names(self)
    }
    fn close(&self) -> BackendCloseOutcome {
        NodeSegmentGroup::close(self)
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
            return !self.witness_owner.has_witnesses();
        }
        self.failed_transfer_accepted() && !self.witness_owner.has_witnesses()
    }
}

/// Exact request made to the installed provider for a native ResidentLease.
/// Shared by the real constructor and source quotation; this does not reserve.
pub(crate) fn workspace_provider_request_bytes(bytes: u64) -> io::Result<u64> {
    crate::disk_memory::add(
        bytes,
        crate::disk_memory::allocation::<crate::DiskMemoryLease>(1)?,
    )
}

impl StorageAdmission for NodeSegmentGroup {
    fn install_source_pool(
        self: Arc<Self>,
        install: &mut kasumi_kv::SourcePoolInstall<'_>,
    ) -> io::Result<()> {
        self.check_owner()
            .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
        let provider: Arc<dyn kasumi_kv::SourceMemoryProvider> = self.disk.memory().clone();
        install.through_installed_provider(provider, workspace_provider_request_bytes)?;
        self.check_owner().map_err(|_| io::ErrorKind::Other.into())
    }

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
        let bytes =
            workspace_provider_request_bytes(bytes).map_err(|_| AdmissionError::CapacityDenied)?;
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

    fn quote_cache_memory(
        &self,
        credit_bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, AdmissionError> {
        self.disk
            .memory()
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
            .disk
            .memory()
            .clone()
            .reserve_cache_memory(credit_bytes)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::OutOfMemory {
                    AdmissionError::CapacityDenied
                } else {
                    self.fence();
                    AdmissionError::OwnerFailed
                }
            })?;
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        Ok(lease)
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
            if resources.transaction.is_some() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
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

#[cfg(test)]
#[path = "segment_group_missing_tests.rs"]
mod missing_tests;

#[cfg(test)]
mod directory_arena_tests {
    use super::*;
    use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
    use std::ffi::OsString;

    const ID: Uuid = Uuid::from_u128(0x5213_e7b8_26e1_4fda_a838_5f8a_0d51_7620);

    #[test]
    fn directory_names_are_canonical_and_kind_bound() {
        let file = GroupFile::directory(0x2a);
        assert_eq!(file.file_name(), "000000000000002a.kvdir");
        assert_eq!(GroupFile::parse_name(&file.file_name()), Some(file));
        for name in [
            "000000000000002A.kvdir",
            "00000000000002a.kvdir",
            "0000000000000000.kvdir",
            "000000000000002a.kvdir.tmp",
        ] {
            assert_eq!(GroupFile::parse_name(name), None, "{name}");
        }
        let bytes = envelope(ID, DIRECTORY_KIND, READY, file.id);
        assert_eq!(
            validate_envelope(&bytes, ID, file.kind.envelope_kind(), file.id).unwrap(),
            READY
        );
        for kind in [ROOT_KIND, SEGMENT_KIND, CHECKPOINT_KIND] {
            assert!(validate_envelope(&bytes, ID, kind, file.id).is_err());
        }
        assert!(validate_envelope(&bytes, ID, DIRECTORY_KIND, file.id + 1).is_err());
    }

    #[test]
    fn directory_arenas_reopen_through_the_bounded_descriptor_cache() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("group");
        let memory: Arc<dyn crate::NodeDiskMemoryAdmission> = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let group = NodeSegmentGroup::retained_prepared(&path, ID, disk.clone(), 1);
        group.acquire_prepared(&NodeOpeningMode::Create).unwrap();
        group
            .write_root(RootSlot::A, &[1; ROOT_SLOT_BYTES])
            .unwrap();
        group.sync_root().unwrap();
        group.publish_ready().unwrap();
        // The three identifier domains are independent. Every lookup below
        // also evicts a descriptor when its kind differs from the last one.
        let files = [
            (GroupFile::segment(1), b"first"),
            (GroupFile::checkpoint(1), b"check"),
            (GroupFile::directory(1), b"arena"),
            (GroupFile::directory(2), b"newer"),
        ];
        for (file, bytes) in files {
            group.create(file).unwrap();
            group.write(file, 0, bytes).unwrap();
            group.sync(file).unwrap();
            assert_eq!(group.cached_files(), 1);
        }
        for (file, expected) in files {
            let mut bytes = [0; 5];
            group.read(file, 0, &mut bytes).unwrap();
            assert_eq!(&bytes, expected);
            assert_eq!(group.cached_files(), 1);
        }
        let image = std::fs::read(path.join(GroupFile::directory(2).file_name())).unwrap();
        assert_eq!(image[32], DIRECTORY_KIND);
        assert_eq!(&image[HEADER_BYTES..], b"newer");
        group.unlink(GroupFile::directory(1)).unwrap();
        assert_eq!(
            group.create(GroupFile::directory(1)).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let closed = group.close();
        assert_eq!(
            closed.native_disposition(),
            BackendNativeDisposition::Drained
        );
        closed.into_result().unwrap();

        let group = NodeSegmentGroup::retained_prepared(&path, ID, disk.clone(), 1);
        group.acquire_prepared(&NodeOpeningMode::Existing).unwrap();
        assert_eq!(group.cached_files(), 1);
        assert!(
            group
                .entries()
                .unwrap()
                .contains(&OsString::from(GroupFile::directory(2).file_name()))
        );
        for (file, expected) in files
            .into_iter()
            .filter(|(file, _)| *file != GroupFile::directory(1))
        {
            let mut bytes = [0; 5];
            group.read(file, 0, &mut bytes).unwrap();
            assert_eq!(&bytes, expected);
        }
        assert_eq!(
            group.create(GroupFile::directory(1)).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        group.create(GroupFile::directory(3)).unwrap();
        group.write(GroupFile::directory(3), 0, b"third").unwrap();
        group.sync(GroupFile::directory(3)).unwrap();
        let closed = group.close();
        assert_eq!(
            closed.native_disposition(),
            BackendNativeDisposition::Drained
        );
        closed.into_result().unwrap();
        disk.reconcile(&CensusCancellation::default()).unwrap();
        assert_eq!(disk.snapshot().open_files, 0);
    }
}
