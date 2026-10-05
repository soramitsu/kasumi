//! Multi-file ownership contract for the segmented log.
//!
//! A group is one root file with two superblock slots plus create-only segment
//! and checkpoint files under one directory. Names are deterministic from a
//! kind and a never-reused identifier. Creation and deletion each include the
//! parent directory synchronization; a failed result after entry leaves the
//! namespace effect unknown, and the caller must fence and reopen. A restart
//! without power loss still lists a name whose parent synchronization failed,
//! so an owner that adopts a present name it did not create in this process
//! synchronizes the names first.

use std::ffi::OsStr;
use std::io;

use crate::core::BackendCloseOutcome;
use crate::root::{ROOT_SLOT_BYTES, RootSlot};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileKind {
    Segment,
    Checkpoint,
    Directory,
}

impl FileKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Segment => ".kvseg",
            Self::Checkpoint => ".kvckpt",
            Self::Directory => ".kvdir",
        }
    }

    pub(crate) fn tag(self) -> u8 {
        match self {
            Self::Segment => 1,
            Self::Checkpoint => 2,
            Self::Directory => 3,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Segment),
            2 => Some(Self::Checkpoint),
            3 => Some(Self::Directory),
            _ => None,
        }
    }
}

/// One owned file of a group. Identifier zero is never allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupFile {
    pub kind: FileKind,
    pub id: u64,
}

impl GroupFile {
    pub const fn segment(id: u64) -> Self {
        Self {
            kind: FileKind::Segment,
            id,
        }
    }

    pub const fn checkpoint(id: u64) -> Self {
        Self {
            kind: FileKind::Checkpoint,
            id,
        }
    }

    pub const fn directory(id: u64) -> Self {
        Self {
            kind: FileKind::Directory,
            id,
        }
    }

    /// The deterministic directory entry. Identifiers use sixteen lowercase
    /// hexadecimal digits so a name has exactly one spelling.
    pub fn file_name(self) -> String {
        format!("{:016x}{}", self.id, self.kind.suffix())
    }

    /// Parse a census entry. Any other spelling is not a group file.
    pub fn parse_name(name: &str) -> Option<Self> {
        let (digits, kind) = if let Some(digits) = name.strip_suffix(FileKind::Segment.suffix()) {
            (digits, FileKind::Segment)
        } else if let Some(digits) = name.strip_suffix(FileKind::Checkpoint.suffix()) {
            (digits, FileKind::Checkpoint)
        } else {
            (
                name.strip_suffix(FileKind::Directory.suffix())?,
                FileKind::Directory,
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

/// The name of the root file holding both superblock slots.
pub const ROOT_FILE_NAME: &str = "root.kvroot";

/// Scalar maximum extent for one existing native file. Byte lengths exclude
/// any enclosing store envelope; the backend adds its actual filesystem costs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExistingFileSpace {
    pub file: GroupFile,
    pub initial_len: u64,
    pub maximum_len: u64,
}

/// Consecutive fresh file identifiers. Each non-final file is bounded by
/// `full_len`, the final file by `last_len`, and their summed native EOFs by
/// `total_len`. A zero count requires every field to be zero. The scalar sum
/// avoids charging every short intermediate segment as a full segment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileSpaceRange {
    pub first_id: u64,
    pub count: u64,
    pub minimum_len: u64,
    pub full_len: u64,
    pub last_len: u64,
    pub total_len: u64,
}
impl FileSpaceRange {
    pub fn validate(&self) -> io::Result<()> {
        if self.count == 0 {
            return if *self == Self::default() {
                Ok(())
            } else {
                Err(io::ErrorKind::InvalidInput.into())
            };
        }
        let minimum = self.count.checked_mul(self.minimum_len);
        let maximum = self
            .count
            .checked_sub(1)
            .and_then(|n| n.checked_mul(self.full_len))
            .and_then(|n| n.checked_add(self.last_len));
        if self.first_id == 0
            || self.minimum_len == 0
            || self.minimum_len > self.last_len
            || minimum.is_none_or(|minimum| self.total_len < minimum)
            || self.last_len == 0
            || self.full_len == 0
            || self.last_len > self.full_len
            || self.full_len > i64::MAX as u64
            || self.total_len < self.last_len
            || maximum.is_none_or(|maximum| self.total_len > maximum)
            || self.first_id.checked_add(self.count - 1).is_none()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
    pub fn maximum_len(&self, id: u64) -> Option<u64> {
        let offset = id.checked_sub(self.first_id)?;
        if offset >= self.count {
            return None;
        }
        Some(if offset + 1 == self.count {
            self.last_len
        } else {
            self.full_len
        })
    }
}

/// Complete pre-effect promise for one exact selected native incarnation.
/// Root generation and batch sequence are checked against the actual selected
/// root; the backend owns this plan until explicit completion or cancellation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionSpacePlan {
    pub group_id: [u8; 16],
    pub root_generation: u64,
    pub batch_seq: u64,
    pub segment: Option<ExistingFileSpace>,
    pub directory: Option<ExistingFileSpace>,
    pub new_segments: FileSpaceRange,
    pub new_directories: FileSpaceRange,
}
impl TransactionSpacePlan {
    pub fn validate(&self) -> io::Result<()> {
        if self.root_generation == 0 || self.batch_seq == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for (existing, kind) in [
            (self.segment, FileKind::Segment),
            (self.directory, FileKind::Directory),
        ] {
            if let Some(existing) = existing
                && (existing.file.kind != kind
                    || existing.file.id == 0
                    || existing.initial_len > existing.maximum_len
                    || existing.maximum_len > i64::MAX as u64)
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        self.new_segments.validate()?;
        self.new_directories.validate()
    }
}

/// Only a backend's complete pre-effect reservation may mint `CapacityDenied`.
/// All other original errors stay owned, including failed physical observation.
#[derive(Debug)]
pub enum TransactionReserveError {
    CapacityDenied,
    Failed(io::Error),
}
impl std::fmt::Display for TransactionReserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapacityDenied => f.write_str("transaction space capacity denied before effects"),
            Self::Failed(error) => std::fmt::Display::fmt(error, f),
        }
    }
}
impl std::error::Error for TransactionReserveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(error) => Some(error),
            Self::CapacityDenied => None,
        }
    }
}

/// Exact multi-file backing for one segmented log.
///
/// Implementations never return short successful reads or writes. `write`
/// only appends to or overwrites below the current length. `sync` includes
/// every prior write and length change of that file. `create` refuses an
/// existing name, creates an empty private file, and synchronizes the parent
/// before success. `unlink` removes the exact owned name and synchronizes the
/// parent before success; an absent name is success after that parent sync.
/// Only a successful `unlink` lets the caller credit the file's space or drop
/// its garbage record; a listing that no longer shows a name proves nothing.
/// `sync_names` synchronizes the parent alone: on success every name the
/// listing shows, and no name it no longer shows, survives power loss.
/// The root file is established with the group and holds two fixed slots; an
/// unwritten slot reads as zeros.
pub trait SegmentGroupBackend: Send + Sync {
    /// Install the complete promise before the first transaction effect.
    /// Implementations must reserve bytes, namespace and peak descriptor rights;
    /// installed disk backends cannot implement this as a free-space check.
    fn reserve_transaction(
        &self,
        plan: &TransactionSpacePlan,
    ) -> Result<(), TransactionReserveError>;
    /// Positively settle all consumed file rights before refunding unused ones.
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()>;
    /// Cancel only an untouched reservation. An entered effect is retained.
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()>;
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()>;
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()>;
    fn sync_root(&self) -> io::Result<()>;
    /// Visit every entry of the group directory in any order, including
    /// `ROOT_FILE_NAME`, without retaining a collection of names. Each name
    /// is borrowed only for its callback. Implementations must not hide names
    /// they do not recognize: the census fails closed on non-group entries.
    /// A non-file entry, including a directory named like a group file, makes
    /// the pass fail. Successful callbacks alone never prove a complete pass.
    ///
    /// A callback error stops the pass. Any error invalidates the whole pass;
    /// callers discard partial output before retrying. Implementations never
    /// restart a pass after delivering a callback. The callback must not
    /// reenter this backend, which may hold its namespace lock for the pass.
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()>;
    fn exists(&self, file: GroupFile) -> io::Result<bool>;
    fn create(&self, file: GroupFile) -> io::Result<()>;
    fn len(&self, file: GroupFile) -> io::Result<u64>;
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()>;
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()>;
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()>;
    fn sync(&self, file: GroupFile) -> io::Result<()>;
    fn unlink(&self, file: GroupFile) -> io::Result<()>;
    /// Synchronize the group directory. A failure leaves the durability of
    /// every name unknown; the caller fences and reopens.
    fn sync_names(&self) -> io::Result<()>;
    /// One-shot native drain of every owned descriptor. A retained result
    /// keeps the group owner; only `NotEntered` may be retried.
    fn close(&self) -> BackendCloseOutcome;
}

// Preserve one shared owner across the native core, cache and installed-store
// lifecycle registry without a second filesystem adapter.
macro_rules! forward_group_backend {
    ($owner:ty) => {
        impl<T: SegmentGroupBackend + ?Sized> SegmentGroupBackend for $owner {
            fn reserve_transaction(
                &self,
                plan: &TransactionSpacePlan,
            ) -> Result<(), TransactionReserveError> {
                (**self).reserve_transaction(plan)
            }
            fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
                (**self).finish_transaction(group_id, batch_seq)
            }
            fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
                (**self).cancel_transaction(group_id, batch_seq)
            }
            fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
                (**self).read_root(slot, out)
            }
            fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
                (**self).write_root(slot, bytes)
            }
            fn sync_root(&self) -> io::Result<()> {
                (**self).sync_root()
            }
            fn visit_entries(
                &self,
                visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>,
            ) -> io::Result<()> {
                (**self).visit_entries(visitor)
            }
            fn exists(&self, file: GroupFile) -> io::Result<bool> {
                (**self).exists(file)
            }
            fn create(&self, file: GroupFile) -> io::Result<()> {
                (**self).create(file)
            }
            fn len(&self, file: GroupFile) -> io::Result<u64> {
                (**self).len(file)
            }
            fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
                (**self).read(file, at, out)
            }
            fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
                (**self).write(file, at, bytes)
            }
            fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
                (**self).set_len(file, length)
            }
            fn sync(&self, file: GroupFile) -> io::Result<()> {
                (**self).sync(file)
            }
            fn unlink(&self, file: GroupFile) -> io::Result<()> {
                (**self).unlink(file)
            }
            fn sync_names(&self) -> io::Result<()> {
                (**self).sync_names()
            }
            fn close(&self) -> BackendCloseOutcome {
                (**self).close()
            }
        }
    };
}

forward_group_backend!(Box<T>);
forward_group_backend!(std::sync::Arc<T>);

pub use memory::{FaultTiming, GroupOp, InMemoryGroup};

/// Volatile group with explicit durable images for crash and fault tests.
mod memory {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

    use super::{GroupFile, ROOT_FILE_NAME, SegmentGroupBackend};
    use crate::core::BackendCloseOutcome;
    use crate::root::{ROOT_SLOT_BYTES, RootSlot};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum GroupOp {
        Create,
        Write,
        SetLen,
        Sync,
        Unlink,
        SyncNames,
        RootWrite,
        RootSync,
    }

    /// `AfterEffect` applies the volatile effect (or persists it for a sync)
    /// and still reports failure, which is the unknown-outcome case.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum FaultTiming {
        BeforeEffect,
        AfterEffect,
    }

    struct Fault {
        op: GroupOp,
        remaining: usize,
        timing: FaultTiming,
    }

    struct MemFile {
        volatile: Vec<u8>,
        durable: Vec<u8>,
        // Present in the volatile namespace.
        linked: bool,
        // The name survives a crash.
        name_durable: bool,
    }

    enum CloseState {
        Open,
        Drained,
        Retained(io::ErrorKind),
    }

    struct GroupState {
        root_volatile: Vec<u8>,
        root_durable: Vec<u8>,
        files: BTreeMap<GroupFile, MemFile>,
        // Names that were ever durable. The group protocol must never create
        // them again, even after a confirmed unlink.
        durable_names: BTreeSet<GroupFile>,
        // Durable directory entries that are not group files.
        strays: BTreeSet<OsString>,
        faults: Vec<Fault>,
        close: CloseState,
        close_not_entered: bool,
        close_error: Option<io::ErrorKind>,
        close_attempts: usize,
        transaction: Option<(super::TransactionSpacePlan, bool)>,
    }

    impl GroupState {
        fn new() -> Self {
            Self {
                root_volatile: vec![0; ROOT_SLOT_BYTES * 2],
                root_durable: vec![0; ROOT_SLOT_BYTES * 2],
                files: BTreeMap::new(),
                durable_names: BTreeSet::new(),
                strays: BTreeSet::new(),
                faults: Vec::new(),
                close: CloseState::Open,
                close_not_entered: false,
                close_error: None,
                close_attempts: 0,
                transaction: None,
            }
        }

        fn fault(&mut self, op: GroupOp) -> Option<FaultTiming> {
            if let Some((_, entered)) = self.transaction.as_mut() {
                *entered = true;
            }
            let position = self.faults.iter().position(|fault| fault.op == op)?;
            let fault = &mut self.faults[position];
            fault.remaining -= 1;
            if fault.remaining > 0 {
                return None;
            }
            Some(self.faults.remove(position).timing)
        }

        fn linked(&mut self, file: GroupFile) -> io::Result<&mut MemFile> {
            self.files
                .get_mut(&file)
                .filter(|entry| entry.linked)
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }
    }

    fn injected(op: GroupOp) -> io::Error {
        io::Error::other(format!("injected {op:?} failure"))
    }

    fn slot_range(slot: RootSlot) -> std::ops::Range<usize> {
        let start = slot.index() * ROOT_SLOT_BYTES;
        start..start + ROOT_SLOT_BYTES
    }

    #[derive(Clone)]
    pub struct InMemoryGroup(Arc<Mutex<GroupState>>);

    impl Default for InMemoryGroup {
        fn default() -> Self {
            Self::new()
        }
    }

    impl InMemoryGroup {
        pub fn new() -> Self {
            Self(Arc::new(Mutex::new(GroupState::new())))
        }

        fn state(&self) -> MutexGuard<'_, GroupState> {
            self.0.lock().expect("in-memory group lock")
        }

        fn open_state(&self) -> io::Result<MutexGuard<'_, GroupState>> {
            let state = self.0.lock().map_err(|_| io::ErrorKind::Other)?;
            match state.close {
                CloseState::Open => Ok(state),
                CloseState::Drained | CloseState::Retained(_) => {
                    Err(io::ErrorKind::BrokenPipe.into())
                }
            }
        }

        /// Fail the `nth` next call of `op`, counting from one.
        pub fn fail(&self, op: GroupOp, nth: usize, timing: FaultTiming) {
            assert!(nth > 0);
            self.state().faults.push(Fault {
                op,
                remaining: nth,
                timing,
            });
        }

        /// Restart from the durable images. Unsynchronized bytes, unsynced
        /// creations, and unsynced unlinks are lost.
        pub fn crash(&self) -> Self {
            self.crash_with(|_| {})
        }

        /// Restart as if `keep` bytes of `file`'s unsynchronized append had
        /// reached the medium before the crash.
        pub fn crash_torn(&self, file: GroupFile, keep: usize) -> Self {
            self.crash_with(|state| {
                let entry = state.files.get_mut(&file).expect("torn file exists");
                let start = entry.durable.len();
                if entry.volatile.len() > start && entry.volatile[..start] == entry.durable[..] {
                    let end = entry.volatile.len().min(start + keep);
                    let torn = entry.volatile[start..end].to_vec();
                    entry.durable.extend_from_slice(&torn);
                }
            })
        }

        /// Restart as if the first `keep` bytes of an unsynchronized root slot
        /// write had reached the medium.
        pub fn crash_torn_root(&self, slot: RootSlot, keep: usize) -> Self {
            self.crash_with(|state| {
                let range = slot_range(slot);
                let end = range.start + keep.min(ROOT_SLOT_BYTES);
                let torn = state.root_volatile[range.start..end].to_vec();
                state.root_durable[range.start..end].copy_from_slice(&torn);
            })
        }

        fn crash_with(&self, tear: impl FnOnce(&mut GroupState)) -> Self {
            let mut state = self.state();
            tear(&mut state);
            let files = state
                .files
                .iter()
                .filter(|(_, entry)| entry.name_durable)
                .map(|(file, entry)| {
                    (
                        *file,
                        MemFile {
                            volatile: entry.durable.clone(),
                            durable: entry.durable.clone(),
                            linked: true,
                            name_durable: true,
                        },
                    )
                })
                .collect();
            let mut restarted = GroupState::new();
            restarted.root_volatile = state.root_durable.clone();
            restarted.root_durable = state.root_durable.clone();
            restarted.files = files;
            restarted.durable_names = state.durable_names.clone();
            restarted.strays = state.strays.clone();
            Self(Arc::new(Mutex::new(restarted)))
        }

        /// Edit the durable image of a present file, as media damage would.
        pub fn with_durable(&self, file: GroupFile, edit: impl FnOnce(&mut Vec<u8>)) {
            let mut state = self.state();
            let entry = state.files.get_mut(&file).expect("damaged file exists");
            edit(&mut entry.durable);
            if entry.linked {
                entry.volatile = entry.durable.clone();
            }
        }

        /// Edit the durable image of one root slot.
        pub fn with_durable_root(&self, slot: RootSlot, edit: impl FnOnce(&mut [u8])) {
            let mut state = self.state();
            let range = slot_range(slot);
            edit(&mut state.root_durable[range.clone()]);
            let durable = state.root_durable[range.clone()].to_vec();
            state.root_volatile[range].copy_from_slice(&durable);
        }

        /// Insert a durable file outside the group protocol, as a foreign
        /// writer or restored image would.
        pub fn insert_foreign(&self, file: GroupFile, bytes: Vec<u8>) {
            let mut state = self.state();
            state.durable_names.insert(file);
            state.files.insert(
                file,
                MemFile {
                    volatile: bytes.clone(),
                    durable: bytes,
                    linked: true,
                    name_durable: true,
                },
            );
        }

        /// Remove a durable file outside the group protocol.
        pub fn remove_foreign(&self, file: GroupFile) {
            self.state().files.remove(&file);
        }

        /// Place a durable directory entry that is not a group file.
        pub fn insert_stray(&self, name: &str) {
            self.state().strays.insert(name.into());
        }

        pub fn durable_image(&self, file: GroupFile) -> Option<Vec<u8>> {
            self.state()
                .files
                .get(&file)
                .filter(|entry| entry.name_durable)
                .map(|entry| entry.durable.clone())
        }

        pub fn durable_exists(&self, file: GroupFile) -> bool {
            self.state()
                .files
                .get(&file)
                .is_some_and(|entry| entry.name_durable)
        }

        pub fn durable_len(&self, file: GroupFile) -> Option<usize> {
            self.state()
                .files
                .get(&file)
                .filter(|entry| entry.name_durable)
                .map(|entry| entry.durable.len())
        }

        pub fn fail_close(&self, kind: io::ErrorKind) {
            self.state().close_error = Some(kind);
        }

        /// Test-only collection convenience. The production boundary streams.
        pub fn entries(&self) -> io::Result<Vec<OsString>> {
            let mut names = Vec::new();
            self.visit_entries(&mut |name| {
                names.push(name.to_owned());
                Ok(())
            })?;
            Ok(names)
        }

        pub fn close_not_entered_once(&self) {
            self.state().close_not_entered = true;
        }

        pub fn close_attempts(&self) -> usize {
            self.state().close_attempts
        }
    }

    impl SegmentGroupBackend for InMemoryGroup {
        /// This synthetic image backend has no persistent quota. It retains the
        /// explicit attempt and enforces cancellation/identity, but does not
        /// attest installed filesystem capacity or allocator admission.
        fn reserve_transaction(
            &self,
            plan: &super::TransactionSpacePlan,
        ) -> Result<(), super::TransactionReserveError> {
            plan.validate()
                .map_err(super::TransactionReserveError::Failed)?;
            let mut state = self
                .open_state()
                .map_err(super::TransactionReserveError::Failed)?;
            if state.transaction.is_some() {
                return Err(super::TransactionReserveError::Failed(
                    io::ErrorKind::WouldBlock.into(),
                ));
            }
            let a: &[u8; ROOT_SLOT_BYTES] = state.root_volatile[..ROOT_SLOT_BYTES]
                .try_into()
                .expect("root image");
            let b: &[u8; ROOT_SLOT_BYTES] = state.root_volatile[ROOT_SLOT_BYTES..]
                .try_into()
                .expect("root image");
            crate::root::validate_transaction_space_roots(plan, a, b)
                .map_err(|error| super::TransactionReserveError::Failed(io::Error::other(error)))?;
            state.transaction = Some((*plan, false));
            Ok(())
        }
        fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
            let mut state = self.open_state()?;
            if !state
                .transaction
                .as_ref()
                .is_some_and(|(plan, _)| plan.group_id == group_id && plan.batch_seq == batch_seq)
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            state.transaction = None;
            Ok(())
        }
        fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
            let mut state = self.open_state()?;
            if !state.transaction.as_ref().is_some_and(|(plan, entered)| {
                !entered && plan.group_id == group_id && plan.batch_seq == batch_seq
            }) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            state.transaction = None;
            Ok(())
        }
        fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
            let state = self.open_state()?;
            out.copy_from_slice(&state.root_volatile[slot_range(slot)]);
            Ok(())
        }

        fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
            let mut state = self.open_state()?;
            let fault = state.fault(GroupOp::RootWrite);
            if fault == Some(FaultTiming::BeforeEffect) {
                return Err(injected(GroupOp::RootWrite));
            }
            state.root_volatile[slot_range(slot)].copy_from_slice(bytes);
            match fault {
                Some(_) => Err(injected(GroupOp::RootWrite)),
                None => Ok(()),
            }
        }

        fn sync_root(&self) -> io::Result<()> {
            let mut state = self.open_state()?;
            let fault = state.fault(GroupOp::RootSync);
            if fault == Some(FaultTiming::BeforeEffect) {
                return Err(injected(GroupOp::RootSync));
            }
            state.root_durable = state.root_volatile.clone();
            match fault {
                Some(_) => Err(injected(GroupOp::RootSync)),
                None => Ok(()),
            }
        }

        fn visit_entries(
            &self,
            visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>,
        ) -> io::Result<()> {
            let state = self.open_state()?;
            visitor(OsStr::new(ROOT_FILE_NAME))?;
            for (file, entry) in &state.files {
                if entry.linked {
                    visitor(OsStr::new(&file.file_name()))?;
                }
            }
            for name in &state.strays {
                visitor(name)?;
            }
            Ok(())
        }

        fn exists(&self, file: GroupFile) -> io::Result<bool> {
            let state = self.open_state()?;
            Ok(state.files.get(&file).is_some_and(|entry| entry.linked))
        }

        fn create(&self, file: GroupFile) -> io::Result<()> {
            let mut state = self.open_state()?;
            if file.id == 0
                || state.durable_names.contains(&file)
                || state.files.get(&file).is_some_and(|entry| entry.linked)
            {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            let fault = state.fault(GroupOp::Create);
            if fault == Some(FaultTiming::BeforeEffect) {
                return Err(injected(GroupOp::Create));
            }
            state.files.insert(
                file,
                MemFile {
                    volatile: Vec::new(),
                    durable: Vec::new(),
                    linked: true,
                    name_durable: false,
                },
            );
            if fault.is_some() {
                // The name exists but its parent synchronization failed.
                return Err(injected(GroupOp::Create));
            }
            state.files.get_mut(&file).expect("created").name_durable = true;
            state.durable_names.insert(file);
            Ok(())
        }

        fn len(&self, file: GroupFile) -> io::Result<u64> {
            let mut state = self.open_state()?;
            Ok(state.linked(file)?.volatile.len() as u64)
        }

        fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
            let mut state = self.open_state()?;
            let entry = state.linked(file)?;
            let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = start
                .checked_add(out.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            out.copy_from_slice(
                entry
                    .volatile
                    .get(start..end)
                    .ok_or(io::ErrorKind::UnexpectedEof)?,
            );
            Ok(())
        }

        fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
            let mut state = self.open_state()?;
            let fault = state.fault(GroupOp::Write);
            if fault == Some(FaultTiming::BeforeEffect) {
                return Err(injected(GroupOp::Write));
            }
            let entry = state.linked(file)?;
            let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
            let end = start
                .checked_add(bytes.len())
                .ok_or(io::ErrorKind::InvalidInput)?;
            if start > entry.volatile.len() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            if end > entry.volatile.len() {
                entry.volatile.resize(end, 0);
            }
            entry.volatile[start..end].copy_from_slice(bytes);
            match fault {
                Some(_) => Err(injected(GroupOp::Write)),
                None => Ok(()),
            }
        }

        fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
            let mut state = self.open_state()?;
            let fault = state.fault(GroupOp::SetLen);
            if fault == Some(FaultTiming::BeforeEffect) {
                return Err(injected(GroupOp::SetLen));
            }
            let length = usize::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?;
            state.linked(file)?.volatile.resize(length, 0);
            match fault {
                Some(_) => Err(injected(GroupOp::SetLen)),
                None => Ok(()),
            }
        }

        fn sync(&self, file: GroupFile) -> io::Result<()> {
            let mut state = self.open_state()?;
            let fault = state.fault(GroupOp::Sync);
            if fault == Some(FaultTiming::BeforeEffect) {
                return Err(injected(GroupOp::Sync));
            }
            let entry = state.linked(file)?;
            entry.durable = entry.volatile.clone();
            match fault {
                Some(_) => Err(injected(GroupOp::Sync)),
                None => Ok(()),
            }
        }

        fn unlink(&self, file: GroupFile) -> io::Result<()> {
            let mut state = self.open_state()?;
            let fault = state.fault(GroupOp::Unlink);
            if fault == Some(FaultTiming::BeforeEffect) {
                return Err(injected(GroupOp::Unlink));
            }
            if let Some(entry) = state.files.get_mut(&file) {
                entry.linked = false;
            }
            if fault.is_some() {
                // The name is gone but the parent synchronization failed.
                return Err(injected(GroupOp::Unlink));
            }
            state.files.remove(&file);
            Ok(())
        }

        fn sync_names(&self) -> io::Result<()> {
            let mut state = self.open_state()?;
            let fault = state.fault(GroupOp::SyncNames);
            if fault == Some(FaultTiming::BeforeEffect) {
                return Err(injected(GroupOp::SyncNames));
            }
            let state = &mut *state;
            // Unlinks whose own parent synchronization failed become durable.
            state.files.retain(|_, entry| entry.linked);
            for (file, entry) in &mut state.files {
                entry.name_durable = true;
                state.durable_names.insert(*file);
            }
            match fault {
                Some(_) => Err(injected(GroupOp::SyncNames)),
                None => Ok(()),
            }
        }

        fn close(&self) -> BackendCloseOutcome {
            let mut state = match self.0.try_lock() {
                Ok(state) => state,
                Err(TryLockError::WouldBlock) => {
                    return BackendCloseOutcome::not_entered(io::ErrorKind::WouldBlock.into());
                }
                Err(TryLockError::Poisoned(_)) => {
                    return BackendCloseOutcome::retained(io::ErrorKind::Other.into());
                }
            };
            state.close_attempts += 1;
            match state.close {
                // A repeat close reports the first terminal disposition.
                CloseState::Drained => return BackendCloseOutcome::drained(Ok(())),
                CloseState::Retained(kind) => return BackendCloseOutcome::retained(kind.into()),
                CloseState::Open => {}
            }
            if std::mem::take(&mut state.close_not_entered) {
                return BackendCloseOutcome::not_entered(io::ErrorKind::WouldBlock.into());
            }
            if let Some(kind) = state.close_error.take() {
                state.close = CloseState::Retained(kind);
                return BackendCloseOutcome::retained(kind.into());
            }
            // Durable images stay behind for a later `crash` restart.
            state.close = CloseState::Drained;
            BackendCloseOutcome::drained(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BackendCloseEntry, BackendNativeDisposition};
    use std::ffi::OsString;

    #[test]
    fn shared_backends_stream_entries_and_do_not_replay_a_stopped_visit() {
        let group = std::sync::Arc::new(InMemoryGroup::new());
        group.create(GroupFile::segment(1)).unwrap();
        group.create(GroupFile::directory(1)).unwrap();
        let backend: Box<std::sync::Arc<dyn SegmentGroupBackend>> = Box::new(group);
        let mut visited = 0;
        let error = backend
            .visit_entries(&mut |_| {
                visited += 1;
                Err(io::ErrorKind::Interrupted.into())
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(visited, 1);
        backend
            .visit_entries(&mut |_| {
                visited += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(visited, 4);
        backend.close().into_result().unwrap();
    }

    #[test]
    fn names_are_deterministic_and_have_one_spelling() {
        let segment = GroupFile::segment(0x2a);
        assert_eq!(segment.file_name(), "000000000000002a.kvseg");
        assert_eq!(GroupFile::parse_name(&segment.file_name()), Some(segment));
        let checkpoint = GroupFile::checkpoint(7);
        assert_eq!(
            GroupFile::parse_name(&checkpoint.file_name()),
            Some(checkpoint)
        );
        for name in [
            "000000000000002A.kvseg",
            "00000000000002a.kvseg",
            "0000000000000000.kvseg",
            "000000000000002a.kvseg.tmp",
            "+00000000000002a.kvseg",
            ROOT_FILE_NAME,
        ] {
            assert_eq!(GroupFile::parse_name(name), None, "{name}");
        }
    }

    #[test]
    fn create_is_create_only_and_never_reuses_a_durable_name() {
        let group = InMemoryGroup::new();
        let file = GroupFile::segment(1);
        group.create(file).unwrap();
        assert_eq!(
            group.create(file).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        group.unlink(file).unwrap();
        assert!(!group.exists(file).unwrap());
        assert_eq!(
            group.create(file).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let restarted = group.crash();
        assert_eq!(
            restarted.create(file).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn create_without_parent_sync_is_lost_on_restart() {
        let group = InMemoryGroup::new();
        let file = GroupFile::checkpoint(3);
        group.fail(GroupOp::Create, 1, FaultTiming::AfterEffect);
        group.create(file).unwrap_err();
        assert!(group.exists(file).unwrap());
        assert!(!group.durable_exists(file));
        let restarted = group.crash();
        assert!(!restarted.exists(file).unwrap());
        // The name never became durable, so its intent may still create it.
        restarted.create(file).unwrap();
        assert!(restarted.crash().exists(file).unwrap());
    }

    #[test]
    fn unlink_is_complete_only_after_parent_sync() {
        let group = InMemoryGroup::new();
        let file = GroupFile::segment(4);
        group.create(file).unwrap();
        group.write(file, 0, b"sealed").unwrap();
        group.sync(file).unwrap();
        group.fail(GroupOp::Unlink, 1, FaultTiming::AfterEffect);
        group.unlink(file).unwrap_err();
        assert!(!group.exists(file).unwrap());
        // The listing no longer shows the name, yet the unlink is not durable.
        assert_eq!(group.entries().unwrap(), [OsString::from(ROOT_FILE_NAME)]);

        let restarted = group.crash();
        assert_eq!(
            restarted.entries().unwrap(),
            [ROOT_FILE_NAME.into(), OsString::from(file.file_name())]
        );
        let mut bytes = [0u8; 6];
        restarted.read(file, 0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"sealed");
        restarted.unlink(file).unwrap();
        // Retrying a completed deletion is idempotent.
        restarted.unlink(file).unwrap();
        assert!(!restarted.crash().exists(file).unwrap());
    }

    #[test]
    fn name_sync_settles_unknown_creates_and_unlinks() {
        let group = InMemoryGroup::new();
        let created = GroupFile::segment(1);
        let removed = GroupFile::checkpoint(1);
        group.create(removed).unwrap();
        group.fail(GroupOp::Create, 1, FaultTiming::AfterEffect);
        group.create(created).unwrap_err();
        group.fail(GroupOp::Unlink, 1, FaultTiming::AfterEffect);
        group.unlink(removed).unwrap_err();
        // The same process lists the new name only; power loss reverses both.
        assert_eq!(
            group.entries().unwrap(),
            [ROOT_FILE_NAME.into(), OsString::from(created.file_name())]
        );
        let lost = group.crash();
        assert!(!lost.exists(created).unwrap());
        assert!(lost.exists(removed).unwrap());

        group.fail(GroupOp::SyncNames, 1, FaultTiming::BeforeEffect);
        group.sync_names().unwrap_err();
        assert!(!group.durable_exists(created));
        assert!(group.durable_exists(removed));
        // A failure after the effect is the unknown case: it persisted.
        group.fail(GroupOp::SyncNames, 1, FaultTiming::AfterEffect);
        group.sync_names().unwrap_err();
        let settled = group.crash();
        assert!(settled.exists(created).unwrap());
        assert!(!settled.exists(removed).unwrap());
        // A name made durable this way is never created again.
        group.unlink(created).unwrap();
        assert_eq!(
            group.create(created).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        group.sync_names().unwrap();
        assert!(!group.crash().exists(created).unwrap());
    }

    #[test]
    fn unsynchronized_bytes_are_lost_or_torn_on_restart() {
        let group = InMemoryGroup::new();
        let file = GroupFile::segment(1);
        group.create(file).unwrap();
        group.write(file, 0, b"durable").unwrap();
        group.sync(file).unwrap();
        group.write(file, 7, b"-volatile").unwrap();
        assert_eq!(group.len(file).unwrap(), 16);
        assert_eq!(group.crash().len(file).unwrap(), 7);
        let torn = group.crash_torn(file, 3);
        let mut bytes = [0u8; 10];
        torn.read(file, 0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"durable-vo");
        assert_eq!(
            group.write(file, 17, b"hole").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn injected_sync_after_effect_persists_but_reports_failure() {
        let group = InMemoryGroup::new();
        let file = GroupFile::segment(1);
        group.create(file).unwrap();
        group.write(file, 0, b"unknown").unwrap();
        group.fail(GroupOp::Sync, 1, FaultTiming::AfterEffect);
        group.sync(file).unwrap_err();
        assert_eq!(group.durable_len(file), Some(7));
        group.write(file, 7, b"!").unwrap();
        group.fail(GroupOp::Sync, 1, FaultTiming::BeforeEffect);
        group.sync(file).unwrap_err();
        assert_eq!(group.durable_len(file), Some(7));
    }

    #[test]
    fn close_is_fallible_and_one_shot() {
        let group = InMemoryGroup::new();
        group.create(GroupFile::segment(1)).unwrap();
        group.close_not_entered_once();
        let busy = group.close();
        assert_eq!(busy.entry(), BackendCloseEntry::NotEntered);
        assert!(group.exists(GroupFile::segment(1)).unwrap());
        let drained = group.close();
        assert_eq!(
            drained.native_disposition(),
            BackendNativeDisposition::Drained
        );
        drained.into_result().unwrap();
        assert_eq!(
            group.exists(GroupFile::segment(1)).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            group.close().native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert!(group.crash().exists(GroupFile::segment(1)).unwrap());

        let failing = InMemoryGroup::new();
        failing.fail_close(io::ErrorKind::TimedOut);
        let retained = failing.close();
        assert_eq!(retained.entry(), BackendCloseEntry::Entered);
        assert_eq!(
            retained.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            retained.into_result().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        // A repeat reports the first terminal disposition without re-entry.
        let repeat = failing.close();
        assert_eq!(
            repeat.native_disposition(),
            BackendNativeDisposition::Retained
        );
        assert_eq!(
            repeat.into_result().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(failing.close_attempts(), 2);
        assert_eq!(
            failing.sync_root().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn torn_root_write_keeps_the_prefix_only() {
        let group = InMemoryGroup::new();
        let bytes = [0x5a; ROOT_SLOT_BYTES];
        group.write_root(RootSlot::B, &bytes).unwrap();
        let torn = group.crash_torn_root(RootSlot::B, 100);
        let mut slot = [0u8; ROOT_SLOT_BYTES];
        torn.read_root(RootSlot::B, &mut slot).unwrap();
        assert!(slot[..100].iter().all(|&byte| byte == 0x5a));
        assert!(slot[100..].iter().all(|&byte| byte == 0));
        torn.read_root(RootSlot::A, &mut slot).unwrap();
        assert!(slot.iter().all(|&byte| byte == 0));
    }
}
