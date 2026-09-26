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

use std::ffi::OsString;
use std::io;

use crate::core::BackendCloseOutcome;
use crate::root::{ROOT_SLOT_BYTES, RootSlot};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum FileKind {
    Segment,
    Checkpoint,
}

impl FileKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Segment => ".kvseg",
            Self::Checkpoint => ".kvckpt",
        }
    }

    pub(crate) fn tag(self) -> u8 {
        match self {
            Self::Segment => 1,
            Self::Checkpoint => 2,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Segment),
            2 => Some(Self::Checkpoint),
            _ => None,
        }
    }
}

/// One owned file of a group. Identifier zero is never allocated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct GroupFile {
    pub(crate) kind: FileKind,
    pub(crate) id: u64,
}

impl GroupFile {
    pub(crate) const fn segment(id: u64) -> Self {
        Self {
            kind: FileKind::Segment,
            id,
        }
    }

    pub(crate) const fn checkpoint(id: u64) -> Self {
        Self {
            kind: FileKind::Checkpoint,
            id,
        }
    }

    /// The deterministic directory entry. Identifiers use sixteen lowercase
    /// hexadecimal digits so a name has exactly one spelling.
    pub(crate) fn file_name(self) -> String {
        format!("{:016x}{}", self.id, self.kind.suffix())
    }

    /// Parse a census entry. Any other spelling is not a group file.
    pub(crate) fn parse_name(name: &str) -> Option<Self> {
        let (digits, kind) = if let Some(digits) = name.strip_suffix(FileKind::Segment.suffix()) {
            (digits, FileKind::Segment)
        } else {
            (
                name.strip_suffix(FileKind::Checkpoint.suffix())?,
                FileKind::Checkpoint,
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
pub(crate) const ROOT_FILE_NAME: &str = "root.kvroot";

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
pub(crate) trait SegmentGroupBackend: Send + Sync {
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()>;
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()>;
    fn sync_root(&self) -> io::Result<()>;
    /// Every entry of the group directory, unfiltered and in any order,
    /// including `ROOT_FILE_NAME`. The census fails closed on any other name
    /// that `GroupFile::parse_name` rejects, such as a temporary file, another
    /// spelling of an identifier, or a subdirectory, so an implementation
    /// must not hide entries it does not recognize.
    fn entries(&self) -> io::Result<Vec<OsString>>;
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

#[cfg(test)]
pub(crate) use memory::{FaultTiming, GroupOp, InMemoryGroup};

/// Volatile group with explicit durable images for crash and fault tests.
#[cfg(test)]
mod memory {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsString;
    use std::io;
    use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

    use super::{GroupFile, ROOT_FILE_NAME, SegmentGroupBackend};
    use crate::core::BackendCloseOutcome;
    use crate::root::{ROOT_SLOT_BYTES, RootSlot};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum GroupOp {
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
    pub(crate) enum FaultTiming {
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
            }
        }

        fn fault(&mut self, op: GroupOp) -> Option<FaultTiming> {
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
    pub(crate) struct InMemoryGroup(Arc<Mutex<GroupState>>);

    impl InMemoryGroup {
        pub(crate) fn new() -> Self {
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
        pub(crate) fn fail(&self, op: GroupOp, nth: usize, timing: FaultTiming) {
            assert!(nth > 0);
            self.state().faults.push(Fault {
                op,
                remaining: nth,
                timing,
            });
        }

        /// Restart from the durable images. Unsynchronized bytes, unsynced
        /// creations, and unsynced unlinks are lost.
        pub(crate) fn crash(&self) -> Self {
            self.crash_with(|_| {})
        }

        /// Restart as if `keep` bytes of `file`'s unsynchronized append had
        /// reached the medium before the crash.
        pub(crate) fn crash_torn(&self, file: GroupFile, keep: usize) -> Self {
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
        pub(crate) fn crash_torn_root(&self, slot: RootSlot, keep: usize) -> Self {
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
        pub(crate) fn with_durable(&self, file: GroupFile, edit: impl FnOnce(&mut Vec<u8>)) {
            let mut state = self.state();
            let entry = state.files.get_mut(&file).expect("damaged file exists");
            edit(&mut entry.durable);
            if entry.linked {
                entry.volatile = entry.durable.clone();
            }
        }

        /// Edit the durable image of one root slot.
        pub(crate) fn with_durable_root(&self, slot: RootSlot, edit: impl FnOnce(&mut [u8])) {
            let mut state = self.state();
            let range = slot_range(slot);
            edit(&mut state.root_durable[range.clone()]);
            let durable = state.root_durable[range.clone()].to_vec();
            state.root_volatile[range].copy_from_slice(&durable);
        }

        /// Insert a durable file outside the group protocol, as a foreign
        /// writer or restored image would.
        pub(crate) fn insert_foreign(&self, file: GroupFile, bytes: Vec<u8>) {
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
        pub(crate) fn remove_foreign(&self, file: GroupFile) {
            self.state().files.remove(&file);
        }

        /// Place a durable directory entry that is not a group file.
        pub(crate) fn insert_stray(&self, name: &str) {
            self.state().strays.insert(name.into());
        }

        pub(crate) fn durable_image(&self, file: GroupFile) -> Option<Vec<u8>> {
            self.state()
                .files
                .get(&file)
                .filter(|entry| entry.name_durable)
                .map(|entry| entry.durable.clone())
        }

        pub(crate) fn durable_exists(&self, file: GroupFile) -> bool {
            self.state()
                .files
                .get(&file)
                .is_some_and(|entry| entry.name_durable)
        }

        pub(crate) fn durable_len(&self, file: GroupFile) -> Option<usize> {
            self.state()
                .files
                .get(&file)
                .filter(|entry| entry.name_durable)
                .map(|entry| entry.durable.len())
        }

        pub(crate) fn fail_close(&self, kind: io::ErrorKind) {
            self.state().close_error = Some(kind);
        }

        pub(crate) fn close_not_entered_once(&self) {
            self.state().close_not_entered = true;
        }

        pub(crate) fn close_attempts(&self) -> usize {
            self.state().close_attempts
        }
    }

    impl SegmentGroupBackend for InMemoryGroup {
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

        fn entries(&self) -> io::Result<Vec<OsString>> {
            let state = self.open_state()?;
            let files = state
                .files
                .iter()
                .filter(|(_, entry)| entry.linked)
                .map(|(file, _)| file.file_name().into());
            Ok(std::iter::once(ROOT_FILE_NAME.into())
                .chain(files)
                .chain(state.strays.iter().cloned())
                .collect())
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
