//! Append-only directory page arenas owned by the segmented file group.
//!
//! A writer always allocates a fresh arena after reopen; it never resumes a
//! physical page offset whose previous append may have had an unknown result.
//! Rolling synchronizes the old arena before reserving a new identity. File
//! growth/descriptor custody belongs to the installed group backend. Root
//! publication and reachability reclamation belong to its transaction owner.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::core::{CoreError, ResidentLease, StorageAdmission};
use crate::directory::{DIRECTORY_PAGE_BYTES, DirectoryBackend, DirectoryPageRef, page_digest};
use crate::group::{GroupFile, SegmentGroupBackend};
use crate::segment::{crc32c, le_u32, le_u64};

const MAGIC: [u8; 16] = *b"KASUMI-KVARENA01";
const VERSION: u32 = 1;
pub(crate) const HEADER_BYTES: usize = 4096;
const CHECKSUM_AT: usize = HEADER_BYTES - 4;
const ARENA_BYTES: u64 = 64 << 20;
const MAX_PAGES: u64 = (ARENA_BYTES - HEADER_BYTES as u64) / DIRECTORY_PAGE_BYTES as u64;
const LEASE_ALLOWANCE: usize = 128;
const ALLOCATION_ALLOWANCE: usize = 64;

/// Both methods publish mirrored superblocks through the one serialized
/// group owner. Reservation must be durable before returning its never-used
/// identifier; confirmation follows the durable file name and header. The
/// owner must resolve any outstanding intent before starting another writer.
pub(crate) trait DirectoryArenaRoll: Send + Sync {
    fn reserve(&self) -> Result<u64, CoreError>;
    fn confirm(&self, arena_id: u64) -> Result<(), CoreError>;
}

struct ActiveArena {
    id: u64,
    pages: u64,
}

struct Writer {
    active: Option<ActiveArena>,
    poisoned: bool,
    // This exact header buffer is charged with DirectoryArenaBackend before
    // any transaction effects; rolling never competes for another grant.
    header: [u8; HEADER_BYTES],
}
impl Default for Writer {
    fn default() -> Self {
        Self {
            active: None,
            poisoned: false,
            header: [0; HEADER_BYTES],
        }
    }
}

/// Cumulative confirmed arena I/O since this adapter was constructed.
/// Counters saturate at u64::MAX. They count successful backend callbacks,
/// even if a subsequent owner or digest check rejects their result. A failed
/// callback may have had partial effects, so these are not exact device I/O
/// counts. Standalone intent recovery is not included.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectoryArenaStats {
    /// Full page payload reads, including repeated validation and uncached
    /// maintenance reads. Cache hits and arena header reads are excluded.
    pub(crate) pages_read: u64,
    /// Full page appends, including private pages never published by a root.
    /// Arena header writes are excluded.
    pub(crate) pages_written: u64,
    /// Arena sync callbacks for fresh headers, old arenas during rolls, and
    /// explicit sync_pages calls. Mirrored-root/name syncs are excluded.
    pub(crate) syncs: u64,
}

pub(crate) struct DirectoryArenaBackend {
    backend: Arc<dyn SegmentGroupBackend>,
    roll: Arc<dyn DirectoryArenaRoll>,
    admission: Arc<dyn StorageAdmission>,
    group_id: [u8; 16],
    writer: Mutex<Writer>,
    // Included in the adapter's fixed admission. Reads must not need a new
    // header reservation after a commit has durably published its directory.
    // Serialize only header access; page outputs belong to admitted callers.
    read_header: Mutex<[u8; HEADER_BYTES]>,
    max_pages: u64,
    pages_read: AtomicU64,
    pages_written: AtomicU64,
    syncs: AtomicU64,
    _lease: Box<dyn ResidentLease>,
}

impl DirectoryArenaBackend {
    pub(crate) fn new(
        backend: Arc<dyn SegmentGroupBackend>,
        roll: Arc<dyn DirectoryArenaRoll>,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
    ) -> Result<Self, CoreError> {
        check_owner(&admission)?;
        let lease = admission.reserve_workspace(
            (std::mem::size_of::<Self>() + LEASE_ALLOWANCE + ALLOCATION_ALLOWANCE) as u64,
        )?;
        check_owner(&admission)?;
        Ok(Self {
            backend,
            roll,
            admission,
            group_id,
            writer: Mutex::new(Writer::default()),
            read_header: Mutex::new([0; HEADER_BYTES]),
            max_pages: MAX_PAGES,
            pages_read: AtomicU64::new(0),
            pages_written: AtomicU64::new(0),
            syncs: AtomicU64::new(0),
            _lease: lease,
        })
    }

    /// Observe counters without allocation, reservation, or backend I/O.
    /// The current owner is checked; concurrent callers may observe a read
    /// or append completing between the individual counter loads.
    pub(crate) fn stats(&self) -> Result<DirectoryArenaStats, CoreError> {
        check_owner(&self.admission)?;
        Ok(DirectoryArenaStats {
            pages_read: self.pages_read.load(Ordering::Relaxed),
            pages_written: self.pages_written.load(Ordering::Relaxed),
            syncs: self.syncs.load(Ordering::Relaxed),
        })
    }

    /// Durably allocate a fresh arena even when the current one has room.
    /// Compaction uses this boundary before copying pages, so every later
    /// append has an identity beyond its recorded evacuation cutoff.
    pub(crate) fn force_roll(&self) -> Result<(), CoreError> {
        check_owner(&self.admission)?;
        let mut writer = self.writer.lock().map_err(|_| CoreError::OwnerFailed)?;
        check_owner(&self.admission)?;
        if writer.poisoned {
            return Err(CoreError::OwnerFailed);
        }
        let result = self.roll(&mut writer);
        if result.is_err() {
            writer.poisoned = true;
        }
        result
    }

    fn roll(&self, writer: &mut Writer) -> Result<(), CoreError> {
        if let Some(active) = &writer.active {
            self.backend.sync(GroupFile::directory(active.id))?;
            record_io(&self.syncs);
            check_owner(&self.admission)?;
        }
        let id = self.roll.reserve()?;
        check_owner(&self.admission)?;
        if id == 0 || id == u64::MAX {
            return Err(CoreError::Corrupt(
                "directory owner allocated an invalid identifier",
            ));
        }
        let file = GroupFile::directory(id);
        self.backend.create(file)?;
        check_owner(&self.admission)?;
        encode_header_into(self.group_id, id, &mut writer.header);
        self.backend.write(file, 0, &writer.header)?;
        check_owner(&self.admission)?;
        self.backend.sync(file)?;
        record_io(&self.syncs);
        check_owner(&self.admission)?;
        self.roll.confirm(id)?;
        check_owner(&self.admission)?;
        writer.active = Some(ActiveArena { id, pages: 0 });
        Ok(())
    }

    fn append(&self, writer: &mut Writer, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        if writer
            .active
            .as_ref()
            .is_none_or(|active| active.pages == self.max_pages)
        {
            self.roll(writer)?;
        }
        let active = writer.active.as_mut().expect("rolled arena");
        let reference = DirectoryPageRef {
            arena_id: active.id,
            page_index: active.pages,
            sha256: page_digest(bytes),
        };
        self.backend.write(
            GroupFile::directory(active.id),
            HEADER_BYTES as u64 + active.pages * DIRECTORY_PAGE_BYTES as u64,
            bytes,
        )?;
        record_io(&self.pages_written);
        check_owner(&self.admission)?;
        active.pages += 1;
        Ok(reference)
    }
}

impl DirectoryBackend for DirectoryArenaBackend {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
        check_owner(&self.admission)?;
        if out.len() != DIRECTORY_PAGE_BYTES {
            return Err(CoreError::InvalidInput("directory read requires one page"));
        }
        if reference.arena_id == 0
            || reference.arena_id == u64::MAX
            || reference.page_index >= MAX_PAGES
        {
            return Err(CoreError::Corrupt("directory page is outside its arena"));
        }
        let file = GroupFile::directory(reference.arena_id);
        let mut header = self
            .read_header
            .lock()
            .map_err(|_| CoreError::OwnerFailed)?;
        // The owner may have expired while this reader waited for scratch.
        check_owner(&self.admission)?;
        self.backend.read(file, 0, &mut *header)?;
        check_owner(&self.admission)?;
        validate_header(&header, self.group_id, reference.arena_id)?;
        drop(header);
        let at = HEADER_BYTES as u64 + reference.page_index * DIRECTORY_PAGE_BYTES as u64;
        let len = self.backend.len(file)?;
        check_owner(&self.admission)?;
        if len < at + DIRECTORY_PAGE_BYTES as u64 || len > ARENA_BYTES {
            return Err(CoreError::Corrupt("directory arena length is invalid"));
        }
        self.backend.read(file, at, out)?;
        record_io(&self.pages_read);
        check_owner(&self.admission)?;
        if page_digest(out) != reference.sha256 {
            return Err(CoreError::Corrupt("directory page digest differs"));
        }
        Ok(())
    }

    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        check_owner(&self.admission)?;
        if bytes.len() != DIRECTORY_PAGE_BYTES {
            return Err(CoreError::InvalidInput(
                "directory append requires one page",
            ));
        }
        let mut writer = self.writer.lock().map_err(|_| CoreError::OwnerFailed)?;
        check_owner(&self.admission)?;
        if writer.poisoned {
            return Err(CoreError::OwnerFailed);
        }
        let result = self.append(&mut writer, bytes);
        // Even an error after a private append fences this writer: retrying
        // its offset could alias an immutable page reference held elsewhere.
        if result.is_err() {
            writer.poisoned = true;
        }
        result
    }

    fn sync_pages(&self) -> Result<(), CoreError> {
        check_owner(&self.admission)?;
        let mut writer = self.writer.lock().map_err(|_| CoreError::OwnerFailed)?;
        if writer.poisoned {
            return Err(CoreError::OwnerFailed);
        }
        let result = (|| {
            if let Some(active) = &writer.active {
                self.backend.sync(GroupFile::directory(active.id))?;
                record_io(&self.syncs);
            }
            check_owner(&self.admission)
        })();
        if result.is_err() {
            writer.poisoned = true;
        }
        result
    }
}

fn record_io(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}

/// Complete the exact pending allocation selected by the durable root.
/// No page can have been appended before confirmation, so the only accepted
/// existing image is a prefix of this arena's own canonical identity header.
/// Successful return proves the name and complete header are durable; the
/// caller then publishes confirmation. Any I/O error requires owner fencing
/// and reopen, even when this helper's visible effect appears incomplete.
pub(crate) fn recover_directory_intent(
    backend: &dyn SegmentGroupBackend,
    admission: &Arc<dyn StorageAdmission>,
    group_id: [u8; 16],
    arena_id: u64,
) -> Result<(), CoreError> {
    check_owner(admission)?;
    if arena_id == 0 || arena_id == u64::MAX {
        return Err(CoreError::InvalidInput(
            "directory intent identifier is invalid",
        ));
    }
    let _workspace = admission.reserve_workspace((2 * HEADER_BYTES + LEASE_ALLOWANCE) as u64)?;
    check_owner(admission)?;
    let expected = encode_header(group_id, arena_id);
    let file = GroupFile::directory(arena_id);
    let exists = backend.exists(file)?;
    check_owner(admission)?;
    if exists {
        let len = backend.len(file)?;
        check_owner(admission)?;
        if len > HEADER_BYTES as u64 {
            return Err(CoreError::Corrupt(
                "unconfirmed directory holds page payload",
            ));
        }
        let mut observed = [0u8; HEADER_BYTES];
        backend.read(file, 0, &mut observed[..len as usize])?;
        check_owner(admission)?;
        if observed[..len as usize] != expected[..len as usize] {
            return Err(CoreError::Corrupt(
                "unconfirmed directory holds bytes other than its header",
            ));
        }
        // A prior create may have failed after establishing a visible name
        // whose parent sync was not durable. Validate before adopting it.
        backend.sync_names()?;
        check_owner(admission)?;
    } else {
        backend.create(file)?;
        check_owner(admission)?;
    }
    backend.write(file, 0, &expected)?;
    check_owner(admission)?;
    backend.sync(file)?;
    check_owner(admission)
}

fn check_owner(admission: &Arc<dyn StorageAdmission>) -> Result<(), CoreError> {
    admission.check_owner().map_err(|_| CoreError::OwnerFailed)
}

fn encode_header(group_id: [u8; 16], arena_id: u64) -> [u8; HEADER_BYTES] {
    let mut bytes = [0u8; HEADER_BYTES];
    encode_header_into(group_id, arena_id, &mut bytes);
    bytes
}

fn encode_header_into(group_id: [u8; 16], arena_id: u64, bytes: &mut [u8; HEADER_BYTES]) {
    bytes.fill(0);
    bytes[..16].copy_from_slice(&MAGIC);
    bytes[16..20].copy_from_slice(&VERSION.to_le_bytes());
    bytes[24..40].copy_from_slice(&group_id);
    bytes[40..48].copy_from_slice(&arena_id.to_le_bytes());
    bytes[48..52].copy_from_slice(&(DIRECTORY_PAGE_BYTES as u32).to_le_bytes());
    let checksum = crc32c(&bytes[..CHECKSUM_AT]);
    bytes[CHECKSUM_AT..].copy_from_slice(&checksum.to_le_bytes());
}

fn validate_header(
    bytes: &[u8; HEADER_BYTES],
    group_id: [u8; 16],
    arena_id: u64,
) -> Result<(), CoreError> {
    if bytes[..16] != MAGIC
        || le_u32(&bytes[16..20]) != VERSION
        || bytes[20..24].iter().any(|&byte| byte != 0)
        || bytes[24..40] != group_id
        || le_u64(&bytes[40..48]) != arena_id
        || le_u32(&bytes[48..52]) != DIRECTORY_PAGE_BYTES as u32
        || bytes[52..CHECKSUM_AT].iter().any(|&byte| byte != 0)
        || le_u32(&bytes[CHECKSUM_AT..]) != crc32c(&bytes[..CHECKSUM_AT])
    {
        return Err(CoreError::Corrupt("directory arena header is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{AdmissionError, BackendCloseOutcome, OwnerFailed};
    use crate::directory::{DirectoryBuilder, DirectoryKey, DirectoryReader, DirectoryValue};
    use crate::group::{FaultTiming, GroupOp, InMemoryGroup};
    use crate::root::{ROOT_SLOT_BYTES, RootSlot, Superblock, publish_root};
    use crate::segment::test_support::GROUP;
    use std::ffi::OsStr;
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Default)]
    struct Admission {
        failed: AtomicBool,
        fail_after_check: AtomicBool,
        deny_workspace: AtomicBool,
        workspace_calls: AtomicUsize,
        last_workspace_bytes: AtomicU64,
    }
    impl StorageAdmission for Admission {
        fn check_owner(&self) -> Result<(), OwnerFailed> {
            if self.failed.load(Ordering::SeqCst) {
                Err(OwnerFailed)
            } else {
                if self.fail_after_check.swap(false, Ordering::SeqCst) {
                    self.failed.store(true, Ordering::SeqCst);
                }
                Ok(())
            }
        }
        fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
            self.check_owner()
                .map_err(|_| AdmissionError::OwnerFailed)?;
            self.workspace_calls.fetch_add(1, Ordering::SeqCst);
            self.last_workspace_bytes.store(bytes, Ordering::SeqCst);
            if self.deny_workspace.load(Ordering::SeqCst) {
                return Err(AdmissionError::CapacityDenied);
            }
            Ok(Box::new(()))
        }
        fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
            Ok(())
        }
        fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
            Ok(())
        }
        fn owner_failed(&self) {
            self.failed.store(true, Ordering::SeqCst);
        }

        fn quote_cache_memory(
            &self,
            bytes: u64,
        ) -> Result<crate::CacheMemoryQuote, crate::AdmissionError> {
            crate::cache_test::quote::<Self>(bytes)
        }
        fn reserve_cache_memory(
            self: std::sync::Arc<Self>,
            bytes: u64,
        ) -> Result<crate::CacheMemoryLease, crate::AdmissionError> {
            crate::cache_test::reserve(self, bytes)
        }
    }
    impl crate::cache_test::Provider for Admission {
        fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
            let _ = first;
            self.workspace_calls.fetch_add(1, Ordering::SeqCst);
            self.last_workspace_bytes.store(bytes, Ordering::SeqCst);
            if self.deny_workspace.load(Ordering::SeqCst) {
                Err(AdmissionError::CapacityDenied)
            } else {
                Ok(())
            }
        }
        fn release_cache(&self, bytes: u64, last: bool) {
            let _ = (bytes, last);
        }
    }

    struct Roll {
        group: InMemoryGroup,
        root: Mutex<Superblock>,
    }
    impl DirectoryArenaRoll for Roll {
        fn reserve(&self) -> Result<u64, CoreError> {
            let mut root = self.root.lock().unwrap();
            let (next, id) = root.reserve_directory()?;
            publish_root(&self.group, &root, &next)?;
            *root = next;
            Ok(id)
        }
        fn confirm(&self, id: u64) -> Result<(), CoreError> {
            let mut root = self.root.lock().unwrap();
            let next = root.confirm_directory(id)?;
            publish_root(&self.group, &root, &next)?;
            *root = next;
            Ok(())
        }
    }

    fn setup() -> (
        InMemoryGroup,
        Arc<Roll>,
        Arc<Admission>,
        DirectoryArenaBackend,
    ) {
        let group = InMemoryGroup::new();
        let roll = Arc::new(Roll {
            group: group.clone(),
            root: Mutex::new(Superblock::genesis(GROUP)),
        });
        let admission = Arc::new(Admission::default());
        let mut arena = DirectoryArenaBackend::new(
            Arc::new(group.clone()),
            roll.clone(),
            admission.clone(),
            GROUP,
        )
        .unwrap();
        arena.max_pages = 2;
        (group, roll, admission, arena)
    }

    #[test]
    fn retained_read_header_is_charged_once_and_reused_during_workspace_denial() {
        let (group, _, admission, arena) = setup();
        assert_eq!(admission.workspace_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            admission.last_workspace_bytes.load(Ordering::SeqCst),
            (std::mem::size_of::<DirectoryArenaBackend>() + LEASE_ALLOWANCE + ALLOCATION_ALLOWANCE)
                as u64
        );
        assert!(admission.last_workspace_bytes.load(Ordering::SeqCst) >= HEADER_BYTES as u64);
        let references = [1, 2, 3].map(|byte| {
            (
                arena.append_page(&[byte; DIRECTORY_PAGE_BYTES]).unwrap(),
                byte,
            )
        });
        arena.sync_pages().unwrap();
        assert_ne!(references[0].0.arena_id, references[2].0.arena_id);
        admission.deny_workspace.store(true, Ordering::SeqCst);
        assert!(matches!(
            admission.reserve_workspace(1),
            Err(AdmissionError::CapacityDenied)
        ));
        let calls = admission.workspace_calls.load(Ordering::SeqCst);
        // These callers own their page outputs. Only the arena identity header
        // is shared, including when readers select different immutable arenas.
        std::thread::scope(|scope| {
            for (reference, byte) in references {
                let arena = &arena;
                scope.spawn(move || {
                    let mut out = [0; DIRECTORY_PAGE_BYTES];
                    for _ in 0..16 {
                        arena.read_page(reference, &mut out).unwrap();
                        assert_eq!(out, [byte; DIRECTORY_PAGE_BYTES]);
                    }
                });
            }
        });
        assert_eq!(admission.workspace_calls.load(Ordering::SeqCst), calls);
        assert_eq!(arena.stats().unwrap().pages_read, 48);

        let reference = references[2].0;
        group
            .write(
                GroupFile::directory(reference.arena_id),
                0,
                &encode_header([9; 16], reference.arena_id),
            )
            .unwrap();
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        assert!(matches!(
            arena.read_page(reference, &mut out),
            Err(CoreError::Corrupt(_))
        ));
        assert_eq!(out, [0; DIRECTORY_PAGE_BYTES]);
        group
            .write(
                GroupFile::directory(reference.arena_id),
                0,
                &encode_header(GROUP, reference.arena_id),
            )
            .unwrap();
        arena.read_page(reference, &mut out).unwrap();
        assert_eq!(out, [3; DIRECTORY_PAGE_BYTES]);
        assert_eq!(admission.workspace_calls.load(Ordering::SeqCst), calls);
    }

    #[test]
    fn poisoned_retained_header_rejects_reads_before_backend_io() {
        let (group, _, admission, mut arena) = setup();
        let reference = arena.append_page(&[3; DIRECTORY_PAGE_BYTES]).unwrap();
        let backend = Arc::new(ExpiringGroup {
            inner: group,
            admission,
            expire: Mutex::new(None),
            effects: Mutex::new(Vec::new()),
        });
        arena.backend = backend.clone();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _header = arena.read_header.lock().unwrap();
                panic!("poison arena read scratch");
            }))
            .is_err()
        );
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        for _ in 0..2 {
            assert!(matches!(
                arena.read_page(reference, &mut out),
                Err(CoreError::OwnerFailed)
            ));
        }
        assert!(backend.effects.lock().unwrap().is_empty());
        assert_eq!(out, [0; DIRECTORY_PAGE_BYTES]);
    }

    #[test]
    fn io_stats_count_page_payloads_and_every_arena_sync_and_reset_on_reopen() {
        let (group, roll, admission, arena) = setup();
        arena.sync_pages().unwrap();
        assert_eq!(arena.stats().unwrap(), DirectoryArenaStats::default());
        let first = arena.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
        assert_eq!(
            arena.stats().unwrap(),
            DirectoryArenaStats {
                pages_read: 0,
                pages_written: 1,
                syncs: 1
            }
        );
        arena.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
        arena.append_page(&[3; DIRECTORY_PAGE_BYTES]).unwrap();
        arena.sync_pages().unwrap();
        arena.force_roll().unwrap();
        let mut bytes = [0; DIRECTORY_PAGE_BYTES];
        for _ in 0..3 {
            arena.read_page(first, &mut bytes).unwrap();
        }
        let mut wrong = first;
        wrong.sha256[0] ^= 1;
        assert!(matches!(
            arena.read_page(wrong, &mut bytes),
            Err(CoreError::Corrupt(_))
        ));
        assert_eq!(
            arena.stats().unwrap(),
            DirectoryArenaStats {
                pages_read: 4,
                pages_written: 3,
                syncs: 6
            }
        );
        let group = group.crash();
        let roll = Arc::new(Roll {
            group: group.clone(),
            root: Mutex::new(roll.root.lock().unwrap().clone()),
        });
        let reopened = DirectoryArenaBackend::new(Arc::new(group), roll, admission, GROUP).unwrap();
        assert_eq!(reopened.stats().unwrap(), DirectoryArenaStats::default());
        reopened.read_page(first, &mut bytes).unwrap();
        assert_eq!(bytes, [1; DIRECTORY_PAGE_BYTES]);
        assert_eq!(reopened.stats().unwrap().pages_read, 1);
    }

    #[test]
    fn io_stats_exclude_cache_hits_and_count_private_misses_and_appends() {
        use crate::cache::CacheConfig;
        use crate::page_cache::CachedDirectoryBackend;

        let (_, _, admission, arena) = setup();
        let cached = CachedDirectoryBackend::new(
            &arena,
            admission,
            GROUP,
            CacheConfig {
                byte_limit: 1 << 20,
            },
        );
        let private = cached.maintenance_private_view();
        let first = private.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
        let second = private.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
        private.sync_pages().unwrap();
        assert_eq!(
            arena.stats().unwrap(),
            DirectoryArenaStats {
                pages_read: 0,
                pages_written: 2,
                syncs: 2
            }
        );
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        cached.read_page(first, &mut out).unwrap();
        for _ in 0..3 {
            cached.read_page(first, &mut out).unwrap();
            private.read_page(first, &mut out).unwrap();
        }
        assert_eq!(arena.stats().unwrap().pages_read, 1);
        for _ in 0..2 {
            private.read_page(second, &mut out).unwrap();
        }
        assert_eq!(arena.stats().unwrap().pages_read, 3);
        let published = cached.maintenance_view();
        for _ in 0..3 {
            published.read_page(second, &mut out).unwrap();
        }
        assert_eq!(arena.stats().unwrap().pages_read, 4);
        assert_eq!(out, [2; DIRECTORY_PAGE_BYTES]);
    }

    #[test]
    fn io_stats_saturate_without_reservation_and_check_the_current_owner() {
        let (_, _, admission, arena) = setup();
        arena.pages_read.store(u64::MAX - 1, Ordering::Relaxed);
        arena.pages_written.store(u64::MAX - 1, Ordering::Relaxed);
        arena.syncs.store(u64::MAX - 1, Ordering::Relaxed);
        let first = arena.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
        arena.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
        arena.sync_pages().unwrap();
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        for _ in 0..2 {
            arena.read_page(first, &mut out).unwrap();
        }
        admission.deny_workspace.store(true, Ordering::Release);
        assert_eq!(
            arena.stats().unwrap(),
            DirectoryArenaStats {
                pages_read: u64::MAX,
                pages_written: u64::MAX,
                syncs: u64::MAX
            }
        );
        admission.owner_failed();
        assert!(matches!(arena.stats(), Err(CoreError::OwnerFailed)));
    }

    #[test]
    fn io_stats_exclude_failed_callbacks_even_when_their_effects_are_unknown() {
        for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
            for op in [GroupOp::Write, GroupOp::Sync] {
                let (group, _, _, arena) = setup();
                arena.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
                let before = arena.stats().unwrap();
                group.fail(op, 1, timing);
                let result = match op {
                    GroupOp::Write => arena.append_page(&[2; DIRECTORY_PAGE_BYTES]).map(|_| ()),
                    GroupOp::Sync => arena.sync_pages(),
                    _ => unreachable!(),
                };
                assert!(result.is_err(), "{op:?} {timing:?}");
                assert_eq!(arena.stats().unwrap(), before);
            }
        }
    }

    #[test]
    fn forced_roll_allocates_a_durable_empty_arena_before_the_next_page() {
        let (group, roll, _, arena) = setup();
        for id in 1..=2 {
            arena.force_roll().unwrap();
            assert_eq!(roll.root.lock().unwrap().last_directory_id(), id);
            assert_eq!(roll.root.lock().unwrap().pending_directory(), None);
            assert_eq!(
                group.crash().durable_image(GroupFile::directory(id)),
                Some(encode_header(GROUP, id).to_vec())
            );
            let writer = arena.writer.lock().unwrap();
            let active = writer.active.as_ref().unwrap();
            assert_eq!((active.id, active.pages), (id, 0));
        }
        let reference = arena.append_page(&[9; DIRECTORY_PAGE_BYTES]).unwrap();
        assert_eq!((reference.arena_id, reference.page_index), (2, 0));
    }

    #[test]
    fn forced_roll_preserves_old_pages_after_reopen_and_never_resumes_the_empty_arena() {
        let (group, roll, admission, arena) = setup();
        let reference = arena.append_page(&[7; DIRECTORY_PAGE_BYTES]).unwrap();
        arena.force_roll().unwrap();
        let group = group.crash();
        let roll = Arc::new(Roll {
            group: group.clone(),
            root: Mutex::new(roll.root.lock().unwrap().clone()),
        });
        let reopened =
            DirectoryArenaBackend::new(Arc::new(group.clone()), roll, admission, GROUP).unwrap();
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        reopened.read_page(reference, &mut out).unwrap();
        assert_eq!(out, [7; DIRECTORY_PAGE_BYTES]);
        assert_eq!(
            group.durable_len(GroupFile::directory(2)),
            Some(HEADER_BYTES)
        );
        let reference = reopened.append_page(&[8; DIRECTORY_PAGE_BYTES]).unwrap();
        assert_eq!((reference.arena_id, reference.page_index), (3, 0));
    }

    #[test]
    fn forced_roll_reuses_owned_header_under_new_workspace_denial() {
        for existing in [false, true] {
            let (group, roll, admission, arena) = setup();
            if existing {
                arena.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
            }
            admission.deny_workspace.store(true, Ordering::SeqCst);
            let calls = admission.workspace_calls.load(Ordering::SeqCst);
            arena.force_roll().unwrap();
            let reference = arena.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
            assert_eq!(
                (reference.arena_id, reference.page_index),
                (if existing { 2 } else { 1 }, 0)
            );
            arena.sync_pages().unwrap();
            assert_eq!(admission.workspace_calls.load(Ordering::SeqCst), calls);
            assert_eq!(roll.root.lock().unwrap().pending_directory(), None);
            assert_eq!(
                group.durable_len(GroupFile::directory(reference.arena_id)),
                Some(HEADER_BYTES + DIRECTORY_PAGE_BYTES)
            );
            let mut output = [0; DIRECTORY_PAGE_BYTES];
            arena.read_page(reference, &mut output).unwrap();
            assert_eq!(output, [2; DIRECTORY_PAGE_BYTES]);
        }
    }

    #[test]
    fn forced_roll_failures_fence_all_later_writer_operations() {
        for existing in [false, true] {
            for op in [
                GroupOp::Create,
                GroupOp::Write,
                GroupOp::Sync,
                GroupOp::RootWrite,
                GroupOp::RootSync,
            ] {
                for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
                    let (group, _, _, arena) = setup();
                    if existing {
                        arena.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
                    }
                    group.fail(op, 1, timing);
                    assert!(arena.force_roll().is_err(), "{existing} {op:?} {timing:?}");
                    assert!(arena.writer.lock().unwrap().poisoned);
                    assert!(matches!(arena.force_roll(), Err(CoreError::OwnerFailed)));
                    assert!(matches!(
                        arena.append_page(&[2; DIRECTORY_PAGE_BYTES]),
                        Err(CoreError::OwnerFailed)
                    ));
                    assert!(matches!(arena.sync_pages(), Err(CoreError::OwnerFailed)));
                }
            }
        }
    }

    #[test]
    fn forced_roll_rejects_expired_owner_or_poisoned_lock_before_mutation() {
        let (group, roll, admission, arena) = setup();
        let names = group.entries().unwrap();
        admission.owner_failed();
        assert!(matches!(arena.force_roll(), Err(CoreError::OwnerFailed)));
        assert_eq!(group.entries().unwrap(), names);
        assert_eq!(roll.root.lock().unwrap().generation(), 0);

        let (group, roll, _, arena) = setup();
        let names = group.entries().unwrap();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _writer = arena.writer.lock().unwrap();
                panic!("poison writer lock");
            }))
            .is_err()
        );
        assert!(matches!(arena.force_roll(), Err(CoreError::OwnerFailed)));
        assert_eq!(group.entries().unwrap(), names);
        assert_eq!(roll.root.lock().unwrap().generation(), 0);
    }

    #[test]
    fn first_arena_and_automatic_roll_reuse_owned_header_under_pressure() {
        for existing in [0, 2] {
            let (group, roll, admission, arena) = setup();
            for value in 0..existing {
                arena.append_page(&[value; DIRECTORY_PAGE_BYTES]).unwrap();
            }
            admission.deny_workspace.store(true, Ordering::SeqCst);
            let calls = admission.workspace_calls.load(Ordering::SeqCst);
            let reference = arena.append_page(&[9; DIRECTORY_PAGE_BYTES]).unwrap();
            assert_eq!(reference.arena_id, if existing == 0 { 1 } else { 2 });
            assert_eq!(reference.page_index, 0);
            arena.sync_pages().unwrap();
            assert_eq!(admission.workspace_calls.load(Ordering::SeqCst), calls);
            assert_eq!(roll.root.lock().unwrap().pending_directory(), None);
            assert_eq!(
                group.durable_len(GroupFile::directory(reference.arena_id)),
                Some(HEADER_BYTES + DIRECTORY_PAGE_BYTES)
            );
            let mut output = [0; DIRECTORY_PAGE_BYTES];
            arena.read_page(reference, &mut output).unwrap();
            assert_eq!(output, [9; DIRECTORY_PAGE_BYTES]);
        }
    }

    #[test]
    fn owner_change_before_writer_entry_is_rechecked_without_effect() {
        for forced in [false, true] {
            for existing in [false, true] {
                let (group, roll, admission, arena) = setup();
                if existing {
                    arena.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
                    arena.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
                }
                let before = roll.root.lock().unwrap().clone();
                let names = group.entries().unwrap();
                let durable = group.durable_len(GroupFile::directory(1));
                // The first owner check returns its valid observation, then
                // makes the real owner failed before writer-lock acquisition.
                admission.fail_after_check.store(true, Ordering::SeqCst);
                let result = if forced {
                    arena.force_roll()
                } else {
                    arena.append_page(&[3; DIRECTORY_PAGE_BYTES]).map(|_| ())
                };
                assert!(matches!(result, Err(CoreError::OwnerFailed)));
                assert_eq!(*roll.root.lock().unwrap(), before);
                assert_eq!(group.entries().unwrap(), names);
                assert_eq!(group.durable_len(GroupFile::directory(1)), durable);
            }
        }
    }

    #[test]
    fn header_constructor_refusal_has_no_backend_effect_and_retries() {
        let (group, roll, admission, arena) = setup();
        drop(arena);
        let names = group.entries().unwrap();
        let before = roll.root.lock().unwrap().clone();
        admission.deny_workspace.store(true, Ordering::SeqCst);
        assert!(matches!(
            DirectoryArenaBackend::new(
                Arc::new(group.clone()),
                roll.clone(),
                admission.clone(),
                GROUP
            ),
            Err(CoreError::CapacityDenied)
        ));
        assert_eq!(group.entries().unwrap(), names);
        assert_eq!(*roll.root.lock().unwrap(), before);
        admission.deny_workspace.store(false, Ordering::SeqCst);
        let arena =
            DirectoryArenaBackend::new(Arc::new(group.clone()), roll.clone(), admission, GROUP)
                .unwrap();
        let reference = arena.append_page(&[7; DIRECTORY_PAGE_BYTES]).unwrap();
        assert_eq!((reference.arena_id, reference.page_index), (1, 0));
        arena.sync_pages().unwrap();
        let mut output = [0; DIRECTORY_PAGE_BYTES];
        arena.read_page(reference, &mut output).unwrap();
        assert_eq!(output, [7; DIRECTORY_PAGE_BYTES]);
    }

    #[test]
    fn confirmation_root_failures_poison_before_any_page_is_written() {
        for op in [GroupOp::RootWrite, GroupOp::RootSync] {
            for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
                // Reservation uses the first pair of effects; confirmation
                // uses the next pair after the durable file name/header.
                for occurrence in 3..=4 {
                    let (group, roll, _, arena) = setup();
                    group.fail(op, occurrence, timing);
                    assert!(
                        matches!(
                            arena.append_page(&[1; DIRECTORY_PAGE_BYTES]),
                            Err(CoreError::UnknownCommit(_))
                        ),
                        "{op:?} {timing:?} {occurrence}"
                    );
                    assert_eq!(
                        group.len(GroupFile::directory(1)).unwrap(),
                        HEADER_BYTES as u64
                    );
                    assert_eq!(
                        group.durable_len(GroupFile::directory(1)),
                        Some(HEADER_BYTES)
                    );
                    assert_eq!(roll.root.lock().unwrap().pending_directory(), Some(1));
                    assert!(arena.writer.lock().unwrap().active.is_none());
                    assert!(matches!(
                        arena.append_page(&[2; DIRECTORY_PAGE_BYTES]),
                        Err(CoreError::OwnerFailed)
                    ));
                    assert!(matches!(arena.sync_pages(), Err(CoreError::OwnerFailed)));
                    assert!(!group.exists(GroupFile::directory(2)).unwrap());
                }
            }
        }
    }

    #[test]
    fn failed_old_arena_sync_during_roll_allocates_no_new_identity() {
        for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
            let (group, roll, _, arena) = setup();
            arena.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
            arena.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
            let before = roll.root.lock().unwrap().clone();
            group.fail(GroupOp::Sync, 1, timing);
            assert!(arena.append_page(&[3; DIRECTORY_PAGE_BYTES]).is_err());
            assert_eq!(*roll.root.lock().unwrap(), before);
            assert_eq!(roll.root.lock().unwrap().pending_directory(), None);
            assert!(!group.exists(GroupFile::directory(2)).unwrap());
            assert_eq!(
                group.durable_len(GroupFile::directory(1)),
                Some(
                    HEADER_BYTES
                        + if timing == FaultTiming::AfterEffect {
                            2 * DIRECTORY_PAGE_BYTES
                        } else {
                            0
                        }
                )
            );
            assert!(matches!(
                arena.append_page(&[4; DIRECTORY_PAGE_BYTES]),
                Err(CoreError::OwnerFailed)
            ));
            assert!(matches!(arena.sync_pages(), Err(CoreError::OwnerFailed)));
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Effect {
        Create,
        HeaderWrite,
        PageWrite,
        Sync,
        HeaderRead,
        Length,
        PageRead,
        NameSync,
    }

    /// Successful I/O that changes the retained owner's state before it
    /// returns. Merely checking ownership at operation entry is insufficient.
    struct ExpiringGroup {
        inner: InMemoryGroup,
        admission: Arc<Admission>,
        expire: Mutex<Option<Effect>>,
        effects: Mutex<Vec<Effect>>,
    }

    impl ExpiringGroup {
        fn observed<T>(&self, effect: Effect, result: io::Result<T>) -> io::Result<T> {
            self.effects.lock().unwrap().push(effect);
            if result.is_ok() && self.expire.lock().unwrap().as_ref() == Some(&effect) {
                self.admission.owner_failed();
            }
            result
        }
    }

    impl SegmentGroupBackend for ExpiringGroup {
        fn reserve_transaction(
            &self,
            plan: &crate::TransactionSpacePlan,
        ) -> std::result::Result<(), crate::TransactionReserveError> {
            self.inner.reserve_transaction(plan)
        }
        fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.inner.finish_transaction(group_id, batch_seq)
        }
        fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.inner.cancel_transaction(group_id, batch_seq)
        }

        fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
            self.inner.read_root(slot, out)
        }
        fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
            self.inner.write_root(slot, bytes)
        }
        fn sync_root(&self) -> io::Result<()> {
            self.inner.sync_root()
        }
        fn visit_entries(
            &self,
            visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>,
        ) -> io::Result<()> {
            self.inner.visit_entries(visitor)
        }
        fn exists(&self, file: GroupFile) -> io::Result<bool> {
            self.inner.exists(file)
        }
        fn create(&self, file: GroupFile) -> io::Result<()> {
            self.observed(Effect::Create, self.inner.create(file))
        }
        fn len(&self, file: GroupFile) -> io::Result<u64> {
            self.observed(Effect::Length, self.inner.len(file))
        }
        fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
            self.observed(
                if at == 0 {
                    Effect::HeaderRead
                } else {
                    Effect::PageRead
                },
                self.inner.read(file, at, out),
            )
        }
        fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
            self.observed(
                if at == 0 {
                    Effect::HeaderWrite
                } else {
                    Effect::PageWrite
                },
                self.inner.write(file, at, bytes),
            )
        }
        fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
            self.inner.set_len(file, length)
        }
        fn sync(&self, file: GroupFile) -> io::Result<()> {
            self.observed(Effect::Sync, self.inner.sync(file))
        }
        fn unlink(&self, file: GroupFile) -> io::Result<()> {
            self.inner.unlink(file)
        }
        fn sync_names(&self) -> io::Result<()> {
            self.observed(Effect::NameSync, self.inner.sync_names())
        }
        fn close(&self) -> BackendCloseOutcome {
            self.inner.close()
        }
    }

    #[test]
    fn forced_roll_owner_expiry_after_successful_io_stops_and_fences_the_writer() {
        for existing in [false, true] {
            let effects: &[Effect] = if existing {
                &[Effect::Sync]
            } else {
                &[Effect::Create, Effect::HeaderWrite, Effect::Sync]
            };
            for (index, effect) in effects.iter().copied().enumerate() {
                let (group, roll, admission, mut arena) = setup();
                if existing {
                    arena.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
                }
                let before = roll.root.lock().unwrap().clone();
                let backend = Arc::new(ExpiringGroup {
                    inner: group,
                    admission,
                    expire: Mutex::new(Some(effect)),
                    effects: Mutex::new(Vec::new()),
                });
                arena.backend = backend.clone();
                assert!(matches!(arena.force_roll(), Err(CoreError::OwnerFailed)));
                assert_eq!(*backend.effects.lock().unwrap(), effects[..=index]);
                assert!(arena.writer.lock().unwrap().poisoned);
                if existing {
                    assert_eq!(*roll.root.lock().unwrap(), before);
                } else {
                    assert_eq!(roll.root.lock().unwrap().pending_directory(), Some(1));
                }
                assert!(matches!(arena.force_roll(), Err(CoreError::OwnerFailed)));
                assert!(matches!(
                    arena.append_page(&[2; DIRECTORY_PAGE_BYTES]),
                    Err(CoreError::OwnerFailed)
                ));
                assert_eq!(*backend.effects.lock().unwrap(), effects[..=index]);
            }
        }
    }

    #[test]
    fn owner_failure_inside_successful_roll_or_page_io_stops_later_effects() {
        let write_effects = [
            Effect::Create,
            Effect::HeaderWrite,
            Effect::Sync,
            Effect::PageWrite,
        ];
        for (index, effect) in write_effects.into_iter().enumerate() {
            let (group, roll, admission, mut arena) = setup();
            let backend = Arc::new(ExpiringGroup {
                inner: group,
                admission,
                expire: Mutex::new(Some(effect)),
                effects: Mutex::new(Vec::new()),
            });
            arena.backend = backend.clone();
            assert!(matches!(
                arena.append_page(&[1; DIRECTORY_PAGE_BYTES]),
                Err(CoreError::OwnerFailed)
            ));
            assert_eq!(*backend.effects.lock().unwrap(), write_effects[..=index]);
            assert!(arena.writer.lock().unwrap().poisoned);
            assert_eq!(
                roll.root.lock().unwrap().pending_directory(),
                if effect == Effect::PageWrite {
                    None
                } else {
                    Some(1)
                }
            );
            assert!(matches!(
                arena.append_page(&[2; DIRECTORY_PAGE_BYTES]),
                Err(CoreError::OwnerFailed)
            ));
            assert_eq!(*backend.effects.lock().unwrap(), write_effects[..=index]);
        }

        let read_effects = [Effect::HeaderRead, Effect::Length, Effect::PageRead];
        for (index, effect) in read_effects.into_iter().enumerate() {
            let (group, _, admission, mut arena) = setup();
            let reference = arena.append_page(&[3; DIRECTORY_PAGE_BYTES]).unwrap();
            let backend = Arc::new(ExpiringGroup {
                inner: group,
                admission,
                expire: Mutex::new(Some(effect)),
                effects: Mutex::new(Vec::new()),
            });
            arena.backend = backend.clone();
            let mut bytes = [0; DIRECTORY_PAGE_BYTES];
            assert!(matches!(
                arena.read_page(reference, &mut bytes),
                Err(CoreError::OwnerFailed)
            ));
            assert_eq!(*backend.effects.lock().unwrap(), read_effects[..=index]);
        }
    }

    #[test]
    fn arenas_roll_durably_and_reopen_never_reuses_a_page_identity() {
        let (group, roll, admission, arena) = setup();
        let mut refs = Vec::new();
        for value in 0..5u8 {
            refs.push(arena.append_page(&[value; DIRECTORY_PAGE_BYTES]).unwrap());
        }
        assert_eq!(
            refs.iter()
                .map(|r| (r.arena_id, r.page_index))
                .collect::<Vec<_>>(),
            [(1, 0), (1, 1), (2, 0), (2, 1), (3, 0)]
        );
        arena.sync_pages().unwrap();
        let group = group.crash();
        let roll = Arc::new(Roll {
            group: group.clone(),
            root: Mutex::new(roll.root.lock().unwrap().clone()),
        });
        let reopened = DirectoryArenaBackend::new(Arc::new(group), roll, admission, GROUP).unwrap();
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        for (index, reference) in refs.into_iter().enumerate() {
            reopened.read_page(reference, &mut out).unwrap();
            assert_eq!(out, [index as u8; DIRECTORY_PAGE_BYTES]);
        }
        let reference = reopened.append_page(&[7; DIRECTORY_PAGE_BYTES]).unwrap();
        assert_eq!((reference.arena_id, reference.page_index), (4, 0));
    }

    #[test]
    fn streamed_directory_reads_from_real_group_arenas_after_crash() {
        let (group, roll, admission, arena) = setup();
        let mut builder = DirectoryBuilder::new(&arena, admission.clone(), GROUP, 1).unwrap();
        for index in 0..1500 {
            let table = format!("table-{index:08}");
            builder
                .push(
                    DirectoryKey::table(&table),
                    DirectoryValue::Table { birth_seq: 1 },
                )
                .unwrap();
        }
        let root = builder.finish().unwrap();
        let group = group.crash();
        let roll = Arc::new(Roll {
            group: group.clone(),
            root: Mutex::new(roll.root.lock().unwrap().clone()),
        });
        let reopened =
            DirectoryArenaBackend::new(Arc::new(group), roll, admission.clone(), GROUP).unwrap();
        let reader = DirectoryReader::new(&reopened, admission);
        for index in [0, 73, 701, 1499] {
            let table = format!("table-{index:08}");
            assert_eq!(
                reader.get(root, DirectoryKey::table(&table)).unwrap(),
                Some(DirectoryValue::Table { birth_seq: 1 })
            );
        }
    }

    #[test]
    fn arena_failures_poison_append_and_sync_without_reusing_offsets() {
        for op in [
            GroupOp::Create,
            GroupOp::Write,
            GroupOp::Sync,
            GroupOp::RootWrite,
            GroupOp::RootSync,
        ] {
            for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
                let (group, _, _, arena) = setup();
                group.fail(op, 1, timing);
                assert!(
                    arena.append_page(&[3; DIRECTORY_PAGE_BYTES]).is_err(),
                    "{op:?} {timing:?}"
                );
                assert!(matches!(
                    arena.append_page(&[4; DIRECTORY_PAGE_BYTES]),
                    Err(CoreError::OwnerFailed)
                ));
                assert!(matches!(arena.sync_pages(), Err(CoreError::OwnerFailed)));
            }
        }
        for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
            let (group, _, _, arena) = setup();
            arena.append_page(&[3; DIRECTORY_PAGE_BYTES]).unwrap();
            group.fail(GroupOp::Write, 1, timing);
            assert!(arena.append_page(&[4; DIRECTORY_PAGE_BYTES]).is_err());
            assert!(matches!(arena.sync_pages(), Err(CoreError::OwnerFailed)));
            let (group, _, _, arena) = setup();
            arena.append_page(&[3; DIRECTORY_PAGE_BYTES]).unwrap();
            group.fail(GroupOp::Sync, 1, timing);
            assert!(arena.sync_pages().is_err());
            assert!(matches!(
                arena.append_page(&[4; DIRECTORY_PAGE_BYTES]),
                Err(CoreError::OwnerFailed)
            ));
        }
    }

    #[test]
    fn arena_reads_reject_wrong_identity_digest_and_failed_owner() {
        let (group, _, admission, arena) = setup();
        let reference = arena.append_page(&[3; DIRECTORY_PAGE_BYTES]).unwrap();
        arena.sync_pages().unwrap();
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        let mut wrong = reference;
        wrong.sha256[0] ^= 1;
        assert!(matches!(
            arena.read_page(wrong, &mut out),
            Err(CoreError::Corrupt(_))
        ));
        wrong = reference;
        wrong.page_index = u64::MAX;
        assert!(matches!(
            arena.read_page(wrong, &mut out),
            Err(CoreError::Corrupt(_))
        ));
        group
            .write(
                GroupFile::directory(reference.arena_id),
                0,
                &encode_header([9; 16], reference.arena_id),
            )
            .unwrap();
        assert!(matches!(
            arena.read_page(reference, &mut out),
            Err(CoreError::Corrupt(_))
        ));
        admission.owner_failed();
        assert!(matches!(
            arena.read_page(reference, &mut out),
            Err(CoreError::OwnerFailed)
        ));
    }

    #[test]
    fn pending_arena_recovery_accepts_only_exact_header_prefixes() {
        let file = GroupFile::directory(3);
        let header = encode_header(GROUP, file.id);
        let admission: Arc<dyn StorageAdmission> = Arc::new(Admission::default());
        for len in [0, 1, 16, 24, 40, 48, 100, HEADER_BYTES - 1, HEADER_BYTES] {
            let group = InMemoryGroup::new();
            group.insert_foreign(file, header[..len].to_vec());
            recover_directory_intent(&group, &admission, GROUP, file.id).unwrap();
            assert_eq!(group.crash().durable_image(file), Some(header.to_vec()));
        }
        let group = InMemoryGroup::new();
        recover_directory_intent(&group, &admission, GROUP, file.id).unwrap();
        assert_eq!(group.crash().durable_image(file), Some(header.to_vec()));

        let mut payload = header.to_vec();
        payload.push(0);
        let mut sparse = header;
        sparse[0] = 0;
        for image in [
            b"foreign bytes".to_vec(),
            vec![0; HEADER_BYTES],
            sparse.to_vec(),
            encode_header([99; 16], file.id)[..40].to_vec(),
            encode_header(GROUP, file.id + 1).to_vec(),
            payload,
        ] {
            let group = InMemoryGroup::new();
            group.insert_foreign(file, image.clone());
            assert!(matches!(
                recover_directory_intent(&group, &admission, GROUP, file.id),
                Err(CoreError::Corrupt(_))
            ));
            assert_eq!(group.durable_image(file), Some(image));
        }
    }

    #[test]
    fn pending_arena_recovery_faults_never_confirm_or_consume_page_offsets() {
        let file = GroupFile::directory(1);
        let header = encode_header(GROUP, file.id);
        let admission: Arc<dyn StorageAdmission> = Arc::new(Admission::default());
        for op in [
            GroupOp::Create,
            GroupOp::Write,
            GroupOp::Sync,
            GroupOp::SyncNames,
        ] {
            for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
                let group = InMemoryGroup::new();
                if op == GroupOp::SyncNames {
                    group.insert_foreign(file, header[..40].to_vec());
                }
                group.fail(op, 1, timing);
                assert!(
                    recover_directory_intent(&group, &admission, GROUP, file.id).is_err(),
                    "{op:?} {timing:?}"
                );
                let reopened = group.crash();
                recover_directory_intent(&reopened, &admission, GROUP, file.id).unwrap();
                assert_eq!(reopened.crash().durable_image(file), Some(header.to_vec()));
                let mut root = [1; ROOT_SLOT_BYTES];
                reopened.read_root(RootSlot::A, &mut root).unwrap();
                assert_eq!(root, [0; ROOT_SLOT_BYTES]);
                reopened.read_root(RootSlot::B, &mut root).unwrap();
                assert_eq!(root, [0; ROOT_SLOT_BYTES]);
            }
        }
    }

    #[test]
    fn pending_arena_recovery_admission_and_owner_checks_precede_mutation() {
        let group = InMemoryGroup::new();
        let concrete = Arc::new(Admission::default());
        let admission: Arc<dyn StorageAdmission> = concrete.clone();
        concrete.deny_workspace.store(true, Ordering::SeqCst);
        assert!(matches!(
            recover_directory_intent(&group, &admission, GROUP, 1),
            Err(CoreError::CapacityDenied)
        ));
        assert!(!group.exists(GroupFile::directory(1)).unwrap());
        concrete.deny_workspace.store(false, Ordering::SeqCst);
        for effect in [
            Effect::Create,
            Effect::Length,
            Effect::HeaderRead,
            Effect::NameSync,
            Effect::HeaderWrite,
            Effect::Sync,
        ] {
            concrete.failed.store(false, Ordering::SeqCst);
            let backend = ExpiringGroup {
                inner: InMemoryGroup::new(),
                admission: concrete.clone(),
                expire: Mutex::new(Some(effect)),
                effects: Mutex::new(Vec::new()),
            };
            if matches!(
                effect,
                Effect::Length | Effect::HeaderRead | Effect::NameSync
            ) {
                backend.inner.insert_foreign(
                    GroupFile::directory(1),
                    encode_header(GROUP, 1)[..40].to_vec(),
                );
            }
            assert!(matches!(
                recover_directory_intent(&backend, &admission, GROUP, 1),
                Err(CoreError::OwnerFailed)
            ));
            assert_eq!(backend.effects.lock().unwrap().last(), Some(&effect));
        }
    }

    #[test]
    fn transaction_space_arena_bound_matches_actual_rolls_and_keeps_planning_effect_free() {
        for initial in [0, 1, 2, 3] {
            let (group, roll, admission, arena) = setup();
            for byte in 0..initial {
                arena.append_page(&[byte; DIRECTORY_PAGE_BYTES]).unwrap();
            }
            arena.sync_pages().unwrap();
            for additional in [0, 1, 2, 3, 7] {
                let first = roll.root.lock().unwrap().last_directory_id() + 1;
                let stats = arena.stats().unwrap();
                let calls = admission.workspace_calls.load(Ordering::SeqCst);
                let generation = roll.root.lock().unwrap().generation();
                let (existing, range) = arena.transaction_space(first, additional).unwrap();
                assert_eq!(arena.stats().unwrap(), stats);
                assert_eq!(admission.workspace_calls.load(Ordering::SeqCst), calls);
                assert_eq!(roll.root.lock().unwrap().generation(), generation);
                if let Some(tail) = &existing {
                    assert_eq!(group.len(tail.file).unwrap(), tail.initial_len);
                }
                for _ in 0..additional {
                    arena.append_page(&[9; DIRECTORY_PAGE_BYTES]).unwrap();
                }
                arena.sync_pages().unwrap();
                if let Some(tail) = existing {
                    assert_eq!(group.len(tail.file).unwrap(), tail.maximum_len);
                }
                let last = roll.root.lock().unwrap().last_directory_id();
                assert_eq!(last + 1 - first, range.count);
                if range.count == 0 {
                    assert_eq!(
                        (
                            range.first_id,
                            range.full_len,
                            range.last_len,
                            range.total_len
                        ),
                        (0, 0, 0, 0)
                    );
                } else {
                    let mut total = 0;
                    for id in range.first_id..range.first_id + range.count {
                        let length = group.len(GroupFile::directory(id)).unwrap();
                        assert_eq!(
                            length,
                            if id == last {
                                range.last_len
                            } else {
                                range.full_len
                            }
                        );
                        total += length;
                    }
                    assert_eq!(total, range.total_len);
                }
            }
        }
    }

    #[test]
    fn transaction_space_arena_rejects_overflow_and_poison_without_consuming_ids() {
        let (_, roll, admission, arena) = setup();
        let root = roll.root.lock().unwrap().clone();
        for (first, pages) in [(0, 1), (u64::MAX - 1, 1), (1, u64::MAX)] {
            assert!(arena.transaction_space(first, pages).is_err());
            assert_eq!(*roll.root.lock().unwrap(), root);
        }
        arena.writer.lock().unwrap().poisoned = true;
        assert!(matches!(
            arena.transaction_space(1, 1),
            Err(CoreError::OwnerFailed)
        ));
        assert_eq!(*roll.root.lock().unwrap(), root);
        admission.failed.store(true, Ordering::SeqCst);
        assert!(matches!(
            arena.transaction_space(1, 0),
            Err(CoreError::OwnerFailed)
        ));
    }
}

// Transaction-space planning is qualified separately before production activation.
#[path = "arena_space.rs"]
mod space;
