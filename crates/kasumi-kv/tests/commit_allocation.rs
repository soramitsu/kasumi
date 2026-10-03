//! Staging and commit materialization stay within admitted workspace.
//!
//! A counting global allocator tracks the live heap of the measuring thread
//! while the test admission tracks live workspace charges. Their difference
//! is sampled at every allocation and every lease release.
//!
//! Staging is measured from a baseline taken before the writer begins.
//! Commit is measured from its own start, so conservative staging charges
//! cannot mask an unadmitted commit allocation, until the first large staging
//! lease that predates the commit is released: from then on the staged batch
//! returns its over-estimated credit. Small prior snapshot retirement remains
//! measured and is bounded by the fixed slack. Coverage checks require native
//! work before freezing and forbid backend/reservation work afterward; remaining
//! positive allocations also consume the fixed slack. Both phases may exceed
//! their baseline by at most
//! `FIXED_SLACK`: the writer's own handles (its staged-batch cell, snapshot
//! and table name) and the first growth of each lease vector.

use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, CacheConfig, CommitError, CoreError, Database, FileKind,
    GroupFile, MAX_VALUE_BYTES, Operation, OwnerFailed, ROOT_FILE_NAME, ROOT_SLOT_BYTES,
    ResidentLease, RootSlot, SegmentGroupBackend, StorageAdmission, StorageError, TableDefinition,
    WriteTerminalSettlement,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rows");
const PUTS: u32 = 65_536;
const SMALL: [u8; 16] = [0x42; 16];
const FIXED_SLACK: i64 = 4 << 10;

struct Counting;

#[global_allocator]
static ALLOCATOR: Counting = Counting;

thread_local! {
    static TRACKED: Cell<bool> = const { Cell::new(false) };
}
static HEAP: AtomicI64 = AtomicI64::new(0);
static ADMITTED: AtomicI64 = AtomicI64::new(0);
static PEAK: AtomicI64 = AtomicI64::new(0);
// Leases are numbered as they are reserved. Only a large lease predating the
// phase freezes its peak: small snapshot retirement precedes native commit.
static LEASES: AtomicU64 = AtomicU64::new(0);
static PHASE_START: AtomicU64 = AtomicU64::new(0);
static FROZEN: AtomicBool = AtomicBool::new(false);
static COMMIT_PHASE: AtomicBool = AtomicBool::new(false);
static SMALL_PRIOR_RELEASES: AtomicI64 = AtomicI64::new(0);
static PHASE_RESERVATIONS: AtomicUsize = AtomicUsize::new(0);
static PHASE_BACKEND_CALLS: AtomicUsize = AtomicUsize::new(0);
static PHASE_ROOT_SYNCS: AtomicUsize = AtomicUsize::new(0);
static ACTIVITY_AFTER_FREEZE: AtomicBool = AtomicBool::new(false);
static ALLOCATED_AFTER_FREEZE: AtomicI64 = AtomicI64::new(0);
// The allocator and admission counters are process-wide; one test measures
// at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn tracked() -> bool {
    TRACKED.try_with(Cell::get).unwrap_or(false)
}

fn excess() -> i64 {
    HEAP.load(Ordering::Acquire) - ADMITTED.load(Ordering::Acquire)
}

fn sample() {
    if tracked() && !FROZEN.load(Ordering::Acquire) {
        PEAK.fetch_max(excess(), Ordering::AcqRel);
    }
}

fn note(delta: i64) {
    if tracked() {
        if delta > 0 && FROZEN.load(Ordering::Acquire) {
            ALLOCATED_AFTER_FREEZE.fetch_add(delta, Ordering::AcqRel);
        }
        HEAP.fetch_add(delta, Ordering::AcqRel);
        sample();
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            note(layout.size() as i64);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            note(layout.size() as i64);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        note(-(layout.size() as i64));
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            note(new_size as i64 - layout.size() as i64);
        }
        moved
    }
}

/// Peak unadmitted heap of one phase over the difference at its start.
struct Window {
    base: i64,
}

impl Window {
    fn open() -> Self {
        let base = Self::start();
        TRACKED.with(|tracked| tracked.set(true));
        Self { base }
    }

    fn start() -> i64 {
        let base = excess();
        FROZEN.store(false, Ordering::Release);
        COMMIT_PHASE.store(false, Ordering::Release);
        SMALL_PRIOR_RELEASES.store(0, Ordering::Release);
        PHASE_RESERVATIONS.store(0, Ordering::Release);
        PHASE_BACKEND_CALLS.store(0, Ordering::Release);
        PHASE_ROOT_SYNCS.store(0, Ordering::Release);
        ACTIVITY_AFTER_FREEZE.store(false, Ordering::Release);
        ALLOCATED_AFTER_FREEZE.store(0, Ordering::Release);
        PHASE_START.store(LEASES.load(Ordering::Acquire), Ordering::Release);
        PEAK.store(base, Ordering::Release);
        base
    }

    /// End the current phase with its peak and start the next one. Staging
    /// releases no lease older than itself, so its peak covers all of it.
    fn mark(&mut self) -> i64 {
        assert!(
            !FROZEN.load(Ordering::Acquire),
            "a phase released a lease that predates it"
        );
        let peak = PEAK.load(Ordering::Acquire) - self.base;
        self.base = Self::start();
        COMMIT_PHASE.store(true, Ordering::Release);
        peak
    }

    fn close(self) -> i64 {
        TRACKED.with(|tracked| tracked.set(false));
        PHASE_START.store(0, Ordering::Release);
        if COMMIT_PHASE.swap(false, Ordering::AcqRel) {
            assert!(
                FROZEN.load(Ordering::Acquire),
                "staging credit was not retired"
            );
            let small = SMALL_PRIOR_RELEASES.load(Ordering::Acquire);
            assert!(small > 0, "the writer snapshot retirement was not measured");
            assert!(
                small <= FIXED_SLACK,
                "small prior releases exceeded slack: {small}"
            );
            assert!(
                PHASE_RESERVATIONS.load(Ordering::Acquire) > 1,
                "the window did not cover native commit reservations"
            );
            assert!(
                PHASE_BACKEND_CALLS.load(Ordering::Acquire) > 0
                    && PHASE_ROOT_SYNCS.load(Ordering::Acquire) > 0,
                "the window did not cover native root publication"
            );
            assert!(
                !ACTIVITY_AFTER_FREEZE.load(Ordering::Acquire),
                "backend or workspace activity continued after freezing"
            );
        }
        // Conservative staging-credit retirement is excluded, but subsequent
        // allocations are not free: their total consumes the remaining slack.
        PEAK.load(Ordering::Acquire) - self.base + ALLOCATED_AFTER_FREEZE.load(Ordering::Acquire)
    }
}

/// Charges its own lease box with each reservation, as the installed
/// NodeFile admission does.
#[derive(Default)]
struct CountingAdmission {
    deny_at_least: AtomicU64,
    denials: AtomicUsize,
    denied_bytes: AtomicU64,
}

struct Lease {
    charge: i64,
    number: u64,
}

impl Lease {
    fn release(&self, charge: i64) {
        if tracked() && self.number < PHASE_START.load(Ordering::Acquire) {
            if charge > FIXED_SLACK {
                FROZEN.store(true, Ordering::Release);
            } else {
                SMALL_PRIOR_RELEASES.fetch_add(charge, Ordering::AcqRel);
            }
        }
        ADMITTED.fetch_sub(charge, Ordering::AcqRel);
        sample();
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.release(self.charge);
    }
}

struct CacheReservation {
    owner: Arc<CountingAdmission>,
    lease: Lease,
}
impl kasumi_kv::CacheMemoryReservation for CacheReservation {
    fn try_grow(&mut self, bytes: u64) -> Result<(), AdmissionError> {
        let charge = i64::try_from(bytes).map_err(|_| AdmissionError::CapacityDenied)?;
        let next = self
            .lease
            .charge
            .checked_add(charge)
            .ok_or(AdmissionError::CapacityDenied)?;
        self.owner.admit_cache(bytes)?;
        self.lease.charge = next;
        Ok(())
    }
    fn retain_charge(&mut self, bytes: u64) {
        let next = i64::try_from(bytes).unwrap();
        let release = self.lease.charge.checked_sub(next).unwrap();
        self.lease.charge = next;
        self.lease.release(release);
    }
}

impl CountingAdmission {
    fn admit_cache(&self, bytes: u64) -> Result<(), AdmissionError> {
        if tracked() && COMMIT_PHASE.load(Ordering::Acquire) {
            if FROZEN.load(Ordering::Acquire) {
                ACTIVITY_AFTER_FREEZE.store(true, Ordering::Release);
            } else {
                PHASE_RESERVATIONS.fetch_add(1, Ordering::AcqRel);
            }
        }
        if bytes >= self.deny_at_least.load(Ordering::Acquire) {
            self.denials.fetch_add(1, Ordering::AcqRel);
            self.denied_bytes.store(bytes, Ordering::Release);
            return Err(AdmissionError::CapacityDenied);
        }
        let charge = i64::try_from(bytes).map_err(|_| AdmissionError::CapacityDenied)?;
        ADMITTED.fetch_add(charge, Ordering::AcqRel);
        Ok(())
    }

    fn new() -> Arc<Self> {
        Arc::new(Self {
            deny_at_least: AtomicU64::new(u64::MAX),
            ..Self::default()
        })
    }
}

impl StorageAdmission for CountingAdmission {
    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, AdmissionError> {
        kasumi_kv::CacheMemoryQuote::new(bytes, size_of::<CacheReservation>() as u64 + 64)
            .ok_or(AdmissionError::CapacityDenied)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryLease, AdmissionError> {
        let quote = self.quote_cache_memory(bytes)?;
        self.admit_cache(quote.charged_bytes())?;
        let number = LEASES.fetch_add(1, Ordering::AcqRel);
        let lease = Lease {
            charge: quote.charged_bytes() as i64,
            number,
        };
        Ok(kasumi_kv::CacheMemoryLease::new(
            quote,
            CacheReservation { owner: self, lease },
        ))
    }

    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        if tracked() && COMMIT_PHASE.load(Ordering::Acquire) {
            if FROZEN.load(Ordering::Acquire) {
                ACTIVITY_AFTER_FREEZE.store(true, Ordering::Release);
            } else {
                PHASE_RESERVATIONS.fetch_add(1, Ordering::AcqRel);
            }
        }
        if bytes >= self.deny_at_least.load(Ordering::Acquire) {
            self.denials.fetch_add(1, Ordering::AcqRel);
            self.denied_bytes.store(bytes, Ordering::Release);
            return Err(AdmissionError::CapacityDenied);
        }
        let charge = i64::try_from(bytes)
            .ok()
            .and_then(|bytes| bytes.checked_add(size_of::<Lease>() as i64))
            .ok_or(AdmissionError::CapacityDenied)?;
        ADMITTED.fetch_add(charge, Ordering::AcqRel);
        let number = LEASES.fetch_add(1, Ordering::AcqRel);
        Ok(Box::new(Lease { charge, number }))
    }

    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        Ok(())
    }

    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn owner_failed(&self) {}
}

/// Real files keep the test's backing data outside the measured heap. Only
/// fixture path/descriptor bookkeeping is excluded; native admission, cache,
/// directory and transaction allocations remain inside the measured window.
struct Image(
    PathBuf,
    Mutex<Option<(kasumi_kv::TransactionSpacePlan, bool)>>,
    Arc<CountingAdmission>,
);
impl Drop for Image {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[derive(Clone)]
struct FileGroup(Arc<Image>);

fn backing<T>(work: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            TRACKED.with(|t| t.set(self.0));
        }
    }
    let restore = Restore(TRACKED.with(|t| t.replace(false)));
    let result = work();
    drop(restore);
    result
}

/// Fixture values allocated with tracking disabled must also be destroyed
/// there, including callback errors and unwinding out of namespace traversal.
struct Excluded<T>(Option<T>);
impl<T> Excluded<T> {
    fn get(&self) -> &T {
        self.0.as_ref().unwrap()
    }
    fn get_mut(&mut self) -> &mut T {
        self.0.as_mut().unwrap()
    }
}
impl<T> Drop for Excluded<T> {
    fn drop(&mut self) {
        let value = self.0.take();
        backing(|| drop(value));
    }
}

fn backend_call() {
    if tracked() && COMMIT_PHASE.load(Ordering::Acquire) {
        if FROZEN.load(Ordering::Acquire) {
            ACTIVITY_AFTER_FREEZE.store(true, Ordering::Release);
        } else {
            PHASE_BACKEND_CALLS.fetch_add(1, Ordering::AcqRel);
        }
    }
}

impl FileGroup {
    fn transaction_effect(&self) {
        if let Some((_, entered)) = self.0.1.lock().unwrap().as_mut() {
            *entered = true;
        }
    }

    fn new(admission: Arc<CountingAdmission>) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "kasumi-allocation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        File::create(path.join(ROOT_FILE_NAME))
            .unwrap()
            .set_len((ROOT_SLOT_BYTES * 2) as u64)
            .unwrap();
        Self(Arc::new(Image(path, Mutex::new(None), admission)))
    }
    fn open(&self, file: Option<GroupFile>) -> io::Result<File> {
        OpenOptions::new().read(true).write(true).open(
            self.0
                .0
                .join(file.map_or_else(|| ROOT_FILE_NAME.to_owned(), GroupFile::file_name)),
        )
    }
    fn bytes(&self) -> Vec<(String, Vec<u8>)> {
        let mut result: Vec<_> = fs::read_dir(&self.0.0)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().into_string().unwrap(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }
    fn crash(&self, _capacity: usize, admission: Arc<CountingAdmission>) -> Self {
        let image = Self::new(admission);
        for entry in fs::read_dir(&self.0.0).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), image.0.0.join(entry.file_name())).unwrap();
        }
        image
    }
}
impl SegmentGroupBackend for FileGroup {
    // This fixture uses ordinary temporary files and has no installed disk
    // quota. Its explicit attempt tracks real effects and exact settlement;
    // it must not attest production admission or mint CapacityDenied.
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> Result<(), kasumi_kv::TransactionReserveError> {
        let result = (|| -> io::Result<()> {
            plan.validate()?;
            let mut attempt = self.0.1.lock().unwrap();
            if attempt.is_some() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let mut a = [0; ROOT_SLOT_BYTES];
            let mut b = [0; ROOT_SLOT_BYTES];
            self.read_root(RootSlot::A, &mut a)?;
            self.read_root(RootSlot::B, &mut b)?;
            // Keep canonical decoder allocations inside the measured window,
            // funded by the same provider as this fixture's native database.
            let _roots_workspace = self
                .0
                .2
                .reserve_workspace(kasumi_kv::TRANSACTION_SPACE_ROOTS_HEAP_BYTES)
                .map_err(io::Error::other)?;
            kasumi_kv::validate_transaction_space_roots(plan, &a, &b).map_err(io::Error::other)?;
            *attempt = Some((*plan, false));
            Ok(())
        })();
        result.map_err(kasumi_kv::TransactionReserveError::Failed)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        let plan = {
            let attempt = self.0.1.lock().unwrap();
            let (plan, _) = attempt.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
            if plan.group_id != group_id || plan.batch_seq != batch_seq {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            *plan
        };
        for existing in plan.segment.into_iter().chain(plan.directory) {
            let length = self.len(existing.file)?;
            if length < existing.initial_len || length > existing.maximum_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.sync(existing.file)?;
        }
        for (kind, range) in [
            (FileKind::Segment, plan.new_segments),
            (FileKind::Directory, plan.new_directories),
        ] {
            let mut absent = false;
            let mut total = 0u64;
            for offset in 0..range.count {
                let file = GroupFile {
                    kind,
                    id: range.first_id + offset,
                };
                if !self.exists(file)? {
                    absent = true;
                    continue;
                }
                if absent {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let length = self.len(file)?;
                if length < range.minimum_len || length > range.maximum_len(file.id).unwrap() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                total = total
                    .checked_add(length)
                    .ok_or(io::ErrorKind::InvalidData)?;
                if total > range.total_len {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                self.sync(file)?;
            }
        }
        self.sync_root()?;
        self.sync_names()?;
        let mut attempt = self.0.1.lock().unwrap();
        if !attempt.as_ref().is_some_and(|(held, _)| *held == plan) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        *attempt = None;
        Ok(())
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        let mut attempt = self.0.1.lock().unwrap();
        if !attempt.as_ref().is_some_and(|(plan, entered)| {
            !entered && plan.group_id == group_id && plan.batch_seq == batch_seq
        }) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        *attempt = None;
        Ok(())
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        backend_call();
        backing(|| {
            self.open(None)?.read_exact_at(
                out,
                match slot {
                    RootSlot::A => 0,
                    RootSlot::B => ROOT_SLOT_BYTES as u64,
                },
            )
        })
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.transaction_effect();
        backend_call();
        backing(|| {
            self.open(None)?.write_all_at(
                bytes,
                match slot {
                    RootSlot::A => 0,
                    RootSlot::B => ROOT_SLOT_BYTES as u64,
                },
            )
        })
    }
    fn sync_root(&self) -> io::Result<()> {
        backend_call();
        let result = backing(|| self.open(None)?.sync_data());
        if result.is_ok()
            && tracked()
            && COMMIT_PHASE.load(Ordering::Acquire)
            && !FROZEN.load(Ordering::Acquire)
        {
            PHASE_ROOT_SYNCS.fetch_add(1, Ordering::AcqRel);
        }
        result
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        backend_call();
        // Restore tracking before native code in the callback runs.
        let mut entries = Excluded(Some(backing(|| fs::read_dir(&self.0.0))?));
        loop {
            let Some(entry) = backing(|| entries.get_mut().next()) else {
                return Ok(());
            };
            let name = Excluded(Some(backing(|| entry.map(|e| e.file_name()))?));
            visitor(name.get())?;
        }
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        backend_call();
        backing(|| self.0.0.join(file.file_name()).try_exists())
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.transaction_effect();
        backend_call();
        backing(|| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.0.0.join(file.file_name()))?;
            File::open(&self.0.0)?.sync_all()
        })
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        backend_call();
        backing(|| Ok(self.open(Some(file))?.metadata()?.len()))
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        backend_call();
        backing(|| self.open(Some(file))?.read_exact_at(out, at))
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.transaction_effect();
        backend_call();
        backing(|| self.open(Some(file))?.write_all_at(bytes, at))
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.transaction_effect();
        backend_call();
        backing(|| self.open(Some(file))?.set_len(length))
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        backend_call();
        backing(|| self.open(Some(file))?.sync_data())
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.transaction_effect();
        backend_call();
        backing(|| {
            match fs::remove_file(self.0.0.join(file.file_name())) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            File::open(&self.0.0)?.sync_all()
        })
    }
    fn sync_names(&self) -> io::Result<()> {
        backend_call();
        backing(|| File::open(&self.0.0)?.sync_all())
    }
    fn close(&self) -> BackendCloseOutcome {
        backend_call();
        BackendCloseOutcome::drained(Ok(()))
    }
}
const GROUP: [u8; 16] = [0x52; 16];

fn database(_capacity: usize) -> (Database, Arc<CountingAdmission>, FileGroup) {
    let admission = CountingAdmission::new();
    let backend = FileGroup::new(admission.clone());
    let database = Database::builder(admission.clone(), GROUP, CacheConfig::default())
        .create_with_backend(backend.clone())
        .unwrap();
    let write = database.begin_write().unwrap();
    write
        .open_table(ROWS)
        .unwrap()
        .insert(b"seed", b"prior")
        .unwrap();
    write.commit().unwrap();
    (database, admission, backend)
}

fn stage_puts(database: &Database) -> kasumi_kv::WriteTransaction {
    let write = database.begin_write().unwrap();
    {
        let mut table = write.open_table(ROWS).unwrap();
        for index in 0..PUTS {
            table.insert(&index.to_be_bytes(), &SMALL).unwrap();
        }
    }
    write
}

fn assert_within_slack(stage: &str, peak: i64) {
    assert!(
        peak <= FIXED_SLACK,
        "{stage} exceeded admitted workspace by {peak} bytes (slack {FIXED_SLACK})"
    );
}

fn assert_census_exclusions_are_balanced(backend: &FileGroup) {
    let window = Window::open();
    let baseline = HEAP.load(Ordering::Acquire);
    backend
        .visit_entries(&mut |_| {
            assert!(tracked(), "native census callbacks must remain measured");
            let before = HEAP.load(Ordering::Acquire);
            let probe = std::hint::black_box(vec![0u8; 8192]);
            assert!(HEAP.load(Ordering::Acquire) >= before + 8192);
            drop(probe);
            Ok(())
        })
        .unwrap();
    assert_eq!(HEAP.load(Ordering::Acquire), baseline, "census completion");
    let error = backend
        .visit_entries(&mut |_| Err(io::ErrorKind::Interrupted.into()))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    drop(error);
    assert_eq!(
        HEAP.load(Ordering::Acquire),
        baseline,
        "census cancellation"
    );
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        backend.visit_entries(&mut |_| std::panic::resume_unwind(Box::new(())))
    }));
    assert!(panic.is_err());
    drop(panic);
    assert_eq!(HEAP.load(Ordering::Acquire), baseline, "census unwind");
    assert!(window.close() >= 8192, "callback allocation was excluded");
}

#[test]
fn many_small_puts_stage_and_commit_within_admitted_workspace() {
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    let (database, _admission, backend) = database(64 << 20);
    assert_census_exclusions_are_balanced(&backend);
    let mut window = Window::open();
    let write = stage_puts(&database);
    let staging = window.mark();
    write.commit().unwrap();
    let commit = window.close();
    assert_within_slack("staging 65,536 puts", staging);
    assert_within_slack("committing 65,536 puts", commit);

    let read = database.begin_read().unwrap();
    let rows = read.open_table(ROWS).unwrap();
    for index in [0, 1, PUTS / 2, PUTS - 1] {
        assert_eq!(
            rows.get(&index.to_be_bytes()).unwrap().unwrap().value(),
            SMALL
        );
    }
    assert_eq!(rows.get(b"seed").unwrap().unwrap().value(), b"prior");
}

#[test]
fn largest_value_stages_and_commits_within_admitted_workspace() {
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    let (database, _admission, _backend) = database(MAX_VALUE_BYTES + (1 << 20));
    let value = vec![0x6b; MAX_VALUE_BYTES];
    let mut window = Window::open();
    let write = database.begin_write().unwrap();
    write
        .open_table(ROWS)
        .unwrap()
        .insert(b"large", value.as_slice())
        .unwrap();
    let staging = window.mark();
    write.commit().unwrap();
    let commit = window.close();
    assert_within_slack("staging a 40 MiB value", staging);
    assert_within_slack("committing a 40 MiB value", commit);

    let read = database.begin_read().unwrap();
    let stored = read
        .open_table(ROWS)
        .unwrap()
        .get(b"large")
        .unwrap()
        .unwrap();
    assert!(stored.value() == value.as_slice());
}

#[test]
fn denied_operation_vector_changes_nothing_and_releases_the_writer() {
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    let capacity = 64 << 20;
    let (database, admission, backend) = database(capacity);
    let before = backend.bytes();
    let database = database.retain();

    let mut writer = stage_puts(database.database().unwrap()).retain();
    // Staging reserves 64 KiB chunks; only the operation vector of this
    // commit needs more than a MiB.
    admission.deny_at_least.store(1 << 20, Ordering::Release);
    {
        let report = writer.commit();
        assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
        assert!(report.is_capacity_denied());
        assert!(matches!(
            report.rejected_no_effect(),
            Some(StorageError::Core(CoreError::CapacityDenied))
        ));
    }
    admission.deny_at_least.store(u64::MAX, Ordering::Release);
    assert_eq!(admission.denials.load(Ordering::Acquire), 1);
    assert!(
        admission.denied_bytes.load(Ordering::Acquire)
            >= u64::from(PUTS) * size_of::<Operation>() as u64
    );
    assert_eq!(backend.bytes(), before);

    // The settled writer released its gate before disposal.
    let admission_handle = database.database().unwrap().transaction_admission();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(admission_handle.begin_write().map(|writer| writer.abort()));
    });
    receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("settled writer kept its gate")
        .unwrap()
        .unwrap();
    assert!(writer.dispose_settled(&database).disposal_complete());

    // The index is unchanged, and the same batch now commits.
    let read = database.database().unwrap().begin_read().unwrap();
    let rows = read.open_table(ROWS).unwrap();
    assert_eq!(rows.iter().unwrap().count(), 1);
    assert!(rows.get(&0u32.to_be_bytes()).unwrap().is_none());
    drop(rows);
    drop(read);
    let reopened_admission = CountingAdmission::new();
    let crash = backend.crash(capacity, reopened_admission.clone());
    stage_puts(database.database().unwrap()).commit().unwrap();

    // A restart from the image left by the denial shows the prior state.
    let reopened = Database::builder(reopened_admission, GROUP, CacheConfig::default())
        .open_with_backend(crash)
        .unwrap();
    let read = reopened.begin_read().unwrap();
    let rows = read.open_table(ROWS).unwrap();
    assert_eq!(rows.get(b"seed").unwrap().unwrap().value(), b"prior");
    assert_eq!(rows.iter().unwrap().count(), 1);
}

#[test]
fn materialization_charge_is_decided_before_any_effect() {
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    let (database, admission, backend) = database(64 << 20);
    let before = backend.bytes();
    let write = stage_puts(&database);
    admission.deny_at_least.store(1 << 20, Ordering::Release);
    assert!(matches!(
        write.commit(),
        Err(CommitError(StorageError::Core(CoreError::CapacityDenied)))
    ));
    admission.deny_at_least.store(u64::MAX, Ordering::Release);
    assert_eq!(backend.bytes(), before);
    // The consumed writer is gone; the next one begins on this thread.
    stage_puts(&database).commit().unwrap();
}
