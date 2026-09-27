//! Staging and commit materialization stay within admitted workspace.
//!
//! A counting global allocator tracks the live heap of the measuring thread
//! while the test admission tracks live workspace charges. Their difference
//! is sampled at every allocation and every lease release.
//!
//! Staging is measured from a baseline taken before the writer begins.
//! Commit is measured from its own start, so conservative staging charges
//! cannot mask an unadmitted commit allocation, until the first lease that
//! predates the commit is released: from then on the staged batch returns
//! its over-estimated credit. Both may exceed their baseline by at most
//! `FIXED_SLACK`: the writer's own handles (its staged-batch cell, snapshot
//! and table name) and the first growth of each lease vector.

use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, CommitError, CoreError, Database, MAX_VALUE_BYTES,
    Operation, OwnerFailed, ResidentLease, StorageAdmission, StorageBackend, StorageError,
    TableDefinition, WriteTerminalSettlement,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io;
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
// Leases are numbered as they are reserved. Releasing one numbered below the
// phase start freezes the phase's peak.
static LEASES: AtomicU64 = AtomicU64::new(0);
static PHASE_START: AtomicU64 = AtomicU64::new(0);
static FROZEN: AtomicBool = AtomicBool::new(false);
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
        peak
    }

    fn close(self) -> i64 {
        TRACKED.with(|tracked| tracked.set(false));
        PHASE_START.store(0, Ordering::Release);
        PEAK.load(Ordering::Acquire) - self.base
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

impl Drop for Lease {
    fn drop(&mut self) {
        if tracked() && self.number < PHASE_START.load(Ordering::Acquire) {
            FROZEN.store(true, Ordering::Release);
        }
        ADMITTED.fetch_sub(self.charge, Ordering::AcqRel);
        sample();
    }
}

impl CountingAdmission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            deny_at_least: AtomicU64::new(u64::MAX),
            ..Self::default()
        })
    }
}

impl StorageAdmission for CountingAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
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

/// A volatile image whose capacity is reserved up front, so backend growth
/// never allocates inside a measured window.
#[derive(Clone)]
struct Preallocated(Arc<Mutex<Vec<u8>>>);

impl Preallocated {
    fn with_capacity(bytes: usize) -> Self {
        Self(Arc::new(Mutex::new(Vec::with_capacity(bytes))))
    }

    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }

    /// A restart from the current image, which every sync has made durable.
    fn crash(&self, capacity: usize) -> Self {
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(&self.0.lock().unwrap());
        Self(Arc::new(Mutex::new(bytes)))
    }
}

impl StorageBackend for Preallocated {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().len() as u64)
    }

    fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let bytes = self.0.lock().unwrap();
        let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::InvalidInput)?;
        out.copy_from_slice(bytes.get(start..end).ok_or(io::ErrorKind::UnexpectedEof)?);
        Ok(())
    }

    fn write(&self, at: u64, input: &[u8]) -> io::Result<()> {
        let mut bytes = self.0.lock().unwrap();
        let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
        let end = start
            .checked_add(input.len())
            .ok_or(io::ErrorKind::InvalidInput)?;
        bytes
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(input);
        Ok(())
    }

    fn set_len(&self, length: u64) -> io::Result<()> {
        let mut bytes = self.0.lock().unwrap();
        let length = usize::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?;
        if length > bytes.capacity() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        bytes.resize(length, 0);
        Ok(())
    }

    fn sync_data(&self) -> io::Result<()> {
        Ok(())
    }

    fn close(&self) -> BackendCloseOutcome {
        BackendCloseOutcome::drained(Ok(()))
    }
}

fn database(capacity: usize) -> (Database, Arc<CountingAdmission>, Preallocated) {
    let admission = CountingAdmission::new();
    let backend = Preallocated::with_capacity(capacity);
    let database = Database::builder(admission.clone())
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

#[test]
fn many_small_puts_stage_and_commit_within_admitted_workspace() {
    let _serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    let (database, _admission, _backend) = database(64 << 20);
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
    let crash = backend.crash(capacity);
    stage_puts(database.database().unwrap()).commit().unwrap();

    // A restart from the image left by the denial shows the prior state.
    let reopened = Database::builder(CountingAdmission::new())
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
