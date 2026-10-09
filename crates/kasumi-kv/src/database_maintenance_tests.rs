//! Database-level maintenance: the inline step before every write, the
//! busy-aware explicit step, status, requests and the error boundary.

use super::*;
use crate::group::{FaultTiming, GroupFile, GroupOp, InMemoryGroup};
use crate::root::{ROOT_SLOT_BYTES, RootSlot};
use crate::{MaintenanceBudget, MaintenanceDeferral, MaintenanceStep, StorageCompactionPhase};
use std::ffi::OsStr;
use std::sync::atomic::AtomicUsize;

const GROUP: [u8; 16] = [57; 16];
const ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("rows");

/// Allows everything except a one-shot refusal of the next large workspace.
#[derive(Default)]
struct Admission {
    deny_next_large: AtomicBool,
    denials: AtomicUsize,
    failed: AtomicBool,
}

impl StorageAdmission for Admission {
    fn check_owner(&self) -> Result<(), crate::core::OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(crate::core::OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_workspace(
        &self,
        bytes: u64,
    ) -> Result<Box<dyn ResidentLease>, crate::core::AdmissionError> {
        self.check_owner()
            .map_err(|_| crate::core::AdmissionError::OwnerFailed)?;
        if bytes >= 1 << 20 && self.deny_next_large.swap(false, Ordering::AcqRel) {
            self.denials.fetch_add(1, Ordering::AcqRel);
            return Err(crate::core::AdmissionError::CapacityDenied);
        }
        Ok(Box::new(()))
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), crate::core::AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), crate::core::OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
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
    fn acquire_cache(&self, _: u64, _: bool) -> Result<(), crate::AdmissionError> {
        Ok(())
    }
    fn release_cache(&self, _: u64, _: bool) {}
}

/// An in-memory group whose next transaction reservation can be refused.
#[derive(Clone)]
struct Group {
    inner: InMemoryGroup,
    deny_next_reservation: Arc<AtomicBool>,
    reservations: Arc<AtomicUsize>,
}

impl Group {
    fn new(inner: InMemoryGroup) -> Self {
        Self {
            inner,
            deny_next_reservation: Arc::new(AtomicBool::new(false)),
            reservations: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl SegmentGroupBackend for Group {
    fn reserve_transaction(
        &self,
        plan: &crate::TransactionSpacePlan,
    ) -> std::result::Result<(), crate::TransactionReserveError> {
        if self.deny_next_reservation.swap(false, Ordering::AcqRel) {
            return Err(crate::TransactionReserveError::CapacityDenied);
        }
        self.reservations.fetch_add(1, Ordering::AcqRel);
        self.inner.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.inner.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
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
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.inner.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.inner.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.inner.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.inner.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.inner.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.inner.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.inner.set_len(file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.inner.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.inner.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.inner.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.inner.close()
    }
}

fn create(group: Group, admission: Arc<Admission>) -> Database {
    Database::builder(admission, GROUP, CacheConfig::default())
        .create_with_backend(group)
        .unwrap()
}

fn open(group: Group, admission: Arc<Admission>) -> Database {
    Database::builder(admission, GROUP, CacheConfig::default())
        .open_with_backend(group)
        .unwrap()
}

fn write(database: &Database, key: &[u8], value: &[u8]) -> Result<(), String> {
    let writer = database.begin_write().map_err(|error| error.to_string())?;
    {
        let mut rows = writer.open_table(ROWS).map_err(|error| error.to_string())?;
        rows.insert(key, value).map_err(|error| error.to_string())?;
    }
    writer.commit().map_err(|error| error.to_string())
}

fn read(database: &Database, key: &[u8]) -> Option<Vec<u8>> {
    let reader = database.begin_read().unwrap();
    let rows = reader.open_table(ROWS).unwrap();
    rows.get(key).unwrap().map(|value| value.value().to_vec())
}

/// Rows in old files, sealed so a cycle covers them.
fn seeded(group: &Group, admission: &Arc<Admission>) -> Database {
    let database = create(group.clone(), admission.clone());
    for index in 0..40u8 {
        write(&database, &[index], &[index; 48]).unwrap();
    }
    database.inner.core.seal_files_for_test().unwrap();
    database
}

const STEP: MaintenanceBudget = MaintenanceBudget {
    units: 64,
    mutations: 1,
};

fn run(database: &Database) -> crate::MaintenanceProgress {
    match database.run_maintenance(STEP).unwrap() {
        MaintenanceStep::Ran(progress) => progress,
        MaintenanceStep::Busy => panic!("unexpected busy writer gate"),
    }
}

#[test]
fn begin_write_and_commit_survive_maintenance_capacity_denial() {
    let group = Group::new(InMemoryGroup::new());
    let admission = Arc::new(Admission::default());
    let database = seeded(&group, &admission);
    database.request_compaction().unwrap();
    // The inline step begins the cycle; its first leaf rewrite is refused
    // its transaction space. The write itself proceeds and commits.
    write(&database, b"x", b"first").unwrap();
    assert_eq!(
        database.maintenance_status().unwrap().phase,
        StorageCompactionPhase::Evacuating
    );
    group.deny_next_reservation.store(true, Ordering::Release);
    write(&database, b"y", b"second").unwrap();
    let status = database.maintenance_status().unwrap();
    assert_eq!(status.last_deferral, Some(MaintenanceDeferral::Capacity));
    assert_eq!(status.capacity_deferrals_total, 1);
    // A refused maintenance workspace reservation behaves the same way.
    database.request_compaction().unwrap();
    admission.deny_next_large.store(true, Ordering::Release);
    write(&database, b"z", b"third").unwrap();
    assert_eq!(admission.denials.load(Ordering::Acquire), 1);
    let status = database.maintenance_status().unwrap();
    assert_eq!(status.capacity_deferrals_total, 2);
    assert!(!database.inner.core.is_fenced());
    // Later steps resume from the kept cursors and finish the cycle.
    let cycle = database.inner.core.complete_cycle_for_test().unwrap();
    assert!(cycle.relocated_bytes > 0);
    assert_eq!(
        database.maintenance_status().unwrap().phase,
        StorageCompactionPhase::Idle
    );
    for (key, value) in [
        (&b"x"[..], &b"first"[..]),
        (b"y", b"second"),
        (b"z", b"third"),
    ] {
        assert_eq!(read(&database, key).as_deref(), Some(value));
    }
    for index in 0..40u8 {
        assert_eq!(read(&database, &[index]), Some(vec![index; 48]));
    }
}

#[test]
fn maintenance_io_failure_fences_begin_write_and_reopen_recovers() {
    let inner = InMemoryGroup::new();
    let group = Group::new(inner.clone());
    let admission = Arc::new(Admission::default());
    let database = seeded(&group, &admission);
    database.request_compaction().unwrap();
    // The inline step's phase publication fails its first slot write.
    inner.fail(GroupOp::RootWrite, 1, FaultTiming::BeforeEffect);
    let error = match database.begin_write() {
        Ok(_) => panic!("a failed inline maintenance publication admitted a writer"),
        Err(error) => error,
    };
    assert!(database.inner.core.is_fenced(), "{error}");
    assert!(database.begin_write().is_err());
    drop(database);
    let restarted = Group::new(inner.crash());
    let reopened = open(restarted, Arc::new(Admission::default()));
    for index in 0..40u8 {
        assert_eq!(read(&reopened, &[index]), Some(vec![index; 48]));
    }
    write(&reopened, b"after", b"reopen").unwrap();
    assert_eq!(read(&reopened, b"after").as_deref(), Some(&b"reopen"[..]));
}

#[test]
fn run_maintenance_returns_busy_while_writer_held() {
    let group = Group::new(InMemoryGroup::new());
    let admission = Arc::new(Admission::default());
    let database = seeded(&group, &admission);
    database.request_compaction().unwrap();
    let writer = database.begin_write().unwrap();
    let before = database.maintenance_status().unwrap();
    assert_eq!(
        database.run_maintenance(STEP).unwrap(),
        MaintenanceStep::Busy
    );
    assert_eq!(
        database
            .transaction_admission()
            .run_maintenance(STEP)
            .unwrap(),
        MaintenanceStep::Busy
    );
    assert_eq!(database.maintenance_status().unwrap(), before);
    writer.abort().unwrap();
    assert!(matches!(
        database.run_maintenance(STEP).unwrap(),
        MaintenanceStep::Ran(_)
    ));
    // The gate is released again after the step.
    write(&database, b"k", b"v").unwrap();
}

#[test]
fn maintenance_status_reports_measurement_phase_and_counters() {
    let group = Group::new(InMemoryGroup::new());
    let admission = Arc::new(Admission::default());
    let fresh = create(group.clone(), admission.clone());
    let status = fresh.maintenance_status().unwrap();
    assert_eq!(status.phase, StorageCompactionPhase::Idle);
    assert_eq!(status.cycle, 0);
    assert!(!status.measured);
    fresh.close().map_err(|_| "busy").unwrap();
    let group = Group::new(group.inner.crash());
    let database = open(group.clone(), admission.clone());
    for index in 0..40u8 {
        write(&database, &[index], &[index; 48]).unwrap();
    }
    database.inner.core.seal_files_for_test().unwrap();
    // Idle steps measure; the default policy needs far more growth.
    loop {
        if run(&database).idle {
            break;
        }
    }
    let status = database.maintenance_status().unwrap();
    assert!(status.measured);
    assert!(
        status.segment_files >= 2 && status.arena_files >= 2,
        "{status:?}"
    );
    assert!(status.segment_bytes > 0 && status.arena_bytes > 0);
    assert_eq!(status.trigger_bytes, 256 << 20);
    assert_eq!(status.trigger_files, 16);
    let cycle = database.inner.core.complete_cycle_for_test().unwrap();
    let status = database.maintenance_status().unwrap();
    assert_eq!(status.cycle, 1);
    assert_eq!(status.cycles_completed, 1);
    assert_eq!(status.relocated_bytes_total, cycle.relocated_bytes);
    assert_eq!(status.reclaimed_files_total, cycle.reclaimed_files);
    assert_eq!(status.reclaimed_bytes_total, cycle.reclaimed_bytes);
    assert!(status.reclaimed_files_total >= 2);
    assert!(status.baseline_bytes > 0 && status.baseline_files > 0);
    assert_eq!(status.garbage_files, 0);
    assert_eq!(status.reclaim_invalidations_total, 0);
    assert!(!status.requested);
}

#[test]
fn request_compaction_drives_one_cycle_to_idle() {
    let group = Group::new(InMemoryGroup::new());
    let admission = Arc::new(Admission::default());
    let database = seeded(&group, &admission);
    database.request_compaction().unwrap();
    assert!(database.maintenance_status().unwrap().requested);
    let mut phases = vec![StorageCompactionPhase::Idle];
    for _ in 0..100_000 {
        let progress = run(&database);
        if phases.last() != Some(&progress.phase) {
            phases.push(progress.phase);
        }
        if progress.phase == StorageCompactionPhase::Idle && phases.len() > 1 {
            break;
        }
    }
    assert_eq!(
        phases,
        [
            StorageCompactionPhase::Idle,
            StorageCompactionPhase::Evacuating,
            StorageCompactionPhase::Reclaiming,
            StorageCompactionPhase::Packing,
            StorageCompactionPhase::Idle,
        ]
    );
    let status = database.maintenance_status().unwrap();
    assert_eq!(status.cycle, 1);
    assert!(!status.requested);
    // Exactly one cycle: further steps stay idle.
    for _ in 0..8 {
        run(&database);
    }
    assert_eq!(database.maintenance_status().unwrap().cycle, 1);
    assert!(group.reservations.load(Ordering::Acquire) > 0);
}
