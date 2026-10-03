mod commit_admission {
    include!("disk_commit_admission_tests.rs");
}

mod prepared_point_shape {
    include!("disk_prepared_point_shape_tests.rs");
}

mod admitted_read_into {
    include!("disk_admitted_read_into_tests.rs");
}

use super::*;

mod batch_leaf {
    include!("disk_batch_leaf_tests.rs");
}

mod warming_failures {
    include!("disk_warm_failure_tests.rs");
}

mod warming {
    include!("disk_warm_tests.rs");
}

mod publication_cache {
    include!("disk_publication_tests.rs");
}

mod publication_failures {
    include!("disk_publication_failure_tests.rs");
}

mod automatic_warming {
    include!("disk_auto_warm_tests.rs");
}
use crate::core::{AdmissionError, BackendCloseOutcome, OwnerFailed};
use crate::group::{FaultTiming, GroupOp, InMemoryGroup};
use crate::root::{ROOT_SLOT_BYTES, RootSlot};
use std::ffi::OsStr;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize};

const GROUP: [u8; 16] = [43; 16];
const LARGE_CACHE: CacheConfig = CacheConfig {
    byte_limit: 4 << 20,
};

struct Admission {
    used: Arc<AtomicU64>,
    peak: AtomicU64,
    limit: AtomicU64,
    calls: AtomicUsize,
    refused_calls: AtomicUsize,
    deny_at: AtomicUsize,
    failed: AtomicBool,
}

struct Lease {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

impl Admission {
    fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            used: Arc::new(AtomicU64::new(0)),
            peak: AtomicU64::new(0),
            limit: AtomicU64::new(limit),
            calls: AtomicUsize::new(0),
            refused_calls: AtomicUsize::new(0),
            deny_at: AtomicUsize::new(usize::MAX),
            failed: AtomicBool::new(false),
        })
    }

    fn deny_nth(&self, nth: usize) {
        self.deny_at
            .store(self.calls.load(Ordering::Acquire) + nth, Ordering::Release);
    }
}

impl StorageAdmission for Admission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }

    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if call == self.deny_at.load(Ordering::Acquire) {
            self.refused_calls.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        let mut old = self.used.load(Ordering::Acquire);
        loop {
            let next = old
                .checked_add(bytes)
                .ok_or(AdmissionError::CapacityDenied)?;
            if next > self.limit.load(Ordering::Acquire) {
                return Err(AdmissionError::CapacityDenied);
            }
            match self
                .used
                .compare_exchange(old, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    self.peak.fetch_max(next, Ordering::AcqRel);
                    break;
                }
                Err(actual) => old = actual,
            }
        }
        Ok(Box::new(Lease {
            used: self.used.clone(),
            bytes,
        }))
    }

    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        self.check_owner().map_err(|_| AdmissionError::OwnerFailed)
    }

    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        self.check_owner()
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
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
        let _ = first;
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if call == self.deny_at.load(Ordering::Acquire) {
            self.refused_calls.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        let old = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.limit.load(Ordering::Acquire))
            })
            .map_err(|_| AdmissionError::CapacityDenied)?;
        self.peak.fetch_max(old + bytes, Ordering::AcqRel);
        Ok(())
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
        self.used.fetch_sub(bytes, Ordering::AcqRel);
    }
}

struct Reads {
    group: InMemoryGroup,
    reads: AtomicUsize,
    effects: AtomicUsize,
    panic_root_write: AtomicBool,
}

impl Reads {
    fn new(group: InMemoryGroup) -> Arc<Self> {
        Arc::new(Self {
            group,
            reads: AtomicUsize::new(0),
            effects: AtomicUsize::new(0),
            panic_root_write: AtomicBool::new(false),
        })
    }
    fn count(&self) -> usize {
        self.reads.load(Ordering::Acquire)
    }
}

impl SegmentGroupBackend for Reads {
    fn reserve_transaction(
        &self,
        plan: &crate::TransactionSpacePlan,
    ) -> std::result::Result<(), crate::TransactionReserveError> {
        self.group.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.group.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.effects.fetch_add(1, Ordering::AcqRel);
        self.group.write_root(slot, bytes)?;
        assert!(
            !self.panic_root_write.swap(false, Ordering::AcqRel),
            "publication unwind"
        );
        Ok(())
    }
    fn sync_root(&self) -> io::Result<()> {
        self.effects.fetch_add(1, Ordering::AcqRel);
        self.group.sync_root()
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.group.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.group.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.effects.fetch_add(1, Ordering::AcqRel);
        self.group.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.group.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::AcqRel);
        self.group.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.effects.fetch_add(1, Ordering::AcqRel);
        self.group.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.effects.fetch_add(1, Ordering::AcqRel);
        self.group.set_len(file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.effects.fetch_add(1, Ordering::AcqRel);
        self.group.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.effects.fetch_add(1, Ordering::AcqRel);
        self.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.effects.fetch_add(1, Ordering::AcqRel);
        self.group.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.group.close()
    }
}

fn create(
    group: Arc<dyn SegmentGroupBackend>,
    admission: Arc<Admission>,
    cache: CacheConfig,
) -> DiskState {
    DiskState::create(group, admission, GROUP, cache).unwrap()
}

fn value(state: &mut DiskState, root: &SnapshotPin, key: &[u8]) -> Option<Vec<u8>> {
    state
        .get(root, "accounts", key, usize::MAX)
        .unwrap()
        .map(|value| value.as_bytes().to_vec())
}

fn warm_all(state: &mut DiskState) -> CacheWarmup {
    for _ in 0..1024 {
        let status = state.warm(17).unwrap();
        if status.complete {
            return status;
        }
    }
    panic!("bounded warm-up never completed");
}

#[test]
fn durable_multi_table_commit_preserves_old_roots_and_ordered_prefixes() {
    let group = InMemoryGroup::new();
    let admission = Admission::new(16 << 20);
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::create_table("documents"),
            Operation::put("accounts", b"a/1", b"old"),
            Operation::put("accounts", b"a/2", b"two"),
            Operation::put("accounts", b"b/1", b"other"),
            Operation::put("documents", b"first", b"doc"),
        ])
        .unwrap();
    let old = state.snapshot().unwrap();
    state
        .commit(&[
            Operation::put("accounts", b"a/1", b"intermediate"),
            Operation::put("accounts", b"a/1", b"new"),
            Operation::delete("accounts", b"a/2"),
            Operation::put("accounts", b"a/3", b"three"),
            Operation::create_table("empty"),
        ])
        .unwrap();
    let current = state.snapshot().unwrap();
    assert_eq!(value(&mut state, &old, b"a/1").unwrap(), b"old");
    assert_eq!(value(&mut state, &old, b"a/2").unwrap(), b"two");
    assert_eq!(value(&mut state, &current, b"a/1").unwrap(), b"new");
    assert_eq!(value(&mut state, &current, b"a/2"), None);
    assert!(state.table_exists(&current, "empty").unwrap());
    assert!(!state.table_exists(&old, "empty").unwrap());
    let first = state
        .next(&current, "accounts", b"a/", None)
        .unwrap()
        .unwrap();
    let second = state
        .next(&current, "accounts", b"a/", first.key().row)
        .unwrap()
        .unwrap();
    assert_eq!(first.key().row.unwrap(), b"a/1");
    assert_eq!(second.key().row.unwrap(), b"a/3");
    assert!(
        state
            .next(&current, "accounts", b"a/", second.key().row)
            .unwrap()
            .is_none()
    );
    drop(first);
    drop(second);
    let current_root = current.root();
    drop(old);
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let mut reopened = DiskState::open(
        Arc::new(group.crash()),
        admission.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    let current = reopened.snapshot().unwrap();
    assert_eq!(current.root(), current_root);
    assert_eq!(value(&mut reopened, &current, b"a/1").unwrap(), b"new");
    assert_eq!(
        reopened
            .get(&current, "documents", b"first", 3)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"doc"
    );
    drop(current);
    drop(reopened);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn fitting_writes_are_immediately_resident_and_reopen_warms_without_misses() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(16 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    let mut ops = vec![Operation::create_table("accounts")];
    // Several leaves plus a branch; newly split siblings must be retained too.
    for key in 0..380u32 {
        ops.push(Operation::put(
            "accounts",
            key.to_be_bytes(),
            vec![key as u8; 80],
        ));
    }
    state.commit(&ops).unwrap();
    let root = state.snapshot().unwrap();
    let before = reads.count();
    for key in 0..380u32 {
        assert_eq!(
            value(&mut state, &root, &key.to_be_bytes()).unwrap(),
            vec![key as u8; 80]
        );
    }
    assert_eq!(
        reads.count(),
        before,
        "fitting committed values/pages were left cold"
    );
    assert_eq!(state.cache_stats().unwrap().evictions, 0);
    drop(root);
    state.commit(&[Operation::create_table("empty")]).unwrap();
    let root = state.snapshot().unwrap();
    let before = reads.count();
    assert!(state.table_exists(&root, "empty").unwrap());
    assert_eq!(
        reads.count(),
        before,
        "table-only commit left its page cold"
    );
    drop(root);
    state
        .commit(&[Operation::delete("accounts", 0u32.to_be_bytes())])
        .unwrap();
    let root = state.snapshot().unwrap();
    let before = reads.count();
    assert_eq!(value(&mut state, &root, &0u32.to_be_bytes()), None);
    assert_eq!(
        reads.count(),
        before,
        "delete-only commit left its page cold"
    );
    let saved_root = root.root();
    drop(root);
    let group = reads.group.crash();
    drop(state);
    let reads = Reads::new(group);
    let mut reopened = DiskState::open(reads.clone(), admission, GROUP, LARGE_CACHE).unwrap();
    assert!(warm_all(&mut reopened).fully_resident);
    let root = reopened.snapshot().unwrap();
    assert_eq!(root.root(), saved_root);
    let before = reads.count();
    for key in 1..380u32 {
        assert!(value(&mut reopened, &root, &key.to_be_bytes()).is_some());
    }
    assert_eq!(reads.count(), before);
}

#[test]
fn pressure_keeps_one_bound_and_refills_when_budget_grows() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let small = CacheConfig {
        byte_limit: 48 << 10,
    };
    let mut state = create(reads.clone(), admission.clone(), small);
    let mut ops = vec![Operation::create_table("accounts")];
    for key in 0..96u32 {
        ops.push(Operation::put(
            "accounts",
            key.to_be_bytes(),
            vec![key as u8; 1024],
        ));
    }
    state.commit(&ops).unwrap();
    let root = state.snapshot().unwrap();
    assert!(!warm_all(&mut state).fully_resident);
    assert!(state.cache_stats().unwrap().resident_bytes <= small.byte_limit);
    let before = reads.count();
    for key in 0..96u32 {
        assert_eq!(
            value(&mut state, &root, &key.to_be_bytes()).unwrap(),
            vec![key as u8; 1024]
        );
    }
    assert!(reads.count() > before);
    state
        .configure_cache(CacheConfig {
            byte_limit: 512 << 10,
        })
        .unwrap();
    assert!(warm_all(&mut state).fully_resident);
    let before = reads.count();
    for key in 0..96u32 {
        assert!(value(&mut state, &root, &key.to_be_bytes()).is_some());
    }
    assert_eq!(reads.count(), before);
    assert!(admission.peak.load(Ordering::Acquire) <= 8 << 20);
    drop(root);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn reopen_and_reads_do_not_rebuild_a_resident_map_for_data_above_admitted_memory() {
    let group = InMemoryGroup::new();
    let admission = Admission::new(3 << 20);
    let config = CacheConfig {
        byte_limit: 48 << 10,
    };
    let mut state = create(Arc::new(group.clone()), admission.clone(), config);
    state
        .commit(&[Operation::create_table("accounts")])
        .unwrap();
    // Four MiB of logical values exceeds the three MiB native admission.
    // Inputs are bounded one-row batches, not a test-owned all-data buffer.
    for key in 0..128u32 {
        state
            .commit(&[Operation::put(
                "accounts",
                key.to_be_bytes(),
                vec![key as u8; 32 << 10],
            )])
            .unwrap();
        assert!(state.cache_stats().unwrap().resident_bytes <= config.byte_limit);
    }
    let saved_root = state.snapshot().unwrap().root();
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let mut state =
        DiskState::open(Arc::new(group.crash()), admission.clone(), GROUP, config).unwrap();
    let root = state.snapshot().unwrap();
    assert_eq!(root.root(), saved_root);
    for key in 0..128u32 {
        let bytes = state
            .get(&root, "accounts", &key.to_be_bytes(), 32 << 10)
            .unwrap()
            .unwrap();
        assert_eq!(bytes.as_bytes().len(), 32 << 10);
        assert!(bytes.as_bytes().iter().all(|byte| *byte == key as u8));
        assert!(state.cache_stats().unwrap().resident_bytes <= config.byte_limit);
    }
    assert!(admission.peak.load(Ordering::Acquire) <= 3 << 20);
    drop(root);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn every_commit_effect_recovers_one_complete_root_or_the_previous_root() {
    let ops = [
        Operation::create_table("accounts"),
        Operation::create_table("documents"),
        Operation::put("accounts", b"a", b"account"),
        Operation::put("documents", b"d", b"document"),
    ];
    for timing in [FaultTiming::BeforeEffect, FaultTiming::AfterEffect] {
        for op in [
            GroupOp::Create,
            GroupOp::Write,
            GroupOp::Sync,
            GroupOp::SyncNames,
            GroupOp::RootWrite,
            GroupOp::RootSync,
        ] {
            for nth in 1..=32 {
                let group = InMemoryGroup::new();
                let admission = Admission::new(16 << 20);
                let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
                group.fail(op, nth, timing);
                let result = state.commit(&ops);
                let successful = result.is_ok();
                if !successful {
                    assert!(state.is_fenced(), "{op:?} {timing:?} {nth}: {result:?}");
                }
                drop(state);
                let mut reopened =
                    DiskState::open(Arc::new(group.crash()), admission, GROUP, LARGE_CACHE)
                        .unwrap_or_else(|error| {
                            panic!("{op:?} {timing:?} {nth}: reopen {error}; commit {result:?}")
                        });
                let root = reopened.snapshot().unwrap();
                let present = reopened.table_exists(&root, "accounts").unwrap();
                assert_eq!(present, reopened.table_exists(&root, "documents").unwrap());
                if present {
                    assert_eq!(value(&mut reopened, &root, b"a").unwrap(), b"account");
                    assert_eq!(
                        reopened
                            .get(&root, "documents", b"d", 100)
                            .unwrap()
                            .unwrap()
                            .as_bytes(),
                        b"document"
                    );
                }
                if successful {
                    assert!(present);
                    break;
                }
                assert!(nth < 32, "unbounded effect count");
            }
        }
    }
}

#[test]
fn cache_hits_still_enforce_owner_and_snapshot_scope() {
    let admission = Admission::new(16 << 20);
    let mut state = create(
        Arc::new(InMemoryGroup::new()),
        admission.clone(),
        LARGE_CACHE,
    );
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", b"value"),
        ])
        .unwrap();
    let root = state.snapshot().unwrap();
    let foreign_registry = SnapshotPins::new(admission.clone(), GROUP, 1).unwrap();
    let foreign = foreign_registry.acquire(root.root()).unwrap();
    assert!(matches!(
        state.get(&foreign, "accounts", b"a", 99),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(!state.is_fenced());
    assert!(value(&mut state, &root, b"a").is_some());
    admission.failed.store(true, Ordering::Release);
    assert!(matches!(
        state.get(&root, "accounts", b"a", 99),
        Err(CoreError::OwnerFailed)
    ));
    assert!(state.is_fenced());
}

#[test]
fn publication_panic_is_unknown_commit_and_reopen_selects_durable_batch() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(16 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    state
        .commit(&[Operation::create_table("accounts")])
        .unwrap();
    reads.panic_root_write.store(true, Ordering::Release);
    let error = state
        .commit(&[Operation::put("accounts", b"a", b"durable")])
        .unwrap_err();
    let CoreError::UnknownCommit(source) = error else {
        panic!("wrong unwind classification: {error}");
    };
    let panic = source
        .get_ref()
        .unwrap()
        .downcast_ref::<CorePanic>()
        .unwrap();
    assert!(
        panic.with_payload(|payload| payload.downcast_ref::<&str>() == Some(&"publication unwind"))
    );
    assert!(state.is_fenced());
    drop(state);
    let mut state =
        DiskState::open(Arc::new(reads.group.crash()), admission, GROUP, LARGE_CACHE).unwrap();
    let root = state.snapshot().unwrap();
    assert_eq!(value(&mut state, &root, b"a").unwrap(), b"durable");
}

#[test]
fn recovery_uses_last_commit_position_before_a_later_abandoned_segment() {
    let group = InMemoryGroup::new();
    let admission = Admission::new(16 << 20);
    let mut state = create(Arc::new(group.clone()), admission.clone(), LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", b"old"),
        ])
        .unwrap();
    // Simulate crash after log commit, before selecting it in the superblock.
    let ops = [Operation::put("accounts", b"a", b"committed")];
    let mut roll = Roll(state.owner.clone());
    let prepared = state
        .writer
        .prepare_batch(state.owner.backend.as_ref(), &ops, &mut roll)
        .unwrap();
    let generation = prepared.batch_seq();
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(state.arena.as_ref(), &mut mutator_workspace).unwrap();
    let root = mutator
        .set(
            state.selected,
            generation,
            DirectoryKey::row("accounts", b"a"),
            Some(DirectoryValue::Row {
                batch_seq: generation,
                value: prepared.values()[0].unwrap(),
            }),
        )
        .unwrap();
    let root = mutator.finish(root).unwrap();
    drop(mutator_workspace);
    let committed = state
        .writer
        .finish_batch(state.owner.backend.as_ref(), prepared, root, &mut roll)
        .unwrap();
    let capacity = committed.end.offset + 32;
    let writer = std::mem::replace(&mut state.writer, SegmentWriter::new(GROUP));
    state.writer = writer.with_capacity(capacity);
    let abandoned = state
        .writer
        .prepare_batch(
            state.owner.backend.as_ref(),
            &[Operation::put("accounts", b"a", vec![7; 256])],
            &mut roll,
        )
        .unwrap();
    assert!(state.writer.position().unwrap().segment_id > committed.end.segment_id);
    drop(abandoned);
    drop(roll);
    drop(state);
    let mut state =
        DiskState::open(Arc::new(group.crash()), admission, GROUP, LARGE_CACHE).unwrap();
    let recovered = state.snapshot().unwrap();
    assert_eq!(recovered.root(), root);
    assert_eq!(value(&mut state, &recovered, b"a").unwrap(), b"committed");
    state
        .commit(&[Operation::put("accounts", b"a", b"after-reopen")])
        .unwrap();
    let current = state.snapshot().unwrap();
    assert!(current.root().generation > root.generation + 1);
    assert_eq!(value(&mut state, &current, b"a").unwrap(), b"after-reopen");
}

#[path = "disk_reclaim_tests.rs"]
mod reclaim;

#[path = "disk_compact_tests.rs"]
mod compact;
