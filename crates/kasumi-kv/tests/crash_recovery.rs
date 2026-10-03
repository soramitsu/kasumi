use kasumi_kv as cache_types;
#[path = "../src/cache_test.rs"]
mod cache_test;

use kasumi_kv::group::InMemoryGroup;
use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, BackendNativeDisposition, CacheConfig, Core, CoreError,
    Database, GroupFile, Operation, OwnerFailed, ROOT_SLOT_BYTES, ResidentLease, RootSlot,
    SegmentGroupBackend, StorageAdmission, StorageError, TableDefinition, TransactionError,
};
use std::ffi::OsStr;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct UnlimitedAdmission;

impl StorageAdmission for UnlimitedAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn reserve_workspace(&self, _bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        Ok(Box::new(()))
    }

    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        Ok(())
    }

    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn owner_failed(&self) {}

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, kasumi_kv::AdmissionError> {
        cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryLease, kasumi_kv::AdmissionError> {
        cache_test::reserve(self, bytes)
    }
}
impl cache_test::Provider for UnlimitedAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), kasumi_kv::AdmissionError> {
        let _ = first;
        let _ = bytes;
        Ok(())
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
    }
}

#[derive(Clone, Copy)]
enum FailureMode {
    Before,
    After,
    TornDurable,
}

struct Fault {
    ordinal: usize,
    mode: FailureMode,
}

#[derive(Default)]
struct Image {
    group: InMemoryGroup,
    effects: usize,
    fault: Option<Fault>,
}

#[derive(Clone, Default)]
struct CrashBackend(Arc<Mutex<Image>>);

impl CrashBackend {
    fn crash(&self) -> Self {
        Self(Arc::new(Mutex::new(Image {
            group: self.0.lock().unwrap().group.crash(),
            ..Image::default()
        })))
    }
    fn inject(&self, ordinal: usize, mode: FailureMode) {
        let mut image = self.0.lock().unwrap();
        image.effects = 0;
        image.fault = Some(Fault { ordinal, mode });
    }
    fn effects(&self) -> usize {
        self.0.lock().unwrap().effects
    }
    fn corrupt_volatile(&self, needle: &[u8]) {
        let image = self.0.lock().unwrap();
        for name in image.group.entries().unwrap() {
            let Some(file) = name.to_str().and_then(GroupFile::parse_name) else {
                continue;
            };
            let mut bytes = vec![0; image.group.len(file).unwrap() as usize];
            image.group.read(file, 0, &mut bytes).unwrap();
            if let Some(at) = bytes
                .windows(needle.len())
                .position(|window| window == needle)
            {
                image
                    .group
                    .write(file, at as u64, &[bytes[at] ^ 0x80])
                    .unwrap();
                return;
            }
        }
        panic!("payload not present");
    }
    fn effect(
        &self,
        work: impl FnOnce(&InMemoryGroup) -> io::Result<()>,
        tear: impl FnOnce(&InMemoryGroup) -> InMemoryGroup,
    ) -> io::Result<()> {
        let mut image = self.0.lock().unwrap();
        image.effects += 1;
        let fault = image
            .fault
            .as_ref()
            .filter(|f| f.ordinal == image.effects)
            .map(|f| f.mode);
        if matches!(fault, Some(FailureMode::Before)) {
            return Err(io::ErrorKind::Other.into());
        }
        work(&image.group)?;
        if matches!(fault, Some(FailureMode::TornDurable)) {
            image.group = tear(&image.group);
        }
        if fault.is_some() {
            Err(io::ErrorKind::Other.into())
        } else {
            Ok(())
        }
    }
}
impl SegmentGroupBackend for CrashBackend {
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
        self.0.lock().unwrap().group.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.0
            .lock()
            .unwrap()
            .group
            .finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.0
            .lock()
            .unwrap()
            .group
            .cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.0.lock().unwrap().group.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.effect(
            |g| g.write_root(slot, bytes),
            |g| g.crash_torn_root(slot, ROOT_SLOT_BYTES / 2),
        )
    }
    fn sync_root(&self) -> io::Result<()> {
        self.effect(|g| g.sync_root(), InMemoryGroup::crash)
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.0.lock().unwrap().group.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.0.lock().unwrap().group.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.effect(|g| g.create(file), InMemoryGroup::crash)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.0.lock().unwrap().group.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.lock().unwrap().group.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.effect(
            |g| g.write(file, at, bytes),
            |g| g.crash_torn(file, bytes.len() / 2),
        )
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.effect(|g| g.set_len(file, length), InMemoryGroup::crash)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.effect(|g| g.sync(file), InMemoryGroup::crash)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.effect(|g| g.unlink(file), InMemoryGroup::crash)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.effect(|g| g.sync_names(), InMemoryGroup::crash)
    }
    fn close(&self) -> BackendCloseOutcome {
        self.0.lock().unwrap().group.close()
    }
}
const GROUP: [u8; 16] = [0x51; 16];

fn admission() -> Arc<dyn StorageAdmission> {
    Arc::new(UnlimitedAdmission)
}

#[derive(Default)]
struct CheckpointAdmission {
    calls: AtomicUsize,
    fail_at: AtomicUsize,
}

struct SlotAdmission {
    live: Arc<AtomicUsize>,
    limit: AtomicUsize,
}

struct SlotLease(Arc<AtomicUsize>);

impl Drop for SlotLease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl SlotAdmission {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            live: Arc::new(AtomicUsize::new(0)),
            limit: AtomicUsize::new(limit),
        })
    }
}

impl StorageAdmission for SlotAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn reserve_workspace(&self, _bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        let mut observed = self.live.load(Ordering::Acquire);
        loop {
            if observed >= self.limit.load(Ordering::Acquire) {
                return Err(AdmissionError::CapacityDenied);
            }
            match self.live.compare_exchange(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Box::new(SlotLease(self.live.clone())));
                }
                Err(actual) => observed = actual,
            }
        }
    }

    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        Ok(())
    }

    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn owner_failed(&self) {}

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, kasumi_kv::AdmissionError> {
        cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryLease, kasumi_kv::AdmissionError> {
        cache_test::reserve(self, bytes)
    }
}
impl cache_test::Provider for SlotAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), kasumi_kv::AdmissionError> {
        let _ = first;
        let _ = bytes;
        if first {
            self.live
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                    live.checked_add(1)
                        .filter(|next| *next <= self.limit.load(Ordering::Acquire))
                })
                .map_err(|_| AdmissionError::CapacityDenied)?;
        }
        Ok(())
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
        if last {
            self.live.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl StorageAdmission for CheckpointAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn reserve_workspace(&self, _bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        let fail_at = self.fail_at.load(Ordering::Acquire);
        if fail_at != 0 && call >= fail_at {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(Box::new(()))
        }
    }

    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        Ok(())
    }

    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn owner_failed(&self) {}

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, kasumi_kv::AdmissionError> {
        cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryLease, kasumi_kv::AdmissionError> {
        cache_test::reserve(self, bytes)
    }
}
impl cache_test::Provider for CheckpointAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), kasumi_kv::AdmissionError> {
        let _ = first;
        let _ = bytes;
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        let fail_at = self.fail_at.load(Ordering::Acquire);
        if fail_at != 0 && call >= fail_at {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(())
        }
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
    }
}

fn baseline() -> (Core, CrashBackend) {
    let backend = CrashBackend::default();
    let core =
        Core::create_with_backend(backend.clone(), admission(), GROUP, CacheConfig::default())
            .unwrap();
    core.commit(&[
        Operation::create_table("items"),
        Operation::put("items", b"a", b"old-a"),
        Operation::put("items", b"b", b"old-b"),
    ])
    .unwrap();
    (core, backend)
}

fn replacement() -> [Operation; 3] {
    [
        Operation::put("items", b"a", b"new-a"),
        Operation::delete("items", b"b"),
        Operation::put("items", b"c", b"new-c"),
    ]
}

fn churned() -> (Core, CrashBackend) {
    let (core, backend) = baseline();
    core.commit(&replacement()).unwrap();
    core.commit(&[
        Operation::put("items", b"a", b"last-a"),
        Operation::put("items", b"c", b"last-c"),
        Operation::put("items", b"temporary", b"scratch"),
    ])
    .unwrap();
    core.commit(&[Operation::delete("items", b"temporary")])
        .unwrap();
    (core, backend)
}

fn read(core: &Core, key: &[u8]) -> Option<Vec<u8>> {
    let view = core.snapshot().unwrap();
    core.get_admitted(&view, "items", key, 16)
        .unwrap()
        .map(|value| value.as_bytes().to_vec())
}

#[test]
fn every_failed_commit_effect_recovers_a_whole_generation() {
    verify_failed_commit_effects(0);
}

#[test]
fn cached_reads_never_expose_any_failed_commit_effect() {
    verify_failed_commit_effects(64 << 10);
}

fn prime_cache(core: &Core, byte_limit: u64) {
    core.configure_cache(CacheConfig { byte_limit }).unwrap();
    if byte_limit != 0 {
        loop {
            let progress = core.warm_cache(4).unwrap();
            if progress.complete {
                assert!(progress.fully_resident);
                break;
            }
        }
    }
}

fn verify_failed_commit_effects(cache_bytes: u64) {
    let (counting_core, counting_backend) = baseline();
    prime_cache(&counting_core, cache_bytes);
    counting_backend.inject(usize::MAX, FailureMode::Before);
    counting_core.commit(&replacement()).unwrap();
    let effect_count = counting_backend.effects();
    assert!(
        effect_count > 10,
        "expected to cover segment, directory and root effects"
    );

    for ordinal in 1..=effect_count {
        for mode in [
            FailureMode::Before,
            FailureMode::After,
            FailureMode::TornDurable,
        ] {
            let (core, backend) = baseline();
            prime_cache(&core, cache_bytes);
            let snapshot = core.snapshot().unwrap();
            backend.inject(ordinal, mode);
            assert!(matches!(
                core.commit(&replacement()),
                Err(CoreError::UnknownCommit(_) | CoreError::Io(_))
            ));
            assert!(matches!(
                core.get_admitted(&snapshot, "items", b"a", 16),
                Err(CoreError::OwnerFailed)
            ));
            let reopened = Core::open_with_backend(
                backend.crash(),
                admission(),
                GROUP,
                CacheConfig::default(),
            )
            .unwrap();
            let observed = (
                read(&reopened, b"a"),
                read(&reopened, b"b"),
                read(&reopened, b"c"),
            );
            let old = (Some(b"old-a".to_vec()), Some(b"old-b".to_vec()), None);
            let new = (Some(b"new-a".to_vec()), None, Some(b"new-c".to_vec()));
            assert!(
                observed == old || observed == new,
                "partial batch after effect {ordinal}: {observed:?}"
            );
        }
    }
}

#[test]
fn closing_wakes_a_queued_writer_even_while_another_writer_is_held() {
    let database = Arc::new(
        Database::builder(admission(), GROUP, CacheConfig::default())
            .create_with_backend(CrashBackend::default())
            .unwrap(),
    );
    let held_writer = database.begin_write().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let queued_database = database.clone();
    let queued = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        finished_tx.send(queued_database.begin_write()).unwrap();
    });
    started_rx.recv().unwrap();
    assert_eq!(
        database.close_native().native_disposition(),
        BackendNativeDisposition::Retained
    );
    let result = finished_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("queued writer should wake when close starts");
    assert!(matches!(
        result,
        Err(TransactionError(StorageError::DatabaseClosed))
    ));
    queued.join().unwrap();
    drop(held_writer);
    assert_eq!(
        database.close_native().native_disposition(),
        BackendNativeDisposition::Drained
    );
}

fn minimum_read_limit<T>(
    admission: &SlotAdmission,
    baseline: usize,
    mut read: impl FnMut() -> Result<T, kasumi_kv::BoundedReadError>,
) {
    for limit in baseline + 1..=baseline + 32 {
        admission.limit.store(limit, Ordering::Release);
        match read() {
            Ok(output) => {
                drop(output);
                assert_eq!(admission.live.load(Ordering::Acquire), baseline);
                return;
            }
            Err(error) => assert!(matches!(
                error,
                kasumi_kv::BoundedReadError::Storage(StorageError::Core(CoreError::CapacityDenied))
            )),
        }
        assert_eq!(admission.live.load(Ordering::Acquire), baseline);
    }
    panic!("bounded read required more than 32 transient admission slots");
}

#[test]
fn retained_raw_read_keeps_its_output_admitted_until_drop() {
    const ITEMS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("items");
    let admission = SlotAdmission::new(128);
    let database = Database::builder(admission.clone(), GROUP, CacheConfig::default())
        .create_with_backend(CrashBackend::default())
        .unwrap();
    let write = database.begin_write().unwrap();
    write
        .open_table(ITEMS)
        .unwrap()
        .insert(b"key", b"value")
        .unwrap();
    write.commit().unwrap();

    let retained = database.retain();
    let reader = retained.database().unwrap().begin_read_retained().unwrap();
    let baseline = admission.live.load(Ordering::Acquire);
    // Find required headroom, excluding optional cache-copy allocations that
    // can fall back to the admitted output. Retention must consume this same
    // capacity and dropping outputs must make the identical read possible.
    minimum_read_limit(&admission, baseline, || reader.get_bytes(ITEMS, b"key", 16));

    let first = reader.get_bytes(ITEMS, b"key", 16).unwrap().unwrap();
    assert_eq!(first.as_bytes(), b"value");
    assert_eq!(admission.live.load(Ordering::Acquire), baseline + 1);
    assert!(reader.get_bytes(ITEMS, b"key", 16).is_err());
    drop(first);
    assert_eq!(admission.live.load(Ordering::Acquire), baseline);
    assert_eq!(
        reader
            .get_bytes(ITEMS, b"key", 16)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"value"
    );

    minimum_read_limit(&admission, baseline, || {
        reader.next_bytes(ITEMS, b"", None, 16)
    });
    let row = reader.next_bytes(ITEMS, b"", None, 16).unwrap().unwrap();
    assert_eq!(row.key.as_bytes(), b"key");
    assert_eq!(row.value.as_bytes(), b"value");
    assert_eq!(admission.live.load(Ordering::Acquire), baseline + 2);
    assert!(reader.next_bytes(ITEMS, b"", None, 16).is_err());
    drop(row);
    assert_eq!(admission.live.load(Ordering::Acquire), baseline);
}

#[test]
fn detected_corruption_fences_preexisting_snapshots() {
    let (core, backend) = baseline();
    let view = core.snapshot().unwrap();
    backend.corrupt_volatile(b"old-a");
    assert!(matches!(
        core.get_admitted(&view, "items", b"a", 16),
        Err(CoreError::Corrupt(_))
    ));
    assert!(matches!(
        core.get_admitted(&view, "items", b"b", 16),
        Err(CoreError::OwnerFailed)
    ));
}

#[test]
fn batch_workspace_denial_leaves_all_published_versions_unchanged() {
    let backend = CrashBackend::default();
    let admission = Arc::new(CheckpointAdmission::default());
    let core = Core::create_with_backend(
        backend.clone(),
        admission.clone(),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap();
    core.commit(&[
        Operation::create_table("items"),
        Operation::put("items", b"a", b"old-a"),
    ])
    .unwrap();
    let generation = core.generation().unwrap();
    let end = core.committed_position().unwrap();
    let effects = backend.effects();
    let start = admission.calls.load(Ordering::Acquire);
    // Value-location and rollback workspace are both admitted before effects.
    // Deny the second reservation and verify no prepared bytes escape.
    admission.fail_at.store(start + 2, Ordering::Release);
    let mut batch = vec![
        Operation::put("items", b"a", b"middle"),
        Operation::put("items", b"a", b"new-a"),
    ];
    for index in 0..140u16 {
        batch.push(Operation::put(
            "items",
            format!("b{index:04}").into_bytes(),
            b"new-b",
        ));
    }
    assert!(matches!(
        core.commit(&batch),
        Err(CoreError::CapacityDenied)
    ));
    assert!(admission.calls.load(Ordering::Acquire) >= start + 2);
    assert_eq!(backend.effects(), effects);
    assert_eq!(core.generation().unwrap(), generation);
    assert_eq!(core.committed_position().unwrap(), end);
    admission.fail_at.store(0, Ordering::Release);
    assert_eq!(read(&core, b"a"), Some(b"old-a".to_vec()));
    assert_eq!(read(&core, b"b0000"), None);

    core.commit(&batch).unwrap();
    assert_eq!(read(&core, b"a"), Some(b"new-a".to_vec()));
    assert_eq!(read(&core, b"b0000"), Some(b"new-b".to_vec()));
    assert_eq!(read(&core, b"b0139"), Some(b"new-b".to_vec()));
    let reopened =
        Core::open_with_backend(backend.crash(), admission, GROUP, CacheConfig::default()).unwrap();
    assert_eq!(read(&reopened, b"a"), Some(b"new-a".to_vec()));
    assert_eq!(read(&reopened, b"b0000"), Some(b"new-b".to_vec()));
    assert_eq!(read(&reopened, b"b0139"), Some(b"new-b".to_vec()));
}

#[test]
fn every_failed_compaction_effect_reopens_all_live_values() {
    verify_failed_compaction_effects(0);
}

#[test]
fn cached_compaction_relocation_is_safe_at_every_failed_effect() {
    verify_failed_compaction_effects(64 << 10);
}

fn verify_failed_compaction_effects(cache_bytes: u64) {
    let (counting_core, counting_backend) = churned();
    prime_cache(&counting_core, cache_bytes);
    let before_position = counting_core.committed_position().unwrap();
    counting_backend.inject(usize::MAX, FailureMode::Before);
    counting_core.compact().unwrap();
    assert_ne!(counting_core.committed_position().unwrap(), before_position);
    let effect_count = counting_backend.effects();
    assert!(
        effect_count > 10,
        "expected segment, directory, root and unlink effects"
    );

    for ordinal in 1..=effect_count {
        for mode in [
            FailureMode::Before,
            FailureMode::After,
            FailureMode::TornDurable,
        ] {
            let (core, backend) = churned();
            prime_cache(&core, cache_bytes);
            backend.inject(ordinal, mode);
            assert!(core.compact().is_err());
            let reopened = Core::open_with_backend(
                backend.crash(),
                admission(),
                GROUP,
                CacheConfig::default(),
            )
            .unwrap_or_else(|error| panic!("reopen after effect {ordinal} failed: {error}"));
            assert_eq!(read(&reopened, b"a"), Some(b"last-a".to_vec()));
            assert_eq!(read(&reopened, b"b"), None);
            assert_eq!(read(&reopened, b"c"), Some(b"last-c".to_vec()));
            assert_eq!(read(&reopened, b"temporary"), None);
        }
    }
}

#[test]
fn many_live_keys_share_bounded_admission_slots_and_reopen() {
    let backend = CrashBackend::default();
    let admission = SlotAdmission::new(128);
    let core = Core::create_with_backend(
        backend.clone(),
        admission.clone(),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap();
    core.commit(&[Operation::create_table("items")]).unwrap();
    let mut operations = Vec::new();
    for index in 0..500u16 {
        operations.push(Operation::put(
            "items",
            format!("{index:04}").into_bytes(),
            vec![index as u8],
        ));
    }
    core.commit(&operations).unwrap();
    assert!(admission.live.load(Ordering::Acquire) <= 128);
    let crash = backend.crash();
    drop(core);
    assert_eq!(admission.live.load(Ordering::Acquire), 0);

    let reopened = Core::open_with_backend(
        crash,
        SlotAdmission::new(128),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap();
    for index in [0u16, 249, 499] {
        assert_eq!(
            read(&reopened, format!("{index:04}").as_bytes()),
            Some(vec![index as u8])
        );
    }
}
