use super::*;
use crate::NodeDiskMemoryAdmission;
use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, GroupFile, OwnerFailed, ROOT_SLOT_BYTES, ResidentLease,
    RootSlot, SegmentGroupBackend, StorageAdmission, TableDefinition,
};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex as StdMutex};

const ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("warming");

struct MemoryAdmission {
    memory: Arc<crate::test_utils::TestDiskMemory>,
    failed: AtomicBool,
    release_on_denial: Mutex<Option<crate::DiskMemoryLease>>,
    /// Pauses the next workspace reservation: database work calls it while
    /// holding the KV core lock.
    workspace_gate: ReadGate,
}
impl StorageAdmission for MemoryAdmission {
    fn check_owner(&self) -> std::result::Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_workspace(
        &self,
        bytes: u64,
    ) -> std::result::Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if self.workspace_gate.armed.swap(false, Ordering::AcqRel) {
            self.workspace_gate.pause();
        }
        let bytes = bytes
            .checked_add(std::mem::size_of::<crate::DiskMemoryLease>() as u64 + 4096)
            .ok_or(AdmissionError::CapacityDenied)?;
        let lease = self
            .memory
            .clone()
            .reserve_installed(bytes)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::OutOfMemory {
                    // Model a foreign reservation retiring inside the failed
                    // callback, before the worker can make an idle observation.
                    self.release_on_denial.lock().take();
                    AdmissionError::CapacityDenied
                } else {
                    AdmissionError::OwnerFailed
                }
            })?;
        Ok(Box::new(lease))
    }
    fn reserve_growth(&self, before: u64, after: u64) -> std::result::Result<(), AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if after < before || after > 256 << 30 {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(())
        }
    }
    fn settle_growth(&self, _: u64) -> std::result::Result<(), OwnerFailed> {
        self.check_owner()
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, AdmissionError> {
        crate::test_utils::cache_memory::quote(self, bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryLease, AdmissionError> {
        crate::test_utils::cache_memory::reserve(self, bytes)
    }
}

impl crate::test_utils::cache_memory::Provider for MemoryAdmission {
    fn inner_quote(&self, bytes: u64) -> Result<kasumi_kv::CacheMemoryQuote, AdmissionError> {
        self.memory
            .quote_cache_memory(bytes)
            .map_err(cache_admission_error)
    }
    fn inner_reserve(&self, bytes: u64) -> Result<kasumi_kv::CacheMemoryLease, AdmissionError> {
        self.memory
            .clone()
            .reserve_cache_memory(bytes)
            .map_err(cache_admission_error)
    }
    fn denied(&self) {
        // The foreign pressure can disappear inside the refused cache growth,
        // before the worker makes its next observation. No extra lease is made.
        self.release_on_denial.lock().take();
    }
}
fn cache_admission_error(error: io::Error) -> AdmissionError {
    if error.kind() == io::ErrorKind::OutOfMemory {
        AdmissionError::CapacityDenied
    } else {
        AdmissionError::OwnerFailed
    }
}

#[derive(Default)]
struct ReadGate {
    armed: AtomicBool,
    entered: tokio::sync::Notify,
    released: StdMutex<bool>,
    changed: Condvar,
}
impl ReadGate {
    fn pause(&self) {
        self.entered.notify_one();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.changed.wait(released).unwrap();
        }
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}
struct ReleaseGate<'a>(&'a ReadGate);
impl Drop for ReleaseGate<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

thread_local! {
    /// Set by a writer around its commit (`write_row_publishing_slowly`): the
    /// next root slot this thread writes, the first write of the commit's root
    /// publication, takes this long.
    static ROOT_WRITE_DELAY: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

struct Probe {
    group: kasumi_kv::backends::InMemoryGroup,
    reads: AtomicUsize,
    closes: AtomicUsize,
    read_failure: Mutex<Option<io::Error>>,
    gate: ReadGate,
    /// Microseconds every durable synchronization takes: a slow disk.
    sync_micros: AtomicU64,
    syncs: AtomicUsize,
    /// When each slow root publication (`ROOT_WRITE_DELAY`) began and ended.
    slow_publications: Mutex<Vec<(Instant, Instant)>>,
}
impl Probe {
    fn slow_sync(&self) {
        self.syncs.fetch_add(1, Ordering::AcqRel);
        let micros = self.sync_micros.load(Ordering::Acquire);
        if micros != 0 {
            std::thread::sleep(Duration::from_micros(micros));
        }
    }
}
impl SegmentGroupBackend for Probe {
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
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
        if let Some(publication) = ROOT_WRITE_DELAY.with(std::cell::Cell::take) {
            let started = Instant::now();
            std::thread::sleep(publication);
            self.slow_publications
                .lock()
                .push((started, Instant::now()));
        }
        self.group.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.slow_sync();
        self.group.sync_root()
    }
    fn visit_entries(
        &self,
        visitor: &mut dyn FnMut(&std::ffi::OsStr) -> io::Result<()>,
    ) -> io::Result<()> {
        self.group.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.group.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.group.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.group.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::AcqRel);
        if self.gate.armed.swap(false, Ordering::AcqRel) {
            self.gate.pause();
        }
        if let Some(error) = self.read_failure.lock().take() {
            return Err(error);
        }
        self.group.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.group.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, len: u64) -> io::Result<()> {
        self.group.set_len(file, len)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.slow_sync();
        self.group.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.slow_sync();
        self.group.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.closes.fetch_add(1, Ordering::AcqRel);
        self.group.close()
    }
}

struct Fixture {
    node: NodeStore,
    probe: Arc<Probe>,
    memory: Arc<crate::test_utils::TestDiskMemory>,
    admission: Arc<MemoryAdmission>,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn cold() -> Self {
        Self::cold_with(0).await
    }

    /// The cold fixture with `wide` more rows whose long keys fill a
    /// directory leaf each few rows: a requested cycle then has that many
    /// leaves' worth of evacuation steps.
    async fn cold_with(wide: u16) -> Self {
        let directory = crate::test_utils::private_tempdir().unwrap();
        let memory = crate::test_utils::TestDiskMemory::new(32 << 20, 4096);
        let scratch = crate::ScratchDisk::fixture(directory.path(), memory.clone());
        let group = Arc::new(kasumi_kv::backends::InMemoryGroup::new());
        let native = || {
            Arc::new(MemoryAdmission {
                memory: memory.clone(),
                failed: AtomicBool::new(false),
                release_on_denial: Mutex::new(None),
                workspace_gate: ReadGate::default(),
            })
        };
        let first =
            NodeStore::create_with_backend(group.clone(), native(), scratch.clone()).unwrap();
        let transaction = first.body().db.begin_write().unwrap();
        {
            let mut table = transaction.open_table(ROWS).unwrap();
            for i in 0..20_u8 {
                table.insert(&[i][..], &[i; 512][..]).unwrap();
            }
            for i in 0..wide {
                table.insert(&wide_key(i)[..], &[7; 64][..]).unwrap();
            }
        }
        transaction.commit().unwrap();
        let crash = group.crash();
        first.shutdown().await.unwrap();
        drop(first);
        let probe = Arc::new(Probe {
            group: crash,
            reads: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            read_failure: Mutex::new(None),
            gate: ReadGate::default(),
            sync_micros: AtomicU64::new(0),
            syncs: AtomicUsize::new(0),
            slow_publications: Mutex::new(Vec::new()),
        });
        let admission = native();
        let mut inputs = Some(crate::NodeFixtureInputs {
            backend: probe.clone(),
            admission: admission.clone(),
            persistent: None,
            scratch,
        });
        let mut config = crate::test_utils::node_storage_config();
        // Declare the same residency share before the registered opening's
        // construction. Runtime configuration may only use that installed cap.
        config.cache.byte_limit = 8 << 20;
        let startup = crate::RegisteredNodeStartup::prepare_fixture(
            &mut inputs,
            crate::test_utils::NODE_STORE_ID,
            true,
            config,
        )
        .unwrap();
        let node = NodeStore::finish_registered_startup(startup).unwrap();
        // Verification may have cached pages. Release that lookup ownership
        // before the original cold-fixture activation below.
        node.configure_cache(kasumi_kv::CacheConfig { byte_limit: 0 })
            .unwrap();
        node.configure_cache(kasumi_kv::CacheConfig {
            byte_limit: 8 << 20,
        })
        .unwrap();
        Self {
            node,
            probe,
            memory,
            admission,
            _directory: directory,
        }
    }

    async fn wait(&self, condition: impl Fn(CacheWorkerStatus) -> bool) -> CacheWorkerStatus {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let status = self.node.cache_worker_status();
                if condition(status) {
                    return status;
                }
                assert!(!status.failed, "cache worker failed: {status:?}");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "cache worker did not reach the expected state: {:?}; native={:?}; reads={}; memory={:?}",
                self.node.cache_worker_status(),
                self.node.cache_warmup_status(),
                self.probe.reads.load(Ordering::Acquire),
                self.memory.snapshot(),
            )
        })
    }

    fn exhaust_memory(&self) -> crate::DiskMemoryLease {
        let memory = self.memory.snapshot();
        let headroom = (32_u64 << 20) - memory.bookkeeping_bytes - memory.used_bytes;
        let overhead = crate::test_utils::TestDiskMemory::required_reservation_bytes(0).unwrap();
        self.memory
            .clone()
            .reserve_installed(headroom - overhead)
            .unwrap()
    }
}

/// A key long enough that a directory leaf holds only a few of them.
fn wide_key(index: u16) -> Vec<u8> {
    let mut key = vec![0xA5; 1024];
    key[..2].copy_from_slice(&index.to_be_bytes());
    key
}

#[tokio::test]
async fn automatic_warmer_stays_dormant_until_acknowledged_activation() {
    let fixture = Fixture::cold().await;
    assert!(fixture.node.activate_cache_warming().is_err());
    fixture.node.prepare_cache_warming().await.unwrap();
    let reads = fixture.probe.reads.load(Ordering::Acquire);
    let memory = fixture.memory.snapshot();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let status = fixture.node.cache_worker_status();
    assert!(status.started);
    assert!(!status.active);
    assert_eq!(status.steps, 0);
    assert_eq!(fixture.probe.reads.load(Ordering::Acquire), reads);
    assert_eq!(fixture.memory.snapshot(), memory);
    fixture.node.shutdown().await.unwrap();
    assert!(fixture.node.activate_cache_warming().is_err());
}

#[test]
fn automatic_warmer_rejects_a_runtime_lost_before_handoff() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = runtime.block_on(async {
        let fixture = Fixture::cold().await;
        fixture.node.prepare_cache_warming().await.unwrap();
        tokio::task::yield_now().await;
        fixture
    });
    let reads = fixture.probe.reads.load(Ordering::Acquire);
    drop(runtime);
    assert!(
        fixture
            .node
            .activate_cache_warming()
            .unwrap_err()
            .to_string()
            .contains("terminated before activation")
    );
    assert!(!fixture.node.cache_worker_status().active);
    assert!(fixture.node.cache_worker_status().failed);
    assert_eq!(fixture.probe.reads.load(Ordering::Acquire), reads);
    let recovery = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let failure = recovery.block_on(fixture.node.shutdown()).unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn automatic_warmer_fills_cold_reopen_without_foreground_reads() {
    let fixture = Fixture::cold().await;
    assert!(!fixture.node.cache_worker_status().started);
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    let status = fixture
        .wait(|s| {
            s.native
                .is_some_and(|n| n.state == CacheWarmupState::Resident)
        })
        .await;
    assert!(status.progress.unwrap().fully_resident);
    assert!(status.work > 0);
    let before = fixture.probe.reads.load(Ordering::Acquire);
    let transaction = fixture.node.body().db.begin_read().unwrap();
    let table = transaction.open_table(ROWS).unwrap();
    for i in 0..20_u8 {
        assert_eq!(table.get(&[i][..]).unwrap().unwrap().value(), &[i; 512]);
    }
    drop(table);
    drop(transaction);
    assert_eq!(fixture.probe.reads.load(Ordering::Acquire), before);
    fixture.node.shutdown().await.unwrap();
    assert!(fixture.node.prepare_cache_warming().await.is_err());
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn automatic_warmer_parks_cache_limited_pass_and_resumes_after_budget_growth() {
    let fixture = Fixture::cold().await;
    fixture
        .node
        .configure_cache(kasumi_kv::CacheConfig { byte_limit: 4096 })
        .unwrap();
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    let parked = fixture
        .wait(|s| {
            s.native
                .is_some_and(|n| n.state == CacheWarmupState::CapacityLimited)
        })
        .await;
    assert!(!parked.native.unwrap().provider_limited);
    let reads = fixture.probe.reads.load(Ordering::Acquire);
    let extra = fixture.memory.clone().reserve_installed(4096).unwrap();
    drop(extra);
    fixture.wait(|s| s.steps >= parked.steps + 3).await;
    assert_eq!(fixture.node.cache_worker_status().work, parked.work);
    assert_eq!(fixture.probe.reads.load(Ordering::Acquire), reads);
    fixture
        .node
        .configure_cache(kasumi_kv::CacheConfig {
            byte_limit: 8 << 20,
        })
        .unwrap();
    fixture
        .wait(|s| {
            s.native
                .is_some_and(|n| n.state == CacheWarmupState::Resident)
        })
        .await;
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn automatic_warmer_retries_blocked_item_after_shared_pressure_releases() {
    let fixture = Fixture::cold().await;
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    // The fixed worker charge already exists. A current-thread runtime has
    // not polled its supervisor before this synchronous external reservation.
    let pressure = fixture.exhaust_memory();
    let parked = fixture
        .wait(|s| s.native.is_some_and(provider_limited))
        .await;
    let reads = fixture.probe.reads.load(Ordering::Acquire);
    fixture.wait(|s| s.steps >= parked.steps + 2).await;
    assert_eq!(fixture.node.cache_worker_status().work, parked.work);
    assert_eq!(fixture.probe.reads.load(Ordering::Acquire), reads);
    drop(pressure);
    fixture
        .wait(|s| {
            s.native
                .is_some_and(|n| n.state == CacheWarmupState::Resident)
        })
        .await;
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn automatic_warmer_recovers_pressure_released_inside_the_denied_step() {
    let fixture = Fixture::cold().await;
    fixture.node.prepare_cache_warming().await.unwrap();
    let pressure = fixture.exhaust_memory();
    *fixture.admission.release_on_denial.lock() = Some(pressure);
    fixture.node.activate_cache_warming().unwrap();
    fixture
        .wait(|s| {
            s.native
                .is_some_and(|n| n.state == CacheWarmupState::Resident)
        })
        .await;
    assert!(fixture.admission.release_on_denial.lock().is_none());
    // No second external release or explicit retry request occurs. Sampling
    // only after the denied step would have missed the available capacity.
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn automatic_warmer_start_denial_spawns_nothing_and_can_retry() {
    let fixture = Fixture::cold().await;
    let pressure = fixture.exhaust_memory();
    let reads = fixture.probe.reads.load(Ordering::Acquire);
    assert!(fixture.node.prepare_cache_warming().await.is_err());
    assert!(!fixture.node.cache_worker_status().started);
    assert_eq!(fixture.probe.reads.load(Ordering::Acquire), reads);
    drop(pressure);
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    fixture
        .wait(|s| {
            s.native
                .is_some_and(|n| n.state == CacheWarmupState::Resident)
        })
        .await;
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test]
async fn automatic_warmer_shutdown_cancellation_retains_blocked_child_and_charge() {
    let fixture = Fixture::cold().await;
    let _release_on_panic = ReleaseGate(&fixture.probe.gate);
    fixture.probe.gate.armed.store(true, Ordering::Release);
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        fixture.probe.gate.entered.notified(),
    )
    .await
    .unwrap();
    let before = fixture.memory.snapshot().used_bytes;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fixture.node.shutdown())
            .await
            .is_err()
    );
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 0);
    assert!(fixture.memory.snapshot().used_bytes >= before);
    assert!(fixture.node.prepare_cache_warming().await.is_err());
    fixture.probe.gate.release();
    tokio::time::timeout(Duration::from_secs(10), fixture.node.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
    fixture.node.shutdown().await.unwrap();
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn automatic_warmer_retains_original_native_failure_through_shutdown() {
    let fixture = Fixture::cold().await;
    *fixture.probe.read_failure.lock() = Some(io::Error::other("automatic cache read failure"));
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    fixture.wait(|s| s.failed).await;
    let first = fixture.node.shutdown().await.unwrap_err();
    assert!(first.to_string().contains("automatic cache read failure"));
    let second = fixture.node.shutdown().await.unwrap_err();
    assert_eq!(first.to_string(), second.to_string());
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn automatic_warmer_stop_between_check_and_admission_drains_cleanly() {
    let fixture = Fixture::cold().await;
    let gate = Arc::new(ReadGate::default());
    let _release_on_panic = ReleaseGate(&gate);
    let before = gate.clone();
    fixture
        .node
        .body()
        .db
        .before_registered_admission_for_test(Box::new(move || before.pause()));
    fixture.node.prepare_cache_warming().await.unwrap();
    let reads = fixture.probe.reads.load(Ordering::Acquire);
    fixture.node.activate_cache_warming().unwrap();
    tokio::time::timeout(Duration::from_secs(10), gate.entered.notified())
        .await
        .unwrap();

    // The child passed its first stopped check, but has not acquired the
    // registered opening. Shutdown must seal and wait for that exact child.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fixture.node.shutdown())
            .await
            .is_err()
    );
    assert!(fixture.node.body().db.is_stopped());
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 0);
    assert!(matches!(
        fixture.node.body().db.warm_cache_if_needed(1),
        Err(kasumi_kv::StorageError::DatabaseClosed)
    ));
    assert_eq!(
        fixture
            .node
            .body()
            .db
            .queue_registered_read()
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::BrokenPipe
    );
    gate.release();
    tokio::time::timeout(Duration::from_secs(10), fixture.node.shutdown())
        .await
        .unwrap()
        .unwrap();
    let status = fixture.node.cache_worker_status();
    assert!(status.stopped && !status.failed, "{status:?}");
    assert_eq!(fixture.probe.reads.load(Ordering::Acquire), reads);
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
    fixture.node.shutdown().await.unwrap();
}

#[derive(Debug)]
struct NativeBrokenPipe(Arc<()>);
impl std::fmt::Display for NativeBrokenPipe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("original native broken pipe")
    }
}
impl std::error::Error for NativeBrokenPipe {}

#[tokio::test]
async fn automatic_warmer_preserves_native_broken_pipe_during_stop() {
    let fixture = Fixture::cold().await;
    let _release_on_panic = ReleaseGate(&fixture.probe.gate);
    let original = Arc::new(());
    *fixture.probe.read_failure.lock() = Some(io::Error::new(
        io::ErrorKind::BrokenPipe,
        NativeBrokenPipe(original.clone()),
    ));
    fixture.probe.gate.armed.store(true, Ordering::Release);
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        fixture.probe.gate.entered.notified(),
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), fixture.node.shutdown())
            .await
            .is_err()
    );
    assert!(fixture.node.body().db.is_stopped());
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 0);
    fixture.probe.gate.release();
    let first = tokio::time::timeout(Duration::from_secs(10), fixture.node.shutdown())
        .await
        .unwrap()
        .unwrap_err();
    // The native failure fenced admission before close. Physical closure is
    // proved, but its failed shutdown observation and undisposed owner must
    // remain retained; a concurrent stop cannot turn this into a clean drain.
    assert_eq!(first.completion(), DrainCompletion::Retained);
    {
        let opening = crate::RegisteredNodeOpening::retained(
            fixture.memory.clone(),
            fixture.node.registered_opening_id().unwrap(),
        )
        .expect("the original failed opening remains owned");
        assert!(opening.children_retired());
        let report = opening.report();
        let engine = report.engine();
        assert_eq!(engine.phase(), kasumi_kv::DatabaseOpenPhase::Closing);
        assert_eq!(
            engine.settlement(),
            kasumi_kv::DatabaseOpenSettlement::DrainedWithFailure
        );
        assert_eq!(
            engine.native_disposition(),
            kasumi_kv::BackendNativeDisposition::Drained
        );
        assert!(!engine.disposal().complete());
    }
    let native_error = first
        .issues()
        .iter()
        .flat_map(|issue| issue.error().chain())
        .filter_map(|error| error.downcast_ref::<io::Error>())
        .find(|error| {
            error
                .get_ref()
                .is_some_and(|original| original.is::<NativeBrokenPipe>())
        })
        .expect("the exact native I/O error must survive a concurrent stop");
    assert_eq!(native_error.kind(), io::ErrorKind::BrokenPipe);
    assert!(Arc::ptr_eq(
        &native_error
            .get_ref()
            .unwrap()
            .downcast_ref::<NativeBrokenPipe>()
            .unwrap()
            .0,
        &original
    ));
    assert!(fixture.node.cache_worker_status().failed);
    let second = fixture.node.shutdown().await.unwrap_err();
    assert_eq!(second.completion(), DrainCompletion::Retained);
    assert_eq!(first.issues().len(), second.issues().len());
    assert!(
        first
            .issues()
            .iter()
            .zip(second.issues())
            .all(|(first, second)| { kasumi_types::drain::DrainIssueRef::ptr_eq(first, second) })
    );
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
}

/// One row on pages written after this opening. The first write of a lifetime
/// rolls a fresh arena, so the cold fixture's pages become older than every
/// file a requested cycle writes.
fn write_row(node: &NodeStore, key: u8) {
    let transaction = node.body().db.begin_write().unwrap();
    {
        let mut table = transaction.open_table(ROWS).unwrap();
        table.insert(&[key][..], &[key; 512][..]).unwrap();
    }
    transaction.commit().unwrap();
}

/// `write_row` as a slow commit: its root publication takes `publication`
/// longer (`Probe::write_root`). Throughout it the commit holds the write gate
/// and the commit gate, which a worker's warm step waits for, but not the KV
/// core lock, which reads take.
fn write_row_publishing_slowly(node: &NodeStore, key: u8, publication: Duration) {
    let transaction = node.body().db.begin_write().unwrap();
    {
        let mut table = transaction.open_table(ROWS).unwrap();
        table.insert(&[key][..], &[key; 512][..]).unwrap();
    }
    ROOT_WRITE_DELAY.with(|slow| slow.set(Some(publication)));
    let committed = transaction.commit();
    ROOT_WRITE_DELAY.with(|slow| slow.set(None));
    committed.unwrap();
}

fn assert_rows(node: &NodeStore, keys: impl Iterator<Item = u8>) {
    let transaction = node.body().db.begin_read().unwrap();
    let table = transaction.open_table(ROWS).unwrap();
    for key in keys {
        assert_eq!(table.get(&[key][..]).unwrap().unwrap().value(), &[key; 512]);
    }
}

/// Wait for the storage cycle, failing on a failed worker or a timeout.
async fn wait_storage(
    fixture: &Fixture,
    condition: impl Fn(&kasumi_kv::StorageMaintenanceStatus) -> bool,
) -> kasumi_kv::StorageMaintenanceStatus {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let storage = fixture.node.storage_maintenance_status().unwrap();
            if condition(&storage) {
                return storage;
            }
            let worker = fixture.node.cache_worker_status();
            assert!(!worker.failed, "cache worker failed: {worker:?}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "storage maintenance did not reach the expected state: {:?}; worker={:?}",
            fixture.node.storage_maintenance_status(),
            fixture.node.cache_worker_status(),
        )
    })
}

fn completed_first_cycle(storage: &kasumi_kv::StorageMaintenanceStatus) -> bool {
    storage.cycle == 1 && storage.phase == kasumi_kv::StorageCompactionPhase::Idle
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_storage_status_is_copied_without_waiting_for_the_kv_core_lock() {
    let fixture = Fixture::cold().await;
    assert!(fixture.node.published_storage_status().is_none());
    write_row(&fixture.node, 100);
    fixture.node.request_storage_compaction().unwrap();
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    wait_storage(&fixture, completed_first_cycle).await;
    let published = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(published) = fixture.node.published_storage_status()
                && completed_first_cycle(&published.status)
                && published.census.is_some()
            {
                return published;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the worker publishes the completed cycle");
    let census = published.census.unwrap();
    assert!(census.measured_at <= published.published_at);
    assert_eq!(census.segment_files, published.status.segment_files);
    // Database work reserves its workspace while it holds the KV core lock,
    // as a running maintenance step does: pause the next reservation there.
    fixture
        .admission
        .workspace_gate
        .armed
        .store(true, Ordering::Release);
    let entered = fixture.admission.workspace_gate.entered.notified();
    let node = fixture.node.clone();
    let writer = std::thread::spawn(move || write_row(&node, 101));
    tokio::time::timeout(Duration::from_secs(10), entered)
        .await
        .expect("the commit reached its workspace reservation");
    let started = Instant::now();
    let copy = fixture.node.published_storage_status().unwrap();
    let writes = fixture.node.background_write_status();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(completed_first_cycle(&copy.status));
    assert!(copy.census.is_some());
    assert!(copy.published_at >= published.published_at);
    // The background-work figures come with the same copy, and the paced
    // write counters from atomics.
    assert!(copy.background.maintenance_steps >= 1, "{copy:?}");
    assert!(
        copy.background.maintenance_time > Duration::ZERO,
        "{copy:?}"
    );
    assert_eq!(copy.background.writes, writes);
    fixture.admission.workspace_gate.release();
    writer.join().unwrap();
    assert_rows(&fixture.node, (0..20).chain([100, 101]));
    // Every read and write begin and every database call takes the opening's
    // state (a read begin holds it while its snapshot waits for the KV core
    // lock); neither the copy nor the write counters need that state.
    let (entered, held) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let node = fixture.node.clone();
    let holder = std::thread::spawn(move || {
        node.hold_maintenance_state_for_test(|| {
            entered.send(()).unwrap();
            // Never outlive a stuck observer: release on our own deadline.
            let _ = released.recv_timeout(Duration::from_secs(20));
        })
    });
    held.recv_timeout(Duration::from_secs(10)).unwrap();
    let started = Instant::now();
    let copy = fixture.node.published_storage_status().unwrap();
    let writes = fixture.node.background_write_status();
    let waited = started.elapsed();
    release.send(()).unwrap();
    holder.join().unwrap();
    assert!(waited < Duration::from_secs(2), "{waited:?}");
    assert_eq!(copy.background.writes, writes);
    assert!(copy.background.maintenance_steps >= 1, "{copy:?}");
    assert!(!fixture.node.cache_worker_status().failed);
    fixture.node.shutdown().await.unwrap();
}

#[test]
fn a_census_survives_an_unmeasured_cycle_and_keeps_its_first_publication_time() {
    let start = Instant::now();
    let measured = kasumi_kv::StorageMaintenanceStatus {
        measured: true,
        segment_files: 3,
        segment_bytes: 300,
        arena_files: 1,
        arena_bytes: 10,
        ..Default::default()
    };
    let first = PublishedStorageStatus::next(None, measured, start);
    assert_eq!(first.census.unwrap().measured_at, start);
    let later = start + Duration::from_secs(5);
    let same = PublishedStorageStatus::next(Some(first), measured, later);
    assert_eq!(same.census.unwrap().measured_at, start);
    assert_eq!(same.published_at, later);
    let evacuating = kasumi_kv::StorageMaintenanceStatus {
        phase: kasumi_kv::StorageCompactionPhase::Evacuating,
        ..Default::default()
    };
    let cycle = PublishedStorageStatus::next(Some(same), evacuating, later);
    assert!(!cycle.status.measured);
    assert_eq!(cycle.census, same.census);
    let remeasured = kasumi_kv::StorageMaintenanceStatus {
        segment_files: 2,
        ..measured
    };
    let newest = start + Duration::from_secs(9);
    let next = PublishedStorageStatus::next(Some(cycle), remeasured, newest);
    assert_eq!(next.census.unwrap().measured_at, newest);
    assert_eq!(next.census.unwrap().segment_files, 2);
}

#[tokio::test]
async fn worker_drives_storage_maintenance_and_reports_progress() {
    let fixture = Fixture::cold().await;
    write_row(&fixture.node, 100);
    let before = fixture.node.storage_maintenance_status().unwrap();
    assert_eq!(
        (before.cycle, before.phase),
        (0, kasumi_kv::StorageCompactionPhase::Idle)
    );
    assert!(fixture.probe.group.exists(GroupFile::directory(1)).unwrap());
    fixture.node.request_storage_compaction().unwrap();
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    let storage = wait_storage(&fixture, completed_first_cycle).await;
    // The worker alone drove the cycle: the pre-reopen arena was evacuated,
    // proved unreachable and unlinked, and nothing is left recorded.
    assert!(storage.reclaimed_files_total >= 1, "{storage:?}");
    assert_eq!(storage.garbage_files, 0);
    assert_eq!(storage.reclaim_invalidations_total, 0);
    assert_eq!(
        storage.capacity_deferrals_total + storage.rejected_deferrals_total,
        0
    );
    assert!(!fixture.probe.group.exists(GroupFile::directory(1)).unwrap());
    let worker = fixture.node.cache_worker_status();
    assert!(!worker.failed);
    assert!(
        worker.maintenance_steps > 0 && worker.maintenance_units > 0,
        "{worker:?}"
    );
    assert!(matches!(
        worker.last_maintenance,
        Some(kasumi_kv::MaintenanceStep::Ran(_))
    ));
    assert_rows(&fixture.node, (0..20).chain([100]));
    // Once the cycle is done, nothing is due and the worker reports idle steps.
    let idle = fixture
        .wait(|s| {
            matches!(
                s.last_maintenance,
                Some(kasumi_kv::MaintenanceStep::Ran(progress)) if progress.idle
            )
        })
        .await;
    assert!(!idle.failed);
    assert_eq!(fixture.node.storage_maintenance_status().unwrap().cycle, 1);
    fixture.node.shutdown().await.unwrap();
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn worker_backs_off_on_busy_and_deferral() {
    let fixture = Fixture::cold().await;
    write_row(&fixture.node, 100);
    // A held writer makes every maintenance step report Busy without waiting
    // on the write gate; the worker keeps iterating and does not fail.
    let writer = fixture.node.body().db.begin_write().unwrap();
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    let busy = fixture.wait(|s| s.maintenance_busy >= 3).await;
    assert!(!busy.failed);
    assert_eq!(
        busy.last_maintenance,
        Some(kasumi_kv::MaintenanceStep::Busy)
    );
    let ran = busy.maintenance_steps;
    writer.abort().unwrap();
    fixture.wait(|s| s.maintenance_steps > ran).await;

    // Shared memory pressure refuses the requested cycle's workspace: a
    // capacity deferral, never a worker or database failure.
    let pressure = fixture.exhaust_memory();
    fixture.node.request_storage_compaction().unwrap();
    let deferred = wait_storage(&fixture, |storage| storage.capacity_deferrals_total > 0).await;
    assert_eq!(
        deferred.last_deferral,
        Some(kasumi_kv::MaintenanceDeferral::Capacity)
    );
    // The engine publishes the step before the worker records it in the same
    // iteration; the steps of the backoff keep reporting the deferral.
    let worker = fixture
        .wait(|status| {
            matches!(
                status.last_maintenance,
                Some(kasumi_kv::MaintenanceStep::Ran(progress)) if progress.deferred.is_some()
            )
        })
        .await;
    assert!(!worker.failed, "{worker:?}");
    drop(pressure);
    // An explicit request also clears the step backoff; the cycle resumes
    // from its kept cursors and completes.
    fixture.node.request_storage_compaction().unwrap();
    let storage = wait_storage(&fixture, completed_first_cycle).await;
    assert!(storage.reclaimed_files_total >= 1, "{storage:?}");
    assert_rows(&fixture.node, (0..20).chain([100]));
    fixture.node.shutdown().await.unwrap();
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn stop_and_drain_unaffected_by_maintenance() {
    let fixture = Fixture::cold().await;
    write_row(&fixture.node, 100);
    fixture.node.request_storage_compaction().unwrap();
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    fixture.wait(|s| s.maintenance_steps >= 1).await;
    // Shutdown drains the worker mid-cycle; no maintenance step outlives it.
    tokio::time::timeout(Duration::from_secs(10), fixture.node.shutdown())
        .await
        .unwrap()
        .unwrap();
    let status = fixture.node.cache_worker_status();
    assert!(status.stopped && !status.failed, "{status:?}");
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
    assert!(fixture.node.storage_maintenance_status().is_err());
    let steps = status.maintenance_steps + status.maintenance_busy;
    tokio::time::sleep(Duration::from_millis(30)).await;
    let later = fixture.node.cache_worker_status();
    assert_eq!(later.maintenance_steps + later.maintenance_busy, steps);
    fixture.node.shutdown().await.unwrap();
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);

    // The persisted cycle resumes after reopen and finishes from its record.
    let reopened = NodeStore::open_with_backend(
        fixture.probe.group.crash(),
        Arc::new(MemoryAdmission {
            memory: fixture.memory.clone(),
            failed: AtomicBool::new(false),
            release_on_denial: Mutex::new(None),
            workspace_gate: ReadGate::default(),
        }),
        fixture.node.scratch_disk().clone(),
    )
    .unwrap_or_else(|_| panic!("reopen after a drained maintenance worker failed"));
    let resumed = reopened.storage_maintenance_status().unwrap();
    assert!(resumed.cycle <= 1, "{resumed:?}");
    reopened.request_storage_compaction().unwrap();
    let mut cycle_done = false;
    for _ in 0..100_000 {
        let step = reopened
            .body()
            .db
            .run_maintenance(kasumi_kv::MaintenanceBudget {
                units: 64,
                mutations: 1,
            })
            .unwrap();
        let kasumi_kv::MaintenanceStep::Ran(progress) = step else {
            panic!("no writer holds the gate");
        };
        assert_eq!(progress.deferred, None);
        let storage = reopened.storage_maintenance_status().unwrap();
        if storage.cycle >= 1 && storage.phase == kasumi_kv::StorageCompactionPhase::Idle {
            cycle_done = true;
            break;
        }
    }
    assert!(cycle_done);
    assert_rows(&reopened, (0..20).chain([100]));
    reopened.shutdown().await.unwrap();
}

#[test]
fn worker_delay_follows_warm_and_maintenance_outcomes() {
    let ran = |idle: bool, units: usize, deferred: Option<kasumi_kv::MaintenanceDeferral>| {
        Some(kasumi_kv::MaintenanceStep::Ran(
            kasumi_kv::MaintenanceProgress {
                units,
                idle,
                deferred,
                ..Default::default()
            },
        ))
    };
    let status = |last_maintenance, maintenance_pending| CacheWorkerStatus {
        last_maintenance,
        maintenance_pending,
        ..Default::default()
    };
    let now = Instant::now();
    // Undeferred maintenance progress keeps the worker running.
    assert_eq!(
        next_delay(&status(ran(false, 7, None), true), now),
        RUNNING_DELAY
    );
    // Nothing due, a deferral backoff, or a step that spent nothing: idle.
    assert_eq!(
        next_delay(&status(ran(true, 3, None), false), now),
        IDLE_DELAY
    );
    assert_eq!(
        next_delay(
            &status(
                ran(false, 0, Some(kasumi_kv::MaintenanceDeferral::Capacity)),
                true
            ),
            now
        ),
        IDLE_DELAY
    );
    assert_eq!(
        next_delay(&status(ran(false, 0, None), true), now),
        IDLE_DELAY
    );
    // A held write gate retries soon only while maintenance has work.
    let busy = Some(kasumi_kv::MaintenanceStep::Busy);
    assert_eq!(next_delay(&status(busy, true), now), BUSY_DELAY);
    assert_eq!(next_delay(&status(busy, false), now), IDLE_DELAY);
    assert_eq!(next_delay(&status(None, false), now), IDLE_DELAY);
    // Warming runs again soon, unless an unfinished attempt was replaced
    // within the restart window; maintenance progress still runs at once.
    let warming = CacheWorkerStatus {
        progress: Some(kasumi_kv::CacheWarmup {
            work: 1,
            complete: false,
            fully_resident: false,
        }),
        ..Default::default()
    };
    assert_eq!(next_delay(&warming, now), RUNNING_DELAY);
    let restarted = CacheWorkerStatus {
        last_warm_restart: Some(now),
        ..warming
    };
    assert_eq!(next_delay(&restarted, now), IDLE_DELAY);
    assert_eq!(
        next_delay(&restarted, now + RESTART_WINDOW - Duration::from_millis(1)),
        IDLE_DELAY
    );
    assert_eq!(next_delay(&restarted, now + RESTART_WINDOW), RUNNING_DELAY);
    let maintaining = CacheWorkerStatus {
        last_maintenance: ran(false, 7, None),
        maintenance_pending: true,
        ..restarted
    };
    assert_eq!(next_delay(&maintaining, now), RUNNING_DELAY);
}

#[test]
fn worker_counts_only_unfinished_attempts_that_were_replaced() {
    let native = |state, attempt| CacheWarmupStatus {
        state,
        complete: state == CacheWarmupState::Resident,
        provider_limited: false,
        cumulative_work: 0,
        attempt_generation: attempt,
        byte_limit: 1 << 20,
    };
    let start = Instant::now();
    let mut status = CacheWorkerStatus::default();
    observe_native(
        &mut status,
        native(CacheWarmupState::Running, Some(7)),
        start,
    );
    observe_native(
        &mut status,
        native(CacheWarmupState::Running, Some(7)),
        start,
    );
    assert_eq!((status.warm_restarts, status.last_warm_restart), (0, None));
    // A publication replaced the unfinished attempt 7.
    let later = start + Duration::from_secs(1);
    observe_native(
        &mut status,
        native(CacheWarmupState::Running, Some(9)),
        later,
    );
    assert_eq!(
        (status.warm_restarts, status.last_warm_restart),
        (1, Some(later))
    );
    // A completed attempt followed by a new one is not a restart.
    observe_native(
        &mut status,
        native(CacheWarmupState::Resident, Some(9)),
        later,
    );
    observe_native(
        &mut status,
        native(CacheWarmupState::Running, Some(12)),
        later + Duration::from_secs(1),
    );
    assert_eq!(
        (status.warm_restarts, status.last_warm_restart),
        (1, Some(later))
    );
    assert_eq!(
        status.native,
        Some(native(CacheWarmupState::Running, Some(12)))
    );
}

fn ran_step(units: usize) -> Option<kasumi_kv::MaintenanceStep> {
    Some(kasumi_kv::MaintenanceStep::Ran(
        kasumi_kv::MaintenanceProgress {
            units,
            ..Default::default()
        },
    ))
}

/// A worker whose last maintenance step made progress and kept the database
/// for `held`, with or without foreground operations around it.
fn maintaining_status(held: Duration, foreground_active: bool) -> CacheWorkerStatus {
    CacheWorkerStatus {
        last_maintenance: ran_step(7),
        maintenance_pending: true,
        last_database_time: held,
        foreground_active,
        ..Default::default()
    }
}

fn published(status: kasumi_kv::StorageMaintenanceStatus) -> Option<PublishedStorageStatus> {
    Some(PublishedStorageStatus::next(None, status, Instant::now()))
}

#[test]
fn worker_keeps_its_own_pace_while_no_foreground_operation_is_active() {
    let now = Instant::now();
    // However long the last iteration kept the database: nobody waited.
    for held in [
        Duration::ZERO,
        Duration::from_millis(3),
        Duration::from_millis(80),
        Duration::from_secs(30),
    ] {
        assert_eq!(
            next_delay(&maintaining_status(held, false), now),
            RUNNING_DELAY
        );
        let busy = CacheWorkerStatus {
            last_maintenance: Some(kasumi_kv::MaintenanceStep::Busy),
            ..maintaining_status(held, false)
        };
        assert_eq!(next_delay(&busy, now), BUSY_DELAY);
        let idle = CacheWorkerStatus {
            last_maintenance: ran_step(0),
            maintenance_pending: false,
            ..maintaining_status(held, false)
        };
        assert_eq!(next_delay(&idle, now), IDLE_DELAY);
    }
}

#[test]
fn worker_yields_the_foreground_share_of_the_time_it_kept_the_database() {
    use crate::background_pace::{FOREGROUND_SHARE, MAX_PACED_DELAY};
    let now = Instant::now();
    // At least four times the time kept, so at most a fifth of the time.
    for held in [3, 10, 50, 100, 250] {
        let held = Duration::from_millis(held);
        let delay = next_delay(&maintaining_status(held, true), now);
        assert_eq!(delay, held * FOREGROUND_SHARE);
        assert!(held.as_secs_f64() / (held + delay).as_secs_f64() <= 0.2 + 1e-9);
    }
    // The floor is the worker's own pace and the cap bounds one pause.
    assert_eq!(
        next_delay(&maintaining_status(Duration::from_micros(40), true), now),
        RUNNING_DELAY
    );
    for held in [Duration::from_millis(251), Duration::from_secs(90)] {
        assert_eq!(
            next_delay(&maintaining_status(held, true), now),
            MAX_PACED_DELAY
        );
    }
    // Warming alone is paced like maintenance.
    let warming = CacheWorkerStatus {
        progress: Some(kasumi_kv::CacheWarmup {
            work: 1,
            complete: false,
            fully_resident: false,
        }),
        last_database_time: Duration::from_millis(20),
        foreground_active: true,
        ..Default::default()
    };
    assert_eq!(next_delay(&warming, now), Duration::from_millis(80));
    // Busy and idle iterations keep their pauses unless the iteration kept
    // the database for more than a quarter of them: the pause never shrinks.
    let busy = |held| CacheWorkerStatus {
        last_maintenance: Some(kasumi_kv::MaintenanceStep::Busy),
        ..maintaining_status(held, true)
    };
    assert_eq!(next_delay(&busy(Duration::from_millis(2)), now), BUSY_DELAY);
    assert_eq!(
        next_delay(&busy(Duration::from_millis(50)), now),
        Duration::from_millis(200)
    );
    let idle = |held| CacheWorkerStatus {
        last_maintenance: ran_step(0),
        maintenance_pending: false,
        ..maintaining_status(held, true)
    };
    assert_eq!(
        next_delay(&idle(Duration::from_millis(50)), now),
        IDLE_DELAY
    );
    assert_eq!(
        next_delay(&idle(Duration::from_millis(100)), now),
        Duration::from_millis(400)
    );
    assert_eq!(
        next_delay(&idle(Duration::from_secs(3)), now),
        MAX_PACED_DELAY
    );
    // A deferral's backoff is an idle pause too.
    let deferred = CacheWorkerStatus {
        last_maintenance: Some(kasumi_kv::MaintenanceStep::Ran(
            kasumi_kv::MaintenanceProgress {
                deferred: Some(kasumi_kv::MaintenanceDeferral::Capacity),
                ..Default::default()
            },
        )),
        ..maintaining_status(Duration::from_millis(1), true)
    };
    assert_eq!(next_delay(&deferred, now), IDLE_DELAY);
}

#[test]
fn urgent_maintenance_does_not_yield_to_foreground_operations() {
    let now = Instant::now();
    let held = Duration::from_millis(40);
    let paced = Duration::from_millis(160);
    let storage = |measured, bytes: u64, retained: u64| kasumi_kv::StorageMaintenanceStatus {
        phase: kasumi_kv::StorageCompactionPhase::Evacuating,
        measured,
        segment_bytes: bytes - (1 << 20),
        arena_bytes: 1 << 20,
        snapshot_retained_bytes: retained,
        trigger_bytes: 300 << 20,
        cycles_completed: 4,
        ..Default::default()
    };
    let with = |status| CacheWorkerStatus {
        storage: published(status),
        ..maintaining_status(held, true)
    };
    // No published status, or retained bytes below twice the trigger.
    let unpublished = maintaining_status(held, true);
    assert!(!unpublished.maintenance_urgent());
    assert_eq!(next_delay(&unpublished, now), paced);
    let below = with(storage(true, (600 << 20) - 1, 0));
    assert!(!below.maintenance_urgent());
    assert_eq!(next_delay(&below, now), paced);
    // The current census found twice the bytes that begin a cycle.
    let behind = with(storage(true, 600 << 20, 0));
    assert!(behind.maintenance_urgent());
    assert_eq!(next_delay(&behind, now), RUNNING_DELAY);
    assert!(behind.published().unwrap().background.maintenance_urgent);
    // Files kept only for pinned snapshots are not compaction's to free.
    let pinned = with(storage(true, 700 << 20, (100 << 20) + 1));
    assert!(!pinned.maintenance_urgent());
    assert_eq!(next_delay(&pinned, now), paced);
    // A census that was invalidated proves nothing about now, and neither
    // does the census from before a cycle once Packing has the new baseline
    // and trigger; through Reclaiming the two still belong together.
    let stale = with(storage(false, 900 << 20, 0));
    assert!(!stale.maintenance_urgent());
    assert_eq!(next_delay(&stale, now), paced);
    let packing = with(kasumi_kv::StorageMaintenanceStatus {
        phase: kasumi_kv::StorageCompactionPhase::Packing,
        ..storage(true, 900 << 20, 0)
    });
    assert!(!packing.maintenance_urgent());
    assert_eq!(next_delay(&packing, now), paced);
    for phase in [
        kasumi_kv::StorageCompactionPhase::Idle,
        kasumi_kv::StorageCompactionPhase::Reclaiming,
    ] {
        let comparable = with(kasumi_kv::StorageMaintenanceStatus {
            phase,
            ..storage(true, 600 << 20, 0)
        });
        assert!(comparable.maintenance_urgent(), "{phase:?}");
    }
    // A store with no trigger yet is not behind one.
    let untriggered = with(kasumi_kv::StorageMaintenanceStatus {
        trigger_bytes: 0,
        ..storage(true, 900 << 20, 0)
    });
    assert!(!untriggered.maintenance_urgent());
    // A capacity deferral of the active cycle, until a cycle completes.
    let deferred = CacheWorkerStatus {
        capacity_deferred_cycle: Some(4),
        ..with(storage(false, 100 << 20, 0))
    };
    assert!(deferred.maintenance_urgent());
    assert_eq!(next_delay(&deferred, now), RUNNING_DELAY);
    let completed = CacheWorkerStatus {
        capacity_deferred_cycle: Some(3),
        ..deferred
    };
    assert!(!completed.maintenance_urgent());
    assert_eq!(next_delay(&completed, now), paced);
    // Urgency speeds maintenance that makes progress, nothing else: a
    // worker that only warms, waits for a writer or idles keeps yielding.
    let warming_only = CacheWorkerStatus {
        last_maintenance: ran_step(0),
        maintenance_pending: false,
        progress: Some(kasumi_kv::CacheWarmup {
            work: 1,
            complete: false,
            fully_resident: false,
        }),
        ..behind
    };
    assert!(warming_only.maintenance_urgent());
    assert_eq!(next_delay(&warming_only, now), paced);
    let busy = CacheWorkerStatus {
        last_maintenance: Some(kasumi_kv::MaintenanceStep::Busy),
        ..behind
    };
    assert_eq!(next_delay(&busy, now), paced);
}

#[test]
fn worker_observes_foreground_activity_and_its_own_database_time() {
    let mut status = CacheWorkerStatus::default();
    let ms = Duration::from_millis;
    // The first sample has nothing to compare with.
    observe_iteration(&mut status, ms(1), ms(4), ms(6), Some(10));
    assert!(!status.foreground_active);
    assert_eq!(status.foreground_seen, Some(10));
    assert_eq!((status.warm_time, status.maintenance_time), (ms(1), ms(4)));
    assert_eq!(
        (status.last_database_time, status.longest_database_time),
        (ms(6), ms(6))
    );
    // The counter did not move: nothing else wanted the database.
    observe_iteration(&mut status, ms(2), ms(20), ms(23), Some(10));
    assert!(!status.foreground_active);
    assert_eq!((status.warm_time, status.maintenance_time), (ms(3), ms(24)));
    assert_eq!(
        (status.last_database_time, status.longest_database_time),
        (ms(23), ms(23))
    );
    // It moved: some transaction began, read or committed meanwhile.
    observe_iteration(&mut status, ms(0), ms(3), ms(3), Some(11));
    assert!(status.foreground_active);
    assert_eq!(
        (status.last_database_time, status.longest_database_time),
        (ms(3), ms(23))
    );
    observe_iteration(&mut status, ms(0), ms(3), ms(3), Some(11));
    assert!(!status.foreground_active);
    // An unreadable counter (a stopping database) is not activity, and the
    // sample after it has nothing to compare with either.
    observe_iteration(&mut status, ms(0), ms(0), ms(0), None);
    assert!(!status.foreground_active);
    assert_eq!(status.foreground_seen, None);
    observe_iteration(&mut status, ms(0), ms(0), ms(0), Some(99));
    assert!(!status.foreground_active);
    observe_iteration(&mut status, ms(0), ms(0), ms(0), Some(100));
    assert!(status.foreground_active);
    // The published copy carries the same counters.
    status.maintenance_steps = 5;
    status.maintenance_busy = 2;
    status.warm_restarts = 1;
    status.paced_delays = 3;
    status.paced_delay = ms(480);
    status.storage = published(kasumi_kv::StorageMaintenanceStatus::default());
    let background = status.published().unwrap().background;
    assert_eq!(
        background,
        PublishedBackgroundWork {
            maintenance_steps: 5,
            maintenance_busy: 2,
            warm_restarts: 1,
            warm_time: ms(3),
            maintenance_time: ms(30),
            longest_database_time: ms(23),
            paced_delays: 3,
            paced_delay: ms(480),
            foreground_active: true,
            maintenance_urgent: false,
            writes: BackgroundWriteStatus::default(),
        }
    );
}

#[test]
fn a_capacity_deferral_of_an_active_cycle_is_noted_until_a_cycle_completes() {
    use kasumi_kv::StorageCompactionPhase::{Evacuating, Idle, Reclaiming};
    let storage = |phase, deferrals, completed| kasumi_kv::StorageMaintenanceStatus {
        phase,
        capacity_deferrals_total: deferrals,
        cycles_completed: completed,
        ..Default::default()
    };
    let mut status = CacheWorkerStatus::default();
    // No deferral, and one while no cycle is active, note nothing.
    observe_capacity_deferral(&mut status, None, &storage(Evacuating, 0, 2));
    assert_eq!(status.capacity_deferred_cycle, None);
    observe_capacity_deferral(&mut status, Some(storage(Idle, 0, 2)), &storage(Idle, 1, 2));
    assert_eq!(status.capacity_deferred_cycle, None);
    // A step of the active cycle was refused capacity.
    observe_capacity_deferral(
        &mut status,
        Some(storage(Evacuating, 1, 2)),
        &storage(Evacuating, 2, 2),
    );
    assert_eq!(status.capacity_deferred_cycle, Some(2));
    // It stays noted through the cycle's later phases and steps.
    observe_capacity_deferral(
        &mut status,
        Some(storage(Evacuating, 2, 2)),
        &storage(Reclaiming, 2, 2),
    );
    assert_eq!(status.capacity_deferred_cycle, Some(2));
    // The cycle completed: maintenance yields again.
    observe_capacity_deferral(
        &mut status,
        Some(storage(Reclaiming, 2, 2)),
        &storage(Idle, 2, 3),
    );
    assert_eq!(status.capacity_deferred_cycle, None);
    // A deferral counted before the worker's first observation is noted
    // while its cycle is still active.
    let mut late = CacheWorkerStatus::default();
    observe_capacity_deferral(&mut late, None, &storage(Evacuating, 3, 7));
    assert_eq!(late.capacity_deferred_cycle, Some(7));
}

#[test]
fn worker_stands_in_for_inline_steps_only_after_a_step_that_ran_undeferred() {
    let delay = Duration::from_millis(200);
    let stand_in = Some(delay * 2 + STAND_IN_MARGIN);
    // A step that made progress, and one that found nothing due: the worker
    // is alive and will step again within its pause.
    assert_eq!(
        inline_stand_in(&maintaining_status(Duration::ZERO, true), delay),
        stand_in
    );
    let idle = CacheWorkerStatus {
        last_maintenance: Some(kasumi_kv::MaintenanceStep::Ran(
            kasumi_kv::MaintenanceProgress {
                idle: true,
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    assert_eq!(inline_stand_in(&idle, delay), stand_in);
    assert_eq!(
        inline_stand_in(&idle, RUNNING_DELAY),
        Some(RUNNING_DELAY * 2 + STAND_IN_MARGIN)
    );
    // Writers starve the worker of the write gate, or the cycle is backing
    // off: the writes' own steps drive it, or count the backoff down.
    let busy = CacheWorkerStatus {
        last_maintenance: Some(kasumi_kv::MaintenanceStep::Busy),
        maintenance_pending: true,
        ..Default::default()
    };
    assert_eq!(inline_stand_in(&busy, delay), None);
    for deferral in [
        kasumi_kv::MaintenanceDeferral::Capacity,
        kasumi_kv::MaintenanceDeferral::Rejected("refused"),
    ] {
        let deferred = CacheWorkerStatus {
            last_maintenance: Some(kasumi_kv::MaintenanceStep::Ran(
                kasumi_kv::MaintenanceProgress {
                    deferred: Some(deferral),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        assert_eq!(inline_stand_in(&deferred, delay), None);
    }
    assert_eq!(inline_stand_in(&CacheWorkerStatus::default(), delay), None);
    // It covers the longest pause with room for the next step to begin.
    assert!(inline_stand_in(&idle, crate::MAX_PACED_DELAY).unwrap() > crate::MAX_PACED_DELAY * 2);
}

/// What foreground readers and a writer saw while the worker drove one
/// compaction cycle on a slow disk.
#[derive(Debug)]
struct CycleUnderLoad {
    wall: Duration,
    reads: usize,
    writes: usize,
    /// Time the reader spent in its reads: on an unloaded database, almost
    /// none; behind a maintenance step, the step's remaining time.
    read_time: Duration,
    read_p99: Duration,
    read_max: Duration,
    /// The same for the writer's commits, each with its inline step if any.
    write_time: Duration,
    write_max: Duration,
    worker: CacheWorkerStatus,
    storage: kasumi_kv::StorageMaintenanceStatus,
    /// Slow commits' root publications (`SLOW_PUBLICATION`) that ran.
    slow_publications: usize,
    /// Reads that began during a slow publication at least `STALL_SLACK`
    /// before it ended, and those of them that ended only after it.
    exposed_reads: usize,
    stalled_reads: usize,
}
impl CycleUnderLoad {
    fn worker_time(&self) -> Duration {
        self.worker.warm_time + self.worker.maintenance_time
    }
    fn worker_share(&self) -> f64 {
        self.worker_time().as_secs_f64() / self.wall.as_secs_f64()
    }
    /// The share of the wall time the reader spent waiting in its reads,
    /// behind the worker's steps and behind the other tenant's commits.
    fn read_share(&self) -> f64 {
        self.read_time.as_secs_f64() / self.wall.as_secs_f64()
    }
    fn reads_per_second(&self) -> f64 {
        self.reads as f64 / self.wall.as_secs_f64()
    }
}

/// Every durable synchronization of the slow disk.
const SLOW_SYNC: Duration = Duration::from_millis(5);
/// The foreground reader's pause between two reads, and the writer's
/// between two commits.
const READER_THINK: Duration = Duration::from_millis(2);
const WRITER_THINK: Duration = Duration::from_millis(40);
const WIDE_ROWS: u16 = 180;
/// How much longer a slow commit's root publication takes: a commit that a
/// sync stalls on a loaded disk.
const SLOW_PUBLICATION: Duration = Duration::from_secs(4);
/// A read that began this long before a slow publication ended, and was
/// still running when it ended, waited for that publication: no read takes
/// that long otherwise, even on a loaded machine.
const STALL_SLACK: Duration = Duration::from_secs(2);

/// Drive one requested compaction cycle through the real worker on a disk
/// whose every sync takes `SLOW_SYNC`, while one foreground thread reads a
/// row every `READER_THINK` and another commits one every `WRITER_THINK`:
/// two tenants of the node database. The writer's commits numbered in
/// `slow_commits` (from zero) take `SLOW_PUBLICATION` longer to publish.
async fn compaction_cycle_under_foreground_load(
    unpaced: bool,
    slow_commits: &'static [usize],
) -> CycleUnderLoad {
    let fixture = Fixture::cold_with(WIDE_ROWS).await;
    write_row(&fixture.node, 100);
    fixture.node.request_storage_compaction().unwrap();
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture
        .node
        .body()
        .cache_warmer
        .set_unpaced_for_test(unpaced);
    fixture
        .probe
        .sync_micros
        .store(SLOW_SYNC.as_micros() as u64, Ordering::Release);
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let node = fixture.node.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            // When each read began, and how long it took.
            let mut reads = Vec::new();
            while !stop.load(Ordering::Acquire) {
                let key = (reads.len() % 20) as u8;
                let started = Instant::now();
                {
                    let transaction = node.body().db.begin_read().unwrap();
                    let table = transaction.open_table(ROWS).unwrap();
                    assert_eq!(table.get(&[key][..]).unwrap().unwrap().value(), &[key; 512]);
                }
                reads.push((started, started.elapsed()));
                std::thread::sleep(READER_THINK);
            }
            reads
        })
    };
    let writer = {
        let node = fixture.node.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut latencies = Vec::new();
            while !stop.load(Ordering::Acquire) {
                let started = Instant::now();
                let key = 101 + (latencies.len() % 100) as u8;
                if slow_commits.contains(&latencies.len()) {
                    write_row_publishing_slowly(&node, key, SLOW_PUBLICATION);
                } else {
                    write_row(&node, key);
                }
                latencies.push(started.elapsed());
                std::thread::sleep(WRITER_THINK);
            }
            latencies
        })
    };
    let started = Instant::now();
    fixture.node.activate_cache_warming().unwrap();
    // The cycle must complete however the worker is paced. The bound only
    // ends a hung run; nothing is asserted about how long a cycle takes.
    let storage = tokio::time::timeout(Duration::from_secs(600), async {
        loop {
            let storage = fixture.node.storage_maintenance_status().unwrap();
            if completed_first_cycle(&storage) {
                return storage;
            }
            let worker = fixture.node.cache_worker_status();
            assert!(!worker.failed, "cache worker failed: {worker:?}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the compaction cycle did not complete: {:?}; worker={:?}",
            fixture.node.storage_maintenance_status(),
            fixture.node.cache_worker_status(),
        )
    });
    let wall = started.elapsed();
    let worker = fixture.node.cache_worker_status();
    stop.store(true, Ordering::Release);
    let timed_reads = reader.join().unwrap();
    let writes = writer.join().unwrap();
    fixture.probe.sync_micros.store(0, Ordering::Release);
    let publications = fixture.probe.slow_publications.lock().clone();
    let exposed = |started: Instant| {
        publications
            .iter()
            .find(|(began, ended)| started >= *began && started + STALL_SLACK <= *ended)
    };
    let exposed_reads = timed_reads
        .iter()
        .filter(|(started, _)| exposed(*started).is_some())
        .count();
    let stalled_reads = timed_reads
        .iter()
        .filter(|(started, took)| {
            exposed(*started).is_some_and(|(_, ended)| *started + *took > *ended)
        })
        .count();
    let mut reads: Vec<_> = timed_reads.iter().map(|(_, took)| *took).collect();
    assert!(!worker.failed, "{worker:?}");
    assert!(storage.reclaimed_files_total >= 1, "{storage:?}");
    assert_rows(&fixture.node, (0..20).chain([100]));
    {
        let transaction = fixture.node.body().db.begin_read().unwrap();
        let table = transaction.open_table(ROWS).unwrap();
        for index in 0..WIDE_ROWS {
            assert_eq!(
                table.get(&wide_key(index)[..]).unwrap().unwrap().value(),
                &[7; 64]
            );
        }
    }
    fixture.node.shutdown().await.unwrap();
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
    let read_time = reads.iter().sum();
    reads.sort_unstable();
    CycleUnderLoad {
        wall,
        reads: reads.len(),
        writes: writes.len(),
        read_time,
        read_p99: reads[(reads.len() * 99) / 100],
        read_max: *reads.last().unwrap(),
        write_time: writes.iter().sum(),
        write_max: writes.iter().copied().max().unwrap_or_default(),
        worker,
        storage,
        slow_publications: publications.len(),
        exposed_reads,
        stalled_reads,
    }
}

fn report_cycle_under_load(name: &str, run: &CycleUnderLoad) {
    eprintln!(
        "compaction under foreground load, {name}: wall={:?} worker_share={:.3} \
         (maintenance={:?} warm={:?} steps={} busy={} longest={:?}) \
         paced_delays={} paced_delay={:?} reads={} reads_per_second={:.1} \
         read_share={:.3} read_p99={:?} read_max={:?} writes={} write_mean={:?} \
         write_max={:?} relocated_bytes={} reclaimed_files={} slow_publications={} \
         exposed_reads={} stalled_reads={}",
        run.wall,
        run.worker_share(),
        run.worker.maintenance_time,
        run.worker.warm_time,
        run.worker.maintenance_steps,
        run.worker.maintenance_busy,
        run.worker.longest_database_time,
        run.worker.paced_delays,
        run.worker.paced_delay,
        run.reads,
        run.reads_per_second(),
        run.read_share(),
        run.read_p99,
        run.read_max,
        run.writes,
        run.write_time / run.writes.max(1) as u32,
        run.write_max,
        run.storage.relocated_bytes_total,
        run.storage.reclaimed_files_total,
        run.slow_publications,
        run.exposed_reads,
        run.stalled_reads,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_leaves_a_slow_disk_to_foreground_operations_during_a_compaction_cycle() {
    // The control: the worker's own pace and no stand-in, as before pacing.
    // It shows what the foreground is protected from; nothing but completion
    // is asserted of it.
    let control = compaction_cycle_under_foreground_load(true, &[]).await;
    let paced = compaction_cycle_under_foreground_load(false, &[]).await;
    for (name, run) in [("unpaced", &control), ("paced", &paced)] {
        report_cycle_under_load(name, run);
    }
    assert_eq!(control.worker.paced_delays, 0, "{control:?}");
    // The worker saw the foreground operations and yielded to them.
    assert!(paced.worker.paced_delays > 0, "{paced:?}");
    assert!(paced.worker.paced_delay >= paced.worker_time(), "{paced:?}");
    // It kept the database for a bounded share of the cycle. The pacing aims
    // at a fifth; twice that allows for iterations before the first
    // foreground operation was seen and for a loaded machine.
    assert!(paced.worker_share() <= 0.4, "{paced:?}");
    // So the foreground kept at least three fifths of the database's time,
    // and used it: the reader completed reads at least half again as fast as
    // with the unpaced worker. In both runs a read waits only while the KV
    // core lock is held, by a step of the worker or by the staging of the
    // other tenant's commit, so its rate follows the share of time that lock
    // is free: about twice to two and a half times that of the unpaced run,
    // with room left for a loaded machine.
    assert!(paced.reads > 0 && paced.writes > 0, "{paced:?}");
    assert!(
        paced.reads_per_second() >= control.reads_per_second() * 1.5,
        "paced={paced:?} control={control:?}"
    );
    // A read waits for at most the iteration or the commit in progress: a
    // few of them bound the worst reads, with slack for a loaded machine.
    assert!(
        paced.read_p99 <= paced.worker.longest_database_time * 4 + Duration::from_millis(250),
        "{paced:?}"
    );
    // The worst read waited for about one iteration and one commit of the
    // other tenant: the bound is the sum, with a second of slack for a
    // loaded machine.
    assert!(
        paced.read_max
            <= paced.worker.longest_database_time + paced.write_max + Duration::from_secs(1),
        "{paced:?}"
    );
    // The worker still did the cycle's work: the writes did not take it
    // over one inline step each, which would keep the database as before.
    assert!(
        paced.worker.maintenance_steps * 2 >= control.worker.maintenance_steps,
        "paced={paced:?} control={control:?}"
    );
    // Pacing is what made the difference.
    assert!(
        paced.worker_share() < control.worker_share(),
        "paced={paced:?} control={control:?}"
    );
}

/// The same cycle, with two of the other tenant's commits each taking
/// `SLOW_PUBLICATION` longer to publish their root, as commits do when a
/// sync stalls on a loaded disk. Such a commit holds the write gate and the
/// commit gate throughout, so the worker's next warm step waits for it; it
/// holds no lock a read takes, so reads go on meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_go_on_while_the_worker_waits_for_a_slow_commit_of_another_tenant() {
    let run = compaction_cycle_under_foreground_load(false, &[10, 25]).await;
    report_cycle_under_load("paced, two slow commits", &run);
    assert_eq!(run.slow_publications, 2, "{run:?}");
    // The worker begins an iteration at least every second (its longest
    // pause), so it met a slow publication with seconds of it left and
    // waited for the rest of it.
    assert!(
        run.worker.longest_database_time >= SLOW_PUBLICATION / 4,
        "{run:?}"
    );
    // The reader went on reading during the slow publications: no read that
    // began at least `STALL_SLACK` before one ended had to wait for its end.
    assert!(run.exposed_reads > 0, "{run:?}");
    assert_eq!(run.stalled_reads, 0, "{run:?}");
}

/// One background unit that keeps the database for at least `held`: it
/// writes a row and stays in its own scope that long. Returns when the unit
/// started and when its work ended.
fn background_unit(
    node: &NodeStore,
    pace: &mut crate::BackgroundPace,
    key: u8,
    held: Duration,
) -> (Instant, Instant) {
    node.paced_background_write(pace, &AtomicBool::new(false), || {
        let started = Instant::now();
        write_row(node, key);
        std::thread::sleep(held);
        (started, Instant::now())
    })
}

#[tokio::test]
async fn a_background_write_stream_pauses_only_for_foreground_operations() {
    use crate::{BackgroundPace, FOREGROUND_SHARE, MIN_PACED_DELAY};
    let fixture = Fixture::cold().await;
    let node = &fixture.node;
    let held = Duration::from_millis(15);
    assert_eq!(node.background_write_status(), Default::default());
    let activity = node.foreground_activity().unwrap();
    // A stream's units are not foreground activity, and with none it owes
    // only the floor between them: nothing is counted as a paced delay.
    let mut pace = BackgroundPace::default();
    let (_, first_ended) = background_unit(node, &mut pace, 150, held);
    let (second_started, second_ended) = background_unit(node, &mut pace, 151, held);
    assert!(second_started.duration_since(first_ended) >= MIN_PACED_DELAY);
    assert_eq!(node.foreground_activity().unwrap(), activity);
    let quiet = node.background_write_status();
    assert_eq!(quiet.units, 2);
    assert!(quiet.database_time >= held * 2, "{quiet:?}");
    assert_eq!(quiet.paced_delay, Duration::ZERO);
    // A foreground read entered since the second unit started: the stream
    // waits the foreground share of the time that unit kept the database.
    assert_rows(node, [150, 151].into_iter());
    assert!(node.foreground_activity().unwrap() > activity);
    let (third_started, third_ended) = background_unit(node, &mut pace, 152, held);
    assert!(
        third_started.duration_since(second_ended) >= held * FOREGROUND_SHARE,
        "{:?}",
        third_started.duration_since(second_ended)
    );
    let paced = node.background_write_status();
    assert_eq!(paced.units, 3);
    assert!(paced.paced_delay > Duration::ZERO, "{paced:?}");
    // No foreground operation since the third unit started: the floor again.
    let (fourth_started, _) = background_unit(node, &mut pace, 153, Duration::ZERO);
    assert!(fourth_started.duration_since(third_ended) >= MIN_PACED_DELAY);
    assert_eq!(
        node.background_write_status().paced_delay,
        paced.paced_delay
    );
    // A fresh stream owes nothing, whatever the foreground did before it.
    assert_rows(node, [152, 153].into_iter());
    let before = node.background_write_status();
    background_unit(node, &mut BackgroundPace::default(), 154, Duration::ZERO);
    assert_eq!(
        node.background_write_status().paced_delay,
        before.paced_delay
    );
    // A stream whose owner hurries (a group that is shutting down) owes the
    // pause for the foreground read below and does not take it.
    background_unit(node, &mut pace, 155, held);
    assert_rows(node, [154, 155].into_iter());
    let before = node.background_write_status();
    node.paced_background_write(&mut pace, &AtomicBool::new(true), || write_row(node, 156));
    assert_eq!(
        node.background_write_status().paced_delay,
        before.paced_delay
    );
    // The published status carries the write counters once a worker exists.
    assert!(node.published_storage_status().is_none());
    node.prepare_cache_warming().await.unwrap();
    node.activate_cache_warming().unwrap();
    fixture.wait(|status| status.maintenance_steps >= 1).await;
    let published = node.published_storage_status().unwrap();
    assert_eq!(published.background.writes, node.background_write_status());
    assert_eq!(published.background.writes.units, 7);
    assert!(published.background.maintenance_steps >= 1);
    assert_rows(node, (0..20).chain(150..157));
    node.shutdown().await.unwrap();
    // A stopped database has no activity to read and ends every pause.
    assert_eq!(node.foreground_activity(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_shared_background_stream_runs_one_unit_at_a_time_and_paces_across_writers() {
    use crate::FOREGROUND_SHARE;
    let fixture = Fixture::cold().await;
    let held = Duration::from_millis(10);
    let running = AtomicUsize::new(0);
    let overlapped = AtomicBool::new(false);
    // Two writers, as two tenants' snapshot builds. During every unit another
    // thread reads a row: a foreground operation, whatever the scheduling.
    let mut spans = std::thread::scope(|scope| {
        let writers: Vec<_> = (0..2u8)
            .map(|writer| {
                let (node, running, overlapped) = (&fixture.node, &running, &overlapped);
                scope.spawn(move || {
                    (0..4u8)
                        .map(|unit| {
                            node.shared_background_write(&AtomicBool::new(false), || {
                                if running.fetch_add(1, Ordering::AcqRel) != 0 {
                                    overlapped.store(true, Ordering::Release);
                                }
                                let started = Instant::now();
                                write_row(node, 160 + writer * 4 + unit);
                                std::thread::scope(|foreground| {
                                    foreground.spawn(|| assert_rows(node, 0..1));
                                });
                                std::thread::sleep(held);
                                let ended = Instant::now();
                                running.fetch_sub(1, Ordering::AcqRel);
                                (started, ended)
                            })
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        writers
            .into_iter()
            .flat_map(|writer| writer.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(!overlapped.load(Ordering::Acquire));
    // Whichever writer ran a unit, the next unit of either waited the
    // foreground share of the time that unit kept the database.
    spans.sort_unstable();
    assert_eq!(spans.len(), 8);
    for pair in spans.windows(2) {
        let (_, ended) = pair[0];
        let (started, _) = pair[1];
        assert!(
            started.duration_since(ended) >= held * FOREGROUND_SHARE,
            "{:?}",
            started.duration_since(ended)
        );
    }
    let status = fixture.node.background_write_status();
    assert_eq!(status.units, 8);
    assert!(status.database_time >= held * 8, "{status:?}");
    assert!(status.paced_delay > Duration::ZERO, "{status:?}");
    assert_rows(&fixture.node, (0..20).chain(160..168));
    fixture.node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closing_writer_does_not_wait_for_another_tenants_unit_on_the_shared_stream() {
    let fixture = Fixture::cold().await;
    let node = &fixture.node;
    let (entered, held) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let (holding, closing) = (&AtomicBool::new(false), &AtomicBool::new(false));
    std::thread::scope(|scope| {
        // One tenant's unit holds the shared stream, as a slow chunk commit or
        // the pause before one does. Its own deadline bounds a regression.
        let holder = scope.spawn(move || {
            node.shared_background_write(&AtomicBool::new(false), || {
                write_row(node, 170);
                holding.store(true, Ordering::Release);
                entered.send(()).unwrap();
                let _ = released.recv_timeout(Duration::from_secs(30));
                holding.store(false, Ordering::Release);
            })
        });
        held.recv_timeout(Duration::from_secs(30)).unwrap();
        // Another tenant's next unit waits for the stream...
        let waiter = scope.spawn(move || {
            node.shared_background_write(closing, || {
                write_row(node, 171);
                holding.load(Ordering::Acquire)
            })
        });
        // Several of its checks pass while the group is open.
        std::thread::sleep(crate::background_pace::PAUSE_SLICE * 10);
        assert!(!waiter.is_finished());
        // ...until its group closes: it then commits at once, while the other
        // unit still holds the stream, instead of waiting for it.
        closing.store(true, Ordering::Release);
        assert!(waiter.join().unwrap(), "the closing writer waited");
        release.send(()).unwrap();
        holder.join().unwrap();
    });
    // The closing writer's commit was direct: no paced unit, no pause.
    let status = node.background_write_status();
    assert_eq!(status.units, 1, "{status:?}");
    assert_eq!(status.paced_delay, Duration::ZERO, "{status:?}");
    assert_rows(node, (0..20).chain([170, 171]));
    node.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pause_in_progress_ends_once_its_owner_hurries_or_the_database_stops() {
    use crate::{BackgroundPace, MAX_PACED_DELAY};
    let fixture = Fixture::cold().await;
    let node = &fixture.node;
    for stop in [false, true] {
        // A unit that kept the database for a quarter second, then a
        // foreground read: the stream owes its longest pause.
        let mut pace = BackgroundPace::default();
        let key = 172 + u8::from(stop);
        let (_, ended) = background_unit(node, &mut pace, key, MAX_PACED_DELAY / 4);
        assert_rows(node, [key].into_iter());
        let hurry = AtomicBool::new(false);
        let (set_at, started) = std::thread::scope(|scope| {
            let next = scope.spawn(|| node.paced_background_write(&mut pace, &hurry, Instant::now));
            std::thread::sleep(Duration::from_millis(50));
            let set_at = Instant::now();
            if stop {
                node.body().db.stop();
            } else {
                hurry.store(true, Ordering::Release);
            }
            (set_at, next.join().unwrap())
        });
        // Set with at least half the pause left, the stop or the hurry cut
        // it short. A machine too slow to set it in time proves nothing.
        if set_at < ended + MAX_PACED_DELAY / 2 {
            assert!(
                started < ended + MAX_PACED_DELAY,
                "stop={stop}: the next unit began {:?} after the paced one",
                started.duration_since(ended)
            );
        }
    }
    // The stopped database ended the last pause; shutdown completes.
    node.shutdown().await.unwrap();
}
