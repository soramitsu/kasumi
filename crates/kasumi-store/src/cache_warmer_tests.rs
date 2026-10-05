use super::*;
use crate::NodeDiskMemoryAdmission;
use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, GroupFile, OwnerFailed, ROOT_SLOT_BYTES, ResidentLease,
    RootSlot, SegmentGroupBackend, StorageAdmission, TableDefinition,
};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex as StdMutex};

const ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("warming");

struct MemoryAdmission {
    memory: Arc<crate::test_utils::TestDiskMemory>,
    failed: AtomicBool,
    release_on_denial: Mutex<Option<crate::DiskMemoryLease>>,
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

struct Probe {
    group: kasumi_kv::backends::InMemoryGroup,
    reads: AtomicUsize,
    closes: AtomicUsize,
    fail_read: AtomicBool,
    gate: ReadGate,
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
        self.group.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
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
            self.gate.entered.notify_one();
            let mut released = self.gate.released.lock().unwrap();
            while !*released {
                released = self.gate.changed.wait(released).unwrap();
            }
        }
        if self.fail_read.swap(false, Ordering::AcqRel) {
            return Err(io::Error::other("automatic cache read failure"));
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
        self.group.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
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
        let directory = crate::test_utils::private_tempdir().unwrap();
        let memory = crate::test_utils::TestDiskMemory::new(32 << 20, 4096);
        let scratch = crate::ScratchDisk::fixture(directory.path(), memory.clone());
        let group = Arc::new(kasumi_kv::backends::InMemoryGroup::new());
        let native = || {
            Arc::new(MemoryAdmission {
                memory: memory.clone(),
                failed: AtomicBool::new(false),
                release_on_denial: Mutex::new(None),
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
        }
        transaction.commit().unwrap();
        let crash = group.crash();
        first.shutdown().await.unwrap();
        drop(first);
        let probe = Arc::new(Probe {
            group: crash,
            reads: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            fail_read: AtomicBool::new(false),
            gate: ReadGate::default(),
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
    fixture.probe.fail_read.store(true, Ordering::Release);
    fixture.node.prepare_cache_warming().await.unwrap();
    fixture.node.activate_cache_warming().unwrap();
    fixture.wait(|s| s.failed).await;
    let first = fixture.node.shutdown().await.unwrap_err();
    assert!(first.to_string().contains("automatic cache read failure"));
    let second = fixture.node.shutdown().await.unwrap_err();
    assert_eq!(first.to_string(), second.to_string());
    assert_eq!(fixture.probe.closes.load(Ordering::Acquire), 1);
}
