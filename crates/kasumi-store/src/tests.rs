use super::*;
use crate::test_utils::{FaultBackend, LocalKeyProvider, ManualClock};
use async_trait::async_trait;
use kasumi_kv::SegmentGroupBackend;
use std::sync::atomic::{AtomicBool, Ordering};

struct FailingNodeSetupBackend {
    inner: kasumi_kv::backends::InMemoryGroup,
    syncs: std::sync::atomic::AtomicUsize,
    closes: std::sync::atomic::AtomicUsize,
}

impl FailingNodeSetupBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: kasumi_kv::backends::InMemoryGroup::new(),
            syncs: std::sync::atomic::AtomicUsize::new(0),
            closes: std::sync::atomic::AtomicUsize::new(0),
        })
    }
}

impl SegmentGroupBackend for FailingNodeSetupBackend {
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
        self.inner.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.inner.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.inner.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(
        &self,
        slot: kasumi_kv::RootSlot,
        out: &mut [u8; kasumi_kv::ROOT_SLOT_BYTES],
    ) -> std::io::Result<()> {
        self.inner.read_root(slot, out)
    }
    fn write_root(
        &self,
        slot: kasumi_kv::RootSlot,
        bytes: &[u8; kasumi_kv::ROOT_SLOT_BYTES],
    ) -> std::io::Result<()> {
        self.inner.write_root(slot, bytes)
    }
    fn sync_root(&self) -> std::io::Result<()> {
        self.inner.sync_root()
    }
    fn visit_entries(
        &self,
        visitor: &mut dyn FnMut(&std::ffi::OsStr) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        self.inner.visit_entries(visitor)
    }
    fn exists(&self, file: kasumi_kv::GroupFile) -> std::io::Result<bool> {
        self.inner.exists(file)
    }
    fn create(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
        self.inner.create(file)
    }
    fn len(&self, file: kasumi_kv::GroupFile) -> std::io::Result<u64> {
        self.inner.len(file)
    }
    fn read(&self, file: kasumi_kv::GroupFile, at: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.inner.read(file, at, out)
    }
    fn write(&self, file: kasumi_kv::GroupFile, at: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.write(file, at, bytes)
    }
    fn set_len(&self, file: kasumi_kv::GroupFile, length: u64) -> std::io::Result<()> {
        self.inner.set_len(file, length)
    }
    fn sync(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
        if self.syncs.fetch_add(1, Ordering::AcqRel) == 1 {
            return Err(std::io::Error::other("injected table setup sync failure"));
        }
        self.inner.sync(file)
    }
    fn unlink(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
        self.inner.unlink(file)
    }
    fn sync_names(&self) -> std::io::Result<()> {
        self.inner.sync_names()
    }
    fn close(&self) -> kasumi_kv::BackendCloseOutcome {
        self.closes.fetch_add(1, Ordering::AcqRel);
        self.inner.close()
    }
}

#[test]
fn failed_node_table_setup_observes_the_original_native_close() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory);
    let backend = FailingNodeSetupBackend::new();
    let error = NodeStore::create_with_backend(
        backend.clone(),
        crate::test_utils::storage_admission(),
        scratch,
    )
    .err()
    .expect("the table setup sync is injected to fail");
    let NodeStoreStartFailure::Opening(failure) = error.original() else {
        panic!("the exact admitted table request must retain its original startup failure");
    };
    let tables = failure
        .custody()
        .tables()
        .expect("failed original table request");
    let report = tables.report();
    let terminal = report.terminal().expect("actual attempted commit");
    let TerminalObservation::Returned(Err(original)) = terminal.terminal() else {
        panic!("injected table setup sync must retain the original commit error");
    };
    let kasumi_kv::WriteTerminalError::Commit(kasumi_kv::CommitError(kasumi_kv::StorageError::Io(
        original,
    ))) = original
    else {
        panic!("injected table setup sync must retain its original native I/O error");
    };
    assert!(
        original
            .to_string()
            .contains("injected table setup sync failure")
    );
    let opening = failure.custody().opening().report();
    assert_eq!(
        opening.engine().native_disposition(),
        BackendNativeDisposition::Drained
    );
    assert_eq!(
        opening.engine().settlement(),
        kasumi_kv::DatabaseOpenSettlement::DrainedWithFailure
    );
    assert_eq!(backend.closes.load(Ordering::Acquire), 1);
}

#[test]
fn failed_node_setup_keeps_the_original_panic_and_closes() {
    let database = Database::builder(
        crate::test_utils::storage_admission(),
        *crate::test_utils::NODE_STORE_ID.as_bytes(),
        kasumi_kv::CacheConfig::default(),
    )
    .create_with_backend(kasumi_kv::backends::InMemoryGroup::new())
    .unwrap();
    let error = NodeStore::finish_setup(database, |_| panic!("injected setup panic"))
        .err()
        .expect("setup panicked");
    let failure = error.downcast_ref::<NodeStoreSetupFailure>().unwrap();
    assert_eq!(
        failure.with_panic_payload(|payload| payload.downcast_ref::<&str>().copied()),
        Some(Some("injected setup panic"))
    );
    failure.with_close_report(|report| {
        assert_eq!(
            report.native_disposition(),
            BackendNativeDisposition::Drained
        );
        assert_eq!(report.settlement(), DatabaseCloseSettlement::Settled);
    });
}

async fn fixture(
    fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>,
    fixture_scratch: std::sync::Arc<crate::ScratchDisk>,
) -> (
    tempfile::TempDir,
    Arc<TenantStore>,
    Arc<LocalKeyProvider>,
    Arc<ManualClock>,
) {
    let dir = crate::test_utils::private_tempdir().unwrap();
    let node = NodeStore::create_new_fixture(
        dir.path().join("database.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .unwrap();
    let provider = Arc::new(LocalKeyProvider::new([41; 32]));
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        node,
        "tenant-a".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    (dir, store, provider, clock)
}

#[tokio::test(start_paused = true)]
async fn periodic_probes_start_every_twenty_seconds_despite_provider_latency() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    struct Delayed {
        inner: LocalKeyProvider,
        delay: AtomicBool,
        starts: std::sync::Mutex<Vec<tokio::time::Instant>>,
    }
    #[async_trait]
    impl KeyProvider for Delayed {
        async fn generate_key(&self, tenant: &str) -> anyhow::Result<GeneratedKey> {
            self.inner.generate_key(tenant).await
        }
        async fn unwrap_key(
            &self,
            tenant: &str,
            wrapped: &WrappedKey,
        ) -> anyhow::Result<SecretKey> {
            if self.delay.load(Ordering::SeqCst) {
                self.starts
                    .lock()
                    .unwrap()
                    .push(tokio::time::Instant::now());
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            self.inner.unwrap_key(tenant, wrapped).await
        }
        async fn rewrap_key(
            &self,
            tenant: &str,
            wrapped: &WrappedKey,
        ) -> anyhow::Result<WrappedKey> {
            self.inner.rewrap_key(tenant, wrapped).await
        }
    }
    let directory = crate::test_utils::private_tempdir().unwrap();
    let provider = Arc::new(Delayed {
        inner: LocalKeyProvider::new([71; 32]),
        delay: AtomicBool::new(false),
        starts: std::sync::Mutex::new(Vec::new()),
    });
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::create_new_fixture(
            directory.path().join("cadence.kv"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "cadence".into(),
        provider.clone(),
        Arc::new(ManualClock::new()),
    )
    .await
    .unwrap();
    assert_eq!(store.catalog.read().keys.len(), 2);
    TenantStore::start_renewal(&store).await;
    tokio::task::yield_now().await;
    let start = tokio::time::Instant::now();
    provider.delay.store(true, Ordering::SeqCst);
    for seconds in [20, 2, 2, 16] {
        tokio::time::advance(Duration::from_secs(seconds)).await;
        tokio::task::yield_now().await;
    }
    let starts = provider.starts.lock().unwrap();
    assert_eq!(starts.len(), 3);
    assert_eq!(starts[0].duration_since(start), Duration::from_secs(20));
    assert_eq!(starts[1].duration_since(start), Duration::from_secs(22));
    assert_eq!(starts[2].duration_since(start), Duration::from_secs(40));
    store.check_access().unwrap();
}

#[tokio::test(start_paused = true)]
async fn canceled_shutdown_drains_blocked_probe_and_releases_the_database_file() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    struct Blocked {
        inner: LocalKeyProvider,
        block: AtomicBool,
        entered: tokio::sync::Notify,
        canceled: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl KeyProvider for Blocked {
        async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
            self.inner.generate_key(tenant).await
        }
        async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
            if self.block.load(Ordering::Acquire) {
                struct Probe<'a>(&'a std::sync::atomic::AtomicUsize);
                impl Drop for Probe<'_> {
                    fn drop(&mut self) {
                        self.0.fetch_add(1, Ordering::AcqRel);
                    }
                }
                let _probe = Probe(&self.canceled);
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            self.inner.unwrap_key(tenant, wrapped).await
        }
        async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey> {
            self.inner.rewrap_key(tenant, wrapped).await
        }
    }
    let directory = crate::test_utils::private_tempdir().unwrap();
    let path = directory.path().join("shutdown.kv");
    let node = NodeStore::create_new_fixture(
        &path,
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .unwrap();
    let weak_node = node.locator();
    let mut node_retirement = node.clone().retire();
    assert_eq!(
        node_retirement.disposition(),
        StorageCensusDisposition::Retained
    );
    let provider = Arc::new(Blocked {
        inner: LocalKeyProvider::new([39; 32]),
        block: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        canceled: std::sync::atomic::AtomicUsize::new(0),
    });
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        node,
        "shutdown".into(),
        provider.clone(),
        Arc::new(ManualClock::new()),
    )
    .await
    .unwrap();
    store
        .write_batch(&[WriteOp::put("documents", b"durable", b"value")])
        .unwrap();
    let weak_store = Arc::downgrade(&store);
    TenantStore::start_renewal(&store).await;
    tokio::task::yield_now().await;
    provider.block.store(true, Ordering::Release);
    tokio::time::advance(Duration::from_secs(20)).await;
    provider.entered.notified().await;
    assert!(weak_store.strong_count() > 1, "the probe owns the store");
    assert!(!store.state.read().keys.is_empty());

    // This current-thread runtime cannot poll the stopped probe while shutdown
    // itself is being polled. Cancel at the first pending join, without any wall
    // clock delay, and require a subsequent caller to retain and drain that join.
    let mut shutdown = Box::pin(store.shutdown());
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(shutdown.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(shutdown);
    assert!(store.shutdown_requested.load(Ordering::Acquire));
    assert!(store.state.read().keys.is_empty());
    assert!(store.check_access().is_err());
    assert!(store.refresh_lease().await.is_err());
    assert_eq!(store.background.lock().await.handles.len(), 2);

    store.shutdown().await.unwrap();
    assert_eq!(provider.canceled.load(Ordering::Acquire), 1);
    assert!(store.background.lock().await.handles.is_empty());
    assert_eq!(weak_store.strong_count(), 1);
    TenantStore::start_renewal(&store).await;
    assert!(store.background.lock().await.handles.is_empty());
    let (first, second) = tokio::join!(store.shutdown(), store.shutdown());
    first.unwrap();
    second.unwrap();
    store.node.shutdown().await.unwrap();
    drop(store);
    assert!(weak_store.upgrade().is_none());
    assert_eq!(node_retirement.retry(), StorageCensusDisposition::Retired);
    assert!(matches!(weak_node.try_borrow(), NodeStoreLookup::Missing));

    // Reopen immediately: completion, rather than a file-lock retry or sleep,
    // proves no background owner can retain the previous database.
    provider.block.store(false, Ordering::Release);
    let reopened = TenantStore::open_existing_fixture_with_clock(
        NodeStore::open_existing_fixture(
            &path,
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "shutdown".into(),
        provider,
        Arc::new(ManualClock::new()),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.get("documents", b"durable").unwrap().as_deref(),
        Some(b"value".as_slice())
    );
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn dormant_store_workers_stop_cooperatively_and_external_abort_is_reported() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, store, _provider, _clock) =
        fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    let (_activate, ready) = watch::channel(false);
    TenantStore::prepare_renewal(&store, ready).await;
    tokio::time::timeout(Duration::from_secs(5), store.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(store.background.lock().await.handles.is_empty());

    let (_directory, store, _provider, _clock) =
        fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    TenantStore::start_renewal(&store).await;
    store.background.lock().await.handles[0].abort();
    let first = store.shutdown().await.unwrap_err();
    assert_eq!(
        first.completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    assert_eq!(first.issues().len(), 1);
    assert!(
        first.issues()[0]
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_cancelled()
    );
    let repeated = store.shutdown().await.unwrap_err();
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &first.issues()[0],
        &repeated.issues()[0]
    ));
}

#[tokio::test]
async fn cancelled_store_drain_retains_joined_panic_and_pending_physical_owner() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    use std::{future::Future, task::Poll};
    let (directory, store, provider, clock) =
        fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    store
        .write_batch(&[WriteOp::put("documents", b"retained", b"value")])
        .unwrap();
    let node = store.node.clone();
    let weak_node = node.locator();
    let mut node_retirement = node.clone().retire();
    assert_eq!(
        node_retirement.disposition(),
        StorageCensusDisposition::Retained
    );
    let (release, waiting) = tokio::sync::oneshot::channel();
    let pending = tokio::spawn(async move {
        let _node = node;
        waiting.await.unwrap();
    });
    let failed = tokio::spawn(async {
        panic!("actual store worker panic");
    });
    while !failed.is_finished() {
        tokio::task::yield_now().await;
    }
    store
        .background
        .lock()
        .await
        .handles
        .extend([pending, failed]);
    let mut first = Box::pin(store.shutdown());
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    let issue = {
        let background = store.background.lock().await;
        assert_eq!(background.handles.len(), 1);
        assert_eq!(background.report.issues().len(), 1);
        background.report.issues()[0].clone()
    };
    assert!(
        issue
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic()
    );
    let path = directory.path().join("database.kv");
    assert!(
        NodeStore::open_existing_fixture(
            &path,
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    let mut repeated = Box::pin(store.shutdown());
    std::future::poll_fn(|cx| {
        assert!(repeated.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    release.send(()).unwrap();
    let failure = tokio::time::timeout(Duration::from_secs(5), repeated)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(
        failure.completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &issue,
        &failure.issues()[0]
    ));
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &issue,
        &store.shutdown().await.unwrap_err().issues()[0]
    ));
    store.node.shutdown().await.unwrap();
    drop(store);
    assert_eq!(node_retirement.retry(), StorageCensusDisposition::Retired);
    assert!(matches!(weak_node.try_borrow(), NodeStoreLookup::Missing));
    let reopened = TenantStore::open_existing_fixture_with_clock(
        NodeStore::open_existing_fixture(
            &path,
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "tenant-a".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.get("documents", b"retained").unwrap().as_deref(),
        Some(b"value".as_slice())
    );
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_fences_a_waiting_background_task_registration() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, store, _provider, _clock) =
        fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    let registration = store.background.lock().await;
    let starter = tokio::spawn({
        let store = store.clone();
        async move { TenantStore::start_renewal(&store).await }
    });
    tokio::task::yield_now().await;
    let mut shutdown = Box::pin(store.shutdown());
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(shutdown.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert!(store.shutdown_requested.load(Ordering::Acquire));
    drop(registration);
    shutdown.await.unwrap();
    starter.await.unwrap();
    assert!(store.background.lock().await.handles.is_empty());
    assert!(!store.background.lock().await.started);
    assert!(store.check_access().is_err());
}

#[tokio::test]
async fn atomic_batches_and_cross_namespace_isolation_survive_reopen() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (dir, store, provider, clock) =
        fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    store
        .write_batch(&[
            WriteOp::put("documents", b"b", b"two"),
            WriteOp::put("documents", b"a", b"one"),
            WriteOp::put("receipts", b"a", b"receipt"),
            WriteOp::put("documents", b"gone", b"old"),
            WriteOp::delete("documents", b"gone"),
        ])
        .unwrap();
    assert_eq!(
        store.scan("documents").unwrap(),
        vec![
            (b"a".to_vec(), b"one".to_vec()),
            (b"b".to_vec(), b"two".to_vec())
        ]
    );
    let same = TenantStore::open_existing_fixture_with_clock(
        store.node.clone(),
        "tenant-a".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    assert!(Arc::ptr_eq(&same, &store));
    let other = TenantStore::initialize_catalog_fixture_with_clock(
        store.node.clone(),
        "tenant-b".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    assert!(other.get("documents", b"a").unwrap().is_none());
    drop(other);
    drop(same);
    store.shutdown().await.unwrap();
    store.node.shutdown().await.unwrap();
    drop(store);
    let store = TenantStore::open_existing_fixture_with_clock(
        NodeStore::open_existing_fixture(
            dir.path().join("database.kv"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "tenant-a".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(
        store.get("documents", b"a").unwrap().as_deref(),
        Some(b"one".as_slice())
    );
    assert_eq!(
        store.get("receipts", b"a").unwrap().as_deref(),
        Some(b"receipt".as_slice())
    );
    assert!(store.get("documents", b"gone").unwrap().is_none());
}

#[tokio::test]
async fn invalid_batch_does_not_apply_earlier_operations() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_dir, store, _, _) = fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    store
        .write_batch(&[WriteOp::put("documents", b"a", b"before")])
        .unwrap();
    assert!(
        store
            .write_batch(&[
                WriteOp::put("documents", b"a", b"after"),
                WriteOp::put("", b"b", b"bad")
            ])
            .is_err()
    );
    assert_eq!(
        store.get("documents", b"a").unwrap().as_deref(),
        Some(b"before".as_slice())
    );
    assert!(
        store
            .write_batch(&[WriteOp::put("documents", vec![0; 4097], b"bad")])
            .is_err()
    );
}

#[tokio::test]
async fn names_keys_and_values_are_absent_from_disk_and_nonce_changes_on_overwrite() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (dir, store, _, _) = fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    let ns = "secret-collection-75aa0b497f";
    let key = b"sensitive-document-key-cb3c328";
    let value = b"secret-document-value-d75ab117818c";
    store.write_batch(&[WriteOp::put(ns, key, value)]).unwrap();
    let read_raw = || {
        let state = store.state.read();
        let disk_key = record_key(store.tenant(), ns, key, state.keys.get(INDEX_KEY).unwrap());
        let tx = store.node.body().db.begin_read().unwrap();
        let table = tx.open_table(RECORDS).unwrap();
        table
            .get(disk_key.as_slice())
            .unwrap()
            .unwrap()
            .value()
            .to_vec()
    };
    let before = read_raw();
    store.write_batch(&[WriteOp::put(ns, key, value)]).unwrap();
    assert_ne!(before, read_raw());
    for path in crate::test_utils::node_group_files(&dir.path().join("database.kv")) {
        let bytes = std::fs::read(&path).unwrap();
        for secret in [ns.as_bytes(), key.as_slice(), value.as_slice()] {
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "plaintext record field in {}",
                path.display()
            );
        }
    }
}

#[tokio::test]
async fn ciphertext_corruption_swapping_and_wrong_tenant_are_rejected() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_dir, store, provider, clock) =
        fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    let other = TenantStore::initialize_catalog_fixture_with_clock(
        store.node.clone(),
        "tenant-b".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    for target in [&store, &other] {
        target
            .write_batch(&[
                WriteOp::put("docs", b"a", b"one"),
                WriteOp::put("docs", b"b", b"two"),
            ])
            .unwrap();
    }
    let physical = |target: &TenantStore, key: &[u8]| {
        record_key(
            target.tenant(),
            "docs",
            key,
            target.state.read().keys.get(INDEX_KEY).unwrap(),
        )
    };
    let a = physical(&store, b"a");
    let b = physical(&store, b"b");
    let cross = physical(&other, b"a");
    let tx = store.node.body().db.begin_read().unwrap();
    let table = tx.open_table(RECORDS).unwrap();
    let original = table.get(a.as_slice()).unwrap().unwrap().value().to_vec();
    drop(table);
    drop(tx);
    let raw_write = |key: &[u8], bytes: &[u8]| {
        let tx = store.node.body().db.begin_write().unwrap();
        {
            tx.open_table(RECORDS).unwrap().insert(key, bytes).unwrap();
        }
        tx.commit().unwrap();
    };
    raw_write(&b, &original);
    assert!(
        store
            .get("docs", b"b")
            .unwrap_err()
            .to_string()
            .contains("authentication")
    );
    raw_write(&cross, &original);
    assert!(other.get("docs", b"a").is_err());
    let mut corrupted = original.clone();
    *corrupted.last_mut().unwrap() ^= 0x80;
    raw_write(&a, &corrupted);
    assert!(
        store
            .get("docs", b"a")
            .unwrap_err()
            .to_string()
            .contains("authentication")
    );
    for truncated in [0, 3, 4, original.len() - 1] {
        raw_write(&a, &original[..truncated]);
        assert!(store.get("docs", b"a").is_err());
    }
}

#[tokio::test]
async fn a_fresh_probe_covers_every_retained_version_and_revocation_seals_warm_state() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_dir, store, provider, _) = fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    assert_eq!(provider.probe_count(), 2); // Fresh decrypts, never generation plaintext.
    store
        .write_batch(&[WriteOp::put("docs", b"old", b"old value")])
        .unwrap();
    provider.rotate();
    store.rotate_data_key().await.unwrap();
    store
        .write_batch(&[WriteOp::put("docs", b"new", b"new value")])
        .unwrap();
    let probes = provider.probe_count();
    store.refresh_lease().await.unwrap();
    assert_eq!(provider.probe_count() - probes, 3);
    assert_eq!(store.key_lease_failure_class(), None);
    provider.set_minimum_version(2);
    let mut seal = store.seal_notifications();
    assert!(store.refresh_lease().await.is_err());
    assert_eq!(store.key_lease_failure_class(), Some("provider_error"));
    // The explicit seal that follows is a consequence, not a second cause.
    assert!(store.check_access().is_err());
    assert_eq!(store.key_lease_failure_class(), Some("provider_error"));
    seal.changed().await.unwrap();
    assert!(store.state.read().keys.is_empty());
    assert!(store.get("docs", b"new").is_err());
    assert!(
        store
            .write_batch(&[WriteOp::delete("docs", b"new")])
            .is_err()
    );
}

#[tokio::test]
async fn sixty_second_suspend_aware_expiry_and_explicit_recovery() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_dir, store, provider, clock) =
        fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    clock.advance(Duration::from_secs(59));
    store.check_access().unwrap();
    assert_eq!(store.key_lease_failure_class(), None);
    clock.advance(Duration::from_secs(1));
    assert!(store.check_access().is_err());
    assert_eq!(store.key_lease_failure_class(), Some("lease_expired"));
    assert!(store.state.read().keys.is_empty());
    assert!(
        TenantStore::open_existing_fixture_with_clock(
            store.node.clone(),
            "tenant-a".into(),
            provider,
            clock
        )
        .await
        .is_err()
    );
    store.refresh_lease().await.unwrap();
    store.check_access().unwrap();
    assert_eq!(store.key_lease_failure_class(), None);
}

struct DelayedProvider {
    inner: LocalKeyProvider,
    delayed: AtomicBool,
    started: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
impl DelayedProvider {
    fn new() -> Self {
        Self {
            inner: LocalKeyProvider::new([63; 32]),
            delayed: AtomicBool::new(false),
            started: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        }
    }
}
#[async_trait]
impl KeyProvider for DelayedProvider {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        self.inner.generate_key(tenant).await
    }
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        if self.delayed.swap(false, Ordering::SeqCst) {
            self.started.notify_one();
            self.resume.notified().await;
        }
        self.inner.unwrap_key(tenant, wrapped).await
    }
    async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey> {
        self.inner.rewrap_key(tenant, wrapped).await
    }
}

#[tokio::test]
async fn delayed_probe_cannot_extend_a_lease_past_sixty_seconds_from_start() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let dir = crate::test_utils::private_tempdir().unwrap();
    let provider = Arc::new(DelayedProvider::new());
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::create_new_fixture(
            dir.path().join("db"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "a".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    provider.delayed.store(true, Ordering::SeqCst);
    let task = {
        let store = store.clone();
        tokio::spawn(async move { store.refresh_lease().await })
    };
    provider.started.notified().await;
    clock.advance(Duration::from_secs(60));
    provider.resume.notify_one();
    assert!(task.await.unwrap().is_err());
    assert_eq!(
        store.key_lease_failure_class(),
        Some("completed_after_expiry")
    );
    assert!(store.check_access().is_err());
    assert_eq!(
        store.key_lease_failure_class(),
        Some("completed_after_expiry")
    );
    assert!(store.state.read().keys.is_empty());
}

#[tokio::test]
async fn a_late_success_cannot_undo_an_explicit_seal() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let dir = crate::test_utils::private_tempdir().unwrap();
    let provider = Arc::new(DelayedProvider::new());
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::create_new_fixture(
            dir.path().join("db"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "a".into(),
        provider.clone(),
        Arc::new(ManualClock::new()),
    )
    .await
    .unwrap();
    provider.delayed.store(true, Ordering::SeqCst);
    let task = {
        let store = store.clone();
        tokio::spawn(async move { store.refresh_lease().await })
    };
    provider.started.notified().await;
    store.seal();
    provider.resume.notify_one();
    assert!(task.await.unwrap().is_err());
    assert!(store.check_access().is_err());
    assert_eq!(store.key_lease_failure_class(), Some("generation_changed"));
}

#[tokio::test]
async fn rewrap_preserves_documents_after_retiring_old_wrapping_versions() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (dir, store, provider, clock) =
        fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    store
        .write_batch(&[WriteOp::put("docs", b"a", b"before rotation")])
        .unwrap();
    provider.rotate();
    store.rewrap_keys().await.unwrap();
    provider.set_minimum_version(2);
    store.refresh_lease().await.unwrap();
    store.shutdown().await.unwrap();
    store.node.shutdown().await.unwrap();
    drop(store);
    let store = TenantStore::open_existing_fixture_with_clock(
        NodeStore::open_existing_fixture(
            dir.path().join("database.kv"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "tenant-a".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(
        store.get("docs", b"a").unwrap().as_deref(),
        Some(b"before rotation".as_slice())
    );
}

#[tokio::test]
async fn every_injected_commit_failure_recovers_whole_batch_or_previous_state() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let backend = FaultBackend::new();
    let provider = Arc::new(LocalKeyProvider::new([51; 32]));
    let clock = Arc::new(ManualClock::new());
    let node = NodeStore::create_with_backend(
        backend.clone(),
        crate::test_utils::storage_admission(),
        fixture_scratch.clone(),
    )
    .unwrap();
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        node,
        "crash".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[
            WriteOp::put("docs", b"a", b"before"),
            WriteOp::put("docs", b"delete", b"present"),
        ])
        .unwrap();
    let baseline = backend.crash();
    let operations = [
        WriteOp::put("docs", b"a", b"after"),
        WriteOp::put("receipts", b"receipt", b"committed"),
        WriteOp::delete("docs", b"delete"),
    ];
    let mut failures = 0;
    let mut acknowledgments = 0;
    for position in 0..128 {
        let backend = baseline.crash();
        let node = NodeStore::open_with_backend(
            backend.clone(),
            crate::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )
        .unwrap();
        let store = TenantStore::open_existing_fixture_with_clock(
            node,
            "crash".into(),
            provider.clone(),
            clock.clone(),
        )
        .await
        .unwrap();
        backend.fail_after(position);
        let result = store.write_batch(&operations);
        let synchronized = backend.crash(); // crash before Drop can flush anything
        backend.disarm();
        drop(store);
        let recovered = TenantStore::open_existing_fixture_with_clock(
            NodeStore::open_with_backend(
                synchronized,
                crate::test_utils::storage_admission(),
                fixture_scratch.clone(),
            )
            .unwrap(),
            "crash".into(),
            provider.clone(),
            clock.clone(),
        )
        .await
        .unwrap();
        let after = recovered.get("docs", b"a").unwrap().as_deref() == Some(b"after".as_slice());
        assert_eq!(
            recovered.get("receipts", b"receipt").unwrap().is_some(),
            after,
            "partial receipt at failure {position}"
        );
        assert_eq!(
            recovered.get("docs", b"delete").unwrap().is_none(),
            after,
            "partial delete at failure {position}"
        );
        if result.is_ok() {
            assert!(after, "acknowledged write lost at failure {position}");
            acknowledgments += 1;
            break;
        }
        failures += 1;
    }
    assert!(
        failures >= 3,
        "must cover both data writes and durable metadata commits"
    );
    assert_eq!(acknowledgments, 1);
}

#[tokio::test]
async fn expiry_watchdog_discards_keys_and_notifies_without_an_incoming_request() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_dir, store, _, clock) = fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    let mut receiver = store.seal_notifications();
    TenantStore::start_renewal(&store).await;
    clock.advance(MAX_KEY_LEASE);
    tokio::time::timeout(Duration::from_secs(3), receiver.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(store.state.read().keys.is_empty());
}

#[tokio::test]
async fn different_tenants_do_not_share_a_slow_key_service_open_gate() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let dir = crate::test_utils::private_tempdir().unwrap();
    let provider = Arc::new(DelayedProvider::new());
    let node = NodeStore::create_new_fixture(
        dir.path().join("db"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .unwrap();
    provider.delayed.store(true, Ordering::SeqCst);
    let first = {
        let node = node.clone();
        let provider = provider.clone();
        tokio::spawn(async move {
            TenantStore::initialize_catalog_fixture_with_clock(
                node,
                "slow".into(),
                provider,
                Arc::new(ManualClock::new()),
            )
            .await
        })
    };
    provider.started.notified().await;
    let second = tokio::time::timeout(
        Duration::from_secs(1),
        TenantStore::initialize_catalog_fixture_with_clock(
            node,
            "fast".into(),
            Arc::new(LocalKeyProvider::new([29; 32])),
            Arc::new(ManualClock::new()),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    second.check_access().unwrap();
    provider.resume.notify_one();
    first.await.unwrap().unwrap().check_access().unwrap();
}

struct BadRewrapProvider(LocalKeyProvider);
#[async_trait]
impl KeyProvider for BadRewrapProvider {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        self.0.generate_key(tenant).await
    }
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        self.0.unwrap_key(tenant, wrapped).await
    }
    async fn rewrap_key(&self, tenant: &str, _wrapped: &WrappedKey) -> Result<WrappedKey> {
        Ok(self.0.generate_key(tenant).await?.wrapped)
    }
}

#[tokio::test]
async fn faulty_provider_rewrap_cannot_replace_data_keys_or_break_recovery() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let dir = crate::test_utils::private_tempdir().unwrap();
    let provider = Arc::new(BadRewrapProvider(LocalKeyProvider::new([30; 32])));
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::create_new_fixture(
            dir.path().join("db"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "t".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[WriteOp::put("docs", b"a", b"still recoverable")])
        .unwrap();
    assert!(
        store
            .rewrap_keys()
            .await
            .unwrap_err()
            .to_string()
            .contains("changed data key")
    );
    store.shutdown().await.unwrap();
    store.node.shutdown().await.unwrap();
    drop(store);
    let store = TenantStore::open_existing_fixture_with_clock(
        NodeStore::open_existing_fixture(
            dir.path().join("db"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "t".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(
        store.get("docs", b"a").unwrap().as_deref(),
        Some(b"still recoverable".as_slice())
    );
}

#[tokio::test]
async fn wrapping_catalog_is_atomic_across_every_injected_commit_failure() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let backend = FaultBackend::new();
    let provider = Arc::new(LocalKeyProvider::new([19; 32]));
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::create_with_backend(
            backend.clone(),
            crate::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "rewrap-crash".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[WriteOp::put("docs", b"a", b"survives key rotation")])
        .unwrap();
    let baseline = backend.crash();
    provider.rotate();
    for position in 0..128 {
        let disk = baseline.crash();
        let store = TenantStore::open_existing_fixture_with_clock(
            NodeStore::open_with_backend(
                disk.clone(),
                crate::test_utils::storage_admission(),
                fixture_scratch.clone(),
            )
            .unwrap(),
            "rewrap-crash".into(),
            provider.clone(),
            clock.clone(),
        )
        .await
        .unwrap();
        disk.fail_after(position);
        let outcome = store.rewrap_keys().await;
        let durable = disk.crash();
        disk.disarm();
        drop(store);
        let recovered = TenantStore::open_existing_fixture_with_clock(
            NodeStore::open_with_backend(
                durable,
                crate::test_utils::storage_admission(),
                fixture_scratch.clone(),
            )
            .unwrap(),
            "rewrap-crash".into(),
            provider.clone(),
            clock.clone(),
        )
        .await
        .unwrap();
        let versions = recovered
            .catalog
            .read()
            .keys
            .values()
            .map(|wrapped| wrapped.version)
            .collect::<Vec<_>>();
        assert!(
            versions.iter().all(|version| *version == versions[0]),
            "partial catalog at failure {position}"
        );
        assert_eq!(
            recovered.get("docs", b"a").unwrap().as_deref(),
            Some(b"survives key rotation".as_slice())
        );
        if outcome.is_ok() {
            assert_eq!(versions[0], 2);
            assert!(position >= 3);
            return;
        }
    }
    panic!("no successful rewrap after all failure positions");
}

#[tokio::test]
async fn expiry_during_fsync_reports_unknown_outcome_and_preserves_committed_batch() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let disk = FaultBackend::new();
    let provider = Arc::new(LocalKeyProvider::new([38; 32]));
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::create_with_backend(
            disk.clone(),
            crate::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "fsync-expiry".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    disk.advance_clock_on_next_sync(clock.clone(), MAX_KEY_LEASE);
    let error = store
        .write_batch(&[
            WriteOp::put("docs", b"a", b"committed"),
            WriteOp::put("receipts", b"r", b"committed"),
        ])
        .unwrap_err();
    assert!(error.to_string().contains("outcome unknown"));
    assert!(store.state.read().keys.is_empty());
    let recovered = TenantStore::open_existing_fixture_with_clock(
        NodeStore::open_with_backend(
            disk.crash(),
            crate::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "fsync-expiry".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(
        recovered.get("docs", b"a").unwrap().as_deref(),
        Some(b"committed".as_slice())
    );
    assert_eq!(
        recovered.get("receipts", b"r").unwrap().as_deref(),
        Some(b"committed".as_slice())
    );
}

#[tokio::test]
async fn expiry_during_key_catalog_fsync_does_not_acknowledge_rotation() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let disk = FaultBackend::new();
    let provider = Arc::new(LocalKeyProvider::new([39; 32]));
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::create_with_backend(
            disk.clone(),
            crate::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "rotation-expiry".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    store
        .write_batch(&[WriteOp::put("docs", b"a", b"old ciphertext")])
        .unwrap();
    disk.advance_clock_on_next_sync(clock.clone(), MAX_KEY_LEASE);
    let error = store.rotate_data_key().await.unwrap_err();
    assert!(error.to_string().contains("outcome unknown"));
    assert!(store.state.read().keys.is_empty());
    let recovered = TenantStore::open_existing_fixture_with_clock(
        NodeStore::open_with_backend(
            disk.crash(),
            crate::test_utils::storage_admission(),
            fixture_scratch.clone(),
        )
        .unwrap(),
        "rotation-expiry".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(recovered.catalog.read().keys.len(), 3);
    assert_eq!(
        recovered.get("docs", b"a").unwrap().as_deref(),
        Some(b"old ciphertext".as_slice())
    );
}

#[tokio::test]
async fn bounded_encrypted_reads_reject_payload_before_plaintext_allocation() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_dir, store, _, _) = fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    store
        .write_batch(&[WriteOp::put("closed-control", b"current", vec![7; 8192])])
        .unwrap();
    let error = store
        .get_bounded("closed-control", b"current", 8191)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("encrypted record exceeds read budget")
    );
    assert_eq!(
        store
            .get_bounded("closed-control", b"current", 8192)
            .unwrap()
            .unwrap(),
        vec![7; 8192]
    );
    let mut visited = false;
    assert!(
        store
            .visit("closed-control", 64, |_, _| {
                visited = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!visited);
    assert!(
        store
            .get_bounded("closed-control", b"absent", 64)
            .unwrap()
            .is_none()
    );
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn completed_shutdown_allows_distinct_store_without_reviving_retained_handles() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, original, provider, clock) =
        fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    original
        .write_batch(&[WriteOp::Put {
            namespace: "docs".into(),
            key: b"retained".to_vec(),
            value: b"durable".to_vec(),
        }])
        .unwrap();
    let retained = original.clone();
    original.seal();
    assert!(
        TenantStore::open_existing_fixture_with_clock(
            original.node.clone(),
            original.tenant.clone(),
            provider.clone(),
            clock.clone()
        )
        .await
        .is_err()
    );
    original.shutdown().await.unwrap();
    let fresh = TenantStore::open_existing_fixture_with_clock(
        original.node.clone(),
        original.tenant.clone(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert!(!Arc::ptr_eq(&fresh, &original));
    assert_eq!(
        fresh.get("docs", b"retained").unwrap().as_deref(),
        Some(b"durable".as_slice())
    );
    assert!(retained.get("docs", b"retained").is_err());
    original.shutdown().await.unwrap();
    assert_eq!(
        fresh.get("docs", b"retained").unwrap().as_deref(),
        Some(b"durable".as_slice())
    );
    fresh.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn node_files_are_private_nofollow_and_keep_exclusive_database_ownership() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = crate::test_utils::private_tempdir().unwrap();
    let directory = root.path().join("private");
    crate::private_files::create_directory(&directory).unwrap();
    let path = directory.join("node.kv");
    let node = NodeStore::create_new_fixture(
        &path,
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .unwrap();
    let root_file = path.join(kasumi_kv::ROOT_FILE_NAME);
    let metadata = std::fs::symlink_metadata(&path).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    for file in crate::test_utils::node_group_files(&path) {
        assert_eq!(
            std::fs::symlink_metadata(&file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "{}",
            file.display()
        );
    }
    assert!(
        NodeStore::open_existing_fixture(
            &path,
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    assert!(crate::private_files::ExclusiveLock::acquire(&root_file).is_err());
    node.shutdown().await.unwrap();
    drop(node);
    let cleanup_lock = crate::private_files::ExclusiveLock::acquire(&root_file).unwrap();
    assert!(
        NodeStore::open_existing_fixture(
            &path,
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    drop(cleanup_lock);
    let alias = directory.join("alias.kv");
    symlink(&path, &alias).unwrap();
    assert!(
        NodeStore::open_existing_fixture(
            &alias,
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    // A new census rejects every symlink in the installed root, even when
    // reopening a different file. Remove the deliberately invalid fixture.
    std::fs::remove_file(&alias).unwrap();
    std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let original = std::fs::read(&root_file).unwrap();
    assert!(
        NodeStore::open_existing_fixture(
            &path,
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    assert_eq!(original, std::fs::read(&root_file).unwrap());
    std::fs::set_permissions(&root_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let reopened = NodeStore::open_existing_fixture(
        &path,
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .unwrap();
    assert!(crate::private_files::ExclusiveLock::acquire(&root_file).is_err());
    reopened.shutdown().await.unwrap();
}

#[tokio::test]
async fn pinned_read_roots_and_streamed_namespace_publication_preserve_isolation() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, store, _, _) = fixture(fixture_memory.clone(), fixture_scratch.clone()).await;
    store
        .write_batch(&[
            WriteOp::put("authority", b"old", b"original"),
            WriteOp::put("unrelated", b"key", b"must-stay"),
        ])
        .unwrap();
    let pinned = store.read_view().unwrap();
    let staged = EncryptedTable::new(
        &fixture_scratch.clone(),
        64 << 20,
        fixture_scratch.clone().native_cache_config(),
    )
    .unwrap();
    staged.insert(b"new", b"replacement").unwrap();
    assert!(staged.insert(b"new", b"substituted").is_err());
    store
        .replace_namespaces(
            &[NamespaceReplacement::from_table("authority", &staged)],
            &[WriteOp::put("meta", b"position", b"new")],
        )
        .unwrap();
    assert_eq!(
        pinned.get("authority", b"old", 1024).unwrap().unwrap(),
        b"original"
    );
    assert!(pinned.get("authority", b"new", 1024).unwrap().is_none());
    assert!(pinned.get("meta", b"position", 1024).unwrap().is_none());
    assert_eq!(store.get("meta", b"position").unwrap().unwrap(), b"new");
    assert!(
        store
            .replace_namespaces(
                &[NamespaceReplacement::from_table("authority", &staged)],
                &[WriteOp::put("authority", b"unexpected", b"overlap")]
            )
            .is_err()
    );
    assert!(
        store
            .replace_namespaces(
                &[
                    NamespaceReplacement::from_table("authority", &staged),
                    NamespaceReplacement::from_table("authority", &staged)
                ],
                &[]
            )
            .is_err()
    );
    assert!(store.get("authority", b"old").unwrap().is_none());
    assert_eq!(
        store.get("authority", b"new").unwrap().unwrap(),
        b"replacement"
    );
    assert_eq!(
        store.get("unrelated", b"key").unwrap().unwrap(),
        b"must-stay"
    );
    assert!(
        store
            .replace_namespaces(&[NamespaceReplacement::from_table("", &staged)], &[])
            .is_err()
    );
    assert_eq!(
        store.get("authority", b"new").unwrap().unwrap(),
        b"replacement"
    );
    store.seal();
    assert!(pinned.get("authority", b"old", 1024).is_err());
}

#[tokio::test]
async fn separate_node_stores_and_pinned_reads_share_one_scratch_budget() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::open_fixture(
        &ScratchDiskConfig {
            directory: directory.path().join("scratch"),
            max_bytes: 192 << 10,
            min_free_bytes: 0,
            native_cache_bytes: 8 << 20,
        },
        fixture_memory.clone(),
    )
    .unwrap();
    let first = NodeStore::create_new_fixture(
        directory.path().join("application.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        disk.clone(),
    )
    .unwrap();
    let second = NodeStore::create_new_fixture(
        directory.path().join("trust.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        disk.clone(),
    )
    .unwrap();
    let store = TenantStore::initialize_catalog_fixture(
        first.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([73; 32])),
    )
    .await
    .unwrap();
    let view = store.read_view().unwrap();
    assert!(Arc::ptr_eq(first.scratch_disk(), second.scratch_disk()));
    assert!(Arc::ptr_eq(view.scratch_disk(), &disk));
    let image = SnapshotImage::from_bytes(view.scratch_disk(), &[17; 128 << 10]).unwrap();
    let retained = image.reader();
    let charge = disk.snapshot().charged_bytes;
    assert!(charge > 128 << 10);
    assert!(SnapshotImage::from_bytes(second.scratch_disk(), &[29; 128 << 10]).is_err());
    assert_eq!(disk.snapshot().charged_bytes, charge);
    drop(image);
    drop(view);
    drop(store);
    drop(first);
    assert_eq!(disk.snapshot().charged_bytes, charge);
    drop(retained);
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().live_files, 0);
    let retry = SnapshotImage::from_bytes(second.scratch_disk(), &[29; 128 << 10]).unwrap();
    drop(retry);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[tokio::test]
async fn explicit_empty_namespace_clears_atomically_without_scratch_and_keeps_pinned_root() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let (_directory, store, _, _) = fixture(memory, scratch.clone()).await;
    store
        .write_batch(&[
            WriteOp::put("authority", b"old", b"original"),
            WriteOp::put("unrelated", b"key", b"must-stay"),
            WriteOp::put("meta", b"position", b"old"),
        ])
        .unwrap();
    let pinned = store.read_view().unwrap();
    let before = scratch.snapshot();
    store
        .replace_namespaces(
            &[NamespaceReplacement::empty("authority")],
            &[WriteOp::put("meta", b"position", b"new")],
        )
        .unwrap();
    let after = scratch.snapshot();
    assert_eq!(after.live_files, before.live_files);
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert!(store.get("authority", b"old").unwrap().is_none());
    assert_eq!(store.get("meta", b"position").unwrap().unwrap(), b"new");
    assert_eq!(
        store.get("unrelated", b"key").unwrap().unwrap(),
        b"must-stay"
    );
    assert_eq!(
        pinned.get("authority", b"old", 1024).unwrap().unwrap(),
        b"original"
    );
    assert_eq!(
        pinned.get("meta", b"position", 1024).unwrap().unwrap(),
        b"old"
    );

    // An omitted replacement retains the namespace even when metadata changes.
    store
        .replace_namespaces(&[], &[WriteOp::put("meta", b"position", b"newer")])
        .unwrap();
    assert_eq!(
        store.get("unrelated", b"key").unwrap().unwrap(),
        b"must-stay"
    );
    let empty = EncryptedTable::new(&scratch, 8 << 20, scratch.native_cache_config()).unwrap();
    for replacements in [
        vec![NamespaceReplacement::empty("")],
        vec![
            NamespaceReplacement::empty("unrelated"),
            NamespaceReplacement::empty("unrelated"),
        ],
        vec![
            NamespaceReplacement::empty("unrelated"),
            NamespaceReplacement::from_table("unrelated", &empty),
        ],
    ] {
        assert!(store.replace_namespaces(&replacements, &[]).is_err());
    }
    assert!(
        store
            .replace_namespaces(
                &[NamespaceReplacement::empty("unrelated")],
                &[WriteOp::put("unrelated", b"key", b"overlap")],
            )
            .is_err()
    );
    assert_eq!(
        store.get("unrelated", b"key").unwrap().unwrap(),
        b"must-stay"
    );
    empty.close().unwrap();
    store.seal();
    assert!(pinned.get("authority", b"old", 1024).is_err());
}
