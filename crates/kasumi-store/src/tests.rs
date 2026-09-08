use super::*;
use crate::test_utils::{FaultBackend, LocalKeyProvider, ManualClock};
use async_trait::async_trait;
use std::sync::atomic::{AtomicBool, Ordering};

async fn fixture() -> (
    tempfile::TempDir,
    Arc<TenantStore>,
    Arc<LocalKeyProvider>,
    Arc<ManualClock>,
) {
    let dir = tempfile::tempdir().unwrap();
    let node = NodeStore::open(dir.path().join("database.redb")).unwrap();
    let provider = Arc::new(LocalKeyProvider::new([41; 32]));
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::open_fixture_with_clock(
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
    let directory = tempfile::tempdir().unwrap();
    let provider = Arc::new(Delayed {
        inner: LocalKeyProvider::new([71; 32]),
        delay: AtomicBool::new(false),
        starts: std::sync::Mutex::new(Vec::new()),
    });
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open(directory.path().join("cadence.redb")).unwrap(),
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
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("shutdown.redb");
    let node = NodeStore::open(&path).unwrap();
    let weak_node = Arc::downgrade(&node);
    let provider = Arc::new(Blocked {
        inner: LocalKeyProvider::new([39; 32]),
        block: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        canceled: std::sync::atomic::AtomicUsize::new(0),
    });
    let store = TenantStore::open_fixture_with_clock(
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

    // This current-thread runtime cannot poll the aborted probe while shutdown
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

    store.shutdown().await;
    assert_eq!(provider.canceled.load(Ordering::Acquire), 1);
    assert!(store.background.lock().await.handles.is_empty());
    assert_eq!(weak_store.strong_count(), 1);
    TenantStore::start_renewal(&store).await;
    assert!(store.background.lock().await.handles.is_empty());
    tokio::join!(store.shutdown(), store.shutdown());
    drop(store);
    assert!(weak_store.upgrade().is_none());
    assert!(weak_node.upgrade().is_none());

    // Reopen immediately: completion, rather than a file-lock retry or sleep,
    // proves no background owner can retain the previous redb database.
    provider.block.store(false, Ordering::Release);
    let reopened = TenantStore::open_fixture_with_clock(
        NodeStore::open(&path).unwrap(),
        "shutdown".into(),
        provider,
        Arc::new(ManualClock::new()),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.get("documents", b"durable").unwrap(),
        Some(b"value".to_vec())
    );
    reopened.shutdown().await;
}

#[tokio::test]
async fn shutdown_fences_a_waiting_background_task_registration() {
    let (_directory, store, _provider, _clock) = fixture().await;
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
    shutdown.await;
    starter.await.unwrap();
    assert!(store.background.lock().await.handles.is_empty());
    assert!(!store.background.lock().await.started);
    assert!(store.check_access().is_err());
}

#[tokio::test]
async fn atomic_batches_and_cross_namespace_isolation_survive_reopen() {
    let (dir, store, provider, clock) = fixture().await;
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
    let same = TenantStore::open_fixture_with_clock(
        store.node.clone(),
        "tenant-a".into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    assert!(Arc::ptr_eq(&same, &store));
    let other = TenantStore::open_fixture_with_clock(
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
    drop(store);
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open(dir.path().join("database.redb")).unwrap(),
        "tenant-a".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(store.get("documents", b"a").unwrap(), Some(b"one".to_vec()));
    assert_eq!(
        store.get("receipts", b"a").unwrap(),
        Some(b"receipt".to_vec())
    );
    assert!(store.get("documents", b"gone").unwrap().is_none());
}

#[tokio::test]
async fn invalid_batch_does_not_apply_earlier_operations() {
    let (_dir, store, _, _) = fixture().await;
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
        store.get("documents", b"a").unwrap(),
        Some(b"before".to_vec())
    );
    assert!(
        store
            .write_batch(&[WriteOp::put("documents", vec![0; 4097], b"bad")])
            .is_err()
    );
}

#[tokio::test]
async fn names_keys_and_values_are_absent_from_disk_and_nonce_changes_on_overwrite() {
    let (dir, store, _, _) = fixture().await;
    let ns = "secret-collection-75aa0b497f";
    let key = b"sensitive-document-key-cb3c328";
    let value = b"secret-document-value-d75ab117818c";
    store.write_batch(&[WriteOp::put(ns, key, value)]).unwrap();
    let read_raw = || {
        let state = store.state.read();
        let disk_key = record_key(store.tenant(), ns, key, state.keys.get(INDEX_KEY).unwrap());
        let tx = store.node.db.begin_read().unwrap();
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
    let bytes = std::fs::read(dir.path().join("database.redb")).unwrap();
    for secret in [ns.as_bytes(), key.as_slice(), value.as_slice()] {
        assert!(!bytes.windows(secret.len()).any(|window| window == secret));
    }
}

#[tokio::test]
async fn ciphertext_corruption_swapping_and_wrong_tenant_are_rejected() {
    let (_dir, store, provider, clock) = fixture().await;
    let other = TenantStore::open_fixture_with_clock(
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
    let tx = store.node.db.begin_read().unwrap();
    let table = tx.open_table(RECORDS).unwrap();
    let original = table.get(a.as_slice()).unwrap().unwrap().value().to_vec();
    drop(table);
    drop(tx);
    let raw_write = |key: &[u8], bytes: &[u8]| {
        let tx = store.node.db.begin_write().unwrap();
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
    let (_dir, store, provider, _) = fixture().await;
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
    provider.set_minimum_version(2);
    let mut seal = store.seal_notifications();
    assert!(store.refresh_lease().await.is_err());
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
    let (_dir, store, provider, clock) = fixture().await;
    clock.advance(Duration::from_secs(59));
    store.check_access().unwrap();
    clock.advance(Duration::from_secs(1));
    assert!(store.check_access().is_err());
    assert!(store.state.read().keys.is_empty());
    assert!(
        TenantStore::open_fixture_with_clock(
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
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(DelayedProvider::new());
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open(dir.path().join("db")).unwrap(),
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
    assert!(store.check_access().is_err());
    assert!(store.state.read().keys.is_empty());
}

#[tokio::test]
async fn a_late_success_cannot_undo_an_explicit_seal() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(DelayedProvider::new());
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open(dir.path().join("db")).unwrap(),
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
}

#[tokio::test]
async fn rewrap_preserves_documents_after_retiring_old_wrapping_versions() {
    let (dir, store, provider, clock) = fixture().await;
    store
        .write_batch(&[WriteOp::put("docs", b"a", b"before rotation")])
        .unwrap();
    provider.rotate();
    store.rewrap_keys().await.unwrap();
    provider.set_minimum_version(2);
    store.refresh_lease().await.unwrap();
    drop(store);
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open(dir.path().join("database.redb")).unwrap(),
        "tenant-a".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(
        store.get("docs", b"a").unwrap(),
        Some(b"before rotation".to_vec())
    );
}

#[tokio::test]
async fn every_injected_commit_failure_recovers_whole_batch_or_previous_state() {
    let backend = FaultBackend::new();
    let provider = Arc::new(LocalKeyProvider::new([51; 32]));
    let clock = Arc::new(ManualClock::new());
    let node = NodeStore::open_with_backend(backend.clone()).unwrap();
    let store =
        TenantStore::open_fixture_with_clock(node, "crash".into(), provider.clone(), clock.clone())
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
        let node = NodeStore::open_with_backend(backend.clone()).unwrap();
        let store = TenantStore::open_fixture_with_clock(
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
        let recovered = TenantStore::open_fixture_with_clock(
            NodeStore::open_with_backend(synchronized).unwrap(),
            "crash".into(),
            provider.clone(),
            clock.clone(),
        )
        .await
        .unwrap();
        let after = recovered.get("docs", b"a").unwrap() == Some(b"after".to_vec());
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
    let (_dir, store, _, clock) = fixture().await;
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
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(DelayedProvider::new());
    let node = NodeStore::open(dir.path().join("db")).unwrap();
    provider.delayed.store(true, Ordering::SeqCst);
    let first = {
        let node = node.clone();
        let provider = provider.clone();
        tokio::spawn(async move {
            TenantStore::open_fixture_with_clock(
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
        TenantStore::open_fixture_with_clock(
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
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(BadRewrapProvider(LocalKeyProvider::new([30; 32])));
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open(dir.path().join("db")).unwrap(),
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
    drop(store);
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open(dir.path().join("db")).unwrap(),
        "t".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(
        store.get("docs", b"a").unwrap(),
        Some(b"still recoverable".to_vec())
    );
}

#[tokio::test]
async fn wrapping_catalog_is_atomic_across_every_injected_commit_failure() {
    let backend = FaultBackend::new();
    let provider = Arc::new(LocalKeyProvider::new([19; 32]));
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open_with_backend(backend.clone()).unwrap(),
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
        let store = TenantStore::open_fixture_with_clock(
            NodeStore::open_with_backend(disk.clone()).unwrap(),
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
        let recovered = TenantStore::open_fixture_with_clock(
            NodeStore::open_with_backend(durable).unwrap(),
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
            recovered.get("docs", b"a").unwrap(),
            Some(b"survives key rotation".to_vec())
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
    let disk = FaultBackend::new();
    let provider = Arc::new(LocalKeyProvider::new([38; 32]));
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open_with_backend(disk.clone()).unwrap(),
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
    let recovered = TenantStore::open_fixture_with_clock(
        NodeStore::open_with_backend(disk.crash()).unwrap(),
        "fsync-expiry".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(
        recovered.get("docs", b"a").unwrap(),
        Some(b"committed".to_vec())
    );
    assert_eq!(
        recovered.get("receipts", b"r").unwrap(),
        Some(b"committed".to_vec())
    );
}

#[tokio::test]
async fn expiry_during_key_catalog_fsync_does_not_acknowledge_rotation() {
    let disk = FaultBackend::new();
    let provider = Arc::new(LocalKeyProvider::new([39; 32]));
    let clock = Arc::new(ManualClock::new());
    let store = TenantStore::open_fixture_with_clock(
        NodeStore::open_with_backend(disk.clone()).unwrap(),
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
    let recovered = TenantStore::open_fixture_with_clock(
        NodeStore::open_with_backend(disk.crash()).unwrap(),
        "rotation-expiry".into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert_eq!(recovered.catalog.read().keys.len(), 3);
    assert_eq!(
        recovered.get("docs", b"a").unwrap(),
        Some(b"old ciphertext".to_vec())
    );
}

#[tokio::test]
async fn bounded_encrypted_reads_reject_payload_before_plaintext_allocation() {
    let (_dir, store, _, _) = fixture().await;
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
    store.shutdown().await;
}

#[tokio::test]
async fn completed_shutdown_allows_distinct_store_without_reviving_retained_handles() {
    let (_directory, original, provider, clock) = fixture().await;
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
        TenantStore::open_fixture_with_clock(
            original.node.clone(),
            original.tenant.clone(),
            provider.clone(),
            clock.clone()
        )
        .await
        .is_err()
    );
    original.shutdown().await;
    let fresh = TenantStore::open_fixture_with_clock(
        original.node.clone(),
        original.tenant.clone(),
        provider,
        clock,
    )
    .await
    .unwrap();
    assert!(!Arc::ptr_eq(&fresh, &original));
    assert_eq!(
        fresh.get("docs", b"retained").unwrap(),
        Some(b"durable".to_vec())
    );
    assert!(retained.get("docs", b"retained").is_err());
    original.shutdown().await;
    assert_eq!(
        fresh.get("docs", b"retained").unwrap(),
        Some(b"durable".to_vec())
    );
    fresh.shutdown().await;
}

#[cfg(unix)]
#[test]
fn node_files_are_private_nofollow_and_keep_exclusive_database_ownership() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("private");
    crate::private_files::create_directory(&directory).unwrap();
    let path = directory.join("node.redb");
    let node = NodeStore::open(&path).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(NodeStore::open(&path).is_err());
    assert!(crate::private_files::ExclusiveLock::acquire(&path).is_err());
    drop(node);
    let cleanup_lock = crate::private_files::ExclusiveLock::acquire(&path).unwrap();
    assert!(NodeStore::open(&path).is_err());
    drop(cleanup_lock);
    let alias = directory.join("alias.redb");
    symlink(&path, &alias).unwrap();
    assert!(NodeStore::open(&alias).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let original = std::fs::read(&path).unwrap();
    assert!(NodeStore::open(&path).is_err());
    assert_eq!(original, std::fs::read(&path).unwrap());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(NodeStore::open(&path).is_ok());
}

#[tokio::test]
async fn pinned_read_roots_and_streamed_namespace_publication_preserve_isolation() {
    let (_directory, store, _, _) = fixture().await;
    store
        .write_batch(&[
            WriteOp::put("authority", b"old", b"original"),
            WriteOp::put("unrelated", b"key", b"must-stay"),
        ])
        .unwrap();
    let pinned = store.read_view().unwrap();
    let staged = EncryptedTable::new(64 << 20).unwrap();
    staged.insert(b"new", b"replacement").unwrap();
    assert!(staged.insert(b"new", b"substituted").is_err());
    store
        .replace_namespaces(
            &[("authority", &staged)],
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
                &[("authority", &staged)],
                &[WriteOp::put("authority", b"unexpected", b"overlap")]
            )
            .is_err()
    );
    assert!(
        store
            .replace_namespaces(&[("authority", &staged), ("authority", &staged)], &[])
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
    assert!(store.replace_namespaces(&[("", &staged)], &[]).is_err());
    assert_eq!(
        store.get("authority", b"new").unwrap().unwrap(),
        b"replacement"
    );
    store.seal();
    assert!(pinned.get("authority", b"old", 1024).is_err());
}
