use super::*;
use crate::test_utils::LocalKeyProvider;
use std::{future::Future, task::Poll};

fn node(
    fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>,
    fixture_scratch: std::sync::Arc<crate::ScratchDisk>,
) -> Result<(tempfile::TempDir, NodeStore)> {
    let directory = crate::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        directory.path().join("catalogs.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .expect("bounded node fixture setup succeeds");
    Ok((directory, node))
}

fn input(node: NodeStore) -> Input {
    Input {
        node,
        tenant: "new-tenant".into(),
        application_provider: Arc::new(LocalKeyProvider::new([51; 32])),
        custody_provider: Arc::new(LocalKeyProvider::new([52; 32])),
        application_access: StorageAccess::fixture(),
    }
}

async fn drain(node: &NodeStore) -> std::result::Result<(), crate::InitializerDrainFailure> {
    tokio::time::timeout(Duration::from_secs(10), node.drain_initializers())
        .await
        .expect("actual original initializer settles within the same fixture deadline")
}

#[tokio::test]
async fn first_failed_catalog_join_keeps_original_and_remaining_handle_until_explicit_disposition()
-> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let (release, waiting) = oneshot::channel::<()>();
    let owned = node.clone();
    let pending = tokio::spawn(async move {
        let _owned = owned;
        waiting.await.unwrap();
        Ok(())
    });
    let pending_id = pending.id();
    let failed: tokio::task::JoinHandle<Result<()>> =
        tokio::spawn(async { panic!("catalog owner panic before cancelled drain") });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !failed.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    node.body()
        .initializers
        .lock()
        .await
        .handles
        .extend([pending, failed]);
    let before = fixture_memory.snapshot();
    let failure = tokio::time::timeout(Duration::from_secs(5), node.drain_initializers())
        .await?
        .unwrap_err();
    let original = failure
        .with_report(|report| {
            let original = report.join_error().expect("the exact failed joined task");
            assert!(original.is_panic());
            assert!(
                original
                    .to_string()
                    .contains("catalog owner panic before cancelled drain")
            );
            assert!(matches!(
                report.handle_disposal(),
                TerminalObservation::Returned(Ok(()))
            ));
            assert!(matches!(
                report.original_disposal(),
                TerminalObservation::NotEntered
            ));
            std::ptr::from_ref(original) as usize
        })
        .await;
    {
        let registry = node.body().initializers.lock().await;
        assert_eq!(registry.handles.len(), 1);
        assert_eq!(registry.handles[0].id(), pending_id);
        assert!(!registry.handles[0].is_finished());
    }
    let repeated = node.drain_initializers().await.unwrap_err();
    assert_eq!(repeated.opening_id(), failure.opening_id());
    repeated
        .with_report(|report| {
            assert_eq!(
                std::ptr::from_ref(report.join_error().unwrap()) as usize,
                original
            );
        })
        .await;
    assert_eq!(fixture_memory.snapshot(), before);
    assert!(failure.dispose_original().await);
    drop(repeated);
    drop(failure);
    release.send(()).unwrap();
    drain(&node)
        .await
        .map_err(|original| anyhow::Error::new(original.observation()))?;
    assert!(node.body().initializers.lock().await.handles.is_empty());
    assert!(node.body().initializers.lock().await.completion.is_none());
    node.shutdown().await.unwrap();
    assert!(node.retire().is_retired());
    Ok(())
}

async fn assert_unpublished(node: &NodeStore) {
    for tenant in [
        "new-tenant".to_owned(),
        CustodyStore::catalog_name("new-tenant"),
    ] {
        let gate = node
            .body()
            .tenants
            .lock()
            .await
            .get(&tenant)
            .unwrap()
            .clone();
        assert!(gate.lock().await.upgrade().is_none());
    }
}

fn contents(node: &NodeStore) -> Result<Vec<u8>> {
    let tx = node.body().db.begin_read()?;
    let mut hash = Sha256::new();
    for (index, definition) in [CATALOG, RECORDS].into_iter().enumerate() {
        hash.update((index as u64).to_be_bytes());
        for row in tx.open_table(definition)?.iter()? {
            let (key, value) = row?;
            hash.update((key.value().len() as u64).to_be_bytes());
            hash.update(key.value());
            hash.update((value.value().len() as u64).to_be_bytes());
            hash.update(value.value());
        }
    }
    Ok(hash.finalize().to_vec())
}

#[tokio::test]
async fn buffered_unclaimed_ticket_drains_only_unpublished_new_owners() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let (send, receive) = oneshot::channel();
    let prepared = prepare(input(node.clone()), &send).await?;
    let observed = prepared.stores.clone();
    let delivery = deliver(Ok(prepared), send);
    tokio::pin!(delivery);
    // Execute the successful send and stop while the ticket is still buffered;
    // this models a caller cancelled before its receive future polls again.
    std::future::poll_fn(|context| {
        assert!(delivery.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        observed.application.background.lock().await.handles.len(),
        2
    );
    assert_eq!(
        observed.custody.store.background.lock().await.handles.len(),
        2
    );
    drop(receive);
    tokio::time::timeout(Duration::from_secs(10), delivery).await??;
    assert_unpublished(&node).await;
    assert!(observed.application.check_access().is_err());
    assert!(observed.custody.store.check_access().is_err());
    assert!(
        observed
            .application
            .background
            .lock()
            .await
            .handles
            .is_empty()
    );
    assert!(
        observed
            .custody
            .store
            .background
            .lock()
            .await
            .handles
            .is_empty()
    );
    // Cancellation did not erase or adopt the permanently written catalogs.
    let before = contents(&node)?;
    assert!(
        TenantStorageSet::initialize_catalogs(
            node.clone(),
            "new-tenant".into(),
            Arc::new(LocalKeyProvider::new([51; 32])),
            Arc::new(LocalKeyProvider::new([52; 32])),
            StorageAccess::fixture(),
        )
        .await
        .is_err()
    );
    drain(&node)
        .await
        .map_err(|original| anyhow::Error::new(original.observation()))?;
    assert_eq!(contents(&node)?, before);
    Ok(())
}

#[tokio::test]
async fn committed_pair_handoff_preserves_a_concurrent_borrower_through_initializer_drain()
-> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let ticket =
        tokio::time::timeout(Duration::from_secs(10), begin(input(node.clone())).await?).await??;
    let opening = TenantStore::open_existing_fixture(
        node.clone(),
        "new-tenant".into(),
        Arc::new(LocalKeyProvider::new([51; 32])),
    );
    tokio::pin!(opening);
    std::future::poll_fn(|context| {
        assert!(opening.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    let stores = ticket.claim()?;
    let borrower = tokio::time::timeout(Duration::from_secs(10), opening).await??;
    assert!(Arc::ptr_eq(&borrower, stores.application()));
    drain(&node)
        .await
        .map_err(|original| anyhow::Error::new(original.observation()))?;
    stores.check_access()?;
    borrower.write_batch(&[WriteOp::put("data", b"key", b"value".to_vec())])?;
    assert_eq!(
        stores.application.get("data", b"key")?.as_deref(),
        Some(b"value".as_slice())
    );
    stores.shutdown().await.unwrap();
    drop(borrower);
    drop(stores);
    // The ordinary existing opener retains the exact pair/binding after drain.
    let reopened = TenantStorageSet::open_existing_fixture(
        node.clone(),
        "new-tenant".into(),
        Arc::new(LocalKeyProvider::new([51; 32])),
        Arc::new(LocalKeyProvider::new([52; 32])),
    )
    .await?;
    assert_eq!(
        reopened.application.get("data", b"key")?.as_deref(),
        Some(b"value".as_slice())
    );
    reopened.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn fresh_pair_rejects_shared_partial_and_orphan_domains_without_mutation() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    for existing_custody in [false, true] {
        let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
        let name = if existing_custody {
            CustodyStore::catalog_name("new-tenant")
        } else {
            "new-tenant".to_owned()
        };
        let live = TenantStore::initialize_catalog_fixture(
            node.clone(),
            name,
            Arc::new(LocalKeyProvider::new([51; 32])),
        )
        .await?;
        live.write_batch(&[WriteOp::put("kept", b"key", b"retained".to_vec())])?;
        let before = contents(&node)?;
        let receive = begin(input(node.clone())).await?;
        assert!(
            tokio::time::timeout(Duration::from_secs(10), receive)
                .await??
                .claim()
                .is_err()
        );
        drain(&node)
            .await
            .map_err(|original| anyhow::Error::new(original.observation()))?;
        assert_eq!(contents(&node)?, before);
        assert_eq!(
            live.get("kept", b"key")?.as_deref(),
            Some(b"retained".as_slice())
        );
        live.shutdown().await.unwrap();
        drop(live);
        // The same partial disk catalog is rejected after its live owner drains.
        let receive = begin(input(node.clone())).await?;
        assert!(
            tokio::time::timeout(Duration::from_secs(10), receive)
                .await??
                .claim()
                .is_err()
        );
        drain(&node)
            .await
            .map_err(|original| anyhow::Error::new(original.observation()))?;
        assert_eq!(contents(&node)?, before);
    }
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let tx = node.body().db.begin_write()?;
    tx.open_table(RECORDS)?
        .insert(tenant_hash("new-tenant").as_slice(), b"unknown".as_slice())?;
    tx.commit()?;
    let before = contents(&node)?;
    let receive = begin(input(node.clone())).await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(10), receive)
            .await??
            .claim()
            .is_err()
    );
    drain(&node)
        .await
        .map_err(|original| anyhow::Error::new(original.observation()))?;
    assert_eq!(contents(&node)?, before);
    Ok(())
}

struct PausedProvider {
    provider: LocalKeyProvider,
    entered: Notify,
    resume: Notify,
    active: AtomicBool,
}

#[async_trait::async_trait]
impl KeyProvider for PausedProvider {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        self.active.store(true, Ordering::Release);
        self.entered.notify_one();
        self.resume.notified().await;
        self.active.store(false, Ordering::Release);
        self.provider.generate_key(tenant).await
    }
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        self.provider.unwrap_key(tenant, wrapped).await
    }
    async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey> {
        self.provider.rewrap_key(tenant, wrapped).await
    }
}

#[tokio::test]
async fn cancelled_receiver_keeps_preparation_registered_until_actual_provider_work_drains()
-> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let provider = Arc::new(PausedProvider {
        provider: LocalKeyProvider::new([51; 32]),
        entered: Notify::new(),
        resume: Notify::new(),
        active: AtomicBool::new(false),
    });
    let mut request = input(node.clone());
    request.application_provider = provider.clone();
    let receive = begin(request).await?;
    tokio::time::timeout(Duration::from_secs(10), provider.entered.notified()).await?;
    assert!(provider.active.load(Ordering::Acquire));
    drop(receive);
    let draining = drain(&node);
    tokio::pin!(draining);
    std::future::poll_fn(|context| {
        assert!(draining.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    // Both finite key generation calls remain owned; permit them separately.
    provider.resume.notify_one();
    tokio::time::timeout(Duration::from_secs(10), provider.entered.notified()).await?;
    provider.resume.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(10), draining)
        .await?
        .unwrap_err();
    crate::test_utils::inspect_and_dispose_initializer(&error, |original| {
        assert!(format!("{original:#}").contains("catalog initialization receiver closed"));
    })
    .await;
    drop(error);
    drain(&node)
        .await
        .map_err(|original| anyhow::Error::new(original.observation()))?;
    assert!(!provider.active.load(Ordering::Acquire));
    assert!(node.catalog("new-tenant")?.is_none());
    assert!(
        node.catalog(&CustodyStore::catalog_name("new-tenant"))?
            .is_none()
    );
    assert_unpublished(&node).await;
    Ok(())
}

#[derive(Debug)]
struct PreparationFailure;
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("injected fresh catalog preparation failure")
    }
}
impl std::error::Error for PreparationFailure {}
struct FailingProvider;
#[async_trait::async_trait]
impl KeyProvider for FailingProvider {
    async fn generate_key(&self, _: &str) -> Result<GeneratedKey> {
        Err(PreparationFailure.into())
    }
    async fn unwrap_key(&self, _: &str, _: &WrappedKey) -> Result<SecretKey> {
        anyhow::bail!("fresh preparation unexpectedly reached unwrap")
    }
    async fn rewrap_key(&self, _: &str, _: &WrappedKey) -> Result<WrappedKey> {
        anyhow::bail!("fresh preparation unexpectedly reached rewrap")
    }
}

/// Register the real preparation/delivery work, then stop after its channel send
/// while the error ticket is still buffered. Only the test's notification is new.
async fn buffered_failure(node: &NodeStore) -> Result<oneshot::Receiver<Ticket>> {
    let (send, receive) = oneshot::channel();
    let buffered = Arc::new(Notify::new());
    let sent = buffered.clone();
    let mut request = input(node.clone());
    request.application_provider = Arc::new(FailingProvider);
    let task = tokio::spawn(async move {
        let outcome = prepare(request, &send).await;
        assert!(outcome.as_ref().err().unwrap().is::<PreparationFailure>());
        let delivery = deliver(outcome, send);
        tokio::pin!(delivery);
        std::future::poll_fn(|context| {
            assert!(delivery.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        sent.notify_one();
        delivery.await
    });
    node.body().initializers.lock().await.handles.push(task);
    tokio::time::timeout(Duration::from_secs(5), buffered.notified()).await?;
    assert!(
        !node
            .body()
            .initializers
            .lock()
            .await
            .handles
            .last()
            .unwrap()
            .is_finished()
    );
    Ok(receive)
}

#[tokio::test]
async fn buffered_preparation_error_requires_claim_before_registry_forgets_it() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    for claim in [false, true] {
        let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
        let before = contents(&node)?;
        let receive = buffered_failure(&node).await?;
        if claim {
            let error = receive.await?.claim().err().expect("preparation must fail");
            assert!(error.is::<PreparationFailure>());
        } else {
            drop(receive);
        }
        let result =
            tokio::time::timeout(Duration::from_secs(5), node.drain_initializers()).await?;
        if claim {
            result.map_err(|original| anyhow::Error::new(original.observation()))?;
        } else {
            let failure = result.unwrap_err();
            crate::test_utils::inspect_and_dispose_initializer(&failure, |original| {
                assert!(original.is::<PreparationFailure>());
            })
            .await;
        }
        drain(&node)
            .await
            .map_err(|original| anyhow::Error::new(original.observation()))?;
        assert_unpublished(&node).await;
        assert!(node.catalog("new-tenant")?.is_none());
        assert!(
            node.catalog(&CustodyStore::catalog_name("new-tenant"))?
                .is_none()
        );
        assert_eq!(contents(&node)?, before);
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_catalog_drain_preserves_unclaimed_preparation_error() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let receive = buffered_failure(&node).await?;
    let (release, waiting) = oneshot::channel::<()>();
    let owned = node.clone();
    let pending = tokio::spawn(async move {
        let _owned = owned;
        waiting.await?;
        Ok(())
    });
    node.body()
        .initializers
        .lock()
        .await
        .handles
        .insert(0, pending);
    drop(receive);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if node
                .body()
                .initializers
                .lock()
                .await
                .handles
                .last()
                .unwrap()
                .is_finished()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let before = fixture_memory.snapshot();
    let error = tokio::time::timeout(Duration::from_secs(5), node.drain_initializers())
        .await?
        .unwrap_err();
    let address = error
        .with_report(|report| {
            let original = report.body_error().unwrap();
            assert!(original.is::<PreparationFailure>());
            std::ptr::from_ref(original) as usize
        })
        .await;
    assert_eq!(node.body().initializers.lock().await.handles.len(), 1);
    let repeated = node.drain_initializers().await.unwrap_err();
    repeated
        .with_report(|report| {
            assert_eq!(
                std::ptr::from_ref(report.body_error().unwrap()) as usize,
                address
            );
        })
        .await;
    assert_eq!(fixture_memory.snapshot(), before);
    crate::test_utils::inspect_and_dispose_initializer(&error, |original| {
        assert!(original.is::<PreparationFailure>());
    })
    .await;
    drop(repeated);
    drop(error);
    release.send(()).unwrap();
    drain(&node)
        .await
        .map_err(|original| anyhow::Error::new(original.observation()))?;
    assert_unpublished(&node).await;
    Ok(())
}

#[tokio::test]
async fn admission_reaper_reports_unclaimed_preparation_failure_before_new_work() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let (_directory, node) = node(fixture_memory.clone(), fixture_scratch.clone())?;
    let before = contents(&node)?;
    drop(buffered_failure(&node).await?);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if node
                .body()
                .initializers
                .lock()
                .await
                .handles
                .iter()
                .all(tokio::task::JoinHandle::is_finished)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let error = begin(input(node.clone()))
        .await
        .err()
        .expect("reaper must report retained failure");
    let observed = error
        .downcast_ref::<crate::InitializerDrainObservation>()
        .expect("nonowning reaper marker");
    assert_eq!(observed.opening_id(), node.registered_opening_id().unwrap());
    assert_eq!(contents(&node)?, before);
    let failure = node.drain_initializers().await.unwrap_err();
    crate::test_utils::inspect_and_dispose_initializer(&failure, |original| {
        assert!(original.is::<PreparationFailure>());
    })
    .await;
    drop(failure);
    drain(&node)
        .await
        .map_err(|original| anyhow::Error::new(original.observation()))?;
    let stores = TenantStorageSet::initialize_catalogs(
        node.clone(),
        "new-tenant".into(),
        Arc::new(LocalKeyProvider::new([51; 32])),
        Arc::new(LocalKeyProvider::new([52; 32])),
        StorageAccess::fixture(),
    )
    .await?;
    stores.shutdown().await.unwrap();
    drain(&node)
        .await
        .map_err(|original| anyhow::Error::new(original.observation()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_pair_registers_one_writer_before_waiting_for_native_gate() -> Result<()> {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir()?;
    let path = directory.path().join("registered-pair.kv");
    let disk = crate::test_utils::retry_disk_registry(|| {
        crate::NodeDisk::fixture_for_path(&path, memory.clone())
    })?;
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(
        &path,
        crate::test_utils::NODE_STORE_ID,
        disk,
        scratch,
        crate::test_utils::node_storage_config(),
    )
    .unwrap_or_else(|original| std::panic::panic_any(original));
    let held = node.body().db.begin_write()?;
    let receive = begin(input(node.clone())).await?;
    let registered = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if memory.storage_census().snapshot().writers == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    drop(held);
    let stores = receive.await?.claim()?;
    assert!(
        registered,
        "paired catalog writer waited at the native gate without one registered child"
    );
    assert!(node.catalog("new-tenant")?.is_some());
    assert!(
        node.catalog(&CustodyStore::catalog_name("new-tenant"))?
            .is_some()
    );
    stores.shutdown().await.unwrap();
    drop(stores);
    drain(&node)
        .await
        .map_err(|original| anyhow::Error::new(original.observation()))?;
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().writers, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_pair_rechecks_second_catalog_and_orphan_inside_one_transaction() -> Result<()> {
    for kind in ["catalog", "orphan"] {
        let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
        let directory = crate::test_utils::private_tempdir()?;
        let path = directory.path().join(format!("pair-{kind}.kv"));
        let disk = crate::test_utils::retry_disk_registry(|| {
            crate::NodeDisk::fixture_for_path(&path, memory.clone())
        })?;
        let scratch_directory = crate::test_utils::private_tempdir()?;
        let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
        let node = NodeStore::create_new(
            &path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            scratch,
            crate::test_utils::node_storage_config(),
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        let hash = tenant_hash(&CustodyStore::catalog_name("new-tenant"));
        let held = node.body().db.begin_write()?;
        if kind == "catalog" {
            held.open_table(CATALOG)?
                .insert(hash.as_slice(), b"preserved catalog".as_slice())?;
        } else {
            let mut key = hash.to_vec();
            key.extend_from_slice(b"orphan");
            held.open_table(RECORDS)?
                .insert(key.as_slice(), b"preserved ciphertext".as_slice())?;
        }
        let receive = begin(input(node.clone())).await?;
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if memory.storage_census().snapshot().writers == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        held.commit()?;
        let before = contents(&node)?;
        let error = receive
            .await?
            .claim()
            .err()
            .expect("pair must reject conflict");
        assert!(format!("{error:#}").contains(if kind == "catalog" {
            "catalog already initialized"
        } else {
            "new catalog has orphan physical rows"
        }));
        drain(&node)
            .await
            .map_err(|original| anyhow::Error::new(original.observation()))?;
        assert_eq!(contents(&node)?, before);
        let read = node.body().db.begin_read()?;
        assert!(
            read.open_table(CATALOG)?
                .get(tenant_hash("new-tenant").as_slice())?
                .is_none(),
            "first catalog must not commit when second is rejected"
        );
        drop(read);
        node.shutdown().await.unwrap();
        assert_eq!(memory.storage_census().snapshot().writers, 0);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_production_pair_waiter_drains_after_atomic_catalog_commit() -> Result<()> {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = crate::test_utils::private_tempdir()?;
    let path = directory.path().join("cancelled-pair.kv");
    let disk = crate::test_utils::retry_disk_registry(|| {
        crate::NodeDisk::fixture_for_path(&path, memory.clone())
    })?;
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), memory.clone());
    let node = NodeStore::create_new(
        &path,
        crate::test_utils::NODE_STORE_ID,
        disk,
        scratch,
        crate::test_utils::node_storage_config(),
    )
    .unwrap_or_else(|original| std::panic::panic_any(original));
    let held = node.body().db.begin_write()?;
    let receive = begin(input(node.clone())).await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if memory.storage_census().snapshot().writers == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    drop(receive);
    drop(held);
    let error = tokio::time::timeout(Duration::from_secs(10), node.drain_initializers())
        .await?
        .unwrap_err();
    crate::test_utils::inspect_and_dispose_initializer(&error, |original| {
        assert!(format!("{original:#}").contains("catalog initialization receiver closed"));
    })
    .await;
    drop(error);
    drain(&node)
        .await
        .map_err(|original| anyhow::Error::new(original.observation()))?;
    assert!(node.catalog("new-tenant")?.is_some());
    assert!(
        node.catalog(&CustodyStore::catalog_name("new-tenant"))?
            .is_some()
    );
    assert_unpublished(&node).await;
    node.shutdown().await.unwrap();
    assert_eq!(memory.storage_census().snapshot().writers, 0);
    Ok(())
}
