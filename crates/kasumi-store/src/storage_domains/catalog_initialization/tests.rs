use super::*;
use crate::test_utils::LocalKeyProvider;
use redb::ReadableTable;
use std::{future::Future, task::Poll};

fn node() -> Result<(tempfile::TempDir, Arc<NodeStore>)> {
    let directory = tempfile::tempdir()?;
    let node = NodeStore::create_new(
        directory.path().join("catalogs.redb"),
        crate::test_utils::NODE_STORE_ID,
        ScratchDisk::fixture(),
    )?;
    Ok((directory, node))
}

fn input(node: Arc<NodeStore>) -> Input {
    Input {
        node,
        tenant: "new-tenant".into(),
        application_provider: Arc::new(LocalKeyProvider::new([51; 32])),
        custody_provider: Arc::new(LocalKeyProvider::new([52; 32])),
        application_access: StorageAccess::fixture(),
    }
}

async fn drain(node: &NodeStore) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), node.drain_initializers()).await??;
    assert!(node.initializers.lock().await.is_empty());
    Ok(())
}

async fn assert_unpublished(node: &NodeStore) {
    for tenant in [
        "new-tenant".to_owned(),
        CustodyStore::catalog_name("new-tenant"),
    ] {
        let gate = node.tenants.lock().await.get(&tenant).unwrap().clone();
        assert!(gate.lock().await.upgrade().is_none());
    }
}

fn contents(node: &NodeStore) -> Result<Vec<u8>> {
    let tx = node.db.begin_read()?;
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
    let (_directory, node) = node()?;
    let (send, receive) = oneshot::channel();
    let prepared = prepare(input(node.clone()), &send).await?;
    let observed = prepared.stores.clone();
    let delivery = deliver(prepared, send);
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
    tokio::time::timeout(Duration::from_secs(10), delivery).await?;
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
    drain(&node).await?;
    assert_eq!(contents(&node)?, before);
    Ok(())
}

#[tokio::test]
async fn committed_pair_handoff_preserves_a_concurrent_borrower_through_initializer_drain()
-> Result<()> {
    let (_directory, node) = node()?;
    let ticket = tokio::time::timeout(Duration::from_secs(10), begin(input(node.clone())).await?)
        .await???;
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
    drain(&node).await?;
    stores.check_access()?;
    borrower.write_batch(&[WriteOp::put("data", b"key", b"value".to_vec())])?;
    assert_eq!(
        stores.application.get("data", b"key")?,
        Some(b"value".to_vec())
    );
    stores.application.shutdown().await;
    stores.custody.store.shutdown().await;
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
        reopened.application.get("data", b"key")?,
        Some(b"value".to_vec())
    );
    reopened.application.shutdown().await;
    reopened.custody.store.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn fresh_pair_rejects_shared_partial_and_orphan_domains_without_mutation() -> Result<()> {
    for existing_custody in [false, true] {
        let (_directory, node) = node()?;
        let name = if existing_custody {
            CustodyStore::catalog_name("new-tenant")
        } else {
            "new-tenant".to_owned()
        };
        let live = TenantStore::open_fixture(
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
                .is_err()
        );
        drain(&node).await?;
        assert_eq!(contents(&node)?, before);
        assert_eq!(live.get("kept", b"key")?, Some(b"retained".to_vec()));
        live.shutdown().await;
        drop(live);
        // The same partial disk catalog is rejected after its live owner drains.
        let receive = begin(input(node.clone())).await?;
        assert!(
            tokio::time::timeout(Duration::from_secs(10), receive)
                .await??
                .is_err()
        );
        drain(&node).await?;
        assert_eq!(contents(&node)?, before);
    }
    let (_directory, node) = node()?;
    let tx = node.db.begin_write()?;
    tx.open_table(RECORDS)?
        .insert(tenant_hash("new-tenant").as_slice(), b"unknown".as_slice())?;
    tx.commit()?;
    let before = contents(&node)?;
    let receive = begin(input(node.clone())).await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(10), receive)
            .await??
            .is_err()
    );
    drain(&node).await?;
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
    let (_directory, node) = node()?;
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
    tokio::time::timeout(Duration::from_secs(10), draining).await??;
    assert!(!provider.active.load(Ordering::Acquire));
    assert!(node.catalog("new-tenant")?.is_none());
    assert!(
        node.catalog(&CustodyStore::catalog_name("new-tenant"))?
            .is_none()
    );
    assert_unpublished(&node).await;
    Ok(())
}
