use super::*;
use crate::test_utils::{LocalKeyProvider, ManualClock};
use redb::ReadableTable;

fn contents(node: &NodeStore) -> Result<String> {
    let transaction = node.db.begin_read()?;
    let mut digest = Sha256::new();
    for (index, definition) in [CATALOG, RECORDS].into_iter().enumerate() {
        digest.update((index as u64).to_be_bytes());
        for item in transaction.open_table(definition)?.iter()? {
            let (key, value) = item?;
            digest.update((key.value().len() as u64).to_be_bytes());
            digest.update(key.value());
            digest.update((value.value().len() as u64).to_be_bytes());
            digest.update(value.value());
        }
    }
    Ok(hex::encode(digest.finalize()))
}

async fn reopen(node: Arc<NodeStore>) -> Result<Arc<TenantStorageSet>> {
    TenantStorageSet::open_existing(
        node,
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([11; 32])),
        Arc::new(LocalKeyProvider::new([12; 32])),
        StorageAccess::fixture(),
    )
    .await
}

#[tokio::test]
async fn missing_catalogs_and_authenticated_binding_never_provision_during_reopen() -> Result<()> {
    for present in [0, 1, 2, 3] {
        let directory = tempfile::tempdir()?;
        let node = NodeStore::create_new(
            directory.path().join("partial.redb"),
            crate::test_utils::NODE_STORE_ID,
            ScratchDisk::fixture(),
        )?;
        let mut opened = Vec::new();
        for (flag, name, key) in [
            (1, "tenant".to_owned(), [11; 32]),
            (2, CustodyStore::catalog_name("tenant"), [12; 32]),
        ] {
            if present & flag != 0 {
                opened.push(
                    TenantStore::open_fixture_with_clock(
                        node.clone(),
                        name,
                        Arc::new(LocalKeyProvider::new(key)),
                        Arc::new(ManualClock::new()),
                    )
                    .await?,
                );
            }
        }
        let before = contents(&node)?;
        assert!(reopen(node.clone()).await.is_err());
        assert_eq!(contents(&node)?, before);
        assert_eq!(node.catalog("tenant")?.is_some(), present & 1 != 0);
        assert_eq!(
            node.catalog(&CustodyStore::catalog_name("tenant"))?
                .is_some(),
            present & 2 != 0
        );
        for store in opened {
            store.shutdown().await;
        }
    }
    Ok(())
}

#[tokio::test]
async fn existing_catalog_admission_cannot_provision_after_waiting_for_the_open_gate() -> Result<()>
{
    use std::{future::Future, task::Poll};
    let directory = tempfile::tempdir()?;
    let node = NodeStore::create_new(
        directory.path().join("gate.redb"),
        crate::test_utils::NODE_STORE_ID,
        ScratchDisk::fixture(),
    )?;
    let provider = Arc::new(LocalKeyProvider::new([11; 32]));
    let store = TenantStore::open_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        provider.clone(),
        Arc::new(ManualClock::new()),
    )
    .await?;
    store.shutdown().await;
    drop(store);
    let gate = node.tenants.lock().await.get("tenant").unwrap().clone();
    let guard = gate.lock().await;
    let pending = TenantStore::open_existing_fixture(node.clone(), "tenant".into(), provider);
    tokio::pin!(pending);
    std::future::poll_fn(|context| {
        assert!(pending.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    let transaction = node.db.begin_write()?;
    transaction
        .open_table(CATALOG)?
        .remove(tenant_hash("tenant").as_slice())?;
    transaction.commit()?;
    let before = contents(&node)?;
    drop(guard);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), pending)
            .await?
            .is_err()
    );
    assert!(node.catalog("tenant")?.is_none());
    assert_eq!(contents(&node)?, before);
    Ok(())
}

#[tokio::test]
async fn corrupt_or_authenticated_wrong_binding_is_never_repaired_by_reopen() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let node = NodeStore::create_new(
        directory.path().join("binding.redb"),
        crate::test_utils::NODE_STORE_ID,
        ScratchDisk::fixture(),
    )?;
    let stores = TenantStorageSet::initialize_catalogs_fixture(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([11; 32])),
        Arc::new(LocalKeyProvider::new([12; 32])),
    )
    .await?;
    let mut wrong = stores.custody.binding.clone();
    wrong.application_catalog = Uuid::new_v4();
    for bytes in [b"corrupt binding".to_vec(), serde_json::to_vec(&wrong)?] {
        stores
            .custody
            .store
            .write_batch(&[WriteOp::put(BINDING_NS, BINDING_KEY, bytes)])?;
        let before = contents(&node)?;
        assert!(reopen(node.clone()).await.is_err());
        assert_eq!(contents(&node)?, before);
    }
    stores.application.shutdown().await;
    stores.custody.store.shutdown().await;
    drop(stores);
    let transaction = node.db.begin_write()?;
    transaction.open_table(CATALOG)?.insert(
        tenant_hash("tenant").as_slice(),
        b"invalid catalog".as_slice(),
    )?;
    transaction.commit()?;
    let before = contents(&node)?;
    assert!(reopen(node.clone()).await.is_err());
    assert_eq!(contents(&node)?, before);
    Ok(())
}

#[tokio::test]
async fn exact_standalone_binding_reopens_after_both_domains_close_and_drain() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("installed.redb");
    let disk = ScratchDisk::fixture();
    let node = NodeStore::create_new(&path, crate::test_utils::NODE_STORE_ID, disk.clone())?;
    let installation = Uuid::new_v4();
    let incarnation = Uuid::new_v4();
    let access = StorageAccess::standalone(installation, "tenant", incarnation)?;
    let application = Arc::new(LocalKeyProvider::new([11; 32]));
    let custody = Arc::new(LocalKeyProvider::new([12; 32]));
    let stores = TenantStorageSet::initialize_catalogs(
        node.clone(),
        "tenant".into(),
        application.clone(),
        custody.clone(),
        access.clone(),
    )
    .await?;
    stores.write_batch(
        &[WriteOp::put("data", b"key", b"retained")],
        &[WriteOp::put("control", b"position", b"committed")],
    )?;
    let binding = stores.custody.binding.clone();
    let before = contents(&node)?;
    stores.application.shutdown().await;
    stores.custody.store.shutdown().await;
    drop(stores);
    drop(node);
    let node = NodeStore::open_existing(&path, crate::test_utils::NODE_STORE_ID, disk)?;
    let unused = Arc::new(LocalKeyProvider::new([99; 32]));
    assert!(
        TenantStorageSet::open_existing(
            node.clone(),
            "tenant".into(),
            unused.clone(),
            custody.clone(),
            StorageAccess::standalone(installation, "tenant", Uuid::new_v4())?,
        )
        .await
        .is_err()
    );
    assert_eq!(
        unused.probe_count(),
        0,
        "wrong purpose must fail before application unwrap"
    );
    let reopened = TenantStorageSet::open_existing(
        node.clone(),
        "tenant".into(),
        application,
        custody,
        access,
    )
    .await?;
    assert_eq!(reopened.custody.binding, binding);
    assert_eq!(
        reopened.application.get("data", b"key")?.as_deref(),
        Some(b"retained".as_slice())
    );
    assert_eq!(
        reopened
            .custody
            .store
            .get("control", b"position")?
            .as_deref(),
        Some(b"committed".as_slice())
    );
    assert_eq!(contents(&node)?, before);
    reopened.application.shutdown().await;
    reopened.custody.store.shutdown().await;
    Ok(())
}
