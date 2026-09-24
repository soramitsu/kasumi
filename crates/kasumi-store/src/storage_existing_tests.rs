use super::*;
use crate::test_utils::{LocalKeyProvider, ManualClock};

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
async fn existing_catalog_rejects_equivalent_alternate_bytes_without_repair() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        directory.path().join("canonical-catalog.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory,
        fixture_scratch,
    )?;
    let provider = Arc::new(LocalKeyProvider::new([11; 32]));
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        provider.clone(),
        Arc::new(ManualClock::new()),
    )
    .await?;
    store.rotate_data_key().await?;
    let original = {
        let transaction = node.db.begin_read()?;
        let table = transaction.open_table(CATALOG)?;
        let value = table
            .get(tenant_hash("tenant").as_slice())?
            .expect("installed catalog");
        value.value().to_vec()
    };
    assert!(
        serde_json::to_vec(&node.catalog("tenant")?.unwrap())?.as_slice() == original.as_slice(),
        "rotated catalog differs from current writer bytes"
    );
    store.shutdown().await?;
    drop(store);

    let mut alternate = original.clone();
    alternate.push(b' ');
    assert!(
        serde_json::from_slice::<KeyCatalog>(&alternate)?
            == serde_json::from_slice::<KeyCatalog>(&original)?,
        "alternate catalog changed its semantic value"
    );
    let transaction = node.db.begin_write()?;
    transaction
        .open_table(CATALOG)?
        .insert(tenant_hash("tenant").as_slice(), alternate.as_slice())?;
    transaction.commit()?;
    let before = contents(&node)?;
    assert!(node.catalog("tenant").is_err());
    assert!(
        TenantStore::open_existing_fixture(node.clone(), "tenant".into(), provider.clone())
            .await
            .is_err()
    );
    assert_eq!(contents(&node)?, before, "failed open repaired the catalog");

    let transaction = node.db.begin_write()?;
    transaction
        .open_table(CATALOG)?
        .insert(tenant_hash("tenant").as_slice(), original.as_slice())?;
    transaction.commit()?;
    let reopened =
        TenantStore::open_existing_fixture(node.clone(), "tenant".into(), provider).await?;
    assert!(
        serde_json::to_vec(&node.catalog("tenant")?.unwrap())?.as_slice() == original.as_slice(),
        "restored catalog differs from current writer bytes"
    );
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn missing_catalogs_and_authenticated_binding_never_provision_during_reopen() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    for present in [0, 1, 2, 3] {
        let directory = crate::test_utils::private_tempdir()?;
        let node = NodeStore::create_new_fixture(
            directory.path().join("partial.kv"),
            crate::test_utils::NODE_STORE_ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )?;
        let mut opened = Vec::new();
        for (flag, name, key) in [
            (1, "tenant".to_owned(), [11; 32]),
            (2, CustodyStore::catalog_name("tenant"), [12; 32]),
        ] {
            if present & flag != 0 {
                opened.push(
                    TenantStore::initialize_catalog_fixture_with_clock(
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
            store.shutdown().await.unwrap();
        }
    }
    Ok(())
}

#[tokio::test]
async fn existing_catalog_admission_cannot_provision_after_waiting_for_the_open_gate() -> Result<()>
{
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    use std::{future::Future, task::Poll};
    let directory = crate::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        directory.path().join("gate.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )?;
    let provider = Arc::new(LocalKeyProvider::new([11; 32]));
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        node.clone(),
        "tenant".into(),
        provider.clone(),
        Arc::new(ManualClock::new()),
    )
    .await?;
    store.shutdown().await.unwrap();
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
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        directory.path().join("binding.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
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
    stores.shutdown().await.unwrap();
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
async fn existing_binding_requires_current_writer_bytes_without_repair() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir()?;
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let node = NodeStore::create_new_fixture(
        directory.path().join("canonical-binding.kv"),
        crate::test_utils::NODE_STORE_ID,
        fixture_memory,
        fixture_scratch,
    )?;
    let stores = TenantStorageSet::initialize_catalogs_fixture(
        node.clone(),
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([11; 32])),
        Arc::new(LocalKeyProvider::new([12; 32])),
    )
    .await?;
    let custody = stores.custody().store().clone();
    let canonical = custody.get(BINDING_NS, BINDING_KEY)?.unwrap();
    assert_eq!(canonical, serde_json::to_vec(stores.custody().binding())?);

    let mut alternate = b" \n".to_vec();
    alternate.extend_from_slice(&canonical);
    assert_eq!(
        serde_json::from_slice::<StorageBinding>(&alternate)?,
        stores.custody().binding().clone()
    );
    custody.write_batch(&[WriteOp::put(BINDING_NS, BINDING_KEY, alternate.clone())])?;
    let install_error = TenantStorageSet::install(stores.application().clone(), custody.clone())
        .err()
        .expect("alternate binding must reject existing-binding install");
    assert!(
        format!("{install_error:#}").contains("installed storage domain binding bytes differ"),
        "{install_error:#}"
    );
    assert_eq!(
        custody.get(BINDING_NS, BINDING_KEY)?,
        Some(alternate.clone())
    );

    stores.shutdown().await.unwrap();
    drop(stores);
    drop(custody);
    node.drain_initializers().await?;
    let before = contents(&node)?;
    let reopen_error = reopen(node.clone())
        .await
        .err()
        .expect("alternate binding must reject existing open");
    assert!(
        format!("{reopen_error:#}").contains("existing storage domain binding bytes differ"),
        "{reopen_error:#}"
    );
    node.drain_initializers().await?;
    assert_eq!(contents(&node)?, before);

    let custody = TenantStore::open_existing_fixture(
        node.clone(),
        CustodyStore::catalog_name("tenant"),
        Arc::new(LocalKeyProvider::new([12; 32])),
    )
    .await?;
    assert_eq!(custody.get(BINDING_NS, BINDING_KEY)?, Some(alternate));
    custody.write_batch(&[WriteOp::put(BINDING_NS, BINDING_KEY, canonical)])?;
    custody.shutdown().await.unwrap();
    drop(custody);
    node.drain_initializers().await?;
    let reopened = reopen(node.clone()).await?;
    reopened.shutdown().await.unwrap();
    node.drain_initializers().await?;
    node.shutdown().await.unwrap();
    Ok(())
}

#[tokio::test]
async fn exact_standalone_binding_reopens_after_both_domains_close_and_drain() -> Result<()> {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = crate::test_utils::private_tempdir()?;
    let path = directory.path().join("installed.kv");
    let disk = fixture_scratch.clone();
    let node = NodeStore::create_new_fixture(
        &path,
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        disk.clone(),
    )?;
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
    stores.shutdown().await.unwrap();
    drop(stores);
    drop(node);
    let node = NodeStore::open_existing_fixture(
        &path,
        crate::test_utils::NODE_STORE_ID,
        fixture_memory.clone(),
        disk,
    )?;
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
    reopened.shutdown().await.unwrap();
    Ok(())
}
