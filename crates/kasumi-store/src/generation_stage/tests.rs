use super::*;
use crate::test_utils::{FaultBackend, LocalKeyProvider, ManualClock};

fn scratch() -> (tempfile::TempDir, Arc<ScratchDisk>) {
    let directory = crate::test_utils::private_tempdir().unwrap();
    let memory = crate::test_utils::TestDiskMemory::new(512 << 20, 4096);
    let scratch = ScratchDisk::fixture(directory.path(), memory);
    (directory, scratch)
}
async fn pair(
    disk: FaultBackend,
    scratch: Arc<ScratchDisk>,
    create: bool,
) -> Arc<TenantStorageSet> {
    let node = if create {
        NodeStore::create_with_backend(disk, crate::test_utils::storage_admission(), scratch)
    } else {
        NodeStore::open_with_backend(disk, crate::test_utils::storage_admission(), scratch)
    }
    .expect("fixture node");
    let mut stores = Vec::new();
    for (tenant, seed) in [
        ("tenant".to_owned(), 11),
        (CustodyStore::catalog_name("tenant"), 12),
    ] {
        let provider = Arc::new(LocalKeyProvider::new([seed; 32]));
        let clock = Arc::new(ManualClock::new());
        stores.push(
            if create {
                TenantStore::initialize_catalog_fixture_with_clock(
                    node.clone(),
                    tenant,
                    provider,
                    clock,
                )
                .await
            } else {
                TenantStore::open_existing_fixture_with_clock(node.clone(), tenant, provider, clock)
                    .await
            }
            .unwrap(),
        );
    }
    TenantStorageSet::install(stores.remove(0), stores.remove(0)).unwrap()
}
fn source(disk: &Arc<ScratchDisk>, rows: u64, size: usize) -> EncryptedTable {
    let table = EncryptedTable::new(disk, 128 << 20, disk.native_cache_config()).unwrap();
    for row in 0..rows {
        table
            .insert(&row.to_be_bytes(), &vec![(row % 251) as u8; size])
            .unwrap();
    }
    table
}
fn select(stores: &TenantStorageSet, stage: &NamespaceStage) -> Result<()> {
    stores.write_batch(
        &[
            WriteOp::put("checkpoint", b"current", stage.namespace.as_bytes()),
            stage.publication_write(),
        ],
        &[WriteOp::put("position", b"applied", b"new")],
    )
}
fn verify(stores: &TenantStorageSet, rows: u64, size: usize) -> Result<bool> {
    let view = stores.read_view()?;
    let selection = view
        .application_get("checkpoint", b"current", 1024)?
        .unwrap();
    let position = view.custody_get("position", b"applied", 10)?.unwrap();
    let new = selection.as_bytes() == b"new";
    assert_eq!(position.as_bytes(), if new { b"new" } else { b"old" });
    if new {
        for row in 0..rows {
            let value = view
                .application_get("new", &row.to_be_bytes(), size)?
                .unwrap();
            assert_eq!(value.as_bytes(), vec![(row % 251) as u8; size]);
        }
    }
    drop(selection);
    drop(position);
    view.close()?;
    Ok(new)
}

#[tokio::test]
async fn bounded_batches_paired_selection_and_pinned_reader() -> Result<()> {
    let (_directory, scratch) = scratch();
    let disk = FaultBackend::new();
    let stores = pair(disk, scratch.clone(), true).await;
    stores.write_batch(
        &[WriteOp::put("checkpoint", b"current", b"old")],
        &[WriteOp::put("position", b"applied", b"old")],
    )?;
    let old = stores.read_view()?;
    let stage = NamespaceStage::begin(stores.application(), "new")?;
    assert!(select(&stores, &stage).is_err());
    assert!(!verify(&stores, 33, 300 << 10)?);
    let table = source(&scratch, 33, 300 << 10); // exceeds both 16 rows and 4 MiB
    stage.write_table(&table)?;
    assert!(!verify(&stores, 33, 300 << 10)?);
    select(&stores, &stage)?;
    assert!(verify(&stores, 33, 300 << 10)?);
    assert_eq!(
        old.application_get("checkpoint", b"current", 10)?
            .unwrap()
            .as_bytes(),
        b"old"
    );
    assert_eq!(
        old.custody_get("position", b"applied", 10)?
            .unwrap()
            .as_bytes(),
        b"old"
    );
    assert!(NamespaceStage::reclaim(stores.application(), "new").is_err());
    assert!(stage.write_table(&table).is_err());
    old.close()?;
    Ok(())
}

#[tokio::test]
async fn abandoned_stages_are_incremental_restartable_and_fence_stale_tokens() -> Result<()> {
    let (_directory, scratch) = scratch();
    let disk = FaultBackend::new();
    let stores = pair(disk.clone(), scratch.clone(), true).await;
    let source = source(&scratch, 40, 32);
    let stage = NamespaceStage::begin(stores.application(), "abandoned")?;
    stage.write_table(&source)?;
    let pin = stores.application().read_view()?;
    assert!(!NamespaceStage::reclaim(stores.application(), "abandoned")?);
    let mut left = 0;
    stores.application().visit("abandoned", 32, |_, _| {
        left += 1;
        Ok(())
    })?;
    assert_eq!(left, 40 - ROWS_PER_BATCH);
    assert!(
        stores
            .application()
            .write_batch(&[stage.publication_write()])
            .is_err()
    );
    let crash = disk.crash();
    let reopened = pair(crash, scratch.clone(), false).await;
    NamespaceStage::reclaim_unpublished(reopened.application())?;
    reopened
        .application()
        .visit("abandoned", 32, |_, _| anyhow::bail!("leaked row"))?;
    let mut pinned = 0;
    pin.visit("abandoned", 32, |_, _| {
        pinned += 1;
        Ok(())
    })?;
    assert_eq!(pinned, 40);
    pin.close()?;
    let replacement = NamespaceStage::begin(reopened.application(), "abandoned")?;
    replacement.seal_empty()?;
    // An old owner cannot select a new owner's generation with the same name.
    assert!(
        reopened
            .application()
            .write_batch(&[stage.publication_write()])
            .is_err()
    );
    reopened
        .application()
        .write_batch(&[replacement.publication_write()])?;
    Ok(())
}

#[tokio::test]
async fn immutable_rows_and_protected_namespaces_are_checked() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch.clone(), true).await;
    for namespace in ["engine.bootstrap", "engine.deployment", "raft.meta", OWNERS] {
        assert!(NamespaceStage::begin(stores.application(), namespace).is_err());
    }
    stores
        .application()
        .write_batch(&[WriteOp::put("occupied", b"k", b"v")])?;
    assert!(NamespaceStage::begin(stores.application(), "occupied").is_err());
    let stage = NamespaceStage::begin(stores.application(), "private")?;
    assert!(NamespaceStage::begin(stores.application(), "private").is_err());
    stage.write_batch(&[WriteOp::put("private", b"k", b"v")])?;
    stage.write_batch(&[WriteOp::put("private", b"k", b"v")])?;
    assert!(
        stage
            .write_batch(&[WriteOp::put("private", b"k", b"x")])
            .is_err()
    );
    assert_eq!(
        stores
            .application()
            .get("private", b"k")?
            .unwrap()
            .as_bytes(),
        b"v"
    );
    Ok(())
}

#[tokio::test]
async fn a_partial_stage_cannot_be_sealed_as_empty() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch.clone(), true).await;
    let stage = NamespaceStage::begin(stores.application(), "new")?;
    stage.write_batch(&[WriteOp::put("new", 0u64.to_be_bytes(), vec![0; 32])])?;

    assert!(stage.seal_empty().is_err());
    assert!(select(&stores, &stage).is_err());
    assert!(
        stores
            .application()
            .get("checkpoint", b"current")?
            .is_none()
    );
    assert!(
        stores
            .custody()
            .store()
            .get("position", b"applied")?
            .is_none()
    );

    // A rejected seal keeps the original owner writable. Exact retry neither
    // double-counts the existing row nor loses it at selection.
    stage.write_table(&source(&scratch, 1, 32))?;
    select(&stores, &stage)?;
    assert!(verify(&stores, 1, 32)?);
    Ok(())
}

#[tokio::test]
async fn retrying_a_subset_cannot_seal_rows_left_by_an_interrupted_stage() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch.clone(), true).await;
    let stage = NamespaceStage::begin(stores.application(), "new")?;
    stage.write_batch(&[
        WriteOp::put("new", 0u64.to_be_bytes(), vec![0; 32]),
        WriteOp::put("new", 1u64.to_be_bytes(), vec![1; 32]),
    ])?;

    assert!(stage.write_table(&source(&scratch, 1, 32)).is_err());
    assert!(select(&stores, &stage).is_err());
    assert!(
        stores
            .application()
            .get("checkpoint", b"current")?
            .is_none()
    );
    assert!(
        stores
            .custody()
            .store()
            .get("position", b"applied")?
            .is_none()
    );
    assert_eq!(
        stores
            .application()
            .get("new", &1u64.to_be_bytes())?
            .unwrap()
            .as_bytes(),
        &[1; 32]
    );

    stage.write_table(&source(&scratch, 2, 32))?;
    select(&stores, &stage)?;
    assert!(verify(&stores, 2, 32)?);
    Ok(())
}

#[tokio::test]
async fn duplicate_owner_transitions_abort_the_whole_selection() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch, true).await;
    let stage = NamespaceStage::begin(stores.application(), "new")?;
    stage.seal_empty()?;
    for duplicate in [stage.publication_write(), WriteOp::delete(OWNERS, b"new")] {
        let application = [
            WriteOp::put("checkpoint", b"current", b"new"),
            stage.publication_write(),
            duplicate,
        ];
        assert!(stores.application().write_batch(&application).is_err());
        assert!(
            stores
                .write_batch(
                    &application,
                    &[WriteOp::put("position", b"applied", b"new")],
                )
                .is_err()
        );
        assert!(
            stores
                .application()
                .get("checkpoint", b"current")?
                .is_none()
        );
        assert!(
            stores
                .custody()
                .store()
                .get("position", b"applied")?
                .is_none()
        );
    }
    // The rejected batches also leave the sealed owner unconsumed.
    select(&stores, &stage)?;
    assert!(verify(&stores, 0, 32)?);
    Ok(())
}

#[tokio::test]
async fn namespace_replacement_cannot_erase_or_substitute_stage_owners() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch.clone(), true).await;
    let stage = NamespaceStage::begin(stores.application(), "new")?;
    stage.seal_empty()?;
    let original = stores
        .application()
        .get_bounded(OWNERS, b"new", OWNER_BYTES)?
        .unwrap();
    let replacement = source(&scratch, 1, 32);
    for replacement in [
        NamespaceReplacement::empty(OWNERS),
        NamespaceReplacement::from_table(OWNERS, &replacement),
    ] {
        let application = [WriteOp::put("checkpoint", b"current", b"new")];
        let custody = [WriteOp::put("position", b"applied", b"new")];
        assert!(
            stores
                .application()
                .replace_namespaces(&[replacement], &application)
                .is_err()
        );
        assert!(
            stores
                .write_batch_replacing(&application, &custody, &[replacement], &[])
                .is_err()
        );
        assert!(
            stores
                .write_batch_replacing(&application, &custody, &[], &[replacement])
                .is_err()
        );
        assert_eq!(
            stores
                .application()
                .get_bounded(OWNERS, b"new", OWNER_BYTES)?
                .unwrap()
                .as_bytes(),
            original.as_bytes()
        );
        assert!(
            stores
                .application()
                .get("checkpoint", b"current")?
                .is_none()
        );
        assert!(
            stores
                .custody()
                .store()
                .get("position", b"applied")?
                .is_none()
        );
    }
    select(&stores, &stage)?;
    assert!(verify(&stores, 0, 32)?);
    Ok(())
}

#[tokio::test]
async fn every_native_crash_cut_keeps_old_or_complete_new_selection() -> Result<()> {
    let (_directory, scratch) = scratch();
    let original = FaultBackend::new();
    let stores = pair(original.clone(), scratch.clone(), true).await;
    stores.write_batch(
        &[WriteOp::put("checkpoint", b"current", b"old")],
        &[WriteOp::put("position", b"applied", b"old")],
    )?;
    let starting = original.crash();
    let table = source(&scratch, 31, 32);
    // Count every actual backend mutation across begin, three batches, seal,
    // and paired selection; do not guess a fixed number of physical cuts.
    let measurement = starting.crash();
    let measured = pair(measurement.clone(), scratch.clone(), false).await;
    let start = measurement.operations();
    let stage = NamespaceStage::begin(measured.application(), "new")?;
    stage.write_table(&table)?;
    select(&measured, &stage)?;
    let mutations = measurement.operations() - start;
    assert!(mutations > 0);
    let mut old = 0;
    let mut new = 0;
    for cut in 0..=mutations {
        let disk = starting.crash();
        let stores = pair(disk.clone(), scratch.clone(), false).await;
        disk.fail_after(cut);
        let result = (|| {
            let stage = NamespaceStage::begin(stores.application(), "new")?;
            stage.write_table(&table)?;
            select(&stores, &stage)
        })();
        let crashed = disk.crash();
        disk.disarm();
        let reopened = pair(crashed, scratch.clone(), false).await;
        if verify(&reopened, 31, 32)? {
            new += 1;
        } else {
            old += 1;
            assert!(result.is_err(), "acknowledged selection lost at cut {cut}");
        }
        NamespaceStage::reclaim_unpublished(reopened.application())?;
        verify(&reopened, 31, 32)?;
    }
    assert!(old > 0 && new > 0);
    Ok(())
}

#[tokio::test]
async fn raw_owner_writes_and_corrupt_inventory_cannot_reclaim_initial_identities() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch, true).await;
    for namespace in ["engine.bootstrap", "engine.deployment", "raft.meta", OWNERS] {
        let owner = Owner {
            version: 1,
            id: Uuid::new_v4(),
            phase: Phase::Writing {
                records: 0,
                bytes: 0,
            },
        };
        assert!(
            stores
                .application()
                .write_batch(&[owner.write(namespace)?])
                .is_err()
        );
        assert!(stores.write_batch(&[], &[owner.write(namespace)?]).is_err());
        // An authenticated but invalid inventory injected below the public
        // facade cannot turn physical cleanup into an identity-delete backdoor.
        crate::test_utils::inject_authenticated_rows_below_facade(
            &stores,
            &[
                owner.write(namespace)?,
                WriteOp::put(namespace, b"protected", b"original"),
            ],
            &[],
        )?;
        assert!(NamespaceStage::reclaim(stores.application(), namespace).is_err());
        assert_eq!(
            stores
                .application()
                .get(namespace, b"protected")?
                .unwrap()
                .as_bytes(),
            b"original"
        );
    }
    assert!(NamespaceStage::reclaim_unpublished(stores.application()).is_err());
    Ok(())
}
