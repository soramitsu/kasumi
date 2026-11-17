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
    NamespaceStage::reclaim_unselected(reopened.application())?;
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
        NamespaceStage::reclaim_unselected(reopened.application())?;
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
    assert!(NamespaceStage::reclaim_unselected(stores.application()).is_err());
    Ok(())
}

const FAMILY: &str = "fixture.family";
const INITIAL: [&str; 2] = ["fixture.a", "fixture.b"];

// Rows written exactly as a store from before generation selectors wrote them.
fn legacy_rows(store: &TenantStore, rows: u64) -> Result<()> {
    for namespace in INITIAL {
        for row in 0..rows {
            store.write_batch(&[WriteOp::put(
                namespace,
                row.to_be_bytes(),
                format!("{namespace}/{row}"),
            )])?;
        }
    }
    Ok(())
}
fn rows_at(view: &TenantReadView) -> Result<Vec<Vec<u8>>> {
    let generation = SelectedGeneration::load_at(view, FAMILY, &INITIAL)?;
    let mut rows = Vec::new();
    for namespace in generation.namespaces() {
        view.visit(namespace, 1024, |_, value| {
            rows.push(value.to_vec());
            Ok(())
        })?;
    }
    Ok(rows)
}
fn staged(
    store: &Arc<TenantStore>,
    scratch: &Arc<ScratchDisk>,
    rows: u64,
) -> Result<[NamespaceStage; 2]> {
    let stage = |base| -> Result<NamespaceStage> {
        let stage = NamespaceStage::begin_generation(store, base)?;
        stage.write_table(&source(scratch, rows, 8))?;
        Ok(stage)
    };
    Ok([stage(INITIAL[0])?, stage(INITIAL[1])?])
}
fn count(store: &TenantStore, namespace: &str) -> Result<u64> {
    let mut rows = 0;
    store.visit(namespace, 1024, |_, _| {
        rows += 1;
        Ok(())
    })?;
    Ok(rows)
}

#[tokio::test]
async fn legacy_family_is_adopted_switched_and_reclaimed_without_touching_pinned_rows() -> Result<()>
{
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch.clone(), true).await;
    let store = stores.application();
    legacy_rows(store, 20)?;
    let legacy = SelectedGeneration::load(store, FAMILY, &INITIAL)?;
    assert_eq!(legacy.namespaces(), INITIAL);
    let [a, b] = staged(store, &scratch, 17)?;
    // Only a recorded predecessor can be replaced.
    assert!(legacy.switch_writes(store, &[&a, &b]).is_err());
    let adopted = SelectedGeneration::adopt(store, FAMILY, &INITIAL)?;
    assert_eq!(adopted.namespaces(), INITIAL);
    assert_eq!(SelectedGeneration::adopt(store, FAMILY, &INITIAL)?, adopted);
    let pinned = store.read_view()?;
    let before = rows_at(&pinned)?;
    assert_eq!(before.len(), 40);
    store.write_batch(&adopted.switch_writes(store, &[&a, &b])?)?;
    let current = SelectedGeneration::load(store, FAMILY, &INITIAL)?;
    assert_eq!(current.namespaces(), [a.namespace(), b.namespace()]);
    // Retirement happens only after the selection commits; legacy rows are
    // byte-identical until the bounded collector removes them.
    for namespace in INITIAL {
        assert_eq!(count(store, namespace)?, 20);
    }
    NamespaceStage::reclaim_unselected(store)?;
    for namespace in INITIAL {
        assert_eq!(count(store, namespace)?, 0);
        assert!(
            store
                .get_bounded(OWNERS, namespace.as_bytes(), OWNER_BYTES)?
                .is_none()
        );
    }
    assert_eq!(count(store, a.namespace())?, 17);
    assert_eq!(rows_at(&pinned)?, before);
    pinned.close()?;
    let view = store.read_view()?;
    assert_eq!(rows_at(&view)?.len(), 34);
    view.close()?;
    // A selected generation is never collected; its replacement retires it.
    assert!(NamespaceStage::reclaim(store, a.namespace()).is_err());
    let [c, d] = staged(store, &scratch, 3)?;
    store.write_batch(&current.switch_writes(store, &[&c, &d])?)?;
    NamespaceStage::reclaim_unselected(store)?;
    assert_eq!(count(store, a.namespace())?, 0);
    assert_eq!(count(store, c.namespace())?, 3);
    Ok(())
}

#[tokio::test]
async fn selector_changes_are_checked_with_their_owners_inside_the_transaction() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch.clone(), true).await;
    let store = stores.application();
    legacy_rows(store, 2)?;
    let adopted = SelectedGeneration::adopt(store, FAMILY, &INITIAL)?;
    let [a, b] = staged(store, &scratch, 2)?;
    let writes = adopted.switch_writes(store, &[&a, &b])?;
    let selector = writes[0].clone();
    let unchanged = || -> Result<()> {
        assert_eq!(SelectedGeneration::load(store, FAMILY, &INITIAL)?, adopted);
        for namespace in INITIAL {
            assert!(
                store
                    .get_bounded(OWNERS, namespace.as_bytes(), OWNER_BYTES)?
                    .is_none()
            );
        }
        Ok(())
    };
    // Without each owner transition, or with a retirement it does not cause.
    for omitted in 1..writes.len() {
        let mut partial = writes.clone();
        partial.remove(omitted);
        assert!(store.write_batch(&partial).is_err(), "omitted {omitted}");
        assert!(stores.write_batch(&partial, &[]).is_err());
        unchanged()?;
    }
    assert!(store.write_batch(&writes[2..]).is_err());
    assert!(store.write_batch(&writes[3..]).is_err());
    unchanged()?;
    // Selectors are never deleted, duplicated or used to adopt staged rows.
    assert!(
        store
            .write_batch(&[WriteOp::delete(SELECTIONS, FAMILY.as_bytes())])
            .is_err()
    );
    let mut duplicate = writes.clone();
    duplicate.push(selector.clone());
    assert!(store.write_batch(&duplicate).is_err());
    let [e, f] = staged(store, &scratch, 1)?;
    let adoption = Selection {
        version: 1,
        namespaces: vec![e.namespace().into(), f.namespace().into()],
    };
    assert!(
        store
            .write_batch(&[adoption.write("fixture.other")?])
            .is_err()
    );
    unchanged()?;
    store.write_batch(&writes)?;
    // A stale predecessor cannot select over the generation that replaced it.
    let [c, d] = staged(store, &scratch, 1)?;
    assert!(
        store
            .write_batch(&adopted.switch_writes(store, &[&c, &d])?)
            .is_err()
    );
    let current = SelectedGeneration::load(store, FAMILY, &INITIAL)?;
    assert_eq!(current.namespaces(), [a.namespace(), b.namespace()]);
    store.write_batch(&current.switch_writes(store, &[&c, &d])?)?;
    Ok(())
}

#[tokio::test]
async fn every_crash_cut_of_a_switch_keeps_one_complete_generation_and_reclaims_the_rest()
-> Result<()> {
    let (_directory, scratch) = scratch();
    let original = FaultBackend::new();
    let stores = pair(original.clone(), scratch.clone(), true).await;
    legacy_rows(stores.application(), 9)?;
    let starting = original.crash();
    let switch = |stores: &TenantStorageSet| -> Result<()> {
        let store = stores.application();
        let adopted = SelectedGeneration::adopt(store, FAMILY, &INITIAL)?;
        let [a, b] = staged(store, &scratch, 16)?;
        stores.write_batch(&adopted.switch_writes(store, &[&a, &b])?, &[])?;
        NamespaceStage::reclaim_unselected(store)
    };
    let measurement = starting.crash();
    let measured = pair(measurement.clone(), scratch.clone(), false).await;
    let start = measurement.operations();
    switch(&measured)?;
    let mutations = measurement.operations() - start;
    let (mut old, mut new) = (0, 0);
    for cut in 0..=mutations {
        let disk = starting.crash();
        let stores = pair(disk.clone(), scratch.clone(), false).await;
        disk.fail_after(cut);
        let result = switch(&stores);
        let crashed = disk.crash();
        disk.disarm();
        let reopened = pair(crashed, scratch.clone(), false).await;
        let store = reopened.application();
        let view = store.read_view()?;
        let rows = rows_at(&view)?;
        view.close()?;
        let generation = SelectedGeneration::load(store, FAMILY, &INITIAL)?;
        if generation.namespaces() == INITIAL {
            old += 1;
            assert_eq!(rows.len(), 18, "legacy rows changed at cut {cut}");
        } else {
            new += 1;
            assert_eq!(rows.len(), 32, "torn generation at cut {cut}");
        }
        assert!(result.is_ok() || generation.namespaces() == INITIAL || rows.len() == 32);
        NamespaceStage::reclaim_unselected(store)?;
        // Only the selected generation and nothing staged or retired remains.
        let mut owners = 0;
        let mut owned = Vec::new();
        store.visit(OWNERS, OWNER_BYTES, |namespace, bytes| {
            owners += 1;
            assert_eq!(Owner::decode(bytes)?.phase, Phase::Selected);
            owned.push(String::from_utf8(namespace.to_vec())?);
            Ok(())
        })?;
        if generation.namespaces() == INITIAL {
            assert_eq!(owners, 0, "unselected stage leaked at cut {cut}");
        } else {
            assert_eq!(owners, 2);
            for namespace in INITIAL {
                assert_eq!(
                    count(store, namespace)?,
                    0,
                    "retired rows leaked at cut {cut}"
                );
            }
            assert!(
                owned
                    .iter()
                    .all(|name| generation.namespaces().contains(name))
            );
        }
    }
    assert!(old > 0 && new > 0);
    Ok(())
}
