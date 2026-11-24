use super::*;
use crate::ordered_pages::{
    Direction, Edit, OVERFLOW_CHUNK_BYTES, TreeReader, edit_tree_staged, recover_abandoned_edits,
    recover_abandoned_edits_in, stage_tree,
};
use crate::test_utils::{FaultBackend, LocalKeyProvider, ManualClock, TestDiskMemory};
use std::collections::BTreeMap;
use std::ops::Bound;

fn scratch() -> (tempfile::TempDir, Arc<ScratchDisk>) {
    let directory = crate::test_utils::private_tempdir().unwrap();
    let memory = TestDiskMemory::new(1 << 30, 4096);
    let scratch = ScratchDisk::fixture(directory.path(), memory);
    (directory, scratch)
}

async fn pair(disk: FaultBackend, scratch: Arc<ScratchDisk>) -> Arc<TenantStorageSet> {
    let node =
        NodeStore::create_with_backend(disk, crate::test_utils::storage_admission(), scratch)
            .expect("fixture node");
    let mut stores = Vec::new();
    for (tenant, seed) in [
        ("tenant".to_owned(), 31),
        (CustodyStore::catalog_name("tenant"), 32),
    ] {
        stores.push(
            TenantStore::initialize_catalog_fixture_with_clock(
                node.clone(),
                tenant,
                Arc::new(LocalKeyProvider::new([seed; 32])),
                Arc::new(ManualClock::new()),
            )
            .await
            .unwrap(),
        );
    }
    TenantStorageSet::install(stores.remove(0), stores.remove(0)).unwrap()
}

fn applied(index: u64) -> PrimaryApplied {
    PrimaryApplied {
        index,
        log_sha256: [index as u8; 32],
        command_sha256: Some([0xc0 | index as u8; 32]),
    }
}

fn key(n: u64) -> Vec<u8> {
    format!("\x03docs\x00\x01{n:06}\x00\x01").into_bytes()
}

fn rows(
    view: &dyn crate::ordered_pages::PageSource,
    manifest: &PrimaryManifest,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let reader = TreeReader::new(view, &manifest.page_space, manifest.records, None).unwrap();
    let mut rows = Vec::new();
    reader
        .scan(Bound::Unbounded, Direction::Forward, &mut |key, value| {
            let mut bytes = Vec::new();
            reader.read_value(&value, &mut bytes)?;
            rows.push((key.to_vec(), bytes));
            Ok(true)
        })
        .unwrap();
    rows
}

fn space_rows(store: &Arc<TenantStore>, space: &str) -> u64 {
    let view = store.read_view().unwrap();
    let mut rows = 0u64;
    view.visit(space, OVERFLOW_CHUNK_BYTES, |_, _| {
        rows += 1;
        Ok(())
    })
    .unwrap();
    view.close().unwrap();
    rows
}

/// Publish an edit with its manifest and an applied cursor in one paired
/// native transaction, as ordinary apply does.
fn publish(
    stores: &TenantStorageSet,
    writes: &[WriteOp],
    manifest: &PrimaryManifest,
) -> Result<()> {
    let mut writes = writes.to_vec();
    writes.push(manifest.write()?);
    stores.write_batch(
        &writes,
        &[WriteOp::put(
            "position",
            b"applied",
            manifest.revision.to_be_bytes(),
        )],
    )
}

fn edit(
    store: &TenantStore,
    manifest: &PrimaryManifest,
    changes: &BTreeMap<Vec<u8>, Option<Vec<u8>>>,
) -> (TreeRoot, Vec<WriteOp>) {
    let edits: Vec<Edit<'_>> = changes
        .iter()
        .map(|(key, value)| match value {
            Some(value) => Edit::Put(key, value),
            None => Edit::Delete(key),
        })
        .collect();
    let edit = edit_tree_staged(store, &manifest.page_space, &manifest.records, &edits).unwrap();
    let (root, writes, _workspace) = edit.into_parts();
    (root, writes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_primary_directory_moves_only_forward_and_pinned_views_keep_their_root() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch).await;
    let store = stores.application();
    assert_eq!(PrimaryManifest::load(store)?, None);

    // A pristine store edits its first tree in the initial space.
    let empty = PrimaryManifest::new(
        "tenant",
        "incarnation",
        0,
        4,
        Some(applied(4)),
        INITIAL_SPACE[0],
        TreeRoot::new_tree(),
        0,
        0,
    );
    let mut model = BTreeMap::new();
    let changes: BTreeMap<_, _> = (0..40u64)
        .map(|n| (key(n), Some(vec![n as u8; 64 + n as usize * 40])))
        .collect();
    let (root, writes) = edit(store, &empty, &changes);
    let first = empty.advance(5, Some(applied(5)), root, 40, 4_000);
    publish(&stores, &writes, &first)?;
    for (key, value) in &changes {
        model.insert(key.clone(), value.clone().unwrap());
    }
    assert_eq!(PrimaryManifest::load(store)?.as_ref(), Some(&first));
    let pinned = store.read_view()?;
    let pinned_model: Vec<_> = model.clone().into_iter().collect();

    // An ordinary successor rewrites only changed paths and deletes the pages
    // it displaced in the same commit.
    let changes: BTreeMap<_, _> = (0..40u64)
        .step_by(3)
        .map(|n| (key(n), (n % 2 == 0).then(|| vec![0xee; 300])))
        .collect();
    let (root, writes) = edit(store, &first, &changes);
    let second = first.advance(6, Some(applied(6)), root, 30, 3_000);
    publish(&stores, &writes, &second)?;
    for (key, value) in &changes {
        match value {
            Some(value) => model.insert(key.clone(), value.clone()),
            None => model.remove(key),
        };
    }
    let current = store.read_view()?;
    let selected = PrimaryManifest::load_at(&current)?.expect("current directory");
    assert_eq!(selected, second);
    assert_eq!(
        rows(&current, &selected),
        model.clone().into_iter().collect::<Vec<_>>()
    );
    current.close()?;
    // The pinned native generation still names and reads its own root.
    let old = PrimaryManifest::load_at(&pinned)?.expect("pinned directory");
    assert_eq!(old, first);
    assert_eq!(rows(&pinned, &old), pinned_model);

    // Covered replay cannot repeat or move the directory backward, and a
    // successor keeps its tree, space and scope.
    for refused in [
        second.clone(),
        first.advance(6, Some(applied(6)), second.records, 30, 3_000),
        PrimaryManifest {
            revision: 4,
            applied: Some(applied(4)),
            ..second.clone()
        },
        PrimaryManifest {
            records: TreeRoot::new_tree(),
            ..second.advance(7, Some(applied(7)), second.records, 30, 3_000)
        },
        PrimaryManifest {
            incarnation: "other".into(),
            ..second.advance(7, Some(applied(7)), second.records, 30, 3_000)
        },
    ] {
        assert!(publish(&stores, &[], &refused).is_err());
    }
    let foreign = PrimaryManifest {
        page_space: format!("{FAMILY}@{}", Uuid::new_v4()),
        ..second.advance(7, Some(applied(7)), second.records, 30, 3_000)
    };
    let error = publish(&stores, &[], &foreign).unwrap_err();
    assert!(format!("{error:#}").contains("unselected page space"));
    // A boundary that differs from its revision cannot be encoded.
    assert!(
        second
            .advance(7, Some(applied(8)), second.records, 30, 3_000)
            .write()
            .is_err()
    );
    assert_eq!(PrimaryManifest::load(store)?.as_ref(), Some(&second));

    // A stale successor keeps its tree named; nothing edits it afterwards.
    let stale = second.stale(7, Some(applied(7)));
    publish(&stores, &[], &stale)?;
    assert!(
        publish(
            &stores,
            &[],
            &second.advance(8, Some(applied(8)), second.records, 30, 3_000)
        )
        .is_err()
    );
    assert!(publish(&stores, &[], &stale.stale(8, Some(applied(8)))).is_err());

    // A replacement generation is selected with its manifest, may restart at
    // an older snapshot boundary, and retires the replaced space.
    let family = SelectedGeneration::adopt(store, FAMILY, &INITIAL_SPACE)?;
    let stage = NamespaceStage::begin_generation(store, FAMILY)?;
    let records = stage_tree(&stage, TreeRoot::new_tree().tree, |builder| {
        for (key, value) in &model {
            builder.push(key, value)?;
        }
        Ok(())
    })?;
    let rebuilt = PrimaryManifest::new(
        "tenant",
        "incarnation",
        0,
        3,
        Some(PrimaryApplied {
            command_sha256: None,
            ..applied(3)
        }),
        stage.namespace(),
        records,
        30,
        3_000,
    );
    let mut stale_replacement = family.switch_writes(store, &[&stage])?;
    stale_replacement.push(rebuilt.stale(3, rebuilt.applied.clone()).write()?);
    assert!(
        stores
            .write_batch(
                &stale_replacement,
                &[WriteOp::put("position", b"applied", b"staged")]
            )
            .is_err()
    );
    let mut switch = family.switch_writes(store, &[&stage])?;
    switch.push(rebuilt.write()?);
    stores.write_batch(&switch, &[WriteOp::put("position", b"applied", b"staged")])?;
    drop(stage);
    let current = store.read_view()?;
    assert_eq!(PrimaryManifest::load_at(&current)?.as_ref(), Some(&rebuilt));
    assert_eq!(
        rows(&current, &rebuilt),
        model.clone().into_iter().collect::<Vec<_>>()
    );
    current.close()?;
    assert!(space_rows(store, INITIAL_SPACE[0]) > 0);
    NamespaceStage::reclaim_family(store, FAMILY)?;
    assert_eq!(space_rows(store, INITIAL_SPACE[0]), 0);
    // Both earlier pinned roots survive the reclaimed space.
    assert_eq!(rows(&pinned, &old), pinned_model);
    pinned.close()?;
    // Ordinary edits continue on the replacement tree.
    let changes = BTreeMap::from([(key(1000), Some(b"after".to_vec()))]);
    let (root, writes) = edit(store, &rebuilt, &changes);
    publish(
        &stores,
        &writes,
        &rebuilt.advance(4, Some(applied(4)), root, 31, 3_005),
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_edit_recovery_reclaims_only_its_family() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch).await;
    let store = stores.application();
    let large: BTreeMap<_, _> = (0..256u64)
        .map(|n| (key(n), Some(vec![n as u8; 8_000])))
        .collect();
    let edits: Vec<Edit<'_>> = large
        .iter()
        .map(|(key, value)| Edit::Put(key, value.as_deref().unwrap()))
        .collect();
    // Two abandoned staged edits: the primary family's and another space's.
    let primary = edit_tree_staged(store, INITIAL_SPACE[0], &TreeRoot::new_tree(), &edits)?;
    let other = edit_tree_staged(store, "test.other", &TreeRoot::new_tree(), &edits)?;
    assert!(primary.staged_batches() > 1 && other.staged_batches() > 1);
    drop((primary, other));
    assert!(space_rows(store, INITIAL_SPACE[0]) > 0);
    assert!(space_rows(store, "test.other") > 0);
    assert!(recover_abandoned_edits_in(store, FAMILY)? > 0);
    assert_eq!(space_rows(store, INITIAL_SPACE[0]), 0);
    assert!(space_rows(store, "test.other") > 0);
    assert_eq!(recover_abandoned_edits_in(store, FAMILY)?, 0);
    assert!(recover_abandoned_edits(store)? > 0);
    assert_eq!(space_rows(store, "test.other"), 0);
    assert_eq!(space_rows(store, "kasumi.app.edit-owners.v2"), 0);
    assert_eq!(space_rows(store, "kasumi.app.edit-batches.v2"), 0);
    Ok(())
}
