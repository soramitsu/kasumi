use super::*;
use crate::ordered_pages::{
    Direction, Edit, OVERFLOW_CHUNK_BYTES, TreeReader, edit_tree_staged,
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
        ("tenant".to_owned(), 41),
        (CustodyStore::catalog_name("tenant"), 42),
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

fn applied(index: u64) -> StructuredApplied {
    StructuredApplied {
        index,
        log_sha256: [index as u8; 32],
        command_sha256: Some([0xc0 | index as u8; 32]),
    }
}

const LAYOUT: [u8; 32] = [7; 32];

fn key(n: u64) -> Vec<u8> {
    format!("Vdocs\x00\x01{n:08}").into_bytes()
}

fn rows(
    view: &dyn crate::ordered_pages::PageSource,
    manifest: &StructuredManifest,
) -> Vec<Vec<u8>> {
    let reader = TreeReader::new(view, &manifest.page_space, manifest.records, None).unwrap();
    let mut rows = Vec::new();
    reader
        .scan(Bound::Unbounded, Direction::Forward, &mut |key, _| {
            rows.push(key.to_vec());
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
    manifest: &StructuredManifest,
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
    manifest: &StructuredManifest,
    changes: &BTreeMap<Vec<u8>, bool>,
) -> (TreeRoot, Vec<WriteOp>, u32) {
    let edits: Vec<Edit<'_>> = changes
        .iter()
        .map(|(key, present)| {
            if *present {
                Edit::Put(key, &[])
            } else {
                Edit::Delete(key)
            }
        })
        .collect();
    let edit = edit_tree_staged(store, &manifest.page_space, &manifest.records, &edits).unwrap();
    let staged = edit.staged_batches();
    let (root, writes, _workspace) = edit.into_parts();
    (root, writes, staged)
}

fn empty(revision: u64) -> StructuredManifest {
    StructuredManifest::new(
        "tenant",
        "incarnation",
        0,
        revision,
        Some(applied(revision)),
        LAYOUT,
        INITIAL_SPACE[0],
        TreeRoot::new_tree(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_structured_directory_moves_only_forward_and_pinned_views_keep_their_root() -> Result<()>
{
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch).await;
    let store = stores.application();
    assert_eq!(StructuredManifest::load(store)?, None);

    let base = empty(4);
    let first: BTreeMap<_, _> = (0..300u64).map(|n| (key(n), true)).collect();
    let (root, writes, _) = edit(store, &base, &first);
    let four = base.advance(5, Some(applied(5)), LAYOUT, root);
    publish(&stores, &writes, &four)?;
    assert_eq!(StructuredManifest::load(store)?.as_ref(), Some(&four));
    let pinned = store.read_view()?;

    // The next edit removes and adds rows; the pinned view still reads its root.
    let second: BTreeMap<_, _> = (0..150u64)
        .map(|n| (key(n * 2), false))
        .chain((300..320u64).map(|n| (key(n), true)))
        .collect();
    let (root, writes, _) = edit(store, &four, &second);
    let six = four.advance(6, Some(applied(6)), [8; 32], root);
    publish(&stores, &writes, &six)?;
    let at_pin = StructuredManifest::load_at(&pinned)?.expect("pinned manifest");
    assert_eq!(at_pin, four);
    assert_eq!(rows(&pinned, &at_pin).len(), 300);
    assert_eq!(rows(&**store, &six).len(), 170);
    pinned.close()?;

    // Covered replay cannot move the directory backward, repeat a revision
    // as current, or swap in another tree without a selection switch.
    for wrong in [
        six.advance(5, Some(applied(5)), LAYOUT, six.records),
        six.advance(6, Some(applied(6)), LAYOUT, six.records),
        StructuredManifest {
            records: TreeRoot::new_tree(),
            ..six.advance(7, Some(applied(7)), LAYOUT, six.records)
        },
        StructuredManifest {
            incarnation: "other".into(),
            ..six.advance(7, Some(applied(7)), LAYOUT, six.records)
        },
    ] {
        assert!(publish(&stores, &[], &wrong).is_err());
    }
    assert_eq!(StructuredManifest::load(store)?.as_ref(), Some(&six));

    // A stale successor keeps its tree; nothing but a replacement follows it.
    assert!(
        publish(
            &stores,
            &[],
            &StructuredManifest {
                records: TreeRoot::new_tree(),
                ..six.stale(7, Some(applied(7)))
            }
        )
        .is_err()
    );
    let stale = six.stale(7, Some(applied(7)));
    publish(&stores, &[], &stale)?;
    assert!(
        publish(
            &stores,
            &[],
            &stale.advance(8, Some(applied(8)), LAYOUT, six.records)
        )
        .is_err()
    );
    assert!(publish(&stores, &[], &stale.stale(8, Some(applied(8)))).is_err());

    // A replacement generation is staged, sealed and selected with its manifest.
    let family = SelectedGeneration::adopt(store, FAMILY, &INITIAL_SPACE)?;
    let stage = NamespaceStage::begin_generation(store, FAMILY)?;
    let records = stage_tree(&stage, TreeRoot::new_tree().tree, |builder| {
        for n in 0..50u64 {
            builder.push(&key(n), &[])?;
        }
        Ok(())
    })?;
    let rebuilt = StructuredManifest::new(
        "tenant",
        "incarnation",
        0,
        9,
        Some(applied(9)),
        LAYOUT,
        stage.namespace(),
        records,
    );
    // The manifest must name the space the same batch selects.
    assert!(publish(&stores, &[], &rebuilt).is_err());
    let mut switch = family.switch_writes(store, &[&stage])?;
    assert!(
        publish(
            &stores,
            &switch,
            &StructuredManifest {
                status: StructuredStatus::Stale,
                ..rebuilt.clone()
            }
        )
        .is_err()
    );
    // A switch without its manifest would leave the old row behind.
    assert!(stores.write_batch(&switch, &[]).is_err());
    switch.push(rebuilt.write()?);
    stores.write_batch(&switch, &[])?;
    assert_eq!(StructuredManifest::load(store)?.as_ref(), Some(&rebuilt));
    assert_eq!(rows(&**store, &rebuilt).len(), 50);
    NamespaceStage::reclaim_family(store, FAMILY)?;
    assert_eq!(space_rows(store, INITIAL_SPACE[0]), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interrupted_staged_structured_edit_is_abandoned_within_its_family() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch).await;
    let store = stores.application();
    let base = empty(1);
    let first: BTreeMap<_, _> = (0..4000u64).map(|n| (key(n), true)).collect();
    let (root, writes, staged) = edit(store, &base, &first);
    assert!(staged > 0, "a large edit stages journaled batches");
    let two = base.advance(2, Some(applied(2)), LAYOUT, root);
    publish(&stores, &writes, &two)?;
    // The published journal's displaced rows are reclaimed afterwards.
    recover_abandoned_edits_in(store, FAMILY)?;
    let selected = space_rows(store, INITIAL_SPACE[0]);
    assert_eq!(rows(&**store, &two).len(), 4000);

    // A second large edit stages its batches and then never publishes.
    let second: BTreeMap<_, _> = (0..4000u64)
        .map(|n| (key(n), n % 2 == 0))
        .chain((4000..7000u64).map(|n| (key(n), true)))
        .collect();
    let (_root, _writes, staged) = edit(store, &two, &second);
    assert!(staged > 0);
    assert!(space_rows(store, INITIAL_SPACE[0]) > selected);
    // Another family's recovery leaves this family's journal alone.
    assert_eq!(
        recover_abandoned_edits_in(store, crate::application_manifest::PAGE_FAMILY)?,
        0
    );
    assert!(space_rows(store, INITIAL_SPACE[0]) > selected);
    assert!(recover_abandoned_edits_in(store, FAMILY)? > 0);
    assert_eq!(space_rows(store, INITIAL_SPACE[0]), selected);
    // The selected directory is untouched and still edits forward.
    assert_eq!(StructuredManifest::load(store)?.as_ref(), Some(&two));
    assert_eq!(rows(&**store, &two).len(), 4000);
    let (root, writes, _) = edit(store, &two, &second);
    let three = two.advance(3, Some(applied(3)), LAYOUT, root);
    publish(&stores, &writes, &three)?;
    recover_abandoned_edits_in(store, FAMILY)?;
    assert_eq!(rows(&**store, &three).len(), 5000);
    Ok(())
}

#[test]
fn legacy_structured_manifest_stays_writable_and_requires_replacement_to_claim_tuple_coverage() {
    let mut legacy = StructuredManifest::new(
        "tenant",
        "incarnation",
        0,
        0,
        None,
        [7; 32],
        INITIAL_SPACE[0],
        TreeRoot::new_tree(),
    );
    legacy.format = 1;
    let decoded = StructuredManifest::decode(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert_eq!(decoded, legacy);
    let applied = StructuredApplied {
        index: 1,
        log_sha256: [3; 32],
        command_sha256: Some([4; 32]),
    };
    let next = legacy.advance(1, Some(applied), legacy.layout_sha256, legacy.records);
    next.write().unwrap();
    next.check_successor(&legacy).unwrap();
    let mut forged = next.clone();
    forged.format = ORDERED_TUPLE_FORMAT;
    assert!(forged.check_successor(&legacy).is_err());
}
