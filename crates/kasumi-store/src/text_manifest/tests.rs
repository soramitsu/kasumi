use super::*;
use crate::ordered_pages::{Edit, edit_tree, stage_tree};
use crate::test_utils::{FaultBackend, LocalKeyProvider, ManualClock};

async fn store() -> (tempfile::TempDir, Arc<TenantStore>) {
    let directory = crate::test_utils::private_tempdir().unwrap();
    let memory = crate::test_utils::TestDiskMemory::new(512 << 20, 4096);
    let scratch = ScratchDisk::fixture(directory.path(), memory);
    let node = NodeStore::create_with_backend(
        FaultBackend::new(),
        crate::test_utils::storage_admission(),
        scratch,
    )
    .unwrap();
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        node,
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([31; 32])),
        Arc::new(ManualClock::new()),
    )
    .await
    .unwrap();
    (directory, store)
}

fn manifest(revision: u64, status: TextStatus, space: &str, records: TreeRoot) -> TextManifest {
    TextManifest::new(
        "tenant",
        "incarnation",
        10,
        revision,
        status,
        space,
        records,
        1,
        records.count(),
        records.bytes(),
    )
}

/// Stage a one-row generation and the writes selecting it.
fn generation(store: &Arc<TenantStore>, row: &[u8]) -> (NamespaceStage, TreeRoot, Vec<WriteOp>) {
    NamespaceStage::reclaim_family(store, FAMILY).unwrap();
    let family = SelectedGeneration::adopt(store, FAMILY, &INITIAL_SPACE).unwrap();
    let stage = NamespaceStage::begin_generation(store, FAMILY).unwrap();
    let root = stage_tree(&stage, TreeRoot::new_tree().tree, |builder| {
        builder.push(row, b"shard")
    })
    .unwrap();
    let writes = family.switch_writes(store, &[&stage]).unwrap();
    (stage, root, writes)
}

#[tokio::test]
async fn text_directory_rows_move_only_forward_on_their_selected_tree() -> Result<()> {
    let (_directory, store) = store().await;
    let initial = TreeRoot::empty(TreeRoot::new_tree().tree);
    // No directory may be written without a staged generation.
    assert!(
        store
            .write_batch(&[manifest(11, TextStatus::Current, INITIAL_SPACE[0], initial).write()?])
            .is_err()
    );
    assert!(TextManifest::load(&store)?.is_none());

    let (stage, root, mut writes) = generation(&store, b"a");
    let first = manifest(11, TextStatus::Current, stage.namespace(), root);
    // A manifest naming another space than the switch selects is refused.
    let mut wrong = writes.clone();
    wrong.push(manifest(11, TextStatus::Current, "kasumi.app.text@other", root).write()?);
    assert!(store.write_batch(&wrong).is_err());
    writes.push(first.write()?);
    store.write_batch(&writes)?;
    assert_eq!(TextManifest::load(&store)?, Some(first.clone()));
    let pinned = store.read_view()?;

    // Forward edits of the selected tree advance; replays and rewinds do not.
    let edit = edit_tree(
        &*store,
        stage.namespace(),
        &root,
        &[Edit::Put(b"b", b"second")],
    )?;
    let (edited, rows, _workspace) = edit.into_parts();
    let next = manifest(12, TextStatus::Current, stage.namespace(), edited);
    for rejected in [
        manifest(11, TextStatus::Current, stage.namespace(), edited),
        manifest(10, TextStatus::Current, stage.namespace(), edited),
        manifest(
            12,
            TextStatus::Current,
            stage.namespace(),
            TreeRoot::new_tree(),
        ),
        TextManifest {
            incarnation: "other".into(),
            ..next.clone()
        },
    ] {
        let mut batch = rows.clone();
        batch.push(rejected.write()?);
        assert!(store.write_batch(&batch).is_err());
    }
    let mut batch = rows;
    batch.push(next.write()?);
    store.write_batch(&batch)?;
    assert_eq!(TextManifest::load(&store)?, Some(next.clone()));
    // The pinned view still reads the generation it observed.
    assert_eq!(TextManifest::load_at(&pinned)?, Some(first));
    pinned.close()?;

    // A failed publication may mark the directory stale at its revision; a
    // stale directory is never edited, only replaced.
    store.write_batch(&[next.stale_at(12).write()?])?;
    assert!(
        store
            .write_batch(&[manifest(13, TextStatus::Current, stage.namespace(), edited).write()?])
            .is_err()
    );
    let (replacement, rebuilt, mut writes) = generation(&store, b"c");
    writes.push(manifest(13, TextStatus::Current, replacement.namespace(), rebuilt).write()?);
    store.write_batch(&writes)?;
    let current = TextManifest::load(&store)?.unwrap();
    assert!(current.is_current());
    assert_eq!(current.page_space, replacement.namespace());
    // The replaced generation retired with the switch and reclaims fully.
    NamespaceStage::reclaim_family(&store, FAMILY)?;
    let view = store.read_view()?;
    let mut leftover = 0;
    view.visit(stage.namespace(), 1 << 20, |_, _| {
        leftover += 1;
        Ok(())
    })?;
    view.close()?;
    assert_eq!(leftover, 0);
    Ok(())
}
