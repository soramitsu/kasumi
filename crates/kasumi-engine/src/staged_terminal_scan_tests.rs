use super::*;

async fn three_rows() -> Result<(tempfile::TempDir, Arc<TenantStore>, TenantState, View)> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    kasumi_store::private_files::create_directory(&directory.path().join("persistent"))?;
    let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 128);
    let path = directory.path().join("persistent/node.kv");
    let disk = kasumi_store::test_utils::retry_disk_registry(|| {
        kasumi_store::NodeDisk::fixture_for_path(&path, memory.clone())
    })?;
    let scratch = ScratchDisk::fixture(directory.path().join("scratch"), memory);
    let node = NodeStore::create_new(
        path,
        kasumi_store::test_utils::NODE_STORE_ID,
        disk,
        scratch,
        kasumi_store::test_utils::node_storage_config(),
    )?;
    let store = TenantStore::initialize_catalog_fixture(
        node,
        "tenant".into(),
        Arc::new(LocalKeyProvider::new([89; 32])),
    )
    .await?;
    let mut state = state();
    let empty = View::empty(&state.tenant, &state.incarnation)?;
    let install = empty.prepare_install(&store, &state, &"10".repeat(32), false)?;
    store.replace_namespaces(&install.replacements(), install.writes())?;
    let mut view = install.view;
    for ordinal in 1..=3 {
        let (next, pending) = stop(&state, &view, &format!("scan-{ordinal}"), &applied(ordinal));
        view = pending.stage()?;
        state = next;
    }
    Ok((directory, store, state, view))
}
fn namespace(view: &View) -> String {
    match view.source.as_deref().unwrap() {
        Source::Durable(rows) => rows.binding.namespace(),
        Source::Staged(_) => panic!("test requires installed rows"),
    }
}

#[tokio::test]
async fn installed_scan_uses_one_snapshot_two_reads_per_row_and_settles_before_final_yield()
-> Result<()> {
    let (_directory, store, state, view) = three_rows().await?;
    let census = store.persistent_disk().memory().storage_census();
    let before = census.snapshot().readers;
    let expected = (1..=3)
        .map(|ordinal| view.row(ordinal).and_then(|row| row.sha256()))
        .collect::<Result<Vec<_>>>()?;
    let mut scan = view.records();
    let id = scan
        .registered_reader_id()
        .expect("installed registered scan");
    assert_eq!(scan.point_reads(), 1, "selected head read once before rows");
    assert_eq!(census.snapshot().readers, before + 1);
    let mut actual = vec![scan.next().unwrap()?.sha256()?];
    assert_eq!(scan.point_reads(), 3);
    assert_eq!(scan.registered_reader_id(), Some(id));
    // A later committed append stays invisible to this selected logical prefix.
    let (_, pending) = stop(&state, &view, "scan-future", &applied(4));
    let future = pending.stage()?;
    assert_eq!(future.head.count, 4);
    // Mutate a not-yet-read point after capture. The active scan keeps the old
    // immutable root; a new scan must observe and reject the changed bytes.
    let namespace = namespace(&view);
    let second = view.row(2)?;
    let original = serde_json::to_vec(&second)?;
    let mut alternate = original.clone();
    alternate.push(b' ');
    store.write_batch(&[WriteOp::put(
        &namespace,
        id_key(&second.key),
        alternate.as_slice(),
    )])?;
    actual.push(scan.next().unwrap()?.sha256()?);
    assert_eq!(scan.point_reads(), 5);
    assert_eq!(scan.registered_reader_id(), Some(id));
    actual.push(scan.next().unwrap()?.sha256()?);
    assert_eq!(actual, expected);
    assert_eq!(
        scan.point_reads(),
        6,
        "no repeated head or predecessor lookup"
    );
    assert!(scan.registered_reader_id().is_none());
    assert_eq!(
        census.snapshot().readers,
        before,
        "last row requires actual settlement"
    );
    assert!(scan.next().is_none());
    let error = view.records().collect::<Result<Vec<_>>>().unwrap_err();
    assert!(format!("{error:#}").contains("noncanonical staged terminal point"));
    assert_eq!(census.snapshot().readers, before);
    store.write_batch(&[WriteOp::put(
        &namespace,
        id_key(&second.key),
        original.as_slice(),
    )])?;
    let mut abandoned = view.records();
    assert!(abandoned.next().unwrap().is_ok());
    drop(abandoned);
    assert_eq!(
        census.snapshot().readers,
        before,
        "early cancellation retires the actual reader"
    );
    store.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn installed_scan_rejects_each_canonical_tamper_without_repair_and_keeps_prefix_checks()
-> Result<()> {
    let (_directory, store, _state, view) = three_rows().await?;
    let namespace = namespace(&view);
    let second = view.row(2)?;
    let third = view.row(3)?;
    let original_point = serde_json::to_vec(&second)?;
    let original_index = store
        .get_bounded(&namespace, &ordinal_key(2), MAX_ROW_BYTES)?
        .unwrap();
    let original_head = store
        .get_bounded(&namespace, &ordinal_key(3), MAX_ROW_BYTES)?
        .unwrap();
    for fault in 0..6 {
        let mut row = second.clone();
        let mut index: Ordinal = serde_json::from_slice(&original_index)?;
        let mut head: Ordinal = serde_json::from_slice(&original_head)?;
        let (key, bytes, original, expected) = match fault {
            0 => {
                row.previous_sha256 = "ed".repeat(32);
                // Matching the ordinal hash cannot conceal a broken parent link.
                index.sha256 = row.sha256()?;
                store.write_batch(&[WriteOp::put(
                    &namespace,
                    ordinal_key(2),
                    serde_json::to_vec(&index)?,
                )])?;
                (
                    id_key(&row.key),
                    serde_json::to_vec(&row)?,
                    original_point.clone(),
                    "terminal parent root differs",
                )
            }
            1 => {
                row.ordinal = 3;
                (
                    id_key(&row.key),
                    serde_json::to_vec(&row)?,
                    original_point.clone(),
                    "terminal ordinal redirected",
                )
            }
            2 => {
                row.key = third.key.clone();
                (
                    id_key(&second.key),
                    serde_json::to_vec(&row)?,
                    original_point.clone(),
                    "terminal point identity differs",
                )
            }
            3 => {
                index.sha256 = "ab".repeat(32);
                (
                    ordinal_key(2),
                    serde_json::to_vec(&index)?,
                    original_index.clone(),
                    "terminal row differs from ordinal commitment",
                )
            }
            4 => {
                head.sha256 = "bc".repeat(32);
                (
                    ordinal_key(3),
                    serde_json::to_vec(&head)?,
                    original_head.clone(),
                    "terminal selected root differs",
                )
            }
            5 => {
                let mut bytes = original_index.clone();
                bytes.push(b' ');
                (
                    ordinal_key(2),
                    bytes,
                    original_index.clone(),
                    "noncanonical staged terminal ordinal",
                )
            }
            _ => unreachable!(),
        };
        store.write_batch(&[WriteOp::put(&namespace, key.as_slice(), bytes.as_slice())])?;
        let error = view.records().collect::<Result<Vec<_>>>().unwrap_err();
        assert!(
            format!("{error:#}").contains(expected),
            "fault {fault}: {error:#}"
        );
        assert_eq!(
            store.get_bounded(&namespace, &key, MAX_ROW_BYTES)?,
            Some(bytes),
            "failed scan repaired data"
        );
        let mut restore = vec![WriteOp::put(&namespace, key.as_slice(), original)];
        if fault == 0 {
            restore.push(WriteOp::put(
                &namespace,
                ordinal_key(2),
                original_index.as_slice(),
            ));
        }
        store.write_batch(&restore)?;
        assert_eq!(view.records().collect::<Result<Vec<_>>>()?.len(), 3);
    }
    store.shutdown().await?;
    Ok(())
}
