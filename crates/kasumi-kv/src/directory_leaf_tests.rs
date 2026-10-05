fn build_leaf_fixture(
    backend: &dyn DirectoryBackend,
    admission: Arc<dyn StorageAdmission>,
    population: usize,
    long: bool,
) -> (DirectoryRoot, BTreeMap<ModelKey, DirectoryValue>) {
    let mut builder = DirectoryBuilder::new(backend, admission, GROUP, 7).unwrap();
    let mut model = BTreeMap::new();
    let table = DirectoryValue::Table { birth_seq: 1 };
    builder.push(DirectoryKey::table("t"), table).unwrap();
    model.insert(("t".into(), None), table);
    for id in 0..population {
        let bytes = long_key(id * 2);
        let key = if long { bytes.as_slice() } else { &bytes[..8] };
        let row = value(3, id as u64);
        builder.push(DirectoryKey::row("t", key), row).unwrap();
        model.insert(("t".into(), Some(key.to_vec())), row);
    }
    (builder.finish().unwrap(), model)
}

#[test]
fn leaf_plans_find_boundaries_and_return_admitted_cursors_without_collecting_prior_keys() {
    let backend = MemoryPages::default();
    let admission = Admission::new(256 << 10);
    let (root, model) = build_leaf_fixture(&backend, admission.clone(), 1200, false);
    let reader = DirectoryReader::new(&backend, admission.clone());
    let mut cursor: Option<DirectoryRecord> = None;
    let mut found = BTreeMap::new();
    let mut previous_reference = None;
    let mut leaves = 0;
    loop {
        let lower = cursor
            .as_ref()
            .map_or(DirectoryKey::table("t"), |record| record.key());
        let Some(leaf) = reader.leaf_after(root, lower, cursor.is_some()).unwrap() else {
            break;
        };
        assert_eq!(leaf.first_index(), 0);
        assert!(leaf.len() <= MAX_DIRECTORY_LEAF_RECORDS);
        assert_eq!(leaf.records().len(), leaf.len());
        assert_ne!(Some(leaf.reference()), previous_reference);
        for (key, value) in leaf.records() {
            assert!(
                found
                    .insert((key.table.into(), key.row.map(<[u8]>::to_vec)), value)
                    .is_none()
            );
        }
        let middle = leaf.owned_record(leaf.len() / 2).unwrap();
        let inclusive = reader
            .leaf_after(root, middle.key(), false)
            .unwrap()
            .unwrap();
        assert_eq!(inclusive.reference(), leaf.reference());
        assert_eq!(inclusive.first_index(), leaf.len() / 2);
        drop(inclusive);
        let exclusive = reader
            .leaf_after(root, middle.key(), true)
            .unwrap()
            .unwrap();
        assert_eq!(exclusive.reference(), leaf.reference());
        assert_eq!(exclusive.first_index(), leaf.len() / 2 + 1);
        drop(exclusive);
        let before = admission.0.used.load(AtomicOrdering::Relaxed);
        assert!(
            matches!(&(leaf.owned_record(leaf.len())), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), before);
        cursor = Some(leaf.owned_record(leaf.len() - 1).unwrap());
        previous_reference = Some(leaf.reference());
        leaves += 1;
    }
    assert!(leaves > 1);
    assert_eq!(found, model);
    let gap = long_key(17);
    let leaf = reader
        .leaf_after(root, DirectoryKey::row("t", &gap[..8]), false)
        .unwrap()
        .unwrap();
    assert_eq!(
        leaf.owned_record(leaf.first_index()).unwrap().key().row,
        Some(&long_key(18)[..8])
    );
    assert!(
        reader
            .leaf_after(empty_root(), DirectoryKey::table("t"), false)
            .unwrap()
            .is_none()
    );
    drop((leaf, cursor));
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn leaf_batch_rewrites_one_path_preserving_versions_counts_siblings_and_old_roots() {
    let backend = MemoryPages::default();
    let admission = Admission::new(256 << 10);
    let (root, model) = build_leaf_fixture(&backend, admission.clone(), 64, true);
    assert!(root.height > 1);
    let reader = DirectoryReader::new(&backend, admission.clone());
    let leaf = reader
        .leaf_after(root, DirectoryKey::table("t"), false)
        .unwrap()
        .unwrap();
    assert!(leaf.len() > 1);
    let original_pages = backend.pages.lock().unwrap().clone();
    let mut expected = model.clone();
    let replacements: Vec<_> = leaf
        .records()
        .map(|(key, old)| {
            let DirectoryValue::Row { batch_seq, value } = old else {
                return None;
            };
            let replacement = ValueLocation {
                segment_id: value.segment_id + 1000,
                offset: 512,
                ..value
            };
            expected.insert(
                (key.table.into(), key.row.map(<[u8]>::to_vec)),
                DirectoryValue::Row {
                    batch_seq,
                    value: replacement,
                },
            );
            Some(replacement)
        })
        .collect();
    let mut mutator_workspace =
        DirectoryWriteWorkspace::for_leaf_rewrite(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let next = mutator.rewrite_leaf(root, 8, &leaf, &replacements).unwrap();
    assert_ne!(next.page, root.page);
    assert_eq!(next.height, root.height);
    assert_eq!(next.entries, root.entries);
    assert_eq!(next.generation, 8);
    assert_eq!(
        backend.pages.lock().unwrap().len() - original_pages.len(),
        usize::from(root.height)
    );
    assert_eq!(
        backend.pages.lock().unwrap()[..original_pages.len()],
        original_pages
    );
    assert_eq!(mutator.finish(next).unwrap(), next);
    assert_directory_model(&backend, admission.clone(), root, &model);
    assert_directory_model(&backend, admission.clone(), next, &expected);
    let next_leaf = reader
        .leaf_after(next, DirectoryKey::table("t"), false)
        .unwrap()
        .unwrap();
    let before = backend.pages.lock().unwrap().len();
    let rewritten = mutator
        .rewrite_leaf(next, 8, &next_leaf, &vec![None; next_leaf.len()])
        .unwrap();
    assert_eq!(
        backend.pages.lock().unwrap().len() - before,
        usize::from(next.height)
    );
    assert_directory_model(&backend, admission.clone(), rewritten, &expected);
    drop((mutator, next_leaf, leaf));
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn leaf_rewrite_rejects_foreign_root_bad_shape_and_changed_value_bytes_before_append() {
    let backend = MemoryPages::default();
    let admission = Admission::new(256 << 10);
    let (root, model) = build_leaf_fixture(&backend, admission.clone(), 24, true);
    let reader = DirectoryReader::new(&backend, admission.clone());
    let leaf = reader
        .leaf_after(root, DirectoryKey::table("t"), false)
        .unwrap()
        .unwrap();
    let mut mutator_workspace =
        DirectoryWriteWorkspace::for_leaf_rewrite(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let before = backend.pages.lock().unwrap().len();
    let mut replacements = vec![None; leaf.len()];
    assert!(matches!(&(mutator.rewrite_leaf(
            DirectoryRoot {
                generation: 8,
                ..root
            },
            8,
            &leaf,
            &replacements
        )), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_)))));
    assert!(
        matches!(&(mutator.rewrite_leaf(root, 6, &leaf, &replacements)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    assert!(
        matches!(&(mutator.rewrite_leaf(root, 8, &leaf, &[])), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    let row = leaf
        .records()
        .position(|(_, value)| matches!(value, DirectoryValue::Row { .. }))
        .unwrap();
    let DirectoryValue::Row { value, .. } = leaf.owned_record(row).unwrap().value else {
        unreachable!();
    };
    for replacement in [
        ValueLocation {
            len: value.len + 1,
            ..value
        },
        ValueLocation {
            crc: value.crc ^ 1,
            ..value
        },
        ValueLocation {
            segment_id: 0,
            ..value
        },
    ] {
        replacements[row] = Some(replacement);
        assert!(
            matches!(&(mutator.rewrite_leaf(root, 8, &leaf, &replacements)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
    }
    replacements[row] = None;
    replacements[0] = Some(value);
    assert!(
        matches!(&(mutator.rewrite_leaf(root, 8, &leaf, &replacements)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    assert_eq!(backend.pages.lock().unwrap().len(), before);
    replacements[0] = None;
    let next = mutator.rewrite_leaf(root, 8, &leaf, &replacements).unwrap();
    assert_directory_model(&backend, admission, next, &model);
}

#[test]
fn leaf_plans_and_rewrites_admit_before_io_and_release_on_denial() {
    let backend = MemoryPages::default();
    let (root, _) = build_leaf_fixture(&backend, Admission::new(256 << 10), 24, true);
    let denied = Admission::new(1);
    let before = backend.reads.load(AtomicOrdering::Relaxed);
    assert!(
        matches!(&(DirectoryReader::new(&backend, denied.clone()).leaf_after(
            root,
            DirectoryKey::table("t"),
            false
        )), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), before);
    assert_eq!(denied.0.used.load(AtomicOrdering::Relaxed), 0);

    let admission = Admission::new(192 << 10);
    let leaf = DirectoryReader::new(&backend, admission.clone())
        .leaf_after(root, DirectoryKey::table("t"), false)
        .unwrap()
        .unwrap();
    let used = admission.0.used.load(AtomicOrdering::Relaxed);
    let blocker = admission
        .reserve_workspace(admission.0.limit - used)
        .unwrap();
    let reads = backend.reads.load(AtomicOrdering::Relaxed);
    let pages = backend.pages.lock().unwrap().len();
    assert!(
        matches!(&(leaf.owned_record(0)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert!(
        matches!(&(DirectoryWriteWorkspace::for_leaf_rewrite(admission.clone())), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), reads);
    assert_eq!(backend.pages.lock().unwrap().len(), pages);
    drop(blocker);
    admission.check_owner().unwrap();
    let mut mutator_workspace =
        DirectoryWriteWorkspace::for_leaf_rewrite(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();

    assert!(
        mutator
            .rewrite_leaf(root, 8, &leaf, &vec![None; leaf.len()])
            .is_ok()
    );
    drop((leaf, mutator));
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn leaf_rewrite_revalidates_parent_and_leaf_digests_before_any_effect() {
    for parent in [false, true] {
        let backend = MemoryPages::default();
        let admission = Admission::new(256 << 10);
        let (root, _) = build_leaf_fixture(&backend, admission.clone(), 24, true);
        let leaf = DirectoryReader::new(&backend, admission.clone())
            .leaf_after(root, DirectoryKey::table("t"), false)
            .unwrap()
            .unwrap();
        let reference = if parent {
            root.page.unwrap()
        } else {
            leaf.reference()
        };
        let before = backend.pages.lock().unwrap().len();
        backend.pages.lock().unwrap()[reference.page_index as usize][36] ^= 1;
        let mut mutator_workspace = DirectoryWriteWorkspace::for_leaf_rewrite(admission).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        assert!(
            matches!(&(mutator.rewrite_leaf(root, 8, &leaf, &vec![None; leaf.len()])), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
        );
        assert_eq!(backend.pages.lock().unwrap().len(), before);
        assert!(
            matches!(&(mutator.finish(root)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
    }
}

#[test]
fn leaf_rewrite_append_and_sync_failures_poison_without_changing_old_roots() {
    let backend = FailingPages::new();
    let admission = Admission::new(256 << 10);
    let (root, model) = build_leaf_fixture(&backend, admission.clone(), 24, true);
    let leaf = DirectoryReader::new(&backend, admission.clone())
        .leaf_after(root, DirectoryKey::table("t"), false)
        .unwrap()
        .unwrap();
    for count in 0..usize::from(root.height) {
        backend
            .appends_remaining
            .store(count, AtomicOrdering::Relaxed);
        let before = backend.inner.pages.lock().unwrap().len();
        let mut mutator_workspace =
            DirectoryWriteWorkspace::for_leaf_rewrite(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        assert!(
            matches!(&(mutator.rewrite_leaf(root, 8, &leaf, &vec![None; leaf.len()])), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Io(_))))
        );
        assert_eq!(backend.inner.pages.lock().unwrap().len() - before, count);
        assert!(
            matches!(&(mutator.finish(root)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert_directory_model(&backend, admission.clone(), root, &model);
    }
    backend
        .appends_remaining
        .store(usize::MAX, AtomicOrdering::Relaxed);
    let mut mutator_workspace =
        DirectoryWriteWorkspace::for_leaf_rewrite(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let next = mutator
        .rewrite_leaf(root, 8, &leaf, &vec![None; leaf.len()])
        .unwrap();
    backend.fail_sync.store(true, AtomicOrdering::Relaxed);
    assert!(
        matches!(&(mutator.finish(next)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Io(_))))
    );
    assert!(
        matches!(&(mutator.finish(next)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert_directory_model(&backend, admission.clone(), root, &model);
    drop((leaf, mutator));
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}
