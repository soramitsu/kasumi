use super::*;

fn assert_two_records_on_both_split_sides(backend: &MemoryPages, before: usize) {
    let pages = backend.pages.lock().unwrap();
    for level in 0..MAX_HEIGHT {
        let mut counts = pages[before..]
            .iter()
            .filter(|page| usize::from(page[44]) == level)
            .map(|page| le_u16(&page[46..48]));
        if let (Some(left), Some(right)) = (counts.next(), counts.next()) {
            assert!(
                left >= 2 && right >= 2,
                "level {level} split {left}+{right}"
            );
        }
        assert!(
            counts.next().is_none(),
            "more than two pages at level {level}"
        );
    }
}

#[test]
fn cow_short_table_marker_descending_max_keys_keep_both_split_sides_nonunary() {
    let backend = MemoryPages::default();
    let admission = Admission::new(160 << 10);
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let table = "t".repeat(MAX_TABLE_BYTES);
    let marker = DirectoryValue::Table { birth_seq: 1 };
    let mut root = mutator
        .set(empty_root(), 1, DirectoryKey::table(&table), Some(marker))
        .unwrap();
    let mut model = BTreeMap::new();
    model.insert((table.clone(), None), marker);
    for id in (0..40).rev() {
        let before = backend.pages.lock().unwrap().len();
        let old_height = root.height;
        root = mutator
            .set(
                root,
                1,
                DirectoryKey::row(&table, &long_key(id)),
                Some(value(1, id as u64)),
            )
            .unwrap();
        assert_two_records_on_both_split_sides(&backend, before);
        assert!(backend.pages.lock().unwrap().len() - before <= 2 * usize::from(old_height) + 1);
        model.insert(
            (table.clone(), Some(long_key(id).to_vec())),
            value(1, id as u64),
        );
    }
    // The former half-byte-only splitter reaches height 20 here.
    assert!(
        root.height <= 6,
        "descending rows produced height {}",
        root.height
    );
    let snapshot = mutator.finish(root).unwrap();
    assert_directory_model(&backend, admission.clone(), snapshot, &model);
    for id in 0..40 {
        let before = backend.pages.lock().unwrap().len();
        root = mutator
            .set(root, 2, DirectoryKey::row(&table, &long_key(id)), None)
            .unwrap();
        assert_two_records_on_both_split_sides(&backend, before);
    }
    assert_eq!(root.height, 1);
    assert_eq!(root.entries, 1);
    root = mutator
        .set(root, 2, DirectoryKey::table(&table), None)
        .unwrap();
    assert_eq!(root.height, 0);
    assert_eq!(root.entries, 0);
    assert_directory_model(&backend, admission.clone(), snapshot, &model);
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn cow_mixed_separator_growth_and_deletion_preserve_split_record_counts() {
    let backend = MemoryPages::default();
    let admission = Admission::new(160 << 10);
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let table = "t".repeat(MAX_TABLE_BYTES);
    let mut root = empty_root();
    let mut model = BTreeMap::new();
    for id in (0..96).rev() {
        let bytes = long_key(id);
        let key = &bytes[..if id % 3 == 0 { 8 } else { MAX_KEY_BYTES }];
        let before = backend.pages.lock().unwrap().len();
        root = mutator
            .set(
                root,
                1,
                DirectoryKey::row(&table, key),
                Some(value(1, id as u64)),
            )
            .unwrap();
        assert_two_records_on_both_split_sides(&backend, before);
        model.insert((table.clone(), Some(key.to_vec())), value(1, id as u64));
    }
    let snapshot = mutator.finish(root).unwrap();
    let old_model = model.clone();
    for id in (0..96).step_by(3) {
        // Removing short minima can grow copied branch separators even while
        // the number of leaf records decreases.
        let bytes = long_key(id);
        let key = &bytes[..8];
        let before = backend.pages.lock().unwrap().len();
        root = mutator
            .set(root, 2, DirectoryKey::row(&table, key), None)
            .unwrap();
        assert_two_records_on_both_split_sides(&backend, before);
        model.remove(&(table.clone(), Some(key.to_vec())));
    }
    assert_eq!(mutator.finish(root).unwrap(), root);
    assert_directory_model(&backend, admission.clone(), root, &model);
    assert_directory_model(&backend, admission.clone(), snapshot, &old_model);
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn cow_transaction_page_bound_covers_old_unary_paths_and_root_regrowth() {
    let backend = MemoryPages::default();
    let admission = Admission::new(160 << 10);
    let table = "t".repeat(MAX_TABLE_BYTES);
    let marker = DirectoryValue::Table { birth_seq: 1 };
    let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
    builder.push(DirectoryKey::table(&table), marker).unwrap();
    for id in 0..96 {
        builder
            .push(
                DirectoryKey::row(&table, &long_key(id)),
                value(1, id as u64),
            )
            .unwrap();
    }
    let mut root = builder.finish().unwrap();
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    for id in 0..95 {
        root = mutator
            .set(root, 2, DirectoryKey::row(&table, &long_key(id)), None)
            .unwrap();
    }
    // Two distant survivors retain the old root's height. Every branch on
    // the first child's path is now unary; live-entry logarithms are invalid.
    assert_eq!(root.entries, 2);
    assert!(root.height >= 3);
    {
        let reader = DirectoryReader::new(&backend, admission.clone());
        let mut buffer =
            PageBuffer::new(&(admission.clone() as Arc<dyn StorageAdmission>)).unwrap();
        let mut bounds = Bounds::root(root);
        let mut reference = root.page.unwrap();
        let mut is_root = true;
        loop {
            let info = reader.load(&mut buffer, root, reference, &bounds).unwrap();
            if info.level == 0 {
                break;
            }
            if !is_root {
                assert_eq!(info.count, 1);
            }
            reference = bounds.child(&buffer.bytes, info, 0).unwrap();
            is_root = false;
        }
    }
    let sparse_snapshot = mutator.finish(root).unwrap();
    let mut sparse_model = BTreeMap::new();
    sparse_model.insert((table.clone(), None), marker);
    sparse_model.insert((table.clone(), Some(long_key(95).to_vec())), value(1, 95));
    let planned_root = root;
    let initial_height = usize::from(root.height);
    let first_page = backend.pages.lock().unwrap().len();
    let mut edits = 0usize;
    let mut page_bound = 0usize;
    // Grow within the old sparse topology; collapse below the fixed initial
    // base level; then regrow beyond that level in the same private sequence.
    for phase in 0..3 {
        let count = [95, 96, 160][phase];
        for ordinal in 0..count {
            let (id, selected) = match phase {
                0 => (94 - ordinal, Some(value(3, (94 - ordinal) as u64))),
                1 => (ordinal, None),
                _ => (159 - ordinal, Some(value(3, (159 - ordinal) as u64))),
            };
            let old_height = root.height;
            let height_bound = (initial_height + (edits + 1).ilog2() as usize).min(MAX_HEIGHT);
            page_bound += 2 * height_bound + 1;
            let before = backend.pages.lock().unwrap().len();
            root = mutator
                .set(root, 3, DirectoryKey::row(&table, &long_key(id)), selected)
                .unwrap();
            edits += 1;
            assert_two_records_on_both_split_sides(&backend, before);
            let pages = backend.pages.lock().unwrap().len();
            assert!(pages - before <= 2 * usize::from(old_height.max(1)) + 1);
            let actual_bound = planned_root.transaction_page_bound(edits).unwrap();
            assert_eq!(actual_bound, page_bound as u64);
            assert!((pages - first_page) as u64 <= actual_bound);
            let next_bound = (initial_height + (edits + 1).ilog2() as usize).min(MAX_HEIGHT);
            assert!(usize::from(root.height) <= next_bound);
        }
        if phase == 1 {
            assert_eq!(root.height, 1);
        }
    }
    assert!(usize::from(root.height) >= initial_height);
    assert_eq!(mutator.finish(root).unwrap(), root);
    let mut model = BTreeMap::new();
    model.insert((table.clone(), None), marker);
    for id in 0..160 {
        model.insert(
            (table.clone(), Some(long_key(id).to_vec())),
            value(3, id as u64),
        );
    }
    assert_directory_model(&backend, admission.clone(), root, &model);
    assert_directory_model(&backend, admission.clone(), sparse_snapshot, &sparse_model);
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}
