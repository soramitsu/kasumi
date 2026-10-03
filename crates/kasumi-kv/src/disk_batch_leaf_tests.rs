use super::*;

fn padded_key(id: u32) -> [u8; 256] {
    let mut key = [0; 256];
    key[..4].copy_from_slice(&id.to_be_bytes());
    key
}

#[test]
fn sixteen_sorted_updates_copy_one_multileaf_path_and_keep_both_snapshots_hot() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(16 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    let mut setup = vec![Operation::create_table("accounts")];
    setup.extend((0..128u32).map(|id| Operation::put("accounts", padded_key(id), [id as u8; 16])));
    state.commit(&setup).unwrap();
    let old = state.snapshot().unwrap();
    assert_eq!(old.root().height, 2);
    assert_eq!(old.root().entries, 129);
    let updates: Vec<_> = (0..16u32)
        .map(|id| Operation::put("accounts", padded_key(id), [200 + id as u8; 16]))
        .collect();
    let before = state.arena.stats().unwrap();
    let reads_before = reads.count();
    state.commit(&updates).unwrap();
    let after = state.arena.stats().unwrap();
    let pages_read = after.pages_read - before.pages_read;
    let pages_written = after.pages_written - before.pages_written;
    let arena_syncs = after.syncs - before.syncs;
    let backend_reads = reads.count() - reads_before;
    let current = state.snapshot().unwrap();
    assert_eq!(current.root().height, 2);
    assert_eq!(current.root().entries, old.root().entries);
    assert_eq!(
        pages_written, 2,
        "one leaf and its selecting root are copied once"
    );
    assert_eq!(arena_syncs, 1);
    eprintln!(
        "native_batch_cow operations=16 height=2 pages_read={pages_read} pages_written={pages_written} arena_syncs={arena_syncs} backend_reads={backend_reads}"
    );
    let resident_reads = reads.count();
    for id in 0..128u32 {
        assert_eq!(
            value(&mut state, &old, &padded_key(id)).unwrap(),
            [id as u8; 16]
        );
        let expected = if id < 16 { 200 + id as u8 } else { id as u8 };
        assert_eq!(
            value(&mut state, &current, &padded_key(id)).unwrap(),
            [expected; 16]
        );
    }
    assert_eq!(
        reads.count(),
        resident_reads,
        "fitting pinned and current multileaf roots stay resident"
    );
    assert_eq!(state.cache_stats().unwrap().evictions, 0);
    let expected_root = current.root();
    drop((old, current, state));
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let mut reopened = DiskState::open(
        Arc::new(reads.group.crash()),
        admission.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    let current = reopened.snapshot().unwrap();
    assert_eq!(current.root(), expected_root);
    for id in 0..128u32 {
        let expected = if id < 16 { 200 + id as u8 } else { id as u8 };
        assert_eq!(
            value(&mut reopened, &current, &padded_key(id)).unwrap(),
            [expected; 16]
        );
    }
    drop((current, reopened));
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn sixteen_sorted_puts_copy_one_leaf_and_preserve_snapshot_parity() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(16 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    state
        .commit(&[Operation::create_table("accounts")])
        .unwrap();
    let old = state.snapshot().unwrap();
    assert_eq!(old.root().height, 1);
    assert_eq!(old.root().entries, 1);

    // EncryptedTableBatch publishes its existing table's staged BTreeMap as
    // one sorted run. These tiny rows fit together in the existing root leaf.
    let operations: Vec<_> = (0..16u32)
        .map(|key| Operation::put("accounts", key.to_be_bytes(), [key as u8; 16]))
        .collect();
    let before = state.arena.stats().unwrap();
    let reads_before = reads.count();
    state.commit(&operations).unwrap();
    // Capture native work before verification performs any additional reads.
    let after = state.arena.stats().unwrap();
    let backend_reads = reads.count() - reads_before;
    let pages_read = after.pages_read - before.pages_read;
    let pages_written = after.pages_written - before.pages_written;
    let arena_syncs = after.syncs - before.syncs;
    let current = state.snapshot().unwrap();
    assert_eq!(current.root().height, 1);
    assert_eq!(current.root().entries, 17);
    assert_eq!(
        pages_written, 1,
        "one batch copies the fitting root leaf once"
    );
    assert_eq!(
        arena_syncs, 1,
        "one transaction synchronizes its pages once"
    );
    eprintln!(
        "native_batch_cow operations=16 height=1 live_pages=1 pages_read={pages_read} pages_written={pages_written} arena_syncs={arena_syncs} backend_reads={backend_reads}"
    );

    let resident_reads = reads.count();
    for key in 0..16u32 {
        assert_eq!(value(&mut state, &old, &key.to_be_bytes()), None);
        assert_eq!(
            value(&mut state, &current, &key.to_be_bytes()).unwrap(),
            [key as u8; 16],
        );
    }
    assert_eq!(
        reads.count(),
        resident_reads,
        "fitting old and new roots stay hot"
    );
    assert_eq!(state.cache_stats().unwrap().evictions, 0);
    let expected = current.root();
    drop(old);
    drop(current);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);

    let mut reopened = DiskState::open(
        Arc::new(reads.group.crash()),
        admission.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    let current = reopened.snapshot().unwrap();
    assert_eq!(current.root(), expected);
    for key in 0..16u32 {
        assert_eq!(
            value(&mut reopened, &current, &key.to_be_bytes()).unwrap(),
            [key as u8; 16],
        );
    }
    assert_eq!(value(&mut reopened, &current, &16u32.to_be_bytes()), None);
    drop(current);
    drop(reopened);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn batch_runs_preserve_repeated_descending_and_create_table_operation_order() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(16 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", b"old-a"),
            Operation::put("accounts", b"b", b"old-b"),
        ])
        .unwrap();
    let old = state.snapshot().unwrap();
    // Cross the 16-entry run boundary before the interleaved creations.
    // Prepared value locations retain their absolute transaction indices.
    let mut operations: Vec<_> = (0..18u32)
        .map(|id| {
            Operation::put(
                "accounts",
                format!("batch/{id:02}").into_bytes(),
                id.to_be_bytes(),
            )
        })
        .collect();
    // The native API keeps caller order. Descending and repeated keys split
    // runs, and a following table creation must be visible to its own puts.
    operations.extend([
        Operation::put("accounts", b"c", b"first-c"),
        Operation::put("accounts", b"b", b"first-b"),
        Operation::delete("accounts", b"a"),
        Operation::put("accounts", b"a", b"new-a"),
        Operation::delete("accounts", b"b"),
        Operation::put("accounts", b"c", b"new-c"),
        Operation::create_table("documents"),
        Operation::put("documents", b"a", b"doc-a"),
        Operation::put("documents", b"b", b"doc-b"),
        Operation::create_table("accounts"),
        Operation::put("accounts", b"z", b"tail"),
    ]);
    state.commit(&operations).unwrap();
    let current = state.snapshot().unwrap();
    let before = reads.count();
    assert_eq!(value(&mut state, &old, b"a").unwrap(), b"old-a");
    assert_eq!(value(&mut state, &old, b"b").unwrap(), b"old-b");
    assert_eq!(value(&mut state, &old, b"c"), None);
    assert!(!state.table_exists(&old, "documents").unwrap());
    for id in 0..18u32 {
        let key = format!("batch/{id:02}");
        assert_eq!(value(&mut state, &old, key.as_bytes()), None);
        assert_eq!(
            value(&mut state, &current, key.as_bytes()).unwrap(),
            id.to_be_bytes()
        );
    }
    for (key, expected) in [
        (b"a", b"new-a".as_slice()),
        (b"c", b"new-c"),
        (b"z", b"tail"),
    ] {
        assert_eq!(value(&mut state, &current, key).unwrap(), expected);
    }
    assert_eq!(value(&mut state, &current, b"b"), None);
    for (key, expected) in [(b"a", b"doc-a"), (b"b", b"doc-b")] {
        assert_eq!(
            state
                .get(&current, "documents", key, 16)
                .unwrap()
                .unwrap()
                .as_bytes(),
            expected,
        );
    }
    assert_eq!(
        reads.count(),
        before,
        "ordered fallback leaves fitting roots hot"
    );
    let expected_root = current.root();
    drop((old, current, state));
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    let mut reopened = DiskState::open(
        Arc::new(reads.group.crash()),
        admission.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    let current = reopened.snapshot().unwrap();
    assert_eq!(current.root(), expected_root);
    for id in 0..18u32 {
        assert_eq!(
            value(&mut reopened, &current, format!("batch/{id:02}").as_bytes()).unwrap(),
            id.to_be_bytes()
        );
    }
    assert_eq!(value(&mut reopened, &current, b"a").unwrap(), b"new-a");
    assert_eq!(value(&mut reopened, &current, b"b"), None);
    assert_eq!(value(&mut reopened, &current, b"c").unwrap(), b"new-c");
    assert_eq!(value(&mut reopened, &current, b"z").unwrap(), b"tail");
    assert_eq!(
        reopened
            .get(&current, "documents", b"b", 16)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"doc-b",
    );
    drop((current, reopened));
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}
