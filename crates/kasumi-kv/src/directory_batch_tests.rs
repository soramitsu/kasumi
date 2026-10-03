use super::*;

fn build_model(
    backend: &dyn DirectoryBackend,
    model: &BTreeMap<ModelKey, DirectoryValue>,
) -> DirectoryRoot {
    let mut builder = DirectoryBuilder::new(backend, Admission::new(256 << 10), GROUP, 1).unwrap();
    for (key, value) in model {
        builder.push(model_key(key), *value).unwrap();
    }
    builder.finish().unwrap()
}

fn small_model() -> BTreeMap<ModelKey, DirectoryValue> {
    BTreeMap::from([
        (("t".into(), None), DirectoryValue::Table { birth_seq: 1 }),
        (("t".into(), Some(b"a".to_vec())), value(1, 1)),
        (("t".into(), Some(b"b".to_vec())), value(1, 2)),
        (("t".into(), Some(b"c".to_vec())), value(1, 3)),
    ])
}

fn pair() -> [DirectoryEdit<'static>; 2] {
    [
        DirectoryEdit {
            key: DirectoryKey::row("t", b"a"),
            value: Some(value(2, 20)),
        },
        DirectoryEdit {
            key: DirectoryKey::row("t", b"d"),
            value: Some(value(2, 21)),
        },
    ]
}

fn long_model(count: usize) -> BTreeMap<ModelKey, DirectoryValue> {
    (10..10 + count)
        .map(|id| {
            (
                ("t".into(), Some(long_key(id).to_vec())),
                value(1, id as u64),
            )
        })
        .collect()
}

fn parent_root(
    backend: &dyn DirectoryBackend,
    children: &[(Vec<u8>, DirectoryRoot)],
) -> DirectoryRoot {
    let mut builder = DirectoryBuilder::new(backend, Admission::new(256 << 10), GROUP, 1).unwrap();
    for (minimum, child) in children {
        let key = DirectoryKey::row("t", minimum);
        let mut encoded = [0; MAX_ENCODED_KEY];
        key.encode(&mut encoded[..key.encoded_len()]);
        builder
            .insert_child(
                child.height as usize,
                Carry {
                    key: encoded,
                    key_len: key.encoded_len(),
                    page: child.page.unwrap(),
                    entries: child.entries,
                },
            )
            .unwrap();
        builder.entries += child.entries;
    }
    builder.finish().unwrap()
}

#[test]
fn deeper_batches_copy_one_path_and_consume_only_the_first_leaf_prefix() {
    for (count, height) in [(6, 2), (20, 3)] {
        let backend = MemoryPages::default();
        let admission = Admission::new(256 << 10);
        let mut model = long_model(count);
        let original = model.clone();
        let old = build_model(&backend, &model);
        assert_eq!(old.height, height);
        let keys: Vec<_> = (11..15).map(long_key).collect();
        let edits: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(id, key)| DirectoryEdit {
                key: DirectoryKey::row("t", key),
                value: Some(value(2, id as u64)),
            })
            .collect();
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        let before = backend.pages.lock().unwrap().len();
        let (first, consumed) = mutator.try_set_leaf_batch(old, 2, &edits).unwrap().unwrap();
        assert_eq!(consumed, 2, "three maximum-size rows fill each leaf");
        assert_eq!(
            backend.pages.lock().unwrap().len() - before,
            height as usize
        );
        for edit in &edits[..consumed] {
            model.insert(
                ("t".into(), Some(edit.key.row.unwrap().to_vec())),
                edit.value.unwrap(),
            );
        }
        assert_directory_model(&backend, admission.clone(), first, &model);
        let before = backend.pages.lock().unwrap().len();
        let (second, consumed) = mutator
            .try_set_leaf_batch(first, 2, &edits[consumed..])
            .unwrap()
            .unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(
            backend.pages.lock().unwrap().len() - before,
            height as usize
        );
        for edit in &edits[2..] {
            model.insert(
                ("t".into(), Some(edit.key.row.unwrap().to_vec())),
                edit.value.unwrap(),
            );
        }
        let second = mutator.finish(second).unwrap();
        assert_directory_model(&backend, admission.clone(), second, &model);
        assert_directory_model(&backend, admission.clone(), old, &original);
        // One routed edit is a clean decline even though later edits fit a
        // different leaf. The caller retains absolute operation positions.
        let boundary_keys = [long_key(12), long_key(13)];
        let boundary = [
            DirectoryEdit {
                key: DirectoryKey::row("t", &boundary_keys[0]),
                value: None,
            },
            DirectoryEdit {
                key: DirectoryKey::row("t", &boundary_keys[1]),
                value: None,
            },
        ];
        let before = backend.pages.lock().unwrap().len();
        assert!(
            mutator
                .try_set_leaf_batch(second, 3, &boundary)
                .unwrap()
                .is_none()
        );
        assert_eq!(backend.pages.lock().unwrap().len(), before);
        assert_eq!(mutator.finish(second).unwrap(), second);
        drop(mutator_workspace);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }
}

#[test]
fn deeper_noop_prefix_and_new_global_minimum_preserve_ancestor_bounds() {
    let backend = MemoryPages::default();
    let admission = Admission::new(256 << 10);
    let mut model = long_model(20);
    let original = model.clone();
    let old = build_model(&backend, &model);
    assert_eq!(old.height, 3);
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let keys = [long_key(9), long_key(10), long_key(13)];
    let noops = [
        DirectoryEdit {
            key: DirectoryKey::row("t", &keys[0]),
            value: None,
        },
        DirectoryEdit {
            key: DirectoryKey::row("t", &keys[1]),
            value: Some(value(1, 10)),
        },
        DirectoryEdit {
            key: DirectoryKey::row("t", &keys[2]),
            value: None,
        },
    ];
    let before = backend.pages.lock().unwrap().len();
    let (unchanged, consumed) = mutator.try_set_leaf_batch(old, 2, &noops).unwrap().unwrap();
    assert_eq!(consumed, 2);
    assert_eq!(
        unchanged,
        DirectoryRoot {
            generation: 2,
            ..old
        }
    );
    assert_eq!(backend.pages.lock().unwrap().len(), before);
    let keys = [long_key(0), long_key(10), long_key(11)];
    let edits = [
        DirectoryEdit {
            key: DirectoryKey::row("t", &keys[0]),
            value: Some(value(3, 0)),
        },
        DirectoryEdit {
            key: DirectoryKey::row("t", &keys[1]),
            value: None,
        },
        DirectoryEdit {
            key: DirectoryKey::row("t", &keys[2]),
            value: Some(value(3, 11)),
        },
    ];
    let (changed, consumed) = mutator
        .try_set_leaf_batch(unchanged, 3, &edits)
        .unwrap()
        .unwrap();
    assert_eq!(consumed, 3);
    assert_eq!(backend.pages.lock().unwrap().len() - before, 3);
    model.remove(&("t".into(), Some(keys[1].to_vec())));
    model.insert(("t".into(), Some(keys[0].to_vec())), value(3, 0));
    model.insert(("t".into(), Some(keys[2].to_vec())), value(3, 11));
    let changed = mutator.finish(changed).unwrap();
    assert_directory_model(&backend, admission.clone(), changed, &model);
    assert_directory_model(&backend, admission.clone(), old, &original);
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn nonroot_empty_and_growing_ancestor_separator_decline_before_any_append() {
    let backend = MemoryPages::default();
    let admission = Admission::new(256 << 10);
    let model = long_model(6);
    let old = build_model(&backend, &model);
    let keys: Vec<_> = (10..13).map(long_key).collect();
    let deletes: Vec<_> = keys
        .iter()
        .map(|key| DirectoryEdit {
            key: DirectoryKey::row("t", key),
            value: None,
        })
        .collect();
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let before = backend.pages.lock().unwrap().len();
    assert!(
        mutator
            .try_set_leaf_batch(old, 2, &deletes)
            .unwrap()
            .is_none()
    );
    assert_eq!(backend.pages.lock().unwrap().len(), before);
    assert_eq!(mutator.finish(old).unwrap(), old);
    drop(mutator_workspace);

    // Four child separators fit while the first is short. Removing that
    // child's short minimum would replace it with a 4096-byte separator and
    // overflow the parent, even though the resulting leaf itself fits.
    let short = 0u64.to_be_bytes().to_vec();
    let mut model = BTreeMap::new();
    let mut children = Vec::new();
    for id in 0..4 {
        let mut leaf = BTreeMap::new();
        let minimum = if id == 0 {
            short.clone()
        } else {
            long_key(id).to_vec()
        };
        if id == 0 {
            leaf.insert(("t".into(), Some(short.clone())), value(1, 40));
        }
        leaf.insert(
            ("t".into(), Some(long_key(id).to_vec())),
            value(1, id as u64),
        );
        children.push((minimum, build_model(&backend, &leaf)));
        model.extend(leaf);
    }
    let old = parent_root(&backend, &children);
    assert_eq!(old.height, 2);
    let original = model.clone();
    assert_directory_model(&backend, admission.clone(), old, &model);
    let long = long_key(0);
    let edits = [
        DirectoryEdit {
            key: DirectoryKey::row("t", &short),
            value: None,
        },
        DirectoryEdit {
            key: DirectoryKey::row("t", &long),
            value: Some(value(2, 50)),
        },
    ];
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let before = backend.pages.lock().unwrap().len();
    assert!(
        mutator
            .try_set_leaf_batch(old, 2, &edits)
            .unwrap()
            .is_none()
    );
    assert_eq!(backend.pages.lock().unwrap().len(), before);
    let mut fallback = old;
    for edit in &edits {
        fallback = mutator.set(fallback, 2, edit.key, edit.value).unwrap();
    }
    let fallback = mutator.finish(fallback).unwrap();
    model.remove(&("t".into(), Some(short)));
    model.insert(("t".into(), Some(long.to_vec())), value(2, 50));
    assert_directory_model(&backend, admission.clone(), fallback, &model);
    assert_directory_model(&backend, admission.clone(), old, &original);
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn root_leaf_batches_match_mixed_ordered_model_and_preserve_every_old_root() {
    let backend = MemoryPages::default();
    let admission = Admission::new(256 << 10);
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let mut root = empty_root();
    let mut model = BTreeMap::new();
    let mut snapshots = Vec::new();
    let mut random = 0x491b_ef31_853e_0871u64;
    for generation in 1..=24 {
        let mut changes = BTreeMap::new();
        while changes.len() < MAX_DIRECTORY_BATCH_EDITS {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let id = (random % 60) as u8;
            let table = if id < 20 {
                "a"
            } else if id < 40 {
                "m"
            } else {
                "t"
            };
            let key = (table.to_owned(), (!id.is_multiple_of(20)).then(|| vec![id]));
            let value = if random.is_multiple_of(4) {
                None
            } else if key.1.is_none() {
                Some(DirectoryValue::Table {
                    birth_seq: generation,
                })
            } else {
                Some(value(generation, u64::from(id)))
            };
            changes.insert(key, value);
        }
        let edits: Vec<_> = changes
            .iter()
            .map(|(key, value)| DirectoryEdit {
                key: model_key(key),
                value: *value,
            })
            .collect();
        let previous = model.clone();
        for (key, value) in &changes {
            match value {
                Some(value) => {
                    model.insert(key.clone(), *value);
                }
                None => {
                    model.remove(key);
                }
            }
        }
        let before = backend.pages.lock().unwrap().len();
        let syncs = backend.syncs.load(AtomicOrdering::Relaxed);
        let (next, consumed) = mutator
            .try_set_leaf_batch(root, generation, &edits)
            .unwrap()
            .unwrap();
        assert_eq!(consumed, edits.len());
        assert_eq!(next.generation, generation);
        assert!(next.height <= 1);
        assert_eq!(
            backend.pages.lock().unwrap().len() - before,
            usize::from(model != previous && !model.is_empty())
        );
        assert_eq!(
            backend.syncs.load(AtomicOrdering::Relaxed),
            syncs,
            "batch append cannot publish/sync by itself"
        );
        root = mutator.finish(next).unwrap();
        assert_directory_model(&backend, admission.clone(), root, &model);
        snapshots.push((root, model.clone()));
    }
    drop(mutator_workspace);
    for (root, model) in snapshots {
        assert_directory_model(&backend, admission.clone(), root, &model);
    }
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    assert!(admission.0.peak.load(AtomicOrdering::Relaxed) <= 256 << 10);
}

#[test]
fn root_leaf_noops_missing_deletes_and_empty_result_do_not_append_pages() {
    let backend = MemoryPages::default();
    let admission = Admission::new(256 << 10);
    let model = small_model();
    let root = build_model(&backend, &model);
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let before = backend.pages.lock().unwrap().len();
    let noops = [
        DirectoryEdit {
            key: DirectoryKey::row("t", b"a"),
            value: Some(value(1, 1)),
        },
        DirectoryEdit {
            key: DirectoryKey::row("t", b"missing"),
            value: None,
        },
    ];
    let (unchanged, consumed) = mutator
        .try_set_leaf_batch(root, 2, &noops)
        .unwrap()
        .unwrap();
    assert_eq!(consumed, noops.len());
    assert_eq!(
        unchanged,
        DirectoryRoot {
            generation: 2,
            ..root
        }
    );
    assert_eq!(backend.pages.lock().unwrap().len(), before);
    let deletes: Vec<_> = model
        .keys()
        .map(|key| DirectoryEdit {
            key: model_key(key),
            value: None,
        })
        .collect();
    let (empty, consumed) = mutator
        .try_set_leaf_batch(unchanged, 3, &deletes)
        .unwrap()
        .unwrap();
    assert_eq!(consumed, deletes.len());
    assert_eq!(
        empty,
        DirectoryRoot {
            generation: 3,
            ..empty_root()
        }
    );
    let (still_empty, consumed) = mutator
        .try_set_leaf_batch(
            empty,
            4,
            &[
                DirectoryEdit {
                    key: DirectoryKey::row("t", b"a"),
                    value: None,
                },
                DirectoryEdit {
                    key: DirectoryKey::row("t", b"b"),
                    value: None,
                },
            ],
        )
        .unwrap()
        .unwrap();
    assert_eq!(consumed, 2);
    assert_eq!(
        still_empty,
        DirectoryRoot {
            generation: 4,
            ..empty_root()
        }
    );
    assert_eq!(backend.pages.lock().unwrap().len(), before);
    assert_directory_model(&backend, admission.clone(), root, &model);
    assert_directory_model(&backend, admission.clone(), still_empty, &BTreeMap::new());
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn oversized_leaf_declines_before_effects_and_allows_normal_fallback() {
    let backend = MemoryPages::default();
    let admission = Admission::new(256 << 10);
    let mut model: BTreeMap<ModelKey, DirectoryValue> =
        BTreeMap::from([(("t".into(), None), DirectoryValue::Table { birth_seq: 1 })]);
    for id in 0..3 {
        model.insert(
            ("t".into(), Some(long_key(id).to_vec())),
            value(1, id as u64),
        );
    }
    let root = build_model(&backend, &model);
    assert_eq!(root.height, 1);
    let keys = [long_key(3), long_key(4)];
    let edits = [
        DirectoryEdit {
            key: DirectoryKey::row("t", &keys[0]),
            value: Some(value(2, 3)),
        },
        DirectoryEdit {
            key: DirectoryKey::row("t", &keys[1]),
            value: Some(value(2, 4)),
        },
    ];
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let before = backend.pages.lock().unwrap().len();
    let syncs = backend.syncs.load(AtomicOrdering::Relaxed);
    assert!(
        mutator
            .try_set_leaf_batch(root, 2, &edits)
            .unwrap()
            .is_none()
    );
    assert_eq!(backend.pages.lock().unwrap().len(), before);
    assert_eq!(backend.syncs.load(AtomicOrdering::Relaxed), syncs);
    let mut fallback = root;
    for edit in &edits {
        fallback = mutator.set(fallback, 2, edit.key, edit.value).unwrap();
        model.insert(
            (edit.key.table.into(), edit.key.row.map(<[u8]>::to_vec)),
            edit.value.unwrap(),
        );
    }
    let fallback = mutator.finish(fallback).unwrap();
    assert!(fallback.height > 1);
    assert_directory_model(&backend, admission.clone(), fallback, &model);
    // A declined fast path never poisons the same mutator.
    assert!(
        mutator
            .try_set_leaf_batch(empty_root(), 3, &pair())
            .unwrap()
            .is_some()
    );
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn invalid_batch_inputs_reject_without_reads_or_appends_and_do_not_poison() {
    let backend = MemoryPages::default();
    let admission = Admission::new(256 << 10);
    let root = build_model(&backend, &small_model());
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let keys: Vec<_> = (0..=MAX_DIRECTORY_BATCH_EDITS)
        .map(|id| vec![id as u8])
        .collect();
    let too_many: Vec<_> = keys
        .iter()
        .map(|key| DirectoryEdit {
            key: DirectoryKey::row("t", key),
            value: Some(value(2, 1)),
        })
        .collect();
    let oversized_key = vec![0; MAX_KEY_BYTES + 1];
    let cases = vec![
        vec![],
        vec![pair()[0]],
        too_many,
        vec![pair()[1], pair()[0]],
        vec![pair()[0], pair()[0]],
        vec![
            DirectoryEdit {
                key: DirectoryKey::row("", b"a"),
                value: None,
            },
            pair()[1],
        ],
        vec![
            DirectoryEdit {
                key: DirectoryKey::row("t", &oversized_key),
                value: None,
            },
            pair()[1],
        ],
        vec![
            DirectoryEdit {
                key: DirectoryKey::table("t"),
                value: Some(value(2, 1)),
            },
            pair()[1],
        ],
        vec![
            DirectoryEdit {
                key: DirectoryKey::table("t"),
                value: Some(DirectoryValue::Table { birth_seq: 0 }),
            },
            pair()[1],
        ],
        vec![
            DirectoryEdit {
                key: DirectoryKey::row("t", b"a"),
                value: Some(value(3, 1)),
            },
            pair()[1],
        ],
    ];
    let pages = backend.pages.lock().unwrap().len();
    let reads = backend.reads.load(AtomicOrdering::Relaxed);
    for edits in cases {
        assert!(matches!(
            mutator.try_set_leaf_batch(root, 2, &edits),
            Err(CoreError::InvalidInput(_))
        ));
    }
    for generation in [0, 2] {
        assert!(matches!(
            mutator.try_set_leaf_batch(
                DirectoryRoot {
                    generation: 3,
                    ..root
                },
                generation,
                &pair()
            ),
            Err(CoreError::InvalidInput(_))
        ));
    }
    assert_eq!(backend.pages.lock().unwrap().len(), pages);
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), reads);
    assert!(
        mutator
            .try_set_leaf_batch(root, 2, &pair())
            .unwrap()
            .is_some()
    );
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn batch_workspace_denial_and_expired_owner_do_not_start_page_effects() {
    let backend = MemoryPages::default();
    let root = build_model(&backend, &small_model());
    let pages = backend.pages.lock().unwrap().len();
    let reads = backend.reads.load(AtomicOrdering::Relaxed);
    let denied = Admission::new(16 << 10);
    assert!(matches!(
        DirectoryWriteWorkspace::for_edits(denied.clone()),
        Err(CoreError::CapacityDenied)
    ));
    assert_eq!(denied.0.used.load(AtomicOrdering::Relaxed), 0);
    denied.check_owner().unwrap();
    assert_eq!(backend.pages.lock().unwrap().len(), pages);
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), reads);

    let admission = Admission::new(256 << 10);
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    admission.0.failed.store(true, AtomicOrdering::Relaxed);
    assert!(matches!(
        mutator.try_set_leaf_batch(root, 2, &pair()),
        Err(CoreError::OwnerFailed)
    ));
    admission.0.failed.store(false, AtomicOrdering::Relaxed);
    assert!(matches!(
        mutator.try_set_leaf_batch(root, 2, &pair()),
        Err(CoreError::OwnerFailed)
    ));
    assert_eq!(backend.pages.lock().unwrap().len(), pages);
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), reads);
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn corrupted_root_leaf_is_an_error_not_a_declined_fast_path() {
    for canonical_digest in [false, true] {
        let backend = MemoryPages::default();
        let admission = Admission::new(256 << 10);
        let mut root = build_model(&backend, &small_model());
        let mut pages = backend.pages.lock().unwrap();
        let page = &mut pages[root.page.unwrap().page_index as usize];
        let original = page.clone();
        page[45] = 1; // Reserved canonical header byte.
        if canonical_digest {
            root.page.as_mut().unwrap().sha256 = page_digest(page);
        }
        let count = pages.len();
        drop(pages);
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        assert!(matches!(
            mutator.try_set_leaf_batch(root, 2, &pair()),
            Err(CoreError::Corrupt(_))
        ));
        assert_eq!(backend.pages.lock().unwrap().len(), count);
        backend.pages.lock().unwrap()[root.page.unwrap().page_index as usize] = original;
        assert!(matches!(mutator.finish(root), Err(CoreError::OwnerFailed)));
        drop(mutator_workspace);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }
}

#[test]
fn corrupted_deeper_root_or_selected_leaf_is_not_a_declined_fast_path() {
    for corrupt_leaf in [false, true] {
        let backend = MemoryPages::default();
        let admission = Admission::new(256 << 10);
        let root = build_model(&backend, &long_model(20));
        assert_eq!(root.height, 3);
        let page_index = if corrupt_leaf {
            0
        } else {
            root.page.unwrap().page_index as usize
        };
        let mut pages = backend.pages.lock().unwrap();
        let original = pages[page_index].clone();
        pages[page_index][45] = 1;
        let before = pages.len();
        drop(pages);
        let keys = [long_key(10), long_key(11)];
        let edits = [
            DirectoryEdit {
                key: DirectoryKey::row("t", &keys[0]),
                value: Some(value(2, 20)),
            },
            DirectoryEdit {
                key: DirectoryKey::row("t", &keys[1]),
                value: Some(value(2, 21)),
            },
        ];
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        assert!(matches!(
            mutator.try_set_leaf_batch(root, 2, &edits),
            Err(CoreError::Corrupt(_))
        ));
        assert_eq!(backend.pages.lock().unwrap().len(), before);
        backend.pages.lock().unwrap()[page_index] = original;
        assert!(matches!(mutator.finish(root), Err(CoreError::OwnerFailed)));
        drop(mutator_workspace);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }
}

#[derive(Default)]
struct FaultPages {
    inner: MemoryPages,
    append: AtomicUsize,
    sync: AtomicBool,
}
impl DirectoryBackend for FaultPages {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
        self.inner.read_page(reference, out)
    }
    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        if self.append.load(AtomicOrdering::Relaxed) == 1 {
            return Err(CoreError::Io(std::io::Error::other(
                "batch append before effect",
            )));
        }
        let reference = self.inner.append_page(bytes)?;
        if self.append.load(AtomicOrdering::Relaxed) == 2 {
            return Err(CoreError::Io(std::io::Error::other(
                "batch append after effect",
            )));
        }
        Ok(reference)
    }
    fn sync_pages(&self) -> Result<(), CoreError> {
        self.inner.sync_pages()?;
        if self.sync.load(AtomicOrdering::Relaxed) {
            return Err(CoreError::Io(std::io::Error::other(
                "batch sync after effect",
            )));
        }
        Ok(())
    }
}

#[test]
fn append_and_sync_failures_poison_only_the_private_batch_and_preserve_old_root() {
    for model in [small_model(), long_model(6), long_model(20)] {
        for failure in 1..=3 {
            let backend = FaultPages::default();
            let admission = Admission::new(256 << 10);
            let root = build_model(&backend, &model);
            let before = backend.inner.pages.lock().unwrap().len();
            let mut mutator_workspace =
                DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
            let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
            if failure < 3 {
                backend.append.store(failure, AtomicOrdering::Relaxed);
            }
            let result = mutator.try_set_leaf_batch(root, 2, &pair());
            if failure < 3 {
                assert!(matches!(result, Err(CoreError::Io(_))));
            } else {
                let (private, consumed) = result.unwrap().unwrap();
                assert_eq!(consumed, 2);
                backend.sync.store(true, AtomicOrdering::Relaxed);
                assert!(matches!(mutator.finish(private), Err(CoreError::Io(_))));
            }
            assert_eq!(
                backend.inner.pages.lock().unwrap().len() - before,
                match failure {
                    1 => 0,
                    2 => 1,
                    _ => root.height as usize,
                }
            );
            backend.append.store(0, AtomicOrdering::Relaxed);
            backend.sync.store(false, AtomicOrdering::Relaxed);
            assert!(matches!(
                mutator.try_set_leaf_batch(root, 2, &pair()),
                Err(CoreError::OwnerFailed)
            ));
            assert!(matches!(mutator.finish(root), Err(CoreError::OwnerFailed)));
            drop(mutator_workspace);
            assert_directory_model(&backend, admission.clone(), root, &model);
            assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
        }
    }
}
