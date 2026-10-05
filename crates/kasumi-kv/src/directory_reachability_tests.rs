use super::*;

fn reachability_tree(
    backend: &MemoryPages,
    admission: Arc<dyn StorageAdmission>,
    rows: usize,
) -> DirectoryRoot {
    let mut builder = DirectoryBuilder::new(backend, admission, GROUP, 7).unwrap();
    builder
        .push(
            DirectoryKey::table("t"),
            DirectoryValue::Table { birth_seq: 2 },
        )
        .unwrap();
    for id in 0..rows {
        builder
            .push(DirectoryKey::row("t", &long_key(id)), value(3, id as u64))
            .unwrap();
    }
    builder.finish().unwrap()
}

fn candidate_bytes(backend: &MemoryPages, reference: DirectoryPageRef) -> Vec<u8> {
    backend.pages.lock().unwrap()[reference.page_index as usize].clone()
}

#[test]
fn exact_membership_covers_leaf_internal_and_root_pages_with_one_path() {
    let backend = MemoryPages::default();
    let build_admission = Admission::new(1 << 20);
    let root = reachability_tree(&backend, build_admission.clone(), 80);
    assert!(root.height >= 3);
    assert_eq!(build_admission.0.used.load(AtomicOrdering::Relaxed), 0);
    let references: Vec<_> = backend
        .pages
        .lock()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, bytes)| DirectoryPageRef {
            arena_id: 1,
            page_index: index as u64,
            sha256: page_digest(bytes),
        })
        .collect();
    assert!(references.len() > 4 * usize::from(root.height));
    let admission = Admission::new(64 << 10);
    let reader = DirectoryReader::new(&backend, admission.clone());
    for reference in references {
        let bytes = candidate_bytes(&backend, reference);
        let before = backend.reads.load(AtomicOrdering::Relaxed);
        assert!(reader.contains_page(root, reference, &bytes).unwrap());
        let reads = backend.reads.load(AtomicOrdering::Relaxed) - before;
        assert_eq!(reads, usize::from(root.height - 1 - bytes[44]));
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }
    assert!(admission.0.peak.load(AtomicOrdering::Relaxed) <= 64 << 10);
}

#[test]
fn cow_roots_distinguish_obsolete_shared_and_newer_candidates() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let old = reachability_tree(&backend, admission.clone(), 12);
    let reader = DirectoryReader::new(&backend, admission.clone());
    let old_leaf = reader
        .leaf_after(old, DirectoryKey::row("t", &long_key(0)), false)
        .unwrap()
        .unwrap();
    let shared_leaf = reader
        .leaf_after(old, DirectoryKey::row("t", &long_key(11)), false)
        .unwrap()
        .unwrap();
    let old_reference = old_leaf.reference();
    let shared_reference = shared_leaf.reference();
    drop((old_leaf, shared_leaf));
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let current = mutator
        .set(
            old,
            8,
            DirectoryKey::row("t", &long_key(0)),
            Some(value(8, 900)),
        )
        .unwrap();
    mutator.finish(current).unwrap();
    for reference in [old.page.unwrap(), old_reference] {
        let bytes = candidate_bytes(&backend, reference);
        assert!(reader.contains_page(old, reference, &bytes).unwrap());
        assert!(!reader.contains_page(current, reference, &bytes).unwrap());
    }
    let shared = candidate_bytes(&backend, shared_reference);
    for root in [old, current] {
        assert!(
            reader
                .contains_page(root, shared_reference, &shared)
                .unwrap()
        );
    }
    let new_reference = current.page.unwrap();
    let new_bytes = candidate_bytes(&backend, new_reference);
    let before = backend.reads.load(AtomicOrdering::Relaxed);
    assert!(
        !reader
            .contains_page(old, new_reference, &new_bytes)
            .unwrap()
    );
    assert!(backend.reads.load(AtomicOrdering::Relaxed) - before <= usize::from(old.height));
    let before = backend.reads.load(AtomicOrdering::Relaxed);
    assert!(
        reader
            .contains_page(current, new_reference, &new_bytes)
            .unwrap()
    );
    assert!(
        !reader
            .contains_page(empty_root(), new_reference, &new_bytes)
            .unwrap()
    );
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), before);
    let newer_leaf = reader
        .leaf_after(current, DirectoryKey::row("t", &long_key(0)), false)
        .unwrap()
        .unwrap();
    let newer_reference = newer_leaf.reference();
    let newer_bytes = candidate_bytes(&backend, newer_reference);
    assert!(
        !reader
            .contains_page(old, newer_reference, &newer_bytes)
            .unwrap()
    );
    assert!(
        reader
            .contains_page(current, newer_reference, &newer_bytes)
            .unwrap()
    );
    drop(newer_leaf);
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn membership_requires_the_complete_reference_and_matching_group() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let root = reachability_tree(&backend, admission.clone(), 12);
    let reader = DirectoryReader::new(&backend, admission.clone());
    let leaf = reader
        .leaf_after(root, DirectoryKey::row("t", &long_key(5)), false)
        .unwrap()
        .unwrap();
    let reference = leaf.reference();
    let bytes = candidate_bytes(&backend, reference);
    drop(leaf);
    for candidate in [
        DirectoryPageRef {
            arena_id: 2,
            ..reference
        },
        DirectoryPageRef {
            page_index: reference.page_index + 10_000,
            ..reference
        },
    ] {
        assert!(!reader.contains_page(root, candidate, &bytes).unwrap());
    }
    // A distinct, canonical digest at the same address is not an exact hit.
    let mut different = bytes.clone();
    different[36..44].copy_from_slice(&6u64.to_le_bytes());
    let other_digest = DirectoryPageRef {
        sha256: page_digest(&different),
        ..reference
    };
    assert!(
        !reader
            .contains_page(root, other_digest, &different)
            .unwrap()
    );
    let foreign = DirectoryRoot {
        group_id: [99; 16],
        ..root
    };
    assert!(
        matches!(&(reader.contains_page(foreign, reference, &bytes)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
    );
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn malformed_candidates_fail_even_for_empty_or_older_roots_before_io() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let root = reachability_tree(&backend, admission.clone(), 12);
    let reference = root.page.unwrap();
    let original = candidate_bytes(&backend, reference);
    let reader = DirectoryReader::new(&backend, admission.clone());
    for damage in 0..7 {
        let mut bytes = original.clone();
        match damage {
            0 => bytes[45] = 1,
            1 => bytes[20] ^= 1,
            2 => bytes[36..44].fill(0),
            3 => bytes[52..60].fill(0),
            4 => bytes[DIRECTORY_PAGE_BYTES - 1] = 1,
            5 => bytes.truncate(DIRECTORY_PAGE_BYTES - 1),
            6 => {
                let info = validate_page(&bytes, root, reference).unwrap();
                let first = nth_entry(&bytes, info, 0).unwrap();
                let value_at = HEADER_BYTES + first.key_bytes.len();
                bytes[value_at..value_at + 8].fill(0);
            }
            _ => unreachable!(),
        }
        let candidate = DirectoryPageRef {
            sha256: page_digest(&bytes),
            ..reference
        };
        let before = backend.reads.load(AtomicOrdering::Relaxed);
        for target in [
            empty_root(),
            DirectoryRoot {
                generation: 1,
                ..root
            },
        ] {
            assert!(
                matches!(&(reader.contains_page(target, candidate, &bytes)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_)))),
                "damage {damage}"
            );
        }
        assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), before);
    }
    let mut bad_digest = reference;
    bad_digest.sha256[0] ^= 1;
    assert!(
        matches!(&(reader.contains_page(empty_root(), bad_digest, &original)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
    );
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn malformed_roots_and_ancestor_bounds_never_prove_absence() {
    for damage in 0..6 {
        let backend = MemoryPages::default();
        let admission = Admission::new(1 << 20);
        let mut root = reachability_tree(&backend, admission.clone(), 8);
        assert_eq!(root.height, 2);
        let reader = DirectoryReader::new(&backend, admission.clone());
        let leaf = reader
            .leaf_after(root, DirectoryKey::table("t"), false)
            .unwrap()
            .unwrap();
        let candidate = leaf.reference();
        let candidate_bytes = candidate_bytes(&backend, candidate);
        drop(leaf);
        let mut pages = backend.pages.lock().unwrap();
        let bytes = &mut pages[root.page.unwrap().page_index as usize];
        let info = validate_page(bytes, root, root.page.unwrap()).unwrap();
        let first = nth_entry(bytes, info, 0).unwrap();
        let value_at = HEADER_BYTES + first.key_bytes.len();
        match damage {
            0 => root.height = 0,
            1 => {
                let count =
                    le_u64(&bytes[value_at + PAGE_REF_BYTES..value_at + BRANCH_VALUE_BYTES]) + 1;
                bytes[value_at + PAGE_REF_BYTES..value_at + BRANCH_VALUE_BYTES]
                    .copy_from_slice(&count.to_le_bytes());
                root.entries += 1;
                bytes[52..60].copy_from_slice(&root.entries.to_le_bytes());
            }
            2 => bytes[36..44].copy_from_slice(&6u64.to_le_bytes()),
            3 => {
                // Preserve canonical ordering but put the first separator
                // below its actual child's minimum. Bounds must reject it.
                bytes[HEADER_BYTES + KEY_HEADER_BYTES] = b's';
            }
            4 => bytes[44] = 2,
            5 => root.generation = 6,
            _ => unreachable!(),
        }
        root.page.as_mut().unwrap().sha256 = page_digest(bytes);
        drop(pages);
        assert!(
            matches!(&(reader.contains_page(root, candidate, &candidate_bytes)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_)))),
            "damage {damage}"
        );
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }
}

#[test]
fn a_probe_below_the_first_separator_still_checks_the_child_minimum() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let leaf = reachability_tree(&backend, admission.clone(), 1);
    assert_eq!(leaf.height, 1);
    let candidate = leaf.page.unwrap();
    let bytes = candidate_bytes(&backend, candidate);
    let owner: Arc<dyn StorageAdmission> = admission.clone();
    let mut page = PendingPage::new(&owner).unwrap();
    let mut value = [0; BRANCH_VALUE_BYTES];
    candidate.encode(&mut value[..PAGE_REF_BYTES]);
    value[PAGE_REF_BYTES..].copy_from_slice(&leaf.entries.to_le_bytes());
    page.append(DirectoryKey::table("u"), &value, leaf.entries)
        .unwrap();
    let parent = &mut page.buffer.bytes;
    parent[..16].copy_from_slice(&MAGIC);
    parent[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    parent[20..36].copy_from_slice(&GROUP);
    parent[36..44].copy_from_slice(&7u64.to_le_bytes());
    parent[44] = 1;
    parent[46..48].copy_from_slice(&1u16.to_le_bytes());
    parent[48..52].copy_from_slice(&(page.used as u32).to_le_bytes());
    parent[52..60].copy_from_slice(&leaf.entries.to_le_bytes());
    let root = DirectoryRoot {
        page: Some(backend.append_page(parent).unwrap()),
        height: 2,
        ..leaf
    };
    drop(page);
    assert!(
        matches!(&(DirectoryReader::new(&backend, admission.clone()).contains_page(root, candidate, &bytes)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
    );
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn proof_denial_and_owner_expiry_precede_or_fence_reads() {
    struct ExpiringReads<'a> {
        pages: &'a MemoryPages,
        admission: Arc<Admission>,
    }
    impl DirectoryBackend for ExpiringReads<'_> {
        fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
            self.pages.read_page(reference, out)?;
            self.admission.0.failed.store(true, AtomicOrdering::Release);
            Ok(())
        }
        fn append_page(&self, _: &[u8]) -> Result<DirectoryPageRef, CoreError> {
            unreachable!()
        }
        fn sync_pages(&self) -> Result<(), CoreError> {
            unreachable!()
        }
    }
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let root = reachability_tree(&backend, admission.clone(), 8);
    let leaf = DirectoryReader::new(&backend, admission.clone())
        .leaf_after(root, DirectoryKey::table("t"), false)
        .unwrap()
        .unwrap();
    let reference = leaf.reference();
    let bytes = candidate_bytes(&backend, reference);
    drop(leaf);
    let before = backend.reads.load(AtomicOrdering::Relaxed);
    let denied = Admission::new(1);
    assert!(
        matches!(&(DirectoryReader::new(&backend, denied.clone()).contains_page(root, reference, &bytes)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), before);
    assert_eq!(denied.0.used.load(AtomicOrdering::Relaxed), 0);
    let expiring = ExpiringReads {
        pages: &backend,
        admission: admission.clone(),
    };
    assert!(
        matches!(&(DirectoryReader::new(&expiring, admission.clone()).contains_page(root, reference, &bytes)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), before + 1);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    let root_bytes = candidate_bytes(&backend, root.page.unwrap());
    assert!(
        matches!(&(DirectoryReader::new(&backend, admission).contains_page(
            root,
            root.page.unwrap(),
            &root_bytes
        )), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), before + 1);
}

#[test]
fn a_failed_path_read_is_not_a_proof_of_absence() {
    struct FailedReads;
    impl DirectoryBackend for FailedReads {
        fn read_page(&self, _: DirectoryPageRef, _: &mut [u8]) -> Result<(), CoreError> {
            Err(CoreError::new(crate::CoreErrorCause::Io(
                std::io::Error::other("membership read failure"),
            )))
        }
        fn append_page(&self, _: &[u8]) -> Result<DirectoryPageRef, CoreError> {
            unreachable!()
        }
        fn sync_pages(&self) -> Result<(), CoreError> {
            unreachable!()
        }
    }
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let root = reachability_tree(&backend, admission.clone(), 8);
    let leaf = DirectoryReader::new(&backend, admission.clone())
        .leaf_after(root, DirectoryKey::table("t"), false)
        .unwrap()
        .unwrap();
    let reference = leaf.reference();
    let bytes = candidate_bytes(&backend, reference);
    drop(leaf);
    assert!(
        matches!(&(DirectoryReader::new(&FailedReads, admission.clone())
            .contains_page(root, reference, &bytes)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Io(_))))
    );
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}
