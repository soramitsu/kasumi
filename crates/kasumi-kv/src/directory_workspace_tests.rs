use super::*;

struct WorkspaceAdmission {
    inner: Arc<Admission>,
    calls: AtomicUsize,
    deny_at: AtomicUsize,
    deny_all: AtomicBool,
}

impl WorkspaceAdmission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Admission::new(1 << 20),
            calls: AtomicUsize::new(0),
            deny_at: AtomicUsize::new(usize::MAX),
            deny_all: AtomicBool::new(false),
        })
    }
}

impl StorageAdmission for WorkspaceAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.inner.check_owner()
    }

    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        let call = self.calls.fetch_add(1, AtomicOrdering::Relaxed) + 1;
        if self.deny_all.load(AtomicOrdering::Relaxed)
            || call == self.deny_at.load(AtomicOrdering::Relaxed)
        {
            return Err(AdmissionError::CapacityDenied);
        }
        self.inner.reserve_workspace(bytes)
    }

    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(current, requested)
    }

    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(actual)
    }

    fn owner_failed(&self) {
        self.inner.owner_failed();
    }

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<crate::CacheMemoryQuote, crate::AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, crate::AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
}
impl crate::cache_test::Provider for WorkspaceAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
        let _ = first;
        let call = self.calls.fetch_add(1, AtomicOrdering::Relaxed) + 1;
        if self.deny_all.load(AtomicOrdering::Relaxed)
            || call == self.deny_at.load(AtomicOrdering::Relaxed)
        {
            return Err(AdmissionError::CapacityDenied);
        }
        crate::cache_test::Provider::acquire_cache(self.inner.as_ref(), bytes, first)
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
        crate::cache_test::Provider::release_cache(self.inner.as_ref(), bytes, last);
    }
}

fn tree(backend: &MemoryPages) -> DirectoryRoot {
    let mut builder = DirectoryBuilder::new(backend, Admission::new(1 << 20), GROUP, 7).unwrap();
    builder
        .push(
            DirectoryKey::table("t"),
            DirectoryValue::Table { birth_seq: 2 },
        )
        .unwrap();
    for id in 0..24 {
        builder
            .push(DirectoryKey::row("t", &long_key(id)), value(3, id as u64))
            .unwrap();
    }
    builder.finish().unwrap()
}

fn leaf(backend: &MemoryPages, root: DirectoryRoot) -> (DirectoryPageRef, Vec<u8>) {
    let selected = DirectoryReader::new(backend, Admission::new(1 << 20))
        .leaf_after(root, DirectoryKey::row("t", &long_key(0)), false)
        .unwrap()
        .unwrap();
    let reference = selected.reference();
    let bytes = backend.pages.lock().unwrap()[reference.page_index as usize].clone();
    (reference, bytes)
}

#[test]
fn point_membership_and_warming_reuse_one_buffer_without_new_admission() {
    let backend = MemoryPages::default();
    let old = tree(&backend);
    assert!(old.height >= 3);
    let (old_leaf, old_bytes) = leaf(&backend, old);
    let mut mutator_workspace =
        DirectoryWriteWorkspace::for_edits(Admission::new(1 << 20)).unwrap();
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

    let admission = WorkspaceAdmission::new();
    let owner: Arc<dyn StorageAdmission> = admission.clone();
    let mut workspace = DirectoryReadWorkspace::new(&owner).unwrap();
    let reader = DirectoryReader::new(&backend, owner);
    let pointer = workspace.buffer.as_ptr();
    let capacity = workspace.buffer.capacity();
    let charged = admission.inner.0.used.load(AtomicOrdering::Relaxed);
    let calls = admission.calls.load(AtomicOrdering::Relaxed);
    assert_eq!(calls, 1, "page and traversal share one actual grant");
    assert_eq!(charged, DirectoryReadWorkspace::request_bytes());
    assert!(charged <= 64 << 10);
    admission.deny_all.store(true, AtomicOrdering::Relaxed);
    for _ in 0..3 {
        for (root, first) in [(old, value(3, 0)), (current, value(8, 900))] {
            for id in [0, 1, 12, 23] {
                let expected = if id == 0 { first } else { value(3, id as u64) };
                assert_eq!(
                    reader
                        .get_with_workspace(
                            root,
                            DirectoryKey::row("t", &long_key(id)),
                            &mut workspace
                        )
                        .unwrap(),
                    Some(expected)
                );
            }
            assert_eq!(
                reader
                    .get_with_workspace(
                        root,
                        DirectoryKey::row("t", &long_key(100)),
                        &mut workspace
                    )
                    .unwrap(),
                None
            );
            assert_eq!(
                reader
                    .contains_page_with_workspace(root, old_leaf, &old_bytes, &mut workspace)
                    .unwrap(),
                root == old
            );
            reader
                .warm_generation_with_workspace(root, root.generation, &mut workspace)
                .unwrap();
            reader
                .warm_generation_with_workspace(root, 0, &mut workspace)
                .unwrap();
        }
        assert_eq!(workspace.buffer.as_ptr(), pointer);
        assert_eq!(workspace.buffer.capacity(), capacity);
        assert_eq!(
            admission.inner.0.used.load(AtomicOrdering::Relaxed),
            charged
        );
        assert_eq!(admission.calls.load(AtomicOrdering::Relaxed), calls);
    }
    drop(workspace);
    assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn read_workspace_constructor_refusal_has_no_effect_and_same_owner_retries() {
    let admission = WorkspaceAdmission::new();
    let owner: Arc<dyn StorageAdmission> = admission.clone();
    admission.deny_at.store(1, AtomicOrdering::Relaxed);
    assert!(
        matches!(&(DirectoryReadWorkspace::new(&owner)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(admission.calls.load(AtomicOrdering::Relaxed), 1);
    assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), 0);
    admission.check_owner().unwrap();
    admission.deny_at.store(usize::MAX, AtomicOrdering::Relaxed);
    let workspace = DirectoryReadWorkspace::new(&owner).unwrap();
    assert_eq!(admission.calls.load(AtomicOrdering::Relaxed), 2);
    assert_eq!(workspace.buffer.len(), DIRECTORY_PAGE_BYTES);
    assert_eq!(workspace.buffer.capacity(), DIRECTORY_PAGE_BYTES);
    assert_eq!(
        admission.inner.0.used.load(AtomicOrdering::Relaxed),
        DirectoryReadWorkspace::request_bytes()
    );
    drop(workspace);
    assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn read_workspace_admits_its_entire_buffer_and_traversal_before_allocation() {
    let request = DirectoryReadWorkspace::request_bytes();
    let denied = Admission::new(request - 1);
    let owner: Arc<dyn StorageAdmission> = denied.clone();
    assert!(
        matches!(&(DirectoryReadWorkspace::new(&owner)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(denied.0.used.load(AtomicOrdering::Relaxed), 0);
    denied.check_owner().unwrap();
    let exact = Admission::new(request);
    let owner: Arc<dyn StorageAdmission> = exact.clone();
    let workspace = DirectoryReadWorkspace::new(&owner).unwrap();
    assert_eq!(workspace.buffer.capacity(), DIRECTORY_PAGE_BYTES);
    assert_eq!(exact.0.used.load(AtomicOrdering::Relaxed), request);
    assert_eq!(exact.0.peak.load(AtomicOrdering::Relaxed), request);
    drop(workspace);
    assert_eq!(exact.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn workspace_rejects_foreign_admission_and_failed_owner_before_io() {
    let backend = MemoryPages::default();
    let root = tree(&backend);
    let (reference, bytes) = leaf(&backend, root);
    let admission = WorkspaceAdmission::new();
    let owner: Arc<dyn StorageAdmission> = admission.clone();
    let mut workspace = DirectoryReadWorkspace::new(&owner).unwrap();
    let foreign = WorkspaceAdmission::new();
    let reader = DirectoryReader::new(&backend, foreign.clone());
    let before = backend.reads.load(AtomicOrdering::Relaxed);
    assert!(
        matches!(&(reader.get_with_workspace(root, DirectoryKey::table("t"), &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    assert!(
        matches!(&(reader.contains_page_with_workspace(root, reference, &bytes, &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    assert!(
        matches!(&(reader.warm_generation_with_workspace(root, 0, &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    assert_eq!(foreign.calls.load(AtomicOrdering::Relaxed), 0);
    admission.owner_failed();
    let reader = DirectoryReader::new(&backend, owner);
    assert!(
        matches!(&(reader.get_with_workspace(root, DirectoryKey::table("t"), &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert!(
        matches!(&(reader.contains_page_with_workspace(root, reference, &bytes, &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert!(
        matches!(&(reader.warm_generation_with_workspace(root, 0, &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), before);
    drop(workspace);
    assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn reused_workspace_preserves_candidate_validation_and_parent_bounds() {
    let backend = MemoryPages::default();
    let root = tree(&backend);
    let (reference, bytes) = leaf(&backend, root);
    let admission = WorkspaceAdmission::new();
    let owner: Arc<dyn StorageAdmission> = admission.clone();
    let mut workspace = DirectoryReadWorkspace::new(&owner).unwrap();
    let reader = DirectoryReader::new(&backend, owner);
    let calls = admission.calls.load(AtomicOrdering::Relaxed);
    admission.deny_all.store(true, AtomicOrdering::Relaxed);
    let mut bad = bytes.clone();
    bad[45] = 1;
    let bad_reference = DirectoryPageRef {
        sha256: page_digest(&bad),
        ..reference
    };
    let before = backend.reads.load(AtomicOrdering::Relaxed);
    assert!(
        matches!(&(reader.contains_page_with_workspace(empty_root(), bad_reference, &bad, &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
    );
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), before);

    // Keep every page canonical while declaring the wrong subtree total in
    // the selected root. All algorithms must reject the same parent bound.
    let invalid = DirectoryRoot {
        entries: root.entries + 1,
        ..root
    };
    assert!(
        matches!(&(reader.get_with_workspace(invalid, DirectoryKey::table("t"), &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
    );
    assert!(
        matches!(&(reader.contains_page_with_workspace(invalid, reference, &bytes, &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
    );
    assert!(
        matches!(&(reader.warm_generation_with_workspace(invalid, 0, &mut workspace)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
    );
    assert_eq!(
        reader
            .get_with_workspace(root, DirectoryKey::table("t"), &mut workspace)
            .unwrap(),
        Some(DirectoryValue::Table { birth_seq: 2 })
    );
    assert_eq!(admission.calls.load(AtomicOrdering::Relaxed), calls);
}

#[test]
fn reused_workspace_preserves_read_failures_and_post_io_owner_checks() {
    struct ControlledReads<'a> {
        backend: &'a MemoryPages,
        admission: Arc<WorkspaceAdmission>,
        fail: AtomicBool,
        expire: AtomicBool,
    }
    impl DirectoryBackend for ControlledReads<'_> {
        fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
            self.backend.read_page(reference, out)?;
            if self.expire.load(AtomicOrdering::Relaxed) {
                self.admission.owner_failed();
            }
            if self.fail.load(AtomicOrdering::Relaxed) {
                return Err(CoreError::new(crate::CoreErrorCause::Io(
                    std::io::ErrorKind::Other.into(),
                )));
            }
            Ok(())
        }
        fn append_page(&self, _: &[u8]) -> Result<DirectoryPageRef, CoreError> {
            unreachable!()
        }
        fn sync_pages(&self) -> Result<(), CoreError> {
            unreachable!()
        }
    }
    for operation in 0..3 {
        let backend = MemoryPages::default();
        let root = tree(&backend);
        let (reference, bytes) = leaf(&backend, root);
        let admission = WorkspaceAdmission::new();
        let owner: Arc<dyn StorageAdmission> = admission.clone();
        let mut workspace = DirectoryReadWorkspace::new(&owner).unwrap();
        let controlled = ControlledReads {
            backend: &backend,
            admission: admission.clone(),
            fail: AtomicBool::new(true),
            expire: AtomicBool::new(false),
        };
        let reader = DirectoryReader::new(&controlled, owner);
        let mut read = || match operation {
            0 => reader
                .get_with_workspace(root, DirectoryKey::table("t"), &mut workspace)
                .map(|_| ()),
            1 => reader
                .contains_page_with_workspace(root, reference, &bytes, &mut workspace)
                .map(|_| ()),
            _ => reader.warm_generation_with_workspace(root, 0, &mut workspace),
        };
        let calls = admission.calls.load(AtomicOrdering::Relaxed);
        admission.deny_all.store(true, AtomicOrdering::Relaxed);
        assert!(
            matches!(&(read()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Io(_))))
        );
        controlled.fail.store(false, AtomicOrdering::Relaxed);
        read().unwrap();
        controlled.expire.store(true, AtomicOrdering::Relaxed);
        assert!(
            matches!(&(read()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        let before = backend.reads.load(AtomicOrdering::Relaxed);
        assert!(
            matches!(&(read()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), before);
        assert_eq!(admission.calls.load(AtomicOrdering::Relaxed), calls);
        drop(workspace);
        assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), 0);
    }
}

#[test]
fn write_workspace_is_one_grant_and_reuses_actual_pages_for_checks_and_edits() {
    let backend = MemoryPages::default();
    let old = tree(&backend);
    let old_pages = backend.pages.lock().unwrap().clone();
    let admission = WorkspaceAdmission::new();
    admission.deny_all.store(true, AtomicOrdering::Relaxed);
    let reads = backend.reads.load(AtomicOrdering::Relaxed);
    assert!(
        matches!(&(DirectoryWriteWorkspace::for_edits(admission.clone())), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), 0);
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), reads);
    assert_eq!(*backend.pages.lock().unwrap(), old_pages);
    admission.check_owner().unwrap();
    admission.deny_all.store(false, AtomicOrdering::Relaxed);
    admission.calls.store(0, AtomicOrdering::Relaxed);
    let mut workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    assert_eq!(admission.calls.load(AtomicOrdering::Relaxed), 1);
    let held = admission.inner.0.used.load(AtomicOrdering::Relaxed);
    assert!(held > (2 * DIRECTORY_PAGE_BYTES) as u64);
    admission.deny_all.store(true, AtomicOrdering::Relaxed);
    assert_eq!(
        workspace
            .get(&backend, old, DirectoryKey::table("t"))
            .unwrap(),
        Some(DirectoryValue::Table { birth_seq: 2 })
    );
    let mut mutator = DirectoryMutator::new(&backend, &mut workspace).unwrap();
    assert!(
        mutator
            .get(old, DirectoryKey::table("missing"))
            .unwrap()
            .is_none()
    );
    let first = long_key(1);
    let second = long_key(2);
    let edits = [
        DirectoryEdit {
            key: DirectoryKey::row("t", &first),
            value: Some(value(8, 91)),
        },
        DirectoryEdit {
            key: DirectoryKey::row("t", &second),
            value: Some(value(8, 92)),
        },
    ];
    let mut next = old;
    let mut applied = 0;
    while applied < edits.len() {
        let rest = &edits[applied..];
        if rest.len() > 1
            && let Some((root, count)) = mutator.try_set_leaf_batch(next, 8, rest).unwrap()
        {
            next = root;
            applied += count;
        } else {
            next = mutator.set(next, 8, rest[0].key, rest[0].value).unwrap();
            applied += 1;
        }
    }
    next = mutator
        .rewrite(next, 8, edits[0].key, edits[0].value.unwrap())
        .unwrap();
    assert_eq!(mutator.get(next, edits[1].key).unwrap(), edits[1].value);
    assert_eq!(mutator.get(old, edits[1].key).unwrap(), Some(value(3, 2)));
    mutator.finish(next).unwrap();
    assert_eq!(
        admission.calls.load(AtomicOrdering::Relaxed),
        1,
        "prepared operations must not request another grant"
    );
    assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), held);
    assert_eq!(backend.pages.lock().unwrap()[..old_pages.len()], old_pages);
    drop(workspace);
    assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn write_workspace_rejects_an_operation_outside_its_admitted_envelope() {
    let backend = MemoryPages::default();
    let old = tree(&backend);
    let admission = WorkspaceAdmission::new();
    let mut workspace = DirectoryWriteWorkspace::for_leaf_rewrite(admission.clone()).unwrap();
    admission.deny_all.store(true, AtomicOrdering::Relaxed);
    let reads = backend.reads.load(AtomicOrdering::Relaxed);
    let pages = backend.pages.lock().unwrap().len();
    let mut mutator = DirectoryMutator::new(&backend, &mut workspace).unwrap();
    assert!(
        matches!(&(mutator.set(old, 8, DirectoryKey::row("t", b"bad"), Some(value(8, 44)))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), reads);
    assert_eq!(backend.pages.lock().unwrap().len(), pages);
    assert_eq!(admission.calls.load(AtomicOrdering::Relaxed), 1);
    // The refusal was pre-effect and did not poison the prepared owner.
    assert!(
        mutator
            .get(old, DirectoryKey::table("t"))
            .unwrap()
            .is_some()
    );
    mutator.finish(old).unwrap();
    drop(workspace);
    assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), 0);
}
