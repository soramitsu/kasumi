// Construct sparse immutable trees directly, so difficult shapes do not need
// hundreds of unrelated COW mutations before the operation under test.

#[derive(Clone)]
struct TestNode {
    minimum: ModelKey,
    reference: DirectoryPageRef,
    entries: u64,
    level: u8,
}

impl TestNode {
    fn root(&self) -> DirectoryRoot {
        DirectoryRoot {
            group_id: GROUP,
            generation: 7,
            page: Some(self.reference),
            height: self.level + 1,
            entries: self.entries,
        }
    }
}

fn append_test_page(
    backend: &dyn DirectoryBackend,
    level: u8,
    entries: &[(ModelKey, Vec<u8>, u64)],
) -> TestNode {
    assert!(!entries.is_empty());
    let mut bytes = vec![0; DIRECTORY_PAGE_BYTES];
    let mut at = HEADER_BYTES;
    let mut population = 0u64;
    let mut previous = None;
    for (key, value, count) in entries {
        let key = model_key(key);
        assert!(previous.is_none_or(|previous| previous < key));
        assert_eq!(value.len(), value_bytes(level));
        assert!(at + key.encoded_len() + value.len() <= DIRECTORY_PAGE_BYTES);
        key.encode(&mut bytes[at..at + key.encoded_len()]);
        at += key.encoded_len();
        bytes[at..at + value.len()].copy_from_slice(value);
        at += value.len();
        population += count;
        previous = Some(key);
    }
    bytes[..16].copy_from_slice(&MAGIC);
    bytes[16..20].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[20..36].copy_from_slice(&GROUP);
    bytes[36..44].copy_from_slice(&7u64.to_le_bytes());
    bytes[44] = level;
    bytes[46..48].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    bytes[48..52].copy_from_slice(&(at as u32).to_le_bytes());
    bytes[52..60].copy_from_slice(&population.to_le_bytes());
    let node = TestNode {
        minimum: entries[0].0.clone(),
        reference: backend.append_page(&bytes).unwrap(),
        entries: population,
        level,
    };
    validate_page(&bytes, node.root(), node.reference).unwrap();
    node
}

fn test_leaf(backend: &dyn DirectoryBackend, records: &[(ModelKey, DirectoryValue)]) -> TestNode {
    let encoded: Vec<_> = records
        .iter()
        .map(|(key, value)| {
            let mut bytes = vec![0; LEAF_VALUE_BYTES];
            value.encode(&mut bytes);
            (key.clone(), bytes, 1)
        })
        .collect();
    append_test_page(backend, 0, &encoded)
}

fn test_branch(backend: &dyn DirectoryBackend, children: &[TestNode]) -> TestNode {
    let level = children[0].level + 1;
    let encoded: Vec<_> = children
        .iter()
        .map(|child| {
            assert_eq!(child.level + 1, level);
            let mut bytes = vec![0; BRANCH_VALUE_BYTES];
            child.reference.encode(&mut bytes[..PAGE_REF_BYTES]);
            bytes[PAGE_REF_BYTES..].copy_from_slice(&child.entries.to_le_bytes());
            (child.minimum.clone(), bytes, child.entries)
        })
        .collect();
    append_test_page(backend, level, &encoded)
}

fn row(id: usize, length: usize) -> (ModelKey, DirectoryValue) {
    assert!((8..=MAX_KEY_BYTES).contains(&length));
    let mut key = vec![0; length];
    key[..8].copy_from_slice(&(id as u64).to_be_bytes());
    (("t".into(), Some(key)), value(1 + id as u64 % 7, id as u64))
}

fn key_row(key: &[u8], id: usize) -> (ModelKey, DirectoryValue) {
    (
        ("t".into(), Some(key.to_vec())),
        value(1 + id as u64 % 7, id as u64),
    )
}

fn reachable_counts(backend: &MemoryPages, root: DirectoryRoot) -> Vec<usize> {
    let pages = backend.pages.lock().unwrap();
    let mut pending = root.page.into_iter().collect::<Vec<_>>();
    let mut visited = std::collections::BTreeSet::new();
    let mut levels = vec![0; usize::from(root.height)];
    while let Some(reference) = pending.pop() {
        assert!(visited.insert((reference.arena_id, reference.page_index)));
        let bytes = &pages[reference.page_index as usize];
        let info = validate_page(bytes, root, reference).unwrap();
        levels[usize::from(info.level)] += 1;
        if info.level != 0 {
            for index in 0..info.count {
                let entry = nth_entry(bytes, info, index).unwrap();
                pending.push(DirectoryPageRef::decode(&entry.value[..PAGE_REF_BYTES]).unwrap());
            }
        }
    }
    levels
}

#[derive(Clone, Copy)]
enum FaultPoint {
    Append { after: bool, index: usize },
    Sync { after: bool },
}

#[derive(Default)]
struct PackFaultPages {
    inner: MemoryPages,
    fault: Mutex<Option<FaultPoint>>,
    appends: AtomicUsize,
}

impl PackFaultPages {
    fn arm(&self, fault: FaultPoint) {
        self.appends.store(0, AtomicOrdering::Relaxed);
        *self.fault.lock().unwrap() = Some(fault);
    }
}

impl DirectoryBackend for PackFaultPages {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
        self.inner.read_page(reference, out)
    }

    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        let index = self.appends.fetch_add(1, AtomicOrdering::Relaxed);
        let fault = *self.fault.lock().unwrap();
        if matches!(fault, Some(FaultPoint::Append { after: false, index: at }) if at == index) {
            return Err(CoreError::Io(std::io::Error::other(
                "packing before append",
            )));
        }
        let reference = self.inner.append_page(bytes)?;
        if matches!(fault, Some(FaultPoint::Append { after: true, index: at }) if at == index) {
            return Err(CoreError::Io(std::io::Error::other("packing after append")));
        }
        Ok(reference)
    }

    fn sync_pages(&self) -> Result<(), CoreError> {
        let fault = *self.fault.lock().unwrap();
        if matches!(fault, Some(FaultPoint::Sync { after: false })) {
            return Err(CoreError::Io(std::io::Error::other("packing before sync")));
        }
        self.inner.sync_pages()?;
        if matches!(fault, Some(FaultPoint::Sync { after: true })) {
            return Err(CoreError::Io(std::io::Error::other("packing after sync")));
        }
        Ok(())
    }
}

fn sparse_tree(
    backend: &dyn DirectoryBackend,
    height: usize,
) -> (DirectoryRoot, BTreeMap<ModelKey, DirectoryValue>) {
    assert!((2..=5).contains(&height));
    let mut model = BTreeMap::new();
    let mut nodes = Vec::new();
    for index in 0..1usize << (height - 1) {
        let mut records = Vec::new();
        if index == 0 {
            records.push((("t".into(), None), DirectoryValue::Table { birth_seq: 2 }));
        }
        records.extend([row(index * 2, 8), row(index * 2 + 1, 8)]);
        model.extend(records.iter().cloned());
        nodes.push(test_leaf(backend, &records));
    }
    while nodes.len() > 1 {
        nodes = nodes
            .chunks(2)
            .map(|children| test_branch(backend, children))
            .collect();
    }
    (nodes.pop().unwrap().root(), model)
}

fn pack_once(
    backend: &dyn DirectoryBackend,
    admission: Arc<dyn StorageAdmission>,
    root: DirectoryRoot,
    level: u8,
    lower: DirectoryKey<'_>,
) -> DirectoryRoot {
    let plan = DirectoryReader::new(backend, admission.clone())
        .pack_after(root, level, lower)
        .unwrap()
        .unwrap();
    assert_eq!(plan.level(), level);
    assert!(plan.references().1.is_some());
    assert!(plan.needs_pack());
    let mut mutator_workspace = DirectoryWriteWorkspace::for_pack(admission).unwrap();
    let mut mutator = DirectoryMutator::new(backend, &mut mutator_workspace).unwrap();
    let next = mutator.pack_pair(root, root.generation + 1, &plan).unwrap();
    assert_ne!(next, root);
    assert_eq!(next.generation, root.generation + 1);
    assert_eq!(next.entries, root.entries);
    assert_eq!(mutator.finish(next).unwrap(), next);
    next
}

#[test]
fn same_parent_leaf_and_internal_packing_preserves_logical_records_and_old_roots() {
    for level in [0, 1] {
        let backend = MemoryPages::default();
        let admission = Admission::new(1 << 20);
        let (root, model) = sparse_tree(&backend, 3);
        let original = backend.pages.lock().unwrap().clone();
        let before = reachable_counts(&backend, root);
        let next = pack_once(
            &backend,
            admission.clone(),
            root,
            level,
            DirectoryKey::table("t"),
        );
        let after = reachable_counts(&backend, next);
        assert_eq!(after[usize::from(level)], before[usize::from(level)] - 1);
        if level == 1 {
            assert_eq!(next.height, 2);
            assert_eq!(after[0], before[0]);
        }
        assert_eq!(backend.pages.lock().unwrap()[..original.len()], original);
        assert_directory_model(&backend, admission.clone(), root, &model);
        assert_directory_model(&backend, admission.clone(), next, &model);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }
}

#[test]
fn cross_parent_pairs_rebuild_both_paths_at_a_distant_common_ancestor() {
    for (height, level, first_row) in [(4, 0, 6), (5, 1, 12)] {
        let backend = MemoryPages::default();
        let admission = Admission::new(1 << 20);
        let (root, model) = sparse_tree(&backend, height);
        let original = backend.pages.lock().unwrap().clone();
        let lower = row(first_row, 8).0;
        let before = reachable_counts(&backend, root);
        let next = pack_once(&backend, admission.clone(), root, level, model_key(&lower));
        let after = reachable_counts(&backend, next);
        assert_eq!(after[usize::from(level)], before[usize::from(level)] - 1);
        assert_eq!(next.height, root.height);
        // The branches not on the pair's two paths stay shared and immutable.
        assert_eq!(backend.pages.lock().unwrap()[..original.len()], original);
        assert_directory_model(&backend, admission.clone(), root, &model);
        assert_directory_model(&backend, admission.clone(), next, &model);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }
}

#[test]
fn merging_across_unary_branches_removes_empty_ancestors_and_collapses_the_root() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let records = [row(0, 8), row(1, 8), row(2, 8), row(3, 8)];
    let mut left = test_leaf(&backend, &records[..2]);
    let mut right = test_leaf(&backend, &records[2..]);
    for _ in 0..2 {
        left = test_branch(&backend, &[left]);
        right = test_branch(&backend, &[right]);
    }
    let root = test_branch(&backend, &[left, right]).root();
    assert_eq!(root.height, 4);
    let model = records.into_iter().collect();
    let next = pack_once(
        &backend,
        admission.clone(),
        root,
        0,
        DirectoryKey::table("t"),
    );
    assert_eq!(next.height, 1);
    assert_eq!(reachable_counts(&backend, next), [1]);
    assert_directory_model(&backend, admission.clone(), root, &model);
    assert_directory_model(&backend, admission.clone(), next, &model);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn greedy_redistribution_with_longer_separator_can_split_the_parent() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let mut records = Vec::new();
    for (id, prefix) in (*b"abcccde").into_iter().enumerate() {
        let mut key = if prefix == b'b' {
            vec![prefix]
        } else {
            vec![prefix; MAX_KEY_BYTES]
        };
        if prefix == b'c' {
            key[1] = id as u8;
        }
        records.push(key_row(&key, id));
    }
    let nodes = [
        test_leaf(&backend, &records[..1]),
        test_leaf(&backend, &records[1..5]),
        test_leaf(&backend, &records[5..6]),
        test_leaf(&backend, &records[6..]),
    ];
    let root = test_branch(&backend, &nodes).root();
    let model = records.iter().cloned().collect();
    let reader = DirectoryReader::new(&backend, admission.clone());
    let plan = reader
        .pack_after(root, 0, model_key(&records[0].0))
        .unwrap()
        .unwrap();
    let mut mutator_workspace = DirectoryWriteWorkspace::for_pack(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let next = mutator.pack_pair(root, 8, &plan).unwrap();
    mutator.finish(next).unwrap();
    assert_eq!(root.height, 2);
    assert_eq!(next.height, 3);
    assert_eq!(reachable_counts(&backend, next), [4, 2, 1]);
    let continuation = plan.into_next().unwrap();
    assert_eq!(continuation.key(), model_key(&records[4].0));
    let unchanged = reader
        .pack_after(next, 0, model_key(&records[0].0))
        .unwrap()
        .unwrap();
    assert!(!unchanged.needs_pack());
    assert_directory_model(&backend, admission.clone(), root, &model);
    assert_directory_model(&backend, admission.clone(), next, &model);
    drop((continuation, unchanged, mutator));
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn a_cross_parent_separator_split_propagates_multiple_carries_through_the_common_ancestor() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let mut records = Vec::new();
    for (id, prefix) in (*b"abcccdefgh").into_iter().enumerate() {
        let mut key = if prefix == b'b' {
            vec![prefix]
        } else {
            vec![prefix; MAX_KEY_BYTES]
        };
        if prefix == b'c' {
            key[1] = id as u8;
        }
        records.push(key_row(&key, id));
    }
    let left = test_branch(&backend, &[test_leaf(&backend, &records[..1])]);
    let right = test_branch(
        &backend,
        &[
            test_leaf(&backend, &records[1..5]),
            test_leaf(&backend, &records[5..6]),
            test_leaf(&backend, &records[6..7]),
            test_leaf(&backend, &records[7..8]),
        ],
    );
    let g = test_branch(&backend, &[test_leaf(&backend, &records[8..9])]);
    let h = test_branch(&backend, &[test_leaf(&backend, &records[9..])]);
    let root = test_branch(&backend, &[left, right, g.clone(), h.clone()]).root();
    assert_eq!(reachable_counts(&backend, root), [7, 4, 1]);
    let original = backend.pages.lock().unwrap().clone();
    let next = pack_once(
        &backend,
        admission.clone(),
        root,
        0,
        model_key(&records[0].0),
    );
    assert_eq!(next.height, 4);
    assert_eq!(reachable_counts(&backend, next), [7, 5, 2, 1]);
    assert_eq!(backend.pages.lock().unwrap()[..original.len()], original);
    let model = records.into_iter().collect();
    assert_directory_model(&backend, admission.clone(), root, &model);
    assert_directory_model(&backend, admission.clone(), next, &model);
    // Neither neighbor outside the changed pair's paths is rewritten.
    for node in [g, h] {
        let found = DirectoryReader::new(&backend, admission.clone())
            .pack_after(next, node.level, model_key(&node.minimum))
            .unwrap()
            .unwrap();
        assert_eq!(found.references().0, node.reference);
    }
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn unchanged_and_terminal_plans_do_not_append_or_advance_generation() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let records: Vec<_> = (0..6).map(|id| row(id, MAX_KEY_BYTES)).collect();
    let first = test_leaf(&backend, &records[..3]);
    let second = test_leaf(&backend, &records[3..]);
    let root = test_branch(&backend, &[first.clone(), second.clone()]).root();
    let reader = DirectoryReader::new(&backend, admission.clone());
    let mut mutator_workspace = DirectoryWriteWorkspace::for_pack(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let before = backend.pages.lock().unwrap().len();
    let syncs = backend.syncs.load(AtomicOrdering::Relaxed);
    let pair = reader
        .pack_after(root, 0, DirectoryKey::table("t"))
        .unwrap()
        .unwrap();
    assert_eq!(pair.references(), (first.reference, Some(second.reference)));
    assert!(!pair.needs_pack());
    assert_eq!(mutator.pack_pair(root, 8, &pair).unwrap(), root);
    let cursor = pair.into_next().unwrap();
    assert_eq!(cursor.key(), model_key(&records[3].0));
    let terminal = reader.pack_after(root, 0, cursor.key()).unwrap().unwrap();
    assert_eq!(terminal.references(), (second.reference, None));
    assert!(!terminal.needs_pack());
    assert_eq!(mutator.pack_pair(root, 8, &terminal).unwrap(), root);
    assert!(terminal.into_next().is_none());
    for level in [root.height, root.height + 1] {
        assert!(
            reader
                .pack_after(root, level, DirectoryKey::table("t"))
                .unwrap()
                .is_none()
        );
    }
    assert!(
        reader
            .pack_after(empty_root(), 0, DirectoryKey::table("t"))
            .unwrap()
            .is_none()
    );
    assert!(
        reader
            .pack_after(root, 0, DirectoryKey::table("z"))
            .unwrap()
            .is_none()
    );
    assert_eq!(backend.pages.lock().unwrap().len(), before);
    assert_eq!(backend.syncs.load(AtomicOrdering::Relaxed), syncs);
    drop((cursor, mutator));
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn a_merged_underfull_page_remains_eligible_for_its_next_neighbor() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let (old, model) = sparse_tree(&backend, 4);
    let mut root = old;
    let mut cursor = None;
    let mut merges = 0;
    loop {
        let lower = cursor
            .as_ref()
            .map_or(DirectoryKey::table("t"), |cursor: &DirectoryCursor| {
                cursor.key()
            });
        let plan = DirectoryReader::new(&backend, admission.clone())
            .pack_after(root, 0, lower)
            .unwrap()
            .unwrap();
        if !plan.needs_pack() {
            assert!(plan.references().1.is_none());
            assert!(plan.into_next().is_none());
            break;
        }
        let mut mutator_workspace = DirectoryWriteWorkspace::for_pack(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        root = mutator.pack_pair(root, root.generation + 1, &plan).unwrap();
        mutator.finish(root).unwrap();
        cursor = plan.into_next();
        assert_eq!(cursor.as_ref().unwrap().key(), DirectoryKey::table("t"));
        merges += 1;
        assert!(merges <= 7);
    }
    assert_eq!(merges, 7);
    assert_eq!(root.height, 1);
    assert_eq!(reachable_counts(&backend, root), [1]);
    assert_directory_model(&backend, admission.clone(), old, &model);
    assert_directory_model(&backend, admission.clone(), root, &model);
    drop(cursor);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

struct PackAdmission {
    inner: Arc<Admission>,
    calls: AtomicUsize,
    denied: AtomicUsize,
}

impl PackAdmission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Admission::new(1 << 20),
            calls: AtomicUsize::new(0),
            denied: AtomicUsize::new(usize::MAX),
        })
    }

    fn deny(&self, call: usize) {
        self.calls.store(0, AtomicOrdering::Relaxed);
        self.denied.store(call, AtomicOrdering::Relaxed);
    }
}

impl StorageAdmission for PackAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.inner.check_owner()
    }

    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        let index = self.calls.fetch_add(1, AtomicOrdering::Relaxed);
        if index == self.denied.load(AtomicOrdering::Relaxed) {
            return Err(AdmissionError::CapacityDenied);
        }
        self.inner.reserve_workspace(bytes)
    }

    fn reserve_growth(&self, allocated: u64, bytes: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(allocated, bytes)
    }

    fn settle_growth(&self, allocated: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(allocated)
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
impl crate::cache_test::Provider for PackAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
        let _ = first;
        let index = self.calls.fetch_add(1, AtomicOrdering::Relaxed);
        if index == self.denied.load(AtomicOrdering::Relaxed) {
            return Err(AdmissionError::CapacityDenied);
        }
        crate::cache_test::Provider::acquire_cache(self.inner.as_ref(), bytes, first)
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
        crate::cache_test::Provider::release_cache(self.inner.as_ref(), bytes, last);
    }
}

#[test]
fn pack_plan_and_workspace_denial_precede_effects_and_prepared_mutation_reuses_grant() {
    let backend = MemoryPages::default();
    let (root, model) = sparse_tree(&backend, 4);
    let denied = Admission::new(1);
    let before = backend.reads.load(AtomicOrdering::Relaxed);
    assert!(matches!(
        DirectoryReader::new(&backend, denied.clone()).pack_after(
            root,
            0,
            DirectoryKey::table("t")
        ),
        Err(CoreError::CapacityDenied)
    ));
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), before);
    assert_eq!(denied.0.used.load(AtomicOrdering::Relaxed), 0);

    let admission = PackAdmission::new();
    let lower = row(6, 8).0;
    let plan = DirectoryReader::new(&backend, admission.clone())
        .pack_after(root, 0, model_key(&lower))
        .unwrap()
        .unwrap();
    let used = admission.inner.0.used.load(AtomicOrdering::Relaxed);
    let pages = backend.pages.lock().unwrap().len();
    let reads = backend.reads.load(AtomicOrdering::Relaxed);
    let syncs = backend.syncs.load(AtomicOrdering::Relaxed);
    admission.deny(0);
    assert!(matches!(
        DirectoryWriteWorkspace::for_pack(admission.clone()),
        Err(CoreError::CapacityDenied)
    ));
    assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), used);
    assert_eq!(backend.pages.lock().unwrap().len(), pages);
    assert_eq!(backend.reads.load(AtomicOrdering::Relaxed), reads);
    assert_eq!(backend.syncs.load(AtomicOrdering::Relaxed), syncs);
    admission.check_owner().unwrap();
    admission.deny(usize::MAX);
    let mut workspace = DirectoryWriteWorkspace::for_pack(admission.clone()).unwrap();
    assert_eq!(admission.calls.load(AtomicOrdering::Relaxed), 1);
    // Refuse any new grant: both authenticated path checks and all appends
    // must use the actual prepared owner's existing page backing.
    admission.deny(0);
    let mut mutator = DirectoryMutator::new(&backend, &mut workspace).unwrap();
    let next = mutator.pack_pair(root, 8, &plan).unwrap();
    mutator.finish(next).unwrap();
    assert_eq!(admission.calls.load(AtomicOrdering::Relaxed), 0);
    drop(workspace);
    admission.deny(usize::MAX);
    assert_directory_model(&backend, admission.clone(), next, &model);
    admission.deny(usize::MAX);
    assert_directory_model(&backend, admission.clone(), root, &model);
    drop(plan);
    assert_eq!(admission.inner.0.used.load(AtomicOrdering::Relaxed), 0);
    assert!(admission.inner.0.peak.load(AtomicOrdering::Relaxed) <= 1 << 20);
}

#[test]
fn pack_pair_rejects_foreign_or_stale_plans_without_poisoning_a_valid_retry() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let (root, model) = sparse_tree(&backend, 3);
    let plan = DirectoryReader::new(&backend, admission.clone())
        .pack_after(root, 0, DirectoryKey::table("t"))
        .unwrap()
        .unwrap();
    let mut mutator_workspace = DirectoryWriteWorkspace::for_pack(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let pages = backend.pages.lock().unwrap().len();
    for foreign in [
        DirectoryRoot {
            group_id: [99; 16],
            ..root
        },
        DirectoryRoot {
            generation: 8,
            ..root
        },
        DirectoryRoot {
            entries: root.entries + 1,
            ..root
        },
    ] {
        assert!(matches!(
            mutator.pack_pair(foreign, 9, &plan),
            Err(CoreError::InvalidInput(_))
        ));
    }
    for generation in [0, 6] {
        assert!(matches!(
            mutator.pack_pair(root, generation, &plan),
            Err(CoreError::InvalidInput(_))
        ));
    }
    assert_eq!(backend.pages.lock().unwrap().len(), pages);
    let next = mutator.pack_pair(root, 8, &plan).unwrap();
    mutator.finish(next).unwrap();
    assert_directory_model(&backend, admission.clone(), next, &model);
    drop((plan, mutator));
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn both_source_pages_and_their_parent_paths_are_revalidated_before_append() {
    for damaged in 0..3 {
        let backend = MemoryPages::default();
        let admission = Admission::new(1 << 20);
        let (root, _) = sparse_tree(&backend, 4);
        let lower = row(6, 8).0;
        let plan = DirectoryReader::new(&backend, admission.clone())
            .pack_after(root, 0, model_key(&lower))
            .unwrap()
            .unwrap();
        let (left, right) = plan.references();
        let reference = match damaged {
            0 => left,
            1 => right.unwrap(),
            _ => root.page.unwrap(),
        };
        backend.pages.lock().unwrap()[reference.page_index as usize][36] ^= 1;
        let pages = backend.pages.lock().unwrap().len();
        let mut mutator_workspace = DirectoryWriteWorkspace::for_pack(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        assert!(matches!(
            mutator.pack_pair(root, 8, &plan),
            Err(CoreError::Corrupt(_))
        ));
        assert_eq!(backend.pages.lock().unwrap().len(), pages);
        assert!(matches!(mutator.finish(root), Err(CoreError::OwnerFailed)));
        drop((plan, mutator));
        drop(mutator_workspace);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }
}

#[test]
fn checksum_valid_malformed_shapes_and_nonadjacent_child_substitution_fail_closed() {
    for damage in 0..5 {
        let backend = MemoryPages::default();
        let admission = Admission::new(1 << 20);
        let records: Vec<_> = (0..6).map(|id| row(id, 8)).collect();
        let leaves: Vec<_> = records
            .chunks(2)
            .map(|rows| test_leaf(&backend, rows))
            .collect();
        let mut root = test_branch(&backend, &leaves).root();
        let root_reference = root.page.unwrap();
        let mut pages = backend.pages.lock().unwrap();
        let bytes = &mut pages[root_reference.page_index as usize];
        let info = validate_page(bytes, root, root_reference).unwrap();
        let first_value = HEADER_BYTES + model_key(&leaves[0].minimum).encoded_len();
        match damage {
            0 => bytes[45] = 1,
            1 => {
                bytes[first_value + PAGE_REF_BYTES..first_value + BRANCH_VALUE_BYTES]
                    .copy_from_slice(&3u64.to_le_bytes());
                root.entries += 1;
                bytes[52..60].copy_from_slice(&root.entries.to_le_bytes());
            }
            2 => {
                // Keep ordered parent separators but point its first child
                // at a nonadjacent subtree. Child bounds must reject this.
                leaves[2]
                    .reference
                    .encode(&mut bytes[first_value..first_value + PAGE_REF_BYTES]);
            }
            3 => bytes[44] = 2,
            4 => {
                let second = nth_entry(bytes, info, 1).unwrap();
                let second_at =
                    HEADER_BYTES + model_key(&leaves[0].minimum).encoded_len() + BRANCH_VALUE_BYTES;
                let key_len = second.key_bytes.len();
                bytes[second_at + key_len..second_at + key_len + PAGE_REF_BYTES]
                    .copy_from_slice(&[0; PAGE_REF_BYTES]);
            }
            _ => unreachable!(),
        }
        root.page.as_mut().unwrap().sha256 = page_digest(bytes);
        let count = pages.len();
        drop(pages);
        assert!(
            matches!(
                DirectoryReader::new(&backend, admission.clone()).pack_after(
                    root,
                    0,
                    DirectoryKey::table("t")
                ),
                Err(CoreError::Corrupt(_))
            ),
            "damage {damage}"
        );
        assert_eq!(backend.pages.lock().unwrap().len(), count);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }
}

#[test]
fn before_and_after_append_or_sync_failures_keep_old_roots_and_poison_the_batch() {
    let baseline = PackFaultPages::default();
    let admission = Admission::new(1 << 20);
    let (root, _) = sparse_tree(&baseline, 4);
    let lower = row(6, 8).0;
    baseline.appends.store(0, AtomicOrdering::Relaxed);
    pack_once(&baseline, admission, root, 0, model_key(&lower));
    let appends = baseline.appends.load(AtomicOrdering::Relaxed);
    assert!(appends >= 4);

    let faults = (0..appends)
        .flat_map(|index| {
            [
                FaultPoint::Append {
                    after: false,
                    index,
                },
                FaultPoint::Append { after: true, index },
            ]
        })
        .chain([
            FaultPoint::Sync { after: false },
            FaultPoint::Sync { after: true },
        ]);
    for fault in faults {
        let backend = PackFaultPages::default();
        let admission = Admission::new(1 << 20);
        let (root, model) = sparse_tree(&backend, 4);
        let original = backend.inner.pages.lock().unwrap().clone();
        let plan = DirectoryReader::new(&backend, admission.clone())
            .pack_after(root, 0, model_key(&lower))
            .unwrap()
            .unwrap();
        let mut mutator_workspace = DirectoryWriteWorkspace::for_pack(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
        backend.arm(fault);
        let result = mutator.pack_pair(root, 8, &plan);
        match fault {
            FaultPoint::Append { after, index } => {
                assert!(matches!(result, Err(CoreError::Io(_))));
                assert_eq!(
                    backend.inner.pages.lock().unwrap().len() - original.len(),
                    index + usize::from(after)
                );
            }
            FaultPoint::Sync { after } => {
                let next = result.unwrap();
                let before = backend.inner.syncs.load(AtomicOrdering::Relaxed);
                assert!(matches!(mutator.finish(next), Err(CoreError::Io(_))));
                assert_eq!(
                    backend.inner.syncs.load(AtomicOrdering::Relaxed) - before,
                    usize::from(after)
                );
            }
        }
        assert!(matches!(mutator.finish(root), Err(CoreError::OwnerFailed)));
        assert_eq!(
            backend.inner.pages.lock().unwrap()[..original.len()],
            original
        );
        assert_directory_model(&backend, admission.clone(), root, &model);
        drop((plan, mutator));
        drop(mutator_workspace);
        assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    }
}

fn sweep_level(
    backend: &dyn DirectoryBackend,
    admission: Arc<dyn StorageAdmission>,
    mut root: DirectoryRoot,
    level: u8,
) -> (DirectoryRoot, usize) {
    let mut cursor: Option<DirectoryCursor> = None;
    let mut changes = 0;
    // The fixture has 16 initial leaves and fewer pages at every other level.
    // A conservative finite guard catches a continuation that revisits forever.
    for step in 0..128 {
        let lower = cursor
            .as_ref()
            .map_or(DirectoryKey::table("t"), DirectoryCursor::key);
        let Some(plan) = DirectoryReader::new(backend, admission.clone())
            .pack_after(root, level, lower)
            .unwrap()
        else {
            return (root, changes);
        };
        if plan.needs_pack() {
            let mut mutator_workspace =
                DirectoryWriteWorkspace::for_pack(admission.clone()).unwrap();
            let mut mutator = DirectoryMutator::new(backend, &mut mutator_workspace).unwrap();
            root = mutator.pack_pair(root, root.generation + 1, &plan).unwrap();
            mutator.finish(root).unwrap();
            changes += 1;
        }
        cursor = plan.into_next();
        if cursor.is_none() {
            return (root, changes);
        }
        assert!(step < 127, "packing level {level} did not finish");
    }
    unreachable!()
}

#[test]
fn complete_uneven_key_sweeps_match_dense_builder_at_every_reachable_level() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let mut model = BTreeMap::new();
    let mut nodes = Vec::new();
    for index in 0..16 {
        let mut records = Vec::new();
        if index == 0 {
            records.push((("t".into(), None), DirectoryValue::Table { birth_seq: 2 }));
        }
        records.extend([row(index * 2, MAX_KEY_BYTES), row(index * 2 + 1, 8)]);
        model.extend(records.iter().cloned());
        nodes.push(test_leaf(&backend, &records));
    }
    while nodes.len() > 1 {
        nodes = nodes
            .chunks(2)
            .map(|nodes| test_branch(&backend, nodes))
            .collect();
    }
    let original = nodes.pop().unwrap().root();
    assert_eq!(original.height, 5);
    assert_eq!(reachable_counts(&backend, original), [16, 8, 4, 2, 1]);
    let original_pages = backend.pages.lock().unwrap().clone();
    let mut root = original;
    let mut leaf_changes = 0;
    let mut internal_changes = 0;
    for level in 0..original.height {
        let (next, changes) = sweep_level(&backend, admission.clone(), root, level);
        root = next;
        if level == 0 {
            leaf_changes += changes;
        } else {
            internal_changes += changes;
        }
        assert_directory_model(&backend, admission.clone(), root, &model);
    }
    assert!(leaf_changes > 0);
    assert!(internal_changes > 0);
    assert!(root.height < original.height);
    let dense = MemoryPages::default();
    let mut builder =
        DirectoryBuilder::new(&dense, admission.clone(), GROUP, root.generation).unwrap();
    for (key, value) in &model {
        builder.push(model_key(key), *value).unwrap();
    }
    let dense_root = builder.finish().unwrap();
    assert_eq!(root.height, dense_root.height);
    assert_eq!(
        reachable_counts(&backend, root),
        reachable_counts(&dense, dense_root)
    );
    assert_eq!(
        backend.pages.lock().unwrap()[..original_pages.len()],
        original_pages
    );
    assert_directory_model(&backend, admission.clone(), original, &model);
    assert_directory_model(&dense, admission.clone(), dense_root, &model);

    // Repeating every level on the packed tree performs no additional writes.
    let before = backend.pages.lock().unwrap().len();
    let syncs = backend.syncs.load(AtomicOrdering::Relaxed);
    for level in 0..root.height {
        let (next, changes) = sweep_level(&backend, admission.clone(), root, level);
        assert_eq!(changes, 0);
        assert_eq!(next, root);
    }
    assert_eq!(backend.pages.lock().unwrap().len(), before);
    assert_eq!(backend.syncs.load(AtomicOrdering::Relaxed), syncs);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
    assert!(admission.0.peak.load(AtomicOrdering::Relaxed) <= 1 << 20);
}

#[test]
fn continuation_reselects_after_its_key_is_deleted_and_the_current_root_shrinks() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let (original, old_model) = sparse_tree(&backend, 3);
    let lower = row(2, 8).0;
    let plan = DirectoryReader::new(&backend, admission.clone())
        .pack_after(original, 0, model_key(&lower))
        .unwrap()
        .unwrap();
    let mut mutator_workspace = DirectoryWriteWorkspace::for_pack(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let packed = mutator.pack_pair(original, 8, &plan).unwrap();
    mutator.finish(packed).unwrap();
    let cursor = plan.into_next().unwrap();
    assert_eq!(cursor.key(), model_key(&lower));
    assert_eq!(packed.height, 3);
    drop(mutator_workspace);
    // Deletion is a distinct admitted operation, with its own smaller shape.
    let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();

    let mut current = packed;
    let mut model = old_model.clone();
    for id in [2, 6, 7] {
        let key = row(id, 8).0;
        current = mutator.set(current, 9, model_key(&key), None).unwrap();
        model.remove(&key);
    }
    mutator.finish(current).unwrap();
    assert_eq!(current.height, 2);
    let reader = DirectoryReader::new(&backend, admission.clone());
    let resumed = reader
        .pack_after(current, 0, cursor.key())
        .unwrap()
        .unwrap();
    let first_remaining = row(3, 8).0;
    let leaf = reader
        .leaf_after(current, model_key(&first_remaining), false)
        .unwrap()
        .unwrap();
    assert_eq!(resumed.references(), (leaf.reference(), None));
    assert_eq!(
        leaf.owned_record(0).unwrap().key(),
        model_key(&first_remaining)
    );
    assert!(!resumed.needs_pack());
    assert!(resumed.into_next().is_none());
    assert!(
        reader
            .pack_after(current, packed.height - 1, cursor.key())
            .unwrap()
            .is_none()
    );
    assert_directory_model(&backend, admission.clone(), original, &old_model);
    assert_directory_model(&backend, admission.clone(), packed, &old_model);
    assert_directory_model(&backend, admission.clone(), current, &model);
    drop((cursor, leaf, mutator));
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}

#[test]
fn a_terminal_unary_root_chain_normalizes_without_appending_or_changing_logical_versions() {
    let backend = MemoryPages::default();
    let admission = Admission::new(1 << 20);
    let records = [
        (("t".into(), None), DirectoryValue::Table { birth_seq: 2 }),
        row(0, 8),
        row(1, MAX_KEY_BYTES),
    ];
    let leaf = test_leaf(&backend, &records);
    let mut node = leaf.clone();
    for _ in 0..3 {
        node = test_branch(&backend, &[node]);
    }
    let root = node.root();
    assert_eq!(root.height, 4);
    assert_eq!(reachable_counts(&backend, root), [1, 1, 1, 1]);
    let original_pages = backend.pages.lock().unwrap().clone();
    let reader = DirectoryReader::new(&backend, admission.clone());
    let plan = reader
        .pack_after(root, 0, DirectoryKey::table("t"))
        .unwrap()
        .unwrap();
    assert_eq!(plan.references(), (leaf.reference, None));
    assert!(plan.needs_pack());
    let mut mutator_workspace = DirectoryWriteWorkspace::for_pack(admission.clone()).unwrap();
    let mut mutator = DirectoryMutator::new(&backend, &mut mutator_workspace).unwrap();
    let next = mutator.pack_pair(root, 8, &plan).unwrap();
    assert_eq!(next.height, 1);
    assert_eq!(next.page, Some(leaf.reference));
    assert_eq!(next.generation, 8);
    assert_eq!(next.entries, root.entries);
    assert_eq!(*backend.pages.lock().unwrap(), original_pages);
    assert_eq!(backend.syncs.load(AtomicOrdering::Relaxed), 0);
    mutator.finish(next).unwrap();
    assert!(plan.into_next().is_none());

    let dense = MemoryPages::default();
    let mut builder = DirectoryBuilder::new(&dense, admission.clone(), GROUP, 8).unwrap();
    for (key, value) in &records {
        builder.push(model_key(key), *value).unwrap();
    }
    let dense_root = builder.finish().unwrap();
    assert_eq!(
        reachable_counts(&backend, next),
        reachable_counts(&dense, dense_root)
    );
    assert_eq!(next.height, dense_root.height);
    let model = records.into_iter().collect();
    assert_directory_model(&backend, admission.clone(), root, &model);
    assert_directory_model(&backend, admission.clone(), next, &model);
    let terminal = reader
        .pack_after(next, 0, DirectoryKey::table("t"))
        .unwrap()
        .unwrap();
    assert!(!terminal.needs_pack());
    assert_eq!(terminal.references(), (leaf.reference, None));
    assert_eq!(mutator.pack_pair(next, 9, &terminal).unwrap(), next);
    assert!(terminal.into_next().is_none());
    assert_eq!(*backend.pages.lock().unwrap(), original_pages);
    drop(mutator_workspace);
    assert_eq!(admission.0.used.load(AtomicOrdering::Relaxed), 0);
}
