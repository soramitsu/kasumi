use super::*;
use crate::application_manifest::{ApplicationManifest, INITIAL_PAGE_SPACE, PAGE_FAMILY};
use crate::test_utils::{FaultBackend, LocalKeyProvider, ManualClock, TestDiskMemory};
use std::collections::BTreeSet;
use std::ops::Bound;

const SPACE: &str = "kasumi.app.pages";

/// Seeded xorshift; a failing seed reproduces exactly.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// One page space in memory. Cloning the rows is a pinned reader's view.
struct MemorySource {
    rows: Mutex<BTreeMap<Vec<u8>, Arc<[u8]>>>,
    memory: Arc<TestDiskMemory>,
}
impl MemorySource {
    fn new() -> Self {
        Self {
            rows: Mutex::new(BTreeMap::new()),
            memory: TestDiskMemory::new(1 << 30, 4096),
        }
    }
    fn apply(&self, writes: &[WriteOp]) {
        let mut rows = self.rows.lock();
        for write in writes {
            match write {
                WriteOp::Put {
                    namespace,
                    key,
                    value,
                } => {
                    assert_eq!(namespace, SPACE);
                    assert!(
                        rows.insert(key.clone(), value.as_slice().into()).is_none(),
                        "immutable row rewritten"
                    );
                }
                WriteOp::Delete { namespace, key } => {
                    assert_eq!(namespace, SPACE);
                    assert!(rows.remove(key).is_some(), "deleted row absent");
                }
            }
        }
    }
    fn pinned(&self) -> Self {
        Self {
            rows: Mutex::new(self.rows.lock().clone()),
            memory: self.memory.clone(),
        }
    }
    fn keys(&self) -> BTreeSet<Vec<u8>> {
        self.rows.lock().keys().cloned().collect()
    }
}
impl PageSource for MemorySource {
    fn check_access(&self) -> Result<()> {
        Ok(())
    }
    fn read_row(&self, space: &str, key: &[u8], max_bytes: usize) -> Result<Option<PageRow>> {
        assert_eq!(space, SPACE);
        let row = self.rows.lock().get(key).cloned();
        if let Some(row) = &row {
            ensure!(row.len() <= max_bytes, "row exceeds bound");
        }
        Ok(row.map(PageRow::Memory))
    }
    fn memory(&self) -> Arc<dyn NodeDiskMemoryAdmission> {
        self.memory.clone()
    }
    fn domain(&self) -> &str {
        "memory"
    }
}

type Model = BTreeMap<Vec<u8>, Vec<u8>>;

fn key(n: u64) -> Vec<u8> {
    // Variable lengths with shared prefixes exercise separators.
    let mut key = format!("k{:06}", n).into_bytes();
    key.extend(std::iter::repeat_n(b'x', (n % 7) as usize));
    key
}

fn value(rng: &mut Rng) -> Vec<u8> {
    let len = match rng.below(100) {
        0..=59 => rng.below(64) as usize,
        60..=89 => 64 + rng.below(1900) as usize,
        90..=98 => MAX_INLINE_VALUE + 1 + rng.below(6000) as usize,
        // A rare value spanning several overflow chunks.
        _ if rng.below(4) == 0 => OVERFLOW_CHUNK_BYTES * 2 + rng.below(5000) as usize,
        _ => MAX_INLINE_VALUE + 1 + rng.below(3000) as usize,
    };
    let fill = rng.next() as u8;
    (0..len).map(|i| fill.wrapping_add(i as u8)).collect()
}

/// Every row in the space is reachable from `root`, every non-root page is
/// within its bounds and above the minimum fill, and the root's aggregates
/// match the model.
fn check_structure(source: &MemorySource, root: &TreeRoot, model: &Model) {
    let mut reachable = BTreeSet::new();
    if let Some(page) = root.root {
        let mut pending = vec![(page, true)];
        while let Some((page_ref, is_root)) = pending.pop() {
            reachable.insert(page_ref.id.row_key().to_vec());
            let row = source
                .read_row(SPACE, &page_ref.id.row_key(), MAX_PAGE_BYTES)
                .unwrap()
                .expect("reachable page present");
            let page = Page::decode(row.as_bytes(), &root.tree, &page_ref).unwrap();
            let payload = row.as_bytes().len() - HEADER_BYTES;
            assert!(
                is_root || !underfull(payload, page.len()),
                "non-root page underfull: {payload} bytes, {} entries",
                page.len()
            );
            if is_root && page.level > 0 {
                assert!(page.len() > 1, "root with one child was not collapsed");
            }
            for index in 0..page.len() {
                if page.is_leaf() {
                    if let ValueRef::Overflow(overflow) = page.value(index) {
                        for chunk in 0..overflow.chunks() {
                            reachable.insert(overflow.chunk_key(chunk).to_vec());
                        }
                    }
                } else {
                    pending.push((page.child(index), false));
                }
            }
        }
    }
    assert_eq!(reachable, source.keys(), "leaked or missing rows");
    assert_eq!(root.count(), model.len() as u64);
    assert_eq!(
        root.bytes(),
        model
            .iter()
            .map(|(key, value)| (key.len() + value.len()) as u64)
            .sum::<u64>()
    );
}

fn expected_range(
    model: &Model,
    start: Bound<&[u8]>,
    direction: Direction,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let entries: Vec<_> = match direction {
        Direction::Forward => model
            .range::<[u8], _>((start, Bound::Unbounded))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        Direction::Reverse => model
            .range::<[u8], _>((Bound::Unbounded, start))
            .rev()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    };
    entries
}

fn check_reads(
    source: &MemorySource,
    root: &TreeRoot,
    model: &Model,
    rng: &mut Rng,
    universe: u64,
) {
    let reader = TreeReader::new(source, SPACE, *root, None).unwrap();
    for direction in [Direction::Forward, Direction::Reverse] {
        let (all, more) = reader
            .page(Bound::Unbounded, direction, usize::MAX)
            .unwrap();
        assert!(!more);
        assert_eq!(all, expected_range(model, Bound::Unbounded, direction));
    }
    let mut out = Vec::new();
    for _ in 0..40 {
        let probe = key(rng.below(universe));
        let found = reader.get(&probe, &mut out).unwrap();
        assert_eq!(found.then(|| out.clone()), model.get(&probe).cloned());
    }
    for _ in 0..20 {
        let probe = key(rng.below(universe));
        let direction = if rng.below(2) == 0 {
            Direction::Forward
        } else {
            Direction::Reverse
        };
        let start = if rng.below(2) == 0 {
            Bound::Included(probe.as_slice())
        } else {
            Bound::Excluded(probe.as_slice())
        };
        let limit = 1 + rng.below(40) as usize;
        let expected = expected_range(model, start, direction);
        let (page, more) = reader.page(start, direction, limit).unwrap();
        assert_eq!(page.as_slice(), &expected[..expected.len().min(limit)]);
        assert_eq!(more, expected.len() > limit);
        // Continue from the last key of the page, as a paginating caller does.
        if let Some((last, _)) = page.last() {
            let (next, _) = reader
                .page(Bound::Excluded(last), direction, limit)
                .unwrap();
            let rest = &expected[page.len()..];
            assert_eq!(next.as_slice(), &rest[..rest.len().min(limit)]);
        }
    }
}

fn random_batch(
    rng: &mut Rng,
    model: &Model,
    universe: u64,
    size: usize,
) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let mut batch = BTreeMap::new();
    let deletes = rng.below(100);
    while batch.len() < size {
        let candidate = key(rng.below(universe));
        let delete = model.contains_key(&candidate) && rng.below(100) < deletes;
        batch.insert(candidate, (!delete).then(|| value(rng)));
    }
    batch.into_iter().collect()
}

fn apply_batch(
    source: &MemorySource,
    root: &TreeRoot,
    model: &mut Model,
    batch: &[(Vec<u8>, Option<Vec<u8>>)],
) -> TreeRoot {
    let edits: Vec<Edit<'_>> = batch
        .iter()
        .map(|(key, value)| match value {
            Some(value) => Edit::Put(key, value),
            None => Edit::Delete(key),
        })
        .collect();
    let edit = edit_tree(source, SPACE, root, &edits).unwrap();
    source.apply(edit.writes());
    for (key, value) in batch {
        match value {
            Some(value) => model.insert(key.clone(), value.clone()),
            None => model.remove(key),
        };
    }
    edit.root
}

#[test]
fn random_batches_match_a_btreemap_through_splits_merges_and_deletes() {
    for seed in [1u64, 7, 99, 0xdead_beef] {
        let mut rng = Rng(seed);
        let source = MemorySource::new();
        let mut root = TreeRoot::new_tree();
        let mut model = Model::new();
        let universe = 3000;
        for round in 0..50 {
            let size = 1 + rng.below(256) as usize;
            let batch = random_batch(&mut rng, &model, universe, size);
            // The previous root still reads completely through its pin.
            let pinned = (round % 10 == 0).then(|| (source.pinned(), root, model.clone()));
            root = apply_batch(&source, &root, &mut model, &batch);
            check_structure(&source, &root, &model);
            check_reads(&source, &root, &model, &mut rng, universe);
            if let Some((pinned, old_root, old_model)) = pinned {
                check_reads(&pinned, &old_root, &old_model, &mut rng, universe);
            }
        }
        // Drain to empty: every page and chunk goes with the last entry.
        let keys: Vec<_> = model.keys().cloned().collect();
        for chunk in keys.chunks(256) {
            let batch: Vec<_> = chunk.iter().map(|key| (key.clone(), None)).collect();
            root = apply_batch(&source, &root, &mut model, &batch);
            check_structure(&source, &root, &model);
        }
        assert!(root.root.is_none());
        assert!(source.keys().is_empty(), "seed {seed} leaked rows");
    }
}

#[test]
fn an_edit_rewrites_only_changed_paths_and_shares_the_rest() {
    let mut rng = Rng(5);
    let source = MemorySource::new();
    let mut model = Model::new();
    let mut root = TreeRoot::new_tree();
    for start in (0..20_000u64).step_by(256) {
        let batch: Vec<_> = (start..start + 256)
            .map(|n| (key(n), Some(vec![(n % 251) as u8; 100])))
            .collect();
        root = apply_batch(&source, &root, &mut model, &batch);
    }
    check_structure(&source, &root, &model);
    assert!(root.height() >= 3);
    let pages_before = source.keys().len();
    // One changed entry rewrites one page per level and deletes as many.
    let probe = key(rng.below(20_000));
    let changed = vec![9u8; 120];
    let edit = edit_tree(&source, SPACE, &root, &[Edit::Put(&probe, &changed)]).unwrap();
    let puts = edit
        .writes()
        .iter()
        .filter(|write| matches!(write, WriteOp::Put { .. }))
        .count();
    let deletes = edit.writes().len() - puts;
    assert_eq!(puts, root.height());
    assert_eq!(deletes, root.height());
    source.apply(edit.writes());
    model.insert(probe, changed);
    root = edit.root;
    check_structure(&source, &root, &model);
    assert_eq!(source.keys().len(), pages_before);
    // An identical value is no change at all.
    let (existing, value) = model
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.clone()))
        .unwrap();
    let edit = edit_tree(&source, SPACE, &root, &[Edit::Put(&existing, &value)]).unwrap();
    assert!(edit.writes().is_empty());
    assert_eq!(edit.root, root);
}

#[test]
fn overflow_values_are_shared_until_replaced_and_deleted_with_their_entry() {
    let source = MemorySource::new();
    let mut model = Model::new();
    let large = vec![7u8; OVERFLOW_CHUNK_BYTES * 3 + 11];
    let batch: Vec<_> = (0..40)
        .map(|n| {
            (
                key(n),
                Some(if n == 3 { large.clone() } else { vec![1; 1500] }),
            )
        })
        .collect();
    let mut root = apply_batch(&source, &TreeRoot::new_tree(), &mut model, &batch);
    check_structure(&source, &root, &model);
    // Rewriting a neighbour copies the overflow reference, not its chunks.
    let edit = edit_tree(&source, SPACE, &root, &[Edit::Put(&key(4), b"changed")]).unwrap();
    assert!(
        edit.writes()
            .iter()
            .all(|write| !matches!(write, WriteOp::Put { key, .. } if key[0] == CHUNK_ROW))
    );
    source.apply(edit.writes());
    model.insert(key(4), b"changed".to_vec());
    root = edit.root;
    check_structure(&source, &root, &model);
    let mut out = Vec::new();
    let reader = TreeReader::new(&source, SPACE, root, None).unwrap();
    assert!(reader.get(&key(3), &mut out).unwrap());
    assert_eq!(out, large);
    drop(reader);
    root = apply_batch(&source, &root, &mut model, &[(key(3), None)]);
    check_structure(&source, &root, &model);
}

#[test]
fn bulk_build_matches_the_model_and_accepts_later_edits() {
    for (seed, entries) in [(3u64, 0u64), (4, 1), (5, 129), (6, 4000)] {
        let mut rng = Rng(seed);
        let source = MemorySource::new();
        let mut model = Model::new();
        let tree = TreeRoot::new_tree().tree;
        let mut rows = Vec::new();
        let mut emit = |key: &[u8], value: &[u8]| -> Result<()> {
            rows.push(WriteOp::put(SPACE, key, value));
            Ok(())
        };
        let mut builder = BulkBuilder::new(tree, source.memory(), &mut emit).unwrap();
        for n in 0..entries {
            let value = value(&mut rng);
            builder.push(&key(n), &value).unwrap();
            model.insert(key(n), value);
        }
        let mut root = builder.finish().unwrap();
        source.apply(&rows);
        check_structure(&source, &root, &model);
        check_reads(&source, &root, &model, &mut rng, entries.max(1) * 2);
        for _ in 0..10 {
            let batch = random_batch(&mut rng, &model, entries.max(1) * 2, 200);
            root = apply_batch(&source, &root, &mut model, &batch);
            check_structure(&source, &root, &model);
        }
        check_reads(&source, &root, &model, &mut rng, entries.max(1) * 2);
    }
}

#[test]
fn bulk_entries_must_be_strictly_increasing() {
    let memory = TestDiskMemory::new(1 << 26, 64);
    let mut emit = |_: &[u8], _: &[u8]| -> Result<()> { Ok(()) };
    let mut builder = BulkBuilder::new([1; 16], memory, &mut emit).unwrap();
    builder.push(b"b", b"1").unwrap();
    assert!(builder.push(b"b", b"2").is_err());
    assert!(builder.push(b"a", b"2").is_err());
    let source = MemorySource::new();
    assert!(
        edit_tree(
            &source,
            SPACE,
            &TreeRoot::new_tree(),
            &[Edit::Put(b"b", b""), Edit::Put(b"a", b"")]
        )
        .is_err()
    );
    let long = vec![0; MAX_KEY_BYTES + 1];
    assert!(
        edit_tree(
            &source,
            SPACE,
            &TreeRoot::new_tree(),
            &[Edit::Put(&long, b"")]
        )
        .is_err()
    );
}

#[test]
fn corrupt_substituted_and_misreferenced_pages_are_refused() {
    let source = MemorySource::new();
    let mut model = Model::new();
    let batch: Vec<_> = (0..2000).map(|n| (key(n), Some(vec![3; 200]))).collect();
    let root = apply_batch(&source, &TreeRoot::new_tree(), &mut model, &batch);
    let full_scan = |source: &MemorySource, root: TreeRoot| -> Result<u64> {
        TreeReader::new(source, SPACE, root, None)?.verify()
    };
    assert!(full_scan(&source, root).is_ok());
    // A flipped byte anywhere in any page fails its parent's hash.
    let page_key = source
        .keys()
        .into_iter()
        .find(|key| key[0] == PAGE_ROW)
        .unwrap();
    let corrupt = source.pinned();
    {
        let mut rows = corrupt.rows.lock();
        let mut bytes = rows[&page_key].to_vec();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        rows.insert(page_key.clone(), bytes.into());
    }
    assert!(full_scan(&corrupt, root).is_err());
    // The same tree under another tree identity is refused.
    let mut other = root;
    other.tree = [9; 16];
    assert!(full_scan(&source, other).is_err());
    // Aggregates are the reference's claim, checked against the page.
    let mut miscounted = root;
    miscounted.root.as_mut().unwrap().count += 1;
    assert!(full_scan(&source, miscounted).is_err());
    let mut wrong_level = root;
    wrong_level.root.as_mut().unwrap().level += 1;
    assert!(full_scan(&source, wrong_level).is_err());
    // A missing page is an error, never an empty subtree.
    let missing = source.pinned();
    missing.rows.lock().remove(&page_key);
    assert!(full_scan(&missing, root).is_err());
    assert!(TreeRoot::decode(&root.encode()).unwrap() == root);
    let mut encoded = root.encode();
    encoded[16] = 2;
    assert!(TreeRoot::decode(&encoded).is_err());
    let json = serde_json::to_string(&root).unwrap();
    assert_eq!(serde_json::from_str::<TreeRoot>(&json).unwrap(), root);
    assert!(serde_json::from_str::<TreeRoot>(&json.to_uppercase()).is_err());
}

#[test]
fn cache_residency_stays_within_budget_and_preloads_what_fits() {
    let mut rng = Rng(11);
    let source = MemorySource::new();
    let mut model = Model::new();
    let batch: Vec<_> = (0..6000).map(|n| (key(n), Some(vec![5; 150]))).collect();
    let mut root = TreeRoot::new_tree();
    for chunk in batch.chunks(256) {
        root = apply_batch(&source, &root, &mut model, chunk);
    }
    let pages = TreeReader::new(&source, SPACE, root, None)
        .unwrap()
        .verify()
        .unwrap();
    let page_rows: u64 = source
        .rows
        .lock()
        .values()
        .map(|row| row.len() as u64 + 4 * MAX_PAGE_ENTRIES as u64 + PAGE_OVERHEAD)
        .sum();
    // Everything fits: preload warms every page and later reads only hit.
    let roomy = PageCache::new(source.memory(), page_rows * 2);
    let reader = TreeReader::new(&source, SPACE, root, Some(&roomy)).unwrap();
    assert!(reader.preload().unwrap());
    assert_eq!(roomy.stats().pages as u64, pages);
    let misses = roomy.stats().misses;
    check_reads_cached(&reader, &model, &mut rng);
    assert_eq!(roomy.stats().misses, misses);
    drop(reader);
    // A dataset several times the budget: preload stops, reads stay correct,
    // and charged and leased credit never exceed the budget.
    let budget = page_rows / 5;
    let small = PageCache::new(source.memory(), budget);
    let reader = TreeReader::new(&source, SPACE, root, Some(&small)).unwrap();
    assert!(!reader.preload().unwrap());
    for _ in 0..3 {
        check_reads_cached(&reader, &model, &mut rng);
        let stats = small.stats();
        assert!(
            stats.charged <= budget && stats.leased <= budget,
            "{stats:?}"
        );
        assert!(stats.pages > 0 && (stats.pages as u64) < pages);
    }
    // Shrinking returns credit immediately.
    small.set_budget(budget / 4);
    let stats = small.stats();
    assert!(stats.charged <= budget / 4 && stats.leased <= budget / 4);
    drop(reader);
    // Edits keep working with readers of the old root using the cache.
    let probe = key(17);
    root = apply_batch(&source, &root, &mut model, &[(probe.clone(), None)]);
    let reader = TreeReader::new(&source, SPACE, root, Some(&small)).unwrap();
    check_reads_cached(&reader, &model, &mut rng);
}

fn check_reads_cached(reader: &TreeReader<'_>, model: &Model, rng: &mut Rng) {
    let (all, _) = reader
        .page(Bound::Unbounded, Direction::Forward, usize::MAX)
        .unwrap();
    assert_eq!(
        all,
        expected_range(model, Bound::Unbounded, Direction::Forward)
    );
    let mut out = Vec::new();
    for _ in 0..50 {
        let probe = key(rng.below(7000));
        let found = reader.get(&probe, &mut out).unwrap();
        assert_eq!(found.then(|| out.clone()), model.get(&probe).cloned());
    }
}

#[test]
fn cache_refused_by_admission_serves_through_bounded_reads() {
    let source = MemorySource::new();
    let mut model = Model::new();
    let batch: Vec<_> = (0..30_000).map(|n| (key(n), Some(vec![5; 150]))).collect();
    let mut root = TreeRoot::new_tree();
    for chunk in batch.chunks(256) {
        root = apply_batch(&source, &root, &mut model, chunk);
    }
    // Node-wide optional cache headroom is far below the cache's own budget.
    let tight = TestDiskMemory::new(4 << 20, 64);
    let cache = PageCache::new(tight, 64 << 20);
    let reader = TreeReader::new(&source, SPACE, root, Some(&cache)).unwrap();
    let (all, _) = reader
        .page(Bound::Unbounded, Direction::Forward, usize::MAX)
        .unwrap();
    assert_eq!(
        all,
        expected_range(&model, Bound::Unbounded, Direction::Forward)
    );
    let stats = cache.stats();
    assert!(stats.refusals > 0, "{stats:?}");
    assert!(stats.leased < 4 << 20, "{stats:?}");
}

// ---- Store-backed page spaces ----

fn scratch() -> (tempfile::TempDir, Arc<ScratchDisk>) {
    let directory = crate::test_utils::private_tempdir().unwrap();
    let memory = TestDiskMemory::new(1 << 30, 4096);
    let scratch = ScratchDisk::fixture(directory.path(), memory);
    (directory, scratch)
}

async fn pair(
    disk: FaultBackend,
    scratch: Arc<ScratchDisk>,
    create: bool,
) -> Arc<TenantStorageSet> {
    let node = if create {
        NodeStore::create_with_backend(disk, crate::test_utils::storage_admission(), scratch)
    } else {
        NodeStore::open_with_backend(disk, crate::test_utils::storage_admission(), scratch)
    }
    .expect("fixture node");
    let mut stores = Vec::new();
    for (tenant, seed) in [
        ("tenant".to_owned(), 11),
        (CustodyStore::catalog_name("tenant"), 12),
    ] {
        let provider = Arc::new(LocalKeyProvider::new([seed; 32]));
        let clock = Arc::new(ManualClock::new());
        stores.push(
            if create {
                TenantStore::initialize_catalog_fixture_with_clock(
                    node.clone(),
                    tenant,
                    provider,
                    clock,
                )
                .await
            } else {
                TenantStore::open_existing_fixture_with_clock(node.clone(), tenant, provider, clock)
                    .await
            }
            .unwrap(),
        );
    }
    TenantStorageSet::install(stores.remove(0), stores.remove(0)).unwrap()
}

const ROOTS: &str = "test.roots";
const FAMILY: &str = PAGE_FAMILY;

/// Publish an edit's writes with the root that names them and an applied
/// position, in one paired native transaction.
fn publish(stores: &TenantStorageSet, edit: &TreeEdit, position: u64) -> Result<()> {
    let mut writes = edit.writes().to_vec();
    writes.push(WriteOp::put(ROOTS, b"current", edit.root.encode()));
    stores.write_batch(
        &writes,
        &[WriteOp::put("position", b"applied", position.to_be_bytes())],
    )
}

fn current_root(view: &TenantReadView) -> Result<Option<TreeRoot>> {
    view.get(ROOTS, b"current", TREE_ROOT_BYTES)?
        .map(|bytes| TreeRoot::decode(bytes.as_bytes()))
        .transpose()
}

fn store_edits(
    root: &TreeRoot,
    store: &TenantStore,
    batch: &[(Vec<u8>, Option<Vec<u8>>)],
) -> Result<TreeEdit> {
    let edits: Vec<Edit<'_>> = batch
        .iter()
        .map(|(key, value)| match value {
            Some(value) => Edit::Put(key, value),
            None => Edit::Delete(key),
        })
        .collect();
    edit_tree(store, SPACE, root, &edits)
}

fn read_all(view: &TenantReadView, space: &str, root: TreeRoot) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let reader = TreeReader::new(view, space, root, None)?;
    Ok(reader
        .page(Bound::Unbounded, Direction::Forward, usize::MAX)?
        .0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_edits_publish_atomically_and_pinned_views_keep_older_roots() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch, true).await;
    let store = stores.application();
    let mut rng = Rng(21);
    let mut model = Model::new();
    let mut root = TreeRoot::new_tree();
    let mut pins = Vec::new();
    for round in 0..12u64 {
        let batch = random_batch(&mut rng, &model, 1500, 256);
        let edit = store_edits(&root, store, &batch)?;
        assert!(edit.put_bytes() < MAX_BATCH as u64);
        publish(&stores, &edit, round)?;
        for (key, value) in &batch {
            match value {
                Some(value) => model.insert(key.clone(), value.clone()),
                None => model.remove(key),
            };
        }
        root = edit.root;
        let view = store.read_view()?;
        assert_eq!(current_root(&view)?, Some(root));
        assert_eq!(
            read_all(&view, SPACE, root)?,
            expected_range(&model, Bound::Unbounded, Direction::Forward)
        );
        pins.push((view, root, model.clone()));
    }
    // Every pinned view still reads its own root after later edits deleted
    // the pages it uses.
    for (view, root, model) in pins {
        assert_eq!(
            read_all(&view, SPACE, root)?,
            expected_range(&model, Bound::Unbounded, Direction::Forward)
        );
        view.close()?;
    }
    // Only the current root's rows remain in the space.
    let view = store.read_view()?;
    let mut rows = 0u64;
    view.visit(SPACE, OVERFLOW_CHUNK_BYTES, |_, _| {
        rows += 1;
        Ok(())
    })?;
    let pages = TreeReader::new(&view, SPACE, root, None)?.verify()?;
    assert!(rows >= pages);
    let chunks: u64 = model
        .values()
        .filter(|value| value.len() > MAX_INLINE_VALUE)
        .map(|value| value.len().div_ceil(OVERFLOW_CHUNK_BYTES) as u64)
        .sum();
    assert_eq!(rows, pages + chunks);
    view.close()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_crash_cut_of_an_edit_keeps_the_old_or_the_new_root() -> Result<()> {
    let (_directory, scratch) = scratch();
    let original = FaultBackend::new();
    let stores = pair(original.clone(), scratch.clone(), true).await;
    let mut rng = Rng(8);
    let mut model = Model::new();
    let batch = random_batch(&mut rng, &model, 800, 256);
    let edit = store_edits(&TreeRoot::new_tree(), stores.application(), &batch)?;
    publish(&stores, &edit, 1)?;
    let old_root = edit.root;
    for (key, value) in &batch {
        if let Some(value) = value {
            model.insert(key.clone(), value.clone());
        }
    }
    let old_model = model.clone();
    let next = random_batch(&mut rng, &model, 800, 200);
    let mut new_model = model.clone();
    for (key, value) in &next {
        match value {
            Some(value) => new_model.insert(key.clone(), value.clone()),
            None => new_model.remove(key),
        };
    }
    let starting = original.crash();
    let measurement = starting.crash();
    let measured = pair(measurement.clone(), scratch.clone(), false).await;
    let start = measurement.operations();
    let edit = store_edits(&old_root, measured.application(), &next)?;
    publish(&measured, &edit, 2)?;
    let mutations = measurement.operations() - start;
    let (mut old, mut new) = (0, 0);
    for cut in 0..=mutations {
        let disk = starting.crash();
        let stores = pair(disk.clone(), scratch.clone(), false).await;
        disk.fail_after(cut);
        let result = store_edits(&old_root, stores.application(), &next)
            .and_then(|edit| publish(&stores, &edit, 2));
        let crashed = disk.crash();
        disk.disarm();
        let reopened = pair(crashed, scratch.clone(), false).await;
        let view = reopened.application().read_view()?;
        let root = current_root(&view)?.unwrap();
        let entries = read_all(&view, SPACE, root)?;
        let position = reopened.read_view()?;
        let applied = position.custody_get("position", b"applied", 8)?.unwrap();
        if root == old_root {
            old += 1;
            assert!(result.is_err(), "acknowledged edit lost at cut {cut}");
            assert_eq!(
                entries,
                expected_range(&old_model, Bound::Unbounded, Direction::Forward)
            );
            assert_eq!(applied.as_bytes(), 1u64.to_be_bytes());
        } else {
            new += 1;
            assert_eq!(
                entries,
                expected_range(&new_model, Bound::Unbounded, Direction::Forward)
            );
            assert_eq!(applied.as_bytes(), 2u64.to_be_bytes());
        }
        drop(applied);
        position.close()?;
        view.close()?;
    }
    assert!(old > 0 && new > 0);
    Ok(())
}

/// Stage a bulk-built tree of `entries` rows in a fresh page space.
fn stage(
    store: &Arc<TenantStore>,
    entries: u64,
    size: usize,
) -> Result<(NamespaceStage, TreeRoot)> {
    let stage = NamespaceStage::begin_generation(store, SPACE)?;
    let root = stage_tree(&stage, TreeRoot::new_tree().tree, |builder| {
        for n in 0..entries {
            builder.push(&key(n), &vec![(n % 251) as u8; size])?;
        }
        Ok(())
    })?;
    Ok((stage, root))
}

fn select_staged(
    stores: &TenantStorageSet,
    generation: &SelectedGeneration,
    stage: &NamespaceStage,
    root: &TreeRoot,
) -> Result<()> {
    let store = stores.application();
    let mut writes = generation.switch_writes(store, &[stage])?;
    let manifest = ApplicationManifest::new(
        store.tenant(),
        "incarnation",
        2,
        0,
        stage.namespace(),
        *root,
        root.count(),
        root.bytes(),
    );
    writes.push(manifest.write()?);
    writes.push(WriteOp::put(ROOTS, b"current", root.encode()));
    stores.write_batch(&writes, &[WriteOp::put("position", b"applied", b"staged")])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bulk_staged_tree_larger_than_a_native_transaction_selects_with_fixed_writes()
-> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch.clone(), true).await;
    let store = stores.application();
    // The incremental history lives in the family's initial space.
    let mut model = Model::new();
    let batch: Vec<_> = (0..300).map(|n| (key(n), Some(vec![1; 100]))).collect();
    let edit = store_edits(&TreeRoot::new_tree(), store, &batch)?;
    publish(&stores, &edit, 1)?;
    for (key, value) in batch {
        model.insert(key, value.unwrap());
    }
    let generation = SelectedGeneration::adopt(store, FAMILY, &[SPACE])?;
    let pinned = store.read_view()?;
    assert!(ApplicationManifest::load_at(&pinned)?.is_none());
    let entries = 400u64;
    let size = 256 << 10; // overflow values: 100 MiB in all
    let (stage, root) = stage(store, entries, size)?;
    assert!(entries as usize * size > kasumi_kv::MAX_BATCH_BYTES);
    select_staged(&stores, &generation, &stage, &root)?;
    NamespaceStage::reclaim_unselected(store)?;
    let view = store.read_view()?;
    let selected = SelectedGeneration::load_at(&view, FAMILY, &[SPACE])?;
    assert_eq!(selected.namespace(0), stage.namespace());
    let reader = TreeReader::new(
        &view,
        selected.namespace(0),
        current_root(&view)?.unwrap(),
        None,
    )?;
    let mut count = 0u64;
    let mut value = Vec::new();
    reader.scan(
        Bound::Unbounded,
        Direction::Forward,
        &mut |found, stored| {
            assert_eq!(found, key(count).as_slice());
            reader.read_value(&stored, &mut value)?;
            assert_eq!(value, vec![(count % 251) as u8; size]);
            count += 1;
            Ok(true)
        },
    )?;
    assert_eq!(count, entries);
    drop(reader);
    view.close()?;
    // The replaced space is reclaimed; its pinned reader still reads it.
    let mut left = 0;
    store.visit(SPACE, MAX_PAGE_BYTES, |_, _| {
        left += 1;
        Ok(())
    })?;
    assert_eq!(left, 0);
    assert_eq!(
        read_all(&pinned, SPACE, edit.root)?,
        expected_range(&model, Bound::Unbounded, Direction::Forward)
    );
    pinned.close()?;
    // Incremental edits continue in the selected space.
    let space = stage.namespace().to_owned();
    let edits = [Edit::Delete(&key(0)[..]), Edit::Put(b"zzz", b"tail")];
    let edit = edit_tree(store.as_ref(), &space, &root, &edits)?;
    let mut writes = edit.writes().to_vec();
    writes.push(WriteOp::put(ROOTS, b"current", edit.root.encode()));
    stores.write_batch(&writes, &[])?;
    let view = store.read_view()?;
    let reader = TreeReader::new(&view, &space, edit.root, None)?;
    assert_eq!(reader.root().count(), entries);
    assert!(!reader.get(&key(0), &mut value)?);
    assert!(reader.get(b"zzz", &mut value)?);
    drop(reader);
    view.close()?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sampled_crash_cuts_of_a_staged_tree_selection_keeps_one_complete_tree() -> Result<()> {
    let (_directory, scratch) = scratch();
    let original = FaultBackend::new();
    let stores = pair(original.clone(), scratch.clone(), true).await;
    let store = stores.application();
    let batch: Vec<_> = (0..50).map(|n| (key(n), Some(vec![2; 40]))).collect();
    let edit = store_edits(&TreeRoot::new_tree(), store, &batch)?;
    publish(&stores, &edit, 1)?;
    let old_root = edit.root;
    let starting = original.crash();
    let run = |stores: &TenantStorageSet| -> Result<()> {
        let store = stores.application();
        let generation = SelectedGeneration::adopt(store, FAMILY, &[SPACE])?;
        let (stage, root) = stage(store, 400, 3000)?;
        select_staged(stores, &generation, &stage, &root)?;
        NamespaceStage::reclaim_unselected(store)
    };
    let measurement = starting.crash();
    let measured = pair(measurement.clone(), scratch.clone(), false).await;
    let start = measurement.operations();
    run(&measured)?;
    let mutations = measurement.operations() - start;
    let (mut old, mut new) = (0, 0);
    for cut in (0..mutations)
        .step_by((mutations / 40).max(1))
        .chain([mutations])
    {
        let disk = starting.crash();
        let stores = pair(disk.clone(), scratch.clone(), false).await;
        disk.fail_after(cut);
        let result = run(&stores);
        let crashed = disk.crash();
        disk.disarm();
        let reopened = pair(crashed, scratch.clone(), false).await;
        let store = reopened.application();
        NamespaceStage::reclaim_unselected(store)?;
        let view = store.read_view()?;
        let root = current_root(&view)?.unwrap();
        let selected = SelectedGeneration::load_at(&view, FAMILY, &[SPACE])?;
        let entries = read_all(&view, selected.namespace(0), root)?;
        let manifest = ApplicationManifest::load_at(&view)?;
        if root == old_root {
            old += 1;
            assert!(manifest.is_none());
            assert_eq!(selected.namespace(0), INITIAL_PAGE_SPACE[0]);
            assert_eq!(entries.len(), 50, "old tree torn at cut {cut}");
        } else {
            new += 1;
            assert!(result.is_ok() || cut < mutations);
            assert_eq!(manifest.context("missing selected manifest")?.records, root);
            assert_eq!(entries.len(), 400, "new tree torn at cut {cut}");
            let mut left = 0;
            store.visit(SPACE, MAX_PAGE_BYTES, |_, _| {
                left += 1;
                Ok(())
            })?;
            assert_eq!(left, 0, "retired space leaked at cut {cut}");
        }
        view.close()?;
    }
    assert!(old > 0 && new > 0);
    Ok(())
}

fn space_rows(store: &TenantStore, space: &str) -> Result<u64> {
    let mut rows = 0;
    store.visit(space, OVERFLOW_CHUNK_BYTES, |_, _| {
        rows += 1;
        Ok(())
    })?;
    Ok(rows)
}

/// Pages plus overflow chunks reachable from `root`.
fn reachable_rows(view: &TenantReadView, space: &str, root: TreeRoot) -> Result<u64> {
    let reader = TreeReader::new(view, space, root, None)?;
    let mut rows = reader.verify()?;
    reader.scan(Bound::Unbounded, Direction::Forward, &mut |_, value| {
        if let ValueRef::Overflow(overflow) = value {
            rows += u64::from(overflow.chunks());
        }
        Ok(true)
    })?;
    Ok(rows)
}

fn large_batch(rng: &mut Rng, universe: u64) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let mut batch = BTreeMap::new();
    while batch.len() < 256 {
        let size = 500 + rng.below(30_000) as usize;
        batch.insert(key(rng.below(universe)), Some(vec![rng.next() as u8; size]));
    }
    batch.into_iter().collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_staged_edit_publishes_only_deletions() -> Result<()> {
    let (_directory, scratch) = scratch();
    let stores = pair(FaultBackend::new(), scratch, true).await;
    let store = stores.application();
    let mut rng = Rng(31);
    let mut model = Model::new();
    let mut root = TreeRoot::new_tree();
    for round in 0..4u64 {
        let batch = large_batch(&mut rng, 4000);
        let edits: Vec<Edit<'_>> = batch
            .iter()
            .map(|(key, value)| Edit::Put(key, value.as_deref().unwrap()))
            .collect();
        let edit = edit_tree_staged(store, SPACE, &root, &edits)?;
        assert!(edit.staged_batches() > 0);
        assert_eq!(edit.put_bytes(), 0);
        assert!(
            edit.writes()
                .iter()
                .all(|write| matches!(write, WriteOp::Delete { .. }))
        );
        let mut writes = edit.writes().to_vec();
        writes.push(WriteOp::put(ROOTS, b"current", edit.root.encode()));
        stores.write_batch(
            &writes,
            &[WriteOp::put("position", b"applied", round.to_be_bytes())],
        )?;
        for (key, value) in batch {
            model.insert(key, value.unwrap());
        }
        root = edit.root;
        assert_eq!(space_rows(store, EDIT_JOURNAL)?, 0);
        let view = store.read_view()?;
        assert_eq!(
            space_rows(store, SPACE)?,
            reachable_rows(&view, SPACE, root)?
        );
        assert_eq!(
            read_all(&view, SPACE, root)?,
            expected_range(&model, Bound::Unbounded, Direction::Forward)
        );
        view.close()?;
    }
    // A small staged edit needs no journal at all.
    let edit = edit_tree_staged(store, SPACE, &root, &[Edit::Put(b"small", b"value")])?;
    assert_eq!(edit.staged_batches(), 0);
    assert!(edit.put_bytes() > 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sampled_crash_cuts_of_a_staged_edit_recover_old_or_new_without_leaks() -> Result<()> {
    let (_directory, scratch) = scratch();
    let original = FaultBackend::new();
    let stores = pair(original.clone(), scratch.clone(), true).await;
    let mut rng = Rng(41);
    let first = large_batch(&mut rng, 3000);
    let edit = store_edits(&TreeRoot::new_tree(), stores.application(), &first)?;
    publish(&stores, &edit, 1)?;
    let old_root = edit.root;
    let next = large_batch(&mut rng, 3000);
    let starting = original.crash();
    let run = |stores: &TenantStorageSet| -> Result<()> {
        let store = stores.application();
        recover_abandoned_edits(store)?;
        let edits: Vec<Edit<'_>> = next
            .iter()
            .map(|(key, value)| Edit::Put(key, value.as_deref().unwrap()))
            .collect();
        let edit = edit_tree_staged(store, SPACE, &old_root, &edits)?;
        publish(stores, &edit, 2)
    };
    let measurement = starting.crash();
    let measured = pair(measurement.clone(), scratch.clone(), false).await;
    let start = measurement.operations();
    run(&measured)?;
    let mutations = measurement.operations() - start;
    let (mut old, mut new) = (0, 0);
    for cut in (0..mutations)
        .step_by((mutations / 40).max(1))
        .chain([mutations])
    {
        let disk = starting.crash();
        let stores = pair(disk.clone(), scratch.clone(), false).await;
        disk.fail_after(cut);
        let result = run(&stores);
        let crashed = disk.crash();
        disk.disarm();
        let reopened = pair(crashed, scratch.clone(), false).await;
        let store = reopened.application();
        recover_abandoned_edits(store)?;
        assert_eq!(space_rows(store, EDIT_JOURNAL)?, 0);
        let view = store.read_view()?;
        let root = current_root(&view)?.unwrap();
        if root == old_root {
            old += 1;
            assert!(result.is_err(), "acknowledged edit lost at cut {cut}");
        } else {
            new += 1;
        }
        assert_eq!(
            space_rows(store, SPACE)?,
            reachable_rows(&view, SPACE, root)?,
            "rows leaked at cut {cut}"
        );
        view.close()?;
    }
    assert!(old > 0 && new > 0);
    Ok(())
}
