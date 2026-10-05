// Include beneath disk_state::tests::compact so the bounded compaction
// helpers and the storage-read counter are available. This regression is
// intentionally separate from the preceding density evidence checkpoint.

use super::*;
use crate::directory::DirectoryPageRef;

fn residency_pages(state: &DiskState, root: DirectoryRoot) -> Vec<DirectoryPageRef> {
    let mut walker = DirectoryWalker::new(root, state.owner.admission.clone()).unwrap();
    let mut pages = Vec::new();
    loop {
        let progress = walker
            .step(
                state.arena.as_ref(),
                64,
                |reference| {
                    pages.push(reference);
                    Ok(())
                },
                |_| Ok(()),
            )
            .unwrap();
        if progress.complete {
            return pages;
        }
    }
}

fn page_identity(reference: DirectoryPageRef) -> NativeIdentity {
    NativeIdentity::Page {
        group_id: GROUP,
        arena_id: reference.arena_id,
        page_index: reference.page_index,
        sha256: reference.sha256,
    }
}

#[test]
fn obsolete_compaction_pages_cannot_displace_a_fitting_current_and_pinned_tree() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let mut state = create(reads.clone(), admission, LARGE_CACHE);
    // Test inputs and the in-memory disk stand-in are outside the native
    // admission ledger. No row values or value aliases can affect this budget.
    let tables: Vec<_> = (0..17)
        .map(|index| {
            let mut name = format!("t{index:02}");
            name.push_str(&"x".repeat(MAX_TABLE_BYTES - name.len()));
            name
        })
        .collect();
    let operations: Vec<_> = tables
        .iter()
        .map(|table| Operation::create_table(table.as_str()))
        .collect();
    state.commit(&operations).unwrap();
    assert!(warm_all(&mut state).fully_resident);
    let old = state.snapshot().unwrap();
    let old_pages = residency_pages(&state, old.root());
    assert_eq!(old_pages.len(), 3, "fixture needs two leaves and a root");
    let initial = state.cache_stats().unwrap();
    assert_eq!(initial.entries, 3);
    assert_eq!(initial.pinned_bytes, 0);
    assert_eq!(initial.evictions, 0);
    assert_eq!(initial.cached_bytes % 3, 0);
    let charged_page = initial.cached_bytes / 3;
    // Six identities fit in the existing sixteen-slot cache directory. Keep
    // all identity, Arc, payload-owner, allocation, and provider charges in
    // the bound, without spare aggregate credit.
    let config = CacheConfig {
        byte_limit: initial.metadata_bytes + 6 * charged_page + initial.provider_overhead_bytes,
    };
    state.configure_cache(config).unwrap();

    let rotation = state.compact_step(2).unwrap();
    assert_eq!(rotation.maintenance_commits, 0);
    let first = state.compact_step(1).unwrap();
    assert_eq!(first.maintenance_commits, 1);
    let intermediate = state.selected.page.unwrap();
    // Merely copy this physical reference: pinning its root would make the
    // intermediate page part of the required live working set.
    assert_ne!(intermediate.arena_id, old_pages[0].arena_id);
    assert_eq!(compact_all(&mut state).1, 0);
    let current = state.snapshot().unwrap();
    let current_pages = residency_pages(&state, current.root());
    assert_eq!(current_pages.len(), 3);
    assert_eq!(current.root().entries, old.root().entries);
    assert!(old_pages.iter().all(|page| !current_pages.contains(page)));
    assert!(!old_pages.contains(&intermediate));
    assert!(!current_pages.contains(&intermediate));

    // Whole-file GC cannot discard either arena: the old tree is pinned and
    // the new arena contains both the obsolete intermediate root and the
    // selected tree. Cache retirement must be finer than file reclamation.
    assert!(
        reads
            .group
            .exists(GroupFile::directory(old_pages[0].arena_id))
            .unwrap()
    );
    assert_eq!(intermediate.arena_id, current_pages[0].arena_id);
    assert!(
        reads
            .group
            .exists(GroupFile::directory(intermediate.arena_id))
            .unwrap()
    );
    let before_reads = state.cache_stats().unwrap();
    assert_eq!(before_reads.metadata_bytes, initial.metadata_bytes);
    assert_eq!(before_reads.pinned_bytes, 0);
    assert_eq!(before_reads.evictions, 0);
    assert!(before_reads.resident_bytes <= config.byte_limit);
    let live_union_bytes = before_reads.metadata_bytes
        + (old_pages.len() + current_pages.len()) as u64 * charged_page
        + before_reads.provider_overhead_bytes;
    assert_eq!(live_union_bytes, config.byte_limit);
    let obsolete_root_is_cached = state
        .cache
        .lock()
        .unwrap()
        .contains(page_identity(intermediate));

    let before = reads.count();
    for table in &tables {
        assert!(state.table_exists(&old, table).unwrap());
    }
    assert_eq!(
        reads.count(),
        before,
        "compaction displaced the pinned tree"
    );
    for table in &tables {
        assert!(state.table_exists(&current, table).unwrap());
    }
    assert_eq!(
        reads.count(),
        before,
        "the complete current+pinned page union fits exactly, but obsolete \
         maintenance identities blocked its residency; intermediate cached: \
         {obsolete_root_is_cached}; before reads: {before_reads:?}"
    );
}
