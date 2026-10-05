// Fixture pages and input names are outside the native admission ledger.
use super::*;
use crate::directory::DirectoryReadWorkspace;

fn commit_tree(backend: &Pages, count: usize) -> (crate::directory::DirectoryRoot, Vec<String>) {
    let names: Vec<_> = (0..count)
        .map(|index| {
            let mut name = format!("t{index:04}");
            name.push_str(&"x".repeat(crate::core::MAX_TABLE_BYTES - name.len()));
            name
        })
        .collect();
    let mut builder = DirectoryBuilder::new(backend, Admission::new(u64::MAX), GROUP, 1).unwrap();
    for name in &names {
        builder
            .push(
                DirectoryKey::table(name),
                DirectoryValue::Table { birth_seq: 1 },
            )
            .unwrap();
    }
    (builder.finish().unwrap(), names)
}

#[test]
fn commit_warm_stops_before_refused_page_io_independently_of_tree_size() {
    for count in [17, 129] {
        for provider_pressure in [false, true] {
            let backend = Pages::default();
            let (root, _) = commit_tree(&backend, count);
            assert!(root.height > 1);
            let admission = Admission::new(u64::MAX);
            let cached = CachedDirectoryBackend::new(
                &backend,
                admission.clone(),
                GROUP,
                CacheConfig {
                    byte_limit: 4 << 20,
                },
            );
            let owner: Arc<dyn StorageAdmission> = admission.clone();
            let mut workspace = DirectoryReadWorkspace::new(&owner).unwrap();
            let warming = cached.commit_warm_view();
            let mut out = [0; DIRECTORY_PAGE_BYTES];
            warming.read_page(root.page.unwrap(), &mut out).unwrap();
            let stats = cached.stats().unwrap();
            // Remove spare credit. The already resident root fits exactly;
            // the first child must need an additional cache reservation.
            cached
                .configure(CacheConfig {
                    byte_limit: stats.allocated_bytes + stats.provider_overhead_bytes,
                })
                .unwrap();
            if provider_pressure {
                cached
                    .configure(CacheConfig {
                        byte_limit: 4 << 20,
                    })
                    .unwrap();
                admission
                    .limit
                    .store(admission.used.load(Ordering::Acquire), Ordering::Release);
            }
            let before = cached.stats().unwrap();
            let reads = backend.reads.load(Ordering::Acquire);
            assert!(
                matches!(&(DirectoryReader::new(&warming, owner).warm_generation_with_workspace(
                    root,
                    root.generation,
                    &mut workspace,
                )), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
            );
            assert_eq!(
                backend.reads.load(Ordering::Acquire),
                reads,
                "optional traversal read a refused page: {count} tables, provider pressure {provider_pressure}"
            );
            assert_eq!(cached.stats().unwrap(), before);
            assert!(admission.check_owner().is_ok());
            drop(workspace);
            drop(cached);
            assert_eq!(admission.used.load(Ordering::Acquire), 0);
        }
    }
}

#[test]
fn commit_warm_retains_the_complete_fitting_tree_without_policy_training() {
    let backend = Pages::default();
    let (root, names) = commit_tree(&backend, 129);
    let admission = Admission::new(u64::MAX);
    let cached = CachedDirectoryBackend::new(
        &backend,
        admission.clone(),
        GROUP,
        CacheConfig {
            byte_limit: 4 << 20,
        },
    );
    let warming = cached.commit_warm_view();
    DirectoryReader::new(&warming, admission.clone())
        .warm_generation(root, 1)
        .unwrap();
    let pages = backend.pages.lock().unwrap().len();
    assert!(pages > 2);
    assert_eq!(backend.reads.load(Ordering::Acquire), pages);
    let stats = cached.stats().unwrap();
    assert_eq!(stats.entries, pages);
    assert_eq!(
        (
            stats.hits,
            stats.misses,
            stats.loads,
            stats.uncached_loads,
            stats.evictions
        ),
        (0, 0, 0, 0, 0)
    );
    DirectoryReader::new(&warming, admission.clone())
        .warm_generation(root, 1)
        .unwrap();
    let reader = DirectoryReader::new(&cached, admission.clone());
    for name in names {
        assert_eq!(
            reader.get(root, DirectoryKey::table(&name)).unwrap(),
            Some(DirectoryValue::Table { birth_seq: 1 })
        );
    }
    assert_eq!(backend.reads.load(Ordering::Acquire), pages);
    assert_eq!(cached.stats().unwrap().evictions, 0);
    drop(cached);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn commit_warm_propagates_corruption_and_owner_expiry_without_installing_pages() {
    let backend = Pages::default();
    let page = backend.append_page(&[3; DIRECTORY_PAGE_BYTES]).unwrap();
    let admission = Admission::new(u64::MAX);
    let cached = CachedDirectoryBackend::new(
        &backend,
        admission.clone(),
        GROUP,
        CacheConfig {
            byte_limit: 1 << 20,
        },
    );
    let warming = cached.commit_warm_view();
    let mut out = [0; DIRECTORY_PAGE_BYTES];
    let mut wrong = page;
    wrong.sha256[0] ^= 1;
    assert!(
        matches!(&(warming.read_page(wrong, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
    );
    assert_eq!(cached.stats().unwrap().entries, 0);
    *backend.expire_on_read.lock().unwrap() = Some(admission.clone());
    assert!(
        matches!(&(warming.read_page(page, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert_eq!(cached.cache.lock().unwrap().stats().entries, 0);
    let reads = backend.reads.load(Ordering::Acquire);
    assert!(
        matches!(&(warming.read_page(page, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert_eq!(backend.reads.load(Ordering::Acquire), reads);
    drop(cached);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}
