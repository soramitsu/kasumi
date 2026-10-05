use super::*;
use crate::directory::DirectoryReadWorkspace;

// The first two tests preclaim the real directory workspace, then reject and
// count every further workspace request. Optional cache credit remains real.
struct PreparedWorkspaceAdmission {
    inner: Arc<Admission>,
    armed: AtomicBool,
    attempts: AtomicUsize,
}
impl PreparedWorkspaceAdmission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Admission::new(u64::MAX),
            armed: AtomicBool::new(false),
            attempts: AtomicUsize::new(0),
        })
    }
}
impl StorageAdmission for PreparedWorkspaceAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.inner.check_owner()
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        if self.armed.load(Ordering::Acquire) {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        self.inner.reserve_workspace(bytes)
    }
    fn quote_cache_memory(&self, bytes: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        self.inner.quote_cache_memory(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        self.inner.clone().reserve_cache_memory(bytes)
    }
    fn reserve_growth(&self, segment: u64, bytes: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(segment, bytes)
    }
    fn settle_growth(&self, segment: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(segment)
    }
    fn owner_failed(&self) {
        self.inner.owner_failed();
    }
}

fn row(id: u64) -> DirectoryValue {
    DirectoryValue::Row {
        batch_seq: 1,
        value: ValueLocation {
            segment_id: 1,
            offset: 256 + id * 8,
            len: 8,
            crc: id as u32,
        },
    }
}

#[test]
fn prepared_directory_read_into_refused_retention_never_requests_temporary_workspace() {
    for (cache_limit, deny_provider) in [(0, false), (1, false), (1 << 20, true)] {
        let provider = PreparedWorkspaceAdmission::new();
        let admission: Arc<dyn StorageAdmission> = provider.clone();
        let pages = Pages::default();
        let mut builder = DirectoryBuilder::new(&pages, admission.clone(), GROUP, 1).unwrap();
        builder
            .push(DirectoryKey::row("accounts", b"a"), row(0))
            .unwrap();
        let root = builder.finish().unwrap();
        let cache = CachedDirectoryBackend::new(
            &pages,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: cache_limit,
            },
        );
        let mut workspace = DirectoryReadWorkspace::new(&admission).unwrap();
        let baseline = provider.inner.used.load(Ordering::Acquire);
        assert!(baseline > 0, "actual workspace was not admitted");
        if deny_provider {
            provider.inner.limit.store(baseline, Ordering::Release);
        }
        provider.armed.store(true, Ordering::Release);
        let reader = DirectoryReader::new(&cache, admission);
        // Initialize platform first-lock control backing before observing the
        // prepared read. These two locks neither read a page nor train/retain
        // cache data; the first measured lookup must still be a cold miss.
        let before = cache.stats().unwrap();
        assert!(pages.expire_on_read.lock().unwrap().is_none());
        assert_eq!(before, CacheStats::default());
        assert_eq!(pages.reads.load(Ordering::Relaxed), 0);
        assert_eq!(provider.inner.used.load(Ordering::Acquire), baseline);
        let allocation = crate::snapshot_pins::allocation_tests::AllocationCount::start();
        for _ in 0..3 {
            assert_eq!(
                reader
                    .get_with_workspace(root, DirectoryKey::row("accounts", b"a"), &mut workspace)
                    .unwrap(),
                Some(row(0))
            );
        }
        let allocated = allocation.count();
        drop(allocation);
        assert_eq!(
            allocated, 0,
            "prepared direct reads allocated another owner: cache_limit={cache_limit} deny_provider={deny_provider}"
        );
        assert_eq!(provider.attempts.load(Ordering::Acquire), 0);
        let stats = cache.stats().unwrap();
        assert_eq!(
            (
                stats.hits,
                stats.misses,
                stats.loads,
                stats.uncached_loads,
                stats.entries
            ),
            (0, 3, 3, 3, 0)
        );
        assert_eq!(pages.reads.load(Ordering::Relaxed), 3);
        assert_eq!(provider.inner.used.load(Ordering::Acquire), baseline);
        drop(workspace);
        drop(cache);
        assert_eq!(provider.inner.used.load(Ordering::Acquire), 0);
    }
}

#[test]
fn prepared_directory_read_into_retains_all_fitting_pages_across_repeated_passes() {
    let provider = PreparedWorkspaceAdmission::new();
    let admission: Arc<dyn StorageAdmission> = provider.clone();
    let pages = Pages::default();
    let mut builder = DirectoryBuilder::new(&pages, admission.clone(), GROUP, 1).unwrap();
    for id in 0..600u64 {
        builder
            .push(DirectoryKey::row("accounts", &id.to_be_bytes()), row(id))
            .unwrap();
    }
    let root = builder.finish().unwrap();
    assert!(root.height > 1);
    let cache = CachedDirectoryBackend::new(
        &pages,
        admission.clone(),
        GROUP,
        CacheConfig {
            byte_limit: 1 << 20,
        },
    );
    let mut workspace = DirectoryReadWorkspace::new(&admission).unwrap();
    provider.armed.store(true, Ordering::Release);
    let reader = DirectoryReader::new(&cache, admission);
    for pass in 0..2 {
        let before = cache.stats().unwrap();
        let reads = pages.reads.load(Ordering::Relaxed);
        for id in 0..600u64 {
            assert_eq!(
                reader
                    .get_with_workspace(
                        root,
                        DirectoryKey::row("accounts", &id.to_be_bytes()),
                        &mut workspace
                    )
                    .unwrap(),
                Some(row(id))
            );
        }
        let after = cache.stats().unwrap();
        assert_eq!(after.entries, pages.pages.lock().unwrap().len());
        assert_eq!((after.uncached_loads, after.evictions), (0, 0));
        assert!(after.hits > before.hits);
        if pass == 1 {
            assert_eq!(pages.reads.load(Ordering::Relaxed), reads);
            assert_eq!((after.loads, after.misses), (before.loads, before.misses));
        }
    }
    assert_eq!(provider.attempts.load(Ordering::Acquire), 0);
    drop(workspace);
    drop(cache);
    assert_eq!(provider.inner.used.load(Ordering::Acquire), 0);
}

#[derive(Debug)]
struct OriginalReadFailure(Arc<()>);
impl std::fmt::Display for OriginalReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original directory read failure")
    }
}
impl std::error::Error for OriginalReadFailure {}

struct FailingPage {
    error: Mutex<Option<CoreError>>,
    calls: AtomicUsize,
}
impl DirectoryBackend for FailingPage {
    fn read_page(&self, _: DirectoryPageRef, _: &mut [u8]) -> Result<(), CoreError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Err(self
            .error
            .lock()
            .unwrap()
            .take()
            .expect("backend failure must not be retried"))
    }
    fn append_page(&self, _: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        panic!("read-only fixture")
    }
    fn sync_pages(&self) -> Result<(), CoreError> {
        panic!("read-only fixture")
    }
}

#[test]
fn directory_read_into_preserves_backend_original_and_capacity_without_retry() {
    for limit in [0, 1 << 20] {
        for capacity in [false, true] {
            let original = Arc::new(());
            let backend = FailingPage {
                error: Mutex::new(Some(if capacity {
                    CoreError::new(crate::CoreErrorCause::CapacityDenied)
                } else {
                    CoreError::new(crate::CoreErrorCause::Io(std::io::Error::other(
                        OriginalReadFailure(original.clone()),
                    )))
                })),
                calls: AtomicUsize::new(0),
            };
            let admission = Admission::new(u64::MAX);
            let cache = CachedDirectoryBackend::new(
                &backend,
                admission.clone(),
                GROUP,
                CacheConfig { byte_limit: limit },
            );
            let mut out = [0xc3; DIRECTORY_PAGE_BYTES];
            let error = cache.read_page(reference(0, 7), &mut out).unwrap_err();
            if capacity {
                assert!(matches!(
                    (error).rejected_cause(),
                    Some(crate::CoreErrorCause::CapacityDenied)
                ));
            } else {
                let error = error.io_error().expect("original I/O failure changed");
                let found = error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<OriginalReadFailure>()
                    .unwrap();
                assert!(Arc::ptr_eq(&original, &found.0));
            }
            assert_eq!(out, [0xc3; DIRECTORY_PAGE_BYTES]);
            assert_eq!(backend.calls.load(Ordering::Relaxed), 1);
            let stats = cache.stats().unwrap();
            assert_eq!(
                (stats.loads, stats.uncached_loads, stats.entries),
                (0, 0, 0)
            );
            drop(cache);
            assert_eq!(admission.used.load(Ordering::Acquire), 0);
        }
    }
}

#[test]
fn directory_read_into_rejects_corrupt_cached_identity_before_copy_or_io() {
    for wrong_length in [false, true] {
        let backend = Pages::default();
        let page = backend.append_page(&[4; DIRECTORY_PAGE_BYTES]).unwrap();
        let admission = Admission::new(u64::MAX);
        let cache = CachedDirectoryBackend::new(
            &backend,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 1 << 20,
            },
        );
        let identity = cache.identity(page).unwrap();
        // Test-only corruption of a real cached owner for the exact physical
        // identity. No backend bytes or selected root are substituted.
        drop(
            cache
                .lock()
                .unwrap()
                .load(
                    identity,
                    if wrong_length {
                        DIRECTORY_PAGE_BYTES - 1
                    } else {
                        DIRECTORY_PAGE_BYTES
                    },
                    |bytes| {
                        bytes.fill(9);
                        Ok::<_, CoreError>(())
                    },
                )
                .unwrap(),
        );
        let mut out = [0xc3; DIRECTORY_PAGE_BYTES];
        assert!(
            matches!(&(cache.read_page(page, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt("cached directory page identity differs"))))
        );
        assert_eq!(out, [0xc3; DIRECTORY_PAGE_BYTES]);
        assert_eq!(backend.reads.load(Ordering::Relaxed), 0);
        drop(cache);
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }
}

#[test]
fn directory_read_into_checks_owner_on_real_hits_and_never_retrains_invalid_input() {
    let backend = Pages::default();
    let page = backend.append_page(&[4; DIRECTORY_PAGE_BYTES]).unwrap();
    let admission = Admission::new(u64::MAX);
    let cache = CachedDirectoryBackend::new(
        &backend,
        admission.clone(),
        GROUP,
        CacheConfig {
            byte_limit: 1 << 20,
        },
    );
    let mut out = [0; DIRECTORY_PAGE_BYTES];
    cache.read_page(page, &mut out).unwrap();
    let before = cache.stats().unwrap();
    let reads = backend.reads.load(Ordering::Relaxed);
    out.fill(0xc3);
    assert!(
        matches!(&(cache.read_page(page, &mut out[..8])), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(
            "directory page output length differs"
        ))))
    );
    assert!(matches!(&(cache.read_page(
            DirectoryPageRef {
                arena_id: 0,
                ..page
            },
            &mut out
        )), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt("directory page reference is invalid")))));
    admission.failed.store(true, Ordering::Release);
    assert!(
        matches!(&(cache.read_page(page, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert_eq!(out, [0xc3; DIRECTORY_PAGE_BYTES]);
    assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
    assert_eq!(cache.lock().unwrap().stats(), before);
    drop(cache);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}
