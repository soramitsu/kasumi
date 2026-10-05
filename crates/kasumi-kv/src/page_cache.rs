//! Owner-bound caching of immutable directory pages.
//!
//! One adapter belongs to one retained backend owner for its entire lifetime.
//! The application owner binds the exact tenant/database-incarnation strings;
//! neither a hash of those strings nor a root generation replaces that scope.
//! Within that owner, keys retain the complete group incarnation and page
//! reference. Unchanged COW pages therefore share one allocation across roots,
//! while a different arena, page address or digest cannot alias a hit.
//!
//! This cache only retains immutable bytes. Directory readers still validate
//! the selected root, page generation, digest and parent bounds on every hit.
//! Current authorization and key-access checks remain the enclosing reader's
//! responsibility. The physical owner is checked before hits and after loads.
//! Appends do not warm the cache. Mutators use the private view: existing
//! committed identities may hit, while misses never admit unpublished pages
//! or train admission policy. The normal view serves owner-selected published/
//! pinned roots, which a durable owner can warm by bounded reads.
//! Maintenance views do not train frequency/recency policy: private misses
//! bypass retention, while published pages are retained only in spare space.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(test)]
use crate::cache::CachedBytes;
use crate::cache::{CacheConfig, CacheLoadError, CacheStats, NativeCache};
use crate::core::{CoreError, StorageAdmission};
use crate::directory::{DIRECTORY_PAGE_BYTES, DirectoryBackend, DirectoryPageRef, page_digest};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) enum NativeIdentity {
    Page {
        group_id: [u8; 16],
        arena_id: u64,
        page_index: u64,
        sha256: [u8; 32],
    },
    Value {
        group_id: [u8; 16],
        segment_id: u64,
        offset: u64,
        len: u32,
        crc: u32,
        // Trusted directory/operation key lengths locate the exact key suffix
        // before the payload for bounded cache reachability checks.
        table_len: u16,
        key_len: u16,
    },
}

impl NativeIdentity {
    pub(crate) fn value(
        group_id: [u8; 16],
        value: crate::segment::ValueLocation,
        table: &str,
        key: &[u8],
    ) -> Result<Self, CoreError> {
        value.validate()?;
        if table.is_empty()
            || table.len() > crate::core::MAX_TABLE_BYTES
            || key.len() > crate::core::MAX_KEY_BYTES
        {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "cached value key bounds are invalid",
            )));
        }
        Ok(Self::Value {
            group_id,
            segment_id: value.segment_id,
            offset: value.offset,
            len: value.len,
            crc: value.crc,
            table_len: table.len() as u16,
            key_len: key.len() as u16,
        })
    }
}

pub(crate) type NativeSharedCache = Arc<Mutex<NativeCache<NativeIdentity>>>;

/// A cache and backend cannot be rebound to another owner. The retained owner
/// admits this inline adapter, backend, and shared cache holder (Arc/Mutex plus
/// allocation overhead) before construction. The cache's ledger covers
/// retained pages/values, complete-key slots, policy state and pinned versions.
/// Pages and values share one reclaimable budget rather than fixed partitions.
pub(crate) struct CachedDirectoryBackend<B: DirectoryBackend> {
    backend: B,
    admission: Arc<dyn StorageAdmission>,
    group_id: [u8; 16],
    cache: NativeSharedCache,
}

impl<B: DirectoryBackend> CachedDirectoryBackend<B> {
    pub(crate) fn new(
        backend: B,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        config: CacheConfig,
    ) -> Self {
        let cache = Arc::new(Mutex::new(NativeCache::new(config, admission.clone())));
        Self::with_shared_cache(backend, admission, group_id, cache)
    }

    /// The owner retains and admits the shared holder once. Neither this
    /// adapter nor value reads may give it a second independent byte limit.
    pub(crate) fn with_shared_cache(
        backend: B,
        admission: Arc<dyn StorageAdmission>,
        group_id: [u8; 16],
        cache: NativeSharedCache,
    ) -> Self {
        Self {
            backend,
            admission,
            group_id,
            cache,
        }
    }

    fn check_owner(&self) -> Result<(), CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))
    }

    fn lock(&self) -> Result<MutexGuard<'_, NativeCache<NativeIdentity>>, CoreError> {
        self.cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))
    }

    pub(crate) fn configure(&self, config: CacheConfig) -> Result<(), CoreError> {
        self.check_owner()?;
        self.lock()?.set_byte_limit(config.byte_limit)?;
        self.check_owner()
    }

    pub(crate) fn stats(&self) -> Result<CacheStats, CoreError> {
        self.check_owner()?;
        Ok(self.lock()?.stats())
    }

    /// Release lookup ownership. Existing returned pages keep their original
    /// admission until their last reader drops them, including after shutdown.
    pub(crate) fn clear(&self) -> Result<(), CoreError> {
        self.lock()?.clear();
        Ok(())
    }

    /// Borrow a COW view that can reuse committed hot pages without admitting
    /// a private page or recording a miss in cache admission policy.
    pub(crate) fn private_view(&self) -> PrivateDirectoryBackend<'_, B> {
        PrivateDirectoryBackend { cached: self }
    }

    /// Observe the actual COW paths for one active publication candidate
    /// scope. Cached identities are marked without policy training; private
    /// misses are read directly and never enter the retention pool.
    pub(crate) fn publication_private_view(&self) -> PublicationDirectoryBackend<'_, B> {
        PublicationDirectoryBackend { cached: self }
    }

    /// Reuse hot committed pages during maintenance without changing their
    /// policy rank or admitting any private page.
    pub(crate) fn maintenance_private_view(&self) -> MaintenanceDirectoryBackend<'_, B> {
        MaintenanceDirectoryBackend {
            cached: self,
            retain: false,
            retention_denied: None,
            stop_on_denial: false,
        }
    }

    /// Warm published maintenance pages when they fit, preserving the hot
    /// working set and its frequency/recency policy under memory pressure.
    pub(crate) fn maintenance_view(&self) -> MaintenanceDirectoryBackend<'_, B> {
        MaintenanceDirectoryBackend {
            cached: self,
            retain: true,
            retention_denied: None,
            stop_on_denial: false,
        }
    }

    /// Policy-neutral refill with an explicit signal for any page that could
    /// not remain resident. The caller resets the flag for each bounded step.
    pub(crate) fn refill_view<'a>(
        &'a self,
        retention_denied: &'a AtomicBool,
    ) -> MaintenanceDirectoryBackend<'a, B> {
        MaintenanceDirectoryBackend {
            cached: self,
            retain: true,
            retention_denied: Some(retention_denied),
            stop_on_denial: false,
        }
    }

    /// Optional commit traversal stops at the first page it cannot retain.
    /// Unlike a logical read, it has no reason to read that page into scratch
    /// and descend into a cold subtree after retention has already failed.
    /// Only CapacityDenied is suppressed by the commit caller; owner, digest
    /// and backend failures still propagate. Final-operation visibility reads
    /// use the ordinary maintenance view independently of this traversal.
    pub(crate) fn commit_warm_view(&self) -> MaintenanceDirectoryBackend<'_, B> {
        MaintenanceDirectoryBackend {
            cached: self,
            retain: true,
            retention_denied: None,
            stop_on_denial: true,
        }
    }

    fn identity(&self, reference: DirectoryPageRef) -> Result<NativeIdentity, CoreError> {
        if reference.arena_id == 0
            || reference.arena_id == u64::MAX
            || reference.page_index == u64::MAX
        {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "directory page reference is invalid",
            )));
        }
        Ok(NativeIdentity::Page {
            group_id: self.group_id,
            arena_id: reference.arena_id,
            page_index: reference.page_index,
            sha256: reference.sha256,
        })
    }

    fn read_verified(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
        self.check_owner()?;
        self.backend.read_page(reference, out)?;
        // A backend may fail/expire its retained owner while fulfilling I/O.
        // Never install or return those bytes under the earlier owner check.
        self.check_owner()?;
        if page_digest(out) != reference.sha256 {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "directory page digest differs",
            )));
        }
        Ok(())
    }

    fn read_private_page(
        &self,
        reference: DirectoryPageRef,
        out: &mut [u8],
        mark: bool,
    ) -> Result<(), CoreError> {
        self.check_owner()?;
        if out.len() != DIRECTORY_PAGE_BYTES {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "directory page output length differs",
            )));
        }
        let identity = self.identity(reference)?;
        let page = {
            let mut cache = self.lock()?;
            if mark {
                cache.mark_publication_candidate(identity)?;
            }
            cache.peek(identity)
        };
        if let Some(page) = page {
            self.check_owner()?;
            if page.as_bytes().len() != DIRECTORY_PAGE_BYTES
                || page_digest(page.as_bytes()) != reference.sha256
            {
                return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "cached directory page identity differs",
                )));
            }
            out.copy_from_slice(page.as_bytes());
            self.check_owner()
        } else {
            self.read_verified(reference, out)?;
            self.check_owner()
        }
    }

    /// Fixture-only shared-owner read for pin-retention/cache-policy tests.
    /// Production directory reads use the caller's admitted destination.
    /// Load one page with an admitted, shared lifetime. The returned guard
    /// represents bytes only, not permission to skip current owner/security
    /// checks when a caller later starts another operation with those bytes.
    #[cfg(test)]
    pub(crate) fn load_page(&self, reference: DirectoryPageRef) -> Result<CachedBytes, CoreError> {
        self.check_owner()?;
        let key = self.identity(reference)?;
        let value = self
            .lock()?
            .load(key, DIRECTORY_PAGE_BYTES, |out| {
                self.read_verified(reference, out)
            })
            .map_err(|error| match error {
                CacheLoadError::Admission(error) => CoreError::from(error),
                CacheLoadError::Load(error) => error,
            })?;
        self.check_owner()?;
        Ok(value)
    }
}

/// Read-through lookup of already-retained committed identities. This view
/// borrows its owner's fixed allocation and retains no additional backing.
pub(crate) struct PrivateDirectoryBackend<'a, B: DirectoryBackend> {
    cached: &'a CachedDirectoryBackend<B>,
}

impl<B: DirectoryBackend> DirectoryBackend for PrivateDirectoryBackend<'_, B> {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
        self.cached.read_private_page(reference, out, false)
    }

    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        self.cached.append_page(bytes)
    }

    fn sync_pages(&self) -> Result<(), CoreError> {
        self.cached.sync_pages()
    }
}

pub(crate) struct PublicationDirectoryBackend<'a, B: DirectoryBackend> {
    cached: &'a CachedDirectoryBackend<B>,
}

impl<B: DirectoryBackend> DirectoryBackend for PublicationDirectoryBackend<'_, B> {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
        self.cached.read_private_page(reference, out, true)
    }

    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        self.cached.append_page(bytes)
    }

    fn sync_pages(&self) -> Result<(), CoreError> {
        self.cached.sync_pages()
    }
}

/// Borrowed maintenance access. All modes leave request-policy counters and
/// recency/frequency unchanged. Published mode may add admitted cache entries;
/// private mode never retains a miss. No mode evicts existing entries. Optional
/// commit traversal stops before uncached fallback when retention is refused.
pub(crate) struct MaintenanceDirectoryBackend<'a, B: DirectoryBackend> {
    cached: &'a CachedDirectoryBackend<B>,
    retain: bool,
    retention_denied: Option<&'a AtomicBool>,
    stop_on_denial: bool,
}

impl<B: DirectoryBackend> DirectoryBackend for MaintenanceDirectoryBackend<'_, B> {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
        self.cached.check_owner()?;
        if out.len() != DIRECTORY_PAGE_BYTES {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "directory page output length differs",
            )));
        }
        let identity = self.cached.identity(reference)?;
        let page = if self.retain {
            match self
                .cached
                .lock()?
                .load_if_fits(identity, DIRECTORY_PAGE_BYTES, |bytes| {
                    self.cached.read_verified(reference, bytes)
                }) {
                Ok(page) => page,
                Err(CacheLoadError::Admission(crate::core::AdmissionError::CapacityDenied)) => None,
                Err(CacheLoadError::Admission(error)) => return Err(error.into()),
                Err(CacheLoadError::Load(error)) => return Err(error),
            }
        } else {
            self.cached.lock()?.peek(identity)
        };
        self.cached.check_owner()?;
        if let Some(page) = page {
            if page.as_bytes().len() != DIRECTORY_PAGE_BYTES
                || page_digest(page.as_bytes()) != reference.sha256
            {
                return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "cached directory page identity differs",
                )));
            }
            out.copy_from_slice(page.as_bytes());
            self.cached.check_owner()
        } else {
            if let Some(denied) = self.retention_denied {
                denied.store(true, Ordering::Release);
            }
            if self.stop_on_denial {
                return Err(CoreError::new(crate::CoreErrorCause::CapacityDenied));
            }
            self.cached.read_verified(reference, out)?;
            self.cached.check_owner()
        }
    }

    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        self.cached.append_page(bytes)
    }

    fn sync_pages(&self) -> Result<(), CoreError> {
        self.cached.sync_pages()
    }
}

impl<B: DirectoryBackend> DirectoryBackend for CachedDirectoryBackend<B> {
    fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
        self.check_owner()?;
        if out.len() != DIRECTORY_PAGE_BYTES {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "directory page output length differs",
            )));
        }
        let identity = self.identity(reference)?;
        // Normal demand policy still retains every fitting page. A refused
        // optional cache allocation reads into the caller's admitted page;
        // it never requests a second temporary CachedBytes workspace.
        let page = self
            .lock()?
            .load_or_read_into(identity, out, |out| self.read_verified(reference, out))
            .map_err(|error| match error {
                CacheLoadError::Admission(error) => CoreError::from(error),
                CacheLoadError::Load(error) => error,
            })?;
        self.check_owner()?;
        if let Some(page) = page {
            if page.as_bytes().len() != DIRECTORY_PAGE_BYTES
                || page_digest(page.as_bytes()) != reference.sha256
            {
                return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "cached directory page identity differs",
                )));
            }
            out.copy_from_slice(page.as_bytes());
        }
        self.check_owner()
    }

    fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
        self.check_owner()?;
        if bytes.len() != DIRECTORY_PAGE_BYTES {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "directory page input length differs",
            )));
        }
        let reference = self.backend.append_page(bytes)?;
        self.check_owner()?;
        self.identity(reference)?;
        if page_digest(bytes) != reference.sha256 {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "appended directory page digest differs",
            )));
        }
        Ok(reference)
    }

    fn sync_pages(&self) -> Result<(), CoreError> {
        self.check_owner()?;
        self.backend.sync_pages()?;
        self.check_owner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod commit_warming {
        include!("page_cache_commit_tests.rs");
    }
    mod read_into {
        include!("page_cache_read_into_tests.rs");
    }
    use crate::core::{AdmissionError, OwnerFailed, ResidentLease};
    use crate::directory::{
        DirectoryBuilder, DirectoryKey, DirectoryMutator, DirectoryReader, DirectoryValue,
        DirectoryWriteWorkspace,
    };
    use crate::segment::ValueLocation;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    const GROUP: [u8; 16] = [11; 16];

    struct Admission {
        used: Arc<AtomicU64>,
        limit: AtomicU64,
        failed: AtomicBool,
    }

    struct Lease(Arc<AtomicU64>, u64);

    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.fetch_sub(self.1, Ordering::AcqRel);
        }
    }

    impl Admission {
        fn new(limit: u64) -> Arc<Self> {
            Arc::new(Self {
                used: Arc::new(AtomicU64::new(0)),
                limit: AtomicU64::new(limit),
                failed: AtomicBool::new(false),
            })
        }
    }

    impl StorageAdmission for Admission {
        fn check_owner(&self) -> Result<(), OwnerFailed> {
            if self.failed.load(Ordering::Acquire) {
                Err(OwnerFailed)
            } else {
                Ok(())
            }
        }

        fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
            self.check_owner()
                .map_err(|_| AdmissionError::OwnerFailed)?;
            self.used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes)
                        .filter(|&total| total <= self.limit.load(Ordering::Acquire))
                })
                .map_err(|_| AdmissionError::CapacityDenied)?;
            Ok(Box::new(Lease(self.used.clone(), bytes)))
        }

        fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
            Ok(())
        }

        fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
            Ok(())
        }

        fn owner_failed(&self) {
            self.failed.store(true, Ordering::Release);
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
    impl crate::cache_test::Provider for Admission {
        fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
            let _ = first;
            self.used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes)
                        .filter(|next| *next <= self.limit.load(Ordering::Acquire))
                })
                .map_err(|_| AdmissionError::CapacityDenied)?;
            Ok(())
        }
        fn release_cache(&self, bytes: u64, last: bool) {
            let _ = (bytes, last);
            self.used.fetch_sub(bytes, Ordering::AcqRel);
        }
    }

    #[derive(Default)]
    struct Pages {
        pages: Mutex<Vec<Vec<u8>>>,
        reads: AtomicUsize,
        expire_on_read: Mutex<Option<Arc<Admission>>>,
    }

    impl DirectoryBackend for Pages {
        fn read_page(&self, reference: DirectoryPageRef, out: &mut [u8]) -> Result<(), CoreError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let pages = self.pages.lock().unwrap();
            let page = pages
                .get(reference.page_index as usize)
                .ok_or(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "test page is absent",
                )))?;
            out.copy_from_slice(page);
            if let Some(admission) = self.expire_on_read.lock().unwrap().take() {
                admission.failed.store(true, Ordering::Release);
            }
            Ok(())
        }

        fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
            let mut pages = self.pages.lock().unwrap();
            let reference = DirectoryPageRef {
                arena_id: 1,
                page_index: pages.len() as u64,
                sha256: page_digest(bytes),
            };
            pages.push(bytes.to_vec());
            Ok(reference)
        }

        fn sync_pages(&self) -> Result<(), CoreError> {
            Ok(())
        }
    }

    fn reference(index: u64, byte: u8) -> DirectoryPageRef {
        DirectoryPageRef {
            arena_id: 1,
            page_index: index,
            sha256: page_digest(&[byte; DIRECTORY_PAGE_BYTES]),
        }
    }

    #[test]
    fn publication_private_reads_mark_only_actual_hot_paths_and_never_retain_misses() {
        let admission = Admission::new(u64::MAX);
        let pages = Pages::default();
        for byte in 1..=3 {
            pages.append_page(&[byte; DIRECTORY_PAGE_BYTES]).unwrap();
        }
        let cached = CachedDirectoryBackend::new(
            &pages,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 1 << 20,
            },
        );
        drop(cached.load_page(reference(0, 1)).unwrap());
        drop(cached.load_page(reference(1, 2)).unwrap());
        let before = cached.stats().unwrap();
        let used = admission.used.load(Ordering::Acquire);
        let reads = pages.reads.load(Ordering::Relaxed);
        cached
            .lock()
            .unwrap()
            .begin_publication_candidates()
            .unwrap();
        let private = cached.publication_private_view();
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        for _ in 0..3 {
            private.read_page(reference(0, 1), &mut out).unwrap();
            assert_eq!(out, [1; DIRECTORY_PAGE_BYTES]);
        }
        private.read_page(reference(2, 3), &mut out).unwrap();
        let unpublished = private.append_page(&[4; DIRECTORY_PAGE_BYTES]).unwrap();
        private.read_page(unpublished, &mut out).unwrap();
        private.sync_pages().unwrap();
        assert_eq!(out, [4; DIRECTORY_PAGE_BYTES]);
        assert_eq!(pages.reads.load(Ordering::Relaxed), reads + 2);
        assert_eq!(cached.stats().unwrap(), before);
        assert_eq!(admission.used.load(Ordering::Acquire), used);
        let mut cache = cached.lock().unwrap();
        let candidate = cache.pop_publication_candidate().unwrap().unwrap();
        assert_eq!(candidate.key, cached.identity(reference(0, 1)).unwrap());
        assert_eq!(candidate.bytes.as_bytes(), &[1; DIRECTORY_PAGE_BYTES]);
        assert!(cache.pop_publication_candidate().unwrap().is_none());
        cache.clear_publication_candidates().unwrap();
        assert_eq!(cache.stats(), before);
    }

    #[test]
    fn publication_private_reads_require_scope_and_recheck_owner_for_hits_and_misses() {
        let admission = Admission::new(u64::MAX);
        let pages = Pages::default();
        pages.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
        pages.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
        let cached = CachedDirectoryBackend::new(
            &pages,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 1 << 20,
            },
        );
        drop(cached.load_page(reference(0, 1)).unwrap());
        let before = cached.stats().unwrap();
        let private = cached.publication_private_view();
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        assert!(
            matches!(&(private.read_page(reference(0, 1), &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        cached
            .lock()
            .unwrap()
            .begin_publication_candidates()
            .unwrap();
        assert!(
            matches!(&(private.read_page(reference(0, 1), &mut out[..8])), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        let mut invalid = reference(0, 1);
        invalid.arena_id = 0;
        assert!(
            matches!(&(private.read_page(invalid, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
        );
        admission.failed.store(true, Ordering::Release);
        assert!(
            matches!(&(private.read_page(reference(0, 1), &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert_eq!(
            cached.lock().unwrap().clear_publication_candidates(),
            Err(AdmissionError::OwnerFailed)
        );
        admission.failed.store(false, Ordering::Release);
        cached
            .lock()
            .unwrap()
            .begin_publication_candidates()
            .unwrap();
        *pages.expire_on_read.lock().unwrap() = Some(admission.clone());
        assert!(
            matches!(&(private.read_page(reference(1, 2), &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert_eq!(
            cached.lock().unwrap().clear_publication_candidates(),
            Err(AdmissionError::OwnerFailed)
        );
        admission.failed.store(false, Ordering::Release);
        assert_eq!(cached.stats().unwrap(), before);
        cached
            .lock()
            .unwrap()
            .begin_publication_candidates()
            .unwrap();
        let mut wrong = reference(1, 2);
        wrong.sha256[0] ^= 1;
        assert!(
            matches!(&(private.read_page(wrong, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
        );
        assert!(
            cached
                .lock()
                .unwrap()
                .pop_publication_candidate()
                .unwrap()
                .is_none()
        );
        cached
            .lock()
            .unwrap()
            .clear_publication_candidates()
            .unwrap();
    }

    #[test]
    fn maintenance_private_reads_reuse_hits_without_retaining_or_training_misses() {
        let backend = Pages::default();
        let hot = backend.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
        let cold = backend.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
        let admission = Admission::new(u64::MAX);
        let cached = CachedDirectoryBackend::new(
            &backend,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 1 << 20,
            },
        );
        drop(cached.load_page(hot).unwrap());
        let before = cached.stats().unwrap();
        let used = admission.used.load(Ordering::Acquire);
        admission.limit.store(used, Ordering::Release);
        let private = cached.maintenance_private_view();
        let mut bytes = [0; DIRECTORY_PAGE_BYTES];
        let reads = backend.reads.load(Ordering::Relaxed);
        for _ in 0..3 {
            private.read_page(hot, &mut bytes).unwrap();
            assert_eq!(bytes, [1; DIRECTORY_PAGE_BYTES]);
            private.read_page(cold, &mut bytes).unwrap();
            assert_eq!(bytes, [2; DIRECTORY_PAGE_BYTES]);
        }
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads + 3);
        assert_eq!(cached.stats().unwrap(), before);
        assert_eq!(admission.used.load(Ordering::Acquire), used);
        let appended = private.append_page(&[3; DIRECTORY_PAGE_BYTES]).unwrap();
        private.sync_pages().unwrap();
        private.read_page(appended, &mut bytes).unwrap();
        assert_eq!(bytes, [3; DIRECTORY_PAGE_BYTES]);
        assert_eq!(cached.stats().unwrap(), before);
    }

    #[test]
    fn maintenance_published_reads_keep_all_fitting_pages_and_preserve_hot_pages_at_capacity() {
        let backend = Pages::default();
        let admission = Admission::new(u64::MAX);
        let cached = CachedDirectoryBackend::new(
            &backend,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 1 << 20,
            },
        );
        for id in 0..64u8 {
            cached.append_page(&[id; DIRECTORY_PAGE_BYTES]).unwrap();
        }
        let published = cached.maintenance_view();
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        for id in 0..32u8 {
            published
                .read_page(reference(id.into(), id), &mut out)
                .unwrap();
            assert_eq!(out, [id; DIRECTORY_PAGE_BYTES]);
        }
        let before = cached.stats().unwrap();
        assert_eq!(before.entries, 32);
        assert_eq!(
            (
                before.hits,
                before.misses,
                before.loads,
                before.uncached_loads,
                before.evictions
            ),
            (0, 0, 0, 0, 0)
        );
        cached
            .configure(CacheConfig {
                byte_limit: before.allocated_bytes + before.provider_overhead_bytes,
            })
            .unwrap();
        let before = cached.stats().unwrap();
        assert_eq!(before.entries, 32);
        assert_eq!(before.unused_credit_bytes, 0);
        for id in 32..64u8 {
            published
                .read_page(reference(id.into(), id), &mut out)
                .unwrap();
            assert_eq!(out, [id; DIRECTORY_PAGE_BYTES]);
        }
        assert_eq!(cached.stats().unwrap(), before);
        let reads = backend.reads.load(Ordering::Relaxed);
        for id in 0..32u8 {
            published
                .read_page(reference(id.into(), id), &mut out)
                .unwrap();
            assert_eq!(out, [id; DIRECTORY_PAGE_BYTES]);
        }
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
        assert_eq!(cached.stats().unwrap(), before);
        assert_eq!(
            admission.used.load(Ordering::Acquire),
            before.resident_bytes
        );
    }

    #[test]
    fn maintenance_reads_preserve_existing_frequency_and_recency_rank() {
        for retain in [false, true] {
            let backend = Pages::default();
            let oldest = backend.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
            let newest = backend.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
            let cold = backend.append_page(&[3; DIRECTORY_PAGE_BYTES]).unwrap();
            let cached = CachedDirectoryBackend::new(
                &backend,
                Admission::new(u64::MAX),
                GROUP,
                CacheConfig {
                    byte_limit: 1 << 20,
                },
            );
            drop(cached.load_page(oldest).unwrap());
            drop(cached.load_page(newest).unwrap());
            let before = cached.stats().unwrap();
            cached
                .configure(CacheConfig {
                    byte_limit: before.allocated_bytes + before.provider_overhead_bytes,
                })
                .unwrap();
            let before = cached.stats().unwrap();
            assert_eq!(before.entries, 2);
            assert_eq!(before.unused_credit_bytes, 0);
            let maintenance = MaintenanceDirectoryBackend {
                cached: &cached,
                retain,
                retention_denied: None,
                stop_on_denial: false,
            };
            let mut out = [0; DIRECTORY_PAGE_BYTES];
            for _ in 0..128 {
                maintenance.read_page(oldest, &mut out).unwrap();
                maintenance.read_page(cold, &mut out).unwrap();
            }
            assert_eq!(cached.stats().unwrap(), before);
            drop(cached.load_page(cold).unwrap());
            let cache = cached.lock().unwrap();
            assert!(!cache.contains(cached.identity(oldest).unwrap()));
            assert!(cache.contains(cached.identity(newest).unwrap()));
            assert!(cache.contains(cached.identity(cold).unwrap()));
            assert_eq!(cache.stats().evictions, 1);
        }
    }

    #[test]
    fn maintenance_reads_check_identity_and_owner_on_hits_and_all_miss_paths() {
        for retain in [false, true] {
            for cache_capacity in [0, 1 << 20] {
                for workspace_capacity in [0, u64::MAX] {
                    let backend = Pages::default();
                    let hot = backend.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
                    let cold = backend.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
                    let admission = Admission::new(u64::MAX);
                    let cached = CachedDirectoryBackend::new(
                        &backend,
                        admission.clone(),
                        GROUP,
                        CacheConfig {
                            byte_limit: 1 << 20,
                        },
                    );
                    drop(cached.load_page(hot).unwrap());
                    let maintenance = MaintenanceDirectoryBackend {
                        cached: &cached,
                        retain,
                        retention_denied: None,
                        stop_on_denial: false,
                    };
                    let mut out = [0; DIRECTORY_PAGE_BYTES];
                    assert!(
                        matches!(&(maintenance.read_page(hot, &mut out[..8])), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
                    );
                    let mut wrong = cold;
                    wrong.sha256[0] ^= 1;
                    assert!(
                        matches!(&(maintenance.read_page(wrong, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
                    );
                    assert_eq!(cached.stats().unwrap().entries, 1);
                    admission.failed.store(true, Ordering::Release);
                    let reads = backend.reads.load(Ordering::Relaxed);
                    assert!(
                        matches!(&(maintenance.read_page(hot, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
                    );
                    assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
                    admission.failed.store(false, Ordering::Release);
                    cached.clear().unwrap();
                    cached
                        .configure(CacheConfig {
                            byte_limit: cache_capacity,
                        })
                        .unwrap();
                    admission.limit.store(workspace_capacity, Ordering::Release);
                    maintenance.read_page(cold, &mut out).unwrap();
                    assert_eq!(out, [2; DIRECTORY_PAGE_BYTES]);
                    cached.clear().unwrap();
                    *backend.expire_on_read.lock().unwrap() = Some(admission.clone());
                    assert!(
                        matches!(&(maintenance.read_page(cold, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
                    );
                    assert_eq!(cached.cache.lock().unwrap().stats().entries, 0);
                    cached.clear().unwrap();
                    assert_eq!(admission.used.load(Ordering::Acquire), 0);
                }
            }
        }
    }

    #[test]
    fn private_view_reuses_committed_pages_without_admitting_intermediate_roots() {
        struct RejectOldReads<'a> {
            backend: &'a Pages,
            old_pages: usize,
            enabled: AtomicBool,
        }
        impl DirectoryBackend for RejectOldReads<'_> {
            fn read_page(
                &self,
                reference: DirectoryPageRef,
                out: &mut [u8],
            ) -> Result<(), CoreError> {
                if self.enabled.load(Ordering::Acquire)
                    && (reference.page_index as usize) < self.old_pages
                {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "published hot page reached disk",
                    )));
                }
                self.backend.read_page(reference, out)
            }
            fn append_page(&self, bytes: &[u8]) -> Result<DirectoryPageRef, CoreError> {
                self.backend.append_page(bytes)
            }
            fn sync_pages(&self) -> Result<(), CoreError> {
                self.backend.sync_pages()
            }
        }
        fn key(index: u64) -> [u8; crate::core::MAX_KEY_BYTES] {
            let mut key = [0; crate::core::MAX_KEY_BYTES];
            key[..8].copy_from_slice(&index.to_be_bytes());
            key
        }
        fn value(generation: u64, index: u64) -> DirectoryValue {
            DirectoryValue::Row {
                batch_seq: generation,
                value: ValueLocation {
                    segment_id: index + 1,
                    offset: 256,
                    len: 8,
                    crc: index as u32,
                },
            }
        }
        let backend = Pages::default();
        let admission = Admission::new(8 << 20);
        let mut builder = DirectoryBuilder::new(&backend, admission.clone(), GROUP, 1).unwrap();
        for index in 0..36 {
            builder
                .push(DirectoryKey::row("t", &key(index)), value(1, index))
                .unwrap();
        }
        let old = builder.finish().unwrap();
        let guarded = RejectOldReads {
            backend: &backend,
            old_pages: backend.pages.lock().unwrap().len(),
            enabled: AtomicBool::new(false),
        };
        let cached = CachedDirectoryBackend::new(
            &guarded,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 4 << 20,
            },
        );
        DirectoryReader::new(&cached, admission.clone())
            .warm_generation(old, 0)
            .unwrap();
        guarded.enabled.store(true, Ordering::Release);
        let before = cached.stats().unwrap();
        let private = cached.private_view();
        let mut mutator_workspace = DirectoryWriteWorkspace::for_edits(admission.clone()).unwrap();
        let mut mutator = DirectoryMutator::new(&private, &mut mutator_workspace).unwrap();
        let first = mutator
            .set(old, 2, DirectoryKey::row("t", &key(36)), Some(value(2, 36)))
            .unwrap();
        let selected = mutator
            .set(
                first,
                2,
                DirectoryKey::row("t", &key(37)),
                Some(value(2, 37)),
            )
            .unwrap();
        let selected = mutator.finish(selected).unwrap();
        let reader = DirectoryReader::new(&private, admission);
        assert_eq!(
            reader.get(old, DirectoryKey::row("t", &key(17))).unwrap(),
            Some(value(1, 17))
        );
        assert_eq!(
            reader.get(first, DirectoryKey::row("t", &key(36))).unwrap(),
            Some(value(2, 36))
        );
        assert_eq!(
            reader
                .get(selected, DirectoryKey::row("t", &key(37)))
                .unwrap(),
            Some(value(2, 37))
        );
        let after = cached.stats().unwrap();
        assert_eq!(after.entries, before.entries);
        assert_eq!(after.resident_bytes, before.resident_bytes);
        assert_eq!(after.loads, before.loads);
        assert_eq!(after.misses, before.misses);
        assert_eq!(after.uncached_loads, before.uncached_loads);
        assert_eq!(after.evictions, before.evictions);
        assert_eq!(after.hits, before.hits);
    }

    #[test]
    fn private_view_checks_identity_owner_and_output_on_hits_and_raw_misses() {
        let backend = Pages::default();
        let hot = backend.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
        let cold = backend.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
        let admission = Admission::new(u64::MAX);
        let cached = CachedDirectoryBackend::new(
            &backend,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 1 << 20,
            },
        );
        drop(cached.load_page(hot).unwrap());
        let private = cached.private_view();
        let mut bytes = [0; DIRECTORY_PAGE_BYTES];
        let reads = backend.reads.load(Ordering::Relaxed);
        private.read_page(hot, &mut bytes).unwrap();
        assert_eq!(bytes, [1; DIRECTORY_PAGE_BYTES]);
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
        let before = cached.stats().unwrap();
        for _ in 0..2 {
            private.read_page(cold, &mut bytes).unwrap();
        }
        assert_eq!(bytes, [2; DIRECTORY_PAGE_BYTES]);
        assert_eq!(cached.stats().unwrap(), before);
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads + 2);
        assert!(
            matches!(&(private.read_page(hot, &mut bytes[..8])), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
        );
        let mut wrong = hot;
        wrong.sha256[31] ^= 1;
        assert!(
            matches!(&(private.read_page(wrong, &mut bytes)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
        );
        assert_eq!(cached.stats().unwrap(), before);
        admission.failed.store(true, Ordering::Release);
        let reads = backend.reads.load(Ordering::Relaxed);
        assert!(
            matches!(&(private.read_page(hot, &mut bytes)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
        admission.failed.store(false, Ordering::Release);
        *backend.expire_on_read.lock().unwrap() = Some(admission.clone());
        assert!(
            matches!(&(private.read_page(cold, &mut bytes)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert_eq!(cached.cache.lock().unwrap().stats(), before);
    }

    #[test]
    fn pages_and_values_retain_full_identity_under_one_shared_limit() {
        let backend = Arc::new(Pages::default());
        let page_ref = backend.append_page(&[7; DIRECTORY_PAGE_BYTES]).unwrap();
        let admission = Admission::new(u64::MAX);
        let shared = Arc::new(Mutex::new(NativeCache::new(
            CacheConfig {
                byte_limit: 1 << 20,
            },
            admission.clone(),
        )));
        let cache = CachedDirectoryBackend::with_shared_cache(
            backend.clone(),
            admission.clone(),
            GROUP,
            shared.clone(),
        );
        let page = cache.load_page(page_ref).unwrap();
        let value_key = NativeIdentity::Value {
            group_id: GROUP,
            segment_id: page_ref.arena_id,
            offset: page_ref.page_index,
            len: DIRECTORY_PAGE_BYTES as u32,
            crc: 7,
            table_len: 1,
            key_len: 0,
        };
        let value = shared
            .lock()
            .unwrap()
            .load(value_key, DIRECTORY_PAGE_BYTES, |bytes| {
                bytes.fill(9);
                Ok::<_, CoreError>(())
            })
            .unwrap();
        assert_eq!(cache.stats().unwrap().entries, 2);
        assert_eq!(
            cache.load_page(page_ref).unwrap().as_bytes(),
            &[7; DIRECTORY_PAGE_BYTES]
        );
        assert_eq!(
            shared.lock().unwrap().get(value_key).unwrap().as_bytes(),
            &[9; DIRECTORY_PAGE_BYTES]
        );
        assert_eq!(backend.reads.load(Ordering::Relaxed), 1);
        let fit = cache.stats().unwrap().resident_bytes;
        cache.configure(CacheConfig { byte_limit: fit }).unwrap();
        assert_eq!(shared.lock().unwrap().config().byte_limit, fit);
        assert_eq!(cache.stats().unwrap().evictions, 0);
        cache.clear().unwrap();
        assert_eq!(shared.lock().unwrap().stats().entries, 0);
        assert!(cache.stats().unwrap().pinned_bytes >= 2 * DIRECTORY_PAGE_BYTES as u64);
        drop(page);
        drop(value);
        cache.clear().unwrap();
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn every_fitting_page_stays_resident_and_append_does_not_warm() {
        let backend = Pages::default();
        let admission = Admission::new(u64::MAX);
        let cache = CachedDirectoryBackend::new(
            &backend,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 1 << 20,
            },
        );
        for id in 0..32u8 {
            cache.append_page(&[id; DIRECTORY_PAGE_BYTES]).unwrap();
        }
        assert_eq!(cache.stats().unwrap().entries, 0);
        for id in 0..32u8 {
            let page = cache.load_page(reference(id.into(), id)).unwrap();
            assert_eq!(page.as_bytes(), &[id; DIRECTORY_PAGE_BYTES]);
        }
        assert_eq!(cache.stats().unwrap().entries, 32);
        assert_eq!(cache.stats().unwrap().evictions, 0);
        let reads = backend.reads.load(Ordering::Relaxed);
        for id in 0..32u8 {
            assert_eq!(
                cache
                    .load_page(reference(id.into(), id))
                    .unwrap()
                    .as_bytes(),
                &[id; DIRECTORY_PAGE_BYTES]
            );
        }
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
        assert_eq!(
            admission.used.load(Ordering::Acquire),
            cache.stats().unwrap().resident_bytes
        );
        cache.clear().unwrap();
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn fitting_directory_repeats_without_page_io_and_checks_snapshot_headers() {
        let backend = Pages::default();
        let admission = Admission::new(u64::MAX);
        let cache = CachedDirectoryBackend::new(
            &backend,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 512 << 10,
            },
        );
        let mut builder = DirectoryBuilder::new(&cache, admission.clone(), GROUP, 3).unwrap();
        for id in 0..1600u64 {
            builder
                .push(
                    DirectoryKey::row("accounts", &id.to_be_bytes()),
                    DirectoryValue::Row {
                        batch_seq: 3,
                        value: ValueLocation {
                            segment_id: 1,
                            offset: 256 + id * 8,
                            len: 8,
                            crc: id as u32,
                        },
                    },
                )
                .unwrap();
        }
        let root = builder.finish().unwrap();
        assert!(root.height > 1);
        let reader = DirectoryReader::new(&cache, admission.clone());
        for _ in 0..2 {
            let reads = backend.reads.load(Ordering::Relaxed);
            for id in 0..1600u64 {
                assert!(
                    reader
                        .get(root, DirectoryKey::row("accounts", &id.to_be_bytes()))
                        .unwrap()
                        .is_some()
                );
            }
            if reads != 0 {
                assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
            }
        }
        let reads = backend.reads.load(Ordering::Relaxed);
        let wrong_group = crate::directory::DirectoryRoot {
            group_id: [99; 16],
            ..root
        };
        assert!(matches!(&(reader.get(
                wrong_group,
                DirectoryKey::row("accounts", &0u64.to_be_bytes())
            )), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_)))));
        let older = crate::directory::DirectoryRoot {
            generation: 2,
            ..root
        };
        assert!(
            matches!(&(reader.get(older, DirectoryKey::row("accounts", &0u64.to_be_bytes()))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
        );
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
        let newer = crate::directory::DirectoryRoot {
            generation: 4,
            ..root
        };
        assert!(
            reader
                .get(newer, DirectoryKey::row("accounts", &0u64.to_be_bytes()))
                .unwrap()
                .is_some()
        );
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
        assert_eq!(cache.stats().unwrap().evictions, 0);
    }

    #[test]
    fn owner_is_checked_on_hits_and_after_io_including_uncached_fallback() {
        for capacity in [0, u64::MAX] {
            let backend = Pages::default();
            let admission = Admission::new(u64::MAX);
            let page = backend.append_page(&[7; DIRECTORY_PAGE_BYTES]).unwrap();
            let cache = CachedDirectoryBackend::new(
                &backend,
                admission.clone(),
                GROUP,
                CacheConfig {
                    byte_limit: 64 << 10,
                },
            );
            drop(cache.load_page(page).unwrap());
            admission.failed.store(true, Ordering::Release);
            let reads = backend.reads.load(Ordering::Relaxed);
            assert!(
                matches!(&(cache.load_page(page)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
            );
            assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
            admission.failed.store(false, Ordering::Release);
            cache.clear().unwrap();
            admission.limit.store(capacity, Ordering::Release);
            *backend.expire_on_read.lock().unwrap() = Some(admission.clone());
            let mut out = [0; DIRECTORY_PAGE_BYTES];
            assert!(
                matches!(&(cache.read_page(page, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
            );
            assert_eq!(cache.lock().unwrap().stats().entries, 0);
            cache.clear().unwrap();
            assert_eq!(admission.used.load(Ordering::Acquire), 0);
        }
    }

    #[test]
    fn fallback_uses_existing_output_and_never_installs_bad_pages() {
        let backend = Pages::default();
        let page = backend.append_page(&[4; DIRECTORY_PAGE_BYTES]).unwrap();
        let admission = Admission::new(0);
        let cache = CachedDirectoryBackend::new(
            &backend,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 64 << 10,
            },
        );
        let mut out = [0; DIRECTORY_PAGE_BYTES];
        cache.read_page(page, &mut out).unwrap();
        assert_eq!(out, [4; DIRECTORY_PAGE_BYTES]);
        assert_eq!(cache.stats().unwrap().resident_bytes, 0);
        assert_eq!(cache.stats().unwrap().loads, 1);
        assert_eq!(cache.stats().unwrap().uncached_loads, 1);
        let mut wrong = page;
        wrong.sha256[0] ^= 1;
        assert!(
            matches!(&(cache.read_page(wrong, &mut out)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
        );
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
        admission.limit.store(u64::MAX, Ordering::Release);
        assert!(
            matches!(&(cache.load_page(wrong)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
        );
        assert_eq!(cache.stats().unwrap().entries, 0);
        cache.clear().unwrap();
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn admitted_table_only_reader_records_page_retention_denial() {
        let backend = Pages::default();
        let mut builder =
            DirectoryBuilder::new(&backend, Admission::new(u64::MAX), GROUP, 1).unwrap();
        builder
            .push(
                DirectoryKey::table("only-table"),
                DirectoryValue::Table { birth_seq: 1 },
            )
            .unwrap();
        let root = builder.finish().unwrap();
        let admission = Admission::new(40 << 10);
        let cache = CachedDirectoryBackend::new(
            &backend,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 1 << 20,
            },
        );
        let reader = DirectoryReader::new(&cache, admission);
        reader.warm_generation(root, 1).unwrap();
        let stats = cache.stats().unwrap();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.loads, 1);
        assert_eq!(stats.uncached_loads, 1);
        assert_eq!(backend.reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn exact_physical_identity_and_owner_scope_never_alias() {
        let first = Pages::default();
        let second = Pages::default();
        let a = first.append_page(&[1; DIRECTORY_PAGE_BYTES]).unwrap();
        let b = second.append_page(&[2; DIRECTORY_PAGE_BYTES]).unwrap();
        let admission = Admission::new(u64::MAX);
        let cache_a = CachedDirectoryBackend::new(
            &first,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 256 << 10,
            },
        );
        let cache_b = CachedDirectoryBackend::new(
            &second,
            admission,
            [22; 16],
            CacheConfig {
                byte_limit: 256 << 10,
            },
        );
        assert_eq!(
            cache_a.load_page(a).unwrap().as_bytes(),
            &[1; DIRECTORY_PAGE_BYTES]
        );
        assert_eq!(
            cache_b.load_page(b).unwrap().as_bytes(),
            &[2; DIRECTORY_PAGE_BYTES]
        );
        let other_arena = DirectoryPageRef { arena_id: 2, ..a };
        drop(cache_a.load_page(other_arena).unwrap());
        // The test backend returns the same bytes for either arena, but both
        // physical identities must coexist in the lookup and remain hot.
        assert_eq!(cache_a.stats().unwrap().entries, 2);
        assert_eq!(first.reads.load(Ordering::Relaxed), 2);
        drop(cache_a.load_page(a).unwrap());
        drop(cache_a.load_page(other_arena).unwrap());
        assert_eq!(first.reads.load(Ordering::Relaxed), 2);
        assert!(matches!(&(cache_a.load_page(DirectoryPageRef {
                sha256: b.sha256,
                ..a
            })), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_)))));
        // Every digest byte participates in equality; the slot hash never
        // substitutes for the complete cryptographic page identity.
        for index in 0..32 {
            let mut different = a;
            different.sha256[index] ^= 1;
            assert!(
                matches!(&(cache_a.load_page(different)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::Corrupt(_))))
            );
        }
        assert_eq!(cache_a.stats().unwrap().entries, 2);
        assert_eq!(
            cache_a.load_page(a).unwrap().as_bytes(),
            &[1; DIRECTORY_PAGE_BYTES]
        );
    }

    #[test]
    fn scan_pressure_preserves_hot_pages_and_pins_survive_clear() {
        let backend = Pages::default();
        for id in 0..80u8 {
            backend.append_page(&[id; DIRECTORY_PAGE_BYTES]).unwrap();
        }
        let admission = Admission::new(u64::MAX);
        let cache = CachedDirectoryBackend::new(
            &backend,
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: 1 << 20,
            },
        );
        for id in 0..8u8 {
            drop(cache.load_page(reference(id.into(), id)).unwrap());
        }
        let limit = cache.stats().unwrap().resident_bytes;
        cache.configure(CacheConfig { byte_limit: limit }).unwrap();
        for _ in 0..40 {
            for id in 0..4u8 {
                drop(cache.load_page(reference(id.into(), id)).unwrap());
            }
        }
        for id in 8..80u8 {
            drop(cache.load_page(reference(id.into(), id)).unwrap());
            assert!(cache.stats().unwrap().resident_bytes <= limit);
        }
        let reads = backend.reads.load(Ordering::Relaxed);
        for id in 0..4u8 {
            drop(cache.load_page(reference(id.into(), id)).unwrap());
        }
        assert_eq!(backend.reads.load(Ordering::Relaxed), reads);
        let pin = cache.load_page(reference(0, 0)).unwrap();
        cache.clear().unwrap();
        assert_eq!(cache.stats().unwrap().pinned_bytes, pin.charged_bytes());
        assert!(
            matches!(&(cache.configure(CacheConfig { byte_limit: 0 })), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        assert_eq!(
            admission.used.load(Ordering::Acquire),
            cache.stats().unwrap().resident_bytes
        );
        drop(cache);
        assert!(admission.used.load(Ordering::Acquire) >= pin.charged_bytes());
        drop(pin);
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }
}
