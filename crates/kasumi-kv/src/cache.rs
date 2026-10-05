//! An admitted cache for immutable backend values and index pages.
//!
//! Keys retain their complete identity; hashing only chooses lookup slots and
//! estimates frequency, never substitutes for equality. Keys are physical
//! identities within one database incarnation. Callers must
//! clear the cache before reusing those identities (for example, compaction).
//! Authorization, expiry and snapshot selection belong to the caller and must
//! run before a lookup. This cache does not make those decisions.

#[cfg(test)]
use crate::ResidentLease;
use crate::core::NativeResidentLease;
use crate::{AdmissionError, StorageAdmission};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::mem::{size_of, take};
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "cache_pool.rs"]
mod pool;

const NONE: usize = usize::MAX;
const MIN_SLOTS: usize = 16;
const SKETCH_WIDTH: usize = 512;
const SKETCH_ROWS: usize = 4;
const SKETCH_SAMPLES: u64 = 32_768;
// Conservative bookkeeping allowances, in addition to Rust object layouts.
// This is an allocation ledger, not an exact physical-RSS measurement. A
// StorageAdmission implementation with a larger custom lease owner must also
// account for that owner's excess backing within its own memory budget.
const ALLOCATION_ALLOWANCE: u64 = 64;
const LEASE_OWNER_ALLOWANCE: u64 = 64;
const LEASE_ALLOWANCE: u64 = LEASE_OWNER_ALLOWANCE + ALLOCATION_ALLOWANCE;

/// Maximum retained cache memory, including indexing and value-owner overhead.
///
/// Zero disables retention. Reads that cannot be retained still require a
/// storage admission, but their request-owned buffers are outside this cache
/// budget. The enclosing owner must budget that request workspace separately.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheConfig {
    pub byte_limit: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub loads: u64,
    pub uncached_loads: u64,
    pub evictions: u64,
    pub entries: usize,
    /// All retained cache allocations, including evicted values still pinned.
    pub resident_bytes: u64,
    /// Distinct payloads reachable through one or more cached identities.
    pub cached_bytes: u64,
    /// Payloads with no cached identity that remain held by readers.
    pub pinned_bytes: u64,
    pub metadata_bytes: u64,
    /// Native allocations currently borrowing aggregate credit.
    pub allocated_bytes: u64,
    /// Admitted usable credit, including bounded unused tail space.
    pub admitted_credit_bytes: u64,
    pub unused_credit_bytes: u64,
    /// Exact provider token/backing charge beyond usable credit.
    pub provider_overhead_bytes: u64,
}

/// A slot pass belongs to one cache's unchanged membership/layout. Demand
/// hits may reorder LRU links without invalidating it. Structural changes
/// restart the next step; completion therefore describes a quiescent pass,
/// not a snapshot retained across concurrent cache changes.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CacheCursor {
    version: Option<u64>,
    next_slot: usize,
}

/// One immutable candidate held while the caller proves reachability outside
/// the cache lock. Its bytes retain their original admission. The private
/// identity is checked again before conditional removal; holding this value
/// alone never authorizes removal or bypasses owner/security checks.
pub(crate) struct CacheCandidate<K> {
    pub(crate) key: K,
    pub(crate) bytes: CachedBytes,
    version: u64,
    slot: usize,
}

pub(crate) struct CacheCandidateStep<K> {
    pub(crate) candidate: Option<CacheCandidate<K>>,
    /// Slots examined, including empty slots; never exceeds the supplied cap.
    pub(crate) work: usize,
    /// True only after reaching the end without an outstanding candidate.
    pub(crate) complete: bool,
    /// Membership/layout changed since the preceding step. The cursor has
    /// restarted at slot zero, and any earlier completeness claim is stale.
    pub(crate) restarted: bool,
}

#[derive(Debug)]
pub enum CacheLoadError<E> {
    Admission(AdmissionError),
    Load(E),
}
impl<E> From<AdmissionError> for CacheLoadError<E> {
    fn from(error: AdmissionError) -> Self {
        Self::Admission(error)
    }
}

/// Cloneable immutable bytes with exact final-allocation retirement. No raw Arc
/// or Weak escapes this handle: the last release deallocates shared ownership
/// before refunding the payload and its aggregate credit.
pub struct CachedBytes(Option<Arc<Payload>>);

struct Payload {
    bytes: Vec<u8>,
    charge: u64,
    cache_owners: AtomicUsize,
    lease: PayloadLease,
}

enum PayloadLease {
    Pool(pool::Credit),
    Workspace(Option<NativeResidentLease>),
}

impl Drop for PayloadLease {
    fn drop(&mut self) {
        if let Self::Workspace(lease) = self
            && let Some(lease) = lease.take()
        {
            lease.retire();
        }
    }
}
impl CachedBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.payload().bytes
    }

    pub fn charged_bytes(&self) -> u64 {
        self.payload().charge
    }

    pub fn ptr_eq(left: &Self, right: &Self) -> bool {
        Arc::ptr_eq(left.0.as_ref().unwrap(), right.0.as_ref().unwrap())
    }

    fn payload(&self) -> &Payload {
        self.0.as_ref().expect("live payload handle")
    }

    fn new(payload: Payload) -> Self {
        Self(Some(Arc::new(payload)))
    }

    fn pool(&self) -> Option<&pool::Pool> {
        match &self.payload().lease {
            PayloadLease::Pool(credit) => Some(credit.pool()),
            PayloadLease::Workspace(_) => None,
        }
    }

    pub(crate) fn charge_for_len(len: usize) -> Option<u64> {
        // Arc's two counters and the entire byte owner, not just payload bytes.
        (len as u64)
            .checked_add((size_of::<Payload>() + 2 * size_of::<usize>()) as u64)
            .and_then(|bytes| {
                bytes
                    .checked_add(ALLOCATION_ALLOWANCE * (1 + u64::from(len != 0)) + LEASE_ALLOWANCE)
            })
    }
}
impl Clone for CachedBytes {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("live payload handle").clone()))
    }
}
impl Drop for CachedBytes {
    fn drop(&mut self) {
        if let Some(mut payload) = Arc::into_inner(self.0.take().expect("live payload handle")) {
            // The Arc allocation is already gone. Free the Vec before either
            // its inline credit or uncached workspace token can refund bytes.
            drop(take(&mut payload.bytes));
            drop(payload);
        }
    }
}

/// One charged directory identity's ownership of a shared immutable payload.
/// Moving an entry, including during rehash, moves this handle unchanged.
/// Reader Arcs do not create cache memberships. A payload's unique charge moves
/// from cached to pinned only when its last membership is actually dropped.
struct CachedOwner(CachedBytes);

impl CachedOwner {
    fn new(value: CachedBytes) -> Self {
        let accounting = value.pool().expect("retained payload owner");
        if value.payload().cache_owners.fetch_add(1, Ordering::AcqRel) == 0 {
            accounting.add_cached(value.charged_bytes());
        }
        Self(value)
    }

    fn externally_pinned(&self) -> bool {
        // Only a victim-selection hint; concurrent reader drops can change it.
        Arc::strong_count(self.0.0.as_ref().unwrap())
            > self.0.payload().cache_owners.load(Ordering::Acquire)
    }
}

impl Deref for CachedOwner {
    type Target = CachedBytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for CachedOwner {
    fn drop(&mut self) {
        if self.0.payload().cache_owners.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0
                .pool()
                .expect("retained payload owner")
                .remove_cached(self.0.charged_bytes());
        }
    }
}

struct Entry<K> {
    key: K,
    value: CachedOwner,
    previous: usize,
    next: usize,
    marked: bool,
    next_marked: Option<K>,
}

/// Byte-bounded LRU with a bounded, aging frequency sketch for admission.
///
/// Every fitting value is retained without frequency filtering. Only memory
/// pressure invokes admission: a one-pass scan cannot replace a more frequently
/// used LRU victim. The sketch ages, allowing a changed working set to enter.
/// The hash directory grows with resident entries and is charged before each
/// allocation. Growth temporarily holds both directories, each with a storage
/// admission; the enclosing workspace budget bounds that temporary overlap.
///
/// Methods require exclusive access. Readers can share returned immutable Arcs
/// across threads; their original admission remains charged after eviction.
/// Complete inline keys are included in the directory's byte charge. A key
/// containing references must have its referenced backing charged by its owner.
pub struct NativeCache<K = u64> {
    config: CacheConfig,
    admission: Arc<dyn StorageAdmission>,
    accounting: Option<pool::Pool>,
    slots: Vec<Option<Entry<K>>>,
    slots_lease: Option<pool::Credit>,
    slots_charge: u64,
    entries: usize,
    head: usize,
    tail: usize,
    sketch: [u8; SKETCH_WIDTH * SKETCH_ROWS],
    samples: u64,
    counters: CacheStats,
    maintenance_provider_denials: u64,
    maintenance_provider_refused: bool,
    // Never wrap and make an old externally held proof appear current.
    // Exhaustion permanently disables traversal and conditional removal.
    structural_version: Option<u64>,
    publication_active: bool,
    publication_head: Option<K>,
    publication_marked: usize,
    publication_pending: Option<K>,
}

impl<K: Copy + Eq + Hash> NativeCache<K> {
    /// Does not allocate or reserve capacity until a value can be retained.
    /// The enclosing owner remains responsible for the inline cache object;
    /// active cache accounting additionally includes that object's full size.
    pub fn new(config: CacheConfig, admission: Arc<dyn StorageAdmission>) -> Self {
        Self {
            config,
            admission,
            accounting: None,
            slots: Vec::new(),
            slots_lease: None,
            slots_charge: 0,
            entries: 0,
            head: NONE,
            tail: NONE,
            sketch: [0; SKETCH_WIDTH * SKETCH_ROWS],
            samples: 0,
            counters: CacheStats::default(),
            maintenance_provider_denials: 0,
            maintenance_provider_refused: false,
            structural_version: Some(1),
            publication_active: false,
            publication_head: None,
            publication_marked: 0,
            publication_pending: None,
        }
    }

    pub fn config(&self) -> CacheConfig {
        self.config
    }

    /// Actual provider refusals while retaining maintenance payloads/metadata.
    /// Local cache limits, allocator failures and optional metadata trimming do
    /// not count. Saturation never wraps. Scheduling uses the exact item-local
    /// flag below so saturation cannot stall successfully retained items.
    #[cfg(test)]
    pub(crate) fn maintenance_provider_denials(&self) -> u64 {
        self.maintenance_provider_denials
    }

    /// Exact item-local evidence for a serialized maintenance caller. Clear
    /// before examining the item, then consume after its optional fill. Unlike
    /// the diagnostic counter, this cannot lose a refusal at saturation.
    pub(crate) fn take_maintenance_provider_refusal(&mut self) -> bool {
        std::mem::take(&mut self.maintenance_provider_refused)
    }

    fn map_pool_error(&mut self, error: pool::BorrowError, maintenance: bool) -> AdmissionError {
        match error {
            pool::BorrowError::Limit => AdmissionError::CapacityDenied,
            pool::BorrowError::Provider(error) => {
                if maintenance && error == AdmissionError::CapacityDenied {
                    self.maintenance_provider_refused = true;
                    self.maintenance_provider_denials =
                        self.maintenance_provider_denials.saturating_add(1);
                }
                error
            }
        }
    }

    fn ensure_pool(&mut self, maintenance: bool) -> Result<(), AdmissionError> {
        if let Some(pool) = &self.accounting {
            pool.set_limit(self.config.byte_limit);
            return Ok(());
        }
        let pool = pool::Pool::new(
            &self.admission,
            Self::metadata_base_charge(),
            self.config.byte_limit,
        )
        .map_err(|error| self.map_pool_error(error, maintenance))?;
        self.accounting = Some(pool);
        Ok(())
    }

    fn reserve_pool(
        &mut self,
        bytes: u64,
        payload: bool,
        maintenance: bool,
    ) -> Result<pool::Credit, AdmissionError> {
        self.ensure_pool(maintenance)?;
        self.accounting
            .as_ref()
            .expect("initialized pool")
            .borrow(self.admission.as_ref(), bytes, payload)
            .map_err(|error| self.map_pool_error(error, maintenance))
    }

    pub fn stats(&self) -> CacheStats {
        let pool = self
            .accounting
            .as_ref()
            .map_or_else(Default::default, pool::Pool::stats);
        CacheStats {
            entries: self.entries,
            resident_bytes: pool.charged,
            cached_bytes: pool.cached_values,
            pinned_bytes: pool.live_values.saturating_sub(pool.cached_values),
            metadata_bytes: pool.used - pool.live_values,
            allocated_bytes: pool.used,
            admitted_credit_bytes: pool.credit,
            unused_credit_bytes: pool.credit - pool.used,
            provider_overhead_bytes: pool.charged - pool.credit,
            ..self.counters
        }
    }

    /// A shrinking budget releases infrequently used, older values first and
    /// shrinks directory backing. If readers still pin more than the new
    /// budget, return denial and keep the previous limit.
    pub fn set_byte_limit(&mut self, byte_limit: u64) -> Result<(), AdmissionError> {
        self.require_no_publication()?;
        let previous_limit = self.config.byte_limit;
        let result = self.set_byte_limit_inner(byte_limit);
        if result.is_err() {
            // A resize may fail before the final fit check, including during
            // metadata replacement. Restore the pool's borrow limit on every
            // error; existing guards retain their charge throughout cleanup.
            if let Some(pool) = &self.accounting {
                pool.set_limit(previous_limit);
            }
        }
        result
    }

    fn set_byte_limit_inner(&mut self, byte_limit: u64) -> Result<(), AdmissionError> {
        if byte_limit == 0 && self.stats().resident_bytes != 0 {
            self.clear();
        }
        if let Some(pool) = &self.accounting {
            pool.set_limit(byte_limit);
        }
        if self.stats().resident_bytes > byte_limit {
            self.shrink_directory()?;
        }
        // Configuration changes are uncommon. Two bounded passes through the
        // sketch's frequency levels avoid allocating a victim list or sorting
        // all keys. Within each frequency, preserve the most recent entries.
        // Releasing pinned lookup ownership is a last resort: only directory
        // backing can be reclaimed from those entries.
        for remove_pinned in [false, true] {
            for frequency in 0..=u8::MAX {
                if self.stats().resident_bytes <= byte_limit {
                    break;
                }
                let mut index = self.head;
                while index != NONE && self.stats().resident_bytes > byte_limit {
                    let entry = self.slots[index].as_ref().unwrap();
                    let next_key =
                        (entry.next != NONE).then(|| self.slots[entry.next].as_ref().unwrap().key);
                    if self.frequency(entry.key) == frequency
                        && (remove_pinned || !entry.value.externally_pinned())
                    {
                        self.remove_slot(index);
                        self.counters.evictions = self.counters.evictions.saturating_add(1);
                        self.shrink_directory()?;
                    }
                    index = next_key.and_then(|key| self.find(key)).unwrap_or(NONE);
                }
            }
        }
        if self.stats().resident_bytes > byte_limit {
            return Err(AdmissionError::CapacityDenied);
        }
        self.config.byte_limit = byte_limit;
        Ok(())
    }

    /// Release lookup ownership and directory capacity, preserving reader pins.
    pub fn clear(&mut self) {
        assert!(
            !self.publication_active,
            "publication candidates are active"
        );
        self.bump_structure();
        self.slots = Vec::new();
        self.slots_lease = None;
        self.slots_charge = 0;
        self.entries = 0;
        self.head = NONE;
        self.tail = NONE;
        self.sketch.fill(0);
        self.samples = 0;
        self.release_unused_accounting();
    }

    /// Remove an identity before its physical address can be reused.
    pub fn remove(&mut self, key: K) -> bool {
        assert!(
            !self.publication_active,
            "publication candidates are active"
        );
        if let Some(index) = self.find(key) {
            self.remove_slot(index);
            true
        } else {
            false
        }
    }

    /// Release unreachable identities without allocating a list of keys.
    /// Existing output guards keep their bytes and admission until dropped.
    pub(crate) fn remove_matching(
        &mut self,
        mut remove: impl FnMut(K) -> bool,
    ) -> Result<usize, AdmissionError> {
        self.require_no_publication()?;
        let mut index = 0;
        let mut removed = 0;
        while index < self.slots.len() {
            if self.slots[index]
                .as_ref()
                .is_some_and(|entry| remove(entry.key))
            {
                self.remove_slot(index);
                removed += 1;
            } else {
                index += 1;
            }
        }
        if self.entries == 0 {
            self.clear();
        } else if removed != 0 {
            self.shrink_directory()?;
        }
        Ok(removed)
    }

    /// A membership check without altering frequency, recency or statistics.
    pub fn contains(&self, key: K) -> bool {
        self.find(key).is_some()
    }

    /// Start one serialized publication's intrusive candidate chain. The
    /// inline scope and complete-key entry links are included in the ordinary
    /// cache/slot charges. Beginning, marking and draining allocate nothing.
    pub(crate) fn begin_publication_candidates(&mut self) -> Result<(), AdmissionError> {
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        self.require_no_publication()?;
        if self.structural_version.is_none()
            || self.publication_head.is_some()
            || self.publication_marked != 0
        {
            return Err(AdmissionError::OwnerFailed);
        }
        self.publication_active = true;
        self.publication_pending = None;
        Ok(())
    }

    /// Mark an existing identity without training policy or retaining a miss.
    /// True means resident, including an identity already marked in this scope.
    pub(crate) fn mark_publication_candidate(&mut self, key: K) -> Result<bool, AdmissionError> {
        self.check_publication()?;
        let Some(index) = self.find(key) else {
            return Ok(false);
        };
        let entry = self.slots[index].as_mut().unwrap();
        if !entry.marked {
            if self.publication_marked >= self.entries {
                return Err(AdmissionError::OwnerFailed);
            }
            entry.marked = true;
            entry.next_marked = self.publication_head;
            self.publication_head = Some(key);
            self.publication_marked += 1;
        }
        Ok(true)
    }

    /// Remove one mark, retaining the exact identity and immutable payload for
    /// an external reachability proof. Scope membership stays frozen until
    /// clear_publication_candidates; only removal of this popped candidate is
    /// allowed. Complete-key links survive backward shifts and directory moves.
    pub(crate) fn pop_publication_candidate(
        &mut self,
    ) -> Result<Option<CacheCandidate<K>>, AdmissionError> {
        self.check_publication()?;
        let Some(key) = self.publication_head else {
            if self.publication_marked != 0 {
                return Err(AdmissionError::OwnerFailed);
            }
            self.publication_pending = None;
            return Ok(None);
        };
        let slot = self.find(key).ok_or(AdmissionError::OwnerFailed)?;
        let entry = self.slots[slot].as_mut().unwrap();
        if !entry.marked || self.publication_marked == 0 {
            return Err(AdmissionError::OwnerFailed);
        }
        self.publication_head = entry.next_marked.take();
        self.publication_marked -= 1;
        entry.marked = false;
        self.publication_pending = Some(key);
        Ok(Some(CacheCandidate {
            key,
            bytes: entry.value.clone(),
            version: self.structural_version.unwrap(),
            slot,
        }))
    }

    /// Abort or finish a scope without removing entries or changing policy.
    /// Cleanup still clears marks after owner failure. A damaged chain gets a
    /// bounded fallback cleanup and permanently disables proof-based removal;
    /// it cannot loop, panic or silently authorize an incomplete publication.
    pub(crate) fn clear_publication_candidates(&mut self) -> Result<(), AdmissionError> {
        let cleanup = self.cleanup_publication_candidates();
        // No marks remain even if this arbitrary provider callback unwinds.
        let owner = self
            .admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed);
        cleanup.and(owner)
    }

    /// Drop/error cleanup only: never invoke admission or any caller callback.
    /// This does not serve data, alter membership or authorize physical reuse.
    pub(crate) fn cleanup_publication_candidates(&mut self) -> Result<(), AdmissionError> {
        let mut damaged = false;
        for _ in 0..self.publication_marked.min(self.entries) {
            let Some(index) = self.publication_head.and_then(|key| self.find(key)) else {
                damaged = true;
                break;
            };
            let entry = self.slots[index].as_mut().unwrap();
            if !entry.marked {
                damaged = true;
                break;
            }
            entry.marked = false;
            self.publication_head = entry.next_marked.take();
        }
        damaged |= self.publication_head.is_some() || self.publication_marked > self.entries;
        if damaged {
            for entry in self.slots.iter_mut().flatten() {
                entry.marked = false;
                entry.next_marked = None;
            }
            self.structural_version = None;
        }
        self.publication_active = false;
        self.publication_head = None;
        self.publication_marked = 0;
        self.publication_pending = None;
        if damaged || self.structural_version.is_none() {
            Err(AdmissionError::OwnerFailed)
        } else {
            Ok(())
        }
    }

    /// Remove a proved identity only if its complete key and payload owner
    /// still match. Unlike a slot cursor, this survives unrelated slot shifts.
    /// Within a publication only its most recently popped candidate may leave.
    pub(crate) fn remove_if_unchanged(
        &mut self,
        candidate: &CacheCandidate<K>,
    ) -> Result<bool, AdmissionError> {
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let version = self.structural_version.ok_or(AdmissionError::OwnerFailed)?;
        if self.publication_active && self.publication_pending != Some(candidate.key) {
            return Ok(false);
        }
        let Some(index) = self.find(candidate.key) else {
            return Ok(false);
        };
        let entry = self.slots[index].as_ref().unwrap();
        if entry.marked || !CachedBytes::ptr_eq(&entry.value, &candidate.bytes) {
            return Ok(false);
        }
        if version == u64::MAX {
            self.structural_version = None;
            return Err(AdmissionError::OwnerFailed);
        }
        self.remove_slot(index);
        self.publication_pending = None;
        Ok(true)
    }

    fn check_publication(&self) -> Result<(), AdmissionError> {
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if !self.publication_active || self.structural_version.is_none() {
            Err(AdmissionError::OwnerFailed)
        } else {
            Ok(())
        }
    }

    fn require_no_publication(&self) -> Result<(), AdmissionError> {
        if self.publication_active {
            Err(AdmissionError::OwnerFailed)
        } else {
            Ok(())
        }
    }

    /// Inspect at most `max_slots` slots and return at most one retained
    /// identity. This allocates nothing, does not load data and does not touch
    /// demand counters, frequency or recency. The caller releases its cache
    /// lock before a disk-backed reachability proof. On a stable pass, a kept
    /// candidate is followed by the next slot; a removed one is revisited so
    /// backward-shift deletion cannot hide its replacement.
    pub(crate) fn candidate_step(
        &self,
        cursor: &mut CacheCursor,
        max_slots: usize,
    ) -> Result<CacheCandidateStep<K>, AdmissionError> {
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let version = self.structural_version.ok_or(AdmissionError::OwnerFailed)?;
        let restarted = cursor.version.is_some_and(|old| old != version);
        if cursor.version != Some(version) {
            *cursor = CacheCursor {
                version: Some(version),
                next_slot: 0,
            };
        }
        let mut work = 0;
        while work < max_slots && cursor.next_slot < self.slots.len() {
            let slot = cursor.next_slot;
            cursor.next_slot += 1;
            work += 1;
            if let Some(entry) = &self.slots[slot] {
                return Ok(CacheCandidateStep {
                    candidate: Some(CacheCandidate {
                        key: entry.key,
                        bytes: entry.value.clone(),
                        version,
                        slot,
                    }),
                    work,
                    complete: false,
                    restarted,
                });
            }
        }
        Ok(CacheCandidateStep {
            candidate: None,
            work,
            complete: cursor.next_slot == self.slots.len(),
            restarted,
        })
    }

    /// Remove only the exact candidate most recently returned by this cursor
    /// while its structure version, slot, full key and payload owner still
    /// match. The caller must already have proved that identity dispensable
    /// under the current selected root and pins. False leaves both ownership
    /// and cursor unchanged; the next step detects structural invalidation.
    /// This releases one alias only, preserving other aliases/output guards.
    pub(crate) fn remove_candidate(
        &mut self,
        cursor: &mut CacheCursor,
        candidate: &CacheCandidate<K>,
    ) -> Result<bool, AdmissionError> {
        self.require_no_publication()?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let version = self.structural_version.ok_or(AdmissionError::OwnerFailed)?;
        if version != candidate.version
            || cursor.version != Some(version)
            || cursor.next_slot != candidate.slot + 1
            || !self.slots.get(candidate.slot).is_some_and(|entry| {
                entry.as_ref().is_some_and(|entry| {
                    entry.key == candidate.key
                        && CachedBytes::ptr_eq(&entry.value, &candidate.bytes)
                })
            })
        {
            return Ok(false);
        }
        // Reserve the next version before removing anything, so exhaustion
        // cannot turn an externally held candidate into a valid old token.
        if version == u64::MAX {
            self.structural_version = None;
            return Err(AdmissionError::OwnerFailed);
        }
        self.remove_slot(candidate.slot);
        cursor.version = self.structural_version;
        cursor.next_slot = candidate.slot;
        Ok(true)
    }

    /// Attempt to release excess hash-directory backing after a completed
    /// prune pass. Optional allocation denial keeps the existing valid table
    /// for a later retry. A successful resize invalidates old slot cursors;
    /// it preserves payload ownership, LRU order and demand-policy counters.
    pub(crate) fn trim_metadata(&mut self) -> Result<(), AdmissionError> {
        self.require_no_publication()?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        self.shrink_directory()?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)
    }

    /// Finish a warm-up prune phase only after excess backing is released.
    /// Unlike publication's optional trim, provider refusal remains retryable:
    /// otherwise excess backing could make a fitting union look permanently
    /// larger than the local cache limit. The caller keeps its exhausted slot
    /// cursor and retries this bounded replacement without rescanning entries.
    pub(crate) fn trim_metadata_for_warm(&mut self) -> Result<(), AdmissionError> {
        self.require_no_publication()?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        self.shrink_directory_inner()?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)
    }

    /// Preserve a cached value across an immutable physical relocation.
    /// Invalidate the destination even when the source was not resident.
    /// This operation allocates no memory and preserves the source's LRU rank.
    pub fn relocate(&mut self, old_key: K, new_key: K) {
        assert!(
            !self.publication_active,
            "publication candidates are active"
        );
        if old_key == new_key {
            return;
        }
        self.remove(new_key);
        let Some(index) = self.find(old_key) else {
            return;
        };
        let frequency = self.frequency(old_key);
        let successor = self.slots[index].as_ref().unwrap().next;
        let successor_key =
            (successor != NONE).then(|| self.slots[successor].as_ref().unwrap().key);
        let mut entry = self.take_slot(index);
        entry.key = new_key;
        self.insert(entry);
        if let Some(successor_key) = successor_key {
            let successor = self.find(successor_key).unwrap();
            let index = self.tail;
            let previous = self.slots[index].as_ref().unwrap().previous;
            self.slots[previous].as_mut().unwrap().next = NONE;
            self.tail = previous;
            let previous = self.slots[successor].as_ref().unwrap().previous;
            self.slots[successor].as_mut().unwrap().previous = index;
            if previous == NONE {
                self.head = index;
            } else {
                self.slots[previous].as_mut().unwrap().next = index;
            }
            let entry = self.slots[index].as_mut().unwrap();
            entry.previous = previous;
            entry.next = successor;
        }
        for row in 0..SKETCH_ROWS {
            let index = Self::sketch_index(new_key, row);
            self.sketch[index] = self.sketch[index].max(frequency);
        }
    }

    /// Share one immutable payload between both addresses after a physical copy.
    /// Only the additional identity metadata needs capacity/admission. Otherwise
    /// move the cached identity, preserving hot current reads and output guards.
    /// The caller establishes byte equality through successful relocation; keys
    /// alone never authorize sharing. Never evict unrelated entries or load a
    /// cold source to populate this cache.
    pub(crate) fn copy_relocated(
        &mut self,
        old_key: K,
        new_key: K,
    ) -> Result<bool, AdmissionError> {
        self.require_no_publication()?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if self.contains(new_key) {
            return Ok(true);
        }
        if !self.contains(old_key) {
            return Ok(false);
        }
        let frequency = self.frequency(old_key);
        if self.alias_if_fits(old_key, new_key)? {
            for row in 0..SKETCH_ROWS {
                let index = Self::sketch_index(new_key, row);
                self.sketch[index] = self.sketch[index].max(frequency);
            }
        } else {
            self.relocate(old_key, new_key);
        }
        Ok(true)
    }

    /// Add an immutable identity alias using only spare metadata capacity.
    /// The caller proves that both identities denote the same immutable bytes.
    /// No payload allocation, eviction, relocation or demand-policy training
    /// occurs. An already retained destination succeeds without modification;
    /// absent sources and optional capacity/admission denial return false.
    pub(crate) fn alias_if_fits(&mut self, old_key: K, new_key: K) -> Result<bool, AdmissionError> {
        self.require_no_publication()?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if self.contains(new_key) {
            return Ok(true);
        }
        let Some(index) = self.find(old_key) else {
            return Ok(false);
        };
        let source = self.slots[index].as_ref().unwrap().value.clone();
        // The payload is already charged once. Preflight prevents prepare
        // from evicting while it admits only possible directory growth.
        let retain = if self.fits_without_eviction(0)? {
            self.prepare(new_key, 0, true)
        } else {
            Ok(false)
        };
        match retain {
            Ok(true) => {
                self.admission
                    .check_owner()
                    .map_err(|_| AdmissionError::OwnerFailed)?;
                self.insert(Entry {
                    key: new_key,
                    value: CachedOwner::new(source),
                    previous: NONE,
                    next: NONE,
                    marked: false,
                    next_marked: None,
                });
                Ok(true)
            }
            Ok(false) | Err(AdmissionError::CapacityDenied) => {
                self.admission
                    .check_owner()
                    .map_err(|_| AdmissionError::OwnerFailed)?;
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// Inspect residency without training frequency, touching recency or
    /// changing demand counters. The caller must check its current owner and
    /// authorization before using this unchecked lookup.
    pub(crate) fn peek(&self, key: K) -> Option<CachedBytes> {
        self.find(key)
            .map(|index| self.slots[index].as_ref().unwrap().value.clone())
    }

    /// Optional maintenance fill with no eviction or demand-policy training.
    /// Reject insufficient cache/admission capacity before invoking `loader`.
    /// Existing identities return their bytes without changing recency or
    /// counters; a new entry is appended without changing existing LRU order.
    pub(crate) fn load_if_fits<E>(
        &mut self,
        key: K,
        len: usize,
        loader: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Option<CachedBytes>, CacheLoadError<E>> {
        self.require_no_publication()?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if let Some(value) = self.peek(key) {
            return Ok(Some(value));
        }
        let Some(charge) = CachedBytes::charge_for_len(len) else {
            return Ok(None);
        };
        if !self.fits_without_eviction(charge)? {
            return Ok(None);
        }
        let lease = match self.reserve_pool(charge, true, true) {
            Ok(lease) => lease,
            Err(AdmissionError::CapacityDenied) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(len).is_err() || bytes.capacity() != len {
            return Ok(None);
        }
        bytes.resize(len, 0);
        // Allocate the payload before changing directory backing, so denied
        // payload capacity cannot leave a larger directory after relocation
        // falls back to moving its existing identity. The preflight covers all
        // metadata growth and retained pins; concurrent guard drops only free
        // capacity, so prepare cannot need eviction under exclusive access.
        // Its inline pool credit already counts the uncommitted payload.
        match self.prepare(key, 0, true) {
            Ok(true) => {}
            Ok(false) | Err(AdmissionError::CapacityDenied) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        loader(&mut bytes).map_err(CacheLoadError::Load)?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let value = CachedBytes::new(Payload {
            bytes,
            charge,
            cache_owners: AtomicUsize::new(0),
            lease: PayloadLease::Pool(lease),
        });
        self.insert(Entry {
            key,
            value: CachedOwner::new(value.clone()),
            previous: NONE,
            next: NONE,
            marked: false,
            next_marked: None,
        });
        Ok(Some(value))
    }

    fn fits_without_eviction(&self, charge: u64) -> Result<bool, AdmissionError> {
        let capacity = if self.slots.is_empty() {
            Some(MIN_SLOTS)
        } else if self.entries + 1 > self.slots.len() / 2 {
            self.slots.len().checked_mul(2)
        } else {
            Some(self.slots.len())
        };
        let Some(add) = capacity
            .and_then(Self::slots_charge)
            .and_then(|metadata| metadata.checked_add(charge))
        else {
            return Ok(false);
        };
        self.fits_charges(self.slots_charge, add)
    }

    fn fits_charges(&self, remove: u64, add: u64) -> Result<bool, AdmissionError> {
        if let Some(pool) = &self.accounting {
            return Ok(pool.fits(remove, add, self.config.byte_limit));
        }
        let Some(credit) = Self::metadata_base_charge().checked_add(add) else {
            return Ok(false);
        };
        self.quoted_credit_fits(credit)
    }

    fn quoted_credit_fits(&self, credit: u64) -> Result<bool, AdmissionError> {
        match self.admission.quote_cache_memory(credit) {
            Ok(quote) => Ok(quote.charged_bytes() <= self.config.byte_limit),
            Err(AdmissionError::CapacityDenied) => Ok(false),
            // A failed quote is still an owner failure even when a later
            // check_owner call would succeed. Never turn it into a cache miss.
            Err(error) => Err(error),
        }
    }

    /// The caller must check its current owner and authorization before using
    /// this unchecked lookup. `load` additionally checks physical ownership.
    pub fn get(&mut self, key: K) -> Option<CachedBytes> {
        self.record_access(key);
        let Some(index) = self.find(key) else {
            self.counters.misses = self.counters.misses.saturating_add(1);
            return None;
        };
        self.counters.hits = self.counters.hits.saturating_add(1);
        self.touch(index);
        Some(self.slots[index].as_ref().unwrap().value.clone())
    }

    /// Load exactly `len` bytes on a miss, reserving before allocating. A failed
    /// loader never installs an entry. Optional retention can be bypassed on a
    /// cache budget or metadata-capacity denial, while an owner failure always
    /// propagates. The returned request buffer itself must obtain admission.
    pub fn load<E>(
        &mut self,
        key: K,
        len: usize,
        loader: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<CachedBytes, CacheLoadError<E>> {
        self.require_no_publication()?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if let Some(value) = self.get(key) {
            return Ok(value);
        }
        let charge = CachedBytes::charge_for_len(len).ok_or(AdmissionError::CapacityDenied)?;
        let mut retain = match self.prepare(key, charge, false) {
            Ok(retain) => retain,
            Err(AdmissionError::CapacityDenied) => false,
            Err(error) => return Err(error.into()),
        };
        let lease = if retain {
            match self.reserve_pool(charge, true, false) {
                Ok(credit) => PayloadLease::Pool(credit),
                Err(AdmissionError::CapacityDenied) => {
                    retain = false;
                    PayloadLease::Workspace(Some(
                        self.admission
                            .reserve_workspace(charge)
                            .map(NativeResidentLease::new)?,
                    ))
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            PayloadLease::Workspace(Some(
                self.admission
                    .reserve_workspace(charge)
                    .map(NativeResidentLease::new)?,
            ))
        };
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| AdmissionError::CapacityDenied)?;
        // Vec's requested capacity is exact for the global allocator. Refuse
        // retention if an allocator ever reports a larger logical capacity;
        // do not silently leave those bytes outside the admitted footprint.
        if bytes.capacity() != len {
            return Err(AdmissionError::CapacityDenied.into());
        }
        bytes.resize(len, 0);
        loader(&mut bytes).map_err(CacheLoadError::Load)?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        self.counters.loads = self.counters.loads.saturating_add(1);
        if !retain {
            self.counters.uncached_loads = self.counters.uncached_loads.saturating_add(1);
        }
        let value = CachedBytes::new(Payload {
            bytes,
            charge,
            cache_owners: AtomicUsize::new(0),
            lease,
        });
        if retain {
            self.insert(Entry {
                key,
                value: CachedOwner::new(value.clone()),
                previous: NONE,
                next: NONE,
                marked: false,
                next_marked: None,
            });
        }
        Ok(value)
    }

    /// Use normal demand policy, retaining a miss when optional cache backing
    /// fits. Otherwise fill the caller's already-admitted destination directly,
    /// without allocating a temporary CachedBytes workspace. Some leaves the
    /// destination unchanged and lends an immutable cached owner; the caller
    /// must validate its exact length/identity before copying. None means the
    /// loader filled the destination. The loader is entered at most once.
    pub(crate) fn load_or_read_into<E>(
        &mut self,
        key: K,
        destination: &mut [u8],
        loader: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Option<CachedBytes>, CacheLoadError<E>> {
        self.require_no_publication()?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if let Some(value) = self.get(key) {
            return Ok(Some(value));
        }
        if let Some(charge) = CachedBytes::charge_for_len(destination.len()) {
            let retain = match self.prepare(key, charge, false) {
                Ok(retain) => retain,
                Err(AdmissionError::CapacityDenied) => false,
                Err(error) => return Err(error.into()),
            };
            let credit = if retain {
                match self.reserve_pool(charge, true, false) {
                    Ok(credit) => Some(credit),
                    Err(AdmissionError::CapacityDenied) => None,
                    Err(error) => return Err(error.into()),
                }
            } else {
                None
            };
            if let Some(credit) = credit {
                let mut bytes = Vec::new();
                if bytes.try_reserve_exact(destination.len()).is_ok()
                    && bytes.capacity() == destination.len()
                {
                    bytes.resize(destination.len(), 0);
                    loader(&mut bytes).map_err(CacheLoadError::Load)?;
                    self.admission
                        .check_owner()
                        .map_err(|_| AdmissionError::OwnerFailed)?;
                    self.counters.loads = self.counters.loads.saturating_add(1);
                    let value = CachedBytes::new(Payload {
                        bytes,
                        charge,
                        cache_owners: AtomicUsize::new(0),
                        lease: PayloadLease::Pool(credit),
                    });
                    self.insert(Entry {
                        key,
                        value: CachedOwner::new(value.clone()),
                        previous: NONE,
                        next: NONE,
                        marked: false,
                        next_marked: None,
                    });
                    return Ok(Some(value));
                }
                // A failed optional allocation may still own backing. Retire
                // that actual Vec before returning its real pool credit.
                drop(bytes);
                drop(credit);
            }
        }
        // A refused optional reservation may coincide with owner expiry.
        // Only capacity is optional; never hide a failed owner as a cache miss.
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        loader(destination).map_err(CacheLoadError::Load)?;
        self.admission
            .check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        self.record_uncached_load();
        Ok(None)
    }

    /// Account for a successful direct read into a caller-owned admitted
    /// buffer after optional cache backing was refused. The failed lookup
    /// already recorded its miss; no cache allocation or entry was retained.
    pub(crate) fn record_uncached_load(&mut self) {
        self.counters.loads = self.counters.loads.saturating_add(1);
        self.counters.uncached_loads = self.counters.uncached_loads.saturating_add(1);
    }

    fn metadata_base_charge() -> u64 {
        size_of::<Self>() as u64 + pool::Pool::backing_bytes() + ALLOCATION_ALLOWANCE
    }

    fn slots_charge(capacity: usize) -> Option<u64> {
        capacity
            .checked_mul(size_of::<Option<Entry<K>>>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| bytes.checked_add(ALLOCATION_ALLOWANCE + LEASE_ALLOWANCE))
    }

    fn shrink_directory(&mut self) -> Result<(), AdmissionError> {
        match self.shrink_directory_inner() {
            Ok(()) | Err(AdmissionError::CapacityDenied) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn shrink_directory_inner(&mut self) -> Result<(), AdmissionError> {
        if self.entries == 0 {
            if !self.slots.is_empty() {
                self.bump_structure();
            }
            self.slots = Vec::new();
            self.slots_lease = None;
            self.slots_charge = 0;
            self.release_unused_accounting();
            return Ok(());
        }
        let capacity = (self.entries * 2).max(MIN_SLOTS).next_power_of_two();
        if capacity < self.slots.len() {
            let charge = Self::slots_charge(capacity).ok_or(AdmissionError::CapacityDenied)?;
            self.resize_slots(capacity, charge)?;
        }
        Ok(())
    }

    fn release_unused_accounting(&mut self) {
        if self.slots.is_empty()
            && self
                .accounting
                .as_ref()
                .is_some_and(|accounting| accounting.stats().live_values == 0)
        {
            self.accounting = None;
        }
    }

    fn prepare(&mut self, key: K, charge: u64, maintenance: bool) -> Result<bool, AdmissionError> {
        self.release_unused_accounting();
        let minimum = Self::metadata_base_charge()
            .checked_add(Self::slots_charge(MIN_SLOTS).unwrap())
            .and_then(|bytes| bytes.checked_add(charge));
        let fits = match minimum {
            Some(credit) => self.quoted_credit_fits(credit)?,
            None => false,
        };
        if !fits {
            return Ok(false);
        }
        self.ensure_pool(maintenance)?;
        loop {
            let required_slots = if self.slots.is_empty() {
                MIN_SLOTS
            } else if self.entries + 1 > self.slots.len() / 2 {
                self.slots
                    .len()
                    .checked_mul(2)
                    .ok_or(AdmissionError::CapacityDenied)?
            } else {
                self.slots.len()
            };
            let next_slots_charge =
                Self::slots_charge(required_slots).ok_or(AdmissionError::CapacityDenied)?;
            let fits = match next_slots_charge.checked_add(charge) {
                Some(add) => self.fits_charges(self.slots_charge, add)?,
                None => false,
            };
            if fits {
                if required_slots != self.slots.len() {
                    self.resize_slots_observed(required_slots, next_slots_charge, maintenance)?;
                }
                return Ok(true);
            }
            if self.head == NONE {
                // Pins may retain all bytes even though the lookup is empty.
                return Ok(false);
            }
            let victim = self.slots[self.head].as_ref().unwrap().key;
            if self.frequency(key) < self.frequency(victim) {
                return Ok(false);
            }
            self.remove_slot(self.head);
            self.counters.evictions = self.counters.evictions.saturating_add(1);
        }
    }

    fn resize_slots(&mut self, capacity: usize, charge: u64) -> Result<(), AdmissionError> {
        self.resize_slots_observed(capacity, charge, false)
    }

    fn resize_slots_observed(
        &mut self,
        capacity: usize,
        charge: u64,
        maintenance: bool,
    ) -> Result<(), AdmissionError> {
        let admission = self.admission.clone();
        let mut new_lease = None;
        let mut overlap = None;
        let allocate = || -> Result<Vec<Option<Entry<K>>>, AdmissionError> {
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(capacity)
                .map_err(|_| AdmissionError::CapacityDenied)?;
            if slots.capacity() != capacity {
                return Err(AdmissionError::CapacityDenied);
            }
            slots.resize_with(capacity, || None);
            admission
                .check_owner()
                .map_err(|_| AdmissionError::OwnerFailed)?;
            Ok(slots)
        };
        let slots = if self.slots_lease.is_some() {
            // Transfer old backing to admitted temporary custody before
            // exchanging its pool credit. This optional-cache reservation
            // bypasses protected audit escrow and covers real rehash overlap.
            admission
                .check_owner()
                .map_err(|_| AdmissionError::OwnerFailed)?;
            let temporary = admission.clone().reserve_cache_memory(self.slots_charge);
            // A refused overlap admission may expire the physical owner.
            // Classify expiry before optional-pressure handling can hide it.
            admission
                .check_owner()
                .map_err(|_| AdmissionError::OwnerFailed)?;
            let temporary = temporary.map_err(|error| {
                self.map_pool_error(pool::BorrowError::Provider(error), maintenance)
            })?;
            let exchange = self
                .slots_lease
                .as_mut()
                .unwrap()
                .exchange(admission.as_ref(), charge);
            let exchange = match exchange {
                Ok(exchange) => exchange,
                Err(error) => {
                    return Err(match error {
                        pool::BorrowError::Limit => AdmissionError::CapacityDenied,
                        pool::BorrowError::Provider(error) => {
                            if maintenance && error == AdmissionError::CapacityDenied {
                                self.maintenance_provider_refused = true;
                                self.maintenance_provider_denials =
                                    self.maintenance_provider_denials.saturating_add(1);
                            }
                            error
                        }
                    });
                }
            };
            let slots = allocate()?;
            exchange.commit();
            overlap = Some(temporary);
            slots
        } else {
            let lease = self.reserve_pool(charge, false, maintenance)?;
            let slots = allocate()?;
            new_lease = Some(lease);
            slots
        };
        self.bump_structure();
        let mut old = std::mem::replace(&mut self.slots, slots);
        if let Some(lease) = new_lease {
            self.slots_lease = Some(lease);
        }
        self.slots_charge = charge;
        let mut index = self.head;
        self.entries = 0;
        self.head = NONE;
        self.tail = NONE;
        while index != NONE {
            let mut entry = old[index].take().unwrap();
            index = entry.next;
            entry.previous = NONE;
            entry.next = NONE;
            self.insert(entry);
        }
        drop(old);
        drop(overlap);
        Ok(())
    }

    fn find(&self, key: K) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut index = key_hash(key) as usize & mask;
        loop {
            match &self.slots[index] {
                None => return None,
                Some(entry) if entry.key == key => return Some(index),
                Some(_) => index = (index + 1) & mask,
            }
        }
    }

    fn insert(&mut self, mut entry: Entry<K>) {
        self.bump_structure();
        let mask = self.slots.len() - 1;
        let mut index = key_hash(entry.key) as usize & mask;
        while self.slots[index].is_some() {
            index = (index + 1) & mask;
        }
        entry.previous = self.tail;
        entry.next = NONE;
        if self.tail != NONE {
            self.slots[self.tail].as_mut().unwrap().next = index;
        } else {
            self.head = index;
        }
        self.tail = index;
        self.entries += 1;
        self.slots[index] = Some(entry);
    }

    fn touch(&mut self, index: usize) {
        if index == self.tail {
            return;
        }
        let entry = self.slots[index].as_ref().unwrap();
        let previous = entry.previous;
        let next = entry.next;
        if previous == NONE {
            self.head = next;
        } else {
            self.slots[previous].as_mut().unwrap().next = next;
        }
        self.slots[next].as_mut().unwrap().previous = previous;
        self.slots[self.tail].as_mut().unwrap().next = index;
        let entry = self.slots[index].as_mut().unwrap();
        entry.previous = self.tail;
        entry.next = NONE;
        self.tail = index;
    }

    fn remove_slot(&mut self, index: usize) {
        drop(self.take_slot(index));
    }

    fn take_slot(&mut self, index: usize) -> Entry<K> {
        self.bump_structure();
        let entry = self.slots[index].take().unwrap();
        if entry.previous == NONE {
            self.head = entry.next;
        } else {
            self.slots[entry.previous].as_mut().unwrap().next = entry.next;
        }
        if entry.next == NONE {
            self.tail = entry.previous;
        } else {
            self.slots[entry.next].as_mut().unwrap().previous = entry.previous;
        }
        self.entries -= 1;
        // Backward-shift deletion avoids a tombstone directory growing with a
        // long scan. Update intrusive LRU links whenever an entry moves.
        let mask = self.slots.len() - 1;
        let mut hole = index;
        let mut scan = (hole + 1) & mask;
        while let Some(entry) = &self.slots[scan] {
            let home = key_hash(entry.key) as usize & mask;
            if scan.wrapping_sub(home) & mask > hole.wrapping_sub(home) & mask {
                let moved = self.slots[scan].take().unwrap();
                if moved.previous == NONE {
                    self.head = hole;
                } else {
                    self.slots[moved.previous].as_mut().unwrap().next = hole;
                }
                if moved.next == NONE {
                    self.tail = hole;
                } else {
                    self.slots[moved.next].as_mut().unwrap().previous = hole;
                }
                self.slots[hole] = Some(moved);
                hole = scan;
            }
            scan = (scan + 1) & mask;
        }
        entry
    }

    fn bump_structure(&mut self) {
        self.structural_version = self
            .structural_version
            .and_then(|version| version.checked_add(1));
    }

    fn record_access(&mut self, key: K) {
        self.samples += 1;
        if self.samples == SKETCH_SAMPLES {
            for count in &mut self.sketch {
                *count >>= 1;
            }
            self.samples = 0;
        }
        for row in 0..SKETCH_ROWS {
            let index = Self::sketch_index(key, row);
            self.sketch[index] = self.sketch[index].saturating_add(1);
        }
    }

    fn frequency(&self, key: K) -> u8 {
        (0..SKETCH_ROWS)
            .map(|row| self.sketch[Self::sketch_index(key, row)])
            .min()
            .unwrap()
    }

    fn sketch_index(key: K, row: usize) -> usize {
        row * SKETCH_WIDTH
            + (hash(key_hash(key).wrapping_add((row as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)))
                as usize
                & (SKETCH_WIDTH - 1))
    }
}

fn key_hash(key: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod pool_tests {
    include!("cache_pool_tests.rs");
}

fn hash(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    mod read_into {
        include!("cache_read_into_tests.rs");
    }
    use super::*;
    use crate::OwnerFailed;
    use std::sync::atomic::{AtomicBool, AtomicU64};

    struct Admission {
        used: Arc<AtomicU64>,
        limit: AtomicU64,
        failed: AtomicBool,
        fail_next_reserve: AtomicBool,
        fail_next_quote: AtomicBool,
        expire_after_reserve: AtomicBool,
        panic_next_check: AtomicBool,
    }
    struct Lease {
        used: Arc<AtomicU64>,
        bytes: u64,
    }
    struct CacheToken {
        admission: Arc<Admission>,
        bytes: u64,
    }
    impl crate::CacheMemoryReservation for CacheToken {
        fn try_grow(&mut self, bytes: u64) -> Result<(), AdmissionError> {
            self.admission.admit(bytes)?;
            self.bytes += bytes;
            Ok(())
        }
        fn retain_charge(&mut self, bytes: u64) {
            self.admission
                .used
                .fetch_sub(self.bytes - bytes, Ordering::AcqRel);
            self.bytes = bytes;
        }
    }
    impl Drop for CacheToken {
        fn drop(&mut self) {
            self.admission.used.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }

    #[test]
    fn maintenance_denial_signal_excludes_cache_limit_and_metadata_trim() {
        let admission = Admission::new(u64::MAX);
        let mut cache = NativeCache::<u64>::new(CacheConfig { byte_limit: 0 }, admission.clone());
        assert!(
            cache
                .load_if_fits(1, 64, |_| Ok::<_, ()>(()))
                .unwrap()
                .is_none()
        );
        assert_eq!(cache.maintenance_provider_denials(), 0);
        cache.set_byte_limit(1 << 20).unwrap();
        admission.limit.store(0, Ordering::Release);
        assert!(
            cache
                .load_if_fits(1, 64, |_| Ok::<_, ()>(()))
                .unwrap()
                .is_none()
        );
        assert_eq!(cache.maintenance_provider_denials(), 1);
        admission.limit.store(u64::MAX, Ordering::Release);
        for key in 0..9 {
            drop(
                cache
                    .load_if_fits(key, 64, |_| Ok::<_, ()>(()))
                    .unwrap()
                    .unwrap(),
            );
        }
        for key in 1..9 {
            cache.remove(key);
        }
        let metadata = cache.stats().metadata_bytes;
        admission.limit.store(admission.used(), Ordering::Release);
        cache.trim_metadata().unwrap();
        assert_eq!(cache.stats().metadata_bytes, metadata);
        assert_eq!(cache.maintenance_provider_denials(), 1);
        cache.maintenance_provider_denials = u64::MAX;
        assert!(
            cache
                .load_if_fits(99, 128 << 10, |_| Ok::<_, ()>(()))
                .unwrap()
                .is_none()
        );
        assert_eq!(cache.maintenance_provider_denials(), u64::MAX);
        assert!(cache.take_maintenance_provider_refusal());
        admission.limit.store(u64::MAX, Ordering::Release);
        assert!(
            cache
                .load_if_fits(99, 128 << 10, |_| Ok::<_, ()>(()))
                .unwrap()
                .is_some()
        );
        assert!(!cache.take_maintenance_provider_refusal());
        assert!(
            cache
                .load_if_fits(99, 128 << 10, |_| Ok::<_, ()>(()))
                .unwrap()
                .is_some()
        );
        assert!(!cache.take_maintenance_provider_refusal());
    }

    #[test]
    fn maintenance_alias_metadata_denial_records_provider_refusal_without_mutation() {
        let admission = Admission::new(u64::MAX);
        let mut cache = NativeCache::<u64>::new(
            CacheConfig {
                byte_limit: 1 << 20,
            },
            admission.clone(),
        );
        for key in 0..8 {
            drop(
                cache
                    .load_if_fits(key, 64, |_| Ok::<_, ()>(()))
                    .unwrap()
                    .unwrap(),
            );
        }
        let before = cache.stats();
        admission.limit.store(admission.used(), Ordering::Release);
        assert!(!cache.alias_if_fits(0, 99).unwrap());
        assert_eq!(cache.maintenance_provider_denials(), 1);
        assert_eq!(cache.stats(), before);
        admission.limit.store(u64::MAX, Ordering::Release);
        assert!(cache.alias_if_fits(0, 99).unwrap());
        assert!(CachedBytes::ptr_eq(
            &cache.peek(0).unwrap(),
            &cache.peek(99).unwrap()
        ));
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            self.used.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
    impl Admission {
        fn admit(&self, bytes: u64) -> Result<(), AdmissionError> {
            self.check_owner()
                .map_err(|_| AdmissionError::OwnerFailed)?;
            if self.fail_next_reserve.swap(false, Ordering::AcqRel) {
                return Err(AdmissionError::OwnerFailed);
            }
            self.used
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes)
                        .filter(|next| *next <= self.limit.load(Ordering::Acquire))
                })
                .map_err(|_| AdmissionError::CapacityDenied)?;
            if self.expire_after_reserve.swap(false, Ordering::AcqRel) {
                self.failed.store(true, Ordering::Release);
            }
            Ok(())
        }
        fn new(limit: u64) -> Arc<Self> {
            Arc::new(Self {
                used: Arc::new(AtomicU64::new(0)),
                limit: AtomicU64::new(limit),
                failed: AtomicBool::new(false),
                fail_next_reserve: AtomicBool::new(false),
                fail_next_quote: AtomicBool::new(false),
                expire_after_reserve: AtomicBool::new(false),
                panic_next_check: AtomicBool::new(false),
            })
        }
        fn used(&self) -> u64 {
            self.used.load(Ordering::Acquire)
        }
    }
    impl StorageAdmission for Admission {
        fn check_owner(&self) -> Result<(), OwnerFailed> {
            assert!(
                !self.panic_next_check.swap(false, Ordering::AcqRel),
                "admission check panic"
            );
            if self.failed.load(Ordering::Acquire) {
                Err(OwnerFailed)
            } else {
                Ok(())
            }
        }
        fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
            self.admit(bytes)?;
            Ok(Box::new(Lease {
                used: self.used.clone(),
                bytes,
            }))
        }
        fn quote_cache_memory(
            &self,
            credit: u64,
        ) -> Result<crate::CacheMemoryQuote, AdmissionError> {
            if self.fail_next_quote.swap(false, Ordering::AcqRel) {
                return Err(AdmissionError::OwnerFailed);
            }
            crate::CacheMemoryQuote::new(
                credit,
                size_of::<CacheToken>() as u64 + ALLOCATION_ALLOWANCE,
            )
            .ok_or(AdmissionError::CapacityDenied)
        }
        fn reserve_cache_memory(
            self: Arc<Self>,
            credit: u64,
        ) -> Result<crate::CacheMemoryLease, AdmissionError> {
            let quote = self.quote_cache_memory(credit)?;
            self.admit(quote.charged_bytes())?;
            Ok(crate::CacheMemoryLease::new(
                quote,
                CacheToken {
                    admission: self,
                    bytes: quote.charged_bytes(),
                },
            ))
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
    }

    #[test]
    fn failed_cache_quote_never_becomes_optional_pressure_or_uncached_io() {
        for populated in [false, true] {
            for maintenance in [false, true] {
                let admission = Admission::new(u64::MAX);
                let mut cache = NativeCache::<u64>::new(
                    CacheConfig {
                        byte_limit: 1 << 20,
                    },
                    admission.clone(),
                );
                if populated {
                    drop(
                        cache
                            .load(1, 64, |out| {
                                out.fill(7);
                                Ok::<_, ()>(())
                            })
                            .unwrap(),
                    );
                }
                let entries = cache.stats().entries;
                let mut loaded = false;
                admission.fail_next_quote.store(true, Ordering::Release);
                let loader = |_: &mut [u8]| {
                    loaded = true;
                    Ok::<_, ()>(())
                };
                let result = if maintenance {
                    cache.load_if_fits(2, 64, loader).map(|_| ())
                } else {
                    cache.load(2, 64, loader).map(|_| ())
                };
                assert!(
                    matches!(
                        result,
                        Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
                    ),
                    "populated={populated}, maintenance={maintenance}"
                );
                assert!(!loaded, "failed quote must stop before fallback I/O");
                assert!(
                    admission.check_owner().is_ok(),
                    "the quote's error is authoritative"
                );
                assert_eq!(cache.stats().entries, entries);
                assert_eq!(cache.stats().uncached_loads, 0);
                if populated {
                    assert_eq!(cache.peek(1).unwrap().as_bytes(), &[7; 64]);
                    // The alias path also calls prepare with a zero payload
                    // charge; metadata-only growth must preserve fatal quotes.
                    admission.fail_next_quote.store(true, Ordering::Release);
                    assert!(matches!(
                        cache.alias_if_fits(1, 3),
                        Err(AdmissionError::OwnerFailed)
                    ));
                    assert!(cache.peek(3).is_none());
                }
                drop(cache);
                assert_eq!(admission.used(), 0);
            }
        }
    }

    fn cache_for(entries: usize, len: usize) -> (NativeCache, Arc<Admission>) {
        let admission = Admission::new(u64::MAX);
        let slots = (entries * 2).max(MIN_SLOTS).next_power_of_two();
        let credit = NativeCache::<u64>::metadata_base_charge()
            + NativeCache::<u64>::slots_charge(slots).unwrap()
            + entries as u64 * CachedBytes::charge_for_len(len).unwrap();
        let limit = admission
            .quote_cache_memory(credit)
            .unwrap()
            .charged_bytes();
        (
            NativeCache::new(CacheConfig { byte_limit: limit }, admission.clone()),
            admission,
        )
    }

    #[test]
    fn pruning_unreachable_identities_shrinks_metadata_and_preserves_output_pins() {
        let (mut cache, admission) = cache_for(256, 64);
        for key in 0..256 {
            drop(load(&mut cache, key, 64));
        }
        let pinned = cache.get(0).unwrap();
        let before = cache.stats().metadata_bytes;
        assert_eq!(cache.remove_matching(|key| key < 240).unwrap(), 240);
        assert_eq!(cache.stats().entries, 16);
        assert!(cache.stats().metadata_bytes < before);
        assert_eq!(cache.stats().pinned_bytes, pinned.charged_bytes());
        assert_eq!(cache.stats().evictions, 0);
        for key in 240..256 {
            assert_eq!(cache.get(key).unwrap().as_bytes(), &[key as u8; 64]);
        }
        drop(cache);
        assert_eq!(pinned.as_bytes(), &[0; 64]);
        drop(pinned);
        assert_eq!(admission.used(), 0);
    }

    fn assert_guard_only_pool(admission: &Admission, value: &CachedBytes) {
        let stats = value.pool().expect("pooled output").stats();
        assert_eq!(
            stats.used,
            NativeCache::<u64>::metadata_base_charge() + value.charged_bytes()
        );
        assert_eq!(stats.live_values, value.charged_bytes());
        assert_eq!(stats.cached_values, 0);
        assert!(stats.credit >= stats.used);
        assert!(stats.credit - stats.used < 64 << 10);
        assert_eq!(
            stats.charged,
            admission
                .quote_cache_memory(stats.credit)
                .unwrap()
                .charged_bytes()
        );
        assert_eq!(admission.used(), stats.charged);
    }

    fn load(cache: &mut NativeCache, key: u64, len: usize) -> CachedBytes {
        cache
            .load(key, len, |out| {
                out.fill(key as u8);
                Ok::<_, ()>(())
            })
            .unwrap()
    }

    fn lru_keys(cache: &NativeCache) -> Vec<u64> {
        let mut keys = Vec::new();
        let mut index = cache.head;
        while index != NONE {
            let entry = cache.slots[index].as_ref().unwrap();
            keys.push(entry.key);
            index = entry.next;
        }
        keys
    }

    #[test]
    fn keeps_every_fitting_value_and_charges_the_directory() {
        let (mut cache, admission) = cache_for(128, 128);
        for key in 0..128 {
            drop(load(&mut cache, key, 128));
        }
        assert_eq!(cache.stats().entries, 128);
        assert_eq!(cache.stats().evictions, 0);
        assert_eq!(cache.stats().resident_bytes, cache.config().byte_limit);
        assert_eq!(admission.used(), cache.stats().resident_bytes);
        for key in 0..128 {
            let value = cache.load(key, 128, |_| Err::<(), _>("disk read"));
            assert_eq!(value.unwrap().as_bytes(), &[key as u8; 128]);
        }
        assert_eq!(cache.stats().loads, 128);
        assert_eq!(cache.stats().hits, 128);
        cache.clear();
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn frequently_read_working_set_survives_a_historical_scan() {
        let (mut cache, admission) = cache_for(16, 256);
        for key in 0..16 {
            drop(load(&mut cache, key, 256));
        }
        for _ in 0..40 {
            for key in 0..8 {
                drop(cache.get(key).unwrap());
            }
        }
        for key in 100..2100 {
            drop(load(&mut cache, key, 256));
            assert!(cache.stats().resident_bytes <= cache.config().byte_limit);
        }
        for key in 0..8 {
            assert!(cache.get(key).is_some(), "hot key {key} was displaced");
        }
        assert!(cache.stats().uncached_loads > 1000);
        assert_eq!(admission.used(), cache.stats().resident_bytes);
    }

    #[test]
    fn evicted_reader_pins_keep_their_original_bytes_charged() {
        let (mut cache, admission) = cache_for(1, 1024);
        let pinned = load(&mut cache, 1, 1024);
        let before = admission.used();
        assert!(cache.remove(1));
        assert_eq!(cache.stats().entries, 0);
        assert_eq!(cache.stats().pinned_bytes, pinned.charged_bytes());
        assert_eq!(admission.used(), before);
        let bypassed = load(&mut cache, 2, 1024);
        assert_eq!(cache.stats().entries, 0);
        assert_eq!(cache.stats().uncached_loads, 1);
        assert_eq!(pinned.as_bytes(), &[1; 1024]);
        drop(bypassed);
        assert_eq!(admission.used(), before);
        drop(pinned);
        drop(load(&mut cache, 2, 1024));
        assert_eq!(cache.stats().entries, 1);
        cache.clear();
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn dropping_cache_keeps_pinned_value_and_accounting_leases_alive() {
        let (mut cache, admission) = cache_for(1, 1024);
        let pinned = load(&mut cache, 8, 1024);
        drop(cache);
        assert_guard_only_pool(&admission, &pinned);
        assert_eq!(pinned.as_bytes(), &[8; 1024]);
        drop(pinned);
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn oversized_and_disabled_reads_use_only_request_admissions() {
        for limit in [0, 1, 2048] {
            let admission = Admission::new(u64::MAX);
            let mut cache = NativeCache::new(CacheConfig { byte_limit: limit }, admission.clone());
            let value = load(&mut cache, 1, 8192);
            assert_eq!(cache.stats().resident_bytes, 0);
            assert_eq!(cache.stats().entries, 0);
            assert_eq!(admission.used(), value.charged_bytes());
            drop(value);
            assert_eq!(admission.used(), 0);
        }
    }

    #[test]
    fn denies_before_loading_when_storage_capacity_is_unavailable() {
        let admission = Admission::new(32);
        let mut cache = NativeCache::new(CacheConfig::default(), admission.clone());
        let result = cache.load(1, 4096, |_| panic!("loader ran without admission"));
        assert!(matches!(
            result,
            Err(CacheLoadError::<()>::Admission(
                AdmissionError::CapacityDenied
            ))
        ));
        assert_eq!(admission.used(), 0);
        admission.failed.store(true, Ordering::Release);
        let result = cache.load(1, 1, |_| Ok::<_, ()>(()));
        assert!(matches!(
            result,
            Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
        ));
    }

    #[test]
    fn failed_load_releases_buffer_and_does_not_install_a_value() {
        let (mut cache, admission) = cache_for(1, 1024);
        assert!(matches!(
            cache.load(1, 1024, |_| Err("I/O error")),
            Err(CacheLoadError::Load("I/O error"))
        ));
        assert_eq!(cache.stats().entries, 0);
        let stats = cache.stats();
        assert_eq!(stats.allocated_bytes, stats.metadata_bytes);
        assert_eq!(stats.cached_bytes + stats.pinned_bytes, 0);
        assert_eq!(
            stats.resident_bytes,
            stats.allocated_bytes + stats.unused_credit_bytes + stats.provider_overhead_bytes
        );
        assert_eq!(admission.used(), stats.resident_bytes);
        cache.clear();
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn shrinking_budget_cannot_forgive_outstanding_reader_pins() {
        let (mut cache, admission) = cache_for(4, 1024);
        let previous = cache.config().byte_limit;
        let pinned = load(&mut cache, 1, 1024);
        assert_eq!(cache.set_byte_limit(0), Err(AdmissionError::CapacityDenied));
        assert_eq!(cache.config().byte_limit, previous);
        assert!(cache.stats().resident_bytes > 0);
        drop(pinned);
        cache.set_byte_limit(0).unwrap();
        assert_eq!(cache.stats().resident_bytes, 0);
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn failed_budget_shrink_restores_pool_limit_at_both_metadata_replacement_boundaries() {
        for initial_trim in [true, false] {
            let entries = if initial_trim { 17 } else { 9 };
            let (mut cache, admission) = cache_for(entries, 64);
            for key in 0..entries as u64 {
                drop(load(&mut cache, key, 64));
            }
            let pinned = cache.peek(0).unwrap();
            if initial_trim {
                for key in 1..entries as u64 {
                    assert!(cache.remove(key));
                }
            }
            let previous_limit = cache.config.byte_limit;
            let capacity = cache.slots.len();
            let credit = NativeCache::<u64>::metadata_base_charge()
                + NativeCache::<u64>::slots_charge(MIN_SLOTS).unwrap()
                + pinned.charged_bytes();
            let smaller_limit = admission
                .quote_cache_memory(credit)
                .unwrap()
                .charged_bytes();
            admission.fail_next_reserve.store(true, Ordering::Release);
            assert_eq!(
                cache.set_byte_limit(smaller_limit),
                Err(AdmissionError::OwnerFailed)
            );
            assert!(!admission.fail_next_reserve.load(Ordering::Acquire));
            assert_eq!(cache.config.byte_limit, previous_limit);
            assert_eq!(cache.slots.len(), capacity);
            assert!(CachedBytes::ptr_eq(&pinned, &cache.peek(0).unwrap()));
            assert_eq!(
                cache.stats().cached_bytes + cache.stats().pinned_bytes,
                cache.stats().entries as u64 * pinned.charged_bytes()
            );
            assert_eq!(admission.used(), cache.stats().resident_bytes);

            // Rehash directly, before ensure_pool can repair a stale limit.
            // The existing backing fits the old public limit but exceeds the
            // failed new limit. Both replacement allocations remain charged.
            assert!(
                cache.stats().allocated_bytes + cache.stats().provider_overhead_bytes
                    > smaller_limit
            );
            cache
                .resize_slots(
                    capacity,
                    NativeCache::<u64>::slots_charge(capacity).unwrap(),
                )
                .unwrap();
            assert!(CachedBytes::ptr_eq(&pinned, &cache.peek(0).unwrap()));
            cache.set_byte_limit(smaller_limit).unwrap();
            assert_eq!(cache.stats().entries, 1);
            assert_eq!(cache.stats().resident_bytes, smaller_limit);
            assert!(CachedBytes::ptr_eq(&pinned, &cache.peek(0).unwrap()));
            drop(cache);
            assert_guard_only_pool(&admission, &pinned);
            drop(pinned);
            assert_eq!(admission.used(), 0);
        }
    }

    #[test]
    fn budget_shrink_preserves_hot_entries_and_releases_directory_capacity() {
        let (mut cache, admission) = cache_for(32, 128);
        for key in 0..32 {
            drop(load(&mut cache, key, 128));
        }
        for _ in 0..20 {
            for key in 0..8 {
                drop(cache.get(key).unwrap());
            }
        }
        let (smaller, _) = cache_for(8, 128);
        let target = smaller.config().byte_limit;
        cache.set_byte_limit(target).unwrap();
        assert_eq!(cache.stats().entries, 8);
        assert_eq!(cache.stats().resident_bytes, target);
        assert_eq!(cache.slots.len(), MIN_SLOTS);
        assert_eq!(admission.used(), target);
        for key in 0..8 {
            assert!(
                cache.contains(key),
                "hot key {key} was evicted while shrinking"
            );
        }
        for key in 8..32 {
            assert!(!cache.contains(key));
        }
    }

    #[test]
    fn colliding_directory_removals_preserve_lookup_and_lru_links() {
        let (mut cache, _) = cache_for(8, 64);
        let keys: Vec<_> = (0..1000)
            .filter(|key| key_hash(*key) as usize & 15 == 15)
            .take(8)
            .collect();
        assert_eq!(keys.len(), 8);
        for key in &keys {
            drop(load(&mut cache, *key, 64));
        }
        for key in keys.iter().step_by(2) {
            assert!(cache.remove(*key));
        }
        for key in keys.iter().skip(1).step_by(2).rev() {
            assert_eq!(cache.get(*key).unwrap().as_bytes(), &[*key as u8; 64]);
        }
        for key in keys.iter().skip(1).step_by(2) {
            assert!(cache.remove(*key));
        }
        assert_eq!(cache.entries, 0);
        assert_eq!(cache.head, NONE);
        assert_eq!(cache.tail, NONE);
        assert!(cache.slots.iter().all(Option::is_none));
    }

    #[test]
    fn relocation_preserves_payload_frequency_recency_and_admission() {
        let (mut cache, admission) = cache_for(8, 64);
        for key in 1..=8 {
            drop(load(&mut cache, key, 64));
        }
        for _ in 0..10 {
            drop(cache.get(2).unwrap());
        }
        // Leave the hot value in the middle of the LRU list.
        drop(cache.get(3).unwrap());
        let order = |cache: &NativeCache| {
            let mut keys = Vec::new();
            let mut index = cache.head;
            while index != NONE {
                let entry = cache.slots[index].as_ref().unwrap();
                keys.push(entry.key);
                index = entry.next;
            }
            keys
        };
        let mut expected = order(&cache);
        *expected.iter_mut().find(|key| **key == 2).unwrap() = 100;
        let used = admission.used();
        let frequency = cache.frequency(2);
        cache.relocate(2, 100);
        assert!(!cache.contains(2));
        assert!(cache.contains(100));
        assert_eq!(order(&cache), expected);
        assert!(cache.frequency(100) >= frequency);
        assert_eq!(admission.used(), used);
        assert_eq!(cache.get(100).unwrap().as_bytes(), &[2; 64]);
        cache.relocate(999, 100);
        assert!(!cache.contains(100));
        cache.relocate(3, 3);
        assert!(cache.contains(3));
    }

    #[test]
    fn relocation_copy_keeps_both_addresses_and_original_output_charges() {
        let (mut cache, admission) = cache_for(4, 64);
        let original = load(&mut cache, 1, 64);
        drop(load(&mut cache, 2, 64));
        for _ in 0..12 {
            drop(cache.get(1).unwrap());
        }
        let before = admission.used();
        let frequency = cache.frequency(1);
        assert!(cache.copy_relocated(1, 100).unwrap());
        assert!(cache.contains(1));
        assert!(cache.contains(2));
        assert!(cache.contains(100));
        assert_eq!(cache.stats().entries, 3);
        assert_eq!(cache.stats().evictions, 0);
        assert_eq!(admission.used(), before);
        assert_eq!(admission.used(), cache.stats().resident_bytes);
        assert!(cache.frequency(100) >= frequency);
        let copied = cache
            .load(100, 64, |_| Err::<(), _>("relocation copy fetched storage"))
            .unwrap();
        assert_eq!(copied.as_bytes(), original.as_bytes());
        assert!(CachedBytes::ptr_eq(&original, &copied));
        assert!(CachedBytes::ptr_eq(&original, &cache.get(1).unwrap()));
        assert!(cache.remove(1));
        assert_eq!(cache.stats().pinned_bytes, 0);
        assert_eq!(admission.used(), before);
        drop(cache);
        assert_guard_only_pool(&admission, &original);
        assert_eq!(original.as_bytes(), &[1; 64]);
        assert_eq!(copied.as_bytes(), &[1; 64]);
        drop(original);
        assert_guard_only_pool(&admission, &copied);
        drop(copied);
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn relocation_copy_of_a_cold_source_leaves_existing_cache_state_unchanged() {
        let (mut cache, admission) = cache_for(2, 64);
        let existing = load(&mut cache, 10, 64);
        let stats = cache.stats();
        let sketch = cache.sketch;
        let used = admission.used();
        assert!(!cache.copy_relocated(999, 100).unwrap());
        assert!(cache.copy_relocated(999, 10).unwrap());
        assert!(cache.copy_relocated(10, 10).unwrap());
        assert_eq!(cache.stats(), stats);
        assert_eq!(cache.sketch, sketch);
        assert_eq!(admission.used(), used);
        assert!(!cache.contains(999));
        assert!(!cache.contains(100));
        assert!(CachedBytes::ptr_eq(&existing, &cache.get(10).unwrap()));
        assert_eq!(existing.as_bytes(), &[10; 64]);
    }

    #[test]
    fn relocation_copy_under_pressure_moves_the_hot_identity_without_unrelated_eviction() {
        for entries in [8, 16] {
            let (mut cache, admission) = cache_for(entries, 64);
            for key in 0..entries as u64 {
                drop(load(&mut cache, key, 64));
            }
            if entries == 16 {
                // Payload headroom alone is insufficient when another entry
                // also needs a doubled directory allocation.
                cache
                    .set_byte_limit(
                        cache.config().byte_limit + CachedBytes::charge_for_len(64).unwrap(),
                    )
                    .unwrap();
            }
            assert!(!cache.fits_without_eviction(0).unwrap());
            let stats = cache.stats();
            let samples = cache.samples;
            let original = cache.peek(0).unwrap();
            let mut order = lru_keys(&cache);
            *order.iter_mut().find(|key| **key == 0).unwrap() = 100;
            let used = admission.used();
            assert!(cache.copy_relocated(0, 100).unwrap());
            assert_eq!(cache.stats(), stats);
            assert_eq!(cache.samples, samples);
            assert_eq!(lru_keys(&cache), order);
            assert_eq!(admission.used(), used);
            assert!(!cache.contains(0));
            assert!(CachedBytes::ptr_eq(&original, &cache.peek(100).unwrap()));
            assert_eq!(original.as_bytes(), &[0; 64]);
            for key in 1..entries as u64 {
                assert_eq!(cache.get(key).unwrap().as_bytes(), &[key as u8; 64]);
            }
        }
    }

    #[test]
    fn relocation_copy_accounts_for_evicted_but_pinned_output_bytes() {
        let (mut cache, admission) = cache_for(3, 64);
        drop(load(&mut cache, 1, 64));
        drop(load(&mut cache, 2, 64));
        let pinned = load(&mut cache, 3, 64);
        assert!(cache.remove(3));
        let used = admission.used();
        assert!(cache.copy_relocated(1, 100).unwrap());
        assert_eq!(cache.stats().pinned_bytes, pinned.charged_bytes());
        assert_eq!(admission.used(), used);
        assert_eq!(cache.stats().evictions, 0);
        assert!(cache.contains(1));
        assert_eq!(cache.peek(100).unwrap().as_bytes(), &[1; 64]);
        assert!(cache.contains(2));
        drop(pinned);
        assert!(cache.copy_relocated(100, 101).unwrap());
        assert!(cache.contains(100));
        assert!(cache.contains(101));
        assert_eq!(cache.stats().entries, 4);
        let stats = cache.stats();
        assert_eq!(
            stats.cached_bytes,
            2 * CachedBytes::charge_for_len(64).unwrap()
        );
        assert_eq!(stats.pinned_bytes, 0);
        assert_eq!(
            stats.allocated_bytes + stats.provider_overhead_bytes,
            cache.config().byte_limit - CachedBytes::charge_for_len(64).unwrap()
        );
        assert_eq!(
            stats.resident_bytes,
            stats.allocated_bytes + stats.unused_credit_bytes + stats.provider_overhead_bytes
        );
        assert_eq!(admission.used(), stats.resident_bytes);
    }

    #[test]
    fn relocation_copy_capacity_denial_is_optional_and_retryable() {
        let (mut cache, admission) = cache_for(9, 64);
        for key in 0..8 {
            drop(load(&mut cache, key, 64));
        }
        let original = cache.peek(1).unwrap();
        let used = admission.used();
        admission.limit.store(used, Ordering::Release);
        assert!(cache.copy_relocated(1, 100).unwrap());
        assert_eq!(admission.used(), used);
        assert_eq!(cache.stats().entries, 8);
        assert_eq!(cache.stats().evictions, 0);
        assert!(!cache.contains(1));
        assert!(CachedBytes::ptr_eq(&original, &cache.peek(100).unwrap()));
        admission.limit.store(u64::MAX, Ordering::Release);
        assert!(cache.copy_relocated(100, 1).unwrap());
        assert!(cache.contains(1));
        assert_eq!(cache.get(100).unwrap().as_bytes(), &[1; 64]);
        assert_eq!(cache.stats().cached_bytes, 8 * original.charged_bytes());
        assert!(CachedBytes::ptr_eq(&original, &cache.peek(1).unwrap()));
    }

    #[test]
    fn relocation_copy_denied_directory_growth_moves_without_retaining_extra_backing() {
        let (mut cache, admission) = cache_for(9, 64);
        for key in 0..8 {
            drop(load(&mut cache, key, 64));
        }
        let original = cache.peek(0).unwrap();
        let before = cache.stats();
        let used = admission.used();
        let slot_count = cache.slots.len();
        // Payload headroom cannot admit a larger directory while the old
        // directory still owns its backing. Fallback creates no payload copy.
        admission.limit.store(
            used + CachedBytes::charge_for_len(64).unwrap(),
            Ordering::Release,
        );
        assert!(cache.copy_relocated(0, 100).unwrap());
        assert_eq!(cache.stats(), before);
        assert_eq!(cache.slots.len(), slot_count);
        assert_eq!(admission.used(), used);
        assert!(!cache.contains(0));
        assert!(CachedBytes::ptr_eq(&original, &cache.peek(100).unwrap()));
        for key in 1..8 {
            assert!(cache.contains(key));
        }
    }

    #[test]
    fn shared_relocation_keeps_every_fitting_identity_without_payload_headroom() {
        let (mut cache, admission) = cache_for(1, 64 << 10);
        let original = load(&mut cache, 1, 64 << 10);
        let before = cache.stats();
        admission.limit.store(admission.used(), Ordering::Release);
        // Both cache and installed admission are full. Existing directory
        // capacity can still retain all eight identities of this one payload.
        for key in 2..=8 {
            assert!(cache.copy_relocated(key - 1, key).unwrap());
            assert!(CachedBytes::ptr_eq(&original, &cache.peek(key).unwrap()));
            assert_eq!(cache.stats().resident_bytes, before.resident_bytes);
            assert_eq!(cache.stats().cached_bytes, original.charged_bytes());
            assert_eq!(cache.stats().pinned_bytes, 0);
            assert_eq!(admission.used(), before.resident_bytes);
        }
        assert_eq!(original.payload().cache_owners.load(Ordering::Acquire), 8);
        for key in 1..=8 {
            assert!(CachedBytes::ptr_eq(
                &original,
                &cache
                    .load(key, 64 << 10, |_| Err::<(), _>("alias missed"))
                    .unwrap()
            ));
        }
        assert_eq!(cache.stats().loads, 1);
        assert_eq!(cache.stats().evictions, 0);
        assert!(cache.copy_relocated(8, 9).unwrap());
        assert!(!cache.contains(8));
        assert!(cache.contains(9));
        assert_eq!(original.payload().cache_owners.load(Ordering::Acquire), 8);
        assert_eq!(admission.used(), before.resident_bytes);
    }

    #[test]
    fn shared_relocation_chain_survives_rehash_moves_pruning_and_clear() {
        let (mut cache, admission) = cache_for(64, 4096);
        let original = load(&mut cache, 0, 4096);
        drop(load(&mut cache, 1000, 4096));
        for key in 1..=32 {
            assert!(cache.copy_relocated(key - 1, key).unwrap());
            assert_eq!(cache.stats().cached_bytes, 2 * original.charged_bytes());
            assert_eq!(cache.stats().pinned_bytes, 0);
            assert_eq!(admission.used(), cache.stats().resident_bytes);
        }
        assert_eq!(cache.slots.len(), 128);
        assert_eq!(original.payload().cache_owners.load(Ordering::Acquire), 33);
        // Moving onto another alias removes exactly one cache membership,
        // without changing unique payload accounting or the original lease.
        cache.relocate(1, 2);
        assert_eq!(original.payload().cache_owners.load(Ordering::Acquire), 32);
        assert_eq!(cache.stats().cached_bytes, 2 * original.charged_bytes());
        assert_eq!(cache.remove_matching(|key| key < 32).unwrap(), 31);
        assert_eq!(cache.slots.len(), MIN_SLOTS);
        assert_eq!(original.payload().cache_owners.load(Ordering::Acquire), 1);
        assert!(CachedBytes::ptr_eq(&original, &cache.peek(32).unwrap()));
        assert_eq!(cache.stats().pinned_bytes, 0);
        assert!(cache.remove(32));
        assert_eq!(original.payload().cache_owners.load(Ordering::Acquire), 0);
        assert_eq!(cache.stats().cached_bytes, original.charged_bytes());
        assert_eq!(cache.stats().pinned_bytes, original.charged_bytes());
        cache.clear();
        assert_eq!(cache.stats().cached_bytes, 0);
        assert_eq!(cache.stats().pinned_bytes, original.charged_bytes());
        assert_eq!(admission.used(), cache.stats().resident_bytes);
        drop(cache);
        assert_guard_only_pool(&admission, &original);
        std::thread::spawn(move || {
            assert_eq!(original.as_bytes(), &[0; 4096]);
            drop(original);
        })
        .join()
        .unwrap();
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn shared_relocation_budget_shrink_distinguishes_aliases_from_external_pins() {
        let (mut cache, admission) = cache_for(16, 1024);
        drop(load(&mut cache, 1, 1024));
        for _ in 0..40 {
            drop(cache.get(1).unwrap());
        }
        for key in 10..17 {
            assert!(cache.copy_relocated(1, key).unwrap());
        }
        let pinned = load(&mut cache, 2, 1024);
        let credit = NativeCache::<u64>::metadata_base_charge()
            + NativeCache::<u64>::slots_charge(MIN_SLOTS).unwrap()
            + pinned.charged_bytes();
        let limit = admission
            .quote_cache_memory(credit)
            .unwrap()
            .charged_bytes();
        // The aliases are hotter but have no external holder. Removing them
        // can release one payload; removing key 2 cannot release its payload.
        cache.set_byte_limit(limit).unwrap();
        assert!(CachedBytes::ptr_eq(&pinned, &cache.peek(2).unwrap()));
        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.stats().cached_bytes, pinned.charged_bytes());
        assert_eq!(cache.stats().pinned_bytes, 0);
        assert_eq!(cache.stats().resident_bytes, limit);
        assert_eq!(admission.used(), limit);
        assert!(!cache.contains(1));
        for key in 10..17 {
            assert!(!cache.contains(key));
        }
    }

    #[test]
    fn shared_relocation_last_alias_eviction_never_refunds_external_guards() {
        let (mut cache, admission) = cache_for(1, 1024);
        let pinned = load(&mut cache, 1, 1024);
        assert!(cache.copy_relocated(1, 2).unwrap());
        let old_limit = cache.config().byte_limit;
        let remaining = admission
            .quote_cache_memory(NativeCache::<u64>::metadata_base_charge() + pinned.charged_bytes())
            .unwrap()
            .charged_bytes();
        assert_eq!(
            cache.set_byte_limit(remaining - 1),
            Err(AdmissionError::CapacityDenied)
        );
        assert_eq!(cache.config().byte_limit, old_limit);
        assert_eq!(cache.stats().entries, 0);
        assert_eq!(cache.stats().cached_bytes, 0);
        assert_eq!(cache.stats().pinned_bytes, pinned.charged_bytes());
        assert_eq!(pinned.payload().cache_owners.load(Ordering::Acquire), 0);
        assert_eq!(admission.used(), remaining);
        drop(pinned);
        cache.clear();
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn maintenance_fill_and_peek_do_not_train_policy_or_demand_counters() {
        let (mut cache, admission) = cache_for(12, 64);
        // Include a directory resize to ensure it preserves the prior LRU order.
        for key in 0..8 {
            drop(load(&mut cache, key, 64));
        }
        let counters = cache.counters;
        let sketch = cache.sketch;
        let samples = cache.samples;
        let mut order = lru_keys(&cache);
        let original = cache.peek(0).unwrap();
        assert!(cache.peek(999).is_none());
        let hit = cache
            .load_if_fits(0, 64, |_| Err::<(), _>("maintenance hit read storage"))
            .unwrap()
            .unwrap();
        assert!(CachedBytes::ptr_eq(&original, &hit));
        let copied = cache
            .load_if_fits(100, 64, |out| {
                out.fill(17);
                Ok::<_, ()>(())
            })
            .unwrap()
            .unwrap();
        order.push(100);
        assert_eq!(lru_keys(&cache), order);
        assert_eq!(cache.counters, counters);
        assert_eq!(cache.sketch, sketch);
        assert_eq!(cache.samples, samples);
        assert_eq!(copied.as_bytes(), &[17; 64]);
        assert_eq!(cache.peek(100).unwrap().as_bytes(), &[17; 64]);
        assert_eq!(cache.stats().entries, 9);
        assert_eq!(admission.used(), cache.stats().resident_bytes);
    }

    #[test]
    fn maintenance_fill_checks_empty_cache_overhead_and_never_reads_without_headroom() {
        for limit in [0, 1, CachedBytes::charge_for_len(64).unwrap()] {
            let admission = Admission::new(u64::MAX);
            let mut cache: NativeCache =
                NativeCache::new(CacheConfig { byte_limit: limit }, admission.clone());
            let before = cache.stats();
            assert!(
                cache
                    .load_if_fits(1, 64, |_| panic!("unfitting fill read storage"))
                    .unwrap_or_else(|_: CacheLoadError<()>| panic!("optional fill failed"))
                    .is_none()
            );
            assert_eq!(cache.stats(), before);
            assert_eq!(cache.samples, 0);
            assert_eq!(admission.used(), 0);
        }
        let (mut cache, admission) = cache_for(1, 64);
        let value = cache
            .load_if_fits(1, 64, |out| {
                out.fill(1);
                Ok::<_, ()>(())
            })
            .unwrap()
            .unwrap();
        assert_eq!(cache.stats().resident_bytes, cache.config().byte_limit);
        let before = cache.stats();
        let sketch = cache.sketch;
        assert!(
            cache
                .load_if_fits(2, 64, |_| Err::<(), _>("full cache read storage"))
                .unwrap()
                .is_none()
        );
        assert_eq!(cache.stats(), before);
        assert_eq!(cache.sketch, sketch);
        assert_eq!(cache.samples, 0);
        assert_eq!(admission.used(), cache.stats().resident_bytes);
        assert!(CachedBytes::ptr_eq(&value, &cache.peek(1).unwrap()));
    }

    #[test]
    fn maintenance_fill_releases_denied_failed_or_expired_loads_without_policy_training() {
        let admission = Admission::new(u64::MAX);
        let mut cache = NativeCache::new(
            CacheConfig {
                byte_limit: 1 << 20,
            },
            admission.clone(),
        );
        drop(load(&mut cache, 1, 64));
        let used = admission.used();
        let stats = cache.stats();
        let sketch = cache.sketch;
        let order = lru_keys(&cache);
        // The replacement exceeds preadmitted slack, so this exercises a real
        // provider refusal rather than expecting a reservation per value.
        assert!(cache.stats().unused_credit_bytes < CachedBytes::charge_for_len(96 << 10).unwrap());
        admission.limit.store(used, Ordering::Release);
        assert!(
            cache
                .load_if_fits(2, 96 << 10, |_| Err::<(), _>("denied fill read storage"))
                .unwrap()
                .is_none()
        );
        admission.limit.store(u64::MAX, Ordering::Release);
        assert!(matches!(
            cache.load_if_fits(2, 96 << 10, |_| Err("storage failure")),
            Err(CacheLoadError::Load("storage failure"))
        ));
        admission
            .expire_after_reserve
            .store(true, Ordering::Release);
        assert!(matches!(
            cache.load_if_fits(2, 96 << 10, |_| Err::<(), _>("expired fill read storage")),
            Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
        ));
        admission.failed.store(false, Ordering::Release);
        assert!(matches!(
            cache.load_if_fits(2, 96 << 10, |_| {
                admission.failed.store(true, Ordering::Release);
                Ok::<_, ()>(())
            }),
            Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
        ));
        assert!(matches!(
            cache.load_if_fits(1, 64, |_| Ok::<_, ()>(())),
            Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
        ));
        assert_eq!(cache.stats(), stats);
        assert_eq!(cache.sketch, sketch);
        assert_eq!(lru_keys(&cache), order);
        assert_eq!(admission.used(), used);
        assert!(!cache.contains(2));
    }

    #[test]
    fn maintenance_alias_shares_one_payload_without_training_existing_policy() {
        let (mut cache, admission) = cache_for(9, 64);
        for key in 0..8 {
            drop(load(&mut cache, key, 64));
        }
        let output = cache.get(3).unwrap();
        let before = cache.stats();
        let counters = cache.counters;
        let sketch = cache.sketch;
        let samples = cache.samples;
        let mut order = lru_keys(&cache);
        let mut cursor = CacheCursor::default();
        let candidate = cache
            .candidate_step(&mut cursor, usize::MAX)
            .unwrap()
            .candidate
            .unwrap();
        assert!(cache.alias_if_fits(3, 100).unwrap());
        assert!(CachedBytes::ptr_eq(&output, &cache.peek(100).unwrap()));
        assert!(CachedBytes::ptr_eq(&output, &cache.peek(3).unwrap()));
        assert_eq!(cache.stats().cached_bytes, before.cached_bytes);
        assert_eq!(cache.stats().pinned_bytes, 0);
        assert_eq!(cache.stats().entries, before.entries + 1);
        assert_eq!(cache.counters, counters);
        assert_eq!(cache.sketch, sketch);
        assert_eq!(cache.samples, samples);
        order.push(100);
        assert_eq!(lru_keys(&cache), order);
        assert!(!cache.remove_candidate(&mut cursor, &candidate).unwrap());
        drop(candidate);
        let unchanged = cache.stats();
        let version = cache.structural_version;
        assert!(cache.alias_if_fits(999, 100).unwrap());
        assert!(cache.alias_if_fits(3, 3).unwrap());
        assert!(!cache.alias_if_fits(999, 101).unwrap());
        assert_eq!(cache.stats(), unchanged);
        assert_eq!(cache.structural_version, version);
        assert_eq!(cache.sketch, sketch);
        assert_eq!(lru_keys(&cache), order);
        assert!(cache.remove(3));
        assert_eq!(cache.stats().pinned_bytes, 0);
        assert!(cache.remove(100));
        assert_eq!(cache.stats().pinned_bytes, output.charged_bytes());
        drop(cache);
        assert_eq!(output.as_bytes(), &[3; 64]);
        drop(output);
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn denied_maintenance_alias_does_not_move_source_or_evict_and_can_retry() {
        for deny_admission in [false, true] {
            let (mut cache, admission) = cache_for(if deny_admission { 9 } else { 8 }, 64);
            for key in 0..8 {
                drop(load(&mut cache, key, 64));
            }
            if deny_admission {
                admission.limit.store(admission.used(), Ordering::Release);
            }
            let stats = cache.stats();
            let sketch = cache.sketch;
            let order = lru_keys(&cache);
            let used = admission.used();
            let version = cache.structural_version;
            assert!(!cache.alias_if_fits(3, 100).unwrap());
            assert_eq!(cache.stats(), stats);
            assert_eq!(cache.sketch, sketch);
            assert_eq!(lru_keys(&cache), order);
            assert_eq!(cache.structural_version, version);
            assert_eq!(admission.used(), used);
            assert!(cache.contains(3));
            assert!(!cache.contains(100));
            if deny_admission {
                admission.limit.store(u64::MAX, Ordering::Release);
            } else {
                cache.set_byte_limit(cache.config.byte_limit * 2).unwrap();
            }
            assert!(cache.alias_if_fits(3, 100).unwrap());
            assert_eq!(cache.stats().evictions, 0);
            assert!(CachedBytes::ptr_eq(
                &cache.peek(3).unwrap(),
                &cache.peek(100).unwrap()
            ));
            drop(cache);
            assert_eq!(admission.used(), 0);
        }
    }

    #[test]
    fn maintenance_alias_checks_owner_on_hits_and_each_metadata_reservation() {
        let (mut cache, admission) = cache_for(9, 64);
        for key in 0..8 {
            drop(load(&mut cache, key, 64));
        }
        let stats = cache.stats();
        let used = admission.used();
        admission.failed.store(true, Ordering::Release);
        for (old, new) in [(3, 100), (3, 3), (999, 3), (999, 100)] {
            assert_eq!(
                cache.alias_if_fits(old, new),
                Err(AdmissionError::OwnerFailed)
            );
        }
        admission.failed.store(false, Ordering::Release);
        admission.fail_next_reserve.store(true, Ordering::Release);
        assert_eq!(
            cache.alias_if_fits(3, 100),
            Err(AdmissionError::OwnerFailed)
        );
        assert_eq!(cache.stats(), stats);
        assert_eq!(admission.used(), used);
        admission
            .expire_after_reserve
            .store(true, Ordering::Release);
        assert_eq!(
            cache.alias_if_fits(3, 100),
            Err(AdmissionError::OwnerFailed)
        );
        assert_eq!(cache.stats(), stats);
        assert_eq!(admission.used(), used);
        assert!(cache.contains(3));
        assert!(!cache.contains(100));
        drop(cache);
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn relocation_copy_propagates_owner_failure_on_hits_and_during_reservation() {
        let (mut cache, admission) = cache_for(9, 64);
        for key in 0..8 {
            drop(load(&mut cache, key, 64));
        }
        let used = admission.used();
        admission.failed.store(true, Ordering::Release);
        for (old, new) in [(1, 100), (1, 2), (1, 1), (999, 100)] {
            assert_eq!(
                cache.copy_relocated(old, new),
                Err(AdmissionError::OwnerFailed)
            );
        }
        admission.failed.store(false, Ordering::Release);
        admission.fail_next_reserve.store(true, Ordering::Release);
        assert_eq!(
            cache.copy_relocated(1, 100),
            Err(AdmissionError::OwnerFailed)
        );
        assert!(!admission.failed.load(Ordering::Acquire));
        assert!(!cache.contains(100));
        assert_eq!(admission.used(), used);
        admission
            .expire_after_reserve
            .store(true, Ordering::Release);
        assert_eq!(
            cache.copy_relocated(1, 100),
            Err(AdmissionError::OwnerFailed)
        );
        assert!(!cache.contains(100));
        assert!(cache.contains(1));
        assert!(cache.contains(2));
        assert_eq!(admission.used(), used);
        assert_eq!(cache.stats().evictions, 0);
    }

    #[test]
    fn long_mixed_collision_workload_preserves_directory_invariants() {
        use std::collections::BTreeSet;
        let (mut cache, _) = cache_for(32, 32);
        let mut expected = BTreeSet::new();
        let mut random = 0x29a3_1822_3382_7221_u64;
        for _ in 0..10_000 {
            random = hash(random);
            let key = random % 64;
            if random & 256 == 0 {
                assert_eq!(cache.remove(key), expected.remove(&key));
            } else if expected.len() < 31 {
                drop(load(&mut cache, key, 32));
                expected.insert(key);
            } else {
                assert_eq!(cache.contains(key), expected.contains(&key));
                drop(cache.get(key));
            }
            assert_eq!(cache.entries, expected.len());
            let mut index = cache.head;
            let mut previous = NONE;
            let mut count = 0;
            while index != NONE {
                let entry = cache.slots[index].as_ref().unwrap();
                assert_eq!(entry.previous, previous);
                assert!(expected.contains(&entry.key));
                assert_eq!(cache.find(entry.key), Some(index));
                previous = index;
                index = entry.next;
                count += 1;
                assert!(count <= expected.len());
            }
            assert_eq!(count, expected.len());
            assert_eq!(previous, cache.tail);
        }
    }

    #[test]
    fn complete_identities_survive_identical_hashes_and_relocation() {
        #[derive(Clone, Copy, PartialEq, Eq)]
        struct Identity {
            owner: [u8; 16],
            version: u64,
        }
        impl Hash for Identity {
            fn hash<H: Hasher>(&self, state: &mut H) {
                // Deliberately collide in every slot and sketch row. Equality
                // must still preserve all fitting identities and their bytes.
                0u64.hash(state);
            }
        }
        let admission = Admission::new(u64::MAX);
        let mut cache = NativeCache::<Identity>::new(
            CacheConfig {
                byte_limit: 64 << 10,
            },
            admission.clone(),
        );
        let key = |id| Identity {
            owner: [id % 2; 16],
            version: u64::from(id),
        };
        for id in 0..32u8 {
            drop(
                cache
                    .load(key(id), 64, |bytes| {
                        bytes.fill(id);
                        Ok::<_, ()>(())
                    })
                    .unwrap(),
            );
        }
        assert_eq!(cache.stats().entries, 32);
        assert_eq!(cache.stats().evictions, 0);
        assert_eq!(admission.used(), cache.stats().resident_bytes);
        assert!(
            NativeCache::<Identity>::slots_charge(64).unwrap()
                > NativeCache::<u64>::slots_charge(64).unwrap()
        );
        for id in 0..32u8 {
            let bytes = cache.load(key(id), 64, |_| Err::<(), _>("unexpected read"));
            assert_eq!(bytes.unwrap().as_bytes(), &[id; 64]);
        }
        for id in (0..32u8).step_by(2) {
            assert!(cache.remove(key(id)));
        }
        cache.relocate(key(17), key(80));
        assert!(!cache.contains(key(17)));
        assert_eq!(cache.get(key(80)).unwrap().as_bytes(), &[17; 64]);
        for id in (1..32u8).step_by(2).filter(|&id| id != 17) {
            assert_eq!(cache.get(key(id)).unwrap().as_bytes(), &[id; 64]);
        }
        cache.clear();
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn load_checks_owner_on_hits_and_after_backend_reads() {
        let (mut cache, admission) = cache_for(2, 128);
        drop(load(&mut cache, 1, 128));
        admission.failed.store(true, Ordering::Release);
        assert!(matches!(
            cache.load(1, 128, |_| panic!("hit called backend")),
            Err(CacheLoadError::<()>::Admission(AdmissionError::OwnerFailed))
        ));
        admission.failed.store(false, Ordering::Release);
        assert!(matches!(
            cache.load(2, 128, |bytes| {
                bytes.fill(2);
                admission.failed.store(true, Ordering::Release);
                Ok::<_, ()>(())
            }),
            Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
        ));
        assert!(!cache.contains(2));
        assert_eq!(admission.used(), cache.stats().resident_bytes);
    }

    fn next_candidate(cache: &NativeCache, cursor: &mut CacheCursor) -> CacheCandidate<u64> {
        loop {
            let step = cache.candidate_step(cursor, 1).unwrap();
            if let Some(candidate) = step.candidate {
                return candidate;
            }
            assert!(!step.complete, "expected a retained candidate");
        }
    }

    #[test]
    fn publication_marks_deduplicate_without_admission_or_policy_changes_and_abort_cleanly() {
        let (mut cache, admission) = cache_for(8, 64);
        for key in 0..4 {
            drop(load(&mut cache, key, 64));
        }
        drop(cache.get(1));
        let before = cache.stats();
        let order = lru_keys(&cache);
        let sketch = cache.sketch;
        let samples = cache.samples;
        let used = admission.used();
        admission.limit.store(used, Ordering::Release);
        cache.begin_publication_candidates().unwrap();
        for _ in 0..100 {
            assert!(cache.mark_publication_candidate(1).unwrap());
            assert!(cache.mark_publication_candidate(3).unwrap());
            assert!(!cache.mark_publication_candidate(999).unwrap());
        }
        assert_eq!(cache.publication_marked, 2);
        assert_eq!(cache.stats(), before);
        assert_eq!(admission.used(), used);
        cache.clear_publication_candidates().unwrap();
        assert!(
            cache
                .slots
                .iter()
                .flatten()
                .all(|entry| !entry.marked && entry.next_marked.is_none())
        );
        assert_eq!(cache.stats(), before);
        assert_eq!(cache.sketch, sketch);
        assert_eq!(cache.samples, samples);
        assert_eq!(lru_keys(&cache), order);
        cache.begin_publication_candidates().unwrap();
        assert!(cache.pop_publication_candidate().unwrap().is_none());
        cache.clear_publication_candidates().unwrap();
    }

    #[test]
    fn publication_chain_survives_collision_backshifts_and_complete_key_rehash() {
        let (mut cache, admission) = cache_for(32, 64);
        let keys: Vec<_> = (0..10000)
            .filter(|key| key_hash(*key) as usize & 63 == 63)
            .take(8)
            .collect();
        assert_eq!(keys.len(), 8);
        for &key in &keys {
            drop(load(&mut cache, key, 64));
        }
        cache.begin_publication_candidates().unwrap();
        for &key in keys.iter().rev() {
            cache.mark_publication_candidate(key).unwrap();
        }
        let order = lru_keys(&cache);
        let counters = cache.counters;
        let sketch = cache.sketch;
        // Public resizing/fill is forbidden during a scope. Exercise the
        // private relocation primitive directly to prove links use full keys,
        // never old slot indices, when backing moves.
        cache
            .resize_slots(64, NativeCache::<u64>::slots_charge(64).unwrap())
            .unwrap();
        assert_eq!(lru_keys(&cache), order);
        for &key in &keys {
            let candidate = cache.pop_publication_candidate().unwrap().unwrap();
            assert_eq!(candidate.key, key);
            assert!(cache.remove_if_unchanged(&candidate).unwrap());
            assert!(!cache.contains(key));
            assert_eq!(candidate.bytes.as_bytes(), &[key as u8; 64]);
        }
        assert!(cache.pop_publication_candidate().unwrap().is_none());
        assert!(cache.publication_active);
        cache.clear_publication_candidates().unwrap();
        assert_eq!(cache.counters, counters);
        assert_eq!(cache.sketch, sketch);
        cache.trim_metadata().unwrap();
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn publication_scope_rejects_unrelated_membership_changes_until_cleared() {
        let (mut cache, _) = cache_for(8, 64);
        for key in 0..3 {
            drop(load(&mut cache, key, 64));
        }
        let mut cursor = CacheCursor::default();
        let unrelated = next_candidate(&cache, &mut cursor);
        cache.begin_publication_candidates().unwrap();
        assert_eq!(
            cache.begin_publication_candidates(),
            Err(AdmissionError::OwnerFailed)
        );
        cache.mark_publication_candidate(1).unwrap();
        assert_eq!(cache.set_byte_limit(0), Err(AdmissionError::OwnerFailed));
        assert_eq!(cache.trim_metadata(), Err(AdmissionError::OwnerFailed));
        assert_eq!(
            cache.remove_matching(|_| true),
            Err(AdmissionError::OwnerFailed)
        );
        assert_eq!(cache.copy_relocated(1, 4), Err(AdmissionError::OwnerFailed));
        assert_eq!(cache.alias_if_fits(1, 4), Err(AdmissionError::OwnerFailed));
        assert_eq!(
            cache.remove_candidate(&mut cursor, &unrelated),
            Err(AdmissionError::OwnerFailed)
        );
        assert!(!cache.remove_if_unchanged(&unrelated).unwrap());
        assert!(matches!(
            cache.load_if_fits(4, 64, |_| Ok::<_, ()>(())),
            Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
        ));
        assert!(matches!(
            cache.load(4, 64, |_| Ok::<_, ()>(())),
            Err(CacheLoadError::Admission(AdmissionError::OwnerFailed))
        ));
        for action in 0..3 {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match action {
                    0 => cache.clear(),
                    1 => {
                        cache.remove(2);
                    }
                    _ => cache.relocate(2, 4),
                }))
                .is_err()
            );
        }
        cache.clear_publication_candidates().unwrap();
        assert_eq!(cache.entries, 3);
        assert!(cache.remove(2));
        drop(load(&mut cache, 4, 64));
    }

    #[test]
    fn publication_cleanup_after_owner_failure_preserves_entries_and_clears_marks() {
        let (mut cache, admission) = cache_for(8, 64);
        drop(load(&mut cache, 1, 64));
        let before = cache.stats();
        admission.failed.store(true, Ordering::Release);
        assert_eq!(
            cache.begin_publication_candidates(),
            Err(AdmissionError::OwnerFailed)
        );
        assert!(!cache.publication_active);
        admission.failed.store(false, Ordering::Release);
        cache.begin_publication_candidates().unwrap();
        cache.mark_publication_candidate(1).unwrap();
        admission.failed.store(true, Ordering::Release);
        assert_eq!(
            cache.mark_publication_candidate(1),
            Err(AdmissionError::OwnerFailed)
        );
        assert!(matches!(
            cache.pop_publication_candidate(),
            Err(AdmissionError::OwnerFailed)
        ));
        assert_eq!(
            cache.clear_publication_candidates(),
            Err(AdmissionError::OwnerFailed)
        );
        assert!(!cache.publication_active);
        assert_eq!(cache.publication_marked, 0);
        assert_eq!(cache.stats(), before);
        admission.failed.store(false, Ordering::Release);
        cache.begin_publication_candidates().unwrap();
        cache.mark_publication_candidate(1).unwrap();
        let candidate = cache.pop_publication_candidate().unwrap().unwrap();
        admission.failed.store(true, Ordering::Release);
        assert_eq!(
            cache.remove_if_unchanged(&candidate),
            Err(AdmissionError::OwnerFailed)
        );
        cache.clear_publication_candidates().unwrap_err();
        assert!(cache.contains(1));
    }

    #[test]
    fn publication_corrupt_chain_cleanup_is_bounded_and_fails_closed() {
        let (mut cache, _) = cache_for(8, 64);
        for key in 0..2 {
            drop(load(&mut cache, key, 64));
        }
        cache.begin_publication_candidates().unwrap();
        cache.mark_publication_candidate(0).unwrap();
        cache.mark_publication_candidate(1).unwrap();
        let index = cache.find(1).unwrap();
        cache.slots[index].as_mut().unwrap().next_marked = Some(1);
        assert_eq!(
            cache.clear_publication_candidates(),
            Err(AdmissionError::OwnerFailed)
        );
        assert!(!cache.publication_active);
        assert_eq!(cache.entries, 2);
        assert!(
            cache
                .slots
                .iter()
                .flatten()
                .all(|entry| !entry.marked && entry.next_marked.is_none())
        );
        assert_eq!(
            cache.begin_publication_candidates(),
            Err(AdmissionError::OwnerFailed)
        );
    }

    #[test]
    fn publication_drop_cleanup_never_calls_admission_and_normal_clear_cleans_before_panic() {
        let (mut cache, admission) = cache_for(8, 64);
        drop(load(&mut cache, 1, 64));
        let before = cache.stats();
        cache.begin_publication_candidates().unwrap();
        cache.mark_publication_candidate(1).unwrap();
        admission.panic_next_check.store(true, Ordering::Release);
        cache.cleanup_publication_candidates().unwrap();
        assert!(admission.panic_next_check.swap(false, Ordering::AcqRel));
        assert!(!cache.publication_active);
        cache.begin_publication_candidates().unwrap();
        cache.mark_publication_candidate(1).unwrap();
        admission.panic_next_check.store(true, Ordering::Release);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                cache.clear_publication_candidates()
            }))
            .is_err()
        );
        assert!(!cache.publication_active);
        assert_eq!(cache.publication_marked, 0);
        assert!(cache.slots.iter().flatten().all(|entry| !entry.marked));
        assert_eq!(cache.stats(), before);
    }

    #[test]
    fn publication_candidate_removal_requires_same_payload_and_preserves_external_guard() {
        let (mut cache, admission) = cache_for(8, 64);
        let output = load(&mut cache, 1, 64);
        cache.begin_publication_candidates().unwrap();
        cache.mark_publication_candidate(1).unwrap();
        let old = cache.pop_publication_candidate().unwrap().unwrap();
        assert!(cache.remove_if_unchanged(&old).unwrap());
        cache.clear_publication_candidates().unwrap();
        let replaced = cache
            .load(1, 64, |bytes| {
                bytes.fill(9);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(!cache.remove_if_unchanged(&old).unwrap());
        assert_eq!(replaced.as_bytes(), &[9; 64]);
        assert_eq!(output.as_bytes(), &[1; 64]);
        drop((old, replaced));
        cache.clear();
        assert!(admission.used() >= output.charged_bytes());
        drop(cache);
        drop(output);
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn candidate_pass_has_bounded_work_and_does_not_train_demand_policy() {
        let (mut cache, admission) = cache_for(16, 64);
        for key in 0..16 {
            drop(load(&mut cache, key, 64));
        }
        drop(cache.get(2));
        let counters = cache.counters;
        let sketch = cache.sketch;
        let samples = cache.samples;
        let order = lru_keys(&cache);
        let used = admission.used();
        let mut cursor = CacheCursor::default();
        let zero = cache.candidate_step(&mut cursor, 0).unwrap();
        assert_eq!(zero.work, 0);
        assert!(!zero.complete && !zero.restarted && zero.candidate.is_none());
        let mut keys = std::collections::BTreeSet::new();
        let mut work = 0;
        loop {
            let step = cache.candidate_step(&mut cursor, 3).unwrap();
            assert!(step.work <= 3 && !step.restarted);
            work += step.work;
            if let Some(candidate) = step.candidate {
                assert!(keys.insert(candidate.key));
                assert_eq!(candidate.bytes.as_bytes(), &[candidate.key as u8; 64]);
                assert!(!step.complete);
            }
            if step.complete {
                break;
            }
            assert!(work <= cache.slots.len());
        }
        assert_eq!(work, cache.slots.len());
        assert_eq!(keys, (0..16).collect());
        assert_eq!(cache.counters, counters);
        assert_eq!(cache.sketch, sketch);
        assert_eq!(cache.samples, samples);
        assert_eq!(lru_keys(&cache), order);
        assert_eq!(admission.used(), used);
        let finished = cache.candidate_step(&mut cursor, 1).unwrap();
        assert!(finished.complete && finished.candidate.is_none());
        assert_eq!(finished.work, 0);
    }

    #[test]
    fn conditional_candidate_removal_revisits_backward_shifted_and_wrapped_slots() {
        for home in [0, 3, 15] {
            let (mut cache, admission) = cache_for(8, 64);
            let keys: Vec<_> = (0..10000)
                .filter(|key| key_hash(*key) as usize & 15 == home)
                .take(8)
                .collect();
            assert_eq!(keys.len(), 8);
            for key in &keys {
                drop(load(&mut cache, *key, 64));
            }
            let counters = cache.counters;
            let sketch = cache.sketch;
            let capacity = cache.slots.len();
            let mut cursor = CacheCursor::default();
            let mut seen = std::collections::BTreeSet::new();
            let mut work = 0;
            loop {
                let step = cache.candidate_step(&mut cursor, 1).unwrap();
                work += step.work;
                assert!(!step.restarted);
                if let Some(candidate) = step.candidate {
                    assert!(seen.insert(candidate.key));
                    assert!(cache.remove_candidate(&mut cursor, &candidate).unwrap());
                    assert!(!cache.contains(candidate.key));
                    assert_eq!(candidate.bytes.as_bytes(), &[candidate.key as u8; 64]);
                }
                if step.complete {
                    break;
                }
                assert!(work <= capacity + keys.len());
            }
            assert_eq!(seen, keys.into_iter().collect());
            assert_eq!(cache.entries, 0);
            assert_eq!(cache.counters, counters);
            assert_eq!(cache.sketch, sketch);
            cache.trim_metadata().unwrap();
            assert_eq!(admission.used(), 0);
        }
    }

    #[test]
    fn get_peek_and_failed_optional_admission_leave_candidate_tokens_valid() {
        let admission = Admission::new(u64::MAX);
        let mut cache = NativeCache::new(
            CacheConfig {
                byte_limit: 1 << 20,
            },
            admission.clone(),
        );
        for key in 0..3 {
            drop(load(&mut cache, key, 64));
        }
        let mut cursor = CacheCursor::default();
        let candidate = next_candidate(&cache, &mut cursor);
        drop(cache.get(candidate.key));
        drop(cache.peek(candidate.key));
        let counters = cache.counters;
        let sketch = cache.sketch;
        admission.limit.store(admission.used(), Ordering::Release);
        let loaded = cache.load_if_fits(100, 96 << 10, |_| -> Result<(), ()> {
            panic!("denied fill read data")
        });
        assert!(matches!(loaded, Ok(None)));
        assert!(cache.take_maintenance_provider_refusal());
        assert!(cache.remove_candidate(&mut cursor, &candidate).unwrap());
        assert_eq!(cache.counters, counters);
        assert_eq!(cache.sketch, sketch);
        assert!(!cache.candidate_step(&mut cursor, 1).unwrap().restarted);
    }

    #[test]
    fn insertion_removal_clear_relocation_and_aliasing_invalidate_external_candidates() {
        for mutation in 0..5 {
            let (mut cache, _) = cache_for(32, 64);
            for key in 0..8 {
                drop(load(&mut cache, key, 64));
            }
            let mut cursor = CacheCursor::default();
            let candidate = next_candidate(&cache, &mut cursor);
            let other = (0..8).find(|&key| key != candidate.key).unwrap();
            match mutation {
                0 => {
                    drop(load(&mut cache, 100, 64));
                    assert_eq!(cache.slots.len(), 32);
                }
                1 => assert!(cache.remove(other)),
                2 => cache.clear(),
                3 => cache.relocate(other, 100),
                4 => assert!(cache.copy_relocated(other, 100).unwrap()),
                _ => unreachable!(),
            }
            let count = cache.entries;
            assert!(!cache.remove_candidate(&mut cursor, &candidate).unwrap());
            assert_eq!(cache.entries, count);
            let restarted = cache.candidate_step(&mut cursor, 1).unwrap();
            assert!(restarted.restarted);
            assert!(restarted.work <= 1);
        }
    }

    #[test]
    fn stale_cursor_position_foreign_cache_and_replaced_payload_cannot_remove_candidates() {
        let (mut cache, _) = cache_for(8, 64);
        for key in 0..3 {
            drop(load(&mut cache, key, 64));
        }
        let mut cursor = CacheCursor::default();
        let candidate = next_candidate(&cache, &mut cursor);
        let later = next_candidate(&cache, &mut cursor);
        assert!(!cache.remove_candidate(&mut cursor, &candidate).unwrap());
        assert!(cache.contains(candidate.key));
        assert!(cache.remove_candidate(&mut cursor, &later).unwrap());

        let (mut other, _) = cache_for(8, 64);
        for key in 0..3 {
            drop(load(&mut other, key, 64));
        }
        let mut foreign_cursor = CacheCursor::default();
        let foreign = next_candidate(&other, &mut foreign_cursor);
        // The original candidate and this cache have equal initial versions,
        // slot positions and full keys, but distinct immutable payload owners.
        assert_eq!(foreign.key, candidate.key);
        assert_eq!(foreign.version, candidate.version);
        assert!(
            !other
                .remove_candidate(&mut foreign_cursor, &candidate)
                .unwrap()
        );
        assert!(other.contains(foreign.key));

        assert!(other.remove(foreign.key));
        let replacement = other
            .load(foreign.key, 64, |bytes| {
                bytes.fill(255);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(
            !other
                .remove_candidate(&mut foreign_cursor, &foreign)
                .unwrap()
        );
        assert_eq!(other.peek(foreign.key).unwrap().as_bytes(), &[255; 64]);
        assert_eq!(replacement.as_bytes(), &[255; 64]);
    }

    #[test]
    fn candidate_alias_removal_preserves_shared_payload_and_external_output_admission() {
        let (mut cache, admission) = cache_for(8, 1024);
        let output = load(&mut cache, 1, 1024);
        assert!(cache.copy_relocated(1, 2).unwrap());
        let charge = output.charged_bytes();
        let mut cursor = CacheCursor::default();
        let first = next_candidate(&cache, &mut cursor);
        assert!(CachedBytes::ptr_eq(&first.bytes, &output));
        assert!(cache.remove_candidate(&mut cursor, &first).unwrap());
        assert_eq!(cache.stats().cached_bytes, charge);
        assert_eq!(cache.stats().pinned_bytes, 0);
        drop(first);
        let last = next_candidate(&cache, &mut cursor);
        assert!(CachedBytes::ptr_eq(&last.bytes, &output));
        assert!(cache.remove_candidate(&mut cursor, &last).unwrap());
        assert_eq!(cache.stats().cached_bytes, 0);
        assert_eq!(cache.stats().pinned_bytes, charge);
        drop(last);
        cache.trim_metadata().unwrap();
        assert_eq!(output.as_bytes(), &[1; 1024]);
        assert!(admission.used() >= charge);
        drop(cache);
        assert!(admission.used() >= charge);
        drop(output);
        assert_eq!(admission.used(), 0);
    }

    #[test]
    fn trimming_retries_capacity_denial_then_invalidates_layout_without_policy_changes() {
        let (mut cache, admission) = cache_for(64, 64);
        for key in 0..64 {
            drop(load(&mut cache, key, 64));
        }
        for key in 4..64 {
            assert!(cache.remove(key));
        }
        let mut cursor = CacheCursor::default();
        let candidate = next_candidate(&cache, &mut cursor);
        let before = cache.stats();
        let counters = cache.counters;
        let order = lru_keys(&cache);
        let sketch = cache.sketch;
        let version = cache.structural_version;
        admission.limit.store(admission.used(), Ordering::Release);
        cache.trim_metadata().unwrap();
        assert_eq!(cache.stats(), before);
        assert_eq!(cache.structural_version, version);
        admission.limit.store(u64::MAX, Ordering::Release);
        cache.trim_metadata().unwrap();
        assert_eq!(cache.slots.len(), MIN_SLOTS);
        assert!(cache.stats().metadata_bytes < before.metadata_bytes);
        assert_eq!(cache.counters, counters);
        assert_eq!(cache.sketch, sketch);
        assert_eq!(lru_keys(&cache), order);
        assert!(!cache.remove_candidate(&mut cursor, &candidate).unwrap());
        assert!(cache.candidate_step(&mut cursor, 1).unwrap().restarted);
    }

    #[test]
    fn candidate_version_exhaustion_and_failed_owner_fail_closed_without_removing_bytes() {
        let (mut cache, admission) = cache_for(2, 64);
        drop(load(&mut cache, 1, 64));
        cache.structural_version = Some(u64::MAX);
        let mut cursor = CacheCursor::default();
        let candidate = next_candidate(&cache, &mut cursor);
        assert_eq!(
            cache.remove_candidate(&mut cursor, &candidate),
            Err(AdmissionError::OwnerFailed)
        );
        assert!(cache.contains(1));
        assert!(matches!(
            cache.candidate_step(&mut cursor, 1),
            Err(AdmissionError::OwnerFailed)
        ));
        cache.clear();
        assert_eq!(cache.structural_version, None);
        assert!(matches!(
            cache.candidate_step(&mut cursor, 1),
            Err(AdmissionError::OwnerFailed)
        ));
        drop(candidate);
        drop(cache);
        assert_eq!(admission.used(), 0);

        let (mut cache, admission) = cache_for(2, 64);
        drop(load(&mut cache, 1, 64));
        let mut cursor = CacheCursor::default();
        let candidate = next_candidate(&cache, &mut cursor);
        admission.failed.store(true, Ordering::Release);
        assert!(matches!(
            cache.candidate_step(&mut cursor, 1),
            Err(AdmissionError::OwnerFailed)
        ));
        assert_eq!(
            cache.remove_candidate(&mut cursor, &candidate),
            Err(AdmissionError::OwnerFailed)
        );
        assert_eq!(cache.trim_metadata(), Err(AdmissionError::OwnerFailed));
        assert!(cache.contains(1));
    }
}
