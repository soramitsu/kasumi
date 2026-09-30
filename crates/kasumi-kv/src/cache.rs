//! An admitted cache for immutable backend values and index pages.
//!
//! Keys are physical identities within one database incarnation. Callers must
//! clear the cache before reusing those identities (for example, compaction).
//! Authorization, expiry and snapshot selection belong to the caller and must
//! run before a lookup. This cache does not make those decisions.

use crate::{AdmissionError, ResidentLease, StorageAdmission};
use std::mem::{size_of, take};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
    /// Values currently reachable through the cache, including their owners.
    pub cached_bytes: u64,
    /// Evicted values still held by readers. Eviction does not release these.
    pub pinned_bytes: u64,
    pub metadata_bytes: u64,
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

struct Accounting {
    live_values: AtomicU64,
    metadata_charge: u64,
    // Retained by values even after their cache has been dropped.
    _lease: Box<dyn ResidentLease>,
}

/// Immutable bytes whose admission lives until the final reader releases them.
pub struct CachedBytes {
    bytes: Vec<u8>,
    charge: u64,
    accounting: Option<Arc<Accounting>>,
    _lease: Box<dyn ResidentLease>,
}
impl CachedBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn charged_bytes(&self) -> u64 {
        self.charge
    }

    fn charge_for_len(len: usize) -> Option<u64> {
        // Arc's two counters and the entire byte owner, not just payload bytes.
        (len as u64)
            .checked_add((size_of::<Self>() + 2 * size_of::<usize>()) as u64)
            .and_then(|bytes| {
                bytes
                    .checked_add(ALLOCATION_ALLOWANCE * (1 + u64::from(len != 0)) + LEASE_ALLOWANCE)
            })
    }
}
impl Drop for CachedBytes {
    fn drop(&mut self) {
        // Free the payload before publishing reusable cache capacity. The
        // storage lease additionally survives through field destruction.
        drop(take(&mut self.bytes));
        if let Some(accounting) = &self.accounting {
            accounting
                .live_values
                .fetch_sub(self.charge, Ordering::AcqRel);
        }
    }
}

struct Entry {
    key: u64,
    value: Arc<CachedBytes>,
    previous: usize,
    next: usize,
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
pub struct NativeCache {
    config: CacheConfig,
    admission: Arc<dyn StorageAdmission>,
    accounting: Option<Arc<Accounting>>,
    slots: Vec<Option<Entry>>,
    slots_lease: Option<Box<dyn ResidentLease>>,
    slots_charge: u64,
    entries: usize,
    cached_bytes: u64,
    head: usize,
    tail: usize,
    sketch: [u8; SKETCH_WIDTH * SKETCH_ROWS],
    samples: u64,
    counters: CacheStats,
}

impl NativeCache {
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
            cached_bytes: 0,
            head: NONE,
            tail: NONE,
            sketch: [0; SKETCH_WIDTH * SKETCH_ROWS],
            samples: 0,
            counters: CacheStats::default(),
        }
    }

    pub fn config(&self) -> CacheConfig {
        self.config
    }

    pub fn stats(&self) -> CacheStats {
        let values = self.accounting.as_ref().map_or(0, |accounting| {
            accounting.live_values.load(Ordering::Acquire)
        });
        let metadata = self.metadata_bytes();
        CacheStats {
            entries: self.entries,
            resident_bytes: metadata + values,
            cached_bytes: self.cached_bytes,
            pinned_bytes: values.saturating_sub(self.cached_bytes),
            metadata_bytes: metadata,
            ..self.counters
        }
    }

    /// A shrinking budget releases infrequently used, older values first and
    /// shrinks directory backing. If readers still pin more than the new
    /// budget, return denial and keep the previous limit.
    pub fn set_byte_limit(&mut self, byte_limit: u64) -> Result<(), AdmissionError> {
        if byte_limit == 0 && self.stats().resident_bytes != 0 {
            self.clear();
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
                        && (remove_pinned || Arc::strong_count(&entry.value) == 1)
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
        self.slots = Vec::new();
        self.slots_lease = None;
        self.slots_charge = 0;
        self.entries = 0;
        self.cached_bytes = 0;
        self.head = NONE;
        self.tail = NONE;
        self.sketch.fill(0);
        self.samples = 0;
        self.release_unused_accounting();
    }

    /// Remove an identity before its physical address can be reused.
    pub fn remove(&mut self, key: u64) -> bool {
        if let Some(index) = self.find(key) {
            self.remove_slot(index);
            true
        } else {
            false
        }
    }

    /// A membership check without altering frequency, recency or statistics.
    pub fn contains(&self, key: u64) -> bool {
        self.find(key).is_some()
    }

    /// Preserve a cached value across an immutable physical relocation.
    /// Invalidate the destination even when the source was not resident.
    /// This operation allocates no memory and preserves the source's LRU rank.
    pub fn relocate(&mut self, old_key: u64, new_key: u64) {
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

    pub fn get(&mut self, key: u64) -> Option<Arc<CachedBytes>> {
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
        key: u64,
        len: usize,
        loader: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<Arc<CachedBytes>, CacheLoadError<E>> {
        if let Some(value) = self.get(key) {
            return Ok(value);
        }
        let charge = CachedBytes::charge_for_len(len).ok_or(AdmissionError::CapacityDenied)?;
        let retain = match self.prepare(key, charge) {
            Ok(retain) => retain,
            Err(AdmissionError::CapacityDenied) => false,
            Err(error) => return Err(error.into()),
        };
        let lease = self.admission.reserve_workspace(charge)?;
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
        self.counters.loads = self.counters.loads.saturating_add(1);
        let accounting = if retain {
            let accounting = self.accounting.as_ref().unwrap().clone();
            accounting.live_values.fetch_add(charge, Ordering::AcqRel);
            Some(accounting)
        } else {
            self.counters.uncached_loads = self.counters.uncached_loads.saturating_add(1);
            None
        };
        let value = Arc::new(CachedBytes {
            bytes,
            charge,
            accounting,
            _lease: lease,
        });
        if retain {
            self.insert(Entry {
                key,
                value: value.clone(),
                previous: NONE,
                next: NONE,
            });
        }
        Ok(value)
    }

    fn metadata_base_charge() -> u64 {
        (size_of::<Self>() + size_of::<Accounting>() + 2 * size_of::<usize>()) as u64
            + ALLOCATION_ALLOWANCE
            + LEASE_ALLOWANCE
    }

    fn slots_charge(capacity: usize) -> Option<u64> {
        capacity
            .checked_mul(size_of::<Option<Entry>>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| bytes.checked_add(ALLOCATION_ALLOWANCE + LEASE_ALLOWANCE))
    }

    fn shrink_directory(&mut self) -> Result<(), AdmissionError> {
        if self.entries == 0 {
            self.slots = Vec::new();
            self.slots_lease = None;
            self.slots_charge = 0;
            self.release_unused_accounting();
            return Ok(());
        }
        let capacity = (self.entries * 2).max(MIN_SLOTS).next_power_of_two();
        if capacity < self.slots.len() {
            let charge = Self::slots_charge(capacity).ok_or(AdmissionError::CapacityDenied)?;
            match self.resize_slots(capacity, charge) {
                Ok(()) | Err(AdmissionError::CapacityDenied) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn metadata_bytes(&self) -> u64 {
        self.slots_charge
            + self
                .accounting
                .as_ref()
                .map_or(0, |accounting| accounting.metadata_charge)
    }

    fn release_unused_accounting(&mut self) {
        if self.slots.is_empty()
            && self
                .accounting
                .as_ref()
                .is_some_and(|accounting| accounting.live_values.load(Ordering::Acquire) == 0)
        {
            self.accounting = None;
        }
    }

    fn prepare(&mut self, key: u64, charge: u64) -> Result<bool, AdmissionError> {
        self.release_unused_accounting();
        let minimum = Self::metadata_base_charge()
            .checked_add(Self::slots_charge(MIN_SLOTS).unwrap())
            .and_then(|bytes| bytes.checked_add(charge));
        if minimum.is_none_or(|bytes| bytes > self.config.byte_limit) {
            return Ok(false);
        }
        if self.accounting.is_none() {
            let metadata_charge = Self::metadata_base_charge();
            let lease = self.admission.reserve_workspace(metadata_charge)?;
            self.accounting = Some(Arc::new(Accounting {
                live_values: AtomicU64::new(0),
                metadata_charge,
                _lease: lease,
            }));
        }
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
            let needed = self
                .stats()
                .resident_bytes
                .checked_sub(self.slots_charge)
                .and_then(|bytes| bytes.checked_add(next_slots_charge))
                .and_then(|bytes| bytes.checked_add(charge));
            if needed.is_some_and(|bytes| bytes <= self.config.byte_limit) {
                if required_slots != self.slots.len() {
                    self.resize_slots(required_slots, next_slots_charge)?;
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
        let lease = self.admission.reserve_workspace(charge)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| AdmissionError::CapacityDenied)?;
        if slots.capacity() != capacity {
            return Err(AdmissionError::CapacityDenied);
        }
        slots.resize_with(capacity, || None);
        let mut old = std::mem::replace(&mut self.slots, slots);
        let old_lease = self.slots_lease.replace(lease);
        self.slots_charge = charge;
        let mut index = self.head;
        self.entries = 0;
        self.cached_bytes = 0;
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
        drop(old_lease);
        Ok(())
    }

    fn find(&self, key: u64) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut index = hash(key) as usize & mask;
        loop {
            match &self.slots[index] {
                None => return None,
                Some(entry) if entry.key == key => return Some(index),
                Some(_) => index = (index + 1) & mask,
            }
        }
    }

    fn insert(&mut self, mut entry: Entry) {
        let mask = self.slots.len() - 1;
        let mut index = hash(entry.key) as usize & mask;
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
        self.cached_bytes += entry.value.charge;
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

    fn take_slot(&mut self, index: usize) -> Entry {
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
        self.cached_bytes -= entry.value.charge;
        // Backward-shift deletion avoids a tombstone directory growing with a
        // long scan. Update intrusive LRU links whenever an entry moves.
        let mask = self.slots.len() - 1;
        let mut hole = index;
        let mut scan = (hole + 1) & mask;
        while let Some(entry) = &self.slots[scan] {
            let home = hash(entry.key) as usize & mask;
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

    fn record_access(&mut self, key: u64) {
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

    fn frequency(&self, key: u64) -> u8 {
        (0..SKETCH_ROWS)
            .map(|row| self.sketch[Self::sketch_index(key, row)])
            .min()
            .unwrap()
    }

    fn sketch_index(key: u64, row: usize) -> usize {
        row * SKETCH_WIDTH
            + (hash(key.wrapping_add((row as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15))) as usize
                & (SKETCH_WIDTH - 1))
    }
}

fn hash(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OwnerFailed;
    use std::sync::atomic::AtomicBool;

    struct Admission {
        used: Arc<AtomicU64>,
        limit: AtomicU64,
        failed: AtomicBool,
    }
    struct Lease {
        used: Arc<AtomicU64>,
        bytes: u64,
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            self.used.fetch_sub(self.bytes, Ordering::AcqRel);
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
        fn used(&self) -> u64 {
            self.used.load(Ordering::Acquire)
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
                        .filter(|next| *next <= self.limit.load(Ordering::Acquire))
                })
                .map_err(|_| AdmissionError::CapacityDenied)?;
            Ok(Box::new(Lease {
                used: self.used.clone(),
                bytes,
            }))
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

    fn cache_for(entries: usize, len: usize) -> (NativeCache, Arc<Admission>) {
        let admission = Admission::new(u64::MAX);
        let slots = (entries * 2).max(MIN_SLOTS).next_power_of_two();
        let limit = NativeCache::metadata_base_charge()
            + NativeCache::slots_charge(slots).unwrap()
            + entries as u64 * CachedBytes::charge_for_len(len).unwrap();
        (
            NativeCache::new(CacheConfig { byte_limit: limit }, admission.clone()),
            admission,
        )
    }

    fn load(cache: &mut NativeCache, key: u64, len: usize) -> Arc<CachedBytes> {
        cache
            .load(key, len, |out| {
                out.fill(key as u8);
                Ok::<_, ()>(())
            })
            .unwrap()
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
        let expected = NativeCache::metadata_base_charge() + pinned.charged_bytes();
        drop(cache);
        assert_eq!(admission.used(), expected);
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
        assert_eq!(admission.used(), cache.stats().metadata_bytes);
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
    fn colliding_directory_removals_preserve_lookup_and_lru_links() {
        let (mut cache, _) = cache_for(8, 64);
        let keys: Vec<_> = (0..1000)
            .filter(|key| hash(*key) as usize & 15 == 15)
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
}
