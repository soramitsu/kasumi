//! Two preallocated std tables, with no resizing or tombstone-dependent denial.
//! Pinned Rust 1.97.1 / hashbrown 0.17.1: capacity == items + growth_left.
use super::Identity;
use std::{collections::HashMap, io, ops::Index};

pub(super) struct Map<V> {
    entries: HashMap<Identity, V>,
    limit: usize,
}
impl<V> Map<V> {
    fn new(limit: usize) -> io::Result<Self> {
        let mut entries = HashMap::new();
        // The only table allocation. The caller holds the complete installed
        // two-bank memory reservation before constructing either bank.
        entries
            .try_reserve(limit)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        if entries.capacity() < limit {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        Ok(Self { entries, limit })
    }
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
    pub(super) fn get(&self, key: &Identity) -> Option<&V> {
        self.entries.get(key)
    }
    pub(super) fn get_mut(&mut self, key: &Identity) -> Option<&mut V> {
        self.entries.get_mut(key)
    }
    pub(super) fn contains_key(&self, key: &Identity) -> bool {
        self.entries.contains_key(key)
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Identity, &V)> {
        self.entries.iter()
    }
    pub(super) fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.values()
    }
    pub(super) fn try_reserve(&mut self, additional: usize) -> io::Result<()> {
        let next = self
            .len()
            .checked_add(additional)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        if next > self.limit || next > self.entries.capacity() {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        Ok(())
    }
    pub(super) fn insert(&mut self, key: Identity, value: V) -> Option<V> {
        // hashbrown insert reserves BEFORE checking occupancy. Never call that
        // path for a replacement at exhausted growth_left.
        if let Some(existing) = self.entries.get_mut(&key) {
            return Some(std::mem::replace(existing, value));
        }
        assert!(
            self.len() < self.limit && self.len() < self.entries.capacity(),
            "absent insertion requires a prepared fixed slot"
        );
        self.entries.insert(key, value)
    }
    pub(super) fn remove(&mut self, key: &Identity) -> Option<V> {
        self.entries.remove(key)
    }
    fn reset(&mut self) {
        // clear() skips an empty map and can preserve depleted growth_left.
        // RawDrain's Drop calls clear_no_drop even when len == 0.
        drop(self.entries.drain());
    }
}
impl<V> Index<&Identity> for Map<V> {
    type Output = V;
    fn index(&self, key: &Identity) -> &V {
        &self.entries[key]
    }
}

struct ResetCandidate<'a, V>(&'a mut Map<V>);
impl<V> Drop for ResetCandidate<'_, V> {
    fn drop(&mut self) {
        self.0.reset();
    }
}

pub(super) struct Banks<V> {
    active: Map<V>,
    spare: Map<V>,
    limit: usize,
    #[cfg(test)]
    rebuilds: usize,
}
impl<V: Clone> Banks<V> {
    pub(super) fn new(limit: usize) -> io::Result<Self> {
        Ok(Self {
            active: Map::new(limit)?,
            spare: Map::new(limit)?,
            limit,
            #[cfg(test)]
            rebuilds: 0,
        })
    }
    pub(super) fn len(&self) -> usize {
        self.active.len()
    }
    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub(super) fn get(&self, key: &Identity) -> Option<&V> {
        self.active.get(key)
    }
    pub(super) fn get_mut(&mut self, key: &Identity) -> Option<&mut V> {
        self.active.get_mut(key)
    }
    pub(super) fn contains_key(&self, key: &Identity) -> bool {
        self.active.contains_key(key)
    }
    pub(super) fn iter(&self) -> impl Iterator<Item = (&Identity, &V)> {
        self.active.iter()
    }
    pub(super) fn values(&self) -> impl Iterator<Item = &V> {
        self.active.values()
    }
    pub(super) fn insert(&mut self, key: Identity, value: V) -> Option<V> {
        self.active.insert(key, value)
    }
    pub(super) fn remove(&mut self, key: &Identity) -> Option<V> {
        self.active.remove(key)
    }
    pub(super) fn try_reserve(&mut self, additional: usize) -> io::Result<()> {
        if self
            .len()
            .checked_add(additional)
            .is_none_or(|next| next > self.limit)
        {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        if self.active.try_reserve(additional).is_ok() {
            return Ok(());
        }
        self.spare.reset();
        self.spare.limit = self.limit;
        // Cleanup runs on error and unwind before the State guard can unlock.
        // In particular, duplicate Weak handles may not outlive preparation
        // and delay a FileOwner's actual last-Weak retirement.
        let candidate = ResetCandidate(&mut self.spare);
        for (key, value) in self.active.iter() {
            candidate.0.try_reserve(1)?;
            assert!(candidate.0.insert(*key, value.clone()).is_none());
        }
        candidate.0.try_reserve(additional)?;
        // The active map remains unchanged until every copy and check succeeds.
        std::mem::swap(&mut self.active, candidate.0);
        #[cfg(test)]
        {
            self.rebuilds += 1;
        }
        drop(candidate);
        Ok(())
    }
    /// State serialization excludes file preparation and another census while
    /// the inactive bank contains an unpublished candidate. Its logical census
    /// quota may be smaller than the retained physical backing.
    pub(super) fn stage(&mut self, logical_limit: usize) -> io::Result<&mut Map<V>> {
        if logical_limit > self.limit {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.spare.reset();
        self.spare.limit = logical_limit;
        Ok(&mut self.spare)
    }
    pub(super) fn cancel_stage(&mut self) {
        self.spare.reset();
        self.spare.limit = self.limit;
    }
    /// Call only after the candidate's complete census and all fallible shared
    /// promise checks. Both banks already have retained capacity; no expansion
    /// allocation or old/new backing overlap is introduced at publication.
    pub(super) fn commit_stage(&mut self) {
        self.spare.limit = self.limit;
        std::mem::swap(&mut self.active, &mut self.spare);
        self.spare.reset();
        self.spare.limit = self.limit;
    }
    pub(super) fn clear(&mut self) {
        self.active.reset();
        self.cancel_stage();
    }
}
impl<V> Index<&Identity> for Banks<V> {
    type Output = V;
    fn index(&self, key: &Identity) -> &V {
        &self.active[key]
    }
}

/// Exact pinned requested table allocation, conservatively using the largest
/// supported control-group width (16). This bounds requested backing, not the
/// allocator's physical footprint. It replaces the former 4*count estimate.
pub(super) fn bank_bytes<V>(limit: usize) -> io::Result<u64> {
    use std::{
        alloc::Layout,
        mem::{align_of, size_of},
    };
    let overflow = || io::Error::from(io::ErrorKind::OutOfMemory);
    if limit == 0 {
        return Ok(0);
    }
    let buckets = if limit < 4 {
        4
    } else if limit < 8 {
        8
    } else if limit < 15 {
        16
    } else {
        (limit.checked_mul(8).ok_or_else(overflow)? / 7)
            .checked_next_power_of_two()
            .ok_or_else(overflow)?
    };
    // Every key is a 16-byte Identity, so hashbrown's tiny-element minimum
    // exceptions cannot apply even when V has zero size.
    let group = 16usize;
    let alignment = align_of::<(Identity, V)>().max(group);
    let data = size_of::<(Identity, V)>()
        .checked_mul(buckets)
        .ok_or_else(overflow)?;
    let controls = data.checked_add(alignment - 1).ok_or_else(overflow)? & !(alignment - 1);
    let bytes = controls
        .checked_add(buckets)
        .and_then(|n| n.checked_add(group))
        .ok_or_else(overflow)?;
    Layout::from_size_align(bytes, alignment).map_err(|_| overflow())?;
    u64::try_from(bytes).map_err(|_| overflow())
}

#[cfg(test)]
mod tests;
