use crate::tree_store::page_store::fast_hash::{FastHashMapU64, Shrink};
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub struct LRUCache<T> {
    // AtomicBool is the second chance flag
    cache: FastHashMapU64<(T, AtomicBool)>,
    lru_queue: VecDeque<u64>,
}

impl<T> LRUCache<T> {
    pub(crate) fn new() -> Self {
        Self {
            cache: FastHashMapU64::default(),
            lru_queue: VecDeque::default(),
        }
    }

    pub(crate) fn contains_key(&self, key: u64) -> bool {
        self.cache.contains_key(&key)
    }

    pub(crate) fn len(&self) -> usize {
        self.cache.len()
    }

    pub(crate) fn insert(&mut self, key: u64, value: T) -> Option<T> {
        let result = self
            .cache
            .insert(key, (value, AtomicBool::new(false)))
            .map(|(x, _)| x);
        if result.is_none() {
            self.lru_queue.push_back(key);
        }
        result
    }

    pub(crate) fn remove(&mut self, key: u64) -> Option<T> {
        if let Some((value, _)) = self.cache.remove(&key) {
            // Remove the queue registration while the key is absent. Leaving
            // it stale and later reinserting the same key turns that stale
            // registration live again, so bounded cache payload would not bound
            // queue memory. Retain preserves every other key's priority and
            // second-chance flag and performs no allocation.
            self.lru_queue.retain(|queued| *queued != key);
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn get(&self, key: u64) -> Option<&T> {
        if let Some((value, second_chance)) = self.cache.get(&key) {
            second_chance.store(true, Ordering::Release);
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn get_mut(&mut self, key: u64) -> Option<&mut T> {
        if let Some((value, second_chance)) = self.cache.get_mut(&key) {
            second_chance.store(true, Ordering::Release);
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = (&u64, &T)> {
        self.cache.iter().map(|(k, (v, _))| (k, v))
    }

    pub(crate) fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = (&u64, &mut T)> {
        self.cache.iter_mut().map(|(k, (v, _))| (k, v))
    }

    pub(crate) fn pop_lowest_priority(&mut self) -> Option<(u64, T)> {
        while let Some(key) = self.lru_queue.pop_front() {
            if let Some((_, second_chance)) = self.cache.get(&key) {
                if second_chance
                    .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    self.lru_queue.push_back(key);
                } else {
                    let (value, _) = self.cache.remove(&key).unwrap();
                    return Some((key, value));
                }
            }
        }
        None
    }

    pub(crate) fn clear(&mut self) {
        self.cache.shrink();
        self.cache.clear();
        self.lru_queue.shrink_to_fit();
        self.lru_queue.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_same_key_invalidation_keeps_one_queue_registration_per_live_page() {
        let mut cache = LRUCache::new();
        for key in 0..3u64 {
            assert!(cache.insert(key, key).is_none());
        }
        for revision in 0..10_000u64 {
            // The old two-entry sweep never sees this absent key. Reinserting
            // it revives its old registration, despite only three live pages.
            let key = (0..3u64)
                .find(|key| !cache.lru_queue.iter().take(2).any(|queued| queued == key))
                .unwrap();
            assert!(cache.remove(key).is_some());
            assert!(cache.insert(key, revision).is_none());
        }
        eprintln!(
            "live_pages={} queue_entries={} queue_capacity={}",
            cache.len(),
            cache.lru_queue.len(),
            cache.lru_queue.capacity()
        );
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.lru_queue.len(), cache.len());
        for key in 0..3u64 {
            assert_eq!(
                cache
                    .lru_queue
                    .iter()
                    .filter(|queued| **queued == key)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn invalidation_preserves_other_pages_priority_and_second_chance() {
        let mut cache = LRUCache::new();
        cache.insert(1, 10);
        cache.insert(2, 20);
        cache.insert(3, 30);
        assert_eq!(cache.get(1), Some(&10));
        assert_eq!(cache.remove(2), Some(20));
        assert_eq!(cache.remove(2), None);
        cache.insert(4, 40);
        assert_eq!(cache.pop_lowest_priority(), Some((3, 30)));
        assert_eq!(cache.pop_lowest_priority(), Some((4, 40)));
        assert_eq!(cache.pop_lowest_priority(), Some((1, 10)));
        assert_eq!(cache.pop_lowest_priority(), None);
        assert!(cache.lru_queue.is_empty());
        cache.insert(5, 50);
        assert_eq!(cache.insert(5, 51), Some(50));
        assert_eq!(cache.lru_queue.len(), 1);
        assert_eq!(cache.pop_lowest_priority(), Some((5, 51)));
    }
}
