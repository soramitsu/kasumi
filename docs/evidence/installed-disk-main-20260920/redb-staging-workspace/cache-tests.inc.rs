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
        eprintln!("live_pages={} queue_entries={} queue_capacity={}", cache.len(), cache.lru_queue.len(), cache.lru_queue.capacity());
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.lru_queue.len(), cache.len());
        for key in 0..3u64 {
            assert_eq!(cache.lru_queue.iter().filter(|queued| **queued == key).count(), 1);
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
