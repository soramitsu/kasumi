//! Canonical allocator keys are checked before any typed comparator or decoder.
//! The raw walk uses the fixed five-byte key / variable value representation.
use super::btree_base::{BRANCH, LEAF, MAX_BTREE_DEPTH};
use super::{BtreeHeader, Page, PageHint, PageNumber, PageResolver};
use crate::transactions::AllocatorStateKey;
use crate::{Result, StorageError};
use core::mem::size_of;

fn malformed() -> StorageError {
    StorageError::Corrupted("Invalid canonical allocator-state page or record".into())
}

fn read_end(bytes: &[u8], offset: usize) -> Result<usize> {
    let raw = bytes
        .get(offset..offset + size_of::<u32>())
        .ok_or_else(malformed)?;
    Ok(u32::from_le_bytes(raw.try_into().map_err(|_| malformed())?) as usize)
}

#[derive(Clone, Copy, Default)]
struct KeyRange {
    lower_exclusive: Option<AllocatorStateKey>,
    upper_inclusive: Option<AllocatorStateKey>,
}
impl KeyRange {
    fn contains(self, key: AllocatorStateKey) -> bool {
        self.lower_exclusive.is_none_or(|lower| key > lower)
            && self.upper_inclusive.is_none_or(|upper| key <= upper)
    }
}

fn validate_leaf(
    bytes: &[u8],
    count: usize,
    previous: &mut Option<AllocatorStateKey>,
    record: &mut impl FnMut(AllocatorStateKey, &[u8]) -> Result,
    range: KeyRange,
) -> Result {
    let keys_start = 4_usize
        .checked_add(count.checked_mul(4).ok_or_else(malformed)?)
        .ok_or_else(malformed)?;
    let keys_end = keys_start
        .checked_add(count.checked_mul(5).ok_or_else(malformed)?)
        .ok_or_else(malformed)?;
    let keys = bytes.get(keys_start..keys_end).ok_or_else(malformed)?;
    let mut value_start = keys_end;
    for (index, raw) in keys.chunks_exact(5).enumerate() {
        let key = AllocatorStateKey::checked(raw)?;
        if !range.contains(key) || previous.is_some_and(|last| last >= key) {
            return Err(malformed());
        }
        let end = read_end(bytes, 4 + index * 4)?;
        if end < value_start || end > bytes.len() {
            return Err(malformed());
        }
        if key == AllocatorStateKey::TransactionId && end - value_start != size_of::<u64>() {
            return Err(malformed());
        }
        record(key, &bytes[value_start..end])?;
        *previous = Some(key);
        value_start = end;
    }
    Ok(())
}

fn validate_page(
    page_number: PageNumber,
    resolver: &PageResolver,
    path: &mut [Option<PageNumber>; MAX_BTREE_DEPTH],
    depth: usize,
    previous: &mut Option<AllocatorStateKey>,
    record: &mut impl FnMut(AllocatorStateKey, &[u8]) -> Result,
    range: KeyRange,
) -> Result {
    if depth >= path.len() || path[..depth].contains(&Some(page_number)) {
        return Err(malformed());
    }
    path[depth] = Some(page_number);
    let page = resolver.get_page(page_number, PageHint::None)?;
    let bytes = page.memory();
    let prefix = bytes.get(..4).ok_or_else(malformed)?;
    let count = usize::from(u16::from_le_bytes([prefix[2], prefix[3]]));
    if count == 0 {
        return Err(malformed());
    }
    match prefix[0] {
        LEAF => validate_leaf(bytes, count, previous, record, range),
        BRANCH => {
            let children = count.checked_add(1).ok_or_else(malformed)?;
            let children_start = 8_usize
                .checked_add(children.checked_mul(16).ok_or_else(malformed)?)
                .ok_or_else(malformed)?;
            let keys_start = children_start
                .checked_add(children.checked_mul(8).ok_or_else(malformed)?)
                .ok_or_else(malformed)?;
            let keys_end = keys_start
                .checked_add(count.checked_mul(5).ok_or_else(malformed)?)
                .ok_or_else(malformed)?;
            let keys = bytes.get(keys_start..keys_end).ok_or_else(malformed)?;
            let mut last_separator = None;
            for raw in keys.chunks_exact(5) {
                let key = AllocatorStateKey::checked(raw)?;
                if !range.contains(key) || last_separator.is_some_and(|last| last >= key) {
                    return Err(malformed());
                }
                last_separator = Some(key);
            }
            // All branch metadata was checked before following even the first
            // pointer, so malformed separators never reach typed comparison.
            let raw_children = bytes
                .get(children_start..keys_start)
                .ok_or_else(malformed)?;
            let mut lower = range.lower_exclusive;
            for (index, raw) in raw_children
                .chunks_exact(PageNumber::serialized_size())
                .enumerate()
            {
                let upper = if index < count {
                    Some(AllocatorStateKey::checked(&keys[index * 5..index * 5 + 5])?)
                } else {
                    range.upper_inclusive
                };
                let child = PageNumber::from_le_bytes(raw.try_into().map_err(|_| malformed())?);
                validate_page(
                    child,
                    resolver,
                    path,
                    depth + 1,
                    previous,
                    record,
                    KeyRange {
                        lower_exclusive: lower,
                        upper_inclusive: upper,
                    },
                )?;
                lower = upper;
            }
            Ok(())
        }
        _ => Err(malformed()),
    }
}

pub(crate) fn validate_allocator_state_keys(
    root: Option<BtreeHeader>,
    resolver: &PageResolver,
) -> Result {
    let mut path = [None; MAX_BTREE_DEPTH];
    let mut previous = None;
    let mut snapshot = resolver.allocator_snapshot_validation()?;
    if let Some(root) = root {
        validate_page(
            root.root,
            resolver,
            &mut path,
            0,
            &mut previous,
            &mut |key, value| snapshot.record(key, value),
            KeyRange::default(),
        )?;
    }
    snapshot.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree_store::{
        AllocationPolicy, InMemoryBackend, PageAllocator, PageTracker, TransactionalMemory,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;

    fn validate_key_leaf(
        bytes: &[u8],
        count: usize,
        previous: &mut Option<AllocatorStateKey>,
    ) -> Result {
        validate_leaf(
            bytes,
            count,
            previous,
            &mut |_, _| Ok(()),
            KeyRange::default(),
        )
    }

    fn validate_key_pages(root: Option<BtreeHeader>, resolver: &PageResolver) -> Result {
        let mut path = [None; MAX_BTREE_DEPTH];
        let mut previous = None;
        if let Some(root) = root {
            validate_page(
                root.root,
                resolver,
                &mut path,
                0,
                &mut previous,
                &mut |_, _| Ok(()),
                KeyRange::default(),
            )?;
        }
        Ok(())
    }

    fn leaf(key: [u8; 5], value: &[u8]) -> alloc::vec::Vec<u8> {
        let mut bytes = vec![0; 13 + value.len()];
        bytes[0] = LEAF;
        bytes[2..4].copy_from_slice(&1_u16.to_le_bytes());
        let end = u32::try_from(bytes.len()).unwrap();
        bytes[4..8].copy_from_slice(&end.to_le_bytes());
        bytes[8..13].copy_from_slice(&key);
        bytes[13..].copy_from_slice(value);
        bytes
    }

    #[test]
    fn allocator_raw_leaf_geometry_is_checked_before_key_or_value_access() {
        let valid = leaf([5, 0, 0, 0, 0], &[0; 8]);
        validate_key_leaf(&valid, 1, &mut None).unwrap();
        for end in 0..valid.len() {
            assert!(matches!(
                validate_key_leaf(&valid[..end], 1, &mut None),
                Err(StorageError::Corrupted(_))
            ));
        }
        let mut backwards = valid.clone();
        backwards[4..8].copy_from_slice(&12_u32.to_le_bytes());
        assert!(validate_key_leaf(&backwards, 1, &mut None).is_err());
        let mut too_far = valid.clone();
        too_far[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(validate_key_leaf(&too_far, 1, &mut None).is_err());
        for size in [0, 7, 9] {
            assert!(
                validate_key_leaf(&leaf([5, 0, 0, 0, 0], &vec![0; size]), 1, &mut None).is_err()
            );
        }
        let mut previous = Some(AllocatorStateKey::TransactionId);
        assert!(validate_key_leaf(&valid, 1, &mut previous).is_err());
    }

    #[test]
    fn allocator_raw_walk_rejects_bad_branch_separator_and_cycle_without_comparison() {
        let mem = TransactionalMemory::new(
            Box::new(InMemoryBackend::new()),
            crate::test_admission(),
            true,
            4096,
            None,
            0,
        )
        .unwrap();
        mem.reset_allocator_state().unwrap();
        let mem = Arc::new(mem);
        let allocator = PageAllocator::new(mem, AllocationPolicy::Default);
        let allocated = PageTracker::new_tracking();
        let mut left = allocator.allocate(4096, &allocated).unwrap();
        let raw = leaf([3, 0, 0, 0, 0], &[]);
        left.memory_mut()[..raw.len()].copy_from_slice(&raw);
        let left_number = left.get_page_number();
        drop(left);
        let mut right = allocator.allocate(4096, &allocated).unwrap();
        let raw = leaf([5, 0, 0, 0, 0], &[0; 8]);
        right.memory_mut()[..raw.len()].copy_from_slice(&raw);
        let right_number = right.get_page_number();
        drop(right);
        let mut branch = allocator.allocate(4096, &allocated).unwrap();
        branch.memory_mut().fill(0);
        branch.memory_mut()[0] = BRANCH;
        branch.memory_mut()[2..4].copy_from_slice(&1_u16.to_le_bytes());
        branch.memory_mut()[40..48].copy_from_slice(&left_number.to_le_bytes());
        branch.memory_mut()[48..56].copy_from_slice(&right_number.to_le_bytes());
        branch.memory_mut()[56..61].copy_from_slice(&[3, 0, 0, 0, 0]);
        let number = branch.get_page_number();
        drop(branch);
        let root = Some(BtreeHeader::new(number, 0, 2));
        validate_key_pages(root, &allocator.resolver()).unwrap();

        // This separator is canonical but routes the right child's equal key
        // into the left subtree. Global leaf ordering alone cannot detect it.
        let mut branch = allocator.get_page_mut(number).unwrap();
        branch.memory_mut()[56] = 5;
        drop(branch);
        assert!(matches!(
            validate_key_pages(root, &allocator.resolver()),
            Err(StorageError::Corrupted(_))
        ));
        let mut branch = allocator.get_page_mut(number).unwrap();
        branch.memory_mut()[56] = 255;
        drop(branch);
        assert!(matches!(
            validate_key_pages(root, &allocator.resolver()),
            Err(StorageError::Corrupted(_))
        ));
        let mut branch = allocator.get_page_mut(number).unwrap();
        branch.memory_mut()[56] = 3;
        branch.memory_mut()[40..48].copy_from_slice(&number.to_le_bytes());
        drop(branch);
        assert!(matches!(
            validate_key_pages(root, &allocator.resolver()),
            Err(StorageError::Corrupted(_))
        ));
    }
}
