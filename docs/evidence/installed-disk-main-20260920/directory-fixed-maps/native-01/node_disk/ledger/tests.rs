use super::super::Identity;
use super::*;
use std::collections::HashMap;

fn file(binding: u8) -> AccountedFile {
    AccountedFile::durable(NamespaceBinding([binding; 32]), 4096, 0, 12)
}
fn directory(binding: u8, parent: Option<Identity>) -> AccountedDirectory {
    AccountedDirectory {
        binding: NamespaceBinding([binding; 32]),
        parent,
        bytes: 8192,
        pending: 0,
        settled: true,
        len: 24,
        children: 3,
        live_handles: 0,
    }
}

#[test]
fn typed_entries_never_reinterpret_another_inode_kind() {
    let mut inode = AccountedInode::File(file(1));
    assert_eq!(inode.binding(), NamespaceBinding([1; 32]));
    assert!(inode.directory().is_none());
    assert!(inode.directory_mut().is_none());
    inode.file_mut().unwrap().pending = 19;
    assert_eq!(inode.file().unwrap().pending, 19);
    let mut inode = AccountedInode::Directory(directory(2, Some(Identity(4, 5))));
    assert_eq!(inode.binding(), NamespaceBinding([2; 32]));
    assert!(inode.file().is_none());
    assert!(inode.file_mut().is_none());
    inode.directory_mut().unwrap().live_handles = 7;
    assert_eq!(inode.directory().unwrap().live_handles, 7);
}

#[test]
fn unified_identity_rejects_cross_kind_double_enrollment() {
    let id = Identity(4, 5);
    let mut map = HashMap::new();
    assert!(map.insert(id, AccountedInode::File(file(1))).is_none());
    // Census requires every insert's previous entry to be None. A second
    // kind under this physical identity therefore fails the same check.
    assert!(
        map.insert(id, AccountedInode::Directory(directory(2, None)))
            .is_some()
    );
    assert_eq!(map.len(), 1);
}

#[test]
fn retained_and_replacement_bounds_preserve_independent_file_capacity() {
    let n = 8;
    let roots = 2;
    let (retained, replacement) = capacities(n, roots).unwrap();
    // No dot-entry credit is assumed. Even N census directories plus roots
    // leave room for the original N files admitted after census completes.
    let mut old = HashMap::new();
    for index in 0..n + roots {
        old.insert(
            Identity(1, index),
            AccountedInode::Directory(directory(1, None)),
        );
    }
    for index in 0..n {
        old.insert(Identity(2, index), AccountedInode::File(file(2)));
    }
    assert_eq!(old.len() as u64, retained);
    assert!(old.len() as u64 > replacement);
    // A fresh census spends one work unit on each non-root inode, whatever
    // its kind. Exhaust every mixture while the old allocation remains live.
    for files in 0..=n {
        let mut new = HashMap::new();
        for index in 0..files {
            new.insert(Identity(3, index), AccountedInode::File(file(3)));
        }
        for index in files..n + roots {
            new.insert(
                Identity(4, index),
                AccountedInode::Directory(directory(4, None)),
            );
        }
        assert_eq!(new.len() as u64, replacement);
        assert_eq!((old.len() + new.len()) as u64, 3 * n + 2 * roots);
    }
}

#[test]
fn peak_cardinality_overflow_fails_before_allocation() {
    assert_eq!(capacities(u64::MAX, 1), None);
    assert_eq!(capacities(u64::MAX / 2 + 1, 0), None);
    assert_eq!(
        capacities(u64::MAX / 2, 1),
        Some((u64::MAX, u64::MAX / 2 + 1))
    );
    assert_eq!(capacities(1_000_000, 1), Some((2_000_001, 1_000_001)));
}
