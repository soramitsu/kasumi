use super::*;
use crate::{Database, DatabaseError};
use std::sync::atomic::AtomicUsize;

#[derive(Debug)]
struct RawAllocatorKey;
impl Value for RawAllocatorKey {
    type SelfType<'a> = [u8; 5];
    type AsBytes<'a> = [u8; 5];

    fn fixed_width() -> Option<usize> {
        Some(5)
    }
    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        data.try_into().unwrap()
    }
    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        *value
    }
    fn type_name() -> TypeName {
        AllocatorStateKey::type_name()
    }
}
impl Key for RawAllocatorKey {
    fn compare(a: &[u8], b: &[u8]) -> core::cmp::Ordering {
        a.cmp(b)
    }
}

fn write_raw_snapshot_record(database: &Database, key: [u8; 5], value: &[u8]) {
    let mut tx = database.begin_write().unwrap();
    let system_root = {
        let mut namespace = tx.system_tables.lock().unwrap();
        {
            let mut raw = namespace
                .open_system_table(
                    &tx.dirty,
                    SystemTableDefinition::<RawAllocatorKey, &[u8]>::new(
                        ALLOCATOR_STATE_TABLE_NAME,
                    ),
                )
                .unwrap();
            raw.insert(key, value).unwrap();
        }
        namespace
            .table_tree
            .flush_table_root_updates()
            .unwrap()
            .finalize_dirty_checksums()
            .unwrap()
    };
    // Publish a deliberately malformed snapshot below the canonical commit
    // writer, which otherwise replaces this table with only canonical keys.
    tx.mem
        .commit(
            tx.mem.get_data_root(),
            system_root,
            tx.transaction_id,
            ShrinkPolicy::Default,
        )
        .unwrap();
    tx.page_allocator().discard_committed_allocations();
    tx.completed = true;
}

fn assert_corrupted<T: core::fmt::Debug>(result: Result<T, DatabaseError>) {
    assert!(
        matches!(
            result,
            Err(DatabaseError::Storage(StorageError::Corrupted(_)))
        ),
        "{result:?}"
    );
}

#[test]
fn allocator_keys_have_only_exact_canonical_tags_width_and_padding() {
    for key in [
        AllocatorStateKey::Region(0),
        AllocatorStateKey::Region(u32::MAX),
        AllocatorStateKey::RegionTracker,
        AllocatorStateKey::TransactionId,
    ] {
        let raw = AllocatorStateKey::as_bytes(&key);
        let (parsed, allocations) =
            crate::admission::observe_test_allocations(|| AllocatorStateKey::checked(&raw));
        assert_eq!(allocations, 0);
        assert_eq!(parsed.unwrap(), key);
        assert_eq!(AllocatorStateKey::from_bytes(&raw), key);
    }
    for tag in [0, 1, 2, 6, 127, 255] {
        assert!(matches!(
            AllocatorStateKey::checked(&[tag, 0, 0, 0, 0]),
            Err(StorageError::Corrupted(_))
        ));
    }
    for bytes in [
        &[][..],
        &[3][..],
        &[3, 0, 0, 0][..],
        &[3, 0, 0, 0, 0, 0][..],
    ] {
        assert!(matches!(
            AllocatorStateKey::checked(bytes),
            Err(StorageError::Corrupted(_))
        ));
    }
    for tag in [4, 5] {
        for index in 1..5 {
            let mut raw = [tag, 0, 0, 0, 0];
            raw[index] = 1;
            assert!(matches!(
                AllocatorStateKey::checked(&raw),
                Err(StorageError::Corrupted(_))
            ));
        }
    }
}

#[test]
fn obsolete_unknown_and_aliased_allocator_keys_never_repair_or_mutate_on_open() {
    for key in [
        [0, 0, 0, 0, 0],
        [1, 0, 0, 0, 0],
        [2, 0, 0, 0, 0],
        [6, 0, 0, 0, 0],
        [255, 0, 0, 0, 0],
        [4, 1, 0, 0, 0],
        [5, 0, 0, 0, 1],
    ] {
        for clean in [false, true] {
            let file = crate::create_tempfile();
            let database = Database::create(file.path(), crate::test_admission()).unwrap();
            write_raw_snapshot_record(&database, key, &[0; 8]);
            if clean {
                database.close().unwrap();
            } else {
                database.get_memory().abandon().unwrap();
                drop(database);
            }
            let before = std::fs::read(file.path()).unwrap();
            let callbacks = Arc::new(AtomicUsize::new(0));
            let observed = callbacks.clone();
            assert_corrupted(
                Database::builder(crate::test_admission())
                    .set_repair_callback(move |_| {
                        observed.fetch_add(1, Ordering::Relaxed);
                    })
                    .open(file.path()),
            );
            assert_eq!(callbacks.load(Ordering::Relaxed), 0);
            assert_eq!(std::fs::read(file.path()).unwrap(), before);
            assert_corrupted(
                Database::builder(crate::test_admission()).open_read_only(file.path()),
            );
            assert_eq!(std::fs::read(file.path()).unwrap(), before);
        }
    }
}

#[test]
fn malformed_allocator_transaction_stamp_is_corruption_before_stale_repair() {
    for size in [0, 7, 9] {
        let file = crate::create_tempfile();
        let database = Database::create(file.path(), crate::test_admission()).unwrap();
        write_raw_snapshot_record(&database, [5, 0, 0, 0, 0], &vec![0; size]);
        database.close().unwrap();
        let before = std::fs::read(file.path()).unwrap();
        let callbacks = Arc::new(AtomicUsize::new(0));
        let observed = callbacks.clone();
        assert_corrupted(
            Database::builder(crate::test_admission())
                .set_repair_callback(move |_| {
                    observed.fetch_add(1, Ordering::Relaxed);
                })
                .open(file.path()),
        );
        assert_eq!(callbacks.load(Ordering::Relaxed), 0);
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
        assert_corrupted(Database::builder(crate::test_admission()).open_read_only(file.path()));
        assert_eq!(std::fs::read(file.path()).unwrap(), before);
    }
}

#[test]
fn integrity_rejects_noncanonical_allocator_keys_without_storage_writes() {
    let file = crate::create_tempfile();
    let mut database = Database::create(file.path(), crate::test_admission()).unwrap();
    write_raw_snapshot_record(&database, [255, 0, 0, 0, 0], &[0; 8]);
    let before = std::fs::read(file.path()).unwrap();
    assert_corrupted(database.check_integrity());
    assert_eq!(std::fs::read(file.path()).unwrap(), before);
    database.get_memory().abandon().unwrap();
    drop(database);
    assert_eq!(std::fs::read(file.path()).unwrap(), before);
}

#[test]
fn exact_canonical_stale_allocator_stamp_still_uses_verified_repair() {
    let file = crate::create_tempfile();
    let database = Database::create(file.path(), crate::test_admission()).unwrap();
    write_raw_snapshot_record(&database, [5, 0, 0, 0, 0], &0_u64.to_le_bytes());
    database.close().unwrap();
    let callbacks = Arc::new(AtomicUsize::new(0));
    let observed = callbacks.clone();
    let mut reopened = Database::builder(crate::test_admission())
        .set_repair_callback(move |_| {
            observed.fetch_add(1, Ordering::Relaxed);
        })
        .open(file.path())
        .unwrap();
    assert!(callbacks.load(Ordering::Relaxed) > 0);
    assert!(reopened.check_integrity().unwrap());
    reopened.close().unwrap();
}

fn snapshot_value(database: &Database, key: [u8; 5]) -> Vec<u8> {
    let tx = database.begin_write().unwrap();
    let bytes = tx
        .read_existing_system_table(
            SystemTableDefinition::<RawAllocatorKey, &[u8]>::new(ALLOCATOR_STATE_TABLE_NAME),
            |tree| Ok(tree.get(&key)?.unwrap().value().to_vec()),
        )
        .unwrap()
        .unwrap();
    tx.abort().unwrap();
    bytes
}

#[test]
fn malformed_canonical_allocator_payloads_reject_before_repair_or_any_opening_write() {
    use crate::backends::FileBackend;
    use crate::{DatabaseOpenMode, DatabaseOpenSettlement, TerminalObservation};
    for case in 0..8 {
        for clean in [false, true] {
            let file = crate::create_tempfile();
            let database = Database::create(file.path(), crate::test_admission()).unwrap();
            let mut key = if case == 5 || case == 6 {
                [4, 0, 0, 0, 0]
            } else {
                [3, 0, 0, 0, 0]
            };
            let mut value = snapshot_value(&database, key);
            match case {
                0 => value.clear(),
                1 => value.truncate(3),
                2 => value.truncate(value.len() - 1),
                3 => value[0] = 255,
                4 => value[8..12].copy_from_slice(&u32::MAX.to_le_bytes()),
                5 => value[..4].copy_from_slice(&u32::MAX.to_le_bytes()),
                6 => {
                    value.push(0);
                }
                7 => key = [3, 2, 0, 0, 0],
                _ => unreachable!(),
            }
            // The direct fixture leaves the stamp stale. Malformed payloads
            // must not become an accepted trigger to rebuild and erase evidence.
            write_raw_snapshot_record(&database, key, &value);
            if clean {
                database.close().unwrap();
            } else {
                database.get_memory().abandon().unwrap();
                drop(database);
            }
            let before = std::fs::read(file.path()).unwrap();
            let callbacks = Arc::new(AtomicUsize::new(0));
            let observed = callbacks.clone();
            assert_corrupted(
                Database::builder(crate::test_admission())
                    .set_repair_callback(move |_| {
                        observed.fetch_add(1, Ordering::Relaxed);
                    })
                    .open(file.path()),
            );
            assert_corrupted(
                Database::builder(crate::test_admission()).open_read_only(file.path()),
            );
            let observed = callbacks.clone();
            let mut builder = Database::builder(crate::test_admission());
            builder.set_repair_callback(move |_| {
                observed.fetch_add(1, Ordering::Relaxed);
            });
            let backend = Box::new(FileBackend::new(file.reopen().unwrap()).unwrap());
            let mut owner = builder.retain_backend(backend, DatabaseOpenMode::Existing);
            let report = owner.open();
            assert_eq!(report.settlement(), DatabaseOpenSettlement::Retained);
            assert!(matches!(
                report.opening(),
                TerminalObservation::Returned(Err(DatabaseError::Storage(
                    StorageError::Corrupted(_)
                )))
            ));
            assert!(owner.database().is_none());
            assert_eq!(owner.close().settlement(), DatabaseOpenSettlement::Closed);
            assert_eq!(callbacks.load(Ordering::Relaxed), 0);
            assert_eq!(std::fs::read(file.path()).unwrap(), before);
        }
    }
}
