//! Integrity checks for immediately durable admitted commits. A corrupted winning
//! root must be reported without silently discarding an acknowledged transaction.

#[path = "common/admission.rs"]
mod admission_support;
#[cfg(feature = "experimental-api-5")]
use redb::ReadableTable;
use redb::{Database, ReadableDatabase, ReadableTableMetadata, StorageBackend, TableDefinition};
use std::sync::{Arc, RwLock};

const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("t");

// A backend backed by a shared Vec<u8> so the test can patch arbitrary on-disk bytes, simulating
// external file modification / corruption.
#[derive(Clone, Debug, Default)]
struct PatchBackend {
    inner: Arc<RwLock<Vec<u8>>>,
}

impl PatchBackend {
    fn file_len(&self) -> usize {
        self.inner.read().unwrap().len()
    }
    fn truncate(&self, len: usize) {
        self.inner.write().unwrap().truncate(len);
    }
    fn extend(&self, additional: usize) {
        let mut guard = self.inner.write().unwrap();
        let new_len = guard.len() + additional;
        guard.resize(new_len, 0);
    }
    // Flip all bits in the first occurrence of `needle`. Returns whether anything was patched.
    fn corrupt_first_occurrence(&self, needle: &[u8]) -> bool {
        let mut guard = self.inner.write().unwrap();
        let mut i = 0;
        while i + needle.len() <= guard.len() {
            if &guard[i..i + needle.len()] == needle {
                for b in &mut guard[i..i + needle.len()] {
                    *b ^= 0xFF;
                }
                return true;
            }
            i += 1;
        }
        false
    }
}

impl StorageBackend for PatchBackend {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.inner.read().unwrap().len() as u64)
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), std::io::Error> {
        let offset = usize::try_from(offset).unwrap();
        let guard = self.inner.read().unwrap();
        if offset + out.len() > guard.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        out.copy_from_slice(&guard[offset..offset + out.len()]);
        Ok(())
    }
    fn set_len(&self, len: u64) -> Result<(), std::io::Error> {
        self.inner
            .write()
            .unwrap()
            .resize(len.try_into().unwrap(), 0);
        Ok(())
    }
    fn sync_data(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
    fn write(&self, offset: u64, data: &[u8]) -> Result<(), std::io::Error> {
        let offset = usize::try_from(offset).unwrap();
        let mut guard = self.inner.write().unwrap();
        if offset + data.len() > guard.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        guard[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn close(&self) -> redb::BackendCloseOutcome {
        redb::BackendCloseOutcome::drained(Ok(()))
    }
}

fn make_db(backend: PatchBackend, n: u64) -> Database {
    let db = Database::builder(crate::admission_support::admission())
        .create_with_backend(backend)
        .unwrap();
    let txn = db.begin_write().unwrap();
    {
        let mut table = txn.open_table(TABLE).unwrap();
        for k in 0..n {
            let v = vec![(k as u8).wrapping_add(0xA0); 64];
            table.insert(&k, v.as_slice()).unwrap();
        }
    }
    txn.commit().unwrap();
    db
}

// Integrity checks must read committed pages from disk rather than trusting the
// cache. Corrupt acknowledged data must fail closed without selecting an older root.
#[test]
fn check_integrity_rejects_disk_corrupt_admitted_commit() {
    let backend = PatchBackend::default();
    let mut db = Database::builder(crate::admission_support::admission())
        .set_cache_size(0)
        .create_with_backend(backend.clone())
        .unwrap();
    {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(TABLE).unwrap();
            for k in 0..5u64 {
                let v = vec![(k as u8).wrapping_add(0xA0); 64];
                table.insert(&k, v.as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();
    }

    // Commit a uniquely tagged page.
    let marker = vec![0xC7u8; 2000];
    {
        let txn = db.begin_write().unwrap();

        {
            let mut table = txn.open_table(TABLE).unwrap();
            table.insert(&999u64, marker.as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }

    // Corrupt the acknowledged page on disk.
    assert!(
        backend.corrupt_first_occurrence(&marker),
        "could not locate the value on disk to corrupt"
    );

    assert!(
        !matches!(db.check_integrity(), Ok(true)),
        "accepted an acknowledged commit that is corrupt on disk"
    );

    assert!(db.begin_write().is_err());
    drop(db);
    assert!(
        Database::builder(crate::admission_support::admission())
            .create_with_backend(backend)
            .is_err()
    );
}

// Integrity repair must preserve an acknowledged commit that grew the file.
#[test]
fn check_integrity_preserves_growing_admitted_commit() {
    let backend = PatchBackend::default();
    let mut db = make_db(backend.clone(), 1);

    let len_before = backend.file_len();
    {
        let txn = db.begin_write().unwrap();

        {
            let mut table = txn.open_table(TABLE).unwrap();
            for k in 1000..3000u64 {
                table.insert(&k, vec![0xEEu8; 2000].as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();
    }
    assert!(
        backend.file_len() > len_before,
        "the admitted commit was expected to grow the file"
    );

    assert!(db.check_integrity().unwrap());

    // The acknowledged commit must survive integrity repair and reopening.
    drop(db);
    let db = Database::builder(crate::admission_support::admission())
        .create_with_backend(backend)
        .unwrap();
    let read = db.begin_read().unwrap();
    let table = read.open_table(TABLE).unwrap();
    assert_eq!(table.len().unwrap(), 2001);
    assert_eq!(
        table.get(&2500u64).unwrap().unwrap().value(),
        [0xEEu8; 2000]
    );
}

// Integrity repair must preserve tables created by acknowledged commits.
#[test]
fn check_integrity_preserves_admitted_commit_that_creates_a_table() {
    const OTHER: TableDefinition<u64, &[u8]> = TableDefinition::new("other");

    let backend = PatchBackend::default();
    let mut db = make_db(backend.clone(), 1);
    {
        let txn = db.begin_write().unwrap();

        txn.open_table(OTHER)
            .unwrap()
            .insert(&7u64, [0xCDu8; 8].as_slice())
            .unwrap();
        txn.commit().unwrap();
    }

    assert!(db.check_integrity().unwrap());

    drop(db);
    let db = Database::builder(crate::admission_support::admission())
        .create_with_backend(backend)
        .unwrap();
    let read = db.begin_read().unwrap();
    assert_eq!(read.list_tables().unwrap().count(), 2);
    assert_eq!(
        read.open_table(OTHER)
            .unwrap()
            .get(&7u64)
            .unwrap()
            .unwrap()
            .value(),
        [0xCDu8; 8]
    );
}

// An external extension creates a layout mismatch. Repair must preserve every
// acknowledged row and restore a consistent layout for subsequent writes.
#[test]
fn check_integrity_preserves_commits_after_external_extension() {
    let backend = PatchBackend::default();
    let mut db = make_db(backend.clone(), 5);

    {
        let txn = db.begin_write().unwrap();

        {
            let mut table = txn.open_table(TABLE).unwrap();
            table.insert(&7777u64, [0x99u8; 100].as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }

    // External extension to a longer file (one full region's worth of bytes).
    backend.extend(4 * 1024 * 1024);

    assert!(
        !matches!(db.check_integrity(), Ok(true)),
        "external file extension reported as clean"
    );

    // The durable data must still be intact, and the database usable for further writes.
    {
        let read = db.begin_read().unwrap();
        let table = read.open_table(TABLE).unwrap();
        assert_eq!(table.len().unwrap(), 6);
        assert!(table.get(&7777u64).unwrap().is_some());
    }
    {
        let txn = db.begin_write().unwrap();
        {
            let mut table = txn.open_table(TABLE).unwrap();
            table.insert(&1u64, [0x11u8; 64].as_slice()).unwrap();
        }
        txn.commit().unwrap();
    }
    // A fresh check must now pass: recovery left a consistent state.
    assert!(db.check_integrity().unwrap());
}

// External truncation can destroy acknowledged pages. Integrity checking and
// reopening must refuse the damaged root without rolling back acknowledged data.
#[test]
fn check_integrity_detects_truncation_after_admitted_growth() {
    let backend = PatchBackend::default();
    let mut db = make_db(backend.clone(), 1);
    let durable_len = backend.file_len();

    {
        let txn = db.begin_write().unwrap();

        {
            let mut table = txn.open_table(TABLE).unwrap();
            for k in 1000..3000u64 {
                table.insert(&k, vec![0xEEu8; 2000].as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();
    }
    assert!(
        backend.file_len() > durable_len,
        "the admitted commit was expected to grow the file"
    );

    // Truncate back to the length before the latest acknowledged commit.
    backend.truncate(durable_len);

    assert!(
        !matches!(db.check_integrity(), Ok(true)),
        "truncation after admitted growth reported as clean"
    );
    drop(db);

    // Truncation destroyed acknowledged data; refuse to silently return an older root.
    assert!(
        Database::builder(crate::admission_support::admission())
            .create_with_backend(backend)
            .is_err()
    );
}
