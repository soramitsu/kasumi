//! Tests for the state a `Database` is left in when `check_integrity()` fails. The check rebuilds
//! the allocator state, so a failure part way through leaves one that no longer describes the file.
//! The database must refuse to write rather than allocate against it.

#[path = "common/admission.rs"]
mod admission_support;
use redb::{
    Database, DatabaseError, ReadableDatabase, StorageBackend, StorageError, TableDefinition,
};
use std::sync::{Arc, RwLock};

const TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("t");

// A backend backed by a shared Vec<u8> so the test can patch on-disk bytes, simulating corruption.
#[derive(Clone, Debug, Default)]
struct PatchBackend {
    inner: Arc<RwLock<Vec<u8>>>,
}

impl PatchBackend {
    // The god byte's recovery-required bit, which a clean shutdown clears.
    fn recovery_required(&self) -> bool {
        self.inner.read().unwrap()[9] & 2 != 0
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

// Corruption introduced after explicit clean close is discovered by a live integrity
// check, which must fence writes after discarding its allocator state.
#[test]
fn writes_are_refused_after_a_failed_check_integrity() {
    let backend = PatchBackend::default();
    let marker = vec![0xC7u8; 2000];
    {
        let db = Database::builder(crate::admission_support::admission())
            .create_with_backend(backend.clone())
            .unwrap();
        let txn = db.begin_write().unwrap();
        txn.open_table(TABLE)
            .unwrap()
            .insert(&1u64, marker.as_slice())
            .unwrap();
        txn.commit().unwrap();
        db.close().unwrap();
    }
    assert!(
        backend.corrupt_first_occurrence(&marker),
        "could not locate the value on disk to corrupt"
    );

    let mut db = Database::builder(crate::admission_support::admission())
        .create_with_backend(backend.clone())
        .unwrap();
    assert!(matches!(
        db.check_integrity(),
        Err(DatabaseError::Storage(StorageError::Corrupted(_)))
    ));

    assert!(matches!(
        db.begin_write(),
        Err(redb::TransactionError::Storage(StorageError::Corrupted(_)))
    ));

    // Retrying rebuilds the same allocator state the first call failed to rebuild
    assert!(matches!(
        db.check_integrity(),
        Err(DatabaseError::Storage(StorageError::Corrupted(_)))
    ));

    // Reads do not allocate, so they are still served.
    assert_eq!(db.begin_read().unwrap().list_tables().unwrap().count(), 1);

    // Drop releases the backend without checkpointing or falsely clearing the dirty flag.
    drop(db);

    // Clearing the flag would assert that this process left the file consistent, which it cannot
    // know without an allocator state.
    assert!(backend.recovery_required());
}
