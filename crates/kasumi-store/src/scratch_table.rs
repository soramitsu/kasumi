//! Temporary point-addressed staging. Database pages, including keys and indexes,
//! are encrypted in an anonymous spool; only a bounded page cache is resident.
use crate::{EncryptedSpool, ScratchDisk};
use anyhow::{Result, ensure};
use kasumi_types::drain::DrainResult;
use redb::{
    AdmissionError, OwnerFailed, ReadableTable, StorageAdmission, StorageBackend, TableDefinition,
};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex};
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("staged");

/// Both redb capabilities retain this exact anonymous file; no independently
/// constructed governor can admit a different spool or turn errors into capacity.
#[derive(Debug)]
struct Owner(Mutex<Option<EncryptedSpool>>);
impl Owner {
    fn with<T>(&self, work: impl FnOnce(&mut EncryptedSpool) -> io::Result<T>) -> io::Result<T> {
        let mut owner = self.0.lock().map_err(|poisoned| {
            if let Some(spool) = poisoned.into_inner().as_ref() {
                spool.owner_failed();
            }
            io::Error::from(io::ErrorKind::Other)
        })?;
        let spool = owner
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        spool.check_owner()?;
        work(spool)
    }
}
impl StorageAdmission for Owner {
    fn check_owner(&self) -> std::result::Result<(), OwnerFailed> {
        self.with(|_| Ok(())).map_err(|_| OwnerFailed)
    }
    fn reserve_workspace(
        &self,
        bytes: u64,
    ) -> std::result::Result<Box<dyn redb::ResidentLease>, AdmissionError> {
        self.with(|spool| {
            let bytes = crate::disk_memory::add(
                bytes,
                crate::disk_memory::allocation::<crate::DiskMemoryLease>(1)
                    .map_err(|_| io::ErrorKind::OutOfMemory)?,
            )
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
            let lease = match spool.disk().memory().clone().reserve_installed(bytes) {
                Ok(lease) => lease,
                Err(error) if error.kind() == io::ErrorKind::OutOfMemory => return Err(error),
                Err(error) => {
                    spool.owner_failed();
                    return Err(error);
                }
            };
            Ok(Box::new(lease) as Box<dyn redb::ResidentLease>)
        })
        .map_err(|error| {
            if error.kind() == io::ErrorKind::OutOfMemory {
                AdmissionError::CapacityDenied
            } else {
                AdmissionError::OwnerFailed
            }
        })
    }
    fn reserve_growth(
        &self,
        current: u64,
        requested: u64,
    ) -> std::result::Result<(), AdmissionError> {
        self.with(|spool| {
            let result = spool.reserve_growth(current, requested);
            // A pure pre-I/O denial leaves the exact owner healthy. An OS error
            // that also fences the physical owner is never a recoverable denial.
            if result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::StorageFull)
                && spool.check_owner().is_err()
            {
                return Err(io::Error::from(io::ErrorKind::Other));
            }
            result
        })
        .map_err(|error| {
            if error.kind() == io::ErrorKind::StorageFull {
                AdmissionError::CapacityDenied
            } else {
                AdmissionError::OwnerFailed
            }
        })
    }
    fn settle_growth(&self, actual: u64) -> std::result::Result<(), OwnerFailed> {
        self.with(|spool| spool.settle_growth(actual))
            .map_err(|_| OwnerFailed)
    }
    fn owner_failed(&self) {
        let owner = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(spool) = owner.as_ref() {
            spool.owner_failed();
        }
    }
}

#[derive(Clone, Debug)]
struct Backend(Arc<Owner>);
impl StorageBackend for Backend {
    fn len(&self) -> io::Result<u64> {
        self.0.with(|spool| Ok(spool.len()))
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.with(|spool| {
            spool.seek(SeekFrom::Start(offset))?;
            spool.read_exact(out)
        })
    }
    fn set_len(&self, length: u64) -> io::Result<()> {
        self.0.with(|spool| spool.resize(length))
    }
    fn sync_data(&self) -> io::Result<()> {
        self.0.with(EncryptedSpool::sync_all)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.with(|spool| {
            spool.seek(SeekFrom::Start(offset))?;
            spool.write_all(bytes)
        })
    }
    fn close(&self) -> redb::BackendCloseOutcome {
        let mut owner = self.0.0.lock().unwrap_or_else(|poisoned| {
            let owner = poisoned.into_inner();
            if let Some(spool) = owner.as_ref() {
                spool.owner_failed();
            }
            owner
        });
        let Some(spool) = owner.as_mut() else {
            // Only a positively drained prior call removes this exact spool.
            return redb::BackendCloseOutcome::drained(Ok(()));
        };
        let outcome = spool.close_once();
        if outcome.native_disposition() == redb::BackendNativeDisposition::Drained {
            // Native retirement precedes key/buffer retirement and its charge.
            // An uncertain close keeps the original spool installed here.
            drop(owner.take());
        }
        outcome
    }
}
pub struct EncryptedTable {
    database: crate::node_database::NodeDatabase,
}
/// An unpublished, bounded staging transaction. A healthy dropped transaction
/// aborts its pending writes; a committed batch remains private until its caller
/// publishes the enclosing verified namespace.
pub struct EncryptedTableBatch {
    transaction: redb::WriteTransaction,
    bytes: usize,
    entries: usize,
    failed: bool,
}
impl EncryptedTableBatch {
    pub const MAX_BYTES: usize = 4 << 20;
    pub const MAX_ENTRIES: usize = 16;

    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        ensure!(!self.failed, "staging batch previously failed");
        self.failed = true;
        ensure!(
            key.len() <= 4096 && value.len() <= 32 << 20,
            "staged record exceeds limit"
        );
        let bytes = self
            .bytes
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or_else(|| anyhow::anyhow!("staging batch byte overflow"))?;
        ensure!(
            bytes <= Self::MAX_BYTES && self.entries < Self::MAX_ENTRIES,
            "staging batch capacity exceeded"
        );
        let mut table = self.transaction.open_table(TABLE)?;
        ensure!(table.insert(key, value)?.is_none(), "duplicate staged key");
        self.bytes = bytes;
        self.entries += 1;
        self.failed = false;
        Ok(())
    }

    pub fn commit(self) -> Result<()> {
        ensure!(!self.failed, "staging batch previously failed");
        self.transaction.commit()?;
        Ok(())
    }
}
impl EncryptedTable {
    pub fn new(disk: &Arc<ScratchDisk>, max_disk_bytes: u64) -> Result<Self> {
        let owner = Arc::new(Owner(Mutex::new(Some(EncryptedSpool::new(
            disk,
            max_disk_bytes,
        )?))));
        let mut builder = redb::Database::builder(owner.clone());
        builder.set_cache_size(8 << 20);
        let database = builder.create_with_backend(Backend(owner))?;
        let tx = database.begin_write()?;
        tx.open_table(TABLE)?;
        tx.commit()?;
        Ok(Self {
            database: crate::node_database::NodeDatabase::new(database, "encrypted scratch table"),
        })
    }
    /// Fence new transactions and retain the exact database while accepted
    /// readers or writers drain. Repeated calls preserve the original outcome.
    pub fn close(&self) -> DrainResult {
        self.database.close()
    }
    pub fn begin_batch(&self) -> Result<EncryptedTableBatch> {
        Ok(EncryptedTableBatch {
            transaction: self.database.begin_write()?,
            bytes: 0,
            entries: 0,
            failed: false,
        })
    }
    pub fn insert(&self, key: &[u8], value: &[u8]) -> Result<()> {
        ensure!(
            key.len() <= 4096 && value.len() <= 32 << 20,
            "staged record exceeds limit"
        );
        let tx = self.database.begin_write()?;
        {
            let mut table = tx.open_table(TABLE)?;
            ensure!(table.insert(key, value)?.is_none(), "duplicate staged key");
        }
        tx.commit()?;
        Ok(())
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tx = self.database.begin_read()?;
        let table = tx.open_table(TABLE)?;
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }
    /// Replace a scratch accumulator. Permanent identities use `insert`, which
    /// rejects duplicates; this operation is only for unpublished working tables.
    pub fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
        ensure!(
            key.len() <= 4096 && value.len() <= 32 << 20,
            "staged record exceeds limit"
        );
        let tx = self.database.begin_write()?;
        {
            tx.open_table(TABLE)?.insert(key, value)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn visit(&self, mut visitor: impl FnMut(&[u8], &[u8]) -> Result<()>) -> Result<()> {
        let tx = self.database.begin_read()?;
        let table = tx.open_table(TABLE)?;
        for entry in table.iter()? {
            let (key, value) = entry?;
            visitor(key.value(), value.value())?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "scratch_table_tests.rs"]
mod tests;
