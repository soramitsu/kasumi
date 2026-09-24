//! Temporary point-addressed staging. Transaction frames, including keys and
//! values, are encrypted in an anonymous spool; the ordered key index is resident.
use crate::{EncryptedSpool, ScratchDisk};
use anyhow::{Result, ensure};
use kasumi_kv::{AdmissionError, OwnerFailed, StorageAdmission, StorageBackend, TableDefinition};
use kasumi_types::drain::{DrainCompletion, DrainResult};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("staged");

/// Both database capabilities retain this exact anonymous file; no independently
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
    ) -> std::result::Result<Box<dyn kasumi_kv::ResidentLease>, AdmissionError> {
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
            Ok(Box::new(lease) as Box<dyn kasumi_kv::ResidentLease>)
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
    fn close(&self) -> kasumi_kv::BackendCloseOutcome {
        let mut owner = self.0.0.lock().unwrap_or_else(|poisoned| {
            let owner = poisoned.into_inner();
            if let Some(spool) = owner.as_ref() {
                spool.owner_failed();
            }
            owner
        });
        let Some(spool) = owner.as_mut() else {
            // Only a positively drained prior call removes this exact spool.
            return kasumi_kv::BackendCloseOutcome::drained(Ok(()));
        };
        let outcome = spool.close_once();
        if outcome.native_disposition() == kasumi_kv::BackendNativeDisposition::Drained {
            // Native retirement precedes key/buffer retirement and its charge.
            // An uncertain close keeps the original spool installed here.
            drop(owner.take());
        }
        outcome
    }
}
struct ScratchTableDatabase {
    database: Option<crate::node_database::NodeDatabase>,
}

impl ScratchTableDatabase {
    fn database(&self) -> &crate::node_database::NodeDatabase {
        self.database.as_ref().expect("scratch database owner")
    }

    fn close(&self) -> DrainResult {
        self.database().close()
    }
}

impl Drop for ScratchTableDatabase {
    fn drop(&mut self) {
        let Some(database) = self.database.take() else {
            return;
        };
        // This is the last table or batch owner. A retained result, including
        // an unexpected unwind, cannot authorize implicit descriptor destruction
        // or return its scratch charge. Keep the exact physical owner alive.
        let drained = match catch_unwind(AssertUnwindSafe(|| database.close())) {
            Ok(Ok(())) => true,
            Ok(Err(failure)) => failure.completion() == DrainCompletion::Complete,
            Err(_) => false,
        };
        if drained {
            drop(database);
        } else {
            std::mem::forget(database);
        }
    }
}

struct ScratchTableSetupFailure {
    original: anyhow::Error,
    close: DrainResult,
    retained: Option<Arc<ScratchTableDatabase>>,
}

impl std::fmt::Debug for ScratchTableSetupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ScratchTableSetupFailure")
            .field("original", &self.original)
            .field("close", &self.close)
            .field("retained", &self.retained.is_some())
            .finish()
    }
}

impl std::fmt::Display for ScratchTableSetupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "scratch table setup failed: {}", self.original)?;
        if let Err(close) = &self.close {
            write!(formatter, "; close: {close}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ScratchTableSetupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}

impl ScratchTableSetupFailure {
    #[cfg(test)]
    fn retry_close(&self) -> DrainResult {
        self.retained
            .as_ref()
            .map_or_else(|| self.close.clone(), |owner| owner.close())
    }
}

pub struct EncryptedTable {
    owner: Arc<ScratchTableDatabase>,
}
/// An unpublished, bounded staging transaction. A healthy dropped transaction
/// aborts its pending writes; a committed batch remains private until its caller
/// publishes the enclosing verified namespace.
pub struct EncryptedTableBatch {
    transaction: kasumi_kv::WriteTransaction,
    // The transaction drops before this owner. If the table is gone, the last
    // batch still gets an observed close after its write settles or aborts.
    _owner: Arc<ScratchTableDatabase>,
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
        let database =
            kasumi_kv::Database::builder(owner.clone()).create_with_backend(Backend(owner))?;
        Self::initialize(database)
    }

    fn initialize(database: kasumi_kv::Database) -> Result<Self> {
        let table = Self {
            owner: Arc::new(ScratchTableDatabase {
                database: Some(crate::node_database::NodeDatabase::new(
                    database,
                    "encrypted scratch table",
                )),
            }),
        };
        let setup = (|| -> Result<()> {
            let tx = table.owner.database().begin_write()?;
            tx.open_table(TABLE)?;
            tx.commit()?;
            Ok(())
        })();
        if let Err(original) = setup {
            let close = table.close();
            let retained = close.as_ref().err().and_then(|failure| {
                (failure.completion() == DrainCompletion::Retained).then(|| table.owner.clone())
            });
            return Err(ScratchTableSetupFailure {
                original,
                close,
                retained,
            }
            .into());
        }
        Ok(table)
    }
    /// Fence new transactions and retain the exact database while accepted
    /// readers or writers drain. Repeated calls preserve the original outcome.
    pub fn close(&self) -> DrainResult {
        self.owner.close()
    }
    pub fn begin_batch(&self) -> Result<EncryptedTableBatch> {
        Ok(EncryptedTableBatch {
            transaction: self.owner.database().begin_write()?,
            _owner: self.owner.clone(),
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
        let tx = self.owner.database().begin_write()?;
        {
            let mut table = tx.open_table(TABLE)?;
            ensure!(table.insert(key, value)?.is_none(), "duplicate staged key");
        }
        tx.commit()?;
        Ok(())
    }
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tx = self.owner.database().begin_read()?;
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
        let tx = self.owner.database().begin_write()?;
        {
            tx.open_table(TABLE)?.insert(key, value)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn visit(&self, mut visitor: impl FnMut(&[u8], &[u8]) -> Result<()>) -> Result<()> {
        let tx = self.owner.database().begin_read()?;
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
