//! Temporary point-addressed staging with encrypted segmented storage and a
//! bounded native page/value cache. The ordered directory also lives on disk.
use crate::ScratchDisk;
use anyhow::{Result, ensure};
use kasumi_kv::{BackendNativeDisposition, CacheConfig, StorageAdmission, TableDefinition};
use kasumi_types::drain::{DrainCompletion, DrainResult};
use std::sync::Arc;

#[path = "scratch_group.rs"]
pub(crate) mod group;
use group::{Backend, Owner};

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("staged");

struct ScratchTableDatabase {
    database: Option<crate::node_database::NodeDatabase>,
    admission: Arc<Owner>,
    // An already-unwinding batch transfers its actual still-charged lease
    // here before the new provider callback could cause a second panic.
    retained_batches: std::sync::Mutex<Option<Box<BatchMemoryLink>>>,
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
        // This is the last table or batch owner. The destructor records no
        // report and allocates nothing. Only positively observed native drain
        // retires the descriptor, key and buffers before the scratch charge;
        // any other outcome, including an earlier failed explicit close, keeps
        // the exact spool and its charge alive for the process lifetime.
        let retained_batches = self
            .retained_batches
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if database.close_native_for_drop() == BackendNativeDisposition::Drained
            && retained_batches.is_none()
        {
            drop(database);
        } else {
            std::mem::forget(database);
            std::mem::forget(retained_batches);
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
    // This actual typed handle owns the validated table name and aliases the
    // transaction's admitted snapshot. Retire it before abort/commit so the
    // completed writer leaves no extra pin on the old root.
    table: Option<kasumi_kv::Table<&'static [u8], &'static [u8]>>,
    transaction: kasumi_kv::WriteTransaction,
    bytes: usize,
    entries: usize,
    failed: bool,
    // Failed native staging may release its writer gate early. Every still-live
    // batch therefore owns its own charge through the last field retirement.
    _memory: BatchMemory,
}
struct BatchMemoryLink {
    lease: Box<dyn kasumi_kv::ResidentLease>,
    next: Option<Box<BatchMemoryLink>>,
}
struct BatchMemory {
    link: Option<Box<BatchMemoryLink>>,
    // Keep the real database alive until the grant callback has returned, even
    // when the original table was dropped before this batch.
    owner: Arc<ScratchTableDatabase>,
}
impl Drop for BatchMemory {
    fn drop(&mut self) {
        let Some(mut link) = self.link.take() else {
            return;
        };
        if std::thread::panicking() {
            // No new callback during an existing unwind. The real preadmitted
            // link, lease and byte credit stay with this exact failed owner.
            self.owner.admission.owner_failed();
            let mut retained = self
                .owner
                .retained_batches
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            link.next = retained.take();
            *retained = Some(link);
            return;
        }
        // Deallocate this link before returning its charge through the actual
        // opaque lease. A normally retiring link was never in the retained list.
        let BatchMemoryLink { lease, next } = *link;
        drop(next);
        if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            lease.retire();
        })) {
            self.owner.admission.owner_failed();
            std::panic::resume_unwind(payload);
        }
    }
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
        ensure!(
            self.table
                .as_mut()
                .expect("live staging batch table")
                .insert(key, value)?
                .is_none(),
            "duplicate staged key"
        );
        self.bytes = bytes;
        self.entries += 1;
        self.failed = false;
        Ok(())
    }

    pub fn commit(self) -> Result<()> {
        let Self {
            table,
            transaction,
            failed,
            _memory: memory,
            ..
        } = self;
        let owner = memory.owner.clone();
        if failed {
            return settle_batch_retirement(
                Err(anyhow::anyhow!("staging batch previously failed")),
                owner,
                || {
                    drop(table);
                    drop(transaction);
                    drop(memory);
                },
            );
        }
        // Release the actual alias before native publication can retire its
        // old snapshot. The owner and this batch's charge outlive the commit.
        drop(table);
        let result = transaction.commit().map_err(anyhow::Error::from);
        settle_batch_retirement(result, owner, || drop(memory))
    }
}

/// A new batch grant's retirement is an actual provider callback. Keep the
/// original outcome outside the narrow catch; a panic proves no clean release.
fn settle_batch_retirement<T>(
    result: Result<T>,
    owner: Arc<ScratchTableDatabase>,
    retire: impl FnOnce(),
) -> Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(retire)) {
        Ok(()) => result,
        Err(payload) => {
            owner.admission.owner_failed();
            Err(ScratchBatchRetirementFailure {
                original: result.err(),
                _payload: std::sync::Mutex::new(payload),
                _owner: owner,
            }
            .into())
        }
    }
}

/// This error owns the exact scratch owner and both observations. Dropping a
/// diagnostic does not prove drain: the fenced native owner retains its files.
struct ScratchBatchRetirementFailure {
    original: Option<anyhow::Error>,
    _payload: std::sync::Mutex<Box<dyn std::any::Any + Send>>,
    _owner: Arc<ScratchTableDatabase>,
}
impl std::fmt::Debug for ScratchBatchRetirementFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScratchBatchRetirementFailure")
            .field("original", &self.original)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for ScratchBatchRetirementFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("scratch batch retirement panicked")
    }
}
impl std::error::Error for ScratchBatchRetirementFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_ref().map(|error| error.as_ref() as _)
    }
}

/// The complete retained batch shell and its fixed Arc<str> name. Shared
/// native snapshot and staged-row backing keeps its own original admission.
fn batch_workspace_bytes() -> std::io::Result<u64> {
    crate::disk_memory::add(
        crate::disk_memory::add(
            crate::disk_memory::size::<EncryptedTableBatch>()?,
            crate::disk_memory::allocation::<BatchMemoryLink>(1)?,
        )?,
        crate::disk_memory::add(
            crate::disk_memory::allocation::<u8>(TABLE.name().len() as u64)?,
            2 * crate::disk_memory::size::<usize>()?,
        )?,
    )
}

impl EncryptedTable {
    pub fn new(disk: &Arc<ScratchDisk>, max_disk_bytes: u64, cache: CacheConfig) -> Result<Self> {
        Self::create(Owner::new(disk, max_disk_bytes)?, cache)
    }

    /// A scratch table owns a fresh encrypted group and an explicit incarnation.
    /// Strict creation never adopts a pre-existing segmented image.
    fn create(owner: Arc<Owner>, cache: CacheConfig) -> Result<Self> {
        let group_id = *uuid::Uuid::new_v4().as_bytes();
        let database = kasumi_kv::Database::builder(owner.clone(), group_id, cache)
            .create_with_backend(Backend(owner.clone()))?;
        Self::initialize(database, owner)
    }

    fn initialize(database: kasumi_kv::Database, admission: Arc<Owner>) -> Result<Self> {
        let table = Self {
            owner: Arc::new(ScratchTableDatabase {
                database: Some(crate::node_database::NodeDatabase::new(
                    database,
                    "encrypted scratch table",
                )),
                admission,
                retained_batches: std::sync::Mutex::new(None),
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
        let transaction = self.owner.database().begin_write()?;
        let lease = self
            .owner
            .admission
            .reserve_workspace(batch_workspace_bytes()?)?;
        let memory = BatchMemory {
            link: Some(Box::new(BatchMemoryLink { lease, next: None })),
            owner: self.owner.clone(),
        };
        self.open_batch(transaction, memory)
    }
    fn open_batch(
        &self,
        transaction: kasumi_kv::WriteTransaction,
        memory: BatchMemory,
    ) -> Result<EncryptedTableBatch> {
        let table = match transaction.open_table(TABLE) {
            Ok(table) => table,
            Err(original) => {
                return settle_batch_retirement(Err(original.into()), self.owner.clone(), || {
                    drop(transaction);
                    drop(memory);
                });
            }
        };
        Ok(EncryptedTableBatch {
            table: Some(table),
            transaction,
            bytes: 0,
            entries: 0,
            failed: false,
            _memory: memory,
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
