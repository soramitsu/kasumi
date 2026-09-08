//! Temporary point-addressed staging. Database pages, including keys and indexes,
//! are encrypted in an anonymous spool; only a bounded page cache is resident.
use crate::EncryptedSpool;
use anyhow::{Result, ensure};
use redb::{ReadableDatabase, ReadableTable, StorageBackend, TableDefinition};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Mutex;
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("staged");
#[derive(Debug)]
struct Backend(Mutex<EncryptedSpool>);
impl StorageBackend for Backend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().len())
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let mut spool = self.0.lock().unwrap();
        spool.seek(SeekFrom::Start(offset))?;
        spool.read_exact(out)
    }
    fn set_len(&self, length: u64) -> io::Result<()> {
        self.0.lock().unwrap().resize(length)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let mut spool = self.0.lock().unwrap();
        spool.seek(SeekFrom::Start(offset))?;
        spool.write_all(bytes)
    }
}
pub struct EncryptedTable {
    database: redb::Database,
}
impl EncryptedTable {
    pub fn new(max_disk_bytes: u64) -> Result<Self> {
        let mut builder = redb::Database::builder();
        builder.set_cache_size(8 << 20);
        let database = builder
            .create_with_backend(Backend(Mutex::new(EncryptedSpool::new(max_disk_bytes)?)))?;
        let tx = database.begin_write()?;
        tx.open_table(TABLE)?;
        tx.commit()?;
        Ok(Self { database })
    }
    pub fn insert(&self, key: &[u8], value: &[u8]) -> Result<()> {
        ensure!(
            key.len() <= 4096 && value.len() <= 32 << 20,
            "staged record exceeds limit"
        );
        let mut tx = self.database.begin_write()?;
        tx.set_durability(redb::Durability::None)?;
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
        let mut tx = self.database.begin_write()?;
        tx.set_durability(redb::Durability::None)?;
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
