//! Explicit resident ownership for adversarial fixture byte copies.
use crate::{DiskMemoryLease, TenantStore, WriteOp, disk_memory};
use anyhow::{Context, Result, ensure};
use std::ops::Deref;
use zeroize::{Zeroize, Zeroizing};

pub struct FixturePlaintextCopy {
    bytes: Zeroizing<Vec<u8>>,
    _charge: DiskMemoryLease,
}
impl FixturePlaintextCopy {
    pub fn with_suffix(store: &TenantStore, source: &[u8], suffix: &[u8]) -> Result<Self> {
        let length = source
            .len()
            .checked_add(suffix.len())
            .context("fixture copy size overflow")?;
        let admitted = disk_memory::allocation::<u8>(u64::try_from(length)?)?;
        let charge = store
            .plaintext_memory_owner()
            .clone()
            .reserve_installed(admitted)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(length)?;
        ensure!(
            bytes.capacity() as u64 <= admitted,
            "fixture copy exceeded admission"
        );
        bytes.extend_from_slice(source);
        bytes.extend_from_slice(suffix);
        Ok(Self {
            bytes,
            _charge: charge,
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn resized(store: &TenantStore, source: &[u8], length: usize, fill: u8) -> Result<Self> {
        let admitted = disk_memory::allocation::<u8>(u64::try_from(length)?)?;
        let charge = store
            .plaintext_memory_owner()
            .clone()
            .reserve_installed(admitted)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(length)?;
        ensure!(
            bytes.capacity() as u64 <= admitted,
            "fixture copy exceeded admission"
        );
        bytes.extend_from_slice(&source[..source.len().min(length)]);
        bytes.resize(length, fill);
        Ok(Self {
            bytes,
            _charge: charge,
        })
    }
}

pub enum FixtureWrite<'a> {
    Put(&'a str, &'a [u8], &'a [u8]),
    Delete(&'a str, &'a [u8]),
}

/// Explicitly copied fixture operations retain their real allocation charge
/// through one atomic native batch. Their original bytes cannot be extracted.
pub struct FixtureWriteBatch {
    operations: Vec<WriteOp>,
    _charge: DiskMemoryLease,
    provider: std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
}
impl FixtureWriteBatch {
    pub fn prepare(store: &TenantStore, writes: &[FixtureWrite<'_>]) -> Result<Self> {
        let mut admitted = disk_memory::allocation::<WriteOp>(u64::try_from(writes.len())?)?;
        for write in writes {
            let (namespace, key, value) = match write {
                FixtureWrite::Put(namespace, key, value) => (*namespace, *key, Some(*value)),
                FixtureWrite::Delete(namespace, key) => (*namespace, *key, None),
            };
            for length in [
                Some(namespace.len()),
                Some(key.len()),
                value.map(<[u8]>::len),
            ]
            .into_iter()
            .flatten()
            {
                admitted =
                    disk_memory::add(admitted, disk_memory::allocation::<u8>(length as u64)?)?;
            }
        }
        let provider = store.plaintext_memory_owner().clone();
        let charge = provider.clone().reserve_installed(admitted)?;
        let mut batch = Self {
            operations: Vec::new(),
            _charge: charge,
            provider,
        };
        batch.operations.try_reserve_exact(writes.len())?;
        for write in writes {
            batch.operations.push(match write {
                FixtureWrite::Put(namespace, key, value) => WriteOp::put(*namespace, *key, *value),
                FixtureWrite::Delete(namespace, key) => WriteOp::delete(*namespace, *key),
            });
        }
        let mut actual =
            disk_memory::allocation::<WriteOp>(u64::try_from(batch.operations.capacity())?)?;
        for operation in &batch.operations {
            let (namespace, key, value) = match operation {
                WriteOp::Put {
                    namespace,
                    key,
                    value,
                } => (namespace, key, Some(value)),
                WriteOp::Delete { namespace, key } => (namespace, key, None),
            };
            for capacity in [
                Some(namespace.capacity()),
                Some(key.capacity()),
                value.map(Vec::capacity),
            ]
            .into_iter()
            .flatten()
            {
                actual = disk_memory::add(
                    actual,
                    disk_memory::allocation::<u8>(u64::try_from(capacity)?)?,
                )?;
            }
        }
        ensure!(
            actual <= admitted,
            "fixture write allocation exceeded admission"
        );
        Ok(batch)
    }
    pub fn write(&self, store: &TenantStore) -> Result<()> {
        ensure!(
            std::sync::Arc::ptr_eq(&self.provider, store.plaintext_memory_owner()),
            "fixture write installed owner differs"
        );
        store.write_batch(&self.operations)
    }
    pub fn write_custody(&self, stores: &crate::TenantStorageSet) -> Result<()> {
        ensure!(
            std::sync::Arc::ptr_eq(
                &self.provider,
                stores.custody().store().plaintext_memory_owner()
            ),
            "fixture write installed owner differs"
        );
        stores.write_batch(&[], &self.operations)
    }
}
impl Drop for FixtureWriteBatch {
    fn drop(&mut self) {
        for operation in &mut self.operations {
            match operation {
                WriteOp::Put {
                    namespace,
                    key,
                    value,
                } => {
                    namespace.zeroize();
                    key.zeroize();
                    value.zeroize();
                }
                WriteOp::Delete { namespace, key } => {
                    namespace.zeroize();
                    key.zeroize();
                }
            }
        }
    }
}
impl Deref for FixturePlaintextCopy {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Admit the necessary WriteOp byte copy and keep it charged until the
/// synchronous native write and operation destruction have both completed.
pub fn write_plaintext_copy_for_fixture(
    store: &TenantStore,
    namespace: &str,
    key: &[u8],
    value: &[u8],
) -> Result<()> {
    FixtureWriteBatch::prepare(store, &[FixtureWrite::Put(namespace, key, value)])?.write(store)
}
