//! Ordered authenticated scan output retains every row and its container credit.
use crate::{
    DiskMemoryLease, KeyState, MAX_RECORD, NodeDiskMemoryAdmission, TenantStore,
    check_encrypted_record_budget, disk_memory, validate_record,
    visit_record::AdmittedPlaintextRecord,
};
use anyhow::{Context, Result, ensure};
use std::{
    fmt,
    ops::{Index, Range},
    sync::Arc,
};

/// One move-only authenticated record whose key and value borrow charged bytes.
pub struct PlaintextRecord {
    record: AdmittedPlaintextRecord,
    key: Range<usize>,
    value: Range<usize>,
}
impl PlaintextRecord {
    pub(crate) fn prepare(
        store: &TenantStore,
        disk_key: &[u8],
        envelope: &[u8],
        state: &KeyState,
        namespace: &str,
    ) -> Result<Self> {
        check_encrypted_record_budget(envelope, namespace.len(), 4096, MAX_RECORD)?;
        let record = AdmittedPlaintextRecord::prepare(store, disk_key, envelope, state)?;
        let fields = store.decode_record_fields(disk_key, record.plaintext(), state)?;
        ensure!(fields.namespace == namespace, "record namespace mismatch");
        validate_record(fields.namespace, fields.key, fields.value.len())?;
        let key_start = 8 + fields.namespace.len();
        let key = key_start..key_start + fields.key.len();
        let value = record.plaintext().len() - fields.value.len()..record.plaintext().len();
        store.require_access(state)?;
        Ok(Self { record, key, value })
    }
    pub fn key(&self) -> &[u8] {
        &self.record.plaintext()[self.key.clone()]
    }
    pub fn value(&self) -> &[u8] {
        &self.record.plaintext()[self.value.clone()]
    }
}
impl fmt::Debug for PlaintextRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlaintextRecord")
            .field("key_len", &self.key.len())
            .field("value_len", &self.value.len())
            .finish_non_exhaustive()
    }
}
impl PartialEq for PlaintextRecord {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key() && self.value() == other.value()
    }
}
impl Eq for PlaintextRecord {}

/// Sorted, move-only scan output with admitted row and vector backing.
///
/// Iteration only borrows fields. No row, owned byte tuple, mutable backing or
/// uncharged container extraction is exposed. The row allocations and vector
/// backing drop before the container's metadata reservation.
pub struct PlaintextScan {
    rows: Vec<PlaintextRecord>,
    metadata: Option<DiskMemoryLease>,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
}
impl PlaintextScan {
    pub(crate) fn new(provider: Arc<dyn NodeDiskMemoryAdmission>) -> Self {
        Self {
            rows: Vec::new(),
            metadata: None,
            provider,
        }
    }
    pub(crate) fn push(&mut self, record: PlaintextRecord) -> Result<()> {
        record.record.require_memory(&self.provider)?;
        if self.rows.len() == self.rows.capacity() {
            let capacity = self
                .rows
                .capacity()
                .checked_mul(2)
                .and_then(|size| size.checked_add(1))
                .context("record scan container capacity overflow")?;
            let admitted = disk_memory::allocation::<PlaintextRecord>(u64::try_from(capacity)?)?;
            // Reallocation may temporarily retain both backings. Fund the whole
            // new vector before it starts, leaving the old charge installed.
            let charge = self
                .provider
                .clone()
                .reserve_installed(admitted)
                .context("record scan container admission denied")?;
            self.rows
                .try_reserve_exact(capacity - self.rows.len())
                .context("record scan container allocation failed")?;
            // The old backing has now retired (or was reused by realloc). Keep
            // the new charge installed even if the capacity check rejects it.
            drop(self.metadata.replace(charge));
            ensure!(
                disk_memory::allocation::<PlaintextRecord>(u64::try_from(self.rows.capacity())?)?
                    <= admitted,
                "record scan container allocation exceeded admission"
            );
        }
        self.rows.push(record);
        Ok(())
    }
    pub(crate) fn sort(&mut self) {
        // Physical HMAC order differs from user-key order. Unstable sorting is
        // in-place and avoids the stable sort's separate allocation.
        self.rows
            .sort_unstable_by(|left, right| left.key().cmp(right.key()));
    }
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&[u8], &[u8])> + DoubleEndedIterator {
        self.rows.iter().map(record_bytes)
    }
}
fn record_bytes(record: &PlaintextRecord) -> (&[u8], &[u8]) {
    (record.key(), record.value())
}
impl<'scan> IntoIterator for &'scan PlaintextScan {
    type Item = (&'scan [u8], &'scan [u8]);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'scan, PlaintextRecord>,
        fn(&'scan PlaintextRecord) -> Self::Item,
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.rows.iter().map(record_bytes)
    }
}
impl Index<usize> for PlaintextScan {
    type Output = PlaintextRecord;
    fn index(&self, index: usize) -> &Self::Output {
        &self.rows[index]
    }
}
impl fmt::Debug for PlaintextScan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlaintextScan")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}
impl PartialEq for PlaintextScan {
    fn eq(&self, other: &Self) -> bool {
        self.rows == other.rows
    }
}
impl Eq for PlaintextScan {}
impl PartialEq<Vec<(Vec<u8>, Vec<u8>)>> for PlaintextScan {
    fn eq(&self, other: &Vec<(Vec<u8>, Vec<u8>)>) -> bool {
        self.len() == other.len()
            && self.iter().zip(other).all(|((key, value), expected)| {
                key == expected.0.as_slice() && value == expected.1.as_slice()
            })
    }
}

#[cfg(test)]
mod tests;
