//! An authenticated point result keeps its actual plaintext backing admitted.
use crate::{
    KeyState, TenantStore, check_encrypted_record_budget, visit_record::AdmittedPlaintextRecord,
};
use anyhow::{Result, ensure};
use std::{
    fmt,
    ops::{Deref, Range},
};

/// A move-only authenticated value with installed resident ownership.
///
/// The complete decrypted record backing stays charged until this owner drops.
/// It is zeroized and freed before its installed memory credit is returned.
/// Borrowed bytes cannot outlive the owner; no mutable backing or uncharged
/// owned-byte extraction is exposed.
pub struct PlaintextValue {
    record: AdmittedPlaintextRecord,
    value: Range<usize>,
}

impl PlaintextValue {
    pub(crate) fn prepare(
        store: &TenantStore,
        disk_key: &[u8],
        envelope: &[u8],
        state: &KeyState,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Self> {
        check_encrypted_record_budget(envelope, namespace.len(), key.len(), max_value_bytes)?;
        let record = AdmittedPlaintextRecord::prepare(store, disk_key, envelope, state)?;
        Self::from_record(
            store,
            disk_key,
            record,
            state,
            namespace,
            key,
            max_value_bytes,
        )
    }

    pub(super) fn prepare_retained(
        store: &TenantStore,
        disk_key: &[u8],
        envelope: &[u8],
        state: &KeyState,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<crate::RetainedPlaintextValue> {
        check_encrypted_record_budget(envelope, namespace.len(), key.len(), max_value_bytes)?;
        let record = AdmittedPlaintextRecord::prepare_retained(store, disk_key, envelope, state)?;
        let value = Self::from_record(
            store,
            disk_key,
            record,
            state,
            namespace,
            key,
            max_value_bytes,
        )?;
        // The actual control was part of this named producer's original quote.
        Ok(crate::RetainedPlaintextValue::from_prepared(value))
    }

    fn from_record(
        store: &TenantStore,
        disk_key: &[u8],
        record: AdmittedPlaintextRecord,
        state: &KeyState,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Self> {
        let fields = store.decode_record_fields(disk_key, record.plaintext(), state)?;
        ensure!(
            fields.namespace == namespace && fields.key == key,
            "record identity mismatch"
        );
        ensure!(
            fields.value.len() <= max_value_bytes,
            "record value exceeds read budget"
        );
        // The authenticated parser rejects trailing bytes; the value is exactly
        // the final field of this owned, immutable plaintext record.
        let value = record.plaintext().len() - fields.value.len()..record.plaintext().len();
        store.require_access(state)?;
        Ok(Self { record, value })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.record.plaintext()[self.value.clone()]
    }

    /// Require this value's original installed memory owner before sharing it
    /// in another component of that same installed node.
    pub fn require_memory(
        &self,
        provider: &std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
    ) -> Result<()> {
        self.record.require_memory(provider)
    }

    pub(crate) fn is_from_memory(
        &self,
        provider: &std::sync::Arc<dyn crate::NodeDiskMemoryAdmission>,
    ) -> bool {
        self.record.is_from_memory(provider)
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

// Private supported point producers only. Public callers cannot inject a
// decoded result type, allocation quote or grant into the shared-read corridor.
pub(crate) trait PointReadValue: Sized {
    fn prepare(
        store: &TenantStore,
        disk_key: &[u8],
        envelope: &[u8],
        state: &KeyState,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Self>;
}
impl PointReadValue for PlaintextValue {
    fn prepare(
        store: &TenantStore,
        disk_key: &[u8],
        envelope: &[u8],
        state: &KeyState,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Self> {
        Self::prepare(
            store,
            disk_key,
            envelope,
            state,
            namespace,
            key,
            max_value_bytes,
        )
    }
}
impl PointReadValue for crate::RetainedPlaintextValue {
    fn prepare(
        store: &TenantStore,
        disk_key: &[u8],
        envelope: &[u8],
        state: &KeyState,
        namespace: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Self> {
        PlaintextValue::prepare_retained(
            store,
            disk_key,
            envelope,
            state,
            namespace,
            key,
            max_value_bytes,
        )
    }
}

impl AsRef<[u8]> for PlaintextValue {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Deref for PlaintextValue {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for PlaintextValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PlaintextValue")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for PlaintextValue {
    fn eq(&self, other: &T) -> bool {
        self.as_bytes() == other.as_ref()
    }
}
impl Eq for PlaintextValue {}

impl PartialEq<PlaintextValue> for Vec<u8> {
    fn eq(&self, other: &PlaintextValue) -> bool {
        self.as_slice() == other.as_bytes()
    }
}

#[cfg(test)]
#[path = "plaintext_value_panic_tests.rs"]
mod panic_tests;
#[cfg(test)]
#[path = "plaintext_value_tests.rs"]
mod tests;
