//! Closed sharing of a named authenticated point-read producer's original lease.
use crate::{NodeDiskMemoryAdmission, PlaintextValue};
use std::{fmt, io, ops::Deref, sync::Arc};

pub(crate) struct SharedPlaintextState {
    // After final control deallocation, this owns the original zeroizing Vec
    // and its original provider token. No second charge or byte copy exists.
    value: PlaintextValue,
}
impl SharedPlaintextState {
    pub(crate) fn required_bytes() -> io::Result<u64> {
        kasumi_types::SharedBudgetCharge::required_bytes::<Self>()
    }
}

/// Immutable aliases of ONE original authenticated record backing and lease.
///
/// Only TenantStore::get_retained_bounded constructs it, after its exact fixed
/// control and plaintext Vec were prospectively quoted in the same point grant.
/// No conversion from an ordinary underquoted PlaintextValue, mutable backing,
/// payload extraction, Weak/raw ownership or capacity/completion proof exists.
pub struct RetainedPlaintextValue(Option<Arc<SharedPlaintextState>>);
impl RetainedPlaintextValue {
    pub(super) fn from_prepared(value: PlaintextValue) -> Self {
        Self(Some(Arc::new(SharedPlaintextState { value })))
    }
    fn state(&self) -> &SharedPlaintextState {
        self.0.as_deref().expect("live retained point value")
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.state().value.as_bytes()
    }
    pub fn require_memory(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
    ) -> anyhow::Result<()> {
        self.state().value.require_memory(provider)
    }
    /// Exact original provider identity; a false result lends no authority and
    /// allocates no replacement diagnostic or grant.
    pub fn is_from_memory(&self, provider: &Arc<dyn NodeDiskMemoryAdmission>) -> bool {
        self.state().value.is_from_memory(provider)
    }
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }
}
impl Clone for RetainedPlaintextValue {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Drop for RetainedPlaintextValue {
    fn drop(&mut self) {
        // Every closed alias uses into_inner: with no Weak owner, the actual
        // final Arc control frees before original Vec/token/credit retirement.
        drop(Arc::into_inner(
            self.0.take().expect("live retained point value"),
        ));
    }
}
impl Deref for RetainedPlaintextValue {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl AsRef<[u8]> for RetainedPlaintextValue {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl fmt::Debug for RetainedPlaintextValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedPlaintextValue")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}
#[cfg(test)]
#[path = "retained_plaintext_value_tests.rs"]
mod tests;
