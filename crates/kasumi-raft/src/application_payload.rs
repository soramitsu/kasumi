//! One application byte encoding with explicit proposal storage ownership.
use anyhow::{Context, Result};
use kasumi_store::{DiskMemoryLease, PlaintextValue};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, ops::Deref, sync::Arc};

/// The caller transfers its actual owned proposal into the group.
/// A stored value retains its original installed resident charge.
pub enum ApplicationProposal {
    Generated(Vec<u8>),
    Admitted(crate::AdmittedApplicationInput),
    Stored(PlaintextValue),
}

impl ApplicationProposal {
    pub fn generated(bytes: Vec<u8>) -> Self {
        Self::Generated(bytes)
    }
    /// An encoded input whose exact buffer/control/token were funded by its
    /// original provider before consensus submission. No candidate credit.
    pub fn admitted_input(bytes: crate::AdmittedApplicationInput) -> Self {
        Self::Admitted(bytes)
    }
    pub fn stored(bytes: PlaintextValue) -> Self {
        Self::Stored(bytes)
    }

    pub(crate) fn admit(
        self,
        store: &Arc<kasumi_store::TenantStore>,
        lease: &std::sync::Weak<crate::lifetime::StorageLease>,
    ) -> Result<ApplicationPayload> {
        match self {
            Self::Admitted(bytes) => {
                bytes
                    .require_memory(store.plaintext_memory_owner())
                    .map_err(|_| anyhow::anyhow!("application input memory owner differs"))?;
                Ok(ApplicationPayload(Payload::Admitted(bytes)))
            }
            Self::Generated(bytes) => Ok(ApplicationPayload(Payload::Ingress(bytes))),
            Self::Stored(value) => {
                let provider = store.plaintext_memory_owner();
                value.require_memory(provider)?;
                let lease = lease
                    .upgrade()
                    .context("application storage ownership drained")?;
                // The original plaintext is already admitted. Only this actual
                // Arc's control and inline backing are newly allocated here.
                let bytes = DiskMemoryLease::token_allocation_bytes::<StoredBacking>()?
                    .checked_add(2 * u64::try_from(std::mem::size_of::<usize>())?)
                    .context("application shared control size overflow")?;
                let charge = provider
                    .clone()
                    .reserve_installed(bytes)
                    .context("application shared control admission denied")?;
                Ok(ApplicationPayload(Payload::Stored(StoredApplication(
                    Some(Arc::new(StoredBacking {
                        value,
                        _store: store.clone(),
                        _storage_lease: lease,
                        _charge: charge,
                    })),
                ))))
            }
        }
    }
}

struct StoredBacking {
    value: PlaintextValue,
    _charge: DiskMemoryLease,
    _store: Arc<kasumi_store::TenantStore>,
    _storage_lease: Arc<crate::lifetime::StorageLease>,
}

struct StoredApplication(Option<Arc<StoredBacking>>);
impl Clone for StoredApplication {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Drop for StoredApplication {
    fn drop(&mut self) {
        // Every handle uses into_inner. Exactly one simultaneous final drop
        // retires the Arc control before freeing backing and returning credit.
        drop(Arc::into_inner(
            self.0.take().expect("stored application custody"),
        ));
    }
}

enum Payload {
    Ingress(Vec<u8>),
    Admitted(crate::AdmittedApplicationInput),
    Stored(StoredApplication),
}

/// Internal storage forms serialize exactly the existing application bytes.
/// Deserialize retains the existing ingress Vec allocation behavior; ingress
/// capacity admission remains the separate M03/M05 release work.
pub struct ApplicationPayload(Payload);
impl ApplicationPayload {
    pub(crate) fn admitted_replay(input: crate::AdmittedApplicationInput) -> Self {
        Self(Payload::Admitted(input))
    }
    pub(crate) fn ingress(bytes: Vec<u8>) -> Self {
        Self(Payload::Ingress(bytes))
    }
    /// Bind an already admitted local input to the exact assigned consensus ID.
    /// Ingress and ordinary Stored proposals have no M03 input loan. A named
    /// persisted ordinary replay result retains its original point-read lease.
    pub(crate) fn bind_input(&self, id: openraft::LogId<u64>) -> anyhow::Result<()> {
        if let Payload::Admitted(input) = &self.0 {
            input
                .bind(id)
                .map_err(|_| anyhow::anyhow!("application input log binding differs"))?;
        }
        Ok(())
    }
    pub(crate) fn input_loan(
        &self,
        id: openraft::LogId<u64>,
    ) -> anyhow::Result<Option<crate::ApplicationInputLoan>> {
        match &self.0 {
            Payload::Admitted(input) => input
                .loan(id)
                .map(Some)
                .map_err(|_| anyhow::anyhow!("application input lacks its exact log binding")),
            // These remain explicit unsupported input producers, not donated
            // credit, guessed capacity or an application completion proof.
            Payload::Ingress(_) | Payload::Stored(_) => Ok(None),
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            Payload::Ingress(bytes) => bytes,
            Payload::Admitted(bytes) => bytes.as_bytes(),
            Payload::Stored(owner) => owner
                .0
                .as_ref()
                .expect("stored application custody")
                .value
                .as_bytes(),
        }
    }
}
impl Clone for ApplicationPayload {
    fn clone(&self) -> Self {
        Self(match &self.0 {
            Payload::Ingress(bytes) => Payload::Ingress(bytes.clone()),
            Payload::Admitted(bytes) => Payload::Admitted(bytes.clone()),
            Payload::Stored(owner) => Payload::Stored(owner.clone()),
        })
    }
}
impl Deref for ApplicationPayload {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}
impl PartialEq for ApplicationPayload {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}
impl Eq for ApplicationPayload {}
impl fmt::Debug for ApplicationPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationPayload")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}
impl Serialize for ApplicationPayload {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.as_bytes().serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for ApplicationPayload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        Vec::<u8>::deserialize(deserializer).map(Self::ingress)
    }
}

#[cfg(test)]
#[path = "application_payload_tests.rs"]
pub(crate) mod tests;
