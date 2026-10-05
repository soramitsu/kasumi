//! Explicit synthetic node construction, available only to fixtures.
//!
//! Original inputs remain inline before the registered constructor accepts
//! its same original grant. This owning carrier deliberately has no StdError
//! implementation and cannot be erased into an ordinary Anyhow error.
use crate::{NodeDisk, NodeStoreStartFailure, ScratchDisk};
use std::sync::Arc;

pub struct NodeFixtureInputs<B> {
    pub(crate) backend: B,
    pub(crate) admission: Arc<dyn kasumi_kv::StorageAdmission>,
    pub(crate) persistent: Option<Arc<NodeDisk>>,
    pub(crate) scratch: Arc<ScratchDisk>,
}
impl<B> NodeFixtureInputs<B> {
    pub fn backend(&self) -> &B {
        &self.backend
    }
    pub fn scratch_disk(&self) -> &Arc<ScratchDisk> {
        &self.scratch
    }
}

#[must_use]
pub struct NodeFixtureStartFailure<B> {
    pub(crate) original: NodeStoreStartFailure,
    pub(crate) unentered: Option<NodeFixtureInputs<B>>,
}
impl<B> NodeFixtureStartFailure<B> {
    pub fn original(&self) -> &NodeStoreStartFailure {
        &self.original
    }
    /// Some means the original backend never entered admitted construction.
    /// This borrow supplies no native close or cleanup witness.
    pub fn unentered(&self) -> Option<&NodeFixtureInputs<B>> {
        self.unentered.as_ref()
    }
    pub fn into_parts(self) -> (NodeStoreStartFailure, Option<NodeFixtureInputs<B>>) {
        (self.original, self.unentered)
    }
}
impl<B> std::fmt::Debug for NodeFixtureStartFailure<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeFixtureStartFailure")
            .field("original", &self.original)
            .field("backend_unentered", &self.unentered.is_some())
            .finish()
    }
}
impl<B> std::fmt::Display for NodeFixtureStartFailure<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "synthetic node fixture preparation: {}", self.original)
    }
}
