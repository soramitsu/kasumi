//! Whole retired-source construction custody, installed before cleanup awaits.
use crate::administration::original_serving_runtime::{CleanupObservation, observe_cleanup};
use kasumi_engine::SnapshotFailure;
use kasumi_types::drain::DrainFailure;

/// This owner cannot be erased into an ordinary error. The exact body, pending
/// native resources and independent cleanup observations stay together.
pub(crate) struct RetiredSourceFailure {
    original: SnapshotFailure,
    pending: crate::startup_resources::Resources,
    cleanup: Option<DrainFailure>,
    cleanup_observation: CleanupObservation,
}
impl RetiredSourceFailure {
    /// Independent preparation backing paid by the same original parent seat;
    /// the inline failure itself is already part of that seat's concrete layout.
    pub(crate) fn required_bytes() -> std::io::Result<u64> {
        let aliases = std::alloc::Layout::array::<std::sync::Arc<kasumi_engine::RetiredCustody>>(1)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        let preparation = crate::runtime::retired_source_preparation_bytes()?;
        u64::try_from(aliases.size())
            .ok()
            .and_then(|bytes| bytes.checked_add(64))
            .and_then(|bytes| bytes.checked_add(preparation))
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::OutOfMemory))
    }
    pub(crate) fn startup_backing()
    -> anyhow::Result<kasumi_engine::admission::startup::StartupBacking> {
        kasumi_engine::admission::startup::StartupBacking::empty()
            .array::<std::sync::Arc<kasumi_engine::RetiredCustody>>(1)?
            .include(crate::runtime::retired_source_preparation_backing()?)
    }
    pub(crate) fn new(
        original: SnapshotFailure,
        pending: crate::startup_resources::Resources,
    ) -> Self {
        Self {
            original,
            pending,
            cleanup: None,
            cleanup_observation: Default::default(),
        }
    }
    pub(crate) fn original(&self) -> &SnapshotFailure {
        &self.original
    }
    pub(crate) fn cleanup(&self) -> Option<&DrainFailure> {
        self.cleanup.as_ref()
    }
    pub(crate) fn cleanup_observation(&self) -> &CleanupObservation {
        &self.cleanup_observation
    }
    /// Call only after installing this whole owner in the preheld paid seat.
    /// Cancellation leaves Entered. An entered or unwound operation is not replayed.
    pub(crate) async fn close_pending(&mut self) {
        observe_cleanup(
            &mut self.cleanup_observation,
            &mut self.cleanup,
            self.pending.close(),
        )
        .await;
    }
}
impl std::fmt::Debug for RetiredSourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetiredSourceFailure")
            .field("original", &self.original)
            .field("cleanup", &self.cleanup)
            .field("cleanup_unsettled", &self.cleanup_observation.unsettled())
            .finish_non_exhaustive()
    }
}
