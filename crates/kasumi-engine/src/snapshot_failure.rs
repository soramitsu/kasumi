//! Snapshot construction keeps its registered scratch failure as an owner.
use kasumi_store::{ScratchAdmissionRefusal, ScratchCreationFailure, ScratchOperationFailure};
use kasumi_types::Error;

/// Ordinary application errors retain their original code and value. A
/// creation failure retains the entire registered native opening facade.
/// This deliberately has no `std::error::Error` implementation.
#[derive(Debug)]
pub enum SnapshotFailure {
    AdmissionRefused(ScratchAdmissionRefusal),
    Creation(ScratchCreationFailure),
    Operation(Error),
    Source(anyhow::Error),
}
impl SnapshotFailure {
    pub(crate) fn ordinary<T>(
        work: impl FnOnce() -> anyhow::Result<T>,
    ) -> std::result::Result<T, Self> {
        work().map_err(Into::into)
    }
    pub(crate) fn into_scratch_failure(self) -> ScratchOperationFailure {
        match self {
            Self::AdmissionRefused(original) => ScratchOperationFailure::AdmissionRefused(original),
            Self::Creation(original) => ScratchOperationFailure::Creation(original),
            Self::Operation(original) => ScratchOperationFailure::Operation(original.into()),
            Self::Source(original) => ScratchOperationFailure::Operation(original),
        }
    }
    pub fn creation(&self) -> Option<&ScratchCreationFailure> {
        match self {
            Self::Creation(original) => Some(original),
            Self::AdmissionRefused(_) | Self::Operation(_) | Self::Source(_) => None,
        }
    }
    pub fn operation_error(&self) -> Option<&Error> {
        match self {
            Self::AdmissionRefused(_) | Self::Creation(_) | Self::Source(_) => None,
            Self::Operation(original) => Some(original),
        }
    }
    pub fn source_error(&self) -> Option<&anyhow::Error> {
        match self {
            Self::Source(original) => Some(original),
            Self::AdmissionRefused(_) | Self::Creation(_) | Self::Operation(_) => None,
        }
    }
    pub fn admission_refusal(&self) -> Option<ScratchAdmissionRefusal> {
        match self {
            Self::AdmissionRefused(original) => Some(*original),
            Self::Creation(_) | Self::Operation(_) | Self::Source(_) => None,
        }
    }
}
impl From<Error> for SnapshotFailure {
    fn from(original: Error) -> Self {
        Self::Operation(original)
    }
}
impl From<ScratchAdmissionRefusal> for SnapshotFailure {
    fn from(original: ScratchAdmissionRefusal) -> Self {
        Self::AdmissionRefused(original)
    }
}
impl From<ScratchOperationFailure> for SnapshotFailure {
    fn from(original: ScratchOperationFailure) -> Self {
        match original {
            ScratchOperationFailure::AdmissionRefused(original) => Self::AdmissionRefused(original),
            ScratchOperationFailure::Creation(original) => Self::Creation(original),
            ScratchOperationFailure::Operation(original) => original.into(),
        }
    }
}
impl From<anyhow::Error> for SnapshotFailure {
    fn from(original: anyhow::Error) -> Self {
        let outer: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
        if !outer.is::<Error>() {
            return Self::Source(original);
        }
        match original.downcast::<Error>() {
            Ok(original) => Self::Operation(original),
            Err(original) => Self::Source(original),
        }
    }
}
impl From<serde_json::Error> for SnapshotFailure {
    fn from(original: serde_json::Error) -> Self {
        anyhow::Error::new(original).into()
    }
}
impl From<std::io::Error> for SnapshotFailure {
    fn from(original: std::io::Error) -> Self {
        anyhow::Error::new(original).into()
    }
}
impl From<tokio::task::JoinError> for SnapshotFailure {
    fn from(original: tokio::task::JoinError) -> Self {
        anyhow::Error::new(original).into()
    }
}
impl From<kasumi_types::drain::DrainFailure> for SnapshotFailure {
    fn from(original: kasumi_types::drain::DrainFailure) -> Self {
        anyhow::Error::new(original).into()
    }
}
impl std::fmt::Display for SnapshotFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdmissionRefused(original) => original.fmt(f),
            Self::Creation(original) => original.fmt(f),
            Self::Operation(original) => original.fmt(f),
            Self::Source(original) => original.fmt(f),
        }
    }
}

#[cfg(test)]
#[path = "snapshot_failure_tests.rs"]
mod tests;
