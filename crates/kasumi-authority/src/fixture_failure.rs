//! Fixture joins retain typed constructor owners and exact ordinary originals.
#[derive(Debug)]
pub(super) enum FixtureFailure {
    Scratch(kasumi_store::ScratchOperationFailure),
    Snapshot(kasumi_engine::SnapshotFailure),
    Operation(anyhow::Error),
}
pub(super) type FixtureResult<T> = std::result::Result<T, FixtureFailure>;

impl std::fmt::Display for FixtureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scratch(original) => original.fmt(f),
            Self::Snapshot(original) => original.fmt(f),
            Self::Operation(original) => original.fmt(f),
        }
    }
}
impl From<kasumi_store::ScratchOperationFailure> for FixtureFailure {
    fn from(original: kasumi_store::ScratchOperationFailure) -> Self {
        Self::Scratch(original)
    }
}
impl From<kasumi_engine::SnapshotFailure> for FixtureFailure {
    fn from(original: kasumi_engine::SnapshotFailure) -> Self {
        Self::Snapshot(original)
    }
}
impl From<anyhow::Error> for FixtureFailure {
    fn from(original: anyhow::Error) -> Self {
        Self::Operation(original)
    }
}
macro_rules! ordinary {
    ($($original:ty),+ $(,)?) => {$ (
        impl From<$original> for FixtureFailure {
            fn from(original: $original) -> Self {
                Self::Operation(anyhow::Error::new(original))
            }
        }
    )+};
}
ordinary!(
    kasumi_types::Error,
    kasumi_types::drain::DrainFailure,
    std::io::Error,
    serde_json::Error,
);
