//! Owning results for fixtures that exercise scratch construction.
//!
//! The creation facade remains in its canonical carrier. Ordinary failures keep
//! their original Anyhow allocation for exact type and identity assertions.

#[derive(Debug)]
pub enum FixtureFailure {
    Scratch(kasumi_store::ScratchOperationFailure),
    NodeStartup(kasumi_store::NodeStoreStartFailure),
    NodeFixture(kasumi_store::NodeFixtureStartFailure<kasumi_store::test_utils::FaultBackend>),
    Operation(anyhow::Error),
}

pub type FixtureResult<T> = std::result::Result<T, FixtureFailure>;

impl FixtureFailure {
    pub fn operation_error(&self) -> Option<&anyhow::Error> {
        match self {
            Self::Scratch(original) => original.operation_error(),
            Self::NodeStartup(_) | Self::NodeFixture(_) => None,
            Self::Operation(original) => Some(original),
        }
    }

    pub fn creation(&self) -> Option<&kasumi_store::ScratchCreationFailure> {
        match self {
            Self::Scratch(original) => original.creation(),
            Self::NodeStartup(_) | Self::NodeFixture(_) | Self::Operation(_) => None,
        }
    }
}

impl std::fmt::Display for FixtureFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scratch(original) => original.fmt(formatter),
            Self::NodeStartup(original) => original.fmt(formatter),
            Self::NodeFixture(original) => original.fmt(formatter),
            Self::Operation(original) => original.fmt(formatter),
        }
    }
}

impl From<kasumi_store::NodeStoreStartFailure> for FixtureFailure {
    fn from(original: kasumi_store::NodeStoreStartFailure) -> Self {
        Self::NodeStartup(original)
    }
}

impl From<kasumi_store::NodeFixtureStartFailure<kasumi_store::test_utils::FaultBackend>>
    for FixtureFailure
{
    fn from(
        original: kasumi_store::NodeFixtureStartFailure<kasumi_store::test_utils::FaultBackend>,
    ) -> Self {
        Self::NodeFixture(original)
    }
}

impl From<kasumi_store::ScratchOperationFailure> for FixtureFailure {
    fn from(original: kasumi_store::ScratchOperationFailure) -> Self {
        Self::Scratch(original)
    }
}

impl From<anyhow::Error> for FixtureFailure {
    fn from(original: anyhow::Error) -> Self {
        Self::Operation(original)
    }
}

impl From<kasumi_store::ScratchCreationFailure> for FixtureFailure {
    fn from(original: kasumi_store::ScratchCreationFailure) -> Self {
        Self::Scratch(original.into())
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
    std::io::Error,
    std::num::TryFromIntError,
    std::array::TryFromSliceError,
    serde_json::Error,
    uuid::Error,
    postcard::Error,
    tokio::task::JoinError,
    tokio::time::error::Elapsed,
    tokio::sync::oneshot::error::RecvError,
    tokio::sync::watch::error::SendError<bool>,
    std::sync::mpsc::RecvTimeoutError,
    std::sync::mpsc::SendError<()>,
    kasumi_types::drain::DrainFailure,
    kasumi_types::Error,
    kasumi_store::DiskOpenError,
    openraft::StorageError<u64>,
    openraft::error::Fatal<u64>,
    openraft::error::RaftError<u64>,
    openraft::error::ShutdownError<u64, tokio::task::JoinError>,
    openraft::metrics::WaitError,
);

/// Observe the actual original payload lifetime in native-free lifecycle fixtures.
/// This marker is not a storage grant or a production admission proof.
#[cfg(test)]
pub(crate) fn observed_budget_charge() -> (
    kasumi_types::SharedBudgetCharge,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    struct Original(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Original {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }
    let retired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    (
        kasumi_types::SharedBudgetCharge::new(Original(retired.clone())),
        retired,
    )
}
