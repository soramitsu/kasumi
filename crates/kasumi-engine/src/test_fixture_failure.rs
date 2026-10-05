//! Test joins keep every owning failure inline; no blanket Anyhow erasure.

#[derive(Debug)]
pub(crate) enum FixtureFailure {
    Snapshot(crate::SnapshotFailure),
    SnapshotContext {
        context: &'static str,
        original: crate::SnapshotFailure,
    },
    Publication(kasumi_raft::TestPublicationFailure),
    Selection(kasumi_raft::SelectionFailure<crate::application_sources::Workspace>),
    SourceCapacity(kasumi_store::SourceCapacityFailure),
    NodeStartup(kasumi_store::NodeStoreStartFailure),
    Operation(anyhow::Error),
}

pub(crate) type FixtureResult<T> = std::result::Result<T, FixtureFailure>;

impl FixtureFailure {
    pub(crate) fn admission_refusal(&self) -> Option<kasumi_store::ScratchAdmissionRefusal> {
        match self {
            Self::Snapshot(original) => original.admission_refusal(),
            Self::SnapshotContext { original, .. } => original.admission_refusal(),
            Self::Publication(original) => original.admission_refusal(),
            Self::Selection(_)
            | Self::SourceCapacity(_)
            | Self::NodeStartup(_)
            | Self::Operation(_) => None,
        }
    }
}

impl std::fmt::Display for FixtureFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Snapshot(original) => original.fmt(f),
            Self::SnapshotContext { context, original } => write!(f, "{context}: {original}"),
            Self::Publication(original) => original.fmt(f),
            Self::Selection(original) => original.fmt(f),
            Self::SourceCapacity(original) => original.fmt(f),
            Self::NodeStartup(original) => original.fmt(f),
            Self::Operation(original) => original.fmt(f),
        }
    }
}
impl From<kasumi_store::NodeStoreStartFailure> for FixtureFailure {
    fn from(original: kasumi_store::NodeStoreStartFailure) -> Self {
        Self::NodeStartup(original)
    }
}

impl From<crate::SnapshotFailure> for FixtureFailure {
    fn from(original: crate::SnapshotFailure) -> Self {
        Self::Snapshot(original)
    }
}
impl From<kasumi_store::ScratchOperationFailure> for FixtureFailure {
    fn from(original: kasumi_store::ScratchOperationFailure) -> Self {
        Self::Snapshot(original.into())
    }
}
impl From<kasumi_raft::TestPublicationFailure> for FixtureFailure {
    fn from(original: kasumi_raft::TestPublicationFailure) -> Self {
        Self::Publication(original)
    }
}
impl From<kasumi_raft::SelectionFailure<crate::application_sources::Workspace>> for FixtureFailure {
    fn from(
        original: kasumi_raft::SelectionFailure<crate::application_sources::Workspace>,
    ) -> Self {
        Self::Selection(original)
    }
}
impl From<kasumi_store::SourceCapacityFailure> for FixtureFailure {
    fn from(original: kasumi_store::SourceCapacityFailure) -> Self {
        Self::SourceCapacity(original)
    }
}
impl From<anyhow::Error> for FixtureFailure {
    fn from(original: anyhow::Error) -> Self {
        Self::Operation(original)
    }
}
impl From<kasumi_types::Error> for FixtureFailure {
    fn from(original: kasumi_types::Error) -> Self {
        Self::Operation(original.into())
    }
}
impl From<std::io::Error> for FixtureFailure {
    fn from(original: std::io::Error) -> Self {
        Self::Operation(original.into())
    }
}
impl From<serde_json::Error> for FixtureFailure {
    fn from(original: serde_json::Error) -> Self {
        Self::Operation(original.into())
    }
}
impl From<tokio::task::JoinError> for FixtureFailure {
    fn from(original: tokio::task::JoinError) -> Self {
        Self::Operation(original.into())
    }
}
impl From<kasumi_types::drain::DrainFailure> for FixtureFailure {
    fn from(original: kasumi_types::drain::DrainFailure) -> Self {
        Self::Operation(original.into())
    }
}

// Each named ordinary diagnostic keeps its complete original body, including
// any registered source custody. Typed construction carriers use the owning
// variants above and cannot enter this ordinary conversion corridor.
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
    kasumi_raft::PublicationExpectationError,
    openraft::metrics::WaitError,
    openraft::error::RaftError<u64>,
    openraft::error::Fatal<u64>,
    openraft::error::ShutdownError<u64, tokio::task::JoinError>,
    std::num::TryFromIntError,
    tokio::time::error::Elapsed,
    tokio::sync::oneshot::error::RecvError,
);
