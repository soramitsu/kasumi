//! Fixed diagnostic projection. Never format, clone or consume an original error.
use openraft::{
    StorageError,
    error::{Fatal, RaftError, ShutdownError},
};

/// Classify a retained Raft failure without exposing error chains or payloads.
/// The original remains owned by its existing shutdown/startup report.
pub fn raft_failure_class(error: &anyhow::Error) -> Option<&'static str> {
    if let Some(shutdown) = error.downcast_ref::<ShutdownError<u64, tokio::task::JoinError>>() {
        return Some(shutdown.core().map_or("non_core_shutdown", fatal_class));
    }
    if let Some(fatal) = error.downcast_ref::<Fatal<u64>>() {
        return Some(fatal_class(fatal));
    }
    if let Some(RaftError::Fatal(fatal)) = error.downcast_ref::<RaftError<u64>>() {
        return Some(fatal_class(fatal));
    }
    error.downcast_ref::<StorageError<u64>>().map(storage_class)
}

fn storage_class(error: &StorageError<u64>) -> &'static str {
    match error {
        StorageError::IO { .. } => "storage_io",
        StorageError::Defensive { .. } => "storage_defensive",
    }
}

fn fatal_class(error: &Fatal<u64>) -> &'static str {
    match error {
        Fatal::StorageError(error) => storage_class(error),
        Fatal::Panicked => "panicked",
        Fatal::TaskCapacity(_) => "task_capacity",
        Fatal::Cancelled => "cancelled",
        Fatal::Stopped => "stopped",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::{ErrorSubject, ErrorVerb, error::TaskCapacity};

    #[test]
    fn projects_only_fixed_fatal_classes_through_opaque_context() {
        for (fatal, expected) in [
            (Fatal::<u64>::Panicked, "panicked"),
            (
                Fatal::TaskCapacity(TaskCapacity {
                    limit: 3,
                    needed: 1,
                }),
                "task_capacity",
            ),
            (Fatal::Cancelled, "cancelled"),
            (Fatal::Stopped, "stopped"),
            (
                Fatal::StorageError(StorageError::from_io_error(
                    ErrorSubject::Store,
                    ErrorVerb::Read,
                    std::io::Error::other("private document and /private/storage/path"),
                )),
                "storage_io",
            ),
            (
                Fatal::StorageError(StorageError::Defensive {
                    source: openraft::DefensiveError::new(
                        ErrorSubject::Store,
                        openraft::Violation::LogsEmpty,
                    ),
                }),
                "storage_defensive",
            ),
        ] {
            let error = anyhow::Error::new(fatal).context("private provider URL and bearer");
            assert_eq!(raft_failure_class(&error), Some(expected));
            assert!(error.downcast_ref::<Fatal<u64>>().is_some());
        }
    }

    #[test]
    fn unknown_errors_are_not_formatted_or_guessed_from_their_text() {
        #[derive(Debug)]
        struct Opaque;
        impl std::fmt::Display for Opaque {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("diagnostics must not format opaque errors")
            }
        }
        impl std::error::Error for Opaque {}
        assert_eq!(raft_failure_class(&anyhow::Error::new(Opaque)), None);
        assert_eq!(
            raft_failure_class(&anyhow::anyhow!("panicked storage_io private")),
            None
        );
    }
}
