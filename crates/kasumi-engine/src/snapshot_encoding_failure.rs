//! Snapshot encoding reads every stored document body through its generation's
//! resolver and every receipt, terminal, target-resolution and backup-binding
//! row from durable storage, then writes a scratch spool or a caller's stream.
//! Most of what can fail there is local and often transient: a sealed key
//! lease, refused read admission, unavailable storage, scratch I/O, a
//! cancellation or a deadline. Reporting those as `Corruption` sends an
//! operator to restore data that is intact, so a failure keeps the
//! classification of its cause. Only a failure with no recognized cause stays
//! `Corruption`: the encoder's own ordering, size and identity checks, or a
//! stored body or record that fails authentication.
use kasumi_types::{Error, ErrorCode};

pub(crate) fn encoding_error(error: anyhow::Error) -> Error {
    // An engine error was classified where it arose, including by an earlier
    // call here, so it passes through unchanged and is not reported twice.
    let error = match error.downcast::<Error>() {
        Ok(original) => return original,
        Err(error) => error,
    };
    // Only fixture builds format the erased chain, so test logs keep the cause.
    #[cfg(any(test, feature = "test-utils"))]
    eprintln!("kasumi-engine snapshot encoding failure: {error:#}");
    // A native read/retirement wrapper records an outcome in addition to its
    // body error. In particular, failed retirement must not become a definite
    // capacity rejection just because that was the earlier body error.
    if causes(&error).any(is_document_read_failure) {
        return crate::service::document_load_error(error);
    }
    if let Some(original) = causes(&error).find_map(|cause| cause.downcast_ref::<Error>()) {
        return original.clone();
    }
    if causes(&error).any(|cause| cause.is::<kasumi_store::KeyAccessDenied>()) {
        // The same outcome as reading the generation after its lease ended.
        return Error::new(
            ErrorCode::Sealed,
            "tenant key authorization expired; recovery required",
        );
    }
    if causes(&error).any(|cause| cause.is::<tokio::task::JoinError>()) {
        return Error::new(ErrorCode::Unavailable, "snapshot worker stopped");
    }
    match causes(&error).find_map(|cause| cause.downcast_ref::<std::io::Error>()) {
        Some(io) => io_error(io.kind()),
        None => Error::new(ErrorCode::Corruption, "snapshot encoding failed"),
    }
}

/// Each cause, outermost first. `io::Error::source` skips the error it
/// carries, and a writer can carry an engine or store failure inside one.
pub(crate) fn causes(
    error: &anyhow::Error,
) -> impl Iterator<Item = &(dyn std::error::Error + 'static)> {
    let outer: &(dyn std::error::Error + 'static) = error.as_ref();
    std::iter::successors(Some(outer), |&cause| {
        match cause
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            Some(carried) => Some(carried as &(dyn std::error::Error + 'static)),
            None => cause.source(),
        }
    })
}

/// A selected or staged body read the read path already classifies as
/// refused capacity or unavailable storage.
fn is_document_read_failure(cause: &(dyn std::error::Error + 'static)) -> bool {
    cause.is::<kasumi_store::NodeScopedReadFailure>()
        || cause.is::<kasumi_store::NodeScopedReadRetirement>()
        || cause.is::<kasumi_store::PointRetirementFailure>()
        || cause.is::<crate::document_restore::ReadAdmissionFailure>()
}

fn io_error(kind: std::io::ErrorKind) -> Error {
    use std::io::ErrorKind;
    match kind {
        // Authenticated bytes that differ or end early are an integrity
        // failure wherever they were read.
        ErrorKind::InvalidData | ErrorKind::UnexpectedEof => {
            Error::new(ErrorCode::Corruption, "snapshot encoding failed")
        }
        // As on the read path, a generic kind, even a full volume, cannot
        // prove a capacity refusal, so it is not ResourceExhausted. The kind
        // is a closed enum and names the cause for the operator.
        _ => Error::new(
            ErrorCode::Unavailable,
            format!("snapshot encoding I/O failed: {kind}"),
        ),
    }
}

#[cfg(test)]
#[path = "snapshot_encoding_failure_tests.rs"]
mod tests;
