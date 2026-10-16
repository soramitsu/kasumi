//! Typed proof that one storage operation was refused for capacity before it
//! took effect. Only the refused operation's own root error value counts: an
//! I/O failure, corruption, an unknown commit or any other uncertain native
//! outcome stays a failure. Nothing is inferred from error text or from a
//! foreign error's source chain.
use kasumi_store::{
    NodeScopedReadFailure, NodeScopedWriteFailure, NodeWriteReport, NodeWriterPhase,
    ScratchOperationFailure, StorageCensusDisposition, TerminalObservation,
};
use std::io;

/// Admission returns these before any reader, writer, file or transaction
/// exists: native memory, a disk allowance, or a census slot.
fn admission_kind(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::OutOfMemory | io::ErrorKind::StorageFull | io::ErrorKind::WouldBlock
    )
}

/// Store's own proof of a settled denial (a clean aborted body or a refused
/// commit, after whole rollback and disposal), or a native begin refused for
/// capacity before any transaction existed.
fn write_refused(report: &NodeWriteReport<'_>) -> bool {
    report.is_capacity_denied()
        || (report.phase() == NodeWriterPhase::Finished
            && report.terminal().is_none()
            && matches!(report.begin(), TerminalObservation::Returned(Err(error))
                if error.0.is_capacity_denied())
            && matches!(report.body(), TerminalObservation::NotEntered)
            && matches!(report.post_commit(), TerminalObservation::NotEntered)
            && matches!(report.outer(), TerminalObservation::Returned(Ok(())))
            && matches!(
                report.output_disposal(),
                TerminalObservation::NotEntered | TerminalObservation::Returned(Ok(()))
            ))
}

/// Store retires only exact routine read outcomes. Apart from a bound
/// violation, excluded here, each is a capacity refusal of the native begin,
/// a table, the read or its output. A reader that cannot retire stays retained.
fn read_refused(failure: &NodeScopedReadFailure) -> bool {
    !matches!(
        failure.report().read_failure(),
        TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::BoundExceeded))
    ) && failure.try_retire_routine() == StorageCensusDisposition::Retired
}

/// `error` proves its operation was refused for capacity with no effect. A
/// refused reader's census entry is retired here.
pub(crate) fn refused(error: &anyhow::Error) -> bool {
    if let Some(original) = error.downcast_ref::<io::Error>() {
        return admission_kind(original.kind());
    }
    if let Some(original) = error.downcast_ref::<kasumi_types::Error>() {
        return original.code == kasumi_types::ErrorCode::ResourceExhausted;
    }
    if error
        .downcast_ref::<kasumi_store::StorageCapacityDenied>()
        .is_some()
    {
        return true;
    }
    if let Some(failure) = error.downcast_ref::<NodeScopedWriteFailure>() {
        return write_refused(&failure.report());
    }
    if let Some(failure) = error.downcast_ref::<NodeScopedReadFailure>() {
        return read_refused(failure);
    }
    false
}

/// `Ok` when `error` is a proven refusal. A refused writer keeps its original
/// observations in its census entry; its outcome is proved, so it is retired
/// as Store retires a settled capacity denial. Any other error is returned.
pub(crate) fn take(error: anyhow::Error) -> Result<(), anyhow::Error> {
    if !refused(&error) {
        return Err(error);
    }
    if let Ok(failure) = error.downcast::<NodeScopedWriteFailure>() {
        // A busy census completes this released entry on its next drain.
        let _ = failure.retire();
    }
    Ok(())
}

/// Scratch seat refusals precede every constructor. A failed scratch
/// constructor keeps its original in a prepaid seat and is never a refusal.
pub(crate) fn scratch_refused(error: &ScratchOperationFailure) -> bool {
    match error {
        ScratchOperationFailure::AdmissionRefused(_) => true,
        ScratchOperationFailure::Operation(error) => refused(error),
        ScratchOperationFailure::Creation(_) => false,
    }
}

/// `take` for a scratch operation's outcome.
pub(crate) fn take_scratch(error: ScratchOperationFailure) -> Result<(), ScratchOperationFailure> {
    match error {
        ScratchOperationFailure::AdmissionRefused(_) => Ok(()),
        ScratchOperationFailure::Operation(error) => {
            take(error).map_err(ScratchOperationFailure::Operation)
        }
        creation @ ScratchOperationFailure::Creation(_) => Err(creation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_typed_root_admission_refusals_prove_no_effect() {
        for kind in [
            io::ErrorKind::OutOfMemory,
            io::ErrorKind::StorageFull,
            io::ErrorKind::WouldBlock,
        ] {
            let error = anyhow::Error::from(io::Error::from(kind)).context("journal append");
            assert!(refused(&error));
            assert!(take(error).is_ok());
        }
        let exhausted = kasumi_types::Error::new(
            kasumi_types::ErrorCode::ResourceExhausted,
            "snapshot work census is full",
        );
        assert!(refused(&anyhow::Error::from(exhausted)));
        for kind in [
            io::ErrorKind::Other,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::TimedOut,
            io::ErrorKind::InvalidData,
        ] {
            assert!(!refused(&anyhow::Error::from(io::Error::from(kind))));
        }
        // A capacity cause nested in a foreign error's source chain proves
        // nothing about that error's own outcome.
        let foreign = anyhow::Error::new(io::Error::other(io::Error::from(
            io::ErrorKind::OutOfMemory,
        )));
        assert!(!refused(&foreign));
        assert!(!refused(&anyhow::anyhow!("storage capacity denied")));
        let unavailable =
            kasumi_types::Error::new(kasumi_types::ErrorCode::Unavailable, "write capacity");
        let error = anyhow::Error::from(unavailable);
        assert!(!refused(&error));
        assert!(take(error).is_err());
        assert!(scratch_refused(&ScratchOperationFailure::AdmissionRefused(
            kasumi_store::ScratchAdmissionRefusal::Busy
        )));
        assert!(!scratch_refused(&ScratchOperationFailure::Operation(
            anyhow::anyhow!("corrupt snapshot manifest")
        )));
    }
}
