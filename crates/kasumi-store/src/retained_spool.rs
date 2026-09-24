//! Borrowed scratch close with one authoritative outcome in the caller's owner.
use super::EncryptedSpool;
use redb::{BackendCloseOutcome, BackendNativeDisposition};
use std::io;

/// The original error or panic belongs to the aggregate that invoked close.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpoolClosePhase {
    Open,
    SyncEntered,
    /// The first caller owns the exact returned I/O error. The spool stays here.
    FailedTransferred,
    /// The original panic unwound to the caller while the spool stayed here.
    InterruptedTransferred,
    /// Successful sync is followed by disposal of the concrete backing.
    DisposalEntered,
    /// Disposal unwound. It must never be replayed or labeled complete.
    DisposalInterrupted,
    /// One native close failed. Its descriptor is diagnostic, never retried.
    NativeUncertain,
    /// Successful sync preceded actual physical and allocation disposal.
    Complete,
}

/// The actual spool must be in registered aggregate custody before close.
///
/// First close transfers its original I/O error or panic to that aggregate's
/// permanent outcome cell while retaining the exact spool and its charge here.
/// The aggregate must record the result without intervening fallible work and
/// retain both this value and the outcome through cancellation. No proxy error,
/// cloned payload, detached reaper, or new allocation is needed at this boundary.
///
/// This value is not self-retaining and establishes no resident-memory bound.
/// Dropping a failed/interrupted owner is not evidence of complete cleanup.
#[must_use = "retain this spool and its aggregate's original close outcome"]
pub struct RetainedSpool {
    spool: Option<EncryptedSpool>,
    phase: SpoolClosePhase,
}
impl std::fmt::Debug for RetainedSpool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetainedSpool")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
impl EncryptedSpool {
    /// Transfer the actual spool into inline custody before entering close.
    pub fn retain(self) -> RetainedSpool {
        RetainedSpool {
            spool: Some(self),
            phase: SpoolClosePhase::Open,
        }
    }
}
struct SyncAttempt<'a>(&'a mut SpoolClosePhase);
impl Drop for SyncAttempt<'_> {
    fn drop(&mut self) {
        *self.0 = match *self.0 {
            SpoolClosePhase::SyncEntered => SpoolClosePhase::InterruptedTransferred,
            SpoolClosePhase::DisposalEntered => SpoolClosePhase::DisposalInterrupted,
            phase => phase,
        };
    }
}
impl RetainedSpool {
    pub fn phase(&self) -> SpoolClosePhase {
        self.phase
    }
    /// Only pre-close callers can read or mutate the spool.
    pub fn spool(&mut self) -> Option<&mut EncryptedSpool> {
        if self.phase == SpoolClosePhase::Open {
            self.spool.as_mut()
        } else {
            None
        }
    }
    /// Close once by borrow. A retry after uncertainty returns only an inline
    /// fence; consult the aggregate's original outcome, never that retry error.
    /// Complete retries succeed without performing any physical operation.
    pub fn close(&mut self) -> BackendCloseOutcome {
        self.close_with(EncryptedSpool::sync_all)
    }
    pub(super) fn close_with(
        &mut self,
        sync: impl FnOnce(&mut EncryptedSpool) -> io::Result<()>,
    ) -> BackendCloseOutcome {
        match self.phase {
            SpoolClosePhase::Complete => return BackendCloseOutcome::drained(Ok(())),
            SpoolClosePhase::Open => {}
            _ => return BackendCloseOutcome::retained(io::ErrorKind::BrokenPipe.into()),
        }
        self.phase = SpoolClosePhase::SyncEntered;
        let attempt = SyncAttempt(&mut self.phase);
        let spool = self.spool.as_mut().expect("open spool retained");
        let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sync(spool))) {
            Ok(result) => result,
            Err(payload) => {
                spool.owner_failed();
                std::panic::resume_unwind(payload)
            }
        };
        match result {
            Err(error) => {
                *attempt.0 = SpoolClosePhase::FailedTransferred;
                BackendCloseOutcome::retained(error)
            }
            Ok(()) => {
                // Native closure is independently observed before the charge
                // may become available. Unknown closure keeps the actual spool.
                *attempt.0 = SpoolClosePhase::DisposalEntered;
                let outcome = spool.close_native_after_sync();
                if outcome.native_disposition() == BackendNativeDisposition::Drained {
                    drop(self.spool.take());
                    *attempt.0 = SpoolClosePhase::Complete;
                } else {
                    *attempt.0 = SpoolClosePhase::NativeUncertain;
                }
                outcome
            }
        }
    }
}

#[cfg(test)]
#[path = "retained_spool_tests.rs"]
mod tests;
