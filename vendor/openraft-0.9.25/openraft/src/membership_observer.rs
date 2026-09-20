//! Synchronous notification before effective or committed membership changes.
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

/// A fixed per-group observer for invalidating application readiness evidence.
///
/// The callback runs synchronously before the membership fields change, under
/// the same lock used to install the observer. It must be bounded, nonblocking,
/// non-panicking, and must not reenter Raft or install another observer. Updating
/// a shared atomic generation is the intended use; no task is spawned for it.
///
/// Readiness must subsequently read current membership through the Raft actor,
/// not through potentially lagging metrics, before publishing fresh evidence.
pub trait MembershipObserver: Debug + Send + Sync + 'static {
    /// Invalidate evidence derived from this group's previous membership.
    fn membership_changing(&self);
}

/// A different observer already owns this group's fixed observer slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a different membership observer is already installed")]
pub struct MembershipObserverAlreadyInstalled;

#[derive(Debug, Default)]
pub(crate) struct MembershipObserverSlot {
    observer: Mutex<Option<Arc<dyn MembershipObserver>>>,
}

impl MembershipObserverSlot {
    /// The guard must remain live across the actual membership field updates,
    /// including when the slot is still empty. This closes the install/mutate gap.
    pub(crate) fn changing(&self) -> MutexGuard<'_, Option<Arc<dyn MembershipObserver>>> {
        let observer = self.observer.lock().unwrap();
        if let Some(observer) = observer.as_ref() {
            observer.membership_changing();
        }
        observer
    }

    pub(crate) fn install(
        &self,
        observer: Arc<dyn MembershipObserver>,
    ) -> Result<(), MembershipObserverAlreadyInstalled> {
        let mut slot = self.observer.lock().unwrap();
        if let Some(current) = slot.as_ref() {
            return if Arc::ptr_eq(current, &observer) {
                Ok(())
            } else {
                Err(MembershipObserverAlreadyInstalled)
            };
        }
        // No certificate made before installation may remain valid. Holding
        // this lock also waits for any unobserved mutation already in progress.
        observer.membership_changing();
        *slot = Some(observer);
        Ok(())
    }
}
