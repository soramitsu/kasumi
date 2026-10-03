//! One pre-admitted terminal apply failure, retained independently of an async
//! waiter. The installed lifecycle owner collects its diagnostic only after
//! the actual storage workers have drained.
//! Retaining or inspecting an error is not proof that any resource it owns has
//! drained; the surrounding lifecycle still preserves those failure semantics.

#[path = "apply_completion_report.rs"]
pub(crate) mod completion;
use completion::{CompletionState, ReportBusy, RetainedApplyReport};

use std::{
    any::Any,
    fmt,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

/// Raw Arc and Weak handles never escape. Field order retires the original
/// error and the Arc allocation before releasing the final admission charge.
struct FailureState {
    error: OnceLock<anyhow::Error>,
    pub(crate) completion: CompletionState,
    // A retained diagnostic keeps the duplicate-open fence independently of
    // the group facade. Its exact store allocation must remain alive too:
    // LIVE_GROUPS uses that allocation's address as its identity.
    ownership: OnceLock<BoundOwnership>,
}
struct BoundOwnership {
    live: Arc<AtomicBool>,
    // This strong owner also keeps the store's existing admission alive. A
    // bare Weak would preserve the allocation after its charge could retire.
    // Release it on positive shutdown even if this diagnostic slot survives.
    identity: Mutex<Option<Arc<dyn Send + Sync>>>,
}
#[derive(Clone)]
struct ChargedSlot {
    state: Arc<FailureState>,
    _charge: Arc<dyn Send + Sync>,
}

/// Construct this owner before dispatching any application work. Callers must
/// serialize apply execution and recheck their failed fence after acquiring
/// that serialization guard, so a queued operation cannot produce a second
/// independent failure after the first has stopped the owner.
///
/// This slot deliberately retains only the first failure. A repeated `retain`
/// returns the supplied error intact; treating that rejection as success or
/// discarding its error could lose independently retained resource custody.
#[derive(Clone)]
pub(crate) struct ApplyFailureSlot(ChargedSlot);

impl ApplyFailureSlot {
    /// Additional heap envelope to admit before `new`, including Arc counters
    /// and alignment. The parent separately accounts for its inline handles.
    /// Original errors and panic payloads arrive already owned; this allowance
    /// does not admit arbitrary allocations made by the backend creating them.
    pub(crate) fn required_bytes() -> u64 {
        (std::mem::size_of::<FailureState>()
            + std::mem::size_of::<[usize; 2]>()
            + std::mem::align_of::<FailureState>()
            - 1) as u64
    }

    /// `charge` already covers `required_bytes`. Every diagnostic clone keeps
    /// that same charge alive, including after the lifecycle owner is dropped.
    pub(crate) fn new(charge: Arc<dyn Send + Sync>) -> Self {
        Self(ChargedSlot {
            state: Arc::new(FailureState {
                error: OnceLock::new(),
                completion: CompletionState::new(),
                ownership: OnceLock::new(),
            }),
            _charge: charge,
        })
    }

    pub(crate) fn bind_ownership(
        &self,
        ownership: Arc<AtomicBool>,
        identity: Arc<dyn Send + Sync>,
    ) -> anyhow::Result<()> {
        let bound = BoundOwnership {
            live: ownership,
            identity: Mutex::new(Some(identity)),
        };
        if let Err(bound) = self.0.state.ownership.set(bound) {
            let existing = self.0.state.ownership.get().expect("bound ownership");
            let existing_identity = existing.identity.lock().unwrap_or_else(|p| p.into_inner());
            let identity = bound
                .identity
                .into_inner()
                .unwrap_or_else(|p| p.into_inner());
            anyhow::ensure!(
                Arc::ptr_eq(&existing.live, &bound.live)
                    && existing_identity
                        .as_ref()
                        .zip(identity.as_ref())
                        .is_some_and(|(existing, identity)| Arc::ptr_eq(existing, identity)),
                "apply failure owner already bound to another group"
            );
        }
        Ok(())
    }

    pub(crate) fn has_live_ownership(&self) -> bool {
        self.0
            .state
            .ownership
            .get()
            .is_some_and(|ownership| ownership.live.load(Ordering::Acquire))
    }

    pub(crate) fn release_ownership(&self) {
        if let Some(ownership) = self.0.state.ownership.get() {
            ownership.live.store(false, Ordering::Release);
            let identity = ownership
                .identity
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take();
            // Never drop a physical owner while holding the identity mutex.
            drop(identity);
        }
    }

    /// Moving an existing error into the slot and cloning its diagnostic do
    /// not allocate. An occupied slot returns the exact supplied error without
    /// replacing, formatting, or dropping either failure.
    pub(crate) fn completion(&self) -> &CompletionState {
        &self.0.state.completion
    }
    pub(crate) fn diagnostic(&self) -> RetainedApplyFailure {
        RetainedApplyFailure(self.0.clone())
    }
    pub(crate) fn retain(
        &self,
        error: anyhow::Error,
    ) -> Result<RetainedApplyFailure, anyhow::Error> {
        self.0.state.error.set(error)?;
        Ok(RetainedApplyFailure(self.0.clone()))
    }

    pub(crate) fn failure_ownership_drained(&self) -> bool {
        self.0.state.error.get().is_none() && self.0.state.completion.failure_ownership_drained()
    }

    /// A stable diagnostic of the first failure, with no ownership transfer or
    /// new allocation. Call again after storage drain to observe late workers.
    pub(crate) fn failure(&self) -> Option<RetainedApplyFailure> {
        (self.0.state.error.get().is_some() || self.0.state.completion.failed())
            .then(|| RetainedApplyFailure(self.0.clone()))
    }
}

/// This diagnostic owns only the independent slot and its charge. It must not
/// point back to the lifecycle owner whose drain report can retain it.
#[derive(Clone)]
pub(crate) struct RetainedApplyFailure(ChargedSlot);

impl RetainedApplyFailure {
    pub(crate) fn try_with_report<R>(
        &self,
        inspect: impl for<'a> FnOnce(RetainedApplyReport<'a>) -> R,
    ) -> Result<R, ReportBusy> {
        if self.0.state.completion.failed() {
            self.0
                .state
                .completion
                .try_with_report(self.0.state.error.get(), inspect)
        } else {
            Ok(inspect(RetainedApplyReport::Single(
                self.0.state.error.get().expect("single retained failure"),
            )))
        }
    }
}

impl fmt::Debug for RetainedApplyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedApplyFailure { original: retained }")
    }
}

impl fmt::Display for RetainedApplyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Raft apply failed; original failure retained")
    }
}

impl std::error::Error for RetainedApplyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if self.0.state.completion.failed() {
            None
        } else {
            self.0.state.error.get().map(|error| error.as_ref())
        }
    }
}

/// The exact unwind payload can be Send without being Sync. Its mutex permits
/// custody inside an anyhow error without interpreting or copying the payload.
/// Catch backend execution with ApplyPublication outside the unwind catcher,
/// then pass this error to its `finish` along with any retained callback error.
pub(crate) struct ApplyBackendPanic {
    _payload: Mutex<Box<dyn Any + Send>>,
}

impl ApplyBackendPanic {
    pub(crate) fn new(payload: Box<dyn Any + Send>) -> Self {
        Self {
            _payload: Mutex::new(payload),
        }
    }

    /// Inspection cannot move the payload out of retained custody. A panicking
    /// inspector does not prevent a later report from borrowing the same value.
    #[cfg(test)]
    pub(crate) fn with_payload<R>(&self, inspect: impl FnOnce(&(dyn Any + Send)) -> R) -> R {
        let payload = self._payload.lock().unwrap_or_else(|p| p.into_inner());
        inspect(payload.as_ref())
    }
}

impl fmt::Debug for ApplyBackendPanic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApplyBackendPanic { payload: retained }")
    }
}

impl fmt::Display for ApplyBackendPanic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Raft application backend panicked; original payload retained")
    }
}

impl std::error::Error for ApplyBackendPanic {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::Cell,
        error::Error,
        panic::{AssertUnwindSafe, catch_unwind, panic_any},
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct OriginalFailure {
        value: usize,
        drops: Arc<AtomicUsize>,
    }

    impl fmt::Display for OriginalFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "original failure {}", self.value)
        }
    }

    impl Error for OriginalFailure {}

    impl Drop for OriginalFailure {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn original(value: usize, drops: &Arc<AtomicUsize>) -> anyhow::Error {
        OriginalFailure {
            value,
            drops: drops.clone(),
        }
        .into()
    }

    #[test]
    fn first_failure_is_stable_and_rejection_returns_the_exact_second_owner() {
        let first_drops = Arc::new(AtomicUsize::new(0));
        let second_drops = Arc::new(AtomicUsize::new(0));
        let slot = ApplyFailureSlot::new(Arc::new(()));
        assert!(slot.failure().is_none());
        let first = original(17, &first_drops);
        let first_address = first.downcast_ref::<OriginalFailure>().unwrap() as *const _;
        let retained = slot.retain(first).unwrap();
        let second = original(29, &second_drops);
        let second_address = second.downcast_ref::<OriginalFailure>().unwrap() as *const _;
        let rejected = slot.retain(second).unwrap_err();
        assert_eq!(
            rejected.downcast_ref::<OriginalFailure>().unwrap() as *const _,
            second_address
        );
        assert_eq!(first_drops.load(Ordering::SeqCst), 0);
        assert_eq!(second_drops.load(Ordering::SeqCst), 0);
        let repeated = slot.failure().unwrap();
        retained
            .try_with_report(|report| {
                let RetainedApplyReport::Single(first) = report else {
                    panic!("single failure")
                };
                repeated
                    .try_with_report(|report| {
                        let RetainedApplyReport::Single(second) = report else {
                            panic!("single failure")
                        };
                        assert!(std::ptr::eq(first, second));
                        assert_eq!(
                            second.downcast_ref::<OriginalFailure>().unwrap() as *const _,
                            first_address
                        );
                    })
                    .unwrap();
            })
            .unwrap();
        drop(rejected);
        assert_eq!(second_drops.load(Ordering::SeqCst), 1);
        drop(slot);
        drop(retained);
        assert_eq!(first_drops.load(Ordering::SeqCst), 0);
        drop(repeated);
        assert_eq!(first_drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn source_and_downcast_preserve_original_contexts_after_parent_drop() {
        let drops = Arc::new(AtomicUsize::new(0));
        let slot = ApplyFailureSlot::new(Arc::new(()));
        let retained = slot
            .retain(original(41, &drops).context("publication context"))
            .unwrap();
        drop(slot);
        retained
            .try_with_report(|report| {
                let RetainedApplyReport::Single(original) = report else {
                    panic!("single failure")
                };
                assert_eq!(
                    original.downcast_ref::<OriginalFailure>().unwrap().value,
                    41
                );
                assert!(
                    original
                        .chain()
                        .any(|error| error.downcast_ref::<OriginalFailure>().is_some())
                );
            })
            .unwrap();
        assert_eq!(
            retained.source().unwrap().to_string(),
            "publication context"
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(retained);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    struct Charge {
        payload_drops: Arc<AtomicUsize>,
        charge_drops: Arc<AtomicUsize>,
        wrong_order: Arc<AtomicBool>,
    }

    impl Drop for Charge {
        fn drop(&mut self) {
            if self.payload_drops.load(Ordering::SeqCst) != 1 {
                self.wrong_order.store(true, Ordering::SeqCst);
            }
            self.charge_drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn final_diagnostic_on_another_thread_drops_error_before_charge() {
        let payload_drops = Arc::new(AtomicUsize::new(0));
        let charge_drops = Arc::new(AtomicUsize::new(0));
        let wrong_order = Arc::new(AtomicBool::new(false));
        let slot = ApplyFailureSlot::new(Arc::new(Charge {
            payload_drops: payload_drops.clone(),
            charge_drops: charge_drops.clone(),
            wrong_order: wrong_order.clone(),
        }));
        let retained = slot.retain(original(53, &payload_drops)).unwrap();
        let final_copy = retained.clone();
        drop(slot);
        drop(retained);
        assert_eq!(payload_drops.load(Ordering::SeqCst), 0);
        assert_eq!(charge_drops.load(Ordering::SeqCst), 0);
        std::thread::spawn(move || drop(final_copy)).join().unwrap();
        assert_eq!(payload_drops.load(Ordering::SeqCst), 1);
        assert_eq!(charge_drops.load(Ordering::SeqCst), 1);
        assert!(!wrong_order.load(Ordering::SeqCst));
    }

    struct OpaquePanic {
        value: Cell<usize>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for OpaquePanic {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct BothFailures {
        callback: anyhow::Error,
        backend: ApplyBackendPanic,
    }

    impl fmt::Display for BothFailures {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("callback and backend failures retained")
        }
    }

    impl Error for BothFailures {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self.callback.as_ref())
        }
    }

    #[test]
    fn callback_and_non_sync_panic_survive_parent_drop_and_borrowed_inspection() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<ApplyBackendPanic>();
        send_sync::<RetainedApplyFailure>();
        let callback_drops = Arc::new(AtomicUsize::new(0));
        let panic_drops = Arc::new(AtomicUsize::new(0));
        let payload_drops = panic_drops.clone();
        let payload = catch_unwind(move || {
            panic_any(OpaquePanic {
                value: Cell::new(67),
                drops: payload_drops,
            });
        })
        .unwrap_err();
        let slot = ApplyFailureSlot::new(Arc::new(()));
        let retained = slot
            .retain(
                BothFailures {
                    callback: original(71, &callback_drops),
                    backend: ApplyBackendPanic::new(payload),
                }
                .into(),
            )
            .unwrap();
        let clone = retained.clone();
        drop(slot);
        drop(retained);
        clone
            .try_with_report(|report| {
                let RetainedApplyReport::Single(original) = report else {
                    panic!("single failure")
                };
                let failures = original.downcast_ref::<BothFailures>().unwrap();
                assert_eq!(
                    failures
                        .callback
                        .downcast_ref::<OriginalFailure>()
                        .unwrap()
                        .value,
                    71
                );
                failures.backend.with_payload(|payload| {
                    let original = payload.downcast_ref::<OpaquePanic>().unwrap();
                    assert_eq!(original.value.replace(73), 67);
                });
                assert!(
                    catch_unwind(AssertUnwindSafe(|| {
                        failures
                            .backend
                            .with_payload::<()>(|_| panic!("inspection interrupted"));
                    }))
                    .is_err()
                );
                failures.backend.with_payload(|payload| {
                    assert_eq!(
                        payload.downcast_ref::<OpaquePanic>().unwrap().value.get(),
                        73
                    );
                });
                assert_eq!(callback_drops.load(Ordering::SeqCst), 0);
                assert_eq!(panic_drops.load(Ordering::SeqCst), 0);
            })
            .unwrap();
        drop(clone);
        assert_eq!(callback_drops.load(Ordering::SeqCst), 1);
        assert_eq!(panic_drops.load(Ordering::SeqCst), 1);
    }

    #[derive(Debug)]
    struct Unformattable;

    impl fmt::Display for Unformattable {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("diagnostics must not format the original failure")
        }
    }

    impl Error for Unformattable {}

    #[test]
    fn diagnostics_are_static_and_do_not_format_original_payloads() {
        let slot = ApplyFailureSlot::new(Arc::new(()));
        let retained = slot.retain(Unformattable.into()).unwrap();
        assert_eq!(
            retained.to_string(),
            "Raft apply failed; original failure retained"
        );
        assert_eq!(
            format!("{retained:?}"),
            "RetainedApplyFailure { original: retained }"
        );
        let panic = ApplyBackendPanic::new(Box::new(Cell::new(79)));
        assert_eq!(
            panic.to_string(),
            "Raft application backend panicked; original payload retained"
        );
        assert_eq!(
            format!("{panic:?}"),
            "ApplyBackendPanic { payload: retained }"
        );
    }

    #[test]
    fn retained_diagnostic_keeps_exact_group_fence_after_facade_and_slot_drop() {
        let slot = ApplyFailureSlot::new(Arc::new(()));
        let ownership = Arc::new(AtomicBool::new(true));
        let weak = Arc::downgrade(&ownership);
        let identity_drops = Arc::new(AtomicUsize::new(0));
        let identity = Arc::new(OriginalFailure {
            value: 101,
            drops: identity_drops.clone(),
        });
        let weak_identity = Arc::downgrade(&identity);
        slot.bind_ownership(ownership.clone(), identity.clone())
            .unwrap();
        slot.bind_ownership(ownership.clone(), identity.clone())
            .unwrap();
        assert!(
            slot.bind_ownership(Arc::new(AtomicBool::new(true)), identity.clone())
                .is_err()
        );
        assert!(
            slot.bind_ownership(ownership.clone(), Arc::new(()))
                .is_err()
        );
        let diagnostic = slot.retain(anyhow::anyhow!("retained child")).unwrap();
        drop(ownership);
        drop(identity);
        drop(slot);
        assert!(weak.upgrade().unwrap().load(Ordering::Acquire));
        assert_eq!(weak_identity.upgrade().unwrap().value, 101);
        assert_eq!(identity_drops.load(Ordering::SeqCst), 0);
        std::thread::spawn(move || drop(diagnostic)).join().unwrap();
        assert!(weak.upgrade().is_none());
        assert!(weak_identity.upgrade().is_none());
        assert_eq!(identity_drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn positive_shutdown_releases_bound_group_fence() {
        let identity_drops = Arc::new(AtomicUsize::new(0));
        let charge_drops = Arc::new(AtomicUsize::new(0));
        let wrong_order = Arc::new(AtomicBool::new(false));
        let slot = ApplyFailureSlot::new(Arc::new(Charge {
            payload_drops: identity_drops.clone(),
            charge_drops: charge_drops.clone(),
            wrong_order: wrong_order.clone(),
        }));
        let ownership = Arc::new(AtomicBool::new(true));
        let identity = Arc::new(OriginalFailure {
            value: 103,
            drops: identity_drops.clone(),
        });
        let weak_identity = Arc::downgrade(&identity);
        slot.bind_ownership(ownership.clone(), identity).unwrap();
        assert!(weak_identity.upgrade().is_some());
        slot.release_ownership();
        assert!(!ownership.load(Ordering::Acquire));
        assert!(weak_identity.upgrade().is_none());
        assert_eq!(identity_drops.load(Ordering::SeqCst), 1);
        assert_eq!(charge_drops.load(Ordering::SeqCst), 0);
        slot.release_ownership();
        drop(slot);
        assert_eq!(charge_drops.load(Ordering::SeqCst), 1);
        assert!(!wrong_order.load(Ordering::SeqCst));
    }

    #[test]
    fn admission_envelope_includes_fixed_slot_and_arc_header() {
        let minimum = std::mem::size_of::<FailureState>() + std::mem::size_of::<[usize; 2]>();
        let envelope = usize::try_from(ApplyFailureSlot::required_bytes()).unwrap();
        assert!(envelope >= minimum);
        assert!(envelope - minimum < std::mem::align_of::<FailureState>());
    }
}
