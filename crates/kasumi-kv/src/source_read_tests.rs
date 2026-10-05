//! Direct real Database tests for retained native source assets, not Store
//! activation or source-byte availability. Reuse the actual allocator/ledger.
use super::*;
use crate::{
    SourceHistorySettlement, SourceReadCallError, SourceReadSettlement,
    SourceRightsNativeRetirement, SourceRightsSettlement, TerminalObservation,
};

fn rights(opening: &RetainedDatabaseOpening) -> crate::SourceReadRights {
    let mut rights = opening.database().unwrap().queue_source_read_rights();
    assert_eq!(
        rights
            .prepare(opening.retained_database().unwrap())
            .unwrap()
            .settlement(),
        SourceRightsSettlement::Ready
    );
    rights
}
fn prepared(
    opening: &RetainedDatabaseOpening,
    rights: &crate::SourceReadRights,
) -> crate::RetainedSourceRead {
    let mut request = opening.database().unwrap().queue_source_read();
    assert_eq!(
        request
            .prepare(opening.retained_database().unwrap(), rights)
            .unwrap()
            .settlement(),
        SourceReadSettlement::Prepared
    );
    request
}
fn dispose_request(opening: &RetainedDatabaseOpening, request: &mut crate::RetainedSourceRead) {
    let owner = opening.retained_database().unwrap();
    assert_eq!(
        request.cancel(owner).unwrap().settlement(),
        SourceReadSettlement::Cancelled
    );
    assert_eq!(
        request.dispose_settled(owner).unwrap().settlement(),
        SourceReadSettlement::Disposed
    );
}
fn retire_rights(opening: &RetainedDatabaseOpening, rights: &mut crate::SourceReadRights) {
    assert_eq!(
        rights
            .retire(opening.retained_database().unwrap())
            .unwrap()
            .settlement(),
        SourceRightsSettlement::Disposed
    );
}
fn original_address(report: crate::SourceReadReport<'_>) -> usize {
    let TerminalObservation::Returned(Err(error)) = report.preparation() else {
        panic!("original preparation failure absent");
    };
    error as *const _ as usize
}
fn finish_failed(mut opening: RetainedDatabaseOpening, admission: &CountedAdmission) {
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::DrainedWithFailure
    );
    assert_eq!(
        opening.dispose().settlement(),
        DatabaseOpenSettlement::FailedDisposed
    );
    drop(opening);
    assert_eq!(admission.census(), (0, 0));
}

type Probe = Box<dyn Fn() -> bool + Send + Sync>;
struct Hooks {
    probe: Mutex<Option<Probe>>,
    checks: AtomicUsize,
    fail_check: AtomicUsize,
    panic_check: AtomicUsize,
    retirements: AtomicUsize,
}
impl Hooks {
    fn probe(&self) {
        if let Some(probe) = self.probe.lock().unwrap().as_ref() {
            assert!(
                probe(),
                "provider callback held Core or native registry gate"
            );
        }
    }
}
struct HookAdmission {
    inner: Arc<CountedAdmission>,
    hooks: Arc<Hooks>,
}
struct HookLease {
    inner: Option<Box<dyn ResidentLease>>,
    hooks: Arc<Hooks>,
}
impl Drop for HookLease {
    fn drop(&mut self) {
        self.hooks.probe();
        self.hooks.retirements.fetch_add(1, Ordering::AcqRel);
        self.inner.take().unwrap().retire();
    }
}
impl HookAdmission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: CountedAdmission::new(),
            hooks: Arc::new(Hooks {
                probe: Mutex::new(None),
                checks: AtomicUsize::new(0),
                fail_check: AtomicUsize::new(0),
                panic_check: AtomicUsize::new(0),
                retirements: AtomicUsize::new(0),
            }),
        })
    }
}
impl StorageAdmission for HookAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.hooks.probe();
        let count = self.hooks.checks.fetch_add(1, Ordering::AcqRel) + 1;
        if self.hooks.panic_check.load(Ordering::Acquire) == count {
            std::panic::panic_any(0xcafef00d_u64);
        }
        if self.hooks.fail_check.load(Ordering::Acquire) == count {
            return Err(OwnerFailed);
        }
        self.inner.check_owner()
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.hooks.probe();
        let inner = self.inner.reserve_workspace(bytes)?;
        Ok(Box::new(HookLease {
            inner: Some(inner),
            hooks: self.hooks.clone(),
        }))
    }
    fn quote_cache_memory(&self, bytes: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(current, requested)
    }
    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(actual)
    }
    fn owner_failed(&self) {
        self.hooks.probe();
        self.inner.owner_failed();
    }
}
impl crate::cache_test::Provider for HookAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), AdmissionError> {
        self.inner.acquire_cache(bytes, first)
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        self.inner.release_cache(bytes, last);
    }
}
fn hooked_opening(admission: &Arc<HookAdmission>) -> RetainedDatabaseOpening {
    let mut opening = Database::builder(admission.clone(), [73; 16], CacheConfig::default())
        .retain_backend(Box::new(InMemoryGroup::new()), DatabaseOpenMode::Create);
    assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
    let writer = opening.database().unwrap().begin_write().unwrap();
    writer
        .open_table(ROWS)
        .unwrap()
        .insert(b"a".as_slice(), b"old-a".as_slice())
        .unwrap();
    writer.commit().unwrap();
    opening
}

#[test]
fn source_preparation_captures_actual_later_commit_without_new_admission_or_allocation() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let database = opening.database().unwrap();
    let old = database.begin_read().unwrap();
    let before = database.inner.core.source_snapshots_for_test();
    let mut rights = rights(&opening);
    let mut request = prepared(&opening, &rights);
    assert_eq!(database.inner.core.source_snapshots_for_test(), before);
    let backing = request.backing_address_for_test();
    assert_ne!(backing, 0);
    let writer = database.begin_write().unwrap();
    writer
        .open_table(ROWS)
        .unwrap()
        .insert(b"a".as_slice(), b"new-a".as_slice())
        .unwrap();
    writer.commit().unwrap();
    let full = admission.census();
    let grants = admission.last_grant();
    admission.limits(full.0, full.1);
    let counting = AllocationCount::start();
    assert_eq!(
        request
            .capture(opening.retained_database().unwrap())
            .unwrap()
            .settlement(),
        SourceReadSettlement::Ready
    );
    let mut selected = request
        .take_ready(opening.retained_database().unwrap())
        .unwrap();
    assert_eq!(counting.count(), 0);
    drop(counting);
    assert_eq!(admission.last_grant(), grants);
    assert_eq!(admission.census(), full);
    assert_eq!(database.inner.core.source_snapshots_for_test(), before + 1);
    admission.limits(BYTE_LIMIT, SLOT_LIMIT);
    assert_eq!(
        selected
            .get_bytes(ROWS, b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"new-a"
    );
    assert_eq!(
        old.get_bytes(ROWS.name(), b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old-a"
    );
    close_reader(&opening, &mut selected);
    drop(old);
    retire_rights(&opening, &mut rights);
    finish(opening, &admission);
}

#[test]
fn source_actual_backing_and_pin_refusals_retain_original_until_explicit_clean_disposal() {
    for allowed in [0, 1] {
        let admission = CountedAdmission::new();
        let opening = opening(&admission);
        let mut rights = rights(&opening);
        let baseline = admission.census();
        let mut request = opening.database().unwrap().queue_source_read();
        admission.limits(BYTE_LIMIT, baseline.1 + allowed);
        request
            .prepare(opening.retained_database().unwrap(), &rights)
            .unwrap();
        assert!(
            matches!(&(request.report().preparation()), TerminalObservation::Returned(Err(StorageError::Core(native_error))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        );
        let original = original_address(request.report());
        assert!(!request.report().is_clean_capacity_refusal());
        assert_eq!(admission.census().1, baseline.1 + allowed);
        dispose_request(&opening, &mut request);
        assert!(request.report().is_clean_capacity_refusal());
        assert_eq!(original_address(request.report()), original);
        assert_eq!(admission.census(), baseline);
        assert!(!admission.failed.load(Ordering::Acquire));
        admission.limits(BYTE_LIMIT, SLOT_LIMIT);
        let mut retry = prepared(&opening, &rights);
        dispose_request(&opening, &mut retry);
        retire_rights(&opening, &mut rights);
        finish(opening, &admission);
    }
}

#[test]
fn source_foreign_database_and_rights_with_same_group_do_not_consume_original_ticket() {
    let a = CountedAdmission::new();
    let b = CountedAdmission::new();
    let first = opening(&a);
    let second = opening(&b);
    let mut ar = rights(&first);
    let mut br = rights(&second);
    let mut request = first.database().unwrap().queue_source_read();
    assert!(matches!(
        request.prepare(second.retained_database().unwrap(), &ar),
        Err(SourceReadCallError::ForeignDatabase)
    ));
    assert!(matches!(
        request.prepare(first.retained_database().unwrap(), &br),
        Err(SourceReadCallError::ForeignRights)
    ));
    request
        .prepare(first.retained_database().unwrap(), &ar)
        .unwrap();
    let before = a.census();
    assert!(matches!(
        request.capture(second.retained_database().unwrap()),
        Err(SourceReadCallError::ForeignDatabase)
    ));
    assert!(matches!(
        request.cancel(second.retained_database().unwrap()),
        Err(SourceReadCallError::ForeignDatabase)
    ));
    assert!(request.report().retains_pending_ticket());
    assert_eq!(a.census(), before);
    dispose_request(&first, &mut request);
    retire_rights(&first, &mut ar);
    retire_rights(&second, &mut br);
    finish(first, &a);
    finish(second, &b);
}

#[test]
fn source_closing_ready_reader_cannot_later_be_taken_as_open() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let mut rights = rights(&opening);
    let mut request = prepared(&opening, &rights);
    let owner = opening.retained_database().unwrap();
    request.capture(owner).unwrap();
    request.close_captured(owner).unwrap();
    assert!(matches!(
        request.take_ready(owner),
        Err(SourceReadCallError::WrongPhase)
    ));
    assert_eq!(
        request.report().reader_close().unwrap().settlement(),
        ReadCloseSettlement::Settled
    );
    assert_eq!(
        request.dispose_settled(owner).unwrap().settlement(),
        SourceReadSettlement::Disposed
    );
    retire_rights(&opening, &mut rights);
    finish(opening, &admission);
}

#[test]
fn source_idle_rights_and_queued_prepared_owners_block_actual_database_close() {
    for mode in 0..3 {
        let admission = CountedAdmission::new();
        let mut opening = opening(&admission);
        let mut rights = rights(&opening);
        let mut request = (mode != 0).then(|| opening.database().unwrap().queue_source_read());
        if mode == 2 {
            request
                .as_mut()
                .unwrap()
                .prepare(opening.retained_database().unwrap(), &rights)
                .unwrap();
        }
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::WaitingForTransactions
        );
        retire_rights(&opening, &mut rights);
        assert_eq!(
            rights.report().native_retirement(),
            if mode == 2 {
                SourceRightsNativeRetirement::OtherHoldersRetainLanes
            } else {
                SourceRightsNativeRetirement::LanesRetired
            }
        );
        if let Some(request) = request.as_mut() {
            assert_eq!(
                opening.close().settlement(),
                DatabaseOpenSettlement::WaitingForTransactions
            );
            dispose_request(&opening, request);
        }
        assert!(!rights.report().retains_database());
        finish(opening, &admission);
    }
}

#[test]
fn source_repeated_and_conflicting_transitions_never_reenter_or_transfer_twice() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let mut rights = rights(&opening);
    let mut request = prepared(&opening, &rights);
    let owner = opening.retained_database().unwrap();
    let before = admission.census();
    rights.prepare(owner).unwrap();
    request.prepare(owner, &rights).unwrap();
    assert_eq!(admission.census(), before);
    request.cancel(owner).unwrap();
    request.cancel(owner).unwrap();
    assert!(matches!(
        request.capture(owner),
        Err(SourceReadCallError::WrongPhase)
    ));
    assert!(matches!(
        request.prepare(owner, &rights),
        Err(SourceReadCallError::WrongPhase)
    ));
    request.dispose_settled(owner).unwrap();
    assert_eq!(
        request.dispose_settled(owner).unwrap().settlement(),
        SourceReadSettlement::Disposed
    );

    let mut next = prepared(&opening, &rights);
    next.capture(owner).unwrap();
    let after = admission.census();
    next.capture(owner).unwrap();
    assert_eq!(admission.census(), after);
    let mut reader = next.take_ready(owner).unwrap();
    assert!(matches!(
        next.take_ready(owner),
        Err(SourceReadCallError::WrongPhase)
    ));
    assert!(matches!(
        next.close_captured(owner),
        Err(SourceReadCallError::WrongPhase)
    ));
    close_reader(&opening, &mut reader);
    retire_rights(&opening, &mut rights);
    assert_eq!(
        rights.retire(owner).unwrap().settlement(),
        SourceRightsSettlement::Disposed
    );
    finish(opening, &admission);
}

#[test]
fn source_rights_positive_lane_retirement_survives_lease_disposal_panic_as_separate_observation() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let mut rights = rights(&opening);
    let grant = admission.last_grant();
    ledger_lock(&admission.state).panic_on_drop = Some(grant);
    let report = rights.retire(opening.retained_database().unwrap()).unwrap();
    assert_eq!(
        report.native_retirement(),
        SourceRightsNativeRetirement::LanesRetired
    );
    assert_eq!(
        report.settlement(),
        SourceRightsSettlement::DisposalUncertain
    );
    assert!(matches!(
        report.retirement(),
        TerminalObservation::Returned(Ok(()))
    ));
    let TerminalObservation::Panicked(payload) = report.disposal() else {
        panic!("rights disposal panic absent");
    };
    assert_eq!(payload.downcast_ref::<u64>(), Some(&0x51ee));
    assert!(report.retains_database());
    assert_eq!(
        rights
            .retire(opening.retained_database().unwrap())
            .unwrap()
            .settlement(),
        SourceRightsSettlement::DisposalUncertain
    );
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    drop(rights);
    finish_failed(opening, &admission);
}

#[test]
fn source_prepared_backing_system_deallocation_precedes_its_actual_refund() {
    let _serial = WATCH_LOCK.lock().unwrap();
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let mut rights = rights(&opening);
    let grant = admission.last_grant() + 1;
    let mut request = prepared(&opening, &rights);
    BACKING_FREED.store(false, Ordering::Release);
    WATCH_REFUNDS.store(0, Ordering::Release);
    WATCH_GRANT.store(grant, Ordering::Release);
    WATCH_LEDGER.store(Arc::as_ptr(&admission.state) as usize, Ordering::Release);
    WATCH_BACKING.store(request.backing_address_for_test(), Ordering::Release);
    let watch = BackingWatch;
    request
        .cancel(opening.retained_database().unwrap())
        .unwrap();
    assert!(
        !BACKING_FREED.load(Ordering::Acquire),
        "cancel only settled the native ticket"
    );
    request
        .dispose_settled(opening.retained_database().unwrap())
        .unwrap();
    assert!(BACKING_FREED.load(Ordering::Acquire));
    assert_eq!(WATCH_REFUNDS.load(Ordering::Acquire), 1);
    drop(watch);
    retire_rights(&opening, &mut rights);
    finish(opening, &admission);
}

#[test]
fn source_preparation_error_survives_cleanup_panic_and_keeps_close_alias() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let mut rights = rights(&opening);
    let baseline = admission.census();
    admission.limits(BYTE_LIMIT, baseline.1 + 1); // actual backing succeeds, pin refuses
    let backing_grant = admission.last_grant() + 1;
    let mut request = opening.database().unwrap().queue_source_read();
    request
        .prepare(opening.retained_database().unwrap(), &rights)
        .unwrap();
    let original = original_address(request.report());
    ledger_lock(&admission.state).panic_on_drop = Some(backing_grant);
    request
        .cancel(opening.retained_database().unwrap())
        .unwrap();
    assert_eq!(
        request
            .dispose_settled(opening.retained_database().unwrap())
            .unwrap()
            .settlement(),
        SourceReadSettlement::DisposalUncertain
    );
    assert_eq!(original_address(request.report()), original);
    let report = request.report();
    let TerminalObservation::Panicked(payload) = report.disposal() else {
        panic!("cleanup panic absent");
    };
    assert_eq!(payload.downcast_ref::<u64>(), Some(&0x51ee));
    assert!(report.retains_database());
    assert!(!report.is_clean_capacity_refusal());
    assert_eq!(
        request
            .dispose_settled(opening.retained_database().unwrap())
            .unwrap()
            .settlement(),
        SourceReadSettlement::DisposalUncertain
    );
    retire_rights(&opening, &mut rights);
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    // Test teardown drops the uncertain diagnostic; no clean disposition is minted.
    drop(request);
    finish_failed(opening, &admission);
}

#[test]
fn source_unknown_ticket_cancellation_and_rights_retirement_never_acknowledge_drop() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let mut rights = rights(&opening);
    let mut request = prepared(&opening, &rights);
    let before = admission.census();
    request.mismatch_ticket_for_test();
    assert_eq!(
        request
            .cancel(opening.retained_database().unwrap())
            .unwrap()
            .settlement(),
        SourceReadSettlement::Retained
    );
    assert!(request.report().retains_pending_ticket());
    assert!(request.report().retains_database());
    assert!(matches!(
        request.dispose_settled(opening.retained_database().unwrap()),
        Err(SourceReadCallError::WrongPhase)
    ));
    assert_eq!(admission.census(), before);
    drop(request); // best effort Drop cannot settle the mismatched registry entry
    let report = rights.retire(opening.retained_database().unwrap()).unwrap();
    assert_eq!(report.settlement(), SourceRightsSettlement::Retained);
    assert!(
        matches!(&(report.retirement()), TerminalObservation::Returned(Err(StorageError::Core(native_error))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    assert!(report.retains_database());
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    drop(rights);
    finish_failed(opening, &admission);
}

#[test]
fn source_final_rights_mismatch_or_poison_retains_payload_and_database_after_arc_retirement() {
    for poison in [false, true] {
        let admission = CountedAdmission::new();
        let mut opening = opening(&admission);
        let mut rights = rights(&opening);
        let before = admission.census();
        rights.corrupt_retirement_for_test(poison);
        let report = rights.retire(opening.retained_database().unwrap()).unwrap();
        assert_eq!(report.settlement(), SourceRightsSettlement::Retained);
        assert!(
            matches!(&(report.retirement()), TerminalObservation::Returned(Err(StorageError::Core(native_error))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
        );
        assert!(matches!(report.disposal(), TerminalObservation::NotEntered));
        assert!(report.retains_database());
        assert_eq!(admission.census(), before);
        assert_eq!(
            rights
                .retire(opening.retained_database().unwrap())
                .unwrap()
                .settlement(),
            SourceRightsSettlement::Retained
        );
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::WaitingForTransactions
        );
        drop(rights);
        finish_failed(opening, &admission);
    }
}

#[test]
fn source_protected_capture_survives_full_ordinary_registry_and_history_reuses_moved_lane() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    admission.limits(BYTE_LIMIT, 1024);
    let mut rights = rights(&opening);
    let mut request = prepared(&opening, &rights);
    let database = opening.database().unwrap();
    let owner = opening.retained_database().unwrap();
    let mut ordinary: Vec<_> = (0..254)
        .map(|_| database.begin_read_retained().unwrap())
        .collect();
    assert!(database.begin_read_retained().is_err());
    let grants = admission.last_grant();
    request.capture(owner).unwrap();
    let mut selected = request.take_ready(owner).unwrap();
    assert_eq!(admission.last_grant(), grants);
    let mut denied = selected.queue_source_history().unwrap();
    denied.prepare(owner).unwrap();
    assert!(
        matches!(&(denied.report().preparation()), TerminalObservation::Returned(Err(StorageError::Core(native_error))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    denied.cancel(owner).unwrap();
    denied.dispose_settled(owner).unwrap();
    close_reader(&opening, &mut ordinary.pop().unwrap());
    let mut history = selected.queue_source_history().unwrap();
    history.prepare(owner).unwrap();
    let counting = AllocationCount::start();
    assert!(history.commit(owner).unwrap().exchange_committed());
    assert_eq!(counting.count(), 0);
    drop(counting);
    assert!(history.commit(owner).unwrap().exchange_committed());
    history.dispose_settled(owner).unwrap();
    assert!(history.report().exchange_committed());
    let mut next = prepared(&opening, &rights);
    next.capture(owner).unwrap();
    let mut next_reader = next.take_ready(owner).unwrap();
    assert_eq!(
        selected
            .get_bytes(ROWS, b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old-a"
    );
    for reader in &mut ordinary {
        close_reader(&opening, reader);
    }
    close_reader(&opening, &mut selected);
    close_reader(&opening, &mut next_reader);
    retire_rights(&opening, &mut rights);
    finish(opening, &admission);
}

#[test]
fn source_history_owner_keeps_database_alive_after_original_reader_and_rights_facade_retire() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let mut rights = rights(&opening);
    let mut request = prepared(&opening, &rights);
    request
        .capture(opening.retained_database().unwrap())
        .unwrap();
    let mut reader = request
        .take_ready(opening.retained_database().unwrap())
        .unwrap();
    let mut history = reader.queue_source_history().unwrap();
    history
        .prepare(opening.retained_database().unwrap())
        .unwrap();
    close_reader(&opening, &mut reader);
    retire_rights(&opening, &mut rights);
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    history
        .cancel(opening.retained_database().unwrap())
        .unwrap();
    history
        .dispose_settled(opening.retained_database().unwrap())
        .unwrap();
    assert!(!history.report().retains_database());
    finish(opening, &admission);
}

#[test]
fn source_prepare_capture_cancel_and_disposal_callbacks_observe_unlocked_native_gates() {
    let admission = HookAdmission::new();
    let opening = hooked_opening(&admission);
    let mut rights = rights(&opening);
    *admission.hooks.probe.lock().unwrap() = Some(
        opening
            .database()
            .unwrap()
            .inner
            .core
            .source_probe_for_test(),
    );
    let initial_retirements = admission.hooks.retirements.load(Ordering::Acquire);
    let mut cancelled = prepared(&opening, &rights);
    dispose_request(&opening, &mut cancelled);
    let mut captured = prepared(&opening, &rights);
    captured
        .capture(opening.retained_database().unwrap())
        .unwrap();
    let mut reader = captured
        .take_ready(opening.retained_database().unwrap())
        .unwrap();
    let mut history = reader.queue_source_history().unwrap();
    history
        .prepare(opening.retained_database().unwrap())
        .unwrap();
    let checks = admission.hooks.checks.load(Ordering::Acquire);
    admission
        .hooks
        .panic_check
        .store(checks + 1, Ordering::Release);
    assert!(
        history
            .commit(opening.retained_database().unwrap())
            .unwrap()
            .exchange_committed()
    );
    assert_eq!(
        admission.hooks.checks.load(Ordering::Acquire),
        checks,
        "exchange invoked a provider"
    );
    admission.hooks.panic_check.store(0, Ordering::Release);
    history
        .dispose_settled(opening.retained_database().unwrap())
        .unwrap();
    close_reader(&opening, &mut reader);
    retire_rights(&opening, &mut rights);
    assert!(admission.hooks.retirements.load(Ordering::Acquire) > initial_retirements);
    admission.hooks.probe.lock().unwrap().take();
    finish(opening, &admission.inner);
}

#[test]
fn source_postcapture_error_and_panic_keep_actual_reader_and_original_observation() {
    for panic in [false, true] {
        let admission = HookAdmission::new();
        let opening = hooked_opening(&admission);
        let mut rights = rights(&opening);
        let mut request = prepared(&opening, &rights);
        let before = opening
            .database()
            .unwrap()
            .inner
            .core
            .source_snapshots_for_test();
        let target = admission.hooks.checks.load(Ordering::Acquire) + 2;
        if panic {
            admission.hooks.panic_check.store(target, Ordering::Release);
        } else {
            admission.hooks.fail_check.store(target, Ordering::Release);
        }
        request
            .capture(opening.retained_database().unwrap())
            .unwrap();
        assert_eq!(
            request.report().settlement(),
            SourceReadSettlement::Retained
        );
        assert_eq!(
            opening
                .database()
                .unwrap()
                .inner
                .core
                .source_snapshots_for_test(),
            before + 1
        );
        assert!(
            request
                .report()
                .reader_close()
                .unwrap()
                .retains_transaction()
        );
        assert!(matches!(
            request.take_ready(opening.retained_database().unwrap()),
            Err(SourceReadCallError::WrongPhase)
        ));
        let report = request.report();
        match report.capture() {
            TerminalObservation::Panicked(payload) if panic => {
                assert_eq!(payload.downcast_ref::<u64>(), Some(&0xcafef00d))
            }
            TerminalObservation::Returned(Err(StorageError::Core(original)))
                if !panic
                    && matches!(
                        original.rejected_cause(),
                        Some(crate::CoreErrorCause::OwnerFailed)
                    ) => {}
            _ => panic!("original postcapture observation changed"),
        }
        request
            .close_captured(opening.retained_database().unwrap())
            .unwrap();
        request
            .dispose_settled(opening.retained_database().unwrap())
            .unwrap();
        assert_eq!(
            request.report().settlement(),
            SourceReadSettlement::Disposed
        );
        retire_rights(&opening, &mut rights);
        finish_failed(opening, &admission.inner);
    }
}

#[test]
fn source_history_exchange_stays_committed_when_final_pin_disposal_panics() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let mut rights = rights(&opening);
    let mut request = prepared(&opening, &rights);
    let pin_grant = admission.last_grant();
    request
        .capture(opening.retained_database().unwrap())
        .unwrap();
    let mut reader = request
        .take_ready(opening.retained_database().unwrap())
        .unwrap();
    let mut history = reader.queue_source_history().unwrap();
    history
        .prepare(opening.retained_database().unwrap())
        .unwrap();
    assert!(
        history
            .commit(opening.retained_database().unwrap())
            .unwrap()
            .exchange_committed()
    );
    close_reader(&opening, &mut reader);
    ledger_lock(&admission.state).panic_on_drop = Some(pin_grant);
    let report = history
        .dispose_settled(opening.retained_database().unwrap())
        .unwrap();
    assert_eq!(
        report.settlement(),
        SourceHistorySettlement::DisposalUncertain
    );
    assert!(report.exchange_committed());
    assert!(report.retains_database());
    let TerminalObservation::Panicked(payload) = report.disposal() else {
        panic!("history disposal panic absent");
    };
    assert_eq!(payload.downcast_ref::<u64>(), Some(&0x51ee));
    assert!(
        history
            .dispose_settled(opening.retained_database().unwrap())
            .unwrap()
            .exchange_committed()
    );
    retire_rights(&opening, &mut rights);
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    drop(history);
    finish_failed(opening, &admission);
}

fn native_failure_address(observation: TerminalObservation<'_, StorageError>) -> usize {
    let TerminalObservation::Returned(Err(error @ StorageError::Core(_))) = observation else {
        panic!("original native retirement failure absent");
    };
    assert!(matches!(error, StorageError::Core(original)
        if matches!(original.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed))));
    error as *const _ as usize
}

#[test]
fn source_transferred_reader_and_fork_retain_final_native_mismatch_or_poison() {
    for fork in [false, true] {
        for poison in [false, true] {
            let admission = HookAdmission::new();
            let mut opening = hooked_opening(&admission);
            let mut rights = rights(&opening);
            let mut request = prepared(&opening, &rights);
            request
                .capture(opening.retained_database().unwrap())
                .unwrap();
            let mut reader = request
                .take_ready(opening.retained_database().unwrap())
                .unwrap();
            if fork {
                let next = reader.fork().unwrap();
                close_reader(&opening, &mut reader);
                reader = next;
            }
            retire_rights(&opening, &mut rights);
            assert_eq!(
                rights.report().native_retirement(),
                SourceRightsNativeRetirement::OtherHoldersRetainLanes
            );
            reader.corrupt_final_release_for_test(poison);
            let checks = admission.hooks.checks.load(Ordering::Acquire);
            let grants = admission.inner.last_grant();
            let owner = opening.retained_database().unwrap();
            reader.close(owner);
            let report = reader.dispose_settled(owner);
            assert_eq!(report.settlement(), ReadCloseSettlement::Retained);
            assert!(!report.retains_transaction());
            assert!(report.retains_database());
            assert!(matches!(
                report.disposal(),
                TerminalObservation::Returned(Ok(()))
            ));
            let original = native_failure_address(report.native_retirement());
            assert_eq!(
                admission.hooks.checks.load(Ordering::Acquire),
                checks,
                "local retirement called provider check_owner"
            );
            assert_eq!(admission.inner.last_grant(), grants);
            let report = reader.dispose_settled(owner);
            assert_eq!(native_failure_address(report.native_retirement()), original);
            assert_eq!(report.settlement(), ReadCloseSettlement::Retained);
            assert_eq!(
                opening.close().settlement(),
                DatabaseOpenSettlement::WaitingForTransactions
            );
            drop(reader); // test teardown; no clean native disposition is minted
            finish_failed(opening, &admission.inner);
        }
    }
}

#[test]
fn source_history_final_native_failure_preserves_committed_exchange_and_database() {
    for poison in [false, true] {
        let admission = CountedAdmission::new();
        let mut opening = opening(&admission);
        let mut rights = rights(&opening);
        let mut request = prepared(&opening, &rights);
        request
            .capture(opening.retained_database().unwrap())
            .unwrap();
        let mut reader = request
            .take_ready(opening.retained_database().unwrap())
            .unwrap();
        let mut history = reader.queue_source_history().unwrap();
        history
            .prepare(opening.retained_database().unwrap())
            .unwrap();
        history
            .commit(opening.retained_database().unwrap())
            .unwrap();
        retire_rights(&opening, &mut rights);
        close_reader(&opening, &mut reader);
        history.corrupt_final_release_for_test(poison);
        let report = history
            .dispose_settled(opening.retained_database().unwrap())
            .unwrap();
        assert_eq!(report.settlement(), SourceHistorySettlement::Retained);
        assert!(report.exchange_committed());
        assert!(report.retains_database());
        assert!(matches!(
            report.disposal(),
            TerminalObservation::Returned(Ok(()))
        ));
        let original = native_failure_address(report.native_retirement());
        let report = history
            .dispose_settled(opening.retained_database().unwrap())
            .unwrap();
        assert!(report.exchange_committed());
        assert_eq!(native_failure_address(report.native_retirement()), original);
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::WaitingForTransactions
        );
        drop(history);
        finish_failed(opening, &admission);
    }
}

#[test]
fn source_cancelled_and_captured_request_keep_final_native_failure_and_database() {
    for captured in [false, true] {
        for poison in [false, true] {
            let admission = CountedAdmission::new();
            let mut opening = opening(&admission);
            let mut rights = rights(&opening);
            let mut request = prepared(&opening, &rights);
            if captured {
                request
                    .capture(opening.retained_database().unwrap())
                    .unwrap();
                request
                    .close_captured(opening.retained_database().unwrap())
                    .unwrap();
            } else {
                request
                    .cancel(opening.retained_database().unwrap())
                    .unwrap();
            }
            retire_rights(&opening, &mut rights);
            request.corrupt_final_release_for_test(poison);
            let report = request
                .dispose_settled(opening.retained_database().unwrap())
                .unwrap();
            assert_eq!(report.settlement(), SourceReadSettlement::Retained);
            assert!(report.retains_database());
            assert!(!report.is_clean_capacity_refusal());
            let original = if captured {
                native_failure_address(report.reader_close().unwrap().native_retirement())
            } else {
                native_failure_address(report.native_retirement())
            };
            let report = request
                .dispose_settled(opening.retained_database().unwrap())
                .unwrap();
            let repeated = if captured {
                native_failure_address(report.reader_close().unwrap().native_retirement())
            } else {
                native_failure_address(report.native_retirement())
            };
            assert_eq!(original, repeated);
            assert_eq!(
                opening.close().settlement(),
                DatabaseOpenSettlement::WaitingForTransactions
            );
            drop(request);
            finish_failed(opening, &admission);
        }
    }
}

#[test]
fn retained_committed_writer_holds_exact_root_through_preowned_capture_without_new_grants() {
    use std::sync::mpsc;
    use std::time::Duration;
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let database = opening.database().unwrap();
    let mut rights = rights(&opening);
    let mut request = prepared(&opening, &rights);
    let write = database.begin_write().unwrap();
    write
        .open_table(ROWS)
        .unwrap()
        .insert(b"a".as_slice(), b"first".as_slice())
        .unwrap();
    let mut committed = write.retain();
    assert_eq!(
        committed.commit_holding_writer().settlement(),
        crate::WriteTerminalSettlement::HoldingWriter
    );
    assert!(*database.inner.gate.held.lock().unwrap());
    let queued = database.transaction_admission();
    let (started, starting) = mpsc::sync_channel(0);
    let (acquired, acquisition) = mpsc::sync_channel(1);
    let next = std::thread::spawn(move || {
        started.send(()).unwrap();
        let writer = queued.begin_write().unwrap();
        acquired.send(()).unwrap();
        writer
            .open_table(ROWS)
            .unwrap()
            .insert(b"a".as_slice(), b"second".as_slice())
            .unwrap();
        writer.commit().unwrap();
    });
    starting.recv().unwrap();
    assert!(matches!(
        acquisition.recv_timeout(Duration::from_millis(20)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    let full = admission.census();
    let grants = admission.last_grant();
    admission.limits(full.0, full.1);
    let counting = AllocationCount::start();
    assert_eq!(
        request
            .capture(opening.retained_database().unwrap())
            .unwrap()
            .settlement(),
        SourceReadSettlement::Ready
    );
    let mut selected = request
        .take_ready(opening.retained_database().unwrap())
        .unwrap();
    assert_eq!(counting.count(), 0);
    drop(counting);
    assert_eq!(admission.last_grant(), grants);
    assert_eq!(admission.census(), full);
    admission.limits(BYTE_LIMIT, SLOT_LIMIT);
    assert!(
        committed
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    acquisition.recv_timeout(Duration::from_secs(2)).unwrap();
    next.join().unwrap();
    assert_eq!(
        selected
            .get_bytes(ROWS, b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"first"
    );
    let current = database.begin_read().unwrap();
    assert_eq!(
        current
            .get_bytes(ROWS.name(), b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"second"
    );
    drop(current);
    close_reader(&opening, &mut selected);
    retire_rights(&opening, &mut rights);
    finish(opening, &admission);
}

#[test]
fn retained_holding_writer_refuses_foreign_disposal_and_keeps_exact_terminal_once() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let foreign_admission = CountedAdmission::new();
    let foreign = super::opening(&foreign_admission);
    let database = opening.database().unwrap();
    let mut writer = database.begin_write().unwrap().retain();
    assert_eq!(
        writer.commit_holding_writer().settlement(),
        crate::WriteTerminalSettlement::HoldingWriter
    );
    assert!(*database.inner.gate.held.lock().unwrap());
    assert!(
        !writer
            .dispose_settled(foreign.retained_database().unwrap())
            .disposal_complete()
    );
    assert_eq!(
        writer.report().settlement(),
        crate::WriteTerminalSettlement::HoldingWriter
    );
    assert!(matches!(
        writer.report().disposal(),
        TerminalObservation::NotEntered
    ));
    assert!(*database.inner.gate.held.lock().unwrap());
    let before = admission.census();
    let grants = admission.last_grant();
    let counting = AllocationCount::start();
    assert_eq!(
        writer.commit().settlement(),
        crate::WriteTerminalSettlement::HoldingWriter
    );
    assert_eq!(
        writer.abort().settlement(),
        crate::WriteTerminalSettlement::HoldingWriter
    );
    assert_eq!(counting.count(), 0);
    drop(counting);
    assert_eq!(admission.last_grant(), grants);
    assert_eq!(admission.census(), before);
    assert!(
        writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    assert!(!*database.inner.gate.held.lock().unwrap());
    assert!(matches!(
        writer.report().terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    finish(foreign, &foreign_admission);
    finish(opening, &admission);
}

#[test]
fn committed_empty_writer_is_a_live_owner_until_its_success_guard_retires() {
    let admission = CountedAdmission::new();
    let mut opening = opening(&admission);
    let committed = opening
        .database()
        .unwrap()
        .begin_write()
        .unwrap()
        .commit_holding_writer()
        .unwrap();
    assert!(*opening.database().unwrap().inner.gate.held.lock().unwrap());
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    drop(committed);
    finish(opening, &admission);
}

#[test]
fn held_writer_commit_capacity_refusal_mints_no_guard_and_releases_actual_writer() {
    let admission = CountedAdmission::new();
    let opening = opening(&admission);
    let database = opening.database().unwrap();
    let write = database.begin_write().unwrap();
    write
        .open_table(ROWS)
        .unwrap()
        .insert(b"a".as_slice(), b"rejected".as_slice())
        .unwrap();
    let full = admission.census();
    admission.limits(full.0, full.1);
    let error = write
        .commit_holding_writer()
        .err()
        .expect("materialization grant must refuse");
    assert!(error.0.is_capacity_denied(), "{error:?}");
    assert!(!*database.inner.gate.held.lock().unwrap());
    assert!(!database.inner.core.is_fenced());
    admission.limits(BYTE_LIMIT, SLOT_LIMIT);
    let next = database.begin_write().unwrap();
    next.abort().unwrap();
    let read = database.begin_read().unwrap();
    assert_eq!(
        read.get_bytes(ROWS.name(), b"a", 32)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old-a"
    );
    drop(read);
    finish(opening, &admission);
}
