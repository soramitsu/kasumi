use super::super::tests::{root, setup};
use super::*;

fn counts(pins: &SnapshotPins) -> (usize, usize, usize, usize) {
    let state = pins.inner.state.lock().unwrap();
    let (mut o, mut h, mut r, mut p) = (0, 0, 0, 0);
    for entry in state.slots.iter() {
        match entry {
            Entry::Empty => {}
            Entry::ProtectedIdle { .. } => r += 1,
            Entry::HistoryHold { .. } => h += 1,
            Entry::Pinned(Slot {
                class: PinClass::Ordinary,
                ..
            }) => o += 1,
            Entry::Pinned(Slot {
                class: PinClass::Protected(_),
                ..
            }) => {
                r += 1;
                p += 1;
            }
        }
    }
    assert!(o + h + r <= state.slots.len());
    assert!(p <= r);
    (o, h, r, p)
}

#[test]
fn protected_capacity_survives_ordinary_saturation_and_install_uses_no_admission_or_allocation() {
    let (admission, pins) = setup(4);
    let rights = pins.reserve_source_rights().unwrap();
    let a = pins.acquire(root(1)).unwrap();
    let b = pins.acquire(root(1)).unwrap();
    assert!(
        matches!(&(pins.acquire(root(1))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    let mut first = pins.prepare_protected(&rights).unwrap();
    let mut second = pins.prepare_protected(&rights).unwrap();
    assert!(
        matches!(&(pins.prepare_protected(&rights)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(counts(&pins), (2, 0, 2, 0));
    let before = admission.reserves.load(Ordering::Acquire);
    let checks = admission.checks.load(Ordering::Acquire);
    let allocations = allocation_tests::AllocationCount::start();
    let first_pin = pins.install_protected(&mut first, root(2)).unwrap();
    let second_pin = pins.install_protected(&mut second, root(3)).unwrap();
    assert_eq!(allocations.count(), 0);
    drop(allocations);
    assert_eq!(admission.checks.load(Ordering::Acquire), checks);
    assert_eq!(admission.reserves.load(Ordering::Acquire), before);
    assert_eq!(counts(&pins), (2, 0, 2, 2));
    let fork = first_pin.clone();
    assert_eq!(counts(&pins), (2, 0, 2, 2));
    assert_eq!(pins.validate(&fork).unwrap(), root(2));
    assert_eq!(
        pins.capture().unwrap().roots(),
        &[root(2), root(3), root(1)]
    );
    drop((first_pin, second_pin, fork, first, second, rights, a, b));
    assert_eq!(counts(&pins), (0, 0, 0, 0));
}

#[test]
fn history_swap_moves_lane_not_original_pin_or_root_and_retirement_does_not_recreate_a_third_right()
{
    let (admission, pins) = setup(4);
    let rights = pins.reserve_source_rights().unwrap();
    let mut prepared = pins.prepare_protected(&rights).unwrap();
    let old = pins.install_protected(&mut prepared, root(1)).unwrap();
    let old_identity = old.identity();
    let old_clone = old.clone();
    let mut history = pins.reserve_history(&old).unwrap();
    assert!(
        matches!(&(pins.reserve_history(&old)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    let ordinary = pins.acquire(root(2)).unwrap();
    assert_eq!(counts(&pins), (1, 1, 2, 1));
    let epoch = pins.epoch().unwrap();
    let capture = pins.capture().unwrap();
    let before = admission.reserves.load(Ordering::Acquire);
    pins.commit_history(&mut history).unwrap();
    assert_eq!(admission.reserves.load(Ordering::Acquire), before);
    assert_eq!(old.identity(), old_identity);
    assert_eq!(pins.epoch().unwrap(), epoch);
    pins.validate_capture(&capture).unwrap();
    assert_eq!(counts(&pins), (2, 0, 2, 0));
    assert!(
        matches!(&(pins.commit_history(&mut history)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    let untouched = pins.prepare_protected(&rights).unwrap();
    let mut next = pins.prepare_protected(&rights).unwrap();
    let fresh = pins.install_protected(&mut next, root(3)).unwrap();
    assert_ne!(fresh.identity().slot, old_identity.slot);
    assert_eq!(pins.validate(&old_clone).unwrap(), root(1));
    assert_eq!(counts(&pins), (2, 0, 2, 1));
    drop((old, old_clone, history));
    assert_eq!(counts(&pins), (1, 0, 2, 1));
    drop((ordinary, fresh, next, untouched, prepared, capture, rights));
    assert_eq!(counts(&pins), (0, 0, 0, 0));
}

#[test]
fn pristine_ticket_and_history_cancel_preserve_roots_and_release_only_their_capacity() {
    let (admission, pins) = setup(3);
    let rights = pins.reserve_source_rights().unwrap();
    let baseline = admission.used.load(Ordering::Acquire);
    let mut prepared = pins.prepare_protected(&rights).unwrap();
    prepared.cancel().unwrap();
    prepared.cancel().unwrap();
    assert_eq!(admission.used.load(Ordering::Acquire), baseline);
    assert_eq!(pins.epoch().unwrap(), 0);
    let mut fresh = pins.prepare_protected(&rights).unwrap();
    assert!(
        matches!(&(pins.install_protected(&mut prepared, root(1))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    let pin = pins.install_protected(&mut fresh, root(1)).unwrap();
    let identity = pin.identity();
    let mut history = pins.reserve_history(&pin).unwrap();
    assert_eq!(counts(&pins), (0, 1, 2, 1));
    history.cancel().unwrap();
    history.cancel().unwrap();
    assert_eq!(counts(&pins), (0, 0, 2, 1));
    assert_eq!(pin.identity(), identity);
    assert!(
        matches!(&(pins.commit_history(&mut history)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    let ordinary = pins.acquire(root(2)).unwrap();
    assert_eq!(counts(&pins), (1, 0, 2, 1));
    drop((ordinary, history, pin, fresh, prepared, rights));
    assert_eq!(counts(&pins), (0, 0, 0, 0));
}

#[test]
fn equal_group_foreign_rights_tickets_and_history_are_rejected_without_consuming_originals() {
    let (_, first) = setup(3);
    let (_, foreign) = setup(3);
    let rights = first.reserve_source_rights().unwrap();
    assert!(
        matches!(&(foreign.prepare_protected(&rights)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    let mut ticket = first.prepare_protected(&rights).unwrap();
    assert!(
        matches!(&(foreign.install_protected(&mut ticket, root(1))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    let mut wrong = root(1);
    wrong.group_id = [99; 16];
    assert!(
        matches!(&(first.install_protected(&mut ticket, wrong)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    let pin = first.install_protected(&mut ticket, root(1)).unwrap();
    assert!(
        matches!(&(foreign.reserve_history(&pin)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    let mut history = first.reserve_history(&pin).unwrap();
    assert!(
        matches!(&(foreign.commit_history(&mut history)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::InvalidInput(_))))
    );
    assert_eq!(counts(&first), (0, 1, 2, 1));
    assert_eq!(counts(&foreign), (0, 0, 0, 0));
    first.commit_history(&mut history).unwrap();
    assert_eq!(first.validate(&pin).unwrap(), root(1));
}

#[test]
fn right_owner_drop_keeps_pending_and_pinned_rights_until_last_actual_owner() {
    let (admission, pins) = setup(3);
    let baseline = admission.used.load(Ordering::Acquire);
    let rights = pins.reserve_source_rights().unwrap();
    let mut ticket = pins.prepare_protected(&rights).unwrap();
    drop(rights);
    assert_eq!(counts(&pins), (0, 0, 2, 0));
    let pin = pins.install_protected(&mut ticket, root(1)).unwrap();
    drop(ticket);
    let mut history = pins.reserve_history(&pin).unwrap();
    pins.commit_history(&mut history).unwrap();
    assert_eq!(counts(&pins), (1, 0, 2, 0));
    drop(pin);
    assert_eq!(counts(&pins), (1, 0, 2, 0));
    drop(history);
    assert_eq!(counts(&pins), (0, 0, 0, 0));
    assert_eq!(admission.used.load(Ordering::Acquire), baseline);
}

#[test]
fn multiple_sources_and_history_saturation_never_borrow_each_others_lanes() {
    let (_, pins) = setup(5);
    let first = pins.reserve_source_rights().unwrap();
    let second = pins.reserve_source_rights().unwrap();
    assert!(
        matches!(&(pins.reserve_source_rights()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    let mut a = pins.prepare_protected(&first).unwrap();
    let pin = pins.install_protected(&mut a, root(1)).unwrap();
    let blocker = pins.acquire(root(2)).unwrap();
    assert!(
        matches!(&(pins.reserve_history(&pin)), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    let mut b = pins.prepare_protected(&second).unwrap();
    let other = pins.install_protected(&mut b, root(3)).unwrap();
    assert_eq!(counts(&pins), (1, 0, 4, 2));
    drop((a, b, pin, other, blocker, first, second));
    assert_eq!(counts(&pins), (0, 0, 0, 0));
}

#[test]
fn ordinary_acquisition_and_history_hold_race_for_only_the_unprotected_capacity() {
    let (_, pins) = setup(3);
    let rights = pins.reserve_source_rights().unwrap();
    for generation in 1..33 {
        let mut prepared = pins.prepare_protected(&rights).unwrap();
        let pin = pins
            .install_protected(&mut prepared, root(generation))
            .unwrap();
        let gate = std::sync::Barrier::new(2);
        let (ordinary, history) = std::thread::scope(|scope| {
            let a = scope.spawn(|| {
                gate.wait();
                pins.acquire(root(generation))
            });
            let h = scope.spawn(|| {
                gate.wait();
                pins.reserve_history(&pin)
            });
            (a.join().unwrap(), h.join().unwrap())
        });
        assert_ne!(ordinary.is_ok(), history.is_ok());
        match history {
            Ok(mut history) => {
                assert!(
                    matches!(&(ordinary), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
                );
                assert_eq!(counts(&pins), (0, 1, 2, 1));
                if generation.is_multiple_of(2) {
                    pins.commit_history(&mut history).unwrap();
                    assert_eq!(counts(&pins), (1, 0, 2, 0));
                } else {
                    history.cancel().unwrap();
                    assert_eq!(counts(&pins), (0, 0, 2, 1));
                }
            }
            Err(error) => {
                assert!(matches!(
                    (error).rejected_cause(),
                    Some(crate::CoreErrorCause::CapacityDenied)
                ));
                assert_eq!(counts(&pins), (1, 0, 2, 1));
                drop(ordinary.unwrap());
            }
        }
        drop((pin, prepared));
        assert_eq!(counts(&pins), (0, 0, 2, 0));
    }
}

#[test]
fn serial_exhaustion_refuses_before_capacity_changes_and_prepared_cancel_survives_poison() {
    let (admission, pins) = setup(3);
    pins.inner.state.lock().unwrap().serial = u64::MAX;
    let baseline = admission.used.load(Ordering::Acquire);
    assert!(
        matches!(&(pins.reserve_source_rights()), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
    );
    assert_eq!(counts(&pins), (0, 0, 0, 0));
    assert_eq!(admission.used.load(Ordering::Acquire), baseline);
    assert_eq!(pins.epoch().unwrap(), 0);
    // Independent setup avoids manufacturing serial reuse in a healthy owner.
    let (admission, pins) = setup(3);
    let baseline = admission.used.load(Ordering::Acquire);
    let rights = pins.reserve_source_rights().unwrap();
    let mut prepared = pins.prepare_protected(&rights).unwrap();
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _lock = pins.inner.state.lock().unwrap();
        panic!("poison prepared pin registry");
    }));
    assert!(poisoned.is_err());
    assert!(
        matches!(&(pins.install_protected(&mut prepared, root(1))), Err(native_error) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::OwnerFailed)))
    );
    prepared.cancel().unwrap();
    drop((prepared, rights));
    let state = pins
        .inner
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // The exact ticket was cancelled, but poisoned final rights retirement
    // cannot prove either lane safe to clear. Drop is not that proof.
    assert_eq!(
        state
            .slots
            .iter()
            .filter(|entry| matches!(entry, Entry::ProtectedIdle { ticket: None, .. }))
            .count(),
        2
    );
    assert!(pins.inner.failed.load(Ordering::Acquire));
    assert_eq!(state.epoch, 0);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), baseline);
    drop(pins);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn corrupt_pending_ticket_cancel_retains_borrowed_owner_and_never_refunds_mismatched_capacity() {
    let (admission, pins) = setup(3);
    let rights = pins.reserve_source_rights().unwrap();
    let mut prepared = pins.prepare_protected(&rights).unwrap();
    let retained = admission.used.load(Ordering::Acquire);
    {
        let mut state = pins.inner.state.lock().unwrap();
        let entry = state
            .slots
            .iter_mut()
            .find(|entry| {
                matches!(entry,
            Entry::ProtectedIdle { lane, ticket: Some(ticket) }
                if *lane == prepared.lane && *ticket == prepared.ticket)
            })
            .unwrap();
        if let Entry::ProtectedIdle { ticket, .. } = entry {
            *ticket = Some(prepared.ticket + 1);
        }
    }
    let original = prepared.cancel().expect_err("mismatched ticket canceled");
    assert!(matches!(
        (original).rejected_cause(),
        Some(crate::CoreErrorCause::OwnerFailed)
    ));
    assert!(prepared.pending);
    assert!(prepared.pin.is_some());
    assert_eq!(admission.used.load(Ordering::Acquire), retained);
    assert_eq!(counts(&pins), (0, 0, 2, 0));
    assert!(pins.inner.failed.load(Ordering::Acquire));
    // Destructor cleanup is not a cancellation proof. Strict rights retirement
    // keeps both lanes when either tag cannot be verified; no partial cleanup
    // can acknowledge the corrupt ticket after local payloads are destroyed.
    drop((prepared, rights));
    assert_eq!(counts(&pins), (0, 0, 2, 0));
    assert!(pins.inner.failed.load(Ordering::Acquire));
    assert_eq!(pins.inner.state.lock().unwrap().epoch, 0);
    drop(pins);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}
