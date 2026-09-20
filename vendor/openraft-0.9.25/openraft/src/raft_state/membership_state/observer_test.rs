use std::panic::catch_unwind;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use maplit::btreeset;

use crate::membership_observer::MembershipObserverSlot;
use crate::testing::log_id;
use crate::EffectiveMembership;
use crate::Membership;
use crate::MembershipObserver;
use crate::MembershipObserverAlreadyInstalled;
use crate::MembershipState;

#[derive(Debug, Default)]
struct Observer {
    calls: AtomicUsize,
    panic: AtomicBool,
}
impl MembershipObserver for Observer {
    fn membership_changing(&self) {
        self.calls.fetch_add(1, Ordering::AcqRel);
        assert!(!self.panic.load(Ordering::Acquire), "stop before membership mutation");
    }
}
fn membership(index: u64, voters: &[u64]) -> Arc<EffectiveMembership<u64, ()>> {
    Arc::new(EffectiveMembership::new(
        Some(log_id(1, 1, index)),
        Membership::new(vec![voters.iter().copied().collect()], None),
    ))
}
fn state() -> MembershipState<u64, ()> {
    MembershipState::new(membership(1, &[1]), membership(3, &[1, 2]))
}

#[test]
fn callbacks_precede_append_commit_truncate_and_both_snapshot_updates() {
    for case in 0..5 {
        let mut state = state();
        let before = state.clone();
        let observer = Arc::new(Observer::default());
        state.observer.install(observer.clone()).unwrap();
        observer.panic.store(true, Ordering::Release);
        let attempted = catch_unwind(AssertUnwindSafe(|| match case {
            0 => state.append(membership(4, &[1, 2, 3])),
            1 => state.commit(&Some(log_id(1, 1, 3))),
            2 => {
                state.truncate(3);
            }
            // A snapshot covering the effective log can roll membership back.
            3 => {
                state.update_committed(membership(1, &[3]), 4);
            }
            // Snapshot committed membership changes while a later effective log stays.
            4 => {
                state.update_committed(membership(2, &[1, 3]), 2);
            }
            _ => unreachable!(),
        }));
        assert!(attempted.is_err());
        assert_eq!(state, before, "case {case} mutated membership before invalidation");
        assert_eq!(observer.calls.load(Ordering::Acquire), 2);
    }
}

#[test]
fn observer_slot_is_shared_and_replacement_is_rejected() {
    let original = state();
    let mut peer = original.clone();
    assert!(Arc::ptr_eq(&original.observer, &peer.observer));
    let observer = Arc::new(Observer::default());
    original.observer.install(observer.clone()).unwrap();
    peer.observer.install(observer.clone()).unwrap();
    assert_eq!(
        observer.calls.load(Ordering::Acquire),
        1,
        "same-Arc install is idempotent"
    );
    assert_eq!(
        peer.observer.install(Arc::new(Observer::default())),
        Err(MembershipObserverAlreadyInstalled)
    );
    peer.append(membership(4, &[1, 2, 3]));
    assert_eq!(observer.calls.load(Ordering::Acquire), 2);
    assert_eq!(
        original.effective().membership().voter_ids().collect::<std::collections::BTreeSet<_>>(),
        btreeset! {1, 2}
    );
}

#[test]
fn unchanged_membership_does_not_invalidate_for_ordinary_commits() {
    let mut state = state();
    let observer = Arc::new(Observer::default());
    state.observer.install(observer.clone()).unwrap();
    state.commit(&Some(log_id(1, 1, 2)));
    assert!(state.truncate(9).is_none());
    assert!(state.update_committed(membership(1, &[1]), 1).is_none());
    assert_eq!(observer.calls.load(Ordering::Acquire), 1);
    state.commit(&Some(log_id(1, 1, 3)));
    assert_eq!(observer.calls.load(Ordering::Acquire), 2);
    state.commit(&Some(log_id(1, 1, 100)));
    state.update_committed(membership(3, &[1, 2]), 100);
    assert_eq!(observer.calls.load(Ordering::Acquire), 2);
}

#[test]
fn installation_waits_for_an_unobserved_mutation_guard() {
    let slot = Arc::new(MembershipObserverSlot::default());
    let guard = slot.changing();
    let installer_slot = slot.clone();
    let observer = Arc::new(Observer::default());
    let installed = observer.clone();
    let (entered, entry) = mpsc::channel();
    let (done, completion) = mpsc::channel();
    let installer = std::thread::spawn(move || {
        entered.send(()).unwrap();
        installer_slot.install(installed).unwrap();
        done.send(()).unwrap();
    });
    entry.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        completion.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    assert_eq!(observer.calls.load(Ordering::Acquire), 0);
    drop(guard);
    completion.recv_timeout(Duration::from_secs(2)).unwrap();
    installer.join().unwrap();
    assert_eq!(observer.calls.load(Ordering::Acquire), 1);
}
