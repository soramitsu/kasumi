//! Actual paid native seats reject sealing before callback construction.
use super::*;
use kasumi_engine::admission::NodeAdmission;
use std::{
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Waker},
};

fn charged(admission: &NodeAdmission) -> (u64, u64, u64, usize) {
    let snapshot = admission.snapshot();
    (
        snapshot.reserved_bytes,
        snapshot.bookkeeping_bytes,
        snapshot.resident_reserved_bytes,
        snapshot.live_reservations,
    )
}

fn reject_without_entering(guard: &mut OriginalRecoveryGuard<'_>) {
    let callbacks_created = AtomicUsize::new(0);
    let callbacks_entered = AtomicUsize::new(0);
    let observation = match guard.begin_node() {
        Err(observation) => observation,
        Ok(loan) => {
            callbacks_created.fetch_add(1, Ordering::SeqCst);
            match loan.run_node(|| {
                callbacks_entered.fetch_add(1, Ordering::SeqCst);
                panic!("a sealed native constructor was entered")
            }) {
                Err(observation) => observation,
                Ok(_) => panic!("a sealed native constructor succeeded"),
            }
        }
    };
    assert_eq!(observation.index, 0);
    assert_eq!(observation.stage, "native_node_start_sealed");
    assert_eq!(callbacks_created.load(Ordering::SeqCst), 0);
    assert_eq!(callbacks_entered.load(Ordering::SeqCst), 0);
    assert!(guard.seat.node_start.is_none());
    assert!(guard.seat.node_start_output.is_none());
    assert!(guard.seat.node_start_observation.panic.is_none());
    assert!(guard.seat.node_start_observation.disposal_panic.is_none());
    assert_eq!(
        guard.seat.node_start_observation.entry,
        CleanupEntry::NotEntered
    );
    assert_eq!(
        guard.seat.node_start_observation.future_disposal,
        CleanupEntry::NotEntered
    );
    assert!(guard.is_empty());
}

#[tokio::test]
async fn native_start_sealed_before_claim_never_constructs_or_enters_callback() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let initial = charged(&admission);
    let inventory = OriginalRecoveries::new(
        &admission,
        OriginalRecoveryParticipants::one(crate::runtime::CONTROL_TENANT),
    )
    .unwrap();
    let installed = charged(&admission);
    inventory.seal();
    {
        let mut guard = inventory.claim(0).await;
        assert!(guard.sealed_at_claim);
        reject_without_entering(&mut guard);
        reject_without_entering(&mut guard);
    }
    assert!(!inventory.retained().await);
    assert_eq!(charged(&admission), installed);
    drop(inventory);
    assert_eq!(charged(&admission), initial);
}

#[tokio::test]
async fn native_start_sealed_while_actual_claim_waits_never_enters_callback() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let initial = charged(&admission);
    let inventory = OriginalRecoveries::new(
        &admission,
        OriginalRecoveryParticipants::one(crate::runtime::CONTROL_TENANT),
    )
    .unwrap();
    let installed = charged(&admission);
    {
        let held = inventory.claim(0).await;
        let mut waiting = std::pin::pin!(inventory.claim(0));
        let mut context = Context::from_waker(Waker::noop());
        assert!(waiting.as_mut().poll(&mut context).is_pending());
        inventory.seal();
        drop(held);
        let mut guard = waiting.await;
        assert!(
            !guard.sealed_at_claim,
            "the actual claim entered before sealing"
        );
        reject_without_entering(&mut guard);
    }
    assert!(!inventory.retained().await);
    assert_eq!(charged(&admission), installed);
    drop(inventory);
    assert_eq!(charged(&admission), initial);
}
