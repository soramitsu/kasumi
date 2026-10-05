//! Actual native provider and output originals in the initial Server receiver.
use super::*;
use crate::recovery_allocation_watch::Watch;
use kasumi_store::{NodeStore, NodeStoreStartFailure, TerminalObservation};
use std::{
    cell::Cell,
    sync::atomic::{AtomicUsize, Ordering},
};

fn provider_error(original: &NodeStoreStartFailure) -> usize {
    let NodeStoreStartFailure::Constructor(original) = original else {
        panic!("the actual provider refusal must retain its constructor receiver: {original:?}");
    };
    assert!(original.id().is_some());
    original.with_report(|report| {
        let report = report.expect("same live actual constructor census cell");
        assert!(report.capacity_refused());
        assert!(!report.has_lease());
        assert!(!report.has_payload());
        assert!(matches!(
            report.construction(),
            TerminalObservation::NotEntered
        ));
        let TerminalObservation::Returned(Err(original)) = report.provider() else {
            panic!("actual provider capacity refusal");
        };
        assert_eq!(original.kind(), std::io::ErrorKind::OutOfMemory);
        original as *const std::io::Error as usize
    })
}
#[derive(Debug)]
struct OriginalCallbackPanic(u64);
struct CallbackDrop(Option<Box<OriginalCallbackPanic>>);
impl Drop for CallbackDrop {
    fn drop(&mut self) {
        std::panic::resume_unwind(self.0.take().expect("one original callback destructor"));
    }
}

#[tokio::test]
async fn native_start_actual_provider_original_and_callback_disposal_panic_stay_in_paid_seat() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        crate::runtime_storage_fixtures::physical(directory.path(), Default::default()).unwrap();
    let originals = OriginalRecoveries::new(
        &physical.admission,
        OriginalRecoveryParticipants::one(crate::runtime::CONTROL_TENANT),
    )
    .unwrap();
    let inventory_bytes = OriginalRecoveries::required_bytes(
        physical.admission.policy(),
        OriginalRecoveryParticipants::one(crate::runtime::CONTROL_TENANT),
    )
    .unwrap();
    let pressure = physical
        .admission
        .memory()
        .reserve_resident(
            physical
                .admission
                .policy()
                .resolved_fixture_total_bytes()
                .unwrap()
                - physical.admission.snapshot().reserved_bytes,
        )
        .unwrap();
    let full = physical.admission.snapshot();
    let path = directory.path().join("persistent/refused.kv");
    let error_address = Cell::new(0);
    let calls = AtomicUsize::new(0);
    let panic = Box::new(OriginalCallbackPanic(719));
    let panic_address = panic.as_ref() as *const OriginalCallbackPanic as usize;
    let disposal = CallbackDrop(Some(panic));
    let mut guard = originals.claim(0).await;
    let loan = guard
        .begin_node()
        .unwrap_or_else(|_| panic!("initial paid seat"));
    let error_address_ref = &error_address;
    let calls_ref = &calls;
    let path_ref = &path;
    let physical_ref = &physical;
    let returned = loan.run_node(move || {
        // Borrowing the whole environment keeps its independent destructor
        // until run_node has installed the actual returned native original.
        let _keep_disposal = &disposal;
        calls_ref.fetch_add(1, Ordering::SeqCst);
        let returned = NodeStore::create_new(
            path_ref,
            kasumi_store::test_utils::NODE_STORE_ID,
            physical_ref.persistent.clone(),
            physical_ref.scratch.clone(),
            physical_ref.persistent.native_storage_config(),
        );
        if let Err(original) = &returned {
            error_address_ref.set(provider_error(original));
        }
        returned
    });
    let observed = returned.err().expect("actual provider refusal");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        guard.seat.node_start_observation.entry,
        CleanupEntry::Returned
    );
    assert_eq!(
        guard.seat.node_start_observation.future_disposal,
        CleanupEntry::Panicked
    );
    // The source error is already installed before the outer ordinary marker.
    assert_eq!(
        provider_error(guard.seat.node_start.as_ref().unwrap()),
        error_address.get()
    );
    drop(observed.foreign_error());
    let watching = Watch::begin();
    assert!(guard.begin_node().is_err());
    assert_eq!(watching.finish().count, 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        guard
            .seat
            .node_start_observation
            .with_disposal_panic(|original| {
                let original = original.downcast_ref::<OriginalCallbackPanic>().unwrap();
                assert_eq!(original.0, 719);
                original as *const OriginalCallbackPanic as usize
            }),
        Some(panic_address)
    );
    drop(guard);
    for _ in 0..3 {
        assert_eq!(
            originals.with_node_start_failure(0, provider_error).await,
            Some(error_address.get())
        );
    }
    assert_eq!(
        originals
            .with_node_start_disposal_panic(0, |original| {
                original.downcast_ref::<OriginalCallbackPanic>().unwrap() as *const _ as usize
            })
            .await,
        Some(panic_address)
    );
    originals.seal();
    let mut refused = originals.claim(0).await;
    assert!(refused.begin_node().is_err());
    drop(refused);
    assert!(originals.retained().await);
    assert_eq!(
        physical.admission.snapshot().reserved_bytes,
        full.reserved_bytes
    );
    assert_eq!(
        physical.admission.snapshot().live_reservations,
        full.live_reservations
    );
    drop(pressure);
    let before_drop = physical.admission.snapshot();
    drop(originals);
    assert_eq!(
        physical.admission.snapshot().reserved_bytes,
        before_drop.reserved_bytes
    );
    assert!(before_drop.reserved_bytes >= inventory_bytes);
}

#[tokio::test]
async fn native_start_successful_original_owner_survives_callback_disposal_panic() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        crate::runtime_storage_fixtures::physical(directory.path(), Default::default()).unwrap();
    let originals = OriginalRecoveries::new(
        &physical.admission,
        OriginalRecoveryParticipants::one(crate::runtime::CONTROL_TENANT),
    )
    .unwrap();
    let path = directory.path().join("persistent/success.kv");
    let address = Cell::new(None);
    let original_panic = Box::new(OriginalCallbackPanic(727));
    let panic_address = original_panic.as_ref() as *const OriginalCallbackPanic as usize;
    let disposal = CallbackDrop(Some(original_panic));
    let address_ref = &address;
    let physical_ref = &physical;
    let path_ref = &path;
    let mut guard = originals.claim(0).await;
    let loan = guard
        .begin_node()
        .unwrap_or_else(|_| panic!("initial paid seat"));
    let returned = loan.run_node(move || {
        let _keep_disposal = &disposal;
        let returned = NodeStore::create_new(
            path_ref,
            kasumi_store::test_utils::NODE_STORE_ID,
            physical_ref.persistent.clone(),
            physical_ref.scratch.clone(),
            physical_ref.persistent.native_storage_config(),
        );
        if let Ok(original) = &returned {
            address_ref.set(original.registered_opening_id());
        }
        returned
    });
    assert!(returned.is_err());
    assert!(
        address.get().is_some(),
        "the actual NodeStore constructor returned successfully"
    );
    assert_eq!(
        guard.seat.node_start_observation.entry,
        CleanupEntry::Returned
    );
    assert_eq!(
        guard.seat.node_start_observation.future_disposal,
        CleanupEntry::Panicked
    );
    assert!(guard.seat.node_start.is_none());
    assert_eq!(
        guard
            .seat
            .node_start_output
            .as_ref()
            .unwrap()
            .registered_opening_id(),
        address.get()
    );
    assert_eq!(
        guard
            .seat
            .node_start_observation
            .with_disposal_panic(|original| {
                let original = original.downcast_ref::<OriginalCallbackPanic>().unwrap();
                assert_eq!(original.0, 727);
                original as *const OriginalCallbackPanic as usize
            }),
        Some(panic_address)
    );
    assert!(!guard.seat.native_free_failure());
    drop(guard);
    assert_eq!(
        originals
            .with_node_start_output(0, NodeStore::registered_opening_id)
            .await,
        Some(address.get())
    );
    assert_eq!(
        originals
            .with_node_start_disposal_panic(0, |original| {
                original.downcast_ref::<OriginalCallbackPanic>().unwrap() as *const _ as usize
            })
            .await,
        Some(panic_address)
    );
    let retained = physical.admission.snapshot();
    assert!(originals.retained().await);
    drop(originals);
    assert_eq!(
        physical.admission.snapshot().reserved_bytes,
        retained.reserved_bytes
    );
    assert_eq!(
        physical.admission.snapshot().live_reservations,
        retained.live_reservations
    );
}
