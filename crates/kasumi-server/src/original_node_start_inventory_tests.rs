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
#[allow(
    clippy::result_large_err,
    reason = "preserve the original native custody error inline without an extra allocation"
)]
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
    originals.retire_closed_node_refusals().await;
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
#[allow(
    clippy::result_large_err,
    reason = "preserve the original native custody error inline without an extra allocation"
)]
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
    originals.retire_closed_node_refusals().await;
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

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "the native constructor passes its whole original into the prepaid receiver"
)]
async fn closed_node_acquisition_refusal_retires_before_startup_cleanup_completes() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        crate::runtime_storage_fixtures::physical(directory.path(), Default::default()).unwrap();
    let originals = OriginalRecoveries::new(
        &physical.admission,
        OriginalRecoveryParticipants::one(crate::runtime::CONTROL_TENANT),
    )
    .unwrap();
    let path = directory.path().join("persistent/existing.kv");
    let node = NodeStore::create_new(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        physical.persistent.clone(),
        physical.scratch.clone(),
        physical.persistent.native_storage_config(),
    )
    .unwrap();
    node.shutdown().await.unwrap();
    assert!(node.retire().is_retired());
    let baseline = physical.admission.snapshot();
    let mut guard = originals.claim(0).await;
    assert!(
        guard
            .begin_node()
            .unwrap_or_else(|_| panic!("initial paid seat"))
            .run_node(|| {
                NodeStore::create_new(
                    &path,
                    kasumi_store::test_utils::NODE_STORE_ID,
                    physical.persistent.clone(),
                    physical.scratch.clone(),
                    physical.persistent.native_storage_config(),
                )
            })
            .is_err()
    );
    let Some(NodeStoreStartFailure::Opening(original)) = &guard.seat.node_start else {
        panic!("acquisition refusal retains its native opening");
    };
    assert!(matches!(
        original.custody().opening().report().acquisition(),
        TerminalObservation::Returned(Err(_))
    ));
    let refused_id = original.opening_id();
    let alias = kasumi_store::RegisteredNodeOpening::retained(
        physical.persistent.memory().clone(),
        refused_id,
    )
    .unwrap();
    drop(guard);
    assert!(originals.retained().await);
    originals.retire_closed_node_refusals().await;
    assert!(
        originals.retained().await,
        "the actual native alias prevents retirement"
    );
    assert_eq!(
        originals
            .claim(0)
            .await
            .seat
            .node_start_retirement
            .as_ref()
            .unwrap()
            .id(),
        refused_id
    );
    drop(alias);
    let mut pending = crate::startup_resources::Resources::default();
    pending.original_recoveries = Some(originals.clone());
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::startup_owner::finish(&mut pending),
    )
    .await
    .expect("a positively closed refusal must not wait for nonexistent cleanup")
    .unwrap();
    assert!(!originals.retained().await);
    assert_eq!(
        physical.admission.snapshot().reserved_bytes,
        baseline.reserved_bytes
    );
    // Cleanup disposes only the failed acquisition. The installed group remains
    // independently reopenable through its original immutable identity.
    let reopened = NodeStore::open_existing(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        physical.persistent.clone(),
        physical.scratch.clone(),
        physical.persistent.native_storage_config(),
    )
    .unwrap();
    let live_baseline = physical.admission.snapshot();
    let mut guard = originals.claim(0).await;
    assert!(
        guard
            .begin_node()
            .unwrap_or_else(|_| panic!("retired failure freed its seat"))
            .run_node(|| {
                NodeStore::open_existing(
                    &path,
                    kasumi_store::test_utils::NODE_STORE_ID,
                    physical.persistent.clone(),
                    physical.scratch.clone(),
                    physical.persistent.native_storage_config(),
                )
            })
            .is_err()
    );
    drop(guard);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::startup_owner::finish(&mut pending),
    )
    .await
    .expect("exclusive-open refusal must also finish cleanup")
    .unwrap();
    assert!(!originals.retained().await);
    assert_eq!(
        physical.admission.snapshot().reserved_bytes,
        live_baseline.reserved_bytes
    );
    reopened.shutdown().await.unwrap();
    assert!(reopened.retire().is_retired());

    let disposal = CallbackDrop(Some(Box::new(OriginalCallbackPanic(733))));
    let physical_ref = &physical;
    let path_ref = &path;
    let mut guard = originals.claim(0).await;
    assert!(
        guard
            .begin_node()
            .unwrap_or_else(|_| panic!("retired failure freed its seat"))
            .run_node(move || {
                let _keep_disposal = &disposal;
                NodeStore::create_new(
                    path_ref,
                    kasumi_store::test_utils::NODE_STORE_ID,
                    physical_ref.persistent.clone(),
                    physical_ref.scratch.clone(),
                    physical_ref.persistent.native_storage_config(),
                )
            })
            .is_err()
    );
    let Some(NodeStoreStartFailure::Opening(original)) = &guard.seat.node_start else {
        panic!("same acquisition refusal");
    };
    let retained_id = original.opening_id();
    drop(guard);
    originals.retire_closed_node_refusals().await;
    assert!(originals.retained().await);
    assert_eq!(
        originals
            .with_node_start_failure(0, |original| match original {
                NodeStoreStartFailure::Opening(original) => original.opening_id(),
                _ => panic!("the original opening carrier must remain"),
            })
            .await,
        Some(retained_id)
    );
    assert_eq!(
        originals
            .with_node_start_disposal_panic(0, |original| {
                original.downcast_ref::<OriginalCallbackPanic>().unwrap().0
            })
            .await,
        Some(733)
    );
}
