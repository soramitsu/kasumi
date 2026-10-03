//! Fault the exact producer-created installed lease, never a substitute grant.
use super::*;
use crate::admission::installed_drop_probe::Probe;
use std::{any::Any, panic::AssertUnwindSafe};

#[derive(Debug)]
struct PointRetirementOriginal;

struct Arm<'a, 'b> {
    actual: &'a mut PublicationPreparation<'b>,
    probe: &'a Probe,
    payload: Option<Box<dyn Any + Send>>,
}
impl SelectionPreparer for Arm<'_, '_> {
    fn prepare(
        &mut self,
        plan: &PreparedSelectionPlan,
        points: PreparedTenantPointWorkspace,
    ) -> Result<()> {
        // The real Entry producer has just retired its planning reader and
        // transferred its final backing. Arm before the actual preparer queues.
        self.probe
            .arm_last(self.payload.take().expect("single actual preparation"));
        self.actual.prepare(plan, points)
    }
}
fn prepare_actual_entry(
    fixture: &Fixture,
    probe: &Probe,
    original: &Arc<PointRetirementOriginal>,
) -> Result<(RootPreparation, kasumi_raft::AppliedEntryContext)> {
    let position = kasumi_raft::AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
        previous: None,
        membership: Default::default(),
        command_sha256: "0".repeat(64),
        retirement_seed: None,
    };
    let response = kasumi_raft::AppliedResponse::application(Vec::new());
    let expectation =
        kasumi_raft::PublicationExpectation::for_entry(&fixture.stores, &position, &[], &response)?;
    let mut actual = fixture.roots.publication_preparation();
    let mut receipt = None;
    {
        let mut arm = Arm {
            actual: &mut actual,
            probe,
            payload: Some(Box::new(original.clone())),
        };
        kasumi_raft::with_application_publisher_for_test(
            &fixture.stores,
            &position,
            |publisher| {
                receipt = Some(publisher.commit_with_selection(
                    response,
                    &[],
                    &mut arm,
                    expectation.challenge()?,
                )?);
                Ok(())
            },
        )?;
        assert!(arm.payload.is_none());
    }
    let prepared =
        actual.finish_publication(&expectation, receipt.context("actual receipt absent")?)?;
    assert!(prepared.points.is_some());
    assert!(!probe.fired(), "point lease retired before capture/cancel");
    Ok((prepared, position))
}
fn assert_point_original(cell: &Cell, original: &Arc<PointRetirementOriginal>) {
    let saved = cell
        .point_failure
        .get()
        .expect("separate point retirement custody");
    let panic = saved
        .owner
        .original
        .downcast_ref::<SourcePanic>()
        .expect("typed point panic");
    assert!(Arc::ptr_eq(
        panic
            ._payload
            .lock()
            .unwrap()
            .downcast_ref::<Arc<PointRetirementOriginal>>()
            .unwrap(),
        original,
    ));
}
fn assert_strict_repeated_drain(fixture: &Fixture, count: usize) {
    let Poll::Ready(Err(first)) = drain(&fixture.roots) else {
        panic!("unknown point retirement falsely drained");
    };
    let Poll::Ready(Err(second)) = drain(&fixture.roots) else {
        panic!("repeated unknown point retirement falsely drained");
    };
    assert_eq!(first.completion(), DrainCompletion::Retained);
    assert_eq!(second.completion(), DrainCompletion::Retained);
    assert_eq!(first.issues().len(), count);
    assert_eq!(second.issues().len(), count);
    for (a, b) in first.issues().iter().zip(second.issues()) {
        assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(a, b));
    }
    assert!(!fixture.roots.is_drained());
}
fn remove_only_injected_unknown(fixture: &Fixture, cell: &CellRef) {
    assert!(cell.state.lock().unwrap().closed);
    assert!(!cell.state.lock().unwrap().preparing);
    assert!(cell.state.lock().unwrap().view.is_none());
    assert!(cell.native_retained.load(Ordering::Acquire));
    // Only this test knows the lease callback panicked after positive actual
    // release. The source must retain unknown custody indefinitely in production.
    let removed = fixture
        .roots
        .gate
        .lock()
        .unwrap()
        .cells
        .remove(&cell.id)
        .unwrap();
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    drop(removed);
}

#[tokio::test]
async fn selected_sources_actual_point_drop_panic_preserves_capture_error_and_separate_payload()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let baseline = fixture.storage.admission.snapshot().live_reservations;
    let probe = Probe::begin(fixture.storage.admission.memory());
    let original = Arc::new(PointRetirementOriginal);
    let (mut prepared, mut wrong) = prepare_actual_entry(&fixture, &probe, &original)?;
    let cell = prepared.cell.clone();
    let reader = prepared
        .queued
        .as_ref()
        .unwrap()
        .registered_reader_id()
        .unwrap();
    wrong.command_sha256 = "1".repeat(64);
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        prepared.capture_in_place(ApplicationBoundaryRef::Entry(&wrong), false)
    }));
    assert!(
        outcome.is_ok(),
        "point retirement panic escaped capture custody"
    );
    let error = outcome
        .unwrap()
        .err()
        .context("wrong Entry boundary captured")?;
    assert!(probe.fired(), "actual installed lease fault did not run");
    assert!(prepared.points.is_none());
    let body = cell.failure.get().expect("actual capture error retained");
    let exact = body
        .owner
        .original
        .downcast_ref::<SelectionFailure<Workspace>>()
        .unwrap();
    assert_eq!(
        exact.original_error().to_string(),
        "replayed source applied position differs"
    );
    let returned = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<SelectionFailure<Workspace>>())
        .unwrap();
    assert!(std::ptr::eq(exact, returned));
    assert_point_original(&cell, &original);
    assert!(cell.close_failure.get().is_none());
    assert_strict_repeated_drain(&fixture, 2);
    assert_point_original(&cell, &original);
    assert!(
        kasumi_store::RegisteredNodeRead::retained(
            fixture.node.persistent_disk().memory().clone(),
            reader,
        )
        .is_none()
    );
    drop(prepared);
    remove_only_injected_unknown(&fixture, &cell);
    drop(error);
    drop(cell);
    drop(probe);
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        baseline
    );
    fixture.close().await
}

#[tokio::test]
async fn selected_sources_actual_point_drop_panic_still_cancels_queued_reader() -> Result<()> {
    let fixture = Fixture::new().await?;
    let baseline = fixture.storage.admission.snapshot().live_reservations;
    let probe = Probe::begin(fixture.storage.admission.memory());
    let original = Arc::new(PointRetirementOriginal);
    let (prepared, _) = prepare_actual_entry(&fixture, &probe, &original)?;
    let cell = prepared.cell.clone();
    let reader = prepared
        .queued
        .as_ref()
        .unwrap()
        .registered_reader_id()
        .unwrap();
    assert!(std::panic::catch_unwind(AssertUnwindSafe(|| drop(prepared))).is_ok());
    assert!(probe.fired(), "actual installed lease fault did not run");
    assert!(cell.failure.get().is_none());
    assert!(cell.close_failure.get().is_none());
    assert!(!cell.state.lock().unwrap().preparing);
    assert!(
        kasumi_store::RegisteredNodeRead::retained(
            fixture.node.persistent_disk().memory().clone(),
            reader,
        )
        .is_none()
    );
    assert_eq!(
        fixture
            .node
            .persistent_disk()
            .memory()
            .storage_census()
            .snapshot()
            .readers,
        0
    );
    assert_point_original(&cell, &original);
    assert_strict_repeated_drain(&fixture, 1);
    assert_point_original(&cell, &original);
    remove_only_injected_unknown(&fixture, &cell);
    drop(cell);
    drop(probe);
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        baseline
    );
    fixture.close().await
}

#[path = "application_source_incoming_points_tests.rs"]
mod incoming_tests;
