//! Real Engine Cell/DTO credit, real protected native roots and one reused
//! encrypted backing. These tests install the closed construction seam directly;
//! actor/recovery acceptance coverage remains a separate production prerequisite.
use super::*;

fn envelope(fixture: &Fixture) -> Result<kasumi_raft::PreparedOrdinarySourceEnvelope> {
    let bootstrap = kasumi_store::ApplicationBootstrapManifest {
        format: 2,
        bytes: fixture.image.len(),
        chunks: fixture
            .image
            .len()
            .div_ceil(kasumi_store::APPLICATION_BOOTSTRAP_CHUNK_BYTES as u64),
        digest: fixture.image.sha256().into(),
    };
    kasumi_raft::PreparedOrdinarySourceEnvelope::for_membership(
        &fixture.stores,
        &bootstrap,
        &kasumi_raft::StoredMembership::default(),
    )
}
fn prepared(fixture: &Fixture) -> Result<RootPreparation> {
    let (plan, points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    let mut points = Some(points);
    let prepared = fixture
        .roots
        .prepare_kind_planned(true, Some(&plan), &mut points)?;
    assert!(points.is_none());
    Ok(prepared)
}
fn all_slots(fixture: &Fixture) -> Vec<Reservation> {
    let mut pressure = Vec::new();
    while let Ok(grant) = fixture.storage.admission.reserve_resident(0) {
        pressure.push(grant);
    }
    assert!(
        fixture
            .storage
            .admission
            .reserve_document_source(0)
            .is_err()
    );
    pressure
}
fn read_payload(fixture: &Fixture, selected: &SelectedApplication) -> Result<Option<Vec<u8>>> {
    let view = selected
        .cell
        .state
        .lock()
        .unwrap()
        .protected_view
        .as_ref()
        .unwrap()
        .clone();
    let cohort = fixture.roots.cohort.get().unwrap();
    let mut points = cohort.take_points()?;
    let result = (|| {
        Ok(view
            .point_reads(&mut points)?
            .application_get("hot", b"key", 64)?
            .map(<[u8]>::to_vec))
    })();
    cohort.return_points(points);
    result
}

#[tokio::test]
async fn source_cohort_real_capture_has_no_new_grant_under_complete_slot_refusal() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.roots.install_source_cohort(envelope(&fixture)?)?;
    let preparation = prepared(&fixture)?;
    let native_id = preparation.queued_source.as_ref().unwrap().reader_id();
    let pressure = all_slots(&fixture);
    let before = fixture.storage.admission.snapshot();
    let selected = preparation.capture(ApplicationBoundaryRef::Bootstrap(&fixture.image), false)?;
    let after = fixture.storage.admission.snapshot();
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    assert!(selected.cell.state.lock().unwrap().view.is_none());
    assert_eq!(
        selected
            .cell
            .state
            .lock()
            .unwrap()
            .protected_view
            .as_ref()
            .unwrap()
            .registered_reader_id(),
        native_id
    );
    assert_eq!(
        selected.cell.position.get().unwrap().bootstrap().digest,
        fixture.image.sha256()
    );
    drop(pressure);
    drop(selected);
    assert!(
        kasumi_store::RegisteredNodeRead::retained(
            fixture.node.persistent_disk().memory().clone(),
            native_id
        )
        .is_none()
    );
    fixture.close().await
}

#[tokio::test]
async fn source_cohort_public_history_refusal_preserves_current_and_then_funds_real_reuse()
-> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.roots.install_source_cohort(envelope(&fixture)?)?;
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put("hot", b"key", b"old".to_vec())],
        &[],
    )?;
    let old =
        prepared(&fixture)?.capture(ApplicationBoundaryRef::Bootstrap(&fixture.image), false)?;
    let old_lane = old.cell._reservation.publication_lane().unwrap();
    let old_id = old
        .cell
        .state
        .lock()
        .unwrap()
        .protected_view
        .as_ref()
        .unwrap()
        .registered_reader_id();
    let pressure = all_slots(&fixture);
    let before = fixture.storage.admission.snapshot();
    assert!(old.retain_public_history().is_err());
    assert!(!old.cell._reservation.is_history());
    assert!(!old.cell.capture_failed());
    assert_eq!(
        old.cell
            .state
            .lock()
            .unwrap()
            .protected_view
            .as_ref()
            .unwrap()
            .history_disposition(),
        kasumi_store::SourceHistoryDisposition::Current
    );
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(read_payload(&fixture, &old)?, Some(b"old".to_vec()));
    drop(pressure);
    let before_history = fixture.storage.admission.snapshot();
    old.retain_public_history()?;
    assert!(old.cell._reservation.is_history());
    let retained = fixture.storage.admission.snapshot();
    assert!(retained.reserved_bytes > before_history.reserved_bytes);
    assert!(retained.live_reservations > before_history.live_reservations);
    old.retain_public_history()?;
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        retained.reserved_bytes
    );
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        retained.live_reservations
    );
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put("hot", b"key", b"new".to_vec())],
        &[],
    )?;
    let next =
        prepared(&fixture)?.capture(ApplicationBoundaryRef::Bootstrap(&fixture.image), false)?;
    assert_eq!(next.cell._reservation.publication_lane(), Some(old_lane));
    assert_eq!(
        old.cell
            .state
            .lock()
            .unwrap()
            .protected_view
            .as_ref()
            .unwrap()
            .registered_reader_id(),
        old_id
    );
    let pressure = all_slots(&fixture);
    let before = fixture.storage.admission.snapshot();
    assert_eq!(read_payload(&fixture, &old)?, Some(b"old".to_vec()));
    assert_eq!(read_payload(&fixture, &next)?, Some(b"new".to_vec()));
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        before.live_reservations
    );
    drop(pressure);
    drop((old, next));
    fixture.close().await
}

#[tokio::test]
async fn source_cohort_unused_preparation_returns_exact_native_right_and_backing() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.roots.install_source_cohort(envelope(&fixture)?)?;
    let unused = prepared(&fixture)?;
    let id = unused.queued_source.as_ref().unwrap().reader_id();
    let lane = unused.cell._reservation.publication_lane();
    drop(unused);
    assert!(
        kasumi_store::RegisteredNodeRead::retained(
            fixture.node.persistent_disk().memory().clone(),
            id
        )
        .is_none()
    );
    let retry = prepared(&fixture)?;
    assert_eq!(retry.cell._reservation.publication_lane(), lane);
    assert_ne!(retry.queued_source.as_ref().unwrap().reader_id(), id);
    let selected = retry.capture(ApplicationBoundaryRef::Bootstrap(&fixture.image), false)?;
    drop(selected);
    fixture.close().await
}

#[tokio::test]
async fn source_cohort_pre_cell_cancellation_returns_actual_backing_and_unused_ticket() -> Result<()>
{
    let fixture = Fixture::new().await?;
    fixture.roots.install_source_cohort(envelope(&fixture)?)?;
    let cohort = fixture.roots.cohort.get().unwrap();
    let before = fixture.storage.admission.snapshot();
    let pending = cohort.prepare_loan()?;
    let lane = pending.credit().publication_lane();
    assert!(cohort.take_points().is_err());
    assert!(fixture.roots.gate.lock().unwrap().cells.is_empty());
    // This is the same guard used through the late gate/identifier checks. No
    // native request has entered, so cancellation can return its unused ticket.
    drop(pending);
    let retry = cohort.prepare_loan()?;
    assert_eq!(retry.credit().publication_lane(), lane);
    drop(retry);
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        before.live_reservations
    );
    let selected =
        prepared(&fixture)?.capture(ApplicationBoundaryRef::Bootstrap(&fixture.image), false)?;
    drop(selected);
    fixture.close().await
}

#[tokio::test]
async fn source_cohort_close_retires_actual_capacity_and_workspaces_before_drained() -> Result<()> {
    let fixture = Fixture::new().await?;
    let before = fixture.storage.admission.snapshot();
    fixture.roots.install_source_cohort(envelope(&fixture)?)?;
    assert!(fixture.storage.admission.snapshot().live_reservations > before.live_reservations);
    let selected =
        prepared(&fixture)?.capture(ApplicationBoundaryRef::Bootstrap(&fixture.image), false)?;
    drop(selected);
    assert!(matches!(drain(&fixture.roots), Poll::Ready(Ok(()))));
    assert!(fixture.roots.is_drained());
    assert!(fixture.roots.cohort.get().unwrap().take_points().is_err());
    let census = fixture
        .node
        .persistent_disk()
        .memory()
        .storage_census()
        .snapshot();
    assert_eq!(census.source_pools, 0);
    assert_eq!(census.readers, 0);
    let after = fixture.storage.admission.snapshot();
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    fixture.close().await
}

#[tokio::test]
async fn source_cohort_partial_admission_keeps_original_until_actual_fields_retire() -> Result<()> {
    let fixture = Fixture::new().await?;
    // This real construction has its own caller-held root; it has not escaped
    // into the fixture's already-bound startup owner or begun any selection.
    let (roots, binding) = SourceRoots::new(
        fixture.stores.clone(),
        fixture.storage.admission.clone(),
        RaftLimits::default(),
    )?;
    // Source grants preserve the independent cache-work slot floor. Saturate
    // this actual class, then release exactly one of its admitted slots: the
    // lane bank can enter, while the next transient source grant must refuse.
    let mut pressure = Vec::new();
    while let Ok(grant) = fixture.storage.admission.reserve_document_source(0) {
        pressure.push(grant);
    }
    assert!(
        fixture
            .storage
            .admission
            .reserve_document_source(0)
            .is_err()
    );
    drop(
        pressure
            .pop()
            .expect("one real source slot for the lane bank"),
    );
    let before = fixture.storage.admission.snapshot();
    let error = roots
        .install_source_cohort(envelope(&fixture)?)
        .unwrap_err();
    assert!(roots.gate.lock().unwrap().cells.is_empty());
    let saved = roots.construction_failure.get().unwrap();
    let original = saved
        .owner
        .original
        .downcast_ref::<cohort::CohortAdmissionRefusal>()
        .unwrap();
    let returned = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<cohort::CohortAdmissionRefusal>())
        .unwrap();
    assert!(std::ptr::eq(original, returned));
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        before.live_reservations + 1
    );
    let Poll::Ready(Err(first)) = drain(&roots) else {
        panic!("partial construction did not settle");
    };
    assert_eq!(first.completion(), DrainCompletion::Complete);
    assert!(roots.is_drained());
    assert_eq!(
        fixture.storage.admission.snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        before.reserved_bytes
    );
    let Poll::Ready(Err(second)) = drain(&roots) else {
        panic!("original admission failure lost");
    };
    assert_eq!(second.completion(), DrainCompletion::Complete);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &first.issues()[0],
        &second.issues()[0]
    ));
    drop((first, second, error, binding, roots, pressure));
    fixture.close().await
}

#[tokio::test]
async fn source_capacity_close_yields_to_actual_report_guard_then_retires_exact_owner() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let before = fixture.storage.admission.snapshot();
    let capacity = fixture.stores.queue_source_capacity()?.install()?;
    let id = capacity.owner_id();
    let capacity = capacity.with_report_held_for_test(|capacity| {
        // This would deadlock with close's former blocking report() observation.
        let kasumi_store::SourceCapacityClose::Pending(capacity) = capacity.close() else {
            panic!("a held actual pool report did not keep the same pending owner");
        };
        assert_eq!(capacity.owner_id(), id);
        capacity
    });
    let kasumi_store::SourceCapacityClose::Retiring(retirement) = capacity.close() else {
        panic!("unused real pool did not finish after report release");
    };
    assert_eq!(retirement.id(), id);
    assert_eq!(
        retirement.retry(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    assert!(!retirement.has_terminal_failure());
    assert_eq!(
        retirement.retry(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    assert_eq!(
        fixture
            .node
            .persistent_disk()
            .memory()
            .storage_census()
            .snapshot()
            .source_pools,
        0
    );
    let after = fixture.storage.admission.snapshot();
    assert_eq!(after.reserved_bytes, before.reserved_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    fixture.close().await
}
