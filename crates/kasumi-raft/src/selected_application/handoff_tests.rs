//! Actual Entry sink, transferred encrypted point backing and queued selected root.
use super::{fixture::*, *};
use crate::{ApplyPublisher, SelectionPreparer};
use kasumi_store::{NodeDiskMemoryAdmission, PreparedTenantStorageReadView};

struct Capture<'a> {
    fixture: &'a Fixture,
    plan: Option<PreparedSelectionPlan>,
    points: Option<PreparedTenantPointWorkspace>,
    queued: Option<PreparedTenantStorageReadView>,
    proof: Option<Workspace>,
}
impl<'a> Capture<'a> {
    fn new(fixture: &'a Fixture) -> Self {
        Self {
            fixture,
            plan: None,
            points: None,
            queued: None,
            proof: None,
        }
    }
}
impl SelectionPreparer for Capture<'_> {
    fn prepare(
        &mut self,
        plan: &PreparedSelectionPlan,
        points: PreparedTenantPointWorkspace,
    ) -> Result<()> {
        assert!(self.plan.is_none());
        // Producer's old planning reader has already settled. The five actual
        // point leases outlive it and move into this preparation before queue.
        assert_eq!(self.fixture.memory.storage_census().snapshot().readers, 0);
        plan.require_stores(&self.fixture.stores)?;
        self.plan = Some(plan.clone());
        self.points = Some(points);
        let mut proof = self.fixture.memory.workspace(1024 + plan.peak_bytes());
        proof.ensure_peak(plan.peak_bytes())?;
        self.proof = Some(proof);
        self.queued = Some(self.fixture.stores.prepare_read_view()?);
        Ok(())
    }
}
fn publish(
    fixture: &Fixture,
    position: &crate::AppliedEntryContext,
    capture: &mut Capture<'_>,
) -> Result<()> {
    let response = crate::AppliedResponse::application(Vec::new());
    let expected =
        crate::PublicationExpectation::for_entry(&fixture.stores, position, &[], &response)?;
    let mut sink =
        crate::apply_publication::EntryPublicationSink::new(&fixture.stores, position, None, false);
    let mut publication = crate::apply_publication::ApplyPublication::new_with_selection(&mut sink);
    let receipt =
        publication.commit_with_selection(response, &[], capture, expected.challenge()?)?;
    expected.consume(
        receipt,
        capture.plan.as_ref().context("producer plan absent")?,
    )?;
    publication.finish(Ok(()))?;
    Ok(())
}

#[tokio::test]
async fn prepared_capture_actual_entry_uses_transferred_loans_when_new_installed_grants_are_denied()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let first = entry(0);
    let mut capture = Capture::new(&fixture);
    publish(&fixture, &first, &mut capture)?;
    let queued = capture.queued.take().context("queued reader absent")?;
    let id = queued.registered_reader_id();
    let view = queued.begin()?;
    assert_eq!(view.registered_reader_id(), id);
    // Publish a newer Entry only after selecting the capture root. Its exact
    // canonical proof must still bind the first publication, never reopen current.
    let later = entry(1);
    crate::control::prepare_applied(&fixture.stores, &later, None)?
        .publish(&fixture.stores, &[])?;
    let requests = fixture.memory.installed_requests();
    fixture.memory.deny_installed(true);
    let result = selected_application_at_prepared(
        &view,
        ApplicationBoundaryRef::Entry(&first),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        capture.proof.take().unwrap(),
        capture.plan.as_ref().unwrap(),
        capture.points.as_mut().unwrap(),
    );
    fixture.memory.deny_installed(false);
    let proof = result?;
    assert_eq!(
        fixture.memory.installed_requests(),
        requests,
        "capture requested fresh native/output backing"
    );
    assert!(
        matches!(proof.applied(), Some(SelectedAppliedRef::Entry { log_id, .. }) if log_id == first.log_id)
    );
    assert!(!proof.is_covered_reconstruction());
    drop(proof);
    drop(capture.points.take());
    view.close()?;
    drop(capture);
    fixture.close().await
}

#[tokio::test]
async fn prepared_capture_actual_entry_preserves_access_failure_and_drops_queued_ownership()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let position = entry(0);
    let baseline = fixture.memory.snapshot();
    let mut capture = Capture::new(&fixture);
    publish(&fixture, &position, &mut capture)?;
    let view = capture.queued.take().unwrap().begin()?;
    fixture.stores.custody().store().seal();
    let requests = fixture.memory.installed_requests();
    fixture.memory.deny_installed(true);
    let failure = selected_application_at_prepared(
        &view,
        ApplicationBoundaryRef::Entry(&position),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        capture.proof.take().unwrap(),
        capture.plan.as_ref().unwrap(),
        capture.points.as_mut().unwrap(),
    )
    .err()
    .context("sealed peer authorized capture")?;
    fixture.memory.deny_installed(false);
    assert_eq!(
        failure.original_error().to_string(),
        "tenant is sealed: key-access lease unavailable or expired"
    );
    assert_eq!(fixture.memory.installed_requests(), requests);
    assert_eq!(
        fixture.memory.snapshot().proof_slots,
        1,
        "failed proof retains its actual original-error grant"
    );
    drop(failure);
    drop(capture.points.take());
    view.close()?;
    drop(capture);
    assert_eq!(fixture.memory.snapshot().slots, baseline.slots);
    fixture.close().await
}
