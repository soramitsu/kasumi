//! Real Entry planning includes prior control reads and transfers its backing.
use super::{fixture::*, *};
use crate::{ApplyPublisher, SelectionPreparer};
use kasumi_store::NodeDiskMemoryAdmission;

struct Capture<'a> {
    fixture: &'a Fixture,
    baseline: u64,
    plan: Option<PreparedSelectionPlan>,
    points: Option<PreparedTenantPointWorkspace>,
}
impl SelectionPreparer for Capture<'_> {
    fn prepare(
        &mut self,
        plan: &PreparedSelectionPlan,
        points: PreparedTenantPointWorkspace,
    ) -> Result<()> {
        assert_eq!(self.fixture.memory.storage_census().snapshot().readers, 0);
        let quote = self.fixture.stores.quote_read_memory()?;
        let peak = self.fixture.memory.snapshot().peak_bytes - self.baseline;
        assert!(
            peak <= plan.planning_read_peak_bytes(&quote)?,
            "actual planning overlap exceeds quote"
        );
        self.plan = Some(plan.clone());
        self.points = Some(points);
        Ok(())
    }
}
fn publish<'a>(fixture: &'a Fixture, position: &crate::AppliedEntryContext) -> Result<Capture<'a>> {
    fixture.memory.reset_peak();
    let mut capture = Capture {
        fixture,
        baseline: fixture.memory.snapshot().bytes,
        plan: None,
        points: None,
    };
    let response = crate::AppliedResponse::application(Vec::new());
    let expected =
        crate::PublicationExpectation::for_entry(&fixture.stores, position, &[], &response)?;
    let mut sink =
        crate::apply_publication::EntryPublicationSink::new(&fixture.stores, position, None, false);
    let mut publication = crate::apply_publication::ApplyPublication::new_with_selection(&mut sink);
    let receipt =
        publication.commit_with_selection(response, &[], &mut capture, expected.challenge()?)?;
    expected.consume(
        receipt,
        capture.plan.as_ref().context("actual plan missing")?,
    )?;
    publication.finish(Ok(()))?;
    Ok(capture)
}

#[tokio::test]
async fn control_planning_sizes_ordinary_entry_from_required_rows_and_ignores_unused_snapshot()
-> Result<()> {
    let fixture = Fixture::new().await?;
    // This unrelated stale row is deliberately not a valid snapshot manifest.
    // An advancing Entry has no reason to load or allocate for it.
    fixture
        .stores
        .application()
        .write_batch(&[kasumi_store::WriteOp::put(
            "raft.snapshot",
            b"current",
            vec![1; 512 << 10],
        )])?;
    let position = entry(0);
    let mut capture = publish(&fixture, &position)?;
    let plan = capture.plan.as_ref().unwrap();
    let phases = plan.planning_phases();
    assert_eq!(phases[0].2, 0);
    assert!(phases[1].2 < 1024);
    assert_eq!(phases[1], phases[2]);
    let view = fixture.stores.read_view()?;
    let requests = fixture.memory.installed_requests();
    fixture.memory.deny_installed(true);
    let result = selected_application_at_prepared(
        &view,
        ApplicationBoundaryRef::Entry(&position),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        plan,
        capture.points.as_mut().unwrap(),
    );
    fixture.memory.deny_installed(false);
    let proof = result?;
    assert_eq!(fixture.memory.installed_requests(), requests);
    assert!(!proof.is_covered_reconstruction());
    drop(proof);
    drop(capture);
    view.close()?;
    fixture.close().await
}

#[tokio::test]
async fn control_planning_reuses_historical_membership_and_rejects_exact_association_corruption()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let membership = openraft::Membership::new(
        vec![std::collections::BTreeSet::from([1])],
        std::collections::BTreeMap::from([(1, BasicNode::new("historical-peer".repeat(4096)))]),
    );
    let first_entry = crate::Entry::<crate::TypeConfig> {
        initialization: None,
        log_id: entry(0).log_id,
        payload: openraft::EntryPayload::Membership(membership.clone()),
    };
    let encoded = crate::storage::encode_entry(&first_entry)?;
    let (header, _) = crate::control::LogHeader::build(&first_entry, &encoded)?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[kasumi_store::WriteOp::put(
            crate::control::HEADERS,
            first_entry.log_id.index.to_be_bytes(),
            serde_json::to_vec(&header)?,
        )])?;
    let first = crate::AppliedEntryContext {
        log_id: first_entry.log_id,
        previous: None,
        membership: StoredMembership::new(Some(first_entry.log_id), membership.clone()),
        command_sha256: crate::command::sha256(&encoded),
        retirement_seed: None,
    };
    drop(publish(&fixture, &first)?);
    let mut later = entry(1);
    later.membership = first.membership.clone();
    let capture = publish(&fixture, &later)?;
    let phases = capture.plan.as_ref().unwrap().planning_phases();
    assert!((32 << 10..256 << 10).contains(&phases[1].2));
    assert_eq!(phases[1], phases[2]);
    drop(capture);
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[kasumi_store::WriteOp::put(
            META,
            crate::initialization_association::ANCHOR,
            serde_json::to_vec(&Some("different"))?,
        )])?;
    let mut next = entry(2);
    next.membership = first.membership;
    let error = crate::control::prepare_applied_and_selection(&fixture.stores, &next, None, &[])
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("initialization association anchor differs"));
    drop(error);
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    fixture.close().await
}

#[tokio::test]
async fn control_planning_covered_snapshot_keeps_five_record_capture_prepared() -> Result<()> {
    let fixture = Fixture::new().await?;
    let snapshot = install_snapshot(&fixture, 4)?;
    let earlier = entry(0);
    let mut capture = publish(&fixture, &earlier)?;
    let plan = capture.plan.as_ref().unwrap();
    assert!(plan.planning_phases()[2].2 < 4096);
    let view = fixture.stores.read_view()?;
    let requests = fixture.memory.installed_requests();
    fixture.memory.deny_installed(true);
    let result = selected_application_at_prepared(
        &view,
        ApplicationBoundaryRef::Entry(&earlier),
        ApplicationSelectionMode::Reconstructing,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        plan,
        capture.points.as_mut().unwrap(),
    );
    fixture.memory.deny_installed(false);
    let proof = result?;
    assert_eq!(fixture.memory.installed_requests(), requests);
    assert_eq!(proof.snapshot().unwrap().meta, &snapshot.meta);
    assert!(proof.is_covered_reconstruction());
    drop(proof);
    drop(capture);
    view.close()?;
    fixture.close().await
}

#[tokio::test]
async fn initial_planning_uses_actual_small_root_and_ignores_unused_snapshot_rows() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture
        .stores
        .application()
        .write_batch(&[kasumi_store::WriteOp::put(
            "raft.snapshot",
            b"current",
            vec![1; 512 << 10],
        )])?;
    fixture.memory.reset_peak();
    let before = fixture.memory.snapshot().bytes;
    let (plan, mut points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    let phases = plan.planning_phases();
    assert_eq!(phases[0].2, 0);
    assert!(phases[1].2 < 1024);
    assert_eq!(phases[1], phases[2]);
    assert!(plan.peak_bytes() < 256 << 10);
    assert!(
        fixture.memory.snapshot().peak_bytes - before
            <= plan.planning_read_peak_bytes(&fixture.stores.quote_read_memory()?)?
    );
    let view = fixture.stores.read_view()?;
    let requests = fixture.memory.installed_requests();
    fixture.memory.deny_installed(true);
    let result = selected_application_at_prepared(
        &view,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Reconstructing,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
        &mut points,
    );
    fixture.memory.deny_installed(false);
    let proof = result?;
    assert_eq!(fixture.memory.installed_requests(), requests);
    assert_eq!(proof.bootstrap().digest, fixture.image.sha256());
    assert!(proof.applied().is_none());
    drop((proof, points));
    view.close()?;
    fixture.close().await
}

#[tokio::test]
async fn initial_planning_binds_snapshot_five_records_and_rejects_later_cursor_change() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let snapshot = install_snapshot(&fixture, 4)?;
    let (plan, mut points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    assert!(plan.planning_phases()[2].2 < 4096);
    let old = fixture.stores.read_view()?;
    let requests = fixture.memory.installed_requests();
    fixture.memory.deny_installed(true);
    let result = selected_application_at_prepared(
        &old,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Reconstructing,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
        &mut points,
    );
    fixture.memory.deny_installed(false);
    let proof = result?;
    assert_eq!(fixture.memory.installed_requests(), requests);
    assert_eq!(proof.snapshot().unwrap().meta, &snapshot.meta);
    assert!(proof.is_covered_reconstruction());
    drop(proof);
    let changed = crate::control::AppliedCursor::Entry(entry(4).record());
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[kasumi_store::WriteOp::put(
            META,
            b"applied",
            serde_json::to_vec(&changed)?,
        )])?;
    let current = fixture.stores.read_view()?;
    let failure = selected_application_at_prepared(
        &current,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Reconstructing,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
        &mut points,
    )
    .err()
    .context("intervening cursor change accepted")?;
    assert!(
        failure
            .original_error()
            .to_string()
            .contains("selected record differs from prospective publication")
    );
    drop((failure, points));
    old.close()?;
    current.close()?;
    fixture.close().await
}

#[tokio::test]
async fn initial_planning_snapshot_row_selection_does_not_accept_noncanonical_cursor() -> Result<()>
{
    let fixture = Fixture::new().await?;
    install_snapshot(&fixture, 4)?;
    let canonical = fixture
        .stores
        .custody()
        .store()
        .get(META, b"applied")?
        .unwrap();
    assert!(canonical.starts_with(br#"{"Snapshot":"#));
    let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
    noncanonical.push(b' ');
    noncanonical.extend_from_slice(&canonical);
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[kasumi_store::WriteOp::put(META, b"applied", noncanonical)])?;
    let (plan, mut points) = PreparedSelectionPlan::for_current_root(&fixture.stores)?;
    assert!(plan.record(false, META, b"snapshot_coverage").is_err());
    assert!(plan.record(true, "raft.snapshot", b"current").is_err());
    let view = fixture.stores.read_view()?;
    let failure = selected_application_at_prepared(
        &view,
        ApplicationBoundaryRef::Bootstrap(&fixture.image),
        ApplicationSelectionMode::Reconstructing,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
        &mut points,
    )
    .err()
    .context("noncanonical Snapshot cursor accepted")?;
    assert!(failure.original_error().to_string().contains("canonical"));
    drop((failure, points));
    view.close()?;
    fixture.close().await
}
