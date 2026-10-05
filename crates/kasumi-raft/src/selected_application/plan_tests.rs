use super::{fixture::*, *};
use crate::{ApplyPublisher, SelectionPreparer};

struct Prepared<'a> {
    stores: &'a kasumi_store::TenantStorageSet,
    plan: Option<PreparedSelectionPlan>,
    deny: bool,
}
#[derive(Debug)]
struct PreparationDenied;
impl std::fmt::Display for PreparationDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original preparation denial")
    }
}
impl std::error::Error for PreparationDenied {}
impl SelectionPreparer for Prepared<'_> {
    fn prepare(
        &mut self,
        plan: &PreparedSelectionPlan,
        _points: kasumi_store::PreparedTenantPointWorkspace,
    ) -> Result<()> {
        assert!(self.plan.is_none());
        ensure!(
            self.stores
                .custody()
                .store()
                .get_bounded(META, b"applied", CONTROL_BYTES)?
                .is_none(),
            "callback ran after actual publication"
        );
        self.plan = Some(plan.clone());
        if self.deny {
            return Err(PreparationDenied.into());
        }
        Ok(())
    }
}

#[derive(Default)]
struct AdvancingOnly {
    calls: usize,
    accepted: usize,
    plan: Option<PreparedSelectionPlan>,
}
impl SelectionPreparer for AdvancingOnly {
    fn prepare(
        &mut self,
        plan: &PreparedSelectionPlan,
        _points: kasumi_store::PreparedTenantPointWorkspace,
    ) -> Result<()> {
        self.calls += 1;
        assert!(self.plan.is_none());
        self.plan = Some(plan.clone());
        plan.require_advancing_entry()?;
        self.accepted += 1;
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prospective_advancing_origin_refuses_real_exact_replay_before_application_effects()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let position = entry(0);
    let mut sink = crate::apply_publication::EntryPublicationSink::new(
        &fixture.stores,
        &position,
        None,
        false,
    );
    let mut advancing = AdvancingOnly::default();
    let mut publication = crate::apply_publication::ApplyPublication::new_with_selection(&mut sink);
    let response = crate::AppliedResponse::application(Vec::new());
    let expectation =
        crate::PublicationExpectation::for_entry(&fixture.stores, &position, &[], &response)?;
    let receipt = publication.commit_with_selection(
        response,
        &[],
        &mut advancing,
        expectation.challenge()?,
    )?;
    expectation.consume(
        receipt,
        advancing.plan.as_ref().context("advance plan absent")?,
    )?;
    publication.finish(Ok(()))?;
    assert_eq!((advancing.calls, advancing.accepted), (1, 1));

    let (namespace, key, maximum) = crate::primary_applied_cursor_read_spec_for_test();
    assert_eq!(
        (namespace, key, maximum),
        (crate::control::META, b"applied".as_slice(), CONTROL_BYTES)
    );
    let before = fixture
        .stores
        .custody()
        .store()
        .get_bounded(namespace, key, maximum)?;
    assert!(before.is_some());

    // The real producer still permits application writes on CoveredReplay.
    // The mandatory origin check must stop those writes, even though this
    // exact-current replay remains a valid non-reconstructing read source.
    let writes = [kasumi_store::WriteOp::Put {
        namespace: "primary.origin-probe".into(),
        key: b"never".to_vec(),
        value: b"published".to_vec(),
    }];
    let mut replay = AdvancingOnly::default();
    let mut publication = crate::apply_publication::ApplyPublication::new_with_selection(&mut sink);
    let response = crate::AppliedResponse::application(Vec::new());
    let expectation =
        crate::PublicationExpectation::for_entry(&fixture.stores, &position, &writes, &response)?;
    assert!(matches!(
        publication.commit_with_selection(response, &writes, &mut replay, expectation.challenge()?),
        Err(crate::PublishCallError::Failed)
    ));
    let original = publication
        .finish(Ok(()))
        .err()
        .context("exact replay admitted primary effects")?;
    assert_eq!(
        original.to_string(),
        "primary publication requires an advancing Entry"
    );
    assert_eq!((replay.calls, replay.accepted), (1, 0));
    assert!(
        fixture
            .stores
            .application()
            .get_bounded("primary.origin-probe", b"never", 32)?
            .is_none()
    );
    assert_eq!(
        fixture
            .stores
            .custody()
            .store()
            .get_bounded(namespace, key, maximum)?,
        before
    );
    let plan = replay.plan.take().context("actual replay plan absent")?;
    assert_eq!(
        plan.clone()
            .require_advancing_entry()
            .unwrap_err()
            .to_string(),
        original.to_string()
    );

    let view = fixture.stores.read_view()?;
    let proof = selected_application_at_planned(
        &view,
        ApplicationBoundaryRef::Entry(&position),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
    )?;
    assert!(!proof.is_covered_reconstruction());
    assert!(
        matches!(proof.applied(), Some(SelectedAppliedRef::Entry { log_id, .. }) if log_id == position.log_id)
    );
    drop(proof);
    drop(plan);
    drop(original);
    drop(advancing);
    view.close()?;
    fixture.close().await
}

#[tokio::test]
async fn prospective_callback_prepares_before_real_producer_publication_and_keeps_original_refusal()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let position = entry(0);
    let mut sink = crate::apply_publication::EntryPublicationSink::new(
        &fixture.stores,
        &position,
        None,
        false,
    );
    let mut rejected = Prepared {
        stores: &fixture.stores,
        plan: None,
        deny: true,
    };
    let mut publication = crate::apply_publication::ApplyPublication::new_with_selection(&mut sink);
    let response = crate::AppliedResponse::application(Vec::new());
    let expectation =
        crate::PublicationExpectation::for_entry(&fixture.stores, &position, &[], &response)?;
    assert!(matches!(
        publication.commit_with_selection(response, &[], &mut rejected, expectation.challenge()?),
        Err(crate::PublishCallError::Failed)
    ));
    let failure = publication
        .finish(Ok(()))
        .err()
        .context("missing refusal")?;
    assert!(failure.downcast_ref::<PreparationDenied>().is_some());
    assert!(
        fixture
            .stores
            .custody()
            .store()
            .get_bounded(META, b"applied", CONTROL_BYTES)?
            .is_none()
    );
    drop(failure);
    drop(rejected);
    let mut accepted = Prepared {
        stores: &fixture.stores,
        plan: None,
        deny: false,
    };
    let mut publication = crate::apply_publication::ApplyPublication::new_with_selection(&mut sink);
    let response = crate::AppliedResponse::application(Vec::new());
    let expectation =
        crate::PublicationExpectation::for_entry(&fixture.stores, &position, &[], &response)?;
    let receipt = publication.commit_with_selection(
        response,
        &[],
        &mut accepted,
        expectation.challenge()?,
    )?;
    expectation.consume(
        receipt,
        accepted.plan.as_ref().context("missing actual plan")?,
    )?;
    publication.finish(Ok(()))?;
    let plan = accepted.plan.take().context("missing actual plan")?;
    assert!(
        plan.peak_bytes() < 1 << 20,
        "tiny producer still reserved the 2MiB read-limit floor"
    );
    let view = fixture.stores.read_view()?;
    let proof = selected_application_at_planned(
        &view,
        ApplicationBoundaryRef::Entry(&position),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
    )?;
    assert!(proof.retained_workspace_bytes() <= plan.retained_bytes());
    drop(proof);
    drop(plan);
    view.close()?;
    fixture.close().await
}

#[tokio::test]
async fn prospective_plan_rejects_later_actual_record_and_foreign_domain_pair() -> Result<()> {
    let fixture = Fixture::new().await?;
    let first = entry(0);
    let pending = crate::control::prepare_applied(&fixture.stores, &first, None)?;
    let plan = PreparedSelectionPlan::for_applied(&fixture.stores, &pending, &[])?;
    pending.publish(&fixture.stores, &[])?;
    let old = fixture.stores.read_view()?;
    let mut substituted = entry(0);
    substituted.command_sha256 = "f".repeat(64);
    fixture
        .stores
        .write_batch(&[], &[crate::control::applied_write(&substituted)?])?;
    let latest = fixture.stores.read_view()?;
    let failure = selected_application_at_planned(
        &latest,
        ApplicationBoundaryRef::Entry(&first),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
    )
    .err()
    .context("later record accepted")?;
    assert!(
        failure
            .original_error()
            .to_string()
            .contains("prospective publication")
    );
    drop(failure);
    let proof = selected_application_at_planned(
        &old,
        ApplicationBoundaryRef::Entry(&first),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
    )?;
    drop(proof);
    let foreign = Fixture::new().await?;
    assert!(plan.require_stores(&foreign.stores).is_err());
    let view = foreign.stores.read_view()?;
    let failure = selected_application_at_planned(
        &view,
        ApplicationBoundaryRef::Entry(&first),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        foreign.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
    )
    .err()
    .context("foreign domains accepted")?;
    assert!(
        failure
            .original_error()
            .to_string()
            .contains("another storage pair")
    );
    drop(failure);
    view.close()?;
    foreign.close().await?;
    drop(plan);
    old.close()?;
    latest.close()?;
    fixture.close().await
}

#[tokio::test]
async fn prospective_covered_replay_quotes_actual_newer_cursor() -> Result<()> {
    let fixture = Fixture::new().await?;
    let first = entry(0);
    let later = entry(1);
    crate::control::prepare_applied(&fixture.stores, &first, None)?
        .publish(&fixture.stores, &[])?;
    crate::control::prepare_applied(&fixture.stores, &later, None)?
        .publish(&fixture.stores, &[])?;
    let pending = crate::control::prepare_applied(&fixture.stores, &first, None)?;
    assert!(matches!(
        pending,
        crate::control::PreparedApplied::CoveredReplay { snapshot: false }
    ));
    let plan = PreparedSelectionPlan::for_applied(&fixture.stores, &pending, &[])?;
    assert_eq!(
        plan.require_advancing_entry().unwrap_err().to_string(),
        "primary publication requires an advancing Entry"
    );
    pending.publish(&fixture.stores, &[])?;
    let view = fixture.stores.read_view()?;
    let proof = selected_application_at_planned(
        &view,
        ApplicationBoundaryRef::Entry(&first),
        ApplicationSelectionMode::Reconstructing,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
    )?;
    assert!(
        matches!(proof.applied(), Some(SelectedAppliedRef::Entry { log_id, .. }) if log_id == later.log_id)
    );
    assert!(proof.is_covered_reconstruction());
    drop(proof);
    drop(plan);
    view.close()?;
    fixture.close().await
}

#[test]
fn producer_wire_shape_overquotes_actual_decoder_for_escaped_unicode_and_nested_metadata()
-> Result<()> {
    for value in [
        serde_json::json!({"entry":{"membership":[[1,2,3],[2,3,4]],"nodes":{"1":{"addr":"x\\\"\n\t\u{0000}東京😀"}}}}),
        serde_json::json!([null, true, false, 0, -1, 1.25, "", {}, [], "\\\\\\\\"]),
        serde_json::json!({"long": "\u{007f}".repeat(4096)}),
    ] {
        let bytes = serde_json::to_vec(&value)?;
        let planned = allocation::canonical_wire_quote(&bytes)?;
        let decoded = allocation::decode_quote(&bytes)?;
        assert!(planned.peak >= decoded.peak);
        assert!(planned.retained >= decoded.retained);
    }
    Ok(())
}

#[tokio::test]
async fn prospective_covered_snapshot_uses_actual_five_record_proof() -> Result<()> {
    let fixture = Fixture::new().await?;
    let context = install_snapshot(&fixture, 4)?;
    let earlier = entry(0);
    let pending = crate::control::prepare_applied(&fixture.stores, &earlier, None)?;
    assert!(matches!(
        pending,
        crate::control::PreparedApplied::CoveredReplay { snapshot: true }
    ));
    let (plan, mut points) =
        PreparedSelectionPlan::for_applied_prepared(&fixture.stores, &pending, &[])?;
    assert_eq!(
        plan.require_advancing_entry().unwrap_err().to_string(),
        "primary publication requires an advancing Entry"
    );
    pending.publish(&fixture.stores, &[])?;
    let view = fixture.stores.read_view()?;
    let requests = fixture.memory.installed_requests();
    fixture.memory.deny_installed(true);
    let result = selected_application_at_prepared(
        &view,
        ApplicationBoundaryRef::Entry(&earlier),
        ApplicationSelectionMode::Reconstructing,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + plan.peak_bytes()),
        &plan,
        &mut points,
    );
    fixture.memory.deny_installed(false);
    let proof = result?;
    assert_eq!(
        fixture.memory.installed_requests(),
        requests,
        "five-record snapshot capture acquired a new installed grant"
    );
    assert_eq!(proof.snapshot().unwrap().meta, &context.meta);
    assert!(proof.is_covered_reconstruction());
    assert!(proof.retained_workspace_bytes() <= plan.retained_bytes());
    drop(proof);
    drop(plan);
    drop(points);
    view.close()?;
    fixture.close().await
}

#[test]
fn producer_wire_quote_covers_arbitrary_numbers_without_reclassifying_literal_markers() -> Result<()>
{
    // Standalone numbers prevent unrelated string/structural overquotation from
    // hiding a missing synthetic key/value or numeric-string allocation.
    for bytes in [
        b"1.25".as_slice(),
        b"1e+300",
        b"-0.0",
        b"18446744073709551616",
        b"-9223372036854775809",
        b"18446744073709551615",
        b"-9223372036854775808",
        br#"{"$serde_json::private::Number":"1.25"}"#,
        br#"{"n":1.25,"literal":{"$serde_json::private::Number":"1.25"}}"#,
    ] {
        let value: serde_json::Value = serde_json::from_slice(bytes)?;
        if bytes.first() == Some(&b'{') {
            assert!(value.is_object(), "literal marker became a number");
        }
        let canonical = serde_json::to_vec(&value)?;
        let planned = allocation::canonical_wire_quote(&canonical)?;
        let decoded = allocation::decode_quote(&canonical)?;
        assert!(planned.peak >= decoded.peak);
        assert!(planned.retained >= decoded.retained);
    }
    let digits = "9".repeat(4096);
    let value: serde_json::Value = serde_json::from_str(&digits)?;
    assert!(value.is_number());
    let bytes = serde_json::to_vec(&value)?;
    let planned = allocation::canonical_wire_quote(&bytes)?;
    let decoded = allocation::decode_quote(&bytes)?;
    assert!(planned.peak >= decoded.peak);
    assert!(planned.retained >= decoded.retained);
    Ok(())
}
