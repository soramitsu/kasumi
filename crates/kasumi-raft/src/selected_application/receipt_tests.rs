use super::{fixture::*, *};
use crate::{
    AppliedResponse, ApplyPublisher, JointPublicationReceipt, PublicationExpectation,
    PublicationExpectationError, SelectionPreparer,
};
use kasumi_store::WriteOp;

#[derive(Default)]
struct Prepared(Option<PreparedSelectionPlan>);
impl SelectionPreparer for Prepared {
    fn prepare(
        &mut self,
        plan: &PreparedSelectionPlan,
        _points: kasumi_store::PreparedTenantPointWorkspace,
    ) -> Result<()> {
        ensure!(self.0.is_none(), "test callback repeated");
        self.0 = Some(plan.clone());
        Ok(())
    }
}
fn publish<'call>(
    fixture: &Fixture,
    position: &crate::AppliedEntryContext,
    writes: &[WriteOp],
    response: AppliedResponse,
    expectation: &'call PublicationExpectation<'_>,
) -> Result<(JointPublicationReceipt<'call>, PreparedSelectionPlan)> {
    let mut prepared = Prepared::default();
    let mut sink =
        crate::apply_publication::EntryPublicationSink::new(&fixture.stores, position, None, false);
    let mut publication = crate::apply_publication::ApplyPublication::new_with_selection(&mut sink);
    // The receipt lifetime must not retain either mutable borrow: finish the
    // publisher and move the prepared plan while the receipt is still alive.
    let publisher: &mut dyn ApplyPublisher = &mut publication;
    let receipt = publisher.commit_with_selection(
        response,
        writes,
        &mut prepared,
        expectation.challenge()?,
    )?;
    publication.finish(Ok(()))?;
    Ok((receipt, prepared.0.context("actual callback absent")?))
}
fn empty() -> AppliedResponse {
    AppliedResponse::application(Vec::new())
}

#[tokio::test]
async fn invocation_receipt_authenticates_advance_and_identical_covered_replays() -> Result<()> {
    let fixture = Fixture::new().await?;
    let first = entry(0);
    let later = entry(1);
    for position in [&first, &later] {
        let response = empty();
        let expectation =
            PublicationExpectation::for_entry(&fixture.stores, position, &[], &response)?;
        let (receipt, plan) = publish(&fixture, position, &[], response, &expectation)?;
        expectation.consume(receipt, &plan)?;
        assert!(matches!(
            expectation.challenge(),
            Err(PublicationExpectationError::Repeated)
        ));
    }
    let writes = [WriteOp::put(
        "receipt.fixture",
        b"row",
        b"new application".to_vec(),
    )];
    let response = empty();
    let old_expectation =
        PublicationExpectation::for_entry(&fixture.stores, &first, &writes, &response)?;
    let (old_receipt, old_plan) = publish(&fixture, &first, &writes, response, &old_expectation)?;
    let response = empty();
    let next_expectation =
        PublicationExpectation::for_entry(&fixture.stores, &first, &writes, &response)?;
    let (next_receipt, next_plan) =
        publish(&fixture, &first, &writes, response, &next_expectation)?;
    assert_eq!(
        old_plan.publication_fingerprint([0; 32], [0; 32]),
        next_plan.publication_fingerprint([0; 32], [0; 32]),
        "receipt identity test requires exactly equal plan/effect contents"
    );
    assert_eq!(
        next_expectation.consume(old_receipt, &next_plan),
        Err(PublicationExpectationError::ForeignInvocation)
    );
    assert_eq!(
        next_expectation.consume(next_receipt, &next_plan),
        Err(PublicationExpectationError::WrongPhase),
        "failed committed verification must remain rejected"
    );
    assert_eq!(
        fixture
            .stores
            .application()
            .get_bounded("receipt.fixture", b"row", 64)?
            .as_deref(),
        Some(b"new application".as_slice())
    );
    let view = fixture.stores.read_view()?;
    let proof = selected_application_at_planned(
        &view,
        ApplicationBoundaryRef::Entry(&first),
        ApplicationSelectionMode::Reconstructing,
        &RaftLimits::default(),
        fixture.memory.workspace(1024 + next_plan.peak_bytes()),
        &next_plan,
    )?;
    assert!(
        matches!(proof.applied(), Some(SelectedAppliedRef::Entry { log_id, .. }) if log_id == later.log_id)
    );
    drop(proof);
    view.close()?;
    drop(old_plan);
    drop(next_plan);
    fixture.close().await
}

#[tokio::test]
async fn invocation_receipt_consumes_covered_replay_with_changed_and_empty_effects() -> Result<()> {
    let fixture = Fixture::new().await?;
    let first = entry(0);
    let later = entry(1);
    let before = [WriteOp::put("receipt.fixture", b"row", b"before".to_vec())];
    crate::control::prepare_applied(&fixture.stores, &first, None)?
        .publish(&fixture.stores, &before)?;
    crate::control::prepare_applied(&fixture.stores, &later, None)?
        .publish(&fixture.stores, &[])?;
    let old = fixture.stores.read_view()?;
    let original_cursor = old
        .custody_get(META, b"applied", CONTROL_BYTES)?
        .context("actual applied cursor absent")?;
    let changed = [WriteOp::put("receipt.fixture", b"row", b"after".to_vec())];
    let mut changed_digest = None;
    for writes in [changed.as_slice(), &[]] {
        // Establish this fixture is actually on the covered path; the named
        // sink independently prepares/publishes its own real producer below.
        let prepared = crate::control::prepare_applied(&fixture.stores, &first, None)?;
        assert!(matches!(
            prepared,
            crate::control::PreparedApplied::CoveredReplay { snapshot: false }
        ));
        drop(prepared);
        let response = empty();
        let expected =
            PublicationExpectation::for_entry(&fixture.stores, &first, writes, &response)?;
        let (receipt, plan) = publish(&fixture, &first, writes, response, &expected)?;
        expected.consume(receipt, &plan)?;
        assert!(matches!(
            expected.challenge(),
            Err(PublicationExpectationError::Repeated)
        ));
        if writes.is_empty() {
            assert_ne!(changed_digest, Some(plan.joint_effects_fingerprint()));
        } else {
            changed_digest = Some(plan.joint_effects_fingerprint());
        }
        let current = fixture.stores.read_view()?;
        assert_eq!(
            current
                .application_get("receipt.fixture", b"row", 64)?
                .as_deref(),
            Some(b"after".as_slice())
        );
        assert_eq!(
            old.application_get("receipt.fixture", b"row", 64)?
                .as_deref(),
            Some(b"before".as_slice())
        );
        assert_eq!(
            current
                .custody_get(META, b"applied", CONTROL_BYTES)?
                .as_deref(),
            Some(original_cursor.as_slice())
        );
        let proof = selected_application_at_planned(
            &current,
            ApplicationBoundaryRef::Entry(&first),
            ApplicationSelectionMode::Reconstructing,
            &RaftLimits::default(),
            fixture.memory.workspace(1024 + plan.peak_bytes()),
            &plan,
        )?;
        assert!(proof.is_covered_reconstruction());
        assert!(
            matches!(proof.applied(), Some(SelectedAppliedRef::Entry { log_id, .. }) if log_id == later.log_id)
        );
        drop(proof);
        current.close()?;
        drop(plan);
    }
    old.close()?;
    fixture.close().await
}

#[tokio::test]
async fn invocation_receipt_reentrant_early_consume_cannot_change_entered_mint_state() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let first = entry(0);
    let later = entry(1);
    let response = empty();
    let old = PublicationExpectation::for_entry(&fixture.stores, &first, &[], &response)?;
    let (foreign, old_plan) = publish(&fixture, &first, &[], response, &old)?;
    let response = empty();
    let expected = PublicationExpectation::for_entry(&fixture.stores, &later, &[], &response)?;
    struct Reentrant<'a, 'env> {
        expected: &'a PublicationExpectation<'env>,
        foreign: Option<JointPublicationReceipt<'a>>,
        plan: Option<PreparedSelectionPlan>,
    }
    impl SelectionPreparer for Reentrant<'_, '_> {
        fn prepare(
            &mut self,
            plan: &PreparedSelectionPlan,
            _points: kasumi_store::PreparedTenantPointWorkspace,
        ) -> Result<()> {
            assert_eq!(
                self.expected
                    .consume(self.foreign.take().context("foreign receipt absent")?, plan),
                Err(PublicationExpectationError::WrongPhase)
            );
            self.plan = Some(plan.clone());
            Ok(())
        }
    }
    let mut preparer = Reentrant {
        expected: &expected,
        foreign: Some(foreign),
        plan: None,
    };
    let mut receipt = None;
    crate::with_application_publisher_for_test(&fixture.stores, &later, |publisher| {
        receipt = Some(publisher.commit_with_selection(
            response,
            &[],
            &mut preparer,
            expected.challenge()?,
        )?);
        Ok(())
    })?;
    let plan = preparer.plan.take().context("actual plan absent")?;
    expected.consume(receipt.context("actual receipt absent")?, &plan)?;
    drop(preparer);
    drop(old_plan);
    drop(plan);
    fixture.close().await
}

#[tokio::test]
async fn invocation_receipt_rejects_pair_context_response_and_ordered_effect_substitution_before_effects()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let foreign = Fixture::new().await?;
    let actual = entry(0);
    let writes = [
        WriteOp::put("receipt.fixture", b"a", b"one".to_vec()),
        WriteOp::delete("receipt.fixture", b"b"),
    ];
    for fault in 0..8 {
        let mut expected_position = actual.clone();
        match fault {
            1 => expected_position.command_sha256 = "f".repeat(64),
            2 => expected_position.previous = Some(entry(9).log_id),
            7 => {
                expected_position.membership = StoredMembership::new(
                    Some(actual.log_id),
                    openraft::Membership::new(
                        vec![std::collections::BTreeSet::from([1, 2])],
                        std::collections::BTreeMap::from([
                            (1, openraft::BasicNode::new("one")),
                            (2, openraft::BasicNode::new("two")),
                        ]),
                    ),
                )
            }
            _ => {}
        }
        let expected_writes = match fault {
            3 => vec![writes[1].clone(), writes[0].clone()],
            4 => vec![
                writes[0].clone(),
                WriteOp::put("receipt.fixture", b"b", Vec::new()),
            ],
            5 => vec![writes[0].clone(), writes[1].clone(), writes[1].clone()],
            _ => writes.to_vec(),
        };
        let expected_response =
            AppliedResponse::application(if fault == 6 { vec![7] } else { Vec::new() });
        let expected_stores = if fault == 0 {
            &foreign.stores
        } else {
            &fixture.stores
        };
        let expected = PublicationExpectation::for_entry(
            expected_stores,
            &expected_position,
            &expected_writes,
            &expected_response,
        )?;
        let mut prepared = Prepared::default();
        let mut sink = crate::apply_publication::EntryPublicationSink::new(
            &fixture.stores,
            &actual,
            None,
            false,
        );
        let mut publication =
            crate::apply_publication::ApplyPublication::new_with_selection(&mut sink);
        assert!(matches!(
            publication.commit_with_selection(
                empty(),
                &writes,
                &mut prepared,
                expected.challenge()?
            ),
            Err(crate::PublishCallError::Failed)
        ));
        let original = publication
            .finish(Ok(()))
            .err()
            .context("substitution succeeded")?;
        assert_eq!(
            original.downcast_ref::<PublicationExpectationError>(),
            Some(&PublicationExpectationError::BindingMismatch)
        );
        assert!(
            prepared.0.is_none(),
            "substitution reached source admission"
        );
        assert!(
            fixture
                .stores
                .custody()
                .store()
                .get_bounded(META, b"applied", CONTROL_BYTES)?
                .is_none()
        );
        assert!(
            fixture
                .stores
                .application()
                .get_bounded("receipt.fixture", b"a", 16)?
                .is_none()
        );
    }
    foreign.close().await?;
    fixture.close().await
}

#[tokio::test]
async fn invocation_receipt_rejects_concrete_retirement_seed_and_response_fields_before_effects()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let (command, seed) = crate::control::tests::seed()?;
    // Both seeds come from the real producer for the same command. Changing a
    // source budget input changes the seed while preserving the primary Entry
    // fingerprint, exercising the additional actual-context binding.
    let mut other_source = seed.source().clone();
    other_source.snapshot_bytes += 1;
    let other_seed = crate::RetirementLogSeed::prepare(&command, other_source)?;
    assert_eq!(seed.command_sha256(), other_seed.command_sha256());
    let mut actual = entry(0);
    actual.command_sha256 = seed.command_sha256().into();
    actual.retirement_seed = Some(seed.clone());
    let receipt = kasumi_types::RetirementReceipt {
        tenant: seed.source().tenant.clone(),
        principal: "owner".into(),
        retirement_id: seed.request().retirement_id.clone(),
        request_digest: seed.request().reference()?.request_digest,
        source_incarnation: seed.source().incarnation.clone(),
        target_incarnation: seed.request().target_incarnation.clone(),
        revision: 1,
        policy_epoch: 2,
        admitted_at_ms: 123,
        checkpoint: seed.request().checkpoint.clone(),
        closure_digest: "4".repeat(64),
    };
    receipt.validate()?;
    let writes = [WriteOp::put(
        "receipt.fixture",
        b"retirement",
        b"must stay absent".to_vec(),
    )];
    for fault in 0..3 {
        let mut expected_position = actual.clone();
        let mut expected_retirement = receipt.clone();
        match fault {
            0 => expected_position.retirement_seed = Some(other_seed.clone()),
            1 => expected_retirement.closure_digest = "5".repeat(64),
            2 => expected_retirement.checkpoint.manifest_ciphertext_sha256 = "6".repeat(64),
            _ => unreachable!(),
        }
        expected_retirement.validate()?;
        let expected_response = AppliedResponse {
            data: vec![7],
            retirement: Some(expected_retirement),
        };
        let expected = PublicationExpectation::for_entry(
            &fixture.stores,
            &expected_position,
            &writes,
            &expected_response,
        )?;
        let actual_response = AppliedResponse {
            data: vec![7],
            retirement: Some(receipt.clone()),
        };
        let mut prepared = Prepared::default();
        let mut sink = crate::apply_publication::EntryPublicationSink::new(
            &fixture.stores,
            &actual,
            None,
            false,
        );
        let mut publication =
            crate::apply_publication::ApplyPublication::new_with_selection(&mut sink);
        assert!(matches!(
            publication.commit_with_selection(
                actual_response,
                &writes,
                &mut prepared,
                expected.challenge()?
            ),
            Err(crate::PublishCallError::Failed)
        ));
        let original = publication
            .finish(Ok(()))
            .err()
            .context("retirement substitution succeeded")?;
        // This concrete marker proves the sink refused at challenge entry,
        // before seed/custody preparation could fail for this metadata fixture.
        assert_eq!(
            original.downcast_ref::<PublicationExpectationError>(),
            Some(&PublicationExpectationError::BindingMismatch)
        );
        assert!(prepared.0.is_none());
        assert!(
            fixture
                .stores
                .custody()
                .store()
                .get_bounded(META, b"applied", CONTROL_BYTES)?
                .is_none()
        );
        assert!(
            fixture
                .stores
                .custody()
                .store()
                .get_bounded(META, b"retired_boundary", CONTROL_BYTES)?
                .is_none()
        );
        assert!(
            fixture
                .stores
                .application()
                .get_bounded("receipt.fixture", b"retirement", 64)?
                .is_none()
        );
    }
    // This is an early content-binding refusal test using concrete real
    // producer metadata, not proof of a successful tenant retirement.
    fixture.close().await
}

#[tokio::test]
async fn invocation_receipt_binds_the_actual_preparer_plan_and_joint_effects() -> Result<()> {
    let fixture = Fixture::new().await?;
    let position = entry(0);
    let prior = crate::control::prepare_applied(&fixture.stores, &position, None)?;
    let other_writes = [WriteOp::put("receipt.fixture", b"row", b"other".to_vec())];
    let other_plan = PreparedSelectionPlan::for_applied(&fixture.stores, &prior, &other_writes)?;
    drop(prior);
    let writes = [WriteOp::put("receipt.fixture", b"row", b"right".to_vec())];
    let response = empty();
    let expected =
        PublicationExpectation::for_entry(&fixture.stores, &position, &writes, &response)?;
    let (receipt, actual_plan) = publish(&fixture, &position, &writes, response, &expected)?;
    assert_ne!(
        other_plan.joint_effects_fingerprint(),
        actual_plan.joint_effects_fingerprint()
    );
    assert_eq!(
        expected.consume(receipt, &other_plan),
        Err(PublicationExpectationError::BindingMismatch)
    );
    drop(other_plan);
    drop(actual_plan);
    fixture.close().await
}

#[tokio::test]
async fn invocation_receipt_fixed_inputs_hash_and_authentic_consume_allocate_nothing() -> Result<()>
{
    let fixture = Fixture::new().await?;
    // Quote-only concrete serializer coverage: populated membership, real
    // retirement seed, and concrete response receipt. This mints no authority.
    let (_, seed) = crate::control::tests::seed()?;
    let mut rich = entry(0);
    rich.command_sha256 = seed.command_sha256().into();
    rich.membership = StoredMembership::new(
        Some(rich.log_id),
        openraft::Membership::new(
            vec![std::collections::BTreeSet::from([1, 2])],
            std::collections::BTreeMap::from([
                (1, openraft::BasicNode::new("one\"東京")),
                (2, openraft::BasicNode::new("two")),
            ]),
        ),
    );
    let retirement = kasumi_types::RetirementReceipt {
        tenant: seed.source().tenant.clone(),
        principal: "owner".into(),
        retirement_id: seed.request().retirement_id.clone(),
        request_digest: seed.request().reference()?.request_digest,
        source_incarnation: seed.source().incarnation.clone(),
        target_incarnation: seed.request().target_incarnation.clone(),
        revision: 1,
        policy_epoch: 2,
        admitted_at_ms: 123,
        checkpoint: seed.request().checkpoint.clone(),
        closure_digest: "4".repeat(64),
    };
    rich.retirement_seed = Some(seed);
    let rich_response = AppliedResponse {
        data: vec![7; 4096],
        retirement: Some(retirement),
    };
    let _rich_expected = allocation_tests::require_no_allocations(|| {
        PublicationExpectation::for_entry(&fixture.stores, &rich, &[], &rich_response)
    })?;
    let position = entry(0);
    let writes = [WriteOp::put("receipt.fixture", b"row", vec![0x44; 4096])];
    let response = AppliedResponse::application(vec![0x55; 1024]);
    let expected = allocation_tests::require_no_allocations(|| {
        PublicationExpectation::for_entry(&fixture.stores, &position, &writes, &response)
    })?;
    let challenge = allocation_tests::require_no_allocations(|| expected.challenge())?;
    assert!(matches!(
        expected.challenge(),
        Err(PublicationExpectationError::Repeated)
    ));
    let mut prepared = Prepared::default();
    let mut receipt = None;
    crate::with_application_publisher_for_test(&fixture.stores, &position, |publisher| {
        receipt =
            Some(publisher.commit_with_selection(response, &writes, &mut prepared, challenge)?);
        Ok(())
    })?;
    let plan = prepared.0.take().context("actual plan absent")?;
    let receipt = receipt.context("actual receipt absent")?;
    allocation_tests::require_no_allocations(|| expected.consume(receipt, &plan))?;
    drop(plan);
    fixture.close().await
}
