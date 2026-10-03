//! Actual ordinary backend/sink publication; the frozen negative separately
//! installs test state and never claims authentic retirement or serving.
use super::*;
use kasumi_raft::{AppliedInput, ApplyPublisher, StateMachineBackend as _};

fn apply(fixture: &Fixture, input: &CommandInput) -> Result<AppliedResponse> {
    kasumi_raft::with_application_publisher_bound_for_test(
        &fixture._buffers,
        &fixture.stores,
        &input.position,
        |publisher| {
            fixture.engine.apply_with_publisher(
                &input.position,
                AppliedInput::Command(&input.bytes),
                publisher,
            )
        },
    )
}
fn selected(fixture: &Fixture, input: &CommandInput) -> Result<()> {
    let current = fixture.engine.generation()?;
    let (_, fingerprint, revision) = current
        .application_selection
        .get()
        .context("source absent")?
        .primary_read_proof(current.state.revision_base)?;
    assert_eq!(
        fingerprint,
        decode(records::boundary::producer(ApplicationBoundaryRef::Entry(
            &input.position,
        )))?
    );
    assert_eq!(revision, current.state.revision);
    assert_eq!(
        revision,
        current.state.revision_base + input.position.log_id.index
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordered_command_real_sink_publishes_acceptance_rejection_and_idempotent_outcome()
-> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.seed(1, false)?;
    let old = fixture.engine.generation()?;
    let input1 = fixture.command(puts(
        "ordinary-envelope",
        vec![("docs".into(), id(0, false), json!({"accepted":true}))],
    ))?;
    let response1 = apply(&fixture, &input1)?;
    assert!(response1.retirement.is_none());
    let receipt: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response1.data)?;
    let receipt = receipt?;
    assert_eq!(receipt.revision, 3);
    selected(&fixture, &input1)?;
    let accepted = fixture.engine.generation()?;
    assert_eq!(
        accepted.state.collections["docs"].documents[&id(0, false)].version,
        3
    );
    assert_eq!(
        old.state.collections["docs"].documents[&id(0, false)].version,
        2
    );
    let input2 = fixture.command(Operation::Mutate(MutationBatch {
        idempotency_key: "ordinary-rejected".into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id(0, false),
            body: json!({"rejected":true}),
            expected: Precondition::Version(2),
        }],
    }))?;
    let response2 = apply(&fixture, &input2)?;
    assert!(response2.retirement.is_none());
    let rejected: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response2.data)?;
    assert_eq!(rejected.unwrap_err().code, ErrorCode::Conflict);
    selected(&fixture, &input2)?;
    let after_rejection = fixture.engine.generation()?;
    assert_eq!(after_rejection.state.revision, 4);
    assert_eq!(
        after_rejection.state.collections["docs"].documents[&id(0, false)].version,
        3
    );
    assert!(Arc::ptr_eq(&accepted.indexes, &after_rejection.indexes));
    let input3 = fixture.command(puts(
        "ordinary-envelope",
        vec![("docs".into(), id(0, false), json!({"accepted":true}))],
    ))?;
    let response3 = apply(&fixture, &input3)?;
    let replay: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response3.data)?;
    assert_eq!(replay?.revision, receipt.revision);
    selected(&fixture, &input3)?;
    let observed = fixture.engine.generation()?;
    assert_eq!(observed.state.revision, 5);
    assert_eq!(
        observed.state.mutation_receipt_head,
        after_rejection.state.mutation_receipt_head
    );
    assert_eq!(
        observed.state.collections["docs"].documents[&id(0, false)].body,
        json!({"accepted":true})
    );
    drop(observed);
    drop(after_rejection);
    drop(accepted);
    drop(old);
    drop(input3);
    drop(response3);
    drop(input2);
    drop(response2);
    drop(input1);
    drop(response1);
    drop(receipt);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordered_command_real_sink_rejects_full_context_substitution_after_preparation()
-> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.seed(1, false)?;
    let old = fixture.engine.generation()?;
    let input = fixture.command(puts(
        "context-mismatch",
        vec![("docs".into(), id(0, false), json!({"next":true}))],
    ))?;
    let mut sink_position = input.position.clone();
    sink_position.log_id = openraft::LogId::new(
        openraft::CommittedLeaderId::new(2, 1),
        input.position.log_id.index,
    );
    let failure = kasumi_raft::with_application_publisher_bound_for_test(
        &fixture._buffers,
        &fixture.stores,
        &sink_position,
        |publisher| {
            fixture.engine.apply_with_publisher(
                &input.position,
                AppliedInput::Command(&input.bytes),
                publisher,
            )
        },
    )
    .err()
    .context("different actual sink context acknowledged")?;
    let inspected = fixture
        ._buffers
        .try_with_retained_apply_report(|report| {
            let kasumi_raft::RetainedApplyReport::Ordinary(report) = report else {
                panic!("source-installed ordinary failure must retain its canonical report");
            };
            let kasumi_raft::ApplyObservationRef::Error(original) = report.sink else {
                panic!("actual sink original absent");
            };
            assert!(original.chain().any(|cause| {
                cause.downcast_ref::<kasumi_raft::PublicationExpectationError>()
                    == Some(&kasumi_raft::PublicationExpectationError::BindingMismatch)
            }));
            assert!(report.response.is_some());
        })
        .expect("uncontended retained report");
    assert!(inspected.is_some(), "{failure:?}");
    assert!(Arc::ptr_eq(&old, &fixture.engine.generation()?));
    let cursor = fixture
        .stores
        .custody()
        .store()
        .get_bounded("raft.meta", b"applied", 2 << 20)?
        .context("cursor absent")?;
    // Compare the actual old cursor bytes using the old captured native source,
    // rather than treating the raw command digest as full-context authority.
    let mut grant = fixture.storage.admission.reserve_document_source(4096)?;
    let mut reader = old
        .application_selection
        .get()
        .unwrap()
        .open_primary_reader(&fixture.roots)?;
    let fingerprint = reader.primary_applied_cursor_fingerprint(&mut grant, 4096)?;
    assert_eq!(fingerprint, (cursor.len(), Sha256::digest(&cursor).into()));
    reader.close()?;
    drop(grant);
    drop(cursor);
    drop(failure);
    drop(sink_position);
    drop(input);
    drop(old);
    // A failed real outer finish is terminal. Preserve the fixture's physical
    // directory and owners with its retained diagnostic; do not reset the slot.
    std::mem::forget(fixture);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordered_command_frozen_refusal_keeps_actual_guard_and_encoded_sealed_outcome() -> Result<()>
{
    struct Refuse<'a> {
        engine: &'a TenantEngine,
        previous: &'a Arc<Generation>,
        calls: usize,
        response: Option<AppliedResponse>,
    }
    impl ApplyPublisher for Refuse<'_> {
        fn with_completion(
            &mut self,
            _: &kasumi_raft::CompletionIdentity,
            _: &mut dyn kasumi_raft::CompletionAction,
        ) -> std::result::Result<(), kasumi_raft::CompletionCallError> {
            Err(kasumi_raft::CompletionCallError::Unsupported)
        }

        fn commit(
            &mut self,
            response: AppliedResponse,
            writes: &[WriteOp],
        ) -> std::result::Result<(), kasumi_raft::PublishCallError> {
            self.calls += 1;
            assert!(writes.is_empty());
            assert!(matches!(
                self.engine.apply_lock.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            assert!(Arc::ptr_eq(
                self.previous,
                &self.engine.generation().unwrap()
            ));
            self.response = Some(response);
            Err(kasumi_raft::PublishCallError::Failed)
        }
        fn commit_with_selection<'call>(
            &mut self,
            _: AppliedResponse,
            _: &[WriteOp],
            _: &mut dyn kasumi_raft::SelectionPreparer,
            _: kasumi_raft::PublicationChallenge<'call>,
        ) -> std::result::Result<
            kasumi_raft::JointPublicationReceipt<'call>,
            kasumi_raft::PublishCallError,
        > {
            panic!("frozen branch must not create a selected candidate")
        }
    }
    let mut fixture = Fixture::new().await?;
    fixture.engine.seal();
    fixture.engine = TenantEngine::new(
        "cow".into(),
        fixture.engine.incarnation.clone(),
        policy(),
        Limits::default(),
    )?;
    let old = fixture.engine.generation()?;
    // No-source branch fixture only: no completion authority is manufactured.
    // Branch fixture only: this deliberately installs retired state without a
    // retirement proof. The only publisher refuses; no selected/durable or
    // authentic retirement capability can be produced by this setup.
    let mut state = old.state.clone();
    state.retired = true;
    let frozen = Arc::new(Generation {
        state,
        receipts: old.receipts.clone(),
        backup_bindings: old.backup_bindings.clone(),
        terminals: old.terminals.clone(),
        target_resolutions: old.target_resolutions.clone(),
        indexes: old.indexes.clone(),
        snapshot_accounting: old.snapshot_accounting.clone(),
        application_selection: std::sync::OnceLock::new(),
        _read_reservations: vec![],
    });
    fixture.engine.publish_generation(Some(frozen.clone()));
    let input = fixture.command(Operation::SetPolicy(policy()))?;
    let mut publisher = Refuse {
        engine: &fixture.engine,
        previous: &frozen,
        calls: 0,
        response: None,
    };
    let error = fixture
        .engine
        .apply_with_publisher(
            &input.position,
            AppliedInput::Command(&input.bytes),
            &mut publisher,
        )
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<kasumi_raft::PublishCallError>(),
        Some(&kasumi_raft::PublishCallError::Failed)
    );
    assert_eq!(publisher.calls, 1);
    let response = publisher.response.take().unwrap();
    assert!(response.retirement.is_none());
    let outcome: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response.data)?;
    assert_eq!(outcome.unwrap_err().code, ErrorCode::Sealed);
    assert!(fixture.engine.apply_lock.try_lock().is_ok());
    assert!(Arc::ptr_eq(&frozen, &fixture.engine.generation()?));
    let foreign = TenantEngine::new(
        "cow".into(),
        fixture.engine.incarnation.clone(),
        policy(),
        Limits::default(),
    )?;
    let prepared = PreparedOrderedCommand::prepare(
        &fixture.engine,
        ByteBoundCommand::check(&input.position, &input.bytes)?,
    )?;
    let failure = prepared.publish(&foreign, &mut publisher).unwrap_err();
    assert_eq!(failure.to_string(), "apply owner belongs to another engine");
    assert_eq!(publisher.calls, 1);
    assert!(fixture.engine.apply_lock.try_lock().is_ok());
    println!(
        "ordered command layouts: prepared={} accepted={} apply_owner={} response={}",
        std::mem::size_of::<PreparedOrderedCommand<'static, 'static>>(),
        std::mem::size_of::<AcceptedGeneration<'static>>(),
        std::mem::size_of::<ApplyOwner<'static>>(),
        std::mem::size_of::<AppliedResponse>()
    );
    drop(publisher);
    drop(failure);
    drop(foreign);
    drop(error);
    drop(response);
    drop(input);
    drop(frozen);
    drop(old);
    fixture.close().await
}
