//! Receipts cross the actual encrypted application/custody boundary, including
//! failed acknowledgements and physical reopen. No replacement receipt store.
use super::*;
use kasumi_store::WriteOp;

#[derive(Default)]
struct Observation {
    calls: usize,
    receipt_rows: Vec<(String, Vec<u8>, Vec<u8>)>,
    body_writes: usize,
    response: Vec<u8>,
    committed: bool,
}

struct InspectPublication<'a> {
    actual: &'a mut dyn kasumi_raft::ApplyPublisher,
    fixture: &'a OrdinaryFixture,
    previous: &'a Arc<crate::state::Generation>,
    observation: &'a mut Observation,
    expected_rows: usize,
    seal: Option<PublicationSealPhase>,
}
struct InspectAction<'a> {
    actual: &'a mut dyn kasumi_raft::CompletionAction,
    fixture: &'a OrdinaryFixture,
    previous: &'a Arc<crate::state::Generation>,
    observation: &'a mut Observation,
    expected_rows: usize,
    seal: Option<PublicationSealPhase>,
}
impl kasumi_raft::CompletionAction for InspectAction<'_> {
    fn run(
        &mut self,
        invocation: &kasumi_raft::CompletionInvocation<'_>,
        publisher: &mut dyn kasumi_raft::ApplyPublisher,
    ) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
        self.actual.run(
            invocation,
            &mut InspectPublication {
                actual: publisher,
                fixture: self.fixture,
                previous: self.previous,
                observation: self.observation,
                expected_rows: self.expected_rows,
                seal: self.seal,
            },
        )
    }
}
impl kasumi_raft::ApplyPublisher for InspectPublication<'_> {
    fn with_completion(
        &mut self,
        expected: &kasumi_raft::CompletionIdentity,
        action: &mut dyn kasumi_raft::CompletionAction,
    ) -> std::result::Result<(), kasumi_raft::CompletionCallError> {
        self.actual.with_completion(
            expected,
            &mut InspectAction {
                actual: action,
                fixture: self.fixture,
                previous: self.previous,
                observation: self.observation,
                expected_rows: self.expected_rows,
                seal: self.seal,
            },
        )
    }
    fn commit(
        &mut self,
        _: AppliedResponse,
        _: &[WriteOp],
    ) -> std::result::Result<(), kasumi_raft::PublishCallError> {
        panic!("ordinary receipt candidate bypassed selected publication")
    }
    fn commit_with_selection<'call>(
        &mut self,
        response: AppliedResponse,
        writes: &[WriteOp],
        preparer: &mut dyn kasumi_raft::SelectionPreparer,
        challenge: kasumi_raft::PublicationChallenge<'call>,
    ) -> std::result::Result<
        kasumi_raft::JointPublicationReceipt<'call>,
        kasumi_raft::PublishCallError,
    > {
        self.observation.calls += 1;
        assert_eq!(self.observation.calls, 1);
        assert!(Arc::ptr_eq(
            self.previous,
            &self.fixture.engine.generation().unwrap()
        ));
        let application = self.fixture.fixture.stores.application();
        for write in writes {
            let WriteOp::Put {
                namespace,
                key,
                value,
            } = write
            else {
                panic!("unexpected deletion in immutable publication")
            };
            if namespace.starts_with("mutation-receipt-") {
                assert!(
                    application.get(namespace, key).unwrap().is_none(),
                    "new receipt was physically published before its custody callback"
                );
                self.observation
                    .receipt_rows
                    .push((namespace.clone(), key.clone(), value.clone()));
            } else {
                assert!(matches!(
                    namespace.as_str(),
                    crate::document_store::BODIES | crate::document_store::BLOBS
                ));
                self.observation.body_writes += 1;
            }
        }
        assert_eq!(self.observation.receipt_rows.len(), self.expected_rows);
        if self.expected_rows != 0 {
            assert_eq!(
                self.observation
                    .receipt_rows
                    .iter()
                    .filter(|(_, key, _)| key.starts_with(b"id/"))
                    .count(),
                1
            );
            assert_eq!(
                self.observation
                    .receipt_rows
                    .iter()
                    .filter(|(_, key, _)| key.starts_with(b"ordinal/"))
                    .count(),
                1
            );
        }
        self.observation.response.clone_from(&response.data);
        let before = self
            .fixture
            .fixture
            .node
            .fixture_native_generation()
            .unwrap();
        if matches!(self.seal, Some(PublicationSealPhase::BeforeCommit)) {
            application.seal();
        }
        let receipt = self
            .actual
            .commit_with_selection(response, writes, preparer, challenge)?;
        self.observation.committed = true;
        assert_eq!(
            self.fixture
                .fixture
                .node
                .fixture_native_generation()
                .unwrap(),
            before + 1
        );
        for (namespace, key, bytes) in &self.observation.receipt_rows {
            assert_eq!(
                application.get(namespace, key).unwrap().unwrap().as_bytes(),
                bytes
            );
        }
        // Durability does not prematurely publish the candidate or its head.
        assert!(Arc::ptr_eq(
            self.previous,
            &self.fixture.engine.generation().unwrap()
        ));
        if matches!(self.seal, Some(PublicationSealPhase::AfterCommit)) {
            application.seal();
        }
        Ok(receipt)
    }
}

#[allow(
    clippy::result_large_err,
    reason = "Retain the original native publication failure for the recovery fixture."
)]
fn inspect_apply(
    fixture: &OrdinaryFixture,
    input: &Input,
    expected_rows: usize,
    seal: Option<PublicationSealPhase>,
    observation: &mut Observation,
) -> Result<AppliedResponse> {
    let previous = fixture.engine.generation().unwrap();
    kasumi_raft::with_application_publisher_bound_for_test(
        &fixture.fixture._buffers,
        &fixture.fixture.stores,
        &input.position,
        |publisher| {
            fixture.engine.apply_with_publisher(
                &input.position,
                AppliedInput::Command(&input.bytes),
                &mut InspectPublication {
                    actual: publisher,
                    fixture,
                    previous: &previous,
                    observation,
                    expected_rows,
                    seal,
                },
            )
        },
    )
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "Preserve original native fixture failures inline."
)]
async fn ordinary_receipts_share_one_native_commit_for_success_rejection_delete_and_replay()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = OrdinaryFixture::new().await?;
    fixture.apply(
        &fixture.input(Operation::CreateCollection(definition()))?,
        || {},
    )?;
    let accepted_operation = put(
        "joint-success",
        json!({"proof": "a".repeat(8192)}),
        Precondition::Absent,
    );
    let cases = [
        (accepted_operation.clone(), "joint-success", 2, true, None),
        (
            put("joint-rejection", json!(false), Precondition::Any),
            "joint-rejection",
            2,
            false,
            Some(ErrorCode::SchemaViolation),
        ),
        (
            Operation::Mutate(MutationBatch {
                idempotency_key: "joint-delete".into(),
                read_set: vec![],
                operations: vec![Mutation::Delete {
                    collection: "docs".into(),
                    id: "row".into(),
                    expected: Precondition::Any,
                }],
            }),
            "joint-delete",
            2,
            false,
            None,
        ),
        (accepted_operation, "joint-success", 0, false, None),
    ];
    let mut first_receipt = None;
    for (operation, key, expected_rows, has_bodies, error_code) in cases {
        let previous = fixture.engine.generation()?;
        let old_count = previous.state.mutation_receipt_head.count;
        let before = fixture.fixture.node.fixture_native_generation()?;
        let input = fixture.input(operation)?;
        let command: Command = serde_json::from_slice(&input.bytes)?;
        let before_admission = fixture.fixture.storage.admission.snapshot().reserved_bytes;
        fixture.engine.admit_document_publication(&command)?;
        let admitted =
            fixture.fixture.storage.admission.snapshot().reserved_bytes - before_admission;
        crate::admission::ApplyEscrow::take_last_peak_for_test();
        let mut observed = Observation::default();
        let response = inspect_apply(&fixture, &input, expected_rows, None, &mut observed)?;
        assert_eq!(observed.calls, 1);
        assert!(observed.committed);
        let peak = crate::admission::ApplyEscrow::take_last_peak_for_test()
            .expect("ordinary apply spent its preproposal escrow");
        assert!(
            peak > 0 && peak <= admitted,
            "native/receipt overlap exceeded admission"
        );
        assert_eq!(observed.body_writes > 0, has_bodies);
        // A separate receipt stage would advance this actual native root twice.
        assert_eq!(
            fixture.fixture.node.fixture_native_generation()?,
            before + 1
        );
        let outcome: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response.data)?;
        assert_eq!(outcome.as_ref().err().map(|error| error.code), error_code);
        if key == "joint-success" {
            if let Some(first) = &first_receipt {
                assert_eq!(&outcome, first);
            } else {
                first_receipt = Some(outcome.clone());
            }
        }
        let selected = fixture.engine.generation()?;
        assert_eq!(selected.state.revision, input.position.log_id.index);
        assert_eq!(
            selected.state.mutation_receipt_head.count,
            old_count + u64::from(expected_rows != 0)
        );
        let identity = kasumi_types::staged_digest(&("owner", key))?.0;
        let row = selected
            .receipts
            .get(&identity)?
            .expect("selected exact receipt");
        assert_eq!(row.receipt.outcome, outcome);
        if expected_rows != 0 {
            assert!(previous.receipts.get(&identity)?.is_none());
        }
        if key == "joint-delete" || expected_rows == 0 {
            assert!(
                selected.state.collections["docs"].documents.is_empty(),
                "receipt replay re-applied a deleted document"
            );
        }
        drop(selected);
        drop(previous);
    }
    fixture.close().await
}

#[allow(
    clippy::result_large_err,
    reason = "Reopen retains the original native drain/startup errors."
)]
async fn reopen(
    mut fixture: OrdinaryFixture,
) -> crate::test_fixture_failure::FixtureResult<OrdinaryFixture> {
    fixture.engine.seal();
    require_positive_drain(fixture.fixture._buffers.drain_startup().await);
    require_positive_drain(std::future::poll_fn(|cx| fixture.fixture.roots.poll_drain(cx)).await);
    // Retire these exact startup/source owners. The shared admission registry
    // must remain open for this fixture's physical reopen; final Fixture::close
    // seals and drains that registry after the replacement owner is done.
    fixture.fixture.stores.shutdown().await?;
    fixture.fixture.node.shutdown().await?;
    fixture.fixture.node = fixture.fixture.storage.open_existing(
        fixture.fixture._directory.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
    )?;
    fixture.fixture.stores = TenantStorageSet::open_existing_fixture(
        fixture.fixture.node.clone(),
        "selected-sources".into(),
        Arc::new(LocalKeyProvider::new([119; 32])),
        Arc::new(LocalKeyProvider::new([120; 32])),
    )
    .await?;
    let (roots, binding) = SourceRoots::new(
        fixture.fixture.stores.clone(),
        fixture.fixture.storage.admission.clone(),
        RaftLimits::default(),
    )?;
    let buffers = fixture.fixture.storage.admission.snapshot_buffer_owner()?;
    roots.bind_lifecycle(&buffers, binding)?;
    fixture.fixture.roots = roots;
    fixture.fixture._buffers = buffers;
    drop(fixture.engine);
    OrdinaryFixture::over(fixture.fixture)
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "Preserve failed publication and physical reopen custody inline."
)]
async fn ordinary_receipt_and_cursor_recover_together_before_and_after_publication_failure()
-> crate::test_fixture_failure::FixtureResult<()> {
    for phase in [
        PublicationSealPhase::BeforeCommit,
        PublicationSealPhase::AfterCommit,
    ] {
        let fixture = OrdinaryFixture::new().await?;
        let create = fixture.input(Operation::CreateCollection(definition()))?;
        fixture.apply(&create, || {})?;
        let input = fixture.input(put(
            "uncertain-receipt",
            json!({"proof":"b".repeat(8192)}),
            Precondition::Absent,
        ))?;
        let previous = fixture.engine.generation()?;
        let before = fixture.fixture.node.fixture_native_generation()?;
        let mut observed = Observation::default();
        let original = inspect_apply(&fixture, &input, 2, Some(phase), &mut observed)
            .err()
            .context("failed publication unexpectedly acknowledged")?;
        let committed = matches!(phase, PublicationSealPhase::AfterCommit);
        assert_eq!(observed.committed, committed);
        assert_eq!(
            fixture.fixture.node.fixture_native_generation()?,
            before + u64::from(committed)
        );
        assert_eq!(
            fixture.engine.generation().err().unwrap().code,
            ErrorCode::Sealed
        );
        assert_eq!(previous.state.mutation_receipt_head.count, 0);
        drop(previous);
        drop(original);
        let fixture = reopen(fixture).await?;
        // Read the real reopened encrypted file before replaying either input.
        for (namespace, key, bytes) in &observed.receipt_rows {
            let stored = fixture.fixture.stores.application().get(namespace, key)?;
            assert_eq!(
                stored.as_ref().map(|value| value.as_bytes()),
                committed.then_some(bytes.as_slice())
            );
        }
        let cursor = fixture
            .fixture
            .stores
            .custody()
            .store()
            .get("raft.meta", b"applied")?
            .unwrap();
        let cursor: serde_json::Value = serde_json::from_slice(cursor.as_bytes())?;
        assert_eq!(
            cursor["Entry"]["log_id"]["index"],
            if committed {
                input.position.log_id.index
            } else {
                create.position.log_id.index
            }
        );
        fixture.apply(&create, || {})?;
        let response = fixture.apply(&input, || {})?;
        assert_eq!(
            response.data, observed.response,
            "exact recovery changed the original outcome"
        );
        let selected = fixture.engine.generation()?;
        let identity = kasumi_types::staged_digest(&("owner", "uncertain-receipt"))?.0;
        let receipt = selected.receipts.get(&identity)?.unwrap();
        assert_eq!(selected.state.mutation_receipt_head.count, 1);
        assert_eq!(
            receipt.receipt.recorded_revision,
            input.position.log_id.index
        );
        assert_eq!(
            selected
                .load_document(&selected.state.collections["docs"].documents["row"])?
                .body,
            json!({"proof":"b".repeat(8192)})
        );
        drop(selected);
        // Repeating the same logical request returns its first receipt and does
        // not append another permanent receipt after physical recovery.
        let replay = fixture.input(put(
            "uncertain-receipt",
            json!({"proof":"b".repeat(8192)}),
            Precondition::Absent,
        ))?;
        let response = fixture.apply(&replay, || {})?;
        assert_eq!(response.data, observed.response);
        assert_eq!(
            fixture
                .engine
                .generation()?
                .state
                .mutation_receipt_head
                .count,
            1
        );
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "Preserve original native fixture failures inline."
)]
async fn ordinary_receipt_above_body_operation_envelope_keeps_original_two_commits()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = OrdinaryFixture::new().await?;
    fixture.apply(
        &fixture.input(Operation::CreateCollection(definition()))?,
        || {},
    )?;
    let input = fixture.input(Operation::Mutate(MutationBatch {
        idempotency_key: "outside-joint-envelope".into(),
        read_set: vec![],
        operations: (0..33)
            .map(|n| Mutation::Put {
                collection: "docs".into(),
                id: format!("row-{n}"),
                body: json!({"distinct": n}),
                expected: Precondition::Absent,
            })
            .collect(),
    }))?;
    let before = fixture.fixture.node.fixture_native_generation()?;
    let mut observed = Observation::default();
    let response = inspect_apply(&fixture, &input, 0, None, &mut observed)?;
    assert_eq!(observed.calls, 1);
    assert_eq!(observed.body_writes, 33);
    assert_eq!(
        fixture.fixture.node.fixture_native_generation()?,
        before + 2,
        "out-of-envelope publication changed the original separate receipt stage"
    );
    let outcome: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response.data)?;
    assert_eq!(outcome?.versions.len(), 33);
    let selected = fixture.engine.generation()?;
    assert_eq!(selected.state.mutation_receipt_head.count, 1);
    let key = kasumi_types::staged_digest(&("owner", "outside-joint-envelope"))?.0;
    assert_eq!(
        selected
            .receipts
            .get(&key)?
            .unwrap()
            .receipt
            .recorded_revision,
        selected.state.revision
    );
    drop(selected);
    fixture.close().await
}

#[derive(Clone, Copy, Debug)]
enum OrphanPair {
    Exact,
    NoncanonicalRow,
    RowOnly,
    IndexOnly,
    OversizedIndex,
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "Preserve original orphan-reconciliation failure and reopen custody inline."
)]
async fn ordinary_receipt_private_publication_reconciles_only_exact_orphan_pairs()
-> crate::test_fixture_failure::FixtureResult<()> {
    for case in [
        OrphanPair::Exact,
        OrphanPair::NoncanonicalRow,
        OrphanPair::RowOnly,
        OrphanPair::IndexOnly,
        OrphanPair::OversizedIndex,
    ] {
        let fixture = OrdinaryFixture::new().await?;
        let create = fixture.input(Operation::CreateCollection(definition()))?;
        fixture.apply(&create, || {})?;
        let input = fixture.input(put("orphan-pair", json!({"value":1}), Precondition::Absent))?;
        let mut captured = Observation::default();
        let original = inspect_apply(
            &fixture,
            &input,
            2,
            Some(PublicationSealPhase::BeforeCommit),
            &mut captured,
        )
        .err()
        .context("before-commit failure acknowledged")?;
        assert!(!captured.committed);
        drop(original);
        let fixture = reopen(fixture).await?;
        fixture.apply(&create, || {})?;
        // These are the exact private bytes from the actual producer, captured
        // before any receipt/cursor commit. Emulate an old writer's orphan pair.
        let mut rows = captured.receipt_rows.clone();
        match case {
            OrphanPair::Exact => {}
            OrphanPair::NoncanonicalRow => {
                rows.iter_mut()
                    .find(|(_, key, _)| key.starts_with(b"id/"))
                    .unwrap()
                    .2
                    .push(b' ');
                // Lookup can decode this ahead row and report it unselected;
                // preparation must still reject its nonidentical raw bytes.
            }
            OrphanPair::RowOnly => rows.retain(|(_, key, _)| key.starts_with(b"id/")),
            OrphanPair::IndexOnly => rows.retain(|(_, key, _)| key.starts_with(b"ordinal/")),
            OrphanPair::OversizedIndex => {
                // The ahead ID row remains valid, so the new pair preparation
                // reaches the bounded physical ordinal lookup itself.
                rows.iter_mut()
                    .find(|(_, key, _)| key.starts_with(b"ordinal/"))
                    .unwrap()
                    .2
                    .resize(crate::mutation_receipt::MAX_SNAPSHOT_RECORD_BYTES + 1, b' ');
            }
        }
        fixture.fixture.stores.application().write_batch(
            &rows
                .iter()
                .map(|(namespace, key, value)| WriteOp::put(namespace, key.clone(), value.clone()))
                .collect::<Vec<_>>(),
        )?;
        let before = fixture.fixture.node.fixture_native_generation()?;
        let mut replay = Observation::default();
        let fixture = if matches!(case, OrphanPair::Exact) {
            let response = inspect_apply(&fixture, &input, 0, None, &mut replay)?;
            assert_eq!(response.data, captured.response);
            assert_eq!(replay.calls, 1);
            assert_eq!(
                fixture.fixture.node.fixture_native_generation()?,
                before + 1,
                "exact orphan reuse performed another receipt commit"
            );
            let selected = fixture.engine.generation()?;
            assert_eq!(selected.state.mutation_receipt_head.count, 1);
            let key = kasumi_types::staged_digest(&("owner", "orphan-pair"))?.0;
            assert_eq!(
                selected
                    .receipts
                    .get(&key)?
                    .unwrap()
                    .receipt
                    .recorded_revision,
                input.position.log_id.index
            );
            drop(selected);
            fixture
        } else {
            // OrdinaryAction enters bound completion before preparation. Its
            // arbitrary preparation error deliberately cannot be retired by a
            // fixture reset. Exercise the production preparation directly for
            // corrupt pairs, with the exact row captured from that real action
            // and the reopened encrypted source. Exact reuse above still runs
            // through the full bound action and custody publisher.
            let previous = fixture.engine.generation()?;
            let row: crate::mutation_receipt::Row = serde_json::from_slice(
                &captured
                    .receipt_rows
                    .iter()
                    .find(|(_, key, _)| key.starts_with(b"id/"))
                    .unwrap()
                    .2,
            )?;
            let crate::mutation_receipt::Lookup::Absent(absent) =
                previous.receipts.lookup(&row.key)?
            else {
                panic!("unselected orphan became a committed receipt")
            };
            let mut state = previous.state.clone();
            state.revision = row.applied.revision;
            let pending = crate::mutation_receipt::Pending::prepare(
                &previous.receipts,
                &state,
                Some((row.receipt.clone(), &absent)),
                &row.applied,
            )?;
            assert_eq!(pending.head().sha256, row.sha256()?);
            let original = pending
                .prepare_publication(&fixture.fixture.roots)
                .err()
                .with_context(|| format!("{case:?} orphan was accepted"))?;
            let diagnostic = original.root_cause().to_string();
            match case {
                OrphanPair::NoncanonicalRow => assert_eq!(
                    diagnostic,
                    "future receipt row differs from exact original command replay"
                ),
                OrphanPair::RowOnly | OrphanPair::IndexOnly => {
                    assert_eq!(diagnostic, "partially published receipt row/index");
                }
                OrphanPair::OversizedIndex => {
                    let failure = original
                        .downcast_ref::<kasumi_store::TenantPointReadFailure>()
                        .expect("oversized ordinal retains its native point-read failure");
                    assert_eq!(failure.stage(), "record bytes");
                    assert!(failure.validation_error().is_none());
                    assert!(matches!(
                        failure.reader().report().read_failure(),
                        kasumi_store::TerminalObservation::Returned(Err(
                            kasumi_kv::BoundedReadError::BoundExceeded
                        ))
                    ));
                }
                OrphanPair::Exact => unreachable!(),
            }
            assert!(Arc::ptr_eq(&previous, &fixture.engine.generation()?));
            assert_eq!(
                fixture.fixture.node.fixture_native_generation()?,
                before,
                "corrupt pair caused a physical write before refusal"
            );
            if matches!(case, OrphanPair::OversizedIndex) {
                let reader = original
                    .downcast::<kasumi_store::TenantPointReadFailure>()
                    .expect("checked native point-read failure")
                    .into_reader();
                assert_eq!(reader.finish(), kasumi_store::NodeReadPhase::Finished);
                assert_eq!(
                    reader.retire(),
                    kasumi_store::StorageCensusDisposition::Retired
                );
            } else {
                drop(original);
            }
            drop(previous);
            // Retire this owner and physically reopen before independently
            // inspecting the immutable evidence; no apply owner was reset.
            reopen(fixture).await?
        };
        for (namespace, key, _) in &captured.receipt_rows {
            let expected = rows
                .iter()
                .find(|(name, id, _)| name == namespace && id == key)
                .map(|(_, _, bytes)| bytes.as_slice());
            let actual = fixture.fixture.stores.application().get(namespace, key)?;
            assert_eq!(
                actual.as_ref().map(|value| value.as_bytes()),
                expected,
                "{case:?} changed an immutable orphan row/index"
            );
        }
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
#[allow(
    clippy::result_large_err,
    reason = "Preserve original native fixture failures inline."
)]
async fn ordinary_receipt_above_row_envelope_keeps_original_two_commits()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = OrdinaryFixture::new().await?;
    fixture.apply(
        &fixture.input(Operation::CreateCollection(definition()))?,
        || {},
    )?;
    let input = fixture.input(Operation::Mutate(MutationBatch {
        idempotency_key: "large-receipt-row".into(),
        read_set: vec![],
        operations: (0..160)
            .map(|n| Mutation::Put {
                collection: "docs".into(),
                id: format!("{}{:03}", "/".repeat(253), n),
                body: json!({}),
                expected: Precondition::Absent,
            })
            .collect(),
    }))?;
    let before = fixture.fixture.node.fixture_native_generation()?;
    let mut observed = Observation::default();
    let response = inspect_apply(&fixture, &input, 0, None, &mut observed)?;
    assert_eq!(observed.calls, 1);
    assert_eq!(
        observed.body_writes, 1,
        "identical bodies did not share their immutable object"
    );
    assert_eq!(
        fixture.fixture.node.fixture_native_generation()?,
        before + 2
    );
    let outcome: kasumi_types::Result<WriteReceipt> = serde_json::from_slice(&response.data)?;
    assert_eq!(outcome?.versions.len(), 160);
    let selected = fixture.engine.generation()?;
    assert_eq!(selected.state.mutation_receipt_head.count, 1);
    let key = kasumi_types::staged_digest(&("owner", "large-receipt-row"))?.0;
    let row = selected.receipts.get(&key)?.unwrap();
    assert!(
        crate::accounting::encoded_len(&row)? > 64 << 10,
        "fixture did not cross the small-receipt optimization envelope"
    );
    assert_eq!(row.receipt.recorded_revision, selected.state.revision);
    drop(selected);
    fixture.close().await
}
