use super::*;
use crate::test_utils::SnapshotFixture;
use kasumi_types::ReadPrecondition;
use serde_json::json;

fn fixture_memory() -> Arc<kasumi_store::test_utils::TestDiskMemory> {
    // Small-case scratch/device ownership takes four leases and each fresh
    // point table takes ten. Initializing the second table needs a 33rd lease
    // for its first directory buffer; restore can overlap a third receipt table.
    // Keep the byte cap unchanged and fund that bounded owner/workspace set.
    // The ignored 100,000-row cohort needs separate slot qualification as its
    // segment/directory file owners grow.
    kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64)
}

fn context() -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: "tenant".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "request".into(),
    }
}
fn command(operation: Operation, revision: u64) -> Command {
    Command {
        context: context(),
        timestamp_ms: revision,
        operation,
    }
}
struct CodecFixture {
    engine: TenantEngine,
    disk: Arc<kasumi_store::ScratchDisk>,
    _directory: tempfile::TempDir,
}
impl std::ops::Deref for CodecFixture {
    type Target = TenantEngine;
    fn deref(&self) -> &Self::Target {
        &self.engine
    }
}
fn engine(
    memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission>,
    max_snapshot_bytes: u64,
) -> CodecFixture {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let disk = kasumi_store::ScratchDisk::fixture(directory.path().join("scratch"), memory);

    let engine = TenantEngine::new(
        "tenant".into(),
        "incarnation".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: context().scopes,
            }],
            strict_read_audit: false,
        },
        Limits {
            max_snapshot_bytes,
            audit_retention: AuditRetentionBudget {
                hot_bytes: 128 << 10,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    engine
        .apply_command(
            &disk,
            1,
            command(
                Operation::CreateCollection(CollectionDefinition {
                    name: "docs".into(),
                    schema: json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: false,
                    retention_class: CollectionRetentionClass::Operational,
                    write_mode: CollectionWriteMode::Mutable,
                }),
                1,
            ),
        )
        .unwrap()
        .unwrap();
    CodecFixture {
        engine,
        disk,
        _directory: directory,
    }
}
fn batch(key: &str, id: &str, size: usize) -> MutationBatch {
    MutationBatch {
        idempotency_key: key.into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: json!({"value":"x".repeat(size)}),
            expected: Precondition::Any,
        }],
    }
}
fn apply(engine: &CodecFixture, revision: u64, operation: Operation) -> Result<WriteReceipt> {
    engine
        .apply_command(&engine.disk, revision, command(operation, revision))
        .unwrap()
}

#[test]
fn limits_change_invalidates_prior_data_capacity_epoch() {
    let engine = engine(fixture_memory(), 2 << 20);
    let before = engine.generation().unwrap();
    let limits = before.state.limits.clone();
    apply(&engine, 2, Operation::SetLimits(limits)).unwrap();
    let after = engine.generation().unwrap();
    assert_eq!(after.state.policy_epoch, before.state.policy_epoch + 1);
    assert_eq!(after.state.schema_epoch, before.state.schema_epoch);
}

fn patch_expansion_fixture() -> (CodecFixture, usize) {
    let engine = engine(fixture_memory(), 2 << 20);
    for (revision, id) in [(2, "a"), (3, "b")] {
        apply(&engine, revision, Operation::Mutate(batch(id, id, 8192))).unwrap();
    }
    let bytes = engine.generation().unwrap().state.collections["docs"]
        .documents
        .values()
        .map(|document| encoded_len(&document.body).unwrap())
        .sum();
    (engine, bytes)
}

fn expansion_patch(key: &str) -> MutationBatch {
    MutationBatch::with_key(key)
        .upsert("docs", "marker", json!({"created":true}))
        .patch("docs", "a", json!({"patched":true}))
        .patch("docs", "b", json!({"patched":true}))
}

fn assert_patch_sources_unchanged(engine: &CodecFixture, before: &Arc<Generation>) {
    let after = engine.generation().unwrap();
    let documents = &after.state.collections["docs"].documents;
    assert!(!documents.contains_key("marker"));
    for id in ["a", "b"] {
        assert!(Arc::ptr_eq(
            &documents[id],
            &before.state.collections["docs"].documents[id]
        ));
    }
}

#[test]
fn merge_patch_expansion_rejects_atomically_and_accepts_the_exact_source_byte_boundary() {
    let (engine, source_bytes) = patch_expansion_fixture();
    let mut limits = engine.generation().unwrap().state.limits.clone();
    limits.max_document_bytes = source_bytes / 2;
    limits.max_batch_bytes = source_bytes - 1;
    apply(&engine, 4, Operation::SetLimits(limits.clone())).unwrap();
    let before = engine.generation().unwrap();
    let patch = expansion_patch("too-large");
    assert!(encoded_len(&patch).unwrap() < limits.max_batch_bytes);
    let error = apply(&engine, 5, Operation::Mutate(patch.clone())).unwrap_err();
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(error.message.contains("source documents exceed byte limit"));
    assert_patch_sources_unchanged(&engine, &before);

    limits.max_batch_bytes = source_bytes;
    // Leave room for the new field while the source-byte bound remains exact.
    limits.max_document_bytes += 64;
    apply(&engine, 6, Operation::SetLimits(limits)).unwrap();
    assert_eq!(
        apply(&engine, 7, Operation::Mutate(patch)).unwrap_err(),
        error,
        "raising the budget must not replace a permanent rejection"
    );
    assert_patch_sources_unchanged(&engine, &before);
    apply(
        &engine,
        8,
        Operation::Mutate(expansion_patch("at-boundary")),
    )
    .unwrap();
    let after = engine.generation().unwrap();
    for id in ["a", "b"] {
        assert_eq!(
            after.state.collections["docs"].documents[id].body["patched"],
            true
        );
        assert_eq!(after.state.collections["docs"].documents[id].version, 8);
    }
}

#[test]
fn merge_patch_expansion_checks_decoded_clone_cost_before_mutating_object_heavy_documents() {
    let engine = engine(fixture_memory(), 2 << 20);
    let body = serde_json::Value::Object(
        (0..100)
            .map(|index| (format!("k{index:03}"), json!(0)))
            .collect(),
    );
    apply(
        &engine,
        2,
        Operation::Mutate(MutationBatch::with_key("seed").insert("docs", "a", body)),
    )
    .unwrap();
    let mut limits = engine.generation().unwrap().state.limits.clone();
    limits.max_document_bytes = 4096;
    limits.max_batch_bytes = 4096;
    apply(&engine, 3, Operation::SetLimits(limits)).unwrap();
    let before = engine.generation().unwrap();
    let source = &before.state.collections["docs"].documents["a"];
    assert!(encoded_len(&source.body).unwrap() < 4096);
    assert!(kasumi_query::document_clone_bytes(source).unwrap() > 3 * 4096);
    let error = apply(
        &engine,
        4,
        Operation::Mutate(MutationBatch::with_key("patch").patch("docs", "a", json!({}))),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(
        error
            .message
            .contains("source documents exceed workspace limit")
    );
    assert!(Arc::ptr_eq(
        source,
        &engine.generation().unwrap().state.collections["docs"].documents["a"]
    ));
}

#[test]
fn staged_merge_patch_expansion_uses_transaction_limit_and_keeps_rejection_permanent() {
    let (engine, source_bytes) = patch_expansion_fixture();
    let mut limits = engine.generation().unwrap().state.limits.clone();
    limits.max_document_bytes = source_bytes / 2;
    limits.max_batch_bytes = source_bytes / 2;
    limits.atomic.max_transaction_bytes = source_bytes - 1;
    apply(&engine, 4, Operation::SetLimits(limits.clone())).unwrap();
    let before = engine.generation().unwrap();
    let reference = upload_stage_operations(
        &engine,
        "too-large",
        5,
        expansion_patch("unused").operations,
    );
    let error = apply(&engine, 7, Operation::FinalizeStaged(reference.clone())).unwrap_err();
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(error.message.contains("source documents exceed byte limit"));
    assert_patch_sources_unchanged(&engine, &before);

    limits.atomic.max_transaction_bytes = source_bytes;
    // Patches below remove a field, so individual document sizes cannot grow.
    apply(&engine, 8, Operation::SetLimits(limits)).unwrap();
    assert_eq!(
        apply(&engine, 9, Operation::FinalizeStaged(reference)).unwrap_err(),
        error
    );
    assert_patch_sources_unchanged(&engine, &before);
    let reference = upload_stage_operations(
        &engine,
        "at-boundary",
        10,
        MutationBatch::new()
            .patch("docs", "a", json!({"value":null}))
            .patch("docs", "b", json!({"value":null}))
            .operations,
    );
    apply(&engine, 12, Operation::FinalizeStaged(reference)).unwrap();
    let after = engine.generation().unwrap();
    for id in ["a", "b"] {
        assert_eq!(
            after.state.collections["docs"].documents[id].body,
            json!({})
        );
        assert_eq!(after.state.collections["docs"].documents[id].version, 12);
    }
}

fn text_engine(max_snapshot_bytes: u64) -> CodecFixture {
    let engine = engine(fixture_memory(), max_snapshot_bytes);
    let mut definition = engine.generation().unwrap().state.collections["docs"]
        .definition
        .clone();
    definition.indexes = vec![
        IndexDefinition {
            name: "text".into(),
            fields: vec![IndexField {
                path: "/value".into(),
                kind: ScalarType::String,
            }],
            unique: false,
            text: Some(TextIndex {
                analyzer: Analyzer::UnicodeV1,
            }),
        },
        IndexDefinition {
            name: "unique_tag".into(),
            fields: vec![IndexField {
                path: "/tag".into(),
                kind: ScalarType::String,
            }],
            unique: true,
            text: None,
        },
    ];
    apply(&engine, 2, Operation::ReplaceCollection(definition)).unwrap();
    engine
}

fn document_batch(key: &str, id: &str, body: serde_json::Value) -> MutationBatch {
    MutationBatch {
        idempotency_key: key.into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body,
            expected: Precondition::Any,
        }],
    }
}

fn text_matches(generation: &Arc<Generation>, text: &str) -> Vec<(String, u64)> {
    struct TextQueryWorkspace;
    impl kasumi_query::QueryWorkspace for TextQueryWorkspace {
        fn ensure_peak(&mut self, bytes: u64) -> Result<()> {
            if bytes > 64 << 20 {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "text query fixture workspace exhausted",
                ));
            }
            Ok(())
        }
    }
    let query: QueryRequest = serde_json::from_value(json!({
        "collection": "docs",
        "search": {"index": "text", "query": text}
    }))
    .unwrap();
    let input_bytes = u64::try_from(crate::accounting::encoded_len(&query).unwrap())
        .unwrap()
        .checked_mul(3)
        .unwrap();
    let mut memory = kasumi_query::QueryMemory::new(TextQueryWorkspace, input_bytes).unwrap();
    generation
        .indexes
        .execute(
            &generation.document_source(&query.collection).unwrap(),
            &query,
            &generation.state.limits,
            &mut memory,
        )
        .unwrap()
        .rows
        .into_iter()
        .map(|row| (row.id, row.version))
        .collect()
}

/// Observe the same synchronous boundary used by Raft while the engine still
/// owns its apply lock. The candidate response must already be encoded, but
/// readers must still see the previous Generation during the callback.
struct ObservingPublisher<'a> {
    engine: &'a TenantEngine,
    previous: Arc<Generation>,
    fail: bool,
    calls: usize,
    response: Option<kasumi_raft::AppliedResponse>,
}
impl<'a> ObservingPublisher<'a> {
    fn new(engine: &'a TenantEngine, fail: bool) -> Self {
        Self {
            engine,
            previous: engine.generation().unwrap(),
            fail,
            calls: 0,
            response: None,
        }
    }
}
impl kasumi_raft::ApplyPublisher for ObservingPublisher<'_> {
    fn with_completion(
        &mut self,
        _: &kasumi_raft::CompletionIdentity,
        _: &mut dyn kasumi_raft::CompletionAction,
    ) -> std::result::Result<(), kasumi_raft::CompletionCallError> {
        Err(kasumi_raft::CompletionCallError::Unsupported)
    }

    fn commit_with_selection<'call>(
        &mut self,
        _: kasumi_raft::AppliedResponse,
        _: &[kasumi_store::WriteOp],
        _: &mut dyn kasumi_raft::SelectionPreparer,
        _: kasumi_raft::PublicationChallenge<'call>,
    ) -> std::result::Result<
        kasumi_raft::JointPublicationReceipt<'call>,
        kasumi_raft::PublishCallError,
    > {
        panic!("response-only fixture must not publish a selected source")
    }

    fn commit(
        &mut self,
        response: kasumi_raft::AppliedResponse,
        application_writes: &[kasumi_store::WriteOp],
    ) -> std::result::Result<(), kasumi_raft::PublishCallError> {
        self.calls += 1;
        assert_eq!(self.calls, 1);
        assert!(application_writes.is_empty());
        assert!(Arc::ptr_eq(
            &self.previous,
            &self.engine.generation().unwrap()
        ));
        assert!(matches!(
            self.engine.apply_lock.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        self.response = Some(response);
        if self.fail {
            Err(kasumi_raft::PublishCallError::Failed)
        } else {
            Ok(())
        }
    }
}

fn fixture_publish(
    engine: &CodecFixture,
    revision: u64,
    input: &Command,
    publisher: &mut dyn kasumi_raft::ApplyPublisher,
) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
    let applied = crate::staged_terminal::AppliedIdentity {
        incarnation: engine.incarnation.clone(),
        revision,
        timestamp_ms: input.timestamp_ms,
        command_sha256: hex::encode(Sha256::digest(
            serde_json::to_vec(input).map_err(anyhow::Error::from)?,
        )),
        origin: crate::staged_terminal::AppliedOrigin::Fixture,
    };
    engine.apply_fixture_command(
        input.clone(),
        applied,
        ApplyScope::Fixture(engine.disk.clone()),
        publisher,
    )
}

#[test]
fn command_publication_keeps_candidate_private_until_commit() {
    let engine = engine(fixture_memory(), 2 << 20);
    let input = command(Operation::Mutate(batch("accepted", "row", 10)), 2);
    let mut publisher = ObservingPublisher::new(&engine, false);
    fixture_publish(&engine, 2, &input, &mut publisher).unwrap();
    let response = publisher.response.as_ref().unwrap();
    let outcome: Result<WriteReceipt> = serde_json::from_slice(&response.data).unwrap();
    assert_eq!(outcome.unwrap().versions["/docs/row"], 2);
    assert!(response.retirement.is_none());
    let selected = engine.generation().unwrap();
    assert_eq!(selected.state.revision, 2);
    assert_eq!(selected.state.mutation_receipt_head.count, 1);
    assert!(
        publisher.previous.state.collections["docs"]
            .documents
            .is_empty()
    );
}

#[test]
fn failed_publication_keeps_staged_receipt_hidden_until_exact_retry() {
    let engine = engine(fixture_memory(), 2 << 20);
    apply(&engine, 2, Operation::Mutate(batch("seed", "row", 3))).unwrap();
    let input = command(Operation::Mutate(batch("later", "row", 20)), 3);
    let mut failed = ObservingPublisher::new(&engine, true);
    let error = fixture_publish(&engine, 3, &input, &mut failed).unwrap_err();
    assert_eq!(
        error
            .operation_error()
            .unwrap()
            .downcast_ref::<kasumi_raft::PublishCallError>(),
        Some(&kasumi_raft::PublishCallError::Failed)
    );
    let selected = engine.generation().unwrap();
    assert!(Arc::ptr_eq(&selected, &failed.previous));
    let key = staged_digest(&("owner", "later")).unwrap().0;
    assert!(selected.receipts.get(&key).unwrap().is_none());
    assert_eq!(
        selected.state.collections["docs"].documents["row"].version,
        2
    );
    let encoded = failed.response.as_ref().unwrap().data.clone();
    drop(failed);

    // This exercises immutable staging under a local fixture. Production Raft
    // fences the failed worker and reaches the retry through recovery/replay.
    let mut retry = ObservingPublisher::new(&engine, false);
    fixture_publish(&engine, 3, &input, &mut retry).unwrap();
    assert_eq!(retry.response.as_ref().unwrap().data, encoded);
    let current = engine.generation().unwrap();
    assert_eq!(current.state.mutation_receipt_head.count, 2);
    assert_eq!(current.receipts.get(&key).unwrap().unwrap().ordinal, 2);
    assert_eq!(
        current.state.collections["docs"].documents["row"].version,
        3
    );
    assert!(selected.receipts.get(&key).unwrap().is_none());
}

#[test]
fn deterministic_rejection_waits_for_publication() {
    let engine = engine(fixture_memory(), 2 << 20);
    let invalid = document_batch("invalid", "row", json!(false));
    let input = command(Operation::Mutate(invalid), 2);
    let mut publisher = ObservingPublisher::new(&engine, true);
    fixture_publish(&engine, 2, &input, &mut publisher).unwrap_err();
    let outcome: Result<WriteReceipt> =
        serde_json::from_slice(&publisher.response.as_ref().unwrap().data).unwrap();
    assert_eq!(outcome.unwrap_err().code, ErrorCode::SchemaViolation);
    assert!(Arc::ptr_eq(
        &publisher.previous,
        &engine.generation().unwrap()
    ));
    assert_eq!(
        engine
            .generation()
            .unwrap()
            .state
            .mutation_receipt_head
            .count,
        0
    );
}

#[test]
fn revision_only_audit_exhaustion_waits_for_publication() {
    let engine = engine(fixture_memory(), 2 << 20);
    let previous = engine.generation().unwrap();
    let mut full = previous.state.clone();
    full.limits.audit_retention.hot_bytes = full.audit_retention.hot_bytes;
    engine.publish_generation(Some(Arc::new(Generation {
        state: full,
        receipts: previous.receipts.clone(),
        backup_bindings: previous.backup_bindings.clone(),
        terminals: previous.terminals.clone(),
        target_resolutions: previous.target_resolutions.clone(),
        indexes: previous.indexes.clone(),
        snapshot_accounting: previous.snapshot_accounting.clone(),
        application_selection: std::sync::OnceLock::new(),
        _read_reservations: vec![],
    })));
    let input = command(Operation::SetPolicy(previous.state.policy.clone()), 2);
    let mut failed = ObservingPublisher::new(&engine, true);
    fixture_publish(&engine, 2, &input, &mut failed).unwrap_err();
    let outcome: Result<WriteReceipt> =
        serde_json::from_slice(&failed.response.as_ref().unwrap().data).unwrap();
    assert_eq!(outcome.unwrap_err().code, ErrorCode::AuditUnavailable);
    assert!(Arc::ptr_eq(&failed.previous, &engine.generation().unwrap()));
    let mut accepted = ObservingPublisher::new(&engine, false);
    fixture_publish(&engine, 2, &input, &mut accepted).unwrap();
    let selected = engine.generation().unwrap();
    assert_eq!(selected.state.revision, 2);
    assert_eq!(selected.state.policy_epoch, previous.state.policy_epoch);
    assert_eq!(selected.state.audits, previous.state.audits);
}

#[test]
fn metadata_publication_covers_forward_and_replayed_positions() {
    use kasumi_raft::{AppliedInput, StateMachineBackend};
    let engine = engine(fixture_memory(), 2 << 20);
    let position = kasumi_raft::AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 2),
        previous: None,
        membership: Default::default(),
        command_sha256: hex::encode(Sha256::digest([])),
        retirement_seed: None,
    };
    let mut failed = ObservingPublisher::new(&engine, true);
    engine
        .apply_with_publisher(&position, AppliedInput::Metadata, &mut failed)
        .unwrap_err();
    assert!(failed.response.as_ref().unwrap().data.is_empty());
    assert!(Arc::ptr_eq(&failed.previous, &engine.generation().unwrap()));
    let mut accepted = ObservingPublisher::new(&engine, false);
    engine
        .apply_with_publisher(&position, AppliedInput::Metadata, &mut accepted)
        .unwrap();
    assert_eq!(engine.generation().unwrap().state.revision, 2);
    let mut replay = ObservingPublisher::new(&engine, false);
    engine
        .apply_with_publisher(&position, AppliedInput::Metadata, &mut replay)
        .unwrap();
    assert_eq!(replay.calls, 1);
    assert!(replay.response.as_ref().unwrap().data.is_empty());
    assert!(Arc::ptr_eq(&replay.previous, &engine.generation().unwrap()));
}

#[test]
fn snapshot_quota_rejection_preserves_text_writer_and_original_receipts() {
    let engine = text_engine(16 << 10);
    let original_body = json!({"value": "original", "tag": "occupied"});
    let original = document_batch("original", "row", original_body.clone());
    let original_receipt = apply(&engine, 3, Operation::Mutate(original.clone())).unwrap();
    let old = engine.generation().unwrap();
    assert_eq!(text_matches(&old, "original"), vec![("row".into(), 3)]);

    // The indexed value is valid and small. Unindexed padding passes the
    // document/batch limits but exceeds the final serialized snapshot budget.
    let oversized = document_batch(
        "too-large",
        "row",
        json!({"value": "discarded", "tag": "occupied", "padding": "x".repeat(100_000)}),
    );
    let rejected = apply(&engine, 4, Operation::Mutate(oversized.clone())).unwrap_err();
    assert_eq!(rejected.code, ErrorCode::QuotaExceeded);
    assert_eq!(
        rejected.message,
        "serialized tenant snapshot byte budget exhausted"
    );
    let after_rejection = engine.generation().unwrap();
    assert_eq!(after_rejection.state.revision, 4);
    assert_eq!(
        after_rejection.state.collections["docs"].documents["row"].body,
        original_body
    );
    assert_eq!(
        text_matches(&after_rejection, "original"),
        vec![("row".into(), 3)]
    );
    assert!(text_matches(&after_rejection, "discarded").is_empty());
    assert_eq!(after_rejection.state.mutation_receipt_head.count, 2);
    let rejected_key = staged_digest(&("owner", "too-large")).unwrap().0;
    let rejected_row = after_rejection
        .receipts
        .get(&rejected_key)
        .unwrap()
        .unwrap();
    assert_eq!(
        rejected_row.receipt.request_digest,
        oversized.digest().unwrap()
    );
    assert_eq!(rejected_row.receipt.outcome, Err(rejected.clone()));

    // No restore or index rebuild intervenes: this must advance the same text
    // writer that the rejected candidate previously made stale.
    let accepted_body = json!({"value": "accepted", "tag": "occupied"});
    let accepted = document_batch("accepted", "row", accepted_body.clone());
    let accepted_receipt = apply(&engine, 5, Operation::Mutate(accepted)).unwrap();
    assert_eq!(accepted_receipt.versions["/docs/row"], 5);
    let current = engine.generation().unwrap();
    assert_eq!(text_matches(&current, "accepted"), vec![("row".into(), 5)]);
    assert!(text_matches(&current, "original").is_empty());
    assert!(text_matches(&current, "discarded").is_empty());
    assert_eq!(text_matches(&old, "original"), vec![("row".into(), 3)]);
    let head = current.state.mutation_receipt_head.clone();
    assert_eq!(head.count, 3);

    assert_eq!(
        apply(&engine, 6, Operation::Mutate(oversized)).unwrap_err(),
        rejected
    );
    assert_eq!(
        apply(&engine, 7, Operation::Mutate(original)).unwrap(),
        original_receipt
    );
    let replayed = engine.generation().unwrap();
    assert_eq!(replayed.state.mutation_receipt_head, head);
    assert_eq!(
        replayed.state.collections["docs"].documents["row"].body,
        accepted_body
    );
    assert_eq!(text_matches(&replayed, "accepted"), vec![("row".into(), 5)]);
}

#[test]
fn invalid_index_inputs_remain_deterministic_rejections_before_text_materialization() {
    let engine = text_engine(2 << 20);
    let original_body = json!({"value": "original", "tag": "occupied"});
    apply(
        &engine,
        3,
        Operation::Mutate(document_batch("original", "row", original_body.clone())),
    )
    .unwrap();
    for (offset, (body, code)) in [
        (
            json!({"value": "x".repeat(241), "tag": "new"}),
            ErrorCode::InvalidArgument,
        ),
        (
            json!({"value": 42, "tag": "new"}),
            ErrorCode::SchemaViolation,
        ),
        (
            json!({"value": "valid", "tag": 42}),
            ErrorCode::SchemaViolation,
        ),
        (
            json!({"value": "valid", "tag": "occupied"}),
            ErrorCode::Conflict,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let revision = 4 + offset as u64;
        let invalid = document_batch(&format!("invalid-{revision}"), "other", body);
        let rejected = apply(&engine, revision, Operation::Mutate(invalid)).unwrap_err();
        assert_eq!(rejected.code, code);
        let generation = engine.generation().unwrap();
        assert_eq!(
            generation.state.mutation_receipt_head.count,
            2 + offset as u64
        );
        assert_eq!(
            generation.state.collections["docs"].documents["row"].body,
            original_body
        );
        assert!(
            !generation.state.collections["docs"]
                .documents
                .contains_key("other")
        );
        assert_eq!(
            text_matches(&generation, "original"),
            vec![("row".into(), 3)]
        );
    }
    apply(
        &engine,
        8,
        Operation::Mutate(document_batch(
            "accepted",
            "other",
            json!({"value": "accepted", "tag": "new"}),
        )),
    )
    .unwrap();
    let generation = engine.generation().unwrap();
    assert_eq!(generation.state.mutation_receipt_head.count, 6);
    assert_eq!(
        text_matches(&generation, "accepted"),
        vec![("other".into(), 8)]
    );
}

#[test]
fn text_materialization_failure_is_outer_and_does_not_select_a_receipt() {
    let engine = text_engine(2 << 20);
    let original_body = json!({"value": "original", "tag": "occupied"});
    apply(
        &engine,
        3,
        Operation::Mutate(document_batch("original", "row", original_body.clone())),
    )
    .unwrap();
    let previous = engine.generation().unwrap();
    let mut unselected = previous.state.clone();
    unselected.revision = 4;
    unselected
        .collections
        .get_mut("docs")
        .unwrap()
        .documents
        .insert(
            "row".into(),
            Arc::new(Document {
                id: "row".into(),
                version: 4,
                body: json!({"value": "unselected", "tag": "occupied"}),
            }),
        );
    // Advance the shared writer without selecting the result to inject its
    // actual stale-generation failure, without changing document validation.
    drop(
        crate::index_source::update(
            &previous.indexes,
            &previous.state,
            &unselected,
            &BTreeMap::from([("docs".into(), BTreeSet::from(["row".into()]))]),
        )
        .unwrap(),
    );
    let failed = document_batch(
        "materialization-failed",
        "row",
        json!({"value": "accepted", "tag": "occupied"}),
    );
    let failure = engine
        .apply_command(&engine.disk, 4, command(Operation::Mutate(failed), 4))
        .expect_err("index materialization must be an outer replica failure");
    let materialization = failure
        .operation_error()
        .unwrap()
        .downcast_ref::<Error>()
        .unwrap();
    assert_eq!(materialization.code, ErrorCode::Unavailable);
    assert!(
        materialization
            .message
            .contains("stale or failed text generation")
    );
    let current = engine.generation().unwrap();
    assert!(Arc::ptr_eq(&current, &previous));
    assert_eq!(
        current.state.collections["docs"].documents["row"].body,
        original_body
    );
    assert_eq!(current.state.mutation_receipt_head.count, 1);
    assert!(
        current
            .receipts
            .get(
                &staged_digest(&("owner", "materialization-failed"))
                    .unwrap()
                    .0
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(text_matches(&current, "original"), vec![("row".into(), 3)]);
}

#[test]
fn recovery_seal_two_writes_three_reads_are_atomic_and_replay_original_receipts() {
    let engine = engine(fixture_memory(), 2 << 20);
    apply(
        &engine,
        2,
        Operation::CreateCollection(CollectionDefinition {
            name: "intent".into(),
            schema: json!({"type":"object"}),
            indexes: vec![],
            strict_read_audit: false,
            retention_class: CollectionRetentionClass::Operational,
            write_mode: CollectionWriteMode::Mutable,
        }),
    )
    .unwrap();
    let claimed = MutationBatch {
        idempotency_key: "claim".into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "recovery".into(),
            body: json!({"state":"processing"}),
            expected: Precondition::Absent,
        }],
    };
    apply(&engine, 3, Operation::Mutate(claimed)).unwrap();

    let state = engine.generation().unwrap().state.clone();
    let reads = vec![
        ReadAssertion::Snapshot {
            incarnation: state.incarnation,
            policy_epoch: state.policy_epoch,
            schema_epoch: state.schema_epoch,
        },
        ReadAssertion::Document {
            collection: "docs".into(),
            id: "recovery".into(),
            expected: ReadPrecondition::Version(3),
        },
        ReadAssertion::Document {
            collection: "intent".into(),
            id: "recovery".into(),
            expected: ReadPrecondition::Absent,
        },
    ];
    let seal = MutationBatch {
        idempotency_key: "seal".into(),
        read_set: reads.clone(),
        operations: vec![
            Mutation::Put {
                collection: "docs".into(),
                id: "recovery".into(),
                body: json!({"state":"writing"}),
                expected: Precondition::Version(3),
            },
            Mutation::Put {
                collection: "intent".into(),
                id: "recovery".into(),
                body: json!({"state":"sealed"}),
                expected: Precondition::Absent,
            },
        ],
    };
    let committed = apply(&engine, 4, Operation::Mutate(seal.clone())).unwrap();
    assert_eq!(
        committed.versions,
        BTreeMap::from([("/docs/recovery".into(), 4), ("/intent/recovery".into(), 4)])
    );
    let generation = engine.generation().unwrap();
    assert_eq!(
        generation.state.collections["docs"].documents["recovery"].body,
        json!({"state":"writing"})
    );
    assert_eq!(
        generation.state.collections["intent"].documents["recovery"].body,
        json!({"state":"sealed"})
    );
    let receipt_key = staged_digest(&("owner", "seal")).unwrap().0;
    let retained = generation.receipts.get(&receipt_key).unwrap().unwrap();
    assert_eq!(retained.receipt.request_digest, seal.digest().unwrap());
    assert_eq!(retained.receipt.outcome, Ok(committed.clone()));
    let committed_head = generation.state.mutation_receipt_head.clone();
    drop(generation);

    // A later failure in the second operation must roll back the first while
    // retaining the rejection for this exact original batch identity.
    let mut failing_reads = reads;
    failing_reads[1] = ReadAssertion::Document {
        collection: "docs".into(),
        id: "recovery".into(),
        expected: ReadPrecondition::Version(4),
    };
    failing_reads[2] = ReadAssertion::Document {
        collection: "intent".into(),
        id: "invalid".into(),
        expected: ReadPrecondition::Absent,
    };
    let rejected = MutationBatch {
        idempotency_key: "bad-seal".into(),
        read_set: failing_reads,
        operations: vec![
            Mutation::Put {
                collection: "docs".into(),
                id: "recovery".into(),
                body: json!({"state":"failed-write"}),
                expected: Precondition::Version(4),
            },
            Mutation::Put {
                collection: "intent".into(),
                id: "invalid".into(),
                body: json!(false),
                expected: Precondition::Absent,
            },
        ],
    };
    let rejected_error = apply(&engine, 5, Operation::Mutate(rejected.clone())).unwrap_err();
    assert_eq!(rejected_error.code, ErrorCode::SchemaViolation);
    let generation = engine.generation().unwrap();
    assert_eq!(
        generation.state.collections["docs"].documents["recovery"].body,
        json!({"state":"writing"})
    );
    assert!(
        !generation.state.collections["intent"]
            .documents
            .contains_key("invalid")
    );
    assert_eq!(
        generation.state.mutation_receipt_head.count,
        committed_head.count + 1
    );
    drop(generation);

    engine
        .fixture_restore(&engine.fixture_snapshot(&engine.disk).unwrap())
        .unwrap();
    let restored_head = engine
        .generation()
        .unwrap()
        .state
        .mutation_receipt_head
        .clone();
    assert_eq!(
        apply(&engine, 6, Operation::Mutate(seal.clone())).unwrap(),
        committed
    );
    assert_eq!(
        apply(&engine, 7, Operation::Mutate(rejected.clone())).unwrap_err(),
        rejected_error
    );
    let mut substituted = seal;
    substituted.operations[1] = Mutation::Put {
        collection: "intent".into(),
        id: "recovery".into(),
        body: json!({"state":"substituted"}),
        expected: Precondition::Absent,
    };
    assert_eq!(
        apply(&engine, 8, Operation::Mutate(substituted))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        engine.generation().unwrap().state.mutation_receipt_head,
        restored_head
    );
    let receipt_key = staged_digest(&("owner", "bad-seal")).unwrap().0;
    let retained = engine
        .generation()
        .unwrap()
        .receipts
        .get(&receipt_key)
        .unwrap()
        .unwrap();
    assert_eq!(retained.receipt.request_digest, rejected.digest().unwrap());
    assert_eq!(retained.receipt.outcome, Err(rejected_error));
}
#[test]
fn admitted_failure_survives_byte_exhaustion_expansion_and_snapshot_replay() {
    let engine = engine(fixture_memory(), 16 << 10);
    let original = batch("original", "row", 100_000);
    let failure = apply(&engine, 2, Operation::Mutate(original.clone())).unwrap_err();
    assert_eq!(failure.code, ErrorCode::QuotaExceeded);
    let head = engine
        .generation()
        .unwrap()
        .state
        .mutation_receipt_head
        .clone();
    assert_eq!(head.count, 1);
    assert!(
        engine.generation().unwrap().state.collections["docs"]
            .documents
            .is_empty()
    );
    let mut limits = engine.generation().unwrap().state.limits.clone();
    limits.max_mutation_receipt_bytes = head.encoded_bytes;
    apply(&engine, 3, Operation::SetLimits(limits)).unwrap();
    assert_eq!(
        apply(&engine, 4, Operation::Mutate(original.clone())).unwrap_err(),
        failure
    );
    assert_eq!(
        apply(
            &engine,
            5,
            Operation::Mutate(batch("original", "different", 0))
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        apply(&engine, 6, Operation::Mutate(batch("new", "small", 0)))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(
        engine.generation().unwrap().state.mutation_receipt_head,
        head
    );
    let mut limits = engine.generation().unwrap().state.limits.clone();
    limits.max_snapshot_bytes = 2 << 20;
    limits.max_mutation_receipt_bytes += 2 << 20;
    apply(&engine, 7, Operation::SetLimits(limits)).unwrap();
    engine
        .fixture_restore(&engine.fixture_snapshot(&engine.disk).unwrap())
        .unwrap();
    // The original body would fit now; its original failure is still final.
    assert_eq!(
        apply(&engine, 8, Operation::Mutate(original)).unwrap_err(),
        failure
    );
    assert_eq!(
        engine.generation().unwrap().state.mutation_receipt_head,
        head
    );
    apply(&engine, 9, Operation::Mutate(batch("new", "small", 0))).unwrap();
    assert_eq!(
        engine
            .generation()
            .unwrap()
            .state
            .mutation_receipt_head
            .count,
        2
    );
    assert_eq!(
        engine.generation().unwrap().state.collections["docs"]
            .documents
            .len(),
        1
    );
}
#[test]
fn hot_audit_exhaustion_cannot_rewrite_original_or_admit_a_new_identity() {
    let engine = engine(fixture_memory(), 2 << 20);
    let original = batch("original", "row", 10);
    let result = apply(&engine, 2, Operation::Mutate(original.clone())).unwrap();
    let head = engine
        .generation()
        .unwrap()
        .state
        .mutation_receipt_head
        .clone();
    let mut revision = 3;
    loop {
        let generation = engine.generation().unwrap();
        let remaining = generation.state.limits.audit_retention.hot_bytes
            - generation.state.audit_retention.hot_bytes;
        if remaining == 0 {
            break;
        }
        let mut event = AuditEvent {
            event_id: format!("fill-{revision}"),
            principal: "owner".into(),
            action: "read".into(),
            request_id: String::new(),
            timestamp_ms: revision,
            data_revision: Some(revision - 1),
            outcome: "authorized_release".into(),
            collection: Some("docs".into()),
        };
        let bytes = remaining.min(60_000) as usize;
        let base = encoded_len(&event).unwrap();
        assert!(bytes >= base);
        event.request_id = "r".repeat(bytes - base);
        let mut input = command(Operation::Audit(event.clone()), revision);
        input.context.request_id = event.request_id;
        drop(generation);
        engine
            .apply_command(&engine.disk, revision, input)
            .unwrap()
            .unwrap();
        revision += 1;
    }
    assert_eq!(
        apply(&engine, revision, Operation::Mutate(original.clone()))
            .unwrap_err()
            .code,
        ErrorCode::AuditUnavailable
    );
    revision += 1;
    assert_eq!(
        apply(
            &engine,
            revision,
            Operation::Mutate(batch("new", "new", 10))
        )
        .unwrap_err()
        .code,
        ErrorCode::AuditUnavailable
    );
    revision += 1;
    assert_eq!(
        engine.generation().unwrap().state.mutation_receipt_head,
        head
    );
    let mut limits = engine.generation().unwrap().state.limits.clone();
    limits.audit_retention.hot_bytes += 128 << 10;
    apply(&engine, revision, Operation::SetLimits(limits)).unwrap();
    revision += 1;
    assert_eq!(
        apply(&engine, revision, Operation::Mutate(original)).unwrap(),
        result
    );
    assert_eq!(
        engine.generation().unwrap().state.mutation_receipt_head,
        head
    );
    revision += 1;
    apply(
        &engine,
        revision,
        Operation::Mutate(batch("new", "new", 10)),
    )
    .unwrap();
    assert_eq!(
        engine
            .generation()
            .unwrap()
            .state
            .mutation_receipt_head
            .count,
        2
    );
}
#[test]
fn terminal_reservation_covers_error_codes_escaped_versions_and_counter_widths() {
    let engine = engine(fixture_memory(), 2 << 20);
    let mut state = engine.generation().unwrap().state.clone();
    state.revision = 100;
    state.mutation_receipt_head.count = 99;
    state.mutation_receipt_head.encoded_bytes = 99_999;
    state.mutation_receipt_head.last_applied_revision = 99;
    let collection = "~/".repeat(128);
    let batch = MutationBatch {
        idempotency_key: "wide".into(),
        read_set: vec![],
        operations: (0..256)
            .map(|i| Mutation::Delete {
                collection: collection.clone(),
                id: format!("{i:03}{}", "~/".repeat(126)),
                expected: Precondition::Any,
            })
            .collect(),
    };
    let input = command(Operation::Mutate(batch.clone()), state.revision);
    let applied = crate::staged_terminal::AppliedIdentity {
        incarnation: state.incarnation.clone(),
        revision: state.revision,
        timestamp_ms: input.timestamp_ms,
        command_sha256: "ab".repeat(32),
        origin: crate::staged_terminal::AppliedOrigin::Fixture,
    };
    let permit =
        Permit::prepare(&state, &input, &batch, &applied, batch.digest().unwrap()).unwrap();
    assert_eq!(permit.maximum_head.count, 100);
    assert!(permit.maximum_head.encoded_bytes >= 100_000);
    let codes = [
        ErrorCode::InvalidArgument,
        ErrorCode::Unauthorized,
        ErrorCode::Forbidden,
        ErrorCode::NotFound,
        ErrorCode::AlreadyExists,
        ErrorCode::Conflict,
        ErrorCode::SchemaViolation,
        ErrorCode::QuotaExceeded,
        ErrorCode::ResourceExhausted,
        ErrorCode::IndexRequired,
        ErrorCode::CursorExpired,
        ErrorCode::Unavailable,
        ErrorCode::UnknownOutcome,
        ErrorCode::Corruption,
        ErrorCode::Sealed,
        ErrorCode::AuditUnavailable,
    ];
    let largest_error = encoded_len(&maximum_error()).unwrap();
    let mut reserved = state.clone();
    reserved.mutation_receipt_head = permit.maximum_head.clone();
    let reserved_header = encoded_len(&crate::snapshot_codec::metadata(&reserved)).unwrap();
    for code in codes {
        for message in ["\u{0001}".repeat(512), "\\\"".repeat(256), "é".repeat(256)] {
            let error = Error::new(code, message);
            assert!(encoded_len(&error).unwrap() <= largest_error);
            let mut receipt = permit.template.clone();
            receipt.outcome = Err(error);
            let row = Row {
                ordinal: 100,
                key: staged_digest(&("owner", "wide")).unwrap().0,
                previous_sha256: state.mutation_receipt_head.sha256.clone(),
                applied: applied.clone(),
                receipt,
            };
            row.validate(&state).unwrap();
            assert!(row.framed_bytes().unwrap() <= permit.maximum_row_bytes);
            let mut actual = state.clone();
            crate::mutation_receipt::advance(&mut actual.mutation_receipt_head, &row).unwrap();
            assert!(
                encoded_len(&crate::snapshot_codec::metadata(&actual)).unwrap() <= reserved_header
            );
        }
    }
}

#[test]
#[ignore = "explicit permanent-receipt capacity cohort; streams 100,000 encrypted point rows"]
fn verified_point_history_crosses_former_count_limit_before_a_real_new_mutation() {
    const PREVIOUS_LIMIT: u64 = 100_000;
    let source = engine(fixture_memory(), 2 << 20);
    let previous = source.generation().unwrap();
    let mut state = previous.state.clone();
    state.revision = PREVIOUS_LIMIT + 1;
    let disk = source.disk.clone();
    let mut builder = crate::mutation_receipt::Builder::new(
        &disk,
        crate::mutation_receipt::scratch_limit(state.limits.max_mutation_receipt_bytes).unwrap(),
        &state.tenant,
        &state.incarnation,
    )
    .unwrap();
    for ordinal in 1..=PREVIOUS_LIMIT {
        let key = format!("prior-{ordinal}");
        let input = batch(&key, &key, 0);
        let applied_revision = ordinal + 1;
        let original = command(Operation::Mutate(input.clone()), applied_revision);
        let row = Row {
            ordinal,
            key: staged_digest(&("owner", &key)).unwrap().0,
            previous_sha256: state.mutation_receipt_head.sha256.clone(),
            applied: crate::staged_terminal::AppliedIdentity {
                incarnation: state.incarnation.clone(),
                revision: applied_revision,
                timestamp_ms: original.timestamp_ms,
                command_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&original).unwrap())),
                origin: crate::staged_terminal::AppliedOrigin::Raft {
                    term: 1,
                    leader: 1,
                    index: applied_revision,
                    context_sha256: "cd".repeat(32),
                },
            },
            receipt: StoredReceipt {
                scope: MutationReceiptScope {
                    tenant: state.tenant.clone(),
                    incarnation: state.incarnation.clone(),
                    principal: "owner".into(),
                },
                idempotency_key: key,
                recorded_revision: applied_revision,
                request_digest: input.digest().unwrap(),
                collections: vec!["docs".into()],
                outcome: Err(Error::new(
                    ErrorCode::QuotaExceeded,
                    "retained fixture failure",
                )),
            },
        };
        builder.push(&row, &state).unwrap();
        crate::mutation_receipt::advance(&mut state.mutation_receipt_head, &row).unwrap();
    }
    let receipts = builder.finish(&state.mutation_receipt_head).unwrap();
    let generation = source
        .prepare_state(
            &CapturedValidation::capture(&source).unwrap().baseline(),
            state,
            receipts,
            previous.backup_bindings.clone(),
            previous.terminals.clone(),
            previous.target_resolutions.clone(),
        )
        .unwrap();
    source.publish_generation(Some(Arc::new(generation)));
    drop(previous);
    let snapshot = source.logical_snapshot(&disk).unwrap();
    let restored = engine(fixture_memory(), 2 << 20);
    restored.fixture_restore(&snapshot).unwrap();
    // The history is deliberately manufactured canonical fixture state. The
    // post-restore admission below executes the real deterministic mutation path;
    // this is not an actual-HA throughput, production-reserve, or hard-RSS claim.
    let revision = PREVIOUS_LIMIT + 2;
    apply(
        &restored,
        revision,
        Operation::Mutate(batch("new-after-limit", "new", 0)),
    )
    .unwrap();
    assert_eq!(
        restored
            .generation()
            .unwrap()
            .state
            .mutation_receipt_head
            .count,
        PREVIOUS_LIMIT + 1
    );
    assert_eq!(
        apply(
            &restored,
            revision + 1,
            Operation::Mutate(batch("prior-1", "prior-1", 0))
        )
        .unwrap_err()
        .message,
        "retained fixture failure"
    );
    assert_eq!(
        apply(
            &restored,
            revision + 2,
            Operation::Mutate(batch("prior-1", "substituted", 0))
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        restored
            .generation()
            .unwrap()
            .state
            .mutation_receipt_head
            .count,
        PREVIOUS_LIMIT + 1
    );
    assert_eq!(restored.generation().unwrap().state.document_count, 1);
}

fn inconsistent_generation(previous: &Arc<Generation>, fault: usize) -> Arc<Generation> {
    let mut collections = previous.state.collections.clone();
    let document = collections
        .get_mut("docs")
        .unwrap()
        .documents
        .get_mut("row")
        .unwrap();
    let document = Arc::make_mut(document);
    match fault {
        0 => document.body["tag"] = json!("mismatch"),
        // Version zero is a valid restored value. A live record whose ID
        // differs from its map key is independently corrupt at any version.
        1 => document.id = "different-row".into(),
        2 => document.version = previous.state.revision + 1,
        _ => unreachable!(),
    }
    Arc::new(previous.read_view(collections, vec![]))
}

#[test]
fn zero_version_source_mutation_preserves_receipt_and_captured_text_reader() {
    let engine = text_engine(2 << 20);
    apply(
        &engine,
        3,
        Operation::Mutate(document_batch(
            "original",
            "row",
            json!({"value":"original", "tag":"occupied"}),
        )),
    )
    .unwrap();
    let previous = engine.generation().unwrap();
    let mut state = previous.state.clone();
    Arc::make_mut(
        state
            .collections
            .get_mut("docs")
            .unwrap()
            .documents
            .get_mut("row")
            .unwrap(),
    )
    .version = 0;
    // Use the real restored-state validator/index constructor. This is a valid
    // bound source/index pair, rather than a mismatched captured-generation fault.
    let restored = Arc::new(
        engine
            .prepare_state(
                &CapturedValidation::capture(&engine).unwrap().baseline(),
                state,
                previous.receipts.clone(),
                previous.backup_bindings.clone(),
                previous.terminals.clone(),
                previous.target_resolutions.clone(),
            )
            .unwrap(),
    );
    engine.publish_generation(Some(restored.clone()));
    assert_eq!(text_matches(&restored, "original"), [("row".into(), 0)]);

    let input = command(
        Operation::Mutate(MutationBatch {
            idempotency_key: "from-zero".into(),
            read_set: vec![ReadAssertion::Document {
                collection: "docs".into(),
                id: "row".into(),
                expected: ReadPrecondition::Version(0),
            }],
            operations: vec![Mutation::Put {
                collection: "docs".into(),
                id: "row".into(),
                body: json!({"value":"accepted", "tag":"occupied"}),
                expected: Precondition::Version(0),
            }],
        }),
        4,
    );
    let mut publisher = ObservingPublisher::new(&engine, false);
    fixture_publish(&engine, 4, &input, &mut publisher).unwrap();
    assert_eq!(publisher.calls, 1);
    let current = engine.generation().unwrap();
    let key = staged_digest(&("owner", "from-zero")).unwrap().0;
    assert!(current.receipts.get(&key).unwrap().is_some());
    assert_eq!(
        current.receipts.head().count,
        restored.receipts.head().count + 1
    );
    assert_eq!(text_matches(&current, "accepted"), [("row".into(), 4)]);
    assert!(text_matches(&current, "original").is_empty());
    assert_eq!(text_matches(&restored, "original"), [("row".into(), 0)]);
    assert!(text_matches(&restored, "accepted").is_empty());
}

#[test]
fn captured_index_corruption_is_outer_before_mutation_receipt_or_text_publication() {
    let engine = text_engine(2 << 20);
    apply(
        &engine,
        3,
        Operation::Mutate(document_batch(
            "original",
            "row",
            json!({"value":"original", "tag":"occupied"}),
        )),
    )
    .unwrap();
    let previous = engine.generation().unwrap();
    let mutation = document_batch(
        "corrupt-source",
        "row",
        json!({"value":"accepted", "tag":"occupied"}),
    );
    let input = command(Operation::Mutate(mutation.clone()), 4);
    let key = staged_digest(&("owner", "corrupt-source")).unwrap().0;
    for fault in 0..3 {
        let inconsistent = inconsistent_generation(&previous, fault);
        engine.publish_generation(Some(inconsistent.clone()));
        let mut publisher = ObservingPublisher::new(&engine, false);
        let failure = fixture_publish(&engine, 4, &input, &mut publisher)
            .expect_err("captured index/source corruption cannot select a receipt");
        assert_eq!(
            failure
                .operation_error()
                .unwrap()
                .downcast_ref::<Error>()
                .unwrap()
                .code,
            ErrorCode::Corruption
        );
        assert_eq!(publisher.calls, 0);
        let current = engine.generation().unwrap();
        assert!(Arc::ptr_eq(&current, &inconsistent));
        assert_eq!(current.receipts.head(), previous.receipts.head());
        assert_eq!(current.terminals.head(), previous.terminals.head());
        assert!(current.receipts.get(&key).unwrap().is_none());
        assert_eq!(text_matches(&previous, "original"), [("row".into(), 3)]);
        assert!(text_matches(&previous, "accepted").is_empty());
    }
    // Repair only the injected state mismatch. The original shared writer must
    // still accept the exact same attempt, without rebuilding its indexes.
    engine.publish_generation(Some(previous.clone()));
    apply(&engine, 4, Operation::Mutate(mutation)).unwrap();
    assert_eq!(
        text_matches(&engine.generation().unwrap(), "accepted"),
        [("row".into(), 4)]
    );
    assert_eq!(text_matches(&previous, "original"), [("row".into(), 3)]);
}

fn upload_stage(
    engine: &CodecFixture,
    id: &str,
    revision: u64,
    mutation: Mutation,
) -> StagedTransactionRef {
    upload_stage_operations(engine, id, revision, vec![mutation])
}

fn upload_stage_operations(
    engine: &CodecFixture,
    id: &str,
    revision: u64,
    operations: Vec<Mutation>,
) -> StagedTransactionRef {
    let chunk = StagedChunk {
        read_set: vec![],
        operations,
    };
    let begin = BeginStagedTransaction {
        scope: StagedTransactionScope {
            tenant: "tenant".into(),
            incarnation: "incarnation".into(),
            principal: "owner".into(),
        },
        transaction_id: id.into(),
        manifest: StagedManifest::from_chunks(std::slice::from_ref(&chunk)).unwrap(),
        ttl_ms: 60_000,
    };
    let reference = begin.reference().unwrap();
    apply(engine, revision, Operation::BeginStaged(begin)).unwrap();
    apply(
        engine,
        revision + 1,
        Operation::AppendStaged(AppendStagedChunk {
            transaction: reference.clone(),
            index: 0,
            chunk,
        }),
    )
    .unwrap();
    reference
}

#[test]
fn captured_index_corruption_leaves_staged_terminal_unselected_but_conflict_is_durable() {
    let engine = text_engine(2 << 20);
    apply(
        &engine,
        3,
        Operation::Mutate(document_batch(
            "original",
            "row",
            json!({"value":"original", "tag":"occupied"}),
        )),
    )
    .unwrap();
    let mutation = document_batch(
        "unused",
        "row",
        json!({"value":"accepted", "tag":"occupied"}),
    )
    .operations
    .remove(0);
    let reference = upload_stage(&engine, "staged-corruption", 4, mutation);
    let previous = engine.generation().unwrap();
    let inconsistent = inconsistent_generation(&previous, 0);
    let input = command(Operation::FinalizeStaged(reference.clone()), 6);
    let key = crate::state::staging::identity("owner", &reference.transaction_id).unwrap();

    // The direct ordered-staging helper must not turn the invariant error into
    // Finished { outcome: Err(..) } before its enclosing publication boundary.
    let mut direct = inconsistent.state.clone();
    direct.revision = 6;
    let before = serde_json::to_vec(&direct).unwrap();
    let failure =
        crate::state::staging::apply(&mut direct, &input, 6, &inconsistent.indexes).unwrap_err();
    assert_eq!(failure.code, ErrorCode::Corruption);
    assert_eq!(serde_json::to_vec(&direct).unwrap(), before);
    assert!(
        direct.staged_transactions[&key]
            .outcome
            .resolved()
            .is_none()
    );

    engine.publish_generation(Some(inconsistent.clone()));
    let mut publisher = ObservingPublisher::new(&engine, false);
    let failure = fixture_publish(&engine, 6, &input, &mut publisher)
        .expect_err("ordered caller must preserve outer staging corruption");
    assert_eq!(
        failure
            .operation_error()
            .unwrap()
            .downcast_ref::<Error>()
            .unwrap()
            .code,
        ErrorCode::Corruption
    );
    assert_eq!(publisher.calls, 0);
    let current = engine.generation().unwrap();
    assert!(Arc::ptr_eq(&current, &inconsistent));
    assert_eq!(current.terminals.head(), previous.terminals.head());
    assert_eq!(current.receipts.head(), previous.receipts.head());
    assert!(current.terminals.get(&key).unwrap().is_none());
    assert_eq!(text_matches(&previous, "original"), [("row".into(), 3)]);
    assert!(text_matches(&previous, "accepted").is_empty());

    engine.publish_generation(Some(previous));
    apply(&engine, 6, input.operation).unwrap();
    let accepted = engine.generation().unwrap();
    assert_eq!(text_matches(&accepted, "accepted"), [("row".into(), 6)]);
    assert!(
        accepted
            .terminals
            .get(&key)
            .unwrap()
            .unwrap()
            .stage
            .outcome
            .resolved()
            .unwrap()
            .is_ok()
    );

    // A validly scoped unique-key conflict still selects a permanent rejection.
    let mutation = document_batch(
        "unused",
        "other",
        json!({"value":"discarded", "tag":"occupied"}),
    )
    .operations
    .remove(0);
    let conflict = upload_stage(&engine, "staged-conflict", 7, mutation);
    let key = crate::state::staging::identity("owner", &conflict.transaction_id).unwrap();
    let failure = apply(&engine, 9, Operation::FinalizeStaged(conflict)).unwrap_err();
    assert_eq!(failure.code, ErrorCode::Conflict);
    let rejected = engine.generation().unwrap();
    assert_eq!(rejected.state.revision, 9);
    assert_eq!(
        rejected.terminals.head().count,
        accepted.terminals.head().count + 1
    );
    assert_eq!(
        rejected
            .terminals
            .get(&key)
            .unwrap()
            .unwrap()
            .stage
            .outcome
            .resolved()
            .unwrap(),
        Err(failure)
    );
    assert_eq!(text_matches(&rejected, "accepted"), [("row".into(), 6)]);
    assert!(text_matches(&rejected, "discarded").is_empty());
}

#[path = "ordered_command_input_tests.rs"]
mod ordered_input;
