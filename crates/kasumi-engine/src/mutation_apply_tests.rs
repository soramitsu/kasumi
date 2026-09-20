use super::*;
use crate::test_utils::SnapshotFixture;
use serde_json::json;
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
fn engine(max_snapshot_bytes: u64) -> TenantEngine {
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
    engine
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
fn apply(engine: &TenantEngine, revision: u64, operation: Operation) -> Result<WriteReceipt> {
    engine
        .apply_command(revision, command(operation, revision))
        .unwrap()
}
#[test]
fn admitted_failure_survives_byte_exhaustion_expansion_and_snapshot_replay() {
    let engine = engine(16 << 10);
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
        .fixture_restore(&engine.fixture_snapshot().unwrap())
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
    let engine = engine(2 << 20);
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
        engine.apply_command(revision, input).unwrap().unwrap();
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
    let engine = engine(2 << 20);
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
    let source = engine(2 << 20);
    let previous = source.generation().unwrap();
    let mut state = previous.state.clone();
    state.revision = PREVIOUS_LIMIT + 1;
    let disk = kasumi_store::ScratchDisk::fixture();
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
            state,
            receipts,
            previous.terminals.clone(),
            previous.target_resolutions.clone(),
        )
        .unwrap();
    source.publish_generation(Some(Arc::new(generation)));
    drop(previous);
    let snapshot = source.logical_snapshot(&disk).unwrap();
    let restored = engine(2 << 20);
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
