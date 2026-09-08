use kasumi_engine::TenantEngine;
use kasumi_engine::test_utils::SnapshotFixture;
use kasumi_types::*;
use serde_json::json;
use std::collections::BTreeSet;

fn context() -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: "tenant".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "request".into(),
    }
}
fn engine(limit: u64) -> TenantEngine {
    TenantEngine::new(
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
            max_snapshot_bytes: limit,
            ..Default::default()
        },
    )
    .unwrap()
}
fn schema() -> Operation {
    Operation::CreateCollection(CollectionDefinition {
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        name: "docs".into(),
        schema: json!({"type":"object"}),
        indexes: vec![],
        strict_read_audit: false,
    })
}
fn batch(key: &str, id: &str, size: usize) -> Operation {
    Operation::Mutate(MutationBatch {
        read_set: Vec::new(),
        idempotency_key: key.into(),
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: id.into(),
            body: json!({"payload":"x".repeat(size)}),
            expected: Precondition::Any,
        }],
    })
}
fn apply(
    db: &TenantEngine,
    revision: u64,
    time: u64,
    operation: Operation,
) -> Result<WriteReceipt> {
    let result = db
        .apply_command(
            revision,
            Command {
                context: context(),
                timestamp_ms: time,
                operation,
            },
        )
        .unwrap();
    let snapshot = db.fixture_snapshot().unwrap();
    assert_eq!(db.snapshot_bytes().unwrap() as u64, snapshot.len());
    assert!(snapshot.len() <= db.generation().unwrap().state.limits.max_snapshot_bytes);
    result
}

#[test]
fn exact_incremental_accounting_covers_documents_receipts_expiry_schemas_policy_and_restore() {
    let db = engine(1 << 20);
    apply(&db, 1, 1, schema()).unwrap();
    for n in 2..30 {
        apply(
            &db,
            n,
            n,
            batch(
                &format!("key{n}"),
                &format!("id{}", n % 5),
                (n * 13) as usize,
            ),
        )
        .unwrap();
    }
    // Expire the entire old receipt cohort without losing size accounting.
    apply(&db, 30, 86_400_100, batch("fresh", "new", 20)).unwrap();
    assert_eq!(db.generation().unwrap().state.receipts.len(), 1);
    let delete = Operation::Mutate(MutationBatch {
        read_set: Vec::new(),
        idempotency_key: "delete".into(),
        operations: vec![Mutation::Delete {
            collection: "docs".into(),
            id: "id0".into(),
            expected: Precondition::Any,
        }],
    });
    apply(&db, 31, 86_400_101, delete).unwrap();
    let mut definition = db.generation().unwrap().state.collections["docs"]
        .definition
        .clone();
    definition.schema = json!({"type":"object","properties":{"payload":{"type":"string"}},"description":"schema metadata"});
    apply(
        &db,
        32,
        86_400_102,
        Operation::ReplaceCollection(definition),
    )
    .unwrap();
    let mut policy = db.generation().unwrap().state.policy.clone();
    policy.strict_read_audit = true;
    apply(&db, 33, 86_400_103, Operation::SetPolicy(policy)).unwrap();
    apply(&db, 34, 86_400_104, Operation::Suspend(true)).unwrap();
    apply(&db, 35, 86_400_105, Operation::Suspend(false)).unwrap();
    let snapshot = db.fixture_snapshot().unwrap();
    let recovered = engine(1 << 20);
    recovered.fixture_restore(&snapshot).unwrap();
    assert_eq!(recovered.fixture_snapshot().unwrap(), snapshot);
    apply(
        &recovered,
        36,
        86_400_106,
        batch("after-restore", "new", 500),
    )
    .unwrap();
}

#[test]
fn oversize_effects_become_a_durable_rejected_receipt_without_partial_documents() {
    let db = engine(8192);
    apply(&db, 1, 1, schema()).unwrap();
    let result = apply(&db, 2, 2, batch("too-large", "id", 7000));
    assert_eq!(result.unwrap_err().code, ErrorCode::QuotaExceeded);
    let generation = db.generation().unwrap();
    assert!(generation.state.collections["docs"].documents.is_empty());
    assert_eq!(generation.state.receipts.len(), 1);
    assert_eq!(
        generation
            .state
            .receipts
            .values()
            .next()
            .unwrap()
            .outcome
            .as_ref()
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(generation.state.audits.back().unwrap().outcome, "rejected");
    drop(generation);
    assert_eq!(
        apply(&db, 3, 3, batch("too-large", "id", 7000))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    apply(&db, 4, 4, batch("small", "id", 5)).unwrap();
}

#[test]
fn full_audit_byte_budget_still_advances_rejections_and_can_be_raised() {
    let db = engine(4096);
    apply(&db, 1, 1, schema()).unwrap();
    let mut failed = false;
    for revision in 2..110 {
        let result = apply(
            &db,
            revision,
            revision,
            Operation::Audit(AuditEvent {
                event_id: revision.to_string(),
                principal: "owner".into(),
                action: "read".into(),
                request_id: "request".into(),
                timestamp_ms: revision,
                data_revision: Some(revision - 1),
                outcome: "authorized_release".into(),
                collection: Some("docs".into()),
            }),
        );
        if let Err(error) = result {
            assert_eq!(error.code, ErrorCode::AuditUnavailable);
            failed = true;
        }
    }
    assert!(failed);
    let mut limits = db.generation().unwrap().state.limits.clone();
    limits.max_snapshot_bytes = 8192;
    apply(&db, 110, 110, Operation::SetLimits(limits)).unwrap();
    apply(&db, 111, 111, batch("after-increase", "id", 10)).unwrap();
}

#[test]
fn replay_with_only_rejection_audit_headroom_keeps_the_original_receipt() {
    let source = engine(16 << 10);
    apply(&source, 1, 1, schema()).unwrap();
    let original = apply(&source, 2, 2, batch("original", "id", 3000)).unwrap();
    let mut before = source.generation().unwrap().state.clone();
    apply(&source, 3, 3, batch("original", "id", 3000)).unwrap();
    let mut after = source.generation().unwrap().state.clone();
    // A committed replay audit is exactly one byte larger than a rejection
    // audit. Account for changing the serialized quota's own decimal digits.
    loop {
        let limit = kasumi_engine::test_utils::encode_snapshot_candidate(&after, 64 << 20)
            .unwrap()
            .len()
            + 19
            - 1;
        if after.limits.max_snapshot_bytes == limit {
            break;
        }
        after.limits.max_snapshot_bytes = limit;
    }
    before.limits.max_snapshot_bytes = after.limits.max_snapshot_bytes;
    let db = engine(16 << 10);
    db.fixture_restore(
        &kasumi_engine::test_utils::encode_snapshot_candidate(&before, 64 << 20).unwrap(),
    )
    .unwrap();
    assert_eq!(
        apply(&db, 3, 3, batch("original", "id", 3000))
            .unwrap_err()
            .code,
        ErrorCode::AuditUnavailable
    );
    let generation = db.generation().unwrap();
    assert_eq!(generation.state.audits.len(), before.audits.len() + 1);
    assert_eq!(generation.state.audits.back().unwrap().outcome, "rejected");
    assert_eq!(
        generation.state.receipts.values().next().unwrap().outcome,
        Ok(original)
    );
}

#[test]
fn recovery_and_limit_changes_cannot_admit_state_above_snapshot_format_or_tenant_budget() {
    let db = engine(16 << 10);
    apply(&db, 1, 1, schema()).unwrap();
    apply(&db, 2, 2, batch("large", "id", 5000)).unwrap();
    let mut state = db.generation().unwrap().state.clone();
    state.limits.max_snapshot_bytes = 4096;
    assert!(
        db.fixture_restore(
            &kasumi_engine::test_utils::encode_snapshot_candidate(&state, 64 << 20).unwrap()
        )
        .is_err()
    );
    let outcome = apply(&db, 3, 3, Operation::SetLimits(state.limits));
    assert_eq!(outcome.unwrap_err().code, ErrorCode::QuotaExceeded);
    assert_eq!(
        db.generation().unwrap().state.limits.max_snapshot_bytes,
        16 << 10
    );
    let mut invalid = db.generation().unwrap().state.limits.clone();
    invalid.max_snapshot_bytes = 0;
    assert_eq!(
        apply(&db, 4, 4, Operation::SetLimits(invalid))
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    let mut state = db.generation().unwrap().state.clone();
    state.limits.max_document_bytes = 1024;
    assert!(
        db.fixture_restore(
            &kasumi_engine::test_utils::encode_snapshot_candidate(&state, 64 << 20).unwrap()
        )
        .is_err()
    );
    assert_eq!(
        apply(&db, 5, 5, Operation::SetLimits(state.limits))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
}
