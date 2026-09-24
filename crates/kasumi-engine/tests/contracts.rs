use kasumi_engine::test_utils::SnapshotFixture;
mod common;

use common::FixtureEngine;
use kasumi_engine::Database;
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

fn context(principal: &str) -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        principal: principal.into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: "test-request".into(),
    }
}
fn policy(strict_read_audit: bool) -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        }],
        strict_read_audit,
    }
}
fn definition() -> CollectionDefinition {
    CollectionDefinition {
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        name: "people".into(),
        schema: json!({"type":"object", "required":["email","age"], "properties":{"email":{"type":"string"},"age":{"type":"integer","minimum":0}}}),
        indexes: vec![IndexDefinition {
            name: "email_unique".into(),
            fields: vec![IndexField {
                path: "/email".into(),
                kind: ScalarType::String,
            }],
            unique: true,
            text: None,
        }],
        strict_read_audit: false,
    }
}
fn engine(strict: bool, limits: Limits) -> FixtureEngine {
    FixtureEngine::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
        "tenant-a".into(),
        "incarnation-a".into(),
        policy(strict),
        limits,
    )
    .unwrap()
}
fn command(operation: Operation) -> Command {
    Command {
        context: context("owner"),
        timestamp_ms: 1_000,
        operation,
    }
}
fn batch(key: &str, operations: Vec<Mutation>) -> MutationBatch {
    MutationBatch {
        read_set: Vec::new(),
        idempotency_key: key.into(),
        operations,
    }
}

#[test]
fn conditional_batches_fence_dependencies_and_phantoms_but_not_audits_or_replays() {
    let db = engine(false, Limits::default());
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(definition())),
    )
    .unwrap()
    .unwrap();
    db.apply_command(
        &db.disk,
        2,
        command(Operation::Mutate(batch(
            "seed",
            vec![put("a", "a", Precondition::Absent)],
        ))),
    )
    .unwrap()
    .unwrap();
    let read_set = vec![
        ReadAssertion::Snapshot {
            incarnation: "incarnation-a".into(),
            policy_epoch: 1,
            schema_epoch: 1,
        },
        ReadAssertion::Document {
            collection: "people".into(),
            id: "a".into(),
            expected: ReadPrecondition::Version(2),
        },
        ReadAssertion::Document {
            collection: "people".into(),
            id: "b".into(),
            expected: ReadPrecondition::Absent,
        },
        ReadAssertion::Collection {
            collection: "people".into(),
            data_epoch: 2,
        },
    ];
    db.apply_command(
        &db.disk,
        3,
        command(Operation::Audit(AuditEvent {
            event_id: "read-audit".into(),
            principal: "owner".into(),
            action: "read".into(),
            request_id: "test-request".into(),
            timestamp_ms: 1_000,
            data_revision: Some(2),
            outcome: "authorized_release".into(),
            collection: Some("people".into()),
        })),
    )
    .unwrap()
    .unwrap();
    let mut conditional = batch("conditional", vec![put("b", "b", Precondition::Absent)]);
    conditional.read_set = read_set.clone();
    let committed = db
        .apply_command(&db.disk, 4, command(Operation::Mutate(conditional.clone())))
        .unwrap()
        .unwrap();
    assert_eq!(
        db.generation().unwrap().state.collections["people"].data_epoch,
        4
    );
    let replay = db
        .apply_command(&db.disk, 5, command(Operation::Mutate(conditional)))
        .unwrap()
        .unwrap();
    assert_eq!(replay, committed);
    assert_eq!(
        db.generation().unwrap().state.collections["people"].data_epoch,
        4
    );
    for (index, assertion) in read_set.into_iter().skip(2).enumerate() {
        let mut rejected = batch(
            &format!("stale-{index}"),
            vec![put("c", "c", Precondition::Absent)],
        );
        rejected.read_set = vec![assertion];
        assert_eq!(
            db.apply_command(
                &db.disk,
                6 + index as u64,
                command(Operation::Mutate(rejected))
            )
            .unwrap()
            .unwrap_err()
            .code,
            ErrorCode::Conflict
        );
        assert!(
            !db.generation().unwrap().state.collections["people"]
                .documents
                .contains_key("c")
        );
        assert_eq!(
            db.generation().unwrap().state.collections["people"].data_epoch,
            4
        );
    }
    let snapshot = db.fixture_snapshot(&db.disk).unwrap();
    db.fixture_restore(&snapshot).unwrap();
    assert_eq!(db.fixture_snapshot(&db.disk).unwrap(), snapshot);
}

#[test]
fn not_before_uses_the_inclusive_leader_stamp_on_every_replica_and_retains_replays() {
    let mut observations = Vec::new();
    for _ in 0..2 {
        let db = engine(false, Limits::default());
        db.apply_command(
            &db.disk,
            1,
            command(Operation::CreateCollection(definition())),
        )
        .unwrap()
        .unwrap();
        db.apply_command(
            &db.disk,
            2,
            command(Operation::Mutate(batch(
                "lease-seed",
                vec![put("lease", "first-owner", Precondition::Absent)],
            ))),
        )
        .unwrap()
        .unwrap();

        let mut reclaim = batch(
            "reclaim-too-early",
            vec![put("lease", "second-owner", Precondition::Version(2))],
        );
        reclaim.read_set = vec![
            ReadAssertion::Document {
                collection: "people".into(),
                id: "lease".into(),
                expected: ReadPrecondition::Version(2),
            },
            ReadAssertion::NotBefore {
                not_before_ms: 2_000,
            },
            ReadAssertion::Before {
                not_after_ms: 2_000,
            },
        ];
        let mut early = command(Operation::Mutate(reclaim.clone()));
        early.timestamp_ms = 1_999;
        let denied = db.apply_command(&db.disk, 3, early).unwrap().unwrap_err();
        assert_eq!(denied.code, ErrorCode::Conflict);
        assert_eq!(
            db.generation().unwrap().state.collections["people"].documents["lease"].body["email"],
            "first-owner"
        );

        // A rejected receipt is permanent: advancing admission time cannot
        // reinterpret the original idempotency key as a new operation.
        let mut retry = command(Operation::Mutate(reclaim.clone()));
        retry.timestamp_ms = 2_000;
        assert_eq!(
            db.apply_command(&db.disk, 4, retry).unwrap().unwrap_err(),
            denied
        );

        reclaim.idempotency_key = "reclaim-at-bound".into();
        let mut admitted = command(Operation::Mutate(reclaim.clone()));
        admitted.timestamp_ms = 2_000;
        let receipt = db.apply_command(&db.disk, 5, admitted).unwrap().unwrap();
        assert_eq!(
            db.generation().unwrap().state.collections["people"].documents["lease"].body["email"],
            "second-owner"
        );

        // Exact receipt resolution precedes the original read assertions,
        // even if a replay arrives with a different leader timestamp.
        let mut replay = command(Operation::Mutate(reclaim));
        replay.timestamp_ms = 1_999;
        assert_eq!(
            db.apply_command(&db.disk, 6, replay).unwrap().unwrap(),
            receipt
        );
        observations.push((denied, receipt));
    }
    assert_eq!(observations[0], observations[1]);
}

#[test]
fn read_assertions_block_write_skew_and_require_read_authority() {
    let db = engine(false, Limits::default());
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(definition())),
    )
    .unwrap()
    .unwrap();
    db.apply_command(
        &db.disk,
        2,
        command(Operation::Mutate(batch(
            "seed",
            vec![
                put("a", "a", Precondition::Absent),
                put("b", "b", Precondition::Absent),
            ],
        ))),
    )
    .unwrap()
    .unwrap();
    let mut first = batch("first", vec![put("a", "a-new", Precondition::Version(2))]);
    first.read_set = vec![ReadAssertion::Document {
        collection: "people".into(),
        id: "b".into(),
        expected: ReadPrecondition::Version(2),
    }];
    db.apply_command(&db.disk, 3, command(Operation::Mutate(first)))
        .unwrap()
        .unwrap();
    let mut second = batch("second", vec![put("b", "b-new", Precondition::Version(2))]);
    second.read_set = vec![ReadAssertion::Document {
        collection: "people".into(),
        id: "a".into(),
        expected: ReadPrecondition::Version(2),
    }];
    assert_eq!(
        db.apply_command(&db.disk, 4, command(Operation::Mutate(second.clone())))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    second.idempotency_key = "write-only".into();
    let mut input = command(Operation::Mutate(second));
    input.context.scopes.remove(&Action::Read);
    assert_eq!(
        db.apply_command(&db.disk, 5, input)
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        db.generation().unwrap().state.collections["people"].documents["b"].body["email"],
        "b"
    );
}

#[test]
fn append_only_mode_rejects_overwrite_delete_and_schema_weakening_atomically() {
    let db = engine(false, Limits::default());
    let mut immutable = definition();
    immutable.write_mode = CollectionWriteMode::AppendOnly;
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(immutable.clone())),
    )
    .unwrap()
    .unwrap();
    db.apply_command(
        &db.disk,
        2,
        command(Operation::Mutate(batch(
            "seed",
            vec![put("a", "a", Precondition::Absent)],
        ))),
    )
    .unwrap()
    .unwrap();
    for (offset, mutation) in [
        put("a", "changed", Precondition::Version(2)),
        Mutation::Delete {
            collection: "people".into(),
            id: "a".into(),
            expected: Precondition::Version(2),
        },
        put("unconditional", "u", Precondition::Any),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            db.apply_command(
                &db.disk,
                3 + offset as u64,
                command(Operation::Mutate(batch(
                    &format!("forbidden-{offset}"),
                    vec![put("b", "b", Precondition::Absent), mutation]
                )))
            )
            .unwrap()
            .unwrap_err()
            .code,
            ErrorCode::Forbidden
        );
        assert!(
            !db.generation().unwrap().state.collections["people"]
                .documents
                .contains_key("b")
        );
    }
    assert_eq!(
        db.apply_command(
            &db.disk,
            6,
            command(Operation::ReplaceCollection(definition()))
        )
        .unwrap()
        .unwrap_err()
        .code,
        ErrorCode::Forbidden
    );
    assert_eq!(db.generation().unwrap().state.schema_epoch, 1);
    db.apply_command(
        &db.disk,
        7,
        command(Operation::ReplaceCollection(immutable)),
    )
    .unwrap()
    .unwrap();
    assert_eq!(db.generation().unwrap().state.schema_epoch, 2);
    assert_eq!(
        db.generation().unwrap().state.collections["people"].data_epoch,
        2
    );
}

#[test]
fn boi_first_owner_and_state_commit_atomically_then_survive_snapshot_with_version_cas() {
    let db = engine(false, Limits::default());
    for (revision, name, write_mode, schema) in [
        (
            1,
            "boi_core_owner",
            CollectionWriteMode::AppendOnly,
            json!({"type":"object", "required":["schema","owner"], "additionalProperties":false,
                   "properties":{"schema":{"const":"boi.core-owner.v1"},
                                 "owner":{"const":"boi-core.is2"}}}),
        ),
        (
            2,
            "boi_core_state",
            CollectionWriteMode::Mutable,
            json!({"type":"object", "required":["schema","owner","state"],
                   "additionalProperties":false,
                   "properties":{"schema":{"const":"boi.central-state.v1"},
                                 "owner":{"const":"boi-core.is2"},
                                 "state":{"type":"object"}}}),
        ),
    ] {
        db.apply_command(
            &db.disk,
            revision,
            command(Operation::CreateCollection(CollectionDefinition {
                name: name.into(),
                write_mode,
                retention_class: CollectionRetentionClass::Operational,
                schema,
                indexes: vec![],
                strict_read_audit: false,
            })),
        )
        .unwrap()
        .unwrap();
    }
    let generation = db.generation().unwrap();
    let mut initial = batch(
        "boi-initialize",
        vec![
            Mutation::Put {
                collection: "boi_core_owner".into(),
                id: "owner".into(),
                body: json!({"schema":"boi.core-owner.v1", "owner":"boi-core.is2"}),
                expected: Precondition::Absent,
            },
            Mutation::Put {
                collection: "boi_core_state".into(),
                id: "central-state".into(),
                body: json!({"schema":"boi.central-state.v1", "owner":"boi-core.is2",
                             "state":{"payments":[]}}),
                expected: Precondition::Absent,
            },
        ],
    );
    initial.read_set = vec![
        ReadAssertion::Snapshot {
            incarnation: generation.state.incarnation.clone(),
            policy_epoch: generation.state.policy_epoch,
            schema_epoch: generation.state.schema_epoch,
        },
        ReadAssertion::Collection {
            collection: "boi_core_owner".into(),
            data_epoch: generation.state.collections["boi_core_owner"].data_epoch,
        },
        ReadAssertion::Collection {
            collection: "boi_core_state".into(),
            data_epoch: generation.state.collections["boi_core_state"].data_epoch,
        },
    ];
    drop(generation);
    let mut malformed = initial.clone();
    malformed.idempotency_key = "boi-malformed-initial-state".into();
    let Mutation::Put { body, .. } = &mut malformed.operations[1] else {
        unreachable!()
    };
    *body = json!({"schema":"boi.central-state.v1", "owner":"boi-core.is2",
                   "state":[]});
    assert_eq!(
        db.apply_command(&db.disk, 3, command(Operation::Mutate(malformed)))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::SchemaViolation
    );
    let generation = db.generation().unwrap();
    assert!(
        !generation.state.collections["boi_core_owner"]
            .documents
            .contains_key("owner")
    );
    assert!(
        !generation.state.collections["boi_core_state"]
            .documents
            .contains_key("central-state")
    );
    drop(generation);
    let initial_receipt = db
        .apply_command(&db.disk, 4, command(Operation::Mutate(initial.clone())))
        .unwrap()
        .unwrap();
    let generation = db.generation().unwrap();
    assert_eq!(
        generation.state.collections["boi_core_owner"].documents["owner"].version,
        4
    );
    assert_eq!(
        generation.state.collections["boi_core_state"].documents["central-state"].version,
        4
    );
    drop(generation);

    let mut other_claim = initial.clone();
    other_claim.idempotency_key = "boi-other-owner".into();
    assert_eq!(
        db.apply_command(&db.disk, 5, command(Operation::Mutate(other_claim)))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let update = batch(
        "boi-payment-1",
        vec![Mutation::Put {
            collection: "boi_core_state".into(),
            id: "central-state".into(),
            body: json!({"schema":"boi.central-state.v1", "owner":"boi-core.is2",
                         "state":{"payments":["payment-1"]}}),
            expected: Precondition::Version(4),
        }],
    );
    let update_receipt = db
        .apply_command(&db.disk, 6, command(Operation::Mutate(update.clone())))
        .unwrap()
        .unwrap();
    let mut stale = update.clone();
    stale.idempotency_key = "boi-stale-payment".into();
    assert_eq!(
        db.apply_command(&db.disk, 7, command(Operation::Mutate(stale)))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let snapshot = db.fixture_snapshot(&db.disk).unwrap();
    db.fixture_restore(&snapshot).unwrap();
    let recovered = db.generation().unwrap();
    assert_eq!(
        recovered.state.collections["boi_core_owner"].documents["owner"].version,
        4
    );
    assert_eq!(
        recovered.state.collections["boi_core_state"].documents["central-state"].version,
        6
    );
    assert_eq!(
        recovered.state.collections["boi_core_state"].documents["central-state"].body["state"]["payments"],
        json!(["payment-1"])
    );
    drop(recovered);
    assert_eq!(
        db.apply_command(&db.disk, 8, command(Operation::Mutate(initial)))
            .unwrap()
            .unwrap(),
        initial_receipt
    );
    assert_eq!(
        db.apply_command(&db.disk, 9, command(Operation::Mutate(update)))
            .unwrap()
            .unwrap(),
        update_receipt
    );
}
fn put(id: &str, email: &str, expected: Precondition) -> Mutation {
    Mutation::Put {
        collection: "people".into(),
        id: id.into(),
        body: json!({"email":email,"age":30}),
        expected,
    }
}
fn query() -> QueryRequest {
    serde_json::from_value(json!({"collection":"people","allow_scan":true,"limit":1})).unwrap()
}

#[test]
fn audit_budget_blocks_effects_and_can_be_increased_without_losing_records() {
    let limits = Limits {
        audit_retention: AuditRetentionBudget {
            hot_bytes: 128 << 10,
            ..AuditRetentionBudget::default()
        },
        ..Limits::default()
    };
    let db = engine(false, limits);
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(definition())),
    )
    .unwrap()
    .unwrap();
    let mut revision = 1;
    loop {
        revision += 1;
        match db
            .apply_command(
                &db.disk,
                revision,
                command(Operation::SetPolicy(policy(false))),
            )
            .unwrap()
        {
            Ok(_) => assert!(revision < 2000, "hot budget did not fill"),
            Err(error) => {
                assert_eq!(error.code, ErrorCode::AuditUnavailable);
                break;
            }
        }
    }
    let retained = db.generation().unwrap().state.audits.len();
    assert!(retained > 1);
    let write = command(Operation::Mutate(batch(
        "audit-cap",
        vec![put("a", "a", Precondition::Absent)],
    )));
    assert_eq!(
        db.apply_command(&db.disk, revision + 1, write.clone())
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::AuditUnavailable
    );
    assert_eq!(db.generation().unwrap().state.document_count, 0);
    assert_eq!(
        db.generation().unwrap().state.mutation_receipt_head.count,
        0
    );
    let limits = Limits {
        audit_retention: AuditRetentionBudget {
            hot_bytes: 256 << 10,
            ..AuditRetentionBudget::default()
        },
        ..Limits::default()
    };
    db.apply_command(
        &db.disk,
        revision + 2,
        command(Operation::SetLimits(limits)),
    )
    .unwrap()
    .unwrap();
    db.apply_command(&db.disk, revision + 3, write)
        .unwrap()
        .unwrap();
    assert_eq!(db.generation().unwrap().state.document_count, 1);
    assert_eq!(db.generation().unwrap().state.audits.len(), retained + 2);
    let snapshot = db.fixture_snapshot(&db.disk).unwrap();
    db.fixture_restore(&snapshot).unwrap();
    assert_eq!(
        db.generation()
            .unwrap()
            .state
            .audits
            .front()
            .unwrap()
            .data_revision,
        Some(1)
    );
}

#[test]
fn permanent_receipts_ignore_former_expiry_boundaries_and_survive_snapshot_recovery() {
    let db = engine(false, Limits::default());
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(definition())),
    )
    .unwrap()
    .unwrap();
    let make = |key: &str, id: &str, timestamp_ms: u64| Command {
        timestamp_ms,
        ..command(Operation::Mutate(batch(
            key,
            vec![put(id, id, Precondition::Any)],
        )))
    };
    let first = db
        .apply_command(&db.disk, 2, make("first", "a", 1000))
        .unwrap()
        .unwrap();
    db.apply_command(&db.disk, 3, make("second", "b", 2000))
        .unwrap()
        .unwrap();
    db.apply_command(&db.disk, 4, make("third", "c", 86_400_999))
        .unwrap()
        .unwrap();
    assert_eq!(
        db.apply_command(&db.disk, 5, make("first", "a", 86_401_000))
            .unwrap()
            .unwrap(),
        first
    );
    assert_eq!(
        db.generation().unwrap().state.mutation_receipt_head.count,
        3
    );
    db.fixture_restore(&db.fixture_snapshot(&db.disk).unwrap())
        .unwrap();
    assert_eq!(
        db.apply_command(&db.disk, 6, make("first", "d", 86_402_000))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        db.apply_command(&db.disk, 7, make("first", "a", u64::MAX - 1))
            .unwrap()
            .unwrap(),
        first
    );
    assert_eq!(
        db.generation().unwrap().state.mutation_receipt_head.count,
        3
    );
    assert!(
        !db.generation().unwrap().state.collections["people"]
            .documents
            .contains_key("d")
    );
}

#[test]
fn retirement_is_terminal_and_survives_snapshot_recovery() {
    let db = engine(false, Limits::default());
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(definition())),
    )
    .unwrap()
    .unwrap();
    let generation = db.generation().unwrap();
    let request = RetireSourceRequest {
        retirement_id: "replica-retire".into(),
        expected_source_incarnation: generation.state.incarnation.clone(),
        target_incarnation: uuid::Uuid::new_v4().to_string(),
        checkpoint: FullBackupCheckpoint {
            tenant: generation.state.tenant.clone(),
            source_incarnation: generation.state.incarnation.clone(),
            revision: 1,
            resident_sha256: "00".repeat(32),
            backup_id: uuid::Uuid::new_v4(),
            manifest_ciphertext_sha256: "00".repeat(32),
            key_lineage_digest: "00".repeat(32),
        },
        destination: "approved".into(),
        not_after_ms: u64::MAX,
    };
    drop(generation);
    // Pure replica apply receives a trusted leader preparation. Actual graph
    // verification and admission are exercised by the encrypted service tests.
    db.apply_command(
        &db.disk,
        2,
        command(Operation::RetireSource(PreparedRetirement {
            request,
            verified_closure_digest: "00".repeat(32),
            observation: Some(RetirementObservation {
                revision: 1,
                closure_digest: "00".repeat(32),
            }),
        })),
    )
    .unwrap()
    .unwrap();
    let restored = engine(false, Limits::default());
    restored
        .fixture_restore(&db.fixture_snapshot(&db.disk).unwrap())
        .unwrap();
    assert!(restored.generation().unwrap().state.retired);
    assert_eq!(
        restored
            .authorize(&context("owner"), Some("people"), Action::Read)
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );
    assert_eq!(
        restored
            .apply_command(&restored.disk, 3, command(Operation::Suspend(false)))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );
    assert_eq!(
        restored
            .apply_command(
                &restored.disk,
                4,
                command(Operation::Mutate(batch(
                    "retired",
                    vec![put("a", "a", Precondition::Any)]
                )))
            )
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );
    assert!(
        restored.generation().unwrap().state.collections["people"]
            .documents
            .is_empty()
    );
}

#[test]
fn batch_failure_leaves_no_partial_document_or_index_effects() {
    let db = engine(false, Limits::default());
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(definition())),
    )
    .unwrap()
    .unwrap();
    let invalid = Mutation::Put {
        collection: "people".into(),
        id: "bad".into(),
        body: json!({"email":"b","age":-1}),
        expected: Precondition::Any,
    };
    let outcome = db
        .apply_command(
            &db.disk,
            2,
            command(Operation::Mutate(batch(
                "bad-batch",
                vec![put("a", "a", Precondition::Any), invalid],
            ))),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(outcome.code, ErrorCode::SchemaViolation);
    let state = db.generation().unwrap();
    assert_eq!(state.state.document_count, 0);
    assert_eq!(state.state.logical_bytes, 0);
    assert!(state.state.collections["people"].documents.is_empty());
    assert_eq!(state.state.audits.back().unwrap().outcome, "rejected");
    assert!(
        state
            .indexes
            .execute(&state.state.collections, &query(), &state.state.limits)
            .unwrap()
            .rows
            .is_empty()
    );
}

#[test]
fn receipts_survive_snapshot_and_precede_changed_schema_and_cas() {
    let db = engine(false, Limits::default());
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(definition())),
    )
    .unwrap()
    .unwrap();
    let input = batch("insert-once", vec![put("a", "a", Precondition::Absent)]);
    let expected = db
        .apply_command(&db.disk, 2, command(Operation::Mutate(input.clone())))
        .unwrap()
        .unwrap();
    let mut updated = definition();
    updated.schema["properties"]["age"]["maximum"] = json!(40);
    db.apply_command(&db.disk, 3, command(Operation::ReplaceCollection(updated)))
        .unwrap()
        .unwrap();
    let restored = engine(false, Limits::default());
    restored
        .fixture_restore(&db.fixture_snapshot(&db.disk).unwrap())
        .unwrap();
    assert_eq!(
        restored
            .apply_command(&restored.disk, 4, command(Operation::Mutate(input)))
            .unwrap()
            .unwrap(),
        expected
    );
    assert_eq!(
        restored.generation().unwrap().state.collections["people"].documents["a"].version,
        2
    );
    let conflict = restored
        .apply_command(
            &restored.disk,
            5,
            command(Operation::Mutate(batch(
                "insert-once",
                vec![put("a", "different", Precondition::Any)],
            ))),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(conflict.code, ErrorCode::Conflict);
}

#[test]
fn unique_index_swap_is_atomic_and_old_generation_remains_coherent() {
    let db = engine(false, Limits::default());
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(definition())),
    )
    .unwrap()
    .unwrap();
    db.apply_command(
        &db.disk,
        2,
        command(Operation::Mutate(batch(
            "initial",
            vec![
                put("a", "a", Precondition::Any),
                put("b", "b", Precondition::Any),
            ],
        ))),
    )
    .unwrap()
    .unwrap();
    let previous = db.generation().unwrap();
    db.apply_command(
        &db.disk,
        3,
        command(Operation::Mutate(batch(
            "swap",
            vec![
                put("a", "b", Precondition::Version(2)),
                put("b", "a", Precondition::Version(2)),
            ],
        ))),
    )
    .unwrap()
    .unwrap();
    let current = db.generation().unwrap();
    let mut request = query();
    request.allow_scan = false;
    request.filter = Predicate::Eq {
        field: "/email".into(),
        value: json!("a"),
    };
    assert_eq!(
        previous
            .indexes
            .execute(
                &previous.state.collections,
                &request,
                &previous.state.limits
            )
            .unwrap()
            .rows[0]
            .id,
        "a"
    );
    assert_eq!(
        current
            .indexes
            .execute(&current.state.collections, &request, &current.state.limits)
            .unwrap()
            .rows[0]
            .id,
        "b"
    );
}

#[test]
fn concurrent_cas_has_exactly_one_winner() {
    let db = Arc::new(engine(false, Limits::default()));
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(definition())),
    )
    .unwrap()
    .unwrap();
    db.apply_command(
        &db.disk,
        2,
        command(Operation::Mutate(batch(
            "initial",
            vec![put("a", "a", Precondition::Any)],
        ))),
    )
    .unwrap()
    .unwrap();
    // Consensus serializes order: two clients observe version 2 but both cannot replace it.
    let first = db
        .apply_command(
            &db.disk,
            3,
            command(Operation::Mutate(batch(
                "writer1",
                vec![put("a", "b", Precondition::Version(2))],
            ))),
        )
        .unwrap();
    let second = db
        .apply_command(
            &db.disk,
            4,
            command(Operation::Mutate(batch(
                "writer2",
                vec![put("a", "c", Precondition::Version(2))],
            ))),
        )
        .unwrap();
    assert!(first.is_ok());
    assert_eq!(second.unwrap_err().code, ErrorCode::Conflict);
    assert_eq!(
        db.generation().unwrap().state.collections["people"].documents["a"].body["email"],
        "b"
    );
}

#[test]
fn tampered_snapshot_never_changes_current_generation() {
    let db = engine(false, Limits::default());
    let before = db.fixture_snapshot(&db.disk).unwrap();
    let mut corrupt = kasumi_engine::test_utils::decode_snapshot_candidate(&before).unwrap();
    corrupt.logical_bytes = 999;
    assert_eq!(
        db.fixture_restore(
            &kasumi_engine::test_utils::encode_snapshot_candidate(&db.disk, &corrupt, 64 << 20)
                .unwrap()
        )
        .unwrap_err()
        .code,
        ErrorCode::Corruption
    );
    assert_eq!(db.fixture_snapshot(&db.disk).unwrap(), before);
    corrupt.tenant = "other".into();
    assert!(
        db.fixture_restore(
            &kasumi_engine::test_utils::encode_snapshot_candidate(&db.disk, &corrupt, 64 << 20)
                .unwrap()
        )
        .is_err()
    );
}

#[test]
fn authorization_is_rechecked_before_idempotency_response() {
    let db = engine(false, Limits::default());
    db.apply_command(
        &db.disk,
        1,
        command(Operation::CreateCollection(definition())),
    )
    .unwrap()
    .unwrap();
    let input = batch("initial", vec![put("a", "a", Precondition::Any)]);
    db.apply_command(&db.disk, 2, command(Operation::Mutate(input.clone())))
        .unwrap()
        .unwrap();
    let new_policy = Policy {
        grants: vec![Grant {
            principal: "new-owner".into(),
            collection: None,
            actions: context("new-owner").scopes,
        }],
        strict_read_audit: false,
    };
    db.apply_command(&db.disk, 3, command(Operation::SetPolicy(new_policy)))
        .unwrap()
        .unwrap();
    assert_eq!(
        db.apply_command(&db.disk, 4, command(Operation::Mutate(input)))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
}

async fn database(
    strict: bool,
) -> (
    tempfile::TempDir,
    common::PhysicalFixture,
    Arc<Database>,
    Arc<LocalKeyProvider>,
    Arc<TenantStore>,
    Arc<kasumi_engine::SecurityAudit>,
) {
    let dir = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical = common::PhysicalFixture::new(&dir.path().join("node.redb"), Default::default());
    let node = physical
        .storage
        .create_new(
            dir.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let audit = common::security_audit(node.clone(), physical.storage.admission.clone()).await;
    let key = Arc::new(LocalKeyProvider::new([7; 32]));
    let store = TenantStore::initialize_catalog_fixture(node, "tenant-a".into(), key.clone())
        .await
        .unwrap();
    let db = kasumi_engine::test_utils::open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
            store.clone(),
            Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        policy(strict),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    db.administer(context("owner"), Operation::CreateCollection(definition()))
        .await
        .unwrap();
    (dir, physical, db, key, store, audit)
}

#[tokio::test]
async fn mixed_put_delete_receipt_reports_one_revision_for_every_target_and_replay() {
    let (_dir, _physical, db, _key, _store, audit) = database(false).await;
    let seeded = db
        .mutate(
            context("owner"),
            batch("mixed-seed", vec![put("old", "old", Precondition::Absent)]),
        )
        .await
        .unwrap();
    let mixed = batch(
        "mixed-targets",
        vec![
            put("new", "new", Precondition::Absent),
            Mutation::Delete {
                collection: "people".into(),
                id: "old".into(),
                expected: Precondition::Version(seeded.revision),
            },
        ],
    );
    let receipt = db.mutate(context("owner"), mixed.clone()).await.unwrap();
    assert_eq!(receipt.versions.len(), 2);
    assert_eq!(receipt.versions.get("/people/new"), Some(&receipt.revision));
    assert_eq!(receipt.versions.get("/people/old"), Some(&receipt.revision));
    assert_eq!(db.mutate(context("owner"), mixed).await.unwrap(), receipt);
    assert_eq!(
        db.operation_receipt(&context("owner"), "mixed-targets")
            .await
            .unwrap()
            .unwrap()
            .outcome
            .unwrap(),
        receipt
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn actual_raft_writes_queries_and_snapshot_pagination() {
    let (_dir, _physical, db, _key, _store, audit) = database(false).await;
    db.mutate(
        context("owner"),
        batch(
            "start",
            vec![
                put("a", "a", Precondition::Any),
                put("b", "b", Precondition::Any),
            ],
        ),
    )
    .await
    .unwrap();
    let first = db.query(&context("owner"), query()).await.unwrap();
    assert_eq!(first.rows[0].id, "a");
    db.mutate(
        context("owner"),
        batch("update", vec![put("b", "new-b", Precondition::Any)]),
    )
    .await
    .unwrap();
    let mut next = query();
    next.cursor = first.cursor;
    let second = db.query(&context("owner"), next).await.unwrap();
    assert_eq!(second.revision, first.revision);
    assert_eq!(second.rows[0].body["email"], "b");
    assert_eq!(
        db.get(&context("owner"), "people", "b").await.unwrap().body["email"],
        "new-b"
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn coherent_snapshot_reads_span_collections_under_concurrent_commits_and_strict_audit() {
    let (_dir, _physical, db, _key, _store, audit) = database(true).await;
    let mut mirror = definition();
    mirror.name = "mirror".into();
    db.administer(context("owner"), Operation::CreateCollection(mirror))
        .await
        .unwrap();
    let pair = |value: &str| {
        let first = put("a", value, Precondition::Any);
        let mut second = first.clone();
        if let Mutation::Put { collection, .. } = &mut second {
            *collection = "mirror".into();
        }
        vec![first, second]
    };
    db.mutate(context("owner"), batch("initial-pair", pair("0")))
        .await
        .unwrap();
    let writer_db = db.clone();
    let writer = tokio::spawn(async move {
        for value in 1..=12 {
            writer_db
                .mutate(
                    context("owner"),
                    batch(&format!("pair-{value}"), pair(&value.to_string())),
                )
                .await
                .unwrap();
        }
    });
    for _ in 0..12 {
        let snapshot = db
            .read_snapshot(
                &context("owner"),
                ReadSnapshotRequest {
                    documents: vec![
                        DocumentKey {
                            collection: "people".into(),
                            id: "a".into(),
                        },
                        DocumentKey {
                            collection: "people".into(),
                            id: "missing".into(),
                        },
                    ],
                    queries: vec![
                        serde_json::from_value(
                            json!({"collection":"mirror","allow_scan":true,"limit":100}),
                        )
                        .unwrap(),
                    ],
                    time_bounds: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            snapshot.documents[0].document.as_ref().unwrap().body["email"],
            snapshot.queries[0].rows[0].body["email"]
        );
        assert!(snapshot.documents[1].document.is_none());
        assert_eq!(snapshot.queries[0].revision, snapshot.revision);
        assert_eq!(snapshot.collection_epochs.len(), 1);
        assert!(snapshot.collection_epochs.contains_key("mirror"));
        let state = db.engine().generation().unwrap();
        assert!(state.state.audits.iter().any(|event| event.action == "read"
            && event.collection.as_deref() == Some("mirror")
            && event.data_revision == Some(snapshot.revision)));
    }
    writer.await.unwrap();
    let snapshot = db
        .read_snapshot(
            &context("owner"),
            ReadSnapshotRequest {
                documents: vec![DocumentKey {
                    collection: "people".into(),
                    id: "a".into(),
                }],
                queries: Vec::new(),
                time_bounds: None,
            },
        )
        .await
        .unwrap();
    let mut conditional = batch(
        "snapshot-dependent",
        vec![put("b", "b", Precondition::Absent)],
    );
    conditional.read_set = snapshot.read_assertions();
    db.mutate(context("owner"), conditional).await.unwrap();
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn snapshot_reads_reject_partial_queries_cursors_and_foreign_authority() {
    let (_dir, _physical, db, _key, _store, audit) = database(false).await;
    db.mutate(
        context("owner"),
        batch(
            "two",
            vec![
                put("a", "a", Precondition::Absent),
                put("b", "b", Precondition::Absent),
            ],
        ),
    )
    .await
    .unwrap();
    let mut request = ReadSnapshotRequest {
        documents: Vec::new(),
        queries: vec![query()],
        time_bounds: None,
    };
    assert_eq!(
        db.read_snapshot(&context("owner"), request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    request.queries[0].limit = 2;
    assert_eq!(
        db.read_snapshot(&context("other"), request.clone())
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    request.queries[0].cursor = Some("cursor".into());
    assert_eq!(
        db.read_snapshot(&context("owner"), request)
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn strict_read_audit_is_committed_before_return_and_tied_to_data_revision() {
    let (_dir, _physical, db, _key, _store, audit) = database(true).await;
    let write = db
        .mutate(
            context("owner"),
            batch("start", vec![put("a", "a", Precondition::Any)]),
        )
        .await
        .unwrap();
    db.get(&context("owner"), "people", "a").await.unwrap();
    let generation = db.engine().generation().unwrap();
    let event = generation.state.audits.back().unwrap();
    assert_eq!(event.action, "read");
    assert_eq!(event.data_revision, Some(write.revision));
    assert!(generation.state.revision > write.revision);
    assert_eq!(event.outcome, "authorized_release");
    assert!(
        db.operation_receipt(&context("owner"), "start")
            .await
            .unwrap()
            .unwrap()
            .outcome
            .is_ok()
    );
    assert_eq!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .audits
            .back()
            .unwrap()
            .action,
        "receipt"
    );
    assert!(
        db.operation_receipt(&context("owner"), "missing")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .audits
            .back()
            .unwrap()
            .collection,
        None
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn shared_get_uses_the_same_audit_and_authorization_and_keeps_historical_values() {
    let (_dir, _physical, db, _key, store, audit) = database(true).await;
    let write = db
        .mutate(
            context("owner"),
            batch(
                "shared-start",
                vec![put("a", "before", Precondition::Absent)],
            ),
        )
        .await
        .unwrap();
    let shared = db
        .get_shared(&context("owner"), "people", "a")
        .await
        .unwrap();
    let generation = db.engine().generation().unwrap();
    assert!(Arc::ptr_eq(
        &shared,
        &generation.state.collections["people"].documents["a"]
    ));
    let read_audit = generation.state.audits.back().unwrap();
    assert_eq!(read_audit.action, "read");
    assert_eq!(read_audit.outcome, "authorized_release");
    assert_eq!(read_audit.data_revision, Some(write.revision));
    assert_eq!(
        db.get_shared(&context("outsider"), "people", "a")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    drop(generation);
    db.mutate(
        context("owner"),
        batch("shared-update", vec![put("a", "after", Precondition::Any)]),
    )
    .await
    .unwrap();
    let current = db
        .get_shared(&context("owner"), "people", "a")
        .await
        .unwrap();
    assert_eq!(shared.body["email"], "before");
    assert_eq!(current.body["email"], "after");
    assert!(!Arc::ptr_eq(&shared, &current));
    let mut detached = current.clone();
    Arc::make_mut(&mut detached).body["email"] = json!("client-only");
    assert_eq!(current.body["email"], "after");
    assert_eq!(
        db.get(&context("owner"), "people", "a").await.unwrap().body["email"],
        "after"
    );
    store.seal();
    assert_eq!(
        db.get_shared(&context("owner"), "people", "a")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );
    // A prior authorized release is owned by the trusted embedding application.
    assert_eq!(shared.body["email"], "before");
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn strict_empty_discovery_is_audited_and_failed_audit_persistence_blocks_results() {
    let audit_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical = common::PhysicalFixture::new(
        &audit_directory.path().join("synthetic-owner"),
        Default::default(),
    );
    let backend = kasumi_store::test_utils::FaultBackend::new();
    let node = NodeStore::open_fixture_backend_on_disk(
        backend.clone(),
        kasumi_store::test_utils::storage_admission(),
        physical.storage.persistent.clone(),
        physical.storage.scratch.clone(),
    )
    .unwrap();
    let audit_store = TenantStore::initialize_catalog_fixture(
        node.clone(),
        kasumi_engine::SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([0xA7; 32])),
    )
    .await
    .unwrap();
    let audit = kasumi_engine::SecurityAudit::initialize_with_archive(
        audit_store,
        kasumi_types::AuditRetentionBudget::default(),
        Arc::new(
            kasumi_store::FilesystemAuditArchive::open_fixture(
                audit_directory.path().join("archive"),
                physical.storage.admission.memory().clone(),
            )
            .unwrap(),
        ),
        physical.storage.admission.clone(),
    )
    .unwrap();
    let store = TenantStore::initialize_catalog_fixture(
        node,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([45; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::test_utils::open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
            store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        policy(true),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    assert!(db.collections(&context("owner")).await.unwrap().is_empty());
    assert_eq!(
        db.engine()
            .generation()
            .unwrap()
            .state
            .audits
            .back()
            .unwrap()
            .action,
        "discovery"
    );
    db.administer(context("owner"), Operation::CreateCollection(definition()))
        .await
        .unwrap();
    db.mutate(
        context("owner"),
        batch(
            "before-fault",
            vec![put("a", "private", Precondition::Absent)],
        ),
    )
    .await
    .unwrap();
    backend.fail_after(0);
    let result = db.get(&context("owner"), "people", "a").await;
    assert!(
        result.is_err(),
        "required audit failure must never release document data"
    );
    assert!(matches!(
        result.unwrap_err().code,
        ErrorCode::AuditUnavailable | ErrorCode::Unavailable | ErrorCode::Sealed
    ));
    let failure = db.shutdown().await.unwrap_err();
    let repeated = db.shutdown().await.unwrap_err();
    assert_eq!(
        failure.completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    assert_eq!(
        repeated.completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    assert_eq!(failure.issues().len(), 2, "{failure:?}");
    assert_eq!(repeated.issues().len(), 2, "{repeated:?}");
    for issue in failure.issues() {
        let again = repeated
            .issues()
            .iter()
            .find(|candidate| {
                candidate.component() == issue.component()
                    && candidate.instance() == issue.instance()
            })
            .unwrap();
        assert!(Arc::ptr_eq(issue, again));
        assert_eq!(issue.instance(), 0);
    }
    let expected = openraft::StorageError::<u64>::from_io_error(
        openraft::ErrorSubject::Store,
        openraft::ErrorVerb::Write,
        std::io::Error::other("durable domain transaction failed; outcome may be unknown"),
    );
    let background = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "background work result")
        .unwrap();
    assert_eq!(background.error().to_string(), expected.to_string());
    let runtime = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "OpenRaft runtime")
        .unwrap()
        .error()
        .downcast_ref::<openraft::error::ShutdownError<u64, tokio::task::JoinError>>()
        .expect("original typed OpenRaft failure missing");
    let Some(openraft::error::Fatal::StorageError(storage)) = runtime.core() else {
        panic!(
            "forced durable write did not retain its original core storage failure: {runtime:?}"
        );
    };
    assert_eq!(storage.to_string(), expected.to_string());
    assert!(runtime.core_join_error().is_none());
    assert!(runtime.ticker().is_none());
    assert!(runtime.state_machine().is_none());
    assert!(runtime.snapshot_builder().is_none());
    assert!(runtime.replications().is_empty());
    assert!(runtime.auxiliary().is_empty());
    assert!(runtime.incoming_snapshot().is_none());
    assert!(db.raft_group().check_access().is_err());
    assert!(db.engine().generation().is_err());
    eprintln!("forced audit persistence failure retained after complete drain: {failure:?}");
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn key_revocation_fences_and_evicts_resident_state() {
    let (_dir, _physical, db, key, store, audit) = database(false).await;
    db.mutate(
        context("owner"),
        batch("start", vec![put("a", "a", Precondition::Any)]),
    )
    .await
    .unwrap();
    key.revoke();
    assert!(store.refresh_lease().await.is_err());
    assert_eq!(
        db.get(&context("owner"), "people", "a")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );
    assert!(db.engine().generation().is_err());
    key.allow();
    assert!(
        db.get(&context("owner"), "people", "a").await.is_err(),
        "reauthorization must not silently resurrect memory"
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn key_revocation_evicts_retained_coherent_leases_and_rejects_every_page() {
    let (_dir, _physical, db, key, store, audit) = database(false).await;
    let generation = db.engine().generation().unwrap();
    let weak = Arc::downgrade(&generation);
    drop(generation);
    let lease = db
        .open_snapshot_lease(&context("owner"), OpenSnapshotLease { ttl_ms: 60_000 })
        .await
        .unwrap();
    assert!(weak.upgrade().is_some());
    key.revoke();
    assert!(store.refresh_lease().await.is_err());
    assert_eq!(
        db.read_snapshot_page(
            &context("owner"),
            ReadSnapshotPage {
                lease_id: lease.lease_id.clone(),
                documents: vec![DocumentKey {
                    collection: "people".into(),
                    id: "a".into()
                }],
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::Sealed
    );
    assert!(
        weak.upgrade().is_none(),
        "key sealing must release every owned lease generation"
    );
    assert_eq!(
        db.scan_snapshot_page(
            &context("owner"),
            ScanSnapshotPage {
                lease_id: lease.lease_id,
                collection: "people".into(),
                after_id: None,
                limit: 1
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::Sealed
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn logical_backup_restores_suspended_with_new_incarnation_and_increasing_revisions() {
    let (_source_dir, _physical, source, source_key, _source_store, source_audit) =
        database(false).await;
    let receipt = source
        .mutate(
            context("owner"),
            batch("original", vec![put("a", "original", Precondition::Any)]),
        )
        .await
        .unwrap();
    let old_incarnation = source
        .engine()
        .generation()
        .unwrap()
        .state
        .incarnation
        .clone();
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new_fixture(
            _source_dir.path().join("backups"),
            16 << 20,
            source_audit.admission().memory().clone(),
        )
        .unwrap(),
    );
    source
        .install_archive_destination("backup".into(), destination.clone())
        .unwrap();
    let checkpoint = source
        .backup_checkpoint(context("owner"), destination.as_ref(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    let target_incarnation = uuid::Uuid::new_v4();
    source
        .retire_source(
            context("owner"),
            RetireSourceRequest {
                retirement_id: "restore".into(),
                expected_source_incarnation: old_incarnation.clone(),
                target_incarnation: target_incarnation.to_string(),
                checkpoint: checkpoint.checkpoint().clone(),
                destination: "backup".into(),
                not_after_ms: u64::MAX,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        source
            .administer(context("owner"), Operation::Suspend(false))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );

    let target_dir = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        common::PhysicalFixture::new(&target_dir.path().join("node.redb"), Default::default());
    let node = physical
        .storage
        .create_new(
            target_dir.path().join("node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let target_audit =
        common::security_audit(node.clone(), physical.storage.admission.clone()).await;
    let target_key = Arc::new(LocalKeyProvider::new([9; 32]));
    let target_store = TenantStore::initialize_catalog_fixture(node, "tenant-a".into(), target_key)
        .await
        .unwrap();
    let restored = kasumi_engine::restore_local(
        &kasumi_engine::RestoreSource {
            timeout_ms: 300_000,
            destination_alias: "backup".into(),
            destination: destination.clone(),
            keys: source_key.clone(),
        },
        kasumi_store::test_utils::initialize_custody_fixture(
            target_store.clone(),
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        common::local_restore_request(
            context("owner"),
            checkpoint.checkpoint(),
            target_incarnation,
        ),
        target_audit.admission().clone(),
        target_audit.clone(),
    )
    .await
    .unwrap();
    assert_ne!(
        restored.engine().generation().unwrap().state.incarnation,
        old_incarnation
    );
    assert!(restored.engine().generation().unwrap().state.suspended);
    assert_eq!(
        restored
            .engine()
            .generation()
            .unwrap()
            .state
            .restored_from
            .as_ref(),
        Some(checkpoint.checkpoint())
    );
    assert_eq!(
        restored
            .get(&context("owner"), "people", "a")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );
    assert!(
        kasumi_engine::restore_local(
            &kasumi_engine::RestoreSource {
                timeout_ms: 300_000,
                destination_alias: "backup".into(),
                destination: destination.clone(),
                keys: source_key
            },
            kasumi_store::test_utils::open_existing_custody_fixture(
                target_store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32]))
            )
            .await
            .unwrap(),
            common::local_restore_request(
                context("owner"),
                checkpoint.checkpoint(),
                uuid::Uuid::new_v4()
            ),
            target_audit.admission().clone(),
            target_audit.clone(),
        )
        .await
        .is_err(),
        "must not overwrite a serving/restored target"
    );
    restored.complete_restore(context("owner")).await.unwrap();
    restored
        .administer(context("owner"), Operation::Suspend(false))
        .await
        .unwrap();
    assert_eq!(
        restored
            .get(&context("owner"), "people", "a")
            .await
            .unwrap()
            .body["email"],
        "original"
    );
    let retained = restored
        .operation_receipt(&context("owner"), "original")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.scope.incarnation, old_incarnation);
    assert_ne!(
        retained.scope.incarnation,
        restored.engine().generation().unwrap().state.incarnation
    );
    assert_eq!(retained.scope.principal, "owner");
    assert_eq!(retained.outcome.unwrap(), receipt);
    let newer = restored
        .mutate(
            context("owner"),
            batch(
                "after-restore",
                vec![put("a", "updated", Precondition::Version(receipt.revision))],
            ),
        )
        .await
        .unwrap();
    assert!(newer.revision > receipt.revision);
    restored.shutdown().await.unwrap();
    source.shutdown().await.unwrap();
    source_audit.shutdown().await.unwrap();
    target_audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn durable_engine_worker() {
    let Ok(root) = std::env::var("KASUMI_ENGINE_TEST_CRASH_PATH") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let physical =
        common::PhysicalFixture::new(&root.join("persistent/node.redb"), Default::default());
    let node = physical
        .storage
        .create_new(
            root.join("persistent/node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let audit = common::security_audit(node.clone(), physical.storage.admission.clone()).await;
    let store = TenantStore::initialize_catalog_fixture(
        node,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([42; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::test_utils::open_fixture(
        kasumi_store::test_utils::initialize_custody_fixture(
            store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        policy(false),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    db.administer(context("owner"), Operation::CreateCollection(definition()))
        .await
        .unwrap();
    let result = db
        .mutate(
            context("owner"),
            batch(
                "kill-retry",
                vec![put("a", "survives", Precondition::Absent)],
            ),
        )
        .await
        .unwrap();
    std::fs::write(
        root.join("ack.pending"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    std::fs::rename(root.join("ack.pending"), root.join("ack.json")).unwrap();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

#[tokio::test]
async fn killed_process_recovers_acknowledged_documents_receipts_and_bootstrap_policy() {
    use std::{
        os::unix::fs::DirBuilderExt,
        process::{Command, Stdio},
    };
    let dir = kasumi_store::test_utils::private_tempdir().unwrap();
    // The crash harness acknowledgement is outside the installed storage root.
    // Every actual installation directory is private from its creation.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir.path().join("persistent"))
        .unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "durable_engine_worker", "--nocapture"])
        .env("KASUMI_ENGINE_TEST_CRASH_PATH", dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    while !dir.path().join("ack.json").exists() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("worker exited before acknowledging: {status}");
        }
        if tokio::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("worker acknowledgment timed out");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    child.kill().unwrap();
    child.wait().unwrap();
    let expected: WriteReceipt =
        serde_json::from_slice(&std::fs::read(dir.path().join("ack.json")).unwrap()).unwrap();
    let physical =
        common::PhysicalFixture::new(&dir.path().join("persistent/node.redb"), Default::default());
    let node = physical
        .storage
        .open_existing(
            dir.path().join("persistent/node.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let audit =
        common::existing_security_audit(node.clone(), physical.storage.admission.clone()).await;
    let store = TenantStore::open_existing_fixture(
        node,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([42; 32])),
    )
    .await
    .unwrap();
    let attacker_defaults = Policy {
        grants: vec![Grant {
            principal: "attacker".into(),
            collection: None,
            actions: context("attacker").scopes,
        }],
        strict_read_audit: true,
    };
    let db = kasumi_engine::test_utils::open_fixture(
        kasumi_store::test_utils::open_existing_custody_fixture(
            store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
        )
        .await
        .unwrap(),
        attacker_defaults,
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        db.get(&context("owner"), "people", "a").await.unwrap().body["email"],
        "survives"
    );
    assert_eq!(
        db.get(&context("attacker"), "people", "a")
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        db.mutate(
            context("owner"),
            batch(
                "kill-retry",
                vec![put("a", "survives", Precondition::Absent)]
            )
        )
        .await
        .unwrap(),
        expected
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
}
