mod common;

use kasumi_engine::{Database, TenantEngine};
use kasumi_raft::RaftGroup;
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

fn context(principal: &str) -> RequestContext {
    RequestContext {
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
fn engine(strict: bool, limits: Limits) -> TenantEngine {
    TenantEngine::new(
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
    db.apply_command(1, command(Operation::CreateCollection(definition())))
        .unwrap()
        .unwrap();
    db.apply_command(
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
        .apply_command(4, command(Operation::Mutate(conditional.clone())))
        .unwrap()
        .unwrap();
    assert_eq!(
        db.generation().unwrap().state.collections["people"].data_epoch,
        4
    );
    let replay = db
        .apply_command(5, command(Operation::Mutate(conditional)))
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
            db.apply_command(6 + index as u64, command(Operation::Mutate(rejected)))
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
    let snapshot = db.snapshot().unwrap();
    db.restore(&snapshot).unwrap();
    assert_eq!(db.snapshot().unwrap(), snapshot);
}

#[test]
fn read_assertions_block_write_skew_and_require_read_authority() {
    let db = engine(false, Limits::default());
    db.apply_command(1, command(Operation::CreateCollection(definition())))
        .unwrap()
        .unwrap();
    db.apply_command(
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
    db.apply_command(3, command(Operation::Mutate(first)))
        .unwrap()
        .unwrap();
    let mut second = batch("second", vec![put("b", "b-new", Precondition::Version(2))]);
    second.read_set = vec![ReadAssertion::Document {
        collection: "people".into(),
        id: "a".into(),
        expected: ReadPrecondition::Version(2),
    }];
    assert_eq!(
        db.apply_command(4, command(Operation::Mutate(second.clone())))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    second.idempotency_key = "write-only".into();
    let mut input = command(Operation::Mutate(second));
    input.context.scopes.remove(&Action::Read);
    assert_eq!(
        db.apply_command(5, input).unwrap().unwrap_err().code,
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
    db.apply_command(1, command(Operation::CreateCollection(immutable.clone())))
        .unwrap()
        .unwrap();
    db.apply_command(
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
        db.apply_command(6, command(Operation::ReplaceCollection(definition())))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(db.generation().unwrap().state.schema_epoch, 1);
    db.apply_command(7, command(Operation::ReplaceCollection(immutable)))
        .unwrap()
        .unwrap();
    assert_eq!(db.generation().unwrap().state.schema_epoch, 2);
    assert_eq!(
        db.generation().unwrap().state.collections["people"].data_epoch,
        2
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
        max_audit_records: 1,
        ..Limits::default()
    };
    let db = engine(false, limits);
    db.apply_command(1, command(Operation::CreateCollection(definition())))
        .unwrap()
        .unwrap();
    let write = command(Operation::Mutate(batch(
        "audit-cap",
        vec![put("a", "a", Precondition::Absent)],
    )));
    assert_eq!(
        db.apply_command(2, write.clone())
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::AuditUnavailable
    );
    assert_eq!(db.generation().unwrap().state.document_count, 0);
    assert!(db.generation().unwrap().state.receipts.is_empty());
    let limits = Limits {
        max_audit_records: 4,
        ..Limits::default()
    };
    db.apply_command(3, command(Operation::SetLimits(limits)))
        .unwrap()
        .unwrap();
    db.apply_command(4, write).unwrap().unwrap();
    assert_eq!(db.generation().unwrap().state.document_count, 1);
    assert_eq!(db.generation().unwrap().state.audits.len(), 3);
    let snapshot = db.snapshot().unwrap();
    db.restore(&snapshot).unwrap();
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
fn receipt_expiry_index_obeys_exact_boundary_and_rebuilds_from_snapshot() {
    let db = engine(
        false,
        Limits {
            max_receipts: 2,
            ..Limits::default()
        },
    );
    db.apply_command(1, command(Operation::CreateCollection(definition())))
        .unwrap()
        .unwrap();
    let make = |key: &str, id: &str, timestamp_ms: u64| Command {
        timestamp_ms,
        ..command(Operation::Mutate(batch(
            key,
            vec![put(id, id, Precondition::Any)],
        )))
    };
    db.apply_command(2, make("first", "a", 1000))
        .unwrap()
        .unwrap();
    db.apply_command(3, make("second", "b", 2000))
        .unwrap()
        .unwrap();
    assert_eq!(
        db.apply_command(4, make("third", "c", 86_400_999))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    db.apply_command(5, make("third", "c", 86_401_000))
        .unwrap()
        .unwrap();
    assert_eq!(db.generation().unwrap().state.receipts.len(), 2);
    db.restore(&db.snapshot().unwrap()).unwrap();
    db.apply_command(6, make("first", "d", 86_402_000))
        .unwrap()
        .unwrap();
    assert_eq!(db.generation().unwrap().state.receipts.len(), 2);
    assert_eq!(
        db.generation().unwrap().state.collections["people"].documents["d"].version,
        6
    );
}

#[test]
fn retirement_is_terminal_and_survives_snapshot_recovery() {
    let db = engine(false, Limits::default());
    db.apply_command(1, command(Operation::CreateCollection(definition())))
        .unwrap()
        .unwrap();
    db.apply_command(2, command(Operation::Retire))
        .unwrap()
        .unwrap();
    let restored = engine(false, Limits::default());
    restored.restore(&db.snapshot().unwrap()).unwrap();
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
            .apply_command(3, command(Operation::Suspend(false)))
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Sealed
    );
    assert_eq!(
        restored
            .apply_command(
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
    db.apply_command(1, command(Operation::CreateCollection(definition())))
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
    db.apply_command(1, command(Operation::CreateCollection(definition())))
        .unwrap()
        .unwrap();
    let input = batch("insert-once", vec![put("a", "a", Precondition::Absent)]);
    let expected = db
        .apply_command(2, command(Operation::Mutate(input.clone())))
        .unwrap()
        .unwrap();
    let mut updated = definition();
    updated.schema["properties"]["age"]["maximum"] = json!(40);
    db.apply_command(3, command(Operation::ReplaceCollection(updated)))
        .unwrap()
        .unwrap();
    let restored = engine(false, Limits::default());
    restored.restore(&db.snapshot().unwrap()).unwrap();
    assert_eq!(
        restored
            .apply_command(4, command(Operation::Mutate(input)))
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
    db.apply_command(1, command(Operation::CreateCollection(definition())))
        .unwrap()
        .unwrap();
    db.apply_command(
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
    db.apply_command(1, command(Operation::CreateCollection(definition())))
        .unwrap()
        .unwrap();
    db.apply_command(
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
            3,
            command(Operation::Mutate(batch(
                "writer1",
                vec![put("a", "b", Precondition::Version(2))],
            ))),
        )
        .unwrap();
    let second = db
        .apply_command(
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
    let before = db.snapshot().unwrap();
    let mut corrupt: serde_json::Value = serde_json::from_slice(&before).unwrap();
    corrupt["logical_bytes"] = json!(999);
    assert_eq!(
        db.restore(&serde_json::to_vec(&corrupt).unwrap())
            .unwrap_err()
            .code,
        ErrorCode::Corruption
    );
    assert_eq!(db.snapshot().unwrap(), before);
    corrupt["tenant"] = json!("other");
    assert!(db.restore(&serde_json::to_vec(&corrupt).unwrap()).is_err());
}

#[test]
fn authorization_is_rechecked_before_idempotency_response() {
    let db = engine(false, Limits::default());
    db.apply_command(1, command(Operation::CreateCollection(definition())))
        .unwrap()
        .unwrap();
    let input = batch("initial", vec![put("a", "a", Precondition::Any)]);
    db.apply_command(2, command(Operation::Mutate(input.clone())))
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
    db.apply_command(3, command(Operation::SetPolicy(new_policy)))
        .unwrap()
        .unwrap();
    assert_eq!(
        db.apply_command(4, command(Operation::Mutate(input)))
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
    Arc<Database>,
    Arc<LocalKeyProvider>,
    Arc<TenantStore>,
    Arc<kasumi_engine::SecurityAudit>,
) {
    let dir = tempfile::tempdir().unwrap();
    let node = NodeStore::open(dir.path().join("node.redb")).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let key = Arc::new(LocalKeyProvider::new([7; 32]));
    let store = TenantStore::open(node, "tenant-a".into(), key.clone())
        .await
        .unwrap();
    let engine = Arc::new(engine(strict, Limits::default()));
    let group = RaftGroup::local(
        1,
        "tenant-a/incarnation-a".into(),
        store.clone(),
        engine.clone(),
    )
    .await
    .unwrap();
    let db = Database::new(engine, group, store.clone(), audit.clone());
    db.administer(context("owner"), Operation::CreateCollection(definition()))
        .await
        .unwrap();
    (dir, db, key, store, audit)
}

#[tokio::test]
async fn actual_raft_writes_queries_and_snapshot_pagination() {
    let (_dir, db, _key, _store, audit) = database(false).await;
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
    audit.shutdown().await;
}

#[tokio::test]
async fn coherent_snapshot_reads_span_collections_under_concurrent_commits_and_strict_audit() {
    let (_dir, db, _key, _store, audit) = database(true).await;
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
    audit.shutdown().await;
}

#[tokio::test]
async fn snapshot_reads_reject_partial_queries_cursors_and_foreign_authority() {
    let (_dir, db, _key, _store, audit) = database(false).await;
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
    audit.shutdown().await;
}

#[tokio::test]
async fn strict_read_audit_is_committed_before_return_and_tied_to_data_revision() {
    let (_dir, db, _key, _store, audit) = database(true).await;
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
    audit.shutdown().await;
}

#[tokio::test]
async fn shared_get_uses_the_same_audit_and_authorization_and_keeps_historical_values() {
    let (_dir, db, _key, store, audit) = database(true).await;
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
    audit.shutdown().await;
}

#[tokio::test]
async fn strict_empty_discovery_is_audited_and_failed_audit_persistence_blocks_results() {
    let backend = kasumi_store::test_utils::FaultBackend::new();
    let node = NodeStore::open_with_backend(backend.clone()).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open(
        node,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([45; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::open_local(store, policy(true), Limits::default(), audit.clone())
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
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}

#[tokio::test]
async fn key_revocation_fences_and_evicts_resident_state() {
    let (_dir, db, key, store, audit) = database(false).await;
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
    audit.shutdown().await;
}

#[tokio::test]
async fn key_revocation_evicts_retained_coherent_leases_and_rejects_every_page() {
    let (_dir, db, key, store, audit) = database(false).await;
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
    audit.shutdown().await;
}

#[tokio::test]
async fn logical_backup_restores_suspended_with_new_incarnation_and_increasing_revisions() {
    let (_source_dir, source, source_key, _source_store, source_audit) = database(false).await;
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
    let backup_dir = tempfile::tempdir().unwrap();
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(backup_dir.path(), 16 << 20).unwrap(),
    );
    let id = source
        .backup(context("owner"), destination.as_ref())
        .await
        .unwrap();
    source
        .administer(context("owner"), Operation::Retire)
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

    let target_dir = tempfile::tempdir().unwrap();
    let node = NodeStore::open(target_dir.path().join("node.redb")).unwrap();
    let target_audit = common::security_audit(node.clone()).await;
    let target_key = Arc::new(LocalKeyProvider::new([9; 32]));
    let target_store = TenantStore::open(node, "tenant-a".into(), target_key)
        .await
        .unwrap();
    let restored = kasumi_engine::restore_local(
        &kasumi_engine::RestoreSource {
            timeout_ms: 300_000,
            destination_alias: "backup".into(),
            destination: destination.clone(),
            keys: source_key.clone(),
        },
        id,
        target_store.clone(),
        context("owner"),
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
            id,
            target_store,
            context("owner"),
            target_audit.clone()
        )
        .await
        .is_err(),
        "must not overwrite a serving/restored target"
    );
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
    assert_eq!(
        restored
            .operation_receipt(&context("owner"), "original")
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        receipt
    );
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
    source_audit.shutdown().await;
    target_audit.shutdown().await;
}

#[tokio::test]
async fn durable_engine_worker() {
    let Ok(root) = std::env::var("KASUMI_ENGINE_TEST_CRASH_PATH") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let node = NodeStore::open(root.join("node.redb")).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open(
        node,
        "tenant-a".into(),
        Arc::new(LocalKeyProvider::new([42; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::open_local(store, policy(false), Limits::default(), audit.clone())
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
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
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
    let node = NodeStore::open(dir.path().join("node.redb")).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open(
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
    let db = kasumi_engine::open_local(store, attacker_defaults, Limits::default(), audit.clone())
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
    audit.shutdown().await;
}
