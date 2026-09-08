use kasumi_engine::test_utils::SnapshotFixture;
mod common;
use kasumi_engine::{Database, SecurityAudit, TenantEngine};
use kasumi_store::{NodeStore, TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::*;
use serde_json::json;
use std::{collections::BTreeSet, sync::Arc};

fn context(principal: &str) -> RequestContext {
    RequestContext {
        authorization: kasumi_types::RequestAuthorization::service_identity(),
        tenant: "schema".into(),
        principal: principal.into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "schema-test".into(),
    }
}
fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: context("owner").scopes,
        }],
        strict_read_audit: false,
    }
}
fn definition(name: &str) -> CollectionDefinition {
    CollectionDefinition {
        name: name.into(),
        write_mode: CollectionWriteMode::Mutable,
        retention_class: CollectionRetentionClass::Operational,
        schema: json!({"type":"object"}),
        indexes: vec![],
        strict_read_audit: false,
    }
}
fn engine(limits: Limits) -> TenantEngine {
    TenantEngine::new("schema".into(), "incarnation".into(), policy(), limits).unwrap()
}
fn request(db: &TenantEngine, id: &str, changes: Vec<SchemaChange>) -> SchemaChangeSet {
    let g = db.generation().unwrap();
    SchemaChangeSet {
        activation_id: id.into(),
        expected_incarnation: g.state.incarnation.clone(),
        expected_schema_epoch: g.state.schema_epoch,
        read_set: vec![],
        changes,
    }
}
fn creates(db: &TenantEngine, id: &str, names: &[&str]) -> SchemaChangeSet {
    request(
        db,
        id,
        names
            .iter()
            .map(|name| SchemaChange::Create {
                definition: definition(name),
            })
            .collect(),
    )
}
fn apply_as(db: &TenantEngine, principal: &str, operation: Operation) -> Result<WriteReceipt> {
    let revision = db.generation().unwrap().state.revision + 1;
    let result = db
        .apply_command(
            revision,
            Command {
                context: context(principal),
                timestamp_ms: revision * 86_400_001,
                operation,
            },
        )
        .unwrap();
    assert_eq!(
        db.fixture_snapshot().unwrap().len(),
        db.snapshot_bytes().unwrap() as u64
    );
    result
}
fn apply(db: &TenantEngine, operation: Operation) -> Result<WriteReceipt> {
    apply_as(db, "owner", operation)
}
fn put(collection: &str, id: &str, n: u64) -> Mutation {
    Mutation::Put {
        collection: collection.into(),
        id: id.into(),
        body: json!({"n":n,"text":"one ledger"}),
        expected: Precondition::Any,
    }
}
fn mutate(db: &TenantEngine, key: &str, operations: Vec<Mutation>) {
    apply(
        db,
        Operation::Mutate(MutationBatch {
            idempotency_key: key.into(),
            read_set: vec![],
            operations,
        }),
    )
    .unwrap();
}
fn unique(mut definition: CollectionDefinition) -> CollectionDefinition {
    definition.indexes.push(IndexDefinition {
        name: "number".into(),
        fields: vec![IndexField {
            path: "/n".into(),
            kind: ScalarType::Number,
        }],
        unique: true,
        text: None,
    });
    definition
}

#[test]
fn atomic_bundle_publishes_all_indexes_once_and_preserves_read_generations() {
    let db = engine(Limits::default());
    let install = creates(&db, "install", &["journal", "balances"]);
    let first = apply(&db, Operation::ActivateSchema(install.clone())).unwrap();
    assert_eq!(db.generation().unwrap().state.schema_epoch, 1);
    assert_eq!(db.generation().unwrap().state.policy_epoch, 1);
    mutate(
        &db,
        "seed",
        vec![put("journal", "a", 1), put("balances", "b", 2)],
    );
    let old = db.generation().unwrap();
    let changes = ["journal", "balances"].map(|name| SchemaChange::Replace {
        definition: unique(old.state.collections[name].definition.clone()),
        expected_data_epoch: old.state.collections[name].data_epoch,
    });
    let upgrade = request(&db, "upgrade", changes.into());
    let receipt = apply(&db, Operation::ActivateSchema(upgrade.clone())).unwrap();
    let new = db.generation().unwrap();
    assert_eq!(new.state.schema_epoch, 2);
    assert_eq!(new.state.policy_epoch, 2);
    assert_eq!(
        new.state.change_feed.next_sequence,
        old.state.change_feed.next_sequence
    );
    for name in ["journal", "balances"] {
        assert!(old.state.collections[name].definition.indexes.is_empty());
        assert_eq!(new.state.collections[name].definition.indexes.len(), 1);
        assert_eq!(
            old.state.collections[name].data_epoch,
            new.state.collections[name].data_epoch
        );
        assert_eq!(
            old.state.collections[name].documents,
            new.state.collections[name].documents
        );
    }
    let query: QueryRequest = serde_json::from_value(
        json!({"collection":"journal","filter":{"op":"eq","field":"/n","value":1},"limit":10}),
    )
    .unwrap();
    assert_eq!(
        new.indexes
            .execute(&new.state.collections, &query, &new.state.limits)
            .unwrap()
            .rows
            .len(),
        1
    );
    assert_eq!(
        old.indexes
            .execute(&old.state.collections, &query, &old.state.limits)
            .unwrap_err()
            .code,
        ErrorCode::IndexRequired
    );
    assert_eq!(
        apply(&db, Operation::ActivateSchema(install)).unwrap(),
        first
    );
    assert_eq!(
        apply(&db, Operation::ActivateSchema(upgrade)).unwrap(),
        receipt
    );
    assert_eq!(db.generation().unwrap().state.schema_epoch, 2);
    assert_eq!(db.generation().unwrap().state.schema_activations.len(), 2);
}

#[test]
fn rejection_is_permanent_and_never_publishes_an_earlier_valid_change() {
    let db = engine(Limits::default());
    apply(
        &db,
        Operation::ActivateSchema(creates(&db, "install", &["a", "b"])),
    )
    .unwrap();
    mutate(
        &db,
        "seed",
        vec![put("a", "a", 1), put("b", "a", 1), put("b", "b", 1)],
    );
    let before = db.generation().unwrap();
    let bad = request(
        &db,
        "upgrade",
        ["a", "b"]
            .map(|name| SchemaChange::Replace {
                definition: unique(before.state.collections[name].definition.clone()),
                expected_data_epoch: before.state.collections[name].data_epoch,
            })
            .into(),
    );
    let error = apply(&db, Operation::ActivateSchema(bad.clone())).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    let unchanged = db.generation().unwrap();
    assert_eq!(unchanged.state.schema_epoch, before.state.schema_epoch);
    for name in ["a", "b"] {
        assert!(
            unchanged.state.collections[name]
                .definition
                .indexes
                .is_empty()
        );
    }
    mutate(&db, "repair", vec![put("b", "b", 2)]);
    assert_eq!(
        apply(&db, Operation::ActivateSchema(bad.clone())).unwrap_err(),
        error
    );
    let mut retry = bad.clone();
    retry.changes[1] = SchemaChange::Replace {
        definition: unique(definition("b")),
        expected_data_epoch: db.generation().unwrap().state.collections["b"].data_epoch,
    };
    assert_eq!(
        apply(&db, Operation::ActivateSchema(retry.clone()))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    retry.activation_id = "upgrade-fixed".into();
    apply(&db, Operation::ActivateSchema(retry)).unwrap();
    assert_eq!(db.generation().unwrap().state.schema_epoch, 2);
}

#[test]
fn incarnation_schema_data_and_current_authority_are_independent_fences() {
    let db = engine(Limits::default());
    let install = creates(&db, "install", &["a", "b"]);
    apply(&db, Operation::ActivateSchema(install.clone())).unwrap();
    for (id, incarnation, epoch) in [("inc", "wrong", 1), ("epoch", "incarnation", 0)] {
        let mut request = creates(&db, id, &["never"]);
        request.expected_incarnation = incarnation.into();
        request.expected_schema_epoch = epoch;
        assert_eq!(
            apply(&db, Operation::ActivateSchema(request))
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
    }
    let stale = request(
        &db,
        "data",
        vec![SchemaChange::Replace {
            definition: unique(definition("a")),
            expected_data_epoch: 0,
        }],
    );
    mutate(&db, "write", vec![put("a", "a", 1)]);
    assert_eq!(
        apply(&db, Operation::ActivateSchema(stale))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let mut scopes = context("owner");
    scopes.scopes.remove(&Action::Admin);
    let revision = db.generation().unwrap().state.revision + 1;
    assert_eq!(
        db.apply_command(
            revision,
            Command {
                context: scopes,
                timestamp_ms: 10,
                operation: Operation::ActivateSchema(install.clone())
            }
        )
        .unwrap()
        .unwrap_err()
        .code,
        ErrorCode::Forbidden
    );
    let mut next_policy = policy();
    next_policy.grants[0].principal = "replacement".into();
    apply(&db, Operation::SetPolicy(next_policy)).unwrap();
    assert_eq!(
        apply(&db, Operation::ActivateSchema(install))
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert!(
        !db.generation()
            .unwrap()
            .state
            .collections
            .contains_key("never")
    );
    assert_eq!(db.generation().unwrap().state.schema_epoch, 1);
}

#[test]
fn record_metadata_and_serialized_budgets_fail_before_partial_activation() {
    let limits = Limits {
        max_schema_activations: 1,
        ..Default::default()
    };
    let db = engine(limits);
    let install = creates(&db, "install", &["a", "b"]);
    let receipt = apply(&db, Operation::ActivateSchema(install.clone())).unwrap();
    assert_eq!(
        apply(&db, Operation::ActivateSchema(creates(&db, "full", &["c"])))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert!(!db.generation().unwrap().state.collections.contains_key("c"));
    assert_eq!(
        apply(&db, Operation::ActivateSchema(install)).unwrap(),
        receipt
    );

    let db = engine(Limits {
        max_schema_bytes: 64,
        ..Default::default()
    });
    let install = creates(&db, "oversize", &["a", "b"]);
    assert_eq!(
        apply(&db, Operation::ActivateSchema(install.clone()))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert!(db.generation().unwrap().state.collections.is_empty());
    assert_eq!(db.generation().unwrap().state.schema_activations.len(), 1);
    apply(&db, Operation::SetLimits(Limits::default())).unwrap();
    assert_eq!(
        apply(&db, Operation::ActivateSchema(install))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );

    let db = engine(Limits {
        max_snapshot_bytes: 8192,
        ..Default::default()
    });
    let mut def = definition("a");
    def.schema["description"] = json!("x".repeat(8000));
    let install = request(
        &db,
        "snapshot-full",
        vec![SchemaChange::Create { definition: def }],
    );
    assert_eq!(
        apply(&db, Operation::ActivateSchema(install.clone()))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert!(db.generation().unwrap().state.collections.is_empty());
    assert_eq!(db.generation().unwrap().state.schema_activations.len(), 1);
    apply(&db, Operation::SetLimits(Limits::default())).unwrap();
    assert_eq!(
        apply(&db, Operation::ActivateSchema(install))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert!(db.generation().unwrap().state.collections.is_empty());
}

#[test]
fn schema_shape_immutable_mode_snapshot_validation_and_retained_quota() {
    let db = engine(Limits::default());
    let mut duplicate = creates(&db, "duplicate", &["a", "a"]);
    assert_eq!(
        apply(&db, Operation::ActivateSchema(duplicate.clone()))
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );
    assert!(db.generation().unwrap().state.schema_activations.is_empty());
    duplicate.changes.pop();
    apply(&db, Operation::ActivateSchema(duplicate)).unwrap();
    let mut immutable = definition("history");
    immutable.write_mode = CollectionWriteMode::AppendOnly;
    apply(
        &db,
        Operation::ActivateSchema(request(
            &db,
            "immutable",
            vec![SchemaChange::Create {
                definition: immutable,
            }],
        )),
    )
    .unwrap();
    let mut weakening = request(
        &db,
        "weaken",
        vec![SchemaChange::Replace {
            definition: definition("history"),
            expected_data_epoch: 0,
        }],
    );
    assert_eq!(
        apply(&db, Operation::ActivateSchema(weakening.clone()))
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    let SchemaChange::Replace { definition, .. } = &mut weakening.changes[0] else {
        unreachable!()
    };
    definition.write_mode = CollectionWriteMode::AppendOnly;
    definition.retention_class = CollectionRetentionClass::ArchivableHistory;
    weakening.activation_id = "retention".into();
    assert_eq!(
        apply(&db, Operation::ActivateSchema(weakening))
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        apply(
            &db,
            Operation::SetLimits(Limits {
                max_schema_activations: 1,
                ..Default::default()
            })
        )
        .unwrap_err()
        .code,
        ErrorCode::QuotaExceeded
    );
    let bytes = db.fixture_snapshot().unwrap();
    let recovered = engine(Limits::default());
    recovered.fixture_restore(&bytes).unwrap();
    assert_eq!(bytes, recovered.fixture_snapshot().unwrap());
    let mut state: TenantState =
        kasumi_engine::test_utils::decode_snapshot_candidate(&bytes).unwrap();
    state.schema_activation_bytes += 1;
    assert_eq!(
        recovered
            .fixture_restore(
                &kasumi_engine::test_utils::encode_snapshot_candidate(&state, 64 << 20).unwrap()
            )
            .unwrap_err()
            .code,
        ErrorCode::Corruption
    );
    assert_eq!(bytes, recovered.fixture_snapshot().unwrap());
}

#[test]
fn text_and_structured_indexes_publish_together_after_existing_documents_validate() {
    let db = engine(Limits::default());
    apply(
        &db,
        Operation::ActivateSchema(creates(&db, "install", &["journal", "balances"])),
    )
    .unwrap();
    mutate(
        &db,
        "seed",
        vec![put("journal", "a", 1), put("balances", "b", 2)],
    );
    let old = db.generation().unwrap();
    let mut text = definition("journal");
    text.indexes.push(IndexDefinition {
        name: "search".into(),
        fields: vec![IndexField {
            path: "/text".into(),
            kind: ScalarType::String,
        }],
        unique: false,
        text: Some(TextIndex {
            analyzer: Analyzer::UnicodeV1,
        }),
    });
    let upgrade = request(
        &db,
        "text-and-structured",
        vec![
            SchemaChange::Replace {
                definition: text,
                expected_data_epoch: old.state.collections["journal"].data_epoch,
            },
            SchemaChange::Replace {
                definition: unique(definition("balances")),
                expected_data_epoch: old.state.collections["balances"].data_epoch,
            },
        ],
    );
    apply(&db, Operation::ActivateSchema(upgrade)).unwrap();
    let current = db.generation().unwrap();
    let query: QueryRequest = serde_json::from_value(json!({"collection":"journal","text":{"index":"search","query":"ledger","mode":"terms"},"limit":10})).unwrap();
    assert_eq!(
        current
            .indexes
            .execute(&current.state.collections, &query, &current.state.limits)
            .unwrap()
            .rows
            .len(),
        1
    );
    let mut invalid = definition("journal");
    invalid.schema = json!({"type":"object","required":["missing"]});
    let failed = request(
        &db,
        "invalid-existing-data",
        vec![
            SchemaChange::Create {
                definition: definition("not-installed"),
            },
            SchemaChange::Replace {
                definition: invalid,
                expected_data_epoch: current.state.collections["journal"].data_epoch,
            },
        ],
    );
    assert_eq!(
        apply(&db, Operation::ActivateSchema(failed))
            .unwrap_err()
            .code,
        ErrorCode::SchemaViolation
    );
    assert!(
        !db.generation()
            .unwrap()
            .state
            .collections
            .contains_key("not-installed")
    );
    assert_eq!(
        db.generation().unwrap().state.schema_epoch,
        current.state.schema_epoch
    );
}

async fn open(path: &std::path::Path) -> (Arc<Database>, Arc<SecurityAudit>) {
    let node = NodeStore::open(path).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let store = TenantStore::open_fixture(
        node,
        "schema".into(),
        Arc::new(LocalKeyProvider::new([0xF1; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::test_utils::open_fixture(
        kasumi_store::test_utils::with_custody(
            store,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([242; 32])),
        )
        .await
        .unwrap(),
        policy(),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    (db, audit)
}

#[tokio::test]
async fn encrypted_restart_and_full_restore_preserve_permanent_activation_receipts() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("node.redb");
    let (db, audit) = open(&path).await;
    let names: Vec<_> = (0..32).map(|n| format!("financial_{n}")).collect();
    let refs: Vec<_> = names.iter().map(String::as_str).collect();
    let schema_read = ReadSchema {
        collections: names.iter().cloned().collect(),
    };
    let empty = db
        .read_schema(&context("owner"), schema_read.clone())
        .await
        .unwrap();
    assert_eq!(empty.schema_epoch, 0);
    assert!(empty.collections.values().all(Option::is_none));
    let install = creates(db.engine(), "financial-install", &refs);
    let reference = install.reference().unwrap();
    let receipt = db
        .activate_schema(context("owner"), install.clone())
        .await
        .unwrap();
    let installed = db
        .read_schema(&context("owner"), schema_read)
        .await
        .unwrap();
    assert_eq!(installed.schema_epoch, 1);
    assert!(installed.collections.values().all(|value| {
        value
            .as_ref()
            .is_some_and(|schema| schema.data_epoch == 0 && schema.archived_document_count == 0)
    }));
    assert_eq!(db.engine().generation().unwrap().state.schema_epoch, 1);
    assert_eq!(db.collections(&context("owner")).await.unwrap().len(), 32);
    assert_eq!(
        db.schema_activation_status(
            &context("owner"),
            &ReadSchemaActivation {
                reference: reference.clone(),
                read_set: vec![]
            }
        )
        .await
        .unwrap()
        .outcome
        .unwrap(),
        receipt
    );
    db.administer(context("owner"), Operation::Suspend(true))
        .await
        .unwrap();
    assert_eq!(
        db.activate_schema(context("owner"), install.clone())
            .await
            .unwrap(),
        receipt
    );
    let destination = Arc::new(
        kasumi_store::FilesystemBackupDestination::new(root.path().join("backups"), 16 << 20)
            .unwrap(),
    );
    let backup = db
        .backup_checkpoint(context("owner"), destination.as_ref(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    db.shutdown().await.unwrap();
    audit.shutdown().await;
    drop(db);
    drop(audit);
    let (db, audit) = open(&path).await;
    assert_eq!(
        db.activate_schema(context("owner"), install.clone())
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(
        db.schema_activation_status(
            &context("owner"),
            &ReadSchemaActivation {
                reference: reference.clone(),
                read_set: vec![]
            }
        )
        .await
        .unwrap()
        .outcome
        .unwrap(),
        receipt
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
    drop(db);
    drop(audit);

    let node = NodeStore::open(root.path().join("restored.redb")).unwrap();
    let audit = common::security_audit(node.clone()).await;
    let provider = Arc::new(LocalKeyProvider::new([0xF1; 32]));
    let target = TenantStore::open_fixture(node, "schema".into(), provider.clone())
        .await
        .unwrap();
    let source = kasumi_engine::RestoreSource {
        destination_alias: "full".into(),
        destination,
        keys: provider,
        timeout_ms: 60_000,
    };
    let restored = kasumi_engine::restore_local(
        &source,
        kasumi_store::test_utils::with_custody(
            target,
            std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([242; 32])),
        )
        .await
        .unwrap(),
        common::local_restore_request(context("owner"), backup.checkpoint(), uuid::Uuid::new_v4()),
        audit.admission().clone(),
        audit.clone(),
    )
    .await
    .unwrap();
    assert_ne!(
        restored.engine().generation().unwrap().state.incarnation,
        install.expected_incarnation
    );
    restored.complete_restore(context("owner")).await.unwrap();
    assert_eq!(
        restored
            .activate_schema(context("owner"), install)
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(
        restored
            .schema_activation_status(
                &context("owner"),
                &ReadSchemaActivation {
                    reference: reference.clone(),
                    read_set: vec![]
                }
            )
            .await
            .unwrap()
            .outcome
            .unwrap(),
        receipt
    );
    restored.shutdown().await.unwrap();
    audit.shutdown().await;
}

#[tokio::test]
async fn cold_schema_change_rejects_whole_bundle_and_scoped_status_rechecks_authority() {
    let root = tempfile::tempdir().unwrap();
    let (db, audit) = open(&root.path().join("node.redb")).await;
    let mut history = definition("history");
    history.write_mode = CollectionWriteMode::AppendOnly;
    history.retention_class = CollectionRetentionClass::ArchivableHistory;
    let install = request(
        db.engine(),
        "install",
        vec![SchemaChange::Create {
            definition: history.clone(),
        }],
    );
    db.activate_schema(context("owner"), install.clone())
        .await
        .unwrap();
    let write = db
        .mutate(
            context("owner"),
            MutationBatch {
                idempotency_key: "seed".into(),
                read_set: vec![],
                operations: vec![Mutation::Put {
                    collection: "history".into(),
                    id: "h1".into(),
                    body: json!({"n":1}),
                    expected: Precondition::Absent,
                }],
            },
        )
        .await
        .unwrap();
    db.install_archive_destination(
        "cold".into(),
        Arc::new(
            kasumi_store::FilesystemBackupDestination::new(root.path().join("cold"), 16 << 20)
                .unwrap(),
        ),
    )
    .unwrap();
    db.archive_history(
        context("owner"),
        ArchiveHistory {
            archive_id: "archive".into(),
            collection: "history".into(),
            cutoff_revision: write.revision,
            destination: "cold".into(),
        },
    )
    .await
    .unwrap();
    let upgrade = request(
        db.engine(),
        "cold-upgrade",
        vec![
            SchemaChange::Create {
                definition: definition("not-created"),
            },
            SchemaChange::Replace {
                definition: history,
                expected_data_epoch: write.revision,
            },
        ],
    );
    assert_eq!(
        db.activate_schema(context("owner"), upgrade)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(
        !db.engine()
            .generation()
            .unwrap()
            .state
            .collections
            .contains_key("not-created")
    );
    let mut next_policy = policy();
    next_policy.grants.push(Grant {
        principal: "scoped".into(),
        collection: Some("scoped".into()),
        actions: BTreeSet::from([Action::Admin]),
    });
    db.administer(context("owner"), Operation::SetPolicy(next_policy))
        .await
        .unwrap();
    let scoped = creates(db.engine(), "scoped-install", &["scoped"]);
    let reference = scoped.reference().unwrap();
    db.activate_schema(context("scoped"), scoped.clone())
        .await
        .unwrap();
    let scoped_snapshot = db
        .read_schema(
            &context("scoped"),
            ReadSchema {
                collections: BTreeSet::from(["scoped".into()]),
            },
        )
        .await
        .unwrap();
    assert!(scoped_snapshot.collections["scoped"].is_some());
    assert_eq!(
        db.read_schema(
            &context("scoped"),
            ReadSchema {
                collections: BTreeSet::from(["history".into()])
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::Forbidden
    );
    db.schema_activation_status(
        &context("scoped"),
        &ReadSchemaActivation {
            reference: reference.clone(),
            read_set: vec![],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        db.schema_activation_status(
            &context("owner"),
            &ReadSchemaActivation {
                reference: reference.clone(),
                read_set: vec![]
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
    db.administer(context("owner"), Operation::SetPolicy(policy()))
        .await
        .unwrap();
    assert_eq!(
        db.activate_schema(context("scoped"), scoped)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    assert_eq!(
        db.schema_activation_status(
            &context("scoped"),
            &ReadSchemaActivation {
                reference: reference.clone(),
                read_set: vec![]
            }
        )
        .await
        .unwrap_err()
        .code,
        ErrorCode::Forbidden
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}

fn guard_assertions(db: &TenantEngine) -> Vec<ReadAssertion> {
    let current = db.generation().unwrap();
    vec![
        ReadAssertion::Snapshot {
            incarnation: current.state.incarnation.clone(),
            policy_epoch: current.state.policy_epoch,
            schema_epoch: current.state.schema_epoch,
        },
        ReadAssertion::Before {
            not_after_ms: u64::MAX,
        },
        ReadAssertion::Document {
            collection: "guards".into(),
            id: "held".into(),
            expected: ReadPrecondition::Version(
                current.state.collections["guards"].documents["held"].version,
            ),
        },
        ReadAssertion::Collection {
            collection: "guards".into(),
            data_epoch: current.state.collections["guards"].data_epoch,
        },
    ]
}

#[test]
fn ordered_schema_dependencies_reject_changed_document_phantom_snapshot_and_expired_deadline() {
    for fault in 0..6 {
        let db = engine(Limits::default());
        apply(
            &db,
            Operation::ActivateSchema(creates(&db, "guards-install", &["guards"])),
        )
        .unwrap();
        mutate(&db, "held", vec![put("guards", "held", 1)]);
        let mut upgrade = creates(&db, "fenced-install", &["journal", "balances"]);
        upgrade.read_set = guard_assertions(&db);
        match fault {
            0 => mutate(&db, "changed", vec![put("guards", "held", 2)]),
            1 => mutate(&db, "phantom", vec![put("guards", "new", 2)]),
            2 => {
                if let ReadAssertion::Snapshot { policy_epoch, .. } = &mut upgrade.read_set[0] {
                    *policy_epoch += 1;
                }
            }
            3 => {
                if let ReadAssertion::Snapshot { incarnation, .. } = &mut upgrade.read_set[0] {
                    *incarnation = "another".into();
                }
            }
            4 => upgrade.read_set[1] = ReadAssertion::Before { not_after_ms: 1 },
            _ => {
                upgrade.read_set[2] = ReadAssertion::Document {
                    collection: "guards".into(),
                    id: "held".into(),
                    expected: ReadPrecondition::Absent,
                }
            }
        }
        let reference = upgrade.reference().unwrap();
        assert_eq!(
            apply(&db, Operation::ActivateSchema(upgrade.clone()))
                .unwrap_err()
                .code,
            ErrorCode::Conflict,
            "fault {fault}"
        );
        assert_eq!(
            apply(&db, Operation::ActivateSchema(upgrade))
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        let state = db.generation().unwrap();
        assert_eq!(state.state.schema_epoch, 1);
        assert!(!state.state.collections.contains_key("journal"));
        assert!(!state.state.collections.contains_key("balances"));
        let stored = state
            .state
            .schema_activations
            .values()
            .find(|record| record.request_digest == reference.request_digest)
            .unwrap();
        assert_eq!(stored.read_collections, BTreeSet::from(["guards".into()]));
        assert_eq!(
            stored.outcome.as_ref().unwrap_err().code,
            ErrorCode::Conflict
        );
    }
}

#[test]
fn schema_effect_digest_binds_dependencies_and_current_read_permission_is_required_on_replay() {
    let db = engine(Limits::default());
    apply(
        &db,
        Operation::ActivateSchema(creates(&db, "guards-install", &["guards"])),
    )
    .unwrap();
    mutate(&db, "held", vec![put("guards", "held", 1)]);
    let mut upgrade = creates(&db, "fenced-install", &["journal"]);
    upgrade.read_set = guard_assertions(&db);
    let receipt = apply(&db, Operation::ActivateSchema(upgrade.clone())).unwrap();
    // The old pre-transition Snapshot does not run again after its own increment.
    assert_eq!(
        apply(&db, Operation::ActivateSchema(upgrade.clone())).unwrap(),
        receipt
    );
    let mut rebound = upgrade.clone();
    rebound.read_set.clear();
    assert_ne!(
        rebound.reference().unwrap().request_digest,
        upgrade.reference().unwrap().request_digest
    );
    assert_eq!(
        apply(&db, Operation::ActivateSchema(rebound))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    let restricted = Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: BTreeSet::from([Action::Admin]),
        }],
        strict_read_audit: false,
    };
    apply(&db, Operation::SetPolicy(restricted)).unwrap();
    assert_eq!(
        apply(&db, Operation::ActivateSchema(upgrade))
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
}

#[tokio::test]
async fn encrypted_schema_lookup_checks_current_fences_without_rewriting_original_effect() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("schema-fences.redb");
    let (db, audit) = open(&path).await;
    let mut install = creates(db.engine(), "fenced-initial", &["guards", "journal"]);
    let before = db.engine().generation().unwrap();
    install.read_set = vec![
        ReadAssertion::Snapshot {
            incarnation: before.state.incarnation.clone(),
            schema_epoch: before.state.schema_epoch,
            policy_epoch: before.state.policy_epoch,
        },
        ReadAssertion::Before {
            not_after_ms: u64::MAX,
        },
    ];
    let reference = install.reference().unwrap();
    let original = db
        .activate_schema(context("owner"), install.clone())
        .await
        .unwrap();
    assert_eq!(
        db.activate_schema(context("owner"), install).await.unwrap(),
        original
    );
    let stale = ReadSchemaActivation {
        reference: reference.clone(),
        read_set: vec![ReadAssertion::Snapshot {
            incarnation: before.state.incarnation.clone(),
            schema_epoch: before.state.schema_epoch,
            policy_epoch: before.state.policy_epoch,
        }],
    };
    assert_eq!(
        db.schema_activation_status(&context("owner"), &stale)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
    drop(db);
    drop(audit);
    let (db, audit) = open(&path).await;
    let current = db.engine().generation().unwrap();
    let lookup = ReadSchemaActivation {
        reference: reference.clone(),
        read_set: vec![
            ReadAssertion::Snapshot {
                incarnation: current.state.incarnation.clone(),
                schema_epoch: current.state.schema_epoch,
                policy_epoch: current.state.policy_epoch,
            },
            ReadAssertion::Before {
                not_after_ms: u64::MAX,
            },
        ],
    };
    assert_eq!(
        db.schema_activation_status(&context("owner"), &lookup)
            .await
            .unwrap()
            .outcome
            .unwrap(),
        original
    );
    let owner = context("owner");
    let release = db.schema_status_response_fence(&owner, &lookup).unwrap();
    db.activate_schema(context("owner"), creates(db.engine(), "later", &["later"]))
        .await
        .unwrap();
    assert_eq!(release.check().unwrap_err().code, ErrorCode::Conflict);
    let fresh = ReadSchemaActivation {
        reference,
        read_set: vec![],
    };
    assert_eq!(
        db.schema_activation_status(&context("owner"), &fresh)
            .await
            .unwrap()
            .outcome
            .unwrap(),
        original
    );
    drop(release);
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}

#[test]
fn first_release_schema_wire_requires_explicit_effect_and_lookup_dependencies() {
    let db = engine(Limits::default());
    let request = creates(&db, "strict-wire", &["journal"]);
    let mut encoded = serde_json::to_value(&request).unwrap();
    encoded.as_object_mut().unwrap().remove("read_set");
    assert!(serde_json::from_value::<SchemaChangeSet>(encoded).is_err());
    let reference = request.reference().unwrap();
    assert!(
        serde_json::from_value::<ReadSchemaActivation>(serde_json::to_value(&reference).unwrap())
            .is_err()
    );
    let mut lookup = serde_json::to_value(ReadSchemaActivation {
        reference,
        read_set: vec![],
    })
    .unwrap();
    lookup.as_object_mut().unwrap().remove("read_set");
    assert!(serde_json::from_value::<ReadSchemaActivation>(lookup).is_err());
}
