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
    assert_eq!(db.snapshot().unwrap().len(), db.snapshot_bytes().unwrap());
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
    let bytes = db.snapshot().unwrap();
    let recovered = engine(Limits::default());
    recovered.restore(&bytes).unwrap();
    assert_eq!(bytes, recovered.snapshot().unwrap());
    let mut state: TenantState = serde_json::from_slice(&bytes).unwrap();
    state.schema_activation_bytes += 1;
    assert_eq!(
        recovered
            .restore(&serde_json::to_vec(&state).unwrap())
            .unwrap_err()
            .code,
        ErrorCode::Corruption
    );
    assert_eq!(bytes, recovered.snapshot().unwrap());
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
    let store = TenantStore::open(
        node,
        "schema".into(),
        Arc::new(LocalKeyProvider::new([0xF1; 32])),
    )
    .await
    .unwrap();
    let db = kasumi_engine::open_local(store, policy(), Limits::default(), audit.clone())
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
        db.schema_activation_status(&context("owner"), &reference)
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
        .backup(context("owner"), destination.as_ref())
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
        db.schema_activation_status(&context("owner"), &reference)
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
    let target = TenantStore::open(node, "schema".into(), provider.clone())
        .await
        .unwrap();
    let source = kasumi_engine::RestoreSource {
        destination_alias: "full".into(),
        destination,
        keys: provider,
        timeout_ms: 60_000,
    };
    let restored =
        kasumi_engine::restore_local(&source, backup, target, context("owner"), audit.clone())
            .await
            .unwrap();
    assert_ne!(
        restored.engine().generation().unwrap().state.incarnation,
        install.expected_incarnation
    );
    assert_eq!(
        restored
            .activate_schema(context("owner"), install)
            .await
            .unwrap(),
        receipt
    );
    assert_eq!(
        restored
            .schema_activation_status(&context("owner"), &reference)
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
    db.schema_activation_status(&context("scoped"), &reference)
        .await
        .unwrap();
    assert_eq!(
        db.schema_activation_status(&context("owner"), &reference)
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
        db.schema_activation_status(&context("scoped"), &reference)
            .await
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    db.shutdown().await.unwrap();
    audit.shutdown().await;
}
