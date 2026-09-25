use kasumi_engine::test_utils::{SnapshotFixture, snapshot_accounted_bytes};
mod common;
use common::FixtureEngine;
use kasumi_engine::{Database, SecurityAudit, TenantEngine};
use kasumi_store::{TenantStore, test_utils::LocalKeyProvider};
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
fn engine(limits: Limits) -> FixtureEngine {
    FixtureEngine::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
        "schema".into(),
        "incarnation".into(),
        policy(),
        limits,
    )
    .unwrap()
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
fn apply_as(db: &FixtureEngine, principal: &str, operation: Operation) -> Result<WriteReceipt> {
    let revision = db.generation().unwrap().state.revision + 1;
    let result = db
        .apply_command(
            &db.disk,
            revision,
            Command {
                context: context(principal),
                timestamp_ms: revision * 86_400_001,
                operation,
            },
        )
        .unwrap();
    assert_eq!(
        snapshot_accounted_bytes(&db.fixture_snapshot(&db.disk).unwrap()).unwrap(),
        db.snapshot_bytes().unwrap() as u64
    );
    result
}
fn apply(db: &FixtureEngine, operation: Operation) -> Result<WriteReceipt> {
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
fn mutate(db: &FixtureEngine, key: &str, operations: Vec<Mutation>) {
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
#[ignore = "requires BOI_COLLECTIONS_DIR from the pinned BOI source checkout"]
fn pinned_boi_collection_files_activate_as_one_native_schema_bundle() {
    let directory = std::path::PathBuf::from(
        std::env::var("BOI_COLLECTIONS_DIR").expect("BOI_COLLECTIONS_DIR must be explicit"),
    );
    assert!(directory.is_absolute(), "collection path must be absolute");
    let expected = std::collections::BTreeMap::from([
        ("boi_core_owner", CollectionWriteMode::AppendOnly),
        ("boi_core_policy", CollectionWriteMode::Mutable),
        ("boi_core_uids", CollectionWriteMode::AppendOnly),
        ("boi_core_wallets", CollectionWriteMode::Mutable),
        (
            "boi_core_dynamic_wallet_bindings",
            CollectionWriteMode::Mutable,
        ),
        ("boi_core_payments", CollectionWriteMode::AppendOnly),
        (
            "boi_core_payment_idempotency",
            CollectionWriteMode::AppendOnly,
        ),
        (
            "boi_core_ledger_payment_intents",
            CollectionWriteMode::AppendOnly,
        ),
        (
            "boi_core_ledger_payment_receipts",
            CollectionWriteMode::AppendOnly,
        ),
        (
            "boi_core_ledger_payment_claims",
            CollectionWriteMode::Mutable,
        ),
        (
            "boi_core_client_payment_quotes",
            CollectionWriteMode::AppendOnly,
        ),
        (
            "boi_core_client_payment_idempotency",
            CollectionWriteMode::AppendOnly,
        ),
        (
            "boi_core_client_payment_receipts",
            CollectionWriteMode::AppendOnly,
        ),
        ("boi_core_settlements", CollectionWriteMode::AppendOnly),
    ]);
    let supplied = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|value| value == "json"))
        .collect::<Vec<_>>();
    assert_eq!(supplied.len(), expected.len(), "exact BOI schema file set");
    let mut definitions = Vec::new();
    for (name, mode) in expected {
        let path = directory.join(format!("{name}.collection.json"));
        let definition: CollectionDefinition =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(definition.name, name);
        assert_eq!(definition.write_mode, mode);
        assert!(definition.strict_read_audit);
        assert_eq!(
            definition.retention_class,
            if mode == CollectionWriteMode::AppendOnly {
                CollectionRetentionClass::ArchivableHistory
            } else {
                CollectionRetentionClass::Operational
            }
        );
        definitions.push(definition);
    }
    let db = engine(Limits::default());
    let receipt = apply(
        &db,
        Operation::ActivateSchema(request(
            &db,
            "boi-first-release-14-collections",
            definitions
                .iter()
                .cloned()
                .map(|definition| SchemaChange::Create { definition })
                .collect(),
        )),
    )
    .unwrap();
    let generation = db.generation().unwrap();
    assert_eq!(generation.state.schema_epoch, 1);
    assert_eq!(generation.state.collections.len(), 14);
    assert_eq!(receipt.revision, generation.state.revision);
    for definition in definitions {
        let installed = &generation.state.collections[&definition.name].definition;
        assert_eq!(
            serde_json::to_value(installed).unwrap(),
            serde_json::to_value(definition).unwrap()
        );
    }
}

#[test]
#[ignore = "requires FI_AUTH_COLLECTIONS_DIR from the pinned FI Core source checkout"]
fn pinned_fi_auth_collection_files_activate_as_one_native_schema_bundle() {
    let directory = std::path::PathBuf::from(
        std::env::var("FI_AUTH_COLLECTIONS_DIR").expect("FI_AUTH_COLLECTIONS_DIR must be explicit"),
    );
    let expected = [
        ("fi_auth_admin_actions", CollectionWriteMode::Mutable),
        ("fi_auth_consumed", CollectionWriteMode::AppendOnly),
        ("fi_auth_devices", CollectionWriteMode::Mutable),
        ("fi_auth_invite_delivery", CollectionWriteMode::Mutable),
        ("fi_auth_ephemeral", CollectionWriteMode::Mutable),
        ("fi_auth_mfa", CollectionWriteMode::Mutable),
        ("fi_auth_rate_limits", CollectionWriteMode::Mutable),
        ("fi_auth_recovery", CollectionWriteMode::Mutable),
        ("fi_auth_users", CollectionWriteMode::Mutable),
    ];
    let supplied = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("fi_auth_") && name.ends_with(".collection.json")
                })
        })
        .count();
    assert_eq!(supplied, expected.len(), "exact FI auth schema file set");
    let definitions = expected
        .into_iter()
        .map(|(name, mode)| {
            let path = directory.join(format!("{name}.collection.json"));
            let definition: CollectionDefinition =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(definition.name, name);
            assert_eq!(definition.write_mode, mode);
            assert!(definition.strict_read_audit);
            assert_eq!(
                definition.retention_class,
                if mode == CollectionWriteMode::AppendOnly {
                    CollectionRetentionClass::ArchivableHistory
                } else {
                    CollectionRetentionClass::Operational
                }
            );
            definition
        })
        .collect::<Vec<_>>();
    let invite = definitions
        .iter()
        .find(|definition| definition.name == "fi_auth_invite_delivery")
        .unwrap();
    let mut sample = json!({
        "schema": "fi.auth-record.v1",
        "fi_id": "leumi.is2",
        "kind": "invite_delivery",
        "subject_sha256": "a".repeat(64),
        "group_sha256": null,
        "expires_at_ms": null,
        "payload": {
            "schema": "fi.invite-delivery.v1",
            "fi_id": "leumi.is2",
            "action_sha256": "b".repeat(64),
            "invite_sha256": "c".repeat(64),
            "delivery_id": "d".repeat(64),
            "sealed": {"key_id": "k1", "ciphertext_base64": "A".repeat(64)},
            "state": {"status": "PENDING"},
            "created_at_ms": 1000,
            "updated_at_ms": 1000,
            "invite_expires_at_ms": 2000
        }
    });
    kasumi_query::validate_document(invite, &sample).unwrap();
    sample["payload"]["state"] = json!({
        "status": "CLAIMED",
        "claim_id": "claim-1",
        "lease_until_ms": 1500
    });
    sample["payload"]["updated_at_ms"] = json!(1100);
    kasumi_query::validate_document(invite, &sample).unwrap();
    sample["payload"]["fi_id"] = json!("hapoalim.is2");
    // The shared FI schema validates an approved FI identity; the signed
    // tenant binding and service readback enforce equality to the local FI.
    kasumi_query::validate_document(invite, &sample).unwrap();
    sample["payload"]["fi_id"] = json!("leumi.is");
    assert!(kasumi_query::validate_document(invite, &sample).is_err());
    let db = engine(Limits::default());
    let receipt = apply(
        &db,
        Operation::ActivateSchema(request(
            &db,
            "fi-auth-first-release-9-collections",
            definitions
                .iter()
                .cloned()
                .map(|definition| SchemaChange::Create { definition })
                .collect(),
        )),
    )
    .unwrap();
    let generation = db.generation().unwrap();
    assert_eq!(generation.state.schema_epoch, 1);
    assert_eq!(generation.state.collections.len(), 9);
    assert_eq!(receipt.revision, generation.state.revision);
    for definition in definitions {
        let installed = &generation.state.collections[&definition.name].definition;
        assert_eq!(
            serde_json::to_value(installed).unwrap(),
            serde_json::to_value(definition).unwrap()
        );
    }
}

#[test]
#[ignore = "requires KYC_COLLECTIONS_DIR rendered from an independently pinned FI identity"]
fn pinned_kyc_collection_files_activate_as_one_native_schema_bundle() {
    let directory = std::path::PathBuf::from(
        std::env::var("KYC_COLLECTIONS_DIR").expect("KYC_COLLECTIONS_DIR must be explicit"),
    );
    let expected = [
        ("kyc_vault_owner", CollectionWriteMode::AppendOnly),
        (
            "kyc_encrypted_resource_chunks",
            CollectionWriteMode::Mutable,
        ),
        ("kyc_document_seals", CollectionWriteMode::Mutable),
        ("kyc_submissions", CollectionWriteMode::Mutable),
        ("kyc_submission_index", CollectionWriteMode::Mutable),
        ("kyc_user_pending_submissions", CollectionWriteMode::Mutable),
        ("kyc_audit_evidence", CollectionWriteMode::AppendOnly),
        ("kyc_audit_outbox", CollectionWriteMode::Mutable),
        ("kyc_idempotency", CollectionWriteMode::AppendOnly),
        ("kyc_recovery_requests", CollectionWriteMode::AppendOnly),
    ];
    let supplied = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|value| value == "json"))
        .count();
    assert_eq!(supplied, expected.len(), "exact KYC schema file set");
    let definitions = expected
        .into_iter()
        .map(|(name, mode)| {
            let path = directory.join(format!("{name}.collection.json"));
            let definition: CollectionDefinition =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(definition.name, name);
            assert_eq!(definition.write_mode, mode);
            assert!(definition.strict_read_audit);
            assert_eq!(
                definition.retention_class,
                if mode == CollectionWriteMode::AppendOnly {
                    CollectionRetentionClass::ArchivableHistory
                } else {
                    CollectionRetentionClass::Operational
                }
            );
            definition
        })
        .collect::<Vec<_>>();
    let submission = definitions
        .iter()
        .find(|definition| definition.name == "kyc_submissions")
        .unwrap();
    let mut sample = json!({
        "schema": "kyc.sealed-submission.v1",
        "fi_id": "leumi.is2",
        "owner_hash": "a".repeat(64),
        "record": {},
        "document_seals": [{"id": format!("seal-{}", "b".repeat(64)), "sha256": "c".repeat(64)}]
    });
    kasumi_query::validate_document(submission, &sample).unwrap();
    sample["document_seals"][0]["sha256"] = json!("tampered");
    assert!(kasumi_query::validate_document(submission, &sample).is_err());
    sample["document_seals"][0]["sha256"] = json!("c".repeat(64));
    sample["fi_id"] = json!("hapoalim.is2");
    assert!(kasumi_query::validate_document(submission, &sample).is_err());
    let outbox = definitions
        .iter()
        .find(|definition| definition.name == "kyc_audit_outbox")
        .unwrap();
    let cursor = json!({
        "schema": "kyc.audit-scan-cursor.v1",
        "fi_id": "leumi.is2",
        "after_id": null,
    });
    kasumi_query::validate_document(outbox, &cursor).unwrap();
    let marker = json!({
        "schema": "kyc.audit-outbox.v1",
        "fi_id": "leumi.is2",
        "event_id": "event-1",
        "delivered": false,
    });
    kasumi_query::validate_document(outbox, &marker).unwrap();
    let mut cross_fi = cursor.clone();
    cross_fi["fi_id"] = json!("hapoalim.is2");
    assert!(kasumi_query::validate_document(outbox, &cross_fi).is_err());
    let mut invalid_resume = cursor.clone();
    invalid_resume["after_id"] = json!("event-not-a-hash");
    assert!(kasumi_query::validate_document(outbox, &invalid_resume).is_err());
    let evidence = definitions
        .iter()
        .find(|definition| definition.name == "kyc_audit_evidence")
        .unwrap();
    let valid_evidence = json!({
        "schema":"kyc.audit-evidence.v1", "fi_id":"leumi.is2",
        "event":{"event_id":"e1"}, "event_sha256":"a".repeat(64),
        "account_id_header_base64":null
    });
    kasumi_query::validate_document(evidence, &valid_evidence).unwrap();
    let mut invalid_evidence = valid_evidence.clone();
    invalid_evidence["event_sha256"] = json!("not-a-hash");
    assert!(kasumi_query::validate_document(evidence, &invalid_evidence).is_err());
    let idempotency = definitions
        .iter()
        .find(|definition| definition.name == "kyc_idempotency")
        .unwrap();
    let claim = json!({
        "schema":"kyc.idempotency.v1", "fi_id":"leumi.is2",
        "scope":"kyc_submission", "key_sha256":"a".repeat(64),
        "request_sha256":"b".repeat(64),
        "resource_id":"729153da-ad5b-4dfa-8c37-2665507007aa",
        "created_at":"2026-09-24T00:00:00Z"
    });
    kasumi_query::validate_document(idempotency, &claim).unwrap();
    let mut wrong_scope = claim.clone();
    wrong_scope["scope"] = json!("legacy_recovery");
    assert!(kasumi_query::validate_document(idempotency, &wrong_scope).is_err());
    let db = engine(Limits::default());
    let receipt = apply(
        &db,
        Operation::ActivateSchema(request(
            &db,
            "kyc-first-release-9-collections",
            definitions
                .iter()
                .cloned()
                .map(|definition| SchemaChange::Create { definition })
                .collect(),
        )),
    )
    .unwrap();
    let generation = db.generation().unwrap();
    assert_eq!(generation.state.schema_epoch, 1);
    assert_eq!(generation.state.collections.len(), 9);
    assert_eq!(receipt.revision, generation.state.revision);
    for definition in definitions {
        let installed = &generation.state.collections[&definition.name].definition;
        assert_eq!(
            serde_json::to_value(installed).unwrap(),
            serde_json::to_value(definition).unwrap()
        );
    }
    let low = format!("event-{}", "0".repeat(64));
    let high = format!("event-{}", "f".repeat(64));
    let behind = format!("event-{}", "8".repeat(64));
    let marker = |event_id: &str| {
        json!({
            "schema": "kyc.audit-outbox.v1", "fi_id": "leumi.is2",
            "event_id": event_id, "delivered": true
        })
    };
    let bootstrap = apply(
        &db,
        Operation::Mutate(MutationBatch {
            idempotency_key: "kyc-owner-cursor-bootstrap".into(),
            read_set: vec![],
            operations: vec![
                Mutation::Put {
                    collection: "kyc_vault_owner".into(),
                    id: "owner".into(),
                    body: json!({"schema":"kyc.vault-owner.v1","fi_id":"leumi.is2"}),
                    expected: Precondition::Absent,
                },
                Mutation::Put {
                    collection: "kyc_audit_outbox".into(),
                    id: "scan-cursor".into(),
                    body: cursor.clone(),
                    expected: Precondition::Absent,
                },
            ],
        }),
    )
    .unwrap();
    assert_eq!(
        bootstrap.versions["/kyc_vault_owner/owner"],
        bootstrap.revision
    );
    assert_eq!(
        bootstrap.versions["/kyc_audit_outbox/scan-cursor"],
        bootstrap.revision
    );
    mutate(
        &db,
        "kyc-audit-markers",
        vec![
            Mutation::Put {
                collection: "kyc_audit_outbox".into(),
                id: low.clone(),
                body: marker("low"),
                expected: Precondition::Absent,
            },
            Mutation::Put {
                collection: "kyc_audit_outbox".into(),
                id: high.clone(),
                body: marker("high"),
                expected: Precondition::Absent,
            },
        ],
    );
    let before = db.generation().unwrap();
    let outbox = &before.state.collections["kyc_audit_outbox"];
    let cursor_version = outbox.documents["scan-cursor"].version;
    let advance = |id: &str, epoch: u64, version: u64, after_id: Option<String>| {
        let state = db.generation().unwrap();
        MutationBatch {
            idempotency_key: id.into(),
            read_set: vec![
                ReadAssertion::Snapshot {
                    incarnation: state.state.incarnation.clone(),
                    policy_epoch: state.state.policy_epoch,
                    schema_epoch: state.state.schema_epoch,
                },
                ReadAssertion::Document {
                    collection: "kyc_audit_outbox".into(),
                    id: "scan-cursor".into(),
                    expected: ReadPrecondition::Version(version),
                },
                ReadAssertion::Collection {
                    collection: "kyc_audit_outbox".into(),
                    data_epoch: epoch,
                },
            ],
            operations: vec![Mutation::Put {
                collection: "kyc_audit_outbox".into(),
                id: "scan-cursor".into(),
                body: json!({"schema":"kyc.audit-scan-cursor.v1","fi_id":"leumi.is2","after_id":after_id}),
                expected: Precondition::Version(version),
            }],
        }
    };
    apply(
        &db,
        Operation::Mutate(advance(
            "cursor-after-high",
            outbox.data_epoch,
            cursor_version,
            Some(high.clone()),
        )),
    )
    .unwrap();
    let committed = db.generation().unwrap();
    let committed_outbox = &committed.state.collections["kyc_audit_outbox"];
    let committed_version = committed_outbox.documents["scan-cursor"].version;
    let stale_epoch = committed_outbox.data_epoch;
    drop(committed);
    mutate(
        &db,
        "insert-behind-cursor",
        vec![Mutation::Put {
            collection: "kyc_audit_outbox".into(),
            id: behind.clone(),
            body: marker("behind"),
            expected: Precondition::Absent,
        }],
    );
    let restarted = db.generation().unwrap();
    assert_eq!(
        restarted.state.collections["kyc_audit_outbox"].documents["scan-cursor"].body["after_id"],
        json!(high)
    );
    assert!(
        restarted.state.collections["kyc_audit_outbox"]
            .documents
            .keys()
            .filter(|id| *id > &high)
            .all(|id| id == "scan-cursor")
    );
    assert_eq!(
        apply(
            &db,
            Operation::Mutate(advance("stale-wrap", stale_epoch, committed_version, None))
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict,
        "insertion during a scan must fence cursor advancement"
    );
    let fresh_epoch = restarted.state.collections["kyc_audit_outbox"].data_epoch;
    drop(restarted);
    apply(
        &db,
        Operation::Mutate(advance("cursor-wrap", fresh_epoch, committed_version, None)),
    )
    .unwrap();
    let after_wrap = db.generation().unwrap();
    assert_eq!(
        after_wrap.state.collections["kyc_audit_outbox"].documents["scan-cursor"].body["after_id"],
        json!(null)
    );
    let ids = after_wrap.state.collections["kyc_audit_outbox"]
        .documents
        .keys()
        .filter(|id| id.starts_with("event-"))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![low, behind, high],
        "fresh scan after restart/wrap must see the inserted marker"
    );
}

#[test]
#[ignore = "requires FI_GOVERNANCE_COLLECTIONS_DIR from the pinned FI Core source checkout"]
fn pinned_fi_governance_collection_files_activate_as_one_native_schema_bundle() {
    let directory = std::path::PathBuf::from(
        std::env::var("FI_GOVERNANCE_COLLECTIONS_DIR")
            .expect("FI_GOVERNANCE_COLLECTIONS_DIR must be explicit"),
    );
    let expected = [
        ("fi_governance_controls", CollectionWriteMode::Mutable),
        (
            "fi_governance_dataspace_profiles",
            CollectionWriteMode::Mutable,
        ),
        ("fi_governance_fee_events", CollectionWriteMode::AppendOnly),
        ("fi_governance_fee_inflows", CollectionWriteMode::AppendOnly),
        (
            "fi_governance_fee_instruction_claims",
            CollectionWriteMode::AppendOnly,
        ),
        (
            "fi_governance_fee_policies",
            CollectionWriteMode::AppendOnly,
        ),
        ("fi_governance_fee_state", CollectionWriteMode::Mutable),
        ("fi_governance_fi_registry", CollectionWriteMode::Mutable),
        ("fi_governance_idempotency", CollectionWriteMode::Mutable),
        (
            "fi_governance_provisioning_jobs",
            CollectionWriteMode::Mutable,
        ),
        ("fi_governance_settlement", CollectionWriteMode::Mutable),
        ("fi_governance_two_tier", CollectionWriteMode::Mutable),
        ("fi_merchant_records", CollectionWriteMode::Mutable),
        ("fi_consumer_cases", CollectionWriteMode::Mutable),
        ("fi_consumer_legal_cases", CollectionWriteMode::Mutable),
        ("fi_compliance_cases", CollectionWriteMode::Mutable),
        ("fi_compliance_events", CollectionWriteMode::AppendOnly),
    ];
    let supplied = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    (name.starts_with("fi_governance_")
                        || name.starts_with("fi_merchant_")
                        || name.starts_with("fi_consumer_")
                        || name.starts_with("fi_compliance_"))
                        && name.ends_with(".collection.json")
                })
        })
        .count();
    assert_eq!(
        supplied,
        expected.len(),
        "exact FI governance schema file set"
    );
    let definitions = expected
        .into_iter()
        .map(|(name, mode)| {
            let path = directory.join(format!("{name}.collection.json"));
            let definition: CollectionDefinition =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            assert_eq!(definition.name, name);
            assert_eq!(definition.write_mode, mode);
            assert!(definition.strict_read_audit);
            assert_eq!(
                definition.retention_class,
                if mode == CollectionWriteMode::AppendOnly {
                    CollectionRetentionClass::ArchivableHistory
                } else {
                    CollectionRetentionClass::Operational
                }
            );
            definition
        })
        .collect::<Vec<_>>();
    let db = engine(Limits::default());
    let receipt = apply(
        &db,
        Operation::ActivateSchema(request(
            &db,
            "fi-governance-first-release-17-collections",
            definitions
                .iter()
                .cloned()
                .map(|definition| SchemaChange::Create { definition })
                .collect(),
        )),
    )
    .unwrap();
    let generation = db.generation().unwrap();
    assert_eq!(generation.state.schema_epoch, 1);
    assert_eq!(generation.state.collections.len(), 17);
    assert_eq!(receipt.revision, generation.state.revision);
    for definition in definitions {
        let installed = &generation.state.collections[&definition.name].definition;
        assert_eq!(
            serde_json::to_value(installed).unwrap(),
            serde_json::to_value(definition).unwrap()
        );
    }
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
            &db.disk,
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
    let db = engine(Limits::default());
    let install = creates(&db, "install", &["a", "b"]);
    let receipt = apply(&db, Operation::ActivateSchema(install.clone())).unwrap();
    let used = db.generation().unwrap().state.schema_activation_bytes;
    apply(
        &db,
        Operation::SetLimits(Limits {
            max_schema_activation_bytes: used,
            ..Default::default()
        }),
    )
    .unwrap();
    let before_epoch = db.generation().unwrap().state.schema_epoch;
    assert_eq!(
        apply(&db, Operation::ActivateSchema(creates(&db, "full", &["c"])))
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert!(!db.generation().unwrap().state.collections.contains_key("c"));
    assert_eq!(db.generation().unwrap().state.schema_epoch, before_epoch);
    assert_eq!(db.generation().unwrap().state.schema_activation_bytes, used);
    assert_eq!(
        apply(&db, Operation::ActivateSchema(install)).unwrap(),
        receipt
    );
    // Expanding the byte budget admits an unaccepted identity without altering
    // already permanent outcomes. Values above the former format ceiling work.
    apply(
        &db,
        Operation::SetLimits(Limits {
            max_schema_activation_bytes: 3 << 30,
            ..Default::default()
        }),
    )
    .unwrap();
    apply(&db, Operation::ActivateSchema(creates(&db, "full", &["c"]))).unwrap();

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
                max_schema_activation_bytes: 1,
                ..Default::default()
            })
        )
        .unwrap_err()
        .code,
        ErrorCode::QuotaExceeded
    );
    let bytes = db.fixture_snapshot(&db.disk).unwrap();
    let recovered = engine(Limits::default());
    recovered.fixture_restore(&bytes).unwrap();
    assert_eq!(bytes, recovered.fixture_snapshot(&recovered.disk).unwrap());
    let mut state = kasumi_engine::test_utils::decode_snapshot_candidate(&bytes).unwrap();
    state.schema_activation_bytes += 1;
    assert_eq!(
        recovered
            .fixture_restore(
                &kasumi_engine::test_utils::encode_snapshot_candidate(&db.disk, &state, 64 << 20)
                    .unwrap()
            )
            .unwrap_err()
            .code,
        ErrorCode::Corruption
    );
    assert_eq!(bytes, recovered.fixture_snapshot(&recovered.disk).unwrap());
}

#[test]
fn restored_permanent_schema_history_exceeds_the_former_lifetime_ceiling() {
    let db = engine(Limits::default());
    apply(&db, Operation::ActivateSchema(creates(&db, "seed", &["a"]))).unwrap();
    let mut state = db.generation().unwrap().state.clone();
    let seed = state.schema_activations.values().next().unwrap().clone();
    state.schema_activations.clear();
    state.schema_activation_bytes = 0;
    // A generated, fully validated history fixture avoids 100,001 live network
    // requests. The subsequent new command still traverses actual admission.
    for index in 0..100_001 {
        let mut record = seed.clone();
        record.activation_id = format!("historic-{index}");
        let key = staged_digest(&(&record.principal, &record.activation_id))
            .unwrap()
            .0;
        state.schema_activation_bytes += (serde_json::to_vec(&key).unwrap().len()
            + 1
            + serde_json::to_vec(&record).unwrap().len())
            as u64;
        state.schema_activations.insert(key, record);
    }
    let bytes =
        kasumi_engine::test_utils::encode_snapshot_candidate(&db.disk, &state, 128 << 20).unwrap();
    let restored = engine(Limits::default());
    restored.fixture_restore(&bytes).unwrap();
    apply(
        &restored,
        Operation::ActivateSchema(creates(&restored, "after-history", &["b"])),
    )
    .unwrap();
    assert_eq!(
        restored
            .generation()
            .unwrap()
            .state
            .schema_activations
            .len(),
        100_002
    );
    let mut incompatible = serde_json::to_value(Limits::default()).unwrap();
    incompatible["max_schema_activations"] = json!(4096);
    assert!(serde_json::from_value::<Limits>(incompatible).is_err());
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

async fn open(
    physical: &common::PhysicalFixture,
    path: &std::path::Path,
    create: bool,
) -> (
    Arc<Database>,
    Arc<SecurityAudit>,
    Arc<kasumi_store::NodeStore>,
) {
    let node = (if create {
        physical
            .storage
            .create_new(path, kasumi_store::test_utils::NODE_STORE_ID)
    } else {
        physical
            .storage
            .open_existing(path, kasumi_store::test_utils::NODE_STORE_ID)
    })
    .unwrap();
    let audit = if create {
        common::security_audit(node.clone(), physical.storage.admission.clone()).await
    } else {
        common::existing_security_audit(node.clone(), physical.storage.admission.clone()).await
    };
    let store = (if create {
        TenantStore::initialize_catalog_fixture(
            node.clone(),
            "schema".into(),
            Arc::new(LocalKeyProvider::new([0xF1; 32])),
        )
        .await
    } else {
        TenantStore::open_existing_fixture(
            node.clone(),
            "schema".into(),
            Arc::new(LocalKeyProvider::new([0xF1; 32])),
        )
        .await
    })
    .unwrap();
    let db = kasumi_engine::test_utils::open_fixture(
        (if create {
            kasumi_store::test_utils::initialize_custody_fixture(
                store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([242; 32])),
            )
            .await
        } else {
            kasumi_store::test_utils::open_existing_custody_fixture(
                store,
                std::sync::Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([242; 32])),
            )
            .await
        })
        .unwrap(),
        policy(),
        Limits::default(),
        audit.clone(),
    )
    .await
    .unwrap();
    (db, audit, node)
}

#[tokio::test]
async fn encrypted_restart_and_full_restore_preserve_permanent_activation_receipts() {
    let root = kasumi_store::test_utils::private_tempdir().unwrap();
    let path = root.path().join("node.kv");
    let physical = common::PhysicalFixture::new(&path, Default::default());
    let (db, audit, node) = open(&physical, &path, true).await;
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
        kasumi_store::FilesystemBackupDestination::new_fixture(
            root.path().join("backups"),
            16 << 20,
            physical.storage.admission.memory().clone(),
        )
        .unwrap(),
    );
    let backup = db
        .backup_checkpoint(context("owner"), destination.as_ref(), uuid::Uuid::new_v4())
        .await
        .unwrap();
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    drop(db);
    drop(audit);
    drop(node);
    let (db, audit, node) = open(&physical, &path, false).await;
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
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    drop(db);
    drop(audit);
    drop(node);

    let node = physical
        .storage
        .create_new(
            root.path().join("restored.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let audit = common::security_audit(node.clone(), physical.storage.admission.clone()).await;
    let provider = Arc::new(LocalKeyProvider::new([0xF1; 32]));
    let target = TenantStore::initialize_catalog_fixture(node, "schema".into(), provider.clone())
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
        kasumi_store::test_utils::initialize_custody_fixture(
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
    audit.shutdown().await.unwrap();
}

#[tokio::test]
async fn cold_schema_change_rejects_whole_bundle_and_scoped_status_rechecks_authority() {
    let root = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical = common::PhysicalFixture::new(&root.path().join("node.kv"), Default::default());
    let (db, audit, node) = open(&physical, &root.path().join("node.kv"), true).await;
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
            kasumi_store::FilesystemBackupDestination::new_fixture(
                root.path().join("cold"),
                16 << 20,
                physical.storage.admission.memory().clone(),
            )
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
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
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
    let root = kasumi_store::test_utils::private_tempdir().unwrap();
    let path = root.path().join("schema-fences.kv");
    let physical = common::PhysicalFixture::new(&path, Default::default());
    let (db, audit, node) = open(&physical, &path, true).await;
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
    // The generation retains its durable receipt store and physical file owner.
    // Its copied snapshot fences above remain valid after the owner is released.
    drop(before);
    db.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    drop(db);
    drop(audit);
    drop(node);
    let (db, audit, node) = open(&physical, &path, false).await;
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
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
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
