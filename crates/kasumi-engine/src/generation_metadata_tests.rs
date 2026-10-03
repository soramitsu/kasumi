use crate::{TenantEngine, validate_genesis_inputs};
use kasumi_types::*;
use std::{collections::BTreeSet, sync::Arc};

fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        }],
        strict_read_audit: true,
    }
}

#[test]
fn generation_metadata_is_borrowed_and_keeps_the_selected_generation() {
    let scope = crate::codec_fixture::ScratchScope::new(
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    )
    .unwrap();
    let engine = TenantEngine::new(
        "tenant".into(),
        "incarnation".into(),
        policy(),
        Limits::default(),
    )
    .unwrap();
    let old = engine.generation().unwrap();
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: "tenant".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "metadata-observation".into(),
    };
    engine
        .apply_command(
            &scope.disk,
            1,
            Command {
                context: context.clone(),
                timestamp_ms: 1,
                operation: Operation::CreateCollection(CollectionDefinition {
                    name: "docs".into(),
                    write_mode: CollectionWriteMode::Mutable,
                    retention_class: CollectionRetentionClass::Operational,
                    schema: serde_json::json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: true,
                }),
            },
        )
        .unwrap()
        .unwrap();
    let created = engine.generation().unwrap();
    let mut updated_policy = policy();
    updated_policy.strict_read_audit = false;
    // A metadata publication reuses the existing terminal owner. A document
    // mutation would additionally initialize an unrelated receipt table and
    // exceed this fixture's deliberately unchanged 32-slot scratch provider.
    engine
        .apply_command(
            &scope.disk,
            2,
            Command {
                context,
                timestamp_ms: 2,
                operation: Operation::SetPolicy(updated_policy),
            },
        )
        .unwrap()
        .unwrap();
    let current = engine.generation().unwrap();
    let before_audits = current.state.audits.len();
    assert_eq!(old.revision(), 0);
    assert_eq!(old.collection_metadata_iter().len(), 0);
    assert!(old.collection_metadata("docs").is_none());
    assert!(old.policy().strict_read_audit);
    assert_eq!(created.revision(), 1);
    assert!(created.policy().strict_read_audit);
    assert_eq!(created.policy_epoch(), old.policy_epoch() + 1);
    assert_eq!(created.schema_epoch(), old.schema_epoch() + 1);
    assert_eq!(created.collection_metadata("docs").unwrap().data_epoch, 0);
    assert_eq!(current.revision(), 2);
    assert_eq!(current.document_count(), 0);
    assert!(!current.policy().strict_read_audit);
    assert_eq!(current.policy_epoch(), created.policy_epoch() + 1);
    assert_eq!(current.schema_epoch(), created.schema_epoch());
    assert_eq!(current.tenant(), "tenant");
    assert_eq!(current.incarnation(), "incarnation");
    let collection = current.collection_metadata("docs").unwrap();
    assert_eq!(collection.data_epoch, 0);
    assert_eq!(collection.live_documents, 0);
    assert_eq!(collection.archived_documents, 0);
    assert!(std::ptr::eq(
        collection.definition,
        &current.state.collections["docs"].definition
    ));
    assert!(std::ptr::eq(current.policy(), &current.state.policy));
    assert!(std::ptr::eq(current.limits(), &current.state.limits));
    assert!(std::ptr::eq(
        current.audit_retention(),
        &current.state.audit_retention
    ));
    assert!(current.lifecycle_installation().is_none());
    assert_eq!(current.collection_metadata_iter().next().unwrap().0, "docs");
    // Observations introduce neither a read audit nor a newer selection.
    let after = engine.generation().unwrap();
    assert!(Arc::ptr_eq(&current, &after));
    assert_eq!(after.state.audits.len(), before_audits);
    assert_eq!(old.document_count(), 0);
}

fn runtime_validation(
    tenant: &str,
    incarnation: &str,
    policy: &Policy,
    limits: &Limits,
) -> Result<()> {
    TenantEngine::new(
        tenant.to_owned(),
        incarnation.to_owned(),
        policy.clone(),
        limits.clone(),
    )
    .map(|_| ())
}

#[test]
fn genesis_input_validation_preserves_name_policy_and_limit_errors() {
    let valid = policy();
    let limits = Limits::default();
    assert_eq!(
        validate_genesis_inputs("tenant", "incarnation", &valid, &limits),
        Ok(())
    );
    let oversized = "x".repeat(257);
    for (tenant, incarnation) in [
        ("", "incarnation"),
        ("tenant", "bad\nincarnation"),
        (oversized.as_str(), "incarnation"),
    ] {
        let observed = validate_genesis_inputs(tenant, incarnation, &valid, &limits);
        assert_eq!(
            observed.as_ref().unwrap_err().code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            observed,
            runtime_validation(tenant, incarnation, &valid, &limits)
        );
    }
    let no_admin = Policy {
        grants: vec![],
        strict_read_audit: false,
    };
    assert_eq!(
        validate_genesis_inputs("tenant", "incarnation", &no_admin, &limits),
        runtime_validation("tenant", "incarnation", &no_admin, &limits)
    );
    let invalid_limits = Limits {
        max_document_bytes: 0,
        ..limits.clone()
    };
    assert_eq!(
        validate_genesis_inputs("tenant", "incarnation", &valid, &invalid_limits),
        runtime_validation("tenant", "incarnation", &valid, &invalid_limits)
    );
    let quota = Limits {
        max_policy_grants: 1,
        ..limits
    };
    let two = Policy {
        grants: vec![valid.grants[0].clone(), valid.grants[0].clone()],
        strict_read_audit: false,
    };
    assert_eq!(
        validate_genesis_inputs("tenant", "incarnation", &two, &quota),
        runtime_validation("tenant", "incarnation", &two, &quota)
    );
}

#[test]
fn genesis_input_validation_keeps_the_actual_initial_snapshot_quota() {
    let mut policy = policy();
    for index in 0..128 {
        policy.grants.push(Grant {
            principal: format!("reader-{index}"),
            collection: None,
            actions: BTreeSet::from([Action::Read]),
        });
    }
    let limits = Limits {
        max_snapshot_bytes: 4096,
        ..Limits::default()
    };
    let error = validate_genesis_inputs("tenant", "incarnation", &policy, &limits).unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert_eq!(error.message, "bootstrap exceeds snapshot byte budget");
    assert_eq!(
        Err(error),
        runtime_validation("tenant", "incarnation", &policy, &limits)
    );
    // Establish the constructor's smallest accepted snapshot limit, including
    // the encoded limit field itself and its reserved revision/headroom bytes.
    let mut denied = 4096;
    let mut accepted = 1 << 20;
    while accepted - denied > 1 {
        let candidate = denied + (accepted - denied) / 2;
        let limits = Limits {
            max_snapshot_bytes: candidate,
            ..Limits::default()
        };
        match runtime_validation("tenant", "incarnation", &policy, &limits) {
            Ok(()) => accepted = candidate,
            Err(error) => {
                assert_eq!(error.code, ErrorCode::QuotaExceeded);
                assert_eq!(error.message, "bootstrap exceeds snapshot byte budget");
                denied = candidate;
            }
        }
    }
    let exact = Limits {
        max_snapshot_bytes: accepted,
        ..Limits::default()
    };
    assert_eq!(
        validate_genesis_inputs("tenant", "incarnation", &policy, &exact),
        Ok(())
    );
    let below = Limits {
        max_snapshot_bytes: accepted - 1,
        ..exact
    };
    assert_eq!(
        validate_genesis_inputs("tenant", "incarnation", &policy, &below),
        runtime_validation("tenant", "incarnation", &policy, &below)
    );
    assert_eq!(
        validate_genesis_inputs("tenant", "incarnation", &policy, &below)
            .unwrap_err()
            .code,
        ErrorCode::QuotaExceeded
    );
}
