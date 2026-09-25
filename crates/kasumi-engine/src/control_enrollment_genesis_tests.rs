use super::*;
use crate::{ControlGenesis, ControlLifecycleGenesis, TenantEngine};
use kasumi_types::{
    Action, CollectionDefinition, Command, ControlAuthorityPartition, ControlSigningRoot,
    ErrorCode, Grant, LifecycleInstallation, Limits, Mutation, MutationBatch, Operation, Policy,
    Precondition, RequestAuthorization, RequestContext,
};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[test]
fn installed_genesis_allows_enrollment_approval_without_reopening_schema() {
    let incarnation = Uuid::from_u128(41);
    let partition = ControlAuthorityPartition {
        authority_id: Uuid::from_u128(42),
        manifest_sha256: "12".repeat(32),
        partition: 0,
        signing_public_key: "34".repeat(32),
        maximum_lifetime_ms: 1000,
        drain_ms: 1000,
    };
    let installation = LifecycleInstallation {
        root: ControlSigningRoot {
            control_incarnation: incarnation,
            public_key: "56".repeat(32),
        },
        generation: 1,
        partitions: BTreeMap::from([(partition.key(), partition)]),
        max_intents: 100,
        max_changes: 10,
        max_state_bytes: 8 << 20,
    };
    let genesis = ControlGenesis {
        topology: ControlTopology {
            nodes: BTreeMap::from([(
                1,
                ControlNode {
                    endpoint: "https://control-1.example".into(),
                    failure_domain: "zone-1".into(),
                    certificate_pins: BTreeSet::from(["ab".repeat(32)]),
                },
            )]),
            tenants: BTreeMap::new(),
        },
        lifecycle: ControlLifecycleGenesis::Installed {
            command_id: Uuid::from_u128(43),
            installation,
        },
    };
    let policy = Policy {
        grants: vec![Grant {
            principal: "operator".into(),
            collection: None,
            actions: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        }],
        strict_read_audit: true,
    };
    let engine = TenantEngine::new_genesis(
        CONTROL_TENANT.into(),
        incarnation.to_string(),
        policy.clone(),
        Limits::default(),
        Some(&genesis),
    )
    .unwrap();
    let state = &engine.generation().unwrap().state;
    assert!(state.lifecycle_control.is_some());
    assert_eq!(
        state.collections["tenant_enrollments"].definition,
        ControlPlane::enrollment_definition()
    );
    ControlPlane::applied_topology(state).unwrap();
    let mut missing = state.clone();
    missing.collections.remove("tenant_enrollments");
    assert_eq!(
        ControlPlane::applied_topology(&missing).unwrap_err().code,
        ErrorCode::Corruption
    );
    let mut changed = state.clone();
    changed
        .collections
        .get_mut("tenant_enrollments")
        .unwrap()
        .definition
        .strict_read_audit = false;
    assert_eq!(
        ControlPlane::applied_topology(&changed).unwrap_err().code,
        ErrorCode::Corruption
    );
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let disk = kasumi_store::ScratchDisk::fixture(
        directory.path().join("scratch"),
        kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32),
    );
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "operator".into(),
        tenant: CONTROL_TENANT.into(),
        scopes: BTreeSet::from([Action::Admin, Action::Read, Action::Write]),
        request_id: "approval".into(),
    };
    engine
        .apply_command(
            &disk,
            2,
            Command {
                context: context.clone(),
                timestamp_ms: 2,
                operation: Operation::Mutate(MutationBatch {
                    idempotency_key: "approve-beta".into(),
                    read_set: vec![],
                    operations: vec![Mutation::Put {
                        collection: "tenant_enrollments".into(),
                        id: "beta".into(),
                        body: serde_json::json!({"tenant":"beta"}),
                        expected: Precondition::Absent,
                    }],
                }),
            },
        )
        .unwrap()
        .unwrap();
    assert!(
        engine.generation().unwrap().state.collections["tenant_enrollments"]
            .documents
            .contains_key("beta")
    );
    assert_eq!(
        engine
            .apply_command(
                &disk,
                3,
                Command {
                    context,
                    timestamp_ms: 3,
                    operation: Operation::CreateCollection(CollectionDefinition {
                        name: "other".into(),
                        ..ControlPlane::enrollment_definition()
                    }),
                },
            )
            .unwrap()
            .unwrap_err()
            .code,
        ErrorCode::Forbidden
    );
    let narrow = Limits {
        max_collections: 1,
        ..Default::default()
    };
    assert_eq!(
        TenantEngine::new_genesis(
            CONTROL_TENANT.into(),
            incarnation.to_string(),
            policy,
            narrow,
            Some(&genesis),
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::QuotaExceeded
    );
}
