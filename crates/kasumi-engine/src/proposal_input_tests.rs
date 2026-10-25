use super::*;
use crate::admission::AdmissionConfig;
use crate::document_pool::allocation_tests::{check_topology_input_drop, measure_topology_input};
use kasumi_types::control_topology::{ControlNode, DeploymentMode, TenantRoute};
use std::collections::{BTreeMap, BTreeSet};

fn topology(count: usize) -> ControlTopology {
    ControlTopology {
        nodes: (1..=count)
            .map(|id| {
                (
                    id as u64,
                    ControlNode {
                        endpoint: format!("https://node-{id}.invalid/"),
                        failure_domain: format!("rack-{id}"),
                        certificate_pins: BTreeSet::from([format!("{id:064x}")]),
                    },
                )
            })
            .collect(),
        tenants: BTreeMap::from([(
            "tenant".into(),
            TenantRoute {
                incarnation: "b63744c9-1caf-4a95-884b-c7c4d261a12f".into(),
                mode: DeploymentMode::Local,
                voters: BTreeSet::from([1]),
            },
        )]),
    }
}
fn node(payload: u64) -> Arc<NodeAdmission> {
    NodeAdmission::with_fixed_memory(
        crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            high_water_bytes: Some(128 << 20),
            low_water_bytes: Some(96 << 20),
            max_inflight_bytes: Some(payload),
            max_inflight_operations: 2,
            max_reservations: 16,
            max_snapshot_startups: 2,
            max_startup_scopes: 2,
            ..Default::default()
        })
        .unwrap(),
        128 << 20,
        0,
    )
    .unwrap()
}
fn context() -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: crate::control::CONTROL_TENANT.into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Admin, Action::Write]),
        request_id: "input".into(),
    }
}

#[test]
fn waiting_mutation_charges_actual_spare_capacity_without_an_execution_slot() {
    let node = node(2 << 20);
    let baseline = node.snapshot();
    let mut proof = String::with_capacity(128 << 10);
    proof.push('x');
    let address = proof.as_ptr();
    let mut input = OperationInput::ordinary(Operation::Mutate(MutationBatch::new().upsert(
        "docs",
        "one",
        Value::String(proof),
    )));
    assert!(input.admit_waiting_mutation(&node, &context()).unwrap());
    let queued = node.snapshot();
    assert_eq!(queued.inflight_operations, baseline.inflight_operations);
    assert!(queued.reserved_bytes - baseline.reserved_bytes >= 128 << 10);
    let command = input.into_command(context());
    let Operation::Mutate(batch) = &command.command.operation else {
        unreachable!()
    };
    let Mutation::Put {
        body: Value::String(proof),
        ..
    } = &batch.operations[0]
    else {
        unreachable!()
    };
    assert_eq!(
        proof.as_ptr(),
        address,
        "queue transfers the original input without copying proofs"
    );
    assert_eq!(node.snapshot().reserved_bytes, queued.reserved_bytes);
    drop(command);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
}

#[test]
fn waiting_mutation_accounts_for_a_retained_empty_object_root() {
    let mut map = serde_json::Map::new();
    map.insert("removed".into(), Value::Null);
    map.remove("removed");
    let mut batch = MutationBatch::new().upsert("docs", "one", Value::Object(map));
    let with_root = waiting_mutation_bytes(&context(), &batch).unwrap();
    let Mutation::Put { body, .. } = &mut batch.operations[0] else {
        unreachable!()
    };
    *body = Value::Null;
    let without_root = waiting_mutation_bytes(&context(), &batch).unwrap();
    assert_eq!(with_root - without_root, tree::<String, Value>(1).unwrap());
}

#[test]
fn topology_input_denial_same_core_and_ordered_unpolled_destruction() {
    let source = topology(3);
    let quoted = quote(&source, 3).unwrap();
    let refused = node(quoted.peak - 1);
    let baseline = refused.snapshot();
    let error = OperationInput::topology(&refused, source.clone(), Precondition::Absent, "key")
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert_eq!(refused.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        refused.snapshot().live_reservations,
        baseline.live_reservations
    );

    let admitted = node(quoted.peak);
    let baseline = admitted.snapshot();
    let input = OperationInput::topology(&admitted, source, Precondition::Absent, "key").unwrap();
    assert_eq!(admitted.snapshot().inflight_operations, 0);
    assert_eq!(
        admitted.snapshot().reserved_bytes,
        baseline.reserved_bytes + quoted.retained
    );
    input.check_admission(&admitted).unwrap();
    assert_eq!(
        input.check_admission(&refused).unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let command = input.into_command(context());
    let address = payload_address_for_test(&command);
    let future = async move {
        std::future::pending::<()>().await;
        drop(command);
    };
    check_topology_input_drop(
        address,
        move || drop(future),
        || {
            assert_eq!(
                admitted.snapshot().reserved_bytes,
                baseline.reserved_bytes + quoted.retained
            );
            assert_eq!(
                admitted.snapshot().live_reservations,
                baseline.live_reservations + 1
            );
        },
    );
    assert_eq!(admitted.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        admitted.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn topology_input_quote_covers_concrete_validation_and_json_factory_heap() {
    // This thread-local window tracks all allocations created inside it; source
    // DTOs are borrowed so their preexisting deallocation is outside the census.
    for count in [1usize, 3, 48, 1024] {
        let mut source = topology(count);
        for endpoint in [
            "https://node.invalid/",
            "https://BÜCHER.invalid/",
            "https://\u{fdfa}.invalid/",
            "not a URL",
        ] {
            source.nodes.get_mut(&1).unwrap().endpoint = endpoint.into();
            let (quoted, live, peak, allocations) = measure_topology_input(|| quote(&source, 8192));
            assert_eq!((live, peak, allocations), (0, 0, 0));
            let quoted = quoted.unwrap();
            let (_, live, peak, _) = measure_topology_input(|| {
                if source.validate().is_ok() {
                    let body = serde_json::to_value(&source).unwrap();
                    let operation = Operation::Mutate(MutationBatch {
                        read_set: vec![],
                        idempotency_key: "k".repeat(8192),
                        operations: vec![Mutation::Put {
                            collection: "topology".into(),
                            id: "current".into(),
                            body,
                            expected: Precondition::Absent,
                        }],
                    });
                    drop(operation);
                }
            });
            assert_eq!(live, 0, "census lost a produced allocation lifetime");
            assert!(
                peak as u64 <= quoted.peak,
                "{count}: {peak} > {}",
                quoted.peak
            );
        }
    }
    assert!(backing(usize::MAX).is_err());
    assert!(tree::<String, Value>(usize::MAX).is_err());
}

#[test]
fn topology_input_validation_failures_preserve_canonical_error_and_release_payload() {
    let node = node(32 << 20);
    for (mut source, expected, message) in [
        (
            topology(1),
            Precondition::Any,
            "control updates require an explicit CAS precondition",
        ),
        (
            topology(1),
            Precondition::Absent,
            "invalid tenant incarnation",
        ),
    ] {
        if !matches!(expected, Precondition::Any) {
            source.tenants.get_mut("tenant").unwrap().incarnation = "bad".into();
        }
        let before = node.snapshot();
        let error = OperationInput::topology(&node, source, expected, "key")
            .err()
            .unwrap();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.message, message);
        assert_eq!(node.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(node.snapshot().live_reservations, before.live_reservations);
        // Returned Error String accounting is an existing separate corridor;
        // this grant proves only construction scratch and original JSON death.
    }
}
