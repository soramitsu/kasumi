//! Actual batch_changes production and its same original input grant. These
//! tests certify only this producer; fixture LogId assignment is not a commit,
//! selected-source, complete candidate or serving-capacity certificate.
use super::*;
use crate::{
    admission::{AdmissionConfig, NodeAdmission, ProposalBudget},
    document_pool::allocation_tests::{check_mutation_change_tree_drop, measure_topology_input},
};
use kasumi_raft::{
    AdmittedApplicationInput, ApplicationInputInstall, ApplicationInputRequirements,
};

fn node() -> Arc<NodeAdmission> {
    NodeAdmission::with_fixed_memory(
        AdmissionConfig {
            high_water_bytes: Some(16 << 20),
            low_water_bytes: Some(14 << 20),
            max_inflight_bytes: Some(8 << 20),
            ..AdmissionConfig::default()
        },
        32 << 20,
        0,
    )
    .unwrap()
}
fn batch(count: usize, groups: usize, duplicate: bool) -> MutationBatch {
    MutationBatch {
        idempotency_key: "target-tree".into(),
        read_set: vec![],
        operations: (0..count)
            .map(|index| {
                let collection = format!("collection_{}", index % groups.max(1));
                let id = if duplicate {
                    "same".into()
                } else {
                    format!("document_{index:06}_{}", "x".repeat(index % 97))
                };
                match index % 3 {
                    0 => Mutation::Put {
                        collection,
                        id,
                        body: json!({"v":index}),
                        expected: Precondition::Any,
                    },
                    1 => Mutation::Patch {
                        collection,
                        id,
                        patch: json!({"v":index}),
                        expected: Precondition::Any,
                    },
                    _ => Mutation::Delete {
                        collection,
                        id,
                        expected: Precondition::Any,
                    },
                }
            })
            .collect(),
    }
}
// Count, reserve, then encode, matching the immutable original producer order.
fn admitted(
    node: &Arc<NodeAdmission>,
    command: &Command,
    log_id: openraft::LogId<u64>,
) -> (AdmittedApplicationInput, ProposalBudget) {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or(std::io::ErrorKind::InvalidInput)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, command).unwrap();
    let Operation::Mutate(batch) = &command.operation else {
        panic!("actual mutation input")
    };
    let requirements = ApplicationInputRequirements::for_capacity(count.0)
        .with_mutation_change_tree(batch)
        .unwrap();
    let budget = ProposalBudget::new(
        node.reserve(
            requirements.with_token::<ProposalBudget>().unwrap()
                + ProposalBudget::required_bytes().unwrap(),
            None,
        )
        .unwrap(),
    );
    let mut bytes = Vec::with_capacity(count.0);
    serde_json::to_writer(&mut bytes, command).unwrap();
    assert_eq!(bytes.capacity(), count.0);
    let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = node.memory().clone();
    let mut install = ApplicationInputInstall::new(bytes, memory);
    install.prepare_mutation_change_tree(batch).unwrap();
    node.memory()
        .bind_application_input(&budget, &mut install)
        .unwrap();
    let input = install.finish().ok().unwrap();
    input.bind_fixture_log_id(log_id).unwrap();
    (input, budget)
}
fn log_id(revision: u64) -> openraft::LogId<u64> {
    openraft::LogId::new(openraft::CommittedLeaderId::new(3, 7), revision)
}

#[test]
fn mutation_change_tree_quote_covers_the_actual_duplicate_and_split_builder() {
    for count in [0, 1, 2, 11, 12, 63, 128, 256] {
        for (groups, duplicate) in [(1, false), (13, false), (13, true), (count.max(1), true)] {
            let batch = batch(count, groups, duplicate);
            let (requirements, live, peak, allocations) = measure_topology_input(|| {
                ApplicationInputRequirements::for_capacity(0).with_mutation_change_tree(&batch)
            });
            assert_eq!(
                (live, peak, allocations),
                (0, 0, 0),
                "quote must remain borrowed and allocation-free"
            );
            let quoted = requirements.unwrap().mutation_change_tree_bytes().unwrap();
            let (_, live, peak, allocations) = measure_topology_input(|| {
                let produced = crate::state::batch_changes(&batch);
                assert!(produced.values().all(|ids| !ids.is_empty()));
                drop(produced);
            });
            assert_eq!(live, 0, "actual producer backing escaped its observation");
            assert!(
                peak as u64 <= quoted,
                "count={count},groups={groups},duplicate={duplicate}: actual {peak},quote {quoted}"
            );
            assert_eq!(allocations == 0, count == 0);
        }
    }
}

#[test]
fn actual_mutation_tree_backing_dies_before_its_original_proposal_fee() {
    let fixture = Fixture::new();
    fixture.create(false);
    let node = node();
    let baseline = node.snapshot();
    let operation = Operation::Mutate(MutationBatch {
        idempotency_key: "actual-tree".into(),
        read_set: vec![],
        operations: vec![Mutation::Put {
            collection: "docs".into(),
            id: "watched".into(),
            body: json!({"v":1}),
            expected: Precondition::Any,
        }],
    });
    let command = fixture.command(2, operation);
    let id = log_id(2);
    let (input, budget) = admitted(&node, &command, id);
    let charged = node.snapshot();
    let mut owner = fixture.lock();
    owner.retain_input(Some(input), id);
    drop(budget);
    let applied = crate::staged_terminal::AppliedIdentity {
        incarnation: fixture.engine.incarnation.clone(),
        revision: 2,
        timestamp_ms: command.timestamp_ms,
        command_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&command).unwrap())),
        origin: crate::staged_terminal::AppliedOrigin::Fixture,
    };
    let prepared = fixture
        .engine
        .prepare_command_ordered(
            &owner,
            &command,
            &applied,
            &ApplyScope::Fixture(fixture.disk.clone()),
        )
        .unwrap();
    assert!(owner._mutation_change_tree.get().is_some());
    assert!(prepared.outcome.is_ok());
    let candidate = prepared.generation.unwrap();
    drop(prepared.outcome);
    let accepted = owner.accept(candidate, prepared.changed).unwrap();
    let address = accepted.delta.changed["docs"]
        .iter()
        .next()
        .unwrap()
        .as_ptr() as usize;
    let observe = node.clone();
    check_mutation_change_tree_drop(
        address,
        || drop(accepted),
        move || {
            assert_eq!(observe.snapshot().reserved_bytes, charged.reserved_bytes);
            assert_eq!(
                observe.snapshot().live_reservations,
                charged.live_reservations
            );
        },
    );
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn rejected_partial_batch_keeps_exact_delta_scoped_and_idempotent_replay_mints_none() {
    let fixture = Fixture::new();
    fixture.create(false);
    let node = node();
    let baseline = node.snapshot();
    let rejected = Operation::Mutate(MutationBatch {
        idempotency_key: "partial".into(),
        read_set: vec![],
        operations: vec![
            Mutation::Put {
                collection: "docs".into(),
                id: "first".into(),
                body: json!({"v":1}),
                expected: Precondition::Any,
            },
            Mutation::Put {
                collection: "missing".into(),
                id: "second".into(),
                body: json!({"v":2}),
                expected: Precondition::Any,
            },
        ],
    });
    let command = fixture.command(2, rejected.clone());
    let id = log_id(2);
    let (input, budget) = admitted(&node, &command, id);
    let mut owner = fixture.lock();
    owner.retain_input(Some(input), id);
    drop(budget);
    let prepared = fixture.prepare(&owner, 2, rejected);
    assert_eq!(
        prepared.outcome.as_ref().unwrap_err().code,
        ErrorCode::NotFound
    );
    assert!(prepared.changed.is_empty());
    assert!(owner._mutation_change_tree.get().is_some());
    assert!(
        fixture.engine.generation().unwrap().state.collections["docs"]
            .documents
            .is_empty()
    );
    drop(prepared);
    drop(owner);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );

    fixture.put(2, "replayed");
    let command = fixture.command(3, mutation("replayed", Precondition::Any));
    let id = log_id(3);
    let (input, budget) = admitted(&node, &command, id);
    let mut owner = fixture.lock();
    owner.retain_input(Some(input), id);
    drop(budget);
    let prepared = fixture.prepare(&owner, 3, command.operation);
    assert!(prepared.outcome.is_ok());
    assert!(prepared.changed.is_empty());
    assert!(
        owner._mutation_change_tree.get().is_none(),
        "receipt replay must not mint change-tree producer authority"
    );
    drop(prepared);
    drop(owner);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}
