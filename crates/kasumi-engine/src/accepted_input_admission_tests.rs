use super::*;
use crate::admission::{AdmissionConfig, NodeAdmission, ProposalBudget};
use crate::primary_tree::tests::AllocationGuard;
use kasumi_raft::{ApplicationInputInstall, ApplicationInputRequirements, InputBindingError};
use kasumi_types::{Mutation, MutationBatch, Precondition};

fn admission() -> Arc<NodeAdmission> {
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

#[test]
fn original_proposal_reservation_moves_once_without_new_grant_or_clone_allocation() {
    let admission = admission();
    let baseline = admission.snapshot();
    let requirements = ApplicationInputRequirements::for_capacity(4096);
    let original = ProposalBudget::new(
        admission
            .reserve(
                requirements.with_token::<ProposalBudget>().unwrap()
                    + ProposalBudget::required_bytes().unwrap(),
                None,
            )
            .unwrap(),
    );
    let charged = admission.snapshot();
    let mut bytes = Vec::with_capacity(4096);
    bytes.resize(4096, 0x73);
    let address = bytes.as_ptr();
    let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = admission.memory().clone();
    let mut install = ApplicationInputInstall::new(bytes, memory);
    let guard = AllocationGuard::begin();
    admission
        .memory()
        .bind_application_input(&original, &mut install)
        .unwrap();
    assert_eq!(
        guard.finish(),
        2,
        "one original budget alias Box and one exact input control"
    );

    let input = install
        .finish()
        .ok()
        .expect("exact original input installed");
    assert_eq!(input.as_bytes().as_ptr(), address);
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        charged.live_reservations
    );
    let guard = AllocationGuard::begin();
    let retained = input.clone();
    assert_eq!(guard.finish(), 0);
    drop(input);
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    drop(retained);
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    drop(original);
    assert_eq!(admission.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn insufficient_original_credit_keeps_original_slot_and_buffer_without_allocating() {
    let admission = admission();
    let original = ProposalBudget::new(
        admission
            .reserve(ProposalBudget::required_bytes().unwrap(), None)
            .unwrap(),
    );
    let charged = admission.snapshot();
    let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = admission.memory().clone();
    let bytes = vec![0x21; 4096];
    let address = bytes.as_ptr();
    let mut install = ApplicationInputInstall::new(bytes, memory);
    let guard = AllocationGuard::begin();
    assert_eq!(
        admission
            .memory()
            .bind_application_input(&original, &mut install),
        Err(InputBindingError::Insufficient)
    );
    assert_eq!(guard.finish(), 0);

    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        charged.live_reservations
    );
    assert_eq!(install.pending_bytes().unwrap().as_ptr(), address);
    // Install refuses before sharing or allocating any original token/control.
    let returned = install.finish().err().expect("not installed");
    drop(returned);
}

#[test]
fn foreign_original_memory_core_refuses_before_moving_the_actual_grant() {
    let first = admission();
    let second = admission();
    let requirements = ApplicationInputRequirements::for_capacity(128);
    let original = ProposalBudget::new(
        first
            .reserve(
                requirements.with_token::<ProposalBudget>().unwrap()
                    + ProposalBudget::required_bytes().unwrap(),
                None,
            )
            .unwrap(),
    );
    let before = first.snapshot();
    let foreign_before = second.snapshot();
    let provider: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = second.memory().clone();
    let bytes = vec![0x38; 128];
    let address = bytes.as_ptr();
    let mut install = ApplicationInputInstall::new(bytes, provider);
    let guard = AllocationGuard::begin();
    assert_eq!(
        second
            .memory()
            .bind_application_input(&original, &mut install),
        Err(InputBindingError::Foreign)
    );
    assert_eq!(guard.finish(), 0);

    assert_eq!(install.pending_bytes().unwrap().as_ptr(), address);
    assert_eq!(first.snapshot().reserved_bytes, before.reserved_bytes);
    assert_eq!(first.snapshot().live_reservations, before.live_reservations);
    assert_eq!(
        second.snapshot().reserved_bytes,
        foreign_before.reserved_bytes
    );
}

#[test]
fn accepted_original_budget_cannot_fund_a_second_control_or_grow_after_submission() {
    let admission = admission();
    let requirements = ApplicationInputRequirements::for_capacity(128);
    let budget = ProposalBudget::new(
        admission
            .reserve(
                requirements.with_token::<ProposalBudget>().unwrap()
                    + ProposalBudget::required_bytes().unwrap(),
                None,
            )
            .unwrap(),
    );
    let provider: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = admission.memory().clone();
    let mut first = ApplicationInputInstall::new(vec![0x17; 128], provider.clone());
    admission
        .memory()
        .bind_application_input(&budget, &mut first)
        .unwrap();
    let first = first.finish().ok().unwrap();
    let charged = admission.snapshot();
    let mut second = ApplicationInputInstall::new(vec![0x81; 128], provider);
    let address = second.pending_bytes().unwrap().as_ptr();
    let guard = AllocationGuard::begin();
    assert_eq!(
        admission
            .memory()
            .bind_application_input(&budget, &mut second),
        Err(InputBindingError::Repeated)
    );
    assert_eq!(guard.finish(), 0);
    assert_eq!(second.pending_bytes().unwrap().as_ptr(), address);
    assert_eq!(first.as_bytes(), &[0x17; 128]);
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().live_reservations,
        charged.live_reservations
    );
    assert!(budget.reserve_additional(1).is_err());
    budget.retain_workspace();
    assert_eq!(admission.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        admission.snapshot().inflight_operations,
        charged.inflight_operations - 1
    );
}

fn mutation_delta_batch() -> MutationBatch {
    MutationBatch {
        idempotency_key: "delta".into(),
        read_set: vec![],
        operations: vec![
            Mutation::Put {
                collection: "docs".into(),
                id: "same".into(),
                body: serde_json::json!({"v":1}),
                expected: Precondition::Any,
            },
            Mutation::Delete {
                collection: "docs".into(),
                id: "same".into(),
                expected: Precondition::Any,
            },
        ],
    }
}
#[test]
fn mutation_change_tree_minimum_checks_the_same_original_ledger_before_controls() {
    let node = admission();
    let batch = mutation_delta_batch();
    let baseline = node.snapshot();
    let requirements = ApplicationInputRequirements::for_capacity(128)
        .with_mutation_change_tree(&batch)
        .unwrap();
    let minimum = requirements.with_token::<ProposalBudget>().unwrap()
        + ProposalBudget::required_bytes().unwrap();
    let budget = ProposalBudget::new(node.reserve(minimum - 1, None).unwrap());
    let charged = node.snapshot();
    let provider: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = node.memory().clone();
    let mut install = ApplicationInputInstall::new(vec![0x74; 128], provider.clone());
    install.prepare_mutation_change_tree(&batch).unwrap();
    let address = install.pending_bytes().unwrap().as_ptr();
    let watch = AllocationGuard::begin();
    assert_eq!(
        node.memory().bind_application_input(&budget, &mut install),
        Err(InputBindingError::Insufficient)
    );
    assert_eq!(watch.finish(), 0);
    assert_eq!(install.pending_bytes().unwrap().as_ptr(), address);
    assert_eq!(node.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, charged.live_reservations);
    drop(install);
    drop(budget);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn mutation_change_tree_bind_transfers_one_original_without_grant_growth() {
    let node = admission();
    let batch = mutation_delta_batch();
    let baseline = node.snapshot();
    let requirements = ApplicationInputRequirements::for_capacity(128)
        .with_mutation_change_tree(&batch)
        .unwrap();
    let minimum = requirements.with_token::<ProposalBudget>().unwrap()
        + ProposalBudget::required_bytes().unwrap();
    let budget = ProposalBudget::new(node.reserve(minimum, None).unwrap());
    let charged = node.snapshot();
    let provider: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = node.memory().clone();
    let mut install = ApplicationInputInstall::new(vec![0x75; 128], provider.clone());
    install.prepare_mutation_change_tree(&batch).unwrap();
    let watch = AllocationGuard::begin();
    node.memory()
        .bind_application_input(&budget, &mut install)
        .unwrap();
    assert_eq!(watch.finish(), 2);
    let input = install.finish().ok().unwrap();
    assert_eq!(node.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(node.snapshot().live_reservations, charged.live_reservations);
    drop(budget);
    assert_eq!(node.snapshot().reserved_bytes, charged.reserved_bytes);
    drop(input);
    assert_eq!(node.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        node.snapshot().live_reservations,
        baseline.live_reservations
    );
}
