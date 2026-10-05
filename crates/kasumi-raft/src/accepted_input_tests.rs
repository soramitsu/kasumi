use super::*;
use crate::selected_application::allocation_tests;
use kasumi_store::test_utils::TestDiskMemory;
use std::sync::atomic::{AtomicUsize, Ordering};

struct OriginalCharge {
    control: Arc<allocation_tests::DeallocationObservation>,
    refunds: Arc<AtomicUsize>,
    // The test observes this SAME real provider lease; the wrappers' exact
    // layouts were included prospectively before either allocation.
    _original: DiskMemoryLease,
}
impl Drop for OriginalCharge {
    fn drop(&mut self) {
        assert!(
            self.control.finished(),
            "actual input control must be deallocated before original refund"
        );
        assert_eq!(self.refunds.fetch_add(1, Ordering::SeqCst), 0);
    }
}

#[test]
fn admitted_input_aliases_keep_same_actual_grant_until_control_is_deallocated() -> anyhow::Result<()>
{
    let memory = TestDiskMemory::new(1 << 20, 32);
    let baseline = memory.snapshot();
    let requirements = ApplicationInputRequirements::for_capacity(8192);
    let original = memory
        .clone()
        .reserve_installed(requirements.with_token::<OriginalCharge>()?)?;
    let charged = memory.snapshot();
    let mut bytes = Vec::with_capacity(8192);
    bytes.resize(8192, 0x41);
    let address = bytes.as_ptr();
    let control = Arc::new(allocation_tests::DeallocationObservation::new(true));
    let refunds = Arc::new(AtomicUsize::new(0));
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let mut install = ApplicationInputInstall::new(bytes, provider.clone());
    let permit = install.try_bind(&provider).expect("same original provider");
    let (_, control_address, allocations) = allocation_tests::observe_last_allocation(|| {
        permit.bind(OriginalCharge {
            control: control.clone(),
            refunds: refunds.clone(),
            _original: original,
        });
    });
    assert_eq!(allocations, 2, "exact original token Box and input Arc");
    let input = install.finish().ok().expect("original input installed");
    assert_eq!(input.as_bytes().as_ptr(), address);
    let aliases = (0..8)
        .map(|_| allocation_tests::require_no_allocations(|| input.clone()))
        .collect::<Vec<_>>();
    drop(input);
    let barrier = Arc::new(std::sync::Barrier::new(aliases.len()));
    std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for input in aliases {
            let barrier = barrier.clone();
            let control = &control;
            threads.push(scope.spawn(move || {
                barrier.wait();
                allocation_tests::observe_deallocation(control_address, control, || drop(input));
            }));
        }
        // Declared after the handles: unwind releases the exact pause before
        // thread::scope waits for those real worker deallocations to finish.
        struct Release<'a>(&'a allocation_tests::DeallocationObservation);
        impl Drop for Release<'_> {
            fn drop(&mut self) {
                self.0.release();
            }
        }
        let release = Release(&control);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !control.entered() && std::time::Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert!(control.entered());
        assert!(!control.finished());
        assert_eq!(refunds.load(Ordering::SeqCst), 0);
        assert_eq!(memory.snapshot().used_bytes, charged.used_bytes);
        drop(release);
        for thread in threads {
            thread.join().unwrap();
        }
    });
    assert!(control.finished());
    assert_eq!(control.count(), 1);
    assert_eq!(refunds.load(Ordering::SeqCst), 1);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    Ok(())
}

#[test]
fn foreign_input_provider_refuses_before_token_or_shared_control_allocation() {
    let memory = TestDiskMemory::new(1 << 20, 32);
    let foreign = TestDiskMemory::new(1 << 20, 32);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory;
    let other: Arc<dyn NodeDiskMemoryAdmission> = foreign;
    let bytes = vec![0x53; 128];
    let address = bytes.as_ptr();
    let mut install = ApplicationInputInstall::new(bytes, provider.clone());
    allocation_tests::require_no_allocations(|| {
        assert!(matches!(
            install.try_bind(&other),
            Err(InputBindingError::Foreign)
        ));
        assert_eq!(install.bytes.as_ref().unwrap().as_ptr(), address);
        assert!(install.installed.is_none());
    });
}

#[test]
fn exact_input_loan_requires_original_provider_body_and_assigned_log_id() -> anyhow::Result<()> {
    let memory = TestDiskMemory::new(1 << 20, 32);
    let baseline = memory.snapshot();
    let requirements = ApplicationInputRequirements::for_capacity(128);
    let original = memory
        .clone()
        .reserve_installed(requirements.with_token::<DiskMemoryLease>()?)?;
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let mut bytes = Vec::with_capacity(128);
    bytes.resize(128, 0x26);
    let mut install = ApplicationInputInstall::new(bytes, provider.clone());
    install.try_bind(&provider).unwrap().bind(original);
    let input = install.finish().ok().unwrap();
    let id = openraft::LogId::new(openraft::CommittedLeaderId::new(3, 7), 11);
    let wrong = openraft::LogId::new(openraft::CommittedLeaderId::new(3, 7), 12);
    let other: Arc<dyn NodeDiskMemoryAdmission> = TestDiskMemory::new(1 << 20, 32);
    let loan = allocation_tests::require_no_allocations(|| {
        assert!(matches!(input.loan(id), Err(InputBindingError::Foreign)));
        input.bind(id).unwrap();
        input.bind(id).unwrap();
        assert_eq!(input.bind(wrong), Err(InputBindingError::Foreign));
        let loan = input.loan(id).unwrap();
        loan.require_memory(&provider).unwrap();
        assert_eq!(loan.require_memory(&other), Err(InputBindingError::Foreign));
        loan.require_bytes(id, &[0x26; 128]).unwrap();
        assert_eq!(
            loan.require_bytes(wrong, &[0x26; 128]),
            Err(InputBindingError::Foreign)
        );
        assert_eq!(
            loan.require_bytes(id, &[0x72; 128]),
            Err(InputBindingError::Foreign)
        );
        loan
    });
    drop(input);
    assert!(memory.snapshot().used_bytes > baseline.used_bytes);
    drop(loan);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    // A decoded ingress value has no accepted-input certificate in this stage.
    let ingress = crate::ApplicationPayload::ingress(vec![0x26; 128]);
    assert!(ingress.input_loan(id)?.is_none());
    Ok(())
}

fn mutation_targets() -> kasumi_types::MutationBatch {
    use kasumi_types::{Mutation, Precondition};
    kasumi_types::MutationBatch {
        idempotency_key: "targets".into(),
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
            Mutation::Patch {
                collection: "other".into(),
                id: "later".into(),
                patch: serde_json::json!({"v":2}),
                expected: Precondition::Any,
            },
        ],
    }
}

#[test]
fn mutation_change_tree_claim_keeps_exact_original_and_rejects_foreign_transcripts_and_reentry()
-> anyhow::Result<()> {
    let batch = mutation_targets();
    let mut reordered = batch.clone();
    reordered.operations.swap(0, 1);
    let mut fewer = batch.clone();
    fewer.operations.remove(1);
    let mut mode = batch.clone();
    mode.operations[0] = kasumi_types::Mutation::Delete {
        collection: "docs".into(),
        id: "same".into(),
        expected: kasumi_types::Precondition::Any,
    };
    let memory = TestDiskMemory::new(1 << 20, 32);
    let baseline = memory.snapshot();
    let requirements = allocation_tests::require_no_allocations(|| {
        ApplicationInputRequirements::for_capacity(256).with_mutation_change_tree(&batch)
    })
    .unwrap();
    assert!(requirements.mutation_change_tree_bytes().unwrap() > 0);
    let original = memory
        .clone()
        .reserve_installed(requirements.with_token::<DiskMemoryLease>()?)?;
    let charged = memory.snapshot();
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let bytes = vec![0x41; 256];
    let address = bytes.as_ptr();
    let mut install = ApplicationInputInstall::new(bytes, provider.clone());
    allocation_tests::require_no_allocations(|| install.prepare_mutation_change_tree(&batch))
        .unwrap();
    install.try_bind(&provider).unwrap().bind(original);
    let input = install.finish().ok().unwrap();
    let id = openraft::LogId::new(openraft::CommittedLeaderId::new(3, 7), 11);
    let wrong = openraft::LogId::new(openraft::CommittedLeaderId::new(3, 7), 12);
    let foreign: Arc<dyn NodeDiskMemoryAdmission> = TestDiskMemory::new(1 << 20, 32);
    let retained = allocation_tests::require_no_allocations(|| {
        assert!(matches!(
            input.claim_mutation_change_tree(id, &batch),
            Err(InputBindingError::Foreign)
        ));
        input.bind(id).unwrap();
        let loan = input.loan(id).unwrap();
        assert_eq!(
            loan.require_memory(&foreign),
            Err(InputBindingError::Foreign)
        );
        loan.require_memory(&provider).unwrap();
        loan.require_bytes(id, &[0x41; 256]).unwrap();
        assert!(matches!(
            input.claim_mutation_change_tree(wrong, &batch),
            Err(InputBindingError::Foreign)
        ));
        for different in [&reordered, &fewer, &mode] {
            assert!(matches!(
                input.claim_mutation_change_tree(id, different),
                Err(InputBindingError::Foreign)
            ));
        }
        let retained = input
            .claim_mutation_change_tree(id, &batch)
            .unwrap()
            .expect("known leader recipe");
        assert!(matches!(
            input.claim_mutation_change_tree(id, &batch),
            Err(InputBindingError::Repeated)
        ));
        retained
    });
    assert_eq!(input.as_bytes().as_ptr(), address);
    assert_eq!(memory.snapshot().used_bytes, charged.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        charged.live_reservations
    );
    drop(input);
    assert_eq!(memory.snapshot().used_bytes, charged.used_bytes);
    drop(retained);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    Ok(())
}

#[test]
fn concurrent_mutation_change_tree_claim_has_exactly_one_original_grant_owner() -> anyhow::Result<()>
{
    let batch = mutation_targets();
    let memory = TestDiskMemory::new(1 << 20, 32);
    let baseline = memory.snapshot();
    let requirements =
        ApplicationInputRequirements::for_capacity(128).with_mutation_change_tree(&batch)?;
    let original = memory
        .clone()
        .reserve_installed(requirements.with_token::<DiskMemoryLease>()?)?;
    let charged = memory.snapshot();
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let mut install = ApplicationInputInstall::new(vec![0x46; 128], provider.clone());
    install.prepare_mutation_change_tree(&batch).unwrap();
    install.try_bind(&provider).unwrap().bind(original);
    let input = install.finish().ok().unwrap();
    let id = openraft::LogId::new(openraft::CommittedLeaderId::new(3, 7), 11);
    input.bind(id).unwrap();
    let barrier = std::sync::Barrier::new(8);
    let results = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let input = &input;
                let batch = &batch;
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    allocation_tests::require_no_allocations(|| {
                        input.claim_mutation_change_tree(id, batch)
                    })
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(Some(_))))
            .count(),
        1
    );
    for result in &results {
        if let Err(error) = result {
            assert_eq!(*error, InputBindingError::Repeated);
        }
    }
    drop(input);
    assert_eq!(memory.snapshot().used_bytes, charged.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        charged.live_reservations
    );
    drop(results);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    Ok(())
}
