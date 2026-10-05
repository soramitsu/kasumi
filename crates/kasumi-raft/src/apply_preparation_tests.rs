//! Actual scratch originals through the production prepaid apply carrier.
use super::*;
use crate::selected_application::allocation_tests::require_no_allocations;
use kasumi_store::{
    DiskMemoryLease, EncryptedTable, NodeDiskMemoryAdmission, ScratchAdmissionRefusal,
    ScratchCreationFailure, ScratchDisk, ScratchOperationFailure, StorageCensusDisposition,
    test_utils::TestDiskMemory,
};
use std::os::unix::fs::PermissionsExt;

fn charge(memory: &Arc<TestDiskMemory>, bytes: u64) -> kasumi_types::SharedBudgetCharge {
    let bytes = bytes
        .checked_add(kasumi_types::SharedBudgetCharge::required_bytes::<DiskMemoryLease>().unwrap())
        .unwrap();
    kasumi_types::SharedBudgetCharge::new(memory.clone().reserve_installed(bytes).unwrap())
}

fn paid_owner(
    memory: &Arc<TestDiskMemory>,
) -> (crate::apply_failure::ApplyFailureSlot, Arc<Control>) {
    let (fixture_slot, control) = owner();
    drop(fixture_slot);
    let slot = crate::apply_failure::ApplyFailureSlot::new(charge(
        memory,
        crate::apply_failure::ApplyFailureSlot::required_bytes(),
    ));
    assert!(
        slot.completion()
            .bind(CompletionBinding::new(Binding(control.clone())))
            .is_ok()
    );
    (slot, control)
}
fn directory_refusal(
    disk: &Arc<ScratchDisk>,
    directory: &std::path::Path,
) -> ScratchCreationFailure {
    let permissions = std::fs::metadata(directory).unwrap().permissions();
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    let original = EncryptedTable::new(disk, 8 << 20, kasumi_kv::CacheConfig { byte_limit: 0 })
        .err()
        .expect("actual unsafe-directory creation must fail");
    std::fs::set_permissions(directory, permissions).unwrap();
    assert!(original.owner_id().is_some());
    original
}
fn original_address(original: &ScratchCreationFailure) -> usize {
    original.with_diagnostic(|report| {
        std::ptr::from_ref(report.unwrap().admission_error().unwrap()) as usize
    })
}
struct FailedSink(Option<anyhow::Error>);
impl PublicationSink for FailedSink {
    fn plain(&mut self, _: &AppliedResponse, _: &[WriteOp]) -> SinkResult<()> {
        Err(self.0.take().unwrap().into())
    }
    fn selected<'call>(
        &mut self,
        _: &AppliedResponse,
        _: &[WriteOp],
        _: &mut dyn SelectionPreparer,
        _: PublicationChallenge<'call>,
    ) -> SinkResult<JointPublicationReceipt<'call>> {
        panic!("plain preparation fixture")
    }
}

#[test]
fn preparation_original_and_independent_sink_error_survive_returned_facade_drop() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let baseline = memory.snapshot();
    let (slot, _) = paid_owner(&memory);
    let original = directory_refusal(&disk, directory.path());
    let id = original.owner_id().unwrap();
    let address = original_address(&original);
    let sink_error: anyhow::Error = Original(101).into();
    let sink_address = sink_error.downcast_ref::<Original>().unwrap() as *const _;
    let mut sink = FailedSink(Some(sink_error));
    let mut publication = ApplyPublication::new_bound(&mut sink, &slot);
    assert_eq!(
        publication.commit(AppliedResponse::application(vec![103]), &[]),
        Err(PublishCallError::Failed)
    );
    let returned = require_no_allocations(|| {
        failed(publication.finish_observed(Ok(Err(original.into())), || {}))
    });
    drop(returned);
    for _ in 0..3 {
        require_no_allocations(|| {
            slot.failure()
                .unwrap()
                .try_with_report(|report| {
                    let RetainedApplyReport::Preparation {
                        original,
                        publication,
                        response,
                        violation,
                    } = report
                    else {
                        panic!("actual preparation original")
                    };
                    assert_eq!(original.creation().unwrap().owner_id(), Some(id));
                    assert_eq!(original_address(original.creation().unwrap()), address);
                    assert_eq!(
                        publication.unwrap().downcast_ref::<Original>().unwrap() as *const _,
                        sink_address
                    );
                    assert!(response.is_none());
                    assert!(violation.is_none());
                })
                .unwrap();
        });
    }
    assert!(!slot.failure_ownership_drained());
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let retirement = ScratchCreationFailure::retained(provider, id)
        .unwrap()
        .retire();
    assert_eq!(retirement.disposition(), StorageCensusDisposition::Retained);
    drop(slot);
    assert_eq!(retirement.retry(), StorageCensusDisposition::Retired);
    drop(retirement);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}

struct FailingAction {
    original: Option<ScratchOperationFailure>,
    response: Option<AppliedResponse>,
}
impl CompletionAction for FailingAction {
    fn run(
        &mut self,
        _: &CompletionInvocation<'_>,
        publisher: &mut dyn ApplyPublisher,
    ) -> Result<(), ScratchOperationFailure> {
        publisher.commit(self.response.take().unwrap(), &[])?;
        Err(self.original.take().unwrap())
    }
}

#[test]
fn creation_after_committed_completion_retains_original_and_response_without_retirement_proof() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let baseline = memory.snapshot();
    let (slot, control) = paid_owner(&memory);
    let original = directory_refusal(&disk, directory.path());
    let id = original.owner_id().unwrap();
    let address = original_address(&original);
    let response = AppliedResponse::application(vec![107, 109]);
    let response_address = response.data.as_ptr();
    let mut action = FailingAction {
        original: Some(original.into()),
        response: Some(response),
    };
    let mut sink = SinkCount(0);
    let mut publication = ApplyPublication::new_bound(&mut sink, &slot);
    assert_eq!(
        publication.with_completion(&control.identity, &mut action),
        Err(crate::CompletionCallError::Recorded)
    );
    drop(failed(publication.finish_observed(Ok(Ok(())), || {})));
    assert_eq!(sink.0, 1);
    let mut context = Context::from_waker(Waker::noop());
    assert!(slot.completion().poll_drain(&mut context).is_ready());
    assert!(control.drained.load(Ordering::SeqCst));
    for _ in 0..3 {
        slot.failure()
            .unwrap()
            .try_with_report(|report| {
                let RetainedApplyReport::Ordinary(report) = report else {
                    panic!("completion")
                };
                let O::Creation(original) = report.action else {
                    panic!("actual creation")
                };
                assert_eq!(original.owner_id(), Some(id));
                assert_eq!(original_address(original), address);
                assert_eq!(report.response.unwrap().data.as_ptr(), response_address);
                assert_eq!(report.response.unwrap().data, [107, 109]);
                assert!(matches!(report.sink, O::Returned));
                assert!(matches!(report.backend, O::Returned));
                assert!(matches!(report.drain, O::Returned));
                assert!(!report.custody_guards.action_error_retired);
            })
            .unwrap();
    }
    assert!(!slot.failure_ownership_drained());
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let retirement = ScratchCreationFailure::retained(provider, id)
        .unwrap()
        .retire();
    assert_eq!(retirement.disposition(), StorageCensusDisposition::Retained);
    drop(slot);
    assert_eq!(retirement.retry(), StorageCensusDisposition::Retired);
    drop(retirement);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[tokio::test]
async fn admitted_owner_maps_busy_and_sealed_inventory_without_allocating() {
    let memory = TestDiskMemory::new(64 << 20, 32);
    let baseline = memory.snapshot();
    let owner = crate::SnapshotBufferOwner::new(
        2,
        charge(
            &memory,
            crate::SnapshotBufferOwner::required_bytes(2).unwrap(),
        ),
    )
    .unwrap();
    let first = require_no_allocations(|| owner.scratch_failure_guard().unwrap());
    let second = require_no_allocations(|| owner.scratch_failure_guard().unwrap());
    let before = memory.snapshot();
    assert!(matches!(
        require_no_allocations(|| owner.scratch_failure_guard()),
        Err(ScratchOperationFailure::AdmissionRefused(
            ScratchAdmissionRefusal::Busy
        ))
    ));
    assert_eq!(memory.snapshot(), before);
    drop(first);
    drop(second);
    owner.drain_buffers().await.unwrap();
    let before = memory.snapshot();
    assert!(matches!(
        require_no_allocations(|| owner.scratch_failure_guard()),
        Err(ScratchOperationFailure::AdmissionRefused(
            ScratchAdmissionRefusal::Sealed
        ))
    ));
    assert_eq!(memory.snapshot(), before);
    drop(owner);
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}
