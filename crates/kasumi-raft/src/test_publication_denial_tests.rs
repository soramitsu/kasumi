use super::*;
use crate::selected_application::allocation_tests::require_no_allocations;
use kasumi_store::ScratchAdmissionRefusal;
use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Debug)]
struct OriginalSinkError(Arc<AtomicUsize>);
impl fmt::Display for OriginalSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("original publication error")
    }
}
impl std::error::Error for OriginalSinkError {}
impl Drop for OriginalSinkError {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn inline_denial_keeps_actual_sink_or_response_and_violation_without_allocation() {
    for original in [
        ScratchAdmissionRefusal::Busy,
        ScratchAdmissionRefusal::Sealed,
    ] {
        for sink_failed in [false, true] {
            for repeated in [false, true] {
                let drops = Arc::new(AtomicUsize::new(0));
                let mut sink_error = Some(anyhow::Error::new(OriginalSinkError(drops.clone())));
                let error_address = std::ptr::from_ref(
                    sink_error
                        .as_ref()
                        .unwrap()
                        .downcast_ref::<OriginalSinkError>()
                        .unwrap(),
                );
                let response = AppliedResponse::application(vec![37, 41, 43]);
                let response_address = response.data.as_ptr();
                let calls = Cell::new(0);
                let mut sink = |_: &AppliedResponse, _: &[WriteOp]| -> Result<()> {
                    calls.set(calls.get() + 1);
                    if sink_failed {
                        Err(sink_error.take().unwrap())
                    } else {
                        Ok(())
                    }
                };
                let mut publication = ApplyPublication::new(&mut sink);
                assert_eq!(
                    publication.commit(response, &[]),
                    if sink_failed {
                        Err(PublishCallError::Failed)
                    } else {
                        Ok(())
                    },
                );
                if repeated {
                    assert_eq!(
                        publication.commit(AppliedResponse::application(Vec::new()), &[]),
                        Err(PublishCallError::Repeated),
                    );
                }
                let returned = require_no_allocations(|| {
                    ScratchOperationFailure::finish(
                        TestPublicationState(publication),
                        Err(ScratchOperationFailure::AdmissionRefused(original)),
                    )
                })
                .err()
                .expect("fixture invocation unexpectedly succeeded");
                assert_eq!(returned.admission_refusal(), Some(original));
                assert!(returned.operation_error().is_none());
                assert!(returned.creation().is_none());
                assert_eq!(
                    returned.preparation_error().unwrap().admission_refusal(),
                    Some(original)
                );
                let TestPublicationFailure::Preparation {
                    original: retained,
                    publication,
                    response,
                    violation,
                    capture,
                } = returned
                else {
                    panic!("the original refusal and independent sink state must stay whole");
                };
                assert_eq!(retained.admission_refusal(), Some(original));
                assert!(capture.is_none());
                assert_eq!(
                    violation,
                    repeated.then_some(crate::CompletionViolation::Repeated)
                );
                assert_eq!(calls.get(), 1);
                if sink_failed {
                    assert!(response.is_none());
                    let publication = publication.unwrap();
                    assert_eq!(
                        std::ptr::from_ref(
                            publication.downcast_ref::<OriginalSinkError>().unwrap()
                        ),
                        error_address,
                    );
                    assert_eq!(drops.load(Ordering::Acquire), 0);
                    drop(publication);
                    assert_eq!(drops.load(Ordering::Acquire), 1);
                } else {
                    assert!(publication.is_none());
                    assert_eq!(response.unwrap().data.as_ptr(), response_address);
                    assert_eq!(drops.load(Ordering::Acquire), 0);
                    drop(sink_error);
                    assert_eq!(drops.load(Ordering::Acquire), 1);
                }
            }
        }
    }
}
