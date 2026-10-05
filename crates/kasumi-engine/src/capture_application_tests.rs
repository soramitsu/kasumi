use super::*;
use kasumi_raft::{AppliedResponse, CompletionViolation, PublishCallError, TestPublicationFailure};
use kasumi_store::{
    EncryptedTable, NodeDiskMemoryAdmission, ScratchAdmissionRefusal, ScratchDisk,
    ScratchOperationFailure, StorageCensusDisposition, test_utils::TestDiskMemory,
};

#[derive(Debug)]
struct OriginalCaptureError(u64);
impl std::fmt::Display for OriginalCaptureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "original capture {}", self.0)
    }
}
impl std::error::Error for OriginalCaptureError {}

#[test]
fn capture_static_ordinary_and_typed_operation_keep_the_exact_original_error() {
    let original = anyhow::Error::new(OriginalCaptureError(37));
    let address = std::ptr::from_ref(original.downcast_ref::<OriginalCaptureError>().unwrap());
    let result: anyhow::Result<AppliedResponse> =
        capture_application(|_| -> anyhow::Result<()> { Err(original) });
    let returned = result
        .err()
        .expect("fixture invocation unexpectedly succeeded");
    assert_eq!(
        std::ptr::from_ref(returned.downcast_ref::<OriginalCaptureError>().unwrap()),
        address
    );

    let original = anyhow::Error::new(OriginalCaptureError(41));
    let address = std::ptr::from_ref(original.downcast_ref::<OriginalCaptureError>().unwrap());
    let result = capture_application(|_| -> std::result::Result<(), ScratchOperationFailure> {
        Err(ScratchOperationFailure::Operation(original))
    });
    let returned = result
        .err()
        .expect("fixture invocation unexpectedly succeeded");
    assert!(returned.creation().is_none());
    assert_eq!(
        std::ptr::from_ref(
            returned
                .operation_error()
                .unwrap()
                .downcast_ref::<OriginalCaptureError>()
                .unwrap()
        ),
        address
    );
}

#[derive(Clone, Copy, Debug)]
enum CaptureMode {
    Ready,
    Committed,
    Repeated,
    Invalid,
}

fn actual_creation_handoff(mode: CaptureMode) {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let memory = TestDiskMemory::new(64 << 20, 32);
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let baseline = memory.snapshot();
    let original = EncryptedTable::new(&disk, u64::MAX, kasumi_kv::CacheConfig { byte_limit: 0 })
        .err()
        .expect("actual unrepresentable encrypted extent must be refused");
    let id = original.owner_id().unwrap();
    let address = original.with_diagnostic(|report| {
        let report = report.unwrap();
        let original = report.admission_error().unwrap();
        assert_eq!(original.kind(), std::io::ErrorKind::InvalidInput);
        assert!(report.opening_error().is_none());
        std::ptr::from_ref(original) as usize
    });
    let response = AppliedResponse::application(vec![13, 17, 19]);
    let response_address = response.data.as_ptr();
    let response_expected = matches!(mode, CaptureMode::Committed | CaptureMode::Repeated);
    let writes = [kasumi_store::WriteOp::delete("fixture", b"key")];
    let result = capture_application(
        |publisher| -> std::result::Result<(), ScratchOperationFailure> {
            match mode {
                CaptureMode::Ready => {}
                CaptureMode::Committed => {
                    publisher.commit(response, &[]).unwrap();
                }
                CaptureMode::Repeated => {
                    publisher.commit(response, &[]).unwrap();
                    assert_eq!(
                        publisher.commit(AppliedResponse::application(Vec::new()), &[]),
                        Err(PublishCallError::Repeated)
                    );
                }
                CaptureMode::Invalid => {
                    assert_eq!(
                        publisher.commit(response, &writes),
                        Err(PublishCallError::Failed)
                    );
                }
            }
            Err(ScratchOperationFailure::Creation(original))
        },
    );
    let returned = result
        .err()
        .expect("fixture invocation unexpectedly succeeded");
    let retained = memory.snapshot();
    let census = memory.storage_census();
    assert!((0..census.snapshot().capacity).any(|index| census.owner_at(index) == Some(id)));
    let crate::test_fixture_failure::FixtureFailure::Publication(returned) =
        crate::test_fixture_failure::FixtureFailure::from(returned)
    else {
        panic!("fixture join must keep the complete original publication owner");
    };
    let TestPublicationFailure::Preparation {
        original,
        publication,
        response,
        violation,
        capture,
    } = returned
    else {
        panic!("actual scratch creation must stay typed");
    };
    let ScratchOperationFailure::Creation(original) = original else {
        panic!("the original registered creation must remain whole");
    };
    assert_eq!(original.owner_id(), Some(id));
    assert_eq!(
        original.with_diagnostic(|report| {
            std::ptr::from_ref(report.unwrap().admission_error().unwrap()) as usize
        }),
        address
    );
    assert!(publication.is_none());
    assert_eq!(response.is_some(), response_expected);
    if let Some(response) = &response {
        assert_eq!(response.data.as_ptr(), response_address);
        assert_eq!(response.data, [13, 17, 19]);
    }
    let capture = capture.expect("original response-only capture state is retained");
    assert_eq!(capture.attempted, !matches!(mode, CaptureMode::Ready));
    assert_eq!(
        capture.invalid,
        matches!(mode, CaptureMode::Repeated | CaptureMode::Invalid)
    );
    assert_eq!(capture.repeated, matches!(mode, CaptureMode::Repeated));
    assert_eq!(
        violation,
        matches!(mode, CaptureMode::Repeated).then_some(CompletionViolation::Repeated)
    );
    assert_eq!(memory.snapshot(), retained);
    drop(response);
    assert_eq!(
        original.retire().disposition(),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[test]
fn capture_creation_after_commit_keeps_registered_original_and_exact_response() {
    actual_creation_handoff(CaptureMode::Committed);
}

#[test]
fn capture_creation_keeps_actual_missing_invalid_and_repeated_observations() {
    for mode in [
        CaptureMode::Ready,
        CaptureMode::Invalid,
        CaptureMode::Repeated,
    ] {
        actual_creation_handoff(mode);
    }
}

#[test]
fn capture_inline_admission_refusal_keeps_response_and_flags_without_allocating() {
    for original in [
        ScratchAdmissionRefusal::Busy,
        ScratchAdmissionRefusal::Sealed,
    ] {
        for mode in [
            CaptureMode::Ready,
            CaptureMode::Committed,
            CaptureMode::Repeated,
            CaptureMode::Invalid,
        ] {
            let response = AppliedResponse::application(vec![23, 29, 31]);
            let address = response.data.as_ptr();
            let writes = [kasumi_store::WriteOp::delete("fixture", b"key")];
            let counting = crate::primary_tree::tests::AllocationGuard::begin();
            let returned = capture_application(
                |publisher| -> std::result::Result<(), ScratchOperationFailure> {
                    match mode {
                        CaptureMode::Ready => {}
                        CaptureMode::Committed => publisher.commit(response, &[]).unwrap(),
                        CaptureMode::Repeated => {
                            publisher.commit(response, &[]).unwrap();
                            assert_eq!(
                                publisher.commit(AppliedResponse::application(Vec::new()), &[]),
                                Err(PublishCallError::Repeated),
                            );
                        }
                        CaptureMode::Invalid => {
                            assert_eq!(
                                publisher.commit(response, &writes),
                                Err(PublishCallError::Failed)
                            );
                        }
                    }
                    Err(ScratchOperationFailure::AdmissionRefused(original))
                },
            )
            .err()
            .expect("fixture invocation unexpectedly succeeded");
            assert_eq!(returned.admission_refusal(), Some(original));
            assert!(returned.operation_error().is_none());
            assert!(returned.creation().is_none());
            let joined = crate::test_fixture_failure::FixtureFailure::from(returned);
            assert_eq!(joined.admission_refusal(), Some(original));
            assert_eq!(counting.finish(), 0);
            let crate::test_fixture_failure::FixtureFailure::Publication(
                TestPublicationFailure::Preparation {
                    original: retained,
                    publication,
                    response,
                    violation,
                    capture,
                },
            ) = joined
            else {
                panic!("inline refusal and original capture must remain one whole owner");
            };
            assert_eq!(retained.admission_refusal(), Some(original));
            assert!(publication.is_none());
            let capture = capture.unwrap();
            assert_eq!(capture.attempted, !matches!(mode, CaptureMode::Ready));
            assert_eq!(
                capture.invalid,
                matches!(mode, CaptureMode::Repeated | CaptureMode::Invalid)
            );
            assert_eq!(capture.repeated, matches!(mode, CaptureMode::Repeated));
            assert_eq!(
                violation,
                matches!(mode, CaptureMode::Repeated).then_some(CompletionViolation::Repeated),
            );
            if matches!(mode, CaptureMode::Ready | CaptureMode::Invalid) {
                assert!(response.is_none());
            } else {
                assert_eq!(response.unwrap().data.as_ptr(), address);
            }
        }
    }
}
