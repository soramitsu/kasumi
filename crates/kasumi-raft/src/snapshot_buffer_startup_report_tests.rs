use super::*;
use kasumi_types::drain::{DrainCompletion, DrainFailure, DrainIssueRef};
use std::sync::atomic::AtomicUsize;

fn actual_io_drain(
    directory: &std::path::Path,
    name: &str,
    completion: DrainCompletion,
) -> (DrainFailure, DrainIssueRef) {
    let original = std::fs::metadata(directory.join(name)).unwrap_err();
    assert_eq!(original.kind(), io::ErrorKind::NotFound);
    let mut report = DrainReport::default();
    let issue = report.record(
        "original startup filesystem",
        0,
        anyhow::Error::new(original),
    );
    let failure = match completion {
        DrainCompletion::Complete => report.complete().unwrap_err(),
        DrainCompletion::Retained => DrainFailure::retained(issue.clone()),
    };
    (failure, issue)
}

fn error_address(original: &anyhow::Error) -> usize {
    let outer: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
    outer as *const _ as *const () as usize
}

fn original_issue(owner: &SnapshotBufferOwner, address: usize) -> DrainIssueRef {
    let report = owner.report.lock().unwrap();
    let issue = report
        .issues()
        .iter()
        .find(|issue| issue.component() == "Raft startup" && issue.instance() == address)
        .unwrap();
    assert_eq!(error_address(issue.error()), address);
    issue.clone()
}

#[test]
fn bare_drain_startup_reports_preserve_independent_outer_allocations_and_issues() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let owner = SnapshotBufferOwner::fixture();
    let (first, first_io) = actual_io_drain(
        directory.path(),
        "first-missing-startup-file",
        DrainCompletion::Retained,
    );
    let (second, second_io) = actual_io_drain(
        directory.path(),
        "second-missing-startup-file",
        DrainCompletion::Complete,
    );
    let first = anyhow::Error::new(first);
    let second = anyhow::Error::new(second);
    let first_address = error_address(&first);
    let second_address = error_address(&second);
    assert_ne!(first_address, second_address);
    let first_result = owner.record_startup_error(first);
    assert_eq!(first_result.completion(), DrainCompletion::Retained);
    let second_result = owner.record_startup_error(second);
    assert_eq!(second_result.completion(), DrainCompletion::Complete);
    assert_eq!(second_result.issues().len(), 4);
    let first_original = original_issue(&owner, first_address);
    let second_original = original_issue(&owner, second_address);
    for _ in 0..3 {
        let first_again = original_issue(&owner, first_address);
        let second_again = original_issue(&owner, second_address);
        assert!(DrainIssueRef::ptr_eq(&first_original, &first_again));
        assert!(DrainIssueRef::ptr_eq(&second_original, &second_again));
        let report = owner.report.lock().unwrap();
        assert_eq!(report.issues().len(), 4);
        assert!(
            report
                .issues()
                .iter()
                .any(|issue| DrainIssueRef::ptr_eq(issue, &first_io))
        );
        assert!(
            report
                .issues()
                .iter()
                .any(|issue| DrainIssueRef::ptr_eq(issue, &second_io))
        );
    }
    drop(owner);
    assert_eq!(error_address(first_original.error()), first_address);
    assert_eq!(error_address(second_original.error()), second_address);
    let first_outer: &(dyn std::error::Error + Send + Sync + 'static) =
        first_original.error().as_ref();
    let second_outer: &(dyn std::error::Error + Send + Sync + 'static) =
        second_original.error().as_ref();
    assert!(DrainIssueRef::ptr_eq(
        &first_outer.downcast_ref::<DrainFailure>().unwrap().issues()[0],
        &first_io,
    ));
    assert!(DrainIssueRef::ptr_eq(
        &second_outer
            .downcast_ref::<DrainFailure>()
            .unwrap()
            .issues()[0],
        &second_io,
    ));
}

struct OwningStartupContext {
    drops: Arc<AtomicUsize>,
}
impl std::fmt::Display for OwningStartupContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owning startup context")
    }
}
impl Drop for OwningStartupContext {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn owning_context_startup_reports_keep_both_exact_allocations_without_inner_classification() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let owner = SnapshotBufferOwner::fixture();
    let first_drops = Arc::new(AtomicUsize::new(0));
    let second_drops = Arc::new(AtomicUsize::new(0));
    let (first, first_io) = actual_io_drain(
        directory.path(),
        "first-context-startup-file",
        DrainCompletion::Retained,
    );
    let (second, second_io) = actual_io_drain(
        directory.path(),
        "second-context-startup-file",
        DrainCompletion::Retained,
    );
    let first = anyhow::Error::new(first).context(OwningStartupContext {
        drops: first_drops.clone(),
    });
    let second = anyhow::Error::new(second).context(OwningStartupContext {
        drops: second_drops.clone(),
    });
    let first_address = error_address(&first);
    let second_address = error_address(&second);
    assert_ne!(first_address, second_address);
    // Only a bare outer DrainFailure may provide its completion observation.
    let first_outer: &(dyn std::error::Error + Send + Sync + 'static) = first.as_ref();
    let second_outer: &(dyn std::error::Error + Send + Sync + 'static) = second.as_ref();
    assert!(first_outer.downcast_ref::<DrainFailure>().is_none());
    assert!(second_outer.downcast_ref::<DrainFailure>().is_none());
    drop(first_io);
    drop(second_io);
    let first_result = owner.record_startup_error(first);
    let second_result = owner.record_startup_error(second);
    assert_eq!(first_result.completion(), DrainCompletion::Complete);
    assert_eq!(second_result.completion(), DrainCompletion::Complete);
    assert_eq!(second_result.issues().len(), 2);
    let first_original = original_issue(&owner, first_address);
    let second_original = original_issue(&owner, second_address);
    for _ in 0..3 {
        assert!(DrainIssueRef::ptr_eq(
            &first_original,
            &original_issue(&owner, first_address),
        ));
        assert!(DrainIssueRef::ptr_eq(
            &second_original,
            &original_issue(&owner, second_address),
        ));
        assert_eq!(owner.report.lock().unwrap().issues().len(), 2);
        assert_eq!(first_drops.load(Ordering::SeqCst), 0);
        assert_eq!(second_drops.load(Ordering::SeqCst), 0);
    }
    drop(owner);
    drop(first_result);
    drop(second_result);
    assert_eq!(first_drops.load(Ordering::SeqCst), 0);
    assert_eq!(second_drops.load(Ordering::SeqCst), 0);
    assert_eq!(error_address(first_original.error()), first_address);
    assert_eq!(error_address(second_original.error()), second_address);
    drop(first_original);
    assert_eq!(first_drops.load(Ordering::SeqCst), 1);
    assert_eq!(second_drops.load(Ordering::SeqCst), 0);
    drop(second_original);
    assert_eq!(second_drops.load(Ordering::SeqCst), 1);
}
