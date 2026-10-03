use super::*;
use kasumi_types::drain::{DrainCompletion, DrainFailure};
use std::sync::atomic::AtomicUsize;

#[derive(Debug)]
struct OriginalSourceFailure(u64);
impl std::fmt::Display for OriginalSourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original selected source close failure {}", self.0)
    }
}
impl std::error::Error for OriginalSourceFailure {}

// This fixture controls lifecycle observations, not storage/provider provenance.
// Engine integration separately exercises the exact registered views and grant.
struct Sources {
    finished_reconstruction: AtomicBool,
    panic_finish: AtomicBool,
    finish_gate: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    finish_error: Mutex<Option<anyhow::Error>>,
    sealed: AtomicBool,
    polls: AtomicUsize,
    ready: AtomicBool,
    positive: AtomicBool,
    wake: Mutex<Option<Waker>>,
    report: DrainReport,
}
impl Sources {
    fn new(failure: Option<u64>) -> Arc<Self> {
        let mut report = DrainReport::default();
        if let Some(value) = failure {
            report.record(
                "selected source close",
                7,
                OriginalSourceFailure(value).into(),
            );
        }
        Arc::new(Self {
            finished_reconstruction: AtomicBool::new(false),
            panic_finish: AtomicBool::new(false),
            finish_gate: Mutex::new(None),
            finish_error: Mutex::new(None),
            sealed: AtomicBool::new(false),
            polls: AtomicUsize::new(0),
            ready: AtomicBool::new(false),
            positive: AtomicBool::new(false),
            wake: Mutex::new(None),
            report,
        })
    }
    fn finish(&self, positive: bool) {
        self.positive.store(positive, Ordering::Release);
        self.ready.store(true, Ordering::Release);
        let wake = self.wake.lock().unwrap().take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
}
impl ApplicationSourceCustody for Sources {
    fn finish_reconstruction(&self) -> anyhow::Result<()> {
        drop(retained().lock().unwrap());
        assert!(!self.finished_reconstruction.swap(true, Ordering::AcqRel));
        let gate = self.finish_gate.lock().unwrap().take();
        if let Some((entered, release)) = gate {
            entered.send(()).unwrap();
            release
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
        }
        if self.panic_finish.load(Ordering::Acquire) {
            std::panic::panic_any(OriginalSourceFailure(113));
        }
        match self.finish_error.lock().unwrap().take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn seal_consumers(&self) {
        // The actual retained inventory can be inspected reentrantly; no hook
        // callback may inherit its lock from a release or startup census.
        drop(retained().lock().unwrap());
        self.sealed.store(true, Ordering::Release);
    }
    fn poll_drain(&self, cx: &mut Context<'_>) -> Poll<DrainResult> {
        drop(retained().lock().unwrap());
        assert!(self.sealed.load(Ordering::Acquire));
        self.polls.fetch_add(1, Ordering::AcqRel);
        let mut wake = self.wake.lock().unwrap();
        if !self.ready.load(Ordering::Acquire) {
            *wake = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(self.report.complete())
    }
    fn is_drained(&self) -> bool {
        drop(retained().lock().unwrap());
        self.positive.load(Ordering::Acquire)
    }
}
async fn pending<F: Future>(mut future: Pin<&mut F>) {
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}
fn retained_owner(owner: &SnapshotBufferOwner) -> bool {
    retained().lock().unwrap().contains_key(&owner.id)
}

#[tokio::test]
async fn application_source_binding_is_single_use_idle_and_before_acquisition() -> anyhow::Result<()>
{
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let sources = Sources::new(None);
    owner.bind_application_sources(crate::ApplicationSourceBinding::fixture(sources.clone()))?;
    assert!(retained_owner(&owner));
    assert!(!owner.application_sources_drained.load(Ordering::Acquire));
    assert!(!sources.sealed.load(Ordering::Acquire));
    assert_eq!(sources.polls.load(Ordering::Acquire), 0);
    let rejected = Sources::new(None);
    assert!(
        owner
            .bind_application_sources(crate::ApplicationSourceBinding::fixture(rejected.clone()))
            .is_err()
    );
    assert_eq!(Arc::strong_count(&rejected), 1);
    sources.finish(true);
    owner.drain_startup().await?;
    assert!(!retained_owner(&owner));
    assert!(
        owner
            .bind_application_sources(crate::ApplicationSourceBinding::fixture(rejected.clone()))
            .is_err()
    );
    assert_eq!(Arc::strong_count(&rejected), 1);

    let opening = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let claimant = opening.start(async { anyhow::bail!("selected opening fixture") });
    assert!(
        opening
            .bind_application_sources(crate::ApplicationSourceBinding::fixture(rejected.clone()))
            .is_err()
    );
    assert_eq!(Arc::strong_count(&rejected), 1);
    assert!(!rejected.sealed.load(Ordering::Acquire));
    assert_eq!(rejected.polls.load(Ordering::Acquire), 0);
    drop(claimant);
    assert_eq!(
        opening.drain_startup().await.unwrap_err().completion(),
        DrainCompletion::Complete
    );
    Ok(())
}

#[tokio::test]
async fn application_source_idle_abandonment_and_cancelled_drain_keep_original_close()
-> anyhow::Result<()> {
    let charge = Arc::new(());
    let owner = SnapshotBufferOwner::new(1, charge.clone())?;
    let weak = Arc::downgrade(&owner);
    let sources = Sources::new(Some(73));
    let original = sources.report.issues()[0].clone();
    owner.bind_application_sources(crate::ApplicationSourceBinding::fixture(sources.clone()))?;
    drop(owner);
    let owner = weak
        .upgrade()
        .expect("prebound idle source has startup custody");
    let mut first = Box::pin(owner.drain_startup());
    pending(first.as_mut()).await;
    drop(first);
    assert!(retained_owner(&owner));
    assert!(sources.sealed.load(Ordering::Acquire));
    assert!(Arc::strong_count(&charge) > 1);
    sources.finish(true);
    let failure = owner.drain_startup().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 1);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &original,
        &failure.issues()[0]
    ));
    assert_eq!(
        failure.issues()[0]
            .error()
            .downcast_ref::<OriginalSourceFailure>()
            .unwrap()
            .0,
        73
    );
    let repeated = owner.drain_startup().await.unwrap_err();
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &original,
        &repeated.issues()[0]
    ));
    assert!(!retained_owner(&owner));
    drop(owner);
    assert!(weak.upgrade().is_none());
    assert_eq!(Arc::strong_count(&charge), 1);
    Ok(())
}

#[tokio::test]
async fn application_source_pending_retirement_blocks_buffer_and_group_release()
-> anyhow::Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let sources = Sources::new(None);
    owner.bind_application_sources(crate::ApplicationSourceBinding::fixture(sources.clone()))?;
    let ownership = Arc::new(AtomicBool::new(true));
    owner.bind_fixture_group_ownership(ownership.clone(), Arc::new(()))?;
    // The early transfer-only drain must leave source preparation untouched.
    owner.drain_buffers().await?;
    assert_eq!(sources.polls.load(Ordering::Acquire), 0);
    assert!(!sources.sealed.load(Ordering::Acquire));
    assert!(retained_owner(&owner));
    owner.release_group_ownership();
    assert!(ownership.load(Ordering::Acquire));
    assert!(retained_owner(&owner));
    owner.seal_application_source_consumers();
    sources.finish(true);
    owner.drain_application_sources().await?;
    owner.release_group_ownership();
    assert!(!ownership.load(Ordering::Acquire));
    assert!(!retained_owner(&owner));
    Ok(())
}

#[tokio::test]
async fn application_source_failed_claim_cannot_release_unclosed_idle_roots() -> anyhow::Result<()>
{
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let sources = Sources::new(None);
    owner.bind_application_sources(crate::ApplicationSourceBinding::fixture(sources.clone()))?;
    assert!(
        owner
            .start(async { anyhow::bail!("failure before group creation") })
            .await
            .is_err()
    );
    assert!(
        retained_owner(&owner),
        "claim's Finished release requires positive source retirement"
    );
    assert_eq!(sources.polls.load(Ordering::Acquire), 0);
    sources.finish(true);
    assert_eq!(
        owner.drain_startup().await.unwrap_err().completion(),
        DrainCompletion::Complete
    );
    assert!(!retained_owner(&owner));
    Ok(())
}

#[tokio::test]
async fn application_source_failed_startup_waits_real_storage_lease_before_final_drain()
-> anyhow::Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let sources = Sources::new(Some(83));
    let original = sources.report.issues()[0].clone();
    owner.bind_application_sources(crate::ApplicationSourceBinding::fixture(sources.clone()))?;
    let (storage, lease) = crate::lifetime::StorageDrain::new();
    let mut first = Box::pin(crate::failed_startup(
        OriginalSourceFailure(89).into(),
        &owner,
        &storage,
    ));
    pending(first.as_mut()).await;
    assert!(sources.sealed.load(Ordering::Acquire));
    assert_eq!(
        sources.polls.load(Ordering::Acquire),
        0,
        "writer still owns real StorageLease"
    );
    drop(lease);
    pending(first.as_mut()).await;
    assert!(sources.polls.load(Ordering::Acquire) > 0);
    drop(first);
    assert!(retained_owner(&owner));
    sources.finish(true);
    let error = crate::failed_startup(OriginalSourceFailure(999).into(), &owner, &storage).await;
    let failure = error.downcast_ref::<DrainFailure>().unwrap();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 2);
    assert!(
        failure
            .issues()
            .iter()
            .any(|issue| kasumi_types::drain::DrainIssueRef::ptr_eq(&original, issue))
    );
    let startup = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "Raft startup")
        .unwrap();
    assert_eq!(
        startup
            .error()
            .downcast_ref::<OriginalSourceFailure>()
            .unwrap()
            .0,
        89
    );
    assert!(!retained_owner(&owner));
    Ok(())
}

#[tokio::test]
async fn application_source_nonpositive_close_keeps_original_error_and_registry()
-> anyhow::Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let sources = Sources::new(Some(97));
    let original = sources.report.issues()[0].clone();
    owner.bind_application_sources(crate::ApplicationSourceBinding::fixture(sources.clone()))?;
    sources.finish(false);
    let failure = owner.drain_startup().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Retained);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &original,
        &failure.issues()[0]
    ));
    assert!(retained_owner(&owner));
    // A later positive exact retirement can release custody, retaining the
    // same original error instead of substituting a successful-close string.
    sources.finish(true);
    let failure = owner.drain_startup().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &original,
        &failure.issues()[0]
    ));
    assert!(!retained_owner(&owner));
    Ok(())
}

#[tokio::test]
async fn application_source_retained_startup_never_seals_writer_preparation() -> anyhow::Result<()>
{
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let sources = Sources::new(None);
    owner.bind_application_sources(crate::ApplicationSourceBinding::fixture(sources.clone()))?;
    let mut report = DrainReport::default();
    let issue = report.record("still owned writer", 0, OriginalSourceFailure(101).into());
    owner
        .install_cleanup_fixture(async move { Err(DrainFailure::retained(issue)) })
        .await;
    let failure = owner.drain_startup().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Retained);
    assert!(sources.sealed.load(Ordering::Acquire));
    assert_eq!(sources.polls.load(Ordering::Acquire), 0);
    assert!(!owner.application_sources_drained.load(Ordering::Acquire));
    assert!(retained_owner(&owner));
    // This real retained startup state intentionally stays in the global
    // inventory; no test-only removal fabricates positive writer completion.
    Ok(())
}

async fn failed_final_handoff(panics: bool) -> anyhow::Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let weak = Arc::downgrade(&owner);
    let sources = Sources::new(None);
    if panics {
        sources.panic_finish.store(true, Ordering::Release);
    } else {
        *sources.finish_error.lock().unwrap() = Some(OriginalSourceFailure(109).into());
    }
    owner.bind_application_sources(crate::ApplicationSourceBinding::fixture(sources.clone()))?;
    let (release, paused) = tokio::sync::oneshot::channel();
    let mut caller = Box::pin(owner.start(async {
        Ok(crate::startup_owner_tests::source_custody_fixture_group(
            tokio::spawn(async move {
                paused.await.unwrap();
            }),
        ))
    }));
    pending(caller.as_mut()).await;
    assert!(sources.finished_reconstruction.load(Ordering::Acquire));
    assert!(owner.startup.try_lock().is_err());
    drop(caller);
    assert!(matches!(
        *owner.startup.try_lock().unwrap(),
        crate::startup_owner::StartupState::Cleaning(_)
    ));
    drop(owner);
    let owner = weak
        .upgrade()
        .expect("failed final check retains unclaimed group across cancellation");
    let mut census = Box::pin(owner.drain_startup());
    pending(census.as_mut()).await;
    assert_eq!(
        sources.polls.load(Ordering::Acquire),
        0,
        "fixture child still owns cleanup"
    );
    drop(census);
    sources.finish(true);
    release.send(()).unwrap();
    let failure = tokio::time::timeout(std::time::Duration::from_secs(10), owner.drain_startup())
        .await?
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let original = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "Raft startup")
        .unwrap()
        .clone();
    if panics {
        let panic = original
            .error()
            .downcast_ref::<crate::startup_owner::ApplicationSourceHandoffPanic>()
            .unwrap();
        assert_eq!(
            panic
                .payload
                .lock()
                .unwrap()
                .downcast_ref::<OriginalSourceFailure>()
                .unwrap()
                .0,
            113
        );
    } else {
        assert_eq!(
            original
                .error()
                .downcast_ref::<OriginalSourceFailure>()
                .unwrap()
                .0,
            109
        );
    }
    let rejected = owner
        .start(async { anyhow::bail!("must not replace original outcome") })
        .await;
    assert!(rejected.is_err());
    let repeated = owner.drain_startup().await.unwrap_err();
    assert!(
        repeated
            .issues()
            .iter()
            .any(|issue| kasumi_types::drain::DrainIssueRef::ptr_eq(issue, &original))
    );
    assert!(!retained_owner(&owner));
    drop(owner);
    assert!(weak.upgrade().is_none());
    Ok(())
}

#[tokio::test]
async fn application_source_final_check_precedes_group_delivery() -> anyhow::Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let sources = Sources::new(None);
    owner.bind_application_sources(crate::ApplicationSourceBinding::fixture(sources.clone()))?;
    let group = owner
        .start(async {
            Ok(crate::startup_owner_tests::source_custody_fixture_group(
                tokio::spawn(async {}),
            ))
        })
        .await?;
    assert!(sources.finished_reconstruction.load(Ordering::Acquire));
    assert!(matches!(
        *owner.startup.try_lock().unwrap(),
        crate::startup_owner::StartupState::Delivered
    ));
    assert!(retained_owner(&owner));
    owner.drain_startup().await?;
    assert!(!sources.sealed.load(Ordering::Acquire));
    assert_eq!(sources.polls.load(Ordering::Acquire), 0);
    match group {
        crate::startup_owner::StartedGroup::Fixture(mut group) => group.shutdown().await?,
        _ => unreachable!(),
    }
    owner.seal_application_source_consumers();
    sources.finish(true);
    owner.drain_application_sources().await?;
    owner.release_group_ownership();
    assert!(!retained_owner(&owner));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn application_source_failed_final_check_and_cancelled_cleanup_keep_unclaimed_group()
-> anyhow::Result<()> {
    failed_final_handoff(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn application_source_panicked_final_check_and_cancelled_cleanup_keep_unclaimed_group()
-> anyhow::Result<()> {
    failed_final_handoff(true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn application_source_shutdown_during_final_check_cannot_deliver_group() -> anyhow::Result<()>
{
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let sources = Sources::new(None);
    let (entered, ready) = std::sync::mpsc::channel();
    let (release, paused) = std::sync::mpsc::channel();
    *sources.finish_gate.lock().unwrap() = Some((entered, paused));
    owner.bind_application_sources(crate::ApplicationSourceBinding::fixture(sources.clone()))?;
    let claiming = owner.clone();
    let caller = tokio::spawn(async move {
        claiming
            .start(async {
                Ok(crate::startup_owner_tests::source_custody_fixture_group(
                    tokio::spawn(async {}),
                ))
            })
            .await
    });
    ready.recv_timeout(std::time::Duration::from_secs(10))?;
    let mut census = Box::pin(owner.drain_startup());
    pending(census.as_mut()).await;
    assert!(owner.startup_closing.load(Ordering::Acquire));
    release.send(())?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(10), caller).await??;
    assert!(
        result.is_err(),
        "closed startup delivered a validated group"
    );
    // Cancel the queued startup-mutex acquisition before inspecting or starting
    // a replacement census; its wake may already own the next permit.
    drop(census);
    assert!(!matches!(
        *owner.startup.try_lock().unwrap(),
        crate::startup_owner::StartupState::Delivered
    ));
    sources.finish(true);
    let failure = owner.drain_startup().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert!(sources.sealed.load(Ordering::Acquire));
    assert!(!retained_owner(&owner));
    Ok(())
}
