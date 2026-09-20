use crate::{
    SnapshotBufferOwner, startup_owner::StartedGroup, startup_test_utils::LocalStartupGate,
};
use anyhow::Result;
use kasumi_types::drain::{DrainCompletion, DrainReport};
use std::{
    future::{Future, poll_fn},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::Poll,
    time::Duration,
};
const WAIT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct OriginalFailure(u64);
impl std::fmt::Display for OriginalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "startup child failure {}", self.0)
    }
}
impl std::error::Error for OriginalFailure {}

pub(crate) struct FixtureGroup {
    child: tokio::task::JoinHandle<()>,
    report: DrainReport,
}
impl FixtureGroup {
    pub(crate) async fn shutdown(mut self) -> kasumi_types::drain::DrainResult {
        if let Err(error) = (&mut self.child).await {
            self.report.record("startup fixture child", 0, error.into());
        }
        self.report.complete()
    }
}
async fn pending<F: Future>(future: std::pin::Pin<&mut F>) {
    let mut future = future;
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_startup_and_drain_keep_actual_child_panic_and_charge() -> Result<()> {
    let charge = Arc::new(());
    let owner = SnapshotBufferOwner::new(1, charge.clone())?;
    let weak = Arc::downgrade(&owner);
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, paused) = mpsc::channel();
    let mut startup = Box::pin(owner.start(async move {
        tokio::task::spawn_blocking(move || {
            let _ = entered.send(tokio::task::id());
            paused.recv_timeout(WAIT).unwrap();
            std::panic::panic_any(OriginalFailure(47));
        })
        .await?;
        anyhow::bail!("unreachable after child panic")
    }));
    pending(startup.as_mut()).await;
    let task_id = tokio::time::timeout(WAIT, ready).await??;
    drop(startup);
    drop(owner);
    let owner = weak.upgrade().expect("registry retains abandoned startup");
    assert!(Arc::strong_count(&charge) > 1);
    let mut first = Box::pin(owner.drain_startup());
    pending(first.as_mut()).await;
    drop(first);
    release.send(())?;
    let failure = tokio::time::timeout(WAIT, owner.drain_startup())
        .await?
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let original = failure.issues()[0].clone();
    let join = original
        .error()
        .downcast_ref::<tokio::task::JoinError>()
        .unwrap();
    assert!(join.is_panic());
    assert_eq!(join.id(), task_id);
    let repeated = owner.drain_startup().await.unwrap_err();
    assert!(Arc::ptr_eq(&original, &repeated.issues()[0]));
    drop(owner);
    assert!(weak.upgrade().is_none());
    assert_eq!(Arc::strong_count(&charge), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_unclaimed_group_cleanup_keeps_same_actual_child() -> Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let (return_group, group_ready) = tokio::sync::oneshot::channel();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, paused) = mpsc::channel();
    let mut startup = Box::pin(owner.start(async move {
        let child = tokio::task::spawn_blocking(move || {
            let _ = entered.send(tokio::task::id());
            paused.recv_timeout(WAIT).unwrap();
            std::panic::panic_any(OriginalFailure(59));
        });
        group_ready.await?;
        Ok(StartedGroup::Fixture(FixtureGroup {
            child,
            report: DrainReport::default(),
        }))
    }));
    pending(startup.as_mut()).await;
    let task_id = tokio::time::timeout(WAIT, ready).await??;
    drop(startup);
    return_group.send(()).unwrap();
    let mut first = Box::pin(owner.drain_startup());
    pending(first.as_mut()).await;
    drop(first);
    release.send(())?;
    let failure = tokio::time::timeout(WAIT, owner.drain_startup())
        .await?
        .unwrap_err();
    let original = failure.issues()[0].clone();
    assert_eq!(
        original
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .id(),
        task_id
    );
    let repeated = owner.drain_startup().await.unwrap_err();
    assert!(Arc::ptr_eq(&original, &repeated.issues()[0]));
    Ok(())
}

#[tokio::test]
async fn delivered_startup_is_not_closed_by_node_startup_census() -> Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let started = owner
        .start(async {
            Ok(StartedGroup::Fixture(FixtureGroup {
                child: tokio::spawn(async {}),
                report: DrainReport::default(),
            }))
        })
        .await?;
    owner.drain_startup().await?;
    owner.check()?;
    let disk = kasumi_store::ScratchDisk::fixture();
    let buffer = crate::SnapshotBuffer::new(&disk, 64, &owner)?;
    drop(buffer);
    match started {
        StartedGroup::Fixture(group) => group.shutdown().await?,
        _ => unreachable!(),
    }
    owner.drain().await?;
    Ok(())
}

#[tokio::test]
async fn oversized_startup_is_rejected_before_polling_or_global_publication() -> Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let weak = Arc::downgrade(&owner);
    let polled = Arc::new(AtomicBool::new(false));
    let observed = polled.clone();
    let payload = [0u8; crate::startup_owner::STARTUP_WORKSPACE as usize + 1];
    let result = owner
        .start(async move {
            observed.store(true, Ordering::Release);
            std::future::pending::<()>().await;
            std::hint::black_box(payload);
            anyhow::bail!("unreachable")
        })
        .await;
    assert!(result.is_err());
    assert!(!polled.load(Ordering::Acquire));
    drop(owner);
    assert!(weak.upgrade().is_none());
    Ok(())
}

struct Backend;
impl crate::StateMachineBackend for Backend {
    fn close_application(&self) {}
    fn apply(
        &self,
        _: &crate::AppliedEntryContext,
        bytes: &[u8],
    ) -> Result<crate::AppliedResponse> {
        Ok(crate::AppliedResponse::application(bytes.to_vec()))
    }
    fn capture_snapshot(&self) -> Result<crate::CapturedSnapshot> {
        Ok(crate::CapturedSnapshot::new(None, |_| Ok(())))
    }
    fn validate_snapshot(
        &self,
        _: &mut dyn std::io::Read,
    ) -> Result<Option<crate::RetiredSnapshotState>> {
        Ok(None)
    }
    fn prepare_restore<'a>(
        &'a self,
        _: &crate::SnapshotRestoreContext,
        _: &mut dyn std::io::Read,
    ) -> Result<Box<dyn crate::PreparedStateMachineRestore + 'a>> {
        anyhow::bail!("empty startup fixture has no snapshot")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_local_initialization_drains_real_group_and_breaks_router_cycle() -> Result<()> {
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let store = kasumi_store::TenantStorageSet::initialize_catalogs_fixture(
        kasumi_store::NodeStore::create_new_fixture(
            directory.path().join("startup.redb"),
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )?,
        "tenant-a".into(),
        Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([19; 32])),
        Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
    )
    .await?;
    let owner = SnapshotBufferOwner::fixture();
    let gate = LocalStartupGate::install(&owner, OriginalFailure(83).into())?;
    let mut startup = Box::pin(crate::RaftGroup::local(
        1,
        "tenant-a".into(),
        store.clone(),
        Arc::new(Backend),
        owner.clone(),
    ));
    tokio::select! {
        result = &mut startup => panic!("startup completed before injected gate: {}", result.is_ok()),
        result = tokio::time::timeout(WAIT, gate.entered.notified()) => result?,
    }
    drop(startup);
    let mut drain = Box::pin(owner.drain_startup());
    pending(drain.as_mut()).await;
    drop(drain);
    assert!(
        gate.ownership
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .upgrade()
            .unwrap()
            .load(Ordering::Acquire)
    );
    gate.release.add_permits(1);
    let failure = tokio::time::timeout(WAIT, owner.drain_startup())
        .await?
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(
        failure.issues()[0]
            .error()
            .downcast_ref::<OriginalFailure>()
            .unwrap()
            .0,
        83
    );
    assert!(
        gate.router
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .upgrade()
            .is_none()
    );
    assert!(
        gate.ownership
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .upgrade()
            .is_none_or(|claim| !claim.load(Ordering::Acquire))
    );
    let raft = gate
        .raft
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .downcast::<crate::Raft>()
        .map_err(|_| anyhow::anyhow!("startup fixture retained a different observer type"))?;
    assert!(raft.metrics().borrow().running_state.is_err());
    raft.shutdown().await?;
    let reopened = crate::RaftGroup::local(
        1,
        "tenant-a".into(),
        store,
        Arc::new(Backend),
        SnapshotBufferOwner::fixture(),
    )
    .await?;
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_census_closes_delivery_before_waiting_for_active_caller() -> Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let (return_group, group_ready) = tokio::sync::oneshot::channel();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, paused) = mpsc::channel();
    let mut startup = Box::pin(owner.start(async move {
        let child = tokio::task::spawn_blocking(move || {
            let _ = entered.send(tokio::task::id());
            paused.recv_timeout(WAIT).unwrap();
            std::panic::panic_any(OriginalFailure(101));
        });
        group_ready.await?;
        Ok(StartedGroup::Fixture(FixtureGroup {
            child,
            report: DrainReport::default(),
        }))
    }));
    pending(startup.as_mut()).await;
    let task_id = tokio::time::timeout(WAIT, ready).await??;
    let mut census = Box::pin(owner.drain_startup());
    pending(census.as_mut()).await;
    return_group.send(()).unwrap();
    // A successful startup result cannot escape the closing census. It is
    // moved into the retained cleanup slot even while the claimant is alive.
    pending(startup.as_mut()).await;
    drop(startup);
    drop(census);
    release.send(())?;
    let failure = tokio::time::timeout(WAIT, owner.drain_startup())
        .await?
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert!(failure.issues().iter().any(|issue| {
        issue
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .is_some_and(|error| error.id() == task_id)
    }));
    assert!(owner.check().is_err());
    Ok(())
}

struct DirectPollState {
    armed: AtomicBool,
    polls: std::sync::atomic::AtomicUsize,
    drops: std::sync::atomic::AtomicUsize,
    payload: Arc<OriginalFailure>,
}
struct DirectPollPanic<T> {
    state: Arc<DirectPollState>,
    output: std::marker::PhantomData<fn() -> T>,
}
impl<T> Future for DirectPollPanic<T> {
    type Output = T;
    fn poll(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> Poll<T> {
        self.state.polls.fetch_add(1, Ordering::AcqRel);
        if !self.state.armed.load(Ordering::Acquire) {
            return Poll::Pending;
        }
        std::panic::panic_any(self.state.payload.clone());
    }
}
impl<T> Drop for DirectPollPanic<T> {
    fn drop(&mut self) {
        self.state.drops.fetch_add(1, Ordering::AcqRel);
    }
}
fn direct_poll_future<T>(armed: bool) -> (Arc<DirectPollState>, DirectPollPanic<T>) {
    let state = Arc::new(DirectPollState {
        armed: AtomicBool::new(armed),
        polls: Default::default(),
        drops: Default::default(),
        payload: Arc::new(OriginalFailure(131)),
    });
    let future = DirectPollPanic {
        state: state.clone(),
        output: std::marker::PhantomData,
    };
    (state, future)
}
async fn assert_original_poll_panic_retained(
    owner: &Arc<SnapshotBufferOwner>,
    state: &DirectPollState,
    first: kasumi_types::drain::DrainFailure,
) {
    assert_eq!(first.completion(), DrainCompletion::Retained);
    let issue = first
        .issues()
        .iter()
        .find(|issue| {
            issue
                .error()
                .downcast_ref::<crate::startup_owner::StartupPollPanic>()
                .is_some()
        })
        .unwrap()
        .clone();
    let error = issue
        .error()
        .downcast_ref::<crate::startup_owner::StartupPollPanic>()
        .unwrap();
    {
        let payload = error.payload.lock().unwrap();
        let original = payload.downcast_ref::<Arc<OriginalFailure>>().unwrap();
        assert!(Arc::ptr_eq(original, &state.payload));
    }
    let polls = state.polls.load(Ordering::Acquire);
    for _ in 0..2 {
        let repeated = owner.drain_startup().await.unwrap_err();
        assert_eq!(repeated.completion(), DrainCompletion::Retained);
        assert!(
            repeated
                .issues()
                .iter()
                .any(|next| Arc::ptr_eq(next, &issue))
        );
    }
    let all_resources = owner.drain().await.unwrap_err();
    assert_eq!(all_resources.completion(), DrainCompletion::Retained);
    assert!(
        all_resources
            .issues()
            .iter()
            .any(|next| Arc::ptr_eq(next, &issue))
    );
    assert_eq!(
        state.polls.load(Ordering::Acquire),
        polls,
        "poisoned future was repolled"
    );
    assert_eq!(
        state.drops.load(Ordering::Acquire),
        0,
        "exact poisoned future was dropped"
    );
    assert!(owner.check().is_err());
}

#[tokio::test]
async fn direct_claim_poll_panic_keeps_original_payload_future_and_registry() -> Result<()> {
    let charge = Arc::new(());
    let owner = SnapshotBufferOwner::new(1, charge.clone())?;
    let weak = Arc::downgrade(&owner);
    let (state, future) = direct_poll_future::<Result<StartedGroup>>(true);
    let failure = match owner.start(future).await {
        Err(error) => error.downcast::<kasumi_types::drain::DrainFailure>()?,
        Ok(_) => panic!("direct poll panic cannot deliver a group"),
    };
    assert_original_poll_panic_retained(&owner, &state, failure).await;
    drop(owner);
    assert!(
        weak.upgrade().is_some(),
        "unresolved startup lost registry custody"
    );
    assert!(Arc::strong_count(&charge) > 1);
    Ok(())
}

#[tokio::test]
async fn direct_abandoned_opening_poll_panic_is_never_repolled_by_drain() -> Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let (state, future) = direct_poll_future::<Result<StartedGroup>>(false);
    let mut startup = Box::pin(owner.start(future));
    pending(startup.as_mut()).await;
    drop(startup);
    state.armed.store(true, Ordering::Release);
    let failure = owner.drain_startup().await.unwrap_err();
    assert_original_poll_panic_retained(&owner, &state, failure).await;
    Ok(())
}

#[tokio::test]
async fn direct_cleanup_poll_panic_keeps_original_payload_and_exact_cleanup_future() -> Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let (state, future) = direct_poll_future::<kasumi_types::drain::DrainResult>(true);
    owner.install_cleanup_fixture(future).await;
    let failure = owner.drain_startup().await.unwrap_err();
    assert_original_poll_panic_retained(&owner, &state, failure).await;
    Ok(())
}

#[tokio::test]
async fn cleanup_retained_result_cannot_be_promoted_to_complete_or_release_custody() -> Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let weak = Arc::downgrade(&owner);
    let mut report = DrainReport::default();
    let issue = report.record("unresolved startup fixture", 0, OriginalFailure(149).into());
    let first = kasumi_types::drain::DrainFailure::retained(issue.clone());
    owner
        .install_cleanup_fixture(std::future::ready(Err(first)))
        .await;
    for _ in 0..2 {
        let failure = owner.drain_startup().await.unwrap_err();
        assert_eq!(failure.completion(), DrainCompletion::Retained);
        assert!(
            failure
                .issues()
                .iter()
                .any(|next| Arc::ptr_eq(next, &issue))
        );
    }
    assert_eq!(
        owner.drain().await.unwrap_err().completion(),
        DrainCompletion::Retained
    );
    drop(owner);
    assert!(weak.upgrade().is_some());
    Ok(())
}

#[tokio::test]
async fn synchronous_enrollment_allows_census_before_the_claimant_is_polled() -> Result<()> {
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let polled = Arc::new(AtomicBool::new(false));
    let observed = polled.clone();
    let claimant = owner.start(async move {
        observed.store(true, Ordering::Release);
        Ok(StartedGroup::Fixture(FixtureGroup {
            child: tokio::spawn(async {}),
            report: DrainReport::default(),
        }))
    });
    assert!(
        !polled.load(Ordering::Acquire),
        "enrollment polled startup work"
    );
    owner.drain_startup().await?;
    assert!(polled.load(Ordering::Acquire));
    let error = match claimant.await {
        Err(error) => error,
        Ok(_) => panic!("shutdown already reclaimed the group"),
    };
    assert_eq!(
        error
            .downcast_ref::<kasumi_types::drain::DrainFailure>()
            .unwrap()
            .completion(),
        DrainCompletion::Complete
    );
    Ok(())
}
