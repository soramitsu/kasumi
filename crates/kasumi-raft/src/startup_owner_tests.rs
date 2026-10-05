use crate::test_utils::FixtureResult;
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

fn paid_snapshot_owner(
    memory: &Arc<kasumi_store::test_utils::TestDiskMemory>,
) -> Result<Arc<SnapshotBufferOwner>> {
    use kasumi_store::{DiskMemoryLease, NodeDiskMemoryAdmission};
    let bytes = SnapshotBufferOwner::required_bytes(1)?
        .checked_add(kasumi_types::SharedBudgetCharge::required_bytes::<
            DiskMemoryLease,
        >()?)
        .ok_or_else(|| anyhow::anyhow!("snapshot fixture root quote overflow"))?;
    SnapshotBufferOwner::new(
        1,
        kasumi_types::SharedBudgetCharge::new(memory.clone().reserve_installed(bytes)?),
    )
}

#[derive(Debug)]
struct OriginalFailure(u64);
impl std::fmt::Display for OriginalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "startup child failure {}", self.0)
    }
}
impl std::error::Error for OriginalFailure {}

struct HeldGroup {
    drops: Arc<std::sync::atomic::AtomicUsize>,
}
impl Drop for HeldGroup {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
pub(crate) struct FixtureGroup {
    child: tokio::task::JoinHandle<()>,
    report: DrainReport,
    retained: Option<kasumi_types::drain::DrainFailure>,
    _held: Option<Arc<HeldGroup>>,
    panic_cleanup: bool,
}
impl FixtureGroup {
    pub(crate) async fn shutdown(&mut self) -> kasumi_types::drain::DrainResult {
        if self.panic_cleanup {
            std::panic::panic_any(OriginalFailure(193));
        }
        if let Err(error) = (&mut self.child).await {
            self.report.record("startup fixture child", 0, error.into());
        }
        self.report.outcome(self.retained.clone())
    }
}
pub(crate) fn source_custody_fixture_group(child: tokio::task::JoinHandle<()>) -> StartedGroup {
    StartedGroup::Fixture(FixtureGroup {
        child,
        report: DrainReport::default(),
        retained: None,
        _held: None,
        panic_cleanup: false,
    })
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
async fn cancelled_startup_and_drain_keep_actual_child_panic_and_charge() -> FixtureResult<()> {
    let (charge, charge_retired) = crate::test_utils::observed_budget_charge();
    let owner = SnapshotBufferOwner::new(1, charge)?;
    let weak = Arc::downgrade(&owner);
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, paused) = mpsc::channel();
    let mut startup = Box::pin(owner.start::<_, anyhow::Error>(async move {
        tokio::task::spawn_blocking(move || {
            let _ = entered.send(tokio::task::id());
            paused.recv_timeout(WAIT).unwrap();
            std::panic::panic_any(OriginalFailure(47));
        })
        .await?;
        Err(anyhow::anyhow!("unreachable after child panic"))
    }));
    pending(startup.as_mut()).await;
    let task_id = tokio::time::timeout(WAIT, ready).await??;
    drop(startup);
    drop(owner);
    let owner = weak.upgrade().expect("registry retains abandoned startup");
    assert!(!charge_retired.load(std::sync::atomic::Ordering::Acquire));
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
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &original,
        &repeated.issues()[0]
    ));
    drop(owner);
    assert!(weak.upgrade().is_none());
    assert!(charge_retired.load(std::sync::atomic::Ordering::Acquire));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_unclaimed_group_cleanup_keeps_same_actual_child() -> FixtureResult<()> {
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let (return_group, group_ready) = tokio::sync::oneshot::channel();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, paused) = mpsc::channel();
    let mut startup = Box::pin(owner.start::<_, anyhow::Error>(async move {
        let child = tokio::task::spawn_blocking(move || {
            let _ = entered.send(tokio::task::id());
            paused.recv_timeout(WAIT).unwrap();
            std::panic::panic_any(OriginalFailure(59));
        });
        group_ready.await?;
        Ok(StartedGroup::Fixture(FixtureGroup {
            child,
            report: DrainReport::default(),
            retained: None,
            _held: None,
            panic_cleanup: false,
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
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &original,
        &repeated.issues()[0]
    ));
    Ok(())
}

#[tokio::test]
async fn delivered_startup_is_not_closed_by_node_startup_census() -> FixtureResult<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let started = owner
        .start::<_, anyhow::Error>(async {
            Ok(StartedGroup::Fixture(FixtureGroup {
                child: tokio::spawn(async {}),
                report: DrainReport::default(),
                retained: None,
                _held: None,
                panic_cleanup: false,
            }))
        })
        .await?;
    owner.drain_startup().await?;
    owner.check()?;
    let disk = fixture_scratch.clone();
    let buffer = crate::SnapshotBuffer::new(&disk, 64, &owner)?;
    drop(buffer);
    match started {
        StartedGroup::Fixture(mut group) => group.shutdown().await?,
        _ => unreachable!(),
    }
    owner.drain().await?;
    Ok(())
}

#[tokio::test]
async fn oversized_startup_is_rejected_before_polling_or_global_publication() -> FixtureResult<()> {
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let weak = Arc::downgrade(&owner);
    let polled = Arc::new(AtomicBool::new(false));
    let observed = polled.clone();
    let payload = [0u8; crate::startup_owner::STARTUP_WORKSPACE as usize + 1];
    let result = owner
        .start::<_, anyhow::Error>(async move {
            observed.store(true, Ordering::Release);
            std::future::pending::<()>().await;
            std::hint::black_box(payload);
            Err(anyhow::anyhow!("unreachable"))
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
    fn apply_with_publisher(
        &self,
        _: &crate::AppliedEntryContext,
        input: crate::AppliedInput<'_>,
        publisher: &mut dyn crate::ApplyPublisher,
    ) -> std::result::Result<(), kasumi_store::ScratchOperationFailure> {
        let crate::AppliedInput::Command(bytes) = input else {
            publisher
                .commit(crate::AppliedResponse::application(Vec::new()), &[])
                .map_err(anyhow::Error::from)?;
            return Ok(());
        };
        publisher
            .commit(crate::AppliedResponse::application(bytes.to_vec()), &[])
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
    fn capture_snapshot(
        &self,
    ) -> std::result::Result<crate::CapturedSnapshot, kasumi_store::ScratchOperationFailure> {
        Ok(crate::CapturedSnapshot::new(None, |_| Ok(())))
    }
    fn validate_snapshot(
        &self,
        _: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Option<crate::RetiredSnapshotState>,
        kasumi_store::ScratchOperationFailure,
    > {
        Ok(None)
    }
    fn prepare_restore<'a>(
        &'a self,
        _: &crate::SnapshotRestoreContext,
        _: &mut dyn std::io::Read,
    ) -> std::result::Result<
        Box<dyn crate::PreparedStateMachineRestore + 'a>,
        kasumi_store::ScratchOperationFailure,
    > {
        Err(anyhow::anyhow!("empty startup fixture has no snapshot").into())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_local_initialization_drains_real_group_and_breaks_router_cycle()
-> FixtureResult<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let store = kasumi_store::TenantStorageSet::initialize_catalogs_fixture(
        kasumi_store::NodeStore::create_new_fixture(
            directory.path().join("startup.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
            fixture_scratch.memory().clone(),
            fixture_scratch.clone(),
        )?,
        "tenant-a".into(),
        Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([19; 32])),
        Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([241; 32])),
    )
    .await?;
    store.write_batch(&[], &crate::initial_storage_identity(1, "tenant-a")?)?;
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
async fn startup_census_closes_delivery_before_waiting_for_active_caller() -> FixtureResult<()> {
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let (return_group, group_ready) = tokio::sync::oneshot::channel();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, paused) = mpsc::channel();
    let mut startup = Box::pin(owner.start::<_, anyhow::Error>(async move {
        let child = tokio::task::spawn_blocking(move || {
            let _ = entered.send(tokio::task::id());
            paused.recv_timeout(WAIT).unwrap();
            std::panic::panic_any(OriginalFailure(101));
        });
        group_ready.await?;
        Ok(StartedGroup::Fixture(FixtureGroup {
            child,
            report: DrainReport::default(),
            retained: None,
            _held: None,
            panic_cleanup: false,
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
                .any(|next| kasumi_types::drain::DrainIssueRef::ptr_eq(next, &issue))
        );
    }
    let all_resources = owner.drain().await.unwrap_err();
    assert_eq!(all_resources.completion(), DrainCompletion::Retained);
    assert!(
        all_resources
            .issues()
            .iter()
            .any(|next| kasumi_types::drain::DrainIssueRef::ptr_eq(next, &issue))
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
async fn direct_claim_poll_panic_keeps_original_payload_future_and_registry() -> FixtureResult<()> {
    let (charge, charge_retired) = crate::test_utils::observed_budget_charge();
    let owner = SnapshotBufferOwner::new(1, charge)?;
    let weak = Arc::downgrade(&owner);
    let (state, future) =
        direct_poll_future::<Result<StartedGroup, kasumi_store::ScratchOperationFailure>>(true);
    let failure = match owner.start(future).await {
        Err(kasumi_store::ScratchOperationFailure::Operation(error)) => {
            error.downcast::<kasumi_types::drain::DrainFailure>()?
        }
        Err(original) => return Err(original.into()),
        Ok(_) => panic!("direct poll panic cannot deliver a group"),
    };
    assert_original_poll_panic_retained(&owner, &state, failure).await;
    drop(owner);
    assert!(
        weak.upgrade().is_some(),
        "unresolved startup lost registry custody"
    );
    assert!(!charge_retired.load(std::sync::atomic::Ordering::Acquire));
    Ok(())
}

#[tokio::test]
async fn direct_abandoned_opening_poll_panic_is_never_repolled_by_drain() -> FixtureResult<()> {
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let (state, future) =
        direct_poll_future::<Result<StartedGroup, kasumi_store::ScratchOperationFailure>>(false);
    let mut startup = Box::pin(owner.start(future));
    pending(startup.as_mut()).await;
    drop(startup);
    state.armed.store(true, Ordering::Release);
    let failure = owner.drain_startup().await.unwrap_err();
    assert_original_poll_panic_retained(&owner, &state, failure).await;
    Ok(())
}

#[tokio::test]
async fn direct_cleanup_poll_panic_keeps_original_payload_and_exact_cleanup_future()
-> FixtureResult<()> {
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let (state, future) = direct_poll_future::<kasumi_types::drain::DrainResult>(true);
    owner.install_cleanup_fixture(future).await;
    let failure = owner.drain_startup().await.unwrap_err();
    assert_original_poll_panic_retained(&owner, &state, failure).await;
    Ok(())
}

#[tokio::test]
async fn cleanup_retained_result_cannot_be_promoted_to_complete_or_release_custody()
-> FixtureResult<()> {
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let weak = Arc::downgrade(&owner);
    let guard = owner.scratch_failure_guard()?;
    let earlier = owner.drain_buffers().await.unwrap_err();
    assert_eq!(earlier.completion(), DrainCompletion::Retained);
    let buffer_issue = earlier.issues()[0].clone();
    assert_eq!(guard.capture_result(Ok(41)).unwrap(), 41);
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
                .any(|next| kasumi_types::drain::DrainIssueRef::ptr_eq(next, &issue))
        );
        assert!(
            failure
                .issues()
                .iter()
                .any(|next| kasumi_types::drain::DrainIssueRef::ptr_eq(next, &buffer_issue))
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
async fn synchronous_enrollment_allows_census_before_the_claimant_is_polled() -> FixtureResult<()> {
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let polled = Arc::new(AtomicBool::new(false));
    let observed = polled.clone();
    let claimant = owner.start::<_, anyhow::Error>(async move {
        observed.store(true, Ordering::Release);
        Ok(StartedGroup::Fixture(FixtureGroup {
            child: tokio::spawn(async {}),
            report: DrainReport::default(),
            retained: None,
            _held: None,
            panic_cleanup: false,
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
            .operation_error()
            .expect("original startup diagnostic is an ordinary failure")
            .downcast_ref::<kasumi_types::drain::DrainFailure>()
            .unwrap()
            .completion(),
        DrainCompletion::Complete
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn panicked_core_closes_group_access_and_drains_complete_for_reopen() -> FixtureResult<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let store = kasumi_store::TenantStorageSet::initialize_catalogs_fixture(
        kasumi_store::NodeStore::create_new_fixture(
            directory.path().join("core-fatal.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
            fixture_scratch.memory().clone(),
            fixture_scratch.clone(),
        )?,
        "tenant-a".into(),
        Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([23; 32])),
        Arc::new(kasumi_store::test_utils::LocalKeyProvider::new([229; 32])),
    )
    .await?;
    store.write_batch(&[], &crate::initial_storage_identity(1, "tenant-a")?)?;
    let group = crate::RaftGroup::local(
        1,
        "tenant-a".into(),
        store.clone(),
        Arc::new(Backend),
        SnapshotBufferOwner::fixture(),
    )
    .await?;
    group.check_access()?;
    assert_eq!(group.access_failure_class(), None);
    // A panicking core cannot publish its Fatal in metrics. Dropping its
    // task-owned metrics sender must still close access immediately.
    group
        .raft()
        .external_request(|_| panic!("fixture Raft core panic"));
    tokio::time::timeout(WAIT, async {
        while group.check_access().is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    assert!(group.raft().metrics().borrow().running_state.is_ok());
    assert_eq!(group.access_failure_class(), Some("raft_core_failed"));
    let failure = group.shutdown().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert!(
        failure
            .issues()
            .iter()
            .any(|issue| issue.component() == "OpenRaft runtime")
    );
    assert!(group.check_access().is_err());
    assert!(group.access_failure_class().is_some());
    drop(group);
    let reopened = crate::RaftGroup::local(
        1,
        "tenant-a".into(),
        store,
        Arc::new(Backend),
        SnapshotBufferOwner::fixture(),
    )
    .await?;
    reopened.check_access()?;
    reopened.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn retained_cleanup_keeps_exact_group_after_shutdown_future_returns() -> FixtureResult<()> {
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let weak_owner = Arc::downgrade(&owner);
    let group_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let held = Arc::new(HeldGroup {
        drops: group_drops.clone(),
    });
    let weak_group = Arc::downgrade(&held);
    let mut report = DrainReport::default();
    let issue = report.record("retained group fixture", 0, OriginalFailure(173).into());
    let retained = kasumi_types::drain::DrainFailure::retained(issue);
    let claimant = owner.start::<_, anyhow::Error>(async move {
        Ok(StartedGroup::Fixture(FixtureGroup {
            child: tokio::spawn(async {}),
            report: DrainReport::default(),
            retained: Some(retained),
            _held: Some(held),
            panic_cleanup: false,
        }))
    });
    // The lifecycle takes an unclaimed group, including its exact held resource.
    let failure = owner.drain_startup().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Retained);
    drop(claimant);
    assert!(weak_group.upgrade().is_some());
    assert_eq!(
        owner.drain_startup().await.unwrap_err().completion(),
        DrainCompletion::Retained
    );
    drop(owner);
    assert!(weak_owner.upgrade().is_some());
    assert!(weak_group.upgrade().is_some());
    assert_eq!(group_drops.load(Ordering::Acquire), 0);
    Ok(())
}

#[tokio::test]
async fn delivered_apply_failure_keeps_registry_and_fence_after_all_facades_drop()
-> FixtureResult<()> {
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let weak_owner = Arc::downgrade(&owner);
    let ownership = Arc::new(AtomicBool::new(true));
    let weak_fence = Arc::downgrade(&ownership);
    let identity_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let identity = Arc::new(HeldGroup {
        drops: identity_drops.clone(),
    });
    let weak_identity = Arc::downgrade(&identity);
    owner.bind_fixture_group_ownership(ownership, identity)?;
    let group = owner
        .start::<_, anyhow::Error>(async {
            Ok(StartedGroup::Fixture(FixtureGroup {
                child: tokio::spawn(async {}),
                report: DrainReport::default(),
                retained: None,
                _held: None,
                panic_cleanup: false,
            }))
        })
        .await?;
    drop(owner.retain_apply_failure(OriginalFailure(181).into()));
    let failure = owner.drain_buffers().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Retained);
    drop(failure);
    drop(group);
    drop(owner);
    let retained = weak_owner
        .upgrade()
        .expect("pre-admitted registry root must survive delivery");
    assert!(weak_fence.upgrade().unwrap().load(Ordering::Acquire));
    assert!(weak_identity.upgrade().is_some());
    assert_eq!(identity_drops.load(Ordering::Acquire), 0);
    assert_eq!(
        retained.drain_startup().await.unwrap_err().completion(),
        DrainCompletion::Retained
    );
    retained
        .apply_failure()
        .unwrap()
        .try_with_report(|report| {
            let crate::RetainedApplyReport::Single(original) = report else {
                panic!("non-completion startup failure requires its single original")
            };
            assert!(original.downcast_ref::<OriginalFailure>().is_some());
        })
        .expect("settled startup failure report is busy");
    Ok(())
}

#[tokio::test]
async fn positive_delivered_shutdown_releases_existing_registry_root_and_fence() -> FixtureResult<()>
{
    let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32);
    let baseline = memory.snapshot();
    let owner = paid_snapshot_owner(&memory)?;
    let weak_owner = Arc::downgrade(&owner);
    let ownership = Arc::new(AtomicBool::new(true));
    let identity_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let identity = Arc::new(HeldGroup {
        drops: identity_drops.clone(),
    });
    let weak_identity = Arc::downgrade(&identity);
    owner.bind_fixture_group_ownership(ownership.clone(), identity)?;
    let admitted = memory.snapshot();
    let guard = owner.scratch_failure_guard()?;
    let (storage, lease) = crate::lifetime::StorageDrain::new();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, paused) = tokio::sync::oneshot::channel();
    let child = tokio::spawn(async move {
        entered.send(()).unwrap();
        paused.await.unwrap();
        assert_eq!(guard.capture_result(Ok(17)).unwrap(), 17);
        // The actual final storage lease cannot wake shutdown before the
        // admitted constructor claim has returned and released its seat.
        drop(lease);
    });
    let group = owner
        .start(async move {
            Ok::<_, kasumi_store::ScratchOperationFailure>(StartedGroup::Fixture(FixtureGroup {
                child,
                report: DrainReport::default(),
                retained: None,
                _held: None,
                panic_cleanup: false,
            }))
        })
        .await?;
    drop(owner);
    let owner = weak_owner
        .upgrade()
        .expect("active delivered group retains admitted root");
    tokio::time::timeout(WAIT, ready).await??;
    let earlier = owner.drain_buffers().await.unwrap_err();
    assert_eq!(earlier.completion(), DrainCompletion::Retained);
    assert_eq!(earlier.issues().len(), 1);
    let original_issue = earlier.issues()[0].clone();
    assert!(!owner.apply_slot().completion().failed());
    owner.release_group_ownership();
    assert!(ownership.load(Ordering::Acquire));
    assert!(weak_identity.upgrade().is_some());
    assert_eq!(identity_drops.load(Ordering::Acquire), 0);
    assert_eq!(memory.snapshot(), admitted);
    let mut waiting = Box::pin(storage.wait());
    pending(waiting.as_mut()).await;
    drop(waiting);
    release.send(()).unwrap();
    match group {
        StartedGroup::Fixture(mut group) => group.shutdown().await?,
        _ => unreachable!(),
    }
    tokio::time::timeout(WAIT, storage.wait()).await?;
    owner.drain_application_sources().await?;
    let mut report = DrainReport::default();
    report.merge(&earlier);
    let unresolved = owner
        .finish_failed_buffer_drain(Some(earlier), &mut report)
        .await;
    assert!(unresolved.is_none());
    assert!(!owner.apply_slot().completion().failed());
    let completed = report.complete().unwrap_err();
    assert_eq!(completed.completion(), DrainCompletion::Complete);
    assert!(
        completed
            .issues()
            .iter()
            .any(|issue| { kasumi_types::drain::DrainIssueRef::ptr_eq(issue, &original_issue) })
    );
    assert!(ownership.load(Ordering::Acquire));
    owner.release_group_ownership();
    assert!(!ownership.load(Ordering::Acquire));
    assert!(weak_identity.upgrade().is_none());
    assert_eq!(identity_drops.load(Ordering::Acquire), 1);
    drop(owner);
    assert!(weak_owner.upgrade().is_none());
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    Ok(())
}

#[tokio::test]
async fn delivered_shutdown_keeps_actual_initial_quote_original_after_worker_and_storage_join()
-> FixtureResult<()> {
    use kasumi_store::{
        DiskMemoryLease, EncryptedTable, NativeConstructorProbe, NodeDiskMemoryAdmission,
        ScratchDisk, ScratchOperationFailure, StorageCensusDisposition,
    };
    let memory = kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 32);
    let directory = kasumi_store::test_utils::private_tempdir()?;
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let owner = paid_snapshot_owner(&memory)?;
    let weak_owner = Arc::downgrade(&owner);
    let ownership = Arc::new(AtomicBool::new(true));
    let identity_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let identity = Arc::new(HeldGroup {
        drops: identity_drops.clone(),
    });
    let weak_identity = Arc::downgrade(&identity);
    owner.bind_fixture_group_ownership(ownership.clone(), identity)?;
    let before_fill = memory.snapshot();
    let mut fillers: [Option<DiskMemoryLease>; 32] = std::array::from_fn(|_| None);
    for slot in fillers.iter_mut().take(32 - before_fill.live_reservations) {
        *slot = Some(memory.clone().reserve_installed(0)?);
    }
    let full = memory.snapshot();
    let disk_before = disk.snapshot();
    let original_census = memory.storage_census().snapshot();
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let mut receivers: [Option<NativeConstructorProbe>; 32] = std::array::from_fn(|_| None);
    for receiver in receivers
        .iter_mut()
        .take(original_census.capacity - original_census.databases)
    {
        *receiver = Some(NativeConstructorProbe::prepare(provider.clone(), 0)?);
    }
    // Claim every actual prepaid receiver without entering its provider. The
    // ensuing refusal belongs to the original source's admission slot because
    // no native constructor receiver can yet take custody of that failure.
    assert_eq!(memory.snapshot(), full);
    let census_before = memory.storage_census().snapshot();
    assert_eq!(census_before.databases, census_before.capacity);
    let guard = owner.scratch_failure_guard()?;
    let (storage, lease) = crate::lifetime::StorageDrain::new();
    let (entered, ready) = tokio::sync::oneshot::channel();
    let (release, paused) = tokio::sync::oneshot::channel();
    let (original_address, address_ready) = tokio::sync::oneshot::channel();
    let captured_disk = disk.clone();
    let child = tokio::spawn(async move {
        entered.send(()).unwrap();
        paused.await.unwrap();
        let original = EncryptedTable::new(
            &captured_disk,
            8 << 20,
            kasumi_kv::CacheConfig { byte_limit: 0 },
        )
        .err()
        .expect("actual first constructor quote must be refused");
        assert_eq!(original.owner_id(), None);
        let returned = guard
            .capture_result::<()>(Err(original.into()))
            .unwrap_err();
        let ScratchOperationFailure::Creation(original) = returned else {
            panic!("the actual original must remain a creation owner")
        };
        let address = original.with_diagnostic(|report| {
            let report = report.unwrap();
            let error = report.admission_error().unwrap();
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
            assert!(report.constructor_report().is_none());
            assert!(report.opening_error().is_none());
            std::ptr::from_ref(error) as usize
        });
        original_address.send(address).unwrap();
        drop(original);
        drop(lease);
    });
    let group = owner
        .start(async move { Ok::<_, ScratchOperationFailure>(source_custody_fixture_group(child)) })
        .await?;
    tokio::time::timeout(WAIT, ready).await??;
    let earlier = owner.drain_buffers().await.unwrap_err();
    assert_eq!(earlier.completion(), DrainCompletion::Retained);
    let original_issue = earlier.issues()[0].clone();
    release.send(()).unwrap();
    match group {
        StartedGroup::Fixture(mut group) => group.shutdown().await?,
        _ => unreachable!(),
    }
    tokio::time::timeout(WAIT, storage.wait()).await?;
    let address = tokio::time::timeout(WAIT, address_ready).await??;
    owner.drain_application_sources().await?;
    let after = memory.snapshot();
    assert_eq!(after.attempts, full.attempts);
    assert_eq!(after.used_bytes, full.used_bytes);
    assert_eq!(after.live_reservations, full.live_reservations);
    let disk_after = disk.snapshot();
    assert_eq!(disk_after.live_files, disk_before.live_files);
    assert_eq!(disk_after.charged_bytes, disk_before.charged_bytes);
    assert_eq!(memory.storage_census().snapshot(), census_before);
    let mut report = DrainReport::default();
    report.merge(&earlier);
    let unresolved = owner
        .finish_failed_buffer_drain(Some(earlier), &mut report)
        .await
        .expect("an occupied original cannot retire with its worker");
    assert_eq!(unresolved.completion(), DrainCompletion::Retained);
    assert!(
        unresolved
            .issues()
            .iter()
            .any(|issue| { kasumi_types::drain::DrainIssueRef::ptr_eq(issue, &original_issue) })
    );
    for _ in 0..2 {
        let original = owner.retained_scratch_admission(0).unwrap();
        assert_eq!(original.owner_id(), None);
        assert_eq!(
            original.with_diagnostic(|report| {
                std::ptr::from_ref(report.unwrap().admission_error().unwrap()) as usize
            }),
            address
        );
        assert_eq!(
            original.retire().disposition(),
            StorageCensusDisposition::Retained
        );
    }
    owner.release_group_ownership();
    assert!(ownership.load(Ordering::Acquire));
    assert!(weak_identity.upgrade().is_some());
    assert_eq!(identity_drops.load(Ordering::Acquire), 0);
    let mut refused_receivers = 0;
    for receiver in receivers.iter_mut().filter_map(Option::take) {
        assert!(!receiver.run());
        receiver.with_report(|report| {
            assert!(report.capacity_refused());
            assert_eq!(report.protocol(), None);
            assert!(!report.has_lease());
            assert!(!report.has_payload());
            assert!(matches!(
                report.provider(),
                kasumi_kv::TerminalObservation::Returned(Err(original))
                    if original.kind() == std::io::ErrorKind::OutOfMemory
            ));
            assert!(matches!(
                report.construction(),
                kasumi_kv::TerminalObservation::NotEntered
            ));
        });
        assert_eq!(receiver.cleanup(), StorageCensusDisposition::Retired);
        refused_receivers += 1;
    }
    assert_eq!(
        refused_receivers,
        census_before.capacity - original_census.databases
    );
    assert_eq!(
        memory.snapshot().attempts,
        full.attempts + refused_receivers as u64
    );
    assert_eq!(memory.storage_census().snapshot(), original_census);
    drop(fillers);
    assert_eq!(memory.snapshot().used_bytes, before_fill.used_bytes);
    assert_eq!(
        memory.snapshot().live_reservations,
        before_fill.live_reservations
    );
    drop(owner);
    assert!(weak_owner.upgrade().is_some());
    assert!(ownership.load(Ordering::Acquire));
    Ok(())
}

#[tokio::test]
async fn actual_group_cleanup_poll_panic_keeps_group_outside_unwinding_generator()
-> FixtureResult<()> {
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
    let weak_owner = Arc::downgrade(&owner);
    let group_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let held = Arc::new(HeldGroup {
        drops: group_drops.clone(),
    });
    let weak_group = Arc::downgrade(&held);
    let claimant = owner.start::<_, anyhow::Error>(async move {
        Ok(StartedGroup::Fixture(FixtureGroup {
            child: tokio::spawn(async {}),
            report: DrainReport::default(),
            retained: None,
            _held: Some(held),
            panic_cleanup: true,
        }))
    });
    let failure = owner.drain_startup().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Retained);
    let issue = failure
        .issues()
        .iter()
        .find(|issue| {
            issue
                .error()
                .downcast_ref::<crate::startup_owner::StartupPollPanic>()
                .is_some()
        })
        .unwrap();
    let panic = issue
        .error()
        .downcast_ref::<crate::startup_owner::StartupPollPanic>()
        .unwrap();
    assert_eq!(
        panic
            .payload
            .lock()
            .unwrap()
            .downcast_ref::<OriginalFailure>()
            .unwrap()
            .0,
        193
    );
    assert!(
        weak_group.upgrade().is_some(),
        "unwinding cleanup dropped the actual group"
    );
    drop(claimant);
    let repeated = owner.drain_startup().await.unwrap_err();
    assert_eq!(repeated.completion(), DrainCompletion::Retained);
    assert!(weak_group.upgrade().is_some());
    drop(owner);
    assert!(weak_owner.upgrade().is_some());
    assert!(weak_group.upgrade().is_some());
    assert_eq!(group_drops.load(Ordering::Acquire), 0);
    Ok(())
}
