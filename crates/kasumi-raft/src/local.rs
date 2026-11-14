//! A single durable writer, without a consensus runtime. The existing journal
//! encoding keeps older one-voter installations recoverable. Its positions are
//! storage identities; no election, network peer, or quorum task is started.
use crate::{BasicNode, Entry, LogId, LogStore, RaftCommand, TypeConfig, storage::LocalAppend};
use anyhow::{Context, Result, ensure};
use openraft::{
    CommittedLeaderId, EntryPayload, Membership, RaftLogReader, RaftMetrics, ServerState,
    storage::{RaftLogStorage, RaftStateMachine},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

type Metrics = RaftMetrics<u64, BasicNode>;
type Worker = tokio::sync::Mutex<Option<tokio::task::JoinHandle<Result<()>>>>;
#[cfg(any(test, feature = "test-utils"))]
type FixtureHook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

// Match the existing default journal retention threshold. Local compaction
// requires no heartbeat or periodic background task.
const SNAPSHOT_INTERVAL: u64 = 5000;

pub(crate) struct LocalGroup<M: RaftStateMachine<TypeConfig>> {
    /// The group identity, only for operator diagnostics.
    group: Arc<str>,
    state: Arc<tokio::sync::Mutex<Option<LocalState<M>>>>,
    metrics: Arc<Mutex<Metrics>>,
    closed: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    worker: Worker,
    snapshot_worker: Arc<Worker>,
    report: Arc<Mutex<kasumi_types::drain::DrainReport>>,
    /// Snapshot builds that ended published since this writer opened. A build at
    /// the stored snapshot's own position re-serves that stored image and still
    /// counts; a deferred or failed build never does.
    published: Arc<AtomicU64>,
    #[cfg(any(test, feature = "test-utils"))]
    before_apply: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(any(test, feature = "test-utils"))]
    before_snapshot: FixtureHook,
    #[cfg(any(test, feature = "test-utils"))]
    refuse_next_blank: AtomicBool,
    #[cfg(any(test, feature = "test-utils"))]
    joined: Arc<JoinedAppends>,
}

struct LocalState<M: RaftStateMachine<TypeConfig>> {
    log: LogStore,
    machine: M,
    next_index: u64,
    term: u64,
    id: u64,
    snapshot_index: Option<u64>,
    snapshot_interval: u64,
    #[cfg(any(test, feature = "test-utils"))]
    joined: Arc<JoinedAppends>,
}

/// Standalone appends that asked to join their journal record to their
/// publication, by outcome, since this writer opened.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Default)]
pub(crate) struct JoinedAppends {
    applied: AtomicU64,
    refused_before_publication: AtomicU64,
    refused_publication: AtomicU64,
    groups: AtomicU64,
}
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JoinedAppendCounts {
    /// Committed and applied in one transaction (or, if an ahead write
    /// committed the record first, in that order).
    pub applied: u64,
    /// Refused for capacity while preparing the record; nothing was written.
    pub refused_before_publication: u64,
    /// The publication carrying the record was refused for capacity.
    pub refused_publication: u64,
    /// Groups of several appends committed in one transaction; their entries
    /// also count in `applied`.
    pub groups: u64,
}

// What a snapshot task shares with its group.
struct SnapshotWork {
    group: Arc<str>,
    metrics: Arc<Mutex<Metrics>>,
    worker: Arc<Worker>,
    /// The group is shutting down: a running build and purge stop yielding
    /// to foreground operations and finish back to back.
    closing: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    report: Arc<Mutex<kasumi_types::drain::DrainReport>>,
    published: Arc<AtomicU64>,
    #[cfg(any(test, feature = "test-utils"))]
    before_build: FixtureHook,
}

/// What one standalone snapshot build left behind.
pub(crate) enum LocalSnapshot {
    /// Durably published, covering every entry through this position.
    Published(Option<LogId<u64>>),
    /// Refused for capacity before publishing. The published snapshot, the
    /// applied state and the journal are unchanged; staged chunks are
    /// crash-equivalent and removed by the next build or open.
    Deferred,
}

/// A machine whose application entries can commit their journal record in
/// their own publication's transaction. Others append, then apply.
pub(crate) trait LocalJoinedApply {
    fn joined(&mut self) -> Option<&mut crate::StateMachine> {
        None
    }
}
impl LocalJoinedApply for crate::StateMachine {
    fn joined(&mut self) -> Option<&mut crate::StateMachine> {
        Some(self)
    }
}

/// A state machine's snapshot builder as the standalone writer runs it: in
/// the background of its group and of every other tenant of the node
/// database, so a build of many commits yields to foreground operations
/// between them until `closing` is set.
pub(crate) trait LocalSnapshotBuilder {
    fn build_local(
        &mut self,
        closing: &Arc<AtomicBool>,
    ) -> impl std::future::Future<Output = Result<LocalSnapshot, openraft::StorageError<u64>>> + Send;
}

// One appended entry, or a proof that capacity was refused before any of it
// reached the journal.
enum Appended {
    Applied(Vec<u8>, LogId<u64>),
    Refused,
}

/// One command's result in a standalone group write: its response, or a
/// capacity refusal that proves it reached neither the journal nor the state.
pub(crate) type GroupMemberResult = std::result::Result<Vec<u8>, crate::LocalAppendCapacityDenied>;

// Lives in the actual worker, including across a cancelled request waiter.
// A panic or persistence failure fences the whole writer until recovery.
struct WorkFence {
    failed: Arc<AtomicBool>,
    complete: bool,
}
impl Drop for WorkFence {
    fn drop(&mut self) {
        if !self.complete {
            self.failed.store(true, Ordering::Release);
        }
    }
}

pub(crate) fn check_membership(membership: &Membership<u64, BasicNode>, id: u64) -> Result<()> {
    ensure!(
        membership.get_joint_config() == &[BTreeSet::from([id])]
            && membership
                .nodes()
                .map(|(node, _)| *node)
                .collect::<Vec<_>>()
                == [id],
        "standalone storage requires exactly the local voter and no remote members"
    );
    Ok(())
}

impl<M> LocalGroup<M>
where
    M: RaftStateMachine<TypeConfig> + LocalJoinedApply + Send + Sync + 'static,
    M::SnapshotBuilder: LocalSnapshotBuilder,
{
    pub(crate) async fn open(
        id: u64,
        group: &str,
        mut log: LogStore,
        mut machine: M,
        failed: Arc<AtomicBool>,
    ) -> Result<Self> {
        let mut logs = log.get_log_state().await?;
        let saved_committed = log.read_committed().await?;
        let (applied, membership) = machine.applied_state().await?;
        if membership.log_id().is_some() {
            check_membership(membership.membership(), id)?;
        }
        // Inspect every retained membership before repairing snapshot-covered
        // logs: recovery must never erase evidence of a clustered deployment.
        log.validate_local_membership(id).await?;
        // A validated installed snapshot is independently committed coverage.
        // Legacy Raft could crash after installing it but before saving the log
        // commit/purge cursors. Repair that window before replaying the suffix.
        let committed = saved_committed.max(applied);
        if (saved_committed < applied || logs.last_log_id < applied)
            && let Some(snapshot_floor) = applied
        {
            log.purge(snapshot_floor).await?;
            logs = log.get_log_state().await?;
        }
        if saved_committed < committed {
            log.save_committed(committed).await?;
        }
        ensure!(
            logs.last_log_id >= committed,
            "local committed journal is incomplete"
        );
        let end = match logs.last_log_id {
            Some(log) => log
                .index
                .checked_add(1)
                .context("local journal index exhausted")?,
            None => 0,
        };
        // The saved vote is read only for legacy term continuity. Local mode
        // neither casts votes nor changes terms on a timer.
        let term = log
            .read_vote()
            .await?
            .map_or(0, |vote| vote.leader_id.term)
            .max(logs.last_log_id.map_or(0, |log| log.leader_id.term))
            .max(1);
        let mut cursor = applied.map_or(0, |log| log.index + 1);
        let committed_end = committed.map_or(0, |log| log.index + 1);
        while cursor < committed_end {
            let entries = log.limited_get_log_entries(cursor, committed_end).await?;
            ensure!(
                !entries.is_empty(),
                "committed local journal contains a gap"
            );
            for entry in &entries {
                ensure!(
                    entry.log_id.index == cursor,
                    "committed local journal contains a gap"
                );
                cursor += 1;
            }
            machine.apply(entries).await?;
        }
        if end > committed_end {
            let entry = log
                .try_get_log_entries(committed_end..=committed_end)
                .await?
                .pop()
                .context("uncommitted local journal prefix is missing")?;
            log.truncate(entry.log_id).await?;
        }
        let mut state = LocalState {
            log,
            machine,
            next_index: committed_end,
            term,
            id,
            snapshot_index: applied.map(|log| log.index),
            snapshot_interval: SNAPSHOT_INTERVAL,
            #[cfg(any(test, feature = "test-utils"))]
            joined: Default::default(),
        };
        #[cfg(any(test, feature = "test-utils"))]
        let joined = state.joined.clone();
        if committed.is_none() {
            let appended = state
                .append(
                    EntryPayload::Membership(Membership::from(BTreeMap::from([(
                        id,
                        BasicNode::new("local"),
                    )]))),
                    false,
                )
                .await?;
            // A refused first entry leaves an empty journal to initialize again.
            ensure!(
                matches!(appended, Appended::Applied(..)),
                crate::LocalAppendCapacityDenied
            );
        }
        let (last_applied, membership) = state.machine.applied_state().await?;
        check_membership(membership.membership(), id)?;
        let mut metrics = Metrics::new_initial(id);
        metrics.current_term = term;
        metrics.last_log_index = last_applied.map(|log| log.index);
        metrics.last_applied = last_applied;
        metrics.snapshot = applied;
        metrics.purged = logs.last_purged_log_id;
        metrics.state = ServerState::Leader;
        metrics.current_leader = Some(id);
        metrics.membership_config = Arc::new(membership);
        Ok(Self {
            group: group.into(),
            state: Arc::new(tokio::sync::Mutex::new(Some(state))),
            metrics: Arc::new(Mutex::new(metrics)),
            closed: Arc::new(AtomicBool::new(false)),
            failed,
            worker: Default::default(),
            snapshot_worker: Default::default(),
            report: Default::default(),
            published: Default::default(),
            #[cfg(any(test, feature = "test-utils"))]
            before_apply: Default::default(),
            #[cfg(any(test, feature = "test-utils"))]
            before_snapshot: Default::default(),
            #[cfg(any(test, feature = "test-utils"))]
            refuse_next_blank: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-utils"))]
            joined,
        })
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn joined_appends(&self) -> JoinedAppendCounts {
        JoinedAppendCounts {
            applied: self.joined.applied.load(Ordering::Acquire),
            refused_before_publication: self
                .joined
                .refused_before_publication
                .load(Ordering::Acquire),
            refused_publication: self.joined.refused_publication.load(Ordering::Acquire),
            groups: self.joined.groups.load(Ordering::Acquire),
        }
    }

    pub(crate) fn ended(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire)
    }

    pub(crate) fn current_term(&self) -> u64 {
        self.metrics
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .current_term
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn fixture_before_apply(&self, hook: Box<dyn FnOnce() + Send>) -> Result<()> {
        let mut installed = self.before_apply.lock().unwrap();
        ensure!(
            installed.is_none(),
            "local apply fixture hook already installed"
        );
        *installed = Some(hook);
        Ok(())
    }

    /// Runs once inside the next snapshot task, after its capture and before
    /// its build.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn fixture_before_snapshot(&self, hook: Box<dyn FnOnce() + Send>) -> Result<()> {
        let mut installed = self.before_snapshot.lock().unwrap();
        ensure!(
            installed.is_none(),
            "local snapshot fixture hook already installed"
        );
        *installed = Some(hook);
        Ok(())
    }

    /// Refuse the next Blank append for capacity, as a full journal store refuses
    /// an append: nothing reaches the journal and the writer serves on. Commands
    /// (a background audit worker's, say) are unaffected.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn fixture_refuse_next_blank(&self) {
        self.refuse_next_blank.store(true, Ordering::Release);
    }

    /// Entries appended between periodic snapshots.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) async fn fixture_snapshot_interval(&self, entries: u64) -> Result<()> {
        ensure!(entries > 0, "local snapshot interval must be positive");
        self.check()?;
        let mut worker = self.worker.lock().await;
        self.finish_worker(&mut worker).await;
        self.check()?;
        self.state
            .lock()
            .await
            .as_mut()
            .context("local writer has shut down")?
            .snapshot_interval = entries;
        Ok(())
    }

    /// Join the write worker and then the current snapshot task, exactly as
    /// the next snapshot would: a failed task has already fenced the writer.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) async fn fixture_snapshot_settled(&self) -> Result<()> {
        self.snapshot_settled().await
    }

    /// Snapshot builds that ended published since this writer opened, including a
    /// re-served stored image at an unchanged position. A deferred or failed build
    /// never counts; compare stored positions to learn whether bytes changed.
    pub(crate) fn published_snapshots(&self) -> u64 {
        self.published.load(Ordering::Acquire)
    }

    /// Join the write worker and then the current snapshot task, exactly as
    /// the next snapshot would: a failed task has already fenced the writer.
    pub(crate) async fn snapshot_settled(&self) -> Result<()> {
        let mut worker = self.worker.lock().await;
        self.finish_worker(&mut worker).await;
        let mut snapshot = self.snapshot_worker.lock().await;
        finish_task(
            &mut snapshot,
            &self.failed,
            &self.report,
            "Local snapshot worker",
        )
        .await;
        drop(snapshot);
        drop(worker);
        self.check()
    }

    fn snapshot_work(&self) -> SnapshotWork {
        SnapshotWork {
            group: self.group.clone(),
            metrics: self.metrics.clone(),
            worker: self.snapshot_worker.clone(),
            closing: self.closed.clone(),
            failed: self.failed.clone(),
            report: self.report.clone(),
            published: self.published.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            before_build: self.before_snapshot.clone(),
        }
    }

    pub(crate) fn metrics(&self) -> Metrics {
        let mut metrics = self
            .metrics
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if self.closed.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire) {
            metrics.running_state = Err(openraft::error::Fatal::Stopped);
            metrics.state = ServerState::Shutdown;
            metrics.current_leader = None;
        }
        metrics
    }

    fn check(&self) -> Result<()> {
        ensure!(
            !self.closed.load(Ordering::Acquire),
            "local writer has shut down"
        );
        ensure!(
            !self.failed.load(Ordering::Acquire),
            "local writer requires recovery"
        );
        Ok(())
    }

    async fn finish_worker(&self, worker: &mut Option<tokio::task::JoinHandle<Result<()>>>) {
        finish_task(worker, &self.failed, &self.report, "Local storage worker").await;
    }

    pub(crate) async fn write(&self, command: RaftCommand) -> Result<Vec<u8>> {
        self.append_payload(EntryPayload::Normal(command), false)
            .await
    }

    /// An application command whose apply publishes through the installed
    /// ordinary completion and stages nothing durable before that
    /// publication: its journal record commits in the same transaction.
    pub(crate) async fn write_joined(&self, command: RaftCommand) -> Result<Vec<u8>> {
        self.append_payload(EntryPayload::Normal(command), true)
            .await
    }

    /// [`Self::write_joined`] for several commands, in order. A machine that
    /// applies groups commits them as consecutive entries in one transaction
    /// with their one publication, and a capacity refusal of it refuses every
    /// command; otherwise each is written by itself. Any other failure fences
    /// the writer, as one command's does.
    pub(crate) async fn write_joined_group(
        &self,
        commands: Vec<RaftCommand>,
    ) -> Result<Vec<GroupMemberResult>> {
        self.check()?;
        let mut worker = self.worker.lock().await;
        self.finish_worker(&mut worker).await;
        self.check()?;
        let mut guard = self.state.clone().lock_owned().await;
        self.check()?;
        let metrics = self.metrics.clone();
        let failed = self.failed.clone();
        let snapshot = self.snapshot_work();
        let (response, receive) = tokio::sync::oneshot::channel();
        #[cfg(any(test, feature = "test-utils"))]
        let before_apply = self.before_apply.lock().unwrap().take();
        // As append_payload: the retained worker owns the serialization guard.
        *worker = Some(tokio::spawn(async move {
            let mut fence = WorkFence {
                failed: failed.clone(),
                complete: false,
            };
            let state = guard.as_mut().context("local writer has shut down")?;
            #[cfg(any(test, feature = "test-utils"))]
            if let Some(hook) = before_apply {
                tokio::task::spawn_blocking(hook).await?;
            }
            let count = commands.len();
            let mut results = Vec::with_capacity(count);
            let mut applied = None;
            if count > 1 && state.applies_groups() {
                match state.append_group(commands).await? {
                    GroupAppended::Applied(responses, last) => {
                        results.extend(responses.into_iter().map(Ok));
                        applied = Some(last);
                    }
                    GroupAppended::Refused => {
                        results.extend((0..count).map(|_| Err(crate::LocalAppendCapacityDenied)));
                    }
                }
            } else {
                for command in commands {
                    match state.append(EntryPayload::Normal(command), true).await? {
                        Appended::Applied(data, position) => {
                            results.push(Ok(data));
                            applied = Some(position);
                        }
                        Appended::Refused => results.push(Err(crate::LocalAppendCapacityDenied)),
                    }
                }
            }
            if let Some(applied) = applied {
                {
                    let mut metrics = metrics.lock().unwrap_or_else(|p| p.into_inner());
                    metrics.last_applied = Some(applied);
                    metrics.last_log_index = Some(applied.index);
                }
                if state
                    .next_index
                    .saturating_sub(state.snapshot_index.map_or(0, |index| index + 1))
                    >= state.snapshot_interval
                {
                    state.schedule_snapshot(&snapshot).await?;
                }
            }
            fence.complete = true;
            let _ = response.send(results);
            Ok(())
        }));
        drop(worker);
        match receive.await {
            Ok(results) => Ok(results),
            Err(_) => {
                let mut worker = self.worker.lock().await;
                self.finish_worker(&mut worker).await;
                self.report
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .outcome(None)
                    .map_err(anyhow::Error::from)?;
                anyhow::bail!("local worker stopped before delivering its responses")
            }
        }
    }

    /// Append one Blank entry: the state machine applies it as metadata, so the
    /// journal and the applied position advance with no application command.
    pub(crate) async fn append_blank(&self) -> Result<()> {
        self.append_payload(EntryPayload::Blank, false)
            .await
            .map(drop)
    }

    async fn append_payload(
        &self,
        payload: EntryPayload<TypeConfig>,
        joined: bool,
    ) -> Result<Vec<u8>> {
        self.check()?;
        let mut worker = self.worker.lock().await;
        self.finish_worker(&mut worker).await;
        self.check()?;
        let mut guard = self.state.clone().lock_owned().await;
        self.check()?;
        let metrics = self.metrics.clone();
        let failed = self.failed.clone();
        let snapshot = self.snapshot_work();
        let (response, receive) = tokio::sync::oneshot::channel();
        #[cfg(any(test, feature = "test-utils"))]
        let before_apply = self.before_apply.lock().unwrap().take();
        #[cfg(any(test, feature = "test-utils"))]
        let refused = matches!(payload, EntryPayload::Blank)
            && self.refuse_next_blank.swap(false, Ordering::AcqRel);
        #[cfg(not(any(test, feature = "test-utils")))]
        let refused = false;
        // Move the serialization guard into the retained worker before
        // yielding. Cancellation cannot split commit and publication.
        *worker = Some(tokio::spawn(async move {
            let mut fence = WorkFence {
                failed: failed.clone(),
                complete: false,
            };
            let state = guard.as_mut().context("local writer has shut down")?;
            #[cfg(any(test, feature = "test-utils"))]
            if let Some(hook) = before_apply {
                tokio::task::spawn_blocking(hook).await?;
            }
            let appended = if refused {
                Appended::Refused
            } else {
                state.append(payload, joined).await?
            };
            let (data, applied) = match appended {
                Appended::Applied(data, applied) => (data, applied),
                // Nothing reached the journal, so this command is rejected
                // and the writer, its position and its applied state go on.
                Appended::Refused => {
                    fence.complete = true;
                    let _ = response.send(Err(crate::LocalAppendCapacityDenied));
                    return Ok(());
                }
            };
            {
                let mut metrics = metrics.lock().unwrap_or_else(|p| p.into_inner());
                metrics.last_applied = Some(applied);
                metrics.last_log_index = Some(applied.index);
            }
            if state
                .next_index
                .saturating_sub(state.snapshot_index.map_or(0, |index| index + 1))
                >= state.snapshot_interval
            {
                state.schedule_snapshot(&snapshot).await?;
            }
            fence.complete = true;
            let _ = response.send(Ok(data));
            Ok(())
        }));
        drop(worker);
        match receive.await {
            Ok(response) => Ok(response?),
            Err(_) => {
                let mut worker = self.worker.lock().await;
                self.finish_worker(&mut worker).await;
                self.report
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .outcome(None)
                    .map_err(anyhow::Error::from)?;
                anyhow::bail!("local worker stopped before delivering its response")
            }
        }
    }

    /// A retained readiness future must never reserve the writer mutex: its
    /// owner may not poll it again until after this group has shut down.
    pub(crate) fn readiness_observation(&self) -> bool {
        if self.ended() {
            return false;
        }
        let Ok(state) = self.state.try_lock() else {
            return false;
        };
        state.is_some() && !self.ended()
    }

    pub(crate) async fn barrier(&self) -> Result<Option<LogId<u64>>> {
        self.check()?;
        let _guard = self.state.lock().await;
        self.check()?;
        Ok(self
            .metrics
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last_applied)
    }

    pub(crate) async fn snapshot(&self) -> Result<()> {
        self.check()?;
        let mut worker = self.worker.lock().await;
        self.finish_worker(&mut worker).await;
        self.check()?;
        let mut state = self.state.clone().lock_owned().await;
        self.check()?;
        let snapshot = self.snapshot_work();
        // Snapshot capture itself may dispatch blocking work. Retain that
        // coordinator too, so cancelling the trigger never abandons its work.
        *worker = Some(tokio::spawn(async move {
            let mut fence = WorkFence {
                failed: snapshot.failed.clone(),
                complete: false,
            };
            state
                .as_mut()
                .context("local writer has shut down")?
                .schedule_snapshot(&snapshot)
                .await?;
            fence.complete = true;
            Ok(())
        }));
        Ok(())
    }

    pub(crate) async fn shutdown(&self) -> kasumi_types::drain::DrainResult {
        self.closed.store(true, Ordering::Release);
        let mut worker = self.worker.lock().await;
        self.finish_worker(&mut worker).await;
        let mut snapshot = self.snapshot_worker.lock().await;
        finish_task(
            &mut snapshot,
            &self.failed,
            &self.report,
            "Local snapshot worker",
        )
        .await;
        self.state.lock().await.take();
        self.report
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .outcome(None)
    }
}

async fn finish_task(
    worker: &mut Option<tokio::task::JoinHandle<Result<()>>>,
    failed: &AtomicBool,
    report: &Mutex<kasumi_types::drain::DrainReport>,
    component: &'static str,
) {
    if let Some(task) = worker.as_mut() {
        // The handle stays in its retained slot across cancellation of a
        // submitter or shutdown; only a completed join can remove it.
        let result = task.await;
        *worker = None;
        let error = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(error) => Some(error.into()),
        };
        if let Some(error) = error {
            failed.store(true, Ordering::Release);
            report
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .record(component, 0, error);
        }
    }
}

impl<M> LocalState<M>
where
    M: RaftStateMachine<TypeConfig> + LocalJoinedApply + Send + Sync + 'static,
    M::SnapshotBuilder: LocalSnapshotBuilder,
{
    async fn schedule_snapshot(&mut self, work: &SnapshotWork) -> Result<()> {
        let mut worker = work.worker.lock().await;
        if worker.as_ref().is_some_and(|task| !task.is_finished()) {
            return Ok(());
        }
        finish_task(
            &mut worker,
            &work.failed,
            &work.report,
            "Local snapshot worker",
        )
        .await;
        ensure!(
            !work.failed.load(Ordering::Acquire),
            "local snapshot requires recovery"
        );
        // Capture the roots while ordered with commands, then serialize and
        // publish independently. The state-machine publication lock and shared
        // log I/O gate already support concurrent append and snapshot purge.
        let mut builder = self.machine.get_snapshot_builder().await;
        self.snapshot_index = self.next_index.checked_sub(1);
        let mut log = self.log.clone();
        let metrics = work.metrics.clone();
        let failed = work.failed.clone();
        let closing = work.closing.clone();
        let published = work.published.clone();
        let group = work.group.clone();
        #[cfg(any(test, feature = "test-utils"))]
        let before_build = work.before_build.clone();
        *worker = Some(tokio::spawn(async move {
            let mut fence = WorkFence {
                failed,
                complete: false,
            };
            #[cfg(any(test, feature = "test-utils"))]
            {
                let hook = before_build.lock().unwrap().take();
                if let Some(hook) = hook {
                    tokio::task::spawn_blocking(hook).await?;
                }
            }
            match builder.build_local(&closing).await? {
                LocalSnapshot::Published(position) => {
                    // A purge refused for capacity keeps the rest of the
                    // journal for a later snapshot to purge.
                    let purged = match position {
                        Some(position) => log.purge_local(position, &closing).await?,
                        None => true,
                    };
                    if !purged {
                        // The journal keeps its entries until a later snapshot purges them.
                        eprintln!(
                            "Kasumi local journal purge deferred: capacity refused group={group} snapshot_index={}",
                            position.map_or(0, |log| log.index)
                        );
                    }
                    let mut metrics = metrics.lock().unwrap_or_else(|p| p.into_inner());
                    metrics.snapshot = position;
                    if purged {
                        metrics.purged = position;
                    }
                    drop(metrics);
                    published.fetch_add(1, Ordering::AcqRel);
                }
                // The journal keeps every entry until a later snapshot covers it.
                LocalSnapshot::Deferred => {
                    // The published snapshot and journal are unchanged; the next
                    // snapshot retries.
                    eprintln!("Kasumi local snapshot deferred: capacity refused group={group}");
                }
            }
            fence.complete = true;
            Ok(())
        }));
        Ok(())
    }

    async fn append(
        &mut self,
        payload: EntryPayload<TypeConfig>,
        joined: bool,
    ) -> Result<Appended> {
        let next = self
            .next_index
            .checked_add(1)
            .context("local journal index exhausted")?;
        let entry = Entry {
            log_id: if self.next_index == 0 {
                LogId::default()
            } else {
                LogId::new(CommittedLeaderId::new(self.term, self.id), self.next_index)
            },
            payload,
            initialization: None,
        };
        let position = entry.log_id;
        // The first entry, and any entry the serving machine cannot apply
        // with its journal record, keeps two commits: append, then apply.
        if joined
            && self.next_index != 0
            && self.log.serving()
            && matches!(
                &entry.payload,
                EntryPayload::Normal(RaftCommand::Application(_))
            )
            && let Some(machine) = self.machine.joined()
        {
            let mut prepared = match self
                .log
                .prepare_local_append(std::slice::from_ref(&entry))
                .await
            {
                Ok(prepared) => prepared,
                // Refused for capacity before anything was written.
                Err(error) => {
                    crate::capacity_refusal::take(error)?;
                    #[cfg(any(test, feature = "test-utils"))]
                    self.joined
                        .refused_before_publication
                        .fetch_add(1, Ordering::AcqRel);
                    return Ok(Appended::Refused);
                }
            };
            let application = std::mem::take(&mut prepared.application);
            let custody = std::mem::take(&mut prepared.custody);
            return match machine.apply_joined(entry, application, custody).await? {
                crate::storage::EntryApplied::Applied(response) => {
                    self.log.install_local_append(prepared)?;
                    #[cfg(any(test, feature = "test-utils"))]
                    self.joined.applied.fetch_add(1, Ordering::AcqRel);
                    self.next_index = next;
                    Ok(Appended::Applied(response, position))
                }
                // Neither the record nor the entry took effect; the retained
                // span, the position and the applied state are unchanged.
                crate::storage::EntryApplied::Refused => {
                    #[cfg(any(test, feature = "test-utils"))]
                    self.joined
                        .refused_publication
                        .fetch_add(1, Ordering::AcqRel);
                    Ok(Appended::Refused)
                }
            };
        }
        if let LocalAppend::Refused = self.log.append_local(entry.clone()).await? {
            return Ok(Appended::Refused);
        }
        let response = self
            .machine
            .apply([entry])
            .await?
            .pop()
            .context("local application returned no response")?;
        self.next_index = next;
        Ok(Appended::Applied(response, position))
    }

    // Whether the next appends may commit as one joined group.
    fn applies_groups(&mut self) -> bool {
        self.next_index != 0
            && self.log.serving()
            && self
                .machine
                .joined()
                .is_some_and(|machine| machine.applies_groups())
    }

    // Consecutive application entries whose journal records commit in their
    // one publication's transaction (see `LocalGroup::write_joined_group`).
    async fn append_group(&mut self, commands: Vec<RaftCommand>) -> Result<GroupAppended> {
        let first = self.next_index;
        let count = u64::try_from(commands.len())?;
        let next = first
            .checked_add(count)
            .context("local journal index exhausted")?;
        ensure!(
            first != 0 && count > 1 && self.log.serving(),
            "a joined group extends a serving journal"
        );
        let entries = commands
            .into_iter()
            .zip(first..next)
            .map(|(command, index)| {
                ensure!(
                    matches!(command, RaftCommand::Application(_)),
                    "a joined group has only application commands"
                );
                Ok(Entry {
                    log_id: LogId::new(CommittedLeaderId::new(self.term, self.id), index),
                    payload: EntryPayload::Normal(command),
                    initialization: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let position = entries.last().context("empty joined group")?.log_id;
        let mut prepared = match self.log.prepare_local_append(&entries).await {
            Ok(prepared) => prepared,
            Err(error) => {
                crate::capacity_refusal::take(error)?;
                #[cfg(any(test, feature = "test-utils"))]
                self.joined
                    .refused_before_publication
                    .fetch_add(count, Ordering::AcqRel);
                return Ok(GroupAppended::Refused);
            }
        };
        let application = std::mem::take(&mut prepared.application);
        let custody = std::mem::take(&mut prepared.custody);
        let machine = self
            .machine
            .joined()
            .context("a joined group requires the serving machine")?;
        match machine
            .apply_joined_group(entries, application, custody)
            .await?
        {
            crate::storage::GroupApplied::Applied(responses) => {
                self.log.install_local_append(prepared)?;
                #[cfg(any(test, feature = "test-utils"))]
                {
                    self.joined.applied.fetch_add(count, Ordering::AcqRel);
                    self.joined.groups.fetch_add(1, Ordering::AcqRel);
                }
                self.next_index = next;
                Ok(GroupAppended::Applied(responses, position))
            }
            crate::storage::GroupApplied::Refused => {
                #[cfg(any(test, feature = "test-utils"))]
                self.joined
                    .refused_publication
                    .fetch_add(count, Ordering::AcqRel);
                Ok(GroupAppended::Refused)
            }
        }
    }
}

// A group of appended entries, or a proof that capacity was refused before any
// of them reached the journal.
enum GroupAppended {
    Applied(Vec<Vec<u8>>, LogId<u64>),
    Refused,
}
