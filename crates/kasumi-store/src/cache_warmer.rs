//! One admitted node worker, with independently retained exact task handles.
//!
//! The supervisor holds only an exact nonowning node locator while idle. Every blocking step owns
//! the node until the serialized native operation returns; BackgroundWork keeps
//! its actual JoinHandle even if a waiter or the last public node is dropped.
//!
//! The worker's steps exclude every tenant's writes and, while they run, reads.
//! Between iterations it therefore yields to foreground operations in
//! proportion to the time the last iteration kept the database (`next_delay`),
//! and meanwhile stands in for the maintenance step every write would
//! otherwise run inline (`inline_stand_in`).
use crate::background_pace::{BackgroundWriteStatus, MIN_PACED_DELAY, paced_delay};
use crate::{NodeStore, NodeStoreLocator, NodeStoreLookup, disk_memory};
use anyhow::{Result, ensure};
use kasumi_kv::{
    CacheWarmup, CacheWarmupState, CacheWarmupStatus, MaintenanceBudget, MaintenanceStep,
    StorageMaintenanceStatus,
};
use kasumi_serving::{BackgroundWork, BackgroundWorkBudget};
use kasumi_types::drain::{DrainCompletion, DrainReport, DrainResult};
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const STEP_WORK: usize = 1;
/// The storage maintenance share of one worker iteration: bounded read units
/// and at most one durable publication, run after the warm step.
const MAINTENANCE_BUDGET: MaintenanceBudget = MaintenanceBudget {
    units: 512,
    mutations: 1,
};
const RUNNING_DELAY: Duration = MIN_PACED_DELAY;
/// A writer held the database write gate; retry soon without waiting on it.
const BUSY_DELAY: Duration = Duration::from_millis(10);
const IDLE_DELAY: Duration = Duration::from_millis(250);
/// A publication resets an unfinished warm attempt and discards its progress,
/// so warming that keeps being restarted never finishes. Once the worker sees
/// an attempt replaced before completing, it warms at the idle pace until
/// this long passes without another restart.
const RESTART_WINDOW: Duration = Duration::from_secs(60);
/// Maintenance stops yielding to foreground operations once the current
/// census finds this many times the bytes that begin a cycle.
const URGENT_RETAINED_FACTOR: u64 = 2;
/// What the worker's stand-in for the writes' inline maintenance steps
/// allows, beyond twice its pause, for its next step to begin: a warm step
/// that waits for a commit, a few tries for the write gate.
const STAND_IN_MARGIN: Duration = Duration::from_millis(100);

/// Lifecycle observations from the node's automatic worker. A completed native
/// pass can still be capacity-limited; `progress.complete` is not residency.
/// Each iteration also runs one bounded storage maintenance step; a fatal
/// maintenance error fails the worker like a fatal warm error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheWorkerStatus {
    pub started: bool,
    pub active: bool,
    pub stopped: bool,
    pub failed: bool,
    pub steps: u64,
    pub work: u64,
    pub progress: Option<CacheWarmup>,
    pub native: Option<CacheWarmupStatus>,
    /// Maintenance steps that ran (not `Busy`).
    pub maintenance_steps: u64,
    /// Read units those steps spent.
    pub maintenance_units: u64,
    /// Steps skipped because a writer held the database write gate.
    pub maintenance_busy: u64,
    pub last_maintenance: Option<MaintenanceStep>,
    /// The last step that ran was not idle: a census, a due cycle or an
    /// active phase still has work.
    pub maintenance_pending: bool,
    /// Unfinished warm attempts that were replaced, and when the last was seen.
    pub warm_restarts: u64,
    pub last_warm_restart: Option<Instant>,
    /// The database's maintenance status as of this worker's last step.
    pub storage: Option<PublishedStorageStatus>,
    /// Wall time the warm steps and the maintenance steps (also `Busy` ones)
    /// kept the database, including their waits for its locks: every
    /// foreground operation that needed the same locks waited as long.
    pub warm_time: Duration,
    pub maintenance_time: Duration,
    /// That time for the last iteration, both steps and their status reads,
    /// and the longest iteration so far.
    pub last_database_time: Duration,
    pub longest_database_time: Duration,
    /// The database's foreground activity counter after the last iteration,
    /// and whether it had moved since the iteration before: some transaction
    /// began, read or committed, or waited to, meanwhile.
    pub foreground_seen: Option<u64>,
    pub foreground_active: bool,
    /// Pauses lengthened for foreground operations, and by how much in all.
    pub paced_delays: u64,
    pub paced_delay: Duration,
    /// `cycles_completed` as of a capacity deferral this worker saw while a
    /// cycle was active; cleared once another cycle completes.
    pub capacity_deferred_cycle: Option<u64>,
}

/// The maintenance status the node worker copies after each of its
/// maintenance steps, whether the step ran or found the write gate busy.
/// Readers take this copy without touching the database, its write gate,
/// the opening's state or the KV core lock, so an observation never waits
/// behind a maintenance step. It is as old as `published_at`; steps that
/// writes run inline in between are reflected by the worker's next copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedStorageStatus {
    pub status: StorageMaintenanceStatus,
    pub published_at: Instant,
    /// The last census completed in this process lifetime. A compaction
    /// cycle clears `status.measured` until it measures again; these figures
    /// then stay, aging, instead of disappearing.
    pub census: Option<PublishedCensus>,
    /// How the node's background work shared the database, as of the read.
    pub background: PublishedBackgroundWork,
}

/// How one node database's background work shared the database with
/// foreground operations since the database opened: the worker's steps and
/// the paced background writes (snapshot chunk commits, journal purge
/// chunks). Counters and times are cumulative.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublishedBackgroundWork {
    /// Maintenance steps the worker ran, and those it skipped because a
    /// writer held the write gate.
    pub maintenance_steps: u64,
    pub maintenance_busy: u64,
    /// Unfinished warm attempts a publication replaced.
    pub warm_restarts: u64,
    /// Wall time the worker's warm and maintenance steps kept the database,
    /// including their waits for its locks.
    pub warm_time: Duration,
    pub maintenance_time: Duration,
    /// The longest single worker iteration: about how long a foreground
    /// operation can wait for one.
    pub longest_database_time: Duration,
    /// Worker pauses lengthened for foreground operations, and by how much.
    pub paced_delays: u64,
    pub paced_delay: Duration,
    /// Foreground operations were active at the worker's last iteration.
    pub foreground_active: bool,
    /// Maintenance is not yielding to foreground operations: see
    /// `CacheWorkerStatus::maintenance_urgent`.
    pub maintenance_urgent: bool,
    /// Paced background writes; filled by `NodeStore::published_storage_status`.
    pub writes: BackgroundWriteStatus,
}

impl PublishedBackgroundWork {
    fn of(status: &CacheWorkerStatus) -> Self {
        Self {
            maintenance_steps: status.maintenance_steps,
            maintenance_busy: status.maintenance_busy,
            warm_restarts: status.warm_restarts,
            warm_time: status.warm_time,
            maintenance_time: status.maintenance_time,
            longest_database_time: status.longest_database_time,
            paced_delays: status.paced_delays,
            paced_delay: status.paced_delay,
            foreground_active: status.foreground_active,
            maintenance_urgent: status.maintenance_urgent(),
            writes: BackgroundWriteStatus::default(),
        }
    }
}

impl CacheWorkerStatus {
    /// Whether storage maintenance must not wait for foreground operations.
    /// Either the census found retained bytes, less those kept only for
    /// pinned snapshots, at or above `URGENT_RETAINED_FACTOR` times the bytes
    /// that begin a cycle, so compaction has fallen a whole trigger behind;
    /// or a step of the active cycle was refused capacity (workspace, memory
    /// or disk space) and that cycle has not completed yet, so the space it
    /// would free may be needed. The census counts only while it is the
    /// figure the trigger was compared with: `measured`, and not in Packing,
    /// whose trigger already derives from the baseline this cycle's
    /// reclamation left while the census still describes the files before it.
    pub fn maintenance_urgent(&self) -> bool {
        let Some(storage) = self.storage.map(|published| published.status) else {
            return false;
        };
        let retained = storage
            .segment_bytes
            .saturating_add(storage.arena_bytes)
            .saturating_sub(storage.snapshot_retained_bytes);
        let behind = storage.measured
            && storage.phase != kasumi_kv::StorageCompactionPhase::Packing
            && storage.trigger_bytes != 0
            && retained >= storage.trigger_bytes.saturating_mul(URGENT_RETAINED_FACTOR);
        behind || self.capacity_deferred_cycle == Some(storage.cycles_completed)
    }

    /// The published status with the worker's counters as of this status.
    fn published(&self) -> Option<PublishedStorageStatus> {
        let mut published = self.storage?;
        published.background = PublishedBackgroundWork::of(self);
        Some(published)
    }
}

/// Retained `.kvseg` and `.kvdir` figures of one completed census.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedCensus {
    pub segment_files: u64,
    pub segment_bytes: u64,
    pub arena_files: u64,
    pub arena_bytes: u64,
    /// When the worker first published these figures.
    pub measured_at: Instant,
}

impl PublishedStorageStatus {
    /// The next publication: `status` taken at `now`, keeping the previous
    /// census while `status` has none and its time while figures are equal.
    fn next(previous: Option<Self>, status: StorageMaintenanceStatus, now: Instant) -> Self {
        let census = if status.measured {
            let figures = (
                status.segment_files,
                status.segment_bytes,
                status.arena_files,
                status.arena_bytes,
            );
            let measured_at = previous
                .and_then(|previous| previous.census)
                .filter(|census| {
                    (
                        census.segment_files,
                        census.segment_bytes,
                        census.arena_files,
                        census.arena_bytes,
                    ) == figures
                })
                .map_or(now, |census| census.measured_at);
            Some(PublishedCensus {
                segment_files: status.segment_files,
                segment_bytes: status.segment_bytes,
                arena_files: status.arena_files,
                arena_bytes: status.arena_bytes,
                measured_at,
            })
        } else {
            previous.and_then(|previous| previous.census)
        };
        Self {
            status,
            published_at: now,
            census,
            background: PublishedBackgroundWork::default(),
        }
    }
}

/// Note a capacity deferral of an active cycle, until another cycle
/// completes: `previous` and `current` are consecutive published statuses.
fn observe_capacity_deferral(
    status: &mut CacheWorkerStatus,
    previous: Option<StorageMaintenanceStatus>,
    current: &StorageMaintenanceStatus,
) {
    let before = previous.map_or(0, |previous| previous.capacity_deferrals_total);
    if current.capacity_deferrals_total > before
        && current.phase != kasumi_kv::StorageCompactionPhase::Idle
    {
        status.capacity_deferred_cycle = Some(current.cycles_completed);
    }
    if status
        .capacity_deferred_cycle
        .is_some_and(|cycle| cycle != current.cycles_completed)
    {
        status.capacity_deferred_cycle = None;
    }
}

/// Record what one iteration cost the database and whether foreground
/// operations were active around it. `activity` is the database's foreground
/// activity counter read after the iteration's steps.
fn observe_iteration(
    status: &mut CacheWorkerStatus,
    warm: Duration,
    maintenance: Duration,
    total: Duration,
    activity: Option<u64>,
) {
    status.warm_time = status.warm_time.saturating_add(warm);
    status.maintenance_time = status.maintenance_time.saturating_add(maintenance);
    status.last_database_time = total;
    status.longest_database_time = status.longest_database_time.max(total);
    // An operation that waited for this iteration was counted when it
    // entered, so it shows here; one queued in front of the database's own
    // locks is counted during the pause and shows after the next iteration.
    status.foreground_active = match (status.foreground_seen, activity) {
        (Some(seen), Some(now)) => seen != now,
        _ => false,
    };
    status.foreground_seen = activity;
}

/// Record the native warm status of a step, noting an unfinished attempt that
/// a publication replaced since the previous step.
fn observe_native(status: &mut CacheWorkerStatus, native: CacheWarmupStatus, now: Instant) {
    if status.native.is_some_and(|previous| {
        previous.state == CacheWarmupState::Running
            && previous.attempt_generation != native.attempt_generation
    }) {
        status.warm_restarts = status.warm_restarts.saturating_add(1);
        status.last_warm_restart = Some(now);
    }
    status.native = Some(native);
}

/// The last maintenance step made undeferred progress.
fn maintaining(status: &CacheWorkerStatus) -> bool {
    matches!(
        status.last_maintenance,
        Some(MaintenanceStep::Ran(progress))
            if !progress.idle && progress.deferred.is_none() && progress.units != 0
    )
}

/// The worker's own pace, whatever foreground operations do: run again soon
/// while warming or maintenance made undeferred progress, briefly while a
/// writer held the gate and maintenance still has work, and otherwise idle. A
/// writer holding the gate while nothing is pending does not shorten the idle
/// pause, and neither does warming whose attempt was restarted within
/// `RESTART_WINDOW`.
fn own_delay(status: &CacheWorkerStatus, now: Instant) -> Duration {
    let blocked = status.native.is_some_and(|n| n.provider_limited);
    let restarted = status
        .last_warm_restart
        .is_some_and(|at| now.saturating_duration_since(at) < RESTART_WINDOW);
    let warming =
        !blocked && !restarted && status.progress.is_some_and(|p| p.work != 0 && !p.complete);
    if warming || maintaining(status) {
        RUNNING_DELAY
    } else if status.last_maintenance == Some(MaintenanceStep::Busy) && status.maintenance_pending {
        BUSY_DELAY
    } else {
        IDLE_DELAY
    }
}

/// The pause before the next iteration: the worker's own pace (`own_delay`),
/// and, while foreground operations are active, at least `FOREGROUND_SHARE`
/// times as long as the last iteration kept the database, up to
/// `MAX_PACED_DELAY`. The worker then uses at most one part in
/// `FOREGROUND_SHARE + 1` of the database's time, and each foreground
/// operation waits for at most the iteration in progress. A database nothing
/// else uses is warmed and compacted at the worker's own pace, and so is one
/// whose maintenance is urgent (`CacheWorkerStatus::maintenance_urgent`)
/// while its steps make progress. A pure function of the status and `now`.
fn next_delay(status: &CacheWorkerStatus, now: Instant) -> Duration {
    let own = own_delay(status, now);
    if !status.foreground_active || (maintaining(status) && status.maintenance_urgent()) {
        return own;
    }
    own.max(paced_delay(status.last_database_time))
}

/// How long the worker's maintenance steps stand in for the inline step of
/// every write, given the pause `delay` before its next iteration: twice the
/// pause and `STAND_IN_MARGIN`, after a step that ran and was not deferred.
/// Every write otherwise runs a maintenance step of its own, at its own
/// expense and that of every reader, and so takes over exactly the work the
/// worker is spacing out for them. After a step that found the write gate
/// busy or was deferred there is no stand-in: the writes drive the cycle, or
/// count down its backoff, as they do without a worker. `None` leaves an
/// earlier stand-in to lapse.
fn inline_stand_in(status: &CacheWorkerStatus, delay: Duration) -> Option<Duration> {
    match status.last_maintenance {
        Some(MaintenanceStep::Ran(progress)) if progress.deferred.is_none() => {
            Some(delay.saturating_mul(2).saturating_add(STAND_IN_MARGIN))
        }
        _ => None,
    }
}

#[derive(Default)]
struct State {
    stopped: bool,
    worker: Option<Arc<Worker>>,
}

#[derive(Default)]
pub(crate) struct CacheWarmer {
    // This gate orders both dispatches and startup against database stop. No
    // admission callbacks or native I/O run while it is held.
    state: Mutex<State>,
}

struct Worker {
    active: AtomicBool,
    supervisor: Arc<BackgroundWork>,
    child: Mutex<Option<Arc<BackgroundWork>>>,
    status: Mutex<CacheWorkerStatus>,
    budget: BackgroundWorkBudget,
    /// Test control: keep the worker's own pace whatever foreground
    /// operations do and stand in for no inline step, as before pacing.
    #[cfg(test)]
    unpaced: AtomicBool,
}

impl CacheWarmer {
    pub(crate) fn prepare(&self, node: &NodeStore) -> Result<()> {
        // This explicit activation, unlike a synchronous node constructor,
        // requires the caller's installed runtime.
        tokio::runtime::Handle::try_current()?;
        {
            let state = self.state.lock();
            ensure!(
                !state.stopped && !node.body().db.is_stopped(),
                "node is stopping"
            );
            if state.worker.is_some() {
                return Ok(());
            }
        }
        let bytes = disk_memory::add(
            disk_memory::add(
                disk_memory::add(
                    BackgroundWorkBudget::required_bytes(2, 1)?,
                    u64::try_from(std::mem::size_of::<NodeStoreLocator>())?,
                )?,
                kasumi_types::SharedBudgetCharge::required_bytes::<crate::DiskMemoryLease>()?,
            )?,
            disk_memory::add(
                std::mem::size_of::<Self>() as u64,
                disk_memory::add(
                    disk_memory::arc::<Worker>()?,
                    disk_memory::mul(2, disk_memory::arc::<BackgroundWork>()?)?,
                )?,
            )?,
        )?;
        let lease = node
            .scratch_disk()
            .memory()
            .clone()
            .reserve_installed(bytes)?;
        let budget = BackgroundWorkBudget::new(2, kasumi_types::SharedBudgetCharge::new(lease))?;
        let worker = Arc::new(Worker {
            active: AtomicBool::new(false),
            supervisor: Arc::new(BackgroundWork::default()),
            child: Mutex::new(None),
            status: Mutex::new(CacheWorkerStatus::default()),
            budget,
            #[cfg(test)]
            unpaced: AtomicBool::new(false),
        });
        let mut state = self.state.lock();
        ensure!(
            !state.stopped && !node.body().db.is_stopped(),
            "node is stopping"
        );
        if state.worker.is_some() {
            return Ok(());
        }
        // Install the control before dispatch. A concurrent stop cannot pass
        // this gate until the actual supervisor handle has entered custody.
        state.worker = Some(worker.clone());
        let run = worker.clone();
        let node = node.locator();
        if let Err(error) = worker
            .supervisor
            .start_result(async move { run.run(node).await }, &worker.budget)
        {
            // BackgroundWork rejects start before launching a child. Keep the
            // caller's original rejection and allow a later clean start.
            state.worker = None;
            return Err(error);
        }
        worker.status.lock().started = true;
        Ok(())
    }

    fn activate(&self, node: &NodeStore) -> Result<()> {
        let state = self.state.lock();
        ensure!(
            !state.stopped && !node.body().db.is_stopped(),
            "node is stopping"
        );
        let worker = state
            .worker
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("cache worker is not prepared"))?;
        if worker.supervisor.observed().is_some() {
            worker.status.lock().failed = true;
            anyhow::bail!("cache worker terminated before activation");
        }
        ensure!(!worker.supervisor.is_closed(), "cache worker is closed");
        worker.active.store(true, Ordering::Release);
        worker.status.lock().active = true;
        worker.supervisor.wake().notify_one();
        Ok(())
    }

    pub(crate) fn stop(&self, node: &NodeStore) {
        let mut state = self.state.lock();
        state.stopped = true;
        node.body().db.stop();
        if let Some(worker) = &state.worker {
            worker.status.lock().stopped = true;
            worker.supervisor.close();
        }
    }

    /// The worker's last published maintenance status. Takes only this
    /// owner's state gate and the worker's status cell, both of which are
    /// held briefly and never across database work.
    pub(crate) fn published_storage(&self) -> Option<PublishedStorageStatus> {
        let worker = self.state.lock().worker.clone()?;
        let status = worker.status.lock();
        status.published()
    }

    /// Test control: `true` disables foreground pacing for this worker.
    #[cfg(test)]
    pub(crate) fn set_unpaced_for_test(&self, unpaced: bool) {
        let worker = self.state.lock().worker.clone().expect("prepared worker");
        worker.unpaced.store(unpaced, Ordering::Release);
    }

    pub(crate) fn status(&self) -> CacheWorkerStatus {
        let state = self.state.lock();
        let stopped = state.stopped;
        let worker = state.worker.clone();
        drop(state);
        if let Some(worker) = worker {
            if matches!(worker.supervisor.observed(), Some(Err(_))) {
                worker.status.lock().failed = true;
            }
            let mut status = *worker.status.lock();
            status.storage = status.published();
            status
        } else {
            CacheWorkerStatus {
                stopped,
                ..Default::default()
            }
        }
    }

    pub(crate) async fn drain(&self) -> DrainResult {
        let worker = self.state.lock().worker.clone();
        let Some(worker) = worker else { return Ok(()) };
        // Both cells retain their original diagnostics across canceled drains.
        // A supervisor panic cannot detach its blocking child.
        let mut report = DrainReport::default();
        let mut retained = None;
        if let Err(failure) = worker.supervisor.drain().await {
            report.merge(&failure);
            if failure.completion() == DrainCompletion::Retained {
                retained = Some(failure);
            }
        }
        let child = worker.child.lock().clone();
        if let Some(child) = child {
            if let Err(failure) = child.drain().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            } else {
                worker.child.lock().take();
            }
        }
        if !report.issues().is_empty() {
            worker.status.lock().failed = true;
        }
        report.outcome(retained)
    }
}

impl Drop for CacheWarmer {
    fn drop(&mut self) {
        if let Some(worker) = &self.state.get_mut().worker {
            // No abort, join, admission callback or storage access in Drop.
            // Independent BackgroundWork custody retains any unfinished job.
            worker.supervisor.close();
        }
    }
}

impl Worker {
    /// Test control: the worker keeps its own pace and stands in for no
    /// inline step, as before pacing.
    fn unpaced(&self) -> bool {
        #[cfg(test)]
        {
            self.unpaced.load(Ordering::Acquire)
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    async fn run(self: Arc<Self>, locator: NodeStoreLocator) -> Result<()> {
        let wake = self.supervisor.wake();
        loop {
            if self.supervisor.is_closed() {
                return Ok(());
            }
            if !self.active.load(Ordering::Acquire) {
                wake.notified().await;
                continue;
            }
            let node = match locator.try_borrow() {
                NodeStoreLookup::Active(node) => node,
                NodeStoreLookup::Busy => {
                    // Metadata contention is not owner disappearance. Keep the
                    // same accepted supervisor and its original fee while idle.
                    tokio::select! {
                        _ = wake.notified() => {},
                        _ = tokio::time::sleep(IDLE_DELAY) => {},
                    }
                    continue;
                }
                NodeStoreLookup::Missing => {
                    // A stale locator is not a clean disposal witness. The
                    // actual worker keeps this original failure for drain.
                    return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe).into());
                }
            };
            let child = {
                let state = node.body().cache_warmer.state.lock();
                if state.stopped || node.body().db.is_stopped() || self.supervisor.is_closed() {
                    return Ok(());
                }
                ensure!(
                    self.child.lock().is_none(),
                    "cache warming child still owned"
                );
                let child = Arc::new(BackgroundWork::default());
                *self.child.lock() = Some(child.clone());
                let work_node = node.clone();
                let observer = self.clone();
                // The gate stays held until exact blocking-handle registration.
                // Database stop uses the same gate, so it cannot race dispatch.
                child.start_blocking_result(
                    move || {
                        let started = Instant::now();
                        let progress = match work_node.body().db.warm_cache_if_needed(STEP_WORK) {
                            Ok(progress) => progress,
                            Err(kasumi_kv::StorageError::DatabaseClosed)
                                if work_node.body().db.is_stopped() =>
                            {
                                return Ok(());
                            }
                            Err(error) => return Err(error.into()),
                        };
                        let native = match work_node.body().db.cache_warmup_status() {
                            Ok(native) => native,
                            Err(kasumi_kv::StorageError::DatabaseClosed)
                                if work_node.body().db.is_stopped() =>
                            {
                                return Ok(());
                            }
                            Err(error) => return Err(error.into()),
                        };
                        let warmed = Instant::now();
                        {
                            let mut status = observer.status.lock();
                            status.steps = status.steps.saturating_add(1);
                            status.work = status.work.saturating_add(progress.work as u64);
                            status.progress = Some(progress);
                            observe_native(&mut status, native, warmed);
                        }
                        // Local maintenance deferrals arrive as progress; an
                        // error here is fatal and the database is fenced.
                        let maintenance =
                            match work_node.body().db.run_maintenance(MAINTENANCE_BUDGET) {
                                Ok(step) => step,
                                Err(kasumi_kv::StorageError::DatabaseClosed)
                                    if work_node.body().db.is_stopped() =>
                                {
                                    return Ok(());
                                }
                                Err(error) => return Err(error.into()),
                            };
                        let maintained = Instant::now();
                        // Publish this step's outcome for observers. A read
                        // failure leaves the previous copy, which ages.
                        let published = match work_node.body().db.maintenance_status() {
                            Ok(status) => Some(status),
                            Err(kasumi_kv::StorageError::DatabaseClosed)
                                if work_node.body().db.is_stopped() =>
                            {
                                return Ok(());
                            }
                            Err(_) => None,
                        };
                        // Read last: every operation that entered while this
                        // iteration kept the database has been counted.
                        let activity = work_node.body().db.foreground_activity().ok();
                        let finished = Instant::now();
                        let mut status = observer.status.lock();
                        observe_iteration(
                            &mut status,
                            warmed.saturating_duration_since(started),
                            maintained.saturating_duration_since(warmed),
                            finished.saturating_duration_since(started),
                            activity,
                        );
                        if let Some(published) = published {
                            let previous = status.storage.map(|previous| previous.status);
                            observe_capacity_deferral(&mut status, previous, &published);
                            status.storage = Some(PublishedStorageStatus::next(
                                status.storage,
                                published,
                                finished,
                            ));
                        }
                        match maintenance {
                            MaintenanceStep::Busy => {
                                status.maintenance_busy = status.maintenance_busy.saturating_add(1);
                            }
                            MaintenanceStep::Ran(progress) => {
                                status.maintenance_steps =
                                    status.maintenance_steps.saturating_add(1);
                                status.maintenance_units = status
                                    .maintenance_units
                                    .saturating_add(progress.units as u64);
                                status.maintenance_pending = !progress.idle;
                            }
                        }
                        status.last_maintenance = Some(maintenance);
                        // While this worker keeps stepping, its steps stand
                        // in for the writes' inline ones.
                        let stand_in = if observer.unpaced() {
                            None
                        } else {
                            inline_stand_in(&status, next_delay(&status, finished))
                        };
                        drop(status);
                        if let Some(stand_in) = stand_in {
                            // A stopping database needs no stand-in.
                            let _ = work_node.body().db.defer_inline_maintenance(stand_in);
                        }
                        Ok(())
                    },
                    &self.budget,
                )?;
                child
            };
            drop(node);
            if let Err(error) = child.drain().await {
                self.status.lock().failed = true;
                return Err(error.into());
            }
            // Successful cells release their budget slot only after the exact
            // join has been observed and reported. Retain failures for shutdown.
            self.child.lock().take();
            drop(child);
            let delay = {
                let mut status = self.status.lock();
                let now = Instant::now();
                let own = own_delay(&status, now);
                let delay = if self.unpaced() {
                    own
                } else {
                    next_delay(&status, now)
                };
                if delay > own {
                    status.paced_delays = status.paced_delays.saturating_add(1);
                    status.paced_delay = status.paced_delay.saturating_add(delay - own);
                }
                delay
            };
            tokio::select! {
                _ = wake.notified() => {},
                _ = tokio::time::sleep(delay) => {},
            }
        }
    }
}

#[cfg(test)]
fn provider_limited(status: CacheWarmupStatus) -> bool {
    status.state == CacheWarmupState::CapacityLimited && status.provider_limited
}

impl NodeStore {
    /// Admit and register one dormant worker while the caller retains this node
    /// in startup custody. No native work or headroom polling starts until the
    /// acknowledged owner calls `activate_cache_warming`. Repeated preparation
    /// is idempotent; synchronous constructors never start a runtime.
    pub async fn prepare_cache_warming(&self) -> Result<()> {
        self.body().cache_warmer.prepare(self)
    }

    /// Open the prepared worker's ready gate at acknowledged handoff. Success
    /// allocates nothing; missing preparation or stopped ownership is an error.
    pub fn activate_cache_warming(&self) -> Result<()> {
        self.body().cache_warmer.activate(self)
    }

    pub fn cache_worker_status(&self) -> CacheWorkerStatus {
        self.body().cache_warmer.status()
    }
}

#[cfg(test)]
#[path = "cache_warmer_tests.rs"]
mod tests;
