//! One admitted node worker, with independently retained exact task handles.
//!
//! The supervisor holds only an exact nonowning node locator while idle. Every blocking step owns
//! the node until the serialized native operation returns; BackgroundWork keeps
//! its actual JoinHandle even if a waiter or the last public node is dropped.
use crate::{NodeStore, NodeStoreLocator, NodeStoreLookup, disk_memory};
use anyhow::{Result, ensure};
use kasumi_kv::{
    CacheWarmup, CacheWarmupState, CacheWarmupStatus, MaintenanceBudget, MaintenanceStep,
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
const RUNNING_DELAY: Duration = Duration::from_millis(1);
/// A writer held the database write gate; retry soon without waiting on it.
const BUSY_DELAY: Duration = Duration::from_millis(10);
const IDLE_DELAY: Duration = Duration::from_millis(250);
/// A publication resets an unfinished warm attempt and discards its progress,
/// so warming that keeps being restarted never finishes. Once the worker sees
/// an attempt replaced before completing, it warms at the idle pace until
/// this long passes without another restart.
const RESTART_WINDOW: Duration = Duration::from_secs(60);

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

/// The pause before the next iteration: run again soon while warming or
/// maintenance made undeferred progress, briefly while a writer held the gate
/// and maintenance still has work, and otherwise idle. A writer holding the
/// gate while nothing is pending does not shorten the idle pause, and neither
/// does warming whose attempt was restarted within `RESTART_WINDOW`.
fn next_delay(status: &CacheWorkerStatus, now: Instant) -> Duration {
    let blocked = status.native.is_some_and(|n| n.provider_limited);
    let restarted = status
        .last_warm_restart
        .is_some_and(|at| now.saturating_duration_since(at) < RESTART_WINDOW);
    let warming =
        !blocked && !restarted && status.progress.is_some_and(|p| p.work != 0 && !p.complete);
    let maintaining = matches!(
        status.last_maintenance,
        Some(MaintenanceStep::Ran(progress))
            if !progress.idle && progress.deferred.is_none() && progress.units != 0
    );
    if warming || maintaining {
        RUNNING_DELAY
    } else if status.last_maintenance == Some(MaintenanceStep::Busy) && status.maintenance_pending {
        BUSY_DELAY
    } else {
        IDLE_DELAY
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

    pub(crate) fn status(&self) -> CacheWorkerStatus {
        let state = self.state.lock();
        let stopped = state.stopped;
        let worker = state.worker.clone();
        drop(state);
        if let Some(worker) = worker {
            if matches!(worker.supervisor.observed(), Some(Err(_))) {
                worker.status.lock().failed = true;
            }
            *worker.status.lock()
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
                        {
                            let mut status = observer.status.lock();
                            status.steps = status.steps.saturating_add(1);
                            status.work = status.work.saturating_add(progress.work as u64);
                            status.progress = Some(progress);
                            observe_native(&mut status, native, Instant::now());
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
                        let mut status = observer.status.lock();
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
            let delay = next_delay(&self.status.lock(), Instant::now());
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
