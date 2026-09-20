//! Process-local custody owns exact child handles; completion cells have no
//! structural task/runtime back-reference. Original opaque panic payloads may
//! themselves contain resources; retaining them does not prove resource release.
use anyhow::{Context, Result, ensure};
use kasumi_types::drain::{DrainFailure, DrainReport, DrainResult};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    sync::{Mutex as AsyncMutex, Notify},
    task::JoinHandle,
};
use uuid::Uuid;

/// Bounded metadata reservation, including child-task and join bookkeeping.
/// This is a workspace estimate; opaque panic payloads are not allocator accounting.
pub const BACKGROUND_WORK_SLOT_BYTES: u64 = 16 << 10;
/// Retained logical trust state and bounded decode/clone workspace per domain.
pub const BACKGROUND_WORK_DOMAIN_BYTES: u64 =
    4 * crate::MAX_SIGNER_TRUST_RECORD_BYTES as u64 + 4096;
#[derive(Clone)]
pub struct BackgroundWorkBudget {
    max_registered: usize,
    // Only the node-memory reservation belongs here, never storage or a runtime.
    _charge: Arc<dyn Send + Sync>,
    slots: Arc<Mutex<usize>>,
}
struct Slot(BackgroundWorkBudget);
impl Drop for Slot {
    fn drop(&mut self) {
        let mut slots = self.0.slots.lock().unwrap_or_else(|p| p.into_inner());
        *slots -= 1;
    }
}
impl BackgroundWorkBudget {
    pub fn required_bytes(max_registered: usize, domains: usize) -> Result<u64> {
        ensure!(
            max_registered > 0 && domains > 0,
            "background work budget is zero"
        );
        u64::try_from(max_registered)?
            .checked_mul(u64::try_from(domains)?)
            .and_then(|slots| slots.checked_mul(BACKGROUND_WORK_SLOT_BYTES))
            .and_then(|bytes| {
                bytes.checked_add(
                    u64::try_from(domains)
                        .ok()?
                        .checked_mul(BACKGROUND_WORK_DOMAIN_BYTES)?,
                )
            })
            .context("background work metadata budget overflow")
    }
    /// The trusted installer reserves required_bytes across its complete domain
    /// set before opening owners, and shares that exact memory charge here.
    pub fn new(max_registered: usize, charge: Arc<dyn Send + Sync>) -> Result<Self> {
        Self::required_bytes(max_registered, 1)?;
        Ok(Self {
            max_registered,
            _charge: charge,
            slots: Default::default(),
        })
    }
    pub fn max_registered(&self) -> usize {
        self.max_registered
    }
    fn reserve(&self) -> Result<Slot> {
        let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            *slots < self.max_registered,
            "background registration capacity exhausted"
        );
        *slots += 1;
        Ok(Slot(self.clone()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    New,
    Running,
    CustodyLost,
    Joined,
}
struct State {
    phase: Phase,
    custody: Option<Uuid>,
    report: DrainReport,
    slot: Option<Slot>,
    reported: bool,
}
impl Default for State {
    fn default() -> Self {
        Self {
            phase: Phase::New,
            custody: None,
            report: DrainReport::default(),
            slot: None,
            reported: false,
        }
    }
}
#[derive(Default)]
pub struct BackgroundWork {
    state: Mutex<State>,
    closed: AtomicBool,
    wake: Arc<Notify>,
    #[cfg(test)]
    before_spawn: Mutex<Option<Arc<SpawnPause>>>,
}
#[cfg(test)]
pub(crate) struct SpawnPause {
    pub(crate) entered: Notify,
    pub(crate) release: std::sync::Barrier,
}
struct Custody {
    id: Uuid,
    cell: Arc<BackgroundWork>,
    task: AsyncMutex<Option<JoinHandle<()>>>,
}
fn custody() -> &'static Mutex<BTreeMap<Uuid, Arc<Custody>>> {
    static OWNERS: OnceLock<Mutex<BTreeMap<Uuid, Arc<Custody>>>> = OnceLock::new();
    OWNERS.get_or_init(Default::default)
}
impl Custody {
    fn publish(
        &self,
        task: &mut Option<JoinHandle<()>>,
        result: std::result::Result<(), tokio::task::JoinError>,
    ) -> DrainResult {
        // The exact handle has just returned Ready. Preserve its original error
        // and publish its terminal state synchronously, before any later await.
        let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Err(error) = result {
            state.report.record("background worker", 0, error.into());
        }
        task.take();
        state.phase = Phase::Joined;
        let outcome = state.report.complete();
        if outcome.is_ok() {
            state.custody = None;
        }
        drop(state);
        if outcome.is_ok() {
            custody()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.id);
        }
        outcome
    }
    fn try_join(&self) {
        // An active drain owns this lock across its await. Never replace its
        // waker; contention and unexpectedly Pending handles remain installed.
        let Ok(mut task) = self.task.try_lock() else {
            return;
        };
        let Some(child) = task.as_mut() else { return };
        if !child.is_finished() {
            return;
        }
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(result) = std::pin::Pin::new(child).poll(&mut context) {
            let _ = self.publish(&mut task, result);
        }
    }
    async fn join(&self) -> DrainResult {
        let mut task = self.task.lock().await;
        if let Some(child) = task.as_mut() {
            let result = child.await;
            return self.publish(&mut task, result);
        }
        self.cell.snapshot().unwrap_or_else(|| {
            self.cell
                .missing_custody("exact child handle is absent without a joined outcome")
        })
    }
}
impl BackgroundWork {
    #[cfg(test)]
    pub(crate) fn pause_before_spawn(&self) -> Arc<SpawnPause> {
        let pause = Arc::new(SpawnPause {
            entered: Notify::new(),
            release: std::sync::Barrier::new(2),
        });
        *self.before_spawn.lock().unwrap() = Some(pause.clone());
        pause
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub fn close(&self) {
        let _state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.closed.store(true, Ordering::Release);
        self.wake.notify_one();
    }
    pub fn wake(&self) -> Arc<Notify> {
        self.wake.clone()
    }
    pub fn start(
        self: &Arc<Self>,
        task: impl Future<Output = ()> + Send + 'static,
        budget: &BackgroundWorkBudget,
    ) -> Result<()> {
        let executor = tokio::runtime::Handle::try_current()?;
        let mut owners = custody().lock().unwrap_or_else(|p| p.into_inner());
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            !self.is_closed() && state.phase == Phase::New,
            "background worker already started or closed"
        );
        let id = Uuid::new_v4();
        ensure!(
            !owners.contains_key(&id),
            "background custody identity collision"
        );
        state.slot = Some(budget.reserve()?);
        #[cfg(test)]
        if let Some(pause) = self.before_spawn.lock().unwrap().take() {
            pause.entered.notify_one();
            pause.release.wait();
        }
        let owner = Arc::new(Custody {
            id,
            cell: self.clone(),
            task: AsyncMutex::new(Some(executor.spawn(task))),
        });
        state.phase = Phase::Running;
        state.custody = Some(id);
        owners.insert(id, owner);
        Ok(())
    }
    /// Retain an infrastructure failure in the same custody cell as the exact
    /// child handle. Expected request rejections belong in the caller's normal
    /// response; an Err here is a failed worker and is reported by typed drain.
    pub fn start_result(
        self: &Arc<Self>,
        task: impl Future<Output = Result<()>> + Send + 'static,
        budget: &BackgroundWorkBudget,
    ) -> Result<()> {
        let cell = self.clone();
        self.start(
            async move {
                if let Err(error) = task.await {
                    let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
                    state.report.record("background work result", 0, error);
                    cell.closed.store(true, Ordering::Release);
                }
            },
            budget,
        )
    }
    /// Try one actual join observation without waiting. No helper task exists;
    /// unfinished or contended child handles remain owned by the custody entry.
    pub fn observed(&self) -> Option<DrainResult> {
        let id = self.state.lock().unwrap_or_else(|p| p.into_inner()).custody;
        if let Some(id) = id {
            let owner = custody()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&id)
                .cloned();
            if let Some(owner) = owner {
                owner.try_join();
            } else {
                return Some(self.missing_custody(
                    "original child custody is unavailable before its exact join",
                ));
            }
        }
        self.snapshot()
    }
    fn snapshot(&self) -> Option<DrainResult> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match state.phase {
            Phase::Joined => Some(state.report.complete()),
            Phase::CustodyLost => Some(state.report.outcome(Some(DrainFailure::retained(
                state.report.issues()[0].clone(),
            )))),
            Phase::New | Phase::Running => None,
        }
    }
    pub fn drained(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.phase == Phase::Joined && (state.report.issues().is_empty() || state.reported)
    }
    fn report_terminal(&self) -> DrainResult {
        let (id, outcome) = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if !matches!(state.phase, Phase::New | Phase::Joined) {
                let issue = state.report.record(
                    "background reporting",
                    0,
                    anyhow::anyhow!("exact worker join is not complete"),
                );
                return state.report.outcome(Some(DrainFailure::retained(issue)));
            }
            state.phase = Phase::Joined;
            state.reported = true;
            (state.custody.take(), state.report.complete())
        };
        if let Some(id) = id {
            custody()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&id);
        }
        outcome
    }
    fn missing_custody(&self, message: &'static str) -> DrainResult {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.phase == Phase::Joined {
            return state.report.complete();
        }
        state.phase = Phase::CustodyLost;
        let issue = state
            .report
            .record("background custody", 0, anyhow::anyhow!(message));
        state.report.outcome(Some(DrainFailure::retained(issue)))
    }
    pub async fn drain(&self) -> DrainResult {
        self.close();
        let (phase, id) = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            (state.phase, state.custody)
        };
        if matches!(phase, Phase::New | Phase::Joined) {
            return self.report_terminal();
        }
        let owner = id.and_then(|id| {
            custody()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&id)
                .cloned()
        });
        if let Some(owner) = owner {
            // Cancellation drops only this waiter and its lock guard. The exact
            // child handle remains in the independently retained custody entry.
            let outcome = owner.join().await;
            if matches!(&outcome, Err(error) if error.completion() == kasumi_types::drain::DrainCompletion::Retained)
            {
                return outcome;
            }
            return self.report_terminal();
        }
        let outcome =
            self.missing_custody("original child custody is unavailable before its exact join");
        if matches!(&outcome, Err(error) if error.completion() == kasumi_types::drain::DrainCompletion::Retained)
        {
            return outcome;
        }
        // Another joiner may have published Joined before removing its entry.
        self.report_terminal()
    }
}

/// Process-local recovery inventory, including workers whose public runtime and
/// verifier facades were dropped. IDs are never wire authority or durable proof.
pub fn pending_background_custody(
    after: Option<Uuid>,
    limit: usize,
) -> Result<Vec<(Uuid, Arc<BackgroundWork>)>> {
    ensure!(
        (1..=256).contains(&limit),
        "background custody page limit must be 1..256"
    );
    let owners = custody().lock().unwrap_or_else(|p| p.into_inner());
    use std::ops::Bound::{Excluded, Unbounded};
    Ok(owners
        .range((after.map_or(Unbounded, Excluded), Unbounded))
        .take(limit)
        .map(|(id, owner)| (*id, owner.cell.clone()))
        .collect())
}

#[cfg(test)]
#[path = "background_work_tests.rs"]
mod tests;
