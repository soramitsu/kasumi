//! A serving waiter never owns the runtime. Registration is synchronous, and
//! both the supervisor handle and its actual resource inventory remain retained.
use anyhow::Result;
use kasumi_types::drain::{DrainCompletion, DrainReport, DrainResult};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::Poll,
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, watch};

/// One installed runtime pays for its registry slot before startup publication.
/// The reservation remains live until its exact supervisor has joined and its
/// outcome has been acknowledged. Repeated abandoned outcomes consume budget.
pub(crate) struct Registration {
    identity: uuid::Uuid,
    _reservation: kasumi_engine::admission::Reservation,
}
impl Registration {
    pub(crate) fn new(
        kind: Kind,
        identity: uuid::Uuid,
        admission: &Arc<kasumi_engine::admission::NodeAdmission>,
    ) -> Result<Self> {
        // Startup's existing pending inventory owns every acquired resource if
        // this reservation/fence fails before the runtime is published.
        check_admission(registry(kind), identity)?;
        let mut reservation = admission.reserve(4096, None)?;
        // Installed metadata holds bytes for its lifetime, not an inflight
        // request-operation slot. The exact charge is released only on Drop.
        reservation.retain(4096);
        Ok(Self {
            identity,
            _reservation: reservation,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Data,
    Authority,
}
type Registry = Mutex<Vec<Arc<Job>>>;
fn registry(kind: Kind) -> &'static Arc<Registry> {
    static DATA: OnceLock<Arc<Registry>> = OnceLock::new();
    static AUTHORITY: OnceLock<Arc<Registry>> = OnceLock::new();
    match kind {
        Kind::Data => &DATA,
        Kind::Authority => &AUTHORITY,
    }
    .get_or_init(Default::default)
}

pub(crate) struct Shutdown {
    requested: watch::Receiver<bool>,
    abandoned: watch::Receiver<bool>,
}
impl Shutdown {
    pub(crate) fn requested(&self) -> bool {
        *self.requested.borrow()
            || *self.abandoned.borrow()
            || self.requested.has_changed().is_err()
            || self.abandoned.has_changed().is_err()
    }
    pub(crate) async fn changed(&mut self) {
        if self.requested() {
            return;
        }
        tokio::select! { _ = self.requested.changed() => {}, _ = self.abandoned.changed() => {} }
    }
}
pub(crate) trait Owner: Send + 'static {
    fn run<'a>(
        &'a mut self,
        shutdown: &'a mut Shutdown,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    fn close(&mut self) -> Pin<Box<dyn Future<Output = DrainResult> + Send + '_>>;
}

#[derive(Default)]
struct State {
    report: DrainReport,
    complete: bool,
    acknowledged: bool,
}
struct Job {
    identity: uuid::Uuid,
    // The runtime is outside the supervisor future as well as every caught
    // run/close future. An unexpected supervisor abort leaves it here.
    owner: AsyncMutex<Option<Box<dyn Owner>>>,
    state: Mutex<State>,
    handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    joining: AsyncMutex<()>,
    stop: watch::Sender<bool>,
    _registration: Registration,
}
impl Job {
    async fn supervise(self: Arc<Self>, mut shutdown: Option<Shutdown>) {
        let mut inventory = self.owner.lock().await;
        let Some(owner) = inventory.as_mut() else {
            return;
        };
        if let Some(shutdown) = shutdown.as_mut() {
            let outcome = crate::startup_preparation::capture("serving", owner.run(shutdown)).await;
            if let Err(error) = outcome {
                self.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .report
                    .record("serving run", 0, error);
            }
        }
        self.stop.send_replace(true);
        let mut delay = Duration::from_secs(1);
        loop {
            // The actual composite stays outside this future even when close
            // itself panics. Never infer a completed census from that panic.
            let outcome = crate::startup_preparation::capture("serving drain", async {
                Ok(owner.close().await)
            })
            .await;
            let complete = {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                match outcome {
                    Ok(Ok(())) => true,
                    Ok(Err(failure)) => {
                        state.report.merge(&failure);
                        failure.completion() == DrainCompletion::Complete
                    }
                    Err(error) => {
                        state.report.record("serving drain panic", 0, error);
                        false
                    }
                }
            };
            if complete {
                break;
            }
            tracing::error!(
                retry_after_secs = delay.as_secs(),
                "serving drain incomplete; exact runtime remains retained"
            );
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(30));
        }
        // Drop physical owners before publishing completion. Declaration order
        // inside each composite makes the installation lock the final owner.
        inventory.take();
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .complete = true;
    }

    async fn join(self: &Arc<Self>) {
        let _joining = self.joining.lock().await;
        loop {
            let outcome = std::future::poll_fn(|cx| {
                let mut handle = self.handle.lock().unwrap_or_else(|p| p.into_inner());
                let Some(task) = handle.as_mut() else {
                    return Poll::Ready(Ok(()));
                };
                match Pin::new(task).poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(result) => {
                        handle.take();
                        Poll::Ready(result)
                    }
                }
            })
            .await;
            // Preserve a joined error before any new await. The slot describes
            // one installed supervisor, so repeated retries cannot grow it.
            if let Err(error) = outcome {
                self.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .report
                    .record("serving supervisor", 0, error.into());
            }
            if self
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .complete
            {
                return;
            }
            if self.owner.lock().await.is_none() {
                // A panicking destructor can remove an owner without publishing
                // a complete census. Keep a stable unresolved diagnostic; never
                // respawn an empty supervisor in an unbounded hot loop.
                self.state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .report
                    .record(
                        "serving inventory missing",
                        0,
                        anyhow::anyhow!(
                            "serving owner disappeared before completion was established"
                        ),
                    );
                tracing::error!(
                    "serving inventory unavailable; registry retains unresolved completion"
                );
                std::future::pending::<()>().await;
            }
            // Runtime shutdown may cancel its original task, but cannot remove
            // the registry's owner. Resume cleanup only, never restart serving.
            self.stop.send_replace(true);
            *self.handle.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(tokio::spawn(self.clone().supervise(None)));
        }
    }

    fn acknowledge(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            state.complete,
            "serving result requires a completed inventory"
        );
        state.acknowledged = true;
        state.report.complete().map_err(Into::into)
    }

    fn reap_acknowledged(&self) -> bool {
        let Ok(_joining) = self.joining.try_lock() else {
            return false;
        };
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.complete || !state.acknowledged {
            return false;
        }
        // Acknowledgement is issued only after join removed the actual handle.
        self.handle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
    }
}

fn prior_failure(entries: &[Arc<Job>], identity: uuid::Uuid) -> Option<anyhow::Error> {
    entries
        .iter()
        .filter(|job| job.identity == identity)
        .find_map(|job| {
            let state = job.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.acknowledged {
                return None;
            }
            let retained = if state.complete {
                None
            } else {
                state
                    .report
                    .issues()
                    .first()
                    .cloned()
                    .map(kasumi_types::drain::DrainFailure::retained)
            };
            if let Err(failure) = state.report.outcome(retained) {
                return Some(
                    anyhow::Error::new(failure)
                        .context("prior serving outcome requires explicit acknowledgement"),
                );
            }
            Some(anyhow::anyhow!(
                "prior serving owner must be joined and acknowledged before replacement"
            ))
        })
}
fn check_admission(registry: &Registry, identity: uuid::Uuid) -> Result<()> {
    let mut entries = registry.lock().unwrap_or_else(|p| p.into_inner());
    entries.retain(|job| !job.reap_acknowledged());
    prior_failure(&entries, identity).map_or(Ok(()), Err)
}

struct WaiterGuard(watch::Sender<bool>);
impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

pub(crate) fn serve(
    kind: Kind,
    registration: Registration,
    owner: impl Owner,
    shutdown: watch::Receiver<bool>,
) -> impl Future<Output = Result<()>> + Send + 'static {
    begin(registry(kind).clone(), registration, owner, shutdown)
}

fn begin(
    registry: Arc<Registry>,
    registration: Registration,
    owner: impl Owner,
    shutdown: watch::Receiver<bool>,
) -> impl Future<Output = Result<()>> + Send + 'static {
    let (stop, abandoned) = watch::channel(false);
    let guard = WaiterGuard(stop.clone());
    let job = Arc::new(Job {
        identity: registration.identity,
        owner: AsyncMutex::new(Some(Box::new(owner))),
        state: Default::default(),
        handle: Default::default(),
        joining: Default::default(),
        stop,
        _registration: registration,
    });
    let mut entries = registry.lock().unwrap_or_else(|p| p.into_inner());
    entries.retain(|job| !job.reap_acknowledged());
    let refused = prior_failure(&entries, job.identity);
    let admitted = refused.is_none();
    if let Some(error) = refused {
        job.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .report
            .record("serving replacement admission", 0, error);
    }
    // All synchronous steps occur before the returned future exists. Dropping
    // even an unpolled waiter leaves the exact owner and supervisor registered.
    entries.push(job.clone());
    *job.handle.lock().unwrap_or_else(|p| p.into_inner()) =
        Some(tokio::spawn(job.clone().supervise(if !admitted {
            None
        } else {
            Some(Shutdown {
                requested: shutdown,
                abandoned,
            })
        })));
    drop(entries);
    async move {
        let _guard = guard;
        job.join().await;
        let outcome = job.acknowledge();
        registry
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|job| !job.reap_acknowledged());
        outcome
    }
}

/// Stop opening/serving new instances before this final process drain. Cancelling
/// this call leaves its census and every original error in the registry.
pub(crate) async fn drain(kind: Kind) -> Result<()> {
    drain_registry(registry(kind)).await
}
async fn drain_registry(registry: &Registry) -> Result<()> {
    let jobs = registry.lock().unwrap_or_else(|p| p.into_inner()).clone();
    for job in &jobs {
        job.stop.send_replace(true);
    }
    for job in &jobs {
        job.join().await;
    }
    let mut report = DrainReport::default();
    // Acknowledge the whole census without yielding, after every handle joined.
    for job in &jobs {
        let mut state = job.state.lock().unwrap_or_else(|p| p.into_inner());
        if !state.acknowledged {
            if let Err(failure) = state.report.complete() {
                report.merge(&failure);
            }
            state.acknowledged = true;
        }
    }
    registry
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .retain(|job| !job.reap_acknowledged());
    report.complete().map_err(Into::into)
}

/// Tests select the exact installed runtime; they must never stop unrelated
/// concurrently running fixture instances via the process-wide final drain.
#[cfg(test)]
pub(crate) async fn drain_test_instance(kind: Kind, identity: uuid::Uuid) -> Result<()> {
    let registry = registry(kind);
    let job = registry
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|job| job.identity == identity)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("serving test instance is not registered"))?;
    job.stop.send_replace(true);
    job.join().await;
    let outcome = job.acknowledge();
    registry
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .retain(|job| !job.reap_acknowledged());
    outcome
}

#[cfg(test)]
#[path = "serving_owner_tests.rs"]
mod tests;
