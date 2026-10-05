//! One initial quote and one registered typed terminal for authority enrollment.
use crate::{administration::OriginalRecoveries, startup_resources::Resources};
use kasumi_engine::admission::{
    MemoryCore,
    startup::{PrepaidStartup, StartupTerminal, StartupTerminalId},
};
use kasumi_types::drain::{DrainCompletion, DrainFailure};
use std::{
    any::Any,
    future::Future,
    mem::ManuallyDrop,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Entry {
    #[default]
    NotEntered,
    Entered,
    Returned,
    Panicked,
}
#[derive(Default)]
pub(crate) struct Observation {
    pub(crate) entry: Entry,
    pub(crate) disposal: Entry,
    pub(crate) panic: Option<Box<dyn Any + Send>>,
    pub(crate) disposal_panic: Option<Box<dyn Any + Send>>,
    pub(crate) completed: bool,
}
impl Observation {
    fn returned(&self) -> bool {
        self.entry == Entry::Returned && self.disposal == Entry::Returned
    }
}
pub(crate) enum BodyOutcome {
    Completed,
    GenesisRejected,
}
#[derive(Default)]
pub(crate) struct Genesis {
    pub(crate) handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    original: Option<anyhow::Error>,
    join_original: Option<tokio::task::JoinError>,
    observation: Observation,
}
impl Genesis {
    pub(crate) async fn join(&mut self) -> bool {
        if self.observation.entry == Entry::Panicked || self.observation.entry == Entry::Returned {
            return self.clean();
        }
        if self.handle.is_none() {
            return false;
        }
        self.observation.entry = Entry::Entered;
        std::future::poll_fn(|cx| {
            let polled = catch_unwind(AssertUnwindSafe(|| {
                Pin::new(self.handle.as_mut().expect("same original genesis worker")).poll(cx)
            }));
            match polled {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(original)) => {
                    match original {
                        Ok(Ok(())) => {}
                        Ok(Err(original)) => self.original = Some(original),
                        Err(original) => self.join_original = Some(original),
                    }
                    self.observation.entry = Entry::Returned;
                    Poll::Ready(())
                }
                Err(original) => {
                    self.observation.panic = Some(original);
                    self.observation.entry = Entry::Panicked;
                    Poll::Ready(())
                }
            }
        })
        .await;
        if self.observation.entry == Entry::Returned {
            self.observation.disposal = Entry::Entered;
            let handle = self.handle.take().expect("same returned genesis handle");
            match catch_unwind(AssertUnwindSafe(|| drop(handle))) {
                Ok(()) => self.observation.disposal = Entry::Returned,
                Err(original) => {
                    self.observation.disposal_panic = Some(original);
                    self.observation.disposal = Entry::Panicked;
                }
            }
        }
        self.clean()
    }
    fn clean(&self) -> bool {
        self.observation.returned()
            && self.handle.is_none()
            && self.original.is_none()
            && self.join_original.is_none()
    }
}
pub(crate) struct EnrollmentTerminal {
    pub(crate) database_id: uuid::Uuid,
    // No terminal -> inventory -> terminal back-reference. The inventory owns
    // only its native original lanes and the same closed initial budget charge.
    pub(crate) parents: Option<OriginalRecoveries>,
    pub(crate) pending: Option<Resources>,
    pub(crate) original: Option<anyhow::Error>,
    pub(crate) body: Observation,
    pub(crate) cleanup: Observation,
    pub(crate) cleanup_error: Option<DrainFailure>,
    pub(crate) resources_disposal: Observation,
    pub(crate) genesis: Genesis,
    pub(crate) started: bool,
    pub(crate) ready: bool,
}
impl EnrollmentTerminal {
    pub(crate) fn new(database_id: uuid::Uuid, parents: OriginalRecoveries) -> Self {
        let mut pending = Resources::default();
        pending.owned_nodes = Vec::with_capacity(1);
        pending.owned_admissions = Vec::with_capacity(1);
        pending.audits = Vec::with_capacity(1);
        pending.verifiers = Vec::with_capacity(1);
        pending.stores = Vec::with_capacity(2);
        Self {
            database_id,
            parents: Some(parents),
            pending: Some(pending),
            original: None,
            body: Observation::default(),
            cleanup: Observation::default(),
            cleanup_error: None,
            resources_disposal: Observation::default(),
            genesis: Genesis::default(),
            started: false,
            ready: false,
        }
    }
    fn succeeded(&self) -> bool {
        self.ready
            && self.body.returned()
            && self.body.completed
            && self.cleanup.returned()
            && self.resources_disposal.returned()
            && self.pending.is_none()
            && self.parents.is_none()
            && self.original.is_none()
            && self.cleanup_error.is_none()
            && self.genesis.clean()
    }
}
pub(crate) struct EnrollmentPlan<'a> {
    pub(crate) policy: &'a kasumi_engine::admission::AdmissionConfig,
    pub(crate) participants: crate::administration::OriginalRecoveryParticipants<'a>,
    pub(crate) database_id: uuid::Uuid,
}
impl StartupTerminal for EnrollmentTerminal {
    type Plan<'a> = EnrollmentPlan<'a>;
    type Output = ();
    fn backing(
        plan: &Self::Plan<'_>,
    ) -> anyhow::Result<kasumi_engine::admission::startup::StartupBacking> {
        OriginalRecoveries::startup_backing(plan.policy, plan.participants)?
            .include(crate::authority_node_enrollment::body_backing()?)?
            .include(cleanup_backing()?)?
            .array::<kasumi_store::NodeStore>(1)?
            .array::<Arc<kasumi_engine::admission::NodeAdmission>>(1)?
            .array::<Arc<kasumi_engine::SecurityAudit>>(1)?
            .array::<Arc<crate::signer_runtime::InstalledSignerVerifier>>(1)?
            .array::<Arc<kasumi_store::TenantStore>>(2)
    }
    fn allocate(plan: Self::Plan<'_>, charge: kasumi_types::SharedBudgetCharge) -> Self {
        let parents = OriginalRecoveries::allocate(plan.policy, plan.participants, charge)
            .expect("same previously validated inert inventory plan");
        Self::new(plan.database_id, parents)
    }
    fn begin(&mut self) -> bool {
        if self.started {
            return false;
        }
        self.started = true;
        true
    }
    fn retirement_ready(&self) -> bool {
        self.succeeded()
    }
    fn claim_output(&mut self) -> Option<()> {
        self.succeeded().then_some(())
    }
}
/// Whole originals stay under the same initial registered terminal. This enum
/// deliberately has no StdError or conversion into an owning Anyhow error.
pub enum EnrollmentFailure {
    Preflight(anyhow::Error),
    Retained(EnrollmentTerminalFacade),
}
impl From<anyhow::Error> for EnrollmentFailure {
    fn from(original: anyhow::Error) -> Self {
        Self::Preflight(original)
    }
}
impl EnrollmentFailure {
    pub fn with_operation_error<R>(
        &self,
        inspect: impl for<'a> FnOnce(Option<&'a anyhow::Error>) -> R,
    ) -> R {
        match self {
            Self::Preflight(original) => inspect(Some(original)),
            Self::Retained(original) => {
                original.with_report(|report| inspect(report.and_then(|report| report.original())))
            }
        }
    }
    pub fn retained(&self) -> Option<&EnrollmentTerminalFacade> {
        match self {
            Self::Retained(owner) => Some(owner),
            Self::Preflight(_) => None,
        }
    }
}
impl std::fmt::Display for EnrollmentFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preflight(original) => std::fmt::Display::fmt(original, f),
            Self::Retained(original) => std::fmt::Display::fmt(original, f),
        }
    }
}
impl std::fmt::Debug for EnrollmentFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preflight(original) => f.debug_tuple("Preflight").field(original).finish(),
            Self::Retained(original) => f.debug_tuple("Retained").field(&original.id()).finish(),
        }
    }
}
pub struct EnrollmentTerminalFacade {
    pub(crate) terminal: PrepaidStartup<EnrollmentTerminal>,
}
impl EnrollmentTerminalFacade {
    pub fn id(&self) -> StartupTerminalId {
        self.terminal.id()
    }
    pub fn retained(memory: &MemoryCore, id: StartupTerminalId) -> Option<Self> {
        memory.prepaid_startup(id).map(|terminal| Self { terminal })
    }
    pub fn with_report<R>(
        &self,
        inspect: impl for<'a> FnOnce(Option<EnrollmentReport<'a>>) -> R,
    ) -> R {
        self.terminal
            .with_report(|terminal| inspect(terminal.map(|terminal| EnrollmentReport { terminal })))
    }
    pub async fn with_node_start_failure<R>(
        &self,
        index: usize,
        inspect: impl for<'a> FnOnce(&'a kasumi_store::NodeStoreStartFailure) -> R,
    ) -> Option<R> {
        let parents = self
            .terminal
            .with_report(|terminal| terminal.and_then(|terminal| terminal.parents.clone()))?;
        parents.with_node_start_failure(index, inspect).await
    }
    pub async fn join(&self) {
        self.terminal.join_worker().await;
    }
    pub fn with_worker_error<R>(
        &self,
        inspect: impl for<'a> FnOnce(Option<&'a tokio::task::JoinError>) -> R,
    ) -> Option<R> {
        self.terminal.with_worker_error(inspect)
    }
    pub(crate) async fn claim(self) -> std::result::Result<(), EnrollmentFailure> {
        self.join().await;
        let succeeded = self
            .terminal
            .with_report(|terminal| terminal.is_some_and(EnrollmentTerminal::succeeded));
        if succeeded
            && self.terminal.take_output().await.is_some()
            && self.terminal.retire_empty().await
        {
            return Ok(());
        }
        Err(EnrollmentFailure::Retained(self))
    }
    #[cfg(test)]
    pub(crate) fn registered_at(memory: &MemoryCore, index: usize) -> Option<Self> {
        memory
            .prepaid_startup_at(index)
            .map(|terminal| Self { terminal })
    }
}
impl Clone for EnrollmentTerminalFacade {
    fn clone(&self) -> Self {
        Self {
            terminal: self.terminal.clone(),
        }
    }
}
impl std::fmt::Display for EnrollmentTerminalFacade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "authority enrollment terminal {:?}: ", self.id())?;
        self.with_report(|report| match report.and_then(|report| report.original()) {
            Some(original) => std::fmt::Display::fmt(original, f),
            None => f.write_str("original startup custody retained"),
        })
    }
}
pub struct EnrollmentReport<'a> {
    terminal: &'a EnrollmentTerminal,
}
impl<'a> EnrollmentReport<'a> {
    pub fn database_id(&self) -> uuid::Uuid {
        self.terminal.database_id
    }
    pub fn original(&self) -> Option<&'a anyhow::Error> {
        self.terminal.original.as_ref()
    }
    pub fn cleanup(&self) -> Option<&'a DrainFailure> {
        self.terminal.cleanup_error.as_ref()
    }
    pub fn genesis_error(&self) -> Option<&'a anyhow::Error> {
        self.terminal.genesis.original.as_ref()
    }
    pub fn genesis_join_error(&self) -> Option<&'a tokio::task::JoinError> {
        self.terminal.genesis.join_original.as_ref()
    }
    pub fn with_body_panic<R>(&self, inspect: impl FnOnce(&(dyn Any + Send)) -> R) -> Option<R> {
        self.terminal.body.panic.as_deref().map(inspect)
    }
    pub fn with_cleanup_disposal_panic<R>(
        &self,
        inspect: impl FnOnce(&(dyn Any + Send)) -> R,
    ) -> Option<R> {
        self.terminal.cleanup.disposal_panic.as_deref().map(inspect)
    }
    pub fn resources_retained(&self) -> bool {
        self.terminal.pending.is_some()
    }
    pub fn native_original_retained(&self) -> bool {
        self.terminal.parents.is_some()
    }
    pub fn body_returned(&self) -> bool {
        self.terminal.body.returned()
    }
    pub fn cleanup_returned(&self) -> bool {
        self.terminal.cleanup.returned()
    }
    pub fn with_future_disposal_panic<R>(
        &self,
        inspect: impl FnOnce(&(dyn Any + Send)) -> R,
    ) -> Option<R> {
        self.terminal.body.disposal_panic.as_deref().map(inspect)
    }
    pub fn with_cleanup_panic<R>(&self, inspect: impl FnOnce(&(dyn Any + Send)) -> R) -> Option<R> {
        self.terminal.cleanup.panic.as_deref().map(inspect)
    }
    pub fn with_resource_disposal_panic<R>(
        &self,
        inspect: impl FnOnce(&(dyn Any + Send)) -> R,
    ) -> Option<R> {
        self.terminal
            .resources_disposal
            .panic
            .as_deref()
            .map(inspect)
    }
}
/// Exact named body is pinned once. Its returned original is installed before
/// independent in-place destruction, including a separate destructor panic.
pub(crate) struct Body<'a, F> {
    future: ManuallyDrop<Pin<Box<F>>>,
    observation: &'a mut Observation,
    original: &'a mut Option<anyhow::Error>,
    disposed: bool,
}
impl<'a, F> Body<'a, F> {
    pub(crate) fn new(
        future: F,
        observation: &'a mut Observation,
        original: &'a mut Option<anyhow::Error>,
    ) -> Self {
        Self {
            future: ManuallyDrop::new(Box::pin(future)),
            observation,
            original,
            disposed: false,
        }
    }
    fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.observation.disposal = Entry::Entered;
        match catch_unwind(AssertUnwindSafe(|| unsafe {
            ManuallyDrop::drop(&mut self.future)
        })) {
            Ok(()) => self.observation.disposal = Entry::Returned,
            Err(original) => {
                self.observation.disposal_panic = Some(original);
                self.observation.disposal = Entry::Panicked;
            }
        }
    }
}
impl<F: Future<Output = anyhow::Result<BodyOutcome>>> Future for Body<'_, F> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = unsafe { self.get_unchecked_mut() };
        this.observation.entry = Entry::Entered;
        match catch_unwind(AssertUnwindSafe(|| this.future.as_mut().poll(cx))) {
            Ok(Poll::Pending) => return Poll::Pending,
            Ok(Poll::Ready(original)) => {
                match original {
                    Ok(BodyOutcome::Completed) => this.observation.completed = true,
                    Ok(BodyOutcome::GenesisRejected) => {}
                    Err(original) => *this.original = Some(original),
                }
                this.observation.entry = Entry::Returned;
            }
            Err(original) => {
                this.observation.panic = Some(original);
                this.observation.entry = Entry::Panicked;
            }
        }
        this.dispose();
        Poll::Ready(())
    }
}
impl<F> Drop for Body<'_, F> {
    fn drop(&mut self) {
        self.dispose();
    }
}
fn cleanup_backing() -> anyhow::Result<kasumi_engine::admission::startup::StartupBacking> {
    fn quote<F: Future>(
        _: impl FnOnce(&'static Resources) -> F,
    ) -> anyhow::Result<kasumi_engine::admission::startup::StartupBacking> {
        kasumi_engine::admission::startup::StartupBacking::empty().boxed::<F>()
    }
    quote(Resources::close)
}
pub(crate) async fn cleanup(terminal: &mut EnrollmentTerminal) {
    let parents = terminal
        .parents
        .as_ref()
        .expect("same initial enrollment inventory");
    parents.seal();
    let native_retained = parents.retained().await;
    {
        let EnrollmentTerminal {
            pending,
            cleanup,
            cleanup_error,
            ..
        } = terminal;
        let Some(resources) = pending.as_ref() else {
            return;
        };
        let mut future = ManuallyDrop::new(Box::pin(resources.close()));
        cleanup.entry = Entry::Entered;
        std::future::poll_fn(|cx| {
            let result = catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx)));
            match result {
                Ok(Poll::Pending) => Poll::Pending,
                Ok(Poll::Ready(original)) => {
                    *cleanup_error = original.err();
                    cleanup.entry = Entry::Returned;
                    Poll::Ready(())
                }
                Err(original) => {
                    cleanup.panic = Some(original);
                    cleanup.entry = Entry::Panicked;
                    Poll::Ready(())
                }
            }
        })
        .await;
        cleanup.disposal = Entry::Entered;
        match catch_unwind(AssertUnwindSafe(|| unsafe {
            ManuallyDrop::drop(&mut future)
        })) {
            Ok(()) => cleanup.disposal = Entry::Returned,
            Err(original) => {
                cleanup.disposal_panic = Some(original);
                cleanup.disposal = Entry::Panicked;
            }
        }
    }
    let cleanup_complete = terminal.cleanup.returned()
        && terminal
            .cleanup_error
            .as_ref()
            .is_none_or(|error| error.completion() == DrainCompletion::Complete);
    if native_retained || !cleanup_complete || terminal.body.disposal != Entry::Returned {
        return;
    }
    terminal.resources_disposal.entry = Entry::Entered;
    let resources = terminal
        .pending
        .take()
        .expect("same positively closed resources");
    match catch_unwind(AssertUnwindSafe(|| drop(resources))) {
        Ok(()) => {
            terminal.resources_disposal.entry = Entry::Returned;
            terminal.resources_disposal.disposal = Entry::Returned;
            drop(terminal.parents.take());
        }
        Err(original) => {
            terminal.resources_disposal.panic = Some(original);
            terminal.resources_disposal.entry = Entry::Panicked;
        }
    }
}
