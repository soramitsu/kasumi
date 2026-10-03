//! Exact application selection custody. This is a publication/lifecycle owner,
//! not a primary tree, document source, authorization or cache-residency proof.
use crate::admission::{MemoryCore, NodeAdmission, Reservation};
use anyhow::{Context as _, Result, ensure};
use kasumi_query::QueryWorkspace;
use kasumi_raft::{
    ApplicationBoundaryRef, ApplicationSelectionMode, PreparedSelectionPlan, RaftLimits,
    SelectedApplicationPosition, SelectionPreparer, SelectionWorkspace,
};
use kasumi_store::{
    PreparedTenantPointWorkspace, PreparedTenantStorageReadView, TenantStorageReadView,
    TenantStorageSet,
};
use kasumi_types::drain::{DrainFailure, DrainReport, DrainResult};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

#[path = "application_source_ownership.rs"]
mod ownership;
use ownership::SourceCredit;
#[path = "application_source_cohort.rs"]
mod cohort;
use cohort::SourceCohort;
#[path = "application_source_completion.rs"]
pub(crate) mod completion;
pub(crate) use completion::CompletionLoan;
// Quotation-only foundation; no current source acquisition uses it.
#[cfg(test)]
#[path = "application_source_memory_quote.rs"]
mod memory_quote;

pub(crate) type SourceRootsRef = ownership::Strong<SourceRoots>;
type SourceRootsWeak = ownership::Weak<SourceRoots>;
type CellRef = ownership::Strong<Cell>;
type CellWeak = ownership::Weak<Cell>;
type ViewRef = ownership::Strong<TenantStorageReadView>;
type ProtectedViewRef = ownership::Strong<kasumi_store::PreparedTenantSourceReadView>;
type FailureRef = ownership::Strong<FailureOwner>;

type Position = SelectedApplicationPosition<Workspace>;

fn allocated(bytes: usize) -> Result<u64> {
    u64::try_from(
        bytes
            .checked_next_power_of_two()
            .and_then(|n| n.checked_add(64))
            .context("application source allocation overflow")?,
    )
    .map_err(Into::into)
}
fn cell_bytes() -> Result<u64> {
    // Cell Arc, independent paired-view Arc and a full B=6 internal registry
    // node per entry (including partially occupied nodes), plus error owner boxes.
    Ok(
        allocated(std::mem::size_of::<Cell>() + 2 * std::mem::size_of::<usize>())?
            + allocated(
                std::mem::size_of::<TenantStorageReadView>() + 2 * std::mem::size_of::<usize>(),
            )?
            + allocated(
                11 * std::mem::size_of::<(u64, CellRef)>() + 16 * std::mem::size_of::<usize>(),
            )?
            + SourceCredit::required_bytes()?
            + allocated(2 * std::mem::size_of::<RootPreparation>())?
            + 4096,
    )
}

/// Real installed-provider workspace. The proof keeps its own mutable grant;
/// the independently charged cell remains funded even if a decoder unwinds.
struct Workspace {
    core: Arc<MemoryCore>,
    baseline: u64,
    // Capture cannot grow beyond the complete producer-owned prospective quote.
    planned_peak: Option<u64>,
    funding: WorkspaceFunding,
}
enum WorkspaceFunding {
    Ordinary(Reservation),
    Publication { credit: SourceCredit, retained: u64 },
}
impl SelectionWorkspace for Workspace {
    fn require_memory(&self, view: &kasumi_raft::SelectionReadIdentity<'_>) -> Result<()> {
        let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = self.core.clone();
        view.require_memory(&memory)
    }
    fn ensure_peak(&mut self, bytes: u64) -> Result<()> {
        let total = self
            .baseline
            .checked_add(bytes)
            .context("application source quote overflow")?;
        ensure!(
            self.planned_peak.is_none_or(|peak| total <= peak),
            "application source exceeded prospective peak"
        );
        match &mut self.funding {
            WorkspaceFunding::Ordinary(reservation) => reservation.ensure_peak(total)?,
            WorkspaceFunding::Publication { credit, .. } => {
                ensure!(
                    credit.publication_lane().is_some(),
                    "source workspace lost lane funding"
                );
            }
        }
        Ok(())
    }
    fn retain(&mut self, bytes: u64) -> Result<()> {
        let bytes = self
            .baseline
            .checked_add(bytes)
            .context("application source retained quote overflow")?;
        ensure!(
            self.planned_peak.is_none_or(|peak| bytes <= peak),
            "application source retained quote exceeds prospective peak"
        );
        match &mut self.funding {
            WorkspaceFunding::Ordinary(reservation) => {
                reservation.ensure_peak(bytes)?;
                reservation.retain(bytes);
            }
            WorkspaceFunding::Publication { retained, .. } => {
                ensure!(
                    bytes <= *retained,
                    "source retained DTO exceeds funded lane"
                );
            }
        }
        Ok(())
    }
}

struct Gate {
    consumers_closed: bool,
    preparations_closed: bool,
    serving: bool,
    next: u64,
    cells: BTreeMap<u64, CellRef>,
    latest: CellWeak,
    waiter: Option<Waker>,
}
/// One database-local inventory. It owns no Engine, Generation, startup owner,
/// worker or reaper. The existing Raft startup custody anchors this registry.
pub(crate) struct SourceRoots {
    stores: Arc<TenantStorageSet>,
    admission: Arc<NodeAdmission>,
    limits: RaftLimits,
    gate: Mutex<Gate>,
    completion: OnceLock<completion::CompletionRef>,
    cohort: OnceLock<SourceCohort>,
    construction_failure: OnceLock<RecordedFailure>,
    capacity_cleanup_failure: OnceLock<RecordedFailure>,
    _reservation: SourceCredit,
}
struct CellState {
    preparing: bool,
    closing: bool,
    closed: bool,
    inflight: usize,
    view: Option<ViewRef>,
    protected_view: Option<ProtectedViewRef>,
}
struct Cell {
    id: u64,
    roots: SourceRootsWeak,
    handles: AtomicUsize,
    state: Mutex<CellState>,
    history_escape: Mutex<()>,
    position: OnceLock<Position>,
    _metadata_parent: OnceLock<CellRef>,
    frozen: OnceLock<bool>,
    failure: OnceLock<RecordedFailure>,
    // Actual point backing has one independent consuming retirement. Its
    // original panic must not replace body, alias or registered-close evidence.
    point_failure: OnceLock<RecordedFailure>,
    close_failure: OnceLock<RecordedFailure>,
    alias_failure: OnceLock<RecordedFailure>,
    native_retained: AtomicBool,
    // Preclaimed before capture, then transferred into the canonical proof.
    workspace: Mutex<Option<Workspace>>,
    _registry_reservation: SourceCredit,
    _reservation: SourceCredit,
}

/// Explicit selected-handle count excludes registry, in-flight callbacks and
/// returned diagnostic aliases. The last actual selected handle retires the
/// parent during ordinary operation, independently of database shutdown.
pub(crate) struct SelectedApplication {
    cell: CellRef,
}
impl Clone for SelectedApplication {
    fn clone(&self) -> Self {
        let old = self.cell.handles.fetch_add(1, Ordering::Relaxed);
        assert!(
            old > 0 && old < isize::MAX as usize,
            "selected application handle overflow"
        );
        Self {
            cell: self.cell.clone(),
        }
    }
}
impl Drop for SelectedApplication {
    fn drop(&mut self) {
        if self.cell.handles.fetch_sub(1, Ordering::AcqRel) == 1
            && let Some(roots) = self.cell.roots.upgrade()
        {
            roots.retire(&self.cell, false);
        }
    }
}
impl std::fmt::Debug for SelectedApplication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SelectedApplication")
            .field(&self.cell.id)
            .finish()
    }
}

struct SourcePanic {
    _payload: Mutex<Box<dyn std::any::Any + Send>>,
}
impl std::fmt::Debug for SourcePanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("application source captured original panic")
    }
}
impl std::fmt::Display for SourcePanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
impl std::error::Error for SourcePanic {}

// OPEN: enclosing SourceFailure anyhow boxes and diagnostic collection
// backing still require their own ownership boundary. The paired FailureRef
// covers only the actual FailureOwner allocation and its owned original error.
struct FailureOwner {
    original: anyhow::Error,
}
struct RecordedFailure {
    owner: FailureRef,
    issue: kasumi_types::drain::DrainIssueRef,
}
#[derive(Clone)]
struct SourceFailure {
    owner: FailureRef,
}
impl SourceFailure {
    fn original(&self) -> &(dyn std::error::Error + 'static) {
        self.owner.original.as_ref()
    }
}
impl std::fmt::Debug for SourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ApplicationSourceFailure")
            .field(&self.owner.original)
            .finish()
    }
}
impl std::fmt::Display for SourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.original(), f)
    }
}
impl std::error::Error for SourceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original())
    }
}
impl Cell {
    fn record_failure(&self, error: anyhow::Error, close: bool) {
        let slot = if close {
            &self.close_failure
        } else {
            &self.failure
        };
        self.record_failure_in(
            error,
            slot,
            if close {
                "application source close"
            } else {
                "application source"
            },
        );
    }
    fn capture_failed(&self) -> bool {
        self.failure.get().is_some() || self.point_failure.get().is_some()
    }
    fn record_point_failure(&self, payload: Box<dyn std::any::Any + Send>) {
        self.record_failure_in(
            SourcePanic {
                _payload: Mutex::new(payload),
            }
            .into(),
            &self.point_failure,
            "application point backing retirement",
        );
    }
    fn record_alias_failure(&self, error: anyhow::Error) {
        self.record_failure_in(error, &self.alias_failure, "application source alias close");
    }
    fn record_failure_in(
        &self,
        error: anyhow::Error,
        slot: &OnceLock<RecordedFailure>,
        phase: &'static str,
    ) {
        if slot.get().is_some() {
            return;
        }
        self._reservation.seal_publication();
        // Conservatively retain until a callback-free inventory pass has made
        // the exact native disposition check outside every registry lock.
        self.native_retained.store(true, Ordering::Release);
        // The diagnostic may outlive its cell; carry the actual cell floor
        // outside the failure allocation without retaining the Cell/registry.
        let owner = FailureRef::new(FailureOwner { original: error }, self._reservation.clone());
        let mut report = DrainReport::default();
        let issue = report.record(
            phase,
            self.id as usize,
            SourceFailure {
                owner: owner.clone(),
            }
            .into(),
        );
        let _ = slot.set(RecordedFailure { owner, issue });
    }
    fn error(&self) -> anyhow::Error {
        SourceFailure {
            owner: self
                .failure
                .get()
                .or_else(|| self.point_failure.get())
                .or_else(|| self.close_failure.get())
                .or_else(|| self.alias_failure.get())
                .expect("source failure recorded")
                .owner
                .clone(),
        }
        .into()
    }
    fn retains_native_failure(&self) -> bool {
        let mut retained = false;
        // Visit every alias even after one reports Pending: a body failure and
        // its close shell can share one reader, and both facades must detach.
        for failure in [
            self.failure.get(),
            self.point_failure.get(),
            self.alias_failure.get(),
            self.close_failure.get(),
        ]
        .into_iter()
        .flatten()
        {
            for cause in failure.owner.original.chain() {
                if cause.downcast_ref::<SourcePanic>().is_some()
                    || cause
                        .downcast_ref::<kasumi_store::PointRetirementFailure>()
                        .is_some()
                {
                    retained = true;
                }
                if let Some(failure) = cause.downcast_ref::<kasumi_store::NodeScopedReadFailure>() {
                    retained |= failure.try_retire_routine()
                        != kasumi_store::StorageCensusDisposition::Retired;
                }
                if let Some(retirement) =
                    cause.downcast_ref::<kasumi_store::NodeScopedReadRetirement>()
                {
                    retained |= retirement.retry_retirement()
                        != kasumi_store::StorageCensusDisposition::Retired;
                }
            }
        }
        retained
    }
    fn close_has_exact_native_retirement(&self) -> bool {
        self.close_failure.get().is_some_and(|failure| {
            failure.owner.original.chain().any(|cause| {
                cause
                    .downcast_ref::<kasumi_store::NodeScopedReadFailure>()
                    .is_some()
                    || cause
                        .downcast_ref::<kasumi_store::NodeScopedReadRetirement>()
                        .is_some()
            })
        })
    }
}

/// Keep incoming backing outside every fallible preparation branch until the
/// registered Cell takes it. Retiring it cannot replace the original failure.
fn with_incoming_points(
    points: PreparedTenantPointWorkspace,
    prepare: impl FnOnce(&mut Option<PreparedTenantPointWorkspace>) -> Result<()>,
) -> Result<()> {
    let mut points = Some(points);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepare(&mut points)));
    if let Some(points) = points {
        if let Err(payload) = points.retire() {
            let original = match outcome {
                Ok(result) => result.err().unwrap_or_else(|| {
                    anyhow::anyhow!("application source preparation omitted point transfer")
                }),
                Err(payload) => SourcePanic {
                    _payload: Mutex::new(payload),
                }
                .into(),
            };
            return Err(kasumi_store::PointRetirementFailure::new(original, payload).into());
        }
        if outcome.as_ref().is_ok_and(|result| result.is_ok()) {
            anyhow::bail!("application source preparation omitted point transfer");
        }
    }
    // After clean retirement or transfer, the original unwind still belongs to
    // the publisher's panic custodian. Only two independent failures need the
    // combined error above; do not turn an ordinary unwind into a returned error.
    match outcome {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

pub(crate) struct RootPreparation {
    roots: SourceRootsRef,
    cell: CellRef,
    plan: Option<PreparedSelectionPlan>,
    points: Option<PreparedTenantPointWorkspace>,
    queued: Option<PreparedTenantStorageReadView>,
    queued_source: Option<kasumi_store::PreparedRegisteredSource>,
    cohort_points: bool,
    settled: bool,
}

/// The actual storage publisher supplies the closed prospective plan.
pub(crate) struct PublicationPreparation<'a> {
    roots: &'a SourceRootsRef,
    prepared: Option<RootPreparation>,
    attempted: bool,
    repeated: bool,
}
impl SelectionPreparer for PublicationPreparation<'_> {
    fn prepare(
        &mut self,
        plan: &PreparedSelectionPlan,
        points: PreparedTenantPointWorkspace,
    ) -> Result<()> {
        with_incoming_points(points, |points| {
            if self.attempted {
                self.repeated = true;
                anyhow::bail!("application source preparation repeated");
            }
            self.attempted = true;
            plan.require_stores(&self.roots.stores)?;
            self.prepared = Some(self.roots.prepare_kind_planned(true, Some(plan), points)?);
            Ok(())
        })
    }
}
impl PublicationPreparation<'_> {
    pub(crate) fn finish_publication(
        self,
        expectation: &kasumi_raft::PublicationExpectation<'_>,
        receipt: kasumi_raft::JointPublicationReceipt<'_>,
    ) -> Result<RootPreparation> {
        let prepared = self.finish_inner()?;
        let plan = prepared
            .plan
            .as_ref()
            .context("actual publication plan absent")?;
        expectation.consume(receipt, plan)?;
        Ok(prepared)
    }
    fn finish_inner(self) -> Result<RootPreparation> {
        ensure!(!self.repeated, "application source preparation repeated");
        self.prepared
            .context("application publisher omitted or failed source preparation")
    }
}
impl SourceRoots {
    fn registry_bytes() -> Result<u64> {
        let registry = allocated(std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>())?;
        let credit = SourceCredit::required_bytes()?;
        let binding = kasumi_raft::ApplicationSourceBinding::required_bytes::<SourceRootsRef>()?;
        registry
            .checked_add(credit)
            .and_then(|bytes| bytes.checked_add(binding))
            .and_then(|bytes| bytes.checked_add(2 * 4096))
            .context("application source registry quote overflow")
    }
    /// Fixed registry and completion owners installed for one database. Selected
    /// roots, point buffers and candidate bodies use their own workload quotes.
    #[cfg(test)]
    pub(crate) fn required_fixed_admission_bytes() -> Result<u64> {
        Self::registry_bytes()?
            .checked_add(completion::OrdinarySourceCompletion::required_bytes()?)
            .context("application source fixed owner quote overflow")
    }

    pub(crate) fn new(
        stores: Arc<TenantStorageSet>,
        admission: Arc<NodeAdmission>,
        limits: RaftLimits,
    ) -> Result<(SourceRootsRef, kasumi_raft::ApplicationSourceBinding)> {
        admission
            .memory()
            .require_store_memory(stores.application())?;
        admission
            .memory()
            .require_store_memory(stores.custody().store())?;
        let bytes = Self::registry_bytes()?;
        let reservation = admission.reserve_application_source(bytes)?;
        let credit = SourceCredit::new(reservation);
        let roots = SourceRootsRef::new(
            Self {
                stores,
                admission,
                limits,
                gate: Mutex::new(Gate {
                    consumers_closed: false,
                    preparations_closed: false,
                    serving: false,
                    next: 0,
                    cells: BTreeMap::new(),
                    latest: CellWeak::new(),
                    waiter: None,
                }),
                completion: OnceLock::new(),
                cohort: OnceLock::new(),
                construction_failure: OnceLock::new(),
                capacity_cleanup_failure: OnceLock::new(),
                _reservation: credit.clone(),
            },
            credit,
        );
        let binding = kasumi_raft::ApplicationSourceBinding::new(roots.clone());
        Ok((roots, binding))
    }
    fn record_capacity_failure(&self, error: anyhow::Error) {
        // Called only by the unique construction or consuming capacity-close
        // worker. Its Running state prevents a second destructive invocation.
        let target = if self.construction_failure.get().is_none() {
            &self.construction_failure
        } else {
            &self.capacity_cleanup_failure
        };
        assert!(
            target.get().is_none(),
            "source capacity consumed more than once"
        );
        let owner = FailureRef::new(FailureOwner { original: error }, self._reservation.clone());
        let mut report = DrainReport::default();
        let issue = report.record(
            "application source capacity",
            0,
            SourceFailure {
                owner: owner.clone(),
            }
            .into(),
        );
        assert!(target.set(RecordedFailure { owner, issue }).is_ok());
    }
    fn capacity_failure_retained(&self) -> bool {
        self.capacity_cleanup_failure.get().is_some()
            || self.construction_failure.get().is_some_and(|failure| {
                !self.cohort.get().is_some_and(SourceCohort::is_closed)
                    || !failure
                        .owner
                        .original
                        .is::<cohort::CohortAdmissionRefusal>()
            })
    }
    fn retry_retirements(&self) {
        let end = self.gate.lock().unwrap_or_else(|p| p.into_inner()).next;
        let mut cursor = None;
        loop {
            let cell = {
                let gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
                match cursor {
                    None => gate.cells.first_key_value(),
                    Some(id) => gate
                        .cells
                        .range((
                            std::ops::Bound::Excluded(id),
                            std::ops::Bound::Excluded(end),
                        ))
                        .next(),
                }
                .filter(|(id, _)| **id < end)
                .map(|(_, cell)| cell.clone())
            };
            let Some(cell) = cell else { break };
            cursor = Some(cell.id);
            self.retire(&cell, false);
        }
    }
}
impl SourceRootsRef {
    /// Closed startup installer. These newly constructed roots have not escaped
    /// to an Engine or begun any source acquisition when this is called.
    pub(crate) fn bind_lifecycle(
        &self,
        buffers: &Arc<kasumi_raft::SnapshotBufferOwner>,
        source: kasumi_raft::ApplicationSourceBinding,
    ) -> Result<()> {
        ensure!(
            self.completion.get().is_none(),
            "application completion already installed"
        );
        ensure!(
            self.gate.lock().unwrap_or_else(|p| p.into_inner()).next == 0,
            "application completion must precede source acquisition"
        );
        let (completion, binding) = completion::OrdinarySourceCompletion::new(self)?;
        let mut source = Some(source);
        let mut binding = Some(binding);
        buffers.bind_application_sources_with_completion(&mut source, &mut binding)?;
        debug_assert!(source.is_none() && binding.is_none());
        // The private construction caller owns these roots exclusively at this
        // point; neither provider callbacks nor user work occur after binding.
        assert!(self.completion.set(completion).is_ok());
        Ok(())
    }
    /// Called only by construction after accepted replay/ingress coverage has
    /// been certified. Installing capacity is not itself acceptance authority.
    pub(crate) fn install_source_cohort(
        &self,
        envelope: kasumi_raft::PreparedOrdinarySourceEnvelope,
    ) -> Result<()> {
        ensure!(
            self.cohort.get().is_none(),
            "source cohort already installed"
        );
        ensure!(
            self.gate.lock().unwrap_or_else(|p| p.into_inner()).next == 0,
            "source cohort must precede first selected root"
        );
        envelope.require_stores(&self.stores)?;
        assert!(self.cohort.set(SourceCohort::empty(envelope)).is_ok());
        let cohort = self.cohort.get().expect("registered cohort construction");
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cohort.install(self)));
        let error = match outcome {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => error,
            Err(payload) => SourcePanic {
                _payload: Mutex::new(payload),
            }
            .into(),
        };
        cohort.seal();
        self.record_capacity_failure(error);
        Err(SourceFailure {
            owner: self.construction_failure.get().unwrap().owner.clone(),
        }
        .into())
    }

    pub(crate) fn completion(&self) -> Result<&completion::CompletionRef> {
        self.completion
            .get()
            .context("application completion is not installed")
    }
    pub(crate) fn prepare(&self) -> Result<RootPreparation> {
        self.prepare_kind(true)
    }
    /// Initial selection has an already durable root. Capture still verifies
    /// every planned record against the root begun by this actual preparation.
    /// Prospective snapshot publication continues through its separate path.
    pub(crate) fn prepare_initial(&self) -> Result<RootPreparation> {
        let (plan, points) = PreparedSelectionPlan::for_current_root(&self.stores)?;
        let mut preparation = None;
        with_incoming_points(points, |points| {
            preparation = Some(self.prepare_kind_planned(true, Some(&plan), points)?);
            Ok(())
        })?;
        preparation.context("initial source preparation absent")
    }
    pub(crate) fn publication_expectation<'call>(
        &'call self,
        position: &'call kasumi_raft::AppliedEntryContext,
        writes: &'call [kasumi_store::WriteOp],
        response: &kasumi_raft::AppliedResponse,
    ) -> Result<kasumi_raft::PublicationExpectation<'call>> {
        Ok(kasumi_raft::PublicationExpectation::for_entry(
            &self.stores,
            position,
            writes,
            response,
        )?)
    }
    pub(crate) fn publication_preparation(&self) -> PublicationPreparation<'_> {
        PublicationPreparation {
            roots: self,
            prepared: None,
            attempted: false,
            repeated: false,
        }
    }
    fn prepare_kind(&self, canonical: bool) -> Result<RootPreparation> {
        self.prepare_kind_planned(canonical, None, &mut None)
    }
    fn prepare_kind_planned(
        &self,
        canonical: bool,
        plan: Option<&PreparedSelectionPlan>,
        points: &mut Option<PreparedTenantPointWorkspace>,
    ) -> Result<RootPreparation> {
        let mut preparation = self.prepare_kind_unqueued(canonical, plan, points)?;
        if plan.is_some() {
            preparation.queue_planned_in_place()?;
        }
        Ok(preparation)
    }
    // The completion corridor stores this owner before queueing the actual
    // registered read. The registry already owns the Cell and proof workspace.
    fn prepare_kind_unqueued(
        &self,
        canonical: bool,
        plan: Option<&PreparedSelectionPlan>,
        points: &mut Option<PreparedTenantPointWorkspace>,
    ) -> Result<RootPreparation> {
        ensure!(
            plan.is_some() == points.is_some(),
            "prospective source lost its point backing"
        );
        if let Some(points) = points.as_ref() {
            points.require_stores(&self.stores)?;
        }
        if let Some(failure) = self.construction_failure.get() {
            return Err(SourceFailure {
                owner: failure.owner.clone(),
            }
            .into());
        }
        self.retry_retirements();
        ensure!(
            !self
                .gate
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .preparations_closed,
            "application source preparation sealed"
        );
        // No admission/provider callback while the source gate is locked.
        let mut cohort_loan = None;
        let (credit, workspace, cohort_points) = if let Some(cohort) = self.cohort.get() {
            ensure!(canonical, "protected cohort requires canonical selection");
            let plan = plan.context("protected cohort requires a producer plan")?;
            cohort.require_plan(plan)?;
            // The current ordinary control planner owns separate admitted
            // backing. Retire its actual completed loan before publication;
            // standing capture consumes only the cohort's real final-row buffer.
            // Until the wider planner borrows that buffer too, its admission is
            // an explicit prerequisite outside this cohort's acceptance claim.
            if let Some(planner) = points.take()
                && let Err(payload) = planner.retire()
            {
                cohort.seal();
                return Err(SourcePanic {
                    _payload: Mutex::new(payload),
                }
                .into());
            }
            let loan = cohort.prepare_loan()?;
            let credit = loan.credit().clone();
            let workspace = cohort.workspace(self, &credit);
            cohort_loan = Some(loan);
            (credit, Some(workspace), true)
        } else {
            let baseline = cell_bytes()?;
            let reservation = self.admission.reserve_application_source(baseline)?;
            let workspace = if canonical {
                let peak = match plan {
                    Some(plan) => plan.peak_bytes(),
                    None => {
                        // Unplanned snapshot capture retains its format ceiling.
                        let plaintext = kasumi_store::plaintext_get_workspace_bytes(
                            self.stores.application().tenant().len(),
                            "raft.snapshot".len(),
                            b"current".len(),
                            2 << 20,
                        )?
                        .max(kasumi_store::plaintext_get_workspace_bytes(
                            self.stores.custody().store().tenant().len(),
                            "raft.meta".len(),
                            b"snapshot_coverage".len(),
                            2 << 20,
                        )?);
                        plaintext
                            .checked_add(64 << 10)
                            .context("application decode floor overflow")?
                    }
                };
                Some(Workspace {
                    core: self.admission.memory().clone(),
                    baseline: 0,
                    planned_peak: plan.map(|_| peak),
                    funding: WorkspaceFunding::Ordinary(
                        self.admission.reserve_application_source(peak)?,
                    ),
                })
            } else {
                None
            };
            (SourceCredit::new(reservation), workspace, false)
        };
        let mut gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            !gate.preparations_closed,
            "application source preparation sealed"
        );
        let id = gate.next;
        gate.next = id
            .checked_add(1)
            .context("application source identifier exhausted")?;
        let cell = CellRef::new(
            Cell {
                id,
                roots: self.downgrade(),
                handles: AtomicUsize::new(0),
                state: Mutex::new(CellState {
                    preparing: true,
                    closing: false,
                    closed: false,
                    inflight: 0,
                    view: None,
                    protected_view: None,
                }),
                history_escape: Mutex::new(()),
                position: OnceLock::new(),
                _metadata_parent: OnceLock::new(),
                frozen: OnceLock::new(),
                failure: OnceLock::new(),
                point_failure: OnceLock::new(),
                close_failure: OnceLock::new(),
                alias_failure: OnceLock::new(),
                native_retained: AtomicBool::new(false),
                workspace: Mutex::new(workspace),
                _registry_reservation: self._reservation.clone(),
                _reservation: credit.clone(),
            },
            credit,
        );
        gate.cells.insert(id, cell.clone());
        drop(gate);
        Ok(RootPreparation {
            roots: self.clone(),
            cell,
            plan: plan.cloned(),
            points: cohort_loan
                .map(cohort::PendingCohortLoan::commit)
                .or_else(|| points.take()),
            queued: None,
            queued_source: None,
            cohort_points,
            settled: false,
        })
    }
}
impl SourceRoots {
    fn wake(&self) {
        let wake = self
            .gate
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .waiter
            .take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
    fn finish_retirement(&self, cell: &CellRef) {
        // The Store operation is read-only with respect to the original error
        // object, and can release its native facade without cleanup admission.
        let mut native_retained = cell.retains_native_failure();
        if native_retained {
            // At most two local shells own this reader (body and close). A
            // second fixed pass observes retirement after the second detaches;
            // it is not an unbounded wait on another owner's callbacks.
            native_retained = cell.retains_native_failure();
        }
        let close_has_exact_native_retirement = cell.close_has_exact_native_retirement();
        let closed = {
            let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
            if !native_retained
                && close_has_exact_native_retirement
                && !state.closing
                && state.view.is_none()
                && state.protected_view.is_none()
            {
                state.closed = true;
            }
            state.closed
        };
        cell.native_retained
            .store(native_retained, Ordering::Release);
        if closed && !native_retained {
            cell._reservation.prove_retirement();
            let (removed, empty) = {
                let mut gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
                let removed = gate.cells.remove(&cell.id);
                if CellWeak::ptr_eq(&gate.latest, &cell.downgrade()) {
                    gate.latest = CellWeak::new();
                }
                // Empty BTree root backing retires before the cell's node credit.
                let empty = gate
                    .cells
                    .is_empty()
                    .then(|| std::mem::take(&mut gate.cells));
                (removed, empty)
            };
            drop(empty);
            drop(removed);
        }
    }
    fn retire(&self, cell: &CellRef, forced: bool) {
        let close = {
            let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.preparing
                || state.closing
                || state.inflight != 0
                || (!forced && cell.handles.load(Ordering::Acquire) != 0)
            {
                return;
            }
            if state.closed
                || (cell.close_failure.get().is_some()
                    && state.view.is_none()
                    && state.protected_view.is_none())
            {
                None
            } else {
                state.closing = true;
                Some((state.view.take(), state.protected_view.take()))
            }
        };
        if let Some((view, protected)) = close {
            // No root/list/gate locks during native close or disposition work.
            let mut still_shared = None;
            let mut protected_shared = None;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if let Some(protected) = protected {
                    ensure!(view.is_none(), "application source has two native views");
                    return match protected.try_unwrap() {
                        Ok(view) => view.consume(kasumi_store::PreparedTenantSourceReadView::close),
                        Err(view) => {
                            protected_shared = Some(view);
                            Err(anyhow::anyhow!(
                                "application source has an uncounted protected alias"
                            ))
                        }
                    };
                }
                view.map(|view| match view.try_unwrap() {
                    Ok(view) => view.consume(TenantStorageReadView::close),
                    Err(view) => {
                        still_shared = Some(view);
                        Err(anyhow::anyhow!(
                            "application source has an uncounted view alias"
                        ))
                    }
                })
                .unwrap_or(Ok(()))
            }))
            .unwrap_or_else(|payload| {
                Err(SourcePanic {
                    _payload: Mutex::new(payload),
                }
                .into())
            });
            let failed = outcome.is_err();
            if let Err(error) = outcome {
                if still_shared.is_some() || protected_shared.is_some() {
                    // This retryable local alias refusal must not occupy the
                    // single consuming-close slot: a later actual close may
                    // fail with its own original native owner or panic.
                    cell.record_alias_failure(error);
                } else {
                    cell.record_failure(error, true);
                }
            }
            let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
            state.closing = false;
            state.closed = !failed;
            if let Some(view) = still_shared {
                state.view = Some(view);
            }
            if let Some(view) = protected_shared {
                state.protected_view = Some(view);
            }
        }
        self.finish_retirement(cell);
        self.wake();
    }
}
impl RootPreparation {
    fn retire_points(&mut self) {
        if self.cohort_points {
            return;
        }
        if let Some(points) = self.points.take()
            && let Err(payload) = points.retire()
        {
            // The actual destructor ran; never fabricate a refund or infer
            // clean retirement from catching it. Retain the original payload in
            // a distinct Cell slot and let strict disposition stay Retained.
            self.cell.record_point_failure(payload);
        }
    }
    fn queue_planned_in_place(&mut self) -> Result<()> {
        ensure!(
            self.plan.is_some()
                && self.points.is_some()
                && self.queued.is_none()
                && self.queued_source.is_none()
                && !self.settled,
            "prospective source queue is not pristine"
        );
        // The ordinary completion already owns self before this provider call.
        // Store retains its actual request on a failed pre-return acquisition.
        if let Some(cohort) = self.roots.cohort.get() {
            self.queued_source = Some(cohort.queue(&self.cell._reservation)?);
        } else {
            self.queued = Some(self.roots.stores.prepare_read_view()?);
        }
        Ok(())
    }
    pub(crate) fn capture(
        mut self,
        boundary: ApplicationBoundaryRef<'_>,
        frozen: bool,
    ) -> Result<SelectedApplication> {
        self.capture_in_place(boundary, frozen)
    }
    fn capture_in_place(
        &mut self,
        boundary: ApplicationBoundaryRef<'_>,
        frozen: bool,
    ) -> Result<SelectedApplication> {
        ensure!(!self.settled, "application source capture already settled");
        self.capture_position(boundary);
        self.finish_capture(frozen)
    }
    fn capture_position(&mut self, boundary: ApplicationBoundaryRef<'_>) {
        let mode = {
            let gate = self.roots.gate.lock().unwrap_or_else(|p| p.into_inner());
            if gate.serving {
                ApplicationSelectionMode::Serving
            } else {
                ApplicationSelectionMode::Reconstructing
            }
        };
        let acquired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            if let Some(queued) = self.queued_source.take() {
                let reader = queued.capture()?;
                let backing = self
                    .points
                    .take()
                    .context("protected source point backing absent")?;
                let (view, backing) = backing
                    .bind_source(&self.roots.stores, reader)?
                    .into_source();
                self.points = Some(backing);
                let view = ProtectedViewRef::new(view, self.cell._reservation.clone());
                self.cell
                    .state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .protected_view = Some(view.clone());
                let workspace = self
                    .cell
                    .workspace
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .take()
                    .expect("preclaimed source workspace");
                let mut loan =
                    view.point_reads(self.points.as_mut().expect("actual cohort backing"))?;
                let result = kasumi_raft::selected_application_at_source_loan(
                    &mut loan,
                    boundary,
                    mode,
                    &self.roots.limits,
                    workspace,
                    Some(self.plan.as_ref().expect("protected producer plan")),
                );
                match result {
                    Ok(position) => {
                        let _ = self.cell.position.set(position);
                    }
                    Err(error) => self.cell.record_failure(error.into(), false),
                }
                return Ok(());
            }
            let acquired = match self.queued.take() {
                Some(queued) => queued.begin(),
                None if self.plan.is_none() => self.roots.stores.read_view(),
                None => anyhow::bail!("prospective source lost its queued reader"),
            };
            match acquired {
                Ok(view) => {
                    let view = ViewRef::new(view, self.cell._reservation.clone());
                    self.cell
                        .state
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .view = Some(view.clone());
                    let workspace = self
                        .cell
                        .workspace
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .take()
                        .expect("preclaimed source workspace");
                    let result = match &self.plan {
                        Some(plan) => kasumi_raft::selected_application_at_prepared(
                            &view,
                            boundary,
                            mode,
                            &self.roots.limits,
                            workspace,
                            plan,
                            self.points.as_mut().expect("prepublished point backing"),
                        ),
                        None => kasumi_raft::selected_application_at(
                            &view,
                            boundary,
                            mode,
                            &self.roots.limits,
                            workspace,
                        ),
                    };
                    match result {
                        Ok(position) => {
                            let _ = self.cell.position.set(position);
                        }
                        Err(error) => self.cell.record_failure(error.into(), false),
                    }
                    drop(view);
                }
                Err(error) => {
                    self.cell.record_failure(error, false);
                }
            }
            Ok(())
        }));
        // Preserve the original operation before invoking another destructor.
        match acquired {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.cell.record_failure(error, false);
            }
            Err(payload) => {
                self.cell.record_failure(
                    SourcePanic {
                        _payload: Mutex::new(payload),
                    }
                    .into(),
                    false,
                );
            }
        }
        // Loans have ended even on panic. The Cell retains its exact registered
        // view while point backing retirement records its independent outcome.
        self.retire_points();
    }
    fn finish_capture(&mut self, frozen: bool) -> Result<SelectedApplication> {
        let _ = self.cell.frozen.set(frozen);
        // Declared before the gate so unwinding releases source locks before
        // the selected owner's retirement path reacquires those same locks.
        let selected;
        let mut gate = self.roots.gate.lock().unwrap_or_else(|p| p.into_inner());
        if gate.preparations_closed && !self.cell.capture_failed() {
            self.cell.record_failure(
                anyhow::anyhow!("application source sealed during capture"),
                false,
            );
        }
        // Capture may have sampled Reconstructing before the startup handoff.
        // Settle against the same gate as that handoff; only an actually frozen
        // Generation may retain covered custody after serving starts.
        if gate.serving
            && !frozen
            && !self.cell.capture_failed()
            && self
                .cell
                .position
                .get()
                .is_some_and(Position::is_covered_reconstruction)
        {
            self.cell.record_failure(
                anyhow::anyhow!("covered application reconstruction settled after serving"),
                false,
            );
        }
        // A retirement worker may already own this Cell Arc. Set the initial
        // selected count and end preparation in the same state transition;
        // there is never a prepared=false, handles=0 success window.
        let failed = self.cell.capture_failed();
        {
            let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
            if !failed {
                self.cell.handles.store(1, Ordering::Release);
                selected = Some(SelectedApplication {
                    cell: self.cell.clone(),
                });
            } else {
                selected = None;
            }
            state.preparing = false;
            self.settled = true;
        }
        if failed {
            drop(gate);
            self.roots.retire(&self.cell, true);
            return Err(self.cell.error());
        }
        // Own the counted handle before replacing an old weak-credit alias or
        // invoking a registered wake callback. Unwind must discharge a real
        // selected owner, never leave only a numeric handle count behind.
        gate.latest = self.cell.downgrade();
        drop(gate);
        self.roots.wake();
        Ok(selected.expect("successful counted selection"))
    }
}
impl Drop for RootPreparation {
    fn drop(&mut self) {
        // Retire point buffers before cancelling/closing their actual reader.
        self.retire_points();
        if !self.settled {
            if let Some(queued) = self.queued_source.take() {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    queued.cancel_settled()
                })) {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => self.cell.record_failure(error, true),
                    Err(payload) => self.cell.record_failure(
                        SourcePanic {
                            _payload: Mutex::new(payload),
                        }
                        .into(),
                        true,
                    ),
                }
            }
            if let Some(queued) = self.queued.take() {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| queued.cancel())) {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => self.cell.record_failure(error, true),
                    Err(payload) => self.cell.record_failure(
                        SourcePanic {
                            _payload: Mutex::new(payload),
                        }
                        .into(),
                        true,
                    ),
                }
            }
            // Unused preparation owns no selected view. Every native capture
            // and fork callback is caught above with its original panic payload;
            // unrelated producer unwind remains owned by the enclosing caller.
            self.cell
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .preparing = false;
            self.roots.retire(&self.cell, true);
        }
        if self.cohort_points {
            let cohort = self.roots.cohort.get().expect("owning source cohort");
            match self.points.take() {
                Some(points) => cohort.return_points(points),
                None => cohort.consumed_points(),
            }
        }
        self.roots.wake();
    }
}
impl kasumi_raft::ApplicationSourceCustody for SourceRoots {
    fn seal_consumers(&self) {
        self.gate
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .consumers_closed = true;
        self.wake();
    }
    fn finish_reconstruction(&self) -> Result<()> {
        let mut gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            !gate.preparations_closed && !gate.consumers_closed,
            "application source closed before serving"
        );
        let latest = gate
            .latest
            .upgrade()
            .context("application selected position absent after replay")?;
        let position = latest
            .position
            .get()
            .context("application selected position failed after replay")?;
        ensure!(
            !position.is_covered_reconstruction() || latest.frozen.get() == Some(&true),
            "application replay did not reach current durable coverage"
        );
        gate.serving = true;
        Ok(())
    }
    fn poll_drain(&self, cx: &mut Context<'_>) -> Poll<DrainResult> {
        let waiter = cx.waker().clone();
        let previous = {
            let mut gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
            gate.consumers_closed = true;
            gate.preparations_closed = true;
            gate.waiter.replace(waiter)
        };
        drop(previous);
        let mut cursor = None;
        let mut pending = false;
        let mut report = DrainReport::default();
        let mut retained = None;
        if let Some(cohort) = self.cohort.get() {
            cohort.seal();
        }
        for failure in [
            self.construction_failure.get(),
            self.capacity_cleanup_failure.get(),
        ]
        .into_iter()
        .flatten()
        {
            let issue = DrainFailure::retained(failure.issue.clone());
            report.merge(&issue);
            if self.capacity_failure_retained() {
                retained = Some(issue);
            }
        }
        let mut cell_retained = false;
        loop {
            let cell = {
                let gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
                match cursor {
                    None => gate.cells.first_key_value(),
                    Some(id) => gate
                        .cells
                        .range((std::ops::Bound::Excluded(id), std::ops::Bound::Unbounded))
                        .next(),
                }
                .map(|(_, cell)| cell.clone())
            };
            let Some(cell) = cell else { break };
            cursor = Some(cell.id);
            self.retire(&cell, true);
            let state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
            pending |= state.preparing || state.inflight != 0 || state.closing;
            drop(state);
            let native_retained = cell.native_retained.load(Ordering::Acquire);
            for failure in [
                cell.failure.get(),
                cell.point_failure.get(),
                cell.alias_failure.get(),
                cell.close_failure.get(),
            ]
            .into_iter()
            .flatten()
            {
                let issue = DrainFailure::retained(failure.issue.clone());
                report.merge(&issue);
                if !cell.state.lock().unwrap_or_else(|p| p.into_inner()).closed || native_retained {
                    retained = Some(issue);
                    cell_retained = true;
                }
            }
        }
        if !pending
            && !cell_retained
            && self.capacity_cleanup_failure.get().is_none()
            && !self.cohort.get().is_some_and(SourceCohort::close_failed)
            && let Some(cohort) = self.cohort.get()
        {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cohort.poll_close())) {
                Ok(Some(Ok(()))) => {}
                Ok(None) => pending = true,
                Ok(Some(Err(error))) => self.record_capacity_failure(error),
                Err(payload) => {
                    cohort.mark_close_failed();
                    self.record_capacity_failure(
                        SourcePanic {
                            _payload: Mutex::new(payload),
                        }
                        .into(),
                    );
                }
            }
            if !cell_retained && !self.capacity_failure_retained() {
                retained = None;
            }
            for failure in [
                self.construction_failure.get(),
                self.capacity_cleanup_failure.get(),
            ]
            .into_iter()
            .flatten()
            {
                let issue = DrainFailure::retained(failure.issue.clone());
                report.merge(&issue);
                if self.capacity_failure_retained() {
                    retained = Some(issue);
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(report.outcome(retained))
        }
    }
    fn is_drained(&self) -> bool {
        let gate = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        gate.preparations_closed
            && !self.capacity_failure_retained()
            && self.cohort.get().is_none_or(SourceCohort::is_closed)
            && gate.cells.values().all(|cell| {
                let state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
                state.closed
                    && !state.preparing
                    && !state.closing
                    && state.inflight == 0
                    && !cell.native_retained.load(Ordering::Acquire)
            })
    }
}

impl kasumi_raft::ApplicationSourceCustody for SourceRootsRef {
    fn seal_consumers(&self) {
        kasumi_raft::ApplicationSourceCustody::seal_consumers(self.as_ref());
    }
    fn finish_reconstruction(&self) -> Result<()> {
        kasumi_raft::ApplicationSourceCustody::finish_reconstruction(self.as_ref())
    }
    fn poll_drain(&self, cx: &mut Context<'_>) -> Poll<DrainResult> {
        kasumi_raft::ApplicationSourceCustody::poll_drain(self.as_ref(), cx)
    }
    fn is_drained(&self) -> bool {
        kasumi_raft::ApplicationSourceCustody::is_drained(self.as_ref())
    }
}

/// Restore outlives the borrowed adapter context. Charge the concrete clone
/// before copying its membership containers and strings; drop it before grant.
pub(crate) struct RestoreSelection {
    context: kasumi_raft::SnapshotRestoreContext,
    preparation: RootPreparation,
    _reservation: Reservation,
}
impl SourceRootsRef {
    pub(crate) fn prepare_restore(
        &self,
        context: &kasumi_raft::SnapshotRestoreContext,
        prepared_owner_bytes: usize,
    ) -> Result<RestoreSelection> {
        fn add(total: &mut u64, extra: u64) -> Result<()> {
            *total = total
                .checked_add(extra)
                .context("restore selection quote overflow")?;
            Ok(())
        }
        let mut bytes = allocated(prepared_owner_bytes)?;
        add(&mut bytes, allocated(context.backend_sha256.len())?)?;
        add(&mut bytes, allocated(context.meta.snapshot_id.len())?)?;
        let membership = context.meta.last_membership.membership();
        let configs = membership.get_joint_config();
        add(
            &mut bytes,
            allocated(
                configs
                    .len()
                    .checked_mul(std::mem::size_of::<std::collections::BTreeSet<u64>>())
                    .context("restore membership vector overflow")?,
            )?,
        )?;
        let set_node =
            allocated(11 * std::mem::size_of::<u64>() + 16 * std::mem::size_of::<usize>())?;
        for config in configs {
            // One full internal node per element also bounds clone's partially
            // occupied leaf/root nodes; Vec clone requests exactly its length.
            add(
                &mut bytes,
                set_node
                    .checked_mul(config.len() as u64)
                    .context("restore voter quote overflow")?,
            )?;
        }
        let map_node = allocated(
            11 * (std::mem::size_of::<u64>() + std::mem::size_of::<kasumi_raft::BasicNode>())
                + 16 * std::mem::size_of::<usize>(),
        )?;
        for (_, node) in membership.nodes() {
            add(&mut bytes, map_node)?;
            add(&mut bytes, allocated(node.addr.len())?)?;
        }
        let reservation = self.admission.reserve_application_source(bytes)?;
        let preparation = self.prepare()?;
        let context = kasumi_raft::SnapshotRestoreContext {
            mode: context.mode,
            backend_sha256: context.backend_sha256.clone(),
            meta: context.meta.clone(),
        };
        Ok(RestoreSelection {
            context,
            preparation,
            _reservation: reservation,
        })
    }
}
impl RestoreSelection {
    pub(crate) fn capture(self, frozen: bool) -> Result<SelectedApplication> {
        self.preparation
            .capture(ApplicationBoundaryRef::Snapshot(&self.context), frozen)
    }
}

// This exact-fork capability is the private boundary for the pending disk
// DocumentSource cutover. No runtime document reads use it in this stage.
#[cfg(test)]
struct ForkPermit {
    roots: SourceRootsRef,
    parent: CellRef,
    view: Option<ViewRef>,
}
#[cfg(test)]
impl Drop for ForkPermit {
    fn drop(&mut self) {
        drop(self.view.take());
        {
            let mut state = self.parent.state.lock().unwrap_or_else(|p| p.into_inner());
            state.inflight -= 1;
        }
        let force = self
            .roots
            .gate
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .preparations_closed;
        self.roots.retire(&self.parent, force);
        self.roots.wake();
    }
}
#[cfg(test)]
impl SelectedApplication {
    fn begin_fork(&self) -> Result<(RootPreparation, ForkPermit)> {
        let roots = self
            .cell
            .roots
            .upgrade()
            .context("selected application registry absent")?;
        {
            let gate = roots.gate.lock().unwrap_or_else(|p| p.into_inner());
            ensure!(
                !gate.consumers_closed && !gate.preparations_closed,
                "application source consumers sealed"
            );
        }
        // Both child registry slot and its owner are funded before gate entry.
        // The second check below settles a concurrent consumer seal.
        let child = roots.prepare()?;
        let gate = roots.gate.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            !gate.consumers_closed && !gate.preparations_closed,
            "application source consumers sealed"
        );
        let mut parent = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            !parent.preparing && !parent.closing && !parent.closed,
            "selected application parent closed"
        );
        let view = parent
            .view
            .as_ref()
            .context("selected application parent absent")?
            .clone();
        parent.inflight = parent
            .inflight
            .checked_add(1)
            .context("application source fork count overflow")?;
        drop(parent);
        drop(gate);
        Ok((
            child,
            ForkPermit {
                roots,
                parent: self.cell.clone(),
                view: Some(view),
            },
        ))
    }
    fn settle_fork(child: RootPreparation, permit: ForkPermit) -> Result<SelectedApplication> {
        let mut child = child;
        let forked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            permit.view.as_ref().expect("inflight parent").fork()
        }))
        .unwrap_or_else(|payload| {
            Err(SourcePanic {
                _payload: Mutex::new(payload),
            }
            .into())
        });
        match forked {
            Ok(view) => {
                child
                    .cell
                    .state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .view = Some(ViewRef::new(view, child.cell._reservation.clone()));
                let _ = child.cell._metadata_parent.set(permit.parent.clone());
            }
            Err(error) => {
                child.cell.record_failure(error, false);
            }
        }
        // Seal is settled against the same gate after physical fork. An
        // accepted child is registered already; a rejected child is closed here.
        let gate = child.roots.gate.lock().unwrap_or_else(|p| p.into_inner());
        if gate.consumers_closed || gate.preparations_closed {
            child.cell.record_failure(
                anyhow::anyhow!("application source sealed during fork"),
                false,
            );
        }
        let failed = child.cell.failure.get().is_some();
        {
            let mut state = child.cell.state.lock().unwrap_or_else(|p| p.into_inner());
            if !failed {
                child.cell.handles.store(1, Ordering::Release);
            }
            state.preparing = false;
            child.settled = true;
        }
        if failed {
            drop(gate);
            child.roots.retire(&child.cell, true);
            return Err(child.cell.error());
        }
        // Forks keep only their concrete owner floor, never a decode maximum.
        let workspace = child
            .cell
            .workspace
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        drop(gate);
        drop(workspace);
        drop(permit);
        Ok(SelectedApplication {
            cell: child.cell.clone(),
        })
    }
}

#[cfg(test)]
#[path = "application_sources_tests.rs"]
pub(crate) mod tests;

// Used by the real encrypted staging candidate; activation is not wired yet.
#[cfg(test)]
#[path = "application_source_reader.rs"]
mod primary_reader;
#[cfg(test)]
pub(crate) use primary_reader::SourceReader;

// This permit keeps native close out of the short history exchange. It borrows
// no apply mutex and drops its exact view alias before retirement is retried.
struct HistoryPermit {
    roots: SourceRootsRef,
    cell: CellRef,
    view: Option<ProtectedViewRef>,
}
impl Drop for HistoryPermit {
    fn drop(&mut self) {
        drop(self.view.take());
        self.cell
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .inflight -= 1;
        let force = self
            .roots
            .gate
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .preparations_closed;
        self.roots.retire(&self.cell, force);
        self.roots.wake();
    }
}
impl SelectedApplication {
    /// Before the first externally returned Generation, acquire a real ordinary
    /// Engine lane replacement and then complete the same native/report/census
    /// history transition. A refused precommit exchange preserves current.
    pub(crate) fn retain_public_history(&self) -> Result<()> {
        if self.cell._reservation.publication_lane().is_none() {
            return Ok(());
        }
        let _exchange = self
            .cell
            .history_escape
            .lock()
            .map_err(|_| anyhow::anyhow!("source history exchange previously unwound"))?;
        let roots = self
            .cell
            .roots
            .upgrade()
            .context("source registry retired")?;
        let permit = {
            let gate = roots.gate.lock().unwrap_or_else(|p| p.into_inner());
            ensure!(
                !gate.consumers_closed && !gate.preparations_closed,
                "source consumers sealed"
            );
            let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
            ensure!(
                !state.preparing && !state.closing && !state.closed,
                "source parent closed"
            );
            let view = state
                .protected_view
                .as_ref()
                .context("protected source absent")?
                .clone();
            state.inflight = state
                .inflight
                .checked_add(1)
                .context("source history permit overflow")?;
            drop(state);
            drop(gate);
            HistoryPermit {
                roots,
                cell: self.cell.clone(),
                view: Some(view),
            }
        };
        let credit = &self.cell._reservation;
        // Pure provider refusal occurs before touching the captured native root.
        let prepared = credit.prepare_history()?;
        let view = permit.view.as_ref().expect("actual history parent");
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| view.retain_history()));
        let disposition = view.history_disposition();
        match disposition {
            kasumi_store::SourceHistoryDisposition::History => {
                if prepared {
                    credit.commit_history();
                }
            }
            kasumi_store::SourceHistoryDisposition::Current => {
                if prepared && let Err(payload) = credit.abort_history() {
                    // Preserve both independent observations before publishing a
                    // redacted failure; never refund/reuse after unknown Drop.
                    match outcome {
                        Ok(Err(original)) => self.cell.record_failure(original, false),
                        Err(original) => self.cell.record_failure(
                            SourcePanic {
                                _payload: Mutex::new(original),
                            }
                            .into(),
                            false,
                        ),
                        Ok(Ok(_)) => self.cell.record_failure(
                            anyhow::anyhow!("source history funding retirement failed"),
                            false,
                        ),
                    }
                    self.cell.record_point_failure(payload);
                    return Err(self.cell.error());
                }
            }
            kasumi_store::SourceHistoryDisposition::Transition => {}
            kasumi_store::SourceHistoryDisposition::Retained => credit.seal_publication(),
        }
        match outcome {
            Ok(Ok(true)) if disposition == kasumi_store::SourceHistoryDisposition::History => {
                Ok(())
            }
            Ok(Ok(_)) => anyhow::bail!("source history transition is still pending"),
            Ok(Err(error))
                if disposition == kasumi_store::SourceHistoryDisposition::Current
                    || disposition == kasumi_store::SourceHistoryDisposition::History =>
            {
                Err(error)
            }
            Ok(Err(error)) => {
                self.cell.record_failure(error, false);
                Err(self.cell.error())
            }
            Err(payload) => {
                self.cell.record_failure(
                    SourcePanic {
                        _payload: Mutex::new(payload),
                    }
                    .into(),
                    false,
                );
                Err(self.cell.error())
            }
        }
    }
}
