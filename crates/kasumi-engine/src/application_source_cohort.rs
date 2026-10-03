//! One real current/next source cohort. The install caller must first close
//! accepted replay and ingress coverage; this type is not that authority.
use super::*;
use ownership::{LaneFunding, LaneFundingRef};

pub(super) struct SourceCohort {
    capacity: Mutex<CapacityState>,
    envelope: kasumi_raft::PreparedOrdinarySourceEnvelope,
    funding: Mutex<Option<LaneFundingRef>>,
    // Exactly one actual decrypt/directory backing is lent to the serialized
    // planner/capture operation and returned only by its outer preparation.
    points: Mutex<PointState>,
    // Above each lane's retained DTO bytes, one operation owns transient decode
    // overlap. This is spent by Workspace::Publication; it is never a refill.
    transient: Mutex<Option<Reservation>>,
}
impl SourceCohort {
    pub(super) fn empty(envelope: kasumi_raft::PreparedOrdinarySourceEnvelope) -> Self {
        Self {
            capacity: Mutex::new(CapacityState::Empty),
            envelope,
            funding: Mutex::new(None),
            points: Mutex::new(PointState {
                backing: None,
                loaned: false,
            }),
            transient: Mutex::new(None),
        }
    }
    /// The enclosing SourceRoots already owns this inline object before any
    /// provider callback. Every successful partial construction is installed in
    /// its real field before the next callback can fail or unwind.
    pub(super) fn install(&self, roots: &SourceRootsRef) -> Result<()> {
        self.envelope.require_stores(&roots.stores)?;
        ensure!(
            self.funding
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_none(),
            "source cohort installation already entered"
        );
        let lane_bytes = cell_bytes()?
            .checked_add(self.envelope.retained_bytes())
            .context("source cohort lane quote overflow")?;
        let funding = LaneFunding::new(roots.admission.clone(), lane_bytes)
            .map_err(CohortAdmissionRefusal::new)?;
        *self.funding.lock().unwrap_or_else(|p| p.into_inner()) = Some(funding);
        let transient = self
            .envelope
            .peak_bytes()
            .checked_sub(self.envelope.retained_bytes())
            .context("source cohort transient quote underflow")?;
        *self.transient.lock().unwrap_or_else(|p| p.into_inner()) = Some(
            roots
                .admission
                .reserve_document_source(transient)
                .map_err(CohortAdmissionRefusal::new)?,
        );
        let (namespace, key, value) = self.envelope.point_bounds();
        let (_, points) = roots
            .stores
            .read_view()?
            .prepare_point_reads(namespace, key, value)?
            .finish_with_workspace(Ok(()))?;
        self.points
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .backing = Some(points);
        let capacity = roots.stores.queue_source_capacity()?.install()?;
        *self.capacity.lock().unwrap_or_else(|p| p.into_inner()) =
            CapacityState::Installed(capacity);
        Ok(())
    }
    fn funding(&self) -> Result<LaneFundingRef> {
        self.funding
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .context("source funding is not installed or has retired")
    }
    pub(super) fn require_plan(&self, plan: &PreparedSelectionPlan) -> Result<()> {
        self.envelope.require_plan(plan)
    }
    pub(super) fn prepare_credit(&self) -> Result<SourceCredit> {
        SourceCredit::publication_available(&self.funding()?)
    }
    pub(super) fn workspace(&self, roots: &SourceRootsRef, credit: &SourceCredit) -> Workspace {
        Workspace {
            core: roots.admission.memory().clone(),
            baseline: 0,
            planned_peak: Some(self.envelope.peak_bytes()),
            funding: WorkspaceFunding::Publication {
                credit: credit.clone(),
                retained: self.envelope.retained_bytes(),
            },
        }
    }
    pub(super) fn take_points(&self) -> Result<PreparedTenantPointWorkspace> {
        let mut state = self.points.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(!state.loaned, "source cohort operation is still active");
        let points = state
            .backing
            .take()
            .context("source cohort backing absent or retired")?;
        state.loaned = true;
        Ok(points)
    }
    pub(super) fn return_points(&self, points: PreparedTenantPointWorkspace) {
        let mut slot = self.points.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            slot.loaned && slot.backing.is_none(),
            "source cohort point backing returned twice"
        );
        slot.backing = Some(points);
        slot.loaned = false;
    }
    /// The consuming Store binder may settle and destroy backing on error.
    /// Its actual original/retirement evidence is retained by the Cell. End
    /// only this outstanding-loan marker and seal; never synthesize a refill.
    pub(super) fn consumed_points(&self) {
        let mut state = self.points.lock().unwrap_or_else(|p| p.into_inner());
        assert!(
            state.loaned && state.backing.is_none(),
            "source backing was not loaned"
        );
        state.loaned = false;
        drop(state);
        self.seal();
    }
    pub(super) fn queue(
        &self,
        credit: &SourceCredit,
    ) -> Result<kasumi_store::PreparedRegisteredSource> {
        let capacity = self.capacity.lock().unwrap_or_else(|p| p.into_inner());
        let CapacityState::Installed(capacity) = &*capacity else {
            anyhow::bail!("source capacity not installed or sealed");
        };
        capacity.prepare(
            credit
                .publication_lane()
                .context("source lane credit absent")?,
        )
    }
    pub(super) fn seal(&self) {
        if let Some(funding) = self
            .funding
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            funding.seal();
        }
        // No root/cell gate is held. A queue already entering this exact pool
        // completes before its admission facade is closed.
        let capacity = self.capacity.lock().unwrap_or_else(|p| p.into_inner());
        if let CapacityState::Installed(capacity) = &*capacity {
            capacity.seal();
        }
    }
    /// None is actual pending observation, never a native-finished substitute
    /// for complete census retirement. The root stores any returned original.
    pub(super) fn poll_close(&self) -> Option<Result<()>> {
        let current = {
            let mut state = self.capacity.try_lock().ok()?;
            match &*state {
                CapacityState::Closed => return Some(Ok(())),
                CapacityState::Running | CapacityState::Failed => return None,
                CapacityState::Empty | CapacityState::NativeClosed => {
                    let points = self.points.try_lock().ok()?;
                    if points.loaned {
                        return None;
                    }
                    drop(points);
                }
                _ => {}
            }
            std::mem::replace(&mut *state, CapacityState::Running)
        };
        let outcome = match current {
            CapacityState::Installed(capacity) => match capacity.close() {
                kasumi_store::SourceCapacityClose::Pending(capacity) => {
                    (CapacityState::Installed(capacity), None)
                }
                kasumi_store::SourceCapacityClose::Retained(error) => {
                    self.mark_close_failed();
                    return Some(Err(error.into()));
                }
                kasumi_store::SourceCapacityClose::Retiring(token) => settle_capacity(token),
            },
            CapacityState::Retiring(token) => settle_capacity(token),
            CapacityState::Empty | CapacityState::NativeClosed => {
                return self.retire_backing();
            }
            _ => unreachable!("checked source capacity close state"),
        };
        let native_closed = matches!(outcome.0, CapacityState::NativeClosed);
        *self.capacity.lock().unwrap_or_else(|p| p.into_inner()) = outcome.0;
        if native_closed {
            self.poll_close()
        } else {
            outcome.1
        }
    }
    // Native closure is already positive, and Running is installed before any
    // consuming callback. Each real owner leaves its field once. An unknown
    // destructor is recorded by SourceRoots, never retried or called drained.
    fn retire_backing(&self) -> Option<Result<()>> {
        let points = self
            .points
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .backing
            .take();
        if let Some(points) = points
            && let Err(payload) = points.retire()
        {
            self.mark_close_failed();
            return Some(Err(SourcePanic {
                _payload: Mutex::new(payload),
            }
            .into()));
        }
        let transient = self
            .transient
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        drop(transient);
        let funding = self
            .funding
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        // A selected metadata/diagnostic alias may still own its actual credit;
        // then this only releases the cohort's reference, and that tail remains
        // fully charged until its own final allocation retirement.
        drop(funding);
        *self.capacity.lock().unwrap_or_else(|p| p.into_inner()) = CapacityState::Closed;
        Some(Ok(()))
    }
    pub(super) fn mark_close_failed(&self) {
        *self.capacity.lock().unwrap_or_else(|p| p.into_inner()) = CapacityState::Failed;
    }
    pub(super) fn close_failed(&self) -> bool {
        matches!(
            *self.capacity.lock().unwrap_or_else(|p| p.into_inner()),
            CapacityState::Failed
        )
    }
    pub(super) fn is_closed(&self) -> bool {
        matches!(
            *self.capacity.lock().unwrap_or_else(|p| p.into_inner()),
            CapacityState::Closed
        )
    }
}
impl Drop for SourceCohort {
    fn drop(&mut self) {
        self.seal();
    }
}

struct PointState {
    backing: Option<PreparedTenantPointWorkspace>,
    loaned: bool,
}
enum CapacityState {
    Empty,
    Installed(kasumi_store::RegisteredSourceCapacity),
    Running,
    Retiring(kasumi_store::SourceCapacityRetirement),
    NativeClosed,
    Failed,
    Closed,
}
fn settle_capacity(
    token: kasumi_store::SourceCapacityRetirement,
) -> (CapacityState, Option<Result<()>>) {
    match token.retry() {
        kasumi_store::StorageCensusDisposition::Retired => (CapacityState::NativeClosed, None),
        _ if token.has_terminal_failure() => (CapacityState::Failed, Some(Err(token.into()))),
        _ => (CapacityState::Retiring(token), None),
    }
}

/// A pre-Cell assignment cannot escape through the ordinary incoming-buffer
/// error path. Until it is committed into RootPreparation there is no native
/// request, so cancellation returns the exact backing and proves this unused
/// ticket; actual credit aliases still keep its bytes until their final drop.
pub(super) struct PendingCohortLoan<'a> {
    cohort: &'a SourceCohort,
    points: Option<PreparedTenantPointWorkspace>,
    credit: SourceCredit,
}
impl SourceCohort {
    pub(super) fn prepare_loan(&self) -> Result<PendingCohortLoan<'_>> {
        let points = self.take_points()?;
        let credit = match self.prepare_credit() {
            Ok(credit) => credit,
            Err(error) => {
                self.return_points(points);
                return Err(error);
            }
        };
        Ok(PendingCohortLoan {
            cohort: self,
            points: Some(points),
            credit,
        })
    }
}
impl PendingCohortLoan<'_> {
    pub(super) fn credit(&self) -> &SourceCredit {
        &self.credit
    }
    pub(super) fn commit(mut self) -> PreparedTenantPointWorkspace {
        self.points.take().expect("actual pending cohort backing")
    }
}
impl Drop for PendingCohortLoan<'_> {
    fn drop(&mut self) {
        if let Some(points) = self.points.take() {
            self.credit.prove_retirement();
            self.cohort.return_points(points);
        }
    }
}

/// Only the actual Engine constructors above mint this wrapper, before any
/// source request can be queued. It preserves the original refusal; a later
/// positive retirement of every partial field can report drained-but-failed.
/// Generic io/error kinds and provider panics never mint this authority.
#[derive(Debug)]
pub(super) struct CohortAdmissionRefusal {
    original: anyhow::Error,
}
impl CohortAdmissionRefusal {
    fn new(error: impl Into<anyhow::Error>) -> Self {
        Self {
            original: error.into(),
        }
    }
}
impl std::fmt::Display for CohortAdmissionRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("source cohort construction admission refused")
    }
}
impl std::error::Error for CohortAdmissionRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}
