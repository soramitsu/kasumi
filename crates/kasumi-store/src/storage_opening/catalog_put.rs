//! One registered catalog transaction with admitted input and exact terminal custody.
use super::write_plan::{AdmittedCatalogPairPut, AdmittedCatalogPut};
use super::*;

#[derive(Debug)]
pub enum NodeCatalogPutBodyError {
    Table(kasumi_kv::TableError),
    ApplicationAccess(anyhow::Error),
    CustodyAccess(anyhow::Error),
    AlreadyInstalled,
    OrphanRecords,
}
impl std::fmt::Display for NodeCatalogPutBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Table(error) => error.fmt(f),
            Self::ApplicationAccess(error) => write!(f, "application catalog access: {error}"),
            Self::CustodyAccess(error) => write!(f, "custody catalog access: {error}"),
            Self::AlreadyInstalled => f.write_str("catalog already initialized"),
            Self::OrphanRecords => f.write_str("new catalog has orphan physical rows"),
        }
    }
}
impl std::error::Error for NodeCatalogPutBodyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Table(error) => Some(error),
            Self::ApplicationAccess(error) | Self::CustodyAccess(error) => Some(error.as_ref()),
            Self::AlreadyInstalled | Self::OrphanRecords => None,
        }
    }
}
impl From<kasumi_kv::TableError> for NodeCatalogPutBodyError {
    fn from(error: kasumi_kv::TableError) -> Self {
        Self::Table(error)
    }
}

enum CatalogPutInput {
    Single(AdmittedCatalogPut),
    Pair {
        plan: AdmittedCatalogPairPut,
        stores: [Arc<crate::TenantStore>; 2],
    },
}
impl CatalogPutInput {
    fn entries(&self) -> &[AdmittedCatalogPut] {
        match self {
            Self::Single(plan) => std::slice::from_ref(plan),
            Self::Pair { plan, .. } => plan.entries(),
        }
    }
    fn is_pair(&self) -> bool {
        matches!(self, Self::Pair { .. })
    }
    fn check_access(&self) -> Result<(), NodeCatalogPutBodyError> {
        if let Self::Pair { stores, .. } = self {
            stores[0]
                .access
                .check()
                .map_err(NodeCatalogPutBodyError::ApplicationAccess)?;
            stores[1]
                .access
                .check()
                .map_err(NodeCatalogPutBodyError::CustodyAccess)?;
        }
        Ok(())
    }
}

struct CatalogWriterState {
    phase: NodeWriterPhase,
    plan: CatalogPutInput,
    transaction: Option<RetainedWriteTransaction>,
    begin: Observation<kasumi_kv::TransactionError>,
    body: Observation<NodeCatalogPutBodyError>,
    post_commit: Observation<NodeCatalogPutBodyError>,
    outer: Observation<std::convert::Infallible>,
    outcomes_released: bool,
    #[cfg(test)]
    fail_owner_before_terminal: bool,
}
impl CatalogWriterState {
    fn has_failures(&self) -> bool {
        observed_failure(self.begin.borrow())
            || observed_failure(self.body.borrow())
            || observed_failure(self.post_commit.borrow())
            || observed_failure(self.outer.borrow())
            || self
                .transaction
                .as_ref()
                .is_some_and(|transaction| transaction_failure(&transaction.report()))
    }
}

struct CatalogPutRequest {
    database: StorageRegistration<DatabaseOwner>,
    state: Mutex<CatalogWriterState>,
}
impl CatalogPutRequest {
    fn dispose(&self, state: &mut CatalogWriterState, wait_for_settled: bool) -> bool {
        let Some(transaction) = state.transaction.as_mut() else {
            return !matches!(state.outer, Observation::Panicked(_))
                && !matches!(state.begin, Observation::Entered);
        };
        if transaction.report().disposal_complete() {
            return true;
        }
        state.outcomes_released = false;
        self.database
            .owner()
            .dispose_write(transaction, wait_for_settled)
    }

    fn execute(&self, state: &mut CatalogWriterState) {
        let owner = self.database.owner();
        let _serial = owner.serial.lock();
        if owner.stopped.load(Ordering::Acquire) {
            state.phase = NodeWriterPhase::Cancelled;
            return;
        }
        state.phase = NodeWriterPhase::Begin;
        state.begin = Observation::Entered;
        let database = owner.state.lock();
        let Some(db) = database.engine.database() else {
            state.begin =
                Observation::Returned(Err(kasumi_kv::StorageError::DatabaseClosed.into()));
            return;
        };
        let admission = db.transaction_admission();
        drop(database);
        match admission.begin_write() {
            Ok(transaction) => {
                state.transaction = Some(transaction.retain());
                state.begin = Observation::Returned(Ok(()));
            }
            Err(error) => {
                state.begin = Observation::Returned(Err(error));
                return;
            }
        }
        state.phase = NodeWriterPhase::Body;
        state.body = Observation::Entered;
        let body = catch_unwind(AssertUnwindSafe(
            || -> Result<(), NodeCatalogPutBodyError> {
                state.plan.check_access()?;
                let transaction = state.transaction.as_ref().unwrap().transaction().unwrap();
                let mut catalogs = transaction.open_table(crate::CATALOG)?;
                let records = state
                    .plan
                    .entries()
                    .iter()
                    .any(AdmittedCatalogPut::fresh_only)
                    .then(|| transaction.open_table(crate::RECORDS))
                    .transpose()?;
                for plan in state.plan.entries() {
                    if plan.fresh_only() {
                        if catalogs.get(plan.hash().as_slice())?.is_some() {
                            return Err(NodeCatalogPutBodyError::AlreadyInstalled);
                        }
                        let records = records.as_ref().expect("fresh writer opened records");
                        if let Some(row) = records.range(plan.hash().as_slice()..)?.next()
                            && row?.0.value().starts_with(plan.hash())
                        {
                            return Err(NodeCatalogPutBodyError::OrphanRecords);
                        }
                    }
                }
                for plan in state.plan.entries() {
                    catalogs.insert(plan.hash().as_slice(), plan.bytes())?;
                }
                state.plan.check_access()?;
                Ok(())
            },
        ));
        state.body = match body {
            Ok(result) => Observation::Returned(result),
            Err(payload) => Observation::Panicked(payload),
        };
        state.phase = NodeWriterPhase::Terminal;
        #[cfg(test)]
        if state.fail_owner_before_terminal {
            owner.state.lock().file.disk().fail();
        }
        let transaction = state.transaction.as_mut().unwrap();
        if state.body.success() {
            let _ = transaction.commit();
        } else {
            let _ = transaction.abort();
        }
        state.phase = NodeWriterPhase::Disposal;
        if self.dispose(state, true) {
            state.phase = NodeWriterPhase::Finished;
        }
        let committed = state.body.success()
            && state.transaction.as_ref().is_some_and(|transaction| {
                let report = transaction.report();
                report.operation() == Some(WriteTerminalOperation::Commit)
                    && matches!(report.terminal(), TerminalObservation::Returned(Ok(())))
            });
        if state.plan.is_pair() && committed {
            state.post_commit = Observation::Entered;
            let post_commit = catch_unwind(AssertUnwindSafe(|| state.plan.check_access()));
            state.post_commit = match post_commit {
                Ok(result) => Observation::Returned(result),
                Err(payload) => Observation::Panicked(payload),
            };
        }
        if state.phase != NodeWriterPhase::Finished {
            owner.stopped.store(true, Ordering::Release);
        }
    }
}
impl StoragePayload for CatalogPutRequest {
    const KIND: StorageOwnerKind = StorageOwnerKind::Writer;

    fn drive(&self) -> bool {
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        if state.phase == NodeWriterPhase::Queued {
            state.phase = NodeWriterPhase::Cancelled;
        }
        self.dispose(&mut state, false) && (state.outcomes_released || !state.has_failures())
    }
}

/// A single census child owns the admitted catalog and native write until its
/// original terminal, rollback, and disposal outcomes have been inspected.
pub struct RegisteredCatalogPut {
    registration: StorageRegistration<CatalogPutRequest>,
}
impl RegisteredCatalogPut {
    #[cfg(test)]
    pub(super) fn fail_owner_before_terminal_for_test(&self) {
        self.registration
            .owner()
            .state
            .lock()
            .fail_owner_before_terminal = true;
    }

    pub fn retained(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<Self> {
        let registration = provider.storage_census().retained(provider.clone(), id)?;
        Some(Self { registration })
    }

    pub fn run(&self) -> NodeWriterPhase {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeWriterPhase::Queued {
            return state.phase;
        }
        state.outcomes_released = false;
        state.outer = Observation::Entered;
        match catch_unwind(AssertUnwindSafe(|| request.execute(&mut state))) {
            Ok(()) => state.outer = Observation::Returned(Ok(())),
            Err(payload) => {
                state.outer = Observation::Panicked(payload);
                request
                    .database
                    .owner()
                    .stopped
                    .store(true, Ordering::Release);
            }
        }
        state.phase
    }

    pub fn id(&self) -> StorageOwnerId {
        self.registration.id()
    }

    pub fn report(&self) -> NodeCatalogWriteReport<'_> {
        NodeCatalogWriteReport {
            state: self.registration.owner().state.lock(),
        }
    }

    pub fn retire(self) -> StorageCensusDisposition {
        let owner = self.registration.owner();
        if let Some(mut state) = owner.state.try_lock() {
            if state.phase == NodeWriterPhase::Queued {
                state.phase = NodeWriterPhase::Cancelled;
            }
            state.outcomes_released = true;
        }
        self.registration.retire()
    }
}

pub struct NodeCatalogWriteReport<'a> {
    state: MutexGuard<'a, CatalogWriterState>,
}
impl NodeCatalogWriteReport<'_> {
    pub fn phase(&self) -> NodeWriterPhase {
        self.state.phase
    }
    pub fn begin(&self) -> TerminalObservation<'_, kasumi_kv::TransactionError> {
        self.state.begin.borrow()
    }
    pub fn body(&self) -> TerminalObservation<'_, NodeCatalogPutBodyError> {
        self.state.body.borrow()
    }
    pub fn post_commit(&self) -> TerminalObservation<'_, NodeCatalogPutBodyError> {
        self.state.post_commit.borrow()
    }
    /// A fresh-only refusal whose original native abort and disposal completed.
    /// The caller may acknowledge this child and return the precise denial.
    pub fn clean_freshness_rejection(&self) -> Option<&'static str> {
        let message = match &self.state.body {
            Observation::Returned(Err(NodeCatalogPutBodyError::AlreadyInstalled)) => {
                "catalog already initialized"
            }
            Observation::Returned(Err(NodeCatalogPutBodyError::OrphanRecords)) => {
                "new catalog has orphan physical rows"
            }
            _ => return None,
        };
        let terminal = self.terminal()?;
        (self.state.phase == NodeWriterPhase::Finished
            && self.state.begin.success()
            && self.state.outer.success()
            && terminal.operation() == Some(WriteTerminalOperation::Abort)
            && matches!(terminal.terminal(), TerminalObservation::Returned(Ok(())))
            && terminal.disposal_complete())
        .then_some(message)
    }
    pub fn outer(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.state.outer.borrow()
    }
    pub fn terminal(&self) -> Option<kasumi_kv::WriteTerminalReport<'_>> {
        self.state
            .transaction
            .as_ref()
            .map(RetainedWriteTransaction::report)
    }
    pub fn committed_and_disposed(&self) -> bool {
        self.state.phase == NodeWriterPhase::Finished
            && self.state.begin.success()
            && self.state.body.success()
            && (!self.state.plan.is_pair() || self.state.post_commit.success())
            && self.state.outer.success()
            && self.terminal().is_some_and(|terminal| {
                terminal.operation() == Some(WriteTerminalOperation::Commit)
                    && matches!(terminal.terminal(), TerminalObservation::Returned(Ok(())))
                    && terminal.disposal_complete()
            })
    }
}

impl RegisteredNodeOpening {
    pub(crate) fn queue_catalog_put(
        &self,
        plan: AdmittedCatalogPut,
    ) -> io::Result<RegisteredCatalogPut> {
        self.queue_catalog_write(CatalogPutInput::Single(plan))
    }

    pub(crate) fn queue_catalog_pair_put(
        &self,
        plan: AdmittedCatalogPairPut,
        application: Arc<crate::TenantStore>,
        custody: Arc<crate::TenantStore>,
    ) -> io::Result<RegisteredCatalogPut> {
        if !Arc::ptr_eq(&application.node, &custody.node)
            || application.node.db.registered_opening_id() != Some(self.id())
            || custody.tenant() != crate::CustodyStore::catalog_name(application.tenant())
            || plan.entries()[0].hash() != &crate::tenant_hash(application.tenant())
            || plan.entries()[1].hash() != &crate::tenant_hash(custody.tenant())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.queue_catalog_write(CatalogPutInput::Pair {
            plan,
            stores: [application, custody],
        })
    }

    fn queue_catalog_write(&self, plan: CatalogPutInput) -> io::Result<RegisteredCatalogPut> {
        let owner = self.registration.owner();
        if owner.stopped.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let opening = owner.state.lock();
        if opening.phase != NodeOpeningPhase::Open
            || (!matches!(opening.mode, NodeOpeningMode::Existing)
                && !opening.ready_publication.success())
            || owner.stopped.load(Ordering::Acquire)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let provider = opening.file.disk().memory().clone();
        if plan
            .entries()
            .iter()
            .any(|entry| !Arc::ptr_eq(&provider, entry.provider()))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        drop(opening);
        let database = self.registration.clone();
        let registration = provider.storage_census().register_child(
            provider.clone(),
            0,
            &self.registration,
            || CatalogPutRequest {
                database,
                state: Mutex::new(CatalogWriterState {
                    phase: NodeWriterPhase::Queued,
                    plan,
                    transaction: None,
                    begin: Observation::NotEntered,
                    body: Observation::NotEntered,
                    post_commit: Observation::NotEntered,
                    outer: Observation::NotEntered,
                    outcomes_released: false,
                    #[cfg(test)]
                    fail_owner_before_terminal: false,
                }),
            },
        )?;
        let opening = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || opening.phase != NodeOpeningPhase::Open {
            drop(opening);
            registration.owner().state.lock().phase = NodeWriterPhase::Cancelled;
        }
        Ok(RegisteredCatalogPut { registration })
    }
}

#[cfg(test)]
#[path = "catalog_put_tests.rs"]
mod tests;
