//! One registered binding insertion with admitted input and exact terminal custody.
use super::*;
use crate::storage_domains::AdmittedBindingPut;

#[derive(Debug)]
pub enum BindingInstallBodyError {
    ApplicationAccess(anyhow::Error),
    CustodyAccess(anyhow::Error),
    Table(kasumi_kv::TableError),
}

struct BindingWriterState {
    phase: NodeWriterPhase,
    plan: AdmittedBindingPut,
    transaction: Option<RetainedWriteTransaction>,
    begin: Observation<kasumi_kv::TransactionError>,
    body: Observation<BindingInstallBodyError>,
    post_commit: Observation<anyhow::Error>,
    outer: Observation<std::convert::Infallible>,
    outcomes_released: bool,
    #[cfg(test)]
    fail_owner_before_terminal: bool,
    #[cfg(test)]
    after_commit: Option<Box<dyn FnOnce() + Send>>,
    #[cfg(test)]
    before_dispose: Option<Box<dyn FnOnce() + Send>>,
}
impl BindingWriterState {
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

struct BindingPutRequest {
    database: StorageRegistration<DatabaseOwner>,
    application: Arc<crate::TenantStore>,
    custody: Arc<crate::TenantStore>,
    state: Mutex<BindingWriterState>,
}
impl BindingPutRequest {
    fn dispose(&self, state: &mut BindingWriterState, wait_for_settled: bool) -> bool {
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

    fn execute(&self, state: &mut BindingWriterState) {
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
        let body = catch_unwind(AssertUnwindSafe(|| {
            self.application
                .check_access()
                .map_err(BindingInstallBodyError::ApplicationAccess)?;
            self.custody
                .check_access()
                .map_err(BindingInstallBodyError::CustodyAccess)?;
            let transaction = state.transaction.as_ref().unwrap().transaction().unwrap();
            transaction
                .open_table(crate::RECORDS)
                .map_err(BindingInstallBodyError::Table)?
                .insert(state.plan.key().as_slice(), state.plan.envelope())
                .map_err(BindingInstallBodyError::Table)?;
            self.application
                .check_access()
                .map_err(BindingInstallBodyError::ApplicationAccess)?;
            self.custody
                .check_access()
                .map_err(BindingInstallBodyError::CustodyAccess)?;
            Ok(())
        }));
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
        #[cfg(test)]
        if let Some(before_dispose) = state.before_dispose.take() {
            before_dispose();
        }
        if self.dispose(state, true) {
            state.phase = NodeWriterPhase::Finished;
        }
        let committed = state.body.success()
            && state.transaction.as_ref().is_some_and(|transaction| {
                let report = transaction.report();
                report.operation() == Some(WriteTerminalOperation::Commit)
                    && matches!(report.terminal(), TerminalObservation::Returned(Ok(())))
            });
        if committed {
            #[cfg(test)]
            if let Some(after_commit) = state.after_commit.take() {
                after_commit();
            }
            state.post_commit = Observation::Entered;
            let post_commit = catch_unwind(AssertUnwindSafe(|| {
                self.application.check_access()?;
                self.custody.check_access()
            }));
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
impl StoragePayload for BindingPutRequest {
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

/// One child owns the admitted ciphertext, native terminal, and post-commit
/// access observation until its actual outcomes have been inspected.
pub struct RegisteredBindingPut {
    registration: StorageRegistration<BindingPutRequest>,
}
impl RegisteredBindingPut {
    #[cfg(test)]
    pub(crate) fn fail_owner_before_terminal_for_test(&self) {
        self.registration
            .owner()
            .state
            .lock()
            .fail_owner_before_terminal = true;
    }

    #[cfg(test)]
    pub(crate) fn after_commit_for_test(&self, callback: Box<dyn FnOnce() + Send>) {
        self.registration.owner().state.lock().after_commit = Some(callback);
    }

    #[cfg(test)]
    pub(crate) fn before_dispose_for_test(&self, callback: Box<dyn FnOnce() + Send>) {
        self.registration.owner().state.lock().before_dispose = Some(callback);
    }

    #[cfg(test)]
    pub(crate) fn hold_database_state_for_test(&self, callback: impl FnOnce()) {
        let _database = self.registration.owner().database.owner().state.lock();
        callback();
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

    pub fn report(&self) -> NodeBindingWriteReport<'_> {
        NodeBindingWriteReport {
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

pub struct NodeBindingWriteReport<'a> {
    state: MutexGuard<'a, BindingWriterState>,
}
impl NodeBindingWriteReport<'_> {
    pub fn phase(&self) -> NodeWriterPhase {
        self.state.phase
    }
    pub fn begin(&self) -> TerminalObservation<'_, kasumi_kv::TransactionError> {
        self.state.begin.borrow()
    }
    pub fn body(&self) -> TerminalObservation<'_, BindingInstallBodyError> {
        self.state.body.borrow()
    }
    pub fn post_commit(&self) -> TerminalObservation<'_, anyhow::Error> {
        self.state.post_commit.borrow()
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
            && self.state.outer.success()
            && self.terminal().is_some_and(|terminal| {
                terminal.operation() == Some(WriteTerminalOperation::Commit)
                    && matches!(terminal.terminal(), TerminalObservation::Returned(Ok(())))
                    && terminal.disposal_complete()
            })
    }
    pub fn confirmed(&self) -> bool {
        self.committed_and_disposed() && self.state.post_commit.success()
    }
}

impl RegisteredNodeOpening {
    pub(crate) fn queue_binding_put(
        &self,
        plan: AdmittedBindingPut,
        application: Arc<crate::TenantStore>,
        custody: Arc<crate::TenantStore>,
    ) -> io::Result<RegisteredBindingPut> {
        if !Arc::ptr_eq(&application.node, &custody.node)
            || application.node.db.registered_opening_id() != Some(self.id())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
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
        if !Arc::ptr_eq(&provider, plan.provider()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        drop(opening);
        let database = self.registration.clone();
        let registration = provider.storage_census().register_child(
            provider.clone(),
            0,
            &self.registration,
            || BindingPutRequest {
                database,
                application,
                custody,
                state: Mutex::new(BindingWriterState {
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
                    #[cfg(test)]
                    after_commit: None,
                    #[cfg(test)]
                    before_dispose: None,
                }),
            },
        )?;
        let opening = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || opening.phase != NodeOpeningPhase::Open {
            drop(opening);
            registration.owner().state.lock().phase = NodeWriterPhase::Cancelled;
        }
        Ok(RegisteredBindingPut { registration })
    }
}
