//! Registered synchronous writes borrow their inputs and retain every original outcome.
use super::*;

struct ScopedWriterState {
    phase: NodeWriterPhase,
    transaction: Option<RetainedWriteTransaction>,
    begin: Observation<kasumi_kv::TransactionError>,
    body: Observation<anyhow::Error>,
    post_commit: Observation<anyhow::Error>,
    outer: Observation<std::convert::Infallible>,
    outcomes_released: bool,
}
impl ScopedWriterState {
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
    fn clean_aborted_body_error(&self) -> bool {
        self.phase == NodeWriterPhase::Finished
            && self.begin.success()
            && matches!(self.body, Observation::Returned(Err(_)))
            && matches!(self.post_commit, Observation::NotEntered)
            && self.outer.success()
            && self.transaction.as_ref().is_some_and(|transaction| {
                let terminal = transaction.report();
                terminal.operation() == Some(WriteTerminalOperation::Abort)
                    && terminal.settlement() == WriteTerminalSettlement::Settled
                    && matches!(terminal.terminal(), TerminalObservation::Returned(Ok(())))
                    && matches!(terminal.rollback(), TerminalObservation::NotEntered)
                    && terminal.disposal_complete()
            })
    }
}
struct ScopedWriteRequest {
    database: StorageRegistration<DatabaseOwner>,
    state: Mutex<ScopedWriterState>,
    clean_body_error_released: AtomicBool,
}

impl ScopedWriteRequest {
    fn dispose(&self, state: &mut ScopedWriterState, wait: bool) -> bool {
        let Some(transaction) = state.transaction.as_mut() else {
            return !matches!(state.outer, Observation::Panicked(_))
                && !matches!(state.begin, Observation::Entered);
        };
        if transaction.report().disposal_complete() {
            return true;
        }
        state.outcomes_released = false;
        self.database.owner().dispose_write(transaction, wait)
    }

    fn execute<W, T>(
        &self,
        state: &mut ScopedWriterState,
        workspace: &mut W,
        body: impl FnOnce(&kasumi_kv::WriteTransaction, &mut W) -> anyhow::Result<()>,
        post_commit: impl FnOnce(&mut W) -> anyhow::Result<T>,
    ) -> Option<T> {
        let owner = self.database.owner();
        let _serial = owner.serial.lock();
        if owner.stopped.load(Ordering::Acquire) {
            state.phase = NodeWriterPhase::Cancelled;
            return None;
        }
        state.phase = NodeWriterPhase::Begin;
        state.begin = Observation::Entered;
        let opening = owner.state.lock();
        let Some(database) = opening.engine.database() else {
            state.begin =
                Observation::Returned(Err(kasumi_kv::StorageError::DatabaseClosed.into()));
            return None;
        };
        let admission = database.transaction_admission();
        drop(opening);
        match admission.begin_write() {
            Ok(transaction) => {
                state.transaction = Some(transaction.retain());
                state.begin = Observation::Returned(Ok(()));
            }
            Err(error) => {
                state.begin = Observation::Returned(Err(error));
                state.phase = NodeWriterPhase::Finished;
                return None;
            }
        }
        state.phase = NodeWriterPhase::Body;
        state.body = Observation::Entered;
        state.body = match catch_unwind(AssertUnwindSafe(|| {
            body(
                state.transaction.as_ref().unwrap().transaction().unwrap(),
                workspace,
            )
        })) {
            Ok(result) => Observation::Returned(result),
            Err(payload) => Observation::Panicked(payload),
        };
        state.phase = NodeWriterPhase::Terminal;
        let transaction = state.transaction.as_mut().unwrap();
        if state.body.success() {
            let _ = transaction.commit_holding_writer();
        } else {
            let _ = transaction.abort();
        }
        let committed = state.body.success()
            && state.transaction.as_ref().is_some_and(|transaction| {
                let terminal = transaction.report();
                terminal.settlement() == WriteTerminalSettlement::HoldingWriter
                    && terminal.operation() == Some(WriteTerminalOperation::Commit)
                    && matches!(terminal.terminal(), TerminalObservation::Returned(Ok(())))
            });
        let mut output = None;
        if committed {
            state.phase = NodeWriterPhase::PostCommit;
            state.post_commit = Observation::Entered;
            state.post_commit = match catch_unwind(AssertUnwindSafe(|| post_commit(workspace))) {
                Ok(Ok(value)) => {
                    output = Some(value);
                    Observation::Returned(Ok(()))
                }
                Ok(Err(error)) => Observation::Returned(Err(error)),
                Err(payload) => Observation::Panicked(payload),
            };
        }
        state.phase = NodeWriterPhase::Disposal;
        if self.dispose(state, true) {
            state.phase = NodeWriterPhase::Finished;
        } else {
            owner.stopped.store(true, Ordering::Release);
        }
        output
    }
}
impl StoragePayload for ScopedWriteRequest {
    const KIND: StorageOwnerKind = StorageOwnerKind::Writer;
    fn drive(&self) -> bool {
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        if state.phase == NodeWriterPhase::Queued {
            state.phase = NodeWriterPhase::Cancelled;
        }
        if self.clean_body_error_released.load(Ordering::Acquire)
            && state.clean_aborted_body_error()
        {
            state.outcomes_released = true;
        }
        self.dispose(&mut state, false) && (state.outcomes_released || !state.has_failures())
    }
}

/// Exact fixed census child for a synchronous installed-node write.
/// No closure, borrowed input, table facade or mutable transaction escapes.
pub struct RegisteredNodeWrite {
    registration: StorageRegistration<ScopedWriteRequest>,
}
impl RegisteredNodeWrite {
    pub fn retained(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<Self> {
        let registration = provider.storage_census().retained(provider.clone(), id)?;
        Some(Self { registration })
    }
    pub fn id(&self) -> StorageOwnerId {
        self.registration.id()
    }
    pub fn report(&self) -> NodeWriteReport<'_> {
        NodeWriteReport {
            state: self.registration.owner().state.lock(),
            output: self
                .registration
                .owner()
                .database
                .owner()
                .provider
                .storage_census()
                .write_output_observation(self.id())
                .expect("exact registered write output slot"),
        }
    }
    pub(crate) fn provider(&self) -> Arc<dyn NodeDiskMemoryAdmission> {
        self.registration.owner().database.owner().provider.clone()
    }
    pub(crate) fn run<W, T>(
        &self,
        workspace: &mut W,
        body: impl FnOnce(&kasumi_kv::WriteTransaction, &mut W) -> anyhow::Result<()>,
        post_commit: impl FnOnce(&mut W) -> anyhow::Result<T>,
    ) -> Option<T> {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeWriterPhase::Queued {
            return None;
        }
        state.outer = Observation::Entered;
        match catch_unwind(AssertUnwindSafe(|| {
            request.execute(&mut state, workspace, body, post_commit)
        })) {
            Ok(output) => {
                state.outer = Observation::Returned(Ok(()));
                output
            }
            Err(payload) => {
                state.outer = Observation::Panicked(payload);
                request
                    .database
                    .owner()
                    .stopped
                    .store(true, Ordering::Release);
                None
            }
        }
    }
    /// A dropped clean rejection acknowledges its original returned body error
    /// only after actual native abort and disposal. Census still observes the
    /// original diagnostic destructor before returning any byte credit.
    pub(crate) fn retire_clean_body_error(self) -> StorageCensusDisposition {
        let owner = self.registration.owner();
        owner
            .clean_body_error_released
            .store(true, Ordering::Release);
        if let Some(mut state) = owner.state.try_lock()
            && state.clean_aborted_body_error()
        {
            state.outcomes_released = true;
        }
        owner
            .database
            .owner()
            .provider
            .storage_census()
            .release_disposed_write_output(self.id());
        self.registration.retire()
    }
    pub fn retire(self) -> StorageCensusDisposition {
        self.retire_inner(true)
    }
    pub(crate) fn retire_for_handoff(self) -> StorageCensusDisposition {
        self.retire_inner(false)
    }
    fn retire_inner(self, release_output: bool) -> StorageCensusDisposition {
        let owner = self.registration.owner();
        let mut cancelled_without_output = false;
        if let Some(mut state) = owner.state.try_lock() {
            if state.phase == NodeWriterPhase::Queued {
                state.phase = NodeWriterPhase::Cancelled;
            }
            cancelled_without_output = state.phase == NodeWriterPhase::Cancelled
                && matches!(state.begin, Observation::NotEntered)
                && matches!(state.body, Observation::NotEntered)
                && matches!(state.post_commit, Observation::NotEntered);
            state.outcomes_released = true;
        }
        if release_output {
            let census = owner.database.owner().provider.storage_census();
            census.release_disposed_write_output(self.id());
            if cancelled_without_output {
                census.release_unentered_write_output(self.id());
            }
        }
        self.registration.retire()
    }
}

pub struct NodeWriteReport<'a> {
    state: MutexGuard<'a, ScopedWriterState>,
    output: crate::storage_census::StorageWriteOutputObservation<'a>,
}
impl NodeWriteReport<'_> {
    pub fn output_disposal(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.output.disposal()
    }
    pub fn phase(&self) -> NodeWriterPhase {
        self.state.phase
    }
    pub fn begin(&self) -> TerminalObservation<'_, kasumi_kv::TransactionError> {
        self.state.begin.borrow()
    }
    pub fn body(&self) -> TerminalObservation<'_, anyhow::Error> {
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
            && self.state.post_commit.success()
            && self.state.outer.success()
            && self.terminal().is_some_and(|terminal| {
                terminal.operation() == Some(WriteTerminalOperation::Commit)
                    && matches!(terminal.terminal(), TerminalObservation::Returned(Ok(())))
                    && terminal.disposal_complete()
            })
    }
    /// Inspect exact native errors only after whole rollback and disposal.
    pub fn is_capacity_denied(&self) -> bool {
        if observed_failure(self.output_disposal()) {
            return false;
        }
        if self.state.clean_aborted_body_error() {
            let Observation::Returned(Err(error)) = &self.state.body else {
                return false;
            };
            return error.chain().any(|cause| {
                cause
                    .downcast_ref::<kasumi_kv::TableError>()
                    .is_some_and(kasumi_kv::TableError::is_capacity_denied)
                    || cause
                        .downcast_ref::<kasumi_kv::StorageError>()
                        .is_some_and(kasumi_kv::StorageError::is_capacity_denied)
            });
        }
        self.state.phase == NodeWriterPhase::Finished
            && self.state.begin.success()
            && self.state.body.success()
            && matches!(self.state.post_commit, Observation::NotEntered)
            && self.state.outer.success()
            && self.terminal().is_some_and(|terminal| {
                terminal.is_capacity_denied() && terminal.disposal_complete()
            })
    }
}

impl RegisteredNodeOpening {
    /// Retry only exact clean body failures whose facade has released its
    /// original observation. A report lock may have delayed that release.
    pub(crate) fn drain_released_clean_writers(
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        opening_id: StorageOwnerId,
    ) {
        let census = provider.storage_census();
        census.drain_disposed_children(opening_id);
        for index in 0..census.capacity() {
            let Some(id) = census.owner_at(index) else {
                continue;
            };
            let Some(registration) = census.retained::<ScopedWriteRequest>(provider.clone(), id)
            else {
                continue;
            };
            let request = registration.owner();
            if request.database.id() != opening_id
                || !request.clean_body_error_released.load(Ordering::Acquire)
            {
                continue;
            }
            let released = if let Some(mut state) = request.state.try_lock() {
                if state.clean_aborted_body_error() {
                    state.outcomes_released = true;
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if released {
                let _ = registration.retire();
            }
        }
        census.drain_disposed_children(opening_id);
    }

    pub(crate) fn queue_write(&self) -> io::Result<RegisteredNodeWrite> {
        let owner = self.registration.owner();
        let opening = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire)
            || opening.phase != NodeOpeningPhase::Open
            || (!matches!(opening.mode, NodeOpeningMode::Existing)
                && !opening.ready_publication.success())
        {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let provider = owner.provider.clone();
        drop(opening);
        let database = self.registration.clone();
        let registration = provider.storage_census().register_write_child(
            provider.clone(),
            0,
            &self.registration,
            || ScopedWriteRequest {
                database,
                clean_body_error_released: AtomicBool::new(false),
                state: Mutex::new(ScopedWriterState {
                    phase: NodeWriterPhase::Queued,
                    transaction: None,
                    begin: Observation::NotEntered,
                    body: Observation::NotEntered,
                    post_commit: Observation::NotEntered,
                    outer: Observation::NotEntered,
                    outcomes_released: false,
                }),
            },
        )?;
        let opening = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || opening.phase != NodeOpeningPhase::Open {
            registration.owner().state.lock().phase = NodeWriterPhase::Cancelled;
        }
        Ok(RegisteredNodeWrite { registration })
    }
}
