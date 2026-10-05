//! One installed read snapshot with admitted, owned byte results.
use super::*;
use kasumi_kv::{BoundedReadError, ReadCloseSettlement, RetainedReadTransaction};
use std::sync::atomic::AtomicUsize;
#[path = "read_report.rs"]
mod read_report;
pub(crate) use read_report::AdmittedReadReport;
mod source_pool;
pub(super) use source_pool::drain_source_owners;
pub use source_pool::{
    PreparedRegisteredSource, RegisteredSourceCapacity, SourceCapacityClose, SourceCapacityFailure,
    SourceCapacityReport, SourceCapacityRetirement, SourceHistoryAbort, SourceHistoryRefusal,
    SourcePoolPhase,
};
#[cfg(any(test, feature = "test-utils"))]
pub use source_pool::{
    RegisteredSourceFundingFixture, SourceCompletionFault, SourceReadDiagnostic,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeReadPhase {
    Queued,
    /// Registered selected-snapshot intent. Public begin must never turn this
    /// into a current-root read, even through a recovered census facade.
    ForkQueued,
    /// Registered protected-source intent; ordinary begin/read cannot dispatch it.
    SourceQueued,
    SourcePreparing,
    SourcePrepared,
    SourceCapturing,
    SourceCaptured,
    SourceHistory,
    Begin,
    Tables,
    Active,
    Failed,
    WaitingForGuards,
    Finished,
    Cancelled,
    Retained,
}

#[derive(Debug)]
pub enum NodeReadAccessError {
    InvalidInput,
    Unavailable,
    Admission(io::Error),
    Reported,
}
impl std::fmt::Display for NodeReadAccessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput => formatter.write_str("invalid retained read bound or key"),
            Self::Unavailable => formatter.write_str("retained read snapshot is unavailable"),
            Self::Admission(error) => std::fmt::Display::fmt(error, formatter),
            Self::Reported => formatter.write_str("retained read failed; inspect its owner report"),
        }
    }
}
impl std::error::Error for NodeReadAccessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(error) => Some(error),
            _ => None,
        }
    }
}

/// The lease stays with the copy while callers decode or hand off the bytes.
pub struct AdmittedReadBytes {
    bytes: kasumi_kv::AdmittedValue,
    // Catalog still has its existing outer reservation. Point values already
    // carry the exact native reservation in `bytes`.
    _charge: Option<crate::DiskMemoryLease>,
}
impl AdmittedReadBytes {
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

/// Both owned vectors share the pre-effect reservation for this one row.
pub struct OwnedEncryptedRow {
    key: kasumi_kv::AdmittedValue,
    value: kasumi_kv::AdmittedValue,
    _charge: crate::DiskMemoryLease,
}
impl OwnedEncryptedRow {
    pub fn key(&self) -> &[u8] {
        self.key.as_bytes()
    }
    pub fn value(&self) -> &[u8] {
        self.value.as_bytes()
    }
    /// Keep only the native-admitted key for the next range seek. The value
    /// and its pessimistic outer reservation are released before that seek.
    pub fn into_key(self) -> AdmittedReadBytes {
        let Self {
            key,
            value,
            _charge,
        } = self;
        drop(value);
        drop(_charge);
        AdmittedReadBytes {
            bytes: key,
            _charge: None,
        }
    }
}

#[derive(Debug)]
pub enum NodeReadTablesError {
    Catalog(BoundedReadError),
    Records(BoundedReadError),
}
impl std::fmt::Display for NodeReadTablesError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Catalog(error) => write!(formatter, "catalog table: {error}"),
            Self::Records(error) => write!(formatter, "records table: {error}"),
        }
    }
}
impl std::error::Error for NodeReadTablesError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Catalog(error) | Self::Records(error) => Some(error),
        }
    }
}

// Native disposition stays attached to its exact original error. Local
// rejections cannot manufacture the native clean-acquisition proof.
enum ReadBeginFailure {
    Native(kasumi_kv::ReadAcquisitionFailure),
    Local(kasumi_kv::TransactionError),
}
impl ReadBeginFailure {
    fn original(&self) -> &kasumi_kv::TransactionError {
        match self {
            Self::Native(error) => error.original(),
            Self::Local(error) => error,
        }
    }
}
#[derive(Clone, Copy)]
enum RoutineReadFailure {
    Acquisition,
    Tables,
    Body,
}

struct ReaderState {
    phase: NodeReadPhase,
    transaction: Option<RetainedReadTransaction>,
    // Private typed source purpose stays present even after native disposal.
    // Its inline layout is included in every owning report quote.
    source: Option<source_pool::SourceReaderState>,
    begin: Observation<ReadBeginFailure>,
    tables: Observation<NodeReadTablesError>,
    outer: Observation<std::convert::Infallible>,
    output_admission: Observation<io::Error>,
    read_failure: Observation<BoundedReadError>,
    body_panic: Observation<std::convert::Infallible>,
    finish_outer: Observation<std::convert::Infallible>,
    outcomes_released: bool,
}
impl ReaderState {
    fn has_failures(&self) -> bool {
        let failures = observed_failure(self.begin.borrow())
            || observed_failure(self.tables.borrow())
            || observed_failure(self.outer.borrow())
            || observed_failure(self.output_admission.borrow())
            || observed_failure(self.read_failure.borrow())
            || observed_failure(self.body_panic.borrow())
            || observed_failure(self.finish_outer.borrow());
        let failures = failures
            || self
                .source
                .as_ref()
                .is_some_and(source_pool::SourceReaderState::has_failures);
        failures
            || self.transaction.as_ref().is_some_and(|transaction| {
                let report = transaction.report();
                observed_failure(report.release())
                    || observed_failure(report.disposal())
                    || observed_failure(report.native_retirement())
            })
    }

    // Classify every observation together; a known capacity result cannot
    // acknowledge an unrelated unknown result introduced by a recovered facade.
    fn routine_failure(&self) -> Option<RoutineReadFailure> {
        if self.source.is_some() {
            return None;
        }
        if !self.outer.success() || !matches!(self.body_panic, Observation::NotEntered) {
            return None;
        }
        let body_unentered = matches!(self.read_failure, Observation::NotEntered)
            && matches!(self.output_admission, Observation::NotEntered);
        if let Observation::Returned(Err(ReadBeginFailure::Native(error))) = &self.begin {
            return (error.is_clean_capacity_refusal()
                && matches!(self.tables, Observation::NotEntered)
                && body_unentered)
                .then_some(RoutineReadFailure::Acquisition);
        }
        if !self.begin.success() {
            return None;
        }
        let table_capacity = match &self.tables {
            Observation::Returned(Err(
                NodeReadTablesError::Catalog(error) | NodeReadTablesError::Records(error),
            )) => matches!(&(error), BoundedReadError::Table(kasumi_kv::TableError::Storage(
                    kasumi_kv::StorageError::Core(native_error)
                )) if matches!(native_error.rejected_cause(), Some(kasumi_kv::CoreErrorCause::CapacityDenied))),
            _ => false,
        };
        if table_capacity && body_unentered {
            return Some(RoutineReadFailure::Tables);
        }
        if !self.tables.success() {
            return None;
        }
        let routine_read = match self.read_failure.borrow() {
            TerminalObservation::Returned(Err(BoundedReadError::BoundExceeded)) => true,
            TerminalObservation::Returned(Err(BoundedReadError::Storage(
                kasumi_kv::StorageError::Core(original),
            ))) => original.is_capacity_denied(),
            _ => false,
        };
        let routine_output = matches!(self.output_admission.borrow(),
            TerminalObservation::Returned(Err(error)) if error.kind() == io::ErrorKind::OutOfMemory);
        let read_safe = routine_read
            || matches!(
                self.read_failure.borrow(),
                TerminalObservation::NotEntered | TerminalObservation::Returned(Ok(()))
            );
        let output_safe = routine_output
            || matches!(
                self.output_admission.borrow(),
                TerminalObservation::NotEntered | TerminalObservation::Returned(Ok(()))
            );
        (read_safe && output_safe && (routine_read || routine_output))
            .then_some(RoutineReadFailure::Body)
    }

    fn routine_diagnostic_detachable(&self) -> bool {
        if self.phase != NodeReadPhase::Finished || !self.finish_outer.success() {
            return false;
        }
        let Some(failure) = self.routine_failure() else {
            return false;
        };
        if matches!(failure, RoutineReadFailure::Acquisition) {
            // Absence only corroborates the native-minted normal-return proof.
            // It never substitutes for that proof or invents close observations.
            return self.transaction.is_none();
        }
        let Some(transaction) = &self.transaction else {
            return false;
        };
        let native = transaction.report();
        native.settlement() == ReadCloseSettlement::Disposed
            && !native.retains_transaction()
            && !native.retains_database()
            && matches!(native.release(), TerminalObservation::Returned(Ok(())))
            && matches!(native.disposal(), TerminalObservation::Returned(Ok(())))
            && matches!(
                native.native_retirement(),
                TerminalObservation::Returned(Ok(()))
            )
    }

    fn acknowledge_settled_routine(&mut self) -> bool {
        if !self.routine_diagnostic_detachable() {
            return false;
        }
        self.outcomes_released = true;
        true
    }
}

struct ReaderRequest {
    database: StorageRegistration<DatabaseOwner>,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    facades: AtomicUsize,
    // Last-facade retry intent must survive a held immutable report without blocking Drop.
    auto_retire_routine_failure: AtomicBool,
    state: AdmittedReadReport,
}
impl ReaderRequest {
    fn begin_locked(&self, state: &mut ReaderState) {
        let owner = self.database.owner();
        if owner.stopped.load(Ordering::Acquire) {
            state.phase = NodeReadPhase::Cancelled;
            return;
        }
        state.phase = NodeReadPhase::Begin;
        state.begin = Observation::Entered;
        let opening = owner.state.lock();
        let Some(database) = opening.engine.database() else {
            state.begin = Observation::Returned(Err(ReadBeginFailure::Local(
                kasumi_kv::StorageError::DatabaseClosed.into(),
            )));
            state.phase = NodeReadPhase::Failed;
            return;
        };
        state.begin = match database.begin_read_retained() {
            Ok(transaction) => {
                state.transaction = Some(transaction);
                Observation::Returned(Ok(()))
            }
            Err(error) => {
                state.phase = NodeReadPhase::Failed;
                Observation::Returned(Err(ReadBeginFailure::Native(error)))
            }
        };
        drop(opening);
        if !state.begin.success() {
            return;
        }
        self.verify_tables_locked(state);
    }

    fn fork_locked(&self, state: &mut ReaderState, parent: &ReaderState) {
        let owner = self.database.owner();
        if owner.stopped.load(Ordering::Acquire) {
            state.phase = NodeReadPhase::Cancelled;
            return;
        }
        state.phase = NodeReadPhase::Begin;
        state.begin = Observation::Entered;
        let opening = owner.state.lock();
        if opening.phase != NodeOpeningPhase::Open
            || opening.engine.database().is_none()
            || parent.phase != NodeReadPhase::Active
        {
            state.begin = Observation::Returned(Err(ReadBeginFailure::Local(
                kasumi_kv::StorageError::DatabaseClosed.into(),
            )));
            state.phase = NodeReadPhase::Failed;
            return;
        }
        let parent = parent
            .transaction
            .as_ref()
            .expect("active parent transaction");
        state.begin = match parent.fork() {
            Ok(transaction) => {
                // Install the actual child before another fallible stage. It
                // owns a different backing while sharing the original pin.
                state.transaction = Some(transaction);
                Observation::Returned(Ok(()))
            }
            Err(error) => {
                state.phase = NodeReadPhase::Failed;
                Observation::Returned(Err(ReadBeginFailure::Native(error)))
            }
        };
    }

    fn verify_tables_locked(&self, state: &mut ReaderState) {
        let owner = self.database.owner();
        state.phase = NodeReadPhase::Tables;
        state.tables = Observation::Entered;
        let transaction = state.transaction.as_ref().expect("installed reader");
        state.tables = match transaction
            .check_bytes_table(crate::CATALOG)
            .map_err(NodeReadTablesError::Catalog)
            .and_then(|_| {
                transaction
                    .check_bytes_table(crate::RECORDS)
                    .map_err(NodeReadTablesError::Records)
            }) {
            Ok(()) => Observation::Returned(Ok(())),
            Err(error) => Observation::Returned(Err(error)),
        };
        if !state.tables.success() {
            state.phase = NodeReadPhase::Failed;
            return;
        }
        let mut opening = owner.state.lock();
        if matches!(opening.mode, NodeOpeningMode::Existing) {
            opening.existing_tables_verified = true;
        }
        state.phase = NodeReadPhase::Active;
    }

    fn finish_locked(&self, state: &mut ReaderState) -> NodeReadPhase {
        if state.source.is_some() {
            return source_pool::finish_source_locked(self, state);
        }
        if matches!(
            state.phase,
            NodeReadPhase::Queued | NodeReadPhase::ForkQueued
        ) {
            state.phase = NodeReadPhase::Cancelled;
            return state.phase;
        }
        if matches!(
            state.phase,
            NodeReadPhase::Finished | NodeReadPhase::Cancelled | NodeReadPhase::Retained
        ) {
            return state.phase;
        }
        let Some(transaction) = state.transaction.as_mut() else {
            state.phase = NodeReadPhase::Finished;
            return state.phase;
        };
        let Some(opening) = self.database.owner().state.try_lock() else {
            return state.phase;
        };
        let Some(database) = opening.engine.retained_database() else {
            state.phase = NodeReadPhase::Retained;
            state.outcomes_released = false;
            return state.phase;
        };
        let settlement = transaction.close(database).settlement();
        let settlement = if settlement == ReadCloseSettlement::Settled {
            transaction.dispose_settled(database).settlement()
        } else {
            settlement
        };
        match settlement {
            ReadCloseSettlement::Disposed => state.phase = NodeReadPhase::Finished,
            ReadCloseSettlement::WaitingForGuards => {
                state.phase = NodeReadPhase::WaitingForGuards;
            }
            ReadCloseSettlement::Retained | ReadCloseSettlement::DisposalUncertain => {
                state.phase = NodeReadPhase::Retained;
                state.outcomes_released = false;
                self.database.owner().stopped.store(true, Ordering::Release);
            }
            ReadCloseSettlement::Open | ReadCloseSettlement::Settled => {
                state.phase = NodeReadPhase::Retained;
                state.outcomes_released = false;
            }
        }
        state.phase
    }
    fn finish_observed(&self, state: &mut ReaderState) -> NodeReadPhase {
        if matches!(
            state.phase,
            NodeReadPhase::Finished | NodeReadPhase::Cancelled | NodeReadPhase::Retained
        ) {
            return state.phase;
        }
        state.finish_outer = Observation::Entered;
        match catch_unwind(AssertUnwindSafe(|| self.finish_locked(state))) {
            Ok(phase) => {
                state.finish_outer = Observation::Returned(Ok(()));
                phase
            }
            Err(payload) => {
                state.finish_outer = Observation::Panicked(payload);
                state.phase = NodeReadPhase::Retained;
                state.outcomes_released = false;
                self.database.owner().stopped.store(true, Ordering::Release);
                state.phase
            }
        }
    }
}
impl crate::storage_census::NativeStartupChild for ReaderRequest {
    const PURPOSE: crate::storage_census::NativeStartupChildPurpose =
        crate::storage_census::NativeStartupChildPurpose::Verification;
    fn report_bytes() -> io::Result<u64> {
        AdmittedReadReport::request_bytes()
    }
    fn abandon_delivery(&self) {
        let previous = self.facades.fetch_sub(1, Ordering::AcqRel);
        assert_ne!(previous, 0, "original undelivered reader facade obligation");
    }
}
impl StoragePayload for ReaderRequest {
    const KIND: StorageOwnerKind = StorageOwnerKind::Reader;
    fn drive(&self) -> bool {
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        if self.facades.load(Ordering::Acquire) != 0
            && !matches!(
                state.phase,
                NodeReadPhase::Finished | NodeReadPhase::Cancelled
            )
        {
            return false;
        }
        let phase = self.finish_observed(&mut state);
        if self.auto_retire_routine_failure.load(Ordering::Acquire) {
            state.acknowledge_settled_routine();
        }
        matches!(phase, NodeReadPhase::Finished | NodeReadPhase::Cancelled)
            && (state.outcomes_released || !state.has_failures())
    }
}

struct ReadFacadeLease {
    registration: Option<StorageRegistration<ReaderRequest>>,
}
impl Drop for ReadFacadeLease {
    fn drop(&mut self) {
        let Some(registration) = self.registration.take() else {
            // The private routine path already released this facade without
            // acknowledging observations again or waiting for a report guard.
            return;
        };
        let request = registration.owner();
        let previous = request.facades.fetch_sub(1, Ordering::AcqRel);
        debug_assert_ne!(previous, 0);
        // A dropped error facade releases its exact observed, routine failure
        // only after the last reader facade has finished inspecting the report.
        // Keep the retirement intent if a retained facade raced this drop and
        // held the census owner through the first drain attempt.
        // Unknown I/O and panics still retain their census cell and report.
        let retry = if previous == 1 {
            request
                .auto_retire_routine_failure
                .store(true, Ordering::Release);
            let settled = if let Some(mut state) = request.state.try_lock() {
                if state.routine_failure().is_some() {
                    request.finish_observed(&mut state);
                    Some(state.acknowledge_settled_routine())
                } else {
                    request
                        .auto_retire_routine_failure
                        .store(false, Ordering::Release);
                    None
                }
            } else {
                Some(false)
            };
            settled.map(|settled| (settled, request.provider.clone(), registration.id()))
        } else {
            None
        };
        if let Some((settled, provider, id)) = retry {
            let disposition = registration.retire();
            if settled {
                let _ = settle_finished_reader_retirement(&provider, id, disposition);
            }
        }
    }
}

/// The census holds the transaction after facade cancellation or drop.
pub struct RegisteredNodeRead {
    registration: StorageRegistration<ReaderRequest>,
    lease: ReadFacadeLease,
}

// A finished, failure-free reader has no remaining transaction work. After its
// facade drops, a concurrent registration can still briefly own the census
// slot metadata, so give that exact slot a bounded chance to retire.
fn settle_finished_reader_retirement(
    provider: &Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
    mut disposition: StorageCensusDisposition,
) -> StorageCensusDisposition {
    for _ in 0..64 {
        match disposition {
            StorageCensusDisposition::Retired | StorageCensusDisposition::Stale => {
                // This facade held the exact generation until retirement
                // began. Stale here means another drainer retired it first.
                return StorageCensusDisposition::Retired;
            }
            StorageCensusDisposition::Retained => {
                std::thread::yield_now();
                disposition = provider.storage_census().drain_owner(id);
            }
        }
    }
    disposition
}

impl RegisteredNodeOpening {
    /// Drive only released routine readers registered under this opening.
    /// Called before close takes the opening state lock, so a prior last-facade
    /// drop that observed transient lock contention can finish its transaction.
    pub(crate) fn drain_released_routine_readers(
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        opening_id: StorageOwnerId,
    ) {
        let census = provider.storage_census();
        // An earlier pass may have disposed a child payload and lost its typed
        // facade while metadata contention delayed lease/cell retirement.
        census.drain_disposed_children(opening_id);
        for index in 0..census.capacity() {
            let Some(id) = census.owner_at(index) else {
                continue;
            };
            let Some(registration) = census.retained::<ReaderRequest>(provider.clone(), id) else {
                continue;
            };
            let request = registration.owner();
            if request.database.id() != opening_id {
                continue;
            }
            let settled = if let Some(mut state) = request.state.try_lock() {
                if !request.auto_retire_routine_failure.load(Ordering::Acquire)
                    || state.routine_failure().is_none()
                {
                    false
                } else {
                    let phase = request.finish_observed(&mut state);
                    state.acknowledge_settled_routine();
                    if phase == NodeReadPhase::Retained {
                        request
                            .auto_retire_routine_failure
                            .store(false, Ordering::Release);
                    }
                    matches!(phase, NodeReadPhase::Finished | NodeReadPhase::Cancelled)
                        && state.outcomes_released
                }
            } else {
                false
            };
            if settled {
                let disposition = registration.retire();
                let _ = settle_finished_reader_retirement(provider, id, disposition);
            }
        }
        census.drain_disposed_children(opening_id);
    }

    /// Register the request before beginning the actual read transaction.
    /// After registration, concurrent close yields the exact cancelled reader
    /// so the caller retains its ID, report, and retirement responsibility.
    pub fn queue_read(&self) -> io::Result<RegisteredNodeRead> {
        self.queue_reader(NodeReadPhase::Queued)
    }

    fn queue_reader(&self, phase: NodeReadPhase) -> io::Result<RegisteredNodeRead> {
        debug_assert!(matches!(
            phase,
            NodeReadPhase::Queued | NodeReadPhase::ForkQueued
        ));
        let owner = self.registration.owner();
        if owner.stopped.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let opening = owner.state.lock();
        if opening.phase != NodeOpeningPhase::Open
            || (!matches!(opening.mode, NodeOpeningMode::Existing)
                && !opening.ready_publication.success())
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let provider = owner.provider.clone();
        drop(opening);
        let report = AdmittedReadReport::new(
            &provider,
            ReaderState {
                phase,
                transaction: None,
                source: None,
                begin: Observation::NotEntered,
                tables: Observation::NotEntered,
                outer: Observation::NotEntered,
                output_admission: Observation::NotEntered,
                read_failure: Observation::NotEntered,
                body_panic: Observation::NotEntered,
                finish_outer: Observation::NotEntered,
                outcomes_released: false,
            },
        )?;
        let database = self.registration.clone();
        let registration = provider.storage_census().register_child(
            provider.clone(),
            0,
            &self.registration,
            || ReaderRequest {
                database,
                provider: provider.clone(),
                facades: AtomicUsize::new(1),
                auto_retire_routine_failure: AtomicBool::new(false),
                state: report,
            },
        )?;
        if owner.stopped.load(Ordering::Acquire)
            || owner.state.lock().phase != NodeOpeningPhase::Open
        {
            registration.owner().state.lock().phase = NodeReadPhase::Cancelled;
        }
        let lease = ReadFacadeLease {
            registration: Some(registration.clone()),
        };
        Ok(RegisteredNodeRead {
            registration,
            lease,
        })
    }

    #[cfg(test)]
    pub(super) fn retained_verification_constructor_for_test(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<NativeConstructorFailure> {
        provider
            .storage_census()
            .retained_native_constructor::<ReaderRequest>(provider.clone(), id)
    }
    /// Prepare the exact startup verification child without beginning it. The
    /// coordinator must install the returned facade before native dispatch.
    pub(super) fn queue_startup_verification(
        &self,
    ) -> Result<RegisteredNodeRead, NativeConstructorFailure> {
        let owner = self.registration.owner();
        let Some(opening) = owner.state.try_lock() else {
            return Err(NativeConstructorFailure::Preclaim(
                io::ErrorKind::WouldBlock.into(),
            ));
        };
        if !matches!(opening.mode, NodeOpeningMode::Existing)
            || opening.phase != NodeOpeningPhase::Open
            || owner.stopped.load(Ordering::Acquire)
        {
            return Err(NativeConstructorFailure::Preclaim(
                io::ErrorKind::InvalidInput.into(),
            ));
        }
        let provider = owner.provider.clone();
        drop(opening);
        let database = self.registration.clone();
        let registration = provider.storage_census().register_native_startup_child(
            provider.clone(),
            &self.registration,
            |_| Ok(()),
            |grant| ReaderRequest {
                database,
                provider: provider.clone(),
                facades: AtomicUsize::new(1),
                auto_retire_routine_failure: AtomicBool::new(false),
                state: AdmittedReadReport::new_startup(
                    grant,
                    ReaderState {
                        phase: NodeReadPhase::Queued,
                        transaction: None,
                        source: None,
                        begin: Observation::NotEntered,
                        tables: Observation::NotEntered,
                        outer: Observation::NotEntered,
                        output_admission: Observation::NotEntered,
                        read_failure: Observation::NotEntered,
                        body_panic: Observation::NotEntered,
                        finish_outer: Observation::NotEntered,
                        outcomes_released: false,
                    },
                ),
            },
        )?;
        let lease = ReadFacadeLease {
            registration: Some(registration.clone()),
        };
        Ok(RegisteredNodeRead {
            registration,
            lease,
        })
    }

    /// Return the exact reader even if verification fails so its report and
    /// transaction can be inspected and retired.
    pub fn verify_existing_tables(&self) -> io::Result<RegisteredNodeRead> {
        if !matches!(
            self.registration.owner().state.lock().mode,
            NodeOpeningMode::Existing
        ) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let reader = self.queue_read()?;
        let _ = reader.begin();
        Ok(reader)
    }
}
impl RegisteredNodeRead {
    /// Recover the exact failed startup verification constructor by its
    /// provider and generation. The separately installed report stays funded.
    pub fn retained_constructor(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<NativeConstructorFailure> {
        provider
            .storage_census()
            .retained_native_constructor::<ReaderRequest>(provider.clone(), id)
    }
    pub(crate) fn memory_requests() -> io::Result<[u64; 2]> {
        Ok([
            AdmittedReadReport::request_bytes()?,
            crate::StorageCensus::registration_request_bytes::<ReaderRequest>(0)?,
        ])
    }

    pub(crate) fn belongs_to(&self, opening: &RegisteredNodeOpening) -> bool {
        std::ptr::eq(
            self.registration.owner().database.owner(),
            opening.registration.owner(),
        )
    }

    fn queue_fork(&self) -> io::Result<Self> {
        let opening = RegisteredNodeOpening {
            registration: self.registration.owner().database.clone(),
        };
        opening.queue_reader(NodeReadPhase::ForkQueued)
    }

    /// Register an independent reader before forking this exact selected pin.
    /// An error is pre-registration refusal. Every registered outcome returns
    /// its actual child ID/report, including failed or cancelled forks.
    pub fn fork(&self) -> io::Result<Self> {
        let child = self.queue_fork()?;
        child.begin_fork(self);
        Ok(child)
    }

    fn begin_fork(&self, parent: &Self) -> NodeReadPhase {
        let request = self.registration.owner();
        let parent_request = parent.registration.owner();
        // These are private construction invariants; no caller can nominate a
        // foreign opening or substitute the child for its selected parent.
        assert!(!std::ptr::eq(request, parent_request));
        assert!(std::ptr::eq(
            request.database.owner(),
            parent_request.database.owner()
        ));
        let parent_state = parent_request.state.lock();
        let mut state = request.state.lock();
        // The census can expose a facade immediately after registration. A
        // recovered begin cannot dispatch ForkQueued; a finish/retire may win
        // and cancel it. Never overwrite that winning terminal observation.
        if state.phase != NodeReadPhase::ForkQueued {
            return state.phase;
        }
        state.outcomes_released = false;
        state.outer = Observation::Entered;
        match catch_unwind(AssertUnwindSafe(|| {
            request.fork_locked(&mut state, &parent_state);
            drop(parent_state);
            if state.begin.success() {
                request.verify_tables_locked(&mut state);
            }
        })) {
            Ok(()) => state.outer = Observation::Returned(Ok(())),
            Err(payload) => {
                state.outer = Observation::Panicked(payload);
                state.phase = NodeReadPhase::Failed;
                request
                    .database
                    .owner()
                    .stopped
                    .store(true, Ordering::Release);
            }
        }
        state.phase
    }

    /// Keep the exact request and its native observations alive when a
    /// long-lived view returns an error before its own facade is dropped.
    pub(crate) fn retain_report_facade(&self) -> Self {
        self.registration
            .owner()
            .facades
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .expect("live read facade count cannot overflow");
        let registration = self.registration.clone();
        let lease = ReadFacadeLease {
            registration: Some(registration.clone()),
        };
        Self {
            registration,
            lease,
        }
    }

    /// The body owns the first unwind payload. It cannot be resumed after
    /// custody transfers to this exact census child.
    pub(crate) fn preserve_body_panic(&self, payload: Box<dyn std::any::Any + Send>) {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if matches!(state.body_panic, Observation::NotEntered) {
            state.body_panic = Observation::Panicked(payload);
            state.outcomes_released = false;
            request
                .auto_retire_routine_failure
                .store(false, Ordering::Release);
        }
    }

    /// Drop during an external unwind has no access to that payload. Mark
    /// the interrupted body so a clean native close cannot auto-retire it.
    pub(crate) fn mark_unwinding_body(&self) {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if matches!(state.body_panic, Observation::NotEntered) {
            state.body_panic = Observation::Entered;
            state.outcomes_released = false;
            request
                .auto_retire_routine_failure
                .store(false, Ordering::Release);
        }
    }

    pub fn retained(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<Self> {
        let registration: StorageRegistration<ReaderRequest> =
            provider.storage_census().retained(provider.clone(), id)?;
        registration
            .owner()
            .facades
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .ok()?;
        let lease = ReadFacadeLease {
            registration: Some(registration.clone()),
        };
        Some(Self {
            registration,
            lease,
        })
    }
    pub fn id(&self) -> StorageOwnerId {
        self.registration.id()
    }
    pub(crate) fn admitted_report(&self) -> AdmittedReadReport {
        self.registration.owner().state.clone()
    }
    pub(crate) fn provider(&self) -> Arc<dyn NodeDiskMemoryAdmission> {
        self.registration.owner().provider.clone()
    }
    /// Permission and the exact recognized outcome are one transition. An
    /// observer can keep the report locked indefinitely; retirement never waits
    /// for that observer and never acknowledges a later unknown observation.
    pub(crate) fn try_acknowledge_routine(&self) -> bool {
        let request = self.registration.owner();
        let Some(mut state) = request.state.try_lock() else {
            return false;
        };
        request.finish_observed(&mut state);
        state.acknowledge_settled_routine()
    }

    /// Release an already-checked facade without re-acknowledging outcomes.
    /// A recovered facade may have added an unknown failure since permission;
    /// its reset outcomes_released flag must still prevent census retirement.
    pub(crate) fn retire_acknowledged(self) -> StorageCensusDisposition {
        let Self {
            registration,
            mut lease,
        } = self;
        let facade = lease.registration.take().expect("read facade registration");
        let previous = facade.owner().facades.fetch_sub(1, Ordering::AcqRel);
        debug_assert_ne!(previous, 0);
        drop(facade);
        drop(lease);
        registration.retire()
    }
    pub fn begin(&self) -> NodeReadPhase {
        self.begin_queued(false)
            .expect("ordinary begin always reports its phase")
    }

    /// Dispatch only a still-unbegun request. The phase check and actual native
    /// acquisition share one state lock, so a recovered begin can never lend an
    /// older Active root to prospective publication capture.
    pub(crate) fn begin_unbegun(&self) -> Option<NodeReadPhase> {
        self.begin_queued(true)
    }

    fn begin_queued(&self, require_unbegun: bool) -> Option<NodeReadPhase> {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeReadPhase::Queued {
            return (!require_unbegun).then_some(state.phase);
        }
        if require_unbegun && state.has_failures() {
            return None;
        }
        state.outcomes_released = false;
        state.outer = Observation::Entered;
        match catch_unwind(AssertUnwindSafe(|| request.begin_locked(&mut state))) {
            Ok(()) => state.outer = Observation::Returned(Ok(())),
            Err(payload) => {
                state.outer = Observation::Panicked(payload);
                state.phase = NodeReadPhase::Failed;
                request
                    .database
                    .owner()
                    .stopped
                    .store(true, Ordering::Release);
            }
        }
        Some(state.phase)
    }
    pub fn phase(&self) -> NodeReadPhase {
        self.registration.owner().state.lock().phase
    }
    pub fn report(&self) -> NodeReadReport<'_> {
        NodeReadReport {
            state: self.registration.owner().state.lock(),
        }
    }
    fn reserve_output(&self, bytes: u64) -> Result<crate::DiskMemoryLease, NodeReadAccessError> {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeReadPhase::Active {
            return Err(NodeReadAccessError::Unavailable);
        }
        state.outcomes_released = false;
        state.output_admission = Observation::Entered;
        match catch_unwind(AssertUnwindSafe(|| {
            request.provider.clone().reserve_installed(bytes)
        })) {
            Ok(Ok(charge)) => {
                state.output_admission = Observation::Returned(Ok(()));
                Ok(charge)
            }
            Ok(Err(error)) => {
                state.output_admission = Observation::Returned(Err(error));
                state.phase = NodeReadPhase::Failed;
                Err(NodeReadAccessError::Reported)
            }
            Err(payload) => {
                state.output_admission = Observation::Panicked(payload);
                state.phase = NodeReadPhase::Failed;
                request
                    .database
                    .owner()
                    .stopped
                    .store(true, Ordering::Release);
                Err(NodeReadAccessError::Reported)
            }
        }
    }
    fn read_current<T>(
        &self,
        read: impl FnOnce(&RetainedReadTransaction) -> Result<T, BoundedReadError>,
    ) -> Result<T, NodeReadAccessError> {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeReadPhase::Active {
            return Err(NodeReadAccessError::Unavailable);
        }
        state.outcomes_released = false;
        state.read_failure = Observation::Entered;
        let transaction = state.transaction.as_ref().expect("active read transaction");
        match catch_unwind(AssertUnwindSafe(|| read(transaction))) {
            Ok(Ok(value)) => {
                state.read_failure = Observation::Returned(Ok(()));
                Ok(value)
            }
            Ok(Err(error)) => {
                state.read_failure = Observation::Returned(Err(error));
                state.phase = NodeReadPhase::Failed;
                Err(NodeReadAccessError::Reported)
            }
            Err(payload) => {
                state.read_failure = Observation::Panicked(payload);
                state.phase = NodeReadPhase::Failed;
                request
                    .database
                    .owner()
                    .stopped
                    .store(true, Ordering::Release);
                Err(NodeReadAccessError::Reported)
            }
        }
    }
    pub fn catalog_bytes(
        &self,
        hash: [u8; 32],
        max_value_bytes: usize,
    ) -> Result<Option<AdmittedReadBytes>, NodeReadAccessError> {
        if max_value_bytes == 0 || max_value_bytes > crate::MAX_KEY_CATALOG_BYTES {
            return Err(NodeReadAccessError::InvalidInput);
        }
        let bound = crate::disk_memory::allocation::<u8>(
            u64::try_from(max_value_bytes).map_err(|_| NodeReadAccessError::InvalidInput)?,
        )
        .map_err(NodeReadAccessError::Admission)?;
        let charge = self.reserve_output(bound)?;
        self.read_current(|transaction| {
            transaction.get_bytes(crate::CATALOG, hash.as_slice(), max_value_bytes)
        })
        .map(|result| {
            result.map(|bytes| AdmittedReadBytes {
                bytes,
                _charge: Some(charge),
            })
        })
    }
    pub fn record_bytes(
        &self,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<AdmittedReadBytes>, NodeReadAccessError> {
        if key.is_empty()
            || key.len() > 4096
            || max_value_bytes == 0
            || max_value_bytes > crate::MAX_BATCH
        {
            return Err(NodeReadAccessError::InvalidInput);
        }
        // Core reserves the exact ciphertext allocation before copying it and
        // keeps that native lease inside AdmittedValue until these bytes drop.
        self.read_current(|transaction| transaction.get_bytes(crate::RECORDS, key, max_value_bytes))
            .map(|row| {
                row.map(|bytes| AdmittedReadBytes {
                    bytes,
                    _charge: None,
                })
            })
    }
    /// Ordinary construction through this actual Active registered reader.
    /// The report owns any provider/native failure before it can escape.
    pub(crate) fn prepare_point_read(
        &self,
        max_value_bytes: usize,
    ) -> Result<kasumi_kv::PreparedPointRead, NodeReadAccessError> {
        self.read_current(|transaction| transaction.prepare_point_read(max_value_bytes))
    }

    pub(crate) fn record_length_prepared(
        &self,
        key: &[u8],
        workspace: &mut kasumi_kv::PreparedPointRead,
    ) -> Result<Option<usize>, NodeReadAccessError> {
        if key.is_empty() || key.len() > 4096 {
            return Err(NodeReadAccessError::InvalidInput);
        }
        if self.is_protected_source() {
            return self.source_record_length_prepared(key, workspace);
        }
        self.read_current(|transaction| {
            transaction.point_length_prepared(crate::RECORDS, key, workspace)
        })
    }

    pub(crate) fn record_bytes_prepared<'workspace>(
        &self,
        key: &[u8],
        max_value_bytes: usize,
        workspace: &'workspace mut kasumi_kv::PreparedPointRead,
    ) -> Result<Option<&'workspace [u8]>, NodeReadAccessError> {
        if key.is_empty()
            || key.len() > 4096
            || max_value_bytes == 0
            || max_value_bytes > crate::MAX_BATCH
        {
            return Err(NodeReadAccessError::InvalidInput);
        }
        if self.is_protected_source() {
            return self.source_record_bytes_prepared(key, max_value_bytes, workspace);
        }
        self.read_current(|transaction| {
            transaction.get_bytes_prepared(crate::RECORDS, key, max_value_bytes, workspace)
        })
    }

    pub fn catalog_exists(&self, hash: [u8; 32]) -> Result<bool, NodeReadAccessError> {
        self.read_current(|transaction| transaction.key_exists(crate::CATALOG, hash.as_slice()))
    }
    pub fn record_prefix_exists(&self, prefix: &[u8]) -> Result<bool, NodeReadAccessError> {
        if prefix.is_empty() || prefix.len() > 4096 {
            return Err(NodeReadAccessError::InvalidInput);
        }
        self.read_current(|transaction| transaction.prefix_exists(crate::RECORDS, prefix))
    }
    pub fn next_record(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        max_value_bytes: usize,
    ) -> Result<Option<OwnedEncryptedRow>, NodeReadAccessError> {
        if prefix.is_empty()
            || prefix.len() > 4096
            || after.is_some_and(|key| !key.starts_with(prefix) || key.len() > 4096)
            || max_value_bytes == 0
            || max_value_bytes > crate::MAX_BATCH
        {
            return Err(NodeReadAccessError::InvalidInput);
        }
        // engine may return an 8192-byte stored key even for a short seek prefix.
        let key_bound =
            crate::disk_memory::allocation::<u8>(8192).map_err(NodeReadAccessError::Admission)?;
        let value_bound = crate::disk_memory::allocation::<u8>(
            u64::try_from(max_value_bytes).map_err(|_| NodeReadAccessError::InvalidInput)?,
        )
        .map_err(NodeReadAccessError::Admission)?;
        let bound = crate::disk_memory::add(key_bound, value_bound)
            .map_err(NodeReadAccessError::Admission)?;
        let charge = self.reserve_output(bound)?;
        self.read_current(|transaction| {
            transaction.next_bytes(crate::RECORDS, prefix, after, max_value_bytes)
        })
        .map(|result| {
            result.map(|row| OwnedEncryptedRow {
                key: row.key,
                value: row.value,
                _charge: charge,
            })
        })
    }
    pub fn finish(&self) -> NodeReadPhase {
        let request = self.registration.owner();
        loop {
            let mut state = request.state.lock();
            let phase = request.finish_observed(&mut state);
            if phase != NodeReadPhase::Active {
                return phase;
            }
            // An active reader can remain Active here only when another
            // opening operation briefly owns its state lock. Do not report a
            // failed catalog read before the same transaction gets its actual
            // close and disposal attempt. Release the reader lock so the
            // competing opening operation can finish before this retry.
            drop(state);
            std::thread::yield_now();
        }
    }
    pub fn retire(self) -> StorageCensusDisposition {
        let request = self.registration.owner();
        let mut clean_finished = false;
        if let Some(mut state) = request.state.try_lock() {
            if matches!(
                state.phase,
                NodeReadPhase::Queued | NodeReadPhase::ForkQueued
            ) {
                state.phase = NodeReadPhase::Cancelled;
            }
            // A recovered ordinary facade cannot acknowledge source exchange
            // or cleanup originals. Its private source owner has a separate gate.
            if state.source.is_none() {
                state.outcomes_released = true;
            }
            clean_finished = state.phase == NodeReadPhase::Finished && !state.has_failures();
        }
        let retry = clean_finished.then(|| (request.provider.clone(), self.registration.id()));
        let Self {
            registration,
            lease,
        } = self;
        drop(lease);
        let disposition = registration.retire();
        match retry {
            Some((provider, id)) => settle_finished_reader_retirement(&provider, id, disposition),
            None => disposition,
        }
    }
}

pub struct NodeReadReport<'a> {
    state: MutexGuard<'a, ReaderState>,
}
impl NodeReadReport<'_> {
    pub fn has_failures(&self) -> bool {
        self.state.has_failures()
    }
    pub fn phase(&self) -> NodeReadPhase {
        self.state.phase
    }
    pub fn begin(&self) -> TerminalObservation<'_, kasumi_kv::TransactionError> {
        match self.state.begin.borrow() {
            TerminalObservation::NotEntered => TerminalObservation::NotEntered,
            TerminalObservation::Entered => TerminalObservation::Entered,
            TerminalObservation::Returned(Ok(())) => TerminalObservation::Returned(Ok(())),
            TerminalObservation::Returned(Err(error)) => {
                TerminalObservation::Returned(Err(error.original()))
            }
            TerminalObservation::Panicked(payload) => TerminalObservation::Panicked(payload),
        }
    }
    /// The actual native acquisition outcome, distinct from local rejection or
    /// an absent transaction. Its original error remains at the same address.
    pub fn acquisition_failure(&self) -> Option<&kasumi_kv::ReadAcquisitionFailure> {
        match &self.state.begin {
            Observation::Returned(Err(ReadBeginFailure::Native(error))) => Some(error),
            _ => None,
        }
    }
    pub fn tables(&self) -> TerminalObservation<'_, NodeReadTablesError> {
        self.state.tables.borrow()
    }
    pub fn outer(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.state.outer.borrow()
    }
    pub fn read_failure(&self) -> TerminalObservation<'_, BoundedReadError> {
        self.state.read_failure.borrow()
    }
    pub fn body_panic(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.state.body_panic.borrow()
    }
    pub fn output_admission(&self) -> TerminalObservation<'_, io::Error> {
        self.state.output_admission.borrow()
    }
    pub fn finish_outer(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.state.finish_outer.borrow()
    }
    pub fn close(&self) -> Option<kasumi_kv::ReadCloseReport<'_>> {
        self.state
            .transaction
            .as_ref()
            .map(RetainedReadTransaction::report)
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;
    use crate::test_utils::{NODE_STORE_ID, TestDiskMemory, private_tempdir, retry_disk_registry};

    struct TemporarilyBusyReader {
        drives: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }
    impl StoragePayload for TemporarilyBusyReader {
        const KIND: StorageOwnerKind = StorageOwnerKind::Reader;

        fn drive(&self) -> bool {
            self.drives.fetch_add(1, Ordering::AcqRel) != 0
        }
    }
    impl Drop for TemporarilyBusyReader {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn routine_permission_never_acknowledges_recovered_unknown_after_its_state_transition() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("routine-permission-race.kv");
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let opening = RegisteredNodeOpening::prepare(
            &path,
            NODE_STORE_ID,
            disk,
            NodeOpeningMode::Create,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        let tables = opening.queue_node_tables().unwrap();
        assert_eq!(tables.run(), NodeWriterPhase::Finished);
        opening.publish_ready_after_tables(&tables).unwrap();
        assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
        let hash = [12u8; 32];
        {
            let state = opening.registration.owner().state.lock();
            let transaction = state.engine.database().unwrap().begin_write().unwrap();
            transaction
                .open_table(crate::CATALOG)
                .unwrap()
                .insert(hash.as_slice(), b"ciphertext".as_slice())
                .unwrap();
            transaction.commit().unwrap();
        }
        let reader = opening.queue_read().unwrap();
        assert_eq!(reader.begin(), NodeReadPhase::Active);
        assert!(matches!(
            reader.catalog_bytes(hash, 1),
            Err(NodeReadAccessError::Reported)
        ));
        let id = reader.id();
        let report = reader.admitted_report();
        let recovered = RegisteredNodeRead::retained(memory.clone(), id).unwrap();
        assert!(reader.try_acknowledge_routine());
        // The exact production split permits another existing facade to win
        // here. Its original payload must revoke routine retirement permission.
        let recovered = std::thread::spawn(move || {
            recovered.preserve_body_panic(Box::new(0xbad_u64));
            recovered
        })
        .join()
        .unwrap();
        assert_eq!(
            reader.retire_acknowledged(),
            StorageCensusDisposition::Retained
        );
        assert!(
            !recovered
                .registration
                .owner()
                .state
                .lock()
                .outcomes_released
        );
        drop(recovered);
        assert_eq!(
            memory.storage_census().drain_owner(id),
            StorageCensusDisposition::Retained
        );
        assert!(!report.try_routine_diagnostic());
        {
            let report = report.report();
            let TerminalObservation::Panicked(payload) = report.body_panic() else {
                panic!()
            };
            assert_eq!(payload.downcast_ref::<u64>(), Some(&0xbad));
        }
        // Explicit legacy acknowledgment is used only to clean up this test's
        // deliberately injected unknown. The routine path never performed it.
        assert_eq!(
            RegisteredNodeRead::retained(memory.clone(), id)
                .unwrap()
                .retire(),
            StorageCensusDisposition::Retired
        );
        assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
    }

    #[test]
    fn finished_reader_retries_a_transient_busy_census_owner() {
        let memory = TestDiskMemory::new(1 << 20, 1);
        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        let drives = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let registration = memory
            .storage_census()
            .register(provider.clone(), 0, || TemporarilyBusyReader {
                drives: drives.clone(),
                drops: drops.clone(),
            })
            .unwrap();
        let id = registration.id();
        let first = registration.retire();
        assert_eq!(first, StorageCensusDisposition::Retained);
        assert_eq!(memory.storage_census().snapshot().readers, 1);
        assert_eq!(
            settle_finished_reader_retirement(&provider, id, first),
            StorageCensusDisposition::Retired
        );
        assert_eq!(drives.load(Ordering::Acquire), 2);
        assert_eq!(drops.load(Ordering::Acquire), 1);
        assert_eq!(memory.storage_census().snapshot().readers, 0);
    }

    #[test]
    fn routine_failure_retires_after_a_facade_reconstitutes_during_last_drop() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("racing-routine-reader.kv");
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let opening = RegisteredNodeOpening::prepare(
            &path,
            NODE_STORE_ID,
            disk,
            NodeOpeningMode::Create,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        let tables = opening.queue_node_tables().unwrap();
        assert_eq!(tables.run(), NodeWriterPhase::Finished);
        opening.publish_ready_after_tables(&tables).unwrap();
        assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
        let hash = [7u8; 32];
        {
            let state = opening.registration.owner().state.lock();
            let transaction = state.engine.database().unwrap().begin_write().unwrap();
            transaction
                .open_table(crate::CATALOG)
                .unwrap()
                .insert(hash.as_slice(), b"ciphertext".as_slice())
                .unwrap();
            transaction.commit().unwrap();
        }

        let reader = opening.queue_read().unwrap();
        assert_eq!(reader.begin(), NodeReadPhase::Active);
        assert!(matches!(
            reader.catalog_bytes(hash, 1),
            Err(NodeReadAccessError::Reported)
        ));
        let id = reader.id();
        let held = reader.registration.clone();
        let state = held.owner().state.lock();
        let worker = std::thread::spawn(move || drop(reader));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while held.owner().facades.load(Ordering::Acquire) != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "reader drop did not start"
            );
            std::thread::yield_now();
        }
        // This exact registration and state guard still own the sole reader.
        // Nonblocking lookup may observe the dropping worker's metadata borrow.
        assert_eq!(held.id(), id);
        assert_eq!(memory.storage_census().snapshot().readers, 1);
        let later = loop {
            if let Some(later) = RegisteredNodeRead::retained(memory.clone(), id) {
                assert_eq!(later.id(), id);
                break later;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "reader recovery remained busy during last drop"
            );
            std::thread::yield_now();
        };
        drop(state);
        drop(held);
        worker.join().unwrap();
        assert_eq!(memory.storage_census().snapshot().readers, 1);
        drop(later);
        assert_eq!(memory.storage_census().snapshot().readers, 0);
        assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());
        assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
    }

    #[test]
    fn close_drains_only_its_released_routine_reader_after_opening_lock_contention() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("busy-opening-routine-reader.kv");
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let opening = RegisteredNodeOpening::prepare(
            &path,
            NODE_STORE_ID,
            disk,
            NodeOpeningMode::Create,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        let tables = opening.queue_node_tables().unwrap();
        assert_eq!(tables.run(), NodeWriterPhase::Finished);
        opening.publish_ready_after_tables(&tables).unwrap();
        assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
        let hash = [8u8; 32];
        {
            let state = opening.registration.owner().state.lock();
            let transaction = state.engine.database().unwrap().begin_write().unwrap();
            transaction
                .open_table(crate::CATALOG)
                .unwrap()
                .insert(hash.as_slice(), b"ciphertext".as_slice())
                .unwrap();
            transaction.commit().unwrap();
        }

        let reader = opening.queue_read().unwrap();
        assert_eq!(reader.begin(), NodeReadPhase::Active);
        assert!(matches!(
            reader.catalog_bytes(hash, 1),
            Err(NodeReadAccessError::Reported)
        ));
        let id = reader.id();
        let opening_state = opening.registration.owner().state.lock();
        std::thread::spawn(move || drop(reader)).join().unwrap();
        assert_eq!(memory.storage_census().snapshot().readers, 1);
        drop(opening_state);

        // A second opening on the same provider has its own released routine
        // reader. Closing the first opening must leave that exact child alone.
        let other_path = directory.path().join("unrelated-routine-reader.kv");
        let other_disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&other_path, memory.clone()))
                .unwrap();
        let other_opening = RegisteredNodeOpening::prepare(
            &other_path,
            uuid::Uuid::from_u128(2),
            other_disk,
            NodeOpeningMode::Create,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        assert_eq!(other_opening.open(), NodeOpeningPhase::Open);
        let other_tables = other_opening.queue_node_tables().unwrap();
        assert_eq!(other_tables.run(), NodeWriterPhase::Finished);
        other_opening
            .publish_ready_after_tables(&other_tables)
            .unwrap();
        assert_eq!(other_tables.retire(), StorageCensusDisposition::Retired);
        {
            let state = other_opening.registration.owner().state.lock();
            let transaction = state.engine.database().unwrap().begin_write().unwrap();
            transaction
                .open_table(crate::CATALOG)
                .unwrap()
                .insert(hash.as_slice(), b"ciphertext".as_slice())
                .unwrap();
            transaction.commit().unwrap();
        }
        let other_reader = other_opening.queue_read().unwrap();
        assert_eq!(other_reader.begin(), NodeReadPhase::Active);
        assert!(matches!(
            other_reader.catalog_bytes(hash, 1),
            Err(NodeReadAccessError::Reported)
        ));
        let other_id = other_reader.id();
        let other_opening_state = other_opening.registration.owner().state.lock();
        std::thread::spawn(move || drop(other_reader))
            .join()
            .unwrap();
        drop(other_opening_state);
        assert_eq!(memory.storage_census().snapshot().readers, 2);

        assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
        assert_eq!(memory.storage_census().snapshot().readers, 1);
        assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
        let unrelated = RegisteredNodeRead::retained(memory.clone(), other_id).unwrap();
        drop(unrelated);
        assert_eq!(memory.storage_census().snapshot().readers, 0);
        assert_eq!(
            other_opening.close().unwrap(),
            DatabaseOpenSettlement::Closed
        );
        assert_eq!(other_opening.retire(), StorageCensusDisposition::Retired);
    }

    #[test]
    fn close_postpass_drains_routine_reader_dropped_inside_first_close() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("drop-during-close-reader.kv");
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let opening = RegisteredNodeOpening::prepare(
            &path,
            NODE_STORE_ID,
            disk,
            NodeOpeningMode::Create,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        let tables = opening.queue_node_tables().unwrap();
        assert_eq!(tables.run(), NodeWriterPhase::Finished);
        opening.publish_ready_after_tables(&tables).unwrap();
        assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
        let hash = [9u8; 32];
        {
            let state = opening.registration.owner().state.lock();
            let transaction = state.engine.database().unwrap().begin_write().unwrap();
            transaction
                .open_table(crate::CATALOG)
                .unwrap()
                .insert(hash.as_slice(), b"ciphertext".as_slice())
                .unwrap();
            transaction.commit().unwrap();
        }
        let reader = opening.queue_read().unwrap();
        assert_eq!(reader.begin(), NodeReadPhase::Active);
        assert!(matches!(
            reader.catalog_bytes(hash, 1),
            Err(NodeReadAccessError::Reported)
        ));
        let id = reader.id();

        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(0);
        let (dropped_tx, dropped_rx) = std::sync::mpsc::sync_channel::<()>(0);
        let dropped_during_close = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_drop = dropped_during_close.clone();
        opening
            .registration
            .owner()
            .state
            .lock()
            .before_close_locked = Some(Box::new(move || {
            entered_tx.send(()).unwrap();
            if dropped_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok()
            {
                saw_drop.store(true, Ordering::Release);
            }
        }));
        let worker = std::thread::spawn(move || {
            entered_rx.recv().unwrap();
            drop(reader);
            dropped_tx.send(()).unwrap();
        });
        let settlement = opening.close().unwrap();
        worker.join().unwrap();
        assert!(dropped_during_close.load(Ordering::Acquire));
        assert_eq!(settlement, DatabaseOpenSettlement::Closed);
        assert_eq!(memory.storage_census().snapshot().readers, 0);
        assert!(RegisteredNodeRead::retained(memory.clone(), id).is_none());
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
    }

    #[test]
    fn routine_reader_dropped_during_close_retry_drains_on_next_close() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("drop-during-close-retry.kv");
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let opening = RegisteredNodeOpening::prepare(
            &path,
            NODE_STORE_ID,
            disk,
            NodeOpeningMode::Create,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        let tables = opening.queue_node_tables().unwrap();
        assert_eq!(tables.run(), NodeWriterPhase::Finished);
        opening.publish_ready_after_tables(&tables).unwrap();
        assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
        let hash = [10u8; 32];
        {
            let state = opening.registration.owner().state.lock();
            let transaction = state.engine.database().unwrap().begin_write().unwrap();
            transaction
                .open_table(crate::CATALOG)
                .unwrap()
                .insert(hash.as_slice(), b"ciphertext".as_slice())
                .unwrap();
            transaction.commit().unwrap();
        }
        let failed = opening.queue_read().unwrap();
        assert_eq!(failed.begin(), NodeReadPhase::Active);
        assert!(matches!(
            failed.catalog_bytes(hash, 1),
            Err(NodeReadAccessError::Reported)
        ));
        let failed_id = failed.id();
        let blocker = opening.queue_read().unwrap();
        assert_eq!(blocker.begin(), NodeReadPhase::Active);

        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(0);
        let (dropped_tx, dropped_rx) = std::sync::mpsc::sync_channel::<()>(0);
        let dropped_during_retry = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saw_drop = dropped_during_retry.clone();
        opening
            .registration
            .owner()
            .state
            .lock()
            .before_retry_close_locked = Some(Box::new(move || {
            entered_tx.send(()).unwrap();
            if dropped_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok()
            {
                saw_drop.store(true, Ordering::Release);
            }
        }));
        let worker = std::thread::spawn(move || {
            entered_rx.recv().unwrap();
            drop(failed);
            dropped_tx.send(()).unwrap();
        });
        let first = opening.close().unwrap();
        worker.join().unwrap();
        assert!(dropped_during_retry.load(Ordering::Acquire));
        assert_eq!(first, DatabaseOpenSettlement::WaitingForTransactions);
        assert_eq!(memory.storage_census().snapshot().readers, 2);

        assert_eq!(blocker.finish(), NodeReadPhase::Finished);
        assert_eq!(blocker.retire(), StorageCensusDisposition::Retired);
        assert_eq!(memory.storage_census().snapshot().readers, 1);
        assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
        assert_eq!(memory.storage_census().snapshot().readers, 0);
        assert!(RegisteredNodeRead::retained(memory.clone(), failed_id).is_none());
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
    }

    #[test]
    fn node_database_retirement_retry_drains_metadata_skipped_routine_child() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("metadata-skipped-reader.kv");
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let opening = RegisteredNodeOpening::prepare(
            &path,
            NODE_STORE_ID,
            disk,
            NodeOpeningMode::Create,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        let tables = opening.queue_node_tables().unwrap();
        assert_eq!(tables.run(), NodeWriterPhase::Finished);
        opening.publish_ready_after_tables(&tables).unwrap();
        assert_eq!(tables.retire(), StorageCensusDisposition::Retired);
        let hash = [11u8; 32];
        {
            let state = opening.registration.owner().state.lock();
            let transaction = state.engine.database().unwrap().begin_write().unwrap();
            transaction
                .open_table(crate::CATALOG)
                .unwrap()
                .insert(hash.as_slice(), b"ciphertext".as_slice())
                .unwrap();
            transaction.commit().unwrap();
        }
        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        let database = crate::node_database::NodeDatabase::new_registered_locator(
            provider,
            opening.id(),
            "reader metadata contention fixture",
        );
        let reader = database.queue_registered_read().unwrap();
        assert_eq!(reader.begin(), NodeReadPhase::Active);
        assert!(matches!(
            reader.catalog_bytes(hash, 1),
            Err(NodeReadAccessError::Reported)
        ));
        let reader_id = reader.id();
        let parent_id = database.registered_opening_id().unwrap();
        let first = memory
            .storage_census()
            .with_owner_metadata_held_for_test(reader_id, || {
                drop(reader);
                database.close()
            });
        assert!(first.is_err());
        assert_eq!(database.registered_opening_id(), Some(parent_id));
        assert_eq!(memory.storage_census().snapshot().readers, 1);
        assert_eq!(memory.storage_census().snapshot().databases, 1);

        database.close().unwrap();
        assert_eq!(memory.storage_census().snapshot().readers, 0);
        assert_eq!(memory.storage_census().snapshot().databases, 1);
        assert_eq!(
            opening.report().engine().settlement(),
            DatabaseOpenSettlement::Disposed
        );
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
        assert_eq!(memory.storage_census().snapshot().databases, 0);
        assert!(RegisteredNodeRead::retained(memory.clone(), reader_id).is_none());
    }

    struct PausedDisposedChild {
        parent: Option<StorageRegistration<DatabaseOwner>>,
        entered: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl StoragePayload for PausedDisposedChild {
        const KIND: StorageOwnerKind = StorageOwnerKind::Reader;
        fn drive(&self) -> bool {
            true
        }
    }
    impl Drop for PausedDisposedChild {
        fn drop(&mut self) {
            // The payload no longer keeps its parent Arc, but this child cell
            // and lease still exist. Pause before census post-effect metadata.
            drop(self.parent.take());
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
    }

    #[test]
    fn parent_shutdown_waits_for_disposed_child_cell_and_exact_lease() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("disposed-child-census.kv");
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let opening = RegisteredNodeOpening::prepare(
            &path,
            NODE_STORE_ID,
            disk,
            NodeOpeningMode::Create,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        let tables = opening.queue_node_tables().unwrap();
        assert_eq!(tables.run(), NodeWriterPhase::Finished);
        opening.publish_ready_after_tables(&tables).unwrap();
        assert_eq!(tables.retire(), StorageCensusDisposition::Retired);

        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        let parent_id = opening.id();
        let parent = opening.registration.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let child = memory
            .storage_census()
            .register_child(provider.clone(), 0, &opening.registration, || {
                PausedDisposedChild {
                    parent: Some(parent),
                    entered: entered_tx,
                    release: Mutex::new(release_rx),
                }
            })
            .unwrap();
        let child_id = child.id();
        let database = crate::node_database::NodeDatabase::new_registered_locator(
            provider.clone(),
            opening.id(),
            "disposed child census fixture",
        );
        let worker = std::thread::spawn(move || child.retire());
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let (first, child_disposition) =
            memory
                .storage_census()
                .with_owner_metadata_held_for_test(child_id, || {
                    release_tx.send(()).unwrap();
                    let child_disposition = worker.join().unwrap();
                    (database.close(), child_disposition)
                });
        assert_eq!(child_disposition, StorageCensusDisposition::Retained);
        assert!(
            first.is_err(),
            "parent completed while child census slot lived"
        );
        assert_eq!(database.registered_opening_id(), Some(parent_id));
        assert_eq!(memory.storage_census().snapshot().readers, 1);
        assert_eq!(memory.storage_census().snapshot().databases, 1);
        assert!(
            memory
                .storage_census()
                .retained::<PausedDisposedChild>(provider, child_id)
                .is_none()
        );

        database.close().unwrap();
        assert_eq!(memory.storage_census().snapshot().readers, 0);
        assert_eq!(memory.storage_census().snapshot().databases, 1);
        assert_eq!(
            opening.report().engine().settlement(),
            DatabaseOpenSettlement::Disposed
        );
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
        assert_eq!(memory.storage_census().snapshot().databases, 0);
    }
}

#[cfg(test)]
#[path = "read_fork_tests.rs"]
mod fork_tests;
