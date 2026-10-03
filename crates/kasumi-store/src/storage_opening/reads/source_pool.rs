//! Registered protected-source custody. Only same-root prepared encrypted loans
//! may read its captured snapshot; ordinary Active/fork/output paths stay closed.
use super::*;
use crate::source_metadata::SourceMetadataPurpose;
use crate::source_metadata::{
    MetadataAttempt, MetadataPreparation, SourceMetadataAccount, SourceMetadataBankHold,
    SourceMetadataHistory, SourcePayloadGrant, SourceReportGrant, StoreSourceMetadataBank,
};
use crate::storage_census::{SourceCellClaim, SourceCensusExchange};
use kasumi_kv::SourceReadSettlement;
use kasumi_kv::{
    BoundSourceRead, NativeSourcePool, SourceReadCallError, SourceReadRights,
    SourceRightsSettlement,
};
use std::convert::Infallible;

mod source_history_abort;
pub use source_history_abort::{SourceHistoryAbort, SourceHistoryRefusal};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourcePoolPhase {
    Registered,
    Installing,
    Ready,
    Sealing,
    Finished,
    Retained,
}

#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceCompletionFault {
    AfterMetadataApplied,
    BeforeCensusFinal,
}

struct SourcePoolRequest {
    id: StorageOwnerId,
    database: StorageRegistration<DatabaseOwner>,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    facades: AtomicUsize,
    state: Mutex<SourcePoolState>,
}
struct SourcePoolState {
    phase: SourcePoolPhase,
    native: Option<NativeSourcePool>,
    rights: Option<SourceReadRights>,
    bank: Option<StoreSourceMetadataBank>,
    preparations: [MetadataPreparation; 3],
    claims: [Option<SourceCellClaim>; 2],
    rights_released: [bool; 2],
    right_cleanup: [MetadataAttempt<io::Error>; 2],
    lane_seal: MetadataAttempt<io::Error>,
    holds: [Option<SourceMetadataBankHold>; 2],
    pending: [PendingSourceReader; 2],
    install: MetadataAttempt<io::Error>,
    native_install: MetadataAttempt<SourceReadCallError>,
    seal: MetadataAttempt<io::Error>,
    native_retire: MetadataAttempt<SourceReadCallError>,
    native_dispose: MetadataAttempt<Infallible>,
    metadata_dispose: MetadataAttempt<Infallible>,
    lane_tokens: [Option<crate::DiskMemoryLease>; 2],
    bank_dispose: MetadataAttempt<Infallible>,
    outcomes_released: bool,
}
struct PendingSourceReader {
    account: Option<SourceMetadataAccount>,
    native: Option<BoundSourceRead>,
    native_queue: MetadataAttempt<SourceReadCallError>,
    native_close: MetadataAttempt<SourceReadCallError>,
    account_retire: MetadataAttempt<io::Error>,
    state: Option<ReaderState>,
    report: Option<AdmittedReadReport>,
    report_grant: Option<SourceReportGrant>,
    payload_grant: Option<SourcePayloadGrant>,
    construction: MetadataAttempt<io::Error>,
    disposal: MetadataAttempt<Infallible>,
}
impl PendingSourceReader {
    const fn new() -> Self {
        Self {
            account: None,
            native: None,
            native_queue: MetadataAttempt::new(),
            native_close: MetadataAttempt::new(),
            account_retire: MetadataAttempt::new(),
            state: None,
            report: None,
            report_grant: None,
            payload_grant: None,
            construction: MetadataAttempt::new(),
            disposal: MetadataAttempt::new(),
        }
    }
    fn empty(&self) -> bool {
        self.account.is_none()
            && self.native.is_none()
            && self.state.is_none()
            && self.report.is_none()
            && self.report_grant.is_none()
            && self.payload_grant.is_none()
            && self.construction.pending()
    }
}
impl SourcePoolState {
    fn new() -> Self {
        Self {
            phase: SourcePoolPhase::Registered,
            native: None,
            rights: None,
            bank: None,
            preparations: std::array::from_fn(|_| MetadataPreparation::new()),
            claims: [None, None],
            rights_released: [false; 2],
            right_cleanup: std::array::from_fn(|_| MetadataAttempt::new()),
            lane_seal: MetadataAttempt::new(),
            holds: [None, None],
            pending: std::array::from_fn(|_| PendingSourceReader::new()),
            install: MetadataAttempt::new(),
            native_install: MetadataAttempt::new(),
            seal: MetadataAttempt::new(),
            native_retire: MetadataAttempt::new(),
            native_dispose: MetadataAttempt::new(),
            metadata_dispose: MetadataAttempt::new(),
            lane_tokens: [None, None],
            bank_dispose: MetadataAttempt::new(),
            outcomes_released: false,
        }
    }
    fn has_failures(&self) -> bool {
        self.lane_seal.failed()
            || self.right_cleanup.iter().any(MetadataAttempt::failed)
            || self.install.failed()
            || self.native_install.failed()
            || self.seal.failed()
            || self.native_retire.failed()
            || self.native_dispose.failed()
            || self.metadata_dispose.failed()
            || self.bank_dispose.failed()
            || self.preparations.iter().any(MetadataPreparation::failed)
            || self.pending.iter().any(|p| {
                p.construction.failed()
                    || p.disposal.failed()
                    || p.native_queue.failed()
                    || p.native_close.failed()
                    || p.account_retire.failed()
            })
            || self.native.as_ref().is_some_and(|pool| {
                observed_failure(pool.installation())
                    || pool.protocol_error().is_some()
                    || observed_failure(pool.seal_barrier())
                    || observed_failure(pool.seal_progress())
                    || observed_failure(pool.sealing())
                    || observed_failure(pool.disposal())
            })
            || self.rights.as_ref().is_some_and(|rights| {
                let report = rights.report();
                observed_failure(report.preparation())
                    || observed_failure(report.disposal())
                    || observed_failure(report.retirement())
            })
    }
}

pub(super) struct SourceReaderState {
    // Cleared under observed disposal after the native/controller is positive;
    // otherwise a diagnostic must keep the actual registered pool recoverable.
    pool: Option<StorageRegistration<SourcePoolRequest>>,
    pool_id: StorageOwnerId,
    native: BoundSourceRead,
    metadata: Option<SourceMetadataAccount>,
    history: Option<SourceMetadataHistory>,
    exchange: Option<SourceCensusExchange>,
    replacement_hold: Option<SourceMetadataBankHold>,
    entry_mark: MetadataAttempt<io::Error>,
    committed_mark: MetadataAttempt<io::Error>,
    cancellation: MetadataAttempt<io::Error>,
    census_cancelled: bool,
    right: usize,
    preparation: MetadataAttempt<SourceReadCallError>,
    capture: MetadataAttempt<SourceReadCallError>,
    history_setup: MetadataAttempt<io::Error>,
    census_refused: bool,
    history_abort_native: MetadataAttempt<SourceReadCallError>,
    history_native_aborted: bool,
    history_abort_metadata: MetadataAttempt<io::Error>,
    history_metadata_aborted: bool,
    history_abort_disposal: MetadataAttempt<Infallible>,
    history_refusal: Option<SourceHistoryRefusal>,
    history_prepare: MetadataAttempt<SourceReadCallError>,
    history_commit: MetadataAttempt<SourceReadCallError>,
    local_completion: MetadataAttempt<io::Error>,
    native_entered: bool,
    native_committed: bool,
    census_native_committed: bool,
    locally_committed: bool,
    native_close: MetadataAttempt<SourceReadCallError>,
    native_dispose: MetadataAttempt<Infallible>,
    metadata_retire: MetadataAttempt<io::Error>,
    metadata_dispose: MetadataAttempt<Infallible>,
    pool_dispose: MetadataAttempt<Infallible>,
    closed: bool,
    #[cfg(any(test, feature = "test-utils"))]
    defer_completion: bool,
    #[cfg(any(test, feature = "test-utils"))]
    defer_committed_marker: bool,
    #[cfg(any(test, feature = "test-utils"))]
    history_commit_calls: usize,
    #[cfg(any(test, feature = "test-utils"))]
    completion_fault: Option<SourceCompletionFault>,
}
impl SourceReaderState {
    fn new(
        pool: StorageRegistration<SourcePoolRequest>,
        native: BoundSourceRead,
        metadata: SourceMetadataAccount,
    ) -> Self {
        let right = metadata.right_index();
        let pool_id = pool.id();
        Self {
            pool: Some(pool),
            pool_id,
            native,
            metadata: Some(metadata),
            history: None,
            exchange: None,
            replacement_hold: None,
            entry_mark: MetadataAttempt::new(),
            committed_mark: MetadataAttempt::new(),
            cancellation: MetadataAttempt::new(),
            census_cancelled: false,
            right,
            preparation: MetadataAttempt::new(),
            capture: MetadataAttempt::new(),
            history_setup: MetadataAttempt::new(),
            census_refused: false,
            history_abort_native: MetadataAttempt::new(),
            history_native_aborted: false,
            history_abort_metadata: MetadataAttempt::new(),
            history_metadata_aborted: false,
            history_abort_disposal: MetadataAttempt::new(),
            history_refusal: None,
            history_prepare: MetadataAttempt::new(),
            history_commit: MetadataAttempt::new(),
            local_completion: MetadataAttempt::new(),
            native_entered: false,
            native_committed: false,
            census_native_committed: false,
            locally_committed: false,
            native_close: MetadataAttempt::new(),
            native_dispose: MetadataAttempt::new(),
            metadata_retire: MetadataAttempt::new(),
            metadata_dispose: MetadataAttempt::new(),
            pool_dispose: MetadataAttempt::new(),
            closed: false,
            #[cfg(any(test, feature = "test-utils"))]
            defer_completion: false,
            #[cfg(any(test, feature = "test-utils"))]
            defer_committed_marker: false,
            #[cfg(any(test, feature = "test-utils"))]
            history_commit_calls: 0,
            #[cfg(any(test, feature = "test-utils"))]
            completion_fault: None,
        }
    }
    pub(super) fn has_failures(&self) -> bool {
        self.entry_mark.failed()
            || self.committed_mark.failed()
            || self.cancellation.failed()
            || self.preparation.failed()
            || self.capture.failed()
            || self.history_setup.failed()
            || self.history_abort_native.failed()
            || self.history_abort_metadata.failed()
            || self.history_abort_disposal.failed()
            || self.history_refusal.is_some()
            || self.history_prepare.failed()
            || self.history_commit.failed()
            || self.local_completion.failed()
            || self.native_close.failed()
            || self.native_dispose.failed()
            || self.metadata_retire.failed()
            || self.metadata_dispose.failed()
            || self.pool_dispose.failed()
            || self
                .history
                .as_ref()
                .is_some_and(|h| h.preparation().failed() || observed_failure(h.cleanup()))
            || observed_failure(self.native.account_installation())
            || observed_failure(self.native.account_release())
            || observed_failure(self.native.account_disposal())
            || observed_failure(self.native.account_retirement())
            || observed_failure(self.native.account_pending_disposal())
            || observed_failure(self.native.account_controller_disposal())
            || self
                .native
                .history_preparation()
                .is_some_and(observed_failure)
            || self.native.history_exchange().is_some_and(observed_failure)
            || self.native.history_disposal().is_some_and(observed_failure)
            || {
                let report = self.native.native_report();
                observed_failure(report.preparation())
                    || observed_failure(report.capture())
                    || observed_failure(report.cancellation())
                    || observed_failure(report.disposal())
                    || observed_failure(report.native_retirement())
            }
            || self.native.history_report().is_some_and(|report| {
                observed_failure(report.preparation())
                    || observed_failure(report.exchange())
                    || observed_failure(report.cancellation())
                    || observed_failure(report.disposal())
                    || observed_failure(report.native_retirement())
            })
    }
    fn advance_committed_marker(&mut self, provider: &Arc<dyn NodeDiskMemoryAdmission>) {
        if !self.native_committed || self.census_native_committed || self.committed_mark.failed() {
            return;
        }
        // Fixture scheduling only: native success is already retained above.
        // A later call still performs the actual census marker operation.
        #[cfg(any(test, feature = "test-utils"))]
        if self.defer_committed_marker {
            self.defer_committed_marker = false;
            return;
        }
        self.committed_mark.retry_success();
        self.committed_mark.run(|| {
            match self
                .exchange
                .as_ref()
                .ok_or(io::ErrorKind::InvalidInput)?
                .mark_native_committed(provider.storage_census())
            {
                Ok(()) => self.census_native_committed = true,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            Ok(())
        });
    }
    fn complete_history(&mut self, provider: &Arc<dyn NodeDiskMemoryAdmission>) -> bool {
        self.advance_committed_marker(provider);
        if self.locally_committed {
            return true;
        }
        if !self.native_committed || !self.census_native_committed || self.local_completion.failed()
        {
            return false;
        }
        #[cfg(any(test, feature = "test-utils"))]
        if self.defer_completion {
            self.defer_completion = false;
            return false;
        }
        let Some(pool) = self.pool.as_ref() else {
            return false;
        };
        let Some(mut pool_state) = pool.owner().state.try_lock() else {
            return false;
        };
        self.local_completion.retry_success();
        self.local_completion.run(|| {
            let exchange = self.exchange.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
            let claim = pool_state.claims[self.right]
                .as_mut()
                .ok_or(io::ErrorKind::InvalidInput)?;
            let Some(mut census) = provider
                .storage_census()
                .try_complete_source_exchange(exchange, claim)?
            else {
                return Ok(());
            };
            let Some(mut metadata) = self
                .history
                .as_mut()
                .ok_or(io::ErrorKind::InvalidInput)?
                .try_complete()?
            else {
                return Ok(());
            };
            // Every guard and every identity check precedes the first half.
            // The suffix is scalar/field moves only: no callbacks/destructors.
            metadata.apply();
            census.mark_metadata_applied();
            #[cfg(any(test, feature = "test-utils"))]
            if self.completion_fault == Some(SourceCompletionFault::AfterMetadataApplied) {
                std::panic::panic_any(self.completion_fault.take().unwrap());
            }
            census.apply_census();
            metadata.final_commit();
            #[cfg(any(test, feature = "test-utils"))]
            if self.completion_fault == Some(SourceCompletionFault::BeforeCensusFinal) {
                std::panic::panic_any(self.completion_fault.take().unwrap());
            }
            census.final_commit();
            self.locally_committed = true;
            Ok(())
        });
        self.locally_committed
    }
}

pub(super) fn finish_source_locked(
    request: &ReaderRequest,
    state: &mut ReaderState,
) -> NodeReadPhase {
    let source = state.source.as_mut().expect("typed source purpose");
    if source.closed {
        state.phase = NodeReadPhase::Finished;
        return state.phase;
    }
    // A native effect cannot be canceled or acknowledged while either local
    // metadata/census half is still pending. Complete it once before closing.
    if source.native_entered && !source.complete_history(&request.provider) {
        state.phase = if source.has_failures() {
            NodeReadPhase::Retained
        } else {
            NodeReadPhase::SourceHistory
        };
        return state.phase;
    }
    let Some(opening) = request.database.owner().state.try_lock() else {
        return state.phase;
    };
    let Some(database) = opening.engine.retained_database() else {
        state.phase = NodeReadPhase::Retained;
        return state.phase;
    };
    if !source.native.is_closed() {
        source.native_close.retry_success();
        source.native_close.run(|| source.native.close(database));
    }
    if !source.native.is_closed() {
        state.phase = if source.has_failures() {
            NodeReadPhase::Retained
        } else {
            NodeReadPhase::WaitingForGuards
        };
        return state.phase;
    }
    drop(opening);
    source.native_dispose.run(|| {
        source.native.dispose_account();
        Ok(())
    });
    if !source.native_dispose.succeeded()
        || !matches!(
            source.native.account_controller_disposal(),
            TerminalObservation::Returned(Ok(()))
        )
    {
        state.phase = NodeReadPhase::Retained;
        return state.phase;
    }
    // Before native entry, cancellation settles the whole source request.
    if !source.native_entered
        && let Some(exchange) = &mut source.exchange
    {
        source.cancellation.retry_success();
        source.cancellation.run(|| {
            match request
                .provider
                .storage_census()
                .cancel_source_exchange(exchange)
            {
                StorageCensusDisposition::Retired => source.census_cancelled = true,
                StorageCensusDisposition::Retained => {}
                StorageCensusDisposition::Stale => {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
            }
            Ok(())
        });
        if !source.census_cancelled {
            state.phase = if source.cancellation.failed() {
                NodeReadPhase::Retained
            } else {
                NodeReadPhase::WaitingForGuards
            };
            return state.phase;
        }
    }
    if let Some(history) = &mut source.history {
        history.dispose();
        if !history.disposed() {
            state.phase = NodeReadPhase::Retained;
            return state.phase;
        }
    }
    source.metadata_retire.run(|| {
        source
            .metadata
            .as_ref()
            .ok_or(io::ErrorKind::InvalidInput)?
            .allow_retirement()
    });
    if !source.metadata_retire.succeeded() {
        state.phase = NodeReadPhase::Retained;
        return state.phase;
    }
    source.metadata_dispose.run(|| {
        drop(source.metadata.take());
        Ok(())
    });
    if !source.metadata_dispose.succeeded() {
        state.phase = NodeReadPhase::Retained;
        return state.phase;
    }
    source.pool_dispose.run(|| {
        drop(source.pool.take());
        Ok(())
    });
    if !source.pool_dispose.succeeded() {
        state.phase = NodeReadPhase::Retained;
        return state.phase;
    }
    source.closed = true;
    state.phase = NodeReadPhase::Finished;
    state.phase
}

impl SourcePoolRequest {
    fn install(&self, id: StorageOwnerId) {
        let mut state = self.state.lock();
        if state.phase != SourcePoolPhase::Registered {
            return;
        }
        state.phase = SourcePoolPhase::Installing;
        let SourcePoolState {
            install,
            preparations,
            bank,
            holds,
            claims,
            ..
        } = &mut *state;
        install.run(|| {
            let requests = StoreSourceMetadataBank::requests()?;
            for (index, preparation) in preparations.iter_mut().enumerate() {
                preparation.acquire(
                    &self.provider,
                    if index == 0 {
                        SourceMetadataPurpose::Fixed
                    } else {
                        SourceMetadataPurpose::PublicationLane
                    },
                    requests[index],
                );
                if !preparation.ready() {
                    return Ok(());
                }
            }
            *bank = StoreSourceMetadataBank::install(&self.provider, id, preparations)?;
            let bank = bank.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
            for index in 0..2 {
                holds[index] = Some(bank.hold());
                claims[index] = Some(self.provider.storage_census().claim_source_right(
                    &self.provider,
                    self.database.id(),
                    id,
                    index,
                    &mut holds[index],
                )?);
            }
            Ok(())
        });
        if !state.install.succeeded()
            || state.bank.is_none()
            || state.claims.iter().any(Option::is_none)
        {
            state.phase = SourcePoolPhase::Retained;
            return;
        }
        let opening = self.database.owner().state.lock();
        if self.database.owner().stopped.load(Ordering::Acquire)
            || opening.phase != NodeOpeningPhase::Open
        {
            state.phase = SourcePoolPhase::Sealing;
            return;
        }
        let Some(database) = opening.engine.retained_database() else {
            state.phase = SourcePoolPhase::Retained;
            return;
        };
        let Some(actual) = database.database() else {
            state.phase = SourcePoolPhase::Retained;
            return;
        };
        let provider: Arc<dyn kasumi_kv::SourceMemoryProvider> = self.provider.clone();
        state.native = Some(actual.queue_native_source_pool(provider));
        state.rights = Some(actual.queue_source_read_rights());
        let SourcePoolState {
            native_install,
            native,
            rights,
            ..
        } = &mut *state;
        native_install.run(|| {
            let native = native.as_mut().expect("owned native pool");
            native.install(database)?;
            if native.is_ready() {
                rights.as_mut().unwrap().prepare_funded(database, native)?;
            }
            Ok(())
        });
        state.phase = if state.native_install.succeeded()
            && state
                .native
                .as_ref()
                .is_some_and(NativeSourcePool::is_ready)
            && state
                .rights
                .as_ref()
                .is_some_and(|r| r.report().settlement() == SourceRightsSettlement::Ready)
        {
            SourcePoolPhase::Ready
        } else {
            SourcePoolPhase::Retained
        };
    }
}

struct RegisteredSourcePool {
    registration: StorageRegistration<SourcePoolRequest>,
    released: AtomicBool,
}
impl RegisteredSourcePool {
    fn queue(&self, right: usize) -> io::Result<RegisteredNodeRead> {
        self.queue_inner(right, false)
    }
    // The held guard is a fixture-only schedule. Production always executes
    // the same real registration without injecting metadata contention.
    fn queue_inner(
        &self,
        right: usize,
        hold_registration_census: bool,
    ) -> io::Result<RegisteredNodeRead> {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if right >= 2
            || state.phase != SourcePoolPhase::Ready
            || request.database.owner().stopped.load(Ordering::Acquire)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if !state.pending[right].empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let SourcePoolState {
            pending,
            claims,
            bank,
            native,
            ..
        } = &mut *state;
        let pending = &mut pending[right];
        let claim = claims[right].as_mut().ok_or(io::ErrorKind::InvalidInput)?;
        request
            .provider
            .storage_census()
            .refresh_source_right(claim)?;
        let bank = bank.as_ref().ok_or(io::ErrorKind::InvalidInput)?;
        let mut produced = None;
        pending.construction.run(|| {
            pending.account = Some(bank.checkout(right)?);
            let account = pending.account.as_ref().unwrap();
            pending.report_grant = Some(account.report_grant()?);
            pending.payload_grant = Some(account.payload_grant()?);
            let opening = request.database.owner().state.lock();
            let Some(database) = opening.engine.database() else {
                return Err(io::ErrorKind::BrokenPipe.into());
            };
            pending.native_queue.run(|| {
                pending.native = Some(native.as_ref().unwrap().queue_read(database)?);
                Ok(())
            });
            drop(opening);
            if !pending.native_queue.succeeded() {
                return Ok(());
            }
            pending.state = Some(ReaderState {
                phase: NodeReadPhase::SourceQueued,
                transaction: None,
                source: Some(SourceReaderState::new(
                    self.registration.clone(),
                    pending.native.take().unwrap(),
                    pending.account.take().unwrap(),
                )),
                begin: Observation::NotEntered,
                tables: Observation::NotEntered,
                outer: Observation::NotEntered,
                output_admission: Observation::NotEntered,
                read_failure: Observation::NotEntered,
                body_panic: Observation::NotEntered,
                finish_outer: Observation::NotEntered,
                outcomes_released: false,
            });
            pending.report = Some(AdmittedReadReport::new_source(
                &request.provider,
                &mut pending.report_grant,
                &mut pending.state,
            )?);
            let report = pending.report.as_ref().unwrap();
            let census = request.provider.storage_census();
            let claim_id = claim.id();
            let mut register = || {
                census.register_source_child(
                    request.provider.clone(),
                    claim,
                    &mut pending.payload_grant,
                    || ReaderRequest {
                        database: request.database.clone(),
                        provider: request.provider.clone(),
                        facades: AtomicUsize::new(0),
                        auto_retire_routine_failure: AtomicBool::new(false),
                        state: report.clone(),
                    },
                )
            };
            #[cfg(any(test, feature = "test-utils"))]
            let registered = if hold_registration_census {
                census.with_owner_metadata_held_for_test(claim_id, register)
            } else {
                register()
            };
            #[cfg(not(any(test, feature = "test-utils")))]
            let registered = {
                let _ = (hold_registration_census, claim_id);
                register()
            };
            produced = Some(registered?);
            Ok(())
        });
        let Some(registration) = produced else {
            // Actual originals/partial owners remain inside the registered pool.
            // This inline marker never wraps or replaces those observations.
            return Err(io::ErrorKind::Other.into());
        };
        // The actual ReaderRequest now owns the report. This is nonfinal alias
        // release only; successful construction left all other pending fields empty.
        pending.report.take();
        *pending = PendingSourceReader::new();
        registration.owner().facades.fetch_add(1, Ordering::AcqRel);
        let lease = ReadFacadeLease {
            registration: Some(registration.clone()),
        };
        Ok(RegisteredNodeRead {
            registration,
            lease,
        })
    }
    fn install(&self) {
        self.registration.owner().install(self.registration.id());
    }
}
impl Drop for RegisteredSourcePool {
    fn drop(&mut self) {
        let request = self.registration.owner();
        if !self.released.swap(true, Ordering::AcqRel) {
            request.facades.fetch_sub(1, Ordering::AcqRel);
        }
        // Census owns the real request. A busy close remains discoverable.
        let _ = request
            .provider
            .storage_census()
            .drain_owner(self.registration.id());
    }
}

impl RegisteredNodeRead {
    fn source_prepare(&self) {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeReadPhase::SourceQueued {
            return;
        }
        state.phase = NodeReadPhase::SourcePreparing;
        let ReaderState { source, phase, .. } = &mut *state;
        let source = source.as_mut().unwrap();
        let pool = source.pool.as_ref().unwrap().owner();
        let pool_state = pool.state.lock();
        let opening = request.database.owner().state.lock();
        let Some(database) = opening.engine.retained_database() else {
            *phase = NodeReadPhase::Retained;
            return;
        };
        if pool_state.phase != SourcePoolPhase::Ready
            || request.database.owner().stopped.load(Ordering::Acquire)
        {
            *phase = NodeReadPhase::Failed;
            return;
        }
        source.preparation.run(|| {
            source
                .native
                .prepare(database, pool_state.rights.as_ref().unwrap())
        });
        let prepared = source.preparation.succeeded()
            && source.native.native_report().settlement() == SourceReadSettlement::Prepared;
        drop(opening);
        drop(pool_state);
        *phase = if prepared {
            NodeReadPhase::SourcePrepared
        } else {
            NodeReadPhase::Failed
        };
    }
    fn source_capture(&self) {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeReadPhase::SourcePrepared {
            return;
        }
        state.phase = NodeReadPhase::SourceCapturing;
        let source = state.source.as_mut().unwrap();
        let opening = request.database.owner().state.lock();
        let Some(database) = opening.engine.retained_database() else {
            state.phase = NodeReadPhase::Retained;
            return;
        };
        source.capture.run(|| source.native.capture(database));
        state.phase = if source.capture.succeeded() && source.native.selected_generation().is_some()
        {
            NodeReadPhase::SourceCaptured
        } else {
            NodeReadPhase::Failed
        };
    }
    pub(crate) fn source_history_complete(&self) -> bool {
        let state = self.registration.owner().state.lock();
        !state.has_failures()
            && state.phase == NodeReadPhase::SourceHistory
            && state.source.as_ref().is_some_and(|source| {
                source.native_committed
                    && source.census_native_committed
                    && source.locally_committed
            })
    }

    pub(crate) fn source_prepare_history(&self) {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeReadPhase::SourceCaptured {
            return;
        }
        state.phase = NodeReadPhase::SourceHistory;
        let source = state.source.as_mut().unwrap();
        source.history_setup.run(|| {
            let pool = source
                .pool
                .as_ref()
                .ok_or(io::ErrorKind::InvalidInput)?
                .owner();
            let pool_state = pool.state.lock();
            let claim = pool_state.claims[source.right]
                .as_ref()
                .ok_or(io::ErrorKind::InvalidInput)?;
            source.replacement_hold = Some(
                pool_state
                    .bank
                    .as_ref()
                    .ok_or(io::ErrorKind::InvalidInput)?
                    .hold(),
            );
            source.exchange = Some(
                match request.provider.storage_census().begin_source_exchange(
                    &request.provider,
                    claim,
                    &mut source.replacement_hold,
                ) {
                    Ok(exchange) => exchange,
                    Err(error) => {
                        // This exact producer returns WouldBlock only before any
                        // replacement is installed. Preserve its original result.
                        source.census_refused = error.kind() == io::ErrorKind::WouldBlock;
                        return Err(error);
                    }
                },
            );
            source.history = Some(source.metadata.as_ref().unwrap().history()?);
            drop(pool_state);
            source.history.as_mut().unwrap().prepare();
            Ok(())
        });
        if !source.history_setup.succeeded()
            || !source
                .history
                .as_ref()
                .is_some_and(SourceMetadataHistory::ready)
        {
            return;
        }
        let opening = request.database.owner().state.lock();
        let Some(database) = opening.engine.retained_database() else {
            return;
        };
        source
            .history_prepare
            .run(|| source.native.prepare_history(database));
    }
    pub(crate) fn source_commit_history(&self) {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeReadPhase::SourceHistory {
            return;
        }
        let source = state.source.as_mut().unwrap();
        if source.native_entered {
            source.complete_history(&request.provider);
            return;
        }
        if !source.history_prepare.succeeded()
            || !source
                .history
                .as_ref()
                .is_some_and(SourceMetadataHistory::ready)
            || !source
                .native
                .history_report()
                .is_some_and(|r| r.settlement() == kasumi_kv::SourceHistorySettlement::Prepared)
        {
            return;
        }
        // Actual opening capability is acquired before the native/bank suffix.
        let opening = request.database.owner().state.lock();
        let Some(database) = opening.engine.retained_database() else {
            return;
        };
        let mut entered = false;
        source.entry_mark.retry_success();
        source.entry_mark.run(|| {
            match source
                .exchange
                .as_ref()
                .ok_or(io::ErrorKind::InvalidInput)?
                .mark_native_entered(request.provider.storage_census())
            {
                Ok(()) => entered = true,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            Ok(())
        });
        if !entered {
            return;
        }
        source.native_entered = true;
        source.history_commit.run(|| {
            #[cfg(any(test, feature = "test-utils"))]
            {
                source.history_commit_calls += 1;
            }
            source.native.commit_history(database)
        });
        source.native_committed = source.history_commit.succeeded()
            && source
                .native
                .history_exchange()
                .is_some_and(|o| matches!(o, TerminalObservation::Returned(Ok(()))))
            && source
                .native
                .history_report()
                .is_some_and(|r| r.exchange_committed());
        drop(opening);
        if !source.native_committed {
            return;
        }
        source.complete_history(&request.provider);
    }
}

impl StoragePayload for SourcePoolRequest {
    const KIND: StorageOwnerKind = StorageOwnerKind::SourcePool;
    fn drive(&self) -> bool {
        if self.facades.load(Ordering::Acquire) != 0
            && !self.database.owner().stopped.load(Ordering::Acquire)
        {
            return false;
        }
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        if state.phase == SourcePoolPhase::Finished {
            return state.outcomes_released || !state.has_failures();
        }
        state.phase = SourcePoolPhase::Sealing;
        let SourcePoolState { bank, seal, .. } = &mut *state;
        seal.run(|| {
            if let Some(bank) = bank {
                bank.begin_seal()?;
            }
            Ok(())
        });
        if !state.seal.succeeded() {
            return false;
        }
        // Never drive a registered reader while holding this pool mutex. Scan
        // uses exact census children after dropping this guard, below.
        drop(state);
        for index in 0..self.provider.storage_census().capacity() {
            let Some(id) = self.provider.storage_census().owner_at(index) else {
                continue;
            };
            let Some(reader) = self
                .provider
                .storage_census()
                .retained::<ReaderRequest>(self.provider.clone(), id)
            else {
                continue;
            };
            if reader.owner().database.id() != self.database.id() {
                continue;
            }
            let ours = reader.owner().state.try_lock().is_some_and(|state| {
                state
                    .source
                    .as_ref()
                    .is_some_and(|source| self.id == source.pool_id)
            });
            if ours {
                // Exchange fences deliberately block generic census dispatch.
                // Recover the exact source request first, outside those guards.
                let _ = reader.owner().drive();
                let _ = reader.retire();
            }
        }
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        // A pre-registration partial queue is also real control-owned custody.
        // Report aliases are inspected/driven without holding the pool lock.
        for index in 0..2 {
            let report = state.pending[index].report.clone();
            if let Some(report) = report {
                drop(state);
                let stack_request = ReaderRequest {
                    database: self.database.clone(),
                    provider: self.provider.clone(),
                    facades: AtomicUsize::new(0),
                    auto_retire_routine_failure: AtomicBool::new(false),
                    state: report.clone(),
                };
                {
                    let Some(mut reader) = report.try_lock() else {
                        return false;
                    };
                    stack_request.finish_observed(&mut reader);
                }
                drop(stack_request);
                drop(report);
                let Some(next) = self.state.try_lock() else {
                    return false;
                };
                state = next;
            }
            let pending = &mut state.pending[index];
            if pending.empty() {
                continue;
            }
            // A state not yet allocated into a report has the same native
            // cleanup, using only a stack request and its retained real fields.
            if let Some(reader) = &mut pending.state {
                let Some(source) = reader.source.as_mut() else {
                    return false;
                };
                let Some(opening) = self.database.owner().state.try_lock() else {
                    return false;
                };
                let Some(database) = opening.engine.retained_database() else {
                    return false;
                };
                source.native_close.retry_success();
                source.native_close.run(|| source.native.close(database));
                if !source.native.is_closed() {
                    return false;
                }
                drop(opening);
                source.native_dispose.run(|| {
                    source.native.dispose_account();
                    Ok(())
                });
                if !matches!(
                    source.native.account_controller_disposal(),
                    TerminalObservation::Returned(Ok(()))
                ) {
                    return false;
                }
                source
                    .metadata_retire
                    .run(|| source.metadata.as_ref().unwrap().allow_retirement());
                if !source.metadata_retire.succeeded() {
                    return false;
                }
            }
            if let Some(native) = &mut pending.native {
                let Some(opening) = self.database.owner().state.try_lock() else {
                    return false;
                };
                let Some(database) = opening.engine.retained_database() else {
                    return false;
                };
                pending.native_close.retry_success();
                pending.native_close.run(|| native.close(database));
                if !native.is_closed() {
                    return false;
                }
                drop(opening);
                native.dispose_account();
                if !matches!(
                    native.account_controller_disposal(),
                    TerminalObservation::Returned(Ok(()))
                ) {
                    return false;
                }
            }
            if let Some(account) = &pending.account {
                pending.account_retire.run(|| account.allow_retirement());
                if !pending.account_retire.succeeded() {
                    return false;
                }
            }
            if let Some(report) = &pending.report {
                let Some(reader) = report.try_lock() else {
                    return false;
                };
                if reader.phase != NodeReadPhase::Finished {
                    return false;
                }
            }
            pending.disposal.run(|| {
                drop(pending.report.take());
                drop(pending.state.take());
                drop(pending.native.take());
                drop(pending.report_grant.take());
                drop(pending.payload_grant.take());
                drop(pending.account.take());
                Ok(())
            });
            if !pending.disposal.succeeded() {
                return false;
            }
        }
        // Returning a physical protected right waits for its actual metadata
        // account/token tails. A historical report uses its independent grant.
        for index in 0..2 {
            let SourcePoolState {
                claims,
                rights_released,
                right_cleanup,
                ..
            } = &mut *state;
            if rights_released[index] || claims[index].is_none() {
                continue;
            }
            let claim = claims[index].as_mut().unwrap();
            right_cleanup[index].retry_success();
            right_cleanup[index].run(|| {
                match self.provider.storage_census().refresh_source_right(claim) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(error) => return Err(error),
                }
                match self.provider.storage_census().release_source_right(claim) {
                    StorageCensusDisposition::Retired => rights_released[index] = true,
                    StorageCensusDisposition::Retained => {}
                    StorageCensusDisposition::Stale => {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                }
                Ok(())
            });
            if !rights_released[index] {
                return false;
            }
        }
        let SourcePoolState {
            preparations,
            holds,
            metadata_dispose,
            ..
        } = &mut *state;
        for preparation in preparations {
            preparation.dispose();
            if !preparation.disposed() {
                return false;
            }
        }
        metadata_dispose.run(|| {
            for hold in holds {
                drop(hold.take());
            }
            Ok(())
        });
        if !metadata_dispose.succeeded() {
            return false;
        }
        let SourcePoolState {
            bank,
            lane_tokens,
            lane_seal,
            ..
        } = &mut *state;
        let mut lanes_moved = bank.is_none();
        lane_seal.retry_success();
        lane_seal.run(|| {
            if let Some(bank) = bank {
                lanes_moved = bank.take_sealed_lanes(lane_tokens)?;
            }
            Ok(())
        });
        if !lane_seal.succeeded() || !lanes_moved {
            return false;
        }
        let Some(opening) = self.database.owner().state.try_lock() else {
            return false;
        };
        let Some(database) = opening.engine.retained_database() else {
            return false;
        };
        let SourcePoolState {
            rights,
            native_retire,
            ..
        } = &mut *state;
        if let Some(rights) = rights {
            native_retire.retry_success();
            native_retire.run(|| {
                rights.retire(database)?;
                Ok(())
            });
            if rights.report().settlement() != SourceRightsSettlement::Disposed {
                return false;
            }
        }
        drop(opening);
        let SourcePoolState {
            native,
            native_dispose,
            ..
        } = &mut *state;
        native_dispose.retry_success();
        let mut native_finished = native.is_none();
        native_dispose.run(|| {
            if let Some(native) = native {
                if observed_failure(native.installation()) && !native.is_ready() {
                    // The native owner itself decides whether no backend was
                    // bound. A rejected unbound disposal falls through to seal.
                    if native.dispose_unbound().is_ok() {
                        native_finished =
                            matches!(native.disposal(), TerminalObservation::Returned(Ok(())));
                    }
                }
                if !native_finished {
                    native.seal();
                    native.dispose_sealed();
                    native_finished =
                        matches!(native.disposal(), TerminalObservation::Returned(Ok(())));
                }
            }
            Ok(())
        });
        if !state.native_dispose.succeeded() || !native_finished {
            return false;
        }
        let SourcePoolState {
            bank,
            lane_tokens,
            bank_dispose,
            ..
        } = &mut *state;
        bank_dispose.run(|| {
            // These concrete token destructors run with no census/bank/account
            // guard. The control report keeps every first unwind observation.
            for token in lane_tokens {
                drop(token.take());
            }
            drop(bank.take());
            Ok(())
        });
        if !state.bank_dispose.succeeded() {
            return false;
        }
        state.phase = SourcePoolPhase::Finished;
        state.outcomes_released || !state.has_failures()
    }
}

pub(in crate::storage_opening) fn drain_source_owners(
    provider: &Arc<dyn NodeDiskMemoryAdmission>,
    opening_id: StorageOwnerId,
) {
    let census = provider.storage_census();
    let closing = census
        .retained::<DatabaseOwner>(provider.clone(), opening_id)
        .is_some_and(|database| database.owner().stopped.load(Ordering::Acquire));
    for index in 0..census.capacity() {
        let Some(id) = census.owner_at(index) else {
            continue;
        };
        if census.source_control_parent(id) == Some(opening_id) {
            if closing {
                let _ = census.cancel_source_control(id);
            }
            let _ = census.drain_owner(id);
            continue;
        }
        if let Some(pool) = census.retained::<SourcePoolRequest>(provider.clone(), id) {
            if pool.owner().database.id() == opening_id {
                let _ = pool.retire();
            }
            continue;
        }
        if let Some(reader) = census.retained::<ReaderRequest>(provider.clone(), id) {
            if reader.owner().database.id() != opening_id {
                continue;
            }
            let source = reader
                .owner()
                .state
                .try_lock()
                .is_some_and(|state| state.source.is_some());
            if source {
                let _ = reader.owner().drive();
                let _ = reader.retire();
            }
        }
    }
    census.drain_disposed_children(opening_id);
}

// The fixture adds test observations to the same production capacity owner.
// SourceRoots activation still requires its own accepted-shape construction.
#[cfg(any(test, feature = "test-utils"))]
pub struct RegisteredSourceFundingFixture {
    reads: [Option<RegisteredNodeRead>; 3],
    capacity: RegisteredSourceCapacity,
}
#[cfg(any(test, feature = "test-utils"))]
impl RegisteredNodeOpening {
    pub fn with_source_control_observation_fixture<R>(
        &self,
        id: StorageOwnerId,
        inspect: impl FnOnce(
            TerminalObservation<'_, io::Error>,
            Option<crate::SourceMetadataCallError>,
            TerminalObservation<'_, Infallible>,
        ) -> R,
    ) -> Option<R> {
        let provider = &self.registration.owner().provider;
        let census = provider.storage_census();
        if census.source_control_parent(id) != Some(self.registration.id()) {
            return None;
        }
        let report = census.source_control_observation(id)?;
        Some(inspect(
            report.original(),
            report.protocol(),
            report.cleanup(),
        ))
    }
    pub fn acknowledge_source_control_fixture(&self, id: StorageOwnerId) -> io::Result<()> {
        let census = self.registration.owner().provider.storage_census();
        if census.source_control_parent(id) != Some(self.registration.id()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        census.acknowledge_source_control(id)
    }
    pub fn queue_registered_source_funding_fixture(
        &self,
    ) -> io::Result<RegisteredSourceFundingFixture> {
        Ok(RegisteredSourceFundingFixture {
            reads: [None, None, None],
            capacity: self.queue_source_capacity()?,
        })
    }
}
#[cfg(any(test, feature = "test-utils"))]
impl RegisteredSourceFundingFixture {
    pub fn id(&self) -> StorageOwnerId {
        self.capacity.control_id
    }
    pub fn phase(&self) -> Option<SourcePoolPhase> {
        self.capacity
            .pool
            .as_ref()
            .map(|pool| pool.registration.owner().state.lock().phase)
    }
    pub fn with_control_observation<R>(
        &self,
        inspect: impl FnOnce(
            TerminalObservation<'_, io::Error>,
            Option<crate::SourceMetadataCallError>,
            TerminalObservation<'_, Infallible>,
        ) -> R,
    ) -> Option<R> {
        let report = self
            .capacity
            .provider
            .storage_census()
            .source_control_observation(self.capacity.control_id)?;
        Some(inspect(
            report.original(),
            report.protocol(),
            report.cleanup(),
        ))
    }
    pub fn install(&self) {
        if let Some(pool) = &self.capacity.pool {
            pool.install();
        }
    }
    pub fn queue(&mut self, slot: usize, right: usize) -> io::Result<()> {
        let target = self
            .reads
            .get_mut(slot)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if target.is_some() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        *target = Some(
            self.capacity
                .pool
                .as_ref()
                .ok_or(io::ErrorKind::InvalidInput)?
                .queue(right)?,
        );
        Ok(())
    }
    /// Force genuine census try_lock contention only after the actual report
    /// and grants exist. No synthetic error or successful result is injected.
    pub fn queue_with_registration_census_held(
        &mut self,
        slot: usize,
        right: usize,
    ) -> io::Result<()> {
        let target = self
            .reads
            .get_mut(slot)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if target.is_some() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        *target = Some(
            self.capacity
                .pool
                .as_ref()
                .ok_or(io::ErrorKind::InvalidInput)?
                .queue_inner(right, true)?,
        );
        Ok(())
    }
    /// Borrow exact partial-construction custody without exposing a grant or
    /// report owner. Flags are account/native/state/report/report-grant/payload.
    pub fn with_pending_queue_observation<R>(
        &self,
        right: usize,
        inspect: impl FnOnce(
            TerminalObservation<'_, io::Error>,
            TerminalObservation<'_, Infallible>,
            [bool; 6],
        ) -> R,
    ) -> Option<R> {
        let state = self
            .capacity
            .pool
            .as_ref()?
            .registration
            .owner()
            .state
            .lock();
        let pending = state.pending.get(right)?;
        Some(inspect(
            pending.construction.view(),
            pending.disposal.view(),
            [
                pending.account.is_some(),
                pending.native.is_some(),
                pending.state.is_some(),
                pending.report.is_some(),
                pending.report_grant.is_some(),
                pending.payload_grant.is_some(),
            ],
        ))
    }
    pub fn reader(&self, slot: usize) -> Option<&RegisteredNodeRead> {
        self.reads.get(slot)?.as_ref()
    }
    pub fn prepare(&self, slot: usize) {
        if let Some(reader) = self.reader(slot) {
            reader.source_prepare();
        }
    }
    pub fn capture(&self, slot: usize) {
        if let Some(reader) = self.reader(slot) {
            reader.source_capture();
        }
    }
    pub fn prepare_history(&self, slot: usize) {
        if let Some(reader) = self.reader(slot) {
            reader.source_prepare_history();
        }
    }
    pub fn commit_history(&self, slot: usize) {
        if let Some(reader) = self.reader(slot) {
            reader.source_commit_history();
        }
    }
    pub fn with_native_report<R>(
        &self,
        slot: usize,
        inspect: impl FnOnce(&BoundSourceRead) -> R,
    ) -> Option<R> {
        let state = self.reader(slot)?.registration.owner().state.lock();
        Some(inspect(&state.source.as_ref()?.native))
    }
    pub fn history_complete(&self, slot: usize) -> bool {
        self.reader(slot)
            .is_some_and(RegisteredNodeRead::source_history_complete)
    }
    pub fn close_read(&self, slot: usize) -> Option<NodeReadPhase> {
        let request = self.reader(slot)?.registration.owner();
        let mut state = request.state.lock();
        Some(request.finish_observed(&mut state))
    }
    pub fn acknowledge_read(&self, slot: usize) -> bool {
        let Some(reader) = self.reader(slot) else {
            return false;
        };
        let mut state = reader.registration.owner().state.lock();
        if !state.source.as_ref().is_some_and(|source| {
            source.closed && (!source.native_entered || source.locally_committed)
        }) {
            return false;
        }
        state.outcomes_released = true;
        true
    }
    pub fn release_read(&mut self, slot: usize) {
        if let Some(target) = self.reads.get_mut(slot) {
            drop(target.take());
        }
    }
    pub fn drain(&self) {
        drain_source_owners(&self.capacity.provider, self.capacity.database.id());
    }
    pub fn seal(&self) {
        if let Some(pool) = &self.capacity.pool {
            let request = pool.registration.owner();
            if !pool.released.swap(true, Ordering::AcqRel) {
                request.facades.fetch_sub(1, Ordering::AcqRel);
            }
            // The fixture relinquishes admission; its immutable facade remains
            // diagnostic only, and its Drop must not decrement again.
            let _ = request.drive();
        } else {
            let _ = self
                .capacity
                .provider
                .storage_census()
                .cancel_source_control(self.capacity.control_id);
        }
    }
    pub fn acknowledge_pool(&self) -> bool {
        let Some(pool) = &self.capacity.pool else {
            return self
                .capacity
                .provider
                .storage_census()
                .acknowledge_source_control(self.capacity.control_id)
                .is_ok();
        };
        let mut state = pool.registration.owner().state.lock();
        if state.phase != SourcePoolPhase::Finished {
            return false;
        }
        state.outcomes_released = true;
        true
    }
    pub fn memory_requests() -> io::Result<[u64; 4]> {
        let [fixed, first, second] = StoreSourceMetadataBank::requests()?;
        Ok([
            crate::StorageCensus::registration_request_bytes::<SourcePoolRequest>(0)?,
            fixed,
            first,
            second,
        ])
    }
    pub fn native_snapshot(&self) -> Option<kasumi_kv::SourceBankSnapshot> {
        self.capacity
            .pool
            .as_ref()?
            .registration
            .owner()
            .state
            .lock()
            .native
            .as_ref()?
            .snapshot()
    }
    pub fn retain_diagnostic(&self, slot: usize) -> Option<SourceReadDiagnostic> {
        Some(SourceReadDiagnostic {
            report: self.reader(slot)?.admitted_report(),
        })
    }
    /// Diagnostic addresses only, for actual allocator boundaries. No Arc,
    /// pointer dereference, mutable owner, or funding authority is exposed.
    pub fn allocation_addresses(&self, slot: usize) -> Option<[usize; 5]> {
        let pool = self.capacity.pool.as_ref()?;
        let reader = self.reader(slot)?.registration.owner();
        let state = reader.state.lock();
        let account = state
            .source
            .as_ref()?
            .metadata
            .as_ref()?
            .allocation_address();
        let bank = pool
            .registration
            .owner()
            .state
            .lock()
            .bank
            .as_ref()?
            .allocation_address();
        let [report, charge] = reader.state.allocation_addresses();
        Some([
            bank,
            account,
            report,
            charge,
            std::ptr::from_ref(pool.registration.owner()) as usize,
        ])
    }
    pub fn with_metadata_preparation<R>(
        &self,
        index: usize,
        inspect: impl FnOnce(
            TerminalObservation<'_, io::Error>,
            Option<crate::SourceMetadataCallError>,
        ) -> R,
    ) -> Option<R> {
        let state = self
            .capacity
            .pool
            .as_ref()?
            .registration
            .owner()
            .state
            .lock();
        let preparation = state.preparations.get(index)?;
        Some(inspect(preparation.original(), preparation.protocol()))
    }
    /// Pause before the local committed marker after actual native success.
    pub fn defer_next_committed_marker(&self, slot: usize) {
        if let Some(reader) = self.reader(slot) {
            reader
                .registration
                .owner()
                .state
                .lock()
                .source
                .as_mut()
                .unwrap()
                .defer_committed_marker = true;
        }
    }
    /// Actual native call count, positive native result, census marker, and
    /// final local completion. These fixed observations confer no authority.
    pub fn history_progress(&self, slot: usize) -> Option<(usize, bool, bool, bool)> {
        let state = self.reader(slot)?.registration.owner().state.lock();
        let source = state.source.as_ref()?;
        Some((
            source.history_commit_calls,
            source.native_committed,
            source.census_native_committed,
            source.locally_committed,
        ))
    }
    pub fn defer_next_local_completion(&self, slot: usize) {
        if let Some(reader) = self.reader(slot) {
            reader
                .registration
                .owner()
                .state
                .lock()
                .source
                .as_mut()
                .unwrap()
                .defer_completion = true;
        }
    }
    pub fn inject_completion_fault(&self, slot: usize, fault: SourceCompletionFault) {
        if let Some(reader) = self.reader(slot) {
            reader
                .registration
                .owner()
                .state
                .lock()
                .source
                .as_mut()
                .unwrap()
                .completion_fault = Some(fault);
        }
    }
    pub fn with_local_completion<R>(
        &self,
        slot: usize,
        inspect: impl FnOnce(TerminalObservation<'_, io::Error>) -> R,
    ) -> Option<R> {
        let state = self.reader(slot)?.registration.owner().state.lock();
        Some(inspect(state.source.as_ref()?.local_completion.view()))
    }
    pub fn with_reader_census_held<R>(&self, slot: usize, work: impl FnOnce() -> R) -> Option<R> {
        let id = self.reader(slot)?.id();
        Some(
            self.capacity
                .provider
                .storage_census()
                .with_owner_metadata_held_for_test(id, work),
        )
    }
    pub fn publish_generation(&self, tag: u8) -> anyhow::Result<()> {
        let opening = self.capacity.database.owner().state.lock();
        let database = opening
            .engine
            .database()
            .ok_or_else(|| anyhow::anyhow!("registered fixture database closed"))?;
        let write = database.begin_write()?;
        {
            let mut table = write.open_table(crate::CATALOG)?;
            table.insert([tag; 32].as_slice(), [tag; 8].as_slice())?;
        }
        write.commit()?;
        Ok(())
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub struct SourceReadDiagnostic {
    report: AdmittedReadReport,
}
#[cfg(any(test, feature = "test-utils"))]
impl SourceReadDiagnostic {
    pub fn phase(&self) -> NodeReadPhase {
        self.report.phase()
    }
    pub fn has_failures(&self) -> bool {
        self.report.report().has_failures()
    }
}

#[path = "source_points.rs"]
mod prepared_points;

#[path = "source_capacity.rs"]
mod capacity;
pub use capacity::{
    PreparedRegisteredSource, RegisteredSourceCapacity, SourceCapacityClose, SourceCapacityFailure,
    SourceCapacityReport, SourceCapacityRetirement,
};
