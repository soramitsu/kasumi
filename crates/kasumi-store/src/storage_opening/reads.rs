//! One installed read snapshot with admitted, owned byte results.
use super::*;
use kasumi_kv::{BoundedReadError, ReadCloseSettlement, RetainedReadTransaction};
use std::sync::atomic::AtomicUsize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeReadPhase {
    Queued,
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

struct ReaderState {
    phase: NodeReadPhase,
    transaction: Option<RetainedReadTransaction>,
    begin: Observation<kasumi_kv::TransactionError>,
    tables: Observation<NodeReadTablesError>,
    outer: Observation<std::convert::Infallible>,
    output_admission: Observation<io::Error>,
    read_failure: Observation<BoundedReadError>,
    body_panic: Observation<std::convert::Infallible>,
    finish_outer: Observation<std::convert::Infallible>,
    outcomes_released: bool,
    auto_retire_routine_failure: bool,
}
impl ReaderState {
    fn has_failures(&self) -> bool {
        observed_failure(self.begin.borrow())
            || observed_failure(self.tables.borrow())
            || observed_failure(self.outer.borrow())
            || observed_failure(self.output_admission.borrow())
            || observed_failure(self.read_failure.borrow())
            || observed_failure(self.body_panic.borrow())
            || observed_failure(self.finish_outer.borrow())
            || self.transaction.as_ref().is_some_and(|transaction| {
                let report = transaction.report();
                observed_failure(report.release()) || observed_failure(report.disposal())
            })
    }

    // Only these reported read failures are ordinary request/capacity denials.
    // An I/O failure, panic, or uncertain transaction disposal retains its
    // census owner for explicit diagnosis instead of disappearing on drop.
    fn recoverable_read_failure(&self) -> bool {
        if self.outcomes_released
            || observed_failure(self.body_panic.borrow())
            || !matches!(self.phase, NodeReadPhase::Failed | NodeReadPhase::Finished)
        {
            return false;
        }
        matches!(
            self.read_failure.borrow(),
            TerminalObservation::Returned(Err(BoundedReadError::BoundExceeded
                | BoundedReadError::Storage(kasumi_kv::StorageError::Core(
                    kasumi_kv::CoreError::CapacityDenied
                ))))
        ) || matches!(
            self.output_admission.borrow(),
            TerminalObservation::Returned(Err(error)) if error.kind() == io::ErrorKind::OutOfMemory
        )
    }
}

struct ReaderRequest {
    database: StorageRegistration<DatabaseOwner>,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    facades: AtomicUsize,
    state: Mutex<ReaderState>,
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
            state.begin =
                Observation::Returned(Err(kasumi_kv::StorageError::DatabaseClosed.into()));
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
                Observation::Returned(Err(error))
            }
        };
        drop(opening);
        if !state.begin.success() {
            return;
        }
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
        if state.phase == NodeReadPhase::Queued {
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
        matches!(phase, NodeReadPhase::Finished | NodeReadPhase::Cancelled)
            && (state.outcomes_released || !state.has_failures())
    }
}

struct ReadFacadeLease {
    registration: Option<StorageRegistration<ReaderRequest>>,
}
impl Drop for ReadFacadeLease {
    fn drop(&mut self) {
        let registration = self.registration.take().expect("read facade registration");
        let request = registration.owner();
        let previous = request.facades.fetch_sub(1, Ordering::AcqRel);
        debug_assert_ne!(previous, 0);
        // A dropped error facade releases its exact observed, routine failure
        // only after the last reader facade has finished inspecting the report.
        // Keep the retirement intent if a retained facade raced this drop and
        // held the census owner through the first drain attempt.
        // Unknown I/O and panics still retain their census cell and report.
        let retry = if previous == 1 {
            let mut state = request.state.lock();
            if state.recoverable_read_failure() {
                state.outcomes_released = true;
                state.auto_retire_routine_failure = true;
                request.finish_observed(&mut state);
            }
            if state.phase == NodeReadPhase::Retained {
                state.auto_retire_routine_failure = false;
            }
            if state.auto_retire_routine_failure {
                Some((
                    matches!(
                        state.phase,
                        NodeReadPhase::Finished | NodeReadPhase::Cancelled
                    ),
                    request.provider.clone(),
                    registration.id(),
                ))
            } else {
                None
            }
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
                if !state.auto_retire_routine_failure {
                    false
                } else {
                    let phase = request.finish_observed(&mut state);
                    if phase == NodeReadPhase::Retained {
                        state.auto_retire_routine_failure = false;
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
        let provider = opening.file.disk().memory().clone();
        drop(opening);
        let database = self.registration.clone();
        let registration = provider.storage_census().register_child(
            provider.clone(),
            0,
            &self.registration,
            || ReaderRequest {
                database,
                provider: provider.clone(),
                facades: AtomicUsize::new(1),
                state: Mutex::new(ReaderState {
                    phase: NodeReadPhase::Queued,
                    transaction: None,
                    begin: Observation::NotEntered,
                    tables: Observation::NotEntered,
                    outer: Observation::NotEntered,
                    output_admission: Observation::NotEntered,
                    read_failure: Observation::NotEntered,
                    body_panic: Observation::NotEntered,
                    finish_outer: Observation::NotEntered,
                    outcomes_released: false,
                    auto_retire_routine_failure: false,
                }),
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
        let mut state = self.registration.owner().state.lock();
        if matches!(state.body_panic, Observation::NotEntered) {
            state.body_panic = Observation::Panicked(payload);
            state.outcomes_released = false;
            state.auto_retire_routine_failure = false;
        }
    }

    /// Drop during an external unwind has no access to that payload. Mark
    /// the interrupted body so a clean native close cannot auto-retire it.
    pub(crate) fn mark_unwinding_body(&self) {
        let mut state = self.registration.owner().state.lock();
        if matches!(state.body_panic, Observation::NotEntered) {
            state.body_panic = Observation::Entered;
            state.outcomes_released = false;
            state.auto_retire_routine_failure = false;
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
    pub fn begin(&self) -> NodeReadPhase {
        let request = self.registration.owner();
        let mut state = request.state.lock();
        if state.phase != NodeReadPhase::Queued {
            return state.phase;
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
        state.phase
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
            if state.phase == NodeReadPhase::Queued {
                state.phase = NodeReadPhase::Cancelled;
            }
            state.outcomes_released = true;
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
        self.state.begin.borrow()
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
        let opening =
            RegisteredNodeOpening::prepare(&path, NODE_STORE_ID, disk, NodeOpeningMode::Create)
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
        let later = RegisteredNodeRead::retained(memory.clone(), id).unwrap();
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
        let opening =
            RegisteredNodeOpening::prepare(&path, NODE_STORE_ID, disk, NodeOpeningMode::Create)
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
        let opening =
            RegisteredNodeOpening::prepare(&path, NODE_STORE_ID, disk, NodeOpeningMode::Create)
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
        let opening =
            RegisteredNodeOpening::prepare(&path, NODE_STORE_ID, disk, NodeOpeningMode::Create)
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
        let opening =
            RegisteredNodeOpening::prepare(&path, NODE_STORE_ID, disk, NodeOpeningMode::Create)
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
        let database = crate::node_database::NodeDatabase::new_registered(
            opening,
            provider,
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
        let opening =
            RegisteredNodeOpening::prepare(&path, NODE_STORE_ID, disk, NodeOpeningMode::Create)
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
        let database = crate::node_database::NodeDatabase::new_registered(
            opening,
            provider.clone(),
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
        assert_eq!(memory.storage_census().snapshot().databases, 0);
    }
}
