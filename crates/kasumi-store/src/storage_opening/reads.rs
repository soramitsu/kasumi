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
    bytes: Vec<u8>,
    _charge: crate::DiskMemoryLease,
}
impl AdmittedReadBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Both owned vectors share the pre-effect reservation for this one row.
pub struct OwnedEncryptedRow {
    key: Vec<u8>,
    value: Vec<u8>,
    _charge: crate::DiskMemoryLease,
}
impl OwnedEncryptedRow {
    pub fn key(&self) -> &[u8] {
        &self.key
    }
    pub fn value(&self) -> &[u8] {
        &self.value
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
    finish_outer: Observation<std::convert::Infallible>,
    outcomes_released: bool,
}
impl ReaderState {
    fn has_failures(&self) -> bool {
        observed_failure(self.begin.borrow())
            || observed_failure(self.tables.borrow())
            || observed_failure(self.outer.borrow())
            || observed_failure(self.output_admission.borrow())
            || observed_failure(self.read_failure.borrow())
            || observed_failure(self.finish_outer.borrow())
            || self.transaction.as_ref().is_some_and(|transaction| {
                let report = transaction.report();
                observed_failure(report.release()) || observed_failure(report.disposal())
            })
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
    registration: StorageRegistration<ReaderRequest>,
}
impl Drop for ReadFacadeLease {
    fn drop(&mut self) {
        let previous = self
            .registration
            .owner()
            .facades
            .fetch_sub(1, Ordering::AcqRel);
        debug_assert_ne!(previous, 0);
    }
}

/// The census holds the transaction after facade cancellation or drop.
pub struct RegisteredNodeRead {
    registration: StorageRegistration<ReaderRequest>,
    lease: ReadFacadeLease,
}
impl RegisteredNodeOpening {
    /// Register the request before beginning the actual read transaction.
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
        let registration = provider
            .storage_census()
            .register(provider.clone(), 0, || ReaderRequest {
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
                    finish_outer: Observation::NotEntered,
                    outcomes_released: false,
                }),
            })?;
        if owner.stopped.load(Ordering::Acquire)
            || owner.state.lock().phase != NodeOpeningPhase::Open
        {
            registration.owner().state.lock().phase = NodeReadPhase::Cancelled;
            let _ = registration.retire();
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        let lease = ReadFacadeLease {
            registration: registration.clone(),
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
            registration: registration.clone(),
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
                _charge: charge,
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
        let bound = crate::disk_memory::allocation::<u8>(
            u64::try_from(max_value_bytes).map_err(|_| NodeReadAccessError::InvalidInput)?,
        )
        .map_err(NodeReadAccessError::Admission)?;
        let charge = self.reserve_output(bound)?;
        self.read_current(|transaction| transaction.get_bytes(crate::RECORDS, key, max_value_bytes))
            .map(|result| {
                result.map(|bytes| AdmittedReadBytes {
                    bytes,
                    _charge: charge,
                })
            })
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
        let mut state = request.state.lock();
        request.finish_observed(&mut state)
    }
    pub fn retire(self) -> StorageCensusDisposition {
        let request = self.registration.owner();
        if let Some(mut state) = request.state.try_lock() {
            if state.phase == NodeReadPhase::Queued {
                state.phase = NodeReadPhase::Cancelled;
            }
            state.outcomes_released = true;
        }
        let Self {
            registration,
            lease,
        } = self;
        drop(lease);
        registration.retire()
    }
}

pub struct NodeReadReport<'a> {
    state: MutexGuard<'a, ReaderState>,
}
impl NodeReadReport<'_> {
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
