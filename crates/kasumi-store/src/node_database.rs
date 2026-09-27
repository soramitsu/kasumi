//! A stopped node retains the exact database owner until accepted transactions end.
use crate::{
    NodeDiskMemoryAdmission, RegisteredBindingPut, RegisteredCatalogPut, RegisteredNodeOpening,
    RegisteredNodeRead, StorageCensusDisposition, StorageOwnerId, TenantStore,
    storage_domains::AdmittedBindingPut,
    storage_opening::write_plan::{AdmittedCatalogPairPut, AdmittedCatalogPut},
};
use kasumi_kv::{
    BackendNativeDisposition, Database, ReadTransaction, TransactionError, WriteTransaction,
};
use kasumi_types::drain::{DrainFailure, DrainReport, DrainResult};
use parking_lot::Mutex;
use std::{
    any::Any,
    fmt,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct State {
    database: Option<Arc<Database>>,
    registered: Option<Arc<RegisteredNodeOpening>>,
    retirement: Option<(Arc<dyn NodeDiskMemoryAdmission>, StorageOwnerId)>,
    registered_provider: Option<Arc<dyn NodeDiskMemoryAdmission>>,
    busy: DrainReport,
    terminal: DrainReport,
    interrupted: Option<DrainFailure>,
}

struct ClosePanic(Mutex<Box<dyn Any + Send>>);
impl fmt::Debug for ClosePanic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("database close panicked; original payload retained")
    }
}
impl fmt::Display for ClosePanic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Borrow the retained payload without exposing its potentially sensitive
        // content or treating its destructor as evidence of physical drain.
        let _payload = self.0.lock();
        f.write_str("database close panicked; ownership completion is unproven")
    }
}
impl std::error::Error for ClosePanic {}

pub(crate) struct NodeDatabase {
    component: &'static str,
    stopped: AtomicBool,
    state: Mutex<State>,
}
enum Accepted {
    Direct(Arc<Database>),
    Registered(Arc<RegisteredNodeOpening>),
}

impl NodeDatabase {
    pub(crate) fn new(database: Database, component: &'static str) -> Self {
        Self {
            component,
            stopped: AtomicBool::new(false),
            state: Mutex::new(State {
                database: Some(Arc::new(database)),
                registered: None,
                retirement: None,
                registered_provider: None,
                busy: DrainReport::default(),
                terminal: DrainReport::default(),
                interrupted: None,
            }),
        }
    }

    pub(crate) fn new_registered(
        opening: RegisteredNodeOpening,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        component: &'static str,
    ) -> Self {
        Self {
            component,
            stopped: AtomicBool::new(false),
            state: Mutex::new(State {
                database: None,
                registered: Some(Arc::new(opening)),
                retirement: None,
                registered_provider: Some(provider),
                busy: DrainReport::default(),
                terminal: DrainReport::default(),
                interrupted: None,
            }),
        }
    }

    fn accepted(&self) -> Result<Accepted, TransactionError> {
        let state = self.state.lock();
        if self.stopped.load(Ordering::Acquire) {
            return Err(kasumi_kv::StorageError::DatabaseClosed.into());
        }
        if let Some(opening) = &state.registered {
            return Ok(Accepted::Registered(opening.clone()));
        }
        state
            .database
            .as_ref()
            .cloned()
            .map(Accepted::Direct)
            .ok_or_else(|| kasumi_kv::StorageError::DatabaseClosed.into())
    }

    pub(crate) fn begin_read(&self) -> Result<ReadTransaction, TransactionError> {
        match self.accepted()? {
            Accepted::Direct(database) => database.begin_read(),
            Accepted::Registered(opening) => opening.begin_store_read(),
        }
    }

    pub(crate) fn begin_write(&self) -> Result<WriteTransaction, TransactionError> {
        match self.accepted()? {
            Accepted::Direct(database) => database.begin_write(),
            Accepted::Registered(opening) => opening.begin_store_write(),
        }
    }

    /// A fixed read has a census child before its transaction begins. No raw
    /// transaction can escape through this installed-node path.
    pub(crate) fn queue_registered_read(&self) -> std::io::Result<RegisteredNodeRead> {
        let opening = {
            let state = self.state.lock();
            if self.stopped.load(Ordering::Acquire) {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            state
                .registered
                .as_ref()
                .cloned()
                .ok_or(std::io::ErrorKind::InvalidInput)?
        };
        opening.queue_read()
    }

    /// A catalog write is bound to the exact opening before any native effect.
    pub(crate) fn queue_registered_catalog_put(
        &self,
        plan: AdmittedCatalogPut,
    ) -> std::io::Result<RegisteredCatalogPut> {
        let opening = {
            let state = self.state.lock();
            if self.stopped.load(Ordering::Acquire) {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            state
                .registered
                .as_ref()
                .cloned()
                .ok_or(std::io::ErrorKind::InvalidInput)?
        };
        opening.queue_catalog_put(plan)
    }

    /// Both fresh catalogs share one exact child and one native terminal.
    pub(crate) fn queue_registered_catalog_pair_put(
        &self,
        plan: AdmittedCatalogPairPut,
        application: Arc<TenantStore>,
        custody: Arc<TenantStore>,
    ) -> std::io::Result<RegisteredCatalogPut> {
        let opening = {
            let state = self.state.lock();
            if self.stopped.load(Ordering::Acquire) {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            state
                .registered
                .as_ref()
                .cloned()
                .ok_or(std::io::ErrorKind::InvalidInput)?
        };
        opening.queue_catalog_pair_put(plan, application, custody)
    }

    pub(crate) fn queue_registered_binding_put(
        &self,
        plan: AdmittedBindingPut,
        application: Arc<TenantStore>,
        custody: Arc<TenantStore>,
    ) -> std::io::Result<RegisteredBindingPut> {
        let opening = {
            let state = self.state.lock();
            if self.stopped.load(Ordering::Acquire) {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            state
                .registered
                .as_ref()
                .cloned()
                .ok_or(std::io::ErrorKind::InvalidInput)?
        };
        opening.queue_binding_put(plan, application, custody)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn has_fixture_direct_database(&self) -> bool {
        self.state.lock().database.is_some()
    }

    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(opening) = self.state.lock().registered.as_ref() {
            opening.seal_store_transactions();
        }
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
    pub(crate) fn registered_opening_id(&self) -> Option<StorageOwnerId> {
        let state = self.state.lock();
        state
            .registered
            .as_ref()
            .map(|opening| opening.id())
            .or_else(|| state.retirement.as_ref().map(|(_, id)| *id))
    }

    pub(crate) fn close(&self) -> DrainResult {
        self.stop();
        let mut state = self.state.lock();
        if let Some(failure) = &state.interrupted {
            return Err(failure.clone());
        }
        if let Some((provider, id)) = state.retirement.take() {
            // A prior close may have skipped a released routine child while
            // its census metadata was busy. That child still owns this parent
            // registration, so rescan the exact children before parent drain.
            RegisteredNodeOpening::drain_released_routine_readers(&provider, id);
            match provider.storage_census().drain_owner(id) {
                StorageCensusDisposition::Retired => return state.terminal.complete(),
                StorageCensusDisposition::Retained => {
                    state.retirement = Some((provider, id));
                    let issue = state.busy.record(
                        self.component,
                        0,
                        anyhow::anyhow!(
                            "registered node opening retirement still owns physical custody"
                        ),
                    );
                    return Err(DrainFailure::retained(issue));
                }
                StorageCensusDisposition::Stale => {
                    let issue = state.terminal.record(
                        self.component,
                        0,
                        anyhow::anyhow!(
                            "registered node opening owner disappeared before retirement"
                        ),
                    );
                    let failure = DrainFailure::retained(issue);
                    state.interrupted = Some(failure.clone());
                    return Err(failure);
                }
            }
        }
        if let Some(opening) = state.registered.as_ref() {
            let id = opening.id();
            let settlement = std::panic::catch_unwind(AssertUnwindSafe(|| opening.close()));
            match settlement {
                Ok(Ok(kasumi_kv::DatabaseOpenSettlement::Closed)) => {
                    let opening = state
                        .registered
                        .take()
                        .expect("registered opening retained");
                    let opening = match Arc::try_unwrap(opening) {
                        Ok(opening) => opening,
                        Err(opening) => {
                            state.registered = Some(opening);
                            let issue = state.busy.record(
                                self.component,
                                0,
                                anyhow::anyhow!(
                                    "accepted registered database callers are still live"
                                ),
                            );
                            return Err(DrainFailure::retained(issue));
                        }
                    };
                    let provider = state
                        .registered_provider
                        .take()
                        .expect("registered opening has exact installed provider");
                    match opening.retire() {
                        StorageCensusDisposition::Retired => return state.terminal.complete(),
                        StorageCensusDisposition::Retained => {
                            state.retirement = Some((provider, id));
                            let issue = state.busy.record(
                                self.component,
                                0,
                                anyhow::anyhow!(
                                    "registered node opening retirement still owns physical custody"
                                ),
                            );
                            return Err(DrainFailure::retained(issue));
                        }
                        StorageCensusDisposition::Stale => {
                            let issue = state.terminal.record(
                                self.component,
                                0,
                                anyhow::anyhow!(
                                    "registered node opening owner disappeared before retirement"
                                ),
                            );
                            let failure = DrainFailure::retained(issue);
                            state.interrupted = Some(failure.clone());
                            return Err(failure);
                        }
                    }
                }
                Ok(Ok(kasumi_kv::DatabaseOpenSettlement::WaitingForTransactions)) | Ok(Err(_)) => {
                    let issue = state.busy.record(
                        self.component,
                        0,
                        anyhow::anyhow!("registered node opening is waiting for admitted work"),
                    );
                    return Err(DrainFailure::retained(issue));
                }
                Ok(Ok(other)) => {
                    // An entered failed/uncertain close is terminal. The same
                    // opening and original report remain in this node and in
                    // the installed census; no second physical close is issued.
                    let issue = state.terminal.record(
                        self.component,
                        0,
                        anyhow::anyhow!("registered node opening {id:?} close settled {other:?}"),
                    );
                    let failure = DrainFailure::retained(issue);
                    state.interrupted = Some(failure.clone());
                    return Err(failure);
                }
                Err(payload) => {
                    let issue = state.terminal.record(
                        self.component,
                        1,
                        ClosePanic(Mutex::new(payload)).into(),
                    );
                    let failure = DrainFailure::retained(issue);
                    state.interrupted = Some(failure.clone());
                    return Err(failure);
                }
            }
        }
        let Some(database) = state.database.take() else {
            return state.terminal.complete();
        };
        let result = match Arc::try_unwrap(database) {
            Ok(database) => match std::panic::catch_unwind(AssertUnwindSafe(|| database.close())) {
                Ok(Ok(())) => return state.terminal.complete(),
                Ok(Err(kasumi_kv::CloseError::Storage(error))) => {
                    let issue = state.terminal.record(self.component, 0, error.into());
                    let failure = DrainFailure::retained(issue);
                    state.interrupted = Some(failure.clone());
                    return Err(failure);
                }
                Ok(Err(kasumi_kv::CloseError::Busy(database))) => Arc::new(database),
                Err(payload) => {
                    let issue = state.terminal.record(
                        self.component,
                        1,
                        ClosePanic(Mutex::new(payload)).into(),
                    );
                    let failure = DrainFailure::retained(issue);
                    state.interrupted = Some(failure.clone());
                    return Err(failure);
                }
            },
            Err(database) => database,
        };
        state.database = Some(result);
        let issue = state.busy.record(
            self.component,
            0,
            anyhow::anyhow!("accepted database callers or transaction handles are still live"),
        );
        Err(DrainFailure::retained(issue))
    }

    /// Destructor fallback for the last owner of a direct database. Unlike
    /// `close`, it records no report, formats nothing and allocates nothing
    /// beyond the backend's own close (the scratch spool's close allocates
    /// nothing). It seals admission and enters the one native close only when
    /// no accepted caller or transaction handle survives. `Drained` is returned
    /// only for clean native drain observed now or by an earlier completed
    /// close. An earlier terminal failure, a live handle, a registered opening,
    /// an unwind or any unproved native outcome is `Retained`: the caller must
    /// keep this exact owner, and with it the physical file and its charge.
    /// The native close is never re-entered; the engine keeps its first report.
    pub(crate) fn close_native_for_drop(&self) -> BackendNativeDisposition {
        self.stopped.store(true, Ordering::Release);
        let mut state = self.state.lock();
        if state.interrupted.is_some() || state.registered.is_some() || state.retirement.is_some() {
            return BackendNativeDisposition::Retained;
        }
        let Some(database) = state.database.as_ref() else {
            // Only a completed close removes the direct database without
            // recording a terminal interruption.
            return BackendNativeDisposition::Drained;
        };
        if Arc::strong_count(database) != 1 {
            return BackendNativeDisposition::Retained;
        }
        let outcome = match std::panic::catch_unwind(AssertUnwindSafe(|| database.close_native())) {
            Ok(outcome) => outcome,
            Err(payload) => {
                // No report can hold the payload here. Its destructor is not
                // run inside the caller's destructor and proves nothing.
                std::mem::forget(payload);
                return BackendNativeDisposition::Retained;
            }
        };
        let (result, native) = outcome.into_parts();
        if native == BackendNativeDisposition::Drained && result.is_ok() {
            state.database = None;
            return BackendNativeDisposition::Drained;
        }
        BackendNativeDisposition::Retained
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_kv::StorageBackend;

    fn memory() -> NodeDatabase {
        NodeDatabase::new(
            Database::builder(crate::test_utils::storage_admission())
                .create_with_backend(kasumi_kv::backends::InMemoryBackend::new())
                .unwrap(),
            "test database",
        )
    }

    #[test]
    fn pinned_transaction_keeps_close_retained_and_repeated_issue_identity() {
        let database = memory();
        let reader = database.begin_read().unwrap();
        let first = database.close().unwrap_err();
        assert_eq!(
            first.completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
        let second = database.close().unwrap_err();
        assert!(Arc::ptr_eq(&first.issues()[0], &second.issues()[0]));
        assert!(database.begin_read().is_err());
        assert!(database.begin_write().is_err());
        drop(reader);
        database.close().unwrap();
        database.close().unwrap();
        assert!(database.begin_read().is_err());
    }

    #[test]
    fn already_queued_writer_retains_database_without_blocking_close() {
        let database = Arc::new(memory());
        let first = database.begin_write().unwrap();
        let second = database.clone();
        let thread = std::thread::spawn(move || second.begin_write().unwrap().commit().unwrap());
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let queued = loop {
            if database
                .state
                .lock()
                .database
                .as_ref()
                .is_some_and(|db| Arc::strong_count(db) > 1)
            {
                break true;
            }
            if std::time::Instant::now() >= until {
                break false;
            }
            std::thread::yield_now();
        };
        let outcome = database.close();
        first.abort().unwrap();
        thread.join().unwrap();
        assert!(
            queued,
            "second actual writer never reached database admission"
        );
        assert_eq!(
            outcome.unwrap_err().completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
        database.close().unwrap();
    }

    #[derive(Debug, PartialEq)]
    struct OriginalClosePanic(u64);
    #[derive(Debug)]
    struct PanicBackend(kasumi_kv::backends::InMemoryBackend);
    impl StorageBackend for PanicBackend {
        fn len(&self) -> std::io::Result<u64> {
            self.0.len()
        }
        fn read(&self, at: u64, out: &mut [u8]) -> std::io::Result<()> {
            self.0.read(at, out)
        }
        fn set_len(&self, length: u64) -> std::io::Result<()> {
            self.0.set_len(length)
        }
        fn sync_data(&self) -> std::io::Result<()> {
            self.0.sync_data()
        }
        fn write(&self, at: u64, bytes: &[u8]) -> std::io::Result<()> {
            self.0.write(at, bytes)
        }
        fn close(&self) -> kasumi_kv::BackendCloseOutcome {
            std::panic::panic_any(OriginalClosePanic(41))
        }
    }

    #[test]
    fn close_panic_retains_original_payload_and_cannot_become_clean_on_retry() {
        let database = NodeDatabase::new(
            Database::builder(crate::test_utils::storage_admission())
                .create_with_backend(PanicBackend(kasumi_kv::backends::InMemoryBackend::new()))
                .unwrap(),
            "panicking backend",
        );
        let first = database.close().unwrap_err();
        let second = database.close().unwrap_err();
        assert_eq!(
            first.completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
        assert!(Arc::ptr_eq(&first.issues()[0], &second.issues()[0]));
        let original = first.issues()[0]
            .error()
            .downcast_ref::<ClosePanic>()
            .unwrap();
        assert_eq!(
            original.0.lock().downcast_ref::<OriginalClosePanic>(),
            Some(&OriginalClosePanic(41))
        );
        assert!(database.begin_read().is_err());
        assert!(database.begin_write().is_err());
    }
    #[derive(Debug)]
    struct UnprovedCloseBackend(kasumi_kv::backends::InMemoryBackend);
    impl StorageBackend for UnprovedCloseBackend {
        fn len(&self) -> std::io::Result<u64> {
            self.0.len()
        }
        fn read(&self, at: u64, bytes: &mut [u8]) -> std::io::Result<()> {
            self.0.read(at, bytes)
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.0.set_len(len)
        }
        fn sync_data(&self) -> std::io::Result<()> {
            self.0.sync_data()
        }
        fn write(&self, at: u64, bytes: &[u8]) -> std::io::Result<()> {
            self.0.write(at, bytes)
        }
        fn close(&self) -> kasumi_kv::BackendCloseOutcome {
            kasumi_kv::BackendCloseOutcome::retained_result(Ok(()))
        }
    }
    #[test]
    fn logical_close_success_without_native_evidence_never_becomes_complete_on_retry() {
        let database = NodeDatabase::new(
            Database::builder(crate::test_utils::storage_admission())
                .create_with_backend(UnprovedCloseBackend(
                    kasumi_kv::backends::InMemoryBackend::new(),
                ))
                .unwrap(),
            "unproved native drain",
        );
        let first = database.close().unwrap_err();
        assert_eq!(
            first.completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
        let second = database.close().unwrap_err();
        assert_eq!(
            second.completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
        assert!(Arc::ptr_eq(&first.issues()[0], &second.issues()[0]));
        assert!(database.begin_read().is_err());
        assert!(database.begin_write().is_err());
        // This legacy consuming facade retains only its report on error. Actual
        // owner custody requires the RegisteredNodeOpening consumer migration.
        assert!(database.state.lock().database.is_none());
    }

    #[derive(Clone, Copy, Debug)]
    enum CloseMode {
        Drained,
        Unproved,
        Panic,
    }
    #[derive(Debug)]
    struct CountedClose {
        backend: kasumi_kv::backends::InMemoryBackend,
        closes: Arc<std::sync::atomic::AtomicUsize>,
        mode: CloseMode,
    }
    impl StorageBackend for CountedClose {
        fn len(&self) -> std::io::Result<u64> {
            self.backend.len()
        }
        fn read(&self, at: u64, bytes: &mut [u8]) -> std::io::Result<()> {
            self.backend.read(at, bytes)
        }
        fn set_len(&self, len: u64) -> std::io::Result<()> {
            self.backend.set_len(len)
        }
        fn sync_data(&self) -> std::io::Result<()> {
            self.backend.sync_data()
        }
        fn write(&self, at: u64, bytes: &[u8]) -> std::io::Result<()> {
            self.backend.write(at, bytes)
        }
        fn close(&self) -> kasumi_kv::BackendCloseOutcome {
            self.closes.fetch_add(1, Ordering::SeqCst);
            match self.mode {
                CloseMode::Drained => kasumi_kv::BackendCloseOutcome::drained(Ok(())),
                CloseMode::Unproved => kasumi_kv::BackendCloseOutcome::retained_result(Ok(())),
                CloseMode::Panic => std::panic::panic_any(OriginalClosePanic(43)),
            }
        }
    }
    fn counted(mode: CloseMode) -> (NodeDatabase, Arc<std::sync::atomic::AtomicUsize>) {
        let closes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let database = NodeDatabase::new(
            Database::builder(crate::test_utils::storage_admission())
                .create_strict_with_backend(CountedClose {
                    backend: kasumi_kv::backends::InMemoryBackend::new(),
                    closes: closes.clone(),
                    mode,
                })
                .unwrap(),
            "counted close",
        );
        // Like a scratch owner, commit once before any close. This also takes
        // the first writer-gate and engine locks, whose storage std allocates
        // lazily on first use on some targets (pthread-backed macOS locks).
        let tx = database.begin_write().unwrap();
        tx.open_table(kasumi_kv::TableDefinition::<&[u8], &[u8]>::new("staged"))
            .unwrap();
        tx.commit().unwrap();
        (database, closes)
    }

    #[test]
    fn drop_fallback_waits_for_live_handles_and_enters_native_close_once() {
        let (database, closes) = counted(CloseMode::Drained);
        let reader = database.begin_read().unwrap();
        let (outcome, allocations) =
            crate::allocation_tests::measure(|| database.close_native_for_drop());
        assert_eq!(outcome, BackendNativeDisposition::Retained);
        assert_eq!(allocations, 0);
        assert_eq!(closes.load(Ordering::SeqCst), 0);
        assert!(database.begin_read().is_err());
        assert!(database.begin_write().is_err());
        drop(reader);
        for _ in 0..2 {
            let (outcome, allocations) =
                crate::allocation_tests::measure(|| database.close_native_for_drop());
            assert_eq!(outcome, BackendNativeDisposition::Drained);
            assert_eq!(allocations, 0);
            assert_eq!(closes.load(Ordering::SeqCst), 1);
        }
        assert!(database.state.lock().database.is_none());
        database.close().unwrap();
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn drop_fallback_never_claims_or_reenters_an_unproved_native_close() {
        let (database, closes) = counted(CloseMode::Unproved);
        for _ in 0..2 {
            let (outcome, allocations) =
                crate::allocation_tests::measure(|| database.close_native_for_drop());
            assert_eq!(outcome, BackendNativeDisposition::Retained);
            assert_eq!(allocations, 0);
            assert_eq!(closes.load(Ordering::SeqCst), 1);
        }
        // A later explicit close projects the engine's first report.
        let failure = database.close().unwrap_err();
        assert_eq!(
            failure.completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn drop_fallback_after_failed_explicit_close_retains_without_reentry() {
        let (database, closes) = counted(CloseMode::Unproved);
        let first = database.close().unwrap_err();
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        let (outcome, allocations) =
            crate::allocation_tests::measure(|| database.close_native_for_drop());
        assert_eq!(outcome, BackendNativeDisposition::Retained);
        assert_eq!(allocations, 0);
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        let second = database.close().unwrap_err();
        assert!(Arc::ptr_eq(&first.issues()[0], &second.issues()[0]));
    }

    #[test]
    fn drop_fallback_contains_close_panic_without_claiming_drain_or_reentry() {
        let (database, closes) = counted(CloseMode::Panic);
        for _ in 0..2 {
            assert_eq!(
                database.close_native_for_drop(),
                BackendNativeDisposition::Retained
            );
            // The entered close is never replayed into the panicking backend.
            assert_eq!(closes.load(Ordering::SeqCst), 1);
        }
        assert!(database.state.lock().database.is_some());
        assert!(database.begin_read().is_err());
        assert_eq!(
            database.close().unwrap_err().completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }
}
