//! A stopped node retains the exact database owner until accepted transactions end.
use crate::{
    NodeDiskMemoryAdmission, RegisteredBindingPut, RegisteredCatalogPut, RegisteredNodeOpening,
    RegisteredNodeRead, StorageOwnerId, TenantStore,
    storage_domains::AdmittedBindingPut,
    storage_opening::write_plan::{AdmittedCatalogPairPut, AdmittedCatalogPut},
};
use kasumi_kv::{
    Database, DatabaseCloseReport, DatabaseCloseSettlement, DatabaseTransactionAdmission,
    ReadTransaction, RetainedDatabase, TransactionError, WriteTransaction,
};
use kasumi_types::drain::{DrainFailure, DrainReport, DrainResult};
use parking_lot::{Mutex, MutexGuard};
use std::{
    any::Any,
    fmt,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

struct NodeDatabaseLocator {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
}
impl NodeDatabaseLocator {
    fn opening(&self) -> std::io::Result<RegisteredNodeOpening> {
        RegisteredNodeOpening::retained(self.provider.clone(), self.id)
            .ok_or_else(|| std::io::ErrorKind::WouldBlock.into())
    }
    fn id(&self) -> StorageOwnerId {
        self.id
    }
}

struct State {
    database: Option<RetainedDatabase>,
    registered: Option<NodeDatabaseLocator>,
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
    Direct(DatabaseTransactionAdmission),
    Registered(RegisteredNodeOpening),
}

/// Borrows the original direct close and disposal observations from the same
/// preowned state. A native Drained result alone does not prove disposal.
pub(crate) struct NodeDirectNativeReport<'a> {
    state: MutexGuard<'a, State>,
}
impl NodeDirectNativeReport<'_> {
    pub(crate) fn close(&self) -> DatabaseCloseReport<'_> {
        self.state
            .database
            .as_ref()
            .expect("direct native owner")
            .report()
    }

    pub(crate) fn disposal_complete(&self) -> bool {
        self.close().disposal().complete()
    }
}

impl NodeDatabase {
    #[cfg(test)]
    pub(crate) fn new(database: Database, component: &'static str) -> Self {
        Self::new_retained(database.retain(), component)
    }

    pub(crate) fn new_retained(database: RetainedDatabase, component: &'static str) -> Self {
        Self {
            component,
            stopped: AtomicBool::new(false),
            state: Mutex::new(State {
                database: Some(database),
                registered: None,
                busy: DrainReport::default(),
                terminal: DrainReport::default(),
                interrupted: None,
            }),
        }
    }

    pub(crate) fn new_registered_locator(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
        component: &'static str,
    ) -> Self {
        Self {
            component,
            stopped: AtomicBool::new(false),
            state: Mutex::new(State {
                database: None,
                registered: Some(NodeDatabaseLocator { provider, id }),
                busy: DrainReport::default(),
                terminal: DrainReport::default(),
                interrupted: None,
            }),
        }
    }

    fn admit_opening_until(
        &self,
        deadline: std::time::Instant,
    ) -> std::io::Result<RegisteredNodeOpening> {
        let (provider, id) = {
            let state = self.state.lock();
            if self.stopped.load(Ordering::Acquire) {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            let locator = state
                .registered
                .as_ref()
                .ok_or(std::io::ErrorKind::InvalidInput)?;
            (locator.provider.clone(), locator.id)
        };
        // Do not hold NodeDatabase state while waiting for census metadata.
        let opening = RegisteredNodeOpening::admit_retained_until(provider, id, deadline)?;
        if self.stopped.load(Ordering::Acquire) {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        Ok(opening)
    }

    fn accepted(&self) -> Result<Accepted, TransactionError> {
        let state = self.state.lock();
        if self.stopped.load(Ordering::Acquire) {
            return Err(kasumi_kv::StorageError::DatabaseClosed.into());
        }
        if state.registered.is_some() {
            drop(state);
            return Ok(Accepted::Registered(
                self.admit_opening_until(std::time::Instant::now() + crate::NATIVE_READ_TIMEOUT)
                    .map_err(kasumi_kv::StorageError::from)?,
            ));
        }
        state
            .database
            .as_ref()
            .and_then(RetainedDatabase::database)
            .map(Database::transaction_admission)
            .map(Accepted::Direct)
            .ok_or_else(|| kasumi_kv::StorageError::DatabaseClosed.into())
    }

    pub(crate) fn begin_read(&self) -> Result<ReadTransaction, TransactionError> {
        match self.accepted()? {
            Accepted::Direct(database) => database.begin_read(),
            Accepted::Registered(opening) => {
                #[cfg(any(test, feature = "test-utils"))]
                {
                    opening.begin_store_read()
                }
                #[cfg(not(any(test, feature = "test-utils")))]
                {
                    let _ = opening;
                    Err(kasumi_kv::StorageError::DatabaseClosed.into())
                }
            }
        }
    }

    pub(crate) fn begin_write(&self) -> Result<WriteTransaction, TransactionError> {
        match self.accepted()? {
            Accepted::Direct(database) => database.begin_write(),
            Accepted::Registered(opening) => {
                #[cfg(any(test, feature = "test-utils"))]
                {
                    opening.begin_store_write()
                }
                #[cfg(not(any(test, feature = "test-utils")))]
                {
                    let _ = opening;
                    Err(kasumi_kv::StorageError::DatabaseClosed.into())
                }
            }
        }
    }

    pub(crate) fn physical_identity(&self) -> anyhow::Result<crate::NodeGroupIdentity> {
        match self.accepted()? {
            Accepted::Registered(opening) => opening.physical_identity(),
            Accepted::Direct(_) => {
                Err(std::io::Error::from(std::io::ErrorKind::Unsupported).into())
            }
        }
    }

    pub(crate) fn configure_cache(
        &self,
        config: kasumi_kv::CacheConfig,
    ) -> Result<(), kasumi_kv::StorageError> {
        match self.accepted().map_err(|error| error.0)? {
            Accepted::Direct(database) => database.configure_cache(config),
            Accepted::Registered(opening) => opening.configure_cache(config),
        }
    }

    pub(crate) fn cache_stats(&self) -> Result<kasumi_kv::CacheStats, kasumi_kv::StorageError> {
        match self.accepted().map_err(|error| error.0)? {
            Accepted::Direct(database) => database.cache_stats(),
            Accepted::Registered(opening) => opening.cache_stats(),
        }
    }

    pub(crate) fn warm_cache(
        &self,
        work_limit: usize,
    ) -> Result<kasumi_kv::CacheWarmup, kasumi_kv::StorageError> {
        match self.accepted().map_err(|error| error.0)? {
            Accepted::Direct(database) => database.warm_cache(work_limit),
            Accepted::Registered(opening) => opening.warm_cache(work_limit),
        }
    }

    pub(crate) fn warm_cache_if_needed(
        &self,
        work_limit: usize,
    ) -> Result<kasumi_kv::CacheWarmup, kasumi_kv::StorageError> {
        match self.accepted().map_err(|error| error.0)? {
            Accepted::Direct(database) => database.warm_cache_if_needed(work_limit),
            Accepted::Registered(opening) => opening.warm_cache_if_needed(work_limit),
        }
    }

    pub(crate) fn cache_warmup_status(
        &self,
    ) -> Result<kasumi_kv::CacheWarmupStatus, kasumi_kv::StorageError> {
        match self.accepted().map_err(|error| error.0)? {
            Accepted::Direct(database) => database.cache_warmup_status(),
            Accepted::Registered(opening) => opening.cache_warmup_status(),
        }
    }

    pub(crate) fn request_cache_warm_retry(&self) -> Result<(), kasumi_kv::StorageError> {
        match self.accepted().map_err(|error| error.0)? {
            Accepted::Direct(database) => database.request_cache_warm_retry(),
            Accepted::Registered(opening) => opening.request_cache_warm_retry(),
        }
    }

    /// A fixed read has a census child before its transaction begins. No raw
    /// transaction can escape through this installed-node path.
    pub(crate) fn queue_registered_read(&self) -> std::io::Result<RegisteredNodeRead> {
        self.queue_registered_read_until(std::time::Instant::now() + crate::NATIVE_READ_TIMEOUT)
    }
    pub(crate) fn queue_registered_read_until(
        &self,
        deadline: std::time::Instant,
    ) -> std::io::Result<RegisteredNodeRead> {
        let opening = self.admit_opening_until(deadline)?;
        opening.queue_read()
    }

    pub(crate) fn queue_registered_write(&self) -> std::io::Result<crate::RegisteredNodeWrite> {
        self.queue_registered_write_until(std::time::Instant::now() + crate::NATIVE_WRITE_TIMEOUT)
    }
    pub(crate) fn queue_registered_write_until(
        &self,
        deadline: std::time::Instant,
    ) -> std::io::Result<crate::RegisteredNodeWrite> {
        let opening = self.admit_opening_until(deadline)?;
        opening.queue_write()
    }

    pub(crate) fn queue_source_capacity(&self) -> std::io::Result<crate::RegisteredSourceCapacity> {
        let opening =
            self.admit_opening_until(std::time::Instant::now() + crate::NATIVE_WRITE_TIMEOUT)?;
        opening.queue_source_capacity()
    }

    pub(crate) fn require_registered_read(
        &self,
        reader: &RegisteredNodeRead,
    ) -> std::io::Result<()> {
        let opening =
            self.admit_opening_until(std::time::Instant::now() + crate::NATIVE_READ_TIMEOUT)?;
        if !reader.belongs_to(&opening) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }

    pub(crate) fn fork_registered_read(
        &self,
        parent: &RegisteredNodeRead,
    ) -> std::io::Result<RegisteredNodeRead> {
        let opening =
            self.admit_opening_until(std::time::Instant::now() + crate::NATIVE_READ_TIMEOUT)?;
        if !parent.belongs_to(&opening) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        // No NodeDatabase lock crosses reader locks, admission or callbacks.
        parent.fork()
    }

    /// A catalog write is bound to the exact opening before any native effect.
    pub(crate) fn queue_registered_catalog_put(
        &self,
        plan: AdmittedCatalogPut,
    ) -> std::io::Result<RegisteredCatalogPut> {
        let opening =
            self.admit_opening_until(std::time::Instant::now() + crate::NATIVE_WRITE_TIMEOUT)?;
        opening.queue_catalog_put(plan)
    }

    /// Both fresh catalogs share one exact child and one native terminal.
    pub(crate) fn queue_registered_catalog_pair_put(
        &self,
        plan: AdmittedCatalogPairPut,
        application: Arc<TenantStore>,
        custody: Arc<TenantStore>,
    ) -> std::io::Result<RegisteredCatalogPut> {
        let opening =
            self.admit_opening_until(std::time::Instant::now() + crate::NATIVE_WRITE_TIMEOUT)?;
        opening.queue_catalog_pair_put(plan, application, custody)
    }

    pub(crate) fn queue_registered_binding_put(
        &self,
        plan: AdmittedBindingPut,
        application: Arc<TenantStore>,
        custody: Arc<TenantStore>,
    ) -> std::io::Result<RegisteredBindingPut> {
        let opening =
            self.admit_opening_until(std::time::Instant::now() + crate::NATIVE_WRITE_TIMEOUT)?;
        opening.queue_binding_put(plan, application, custody)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn has_fixture_direct_database(&self) -> bool {
        self.state.lock().database.is_some()
    }

    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(locator) = self.state.lock().registered.as_ref()
            && let Ok(opening) = locator.opening()
        {
            opening.seal_store_transactions();
        }
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
    pub(crate) fn registered_opening_id(&self) -> Option<StorageOwnerId> {
        let state = self.state.lock();
        state.registered.as_ref().map(NodeDatabaseLocator::id)
    }

    pub(crate) fn close(&self) -> DrainResult {
        self.stop();
        let mut state = self.state.lock();
        if let Some(failure) = &state.interrupted {
            return Err(failure.clone());
        }
        if let Some(locator) = state.registered.as_ref() {
            let opening = match locator.opening() {
                Ok(opening) => opening,
                Err(_) => {
                    let issue = state.busy.record(
                        self.component,
                        0,
                        anyhow::anyhow!("registered node opening observation is busy"),
                    );
                    return Err(DrainFailure::retained(issue));
                }
            };
            let id = opening.id();
            let settlement = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let closed = opening.close()?;
                if matches!(
                    closed,
                    kasumi_kv::DatabaseOpenSettlement::Closed
                        | kasumi_kv::DatabaseOpenSettlement::Disposed
                ) {
                    opening.dispose_native()
                } else {
                    Ok(closed)
                }
            }));
            match settlement {
                Ok(Ok(kasumi_kv::DatabaseOpenSettlement::Disposed)) => {
                    if opening.report().engine().disposal().complete() {
                        if !opening.children_retired() {
                            // Native engine disposal alone does not retire a
                            // child's retained original outcome or paid lease.
                            // This remains retryable after exact child cleanup.
                            let issue = state.busy.record(
                                self.component,
                                0,
                                anyhow::anyhow!(
                                    "registered node opening has unretired admitted children"
                                ),
                            );
                            return Err(DrainFailure::retained(issue));
                        }
                        // The node facade/control/path keeps its original fee;
                        // every admitted child has actually retired.
                        return state.terminal.complete();
                    }
                    let issue = state.terminal.record(
                        self.component,
                        0,
                        anyhow::anyhow!(
                            "registered node opening {id:?} native disposal is unproved"
                        ),
                    );
                    let failure = DrainFailure::retained(issue);
                    state.interrupted = Some(failure.clone());
                    return Err(failure);
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
        let Some(database) = state.database.as_mut() else {
            return state.terminal.complete();
        };
        // Existing accepted work owns the same closed native controls. Wrapper
        // dispatch is sealed, but an already queued writer may finish before
        // native closure enters. This is a pre-effect busy condition.
        let settlement = if Self::direct_work_survives(database) {
            DatabaseCloseSettlement::WaitingForTransactions
        } else {
            database.close().settlement()
        };
        match settlement {
            DatabaseCloseSettlement::Settled | DatabaseCloseSettlement::Disposed => {
                if database.dispose().settlement() == DatabaseCloseSettlement::Disposed
                    && database.report().disposal().complete()
                {
                    return state.terminal.complete();
                }
            }
            DatabaseCloseSettlement::Open | DatabaseCloseSettlement::WaitingForTransactions => {
                let issue = state.busy.record(
                    self.component,
                    0,
                    anyhow::anyhow!(
                        "accepted database callers or transaction handles are still live"
                    ),
                );
                return Err(DrainFailure::retained(issue));
            }
            _ => {}
        }
        // The original close/disposal errors and panic payloads remain in the
        // retained database. This stable drain issue is a nonowning diagnostic.
        let issue = state.terminal.record(
            self.component,
            0,
            anyhow::anyhow!("direct database close or disposal is unproved; inspect native report"),
        );
        let failure = DrainFailure::retained(issue);
        state.interrupted = Some(failure.clone());
        Err(failure)
    }

    /// Inspect native disposal and sealed child retirement while keeping the
    /// composite node's body, locator and original census fee live. Missing or
    /// contended observations never establish completion.
    pub(crate) fn native_resources_disposed(&self) -> bool {
        let state = self.state.lock();
        if let Some(locator) = &state.registered {
            let Ok(opening) = locator.opening() else {
                return false;
            };
            let report = opening.report();
            return report.engine().settlement() == kasumi_kv::DatabaseOpenSettlement::Disposed
                && report.engine().disposal().complete()
                && opening.children_retired();
        }
        state.database.as_ref().is_some_and(|database| {
            let report = database.report();
            report.settlement() == DatabaseCloseSettlement::Disposed && report.disposal().complete()
        })
    }

    fn direct_work_survives(database: &RetainedDatabase) -> bool {
        database
            .database()
            .is_some_and(|database| database.active_transactions() != 0)
    }

    /// Explicit native close for registered scratch custody. Every original
    /// result stays in State; no diagnostic allocation or Drop witness occurs.
    pub(crate) fn close_direct_native(&self) -> Option<NodeDirectNativeReport<'_>> {
        self.stopped.store(true, Ordering::Release);
        let mut state = self.state.try_lock()?;
        if state.registered.is_some() {
            return None;
        }
        let database = state.database.as_mut()?;
        if !Self::direct_work_survives(database) {
            let _ = database.close();
        }
        Some(NodeDirectNativeReport { state })
    }

    /// Dispose only the previously closed original owner. A call before close,
    /// contention, or an unknown close remains unproved without entering close.
    pub(crate) fn dispose_direct_native(&self) -> Option<NodeDirectNativeReport<'_>> {
        self.stopped.store(true, Ordering::Release);
        let mut state = self.state.try_lock()?;
        if state.registered.is_some() {
            return None;
        }
        let _ = state.database.as_mut()?.dispose();
        Some(NodeDirectNativeReport { state })
    }

    #[cfg(test)]
    pub(crate) fn direct_native_report(&self) -> Option<NodeDirectNativeReport<'_>> {
        let state = self.state.try_lock()?;
        state.database.as_ref()?;
        Some(NodeDirectNativeReport { state })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_kv::{BackendNativeDisposition, SegmentGroupBackend};

    fn memory() -> NodeDatabase {
        NodeDatabase::new(
            Database::builder(
                crate::test_utils::storage_admission(),
                *crate::test_utils::NODE_STORE_ID.as_bytes(),
                crate::test_utils::node_storage_config().cache,
            )
            .create_with_backend(kasumi_kv::backends::InMemoryGroup::new())
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
        assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
            &first.issues()[0],
            &second.issues()[0]
        ));
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
                .and_then(RetainedDatabase::database)
                .is_some_and(|db| db.active_transactions() > 1)
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
    struct PanicBackend(kasumi_kv::backends::InMemoryGroup);
    impl SegmentGroupBackend for PanicBackend {
        fn reserve_transaction(
            &self,
            plan: &kasumi_kv::TransactionSpacePlan,
        ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
            self.0.reserve_transaction(plan)
        }
        fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.0.finish_transaction(group_id, batch_seq)
        }
        fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.0.cancel_transaction(group_id, batch_seq)
        }

        fn read_root(
            &self,
            slot: kasumi_kv::RootSlot,
            out: &mut [u8; kasumi_kv::ROOT_SLOT_BYTES],
        ) -> std::io::Result<()> {
            self.0.read_root(slot, out)
        }
        fn write_root(
            &self,
            slot: kasumi_kv::RootSlot,
            bytes: &[u8; kasumi_kv::ROOT_SLOT_BYTES],
        ) -> std::io::Result<()> {
            self.0.write_root(slot, bytes)
        }
        fn sync_root(&self) -> std::io::Result<()> {
            self.0.sync_root()
        }
        fn visit_entries(
            &self,
            visitor: &mut dyn FnMut(&std::ffi::OsStr) -> std::io::Result<()>,
        ) -> std::io::Result<()> {
            self.0.visit_entries(visitor)
        }
        fn exists(&self, file: kasumi_kv::GroupFile) -> std::io::Result<bool> {
            self.0.exists(file)
        }
        fn create(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            self.0.create(file)
        }
        fn len(&self, file: kasumi_kv::GroupFile) -> std::io::Result<u64> {
            self.0.len(file)
        }
        fn read(&self, file: kasumi_kv::GroupFile, at: u64, out: &mut [u8]) -> std::io::Result<()> {
            self.0.read(file, at, out)
        }
        fn write(&self, file: kasumi_kv::GroupFile, at: u64, bytes: &[u8]) -> std::io::Result<()> {
            self.0.write(file, at, bytes)
        }
        fn set_len(&self, file: kasumi_kv::GroupFile, length: u64) -> std::io::Result<()> {
            self.0.set_len(file, length)
        }
        fn sync(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            self.0.sync(file)
        }
        fn unlink(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            self.0.unlink(file)
        }
        fn sync_names(&self) -> std::io::Result<()> {
            self.0.sync_names()
        }
        fn close(&self) -> kasumi_kv::BackendCloseOutcome {
            std::panic::panic_any(OriginalClosePanic(41))
        }
    }

    #[test]
    fn close_panic_retains_original_payload_and_cannot_become_clean_on_retry() {
        let database = NodeDatabase::new(
            Database::builder(
                crate::test_utils::storage_admission(),
                *crate::test_utils::NODE_STORE_ID.as_bytes(),
                crate::test_utils::node_storage_config().cache,
            )
            .create_with_backend(PanicBackend(kasumi_kv::backends::InMemoryGroup::new()))
            .unwrap(),
            "panicking backend",
        );
        let first = database.close().unwrap_err();
        let second = database.close().unwrap_err();
        assert_eq!(
            first.completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
        assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
            &first.issues()[0],
            &second.issues()[0]
        ));
        let original_address = {
            let native = database.direct_native_report().unwrap();
            let close = native.close();
            let kasumi_kv::TerminalObservation::Panicked(original) = close.backend() else {
                panic!("original native close panic was not retained");
            };
            assert_eq!(
                original.downcast_ref::<OriginalClosePanic>(),
                Some(&OriginalClosePanic(41))
            );
            assert!(!native.disposal_complete());
            std::ptr::from_ref(original).cast::<()>()
        };
        {
            let native = database.close_direct_native().unwrap();
            let close = native.close();
            let kasumi_kv::TerminalObservation::Panicked(original) = close.backend() else {
                panic!("a repeated close lost the original panic");
            };
            assert_eq!(std::ptr::from_ref(original).cast::<()>(), original_address);
            assert!(!native.disposal_complete());
        }
        assert!(database.begin_read().is_err());
        assert!(database.begin_write().is_err());
    }
    struct UnprovedCloseBackend(kasumi_kv::backends::InMemoryGroup);
    impl SegmentGroupBackend for UnprovedCloseBackend {
        fn reserve_transaction(
            &self,
            plan: &kasumi_kv::TransactionSpacePlan,
        ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
            self.0.reserve_transaction(plan)
        }
        fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.0.finish_transaction(group_id, batch_seq)
        }
        fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.0.cancel_transaction(group_id, batch_seq)
        }

        fn read_root(
            &self,
            slot: kasumi_kv::RootSlot,
            out: &mut [u8; kasumi_kv::ROOT_SLOT_BYTES],
        ) -> std::io::Result<()> {
            self.0.read_root(slot, out)
        }
        fn write_root(
            &self,
            slot: kasumi_kv::RootSlot,
            bytes: &[u8; kasumi_kv::ROOT_SLOT_BYTES],
        ) -> std::io::Result<()> {
            self.0.write_root(slot, bytes)
        }
        fn sync_root(&self) -> std::io::Result<()> {
            self.0.sync_root()
        }
        fn visit_entries(
            &self,
            visitor: &mut dyn FnMut(&std::ffi::OsStr) -> std::io::Result<()>,
        ) -> std::io::Result<()> {
            self.0.visit_entries(visitor)
        }
        fn exists(&self, file: kasumi_kv::GroupFile) -> std::io::Result<bool> {
            self.0.exists(file)
        }
        fn create(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            self.0.create(file)
        }
        fn len(&self, file: kasumi_kv::GroupFile) -> std::io::Result<u64> {
            self.0.len(file)
        }
        fn read(&self, file: kasumi_kv::GroupFile, at: u64, out: &mut [u8]) -> std::io::Result<()> {
            self.0.read(file, at, out)
        }
        fn write(&self, file: kasumi_kv::GroupFile, at: u64, bytes: &[u8]) -> std::io::Result<()> {
            self.0.write(file, at, bytes)
        }
        fn set_len(&self, file: kasumi_kv::GroupFile, length: u64) -> std::io::Result<()> {
            self.0.set_len(file, length)
        }
        fn sync(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            self.0.sync(file)
        }
        fn unlink(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            self.0.unlink(file)
        }
        fn sync_names(&self) -> std::io::Result<()> {
            self.0.sync_names()
        }
        fn close(&self) -> kasumi_kv::BackendCloseOutcome {
            kasumi_kv::BackendCloseOutcome::retained_result(Ok(()))
        }
    }
    #[test]
    fn logical_close_success_without_native_evidence_never_becomes_complete_on_retry() {
        let database = NodeDatabase::new(
            Database::builder(
                crate::test_utils::storage_admission(),
                *crate::test_utils::NODE_STORE_ID.as_bytes(),
                crate::test_utils::node_storage_config().cache,
            )
            .create_with_backend(UnprovedCloseBackend(
                kasumi_kv::backends::InMemoryGroup::new(),
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
        assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
            &first.issues()[0],
            &second.issues()[0]
        ));
        assert!(database.begin_read().is_err());
        assert!(database.begin_write().is_err());
        // The actual native owner and its first close report remain together.
        let native = database.direct_native_report().unwrap();
        assert_eq!(
            native.close().settlement(),
            DatabaseCloseSettlement::Retained
        );
        assert!(!native.disposal_complete());
    }

    #[derive(Clone, Copy, Debug)]
    enum CloseMode {
        Drained,
        Unproved,
        Panic,
    }
    struct CountedClose {
        backend: kasumi_kv::backends::InMemoryGroup,
        closes: Arc<std::sync::atomic::AtomicUsize>,
        mode: CloseMode,
    }
    impl SegmentGroupBackend for CountedClose {
        fn reserve_transaction(
            &self,
            plan: &kasumi_kv::TransactionSpacePlan,
        ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
            self.backend.reserve_transaction(plan)
        }
        fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.backend.finish_transaction(group_id, batch_seq)
        }
        fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
            self.backend.cancel_transaction(group_id, batch_seq)
        }

        fn read_root(
            &self,
            slot: kasumi_kv::RootSlot,
            out: &mut [u8; kasumi_kv::ROOT_SLOT_BYTES],
        ) -> std::io::Result<()> {
            self.backend.read_root(slot, out)
        }
        fn write_root(
            &self,
            slot: kasumi_kv::RootSlot,
            bytes: &[u8; kasumi_kv::ROOT_SLOT_BYTES],
        ) -> std::io::Result<()> {
            self.backend.write_root(slot, bytes)
        }
        fn sync_root(&self) -> std::io::Result<()> {
            self.backend.sync_root()
        }
        fn visit_entries(
            &self,
            visitor: &mut dyn FnMut(&std::ffi::OsStr) -> std::io::Result<()>,
        ) -> std::io::Result<()> {
            self.backend.visit_entries(visitor)
        }
        fn exists(&self, file: kasumi_kv::GroupFile) -> std::io::Result<bool> {
            self.backend.exists(file)
        }
        fn create(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            self.backend.create(file)
        }
        fn len(&self, file: kasumi_kv::GroupFile) -> std::io::Result<u64> {
            self.backend.len(file)
        }
        fn read(&self, file: kasumi_kv::GroupFile, at: u64, out: &mut [u8]) -> std::io::Result<()> {
            self.backend.read(file, at, out)
        }
        fn write(&self, file: kasumi_kv::GroupFile, at: u64, bytes: &[u8]) -> std::io::Result<()> {
            self.backend.write(file, at, bytes)
        }
        fn set_len(&self, file: kasumi_kv::GroupFile, length: u64) -> std::io::Result<()> {
            self.backend.set_len(file, length)
        }
        fn sync(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            self.backend.sync(file)
        }
        fn unlink(&self, file: kasumi_kv::GroupFile) -> std::io::Result<()> {
            self.backend.unlink(file)
        }
        fn sync_names(&self) -> std::io::Result<()> {
            self.backend.sync_names()
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
            Database::builder(
                crate::test_utils::storage_admission(),
                *crate::test_utils::NODE_STORE_ID.as_bytes(),
                crate::test_utils::node_storage_config().cache,
            )
            .create_with_backend(CountedClose {
                backend: kasumi_kv::backends::InMemoryGroup::new(),
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

    fn close_and_dispose(database: &NodeDatabase) -> BackendNativeDisposition {
        let Some(closed) = database.close_direct_native() else {
            return BackendNativeDisposition::Retained;
        };
        if !matches!(
            closed.close().settlement(),
            DatabaseCloseSettlement::Settled | DatabaseCloseSettlement::Disposed
        ) {
            return BackendNativeDisposition::Retained;
        }
        drop(closed);
        if database
            .dispose_direct_native()
            .is_some_and(|report| report.disposal_complete())
        {
            BackendNativeDisposition::Drained
        } else {
            BackendNativeDisposition::Retained
        }
    }

    #[test]
    fn explicit_disposal_waits_for_live_handles_and_enters_native_close_once() {
        let (database, closes) = counted(CloseMode::Drained);
        let reader = database.begin_read().unwrap();
        let (outcome, allocations) =
            crate::allocation_tests::measure(|| close_and_dispose(&database));
        assert_eq!(outcome, BackendNativeDisposition::Retained);
        assert_eq!(allocations, 0);
        assert_eq!(closes.load(Ordering::SeqCst), 0);
        assert!(database.begin_read().is_err());
        assert!(database.begin_write().is_err());
        drop(reader);
        for _ in 0..2 {
            let (outcome, allocations) =
                crate::allocation_tests::measure(|| close_and_dispose(&database));
            assert_eq!(outcome, BackendNativeDisposition::Drained);
            assert_eq!(allocations, 0);
            assert_eq!(closes.load(Ordering::SeqCst), 1);
        }
        {
            let native = database.direct_native_report().unwrap();
            assert_eq!(
                native.close().settlement(),
                DatabaseCloseSettlement::Disposed
            );
            assert!(native.disposal_complete());
        }
        database.close().unwrap();
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn explicit_disposal_never_claims_or_reenters_an_unproved_native_close() {
        let (database, closes) = counted(CloseMode::Unproved);
        for _ in 0..2 {
            let (outcome, allocations) =
                crate::allocation_tests::measure(|| close_and_dispose(&database));
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
    fn explicit_disposal_after_failed_close_retains_without_reentry() {
        let (database, closes) = counted(CloseMode::Unproved);
        let first = database.close().unwrap_err();
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        let (outcome, allocations) =
            crate::allocation_tests::measure(|| close_and_dispose(&database));
        assert_eq!(outcome, BackendNativeDisposition::Retained);
        assert_eq!(allocations, 0);
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        let second = database.close().unwrap_err();
        assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
            &first.issues()[0],
            &second.issues()[0]
        ));
    }

    #[test]
    fn explicit_disposal_preserves_close_panic_without_claiming_drain_or_reentry() {
        let (database, closes) = counted(CloseMode::Panic);
        for _ in 0..2 {
            assert_eq!(
                close_and_dispose(&database),
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
