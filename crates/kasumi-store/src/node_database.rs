//! A stopped node retains the exact redb owner until accepted transactions end.
use kasumi_types::drain::{DrainFailure, DrainReport, DrainResult};
use parking_lot::Mutex;
use redb::{Database, ReadTransaction, ReadableDatabase, TransactionError, WriteTransaction};
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
    busy: DrainReport,
    terminal: DrainReport,
    interrupted: Option<DrainFailure>,
}

struct ClosePanic(Mutex<Box<dyn Any + Send>>);
impl fmt::Debug for ClosePanic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("redb close panicked; original payload retained")
    }
}
impl fmt::Display for ClosePanic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Borrow the retained payload without exposing its potentially sensitive
        // content or treating its destructor as evidence of physical drain.
        let _payload = self.0.lock();
        f.write_str("redb close panicked; ownership completion is unproven")
    }
}
impl std::error::Error for ClosePanic {}

pub(crate) struct NodeDatabase {
    component: &'static str,
    stopped: AtomicBool,
    state: Mutex<State>,
}

impl NodeDatabase {
    pub(crate) fn new(database: Database, component: &'static str) -> Self {
        Self {
            component,
            stopped: AtomicBool::new(false),
            state: Mutex::new(State {
                database: Some(Arc::new(database)),
                busy: DrainReport::default(),
                terminal: DrainReport::default(),
                interrupted: None,
            }),
        }
    }

    fn accepted(&self) -> Result<Arc<Database>, TransactionError> {
        let state = self.state.lock();
        if self.stopped.load(Ordering::Acquire) {
            return Err(redb::StorageError::DatabaseClosed.into());
        }
        state
            .database
            .clone()
            .ok_or_else(|| redb::StorageError::DatabaseClosed.into())
    }

    pub(crate) fn begin_read(&self) -> Result<ReadTransaction, TransactionError> {
        self.accepted()?.begin_read()
    }

    pub(crate) fn begin_write(&self) -> Result<WriteTransaction, TransactionError> {
        // A queued writer keeps an Arc, never this state mutex. Close can report
        // retained ownership promptly while the original writer remains queued.
        self.accepted()?.begin_write()
    }

    pub(crate) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    pub(crate) fn close(&self) -> DrainResult {
        self.stop();
        let mut state = self.state.lock();
        if let Some(failure) = &state.interrupted {
            return Err(failure.clone());
        }
        let Some(database) = state.database.take() else {
            return state.terminal.complete();
        };
        let result = match Arc::try_unwrap(database) {
            Ok(database) => match std::panic::catch_unwind(AssertUnwindSafe(|| database.close())) {
                Ok(Ok(())) => return state.terminal.complete(),
                Ok(Err(redb::CloseError::Storage(error))) => {
                    let issue = state.terminal.record(self.component, 0, error.into());
                    let failure = DrainFailure::retained(issue);
                    state.interrupted = Some(failure.clone());
                    return Err(failure);
                }
                Ok(Err(redb::CloseError::Busy(database))) => Arc::new(database),
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
            anyhow::anyhow!("accepted redb callers or transaction handles are still live"),
        );
        Err(DrainFailure::retained(issue))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::StorageBackend;

    fn memory() -> NodeDatabase {
        NodeDatabase::new(
            Database::builder(crate::test_utils::storage_admission())
                .create_with_backend(redb::backends::InMemoryBackend::new())
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
        assert!(queued, "second actual writer never reached redb admission");
        assert_eq!(
            outcome.unwrap_err().completion(),
            kasumi_types::drain::DrainCompletion::Retained
        );
        database.close().unwrap();
    }

    #[derive(Debug, PartialEq)]
    struct OriginalClosePanic(u64);
    #[derive(Debug)]
    struct PanicBackend(redb::backends::InMemoryBackend);
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
        fn close(&self) -> redb::BackendCloseOutcome {
            std::panic::panic_any(OriginalClosePanic(41))
        }
    }

    #[test]
    fn close_panic_retains_original_payload_and_cannot_become_clean_on_retry() {
        let database = NodeDatabase::new(
            Database::builder(crate::test_utils::storage_admission())
                .create_with_backend(PanicBackend(redb::backends::InMemoryBackend::new()))
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
    struct UnprovedCloseBackend(redb::backends::InMemoryBackend);
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
        fn close(&self) -> redb::BackendCloseOutcome {
            redb::BackendCloseOutcome::retained_result(Ok(()))
        }
    }
    #[test]
    fn logical_close_success_without_native_evidence_never_becomes_complete_on_retry() {
        let database = NodeDatabase::new(
            Database::builder(crate::test_utils::storage_admission())
                .create_with_backend(UnprovedCloseBackend(redb::backends::InMemoryBackend::new()))
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
}
