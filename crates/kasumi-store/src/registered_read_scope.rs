//! Exact census custody for a bounded installed-node read body.
use super::*;
use std::any::Any;
use std::panic::AssertUnwindSafe;
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};

/// Immutable original read observations with separately drainable native
/// custody. A positively disposed routine failure may outlive its census entry
/// without pinning its database. Unknown failures retain their actual facade.
pub struct NodeScopedReadFailure {
    native: Mutex<Option<RegisteredNodeRead>>,
    report: crate::storage_opening::AdmittedReadReport,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
    stage: &'static str,
    body_error: Option<anyhow::Error>,
    detached: AtomicBool,
    retired: AtomicBool,
    retiring: AtomicBool,
    retirement_panic: OnceLock<Mutex<Box<dyn Any + Send>>>,
}
impl NodeScopedReadFailure {
    pub(crate) fn new(
        reader: RegisteredNodeRead,
        stage: &'static str,
        body_error: Option<anyhow::Error>,
    ) -> Self {
        let report = reader.admitted_report();
        let provider = reader.provider();
        let id = reader.id();
        Self {
            native: Mutex::new(Some(reader)),
            report,
            provider,
            id,
            stage,
            body_error,
            detached: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            retiring: AtomicBool::new(false),
            retirement_panic: OnceLock::new(),
        }
    }
    pub(crate) fn from_view(reader: &RegisteredNodeRead, body_error: anyhow::Error) -> Self {
        Self::new(reader.retain_report_facade(), "view read", Some(body_error))
    }
    pub fn reader_id(&self) -> StorageOwnerId {
        self.id
    }
    pub fn phase(&self) -> NodeReadPhase {
        self.report.phase()
    }
    /// Original observations remain in the same preadmitted allocation even
    /// after routine native retirement. No mutable reader capability escapes.
    pub fn report(&self) -> NodeReadReport<'_> {
        self.report.report()
    }
    pub fn stage(&self) -> &'static str {
        self.stage
    }
    pub fn body_error(&self) -> Option<&anyhow::Error> {
        self.body_error.as_ref()
    }
    pub fn has_retirement_panic(&self) -> bool {
        self.retirement_panic.get().is_some()
    }

    /// Retire only exact recognized routine outcomes after positive native
    /// release AND disposal, or a native clean acquisition refusal. This preserves every original observation and
    /// needs no new admission. Concurrent observations/aliases may leave the
    /// exact census Retained; retry this same error rather than reopening.
    /// Unknown I/O, a panic, or uncertain native close is never acknowledged.
    pub fn try_retire_routine(&self) -> StorageCensusDisposition {
        if self.retired.load(Ordering::Acquire) {
            return StorageCensusDisposition::Retired;
        }
        if self.retirement_panic.get().is_some()
            || self
                .retiring
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return StorageCensusDisposition::Retained;
        }
        struct Retiring<'a>(&'a AtomicBool);
        impl Drop for Retiring<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        let _retiring = Retiring(&self.retiring);
        // No native/provider/census callback runs under this custody mutex.
        let mut reader = self.native.lock().take();
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            if let Some(active) = reader.as_ref() {
                // An arbitrary independent body failure may own another scope.
                // Only Store's precise Reported marker (or no body error) is
                // covered by this routine reader retirement operation.
                if self.body_error.as_ref().is_some_and(|error| {
                    !matches!(
                        error.downcast_ref::<NodeReadAccessError>(),
                        Some(NodeReadAccessError::Reported)
                    )
                }) || !active.try_acknowledge_routine()
                {
                    return None;
                }
                // Original observations already have this error's independent
                // admitted report owner. Drop the actual facade only now.
                self.detached.store(true, Ordering::Release);
                Some(
                    reader
                        .take()
                        .expect("checked native reader")
                        .retire_acknowledged(),
                )
            } else if self.detached.load(Ordering::Acquire) && self.report.try_routine_diagnostic()
            {
                Some(self.provider.storage_census().drain_owner(self.id))
            } else {
                None
            }
        }));
        if let Some(reader) = reader {
            *self.native.lock() = Some(reader);
        }
        match result {
            Ok(Some(StorageCensusDisposition::Retired | StorageCensusDisposition::Stale))
                if self.report.try_routine_diagnostic() =>
            {
                // This exact generation previously existed. Native disposal
                // or clean acquisition refusal was proved before detachment.
                // Stale now proves its census lease/cell already retired.
                self.retired.store(true, Ordering::Release);
                StorageCensusDisposition::Retired
            }
            Ok(Some(StorageCensusDisposition::Retired | StorageCensusDisposition::Stale)) => {
                StorageCensusDisposition::Retained
            }
            Ok(Some(disposition)) => disposition,
            Ok(None) => StorageCensusDisposition::Retained,
            Err(payload) => {
                let _ = self.retirement_panic.set(Mutex::new(payload));
                StorageCensusDisposition::Retained
            }
        }
    }
}
impl std::fmt::Debug for NodeScopedReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeScopedReadFailure")
            .field("reader_id", &self.id)
            .field("stage", &self.stage)
            .field("reader_phase", &self.phase())
            .field("body_error", &self.body_error)
            .field("native_retired", &self.retired.load(Ordering::Acquire))
            .field("retirement_panic", &self.has_retirement_panic())
            .finish()
    }
}
impl std::fmt::Display for NodeScopedReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "registered read {:?} failed at {}", self.id, self.stage)
    }
}
impl std::error::Error for NodeScopedReadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.body_error.as_ref().map(|error| error.as_ref() as _)
    }
}

/// A clean native close whose exact census cell still needs a retirement retry.
pub struct NodeScopedReadRetirement {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
    disposition: StorageCensusDisposition,
    body_error: Option<anyhow::Error>,
}
impl NodeScopedReadRetirement {
    pub(crate) fn after_source_close(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
        disposition: StorageCensusDisposition,
    ) -> Self {
        Self {
            provider,
            id,
            disposition,
            body_error: None,
        }
    }
    pub fn id(&self) -> StorageOwnerId {
        self.id
    }
    pub fn disposition(&self) -> StorageCensusDisposition {
        self.disposition
    }
    pub fn retry_retirement(&self) -> StorageCensusDisposition {
        match self.provider.storage_census().drain_owner(self.id) {
            // This private constructor captured an actual generation only
            // after its native release/disposal positively completed. Another
            // exact drainer can have finished its census retirement already.
            StorageCensusDisposition::Stale | StorageCensusDisposition::Retired => {
                StorageCensusDisposition::Retired
            }
            pending => pending,
        }
    }
    pub fn body_error(&self) -> Option<&anyhow::Error> {
        self.body_error.as_ref()
    }
}
impl std::fmt::Debug for NodeScopedReadRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeScopedReadRetirement")
            .field("id", &self.id)
            .field("disposition", &self.disposition)
            .field("body_error", &self.body_error)
            .finish()
    }
}
impl std::fmt::Display for NodeScopedReadRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "registered read {:?} retirement {:?}",
            self.id, self.disposition
        )
    }
}
impl std::error::Error for NodeScopedReadRetirement {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.body_error.as_ref().map(|error| error.as_ref() as _)
    }
}

impl NodeStore {
    pub(crate) fn begin_registered_read(&self) -> Result<RegisteredNodeRead> {
        let reader = self.db.queue_registered_read()?;
        if reader.begin() != NodeReadPhase::Active {
            return Err(NodeScopedReadFailure::new(reader, "begin", None).into());
        }
        Ok(reader)
    }

    pub(crate) fn begin_prepared_registered_read(
        &self,
        reader: RegisteredNodeRead,
    ) -> Result<RegisteredNodeRead> {
        match reader.begin_unbegun() {
            Some(NodeReadPhase::Active) => Ok(reader),
            Some(_) => Err(NodeScopedReadFailure::new(reader, "prepared begin", None).into()),
            None => Err(
                NodeScopedReadFailure::new(reader, "prepared begin already entered", None).into(),
            ),
        }
    }

    /// Cancel only an unbegun queued view. A recovered facade may have changed
    /// its observations: preserve that exact outcome instead of acknowledging it.
    pub(crate) fn cancel_queued_registered_read<T>(
        &self,
        reader: RegisteredNodeRead,
        result: Result<T>,
    ) -> Result<T> {
        if reader.finish() != NodeReadPhase::Cancelled || reader.report().has_failures() {
            return Err(
                NodeScopedReadFailure::new(reader, "cancel queued view", result.err()).into(),
            );
        }
        let id = reader.id();
        // This never acknowledges observations added after the clean check.
        // A racing unknown failure therefore keeps the census child retained.
        let disposition = reader.retire_acknowledged();
        if disposition != StorageCensusDisposition::Retired {
            return Err(NodeScopedReadRetirement {
                provider: self.persistent_disk().memory().clone(),
                id,
                disposition,
                body_error: result.err(),
            }
            .into());
        }
        result
    }

    pub(crate) fn fork_registered_read(
        &self,
        parent: &RegisteredNodeRead,
    ) -> Result<RegisteredNodeRead> {
        let reader = self.db.fork_registered_read(parent)?;
        if reader.phase() != NodeReadPhase::Active {
            return Err(NodeScopedReadFailure::new(reader, "fork", None).into());
        }
        Ok(reader)
    }

    pub(crate) fn with_registered_read<T>(
        &self,
        body: impl FnOnce(&RegisteredNodeRead) -> Result<T>,
    ) -> Result<T> {
        let reader = self.begin_registered_read()?;
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| body(&reader)));
        match result {
            Ok(result) => self.settle_registered_read(reader, result),
            Err(payload) => {
                // Transfer the original payload into the exact census child.
                // Re-unwinding it would consume that original and let a later
                // parent drive mistake the native close for clean success.
                reader.preserve_body_panic(payload);
                let _ = reader.finish();
                Err(NodeScopedReadFailure::new(reader, "body panic", None).into())
            }
        }
    }

    pub(crate) fn settle_registered_read<T>(
        &self,
        reader: RegisteredNodeRead,
        result: Result<T>,
    ) -> Result<T> {
        let phase = reader.finish();
        if phase != NodeReadPhase::Finished || reader.report().has_failures() {
            return Err(NodeScopedReadFailure::new(
                reader,
                if phase == NodeReadPhase::Finished {
                    "body"
                } else {
                    "finish"
                },
                result.err(),
            )
            .into());
        }
        let id = reader.id();
        let provider = reader.provider();
        let disposition = reader.retire();
        if disposition != StorageCensusDisposition::Retired {
            return Err(NodeScopedReadRetirement {
                provider,
                id,
                disposition,
                body_error: result.err(),
            }
            .into());
        }
        result
    }
}
