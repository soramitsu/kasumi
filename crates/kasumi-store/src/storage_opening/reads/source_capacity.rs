//! Production ownership facade over the registered two-right source corridor.
//! Construction is deliberately explicit: no caller gets a usable capacity by
//! dropping an error, recovering an ordinary reader, or supplying byte counts.
use super::*;

/// Owns the existing control request, metadata bank and exactly two publication
/// rights. There is no second registry or shadow funding pool in this facade.
/// Its enclosing construction/SourceRoots owner accounts for this inline shell.
pub struct RegisteredSourceCapacity {
    pub(super) pool: Option<RegisteredSourcePool>,
    pub(super) database: StorageRegistration<DatabaseOwner>,
    pub(super) provider: Arc<dyn NodeDiskMemoryAdmission>,
    pub(super) control_id: StorageOwnerId,
}

/// Borrowed original installation observations from the actual registered pool.
/// The guard exposes no mutable phase, account, acknowledgment or native reader.
pub struct SourceCapacityReport<'a> {
    state: MutexGuard<'a, SourcePoolState>,
}
impl SourceCapacityReport<'_> {
    pub fn phase(&self) -> SourcePoolPhase {
        self.state.phase
    }
    pub fn has_failures(&self) -> bool {
        self.state.has_failures()
    }
    pub fn installation(&self) -> TerminalObservation<'_, io::Error> {
        self.state.install.view()
    }
    pub fn metadata_preparation(
        &self,
        index: usize,
    ) -> Option<(
        TerminalObservation<'_, io::Error>,
        Option<crate::SourceMetadataCallError>,
    )> {
        let preparation = self.state.preparations.get(index)?;
        Some((preparation.original(), preparation.protocol()))
    }
    pub fn native_installation(&self) -> TerminalObservation<'_, SourceReadCallError> {
        self.state.native_install.view()
    }
    pub fn native_pool_installation(
        &self,
    ) -> Option<TerminalObservation<'_, kasumi_kv::SourceFundingError>> {
        self.state
            .native
            .as_ref()
            .map(NativeSourcePool::installation)
    }
    pub fn native_pool_protocol(&self) -> Option<kasumi_kv::SourceFundingCallError> {
        self.state
            .native
            .as_ref()
            .and_then(NativeSourcePool::protocol_error)
    }
    pub fn with_rights_preparation<R>(
        &self,
        inspect: impl FnOnce(TerminalObservation<'_, kasumi_kv::StorageError>) -> R,
    ) -> Option<R> {
        self.state
            .rights
            .as_ref()
            .map(|rights| inspect(rights.report().preparation()))
    }
}

/// The original registered construction remains owned on failure. Inspection
/// borrows the fixed control/report observations; it cannot acknowledge them.
pub struct SourceCapacityFailure {
    capacity: RegisteredSourceCapacity,
}
impl std::fmt::Debug for SourceCapacityFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceCapacityFailure")
            .field("id", &self.capacity.control_id)
            .field("phase", &self.capacity.phase())
            .finish()
    }
}
impl std::fmt::Display for SourceCapacityFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("protected source construction failed; original registered custody retained")
    }
}
impl std::error::Error for SourceCapacityFailure {}
impl SourceCapacityFailure {
    pub fn report(&self) -> Option<SourceCapacityReport<'_>> {
        self.capacity.report()
    }
    pub fn owner_id(&self) -> StorageOwnerId {
        self.capacity.control_id
    }
    pub fn phase(&self) -> Option<SourcePoolPhase> {
        self.capacity.phase()
    }
    pub fn with_control_observation<R>(
        &self,
        inspect: impl FnOnce(
            TerminalObservation<'_, io::Error>,
            Option<crate::SourceMetadataCallError>,
            TerminalObservation<'_, Infallible>,
        ) -> R,
    ) -> Option<R> {
        self.capacity.with_control_observation(inspect)
    }
}

/// A queued and prepared protected root. The real native capture remains
/// deferred until the producer has completed its durable publication. Public
/// ordinary begin/read/fork on its registered reader cannot promote its phase.
pub struct PreparedRegisteredSource {
    reader: RegisteredNodeRead,
}
impl PreparedRegisteredSource {
    /// The Store publisher checks native/provider identity and source phase before
    /// entering its write. A foreign or already entered source has no effect.
    pub(crate) fn require_prepared_store(&self, store: &crate::TenantStore) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.reader.phase() == NodeReadPhase::SourcePrepared,
            "publication source is not prepared"
        );
        let provider = self.reader.provider();
        anyhow::ensure!(
            Arc::ptr_eq(store.persistent_disk().memory(), &provider)
                && Arc::ptr_eq(store.scratch_disk().memory(), &provider),
            "publication source provider differs"
        );
        store.node.db.require_registered_read(&self.reader)?;
        Ok(())
    }

    /// Called only while the actual Store publisher retains the native
    /// CommittedWrite token. No writer, including another catalog facade, can
    /// intervene. The exact first failure stays in this registered reader.
    pub(crate) fn capture_published_store(
        &mut self,
        store: &crate::TenantStore,
    ) -> anyhow::Result<()> {
        self.require_prepared_store(store)?;
        self.reader.source_capture();
        if self.reader.phase() != NodeReadPhase::SourceCaptured {
            return Err(crate::NodeScopedReadFailure::new(
                self.reader.retain_report_facade(),
                "protected source capture after publication",
                None,
            )
            .into());
        }
        Ok(())
    }

    pub fn reader_id(&self) -> StorageOwnerId {
        self.reader.id()
    }
    pub fn phase(&self) -> NodeReadPhase {
        self.reader.phase()
    }
    #[allow(
        clippy::result_large_err,
        reason = "The original failure keeps the actual registered source inline; boxing would require a new allocation on a protected failure path."
    )]
    pub fn capture(self) -> Result<RegisteredNodeRead, crate::NodeScopedReadFailure> {
        self.reader.source_capture();
        if self.reader.phase() == NodeReadPhase::SourceCaptured {
            Ok(self.reader)
        } else {
            Err(crate::NodeScopedReadFailure::new(
                self.reader,
                "protected source capture",
                None,
            ))
        }
    }
    /// Consuming cancellation for an Engine lane. A native-clean but pending
    /// census cell retains its exact provider/id diagnostic for positive retry.
    pub fn cancel_settled(self) -> anyhow::Result<()> {
        let phase = self.reader.finish();
        if phase != NodeReadPhase::Finished || self.reader.report().has_failures() {
            return Err(crate::NodeScopedReadFailure::new(
                self.reader,
                "protected source cancellation",
                None,
            )
            .into());
        }
        let id = self.reader.id();
        let provider = self.reader.provider();
        let disposition = self.reader.retire();
        if disposition != StorageCensusDisposition::Retired {
            return Err(crate::NodeScopedReadRetirement::after_source_close(
                provider,
                id,
                disposition,
            )
            .into());
        }
        Ok(())
    }
    #[allow(
        clippy::result_large_err,
        reason = "The original failure keeps the actual registered source inline; boxing would require a new allocation on a protected failure path."
    )]
    pub fn cancel(self) -> Result<StorageCensusDisposition, crate::NodeScopedReadFailure> {
        let phase = self.reader.finish();
        if phase != NodeReadPhase::Finished || self.reader.report().has_failures() {
            return Err(crate::NodeScopedReadFailure::new(
                self.reader,
                "protected source cancellation",
                None,
            ));
        }
        // This is the exact observed disposition, not an inferred successful
        // close. The construction owner/census retains a busy native tail.
        Ok(self.reader.retire())
    }
}

impl RegisteredNodeOpening {
    /// Queue the actual registered installation before executing its provider
    /// callbacks. A partial installation is discoverable under this exact ID.
    pub fn queue_source_capacity(&self) -> io::Result<RegisteredSourceCapacity> {
        let owner = self.registration.owner();
        if owner.stopped.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        {
            let opening = owner.state.lock();
            if opening.phase != NodeOpeningPhase::Open {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
        let provider = owner.provider.clone();
        let mut claim = provider
            .storage_census()
            .claim_source_control(&provider, &self.registration)?;
        let control_id = claim.id();
        let registered =
            provider
                .storage_census()
                .register_source_control(provider.clone(), &mut claim, || SourcePoolRequest {
                    id: control_id,
                    database: self.registration.clone(),
                    provider: provider.clone(),
                    facades: AtomicUsize::new(0),
                    state: Mutex::new(SourcePoolState::new()),
                });
        let pool = registered.ok().map(|registration| {
            registration.owner().facades.fetch_add(1, Ordering::AcqRel);
            RegisteredSourcePool {
                registration,
                released: AtomicBool::new(false),
            }
        });
        Ok(RegisteredSourceCapacity {
            pool,
            database: self.registration.clone(),
            provider,
            control_id,
        })
    }
}
impl RegisteredSourceCapacity {
    /// Test scheduling seam over the actual registered report. The cloned
    /// registration lets the callback consume the facade without borrowing it.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_report_held_for_test<R>(self, work: impl FnOnce(Self) -> R) -> R {
        let actual = self
            .pool
            .as_ref()
            .expect("installed source pool")
            .registration
            .clone();
        let report = actual.owner().state.lock();
        let result = work(self);
        drop(report);
        drop(actual);
        result
    }
    pub fn report(&self) -> Option<SourceCapacityReport<'_>> {
        Some(SourceCapacityReport {
            state: self.pool.as_ref()?.registration.owner().state.lock(),
        })
    }
    pub fn owner_id(&self) -> StorageOwnerId {
        self.control_id
    }
    pub fn phase(&self) -> Option<SourcePoolPhase> {
        self.pool
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
            .provider
            .storage_census()
            .source_control_observation(self.control_id)?;
        Some(inspect(
            report.original(),
            report.protocol(),
            report.cleanup(),
        ))
    }
    /// The owner, including failed partial construction, crosses this consuming
    /// boundary. Readiness requires positive metadata and native installation.
    pub fn install(self) -> Result<Self, SourceCapacityFailure> {
        if let Some(pool) = &self.pool {
            pool.install();
        }
        if self.phase() == Some(SourcePoolPhase::Ready) {
            Ok(self)
        } else {
            Err(SourceCapacityFailure { capacity: self })
        }
    }
    pub fn prepare(&self, right: usize) -> anyhow::Result<PreparedRegisteredSource> {
        let reader = self
            .pool
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
            .queue(right)?;
        reader.source_prepare();
        if reader.phase() != NodeReadPhase::SourcePrepared {
            return Err(crate::NodeScopedReadFailure::new(
                reader,
                "protected source preparation",
                None,
            )
            .into());
        }
        Ok(PreparedRegisteredSource { reader })
    }
    pub fn seal(&self) {
        if let Some(pool) = &self.pool {
            let request = pool.registration.owner();
            if !pool.released.swap(true, Ordering::AcqRel) {
                request.facades.fetch_sub(1, Ordering::AcqRel);
            }
            let _ = request.drive();
        } else {
            let _ = self
                .provider
                .storage_census()
                .cancel_source_control(self.control_id);
        }
    }
    pub fn drain(&self) {
        drain_source_owners(&self.provider, self.database.id());
    }
}

impl Drop for RegisteredSourceCapacity {
    fn drop(&mut self) {
        // Seal is explicit and non-destructive to active children. Their exact
        // registered owners remain discoverable until positive retirement.
        self.seal();
    }
}

/// The same construction owns pending/failed drain; only a positively finished
/// native/report pool can shed its facade and produce an exact census token.
pub enum SourceCapacityClose {
    Pending(RegisteredSourceCapacity),
    Retained(SourceCapacityFailure),
    Retiring(SourceCapacityRetirement),
}
/// This token is created only after the real source pool has finished without
/// any original failure and its last production facade has been consumed.
pub struct SourceCapacityRetirement {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    id: StorageOwnerId,
}
impl SourceCapacityRetirement {
    pub fn has_terminal_failure(&self) -> bool {
        self.provider
            .storage_census()
            .retirement_is_terminal(self.id)
    }
    pub fn id(&self) -> StorageOwnerId {
        self.id
    }
    pub fn retry(&self) -> StorageCensusDisposition {
        match self.provider.storage_census().drain_owner(self.id) {
            StorageCensusDisposition::Stale | StorageCensusDisposition::Retired => {
                StorageCensusDisposition::Retired
            }
            other => other,
        }
    }
}
impl RegisteredSourceCapacity {
    pub fn close(self) -> SourceCapacityClose {
        self.seal();
        self.drain();
        // Drive and census retirement deliberately yield on contention. Do
        // not follow them with a blocking public report guard: the owner may
        // be inspected by another caller while shutdown is being polled.
        let observation = match self.pool.as_ref() {
            Some(pool) => pool
                .registration
                .owner()
                .state
                .try_lock()
                .map(|state| (Some(state.phase), state.has_failures())),
            None => Some((None, true)),
        };
        let Some((phase, failed)) = observation else {
            return SourceCapacityClose::Pending(self);
        };
        if failed || phase == Some(SourcePoolPhase::Retained) {
            return SourceCapacityClose::Retained(SourceCapacityFailure { capacity: self });
        }
        if phase != Some(SourcePoolPhase::Finished) {
            return SourceCapacityClose::Pending(self);
        }
        let retirement = SourceCapacityRetirement {
            provider: self.provider.clone(),
            id: self.control_id,
        };
        // SourcePoolRequest cannot dispose its payload until this exact Arc
        // facade is gone. The token performs the separate census observation.
        drop(self);
        SourceCapacityClose::Retiring(retirement)
    }
}

impl std::fmt::Debug for SourceCapacityRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceCapacityRetirement")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for SourceCapacityRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("source capacity census retirement retains its actual owner")
    }
}
impl std::error::Error for SourceCapacityRetirement {}

#[cfg(test)]
#[path = "source_capacity_tests.rs"]
mod tests;
