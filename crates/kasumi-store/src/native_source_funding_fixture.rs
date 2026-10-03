//! Test-only bridge to the actual registered opening. It deliberately owns no
//! ReaderRequest/census child, exposes no native transaction and cannot serve a
//! production TenantStorageReadView. Keep this entire module behind test-utils.
use super::*;
use kasumi_kv::{BoundSourceRead, NativeSourcePool, SourceReadCallError, SourceReadRights};

#[derive(Debug)]
pub enum NativeSourceFixtureError {
    Closed,
    Slot,
    Native(SourceReadCallError),
}
impl From<SourceReadCallError> for NativeSourceFixtureError {
    fn from(value: SourceReadCallError) -> Self {
        Self::Native(value)
    }
}
/// Fixed inline fixture state. Tests put it on the stack; a future boxed
/// registered owner must quote its actual enlarged containing layout.
pub struct NativeSourceFundingFixture {
    registration: StorageRegistration<DatabaseOwner>,
    pool: NativeSourcePool,
    rights: SourceReadRights,
    reads: [Option<BoundSourceRead>; 3],
}
impl RegisteredNodeOpening {
    pub fn queue_native_source_funding_fixture(
        &self,
    ) -> Result<NativeSourceFundingFixture, NativeSourceFixtureError> {
        self.queue_native_source_funding_with_provider_fixture(None)
    }
    pub fn queue_native_source_funding_with_provider_fixture(
        &self,
        expected: Option<Arc<dyn crate::NodeDiskMemoryAdmission>>,
    ) -> Result<NativeSourceFundingFixture, NativeSourceFixtureError> {
        let owner = self.registration.owner();
        let state = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) || state.phase != NodeOpeningPhase::Open {
            return Err(NativeSourceFixtureError::Closed);
        }
        let database = state
            .engine
            .database()
            .ok_or(NativeSourceFixtureError::Closed)?;
        let provider: Arc<dyn kasumi_kv::SourceMemoryProvider> =
            expected.unwrap_or_else(|| state.file.disk().memory().clone());
        Ok(NativeSourceFundingFixture {
            registration: self.registration.clone(),
            pool: database.queue_native_source_pool(provider),
            rights: database.queue_source_read_rights(),
            reads: [None, None, None],
        })
    }
}
impl NativeSourceFundingFixture {
    pub fn dispose_unbound_pool(&mut self) -> Result<(), kasumi_kv::SourceFundingCallError> {
        self.pool.dispose_unbound()
    }
    pub fn seal_pool(&mut self) {
        self.pool.seal();
    }
    /// Actual committed root advancement for the native-only fixture. These
    /// ordinary table/write allocations are explicitly outside lane funding.
    pub fn publish_generation(&self, tag: u8) -> anyhow::Result<()> {
        let state = self.registration.owner().state.lock();
        let database = state
            .engine
            .database()
            .ok_or_else(|| anyhow::anyhow!("fixture database closed"))?;
        let write = database.begin_write()?;
        {
            let mut table = write.open_table(crate::CATALOG)?;
            table.insert([tag; 32].as_slice(), [tag; 8].as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    pub fn pool(&self) -> &NativeSourcePool {
        &self.pool
    }
    pub fn rights(&self) -> kasumi_kv::SourceRightsReport<'_> {
        self.rights.report()
    }
    pub fn read(&self, slot: usize) -> Option<&BoundSourceRead> {
        self.reads.get(slot).and_then(Option::as_ref)
    }
    pub fn install(&mut self) -> Result<(), NativeSourceFixtureError> {
        let state = self.registration.owner().state.lock();
        let database = state
            .engine
            .retained_database()
            .ok_or(NativeSourceFixtureError::Closed)?;
        self.pool.install(database)?;
        if self.pool.is_ready() {
            self.rights.prepare_funded(database, &mut self.pool)?;
        }
        Ok(())
    }
    pub fn prepare(&mut self, slot: usize) -> Result<(), NativeSourceFixtureError> {
        let read = self
            .reads
            .get_mut(slot)
            .ok_or(NativeSourceFixtureError::Slot)?;
        if read.is_some() {
            return Err(NativeSourceFixtureError::Slot);
        }
        let owner = self.registration.owner();
        let state = owner.state.lock();
        if owner.stopped.load(Ordering::Acquire) {
            return Err(NativeSourceFixtureError::Closed);
        }
        let database = state
            .engine
            .retained_database()
            .ok_or(NativeSourceFixtureError::Closed)?;
        *read = Some(
            self.pool.queue_read(
                database
                    .database()
                    .ok_or(NativeSourceFixtureError::Closed)?,
            )?,
        );
        read.as_mut().unwrap().prepare(database, &self.rights)?;
        Ok(())
    }
    pub fn capture(&mut self, slot: usize) -> Result<(), NativeSourceFixtureError> {
        let state = self.registration.owner().state.lock();
        let database = state
            .engine
            .retained_database()
            .ok_or(NativeSourceFixtureError::Closed)?;
        self.reads
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(NativeSourceFixtureError::Slot)?
            .capture(database)?;
        Ok(())
    }
    pub fn prepare_history(&mut self, slot: usize) -> Result<(), NativeSourceFixtureError> {
        let state = self.registration.owner().state.lock();
        let database = state
            .engine
            .retained_database()
            .ok_or(NativeSourceFixtureError::Closed)?;
        self.reads
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(NativeSourceFixtureError::Slot)?
            .prepare_history(database)?;
        Ok(())
    }
    pub fn commit_history(&mut self, slot: usize) -> Result<(), NativeSourceFixtureError> {
        // Acquire actual opening custody before the bank/account/native suffix.
        let state = self.registration.owner().state.lock();
        let database = state
            .engine
            .retained_database()
            .ok_or(NativeSourceFixtureError::Closed)?;
        self.reads
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(NativeSourceFixtureError::Slot)?
            .commit_history(database)?;
        Ok(())
    }
    pub fn close_read(&mut self, slot: usize) -> Result<(), NativeSourceFixtureError> {
        let state = self.registration.owner().state.lock();
        let database = state
            .engine
            .retained_database()
            .ok_or(NativeSourceFixtureError::Closed)?;
        let read = self
            .reads
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(NativeSourceFixtureError::Slot)?;
        read.close(database)?;
        read.dispose_account();
        Ok(())
    }
    pub fn retire(&mut self) -> Result<(), NativeSourceFixtureError> {
        let state = self.registration.owner().state.lock();
        let database = state
            .engine
            .retained_database()
            .ok_or(NativeSourceFixtureError::Closed)?;
        self.rights.retire(database)?;
        drop(state);
        self.pool.seal();
        self.pool.dispose_sealed();
        Ok(())
    }
}

/// Separately admitted test-only ordinary native readers. These do not consume
/// publication byte lanes; no native reader escapes this bounded owner.
pub struct NativeSlotBlockers {
    registration: StorageRegistration<DatabaseOwner>,
    reads: Vec<Option<kasumi_kv::RetainedReadTransaction>>,
    acquisition: Observation<kasumi_kv::ReadAcquisitionFailure>,
    _credit: crate::DiskMemoryLease,
}
impl RegisteredNodeOpening {
    pub fn queue_native_slot_blockers_fixture(&self) -> io::Result<NativeSlotBlockers> {
        let provider = {
            let state = self.registration.owner().state.lock();
            state.file.disk().memory().clone()
        };
        // 256 actual native slots minus the exact two protected rights. The
        // vector's actual backing is admitted before allocation, independently
        // of the bank and of each ordinary native reader's own constructors.
        let credit = provider.reserve_installed(crate::disk_memory::allocation::<
            Option<kasumi_kv::RetainedReadTransaction>,
        >(254)?)?;
        let mut reads = Vec::with_capacity(254);
        reads.resize_with(254, || None);
        Ok(NativeSlotBlockers {
            registration: self.registration.clone(),
            reads,
            acquisition: Observation::NotEntered,
            _credit: credit,
        })
    }
}
impl NativeSlotBlockers {
    pub fn begin(&mut self) {
        if !matches!(self.acquisition, Observation::NotEntered) {
            return;
        }
        let state = self.registration.owner().state.lock();
        let Some(database) = state.engine.database() else {
            return;
        };
        self.acquisition = Observation::Entered;
        self.acquisition = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for read in &mut self.reads {
                *read = Some(database.begin_read_retained()?);
            }
            Ok(())
        })) {
            Ok(result) => Observation::Returned(result),
            Err(payload) => Observation::Panicked(payload),
        };
    }
    pub fn count(&self) -> usize {
        self.reads.iter().filter(|read| read.is_some()).count()
    }
    pub fn acquisition(&self) -> TerminalObservation<'_, kasumi_kv::ReadAcquisitionFailure> {
        self.acquisition.borrow()
    }
    pub fn close(&mut self) -> bool {
        let state = self.registration.owner().state.lock();
        let Some(database) = state.engine.retained_database() else {
            return false;
        };
        for read in self.reads.iter_mut().flatten() {
            read.close(database);
            read.dispose_settled(database);
        }
        self.reads
            .iter()
            .flatten()
            .all(|read| read.report().settlement() == kasumi_kv::ReadCloseSettlement::Disposed)
    }
}
