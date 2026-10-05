//! Retained protected-source acquisition. These APIs prepare real native
//! assets; they do not provide Engine source byte lanes or Store activation.
use super::source_funding::SourceFundingIdentity;
use super::*;
use crate::core::SourceReadContext;
use crate::snapshot_pins::{
    HistoryPinRight, PendingSourceRights, PreparedProtectedPin, RightsRetirement,
};
use crate::tables::source_read::{ReadRetirementObserver, SourceBacking, SourceDatabase};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceReadCallError {
    ForeignDatabase,
    ForeignRights,
    RightsNotReady,
    FundingRequired,
    ForeignFunding,
    WrongPhase,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceRightsSettlement {
    Queued,
    Ready,
    Retained,
    Disposed,
    DisposalUncertain,
}
/// Native result of retiring this facade, independent of later byte disposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceRightsNativeRetirement {
    NotEntered,
    NoLanesInstalled,
    OtherHoldersRetainLanes,
    LanesRetired,
    Retained,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceReadSettlement {
    Queued,
    Prepared,
    Ready,
    Retained,
    Cancelled,
    Disposed,
    DisposalUncertain,
    Transferred,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceHistorySettlement {
    Queued,
    Prepared,
    Committed,
    Cancelled,
    Retained,
    Disposed,
    DisposalUncertain,
}

fn require_database(
    binding: &Option<SourceDatabase>,
    database: &RetainedDatabase,
) -> Result<(), SourceReadCallError> {
    match binding {
        Some(binding)
            if database
                .database
                .as_ref()
                .is_some_and(|db| binding.belongs_to(db)) =>
        {
            Ok(())
        }
        Some(_) => Err(SourceReadCallError::ForeignDatabase),
        None => Err(SourceReadCallError::WrongPhase),
    }
}
fn fence_attempt(binding: &SourceDatabase, attempt: &Attempt<StorageError>) {
    let failed = match attempt {
        Attempt::Unwound(_) | Attempt::Running => true,
        Attempt::Done(Err(StorageError::Core(error))) => error.fences_owner(),
        _ => false,
    };
    if failed {
        binding.fence();
    }
}

#[must_use]
pub struct SourceReadRights {
    binding: Option<SourceDatabase>,
    context: Option<SourceReadContext>,
    native: Option<PendingSourceRights>,
    // Retained through native and context disposal, including unwind.
    funding: Option<SourceFundingIdentity>,
    preparation: Attempt<StorageError>,
    retirement: Attempt<StorageError>,
    native_retirement: SourceRightsNativeRetirement,
    disposal: Attempt<Infallible>,
    settlement: SourceRightsSettlement,
}
pub struct SourceRightsReport<'a> {
    owner: &'a SourceReadRights,
}
impl SourceRightsReport<'_> {
    pub fn settlement(&self) -> SourceRightsSettlement {
        self.owner.settlement
    }
    pub fn preparation(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.preparation.view()
    }
    pub fn disposal(&self) -> TerminalObservation<'_, Infallible> {
        self.owner.disposal.view()
    }
    pub fn retirement(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.retirement.view()
    }
    pub fn native_retirement(&self) -> SourceRightsNativeRetirement {
        self.owner.native_retirement
    }
    pub fn retains_database(&self) -> bool {
        self.owner.binding.is_some()
    }
}
impl Database {
    pub fn queue_source_read_rights(&self) -> SourceReadRights {
        SourceReadRights {
            binding: Some(SourceDatabase::new(self)),
            context: None,
            native: Some(PendingSourceRights::new()),
            funding: None,
            preparation: Attempt::Pending,
            retirement: Attempt::Pending,
            native_retirement: SourceRightsNativeRetirement::NotEntered,
            disposal: Attempt::Pending,
            settlement: SourceRightsSettlement::Queued,
        }
    }
    pub fn queue_source_read(&self) -> RetainedSourceRead {
        RetainedSourceRead {
            retirement_observer: None,
            native_retirement: Attempt::Pending,
            binding: Some(SourceDatabase::new(self)),
            resources: Some(ReadResources {
                context: None,
                backing: SourceBacking::new(),
                pin: None,
                funding: None,
            }),
            reader: None,
            preparation: Attempt::Pending,
            capture: Attempt::Pending,
            cancellation: Attempt::Pending,
            disposal: Attempt::Pending,
            settlement: SourceReadSettlement::Queued,
        }
    }
}
impl SourceReadRights {
    #[cfg(test)]
    pub(crate) fn corrupt_retirement_for_test(&self, poison: bool) {
        let native = self.native.as_ref().unwrap();
        if poison {
            native.poison_for_test();
        } else {
            native.remove_lane_for_test();
        }
    }
    pub fn report(&self) -> SourceRightsReport<'_> {
        SourceRightsReport { owner: self }
    }
    pub fn prepare(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceRightsReport<'_>, SourceReadCallError> {
        require_database(&self.binding, database)?;
        if !matches!(self.retirement, Attempt::Pending) {
            return Err(SourceReadCallError::WrongPhase);
        }
        if self.funding.is_some() {
            return Err(SourceReadCallError::FundingRequired);
        }
        Ok(self.prepare_with(|native, context| native.prepare(&context.pins)))
    }
    pub fn prepare_funded(
        &mut self,
        database: &RetainedDatabase,
        pool: &mut NativeSourcePool,
    ) -> Result<SourceRightsReport<'_>, SourceReadCallError> {
        require_database(&self.binding, database)?;
        if !pool.belongs_to_database(database) {
            return Err(SourceReadCallError::ForeignFunding);
        }
        if !matches!(self.retirement, Attempt::Pending)
            || !matches!(self.preparation, Attempt::Pending)
        {
            return Err(SourceReadCallError::WrongPhase);
        }
        self.funding = Some(pool.binding_token()?);
        Ok(self.prepare_with(|native, context| native.prepare_funded(&context.pins, pool)))
    }
    fn prepare_with(
        &mut self,
        prepare: impl FnOnce(&mut PendingSourceRights, &SourceReadContext) -> Result<(), CoreError>,
    ) -> SourceRightsReport<'_> {
        let binding = self.binding.as_ref().unwrap();
        self.preparation.run(|| {
            self.context = Some(binding.context()?);
            prepare(
                self.native.as_mut().unwrap(),
                self.context.as_ref().unwrap(),
            )?;
            binding.check_local()?;
            Ok(())
        });
        fence_attempt(binding, &self.preparation);
        self.settlement = if self.preparation.succeeded() {
            SourceRightsSettlement::Ready
        } else {
            SourceRightsSettlement::Retained
        };
        self.report()
    }
    pub fn retire(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceRightsReport<'_>, SourceReadCallError> {
        if self.settlement == SourceRightsSettlement::Disposed {
            return Ok(self.report());
        }
        require_database(&self.binding, database)?;
        self.retirement.run(|| {
            self.native_retirement = SourceRightsNativeRetirement::Retained;
            self.native_retirement = match self
                .native
                .as_mut()
                .expect("retained rights owner")
                .retire_checked()?
            {
                RightsRetirement::NoLanes => SourceRightsNativeRetirement::NoLanesInstalled,
                RightsRetirement::OtherHolders => {
                    SourceRightsNativeRetirement::OtherHoldersRetainLanes
                }
                RightsRetirement::LanesRetired => SourceRightsNativeRetirement::LanesRetired,
            };
            Ok(())
        });
        if !self.retirement.succeeded() {
            fence_attempt(self.binding.as_ref().unwrap(), &self.retirement);
            self.settlement = SourceRightsSettlement::Retained;
            return Ok(self.report());
        }
        // Keep binding outside the destroyed bundle: an unwind cannot let
        // Database close race an unproven resource retirement.
        self.disposal.run(|| {
            drop(self.native.take());
            drop(self.context.take());
            drop(self.funding.take());
            Ok(())
        });
        if self.disposal.succeeded() {
            self.binding.take();
            self.settlement = SourceRightsSettlement::Disposed;
        } else {
            self.binding.as_ref().unwrap().fence();
            self.settlement = SourceRightsSettlement::DisposalUncertain;
        }
        Ok(self.report())
    }
}

struct ReadResources {
    context: Option<SourceReadContext>,
    backing: SourceBacking,
    pin: Option<PreparedProtectedPin>,
    // Last: exact pool identity outlives partial native allocation retirement.
    funding: Option<SourceFundingIdentity>,
}
#[must_use]
pub struct RetainedSourceRead {
    retirement_observer: Option<ReadRetirementObserver>,
    native_retirement: Attempt<StorageError>,
    binding: Option<SourceDatabase>,
    resources: Option<ReadResources>,
    reader: Option<RetainedReadTransaction>,
    preparation: Attempt<StorageError>,
    capture: Attempt<StorageError>,
    cancellation: Attempt<StorageError>,
    disposal: Attempt<Infallible>,
    settlement: SourceReadSettlement,
}
pub struct SourceReadReport<'a> {
    owner: &'a RetainedSourceRead,
}
impl SourceReadReport<'_> {
    pub fn native_retirement(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.native_retirement.view()
    }
    pub fn settlement(&self) -> SourceReadSettlement {
        self.owner.settlement
    }
    pub fn preparation(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.preparation.view()
    }
    pub fn capture(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.capture.view()
    }
    pub fn cancellation(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.cancellation.view()
    }
    pub fn disposal(&self) -> TerminalObservation<'_, Infallible> {
        self.owner.disposal.view()
    }
    pub fn reader_close(&self) -> Option<ReadCloseReport<'_>> {
        self.owner
            .reader
            .as_ref()
            .map(RetainedReadTransaction::report)
    }
    pub fn retains_database(&self) -> bool {
        self.owner.binding.is_some()
    }
    pub fn retains_pending_ticket(&self) -> bool {
        self.owner
            .resources
            .as_ref()
            .and_then(|r| r.pin.as_ref())
            .is_some_and(PreparedProtectedPin::is_pending)
    }
    pub fn is_clean_capacity_refusal(&self) -> bool {
        self.owner.settlement == SourceReadSettlement::Disposed
            && matches!(&(self.owner.preparation), Attempt::Done(Err(StorageError::Core(native_error))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
            && matches!(self.owner.capture, Attempt::Pending)
            && self.owner.cancellation.succeeded()
            && self.owner.disposal.succeeded()
    }
}
impl RetainedSourceRead {
    #[cfg(test)]
    pub(crate) fn corrupt_final_release_for_test(&self, poison: bool) {
        self.resources
            .as_ref()
            .unwrap()
            .context
            .as_ref()
            .unwrap()
            .pins
            .corrupt_final_release_for_test(poison);
    }

    #[cfg(test)]
    pub(crate) fn backing_address_for_test(&self) -> usize {
        self.resources.as_ref().unwrap().backing.address_for_test()
    }
    #[cfg(test)]
    pub(crate) fn mismatch_ticket_for_test(&mut self) {
        self.resources
            .as_mut()
            .unwrap()
            .pin
            .as_mut()
            .unwrap()
            .mismatch_ticket_for_test();
    }
    pub fn report(&self) -> SourceReadReport<'_> {
        SourceReadReport { owner: self }
    }
    pub fn prepare(
        &mut self,
        database: &RetainedDatabase,
        rights: &SourceReadRights,
    ) -> Result<SourceReadReport<'_>, SourceReadCallError> {
        require_database(&self.binding, database)?;
        if rights.funding.is_some()
            || self
                .resources
                .as_ref()
                .is_some_and(|resources| resources.funding.is_some())
        {
            return Err(SourceReadCallError::FundingRequired);
        }
        self.prepare_with(database, rights, |resources, rights| {
            let native = rights
                .native
                .as_ref()
                .and_then(PendingSourceRights::rights)
                .unwrap();
            let context = resources.context.as_ref().unwrap();
            resources.backing.prepare(context)?;
            resources.pin = Some(native.queue_pin());
            resources.pin.as_mut().unwrap().prepare_retained()
        })
    }
    pub fn prepare_funded(
        &mut self,
        database: &RetainedDatabase,
        rights: &SourceReadRights,
        funding: &mut NativeSourceFunding,
    ) -> Result<SourceReadReport<'_>, SourceReadCallError> {
        require_database(&self.binding, database)?;
        if !matches!(self.preparation, Attempt::Pending)
            || !matches!(self.cancellation, Attempt::Pending)
            || !matches!(self.capture, Attempt::Pending)
        {
            return Err(SourceReadCallError::WrongPhase);
        }
        let identity = rights
            .funding
            .as_ref()
            .ok_or(SourceReadCallError::ForeignFunding)?;
        if !funding.belongs_to_database(database) || !funding.belongs_to(identity) {
            return Err(SourceReadCallError::ForeignFunding);
        }
        // Validate the native facade before retaining this identity. No provider
        // or allocation is entered for ordinary/foreign/not-ready rights.
        self.require_rights(rights)?;
        self.resources.as_mut().unwrap().funding = Some(identity.clone());
        self.prepare_with(database, rights, |resources, rights| {
            let native = rights
                .native
                .as_ref()
                .and_then(PendingSourceRights::rights)
                .unwrap();
            let context = resources.context.as_ref().unwrap();
            resources.backing.prepare_funded(context, funding)?;
            resources.pin = Some(native.queue_pin());
            resources
                .pin
                .as_mut()
                .unwrap()
                .prepare_retained_funded(funding)
        })
    }
    fn require_rights(&self, rights: &SourceReadRights) -> Result<(), SourceReadCallError> {
        let binding = self.binding.as_ref().unwrap();
        if !rights
            .binding
            .as_ref()
            .is_some_and(|other| binding.same_owner(other))
        {
            return Err(SourceReadCallError::ForeignRights);
        }
        if rights.settlement != SourceRightsSettlement::Ready
            || rights
                .native
                .as_ref()
                .and_then(PendingSourceRights::rights)
                .is_none()
        {
            return Err(SourceReadCallError::RightsNotReady);
        }
        Ok(())
    }
    fn prepare_with(
        &mut self,
        database: &RetainedDatabase,
        rights: &SourceReadRights,
        prepare: impl FnOnce(&mut ReadResources, &SourceReadRights) -> Result<(), CoreError>,
    ) -> Result<SourceReadReport<'_>, SourceReadCallError> {
        require_database(&self.binding, database)?;
        if !matches!(self.cancellation, Attempt::Pending)
            || !matches!(self.capture, Attempt::Pending)
        {
            return Err(SourceReadCallError::WrongPhase);
        }
        if !matches!(self.preparation, Attempt::Pending) {
            return Ok(self.report());
        }
        self.require_rights(rights)?;
        let binding = self.binding.as_ref().unwrap();
        let native = rights
            .native
            .as_ref()
            .and_then(PendingSourceRights::rights)
            .unwrap();
        let resources = self.resources.as_mut().unwrap();
        self.preparation.run(|| {
            resources.context = Some(binding.context()?);
            let context = resources.context.as_ref().unwrap();
            if !native.belongs_to(&context.pins) {
                return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "source rights registry differs",
                ))
                .into());
            }
            prepare(resources, rights)?;
            binding.check_local()?;
            resources.context.as_ref().unwrap().check()?;
            Ok(())
        });
        fence_attempt(binding, &self.preparation);
        self.settlement = if self.preparation.succeeded() {
            SourceReadSettlement::Prepared
        } else {
            SourceReadSettlement::Retained
        };
        Ok(self.report())
    }
    pub fn capture(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceReadReport<'_>, SourceReadCallError> {
        require_database(&self.binding, database)?;
        if !matches!(self.capture, Attempt::Pending) {
            return Ok(self.report());
        }
        if self.settlement != SourceReadSettlement::Prepared || !self.preparation.succeeded() {
            return Err(SourceReadCallError::WrongPhase);
        }
        let binding = self.binding.as_ref().unwrap();
        let resources = self.resources.as_mut().unwrap();
        let reader = &mut self.reader;
        self.capture.run(|| {
            binding.check_local()?;
            let context = resources.context.as_ref().unwrap();
            context.check()?;
            resources
                .backing
                .capture(context, resources.pin.as_mut().unwrap())?;
            *reader = binding
                .reader(&mut resources.backing)
                .map(ReadTransaction::retain);
            // The actual reader is installed before these fallible observations.
            context.check()?;
            binding.check_local()?;
            Ok(())
        });
        // A caught internal unwind after OnceLock installation must also keep
        // its real native reader in the existing retained close protocol.
        if reader.is_none() {
            *reader = binding
                .reader(&mut resources.backing)
                .map(ReadTransaction::retain);
        }
        fence_attempt(binding, &self.capture);
        self.settlement = if self.capture.succeeded() {
            SourceReadSettlement::Ready
        } else {
            SourceReadSettlement::Retained
        };
        Ok(self.report())
    }
    pub fn take_ready(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<RetainedReadTransaction, SourceReadCallError> {
        require_database(&self.binding, database)?;
        if self.settlement != SourceReadSettlement::Ready
            || !self
                .reader
                .as_ref()
                .is_some_and(|reader| reader.report().settlement() == ReadCloseSettlement::Open)
        {
            return Err(SourceReadCallError::WrongPhase);
        }
        let reader = self.reader.take().expect("successful source capture");
        // The actual captured pin keeps its rights/registry alive. These now
        // empty preparation shells cannot retire a final provider allocation.
        // For funded reads, NativeSourceFunding has no public constructor or
        // escape: BoundSourceRead owns it throughout this transfer. Its exact
        // PoolOwner alias makes ReadResources' identity nonfinal here. Any
        // future independent funding/reader escape must revisit this proof.
        drop(self.resources.take());
        self.binding.take();
        self.settlement = SourceReadSettlement::Transferred;
        Ok(reader)
    }
    pub fn cancel(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceReadReport<'_>, SourceReadCallError> {
        if self.settlement == SourceReadSettlement::Disposed {
            return Ok(self.report());
        }
        require_database(&self.binding, database)?;
        if self.reader.is_some() {
            return Err(SourceReadCallError::WrongPhase);
        }
        self.cancellation.run(|| {
            if let Some(pin) = self.resources.as_mut().and_then(|r| r.pin.as_mut()) {
                pin.cancel_ticket()?;
            }
            Ok(())
        });
        fence_attempt(self.binding.as_ref().unwrap(), &self.cancellation);
        self.settlement = if self.cancellation.succeeded() {
            SourceReadSettlement::Cancelled
        } else {
            SourceReadSettlement::Retained
        };
        Ok(self.report())
    }
    pub fn close_captured(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceReadReport<'_>, SourceReadCallError> {
        require_database(&self.binding, database)?;
        let reader = self
            .reader
            .as_mut()
            .ok_or(SourceReadCallError::WrongPhase)?;
        reader.close(database);
        // No closed/closing reader can subsequently be handed out as ready.
        self.settlement = SourceReadSettlement::Retained;
        Ok(self.report())
    }
    pub fn dispose_settled(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceReadReport<'_>, SourceReadCallError> {
        if self.settlement == SourceReadSettlement::Disposed {
            return Ok(self.report());
        }
        require_database(&self.binding, database)?;
        if let Some(reader) = self.reader.as_mut() {
            reader.dispose_settled(database);
            if reader.report().settlement() != ReadCloseSettlement::Disposed {
                if reader.report().settlement() == ReadCloseSettlement::DisposalUncertain {
                    self.binding.as_ref().unwrap().fence();
                    self.settlement = SourceReadSettlement::DisposalUncertain;
                }
                return Ok(self.report());
            }
        } else if !self.cancellation.succeeded() {
            return Err(SourceReadCallError::WrongPhase);
        }
        if matches!(self.disposal, Attempt::Pending) {
            self.retirement_observer = self
                .resources
                .as_ref()
                .and_then(|r| r.context.as_ref())
                .map(|context| {
                    ReadRetirementObserver::from_context(self.binding.as_ref().unwrap(), context)
                });
        }
        self.disposal.run(|| {
            drop(self.resources.take());
            Ok(())
        });
        if self.disposal.succeeded() {
            self.native_retirement.run(|| {
                self.retirement_observer
                    .as_ref()
                    .map_or(Ok(()), ReadRetirementObserver::check)
                    .map_err(StorageError::from)
            });
            if self.native_retirement.succeeded() {
                self.retirement_observer.take();
                self.binding.take();
                self.settlement = SourceReadSettlement::Disposed;
            } else {
                self.binding.as_ref().unwrap().fence();
                self.settlement = SourceReadSettlement::Retained;
            }
        } else {
            self.binding.as_ref().unwrap().fence();
            self.settlement = SourceReadSettlement::DisposalUncertain;
        }
        Ok(self.report())
    }
}

#[must_use]
pub struct RetainedSourceHistory {
    retirement_observer: Option<ReadRetirementObserver>,
    native_retirement: Attempt<StorageError>,
    binding: Option<SourceDatabase>,
    context: Option<SourceReadContext>,
    native: Option<HistoryPinRight>,
    preparation: Attempt<StorageError>,
    exchange: Attempt<StorageError>,
    cancellation: Attempt<StorageError>,
    disposal: Attempt<Infallible>,
    settlement: SourceHistorySettlement,
}
pub struct SourceHistoryReport<'a> {
    owner: &'a RetainedSourceHistory,
}
impl SourceHistoryReport<'_> {
    pub fn native_retirement(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.native_retirement.view()
    }
    pub fn settlement(&self) -> SourceHistorySettlement {
        self.owner.settlement
    }
    pub fn preparation(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.preparation.view()
    }
    pub fn exchange(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.exchange.view()
    }
    pub fn cancellation(&self) -> TerminalObservation<'_, StorageError> {
        self.owner.cancellation.view()
    }
    pub fn disposal(&self) -> TerminalObservation<'_, Infallible> {
        self.owner.disposal.view()
    }
    pub fn exchange_committed(&self) -> bool {
        self.owner.exchange.succeeded()
    }
    pub fn retains_database(&self) -> bool {
        self.owner.binding.is_some()
    }
    pub fn retains_pending_ticket(&self) -> bool {
        self.owner
            .native
            .as_ref()
            .is_some_and(HistoryPinRight::is_pending)
    }
}
impl RetainedReadTransaction {
    pub fn queue_source_history(&self) -> Result<RetainedSourceHistory, SourceReadCallError> {
        if self.settlement != ReadCloseSettlement::Open {
            return Err(SourceReadCallError::WrongPhase);
        }
        let (binding, native) = self
            .transaction
            .as_ref()
            .ok_or(SourceReadCallError::WrongPhase)?
            .source_history();
        Ok(RetainedSourceHistory {
            retirement_observer: None,
            native_retirement: Attempt::Pending,
            binding: Some(binding),
            context: None,
            native: Some(native),
            preparation: Attempt::Pending,
            exchange: Attempt::Pending,
            cancellation: Attempt::Pending,
            disposal: Attempt::Pending,
            settlement: SourceHistorySettlement::Queued,
        })
    }
}
impl RetainedSourceHistory {
    pub(super) fn history_abortable(&self) -> bool {
        (matches!(self.preparation, Attempt::Pending | Attempt::Done(Ok(())))
            || matches!(&self.preparation,
                Attempt::Done(Err(StorageError::Core(original))) if original.is_capacity_denied()))
            && matches!(self.exchange, Attempt::Pending)
            && matches!(self.cancellation, Attempt::Pending | Attempt::Done(Ok(())))
            && matches!(self.disposal, Attempt::Pending | Attempt::Done(Ok(())))
            && matches!(
                self.native_retirement,
                Attempt::Pending | Attempt::Done(Ok(()))
            )
    }

    pub(super) fn take_aborted_capacity_refusal(&mut self) -> Option<StorageError> {
        if self.settlement != SourceHistorySettlement::Disposed
            || !self.cancellation.succeeded()
            || !self.disposal.succeeded()
            || !self.native_retirement.succeeded()
            || !matches!(self.exchange, Attempt::Pending)
            || !matches!(&(self.preparation), Attempt::Done(Err(StorageError::Core(native_error))) if matches!(native_error.rejected_cause(), Some(crate::CoreErrorCause::CapacityDenied)))
        {
            return None;
        }
        let Attempt::Done(Err(error)) = std::mem::replace(&mut self.preparation, Attempt::Pending)
        else {
            unreachable!("checked disposed capacity refusal")
        };
        Some(error)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_final_release_for_test(&self, poison: bool) {
        self.native
            .as_ref()
            .unwrap()
            .retirement_registry()
            .corrupt_final_release_for_test(poison);
    }

    pub fn report(&self) -> SourceHistoryReport<'_> {
        SourceHistoryReport { owner: self }
    }
    pub fn prepare(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceHistoryReport<'_>, SourceReadCallError> {
        require_database(&self.binding, database)?;
        if !matches!(self.cancellation, Attempt::Pending)
            || !matches!(self.exchange, Attempt::Pending)
        {
            return Err(SourceReadCallError::WrongPhase);
        }
        let binding = self.binding.as_ref().unwrap();
        self.preparation.run(|| {
            self.context = Some(binding.context()?);
            let native = self.native.as_mut().unwrap();
            if !native.belongs_to(&self.context.as_ref().unwrap().pins) {
                return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "history database registry differs",
                ))
                .into());
            }
            native.prepare_retained()?;
            binding.check_local()?;
            Ok(())
        });
        fence_attempt(binding, &self.preparation);
        self.settlement = if self.preparation.succeeded() {
            SourceHistorySettlement::Prepared
        } else {
            SourceHistorySettlement::Retained
        };
        Ok(self.report())
    }
    /// Local class exchange only. The caller owns ordinary history bytes before
    /// entering. This method performs no provider check, fence callback, reserve,
    /// allocation, funded-resource destruction or post-success check before its report
    /// is returned. Only known nonfinal registry aliases are released.
    pub fn commit(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceHistoryReport<'_>, SourceReadCallError> {
        require_database(&self.binding, database)?;
        if !matches!(self.exchange, Attempt::Pending) {
            return Ok(self.report());
        }
        if self.settlement != SourceHistorySettlement::Prepared {
            return Err(SourceReadCallError::WrongPhase);
        }
        self.exchange.run(|| {
            self.binding.as_ref().unwrap().check_local()?;
            self.context.as_ref().unwrap().check_local()?;
            self.native.as_mut().unwrap().commit_local()?;
            Ok(())
        });
        self.settlement = if self.exchange.succeeded() {
            SourceHistorySettlement::Committed
        } else {
            SourceHistorySettlement::Retained
        };
        Ok(self.report())
    }
    pub fn cancel(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceHistoryReport<'_>, SourceReadCallError> {
        if self.settlement == SourceHistorySettlement::Disposed {
            return Ok(self.report());
        }
        require_database(&self.binding, database)?;
        if !matches!(self.exchange, Attempt::Pending) {
            return Err(SourceReadCallError::WrongPhase);
        }
        self.cancellation.run(|| {
            self.native.as_mut().unwrap().cancel()?;
            Ok(())
        });
        fence_attempt(self.binding.as_ref().unwrap(), &self.cancellation);
        self.settlement = if self.cancellation.succeeded() {
            SourceHistorySettlement::Cancelled
        } else {
            SourceHistorySettlement::Retained
        };
        Ok(self.report())
    }
    pub fn dispose_settled(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceHistoryReport<'_>, SourceReadCallError> {
        if self.settlement == SourceHistorySettlement::Disposed {
            return Ok(self.report());
        }
        require_database(&self.binding, database)?;
        if !self.exchange.succeeded() && !self.cancellation.succeeded() {
            return Err(SourceReadCallError::WrongPhase);
        }
        if matches!(self.disposal, Attempt::Pending) {
            self.retirement_observer = self.native.as_ref().map(|native| {
                ReadRetirementObserver::from_registry(
                    self.binding.as_ref().unwrap(),
                    native.retirement_registry(),
                )
            });
        }
        self.disposal.run(|| {
            drop(self.native.take());
            drop(self.context.take());
            Ok(())
        });
        if self.disposal.succeeded() {
            self.native_retirement.run(|| {
                self.retirement_observer
                    .as_ref()
                    .map_or(Ok(()), ReadRetirementObserver::check)
                    .map_err(StorageError::from)
            });
            if self.native_retirement.succeeded() {
                self.retirement_observer.take();
                self.binding.take();
                self.settlement = SourceHistorySettlement::Disposed;
            } else {
                self.binding.as_ref().unwrap().fence();
                self.settlement = SourceHistorySettlement::Retained;
            }
        } else {
            self.binding.as_ref().unwrap().fence();
            self.settlement = SourceHistorySettlement::DisposalUncertain;
        }
        Ok(self.report())
    }
}
