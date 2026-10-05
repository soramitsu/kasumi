//! Closed installed-provider funding for native protected source allocations.
//! This is not a registered Store reader or a complete canonical read grant.
use super::*;
use crate::core::NativeResidentLease;
use crate::core::SourceReadContext;
use crate::snapshot_pins::SnapshotPins;
use crate::tables::source_read::SourceDatabase;
use std::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceFundingCallError {
    ForeignProvider,
    RepeatedBind,
    IncompleteBind,
    WrongPhase,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceFundingPurpose {
    Rights,
    Backing,
    Pin,
}
impl SourceFundingPurpose {
    pub fn native_bytes(self) -> u64 {
        match self {
            Self::Rights => crate::ProtectedReadRequests::rights_request_bytes(),
            Self::Backing => crate::ProtectedReadRequests::snapshot_backing_request_bytes(),
            Self::Pin => crate::ProtectedReadRequests::pin_backing_request_bytes(),
        }
    }
}
/// These request values are minted by the installed physical admission adapter.
/// The owning native constructor chooses the purpose and native request.
#[derive(Clone, Copy)]
pub struct SourceFundingRequests {
    native: [u64; 3],
    wrapped: [u64; 3],
}
impl SourceFundingRequests {
    pub fn wrapped_bytes(&self, purpose: SourceFundingPurpose) -> u64 {
        self.wrapped[purpose as usize]
    }
    pub fn native_bytes(&self, purpose: SourceFundingPurpose) -> u64 {
        self.native[purpose as usize]
    }
    /// The real shared native controller shell; its backend and credit are
    /// retired only after the last Arc shell is deallocated.
    pub fn controller_bytes(&self) -> io::Result<u64> {
        allocation::<PoolOwner>().and_then(|n| {
            n.checked_add(2 * size_of::<usize>() as u64)
                .ok_or_else(|| io::ErrorKind::OutOfMemory.into())
        })
    }
}
fn allocation<T>() -> io::Result<u64> {
    (size_of::<T>() as u64)
        .checked_add(4096)
        .ok_or_else(|| io::ErrorKind::OutOfMemory.into())
}
pub fn source_backend_allocation_bytes<T>() -> io::Result<u64> {
    allocation::<T>()
}

/// Installed governor extension. Unsupported never falls back to ordinary work.
pub trait SourceMemoryProvider: Send + Sync {
    fn install_source_pool(
        self: Arc<Self>,
        _install: &mut SourcePoolInstall<'_>,
    ) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindState {
    Fresh,
    Claimed,
    Bound,
    CapacityRefused,
}
#[derive(Clone, Copy)]
struct BindStatus {
    state: BindState,
    rejected: Option<SourceFundingCallError>,
}
impl BindStatus {
    const fn new() -> Self {
        Self {
            state: BindState::Fresh,
            rejected: None,
        }
    }
    fn claim(&mut self, same: bool) -> Result<(), SourceFundingCallError> {
        if let Some(error) = self.rejected {
            return Err(error);
        }
        let error = if !same {
            Some(SourceFundingCallError::ForeignProvider)
        } else if self.state != BindState::Fresh {
            Some(SourceFundingCallError::RepeatedBind)
        } else {
            None
        };
        if let Some(error) = error {
            self.rejected.get_or_insert(error);
            return Err(error);
        }
        self.state = BindState::Claimed;
        Ok(())
    }
    fn result(self) -> Result<(), SourceFundingCallError> {
        if let Some(error) = self.rejected {
            return Err(error);
        }
        if self.state != BindState::Bound {
            return Err(SourceFundingCallError::IncompleteBind);
        }
        Ok(())
    }
}

/// The actual provider owns the concrete bank. All returned owners are retained
/// before the provider is allowed to return an error or unwind.
pub trait SourcePoolBackend: Send + Sync + 'static {
    fn install_account(&self, install: &mut SourceAccountInstall<'_>) -> io::Result<()>;
    fn acquire_rights(&self, install: &mut SourceChildInstall<'_>) -> io::Result<()>;
    fn begin_seal(&self) -> io::Result<()>;
    fn seal(&self) -> io::Result<()>;
    fn snapshot(&self) -> SourceBankSnapshot;
    fn retirement(&self, stamp: SourceAccountRetirement) -> bool;
}
pub trait SourceAccountBackend: Send + Sync + 'static {
    fn allow_retirement(&self) -> io::Result<()>;
    fn acquire(&self, install: &mut SourceChildInstall<'_>) -> io::Result<()>;
    fn install_history(&self, install: &mut SourceHistoryInstall<'_>) -> io::Result<()>;
}
pub trait SourceHistoryBackend: Send + Sync + 'static {
    fn commit(&mut self, native: &mut SourceHistoryCommit<'_>) -> io::Result<()>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceBankSnapshot {
    pub fixed_bytes: u64,
    pub lane_bytes: u64,
    pub charged_bytes: u64,
    pub assigned: usize,
    pub retained: usize,
    pub sealed: bool,
}

macro_rules! retired_box {
    ($name:ident, $trait:ident, $retire:ident) => {
        trait $retire: $trait {
            fn retire(self: Box<Self>);
        }
        impl<T: $trait> $retire for T {
            fn retire(self: Box<Self>) {
                let payload = {
                    let allocation = self;
                    *allocation
                };
                drop(payload);
            }
        }
        struct $name(Option<Box<dyn $retire>>);
        impl Drop for $name {
            fn drop(&mut self) {
                if let Some(owner) = self.0.take() {
                    owner.retire();
                }
            }
        }
    };
}
retired_box!(PoolBackend, SourcePoolBackend, RetirePool);
retired_box!(AccountBackend, SourceAccountBackend, RetireAccount);
retired_box!(HistoryBackend, SourceHistoryBackend, RetireHistory);
impl PoolBackend {
    fn get(&self) -> &dyn SourcePoolBackend {
        self.0.as_deref().expect("owned pool backend")
    }
}
impl AccountBackend {
    fn get(&self) -> &dyn SourceAccountBackend {
        self.0.as_deref().expect("owned account backend")
    }
}

/// Only an exact native owner constructs an installer.
/// ```compile_fail
/// let _ = kasumi_kv::SourcePoolInstall {};
/// ```
pub struct SourcePoolInstall<'a> {
    provider: &'a Arc<dyn SourceMemoryProvider>,
    requests: &'a mut Option<SourceFundingRequests>,
    status: &'a mut BindStatus,
    backend: &'a mut Option<PoolBackend>,
}
impl SourcePoolInstall<'_> {
    /// Called only by the real physical-owner adapter. The native requests are
    /// fixed; its function supplies actual wrapper costs, never a caller budget.
    pub fn through_installed_provider(
        &mut self,
        actual: Arc<dyn SourceMemoryProvider>,
        wrap: fn(u64) -> io::Result<u64>,
    ) -> io::Result<()> {
        if !Arc::ptr_eq(self.provider, &actual) {
            self.status
                .rejected
                .get_or_insert(SourceFundingCallError::ForeignProvider);
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if self.requests.is_some() {
            self.status
                .rejected
                .get_or_insert(SourceFundingCallError::RepeatedBind);
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let native = [
            SourceFundingPurpose::Rights.native_bytes(),
            SourceFundingPurpose::Backing.native_bytes(),
            SourceFundingPurpose::Pin.native_bytes(),
        ];
        *self.requests = Some(SourceFundingRequests {
            native,
            wrapped: [wrap(native[0])?, wrap(native[1])?, wrap(native[2])?],
        });
        actual.install_source_pool(self)
    }
    pub fn try_begin_bind(
        &mut self,
        actual: Arc<dyn SourceMemoryProvider>,
    ) -> Result<SourceBindPermit<'_>, SourceFundingCallError> {
        self.status.claim(Arc::ptr_eq(self.provider, &actual))?;
        let requests = self
            .requests
            .ok_or(SourceFundingCallError::IncompleteBind)?;
        Ok(SourceBindPermit {
            status: self.status,
            target: self.backend,
            requests,
        })
    }
}
pub struct SourceBindPermit<'a> {
    status: &'a mut BindStatus,
    target: &'a mut Option<PoolBackend>,
    requests: SourceFundingRequests,
}
impl SourceBindPermit<'_> {
    pub fn requests(&self) -> SourceFundingRequests {
        self.requests
    }
    pub fn bind<T: SourcePoolBackend>(self, backend: T) {
        *self.target = Some(PoolBackend(Some(Box::new(backend))));
        self.status.state = BindState::Bound;
    }
}

#[derive(Clone, Copy)]
pub struct SourceAccountRetirement {
    lane: usize,
    ticket: u64,
}
impl SourceAccountRetirement {
    pub fn lane(self) -> usize {
        self.lane
    }
    pub fn ticket(self) -> u64 {
        self.ticket
    }
}
pub struct SourceAccountInstall<'a> {
    stamp: &'a mut Option<SourceAccountRetirement>,
    provider: &'a Arc<dyn SourceMemoryProvider>,
    status: &'a mut BindStatus,
    backend: &'a mut Option<AccountBackend>,
}
pub struct SourceAccountPermit<'a> {
    status: &'a mut BindStatus,
    target: &'a mut Option<AccountBackend>,
    stamp: &'a mut Option<SourceAccountRetirement>,
}
impl SourceAccountInstall<'_> {
    pub fn try_begin_bind(
        &mut self,
        actual: Arc<dyn SourceMemoryProvider>,
    ) -> Result<SourceAccountPermit<'_>, SourceFundingCallError> {
        self.status.claim(Arc::ptr_eq(self.provider, &actual))?;
        Ok(SourceAccountPermit {
            status: self.status,
            target: self.backend,
            stamp: self.stamp,
        })
    }
}
impl SourceAccountPermit<'_> {
    pub fn bind<T: SourceAccountBackend>(self, backend: T, lane: usize, ticket: u64) {
        *self.target = Some(AccountBackend(Some(Box::new(backend))));
        // Diagnostic assignment comes from this one actual bank constructor;
        // it confers no authority and requires no virtual callback after debit.
        if lane >= 2 || ticket == 0 {
            self.status
                .rejected
                .get_or_insert(SourceFundingCallError::IncompleteBind);
            return;
        }
        *self.stamp = Some(SourceAccountRetirement { lane, ticket });
        self.status.state = BindState::Bound;
    }
}

// The permit itself boxes the concrete credit and stores it in retained
// custody. No provider callback or token virtual constructor runs after debit.
pub struct SourceChildInstall<'a> {
    provider: &'a Arc<dyn SourceMemoryProvider>,
    status: &'a mut BindStatus,
    target: &'a mut Option<crate::ResidentAllocation>,
    purpose: SourceFundingPurpose,
}
/// A caller cannot manufacture a prepaid child capability.
/// ```compile_fail
/// let _ = kasumi_kv::SourceChildPermit {};
/// ```
pub struct SourceChildPermit<'a> {
    status: &'a mut BindStatus,
    target: &'a mut Option<crate::ResidentAllocation>,
}
impl SourceChildInstall<'_> {
    pub fn purpose(&self) -> SourceFundingPurpose {
        self.purpose
    }
    pub fn try_begin_bind(
        &mut self,
        actual: Arc<dyn SourceMemoryProvider>,
    ) -> Result<SourceChildPermit<'_>, SourceFundingCallError> {
        self.status.claim(Arc::ptr_eq(self.provider, &actual))?;
        Ok(SourceChildPermit {
            status: self.status,
            target: self.target,
        })
    }
}
impl SourceChildPermit<'_> {
    pub fn bind<T: Send + Sync + 'static>(self, token: T) {
        *self.target = Some(crate::ResidentAllocation::new(token));
        self.status.state = BindState::Bound;
    }
}

pub struct SourceHistoryInstall<'a> {
    provider: &'a Arc<dyn SourceMemoryProvider>,
    status: &'a mut BindStatus,
    backend: &'a mut Option<HistoryBackend>,
}
pub struct SourceHistoryPermit<'a> {
    status: &'a mut BindStatus,
    target: &'a mut Option<HistoryBackend>,
}
impl SourceHistoryInstall<'_> {
    pub fn try_begin_bind(
        &mut self,
        actual: Arc<dyn SourceMemoryProvider>,
    ) -> Result<SourceHistoryPermit<'_>, SourceFundingCallError> {
        self.status.claim(Arc::ptr_eq(self.provider, &actual))?;
        Ok(SourceHistoryPermit {
            status: self.status,
            target: self.backend,
        })
    }
}
impl SourceHistoryPermit<'_> {
    /// Positively report capacity exhaustion before binding or changing the
    /// source account. Only the installed provider's actual refusal branch may
    /// call this; returning an error or dropping a permit alone is not proof.
    /// The exact original error continues through the provider result.
    pub fn refuse_capacity(self, original: io::Error) -> io::Error {
        self.status.state = BindState::CapacityRefused;
        original
    }

    pub fn bind<T: SourceHistoryBackend>(self, backend: T) {
        *self.target = Some(HistoryBackend(Some(Box::new(backend))));
        self.status.state = BindState::Bound;
    }
}
/// One concrete native operation; there is no arbitrary callback in the bank's
/// commit suffix. Constructed only from the same bound reader's history owner.
pub struct SourceHistoryCommit<'a> {
    native: &'a mut RetainedSourceHistory,
    database: &'a RetainedDatabase,
    entered: bool,
}
impl SourceHistoryCommit<'_> {
    pub fn commit(&mut self) -> bool {
        if self.entered {
            return false;
        }
        self.entered = true;
        self.native
            .commit(self.database)
            .is_ok_and(|report| report.exchange_committed())
    }
}

struct PoolOwner {
    backend: PoolBackend,
    context: SourceReadContext,
    provider: Arc<dyn SourceMemoryProvider>,
}
/// No Weak/raw Arc escape; final controller shell is freed before bank credit.
pub(crate) struct SourceFundingIdentity(Option<Arc<PoolOwner>>);
impl Clone for SourceFundingIdentity {
    fn clone(&self) -> Self {
        Self(Some(self.0.as_ref().expect("owned pool").clone()))
    }
}
impl Drop for SourceFundingIdentity {
    fn drop(&mut self) {
        if let Some(arc) = self.0.take() {
            drop(Arc::into_inner(arc));
        }
    }
}
impl SourceFundingIdentity {
    fn get(&self) -> &PoolOwner {
        self.0.as_deref().expect("owned pool")
    }
    fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.0.as_ref().unwrap(), other.0.as_ref().unwrap())
    }
}
#[derive(Debug)]
pub enum SourceFundingError {
    Native(CoreError),
    Provider(io::Error),
    Protocol(SourceFundingCallError),
}
impl From<CoreError> for SourceFundingError {
    fn from(e: CoreError) -> Self {
        Self::Native(e)
    }
}
impl From<io::Error> for SourceFundingError {
    fn from(e: io::Error) -> Self {
        Self::Provider(e)
    }
}
impl From<SourceFundingCallError> for SourceFundingError {
    fn from(e: SourceFundingCallError) -> Self {
        Self::Protocol(e)
    }
}

#[must_use]
pub struct NativeSourcePool {
    binding: Option<SourceDatabase>,
    provider: Arc<dyn SourceMemoryProvider>,
    context: Option<SourceReadContext>,
    requests: Option<SourceFundingRequests>,
    unbound: Option<PoolBackend>,
    owner: Option<SourceFundingIdentity>,
    status: BindStatus,
    installation: Attempt<SourceFundingError>,
    seal_barrier: Attempt<io::Error>,
    seal_poll: Attempt<Infallible>,
    seal: Attempt<io::Error>,
    disposal: Attempt<Infallible>,
    rights_status: BindStatus,
    rights_credit: Option<crate::ResidentAllocation>,
}
impl Database {
    pub fn queue_native_source_pool(
        &self,
        expected: Arc<dyn SourceMemoryProvider>,
    ) -> NativeSourcePool {
        NativeSourcePool {
            binding: Some(SourceDatabase::new(self)),
            provider: expected,
            context: None,
            requests: None,
            unbound: None,
            owner: None,
            status: BindStatus::new(),
            installation: Attempt::Pending,
            seal_barrier: Attempt::Pending,
            seal_poll: Attempt::Pending,
            seal: Attempt::Pending,
            disposal: Attempt::Pending,
            rights_status: BindStatus::new(),
            rights_credit: None,
        }
    }
}
impl NativeSourcePool {
    pub fn installation(&self) -> TerminalObservation<'_, SourceFundingError> {
        self.installation.view()
    }
    pub fn protocol_error(&self) -> Option<SourceFundingCallError> {
        self.status.rejected
    }
    pub fn is_ready(&self) -> bool {
        self.installation.succeeded()
            && matches!(self.seal_barrier, Attempt::Pending)
            && self.owner.is_some()
    }
    pub fn snapshot(&self) -> Option<SourceBankSnapshot> {
        self.owner
            .as_ref()
            .map(|owner| owner.get().backend.get().snapshot())
            .or_else(|| {
                self.unbound
                    .as_ref()
                    .map(|backend| backend.get().snapshot())
            })
    }
    pub(crate) fn belongs_to_database(&self, db: &RetainedDatabase) -> bool {
        db.database.as_ref().is_some_and(|db| {
            self.binding
                .as_ref()
                .is_some_and(|binding| binding.belongs_to(db))
        })
    }
    pub(crate) fn binding_token(&self) -> Result<SourceFundingIdentity, SourceReadCallError> {
        if !self.is_ready() {
            return Err(SourceReadCallError::WrongPhase);
        }
        Ok(self.owner.as_ref().unwrap().clone())
    }
    pub fn install(&mut self, database: &RetainedDatabase) -> Result<(), SourceReadCallError> {
        if !self.belongs_to_database(database) {
            return Err(SourceReadCallError::ForeignDatabase);
        }
        self.installation.run(|| {
            self.context = Some(self.binding.as_ref().unwrap().context()?);
            let admission = self.context.as_ref().unwrap().admission();
            let mut install = SourcePoolInstall {
                provider: &self.provider,
                requests: &mut self.requests,
                status: &mut self.status,
                backend: &mut self.unbound,
            };
            admission.install_source_pool(&mut install)?;
            self.status.result()?;
            self.owner = Some(SourceFundingIdentity(Some(Arc::new(PoolOwner {
                backend: self.unbound.take().expect("bound pool"),
                context: self.context.take().expect("exact context"),
                provider: self.provider.clone(),
            }))));
            self.owner.as_ref().unwrap().get().context.check()?;
            Ok(())
        });
        Ok(())
    }
    pub fn seal(&mut self) {
        self.seal_barrier.run(|| {
            let backend = self
                .owner
                .as_ref()
                .map(|o| &o.get().backend)
                .or(self.unbound.as_ref())
                .ok_or(io::ErrorKind::InvalidInput)?;
            backend.get().begin_seal()
        });
        if !self.seal_barrier.succeeded() {
            return;
        }
        if !matches!(self.seal, Attempt::Pending) {
            return;
        }
        // Successful busy observations may advance; the first panic remains
        // sticky in bounded retained custody after the one-way seal barrier.
        if self.seal_poll.succeeded() {
            self.seal_poll = Attempt::Pending;
        }
        let mut ready = false;
        self.seal_poll.run(|| {
            let snapshot = self
                .owner
                .as_ref()
                .map(|o| o.get().backend.get().snapshot())
                .or_else(|| self.unbound.as_ref().map(|b| b.get().snapshot()));
            ready = snapshot.is_some_and(|s| s.assigned == 0 && s.retained == 0);
            Ok(())
        });
        if !self.seal_poll.succeeded() || !ready {
            return;
        }
        self.seal.run(|| {
            let backend = self
                .owner
                .as_ref()
                .map(|o| &o.get().backend)
                .or(self.unbound.as_ref())
                .ok_or(io::ErrorKind::InvalidInput)?;
            backend.get().seal()
        });
    }
    pub fn seal_progress(&self) -> TerminalObservation<'_, Infallible> {
        self.seal_poll.view()
    }
    pub fn seal_barrier(&self) -> TerminalObservation<'_, io::Error> {
        self.seal_barrier.view()
    }
    pub fn sealing(&self) -> TerminalObservation<'_, io::Error> {
        self.seal.view()
    }
    /// Retire only a terminal failed installation that bound no backend. The
    /// original installation observation remains owned; exact context and DB
    /// custody release is independently observed. Bound banks still require
    /// their normal seal and dispose_sealed protocol.
    pub fn dispose_unbound(&mut self) -> Result<(), SourceFundingCallError> {
        if !matches!(
            self.installation,
            Attempt::Done(Err(_)) | Attempt::Unwound(_)
        ) || self.owner.is_some()
            || self.unbound.is_some()
            || self.rights_credit.is_some()
        {
            return Err(SourceFundingCallError::WrongPhase);
        }
        self.disposal.run(|| {
            drop(self.context.take());
            Ok(())
        });
        if self.disposal.succeeded() {
            self.binding.take();
        }
        Ok(())
    }
    pub fn dispose_sealed(&mut self) {
        if !self.seal.succeeded() {
            return;
        }
        self.disposal.run(|| {
            drop(self.rights_credit.take());
            drop(self.owner.take());
            drop(self.unbound.take());
            drop(self.context.take());
            Ok(())
        });
        if self.disposal.succeeded() {
            self.binding.take();
        }
    }
    pub fn disposal(&self) -> TerminalObservation<'_, Infallible> {
        self.disposal.view()
    }
    pub(crate) fn reserve_rights_into(
        &mut self,
        pins: &SnapshotPins,
        target: &mut Option<NativeResidentLease>,
    ) -> Result<(), CoreError> {
        let owner = self
            .owner
            .as_ref()
            .ok_or(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "source pool absent",
            )))?
            .get();
        if !self.installation.succeeded() || !owner.context.pins.same_owner(pins) {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "foreign source rights funding",
            )));
        }
        owner.context.check()?;
        let mut install = SourceChildInstall {
            provider: &owner.provider,
            status: &mut self.rights_status,
            target: &mut self.rights_credit,
            purpose: SourceFundingPurpose::Rights,
        };
        owner
            .backend
            .get()
            .acquire_rights(&mut install)
            .map_err(|original| CoreError::new(crate::CoreErrorCause::Io(original)))?;
        self.rights_status.result().map_err(|_| {
            CoreError::new(crate::CoreErrorCause::InvalidInput(
                "source rights binding failed",
            ))
        })?;
        // Closed conversion: Store's DiskMemoryLease is this exact shared
        // allocation holder. No user/provider continuation can run here.
        *target = self
            .rights_credit
            .take()
            .map(crate::ResidentAllocation::into_native);
        owner.context.check()
    }
    pub fn queue_read(&self, database: &Database) -> Result<BoundSourceRead, SourceReadCallError> {
        if !self
            .binding
            .as_ref()
            .is_some_and(|b| b.belongs_to(database))
        {
            return Err(SourceReadCallError::ForeignDatabase);
        }
        let owner = self.binding_token()?;
        Ok(BoundSourceRead {
            funding: NativeSourceFunding {
                binding: Some(SourceDatabase::new(database)),
                owner: Some(owner),
                backend: None,
                status: BindStatus::new(),
                installation: Attempt::Pending,
                children: [BindStatus::new(); 2],
                child_credit: [None, None],
                pending_disposal: Attempt::Pending,
                controller_disposal: Attempt::Pending,
                stamp: None,
                release: Attempt::Pending,
                disposal: Attempt::Pending,
                retirement: Attempt::Pending,
            },
            native: database.queue_source_read(),
            ready: None,
            history: None,
        })
    }
}

/// Created only inside the bound native read. There is no raw-grant constructor.
/// ```compile_fail
/// let _ = kasumi_kv::NativeSourceFunding {};
/// ```
pub struct NativeSourceFunding {
    binding: Option<SourceDatabase>,
    owner: Option<SourceFundingIdentity>,
    backend: Option<AccountBackend>,
    status: BindStatus,
    installation: Attempt<SourceFundingError>,
    children: [BindStatus; 2],
    child_credit: [Option<crate::ResidentAllocation>; 2],
    pending_disposal: Attempt<Infallible>,
    controller_disposal: Attempt<Infallible>,
    stamp: Option<SourceAccountRetirement>,
    release: Attempt<io::Error>,
    disposal: Attempt<Infallible>,
    retirement: Attempt<io::Error>,
}
impl NativeSourceFunding {
    fn retire_closed(&mut self) {
        if self.backend.is_none() && self.stamp.is_none() {
            self.retire_controller();
            return;
        }
        self.pending_disposal.run(|| {
            for credit in &mut self.child_credit {
                drop(credit.take());
            }
            Ok(())
        });
        if !self.pending_disposal.succeeded() {
            return;
        }
        self.release.run(|| {
            self.backend
                .as_ref()
                .ok_or(io::ErrorKind::InvalidInput)?
                .get()
                .allow_retirement()
        });
        if !self.release.succeeded() {
            return;
        }
        self.disposal.run(|| {
            drop(self.backend.take());
            Ok(())
        });
        if self.disposal.succeeded() {
            self.retirement.run(|| {
                if self.stamp.is_some_and(|stamp| {
                    self.owner
                        .as_ref()
                        .expect("retained funding controller")
                        .get()
                        .backend
                        .get()
                        .retirement(stamp)
                }) {
                    Ok(())
                } else {
                    Err(io::ErrorKind::Other.into())
                }
            });
        }
        if self.retirement.succeeded() {
            self.retire_controller();
        }
    }
    fn retire_controller(&mut self) {
        // This can be the actual final pool/backend/bank allocation after a
        // historical reader outlives the sealed pool. Retain the exact DB alias
        // outside the destructive Attempt until that tail positively returns.
        self.controller_disposal.run(|| {
            drop(self.owner.take());
            Ok(())
        });
        if self.controller_disposal.succeeded() {
            self.binding.take();
        }
    }

    pub(crate) fn belongs_to(&self, token: &SourceFundingIdentity) -> bool {
        self.owner.as_ref().is_some_and(|owner| owner.same(token))
    }
    pub(crate) fn belongs_to_database(&self, database: &RetainedDatabase) -> bool {
        database.database.as_ref().is_some_and(|db| {
            self.binding
                .as_ref()
                .is_some_and(|binding| binding.belongs_to(db))
        })
    }
    fn install(&mut self) {
        self.installation.run(|| {
            self.owner
                .as_ref()
                .expect("retained funding controller")
                .get()
                .context
                .check()?;
            let mut install = SourceAccountInstall {
                stamp: &mut self.stamp,
                provider: &self
                    .owner
                    .as_ref()
                    .expect("retained funding controller")
                    .get()
                    .provider,
                status: &mut self.status,
                backend: &mut self.backend,
            };
            self.owner
                .as_ref()
                .expect("retained funding controller")
                .get()
                .backend
                .get()
                .install_account(&mut install)?;
            self.status.result()?;
            self.owner
                .as_ref()
                .expect("retained funding controller")
                .get()
                .context
                .check()?;
            Ok(())
        });
    }
    fn reserve(
        &mut self,
        target: &mut Option<NativeResidentLease>,
        purpose: SourceFundingPurpose,
    ) -> Result<(), CoreError> {
        if !self.installation.succeeded() {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "source account not installed",
            )));
        }
        let owner = self
            .owner
            .as_ref()
            .expect("retained funding controller")
            .get();
        owner.context.check()?;
        let status = &mut self.children[purpose as usize - 1];
        let mut install = SourceChildInstall {
            provider: &owner.provider,
            status,
            target: &mut self.child_credit[purpose as usize - 1],
            purpose,
        };
        self.backend
            .as_ref()
            .unwrap()
            .get()
            .acquire(&mut install)
            .map_err(|original| CoreError::new(crate::CoreErrorCause::Io(original)))?;
        status.result().map_err(|_| {
            CoreError::new(crate::CoreErrorCause::InvalidInput(
                "source child binding failed",
            ))
        })?;
        *target = self.child_credit[purpose as usize - 1]
            .take()
            .map(crate::ResidentAllocation::into_native);
        owner.context.check()
    }
    pub(crate) fn reserve_backing_into(
        &mut self,
        context: &SourceReadContext,
        target: &mut Option<NativeResidentLease>,
    ) -> Result<(), CoreError> {
        if !self
            .owner
            .as_ref()
            .expect("retained funding controller")
            .get()
            .context
            .same_owner(context)
        {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "foreign source backing",
            )));
        }
        self.reserve(target, SourceFundingPurpose::Backing)
    }
    pub(crate) fn reserve_pin_into(
        &mut self,
        pins: &SnapshotPins,
        target: &mut Option<NativeResidentLease>,
    ) -> Result<(), CoreError> {
        if !self
            .owner
            .as_ref()
            .expect("retained funding controller")
            .get()
            .context
            .pins
            .same_owner(pins)
        {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "foreign source pin",
            )));
        }
        self.reserve(target, SourceFundingPurpose::Pin)
    }
}

/// Owns the controller alongside exactly the read it funded. No raw reader or
/// account conversion exists. The Store bridge is test-only in this tranche.
#[must_use]
pub struct BoundSourceRead {
    funding: NativeSourceFunding,
    native: RetainedSourceRead,
    ready: Option<RetainedReadTransaction>,
    history: Option<BoundSourceHistory>,
}
/// Exact capacity cause released only after positive precommit cancellation.
#[derive(Debug)]
pub enum SourceHistoryRefusal {
    Provider(io::Error),
    Native(StorageError),
}
impl fmt::Display for SourceHistoryRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider(error) => fmt::Display::fmt(error, out),
            Self::Native(error) => fmt::Display::fmt(error, out),
        }
    }
}
impl std::error::Error for SourceHistoryRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Provider(error) => Some(error),
            Self::Native(error) => Some(error),
        }
    }
}

/// No current source escapes until its exact history-only cleanup is proven.
#[derive(Debug)]
pub enum SourceHistoryAbort {
    Restored {
        refusal: Option<SourceHistoryRefusal>,
    },
    Retained,
}
struct BoundSourceHistory {
    native: RetainedSourceHistory,
    backend: Option<HistoryBackend>,
    status: BindStatus,
    preparation: Attempt<SourceFundingError>,
    exchange: Attempt<io::Error>,
    disposal: Attempt<Infallible>,
}
impl BoundSourceRead {
    fn readable(&self) -> Result<&RetainedReadTransaction, BoundedReadError> {
        if self.history.as_ref().is_some_and(|history| {
            !history.exchange.succeeded() || !history.native.report().exchange_committed()
        }) {
            return Err(BoundedReadError::Closed);
        }
        self.ready.as_ref().ok_or(BoundedReadError::Closed)
    }

    /// Borrow only the actual captured root with caller-owned, same-database
    /// prepared backing. No raw transaction or ordinary acquisition can escape.
    pub fn check_bytes_table_prepared(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        workspace: &mut crate::PreparedPointRead,
    ) -> Result<(), BoundedReadError> {
        self.readable()?
            .check_bytes_table_prepared(definition, workspace)
    }

    pub fn get_bytes_prepared<'workspace>(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
        max_value_bytes: usize,
        workspace: &'workspace mut crate::PreparedPointRead,
    ) -> Result<Option<&'workspace [u8]>, BoundedReadError> {
        self.readable()?
            .get_bytes_prepared(definition, key, max_value_bytes, workspace)
    }

    pub fn point_length_prepared(
        &self,
        definition: TableDefinition<&[u8], &[u8]>,
        key: &[u8],
        workspace: &mut crate::PreparedPointRead,
    ) -> Result<Option<usize>, BoundedReadError> {
        self.readable()?
            .point_length_prepared(definition, key, workspace)
    }

    /// Diagnostic only; no read, provider callback or snapshot handle escapes.
    pub fn selected_generation(&self) -> Option<u64> {
        self.ready
            .as_ref()?
            .transaction
            .as_ref()
            .map(ReadTransaction::source_generation)
    }

    pub fn account_installation(&self) -> TerminalObservation<'_, SourceFundingError> {
        self.funding.installation.view()
    }
    pub fn native_report(&self) -> SourceReadReport<'_> {
        self.native.report()
    }
    pub fn prepare(
        &mut self,
        database: &RetainedDatabase,
        rights: &SourceReadRights,
    ) -> Result<(), SourceReadCallError> {
        if !self.funding.belongs_to_database(database) {
            return Err(SourceReadCallError::ForeignDatabase);
        }
        self.funding.install();
        if self.funding.installation.succeeded() {
            self.native
                .prepare_funded(database, rights, &mut self.funding)?;
        }
        Ok(())
    }
    pub fn capture(&mut self, database: &RetainedDatabase) -> Result<(), SourceReadCallError> {
        self.native.capture(database)?;
        if self.native.report().settlement() == SourceReadSettlement::Ready {
            self.ready = Some(self.native.take_ready(database)?);
        }
        Ok(())
    }
    pub fn prepare_history(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<(), SourceReadCallError> {
        if !self.funding.belongs_to_database(database) {
            return Err(SourceReadCallError::ForeignDatabase);
        }
        if self.history.is_some() {
            return Err(SourceReadCallError::WrongPhase);
        }
        let native = self
            .ready
            .as_ref()
            .ok_or(SourceReadCallError::WrongPhase)?
            .queue_source_history()?;
        self.history = Some(BoundSourceHistory {
            native,
            backend: None,
            status: BindStatus::new(),
            preparation: Attempt::Pending,
            exchange: Attempt::Pending,
            disposal: Attempt::Pending,
        });
        let history = self.history.as_mut().unwrap();
        history.preparation.run(|| {
            let mut install = SourceHistoryInstall {
                provider: &self
                    .funding
                    .owner
                    .as_ref()
                    .expect("retained funding controller")
                    .get()
                    .provider,
                status: &mut history.status,
                backend: &mut history.backend,
            };
            self.funding
                .backend
                .as_ref()
                .unwrap()
                .get()
                .install_history(&mut install)?;
            history.status.result()?;
            Ok(())
        });
        if history.preparation.succeeded() {
            history.native.prepare(database)?;
        }
        Ok(())
    }
    /// Cancel a transition without closing the captured protected root. Only
    /// known preparation success or a permit-minted/native capacity refusal
    /// qualifies; unknown callbacks, protocol errors and entered exchange stay
    /// in the original retained owner. No ordinary acquisition is performed.
    pub fn abort_history(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<SourceHistoryAbort, SourceReadCallError> {
        if !self.funding.belongs_to_database(database) {
            return Err(SourceReadCallError::ForeignDatabase);
        }
        if self
            .ready
            .as_ref()
            .is_none_or(|ready| ready.report().settlement() != ReadCloseSettlement::Open)
        {
            return Err(SourceReadCallError::WrongPhase);
        }
        let Some(history) = self.history.as_mut() else {
            return Ok(SourceHistoryAbort::Restored { refusal: None });
        };
        let provider_refusal = matches!(
            history.preparation,
            Attempt::Done(Err(SourceFundingError::Provider(_)))
        ) && history.status.state == BindState::CapacityRefused
            && history.status.rejected.is_none()
            && history.backend.is_none();
        let accepted = history.preparation.succeeded()
            && history.status.result().is_ok()
            && history.backend.is_some();
        if (!provider_refusal && !accepted)
            || !matches!(history.exchange, Attempt::Pending)
            || !history.native.history_abortable()
        {
            return Ok(SourceHistoryAbort::Retained);
        }
        history.native.cancel(database)?;
        if history.native.report().settlement() != SourceHistorySettlement::Cancelled {
            return Ok(SourceHistoryAbort::Retained);
        }
        history.native.dispose_settled(database)?;
        if history.native.report().settlement() != SourceHistorySettlement::Disposed {
            return Ok(SourceHistoryAbort::Retained);
        }
        history.disposal.run(|| {
            drop(history.backend.take());
            Ok(())
        });
        if !history.disposal.succeeded() {
            return Ok(SourceHistoryAbort::Retained);
        }
        let refusal = if provider_refusal {
            let Attempt::Done(Err(SourceFundingError::Provider(error))) =
                std::mem::replace(&mut history.preparation, Attempt::Pending)
            else {
                unreachable!("checked exact refused provider result")
            };
            Some(SourceHistoryRefusal::Provider(error))
        } else {
            history
                .native
                .take_aborted_capacity_refusal()
                .map(SourceHistoryRefusal::Native)
        };
        // Every remaining field is an empty native/backend owner or a known
        // successful scalar observation. The captured ready owner stays put.
        self.history.take();
        Ok(SourceHistoryAbort::Restored { refusal })
    }

    pub fn history_preparation(&self) -> Option<TerminalObservation<'_, SourceFundingError>> {
        self.history.as_ref().map(|h| h.preparation.view())
    }
    pub fn history_report(&self) -> Option<SourceHistoryReport<'_>> {
        self.history.as_ref().map(|h| h.native.report())
    }
    pub fn history_exchange(&self) -> Option<TerminalObservation<'_, io::Error>> {
        self.history.as_ref().map(|h| h.exchange.view())
    }
    pub fn history_disposal(&self) -> Option<TerminalObservation<'_, Infallible>> {
        self.history.as_ref().map(|h| h.disposal.view())
    }
    pub fn commit_history(
        &mut self,
        database: &RetainedDatabase,
    ) -> Result<(), SourceReadCallError> {
        if !self.funding.belongs_to_database(database) {
            return Err(SourceReadCallError::ForeignDatabase);
        }
        let history = self
            .history
            .as_mut()
            .ok_or(SourceReadCallError::WrongPhase)?;
        if !history.preparation.succeeded()
            || history.native.report().settlement() != SourceHistorySettlement::Prepared
        {
            return Err(SourceReadCallError::WrongPhase);
        }
        // The retained database borrow was acquired by the Store bridge before
        // entering the backend's bank/account locks.
        let mut native = SourceHistoryCommit {
            native: &mut history.native,
            database,
            entered: false,
        };
        history.exchange.run(|| {
            history
                .backend
                .as_mut()
                .unwrap()
                .0
                .as_deref_mut()
                .unwrap()
                .commit(&mut native)
        });
        Ok(())
    }
    pub fn close(&mut self, database: &RetainedDatabase) -> Result<(), SourceReadCallError> {
        if !self.funding.belongs_to_database(database) {
            return Err(SourceReadCallError::ForeignDatabase);
        }
        if let Some(history) = &mut self.history {
            if matches!(history.exchange, Attempt::Pending) {
                history.native.cancel(database)?;
            }
            history.native.dispose_settled(database)?;
            if history.native.report().settlement() != SourceHistorySettlement::Disposed {
                return Ok(());
            }
        }
        if let Some(ready) = &mut self.ready {
            ready.close(database);
            ready.dispose_settled(database);
        } else if self.native.report().settlement() != SourceReadSettlement::Disposed {
            if self.native.report().reader_close().is_some() {
                self.native.close_captured(database)?;
            } else {
                self.native.cancel(database)?;
            }
            self.native.dispose_settled(database)?;
        }
        Ok(())
    }
    /// Only positive native disposal authorizes account retirement. The bank
    /// observer survives the destructive backend/Arc retirement attempt.
    pub fn dispose_account(&mut self) {
        if !self.is_closed() {
            return;
        }
        // History backend holds another real account alias; retire it first,
        // retaining any destructor panic separately from earlier observations.
        if let Some(history) = &mut self.history {
            history.disposal.run(|| {
                drop(history.backend.take());
                Ok(())
            });
            if !history.disposal.succeeded() {
                return;
            }
        }
        self.funding.retire_closed();
    }
    pub fn account_pending_disposal(&self) -> TerminalObservation<'_, Infallible> {
        self.funding.pending_disposal.view()
    }
    pub fn account_release(&self) -> TerminalObservation<'_, io::Error> {
        self.funding.release.view()
    }
    pub fn account_retirement(&self) -> TerminalObservation<'_, io::Error> {
        self.funding.retirement.view()
    }
    pub fn account_controller_disposal(&self) -> TerminalObservation<'_, Infallible> {
        self.funding.controller_disposal.view()
    }
    pub fn account_disposal(&self) -> TerminalObservation<'_, Infallible> {
        self.funding.disposal.view()
    }
    /// Native disposition only. Account/controller retirement have separate
    /// reports; this alone never authorizes a source owner or Generation escape.
    pub fn is_closed(&self) -> bool {
        self.history
            .as_ref()
            .is_none_or(|h| h.native.report().settlement() == SourceHistorySettlement::Disposed)
            && self.ready.as_ref().map_or(
                self.native.report().settlement() == SourceReadSettlement::Disposed,
                |r| r.report().settlement() == ReadCloseSettlement::Disposed,
            )
    }
}

#[cfg(test)]
#[path = "source_funding_tests.rs"]
mod tests;
#[cfg(test)]
pub(crate) fn source_funding_note_deallocation(pointer: *mut u8, layout: std::alloc::Layout) {
    tests::note_deallocation(pointer, layout);
}
