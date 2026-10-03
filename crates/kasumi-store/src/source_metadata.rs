//! Closed Store metadata funding. These constructors fund registered source
//! control/report/census owners only; no canonical or encrypted read scratch.
use crate::{DiskMemoryLease, NodeDiskMemoryAdmission, StorageOwnerId, disk_memory};
use kasumi_kv::TerminalObservation;
use std::{
    any::Any,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, MutexGuard, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
};

#[path = "source_metadata_bank.rs"]
mod bank;
pub(crate) use bank::{
    SourceMetadataAccount, SourceMetadataBankHold, SourceMetadataHistory, SourceMetadataRetirement,
    SourceMetadataWitness, SourcePayloadGrant, SourceReportGrant, StoreSourceMetadataBank,
};

/// Constructor-selected metadata purpose. Callers cannot create an installer
/// or turn a byte amount into authority. History consumes ordinary source
/// capacity before the protected assignment is transferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceMetadataPurpose {
    Control,
    Fixed,
    PublicationLane,
    History,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceMetadataCallError {
    ForeignProvider,
    AlreadyEntered,
    MissingBinding,
}

#[derive(Clone, Copy)]
enum Binding {
    Fresh,
    Claimed,
    Bound,
    CapacityRefused,
}
struct BindStatus {
    binding: Binding,
    rejected: Option<SourceMetadataCallError>,
}
impl BindStatus {
    const fn new() -> Self {
        Self {
            binding: Binding::Fresh,
            rejected: None,
        }
    }
    fn claim(&mut self, same: bool) -> Result<(), SourceMetadataCallError> {
        let error = self.rejected.or({
            if !same {
                Some(SourceMetadataCallError::ForeignProvider)
            } else if !matches!(self.binding, Binding::Fresh) {
                Some(SourceMetadataCallError::AlreadyEntered)
            } else {
                None
            }
        });
        if let Some(error) = error {
            self.rejected.get_or_insert(error);
            return Err(error);
        }
        self.binding = Binding::Claimed;
        Ok(())
    }
    fn result(&self) -> Result<(), SourceMetadataCallError> {
        if let Some(error) = self.rejected {
            return Err(error);
        }
        if matches!(self.binding, Binding::Bound) {
            Ok(())
        } else {
            Err(SourceMetadataCallError::MissingBinding)
        }
    }
}

/// Provider callback capability minted only by the registered Store owner.
/// ```compile_fail
/// let _ = kasumi_store::SourceMetadataInstall {};
/// ```
pub struct SourceMetadataInstall<'a> {
    expected: &'a Arc<dyn NodeDiskMemoryAdmission>,
    purpose: SourceMetadataPurpose,
    bytes: u64,
    status: &'a mut BindStatus,
    pending: &'a mut Option<DiskMemoryLease>,
}
impl SourceMetadataInstall<'_> {
    pub fn try_begin_bind(
        &mut self,
        provider: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<SourceMetadataPermit<'_>, SourceMetadataCallError> {
        self.status.claim(Arc::ptr_eq(self.expected, &provider))?;
        Ok(SourceMetadataPermit {
            purpose: self.purpose,
            bytes: self.bytes,
            status: self.status,
            pending: self.pending,
        })
    }
}
/// One preconstruction permit; it cannot be cloned or constructed externally.
/// The provider adds its concrete token Box quote before reserving bytes.
/// ```compile_fail
/// let _ = kasumi_store::SourceMetadataPermit {};
/// ```
pub struct SourceMetadataPermit<'a> {
    purpose: SourceMetadataPurpose,
    bytes: u64,
    status: &'a mut BindStatus,
    pending: &'a mut Option<DiskMemoryLease>,
}
impl SourceMetadataPermit<'_> {
    pub fn purpose(&self) -> SourceMetadataPurpose {
        self.purpose
    }
    pub fn request_bytes(&self) -> u64 {
        self.bytes
    }
    /// Installed-provider proof that its actual ordinary reservation refused
    /// capacity before binding a token or changing any source account. Generic
    /// returned errors and destructor observations cannot mint this proof.
    pub fn refuse_capacity(self, original: io::Error) -> io::Error {
        self.status.binding = Binding::CapacityRefused;
        original
    }

    /// The closed allocation holder owns T before any provider continuation.
    /// No callbacks, fallible conversion or raw token extraction are involved.
    pub fn bind<T: Send + Sync + 'static>(self, token: T) {
        *self.pending = Some(DiskMemoryLease::new(token));
        self.status.binding = Binding::Bound;
    }
}

pub(crate) enum MetadataAttempt<E> {
    Pending,
    Entered,
    Returned(Result<(), E>),
    Panicked(Box<dyn Any + Send>),
}
impl<E> MetadataAttempt<E> {
    pub(crate) const fn new() -> Self {
        Self::Pending
    }
    pub(crate) fn run(&mut self, work: impl FnOnce() -> Result<(), E>) {
        if !matches!(self, Self::Pending) {
            return;
        }
        *self = Self::Entered;
        *self = match catch_unwind(AssertUnwindSafe(work)) {
            Ok(value) => Self::Returned(value),
            Err(payload) => Self::Panicked(payload),
        };
    }
    pub(crate) fn retry_success(&mut self) {
        if self.succeeded() {
            *self = Self::Pending;
        }
    }
    pub(crate) fn succeeded(&self) -> bool {
        matches!(self, Self::Returned(Ok(())))
    }
    pub(crate) fn failed(&self) -> bool {
        matches!(
            self,
            Self::Entered | Self::Returned(Err(_)) | Self::Panicked(_)
        )
    }
    pub(crate) fn pending(&self) -> bool {
        matches!(self, Self::Pending)
    }
    pub(crate) fn view(&self) -> TerminalObservation<'_, E> {
        match self {
            Self::Pending => TerminalObservation::NotEntered,
            Self::Entered => TerminalObservation::Entered,
            Self::Returned(Ok(())) => TerminalObservation::Returned(Ok(())),
            Self::Returned(Err(error)) => TerminalObservation::Returned(Err(error)),
            Self::Panicked(payload) => TerminalObservation::Panicked(payload.as_ref()),
        }
    }
}

// The preparation always owns a bound token on provider Err/panic. Its original
// provider error stays distinct from the fixed protocol marker and cleanup.
pub(crate) struct MetadataPreparation {
    status: BindStatus,
    original: MetadataAttempt<io::Error>,
    cleanup: MetadataAttempt<std::convert::Infallible>,
    lease: Option<DiskMemoryLease>,
    request: Option<(SourceMetadataPurpose, u64)>,
    provider: Option<Arc<dyn NodeDiskMemoryAdmission>>,
}
impl MetadataPreparation {
    pub(crate) const fn new() -> Self {
        Self {
            status: BindStatus::new(),
            original: MetadataAttempt::new(),
            cleanup: MetadataAttempt::new(),
            lease: None,
            request: None,
            provider: None,
        }
    }
    pub(crate) fn acquire(
        &mut self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        purpose: SourceMetadataPurpose,
        bytes: u64,
    ) {
        if self.original.pending() {
            self.provider = Some(provider.clone());
            self.request = Some((purpose, bytes));
        }
        self.original.run(|| {
            let mut install = SourceMetadataInstall {
                expected: provider,
                purpose,
                bytes,
                status: &mut self.status,
                pending: &mut self.lease,
            };
            provider.clone().install_source_metadata(&mut install)
        });
    }
    pub(crate) fn ready(&self) -> bool {
        self.original.succeeded() && self.status.result().is_ok() && self.lease.is_some()
    }
    pub(crate) fn matches_for(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        purpose: SourceMetadataPurpose,
        bytes: u64,
    ) -> bool {
        self.request == Some((purpose, bytes))
            && self
                .provider
                .as_ref()
                .is_some_and(|actual| Arc::ptr_eq(actual, provider))
    }
    pub(crate) fn ready_for(
        &self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        purpose: SourceMetadataPurpose,
        bytes: u64,
    ) -> bool {
        self.ready() && self.matches_for(provider, purpose, bytes)
    }
    pub(crate) fn take_for(
        &mut self,
        provider: &Arc<dyn NodeDiskMemoryAdmission>,
        purpose: SourceMetadataPurpose,
        bytes: u64,
    ) -> Option<DiskMemoryLease> {
        if self.ready_for(provider, purpose, bytes) {
            self.lease.take()
        } else {
            None
        }
    }
    pub(crate) fn clean_history_refusal(&self) -> bool {
        matches!(self.original, MetadataAttempt::Returned(Err(_)))
            && matches!(self.status.binding, Binding::CapacityRefused)
            && self.status.rejected.is_none()
            && self.lease.is_none()
            && self
                .request
                .is_some_and(|(purpose, _)| purpose == SourceMetadataPurpose::History)
    }
    pub(crate) fn accepted(&self) -> bool {
        self.original.succeeded() && self.status.result().is_ok()
    }
    pub(crate) fn take_clean_history_refusal(&mut self) -> Option<io::Error> {
        if !self.clean_history_refusal() || !self.disposed() {
            return None;
        }
        let MetadataAttempt::Returned(Err(error)) =
            std::mem::replace(&mut self.original, MetadataAttempt::Pending)
        else {
            unreachable!("checked disposed history refusal")
        };
        Some(error)
    }

    pub(crate) fn failed(&self) -> bool {
        self.original.failed() || (self.original.succeeded() && self.status.result().is_err())
    }
    pub(crate) fn original(&self) -> TerminalObservation<'_, io::Error> {
        self.original.view()
    }
    pub(crate) fn protocol(&self) -> Option<SourceMetadataCallError> {
        if self.original.succeeded() {
            self.status.result().err()
        } else {
            self.status.rejected
        }
    }
    pub(crate) fn dispose(&mut self) {
        self.cleanup.run(|| {
            drop(self.lease.take());
            Ok(())
        });
    }
    pub(crate) fn disposed(&self) -> bool {
        self.cleanup.succeeded()
    }
    pub(crate) fn cleanup(&self) -> TerminalObservation<'_, std::convert::Infallible> {
        self.cleanup.view()
    }
}

fn invalid() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}
fn poisoned<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::ErrorKind::Other.into()
}
fn try_lock<T>(lock: &Mutex<T>) -> io::Result<Option<MutexGuard<'_, T>>> {
    match lock.try_lock() {
        Ok(guard) => Ok(Some(guard)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Poisoned(_)) => Err(io::ErrorKind::Other.into()),
    }
}
