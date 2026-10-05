//! Prepaid custody for scratch construction. The original native owner is never
//! transported inside an Anyhow allocation.
use super::{
    EncryptedTable, ScratchTableDatabase, TABLE,
    group::{Backend, Owner},
};
use crate::storage_census::{StorageOwnerKind, StoragePayload, StorageRegistration};
use crate::{
    NativeConstructorFailure, NativeConstructorReport, NodeDiskMemoryAdmission, ScratchDisk,
    StorageCensusDisposition, StorageOwnerId,
};
use kasumi_kv::{
    CacheConfig, NativeOpenFailure, RetainedDatabase, RetainedWriteTransaction,
    TerminalObservation, WriteTerminalSettlement,
};
use kasumi_types::SharedBudgetCharge;
use parking_lot::{Mutex, MutexGuard};
use std::{
    any::Any,
    fmt, io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

/// Construction ownership stays inline through codec and worker joins. There
/// is intentionally no StdError implementation or conversion into Anyhow.
pub enum ScratchOperationFailure {
    Creation(ScratchCreationFailure),
    AdmissionRefused(ScratchAdmissionRefusal),
    Operation(anyhow::Error),
}

/// An inventory refuses before entering a constructor. These fixed values
/// carry neither native custody nor an owning diagnostic allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScratchAdmissionRefusal {
    Busy,
    Sealed,
}
impl fmt::Display for ScratchAdmissionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Busy => "scratch constructor admission is busy",
            Self::Sealed => "scratch constructor admission is sealed",
        })
    }
}
impl From<ScratchAdmissionRefusal> for ScratchOperationFailure {
    fn from(original: ScratchAdmissionRefusal) -> Self {
        Self::AdmissionRefused(original)
    }
}
impl From<anyhow::Error> for ScratchOperationFailure {
    fn from(original: anyhow::Error) -> Self {
        Self::Operation(original)
    }
}
impl From<io::Error> for ScratchOperationFailure {
    fn from(original: io::Error) -> Self {
        Self::Operation(anyhow::Error::new(original))
    }
}
impl From<serde_json::Error> for ScratchOperationFailure {
    fn from(original: serde_json::Error) -> Self {
        Self::Operation(anyhow::Error::new(original))
    }
}
impl From<std::array::TryFromSliceError> for ScratchOperationFailure {
    fn from(original: std::array::TryFromSliceError) -> Self {
        Self::Operation(anyhow::Error::new(original))
    }
}
impl From<tokio::task::JoinError> for ScratchOperationFailure {
    fn from(original: tokio::task::JoinError) -> Self {
        Self::Operation(anyhow::Error::new(original))
    }
}
impl From<ScratchCreationFailure> for ScratchOperationFailure {
    fn from(original: ScratchCreationFailure) -> Self {
        Self::Creation(original)
    }
}
impl fmt::Display for ScratchOperationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Creation(original) => original.fmt(f),
            Self::AdmissionRefused(original) => original.fmt(f),
            Self::Operation(original) => original.fmt(f),
        }
    }
}
impl fmt::Debug for ScratchOperationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Creation(original) => f.debug_tuple("Creation").field(original).finish(),
            Self::AdmissionRefused(original) => {
                f.debug_tuple("AdmissionRefused").field(original).finish()
            }
            Self::Operation(original) => f.debug_tuple("Operation").field(original).finish(),
        }
    }
}
impl ScratchOperationFailure {
    pub fn operation(original: anyhow::Error) -> Self {
        Self::Operation(original)
    }
    pub fn ordinary<T>(body: impl FnOnce() -> anyhow::Result<T>) -> Result<T, Self> {
        body().map_err(Self::Operation)
    }
    pub fn creation(&self) -> Option<&ScratchCreationFailure> {
        match self {
            Self::Creation(original) => Some(original),
            _ => None,
        }
    }
    pub fn operation_error(&self) -> Option<&anyhow::Error> {
        match self {
            Self::Operation(original) => Some(original),
            _ => None,
        }
    }
    pub fn admission_refusal(&self) -> Option<ScratchAdmissionRefusal> {
        match self {
            Self::AdmissionRefused(original) => Some(*original),
            _ => None,
        }
    }
}

struct AdmissionState {
    original: OnceLock<io::Error>,
    retained: AtomicBool,
}

/// One prepaid constructor seat for an initial quote refusal. Its parent pays
/// `required_bytes` before construction and retains its own handle backing.
/// The original opaque diagnostic has no disposal protocol, so an occupied
/// seat remains retained even if every returned facade is canceled.
#[derive(Clone)]
pub struct ScratchAdmissionSlot {
    // Actual state/control retirement precedes the final parent charge.
    state: Arc<AdmissionState>,
    _charge: SharedBudgetCharge,
}
impl ScratchAdmissionSlot {
    pub fn required_bytes() -> io::Result<u64> {
        crate::disk_memory::arc::<AdmissionState>()
    }

    pub fn new(charge: SharedBudgetCharge) -> Self {
        Self {
            state: Arc::new(AdmissionState {
                original: OnceLock::new(),
                retained: AtomicBool::new(false),
            }),
            _charge: charge,
        }
    }

    pub fn occupied(&self) -> bool {
        self.state.original.get().is_some()
    }

    /// Installs only the original unregistered admission refusal. Registered
    /// construction owners pass through intact; an occupied seat returns the
    /// whole incoming original without projecting or disposing it.
    pub fn capture(
        &self,
        original: ScratchCreationFailure,
    ) -> Result<ScratchCreationFailure, ScratchCreationFailure> {
        if !matches!(&original.custody, Custody::Admission(_)) {
            return Ok(original);
        }
        if self.occupied() {
            return Err(original);
        }
        let Custody::Admission(original) = original.custody else {
            unreachable!();
        };
        match self.state.original.set(original) {
            Ok(()) => Ok(ScratchCreationFailure {
                custody: Custody::RetainedAdmission(self.clone()),
            }),
            Err(original) => Err(ScratchCreationFailure {
                custody: Custody::Admission(original),
            }),
        }
    }

    /// Reacquires the same original without allocating or granting disposal
    /// authority. No native construction is entered by this operation.
    pub fn original_failure(&self) -> Option<ScratchCreationFailure> {
        self.occupied().then(|| ScratchCreationFailure {
            custody: Custody::RetainedAdmission(self.clone()),
        })
    }

    fn with_diagnostic<R>(
        &self,
        inspect: impl for<'a> FnOnce(Option<ScratchCreationReport<'a>>) -> R,
    ) -> R {
        inspect(
            self.state
                .original
                .get()
                .map(|original| ScratchCreationReport {
                    inner: ReportInner::Admission(original),
                }),
        )
    }
}
impl Drop for ScratchAdmissionSlot {
    fn drop(&mut self) {
        if self.occupied() && !self.state.retained.swap(true, Ordering::AcqRel) {
            // One bounded same-slot alias retains both actual backing and its
            // original charge. Drop is not an opaque IO disposal observation.
            std::mem::forget(self.clone());
        }
    }
}

enum Custody {
    Admission(io::Error),
    RetainedAdmission(ScratchAdmissionSlot),
    Constructor(NativeConstructorFailure),
    Registered(StorageRegistration<CreationOwner>),
}
/// A typed facade to the original prepaid slot. Dropping a facade grants no
/// deallocation or native-disposal authority to that slot.
#[must_use]
pub struct ScratchCreationFailure {
    custody: Custody,
}
impl fmt::Display for ScratchCreationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(id) = self.owner_id() {
            write!(f, "scratch creation owner {id:?}: ")?;
        }
        self.with_diagnostic(|report| match report {
            Some(report) => report.fmt(f),
            None => f.write_str("scratch creation report is busy; original retained"),
        })
    }
}
impl fmt::Debug for ScratchCreationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScratchCreationFailure")
            .field("owner", &self.owner_id())
            .finish_non_exhaustive()
    }
}

/// One exact borrow; neither native authority nor an owning diagnostic can
/// escape this report's lifetime.
pub struct ScratchCreationReport<'a> {
    inner: ReportInner<'a>,
}
enum ReportInner<'a> {
    Admission(&'a io::Error),
    Constructor(NativeConstructorReport<'a>),
    Registered(MutexGuard<'a, State>),
}
impl<'report> ScratchCreationReport<'report> {
    pub fn constructor_report(&self) -> Option<&NativeConstructorReport<'report>> {
        match &self.inner {
            ReportInner::Constructor(report) => Some(report),
            _ => None,
        }
    }
    pub fn admission_error(&self) -> Option<&io::Error> {
        match &self.inner {
            ReportInner::Admission(original) => Some(original),
            ReportInner::Constructor(report) => match report.provider() {
                TerminalObservation::Returned(Err(original)) => Some(original),
                _ => None,
            },
            ReportInner::Registered(state) => state
                .acquisition_error
                .as_ref()
                .map(super::group::OwnerCreationFailure::original),
        }
    }
    pub fn opening_error(&self) -> Option<&kasumi_kv::CoreError> {
        match &self.inner {
            ReportInner::Registered(state) => state.opening_failure.as_ref()?.original_error(),
            _ => None,
        }
    }
    pub fn with_acquisition_disposal<R>(
        &self,
        inspect: impl for<'a> FnOnce(Option<TerminalObservation<'a, std::convert::Infallible>>) -> R,
    ) -> R {
        match &self.inner {
            ReportInner::Registered(state) => {
                if let Some(original) = &state.acquisition_error {
                    original.with_root_disposal(inspect)
                } else {
                    inspect(None)
                }
            }
            _ => inspect(None),
        }
    }
    pub fn opening_returned_ok(&self) -> bool {
        match &self.inner {
            ReportInner::Registered(state) => state
                .opening_failure
                .as_ref()
                .is_some_and(NativeOpenFailure::opening_returned_ok),
            _ => false,
        }
    }
    pub fn opening_close(&self) -> Option<&kasumi_kv::BackendCloseOutcome> {
        match &self.inner {
            ReportInner::Registered(state) => state.opening_failure.as_ref()?.close_report(),
            _ => None,
        }
    }
    pub fn opening_close_panic(&self) -> Option<&kasumi_kv::CorePanic> {
        match &self.inner {
            ReportInner::Registered(state) => state.opening_failure.as_ref()?.close_panic(),
            _ => None,
        }
    }
    pub fn opening_disposal(&self) -> Option<kasumi_kv::NativeDisposalReport<'_>> {
        match &self.inner {
            ReportInner::Registered(state) => Some(state.opening_failure.as_ref()?.disposal()),
            _ => None,
        }
    }
    pub fn setup_begin(&self) -> Option<&kasumi_kv::TransactionError> {
        match &self.inner {
            ReportInner::Registered(state) => state.begin_error.as_ref(),
            _ => None,
        }
    }
    pub fn setup_table(&self) -> Option<&kasumi_kv::TableError> {
        match &self.inner {
            ReportInner::Registered(state) => state.table_error.as_ref(),
            _ => None,
        }
    }
    pub fn setup_terminal(&self) -> Option<kasumi_kv::WriteTerminalReport<'_>> {
        match &self.inner {
            ReportInner::Registered(state) => Some(state.writer.as_ref()?.report()),
            _ => None,
        }
    }
    pub fn setup_close(&self) -> Option<kasumi_kv::DatabaseCloseReport<'_>> {
        match &self.inner {
            ReportInner::Registered(state) => Some(state.native.as_ref()?.report()),
            _ => None,
        }
    }
    pub fn panic(&self) -> Option<&(dyn Any + Send)> {
        match &self.inner {
            ReportInner::Constructor(report) => {
                if let TerminalObservation::Panicked(original) = report.provider() {
                    return Some(original);
                }
                if let TerminalObservation::Panicked(original) = report.construction() {
                    return Some(original);
                }
                if let TerminalObservation::Panicked(original) = report.lease_cleanup() {
                    return Some(original);
                }
                if let TerminalObservation::Panicked(original) = report.diagnostic_cleanup() {
                    return Some(original);
                }
                None
            }
            ReportInner::Registered(state) => state.outer_panic.as_deref(),
            _ => None,
        }
    }
}
impl fmt::Display for ScratchCreationReport<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("scratch table creation failed")?;
        if let Some(original) = self.admission_error() {
            write!(f, ": {original}")?;
        } else if let Some(original) = self.opening_error() {
            write!(f, ": {original}")?;
        } else if self.opening_returned_ok() {
            f.write_str(" after opening returned successfully; cleanup retained")?;
        } else if let Some(original) = self.setup_begin() {
            write!(f, " at setup begin: {original}")?;
        } else if let Some(original) = self.setup_table() {
            write!(f, " at setup table: {original}")?;
        } else if let Some(report) = self.setup_terminal() {
            match report.terminal() {
                TerminalObservation::Returned(Err(original)) => {
                    write!(f, " at setup terminal: {original:?}")?
                }
                TerminalObservation::Panicked(_) => {
                    f.write_str(" at setup terminal: original panic retained")?
                }
                _ => f.write_str("; setup completion retained")?,
            }
        }
        if let Some(report) = self.constructor_report()
            && report.protocol().is_some()
        {
            f.write_str("; constructor protocol retained")?;
        }
        if self.panic().is_some() {
            f.write_str("; original construction panic retained")?;
        }
        Ok(())
    }
}
impl ScratchCreationFailure {
    /// Reborrow the same original construction after a foreign transport has
    /// rendered its owner ID. Provider, payload type and generation must match;
    /// lookup creates neither a new grant nor a completion acknowledgment.
    pub fn retained(
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    ) -> Option<Self> {
        if let Some(original) = provider
            .storage_census()
            .retained_native_constructor::<CreationOwner>(provider.clone(), id)
        {
            return Some(Self {
                custody: Custody::Constructor(original),
            });
        }
        let owner = provider
            .storage_census()
            .retained::<CreationOwner>(provider.clone(), id)?;
        {
            let state = owner.owner().state.try_lock()?;
            if state.constructing || state.table.is_some() {
                return None;
            }
        }
        Some(Self {
            custody: Custody::Registered(owner),
        })
    }

    pub fn owner_id(&self) -> Option<StorageOwnerId> {
        match &self.custody {
            Custody::Admission(_) | Custody::RetainedAdmission(_) => None,
            Custody::Constructor(original) => original.id(),
            Custody::Registered(owner) => Some(owner.id()),
        }
    }
    pub fn with_diagnostic<R>(
        &self,
        inspect: impl for<'a> FnOnce(Option<ScratchCreationReport<'a>>) -> R,
    ) -> R {
        match &self.custody {
            Custody::Admission(original) => inspect(Some(ScratchCreationReport {
                inner: ReportInner::Admission(original),
            })),
            Custody::RetainedAdmission(slot) => slot.with_diagnostic(inspect),
            Custody::Constructor(original) => original.with_report(|report| {
                inspect(report.map(|report| ScratchCreationReport {
                    inner: ReportInner::Constructor(report),
                }))
            }),
            Custody::Registered(owner) => {
                inspect(
                    owner
                        .owner()
                        .state
                        .try_lock()
                        .map(|state| ScratchCreationReport {
                            inner: ReportInner::Registered(state),
                        }),
                )
            }
        }
    }
    /// Explicit report acknowledgment. The independent census performs actual
    /// native and payload disposal before its original backing lease may retire.
    pub fn retire(self) -> ScratchCreationRetirement {
        match self.custody {
            Custody::Admission(original) => {
                drop(original);
                ScratchCreationRetirement {
                    custody: RetirementCustody::Released,
                    disposition: StorageCensusDisposition::Retired,
                }
            }
            Custody::RetainedAdmission(slot) => ScratchCreationRetirement {
                custody: RetirementCustody::Admission(slot),
                disposition: StorageCensusDisposition::Retained,
            },
            Custody::Constructor(original) => {
                let disposition = original.cleanup();
                ScratchCreationRetirement {
                    custody: RetirementCustody::Constructor(original),
                    disposition,
                }
            }
            Custody::Registered(owner) => {
                owner.owner().acknowledged.store(true, Ordering::Release);
                let provider = owner.owner().provider.clone();
                let id = owner.id();
                let disposition = owner.retire();
                ScratchCreationRetirement {
                    custody: RetirementCustody::Registered { provider, id },
                    disposition,
                }
            }
        }
    }
}
pub struct ScratchCreationRetirement {
    custody: RetirementCustody,
    disposition: StorageCensusDisposition,
}
enum RetirementCustody {
    Released,
    Registered {
        provider: Arc<dyn NodeDiskMemoryAdmission>,
        id: StorageOwnerId,
    },
    Admission(ScratchAdmissionSlot),
    Constructor(NativeConstructorFailure),
}
impl ScratchCreationRetirement {
    pub fn disposition(&self) -> StorageCensusDisposition {
        self.disposition
    }
    pub fn retry(&self) -> StorageCensusDisposition {
        match &self.custody {
            RetirementCustody::Released => StorageCensusDisposition::Retired,
            RetirementCustody::Admission(_) => StorageCensusDisposition::Retained,
            RetirementCustody::Constructor(original) => original.cleanup(),
            RetirementCustody::Registered { provider, id } => {
                match provider.storage_census().drain_owner(*id) {
                    StorageCensusDisposition::Stale => StorageCensusDisposition::Retired,
                    outcome => outcome,
                }
            }
        }
    }
    pub fn with_diagnostic<R>(
        &self,
        inspect: impl for<'a> FnOnce(Option<ScratchCreationReport<'a>>) -> R,
    ) -> R {
        let (provider, id) = match &self.custody {
            RetirementCustody::Released => return inspect(None),
            RetirementCustody::Admission(slot) => return slot.with_diagnostic(inspect),
            RetirementCustody::Constructor(original) => {
                return original.with_report(|report| {
                    inspect(report.map(|report| ScratchCreationReport {
                        inner: ReportInner::Constructor(report),
                    }))
                });
            }
            RetirementCustody::Registered { provider, id } => (provider, id),
        };
        let Some(owner) = provider
            .storage_census()
            .retained::<CreationOwner>(provider.clone(), *id)
        else {
            return inspect(None);
        };
        inspect(
            owner
                .owner()
                .state
                .try_lock()
                .map(|state| ScratchCreationReport {
                    inner: ReportInner::Registered(state),
                }),
        )
    }
}

struct State {
    acquisition_error: Option<super::group::OwnerCreationFailure>,
    opening_failure: Option<NativeOpenFailure<Backend>>,
    native: Option<RetainedDatabase>,
    writer: Option<RetainedWriteTransaction>,
    setup_table: Option<kasumi_kv::Table<&'static [u8], &'static [u8]>>,
    begin_error: Option<kasumi_kv::TransactionError>,
    table_error: Option<kasumi_kv::TableError>,
    outer_panic: Option<Box<dyn Any + Send>>,
    table: Option<Arc<ScratchTableDatabase>>,
    acquired_owner: Option<Arc<Owner>>,
    constructing: bool,
}
impl State {
    fn new() -> Self {
        Self {
            acquisition_error: None,
            opening_failure: None,
            native: None,
            writer: None,
            setup_table: None,
            begin_error: None,
            table_error: None,
            outer_panic: None,
            table: None,
            acquired_owner: None,
            constructing: true,
        }
    }
}
struct CreationOwner {
    provider: Arc<dyn NodeDiskMemoryAdmission>,
    state: Mutex<State>,
    acknowledged: AtomicBool,
}
impl Drop for CreationOwner {
    fn drop(&mut self) {
        let id = self
            .state
            .get_mut()
            .acquired_owner
            .as_ref()
            .map(|owner| owner.census_id());
        // Census has already observed native disposal. Destroy every original
        // slot, facade and Owner alias before driving that exact Owner's grant.
        let original = std::mem::replace(self.state.get_mut(), State::new());
        drop(original);
        if let Some(id) = id {
            let _ = self.provider.storage_census().drain_owner(id);
        }
    }
}
impl StoragePayload for CreationOwner {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        let Some(mut state) = self.state.try_lock() else {
            return false;
        };
        if state.constructing
            || !self.acknowledged.load(Ordering::Acquire)
            || state.outer_panic.is_some()
        {
            return false;
        }
        if !settle_native(&mut state) {
            return false;
        }
        if let Some(table) = &state.table {
            if Arc::strong_count(table) != 1 {
                return false;
            }
            if !table
                .retained_batches
                .try_lock()
                .is_some_and(|batches| batches.is_none())
            {
                return false;
            }
            if table.database().close_direct_native().is_none() {
                return false;
            }
            if !table
                .database()
                .dispose_direct_native()
                .is_some_and(|report| report.disposal_complete())
            {
                return false;
            }
        }
        true
    }
}
fn settle_native(state: &mut State) -> bool {
    if state
        .acquisition_error
        .as_ref()
        .is_some_and(|original| !original.settle_root_memory())
    {
        return false;
    }
    if let Some(original) = state.opening_failure.as_mut()
        && !original.dispose().complete()
    {
        return false;
    }
    if state.native.is_some() {
        let State {
            native,
            writer,
            setup_table,
            ..
        } = &mut *state;
        if setup_table.is_some() {
            return false;
        }
        let native = native.as_mut().unwrap();
        if let Some(writer) = writer.as_mut() {
            if writer.report().operation().is_none() {
                writer.abort();
            }
            if writer.report().settlement() != WriteTerminalSettlement::Settled {
                return false;
            }
            if !writer.dispose_settled(native).disposal_complete() {
                return false;
            }
        }
        native.close();
        if !native.dispose().disposal().complete() {
            return false;
        }
    }
    true
}

pub(super) fn create(
    disk: &Arc<ScratchDisk>,
    max_disk_bytes: u64,
    cache: CacheConfig,
) -> Result<EncryptedTable, ScratchCreationFailure> {
    let provider = disk.memory().clone();
    let owner = register(provider)?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        construct(owner.owner(), owner.id(), disk, max_disk_bytes, cache)
    }));
    finish(owner, result)
}
fn register(
    provider: Arc<dyn NodeDiskMemoryAdmission>,
) -> Result<StorageRegistration<CreationOwner>, ScratchCreationFailure> {
    let backing = crate::disk_memory::arc::<ScratchTableDatabase>().map_err(|original| {
        ScratchCreationFailure {
            custody: Custody::Admission(original),
        }
    })?;
    provider
        .storage_census()
        .register_native(provider.clone(), backing, |_| CreationOwner {
            provider: provider.clone(),
            state: Mutex::new(State::new()),
            acknowledged: AtomicBool::new(false),
        })
        .map_err(|original| ScratchCreationFailure {
            custody: match original {
                NativeConstructorFailure::Preclaim(original) => Custody::Admission(original),
                original => Custody::Constructor(original),
            },
        })
}
fn finish(
    owner: StorageRegistration<CreationOwner>,
    result: Result<(), Box<dyn Any + Send>>,
) -> Result<EncryptedTable, ScratchCreationFailure> {
    let mut state = owner.owner().state.lock();
    state.constructing = false;
    if let Err(original) = result {
        state.outer_panic = Some(original);
    }
    if state.table.is_none()
        && state.outer_panic.is_none()
        && let Err(original) = catch_unwind(AssertUnwindSafe(|| settle_native(&mut state)))
    {
        state.outer_panic = Some(original);
    }
    if let Some(table) = &state.table {
        let table = EncryptedTable {
            owner: super::ScratchTableRef::new(table.clone()),
        };
        owner.owner().acknowledged.store(true, Ordering::Release);
        drop(state);
        return Ok(table);
    }
    drop(state);
    Err(ScratchCreationFailure {
        custody: Custody::Registered(owner),
    })
}
fn construct(
    request: &CreationOwner,
    id: StorageOwnerId,
    disk: &Arc<ScratchDisk>,
    max_disk_bytes: u64,
    cache: CacheConfig,
) {
    let admission = match Owner::new(disk, max_disk_bytes) {
        Ok(owner) => owner,
        Err(original) => {
            request.state.lock().acquisition_error = Some(original);
            return;
        }
    };
    open(request, id, admission, cache);
}
fn open(request: &CreationOwner, id: StorageOwnerId, admission: Arc<Owner>, cache: CacheConfig) {
    request.state.lock().acquired_owner = Some(admission.clone());
    let database = match kasumi_kv::Database::builder(
        admission.clone(),
        *uuid::Uuid::new_v4().as_bytes(),
        cache,
    )
    .create_with_backend(Backend(admission.clone()))
    {
        Ok(database) => database,
        Err(original) => {
            request.state.lock().opening_failure = Some(original);
            return;
        }
    };
    setup(request, id, database, admission);
}
fn setup(
    request: &CreationOwner,
    id: StorageOwnerId,
    database: kasumi_kv::Database,
    admission: Arc<Owner>,
) {
    // Install the successful whole native database before setup can unwind.
    let mut state = request.state.lock();
    state.native = Some(database.retain());
    let transaction = match state
        .native
        .as_ref()
        .unwrap()
        .database()
        .unwrap()
        .begin_write()
    {
        Ok(transaction) => transaction,
        Err(original) => {
            state.begin_error = Some(original);
            return;
        }
    };
    state.writer = Some(transaction.retain());
    match state
        .writer
        .as_ref()
        .unwrap()
        .transaction()
        .unwrap()
        .open_table(TABLE)
    {
        Ok(table) => state.setup_table = Some(table),
        Err(original) => {
            state.table_error = Some(original);
            return;
        }
    }
    // The actual table handle is outside the callback's stack until its one
    // disposal returns. A destructor panic stays in this prepaid request.
    drop(state.setup_table.take());
    let terminal = state.writer.as_mut().unwrap().commit();
    if !matches!(terminal.terminal(), TerminalObservation::Returned(Ok(())))
        || terminal.settlement() != WriteTerminalSettlement::Settled
    {
        return;
    }
    let State { native, writer, .. } = &mut *state;
    if !writer
        .as_mut()
        .unwrap()
        .dispose_settled(native.as_ref().unwrap())
        .disposal_complete()
    {
        return;
    }
    drop(state.writer.take());
    let native = state.native.take().unwrap();
    let table = Arc::new(ScratchTableDatabase {
        database: Some(crate::node_database::NodeDatabase::new_retained(
            native,
            "encrypted scratch table",
        )),
        admission,
        retained_batches: parking_lot::Mutex::new(None),
        retirement: (request.provider.clone(), id),
    });
    state.table = Some(table);
}

#[cfg(test)]
pub(super) fn create_owned(
    admission: Arc<Owner>,
    cache: CacheConfig,
) -> Result<EncryptedTable, ScratchCreationFailure> {
    let owner = register(admission.provider())?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        open(owner.owner(), owner.id(), admission, cache)
    }));
    finish(owner, result)
}
#[cfg(test)]
pub(super) fn initialize(
    database: kasumi_kv::Database,
    admission: Arc<Owner>,
) -> Result<EncryptedTable, ScratchCreationFailure> {
    let owner = register(admission.provider())?;
    owner.owner().state.lock().acquired_owner = Some(admission.clone());
    let result = catch_unwind(AssertUnwindSafe(|| {
        setup(owner.owner(), owner.id(), database, admission)
    }));
    finish(owner, result)
}

// The malformed-schema regression must reach the real batch-open continuation
// with its incompatible native catalog. It still installs the actual database
// in the same prepaid request before constructing a table owner.
#[cfg(test)]
pub(super) fn initialize_without_table_setup(
    database: kasumi_kv::Database,
    admission: Arc<Owner>,
) -> Result<EncryptedTable, ScratchCreationFailure> {
    let owner = register(admission.provider())?;
    {
        let mut state = owner.owner().state.lock();
        state.acquired_owner = Some(admission.clone());
        state.native = Some(database.retain());
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let request = owner.owner();
        let mut state = request.state.lock();
        let native = state.native.take().unwrap();
        state.table = Some(Arc::new(ScratchTableDatabase {
            database: Some(crate::node_database::NodeDatabase::new_retained(
                native,
                "batch type fixture",
            )),
            admission,
            retained_batches: parking_lot::Mutex::new(None),
            retirement: (request.provider.clone(), owner.id()),
        }));
    }));
    finish(owner, result)
}

#[cfg(test)]
#[path = "scratch_creation_tests.rs"]
mod tests;
