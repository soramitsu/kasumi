//! Fresh admission of installed original tenants after a permanently closed
//! serving instance. Old engines, captured replies and storage handles stay shut.
use super::*;
use std::fmt;

/// Fixed, non-sensitive stage at which one fresh original admission attempt
/// stopped. Attached as error context; the underlying cause is never logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoverStage {
    EnrollmentMismatch,
    PreviousLeaseRetained,
    PreviousDetach,
    PreviousShutdownRetained,
    CustodyOpen,
    AccessLease,
    KeyProvider,
    StorageOpen,
    AdmissionReserve,
    EngineOpen,
    RouteRegister,
    SetupRouteChanged,
    Publish,
    Initialize,
}
impl RecoverStage {
    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::EnrollmentMismatch => "enrollment_mismatch",
            Self::PreviousLeaseRetained => "previous_lease_retained",
            Self::PreviousDetach => "previous_detach",
            Self::PreviousShutdownRetained => "previous_shutdown_retained",
            Self::CustodyOpen => "custody_open",
            Self::AccessLease => "access_lease",
            Self::KeyProvider => "key_provider",
            Self::StorageOpen => "storage_open",
            Self::AdmissionReserve => "admission_reserve",
            Self::EngineOpen => "engine_open",
            Self::RouteRegister => "route_register",
            Self::SetupRouteChanged => "setup_route_changed",
            Self::Publish => "publish",
            Self::Initialize => "initialize",
        }
    }
}
impl fmt::Display for RecoverStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class())
    }
}

#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "whole returned custody is inline in the initial admitted seat; boxing on failure would allocate outside that admission"
)]
enum RecoveryOriginal {
    Snapshot(kasumi_engine::SnapshotFailure),
    Retired(crate::runtime::RetiredSourceFailure),
}
impl RecoveryOriginal {
    fn original(&self) -> &kasumi_engine::SnapshotFailure {
        match self {
            Self::Snapshot(original) => original,
            Self::Retired(original) => original.original(),
        }
    }
}

/// The returned body and independently observed cleanup owners stay
/// inline. A scratch creation original never becomes an Anyhow context.
#[derive(Debug)]
pub(crate) struct OriginalRecoveryFailure {
    original: RecoveryOriginal,
    stage: Option<RecoverStage>,
    route_cleanup: Option<anyhow::Error>,
    database_cleanup: Option<DrainFailure>,
    stores_cleanup: Option<DrainFailure>,
    retired_cleanup: Option<DrainFailure>,
}
impl OriginalRecoveryFailure {
    fn snapshot_at(original: kasumi_engine::SnapshotFailure, stage: RecoverStage) -> Self {
        let mut failure = Self::from(original);
        failure.stage = Some(stage);
        failure
    }
    pub(crate) fn source_stage(&self) -> Option<&RecoverStage> {
        self.stage.as_ref().or_else(|| {
            self.original()
                .source_error()
                .and_then(|original| original.downcast_ref::<RecoverStage>())
        })
    }
    pub(crate) fn original(&self) -> &kasumi_engine::SnapshotFailure {
        self.original.original()
    }
}
impl From<kasumi_engine::SnapshotFailure> for OriginalRecoveryFailure {
    fn from(original: kasumi_engine::SnapshotFailure) -> Self {
        Self {
            original: RecoveryOriginal::Snapshot(original),
            stage: None,
            route_cleanup: None,
            database_cleanup: None,
            stores_cleanup: None,
            retired_cleanup: None,
        }
    }
}
impl From<crate::runtime::RetiredSourceFailure> for OriginalRecoveryFailure {
    fn from(original: crate::runtime::RetiredSourceFailure) -> Self {
        Self {
            original: RecoveryOriginal::Retired(original),
            stage: Some(RecoverStage::CustodyOpen),
            route_cleanup: None,
            database_cleanup: None,
            stores_cleanup: None,
            retired_cleanup: None,
        }
    }
}
impl From<anyhow::Error> for OriginalRecoveryFailure {
    fn from(original: anyhow::Error) -> Self {
        kasumi_engine::SnapshotFailure::from(original).into()
    }
}
impl From<uuid::Error> for OriginalRecoveryFailure {
    fn from(original: uuid::Error) -> Self {
        anyhow::Error::new(original).into()
    }
}
impl From<DrainFailure> for OriginalRecoveryFailure {
    fn from(original: DrainFailure) -> Self {
        anyhow::Error::new(original).into()
    }
}

#[derive(Default)]
struct RecoverySeat {
    // The original native startup carrier is never normalized to a scratch or
    // Anyhow error. This fixed lane is paid by the same initial inventory.
    node_start: Option<kasumi_store::NodeStoreStartFailure>,
    node_start_output: Option<kasumi_store::NodeStore>,
    node_start_observation: CleanupObservation,
    failure: Option<OriginalRecoveryFailure>,
    database: Option<Arc<Database>>,
    stores: Option<Arc<TenantStorageSet>>,
    retired: Option<Arc<kasumi_engine::RetiredCustody>>,
    route_to_unregister: Option<String>,
    route_observation: CleanupObservation,
    database_observation: CleanupObservation,
    stores_observation: CleanupObservation,
    retired_observation: CleanupObservation,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum CleanupEntry {
    #[default]
    NotEntered,
    Entered,
    Returned,
    Panicked,
}
#[derive(Default)]
pub(crate) struct CleanupObservation {
    entry: CleanupEntry,
    panic: Option<Box<dyn std::any::Any + Send>>,
    future_disposal: CleanupEntry,
    disposal_panic: Option<Box<dyn std::any::Any + Send>>,
}
impl CleanupObservation {
    pub(crate) fn entry(&self) -> CleanupEntry {
        self.entry
    }
    pub(crate) fn future_disposal(&self) -> CleanupEntry {
        self.future_disposal
    }
    pub(crate) fn with_panic<R>(
        &self,
        inspect: impl FnOnce(&(dyn std::any::Any + Send)) -> R,
    ) -> Option<R> {
        self.panic.as_deref().map(inspect)
    }
    pub(crate) fn with_disposal_panic<R>(
        &self,
        inspect: impl FnOnce(&(dyn std::any::Any + Send)) -> R,
    ) -> Option<R> {
        self.disposal_panic.as_deref().map(inspect)
    }
    pub(crate) fn unsettled(&self) -> bool {
        matches!(self.entry, CleanupEntry::Entered | CleanupEntry::Panicked)
            || matches!(
                self.future_disposal,
                CleanupEntry::Entered | CleanupEntry::Panicked
            )
    }
}

/// Capture the original terminal before independently disposing the completed
/// or unwound future. Cancellation leaves Entered and the parent stays retained.
pub(crate) async fn observe_cleanup(
    observation: &mut CleanupObservation,
    returned_error: &mut Option<DrainFailure>,
    future: impl std::future::Future<Output = kasumi_types::drain::DrainResult>,
) {
    use std::{
        mem::ManuallyDrop,
        panic::{AssertUnwindSafe, catch_unwind},
        task::Poll,
    };
    let mut future = std::pin::pin!(ManuallyDrop::new(future));
    if observation.entry != CleanupEntry::NotEntered {
        return;
    }
    observation.entry = CleanupEntry::Entered;
    std::future::poll_fn(|cx| {
        // SAFETY: the future stays at this address until the one terminal
        // observation, then is explicitly destroyed without another poll.
        let polled = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: ManuallyDrop is transparent and the original future is
            // projected in place; neither the wrapper nor its body is moved.
            unsafe { future.as_mut().map_unchecked_mut(|future| &mut **future) }.poll(cx)
        }));
        match polled {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(original)) => {
                *returned_error = original.err();
                observation.entry = CleanupEntry::Returned;
                Poll::Ready(())
            }
            Err(original) => {
                observation.panic = Some(original);
                observation.entry = CleanupEntry::Panicked;
                Poll::Ready(())
            }
        }
    })
    .await;
    observation.future_disposal = CleanupEntry::Entered;
    let disposed = catch_unwind(AssertUnwindSafe(|| unsafe {
        // SAFETY: this is the sole destruction; ManuallyDrop prevents replay
        // after either a returned destructor or its observed original panic.
        ManuallyDrop::drop(future.as_mut().get_unchecked_mut());
    }));
    match disposed {
        Ok(()) => observation.future_disposal = CleanupEntry::Returned,
        Err(original) => {
            observation.disposal_panic = Some(original);
            observation.future_disposal = CleanupEntry::Panicked;
        }
    }
}
impl RecoverySeat {
    fn empty(&self) -> bool {
        self.node_start.is_none()
            && self.node_start_output.is_none()
            && !self.node_start_observation.unsettled()
            && self.failure.is_none()
            && self.database.is_none()
            && self.stores.is_none()
            && self.retired.is_none()
            && self.route_to_unregister.is_none()
            && !self.route_observation.unsettled()
            && !self.database_observation.unsettled()
            && !self.stores_observation.unsettled()
            && !self.retired_observation.unsettled()
    }
    fn native_free_failure(&self) -> bool {
        self.node_start.is_none()
            && self.node_start_output.is_none()
            && !self.node_start_observation.unsettled()
            && self.database.is_none()
            && self.stores.is_none()
            && self.retired.is_none()
            && self.route_to_unregister.is_none()
            && !self.route_observation.unsettled()
            && !self.database_observation.unsettled()
            && !self.stores_observation.unsettled()
            && !self.retired_observation.unsettled()
            && self.failure.as_ref().is_some_and(|failure| {
                matches!(
                    failure.original,
                    RecoveryOriginal::Snapshot(
                        kasumi_engine::SnapshotFailure::Operation(_)
                            | kasumi_engine::SnapshotFailure::AdmissionRefused(_)
                    )
                ) && failure.route_cleanup.is_none()
                    && failure.database_cleanup.is_none()
                    && failure.stores_cleanup.is_none()
                    && failure.retired_cleanup.is_none()
            })
    }
    fn stage(&self) -> &'static str {
        if self.node_start.is_some()
            || self.node_start_output.is_some()
            || self.node_start_observation.unsettled()
        {
            return "native_node_start";
        }
        self.failure
            .as_ref()
            .and_then(OriginalRecoveryFailure::source_stage)
            .map_or("unclassified", |stage| stage.class())
    }
}

/// Immutable sources supported by the actual node/fixture constructors. This
/// closed plan never invokes an arbitrary iterator callback before admission.
#[derive(Clone, Copy)]
pub struct OriginalRecoveryParticipants<'a>(ParticipantSource<'a>);
#[derive(Clone, Copy)]
enum ParticipantSource<'a> {
    Configured(&'a crate::runtime::RuntimeConfig),
    One(&'a str),
    Names(&'a [&'a str]),
    Enrollment {
        primary: &'a str,
        expected: &'a BTreeSet<String>,
    },
}
impl<'a> OriginalRecoveryParticipants<'a> {
    pub fn configured(config: &'a crate::runtime::RuntimeConfig) -> Self {
        Self(ParticipantSource::Configured(config))
    }
    pub fn one(name: &'a str) -> Self {
        Self(ParticipantSource::One(name))
    }
    pub fn names(names: &'a [&'a str]) -> Self {
        Self(ParticipantSource::Names(names))
    }
    pub fn enrollment(primary: &'a str, expected: &'a BTreeSet<String>) -> Self {
        Self(ParticipantSource::Enrollment { primary, expected })
    }
    fn len(self) -> Result<usize> {
        match self.0 {
            ParticipantSource::Configured(config) => OriginalRecoveries::participant_count(config),
            ParticipantSource::One(_) => Ok(1),
            ParticipantSource::Names(names) => Ok(names.len()),
            ParticipantSource::Enrollment { primary, expected } => expected
                .iter()
                .filter(|name| {
                    name.as_str() != crate::runtime::CONTROL_TENANT && name.as_str() != primary
                })
                .count()
                .checked_add(2)
                .context("enrollment participant count overflow"),
        }
    }
    fn name(self, index: usize) -> Option<&'a str> {
        match self.0 {
            ParticipantSource::Configured(config) => {
                if index == 0 {
                    Some(crate::runtime::CONTROL_TENANT)
                } else {
                    config
                        .tenants
                        .get(index - 1)
                        .map(|tenant| tenant.tenant.as_str())
                }
            }
            ParticipantSource::One(name) => (index == 0).then_some(name),
            ParticipantSource::Names(names) => names.get(index).copied(),
            ParticipantSource::Enrollment { primary, expected } => match index {
                0 => Some(crate::runtime::CONTROL_TENANT),
                1 => Some(primary),
                index => expected
                    .iter()
                    .map(String::as_str)
                    .filter(|name| *name != crate::runtime::CONTROL_TENANT && *name != primary)
                    .nth(index - 2),
            },
        }
    }
}

/// One actual topology participant owns a recovery seat. Independent RPC
/// seats use that exact installed policy's existing in-flight operation count.
struct RecoveryInventoryState {
    seats: Option<Box<[tokio::sync::Mutex<RecoverySeat>]>>,
    rpc: Option<Box<[RpcSeat]>>,
    participants: Option<Box<[String]>>,
    rpc_per_participant: usize,
    sealed: std::sync::atomic::AtomicBool,
    charge: Option<kasumi_types::SharedBudgetCharge>,
}
struct RpcSeat {
    claimed: std::sync::atomic::AtomicBool,
    // 0: no work, 1: body entered, 2: returned, 3: disposed, 4: work owned.
    phase: std::sync::atomic::AtomicU8,
    original: tokio::sync::Mutex<RpcOutcome>,
}
#[derive(Default)]
struct RpcOutcome {
    error: Option<kasumi_engine::SnapshotFailure>,
    output: Option<RpcOutput>,
    observation: CleanupObservation,
}
impl RpcOutcome {
    fn empty(&self) -> bool {
        self.error.is_none()
            && self.output.is_none()
            && self.observation.entry == CleanupEntry::NotEntered
            && self.observation.future_disposal == CleanupEntry::NotEntered
    }
}
/// Only actual administrative results enter this prepaid output lane. The
/// result's preexisting backing remains its producer's responsibility.
#[allow(
    clippy::large_enum_variant,
    reason = "the closed output lane is included in the same initial seat quote and preserves whole verified owners without a later Box"
)]
pub(crate) enum RpcOutput {
    Unit,
    Uuid(uuid::Uuid),
    Checkpoint(kasumi_engine::VerifiedBackupCheckpoint),
    Retirement(kasumi_engine::VerifiedRetirementReceipt),
    Encoded(Vec<u8>),
}
mod rpc_output_sealed {
    pub trait Sealed {}
    impl Sealed for () {}
    impl Sealed for uuid::Uuid {}
    impl Sealed for kasumi_engine::VerifiedBackupCheckpoint {}
    impl Sealed for kasumi_engine::VerifiedRetirementReceipt {}
    impl Sealed for Vec<u8> {}
}
pub(crate) trait RpcSnapshotOutput: rpc_output_sealed::Sealed {
    fn retain(self) -> RpcOutput;
    fn recover(original: RpcOutput) -> Self;
}
impl RpcSnapshotOutput for () {
    fn retain(self) -> RpcOutput {
        RpcOutput::Unit
    }
    fn recover(original: RpcOutput) -> Self {
        match original {
            RpcOutput::Unit => (),
            _ => unreachable!("same closed output producer"),
        }
    }
}
impl RpcSnapshotOutput for uuid::Uuid {
    fn retain(self) -> RpcOutput {
        RpcOutput::Uuid(self)
    }
    fn recover(original: RpcOutput) -> Self {
        match original {
            RpcOutput::Uuid(original) => original,
            _ => unreachable!("same closed output producer"),
        }
    }
}
impl RpcSnapshotOutput for kasumi_engine::VerifiedBackupCheckpoint {
    fn retain(self) -> RpcOutput {
        RpcOutput::Checkpoint(self)
    }
    fn recover(original: RpcOutput) -> Self {
        match original {
            RpcOutput::Checkpoint(original) => original,
            _ => unreachable!("same closed output producer"),
        }
    }
}
impl RpcSnapshotOutput for kasumi_engine::VerifiedRetirementReceipt {
    fn retain(self) -> RpcOutput {
        RpcOutput::Retirement(self)
    }
    fn recover(original: RpcOutput) -> Self {
        match original {
            RpcOutput::Retirement(original) => original,
            _ => unreachable!("same closed output producer"),
        }
    }
}
impl RpcSnapshotOutput for Vec<u8> {
    fn retain(self) -> RpcOutput {
        RpcOutput::Encoded(self)
    }
    fn recover(original: RpcOutput) -> Self {
        match original {
            RpcOutput::Encoded(original) => original,
            _ => unreachable!("same closed output producer"),
        }
    }
}
pub(crate) struct RpcConstructorReport<'a> {
    outcome: &'a RpcOutcome,
}
impl RpcConstructorReport<'_> {
    pub(crate) fn original(&self) -> Option<&kasumi_engine::SnapshotFailure> {
        self.outcome.error.as_ref()
    }
    #[cfg(test)]
    pub(crate) fn output(&self) -> Option<&RpcOutput> {
        self.outcome.output.as_ref()
    }
    pub(crate) fn observation(&self) -> &CleanupObservation {
        &self.outcome.observation
    }
}
/// Closed shared aliases retain the same original reservation. No raw or weak
/// aliases escape; the last control retires before arrays, names and credit.
pub struct OriginalRecoveries {
    inner: Option<Arc<RecoveryInventoryState>>,
}
impl OriginalRecoveries {
    fn state(&self) -> &RecoveryInventoryState {
        self.inner
            .as_deref()
            .expect("live original recovery inventory")
    }
    pub(crate) fn participant_count(config: &crate::runtime::RuntimeConfig) -> Result<usize> {
        config
            .tenants
            .len()
            .checked_add(1)
            .context("original recovery participant count overflow")
    }
    pub(crate) fn configured_index(
        config: &crate::runtime::RuntimeConfig,
        participant: &str,
    ) -> Result<usize> {
        if participant == crate::runtime::CONTROL_TENANT {
            return Ok(0);
        }
        config
            .tenants
            .iter()
            .position(|configured| configured.tenant == participant)
            .and_then(|index| index.checked_add(1))
            .context("participant lacks installed recovery seat")
    }
    /// Quote concrete backing without calling constructors or allocating names.
    pub fn required_bytes(
        policy: &kasumi_engine::admission::AdmissionConfig,
        participants: OriginalRecoveryParticipants<'_>,
    ) -> Result<u64> {
        fn allocation(layout: std::alloc::Layout) -> Result<u64> {
            u64::try_from(layout.size())?
                .checked_add(if layout.size() == 0 { 0 } else { 64 })
                .context("original inventory allocation quote overflow")
        }
        let count = participants.len()?;
        let rpc = count
            .checked_mul(policy.max_inflight_operations)
            .context("original RPC seat count overflow")?;
        let (control, _) = std::alloc::Layout::new::<[usize; 2]>()
            .extend(std::alloc::Layout::new::<RecoveryInventoryState>())?;
        let mut bytes = allocation(control.pad_to_align())?
            .checked_add(kasumi_types::SharedBudgetCharge::required_bytes::<
                kasumi_engine::admission::Reservation,
            >()?)
            .context("original shared charge quote overflow")?
            .checked_add(allocation(std::alloc::Layout::array::<
                tokio::sync::Mutex<RecoverySeat>,
            >(count)?)?)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>() as u64))
            .context("original recovery quote overflow")?;
        for extra in [
            allocation(std::alloc::Layout::array::<RpcSeat>(rpc)?)?,
            allocation(std::alloc::Layout::array::<String>(count)?)?,
            crate::runtime::RetiredSourceFailure::required_bytes()?
                .checked_mul(u64::try_from(count)?)
                .context("original preparation quote overflow")?,
        ] {
            bytes = bytes
                .checked_add(extra)
                .context("original inventory quote overflow")?;
        }
        for index in 0..count {
            let name = participants
                .name(index)
                .expect("closed immutable participant source");
            bytes = bytes
                .checked_add(allocation(std::alloc::Layout::array::<u8>(name.len())?)?)
                .context("original participant name quote overflow")?;
        }
        Ok(bytes)
    }
    pub(crate) fn startup_backing(
        policy: &kasumi_engine::admission::AdmissionConfig,
        participants: OriginalRecoveryParticipants<'_>,
    ) -> Result<kasumi_engine::admission::startup::StartupBacking> {
        use kasumi_engine::admission::startup::StartupBacking;
        let count = participants.len()?;
        let rpc = count
            .checked_mul(policy.max_inflight_operations)
            .context("original RPC seat count overflow")?;
        let mut backing = StartupBacking::empty()
            .shared::<RecoveryInventoryState>()?
            .array::<tokio::sync::Mutex<RecoverySeat>>(count)?
            .array::<RpcSeat>(rpc)?
            .array::<String>(count)?;
        for index in 0..count {
            backing = backing
                .string(
                    participants
                        .name(index)
                        .expect("same closed immutable participant source"),
                )?
                .include(crate::runtime::RetiredSourceFailure::startup_backing()?)?;
        }
        Ok(backing)
    }
    /// The original installed policy supplies the concurrency bound. All name,
    /// array and shared-control allocations follow this same successful grant.
    pub fn new(
        admission: &Arc<kasumi_engine::admission::NodeAdmission>,
        participants: OriginalRecoveryParticipants<'_>,
    ) -> Result<Self> {
        let policy = admission.policy();
        let charge = kasumi_types::SharedBudgetCharge::new(
            admission
                .memory()
                .reserve_resident(Self::required_bytes(policy, participants)?)?,
        );
        Self::allocate(policy, participants, charge)
    }
    /// Authority enrollment has one joint initial quote: this original
    /// inventory, its typed terminal/handoff and all inert resource backing.
    pub(crate) fn prepare_authority_enrollment(
        admission: &Arc<kasumi_engine::admission::NodeAdmission>,
        participants: OriginalRecoveryParticipants<'_>,
        database_id: uuid::Uuid,
    ) -> Result<
        kasumi_engine::admission::startup::PrepaidStartup<
            crate::authority_enrollment_terminal::EnrollmentTerminal,
        >,
    > {
        let prepared = admission
            .memory()
            .prepare_prepaid_startup::<crate::authority_enrollment_terminal::EnrollmentTerminal>(
        )?;
        prepared.install(crate::authority_enrollment_terminal::EnrollmentPlan {
            policy: admission.policy(),
            participants,
            database_id,
        })
    }
    pub(crate) fn allocate(
        policy: &kasumi_engine::admission::AdmissionConfig,
        participants: OriginalRecoveryParticipants<'_>,
        charge: kasumi_types::SharedBudgetCharge,
    ) -> Result<Self> {
        let count = participants.len()?;
        let rpc_count = count
            .checked_mul(policy.max_inflight_operations)
            .context("original RPC seat count overflow")?;
        let mut seats = Box::<[tokio::sync::Mutex<RecoverySeat>]>::new_uninit_slice(count);
        for seat in &mut seats {
            seat.write(tokio::sync::Mutex::new(RecoverySeat::default()));
        }
        let mut rpc = Box::<[RpcSeat]>::new_uninit_slice(rpc_count);
        for seat in &mut rpc {
            seat.write(RpcSeat {
                claimed: std::sync::atomic::AtomicBool::new(false),
                phase: std::sync::atomic::AtomicU8::new(0),
                original: tokio::sync::Mutex::new(RpcOutcome::default()),
            });
        }
        let mut names = Box::<[String]>::new_uninit_slice(count);
        for (index, name) in names.iter_mut().enumerate() {
            name.write(
                participants
                    .name(index)
                    .expect("same closed immutable participant source")
                    .to_owned(),
            );
        }
        // SAFETY: each exact array was fully initialized before publication.
        let (seats, rpc, names) =
            unsafe { (seats.assume_init(), rpc.assume_init(), names.assume_init()) };
        Ok(Self {
            inner: Some(Arc::new(RecoveryInventoryState {
                seats: Some(seats),
                rpc: Some(rpc),
                participants: Some(names),
                rpc_per_participant: policy.max_inflight_operations,
                sealed: std::sync::atomic::AtomicBool::new(false),
                charge: Some(charge),
            })),
        })
    }
    async fn seat(&self, index: usize) -> tokio::sync::MutexGuard<'_, RecoverySeat> {
        self.state()
            .seats
            .as_ref()
            .expect("live original recovery seats")[index]
            .lock()
            .await
    }
    pub(crate) async fn claim(&self, index: usize) -> OriginalRecoveryGuard<'_> {
        let sealed = &self.state().sealed;
        let sealed_at_claim = sealed.load(std::sync::atomic::Ordering::SeqCst);
        OriginalRecoveryGuard {
            seat: self.seat(index).await,
            index,
            sealed,
            sealed_at_claim,
        }
    }
    /// Claim one independent empty RPC seat before polling its constructor.
    /// Busy and Sealed are inline scalars, with no allocation after refusal.
    pub(crate) async fn rpc_claim(
        &self,
        participant: &str,
    ) -> std::result::Result<RpcConstructorGuard<'_>, kasumi_store::ScratchAdmissionRefusal> {
        use std::sync::atomic::Ordering;
        let state = self.state();
        if state.sealed.load(Ordering::SeqCst) {
            return Err(kasumi_store::ScratchAdmissionRefusal::Sealed);
        }
        let Some(participant) = state
            .participants
            .as_ref()
            .expect("live original participants")
            .iter()
            .position(|name| name == participant)
        else {
            return Err(kasumi_store::ScratchAdmissionRefusal::Busy);
        };
        let start = participant * state.rpc_per_participant;
        for (relative, seat) in state.rpc.as_ref().expect("live original RPC seats")
            [start..start + state.rpc_per_participant]
            .iter()
            .enumerate()
        {
            if seat
                .claimed
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                if state.sealed.load(Ordering::SeqCst) {
                    seat.claimed.store(false, Ordering::SeqCst);
                    return Err(kasumi_store::ScratchAdmissionRefusal::Sealed);
                }
                #[cfg(test)]
                inventory_tests::after_rpc_claim(state as *const _ as usize);
                let Ok(original) = seat.original.try_lock() else {
                    seat.claimed.store(false, Ordering::SeqCst);
                    continue;
                };
                if !original.empty() {
                    drop(original);
                    continue;
                }
                if state.sealed.load(Ordering::SeqCst) {
                    seat.claimed.store(false, Ordering::SeqCst);
                    return Err(kasumi_store::ScratchAdmissionRefusal::Sealed);
                }
                return Ok(RpcConstructorGuard {
                    original,
                    claimed: &seat.claimed,
                    phase: &seat.phase,
                    index: start + relative,
                });
            }
        }
        Err(kasumi_store::ScratchAdmissionRefusal::Busy)
    }
    pub(crate) fn seal(&self) {
        self.state()
            .sealed
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    pub(crate) async fn retained(&self) -> bool {
        for seat in self
            .state()
            .seats
            .as_ref()
            .expect("live original recoveries")
        {
            if !seat.lock().await.empty() {
                return true;
            }
        }
        for seat in self.state().rpc.as_ref().expect("live original RPC") {
            // Together with the seal/CAS/recheck sequence, this observes the
            // reservation window before a constructor guard owns the mutex.
            if seat.claimed.load(std::sync::atomic::Ordering::SeqCst) {
                return true;
            }
            if !seat.original.lock().await.empty() {
                return true;
            }
        }
        false
    }
    /// Borrow the exact original native startup carrier from its initial paid
    /// seat. The callback has no owning extraction capability.
    pub async fn with_node_start_failure<R>(
        &self,
        index: usize,
        inspect: impl FnOnce(&kasumi_store::NodeStoreStartFailure) -> R,
    ) -> Option<R> {
        let seat = self.seat(index).await;
        seat.node_start.as_ref().map(inspect)
    }
    /// Borrow the successful owner retained when callback disposal did not
    /// return. This lends the body without an owning Arc extraction.
    pub async fn with_node_start_output<R>(
        &self,
        index: usize,
        inspect: impl FnOnce(&kasumi_store::NodeStore) -> R,
    ) -> Option<R> {
        let seat = self.seat(index).await;
        seat.node_start_output.as_ref().map(inspect)
    }
    /// Each independent unwind stays in this same fixed paid seat.
    pub async fn with_node_start_panic<R>(
        &self,
        index: usize,
        inspect: impl FnOnce(&(dyn std::any::Any + Send)) -> R,
    ) -> Option<R> {
        let seat = self.seat(index).await;
        seat.node_start_observation.with_panic(inspect)
    }
    pub async fn with_node_start_disposal_panic<R>(
        &self,
        index: usize,
        inspect: impl FnOnce(&(dyn std::any::Any + Send)) -> R,
    ) -> Option<R> {
        let seat = self.seat(index).await;
        seat.node_start_observation.with_disposal_panic(inspect)
    }
    pub(crate) async fn with_failure<R>(
        &self,
        index: usize,
        inspect: impl FnOnce(&OriginalRecoveryFailure) -> R,
    ) -> Option<R> {
        let seat = self.seat(index).await;
        seat.failure.as_ref().map(inspect)
    }
    #[cfg(test)]
    pub(crate) fn with_rpc_report<R>(
        &self,
        index: usize,
        inspect: impl FnOnce(RpcConstructorReport<'_>) -> R,
    ) -> Option<R> {
        let outcome = self
            .state()
            .rpc
            .as_ref()?
            .get(index)?
            .original
            .try_lock()
            .ok()?;
        Some(inspect(RpcConstructorReport { outcome: &outcome }))
    }
    #[cfg(test)]
    pub(crate) fn with_rpc_original<R>(
        &self,
        index: usize,
        inspect: impl FnOnce(&kasumi_engine::SnapshotFailure) -> R,
    ) -> Option<R> {
        self.with_rpc_report(index, |report| report.original().map(inspect))
            .flatten()
    }
}
impl Clone for OriginalRecoveries {
    fn clone(&self) -> Self {
        Self {
            inner: Some(
                self.inner
                    .as_ref()
                    .expect("live original inventory")
                    .clone(),
            ),
        }
    }
}
impl Drop for OriginalRecoveries {
    fn drop(&mut self) {
        drop(Arc::into_inner(
            self.inner.take().expect("live original inventory"),
        ));
    }
}
impl Drop for RecoveryInventoryState {
    fn drop(&mut self) {
        let mut seats = self.seats.take().expect("live original recovery array");
        let mut rpc = self.rpc.take().expect("live original RPC array");
        let names = self
            .participants
            .take()
            .expect("live original participant array");
        if seats.iter_mut().any(|seat| !seat.get_mut().empty())
            || rpc.iter_mut().any(|seat| {
                seat.claimed.load(std::sync::atomic::Ordering::SeqCst)
                    || seat.phase.load(std::sync::atomic::Ordering::SeqCst) != 0
                    || !seat.original.get_mut().empty()
            })
        {
            std::mem::forget(seats);
            std::mem::forget(rpc);
            std::mem::forget(names);
            std::mem::forget(self.charge.take().expect("same original inventory credit"));
        } else {
            #[cfg(test)]
            let address = seats.as_ptr() as usize;
            drop(seats);
            drop(rpc);
            drop(names);
            #[cfg(test)]
            inventory_tests::before_refund(address);
            drop(self.charge.take().expect("same original inventory credit"));
        }
    }
}
/// A Snapshot-only RPC loan cannot invoke Server retired-source preparation.
pub(crate) struct RpcConstructorGuard<'a> {
    original: tokio::sync::MutexGuard<'a, RpcOutcome>,
    claimed: &'a std::sync::atomic::AtomicBool,
    phase: &'a std::sync::atomic::AtomicU8,
    index: usize,
}
impl<'a> RpcConstructorGuard<'a> {
    /// Synchronous ownership transfer precedes the first possible yield. This
    /// one accepted loan cannot accept a second producer on a retained failure.
    pub(crate) fn run_snapshot<T: RpcSnapshotOutput, F>(self, work: F) -> RpcRun<'a, F, T>
    where
        F: std::future::Future<Output = std::result::Result<T, kasumi_engine::SnapshotFailure>>,
    {
        self.phase.store(4, std::sync::atomic::Ordering::SeqCst);
        RpcRun {
            guard: Some(self),
            work: std::mem::ManuallyDrop::new(work),
            started: false,
            disposed: false,
            output: std::marker::PhantomData,
        }
    }
}
/// Inline producer ownership is not a new allocation/grant or a claim that
/// arbitrary producer future/backing allocations are funded by this inventory.
pub(crate) struct RpcRun<'a, F, T> {
    guard: Option<RpcConstructorGuard<'a>>,
    work: std::mem::ManuallyDrop<F>,
    started: bool,
    disposed: bool,
    output: std::marker::PhantomData<fn() -> T>,
}
impl<F, T> RpcRun<'_, F, T> {
    fn dispose_work(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        let guard = self.guard.as_mut().expect("actual producer loan");
        guard.original.observation.future_disposal = CleanupEntry::Entered;
        let disposed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            // SAFETY: this exact future remains in its RpcRun slot, including
            // during Drop before its first poll. This is its only destruction.
            std::mem::ManuallyDrop::drop(&mut self.work);
        }));
        match disposed {
            Ok(()) => guard.original.observation.future_disposal = CleanupEntry::Returned,
            Err(original) => {
                guard.original.observation.disposal_panic = Some(original);
                guard.original.observation.future_disposal = CleanupEntry::Panicked;
            }
        }
    }
}
impl<'a, F, T> std::future::Future for RpcRun<'a, F, T>
where
    T: RpcSnapshotOutput,
    F: std::future::Future<Output = std::result::Result<T, kasumi_engine::SnapshotFailure>>,
{
    type Output = std::result::Result<T, RpcConstructorFailure<'a>>;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::{
            panic::{AssertUnwindSafe, catch_unwind},
            sync::atomic::Ordering,
            task::Poll,
        };
        // SAFETY: only pinned in-place projection/destruction touches work;
        // no F or owner is moved out while the future may still be polled.
        let this = unsafe { self.get_unchecked_mut() };
        let guard = this.guard.as_mut().expect("one actual producer terminal");
        if !this.started {
            this.started = true;
            guard.original.observation.entry = CleanupEntry::Entered;
            guard.phase.store(1, Ordering::SeqCst);
        }
        let polled = catch_unwind(AssertUnwindSafe(|| {
            unsafe { std::pin::Pin::new_unchecked(&mut *this.work) }.poll(cx)
        }));
        match polled {
            Ok(Poll::Pending) => return Poll::Pending,
            Ok(Poll::Ready(returned)) => {
                match returned {
                    Ok(original) => guard.original.output = Some(original.retain()),
                    Err(original) => guard.original.error = Some(original),
                }
                guard.original.observation.entry = CleanupEntry::Returned;
                guard.phase.store(2, Ordering::SeqCst);
            }
            Err(original) => {
                guard.original.observation.panic = Some(original);
                guard.original.observation.entry = CleanupEntry::Panicked;
            }
        }
        // The original terminal is in its exact lane before the independent
        // disposal catch. There is no suspension or fallible handoff here.
        this.dispose_work();
        let mut guard = this.guard.take().expect("same original loan");
        if guard.original.observation.entry == CleanupEntry::Returned
            && guard.original.observation.future_disposal == CleanupEntry::Returned
        {
            guard.phase.store(3, Ordering::SeqCst);
            if let Some(original) = guard.original.output.take() {
                return Poll::Ready(Ok(T::recover(original)));
            }
        }
        Poll::Ready(Err(RpcConstructorFailure { guard }))
    }
}
impl<F, T> Drop for RpcRun<'_, F, T> {
    fn drop(&mut self) {
        self.dispose_work();
    }
}
/// The same loan returns as a closed observation owner. It cannot be invoked
/// again, normalized into Anyhow, or used to extract any retained original.
pub(crate) struct RpcConstructorFailure<'a> {
    guard: RpcConstructorGuard<'a>,
}
impl RpcConstructorFailure<'_> {
    #[cfg(test)]
    pub(crate) fn with_original<R>(
        &self,
        inspect: impl FnOnce(&kasumi_engine::SnapshotFailure) -> R,
    ) -> Option<R> {
        self.guard.original.error.as_ref().map(inspect)
    }
    pub(crate) fn with_report<R>(&self, inspect: impl FnOnce(RpcConstructorReport<'_>) -> R) -> R {
        inspect(RpcConstructorReport {
            outcome: &self.guard.original,
        })
    }
    pub(crate) fn foreign_error(self) -> anyhow::Error {
        OriginalRecoveryObservation {
            index: self.guard.index,
            stage: "rpc_constructor",
        }
        .foreign_error()
    }
}

impl Drop for RpcConstructorGuard<'_> {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        let phase = self.phase.load(Ordering::SeqCst);
        if matches!(phase, 1 | 2 | 4) {
            return;
        }
        if phase == 3 {
            if matches!(
                self.original.error.as_ref(),
                Some(
                    kasumi_engine::SnapshotFailure::Operation(_)
                        | kasumi_engine::SnapshotFailure::AdmissionRefused(_)
                )
            ) {
                drop(self.original.error.take());
            }
            if self.original.error.is_none() && self.original.output.is_none() {
                self.original.observation = CleanupObservation::default();
            }
        }
        if self.original.empty() {
            self.phase.store(0, Ordering::SeqCst);
            self.claimed.store(false, Ordering::SeqCst);
        }
    }
}

pub struct OriginalRecoveryObservation {
    pub(crate) index: usize,
    pub(crate) stage: &'static str,
}

impl OriginalRecoveryObservation {
    /// Only a resource-free foreign marker leaves the already installed seat.
    pub(crate) fn foreign_error(self) -> anyhow::Error {
        kasumi_types::Error::new(
            kasumi_types::ErrorCode::Unavailable,
            "original constructor failure remains in admitted custody",
        )
        .into()
    }
}

/// A claimed actual configured-tenant seat. The guard is held before effects
/// and the original is installed synchronously before cleanup is polled.
pub(crate) struct OriginalRecoveryGuard<'a> {
    seat: tokio::sync::MutexGuard<'a, RecoverySeat>,
    index: usize,
    sealed: &'a std::sync::atomic::AtomicBool,
    sealed_at_claim: bool,
}
impl<'inventory> OriginalRecoveryGuard<'inventory> {
    pub(crate) fn is_empty(&self) -> bool {
        self.seat.empty()
    }
    pub(crate) fn observation(&self) -> OriginalRecoveryObservation {
        OriginalRecoveryObservation {
            index: self.index,
            stage: self.seat.stage(),
        }
    }
    /// Check refusal before callers construct an owning callback. The
    /// nonclone loan owns this one accepted admission; abandoning it leaves
    /// Entered in the same paid seat and never mints native disposal proof.
    pub(crate) fn begin_node(
        &mut self,
    ) -> std::result::Result<NodeConstructorLoan<'_, 'inventory>, OriginalRecoveryObservation> {
        if self.sealed_at_claim || self.sealed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(OriginalRecoveryObservation {
                index: self.index,
                stage: "native_node_start_sealed",
            });
        }
        if !self.seat.empty() {
            return Err(self.observation());
        }
        self.seat.node_start_observation.entry = CleanupEntry::Entered;
        Ok(NodeConstructorLoan { guard: self })
    }
    #[cfg(test)]
    pub(crate) fn capture_snapshot(
        &mut self,
        original: kasumi_engine::SnapshotFailure,
    ) -> std::result::Result<OriginalRecoveryObservation, kasumi_engine::SnapshotFailure> {
        if !self.seat.empty() {
            return Err(original);
        }
        self.seat.failure = Some(original.into());
        Ok(self.observation())
    }
    pub(crate) async fn close_pending(&mut self) {
        if let Some(failure) = self.seat.failure.as_mut()
            && let RecoveryOriginal::Retired(original) = &mut failure.original
        {
            original.close_pending().await;
        }
    }
    /// The exclusive guard is checked before polling, so a returned original
    /// is installed without an intervening await or fallible handoff.
    pub(crate) async fn run_retired<T>(
        &mut self,
        work: impl std::future::Future<
            Output = std::result::Result<T, crate::runtime::RetiredSourceFailure>,
        >,
    ) -> std::result::Result<T, OriginalRecoveryObservation> {
        if !self.seat.empty() {
            return Err(self.observation());
        }
        match work.await {
            Ok(value) => Ok(value),
            Err(original) => {
                self.seat.failure = Some(original.into());
                self.close_pending().await;
                Err(self.observation())
            }
        }
    }
    pub(crate) async fn run_snapshot<T>(
        &mut self,
        work: impl std::future::Future<Output = std::result::Result<T, kasumi_engine::SnapshotFailure>>,
    ) -> std::result::Result<T, OriginalRecoveryObservation> {
        if !self.seat.empty() {
            return Err(self.observation());
        }
        match work.await {
            Ok(value) => Ok(value),
            Err(original) => {
                self.seat.failure = Some(original.into());
                Err(self.observation())
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn with_failure<R>(
        &self,
        inspect: impl FnOnce(&OriginalRecoveryFailure) -> R,
    ) -> Option<R> {
        self.seat.failure.as_ref().map(inspect)
    }
}

/// Synchronous inputs and the original result remain under the same accepted
/// seat. There is no callback allocation or generic output erasure here.
pub(crate) struct NodeConstructorLoan<'guard, 'inventory> {
    guard: &'guard mut OriginalRecoveryGuard<'inventory>,
}
impl NodeConstructorLoan<'_, '_> {
    #[allow(
        clippy::result_large_err,
        reason = "the callback returns whole native startup custody into its existing prepaid lane before any diagnostic projection; an error-path Box would lose that boundary"
    )]
    pub(crate) fn run_node<F>(
        self,
        work: F,
    ) -> std::result::Result<kasumi_store::NodeStore, OriginalRecoveryObservation>
    where
        F: FnMut() -> std::result::Result<
            kasumi_store::NodeStore,
            kasumi_store::NodeStoreStartFailure,
        >,
    {
        let mut work = std::mem::ManuallyDrop::new(work);
        self.guard.seat.node_start_observation.entry = CleanupEntry::Entered;
        let returned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (*work)()));
        match returned {
            Ok(Ok(value)) => self.guard.seat.node_start_output = Some(value),
            Ok(Err(original)) => self.guard.seat.node_start = Some(original),
            Err(original) => {
                self.guard.seat.node_start_observation.panic = Some(original);
                self.guard.seat.node_start_observation.entry = CleanupEntry::Panicked;
            }
        }
        if self.guard.seat.node_start_observation.entry == CleanupEntry::Entered {
            self.guard.seat.node_start_observation.entry = CleanupEntry::Returned;
        }
        self.guard.seat.node_start_observation.future_disposal = CleanupEntry::Entered;
        let disposed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // SAFETY: the original callback was invoked only by borrow. This is
            // its sole destruction after the returned result entered the lane.
            unsafe { std::mem::ManuallyDrop::drop(&mut work) };
        }));
        match disposed {
            Ok(()) => {
                self.guard.seat.node_start_observation.future_disposal = CleanupEntry::Returned
            }
            Err(original) => {
                self.guard.seat.node_start_observation.disposal_panic = Some(original);
                self.guard.seat.node_start_observation.future_disposal = CleanupEntry::Panicked;
            }
        }
        if self.guard.seat.node_start_observation.entry == CleanupEntry::Returned
            && self.guard.seat.node_start_observation.future_disposal == CleanupEntry::Returned
            && let Some(value) = self.guard.seat.node_start_output.take()
        {
            // The same successful registered NodeStore travels with value.
            // Retiring the empty diagnostic lane is no native teardown proof.
            self.guard.seat.node_start_observation = CleanupObservation::default();
            return Ok(value);
        }
        Err(self.guard.observation())
    }
}

/// A closed original generation awaiting fresh admission. Its failed owner has
/// drained and left `generations`; this record keeps the retry authorized
/// without retaining that owner, and carries only fixed diagnostic classes.
#[derive(Clone, Debug)]
pub(crate) struct PendingAdmission {
    pub(crate) closure_cause: &'static str,
    pub(crate) key_lease_class: Option<&'static str>,
    pub(crate) drained_with_issues: BTreeSet<&'static str>,
    pub(crate) failed_attempts: u64,
}

/// Owners whose complete drain already recorded their issues. Entries are Weak
/// and pruned when their last handle drops, so this never extends a lifetime.
#[derive(Default)]
pub(crate) struct Superseded {
    databases: std::sync::Mutex<Vec<std::sync::Weak<Database>>>,
    leases: std::sync::Mutex<Vec<std::sync::Weak<crate::serving_runtime::RuntimeLease>>>,
}
fn retain_weak<T>(entries: &std::sync::Mutex<Vec<std::sync::Weak<T>>>, owner: &Arc<T>) {
    let mut entries = entries.lock().unwrap_or_else(|p| p.into_inner());
    entries.retain(|entry| entry.strong_count() > 0);
    if !entries
        .iter()
        .any(|entry| std::ptr::eq(entry.as_ptr(), Arc::as_ptr(owner)))
    {
        entries.push(Arc::downgrade(owner));
    }
}
fn contains_weak<T>(entries: &std::sync::Mutex<Vec<std::sync::Weak<T>>>, owner: &Arc<T>) -> bool {
    entries
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .any(|entry| std::ptr::eq(entry.as_ptr(), Arc::as_ptr(owner)))
}

/// Component names are fixed `&'static str` inventory labels, never errors.
fn component_names(failure: &DrainFailure) -> BTreeSet<&'static str> {
    failure
        .issues()
        .iter()
        .map(|issue| issue.component())
        .collect()
}

fn joined(names: &BTreeSet<&'static str>) -> String {
    names.iter().copied().collect::<Vec<_>>().join(",")
}

impl Administration {
    /// True only for this exact original database handle after its complete
    /// drain was observed and reported by fresh admission.
    pub(crate) fn superseded_database(&self, database: &Arc<Database>) -> bool {
        contains_weak(&self.superseded.databases, database)
    }

    pub(crate) fn superseded_lease(
        &self,
        lease: &Arc<crate::serving_runtime::RuntimeLease>,
    ) -> bool {
        contains_weak(&self.superseded.leases, lease)
    }

    #[cfg(test)]
    pub(crate) fn pending_admission(
        &self,
        tenant: &str,
        incarnation: &str,
    ) -> Option<PendingAdmission> {
        self.pending_admission
            .read()
            .ok()?
            .get(&(tenant.to_owned(), incarnation.to_owned()))
            .cloned()
    }

    /// One failed attempt of an already recorded closure. Returns its cause.
    pub(crate) fn record_failed_admission(&self, tenant: &str, incarnation: &str) -> &'static str {
        let Ok(mut pending) = self.pending_admission.write() else {
            return "unobservable";
        };
        match pending.get_mut(&(tenant.to_owned(), incarnation.to_owned())) {
            Some(record) => {
                record.failed_attempts = record.failed_attempts.saturating_add(1);
                record.closure_cause
            }
            None => "unobservable",
        }
    }

    pub(super) async fn recover_original(
        &self,
        tenant: &str,
        incarnation: &str,
    ) -> std::result::Result<(), OriginalRecoveryObservation> {
        let Some(index) = self
            .config
            .tenants
            .iter()
            .position(|entry| entry.tenant == tenant)
        else {
            return Ok(());
        };
        let index = index + 1;
        let mut seat = self.original_recoveries.seat(index).await;
        if !seat.empty() {
            return Err(OriginalRecoveryObservation {
                index,
                stage: seat.stage(),
            });
        }
        let body = self
            .recover_original_body(tenant, incarnation, &mut seat)
            .await;
        match body {
            Ok(()) => {
                // The generation/custody registry now owns these same aliases.
                // Releasing the temporary borrows proves no native disposal.
                seat.database.take();
                seat.stores.take();
                seat.retired.take();
                seat.route_to_unregister.take();
                Ok(())
            }
            Err(original) => {
                let seat = &mut *seat;
                // The original is installed before every cleanup await.
                seat.failure = Some(original);
                if let RecoveryOriginal::Retired(original) =
                    &mut seat.failure.as_mut().expect("installed original").original
                {
                    original.close_pending().await;
                }
                if let Some(group) = seat.route_to_unregister.as_ref()
                    && let Some(network) = &self.cluster
                {
                    seat.route_observation.entry = CleanupEntry::Entered;
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        network.unregister_group(group)
                    }));
                    match outcome {
                        Ok(original) => {
                            seat.failure
                                .as_mut()
                                .expect("installed original")
                                .route_cleanup = original.err();
                            seat.route_observation.entry = CleanupEntry::Returned;
                        }
                        Err(original) => {
                            seat.route_observation.panic = Some(original);
                            seat.route_observation.entry = CleanupEntry::Panicked;
                        }
                    }
                }
                if let Some(database) = seat.database.as_ref() {
                    observe_cleanup(
                        &mut seat.database_observation,
                        &mut seat
                            .failure
                            .as_mut()
                            .expect("installed original")
                            .database_cleanup,
                        database.shutdown(),
                    )
                    .await;
                }
                if let Some(stores) = seat.stores.as_ref() {
                    observe_cleanup(
                        &mut seat.stores_observation,
                        &mut seat
                            .failure
                            .as_mut()
                            .expect("installed original")
                            .stores_cleanup,
                        stores.shutdown(),
                    )
                    .await;
                }
                if let Some(retired) = seat.retired.as_ref() {
                    observe_cleanup(
                        &mut seat.retired_observation,
                        &mut seat
                            .failure
                            .as_mut()
                            .expect("installed original")
                            .retired_cleanup,
                        retired.shutdown(),
                    )
                    .await;
                }
                let stage = seat.stage();
                if seat.native_free_failure() {
                    // This retires only a statically native-free diagnostic.
                    drop(seat.failure.take());
                }
                Err(OriginalRecoveryObservation { index, stage })
            }
        }
    }

    async fn recover_original_body(
        &self,
        tenant: &str,
        incarnation: &str,
        seat: &mut RecoverySeat,
    ) -> Result<(), OriginalRecoveryFailure> {
        macro_rules! ensure {
            ($condition:expr, $($message:tt)+) => {
                if !$condition {
                    return Err(anyhow::anyhow!($($message)+).into());
                }
            };
        }
        let Some(configured) = self
            .config
            .tenants
            .iter()
            .find(|entry| entry.tenant == tenant)
        else {
            return Ok(());
        };
        if self.config.mode == crate::runtime::DeploymentMode::Replicated {
            let enrolled = crate::node_enrollment::tenant_record(self.audit.store(), tenant)
                .context(RecoverStage::EnrollmentMismatch)?
                .context("routed original tenant has no enrollment")
                .context(RecoverStage::EnrollmentMismatch)?;
            ensure!(
                enrolled.stage == crate::node_enrollment::Stage::Prepared
                    && enrolled.incarnation
                        == Uuid::parse_str(incarnation)
                            .context(RecoverStage::EnrollmentMismatch)?,
                RecoverStage::EnrollmentMismatch
            );
        }
        let context = RequestContext {
            tenant: tenant.to_owned(),
            ..self.control_context.clone()
        };
        if matches!(
            self.registry.retirement_source(&context, incarnation),
            Ok(kasumi_engine::InstalledRetirementSource::RetiredCustody(_))
        ) {
            return Ok(());
        }
        let key = (tenant.to_owned(), incarnation.to_owned());
        let previous = self.generation(tenant, incarnation).ok();
        let pending = self
            .pending_admission
            .read()
            .map_err(|_| anyhow::anyhow!("pending admission registry unavailable"))?
            .contains_key(&key);
        if configured
            .incarnation
            .as_deref()
            .is_some_and(|installed| installed != incarnation)
            || (configured.incarnation.is_none() && previous.is_none() && !pending)
        {
            return Ok(());
        }
        if self
            .custody_generations
            .read()
            .map_err(|_| anyhow::anyhow!("custody registry unavailable"))?
            .contains_key(&key)
        {
            return Ok(());
        }
        if let Some(previous) = &previous {
            if previous.database.check_serving().is_ok() {
                return self
                    .initialize_original_if_ready(tenant, previous)
                    .await
                    .context(RecoverStage::Initialize)
                    .map_err(Into::into);
            }
            self.observe_closure(tenant, incarnation, previous)?;
            if let Some(lease) = &previous.lease {
                match lease.shutdown().await {
                    Ok(()) => {}
                    Err(failure) if failure.completion() == DrainCompletion::Complete => {
                        self.record_drain_issues(tenant, incarnation, &failure);
                        retain_weak(&self.superseded.leases, lease);
                    }
                    Err(failure) => {
                        return Err(anyhow::Error::new(failure))
                            .context(RecoverStage::PreviousLeaseRetained)
                            .map_err(Into::into);
                    }
                }
            }
            self.registry
                .detach_target_generation(tenant, incarnation, &previous.database)
                .context(RecoverStage::PreviousDetach)?;
            if let Some(network) = &self.cluster {
                network
                    .unregister_group(&format!("{tenant}/{incarnation}"))
                    .context(RecoverStage::PreviousDetach)?;
            }
            // Completion drains proposals, queries, Raft storage and key probes.
            // Retained caller handles still refer to this permanently closed instance.
            // A complete drain that recorded issues is still complete: those
            // issues are the closure's evidence, retained sticky by that owner,
            // not a reason to refuse fresh admission forever. Only an owner whose
            // completion is not established keeps this tenant closed.
            match previous.database.shutdown().await {
                Ok(()) => {}
                Err(failure) if failure.completion() == DrainCompletion::Complete => {
                    self.record_drain_issues(tenant, incarnation, &failure);
                    retain_weak(&self.superseded.databases, &previous.database);
                }
                Err(failure) => {
                    return Err(anyhow::Error::new(failure))
                        .context(RecoverStage::PreviousShutdownRetained)
                        .map_err(Into::into);
                }
            }
            // Every owner of this exact failed instance has drained. Remove it
            // so neither retries nor daemon shutdown drain it again; the pending
            // record keeps fresh admission of this incarnation authorized.
            let mut generations = self
                .generations
                .write()
                .map_err(|_| anyhow::anyhow!("generation registry unavailable"))?;
            if generations
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(&current.database, &previous.database))
            {
                generations.remove(&key);
            }
        }
        let custody_provider = configured
            .custody_keys
            .provider(self.credential.clone())
            .context(RecoverStage::KeyProvider)?;
        if kasumi_store::CustodyStore::catalog_installed(&self.node, tenant)
            .context(RecoverStage::CustodyOpen)?
        {
            let custody = kasumi_store::CustodyStore::open(
                self.node.clone(),
                tenant.to_owned(),
                custody_provider.clone(),
            )
            .await
            .map_err(|original| {
                OriginalRecoveryFailure::snapshot_at(original.into(), RecoverStage::CustodyOpen)
            })?;
            if kasumi_raft::ControlLog::installed(custody.clone())
                .context(RecoverStage::CustodyOpen)?
                .is_some()
                && self
                    .control
                    .raft_group()
                    .recover_retired_custody(&custody)
                    .map_err(kasumi_engine::SnapshotFailure::from)
                    .map_err(|original| {
                        OriginalRecoveryFailure::snapshot_at(original, RecoverStage::CustodyOpen)
                    })?
            {
                let owner = crate::runtime::open_retired_source(
                    &self.config,
                    custody,
                    self.cluster.as_ref(),
                    self.audit.clone(),
                    self.admission.clone(),
                )
                .await
                .map_err(OriginalRecoveryFailure::from)?;
                seat.retired = Some(owner.clone());
                self.registry
                    .install_retirement_source(
                        kasumi_engine::InstalledRetirementSource::RetiredCustody(owner.clone()),
                    )
                    .context(RecoverStage::Publish)?;
                self.custody_generations
                    .write()
                    .map_err(|_| anyhow::anyhow!("custody registry unavailable"))
                    .context(RecoverStage::Publish)?
                    .insert(key.clone(), owner);
                // Retired custody never returns to data routing.
                self.registry
                    .set_pending_admission(tenant, incarnation, false)
                    .context(RecoverStage::Publish)?;
                self.finish_pending_admission(tenant, incarnation);
                return Ok(());
            }
        }
        // No application provider is constructed until the exact incarnation is
        // independently admitted again. This never uses a preparation fallback.
        let (access, lease) = crate::serving_runtime::acquire_tenant_access(
            &self.config,
            &self.authority_trusts,
            self.credential.clone(),
            tenant,
            Uuid::parse_str(incarnation)?,
            kasumi_serving::LeasePurpose::Serving,
        )
        .await
        .context(RecoverStage::AccessLease)?;
        let provider = configured
            .keys
            .provider(self.credential.clone())
            .context(RecoverStage::KeyProvider)?;
        let stores = TenantStorageSet::open_existing(
            self.node.clone(),
            tenant.to_owned(),
            provider.clone(),
            custody_provider.clone(),
            access,
        )
        .await
        .map_err(|original| {
            OriginalRecoveryFailure::snapshot_at(original.into(), RecoverStage::StorageOpen)
        })?;
        seat.stores = Some(stores.clone());
        let mut group = Some(format!("{tenant}/{incarnation}"));
        let opened = async {
            // Replay requires the configured tenant audit placement, installed on
            // this fresh store exactly as at startup; none is selected by default.
            self.config
                .install_tenant_audit_archive(stores.application(), None)
                .context(RecoverStage::StorageOpen)?;
            let _reservation = self
                .admission
                .reserve(kasumi_engine::recovery_workspace_bytes(&stores)?, None)
                .context(RecoverStage::AdmissionReserve)?;
            let expected_incarnation = Uuid::parse_str(incarnation)?;
            let (database, bootstrap) =
                if self.config.mode == crate::runtime::DeploymentMode::Replicated {
                    let network = self.cluster.as_ref().context("replication unavailable")?;
                    let opened = kasumi_engine::open_existing_replicated(
                        self.config
                            .replication
                            .as_ref()
                            .context("replication unavailable")?
                            .node_id,
                        stores.clone(),
                        expected_incarnation,
                        network.clone(),
                        kasumi_raft::server_config(),
                        self.audit.clone(),
                    )
                    .await
                    .map_err(|original| {
                        OriginalRecoveryFailure::snapshot_at(original, RecoverStage::EngineOpen)
                    })?;
                    seat.database = Some(opened.database.clone());
                    let fingerprint = crate::runtime::opened_replicated_bootstrap_fingerprint(
                        stores.application().tenant(),
                        &opened,
                    )
                    .context(RecoverStage::EngineOpen)?;
                    let kasumi_engine::OpenedReplica {
                        database,
                        bootstrap,
                        ..
                    } = opened;
                    let store = stores.application().clone();
                    if let Err(error) = network.register_group_with_bootstrap(
                        group.as_ref().expect("unpublished route").clone(),
                        database.raft_group().raft().clone(),
                        self.config
                            .replication
                            .as_ref()
                            .unwrap()
                            .peers
                            .iter()
                            .map(|peer| peer.node_id)
                            .collect(),
                        fingerprint,
                        Arc::new(move || store.check_access()),
                    ) {
                        return Err(OriginalRecoveryFailure::from(
                            error.context(RecoverStage::RouteRegister),
                        ));
                    }
                    seat.route_to_unregister = group.take();
                    (database, Some(bootstrap))
                } else {
                    let database = kasumi_engine::open_existing_local(
                        stores.clone(),
                        self.audit.clone(),
                        expected_incarnation,
                    )
                    .await
                    .map_err(|original| {
                        OriginalRecoveryFailure::snapshot_at(original, RecoverStage::EngineOpen)
                    })?;
                    seat.database = Some(database.clone());
                    (database, None)
                };
            let setup = (|| {
                for (name, destination) in &self.destinations {
                    database.install_archive_destination(name.clone(), destination.clone())?;
                }
                database.check_serving()?;
                ensure!(
                    self.committed_topology()?
                        .tenants
                        .get(tenant)
                        .is_some_and(|route| route.incarnation == incarnation),
                    "Control route changed during fresh tenant admission"
                );
                Ok::<_, anyhow::Error>(())
            })();
            if let Err(error) = setup {
                return Err(OriginalRecoveryFailure::from(
                    error.context(RecoverStage::SetupRouteChanged),
                ));
            }
            Ok::<_, OriginalRecoveryFailure>(ManagedTenant {
                database,
                store: stores.application().clone(),
                bootstrap,
                lease,
            })
        }
        .await;
        let current = match opened {
            Ok(current) => current,
            Err(error) => return Err(error),
        };
        self.generations
            .write()
            .map_err(|_| anyhow::anyhow!("generation registry unavailable"))
            .context(RecoverStage::Publish)?
            .insert(key, current.clone());
        self.registry
            .install_retirement_source(kasumi_engine::InstalledRetirementSource::Serving(
                current.database.clone(),
            ))
            .context(RecoverStage::Publish)?;
        // Routing the fresh generation clears the registry's pending mark.
        self.finish_pending_admission(tenant, incarnation);
        self.initialize_original_if_ready(tenant, &current)
            .await
            .context(RecoverStage::Initialize)
            .map_err(Into::into)
    }

    /// Record the first observation of a closed generation with only fixed
    /// classes. Later attempts for the same incarnation reuse this record.
    fn observe_closure(
        &self,
        tenant: &str,
        incarnation: &str,
        previous: &ManagedTenant,
    ) -> Result<()> {
        let mut pending = self
            .pending_admission
            .write()
            .map_err(|_| anyhow::anyhow!("pending admission registry unavailable"))?;
        let key = (tenant.to_owned(), incarnation.to_owned());
        if pending.contains_key(&key) {
            return Ok(());
        }
        let record = PendingAdmission {
            closure_cause: previous
                .database
                .serving_failure_class()
                .unwrap_or("unclassified"),
            key_lease_class: previous.store.key_lease_failure_class(),
            drained_with_issues: BTreeSet::new(),
            failed_attempts: 0,
        };
        tracing::warn!(
            tenant,
            event = "original_tenant_closed",
            closure_cause = record.closure_cause,
            key_lease_class = record.key_lease_class.unwrap_or("none"),
            "original tenant closed; draining for fresh admission"
        );
        pending.insert(key, record);
        // Native callers bound to this incarnation now see a retryable outage
        // once the closed generation is detached, not an authorization denial.
        self.registry
            .set_pending_admission(tenant, incarnation, true)?;
        Ok(())
    }

    fn record_drain_issues(&self, tenant: &str, incarnation: &str, failure: &DrainFailure) {
        let names = component_names(failure);
        tracing::warn!(
            tenant,
            event = "original_tenant_drain_completed_with_issues",
            components = joined(&names),
            "closed original tenant drained with recorded issues"
        );
        if let Ok(mut pending) = self.pending_admission.write()
            && let Some(record) = pending.get_mut(&(tenant.to_owned(), incarnation.to_owned()))
        {
            record.drained_with_issues.extend(names);
        }
    }

    fn finish_pending_admission(&self, tenant: &str, incarnation: &str) {
        let Some(record) =
            self.pending_admission.write().ok().and_then(|mut pending| {
                pending.remove(&(tenant.to_owned(), incarnation.to_owned()))
            })
        else {
            return;
        };
        tracing::info!(
            tenant,
            event = "original_tenant_reopened",
            closure_cause = record.closure_cause,
            key_lease_class = record.key_lease_class.unwrap_or("none"),
            drained_with_issues = joined(&record.drained_with_issues),
            failed_attempts = record.failed_attempts,
            "original tenant reopened through fresh admission"
        );
    }

    async fn initialize_original_if_ready(
        &self,
        tenant: &str,
        current: &ManagedTenant,
    ) -> Result<()> {
        let Some(bootstrap) = &current.bootstrap else {
            return Ok(());
        };
        if current
            .database
            .raft_group()
            .raft()
            .is_initialized()
            .await?
        {
            return Ok(());
        }
        let local = self
            .config
            .replication
            .as_ref()
            .context("replication unavailable")?
            .node_id;
        if bootstrap.voters.keys().next() != Some(&local) {
            return Ok(());
        }
        let network = self.cluster.as_ref().context("replication unavailable")?;
        let group = format!("{tenant}/{}", bootstrap.incarnation);
        let expected =
            crate::runtime::persisted_replicated_bootstrap_fingerprint(current.database.stores())?;
        for member in bootstrap.voters.keys() {
            ensure!(
                network.bootstrap_fingerprint(*member, &group).await? == expected,
                "original tenant bootstrap differs across voters"
            );
        }
        kasumi_engine::initialize_replicated(&current.database, bootstrap).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_stage_preserves_only_outer_typed_retry_and_retains_cleanup() {
        let unavailable = || {
            anyhow::Error::new(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unavailable,
                "installed credential is unavailable",
            ))
        };
        let failure = OriginalRecoveryFailure::snapshot_at(
            unavailable().into(),
            RecoverStage::StorageOpen,
        );
        assert_eq!(failure.source_stage(), Some(&RecoverStage::StorageOpen));
        let mut seat = RecoverySeat {
            failure: Some(failure),
            ..Default::default()
        };
        assert!(seat.native_free_failure());
        seat.stores_observation.entry = CleanupEntry::Entered;
        assert!(!seat.native_free_failure());
        seat.stores_observation.entry = CleanupEntry::Returned;
        seat.stores_observation.future_disposal = CleanupEntry::Entered;
        assert!(!seat.native_free_failure());
        seat.stores_observation.future_disposal = CleanupEntry::Returned;
        let mut report = DrainReport::default();
        let failure = report.record("fixture cleanup", 0, anyhow::anyhow!("cleanup failed"));
        seat.failure.as_mut().unwrap().stores_cleanup = Some(DrainFailure::retained(failure));
        assert!(!seat.native_free_failure());
        seat.failure = Some(OriginalRecoveryFailure::snapshot_at(
            unavailable().context("opaque provider context").into(),
            RecoverStage::StorageOpen,
        ));
        assert!(!seat.native_free_failure());
        assert!(seat.failure.as_ref().unwrap().original().source_error().is_some());
    }

    #[test]
    fn recover_stage_is_the_only_logged_class_of_a_failed_attempt() {
        let failed: Result<()> = Err(anyhow::anyhow!("provider https://private.example/key"));
        let error = failed.context(RecoverStage::StorageOpen).unwrap_err();
        let stage = error.downcast_ref::<RecoverStage>().copied();
        assert_eq!(stage, Some(RecoverStage::StorageOpen));
        assert_eq!(stage.unwrap().class(), "storage_open");
        let ensured = (|| -> Result<()> {
            ensure!(false, RecoverStage::EnrollmentMismatch);
            Ok(())
        })()
        .unwrap_err();
        assert_eq!(
            ensured.downcast_ref::<RecoverStage>(),
            Some(&RecoverStage::EnrollmentMismatch)
        );
        // A later drain context keeps the stage observable beneath it.
        let nested = Err::<(), _>(anyhow::anyhow!("private detail"))
            .context(RecoverStage::EngineOpen)
            .context("store shutdown also failed")
            .unwrap_err();
        assert_eq!(
            nested.downcast_ref::<RecoverStage>(),
            Some(&RecoverStage::EngineOpen)
        );
        for stage in [
            RecoverStage::EnrollmentMismatch,
            RecoverStage::PreviousLeaseRetained,
            RecoverStage::PreviousDetach,
            RecoverStage::PreviousShutdownRetained,
            RecoverStage::CustodyOpen,
            RecoverStage::AccessLease,
            RecoverStage::KeyProvider,
            RecoverStage::StorageOpen,
            RecoverStage::AdmissionReserve,
            RecoverStage::EngineOpen,
            RecoverStage::RouteRegister,
            RecoverStage::SetupRouteChanged,
            RecoverStage::Publish,
            RecoverStage::Initialize,
        ] {
            assert!(
                stage
                    .class()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
    }
}

#[cfg(test)]
#[path = "original_recovery_inventory_tests.rs"]
mod inventory_tests;

#[cfg(test)]
#[path = "original_node_start_inventory_tests.rs"]
mod node_start_inventory_tests;

#[cfg(test)]
#[path = "original_node_start_sealed_tests.rs"]
mod original_node_start_sealed_tests;
