//! Bounded snapshot transfer children. The retained owner, never an awaiting
//! future or a background reaper, owns every actual blocking-task handle.
use kasumi_store::{EncryptedSpool, SnapshotImage};
use kasumi_types::{
    SharedBudgetCharge,
    drain::{DrainReport, DrainResult},
};
use std::{
    collections::BTreeMap,
    future::Future,
    io::{self, Read, Seek, SeekFrom, Write},
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

// Map a returned error without an async generator around the actual opening.
// The retained startup owner must keep the exact pinned future after its poll
// panics. A generator wrapper would drop that future during unwinding.
#[repr(transparent)]
struct OpeningFailureMap<F>(F);
impl<F, E> Future for OpeningFailureMap<F>
where
    F: Future<Output = Result<crate::startup_owner::StartedGroup, E>>,
    E: Into<kasumi_store::ScratchOperationFailure>,
{
    type Output = Result<crate::startup_owner::StartedGroup, kasumi_store::ScratchOperationFailure>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // SAFETY: the private single field is structurally pinned. No method
        // moves it out after pinning, and this wrapper has no custom Drop.
        let original = unsafe { self.map_unchecked_mut(|wrapper| &mut wrapper.0) };
        original.poll(cx).map(|outcome| outcome.map_err(Into::into))
    }
}

const WORKSPACE: usize = 64 << 10;
// Two 64KiB encrypted-spool buffers, one transfer Vec, and the bounded
// freeze/hash workspace. The authentication slot overhead fits metadata.
const BUFFER_WORKSPACE: u64 = 4 * WORKSPACE as u64;
const CELL_METADATA: u64 = 16 << 10;
// Each admitted slot covers its receiving spool's separate allocation before
// acquire invokes the constructor; child custody retains the same owner charge.
const RECEIVING_BACKING: u64 = std::mem::size_of::<EncryptedSpool>() as u64;
pub const SNAPSHOT_BUFFER_SLOTS: usize = 32;

#[derive(Debug)]
enum Backing {
    Receiving(Box<EncryptedSpool>),
    Captured(SnapshotImage),
}
#[derive(Debug)]
enum Completion {
    Read { bytes: Vec<u8>, offset: usize },
    Write(usize),
    Flush,
}
#[derive(Debug)]
enum Kind {
    Read,
    Write { count: usize, digest: [u8; 32] },
    Flush,
}
#[derive(Debug)]
struct Pending {
    kind: Kind,
    task: tokio::task::JoinHandle<io::Result<Completion>>,
}
#[derive(Debug, Default)]
struct State {
    position: u64,
    pending: Option<Pending>,
    completion: Option<Completion>,
    shutdown_started: bool,
    shutdown_done: bool,
    released: bool,
    report: DrainReport,
}

/// There are exactly two polling roles: the exclusively borrowed buffer and
/// the owner's serialized drain. A cancelled waiter replaces only its own slot.
#[derive(Debug, Default)]
struct ChildWake(Mutex<[Option<Waker>; 2]>);
impl ChildWake {
    fn register(&self, role: usize, waker: &Waker) {
        let mut waiters = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if waiters[role]
            .as_ref()
            .is_none_or(|old| !old.will_wake(waker))
        {
            waiters[role] = Some(waker.clone());
        }
    }
}
impl Wake for ChildWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let waiters = std::mem::take(&mut *self.0.lock().unwrap_or_else(|p| p.into_inner()));
        for waker in waiters.into_iter().flatten() {
            waker.wake();
        }
    }
}
#[derive(Debug)]
struct Cell {
    backing: Arc<Mutex<Option<Backing>>>,
    length: Arc<AtomicU64>,
    limit: u64,
    failed: Arc<AtomicBool>,
    state: Mutex<State>,
    wake: Arc<ChildWake>,
    #[cfg(test)]
    next_child: Mutex<Option<Arc<tests::ChildControl>>>,
}

/// Lifecycle custody for the application's exact selected storage sources.
///
/// Bind once before acquiring any source. Implementations must not retain a
/// `SnapshotBufferOwner`, Database, Engine or Generation, or call startup APIs:
/// unclaimed group cleanup can poll them while startup is serialized. Calls run
/// outside this owner's retained registry and transfer-cell locks. This hook
/// confers no storage-provider, document-allocation or primary-format authority.
///
/// `seal_consumers` is idempotent and leaves admitted application writers able to finish.
/// `poll_drain` is called only after those writers stop; it must seal preparation,
/// preserve original errors and cleanup ownership across canceled polls, and be
/// idempotent. `is_drained` is monotonic and true only after positive retirement
/// of every exact source and in-flight acquisition.
pub trait ApplicationSourceCustody: Send + Sync {
    /// Check the final selected reconstruction after full startup and before
    /// delivery. Success may switch the concrete source owner into serving;
    /// failure is retained with the unclaimed group before cleanup awaits.
    fn finish_reconstruction(&self) -> anyhow::Result<()>;
    fn seal_consumers(&self);
    fn poll_drain(&self, cx: &mut Context<'_>) -> Poll<DrainResult>;
    fn is_drained(&self) -> bool;
}

// This erasure preserves the concrete owner's external credit through the
// binding Box's deallocation. There is no clone/raw-Box extraction API.
trait RetireApplicationSource: ApplicationSourceCustody {
    fn retire(self: Box<Self>);
}
impl<T: ApplicationSourceCustody> RetireApplicationSource for T {
    fn retire(self: Box<Self>) {
        let source = {
            let allocation = self;
            *allocation
        };
        drop(source);
    }
}

/// One pre-admitted application-source hook. Its concrete source must retain
/// the quoted binding allocation's credit until that source is dropped.
/// The trusted installer constructs exactly one binding from its root grant.
pub struct ApplicationSourceBinding {
    source: Option<Box<dyn RetireApplicationSource>>,
}
impl ApplicationSourceBinding {
    pub fn required_bytes<T: ApplicationSourceCustody>() -> anyhow::Result<u64> {
        std::mem::size_of::<T>()
            .checked_next_power_of_two()
            .and_then(|bytes| bytes.checked_add(64))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(|| anyhow::anyhow!("application source binding quote overflow"))
    }
    /// The caller has already reserved `required_bytes::<T>()` and carries that
    /// reservation in `source`. Construction does not authorize admission.
    pub fn new<T: ApplicationSourceCustody + 'static>(source: T) -> Self {
        Self {
            source: Some(Box::new(source)),
        }
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn allocation_address(&self) -> usize {
        std::ptr::from_ref(self.source.as_deref().expect("source binding")) as *const () as usize
    }
    /// Explicit fixture-only hook without production admission semantics.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture(source: Arc<dyn ApplicationSourceCustody>) -> Self {
        struct Fixture(Arc<dyn ApplicationSourceCustody>);
        impl ApplicationSourceCustody for Fixture {
            fn finish_reconstruction(&self) -> anyhow::Result<()> {
                self.0.finish_reconstruction()
            }
            fn seal_consumers(&self) {
                self.0.seal_consumers();
            }
            fn poll_drain(&self, cx: &mut Context<'_>) -> Poll<DrainResult> {
                self.0.poll_drain(cx)
            }
            fn is_drained(&self) -> bool {
                self.0.is_drained()
            }
        }
        Self::new(Fixture(source))
    }
}
impl ApplicationSourceCustody for ApplicationSourceBinding {
    fn finish_reconstruction(&self) -> anyhow::Result<()> {
        self.source
            .as_ref()
            .expect("source binding")
            .finish_reconstruction()
    }
    fn seal_consumers(&self) {
        self.source
            .as_ref()
            .expect("source binding")
            .seal_consumers();
    }
    fn poll_drain(&self, cx: &mut Context<'_>) -> Poll<DrainResult> {
        self.source.as_ref().expect("source binding").poll_drain(cx)
    }
    fn is_drained(&self) -> bool {
        self.source.as_ref().expect("source binding").is_drained()
    }
}
impl Drop for ApplicationSourceBinding {
    fn drop(&mut self) {
        if let Some(source) = self.source.take() {
            source.retire();
        }
    }
}

/// A trusted installer reserves `required_bytes` from its node governor before
/// constructing this owner. Its fixed inventory covers transfer workspace and
/// child/handle metadata; encrypted extents retain their ScratchDisk charges.
pub struct SnapshotBufferOwner {
    id: uuid::Uuid,
    cells: Mutex<Box<[Option<Arc<Cell>>]>>,
    closed: AtomicBool,
    startup_closing: AtomicBool,
    application_sources: OnceLock<ApplicationSourceBinding>,
    // Set false before binding is visible; only a completed final drain with
    // positive source retirement sets it true. Release predicates never invoke
    // application callbacks while holding startup/registry/cell locks.
    application_sources_drained: AtomicBool,
    failed: Arc<AtomicBool>,
    drain_gate: tokio::sync::Mutex<()>,
    startup: tokio::sync::Mutex<crate::startup_owner::StartupState>,
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) local_startup_gate: Mutex<Option<Arc<crate::startup_test_utils::LocalStartupGate>>>,
    report: Mutex<DrainReport>,
    apply_failure: crate::apply_failure::ApplyFailureSlot,
    scratch_failures: crate::scratch_failure_inventory::ScratchFailureInventory,
    _charge: SharedBudgetCharge,
}
impl std::fmt::Debug for SnapshotBufferOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotBufferOwner")
            .field("id", &self.id)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}
fn retained() -> &'static Mutex<BTreeMap<uuid::Uuid, Arc<SnapshotBufferOwner>>> {
    static OWNERS: OnceLock<Mutex<BTreeMap<uuid::Uuid, Arc<SnapshotBufferOwner>>>> =
        OnceLock::new();
    OWNERS.get_or_init(Default::default)
}
impl SnapshotBufferOwner {
    pub fn required_bytes(max_buffers: usize) -> anyhow::Result<u64> {
        anyhow::ensure!(
            max_buffers > 0 && max_buffers <= 4096,
            "snapshot buffer inventory outside supported bounds"
        );
        let scratch_failures =
            crate::scratch_failure_inventory::ScratchFailureInventory::required_bytes(max_buffers)?
                .checked_add(std::mem::size_of::<
                    crate::scratch_failure_inventory::ScratchFailureInventory,
                >() as u64)
                .ok_or_else(|| anyhow::anyhow!("scratch failure inventory quote overflow"))?;
        u64::try_from(max_buffers)?
            .checked_mul(BUFFER_WORKSPACE + CELL_METADATA + RECEIVING_BACKING)
            .and_then(|bytes| {
                bytes.checked_add(
                    CELL_METADATA
                        + crate::startup_owner::STARTUP_WORKSPACE
                        + std::mem::size_of::<crate::startup_owner::StartupState>() as u64
                        + std::mem::size_of::<(OnceLock<ApplicationSourceBinding>, AtomicBool)>()
                            as u64
                        + crate::apply_failure::ApplyFailureSlot::required_bytes()
                        + std::mem::size_of::<crate::apply_failure::ApplyFailureSlot>() as u64
                        + scratch_failures,
                )
            })
            .ok_or_else(|| anyhow::anyhow!("snapshot buffer inventory overflow"))
    }
    pub fn new(max_buffers: usize, charge: SharedBudgetCharge) -> anyhow::Result<Arc<Self>> {
        Self::required_bytes(max_buffers)?;
        let scratch_failures = crate::scratch_failure_inventory::ScratchFailureInventory::new(
            max_buffers,
            charge.clone(),
        )?;
        let owner = Arc::new(Self {
            id: uuid::Uuid::new_v4(),
            cells: Mutex::new((0..max_buffers).map(|_| None).collect()),
            closed: AtomicBool::new(false),
            startup_closing: AtomicBool::new(false),
            application_sources: OnceLock::new(),
            application_sources_drained: AtomicBool::new(true),
            failed: Arc::new(AtomicBool::new(false)),
            drain_gate: Default::default(),
            startup: Default::default(),
            #[cfg(any(test, feature = "test-utils"))]
            local_startup_gate: Default::default(),
            report: Default::default(),
            apply_failure: crate::apply_failure::ApplyFailureSlot::new(charge.clone()),
            scratch_failures,
            _charge: charge,
        });
        Ok(owner)
    }
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture() -> Arc<Self> {
        Self::new(SNAPSHOT_BUFFER_SLOTS, SharedBudgetCharge::new(())).unwrap()
    }

    /// Enroll one pre-admitted application source registry before native source
    /// acquisition or startup. The existing strong startup root is installed
    /// synchronously, so an abandoned Idle construction remains drainable.
    /// The concrete registry and its backings require their own real charge;
    /// `required_bytes` includes this owner's hook/control layout; its existing
    /// `CELL_METADATA` allowance covers the same retained-map entry previously
    /// installed by `start` or first transfer acquisition. There is no second
    /// registry entry or per-binding dynamic inventory.
    pub fn bind_application_sources(
        self: &Arc<Self>,
        source: ApplicationSourceBinding,
    ) -> anyhow::Result<()> {
        let startup = self
            .startup
            .try_lock()
            .map_err(|_| anyhow::anyhow!("Raft startup owner is already in use"))?;
        self.check_startup()?;
        anyhow::ensure!(
            matches!(*startup, crate::startup_owner::StartupState::Idle),
            "application sources must be bound before Raft startup"
        );
        anyhow::ensure!(
            self.application_sources.get().is_none(),
            "application source custody is already bound"
        );
        let mut registry = retained().lock().unwrap_or_else(|p| p.into_inner());
        anyhow::ensure!(
            registry
                .get(&self.id)
                .is_none_or(|owner| Arc::ptr_eq(owner, self)),
            "snapshot custody identity collision"
        );
        // Every removal path holds startup through its registry mutation. No
        // release can observe the old true latch while this binding publishes.
        self.application_sources_drained
            .store(false, Ordering::Release);
        assert!(self.application_sources.set(source).is_ok());
        registry.insert(self.id, self.clone());
        Ok(())
    }

    /// Atomically enroll the paired source registry and its ordinary completion.
    /// Both erased owners already hold their actual construction grants.
    pub fn bind_application_sources_with_completion(
        self: &Arc<Self>,
        source: &mut Option<ApplicationSourceBinding>,
        completion: &mut Option<crate::CompletionBinding>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            source.is_some() && completion.is_some(),
            "application source or completion binding absent"
        );
        let startup = self
            .startup
            .try_lock()
            .map_err(|_| anyhow::anyhow!("Raft startup owner is already in use"))?;
        self.check_startup()?;
        anyhow::ensure!(
            matches!(*startup, crate::startup_owner::StartupState::Idle),
            "application sources must be bound before Raft startup"
        );
        anyhow::ensure!(
            self.application_sources.get().is_none() && !self.apply_failure.completion().bound(),
            "application source or completion custody is already bound"
        );
        let mut registry = retained().lock().unwrap_or_else(|p| p.into_inner());
        anyhow::ensure!(
            registry
                .get(&self.id)
                .is_none_or(|owner| Arc::ptr_eq(owner, self)),
            "snapshot custody identity collision"
        );
        self.application_sources_drained
            .store(false, Ordering::Release);
        assert!(
            self.apply_failure
                .completion()
                .bind(completion.take().expect("prevalidated completion"))
                .is_ok()
        );
        assert!(
            self.application_sources
                .set(source.take().expect("prevalidated source"))
                .is_ok()
        );
        registry.insert(self.id, self.clone());
        Ok(())
    }
    pub(crate) fn scratch_failure_guard(
        &self,
    ) -> Result<
        crate::scratch_failure_inventory::ScratchFailureGuard,
        kasumi_store::ScratchOperationFailure,
    > {
        use crate::scratch_failure_inventory::ScratchInventoryRefusal;
        match self.scratch_failures.acquire() {
            Ok(guard) => Ok(guard),
            Err(ScratchInventoryRefusal::Occupied(original)) => {
                Err(kasumi_store::ScratchOperationFailure::Creation(original))
            }
            Err(ScratchInventoryRefusal::Busy) => {
                Err(kasumi_store::ScratchOperationFailure::AdmissionRefused(
                    kasumi_store::ScratchAdmissionRefusal::Busy,
                ))
            }
            Err(ScratchInventoryRefusal::Sealed) => {
                Err(kasumi_store::ScratchOperationFailure::AdmissionRefused(
                    kasumi_store::ScratchAdmissionRefusal::Sealed,
                ))
            }
        }
    }
    /// The actual prepaid admission report survives dropped external errors.
    /// Borrowing it does not acknowledge or dispose its original diagnostic.
    pub fn retained_scratch_admission(
        &self,
        index: usize,
    ) -> Option<kasumi_store::ScratchCreationFailure> {
        self.scratch_failures.original_failure(index)
    }
    pub fn scratch_admission_capacity(&self) -> usize {
        self.scratch_failures.capacity()
    }

    pub(crate) fn apply_slot(&self) -> &crate::apply_failure::ApplyFailureSlot {
        &self.apply_failure
    }
    /// Borrow the actual retained apply report without releasing its custody.
    ///
    /// `Ok(None)` means no terminal failure is latched at this observation; it
    /// does not prove successful apply or completed drain. `ReportBusy` means
    /// the report is currently borrowed or being updated, not that it is absent.
    ///
    /// The callback runs synchronously and cannot move originals out. It may
    /// observe a failed worker still recording its remaining outcomes, so it
    /// must not wait for that worker or drain while holding this borrow.
    /// Inspection never acknowledges, retries, clears, or drains an outcome.
    /// Its borrow is released before waking a waiting drain, even on unwind.
    pub fn try_with_retained_apply_report<R>(
        &self,
        inspect: impl for<'a> FnOnce(crate::RetainedApplyReport<'a>) -> R,
    ) -> Result<Option<R>, crate::ReportBusy> {
        self.apply_failure
            .failure()
            .map(|failure| failure.try_with_report(inspect))
            .transpose()
    }
    fn completion_released(&self) -> bool {
        (!self.apply_failure.completion().unsettled()
            || self.apply_failure.failure_ownership_drained())
            && self.apply_failure.completion().drained()
    }

    fn failed_apply_resources_drained(&self) -> bool {
        self.application_sources_drained.load(Ordering::Acquire)
            && self.apply_failure.failure_ownership_drained()
    }

    fn apply_failure_unresolved(&self) -> bool {
        self.apply_failure.failure().is_some() && !self.failed_apply_resources_drained()
    }

    /// Revisit only this owner's earlier buffer census after actual writers and
    /// application sources have stopped. The trusted disposition does not clear
    /// the original diagnostic, acknowledge the entry, or settle other owners.
    pub(crate) async fn finish_failed_buffer_drain(
        &self,
        earlier: Option<kasumi_types::drain::DrainFailure>,
        report: &mut DrainReport,
    ) -> Option<kasumi_types::drain::DrainFailure> {
        if earlier.is_none() {
            return earlier;
        }
        let final_census = self.drain_buffers().await;
        report.merge_result(&final_census);
        final_census.err().filter(|failure| {
            failure.completion() == kasumi_types::drain::DrainCompletion::Retained
        })
    }

    pub(crate) fn finish_application_source_reconstruction(&self) -> anyhow::Result<()> {
        match self.application_sources.get() {
            Some(source) => source.finish_reconstruction(),
            None => Ok(()),
        }
    }

    /// Stop new source consumers while allowing admitted apply/replay writers
    /// to reach their actual durable publication boundary.
    pub fn seal_application_source_consumers(&self) {
        if let Some(source) = self.application_sources.get() {
            source.seal_consumers();
        }
    }

    /// Final source retirement, only after real application writers stop.
    /// Cancellation leaves the exact registry, cells and errors in the bound
    /// hook. Do not call from the initial transfer-buffer drain.
    pub(crate) async fn drain_application_sources(&self) -> DrainResult {
        std::future::poll_fn(|cx| self.apply_failure.completion().poll_drain(cx)).await;
        if !self.apply_failure.completion().drained() {
            let failure = self.apply_failure.diagnostic();
            let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
            let issue = report.record("Raft ordinary completion", 0, failure.into());
            return report.outcome(Some(kasumi_types::drain::DrainFailure::retained(issue)));
        }
        let Some(source) = self.application_sources.get() else {
            return Ok(());
        };
        let result = std::future::poll_fn(|cx| source.poll_drain(cx)).await;
        let positive = source.is_drained();
        let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
        report.merge_result(&result);
        let unresolved = if !positive {
            Some(match result {
                Err(failure) => failure,
                Ok(()) => {
                    let issue = report.record(
                        "application source custody",
                        0,
                        anyhow::anyhow!("source drain returned without positive retirement"),
                    );
                    kasumi_types::drain::DrainFailure::retained(issue)
                }
            })
        } else if !drain_completed(&result) {
            result.err()
        } else {
            self.application_sources_drained
                .store(true, Ordering::Release);
            None
        };
        report.outcome(unresolved)
    }

    pub(crate) fn start<F, E>(
        self: &Arc<Self>,
        future: F,
    ) -> impl Future<
        Output = Result<crate::startup_owner::StartedGroup, kasumi_store::ScratchOperationFailure>,
    > + Send
    + '_
    where
        F: Future<Output = Result<crate::startup_owner::StartedGroup, E>> + Send + 'static,
        E: Into<kasumi_store::ScratchOperationFailure> + Send + 'static,
    {
        // Synchronous admission erases F before any caller awaits. A single
        // owner can never accumulate multiple prepared, charged allocations.
        let prepared = (|| {
            let mut startup = self
                .startup
                .try_lock()
                .map_err(|_| anyhow::anyhow!("Raft startup owner is already in use"))?;
            self.check_startup()?;
            let mut registry = retained().lock().unwrap_or_else(|p| p.into_inner());
            anyhow::ensure!(
                registry
                    .get(&self.id)
                    .is_none_or(|owner| Arc::ptr_eq(owner, self)),
                "snapshot custody identity collision"
            );
            // install checks the concrete opening + cleanup sizes before boxing.
            // Registry custody exists before the first actual Opening poll.
            startup.install(OpeningFailureMap(future))?;
            registry.insert(self.id, self.clone());
            Ok(())
        })();
        self.claim_startup(prepared)
    }

    async fn claim_startup(
        self: &Arc<Self>,
        prepared: anyhow::Result<()>,
    ) -> Result<crate::startup_owner::StartedGroup, kasumi_store::ScratchOperationFailure> {
        prepared?;
        // This non-generic future contains only the owner and admission result.
        let mut startup = self.startup.lock().await;
        let result = startup.claim(self).await;
        // Keep the already admitted strong root throughout a real group's
        // lifetime. Installed startup inventories hold only Weak handles, and
        // a canceled apply waiter must not become the last failure owner.
        let cells = self.cells.lock().unwrap_or_else(|p| p.into_inner());
        if startup.can_release_custody()
            && self.application_sources_drained.load(Ordering::Acquire)
            && self.completion_released()
            && !self.scratch_failures.retirement_blocked()
            && !self.apply_failure.has_live_ownership()
            && !self.apply_failure_unresolved()
            && cells.iter().all(Option::is_none)
        {
            retained()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.id);
        }
        result
    }

    pub(crate) fn bind_group_ownership(
        &self,
        ownership: Arc<AtomicBool>,
        identity: Arc<kasumi_store::TenantStore>,
    ) -> anyhow::Result<()> {
        self.apply_failure.bind_ownership(ownership, identity)
    }
    #[cfg(test)]
    pub(crate) fn bind_fixture_group_ownership(
        &self,
        ownership: Arc<AtomicBool>,
        identity: Arc<dyn Send + Sync>,
    ) -> anyhow::Result<()> {
        self.apply_failure.bind_ownership(ownership, identity)
    }
    pub(crate) fn release_group_ownership(&self) {
        if !self.application_sources_drained.load(Ordering::Acquire)
            || !self.completion_released()
            || self.scratch_failures.retirement_blocked()
        {
            return;
        }
        self.apply_failure.release_ownership();
        // Called only after a positive final drain. During startup cleanup the
        // startup lock is held; its subsequent final census removes this root.
        if let Ok(startup) = self.startup.try_lock()
            && startup.can_release_custody()
            && self.application_sources_drained.load(Ordering::Acquire)
            && self.completion_released()
            && !self.scratch_failures.retirement_blocked()
            && !self.apply_failure_unresolved()
            && self
                .cells
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .all(Option::is_none)
        {
            retained()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.id);
        }
    }

    pub(crate) fn apply_failure(&self) -> Option<crate::apply_failure::RetainedApplyFailure> {
        self.apply_failure.failure()
    }

    // Called while the state-machine serialization guard is held, before the
    // blocking worker returns. The waiter does not own the only error handle.
    pub(crate) fn retain_apply_failure(
        &self,
        error: anyhow::Error,
    ) -> crate::apply_failure::RetainedApplyFailure {
        self.failed.store(true, Ordering::Release);
        match self.apply_failure.retain(error) {
            Ok(retained) => retained,
            Err(independent) => {
                // This requires a violated owner/serialization contract. Keep
                // the independent owner in the lifecycle report as well.
                let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
                report.record("Raft additional apply failure", 0, independent);
                self.apply_failure.failure().expect("occupied apply slot")
            }
        }
    }

    pub(crate) fn record_startup_preparation(
        &self,
        original: &kasumi_store::ScratchOperationFailure,
    ) -> kasumi_types::drain::DrainFailure {
        self.failed.store(true, Ordering::Release);
        let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
        // The foreign shutdown marker borrows the typed preparation outcome.
        // The marker never contains its original native custody.
        let issue = report.record("Raft scratch startup", 0, anyhow::anyhow!("{original}"));
        report
            .outcome(Some(kasumi_types::drain::DrainFailure::retained(issue)))
            .expect_err("startup preparation remains unresolved")
    }

    pub(crate) fn record_startup_error(
        &self,
        error: anyhow::Error,
    ) -> kasumi_types::drain::DrainFailure {
        self.failed.store(true, Ordering::Release);
        let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
        // Observe only the outer ordinary value. An owning context must remain
        // in the original Anyhow allocation throughout startup and native drain.
        let outer: &(dyn std::error::Error + Send + Sync + 'static) = error.as_ref();
        // An independent live allocation has an independent report seat. Its
        // address cannot be reused while this report retains the original.
        let instance = outer as *const _ as *const () as usize;
        let original_drain = outer
            .downcast_ref::<kasumi_types::drain::DrainFailure>()
            .cloned();
        report.record("Raft startup", instance, error);
        let unresolved = if let Some(failure) = original_drain {
            report.merge(&failure);
            (failure.completion() == kasumi_types::drain::DrainCompletion::Retained)
                .then_some(failure)
        } else {
            None
        };
        report
            .outcome(unresolved)
            .expect_err("startup failure was recorded")
    }

    pub(crate) fn record_startup_poll_panic(
        &self,
        error: crate::startup_owner::StartupPollPanic,
    ) -> kasumi_types::drain::DrainFailure {
        self.failed.store(true, Ordering::Release);
        let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
        let issue = report.record("Raft startup poll panic", 0, error.into());
        report
            .outcome(Some(kasumi_types::drain::DrainFailure::retained(issue)))
            .expect_err("poll panic retains unresolved ownership")
    }

    #[cfg(test)]
    pub(crate) async fn install_cleanup_fixture<F>(self: &Arc<Self>, future: F)
    where
        F: Future<Output = DrainResult> + Send + 'static,
    {
        self.startup.lock().await.install_cleanup_fixture(future);
        retained()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(self.id, self.clone());
    }

    pub(crate) fn check_startup(&self) -> io::Result<()> {
        if self.startup_closing.load(Ordering::Acquire) {
            return Err(io::Error::other("Raft startup admission is closed"));
        }
        self.check()
    }

    pub(crate) fn check(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire)
            || (self.failed.load(Ordering::Acquire) || self.apply_failure.completion().failed())
        {
            Err(io::Error::other("snapshot transfer admission is closed"))
        } else {
            Ok(())
        }
    }
    fn acquire(
        self: &Arc<Self>,
        backing: impl FnOnce() -> io::Result<Backing>,
        length: u64,
        limit: u64,
    ) -> io::Result<SnapshotBuffer> {
        let mut cells = self.cells.lock().unwrap_or_else(|p| p.into_inner());
        self.check()?;
        // Reclaim only abandoned cells whose exact child has already joined.
        // A running cell remains charged and consumes its original fixed slot.
        for slot in cells.iter_mut() {
            if let Some(cell) = slot {
                let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
                if state.released {
                    let mut cx = Context::from_waker(Waker::noop());
                    let _ = cell.join(&mut state, &mut cx, 1);
                    if state.pending.is_none() {
                        self.report
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .merge_result(&state.report.complete());
                        drop(state);
                        *slot = None;
                    }
                }
            }
        }
        self.check()?;
        let slot = cells
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or_else(|| io::Error::other("snapshot buffer inventory exhausted"))?;
        // Admission precedes file creation. Idle owners have no global custody;
        // the first actual cell installs it before any worker can be spawned.
        let mut registry = retained().lock().unwrap_or_else(|p| p.into_inner());
        if registry
            .get(&self.id)
            .is_some_and(|owner| !Arc::ptr_eq(owner, self))
        {
            return Err(io::Error::other("snapshot custody identity collision"));
        }
        let cell = Arc::new(Cell {
            backing: Arc::new(Mutex::new(Some(backing()?))),
            length: Arc::new(AtomicU64::new(length)),
            limit,
            failed: self.failed.clone(),
            state: Default::default(),
            wake: Default::default(),
            #[cfg(test)]
            next_child: Default::default(),
        });
        *slot = Some(cell.clone());
        registry.entry(self.id).or_insert_with(|| self.clone());
        Ok(SnapshotBuffer {
            owner: self.clone(),
            cell,
        })
    }

    /// Stop new work and join every actual child, including abandoned buffer
    /// facades. Cancellation leaves the same handles, report and charge installed.
    pub async fn drain(&self) -> DrainResult {
        self.closed.store(true, Ordering::Release);
        self.drain_startup().await?;
        self.drain_buffers().await
    }

    /// Drain only a pending or unclaimed startup. An already delivered group
    /// keeps its buffer admission and is drained through its own shutdown API.
    /// Node shutdown can census these owners independently of startup callers.
    pub async fn drain_startup(&self) -> DrainResult {
        // Close delivery before waiting for a currently polled startup caller.
        // Claimed groups keep their independent buffer admission unchanged.
        self.startup_closing.store(true, Ordering::Release);
        let mut startup = self.startup.lock().await;
        if matches!(*startup, crate::startup_owner::StartupState::Delivered) {
            // Delivered healthy groups drain through their runtime. A known
            // apply failure must remain visible to the installed weak census.
            return if let Some(failure) = self.apply_failure.failure() {
                let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
                let issue = report.record("Raft apply", 0, failure.into());
                let unresolved = (!self.failed_apply_resources_drained())
                    .then(|| kasumi_types::drain::DrainFailure::retained(issue));
                report.outcome(unresolved)
            } else if self.apply_failure.completion().unsettled() {
                let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
                let issue = report.record(
                    "Raft ordinary completion in progress",
                    0,
                    anyhow::anyhow!("ordinary completion remains owned by active runtime"),
                );
                report.outcome(Some(kasumi_types::drain::DrainFailure::retained(issue)))
            } else {
                Ok(())
            };
        }
        // A binder already admitted before startup_closing may finish while
        // this census waits for startup. Inspect the installed hook only after
        // acquiring that lock. Delivered groups retain their established
        // independent runtime shutdown contract above.
        self.seal_application_source_consumers();
        self.closed.store(true, Ordering::Release);
        let startup_result = startup.drain(self).await;
        let writers_stopped = drain_completed(&startup_result);
        let startup_unresolved = match startup_result {
            Err(failure) => {
                self.report
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .merge(&failure);
                (failure.completion() == kasumi_types::drain::DrainCompletion::Retained)
                    .then_some(failure)
            }
            Ok(()) => None,
        };
        let mut buffers = self.drain_buffers().await;
        let buffer_unresolved = buffers
            .as_ref()
            .err()
            .filter(|failure| {
                failure.completion() == kasumi_types::drain::DrainCompletion::Retained
            })
            .cloned();
        // Idle abandonment has no writer. Opening/Cleaning may have writer
        // ownership even after an error, so only a positive startup drain may
        // close preparation. Actual groups already do this after StorageDrain.
        let sources = if writers_stopped {
            self.drain_application_sources().await
        } else {
            Ok(())
        };
        let source_unresolved = sources
            .as_ref()
            .err()
            .filter(|failure| {
                failure.completion() == kasumi_types::drain::DrainCompletion::Retained
            })
            .cloned();
        // A retained startup error is independent and stays retained. Revisit
        // only the buffer owner after its real source census has completed.
        let buffer_unresolved = if buffer_unresolved.is_some() {
            buffers = self.drain_buffers().await;
            buffers
                .as_ref()
                .err()
                .filter(|failure| {
                    failure.completion() == kasumi_types::drain::DrainCompletion::Retained
                })
                .cloned()
        } else {
            buffer_unresolved
        };
        let unresolved = startup_unresolved
            .or(source_unresolved)
            .or(buffer_unresolved);
        let result = {
            let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
            report.merge_result(&buffers);
            report.merge_result(&sources);
            report.outcome(unresolved)
        };
        if drain_completed(&result)
            && self.application_sources_drained.load(Ordering::Acquire)
            && self.completion_released()
            && !self.scratch_failures.retirement_blocked()
            && !self.apply_failure.has_live_ownership()
            && startup.can_release_custody()
        {
            retained()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.id);
        }
        result
    }

    // Startup error cleanup and a retained unclaimed group's shutdown must not
    // await the startup gate that currently owns their future.
    pub(crate) async fn drain_buffers(&self) -> DrainResult {
        self.scratch_failures.seal();
        self.closed.store(true, Ordering::Release);
        let _exclusive = self.drain_gate.lock().await;
        let result = std::future::poll_fn(|cx| {
            let mut all_ready = true;
            let mut cells = self.cells.lock().unwrap_or_else(|p| p.into_inner());
            let mut report = self.report.lock().unwrap_or_else(|p| p.into_inner());
            for slot in cells.iter_mut() {
                let Some(cell) = slot else { continue };
                let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
                match cell.shutdown(&mut state, cx, 1, &self.failed) {
                    Poll::Pending => all_ready = false,
                    Poll::Ready(result) => {
                        report.merge_result(&result);
                        // No child can still use the backing after shutdown.
                        cell.backing
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .take();
                        drop(state);
                        *slot = None;
                    }
                }
            }
            if all_ready {
                // Arbitrary errors may own native children. Only the exact
                // typed publication failure plus completed source/completion
                // census can retire ownership while keeping its diagnostic.
                let unresolved = self.apply_failure.failure().and_then(|failure| {
                    let issue = report.record("Raft apply", 0, failure.into());
                    (!self.failed_apply_resources_drained())
                        .then(|| kasumi_types::drain::DrainFailure::retained(issue))
                });
                let unresolved = unresolved.or_else(|| {
                    (self.apply_failure.completion().unsettled()
                        && !self.failed_apply_resources_drained())
                    .then(|| {
                        let issue = report.record(
                            "Raft ordinary completion in progress",
                            0,
                            anyhow::anyhow!("ordinary completion has not settled"),
                        );
                        kasumi_types::drain::DrainFailure::retained(issue)
                    })
                });
                let unresolved = unresolved.or_else(|| {
                    self.scratch_failures.retirement_blocked().then(|| {
                        let issue = report.record("Raft scratch admission custody", 0,
                            anyhow::anyhow!("scratch constructor job or original admission diagnostic remains owned"));
                        kasumi_types::drain::DrainFailure::retained(issue)
                    })
                });
                Poll::Ready(report.outcome(unresolved))
            } else {
                Poll::Pending
            }
        })
        .await;
        // Internal cleanup may be running inside the retained startup future.
        // Only a non-running startup can release this global custody root.
        if let Ok(startup) = self.startup.try_lock()
            && startup.can_release_custody()
            && drain_completed(&result)
            && self.application_sources_drained.load(Ordering::Acquire)
            && self.completion_released()
            && !self.scratch_failures.retirement_blocked()
            && !self.apply_failure.has_live_ownership()
        {
            retained()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.id);
        }
        result
    }
}
fn drain_completed(result: &DrainResult) -> bool {
    result.as_ref().err().is_none_or(|failure| {
        failure.completion() == kasumi_types::drain::DrainCompletion::Complete
    })
}
trait MergeResult {
    fn merge_result(&mut self, result: &DrainResult);
}
impl MergeResult for DrainReport {
    fn merge_result(&mut self, result: &DrainResult) {
        if let Err(failure) = result {
            self.merge(failure);
        }
    }
}

struct FailureGuard {
    failed: Arc<AtomicBool>,
    returned: bool,
}
impl Drop for FailureGuard {
    fn drop(&mut self) {
        if !self.returned {
            self.failed.store(true, Ordering::Release);
        }
    }
}
impl Cell {
    fn spawn(
        &self,
        state: &mut State,
        kind: Kind,
        failed: &Arc<AtomicBool>,
        work: impl FnOnce() -> io::Result<Completion> + Send + 'static,
    ) {
        let failed = failed.clone();
        #[cfg(test)]
        let control = self.next_child.lock().unwrap().take();
        let task = tokio::task::spawn_blocking(move || {
            let mut guard = FailureGuard {
                failed,
                returned: false,
            };
            #[cfg(test)]
            if let Some(control) = control {
                control.run()?;
            }
            let result = work();
            if result.is_err() {
                guard.failed.store(true, Ordering::Release);
            }
            guard.returned = true;
            drop(guard);
            result
        });
        state.pending = Some(Pending { kind, task });
    }
    fn join(&self, state: &mut State, cx: &mut Context<'_>, role: usize) -> Poll<()> {
        let Some(pending) = &mut state.pending else {
            return Poll::Ready(());
        };
        self.wake.register(role, cx.waker());
        let waker = Waker::from(self.wake.clone());
        let result = match Pin::new(&mut pending.task).poll(&mut Context::from_waker(&waker)) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        state.pending.take();
        match result {
            Ok(Ok(completion)) => {
                if let Completion::Write(count) = &completion {
                    state.position += *count as u64;
                }
                state.completion = Some(completion);
            }
            Ok(Err(error)) => {
                self.failed.store(true, Ordering::Release);
                state
                    .report
                    .record("snapshot blocking I/O", 0, error.into());
            }
            Err(error) => {
                self.failed.store(true, Ordering::Release);
                state
                    .report
                    .record("snapshot blocking child", 0, error.into());
            }
        }
        Poll::Ready(())
    }
    fn flush(
        &self,
        state: &mut State,
        cx: &mut Context<'_>,
        role: usize,
        failed: &Arc<AtomicBool>,
    ) -> Poll<DrainResult> {
        if self.join(state, cx, role).is_pending() {
            return Poll::Pending;
        }
        if let Err(error) = state.report.complete() {
            return Poll::Ready(Err(error));
        }
        if matches!(state.completion.take(), Some(Completion::Flush)) {
            return Poll::Ready(Ok(()));
        }
        let backing = self.backing.clone();
        self.spawn(state, Kind::Flush, failed, move || {
            match backing.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
                Some(Backing::Receiving(spool)) => spool.flush()?,
                Some(Backing::Captured(_)) => {}
                None => return Err(io::Error::other("snapshot storage is closed")),
            }
            Ok(Completion::Flush)
        });
        if self.join(state, cx, role).is_pending() {
            return Poll::Pending;
        }
        state.completion.take();
        Poll::Ready(state.report.complete())
    }
    fn shutdown(
        &self,
        state: &mut State,
        cx: &mut Context<'_>,
        role: usize,
        failed: &Arc<AtomicBool>,
    ) -> Poll<DrainResult> {
        state.shutdown_started = true;
        if state.shutdown_done {
            return Poll::Ready(state.report.complete());
        }
        match self.flush(state, cx, role, failed) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                state.shutdown_done = true;
                Poll::Ready(result)
            }
        }
    }
}

/// One exclusively polled transfer facade; dropping it never drops an unjoined
/// handle. Its fixed owner slot remains charged until actual completion/drain.
#[derive(Debug)]
pub struct SnapshotBuffer {
    owner: Arc<SnapshotBufferOwner>,
    cell: Arc<Cell>,
}
impl SnapshotBuffer {
    pub fn new(
        disk: &Arc<kasumi_store::ScratchDisk>,
        limit: u64,
        owner: &Arc<SnapshotBufferOwner>,
    ) -> io::Result<Self> {
        owner.acquire(
            || {
                Ok(Backing::Receiving(Box::new(EncryptedSpool::new(
                    disk, limit,
                )?)))
            },
            0,
            limit,
        )
    }
    pub fn from_image(image: SnapshotImage, owner: &Arc<SnapshotBufferOwner>) -> io::Result<Self> {
        let length = image.len();
        owner.acquire(|| Ok(Backing::Captured(image)), length, length)
    }
    pub fn from_bytes(
        disk: &Arc<kasumi_store::ScratchDisk>,
        bytes: Vec<u8>,
        limit: u64,
        owner: &Arc<SnapshotBufferOwner>,
    ) -> io::Result<Self> {
        if bytes.len() as u64 > limit {
            return Err(io::Error::other("snapshot exceeds byte limit"));
        }
        owner.acquire(
            || {
                Ok(Backing::Captured(
                    SnapshotImage::from_bytes(disk, &bytes).map_err(io::Error::other)?,
                ))
            },
            bytes.len() as u64,
            limit,
        )
    }
    pub fn len(&self) -> u64 {
        self.cell.length.load(Ordering::Acquire)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub async fn drain(&mut self) -> DrainResult {
        std::future::poll_fn(|cx| {
            let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
            self.cell.shutdown(&mut state, cx, 0, &self.owner.failed)
        })
        .await
    }
    pub fn into_image(self) -> anyhow::Result<SnapshotImage> {
        let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
        anyhow::ensure!(
            state.pending.is_none(),
            "snapshot transfer work has not drained"
        );
        state.report.complete()?;
        state.shutdown_started = true;
        state.shutdown_done = true;
        state.completion.take();
        let backing = self
            .cell
            .backing
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .ok_or_else(|| anyhow::anyhow!("snapshot storage is closed"))?;
        drop(state);
        match backing {
            Backing::Receiving(spool) => SnapshotImage::freeze(*spool),
            Backing::Captured(image) => Ok(image),
        }
    }
    pub(crate) fn image(&self) -> anyhow::Result<SnapshotImage> {
        match self
            .cell
            .backing
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
        {
            Some(Backing::Captured(image)) => Ok(image.clone()),
            _ => anyhow::bail!("snapshot is not a captured image"),
        }
    }
}
impl Drop for SnapshotBuffer {
    fn drop(&mut self) {
        self.cell
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .released = true;
    }
}
fn check_open(state: &State) -> io::Result<()> {
    if state.shutdown_started {
        Err(io::Error::other("snapshot transfer is closing"))
    } else {
        state.report.complete().map_err(io::Error::other)
    }
}
impl AsyncRead for SnapshotBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let cell = &self.cell;
        let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
        check_open(&state)?;
        if state.pending.is_none() {
            self.owner.check()?;
        }
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| !matches!(pending.kind, Kind::Read))
            || state
                .completion
                .as_ref()
                .is_some_and(|value| !matches!(value, Completion::Read { .. }))
        {
            return Poll::Ready(Err(io::Error::other(
                "different snapshot operation pending",
            )));
        }
        if state.pending.is_none() && state.completion.is_none() {
            let backing = cell.backing.clone();
            let position = state.position;
            let count = buffer.remaining().min(WORKSPACE);
            cell.spawn(&mut state, Kind::Read, &self.owner.failed, move || {
                let mut bytes = vec![0; count];
                let count = match backing.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
                    Some(Backing::Receiving(spool)) => {
                        spool.seek(SeekFrom::Start(position))?;
                        spool.read(&mut bytes)?
                    }
                    Some(Backing::Captured(image)) => {
                        let mut reader = image.reader();
                        reader.seek(SeekFrom::Start(position))?;
                        reader.read(&mut bytes)?
                    }
                    None => return Err(io::Error::other("snapshot storage is closed")),
                };
                bytes.truncate(count);
                Ok(Completion::Read { bytes, offset: 0 })
            });
        }
        if cell.join(&mut state, cx, 0).is_pending() {
            return Poll::Pending;
        }
        state.report.complete().map_err(io::Error::other)?;
        let Some(Completion::Read { bytes, offset }) = state.completion.as_mut() else {
            unreachable!("read child outcome")
        };
        let count = (bytes.len() - *offset).min(buffer.remaining());
        buffer.put_slice(&bytes[*offset..*offset + count]);
        *offset += count;
        let done = *offset == bytes.len();
        state.position += count as u64;
        if done {
            state.completion.take();
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for SnapshotBuffer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        use sha2::Digest;
        let cell = &self.cell;
        let mut state = cell.state.lock().unwrap_or_else(|p| p.into_inner());
        check_open(&state)?;
        if state.pending.is_none() {
            self.owner.check()?;
        }
        if state.completion.is_some() {
            return Poll::Ready(Err(io::Error::other(
                "different snapshot operation pending",
            )));
        }
        if bytes.is_empty() && state.pending.is_none() {
            return Poll::Ready(Ok(0));
        }
        let count = bytes.len().min(WORKSPACE);
        let digest: [u8; 32] = sha2::Sha256::digest(&bytes[..count]).into();
        if let Some(pending) = &state.pending {
            if !matches!(&pending.kind, Kind::Write { count: original, digest: original_digest } if *original == count && *original_digest == digest)
            {
                return Poll::Ready(Err(io::Error::other(
                    "different snapshot operation pending",
                )));
            }
        } else {
            if state
                .position
                .checked_add(count as u64)
                .is_none_or(|end| end > cell.limit)
            {
                return Poll::Ready(Err(io::Error::other("snapshot exceeds byte limit")));
            }
            let bytes = bytes[..count].to_vec();
            let backing = cell.backing.clone();
            let position = state.position;
            let length = cell.length.clone();
            cell.spawn(
                &mut state,
                Kind::Write { count, digest },
                &self.owner.failed,
                move || {
                    let mut backing = backing.lock().unwrap_or_else(|p| p.into_inner());
                    let Some(Backing::Receiving(spool)) = backing.as_mut() else {
                        return Err(io::Error::other("snapshot is not writable"));
                    };
                    spool.seek(SeekFrom::Start(position))?;
                    let count = spool.write(&bytes)?;
                    length.store(spool.len(), Ordering::Release);
                    Ok(Completion::Write(count))
                },
            );
        }
        if cell.join(&mut state, cx, 0).is_pending() {
            return Poll::Pending;
        }
        state.report.complete().map_err(io::Error::other)?;
        let Some(Completion::Write(count)) = state.completion.take() else {
            unreachable!("write child outcome")
        };
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.shutdown_done {
            return Poll::Ready(state.report.complete().map_err(io::Error::other));
        }
        self.cell
            .flush(&mut state, cx, 0, &self.owner.failed)
            .map(|result| result.map_err(io::Error::other))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
        self.cell
            .shutdown(&mut state, cx, 0, &self.owner.failed)
            .map(|result| result.map_err(io::Error::other))
    }
}
impl AsyncSeek for SnapshotBuffer {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let mut state = self.cell.state.lock().unwrap_or_else(|p| p.into_inner());
        check_open(&state)?;
        self.owner.check()?;
        if state.pending.is_some() || state.completion.is_some() {
            return Err(io::Error::other("snapshot operation still pending"));
        }
        let position = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(state.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.len()) + i128::from(value),
        };
        if position < 0 || position > i128::from(self.len()) {
            return Err(io::Error::other("snapshot seek outside existing stream"));
        }
        state.position = position as u64;
        Ok(())
    }
    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self
            .cell
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .position))
    }
}

#[cfg(test)]
#[path = "snapshot_buffer_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "snapshot_buffer_startup_report_tests.rs"]
mod startup_report_tests;

#[cfg(test)]
#[path = "application_source_custody_tests.rs"]
mod application_source_custody_tests;
