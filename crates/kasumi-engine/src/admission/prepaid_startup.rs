//! Already paid typed startup terminals in the existing strong startup census.
use super::{CensusOwner, MemoryCore, next_generation};
use kasumi_types::{Error, ErrorCode, Result, SharedBudgetCharge};
use std::{
    alloc::Layout,
    any::{Any, TypeId},
    future::Future,
    marker::PhantomData,
    ptr::NonNull,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Closed recipe for actual typed backing. No arbitrary byte total or opaque
/// charge can be supplied to the installer. Counts come from the producer's
/// validated acquisition topology, and every constructor remains inert.
#[derive(Default)]
pub struct StartupBacking {
    bytes: u64,
}
impl StartupBacking {
    pub fn empty() -> Self {
        Self::default()
    }
    fn allocation(mut self, layout: Layout) -> anyhow::Result<Self> {
        if layout.size() != 0 {
            let bytes = u64::try_from(
                layout
                    .size()
                    .checked_next_power_of_two()
                    .ok_or_else(|| anyhow::anyhow!("startup backing layout overflow"))?,
            )?
            .checked_add(64)
            .ok_or_else(|| anyhow::anyhow!("startup backing quote overflow"))?;
            self.bytes = self
                .bytes
                .checked_add(bytes)
                .ok_or_else(|| anyhow::anyhow!("startup backing quote overflow"))?;
        }
        Ok(self)
    }
    pub fn array<T>(self, count: usize) -> anyhow::Result<Self> {
        self.allocation(Layout::array::<T>(count)?)
    }
    pub fn boxed<T>(self) -> anyhow::Result<Self> {
        self.allocation(Layout::new::<T>())
    }
    pub fn shared<T>(self) -> anyhow::Result<Self> {
        let (layout, _) = Layout::array::<usize>(2)?.extend(Layout::new::<T>())?;
        self.allocation(layout.pad_to_align())
    }
    pub fn string(self, value: &str) -> anyhow::Result<Self> {
        self.array::<u8>(value.len())
    }
    pub fn include(mut self, other: Self) -> anyhow::Result<Self> {
        self.bytes = self
            .bytes
            .checked_add(other.bytes)
            .ok_or_else(|| anyhow::anyhow!("startup backing quote overflow"))?;
        Ok(self)
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}
/// Trusted typed ownership producers. Implementations measure the actual
/// layout recipe and allocate only inert state using the supplied same-core
/// charge. No native/resource acquisition occurs until the accepted loan.
///
/// A retirement-ready value has explicitly disposed every acquired resource
/// and original diagnostic; Drop, a joined worker, or an opaque report alone
/// must never satisfy that contract. The production facade hides its value,
/// plan and implementation; no Any storage or owning error erasure is exposed.
pub trait StartupTerminal: Send + 'static {
    type Plan<'a>;
    type Output: Send + 'static;
    fn backing(plan: &Self::Plan<'_>) -> anyhow::Result<StartupBacking>;
    fn allocate(plan: Self::Plan<'_>, charge: SharedBudgetCharge) -> Self;
    fn begin(&mut self) -> bool;
    fn retirement_ready(&self) -> bool;
    /// Move only the same positively successful closed facade. Its resource
    /// and control aliases must retain the same original charge supplied to
    /// allocate; transfer is never a native-disposal or diagnostic-ack proof.
    fn claim_output(&mut self) -> Option<Self::Output>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupTerminalId {
    slot: usize,
    generation: u64,
}
impl StartupTerminalId {
    pub fn slot(self) -> usize {
        self.slot
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}
#[derive(Default)]
struct Worker {
    handle: Option<tokio::task::JoinHandle<()>>,
    original: Option<tokio::task::JoinError>,
    entered: bool,
    returned: bool,
    poll_panic: Option<Box<dyn Any + Send>>,
    factory_panic: Option<Box<dyn Any + Send>>,
    dispatch_error: Option<tokio::runtime::TryCurrentError>,
    dispatch_panic: Option<Box<dyn Any + Send>>,
    handle_disposal_entered: bool,
    handle_disposal_returned: bool,
    handle_disposal_panic: Option<Box<dyn Any + Send>>,
}
impl Worker {
    fn clean(&self) -> bool {
        self.returned
            && self.handle.is_none()
            && self.original.is_none()
            && self.poll_panic.is_none()
            && self.factory_panic.is_none()
            && self.dispatch_error.is_none()
            && self.dispatch_panic.is_none()
            && self.handle_disposal_returned
            && self.handle_disposal_panic.is_none()
    }
}
struct State<T: StartupTerminal> {
    value: Arc<tokio::sync::Mutex<T>>,
    worker: Arc<tokio::sync::Mutex<Worker>>,
    producer_started: AtomicBool,
    output_taken: AtomicBool,
    id: StartupTerminalId,
    core: Arc<MemoryCore>,
    // Last: the actual control and terminal backing precede the same charge.
    _charge: SharedBudgetCharge,
}
/// Closed strong ownership, with no Weak/raw/control or payload extraction.
pub struct PrepaidStartup<T: StartupTerminal> {
    inner: Option<Arc<State<T>>>,
}
impl<T: StartupTerminal> PrepaidStartup<T> {
    pub fn required_bytes(plan: &T::Plan<'_>) -> anyhow::Result<u64> {
        StartupBacking::empty()
            .shared::<State<T>>()?
            .shared::<tokio::sync::Mutex<T>>()?
            .shared::<tokio::sync::Mutex<Worker>>()?
            .include(T::backing(plan)?)?
            .bytes()
            .checked_add(SharedBudgetCharge::required_bytes::<super::Reservation>()?)
            .ok_or_else(|| anyhow::anyhow!("startup terminal quote overflow"))
    }
    fn state(&self) -> &State<T> {
        self.inner.as_deref().expect("live closed startup terminal")
    }
    pub fn id(&self) -> StartupTerminalId {
        self.state().id
    }
    // Nonowning exact control addresses for the existing allocator observer.
    // This helper neither clones an Arc nor exposes a production raw/Weak owner.
    #[cfg(test)]
    pub(crate) fn control_addresses(&self) -> [usize; 3] {
        fn allocation_address<U>(owner: &Arc<U>) -> usize {
            let (_, offset) = Layout::new::<[usize; 2]>()
                .extend(Layout::new::<U>())
                .expect("quoted concrete startup control layout");
            (Arc::as_ptr(owner) as usize) - offset
        }
        [
            allocation_address(self.inner.as_ref().expect("live startup owner")),
            allocation_address(&self.state().value),
            allocation_address(&self.state().worker),
        ]
    }
    pub fn with_report<R>(&self, inspect: impl for<'a> FnOnce(Option<&'a T>) -> R) -> R {
        match self.state().value.try_lock() {
            Ok(value) => inspect(Some(&value)),
            Err(_) => inspect(None),
        }
    }
    /// Claim before constructing the owned producer. All three actual controls were
    /// installed under the same quote; the guard precedes its charged handle.
    pub fn begin(&self) -> Result<StartupTerminalLoan<T>> {
        let mut value = self.state().value.clone().try_lock_owned().map_err(|_| {
            Error::new(ErrorCode::ResourceExhausted, "startup terminal is borrowed")
        })?;
        let worker = self.state().worker.clone().try_lock_owned().map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "startup worker slot is borrowed",
            )
        })?;
        if self
            .state()
            .producer_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
            || !value.begin()
        {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "startup terminal already entered",
            ));
        }
        Ok(StartupTerminalLoan {
            value,
            worker: Some(worker),
            owner: self.clone(),
        })
    }
    /// Cancellation leaves the exact handle and every joined original in this
    /// same installed cell. Join success supplies no native-disposal witness.
    pub async fn join_worker(&self) {
        let mut worker = self.state().worker.lock().await;
        std::future::poll_fn(|cx| {
            if worker.poll_panic.is_some() {
                return std::task::Poll::Ready(());
            }
            if worker.handle.is_some() {
                worker.entered = true;
            }
            let Some(handle) = worker.handle.as_mut() else {
                return std::task::Poll::Ready(());
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                std::pin::Pin::new(handle).poll(cx)
            }));
            match result {
                Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
                Ok(std::task::Poll::Ready(original)) => {
                    worker.original = original.err();
                    worker.returned = true;
                    worker.handle_disposal_entered = true;
                    let handle = worker.handle.take().expect("same returned worker handle");
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(handle))) {
                        Ok(()) => worker.handle_disposal_returned = true,
                        Err(original) => worker.handle_disposal_panic = Some(original),
                    }
                    std::task::Poll::Ready(())
                }
                Err(original) => {
                    worker.poll_panic = Some(original);
                    std::task::Poll::Ready(())
                }
            }
        })
        .await;
    }
    pub fn with_worker_error<R>(
        &self,
        inspect: impl for<'a> FnOnce(Option<&'a tokio::task::JoinError>) -> R,
    ) -> Option<R> {
        self.state()
            .worker
            .try_lock()
            .ok()
            .map(|worker| inspect(worker.original.as_ref()))
    }
    pub fn with_worker_poll_panic<R>(
        &self,
        inspect: impl for<'a> FnOnce(Option<&'a (dyn Any + Send)>) -> R,
    ) -> Option<R> {
        self.state()
            .worker
            .try_lock()
            .ok()
            .map(|worker| inspect(worker.poll_panic.as_deref()))
    }
    pub fn with_worker_report<R>(
        &self,
        inspect: impl for<'a> FnOnce(StartupWorkerReport<'a>) -> R,
    ) -> Option<R> {
        self.state()
            .worker
            .try_lock()
            .ok()
            .map(|worker| inspect(StartupWorkerReport { worker: &worker }))
    }
    /// One explicit supported typed custody handoff. The internal value guard
    /// never escapes; worker completion and actual handle destruction are
    /// independently positive before the named producer moves its output.
    pub async fn take_output(&self) -> Option<T::Output> {
        let mut value = self.state().value.lock().await;
        let worker = self.state().worker.try_lock().ok()?;
        if !worker.clean() || self.state().output_taken.load(Ordering::Acquire) {
            return None;
        }
        let output = value.claim_output()?;
        self.state().output_taken.store(true, Ordering::Release);
        Some(output)
    }
    /// Drop does not call this. Positive disposition removes only this exact
    /// generation; any original/unknown observation keeps the census owner.
    pub async fn retire_empty(&self) -> bool {
        let value = self.state().value.lock().await;
        if !value.retirement_ready() {
            return false;
        }
        let Ok(worker) = self.state().worker.try_lock() else {
            return false;
        };
        if !worker.clean() {
            return false;
        }
        let retired = {
            let mut census = self
                .state()
                .core
                .startups
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let Some(slot) = census.slots.get_mut(self.id().slot) else {
                return false;
            };
            if slot.generation != self.id().generation {
                return false;
            }
            let Some(CensusOwner::Terminal(owner)) = slot.owner.as_ref() else {
                return false;
            };
            if !owner.same::<T>(self) {
                return false;
            }
            slot.reserved = false;
            slot.owner.take()
        };
        drop(worker);
        drop(value);
        drop(retired);
        true
    }
    fn erased(&self) -> ErasedTerminal {
        let pointer = Arc::into_raw(self.inner.as_ref().expect("live terminal").clone()).cast_mut();
        ErasedTerminal {
            pointer: NonNull::new(pointer.cast()).unwrap(),
            operations: &Typed::<T>::OPERATIONS,
        }
    }
}
impl<T: StartupTerminal> Clone for PrepaidStartup<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Some(self.inner.as_ref().expect("live terminal").clone()),
        }
    }
}
impl<T: StartupTerminal> Drop for PrepaidStartup<T> {
    fn drop(&mut self) {
        drop(Arc::into_inner(self.inner.take().expect("live terminal")));
    }
}
/// One nonclone admitted producer loan. The original value guard always drops
/// before its same charged owner, including cancellation and last alias drop.
pub struct StartupTerminalLoan<T: StartupTerminal> {
    value: tokio::sync::OwnedMutexGuard<T>,
    worker: Option<tokio::sync::OwnedMutexGuard<Worker>>,
    owner: PrepaidStartup<T>,
}
impl<T: StartupTerminal> std::ops::Deref for StartupTerminalLoan<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}
impl<T: StartupTerminal> std::ops::DerefMut for StartupTerminalLoan<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.value
    }
}
impl<T: StartupTerminal> StartupTerminalLoan<T> {
    pub fn id(&self) -> StartupTerminalId {
        self.owner.id()
    }
    /// The producer factory is a nonowning function pointer; its concrete
    /// future is formed only after this one nonclone admitted loan exists.
    pub fn spawn<A, F>(mut self, make: fn(Self, A) -> F, arguments: A) -> PrepaidStartup<T>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut worker = self.worker.take().expect("same admitted worker guard");
        let owner = self.owner.clone();
        let runtime = match tokio::runtime::Handle::try_current() {
            Ok(runtime) => runtime,
            Err(original) => {
                worker.dispatch_error = Some(original);
                // The unused admitted producer loan remains sticky. No factory
                // is entered, and no absence of native owners is inferred.
                drop(self);
                drop(arguments);
                drop(worker);
                return owner;
            }
        };
        let future = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            make(self, arguments)
        })) {
            Ok(future) => future,
            Err(original) => {
                worker.factory_panic = Some(original);
                drop(worker);
                return owner;
            }
        };
        let handle = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.spawn(future)
        })) {
            Ok(handle) => handle,
            Err(original) => {
                worker.dispatch_panic = Some(original);
                drop(worker);
                return owner;
            }
        };
        // Only this once-consumed loan can publish a worker. No independent
        // owning-handle installation API or reusable producer gate escapes.
        worker.handle = Some(handle);
        drop(worker);
        owner
    }
}
pub struct StartupWorkerReport<'a> {
    worker: &'a Worker,
}
impl<'a> StartupWorkerReport<'a> {
    pub fn entered(&self) -> bool {
        self.worker.entered
    }
    pub fn returned(&self) -> bool {
        self.worker.returned
    }
    pub fn handle_retained(&self) -> bool {
        self.worker.handle.is_some()
    }
    pub fn original(&self) -> Option<&'a tokio::task::JoinError> {
        self.worker.original.as_ref()
    }
    pub fn dispatch_error(&self) -> Option<&'a tokio::runtime::TryCurrentError> {
        self.worker.dispatch_error.as_ref()
    }
    pub fn handle_disposal_entered(&self) -> bool {
        self.worker.handle_disposal_entered
    }
    pub fn handle_disposal_returned(&self) -> bool {
        self.worker.handle_disposal_returned
    }
    pub fn handle_disposal_panic(&self) -> Option<&'a (dyn Any + Send)> {
        self.worker.handle_disposal_panic.as_deref()
    }
    pub fn dispatch_panic(&self) -> Option<&'a (dyn Any + Send)> {
        self.worker.dispatch_panic.as_deref()
    }
    pub fn factory_panic(&self) -> Option<&'a (dyn Any + Send)> {
        self.worker.factory_panic.as_deref()
    }
    pub fn poll_panic(&self) -> Option<&'a (dyn Any + Send)> {
        self.worker.poll_panic.as_deref()
    }
}
struct Operations {
    clone: unsafe fn(NonNull<()>),
    retire: unsafe fn(NonNull<()>),
    type_id: fn() -> TypeId,
}
struct Typed<T>(PhantomData<T>);
impl<T: StartupTerminal> Typed<T> {
    const OPERATIONS: Operations = Operations {
        clone: clone::<T>,
        retire: retire::<T>,
        type_id: TypeId::of::<T>,
    };
}
/// Only the census holds this private monomorphized control handle. The whole
/// terminal remains in its original sized allocation; no erased payload Box.
pub(super) struct ErasedTerminal {
    pointer: NonNull<()>,
    operations: &'static Operations,
}
// SAFETY: State<T> contains a Tokio mutex around Send T; every private pointer
// retains its own strong count and immutable paired monomorphized operations.
unsafe impl Send for ErasedTerminal {}
unsafe impl Sync for ErasedTerminal {}
impl ErasedTerminal {
    fn typed<T: StartupTerminal>(&self) -> Option<PrepaidStartup<T>> {
        if (self.operations.type_id)() != TypeId::of::<T>() {
            return None;
        }
        // SAFETY: the private operations type check matches the original State<T>.
        unsafe {
            (self.operations.clone)(self.pointer);
        }
        Some(PrepaidStartup {
            inner: Some(unsafe { Arc::from_raw(self.pointer.as_ptr().cast::<State<T>>()) }),
        })
    }
    fn same<T: StartupTerminal>(&self, handle: &PrepaidStartup<T>) -> bool {
        (self.operations.type_id)() == TypeId::of::<T>()
            && self.pointer.as_ptr()
                == Arc::as_ptr(handle.inner.as_ref().expect("live terminal"))
                    .cast_mut()
                    .cast()
    }
}
impl Drop for ErasedTerminal {
    fn drop(&mut self) {
        unsafe {
            (self.operations.retire)(self.pointer);
        }
    }
}
unsafe fn clone<T: StartupTerminal>(pointer: NonNull<()>) {
    unsafe {
        Arc::increment_strong_count(pointer.as_ptr().cast::<State<T>>());
    }
}
unsafe fn retire<T: StartupTerminal>(pointer: NonNull<()>) {
    drop(Arc::into_inner(unsafe {
        Arc::from_raw(pointer.as_ptr().cast::<State<T>>())
    }));
}
/// Exact pre-effect seat in the existing max_startup_scopes inventory. It
/// holds no second grant and returns an unused seat on inert admission failure.
pub struct PreparedStartup<T: StartupTerminal> {
    core: Arc<MemoryCore>,
    id: StartupTerminalId,
    installed: bool,
    _terminal: PhantomData<fn() -> T>,
}
impl<T: StartupTerminal> PreparedStartup<T> {
    pub fn install(mut self, plan: T::Plan<'_>) -> anyhow::Result<PrepaidStartup<T>> {
        let bytes = PrepaidStartup::<T>::required_bytes(&plan)?;
        // The exact census Core mints this real resident reservation. There is
        // no public foreign-core/opaque-charge input or second resource grant.
        let charge = SharedBudgetCharge::new(self.core.reserve_resident(bytes)?);
        let value = T::allocate(plan, charge.clone());
        let owner = PrepaidStartup {
            inner: Some(Arc::new(State {
                value: Arc::new(tokio::sync::Mutex::new(value)),
                worker: Arc::new(tokio::sync::Mutex::new(Worker::default())),
                producer_started: AtomicBool::new(false),
                output_taken: AtomicBool::new(false),
                id: self.id,
                core: self.core.clone(),
                _charge: charge,
            })),
        };
        let mut census = self.core.startups.lock().unwrap_or_else(|p| p.into_inner());
        let slot = &mut census.slots[self.id.slot];
        assert!(slot.reserved && slot.generation == self.id.generation && slot.owner.is_none());
        slot.owner = Some(CensusOwner::Terminal(owner.erased()));
        self.installed = true;
        drop(census);
        Ok(owner)
    }
}
impl<T: StartupTerminal> Drop for PreparedStartup<T> {
    fn drop(&mut self) {
        if self.installed {
            return;
        }
        let mut census = self.core.startups.lock().unwrap_or_else(|p| p.into_inner());
        let slot = &mut census.slots[self.id.slot];
        if slot.generation == self.id.generation && slot.owner.is_none() {
            slot.reserved = false;
        }
    }
}
impl MemoryCore {
    pub fn prepare_prepaid_startup<T: StartupTerminal>(
        self: &Arc<Self>,
    ) -> Result<PreparedStartup<T>> {
        let mut census = self.startups.lock().unwrap_or_else(|p| p.into_inner());
        let slot = census
            .slots
            .iter()
            .position(|slot| !slot.reserved)
            .ok_or_else(|| {
                Error::new(ErrorCode::ResourceExhausted, "startup scope census is full")
            })?;
        let generation = next_generation()?;
        census.slots[slot].reserved = true;
        census.slots[slot].generation = generation;
        Ok(PreparedStartup {
            core: self.clone(),
            id: StartupTerminalId { slot, generation },
            installed: false,
            _terminal: PhantomData,
        })
    }
    pub fn prepaid_startup<T: StartupTerminal>(
        &self,
        id: StartupTerminalId,
    ) -> Option<PrepaidStartup<T>> {
        let census = self.startups.lock().unwrap_or_else(|p| p.into_inner());
        let slot = census.slots.get(id.slot)?;
        if slot.generation != id.generation {
            return None;
        }
        match slot.owner.as_ref()? {
            CensusOwner::Terminal(owner) => owner.typed(),
            CensusOwner::Scope(_) => None,
        }
    }
    pub fn prepaid_startup_at<T: StartupTerminal>(
        &self,
        index: usize,
    ) -> Option<PrepaidStartup<T>> {
        let census = self.startups.lock().unwrap_or_else(|p| p.into_inner());
        match census.slots.get(index)?.owner.as_ref()? {
            CensusOwner::Terminal(owner) => owner.typed(),
            CensusOwner::Scope(_) => None,
        }
    }
}

#[cfg(test)]
#[path = "prepaid_startup_tests.rs"]
mod tests;
