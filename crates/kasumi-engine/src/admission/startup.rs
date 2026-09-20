//! Fixed admission and ownership foundation for one startup lifecycle.
//!
//! This module deliberately has no adapter for an existing DrainFailure,
//! NodeRuntime, or Resources. Those owners must first provide measured backing,
//! fixed diagnostics, and independently retained acquisition/cleanup state.
use super::{MemoryCore, Reservation, allocation_bytes, arc_bytes};
use kasumi_types::{Error, ErrorCode, Result, drain::DrainCompletion};
use std::{
    any::Any,
    error::Error as StdError,
    marker::PhantomData,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
};

/// Exact number of resource/terminal-observation cells derived from the
/// validated operation configuration. Memory admission bounds its allocation;
/// this is not a second implicit policy or a diagnostic-payload allowance.
#[derive(Clone, Copy, Debug)]
pub struct StartupSpec {
    pub resources: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupScopeId {
    pub slot: usize,
    pub generation: u64,
}

struct CensusSlot {
    generation: u64,
    reserved: bool,
    owner: Option<Arc<StartupScope>>,
}
pub(super) struct Census {
    next: u64,
    slots: Box<[CensusSlot]>,
}
impl Census {
    pub(super) fn required_bytes(capacity: usize) -> anyhow::Result<u64> {
        allocation_bytes::<CensusSlot>(capacity)
    }
    pub(super) fn allocate(capacity: usize) -> anyhow::Result<Self> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity)?;
        slots.resize_with(capacity, || CensusSlot {
            generation: 0,
            reserved: false,
            owner: None,
        });
        Ok(Self {
            next: 0,
            slots: slots.into_boxed_slice(),
        })
    }
}
struct CensusTicket {
    core: Arc<MemoryCore>,
    id: StartupScopeId,
    published: bool,
}
impl Drop for CensusTicket {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let mut census = self.core.startups.lock().unwrap_or_else(|p| p.into_inner());
        let slot = &mut census.slots[self.id.slot];
        if slot.generation == self.id.generation && slot.owner.is_none() {
            slot.reserved = false;
        }
    }
}

/// An adapter's inert allocation and retained drain state. Implementations are
/// trusted ownership code, never constructed from wire-provided byte assertions.
///
/// `backing_bytes` validates its typed plan and measures every owned heap/future/
/// result/diagnostic allocation beyond Self. `allocate` is inert: no child or
/// physical ownership acquisition may start until the returned resource has been
/// installed and activate() enters its retained cell. Every actual acquisition
/// must itself use a retained result owner; a supervisor future is not that owner.
///
/// poll_drain must keep actual handles/results in Self through Pending, Retained,
/// and repeated calls. Complete means all children/backing/physical claims are
/// positively drained and dropping Self requires no fallible physical cleanup.
/// Original diagnostics remain in Self and are borrowed through the report.
/// Arbitrary anyhow/JoinError heap payloads without an admitted originating owner
/// do not satisfy this contract and must remain Retained, never be bridged here.
pub trait StartupResource: Send + Unpin + 'static {
    type Plan;
    fn backing_bytes(plan: &Self::Plan) -> anyhow::Result<u64>;
    fn allocate(plan: Self::Plan) -> Self;
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<DrainCompletion>;
    fn visit_diagnostics(&self, visit: &mut dyn FnMut(&(dyn StdError + 'static)));
}
trait ErasedResource: Send {
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<DrainCompletion>;
    fn visit_diagnostics(&self, visit: &mut dyn FnMut(&(dyn StdError + 'static)));
}
impl<R: StartupResource> ErasedResource for R {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<DrainCompletion> {
        StartupResource::poll_drain(self, cx)
    }
    fn visit_diagnostics(&self, visit: &mut dyn FnMut(&(dyn StdError + 'static))) {
        StartupResource::visit_diagnostics(self, visit)
    }
}

struct OwnedResource {
    // An inert constructor or direct poll panic never removes these owners.
    resource: Option<Box<dyn ErasedResource>>,
    poisoned: Option<Box<dyn Any + Send>>,
    complete: bool,
    // Declaration order keeps the lease through every resource/diagnostic drop.
    _charge: Reservation,
}
enum Cell {
    Empty,
    Preparing,
    Owned(OwnedResource),
}
struct ScopeState {
    closing: bool,
    cells: Box<[Cell]>,
}

// Actual resources receive this pre-admitted proxy waker, never a drain
// caller's potentially large task allocation. Cancellation clears only the
// current waiter, leaving the resource's original proxy and handle in place.
#[derive(Default)]
struct DrainWake {
    waiter: Mutex<Option<Waker>>,
}
impl Wake for DrainWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let waiter = self
            .waiter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .cloned();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}
struct ClearWaiter<'a>(&'a DrainWake);
impl Drop for ClearWaiter<'_> {
    fn drop(&mut self) {
        self.0
            .waiter
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
    }
}

pub struct StartupScope {
    id: StartupScopeId,
    state: Mutex<ScopeState>,
    draining: tokio::sync::Mutex<()>,
    wake: Arc<DrainWake>,
    // The explicit core -> scope -> reservation -> core custody cycle is broken
    // only by retire_completed. Retained cells can never disappear on caller Drop.
    core: Arc<MemoryCore>,
    _charge: Reservation,
}
impl StartupScope {
    pub fn required_bytes(spec: StartupSpec) -> anyhow::Result<u64> {
        anyhow::ensure!(spec.resources > 0, "startup resource census is empty");
        arc_bytes::<Self>()?
            .checked_add(allocation_bytes::<Cell>(spec.resources)?)
            .and_then(|bytes| bytes.checked_add(arc_bytes::<DrainWake>().ok()?))
            .ok_or_else(|| anyhow::anyhow!("startup scope allocation overflow"))
    }
    pub fn id(&self) -> StartupScopeId {
        self.id
    }
    pub fn report(self: &Arc<Self>) -> StartupReport {
        StartupReport {
            scope: self.clone(),
        }
    }
    /// Reserve the actual adapter layout before its inert builder runs. There is
    /// no arbitrary public byte argument and no fallback to a process governor.
    pub fn prepare<R: StartupResource>(
        self: &Arc<Self>,
        plan: R::Plan,
    ) -> Result<ResourceHandle<R>> {
        let bytes = allocation_bytes::<R>(1)
            .and_then(|inline| {
                inline
                    .checked_add(R::backing_bytes(&plan)?)
                    .ok_or_else(|| anyhow::anyhow!("startup resource allocation overflow"))
            })
            .map_err(|_| {
                Error::new(
                    ErrorCode::ResourceExhausted,
                    "startup resource layout invalid",
                )
            })?;
        let index = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.closing {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    "startup scope is closing",
                ));
            }
            let index = state
                .cells
                .iter()
                .position(|cell| matches!(cell, Cell::Empty))
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::ResourceExhausted,
                        "startup resource census is full",
                    )
                })?;
            state.cells[index] = Cell::Preparing;
            index
        };
        let charge = match self.core.reserve_resident(bytes) {
            Ok(charge) => charge,
            Err(error) => {
                self.state.lock().unwrap_or_else(|p| p.into_inner()).cells[index] = Cell::Empty;
                self.wake.wake_by_ref();
                return Err(error);
            }
        };
        let allocated = catch_unwind(AssertUnwindSafe(|| {
            Box::new(R::allocate(plan)) as Box<dyn ErasedResource>
        }));
        let (resource, poisoned) = match allocated {
            Ok(resource) => (Some(resource), None),
            Err(payload) => (None, Some(payload)),
        };
        let allocation_panicked = poisoned.is_some();
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.cells[index] = Cell::Owned(OwnedResource {
                resource,
                poisoned,
                complete: false,
                _charge: charge,
            });
        }
        self.wake.wake_by_ref();
        if allocation_panicked {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "startup allocation panicked; exact payload retained",
            ));
        }
        Ok(ResourceHandle {
            scope: self.clone(),
            index,
            _resource: PhantomData,
        })
    }
    fn poll_drain(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let mut pending = false;
        for cell in &mut state.cells {
            match cell {
                Cell::Empty => {}
                Cell::Preparing => pending = true,
                Cell::Owned(owner) if owner.complete || owner.poisoned.is_some() => {}
                Cell::Owned(owner) => {
                    let resource = owner
                        .resource
                        .as_mut()
                        .expect("non-poisoned allocated resource");
                    match catch_unwind(AssertUnwindSafe(|| resource.poll_drain(cx))) {
                        Ok(Poll::Pending) => pending = true,
                        Ok(Poll::Ready(DrainCompletion::Complete)) => owner.complete = true,
                        Ok(Poll::Ready(DrainCompletion::Retained)) => {}
                        Err(payload) => owner.poisoned = Some(payload),
                    }
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
    /// Close new resource admission before the first suspension. All actual
    /// resources stay in their cells if this drain future is canceled.
    pub async fn drain(self: &Arc<Self>) -> StartupReport {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).closing = true;
        let _serial = self.draining.lock().await;
        let _clear_waiter = ClearWaiter(&self.wake);
        let resource_waker = Waker::from(self.wake.clone());
        std::future::poll_fn(|cx| {
            {
                let mut waiter = self.wake.waiter.lock().unwrap_or_else(|p| p.into_inner());
                if waiter.as_ref().is_none_or(|old| !old.will_wake(cx.waker())) {
                    *waiter = Some(cx.waker().clone());
                }
            }
            self.poll_drain(&mut Context::from_waker(&resource_waker))
        })
        .await;
        let report = self.report();
        if report.completion() == DrainCompletion::Complete {
            self.retire_completed();
        }
        report
    }
    fn retire_completed(&self) {
        let retired = {
            let mut census = self.core.startups.lock().unwrap_or_else(|p| p.into_inner());
            let slot = &mut census.slots[self.id.slot];
            if slot.generation != self.id.generation {
                return;
            }
            slot.reserved = false;
            slot.owner.take()
        };
        // Never drop a resource/report charge while the census lock is held.
        drop(retired);
    }
}

pub struct ResourceHandle<R> {
    scope: Arc<StartupScope>,
    index: usize,
    _resource: PhantomData<fn() -> R>,
}
impl<R: StartupResource> ResourceHandle<R> {
    /// Enter only the already installed actual resource. The callback is short,
    /// synchronous, and must not recursively acquire this scope's state lock.
    pub fn activate(&self, activate: impl FnOnce(&mut R)) -> Result<()> {
        let mut state = self.scope.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.closing {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "startup scope is closing",
            ));
        }
        let Cell::Owned(owner) = &mut state.cells[self.index] else {
            unreachable!("published resource handle")
        };
        if owner.poisoned.is_some() {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "startup resource poll is poisoned",
            ));
        }
        let resource = owner
            .resource
            .as_mut()
            .expect("allocated resource")
            .as_any_mut()
            .downcast_mut::<R>()
            .expect("typed resource handle");
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| activate(resource))) {
            owner.poisoned = Some(payload);
            return Err(Error::new(
                ErrorCode::Unavailable,
                "startup activation panicked; exact owner retained",
            ));
        }
        Ok(())
    }
}

/// A shared view, not a Vec of cloned issues. Every clone keeps the exact scope,
/// each original diagnostic, and all of their original charges alive. Borrowed
/// observations cannot accidentally release their diagnostic's owner lease.
#[derive(Clone)]
pub struct StartupReport {
    scope: Arc<StartupScope>,
}
pub enum StartupObservation<'a> {
    Diagnostic {
        resource: usize,
        error: &'a (dyn StdError + 'static),
    },
    /// Opaque panic payloads have no proven diagnostic envelope. Their original
    /// owner and payload are retained and are never reported as Complete.
    PollPanic {
        resource: usize,
        payload: &'a (dyn Any + Send),
    },
}
impl StartupReport {
    pub fn completion(&self) -> DrainCompletion {
        let state = self.scope.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.closing
            && state.cells.iter().all(|cell| match cell {
                Cell::Empty => true,
                Cell::Preparing => false,
                Cell::Owned(owner) => owner.complete && owner.poisoned.is_none(),
            })
        {
            DrainCompletion::Complete
        } else {
            DrainCompletion::Retained
        }
    }
    pub fn visit(&self, mut visit: impl FnMut(StartupObservation<'_>)) {
        let state = self.scope.state.lock().unwrap_or_else(|p| p.into_inner());
        for (resource, cell) in state.cells.iter().enumerate() {
            if let Cell::Owned(owner) = cell {
                if let Some(inner) = owner.resource.as_ref() {
                    inner.visit_diagnostics(&mut |error| {
                        visit(StartupObservation::Diagnostic { resource, error })
                    });
                }
                if let Some(payload) = owner.poisoned.as_ref() {
                    visit(StartupObservation::PollPanic {
                        resource,
                        payload: payload.as_ref(),
                    });
                }
            }
        }
    }
}

impl MemoryCore {
    pub fn prepare_startup_scope(self: &Arc<Self>, spec: StartupSpec) -> Result<Arc<StartupScope>> {
        let bytes = StartupScope::required_bytes(spec).map_err(|_| {
            Error::new(ErrorCode::ResourceExhausted, "startup scope layout invalid")
        })?;
        let mut ticket = {
            let mut census = self.startups.lock().unwrap_or_else(|p| p.into_inner());
            let slot = census
                .slots
                .iter()
                .position(|slot| !slot.reserved)
                .ok_or_else(|| {
                    Error::new(ErrorCode::ResourceExhausted, "startup scope census is full")
                })?;
            let generation = census.next;
            census.next = generation.checked_add(1).ok_or_else(|| {
                Error::new(ErrorCode::Unavailable, "startup scope identity exhausted")
            })?;
            census.slots[slot].reserved = true;
            census.slots[slot].generation = generation;
            CensusTicket {
                core: self.clone(),
                id: StartupScopeId { slot, generation },
                published: false,
            }
        };
        let charge = self.reserve_resident(bytes)?;
        let mut cells = Vec::new();
        cells.try_reserve_exact(spec.resources).map_err(|_| {
            Error::new(
                ErrorCode::ResourceExhausted,
                "startup scope allocation failed",
            )
        })?;
        cells.resize_with(spec.resources, || Cell::Empty);
        let scope = Arc::new(StartupScope {
            id: ticket.id,
            state: Mutex::new(ScopeState {
                closing: false,
                cells: cells.into_boxed_slice(),
            }),
            draining: tokio::sync::Mutex::new(()),
            wake: Arc::new(DrainWake::default()),
            core: self.clone(),
            _charge: charge,
        });
        {
            let mut census = self.startups.lock().unwrap_or_else(|p| p.into_inner());
            census.slots[ticket.id.slot].owner = Some(scope.clone());
            ticket.published = true;
        }
        Ok(scope)
    }
    /// A bounded nonallocating lookup for an admitted shutdown traversal. This
    /// does not assert that a concurrently changing whole core has drained.
    pub fn startup_scope_at(&self, index: usize) -> Option<Arc<StartupScope>> {
        self.startups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .slots
            .get(index)
            .and_then(|slot| slot.owner.clone())
    }
    pub fn startup_scope_capacity(&self) -> usize {
        self.data.config.max_startup_scopes
    }
}

#[cfg(test)]
#[path = "startup_tests.rs"]
mod tests;
