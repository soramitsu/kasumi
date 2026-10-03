//! Scoped observation of one actual installed lease, never replacement funding.
use super::{MemoryCore, Reservation};
use std::{any::Any, cell::RefCell, sync::Arc};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    core: usize,
    slot: usize,
    id: u64,
}
impl Identity {
    fn of(reservation: &Reservation) -> Self {
        Self {
            core: Arc::as_ptr(&reservation.core) as usize,
            slot: reservation.slot,
            id: reservation.id,
        }
    }
}
struct State {
    core: usize,
    last: Option<Identity>,
    armed: Option<(Identity, Box<dyn Any + Send>)>,
    fired: bool,
}
thread_local! {
    static ACTIVE: RefCell<Option<State>> = const { RefCell::new(None) };
}

/// The fixture and producer run synchronously on this test's thread. No hook
/// state or callback crosses into another admission core or test thread.
pub(crate) struct Probe {
    core: usize,
}
impl Probe {
    pub(crate) fn begin(core: &Arc<MemoryCore>) -> Self {
        let core = Arc::as_ptr(core) as usize;
        ACTIVE.with(|active| {
            assert!(
                active.borrow().is_none(),
                "installed lease probe already active"
            );
            *active.borrow_mut() = Some(State {
                core,
                last: None,
                armed: None,
                fired: false,
            });
        });
        Self { core }
    }
    /// Called by SelectionPreparer before it queues or allocates anything: the
    /// last installed grant is the producer's actual native output buffer.
    pub(crate) fn arm_last(&self, payload: Box<dyn Any + Send>) {
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            let state = active.as_mut().expect("active installed lease probe");
            assert_eq!(state.core, self.core);
            assert!(state.armed.is_none() && !state.fired);
            state.armed = Some((
                state.last.expect("producer installed no actual lease"),
                payload,
            ));
        });
    }
    pub(crate) fn fired(&self) -> bool {
        ACTIVE.with(|active| {
            let active = active.borrow();
            let state = active.as_ref().expect("active installed lease probe");
            assert_eq!(state.core, self.core);
            state.fired
        })
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            let state = active
                .borrow_mut()
                .take()
                .expect("active installed lease probe");
            assert_eq!(state.core, self.core);
            drop(state);
        });
    }
}
pub(super) fn observe(reservation: &Reservation) {
    let _ = ACTIVE.try_with(|active| {
        let mut active = active.borrow_mut();
        if let Some(state) = active.as_mut() {
            let identity = Identity::of(reservation);
            if identity.core == state.core {
                state.last = Some(identity);
            }
        }
    });
}
pub(super) fn retired(reservation: &Reservation) {
    let payload = ACTIVE
        .try_with(|active| {
            let mut active = active.borrow_mut();
            let state = active.as_mut()?;
            if !state
                .armed
                .as_ref()
                .is_some_and(|(id, _)| *id == Identity::of(reservation))
            {
                return None;
            }
            state.fired = true;
            state.armed.take().map(|(_, payload)| payload)
        })
        .ok()
        .flatten();
    // The real ledger entry and mutex have already retired. The production
    // caller must still treat this callback panic as unknown custody; only this
    // fixture knows the deliberately injected post-retirement location.
    if let Some(payload) = payload {
        std::panic::resume_unwind(payload);
    }
}
