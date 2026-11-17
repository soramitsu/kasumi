//! A bounded table of blocking children whose exact handles belong to an
//! installed owner, never to the caller awaiting them. A caller that is
//! cancelled or times out gives up only its claim on the output: the child
//! still runs to its end inside the owner, and a panic, or a failure that no
//! caller received, stays in the owner's typed drain report instead of
//! disappearing with a dropped handle.
use kasumi_types::drain::{DrainReport, DrainResult};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll, Waker},
};
use tokio::{
    sync::oneshot,
    task::{JoinError, JoinHandle},
};

/// How a child that did not produce its value classifies itself.
pub enum ChildFailure<E> {
    /// The child was told to stop: cancellation, an expired deadline, a known
    /// conflict that changed nothing. An ordinary reply and never drain
    /// evidence, even when no caller receives it.
    Stopped(E),
    /// The child's own failure. It is the caller's ordinary error when the
    /// caller receives it, and drain evidence when no caller does.
    Failed(E),
}

/// Why a table started nothing.
#[derive(Debug, PartialEq, Eq)]
pub enum ChildRefused {
    /// Every slot holds a running child or retained evidence.
    Full,
    /// The process's final drain sealed the table.
    Sealed,
}
impl fmt::Display for ChildRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Full => "blocking child registry is full",
            Self::Sealed => "the process is exiting; no blocking child is admitted",
        })
    }
}
impl std::error::Error for ChildRefused {}

/// The child ended without an output: it panicked, or its runtime discarded
/// it unrun. The owner's drain report retains the original join error.
#[derive(Debug)]
pub struct ChildLost;
impl fmt::Display for ChildLost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("blocking child ended without an output")
    }
}
impl std::error::Error for ChildLost {}

/// Destroy an output that no caller claims any more and keep only its failure.
fn unclaimed<T, E: Into<anyhow::Error>>(
    output: Result<T, ChildFailure<E>>,
) -> Option<anyhow::Error> {
    match output {
        Err(ChildFailure::Failed(error)) => Some(error.into()),
        Ok(_) | Err(ChildFailure::Stopped(_)) => None,
    }
}

struct Slot {
    // The child returns the failure of an output it could not deliver; a
    // delivered output, and everything it retains, travels to the caller.
    child: Option<JoinHandle<Option<anyhow::Error>>>,
    // A caller still claims this child's output. A handle wakes only its
    // latest poller, so that caller alone joins it; a drain waits to be told.
    claimed: bool,
    // The report keeps this slot's one failure. The slot is never reused, so
    // no later child can displace that evidence or share its position.
    failed: bool,
}
struct State {
    slots: Box<[Slot]>,
    report: DrainReport,
    // The one draining waiter, woken when a caller joins or leaves its child.
    drain: Option<Waker>,
    // A child accepted after the process's final drain would be dropped with
    // the runtime, its outcome unobserved.
    sealed: bool,
}
impl State {
    fn fail(&mut self, component: &'static str, index: usize, error: anyhow::Error) {
        self.slots[index].failed = true;
        self.report.record(component, index, error);
    }

    /// The exact handle returned Ready: record its terminal outcome at once.
    fn joined(
        &mut self,
        component: &'static str,
        index: usize,
        result: Result<Option<anyhow::Error>, JoinError>,
    ) {
        let slot = &mut self.slots[index];
        slot.child = None;
        slot.claimed = false;
        let failure = match result {
            Ok(undelivered) => undelivered,
            Err(error) => Some(error.into()),
        };
        if let Some(error) = failure {
            self.fail(component, index, error);
        }
    }
}

/// Owned by the resource whose blocking work it runs: a disk, a node's memory
/// core. `drain` joins every accepted child in place and may be cancelled and
/// repeated; it reports the same original evidence each time.
pub struct BlockingChildren {
    component: &'static str,
    state: Mutex<State>,
    // One drain waits at a time, so `State::drain` names that one waiter.
    draining: tokio::sync::Mutex<()>,
}
impl BlockingChildren {
    /// The table's one allocation, for an owner that funds its exact backing.
    pub fn required_bytes(capacity: usize) -> Option<u64> {
        u64::try_from(std::mem::size_of::<Slot>())
            .ok()?
            .checked_mul(u64::try_from(capacity).ok()?)
    }

    /// `capacity` bounds running children and retained failures together.
    /// `component` names this owner in its drain issues.
    pub fn new(component: &'static str, capacity: usize) -> anyhow::Result<Self> {
        anyhow::ensure!(capacity > 0, "blocking child registry is empty");
        let mut slots = Vec::new();
        slots.try_reserve_exact(capacity)?;
        slots.resize_with(capacity, || Slot {
            child: None,
            claimed: false,
            failed: false,
        });
        let children = Self {
            component,
            state: Mutex::new(State {
                slots: slots.into_boxed_slice(),
                report: DrainReport::default(),
                drain: None,
                sealed: false,
            }),
            draining: tokio::sync::Mutex::new(()),
        };
        // First-use allocation of a lazily created native mutex belongs to
        // this constructor, not to the first child's dispatch or drain.
        drop(children.state());
        drop(children.draining.try_lock());
        Ok(children)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Join the children no caller claims. With a context every unfinished
    /// one wakes it; without, only finished handles are polled, so a draining
    /// waiter's registration is never replaced. Returns how many children
    /// remain, claimed ones included.
    fn settle(&self, state: &mut State, mut cx: Option<&mut Context<'_>>) -> usize {
        let mut running = 0;
        for index in 0..state.slots.len() {
            let slot = &mut state.slots[index];
            let Some(child) = slot.child.as_mut() else {
                continue;
            };
            let joined = match cx.as_deref_mut() {
                _ if slot.claimed => Poll::Pending,
                Some(cx) => Pin::new(child).poll(cx),
                None if child.is_finished() => {
                    Pin::new(child).poll(&mut Context::from_waker(Waker::noop()))
                }
                None => Poll::Pending,
            };
            match joined {
                Poll::Ready(result) => state.joined(self.component, index, result),
                Poll::Pending => running += 1,
            }
        }
        running
    }

    /// Run `run` on a blocking child this owner retains. A full or sealed
    /// table starts nothing and consumes nothing.
    pub fn start<T, E>(
        &self,
        run: impl FnOnce() -> Result<T, ChildFailure<E>> + Send + 'static,
    ) -> Result<Call<'_, T, E>, ChildRefused>
    where
        T: Send + 'static,
        E: Into<anyhow::Error> + Send + 'static,
    {
        let mut state = self.state();
        if state.sealed {
            return Err(ChildRefused::Sealed);
        }
        self.settle(&mut state, None);
        let index = state
            .slots
            .iter()
            .position(|slot| slot.child.is_none() && !slot.failed)
            .ok_or(ChildRefused::Full)?;
        let (deliver, output) = oneshot::channel();
        // Installed under the table's lock: no drain can observe an accepted
        // child before its exact handle is in custody.
        state.slots[index] = Slot {
            child: Some(tokio::task::spawn_blocking(move || {
                // A caller that already left cannot take the output. The child
                // destroys it here, so nothing it retains (a charge, a work
                // registration) waits for a drain, and keeps its failure.
                deliver.send(run()).err().and_then(unclaimed)
            })),
            claimed: true,
            failed: false,
        };
        Ok(Call {
            children: self,
            slot: index,
            joined: false,
            output,
        })
    }

    /// Refuse every later child. Only a process's final drain seals: a child
    /// accepted after that drain's census would be dropped with the runtime.
    pub fn seal(&self) {
        self.state().sealed = true;
    }

    /// Children still running, whether or not a caller awaits them.
    pub fn running(&self) -> usize {
        let mut state = self.state();
        self.settle(&mut state, None)
    }

    /// Join every accepted child. One that a caller still awaits is joined by
    /// that caller, which then wakes this drain. Admission stays open: a child
    /// accepted after this returns belongs to a later drain. Cancellation
    /// leaves every handle and every recorded outcome in this owner.
    pub async fn drain(&self) -> DrainResult {
        let _one = self.draining.lock().await;
        std::future::poll_fn(|cx| {
            let mut state = self.state();
            if self.settle(&mut state, Some(cx)) > 0 {
                state.drain = Some(cx.waker().clone());
                return Poll::Pending;
            }
            state.drain = None;
            Poll::Ready(state.report.complete())
        })
        .await
    }
}

/// One caller's claim on its child's output. Dropping it gives up the claim,
/// never the child, which the owner's drain then joins.
pub struct Call<'a, T, E: Into<anyhow::Error>> {
    children: &'a BlockingChildren,
    slot: usize,
    joined: bool,
    output: oneshot::Receiver<Result<T, ChildFailure<E>>>,
}
impl<T, E: Into<anyhow::Error>> Call<'_, T, E> {
    /// Join the child in its owner's slot and take its own result, or
    /// `ChildLost` when it ended without one. The child has returned, and
    /// destroyed everything it captured, before this does.
    pub async fn wait(mut self) -> Result<Result<T, E>, ChildLost> {
        std::future::poll_fn(|cx| {
            let mut state = self.children.state();
            let child = state.slots[self.slot]
                .child
                .as_mut()
                .expect("a claimed child is joined only by its caller");
            let Poll::Ready(result) = Pin::new(child).poll(cx) else {
                return Poll::Pending;
            };
            self.joined = true;
            // A panic is nobody's ordinary outcome: the owner keeps it.
            let lost = result.is_err();
            state.joined(self.children.component, self.slot, result);
            let drain = state.drain.take();
            drop(state);
            if let Some(drain) = drain {
                drain.wake();
            }
            Poll::Ready(if lost { Err(ChildLost) } else { Ok(()) })
        })
        .await?;
        // The child delivered into this claim before it returned.
        let outcome = self.output.try_recv().map_err(|_| ChildLost)?;
        Ok(outcome.map_err(|failure| match failure {
            ChildFailure::Stopped(error) | ChildFailure::Failed(error) => error,
        }))
    }
}
impl<T, E: Into<anyhow::Error>> Drop for Call<'_, T, E> {
    fn drop(&mut self) {
        if self.joined {
            return;
        }
        // Refuse a later delivery, so the child destroys its own output, and
        // destroy one it already delivered here, outside the table's lock.
        self.output.close();
        let failure = self.output.try_recv().ok().and_then(unclaimed);
        let mut state = self.children.state();
        state.slots[self.slot].claimed = false;
        if let Some(error) = failure {
            state.fail(self.children.component, self.slot, error);
        }
        let drain = state.drain.take();
        drop(state);
        if let Some(drain) = drain {
            drain.wake();
        }
    }
}

#[cfg(test)]
#[path = "blocking_children_tests.rs"]
mod tests;
