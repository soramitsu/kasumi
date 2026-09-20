//! Bounded, retained collectors for leadership checks and election rounds.
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::task::Context;
use std::task::Poll;

use tokio::sync::Mutex;

use crate::core::sm::tasks::Task;
use crate::core::sm::tasks::TaskError;
use crate::error::AuxiliaryShutdownError;
use crate::error::AuxiliaryTaskKind;
use crate::error::TaskCapacity;
use crate::type_config::alias::JoinErrorOf;
use crate::RaftTypeConfig;

pub(crate) struct Owner<C: RaftTypeConfig> {
    id: u64,
    kind: AuxiliaryTaskKind,
    pub(crate) task: Mutex<Option<Task<C>>>,
}

struct Inventory<C: RaftTypeConfig> {
    owners: Vec<Arc<Owner<C>>>,
    next_id: u64,
}

pub(crate) struct Registry<C: RaftTypeConfig> {
    limit: usize,
    inventory: StdMutex<Inventory<C>>,
}

impl<C: RaftTypeConfig> Registry<C> {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            inventory: StdMutex::new(Inventory {
                owners: Vec::with_capacity(limit),
                next_id: 0,
            }),
        }
    }

    fn poll_owner(owner: &Owner<C>, cx: &mut Context<'_>) -> Poll<Result<(), TaskError<C>>> {
        let Ok(mut task) = owner.task.try_lock() else {
            return Poll::Pending;
        };
        match task.as_mut() {
            Some(task) => task.poll_join(cx),
            None => Poll::Pending,
        }
    }

    fn reap(&self) {
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        self.inventory
            .lock()
            .unwrap()
            .owners
            .retain(|owner| !matches!(Self::poll_owner(owner, &mut cx), Poll::Ready(Ok(()))));
    }

    /// Leadership reads leave one slot exclusively available to vote rounds.
    /// The sole producer is RaftCore; no producer races the synchronous check.
    pub(crate) fn available(&self, kind: AuxiliaryTaskKind) -> Result<(), TaskCapacity> {
        self.reap();
        let inventory = self.inventory.lock().unwrap();
        let limit = if kind == AuxiliaryTaskKind::LeadershipRead {
            self.limit.saturating_sub(1)
        } else {
            self.limit
        };
        if inventory.owners.len() >= limit || inventory.next_id == u64::MAX {
            Err(TaskCapacity { limit, needed: 1 })
        } else {
            Ok(())
        }
    }

    pub(crate) fn reserve(&self, kind: AuxiliaryTaskKind) -> Result<Arc<Owner<C>>, TaskCapacity> {
        self.available(kind)?;
        let mut inventory = self.inventory.lock().unwrap();
        let id = inventory.next_id;
        inventory.next_id += 1;
        let owner = Arc::new(Owner {
            id,
            kind,
            task: Mutex::new(None),
        });
        inventory.owners.push(owner.clone());
        Ok(owner)
    }

    /// The event loop joins the actual handles in place; no monitor is spawned.
    pub(crate) async fn changed(&self) -> Result<(), TaskError<C>> {
        std::future::poll_fn(|cx| {
            let mut inventory = self.inventory.lock().unwrap();
            for (index, owner) in inventory.owners.iter().enumerate() {
                match Self::poll_owner(owner, cx) {
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        inventory.owners.remove(index);
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }

    /// Called after the producer core joins. Cancellation leaves every actual
    /// handle/result in its cell; every later child is joined despite failures.
    pub(crate) async fn shutdown(&self) -> Vec<AuxiliaryShutdownError<C::NodeId, JoinErrorOf<C>>> {
        let owners = self.inventory.lock().unwrap().owners.clone();
        let mut failures = Vec::new();
        for owner in owners {
            if let Some(task) = owner.task.lock().await.as_mut() {
                if let Err(error) = task.join().await {
                    failures.push(AuxiliaryShutdownError {
                        owner_id: owner.id,
                        kind: owner.kind,
                        error,
                    });
                }
            }
        }
        self.reap();
        self.inventory
            .lock()
            .unwrap()
            .owners
            .retain(|owner| owner.task.try_lock().map_or(true, |task| task.is_some()));
        failures
    }
}

#[cfg(all(test, not(feature = "singlethreaded")))]
#[path = "auxiliary_test.rs"]
mod tests;
