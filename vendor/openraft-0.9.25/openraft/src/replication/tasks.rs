//! Bounded custody for active and retired replication streams and snapshot senders.
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::task::Context;
use std::task::Poll;

use tokio::sync::Mutex;

use crate::core::sm::tasks::Task;
use crate::core::sm::tasks::TaskError;
use crate::error::ReplicationShutdownError;
use crate::error::TaskCapacity;
use crate::RaftTypeConfig;

pub(crate) struct Owner<C: RaftTypeConfig> {
    pub(crate) id: u64,
    pub(crate) target: C::NodeId,
    pub(crate) stream: Mutex<Option<Task<C>>>,
    pub(crate) snapshot: Arc<Mutex<Option<Task<C>>>>,
}

struct Inventory<C: RaftTypeConfig> {
    owners: Vec<Arc<Owner<C>>>,
    next_id: u64,
}

/// One fixed maximum counts active, retired and failed owners together. Each
/// owner has one stream cell and one reusable snapshot-sender cell.
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

    /// Admission is synchronous and never evicts an unresolved or failed owner.
    /// The sole producer is RaftCore, so a batch preflight cannot race another
    /// producer consuming its capacity before all replacements are published.
    pub(crate) fn available(&self, needed: usize) -> Result<(), TaskCapacity> {
        self.reap();
        let inventory = self.inventory.lock().unwrap();
        if needed > self.limit.saturating_sub(inventory.owners.len())
            || inventory.next_id.checked_add(needed as u64).is_none()
        {
            return Err(TaskCapacity {
                limit: self.limit,
                needed,
            });
        }
        Ok(())
    }

    pub(crate) fn reserve(&self, target: C::NodeId) -> Result<Arc<Owner<C>>, TaskCapacity> {
        self.available(1)?;
        let mut inventory = self.inventory.lock().unwrap();
        let id = inventory.next_id;
        inventory.next_id = id.checked_add(1).ok_or(TaskCapacity {
            limit: self.limit,
            needed: 1,
        })?;
        let owner = Arc::new(Owner {
            id,
            target,
            stream: Mutex::new(None),
            snapshot: Arc::new(Mutex::new(None)),
        });
        inventory.owners.push(owner.clone());
        Ok(owner)
    }

    /// Only fully joined successful owners may give capacity back. A reserved
    /// but unpublished stream has no terminal result and cannot be reaped.
    fn poll_owner(owner: &Owner<C>, cx: &mut Context<'_>) -> Poll<Result<(), TaskError<C>>> {
        let Ok(mut stream) = owner.stream.try_lock() else {
            return Poll::Pending;
        };
        let Some(stream) = stream.as_mut() else {
            return Poll::Pending;
        };
        let stream_result = stream.poll_join(cx);
        let Ok(mut snapshot) = owner.snapshot.try_lock() else {
            return Poll::Pending;
        };
        let snapshot_result = match snapshot.as_mut() {
            Some(task) => task.poll_join(cx),
            None => Poll::Ready(Ok(())),
        };
        match (stream_result, snapshot_result) {
            (Poll::Ready(Err(error)), _) | (_, Poll::Ready(Err(error))) => Poll::Ready(Err(error)),
            (Poll::Ready(Ok(())), Poll::Ready(Ok(()))) => Poll::Ready(Ok(())),
            _ => Poll::Pending,
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

    /// Wake the core on actual completion so it can resume deferred admission,
    /// and surface original failures even when no protocol notification arrived.
    pub(crate) async fn changed(&self) -> Result<(), TaskError<C>> {
        std::future::poll_fn(|cx| {
            let mut inventory = self.inventory.lock().unwrap();
            let mut completed = None;
            for (index, owner) in inventory.owners.iter().enumerate() {
                match Self::poll_owner(owner, cx) {
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {
                        completed = Some(index);
                        break;
                    }
                    Poll::Pending => {}
                }
            }
            if let Some(index) = completed {
                inventory.owners.remove(index);
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        })
        .await
    }

    /// Called after the sole producer core is joined. All handles stay in their
    /// cells across every await and all outcomes are retained across retries.
    pub(crate) async fn shutdown(
        &self,
    ) -> Vec<ReplicationShutdownError<C::NodeId, crate::type_config::alias::JoinErrorOf<C>>> {
        let owners = self.inventory.lock().unwrap().owners.clone();
        let mut failures = Vec::new();
        for owner in owners {
            let stream = match owner.stream.lock().await.as_mut() {
                Some(task) => task.join().await.err(),
                None => None,
            };
            let snapshot = match owner.snapshot.lock().await.as_mut() {
                Some(task) => task.join().await.err(),
                None => None,
            };
            if stream.is_some() || snapshot.is_some() {
                failures.push(ReplicationShutdownError {
                    owner_id: owner.id,
                    target: owner.target.clone(),
                    stream,
                    snapshot,
                });
            }
        }
        self.reap();
        // A producer may have failed during async client preparation, before
        // spawning a stream. Once the core is joined, these reservations own no
        // actual task and can be released without inventing a terminal result.
        self.inventory
            .lock()
            .unwrap()
            .owners
            .retain(|owner| owner.stream.try_lock().map_or(true, |task| task.is_some()));
        failures
    }
}
