//! Fixed custody cells for the state-machine worker and its one snapshot builder.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use tokio::sync::Mutex;

use crate::error::Fatal;
use crate::error::ShutdownTaskError;
use crate::type_config::alias::JoinErrorOf;
use crate::type_config::alias::JoinHandleOf;
use crate::AsyncRuntime;
use crate::RaftTypeConfig;

pub(crate) type TaskError<C> = ShutdownTaskError<<C as RaftTypeConfig>::NodeId, JoinErrorOf<C>>;

pub(crate) enum Task<C: RaftTypeConfig> {
    Running(JoinHandleOf<C, Result<(), TaskError<C>>>),
    Done(Result<(), TaskError<C>>),
}

impl<C: RaftTypeConfig> Task<C> {
    pub(crate) fn is_running(&self) -> bool {
        matches!(self, Self::Running(_))
    }

    /// Poll the actual handle in its owner cell and retain its terminal result
    /// synchronously. Used by owner event loops without spawning a monitor.
    pub(crate) fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TaskError<C>>> {
        if let Self::Running(handle) = self {
            let outcome = match Pin::new(handle).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(result)) => result,
                Poll::Ready(Err(error)) => Err(ShutdownTaskError::Join(Arc::new(error))),
            };
            *self = Self::Done(outcome);
        }
        let Self::Done(outcome) = self else {
            unreachable!("joined above")
        };
        Poll::Ready(outcome.clone())
    }

    /// Never take the actual handle across an await.
    pub(crate) async fn join(&mut self) -> Result<(), TaskError<C>> {
        std::future::poll_fn(|cx| self.poll_join(cx)).await
    }
}

pub(crate) fn fatal<C: RaftTypeConfig>(error: &TaskError<C>) -> Fatal<C::NodeId> {
    match error {
        ShutdownTaskError::Storage(error) => Fatal::StorageError((**error).clone()),
        ShutdownTaskError::Join(error) => {
            if C::AsyncRuntime::is_panic(error) {
                Fatal::Panicked
            } else {
                Fatal::Cancelled
            }
        }
    }
}

/// Two cells are sufficient: the engine admits at most one snapshot build, and
/// a completed successful builder is joined before its cell can be reused.
/// Errors are never replaced, so metadata does not grow with snapshot history.
pub(crate) struct Tasks<C: RaftTypeConfig> {
    pub(crate) worker: Arc<Mutex<Task<C>>>,
    pub(crate) snapshot: Arc<Mutex<Option<Task<C>>>>,
}

impl<C: RaftTypeConfig> Tasks<C> {
    /// Call only after the core is joined and cannot send another command. A
    /// worker failure does not skip the snapshot join, including on retry.
    pub(crate) async fn shutdown(&self) -> (Option<TaskError<C>>, Option<TaskError<C>>) {
        let worker = self.worker.lock().await.join().await.err();
        let mut snapshot = self.snapshot.lock().await;
        let snapshot = match snapshot.as_mut() {
            Some(task) => task.join().await.err(),
            None => None,
        };
        (worker, snapshot)
    }

    #[cfg(test)]
    pub(crate) fn completed_test_tasks() -> Self {
        Self {
            worker: Arc::new(Mutex::new(Task::Done(Ok(())))),
            snapshot: Arc::new(Mutex::new(None)),
        }
    }
}
