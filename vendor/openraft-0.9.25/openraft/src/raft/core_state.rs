use std::sync::Arc;

use crate::error::Fatal;
use crate::error::Infallible;
use crate::AsyncRuntime;
use crate::NodeId;

/// The running state of RaftCore
#[allow(clippy::large_enum_variant)]
pub(in crate::raft) enum CoreState<NID, A>
where
    NID: NodeId,
    A: AsyncRuntime,
{
    /// The RaftCore task is still running.
    Running(A::JoinHandle<Result<Infallible, Fatal<NID>>>),

    /// The RaftCore task has finished. The return value of the task is stored.
    Done(CoreOutcome<NID, A>),
}

/// A completed core keeps its wire classification and original runtime failure.
/// The core cannot return successfully because its success type is Infallible.
pub(in crate::raft) struct CoreOutcome<NID: NodeId, A: AsyncRuntime> {
    pub(in crate::raft) fatal: Fatal<NID>,
    pub(in crate::raft) join_error: Option<Arc<A::JoinError>>,
}

impl<NID: NodeId, A: AsyncRuntime> Clone for CoreOutcome<NID, A> {
    fn clone(&self) -> Self {
        Self {
            fatal: self.fatal.clone(),
            join_error: self.join_error.clone(),
        }
    }
}
