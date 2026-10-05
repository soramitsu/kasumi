use crate::core::sm::apply_batch::ApplyBatch;
use crate::core::sm::command::CommandSeq;
use crate::type_config::alias::OneshotSenderOf;
use crate::RaftTypeConfig;
use crate::SnapshotMeta;
use crate::StorageError;
use std::sync::Arc;

/// The Ok part of a state machine command result.
#[derive(Debug)]
pub(crate) enum Response<C>
where
    C: RaftTypeConfig,
{
    /// Build a snapshot, it returns result via the universal RaftCore response channel.
    BuildSnapshot(SnapshotMeta<C::NodeId, C::Node>),

    /// When finishing installing a snapshot.
    ///
    /// It does not return any value to RaftCore.
    InstallSnapshot(Option<SnapshotMeta<C::NodeId, C::Node>>),

    /// Send back applied result to RaftCore.
    Apply {
        batch: Arc<ApplyBatch<C>>,
        final_batch: bool,
        consumed: OneshotSenderOf<C, ()>,
    },
}

/// Container of result of a command.
#[derive(Debug)]
pub(crate) struct CommandResult<C>
where
    C: RaftTypeConfig,
{
    #[allow(dead_code)]
    pub(crate) command_seq: CommandSeq,
    pub(crate) result: Result<Response<C>, StorageError<C::NodeId>>,
}

impl<C> CommandResult<C>
where
    C: RaftTypeConfig,
{
    pub(crate) fn new(command_seq: CommandSeq, result: Result<Response<C>, StorageError<C::NodeId>>) -> Self {
        Self { command_seq, result }
    }
}
