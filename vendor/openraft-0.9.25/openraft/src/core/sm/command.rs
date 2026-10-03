use std::fmt::Debug;
use std::fmt::Formatter;

use super::pending_apply::ApplyRange;
use crate::core::raft_msg::ResultSender;
use crate::error::Infallible;
use crate::type_config::alias::SnapshotDataOf;
use crate::LogId;
use crate::RaftTypeConfig;
use crate::Snapshot;

#[derive(PartialEq)]
pub(crate) struct Command<C>
where
    C: RaftTypeConfig,
{
    pub(crate) seq: CommandSeq,
    pub(crate) apply_before: Option<ApplyRange<C>>,
    pub(crate) payload: CommandPayload<C>,
}

impl<C> Debug for Command<C>
where
    C: RaftTypeConfig,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateMachineCommand")
            .field("seq", &self.seq)
            .field("apply_before", &self.apply_before)
            .field("payload", &self.payload)
            .finish()
    }
}

impl<C> Command<C>
where
    C: RaftTypeConfig,
{
    pub(crate) fn new(payload: CommandPayload<C>) -> Self {
        Self {
            seq: 0,
            apply_before: None,
            payload,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn seq(&self) -> CommandSeq {
        self.seq
    }

    pub(crate) fn with_seq(mut self, seq: CommandSeq) -> Self {
        self.seq = seq;
        self
    }

    pub(crate) fn set_seq(&mut self, seq: CommandSeq) {
        self.seq = seq;
    }

    pub(crate) fn build_snapshot() -> Self {
        let payload = CommandPayload::BuildSnapshot;
        Command::new(payload)
    }

    pub(crate) fn get_snapshot(tx: ResultSender<C, Option<Snapshot<C>>>) -> Self {
        let payload = CommandPayload::GetSnapshot { tx };
        Command::new(payload)
    }

    pub(crate) fn begin_receiving_snapshot(tx: ResultSender<C, Box<SnapshotDataOf<C>>, Infallible>) -> Self {
        let payload = CommandPayload::BeginReceivingSnapshot { tx };
        Command::new(payload)
    }

    pub(crate) fn install_full_snapshot(snapshot: Snapshot<C>) -> Self {
        let payload = CommandPayload::InstallFullSnapshot { snapshot };
        Command::new(payload)
    }

    pub(crate) fn apply(since: u64, upto: LogId<C::NodeId>) -> Self {
        let payload = CommandPayload::Apply { since, upto };
        Command::new(payload)
    }
}

// TODO: move to other mod, it is shared by log, sm and replication
/// A sequence number of a state machine command.
///
/// It is used to identify and consume a submitted command when the command callback is received by
/// RaftCore.
pub(crate) type CommandSeq = u64;

/// The payload of a state machine command.
pub(crate) enum CommandPayload<C>
where
    C: RaftTypeConfig,
{
    /// Instruct the state machine to create a snapshot based on its most recent view.
    BuildSnapshot,

    /// Get the latest built snapshot.
    GetSnapshot {
        tx: ResultSender<C, Option<Snapshot<C>>>,
    },

    BeginReceivingSnapshot {
        tx: ResultSender<C, Box<SnapshotDataOf<C>>, Infallible>,
    },

    InstallFullSnapshot {
        snapshot: Snapshot<C>,
    },

    /// Apply this committed range in bounded, acknowledged batches.
    Apply {
        since: u64,
        upto: LogId<C::NodeId>,
    },
}

impl<C> Debug for CommandPayload<C>
where
    C: RaftTypeConfig,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandPayload::BuildSnapshot => write!(f, "BuildSnapshot"),
            CommandPayload::GetSnapshot { .. } => write!(f, "GetSnapshot"),
            CommandPayload::InstallFullSnapshot { snapshot } => {
                write!(f, "InstallFullSnapshot: meta: {:?}", snapshot.meta)
            }
            CommandPayload::BeginReceivingSnapshot { .. } => {
                write!(f, "BeginReceivingSnapshot")
            }
            CommandPayload::Apply { since, upto } => write!(f, "Apply: {}..={}", since, upto),
        }
    }
}

// `PartialEq` is only used for testing
impl<C> PartialEq for CommandPayload<C>
where
    C: RaftTypeConfig,
{
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CommandPayload::BuildSnapshot, CommandPayload::BuildSnapshot) => true,
            (CommandPayload::GetSnapshot { .. }, CommandPayload::GetSnapshot { .. }) => true,
            (CommandPayload::BeginReceivingSnapshot { .. }, CommandPayload::BeginReceivingSnapshot { .. }) => true,
            (
                CommandPayload::InstallFullSnapshot { snapshot: s1 },
                CommandPayload::InstallFullSnapshot { snapshot: s2 },
            ) => s1.meta == s2.meta,
            (
                CommandPayload::Apply { since, upto },
                CommandPayload::Apply {
                    since: b_since,
                    upto: b_upto,
                },
            ) => since == b_since && upto == b_upto,
            _ => false,
        }
    }
}
