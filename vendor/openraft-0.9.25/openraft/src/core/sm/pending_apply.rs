//! One pending committed range, independent of the number of advancing commits.
//!
//! A non-apply command captures the preceding range under this same lock. That
//! boundary preserves snapshot ordering without queuing one node per commit.
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, Notify};

use super::{Command, CommandPayload, CommandSeq};
use crate::{LogId, RaftTypeConfig};

#[derive(Debug, PartialEq)]
pub(crate) struct ApplyRange<C: RaftTypeConfig> {
    pub(crate) since: u64,
    pub(crate) upto: LogId<C::NodeId>,
    pub(crate) seq: CommandSeq,
}

pub(crate) struct PendingApply<C: RaftTypeConfig> {
    pending: Mutex<State<C>>,
    pub(crate) ready: Notify,
}

struct State<C: RaftTypeConfig> {
    range: Option<ApplyRange<C>>,
    // Retain continuity across a range already taken by the worker. A real
    // snapshot install establishes the next log boundary explicitly.
    last: Option<(LogId<C::NodeId>, CommandSeq)>,
}

impl<C: RaftTypeConfig> PendingApply<C> {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            pending: Mutex::new(State {
                range: None,
                last: None,
            }),
            ready: Notify::new(),
        })
    }

    pub(crate) fn send(
        &self,
        sender: &mpsc::UnboundedSender<Command<C>>,
        mut command: Command<C>,
    ) -> Result<(), mpsc::error::SendError<Command<C>>> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if sender.is_closed() || command.apply_before.is_some() {
            return Err(mpsc::error::SendError(command));
        }
        if let CommandPayload::Apply { since, upto } = &command.payload {
            if *since > upto.index || upto.index == u64::MAX {
                return Err(mpsc::error::SendError(command));
            }
            if let Some((previous, seq)) = &pending.last {
                if previous.index.checked_add(1) != Some(*since) || previous > upto || *seq >= command.seq {
                    return Err(mpsc::error::SendError(command));
                }
            }
            pending.last = Some((upto.clone(), command.seq));
            if let Some(previous) = pending.range.as_mut() {
                previous.upto = upto.clone();
                previous.seq = command.seq;
            } else {
                pending.range = Some(ApplyRange {
                    since: *since,
                    upto: upto.clone(),
                    seq: command.seq,
                });
            }
            drop(pending);
            self.ready.notify_one();
            Ok(())
        } else {
            command.apply_before = pending.range.take();
            if let CommandPayload::InstallFullSnapshot { snapshot } = &command.payload {
                pending.last = snapshot.meta.last_log_id.clone().map(|id| (id, command.seq));
            }
            // Enqueue while holding the same mutex used by take_next: a later
            // commit cannot be selected ahead of this real command boundary.
            sender.send(command)
        }
    }

    /// Select queued boundaries before the single range following them.
    pub(crate) fn take_next(
        &self,
        receiver: &mut mpsc::UnboundedReceiver<Command<C>>,
    ) -> Result<Command<C>, mpsc::error::TryRecvError> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        match receiver.try_recv() {
            Ok(command) => Ok(command),
            Err(empty) => match pending.range.take() {
                Some(range) => Ok(Command::apply(range.since, range.upto).with_seq(range.seq)),
                None => Err(empty),
            },
        }
    }
}
