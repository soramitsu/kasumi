//! Bounded metadata from the actual Append transport future. No payload is
//! cloned, no RPC is retried, and a dropped future is not called a remote failure.
use super::ErrorText;
use kasumi_raft::{RpcResponse, TypeConfig};
use openraft::{
    LogId, Vote,
    raft::{AppendEntriesRequest, AppendEntriesResponse},
};
use std::{
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

const APPEND_SLOTS: usize = 32;
#[derive(Clone, Debug)]
#[allow(dead_code, reason = "Read by failure-only Debug output.")]
enum Outcome {
    Pending,
    Success,
    PartialSuccess(Option<LogId<u64>>),
    Conflict,
    HigherVote(Vote<u64>),
    RemoteError(ErrorText),
    TransportError(ErrorText),
    UnexpectedResponse,
    FutureDropped { during_unwind: bool },
}
impl Outcome {
    fn index(&self) -> usize {
        match self {
            Self::Pending => unreachable!("pending outcome is not terminal"),
            Self::Success => 0,
            Self::PartialSuccess(_) => 1,
            Self::Conflict => 2,
            Self::HigherVote(_) => 3,
            Self::RemoteError(_) => 4,
            Self::TransportError(_) => 5,
            Self::UnexpectedResponse => 6,
            Self::FutureDropped { .. } => 7,
        }
    }
}
#[derive(Clone, Debug)]
#[allow(dead_code, reason = "Read by failure-only Debug output.")]
struct Observation {
    source: u64,
    target: u64,
    vote: Vote<u64>,
    previous: Option<LogId<u64>>,
    last: Option<LogId<u64>>,
    leader_commit: Option<LogId<u64>>,
    entries: usize,
    started: Duration,
    elapsed: Option<Duration>,
    outcome: Outcome,
}
#[derive(Debug)]
struct History {
    slots: [Option<Observation>; APPEND_SLOTS],
    // First non-success with a captured slot. Omitted calls still contribute
    // to terminal counters but cannot supply this observation's metadata.
    first_non_success: Option<Observation>,
    next: usize,
    started: u64,
    // success, partial, conflict, higher vote, remote error, transport error,
    // unexpected response, dropped transport future.
    outcomes: [u64; 8],
    evicted: u64,
    omitted_while_full: u64,
}
pub(super) struct Probe {
    origin: Instant,
    history: Mutex<History>,
}
impl Probe {
    pub(super) fn new(origin: Instant) -> Self {
        Self {
            origin,
            history: Mutex::new(History {
                slots: [const { None }; APPEND_SLOTS],
                first_non_success: None,
                next: 0,
                started: 0,
                outcomes: [0; 8],
                evicted: 0,
                omitted_while_full: 0,
            }),
        }
    }
    fn history(&self) -> MutexGuard<'_, History> {
        self.history.lock().unwrap_or_else(|p| p.into_inner())
    }
    pub(super) fn diagnostic(&self) -> String {
        format!(
            "at={:?}; inline_bytes[probe,history,observation]=[{},{},{}]; outcomes=[success,partial,conflict,higher_vote,remote_error,transport_error,unexpected,dropped]; {:?}",
            self.origin.elapsed(),
            std::mem::size_of::<Self>(),
            std::mem::size_of::<History>(),
            std::mem::size_of::<Observation>(),
            self.history(),
        )
    }
    pub(super) fn begin(
        &self,
        source: u64,
        target: u64,
        request: &AppendEntriesRequest<TypeConfig>,
    ) -> Guard<'_> {
        let started = Instant::now();
        let mut history = self.history();
        history.started = history.started.saturating_add(1);
        // Pending futures keep their slot. The only copied request data are
        // fixed scalar headers, never entry commands, bodies or credentials.
        let slot = (0..APPEND_SLOTS)
            .map(|offset| (history.next + offset) % APPEND_SLOTS)
            .find(|index| {
                history.slots[*index]
                    .as_ref()
                    .is_none_or(|old| !matches!(old.outcome, Outcome::Pending))
            });
        if let Some(slot) = slot {
            if history.slots[slot].is_some() {
                history.evicted = history.evicted.saturating_add(1);
            }
            history.slots[slot] = Some(Observation {
                source,
                target,
                vote: request.vote,
                previous: request.prev_log_id,
                last: request.entries.last().map(|entry| entry.log_id),
                leader_commit: request.leader_commit,
                entries: request.entries.len(),
                started: started.duration_since(self.origin),
                elapsed: None,
                outcome: Outcome::Pending,
            });
            history.next = (slot + 1) % APPEND_SLOTS;
        } else {
            history.omitted_while_full = history.omitted_while_full.saturating_add(1);
        }
        Guard {
            probe: self,
            slot,
            started,
            finished: false,
        }
    }
}
pub(super) struct Guard<'a> {
    probe: &'a Probe,
    slot: Option<usize>,
    started: Instant,
    finished: bool,
}
impl Guard<'_> {
    pub(super) fn returned(&mut self, response: &anyhow::Result<RpcResponse>) {
        let outcome = match response {
            Ok(RpcResponse::Append(Ok(response))) => match response {
                AppendEntriesResponse::Success => Outcome::Success,
                AppendEntriesResponse::PartialSuccess(matching) => {
                    Outcome::PartialSuccess(*matching)
                }
                AppendEntriesResponse::Conflict => Outcome::Conflict,
                AppendEntriesResponse::HigherVote(vote) => Outcome::HigherVote(*vote),
            },
            Ok(RpcResponse::Append(Err(error))) => Outcome::RemoteError(ErrorText::capture(error)),
            Ok(_) => Outcome::UnexpectedResponse,
            Err(error) => Outcome::TransportError(ErrorText::capture(error)),
        };
        self.finish(outcome);
    }
    fn finish(&mut self, outcome: Outcome) {
        let elapsed = self.started.elapsed();
        let mut history = self.probe.history();
        let index = outcome.index();
        history.outcomes[index] = history.outcomes[index].saturating_add(1);
        if let Some(slot) = self.slot {
            let observation = history.slots[slot].as_mut().unwrap();
            observation.elapsed = Some(elapsed);
            observation.outcome = outcome;
            if index != 0 && history.first_non_success.is_none() {
                // Fixed metadata/error-text clone; there is no heap owner here.
                history.first_non_success = history.slots[slot].clone();
            }
        }
        self.finished = true;
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(Outcome::FutureDropped {
                during_unwind: std::thread::panicking(),
            });
        }
    }
}
