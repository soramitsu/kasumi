//! Bounded fixture telemetry. The original transport request/result passes
//! through unchanged. A return is observed before the candidate's notification
//! queue; published metrics do not prove that its core accepted that response.
use kasumi_raft::{BasicNode, InProcessRouter, RaftTransport, RpcRequest, RpcResponse};
use openraft::{RaftMetrics, ServerState, Vote, raft::VoteRequest, raft::VoteResponse};
use std::{
    fmt::{self, Write},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio::sync::watch;

const VOTE_SLOTS: usize = 32;
type MemberMetrics = watch::Receiver<RaftMetrics<u64, BasicNode>>;

struct ErrorText {
    bytes: [u8; 128],
    len: usize,
    truncated: bool,
}
impl Default for ErrorText {
    fn default() -> Self {
        Self {
            bytes: [0; 128],
            len: 0,
            truncated: false,
        }
    }
}
impl ErrorText {
    fn capture(error: &impl fmt::Display) -> Self {
        let mut text = Self::default();
        let _ = write!(text, "{error}");
        text
    }
}
impl Write for ErrorText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let mut take = value.len().min(self.bytes.len() - self.len);
        while !value.is_char_boundary(take) {
            take -= 1;
        }
        self.bytes[self.len..self.len + take].copy_from_slice(&value.as_bytes()[..take]);
        self.len += take;
        if take != value.len() {
            self.truncated = true;
            return Err(fmt::Error);
        }
        Ok(())
    }
}
impl fmt::Debug for ErrorText {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("ErrorText")
            .field(
                "text",
                &std::str::from_utf8(&self.bytes[..self.len]).unwrap(),
            )
            .field("truncated", &self.truncated)
            .finish()
    }
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "Retained fields are read by failure-only Debug output."
)]
struct CandidateMetrics {
    term: u64,
    persisted_vote: Vote<u64>,
    state: ServerState,
    leader: Option<u64>,
    running: bool,
}
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "Retained fields are read by failure-only Debug output."
)]
enum Outcome {
    Pending,
    ReturnedVote(VoteResponse<u64>),
    ReturnedRaftError(ErrorText),
    ReturnedTransportError(ErrorText),
    ReturnedUnexpectedResponse,
    // The wrapper cannot identify which parent dropped it, or whether a
    // dispatched remote operation continued after its receiver was dropped.
    FutureDropped { during_unwind: bool },
}
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "Retained fields are read by failure-only Debug output."
)]
struct Observation {
    source: u64,
    target: u64,
    request: VoteRequest<u64>,
    started: Duration,
    elapsed: Option<Duration>,
    published_candidate_at_start: Option<CandidateMetrics>,
    published_candidate_at_end: Option<CandidateMetrics>,
    outcome: Outcome,
}
#[derive(Debug)]
struct History {
    slots: [Option<Observation>; VOTE_SLOTS],
    next: usize,
    started: u64,
    returned: u64,
    dropped: u64,
    evicted: u64,
    omitted_while_full: u64,
}
pub(super) struct BootstrapVoteProbe {
    router: Arc<InProcessRouter>,
    origin: Instant,
    metrics: Mutex<[Option<MemberMetrics>; 3]>,
    history: Mutex<History>,
}
impl BootstrapVoteProbe {
    pub(super) fn new(router: Arc<InProcessRouter>) -> Self {
        Self {
            router,
            origin: Instant::now(),
            metrics: Mutex::new(std::array::from_fn(|_| None)),
            history: Mutex::new(History {
                slots: std::array::from_fn(|_| None),
                next: 0,
                started: 0,
                returned: 0,
                dropped: 0,
                evicted: 0,
                omitted_while_full: 0,
            }),
        }
    }
    pub(super) fn register(&self, node: u64, metrics: MemberMetrics) {
        self.metrics.lock().unwrap()[node as usize - 1] = Some(metrics);
    }
    pub(super) fn unregister(&self, node: u64) {
        self.metrics.lock().unwrap()[node as usize - 1] = None;
    }
    fn candidate(&self, node: u64) -> Option<CandidateMetrics> {
        let sources = self.metrics.lock().unwrap_or_else(|p| p.into_inner());
        let metrics = sources
            .get(node.checked_sub(1)? as usize)?
            .as_ref()?
            .borrow();
        Some(CandidateMetrics {
            term: metrics.current_term,
            persisted_vote: metrics.vote,
            state: metrics.state,
            leader: metrics.current_leader,
            running: metrics.running_state.is_ok(),
        })
    }
    fn history(&self) -> MutexGuard<'_, History> {
        self.history.lock().unwrap_or_else(|p| p.into_inner())
    }
    pub(super) fn diagnostic(&self) -> String {
        format!("at={:?} {:?}", self.origin.elapsed(), self.history())
    }
    fn begin(&self, source: u64, target: u64, request: &VoteRequest<u64>) -> Guard<'_> {
        let started = Instant::now();
        let published_candidate_at_start = self.candidate(source);
        let mut history = self.history();
        history.started = history.started.saturating_add(1);
        // Never overwrite an observation whose actual future is still pending.
        let slot = (0..VOTE_SLOTS)
            .map(|offset| (history.next + offset) % VOTE_SLOTS)
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
                request: request.clone(),
                started: started.duration_since(self.origin),
                elapsed: None,
                published_candidate_at_start,
                published_candidate_at_end: None,
                outcome: Outcome::Pending,
            });
            history.next = (slot + 1) % VOTE_SLOTS;
        } else {
            history.omitted_while_full = history.omitted_while_full.saturating_add(1);
        }
        Guard {
            probe: self,
            source,
            started,
            slot,
            finished: false,
        }
    }
}
struct Guard<'a> {
    probe: &'a BootstrapVoteProbe,
    source: u64,
    started: Instant,
    slot: Option<usize>,
    finished: bool,
}
impl Guard<'_> {
    fn finish(&mut self, outcome: Outcome, returned: bool) {
        let elapsed = self.started.elapsed();
        let published_candidate_at_end = self.probe.candidate(self.source);
        let mut history = self.probe.history();
        if returned {
            history.returned = history.returned.saturating_add(1);
        } else {
            history.dropped = history.dropped.saturating_add(1);
        }
        if let Some(slot) = self.slot {
            let observation = history.slots[slot].as_mut().unwrap();
            observation.elapsed = Some(elapsed);
            observation.published_candidate_at_end = published_candidate_at_end;
            observation.outcome = outcome;
        }
        self.finished = true;
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(
                Outcome::FutureDropped {
                    during_unwind: std::thread::panicking(),
                },
                false,
            );
        }
    }
}
#[async_trait::async_trait]
impl RaftTransport for BootstrapVoteProbe {
    async fn send(
        &self,
        group: &str,
        source: u64,
        target: u64,
        node: &BasicNode,
        request: RpcRequest,
    ) -> anyhow::Result<RpcResponse> {
        let mut guard = match &request {
            RpcRequest::Vote(vote) => Some(self.begin(source, target, vote)),
            _ => None,
        };
        let result = self.router.send(group, source, target, node, request).await;
        if let Some(guard) = &mut guard {
            let outcome = match &result {
                Ok(RpcResponse::Vote(Ok(response))) => Outcome::ReturnedVote(response.clone()),
                Ok(RpcResponse::Vote(Err(error))) => {
                    Outcome::ReturnedRaftError(ErrorText::capture(error))
                }
                Ok(_) => Outcome::ReturnedUnexpectedResponse,
                Err(error) => Outcome::ReturnedTransportError(ErrorText::capture(error)),
            };
            guard.finish(outcome, true);
        }
        result
    }
}
