//! Bounded summaries of a complete background sweep of the committed local
//! membership. Detailed diagnostics have a separate bound; coverage does not.
use kasumi_engine::admission::{NodeAdmission, Reservation};
use serde::Serialize;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;

pub(crate) const DETAIL_LIMIT: usize = 128;
pub(crate) const FRESHNESS: Duration = Duration::from_secs(30);
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const METADATA_BYTES: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Epoch {
    pub topology_version: u64,
    pub installed_routes: u64,
    pub actual_membership: u64,
}

/// One constant-sized invalidation target shared by every local Raft group.
/// The SDK calls this synchronously before effective membership changes, even
/// when a remote append, truncation or snapshot precedes Control publication.
#[derive(Debug, Default)]
pub(crate) struct MembershipEpoch(AtomicU64);
impl kasumi_raft::MembershipObserver for MembershipEpoch {
    fn membership_changing(&self) {
        let _ = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_add(1))
            });
    }
}
impl MembershipEpoch {
    pub(crate) fn current(&self) -> kasumi_types::Result<u64> {
        let value = self.0.load(Ordering::Acquire);
        if value == u64::MAX {
            return Err(kasumi_types::Error::new(
                kasumi_types::ErrorCode::Unavailable,
                "membership epoch exhausted",
            ));
        }
        Ok(value)
    }
}
#[derive(Clone)]
pub(crate) struct Sample {
    pub tenant: String,
    pub incarnation: String,
    pub quorum: bool,
}
struct Sweep {
    epoch: Epoch,
    expected: usize,
    examined: usize,
    healthy: usize,
    started: Instant,
    valid_until: Instant,
    details: Vec<Sample>,
}
#[derive(Default)]
struct State {
    completed: Option<Sweep>,
    progress: Option<Sweep>,
    invalidation: u64,
}
pub(crate) struct Coverage {
    state: Mutex<State>,
    pub(crate) probe: crate::readiness_probe::ProbeSlot,
    // Covers both fixed-size detailed pages, counters and the worker metadata.
    // The separately retained topology document has its own actual node charge.
    _reservation: Reservation,
}
#[derive(Serialize)]
pub(crate) struct Status {
    pub membership_epoch: Epoch,
    pub expected_groups: Option<usize>,
    pub examined_groups: usize,
    pub healthy_groups: usize,
    pub complete: bool,
    pub fresh: bool,
    pub oldest_probe_age_seconds: Option<f64>,
    pub detail_limit: usize,
}
impl Status {
    pub(crate) fn ready(&self) -> bool {
        self.complete
            && self.fresh
            && self.expected_groups.is_some_and(|expected| {
                expected > 0 && self.examined_groups == expected && self.healthy_groups == expected
            })
    }
}
pub(crate) struct Snapshot {
    pub status: Status,
    pub details: Vec<Sample>,
    pub token: Option<Token>,
}
#[derive(Clone, Copy)]
pub(crate) struct Token {
    epoch: Epoch,
    invalidation: u64,
    valid_until: Instant,
}
impl Coverage {
    pub(crate) fn new(admission: &Arc<NodeAdmission>) -> kasumi_types::Result<Self> {
        let mut reservation = admission.reserve(METADATA_BYTES, None)?;
        reservation.retain(METADATA_BYTES);
        Ok(Self {
            state: Mutex::new(State::default()),
            probe: Default::default(),
            _reservation: reservation,
        })
    }
    pub(crate) fn begin(&self, epoch: Epoch, expected: usize, now: Instant) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.completed.as_ref().is_some_and(|s| s.epoch != epoch) {
            state.completed = None;
            state.invalidation = state.invalidation.saturating_add(1);
        }
        state.progress = Some(Sweep {
            epoch,
            expected,
            examined: 0,
            healthy: 0,
            started: now,
            valid_until: now + FRESHNESS,
            details: Vec::with_capacity(DETAIL_LIMIT.min(expected)),
        });
    }
    pub(crate) fn record(&self, sample: Sample, healthy: bool, valid_until: Instant) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !healthy {
            // A newly observed failure invalidates the preceding successful
            // sweep immediately, including a response awaiting final release.
            state.completed = None;
            state.invalidation = state.invalidation.saturating_add(1);
        }
        if let Some(sweep) = state.progress.as_mut() {
            sweep.examined += 1;
            sweep.healthy += usize::from(healthy);
            sweep.valid_until = sweep.valid_until.min(valid_until);
            if sweep.details.len() < DETAIL_LIMIT {
                sweep.details.push(sample);
            }
        }
    }
    pub(crate) fn finish(&self, epoch: Epoch) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(sweep) = state.progress.take()
            && sweep.epoch == epoch
            && sweep.examined == sweep.expected
        {
            state.completed = Some(sweep);
        }
    }
    pub(crate) fn invalidate(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.completed = None;
        state.progress = None;
        state.invalidation = state.invalidation.saturating_add(1);
    }
    pub(crate) fn snapshot(&self, epoch: Epoch, now: Instant) -> Snapshot {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let completed = state.completed.as_ref().filter(|s| s.epoch == epoch);
        let selected = completed.or_else(|| state.progress.as_ref().filter(|s| s.epoch == epoch));
        let complete = completed.is_some();
        let fresh = complete && selected.is_some_and(|s| now < s.valid_until);
        let token = selected
            .filter(|_| fresh && state.invalidation < u64::MAX)
            .map(|s| Token {
                epoch,
                invalidation: state.invalidation,
                valid_until: s.valid_until,
            });
        Snapshot {
            status: Status {
                membership_epoch: epoch,
                expected_groups: selected.map(|s| s.expected),
                examined_groups: selected.map_or(0, |s| s.examined),
                healthy_groups: selected.map_or(0, |s| s.healthy),
                complete,
                fresh,
                oldest_probe_age_seconds: selected
                    .map(|s| now.saturating_duration_since(s.started).as_secs_f64()),
                detail_limit: DETAIL_LIMIT,
            },
            // Detail identities remain useful for fresh storage observations;
            // the adapter omits their quorum value unless this sweep is fresh.
            details: selected.map_or_else(Vec::new, |s| s.details.clone()),
            token,
        }
    }
    pub(crate) fn check(&self, token: Token, epoch: Epoch, now: Instant) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        token.epoch == epoch
            && token.invalidation == state.invalidation
            && state.invalidation < u64::MAX
            && now < token.valid_until
    }
}

#[cfg(test)]
#[path = "readiness_tests.rs"]
mod tests;
