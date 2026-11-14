//! Pacing of background work on one node database.
//!
//! Every tenant of a node shares one database, whose maintenance steps and
//! commits exclude each other and, while a step runs or a commit stages, the
//! reads of every tenant. Background work (the node worker's warm and
//! maintenance steps, snapshot chunk commits, journal purge chunks) therefore
//! pauses after each of its units whenever a foreground operation wanted the
//! database meanwhile: `FOREGROUND_SHARE` times as long as the unit kept the
//! database, so it uses at most one part in `FOREGROUND_SHARE + 1` of the
//! database's time. With no foreground operation it keeps its own pace.
//!
//! Foreground activity is `kasumi_kv::Database::foreground_activity`, a
//! counter each transaction bumps as it begins, reads and commits, before it
//! waits for a lock. A paced writer runs its own units inside
//! `kasumi_kv::background_work`, so it yields to others and never to itself.
use crate::NodeStore;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The pause per unit of time a background unit kept the database while
/// foreground operations are active.
pub const FOREGROUND_SHARE: u32 = 4;
/// The shortest pause between two background units: long enough for an
/// operation queued behind the previous unit to enter and be counted.
pub const MIN_PACED_DELAY: Duration = Duration::from_millis(1);
/// The longest single pause. A unit that kept the database for more than a
/// quarter of this is followed by a pause shorter than `FOREGROUND_SHARE`
/// times its own length, so that one slow unit cannot stop background work
/// for long.
pub const MAX_PACED_DELAY: Duration = Duration::from_secs(1);
/// A pausing writer, or one waiting for the shared stream, checks this often
/// whether its database has stopped or its owner hurries: the most a stop or
/// a group's shutdown can wait for a pause.
pub(crate) const PAUSE_SLICE: Duration = Duration::from_millis(10);

/// The pause that follows a background unit which kept the database for
/// `held`, while foreground operations are active.
pub fn paced_delay(held: Duration) -> Duration {
    held.saturating_mul(FOREGROUND_SHARE)
        .clamp(MIN_PACED_DELAY, MAX_PACED_DELAY)
}

/// What one unit left for the next to pace against.
#[derive(Clone, Copy, Debug)]
struct PacedUnit {
    ended: Instant,
    held: Duration,
    /// The database's foreground activity when the unit started; `None` when
    /// it could not be read.
    activity: Option<u64>,
}

/// The pacing state of one stream of background writes: consecutive units
/// (chunk commits) of one activity. A fresh stream owes no pause.
#[derive(Debug, Default)]
pub struct BackgroundPace {
    previous: Option<PacedUnit>,
}

/// Paced background writes on one node database since it opened.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackgroundWriteStatus {
    /// Units that ran: snapshot chunk commits and journal purge chunks.
    pub units: u64,
    /// Wall time those units kept, or waited for, the database, and the
    /// longest single unit: about how long a foreground operation can wait
    /// for one.
    pub database_time: Duration,
    pub longest_database_time: Duration,
    /// Time their writers paused for foreground operations beyond
    /// `MIN_PACED_DELAY`.
    pub paced_delay: Duration,
}

/// One node database's paced background writers. Snapshot chunk commits of
/// every tenant share `shared`, so together they keep to one share.
#[derive(Default)]
pub(crate) struct BackgroundWrites {
    // Held across a unit and the pause before it; never taken while any
    // database lock is held. A writer waiting for it gives up the wait once
    // its owner hurries or the database stops (`shared_background_write`).
    shared: Mutex<BackgroundPace>,
    units: AtomicU64,
    database_nanos: AtomicU64,
    longest_nanos: AtomicU64,
    paced_nanos: AtomicU64,
}

impl BackgroundWrites {
    pub(crate) fn status(&self) -> BackgroundWriteStatus {
        BackgroundWriteStatus {
            units: self.units.load(Ordering::Relaxed),
            database_time: Duration::from_nanos(self.database_nanos.load(Ordering::Relaxed)),
            longest_database_time: Duration::from_nanos(self.longest_nanos.load(Ordering::Relaxed)),
            paced_delay: Duration::from_nanos(self.paced_nanos.load(Ordering::Relaxed)),
        }
    }
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// The pause owed between a unit that kept the database for `held` and the
/// next one of its stream: the floor, or the paced delay while a foreground
/// operation entered the database since that unit started.
fn owed_pause(held: Duration, foreground: bool) -> Duration {
    if foreground {
        paced_delay(held)
    } else {
        MIN_PACED_DELAY
    }
}

impl NodeStore {
    /// `kasumi_kv::Database::foreground_activity` of this node's database,
    /// or `None` once it has stopped. Like any use of the database it is
    /// admitted through the node's opening, whose state it takes briefly; it
    /// takes no lock of the database itself.
    pub fn foreground_activity(&self) -> Option<u64> {
        self.body().db.foreground_activity().ok()
    }

    /// Paced background writes on this node's database since it opened.
    /// Reads counters only; takes no lock.
    pub fn background_write_status(&self) -> BackgroundWriteStatus {
        self.body().background_writes.status()
    }

    /// Run one unit of a background write stream (one chunk commit) on the
    /// calling thread, which must be free to block. Before any unit but the
    /// stream's first it pauses: `MIN_PACED_DELAY` after the previous unit
    /// ended, and, if a foreground operation entered the database since that
    /// unit started, until `paced_delay` of the time that unit took has
    /// passed. Time that passed anyway counts towards the pause; a stopped
    /// database, or `hurry` once its owner sets it (a group that is shutting
    /// down), ends it within `PAUSE_SLICE`. `work` runs inside
    /// `kasumi_kv::background_work`: its own transactions are not foreground
    /// activity. The stream stays ordered and each unit is as atomic as
    /// `work` makes it; only the time between units changes.
    pub fn paced_background_write<T>(
        &self,
        pace: &mut BackgroundPace,
        hurry: &AtomicBool,
        work: impl FnOnce() -> T,
    ) -> T {
        let writes = &self.body().background_writes;
        if let Some(previous) = pace.previous {
            // The floor first: an operation that queued behind the previous
            // unit gets in, and is counted, before this stream decides.
            self.pause_until(previous.ended + MIN_PACED_DELAY, hurry);
            let foreground = match (previous.activity, self.foreground_activity()) {
                (Some(before), Some(now)) => before != now,
                _ => false,
            };
            let owed = owed_pause(previous.held, foreground);
            let paused = self.pause_until(previous.ended + owed, hurry);
            writes
                .paced_nanos
                .fetch_add(nanos(paused), Ordering::Relaxed);
        }
        let activity = self.foreground_activity();
        let started = Instant::now();
        let output = kasumi_kv::background_work(work);
        let ended = Instant::now();
        let held = ended.saturating_duration_since(started);
        pace.previous = Some(PacedUnit {
            ended,
            held,
            activity,
        });
        writes.units.fetch_add(1, Ordering::Relaxed);
        writes
            .database_nanos
            .fetch_add(nanos(held), Ordering::Relaxed);
        writes
            .longest_nanos
            .fetch_max(nanos(held), Ordering::Relaxed);
        output
    }

    /// `paced_background_write` on the stream every tenant of this node's
    /// database shares: units run one at a time, each paced against the
    /// previous one whichever tenant wrote it, so concurrent snapshot builds
    /// keep to one share of the database between them. The caller may hold
    /// only locks that no foreground operation of another tenant waits for.
    ///
    /// A writer that waits for the stream while another tenant's unit, or the
    /// pause before it, holds the stream checks `hurry` and the database every
    /// `PAUSE_SLICE`: once its owner hurries or the database stops, its unit
    /// runs at once and unpaced, as a direct commit would. A closing group
    /// therefore never waits for another tenant's pause.
    pub fn shared_background_write<T>(&self, hurry: &AtomicBool, work: impl FnOnce() -> T) -> T {
        let shared = &self.body().background_writes.shared;
        let mut pace = loop {
            if let Some(pace) = shared.try_lock_for(PAUSE_SLICE) {
                break pace;
            }
            if hurry.load(Ordering::Acquire) || self.body().db.is_stopped() {
                return work();
            }
        };
        self.paced_background_write(&mut pace, hurry, work)
    }

    /// Sleep until `deadline`, or until the database stops or `hurry` is
    /// set. Returns the time slept: zero when the deadline had already
    /// passed.
    fn pause_until(&self, deadline: Instant, hurry: &AtomicBool) -> Duration {
        let mut slept = Duration::ZERO;
        loop {
            let now = Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() || hurry.load(Ordering::Acquire) || self.body().db.is_stopped() {
                return slept;
            }
            std::thread::sleep(remaining.min(PAUSE_SLICE));
            slept = slept.saturating_add(now.elapsed());
        }
    }
}

#[cfg(test)]
#[path = "background_pace_tests.rs"]
mod tests;
