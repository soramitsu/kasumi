//! The serving reconciliation loop. It checks for control-plane closure every
//! interval and runs a pass whenever its backoff allows. Failed passes wait
//! longer and longer, up to a bound, and a clean pass resets the wait. An
//! unavailability is logged when it starts, when its failing steps change, at
//! a bounded reminder interval and when it ends, never once per pass.
use super::failure_episodes::{EpisodeReport, EpisodeSummary, FailureEpisodes, utc};
use super::*;
use std::{
    future::Future,
    time::{Duration, SystemTime},
};
use tokio::{sync::watch, time::Instant};

/// Fixed class of the reconciliation step a pass could not complete. Attached
/// as error context; the underlying error text is never logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ReconcileStep {
    ManagementGate,
    RetiredGenerations,
    ControlTopology,
    OriginalRecovery,
    GenerationRegistry,
    RouteInstall,
    Unclassified,
}
impl ReconcileStep {
    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::ManagementGate => "management_gate",
            Self::RetiredGenerations => "retired_generations",
            Self::ControlTopology => "control_topology",
            Self::OriginalRecovery => "original_recovery",
            Self::GenerationRegistry => "generation_registry",
            Self::RouteInstall => "route_install",
            Self::Unclassified => "unclassified",
        }
    }
}
impl std::fmt::Display for ReconcileStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.class())
    }
}

/// The steps one pass could not complete and the typed classes of their
/// causes. A cause's own text may carry provider or path detail and is never
/// kept here.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReconcileOutcome {
    steps: BTreeSet<ReconcileStep>,
    classes: BTreeSet<&'static str>,
}
impl ReconcileOutcome {
    pub(crate) fn failed(&mut self, step: ReconcileStep, cause: &anyhow::Error) {
        self.steps.insert(step);
        self.classes.extend(crate::logging::failure_classes(cause));
    }
    /// A failed step whose cause was already reduced to a fixed class.
    pub(crate) fn failed_as(&mut self, step: ReconcileStep, class: &'static str) {
        self.steps.insert(step);
        self.classes.insert(class);
    }
    /// A pass that stopped early, at the step its error names as context.
    pub(crate) fn stopped(&mut self, error: &anyhow::Error) {
        let step = error
            .downcast_ref::<ReconcileStep>()
            .copied()
            .unwrap_or(ReconcileStep::Unclassified);
        self.failed(step, error);
    }
    pub(crate) fn contains(&self, step: ReconcileStep) -> bool {
        self.steps.contains(&step)
    }
    fn is_clean(&self) -> bool {
        self.steps.is_empty()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ReconcileSchedule {
    /// Between closure checks, and between passes while they succeed.
    pub(crate) interval: Duration,
    /// Consecutive failed passes double the wait from `interval` up to this.
    pub(crate) max_backoff: Duration,
    /// A lasting unavailability is logged again at most this often.
    pub(crate) reminder: Duration,
}
impl ReconcileSchedule {
    /// Closure is still observed within 250 ms. Only passes back off: 0.5 s,
    /// 1 s, 2 s, 4 s, then every 5 s. A key provider or store that keeps
    /// failing is no longer retried four times a second. A route install or
    /// a closed original tenant's fresh admission that was failing still
    /// proceeds within 5 s of its cause clearing.
    pub(crate) const SERVING: Self = Self {
        interval: Duration::from_millis(250),
        max_backoff: Duration::from_secs(5),
        reminder: Duration::from_secs(600),
    };
    fn backoff(&self, failed_in_a_row: u32) -> Duration {
        let factor = 1u32.checked_shl(failed_in_a_row).unwrap_or(u32::MAX);
        self.interval
            .saturating_mul(factor)
            .min(self.max_backoff.max(self.interval))
    }
}

/// One log line the loop owes. Failure counts and first and last occurrence
/// stay visible without a line per failed pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReconcileReport {
    /// The first failed pass after a clean one, or a change in failing steps.
    Unavailable {
        steps: Vec<&'static str>,
        failure_classes: Vec<&'static str>,
        failed_passes: u64,
        retry_after: Duration,
    },
    /// An unavailability that lasted a reminder interval, or that was still
    /// open when the loop stopped.
    StillUnavailable {
        steps: Vec<&'static str>,
        failure_classes: Vec<&'static str>,
        failed_passes: u64,
        first_failure: SystemTime,
        last_failure: SystemTime,
    },
    /// The first clean pass after an unavailability.
    Recovered {
        steps: Vec<&'static str>,
        failed_passes: u64,
        first_failure: SystemTime,
        last_failure: SystemTime,
    },
}
impl ReconcileReport {
    pub(crate) fn log(&self) {
        match self {
            Self::Unavailable {
                steps,
                failure_classes,
                failed_passes,
                retry_after,
            } => tracing::warn!(
                event = "serving_reconciliation_unavailable",
                failed_steps = %steps.join(","),
                failure_classes = %joined_classes(failure_classes),
                failed_passes,
                retry_after_ms = u64::try_from(retry_after.as_millis()).unwrap_or(u64::MAX),
                "serving reconciliation unavailable; will retry"
            ),
            Self::StillUnavailable {
                steps,
                failure_classes,
                failed_passes,
                first_failure,
                last_failure,
            } => tracing::warn!(
                event = "serving_reconciliation_still_unavailable",
                failed_steps = %steps.join(","),
                failure_classes = %joined_classes(failure_classes),
                failed_passes,
                first_failure = %utc(*first_failure),
                last_failure = %utc(*last_failure),
                "serving reconciliation still unavailable"
            ),
            Self::Recovered {
                steps,
                failed_passes,
                first_failure,
                last_failure,
            } => tracing::info!(
                event = "serving_reconciliation_recovered",
                failed_steps = %steps.join(","),
                failed_passes,
                first_failure = %utc(*first_failure),
                last_failure = %utc(*last_failure),
                "serving reconciliation recovered"
            ),
        }
    }
}
fn joined_classes(classes: &[&'static str]) -> String {
    if classes.is_empty() {
        "unclassified".into()
    } else {
        classes.join(",")
    }
}
fn step_classes(steps: &BTreeSet<ReconcileStep>) -> Vec<&'static str> {
    steps.iter().map(|step| step.class()).collect()
}

/// Pass scheduling and the transitions of one unavailability at a time. An
/// unavailability is keyed by its failing steps; its failure classes may vary
/// from pass to pass and are collected between reports.
#[derive(Debug)]
pub(crate) struct ReconcileBackoff {
    schedule: ReconcileSchedule,
    failed_in_a_row: u32,
    /// Absent while passes succeed: every interval is due.
    next_pass: Option<Instant>,
    unavailability: FailureEpisodes<BTreeSet<ReconcileStep>>,
    /// Classes observed since the last report, so no report omits one.
    classes: BTreeSet<&'static str>,
}
impl ReconcileBackoff {
    pub(crate) fn new(schedule: ReconcileSchedule) -> Self {
        Self {
            schedule,
            failed_in_a_row: 0,
            next_pass: None,
            unavailability: FailureEpisodes::new(schedule.reminder),
            classes: BTreeSet::new(),
        }
    }
    pub(crate) fn due(&self, now: Instant) -> bool {
        self.next_pass.is_none_or(|next| now >= next)
    }
    /// Schedule the next pass and return the report this outcome owes, if any.
    pub(crate) fn record(
        &mut self,
        outcome: ReconcileOutcome,
        now: Instant,
        wall: SystemTime,
    ) -> Option<ReconcileReport> {
        if outcome.is_clean() {
            self.failed_in_a_row = 0;
            self.next_pass = None;
            self.classes.clear();
            return self
                .unavailability
                .close()
                .map(|ended| ReconcileReport::Recovered {
                    steps: step_classes(&ended.key),
                    failed_passes: ended.failures,
                    first_failure: ended.first_failure,
                    last_failure: ended.last_failure,
                });
        }
        self.failed_in_a_row = self.failed_in_a_row.saturating_add(1);
        let retry_after = self.schedule.backoff(self.failed_in_a_row);
        self.next_pass = Some(now + retry_after);
        let ReconcileOutcome { steps, classes } = outcome;
        self.classes.extend(classes);
        Some(match self.unavailability.failed(steps, now, wall)? {
            EpisodeReport::Started { key, failures } => ReconcileReport::Unavailable {
                steps: step_classes(&key),
                failure_classes: self.reported_classes(),
                failed_passes: failures,
                retry_after,
            },
            EpisodeReport::Lasting(lasting) => self.still_unavailable(lasting),
        })
    }
    /// The summary owed when the loop ends during an unavailability.
    pub(crate) fn finish(&mut self) -> Option<ReconcileReport> {
        let open = self.unavailability.close()?;
        Some(self.still_unavailable(open))
    }
    fn still_unavailable(
        &mut self,
        open: EpisodeSummary<BTreeSet<ReconcileStep>>,
    ) -> ReconcileReport {
        ReconcileReport::StillUnavailable {
            steps: step_classes(&open.key),
            failure_classes: self.reported_classes(),
            failed_passes: open.failures,
            first_failure: open.first_failure,
            last_failure: open.last_failure,
        }
    }
    fn reported_classes(&mut self) -> Vec<&'static str> {
        std::mem::take(&mut self.classes).into_iter().collect()
    }
}

impl Administration {
    /// Serving reconciliation. Returns only when the control plane has closed:
    /// every later reconciliation, readiness probe and credential renewal would
    /// fail, so the daemon must stop (non-zero) for its service manager to
    /// reopen it, instead of staying up while unable to serve.
    pub(crate) async fn reconcile_while_serving(
        self: Arc<Self>,
        stop: watch::Receiver<bool>,
    ) -> Result<()> {
        let manager: &Self = &self;
        drive_reconciliation(
            ReconcileSchedule::SERVING,
            stop,
            || manager.control_closure(),
            move || manager.reconcile_pass(),
        )
        .await
    }
}

async fn drive_reconciliation<P, F>(
    schedule: ReconcileSchedule,
    mut stop: watch::Receiver<bool>,
    mut closure: impl FnMut() -> Option<(&'static str, &'static str)>,
    mut pass: P,
) -> Result<()>
where
    P: FnMut() -> F,
    F: Future<Output = ReconcileOutcome>,
{
    let mut backoff = ReconcileBackoff::new(schedule);
    loop {
        tokio::select! {
            _ = stop.changed() => {
                if let Some(report) = backoff.finish() {
                    report.log();
                }
                return Ok(());
            }
            _ = tokio::time::sleep(schedule.interval) => {}
        }
        if let Some((closure_cause, key_lease_class)) = closure() {
            if let Some(report) = backoff.finish() {
                report.log();
            }
            tracing::error!(
                event = "control_plane_closed",
                closure_cause,
                key_lease_class,
                "control plane closed; daemon stopping for restart"
            );
            anyhow::bail!("control plane closed; daemon restart required");
        }
        if !backoff.due(Instant::now()) {
            continue;
        }
        let outcome = pass().await;
        if let Some(report) = backoff.record(outcome, Instant::now(), SystemTime::now()) {
            report.log();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::administration::failure_episodes::test_log::Logs;
    use std::{cell::RefCell, collections::VecDeque, time::UNIX_EPOCH};

    fn failed(step: ReconcileStep, code: kasumi_types::ErrorCode) -> ReconcileOutcome {
        let mut outcome = ReconcileOutcome::default();
        let cause =
            anyhow::Error::new(kasumi_types::Error::new(code, "private-cause-text")).context(step);
        outcome.stopped(&cause);
        outcome
    }

    #[test]
    fn failed_passes_back_off_to_the_bound_and_a_clean_pass_resets_it() {
        let mut backoff = ReconcileBackoff::new(ReconcileSchedule::SERVING);
        let wall = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut now = Instant::now();
        assert!(backoff.due(now));
        let mut waits = Vec::new();
        for _ in 0..9 {
            backoff.record(
                failed(
                    ReconcileStep::ControlTopology,
                    kasumi_types::ErrorCode::Sealed,
                ),
                now,
                wall,
            );
            let next = backoff.next_pass.unwrap();
            waits.push(next - now);
            assert!(!backoff.due(next - Duration::from_millis(1)));
            now = next;
            assert!(backoff.due(now));
        }
        let ms = Duration::from_millis;
        assert_eq!(
            waits,
            [
                ms(500),
                ms(1_000),
                ms(2_000),
                ms(4_000),
                ms(5_000),
                ms(5_000),
                ms(5_000),
                ms(5_000),
                ms(5_000),
            ]
        );

        backoff.record(ReconcileOutcome::default(), now, wall);
        assert!(
            backoff.due(now),
            "a clean pass leaves the next interval due"
        );
        backoff.record(
            failed(
                ReconcileStep::ControlTopology,
                kasumi_types::ErrorCode::Sealed,
            ),
            now,
            wall,
        );
        assert_eq!(
            backoff.next_pass.unwrap() - now,
            ms(500),
            "a new unavailability starts from the shortest wait"
        );
    }

    #[test]
    fn an_unavailability_is_reported_by_its_transitions_not_per_pass() {
        let schedule = ReconcileSchedule::SERVING;
        let mut backoff = ReconcileBackoff::new(schedule);
        let start = Instant::now();
        let first_wall = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let topology = || {
            failed(
                ReconcileStep::ControlTopology,
                kasumi_types::ErrorCode::Sealed,
            )
        };

        assert_eq!(
            backoff.record(topology(), start, first_wall),
            Some(ReconcileReport::Unavailable {
                steps: vec!["control_topology"],
                failure_classes: vec!["sealed"],
                failed_passes: 1,
                retry_after: Duration::from_millis(500),
            })
        );
        // Repeating the same failure stays silent until the reminder.
        let mut now = start;
        let mut wall = first_wall;
        for _ in 1..20 {
            now += Duration::from_secs(29);
            wall += Duration::from_secs(29);
            assert_eq!(backoff.record(topology(), now, wall), None);
        }

        // Another failing step is a state change, reported with the count.
        let mut both = topology();
        both.failed(
            ReconcileStep::RetiredGenerations,
            &anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "private-path",
            )),
        );
        now += Duration::from_secs(29);
        wall += Duration::from_secs(29);
        assert_eq!(
            backoff.record(both.clone(), now, wall),
            Some(ReconcileReport::Unavailable {
                steps: vec!["retired_generations", "control_topology"],
                failure_classes: vec!["io_storage_full", "sealed"],
                failed_passes: 21,
                retry_after: Duration::from_secs(5),
            })
        );

        // A lasting unavailability is reminded once per reminder interval.
        let changed_at = now;
        let mut reminders = Vec::new();
        while now < changed_at + schedule.reminder * 2 {
            now += Duration::from_secs(30);
            wall += Duration::from_secs(30);
            if let Some(report) = backoff.record(both.clone(), now, wall) {
                reminders.push(report);
            }
        }
        assert_eq!(reminders.len(), 2);
        let ReconcileReport::StillUnavailable {
            steps,
            failure_classes,
            first_failure,
            ..
        } = &reminders[0]
        else {
            panic!("expected a reminder, got {:?}", reminders[0]);
        };
        assert_eq!(steps, &["retired_generations", "control_topology"]);
        assert_eq!(failure_classes, &["io_storage_full", "sealed"]);
        assert_eq!(*first_failure, first_wall);

        // The first clean pass reports the whole unavailability once.
        let last_wall = wall;
        now += Duration::from_secs(30);
        wall += Duration::from_secs(30);
        let Some(ReconcileReport::Recovered {
            steps,
            failed_passes,
            first_failure,
            last_failure,
        }) = backoff.record(ReconcileOutcome::default(), now, wall)
        else {
            panic!("a clean pass must report recovery");
        };
        assert_eq!(steps, ["retired_generations", "control_topology"]);
        assert_eq!(failed_passes, 21 + 40);
        assert_eq!((first_failure, last_failure), (first_wall, last_wall));
        assert_eq!(backoff.record(ReconcileOutcome::default(), now, wall), None);
        assert_eq!(backoff.finish(), None);

        // A later failure opens a new unavailability counted from one.
        let Some(ReconcileReport::Unavailable { failed_passes, .. }) =
            backoff.record(topology(), now, wall)
        else {
            panic!("a new unavailability must be reported");
        };
        assert_eq!(failed_passes, 1);
        assert!(matches!(
            backoff.finish(),
            Some(ReconcileReport::StillUnavailable {
                failed_passes: 1,
                ..
            })
        ));
    }

    /// Millisecond intervals keep the real loop fast. Elapsed-time assertions
    /// are lower bounds only, since a loaded host can only delay a pass.
    const FAST: ReconcileSchedule = ReconcileSchedule {
        interval: Duration::from_millis(1),
        max_backoff: Duration::from_millis(8),
        reminder: Duration::from_secs(3_600),
    };

    #[tokio::test]
    async fn the_loop_backs_off_logs_transitions_and_recovers_after_a_success() {
        let logs = Logs::default();
        let _subscriber = logs.capture();
        let (stop_sender, stop) = watch::channel(false);
        let topology = || {
            failed(
                ReconcileStep::ControlTopology,
                kasumi_types::ErrorCode::Sealed,
            )
        };
        let mut script = VecDeque::new();
        script.extend((0..12).map(|_| topology()));
        script.push_back(ReconcileOutcome::default());
        script.extend((0..2).map(|_| topology()));
        script.push_back(ReconcileOutcome::default());
        script.push_back(ReconcileOutcome::default());
        let passes = script.len();
        let script = RefCell::new(script);
        let started = RefCell::new(Vec::new());
        drive_reconciliation(
            FAST,
            stop,
            || None,
            || {
                started.borrow_mut().push(Instant::now());
                let outcome = script.borrow_mut().pop_front().unwrap();
                if script.borrow().is_empty() {
                    stop_sender.send_replace(true);
                }
                std::future::ready(outcome)
            },
        )
        .await
        .unwrap();

        let started = started.into_inner();
        assert_eq!(started.len(), passes);
        let waits = started
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .collect::<Vec<_>>();
        let ms = Duration::from_millis;
        let minimum = [2, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 1, 2, 4, 1].map(ms);
        for (index, (wait, minimum)) in waits.iter().zip(minimum).enumerate() {
            assert!(
                *wait >= minimum,
                "pass {index} waited {wait:?} < {minimum:?}"
            );
        }

        let events = logs.events();
        let names = events
            .iter()
            .map(|event| event["fields"]["event"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "serving_reconciliation_unavailable",
                "serving_reconciliation_recovered",
                "serving_reconciliation_unavailable",
                "serving_reconciliation_recovered",
            ],
            "{events:#?}"
        );
        let unavailable = &events[0]["fields"];
        assert_eq!(unavailable["failed_steps"], "control_topology");
        assert_eq!(unavailable["failure_classes"], "sealed");
        assert_eq!(unavailable["failed_passes"], 1);
        assert_eq!(unavailable["retry_after_ms"], 2);
        assert_eq!(events[0]["level"], "WARN");
        let recovered = &events[1]["fields"];
        assert_eq!(recovered["failed_steps"], "control_topology");
        assert_eq!(recovered["failed_passes"], 12);
        assert_eq!(events[1]["level"], "INFO");
        let first = recovered["first_failure"].as_str().unwrap();
        let last = recovered["last_failure"].as_str().unwrap();
        assert!(
            first.ends_with('Z') && last.ends_with('Z'),
            "{first} {last}"
        );
        assert_eq!(events[3]["fields"]["failed_passes"], 2);
    }

    #[tokio::test]
    async fn closure_during_an_unavailability_logs_its_summary_and_stops() {
        let logs = Logs::default();
        let _subscriber = logs.capture();
        let (_stop_sender, stop) = watch::channel(false);
        let passes = RefCell::new(0u32);
        let error = drive_reconciliation(
            FAST,
            stop,
            || (*passes.borrow() >= 3).then_some(("key_lease_sealed", "lease_expired")),
            || {
                *passes.borrow_mut() += 1;
                std::future::ready(failed(
                    ReconcileStep::RetiredGenerations,
                    kasumi_types::ErrorCode::Sealed,
                ))
            },
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("control plane closed"));
        assert_eq!(*passes.borrow(), 3);

        let events = logs.events();
        let names = events
            .iter()
            .map(|event| event["fields"]["event"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "serving_reconciliation_unavailable",
                "serving_reconciliation_still_unavailable",
                "control_plane_closed",
            ]
        );
        assert_eq!(events[1]["fields"]["failed_passes"], 3);
        assert_eq!(events[1]["fields"]["failed_steps"], "retired_generations");
        assert_eq!(events[2]["fields"]["closure_cause"], "key_lease_sealed");
        assert_eq!(events[2]["level"], "ERROR");
    }
}
