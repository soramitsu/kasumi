//! A repeating failure is logged as an episode. A report is owed when the
//! episode starts, when what fails changes, at most once per reminder interval
//! while it lasts, and when it ends, never once per failed attempt. Every
//! report can carry the failure count and the first and last failure.
use std::time::{Duration, SystemTime};
use tokio::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EpisodeSummary<K> {
    pub(crate) key: K,
    pub(crate) failures: u64,
    pub(crate) first_failure: SystemTime,
    pub(crate) last_failure: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EpisodeReport<K> {
    /// The first failure after a success, or a failure under another key.
    /// `failures` counts the whole episode so far.
    Started { key: K, failures: u64 },
    /// An episode that lasted another reminder interval.
    Lasting(EpisodeSummary<K>),
}

/// At most one open episode. `K` holds the fixed classes that identify what is
/// failing; a different key is a state change worth a report.
#[derive(Debug)]
pub(crate) struct FailureEpisodes<K> {
    reminder: Duration,
    open: Option<OpenEpisode<K>>,
}
#[derive(Debug)]
struct OpenEpisode<K> {
    summary: EpisodeSummary<K>,
    reported_at: Instant,
}
impl<K: Clone + PartialEq> FailureEpisodes<K> {
    pub(crate) fn new(reminder: Duration) -> Self {
        Self {
            reminder,
            open: None,
        }
    }
    /// Count one failure under `key` and return the report it owes, if any.
    pub(crate) fn failed(
        &mut self,
        key: K,
        now: Instant,
        wall: SystemTime,
    ) -> Option<EpisodeReport<K>> {
        let Some(open) = &mut self.open else {
            self.open = Some(OpenEpisode {
                summary: EpisodeSummary {
                    key: key.clone(),
                    failures: 1,
                    first_failure: wall,
                    last_failure: wall,
                },
                reported_at: now,
            });
            return Some(EpisodeReport::Started { key, failures: 1 });
        };
        let summary = &mut open.summary;
        summary.failures = summary.failures.saturating_add(1);
        summary.last_failure = wall;
        if summary.key != key {
            summary.key = key.clone();
            open.reported_at = now;
            return Some(EpisodeReport::Started {
                key,
                failures: summary.failures,
            });
        }
        if now.saturating_duration_since(open.reported_at) >= self.reminder {
            open.reported_at = now;
            return Some(EpisodeReport::Lasting(summary.clone()));
        }
        None
    }
    /// Close the open episode, if any: after a success it has ended, and when
    /// the reporter stops it is still failing.
    pub(crate) fn close(&mut self) -> Option<EpisodeSummary<K>> {
        self.open.take().map(|open| open.summary)
    }
}

/// How reports log the first and last failure.
pub(crate) fn utc(time: SystemTime) -> String {
    ::time::OffsetDateTime::from(time)
        .format(&::time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unrepresentable".into())
}

/// Captures what the daemon would log, in its JSON layout, on this thread.
#[cfg(test)]
pub(crate) mod test_log {
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    pub(crate) struct Logs(Arc<Mutex<Vec<u8>>>);
    impl Write for Logs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }
    impl Logs {
        pub(crate) fn capture(&self) -> tracing::subscriber::DefaultGuard {
            tracing::subscriber::set_default(
                tracing_subscriber::registry().with(
                    tracing_subscriber::fmt::layer()
                        .json()
                        .with_ansi(false)
                        .with_current_span(false)
                        .with_span_list(false)
                        .with_writer(self.clone()),
                ),
            )
        }
        /// Every line as JSON. Test causes carry `private-` text, which must
        /// never reach a log line.
        pub(crate) fn events(&self) -> Vec<serde_json::Value> {
            let bytes = self.0.lock().unwrap().clone();
            assert!(
                !String::from_utf8_lossy(&bytes).contains("private-"),
                "a cause's own text reached the log"
            );
            bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
                .collect()
        }
        pub(crate) fn event_names(&self) -> Vec<String> {
            self.events()
                .iter()
                .map(|event| event["fields"]["event"].as_str().unwrap().to_owned())
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn an_episode_reports_start_key_changes_reminders_and_its_end() {
        let mut episodes = FailureEpisodes::new(Duration::from_secs(600));
        let start = Instant::now();
        let first = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let at = |seconds: u64| {
            (
                start + Duration::from_secs(seconds),
                first + Duration::from_secs(seconds),
            )
        };
        let (now, wall) = at(0);
        assert_eq!(
            episodes.failed("a", now, wall),
            Some(EpisodeReport::Started {
                key: "a",
                failures: 1
            })
        );
        let mut reports = Vec::new();
        for second in 1..1_800 {
            let (now, wall) = at(second);
            reports.extend(episodes.failed("a", now, wall));
        }
        assert_eq!(
            reports,
            [600, 1_200]
                .map(|second| EpisodeReport::Lasting(EpisodeSummary {
                    key: "a",
                    failures: second + 1,
                    first_failure: first,
                    last_failure: at(second).1,
                }))
                .to_vec()
        );
        let (now, wall) = at(1_800);
        assert_eq!(
            episodes.failed("b", now, wall),
            Some(EpisodeReport::Started {
                key: "b",
                failures: 1_801
            })
        );
        // A key change restarts the reminder interval.
        let (now, wall) = at(2_399);
        assert_eq!(episodes.failed("b", now, wall), None);
        assert_eq!(
            episodes.close(),
            Some(EpisodeSummary {
                key: "b",
                failures: 1_802,
                first_failure: first,
                last_failure: wall,
            })
        );
        assert_eq!(episodes.close(), None);
        let (now, wall) = at(2_400);
        assert_eq!(
            episodes.failed("b", now, wall),
            Some(EpisodeReport::Started {
                key: "b",
                failures: 1
            }),
            "a new episode counts from one"
        );
    }

    #[test]
    fn occurrences_are_logged_as_utc_rfc3339() {
        let at = UNIX_EPOCH + Duration::from_millis(1_800_000_000_250);
        assert_eq!(utc(at), "2027-01-15T08:00:00.25Z");
    }
}
