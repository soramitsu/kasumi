//! Fixed-label timing diagnostics. An unfinished phase does not imply rollback.
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const TARGET: &str = "kasumi_engine::restore_phase";
// Process-local diagnostic correlation only; never a durable operation identity.
static NEXT_PHASE: AtomicU64 = AtomicU64::new(1);

pub(crate) struct VerificationPhase(Option<ActivePhase>);

struct ActivePhase {
    name: &'static str,
    id: u64,
    started: Instant,
    deadline: Option<super::VerificationDeadline>,
}

impl VerificationPhase {
    pub(crate) fn start(name: &'static str, deadline: Option<super::VerificationDeadline>) -> Self {
        if !tracing::enabled!(target: TARGET, tracing::Level::DEBUG) {
            return Self(None);
        }
        let phase = ActivePhase {
            name,
            id: NEXT_PHASE.fetch_add(1, Ordering::Relaxed),
            started: Instant::now(),
            deadline,
        };
        phase.emit("restore_phase_started", "started");
        Self(Some(phase))
    }

    pub(crate) fn complete(mut self) {
        if let Some(phase) = self.0.take() {
            phase.emit("restore_phase_ended", "succeeded");
        }
    }
}

impl Drop for VerificationPhase {
    fn drop(&mut self) {
        if let Some(phase) = self.0.take() {
            // Early error, cancellation, future drop and unwinding all end here.
            // The event makes no claim about publication or resource rollback.
            phase.emit("restore_phase_ended", "unfinished");
        }
    }
}

impl ActivePhase {
    fn emit(&self, event: &'static str, outcome: &'static str) {
        let remaining_ms = self.deadline.map(|deadline| {
            milliseconds(
                deadline
                    .0
                    .saturating_duration_since(tokio::time::Instant::now()),
            )
        });
        tracing::debug!(
            target: TARGET,
            event,
            phase = self.name,
            phase_id = self.id,
            elapsed_ms = milliseconds(self.started.elapsed()),
            remaining_ms,
            outcome,
            "restore phase timing"
        );
    }
}

fn milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Numeric framing diagnostics only: no tenant, key, identifier or payload.
/// This uses the already inspected layout and performs no additional reads.
pub(super) fn snapshot_layout(layout: &crate::snapshot_codec::StreamSummary) {
    if !tracing::enabled!(target: TARGET, tracing::Level::DEBUG) {
        return;
    }
    tracing::debug!(
        target: TARGET,
        event = "snapshot_layout",
        records = layout.records,
        framed_bytes = layout.bytes,
        "restore snapshot layout"
    );
    for (kind, layout) in layout.kinds.iter().enumerate() {
        if layout.records != 0 {
            tracing::debug!(
                target: TARGET,
                event = "snapshot_kind_layout",
                kind = kind as u64,
                records = layout.records,
                framed_bytes = layout.framed_bytes,
                maximum_payload_bytes = layout.maximum_payload_bytes,
                "restore snapshot kind layout"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        future::Future,
        sync::{Arc, Mutex},
        task::Poll,
    };
    use tracing::{Dispatch, Event, Subscriber, field::Visit};
    use tracing_subscriber::{Layer, layer::Context, prelude::*};

    type Fields = BTreeMap<String, String>;
    #[derive(Clone, Default)]
    struct Events(Arc<Mutex<Vec<Fields>>>);

    struct Visitor(Fields);
    impl Visit for Visitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().into(), format!("{value:?}"));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().into(), value.into());
        }
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.0.insert(field.name().into(), value.to_string());
        }
    }
    impl<S: Subscriber> Layer<S> for Events {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            let mut visitor = Visitor(Fields::new());
            event.record(&mut visitor);
            self.0.lock().unwrap().push(visitor.0);
        }
    }
    impl Events {
        fn dispatch(&self) -> Dispatch {
            Dispatch::new(
                tracing_subscriber::registry()
                    .with(tracing_subscriber::filter::filter_fn(|metadata| {
                        metadata.target() == TARGET && *metadata.level() <= tracing::Level::DEBUG
                    }))
                    .with(self.clone()),
            )
        }
        fn records(&self) -> Vec<Fields> {
            self.0.lock().unwrap().clone()
        }
    }

    fn pair(records: &[Fields], name: &str, outcome: &str) {
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["event"], "restore_phase_started");
        assert_eq!(records[0]["outcome"], "started");
        assert_eq!(records[1]["event"], "restore_phase_ended");
        assert_eq!(records[1]["outcome"], outcome);
        assert_eq!(records[0]["phase"], name);
        assert_eq!(records[1]["phase"], name);
        assert_eq!(records[0]["phase_id"], records[1]["phase_id"]);
        for record in records {
            assert!(record.keys().all(|key| matches!(
                key.as_str(),
                "event"
                    | "phase"
                    | "phase_id"
                    | "elapsed_ms"
                    | "remaining_ms"
                    | "outcome"
                    | "message"
            )));
        }
    }

    #[test]
    fn phase_success_and_early_return_keep_fixed_fields_and_original_deadline() {
        let events = Events::default();
        tracing::dispatcher::with_default(&events.dispatch(), || {
            let deadline = super::super::VerificationDeadline::new(60_000).unwrap();
            VerificationPhase::start("fixture_success", Some(deadline)).complete();
            let result: Result<(), &'static str> = {
                let _phase = VerificationPhase::start("fixture_error", None);
                Err("unlogged source error")
            };
            assert!(result.is_err());
            tracing::error!(target: "unrelated_dependency", value = "unlogged payload");
        });
        let records = events.records();
        pair(&records[..2], "fixture_success", "succeeded");
        pair(&records[2..], "fixture_error", "unfinished");
        let start = records[0]["remaining_ms"].parse::<u64>().unwrap();
        let end = records[1]["remaining_ms"].parse::<u64>().unwrap();
        assert!(end <= start && start <= 60_000);
        assert!(!records[2].contains_key("remaining_ms"));
        assert!(!records[3].contains_key("remaining_ms"));
        assert_ne!(records[0]["phase_id"], records[2]["phase_id"]);
    }

    #[test]
    fn phase_disabled_target_keeps_no_timer_or_id_state() {
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
            let phase = VerificationPhase::start("disabled", None);
            assert!(phase.0.is_none());
            phase.complete();
        });
    }

    #[tokio::test]
    async fn phase_dropped_async_future_reports_unfinished() {
        let events = Events::default();
        let dispatch = events.dispatch();
        let mut future = Box::pin(async {
            let phase = VerificationPhase::start("fixture_async", None);
            std::future::pending::<()>().await;
            phase.complete();
        });
        std::future::poll_fn(|context| {
            tracing::dispatcher::with_default(&dispatch, || {
                assert!(future.as_mut().poll(context).is_pending());
            });
            Poll::Ready(())
        })
        .await;
        assert_eq!(events.records().len(), 1);
        tracing::dispatcher::with_default(&dispatch, || drop(future));
        pair(&events.records(), "fixture_async", "unfinished");
    }

    #[tokio::test]
    async fn phase_blocking_worker_finishes_after_its_waiter_times_out() {
        let events = Events::default();
        let dispatch = events.dispatch();
        let (started, entered) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (finished, completed) = tokio::sync::oneshot::channel();
        let worker = tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                let phase = VerificationPhase::start("fixture_worker", None);
                started.send(()).unwrap();
                released.recv().unwrap();
                phase.complete();
                finished.send(()).unwrap();
            });
        });
        entered.await.unwrap();
        let timed_out = tokio::time::timeout(Duration::ZERO, worker).await;
        let while_blocked = events.records();
        // Always release the actual worker before asserting about its waiter.
        release.send(()).unwrap();
        completed.await.unwrap();
        assert!(timed_out.is_err());
        assert_eq!(while_blocked.len(), 1);
        pair(&events.records(), "fixture_worker", "succeeded");
    }
}
