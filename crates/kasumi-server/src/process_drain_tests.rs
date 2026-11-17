//! The serving registry and background custody are process-wide in this test
//! binary too, so these cases drive the bounded traversal over the startup
//! registries, which resolve per test runtime. `scripts/smoke_dev_standalone.py`
//! checks the whole traversal on a real daemon's SIGTERM.
use super::*;
use crate::startup_owner::{Kind, Runtime};
use std::{
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
};
use tokio::sync::{Notify, oneshot};

const LIVENESS: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Observation {
    closing: Notify,
    release: Notify,
    closed: AtomicBool,
}
struct Candidate {
    report: DrainReport,
    observation: Arc<Observation>,
    fail: bool,
}
impl Runtime for Candidate {
    fn close(&mut self) -> Pin<Box<dyn Future<Output = DrainResult> + Send + '_>> {
        Box::pin(async move {
            self.observation.closing.notify_one();
            self.observation.release.notified().await;
            self.observation.closed.store(true, Ordering::Release);
            if self.fail {
                self.report.record(
                    "candidate",
                    0,
                    anyhow::anyhow!("original abandoned close failure"),
                );
            }
            self.report.complete()
        })
    }
}

/// An operator open whose caller is cancelled before its owner is published:
/// the registry's retained task then closes that owner.
async fn abandoned_open(fail: bool) -> Arc<Observation> {
    let observation = Arc::new(Observation::default());
    let candidate = Candidate {
        report: DrainReport::default(),
        observation: observation.clone(),
        fail,
    };
    let (publish, published) = oneshot::channel::<()>();
    let mut opening = Box::pin(crate::startup_owner::open(
        Kind::LocalOperator,
        async move {
            published.await?;
            Ok(candidate)
        },
    ));
    std::future::poll_fn(|cx| {
        assert!(opening.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(opening);
    publish.send(()).unwrap();
    tokio::time::timeout(LIVENESS, observation.closing.notified())
        .await
        .unwrap();
    observation
}

fn final_drain(grace: Duration) -> impl Future<Output = ProcessDrain> {
    bounded(grace, |failed| async move {
        seal_startups().await;
        startups(&failed).await
    })
}

#[tokio::test]
async fn final_drain_joins_the_cleanup_of_an_open_whose_caller_was_cancelled() {
    let observation = abandoned_open(false).await;
    let mut draining = Box::pin(final_drain(LIVENESS));
    std::future::poll_fn(|cx| {
        assert!(draining.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // Returning from main here would have cancelled the close mid-way.
    assert!(!observation.closed.load(Ordering::Acquire));
    observation.release.notify_one();
    assert_eq!(draining.await, ProcessDrain::Clean);
    assert!(observation.closed.load(Ordering::Acquire));
    assert_eq!(final_drain(LIVENESS).await, ProcessDrain::Clean);
}

#[tokio::test]
async fn final_drain_reports_an_abandoned_owners_failure_as_a_failed_exit() {
    let observation = abandoned_open(true).await;
    observation.release.notify_one();
    assert_eq!(final_drain(LIVENESS).await, ProcessDrain::Failed);
    assert!(observation.closed.load(Ordering::Acquire));
    // The registry returned that failure once, to this process's exit.
    assert_eq!(final_drain(LIVENESS).await, ProcessDrain::Clean);
}

#[tokio::test]
async fn expired_grace_reports_retained_and_leaves_the_owner_in_its_registry() {
    let observation = abandoned_open(false).await;
    assert_eq!(
        final_drain(Duration::from_millis(50)).await,
        ProcessDrain::Retained
    );
    assert!(!observation.closed.load(Ordering::Acquire));
    // The cancelled traversal dropped only its wait: a later one still joins.
    observation.release.notify_one();
    assert_eq!(final_drain(LIVENESS).await, ProcessDrain::Clean);
    assert!(observation.closed.load(Ordering::Acquire));
}

#[tokio::test]
async fn final_drain_seals_admission_so_no_later_open_starts() {
    let observation = abandoned_open(false).await;
    let mut draining = Box::pin(final_drain(LIVENESS));
    std::future::poll_fn(|cx| {
        assert!(draining.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // An open arriving during the final drain would start after its census:
    // it waits for the registry, then finds it sealed.
    let started = Arc::new(AtomicBool::new(false));
    let opening = started.clone();
    let mut refused = Box::pin(crate::startup_owner::open(
        Kind::LocalOperator,
        async move {
            opening.store(true, Ordering::Release);
            Ok(Candidate {
                report: DrainReport::default(),
                observation: Arc::new(Observation::default()),
                fail: false,
            })
        },
    ));
    std::future::poll_fn(|cx| {
        assert!(refused.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    observation.release.notify_one();
    assert_eq!(draining.await, ProcessDrain::Clean);
    assert!(
        tokio::time::timeout(LIVENESS, refused)
            .await
            .unwrap()
            .is_err()
    );
    assert!(!started.load(Ordering::Acquire));
}
