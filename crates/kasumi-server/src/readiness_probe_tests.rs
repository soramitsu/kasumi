use super::*;
use kasumi_engine::admission::AdmissionConfig;
use std::{
    future::poll_fn,
    sync::atomic::{AtomicUsize, Ordering},
    task::Poll,
    time::Duration,
};

fn admission() -> Arc<NodeAdmission> {
    let mut config = AdmissionConfig {
        max_inflight_bytes: Some(PROBE_BYTES * 2),
        max_sample_age_ms: 60_000,
        ..Default::default()
    };
    let bookkeeping = NodeAdmission::required_bookkeeping_bytes(&config).unwrap();
    config.max_inflight_bytes = Some(bookkeeping.checked_add(PROBE_BYTES * 2).unwrap());
    NodeAdmission::new(config).unwrap()
}

#[tokio::test]
async fn repeated_timeouts_keep_one_actual_queued_probe_and_its_charge() {
    let admission = admission();
    let bookkeeping = admission.snapshot().bookkeeping_bytes;
    let slot = ProbeSlot::default();
    let queued = Arc::new(AtomicUsize::new(0));
    let (reply, receiver) = tokio::sync::oneshot::channel();
    let dispatched = queued.clone();
    slot.start(&admission, async move {
        dispatched.fetch_add(1, Ordering::AcqRel);
        receiver.await?;
        Ok(true)
    })
    .await
    .unwrap();
    let mut observation = Box::pin(slot.observe());
    poll_fn(|cx| {
        assert!(observation.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(observation);
    for _ in 0..16 {
        assert!(
            tokio::time::timeout(Duration::from_millis(1), slot.observe())
                .await
                .is_err()
        );
        let attempted = queued.clone();
        assert!(
            slot.start(&admission, async move {
                attempted.fetch_add(1, Ordering::AcqRel);
                Ok(true)
            })
            .await
            .is_err()
        );
        assert_eq!(queued.load(Ordering::Acquire), 1);
        assert_eq!(
            admission.snapshot().reserved_bytes,
            bookkeeping + PROBE_BYTES
        );
        assert_eq!(admission.snapshot().inflight_operations, 0);
    }
    reply.send(()).unwrap();
    assert_eq!(slot.observe().await, Outcome::Healthy);
    assert_eq!(admission.snapshot().reserved_bytes, bookkeeping);
    slot.drain_after_group_shutdown().await.unwrap();
}

#[derive(Debug)]
struct ProbeFailure(Arc<()>);
impl std::fmt::Display for ProbeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original probe error")
    }
}
impl std::error::Error for ProbeFailure {}

#[tokio::test]
async fn cancelled_probe_drain_retains_original_future_charge_and_typed_failure() {
    let admission = admission();
    let bookkeeping = admission.snapshot().bookkeeping_bytes;
    let slot = ProbeSlot::default();
    let original = Arc::new(());
    let identity = original.clone();
    let (reply, receiver) = tokio::sync::oneshot::channel();
    slot.start(&admission, async move {
        receiver.await?;
        Err(ProbeFailure(identity).into())
    })
    .await
    .unwrap();
    let mut draining = Box::pin(slot.drain_after_group_shutdown());
    poll_fn(|cx| {
        assert!(draining.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(draining);
    assert_eq!(
        admission.snapshot().reserved_bytes,
        bookkeeping + PROBE_BYTES
    );
    assert!(slot.start(&admission, async { Ok(true) }).await.is_err());
    reply.send(()).unwrap();
    let failure = slot.drain_after_group_shutdown().await.unwrap_err();
    assert_eq!(
        failure.completion(),
        kasumi_types::drain::DrainCompletion::Complete
    );
    let issue = &failure.issues()[0];
    assert!(Arc::ptr_eq(
        &original,
        &issue.error().downcast_ref::<ProbeFailure>().unwrap().0
    ));
    assert_eq!(admission.snapshot().reserved_bytes, bookkeeping);
    let repeated = slot.drain_after_group_shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(issue, &repeated.issues()[0]));
}

#[tokio::test]
async fn panicked_probe_keeps_original_payload_and_charge_until_core_shutdown() {
    let admission = admission();
    let bookkeeping = admission.snapshot().bookkeeping_bytes;
    let slot = ProbeSlot::default();
    let payload = Arc::new(());
    let weak = Arc::downgrade(&payload);
    slot.start(&admission, async move {
        std::panic::panic_any(payload);
    })
    .await
    .unwrap();
    assert_eq!(slot.observe().await, Outcome::Failed);
    assert_eq!(
        admission.snapshot().reserved_bytes,
        bookkeeping + PROBE_BYTES
    );
    assert!(weak.upgrade().is_some());
    assert!(slot.start(&admission, async { Ok(true) }).await.is_err());
    let failure = slot.drain_after_group_shutdown().await.unwrap_err();
    assert!(
        failure.issues()[0]
            .error()
            .downcast_ref::<crate::startup_preparation::PreparationPanic>()
            .is_some()
    );
    assert_eq!(admission.snapshot().reserved_bytes, bookkeeping);
    assert!(weak.upgrade().is_some());
    let repeated = slot.drain_after_group_shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(&failure.issues()[0], &repeated.issues()[0]));
}
