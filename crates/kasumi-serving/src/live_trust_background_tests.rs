use super::*;
use crate::{BackgroundWork, BackgroundWorkBudget};
use kasumi_types::drain::DrainCompletion;
use std::{
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
    time::Duration,
};

fn live(capacity: usize) -> Arc<LiveSignerTrust> {
    let key =
        ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let root = crate::test_utils::FixtureSigningRoot::from_pkcs8(key.as_ref()).unwrap();
    let signing = root
        .install(
            crate::AuthorityManifest {
                authority_id: Uuid::new_v4(),
                partitions: std::collections::BTreeMap::from([(
                    0,
                    crate::AuthorityPartition {
                        group: "worker-test".into(),
                        public_key: root.public_key(),
                    },
                )]),
                lifecycle_controls: Default::default(),
                max_lease_ms: 1000,
                clock_rate_error_ppm: 0,
            },
            0,
        )
        .unwrap();
    let live = signing.verifier;
    live.state.lock().unwrap().work_budget =
        BackgroundWorkBudget::new(capacity, Arc::new(())).unwrap();
    live
}
#[tokio::test]
async fn live_close_waits_for_actual_worker_registration_publication() {
    let live = live(1);
    let worker = Arc::new(BackgroundWork::default());
    let pause = worker.pause_before_spawn();
    let executor = tokio::runtime::Handle::current();
    let registering = live.clone();
    let registered = std::thread::spawn(move || {
        let _runtime = executor.enter();
        registering.start_background_work(worker, async {})
    });
    tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
        .await
        .unwrap();
    let (closed, mut completion) = tokio::sync::oneshot::channel();
    let closing = live.clone();
    let closer = std::thread::spawn(move || {
        closing.close();
        closed.send(()).unwrap();
    });
    let crossed = tokio::time::timeout(Duration::from_millis(50), &mut completion)
        .await
        .is_ok();
    pause.release.wait();
    registered.join().unwrap().unwrap();
    closer.join().unwrap();
    assert!(!crossed, "live close crossed worker registration");
    assert_eq!(live.state.lock().unwrap().workers.len(), 1);
    live.drain_background_work().await.unwrap();
}

#[tokio::test]
async fn close_and_capacity_reject_unpolled_work_and_success_churn_is_bounded() {
    let live = live(1);
    for _ in 0..128 {
        let worker = Arc::new(BackgroundWork::default());
        live.start_background_work(worker.clone(), async {})
            .unwrap();
        worker.drain().await.unwrap();
        drop(worker);
        assert_eq!(live.state.lock().unwrap().workers.len(), 1);
    }
    let worker = Arc::new(BackgroundWork::default());
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    live.start_background_work(worker, async move {
        waiting.await.unwrap();
    })
    .unwrap();
    let called = Arc::new(AtomicBool::new(false));
    let marker = called.clone();
    assert!(
        live.start_background_work(Arc::new(BackgroundWork::default()), async move {
            marker.store(true, Ordering::Release);
        })
        .is_err()
    );
    live.close();
    assert!(
        live.start_background_work(Arc::new(BackgroundWork::default()), async {
            panic!("closed registration polled task");
        })
        .is_err()
    );
    assert!(!called.load(Ordering::Acquire));
    assert!(!live.background_drained());
    release.send(()).unwrap();
    live.drain_background_work().await.unwrap();
    assert!(live.background_drained());
}
#[tokio::test]
async fn cancelled_multiworker_drain_keeps_original_failure_and_seals_registration() {
    let live = live(3);
    let failed = Arc::new(BackgroundWork::default());
    let (fail, failing) = tokio::sync::oneshot::channel::<()>();
    live.start_background_work(failed.clone(), async move {
        failing.await.unwrap();
        panic!("retained failure");
    })
    .unwrap();
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    live.start_background_work(Arc::new(BackgroundWork::default()), async move {
        waiting.await.unwrap();
    })
    .unwrap();
    fail.send(()).unwrap();
    let first = failed.drain().await.unwrap_err();
    drop(failed);
    // The strong outcome registry survives the public worker facade.
    assert!(
        live.start_background_work(Arc::new(BackgroundWork::default()), async {
            panic!("failed trust spawned")
        })
        .is_err()
    );
    let mut draining = Box::pin(live.drain_background_work());
    std::future::poll_fn(|cx| {
        assert!(draining.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(draining);
    release.send(()).unwrap();
    let result = live.drain_background_work().await.unwrap_err();
    assert_eq!(result.completion(), DrainCompletion::Complete);
    assert!(Arc::ptr_eq(&first.issues()[0], &result.issues()[0]));
    assert_eq!(live.state.lock().unwrap().work_report.issues().len(), 1);
}
#[tokio::test]
async fn resource_owner_drops_after_actual_join_without_a_registry_cycle() {
    struct Runtime {
        _live: Arc<LiveSignerTrust>,
        _worker: Arc<BackgroundWork>,
    }
    let live = live(1);
    let worker = Arc::new(BackgroundWork::default());
    let runtime = Arc::new(Runtime {
        _live: live.clone(),
        _worker: worker.clone(),
    });
    let weak = Arc::downgrade(&runtime);
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    live.start_background_work(worker, async move {
        waiting.await.unwrap();
        drop(runtime);
    })
    .unwrap();
    assert!(weak.upgrade().is_some());
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), live.drain_background_work())
        .await
        .unwrap()
        .unwrap();
    assert!(weak.upgrade().is_none());
}
