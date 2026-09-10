use super::*;
use kasumi_types::drain::DrainCompletion;
use std::{future::Future, task::Poll, time::Duration};

fn budget(slots: usize) -> BackgroundWorkBudget {
    BackgroundWorkBudget::new(slots, Arc::new(())).unwrap()
}
#[tokio::test]
async fn closing_cannot_cross_an_admitted_but_not_yet_spawned_worker() {
    let worker = Arc::new(BackgroundWork::default());
    let pause = Arc::new(SpawnPause {
        entered: Notify::new(),
        release: std::sync::Barrier::new(2),
    });
    *worker.before_spawn.lock().unwrap() = Some(pause.clone());
    let runtime = tokio::runtime::Handle::current();
    let starting = worker.clone();
    let started = std::thread::spawn(move || {
        let _runtime = runtime.enter();
        starting.start(async {}, &budget(1))
    });
    tokio::time::timeout(Duration::from_secs(5), pause.entered.notified())
        .await
        .unwrap();
    let attempted = Arc::new(Notify::new());
    let observed = attempted.clone();
    let closing = worker.clone();
    let (closed, mut completion) = tokio::sync::oneshot::channel();
    let closer = std::thread::spawn(move || {
        observed.notify_one();
        closing.close();
        closed.send(()).unwrap();
    });
    attempted.notified().await;
    let crossed = tokio::time::timeout(Duration::from_millis(50), &mut completion)
        .await
        .is_ok();
    // Always release the actual paused registration before asserting, so a
    // failing regression does not strand either thread or an owned task.
    pause.release.wait();
    started.join().unwrap().unwrap();
    closer.join().unwrap();
    assert!(
        !crossed,
        "close crossed an admitted task before custody publication"
    );
    worker.drain().await.unwrap();
}
#[tokio::test]
async fn repeated_and_concurrent_drains_preserve_original_join_error() {
    let worker = Arc::new(BackgroundWork::default());
    worker
        .start(async { panic!("original background panic") }, &budget(1))
        .unwrap();
    let (first, second) = tokio::join!(worker.drain(), worker.drain());
    let first = first.unwrap_err();
    let second = second.unwrap_err();
    assert_eq!(first.completion(), DrainCompletion::Complete);
    assert!(Arc::ptr_eq(&first.issues()[0], &second.issues()[0]));
    let original = first.issues()[0]
        .error()
        .downcast_ref::<tokio::task::JoinError>()
        .unwrap();
    assert!(original.is_panic());
    let again = worker.drain().await.unwrap_err();
    assert!(Arc::ptr_eq(&first.issues()[0], &again.issues()[0]));
}

#[tokio::test]
async fn actual_child_abort_keeps_its_original_cancelled_join_error() {
    let worker = Arc::new(BackgroundWork::default());
    worker.start(std::future::pending(), &budget(1)).unwrap();
    let id = worker.state.lock().unwrap().custody.unwrap();
    let owner = custody().lock().unwrap().get(&id).unwrap().clone();
    owner.task.lock().await.as_ref().unwrap().abort();
    let failed = worker.drain().await.unwrap_err();
    assert_eq!(failed.completion(), DrainCompletion::Complete);
    assert_eq!(failed.issues().len(), 1);
    assert!(
        failed.issues()[0]
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_cancelled()
    );
    let repeated = worker.drain().await.unwrap_err();
    assert!(Arc::ptr_eq(&failed.issues()[0], &repeated.issues()[0]));
}

#[tokio::test]
async fn cancelled_drain_retains_exact_child_and_charge_after_all_facades_drop() {
    let charge = Arc::new(());
    let weak_charge = Arc::downgrade(&charge);
    let budget = BackgroundWorkBudget::new(1, charge).unwrap();
    let worker = Arc::new(BackgroundWork::default());
    let weak = Arc::downgrade(&worker);
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    worker
        .start(
            async move {
                waiting.await.unwrap();
                panic!("original child after drain cancellation");
            },
            &budget,
        )
        .unwrap();
    let id = worker.state.lock().unwrap().custody.unwrap();
    let draining = worker.clone();
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let waiter = tokio::spawn(async move {
        let mut drain = Box::pin(draining.drain());
        std::future::poll_fn(|cx| {
            assert!(drain.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        entered.send(()).unwrap();
        drain.await
    });
    waiting.await.unwrap();
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(worker.observed().is_none());
    assert!(!worker.drained());
    drop(worker);
    drop(budget);
    assert!(weak_charge.upgrade().is_some());
    let mut after = None;
    let worker = loop {
        let page = pending_background_custody(after, 16).unwrap();
        assert!(!page.is_empty(), "cancelled join lost exact child custody");
        if let Some((_, worker)) = page.iter().find(|(key, _)| *key == id) {
            break worker.clone();
        }
        after = Some(page.last().unwrap().0);
    };
    let mut draining = Box::pin(worker.drain());
    std::future::poll_fn(|cx| {
        assert!(draining.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(draining);
    assert!(worker.observed().is_none());
    release.send(()).unwrap();
    let result = worker.drain().await.unwrap_err();
    assert_eq!(result.completion(), DrainCompletion::Complete);
    assert_eq!(result.issues().len(), 1);
    assert!(
        result.issues()[0]
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic()
    );
    assert!(!custody().lock().unwrap().contains_key(&id));
    drop(worker);
    assert!(weak.upgrade().is_none());
    assert!(weak_charge.upgrade().is_none());
}

#[tokio::test]
async fn finished_child_remains_in_custody_until_actual_join_observation() {
    let worker = Arc::new(BackgroundWork::default());
    worker.start(async {}, &budget(1)).unwrap();
    let id = worker.state.lock().unwrap().custody.unwrap();
    let owner = custody().lock().unwrap().get(&id).unwrap().clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !owner.task.lock().await.as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(worker.state.lock().unwrap().phase, Phase::Running));
    assert!(custody().lock().unwrap().contains_key(&id));
    assert!(!worker.drained());
    assert!(worker.observed().unwrap().is_ok());
    assert!(owner.task.lock().await.is_none());
    assert!(!custody().lock().unwrap().contains_key(&id));
    assert!(worker.drained());
    worker.drain().await.unwrap();
}

#[tokio::test]
async fn nonblocking_observation_preserves_the_active_join_waiter() {
    let worker = Arc::new(BackgroundWork::default());
    let (release, waiting) = tokio::sync::oneshot::channel::<()>();
    let (finished, completion) = tokio::sync::oneshot::channel();
    worker
        .start(
            async move {
                waiting.await.unwrap();
                finished.send(()).unwrap();
            },
            &budget(1),
        )
        .unwrap();
    let mut draining = Box::pin(worker.drain());
    std::future::poll_fn(|cx| {
        assert!(draining.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    release.send(()).unwrap();
    completion.await.unwrap();
    // Child completed its poll; the original drain still owns its join mutex.
    assert!(worker.observed().is_none());
    tokio::time::timeout(Duration::from_secs(5), draining)
        .await
        .unwrap()
        .unwrap();
    assert!(worker.drained());
}

#[tokio::test]
async fn never_started_close_is_terminal_and_cannot_later_spawn() {
    let worker = Arc::new(BackgroundWork::default());
    worker.drain().await.unwrap();
    assert!(worker.drained());
    assert!(
        worker
            .start(async { panic!("closed cell spawned") }, &budget(1))
            .is_err()
    );
}

#[tokio::test]
async fn shared_capacity_rejection_never_spawns_and_completed_cells_keep_their_charge() {
    let budget = budget(1);
    let first = Arc::new(BackgroundWork::default());
    first.start(async {}, &budget).unwrap();
    first.drain().await.unwrap();
    let called = Arc::new(AtomicBool::new(false));
    let marker = called.clone();
    let rejected = Arc::new(BackgroundWork::default());
    assert!(
        rejected
            .start(
                async move {
                    marker.store(true, Ordering::Release);
                },
                &budget
            )
            .is_err()
    );
    assert!(!called.load(Ordering::Acquire));
    drop(first);
    rejected.start(async {}, &budget).unwrap();
    rejected.drain().await.unwrap();
    assert!(BackgroundWorkBudget::required_bytes(usize::MAX, usize::MAX).is_err());
    assert!(BackgroundWorkBudget::required_bytes(1, 0).is_err());
    assert_eq!(
        BackgroundWorkBudget::required_bytes(2, 3).unwrap(),
        6 * BACKGROUND_WORK_SLOT_BYTES + 3 * BACKGROUND_WORK_DOMAIN_BYTES
    );
}
