use super::ServingTasks;
use kasumi_types::drain::DrainCompletion;
use std::{future::Future, sync::Arc, task::Poll, time::Duration};

#[tokio::test]
async fn cancelled_serving_drain_retains_joined_panic_and_exact_pending_owner() {
    let mut tasks = ServingTasks::new();
    let failed = tasks.maintenance.spawn(async {
        panic!("actual maintenance task panic");
    });
    let failed_id = failed.id();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !failed.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("serving-task.redb");
    let node = kasumi_store::NodeStore::create_new(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let weak = Arc::downgrade(&node);
    let (release, waiting) = tokio::sync::oneshot::channel();
    let pending = tasks.listeners.spawn(async move {
        let _node = node;
        waiting.await?;
        Ok(())
    });
    let pending_id = pending.id();
    let mut first = Box::pin(tasks.shutdown());
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    assert!(tasks.maintenance.is_empty());
    assert_eq!(tasks.listeners.len(), 1);
    assert!(!pending.is_finished());
    assert!(weak.upgrade().is_some());
    assert!(
        kasumi_store::NodeStore::open_existing(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .is_err()
    );
    let issue = tasks.report.issues()[0].clone();
    let error = issue
        .error()
        .downcast_ref::<tokio::task::JoinError>()
        .unwrap();
    assert!(error.is_panic());
    assert_eq!(error.id(), failed_id);
    assert_ne!(error.id(), pending_id);

    let mut resumed = Box::pin(tasks.shutdown());
    std::future::poll_fn(|cx| {
        assert!(resumed.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    release.send(()).unwrap();
    let failure = tokio::time::timeout(Duration::from_secs(5), resumed)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 1);
    assert!(Arc::ptr_eq(&issue, &failure.issues()[0]));
    assert!(pending.is_finished());
    assert!(weak.upgrade().is_none());
    assert!(tasks.listeners.is_empty());
    let repeated = tasks.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(&issue, &repeated.issues()[0]));
    assert_eq!(tasks.failed_tasks.len(), 1);
    let reopened = kasumi_store::NodeStore::open_existing(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    drop(reopened);
}

#[derive(Debug)]
struct ListenerFailure;
impl std::fmt::Display for ListenerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original returned listener error")
    }
}
impl std::error::Error for ListenerFailure {}

#[tokio::test]
async fn required_listener_failure_interrupts_pending_startup_before_retained_owner_drain() {
    let mut tasks = ServingTasks::new();
    let (fail, failing) = tokio::sync::oneshot::channel();
    tasks.listeners.spawn(async move {
        failing.await?;
        Err(ListenerFailure.into())
    });

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pending-startup.redb");
    let node = kasumi_store::NodeStore::create_new(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
    let weak = Arc::downgrade(&node);
    let (release, retained) = tokio::sync::oneshot::channel();
    tasks.maintenance.spawn(async move {
        let _node = node;
        retained.await?;
        Ok(())
    });

    let (entered, mut started) = tokio::sync::oneshot::channel();
    let mut startup = Box::pin(tasks.wait_for_startup(
        async move {
            entered.send(()).unwrap();
            // Quorum/Control publication cannot finish while another voter is
            // absent. Only the required listener failure can resolve this wait.
            std::future::pending::<anyhow::Result<()>>().await
        },
        std::future::pending::<()>(),
    ));
    std::future::poll_fn(|cx| {
        assert!(startup.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    started.try_recv().unwrap();
    fail.send(()).unwrap();
    let error = tokio::time::timeout(Duration::from_secs(5), startup)
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.is::<ListenerFailure>());
    assert!(tasks.listeners.is_empty());

    // Returning the startup failure must not discard the rest of the actual
    // serving inventory. A cancelled cleanup still excludes physical reopen.
    let mut drain = Box::pin(tasks.shutdown());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    assert!(weak.upgrade().is_some());
    assert!(
        kasumi_store::NodeStore::open_existing(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .is_err()
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), tasks.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!(weak.upgrade().is_none());
    assert!(error.is::<ListenerFailure>());
    let _reopened = kasumi_store::NodeStore::open_existing(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        kasumi_store::ScratchDisk::fixture(),
    )
    .unwrap();
}

#[tokio::test]
async fn standalone_startup_without_cluster_listener_can_complete() {
    let mut tasks = ServingTasks::new();
    let (_stop, mut shutdown) = tokio::sync::watch::channel(false);
    assert_eq!(
        tasks
            .wait_for_startup(async { Ok(37) }, shutdown.changed())
            .await
            .unwrap(),
        Some(37)
    );
    tasks.shutdown().await.unwrap();
}

#[tokio::test]
async fn serving_drain_keeps_every_panic_abort_and_returned_error() {
    let mut tasks = ServingTasks::new();
    let failed = tasks.maintenance.spawn(async {
        panic!("actual maintenance panic");
    });
    let aborted = tasks.maintenance.spawn(std::future::pending());
    let returned = tasks.listeners.spawn(async { Err(ListenerFailure.into()) });
    let failed_id = failed.id();
    let aborted_id = aborted.id();
    let returned_id = returned.id();
    aborted.abort();
    let failure = tokio::time::timeout(Duration::from_secs(5), tasks.shutdown())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 3);
    assert_eq!(tasks.failed_tasks.len(), 3);
    let panic = failure
        .issues()
        .iter()
        .find(|issue| {
            issue
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .is_some_and(|error| error.is_panic())
        })
        .unwrap();
    assert_eq!(
        panic
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .id(),
        failed_id
    );
    let cancelled = failure
        .issues()
        .iter()
        .find(|issue| {
            issue
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .is_some_and(|error| error.is_cancelled())
        })
        .unwrap();
    assert_eq!(
        cancelled
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .id(),
        aborted_id
    );
    let returned = failure
        .issues()
        .iter()
        .find(|issue| issue.error().is::<ListenerFailure>())
        .unwrap();
    assert_eq!(tasks.failed_tasks[&returned_id], returned.instance());
    let repeated = tasks.shutdown().await.unwrap_err();
    for (first, again) in failure.issues().iter().zip(repeated.issues()) {
        assert!(Arc::ptr_eq(first, again));
    }
    assert_eq!(tasks.failed_tasks.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aborted_listener_retains_http1_and_http2_requests_until_exact_nested_join() {
    use crate::tls::{self, TlsHandshakeAudit, TlsHandshakeEvent};
    use axum::{Router, extract::State, routing::post};
    use kasumi_transport::{ClientAuthentication, TlsIdentity};
    use tokio::sync::{Notify, oneshot, watch};
    struct Audit;
    #[async_trait::async_trait]
    impl TlsHandshakeAudit for Audit {
        async fn record(&self, _: &TlsHandshakeEvent) -> anyhow::Result<()> {
            Ok(())
        }
    }
    struct Request {
        _node: Arc<kasumi_store::NodeStore>,
        entered: std::sync::Mutex<Option<oneshot::Sender<()>>>,
        release: Arc<Notify>,
    }
    async fn held(State(request): State<Arc<Request>>) -> &'static str {
        request
            .entered
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(())
            .unwrap();
        request.release.notified().await;
        "joined request"
    }
    for http2 in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested-listener.redb");
        let node = kasumi_store::NodeStore::create_new(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
        let weak = Arc::downgrade(&node);
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let identity = TlsIdentity::from_pem(
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "https://localhost:{}/held",
            socket.local_addr().unwrap().port()
        );
        let (entered, ready) = oneshot::channel();
        let release = Arc::new(Notify::new());
        let router = Router::new()
            .route("/held", post(held))
            .with_state(Arc::new(Request {
                _node: node,
                entered: std::sync::Mutex::new(Some(entered)),
                release: release.clone(),
            }));
        let mut tasks = ServingTasks::new();
        let (_stop, shutdown) = watch::channel(false);
        tasks.spawn_listener(tls::serve_tls(
            socket,
            kasumi_transport::server_config(&identity, ClientAuthentication::OAuth).unwrap(),
            router,
            tls::ListenerLimits::default(),
            Arc::new(Audit),
            shutdown,
        ));
        let client = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap());
        let client = if http2 {
            client.http2_prior_knowledge()
        } else {
            client.http1_only()
        }
        .build()
        .unwrap();
        let response = tokio::spawn(async move {
            client
                .post(endpoint)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        });
        tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .unwrap()
            .unwrap();
        // This aborts only the listener task. Its nested inventory is already in
        // ServingTasks, so neither HTTP/1 requests nor Hyper H2 streams detach.
        tasks.listeners.abort_all();
        let mut first = Box::pin(tasks.shutdown());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut first)
                .await
                .is_err()
        );
        drop(first);
        assert!(weak.upgrade().is_some());
        assert!(
            kasumi_store::NodeStore::open_existing(
                &path,
                kasumi_store::test_utils::NODE_STORE_ID,
                kasumi_store::ScratchDisk::fixture()
            )
            .is_err()
        );
        let issue = tasks.report.issues()[0].clone();
        assert!(
            issue
                .error()
                .downcast_ref::<tokio::task::JoinError>()
                .unwrap()
                .is_cancelled()
        );
        release.notify_one();
        let failure = tokio::time::timeout(Duration::from_secs(5), tasks.shutdown())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(failure.completion(), DrainCompletion::Complete);
        assert!(Arc::ptr_eq(&issue, &failure.issues()[0]));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), response)
                .await
                .unwrap()
                .unwrap(),
            "joined request"
        );
        assert!(weak.upgrade().is_none());
        let _reopened = kasumi_store::NodeStore::open_existing(
            &path,
            kasumi_store::test_utils::NODE_STORE_ID,
            kasumi_store::ScratchDisk::fixture(),
        )
        .unwrap();
    }
}
