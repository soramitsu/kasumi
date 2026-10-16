use super::{NodeRuntime, NodeServing, RuntimeConfig, ServingTasks};
use crate::serving_owner::Owner;
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

    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        crate::runtime_storage_fixtures::physical(directory.path(), Default::default()).unwrap();
    let path = directory.path().join("persistent/serving-task.kv");
    let node = physical
        .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
        .unwrap();
    let weak = node.locator();
    let mut weak_retirement = node.clone().retire();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let pending = tasks.listeners.spawn(async move {
        waiting.await?;
        node.shutdown().await?;
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
    assert!(matches!(
        weak.try_borrow(),
        kasumi_store::NodeStoreLookup::Active(_)
    ));
    assert!(
        physical
            .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
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
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &issue,
        &failure.issues()[0]
    ));
    assert!(pending.is_finished());
    assert!({
        assert_eq!(
            weak_retirement.retry(),
            kasumi_store::StorageCensusDisposition::Retired
        );
        matches!(weak.try_borrow(), kasumi_store::NodeStoreLookup::Missing)
    });
    assert!(tasks.listeners.is_empty());
    let repeated = tasks.shutdown().await.unwrap_err();
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &issue,
        &repeated.issues()[0]
    ));
    assert_eq!(tasks.failed_tasks.len(), 1);
    let reopened = physical
        .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
        .unwrap();
    reopened.shutdown().await.unwrap();
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

    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        crate::runtime_storage_fixtures::physical(directory.path(), Default::default()).unwrap();
    let path = directory.path().join("persistent/pending-startup.kv");
    let node = physical
        .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
        .unwrap();
    let weak = node.locator();
    let mut weak_retirement = node.clone().retire();
    let (release, retained) = tokio::sync::oneshot::channel();
    tasks.maintenance.spawn(async move {
        retained.await?;
        node.shutdown().await?;
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
    assert!(matches!(
        weak.try_borrow(),
        kasumi_store::NodeStoreLookup::Active(_)
    ));
    assert!(
        physical
            .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .is_err()
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), tasks.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert!({
        assert_eq!(
            weak_retirement.retry(),
            kasumi_store::StorageCensusDisposition::Retired
        );
        matches!(weak.try_borrow(), kasumi_store::NodeStoreLookup::Missing)
    });
    assert!(error.is::<ListenerFailure>());
    let reopened = physical
        .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
        .unwrap();
    reopened.shutdown().await.unwrap();
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

async fn management_shutdown_runtime(directory: &std::path::Path) -> NodeRuntime {
    // Preserve initialize_standalone's ordinary memory budget, but give the
    // installed Control and tenant exactly one snapshot-startup slot each.
    let mut policy = kasumi_engine::admission::AdmissionConfig::default();
    let former_total = policy.resolved_fixture_total_bytes().unwrap();
    policy.max_inflight_bytes = Some(
        former_total
            .checked_add(4 * kasumi_types::AuditRetentionBudget::MAINTENANCE_BYTES)
            .unwrap(),
    );
    policy.max_snapshot_startups = 2;
    let storage = crate::runtime_storage_fixtures::standalone_storage(directory, policy).unwrap();
    let installation = crate::standalone::initialize_with_storage(
        directory,
        "tenant-a",
        kasumi_store::DirectoryPolicy::fixture(),
        kasumi_store::FileAllocationPolicy::fixture(),
        crate::standalone::StandaloneNetwork::fixture(),
        crate::standalone::local_audit_placements("tenant-a"),
        storage.clone(),
    )
    .await
    .unwrap();
    let mut config = RuntimeConfig::load(&installation.configuration).unwrap();
    assert_eq!(config.admission.max_snapshot_startups, 2);
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    config.mcp.listen = listeners[0].local_addr().unwrap();
    config.native.listen = listeners[1].local_addr().unwrap();
    config.admin.listen = listeners[2].local_addr().unwrap();
    config.mcp.protocol = crate::mcp::McpConfig::new(format!(
        "https://localhost:{}/mcp",
        config.mcp.listen.port()
    ))
    .unwrap();
    crate::standalone::configure_test_topology(&config, storage.clone()).await;
    drop(listeners);
    NodeRuntime::open_using_storage(config, super::file_secret, storage)
        .await
        .unwrap()
}

fn run_management_shutdown_fixture(test: fn() -> std::pin::Pin<Box<dyn Future<Output = ()>>>) {
    // Installed initialization and runtime ownership exceed libtest's default
    // stack. Construct their futures on the fixture thread, as the other real
    // standalone serving tests do, and keep the scheduling current-thread.
    std::thread::Builder::new()
        .name("management shutdown fixture".into())
        .stack_size(16 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(test());
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn serving_shutdown_closes_management_before_joining_queued_reconciliation() {
    run_management_shutdown_fixture(|| {
        Box::pin(serving_shutdown_closes_management_before_joining_queued_reconciliation_impl())
    });
}

async fn serving_shutdown_closes_management_before_joining_queued_reconciliation_impl() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let runtime = management_shutdown_runtime(&directory.path().join("kasumi")).await;
    let management = runtime.administration.as_ref().unwrap().clone();
    let tenant = runtime.tenants[0].store.tenant().to_owned();
    let incarnation = runtime.tenants[0]
        .database
        .engine()
        .generation()
        .unwrap()
        .incarnation()
        .to_owned();
    let original = management.test_generation(&tenant, &incarnation);
    assert!(
        management
            .pending_admission(&tenant, &incarnation)
            .is_none()
    );
    let active = management.test_hold_management().await.unwrap();

    // Queue the actual reconciliation future before shutdown, rather than
    // relying on whether a newly spawned task has reached its admission await.
    let queued_management = management.clone();
    let mut queued = Box::pin(async move { queued_management.reconcile().await });
    std::future::poll_fn(|cx| {
        assert!(queued.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let mut tasks = ServingTasks::new();
    let (release, waiting) = tokio::sync::oneshot::channel();
    let admitted = tasks.maintenance.spawn(async move {
        waiting.await?;
        drop(active);
        Ok(())
    });
    let (observed, outcome) = tokio::sync::oneshot::channel();
    let queued_task = tasks.maintenance.spawn(async move {
        observed.send(queued.await).unwrap();
        Ok(())
    });
    let mut owner = NodeServing {
        tasks,
        report: Default::default(),
        runtime,
    };

    let mut first = owner.close();
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);

    // This must reject synchronously while the original guard remains held.
    // Keep the observation until after cleanup so the regression's failure
    // does not abandon the admitted operation or its queued successor.
    let mut late = Box::pin(management.test_hold_management());
    let admission_closed = std::future::poll_fn(|cx| {
        Poll::Ready(matches!(
            late.as_mut().poll(cx),
            Poll::Ready(Err(error)) if error.code == kasumi_types::ErrorCode::Unavailable
        ))
    })
    .await;
    drop(late);
    assert_eq!(owner.tasks.maintenance.len(), 2);
    assert!(!admitted.is_finished());
    assert!(!queued_task.is_finished());
    assert!(!owner.runtime.closed);
    original.check_serving().unwrap();
    assert!(Arc::ptr_eq(
        &original,
        &management.test_generation(&tenant, &incarnation)
    ));

    let mut resumed = owner.close();
    std::future::poll_fn(|cx| {
        assert!(resumed.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    release.send(()).unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(60), resumed)
        .await
        .expect("serving shutdown must join both retained management tasks");
    let queued = outcome.await.unwrap();
    assert!(
        admission_closed,
        "serving shutdown left management admission open"
    );
    assert!(matches!(
        queued,
        Err(error) if error.downcast_ref::<kasumi_types::Error>()
            .is_some_and(|error| error.code == kasumi_types::ErrorCode::Unavailable)
    ));
    closed.unwrap();
    assert!(admitted.is_finished());
    assert!(queued_task.is_finished());
    assert!(owner.tasks.maintenance.is_empty());
    assert!(owner.runtime.closed);
    assert!(Arc::ptr_eq(
        &original,
        &management.test_generation(&tenant, &incarnation)
    ));
    assert!(
        management
            .pending_admission(&tenant, &incarnation)
            .is_none()
    );
    // The installed runtime transfers its recovery inventory to the admin
    // listener at open. The positive close above includes Administration's
    // census of that exact inventory; the runtime's Option is already empty.
}

#[test]
fn sealed_tenant_recovery_reuses_drained_snapshot_startup_slot() {
    run_management_shutdown_fixture(|| {
        Box::pin(sealed_tenant_recovery_reuses_drained_snapshot_startup_slot_impl())
    });
}

async fn sealed_tenant_recovery_reuses_drained_snapshot_startup_slot_impl() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let runtime = management_shutdown_runtime(&directory.path().join("kasumi")).await;
    let management = runtime.administration.as_ref().unwrap().clone();
    let store = runtime.tenants[0].store.clone();
    let original = runtime.tenants[0].database.clone();
    let incarnation = original
        .engine()
        .generation()
        .unwrap()
        .incarnation()
        .to_owned();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));

    async fn coverage(management: &crate::administration::Administration, healthy_groups: usize) {
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let epoch = management.readiness_epoch().unwrap();
                let snapshot = management
                    .readiness
                    .snapshot(epoch, tokio::time::Instant::now());
                if snapshot.status.complete
                    && snapshot.status.fresh
                    && snapshot.status.healthy_groups == healthy_groups
                {
                    assert_eq!(snapshot.status.expected_groups, Some(2));
                    assert_eq!(snapshot.status.examined_groups, 2);
                    assert_eq!(snapshot.details.len(), 2);
                    assert_eq!(
                        snapshot
                            .details
                            .iter()
                            .filter(|sample| sample.quorum)
                            .count(),
                        healthy_groups
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("readiness must finish observing both installed groups");
    }

    coverage(&management, 2).await;
    let active = management.test_hold_management().await.unwrap();
    store.seal();
    coverage(&management, 1).await;
    // Recovery must run while serving admission is still open. Closing the
    // management gate first would hide exhaustion by rejecting this attempt.
    // The old Database facade intentionally remains alive after its drain.
    drop(active);
    tokio::time::timeout(Duration::from_secs(60), management.reconcile())
        .await
        .expect("sealed tenant reconciliation must finish")
        .unwrap();
    assert!(
        management.test_has_generation(store.tenant(), &incarnation),
        "recovery must reuse the drained tenant's startup slot while its old facade remains alive"
    );
    let replacement = management.test_generation(store.tenant(), &incarnation);
    assert!(!Arc::ptr_eq(&original, &replacement));
    assert!(original.check_serving().is_err());
    replacement.check_serving().unwrap();
    assert!(
        management
            .pending_admission(store.tenant(), &incarnation)
            .is_none()
    );
    coverage(&management, 2).await;
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(60), serving)
        .await
        .expect("serving supervisor must join after recovering with both startup slots occupied")
        .unwrap()
        .unwrap();
    // Both old and replacement facades outlive the complete serving drain.
    drop(original);
    drop(replacement);
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
        assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(first, again));
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
        _node: kasumi_store::NodeStore,
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
        request._node.shutdown().await.unwrap();
        "joined request"
    }
    for http2 in [false, true] {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let physical =
            crate::runtime_storage_fixtures::physical(directory.path(), Default::default())
                .unwrap();
        let path = directory.path().join("persistent/nested-listener.kv");
        let node = physical
            .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        let weak = node.locator();
        let mut weak_retirement = node.clone().retire();
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
        assert!(matches!(
            weak.try_borrow(),
            kasumi_store::NodeStoreLookup::Active(_)
        ));
        assert!(
            physical
                .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
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
        assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
            &issue,
            &failure.issues()[0]
        ));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), response)
                .await
                .unwrap()
                .unwrap(),
            "joined request"
        );
        assert!({
            assert_eq!(
                weak_retirement.retry(),
                kasumi_store::StorageCensusDisposition::Retired
            );
            matches!(weak.try_borrow(), kasumi_store::NodeStoreLookup::Missing)
        });
        let reopened = physical
            .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
            .unwrap();
        reopened.shutdown().await.unwrap();
    }
}
