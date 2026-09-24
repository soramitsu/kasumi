use super::*;
use kasumi_store::{FilesystemBackupDestination, NodeStore, test_utils::LocalKeyProvider};
use std::{future::Future, path::PathBuf, task::Poll};

type BlockingHook = Box<dyn FnOnce() + Send>;

#[derive(Default)]
pub(super) struct BlockingHooks {
    pub(super) monitor: Mutex<Option<BlockingHook>>,
    pub(super) audit: Mutex<Option<BlockingHook>>,
    pub(super) backup_stream: Mutex<Option<BlockingHook>>,
    pub(super) waiting_preparation: tokio::sync::Notify,
}

struct Release(Option<std::sync::mpsc::Sender<()>>);
impl Release {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        self.release();
    }
}

fn held_hook(
    panic_after_release: bool,
) -> (BlockingHook, tokio::sync::oneshot::Receiver<()>, Release) {
    let (entered, entry) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    (
        Box::new(move || {
            let _ = entered.send(());
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(!panic_after_release, "actual retained blocking child panic");
        }),
        entry,
        Release(Some(release)),
    )
}

struct Fixture {
    storage: crate::test_utils::FixtureStorage,
    path: PathBuf,
    node: Arc<NodeStore>,
    database: Arc<Database>,
    audit: Arc<SecurityAudit>,
    directory: tempfile::TempDir,
}
impl Fixture {
    async fn new(name: &str) -> anyhow::Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (persistent, scratch) = crate::test_utils::fixture_disk_configs(directory.path())?;
        let storage =
            crate::test_utils::FixtureStorage::open(&persistent, &scratch, Default::default())?;
        Self::on_disk(directory, storage, name).await
    }
    async fn on_disk(
        directory: tempfile::TempDir,
        storage: crate::test_utils::FixtureStorage,
        name: &str,
    ) -> anyhow::Result<Self> {
        let admission = storage.admission.clone();
        let path = directory.path().join("persistent/node.kv");
        let node = storage.create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)?;
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            name.into(),
            Arc::new(LocalKeyProvider::new([71; 32])),
        )
        .await?;
        store.write_batch(&[kasumi_store::WriteOp::put(
            "worker-test",
            b"marker",
            b"durable".to_vec(),
        )])?;
        let audit_store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            crate::SECURITY_TENANT.into(),
            Arc::new(LocalKeyProvider::new([72; 32])),
        )
        .await?;
        let audit = SecurityAudit::initialize(audit_store, Default::default(), admission.clone())?;
        let incarnation = uuid::Uuid::new_v4().to_string();
        let engine = Arc::new(TenantEngine::new(
            name.into(),
            incarnation.clone(),
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: BTreeSet::from([Action::Read, Action::Admin]),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
        )?);
        engine.install_storage_access(&store)?;
        engine.install_audit_maintenance(&admission)?;
        let stores = kasumi_store::test_utils::initialize_custody_fixture(
            store.clone(),
            Arc::new(LocalKeyProvider::new([73; 32])),
        )
        .await?;
        let database = construction::DatabaseConstruction::new(stores, audit.clone())?
            .start_local(engine, 1, format!("{name}/{incarnation}"))
            .await?;
        database
            .group
            .raft()
            .wait(Some(Duration::from_secs(5)))
            .current_leader(1, "worker outcome fixture leader")
            .await?;
        Ok(Self {
            directory,
            storage,
            path,
            node,
            database,
            audit,
        })
    }

    fn assert_exclusive(&self) {
        assert!(
            self.storage
                .open_existing(&self.path, kasumi_store::test_utils::NODE_STORE_ID)
                .is_err()
        );
    }

    async fn release(self) -> anyhow::Result<()> {
        self.audit.shutdown().await?;
        let name = self.database.store.tenant().to_owned();
        let weak = Arc::downgrade(&self.database);
        drop(self.database);
        assert!(weak.upgrade().is_none());
        drop(self.audit);
        self.node.shutdown().await?;
        drop(self.node);
        let node = self
            .storage
            .open_existing(&self.path, kasumi_store::test_utils::NODE_STORE_ID)?;
        let store = TenantStore::open_existing_fixture(
            node.clone(),
            name,
            Arc::new(LocalKeyProvider::new([71; 32])),
        )
        .await?;
        assert_eq!(store.get("worker-test", b"marker")?.unwrap(), b"durable");
        store.shutdown().await?;
        node.shutdown().await?;
        drop(store);
        drop(node);
        drop(self.directory);
        Ok(())
    }
}

async fn until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker fixture did not reach its actual boundary");
}

fn panic_issue(failure: &DrainFailure, component: &str) -> Arc<kasumi_types::drain::DrainIssue> {
    let issue = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == component)
        .unwrap();
    assert!(
        issue
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic()
    );
    issue.clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_database_drain_keeps_monitor_panic_before_pending_audit_child()
-> anyhow::Result<()> {
    let fixture = Fixture::new("tenant").await?;
    let database = &fixture.database;
    let (hook, entered, mut release) = held_hook(false);
    *database.worker_test_hooks.audit.lock().unwrap() = Some(hook);
    database.audit_worker_wake.notify_one();
    tokio::time::timeout(Duration::from_secs(5), entered).await??;
    *database.worker_test_hooks.monitor.lock().unwrap() =
        Some(Box::new(|| panic!("actual monitor child panic")));
    database.seal_monitor_wake.notify_one();
    until(|| {
        database
            .seal_monitor
            .try_lock()
            .is_ok_and(|task| task.as_ref().is_some_and(|task| task.is_finished()))
    })
    .await;
    assert!(database.check_serving().is_err());
    let mut first = Box::pin(database.shutdown());
    tokio::time::timeout(
        Duration::from_secs(5),
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            if database.audit_worker.try_lock().is_err() {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }),
    )
    .await?;
    drop(first);
    let prior = database.shutdown_gate.lock().await.complete().unwrap_err();
    let original = panic_issue(&prior, "database retention check");
    fixture.assert_exclusive();
    release.release();
    let failure = tokio::time::timeout(Duration::from_secs(5), database.shutdown())
        .await?
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert!(Arc::ptr_eq(
        &original,
        &panic_issue(&failure, "database retention check")
    ));
    let repeated = database.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        &original,
        &panic_issue(&repeated, "database retention check")
    ));
    fixture.release().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aborted_database_monitor_retains_its_blocking_child_and_distinct_panic()
-> anyhow::Result<()> {
    let fixture = Fixture::new("tenant").await?;
    let database = &fixture.database;
    let (hook, entered, mut release) = held_hook(true);
    *database.worker_test_hooks.monitor.lock().unwrap() = Some(hook);
    database.seal_monitor_wake.notify_one();
    tokio::time::timeout(Duration::from_secs(5), entered).await??;
    database.seal_monitor.lock().await.as_ref().unwrap().abort();
    until(|| {
        database
            .seal_monitor
            .try_lock()
            .is_ok_and(|task| task.as_ref().is_some_and(|task| task.is_finished()))
    })
    .await;
    assert!(database.check_serving().is_err());
    let mut first = Box::pin(database.shutdown());
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    let before = database.shutdown_gate.lock().await.complete().unwrap_err();
    let cancelled = before
        .issues()
        .iter()
        .find(|issue| issue.component() == "database seal monitor")
        .unwrap()
        .clone();
    assert!(
        cancelled
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_cancelled()
    );
    fixture.assert_exclusive();
    release.release();
    let failure = tokio::time::timeout(Duration::from_secs(5), database.shutdown())
        .await?
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let panic = panic_issue(&failure, "database retention check");
    assert!(
        failure
            .issues()
            .iter()
            .any(|issue| Arc::ptr_eq(issue, &cancelled))
    );
    let repeated = database.shutdown().await.unwrap_err();
    assert!(
        repeated
            .issues()
            .iter()
            .any(|issue| Arc::ptr_eq(issue, &panic))
    );
    fixture.release().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn database_audit_blocking_panic_is_terminal_and_retained() -> anyhow::Result<()> {
    let fixture = Fixture::new("tenant").await?;
    let database = &fixture.database;
    *database.worker_test_hooks.audit.lock().unwrap() =
        Some(Box::new(|| panic!("actual audit preparation panic")));
    database.audit_worker_wake.notify_one();
    until(|| {
        database
            .audit_worker
            .try_lock()
            .is_ok_and(|task| task.as_ref().is_some_and(|task| task.is_finished()))
    })
    .await;
    assert!(database.check_serving().is_err());
    assert_eq!(database.audit_maintenance_status().unwrap().failures, 1);
    let failure = tokio::time::timeout(Duration::from_secs(5), database.shutdown())
        .await?
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let panic = panic_issue(&failure, "database audit preparation");
    let repeated = database.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        &panic,
        &panic_issue(&repeated, "database audit preparation")
    ));
    fixture.release().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn database_shutdown_cancels_undispatched_shared_permit_wait_before_other_tenant_drain()
-> anyhow::Result<()> {
    let blocked_directory = kasumi_store::test_utils::private_tempdir()?;
    let waiting_directory = kasumi_store::test_utils::private_tempdir()?;
    let (blocked_persistent, blocked_scratch) =
        crate::test_utils::fixture_disk_configs(blocked_directory.path())?;
    let (waiting_persistent, waiting_scratch) =
        crate::test_utils::fixture_disk_configs(waiting_directory.path())?;
    // One original operation allowance, plus both actual isolated installations.
    let config = crate::test_utils::isolated_disk_config_with_metadata(
        Default::default(),
        &blocked_persistent,
        &blocked_scratch,
    )?;
    let config = crate::test_utils::isolated_disk_config_with_metadata(
        config,
        &waiting_persistent,
        &waiting_scratch,
    )?;
    let admission = NodeAdmission::new(config)?;
    let blocked_storage = crate::test_utils::FixtureStorage::with_admission(
        &blocked_persistent,
        &blocked_scratch,
        admission.clone(),
    )?;
    let waiting_storage = crate::test_utils::FixtureStorage::with_admission(
        &waiting_persistent,
        &waiting_scratch,
        admission,
    )?;
    let blocked = Fixture::on_disk(blocked_directory, blocked_storage, "blocked").await?;
    let (hook, entered, mut release) = held_hook(false);
    *blocked.database.worker_test_hooks.audit.lock().unwrap() = Some(hook);
    blocked.database.audit_worker_wake.notify_one();
    tokio::time::timeout(Duration::from_secs(5), entered).await??;
    blocked
        .database
        .audit_worker
        .lock()
        .await
        .as_ref()
        .unwrap()
        .abort();
    until(|| {
        blocked
            .database
            .audit_worker
            .try_lock()
            .is_ok_and(|task| task.as_ref().is_some_and(|task| task.is_finished()))
    })
    .await;
    release.release();
    tokio::time::timeout(Duration::from_secs(5), async {
        while blocked.database.audit_preparation.child_finished().await != Some(true) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let pool = blocked
        .database
        .engine
        .audit_maintenance
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert!(pool.preparation.try_acquire().is_err());
    let waiting = Fixture::on_disk(waiting_directory, waiting_storage, "waiting").await?;
    let waiting_pool = waiting
        .database
        .engine
        .audit_maintenance
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert!(Arc::ptr_eq(&pool, &waiting_pool));
    tokio::time::timeout(
        Duration::from_secs(5),
        waiting
            .database
            .worker_test_hooks
            .waiting_preparation
            .notified(),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(5), waiting.database.shutdown()).await??;
    assert_eq!(
        blocked.database.audit_preparation.child_finished().await,
        Some(true)
    );
    assert!(
        pool.preparation.try_acquire().is_err(),
        "other tenant has not yet drained its actual result"
    );
    waiting.release().await?;
    let failure = tokio::time::timeout(Duration::from_secs(5), blocked.database.shutdown())
        .await?
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let issue = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "database audit worker")
        .unwrap();
    assert!(
        issue
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_cancelled()
    );
    assert_eq!(
        blocked.database.audit_preparation.child_finished().await,
        None
    );
    drop(
        pool.preparation
            .try_acquire()
            .expect("drained result must release shared capacity"),
    );
    drop(pool);
    drop(waiting_pool);
    blocked.release().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelled_backup_producer_and_shutdown_waiter_keep_original_blocking_panic()
-> anyhow::Result<()> {
    let fixture = Fixture::new("tenant").await?;
    let database = &fixture.database;
    database.backup_producers.prepare(database.admission())?;
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel();
    let producer = database.backup_producers.start(
        move || -> std::result::Result<(), super::backup_producer_jobs::Failure> {
            let _ = entered.send(());
            held.recv().unwrap();
            panic!("original database backup producer panic");
        },
    )?;
    tokio::time::timeout(Duration::from_secs(5), waiting).await??;
    let worker = database.backup_producers.test_worker(0);
    drop(producer);
    assert!(!worker.is_closed());
    let mut first = Box::pin(database.shutdown());
    tokio::time::timeout(Duration::from_secs(10), async {
        while !worker.is_closed() {
            std::future::poll_fn(|cx| {
                assert!(first.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            tokio::task::yield_now().await;
        }
    })
    .await?;
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    fixture.assert_exclusive();
    release.send(()).unwrap();
    let failure = tokio::time::timeout(Duration::from_secs(30), database.shutdown())
        .await?
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let original = panic_issue(&failure, "background worker");
    let repeated = database.shutdown().await.unwrap_err();
    assert!(Arc::ptr_eq(
        &original,
        &panic_issue(&repeated, "background worker")
    ));
    drop(worker);
    fixture.release().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admitted_full_backup_cancelled_caller_retains_exact_state_stream_producer_until_release()
-> anyhow::Result<()> {
    let fixture = Fixture::new("tenant").await?;
    let database = &fixture.database;
    let destination = Arc::new(FilesystemBackupDestination::new(
        database
            .store
            .durable_directory()?
            .join("backup-cancellation"),
        32 << 20,
        database.store.persistent_disk().clone(),
    )?);
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        tenant: "tenant".into(),
        principal: "owner".into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin]),
        request_id: "backup-state-stream-cancellation".into(),
    };
    let session_id = uuid::Uuid::new_v4();
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel();
    let mut release = Release(Some(release));
    *database.worker_test_hooks.backup_stream.lock().unwrap() = Some(Box::new(move || {
        let _ = entered.send(());
        held.recv_timeout(Duration::from_secs(30))
            .expect("state stream test release");
    }));
    let caller = tokio::spawn({
        let database = Arc::clone(database);
        let destination = Arc::clone(&destination);
        let context = context.clone();
        async move {
            database
                .backup_checkpoint(context, destination.as_ref(), session_id)
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(15), waiting).await??;
    let pending = database
        .backup_session(&context, destination.as_ref(), session_id)
        .await?
        .expect("producer starts only after authenticated intent readback");
    assert_eq!(pending.intent().session_id, session_id);
    assert!(pending.outcome().is_none());
    let worker = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(worker) = database.backup_producers.test_worker_if_started(0) {
                break worker;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(!worker.is_closed());
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(
        worker.observed().is_none(),
        "aborted caller lost original producer"
    );
    let mut first = Box::pin(database.shutdown());
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    assert!(
        worker.observed().is_none(),
        "cancelled shutdown waiter lost original producer"
    );
    fixture.assert_exclusive();
    release.release();
    tokio::time::timeout(Duration::from_secs(30), database.shutdown()).await??;
    assert!(worker.observed().is_some_and(|result| result.is_ok()));
    drop(worker);
    drop(destination);
    fixture.release().await
}
