use super::*;
use kasumi_store::{DiskWork, NodeDisk, NodeDiskConfig, NodeDiskFile, NodeStore, ScratchDisk};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Weak,
    task::Poll,
};
use tokio::sync::{Notify, oneshot};

struct PhysicalOwner {
    worker: Option<tokio::task::JoinHandle<()>>,
    node: Arc<NodeStore>,
    entered: Arc<Notify>,
    closing: Arc<Notify>,
    panic_run: bool,
    panic_close: bool,
    report: DrainReport,
    // The real installation lock outlives the worker and direct physical node.
    _lock: NodeDiskFile,
}
impl Owner for PhysicalOwner {
    fn run<'a>(
        &'a mut self,
        shutdown: &'a mut Shutdown,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.entered.notify_one();
            if self.panic_run {
                std::panic::panic_any("actual serving poll panic");
            }
            shutdown.changed().await;
            Ok(())
        })
    }
    fn close(&mut self) -> Pin<Box<dyn Future<Output = DrainResult> + Send + '_>> {
        Box::pin(async move {
            self.closing.notify_one();
            if std::mem::take(&mut self.panic_close) {
                std::panic::panic_any("actual drain poll panic");
            }
            if let Some(worker) = self.worker.as_mut() {
                if let Err(error) = worker.await {
                    self.report.record("physical worker", 0, error.into());
                }
                self.worker.take();
            }
            let retained = match self.node.shutdown().await {
                Ok(()) => None,
                Err(failure) => {
                    self.report.merge(&failure);
                    (failure.completion() == DrainCompletion::Retained).then_some(failure)
                }
            };
            self.report.outcome(retained)
        })
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    lock: PathBuf,
    weak: Weak<NodeStore>,
    disk: Arc<NodeDisk>,
    disk_config: NodeDiskConfig,
    scratch: Arc<ScratchDisk>,
    release: Option<oneshot::Sender<()>>,
    entered: Arc<Notify>,
    closing: Arc<Notify>,
}
fn open_lock(disk: &Arc<NodeDisk>, config: &NodeDiskConfig, path: &Path) -> Result<NodeDiskFile> {
    let (root, relative) = config.binding(path)?;
    Ok(disk.open_file(root, relative)?)
}
fn create_lock(disk: &Arc<NodeDisk>, config: &NodeDiskConfig, path: &Path) -> NodeDiskFile {
    let (root, relative) = config.binding(path).unwrap();
    disk.create_file(root, relative, DiskWork::Foreground)
        .unwrap()
}
fn fixture(panic_run: bool, panic_close: bool) -> (Fixture, PhysicalOwner, Registration) {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("serving.redb");
    let lock = directory.path().join("installation.lock");
    let disk_config = crate::persistent_disk::fixture_config(directory.path());
    let disk = crate::persistent_disk::open(&disk_config).unwrap();
    let scratch = ScratchDisk::fixture();
    let node = NodeStore::create_new(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        disk.clone(),
        scratch.clone(),
    )
    .unwrap();
    let held = node.clone();
    let (release, waiting) = oneshot::channel();
    let worker = tokio::spawn(async move {
        let _node = held;
        let _ = waiting.await;
    });
    let entered = Arc::new(Notify::new());
    let closing = Arc::new(Notify::new());
    let fixture = Fixture {
        weak: Arc::downgrade(&node),
        disk: disk.clone(),
        disk_config: disk_config.clone(),
        scratch,
        _directory: directory,
        path,
        lock: lock.clone(),
        release: Some(release),
        entered: entered.clone(),
        closing: closing.clone(),
    };
    let owner = PhysicalOwner {
        worker: Some(worker),
        node,
        entered,
        closing,
        panic_run,
        panic_close,
        report: Default::default(),
        _lock: create_lock(&disk, &disk_config, &lock),
    };
    let registration = Registration::new(
        Kind::Data,
        uuid::Uuid::new_v4(),
        &kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
    )
    .unwrap();
    (fixture, owner, registration)
}
impl Fixture {
    fn still_owned(&self) {
        assert!(self.weak.upgrade().is_some());
        assert!(
            NodeStore::open_existing(
                &self.path,
                kasumi_store::test_utils::NODE_STORE_ID,
                self.disk.clone(),
                self.scratch.clone(),
            )
            .is_err()
        );
        assert!(open_lock(&self.disk, &self.disk_config, &self.lock).is_err());
    }
    fn release(&mut self) {
        self.release.take().unwrap().send(()).unwrap();
    }
    async fn reopened(&self) {
        assert!(self.weak.upgrade().is_none());
        // Reuse the exact installed owners. A fixture re-census while holding
        // this same installation lock would correctly reject that live file.
        let _lock = open_lock(&self.disk, &self.disk_config, &self.lock).unwrap();
        let node = NodeStore::open_existing(
            &self.path,
            kasumi_store::test_utils::NODE_STORE_ID,
            self.disk.clone(),
            self.scratch.clone(),
        )
        .unwrap();
        node.shutdown().await.unwrap();
    }
}
async fn pending(future: &mut Pin<Box<impl Future>>) {
    std::future::poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await
}

#[tokio::test]
async fn unpolled_serving_waiter_drop_retains_physical_owner_through_cancelled_drain() {
    let registry = Arc::new(Registry::default());
    let (mut fixture, owner, registration) = fixture(false, false);
    let (_stop, shutdown) = watch::channel(false);
    let waiter = begin(registry.clone(), registration, owner, shutdown);
    assert_eq!(registry.lock().unwrap().len(), 1);
    // The public future has never been polled. Its Drop requests stop, while
    // its supervisor and actual node/installation lock are already registered.
    drop(waiter);
    tokio::time::timeout(Duration::from_secs(5), fixture.closing.notified())
        .await
        .unwrap();
    fixture.still_owned();
    let mut drain = Box::pin(drain_registry(&registry));
    pending(&mut drain).await;
    drop(drain);
    fixture.still_owned();
    fixture.release();
    tokio::time::timeout(Duration::from_secs(5), drain_registry(&registry))
        .await
        .unwrap()
        .unwrap();
    fixture.reopened().await;
    assert!(registry.lock().unwrap().is_empty());
}

#[tokio::test]
async fn serving_poll_and_drain_panics_keep_actual_owner_and_original_failures() {
    let registry = Arc::new(Registry::default());
    let (mut fixture, owner, registration) = fixture(true, true);
    let (_stop, shutdown) = watch::channel(false);
    let waiter = begin(registry.clone(), registration, owner, shutdown);
    drop(waiter);
    tokio::time::timeout(Duration::from_secs(5), fixture.closing.notified())
        .await
        .unwrap();
    fixture.still_owned();
    let job = registry.lock().unwrap()[0].clone();
    let issues = job.state.lock().unwrap().report.issues().to_vec();
    assert_eq!(issues.len(), 2);
    for issue in &issues {
        assert!(
            issue
                .error()
                .downcast_ref::<crate::startup_preparation::PreparationPanic>()
                .is_some()
        );
    }
    let mut drain = Box::pin(drain_registry(&registry));
    pending(&mut drain).await;
    drop(drain);
    fixture.still_owned();
    fixture.release();
    let failure = tokio::time::timeout(Duration::from_secs(5), drain_registry(&registry))
        .await
        .unwrap()
        .unwrap_err();
    let failure = failure
        .downcast_ref::<kasumi_types::drain::DrainFailure>()
        .unwrap();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 2);
    for (original, retained) in issues.iter().zip(failure.issues()) {
        assert!(Arc::ptr_eq(original, retained));
    }
    fixture.reopened().await;
}

#[tokio::test]
async fn aborted_serving_supervisor_keeps_inventory_for_joined_cleanup_only() {
    let registry = Arc::new(Registry::default());
    let (mut fixture, owner, registration) = fixture(false, false);
    let (_stop, shutdown) = watch::channel(false);
    let waiter = begin(registry.clone(), registration, owner, shutdown);
    tokio::time::timeout(Duration::from_secs(5), fixture.entered.notified())
        .await
        .unwrap();
    let job = registry.lock().unwrap()[0].clone();
    let aborted_id = {
        let handle = job.handle.lock().unwrap();
        let task = handle.as_ref().unwrap();
        task.abort();
        task.id()
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        while !job.handle.lock().unwrap().as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    fixture.still_owned();
    drop(waiter);
    let mut first = Box::pin(drain_registry(&registry));
    pending(&mut first).await;
    tokio::time::timeout(Duration::from_secs(5), fixture.closing.notified())
        .await
        .unwrap();
    drop(first);
    let issue = job.state.lock().unwrap().report.issues()[0].clone();
    let joined = issue
        .error()
        .downcast_ref::<tokio::task::JoinError>()
        .unwrap();
    assert!(joined.is_cancelled());
    assert_eq!(joined.id(), aborted_id);
    fixture.still_owned();
    fixture.release();
    let failure = tokio::time::timeout(Duration::from_secs(5), drain_registry(&registry))
        .await
        .unwrap()
        .unwrap_err();
    assert!(Arc::ptr_eq(
        &issue,
        &failure
            .downcast_ref::<kasumi_types::drain::DrainFailure>()
            .unwrap()
            .issues()[0]
    ));
    fixture.reopened().await;
}

#[tokio::test]
async fn unacknowledged_failure_fences_only_its_installation_and_drains_refused_replacement() {
    let registry = Arc::new(Registry::default());
    let (mut failed, owner, registration) = fixture(true, false);
    let identity = registration.identity;
    let (_stop, shutdown) = watch::channel(false);
    drop(begin(registry.clone(), registration, owner, shutdown));
    tokio::time::timeout(Duration::from_secs(5), failed.closing.notified())
        .await
        .unwrap();
    failed.release();
    let prior = registry.lock().unwrap()[0].clone();
    tokio::time::timeout(Duration::from_secs(5), prior.join())
        .await
        .unwrap();
    failed.reopened().await;
    let issue = prior.state.lock().unwrap().report.issues()[0].clone();
    assert!(check_admission(&registry, identity).is_err());
    check_admission(&registry, uuid::Uuid::new_v4()).unwrap();

    // Simulate a runtime already opened before this identity's prior failure was
    // observed. The atomic begin recheck drains that actual replacement owner
    // while never polling its run phase, and retains the original cause object.
    let (mut refused, replacement, mut registration) = fixture(false, false);
    registration.identity = identity;
    let (_stop, shutdown) = watch::channel(false);
    let waiter = begin(registry.clone(), registration, replacement, shutdown);
    tokio::time::timeout(Duration::from_secs(5), refused.closing.notified())
        .await
        .unwrap();
    let mut entered = Box::pin(refused.entered.notified());
    pending(&mut entered).await;
    drop(entered);
    refused.still_owned();
    refused.release();
    let error = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .unwrap()
        .unwrap_err();
    let observed = error
        .downcast_ref::<kasumi_types::drain::DrainFailure>()
        .unwrap();
    let prior_failure = observed.issues()[0]
        .error()
        .downcast_ref::<kasumi_types::drain::DrainFailure>()
        .unwrap();
    assert!(Arc::ptr_eq(&issue, &prior_failure.issues()[0]));
    refused.reopened().await;
    assert!(check_admission(&registry, identity).is_err());
    let error = drain_registry(&registry).await.unwrap_err();
    assert!(Arc::ptr_eq(
        &issue,
        &error
            .downcast_ref::<kasumi_types::drain::DrainFailure>()
            .unwrap()
            .issues()[0]
    ));
    check_admission(&registry, identity).unwrap();
}

#[tokio::test]
async fn panicking_owner_destructor_retains_unavailable_census_without_respawn_churn() {
    struct DestructorPanic {
        _node: Arc<NodeStore>,
        _lock: NodeDiskFile,
    }
    impl Owner for DestructorPanic {
        fn run<'a>(
            &'a mut self,
            _: &'a mut Shutdown,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
        fn close(&mut self) -> Pin<Box<dyn Future<Output = DrainResult> + Send + '_>> {
            Box::pin(self._node.shutdown())
        }
    }
    impl Drop for DestructorPanic {
        fn drop(&mut self) {
            panic!("actual owner destructor panic");
        }
    }
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("destructor.redb");
    let lock = directory.path().join("installation.lock");
    let disk_config = crate::persistent_disk::fixture_config(directory.path());
    let disk = crate::persistent_disk::open(&disk_config).unwrap();
    let scratch = ScratchDisk::fixture();
    let node = NodeStore::create_new(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        disk.clone(),
        scratch.clone(),
    )
    .unwrap();
    let registry = Arc::new(Registry::default());
    let registration = Registration::new(
        Kind::Data,
        uuid::Uuid::new_v4(),
        &kasumi_engine::admission::NodeAdmission::new(Default::default()).unwrap(),
    )
    .unwrap();
    let (_stop, shutdown) = watch::channel(false);
    drop(begin(
        registry.clone(),
        registration,
        DestructorPanic {
            _node: node,
            _lock: create_lock(&disk, &disk_config, &lock),
        },
        shutdown,
    ));
    let job = registry.lock().unwrap()[0].clone();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !job.handle.lock().unwrap().as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut drain = Box::pin(drain_registry(&registry));
    pending(&mut drain).await;
    drop(drain);
    assert!(job.owner.lock().await.is_none());
    assert!(job.handle.lock().unwrap().is_none());
    let issues = job.state.lock().unwrap().report.issues().to_vec();
    assert_eq!(issues.len(), 2);
    assert!(!job.state.lock().unwrap().complete);
    for _ in 0..3 {
        let mut retry = Box::pin(drain_registry(&registry));
        pending(&mut retry).await;
        drop(retry);
        assert!(job.handle.lock().unwrap().is_none());
        let state = job.state.lock().unwrap();
        assert_eq!(state.report.issues().len(), 2);
        assert!(Arc::ptr_eq(&issues[1], &state.report.issues()[1]));
    }
    // close actually drained the database before the destructor panicked, and
    // unwinding released its managed lock. The outer destructor census remains
    // unknown and retained even though these specific files can reopen.
    let _lock = open_lock(&disk, &disk_config, &lock).unwrap();
    let node = NodeStore::open_existing(
        &path,
        kasumi_store::test_utils::NODE_STORE_ID,
        disk,
        scratch,
    )
    .unwrap();
    node.shutdown().await.unwrap();
}

#[test]
fn serving_registration_retains_memory_without_an_inflight_operation_slot() {
    let admission =
        kasumi_engine::admission::NodeAdmission::new(kasumi_engine::admission::AdmissionConfig {
            max_inflight_operations: 1,
            ..Default::default()
        })
        .unwrap();
    let bookkeeping = admission.snapshot().bookkeeping_bytes;
    let registration = Registration::new(Kind::Data, uuid::Uuid::new_v4(), &admission).unwrap();
    assert_eq!(admission.snapshot().reserved_bytes, bookkeeping + 4096);
    assert_eq!(admission.snapshot().inflight_operations, 0);
    let request = admission.reserve(1, None).unwrap();
    assert_eq!(admission.snapshot().inflight_operations, 1);
    assert_eq!(admission.snapshot().reserved_bytes, bookkeeping + 4097);
    drop(request);
    assert_eq!(admission.snapshot().reserved_bytes, bookkeeping + 4096);
    drop(registration);
    assert_eq!(admission.snapshot().reserved_bytes, bookkeeping);
}
