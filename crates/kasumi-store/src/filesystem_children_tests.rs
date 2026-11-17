//! A cancelled destination caller leaves its real blocking child, the files it
//! holds and its terminal outcome with the installed disk.
use crate::{
    BackupDestination, BackupUpload, FilesystemBackupDestination, NodeDisk,
    backup_sessions::filesystem::test_sync,
    test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry},
};
use kasumi_types::drain::{DrainCompletion, DrainIssueRef, DrainResult};
use std::{future::Future, pin::Pin, sync::Arc, task::Poll, time::Duration};
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(10);

struct Fixture {
    _temporary: tempfile::TempDir,
    root: std::path::PathBuf,
    disk: Arc<NodeDisk>,
    destination: Arc<FilesystemBackupDestination>,
}
fn fixture() -> Fixture {
    let temporary = private_tempdir().unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| {
        NodeDisk::fixture_for_path(temporary.path().join("unused"), memory.clone())
    })
    .unwrap();
    let root = temporary.path().join("backup");
    let destination =
        Arc::new(FilesystemBackupDestination::new(&root, 1 << 20, disk.clone()).unwrap());
    Fixture {
        _temporary: temporary,
        root,
        disk,
        destination,
    }
}

async fn entered(paused: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || paused.recv_timeout(WAIT))
        .await
        .unwrap()
        .unwrap();
}

async fn pending_once(drain: &mut Pin<Box<impl Future<Output = DrainResult>>>) {
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

/// Start `put`, stop its child after it created the pending inode, and cancel
/// the caller there.
async fn abandoned_put(fixture: &Fixture, id: Uuid) -> std::sync::mpsc::SyncSender<()> {
    let name = format!("{id}.kasumi");
    let (paused, release) =
        test_sync::pause(&fixture.root, &name, test_sync::Point::BackupCreated).unwrap();
    let destination = fixture.destination.clone();
    let caller = tokio::spawn(async move {
        destination
            .put(id, BackupUpload::received(vec![7; 4096]))
            .await
    });
    entered(paused).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    release
}

#[tokio::test]
async fn cancelled_put_keeps_its_child_and_later_failure_with_the_disk() {
    let fixture = fixture();
    let id = Uuid::new_v4();
    let name = format!("{id}.kasumi");
    let open_before = fixture.disk.snapshot().open_files;
    let release = abandoned_put(&fixture, id).await;

    // The caller is gone; the child and the file it created are not.
    assert_eq!(fixture.disk.filesystem_children_running(), 1);
    assert!(fixture.disk.snapshot().open_files > open_before);
    let mut first = Box::pin(fixture.disk.drain_filesystem_children());
    pending_once(&mut first).await;
    drop(first);
    assert_eq!(fixture.disk.filesystem_children_running(), 1);
    assert!(fixture.disk.snapshot().open_files > open_before);

    // The write now fails where nobody is waiting for it.
    let _fault = test_sync::fail(&fixture.root, &name, &[test_sync::Point::BackupCreated]).unwrap();
    release.send(()).unwrap();
    let failure = tokio::time::timeout(WAIT, fixture.disk.drain_filesystem_children())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 1);
    let original = &failure.issues()[0];
    assert_eq!(original.component(), "filesystem child");
    assert!(
        format!("{:#}", original.error())
            .contains("injected backup session synchronization failure")
    );
    assert_eq!(fixture.disk.filesystem_children_running(), 0);
    // The failed creation fenced the disk, which keeps the inode's custody.
    assert_eq!(fixture.disk.snapshot().phase, crate::NodeDiskPhase::Failed);
    let repeated = fixture.disk.drain_filesystem_children().await.unwrap_err();
    assert!(DrainIssueRef::ptr_eq(original, &repeated.issues()[0]));
    assert!(!fixture.root.join(&name).exists());
}

#[tokio::test]
async fn cancelled_put_that_completes_is_published_and_drains_clean() {
    let fixture = fixture();
    let id = Uuid::new_v4();
    let release = abandoned_put(&fixture, id).await;
    release.send(()).unwrap();
    tokio::time::timeout(WAIT, fixture.disk.drain_filesystem_children())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fixture.disk.filesystem_children_running(), 0);
    // Nothing writes after the drain: the object is already complete.
    assert_eq!(
        fixture.destination.get(id, 1 << 20).await.unwrap(),
        vec![7; 4096]
    );
    // The create-only conflict the caller receives is its own outcome.
    assert!(
        fixture
            .destination
            .put(id, BackupUpload::received(vec![9; 4096]))
            .await
            .is_err()
    );
    fixture.disk.drain_filesystem_children().await.unwrap();
}

#[tokio::test]
async fn abandoned_read_failure_is_not_evidence() {
    let fixture = fixture();
    let id = Uuid::new_v4();
    let name = format!("{id}.kasumi");
    fixture
        .destination
        .put(id, BackupUpload::received(vec![3; 4096]))
        .await
        .unwrap();
    let (paused, release) =
        test_sync::pause(&fixture.root, &name, test_sync::Point::ReadFile).unwrap();
    let destination = fixture.destination.clone();
    let reader = tokio::spawn(async move { destination.get(id, 1 << 20).await });
    entered(paused).await;
    reader.abort();
    assert!(reader.await.unwrap_err().is_cancelled());
    assert_eq!(fixture.disk.filesystem_children_running(), 1);
    let _fault = test_sync::fail(&fixture.root, &name, &[test_sync::Point::ReadFile]).unwrap();
    release.send(()).unwrap();
    tokio::time::timeout(WAIT, fixture.disk.drain_filesystem_children())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fixture.disk.filesystem_children_running(), 0);
}

/// One abandoned child of `effect` that ends with `outcome` after its caller
/// was cancelled.
async fn abandoned(
    disk: &Arc<NodeDisk>,
    effect: crate::FilesystemEffect,
    outcome: impl FnOnce() -> anyhow::Result<()> + Send + 'static,
) {
    let (started, running) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel::<()>();
    let owner = disk.clone();
    let caller = tokio::spawn(async move {
        owner
            .filesystem_child(effect, move || {
                let _ = started.send(());
                let _ = held.recv();
                outcome()
            })
            .await
    });
    tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    release.send(()).unwrap();
}

#[tokio::test]
async fn only_an_unobserved_write_failure_or_a_panic_becomes_disk_evidence() {
    use crate::FilesystemEffect::{Read, Write};
    let fixture = fixture();
    let disk = &fixture.disk;
    let conflict = || std::io::Error::from(std::io::ErrorKind::AlreadyExists);

    // A create-only conflict found before any effect changed nothing.
    abandoned(disk, Write, move || Err(conflict().into())).await;
    abandoned(disk, Read, || anyhow::bail!("unobserved read failure")).await;
    abandoned(disk, Write, || Ok(())).await;
    tokio::time::timeout(WAIT, disk.drain_filesystem_children())
        .await
        .unwrap()
        .unwrap();

    // The same kind after a failed re-verification is no longer a known one.
    abandoned(disk, Write, move || {
        Err(anyhow::Error::new(conflict()).context("destination was not re-verified"))
    })
    .await;
    let failure = tokio::time::timeout(WAIT, disk.drain_filesystem_children())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.issues().len(), 1);
    assert_eq!(
        failure.issues()[0]
            .error()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );

    abandoned(disk, Read, || panic!("original filesystem child panic")).await;
    let failure = tokio::time::timeout(WAIT, disk.drain_filesystem_children())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 2);
    assert!(
        failure.issues()[1]
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic()
    );
    // A caller that receives its child's failure owns it: no third issue.
    let received = disk
        .filesystem_child(Write, || -> anyhow::Result<()> {
            anyhow::bail!("received write failure")
        })
        .await
        .unwrap_err();
    assert_eq!(received.to_string(), "received write failure");
    let repeated = disk.drain_filesystem_children().await.unwrap_err();
    assert_eq!(repeated.issues().len(), 2);
    assert!(DrainIssueRef::ptr_eq(
        &failure.issues()[0],
        &repeated.issues()[0]
    ));
}

#[tokio::test]
async fn node_shutdown_keeps_its_database_open_until_the_disk_joins_an_abandoned_child() {
    let temporary = private_tempdir().unwrap();
    let scratch = private_tempdir().unwrap();
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let node = crate::NodeStore::create_new_fixture(
        temporary.path().join("node.kv"),
        crate::test_utils::NODE_STORE_ID,
        memory.clone(),
        crate::ScratchDisk::fixture(scratch.path(), memory.clone()),
    )
    .unwrap();
    let disk = node.persistent_disk().clone();
    let root = temporary.path().join("backup");
    let destination =
        Arc::new(FilesystemBackupDestination::new(&root, 1 << 20, disk.clone()).unwrap());
    let fixture = Fixture {
        _temporary: temporary,
        root,
        disk,
        destination,
    };
    let id = Uuid::new_v4();
    let release = abandoned_put(&fixture, id).await;

    let mut closing = Box::pin(node.shutdown());
    pending_once(&mut closing).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    pending_once(&mut closing).await;
    assert_eq!(fixture.disk.filesystem_children_running(), 1);
    // A cancelled shutdown leaves the child with the disk for the next one.
    drop(closing);
    assert_eq!(fixture.disk.filesystem_children_running(), 1);

    release.send(()).unwrap();
    tokio::time::timeout(WAIT, node.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fixture.disk.filesystem_children_running(), 0);
    assert!(fixture.root.join(format!("{id}.kasumi")).exists());
}

#[tokio::test]
async fn queued_child_that_holds_no_file_yet_keeps_the_disk_from_pausing() {
    let Fixture {
        _temporary,
        disk,
        destination,
        ..
    } = fixture();
    // The destination's retained root descriptor would keep the disk busy.
    drop(destination);
    let disk = &disk;
    disk.pause().unwrap();
    disk.reconcile(&crate::CensusCancellation::default())
        .unwrap();
    let open_before = disk.snapshot().open_files;
    let (started, running) = tokio::sync::oneshot::channel();
    let (release, held) = std::sync::mpsc::channel::<()>();
    let owner = disk.clone();
    let caller = tokio::spawn(async move {
        owner
            .filesystem_child(crate::FilesystemEffect::Write, move || {
                let _ = started.send(());
                let _ = held.recv();
                Ok(())
            })
            .await
    });
    tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());

    // The child opened nothing, yet it may still: neither pause nor the
    // idle census may declare the disk drained.
    assert_eq!(disk.snapshot().open_files, open_before);
    assert!(disk.pause().is_err());
    assert!(
        disk.reconcile(&crate::CensusCancellation::default())
            .is_err()
    );
    release.send(()).unwrap();
    tokio::time::timeout(WAIT, disk.drain_filesystem_children())
        .await
        .unwrap()
        .unwrap();
    disk.pause().unwrap();
    disk.reconcile(&crate::CensusCancellation::default())
        .unwrap();
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
}
