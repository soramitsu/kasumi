use super::*;
use kasumi_types::drain::{DrainCompletion, DrainFailure};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[derive(Debug)]
pub(super) struct ChildControl {
    entered: tokio::sync::Notify,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    outcome: u8,
}
impl ChildControl {
    fn paused(buffer: &SnapshotBuffer, outcome: u8) -> (Arc<Self>, std::sync::mpsc::Sender<()>) {
        let (release, receiver) = std::sync::mpsc::channel();
        let control = Arc::new(Self {
            entered: Default::default(),
            release: Mutex::new(Some(receiver)),
            outcome,
        });
        *buffer.cell.next_child.lock().unwrap() = Some(control.clone());
        (control, release)
    }
    pub(super) fn run(&self) -> io::Result<()> {
        self.entered.notify_one();
        self.release
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("snapshot test release deadline");
        match self.outcome {
            1 => Err(io::Error::other(OriginalFailure(73))),
            2 => std::panic::panic_any(OriginalFailure(97)),
            _ => Ok(()),
        }
    }
}
#[derive(Debug)]
struct OriginalFailure(u64);
impl std::fmt::Display for OriginalFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original snapshot failure {}", self.0)
    }
}
impl std::error::Error for OriginalFailure {}
async fn begin_write(buffer: &mut SnapshotBuffer) {
    let mut write = Box::pin(buffer.write(b"original encrypted snapshot bytes"));
    std::future::poll_fn(|cx| {
        assert!(write.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_write_and_shutdown_join_actual_child_before_freezing() -> anyhow::Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = fixture_scratch.clone();
    let owner = SnapshotBufferOwner::fixture();
    let mut buffer = SnapshotBuffer::new(&disk, 1 << 20, &owner)?;
    let (control, release) = ChildControl::paused(&buffer, 0);
    begin_write(&mut buffer).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        control.entered.notified(),
    )
    .await?;
    let mut first = Box::pin(buffer.shutdown());
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    assert_eq!(disk.snapshot().live_files, 1);
    release.send(())?;
    buffer.drain().await?;
    buffer.drain().await?;
    let image = buffer.into_image()?;
    let mut bytes = Vec::new();
    image.reader().read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"original encrypted snapshot bytes");
    owner.drain().await?;
    drop(image);
    assert_eq!(disk.snapshot().live_files, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abandoned_facade_and_cancelled_owner_drain_keep_actual_panic_and_charge()
-> anyhow::Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = fixture_scratch.clone();
    let charged = Arc::new(());
    let owner = SnapshotBufferOwner::new(1, charged.clone())?;
    let weak = Arc::downgrade(&owner);
    let mut buffer = SnapshotBuffer::new(&disk, 1 << 20, &owner)?;
    let (control, release) = ChildControl::paused(&buffer, 2);
    begin_write(&mut buffer).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        control.entered.notified(),
    )
    .await?;
    drop(buffer);
    drop(owner);
    let owner = weak.upgrade().expect("custody survives every facade");
    assert!(Arc::strong_count(&charged) > 1);
    let mut first = Box::pin(owner.drain());
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    assert_eq!(disk.snapshot().live_files, 1);
    release.send(())?;
    let failure = owner.drain().await.unwrap_err();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    let original = failure.issues()[0].clone();
    assert!(
        original
            .error()
            .downcast_ref::<tokio::task::JoinError>()
            .unwrap()
            .is_panic()
    );
    let repeated = owner.drain().await.unwrap_err();
    assert!(Arc::ptr_eq(&original, &repeated.issues()[0]));
    assert_eq!(disk.snapshot().live_files, 0);
    drop(owner);
    assert!(weak.upgrade().is_none());
    assert_eq!(Arc::strong_count(&charged), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn original_io_failure_survives_io_bridge_and_repeated_typed_drain() -> anyhow::Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = fixture_scratch.clone();
    let owner = SnapshotBufferOwner::fixture();
    let mut buffer = SnapshotBuffer::new(&disk, 1 << 20, &owner)?;
    let (control, release) = ChildControl::paused(&buffer, 1);
    begin_write(&mut buffer).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        control.entered.notified(),
    )
    .await?;
    release.send(())?;
    let error = buffer.shutdown().await.unwrap_err();
    let bridge = error
        .get_ref()
        .unwrap()
        .downcast_ref::<DrainFailure>()
        .unwrap();
    let original = bridge.issues()[0].clone();
    let source = original.error().downcast_ref::<io::Error>().unwrap();
    assert_eq!(
        source
            .get_ref()
            .unwrap()
            .downcast_ref::<OriginalFailure>()
            .unwrap()
            .0,
        73
    );
    let repeated = buffer.drain().await.unwrap_err();
    assert!(Arc::ptr_eq(&original, &repeated.issues()[0]));
    assert!(SnapshotBuffer::new(&disk, 1 << 20, &owner).is_err());
    let global = owner.drain().await.unwrap_err();
    assert!(Arc::ptr_eq(&original, &global.issues()[0]));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_read_is_joined_by_shutdown_and_cancelled_read_keeps_unread_bytes()
-> anyhow::Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = fixture_scratch.clone();
    let owner = SnapshotBufferOwner::fixture();
    let mut buffer = SnapshotBuffer::from_bytes(&disk, b"abcdefgh".to_vec(), 8, &owner)?;
    let (control, release) = ChildControl::paused(&buffer, 0);
    let mut large = [0; 8];
    let mut read = Box::pin(buffer.read(&mut large));
    std::future::poll_fn(|cx| {
        assert!(read.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(read);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        control.entered.notified(),
    )
    .await?;
    release.send(())?;
    let mut small = [0; 3];
    buffer.read_exact(&mut small).await?;
    assert_eq!(&small, b"abc");
    let mut rest = [0; 5];
    buffer.read_exact(&mut rest).await?;
    assert_eq!(&rest, b"defgh");
    buffer.seek(SeekFrom::Start(0)).await?;
    let (control, release) = ChildControl::paused(&buffer, 0);
    let mut read = Box::pin(buffer.read(&mut large));
    std::future::poll_fn(|cx| {
        assert!(read.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(read);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        control.entered.notified(),
    )
    .await?;
    let mut close = Box::pin(buffer.shutdown());
    std::future::poll_fn(|cx| {
        assert!(close.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(close);
    release.send(())?;
    buffer.shutdown().await?;
    owner.drain().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_child_holds_its_fixed_slot_until_actual_join() -> anyhow::Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = fixture_scratch.clone();
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let mut buffer = SnapshotBuffer::new(&disk, 1 << 20, &owner)?;
    let (control, release) = ChildControl::paused(&buffer, 0);
    begin_write(&mut buffer).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        control.entered.notified(),
    )
    .await?;
    drop(buffer);
    assert!(SnapshotBuffer::new(&disk, 1 << 20, &owner).is_err());
    assert_eq!(disk.snapshot().live_files, 1);
    release.send(())?;
    owner.drain().await?;
    assert_eq!(disk.snapshot().live_files, 0);
    assert!(SnapshotBuffer::new(&disk, 1 << 20, &owner).is_err());
    Ok(())
}

#[test]
fn unused_owner_releases_its_reservation_without_a_drain() -> anyhow::Result<()> {
    let charge = Arc::new(());
    let owner = SnapshotBufferOwner::new(1, charge.clone())?;
    let weak = Arc::downgrade(&owner);
    drop(owner);
    assert!(weak.upgrade().is_none());
    assert_eq!(Arc::strong_count(&charge), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_startup_keeps_original_error_while_actual_child_drains() -> anyhow::Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = fixture_scratch.clone();
    let owner = SnapshotBufferOwner::new(1, Arc::new(()))?;
    let mut buffer = SnapshotBuffer::new(&disk, 1 << 20, &owner)?;
    let (control, release) = ChildControl::paused(&buffer, 1);
    begin_write(&mut buffer).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        control.entered.notified(),
    )
    .await?;
    let (storage, lease) = crate::lifetime::StorageDrain::new();
    drop(lease);
    let mut first = Box::pin(crate::failed_startup(
        OriginalFailure(321).into(),
        &owner,
        &storage,
    ));
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(first);
    assert_eq!(disk.snapshot().live_files, 1);
    release.send(())?;
    let error = crate::failed_startup(OriginalFailure(999).into(), &owner, &storage).await;
    let failure = error.downcast_ref::<DrainFailure>().unwrap();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 2);
    let original = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "Raft startup")
        .unwrap();
    assert_eq!(
        original
            .error()
            .downcast_ref::<OriginalFailure>()
            .unwrap()
            .0,
        321
    );
    let child = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "snapshot blocking I/O")
        .unwrap();
    assert_eq!(
        child
            .error()
            .downcast_ref::<io::Error>()
            .unwrap()
            .get_ref()
            .unwrap()
            .downcast_ref::<OriginalFailure>()
            .unwrap()
            .0,
        73
    );
    assert_eq!(disk.snapshot().live_files, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_close_retains_the_actual_flush_child() -> anyhow::Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = fixture_scratch.clone();
    let owner = SnapshotBufferOwner::fixture();
    let mut buffer = SnapshotBuffer::new(&disk, 1 << 20, &owner)?;
    buffer.write_all(b"dirty encrypted block").await?;
    let (control, release) = ChildControl::paused(&buffer, 0);
    let mut close = Box::pin(buffer.shutdown());
    std::future::poll_fn(|cx| {
        assert!(close.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(close);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        control.entered.notified(),
    )
    .await?;
    let mut drain = Box::pin(owner.drain());
    std::future::poll_fn(|cx| {
        assert!(drain.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(drain);
    assert_eq!(disk.snapshot().live_files, 1);
    release.send(())?;
    let (global, local) = tokio::join!(owner.drain(), buffer.drain());
    global?;
    local?;
    assert_eq!(disk.snapshot().live_files, 0);
    Ok(())
}
