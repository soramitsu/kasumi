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
    let (charged, charge_retired) = crate::test_utils::observed_budget_charge();
    let owner = SnapshotBufferOwner::new(1, charged)?;
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
    assert!(!charge_retired.load(std::sync::atomic::Ordering::Acquire));
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
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &original,
        &repeated.issues()[0]
    ));
    assert_eq!(disk.snapshot().live_files, 0);
    drop(owner);
    assert!(weak.upgrade().is_none());
    assert!(charge_retired.load(std::sync::atomic::Ordering::Acquire));
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
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &original,
        &repeated.issues()[0]
    ));
    assert!(SnapshotBuffer::new(&disk, 1 << 20, &owner).is_err());
    let global = owner.drain().await.unwrap_err();
    assert!(kasumi_types::drain::DrainIssueRef::ptr_eq(
        &original,
        &global.issues()[0]
    ));
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
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
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
    let (charge, charge_retired) = crate::test_utils::observed_budget_charge();
    let owner = SnapshotBufferOwner::new(1, charge)?;
    let weak = Arc::downgrade(&owner);
    drop(owner);
    assert!(weak.upgrade().is_none());
    assert!(charge_retired.load(std::sync::atomic::Ordering::Acquire));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_startup_keeps_original_error_while_actual_child_drains() -> anyhow::Result<()> {
    let disk_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch = kasumi_store::ScratchDisk::fixture(scratch_directory.path(), disk_memory);
    let disk = fixture_scratch.clone();
    let owner = SnapshotBufferOwner::new(1, kasumi_types::SharedBudgetCharge::new(()))?;
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
    let first_original = anyhow::Error::new(OriginalFailure(321));
    let first_outer: &(dyn std::error::Error + Send + Sync + 'static) = first_original.as_ref();
    let first_address = first_outer as *const _ as *const () as usize;
    let mut first = Box::pin(crate::failed_startup(
        kasumi_store::ScratchOperationFailure::Operation(first_original),
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
    let second_original = anyhow::Error::new(OriginalFailure(999));
    let second_outer: &(dyn std::error::Error + Send + Sync + 'static) = second_original.as_ref();
    let second_address = second_outer as *const _ as *const () as usize;
    assert_ne!(first_address, second_address);
    let error = crate::failed_startup(
        kasumi_store::ScratchOperationFailure::Operation(second_original),
        &owner,
        &storage,
    )
    .await;
    let outer: &(dyn std::error::Error + Send + Sync + 'static) =
        error.operation_error().unwrap().as_ref();
    let failure = outer.downcast_ref::<DrainFailure>().unwrap();
    assert_eq!(failure.completion(), DrainCompletion::Complete);
    assert_eq!(failure.issues().len(), 3);
    let original = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "Raft startup" && issue.instance() == first_address)
        .unwrap();
    assert_eq!(
        original
            .error()
            .downcast_ref::<OriginalFailure>()
            .unwrap()
            .0,
        321
    );
    let first_outer: &(dyn std::error::Error + Send + Sync + 'static) = original.error().as_ref();
    assert_eq!(first_outer as *const _ as *const () as usize, first_address);
    let independent = failure
        .issues()
        .iter()
        .find(|issue| issue.component() == "Raft startup" && issue.instance() == second_address)
        .unwrap();
    let second_outer: &(dyn std::error::Error + Send + Sync + 'static) =
        independent.error().as_ref();
    assert_eq!(
        second_outer as *const _ as *const () as usize,
        second_address
    );
    assert_eq!(
        second_outer.downcast_ref::<OriginalFailure>().unwrap().0,
        999
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

#[tokio::test]
async fn startup_slot_reuse_requires_positive_delivered_shutdown_and_keeps_alias_charge() {
    let (charge, charge_retired) = crate::test_utils::observed_budget_charge();
    let owner = SnapshotBufferOwner::new(1, charge).unwrap();
    assert!(
        !owner.startup_slot_reusable(),
        "idle startup is still admitted"
    );
    let ownership = Arc::new(AtomicBool::new(true));
    owner
        .bind_fixture_group_ownership(ownership.clone(), Arc::new(()))
        .unwrap();
    let (release, ready) = tokio::sync::oneshot::channel();
    let mut opening = Box::pin(owner.start::<_, anyhow::Error>(async move {
        ready.await?;
        Ok(crate::startup_owner_tests::source_custody_fixture_group(
            tokio::spawn(async {}),
        ))
    }));
    std::future::poll_fn(|cx| {
        assert!(opening.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(
        !owner.startup_slot_reusable(),
        "pending startup owns its seat"
    );
    release.send(()).unwrap();
    let group = opening.await.unwrap();
    assert!(
        !owner.startup_slot_reusable(),
        "delivered runtime is still live"
    );
    owner.drain_buffers().await.unwrap();
    assert!(
        !owner.startup_slot_reusable(),
        "buffer closure is not group join"
    );
    match group {
        crate::startup_owner::StartedGroup::Fixture(mut group) => {
            group.shutdown().await.unwrap();
        }
        _ => unreachable!(),
    }
    owner.drain_application_sources().await.unwrap();
    assert!(
        !owner.startup_slot_reusable(),
        "group ownership is not released"
    );
    {
        let _startup = owner.startup.try_lock().unwrap();
        owner.release_group_ownership();
        assert!(!ownership.load(Ordering::Acquire));
        assert!(retained().lock().unwrap().contains_key(&owner.id));
        assert!(
            !owner.startup_slot_reusable(),
            "global custody is not released"
        );
    }
    owner.release_group_ownership();
    assert!(!retained().lock().unwrap().contains_key(&owner.id));
    assert!(owner.startup_slot_reusable());
    {
        let _startup = owner.startup.try_lock().unwrap();
        assert!(
            owner.startup_slot_reusable(),
            "released query never contends startup"
        );
    }
    {
        let _drain = owner.drain_gate.try_lock().unwrap();
        assert!(!owner.startup_slot_reusable());
    }
    {
        let _cells = owner.cells.try_lock().unwrap();
        assert!(!owner.startup_slot_reusable());
    }
    {
        let _report = owner.report.try_lock().unwrap();
        assert!(!owner.startup_slot_reusable());
    }
    let alias = owner.clone();
    drop(owner);
    assert!(alias.startup_slot_reusable());
    assert!(!charge_retired.load(Ordering::Acquire));
    drop(alias);
    assert!(charge_retired.load(Ordering::Acquire));
}

#[tokio::test]
async fn startup_slot_reuse_preserves_complete_and_retained_original_failure_reports() {
    use kasumi_types::drain::DrainIssueRef;
    for completion in [DrainCompletion::Complete, DrainCompletion::Retained] {
        let owner = SnapshotBufferOwner::new(1, SharedBudgetCharge::new(())).unwrap();
        let ownership = Arc::new(AtomicBool::new(true));
        owner
            .bind_fixture_group_ownership(ownership, Arc::new(()))
            .unwrap();
        let group = owner
            .start::<_, anyhow::Error>(async {
                Ok(crate::startup_owner_tests::source_custody_fixture_group(
                    tokio::spawn(async {}),
                ))
            })
            .await
            .unwrap();
        match group {
            crate::startup_owner::StartedGroup::Fixture(mut group) => {
                group.shutdown().await.unwrap();
            }
            _ => unreachable!(),
        }
        owner.drain_buffers().await.unwrap();
        owner.drain_application_sources().await.unwrap();
        owner.release_group_ownership();
        assert!(owner.startup_slot_reusable());
        let mut report = DrainReport::default();
        let original = report.record("original startup failure", 0, OriginalFailure(229).into());
        let failure = match completion {
            DrainCompletion::Complete => report.complete().unwrap_err(),
            DrainCompletion::Retained => DrainFailure::retained(original.clone()),
        };
        // A completed owner can still carry a previously returned original.
        // Neither the exact report nor its failure disposition is disposable.
        let recorded = owner.record_startup_error(failure.into());
        assert_eq!(recorded.completion(), completion);
        for _ in 0..2 {
            assert!(!owner.startup_slot_reusable());
            let stored = owner.report.lock().unwrap();
            assert!(
                stored
                    .issues()
                    .iter()
                    .any(|issue| DrainIssueRef::ptr_eq(issue, &original))
            );
            let outer = stored
                .issues()
                .iter()
                .find_map(|issue| issue.error().downcast_ref::<DrainFailure>())
                .expect("original typed startup outcome remains stored");
            assert_eq!(outer.completion(), completion);
            assert!(DrainIssueRef::ptr_eq(&outer.issues()[0], &original));
        }
    }
}
