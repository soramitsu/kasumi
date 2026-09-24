use super::*;
use redb::BackendNativeDisposition;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

#[derive(Debug)]
struct Marker(Arc<u64>);
impl std::fmt::Display for Marker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original sync error")
    }
}
impl std::error::Error for Marker {}

fn fixture() -> (tempfile::TempDir, Arc<ScratchDisk>, EncryptedSpool) {
    let directory = crate::test_utils::private_tempdir().unwrap();
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let disk = ScratchDisk::isolated_fixture(directory.path(), 8 << 20, memory);
    let spool = EncryptedSpool::new(&disk, 1 << 20).unwrap();
    (directory, disk, spool)
}

#[test]
fn retained_spool_retires_actual_descriptor_before_releasing_its_charge() {
    let (_directory, disk, spool) = fixture();
    let mut retained = spool.retain();
    assert_eq!(disk.snapshot().live_files, 1);
    let (descriptor, identity) = {
        let file = &retained.spool().unwrap().file;
        let metadata = file.metadata().unwrap();
        (file.as_raw_fd(), (metadata.dev(), metadata.ino()))
    };
    let outcome = retained.close();
    assert_eq!(
        outcome.native_disposition(),
        BackendNativeDisposition::Drained
    );
    outcome.into_result().unwrap();
    assert_eq!(retained.phase(), SpoolClosePhase::Complete);
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor, &mut stat) } == 0 {
        assert_ne!((stat.st_dev as u64, stat.st_ino as u64), identity);
    } else {
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(
        retained.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
}

#[test]
fn uncertain_native_close_retains_one_attempt_and_fences_scratch_owner() {
    let (_directory, disk, mut spool) = fixture();
    spool.sync_all().unwrap();
    let original_descriptor = spool.file.as_raw_fd();
    let outcome = spool.close_native_with(|descriptor| {
        assert_eq!(descriptor, original_descriptor);
        // The OS has actually retired the descriptor. EINTR is injected after
        // that syscall so a second close could hit an unrelated reused number.
        assert_eq!(unsafe { libc::close(descriptor) }, 0);
        Err(io::Error::from_raw_os_error(libc::EINTR))
    });
    assert_eq!(
        outcome.native_disposition(),
        BackendNativeDisposition::Retained
    );
    assert_eq!(
        outcome.into_result().unwrap_err().raw_os_error(),
        Some(libc::EINTR)
    );
    assert_eq!(
        spool.native_close,
        NativeClosePhase::Unknown(original_descriptor)
    );
    assert!(spool.file.0.is_none());
    assert_eq!(
        spool.check_owner().unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert!(!disk.snapshot().filesystem_admission_ready);

    let mut replayed = false;
    let repeat = spool.close_native_with(|_| {
        replayed = true;
        Ok(())
    });
    assert_eq!(
        repeat.native_disposition(),
        BackendNativeDisposition::Retained
    );
    assert!(!replayed, "an uncertain descriptor must never be retried");
    assert_eq!(disk.snapshot().live_files, 1);
    assert!(!disk.snapshot().filesystem_admission_ready);
}

#[test]
fn native_close_unwind_retains_original_payload_and_never_retries_number() {
    let (_directory, disk, mut spool) = fixture();
    spool
        .write_all(b"panic path holds an allocated extent")
        .unwrap();
    spool.sync_all().unwrap();
    spool.reserve_growth(spool.len(), 2 * BLOCK as u64).unwrap();
    let before = disk.snapshot();
    assert!(before.charged_bytes > 0);
    assert!(before.filesystem_pending_bytes > 0);
    let descriptor = spool.file.as_raw_fd();
    let marker = Arc::new(53_u64);
    let original = marker.clone();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = spool.close_native_with(|number| {
            assert_eq!(number, descriptor);
            // Model an unwind after the native syscall has already retired it.
            assert_eq!(unsafe { libc::close(number) }, 0);
            std::panic::panic_any(original);
        });
    }))
    .unwrap_err();
    assert!(Arc::ptr_eq(
        unwind.downcast_ref::<Arc<u64>>().unwrap(),
        &marker
    ));
    assert_eq!(spool.native_close, NativeClosePhase::Unknown(descriptor));
    assert!(spool.file.0.is_none());
    assert!(!disk.snapshot().filesystem_admission_ready);
    let repeat = spool.close_native_with(|_| panic!("native close replayed"));
    assert_eq!(
        repeat.native_disposition(),
        BackendNativeDisposition::Retained
    );
    let ((), allocations) = crate::allocation_tests::measure(|| drop(spool));
    assert_eq!(allocations, 0);
    let after = disk.snapshot();
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert_eq!(after.live_files, before.live_files);
    assert_eq!(
        after.filesystem_pending_bytes,
        before.filesystem_pending_bytes
    );
    assert!(!after.filesystem_admission_ready);
}

#[test]
fn sync_unwind_fences_owner_and_preserves_original_payload_without_native_entry() {
    let (_directory, disk, mut spool) = fixture();
    let descriptor = spool.file.as_raw_fd();
    let marker = Arc::new(67_u64);
    let original = marker.clone();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = spool.close_once_with(|_| std::panic::panic_any(original));
    }))
    .unwrap_err();
    assert!(Arc::ptr_eq(
        unwind.downcast_ref::<Arc<u64>>().unwrap(),
        &marker
    ));
    assert_eq!(spool.native_close, NativeClosePhase::Open);
    assert_eq!(spool.file.as_raw_fd(), descriptor);
    assert!(!disk.snapshot().filesystem_admission_ready);
    let repeat = spool.close_once_with(|_| panic!("sync retried"));
    assert_eq!(
        repeat.native_disposition(),
        BackendNativeDisposition::Retained
    );
}

#[test]
fn original_sync_error_retains_open_spool_without_claiming_native_drain() {
    let (_directory, disk, spool) = fixture();
    let mut retained = spool.retain();
    let marker = std::sync::Arc::new(41_u64);
    let original = io::Error::other(Marker(marker.clone()));
    let error = retained
        .close_with(|_| Err(original))
        .into_result()
        .unwrap_err();
    assert!(std::sync::Arc::ptr_eq(
        &error.get_ref().unwrap().downcast_ref::<Marker>().unwrap().0,
        &marker
    ));
    assert_eq!(retained.phase(), SpoolClosePhase::FailedTransferred);
    assert_eq!(disk.snapshot().live_files, 1);
    assert_eq!(
        retained.close().native_disposition(),
        BackendNativeDisposition::Retained
    );
}

#[test]
fn unknown_native_close_keeps_charge_after_aggregate_owner_drop() {
    let (_directory, disk, mut spool) = fixture();
    spool.write_all(b"charged ciphertext").unwrap();
    spool.sync_all().unwrap();
    spool.reserve_growth(spool.len(), 2 * BLOCK as u64).unwrap();
    let before = disk.snapshot();
    assert!(before.charged_bytes > 0);
    assert!(before.filesystem_pending_bytes > 0);
    let outcome = spool.close_native_with(|descriptor| {
        assert_eq!(unsafe { libc::close(descriptor) }, 0);
        Err(io::Error::from_raw_os_error(libc::EINTR))
    });
    assert_eq!(
        outcome.native_disposition(),
        BackendNativeDisposition::Retained
    );
    assert_eq!(
        outcome.into_result().unwrap_err().raw_os_error(),
        Some(libc::EINTR)
    );
    let ((), allocations) = crate::allocation_tests::measure(|| drop(spool));
    assert_eq!(allocations, 0);
    let snapshot = disk.snapshot();
    assert_eq!(snapshot.charged_bytes, before.charged_bytes);
    assert_eq!(snapshot.live_files, before.live_files);
    assert_eq!(
        snapshot.filesystem_pending_bytes,
        before.filesystem_pending_bytes
    );
    assert!(!snapshot.filesystem_admission_ready);
}
