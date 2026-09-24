use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};
use std::{io, os::unix::fs::MetadataExt};

fn installed(path: &Path, payload_bytes: u64, files: u64) -> Arc<crate::NodeDisk> {
    let mut config = crate::NodeDisk::fixture_config(path.join("unused")).unwrap();
    config.max_bytes = config.directory_policy.extent_bytes + payload_bytes;
    config.maintenance_reserve_bytes = 0;
    config.max_persistent_files = files;
    let memory = TestDiskMemory::new(256 << 20, 4096);
    retry_disk_registry(|| {
        crate::NodeDisk::open_fixture(
            &config,
            memory.clone(),
            &crate::CensusCancellation::default(),
        )
    })
    .unwrap()
}
fn kind(error: &anyhow::Error) -> io::ErrorKind {
    error.downcast_ref::<io::Error>().unwrap().kind()
}

#[test]
fn backup_file_denies_complete_extent_before_creating_a_pending_inode() {
    let temporary = private_tempdir().unwrap();
    let disk = installed(temporary.path(), 4096, 1);
    let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
    let id = Uuid::new_v4();
    let before = disk.snapshot();
    let error = directory.put_backup(id, &[17; 8192]).unwrap_err();
    assert_eq!(kind(&error), io::ErrorKind::StorageFull);
    assert!(
        !temporary
            .path()
            .join(format!("{id}.kasumi.pending"))
            .exists()
    );
    assert!(!temporary.path().join(format!("{id}.kasumi")).exists());
    let after = disk.snapshot();
    assert_eq!(after.phase, crate::NodeDiskPhase::Open);
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert_eq!(after.pending_bytes, before.pending_bytes);
    assert_eq!(after.persistent_files, before.persistent_files);
    assert_eq!(after.open_files, before.open_files);
}

#[test]
fn backup_file_denies_inode_cardinality_before_creating_a_pending_inode() {
    let temporary = private_tempdir().unwrap();
    crate::private_files::create(&temporary.path().join("enrolled"), &[]).unwrap();
    let disk = installed(temporary.path(), 16 << 10, 1);
    let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
    let before = disk.snapshot();
    let error = directory
        .put_backup(Uuid::new_v4(), &[17; 8192])
        .unwrap_err();
    assert_eq!(kind(&error), io::ErrorKind::StorageFull);
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 1);
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.snapshot().persistent_files, before.persistent_files);
}

#[test]
fn backup_file_publishes_original_inode_with_complete_precreation_reservation() {
    let temporary = private_tempdir().unwrap();
    let disk = installed(temporary.path(), 8192, 1);
    let directory = Arc::new(Directory::open(temporary.path(), disk.clone()).unwrap());
    let id = Uuid::new_v4();
    let name = format!("{id}.kasumi");
    let path = temporary.path().join(&name);
    let pending = temporary.path().join(format!("{name}.pending"));
    let before = disk.snapshot();
    let (entered, release) =
        test_sync::pause(temporary.path(), &name, test_sync::Point::BackupCreated).unwrap();
    let worker = std::thread::spawn(move || directory.put_backup(id, &[73; 8192]));
    entered
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    let original = pending.metadata().unwrap();
    assert_eq!(original.len(), 0);
    assert!(!path.exists());
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes + 8192);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes + 8192);
    assert_eq!(disk.snapshot().persistent_files, 1);
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    let published = path.metadata().unwrap();
    assert_eq!(
        (published.dev(), published.ino()),
        (original.dev(), original.ino())
    );
    assert_eq!(published.len(), 8192);
    assert_eq!(std::fs::read(path).unwrap(), [73; 8192]);
    assert!(!pending.exists());
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes + 8192);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.snapshot().persistent_files, 1);
}

#[test]
fn backup_file_never_adopts_existing_pending_or_overwrites_published_bytes() {
    for pending in [false, true] {
        let temporary = private_tempdir().unwrap();
        let id = Uuid::new_v4();
        let name = format!("{id}.kasumi");
        let original_path = temporary.path().join(if pending {
            format!("{name}.pending")
        } else {
            name.clone()
        });
        crate::private_files::create(&original_path, &[91; 8192]).unwrap();
        let original = original_path.metadata().unwrap();
        let disk = installed(temporary.path(), 16 << 10, 2);
        let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
        let before = disk.snapshot();
        for bytes in [&[23; 4096][..], &[91; 8192][..]] {
            let error = directory.put_backup(id, bytes).unwrap_err();
            assert_eq!(kind(&error), io::ErrorKind::AlreadyExists);
            let after = original_path.metadata().unwrap();
            assert_eq!(
                (after.dev(), after.ino(), after.len()),
                (original.dev(), original.ino(), original.len())
            );
            assert_eq!(std::fs::read(&original_path).unwrap(), [91; 8192]);
            assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
            assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
            assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
            assert_eq!(disk.snapshot().persistent_files, 1);
        }
        assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 1);
    }
}

#[test]
fn backup_file_claim_rejects_nil_and_busy_without_owned_path_allocation() {
    let temporary = private_tempdir().unwrap();
    let disk = installed(temporary.path(), 8192, 1);
    let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
    let (nil, allocations) =
        crate::allocation_tests::measure(|| directory.claim_backup_namespace(Uuid::nil()));
    assert_eq!(nil.err().unwrap().kind(), io::ErrorKind::InvalidInput);
    assert_eq!(allocations, 0);
    // Claim validation rejects only nil, not other UUID versions/variants.
    for id in [
        Uuid::from_u128(1),
        Uuid::from_u128(u128::MAX),
        Uuid::new_v4(),
    ] {
        let held = directory.claim_backup_namespace(id).unwrap();
        let (busy, allocations) =
            crate::allocation_tests::measure(|| directory.claim_backup_namespace(id));
        assert_eq!(busy.err().unwrap().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(allocations, 0);
        drop(held);
    }
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
}

#[test]
fn backup_file_two_wrappers_serialize_absence_classification_through_publication() {
    let temporary = private_tempdir().unwrap();
    let disk = installed(temporary.path(), 8192, 1);
    let first = Arc::new(Directory::open(temporary.path(), disk.clone()).unwrap());
    let second = Directory::open(temporary.path(), disk.clone()).unwrap();
    let id = Uuid::new_v4();
    let name = format!("{id}.kasumi");
    let (entered, release) =
        test_sync::pause(temporary.path(), &name, test_sync::Point::BackupClassified).unwrap();
    let worker = std::thread::spawn(move || first.put_backup(id, &[73; 8192]));
    entered
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    assert_eq!(
        kind(&second.put_backup(id, &[91; 8192]).unwrap_err()),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    assert_eq!(
        std::fs::read(temporary.path().join(&name)).unwrap(),
        [73; 8192]
    );
    assert_eq!(
        kind(&second.put_backup(id, &[91; 8192]).unwrap_err()),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 1);
}

#[test]
fn backup_file_failed_creation_retains_complete_charge_until_explicit_census() {
    let temporary = private_tempdir().unwrap();
    let disk = installed(temporary.path(), 8192, 1);
    let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
    let id = Uuid::new_v4();
    let name = format!("{id}.kasumi");
    let pending = temporary.path().join(format!("{name}.pending"));
    let before = disk.snapshot();
    let fault =
        test_sync::fail(temporary.path(), &name, &[test_sync::Point::BackupCreated]).unwrap();
    assert!(directory.put_backup(id, &[73; 8192]).is_err());
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Failed);
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes + 8192);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes + 8192);
    assert_eq!(pending.metadata().unwrap().len(), 0);
    assert!(!temporary.path().join(&name).exists());
    assert!(directory.put_backup(id, &[91; 8192]).is_err());
    assert!(
        disk.reconcile(&crate::CensusCancellation::default())
            .is_err()
    );
    drop((fault, directory));
    disk.reconcile(&crate::CensusCancellation::default())
        .unwrap();
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    assert_eq!(disk.snapshot().persistent_files, 1);
    let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
    assert_eq!(
        kind(&directory.put_backup(id, &[91; 8192]).unwrap_err()),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(pending.metadata().unwrap().len(), 0);
    assert!(!temporary.path().join(&name).exists());
}
