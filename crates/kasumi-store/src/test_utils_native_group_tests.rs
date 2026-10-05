use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir};

fn fixture_group(path: &Path) {
    std::fs::create_dir(path).unwrap();
    for (name, content) in [
        (kasumi_kv::ROOT_FILE_NAME, b"root".as_slice()),
        ("0000000000000001.kvseg", b"segment".as_slice()),
        ("0000000000000002.kvckpt", b"checkpoint".as_slice()),
        ("0000000000000003.kvdir", b"directory".as_slice()),
    ] {
        std::fs::write(path.join(name), content).unwrap();
    }
}

#[test]
fn complete_native_group_copy_and_restore_preserve_installed_identity() {
    let directory = private_tempdir().unwrap();
    let installed = directory.path().join("installed.kv");
    let saved = directory.path().join("saved.kv");
    fixture_group(&installed);
    let memory = TestDiskMemory::new(1 << 20, 64);
    let original = capture_native_group_image(&installed, memory.clone()).unwrap();
    copy_closed_native_group(&installed, &saved, memory.clone()).unwrap();
    assert_eq!(
        capture_native_group_image(&saved, memory.clone()).unwrap(),
        original
    );
    std::fs::write(installed.join(kasumi_kv::ROOT_FILE_NAME), b"later root").unwrap();
    std::fs::write(installed.join("0000000000000001.kvseg"), b"later segment").unwrap();
    std::fs::remove_file(installed.join("0000000000000002.kvckpt")).unwrap();
    std::fs::write(installed.join("0000000000000004.kvdir"), b"later directory").unwrap();
    assert_ne!(
        capture_native_group_image(&installed, memory.clone()).unwrap(),
        original
    );
    restore_closed_native_group(&saved, &installed, memory.clone()).unwrap();
    let restored = capture_native_group_image(&installed, memory.clone()).unwrap();
    assert_eq!(restored, original);
    assert_eq!(restored.directory_identity, original.directory_identity);
    assert_eq!(restored.root_identity, original.root_identity);
    assert!(!installed.join("0000000000000004.kvdir").exists());
    drop((restored, original));
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.snapshot().live_reservations, 0);
}

#[test]
fn complete_native_inventory_rejects_unexpected_entries_and_symlinks() {
    let directory = private_tempdir().unwrap();
    let installed = directory.path().join("installed.kv");
    fixture_group(&installed);
    let memory = TestDiskMemory::new(1 << 20, 64);
    std::fs::write(installed.join("000000000000000A.kvseg"), b"wrong spelling").unwrap();
    assert!(capture_native_group_image(&installed, memory.clone()).is_err());
    std::fs::remove_file(installed.join("000000000000000A.kvseg")).unwrap();
    std::fs::remove_file(installed.join("0000000000000001.kvseg")).unwrap();
    std::os::unix::fs::symlink(
        directory.path().join("outside"),
        installed.join("0000000000000001.kvseg"),
    )
    .unwrap();
    assert!(capture_native_group_image(&installed, memory.clone()).is_err());
    assert_eq!(memory.snapshot().used_bytes, 0);
}

#[test]
fn complete_native_inventory_refuses_before_allocating_without_admission() {
    let directory = private_tempdir().unwrap();
    let installed = directory.path().join("installed.kv");
    fixture_group(&installed);
    // The fixed provider/census backing is admitted; no payload headroom is
    // available for the first directory workspace or a member inventory.
    let memory = TestDiskMemory::new(TestDiskMemory::required_bookkeeping_bytes(64).unwrap(), 64);
    let (result, observed) = crate::test_utils::source_quote_observer::measure(&memory, || {
        capture_native_group_image(&installed, memory.clone())
    });
    assert!(result.is_err());
    assert!(!observed.overflow);
    assert_eq!(observed.count, 0, "no workspace or inventory was admitted");
    assert_eq!(observed.refused_count, 1);
    assert_eq!(
        observed.last_refused_bytes,
        TestDiskMemory::required_reservation_bytes(disk_memory::allocation::<u8>(255).unwrap())
            .unwrap()
    );
    assert_eq!(
        memory.snapshot().attempts,
        1,
        "refusal must stop inventory construction"
    );
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.snapshot().live_reservations, 0);
}
