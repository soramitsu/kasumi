use super::*;
use crate::test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry};

fn open(path: &Path, files: u64) -> Arc<crate::NodeDisk> {
    let mut config = crate::NodeDisk::fixture_config(path.join("unused")).unwrap();
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

#[test]
fn new_session_denies_before_mkdir_when_both_terminal_inodes_cannot_fit() {
    let temporary = private_tempdir().unwrap();
    let disk = open(temporary.path(), 1);
    let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
    let before = disk.snapshot();
    assert!(
        directory
            .put(Uuid::new_v4(), BackupSessionSlot::Intent, b"intent")
            .is_err()
    );
    assert!(!temporary.path().join("sessions").exists());
    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
}

#[test]
fn terminal_publication_keeps_original_inode_full_extent_and_exact_ciphertext() {
    use std::os::unix::fs::MetadataExt;
    let temporary = private_tempdir().unwrap();
    let disk = open(temporary.path(), 2);
    let directory = Directory::open(temporary.path(), disk.clone()).unwrap();
    let session = Uuid::new_v4();
    directory
        .put(
            session,
            BackupSessionSlot::Intent,
            b"original encrypted intent",
        )
        .unwrap();
    let path = temporary.path().join("sessions").join(session.to_string());
    assert!(!path.join("intent.reserve").exists());
    assert_eq!(
        path.join("intent.kasumi").metadata().unwrap().len(),
        terminal::FILE_BYTES as u64
    );
    let session_directory = directory.session(session).unwrap().unwrap();
    let intent = session_directory.open_leaf("intent.kasumi").unwrap().unwrap();
    let (valid, allocations) = crate::allocation_tests::measure(|| terminal::validate(&intent, session, Terminal::Intent));
    valid.unwrap();
    assert_eq!(allocations, 0, "classification streams the admitted fixed buffer");
    let (small, allocations) = crate::allocation_tests::measure(|| terminal::read(&intent, session, Terminal::Intent, 0));
    assert_eq!(small.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(allocations, 0, "caller limit rejects before payload allocation");
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    drop((intent, session_directory));
    let reserve = path.join("outcome.reserve").metadata().unwrap();
    assert_eq!(reserve.len(), terminal::FILE_BYTES as u64);
    assert_eq!(disk.snapshot().persistent_files, 2);
    assert_eq!(
        directory
            .get(session, BackupSessionSlot::Intent, 64)
            .unwrap()
            .unwrap(),
        b"original encrypted intent"
    );
    let charged = disk.snapshot().charged_bytes;
    directory
        .put(
            session,
            BackupSessionSlot::Outcome,
            b"original encrypted outcome",
        )
        .unwrap();
    assert!(!path.join("outcome.reserve").exists());
    let published = path.join("outcome.kasumi").metadata().unwrap();
    assert_eq!(
        (published.dev(), published.ino()),
        (reserve.dev(), reserve.ino())
    );
    assert_eq!(published.len(), terminal::FILE_BYTES as u64);
    assert_eq!(disk.snapshot().charged_bytes, charged);
    assert_eq!(disk.snapshot().persistent_files, 2);
    assert_eq!(
        directory
            .get(session, BackupSessionSlot::Outcome, 64)
            .unwrap()
            .unwrap(),
        b"original encrypted outcome"
    );
}

#[test]
fn two_wrappers_cannot_recreate_reserve_across_terminal_classification_and_rename() {
    let temporary = private_tempdir().unwrap();
    let disk = open(temporary.path(), 4);
    let first = Arc::new(Directory::open(temporary.path(), disk.clone()).unwrap());
    let second = Directory::open(temporary.path(), disk.clone()).unwrap();
    let session = Uuid::new_v4();
    first
        .put(session, BackupSessionSlot::Intent, b"intent")
        .unwrap();
    let path = temporary.path().join("sessions").join(session.to_string());
    let (entered, release) = test_sync::pause(
        &path,
        "outcome.kasumi",
        test_sync::Point::TerminalClassified,
    )
    .unwrap();
    let worker =
        std::thread::spawn(move || first.put(session, BackupSessionSlot::Outcome, b"winner"));
    entered
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    // The first wrapper has observed published absence but has not opened the
    // reserve. The competing wrapper must stop before doing either observation.
    let competing = second
        .put(session, BackupSessionSlot::Outcome, b"loser")
        .unwrap_err();
    assert_eq!(
        competing.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    assert!(path.join("outcome.reserve").exists());
    assert!(!path.join("outcome.kasumi").exists());
    release.send(()).unwrap();
    worker.join().unwrap().unwrap();
    assert!(!path.join("outcome.reserve").exists());
    assert_eq!(
        second
            .get(session, BackupSessionSlot::Outcome, 32)
            .unwrap()
            .unwrap(),
        b"winner"
    );
    assert_eq!(disk.snapshot().persistent_files, 2);
    assert!(
        second
            .put(session, BackupSessionSlot::Outcome, b"late")
            .is_err()
    );
    assert!(!path.join("outcome.reserve").exists());
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
}

#[test]
fn permanent_terminal_capacity_survives_real_process_restart_at_full_file_and_byte_limits() {
    let temporary = private_tempdir().unwrap();
    let session = Uuid::new_v4();
    for stage in ["prepare", "finish"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backup_sessions::filesystem::session_admission_tests::terminal_restart_worker",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("KASUMI_TERMINAL_RESTART_STAGE", stage)
            .env("KASUMI_TERMINAL_RESTART_ROOT", temporary.path())
            .env("KASUMI_TERMINAL_RESTART_SESSION", session.to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{stage}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn terminal_restart_worker() {
    let Ok(stage) = std::env::var("KASUMI_TERMINAL_RESTART_STAGE") else {
        return;
    };
    let path = PathBuf::from(std::env::var_os("KASUMI_TERMINAL_RESTART_ROOT").unwrap());
    let session =
        Uuid::parse_str(&std::env::var("KASUMI_TERMINAL_RESTART_SESSION").unwrap()).unwrap();
    let mut config = crate::NodeDisk::fixture_config(path.join("unused")).unwrap();
    config.max_persistent_files = 3;
    config.max_persistent_subdirectories = 3;
    config.max_bytes = 16 << 20;
    config.maintenance_reserve_bytes = 0;
    let memory = TestDiskMemory::new(256 << 20, 4096);
    let disk = retry_disk_registry(|| {
        crate::NodeDisk::open_fixture(
            &config,
            memory.clone(),
            &crate::CensusCancellation::default(),
        )
    })
    .unwrap();
    let directory = Directory::open(&path, disk.clone()).unwrap();
    if stage == "prepare" {
        directory
            .put(session, BackupSessionSlot::Intent, b"intent before restart")
            .unwrap();
        let file = disk
            .create_file(
                "fixture",
                Path::new("unrelated.kasumi"),
                crate::DiskWork::Foreground,
            )
            .unwrap();
        let remaining = config.max_bytes - disk.snapshot().charged_bytes;
        file.reserve_growth(0, remaining, crate::DiskWork::Foreground)
            .unwrap();
        file.grow_reserved(remaining).unwrap();
        file.sync_all_and_parent().unwrap();
        drop(file);
        assert_eq!(
            disk.snapshot().persistent_files,
            config.max_persistent_files
        );
        assert_eq!(disk.snapshot().charged_bytes, config.max_bytes);
    } else {
        assert_eq!(stage, "finish");
        // This is a fresh process and a fresh cold census, with no RAM permit or
        // prior registry owner. Both promises come only from actual fixed files.
        assert_eq!(
            disk.snapshot().persistent_files,
            config.max_persistent_files
        );
        assert_eq!(disk.snapshot().charged_bytes, config.max_bytes);
        directory
            .put(
                session,
                BackupSessionSlot::Outcome,
                b"outcome after restart",
            )
            .unwrap();
        assert_eq!(
            directory
                .get(session, BackupSessionSlot::Outcome, 64)
                .unwrap()
                .unwrap(),
            b"outcome after restart"
        );
        assert_eq!(
            disk.snapshot().persistent_files,
            config.max_persistent_files
        );
        assert_eq!(disk.snapshot().charged_bytes, config.max_bytes);
    }
}
