use super::*;
use crate::private_files;
use crate::{NodeStore, ScratchDisk};
use kasumi_kv::{Database, TableDefinition};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{FileExt, OpenOptionsExt},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const ID: Uuid = Uuid::from_u128(0xac08_d6b1_a41e_47f1_9a86_8bd6_c541_d550);
const PROBE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("node_crash_probe");

fn directory() -> tempfile::TempDir {
    crate::test_utils::private_tempdir().unwrap()
}

fn raw_database(path: &Path) -> Database {
    let file = options().create_new(true).open(path).unwrap();
    Database::builder(crate::test_utils::storage_admission())
        .create_file(file)
        .unwrap()
}

fn commit_probe(transaction: kasumi_kv::WriteTransaction) {
    transaction
        .open_table(PROBE)
        .unwrap()
        .insert(b"key".as_slice(), b"durable value".as_slice())
        .unwrap();
    transaction.commit().unwrap();
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
}

fn create_node(
    path: &Path,
    id: Uuid,
    fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>,
) -> Arc<NodeFile> {
    NodeFile::create_new(
        path,
        id,
        crate::test_utils::retry_disk_registry(|| {
            NodeDisk::fixture_for_path(path, fixture_memory.clone())
        })
        .unwrap(),
    )
    .unwrap()
}

fn open_node(
    path: &Path,
    id: Uuid,
    fixture_memory: Arc<dyn crate::NodeDiskMemoryAdmission>,
) -> Result<Arc<NodeFile>> {
    NodeFile::open_existing(
        path,
        id,
        crate::test_utils::retry_disk_registry(|| {
            NodeDisk::fixture_for_path(path, fixture_memory.clone())
        })?,
    )
}

fn resize(backend: &NodeBackend, len: u64) -> io::Result<()> {
    let current = backend.len()?;
    if len > current {
        backend
            .0
            .reserve_growth(current, len)
            .map_err(|_| io::ErrorKind::StorageFull)?;
    }
    backend.set_len(len)
}

#[test]
fn unrelated_clean_and_unclean_old_format_rejection_is_byte_exact() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = directory();
    for dirty in [false, true] {
        let path = directory.path().join(if dirty { "dirty" } else { "clean" });
        if dirty {
            run_child(&path, "raw");
        } else {
            let db = raw_database(&path);
            commit_probe(db.begin_write().unwrap());
            drop(db);
        }
        // These deliberately small test files permit a byte-for-byte witness;
        // production admission reads only the fixed 4096-byte envelope.
        let before = std::fs::read(&path).unwrap();
        assert!(
            NodeStore::open_existing_fixture(
                &path,
                ID,
                fixture_memory.clone(),
                fixture_scratch.clone()
            )
            .is_err()
        );
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert!(
            NodeStore::create_new_fixture(
                &path,
                ID,
                fixture_memory.clone(),
                fixture_scratch.clone()
            )
            .is_err()
        );
        assert_eq!(before, std::fs::read(&path).unwrap());
    }
}

#[test]
fn recognized_store_recovers_after_actual_process_exit_without_close() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = directory();
    let path = directory.path().join("owned");
    run_child(&path, "owned");
    let before = std::fs::read(&path).unwrap();
    assert!(
        NodeStore::open_existing_fixture(
            &path,
            Uuid::from_u128(9),
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    assert_eq!(before, std::fs::read(&path).unwrap());
    let node = NodeStore::open_existing_fixture(
        &path,
        ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .unwrap();
    let transaction = node.db.begin_read().unwrap();
    let table = transaction.open_table(PROBE).unwrap();
    assert_eq!(
        table.get(b"key".as_slice()).unwrap().unwrap().value(),
        b"durable value"
    );
    drop(table);
    drop(transaction);
    assert!(
        NodeStore::open_existing_fixture(
            &path,
            ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    drop(node);
    let reopened = NodeStore::open_existing_fixture(
        &path,
        ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .unwrap();
    drop(reopened);
}

#[test]
fn partial_envelopes_are_never_adopted_or_reinitialized() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = directory();
    let path = directory.path().join("partial");
    let owner = create_node(&path, ID, fixture_memory.clone());
    let identity = private_files::file_identity(&path).unwrap();
    resize(&owner.backend(), 8192).unwrap();
    owner
        .backend()
        .write(0, b"partly initialized payload")
        .unwrap();
    owner.backend().sync_data().unwrap();
    owner.backend().close().into_result().unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(
        NodeStore::open_existing_fixture(
            &path,
            ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    assert!(
        NodeStore::initialize_owned_empty_fixture(
            &path,
            &identity,
            ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    assert!(
        NodeStore::create_new_fixture(&path, ID, fixture_memory.clone(), fixture_scratch.clone())
            .is_err()
    );
    assert_eq!(before, std::fs::read(&path).unwrap());

    for length in [0, 15, 31, 33, HEADER_BYTES - 1, HEADER_BYTES] {
        let path = directory.path().join(format!("truncated-{length}"));
        let file = options().create_new(true).open(&path).unwrap();
        file.write_all_at(&header(ID, READY)[..length], 0).unwrap();
        drop(file);
        let before = std::fs::read(&path).unwrap();
        assert!(
            NodeStore::open_existing_fixture(
                &path,
                ID,
                fixture_memory.clone(),
                fixture_scratch.clone()
            )
            .is_err()
        );
        assert_eq!(before, std::fs::read(&path).unwrap());
    }
}

#[test]
fn existing_header_requires_exact_canonical_fields_and_checksum() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = directory();
    for (index, replacement) in [(0, b'X'), (32, 3), (33, 1), (CHECKSUM_AT, 11)] {
        let path = directory.path().join(format!("bad-{index}"));
        drop(
            NodeStore::create_new_fixture(
                &path,
                ID,
                fixture_memory.clone(),
                fixture_scratch.clone(),
            )
            .unwrap(),
        );
        let file = options().open(&path).unwrap();
        let replacement = if index == CHECKSUM_AT {
            std::fs::read(&path).unwrap()[index] ^ 0xff
        } else {
            replacement
        };
        file.write_all_at(&[replacement], index as u64).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let before = std::fs::read(&path).unwrap();
        assert!(
            NodeStore::open_existing_fixture(
                &path,
                ID,
                fixture_memory.clone(),
                fixture_scratch.clone()
            )
            .is_err()
        );
        assert_eq!(before, std::fs::read(&path).unwrap());
    }
}

#[test]
fn previous_node_format_is_rejected_without_changing_its_bytes() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = directory();
    let path = directory.path().join("previous-format");
    drop(
        NodeStore::create_new_fixture(&path, ID, fixture_memory.clone(), fixture_scratch.clone())
            .unwrap(),
    );
    let mut old_header = header(ID, READY);
    old_header[..16].copy_from_slice(b"KASUMI-NODE-0001");
    let digest = Sha256::digest(&old_header[..CHECKSUM_AT]);
    old_header[CHECKSUM_AT..].copy_from_slice(&digest);
    let file = options().open(&path).unwrap();
    file.write_all_at(&old_header, 0).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let before = std::fs::read(&path).unwrap();
    assert!(NodeStore::open_existing_fixture(&path, ID, fixture_memory, fixture_scratch).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn initialization_requires_exact_journal_owned_empty_inode() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = directory();
    let path = directory.path().join("prepared");
    let other = directory.path().join("other");
    drop(options().create_new(true).open(&path).unwrap());
    drop(options().create_new(true).open(&other).unwrap());
    let identity = private_files::file_identity(&path).unwrap();
    let foreign = private_files::file_identity(&other).unwrap();
    assert!(
        NodeStore::initialize_owned_empty_fixture(
            &path,
            &foreign,
            ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    let node = NodeStore::initialize_owned_empty_fixture(
        &path,
        &identity,
        ID,
        fixture_memory.clone(),
        fixture_scratch.clone(),
    )
    .unwrap();
    assert_eq!(private_files::file_identity(&path).unwrap(), identity);
    drop(node);
    drop(
        NodeStore::open_existing_fixture(
            &path,
            ID,
            fixture_memory.clone(),
            fixture_scratch.clone(),
        )
        .unwrap(),
    );
    assert!(
        NodeStore::initialize_owned_empty_fixture(
            &path,
            &identity,
            ID,
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
}

#[test]
fn offset_io_preserves_header_and_retained_backend_cannot_outlive_close() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let path = directory.path().join("offset");
    let owner = create_node(&path, ID, fixture_memory.clone());
    let backend = owner.backend();
    let header_before = std::fs::read(&path).unwrap();
    resize(&backend, 8).unwrap();
    backend.write(0, b"12345678").unwrap();
    let mut read = [0; 8];
    backend.read(0, &mut read).unwrap();
    assert_eq!(read, *b"12345678");
    assert!(backend.write(8, b"outside allocated extent").is_err());
    assert!(backend.read(u64::MAX, &mut read).is_err());
    assert!(backend.write(u64::MAX, b"overflow").is_err());
    resize(&backend, 0).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), header_before);
    assert!(open_node(&path, ID, fixture_memory.clone()).is_err());
    // This impossible engine admission is an owner failure, not a recoverable
    // capacity denial. A later resize must not start I/O through that owner.
    assert_eq!(
        owner.reserve_growth(0, i64::MAX as u64),
        Err(AdmissionError::OwnerFailed)
    );
    assert_eq!(owner.disk.snapshot().phase, crate::NodeDiskPhase::Failed);
    assert!(resize(&backend, 0).is_err());
    assert!(backend.sync_data().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), header_before);
    assert!(backend.close().into_result().is_err());
    assert!(matches!(*owner.file.read(), FileState::Owned(_)));
    assert_eq!(owner.disk.snapshot().open_files, 1);
    assert!(backend.len().is_err());
    assert!(backend.read(0, &mut read).is_err());
    assert!(backend.write(0, b"closed").is_err());
    assert!(resize(&backend, 8).is_err());
    assert!(backend.sync_data().is_err());
    let file = options().open(&path).unwrap();
    file.try_lock().unwrap();
}

#[test]
fn canonical_header_rejects_nil_identity_without_creating_a_file() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = directory();
    let path = directory.path().join("nil");
    assert!(
        NodeStore::create_new_fixture(
            &path,
            Uuid::nil(),
            fixture_memory.clone(),
            fixture_scratch.clone()
        )
        .is_err()
    );
    assert!(!path.exists());
}

#[test]
fn validated_descriptor_handoff_never_reopens_a_substituted_path() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = directory();
    let path = directory.path().join("candidate");
    let moved = directory.path().join("original-inode");
    drop(
        NodeStore::create_new_fixture(&path, ID, fixture_memory.clone(), fixture_scratch.clone())
            .unwrap(),
    );
    let expected = private_files::file_identity(&path).unwrap();
    let owner = open_node(&path, ID, fixture_memory.clone()).unwrap();
    let disk = owner.disk.clone();
    assert_eq!(disk.snapshot().open_files, 1);
    std::fs::rename(&path, &moved).unwrap();
    drop(raw_database(&path));
    let unrelated = std::fs::read(&path).unwrap();
    let original = std::fs::read(&moved).unwrap();

    let mut opening = Database::builder(owner.clone()).retain_backend(
        Box::new(owner.backend()),
        kasumi_kv::DatabaseOpenMode::Existing,
    );
    let original_failure = match opening.open().opening() {
        kasumi_kv::TerminalObservation::Returned(Err(error)) => std::ptr::from_ref(error),
        _ => panic!("substituted descriptor opening must retain its original error"),
    };
    // Opening records the failure but cannot attest drain before explicit close.
    assert_eq!(
        opening.report().settlement(),
        kasumi_kv::DatabaseOpenSettlement::Retained
    );
    assert!(matches!(
        opening.report().partial_close(),
        kasumi_kv::TerminalObservation::NotEntered
    ));
    assert_eq!(
        opening.report().native_disposition(),
        kasumi_kv::BackendNativeDisposition::Retained
    );
    assert!(owner.failed_close_witness().is_err());
    assert_eq!(original, std::fs::read(&moved).unwrap());
    assert_eq!(unrelated, std::fs::read(&path).unwrap());
    assert_eq!(private_files::file_identity(&moved).unwrap(), expected);
    // Identity substitution fences this owner before any payload repair/write.
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Failed);
    assert!(owner.backend().write(0, b"must not write").is_err());
    assert!(NodeStore::open_existing(&moved, ID, disk.clone(), fixture_scratch.clone()).is_err());
    // A failed physical owner cannot produce positive close merely because
    // its known descriptors closed. Both original opening error and actual
    // file owner remain retained until this test explicitly drops them.
    assert_eq!(disk.snapshot().open_files, 1);
    let file_owner = owner.file.read().owned().unwrap().close_owner_address();
    assert_eq!(
        opening.close().settlement(),
        kasumi_kv::DatabaseOpenSettlement::DrainedWithFailure
    );
    {
        let report = opening.report();
        let kasumi_kv::TerminalObservation::Returned(Err(error)) = report.opening() else {
            panic!("failed close must preserve the original opening error");
        };
        assert_eq!(std::ptr::from_ref(error), original_failure);
        assert!(matches!(
            report.partial_close(),
            kasumi_kv::TerminalObservation::Returned(Err(_))
        ));
    }
    assert_eq!(
        owner.file.read().owned().unwrap().close_owner_address(),
        file_owner
    );
    assert_eq!(disk.snapshot().open_files, 1);
    assert!(owner.backend().len().is_err());
    assert!(owner.backend().write(0, b"still retained").is_err());
    assert!(
        disk.reconcile(&crate::CensusCancellation::default())
            .is_err()
    );
    assert_eq!(original, std::fs::read(&moved).unwrap());
    assert_eq!(unrelated, std::fs::read(&path).unwrap());
    drop(opening);
    drop(owner);
    // Explicitly observed/dropped outcomes transfer to installed custody. Only
    // an accepted census after actual facade drain may now release that custody.
    disk.reconcile(&crate::CensusCancellation::default())
        .unwrap();
    assert_eq!(disk.snapshot().open_files, 0);
    assert_eq!(disk.snapshot().phase, crate::NodeDiskPhase::Open);
    let reopened = NodeStore::open_existing(&moved, ID, disk, fixture_scratch.clone()).unwrap();
    let tx = reopened.db.begin_read().unwrap();
    assert!(tx.open_table(PROBE).is_err());
    assert_eq!(unrelated, std::fs::read(&path).unwrap());
}

#[test]
fn cleanup_custody_accepts_only_exact_recognized_headers_and_holds_the_inode_lock() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = crate::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        crate::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let directory = directory();
    for ready in [false, true] {
        let path = directory.path().join(if ready {
            "ready-cleanup"
        } else {
            "prepared-cleanup"
        });
        if ready {
            drop(
                NodeStore::create_new_fixture(
                    &path,
                    ID,
                    fixture_memory.clone(),
                    fixture_scratch.clone(),
                )
                .unwrap(),
            );
        } else {
            drop(create_node(&path, ID, fixture_memory.clone()));
        }
        let before = std::fs::read(&path).unwrap();
        assert!(
            NodeStore::claim_cleanup_fixture(&path, Uuid::from_u128(10), fixture_memory.clone())
                .is_err()
        );
        assert_eq!(before, std::fs::read(&path).unwrap());
        let identity = private_files::file_identity(&path).unwrap();
        let cleanup = NodeStore::claim_cleanup_fixture(&path, ID, fixture_memory.clone()).unwrap();
        assert_eq!(cleanup.identity(), &identity);
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert!(NodeStore::claim_cleanup_fixture(&path, ID, fixture_memory.clone()).is_err());
        assert!(options().open(&path).unwrap().try_lock().is_err());
        let alias = directory.path().join(if ready {
            "ready-moved"
        } else {
            "prepared-moved"
        });
        std::fs::rename(&path, &alias).unwrap();
        assert!(options().open(&alias).unwrap().try_lock().is_err());
        assert_eq!(private_files::file_identity(&alias).unwrap(), identity);
        std::fs::remove_file(&alias).unwrap();
        File::open(directory.path()).unwrap().sync_all().unwrap();
        assert_eq!(cleanup.identity(), &identity);
        drop(cleanup);
    }
    let torn = header(ID, PREPARED);
    for (name, bytes) in [("empty", &b""[..]), ("torn", &torn[..40])] {
        let path = directory.path().join(name);
        let file = options().create_new(true).open(&path).unwrap();
        file.write_all_at(bytes, 0).unwrap();
        drop(file);
        let before = std::fs::read(&path).unwrap();
        assert!(NodeStore::claim_cleanup_fixture(&path, ID, fixture_memory.clone()).is_err());
        assert_eq!(before, std::fs::read(&path).unwrap());
    }
    let path = directory.path().join("unrelated-cleanup");
    drop(raw_database(&path));
    let before = std::fs::read(&path).unwrap();
    assert!(NodeStore::claim_cleanup_fixture(&path, ID, fixture_memory.clone()).is_err());
    assert_eq!(before, std::fs::read(&path).unwrap());
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run_child(path: &Path, mode: &str) {
    let log_path = path.with_extension("node-child.log");
    let log = options().create_new(true).open(&log_path).unwrap();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "node_file::tests::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("KASUMI_NODE_FILE_CHILD_PATH", path)
            .env("KASUMI_NODE_FILE_CHILD_MODE", mode)
            // Child libtest lines must not interleave with the parent's test
            // result protocol. A regular file cannot deadlock on pipe capacity.
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let outcome = loop {
        match child.0.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                break Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "node crash child deadline elapsed",
                ));
            }
            Err(error) => break Err(error),
        }
    };
    if outcome
        .as_ref()
        .is_ok_and(|status| status.code() == Some(77))
    {
        return;
    }
    // Drain before reading diagnostics. Drop still owns a second cleanup attempt
    // if either syscall fails or reading the bounded log itself panics.
    let kill = child.0.kill();
    let drain = child.0.wait();
    let mut diagnostic = Vec::new();
    let read =
        File::open(&log_path).and_then(|file| file.take(16 << 10).read_to_end(&mut diagnostic));
    panic!(
        "node crash child failed: {outcome:?}; kill={kill:?}; drain={drain:?}; log={log_path:?}; read={read:?}; first16KiB={}",
        String::from_utf8_lossy(&diagnostic)
    );
}

#[test]
#[ignore = "subprocess helper; invoked with an owned temporary path"]
fn crash_child() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let path = PathBuf::from(std::env::var_os("KASUMI_NODE_FILE_CHILD_PATH").unwrap());
    match std::env::var("KASUMI_NODE_FILE_CHILD_MODE")
        .unwrap()
        .as_str()
    {
        "raw" => {
            let db = raw_database(&path);
            commit_probe(db.begin_write().unwrap());
            std::process::exit(77);
        }
        "owned" => {
            // The parent owns this whole temporary directory, including files
            // whose Rust destructors the deliberate process exit will skip.
            let scratch = ScratchDisk::open_fixture(
                &crate::ScratchDiskConfig {
                    directory: path.parent().unwrap().join("crash-child-scratch"),
                    max_bytes: 8 << 20,
                    min_free_bytes: 0,
                },
                fixture_memory.clone(),
            )
            .unwrap();
            let node =
                NodeStore::create_new_fixture(&path, ID, fixture_memory.clone(), scratch).unwrap();
            commit_probe(node.db.begin_write().unwrap());
            std::process::exit(77);
        }
        _ => panic!("unexpected node crash child mode"),
    }
}

#[test]
fn reads_enforce_payload_bounds_even_for_empty_buffers() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let path = directory.path().join("read-bounds");
    let owner = create_node(&path, ID, fixture_memory.clone());
    let backend = owner.backend();
    resize(&backend, 8).unwrap();
    assert!(backend.read(8, &mut []).is_ok());
    assert_eq!(
        backend.read(9, &mut []).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        backend.read(8, &mut [0]).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(
        backend.read(7, &mut [0, 0]).unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    resize(&backend, 0).unwrap();
    assert!(backend.read(0, &mut []).is_ok());
    assert!(backend.read(1, &mut []).is_err());
    backend.close().into_result().unwrap();
}

#[test]
fn resize_drains_a_write_after_its_extent_check_before_truncating() {
    let fixture_memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    use std::sync::mpsc::{self, RecvTimeoutError};
    let directory = directory();
    let path = directory.path().join("resize-drain");
    let owner = create_node(&path, ID, fixture_memory.clone());
    let backend = owner.backend();
    resize(&backend, 8).unwrap();
    let expected_header = header(ID, PREPARED);
    let (entered, paused) = mpsc::channel();
    let (resume, released) = mpsc::channel();
    *owner.after_write_check.lock() = Some(Box::new(move || {
        entered.send(()).unwrap();
        released.recv_timeout(Duration::from_secs(5)).unwrap();
    }));
    let (attempted, attempting) = mpsc::channel();
    let (finished, completed) = mpsc::channel();
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| backend.write(0, b"12345678"));
        paused.recv_timeout(Duration::from_secs(5)).unwrap();
        // The actual write is paused after its accepted range check with its
        // descriptor owner held. A resize must wait for that operation to drain.
        let resizer = scope.spawn(|| {
            attempted.send(()).unwrap();
            finished.send(resize(&backend, 0)).unwrap();
        });
        attempting.recv_timeout(Duration::from_secs(5)).unwrap();
        let before_release = completed.recv_timeout(Duration::from_millis(250));
        let waited_for_write = matches!(&before_release, Err(RecvTimeoutError::Timeout));
        // Always release before asserting, so a failing ownership regression
        // still drains both bounded scoped threads and their file descriptors.
        resume.send(()).unwrap();
        let write = writer.join().unwrap();
        let resize = match before_release {
            Err(RecvTimeoutError::Timeout) => {
                completed.recv_timeout(Duration::from_secs(5)).unwrap()
            }
            Ok(result) => result,
            Err(error) => panic!("resize worker disconnected: {error}"),
        };
        resizer.join().unwrap();
        write.unwrap();
        resize.unwrap();
        assert!(
            waited_for_write,
            "resize completed before the admitted write drained"
        );
    });
    assert_eq!(backend.len().unwrap(), 0);
    assert_eq!(std::fs::read(&path).unwrap(), expected_header);
    backend.close().into_result().unwrap();
}

#[test]
fn retained_database_retries_node_close_only_after_proved_pre_entry_contention() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let path = directory.path().join("retained-close-contention");
    let owner = create_node(&path, ID, memory);
    let mut opening = Database::builder(owner.clone()).retain_backend(
        Box::new(owner.backend()),
        kasumi_kv::DatabaseOpenMode::Create,
    );
    assert_eq!(
        opening.open().settlement(),
        kasumi_kv::DatabaseOpenSettlement::Ready
    );
    owner.publish_ready().unwrap();
    let attempts = NodeFile::native_close_attempts();
    let held = owner.file.read();
    assert_eq!(
        opening.close().settlement(),
        kasumi_kv::DatabaseOpenSettlement::WaitingForTransactions
    );
    let report = opening.report();
    let close = report.database_close().unwrap();
    assert!(matches!(
        close.backend(),
        kasumi_kv::TerminalObservation::NotEntered
    ));
    assert_eq!(
        close.native_disposition(),
        kasumi_kv::BackendNativeDisposition::Retained
    );
    assert_eq!(NodeFile::native_close_attempts(), attempts);
    assert_eq!(owner.disk.snapshot().open_files, 1);
    drop(held);
    assert_eq!(
        opening.close().settlement(),
        kasumi_kv::DatabaseOpenSettlement::Closed
    );
    // A clean NodeDiskFile closes its data descriptor and retained parent.
    assert_eq!(NodeFile::native_close_attempts(), attempts + 2);
    assert_eq!(owner.disk.snapshot().open_files, 0);
    assert!(matches!(*owner.file.read(), FileState::Closed));
    assert_eq!(
        opening.close().settlement(),
        kasumi_kv::DatabaseOpenSettlement::Closed
    );
    assert_eq!(NodeFile::native_close_attempts(), attempts + 2);
}

#[test]
fn retained_partial_opening_retries_node_close_after_pre_entry_contention() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let path = directory.path().join("partial-close-contention");
    let owner = create_node(&path, ID, memory);
    let mut opening = Database::builder(owner.clone()).retain_backend(
        Box::new(owner.backend()),
        kasumi_kv::DatabaseOpenMode::Existing,
    );
    assert!(matches!(
        opening.open().opening(),
        kasumi_kv::TerminalObservation::Returned(Err(_))
    ));
    let attempts = NodeFile::native_close_attempts();
    let held = owner.file.read();
    assert_eq!(
        opening.close().settlement(),
        kasumi_kv::DatabaseOpenSettlement::WaitingForTransactions
    );
    assert_eq!(NodeFile::native_close_attempts(), attempts);
    assert!(matches!(
        opening.report().partial_close(),
        kasumi_kv::TerminalObservation::NotEntered
    ));
    assert_eq!(owner.disk.snapshot().open_files, 1);
    drop(held);
    assert_eq!(
        opening.close().settlement(),
        kasumi_kv::DatabaseOpenSettlement::Closed
    );
    assert_eq!(NodeFile::native_close_attempts(), attempts + 2);
    assert_eq!(owner.disk.snapshot().open_files, 0);
    assert!(matches!(*owner.file.read(), FileState::Closed));
}

#[test]
fn retained_database_retries_node_close_after_lower_arc_pre_entry_contention() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let path = directory.path().join("retained-arc-contention");
    let owner = create_node(&path, ID, memory);
    let mut opening = Database::builder(owner.clone()).retain_backend(
        Box::new(owner.backend()),
        kasumi_kv::DatabaseOpenMode::Create,
    );
    assert_eq!(
        opening.open().settlement(),
        kasumi_kv::DatabaseOpenSettlement::Ready
    );
    owner.publish_ready().unwrap();
    let attempts = NodeFile::native_close_attempts();
    let held = owner.file.read().owned().unwrap().clone();
    let address = held.close_owner_address();
    assert_eq!(
        opening.close().settlement(),
        kasumi_kv::DatabaseOpenSettlement::WaitingForTransactions
    );
    assert!(matches!(
        opening.report().database_close().unwrap().backend(),
        kasumi_kv::TerminalObservation::NotEntered
    ));
    assert_eq!(NodeFile::native_close_attempts(), attempts);
    assert_eq!(held.close_owner_address(), address);
    assert_eq!(owner.disk.snapshot().open_files, 1);
    drop(held);
    assert_eq!(
        opening.close().settlement(),
        kasumi_kv::DatabaseOpenSettlement::Closed
    );
    assert_eq!(NodeFile::native_close_attempts(), attempts + 2);
    assert_eq!(owner.disk.snapshot().open_files, 0);
}

#[test]
fn backend_close_preserves_busy_owner_then_retires_before_positive_idempotent_close() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let path = directory.path().join("explicit-close");
    let owner = create_node(&path, ID, memory);
    let backend = owner.backend();
    let before = std::fs::read(&path).unwrap();
    let held = owner.file.read().owned().unwrap().clone();
    let address = held.close_owner_address();
    assert_eq!(
        backend.close().into_result().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        owner.file.read().owned().unwrap().close_owner_address(),
        address
    );
    assert_eq!(owner.disk.snapshot().open_files, 1);
    assert_eq!(backend.len().unwrap(), 0);
    drop(held);
    backend.close().into_result().unwrap();
    assert!(matches!(*owner.file.read(), FileState::Closed));
    assert_eq!(owner.disk.snapshot().open_files, 0);
    backend.close().into_result().unwrap();
    assert!(backend.len().is_err());
    assert!(backend.read(0, &mut []).is_err());
    assert!(backend.write(0, &[]).is_err());
    assert!(backend.sync_data().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let observer = options().open(&path).unwrap();
    observer.try_lock().unwrap();
}

#[test]
fn backend_close_reports_native_error_and_keeps_exact_file_and_original_outcome() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let path = directory.path().join("failed-explicit-close");
    let owner = create_node(&path, ID, memory);
    let backend = owner.backend();
    let address = owner.file.read().owned().unwrap().close_owner_address();
    let before = owner.disk.snapshot();
    let bytes = std::fs::read(&path).unwrap();
    NodeDiskFile::fail_next_native_close(libc::EIO);
    assert_eq!(
        backend.close().into_result().unwrap_err().raw_os_error(),
        Some(libc::EIO)
    );
    let original = owner
        .file
        .read()
        .owned()
        .unwrap()
        .close_error_address()
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            backend.close().into_result().unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        let file = owner.file.read();
        let file = file.owned().unwrap();
        assert_eq!(file.close_owner_address(), address);
        assert_eq!(file.close_error_address(), Some(original));
        assert_eq!(owner.disk.snapshot().open_files, 1);
        assert_eq!(owner.disk.snapshot().charged_bytes, before.charged_bytes);
        assert_eq!(owner.disk.snapshot().pending_bytes, before.pending_bytes);
        assert_eq!(owner.disk.snapshot().phase, crate::NodeDiskPhase::Failed);
        assert!(
            owner
                .disk
                .reconcile(&crate::CensusCancellation::default())
                .is_err()
        );
    }
    assert!(backend.len().is_err());
    assert!(backend.read(0, &mut []).is_err());
    assert!(backend.write(0, &[]).is_err());
    assert!(backend.sync_data().is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn acknowledged_known_drained_file_waits_for_accepted_census_without_reopening() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let path = directory.path().join("acknowledged-failure");
    let owner = create_node(&path, ID, memory);
    let backend = owner.backend();
    let identity = private_files::file_identity(&path).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    owner.disk.fail();
    let closed = backend.close();
    assert_eq!(
        closed.native_disposition(),
        kasumi_kv::BackendNativeDisposition::Drained
    );
    assert!(closed.into_result().is_err());
    let original = owner.retained_file_custody().unwrap().1.unwrap();
    let before = owner.disk.snapshot();
    let witness = owner.failed_close_witness().unwrap();
    let mut originals = 0;
    owner
        .with_failed_close_report(&witness, |report| {
            // A diagnostic borrower must never retain the NodeDisk State gate.
            assert_eq!(owner.disk.snapshot().open_files, 1);
            report.visit_errors(|error| {
                assert_eq!(std::ptr::from_ref(error) as usize, original);
                originals += 1;
            });
        })
        .unwrap();
    assert_eq!(originals, 1);
    let stale = owner.failed_close_witness().unwrap();
    let attempts = NodeFile::native_close_attempts();
    let (transferred, allocations) =
        crate::allocation_tests::measure(|| owner.transfer_failed(&witness));
    let transferred = transferred.unwrap().unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(NodeFile::native_close_attempts(), attempts);
    assert!(matches!(*owner.file.read(), FileState::FailedTransferred));
    assert!(owner.transfer_failed(&stale).is_err());
    assert!(
        owner
            .acquire_prepared(&crate::storage_opening::NodeOpeningMode::Create)
            .is_err()
    );
    assert!(backend.len().is_err());
    assert!(backend.write(0, b"forbidden").is_err());
    assert_eq!(owner.disk.snapshot().open_files, before.open_files);
    assert_eq!(owner.disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(owner.disk.snapshot().pending_bytes, before.pending_bytes);
    assert_eq!(owner.disk.snapshot().retained_file_attempts, 1);
    assert!(!owner.disk.accepted_failure_transfer(&transferred));
    let cancel = crate::CensusCancellation::default();
    cancel.cancel();
    assert!(owner.disk.reconcile(&cancel).is_err());
    assert!(!owner.disk.accepted_failure_transfer(&transferred));
    assert_eq!(owner.disk.snapshot().open_files, 1);
    assert_eq!(owner.disk.snapshot().retained_file_attempts, 1);
    assert_eq!(owner.disk.snapshot().charged_bytes, before.charged_bytes);
    owner
        .disk
        .reconcile(&crate::CensusCancellation::default())
        .unwrap();
    assert!(owner.disk.accepted_failure_transfer(&transferred));
    assert_eq!(owner.disk.snapshot().open_files, 0);
    assert_eq!(owner.disk.snapshot().retained_file_attempts, 0);
    assert_eq!(private_files::file_identity(&path).unwrap(), identity);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(
        owner
            .acquire_prepared(&crate::storage_opening::NodeOpeningMode::Existing)
            .is_err()
    );
    let (root, relative) = owner.disk.binding(&path).unwrap();
    owner
        .disk
        .open_file(root, relative)
        .unwrap()
        .close()
        .unwrap();
}

#[test]
fn failed_file_report_blocks_transfer_and_foreign_witnesses_do_not_move_custody() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let first = create_node(&directory.path().join("first"), ID, memory.clone());
    let second = create_node(&directory.path().join("second"), ID, memory);
    assert!(Arc::ptr_eq(&first.disk, &second.disk));
    first.disk.fail();
    assert!(first.backend().close().into_result().is_err());
    assert!(second.backend().close().into_result().is_err());
    let original = first.retained_file_custody().unwrap();
    assert!(
        first
            .transfer_failed(&second.failed_close_witness().unwrap())
            .is_err()
    );
    assert_eq!(first.retained_file_custody().unwrap(), original);
    let report = first.failed_close_witness().unwrap();
    let racing = first.failed_close_witness().unwrap();
    first
        .with_failed_close_report(&report, |borrowed| {
            let mut count = 0;
            borrowed.visit_errors(|_| count += 1);
            assert_eq!(count, 1);
            assert!(first.transfer_failed(&racing).unwrap().is_none());
        })
        .unwrap();
    let one = first.transfer_failed(&racing).unwrap().unwrap();
    assert!(
        first
            .disk
            .reconcile(&crate::CensusCancellation::default())
            .is_err()
    );
    assert!(!first.disk.accepted_failure_transfer(&one));
    let two = second
        .transfer_failed(&second.failed_close_witness().unwrap())
        .unwrap()
        .unwrap();
    first
        .disk
        .reconcile(&crate::CensusCancellation::default())
        .unwrap();
    assert!(first.disk.accepted_failure_transfer(&one));
    assert!(first.disk.accepted_failure_transfer(&two));
}

#[test]
fn unknown_native_close_cannot_mint_recovery_witness_or_retry_a_reused_descriptor() {
    use std::os::fd::AsRawFd;
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let path = directory.path().join("unknown-close");
    let owner = create_node(&path, ID, memory);
    let backend = owner.backend();
    let descriptor = owner.file.read().owned().unwrap().data_descriptor();
    NodeFile::fail_next_native_close(libc::EIO);
    let closed = backend.close();
    assert_eq!(
        closed.native_disposition(),
        kasumi_kv::BackendNativeDisposition::Retained
    );
    assert_eq!(
        closed.into_result().unwrap_err().raw_os_error(),
        Some(libc::EIO)
    );
    let original = owner.retained_file_custody().unwrap();
    let attempts = NodeFile::native_close_attempts();
    let sentinel = options()
        .create_new(true)
        .open(directory.path().join("sentinel"))
        .unwrap();
    assert_eq!(
        sentinel.as_raw_fd(),
        descriptor,
        "fixture reuses the diagnostic descriptor integer"
    );
    sentinel.write_all_at(b"still owned", 0).unwrap();
    for _ in 0..2 {
        assert!(owner.failed_close_witness().is_err());
        let repeated = backend.close();
        assert_eq!(
            repeated.native_disposition(),
            kasumi_kv::BackendNativeDisposition::Retained
        );
        assert_eq!(
            repeated.into_result().unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        assert_eq!(NodeFile::native_close_attempts(), attempts);
        assert_eq!(owner.retained_file_custody().unwrap(), original);
        let mut bytes = [0; 11];
        sentinel.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"still owned");
    }
}

#[test]
fn closed_prepared_node_file_cannot_acquire_a_new_descriptor() {
    let memory = crate::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let directory = directory();
    let path = directory.path().join("never-acquired");
    let disk = NodeDisk::fixture_for_path(&path, memory).unwrap();
    let owner = NodeFile::retained_prepared(&path, ID, disk);
    let closed = owner.backend().close();
    assert_eq!(
        closed.native_disposition(),
        kasumi_kv::BackendNativeDisposition::Drained
    );
    closed.into_result().unwrap();
    assert!(matches!(*owner.file.read(), FileState::Closed));
    assert!(
        owner
            .acquire_prepared(&crate::storage_opening::NodeOpeningMode::Create)
            .is_err()
    );
    assert!(!path.exists());
    assert_eq!(owner.disk.snapshot().open_files, 0);
}
