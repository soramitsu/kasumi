use super::*;
use crate::{NodeStore, ScratchDisk};
use redb::{Database, Durability, ReadableDatabase, TableDefinition};
use std::{
    io::Read,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const ID: Uuid = Uuid::from_u128(0xac08_d6b1_a41e_47f1_9a86_8bd6c541d550);
const PROBE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("node_crash_probe");

fn directory() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn raw_database(path: &Path) -> Database {
    let file = options().create_new(true).open(path).unwrap();
    Database::builder().create_file(file).unwrap()
}

fn commit_probe(db: &Database) {
    let mut transaction = db.begin_write().unwrap();
    transaction.set_durability(Durability::Immediate).unwrap();
    transaction.set_two_phase_commit(true);
    transaction
        .open_table(PROBE)
        .unwrap()
        .insert(b"key".as_slice(), b"durable value".as_slice())
        .unwrap();
    transaction.commit().unwrap();
}

#[test]
fn unrelated_clean_and_unclean_redb_rejection_is_byte_exact() {
    let directory = directory();
    for dirty in [false, true] {
        let path = directory.path().join(if dirty { "dirty" } else { "clean" });
        if dirty {
            run_child(&path, "raw");
        } else {
            let db = raw_database(&path);
            commit_probe(&db);
            drop(db);
        }
        // These deliberately small test files permit a byte-for-byte witness;
        // production admission reads only the fixed 4096-byte envelope.
        let before = std::fs::read(&path).unwrap();
        assert!(NodeStore::open_existing(&path, ID, ScratchDisk::fixture()).is_err());
        assert_eq!(before, std::fs::read(&path).unwrap());
        assert!(NodeStore::create_new(&path, ID, ScratchDisk::fixture()).is_err());
        assert_eq!(before, std::fs::read(&path).unwrap());
    }
}

#[test]
fn recognized_store_recovers_after_actual_process_exit_without_close() {
    let directory = directory();
    let path = directory.path().join("owned");
    run_child(&path, "owned");
    let before = std::fs::read(&path).unwrap();
    assert!(NodeStore::open_existing(&path, Uuid::from_u128(9), ScratchDisk::fixture()).is_err());
    assert_eq!(before, std::fs::read(&path).unwrap());
    let node = NodeStore::open_existing(&path, ID, ScratchDisk::fixture()).unwrap();
    let transaction = node.db.begin_read().unwrap();
    let table = transaction.open_table(PROBE).unwrap();
    assert_eq!(
        table.get(b"key".as_slice()).unwrap().unwrap().value(),
        b"durable value"
    );
    drop(table);
    drop(transaction);
    assert!(NodeStore::open_existing(&path, ID, ScratchDisk::fixture()).is_err());
    drop(node);
    let reopened = NodeStore::open_existing(&path, ID, ScratchDisk::fixture()).unwrap();
    drop(reopened);
}

#[test]
fn partial_envelopes_are_never_adopted_or_reinitialized() {
    let directory = directory();
    let path = directory.path().join("partial");
    let owner = NodeFile::create_new(&path, ID).unwrap();
    let identity = private_files::file_identity(&path).unwrap();
    owner.backend().set_len(8192).unwrap();
    owner
        .backend()
        .write(0, b"partly initialized payload")
        .unwrap();
    owner.backend().sync_data().unwrap();
    owner.backend().close().unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(NodeStore::open_existing(&path, ID, ScratchDisk::fixture()).is_err());
    assert!(
        NodeStore::initialize_owned_empty(&path, &identity, ID, ScratchDisk::fixture()).is_err()
    );
    assert!(NodeStore::create_new(&path, ID, ScratchDisk::fixture()).is_err());
    assert_eq!(before, std::fs::read(&path).unwrap());

    for length in [0, 15, 31, 33, HEADER_BYTES - 1, HEADER_BYTES] {
        let path = directory.path().join(format!("truncated-{length}"));
        let file = options().create_new(true).open(&path).unwrap();
        file.write_all_at(&header(ID, READY)[..length], 0).unwrap();
        drop(file);
        let before = std::fs::read(&path).unwrap();
        assert!(NodeStore::open_existing(&path, ID, ScratchDisk::fixture()).is_err());
        assert_eq!(before, std::fs::read(&path).unwrap());
    }
}

#[test]
fn existing_header_requires_exact_canonical_fields_and_checksum() {
    let directory = directory();
    for (index, replacement) in [(0, b'X'), (32, 3), (33, 1), (CHECKSUM_AT, 11)] {
        let path = directory.path().join(format!("bad-{index}"));
        drop(NodeStore::create_new(&path, ID, ScratchDisk::fixture()).unwrap());
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
        assert!(NodeStore::open_existing(&path, ID, ScratchDisk::fixture()).is_err());
        assert_eq!(before, std::fs::read(&path).unwrap());
    }
}

#[test]
fn initialization_requires_exact_journal_owned_empty_inode() {
    let directory = directory();
    let path = directory.path().join("prepared");
    let other = directory.path().join("other");
    drop(options().create_new(true).open(&path).unwrap());
    drop(options().create_new(true).open(&other).unwrap());
    let identity = private_files::file_identity(&path).unwrap();
    let foreign = private_files::file_identity(&other).unwrap();
    assert!(
        NodeStore::initialize_owned_empty(&path, &foreign, ID, ScratchDisk::fixture()).is_err()
    );
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    let node =
        NodeStore::initialize_owned_empty(&path, &identity, ID, ScratchDisk::fixture()).unwrap();
    assert_eq!(private_files::file_identity(&path).unwrap(), identity);
    drop(node);
    drop(NodeStore::open_existing(&path, ID, ScratchDisk::fixture()).unwrap());
    assert!(
        NodeStore::initialize_owned_empty(&path, &identity, ID, ScratchDisk::fixture()).is_err()
    );
}

#[test]
fn offset_io_preserves_header_and_retained_backend_cannot_outlive_close() {
    let directory = directory();
    let path = directory.path().join("offset");
    let owner = NodeFile::create_new(&path, ID).unwrap();
    let backend = owner.backend();
    let header_before = std::fs::read(&path).unwrap();
    backend.set_len(8).unwrap();
    backend.write(0, b"12345678").unwrap();
    let mut read = [0; 8];
    backend.read(0, &mut read).unwrap();
    assert_eq!(read, *b"12345678");
    assert!(backend.write(8, b"outside allocated extent").is_err());
    assert!(backend.set_len(i64::MAX as u64).is_err());
    assert!(backend.read(u64::MAX, &mut read).is_err());
    assert!(backend.write(u64::MAX, b"overflow").is_err());
    backend.set_len(0).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), header_before);
    assert!(NodeFile::open_existing(&path, ID).is_err());
    backend.close().unwrap();
    assert!(backend.len().is_err());
    assert!(backend.read(0, &mut read).is_err());
    assert!(backend.write(0, b"closed").is_err());
    assert!(backend.set_len(8).is_err());
    assert!(backend.sync_data().is_err());
    let file = options().open(&path).unwrap();
    file.try_lock().unwrap();
}

#[test]
fn canonical_header_rejects_nil_identity_without_creating_a_file() {
    let directory = directory();
    let path = directory.path().join("nil");
    assert!(NodeStore::create_new(&path, Uuid::nil(), ScratchDisk::fixture()).is_err());
    assert!(!path.exists());
}

#[test]
fn validated_descriptor_handoff_never_reopens_a_substituted_path() {
    let directory = directory();
    let path = directory.path().join("candidate");
    let moved = directory.path().join("original-inode");
    drop(NodeStore::create_new(&path, ID, ScratchDisk::fixture()).unwrap());
    let expected = private_files::file_identity(&path).unwrap();
    let owner = NodeFile::open_existing(&path, ID).unwrap();
    std::fs::rename(&path, &moved).unwrap();
    drop(raw_database(&path));
    let unrelated = std::fs::read(&path).unwrap();

    let db = Database::builder()
        .create_with_backend(owner.backend())
        .unwrap();
    commit_probe(&db);
    assert_eq!(unrelated, std::fs::read(&path).unwrap());
    assert_eq!(private_files::file_identity(&moved).unwrap(), expected);
    assert!(NodeStore::open_existing(&moved, ID, ScratchDisk::fixture()).is_err());
    drop(db);
    // Even this retained admission owner has no descriptor after redb close.
    assert!(owner.backend().len().is_err());
    let reopened = NodeStore::open_existing(&moved, ID, ScratchDisk::fixture()).unwrap();
    let tx = reopened.db.begin_read().unwrap();
    assert_eq!(
        tx.open_table(PROBE)
            .unwrap()
            .get(b"key".as_slice())
            .unwrap()
            .unwrap()
            .value(),
        b"durable value"
    );
    assert_eq!(unrelated, std::fs::read(&path).unwrap());
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
    let path = PathBuf::from(std::env::var_os("KASUMI_NODE_FILE_CHILD_PATH").unwrap());
    match std::env::var("KASUMI_NODE_FILE_CHILD_MODE")
        .unwrap()
        .as_str()
    {
        "raw" => {
            let db = raw_database(&path);
            commit_probe(&db);
            std::process::exit(77);
        }
        "owned" => {
            // The parent owns this whole temporary directory, including files
            // whose Rust destructors the deliberate process exit will skip.
            let scratch = ScratchDisk::open(crate::ScratchDiskConfig {
                directory: path.parent().unwrap().join("crash-child-scratch"),
                max_bytes: 8 << 20,
                min_free_bytes: 0,
            })
            .unwrap();
            let node = NodeStore::create_new(&path, ID, scratch).unwrap();
            commit_probe(&node.db);
            std::process::exit(77);
        }
        _ => panic!("unexpected node crash child mode"),
    }
}
