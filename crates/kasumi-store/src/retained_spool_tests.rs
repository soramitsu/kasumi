use super::*;
use crate::{
    ScratchDisk,
    allocation_tests::{DeallocationObservation, measure, observe_deallocation},
    test_utils::TestDiskMemory,
};
use kasumi_kv::{
    AdmissionError, CacheConfig, DatabaseCloseSettlement, GroupFile, OwnerFailed, ROOT_SLOT_BYTES,
    RetainedDatabase, RootSlot, SegmentGroupBackend, StorageAdmission, StorageError,
    TableDefinition, TerminalObservation,
};
use std::{
    any::Any,
    io::Write,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Debug)]
struct Marker(u64);
#[derive(Debug)]
struct OriginalIo(Arc<Marker>);
impl std::fmt::Display for OriginalIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original scratch close sync failure {}", self.0.0)
    }
}
impl std::error::Error for OriginalIo {}
enum CloseFault {
    Error(io::Error),
    Panic(Box<dyn Any + Send>),
}
struct AggregateBackend {
    owner: Arc<crate::scratch_table::group::Owner>,
    group: crate::scratch_table::group::Backend,
    fault: Mutex<Option<CloseFault>>,
    closes: AtomicUsize,
    terminal_syncs: AtomicUsize,
}
impl std::fmt::Debug for AggregateBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("actual retained scratch backend")
    }
}
impl StorageAdmission for AggregateBackend {
    fn reserve_workspace(
        &self,
        bytes: u64,
    ) -> Result<Box<dyn kasumi_kv::ResidentLease>, AdmissionError> {
        self.owner.reserve_workspace(bytes)
    }
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.owner.check_owner()
    }
    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        self.owner.reserve_growth(current, requested)
    }
    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        self.owner.settle_growth(actual)
    }
    fn owner_failed(&self) {
        self.owner.owner_failed();
    }

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryQuote, AdmissionError> {
        self.owner.quote_cache_memory(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<kasumi_kv::CacheMemoryLease, AdmissionError> {
        self.owner.clone().reserve_cache_memory(bytes)
    }
}
#[derive(Debug)]
struct Backend(Arc<AggregateBackend>);
impl SegmentGroupBackend for Backend {
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> std::result::Result<(), kasumi_kv::TransactionReserveError> {
        self.0.group.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.0.group.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.0.group.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.0.group.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.0.group.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.0.group.sync_root()
    }
    fn visit_entries(
        &self,
        visitor: &mut dyn FnMut(&std::ffi::OsStr) -> io::Result<()>,
    ) -> io::Result<()> {
        self.0.group.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.0.group.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.0.group.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.0.group.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.group.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.group.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, len: u64) -> io::Result<()> {
        self.0.group.set_len(file, len)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.0.group.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.0.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.0.group.sync_names()
    }
    fn close(&self) -> kasumi_kv::BackendCloseOutcome {
        self.0.closes.fetch_add(1, Ordering::SeqCst);
        self.0.owner.close_with_root(|spool| {
            self.0.terminal_syncs.fetch_add(1, Ordering::SeqCst);
            spool.sync_all()?;
            match self.0.fault.lock().unwrap().take() {
                Some(CloseFault::Error(error)) => Err(error),
                Some(CloseFault::Panic(payload)) => std::panic::resume_unwind(payload),
                None => Ok(()),
            }
        })
    }
}

struct Fixture {
    database: RetainedDatabase,
    backend: Arc<AggregateBackend>,
    disk: Arc<ScratchDisk>,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = crate::test_utils::private_tempdir().unwrap();
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory);
        let owner = crate::scratch_table::group::Owner::new(&disk, 8 << 20).unwrap();
        let backend = Arc::new(AggregateBackend {
            group: crate::scratch_table::group::Backend(owner.clone()),
            owner,
            fault: Mutex::new(None),
            closes: AtomicUsize::new(0),
            terminal_syncs: AtomicUsize::new(0),
        });
        let database = kasumi_kv::Database::builder(
            backend.clone(),
            [101; 16],
            CacheConfig {
                byte_limit: 8 << 20,
            },
        )
        .create_with_backend(Backend(backend.clone()))
        .unwrap();
        let write = database.begin_write().unwrap();
        write
            .open_table(TableDefinition::<u64, u64>::new("spool-close"))
            .unwrap()
            .insert(1, 41)
            .unwrap();
        write.commit().unwrap();
        Self {
            database: database.retain(),
            backend,
            disk,
            _directory: directory,
        }
    }
}
// These slots retain the actual aggregate and its single original cause after
// test return. They are not a production census or a diagnostic-size guarantee.
static RETAINED: Mutex<[Option<Fixture>; 2]> = Mutex::new([const { None }; 2]);
fn retain(index: usize, fixture: Fixture) {
    assert_eq!(
        fixture.database.report().settlement(),
        DatabaseCloseSettlement::Retained
    );
    let mut census = RETAINED.lock().unwrap();
    assert!(census[index].is_none());
    census[index] = Some(fixture);
}

#[test]
fn original_sync_error_moves_once_to_database_while_spool_and_charge_stay_owned() {
    let mut fixture = Fixture::new();
    let marker = Arc::new(Marker(41));
    let original = io::Error::other(OriginalIo(marker.clone()));
    let identity = original
        .get_ref()
        .unwrap()
        .downcast_ref::<OriginalIo>()
        .unwrap() as *const OriginalIo;
    *fixture.backend.fault.lock().unwrap() = Some(CloseFault::Error(original));
    let (address, descriptor) = fixture.backend.owner.with_root(|retained| {
        let spool = retained.spool.as_ref().unwrap();
        (spool as *const EncryptedSpool, spool.file.as_raw_fd())
    });
    let before = fixture.disk.snapshot();
    let report = fixture.database.close();
    assert_eq!(report.settlement(), DatabaseCloseSettlement::Retained);
    assert_eq!(
        report.native_disposition(),
        kasumi_kv::BackendNativeDisposition::Retained
    );
    assert!(matches!(
        report.shutdown(),
        TerminalObservation::Returned(Ok(()))
    ));
    let TerminalObservation::Returned(Err(StorageError::Io(error))) = report.backend() else {
        panic!("original backend error missing");
    };
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<OriginalIo>()
            .unwrap() as *const OriginalIo,
        identity
    );
    assert!(Arc::ptr_eq(
        &error
            .get_ref()
            .unwrap()
            .downcast_ref::<OriginalIo>()
            .unwrap()
            .0,
        &marker
    ));
    let original_cell = error as *const io::Error;
    let repeated_report = fixture.database.close();
    let TerminalObservation::Returned(Err(StorageError::Io(repeated))) = repeated_report.backend()
    else {
        panic!("original error missing on repeat");
    };
    assert_eq!(repeated as *const io::Error, original_cell);
    fixture.backend.owner.with_root(|retained| {
        assert_eq!(retained.phase(), SpoolClosePhase::FailedTransferred);
        assert!(retained.spool().is_none());
        assert_eq!(
            retained.spool.as_ref().unwrap() as *const EncryptedSpool,
            address
        );
        assert_eq!(
            retained.spool.as_ref().unwrap().file.as_raw_fd(),
            descriptor
        );
        assert!(
            retained
                .spool
                .as_ref()
                .unwrap()
                .file
                .metadata()
                .unwrap()
                .len()
                > 0
        );
        let (result, native) = retained.close().into_parts();
        assert_eq!(native, kasumi_kv::BackendNativeDisposition::Retained);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    });
    assert_eq!(fixture.backend.closes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.backend.terminal_syncs.load(Ordering::SeqCst), 1);
    let after = fixture.disk.snapshot();
    assert_eq!(after.charged_bytes, before.charged_bytes);
    assert_eq!(after.live_files, before.live_files);
    retain(0, fixture);
}

#[test]
fn actual_final_sync_panic_reaches_database_with_same_payload_and_spool_still_present() {
    let mut fixture = Fixture::new();
    let marker = Arc::new(Marker(53));
    let payload: Box<dyn Any + Send> = Box::new(marker.clone());
    let identity = payload.as_ref() as *const (dyn Any + Send);
    *fixture.backend.fault.lock().unwrap() = Some(CloseFault::Panic(payload));
    let before = fixture.disk.snapshot();
    let report = fixture.database.close();
    assert_eq!(report.settlement(), DatabaseCloseSettlement::Retained);
    assert_eq!(
        report.native_disposition(),
        kasumi_kv::BackendNativeDisposition::Retained
    );
    let TerminalObservation::Panicked(original) = report.backend() else {
        panic!("original unwind missing");
    };
    assert!(std::ptr::eq(original, identity));
    assert!(Arc::ptr_eq(
        original.downcast_ref::<Arc<Marker>>().unwrap(),
        &marker
    ));
    let repeated = fixture.database.close();
    let TerminalObservation::Panicked(original) = repeated.backend() else {
        panic!("original unwind missing on repeat");
    };
    assert!(std::ptr::eq(original, identity));
    fixture.backend.owner.with_root(|retained| {
        assert_eq!(retained.phase(), SpoolClosePhase::InterruptedTransferred);
        assert!(
            retained
                .spool
                .as_ref()
                .unwrap()
                .file
                .metadata()
                .unwrap()
                .len()
                > 0
        );
        assert!(retained.spool().is_none());
        let (result, native) = retained.close().into_parts();
        assert_eq!(native, kasumi_kv::BackendNativeDisposition::Retained);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    });
    assert_eq!(fixture.backend.closes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.backend.terminal_syncs.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.disk.snapshot().charged_bytes, before.charged_bytes);
    assert_eq!(fixture.disk.snapshot().live_files, before.live_files);
    retain(1, fixture);
}

struct PausedClose {
    observation: Arc<DeallocationObservation>,
    worker: Option<std::thread::JoinHandle<RetainedSpool>>,
}
impl Drop for PausedClose {
    fn drop(&mut self) {
        self.observation.release();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
#[test]
fn file_key_and_each_buffer_retire_before_extent_credit_is_reusable() {
    for resource in 0..3 {
        let directory = crate::test_utils::private_tempdir().unwrap();
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk = ScratchDisk::isolated_fixture(directory.path(), 128 << 10, memory);
        let mut spool = EncryptedSpool::new(&disk, 1 << 20).unwrap();
        spool.write_all(b"actual retained ciphertext").unwrap();
        let before = disk.snapshot().charged_bytes;
        assert!(before > 0);
        let descriptor = spool.file.as_raw_fd();
        let metadata = spool.file.metadata().unwrap();
        let identity = (metadata.dev(), metadata.ino());
        let address = match resource {
            0 => spool.key.as_bytes().as_ptr(),
            1 => spool.cached.as_ptr(),
            _ => spool.ciphertext.as_ptr(),
        } as usize;
        let observation = Arc::new(DeallocationObservation::new(true));
        let worker_observation = observation.clone();
        let worker = std::thread::spawn(move || {
            let mut retained = spool.retain();
            let (result, allocations) = measure(|| {
                observe_deallocation(address as *const (), &worker_observation, || {
                    retained.close()
                })
            });
            let (result, native) = result.into_parts();
            assert_eq!(native, kasumi_kv::BackendNativeDisposition::Drained);
            result.unwrap();
            assert_eq!(allocations, 0);
            retained
        });
        let mut pending = PausedClose {
            observation,
            worker: Some(worker),
        };
        let until = Instant::now() + Duration::from_secs(5);
        while !pending.observation.entered() {
            assert!(
                Instant::now() < until,
                "actual spool allocation retirement was not observed"
            );
            std::thread::yield_now();
        }
        assert!(!pending.observation.finished());
        // A concurrent test may already have reused the descriptor number.
        // The original anonymous inode must no longer be open at that number.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(descriptor, &mut stat) } == 0 {
            assert_ne!((stat.st_dev as u64, stat.st_ino as u64), identity);
        } else {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
        assert_eq!(disk.snapshot().charged_bytes, before);
        let (file, mut charge) = disk.file().unwrap();
        assert_eq!(
            charge.grow(128 << 10).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        drop(file);
        drop(charge);
        pending.observation.release();
        let mut retained = pending.worker.take().unwrap().join().unwrap();
        assert!(pending.observation.finished());
        assert_eq!(pending.observation.count(), 1);
        assert_eq!(retained.phase(), SpoolClosePhase::Complete);
        assert!(retained.spool.is_none());
        assert!(retained.spool().is_none());
        let (outcome, allocations) = measure(|| retained.close());
        let (result, native) = outcome.into_parts();
        assert_eq!(native, kasumi_kv::BackendNativeDisposition::Drained);
        result.unwrap();
        assert_eq!(allocations, 0);
        assert_eq!(disk.snapshot().charged_bytes, 0);
        assert_eq!(disk.snapshot().live_files, 0);
        let (file, mut charge) = disk.file().unwrap();
        charge.grow(128 << 10).unwrap();
        drop(file);
        drop(charge);
    }
}

#[test]
fn group_root_and_data_files_are_independently_encrypted_anonymous_spools() {
    use std::os::unix::fs::FileExt;
    let directory = crate::test_utils::private_tempdir().unwrap();
    let memory = TestDiskMemory::new(16 << 20, 256);
    let disk = ScratchDisk::isolated_fixture(directory.path(), 8 << 20, memory.clone());
    let baseline = memory.snapshot().used_bytes;
    let owner = crate::scratch_table::group::Owner::new(&disk, 4 << 20).unwrap();
    let backend = crate::scratch_table::group::Backend(owner.clone());
    let first = GroupFile::segment(1);
    let second = GroupFile::directory(1);
    let plaintext = b"scratch group private value must remain encrypted";
    let mut root = [0; ROOT_SLOT_BYTES];
    root[..plaintext.len()].copy_from_slice(plaintext);
    backend.write_root(RootSlot::A, &root).unwrap();
    backend.sync_root().unwrap();
    for file in [first, second] {
        backend.create(file).unwrap();
        backend.write(file, 0, plaintext).unwrap();
        backend.sync(file).unwrap();
        let mut recovered = vec![0; plaintext.len()];
        backend.read(file, 0, &mut recovered).unwrap();
        assert_eq!(recovered, plaintext);
    }
    let ciphertext = |retained: &mut RetainedSpool| {
        let spool = retained.spool.as_ref().unwrap();
        assert_eq!(spool.file.metadata().unwrap().nlink(), 0);
        let mut bytes = vec![0; spool.file.metadata().unwrap().len() as usize];
        spool.file.read_exact_at(&mut bytes, 0).unwrap();
        assert!(
            !bytes
                .windows(plaintext.len())
                .any(|window| window == plaintext)
        );
        bytes
    };
    let a = owner.with_root(ciphertext);
    let b = owner.with_file(first, ciphertext);
    let c = owner.with_file(second, ciphertext);
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    backend.close().into_result().unwrap();
    drop((backend, owner));
    assert_eq!(disk.snapshot().charged_bytes, 0);
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(memory.snapshot().used_bytes, baseline);
}
