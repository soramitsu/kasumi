use super::*;
use crate::{
    ScratchDisk,
    allocation_tests::{DeallocationObservation, measure, observe_deallocation},
    test_utils::TestDiskMemory,
};
use redb::{
    AdmissionError, DatabaseCloseSettlement, OwnerFailed, RetainedDatabase, StorageAdmission,
    StorageBackend, StorageError, TableDefinition, TerminalObservation,
};
use std::{
    any::Any,
    io::{Read, Seek, SeekFrom, Write},
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
    spool: Mutex<RetainedSpool>,
    fault: Mutex<Option<CloseFault>>,
    closes: AtomicUsize,
    terminal_syncs: AtomicUsize,
}
impl std::fmt::Debug for AggregateBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("actual retained scratch backend")
    }
}
impl AggregateBackend {
    fn with<T>(&self, work: impl FnOnce(&mut EncryptedSpool) -> io::Result<T>) -> io::Result<T> {
        let mut retained = self.spool.lock().unwrap_or_else(|p| p.into_inner());
        let spool = retained.spool().ok_or(io::ErrorKind::BrokenPipe)?;
        work(spool)
    }
}
impl StorageAdmission for AggregateBackend {
    fn reserve_workspace(
        &self,
        _bytes: u64,
    ) -> core::result::Result<Box<dyn redb::ResidentLease>, redb::AdmissionError> {
        self.check_owner()
            .map_err(|_| redb::AdmissionError::OwnerFailed)?;
        Ok(Box::new(()))
    }
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.with(|spool| spool.check_owner())
            .map_err(|_| OwnerFailed)
    }
    fn reserve_growth(&self, current: u64, requested: u64) -> Result<(), AdmissionError> {
        self.with(|spool| spool.reserve_growth(current, requested))
            .map_err(|error| {
                if error.kind() == io::ErrorKind::StorageFull {
                    AdmissionError::CapacityDenied
                } else {
                    AdmissionError::OwnerFailed
                }
            })
    }
    fn settle_growth(&self, actual: u64) -> Result<(), OwnerFailed> {
        self.with(|spool| spool.settle_growth(actual))
            .map_err(|_| OwnerFailed)
    }
    fn owner_failed(&self) {
        let retained = self.spool.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(spool) = retained.spool.as_ref() {
            spool.owner_failed();
        }
    }
}
#[derive(Debug)]
struct Backend(Arc<AggregateBackend>);
impl StorageBackend for Backend {
    fn len(&self) -> io::Result<u64> {
        self.0.with(|spool| Ok(spool.len()))
    }
    fn read(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.0.with(|spool| {
            spool.seek(SeekFrom::Start(offset))?;
            spool.read_exact(bytes)
        })
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.0.with(|spool| spool.resize(len))
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.0.with(|spool| {
            spool.seek(SeekFrom::Start(offset))?;
            spool.write_all(bytes)
        })
    }
    fn sync_data(&self) -> io::Result<()> {
        self.0.with(EncryptedSpool::sync_all)
    }
    fn close(&self) -> redb::BackendCloseOutcome {
        self.0.closes.fetch_add(1, Ordering::SeqCst);
        let mut retained = self.0.spool.lock().unwrap_or_else(|p| p.into_inner());
        retained.close_with(|spool| {
            self.0.terminal_syncs.fetch_add(1, Ordering::SeqCst);
            // Exercise actual final spool sync before injecting an uncertain
            // completion. The prefabricated original is transferred unchanged.
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
        let backend = Arc::new(AggregateBackend {
            spool: Mutex::new(EncryptedSpool::new(&disk, 8 << 20).unwrap().retain()),
            fault: Mutex::new(None),
            closes: AtomicUsize::new(0),
            terminal_syncs: AtomicUsize::new(0),
        });
        let database = redb::Database::builder(backend.clone())
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
    let (address, descriptor) = {
        let retained = fixture.backend.spool.lock().unwrap();
        let spool = retained.spool.as_ref().unwrap();
        (spool as *const EncryptedSpool, spool.file.as_raw_fd())
    };
    let before = fixture.disk.snapshot();
    let report = fixture.database.close();
    assert_eq!(report.settlement(), DatabaseCloseSettlement::Retained);
    assert_eq!(
        report.native_disposition(),
        redb::BackendNativeDisposition::Retained
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
    let mut retained = fixture.backend.spool.lock().unwrap();
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
    assert_eq!(native, redb::BackendNativeDisposition::Retained);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    drop(retained);
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
        redb::BackendNativeDisposition::Retained
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
    let mut retained = fixture
        .backend
        .spool
        .lock()
        .unwrap_or_else(|p| p.into_inner());
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
    assert_eq!(native, redb::BackendNativeDisposition::Retained);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    drop(retained);
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
            assert_eq!(native, redb::BackendNativeDisposition::Drained);
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
        assert_eq!(native, redb::BackendNativeDisposition::Drained);
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
