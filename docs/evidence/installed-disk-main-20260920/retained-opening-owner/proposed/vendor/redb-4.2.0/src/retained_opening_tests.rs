use super::*;
#[cfg(feature = "experimental-api-5")]
use crate::ReadableTable;
use crate::{ReadableDatabase, StorageBackend, TableDefinition, WriteTerminalOperation, backends::FileBackend};
use std::sync::{Mutex, atomic::{AtomicU8, AtomicUsize, Ordering}};

#[derive(Debug)]
struct Marker;
#[derive(Debug)]
struct OriginalIo(Arc<Marker>);
impl std::fmt::Display for OriginalIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("opening fault") }
}
impl std::error::Error for OriginalIo {}
#[derive(Debug)]
struct Control {
    len_mode: AtomicU8,
    write_mode: AtomicU8,
    close_mode: AtomicU8,
    calls: AtomicUsize,
    closes: AtomicUsize,
    drops: AtomicUsize,
    primary: Arc<Marker>,
    secondary: Arc<Marker>,
}
impl Control {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            len_mode: AtomicU8::new(0), write_mode: AtomicU8::new(0), close_mode: AtomicU8::new(0),
            calls: AtomicUsize::new(0), closes: AtomicUsize::new(0), drops: AtomicUsize::new(0),
            primary: Arc::new(Marker), secondary: Arc::new(Marker),
        })
    }
    fn fault(&self, mode: u8, marker: &Arc<Marker>) -> std::io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match mode {
            1 => Err(std::io::Error::other(OriginalIo(marker.clone()))),
            2 => std::panic::panic_any(marker.clone()),
            _ => Ok(()),
        }
    }
}
#[derive(Debug)]
struct Backend {
    file: FileBackend,
    control: Arc<Control>,
}
impl Drop for Backend {
    fn drop(&mut self) { self.control.drops.fetch_add(1, Ordering::SeqCst); }
}
impl StorageBackend for Backend {
    fn len(&self) -> std::io::Result<u64> {
        self.control.fault(self.control.len_mode.load(Ordering::SeqCst), &self.control.primary)?;
        self.file.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.control.fault(0, &self.control.primary)?;
        self.file.read(offset, out)
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        self.control.fault(0, &self.control.primary)?;
        self.file.set_len(len)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.control.fault(self.control.write_mode.load(Ordering::SeqCst), &self.control.primary)?;
        self.file.write(offset, bytes)
    }
    fn sync_data(&self) -> std::io::Result<()> {
        self.control.fault(0, &self.control.primary)?;
        self.file.sync_data()
    }
    fn close(&self) -> std::io::Result<()> {
        self.control.closes.fetch_add(1, Ordering::SeqCst);
        self.control.fault(self.control.close_mode.load(Ordering::SeqCst), &self.control.secondary)?;
        self.file.close()
    }
}
struct Fixture {
    owner: RetainedDatabaseOpening,
    control: Arc<Control>,
    file: tempfile::NamedTempFile,
}
impl Fixture {
    fn new() -> Self { Self::with_admission(crate::test_admission()) }
    fn with_admission(admission: Arc<dyn crate::StorageAdmission>) -> Self {
        let file = crate::create_tempfile();
        let control = Control::new();
        let owner = Builder::new(admission).retain_backend(
            Box::new(Backend { file: FileBackend::new(file.reopen().unwrap()).unwrap(), control: control.clone() }),
            DatabaseOpenMode::Create,
        );
        Self { owner, control, file }
    }
}
// Fixed process custody; uncertain file owners outlive the native test thread.
static RETAINED: Mutex<[Option<Fixture>; 2]> = Mutex::new([const { None }; 2]);
fn original_io(observation: TerminalObservation<'_, StorageError>, expected: &Arc<Marker>) -> *const StorageError {
    let TerminalObservation::Returned(Err(error @ StorageError::Io(io))) = observation else { panic!("original I/O missing") };
    assert!(Arc::ptr_eq(&io.get_ref().unwrap().downcast_ref::<OriginalIo>().unwrap().0, expected));
    error
}
fn original_open_io(observation: TerminalObservation<'_, DatabaseError>, expected: &Arc<Marker>) -> *const DatabaseError {
    let TerminalObservation::Returned(Err(error @ DatabaseError::Storage(StorageError::Io(io)))) = observation else { panic!("original opening I/O missing") };
    assert!(Arc::ptr_eq(&io.get_ref().unwrap().downcast_ref::<OriginalIo>().unwrap().0, expected));
    error
}

#[test]
fn prepare_has_no_backend_effect_and_close_before_open_never_initializes() {
    let mut fixture = Fixture::new();
    assert_eq!(fixture.control.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.owner.report().settlement(), DatabaseOpenSettlement::Prepared);
    assert!(matches!(fixture.owner.close().opening(), TerminalObservation::NotEntered));
    assert_eq!(fixture.owner.report().settlement(), DatabaseOpenSettlement::Closed);
    let calls = fixture.control.calls.load(Ordering::SeqCst);
    assert_eq!(fixture.owner.open().settlement(), DatabaseOpenSettlement::Closed);
    assert_eq!(fixture.control.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fixture.control.closes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 0);
    drop(fixture.owner);
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn first_io_and_secondary_close_failure_keep_both_originals_and_locked_backend() {
    let mut fixture = Fixture::new();
    fixture.control.len_mode.store(1, Ordering::SeqCst);
    fixture.control.close_mode.store(1, Ordering::SeqCst);
    let opening = original_open_io(fixture.owner.open().opening(), &fixture.control.primary);
    assert_eq!(fixture.owner.report().phase(), DatabaseOpenPhase::MemoryInitialization);
    assert!(fixture.owner.memory.is_none());
    assert!(fixture.owner.database.is_none());
    let report = fixture.owner.close();
    assert_eq!(report.settlement(), DatabaseOpenSettlement::Retained);
    let close = original_io(report.partial_close(), &fixture.control.secondary);
    assert_eq!(original_open_io(report.opening(), &fixture.control.primary), opening);
    let calls = fixture.control.calls.load(Ordering::SeqCst);
    let report = fixture.owner.close();
    assert_eq!(original_io(report.partial_close(), &fixture.control.secondary), close);
    assert_eq!(original_open_io(report.opening(), &fixture.control.primary), opening);
    assert_eq!(fixture.owner.open().settlement(), DatabaseOpenSettlement::Retained);
    assert_eq!(fixture.control.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 0);
    assert!(matches!(FileBackend::new(fixture.file.reopen().unwrap()), Err(DatabaseError::DatabaseAlreadyOpen)));
    let mut retained = RETAINED.lock().unwrap();
    assert!(retained[0].is_none());
    retained[0] = Some(fixture);
}

#[test]
fn initialization_write_unwind_keeps_payload_and_partial_cache_until_positive_release() {
    let mut fixture = Fixture::new();
    fixture.control.write_mode.store(2, Ordering::SeqCst);
    let report = fixture.owner.open();
    let TerminalObservation::Panicked(payload) = report.opening() else { panic!("opening panic missing") };
    assert!(Arc::ptr_eq(payload.downcast_ref::<Arc<Marker>>().unwrap(), &fixture.control.primary));
    let original = payload as *const (dyn Any + Send);
    assert!(fixture.owner.memory.is_none());
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 0);
    let report = fixture.owner.close();
    assert_eq!(report.settlement(), DatabaseOpenSettlement::Closed);
    let TerminalObservation::Panicked(payload) = report.opening() else { panic!("opening panic erased") };
    assert!(std::ptr::eq(original, payload));
    assert_eq!(fixture.control.closes.load(Ordering::SeqCst), 1);
    drop(fixture.owner);
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn repair_callback_unwind_keeps_actual_memory_and_original_callback_payload() {
    let mut fixture = Fixture::new();
    let marker = fixture.control.primary.clone();
    fixture.owner.builder.set_repair_callback(move |_| std::panic::panic_any(marker.clone()));
    let report = fixture.owner.open();
    assert_eq!(report.phase(), DatabaseOpenPhase::AllocatorRestoration);
    let TerminalObservation::Panicked(payload) = report.opening() else { panic!("callback panic missing") };
    assert!(Arc::ptr_eq(payload.downcast_ref::<Arc<Marker>>().unwrap(), &fixture.control.primary));
    assert!(fixture.owner.memory.is_some());
    assert!(fixture.owner.database.is_none());
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.owner.close().settlement(), DatabaseOpenSettlement::Closed);
    drop(fixture.owner);
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn successful_repair_bootstrap_is_committed_disposed_and_preserved_through_reader_drain() {
    const TABLE: TableDefinition<u64, u64> = TableDefinition::new("retained-open");
    let mut fixture = Fixture::new();
    let report = fixture.owner.open();
    assert_eq!(report.settlement(), DatabaseOpenSettlement::Ready);
    assert!(matches!(report.opening(), TerminalObservation::Returned(Ok(()))));
    let bootstrap = report.bootstrap().unwrap();
    assert_eq!(bootstrap.operation(), Some(WriteTerminalOperation::Commit));
    assert!(bootstrap.disposal_complete());
    let database = fixture.owner.database().unwrap();
    let writer = database.begin_write().unwrap();
    writer.open_table(TABLE).unwrap().insert(1, 42).unwrap();
    writer.commit().unwrap();
    let reader = database.begin_read().unwrap();
    assert_eq!(fixture.owner.close().settlement(), DatabaseOpenSettlement::WaitingForTransactions);
    assert!(fixture.owner.database().is_none());
    assert_eq!(fixture.control.closes.load(Ordering::SeqCst), 0);
    assert_eq!(reader.open_table(TABLE).unwrap().get(1).unwrap().unwrap().value(), 42);
    drop(reader);
    assert_eq!(fixture.owner.close().settlement(), DatabaseOpenSettlement::Closed);
    assert!(fixture.owner.report().bootstrap().unwrap().disposal_complete());
    drop(fixture.owner);
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 1);
    let backend = Box::new(FileBackend::new(fixture.file.reopen().unwrap()).unwrap());
    let mut reopened = Builder::new(crate::test_admission()).retain_backend(backend, DatabaseOpenMode::Existing);
    assert_eq!(reopened.open().settlement(), DatabaseOpenSettlement::Ready);
    assert_eq!(reopened.report().bootstrap().unwrap().operation(), Some(WriteTerminalOperation::Abort));
    assert_eq!(reopened.database().unwrap().begin_read().unwrap().open_table(TABLE).unwrap().get(1).unwrap().unwrap().value(), 42);
    assert_eq!(reopened.close().settlement(), DatabaseOpenSettlement::Closed);
}

#[derive(Debug)]
struct PanickingAdmission {
    marker: Arc<Marker>,
    calls: AtomicUsize,
}
impl crate::StorageAdmission for PanickingAdmission {
    fn check_owner(&self) -> Result<(), crate::OwnerFailed> { Ok(()) }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), crate::AdmissionError> { Ok(()) }
    fn settle_growth(&self, _: u64) -> Result<(), crate::OwnerFailed> { Ok(()) }
    fn owner_failed(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::panic::panic_any(self.marker.clone());
    }
}

#[test]
fn original_io_survives_admission_fence_panic_and_proxy_fences_before_callback() {
    let admission = Arc::new(PanickingAdmission { marker: Arc::new(Marker), calls: AtomicUsize::new(0) });
    let mut fixture = Fixture::with_admission(admission.clone());
    assert!(Arc::ptr_eq(&fixture.owner.admission.inner, &(admission.clone() as Arc<dyn crate::StorageAdmission>)));
    fixture.control.len_mode.store(1, Ordering::SeqCst);
    fixture.control.close_mode.store(1, Ordering::SeqCst);
    let report = fixture.owner.open();
    let opening = original_open_io(report.opening(), &fixture.control.primary);
    let original = {
        let fence = report.fence();
        let Some(TerminalObservation::Panicked(payload)) = fence.observation() else { panic!("fence panic missing") };
        assert!(Arc::ptr_eq(payload.downcast_ref::<Arc<Marker>>().unwrap(), &admission.marker));
        payload as *const (dyn Any + Send)
    };
    assert_eq!(admission.calls.load(Ordering::SeqCst), 1);
    assert!(fixture.owner.builder.admission.check_owner().is_err());
    assert!(matches!(fixture.owner.builder.admission.reserve_growth(0, 4096), Err(crate::AdmissionError::OwnerFailed)));
    assert!(fixture.owner.builder.admission.settle_growth(0).is_err());
    let report = fixture.owner.close();
    assert_eq!(report.settlement(), DatabaseOpenSettlement::Retained);
    original_io(report.partial_close(), &fixture.control.secondary);
    assert_eq!(original_open_io(report.opening(), &fixture.control.primary), opening);
    assert_eq!(report.opening_phase(), DatabaseOpenPhase::MemoryInitialization);
    assert_eq!(report.phase(), DatabaseOpenPhase::Closing);
    let fence = report.fence();
    let Some(TerminalObservation::Panicked(payload)) = fence.observation() else { panic!("fence panic erased") };
    assert!(std::ptr::eq(original, payload));
    assert_eq!(admission.calls.load(Ordering::SeqCst), 1);
    drop(fence);
    assert!(matches!(FileBackend::new(fixture.file.reopen().unwrap()), Err(DatabaseError::DatabaseAlreadyOpen)));
    let mut retained = RETAINED.lock().unwrap();
    assert!(retained[1].is_none());
    retained[1] = Some(fixture);
}
