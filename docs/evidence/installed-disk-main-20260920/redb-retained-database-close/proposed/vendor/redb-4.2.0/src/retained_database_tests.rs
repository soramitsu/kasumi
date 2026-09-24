use super::*;
#[cfg(feature = "experimental-api-5")]
use crate::ReadableTable;
use crate::{ReadableDatabase, StorageBackend, TableDefinition, backends::FileBackend};
use std::sync::{
    Mutex,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};

const TABLE: TableDefinition<u64, u64> = TableDefinition::new("retained-close");
#[derive(Debug)]
struct Marker;
#[derive(Debug)]
struct OriginalIo(Arc<Marker>);
impl std::fmt::Display for OriginalIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original close I/O failure")
    }
}
impl std::error::Error for OriginalIo {}
#[derive(Debug)]
struct Control {
    sync_mode: AtomicU8,
    close_mode: AtomicU8,
    syncs: AtomicUsize,
    closes: AtomicUsize,
    drops: AtomicUsize,
    shutdown_marker: Arc<Marker>,
    close_marker: Arc<Marker>,
}
#[derive(Debug)]
struct Backend {
    file: FileBackend,
    control: Arc<Control>,
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.control.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl StorageBackend for Backend {
    fn len(&self) -> std::io::Result<u64> {
        self.file.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.file.read(offset, out)
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        self.file.set_len(len)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.file.write(offset, bytes)
    }
    fn sync_data(&self) -> std::io::Result<()> {
        self.control.syncs.fetch_add(1, Ordering::SeqCst);
        match self.control.sync_mode.load(Ordering::SeqCst) {
            1 => Err(std::io::Error::other(OriginalIo(
                self.control.shutdown_marker.clone(),
            ))),
            2 => std::panic::panic_any(self.control.shutdown_marker.clone()),
            _ => self.file.sync_data(),
        }
    }
    fn close(&self) -> std::io::Result<()> {
        self.control.closes.fetch_add(1, Ordering::SeqCst);
        match self.control.close_mode.load(Ordering::SeqCst) {
            1 => Err(std::io::Error::other(OriginalIo(
                self.control.close_marker.clone(),
            ))),
            2 => std::panic::panic_any(self.control.close_marker.clone()),
            _ => self.file.close(),
        }
    }
}
struct Fixture {
    owner: RetainedDatabase,
    control: Arc<Control>,
    file: tempfile::NamedTempFile,
}
impl Fixture {
    fn new() -> Self {
        let file = crate::create_tempfile();
        let control = Arc::new(Control {
            sync_mode: AtomicU8::new(0),
            close_mode: AtomicU8::new(0),
            syncs: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            shutdown_marker: Arc::new(Marker),
            close_marker: Arc::new(Marker),
        });
        let database = Database::builder(crate::test_admission())
            .create_with_backend(Backend {
                file: FileBackend::new(file.reopen().unwrap()).unwrap(),
                control: control.clone(),
            })
            .unwrap();
        let tx = database.begin_write().unwrap();
        tx.open_table(TABLE).unwrap().insert(1, 41).unwrap();
        tx.commit().unwrap();
        Self {
            owner: database.retain(),
            control,
            file,
        }
    }
    fn counts(&self) -> (usize, usize, usize) {
        (
            self.control.syncs.load(Ordering::SeqCst),
            self.control.closes.load(Ordering::SeqCst),
            self.control.drops.load(Ordering::SeqCst),
        )
    }
}

// Uncertain physical cleanup is retained in three fixed test-process slots.
// This is test custody, not a production census or bounded panic-payload proof.
static RETAINED: Mutex<[Option<Fixture>; 3]> = Mutex::new([const { None }; 3]);
fn retain(slot: usize, fixture: Fixture) {
    assert_eq!(
        fixture.owner.report().settlement(),
        DatabaseCloseSettlement::Retained
    );
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 0);
    let mut census = RETAINED.lock().unwrap();
    assert!(census[slot].is_none());
    census[slot] = Some(fixture);
}
fn original_io(observation: TerminalObservation<'_, StorageError>, marker: &Arc<Marker>) {
    let TerminalObservation::Returned(Err(StorageError::Io(error))) = observation else {
        panic!("original physical I/O error missing");
    };
    assert!(Arc::ptr_eq(
        &error
            .get_ref()
            .unwrap()
            .downcast_ref::<OriginalIo>()
            .unwrap()
            .0,
        marker
    ));
}
fn error_pointer(observation: TerminalObservation<'_, StorageError>) -> *const StorageError {
    let TerminalObservation::Returned(Err(error)) = observation else {
        panic!("original error missing");
    };
    error
}
fn original_panic(
    observation: TerminalObservation<'_, StorageError>,
    marker: &Arc<Marker>,
) -> *const (dyn Any + Send) {
    let TerminalObservation::Panicked(payload) = observation else {
        panic!("original close panic missing");
    };
    assert!(Arc::ptr_eq(
        payload.downcast_ref::<Arc<Marker>>().unwrap(),
        marker
    ));
    payload
}

#[test]
fn existing_reader_keeps_close_waiting_then_actual_success_is_never_replayed() {
    let mut fixture = Fixture::new();
    let reader = fixture.owner.database().unwrap().begin_read().unwrap();
    let before = fixture.counts();
    let report = fixture.owner.close();
    assert_eq!(
        report.settlement(),
        DatabaseCloseSettlement::WaitingForTransactions
    );
    assert!(matches!(report.shutdown(), TerminalObservation::NotEntered));
    assert!(matches!(report.backend(), TerminalObservation::NotEntered));
    assert!(fixture.owner.database().is_none());
    assert_eq!(fixture.counts(), before);
    assert_eq!(
        reader
            .open_table(TABLE)
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap()
            .value(),
        41
    );
    drop(reader);
    let report = fixture.owner.close();
    assert_eq!(report.settlement(), DatabaseCloseSettlement::Settled);
    assert!(matches!(
        report.shutdown(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(matches!(
        report.backend(),
        TerminalObservation::Returned(Ok(()))
    ));
    let after = fixture.counts();
    assert_eq!(after.1, 1);
    assert_eq!(after.2, 0);
    assert_eq!(
        fixture.owner.close().settlement(),
        DatabaseCloseSettlement::Settled
    );
    assert_eq!(fixture.counts(), after);
    drop(fixture.owner);
    assert_eq!(fixture.control.closes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 1);
    let reopened = Database::open(fixture.file.path(), crate::test_admission()).unwrap();
    assert_eq!(
        reopened
            .begin_read()
            .unwrap()
            .open_table(TABLE)
            .unwrap()
            .get(1)
            .unwrap()
            .unwrap()
            .value(),
        41
    );
    reopened.close().unwrap();
}

#[test]
fn original_shutdown_error_survives_successful_backend_release() {
    let mut fixture = Fixture::new();
    fixture.control.sync_mode.store(1, Ordering::SeqCst);
    let report = fixture.owner.close();
    assert_eq!(report.settlement(), DatabaseCloseSettlement::Settled);
    original_io(report.shutdown(), &fixture.control.shutdown_marker);
    assert!(matches!(
        report.backend(),
        TerminalObservation::Returned(Ok(()))
    ));
    let primary = error_pointer(report.shutdown());
    let counts = fixture.counts();
    assert_eq!(error_pointer(fixture.owner.close().shutdown()), primary);
    assert_eq!(fixture.counts(), counts);
    drop(fixture.owner);
    assert_eq!(fixture.control.closes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.control.drops.load(Ordering::SeqCst), 1);
}

#[test]
fn both_original_errors_and_actual_locked_file_survive_repeated_close() {
    let mut fixture = Fixture::new();
    fixture.control.sync_mode.store(1, Ordering::SeqCst);
    fixture.control.close_mode.store(1, Ordering::SeqCst);
    let report = fixture.owner.close();
    assert_eq!(report.settlement(), DatabaseCloseSettlement::Retained);
    original_io(report.shutdown(), &fixture.control.shutdown_marker);
    original_io(report.backend(), &fixture.control.close_marker);
    let shutdown = error_pointer(report.shutdown());
    let backend = error_pointer(report.backend());
    let counts = fixture.counts();
    let repeated = fixture.owner.close();
    assert_eq!(error_pointer(repeated.shutdown()), shutdown);
    assert_eq!(error_pointer(repeated.backend()), backend);
    assert_eq!(fixture.counts(), counts);
    assert!(FileBackend::new(fixture.file.reopen().unwrap()).is_err());
    retain(0, fixture);
}

#[test]
fn shutdown_unwind_retains_original_payload_even_after_backend_release() {
    let mut fixture = Fixture::new();
    fixture.control.sync_mode.store(2, Ordering::SeqCst);
    let report = fixture.owner.close();
    assert_eq!(report.settlement(), DatabaseCloseSettlement::Retained);
    let original = original_panic(report.shutdown(), &fixture.control.shutdown_marker);
    assert!(matches!(
        report.backend(),
        TerminalObservation::Returned(Ok(()))
    ));
    let counts = fixture.counts();
    let repeated = fixture.owner.close();
    assert!(std::ptr::eq(
        original_panic(repeated.shutdown(), &fixture.control.shutdown_marker),
        original
    ));
    assert_eq!(fixture.counts(), counts);
    retain(1, fixture);
}

#[test]
fn backend_unwind_retains_database_payload_and_actual_locked_file_without_retry() {
    let mut fixture = Fixture::new();
    fixture.control.close_mode.store(2, Ordering::SeqCst);
    let address = &fixture.owner.database as *const Database;
    let report = fixture.owner.close();
    assert_eq!(report.settlement(), DatabaseCloseSettlement::Retained);
    assert!(matches!(
        report.shutdown(),
        TerminalObservation::Returned(Ok(()))
    ));
    let original = original_panic(report.backend(), &fixture.control.close_marker);
    assert_eq!(&fixture.owner.database as *const Database, address);
    let counts = fixture.counts();
    let repeated = fixture.owner.close();
    assert!(std::ptr::eq(
        original_panic(repeated.backend(), &fixture.control.close_marker),
        original
    ));
    assert_eq!(fixture.counts(), counts);
    assert!(fixture.owner.database().is_none());
    assert!(FileBackend::new(fixture.file.reopen().unwrap()).is_err());
    retain(2, fixture);
}
