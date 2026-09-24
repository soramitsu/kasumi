use kasumi_kv::{
    AdmissionError, BackendCloseOutcome, BackendNativeDisposition, Core, CoreError, Database,
    Operation, OwnerFailed, ResidentLease, StorageAdmission, StorageBackend, StorageError,
    TransactionError,
};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct UnlimitedAdmission;

impl StorageAdmission for UnlimitedAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn reserve_workspace(&self, _bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        Ok(Box::new(()))
    }

    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        Ok(())
    }

    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn owner_failed(&self) {}
}

#[derive(Clone, Copy)]
enum FailureMode {
    Before,
    After,
    TornDurable,
}

struct Fault {
    ordinal: usize,
    mode: FailureMode,
}

#[derive(Default)]
struct Image {
    volatile: Vec<u8>,
    durable: Vec<u8>,
    effects: usize,
    fault: Option<Fault>,
}

#[derive(Clone, Default)]
struct CrashBackend(Arc<Mutex<Image>>);

impl CrashBackend {
    fn crash(&self) -> Self {
        let bytes = self.0.lock().unwrap().durable.clone();
        Self(Arc::new(Mutex::new(Image {
            volatile: bytes.clone(),
            durable: bytes,
            ..Image::default()
        })))
    }

    fn inject(&self, ordinal: usize, mode: FailureMode) {
        let mut image = self.0.lock().unwrap();
        image.effects = 0;
        image.fault = Some(Fault { ordinal, mode });
    }

    fn effects(&self) -> usize {
        self.0.lock().unwrap().effects
    }

    fn corrupt_volatile(&self, needle: &[u8]) {
        let mut image = self.0.lock().unwrap();
        let at = image
            .volatile
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        image.volatile[at] ^= 0x80;
    }
}

impl StorageBackend for CrashBackend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().volatile.len() as u64)
    }

    fn read(&self, at: u64, out: &mut [u8]) -> io::Result<()> {
        let image = self.0.lock().unwrap();
        let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
        let end = start
            .checked_add(out.len())
            .ok_or(io::ErrorKind::InvalidInput)?;
        out.copy_from_slice(
            image
                .volatile
                .get(start..end)
                .ok_or(io::ErrorKind::UnexpectedEof)?,
        );
        Ok(())
    }

    fn write(&self, at: u64, input: &[u8]) -> io::Result<()> {
        let mut image = self.0.lock().unwrap();
        image.effects += 1;
        let fault = image
            .fault
            .as_ref()
            .filter(|fault| fault.ordinal == image.effects)
            .map(|fault| fault.mode);
        if matches!(fault, Some(FailureMode::Before)) {
            return Err(io::Error::other("injected write failure"));
        }
        let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
        let count = if matches!(fault, Some(FailureMode::TornDurable)) {
            input.len().div_ceil(2)
        } else {
            input.len()
        };
        let end = start
            .checked_add(count)
            .ok_or(io::ErrorKind::InvalidInput)?;
        image
            .volatile
            .get_mut(start..end)
            .ok_or(io::ErrorKind::UnexpectedEof)?
            .copy_from_slice(&input[..count]);
        if matches!(fault, Some(FailureMode::TornDurable)) {
            image.durable = image.volatile.clone();
        }
        if fault.is_some() {
            Err(io::Error::other("injected write failure"))
        } else {
            Ok(())
        }
    }

    fn set_len(&self, length: u64) -> io::Result<()> {
        let mut image = self.0.lock().unwrap();
        image.effects += 1;
        let fault = image
            .fault
            .as_ref()
            .filter(|fault| fault.ordinal == image.effects)
            .map(|fault| fault.mode);
        if matches!(fault, Some(FailureMode::Before)) {
            return Err(io::Error::other("injected resize failure"));
        }
        image.volatile.resize(
            usize::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?,
            0,
        );
        if matches!(fault, Some(FailureMode::TornDurable)) {
            image.durable = image.volatile.clone();
        }
        if fault.is_some() {
            Err(io::Error::other("injected resize failure"))
        } else {
            Ok(())
        }
    }

    fn sync_data(&self) -> io::Result<()> {
        let mut image = self.0.lock().unwrap();
        image.effects += 1;
        let fault = image
            .fault
            .as_ref()
            .filter(|fault| fault.ordinal == image.effects)
            .map(|fault| fault.mode);
        if !matches!(fault, Some(FailureMode::Before)) {
            image.durable = image.volatile.clone();
        }
        if fault.is_some() {
            Err(io::Error::other("injected sync failure"))
        } else {
            Ok(())
        }
    }

    fn close(&self) -> BackendCloseOutcome {
        BackendCloseOutcome::drained(Ok(()))
    }
}

fn admission() -> Arc<dyn StorageAdmission> {
    Arc::new(UnlimitedAdmission)
}

#[derive(Default)]
struct CheckpointAdmission {
    calls: AtomicUsize,
    fail_at: AtomicUsize,
}

struct SlotAdmission {
    live: Arc<AtomicUsize>,
    limit: usize,
}

struct SlotLease(Arc<AtomicUsize>);

impl Drop for SlotLease {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl SlotAdmission {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            live: Arc::new(AtomicUsize::new(0)),
            limit,
        })
    }
}

impl StorageAdmission for SlotAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn reserve_workspace(&self, _bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        let mut observed = self.live.load(Ordering::Acquire);
        loop {
            if observed >= self.limit {
                return Err(AdmissionError::CapacityDenied);
            }
            match self.live.compare_exchange(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Box::new(SlotLease(self.live.clone()))),
                Err(actual) => observed = actual,
            }
        }
    }

    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        Ok(())
    }

    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn owner_failed(&self) {}
}

impl StorageAdmission for CheckpointAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn reserve_workspace(&self, _bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        let fail_at = self.fail_at.load(Ordering::Acquire);
        if fail_at != 0 && call >= fail_at {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(Box::new(()))
        }
    }

    fn reserve_growth(&self, _current: u64, _requested: u64) -> Result<(), AdmissionError> {
        Ok(())
    }

    fn settle_growth(&self, _actual: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }

    fn owner_failed(&self) {}
}

fn baseline() -> (Core, CrashBackend) {
    let backend = CrashBackend::default();
    let core = Core::create_with_backend(backend.clone(), admission()).unwrap();
    core.commit(&[
        Operation::create_table("items"),
        Operation::put("items", b"a", b"old-a"),
        Operation::put("items", b"b", b"old-b"),
    ])
    .unwrap();
    (core, backend)
}

fn replacement() -> [Operation; 3] {
    [
        Operation::put("items", b"a", b"new-a"),
        Operation::delete("items", b"b"),
        Operation::put("items", b"c", b"new-c"),
    ]
}

fn churned() -> (Core, CrashBackend) {
    let (core, backend) = baseline();
    core.commit(&replacement()).unwrap();
    core.commit(&[
        Operation::put("items", b"a", b"last-a"),
        Operation::put("items", b"c", b"last-c"),
        Operation::put("items", b"temporary", b"scratch"),
    ])
    .unwrap();
    core.commit(&[Operation::delete("items", b"temporary")])
        .unwrap();
    (core, backend)
}

fn read(core: &Core, key: &[u8]) -> Option<Vec<u8>> {
    let view = core.snapshot().unwrap();
    core.get_admitted(&view, "items", key, 16)
        .unwrap()
        .map(|value| value.as_bytes().to_vec())
}

#[test]
fn every_failed_commit_effect_recovers_a_whole_generation() {
    let (counting_core, counting_backend) = baseline();
    counting_backend.inject(usize::MAX, FailureMode::Before);
    counting_core.commit(&replacement()).unwrap();
    let effect_count = counting_backend.effects();
    assert!(
        effect_count > 10,
        "expected to cover frame and header effects"
    );

    for ordinal in 1..=effect_count {
        for mode in [
            FailureMode::Before,
            FailureMode::After,
            FailureMode::TornDurable,
        ] {
            let (core, backend) = baseline();
            backend.inject(ordinal, mode);
            assert!(matches!(
                core.commit(&replacement()),
                Err(CoreError::UnknownCommit(_))
            ));
            let reopened = Core::open_with_backend(backend.crash(), admission()).unwrap();
            let observed = (
                read(&reopened, b"a"),
                read(&reopened, b"b"),
                read(&reopened, b"c"),
            );
            let old = (Some(b"old-a".to_vec()), Some(b"old-b".to_vec()), None);
            let new = (Some(b"new-a".to_vec()), None, Some(b"new-c".to_vec()));
            assert!(
                observed == old || observed == new,
                "partial batch after effect {ordinal}: {observed:?}"
            );
        }
    }
}

#[test]
fn closing_wakes_a_queued_writer_even_while_another_writer_is_held() {
    let database = Arc::new(
        Database::builder(admission())
            .create_with_backend(CrashBackend::default())
            .unwrap(),
    );
    let held_writer = database.begin_write().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let queued_database = database.clone();
    let queued = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        finished_tx.send(queued_database.begin_write()).unwrap();
    });
    started_rx.recv().unwrap();
    assert_eq!(
        database.close_native().native_disposition(),
        BackendNativeDisposition::Retained
    );
    let result = finished_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("queued writer should wake when close starts");
    assert!(matches!(
        result,
        Err(TransactionError(StorageError::DatabaseClosed))
    ));
    queued.join().unwrap();
    drop(held_writer);
    assert_eq!(
        database.close_native().native_disposition(),
        BackendNativeDisposition::Drained
    );
}

#[test]
fn detected_corruption_fences_preexisting_snapshots() {
    let (core, backend) = baseline();
    let view = core.snapshot().unwrap();
    backend.corrupt_volatile(b"old-a");
    assert!(matches!(
        core.get_admitted(&view, "items", b"a", 16),
        Err(CoreError::Corrupt(_))
    ));
    assert!(matches!(
        core.get_admitted(&view, "items", b"b", 16),
        Err(CoreError::OwnerFailed)
    ));
}

#[test]
fn midbatch_admission_denial_rolls_back_every_provisional_version() {
    let backend = CrashBackend::default();
    let admission = Arc::new(CheckpointAdmission::default());
    let core = Core::create_with_backend(backend.clone(), admission.clone()).unwrap();
    core.commit(&[
        Operation::create_table("items"),
        Operation::put("items", b"a", b"old-a"),
    ])
    .unwrap();
    let generation = core.generation().unwrap();
    let end = core.committed_end().unwrap();
    let effects = backend.effects();
    let start = admission.calls.load(Ordering::Acquire);
    // The first reserve admits undo space. The second happens only after
    // provisional versions cross the current 64 KiB index-credit chunk.
    admission.fail_at.store(start + 2, Ordering::Release);
    let mut batch = vec![
        Operation::put("items", b"a", b"middle"),
        Operation::put("items", b"a", b"new-a"),
    ];
    for index in 0..140u16 {
        batch.push(Operation::put(
            "items",
            format!("b{index:04}").into_bytes(),
            b"new-b",
        ));
    }
    assert!(matches!(
        core.commit(&batch),
        Err(CoreError::CapacityDenied)
    ));
    assert!(admission.calls.load(Ordering::Acquire) >= start + 3);
    assert_eq!(backend.effects(), effects);
    assert_eq!(core.generation().unwrap(), generation);
    assert_eq!(core.committed_end().unwrap(), end);
    admission.fail_at.store(0, Ordering::Release);
    assert_eq!(read(&core, b"a"), Some(b"old-a".to_vec()));
    assert_eq!(read(&core, b"b0000"), None);

    core.commit(&batch).unwrap();
    assert_eq!(read(&core, b"a"), Some(b"new-a".to_vec()));
    assert_eq!(read(&core, b"b0000"), Some(b"new-b".to_vec()));
    assert_eq!(read(&core, b"b0139"), Some(b"new-b".to_vec()));
    let reopened = Core::open_with_backend(backend.crash(), admission).unwrap();
    assert_eq!(read(&reopened, b"a"), Some(b"new-a".to_vec()));
    assert_eq!(read(&reopened, b"b0000"), Some(b"new-b".to_vec()));
    assert_eq!(read(&reopened, b"b0139"), Some(b"new-b".to_vec()));
}

#[test]
fn every_failed_compaction_effect_reopens_all_live_values() {
    let (counting_core, counting_backend) = churned();
    let before_end = counting_core.committed_end().unwrap();
    counting_backend.inject(usize::MAX, FailureMode::Before);
    counting_core.compact().unwrap();
    assert!(counting_core.committed_end().unwrap() < before_end);
    let effect_count = counting_backend.effects();
    assert!(effect_count > 10, "expected shadow and front copy effects");

    for ordinal in 1..=effect_count {
        for mode in [
            FailureMode::Before,
            FailureMode::After,
            FailureMode::TornDurable,
        ] {
            let (core, backend) = churned();
            backend.inject(ordinal, mode);
            assert!(core.compact().is_err());
            let reopened = Core::open_with_backend(backend.crash(), admission())
                .unwrap_or_else(|error| panic!("reopen after effect {ordinal} failed: {error}"));
            assert_eq!(read(&reopened, b"a"), Some(b"last-a".to_vec()));
            assert_eq!(read(&reopened, b"b"), None);
            assert_eq!(read(&reopened, b"c"), Some(b"last-c".to_vec()));
            assert_eq!(read(&reopened, b"temporary"), None);
        }
    }
}

#[test]
fn many_live_keys_share_bounded_admission_slots_and_reopen() {
    let backend = CrashBackend::default();
    let admission = SlotAdmission::new(128);
    let core = Core::create_with_backend(backend.clone(), admission.clone()).unwrap();
    core.commit(&[Operation::create_table("items")]).unwrap();
    let mut operations = Vec::new();
    for index in 0..500u16 {
        operations.push(Operation::put(
            "items",
            format!("{index:04}").into_bytes(),
            vec![index as u8],
        ));
    }
    core.commit(&operations).unwrap();
    assert!(admission.live.load(Ordering::Acquire) <= 128);
    let crash = backend.crash();
    drop(core);
    assert_eq!(admission.live.load(Ordering::Acquire), 0);

    let reopened = Core::open_with_backend(crash, SlotAdmission::new(128)).unwrap();
    for index in [0u16, 249, 499] {
        assert_eq!(
            read(&reopened, format!("{index:04}").as_bytes()),
            Some(vec![index as u8])
        );
    }
}
