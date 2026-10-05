//! Actual encrypted backend uses its prepared workspace under late slot pressure.
use super::*;
use crate::{DiskMemoryLease, NodeDiskMemoryAdmission, test_utils::TestDiskMemory};
use std::sync::Mutex;

const RESERVATIONS: usize = 32;

struct SlotPressure {
    memory: Arc<TestDiskMemory>,
    armed: AtomicBool,
    entered: AtomicBool,
    blockers: Mutex<[Option<DiskMemoryLease>; RESERVATIONS]>,
    _charge: DiskMemoryLease,
}

impl SlotPressure {
    fn new(memory: Arc<TestDiskMemory>) -> Arc<Self> {
        let charge = memory
            .clone()
            .reserve_installed(crate::disk_memory::arc::<Self>().unwrap())
            .unwrap();
        Arc::new(Self {
            memory,
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            blockers: Mutex::new(std::array::from_fn(|_| None)),
            _charge: charge,
        })
    }

    fn after_segment_sync(&self) {
        if !self.armed.swap(false, Ordering::AcqRel) {
            return;
        }
        self.occupy_remaining();
        self.entered.store(true, Ordering::Release);
    }

    fn occupy_remaining(&self) {
        // A competing owner takes only currently unused slots under the same
        // installed provider and unchanged capacity bounds.
        let mut blockers = self.blockers.lock().unwrap();
        let remaining = RESERVATIONS - self.memory.snapshot().live_reservations;
        assert!(remaining > 0);
        for slot in &mut blockers[..remaining] {
            assert!(slot.is_none());
            *slot = Some(self.memory.clone().reserve_installed(0).unwrap());
        }
        assert_eq!(self.memory.snapshot().live_reservations, RESERVATIONS);
    }

    fn release(&self) {
        for slot in self.blockers.lock().unwrap().iter_mut() {
            drop(slot.take());
        }
    }
}

struct PressuredBackend {
    backend: Backend,
    pressure: Arc<SlotPressure>,
}

impl SegmentGroupBackend for PressuredBackend {
    fn reserve_transaction(
        &self,
        plan: &kasumi_kv::TransactionSpacePlan,
    ) -> Result<(), kasumi_kv::TransactionReserveError> {
        self.backend.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.backend.finish_transaction(group, batch)
    }
    fn cancel_transaction(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.backend.cancel_transaction(group, batch)
    }
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.backend.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.backend.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.backend.sync_root()
    }
    fn visit_entries(
        &self,
        visitor: &mut dyn FnMut(&std::ffi::OsStr) -> io::Result<()>,
    ) -> io::Result<()> {
        self.backend.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.backend.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.backend.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.backend.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.backend.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.backend.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.backend.set_len(file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.backend.sync(file)?;
        if file == DATA {
            self.pressure.after_segment_sync();
        }
        Ok(())
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.backend.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.backend.sync_names()
    }
    fn close(&self) -> kasumi_kv::BackendCloseOutcome {
        self.backend.close()
    }
}

#[test]
fn scratch_prepared_workspace_survives_capacity_pressure_after_prepare() {
    let memory = TestDiskMemory::new(64 << 20, RESERVATIONS);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let pressure = SlotPressure::new(memory.clone());
    let (owner, backend) = owner(&disk, 8 << 20);
    let database = kasumi_kv::Database::builder(owner.clone(), GROUP, CACHE)
        .create_with_backend(PressuredBackend {
            backend: backend.clone(),
            pressure: pressure.clone(),
        })
        .unwrap();
    assert!(!backend.exists(DATA).unwrap());
    let tx = database.begin_write().unwrap();
    drop(tx.open_table(TABLE).unwrap());
    pressure.armed.store(true, Ordering::Release);
    tx.commit().unwrap();
    assert!(pressure.entered.load(Ordering::Acquire));
    // The real private segment was synchronized before pressure occupied every
    // remaining slot. Directory publication uses only its admitted workspace.
    assert!(backend.exists(DATA).unwrap());
    owner.check_owner().unwrap();
    let pressured = memory.snapshot();
    assert!(pressured.used_bytes + pressured.bookkeeping_bytes < 64 << 20);
    pressure.release();
    assert!(database.begin_read().unwrap().open_table(TABLE).is_ok());
    // Continue through the same database after the competing
    // owner retires its actual leases. No cap, slot count, or deadline changes.
    let tx = database.begin_write().unwrap();
    tx.open_table(TABLE)
        .unwrap()
        .insert(b"retry".as_slice(), b"committed".as_slice())
        .unwrap();
    tx.commit().unwrap();
    {
        let read = database.begin_read().unwrap();
        let table = read.open_table(TABLE).unwrap();
        assert_eq!(table.get(b"retry").unwrap().unwrap().value(), b"committed");
    }
    let closed = database.close_native();
    assert_eq!(
        closed.native_disposition(),
        BackendNativeDisposition::Drained
    );
    closed.into_result().unwrap();
    assert!(owner.drained());
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}

#[test]
fn scratch_preparation_capacity_refusal_has_no_private_effect_and_retries() {
    let memory = TestDiskMemory::new(64 << 20, RESERVATIONS);
    let directory = crate::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let pressure = SlotPressure::new(memory.clone());
    let (owner, backend) = owner(&disk, 8 << 20);
    let database = kasumi_kv::Database::builder(owner.clone(), GROUP, CACHE)
        .create_with_backend(PressuredBackend {
            backend: backend.clone(),
            pressure: pressure.clone(),
        })
        .unwrap();
    let tx = database.begin_write().unwrap();
    drop(tx.open_table(TABLE).unwrap());
    pressure.occupy_remaining();
    let error = tx.commit().unwrap_err();
    assert!(
        error.0.is_capacity_denied(),
        "unexpected commit error: {error}"
    );
    assert!(
        !backend.exists(DATA).unwrap(),
        "refusal must precede private segment creation"
    );
    owner.check_owner().unwrap();
    pressure.release();
    assert!(matches!(
        database.begin_read().unwrap().open_table(TABLE),
        Err(kasumi_kv::TableError::DoesNotExist(_))
    ));
    let tx = database.begin_write().unwrap();
    tx.open_table(TABLE)
        .unwrap()
        .insert(b"retry".as_slice(), b"committed".as_slice())
        .unwrap();
    tx.commit().unwrap();
    {
        let read = database.begin_read().unwrap();
        let table = read.open_table(TABLE).unwrap();
        assert_eq!(table.get(b"retry").unwrap().unwrap().value(), b"committed");
    }
    let closed = database.close_native();
    assert_eq!(
        closed.native_disposition(),
        BackendNativeDisposition::Drained
    );
    closed.into_result().unwrap();
    assert!(owner.drained());
    assert_eq!(disk.snapshot().live_files, 0);
    assert_eq!(disk.snapshot().charged_bytes, 0);
}
