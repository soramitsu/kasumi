//! Real public transactions drive the native writer, root publication and retained
//! outcome. The image backend has explicit synthetic (no filesystem quota) claim
//! semantics; these tests qualify orchestration, never installed quota accounting.
use super::*;
use crate::cache::CacheConfig;
use crate::group::{FileKind, InMemoryGroup, TransactionReserveError, TransactionSpacePlan};
use crate::root::{RootSelection, select_root};

const GROUP: [u8; 16] = [184; 16];
const ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("claim-accounts");
const OLD: &[u8] = b"old account version";
const NEW: &[u8] = b"new account version";

#[derive(Default)]
struct Admission {
    failed: AtomicBool,
    deny_next: AtomicBool,
    denials: AtomicUsize,
}
impl StorageAdmission for Admission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_workspace(&self, _: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if self.deny_next.swap(false, Ordering::AcqRel) {
            self.denials.fetch_add(1, Ordering::AcqRel);
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(Box::new(()))
        }
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        self.check_owner().map_err(|_| AdmissionError::OwnerFailed)
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        self.check_owner()
    }
    fn owner_failed(&self) {
        self.failed.store(true, Ordering::Release);
    }
    fn quote_cache_memory(&self, bytes: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
}
impl crate::cache_test::Provider for Admission {
    fn acquire_cache(&self, _: u64, _: bool) -> Result<(), AdmissionError> {
        self.check_owner().map_err(|_| AdmissionError::OwnerFailed)
    }
    fn release_cache(&self, _: u64, _: bool) {}
}

#[derive(Default)]
enum ReserveAction {
    #[default]
    Admit,
    Refuse,
    Fail(io::Error),
}
struct Control {
    group: InMemoryGroup,
    admission: Arc<Admission>,
    reserve: Mutex<ReserveAction>,
    write_error: Mutex<Option<io::Error>>,
    finish_error: Mutex<Option<io::Error>>,
    deny_after_prepare: AtomicBool,
    active: Mutex<Option<TransactionSpacePlan>>,
    reserves: AtomicUsize,
    finishes: AtomicUsize,
    cancels: AtomicUsize,
    effects: AtomicUsize,
    closes: AtomicUsize,
    // Actual durable selected batch observed when native calls finish.
    finished: Mutex<Vec<(u64, u64)>>,
}
#[derive(Clone)]
struct Backend(Arc<Control>);
impl Backend {
    fn new(group: InMemoryGroup) -> Self {
        Self(Arc::new(Control {
            group,
            admission: Arc::new(Admission::default()),
            reserve: Mutex::new(ReserveAction::Admit),
            write_error: Mutex::new(None),
            finish_error: Mutex::new(None),
            deny_after_prepare: AtomicBool::new(false),
            active: Mutex::new(None),
            reserves: AtomicUsize::new(0),
            finishes: AtomicUsize::new(0),
            cancels: AtomicUsize::new(0),
            effects: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            finished: Mutex::new(Vec::new()),
        }))
    }
    fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.0.reserves.load(Ordering::Acquire),
            self.0.finishes.load(Ordering::Acquire),
            self.0.cancels.load(Ordering::Acquire),
            self.0.effects.load(Ordering::Acquire),
        )
    }
    fn effect(&self) {
        self.0.effects.fetch_add(1, Ordering::AcqRel);
    }
    fn selected_batch(&self) -> u64 {
        // Inspect only a restarted copy of already durable bytes. select_root
        // synchronizes its input; observing the original would incorrectly
        // supply a missing production root sync and conceal that regression.
        let RootSelection::Selected {
            superblock,
            mirrored,
            ..
        } = select_root(&self.0.group.crash()).unwrap()
        else {
            panic!("native initialized root missing");
        };
        assert!(mirrored);
        superblock
            .directory()
            .map_or(0, |commit| commit.start.batch_seq)
    }
    fn validate_consumed_prefix(&self, plan: &TransactionSpacePlan) {
        for existing in plan.segment.into_iter().chain(plan.directory) {
            let len = self.0.group.len(existing.file).unwrap();
            assert!((existing.initial_len..=existing.maximum_len).contains(&len));
        }
        for (range, kind) in [
            (plan.new_segments, FileKind::Segment),
            (plan.new_directories, FileKind::Directory),
        ] {
            let mut count = 0;
            let mut sum = 0;
            for offset in 0..range.count {
                let file = GroupFile {
                    kind,
                    id: range.first_id + offset,
                };
                if self.0.group.exists(file).unwrap() {
                    assert_eq!(offset, count, "created prefix cannot contain a hole");
                    let len = self.0.group.len(file).unwrap();
                    assert!(
                        (range.minimum_len..=range.maximum_len(file.id).unwrap()).contains(&len)
                    );
                    assert_eq!(self.0.group.durable_len(file), Some(len as usize));
                    count += 1;
                    sum += len;
                }
            }
            assert!(sum <= range.total_len);
        }
    }
}
impl SegmentGroupBackend for Backend {
    fn reserve_transaction(
        &self,
        plan: &TransactionSpacePlan,
    ) -> Result<(), TransactionReserveError> {
        self.0.reserves.fetch_add(1, Ordering::AcqRel);
        match std::mem::take(&mut *self.0.reserve.lock().unwrap()) {
            ReserveAction::Refuse => return Err(TransactionReserveError::CapacityDenied),
            ReserveAction::Fail(error) => return Err(TransactionReserveError::Failed(error)),
            ReserveAction::Admit => {}
        }
        self.0.group.reserve_transaction(plan)?;
        assert!(self.0.active.lock().unwrap().replace(*plan).is_none());
        Ok(())
    }
    fn finish_transaction(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.0.finishes.fetch_add(1, Ordering::AcqRel);
        let plan = self
            .0
            .active
            .lock()
            .unwrap()
            .expect("native claim remains owned");
        assert_eq!((group, batch), (plan.group_id, plan.batch_seq));
        self.validate_consumed_prefix(&plan);
        self.0
            .finished
            .lock()
            .unwrap()
            .push((batch, self.selected_batch()));
        if let Some(error) = self.0.finish_error.lock().unwrap().take() {
            return Err(error);
        }
        self.0.group.finish_transaction(group, batch)?;
        self.0.active.lock().unwrap().take();
        Ok(())
    }
    fn cancel_transaction(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.0.cancels.fetch_add(1, Ordering::AcqRel);
        self.0.group.cancel_transaction(group, batch)?;
        let plan = self
            .0
            .active
            .lock()
            .unwrap()
            .take()
            .expect("native claim cancelled");
        assert_eq!((group, batch), (plan.group_id, plan.batch_seq));
        Ok(())
    }
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.0.group.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.effect();
        self.0.group.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.0.group.sync_root()
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.0.group.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.0.group.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.effect();
        self.0.group.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.0.group.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.group.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.effect();
        self.0.group.write(file, at, bytes)?;
        // Return the original error only after the actual image accepted bytes.
        if let Some(error) = self.0.write_error.lock().unwrap().take() {
            return Err(error);
        }
        Ok(())
    }
    fn set_len(&self, file: GroupFile, len: u64) -> io::Result<()> {
        assert!(
            self.0.active.lock().unwrap().is_none(),
            "physical rollback must follow claim settlement"
        );
        self.effect();
        self.0.group.set_len(file, len)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.0.group.sync(file)?;
        // Seeded tests append to an existing segment: this is the actual
        // operation-prefix sync, after mandatory write workspace admission.
        if file.kind == FileKind::Segment && self.0.deny_after_prepare.swap(false, Ordering::AcqRel)
        {
            self.0.admission.deny_next.store(true, Ordering::Release);
        }
        Ok(())
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.effect();
        self.0.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.0.group.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.0.closes.fetch_add(1, Ordering::AcqRel);
        self.0.group.close()
    }
}

fn opening(backend: &Backend, mode: DatabaseOpenMode) -> RetainedDatabaseOpening {
    let mut opening = Database::builder(
        backend.0.admission.clone(),
        GROUP,
        CacheConfig { byte_limit: 0 },
    )
    .retain_backend(Box::new(backend.clone()), mode);
    assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
    opening
}
fn fixture() -> (RetainedDatabaseOpening, Backend) {
    let backend = Backend::new(InMemoryGroup::new());
    let opening = opening(&backend, DatabaseOpenMode::Create);
    let mut writer = staged(&opening, OLD);
    assert!(matches!(
        writer.commit().terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(
        writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    assert!(backend.0.active.lock().unwrap().is_none());
    (opening, backend)
}
fn staged(opening: &RetainedDatabaseOpening, value: &[u8]) -> RetainedWriteTransaction {
    let writer = opening.database().unwrap().begin_write().unwrap();
    writer
        .open_table(ROWS)
        .unwrap()
        .insert(b"account".as_slice(), value)
        .unwrap();
    writer.retain()
}
fn read(database: &Database) -> Vec<u8> {
    let transaction = database.begin_read().unwrap();
    let table = transaction.open_table(ROWS).unwrap();
    let value = table.get(b"account".as_slice()).unwrap().unwrap();
    value.value().to_vec()
}
fn assert_reopened(group: &InMemoryGroup, expected: &[u8]) {
    let backend = Backend::new(group.crash());
    let mut reopened = opening(&backend, DatabaseOpenMode::Existing);
    assert_eq!(read(reopened.database().unwrap()), expected);
    assert_eq!(
        reopened.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
}
fn image(group: &InMemoryGroup) -> (Vec<u8>, Vec<(GroupFile, Vec<u8>)>) {
    let mut roots = Vec::new();
    for slot in [RootSlot::A, RootSlot::B] {
        let mut bytes = [0; ROOT_SLOT_BYTES];
        group.read_root(slot, &mut bytes).unwrap();
        roots.extend_from_slice(&bytes);
    }
    let mut files = Vec::new();
    for name in group.entries().unwrap() {
        if let Some(file) = name.to_str().and_then(GroupFile::parse_name) {
            files.push((file, group.durable_image(file).unwrap()));
        }
    }
    files.sort_by_key(|(file, _)| *file);
    (roots, files)
}
#[derive(Debug)]
struct NativeMarker(&'static str);
impl fmt::Display for NativeMarker {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.0)
    }
}
impl std::error::Error for NativeMarker {}
fn error_at(phase: &'static str) -> (io::Error, usize) {
    let error = io::Error::new(io::ErrorKind::StorageFull, NativeMarker(phase));
    let address = error.get_ref().unwrap() as *const _ as *const () as usize;
    (error, address)
}
fn assert_original(writer: &RetainedWriteTransaction, address: usize, unknown: bool) {
    let report = writer.report();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Retained);
    assert!(!report.is_capacity_denied());
    assert!(report.rejected_no_effect().is_none());
    let TerminalObservation::Returned(Err(WriteTerminalError::Commit(CommitError(error)))) =
        report.terminal()
    else {
        panic!("original commit error missing");
    };
    let original = match (unknown, error) {
        (true, StorageError::UnknownCommit(original)) | (false, StorageError::Io(original)) => {
            original
        }
        _ => panic!("wrong error identity: {error:?}"),
    };
    assert_eq!(original.kind(), io::ErrorKind::StorageFull);
    assert_eq!(
        original.get_ref().unwrap() as *const _ as *const () as usize,
        address
    );
}
fn assert_retained_no_retry(
    opening: &mut RetainedDatabaseOpening,
    backend: &Backend,
    writer: &mut RetainedWriteTransaction,
    address: usize,
    unknown: bool,
) {
    let counts = backend.counts();
    assert!(backend.0.admission.failed.load(Ordering::Acquire));
    assert!(opening.database().unwrap().begin_read().is_err());
    for _ in 0..2 {
        writer.commit();
        assert_original(writer, address, unknown);
        assert!(
            !writer
                .dispose_settled(opening.retained_database().unwrap())
                .disposal_complete()
        );
        assert_eq!(backend.counts(), counts);
    }
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    assert_eq!(backend.0.closes.load(Ordering::Acquire), 0);
}

#[test]
fn transaction_claim_activation_typed_refusal_is_pristine_settled_and_retryable() {
    let (mut opening, backend) = fixture();
    let before = image(&backend.0.group);
    let counts = backend.counts();
    *backend.0.reserve.lock().unwrap() = ReserveAction::Refuse;
    let mut writer = staged(&opening, NEW);
    let report = writer.commit();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(report.is_capacity_denied());
    assert!(matches!(report.rollback(), TerminalObservation::NotEntered));
    assert!(
        writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    assert_eq!(
        backend.counts(),
        (counts.0 + 1, counts.1, counts.2, counts.3)
    );
    assert_eq!(image(&backend.0.group), before);
    assert!(backend.0.active.lock().unwrap().is_none());
    assert!(!backend.0.admission.failed.load(Ordering::Acquire));
    assert_eq!(read(opening.database().unwrap()), OLD);
    assert_reopened(&backend.0.group, OLD);
    let mut retry = staged(&opening, NEW);
    assert!(matches!(
        retry.commit().terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(
        retry
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    assert_eq!(read(opening.database().unwrap()), NEW);
    assert_reopened(&backend.0.group, NEW);
    assert_eq!(
        opening.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
}

#[test]
fn transaction_claim_activation_raw_reserve_storage_full_is_not_capacity_and_retains_original() {
    let (mut opening, backend) = fixture();
    let before = image(&backend.0.group);
    let counts = backend.counts();
    let (error, address) = error_at("reserve observation");
    *backend.0.reserve.lock().unwrap() = ReserveAction::Fail(error);
    let mut writer = staged(&opening, NEW);
    writer.commit();
    assert_original(&writer, address, false);
    assert_eq!(
        backend.counts(),
        (counts.0 + 1, counts.1, counts.2, counts.3)
    );
    assert_eq!(image(&backend.0.group), before);
    assert_retained_no_retry(&mut opening, &backend, &mut writer, address, false);
    assert_reopened(&backend.0.group, OLD);
    std::mem::forget((opening, writer));
}

#[test]
fn transaction_claim_activation_raw_write_storage_full_keeps_entered_claim_and_original() {
    let (mut opening, backend) = fixture();
    let counts = backend.counts();
    let (error, address) = error_at("after operation write");
    *backend.0.write_error.lock().unwrap() = Some(error);
    let mut writer = staged(&opening, NEW);
    writer.commit();
    assert_original(&writer, address, false);
    assert!(backend.0.active.lock().unwrap().is_some());
    assert_eq!(backend.0.finishes.load(Ordering::Acquire), counts.1);
    assert_eq!(backend.0.cancels.load(Ordering::Acquire), counts.2);
    assert!(backend.0.effects.load(Ordering::Acquire) > counts.3);
    assert_retained_no_retry(&mut opening, &backend, &mut writer, address, false);
    assert_reopened(&backend.0.group, OLD);
    std::mem::forget((opening, writer));
}

#[test]
fn transaction_claim_activation_success_settles_once_after_durable_selection_and_preserves_snapshot()
 {
    let (mut opening, backend) = fixture();
    let old = opening.database().unwrap().begin_read().unwrap();
    let counts = backend.counts();
    let mut writer = staged(&opening, NEW);
    let report = writer.commit();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    let (claimed, selected) = *backend.0.finished.lock().unwrap().last().unwrap();
    assert_eq!(claimed, selected);
    assert_eq!(backend.0.finishes.load(Ordering::Acquire), counts.1 + 1);
    assert_eq!(backend.0.cancels.load(Ordering::Acquire), counts.2);
    assert!(backend.0.active.lock().unwrap().is_none());
    assert!(
        writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    let table = old.open_table(ROWS).unwrap();
    assert_eq!(
        table.get(b"account".as_slice()).unwrap().unwrap().value(),
        OLD
    );
    drop(table);
    drop(old);
    assert_eq!(read(opening.database().unwrap()), NEW);
    assert_reopened(&backend.0.group, NEW);
    assert_eq!(
        opening.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
}

#[test]
fn transaction_claim_activation_prepared_workspace_survives_postprepare_memory_pressure() {
    let (mut opening, backend) = fixture();
    let selected = backend.selected_batch();
    let counts = backend.counts();
    let mut writer = staged(&opening, NEW);
    backend.0.deny_after_prepare.store(true, Ordering::Release);
    let report = writer.commit();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(matches!(
        report.terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(!backend.0.deny_after_prepare.load(Ordering::Acquire));
    assert!(backend.0.admission.deny_next.load(Ordering::Acquire));
    assert_eq!(backend.0.admission.denials.load(Ordering::Acquire), 0);
    assert_eq!(backend.0.finishes.load(Ordering::Acquire), counts.1 + 1);
    assert_eq!(backend.0.cancels.load(Ordering::Acquire), counts.2);
    let (claimed, at_settlement) = *backend.0.finished.lock().unwrap().last().unwrap();
    assert!(claimed > selected);
    assert_eq!(at_settlement, claimed);
    assert!(backend.0.active.lock().unwrap().is_none());
    assert!(!backend.0.admission.failed.load(Ordering::Acquire));
    assert!(
        writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    // The armed refusal was never consumed during durable publication. Release
    // that competing pressure before subsequent reads acquire their own work.
    backend
        .0
        .admission
        .deny_next
        .store(false, Ordering::Release);
    assert_eq!(read(opening.database().unwrap()), NEW);
    assert_reopened(&backend.0.group, NEW);
    assert_eq!(
        opening.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
}

#[test]
fn transaction_claim_activation_preparation_memory_refusal_precedes_claim_and_retries() {
    let (mut opening, backend) = fixture();
    let before = image(&backend.0.group);
    let counts = backend.counts();
    let selected = backend.selected_batch();
    let mut writer = staged(&opening, NEW);
    backend.0.admission.deny_next.store(true, Ordering::Release);
    let report = writer.commit();
    assert_eq!(report.settlement(), WriteTerminalSettlement::Settled);
    assert!(report.is_capacity_denied());
    assert_eq!(backend.0.admission.denials.load(Ordering::Acquire), 1);
    assert_eq!(backend.counts(), counts);
    assert!(backend.0.active.lock().unwrap().is_none());
    assert!(!backend.0.admission.failed.load(Ordering::Acquire));
    assert_eq!(
        image(&backend.0.group),
        before,
        "refusal precedes private effects"
    );
    assert!(
        writer
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    assert_reopened(&backend.0.group, OLD);
    let mut retry = staged(&opening, NEW);
    assert!(matches!(
        retry.commit().terminal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(
        retry
            .dispose_settled(opening.retained_database().unwrap())
            .disposal_complete()
    );
    let (claimed, at_settlement) = *backend.0.finished.lock().unwrap().last().unwrap();
    assert!(claimed > selected);
    assert_eq!(claimed, at_settlement);
    assert_eq!(read(opening.database().unwrap()), NEW);
    assert_reopened(&backend.0.group, NEW);
    assert_eq!(
        opening.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
}

#[test]
fn transaction_claim_activation_postcommit_finish_error_is_unknown_and_reopens_new_version() {
    let (mut opening, backend) = fixture();
    let counts = backend.counts();
    let (error, address) = error_at("postcommit claim settlement");
    *backend.0.finish_error.lock().unwrap() = Some(error);
    let mut writer = staged(&opening, NEW);
    writer.commit();
    assert_original(&writer, address, true);
    assert_eq!(backend.0.finishes.load(Ordering::Acquire), counts.1 + 1);
    let (claimed, selected) = *backend.0.finished.lock().unwrap().last().unwrap();
    assert_eq!(
        claimed, selected,
        "durable selection precedes uncertain physical settlement"
    );
    assert!(backend.0.active.lock().unwrap().is_some());
    assert_retained_no_retry(&mut opening, &backend, &mut writer, address, true);
    assert_reopened(&backend.0.group, NEW);
    std::mem::forget((opening, writer));
}
