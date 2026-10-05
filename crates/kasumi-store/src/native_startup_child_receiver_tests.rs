//! Real closed Tables/Verification construction, under their opening parent.
use super::*;
use crate::{
    DiskMemoryLease, NativeConstructorReport, NodeDiskMemoryAdmission, StorageCensus, disk_memory,
    test_utils::{TestDiskMemory, node_storage_config, private_tempdir, retry_disk_registry},
};
use kasumi_kv::TerminalObservation;
use std::{
    any::Any,
    fmt,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::Duration,
};

const LIMIT: u64 = 64 << 20;
const CAPACITY: usize = 16;
const ID: Uuid = Uuid::from_u128(0x7806_283c_5591_4d94_8dd4_3ff8_5bd1_9148);
const WAIT: Duration = Duration::from_secs(5);
type OriginalPanic = Box<dyn Any + Send>;

#[derive(Clone, Copy)]
enum Mode {
    Success,
    Error,
    Panic,
    HoldPublication,
}
#[derive(Debug)]
struct Marker(u64);
struct Diagnostic(Arc<AtomicUsize>);
impl fmt::Debug for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("original startup child provider error")
    }
}
impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
impl std::error::Error for Diagnostic {}
impl Drop for Diagnostic {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}
struct Token {
    backing: Option<DiskMemoryLease>,
    drops: Arc<AtomicUsize>,
}
impl Drop for Token {
    fn drop(&mut self) {
        drop(self.backing.take());
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
struct HoldRequest {
    entered: mpsc::Sender<StorageOwnerId>,
    held: mpsc::Receiver<()>,
}
struct Memory {
    census: StorageCensus,
    backing: Arc<TestDiskMemory>,
    mode: Mode,
    calls: AtomicUsize,
    fault_call: AtomicUsize,
    tracking: AtomicBool,
    parent: Mutex<Option<StorageOwnerId>>,
    prior: Mutex<[Option<StorageOwnerId>; CAPACITY]>,
    child: Mutex<Option<StorageOwnerId>>,
    metadata_observations: AtomicUsize,
    token_drops: Arc<AtomicUsize>,
    diagnostic_drops: Arc<AtomicUsize>,
    original_error: Mutex<Option<io::Error>>,
    original_panic: Mutex<Option<OriginalPanic>>,
    hold: Mutex<Option<HoldRequest>>,
    // All concrete fixture/census/diagnostic allocations precede this lease's
    // retirement. Callback tokens have a separate actual quote and grant.
    _bookkeeping: DiskMemoryLease,
}
impl Memory {
    fn new(mode: Mode) -> Arc<Self> {
        let backing = TestDiskMemory::new(LIMIT, 64);
        let mut bytes = disk_memory::add(
            StorageCensus::required_bytes(CAPACITY).unwrap(),
            disk_memory::arc::<Self>().unwrap(),
        )
        .unwrap();
        for allocation in [
            disk_memory::arc::<AtomicUsize>().unwrap(),
            disk_memory::arc::<AtomicUsize>().unwrap(),
            disk_memory::allocation::<Diagnostic>(1).unwrap(),
            disk_memory::allocation::<[usize; 16]>(1).unwrap(),
            disk_memory::allocation::<Marker>(1).unwrap(),
        ] {
            bytes = disk_memory::add(bytes, allocation).unwrap();
        }
        let bookkeeping = backing.clone().reserve_installed(bytes).unwrap();
        let token_drops = Arc::new(AtomicUsize::new(0));
        let diagnostic_drops = Arc::new(AtomicUsize::new(0));
        let original_error = io::Error::other(Diagnostic(diagnostic_drops.clone()));
        let owner = Arc::new(Self {
            census: StorageCensus::allocate(CAPACITY).unwrap(),
            backing,
            mode,
            calls: AtomicUsize::new(0),
            fault_call: AtomicUsize::new(0),
            tracking: AtomicBool::new(false),
            parent: Mutex::new(None),
            prior: Mutex::new([None; CAPACITY]),
            child: Mutex::new(None),
            metadata_observations: AtomicUsize::new(0),
            token_drops,
            diagnostic_drops,
            original_error: Mutex::new(Some(original_error)),
            original_panic: Mutex::new(Some(Box::new(Marker(907)))),
            hold: Mutex::new(None),
            _bookkeeping: bookkeeping,
        });
        let provider = owner.provider();
        owner.census.bind_provider(&provider).unwrap();
        owner
    }
    fn provider(self: &Arc<Self>) -> Arc<dyn NodeDiskMemoryAdmission> {
        self.clone()
    }
    fn arm(&self, parent: StorageOwnerId, offset: usize) -> usize {
        assert!(!self.tracking.swap(true, Ordering::AcqRel));
        *self.parent.lock().unwrap() = Some(parent);
        let mut prior = self.prior.lock().unwrap();
        for (index, id) in prior.iter_mut().enumerate() {
            *id = self.census.owner_at(index);
        }
        let before = self.calls.load(Ordering::Acquire);
        self.fault_call.store(before + offset, Ordering::Release);
        before
    }
    fn child(&self) -> StorageOwnerId {
        self.child.lock().unwrap().expect("actual claimed child ID")
    }
    fn inspect_claimed_metadata(&self) {
        let parent = self.parent.lock().unwrap().unwrap();
        assert_eq!(self.census.child_count_for_test(parent), Some(1));
        let prior = self.prior.lock().unwrap();
        let child = (0..CAPACITY)
            .filter_map(|index| self.census.owner_at(index))
            .find(|id| !prior.contains(&Some(*id)))
            .expect("actual claimed child metadata is available during provider dispatch");
        let mut recorded = self.child.lock().unwrap();
        if let Some(original) = *recorded {
            assert_eq!(child, original);
        } else {
            *recorded = Some(child);
        }
        self.metadata_observations.fetch_add(1, Ordering::AcqRel);
    }
    fn diagnostic_address(&self) -> usize {
        let original = self.original_error.lock().unwrap();
        let diagnostic = original
            .as_ref()
            .unwrap()
            .get_ref()
            .unwrap()
            .downcast_ref::<Diagnostic>()
            .unwrap();
        std::ptr::from_ref(diagnostic) as usize
    }
    fn panic_address(&self) -> usize {
        let original = self.original_panic.lock().unwrap();
        let marker = original.as_ref().unwrap().downcast_ref::<Marker>().unwrap();
        assert_eq!(marker.0, 907);
        std::ptr::from_ref(marker) as usize
    }
}
impl kasumi_kv::SourceMemoryProvider for Memory {}
impl NodeDiskMemoryAdmission for Memory {
    fn storage_census(&self) -> &StorageCensus {
        &self.census
    }
    fn reserve_installed(self: Arc<Self>, bytes: u64) -> io::Result<DiskMemoryLease> {
        self.backing.clone().reserve_installed(bytes)
    }
    fn install_native_constructor(
        self: Arc<Self>,
        install: &mut crate::NativeConstructorInstall<'_>,
    ) -> io::Result<()> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if self.tracking.load(Ordering::Acquire) {
            self.inspect_claimed_metadata();
        }
        let permit = install.try_begin_bind(self.provider()).unwrap();
        let bytes = disk_memory::add(
            permit.request_bytes(),
            DiskMemoryLease::token_allocation_bytes::<Token>()?,
        )?;
        let backing = match self.backing.clone().reserve_installed(bytes) {
            Ok(backing) => backing,
            Err(original) if original.kind() == io::ErrorKind::OutOfMemory => {
                return Err(permit.refuse_capacity(original));
            }
            Err(original) => return Err(original),
        };
        permit.bind(Token {
            backing: Some(backing),
            drops: self.token_drops.clone(),
        });
        if call != self.fault_call.load(Ordering::Acquire) {
            return Ok(());
        }
        match self.mode {
            Mode::Success => Ok(()),
            Mode::Error => Err(self.original_error.lock().unwrap().take().unwrap()),
            Mode::Panic => {
                let original = self.original_panic.lock().unwrap().take().unwrap();
                std::panic::resume_unwind(original)
            }
            Mode::HoldPublication => {
                let hold = self.hold.lock().unwrap().take().unwrap();
                hold.entered.send(self.child()).unwrap();
                hold.held.recv_timeout(WAIT).unwrap();
                Ok(())
            }
        }
    }
    fn quote_cache_memory(&self, bytes: u64) -> io::Result<kasumi_kv::CacheMemoryQuote> {
        self.backing.quote_cache_memory(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> io::Result<kasumi_kv::CacheMemoryLease> {
        self.backing.clone().reserve_cache_memory(bytes)
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    disk: Arc<NodeDisk>,
    memory: Arc<Memory>,
}
impl Fixture {
    fn new(mode: Mode) -> Self {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("startup-child.kv");
        let memory = Memory::new(mode);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.provider())).unwrap();
        Self {
            directory,
            disk,
            memory,
        }
    }
    fn opening(&self, mode: NodeOpeningMode) -> RegisteredNodeOpening {
        let opening = RegisteredNodeOpening::prepare(
            &self.directory.path().join("startup-child.kv"),
            ID,
            self.disk.clone(),
            mode,
            node_storage_config(),
        )
        .unwrap();
        assert_eq!(opening.open(), NodeOpeningPhase::Open);
        opening
    }
    fn existing(&self) -> RegisteredNodeOpening {
        let mut create = RegisteredNodeStartup::prepare(
            &self.directory.path().join("startup-child.kv"),
            ID,
            self.disk.clone(),
            NodeOpeningMode::Create,
            node_storage_config(),
        )
        .unwrap();
        assert_eq!(create.advance(), NodeStartupPhase::Ready);
        let opening = create.into_opening().ok().unwrap();
        self.finish(opening);
        self.opening(NodeOpeningMode::Existing)
    }
    fn finish(&self, opening: RegisteredNodeOpening) {
        assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
    }
}
fn report_error(report: &NativeConstructorReport<'_>) -> (usize, usize) {
    let TerminalObservation::Returned(Err(original)) = report.report_provider() else {
        panic!("the original report grant provider error must remain borrowed");
    };
    let diagnostic = original
        .get_ref()
        .unwrap()
        .downcast_ref::<Diagnostic>()
        .unwrap();
    (
        std::ptr::from_ref(original) as usize,
        std::ptr::from_ref(diagnostic) as usize,
    )
}
fn verification_failure(opening: &RegisteredNodeOpening) -> NativeConstructorFailure {
    opening
        .queue_startup_verification()
        .err()
        .expect("armed actual provider failure")
}

#[test]
fn startup_child_parent_metadata_refusal_is_pre_entry_without_grant_or_child() {
    let fixture = Fixture::new(Mode::Success);
    let opening = fixture.opening(NodeOpeningMode::Create);
    let parent = opening.id();
    let before = fixture.memory.backing.snapshot();
    let calls = fixture.memory.calls.load(Ordering::Acquire);
    fixture.memory.census.with_owner_metadata_held_for_test(parent, || {
        let error = opening.queue_startup_tables().err().expect("actual parent metadata is held");
        assert!(matches!(error, NativeConstructorFailure::Preclaim(original) if original.kind() == io::ErrorKind::WouldBlock));
        assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls);
        assert_eq!(fixture.memory.backing.snapshot(), before);
    });
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(0));
    assert_eq!(fixture.memory.census.snapshot().writers, 0);
    assert!(!opening.registration.owner().state.lock().tables_reserved);
    fixture.finish(opening);
}

#[test]
fn startup_tables_bound_provider_error_keeps_exact_child_and_original_after_locator_drop() {
    let fixture = Fixture::new(Mode::Error);
    let opening = fixture.opening(NodeOpeningMode::Create);
    let parent = opening.id();
    let diagnostic = fixture.memory.diagnostic_address();
    let standing = fixture.memory.backing.snapshot();
    let drops = fixture.memory.token_drops.load(Ordering::Acquire);
    let calls = fixture.memory.arm(parent, 1);
    let failure = opening.queue_startup_tables().err().unwrap();
    let child = failure.id().unwrap();
    assert_eq!(child, fixture.memory.child());
    assert_eq!(
        opening.registration.owner().state.lock().tables_request,
        Some(child)
    );
    let original = failure.with_report(|report| {
        let report = report.unwrap();
        assert_eq!(report.parent_id(), Some(parent));
        assert!(matches!(
            report.preparation(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(report.has_lease());
        assert!(!report.has_report_lease());
        assert!(!report.has_payload());
        assert!(matches!(
            report.construction(),
            TerminalObservation::NotEntered
        ));
        let TerminalObservation::Returned(Err(original)) = report.provider() else {
            panic!("actual bound provider error");
        };
        assert_eq!(
            std::ptr::from_ref(
                original
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<Diagnostic>()
                    .unwrap()
            ) as usize,
            diagnostic
        );
        std::ptr::from_ref(original) as usize
    });
    drop(failure);
    let retained = fixture
        .memory
        .census
        .retained_native_constructor::<super::super::NodeTablesRequest>(
            fixture.memory.provider(),
            child,
        )
        .unwrap();
    for _ in 0..2 {
        retained.with_report(|report| {
            let report = report.unwrap();
            let TerminalObservation::Returned(Err(error)) = report.provider() else {
                panic!("same original bound provider error");
            };
            assert_eq!(std::ptr::from_ref(error) as usize, original);
        });
        assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(1));
        assert_eq!(fixture.memory.token_drops.load(Ordering::Acquire), drops);
    }
    assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 1);
    assert_eq!(retained.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(
        fixture.memory.token_drops.load(Ordering::Acquire),
        drops + 1
    );
    assert_eq!(
        fixture.memory.backing.snapshot().used_bytes,
        standing.used_bytes
    );
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(0));
    fixture.finish(opening);
}

#[test]
fn startup_verification_second_bound_grant_error_survives_locator_loss_with_both_grants() {
    let fixture = Fixture::new(Mode::Error);
    let opening = fixture.existing();
    let parent = opening.id();
    let diagnostic = fixture.memory.diagnostic_address();
    let standing = fixture.memory.backing.snapshot();
    let drops = fixture.memory.token_drops.load(Ordering::Acquire);
    let calls = fixture.memory.arm(parent, 2);
    let failure = verification_failure(&opening);
    let child = failure.id().unwrap();
    assert_eq!(child, fixture.memory.child());
    let original = failure.with_report(|report| {
        let report = report.unwrap();
        assert_eq!(report.parent_id(), Some(parent));
        assert!(report.has_lease() && report.has_report_lease());
        assert!(report.report_request_bytes() > 0);
        assert!(!report.has_payload());
        assert!(matches!(
            report.provider(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(matches!(
            report.construction(),
            TerminalObservation::NotEntered
        ));
        let original = report_error(&report);
        assert_eq!(original.1, diagnostic);
        original
    });
    drop(failure);
    let retained = RegisteredNodeOpening::retained_verification_constructor_for_test(
        fixture.memory.provider(),
        child,
    )
    .unwrap();
    for _ in 0..2 {
        retained.with_report(|report| assert_eq!(report_error(&report.unwrap()), original));
        assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(1));
        assert_eq!(fixture.memory.token_drops.load(Ordering::Acquire), drops);
        assert_eq!(fixture.memory.diagnostic_drops.load(Ordering::Acquire), 0);
    }
    assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 2);
    assert_eq!(
        fixture.memory.metadata_observations.load(Ordering::Acquire),
        2
    );
    assert!(fixture.memory.backing.snapshot().used_bytes > standing.used_bytes);
    assert_eq!(retained.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(
        fixture.memory.token_drops.load(Ordering::Acquire),
        drops + 2
    );
    assert_eq!(fixture.memory.diagnostic_drops.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture.memory.backing.snapshot().used_bytes,
        standing.used_bytes
    );
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(0));
    fixture.finish(opening);
}

#[test]
fn startup_verification_second_bound_grant_panic_keeps_original_and_parent_until_cleanup() {
    let fixture = Fixture::new(Mode::Panic);
    let opening = fixture.existing();
    let parent = opening.id();
    let original = fixture.memory.panic_address();
    let standing = fixture.memory.backing.snapshot();
    let drops = fixture.memory.token_drops.load(Ordering::Acquire);
    let calls = fixture.memory.arm(parent, 2);
    let failure = verification_failure(&opening);
    assert_eq!(failure.id(), Some(fixture.memory.child()));
    for _ in 0..2 {
        failure.with_report(|report| {
            let report = report.unwrap();
            assert_eq!(report.parent_id(), Some(parent));
            assert!(report.has_lease() && report.has_report_lease());
            assert!(!report.has_payload());
            assert!(matches!(
                report.construction(),
                TerminalObservation::NotEntered
            ));
            let TerminalObservation::Panicked(payload) = report.report_provider() else {
                panic!("actual report provider unwind");
            };
            let marker = payload.downcast_ref::<Marker>().unwrap();
            assert_eq!(marker.0, 907);
            assert_eq!(std::ptr::from_ref(marker) as usize, original);
        });
        assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(1));
        assert_eq!(fixture.memory.token_drops.load(Ordering::Acquire), drops);
    }
    assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 2);
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(
        fixture.memory.token_drops.load(Ordering::Acquire),
        drops + 2
    );
    assert_eq!(
        fixture.memory.backing.snapshot().used_bytes,
        standing.used_bytes
    );
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(0));
    fixture.finish(opening);
}

#[test]
fn startup_unpublished_child_cleanup_tail_does_not_replay_grants_or_release_parent_early() {
    let fixture = Fixture::new(Mode::Error);
    let opening = fixture.existing();
    let parent = opening.id();
    let standing = fixture.memory.backing.snapshot();
    let drops = fixture.memory.token_drops.load(Ordering::Acquire);
    let calls = fixture.memory.arm(parent, 2);
    let failure = verification_failure(&opening);
    let child = failure.id().unwrap();
    fixture
        .memory
        .census
        .with_owner_metadata_held_for_test(child, || {
            for _ in 0..2 {
                assert_eq!(failure.cleanup(), StorageCensusDisposition::Retained);
                failure.with_report(|report| {
                    let report = report.unwrap();
                    assert!(matches!(
                        report.diagnostic_cleanup(),
                        TerminalObservation::Returned(Ok(()))
                    ));
                    assert!(matches!(
                        report.lease_cleanup(),
                        TerminalObservation::Returned(Ok(()))
                    ));
                    assert!(
                        !report.has_lease() && !report.has_report_lease() && !report.has_payload()
                    );
                });
                assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(1));
                assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 2);
                assert_eq!(
                    fixture.memory.token_drops.load(Ordering::Acquire),
                    drops + 2
                );
                assert_eq!(fixture.memory.diagnostic_drops.load(Ordering::Acquire), 1);
                assert_eq!(
                    fixture.memory.backing.snapshot().used_bytes,
                    standing.used_bytes
                );
            }
        });
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(0));
    assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 2);
    assert_eq!(
        fixture.memory.token_drops.load(Ordering::Acquire),
        drops + 2
    );
    fixture.finish(opening);
}

struct PublicationHold {
    release: Option<mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl PublicationHold {
    fn start(memory: &Arc<Memory>) -> Self {
        let (entered, child) = mpsc::channel();
        let (acknowledge, held) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        *memory.hold.lock().unwrap() = Some(HoldRequest { entered, held });
        let holding = memory.clone();
        let worker = std::thread::spawn(move || {
            let child = child.recv_timeout(WAIT).unwrap();
            holding.census.with_owner_metadata_held_for_test(child, || {
                acknowledge.send(()).unwrap();
                resume.recv_timeout(WAIT).unwrap();
            });
        });
        Self {
            release: Some(release),
            worker: Some(worker),
        }
    }
    fn finish(&mut self) {
        self.release.take().unwrap().send(()).unwrap();
        self.worker.take().unwrap().join().unwrap();
    }
}
impl Drop for PublicationHold {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn startup_unpublished_verification_payload_abandons_real_delivery_once_before_cleanup() {
    let fixture = Fixture::new(Mode::HoldPublication);
    let opening = fixture.existing();
    let parent = opening.id();
    let standing = fixture.memory.backing.snapshot();
    let drops = fixture.memory.token_drops.load(Ordering::Acquire);
    let mut hold = PublicationHold::start(&fixture.memory);
    let calls = fixture.memory.arm(parent, 2);
    let failure = verification_failure(&opening);
    let child = failure.id().unwrap();
    assert_eq!(child, fixture.memory.child());
    failure.with_report(|report| {
        let report = report.unwrap();
        assert!(matches!(
            report.construction(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(matches!(
            report.delivery_abandonment(),
            TerminalObservation::NotEntered
        ));
        assert!(report.has_payload() && report.has_lease());
        assert!(
            !report.has_report_lease(),
            "actual report grant entered the real Reader payload"
        );
    });
    for _ in 0..2 {
        assert_eq!(failure.cleanup(), StorageCensusDisposition::Retained);
        failure.with_report(|report| {
            let report = report.unwrap();
            assert!(matches!(
                report.delivery_abandonment(),
                TerminalObservation::Returned(Ok(()))
            ));
            assert!(report.has_payload() && report.has_lease());
        });
        assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(1));
        assert_eq!(fixture.memory.token_drops.load(Ordering::Acquire), drops);
        assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 2);
    }
    hold.finish();
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(0));
    assert_eq!(fixture.memory.census.snapshot().readers, 0);
    assert_eq!(
        fixture.memory.token_drops.load(Ordering::Acquire),
        drops + 2
    );
    assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 2);
    assert_eq!(
        fixture.memory.backing.snapshot().used_bytes,
        standing.used_bytes
    );
    fixture.finish(opening);
}

#[test]
fn startup_verification_returns_exact_paid_queued_reader_before_native_begin() {
    let fixture = Fixture::new(Mode::Success);
    let opening = fixture.existing();
    let parent = opening.id();
    let drops = fixture.memory.token_drops.load(Ordering::Acquire);
    let calls = fixture.memory.arm(parent, 2);
    let reader = opening.queue_startup_verification().unwrap();
    assert_eq!(reader.id(), fixture.memory.child());
    assert_eq!(reader.phase(), NodeReadPhase::Queued);
    assert!(!opening.report().existing_tables_verified());
    {
        let report = reader.report();
        assert!(matches!(report.begin(), TerminalObservation::NotEntered));
        assert!(matches!(report.outer(), TerminalObservation::NotEntered));
        assert!(report.close().is_none());
    }
    assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 2);
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(1));
    assert_eq!(fixture.memory.token_drops.load(Ordering::Acquire), drops);
    assert_eq!(reader.begin(), NodeReadPhase::Active);
    assert!(opening.report().existing_tables_verified());
    assert_eq!(reader.finish(), NodeReadPhase::Finished);
    assert_eq!(reader.retire(), StorageCensusDisposition::Retired);
    assert_eq!(
        fixture.memory.token_drops.load(Ordering::Acquire),
        drops + 2
    );
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(0));
    fixture.finish(opening);
}

#[test]
fn startup_verification_report_quota_refusal_keeps_first_grant_and_exact_original() {
    let fixture = Fixture::new(Mode::Success);
    let opening = fixture.existing();
    let parent = opening.id();
    let standing = fixture.memory.backing.snapshot();
    let [report_request, owner_request] = RegisteredNodeRead::memory_requests().unwrap();
    let token = DiskMemoryLease::token_allocation_bytes::<Token>().unwrap();
    let owner_cost =
        TestDiskMemory::required_reservation_bytes(owner_request.checked_add(token).unwrap())
            .unwrap();
    let report_cost =
        TestDiskMemory::required_reservation_bytes(report_request.checked_add(token).unwrap())
            .unwrap();
    let headroom = owner_cost
        .checked_add(report_cost)
        .unwrap()
        .checked_sub(1)
        .unwrap();
    let filler_cost = LIMIT
        .checked_sub(standing.bookkeeping_bytes)
        .unwrap()
        .checked_sub(standing.used_bytes)
        .unwrap()
        .checked_sub(headroom)
        .unwrap();
    let filler_request = filler_cost
        .checked_sub(TestDiskMemory::required_reservation_bytes(0).unwrap())
        .unwrap();
    // This is an actual quota debit, not an injected OOM or a permit forged by
    // the fixture. The first grant fits; the report misses by one actual byte.
    let pressure = fixture
        .memory
        .backing
        .clone()
        .reserve_installed(filler_request)
        .unwrap();
    let filled = fixture.memory.backing.snapshot();
    assert_eq!(filled.used_bytes, standing.used_bytes + filler_cost);
    assert_eq!(
        LIMIT - filled.bookkeeping_bytes - filled.used_bytes,
        headroom
    );
    assert!(
        filled.live_reservations + 2 <= 64,
        "refusal must be bytes, not reservation slots"
    );
    let drops = fixture.memory.token_drops.load(Ordering::Acquire);
    let calls = fixture.memory.arm(parent, 2);
    let failure = verification_failure(&opening);
    let child = failure.id().unwrap();
    assert_eq!(child, fixture.memory.child());
    assert!(failure.is_capacity_denied());
    let original = failure.with_report(|report| {
        let report = report.unwrap();
        assert!(report.capacity_refused());
        assert_eq!(report.protocol(), None);
        assert_eq!(report.parent_id(), Some(parent));
        assert_eq!(report.request_bytes(), owner_request);
        assert_eq!(report.report_request_bytes(), report_request);
        assert!(report.has_lease());
        assert!(!report.has_report_lease() && !report.has_payload());
        assert!(matches!(
            report.provider(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(matches!(
            report.construction(),
            TerminalObservation::NotEntered
        ));
        assert!(matches!(
            report.delivery_abandonment(),
            TerminalObservation::NotEntered
        ));
        let TerminalObservation::Returned(Err(original)) = report.report_provider() else {
            panic!("actual TestDiskMemory report quota refusal");
        };
        assert_eq!(original.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(original.raw_os_error(), None);
        std::ptr::from_ref(original) as usize
    });
    let held = fixture.memory.backing.snapshot();
    assert_eq!(held.used_bytes, filled.used_bytes + owner_cost);
    assert_eq!(held.live_reservations, filled.live_reservations + 1);
    assert_eq!(held.attempts, filled.attempts + 2);
    assert_eq!(
        LIMIT - held.bookkeeping_bytes - held.used_bytes,
        report_cost - 1
    );
    for _ in 0..2 {
        failure.with_report(|report| {
            let report = report.unwrap();
            let TerminalObservation::Returned(Err(error)) = report.report_provider() else {
                panic!("same original report quota refusal");
            };
            assert_eq!(std::ptr::from_ref(error) as usize, original);
            assert!(report.capacity_refused() && report.has_lease());
            assert!(!report.has_report_lease() && !report.has_payload());
        });
        assert_eq!(fixture.memory.backing.snapshot(), held);
        assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 2);
        assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(1));
        assert_eq!(fixture.memory.token_drops.load(Ordering::Acquire), drops);
    }
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    let acknowledged = fixture.memory.backing.snapshot();
    assert_eq!(acknowledged.used_bytes, filled.used_bytes);
    assert_eq!(acknowledged.live_reservations, filled.live_reservations);
    assert_eq!(acknowledged.attempts, held.attempts);
    assert_eq!(
        fixture.memory.token_drops.load(Ordering::Acquire),
        drops + 1
    );
    assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 2);
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(0));
    drop(pressure);
    let released = fixture.memory.backing.snapshot();
    assert_eq!(released.used_bytes, standing.used_bytes);
    assert_eq!(released.live_reservations, standing.live_reservations);
    fixture.finish(opening);
}

#[test]
fn startup_advance_retains_exact_child_marker_across_failed_custody_and_caller_loss() {
    let fixture = Fixture::new(Mode::Error);
    let mut startup = RegisteredNodeStartup::prepare(
        &fixture.directory.path().join("startup-child.kv"),
        ID,
        fixture.disk.clone(),
        NodeOpeningMode::Create,
        node_storage_config(),
    )
    .unwrap();
    let parent = startup.opening_id();
    let diagnostic = fixture.memory.diagnostic_address();
    let drops = fixture.memory.token_drops.load(Ordering::Acquire);
    let calls = fixture.memory.arm(parent, 1);
    assert_eq!(
        calls, 1,
        "only the real opening constructor ran before advance"
    );
    assert_eq!(startup.advance(), NodeStartupPhase::Failed);
    assert_eq!(startup.advance(), NodeStartupPhase::Failed);
    let child = startup
        .child_id()
        .expect("the original retained Tables claim");
    assert_eq!(child, fixture.memory.child());
    assert_eq!(
        startup.child_constructor,
        Some(NativeStartupChildPurpose::Tables)
    );
    let original = startup.child_constructor().unwrap().with_report(|report| {
        let report = report.unwrap();
        assert_eq!(report.parent_id(), Some(parent));
        assert!(report.has_lease() && !report.has_payload());
        assert!(matches!(
            report.construction(),
            TerminalObservation::NotEntered
        ));
        let TerminalObservation::Returned(Err(original)) = report.provider() else {
            panic!("actual Tables provider failure from advance");
        };
        assert_eq!(
            std::ptr::from_ref(
                original
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<Diagnostic>()
                    .unwrap()
            ) as usize,
            diagnostic
        );
        std::ptr::from_ref(original) as usize
    });
    assert!(startup.local_error().is_none());
    assert_eq!(
        startup.close_failed().unwrap(),
        DatabaseOpenSettlement::Closed
    );
    let custody = startup.into_failed_custody().ok().unwrap();
    assert_eq!(custody.phase(), NodeStartupPhase::Failed);
    assert_eq!(custody.child_id(), Some(child));
    assert_eq!(
        custody.child_constructor,
        Some(NativeStartupChildPurpose::Tables)
    );
    assert!(custody.tables().is_none() && custody.verification().is_none());
    for _ in 0..2 {
        let located = custody
            .child_constructor()
            .expect("fresh exact original lookup");
        assert_eq!(located.id(), Some(child));
        located.with_report(|report| {
            let report = report.unwrap();
            let TerminalObservation::Returned(Err(error)) = report.provider() else {
                panic!("same actual original after failed-custody transfer");
            };
            assert_eq!(std::ptr::from_ref(error) as usize, original);
            assert_eq!(
                std::ptr::from_ref(
                    error
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<Diagnostic>()
                        .unwrap()
                ) as usize,
                diagnostic
            );
        });
        drop(located);
        assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(1));
        assert_eq!(fixture.memory.token_drops.load(Ordering::Acquire), drops);
        assert_eq!(fixture.memory.diagnostic_drops.load(Ordering::Acquire), 0);
    }
    drop(custody);
    let opening = RegisteredNodeOpening::retained(fixture.memory.provider(), parent).unwrap();
    let retained =
        RegisteredNodeTables::retained_constructor(fixture.memory.provider(), child).unwrap();
    retained.with_report(|report| {
        let report = report.unwrap();
        let TerminalObservation::Returned(Err(error)) = report.provider() else {
            panic!("same original survives losing coordinator and custody");
        };
        assert_eq!(std::ptr::from_ref(error) as usize, original);
        assert_eq!(
            std::ptr::from_ref(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<Diagnostic>()
                    .unwrap()
            ) as usize,
            diagnostic
        );
    });
    assert_eq!(
        opening.report().engine().settlement(),
        DatabaseOpenSettlement::Closed
    );
    assert!(matches!(
        opening.report().ready_publication(),
        TerminalObservation::NotEntered
    ));
    assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 1);
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(1));
    assert_eq!(fixture.memory.token_drops.load(Ordering::Acquire), drops);
    assert_eq!(fixture.memory.diagnostic_drops.load(Ordering::Acquire), 0);
    assert_eq!(retained.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(retained.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(fixture.memory.census.child_count_for_test(parent), Some(0));
    assert_eq!(
        fixture.memory.token_drops.load(Ordering::Acquire),
        drops + 1
    );
    assert_eq!(fixture.memory.diagnostic_drops.load(Ordering::Acquire), 1);
    assert_eq!(fixture.memory.calls.load(Ordering::Acquire), calls + 1);
    fixture.finish(opening);
}
