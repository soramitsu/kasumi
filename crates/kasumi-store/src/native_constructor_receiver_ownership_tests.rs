use super::*;
use crate::test_utils::TestDiskMemory;
use std::sync::atomic::AtomicUsize;

const LIMIT: u64 = 64 << 20;
const CAPACITY: usize = 16;

#[derive(Clone, Copy)]
enum Mode {
    Error,
    Panic,
    Missing,
    Foreign,
    Duplicate,
    DiagnosticPanic,
    Success,
}
#[derive(Debug)]
struct Marker(u8);
struct Diagnostic {
    drops: Arc<AtomicUsize>,
    panic: Arc<Mutex<Option<Panic>>>,
}
impl fmt::Debug for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("receiver original diagnostic")
    }
}
impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("receiver original diagnostic")
    }
}
impl std::error::Error for Diagnostic {}
impl Drop for Diagnostic {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
        let original = self.panic.lock().unwrap().take();
        if let Some(original) = original {
            std::panic::resume_unwind(original);
        }
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
struct Memory {
    census: StorageCensus,
    backing: Arc<TestDiskMemory>,
    foreign: Arc<TestDiskMemory>,
    mode: Mode,
    calls: AtomicUsize,
    body_constructions: AtomicUsize,
    token_drops: Arc<AtomicUsize>,
    diagnostic_drops: Arc<AtomicUsize>,
    body_drives: Arc<AtomicUsize>,
    body_drops: Arc<AtomicUsize>,
    diagnostic_panic: Arc<Mutex<Option<Panic>>>,
    original_error: Mutex<Option<io::Error>>,
    provider_panic: Mutex<Option<Panic>>,
    observer_panic: Mutex<Option<Panic>>,
    body_panic: Mutex<Option<Panic>>,
    // The fixture's prebuilt diagnostic/counter/census allocations retire first.
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
        for quote in [
            disk_memory::arc::<AtomicUsize>().unwrap(),
            disk_memory::arc::<AtomicUsize>().unwrap(),
            disk_memory::arc::<AtomicUsize>().unwrap(),
            disk_memory::arc::<AtomicUsize>().unwrap(),
            disk_memory::arc::<Mutex<Option<Panic>>>().unwrap(),
            disk_memory::allocation::<Diagnostic>(1).unwrap(),
            // Conservative fixed storage for the ordinary io::Error custom
            // representation, independently of its concrete diagnostic Box.
            disk_memory::allocation::<[usize; 16]>(1).unwrap(),
            disk_memory::allocation::<Marker>(1).unwrap(),
            disk_memory::allocation::<Marker>(1).unwrap(),
            disk_memory::allocation::<Marker>(1).unwrap(),
            disk_memory::allocation::<Marker>(1).unwrap(),
        ] {
            bytes = disk_memory::add(bytes, quote).unwrap();
        }
        let bookkeeping = backing.clone().reserve_installed(bytes).unwrap();
        let token_drops = Arc::new(AtomicUsize::new(0));
        let diagnostic_drops = Arc::new(AtomicUsize::new(0));
        let diagnostic_panic = Arc::new(Mutex::new(
            matches!(mode, Mode::DiagnosticPanic).then(|| Box::new(Marker(2)) as Panic),
        ));
        let original_error = io::Error::other(Diagnostic {
            drops: diagnostic_drops.clone(),
            panic: diagnostic_panic.clone(),
        });
        let memory = Arc::new(Self {
            census: StorageCensus::allocate(CAPACITY).unwrap(),
            backing,
            foreign: TestDiskMemory::new(LIMIT, CAPACITY),
            mode,
            calls: AtomicUsize::new(0),
            body_constructions: AtomicUsize::new(0),
            token_drops,
            diagnostic_drops,
            body_drives: Arc::new(AtomicUsize::new(0)),
            body_drops: Arc::new(AtomicUsize::new(0)),
            diagnostic_panic,
            original_error: Mutex::new(Some(original_error)),
            provider_panic: Mutex::new(Some(Box::new(Marker(1)))),
            observer_panic: Mutex::new(Some(Box::new(Marker(3)))),
            body_panic: Mutex::new(Some(Box::new(Marker(4)))),
            _bookkeeping: bookkeeping,
        });
        drop(memory.original_error.lock().unwrap());
        drop(memory.provider_panic.lock().unwrap());
        drop(memory.observer_panic.lock().unwrap());
        drop(memory.body_panic.lock().unwrap());
        drop(memory.diagnostic_panic.lock().unwrap());
        let provider = memory.provider();
        memory.census.bind_provider(&provider).unwrap();
        memory
    }
    fn provider(self: &Arc<Self>) -> Arc<dyn NodeDiskMemoryAdmission> {
        self.clone()
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
    fn payload(&self, busy_drives: usize) -> Payload {
        self.body_constructions.fetch_add(1, Ordering::AcqRel);
        Payload {
            drives: self.body_drives.clone(),
            drops: self.body_drops.clone(),
            busy_drives,
        }
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
        install: &mut NativeConstructorInstall<'_>,
    ) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if matches!(self.mode, Mode::Missing) {
            return Ok(());
        }
        if matches!(self.mode, Mode::Foreign) {
            assert_eq!(
                install.try_begin_bind(self.foreign.clone()).err(),
                Some(NativeConstructorCallError::ForeignProvider),
            );
            return Ok(());
        }
        let provider = self.provider();
        let permit = install.try_begin_bind(provider.clone()).unwrap();
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
        match self.mode {
            Mode::Error | Mode::DiagnosticPanic => {
                Err(self.original_error.lock().unwrap().take().unwrap())
            }
            Mode::Panic => {
                let original = self.provider_panic.lock().unwrap().take().unwrap();
                std::panic::resume_unwind(original);
            }
            Mode::Duplicate => {
                assert_eq!(
                    install.try_begin_bind(provider).err(),
                    Some(NativeConstructorCallError::AlreadyEntered),
                );
                Ok(())
            }
            Mode::Success => Ok(()),
            Mode::Missing | Mode::Foreign => unreachable!(),
        }
    }
    fn quote_cache_memory(&self, _: u64) -> io::Result<kasumi_kv::CacheMemoryQuote> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn reserve_cache_memory(self: Arc<Self>, _: u64) -> io::Result<kasumi_kv::CacheMemoryLease> {
        Err(io::ErrorKind::Unsupported.into())
    }
}
struct Payload {
    drives: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    busy_drives: usize,
}
impl StoragePayload for Payload {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        self.drives.fetch_add(1, Ordering::AcqRel) >= self.busy_drives
    }
}
impl Drop for Payload {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}
struct OtherPayload;
impl StoragePayload for OtherPayload {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        true
    }
}
fn marker_address(original: &Panic, tag: u8) -> usize {
    let marker = original.downcast_ref::<Marker>().unwrap();
    assert_eq!(marker.0, tag);
    std::ptr::from_ref(marker) as usize
}
fn error_address(report: &NativeConstructorReport<'_>) -> usize {
    match report.provider() {
        TerminalObservation::Returned(Err(original)) => {
            assert_eq!(original.kind(), io::ErrorKind::Other);
            let diagnostic = original
                .get_ref()
                .unwrap()
                .downcast_ref::<Diagnostic>()
                .unwrap();
            std::ptr::from_ref(diagnostic) as usize
        }
        _ => panic!("original provider error must remain owned"),
    }
}
fn failed(memory: &Arc<Memory>) -> NativeConstructorFailure {
    memory
        .census
        .register_native(memory.provider(), 0, |_| memory.payload(0))
        .err()
        .expect("actual receiver failure")
}

#[test]
fn bound_provider_error_retains_original_token_and_exact_diagnostic_after_facade_drop() {
    let memory = Memory::new(Mode::Error);
    let standing = memory.backing.snapshot();
    let original = memory.diagnostic_address();
    let failure = failed(&memory);
    let id = failure.id().unwrap();
    let receiver_error = failure.with_report(|report| {
        let report = report.unwrap();
        assert_eq!(error_address(&report), original);
        assert!(report.has_lease());
        assert!(!report.has_payload());
        assert!(matches!(
            report.construction(),
            TerminalObservation::NotEntered
        ));
        match report.provider() {
            TerminalObservation::Returned(Err(original)) => std::ptr::from_ref(original) as usize,
            _ => panic!("original error wrapper remains in receiver"),
        }
    });
    drop(failure);
    assert!(
        memory
            .census
            .retained_native_constructor::<OtherPayload>(memory.provider(), id)
            .is_none()
    );
    let retained = memory
        .census
        .retained_native_constructor::<Payload>(memory.provider(), id)
        .unwrap();
    retained.with_report(|report| {
        let report = report.unwrap();
        assert_eq!(error_address(&report), original);
        match report.provider() {
            TerminalObservation::Returned(Err(original)) => {
                assert_eq!(std::ptr::from_ref(original) as usize, receiver_error);
            }
            _ => panic!("same original error wrapper remains after facade drop"),
        }
    });
    assert_eq!(memory.body_constructions.load(Ordering::Acquire), 0);
    assert_eq!(memory.body_drives.load(Ordering::Acquire), 0);
    assert_eq!(memory.body_drops.load(Ordering::Acquire), 0);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 0);
    assert_eq!(
        memory.backing.snapshot().live_reservations,
        standing.live_reservations + 1
    );
    assert_eq!(retained.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.diagnostic_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.backing.snapshot().used_bytes, standing.used_bytes);
}

#[test]
fn provider_panic_after_bind_keeps_exact_payload_and_real_grant_until_cleanup() {
    let memory = Memory::new(Mode::Panic);
    let standing = memory.backing.snapshot();
    let original = marker_address(memory.provider_panic.lock().unwrap().as_ref().unwrap(), 1);
    let failure = failed(&memory);
    failure.with_report(|report| {
        let report = report.unwrap();
        match report.provider() {
            TerminalObservation::Panicked(payload) => {
                assert_eq!(
                    std::ptr::from_ref(payload.downcast_ref::<Marker>().unwrap()) as usize,
                    original
                );
            }
            _ => panic!("original provider panic"),
        }
        assert!(report.has_lease());
        assert!(matches!(
            report.construction(),
            TerminalObservation::NotEntered
        ));
    });
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 0);
    assert_eq!(memory.body_constructions.load(Ordering::Acquire), 0);
    assert_eq!(memory.body_drops.load(Ordering::Acquire), 0);
    assert!(memory.backing.snapshot().used_bytes > standing.used_bytes);
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.backing.snapshot().used_bytes, standing.used_bytes);
}

#[test]
fn missing_foreign_and_duplicate_binding_cannot_enter_payload_construction() {
    for (mode, expected, bound) in [
        (
            Mode::Missing,
            NativeConstructorCallError::MissingBinding,
            false,
        ),
        (
            Mode::Foreign,
            NativeConstructorCallError::ForeignProvider,
            false,
        ),
        (
            Mode::Duplicate,
            NativeConstructorCallError::AlreadyEntered,
            true,
        ),
    ] {
        let memory = Memory::new(mode);
        let standing = memory.backing.snapshot();
        let failure = failed(&memory);
        failure.with_report(|report| {
            let report = report.unwrap();
            assert_eq!(report.protocol(), Some(expected));
            assert_eq!(report.has_lease(), bound);
            assert!(!report.has_payload());
            assert!(!report.capacity_refused());
            assert!(matches!(
                report.construction(),
                TerminalObservation::NotEntered
            ));
        });
        assert_eq!(memory.calls.load(Ordering::Acquire), 1);
        assert_eq!(memory.body_constructions.load(Ordering::Acquire), 0);
        assert_eq!(memory.body_drives.load(Ordering::Acquire), 0);
        assert_eq!(memory.body_drops.load(Ordering::Acquire), 0);
        assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
        assert_eq!(
            memory.token_drops.load(Ordering::Acquire),
            usize::from(bound)
        );
        assert_eq!(memory.backing.snapshot().used_bytes, standing.used_bytes);
    }
}

#[test]
fn diagnostic_destructor_panic_retains_actual_grant_without_entering_lease_cleanup() {
    let memory = Memory::new(Mode::DiagnosticPanic);
    let original = marker_address(memory.diagnostic_panic.lock().unwrap().as_ref().unwrap(), 2);
    let failure = failed(&memory);
    let held = memory.backing.snapshot();
    for _ in 0..2 {
        assert_eq!(failure.cleanup(), StorageCensusDisposition::Retained);
        failure.with_report(|report| {
            let report = report.unwrap();
            match report.diagnostic_cleanup() {
                TerminalObservation::Panicked(payload) => {
                    assert_eq!(
                        std::ptr::from_ref(payload.downcast_ref::<Marker>().unwrap()) as usize,
                        original
                    );
                }
                _ => panic!("original diagnostic destructor panic"),
            }
            assert!(report.has_lease());
            assert!(matches!(
                report.lease_cleanup(),
                TerminalObservation::NotEntered
            ));
        });
        assert_eq!(memory.token_drops.load(Ordering::Acquire), 0);
        assert_eq!(memory.diagnostic_drops.load(Ordering::Acquire), 1);
        assert_eq!(memory.calls.load(Ordering::Acquire), 1);
        assert_eq!(memory.backing.snapshot(), held);
    }
}

#[test]
fn observer_closure_panic_keeps_original_outcome_and_cleanup_custody() {
    let memory = Memory::new(Mode::Error);
    let standing = memory.backing.snapshot();
    let original = memory.diagnostic_address();
    let failure = failed(&memory);
    let observer = memory.observer_panic.lock().unwrap().take().unwrap();
    let observer_address = marker_address(&observer, 3);
    let caught = catch_unwind(AssertUnwindSafe(|| {
        failure.with_report(|report| {
            assert_eq!(error_address(&report.unwrap()), original);
            std::panic::resume_unwind(observer);
        });
    }))
    .expect_err("actual inspection panic");
    assert_eq!(marker_address(&caught, 3), observer_address);
    failure.with_report(|report| assert_eq!(error_address(&report.unwrap()), original));
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 0);
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.backing.snapshot().used_bytes, standing.used_bytes);
}

#[test]
fn publication_metadata_contention_preserves_same_arc_grant_and_never_replays_construction() {
    let memory = Memory::new(Mode::Success);
    let standing = memory.backing.snapshot();
    let (entered, observe) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let mut worker = None;
    let mut constructions = 0;
    let failure = memory
        .census
        .register_native(memory.provider(), 0, |_| {
            constructions += 1;
            let id = memory.census.owner_at(0).unwrap();
            let holding = memory.clone();
            worker = Some(std::thread::spawn(move || {
                holding.census.with_owner_metadata_held_for_test(id, || {
                    entered.send(()).unwrap();
                    resume
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                });
            }));
            observe
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            memory.payload(1)
        })
        .err()
        .expect("actual publication lock is held");
    let id = failure.id().unwrap();
    let unpublished = {
        let state = native_state(&memory.census.slots[id.index]).unwrap();
        assert!(state.lease.is_some());
        assert!(!state.published);
        Arc::as_ptr(state.payload.as_ref().unwrap()) as *const () as usize
    };
    assert_eq!(memory.calls.load(Ordering::Acquire), 1);
    assert_eq!(constructions, 1);
    assert_eq!(memory.body_constructions.load(Ordering::Acquire), 1);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 0);
    release.send(()).unwrap();
    worker.unwrap().join().unwrap();
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retained);
    {
        let slot = &memory.census.slots[id.index];
        let metadata = slot.metadata.lock().unwrap();
        let Cell::Active { owner, .. } = &metadata.cell else {
            panic!("actual same payload must be published");
        };
        assert_eq!(Arc::as_ptr(owner) as *const () as usize, unpublished);
        assert!(metadata.lease.is_some());
    }
    assert_eq!(memory.calls.load(Ordering::Acquire), 1);
    assert_eq!(constructions, 1);
    assert_eq!(memory.body_constructions.load(Ordering::Acquire), 1);
    assert_eq!(memory.body_drives.load(Ordering::Acquire), 1);
    assert_eq!(memory.body_drops.load(Ordering::Acquire), 0);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 0);
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(memory.body_drives.load(Ordering::Acquire), 2);
    assert_eq!(memory.body_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.backing.snapshot().used_bytes, standing.used_bytes);
}

#[test]
fn completed_cleanup_metadata_tail_retries_without_provider_or_retirement_reentry() {
    let memory = Memory::new(Mode::Error);
    let standing = memory.backing.snapshot();
    let probe = NativeConstructorProbe::prepare(memory.provider(), 1234).unwrap();
    assert!(!probe.run());
    memory
        .census
        .with_owner_metadata_held_for_test(probe.id, || {
            assert_eq!(probe.cleanup(), StorageCensusDisposition::Retained);
            probe.with_report(|report| {
                assert!(matches!(
                    report.diagnostic_cleanup(),
                    TerminalObservation::Returned(Ok(()))
                ));
                assert!(matches!(
                    report.lease_cleanup(),
                    TerminalObservation::Returned(Ok(()))
                ));
                assert!(!report.has_lease());
            });
            assert!(!probe.run_provider_again_for_test());
        });
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.diagnostic_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.calls.load(Ordering::Acquire), 1);
    assert_eq!(memory.backing.snapshot().used_bytes, standing.used_bytes);
    let retained = memory
        .census
        .retained_native_constructor::<ProbePayload>(memory.provider(), probe.id)
        .expect("same completed tail remains recoverable");
    assert_eq!(retained.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(memory.census.snapshot().databases, 0);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.diagnostic_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.calls.load(Ordering::Acquire), 1);
}

#[test]
fn retired_probe_cannot_dispatch_a_reused_generation() {
    let memory = Memory::new(Mode::Success);
    let standing = memory.backing.snapshot();
    let old = NativeConstructorProbe::prepare(memory.provider(), 1234).unwrap();
    assert!(old.run());
    assert_eq!(old.cleanup(), StorageCensusDisposition::Retired);
    assert!(!old.run_provider_again_for_test());
    let current = NativeConstructorProbe::prepare(memory.provider(), 4321).unwrap();
    assert_eq!(old.id.index, current.id.index);
    assert_ne!(old.id.generation, current.id.generation);
    assert!(!old.run_provider_again_for_test());
    // The independent positive retirement witness remains for this exact old
    // generation. It cannot retire or dispatch the new preclaimed generation.
    assert_eq!(old.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(memory.calls.load(Ordering::Acquire), 1);
    assert!(current.run());
    assert_eq!(memory.calls.load(Ordering::Acquire), 2);
    assert_eq!(current.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 2);
    assert_eq!(memory.backing.snapshot().used_bytes, standing.used_bytes);
}

#[test]
fn delayed_cleanup_cannot_replace_reused_generation_retirement_receipt() {
    let memory = Memory::new(Mode::Success);
    let standing = memory.backing.snapshot();
    let old = memory
        .census
        .register_native(memory.provider(), 0, |_| memory.payload(0))
        .unwrap();
    let old_id = old.id();
    drop(old);
    let (drained, observe) = std::sync::mpsc::channel();
    let (release, resume) = std::sync::mpsc::channel();
    let delayed_memory = memory.clone();
    let delayed = std::thread::spawn(move || {
        delayed_memory
            .census
            .cleanup_native_constructor_after_drain(old_id, TypeId::of::<Payload>(), || {
                drained.send(()).unwrap();
                resume
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            })
    });
    observe
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    // The old body and actual grant have retired, but its receipt tail is
    // paused after metadata release. Reuse and retire that same real slot.
    assert_eq!(memory.body_drives.load(Ordering::Acquire), 1);
    assert_eq!(memory.body_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 1);
    let current = NativeConstructorProbe::prepare(memory.provider(), 4321).unwrap();
    assert_eq!(old_id.index, current.id.index);
    assert!(current.id.generation > old_id.generation);
    assert!(current.run());
    assert_eq!(current.cleanup(), StorageCensusDisposition::Retired);
    let slot = &memory.census.slots[current.id.index];
    let state = slot.native_constructor.lock();
    assert!(state.retired);
    release.send(()).unwrap();
    assert_eq!(delayed.join().unwrap(), StorageCensusDisposition::Retired);
    // The independent exact receipt must remain available while its receiver
    // is busy; a stale terminal tail cannot downgrade this to Retained.
    assert_eq!(current.cleanup(), StorageCensusDisposition::Retired);
    // A later positive native retirement in this same slot proves its prior
    // issued native generation reached Vacant too. The old acknowledgement
    // survives reuse without inspecting or mutating the new receiver.
    assert_eq!(
        memory
            .census
            .cleanup_native_constructor(old_id, TypeId::of::<Payload>()),
        StorageCensusDisposition::Retired,
    );
    assert_eq!(
        slot.native_constructor_retired_generation
            .load(Ordering::Acquire),
        current.id.generation,
    );
    drop(state);
    assert!(!current.run_provider_again_for_test());
    assert_eq!(memory.calls.load(Ordering::Acquire), 2);
    assert_eq!(memory.body_drives.load(Ordering::Acquire), 1);
    assert_eq!(memory.body_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 2);
    assert_eq!(memory.backing.snapshot().used_bytes, standing.used_bytes);
}

#[test]
fn original_constructor_panic_is_retained_and_only_direct_native_registration_accepts_database() {
    let memory = Memory::new(Mode::Success);
    let standing = memory.backing.snapshot();
    let original = memory.body_panic.lock().unwrap().take().unwrap();
    let address = marker_address(&original, 4);
    let failure = memory
        .census
        .register_native::<Payload>(memory.provider(), 0, |_| {
            std::panic::resume_unwind(original);
        })
        .err()
        .expect("original constructor panic");
    failure.with_report(|report| {
        let report = report.unwrap();
        match report.construction() {
            TerminalObservation::Panicked(payload) => {
                assert_eq!(
                    std::ptr::from_ref(payload.downcast_ref::<Marker>().unwrap()) as usize,
                    address
                );
            }
            _ => panic!("original constructor panic remains owned"),
        }
        assert!(report.has_lease());
        assert!(!report.has_payload());
    });
    assert_eq!(memory.body_drives.load(Ordering::Acquire), 0);
    assert_eq!(memory.body_drops.load(Ordering::Acquire), 0);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 0);
    assert_eq!(failure.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(memory.token_drops.load(Ordering::Acquire), 1);
    assert_eq!(memory.backing.snapshot().used_bytes, standing.used_bytes);

    let direct = Memory::new(Mode::Success);
    let standing = direct.backing.snapshot();
    let ordinary = direct
        .census
        .register(direct.provider(), 0, || direct.payload(0))
        .err()
        .expect("Database cannot bypass the native constructor receiver");
    assert_eq!(ordinary.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(direct.backing.snapshot(), standing);
    assert_eq!(direct.calls.load(Ordering::Acquire), 0);
    let owner = direct
        .census
        .register_native(direct.provider(), 0, |_| direct.payload(0))
        .expect("direct native constructor success");
    let id = owner.id();
    assert!(
        direct
            .census
            .retained_native_constructor::<OtherPayload>(direct.provider(), id)
            .is_none()
    );
    assert!(
        direct
            .census
            .retained_native_constructor::<Payload>(direct.provider(), id)
            .is_none()
    );
    assert_eq!(direct.calls.load(Ordering::Acquire), 1);
    assert_eq!(owner.retire(), StorageCensusDisposition::Retired);
    assert_eq!(direct.body_drives.load(Ordering::Acquire), 1);
    assert_eq!(direct.body_drops.load(Ordering::Acquire), 1);
    assert_eq!(direct.token_drops.load(Ordering::Acquire), 1);
    assert_eq!(direct.backing.snapshot().used_bytes, standing.used_bytes);
}
