use super::*;
use crate::{allocation_tests::measure_requested, test_utils::TestDiskMemory};
use std::sync::atomic::AtomicUsize;

const LIMIT: u64 = 64 << 20;
const CAPACITY: usize = 32;

fn saturate(memory: &Arc<TestDiskMemory>) -> DiskMemoryLease {
    let before = memory.snapshot();
    let remaining = LIMIT - before.bookkeeping_bytes - before.used_bytes;
    memory
        .clone()
        .reserve_installed(remaining - TestDiskMemory::required_reservation_bytes(0).unwrap())
        .unwrap()
}

#[test]
fn native_constructor_first_refused_grant_uses_prepaid_receiver_without_allocation() {
    let memory = TestDiskMemory::new(LIMIT, CAPACITY);
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let pressure = saturate(&memory);
    let before = memory.snapshot();
    // No receiver lock has been used or warmed before this measurement. The
    // real installed provider refuses its first grant after the actual claim.
    let (result, allocations, requested_bytes) = measure_requested(|| {
        let receiver = NativeConstructorProbe::prepare(provider.clone(), 1234)?;
        let ready = receiver.run();
        Ok::<_, io::Error>((receiver, ready))
    });
    let (receiver, ready) = result.unwrap();
    assert!(!ready);
    assert_eq!(
        allocations, 0,
        "actual allocator requested {requested_bytes} bytes"
    );
    let after = memory.snapshot();
    assert_eq!(after.used_bytes, before.used_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(after.attempts, before.attempts + 1);
    let original = receiver.with_report(|report| {
        assert!(report.capacity_refused());
        assert_eq!(report.protocol(), None);
        assert!(!report.has_lease());
        assert!(!report.has_payload());
        assert!(matches!(
            report.construction(),
            TerminalObservation::NotEntered
        ));
        match report.provider() {
            TerminalObservation::Returned(Err(original)) => {
                assert_eq!(original.kind(), io::ErrorKind::OutOfMemory);
                std::ptr::from_ref(original)
            }
            _ => panic!("actual refused provider callback"),
        }
    });
    assert!(!receiver.run_provider_again_for_test());
    receiver.with_report(|report| match report.provider() {
        TerminalObservation::Returned(Err(error)) => {
            assert_eq!(std::ptr::from_ref(error), original);
        }
        _ => panic!("same original refusal remains installed"),
    });
    assert_eq!(memory.snapshot(), after);
    assert_eq!(receiver.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(memory.storage_census().snapshot().databases, 0);
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    drop(pressure);
    assert_eq!(memory.snapshot().used_bytes, 0);
    assert_eq!(memory.snapshot().live_reservations, 0);
}

#[derive(Clone, Copy)]
enum Reentry {
    Duplicate,
    Foreign,
}
struct RefusingMemory {
    census: StorageCensus,
    backing: Arc<TestDiskMemory>,
    foreign: Arc<TestDiskMemory>,
    reentry: Reentry,
    calls: AtomicUsize,
    _bookkeeping: DiskMemoryLease,
}
impl RefusingMemory {
    fn new(reentry: Reentry) -> Arc<Self> {
        let backing = TestDiskMemory::new(LIMIT, CAPACITY);
        let bytes = disk_memory::add(
            disk_memory::arc::<Self>().unwrap(),
            StorageCensus::required_bytes(CAPACITY).unwrap(),
        )
        .unwrap();
        let bookkeeping = backing.clone().reserve_installed(bytes).unwrap();
        let memory = Arc::new(Self {
            census: StorageCensus::allocate(CAPACITY).unwrap(),
            backing,
            foreign: TestDiskMemory::new(LIMIT, CAPACITY),
            reentry,
            calls: AtomicUsize::new(0),
            _bookkeeping: bookkeeping,
        });
        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        memory.census.bind_provider(&provider).unwrap();
        memory
    }
}
impl kasumi_kv::SourceMemoryProvider for RefusingMemory {}
impl NodeDiskMemoryAdmission for RefusingMemory {
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
        let provider: Arc<dyn NodeDiskMemoryAdmission> = self.clone();
        let permit = install.try_begin_bind(provider.clone()).unwrap();
        let bytes = disk_memory::add(
            permit.request_bytes(),
            DiskMemoryLease::token_allocation_bytes::<DiskMemoryLease>()?,
        )?;
        let original = match self.backing.clone().reserve_installed(bytes) {
            Err(original) => original,
            Ok(token) => {
                permit.bind(token);
                panic!("the actual backing must already be saturated")
            }
        };
        assert_eq!(original.kind(), io::ErrorKind::OutOfMemory);
        let original = permit.refuse_capacity(original);
        let (offered, expected) = match self.reentry {
            Reentry::Duplicate => (provider, NativeConstructorCallError::AlreadyEntered),
            Reentry::Foreign => (
                self.foreign.clone() as Arc<dyn NodeDiskMemoryAdmission>,
                NativeConstructorCallError::ForeignProvider,
            ),
        };
        assert_eq!(install.try_begin_bind(offered).err(), Some(expected));
        // A faulty provider returns its exact first refusal despite violating
        // the closed bind protocol. That original must survive uncertified.
        Err(original)
    }
    fn quote_cache_memory(&self, _bytes: u64) -> io::Result<kasumi_kv::CacheMemoryQuote> {
        Err(io::ErrorKind::Unsupported.into())
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        _bytes: u64,
    ) -> io::Result<kasumi_kv::CacheMemoryLease> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

fn assert_reentry_preserves_original_without_certifying_capacity(reentry: Reentry) {
    let memory = RefusingMemory::new(reentry);
    let standing = memory.backing.snapshot();
    let pressure = saturate(&memory.backing);
    let before = memory.backing.snapshot();
    let foreign = memory.foreign.snapshot();
    let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
    let (result, allocations, requested_bytes) = measure_requested(|| {
        memory
            .census
            .register_native(provider.clone(), 0, |_| ProbePayload)
    });
    let failure = result
        .err()
        .expect("actual constructor refusal is retained");
    assert_eq!(
        allocations, 0,
        "actual allocator requested {requested_bytes} bytes"
    );
    assert!(!failure.is_capacity_denied());
    let id = failure.id().unwrap();
    let expected = match reentry {
        Reentry::Duplicate => NativeConstructorCallError::AlreadyEntered,
        Reentry::Foreign => NativeConstructorCallError::ForeignProvider,
    };
    let original = failure.with_report(|report| {
        let report = report.unwrap();
        assert_eq!(report.protocol(), Some(expected));
        assert!(!report.capacity_refused());
        assert!(!report.has_lease());
        assert!(!report.has_payload());
        assert!(matches!(
            report.construction(),
            TerminalObservation::NotEntered
        ));
        match report.provider() {
            TerminalObservation::Returned(Err(error)) => {
                assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
                std::ptr::from_ref(error)
            }
            _ => panic!("exact original provider refusal"),
        }
    });
    drop(failure);
    let retained = memory
        .census
        .retained_native_constructor::<ProbePayload>(provider, id)
        .unwrap();
    retained.with_report(|report| match report.unwrap().provider() {
        TerminalObservation::Returned(Err(error)) => {
            assert_eq!(std::ptr::from_ref(error), original);
        }
        _ => panic!("original survived facade cancellation and protocol violation"),
    });
    assert!(!retained.is_capacity_denied());
    assert_eq!(memory.calls.load(Ordering::Acquire), 1);
    assert_eq!(memory.foreign.snapshot(), foreign);
    let after = memory.backing.snapshot();
    assert_eq!(after.used_bytes, before.used_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    assert_eq!(after.attempts, before.attempts + 1);
    assert_eq!(memory.census.snapshot().databases, 1);
    assert_eq!(retained.cleanup(), StorageCensusDisposition::Retired);
    assert_eq!(memory.census.snapshot().databases, 0);
    assert_eq!(memory.backing.snapshot(), after);
    drop(pressure);
    assert_eq!(memory.backing.snapshot().used_bytes, standing.used_bytes);
    assert_eq!(
        memory.backing.snapshot().live_reservations,
        standing.live_reservations
    );
}

#[test]
fn native_constructor_duplicate_binding_revokes_capacity_certificate_and_keeps_original() {
    assert_reentry_preserves_original_without_certifying_capacity(Reentry::Duplicate);
}

#[test]
fn native_constructor_foreign_binding_revokes_capacity_certificate_and_keeps_original() {
    assert_reentry_preserves_original_without_certifying_capacity(Reentry::Foreign);
}
