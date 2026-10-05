//! Actual native enclosing allocations and their original provider refunds.
//! The image backend qualifies ownership order, not installed filesystem quota.
use super::*;
use crate::NativeCache;
use crate::core::{AdmissionError, OwnerFailed, ResidentLease};
use crate::group::{InMemoryGroup, TransactionReserveError, TransactionSpacePlan};
use crate::root::{ROOT_SLOT_BYTES, RootSlot};
use std::alloc::Layout;
use std::ffi::OsStr;
use std::sync::Barrier;
use std::sync::atomic::AtomicU64;

const GROUP: [u8; 16] = [187; 16];
const TARGET_COUNT: usize = 12;
const SHARED: usize = 0;
const SHARED_GRANT: usize = 1;
const ROOT: usize = 2;
const ROOT_GRANT: usize = 3;
const ARENA: usize = 4;
const ARENA_GRANT: usize = 5;
const ROLL: usize = 6;
const CORE: usize = 7;
const GATE: usize = 8;
const DATABASE: usize = 9;
const BACKEND_CELL: usize = 10;
const BACKEND_BODY: usize = 11;
const DEPENDENCIES: [&[usize]; 3] = [
    &[
        SHARED,
        SHARED_GRANT,
        CORE,
        GATE,
        DATABASE,
        BACKEND_CELL,
        BACKEND_BODY,
    ],
    &[ROOT, ROOT_GRANT],
    &[ARENA, ARENA_GRANT, ROLL],
];
static WATCH_LOCK: Mutex<()> = Mutex::new(());
static TARGETS: [AtomicUsize; TARGET_COUNT] = [const { AtomicUsize::new(0) }; TARGET_COUNT];
static FREED: [AtomicBool; TARGET_COUNT] = [const { AtomicBool::new(false) }; TARGET_COUNT];
static DEALLOCATIONS: [AtomicUsize; TARGET_COUNT] = [const { AtomicUsize::new(0) }; TARGET_COUNT];

// Called only after System.dealloc returns. Data addresses are borrowed from
// actual Arc payloads, so the containing allocation includes its control too.
pub(crate) fn note_deallocation(pointer: *mut u8, layout: Layout) {
    let start = pointer as usize;
    for index in 0..TARGET_COUNT {
        let target = TARGETS[index].load(Ordering::Acquire);
        if target != 0
            && target >= start
            && target - start < layout.size()
            && !FREED[index].swap(true, Ordering::AcqRel)
        {
            DEALLOCATIONS[index].fetch_add(1, Ordering::AcqRel);
        }
    }
}

#[derive(Clone, Copy, Default)]
struct GrantRecord {
    address: usize,
    bytes: u64,
    live: bool,
}
struct Ledger {
    records: Mutex<[GrantRecord; 128]>,
    issued: AtomicUsize,
    used: AtomicU64,
    deny: AtomicU64,
    denied: AtomicUsize,
    failed: AtomicBool,
    watch_ids: [AtomicUsize; 3],
    watch_refunds: [AtomicUsize; 3],
    backend_address: AtomicUsize,
    backend_close_allocations_before: AtomicUsize,
    backend_close_allocations_after: AtomicUsize,
    cache_address: AtomicUsize,
    cache_issued: AtomicUsize,
    cache_bytes: AtomicU64,
    cache_denied: AtomicBool,
}
impl Ledger {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            records: Mutex::new([GrantRecord::default(); 128]),
            issued: AtomicUsize::new(0),
            used: AtomicU64::new(0),
            deny: AtomicU64::new(0),
            denied: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            watch_ids: [const { AtomicUsize::new(0) }; 3],
            watch_refunds: [const { AtomicUsize::new(0) }; 3],
            backend_address: AtomicUsize::new(0),
            backend_close_allocations_before: AtomicUsize::new(usize::MAX),
            backend_close_allocations_after: AtomicUsize::new(usize::MAX),
            cache_address: AtomicUsize::new(0),
            cache_issued: AtomicUsize::new(0),
            cache_bytes: AtomicU64::new(0),
            cache_denied: AtomicBool::new(false),
        })
    }
    fn grant(self: &Arc<Self>, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        if self.failed.load(Ordering::Acquire) {
            return Err(AdmissionError::OwnerFailed);
        }
        if bytes == self.deny.load(Ordering::Acquire) {
            self.denied.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        let id = self.issued.fetch_add(1, Ordering::AcqRel) + 1;
        assert!(id <= 128, "bounded actual fixture grant census");
        let token = Box::new(Token {
            ledger: self.clone(),
            bytes,
            id,
        });
        let address = token.as_ref() as *const Token as usize;
        self.records.lock().unwrap()[id - 1] = GrantRecord {
            address,
            bytes,
            live: true,
        };
        self.used.fetch_add(bytes, Ordering::AcqRel);
        Ok(token)
    }
    fn live_grant_id(&self, address: usize) -> usize {
        let records = self.records.lock().unwrap();
        let issued = self.issued.load(Ordering::Acquire);
        let index = records[..issued]
            .iter()
            .position(|record| record.live && record.address == address)
            .expect("same actual original native provider token");
        assert_ne!(records[index].bytes, 0);
        index + 1
    }
}
struct Token {
    ledger: Arc<Ledger>,
    bytes: u64,
    id: usize,
}
impl Drop for Token {
    fn drop(&mut self) {
        let original_address = self.ledger.records.lock().unwrap()[self.id - 1].address;
        crate::native_sync::tests::assert_retired_for(original_address);
        for (owner, required) in DEPENDENCIES.iter().enumerate() {
            if self.ledger.watch_ids[owner].load(Ordering::Acquire) == self.id {
                for index in *required {
                    assert!(
                        FREED[*index].load(Ordering::Acquire),
                        "actual allocation {index} survives original owner {owner} grant refund"
                    );
                    assert_eq!(DEALLOCATIONS[*index].load(Ordering::Acquire), 1);
                }
                self.ledger.watch_refunds[owner].fetch_add(1, Ordering::AcqRel);
            }
        }
        let mut records = self.ledger.records.lock().unwrap();
        let original = &mut records[self.id - 1];
        assert!(original.live, "original token refunded once");
        assert_eq!(original.bytes, self.bytes);
        original.live = false;
        self.ledger.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
struct Admission(Arc<Ledger>);
impl StorageAdmission for Admission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        if self.0.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.0.grant(bytes)
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        self.check_owner()
    }
    fn owner_failed(&self) {
        self.0.failed.store(true, Ordering::Release);
    }
    fn quote_cache_memory(&self, bytes: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        let actual = crate::cache_test::reserve(self.clone(), bytes)?;
        self.0
            .cache_address
            .store(actual.allocation_address_for_test(), Ordering::Release);
        Ok(actual)
    }
}
impl crate::cache_test::Provider for Admission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), AdmissionError> {
        if self.0.cache_denied.load(Ordering::Acquire) {
            return Err(AdmissionError::CapacityDenied);
        }
        if first {
            self.0.cache_issued.fetch_add(1, Ordering::AcqRel);
        }
        self.0.cache_bytes.fetch_add(bytes, Ordering::AcqRel);
        Ok(())
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        if last {
            crate::native_sync::tests::assert_retired_for(
                self.0.cache_address.load(Ordering::Acquire),
            );
        }
        self.0.cache_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }
}
fn fixture() -> (Database, InMemoryGroup, Arc<Ledger>) {
    let ledger = Ledger::new();
    let group = InMemoryGroup::new();
    let database = Database::builder(
        Arc::new(Admission(ledger.clone())),
        GROUP,
        CacheConfig { byte_limit: 0 },
    )
    .create_with_backend(group.clone())
    .unwrap();
    (database, group, ledger)
}
struct Watch;
impl Watch {
    fn new(database: &Database, ledger: &Ledger) -> Self {
        let original = database.inner.core.owner_allocation_addresses_for_test();
        let backend = database.inner.core.backend_allocation_addresses_for_test();
        let addresses = [
            original[0],
            original[1],
            original[2],
            original[3],
            original[4],
            original[5],
            original[6],
            database.inner.core.as_ref() as *const Core as usize,
            database.inner.gate.as_ref() as *const WriterGate as usize,
            database.inner.as_ref() as *const DatabaseInner as usize,
            backend[0],
            backend[1],
        ];
        for (index, address) in addresses.into_iter().enumerate() {
            assert_ne!(address, 0);
            assert!(!addresses[..index].contains(&address));
            FREED[index].store(false, Ordering::Release);
            DEALLOCATIONS[index].store(0, Ordering::Release);
            TARGETS[index].store(address, Ordering::Release);
        }
        for (owner, grant) in [SHARED_GRANT, ROOT_GRANT, ARENA_GRANT]
            .into_iter()
            .enumerate()
        {
            ledger.watch_ids[owner]
                .store(ledger.live_grant_id(addresses[grant]), Ordering::Release);
        }
        Self
    }
    fn assert_all_retired(&self, ledger: &Ledger) {
        assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
        assert!(
            DEALLOCATIONS
                .iter()
                .all(|calls| calls.load(Ordering::Acquire) == 1)
        );
        assert!(
            ledger
                .watch_refunds
                .iter()
                .all(|calls| calls.load(Ordering::Acquire) == 1)
        );
        assert_eq!(ledger.used.load(Ordering::Acquire), 0);
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        for target in &TARGETS {
            target.store(0, Ordering::Release);
        }
    }
}

#[test]
fn native_closed_arc_actual_aliases_keep_original_grants_until_controls_retire() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let sync = crate::native_sync::tests::Watch::new();
    let (database, group, ledger) = fixture();
    assert_constructor_sync(&sync, &ledger);
    let issued = ledger.issued.load(Ordering::Acquire);
    let counting = super::read_fork_tests::AllocationCount::start();
    let admission = database.transaction_admission();
    let after_admission = (counting.count(), counting.layouts(), counting.addresses());
    let writer = WriterGate::enter(&database.inner.gate, &database.inner.closing).unwrap();
    let after_writer = (counting.count(), counting.layouts(), counting.addresses());
    let source = database.inner.core.source_context().unwrap();
    let after_source = (counting.count(), counting.layouts(), counting.addresses());
    drop(counting);
    eprintln!(
        "actual closed-owner alias allocations: admission={after_admission:?}; writer={after_writer:?}; source={after_source:?}; grants before={issued}, after={}",
        ledger.issued.load(Ordering::Acquire)
    );
    assert_eq!(after_source.0, 0, "actual aliases allocate no new controls");
    assert_eq!(
        ledger.issued.load(Ordering::Acquire),
        issued,
        "aliases reuse original grants"
    );
    let point = database.inner.core.prepare_point_read(8).unwrap();
    let watch = Watch::new(&database, &ledger);
    assert_eq!(
        database.inner.core.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
    let mut disposal = database.into_disposal();
    assert!(
        !disposal.dispose().complete(),
        "live admission alias refuses actual control disposal"
    );
    assert!(
        !FREED[DATABASE].load(Ordering::Acquire),
        "transaction admission keeps exact facade"
    );
    drop(admission);
    assert!(
        !disposal.dispose().complete(),
        "live writer lease refuses gate disposal"
    );
    assert!(FREED[DATABASE].load(Ordering::Acquire));
    assert!(
        !FREED[GATE].load(Ordering::Acquire),
        "writer lease keeps exact gate"
    );
    assert!(!FREED[CORE].load(Ordering::Acquire));
    drop(writer);
    assert!(
        !disposal.dispose().complete(),
        "source aliases refuse Shared disposal"
    );
    assert!(FREED[GATE].load(Ordering::Acquire));
    assert!(FREED[CORE].load(Ordering::Acquire));
    assert!(
        !FREED[SHARED].load(Ordering::Acquire),
        "source/prepared point keep exact shared owner"
    );
    drop(source);
    assert!(
        !FREED[SHARED].load(Ordering::Acquire),
        "prepared point remains an original alias"
    );
    drop(point);
    assert!(disposal.dispose().complete());
    assert_eq!(ledger.watch_refunds[1].load(Ordering::Acquire), 1);
    assert_eq!(ledger.watch_refunds[2].load(Ordering::Acquire), 1);
    assert_eq!(ledger.watch_refunds[0].load(Ordering::Acquire), 1);
    watch.assert_all_retired(&ledger);
    sync.assert_all_retired();
    assert_eq!(
        group.close_attempts(),
        1,
        "owner disposal never replays native close"
    );
}

#[test]
fn native_closed_arc_concurrent_final_aliases_retire_original_controls_once() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let sync = crate::native_sync::tests::Watch::new();
    let (database, group, ledger) = fixture();
    assert_constructor_sync(&sync, &ledger);
    let issued = ledger.issued.load(Ordering::Acquire);
    let counting = super::read_fork_tests::AllocationCount::start();
    let left = (
        database.transaction_admission(),
        database.inner.core.source_context().unwrap(),
    );
    let after_left = (counting.count(), counting.layouts(), counting.addresses());
    let right = (
        database.transaction_admission(),
        database.inner.core.source_context().unwrap(),
    );
    let after_right = (counting.count(), counting.layouts(), counting.addresses());
    drop(counting);
    eprintln!(
        "actual closed-owner concurrent alias allocations: left={after_left:?}; right={after_right:?}; grants before={issued}, after={}",
        ledger.issued.load(Ordering::Acquire)
    );
    assert_eq!(
        after_right.0, 0,
        "actual final aliases allocate no new controls"
    );
    assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
    let watch = Watch::new(&database, &ledger);
    assert_eq!(
        database.inner.core.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
    let mut disposal = database.into_disposal();
    assert!(!disposal.dispose().complete());
    assert!(!FREED[DATABASE].load(Ordering::Acquire));
    assert!(!FREED[SHARED].load(Ordering::Acquire));
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        for (admission, source) in [left, right] {
            let barrier = &barrier;
            scope.spawn(move || {
                barrier.wait();
                drop(admission);
                drop(source);
            });
        }
    });
    assert!(disposal.dispose().complete());
    watch.assert_all_retired(&ledger);
    sync.assert_all_retired();
    assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
    assert_eq!(group.close_attempts(), 1);
}

#[test]
fn successful_native_create_and_reopen_release_constructor_provider_binding() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    for facade in [false, true] {
        let mut group = InMemoryGroup::new();
        for create in [true, false] {
            let sync = crate::native_sync::tests::Watch::new();
            let ledger = Ledger::new();
            // Workspace tokens own the ledger, not this provider. A leaked
            // constructor binding therefore keeps this exact Weak live.
            let provider = Arc::new(Admission(ledger.clone()));
            let weak = Arc::downgrade(&provider);
            let admission: Arc<dyn StorageAdmission> = provider.clone();
            let mut disposal = if facade {
                let builder = Database::builder(admission, GROUP, CacheConfig { byte_limit: 0 });
                let database = if create {
                    builder.create_with_backend(group.clone())
                } else {
                    builder.open_with_backend(group.clone())
                }
                .unwrap();
                drop(provider);
                assert!(
                    weak.upgrade().is_some(),
                    "actual facade still owns provider"
                );
                assert_eq!(
                    database.inner.core.close().native_disposition(),
                    BackendNativeDisposition::Drained
                );
                database.into_disposal()
            } else {
                let core = if create {
                    Core::create_with_backend(
                        group.clone(),
                        admission,
                        GROUP,
                        CacheConfig { byte_limit: 0 },
                    )
                } else {
                    Core::open_with_backend(
                        group.clone(),
                        admission,
                        GROUP,
                        CacheConfig { byte_limit: 0 },
                    )
                }
                .unwrap();
                drop(provider);
                assert!(weak.upgrade().is_some(), "actual Core still owns provider");
                assert_eq!(
                    core.close().native_disposition(),
                    BackendNativeDisposition::Drained
                );
                core.into_disposal()
            };
            assert!(
                disposal.dispose().complete(),
                "actual native owners must retire"
            );
            drop(disposal);
            sync.assert_all_retired();
            assert_eq!(ledger.used.load(Ordering::Acquire), 0);
            assert_eq!(ledger.cache_bytes.load(Ordering::Acquire), 0);
            assert!(!ledger.failed.load(Ordering::Acquire));
            assert_eq!(
                group.close_attempts(),
                1,
                "disposal must not replay native close"
            );
            assert!(
                weak.upgrade().is_none(),
                "successful constructor must release its original provider binding after native disposal: facade={facade}, create={create}"
            );
            if create {
                group = group.crash();
            }
        }
    }
}

// First denial keeps the original sized backend inline. Its exact close
// callback identifies that same original without a Kasumi erasure allocation.
struct Backend {
    group: InMemoryGroup,
    ledger: Arc<Ledger>,
    drop_panic: Option<crate::CorePanic>,
}
impl Drop for Backend {
    fn drop(&mut self) {
        if let Some(original) = self.drop_panic.take() {
            assert!(!FREED[BACKEND_CELL].load(Ordering::Acquire));
            assert!(!FREED[SHARED_GRANT].load(Ordering::Acquire));
            let grant = self.ledger.watch_ids[0].load(Ordering::Acquire);
            assert_ne!(grant, 0);
            assert!(self.ledger.records.lock().unwrap()[grant - 1].live);
            std::panic::resume_unwind(original.into_payload_for_test());
        }
    }
}
impl SegmentGroupBackend for Backend {
    fn reserve_transaction(
        &self,
        plan: &TransactionSpacePlan,
    ) -> Result<(), TransactionReserveError> {
        self.group.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.group.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.group.cancel_transaction(group_id, batch_seq)
    }
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.group.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.group.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.group.sync_root()
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.group.visit_entries(visitor)
    }
    fn exists(&self, file: crate::GroupFile) -> io::Result<bool> {
        self.group.exists(file)
    }
    fn create(&self, file: crate::GroupFile) -> io::Result<()> {
        self.group.create(file)
    }
    fn len(&self, file: crate::GroupFile) -> io::Result<u64> {
        self.group.len(file)
    }
    fn read(&self, file: crate::GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.group.read(file, at, out)
    }
    fn write(&self, file: crate::GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.group.write(file, at, bytes)
    }
    fn set_len(&self, file: crate::GroupFile, len: u64) -> io::Result<()> {
        self.group.set_len(file, len)
    }
    fn sync(&self, file: crate::GroupFile) -> io::Result<()> {
        self.group.sync(file)
    }
    fn unlink(&self, file: crate::GroupFile) -> io::Result<()> {
        self.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.group.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        if let Some(count) = super::read_fork_tests::AllocationCount::current_count_if_enabled() {
            self.ledger
                .backend_close_allocations_before
                .store(count, Ordering::Release);
        }
        self.ledger
            .backend_address
            .store(self as *const Self as usize, Ordering::Release);
        let outcome = self.group.close();
        if let Some(count) = super::read_fork_tests::AllocationCount::current_count_if_enabled() {
            self.ledger
                .backend_close_allocations_after
                .store(count, Ordering::Release);
        }
        outcome
    }
}

// Actual allocator refusals happen after the original shell grant is issued.
// The over-aligned original body has a distinct layout from its grant/control.
#[derive(Default)]
struct ConstructorProbe {
    control_allocated: bool,
    issued: AtomicUsize,
    used: AtomicU64,
    token_address: AtomicUsize,
    native_calls: AtomicUsize,
    closes: AtomicUsize,
    drops: AtomicUsize,
    body_returned: AtomicBool,
    callbacks: AtomicUsize,
    refunds: AtomicUsize,
    owner_failures: AtomicUsize,
}
struct ConstructorWatch;
impl ConstructorWatch {
    fn new() -> Self {
        for index in 0..TARGET_COUNT {
            TARGETS[index].store(0, Ordering::Release);
            FREED[index].store(false, Ordering::Release);
            DEALLOCATIONS[index].store(0, Ordering::Release);
        }
        Self
    }
}
impl Drop for ConstructorWatch {
    fn drop(&mut self) {
        for target in &TARGETS {
            target.store(0, Ordering::Release);
        }
    }
}
struct ConstructorToken {
    probe: Arc<ConstructorProbe>,
    bytes: u64,
    original_panic: Option<crate::CorePanic>,
}
impl Drop for ConstructorToken {
    fn drop(&mut self) {
        assert_eq!(self.probe.callbacks.fetch_add(1, Ordering::AcqRel), 0);
        assert_eq!(self.probe.closes.load(Ordering::Acquire), 1);
        assert_eq!(self.probe.drops.load(Ordering::Acquire), 1);
        assert!(self.probe.body_returned.load(Ordering::Acquire));
        assert_eq!(self.probe.native_calls.load(Ordering::Acquire), 0);
        assert_eq!(self.probe.used.load(Ordering::Acquire), self.bytes);
        assert!(FREED[SHARED_GRANT].load(Ordering::Acquire));
        assert_eq!(DEALLOCATIONS[SHARED_GRANT].load(Ordering::Acquire), 1);
        crate::native_sync::tests::assert_retired_for(
            self.probe.token_address.load(Ordering::Acquire),
        );
        if self.probe.control_allocated {
            assert!(FREED[BACKEND_CELL].load(Ordering::Acquire));
            assert_eq!(DEALLOCATIONS[BACKEND_CELL].load(Ordering::Acquire), 1);
        } else {
            assert_eq!(TARGETS[BACKEND_CELL].load(Ordering::Acquire), 0);
            assert!(!FREED[BACKEND_CELL].load(Ordering::Acquire));
            assert_eq!(DEALLOCATIONS[BACKEND_CELL].load(Ordering::Acquire), 0);
        }
        if let Some(original) = self.original_panic.take() {
            // The actual opaque token callback did not return or refund.
            std::panic::resume_unwind(original.into_payload_for_test());
        }
        self.probe.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.probe.refunds.fetch_add(1, Ordering::AcqRel);
    }
}
struct ConstructorAdmission {
    probe: Arc<ConstructorProbe>,
    request: u64,
    refused_layout: Layout,
    original_panic: Mutex<Option<crate::CorePanic>>,
}
impl StorageAdmission for ConstructorAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        assert_eq!(
            bytes, self.request,
            "same prospectively checked shell quote"
        );
        assert_eq!(self.probe.issued.fetch_add(1, Ordering::AcqRel), 0);
        let token = Box::new(ConstructorToken {
            probe: self.probe.clone(),
            bytes,
            original_panic: self.original_panic.lock().unwrap().take(),
        });
        let address = token.as_ref() as *const ConstructorToken as usize;
        self.probe.token_address.store(address, Ordering::Release);
        TARGETS[SHARED_GRANT].store(address, Ordering::Release);
        self.probe.used.store(bytes, Ordering::Release);
        // The real original token Box and census debit precede null injection.
        super::read_fork_tests::AllocationRefusal::arm_after_grant(self.refused_layout);
        Ok(token)
    }
    fn quote_cache_memory(&self, _: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        Err(AdmissionError::CapacityDenied)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        _: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        Err(AdmissionError::CapacityDenied)
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        panic!("actual constructor allocation refusal precedes growth admission")
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        panic!("actual constructor allocation refusal precedes growth settlement")
    }
    fn owner_failed(&self) {
        self.probe.owner_failures.fetch_add(1, Ordering::AcqRel);
    }
}
#[repr(align(64))]
struct ConstructorBackend {
    group: InMemoryGroup,
    probe: Arc<ConstructorProbe>,
    identity: u64,
    original_panic: Option<crate::CorePanic>,
}
impl Drop for ConstructorBackend {
    fn drop(&mut self) {
        assert_eq!(self.identity, 0xc7ad_034b_61f9);
        assert_eq!(self.probe.drops.fetch_add(1, Ordering::AcqRel), 0);
        assert_eq!(self.probe.closes.load(Ordering::Acquire), 1);
        assert_ne!(self.probe.used.load(Ordering::Acquire), 0);
        assert_eq!(self.probe.callbacks.load(Ordering::Acquire), 0);
        assert!(!FREED[SHARED_GRANT].load(Ordering::Acquire));
        if self.probe.control_allocated {
            assert_ne!(TARGETS[BACKEND_CELL].load(Ordering::Acquire), 0);
            assert!(!FREED[BACKEND_CELL].load(Ordering::Acquire));
        }
        if let Some(original) = self.original_panic.take() {
            std::panic::resume_unwind(original.into_payload_for_test());
        }
        self.probe.body_returned.store(true, Ordering::Release);
    }
}
impl SegmentGroupBackend for ConstructorBackend {
    fn reserve_transaction(
        &self,
        plan: &TransactionSpacePlan,
    ) -> Result<(), TransactionReserveError> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.cancel_transaction(group_id, batch_seq)
    }
    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.sync_root()
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.visit_entries(visitor)
    }
    fn exists(&self, file: crate::GroupFile) -> io::Result<bool> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.exists(file)
    }
    fn create(&self, file: crate::GroupFile) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.create(file)
    }
    fn len(&self, file: crate::GroupFile) -> io::Result<u64> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.len(file)
    }
    fn read(&self, file: crate::GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.read(file, at, out)
    }
    fn write(&self, file: crate::GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.write(file, at, bytes)
    }
    fn set_len(&self, file: crate::GroupFile, len: u64) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.set_len(file, len)
    }
    fn sync(&self, file: crate::GroupFile) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.sync(file)
    }
    fn unlink(&self, file: crate::GroupFile) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.probe.native_calls.fetch_add(1, Ordering::AcqRel);
        self.group.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.probe.closes.fetch_add(1, Ordering::AcqRel);
        self.group.close()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RefusedBacking {
    Control,
    Body,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RefusalPanic {
    None,
    Grant,
    InlineBody,
}
struct OriginalConstructorPanic(u64);
fn constructor_panic(enabled: bool, identity: u64) -> (Option<crate::CorePanic>, usize) {
    if !enabled {
        return (None, 0);
    }
    let original = Box::new(OriginalConstructorPanic(identity));
    let address = original.as_ref() as *const OriginalConstructorPanic as usize;
    (Some(crate::CorePanic::new(original)), address)
}
fn assert_constructor_allocation_refusal(backing: RefusedBacking, panic: RefusalPanic) {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let _watch = ConstructorWatch::new();
    let control = crate::native_backend::BackendOwner::control_allocation_layout_for_test()
        .expect("checked actual native backend control layout");
    let body = Layout::new::<ConstructorBackend>();
    assert_ne!(control, body);
    assert_ne!(control, Layout::new::<ConstructorToken>());
    assert_ne!(body, Layout::new::<ConstructorToken>());
    let probe = Arc::new(ConstructorProbe {
        control_allocated: backing == RefusedBacking::Body,
        ..ConstructorProbe::default()
    });
    let group = InMemoryGroup::new();
    let request =
        Core::shell_request_bytes::<ConstructorBackend>().expect("checked native shell quote");
    let (grant_panic, grant_panic_address) =
        constructor_panic(panic == RefusalPanic::Grant, 0x7abc);
    let (body_panic, body_panic_address) =
        constructor_panic(panic == RefusalPanic::InlineBody, 0x7def);
    let provider = Arc::new(ConstructorAdmission {
        probe: probe.clone(),
        request,
        refused_layout: if backing == RefusedBacking::Control {
            control
        } else {
            body
        },
        original_panic: Mutex::new(grant_panic),
    });
    // Warm only this fixture-owned callback lock before observing the opening.
    drop(provider.original_panic.lock().unwrap());
    let backend = ConstructorBackend {
        group: group.clone(),
        probe: probe.clone(),
        identity: 0xc7ad_034b_61f9,
        original_panic: body_panic,
    };
    let refusal = super::read_fork_tests::AllocationRefusal::start();
    let counting = super::read_fork_tests::AllocationCount::start();
    let mut failure = match Core::create_with_backend(
        backend,
        provider,
        [189; 16],
        CacheConfig { byte_limit: 0 },
    ) {
        Err(original) => original,
        Ok(_) => panic!("actual admitted backend allocation must return null"),
    };
    refusal.assert_denied();
    let original = failure
        .original_error()
        .expect("original allocation failure");
    assert!(matches!(original.rejected_cause(),
        Some(crate::CoreErrorCause::AllocationRefused(error))
            if error.kind() == io::ErrorKind::OutOfMemory));
    assert!(original.is_capacity_denied());
    assert!(!original.fences_owner());
    let original_io_address = original.io_error().unwrap() as *const io::Error as usize;
    assert!(!failure.opening_returned_ok());
    let retained = failure
        .backend()
        .expect("original sized backend remains inline");
    assert!(Arc::ptr_eq(&retained.probe, &probe));
    assert_eq!(retained.identity, 0xc7ad_034b_61f9);
    let close = failure
        .close_report()
        .expect("actual original close returned");
    assert_eq!(close.entry(), BackendCloseEntry::Entered);
    assert_eq!(
        close.native_disposition(),
        BackendNativeDisposition::Drained
    );
    assert_eq!(
        failure.native_disposition(),
        BackendNativeDisposition::Drained
    );
    assert!(failure.close_panic().is_none());
    assert!(failure.retry_close_report().is_none());
    assert_eq!(probe.native_calls.load(Ordering::Acquire), 0);
    assert_eq!(probe.closes.load(Ordering::Acquire), 1);
    assert_eq!(group.close_attempts(), 1);
    assert_eq!(probe.issued.load(Ordering::Acquire), 1);
    assert_eq!(probe.used.load(Ordering::Acquire), request);
    assert_eq!(probe.drops.load(Ordering::Acquire), 0);
    assert_eq!(probe.callbacks.load(Ordering::Acquire), 0);
    assert_eq!(probe.refunds.load(Ordering::Acquire), 0);
    assert_eq!(probe.owner_failures.load(Ordering::Acquire), 0);
    let count = counting.count();
    assert!(count <= 8, "complete bounded actual allocation observation");
    let layouts = counting.layouts();
    let addresses = counting.addresses();
    let retirements = counting.retirements();
    let mut control_count = 0;
    for index in 0..count {
        if layouts[index] == (control.size(), control.align()) {
            control_count += 1;
            assert!(
                !retirements[index],
                "actual pending control stays owned before disposal"
            );
            TARGETS[BACKEND_CELL].store(addresses[index], Ordering::Release);
        }
    }
    assert_eq!(control_count, usize::from(probe.control_allocated));
    assert!((0..count).all(|index| layouts[index] != (body.size(), body.align())));
    let token_index = (0..count)
        .find(|index| addresses[*index] == probe.token_address.load(Ordering::Acquire))
        .expect("same actual original provider token Box");
    assert!(!retirements[token_index]);
    let observations = failure.disposal().observation_count();
    for index in [0, observations - 3, observations - 2, observations - 1] {
        failure.disposal().with_observation(index, |observation| {
            assert!(matches!(
                observation,
                crate::TerminalObservation::NotEntered
            ));
        });
    }
    for _ in 0..2 {
        let report = failure.dispose();
        assert_eq!(report.complete(), panic == RefusalPanic::None);
        report.with_observation(0, |observation| {
            if panic == RefusalPanic::InlineBody {
                let crate::TerminalObservation::Panicked(payload) = observation else {
                    panic!("original inline body callback panic stays owned");
                };
                let original = payload.downcast_ref::<OriginalConstructorPanic>().unwrap();
                assert_eq!(original.0, 0x7def);
                assert_eq!(
                    original as *const OriginalConstructorPanic as usize,
                    body_panic_address
                );
            } else {
                assert!(matches!(
                    observation,
                    crate::TerminalObservation::Returned(Ok(()))
                ));
            }
        });
        report.with_observation(observations - 3, |observation| {
            assert!(matches!(
                observation,
                crate::TerminalObservation::NotEntered
            ));
        });
        report.with_observation(observations - 2, |observation| {
            if probe.control_allocated && panic != RefusalPanic::InlineBody {
                assert!(matches!(
                    observation,
                    crate::TerminalObservation::Returned(Ok(()))
                ));
            } else {
                assert!(matches!(
                    observation,
                    crate::TerminalObservation::NotEntered
                ));
            }
        });
        report.with_observation(observations - 1, |observation| match panic {
            RefusalPanic::None => {
                assert!(matches!(
                    observation,
                    crate::TerminalObservation::Returned(Ok(()))
                ));
            }
            RefusalPanic::InlineBody => {
                assert!(matches!(
                    observation,
                    crate::TerminalObservation::NotEntered
                ));
            }
            RefusalPanic::Grant => {
                let crate::TerminalObservation::Panicked(payload) = observation else {
                    panic!("original grant callback panic stays owned");
                };
                let original = payload.downcast_ref::<OriginalConstructorPanic>().unwrap();
                assert_eq!(original.0, 0x7abc);
                assert_eq!(
                    original as *const OriginalConstructorPanic as usize,
                    grant_panic_address
                );
            }
        });
        assert_eq!(
            failure.original_error().unwrap().io_error().unwrap() as *const io::Error as usize,
            original_io_address
        );
        assert!(failure.backend().is_none());
        assert_eq!(probe.drops.load(Ordering::Acquire), 1);
        assert_eq!(probe.closes.load(Ordering::Acquire), 1);
        assert_eq!(group.close_attempts(), 1);
        assert_eq!(probe.issued.load(Ordering::Acquire), 1);
        assert_eq!(probe.owner_failures.load(Ordering::Acquire), 0);
        assert_eq!(
            probe.callbacks.load(Ordering::Acquire),
            usize::from(panic != RefusalPanic::InlineBody)
        );
        assert_eq!(
            probe.refunds.load(Ordering::Acquire),
            usize::from(panic == RefusalPanic::None)
        );
        assert_eq!(
            probe.used.load(Ordering::Acquire),
            if panic == RefusalPanic::None {
                0
            } else {
                request
            }
        );
        if panic == RefusalPanic::InlineBody {
            assert!(!probe.body_returned.load(Ordering::Acquire));
            assert!(!FREED[BACKEND_CELL].load(Ordering::Acquire));
            assert!(!FREED[SHARED_GRANT].load(Ordering::Acquire));
        }
    }
    drop(failure);
    drop(group);
    if panic == RefusalPanic::InlineBody {
        assert!(!FREED[BACKEND_CELL].load(Ordering::Acquire));
        assert!(!FREED[SHARED_GRANT].load(Ordering::Acquire));
        assert_eq!(probe.callbacks.load(Ordering::Acquire), 0);
        assert_eq!(probe.refunds.load(Ordering::Acquire), 0);
        assert_eq!(probe.used.load(Ordering::Acquire), request);
        assert!(!counting.all_actual_allocations_retired());
    } else {
        assert!(counting.all_actual_allocations_retired());
    }
    refusal.assert_denied();
    drop(counting);
}
#[test]
fn native_backend_control_allocation_refusal_retains_original_body_and_grant() {
    assert_constructor_allocation_refusal(RefusedBacking::Control, RefusalPanic::None);
}
#[test]
fn native_backend_body_allocation_refusal_retires_actual_pending_control_before_grant() {
    assert_constructor_allocation_refusal(RefusedBacking::Body, RefusalPanic::None);
}
#[test]
fn native_backend_allocation_refusal_retains_original_grant_callback_panic_once() {
    assert_constructor_allocation_refusal(RefusedBacking::Body, RefusalPanic::Grant);
}
#[test]
fn native_backend_inline_body_panic_after_allocation_refusal_keeps_pending_control_and_grant() {
    assert_constructor_allocation_refusal(RefusedBacking::Body, RefusalPanic::InlineBody);
}

#[test]
fn native_closed_arc_shell_refusal_allocates_no_closed_controls_and_preserves_original_owner() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let sync = crate::native_sync::tests::Watch::new();
    let (database, group, ledger) = fixture();
    assert_constructor_sync(&sync, &ledger);
    let original_sync_count = sync.count();
    let original_addresses = database.inner.core.owner_allocation_addresses_for_test();
    let issued = ledger.issued.load(Ordering::Acquire);
    let used = ledger.used.load(Ordering::Acquire);
    let denied_group = InMemoryGroup::new();
    let backend = Backend {
        group: denied_group.clone(),
        ledger: ledger.clone(),
        drop_panic: None,
    };
    let provider: Arc<dyn StorageAdmission> = Arc::new(Admission(ledger.clone()));
    ledger.deny.store(
        Core::shell_request_bytes::<Backend>().expect("checked native shell quote"),
        Ordering::Release,
    );
    let counting = super::read_fork_tests::AllocationCount::start();
    let refused =
        Core::create_with_backend(backend, provider, [188; 16], CacheConfig { byte_limit: 0 });
    let mut actual = match refused {
        Err(actual) => actual,
        Ok(_) => panic!("actual first shell admission must refuse"),
    };
    assert!(actual.original_error().unwrap().is_capacity_denied());
    let observations = (counting.count(), counting.layouts(), counting.addresses());
    // First denial constructs no Kasumi backend box, cell, shared control or
    // diagnostic shell. The original callback-owned Mutex stays explicit.
    assert_eq!(
        sync.count(),
        original_sync_count,
        "first-grant refusal constructs zero funded native synchronization controls"
    );
    assert_eq!(
        ledger
            .backend_close_allocations_before
            .load(Ordering::Acquire),
        0,
        "first admission refusal precedes every Kasumi allocation"
    );
    let callback_controls = usize::from(crate::native_sync::mutex_backing_bytes() != 0);
    assert_eq!(
        ledger
            .backend_close_allocations_after
            .load(Ordering::Acquire),
        callback_controls,
        "original backend close initializes only its own platform mutex"
    );
    assert_eq!(
        observations.0,
        ledger
            .backend_close_allocations_after
            .load(Ordering::Acquire),
        "failed-open adds no closed owner control or diagnostic shell after original close"
    );
    let backend_address = ledger.backend_address.load(Ordering::Acquire);
    assert_ne!(backend_address, 0, "actual original close callback ran");
    for index in 0..observations.0 {
        let (bytes, _) = observations.1[index];
        let start = observations.2[index];
        assert!(
            backend_address < start || backend_address - start >= bytes,
            "original inline backend is outside every actual heap allocation"
        );
    }
    if callback_controls != 0 {
        #[cfg(unix)]
        assert_eq!(
            observations.1[0],
            (
                size_of::<libc::pthread_mutex_t>(),
                std::mem::align_of::<libc::pthread_mutex_t>()
            )
        );
        assert!(
            !counting.retirements()[0],
            "exact external image alias holds its callback Mutex"
        );
    }
    assert_eq!(denied_group.close_attempts(), 1);
    assert!(
        actual.dispose().complete(),
        "actual inline body disposal is independent from native drain"
    );
    if callback_controls != 0 {
        assert!(!counting.retirements()[0]);
    }
    drop(denied_group);
    assert!(
        counting.all_actual_allocations_retired(),
        "original external callback Mutex retires only after its actual final alias"
    );
    assert_eq!(counting.count(), observations.0);
    drop(counting);
    assert_eq!(ledger.denied.load(Ordering::Acquire), 1);
    assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
    assert_eq!(ledger.used.load(Ordering::Acquire), used);
    assert!(!database.inner.core.is_fenced());
    assert!(!ledger.failed.load(Ordering::Acquire));
    assert_eq!(
        database.inner.core.owner_allocation_addresses_for_test(),
        original_addresses
    );
    database.close_native().into_result().unwrap();
    let mut disposal = database.into_disposal();
    assert!(disposal.dispose().complete());
    assert_eq!(group.close_attempts(), 1);
    assert_eq!(ledger.used.load(Ordering::Acquire), 0);
    sync.assert_all_retired();
}

#[test]
fn native_backend_body_panic_keeps_same_authoritative_cell_and_original_grant() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let sync = crate::native_sync::tests::Watch::new();
    let ledger = Ledger::new();
    let group = InMemoryGroup::new();
    struct OriginalBodyPanic(u64);
    let original = Box::new(OriginalBodyPanic(0x19a3));
    let original_address = original.as_ref() as *const OriginalBodyPanic as usize;
    let database = Database::builder(
        Arc::new(Admission(ledger.clone())),
        GROUP,
        CacheConfig { byte_limit: 0 },
    )
    .create_with_backend(Backend {
        group: group.clone(),
        ledger: ledger.clone(),
        drop_panic: Some(crate::CorePanic::new(original)),
    })
    .unwrap();
    let issued = ledger.issued.load(Ordering::Acquire);
    let _watch = Watch::new(&database, &ledger);
    assert_eq!(
        database.inner.core.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
    let mut disposal = database.into_disposal();
    for _ in 0..2 {
        let report = disposal.dispose();
        assert!(!report.complete(), "body panic never qualifies as disposed");
        let mut observed = 0;
        for index in 0..report.observation_count() {
            report.with_observation(index, |observation| {
                if let crate::TerminalObservation::Panicked(payload) = observation {
                    let original = payload
                        .downcast_ref::<OriginalBodyPanic>()
                        .expect("exact original body payload");
                    assert_eq!(original.0, 0x19a3);
                    assert_eq!(
                        original as *const OriginalBodyPanic as usize,
                        original_address
                    );
                    observed += 1;
                }
            });
        }
        assert_eq!(observed, 1);
        assert!(
            FREED[BACKEND_BODY].load(Ordering::Acquire),
            "actual consumed Box backing retired during unwind"
        );
        assert!(
            !FREED[BACKEND_CELL].load(Ordering::Acquire),
            "same authoritative control stays live"
        );
        assert!(
            !FREED[SHARED_GRANT].load(Ordering::Acquire),
            "same actual grant Box stays live"
        );
        assert_eq!(ledger.watch_refunds[0].load(Ordering::Acquire), 0);
        assert_eq!(ledger.issued.load(Ordering::Acquire), issued);
        assert_eq!(
            group.close_attempts(),
            1,
            "pure disposal retry never replays native close"
        );
    }
    assert!(ledger.used.load(Ordering::Acquire) > 0);
    // Report abandonment retains the exact cell/grant; it cannot refund a body
    // whose original destructor panic remains unresolved.
    drop(disposal);
    assert_eq!(ledger.watch_refunds[0].load(Ordering::Acquire), 0);
    assert!(!FREED[BACKEND_CELL].load(Ordering::Acquire));
    drop(sync);
}

fn assert_constructor_sync(sync: &crate::native_sync::tests::Watch, ledger: &Ledger) {
    let mutex_controls = usize::from(crate::native_sync::mutex_backing_bytes() != 0);
    let condvar_controls = usize::from(crate::native_sync::condvar_backing_bytes() != 0);
    assert_eq!(
        sync.count(),
        7 * mutex_controls + condvar_controls,
        "actual Shared/Gate/Root/Arena/Pin/Disk-cache controls were initialized under their original grants"
    );
    for index in 0..sync.count() {
        let (funding, address, bytes, align, freed) = sync.record(index);
        assert_ne!(address, 0);
        ledger.live_grant_id(funding);
        assert!(!freed);
        #[cfg(unix)]
        assert!(
            (bytes, align)
                == (
                    size_of::<libc::pthread_mutex_t>(),
                    std::mem::align_of::<libc::pthread_mutex_t>()
                )
                || (bytes, align)
                    == (
                        size_of::<libc::pthread_cond_t>(),
                        std::mem::align_of::<libc::pthread_cond_t>()
                    ),
            "actual synchronization allocation must match the prospectively quoted pinned platform representation"
        );
    }
}

#[test]
fn native_cache_pool_sync_backing_uses_original_optional_grant_until_final_value() {
    let sync = crate::native_sync::tests::Watch::new();
    let ledger = Ledger::new();
    let admission: Arc<dyn StorageAdmission> = Arc::new(Admission(ledger.clone()));
    let mut cache = NativeCache::<u64>::new(
        CacheConfig {
            byte_limit: 1 << 20,
        },
        admission,
    );
    ledger.cache_denied.store(true, Ordering::Release);
    let loaded = AtomicUsize::new(0);
    let counting = super::read_fork_tests::AllocationCount::start();
    assert!(
        cache
            .load_if_fits(1, 4, |_| {
                loaded.fetch_add(1, Ordering::AcqRel);
                Ok::<_, ()>(())
            })
            .unwrap()
            .is_none()
    );
    assert_eq!(
        counting.count(),
        0,
        "actual optional grant refusal precedes pool/mutex/payload allocation"
    );
    assert_eq!(sync.count(), 0);
    assert_eq!(loaded.load(Ordering::Acquire), 0);
    assert_eq!(ledger.cache_issued.load(Ordering::Acquire), 0);
    assert_eq!(ledger.cache_bytes.load(Ordering::Acquire), 0);
    drop(counting);
    ledger.cache_denied.store(false, Ordering::Release);
    let value = cache
        .load_if_fits(1, 4, |out| {
            out.copy_from_slice(b"data");
            Ok::<_, ()>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        sync.count(),
        usize::from(crate::native_sync::mutex_backing_bytes() != 0)
    );
    if sync.count() != 0 {
        let (funding, _, bytes, align, freed) = sync.record(0);
        assert_eq!(funding, ledger.cache_address.load(Ordering::Acquire));
        #[cfg(unix)]
        assert_eq!(
            (bytes, align),
            (
                size_of::<libc::pthread_mutex_t>(),
                std::mem::align_of::<libc::pthread_mutex_t>()
            )
        );
        assert!(!freed);
    }
    assert_eq!(ledger.cache_issued.load(Ordering::Acquire), 1);
    let counting = super::read_fork_tests::AllocationCount::start();
    let alias = value.clone();
    assert_eq!(counting.count(), 0);
    drop(counting);
    drop(cache);
    drop(value);
    assert!(
        ledger.cache_bytes.load(Ordering::Acquire) != 0,
        "original final value alias retains the optional grant and its synchronization control"
    );
    drop(alias);
    sync.assert_all_retired();
    assert_eq!(ledger.cache_issued.load(Ordering::Acquire), 1);
    assert_eq!(ledger.cache_bytes.load(Ordering::Acquire), 0);
    assert_eq!(
        ledger.issued.load(Ordering::Acquire),
        0,
        "optional pool never creates a mandatory native grant"
    );
}
