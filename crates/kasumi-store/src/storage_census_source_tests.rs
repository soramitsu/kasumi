use super::*;
use crate::source_metadata::{MetadataPreparation, SourceMetadataPurpose, StoreSourceMetadataBank};
use crate::test_utils::TestDiskMemory;
use kasumi_kv::TerminalObservation;
use std::sync::atomic::AtomicUsize;

struct Database;
impl StoragePayload for Database {
    const KIND: StorageOwnerKind = StorageOwnerKind::Database;
    fn drive(&self) -> bool {
        true
    }
}
struct Pool;
impl StoragePayload for Pool {
    const KIND: StorageOwnerKind = StorageOwnerKind::SourcePool;
    fn drive(&self) -> bool {
        true
    }
}
#[derive(Debug)]
struct Original;
impl std::fmt::Display for Original {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("source control original")
    }
}
impl std::error::Error for Original {}

struct Token {
    _lease: DiskMemoryLease,
    panic: Arc<AtomicBool>,
    marker: Arc<Original>,
}
impl Drop for Token {
    fn drop(&mut self) {
        if self.panic.swap(false, Ordering::AcqRel) {
            std::panic::panic_any(self.marker.clone());
        }
    }
}
struct Memory {
    census: StorageCensus,
    backing: Arc<TestDiskMemory>,
    _bookkeeping: DiskMemoryLease,
    mode: AtomicU8,
    calls: AtomicUsize,
    original: Mutex<Option<io::Error>>,
    panic: Arc<Original>,
    token_panic: Arc<AtomicBool>,
}
impl Memory {
    fn new(capacity: usize) -> Arc<Self> {
        let backing = TestDiskMemory::new(64 << 20, 64);
        let bytes = disk_memory::add(
            StorageCensus::required_bytes(capacity).unwrap(),
            disk_memory::arc::<Self>().unwrap(),
        )
        .unwrap();
        let credit = backing.clone().reserve_installed(bytes).unwrap();
        let memory = Arc::new(Self {
            census: StorageCensus::allocate(capacity).unwrap(),
            backing,
            _bookkeeping: credit,
            mode: AtomicU8::new(0),
            calls: AtomicUsize::new(0),
            original: Mutex::new(Some(io::Error::other(Original))),
            panic: Arc::new(Original),
            token_panic: Arc::new(AtomicBool::new(false)),
        });
        let provider: Arc<dyn NodeDiskMemoryAdmission> = memory.clone();
        memory.census.bind_provider(&provider).unwrap();
        memory
    }
    fn provider(self: &Arc<Self>) -> Arc<dyn NodeDiskMemoryAdmission> {
        self.clone()
    }
    fn parent(self: &Arc<Self>) -> StorageRegistration<Database> {
        self.census
            .register_native(self.provider(), 0, |_| Database)
            .unwrap()
    }
    fn pool(self: &Arc<Self>, parent: &StorageRegistration<Database>) -> StorageRegistration<Pool> {
        let mut claim = self
            .census
            .claim_source_control(&self.provider(), parent)
            .unwrap();
        self.census
            .register_source_control(self.provider(), &mut claim, || Pool)
            .unwrap()
    }
    fn bank(self: &Arc<Self>, pool: StorageOwnerId) -> StoreSourceMetadataBank {
        let requests = StoreSourceMetadataBank::requests().unwrap();
        let purposes = [
            SourceMetadataPurpose::Fixed,
            SourceMetadataPurpose::PublicationLane,
            SourceMetadataPurpose::PublicationLane,
        ];
        let mut preparation = std::array::from_fn(|_| MetadataPreparation::new());
        for ((preparation, purpose), bytes) in preparation.iter_mut().zip(purposes).zip(requests) {
            preparation.acquire(&self.provider(), purpose, bytes);
            assert!(preparation.ready());
        }
        StoreSourceMetadataBank::install(&self.provider(), pool, &mut preparation)
            .unwrap()
            .unwrap()
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
    ) -> std::io::Result<()> {
        let provider: Arc<dyn NodeDiskMemoryAdmission> = self.clone();
        let permit = install
            .try_begin_bind(provider)
            .map_err(|_| std::io::ErrorKind::InvalidInput)?;
        let requested_bytes = permit.request_bytes();
        let bytes = crate::disk_memory::add(
            requested_bytes,
            crate::DiskMemoryLease::token_allocation_bytes::<crate::DiskMemoryLease>()?,
        )?;
        match self.backing.clone().reserve_installed(bytes) {
            Ok(token) => {
                permit.bind(token);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::OutOfMemory => {
                Err(permit.refuse_capacity(error))
            }
            Err(error) => Err(error),
        }
    }
    fn quote_installed(&self, bytes: u64) -> io::Result<u64> {
        self.backing.quote_installed(bytes)
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
    fn install_source_metadata(
        self: Arc<Self>,
        install: &mut crate::SourceMetadataInstall<'_>,
    ) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        // Real census metadata remains observable during provider dispatch.
        // Its actual SourcePool construction cell and parent count preexist.
        let snapshot = self
            .census
            .try_snapshot()
            .expect("provider held census metadata");
        assert!(snapshot.source_pools > 0);
        let mode = self.mode.load(Ordering::Acquire);
        if mode == 1 {
            return Err(self.original.lock().unwrap().take().unwrap());
        }
        if mode == 2 {
            std::panic::panic_any(self.panic.clone());
        }
        let provider: Arc<dyn NodeDiskMemoryAdmission> = self.clone();
        let permit = install.try_begin_bind(provider).unwrap();
        let bytes = disk_memory::add(
            permit.request_bytes(),
            DiskMemoryLease::token_allocation_bytes::<Token>()?,
        )
        .unwrap();
        let lease = self.backing.clone().reserve_installed(bytes)?;
        permit.bind(Token {
            _lease: lease,
            panic: self.token_panic.clone(),
            marker: self.panic.clone(),
        });
        if mode == 3 {
            return Err(self.original.lock().unwrap().take().unwrap());
        }
        if mode == 4 {
            std::panic::panic_any(self.panic.clone());
        }
        Ok(())
    }
}
fn children(memory: &Memory, parent: StorageOwnerId) -> usize {
    memory.census.slots[parent.index]
        .children
        .load(Ordering::Acquire)
}

#[test]
fn source_census_control_preclaims_identity_before_provider_and_retires_successful_report() {
    let memory = Memory::new(3);
    let parent = memory.parent();
    let mut claim = memory
        .census
        .claim_source_control(&memory.provider(), &parent)
        .unwrap();
    let id = claim.id();
    assert_eq!(memory.calls.load(Ordering::Acquire), 0);
    assert_eq!(memory.census.owner_at(id.index), Some(id));
    assert_eq!(memory.census.source_control_parent(id), Some(parent.id()));
    assert_eq!(children(&memory, parent.id()), 1);
    assert_eq!(
        memory.census.drain_owner(id),
        StorageCensusDisposition::Retained
    );
    let registration = memory
        .census
        .register_source_control(memory.provider(), &mut claim, || Pool)
        .unwrap();
    assert_eq!(registration.id(), id);
    assert_eq!(memory.calls.load(Ordering::Acquire), 1);
    assert!(memory.census.source_control_observation(id).is_none());
    assert_eq!(registration.retire(), StorageCensusDisposition::Retired);
    assert_eq!(children(&memory, parent.id()), 0);
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn source_census_control_originals_survive_no_facade_cleanup_and_are_never_retried() {
    for mode in 1..=4 {
        let memory = Memory::new(3);
        let parent = memory.parent();
        let (id, original_address) = {
            let mut claim = memory
                .census
                .claim_source_control(&memory.provider(), &parent)
                .unwrap();
            let id = claim.id();
            memory.mode.store(mode, Ordering::Release);
            let constructed = AtomicUsize::new(0);
            for _ in 0..2 {
                assert!(
                    memory
                        .census
                        .register_source_control(memory.provider(), &mut claim, || {
                            constructed.fetch_add(1, Ordering::AcqRel);
                            Pool
                        })
                        .is_err()
                );
            }
            assert_eq!(constructed.load(Ordering::Acquire), 0);
            assert_eq!(memory.calls.load(Ordering::Acquire), 1);
            let original_address = {
                let observation = memory.census.source_control_observation(id).unwrap();
                match observation.original() {
                    TerminalObservation::Returned(Err(error)) => {
                        error.get_ref().unwrap() as *const _ as *const () as usize
                    }
                    TerminalObservation::Panicked(payload) => {
                        assert!(Arc::ptr_eq(
                            payload.downcast_ref::<Arc<Original>>().unwrap(),
                            &memory.panic
                        ));
                        payload as *const _ as *const () as usize
                    }
                    _ => panic!("missing provider original"),
                }
            };
            (id, original_address)
        };
        assert_eq!(
            memory.census.drain_owner(id),
            StorageCensusDisposition::Retained
        );
        assert_eq!(children(&memory, parent.id()), 1);
        let observation = memory.census.source_control_observation(id).unwrap();
        assert!(matches!(
            observation.cleanup(),
            TerminalObservation::Returned(Ok(()))
        ));
        let address = match observation.original() {
            TerminalObservation::Returned(Err(error)) => {
                error.get_ref().unwrap() as *const _ as *const () as usize
            }
            TerminalObservation::Panicked(payload) => payload as *const _ as *const () as usize,
            _ => panic!("original changed"),
        };
        assert_eq!(address, original_address);
        drop(observation);
        memory.census.acknowledge_source_control(id).unwrap();
        assert_eq!(
            memory.census.drain_owner(id),
            StorageCensusDisposition::Retired
        );
        assert_eq!(children(&memory, parent.id()), 0);
        assert_eq!(memory.calls.load(Ordering::Acquire), 1);
        assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
    }
}

#[test]
fn source_census_control_cancel_pristine_and_capacity_refusal_never_dispatch_provider() {
    let memory = Memory::new(2);
    let parent = memory.parent();
    let id = {
        let claim = memory
            .census
            .claim_source_control(&memory.provider(), &parent)
            .unwrap();
        let id = claim.id();
        assert!(
            memory
                .census
                .claim_source_control(&memory.provider(), &parent)
                .is_err()
        );
        assert_eq!(children(&memory, parent.id()), 1);
        id
    };
    assert_eq!(
        memory.census.cancel_source_control(id),
        StorageCensusDisposition::Retired
    );
    assert_eq!(memory.calls.load(Ordering::Acquire), 0);
    assert_eq!(children(&memory, parent.id()), 0);
    assert_eq!(
        memory.census.cancel_source_control(id),
        StorageCensusDisposition::Stale
    );
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn source_census_control_cleanup_panic_preserves_provider_original_and_parent() {
    let memory = Memory::new(3);
    let parent = memory.parent();
    let mut claim = memory
        .census
        .claim_source_control(&memory.provider(), &parent)
        .unwrap();
    let id = claim.id();
    memory.mode.store(3, Ordering::Release);
    assert!(
        memory
            .census
            .register_source_control(memory.provider(), &mut claim, || Pool)
            .is_err()
    );
    memory.token_panic.store(true, Ordering::Release);
    assert_eq!(
        memory.census.drain_owner(id),
        StorageCensusDisposition::Retained
    );
    let observation = memory.census.source_control_observation(id).unwrap();
    assert!(matches!(
        observation.original(),
        TerminalObservation::Returned(Err(_))
    ));
    let TerminalObservation::Panicked(payload) = observation.cleanup() else {
        panic!("missing cleanup original")
    };
    assert!(Arc::ptr_eq(
        payload.downcast_ref::<Arc<Original>>().unwrap(),
        &memory.panic
    ));
    drop(observation);
    assert!(memory.census.acknowledge_source_control(id).is_err());
    assert_eq!(
        memory.census.drain_owner(id),
        StorageCensusDisposition::Retained
    );
    assert_eq!(children(&memory, parent.id()), 1);
    assert_eq!(memory.calls.load(Ordering::Acquire), 1);
}

#[test]
fn source_census_partial_right_claim_is_real_capacity_and_release_returns_parent_once() {
    let memory = Memory::new(3);
    let parent = memory.parent();
    let pool = memory.pool(&parent);
    let bank = memory.bank(pool.id());
    let mut hold = Some(bank.hold());
    let mut right = memory
        .census
        .claim_source_right(&memory.provider(), parent.id(), pool.id(), 0, &mut hold)
        .unwrap();
    assert!(hold.is_none());
    assert_eq!(children(&memory, parent.id()), 2);
    let mut second = Some(bank.hold());
    let error = memory
        .census
        .claim_source_right(&memory.provider(), parent.id(), pool.id(), 1, &mut second)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert!(second.is_some());
    assert_eq!(memory.census.snapshot().source_reserved, 1);
    assert!(
        memory
            .census
            .register_native(memory.provider(), 0, |_| Database)
            .is_err()
    );
    assert_eq!(
        memory.census.release_source_right(&mut right),
        StorageCensusDisposition::Retired
    );
    assert_eq!(
        memory.census.release_source_right(&mut right),
        StorageCensusDisposition::Retired
    );
    assert_eq!(children(&memory, parent.id()), 1);
    drop(second);
    bank.begin_seal().unwrap();
    let mut standing = [None, None];
    assert!(bank.take_sealed_lanes(&mut standing).unwrap());
    drop(standing);
    drop(bank);
    assert_eq!(pool.retire(), StorageCensusDisposition::Retired);
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn source_census_foreign_holds_never_consume_capacity_or_parent_counts() {
    let memory = Memory::new(5);
    let other = Memory::new(5);
    let parent = memory.parent();
    let other_parent = other.parent();
    let pool = memory.pool(&parent);
    let other_pool = other.pool(&other_parent);
    // Separate providers reuse the same slot position, but their exact owner
    // generations are process-wide and cannot alias.
    assert_eq!(pool.id().index, other_pool.id().index);
    assert_ne!(pool.id().generation, other_pool.id().generation);
    let bank = other.bank(other_pool.id());
    let mut hold = Some(bank.hold());
    let own_census = memory.census.snapshot();
    let foreign_census = other.census.snapshot();
    let own_memory = memory.backing.snapshot();
    let foreign_memory = other.backing.snapshot();
    assert_eq!(
        memory
            .census
            .claim_source_right(&memory.provider(), parent.id(), pool.id(), 0, &mut hold)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(hold.is_some());
    assert_eq!(memory.census.snapshot(), own_census);
    assert_eq!(other.census.snapshot(), foreign_census);
    assert_eq!(memory.backing.snapshot(), own_memory);
    assert_eq!(other.backing.snapshot(), foreign_memory);
    assert_eq!(children(&memory, parent.id()), 1);
    assert_eq!(children(&other, other_parent.id()), 1);
    assert_eq!(memory.census.snapshot().source_reserved, 0);
    drop(hold);
    bank.begin_seal().unwrap();
    let mut standing = [None, None];
    assert!(bank.take_sealed_lanes(&mut standing).unwrap());
    drop(standing);
    drop(bank);
    assert_eq!(pool.retire(), StorageCensusDisposition::Retired);
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
    assert_eq!(other_pool.retire(), StorageCensusDisposition::Retired);
    assert_eq!(other_parent.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn source_census_poisoned_control_report_cannot_mint_a_later_claim() {
    let memory = Memory::new(4);
    let parent = memory.parent();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _guard = memory.census.slots[1].source_control.lock().unwrap();
            panic!("poison actual vacant control report");
        }))
        .is_err()
    );
    let error = memory
        .census
        .claim_source_control(&memory.provider(), &parent)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(memory.census.snapshot().fenced);
    assert_eq!(memory.census.snapshot().source_pools, 0);
    assert_eq!(children(&memory, parent.id()), 0);
    assert_eq!(memory.calls.load(Ordering::Acquire), 0);
    for index in 1..4 {
        assert!(memory.census.owner_at(index).is_none());
    }
}

#[test]
fn source_census_recorded_release_survives_async_drain_and_slot_reuse() {
    struct OrdinaryReader;
    impl StoragePayload for OrdinaryReader {
        const KIND: StorageOwnerKind = StorageOwnerKind::Reader;
        fn drive(&self) -> bool {
            true
        }
    }
    let memory = Memory::new(3);
    let parent = memory.parent();
    let pool = memory.pool(&parent);
    let bank = memory.bank(pool.id());
    let mut hold = Some(bank.hold());
    let mut right = memory
        .census
        .claim_source_right(&memory.provider(), parent.id(), pool.id(), 0, &mut hold)
        .unwrap();
    let id = right.id();
    // Stop at the same fixed intent that release_source_right records before
    // dispatch. The following drain performs actual Hold destruction/count
    // retirement independently of the still-uninformed pool authority token.
    {
        let mut metadata = memory.census.slots[id.index].metadata.lock().unwrap();
        metadata.source.as_mut().unwrap().class = SourceClass::Releasing;
        metadata.cell = Cell::RetiringSourceHold;
    }
    memory.census.refresh_source_right(&mut right).unwrap();
    assert_eq!(
        memory.census.drain_owner(id),
        StorageCensusDisposition::Retired
    );
    assert_eq!(children(&memory, parent.id()), 1);
    let replacement = memory
        .census
        .register_child(memory.provider(), 0, &parent, || OrdinaryReader)
        .unwrap();
    assert_eq!(replacement.id().index, id.index);
    assert_ne!(replacement.id().generation, id.generation);
    memory.census.refresh_source_right(&mut right).unwrap();
    assert_eq!(
        memory.census.release_source_right(&mut right),
        StorageCensusDisposition::Retired
    );
    assert_eq!(children(&memory, parent.id()), 2);
    assert_eq!(memory.census.owner_at(id.index), Some(replacement.id()));
    assert_eq!(replacement.retire(), StorageCensusDisposition::Retired);
    bank.begin_seal().unwrap();
    let mut standing = [None, None];
    assert!(bank.take_sealed_lanes(&mut standing).unwrap());
    drop(standing);
    drop(bank);
    assert_eq!(pool.retire(), StorageCensusDisposition::Retired);
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn sealed_parent_rejects_source_control_and_right_without_provider_or_hold_transfer() {
    let memory = Memory::new(4);
    let parent = memory.parent();
    let id = parent.id();
    let pool = memory.pool(&parent);
    let bank = memory.bank(pool.id());
    let mut hold = Some(bank.hold());
    memory.census.seal_child_admission(id).unwrap();
    let calls = memory.calls.load(Ordering::Acquire);
    let control = memory
        .census
        .claim_source_control(&memory.provider(), &parent)
        .err()
        .unwrap();
    assert_eq!(control.kind(), io::ErrorKind::BrokenPipe);
    let right = memory
        .census
        .claim_source_right(&memory.provider(), id, pool.id(), 0, &mut hold)
        .err()
        .unwrap();
    assert_eq!(right.kind(), io::ErrorKind::BrokenPipe);
    assert!(hold.is_some(), "refused admission retains original hold");
    assert_eq!(memory.calls.load(Ordering::Acquire), calls);
    assert_eq!(children(&memory, id), 1, "only original pool remains");
    assert!(!memory.census.children_retired(id));
    drop(hold);
    bank.begin_seal().unwrap();
    let mut standing = [None, None];
    assert!(bank.take_sealed_lanes(&mut standing).unwrap());
    drop(standing);
    drop(bank);
    assert_eq!(pool.retire(), StorageCensusDisposition::Retired);
    assert!(memory.census.children_retired(id));
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
}

#[test]
fn sealed_parent_denies_source_exchange_before_any_hold_or_original_transition() {
    let memory = Memory::new(5);
    let parent = memory.parent();
    let id = parent.id();
    let pool = memory.pool(&parent);
    let bank = memory.bank(pool.id());
    let mut first = Some(bank.hold());
    let mut claim = memory
        .census
        .claim_source_right(&memory.provider(), id, pool.id(), 0, &mut first)
        .unwrap();
    // This is a genuine reserved source right. Admission must reject a sealed
    // parent before any attempted activation/exchange or hold consumption.
    let mut replacement = Some(bank.hold());
    let account = bank.checkout(0).unwrap();
    let witness = account.witness();
    account.allow_retirement().unwrap();
    drop(account);
    assert!(witness.same_bank(replacement.as_ref().unwrap()));
    let child_count = children(&memory, id);
    let snapshot = memory.census.snapshot();
    memory.census.seal_child_admission(id).unwrap();
    let calls = memory.calls.load(Ordering::Acquire);
    let failure = memory
        .census
        .begin_source_exchange(&memory.provider(), &claim, &mut replacement)
        .err()
        .unwrap();
    assert_eq!(failure.kind(), io::ErrorKind::BrokenPipe);
    assert!(witness.same_bank(replacement.as_ref().unwrap()));
    assert_eq!(children(&memory, id), child_count);
    assert_eq!(
        memory.census.snapshot().source_reserved,
        snapshot.source_reserved
    );
    assert_eq!(memory.calls.load(Ordering::Acquire), calls);
    {
        let old = memory.census.slots[claim.id().index]
            .metadata
            .lock()
            .unwrap();
        assert_eq!(old.generation, claim.id().generation);
        let slot = &memory.census.slots[claim.id().index];
        assert!(!super::source::exchange_blocks(slot, &old));
        assert_eq!(slot.source_completion.load(Ordering::Acquire), NONE);
    }
    drop(replacement);
    drop(witness);
    assert_eq!(
        memory.census.release_source_right(&mut claim),
        StorageCensusDisposition::Retired
    );
    bank.begin_seal().unwrap();
    let mut standing = [None, None];
    assert!(bank.take_sealed_lanes(&mut standing).unwrap());
    drop(standing);
    drop(bank);
    assert_eq!(pool.retire(), StorageCensusDisposition::Retired);
    assert!(memory.census.children_retired(id));
    assert_eq!(parent.retire(), StorageCensusDisposition::Retired);
}
