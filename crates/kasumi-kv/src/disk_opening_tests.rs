use super::*;
use crate::core::{AdmissionError, BackendCloseOutcome, OwnerFailed, ResidentLease};
use crate::group::InMemoryGroup;
use crate::retained::TerminalObservation;
use std::ffi::OsStr;
use std::io;
use std::panic::resume_unwind;
use std::sync::atomic::{AtomicU64, AtomicUsize};

const GROUP: [u8; 16] = [93; 16];
const CONFIG: CacheConfig = CacheConfig {
    byte_limit: 1 << 20,
};
#[derive(Debug)]
struct OriginalCleanup(u64);
#[derive(Debug)]
struct OriginalIo(u64);
impl std::fmt::Display for OriginalIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original lower opening I/O")
    }
}
impl std::error::Error for OriginalIo {}

struct Admission {
    requests: AtomicUsize,
    checks: AtomicUsize,
    fail_check: usize,
    deny: usize,
    panic_refund: usize,
    charges: [AtomicU64; 64],
    used: AtomicU64,
    refunds: AtomicUsize,
    original: Mutex<Option<Box<OriginalCleanup>>>,
}
impl Admission {
    fn new(fail_check: usize, deny: usize, panic_refund: usize) -> (Arc<Self>, usize) {
        let original = Box::new(OriginalCleanup(17));
        let address = std::ptr::from_ref(original.as_ref()) as usize;
        let actual = Arc::new(Self {
            requests: AtomicUsize::new(0),
            checks: AtomicUsize::new(0),
            fail_check,
            deny,
            panic_refund,
            charges: std::array::from_fn(|_| AtomicU64::new(0)),
            used: AtomicU64::new(0),
            refunds: AtomicUsize::new(0),
            original: Mutex::new(Some(original)),
        });
        // The fixture's original inspection mutex is outside construction.
        drop(actual.original.lock().unwrap());
        (actual, address)
    }
}
struct Grant {
    owner: Arc<Admission>,
    bytes: u64,
    id: usize,
}
impl Drop for Grant {
    fn drop(&mut self) {
        if self.id == self.owner.panic_refund {
            let actual = self.owner.original.lock().unwrap().take().unwrap();
            resume_unwind(actual);
        }
        self.owner.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.owner.refunds.fetch_add(1, Ordering::AcqRel);
    }
}
// The original fixture provider remains alive outside every lower stage.
struct Provider(Arc<Admission>);
impl StorageAdmission for Provider {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        let check = self.0.checks.fetch_add(1, Ordering::AcqRel) + 1;
        if check == self.0.fail_check {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        let id = self.0.requests.fetch_add(1, Ordering::AcqRel) + 1;
        assert!(id < self.0.charges.len(), "bounded fixture grant inventory");
        if id == self.0.deny {
            return Err(AdmissionError::CapacityDenied);
        }
        self.0.charges[id].store(bytes, Ordering::Release);
        self.0.used.fetch_add(bytes, Ordering::AcqRel);
        Ok(Box::new(Grant {
            owner: self.0.clone(),
            bytes,
            id,
        }))
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {}
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
impl crate::cache_test::Provider for Provider {
    fn acquire_cache(&self, _: u64, _: bool) -> Result<(), AdmissionError> {
        Err(AdmissionError::CapacityDenied)
    }
    fn release_cache(&self, _: u64, _: bool) {
        panic!("fixture never acquired optional cache memory");
    }
}
fn provider(owner: &Arc<Admission>) -> Arc<dyn StorageAdmission> {
    Arc::new(Provider(owner.clone()))
}

fn panic_address(observation: TerminalObservation<'_, std::convert::Infallible>) -> usize {
    let TerminalObservation::Panicked(actual) = observation else {
        panic!("actual original cleanup panic");
    };
    let actual = actual.downcast_ref::<OriginalCleanup>().unwrap();
    assert_eq!(actual.0, 17);
    std::ptr::from_ref(actual) as usize
}
fn io_address(error: &CoreError) -> usize {
    let actual = error
        .io_error()
        .unwrap()
        .get_ref()
        .unwrap()
        .downcast_ref::<OriginalIo>()
        .unwrap();
    assert_eq!(actual.0, 19);
    std::ptr::from_ref(actual) as usize
}
struct ReadFailure {
    group: InMemoryGroup,
    owner: Arc<Admission>,
    after_grant: usize,
    roots: bool,
    original: Mutex<Option<io::Error>>,
}
impl ReadFailure {
    fn new(
        group: InMemoryGroup,
        owner: Arc<Admission>,
        after_grant: usize,
        roots: bool,
    ) -> (Arc<Self>, usize) {
        let original = io::Error::other(OriginalIo(19));
        let actual = original
            .get_ref()
            .unwrap()
            .downcast_ref::<OriginalIo>()
            .unwrap();
        let address = std::ptr::from_ref(actual) as usize;
        let actual = Arc::new(Self {
            group,
            owner,
            after_grant,
            roots,
            original: Mutex::new(Some(original)),
        });
        drop(actual.original.lock().unwrap());
        (actual, address)
    }
    fn failure(&self) -> Option<io::Error> {
        if self.owner.requests.load(Ordering::Acquire) >= self.after_grant {
            self.original.lock().unwrap().take()
        } else {
            None
        }
    }
}
impl SegmentGroupBackend for ReadFailure {
    fn reserve_transaction(
        &self,
        plan: &crate::TransactionSpacePlan,
    ) -> Result<(), crate::TransactionReserveError> {
        self.group.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.group.finish_transaction(group, batch)
    }
    fn cancel_transaction(&self, group: [u8; 16], batch: u64) -> io::Result<()> {
        self.group.cancel_transaction(group, batch)
    }
    fn read_root(
        &self,
        slot: crate::root::RootSlot,
        out: &mut [u8; crate::root::ROOT_SLOT_BYTES],
    ) -> io::Result<()> {
        if self.roots
            && let Some(error) = self.failure()
        {
            return Err(error);
        }
        self.group.read_root(slot, out)
    }
    fn write_root(
        &self,
        slot: crate::root::RootSlot,
        bytes: &[u8; crate::root::ROOT_SLOT_BYTES],
    ) -> io::Result<()> {
        self.group.write_root(slot, bytes)
    }
    fn sync_root(&self) -> io::Result<()> {
        self.group.sync_root()
    }
    fn visit_entries(&self, visitor: &mut dyn FnMut(&OsStr) -> io::Result<()>) -> io::Result<()> {
        self.group.visit_entries(visitor)
    }
    fn exists(&self, file: GroupFile) -> io::Result<bool> {
        self.group.exists(file)
    }
    fn create(&self, file: GroupFile) -> io::Result<()> {
        self.group.create(file)
    }
    fn len(&self, file: GroupFile) -> io::Result<u64> {
        self.group.len(file)
    }
    fn read(&self, file: GroupFile, at: u64, bytes: &mut [u8]) -> io::Result<()> {
        if !self.roots
            && let Some(error) = self.failure()
        {
            return Err(error);
        }
        self.group.read(file, at, bytes)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.group.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, len: u64) -> io::Result<()> {
        self.group.set_len(file, len)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.group.sync(file)
    }
    fn unlink(&self, file: GroupFile) -> io::Result<()> {
        self.group.unlink(file)
    }
    fn sync_names(&self) -> io::Result<()> {
        self.group.sync_names()
    }
    fn close(&self) -> BackendCloseOutcome {
        self.group.close()
    }
}

#[test]
fn lower_opening_keeps_original_root_io_before_fixed_refund_panic() {
    let (owner, original_panic) = Admission::new(0, 0, 1);
    let (backend, original_io) = ReadFailure::new(InMemoryGroup::new(), owner.clone(), 1, true);
    let mut stage = DiskOpening::default();
    let original = stage
        .create(
            OriginalBackend::component_fixture(backend.clone()),
            provider(&owner),
            GROUP,
            CONFIG,
        )
        .unwrap_err();
    assert_eq!(io_address(&original), original_io);
    let charged = owner.used.load(Ordering::Acquire);
    assert_eq!(owner.requests.load(Ordering::Acquire), 1);
    assert!(!stage.dispose());
    assert!(!stage.complete());
    assert_eq!(io_address(&original), original_io);
    assert_eq!(stage.with_observation(13, panic_address), original_panic);
    assert_eq!(owner.used.load(Ordering::Acquire), charged);
    assert_eq!(owner.refunds.load(Ordering::Acquire), 0);
    assert!(!stage.dispose());
    assert_eq!(stage.with_observation(13, panic_address), original_panic);
    backend.group.close().into_result().unwrap();
}

#[test]
fn lower_opening_keeps_arena_denial_before_original_root_refund_panic() {
    let (owner, original_panic) = Admission::new(0, 3, 2);
    let group = Arc::new(InMemoryGroup::new());
    let mut stage = DiskOpening::default();
    let original = stage
        .create(
            OriginalBackend::component_fixture(group.clone()),
            provider(&owner),
            GROUP,
            CONFIG,
        )
        .unwrap_err();
    assert!(original.is_capacity_denied());
    assert_eq!(owner.requests.load(Ordering::Acquire), 3);
    let fixed = stage.fixed.as_ref().unwrap().allocation_address_for_test();
    let charged = owner.used.load(Ordering::Acquire);
    assert!(!stage.dispose());
    assert!(!stage.complete());
    assert!(original.is_capacity_denied());
    assert_eq!(stage.with_observation(10, panic_address), original_panic);
    assert_eq!(
        stage.fixed.as_ref().unwrap().allocation_address_for_test(),
        fixed
    );
    assert_eq!(owner.used.load(Ordering::Acquire), charged);
    assert_eq!(owner.refunds.load(Ordering::Acquire), 0);
    assert!(!stage.dispose());
    assert_eq!(owner.requests.load(Ordering::Acquire), 3);
    group.close().into_result().unwrap();
}

struct Roll {
    original: Option<Box<OriginalCleanup>>,
}
impl crate::arena::DirectoryArenaRoll for Roll {
    fn reserve(&self) -> Result<u64, CoreError> {
        panic!("constructor must not reserve an arena");
    }
    fn confirm(&self, _: u64) -> Result<(), CoreError> {
        panic!("constructor must not confirm an arena");
    }
}
impl Drop for Roll {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            resume_unwind(original);
        }
    }
}
#[test]
fn lower_arena_keeps_second_owner_refusal_before_original_roll_destructor_panic() {
    let (owner, _) = Admission::new(2, 0, 0);
    let original = Box::new(OriginalCleanup(17));
    let address = std::ptr::from_ref(original.as_ref()) as usize;
    let group = Arc::new(InMemoryGroup::new());
    let mut stage = ArenaOpening::default();
    let original = stage
        .build(
            BackendRef::Original(OriginalBackend::component_fixture(group.clone())),
            Roll {
                original: Some(original),
            },
            provider(&owner),
            GROUP,
        )
        .unwrap_err();
    assert!(matches!(
        original.rejected_cause(),
        Some(crate::CoreErrorCause::OwnerFailed)
    ));
    let charged = owner.used.load(Ordering::Acquire);
    assert!(!stage.dispose());
    assert!(!stage.complete());
    assert_eq!(stage.with_observation(0, panic_address), address);
    assert!(matches!(
        original.rejected_cause(),
        Some(crate::CoreErrorCause::OwnerFailed)
    ));
    assert_eq!(owner.used.load(Ordering::Acquire), charged);
    assert_eq!(owner.refunds.load(Ordering::Acquire), 0);
    assert_eq!(owner.requests.load(Ordering::Acquire), 1);
    assert!(!stage.dispose());
    group.close().into_result().unwrap();
}

#[test]
fn lower_pin_registry_keeps_final_owner_refusal_before_original_refund_panic() {
    let (owner, original_panic) = Admission::new(3, 0, 1);
    let mut stage = SnapshotPinsOpening::default();
    let original = stage.build(provider(&owner), GROUP, 2).unwrap_err();
    assert!(matches!(
        original.rejected_cause(),
        Some(crate::CoreErrorCause::OwnerFailed)
    ));
    let charged = owner.used.load(Ordering::Acquire);
    assert!(!stage.dispose());
    assert!(!stage.complete());
    assert_eq!(stage.with_observation(4, panic_address), original_panic);
    stage.with_observation(0, |actual| {
        assert!(matches!(actual, TerminalObservation::Returned(Ok(()))))
    });
    stage.with_observation(1, |actual| {
        assert!(matches!(actual, TerminalObservation::Returned(Ok(()))))
    });
    assert_eq!(owner.used.load(Ordering::Acquire), charged);
    assert_eq!(owner.refunds.load(Ordering::Acquire), 0);
    assert_eq!(owner.requests.load(Ordering::Acquire), 1);
    assert!(!stage.dispose());
}

#[test]
fn lower_opening_keeps_replay_io_and_original_live_state_before_replay_refund_panic() {
    let (seed_owner, _) = Admission::new(0, 0, 0);
    let group = InMemoryGroup::new();
    let mut seed = DiskState::create(
        Arc::new(group.clone()),
        provider(&seed_owner),
        GROUP,
        CONFIG,
    )
    .unwrap();
    seed.commit(&[Operation::create_table("records")]).unwrap();
    drop(seed);
    assert_eq!(seed_owner.used.load(Ordering::Acquire), 0);
    let (owner, original_panic) = Admission::new(0, 0, 5);
    let (backend, original_io) = ReadFailure::new(group.crash(), owner.clone(), 5, false);
    let mut stage = DiskOpening::default();
    let original = stage
        .open(
            OriginalBackend::component_fixture(backend.clone()),
            provider(&owner),
            GROUP,
            CONFIG,
        )
        .unwrap_err();
    assert_eq!(io_address(&original), original_io);
    assert!(stage.replay.is_some());
    let original_state = stage
        .completed()
        .unwrap()
        .owner_allocation_addresses_for_test();
    let charged = owner.used.load(Ordering::Acquire);
    assert!(!stage.dispose());
    assert!(!stage.complete());
    assert_eq!(io_address(&original), original_io);
    assert_eq!(stage.with_observation(0, panic_address), original_panic);
    // The same state was staged before disposal, then split without a new
    // allocation. Its original root/arena/grants remain unchanged on refusal.
    let owner_now = stage.owner.as_ref().unwrap();
    let arena_now = stage.arena.as_ref().unwrap();
    assert_eq!(
        owner_now.as_ref() as *const RootOwner as usize,
        original_state[0]
    );
    assert_eq!(
        owner_now
            ._lease
            .as_ref()
            .unwrap()
            .allocation_address_for_test(),
        original_state[1]
    );
    assert_eq!(
        arena_now.as_ref() as *const DirectoryArenaBackend as usize,
        original_state[2]
    );
    assert_eq!(arena_now._lease_address_for_test(), original_state[3]);
    assert_eq!(arena_now.roll_address_for_test(), original_state[4]);
    assert_eq!(owner.used.load(Ordering::Acquire), charged);
    assert_eq!(owner.refunds.load(Ordering::Acquire), 0);
    assert!(!stage.dispose());
    assert_eq!(owner.requests.load(Ordering::Acquire), 5);
    backend.group.close().into_result().unwrap();
}

#[test]
fn lower_opening_promotes_original_controls_and_observes_their_actual_disposal() {
    let (owner, _) = Admission::new(0, 0, 0);
    let group = Arc::new(InMemoryGroup::new());
    let mut opening = DiskOpening::default();
    opening
        .create(
            OriginalBackend::component_fixture(group.clone()),
            provider(&owner),
            GROUP,
            CONFIG,
        )
        .unwrap();
    let addresses = opening
        .completed()
        .unwrap()
        .owner_allocation_addresses_for_test();
    let charged = owner.used.load(Ordering::Acquire);
    assert!(charged > 0);
    assert!(opening.retire_transients());
    let state = opening.take_completed().unwrap();
    assert!(opening.complete());
    assert_eq!(state.owner_allocation_addresses_for_test(), addresses);
    assert_eq!(owner.used.load(Ordering::Acquire), charged);
    // The fixture's actual backend owner supplies native drain first. Lower
    // stages never create a second backend close authority.
    group.close().into_result().unwrap();
    let mut disposal = DiskOpening::default();
    disposal.adopt(state);
    assert!(!disposal.complete());
    assert!(disposal.dispose());
    assert!(disposal.complete());
    assert_eq!(owner.used.load(Ordering::Acquire), 0);
    assert_eq!(owner.refunds.load(Ordering::Acquire), 4);
    assert!(disposal.dispose());
    assert_eq!(owner.refunds.load(Ordering::Acquire), 4);
}
