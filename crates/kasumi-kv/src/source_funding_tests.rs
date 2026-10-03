//! Protocol tests use the actual retained native opening and constructors. The
//! provider is deliberately adversarial; real MemoryCore debit/transfer tests
//! live in Engine. No test manufactures a successful native history exchange.
use super::*;
use crate::group::InMemoryGroup;
use crate::{CacheConfig, CacheMemoryLease, CacheMemoryQuote};
use std::alloc::Layout;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const POOL: usize = 0;
const ACCOUNT: usize = 1;
const RIGHTS: usize = 2;
const BACKING: usize = 3;
const PIN: usize = 4;

#[derive(Debug)]
struct Original(Arc<()>);
impl std::fmt::Display for Original {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("original source funding fixture failure")
    }
}
impl std::error::Error for Original {}
struct FixtureProvider {
    mode: [AtomicUsize; 5],
    calls: [AtomicUsize; 5],
    live: [Arc<AtomicUsize>; 5],
    original: Arc<()>,
    busy: AtomicBool,
    panic_poll: AtomicBool,
    polls: AtomicUsize,
    barriers: AtomicUsize,
    seals: AtomicUsize,
    fail_pool_before_bind: AtomicBool,
    panic_pool_drop: AtomicBool,
    pool_drops: AtomicUsize,
    history_mode: AtomicUsize,
}
impl FixtureProvider {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            mode: [const { AtomicUsize::new(0) }; 5],
            calls: [const { AtomicUsize::new(0) }; 5],
            live: std::array::from_fn(|_| Arc::new(AtomicUsize::new(0))),
            original: Arc::new(()),
            busy: AtomicBool::new(false),
            panic_poll: AtomicBool::new(false),
            polls: AtomicUsize::new(0),
            barriers: AtomicUsize::new(0),
            seals: AtomicUsize::new(0),
            fail_pool_before_bind: AtomicBool::new(false),
            panic_pool_drop: AtomicBool::new(false),
            pool_drops: AtomicUsize::new(0),
            history_mode: AtomicUsize::new(0),
        })
    }
    fn after_bind(&self, stage: usize) -> io::Result<()> {
        self.calls[stage].fetch_add(1, Ordering::AcqRel);
        match self.mode[stage].load(Ordering::Acquire) {
            0 => Ok(()),
            1 => Err(io::Error::other(Original(self.original.clone()))),
            2 => std::panic::panic_any(Original(self.original.clone())),
            _ => unreachable!(),
        }
    }
    fn token(&self, stage: usize) -> Token {
        self.live[stage].fetch_add(1, Ordering::AcqRel);
        Token(self.live[stage].clone())
    }
    fn child(self: &Arc<Self>, install: &mut SourceChildInstall<'_>) -> io::Result<()> {
        let stage = match install.purpose() {
            SourceFundingPurpose::Rights => RIGHTS,
            SourceFundingPurpose::Backing => BACKING,
            SourceFundingPurpose::Pin => PIN,
        };
        install
            .try_begin_bind(self.clone())
            .unwrap()
            .bind(self.token(stage));
        self.after_bind(stage)
    }
}
struct Token(Arc<AtomicUsize>);
impl Drop for Token {
    fn drop(&mut self) {
        assert!(self.0.fetch_sub(1, Ordering::AcqRel) > 0);
    }
}
struct Pool {
    provider: Arc<FixtureProvider>,
    _token: Token,
}
struct Account {
    provider: Arc<FixtureProvider>,
    _token: Token,
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.provider.pool_drops.fetch_add(1, Ordering::AcqRel);
        if self.provider.panic_pool_drop.load(Ordering::Acquire) {
            std::panic::panic_any(Original(self.provider.original.clone()));
        }
    }
}
impl SourceMemoryProvider for FixtureProvider {
    fn install_source_pool(self: Arc<Self>, install: &mut SourcePoolInstall<'_>) -> io::Result<()> {
        if self.fail_pool_before_bind.load(Ordering::Acquire) {
            return self.after_bind(POOL);
        }
        let permit = install.try_begin_bind(self.clone()).unwrap();
        assert_eq!(
            permit.requests().native_bytes(SourceFundingPurpose::Pin),
            SourceFundingPurpose::Pin.native_bytes()
        );
        permit.bind(Pool {
            provider: self.clone(),
            _token: self.token(POOL),
        });
        self.after_bind(POOL)
    }
}
impl SourcePoolBackend for Pool {
    fn install_account(&self, install: &mut SourceAccountInstall<'_>) -> io::Result<()> {
        install.try_begin_bind(self.provider.clone()).unwrap().bind(
            Account {
                provider: self.provider.clone(),
                _token: self.provider.token(ACCOUNT),
            },
            0,
            1,
        );
        self.provider.after_bind(ACCOUNT)
    }
    fn acquire_rights(&self, install: &mut SourceChildInstall<'_>) -> io::Result<()> {
        self.provider.child(install)
    }
    fn begin_seal(&self) -> io::Result<()> {
        self.provider.barriers.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    fn seal(&self) -> io::Result<()> {
        self.provider.seals.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    fn snapshot(&self) -> SourceBankSnapshot {
        self.provider.polls.fetch_add(1, Ordering::AcqRel);
        if self.provider.panic_poll.load(Ordering::Acquire) {
            std::panic::panic_any(Original(self.provider.original.clone()));
        }
        SourceBankSnapshot {
            fixed_bytes: 1,
            lane_bytes: 2,
            charged_bytes: 5,
            assigned: usize::from(self.provider.busy.load(Ordering::Acquire)),
            retained: 0,
            sealed: false,
        }
    }
    fn retirement(&self, _: SourceAccountRetirement) -> bool {
        true
    }
}
impl SourceAccountBackend for Account {
    fn allow_retirement(&self) -> io::Result<()> {
        Ok(())
    }
    fn acquire(&self, install: &mut SourceChildInstall<'_>) -> io::Result<()> {
        self.provider.child(install)
    }
    fn install_history(&self, install: &mut SourceHistoryInstall<'_>) -> io::Result<()> {
        let mode = self.provider.history_mode.load(Ordering::Acquire);
        if mode == 0 {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let permit = install.try_begin_bind(self.provider.clone()).unwrap();
        match mode {
            // A capacity-shaped error without the consumed refusal capability
            // proves neither provider rollback nor restored account state.
            1 => Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                Original(self.provider.original.clone()),
            )),
            2 => std::panic::panic_any(Original(self.provider.original.clone())),
            3 => {
                drop(permit.refuse_capacity(io::ErrorKind::OutOfMemory.into()));
                Ok(())
            }
            _ => unreachable!(),
        }
    }
}
impl StorageAdmission for FixtureProvider {
    fn install_source_pool(self: Arc<Self>, install: &mut SourcePoolInstall<'_>) -> io::Result<()> {
        install.through_installed_provider(self, Ok)
    }
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn reserve_workspace(&self, _: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        Ok(Box::new(()))
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {}
    fn quote_cache_memory(&self, bytes: u64) -> Result<CacheMemoryQuote, AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<CacheMemoryLease, AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
}
impl crate::cache_test::Provider for FixtureProvider {
    fn acquire_cache(&self, _: u64, _: bool) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn release_cache(&self, _: u64, _: bool) {}
}
fn opening(provider: &Arc<FixtureProvider>) -> RetainedDatabaseOpening {
    let mut opening = Database::builder(provider.clone(), [79; 16], CacheConfig::default())
        .retain_backend(Box::new(InMemoryGroup::new()), DatabaseOpenMode::Create);
    assert_eq!(opening.open().settlement(), DatabaseOpenSettlement::Ready);
    opening
}
fn pool(opening: &RetainedDatabaseOpening, provider: &Arc<FixtureProvider>) -> NativeSourcePool {
    let mut pool = opening
        .database()
        .unwrap()
        .queue_native_source_pool(provider.clone());
    pool.install(opening.retained_database().unwrap()).unwrap();
    pool
}
fn rights(opening: &RetainedDatabaseOpening, pool: &mut NativeSourcePool) -> SourceReadRights {
    let mut rights = opening.database().unwrap().queue_source_read_rights();
    rights
        .prepare_funded(opening.retained_database().unwrap(), pool)
        .unwrap();
    rights
}
fn same_original(error: &io::Error, provider: &FixtureProvider) -> usize {
    let original = error.get_ref().unwrap().downcast_ref::<Original>().unwrap();
    assert!(Arc::ptr_eq(&original.0, &provider.original));
    original as *const Original as usize
}
fn funding_original(
    observation: TerminalObservation<'_, SourceFundingError>,
    provider: &FixtureProvider,
    mode: usize,
) -> usize {
    match observation {
        TerminalObservation::Returned(Err(SourceFundingError::Provider(error))) if mode == 1 => {
            same_original(error, provider)
        }
        TerminalObservation::Panicked(payload) if mode == 2 => {
            let original = payload.downcast_ref::<Original>().unwrap();
            assert!(Arc::ptr_eq(&original.0, &provider.original));
            original as *const Original as usize
        }
        _ => panic!("original funding failure was not retained"),
    }
}
fn native_original(
    observation: TerminalObservation<'_, StorageError>,
    provider: &FixtureProvider,
    mode: usize,
) -> usize {
    match observation {
        TerminalObservation::Returned(Err(StorageError::Io(error))) if mode == 1 => {
            same_original(error, provider)
        }
        TerminalObservation::Panicked(payload) if mode == 2 => {
            let original = payload.downcast_ref::<Original>().unwrap();
            assert!(Arc::ptr_eq(&original.0, &provider.original));
            original as *const Original as usize
        }
        _ => panic!("original native failure was not retained"),
    }
}

#[test]
fn pool_bind_retains_original_error_or_panic_and_actual_backend_without_retry() {
    for mode in [1, 2] {
        let provider = FixtureProvider::new();
        provider.mode[POOL].store(mode, Ordering::Release);
        let opening = opening(&provider);
        let mut pool = pool(&opening, &provider);
        let original = funding_original(pool.installation(), &provider, mode);
        assert!(!pool.is_ready());
        assert_eq!(
            pool.dispose_unbound(),
            Err(SourceFundingCallError::WrongPhase)
        );
        assert!(pool.unbound.is_some());
        assert!(pool.binding.is_some());
        assert_eq!(provider.live[POOL].load(Ordering::Acquire), 1);
        pool.install(opening.retained_database().unwrap()).unwrap();
        assert_eq!(
            funding_original(pool.installation(), &provider, mode),
            original
        );
        assert_eq!(provider.calls[POOL].load(Ordering::Acquire), 1);
        pool.seal();
        pool.dispose_sealed();
        assert!(matches!(
            pool.disposal(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert_eq!(provider.live[POOL].load(Ordering::Acquire), 0);
    }
}

#[test]
fn account_bind_retains_original_error_or_panic_and_actual_backend_without_retry() {
    for mode in [1, 2] {
        let provider = FixtureProvider::new();
        let opening = opening(&provider);
        let mut pool = pool(&opening, &provider);
        let rights = rights(&opening, &mut pool);
        provider.mode[ACCOUNT].store(mode, Ordering::Release);
        let mut read = pool.queue_read(opening.database().unwrap()).unwrap();
        read.prepare(opening.retained_database().unwrap(), &rights)
            .unwrap();
        let original = funding_original(read.account_installation(), &provider, mode);
        assert!(read.funding.backend.is_some());
        assert!(read.funding.binding.is_some());
        assert_eq!(provider.live[ACCOUNT].load(Ordering::Acquire), 1);
        read.prepare(opening.retained_database().unwrap(), &rights)
            .unwrap();
        assert_eq!(
            funding_original(read.account_installation(), &provider, mode),
            original
        );
        assert_eq!(provider.calls[ACCOUNT].load(Ordering::Acquire), 1);
        read.close(opening.retained_database().unwrap()).unwrap();
        read.dispose_account();
        assert!(matches!(
            read.account_retirement(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert_eq!(provider.live[ACCOUNT].load(Ordering::Acquire), 0);
    }
}

#[test]
fn each_child_bind_keeps_original_and_pending_credit_after_provider_error_or_panic() {
    for stage in [RIGHTS, BACKING, PIN] {
        for mode in [1, 2] {
            let provider = FixtureProvider::new();
            let opening = opening(&provider);
            let mut pool = pool(&opening, &provider);
            provider.mode[stage].store(mode, Ordering::Release);
            let mut rights = rights(&opening, &mut pool);
            if stage == RIGHTS {
                let original = native_original(rights.report().preparation(), &provider, mode);
                assert!(pool.rights_credit.is_some());
                assert_eq!(provider.live[stage].load(Ordering::Acquire), 1);
                assert_eq!(
                    rights
                        .prepare_funded(opening.retained_database().unwrap(), &mut pool)
                        .err(),
                    Some(SourceReadCallError::WrongPhase)
                );
                assert_eq!(
                    native_original(rights.report().preparation(), &provider, mode),
                    original
                );
            } else {
                assert_eq!(rights.report().settlement(), SourceRightsSettlement::Ready);
                let mut read = pool.queue_read(opening.database().unwrap()).unwrap();
                read.prepare(opening.retained_database().unwrap(), &rights)
                    .unwrap();
                let original = native_original(read.native_report().preparation(), &provider, mode);
                assert!(read.funding.child_credit[stage - BACKING].is_some());
                assert_eq!(provider.live[stage].load(Ordering::Acquire), 1);
                assert_eq!(
                    read.prepare(opening.retained_database().unwrap(), &rights)
                        .err(),
                    Some(SourceReadCallError::WrongPhase)
                );
                assert_eq!(
                    native_original(read.native_report().preparation(), &provider, mode),
                    original
                );
            }
            assert_eq!(provider.calls[stage].load(Ordering::Acquire), 1);
        }
    }
}

#[test]
fn child_foreign_and_repeated_claims_are_terminal_before_another_constructor() {
    let provider: Arc<dyn SourceMemoryProvider> = FixtureProvider::new();
    let foreign: Arc<dyn SourceMemoryProvider> = FixtureProvider::new();
    for foreign_first in [false, true] {
        let mut status = BindStatus::new();
        let mut target = None;
        let live = Arc::new(AtomicUsize::new(0));
        {
            let mut install = SourceChildInstall {
                provider: &provider,
                status: &mut status,
                target: &mut target,
                purpose: SourceFundingPurpose::Pin,
            };
            if foreign_first {
                assert_eq!(
                    install.try_begin_bind(foreign.clone()).err(),
                    Some(SourceFundingCallError::ForeignProvider)
                );
                assert_eq!(
                    install.try_begin_bind(provider.clone()).err(),
                    Some(SourceFundingCallError::ForeignProvider)
                );
            } else {
                let permit = install.try_begin_bind(provider.clone()).unwrap();
                live.store(1, Ordering::Release);
                permit.bind(Token(live.clone()));
                assert_eq!(
                    install.try_begin_bind(provider.clone()).err(),
                    Some(SourceFundingCallError::RepeatedBind)
                );
                assert_eq!(
                    install.try_begin_bind(foreign.clone()).err(),
                    Some(SourceFundingCallError::RepeatedBind)
                );
            }
        }
        assert_eq!(target.is_some(), !foreign_first);
        assert_eq!(live.load(Ordering::Acquire), usize::from(!foreign_first));
        assert_eq!(
            status.result(),
            Err(if foreign_first {
                SourceFundingCallError::ForeignProvider
            } else {
                SourceFundingCallError::RepeatedBind
            })
        );
        drop(target);
        assert_eq!(live.load(Ordering::Acquire), 0);
    }
}

#[test]
fn invalid_account_stamp_keeps_the_actual_bound_owner_and_sticky_rejection() {
    for (lane, ticket) in [(2, 1), (0, 0)] {
        let provider = FixtureProvider::new();
        let expected: Arc<dyn SourceMemoryProvider> = provider.clone();
        let mut status = BindStatus::new();
        let mut backend = None;
        let mut stamp = None;
        {
            let mut install = SourceAccountInstall {
                provider: &expected,
                status: &mut status,
                backend: &mut backend,
                stamp: &mut stamp,
            };
            install.try_begin_bind(expected.clone()).unwrap().bind(
                Account {
                    provider: provider.clone(),
                    _token: provider.token(ACCOUNT),
                },
                lane,
                ticket,
            );
            assert_eq!(
                install.try_begin_bind(expected.clone()).err(),
                Some(SourceFundingCallError::IncompleteBind)
            );
        }
        assert!(backend.is_some());
        assert!(stamp.is_none());
        assert_eq!(status.result(), Err(SourceFundingCallError::IncompleteBind));
        assert_eq!(provider.live[ACCOUNT].load(Ordering::Acquire), 1);
        drop(backend);
        assert_eq!(provider.live[ACCOUNT].load(Ordering::Acquire), 0);
    }
}

#[test]
fn seal_busy_poll_can_progress_but_first_poll_panic_is_retained_without_retry() {
    for panic in [false, true] {
        let provider = FixtureProvider::new();
        let opening = opening(&provider);
        let mut pool = pool(&opening, &provider);
        provider.busy.store(true, Ordering::Release);
        pool.seal();
        assert!(!pool.is_ready());
        assert!(matches!(
            pool.seal_barrier(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(matches!(
            pool.seal_progress(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(matches!(pool.sealing(), TerminalObservation::NotEntered));
        provider.busy.store(false, Ordering::Release);
        provider.panic_poll.store(panic, Ordering::Release);
        pool.seal();
        if panic {
            let TerminalObservation::Panicked(original) = pool.seal_progress() else {
                panic!("seal poll panic escaped custody")
            };
            assert!(Arc::ptr_eq(
                &original.downcast_ref::<Original>().unwrap().0,
                &provider.original
            ));
            let address = original as *const _ as *const () as usize;
            provider.panic_poll.store(false, Ordering::Release);
            pool.seal();
            let TerminalObservation::Panicked(original) = pool.seal_progress() else {
                panic!("seal poll panic was replaced")
            };
            assert_eq!(original as *const _ as *const () as usize, address);
            assert!(matches!(pool.sealing(), TerminalObservation::NotEntered));
            assert!(pool.binding.is_some());
            assert_eq!(provider.seals.load(Ordering::Acquire), 0);
        } else {
            assert!(matches!(
                pool.sealing(),
                TerminalObservation::Returned(Ok(()))
            ));
            pool.seal();
            assert_eq!(provider.seals.load(Ordering::Acquire), 1);
            pool.dispose_sealed();
            assert!(pool.binding.is_none());
        }
        assert_eq!(provider.barriers.load(Ordering::Acquire), 1);
        assert_eq!(provider.polls.load(Ordering::Acquire), 2);
    }
}

static WATCH_LOCK: Mutex<()> = Mutex::new(());
static TARGETS: [AtomicUsize; 2] = [const { AtomicUsize::new(0) }; 2];
static FREED: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
pub(super) fn note_deallocation(pointer: *mut u8, layout: Layout) {
    let start = pointer as usize;
    for (target, freed) in TARGETS.iter().zip(&FREED) {
        let target = target.load(Ordering::Acquire);
        if target != 0 && target >= start && target - start < layout.size() {
            freed.store(true, Ordering::Release);
        }
    }
}
struct DeallocationWatch;
impl Drop for DeallocationWatch {
    fn drop(&mut self) {
        for target in &TARGETS {
            target.store(0, Ordering::Release);
        }
    }
}
struct FinalCredit(Arc<AtomicUsize>);
impl Drop for FinalCredit {
    fn drop(&mut self) {
        assert!(
            FREED.iter().all(|freed| freed.load(Ordering::Acquire)),
            "actual inner token Box or native outer Box survived final credit"
        );
        assert_eq!(self.0.fetch_sub(1, Ordering::AcqRel), 1);
    }
}
#[test]
fn actual_child_token_and_native_outer_box_deallocate_before_final_credit() {
    let _exclusive = WATCH_LOCK.lock().unwrap();
    let provider: Arc<dyn SourceMemoryProvider> = FixtureProvider::new();
    let mut status = BindStatus::new();
    let mut target = None;
    let credit = Arc::new(AtomicUsize::new(1));
    SourceChildInstall {
        provider: &provider,
        status: &mut status,
        target: &mut target,
        purpose: SourceFundingPurpose::Backing,
    }
    .try_begin_bind(provider.clone())
    .unwrap()
    .bind(FinalCredit(credit.clone()));
    assert_eq!(status.result(), Ok(()));
    let allocation = target.take().unwrap();
    let inner = allocation.token_address_for_test();
    let native = allocation.into_native();
    let outer = native.as_ref() as *const dyn ResidentLease as *const () as usize;
    for ((target, freed), address) in TARGETS.iter().zip(&FREED).zip([inner, outer]) {
        freed.store(false, Ordering::Release);
        target.store(address, Ordering::Release);
    }
    let _watch = DeallocationWatch;
    assert_eq!(credit.load(Ordering::Acquire), 1);
    native.retire();
    assert!(FREED.iter().all(|freed| freed.load(Ordering::Acquire)));
    assert_eq!(credit.load(Ordering::Acquire), 0);
}

#[test]
fn funded_corridor_rejects_ordinary_foreign_database_pool_and_repeated_account_before_children() {
    let provider = FixtureProvider::new();
    let opening = opening(&provider);
    let database = opening.retained_database().unwrap();
    let mut first = pool(&opening, &provider);
    let mut second = pool(&opening, &provider);
    let first_rights = rights(&opening, &mut first);
    let second_rights = rights(&opening, &mut second);
    let mut ordinary = opening.database().unwrap().queue_source_read_rights();
    ordinary.prepare(database).unwrap();
    let mut read = first.queue_read(opening.database().unwrap()).unwrap();
    assert_eq!(
        read.native.prepare(database, &first_rights).err(),
        Some(SourceReadCallError::FundingRequired)
    );
    assert_eq!(
        read.native
            .prepare_funded(database, &ordinary, &mut read.funding)
            .err(),
        Some(SourceReadCallError::ForeignFunding)
    );
    assert_eq!(
        read.native
            .prepare_funded(database, &second_rights, &mut read.funding)
            .err(),
        Some(SourceReadCallError::ForeignFunding)
    );
    let foreign_provider = FixtureProvider::new();
    let foreign = super::tests::opening(&foreign_provider);
    assert_eq!(
        read.native
            .prepare_funded(
                foreign.retained_database().unwrap(),
                &first_rights,
                &mut read.funding
            )
            .err(),
        Some(SourceReadCallError::ForeignDatabase)
    );
    assert_eq!(provider.calls[ACCOUNT].load(Ordering::Acquire), 0);
    assert_eq!(provider.calls[BACKING].load(Ordering::Acquire), 0);
    read.prepare(database, &first_rights).unwrap();
    assert_eq!(
        read.native_report().settlement(),
        SourceReadSettlement::Prepared
    );
    assert_eq!(
        read.native.prepare(database, &ordinary).err(),
        Some(SourceReadCallError::FundingRequired)
    );
    let mut other = first.queue_read(opening.database().unwrap()).unwrap();
    assert_eq!(
        read.native
            .prepare_funded(database, &first_rights, &mut other.funding)
            .err(),
        Some(SourceReadCallError::WrongPhase)
    );
    assert_eq!(provider.calls[ACCOUNT].load(Ordering::Acquire), 1);
    assert_eq!(provider.calls[BACKING].load(Ordering::Acquire), 1);
    assert_eq!(provider.calls[PIN].load(Ordering::Acquire), 1);
    read.close(database).unwrap();
    read.dispose_account();
    assert!(matches!(
        read.account_retirement(),
        TerminalObservation::Returned(Ok(()))
    ));
}

#[test]
fn final_controller_disposal_panic_retains_original_database_and_does_not_retry() {
    let provider = FixtureProvider::new();
    let mut opening = opening(&provider);
    let mut pool = pool(&opening, &provider);
    let mut read = pool.queue_read(opening.database().unwrap()).unwrap();
    // No account was ever installed. Sealing/disposal removes the pool's
    // facade, leaving this real queued request's controller as the final alias.
    pool.seal();
    pool.dispose_sealed();
    assert!(matches!(
        pool.disposal(),
        TerminalObservation::Returned(Ok(()))
    ));
    assert!(pool.binding.is_none());
    assert_eq!(provider.pool_drops.load(Ordering::Acquire), 0);
    read.close(opening.retained_database().unwrap()).unwrap();
    assert!(read.is_closed());
    assert!(read.funding.binding.is_some());
    provider.panic_pool_drop.store(true, Ordering::Release);
    read.dispose_account();
    let TerminalObservation::Panicked(payload) = read.account_controller_disposal() else {
        panic!("final controller destructor panic escaped retained custody");
    };
    let original = payload.downcast_ref::<Original>().unwrap();
    assert!(Arc::ptr_eq(&original.0, &provider.original));
    let address = original as *const Original as usize;
    assert!(read.funding.binding.is_some());
    assert!(read.funding.owner.is_none());
    assert_eq!(provider.pool_drops.load(Ordering::Acquire), 1);
    // The distinct native disposition cannot falsely certify controller drop.
    assert!(read.is_closed());
    assert_eq!(
        opening.close().settlement(),
        DatabaseOpenSettlement::WaitingForTransactions
    );
    read.dispose_account();
    let TerminalObservation::Panicked(payload) = read.account_controller_disposal() else {
        panic!("first controller destructor panic was replaced");
    };
    assert_eq!(
        payload.downcast_ref::<Original>().unwrap() as *const Original as usize,
        address
    );
    assert!(read.funding.binding.is_some());
    assert_eq!(provider.pool_drops.load(Ordering::Acquire), 1);
    assert_eq!(provider.calls[ACCOUNT].load(Ordering::Acquire), 0);
}

#[test]
fn unbound_install_failure_disposes_exact_database_once_and_keeps_original() {
    for mode in [1, 2] {
        let provider = FixtureProvider::new();
        provider
            .fail_pool_before_bind
            .store(true, Ordering::Release);
        provider.mode[POOL].store(mode, Ordering::Release);
        let mut opening = opening(&provider);
        let mut pool = opening
            .database()
            .unwrap()
            .queue_native_source_pool(provider.clone());
        assert_eq!(
            pool.dispose_unbound(),
            Err(SourceFundingCallError::WrongPhase)
        );
        pool.install(opening.retained_database().unwrap()).unwrap();
        let original = funding_original(pool.installation(), &provider, mode);
        assert!(pool.owner.is_none() && pool.unbound.is_none());
        assert!(pool.context.is_some() && pool.binding.is_some());
        assert_eq!(provider.live[POOL].load(Ordering::Acquire), 0);
        assert_eq!(
            opening.close().settlement(),
            DatabaseOpenSettlement::WaitingForTransactions
        );
        pool.dispose_unbound().unwrap();
        assert!(matches!(
            pool.disposal(),
            TerminalObservation::Returned(Ok(()))
        ));
        assert!(pool.context.is_none() && pool.binding.is_none());
        assert_eq!(
            funding_original(pool.installation(), &provider, mode),
            original
        );
        assert_eq!(provider.calls[POOL].load(Ordering::Acquire), 1);
        pool.dispose_unbound().unwrap();
        assert_eq!(
            funding_original(pool.installation(), &provider, mode),
            original
        );
        assert_eq!(opening.close().settlement(), DatabaseOpenSettlement::Closed);
    }
}

#[test]
fn history_abort_rejects_unproved_provider_capacity_panic_and_false_success() {
    for mode in [1, 2, 3] {
        let provider = FixtureProvider::new();
        let opening = opening(&provider);
        let mut pool = pool(&opening, &provider);
        let rights = rights(&opening, &mut pool);
        let mut read = pool.queue_read(opening.database().unwrap()).unwrap();
        read.prepare(opening.retained_database().unwrap(), &rights)
            .unwrap();
        read.capture(opening.retained_database().unwrap()).unwrap();
        let selected = read.selected_generation();
        assert!(selected.is_some());
        provider.history_mode.store(mode, Ordering::Release);
        read.prepare_history(opening.retained_database().unwrap())
            .unwrap();
        let original = if mode < 3 {
            funding_original(read.history_preparation().unwrap(), &provider, mode)
        } else {
            assert!(matches!(
                read.history_preparation(),
                Some(TerminalObservation::Returned(Err(
                    SourceFundingError::Protocol(SourceFundingCallError::IncompleteBind)
                )))
            ));
            0
        };
        for _ in 0..2 {
            assert!(matches!(
                read.abort_history(opening.retained_database().unwrap())
                    .unwrap(),
                SourceHistoryAbort::Retained
            ));
            assert_eq!(read.selected_generation(), selected);
            assert!(read.readable().is_err());
            if mode < 3 {
                assert_eq!(
                    funding_original(read.history_preparation().unwrap(), &provider, mode),
                    original
                );
            }
            assert!(matches!(
                read.history_report().unwrap().cancellation(),
                TerminalObservation::NotEntered
            ));
        }
        // Full closure remains a separate operation and preserves the cause.
        read.close(opening.retained_database().unwrap()).unwrap();
        if mode < 3 {
            assert_eq!(
                funding_original(read.history_preparation().unwrap(), &provider, mode),
                original
            );
        }
        read.dispose_account();
    }
}
