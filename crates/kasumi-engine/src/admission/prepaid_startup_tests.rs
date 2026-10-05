use super::*;
use crate::admission::{AdmissionConfig, MemorySource, startup::StartupSpec};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::task::Poll;
use std::time::Duration;

struct ZeroRss;
impl MemorySource for ZeroRss {
    fn resident_bytes(&self) -> anyhow::Result<u64> {
        Ok(0)
    }
}
fn core() -> Arc<MemoryCore> {
    MemoryCore::create(
        AdmissionConfig {
            max_startup_scopes: 1,
            ..Default::default()
        },
        1 << 30,
        Arc::new(ZeroRss),
        Arc::new(kasumi_clock::SystemLeaseClock),
    )
    .unwrap()
}
#[derive(Default)]
struct Terminal {
    started: bool,
    finished: bool,
    original: Option<u64>,
}
impl StartupTerminal for Terminal {
    type Plan<'a> = ();
    type Output = ();
    fn backing(_: &()) -> anyhow::Result<StartupBacking> {
        Ok(StartupBacking::empty())
    }
    fn allocate(_: (), _: SharedBudgetCharge) -> Self {
        Self::default()
    }
    fn begin(&mut self) -> bool {
        if self.started {
            return false;
        }
        self.started = true;
        true
    }
    fn retirement_ready(&self) -> bool {
        self.started && self.finished && self.original.is_none()
    }
    fn claim_output(&mut self) -> Option<()> {
        self.retirement_ready().then_some(())
    }
}
struct Other;
impl StartupTerminal for Other {
    type Plan<'a> = ();
    type Output = ();
    fn backing(_: &()) -> anyhow::Result<StartupBacking> {
        Ok(StartupBacking::empty())
    }
    fn allocate(_: (), _: SharedBudgetCharge) -> Self {
        Self
    }
    fn begin(&mut self) -> bool {
        true
    }
    fn retirement_ready(&self) -> bool {
        false
    }
    fn claim_output(&mut self) -> Option<()> {
        None
    }
}
#[derive(Default)]
struct Gate {
    entered: AtomicBool,
    released: AtomicBool,
}
async fn worker(
    mut loan: StartupTerminalLoan<Terminal>,
    (gate, original): (Arc<Gate>, Option<u64>),
) {
    gate.entered.store(true, Ordering::Release);
    while !gate.released.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    loan.original = original;
    loan.finished = true;
}
async fn panic_worker(_: StartupTerminalLoan<Terminal>, _: ()) {
    std::panic::panic_any("exact actual startup worker panic");
}

#[tokio::test]
async fn same_initial_joint_reservation_precedes_real_terminal_controls_and_worker() {
    let core = core();
    let baseline = core.snapshot();
    let quote = PrepaidStartup::<Terminal>::required_bytes(&()).unwrap();
    let owner = core
        .prepare_prepaid_startup::<Terminal>()
        .unwrap()
        .install(())
        .unwrap();
    assert_eq!(
        core.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    assert_eq!(
        core.snapshot().reserved_bytes,
        baseline.reserved_bytes + quote
    );
    let gate = Arc::new(Gate::default());
    gate.released.store(true, Ordering::Release);
    let running = owner.begin().unwrap().spawn(worker, (gate, None));
    drop(owner);
    let owner = running;
    let alias = owner.clone();
    owner.join_worker().await;
    assert!(owner.take_output().await.is_some());
    assert!(owner.take_output().await.is_none());
    assert!(owner.retire_empty().await);
    assert!(core.prepaid_startup::<Terminal>(owner.id()).is_none());
    drop(owner);
    assert_eq!(
        core.snapshot().reserved_bytes,
        baseline.reserved_bytes + quote
    );
    drop(alias);
    assert_eq!(core.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        core.snapshot().live_reservations,
        baseline.live_reservations
    );
}

#[tokio::test]
async fn cancelled_join_and_last_facade_drop_preserve_original_same_generation_and_grant() {
    let core = core();
    let baseline = core.snapshot();
    let owner = core
        .prepare_prepaid_startup::<Terminal>()
        .unwrap()
        .install(())
        .unwrap();
    let id = owner.id();
    let gate = Arc::new(Gate::default());
    let owner = owner
        .begin()
        .unwrap()
        .spawn(worker, (gate.clone(), Some(71)));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !gate.entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut joining = Box::pin(owner.join_worker());
    std::future::poll_fn(|cx| {
        assert!(joining.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // The future owns only the borrowed join lock, never the actual handle.
    drop(joining);
    let charged = core.snapshot();
    drop(owner);
    let owner = core.prepaid_startup::<Terminal>(id).unwrap();
    gate.released.store(true, Ordering::Release);
    owner.join_worker().await;
    let address = owner.with_report(|value| {
        let original = value.unwrap().original.as_ref().unwrap();
        assert_eq!(*original, 71);
        original as *const u64 as usize
    });
    assert!(!owner.retire_empty().await);
    drop(owner);
    let owner = core.prepaid_startup::<Terminal>(id).unwrap();
    assert_eq!(owner.id(), id);
    assert_eq!(
        owner.with_report(|value| value.unwrap().original.as_ref().unwrap() as *const u64 as usize),
        address
    );
    assert_eq!(core.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(
        core.snapshot().live_reservations,
        baseline.live_reservations + 1
    );
    assert!(core.prepare_prepaid_startup::<Terminal>().is_err());
}

#[tokio::test]
async fn unused_accepted_loan_and_full_census_refuse_before_named_factory() {
    static FACTORIES: AtomicUsize = AtomicUsize::new(0);
    fn factory(_: StartupTerminalLoan<Terminal>, _: ()) -> impl Future<Output = ()> {
        FACTORIES.fetch_add(1, Ordering::AcqRel);
        async {}
    }
    let core = core();
    let owner = core
        .prepare_prepaid_startup::<Terminal>()
        .unwrap()
        .install(())
        .unwrap();
    let id = owner.id();
    let charged = core.snapshot();
    let unused = owner.begin().unwrap();
    assert!(core.prepare_prepaid_startup::<Terminal>().is_err());
    drop(unused);
    if let Ok(loan) = owner.begin() {
        let _owner = loan.spawn(factory, ());
    }
    assert_eq!(FACTORIES.load(Ordering::Acquire), 0);
    assert!(!owner.retire_empty().await);
    drop(owner);
    let owner = core.prepaid_startup::<Terminal>(id).unwrap();
    assert!(owner.with_report(|value| value.unwrap().started));
    assert!(
        !owner
            .with_worker_report(|report| report.returned())
            .unwrap()
    );
    assert_eq!(core.snapshot().reserved_bytes, charged.reserved_bytes);
}

#[tokio::test]
async fn repeated_old_scope_cannot_remove_reused_typed_terminal_and_foreign_lookup_is_absent() {
    let core = core();
    let other_core = self::core();
    let old = core
        .prepare_startup_scope(StartupSpec { resources: 1 })
        .unwrap();
    let old_id = old.id();
    drop(old.drain().await);
    let owner = core
        .prepare_prepaid_startup::<Terminal>()
        .unwrap()
        .install(())
        .unwrap();
    let id = owner.id();
    assert_eq!(id.slot(), old_id.slot);
    assert_ne!(id.generation(), old_id.generation);
    drop(old.drain().await);
    assert!(core.prepaid_startup::<Terminal>(id).is_some());
    assert!(core.prepaid_startup::<Other>(id).is_none());
    assert!(other_core.prepaid_startup::<Terminal>(id).is_none());
    let other = other_core
        .prepare_prepaid_startup::<Terminal>()
        .unwrap()
        .install(())
        .unwrap();
    assert_eq!(other.id().slot(), id.slot());
    assert_ne!(other.id().generation(), id.generation());
    assert!(other_core.prepaid_startup::<Terminal>(id).is_none());
}

#[tokio::test]
async fn real_join_panic_stays_original_after_facade_drop_without_empty_retirement() {
    let core = core();
    let owner = core
        .prepare_prepaid_startup::<Terminal>()
        .unwrap()
        .install(())
        .unwrap();
    let id = owner.id();
    let owner = owner.begin().unwrap().spawn(panic_worker, ());
    owner.join_worker().await;
    let address = owner
        .with_worker_report(|report| {
            let original = report.original().unwrap();
            assert!(original.is_panic());
            original as *const tokio::task::JoinError as usize
        })
        .unwrap();
    assert!(!owner.retire_empty().await);
    let charged = core.snapshot();
    drop(owner);
    let owner = core.prepaid_startup::<Terminal>(id).unwrap();
    assert_eq!(
        owner.with_worker_report(
            |report| report.original().unwrap() as *const tokio::task::JoinError as usize
        ),
        Some(address)
    );
    assert_eq!(core.snapshot().reserved_bytes, charged.reserved_bytes);
}

#[test]
fn actual_named_factory_panic_is_retained_before_any_worker_join() {
    fn panicking_factory(_: StartupTerminalLoan<Terminal>, _: ()) -> std::future::Ready<()> {
        std::panic::panic_any("exact original factory panic")
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _entered = runtime.enter();
    let core = core();
    let owner = core
        .prepare_prepaid_startup::<Terminal>()
        .unwrap()
        .install(())
        .unwrap();
    let id = owner.id();
    let owner = owner.begin().unwrap().spawn(panicking_factory, ());
    let address = owner
        .with_worker_report(|report| {
            let original = report.factory_panic().unwrap();
            assert_eq!(
                original.downcast_ref::<&'static str>(),
                Some(&"exact original factory panic")
            );
            assert!(!report.returned());
            assert!(!report.handle_retained());
            original as *const (dyn Any + Send) as *const () as usize
        })
        .unwrap();
    drop(owner);
    let owner = core.prepaid_startup::<Terminal>(id).unwrap();
    assert_eq!(
        owner.with_worker_report(
            |report| report.factory_panic().unwrap() as *const (dyn Any + Send) as *const ()
                as usize
        ),
        Some(address)
    );
}

#[test]
fn real_initial_joint_quote_refusal_releases_only_the_unentered_census_seat() {
    static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
    struct Counted;
    impl StartupTerminal for Counted {
        type Plan<'a> = ();
        type Output = ();
        fn backing(_: &()) -> anyhow::Result<StartupBacking> {
            Ok(StartupBacking::empty())
        }
        fn allocate(_: (), _: SharedBudgetCharge) -> Self {
            ALLOCATIONS.fetch_add(1, Ordering::AcqRel);
            Self
        }
        fn begin(&mut self) -> bool {
            true
        }
        fn retirement_ready(&self) -> bool {
            false
        }
        fn claim_output(&mut self) -> Option<()> {
            None
        }
    }
    let core = core();
    let quote = PrepaidStartup::<Counted>::required_bytes(&()).unwrap();
    let free = core.data.max_bytes - core.snapshot().reserved_bytes;
    let held = core.reserve_resident(free - quote + 1).unwrap();
    let charged = core.snapshot();
    let prepared = core.prepare_prepaid_startup::<Counted>().unwrap();
    assert!(prepared.install(()).is_err());
    assert_eq!(ALLOCATIONS.load(Ordering::Acquire), 0);
    assert_eq!(core.snapshot().reserved_bytes, charged.reserved_bytes);
    assert_eq!(core.snapshot().live_reservations, charged.live_reservations);
    assert!(core.prepaid_startup_at::<Counted>(0).is_none());
    // A denial releases its unused seat, not any admitted/retained successor.
    drop(held);
    let owner = core
        .prepare_prepaid_startup::<Counted>()
        .unwrap()
        .install(())
        .unwrap();
    assert_eq!(ALLOCATIONS.load(Ordering::Acquire), 1);
    let id = owner.id();
    drop(owner);
    assert!(core.prepaid_startup::<Counted>(id).is_some());
}

// A supported success facade keeps its SAME original charge on every closed
// alias. The final sized output control retires before that credit is released.
struct SuccessState {
    identity: u64,
    _charge: SharedBudgetCharge,
}
struct Success {
    inner: Option<Arc<SuccessState>>,
}
impl Clone for Success {
    fn clone(&self) -> Self {
        Self {
            inner: Some(self.inner.as_ref().unwrap().clone()),
        }
    }
}
impl Drop for Success {
    fn drop(&mut self) {
        drop(Arc::into_inner(self.inner.take().unwrap()));
    }
}
struct TransferTerminal {
    started: bool,
    finished: bool,
    output: Option<Success>,
}
impl StartupTerminal for TransferTerminal {
    type Plan<'a> = u64;
    type Output = Success;
    fn backing(_: &u64) -> anyhow::Result<StartupBacking> {
        StartupBacking::empty().shared::<SuccessState>()
    }
    fn allocate(identity: u64, charge: SharedBudgetCharge) -> Self {
        Self {
            started: false,
            finished: false,
            output: Some(Success {
                inner: Some(Arc::new(SuccessState {
                    identity,
                    _charge: charge,
                })),
            }),
        }
    }
    fn begin(&mut self) -> bool {
        if self.started {
            return false;
        }
        self.started = true;
        true
    }
    fn retirement_ready(&self) -> bool {
        self.finished && self.output.is_none()
    }
    fn claim_output(&mut self) -> Option<Success> {
        if !self.finished {
            return None;
        }
        self.output.take()
    }
}
async fn transfer_worker(mut loan: StartupTerminalLoan<TransferTerminal>, _: ()) {
    loan.finished = true;
}

#[tokio::test]
async fn exact_success_facade_handoff_is_once_and_same_original_credit_outlives_all_aliases() {
    let core = core();
    let baseline = core.snapshot();
    let quote = PrepaidStartup::<TransferTerminal>::required_bytes(&137).unwrap();
    let owner = core
        .prepare_prepaid_startup::<TransferTerminal>()
        .unwrap()
        .install(137)
        .unwrap();
    let id = owner.id();
    let address = owner.with_report(|value| {
        let output = value
            .unwrap()
            .output
            .as_ref()
            .unwrap()
            .inner
            .as_ref()
            .unwrap();
        assert!(SharedBudgetCharge::ptr_eq(
            &output._charge,
            &owner.state()._charge
        ));
        Arc::as_ptr(output) as usize
    });
    assert!(owner.take_output().await.is_none());
    let running = owner.begin().unwrap().spawn(transfer_worker, ());
    drop(owner);
    let owner = running;
    owner.join_worker().await;
    assert!(
        !owner.retire_empty().await,
        "successful output has not yet transferred"
    );
    let output = owner.take_output().await.unwrap();
    assert_eq!(output.inner.as_ref().unwrap().identity, 137);
    assert_eq!(
        Arc::as_ptr(output.inner.as_ref().unwrap()) as usize,
        address
    );
    assert!(SharedBudgetCharge::ptr_eq(
        &output.inner.as_ref().unwrap()._charge,
        &owner.state()._charge
    ));
    assert!(owner.take_output().await.is_none());
    assert!(owner.retire_empty().await);
    assert!(core.prepaid_startup::<TransferTerminal>(id).is_none());
    let alias = output.clone();
    drop(owner);
    drop(output);
    assert_eq!(
        core.snapshot().reserved_bytes,
        baseline.reserved_bytes + quote
    );
    assert_eq!(alias.inner.as_ref().unwrap().identity, 137);
    drop(alias);
    assert_eq!(core.snapshot().reserved_bytes, baseline.reserved_bytes);
    assert_eq!(
        core.snapshot().live_reservations,
        baseline.live_reservations
    );
}
