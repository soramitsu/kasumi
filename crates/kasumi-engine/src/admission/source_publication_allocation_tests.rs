//! Actual allocator-tail observations for the real installed MemoryCore bank.
use super::*;
use std::{
    alloc::Layout,
    cell::RefCell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

#[derive(Default)]
struct Captured {
    addresses: [usize; 4],
    bank: Option<BankRef>,
}
thread_local! { static CAPTURE: RefCell<Option<Captured>> = const { RefCell::new(None) }; }
fn record(index: usize, pointer: usize) {
    CAPTURE.with(|slot| {
        if let Some(capture) = slot.borrow_mut().as_mut() {
            capture.addresses[index] = pointer;
        }
    });
}
pub(super) fn bank(bank: &BankRef) {
    record(0, std::ptr::from_ref(bank.get()) as usize);
    CAPTURE.with(|slot| {
        if let Some(capture) = slot.borrow_mut().as_mut() {
            capture.bank = Some(bank.clone());
        }
    });
}
pub(super) fn account(account: &AccountRef) {
    record(1, std::ptr::from_ref(account.get()) as usize);
}
pub(super) fn pool_box(pool: &Pool) {
    record(2, std::ptr::from_ref(pool) as usize);
}
pub(super) fn account_box(account: &AccountFacade) {
    record(3, std::ptr::from_ref(account) as usize);
}
struct Watch {
    address: AtomicUsize,
    entered: AtomicBool,
    released: AtomicBool,
    finished: AtomicBool,
}
static WATCH: Watch = Watch {
    address: AtomicUsize::new(0),
    entered: AtomicBool::new(false),
    released: AtomicBool::new(false),
    finished: AtomicBool::new(false),
};
static SERIAL: Mutex<()> = Mutex::new(());
pub(crate) fn before_deallocate(pointer: *mut u8, layout: Layout) -> bool {
    let address = WATCH.address.load(Ordering::Acquire);
    if address == 0 || address.wrapping_sub(pointer as usize) >= layout.size() {
        return false;
    }
    if WATCH
        .address
        .compare_exchange(address, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    WATCH.entered.store(true, Ordering::Release);
    while !WATCH.released.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    true
}
pub(crate) fn after_deallocate(matched: bool) {
    if matched {
        WATCH.finished.store(true, Ordering::Release);
    }
}
struct Gate;
impl Gate {
    fn arm(address: usize) -> Self {
        assert_ne!(address, 0);
        assert_eq!(WATCH.address.load(Ordering::Acquire), 0);
        WATCH.entered.store(false, Ordering::Relaxed);
        WATCH.released.store(false, Ordering::Relaxed);
        WATCH.finished.store(false, Ordering::Relaxed);
        WATCH.address.store(address, Ordering::Release);
        Self
    }
    fn wait(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !WATCH.entered.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "actual source funding allocation never reached System.dealloc"
            );
            std::thread::yield_now();
        }
        assert!(!WATCH.finished.load(Ordering::Acquire));
    }
    fn release(&self) {
        WATCH.released.store(true, Ordering::Release);
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        self.release();
        WATCH.address.store(0, Ordering::Release);
    }
}
struct Worker<T>(Option<std::thread::JoinHandle<T>>);
impl<T> Worker<T> {
    fn join(mut self) -> T {
        WATCH.released.store(true, Ordering::Release);
        self.0
            .take()
            .unwrap()
            .join()
            .expect("retirement worker failed")
    }
}
impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        WATCH.released.store(true, Ordering::Release);
        if let Some(worker) = self.0.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn source_bank_and_account_actual_arc_and_backend_box_tails_remain_funded() -> anyhow::Result<()> {
    let _serial = SERIAL.lock().unwrap();
    for target in [0, 1, 2, 3] {
        let fixture = tests::Fixture::new()?;
        let core = fixture.core().clone();
        let before = core.snapshot();
        let mut native = fixture.native();
        CAPTURE.with(|slot| *slot.borrow_mut() = Some(Captured::default()));
        native.install().unwrap();
        let bank = native.pool().snapshot().unwrap();
        native.prepare(0).unwrap();
        let mut captured = CAPTURE.with(|slot| slot.borrow_mut().take().unwrap());
        assert!(captured.addresses.iter().all(|address| *address != 0));
        let address = captured.addresses[target];
        if target == 0 || target == 2 {
            // Fixed-bank tail is final: no observer may keep the bank alive.
            drop(captured.bank.take());
            tests::close(&mut native, 0);
        }
        let gate = Gate::arm(address);
        let worker = Worker(Some(std::thread::spawn(move || {
            if target == 1 || target == 3 {
                tests::close(&mut native, 0);
            } else {
                native.retire().unwrap();
            }
            native
        })));
        gate.wait();
        let snapshot = core.snapshot();
        assert_eq!(snapshot.live_reservations, before.live_reservations + 1);
        if target == 1 || target == 3 {
            assert_eq!(
                snapshot.reserved_bytes,
                before.reserved_bytes + bank.charged_bytes
            );
            let state = captured.bank.as_ref().unwrap().get().state.lock().unwrap();
            assert_eq!(
                state
                    .lanes
                    .iter()
                    .filter(|lane| lane.assignment == Assignment::Assigned)
                    .count(),
                1,
                "logical source lane released before actual account allocation deallocation"
            );
        } else {
            assert_eq!(
                snapshot.reserved_bytes,
                before.reserved_bytes + bank.fixed_bytes,
                "fixed bank credit released before its actual Arc/backend Box deallocation"
            );
        }
        gate.release();
        let mut native = worker.join();
        assert!(WATCH.finished.load(Ordering::Acquire));
        drop(gate);
        drop(captured.bank.take());
        if target == 1 || target == 3 {
            assert_eq!(native.pool().snapshot().unwrap().assigned, 0);
            native.retire().unwrap();
        }
        drop(native);
        assert_eq!(core.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(core.snapshot().live_reservations, before.live_reservations);
        fixture.finish()?;
    }
    Ok(())
}

#[test]
fn registered_source_actual_bank_account_report_and_control_tails_keep_exact_credit()
-> anyhow::Result<()> {
    use kasumi_store::{NodeReadPhase, SourcePoolPhase};
    let _serial = SERIAL.lock().unwrap();
    // Actual Bank Arc, Account Arc, ReaderState Arc, ReportCharge Arc, and
    // SourcePoolRequest census Arc. The unchanged ResidentAllocation tests
    // independently prove token Box-before-credit; no token internals escape.
    for target in [0, 1, 2, 3, 4] {
        let fixture = tests::Fixture::new()?;
        let core = fixture.core().clone();
        let before = core.snapshot();
        let metadata = registered_tests::metadata_quote(&fixture)?;
        let mut source = fixture.registered();
        source.install();
        source.queue(0, 0)?;
        source.prepare(0);
        source.capture(0);
        let total = metadata.iter().sum::<u64>() + source.native_snapshot().unwrap().charged_bytes;
        let addresses = source.allocation_addresses(0).unwrap();
        let pool_id = source.id();
        assert!(addresses.iter().all(|address| *address != 0));
        if target == 0 || target == 4 {
            assert_eq!(source.close_read(0), Some(NodeReadPhase::Finished));
            source.release_read(0);
            source.drain();
        }
        let gate = Gate::arm(addresses[target]);
        let worker_core = core.clone();
        let worker = Worker(Some(std::thread::spawn(move || {
            if matches!(target, 1..=3) {
                assert_eq!(source.close_read(0), Some(NodeReadPhase::Finished));
                source.release_read(0);
                source.drain();
            } else {
                source.seal();
                source.drain();
                assert_eq!(source.phase(), Some(SourcePoolPhase::Finished));
            }
            if target == 4 {
                drop(source);
                worker_core.storage_census.drain_owner(pool_id);
                None
            } else {
                Some(source)
            }
        })));
        gate.wait();
        let snapshot = core.snapshot();
        match target {
            1..=3 => {
                assert_eq!(snapshot.reserved_bytes, before.reserved_bytes + total);
                assert_eq!(snapshot.live_reservations, before.live_reservations + 5);
                assert_eq!(
                    core.storage_census.snapshot().source_active,
                    1,
                    "protected cell was returned before its real report/account allocation deallocated"
                );
            }
            0 => {
                assert_eq!(
                    snapshot.reserved_bytes,
                    before.reserved_bytes + metadata[0] + metadata[1]
                );
                assert_eq!(snapshot.live_reservations, before.live_reservations + 2);
            }
            4 => {
                assert_eq!(snapshot.reserved_bytes, before.reserved_bytes + metadata[0]);
                assert_eq!(snapshot.live_reservations, before.live_reservations + 1);
            }
            _ => unreachable!(),
        }
        gate.release();
        let source = worker.join();
        assert!(WATCH.finished.load(Ordering::Acquire));
        drop(gate);
        if let Some(source) = source {
            source.seal();
            source.drain();
            assert_eq!(source.phase(), Some(SourcePoolPhase::Finished));
            drop(source);
            core.storage_census.drain_owner(pool_id);
        }
        assert_eq!(core.snapshot().reserved_bytes, before.reserved_bytes);
        assert_eq!(core.snapshot().live_reservations, before.live_reservations);
        fixture.finish()?;
    }
    Ok(())
}
