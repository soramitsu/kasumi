//! Scoped observation of actual successful TestDiskMemory installed requests.
//! No allocation, callbacks, admission changes or lock acquisition in the hook.
use super::TestDiskMemory;
use std::cell::Cell;
#[derive(Clone, Copy)]
pub(crate) struct Observed {
    owner: usize,
    baseline_bytes: u64,
    baseline_slots: usize,
    pub(crate) peak_bytes: u64,
    pub(crate) peak_slots: usize,
    pub(crate) requests: [u64; 64],
    pub(crate) count: usize,
    pub(crate) overflow: bool,
}
thread_local! { static WATCH: Cell<Option<Observed>> = const { Cell::new(None) }; }
pub(super) fn record(owner: usize, charge: u64, total: u64, slots: usize) {
    let _ = WATCH.try_with(|watch| {
        if let Some(mut value) = watch.get() {
            if value.owner != owner {
                return;
            }
            value.peak_bytes = value
                .peak_bytes
                .max(total.saturating_sub(value.baseline_bytes));
            value.peak_slots = value
                .peak_slots
                .max(slots.saturating_sub(value.baseline_slots));
            if value.count < value.requests.len() {
                value.requests[value.count] = charge;
                value.count += 1;
            } else {
                value.overflow = true;
            }
            watch.set(Some(value));
        }
    });
}
pub(crate) fn measure<T>(memory: &TestDiskMemory, work: impl FnOnce() -> T) -> (T, Observed) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            WATCH.with(|watch| watch.set(None));
        }
    }
    let baseline = memory.snapshot();
    let initial = Observed {
        owner: std::ptr::from_ref(memory) as usize,
        baseline_bytes: baseline.used_bytes,
        baseline_slots: baseline.live_reservations,
        peak_bytes: 0,
        peak_slots: 0,
        requests: [0; 64],
        count: 0,
        overflow: false,
    };
    WATCH.with(|watch| {
        assert!(
            watch.replace(Some(initial)).is_none(),
            "nested request observation"
        )
    });
    let reset = Reset;
    let result = work();
    let observed = WATCH.with(|watch| watch.get().unwrap());
    drop(reset);
    (result, observed)
}
