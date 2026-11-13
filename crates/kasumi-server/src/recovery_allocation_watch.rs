//! Fixed test-only observation shared by the sole Server allocator.
use std::{
    cell::Cell,
    sync::{
        Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
};

// Exact addresses are fixed before aliases race. This observer does not own
// tested allocations and introduces no allocator callback or new heap backing.
// The allocator hook finds the watched set from any thread without allocating,
// so one set is active in the process at a time (ADDRESS_LOCK). Watched blocks
// are live when their watch begins, so the first free of a watched address is
// that block's retirement, on whichever thread. After it the allocator may
// hand the address to another concurrently running test, whose own free is not
// a retirement: later frees count only on the watch's enrolled threads.
const ADDRESS_CAPACITY: usize = 8;
static ADDRESS_LOCK: Mutex<()> = Mutex::new(());
static ADDRESSES: [AtomicUsize; ADDRESS_CAPACITY] =
    [const { AtomicUsize::new(0) }; ADDRESS_CAPACITY];
static RETIREMENTS: [AtomicUsize; ADDRESS_CAPACITY] =
    [const { AtomicUsize::new(0) }; ADDRESS_CAPACITY];
/// The active watch's generation; 0 while no watch is active.
static ACTIVE_GENERATION: AtomicUsize = AtomicUsize::new(0);
static GENERATIONS: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    /// The generation this thread is enrolled in; 0 for none.
    static ENROLLED: Cell<usize> = const { Cell::new(0) };
}
pub(crate) struct AddressWatch {
    generation: usize,
    _serial: MutexGuard<'static, ()>,
}
impl AddressWatch {
    /// Watch `addresses` and enroll the calling thread.
    pub(crate) fn begin(addresses: [usize; ADDRESS_CAPACITY]) -> Self {
        // A watch whose test failed an assertion unwound holding this guard.
        // Every watched value is reset below, so that poison carries no state.
        let serial = ADDRESS_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let generation = GENERATIONS.fetch_add(1, Ordering::SeqCst) + 1;
        for (index, address) in addresses.into_iter().enumerate() {
            RETIREMENTS[index].store(0, Ordering::SeqCst);
            ADDRESSES[index].store(address, Ordering::SeqCst);
        }
        ACTIVE_GENERATION.store(generation, Ordering::SeqCst);
        let watch = Self {
            generation,
            _serial: serial,
        };
        watch.enroll();
        watch
    }
    /// Count the calling thread's frees as well: a fixture thread that drops
    /// a watched owner.
    pub(crate) fn enroll(&self) {
        ENROLLED.with(|enrolled| enrolled.set(self.generation));
    }
    pub(crate) fn all_retired() -> bool {
        ADDRESSES.iter().zip(&RETIREMENTS).all(|(address, count)| {
            address.load(Ordering::SeqCst) == 0 || count.load(Ordering::SeqCst) == 1
        })
    }
    pub(crate) fn counts(&self) -> [usize; ADDRESS_CAPACITY] {
        std::array::from_fn(|index| RETIREMENTS[index].load(Ordering::SeqCst))
    }
}
impl Drop for AddressWatch {
    fn drop(&mut self) {
        ACTIVE_GENERATION.store(0, Ordering::SeqCst);
        for address in &ADDRESSES {
            address.store(0, Ordering::SeqCst);
        }
    }
}
/// Whether a free on the calling thread belongs to the active address watch.
fn enrolled_in_active_watch() -> bool {
    let active = ACTIVE_GENERATION.load(Ordering::SeqCst);
    active != 0 && ENROLLED.try_with(Cell::get).is_ok_and(|own| own == active)
}

const CAPACITY: usize = 256;
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Allocation {
    pub(crate) address: usize,
    pub(crate) bytes: usize,
    pub(crate) align: usize,
    pub(crate) freed: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct Observation {
    pub(crate) allocations: [Allocation; CAPACITY],
    pub(crate) count: usize,
    pub(crate) overflow: bool,
}
impl Observation {
    pub(crate) fn allocation(&self, address: usize) -> Option<Allocation> {
        self.allocations[..self.count]
            .iter()
            .rev()
            .find(|allocation| allocation.address == address)
            .copied()
    }
}
thread_local! {
    static WATCH: Cell<Option<Observation>> = const { Cell::new(None) };
}
pub(crate) fn allocated(address: usize, bytes: usize, align: usize) {
    let _ = WATCH.try_with(|slot| {
        if let Some(mut observation) = slot.get() {
            if observation.count < CAPACITY {
                observation.allocations[observation.count] = Allocation {
                    address,
                    bytes,
                    align,
                    freed: false,
                };
                observation.count += 1;
            } else {
                observation.overflow = true;
            }
            slot.set(Some(observation));
        }
    });
}
pub(crate) fn deallocated(address: usize) {
    let enrolled = enrolled_in_active_watch();
    for (target, count) in ADDRESSES.iter().zip(&RETIREMENTS) {
        if target.load(Ordering::SeqCst) == address {
            if enrolled {
                count.fetch_add(1, Ordering::SeqCst);
            } else {
                let _ = count.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
            }
        }
    }
    let _ = WATCH.try_with(|slot| {
        if let Some(mut observation) = slot.get() {
            if let Some(allocation) = observation.allocations[..observation.count]
                .iter_mut()
                .rev()
                .find(|allocation| allocation.address == address && !allocation.freed)
            {
                allocation.freed = true;
            }
            slot.set(Some(observation));
        }
    });
}
pub(crate) struct Watch;
impl Watch {
    pub(crate) fn begin() -> Self {
        WATCH.with(|slot| {
            assert!(slot.get().is_none());
            slot.set(Some(Observation {
                allocations: [Allocation {
                    address: 0,
                    bytes: 0,
                    align: 0,
                    freed: false,
                }; CAPACITY],
                count: 0,
                overflow: false,
            }));
        });
        Self
    }
    pub(crate) fn snapshot(&self) -> Observation {
        Self::current()
    }
    pub(crate) fn current() -> Observation {
        WATCH.with(|slot| slot.get().expect("active fixed allocation watch"))
    }
    pub(crate) fn finish(self) -> Observation {
        WATCH.with(|slot| slot.take().expect("active fixed allocation watch"))
    }
}
impl Drop for Watch {
    fn drop(&mut self) {
        let _ = WATCH.try_with(|slot| slot.set(None));
    }
}
