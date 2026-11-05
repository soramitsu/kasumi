//! A commit publishes its root without the state lock. These tests block
//! that publication's final flush and check what runs meanwhile: reads on
//! the previous root, with their pins and cache loads, but no operation
//! behind the commit gate.
use super::*;
use crate::group::{GroupFile, TransactionReserveError, TransactionSpacePlan};
use crate::root::{ROOT_SLOT_BYTES, RootSlot};
use std::ffi::OsStr;
use std::sync::Condvar;
use std::sync::mpsc;
use std::time::Duration;

/// Long enough for a loaded host; only a regression or deadlock reaches it.
const PATIENCE: Duration = Duration::from_secs(120);

#[derive(Default)]
struct HoldState {
    armed: bool,
    held: bool,
    /// `Some(fail)` once released.
    release: Option<bool>,
}

/// Blocks the next full root synchronization, the last step of a commit's
/// root publication, until released.
#[derive(Default)]
struct Hold {
    state: Mutex<HoldState>,
    changed: Condvar,
}

impl Hold {
    fn arm(&self) {
        let mut state = self.state.lock().unwrap();
        state.armed = true;
        state.release = None;
    }

    fn wait_held(&self) {
        let state = self.state.lock().unwrap();
        let (_state, waited) = self
            .changed
            .wait_timeout_while(state, PATIENCE, |state| !state.held)
            .unwrap();
        assert!(!waited.timed_out(), "no root flush reached the hold");
    }

    fn release(&self, fail: bool) {
        self.state.lock().unwrap().release = Some(fail);
        self.changed.notify_all();
    }
}

struct HeldRoot {
    group: InMemoryGroup,
    hold: Arc<Hold>,
}

impl crate::group::SegmentGroupBackend for HeldRoot {
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
        let mut state = self.hold.state.lock().unwrap();
        if state.armed {
            state.armed = false;
            state.held = true;
            self.hold.changed.notify_all();
            let (mut state, waited) = self
                .hold
                .changed
                .wait_timeout_while(state, PATIENCE, |state| state.release.is_none())
                .unwrap();
            state.held = false;
            let fail = waited.timed_out() || state.release.take() == Some(true);
            drop(state);
            if fail {
                return Err(io::Error::other("injected root flush failure"));
            }
        } else {
            drop(state);
        }
        self.group.sync_root()
    }
    fn sync_root_ordered(&self) -> io::Result<()> {
        // The inner group orders through its own full synchronization.
        self.group.sync_root_ordered()
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
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        self.group.read(file, at, out)
    }
    fn write(&self, file: GroupFile, at: u64, bytes: &[u8]) -> io::Result<()> {
        self.group.write(file, at, bytes)
    }
    fn set_len(&self, file: GroupFile, length: u64) -> io::Result<()> {
        self.group.set_len(file, length)
    }
    fn sync(&self, file: GroupFile) -> io::Result<()> {
        self.group.sync(file)
    }
    fn sync_ordered(&self, file: GroupFile) -> io::Result<()> {
        self.group.sync_ordered(file)
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

const CACHE: CacheConfig = CacheConfig {
    byte_limit: 4 << 20,
};

/// A seeded core over `group` whose root flushes `hold` can block.
fn held(group: InMemoryGroup, create: bool) -> (Core, Arc<Hold>, Arc<Admission>) {
    let hold = Arc::new(Hold::default());
    let admission = Admission::new();
    let backend = HeldRoot {
        group,
        hold: hold.clone(),
    };
    let core = if create {
        Core::create_with_backend(backend, admission.clone(), GROUP, CACHE)
    } else {
        Core::open_with_backend(backend, admission.clone(), GROUP, CACHE)
    }
    .unwrap();
    (core, hold, admission)
}

fn read(core: &Core, snapshot: &ReadSnapshot, key: &[u8]) -> Result<Option<Vec<u8>>, CoreError> {
    Ok(core
        .get_admitted(snapshot, "rows", key, 64)?
        .map(|value| value.as_bytes().to_vec()))
}

/// Run `work` on another thread of `scope`; the result must arrive in time.
fn promptly<'scope, T: Send + 'scope>(
    scope: &'scope std::thread::Scope<'scope, '_>,
    work: impl FnOnce() -> T + Send + 'scope,
) -> T {
    let (sender, receiver) = mpsc::channel();
    scope.spawn(move || sender.send(work()).unwrap());
    receiver
        .recv_timeout(PATIENCE)
        .expect("the operation waited for the root flush")
}

#[test]
fn reads_use_the_previous_root_while_a_commit_flushes_its_root() {
    let group = InMemoryGroup::new();
    let (c, hold, _) = held(group.clone(), true);
    seed(&c);
    let before = c.generation().unwrap();
    hold.arm();
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| c.commit(&[Operation::put("rows", b"a", b"new")]));
        hold.wait_held();
        // The commit holds its gate but not the state lock.
        assert!(matches!(c.gate.try_lock(), Err(TryLockError::WouldBlock)));
        let (generation, pin, value) = promptly(scope, || {
            let pin = c.snapshot().unwrap();
            let value = read(&c, &pin, b"a").unwrap();
            assert!(c.key_exists(&pin, "rows", b"a").unwrap());
            (c.generation().unwrap(), pin, value)
        });
        assert_eq!(generation, before);
        assert_eq!(value.as_deref(), Some(&b"old"[..]));
        assert!(!writer.is_finished());
        hold.release(false);
        writer.join().unwrap().unwrap();
        // The pin taken during the publication keeps reading its root.
        assert_eq!(read(&c, &pin, b"a").unwrap().as_deref(), Some(&b"old"[..]));
    });
    assert!(c.generation().unwrap() > before);
    let pin = c.snapshot().unwrap();
    assert_eq!(read(&c, &pin, b"a").unwrap().as_deref(), Some(&b"new"[..]));
    assert!(!c.is_fenced());
    drop(pin);
    c.close().into_result().unwrap();
    let reopened = Core::open_with_backend(group.crash(), Admission::new(), GROUP, CACHE).unwrap();
    let pin = reopened.snapshot().unwrap();
    assert_eq!(
        read(&reopened, &pin, b"a").unwrap().as_deref(),
        Some(&b"new"[..])
    );
}

#[test]
fn pins_taken_during_the_root_flush_are_covered_by_the_publication() {
    let (c, hold, admission) = held(InMemoryGroup::new(), true);
    seed(&c);
    c.commit(&[Operation::put("rows", b"b", b"kept")]).unwrap();
    // No pin exists when the commit admits its capture.
    hold.arm();
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| c.commit(&[Operation::put("rows", b"a", b"new")]));
        hold.wait_held();
        let pins = promptly(scope, || {
            let first = c.snapshot().unwrap();
            let second = c.snapshot().unwrap();
            assert_eq!(
                read(&c, &first, b"a").unwrap().as_deref(),
                Some(&b"old"[..])
            );
            (first, second)
        });
        hold.release(false);
        // Coverage validation would refuse a pin missing from a stale capture.
        writer.join().unwrap().unwrap();
        assert!(!c.is_fenced());
        assert_eq!(admission.notifications.load(Ordering::Acquire), 0);
        for pin in [&pins.0, &pins.1] {
            assert_eq!(read(&c, pin, b"a").unwrap().as_deref(), Some(&b"old"[..]));
            assert_eq!(read(&c, pin, b"b").unwrap().as_deref(), Some(&b"kept"[..]));
        }
    });
    // Later publications reconcile what those pins retained.
    c.commit(&[Operation::put("rows", b"a", b"newer")]).unwrap();
    let pin = c.snapshot().unwrap();
    assert_eq!(
        read(&c, &pin, b"a").unwrap().as_deref(),
        Some(&b"newer"[..])
    );
    assert!(!c.is_fenced());
}

#[test]
fn cache_misses_during_the_root_flush_load_through_the_cache() {
    let group = InMemoryGroup::new();
    {
        let (c, _, _) = held(group.clone(), true);
        seed(&c);
        c.commit(&[Operation::put("rows", b"cold", b"cold value")])
            .unwrap();
        c.close().into_result().unwrap();
    }
    // A reopened owner starts with nothing resident. Its first commit rolls
    // fresh files through root publications of their own; the values read
    // below stay cold.
    let (c, hold, _) = held(group.crash(), false);
    c.commit(&[Operation::put("rows", b"warm", b"rolled")])
        .unwrap();
    let start = c.cache_stats().unwrap();
    hold.arm();
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| c.commit(&[Operation::put("rows", b"a", b"new")]));
        hold.wait_held();
        let (loaded, again) = promptly(scope, || {
            let pin = c.snapshot().unwrap();
            let cold = read(&c, &pin, b"cold").unwrap();
            // Including the value this commit replaces.
            let old = read(&c, &pin, b"a").unwrap();
            let loaded = c.cache_stats().unwrap();
            let again = read(&c, &pin, b"cold").unwrap();
            assert_eq!(cold.as_deref(), Some(&b"cold value"[..]));
            assert_eq!(old.as_deref(), Some(&b"old"[..]));
            assert_eq!(again, cold);
            (loaded, c.cache_stats().unwrap())
        });
        assert!(loaded.misses > start.misses, "{start:?} {loaded:?}");
        assert!(loaded.loads > start.loads, "{start:?} {loaded:?}");
        assert!(loaded.entries > start.entries, "{start:?} {loaded:?}");
        assert!(
            loaded.cached_bytes > start.cached_bytes,
            "{start:?} {loaded:?}"
        );
        assert!(again.hits > loaded.hits, "{loaded:?} {again:?}");
        assert_eq!(again.loads, loaded.loads, "{loaded:?} {again:?}");
        hold.release(false);
        writer.join().unwrap().unwrap();
    });
    let pin = c.snapshot().unwrap();
    assert_eq!(read(&c, &pin, b"a").unwrap().as_deref(), Some(&b"new"[..]));
    assert_eq!(
        read(&c, &pin, b"cold").unwrap().as_deref(),
        Some(&b"cold value"[..])
    );
    assert!(!c.is_fenced());
}

#[test]
fn a_failed_root_flush_fences_with_an_unknown_commit() {
    let group = InMemoryGroup::new();
    let (c, hold, admission) = held(group.clone(), true);
    seed(&c);
    hold.arm();
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| c.commit(&[Operation::put("rows", b"a", b"new")]));
        hold.wait_held();
        let value = promptly(scope, || {
            let pin = c.snapshot().unwrap();
            read(&c, &pin, b"a").unwrap()
        });
        assert_eq!(value.as_deref(), Some(&b"old"[..]));
        hold.release(true);
        let error = writer.join().unwrap().unwrap_err();
        assert!(error.is_unknown_commit(), "{error}");
        assert_eq!(
            error.io_error().map(io::Error::to_string).as_deref(),
            Some("injected root flush failure")
        );
    });
    assert!(c.is_fenced());
    assert_eq!(admission.notifications.load(Ordering::Acquire), 1);
    assert!(matches!(
        c.snapshot().err().expect("fenced owner").rejected_cause(),
        Some(crate::CoreErrorCause::OwnerFailed)
    ));
    assert!(matches!(
        c.commit(&[Operation::put("rows", b"a", b"again")])
            .unwrap_err()
            .rejected_cause(),
        Some(crate::CoreErrorCause::OwnerFailed)
    ));
    assert_eq!(
        c.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
    // Reopen decides from what the device kept: here the ordered first slot.
    let reopened = Core::open_with_backend(group.crash(), Admission::new(), GROUP, CACHE).unwrap();
    let pin = reopened.snapshot().unwrap();
    assert_eq!(
        read(&reopened, &pin, b"a").unwrap().as_deref(),
        Some(&b"new"[..])
    );
}

#[test]
fn gated_operations_wait_for_an_in_flight_root_flush() {
    let (c, hold, _) = held(InMemoryGroup::new(), true);
    seed(&c);
    let before = c.generation().unwrap();
    hold.arm();
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| c.commit(&[Operation::put("rows", b"a", b"new")]));
        hold.wait_held();
        let (sender, receiver) = mpsc::channel();
        let maintenance = sender.clone();
        let c = &c;
        scope.spawn(move || {
            let result = c.run_maintenance(crate::MaintenanceBudget {
                units: 64,
                mutations: 1,
            });
            maintenance
                .send(("maintenance", result.map(drop), c.generation().unwrap()))
                .unwrap();
        });
        let configure = sender.clone();
        scope.spawn(move || {
            let result = c.configure_cache(CACHE);
            configure
                .send(("configure", result, c.generation().unwrap()))
                .unwrap();
        });
        scope.spawn(move || {
            let result = c.request_compaction();
            sender
                .send(("compaction", result, c.generation().unwrap()))
                .unwrap();
        });
        // Each waits at the gate while reads still complete.
        assert!(matches!(
            receiver.recv_timeout(Duration::from_millis(500)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        let value = promptly(scope, || {
            let pin = c.snapshot().unwrap();
            read(c, &pin, b"a").unwrap()
        });
        assert_eq!(value.as_deref(), Some(&b"old"[..]));
        assert!(!writer.is_finished());
        hold.release(false);
        writer.join().unwrap().unwrap();
        let committed = c.generation().unwrap();
        assert!(committed > before);
        for _ in 0..3 {
            let (name, result, generation) = receiver.recv_timeout(PATIENCE).unwrap();
            result.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(
                generation >= committed,
                "{name} ran before the commit completed"
            );
        }
    });
    assert!(!c.is_fenced());
}

#[test]
fn close_during_a_root_flush_is_busy_and_the_commit_still_completes() {
    let group = InMemoryGroup::new();
    let (c, hold, _) = held(group.clone(), true);
    seed(&c);
    hold.arm();
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| c.commit(&[Operation::put("rows", b"a", b"new")]));
        hold.wait_held();
        let busy = c.close();
        assert_eq!(busy.entry(), BackendCloseEntry::NotEntered);
        assert_eq!(
            busy.into_result().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        hold.release(false);
        // The durable root is adopted although admission has stopped.
        writer.join().unwrap().unwrap();
    });
    assert!(!c.is_fenced());
    assert_eq!(
        c.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
    assert_eq!(group.close_attempts(), 1);
    let reopened = Core::open_with_backend(group.crash(), Admission::new(), GROUP, CACHE).unwrap();
    let pin = reopened.snapshot().unwrap();
    assert_eq!(
        read(&reopened, &pin, b"a").unwrap().as_deref(),
        Some(&b"new"[..])
    );
}
