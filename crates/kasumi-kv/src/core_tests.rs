use super::*;
use crate::group::InMemoryGroup;
use std::sync::atomic::AtomicU64;

const GROUP: [u8; 16] = [0x63; 16];

struct Admission {
    failed: AtomicBool,
    panic_check: AtomicBool,
    notifications: AtomicUsize,
    limit: AtomicU64,
    deny_cache_growth: AtomicBool,
    cache_denials: AtomicUsize,
}
impl Admission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            failed: AtomicBool::new(false),
            panic_check: AtomicBool::new(false),
            notifications: AtomicUsize::new(0),
            limit: AtomicU64::new(u64::MAX),
            deny_cache_growth: AtomicBool::new(false),
            cache_denials: AtomicUsize::new(0),
        })
    }
}
impl StorageAdmission for Admission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        assert!(
            !self.panic_check.load(Ordering::Acquire),
            "owner check payload"
        );
        if self.failed.load(Ordering::Acquire) {
            Err(OwnerFailed)
        } else {
            Ok(())
        }
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        if bytes > self.limit.load(Ordering::Acquire) {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(Box::new(()))
        }
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {
        self.notifications.fetch_add(1, Ordering::AcqRel);
    }

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<crate::CacheMemoryQuote, crate::AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, crate::AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
}
impl crate::cache_test::Provider for Admission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
        if !first && self.deny_cache_growth.load(Ordering::Acquire) {
            self.cache_denials.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        if bytes > self.limit.load(Ordering::Acquire) {
            Err(AdmissionError::CapacityDenied)
        } else {
            Ok(())
        }
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
    }
}

fn core(group: InMemoryGroup, admission: Arc<Admission>) -> Core {
    Core::create_with_backend(
        group,
        admission,
        GROUP,
        CacheConfig {
            byte_limit: 4 << 20,
        },
    )
    .unwrap()
}
fn seed(core: &Core) {
    core.commit(&[
        Operation::create_table("rows"),
        Operation::put("rows", b"a", b"old"),
    ])
    .unwrap();
}

#[test]
fn synchronous_compaction_returns_provider_pressure_without_spinning_or_fencing() {
    // The page prefix fits the first 64 KiB credit chunk; this value needs
    // real aggregate growth, including its exact-size fallback on refusal.
    const VALUE_BYTES: usize = 96 << 10;
    let admission = Admission::new();
    let c = Arc::new(core(InMemoryGroup::new(), admission.clone()));
    c.commit(&[
        Operation::create_table("rows"),
        Operation::put("rows", b"a", vec![7; VALUE_BYTES]),
    ])
    .unwrap();
    c.configure_cache(CacheConfig { byte_limit: 0 }).unwrap();
    c.configure_cache(CacheConfig {
        byte_limit: 4 << 20,
    })
    .unwrap();
    let before = c.committed_position().unwrap();
    admission.deny_cache_growth.store(true, Ordering::Release);
    let (send, receive) = std::sync::mpsc::channel();
    let task = c.clone();
    let worker = std::thread::spawn(move || send.send(task.compact()).unwrap());
    let result = receive.recv_timeout(std::time::Duration::from_secs(5));
    // If a regression spins, remove the obstruction before joining the exact
    // worker so the failing test never leaves an uncontrolled background loop.
    admission.deny_cache_growth.store(false, Ordering::Release);
    worker.join().unwrap();
    assert!(matches!(
        result.expect("compaction spun on provider refusal"),
        Err(CoreError::CapacityDenied)
    ));
    assert!(admission.cache_denials.load(Ordering::Acquire) >= 2);
    assert_ne!(
        c.committed_position().unwrap(),
        before,
        "denial preceded maintenance publication"
    );
    assert!(!c.is_fenced());
    c.compact().unwrap();
    let current = c.snapshot().unwrap();
    assert_eq!(
        c.get_admitted(&current, "rows", b"a", VALUE_BYTES)
            .unwrap()
            .unwrap()
            .as_bytes(),
        vec![7; VALUE_BYTES]
    );
    assert!(!c.is_fenced());
}

#[test]
fn strict_create_rejects_existing_group_and_open_requires_exact_incarnation() {
    let group = InMemoryGroup::new();
    let c = core(group.clone(), Admission::new());
    seed(&c);
    let crash = group.crash();
    assert!(matches!(
        Core::create_with_backend(
            crash.clone(),
            Admission::new(),
            GROUP,
            CacheConfig::default()
        ),
        Err(CoreError::InvalidInput(_))
    ));
    assert_eq!(crash.close_attempts(), 1);
    let crash = group.crash();
    assert!(matches!(
        Core::open_with_backend(
            crash.clone(),
            Admission::new(),
            [3; 16],
            CacheConfig::default()
        ),
        Err(CoreError::Corrupt(_))
    ));
    assert_eq!(crash.close_attempts(), 1);
    let reopened = Core::open_with_backend(
        group.crash(),
        Admission::new(),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap();
    let pin = reopened.snapshot().unwrap();
    assert_eq!(
        reopened
            .get_admitted(&pin, "rows", b"a", 3)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old"
    );
}

#[test]
fn snapshot_root_survives_overwrite_delete_and_later_table_birth() {
    let c = core(InMemoryGroup::new(), Admission::new());
    seed(&c);
    let before = c.snapshot().unwrap();
    c.commit(&[
        Operation::put("rows", b"a", b"new"),
        Operation::create_table("later"),
        Operation::put("rows", b"b", b"insert"),
    ])
    .unwrap();
    let middle = c.snapshot().unwrap();
    c.commit(&[Operation::delete("rows", b"a")]).unwrap();
    assert_eq!(
        c.get_admitted(&before, "rows", b"a", 3)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old"
    );
    assert_eq!(
        c.get_admitted(&middle, "rows", b"a", 3)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"new"
    );
    assert!(!before.table_exists("later").unwrap());
    assert!(middle.table_exists("later").unwrap());
    assert!(!c.key_exists(&c.snapshot().unwrap(), "rows", b"a").unwrap());
    c.compact().unwrap();
    assert_eq!(
        c.get_admitted(&before, "rows", b"a", 3)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old"
    );
}

#[test]
fn lower_bound_iteration_is_not_a_prefix_scan() {
    let c = core(InMemoryGroup::new(), Admission::new());
    c.commit(&[
        Operation::create_table("rows"),
        Operation::put("rows", b"b", b"1"),
        Operation::put("rows", b"z", b"2"),
        Operation::create_table("zz"),
        Operation::put("zz", b"a", b"3"),
    ])
    .unwrap();
    let pin = c.snapshot().unwrap();
    assert_eq!(
        pin.next_key_admitted("rows", b"c", None)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"z"
    );
    assert!(
        c.next_admitted(&pin, "rows", b"c", None, 3)
            .unwrap()
            .is_none()
    );
    assert!(
        pin.next_key_admitted("rows", b"", Some(b"z"))
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        pin.next_key_admitted("missing", b"", None),
        Err(CoreError::MissingTable)
    ));
}

#[test]
fn snapshot_belongs_to_exact_owner_even_with_same_group_id() {
    let a = core(InMemoryGroup::new(), Admission::new());
    let b = core(InMemoryGroup::new(), Admission::new());
    seed(&a);
    seed(&b);
    let pin = a.snapshot().unwrap();
    assert!(matches!(
        b.get_admitted(&pin, "rows", b"a", 3),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(!b.is_fenced());
}

#[test]
fn cache_hit_still_obeys_owner_and_read_bound() {
    let admission = Admission::new();
    let c = core(InMemoryGroup::new(), admission.clone());
    seed(&c);
    let pin = c.snapshot().unwrap();
    assert!(matches!(
        c.get_admitted(&pin, "rows", b"a", 2),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(!c.is_fenced());
    c.get_admitted(&pin, "rows", b"a", 3).unwrap();
    admission.failed.store(true, Ordering::Release);
    assert!(matches!(
        c.get_admitted(&pin, "rows", b"a", 3),
        Err(CoreError::OwnerFailed)
    ));
    admission.failed.store(false, Ordering::Release);
    assert!(matches!(c.generation(), Err(CoreError::OwnerFailed)));
    assert_eq!(admission.notifications.load(Ordering::Acquire), 1);
}

#[test]
fn poisoned_state_fences_once_and_still_drains_exact_backend() {
    let admission = Admission::new();
    let group = InMemoryGroup::new();
    let c = core(group.clone(), admission.clone());
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = c.shared.state.lock().unwrap();
        panic!("state holder");
    }));
    assert!(matches!(c.generation(), Err(CoreError::OwnerFailed)));
    assert!(matches!(c.snapshot(), Err(CoreError::OwnerFailed)));
    assert_eq!(admission.notifications.load(Ordering::Acquire), 1);
    assert_eq!(
        c.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
    assert_eq!(group.close_attempts(), 1);
}

#[test]
fn close_waits_for_snapshot_clones_and_retries_only_not_entered() {
    let group = InMemoryGroup::new();
    let c = core(group.clone(), Admission::new());
    let pin = c.snapshot().unwrap();
    let clone = pin.clone();
    assert_eq!(c.close().entry(), BackendCloseEntry::NotEntered);
    assert_eq!(group.close_attempts(), 0);
    assert!(matches!(c.snapshot(), Err(CoreError::Closed)));
    drop(pin);
    drop(clone);
    group.close_not_entered_once();
    assert_eq!(c.close().entry(), BackendCloseEntry::NotEntered);
    assert_eq!(
        c.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
    let attempts = group.close_attempts();
    assert_eq!(
        c.close().native_disposition(),
        BackendNativeDisposition::Drained
    );
    assert_eq!(group.close_attempts(), attempts);
}

#[test]
fn constructor_retains_uncertain_close_and_does_not_repeat_it() {
    let group = InMemoryGroup::new();
    group.fail_close(io::ErrorKind::Other);
    let admission = Admission::new();
    admission.limit.store(0, Ordering::Release);
    let Err(CoreError::OpeningFailure(mut failure)) =
        Core::create_with_backend(group.clone(), admission, GROUP, CacheConfig::default())
    else {
        panic!("expected retained opening failure")
    };
    assert!(matches!(
        failure.original_error(),
        CoreError::CapacityDenied
    ));
    assert_eq!(
        failure.close_report().native_disposition(),
        BackendNativeDisposition::Retained
    );
    failure.retry_close();
    assert_eq!(group.close_attempts(), 1);
}

#[test]
fn constructor_retries_the_same_owner_after_proven_no_close_entry() {
    let group = InMemoryGroup::new();
    group.close_not_entered_once();
    let admission = Admission::new();
    admission.limit.store(0, Ordering::Release);
    let Err(CoreError::OpeningFailure(mut failure)) =
        Core::create_with_backend(group.clone(), admission, GROUP, CacheConfig::default())
    else {
        panic!("expected retained opening failure")
    };
    assert_eq!(
        failure.close_report().entry(),
        BackendCloseEntry::NotEntered
    );
    assert_eq!(
        failure.retry_close().native_disposition(),
        BackendNativeDisposition::Drained
    );
    assert_eq!(group.close_attempts(), 2);
}

#[test]
fn snapshot_limit_denial_does_not_leak_close_count_or_fence() {
    let group = InMemoryGroup::new();
    let c = core(group.clone(), Admission::new());
    let pins: Vec<_> = (0..256).map(|_| c.snapshot().unwrap()).collect();
    assert!(matches!(c.snapshot(), Err(CoreError::CapacityDenied)));
    assert!(!c.is_fenced());
    drop(pins);
    c.close().into_result().unwrap();
    assert_eq!(group.close_attempts(), 1);
}

struct OutputBudget {
    live: Arc<AtomicU64>,
    limit: AtomicU64,
    denials: AtomicUsize,
    notifications: AtomicUsize,
}

struct OutputLease {
    live: Arc<AtomicU64>,
    bytes: u64,
}
impl Drop for OutputLease {
    fn drop(&mut self) {
        self.live.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
impl OutputBudget {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            live: Arc::new(AtomicU64::new(0)),
            limit: AtomicU64::new(u64::MAX),
            denials: AtomicUsize::new(0),
            notifications: AtomicUsize::new(0),
        })
    }
    fn live(&self) -> u64 {
        self.live.load(Ordering::Acquire)
    }
}
impl StorageAdmission for OutputBudget {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        let result = self
            .live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                live.checked_add(bytes)
                    .filter(|next| *next <= self.limit.load(Ordering::Acquire))
            });
        if result.is_err() {
            self.denials.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        Ok(Box::new(OutputLease {
            live: self.live.clone(),
            bytes,
        }))
    }
    fn reserve_growth(&self, _: u64, _: u64) -> Result<(), AdmissionError> {
        Ok(())
    }
    fn settle_growth(&self, _: u64) -> Result<(), OwnerFailed> {
        Ok(())
    }
    fn owner_failed(&self) {
        self.notifications.fetch_add(1, Ordering::AcqRel);
    }

    fn quote_cache_memory(
        &self,
        bytes: u64,
    ) -> Result<crate::CacheMemoryQuote, crate::AdmissionError> {
        crate::cache_test::quote::<Self>(bytes)
    }
    fn reserve_cache_memory(
        self: std::sync::Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, crate::AdmissionError> {
        crate::cache_test::reserve(self, bytes)
    }
}
impl crate::cache_test::Provider for OutputBudget {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
        let _ = first;
        self.live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                live.checked_add(bytes)
                    .filter(|next| *next <= self.limit.load(Ordering::Acquire))
            })
            .map_err(|_| {
                self.denials.fetch_add(1, Ordering::AcqRel);
                AdmissionError::CapacityDenied
            })?;
        Ok(())
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        let _ = (bytes, last);
        self.live.fetch_sub(bytes, Ordering::AcqRel);
    }
}

#[test]
fn public_output_fits_one_buffer_and_retains_its_charge_after_native_close() {
    const VALUE_BYTES: usize = 512 << 10;
    for cache_bytes in [0, 4 << 20] {
        let admission = OutputBudget::new();
        let group = InMemoryGroup::new();
        let c = Core::create_with_backend(
            group.clone(),
            admission.clone(),
            GROUP,
            CacheConfig {
                byte_limit: cache_bytes,
            },
        )
        .unwrap();
        c.commit(&[
            Operation::create_table("rows"),
            Operation::put("rows", b"large", vec![0x79; VALUE_BYTES]),
        ])
        .unwrap();
        let pin = c.snapshot().unwrap();
        let baseline = admission.live();
        // Directory lookups fit in this headroom, as does the required output.
        // A second value-sized allocation cannot fit once output is reserved.
        admission
            .limit
            .store(baseline + VALUE_BYTES as u64 + 4096, Ordering::Release);
        admission.denials.store(0, Ordering::Release);
        let output = c
            .get_admitted(&pin, "rows", b"large", VALUE_BYTES)
            .unwrap()
            .unwrap();
        assert_eq!(output.as_bytes().len(), VALUE_BYTES);
        assert!(output.as_bytes().iter().all(|byte| *byte == 0x79));
        let output_charge = admission.live() - baseline;
        assert!(output_charge >= VALUE_BYTES as u64);
        assert!(output_charge <= VALUE_BYTES as u64 + 4096);
        assert_eq!(admission.notifications.load(Ordering::Acquire), 0);
        assert!(!c.is_fenced());
        if cache_bytes == 0 {
            assert_eq!(
                admission.denials.load(Ordering::Acquire),
                0,
                "direct output needs no redundant temporary value admission"
            );
            assert_eq!(c.cache_stats().unwrap().entries, 0);
        } else {
            assert_eq!(
                admission.denials.load(Ordering::Acquire),
                0,
                "a hot read needs no second payload allocation"
            );
            assert!(c.cache_stats().unwrap().hits > 0);
        }
        drop(pin);
        c.close().into_result().unwrap();
        assert_eq!(group.close_attempts(), 1);
        drop(c);
        assert_eq!(
            admission.live(),
            output_charge,
            "only returned bytes retain admission after owner drain"
        );
        assert_eq!(output.as_bytes()[VALUE_BYTES - 1], 0x79);
        drop(output);
        assert_eq!(admission.live(), 0);
    }
}

#[test]
fn closed_snapshot_result_does_not_reenter_a_poisoned_state() {
    let group = InMemoryGroup::new();
    let admission = Admission::new();
    let c = core(group.clone(), admission.clone());
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _guard = c.shared.state.lock().unwrap();
        panic!("interrupted state holder");
    }));
    c.close().into_result().unwrap();
    assert!(matches!(c.snapshot(), Err(CoreError::Closed)));
    assert_eq!(admission.notifications.load(Ordering::Acquire), 1);
    assert_eq!(group.close_attempts(), 1);
}

#[test]
fn preparatory_segment_roll_does_not_report_a_fabricated_commit() {
    let group = InMemoryGroup::new();
    let c = core(group.clone(), Admission::new());
    seed(&c);
    let small_commit = c.committed_position().unwrap().unwrap();
    c.prepare_write().unwrap();
    assert_eq!(c.committed_position().unwrap(), Some(small_commit));
    assert!(
        !group
            .exists(crate::group::GroupFile::segment(
                small_commit.segment_id + 1
            ))
            .unwrap()
    );
    // Cross the automatic-maintenance threshold with one bounded large value.
    c.commit(&[Operation::put(
        "rows",
        b"payload",
        vec![0x24; (1 << 20) + 64],
    )])
    .unwrap();
    let before = c.committed_position().unwrap().unwrap();
    let generation = c.generation().unwrap();
    // Its one work unit starts evacuation by rolling the segment, without a
    // new batch; physical progress must not masquerade as a published commit.
    c.prepare_write().unwrap();
    assert!(
        group
            .exists(crate::group::GroupFile::segment(before.segment_id + 1))
            .unwrap()
    );
    assert_eq!(c.generation().unwrap(), generation);
    assert_eq!(c.committed_position().unwrap(), Some(before));
    let pin = c.snapshot().unwrap();
    assert_eq!(
        c.get_admitted(&pin, "rows", b"a", 3)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"old"
    );
    drop(pin);
    c.close().into_result().unwrap();

    let reopened = Core::open_with_backend(
        group.crash(),
        Admission::new(),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap();
    assert_eq!(reopened.generation().unwrap(), generation);
    assert_eq!(reopened.committed_position().unwrap(), Some(before));
    reopened
        .commit(&[Operation::put("rows", b"a", b"new")])
        .unwrap();
    assert!(reopened.generation().unwrap() > generation);
    assert_ne!(reopened.committed_position().unwrap(), Some(before));
    let pin = reopened.snapshot().unwrap();
    assert_eq!(
        reopened
            .get_admitted(&pin, "rows", b"a", 3)
            .unwrap()
            .unwrap()
            .as_bytes(),
        b"new"
    );
}
