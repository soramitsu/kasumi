use super::*;
use crate::CachedBytes;
use std::sync::Mutex;

fn step(state: &mut DiskState, manual: bool) -> CacheWarmup {
    let result = if manual {
        state.warm(1)
    } else {
        state.warm_if_needed(1)
    }
    .unwrap();
    assert!(result.work <= 1);
    result
}

fn advance_until_skipped(state: &mut DiskState, manual: bool) {
    for _ in 0..1024 {
        let progress = step(state, manual);
        assert!(
            !progress.complete,
            "expected a refused row before completion"
        );
        if state.warm_refill_checkpoint().0 {
            let status = state.warm_status().unwrap();
            assert_eq!(status.state, CacheWarmupState::Running);
            assert!(!status.provider_limited);
            return;
        }
    }
    panic!("warm pass never reached a local-limit refusal");
}

fn complete_nonresident(state: &mut DiskState, manual: bool) {
    for _ in 0..1024 {
        let progress = step(state, manual);
        if progress.complete {
            assert!(!progress.fully_resident);
            return;
        }
    }
    panic!("warm pass did not finish");
}

fn assert_refilled_without_disk(
    state: &mut DiskState,
    reads: &Reads,
    admission: &Admission,
    first: u8,
) {
    assert_eq!(
        state.warm_status().unwrap().state,
        CacheWarmupState::Pending
    );
    assert!(finish(state).fully_resident);
    let pin = state.snapshot().unwrap();
    let before = reads.count();
    assert_eq!(value(state, &pin, b"a").unwrap(), vec![first; 64 << 10]);
    assert_eq!(value(state, &pin, b"b").unwrap(), vec![2; 64 << 10]);
    assert_eq!(reads.count(), before);
    drop(pin);
    assert_parked(state, reads, admission);
}

#[test]
fn output_release_while_running_retries_automatic_and_manual_nonresident_passes() {
    for manual in [false, true] {
        let (mut state, reads, admission) = fixture(64 << 10, 192 << 10);
        let old = state.snapshot().unwrap();
        let guard = state
            .get(&old, "accounts", b"a", usize::MAX)
            .unwrap()
            .unwrap();
        drop(old);
        state
            .commit(&[Operation::put("accounts", b"a", vec![9; 64 << 10])])
            .unwrap();
        assert_eq!(
            state.cache_stats().unwrap().pinned_bytes,
            guard.charged_bytes()
        );
        advance_until_skipped(&mut state, manual);
        // No root change, budget growth or provider refusal can request retry.
        // The output retires before the running pass records its completion.
        drop(guard);
        assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
        complete_nonresident(&mut state, manual);
        assert_refilled_without_disk(&mut state, &reads, &admission, 9);
    }
}

struct ReleaseAtCapture {
    inner: Arc<Admission>,
    output: Mutex<Option<CachedBytes>>,
    released: AtomicBool,
}
impl StorageAdmission for ReleaseAtCapture {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.inner.check_owner()
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        // SnapshotRoots capture is the first required reservation after the
        // common warm step entrance. Drop the actual output after that sample,
        // before the final step returns and records its completed result.
        let output = self.output.lock().unwrap().take();
        if let Some(output) = output {
            drop(output);
            self.released.store(true, Ordering::Release);
        }
        self.inner.reserve_workspace(bytes)
    }
    fn reserve_growth(&self, before: u64, after: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(before, after)
    }
    fn settle_growth(&self, bytes: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(bytes)
    }
    fn owner_failed(&self) {
        self.inner.owner_failed();
    }
    fn quote_cache_memory(&self, bytes: u64) -> Result<crate::CacheMemoryQuote, AdmissionError> {
        self.inner.quote_cache_memory(bytes)
    }
    fn reserve_cache_memory(
        self: Arc<Self>,
        bytes: u64,
    ) -> Result<crate::CacheMemoryLease, AdmissionError> {
        self.inner.clone().reserve_cache_memory(bytes)
    }
}

#[test]
fn guard_acquired_between_steps_and_released_inside_completion_cannot_be_forgotten() {
    for manual in [false, true] {
        let reads = Reads::new(InMemoryGroup::new());
        let admission = Admission::new(16 << 20);
        let gate = Arc::new(ReleaseAtCapture {
            inner: admission.clone(),
            output: Mutex::new(None),
            released: AtomicBool::new(false),
        });
        let mut state = DiskState::create(reads.clone(), gate.clone(), GROUP, LARGE_CACHE).unwrap();
        state
            .commit(&[
                Operation::create_table("accounts"),
                Operation::put("accounts", b"a", vec![1; 64 << 10]),
                Operation::put("accounts", b"b", vec![2; 64 << 10]),
            ])
            .unwrap();
        state
            .configure_cache(CacheConfig {
                byte_limit: 192 << 10,
            })
            .unwrap();
        assert!(finish(&mut state).fully_resident);
        state.request_warm_retry().unwrap();
        assert!(!step(&mut state, manual).complete);
        assert_eq!(
            state.warm_status().unwrap().state,
            CacheWarmupState::Running
        );
        assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);

        // Acquire an actual bound-source output after the attempt has started.
        // Release only its cache lookup owner to model a pressure eviction;
        // the output keeps its original admitted payload alive independently.
        let pin = state.snapshot().unwrap();
        let guard = state
            .get(&pin, "accounts", b"a", usize::MAX)
            .unwrap()
            .unwrap();
        let Some(DirectoryValue::Row { value, .. }) =
            DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone())
                .get(pin.root(), DirectoryKey::row("accounts", b"a"))
                .unwrap()
        else {
            panic!("actual source row missing");
        };
        let identity = NativeIdentity::value(GROUP, value, "accounts", b"a").unwrap();
        assert!(state.cache.lock().unwrap().remove(identity));
        drop(pin);
        assert_eq!(
            state.cache_stats().unwrap().pinned_bytes,
            guard.charged_bytes()
        );
        advance_until_skipped(&mut state, manual);
        for _ in 0..1024 {
            if state.warm_refill_checkpoint().1 {
                break;
            }
            assert!(!step(&mut state, manual).complete);
        }
        assert!(
            state.warm_refill_checkpoint().1,
            "did not reach final transition"
        );
        *gate.output.lock().unwrap() = Some(guard);
        let completed = step(&mut state, manual);
        assert!(gate.released.load(Ordering::Acquire));
        assert!(completed.complete && !completed.fully_resident);
        assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
        assert_refilled_without_disk(&mut state, &reads, &admission, 1);
    }
}

#[test]
fn oversized_passes_do_not_retry_for_step_local_proof_guards() {
    for manual in [false, true] {
        let (mut state, reads, admission) = fixture(96 << 10, 160 << 10);
        // Keep the obsolete lookup across publication using an actual old
        // native pin, then retire that pin without retaining a payload output.
        // Pruning briefly orphans only its temporary candidate/proof guard.
        let old = state.snapshot().unwrap();
        state
            .commit(&[Operation::put("accounts", b"a", vec![9; 96 << 10])])
            .unwrap();
        drop(old);
        complete_nonresident(&mut state, manual);
        assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
        let status = state.warm_status().unwrap();
        assert_eq!(status.state, CacheWarmupState::CapacityLimited);
        assert!(status.complete && !status.provider_limited);
        assert_parked(&mut state, &reads, &admission);
    }
}

#[test]
fn manual_resume_retains_pin_history_after_automatic_workspace_refusal() {
    let (mut state, reads, admission) = fixture(64 << 10, 192 << 10);
    let old = state.snapshot().unwrap();
    let guard = state
        .get(&old, "accounts", b"a", usize::MAX)
        .unwrap()
        .unwrap();
    drop(old);
    state
        .commit(&[Operation::put("accounts", b"a", vec![9; 64 << 10])])
        .unwrap();
    advance_until_skipped(&mut state, false);
    admission.deny_nth(1);
    let refused = state.warm_if_needed(1).unwrap();
    assert!(!refused.complete);
    let status = state.warm_status().unwrap();
    assert_eq!(status.state, CacheWarmupState::CapacityLimited);
    assert!(status.provider_limited && !status.complete);
    admission.deny_at.store(usize::MAX, Ordering::Release);
    drop(guard);
    // Do not poll automatic eligibility here: explicitly resume the actual
    // incomplete cursor through the manual entrance after its pressure clears.
    complete_nonresident(&mut state, true);
    assert_refilled_without_disk(&mut state, &reads, &admission, 9);
}

#[test]
fn same_batch_pruning_records_real_output_before_refusal_and_immediate_release() {
    for manual in [false, true] {
        let (mut state, reads, admission) = fixture(64 << 10, 192 << 10);
        let old = state.snapshot().unwrap();
        let guard = state
            .get(&old, "accounts", b"a", usize::MAX)
            .unwrap()
            .unwrap();
        state
            .commit(&[Operation::put("accounts", b"a", vec![9; 64 << 10])])
            .unwrap();
        // The historical native root preserves the real old lookup during
        // publication. Dropping only that root makes the identity prunable;
        // at warm entrance the external guard is still indexed and counts zero pinned bytes.
        drop(old);
        assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
        let release = crate::disk_state::warming::refusal_release_fixture::Release::arm(guard);
        let completed = if manual {
            state.warm(1024)
        } else {
            state.warm_if_needed(1024)
        }
        .unwrap();
        assert!(completed.work <= 1024);
        assert!(completed.complete && !completed.fully_resident);
        assert!(release.released(), "expected an actual local refusal");
        assert_eq!(state.cache_stats().unwrap().pinned_bytes, 0);
        // Release occurred immediately after refusal and before any later
        // sample. Only the earlier intra-batch observation can request retry.
        assert_refilled_without_disk(&mut state, &reads, &admission, 9);
    }
}
