// Include as disk_state::tests::warming_failures. Fixture inputs, observation
// vectors and the in-memory disk are outside the native admission ledger.
use super::*;
use crate::directory::{DIRECTORY_PAGE_BYTES, DirectoryPageRef};

fn selected_value(state: &DiskState, key: &[u8]) -> ValueLocation {
    match DirectoryReader::new(state.arena.as_ref(), state.owner.admission.clone())
        .get(state.selected, DirectoryKey::row("accounts", key))
        .unwrap()
        .unwrap()
    {
        DirectoryValue::Row { value, .. } => value,
        _ => panic!("expected row"),
    }
}

fn install_only_value(state: &DiskState, location: ValueLocation, bytes: &[u8]) -> NativeIdentity {
    let identity = NativeIdentity::value(GROUP, location, "accounts", b"a").unwrap();
    let mut cache = state.cache.lock().unwrap();
    cache.clear();
    drop(
        cache
            .load(identity, bytes.len(), |out| {
                out.copy_from_slice(bytes);
                Ok::<_, CoreError>(())
            })
            .unwrap(),
    );
    identity
}

fn stale_value_state(
    backend: Arc<dyn SegmentGroupBackend>,
    admission: Arc<Admission>,
) -> (DiskState, ValueLocation, NativeIdentity) {
    let mut state = create(backend, admission, LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", b"old"),
        ])
        .unwrap();
    let old = selected_value(&state, b"a");
    state
        .commit(&[Operation::put("accounts", b"a", b"new")])
        .unwrap();
    let identity = install_only_value(&state, old, b"old");
    (state, old, identity)
}

fn require_full_retry(state: &mut DiskState) {
    // Optional fill denial may complete one honest, nonresident pass. The
    // next explicit pass must retry that fill with fresh retention status.
    for _ in 0..2 {
        if warm_all(state).fully_resident {
            return;
        }
    }
    panic!("warm retry never established full residency");
}

#[test]
fn warm_proof_admission_denial_retries_the_unproved_stale_identity() {
    // Capture, then one admitted proof owner containing locator, traversal
    // shell and directory input page. Both are required before proving stale.
    for nth in 1..=2 {
        let reads = Reads::new(InMemoryGroup::new());
        let admission = Admission::new(8 << 20);
        let (mut state, _, stale) = stale_value_state(reads.clone(), admission.clone());
        let before = admission.calls.load(Ordering::Acquire);
        admission.deny_nth(nth);
        assert!(
            matches!(state.warm(512), Err(CoreError::CapacityDenied)),
            "reservation {nth}"
        );
        assert!(admission.calls.load(Ordering::Acquire) >= before + nth);
        assert!(!state.is_fenced());
        assert!(state.cache.lock().unwrap().contains(stale));
        require_full_retry(&mut state);
        assert!(
            !state.cache.lock().unwrap().contains(stale),
            "proof retry skipped reservation {nth}'s candidate"
        );
        let current = state.snapshot().unwrap();
        let before_reads = reads.count();
        assert_eq!(value(&mut state, &current, b"a").unwrap(), b"new");
        assert_eq!(reads.count(), before_reads);
        assert_eq!(state.cache_stats().unwrap().evictions, 0);
        drop(current);
        drop(state);
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }
}

#[test]
fn warm_refill_and_cursor_denials_are_retryable_and_never_fence_the_owner() {
    // Separate required workspace from optional retention: root capture,
    // successor bounds, input page and owned logical cursor are four required
    // reservations. Page retention instead acquires one aggregate token and
    // may retry the exact credit after a rounded refusal.
    for workspace in [Some(1), Some(2), Some(3), Some(4), None] {
        let reads = Reads::new(InMemoryGroup::new());
        let admission = Admission::new(8 << 20);
        let gate = WarmGate::new(admission.clone());
        let mut state = DiskState::create(reads.clone(), gate.clone(), GROUP, LARGE_CACHE).unwrap();
        state
            .commit(&[
                Operation::create_table("accounts"),
                Operation::put("accounts", b"a", b"new"),
            ])
            .unwrap();
        state.cache.lock().unwrap().clear();
        assert!(!state.warm(1).unwrap().complete);
        let before = gate.workspace_calls.load(Ordering::Acquire);
        if let Some(nth) = workspace {
            gate.deny_workspace_at
                .store(before + nth, Ordering::Release);
        } else {
            gate.deny_new_cache.store(true, Ordering::Release);
        }
        let before_reads = reads.count();
        let result = state.warm(1);
        if let Some(nth) = workspace {
            assert!(
                matches!(result, Err(CoreError::CapacityDenied)),
                "workspace {nth}"
            );
            assert_eq!(gate.workspace_calls.load(Ordering::Acquire), before + nth);
            assert_eq!(gate.denied.load(Ordering::Acquire), 1);
            if nth <= 3 {
                assert_eq!(
                    reads.count(),
                    before_reads,
                    "required admission preceded I/O"
                );
            }
        } else {
            let progress = result.unwrap();
            assert!(!progress.complete && !progress.fully_resident);
            assert_eq!(gate.denied.load(Ordering::Acquire), 2);
            assert_eq!(state.cache_stats().unwrap().entries, 0);
        }
        assert!(!state.is_fenced());
        gate.deny_workspace_at.store(usize::MAX, Ordering::Release);
        gate.deny_new_cache.store(false, Ordering::Release);
        require_full_retry(&mut state);
        assert_eq!(state.cache_stats().unwrap().entries, 2);
        assert_eq!(state.cache_stats().unwrap().evictions, 0);
        let pin = state.snapshot().unwrap();
        let before_reads = reads.count();
        assert_eq!(value(&mut state, &pin, b"a").unwrap(), b"new");
        assert_eq!(reads.count(), before_reads);
        drop(pin);
        drop(state);
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }
}

struct WarmGate {
    inner: Arc<Admission>,
    workspace_calls: AtomicUsize,
    deny_workspace_at: AtomicUsize,
    deny_new_cache: AtomicBool,
    denied: AtomicUsize,
}

impl WarmGate {
    fn new(inner: Arc<Admission>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            workspace_calls: AtomicUsize::new(0),
            deny_workspace_at: AtomicUsize::new(usize::MAX),
            deny_new_cache: AtomicBool::new(false),
            denied: AtomicUsize::new(0),
        })
    }
}

impl StorageAdmission for WarmGate {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.inner.check_owner()
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        self.check_owner()
            .map_err(|_| AdmissionError::OwnerFailed)?;
        let call = self.workspace_calls.fetch_add(1, Ordering::AcqRel) + 1;
        if self.deny_workspace_at.load(Ordering::Acquire) == call {
            self.denied.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
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
impl crate::cache_test::Provider for WarmGate {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), crate::AdmissionError> {
        if first && self.deny_new_cache.load(Ordering::Acquire) {
            self.denied.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        crate::cache_test::Provider::acquire_cache(self.inner.as_ref(), bytes, first)
    }
    fn release_cache(&self, bytes: u64, last: bool) {
        crate::cache_test::Provider::release_cache(self.inner.as_ref(), bytes, last);
    }
}

#[test]
fn warm_metadata_shrink_denial_keeps_valid_backing_and_retries_on_the_next_pass() {
    let admission = Admission::new(8 << 20);
    let gate = WarmGate::new(admission.clone());
    let mut state = DiskState::create(
        Arc::new(InMemoryGroup::new()),
        gate.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    let mut operations = vec![Operation::create_table("accounts")];
    operations.extend((0..18u8).map(|key| Operation::put("accounts", [key], [key])));
    state.commit(&operations).unwrap();
    let old = state.snapshot().unwrap();
    let deletes: Vec<_> = (1..18u8)
        .map(|key| Operation::delete("accounts", [key]))
        .collect();
    state.commit(&deletes).unwrap();
    let before = state.cache_stats().unwrap();
    assert!(before.entries > 8);
    // The foreground reconciler must keep these identities while pinned.
    // Pin retirement makes them candidates for this explicit warm-up pass.
    drop(old);
    // The existing pool continues to serve retained values; shrinking its
    // hash table needs a separate token for the old backing during rehash.
    // Refuse that acquisition without denying required proof/cursor workspace.
    gate.deny_new_cache.store(true, Ordering::Release);
    assert!(matches!(state.warm(512), Err(CoreError::CapacityDenied)));
    assert_eq!(gate.denied.load(Ordering::Acquire), 1);
    assert!(!state.is_fenced());
    let denied = state.cache_stats().unwrap();
    assert_eq!(denied.entries, 2);
    assert_eq!(denied.metadata_bytes, before.metadata_bytes);
    assert_eq!(denied.evictions, 0);
    let refusals = gate.denied.load(Ordering::Acquire);
    assert!(matches!(state.warm(512), Err(CoreError::CapacityDenied)));
    assert_eq!(gate.denied.load(Ordering::Acquire), refusals + 1);
    assert_eq!(state.cache_stats().unwrap(), denied);
    assert!(!state.is_fenced());
    gate.deny_new_cache.store(false, Ordering::Release);
    assert!(warm_all(&mut state).fully_resident);
    assert!(state.cache_stats().unwrap().metadata_bytes < denied.metadata_bytes);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

fn image(group: &InMemoryGroup, file: GroupFile) -> Vec<u8> {
    let mut bytes = vec![0; group.len(file).unwrap() as usize];
    group.read(file, 0, &mut bytes).unwrap();
    bytes
}

fn page_identity(reference: DirectoryPageRef) -> NativeIdentity {
    NativeIdentity::Page {
        group_id: GROUP,
        arena_id: reference.arena_id,
        page_index: reference.page_index,
        sha256: reference.sha256,
    }
}

#[test]
fn warm_corruption_fences_before_removing_the_unproved_identity_or_mutating_source() {
    for corrupt_page in [false, true] {
        let group = InMemoryGroup::new();
        let admission = Admission::new(8 << 20);
        let (mut state, old, value_key) =
            stale_value_state(Arc::new(group.clone()), admission.clone());
        let (identity, file) = if corrupt_page {
            let reference = state.selected.page.unwrap();
            let identity = page_identity(reference);
            let mut cache = state.cache.lock().unwrap();
            cache.clear();
            drop(
                cache
                    .load(identity, DIRECTORY_PAGE_BYTES, |out| {
                        out.fill(0);
                        Ok::<_, CoreError>(())
                    })
                    .unwrap(),
            );
            (identity, GroupFile::directory(reference.arena_id))
        } else {
            // Change only the old record's logical key envelope. Cached value
            // bytes/CRC remain valid, so its body proof must catch this.
            let file = GroupFile::segment(old.segment_id);
            group
                .write(file, old.offset - ("accounts".len() + 1) as u64, b"x")
                .unwrap();
            (value_key, file)
        };
        let before = image(&group, file);
        let stats = state.cache_stats().unwrap();
        assert!(matches!(state.warm(512), Err(CoreError::Corrupt(_))));
        assert!(state.is_fenced());
        let cache = state.cache.lock().unwrap();
        assert!(cache.contains(identity));
        assert_eq!(cache.stats().entries, stats.entries);
        assert_eq!(cache.stats().evictions, stats.evictions);
        drop(cache);
        assert_eq!(image(&group, file), before);
        drop(state);
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }
}

struct FailProofRead {
    group: InMemoryGroup,
    fail: AtomicBool,
}
impl SegmentGroupBackend for FailProofRead {
    fn reserve_transaction(
        &self,
        plan: &crate::TransactionSpacePlan,
    ) -> std::result::Result<(), crate::TransactionReserveError> {
        self.group.reserve_transaction(plan)
    }
    fn finish_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.finish_transaction(group_id, batch_seq)
    }
    fn cancel_transaction(&self, group_id: [u8; 16], batch_seq: u64) -> std::io::Result<()> {
        self.group.cancel_transaction(group_id, batch_seq)
    }

    fn read_root(&self, slot: RootSlot, out: &mut [u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
        self.group.read_root(slot, out)
    }
    fn write_root(&self, slot: RootSlot, bytes: &[u8; ROOT_SLOT_BYTES]) -> io::Result<()> {
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
    fn read(&self, file: GroupFile, at: u64, out: &mut [u8]) -> io::Result<()> {
        if self.fail.load(Ordering::Acquire) {
            return Err(io::Error::other("warm proof read failed"));
        }
        self.group.read(file, at, out)
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
fn warm_proof_read_failure_fences_and_preserves_the_unproved_value() {
    let backend = Arc::new(FailProofRead {
        group: InMemoryGroup::new(),
        fail: AtomicBool::new(false),
    });
    let admission = Admission::new(8 << 20);
    let (mut state, old, identity) = stale_value_state(backend.clone(), admission.clone());
    let file = GroupFile::segment(old.segment_id);
    let before = image(&backend.group, file);
    backend.fail.store(true, Ordering::Release);
    assert!(matches!(state.warm(512), Err(CoreError::Io(_))));
    assert!(state.is_fenced());
    let cache = state.cache.lock().unwrap();
    assert!(cache.contains(identity));
    assert_eq!(cache.stats().entries, 1);
    assert_eq!(cache.stats().evictions, 0);
    drop(cache);
    assert_eq!(image(&backend.group, file), before);
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn warm_duplicate_pin_capacity_and_final_output_guard_keep_exact_charge_lifetimes() {
    let admission = Admission::new(8 << 20);
    let mut state = create(
        Arc::new(InMemoryGroup::new()),
        admission.clone(),
        LARGE_CACHE,
    );
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", b"held"),
        ])
        .unwrap();
    assert!(warm_all(&mut state).fully_resident);
    let temporary = state.snapshot().unwrap();
    let output = state
        .get(&temporary, "accounts", b"a", 99)
        .unwrap()
        .unwrap();
    drop(temporary);
    let baseline = admission.used.load(Ordering::Acquire);
    let pins: Vec<_> = (0..MAX_PINNED_ROOTS)
        .map(|_| state.snapshot().unwrap())
        .collect();
    let full = admission.used.load(Ordering::Acquire);
    assert!(full > baseline);
    assert!(matches!(state.snapshot(), Err(CoreError::CapacityDenied)));
    assert_eq!(admission.used.load(Ordering::Acquire), full);
    assert!(!state.is_fenced());
    let clones = pins.clone();
    assert_eq!(admission.used.load(Ordering::Acquire), full);
    assert!(warm_all(&mut state).fully_resident);
    assert_eq!(admission.used.load(Ordering::Acquire), full);
    drop(pins);
    assert_eq!(admission.used.load(Ordering::Acquire), full);
    drop(clones);
    assert_eq!(admission.used.load(Ordering::Acquire), baseline);
    state.cache.lock().unwrap().clear();
    assert_eq!(
        state.cache_stats().unwrap().pinned_bytes,
        output.charged_bytes()
    );
    drop(state);
    assert!(admission.used.load(Ordering::Acquire) >= output.charged_bytes());
    assert_eq!(output.as_bytes(), b"held");
    drop(output);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn cached_identity_proof_one_grant_covers_complete_owner_before_allocation() {
    use super::super::warming::CachedIdentityProofWorkspace;
    use crate::directory::DirectoryReadWorkspace;

    let bytes = DirectoryReadWorkspace::request_bytes()
        + (std::mem::size_of::<CachedIdentityProofWorkspace>()
            - std::mem::size_of::<DirectoryReadWorkspace>()) as u64;
    let admission = Admission::new(bytes - 1);
    let owner: Arc<dyn StorageAdmission> = admission.clone();
    assert!(matches!(
        CachedIdentityProofWorkspace::new(&owner),
        Err(CoreError::CapacityDenied)
    ));
    assert_eq!(admission.calls.load(Ordering::Acquire), 1);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
    assert!(admission.check_owner().is_ok());

    admission.limit.store(bytes, Ordering::Release);
    let proof = CachedIdentityProofWorkspace::new(&owner).unwrap();
    assert_eq!(admission.calls.load(Ordering::Acquire), 2);
    assert_eq!(admission.used.load(Ordering::Acquire), bytes);
    drop(proof);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn cached_identity_proof_reuses_actual_owner_for_current_and_pinned_history_under_denial() {
    use super::super::warming::CachedIdentityProofWorkspace;

    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(8 << 20);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", b"old"),
        ])
        .unwrap();
    let old_pin = state.snapshot().unwrap();
    let old_location = selected_value(&state, b"a");
    state
        .commit(&[Operation::put("accounts", b"a", b"new")])
        .unwrap();
    let new_location = selected_value(&state, b"a");
    let old_identity = NativeIdentity::value(GROUP, old_location, "accounts", b"a").unwrap();
    let new_identity = NativeIdentity::value(GROUP, new_location, "accounts", b"a").unwrap();
    let candidate = |identity| {
        let cache = state.cache.lock().unwrap();
        let mut cursor = crate::cache::CacheCursor::default();
        loop {
            let step = cache.candidate_step(&mut cursor, usize::MAX).unwrap();
            if let Some(candidate) = step.candidate
                && candidate.key == identity
            {
                break candidate;
            }
            assert!(!step.complete, "expected retained cache identity");
        }
    };
    let old = candidate(old_identity);
    let current = candidate(new_identity);
    let both = state.pins.capture().unwrap();
    let mut proof = CachedIdentityProofWorkspace::new(&state.owner.admission).unwrap();
    let foreign_owner: Arc<dyn StorageAdmission> = Admission::new(1 << 20);
    let mut foreign = CachedIdentityProofWorkspace::new(&foreign_owner).unwrap();
    let calls = admission.calls.load(Ordering::Acquire);
    let charged = admission.used.load(Ordering::Acquire);
    admission.limit.store(charged, Ordering::Release);
    for _ in 0..3 {
        assert!(
            state
                .cached_identity_is_live_with(&old, &both, &mut proof)
                .unwrap()
        );
        assert!(
            state
                .cached_identity_is_live_with(&current, &both, &mut proof)
                .unwrap()
        );
    }
    assert!(matches!(
        state.cached_identity_is_live_with(&current, &both, &mut foreign),
        Err(CoreError::InvalidInput(_))
    ));
    assert_eq!(admission.calls.load(Ordering::Acquire), calls);
    assert_eq!(admission.used.load(Ordering::Acquire), charged);
    assert!(!state.is_fenced());

    admission.limit.store(8 << 20, Ordering::Release);
    drop(both);
    drop(old_pin);
    let only_current = state.pins.capture().unwrap();
    let calls = admission.calls.load(Ordering::Acquire);
    admission
        .limit
        .store(admission.used.load(Ordering::Acquire), Ordering::Release);
    assert!(
        !state
            .cached_identity_is_live_with(&old, &only_current, &mut proof)
            .unwrap()
    );
    assert!(
        state
            .cached_identity_is_live_with(&current, &only_current, &mut proof)
            .unwrap()
    );
    assert_eq!(admission.calls.load(Ordering::Acquire), calls);
    drop((proof, foreign, only_current, old, current));
    drop(state);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}
