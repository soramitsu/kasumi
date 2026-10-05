use super::*;

// Observe actual backend mutation calls. Deny every new memory reservation
// after the first effect, independently of the number/order of earlier grants.
struct EffectAdmission {
    inner: Arc<Admission>,
    backend: Arc<Reads>,
    boundary: AtomicUsize,
    late_workspace: AtomicUsize,
    late_cache: AtomicUsize,
}

impl EffectAdmission {
    fn after_effect(&self) -> bool {
        self.backend.effects.load(Ordering::Acquire) > self.boundary.load(Ordering::Acquire)
    }
}

impl StorageAdmission for EffectAdmission {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.inner.check_owner()
    }

    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        if self.after_effect() {
            self.late_workspace.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        self.inner.reserve_workspace(bytes)
    }

    fn reserve_growth(&self, bytes: u64, files: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(bytes, files)
    }

    fn settle_growth(&self, bytes: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(bytes)
    }

    fn owner_failed(&self) {
        self.inner.owner_failed();
    }

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

impl crate::cache_test::Provider for EffectAdmission {
    fn acquire_cache(&self, bytes: u64, first: bool) -> Result<(), AdmissionError> {
        if self.after_effect() {
            self.late_cache.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        self.inner.acquire_cache(bytes, first)
    }

    fn release_cache(&self, bytes: u64, last: bool) {
        self.inner.release_cache(bytes, last);
    }
}

#[test]
fn mandatory_capacity_denial_precedes_disk_effects_and_allows_retry() {
    let mut denials = 0;
    for nth in 1..=36 {
        let admission = Admission::new(16 << 20);
        let backend = Reads::new(InMemoryGroup::new());
        let mut state = create(backend.clone(), admission.clone(), LARGE_CACHE);
        state
            .commit(&[
                Operation::create_table("accounts"),
                Operation::put("accounts", b"old", b"stable"),
            ])
            .unwrap();
        let old = state.snapshot().unwrap();
        let ops = [
            Operation::put("accounts", b"new", b"candidate"),
            Operation::delete("accounts", b"old"),
        ];
        let before = backend.effects.load(Ordering::Acquire);
        admission.deny_nth(nth);
        let result = state.commit(&ops);
        admission.deny_at.store(usize::MAX, Ordering::Release);
        match result {
            Err(error) if error.is_capacity_denied() => {
                denials += 1;
                assert_eq!(
                    backend.effects.load(Ordering::Acquire),
                    before,
                    "reservation {nth} refused after backend effects"
                );
                assert!(
                    !state.is_fenced(),
                    "reservation {nth} fenced retryable capacity denial"
                );
                assert_eq!(state.snapshot().unwrap().root(), old.root());
                assert_eq!(value(&mut state, &old, b"old").unwrap(), b"stable");
                assert_eq!(value(&mut state, &old, b"new"), None);
                let mut reopened = DiskState::open(
                    Arc::new(backend.group.crash()),
                    Admission::new(16 << 20),
                    GROUP,
                    LARGE_CACHE,
                )
                .unwrap();
                let durable = reopened.snapshot().unwrap();
                assert_eq!(durable.root(), old.root());
                assert_eq!(value(&mut reopened, &durable, b"old").unwrap(), b"stable");
                assert_eq!(value(&mut reopened, &durable, b"new"), None);
                state.commit(&ops).unwrap_or_else(|error| {
                    panic!("reservation {nth} left a pending write: {error}")
                });
            }
            Ok(()) => {}
            Err(error) => panic!("reservation {nth}: {error}"),
        }
        let current = state.snapshot().unwrap();
        assert_eq!(value(&mut state, &current, b"new").unwrap(), b"candidate");
        assert_eq!(value(&mut state, &current, b"old"), None);
        assert_eq!(value(&mut state, &old, b"old").unwrap(), b"stable");
        assert_eq!(value(&mut state, &old, b"new"), None);
    }
    assert!(denials > 0, "injection must reach mandatory admission");
}

#[test]
fn commit_reuses_prepared_memory_when_all_post_effect_admissions_refuse() {
    let backend = Reads::new(InMemoryGroup::new());
    let inner = Admission::new(16 << 20);
    let admission = Arc::new(EffectAdmission {
        inner: inner.clone(),
        backend: backend.clone(),
        boundary: AtomicUsize::new(usize::MAX),
        late_workspace: AtomicUsize::new(0),
        late_cache: AtomicUsize::new(0),
    });
    let mut state =
        DiskState::create(backend.clone(), admission.clone(), GROUP, LARGE_CACHE).unwrap();
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"old", b"stable"),
        ])
        .unwrap();
    let old = state.snapshot().unwrap();
    // Exceed existing fungible cache credit, while fitting the cache ceiling.
    let payload = vec![0xa7; 256 << 10];
    admission
        .boundary
        .store(backend.effects.load(Ordering::Acquire), Ordering::Release);
    state
        .commit(&[
            Operation::put("accounts", b"new", payload.as_slice()),
            Operation::delete("accounts", b"old"),
        ])
        .unwrap();
    assert!(
        admission.after_effect(),
        "commit must reach the actual backend"
    );
    assert_eq!(
        admission.late_workspace.load(Ordering::Acquire),
        0,
        "mandatory work must use its prepared backing"
    );
    assert!(
        admission.late_cache.load(Ordering::Acquire) > 0,
        "exercise real optional cache refusal after durable effects"
    );
    assert!(!state.is_fenced());
    admission.boundary.store(usize::MAX, Ordering::Release);
    let current = state.snapshot().unwrap();
    assert_eq!(value(&mut state, &current, b"new").unwrap(), payload);
    assert_eq!(value(&mut state, &current, b"old"), None);
    assert_eq!(value(&mut state, &old, b"old").unwrap(), b"stable");
    assert_eq!(value(&mut state, &old, b"new"), None);
    let saved = current.root();
    drop(current);
    drop(old);
    drop(state);
    assert_eq!(inner.used.load(Ordering::Acquire), 0);
    let mut reopened = DiskState::open(
        Arc::new(backend.group.crash()),
        inner.clone(),
        GROUP,
        LARGE_CACHE,
    )
    .unwrap();
    let root = reopened.snapshot().unwrap();
    assert_eq!(root.root(), saved);
    assert_eq!(value(&mut reopened, &root, b"new").unwrap(), payload);
    assert_eq!(value(&mut reopened, &root, b"old"), None);
    drop(root);
    drop(reopened);
    assert_eq!(inner.used.load(Ordering::Acquire), 0);
}
