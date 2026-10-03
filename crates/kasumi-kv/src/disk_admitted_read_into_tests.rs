use super::*;

struct ValueWorkspaceGuard {
    inner: Arc<Admission>,
    forbidden: AtomicU64,
    attempts: AtomicUsize,
}
impl ValueWorkspaceGuard {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Admission::new(u64::MAX),
            forbidden: AtomicU64::new(0),
            attempts: AtomicUsize::new(0),
        })
    }
}
impl StorageAdmission for ValueWorkspaceGuard {
    fn check_owner(&self) -> Result<(), OwnerFailed> {
        self.inner.check_owner()
    }
    fn reserve_workspace(&self, bytes: u64) -> Result<Box<dyn ResidentLease>, AdmissionError> {
        if bytes == self.forbidden.load(Ordering::Acquire) {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            return Err(AdmissionError::CapacityDenied);
        }
        self.inner.reserve_workspace(bytes)
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
    fn reserve_growth(&self, segment: u64, bytes: u64) -> Result<(), AdmissionError> {
        self.inner.reserve_growth(segment, bytes)
    }
    fn settle_growth(&self, segment: u64) -> Result<(), OwnerFailed> {
        self.inner.settle_growth(segment)
    }
    fn owner_failed(&self) {
        self.inner.owner_failed();
    }
}

#[test]
fn admitted_point_and_successor_never_request_a_temporary_value_payload() {
    const VALUE_BYTES: usize = 131_071;
    let provider = ValueWorkspaceGuard::new();
    let reads = Reads::new(InMemoryGroup::new());
    let mut state = DiskState::create(
        reads.clone(),
        provider.clone(),
        GROUP,
        CacheConfig::default(),
    )
    .unwrap();
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", vec![0xa1; VALUE_BYTES]),
            Operation::put("accounts", b"b", vec![0xb2; VALUE_BYTES]),
        ])
        .unwrap();
    let pin = state.snapshot().unwrap();
    let fallback = CachedBytes::charge_for_len(VALUE_BYTES).unwrap();
    assert_ne!(
        fallback,
        crate::core::AdmittedValue::request_bytes(VALUE_BYTES).unwrap()
    );
    provider.forbidden.store(fallback, Ordering::Release);
    let baseline = provider.inner.used.load(Ordering::Acquire);
    let point = state
        .get_admitted(&pin, "accounts", b"a", VALUE_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(point.as_bytes(), vec![0xa1; VALUE_BYTES]);
    assert_eq!(provider.attempts.load(Ordering::Acquire), 0);
    assert_eq!(
        provider.inner.used.load(Ordering::Acquire) - baseline,
        crate::core::AdmittedValue::request_bytes(VALUE_BYTES).unwrap()
    );
    drop(point);
    assert_eq!(provider.inner.used.load(Ordering::Acquire), baseline);
    let (key, value) = state
        .next_admitted(&pin, "accounts", b"", Some(b"a"), VALUE_BYTES)
        .unwrap()
        .unwrap();
    assert_eq!(key.as_bytes(), b"b");
    assert_eq!(value.as_bytes(), vec![0xb2; VALUE_BYTES]);
    assert_eq!(provider.attempts.load(Ordering::Acquire), 0);
    assert_eq!(state.cache_stats().unwrap().entries, 0);
    assert!(!provider.inner.failed.load(Ordering::Acquire));
    drop(key);
    drop(pin);
    drop(state);
    assert_eq!(
        provider.inner.used.load(Ordering::Acquire),
        crate::core::AdmittedValue::request_bytes(VALUE_BYTES).unwrap()
    );
    assert_eq!(value.as_bytes()[VALUE_BYTES - 1], 0xb2);
    drop(value);
    assert_eq!(provider.inner.used.load(Ordering::Acquire), 0);
}

#[test]
fn admitted_reads_preserve_fitting_retention_and_existing_zero_copy_owner() {
    let reads = Reads::new(InMemoryGroup::new());
    let admission = Admission::new(u64::MAX);
    let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
    state
        .commit(&[
            Operation::create_table("accounts"),
            Operation::put("accounts", b"a", vec![0x4a; 8192]),
        ])
        .unwrap();
    state.configure_cache(CacheConfig::default()).unwrap();
    state.configure_cache(LARGE_CACHE).unwrap();
    let pin = state.snapshot().unwrap();
    let before = reads.count();
    let first = state
        .get_admitted(&pin, "accounts", b"a", 8192)
        .unwrap()
        .unwrap();
    assert_eq!(first.as_bytes(), &[0x4a; 8192]);
    assert!(reads.count() > before);
    drop(first);
    let before = reads.count();
    let stats = state.cache_stats().unwrap();
    let second = state
        .get_admitted(&pin, "accounts", b"a", 8192)
        .unwrap()
        .unwrap();
    assert_eq!(second.as_bytes(), &[0x4a; 8192]);
    assert_eq!(reads.count(), before);
    let after = state.cache_stats().unwrap();
    assert_eq!(after.loads, stats.loads);
    assert_eq!(after.uncached_loads, stats.uncached_loads);
    assert!(after.hits > stats.hits);
    drop(second);
    let charge = admission.used.load(Ordering::Acquire);
    let zero_copy = state.get(&pin, "accounts", b"a", 8192).unwrap().unwrap();
    assert_eq!(admission.used.load(Ordering::Acquire), charge);
    assert_eq!(reads.count(), before);
    drop(pin);
    drop(state);
    assert!(admission.used.load(Ordering::Acquire) > 0);
    assert_eq!(zero_copy.as_bytes(), &[0x4a; 8192]);
    drop(zero_copy);
    assert_eq!(admission.used.load(Ordering::Acquire), 0);
}

#[test]
fn admitted_cached_length_and_checksum_mismatches_are_typed_corruption_before_copy() {
    for wrong_length in [true, false] {
        let reads = Reads::new(InMemoryGroup::new());
        let admission = Admission::new(u64::MAX);
        let mut state = create(reads.clone(), admission.clone(), LARGE_CACHE);
        state
            .commit(&[
                Operation::create_table("accounts"),
                Operation::put("accounts", b"a", vec![0x3a; 128]),
            ])
            .unwrap();
        let pin = state.snapshot().unwrap();
        let root = state.check_snapshot(&pin).unwrap();
        let record = DirectoryReader::new(&state.pages, state.owner.admission.clone())
            .get(root, DirectoryKey::row("accounts", b"a"))
            .unwrap()
            .unwrap();
        let DirectoryValue::Row { value, .. } = record else {
            panic!("row missing")
        };
        let identity = NativeIdentity::value(GROUP, value, "accounts", b"a").unwrap();
        {
            // Deliberately corrupt this exact cached identity, without changing
            // the real backend or selected snapshot. The public read must check
            // both length and CRC before copying into its admitted output.
            let mut cache = state.cache.lock().unwrap();
            cache.remove(identity);
            drop(
                cache
                    .load(identity, if wrong_length { 127 } else { 128 }, |bytes| {
                        bytes.fill(0x9c);
                        Ok::<_, CoreError>(())
                    })
                    .unwrap(),
            );
        }
        let before = reads.count();
        let result = state.get_admitted(&pin, "accounts", b"a", 128);
        assert!(matches!(
            result,
            Err(CoreError::Corrupt("cached value identity differs"))
        ));
        assert_eq!(reads.count(), before, "corrupt cache was retried from disk");
        drop(pin);
        drop(state);
        assert_eq!(admission.used.load(Ordering::Acquire), 0);
    }
}
