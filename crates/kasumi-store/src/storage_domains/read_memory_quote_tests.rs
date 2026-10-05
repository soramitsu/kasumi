use super::*;
use crate::{
    allocation_tests::measure_requested,
    test_utils::{LocalKeyProvider, TestDiskMemory, private_tempdir, retry_disk_registry},
};

struct Fixture {
    _persistent: tempfile::TempDir,
    _scratch: tempfile::TempDir,
    stores: Arc<TenantStorageSet>,
    node: NodeStore,
    memory: Arc<TestDiskMemory>,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let persistent = private_tempdir()?;
        let scratch = private_tempdir()?;
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let path = persistent.path().join("read-quotes.kv");
        let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
        let scratch_disk = ScratchDisk::fixture(scratch.path(), memory.clone());
        let mut config = crate::test_utils::node_storage_config();
        config.cache.byte_limit = 0;
        let node = NodeStore::create_new(
            path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            scratch_disk,
            config,
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        let stores = TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "quote-source".into(),
            Arc::new(LocalKeyProvider::new([91; 32])),
            Arc::new(LocalKeyProvider::new([92; 32])),
        )
        .await?;
        Ok(Self {
            _persistent: persistent,
            _scratch: scratch,
            stores,
            node,
            memory,
        })
    }
    async fn close(self) -> Result<()> {
        self.stores.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}

#[tokio::test]
async fn paired_read_quote_has_no_allocations_or_admission_and_matches_reader_retention()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let before = fixture.memory.snapshot();
    let (quote, allocations, bytes) = measure_requested(|| fixture.stores.quote_read_memory());
    let quote = quote?;
    assert_eq!((allocations, bytes), (0, 0));
    assert_eq!(fixture.memory.snapshot().attempts, before.attempts);
    let view = fixture.stores.read_view()?;
    assert_eq!(
        fixture.memory.snapshot().used_bytes - before.used_bytes,
        quote.retained_bytes()
    );
    assert_eq!(
        fixture.memory.snapshot().live_reservations - before.live_reservations,
        4
    );
    view.close()?;
    assert_eq!(fixture.memory.snapshot().used_bytes, before.used_bytes);
    let (point, allocations, bytes) = measure_requested(|| quote.application_get(7, 3, 65_537));
    assert_eq!((allocations, bytes), (0, 0));
    let point = point?;
    {
        let state = fixture.stores.application().state.read();
        assert_eq!(
            point.ciphertext_limit(),
            encrypted_record_limit(7, 3, 65_537, &state)?
        );
    }
    for args in [(0, 0, 0), (1025, 1, 0), (1, 4097, 0), (1, 0, usize::MAX)] {
        let (result, allocations, bytes) =
            measure_requested(|| quote.application_get(args.0, args.1, args.2));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!((allocations, bytes), (0, 0));
    }
    drop(quote);
    fixture.close().await
}

#[tokio::test]
async fn paired_read_quote_key_id_ceiling_is_owned_and_stale_growth_is_rejected() -> Result<()> {
    let fixture = Fixture::new().await?;
    let quote = fixture.stores.quote_read_memory()?;
    let application = fixture.stores.application();
    let (old, key) = application.state.write().keys.pop_last().unwrap();
    let longer = "k".repeat(quote.key_id_bytes[0] + 1);
    application.state.write().keys.insert(longer.clone(), key);
    assert_eq!(
        quote.application_get(3, 2, 1).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    // This mutates only the fixture's installed key state to test stale size
    // detection, then restores it before any actual cryptographic operation.
    let key = application.state.write().keys.remove(&longer).unwrap();
    application.state.write().keys.insert(old, key);
    quote.application_get(3, 2, 1)?;
    assert_eq!(
        quote
            .require_domains(fixture.stores.custody().store(), application)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    drop(quote);
    fixture.close().await
}

#[tokio::test]
async fn paired_read_quote_covers_real_encrypted_get_requested_allocations() -> Result<()> {
    let fixture = Fixture::new().await?;
    for len in [1, 65_537] {
        let bytes = vec![42; len];
        fixture.stores.application().write_batch(&[WriteOp::Put {
            namespace: "payload".into(),
            key: b"key".to_vec(),
            value: bytes.clone(),
        }])?;
        let quote = fixture.stores.quote_read_memory()?;
        let point = quote.application_get(7, 3, bytes.len())?;
        let view = fixture.stores.read_view()?;
        // Canonical record framing puts all three fields in one plaintext backing.
        // Its installed lease overlaps the native ciphertext during decode.
        let plaintext_len = crate::encode_plain_record("payload", b"key", &bytes)?.len();
        let plaintext = fixture
            .memory
            .quote_installed(crate::disk_memory::allocation::<u8>(u64::try_from(
                plaintext_len,
            )?)?)?;
        assert!(plaintext <= point.plaintext_bytes());
        let before_read = fixture.memory.snapshot();
        // Observe both actual native and plaintext admissions. Cache retention
        // is zero: directory pages and values use their admitted output.
        let ((read, observed), allocations, requested) = measure_requested(|| {
            crate::test_utils::source_quote_observer::measure(&fixture.memory, || {
                view.application_get("payload", b"key", bytes.len())
            })
        });
        let read = read?;
        assert_eq!(read.as_deref(), Some(bytes.as_slice()));
        assert_eq!(
            fixture.memory.snapshot().used_bytes,
            before_read.used_bytes + plaintext
        );
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            before_read.live_reservations + 1
        );
        assert!(observed.requests[..observed.count].contains(&plaintext));
        assert!(allocations > 0);
        assert!(!observed.overflow);
        // measure_requested is cumulative traffic, not a simultaneous peak.
        // Sequential table/row probes can each allocate the same page buffers.
        let admitted_traffic: u64 = observed.requests[..observed.count].iter().sum();
        assert!(requested as u64 <= point.plaintext_bytes() + admitted_traffic);
        // Bounds/page and later ciphertext/plaintext each need two leases.
        assert_eq!(observed.peak_slots, 2);
        let requests = PointReadRequests::new(point.ciphertext_limit()).unwrap();
        let native = |bytes| native_charge(fixture.memory.as_ref(), bytes).unwrap();
        for request in [
            requests.bounds_request_bytes(),
            requests.page_request_bytes(),
            requests.output_request_bytes(),
        ] {
            assert!(
                observed.requests[..observed.count].contains(&native(request)),
                "actual zero-cache read omitted a quoted mandatory request"
            );
        }
        // Keep the actual two-lease directory or ciphertext/plaintext peak
        // exact, apart from the unchanged conservative fallback allowances.
        let directory =
            native(requests.bounds_request_bytes()) + native(requests.page_request_bytes());
        let value = native(requests.output_request_bytes());
        let former_page = native(requests.page_fallback_request_bytes());
        let former_value = native(requests.value_fallback_request_bytes());
        for former in [former_page, former_value] {
            assert!(
                ![
                    native(requests.bounds_request_bytes()),
                    native(requests.page_request_bytes()),
                    value,
                    plaintext,
                ]
                .contains(&former),
                "fixture requests must distinguish temporary fallback"
            );
            assert!(
                !observed.requests[..observed.count].contains(&former),
                "admitted read recreated a temporary workspace payload"
            );
        }
        assert_eq!(observed.peak_bytes, directory.max(value + plaintext));
        assert_eq!(
            point.native_peak_bytes(),
            (directory + former_page).max(value + former_value)
        );
        assert!(observed.peak_bytes <= point.native_peak_bytes());
        if len == 1 {
            assert!(directory > value);
        } else {
            assert!(value > directory);
        }
        assert!(observed.peak_bytes <= point.peak_bytes()?);
        drop(read);
        assert_eq!(fixture.memory.snapshot().used_bytes, before_read.used_bytes);
        assert_eq!(
            fixture.memory.snapshot().live_reservations,
            before_read.live_reservations
        );
        view.close()?;
        drop(quote);
    }
    fixture.close().await
}

#[test]
fn provider_without_own_quote_refuses_without_guessing_or_allocating() {
    struct Unquoted(Arc<TestDiskMemory>);
    impl kasumi_kv::SourceMemoryProvider for Unquoted {}
    impl NodeDiskMemoryAdmission for Unquoted {
        fn storage_census(&self) -> &crate::StorageCensus {
            self.0.storage_census()
        }
        fn reserve_installed(self: Arc<Self>, bytes: u64) -> io::Result<crate::DiskMemoryLease> {
            self.0.clone().reserve_installed(bytes)
        }
        fn install_native_constructor(
            self: Arc<Self>,
            _install: &mut crate::NativeConstructorInstall<'_>,
        ) -> io::Result<()> {
            Err(io::ErrorKind::Unsupported.into())
        }
        fn quote_cache_memory(&self, bytes: u64) -> io::Result<kasumi_kv::CacheMemoryQuote> {
            self.0.quote_cache_memory(bytes)
        }
        fn reserve_cache_memory(
            self: Arc<Self>,
            bytes: u64,
        ) -> io::Result<kasumi_kv::CacheMemoryLease> {
            self.0.clone().reserve_cache_memory(bytes)
        }
    }
    let memory = TestDiskMemory::new(1 << 20, 8);
    let provider = Unquoted(memory.clone());
    let before = memory.snapshot();
    let (result, allocations, bytes) = measure_requested(|| provider.quote_installed(12));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    assert_eq!((allocations, bytes), (0, 0));
    assert_eq!(memory.snapshot().attempts, before.attempts);
}
