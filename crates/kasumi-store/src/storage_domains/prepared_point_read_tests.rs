use super::*;
use crate::{
    allocation_tests::measure_requested,
    test_utils::{
        LocalKeyProvider, ManualClock, TestDiskMemory, private_tempdir, retry_disk_registry,
    },
};

struct Fixture {
    stores: Arc<TenantStorageSet>,
    node: NodeStore,
    memory: Arc<TestDiskMemory>,
    clock: Arc<ManualClock>,
    _persistent: tempfile::TempDir,
    _scratch: tempfile::TempDir,
}
impl Fixture {
    async fn new(cache_bytes: u64) -> Result<Self> {
        let persistent = private_tempdir()?;
        let scratch = private_tempdir()?;
        let memory = TestDiskMemory::new(256 << 20, 128);
        let path = persistent.path().join("prepared-points.kv");
        let mut config = crate::test_utils::node_storage_config();
        config.cache.byte_limit = cache_bytes;
        // Install the same bounded cache share that this fixture requests.
        // The generic disk fixture installs a zero-byte cache ceiling.
        let mut disk_config = NodeDisk::fixture_config(&path)?;
        disk_config.native_storage = config;
        let disk = retry_disk_registry(|| {
            NodeDisk::open_fixture(&disk_config, memory.clone(), &CensusCancellation::default())
        })?;
        let scratch_disk = ScratchDisk::fixture(scratch.path(), memory.clone());
        let node = NodeStore::create_new(
            path,
            crate::test_utils::NODE_STORE_ID,
            disk,
            scratch_disk,
            config,
        )
        .unwrap_or_else(|original| std::panic::panic_any(original));
        let clock = Arc::new(ManualClock::default());
        let tenant = "prepared-source";
        let application = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            tenant.into(),
            Arc::new(LocalKeyProvider::new([91; 32])),
            clock.clone(),
        )
        .await?;
        let custody = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            CustodyStore::catalog_name(tenant),
            Arc::new(LocalKeyProvider::new([92; 32])),
            clock.clone(),
        )
        .await?;
        let stores = TenantStorageSet::install(application, custody)?;
        Ok(Self {
            stores,
            node,
            memory,
            clock,
            _persistent: persistent,
            _scratch: scratch,
        })
    }
    fn write(&self, value: &[u8]) -> Result<()> {
        self.stores.write_batch(
            &[WriteOp::put("payload", b"key", value)],
            &[WriteOp::put("payload", b"key", value)],
        )
    }
    fn session(&self, bytes: usize) -> Result<PreparedTenantPointReads> {
        let view = self.stores.read_view()?;
        assert!(
            view.registered_reader_id().is_some(),
            "must use the actual registered reader"
        );
        view.prepare_point_reads(7, 8, bytes)
    }
    // Physical corruption below the encrypted facade retains valid native CRCs.
    fn inject(&self, plaintext: &[u8], tamper_tag: bool) -> Result<()> {
        let store = self.stores.application();
        let state = store.state.read();
        let catalog = store.catalog.read();
        let disk_key = inline_record_key(
            store.tenant(),
            "payload",
            b"key",
            state.keys.get(INDEX_KEY).unwrap(),
        );
        let mut envelope = Vec::new();
        append_bytes(&mut envelope, catalog.active.as_bytes())?;
        envelope.extend(encrypt(
            state.keys.get(&catalog.active).unwrap(),
            plaintext,
            &record_aad(store.tenant(), &disk_key),
        )?);
        if tamper_tag {
            *envelope.last_mut().unwrap() ^= 1;
        }
        let tx = self.node.body().db.begin_write()?;
        tx.open_table(RECORDS)?
            .insert(disk_key.as_slice(), envelope.as_slice())?;
        tx.commit()?;
        Ok(())
    }
    async fn close(self) -> Result<()> {
        assert_eq!(self.memory.storage_census().snapshot().readers, 0);
        self.stores.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}

#[tokio::test]
async fn prepared_points_reuse_real_encrypted_backing_with_exact_overlapping_charges() -> Result<()>
{
    let fixture = Fixture::new(0).await?;
    let value = vec![42; 65_537];
    fixture.write(&value)?;
    let before = fixture.memory.snapshot();
    let quote = fixture.stores.quote_read_memory()?;
    let quoted = quote.prepared_point_peak_bytes(7, 8, value.len())?;
    let ((session, observed), _, _) = measure_requested(|| {
        crate::test_utils::source_quote_observer::measure(&fixture.memory, || {
            fixture.session(value.len())
        })
    });
    let mut session = session?;
    let retained = fixture.memory.snapshot();
    assert!(!observed.overflow);
    assert!(observed.peak_bytes <= quoted);
    assert!(retained.used_bytes - before.used_bytes > (2 * value.len()) as u64);
    // Four registered-reader leases and four coexisting point-workspace leases:
    // Store plaintext/AAD, native shell, combined directory, and ciphertext output.
    assert_eq!(retained.live_reservations - before.live_reservations, 8);
    let plaintext = session.workspace.backing.plaintext.as_ptr();
    let aad = session.workspace.backing.aad.as_ptr();
    let id = session.registered_reader_id();
    for _ in 0..3 {
        let ((result, requests), allocations, bytes) = measure_requested(|| {
            crate::test_utils::source_quote_observer::measure(&fixture.memory, || {
                assert_eq!(
                    session.application_get("payload", b"key", value.len())?,
                    Some(value.as_slice())
                );
                assert_eq!(
                    session.custody_get("payload", b"key", value.len())?,
                    Some(value.as_slice())
                );
                assert!(
                    session
                        .application_get("payload", b"absent", value.len())?
                        .is_none()
                );
                Ok::<_, anyhow::Error>(())
            })
        });
        result?;
        assert_eq!(
            (requests.count, requests.peak_slots, allocations, bytes),
            (0, 0, 0, 0)
        );
        assert_eq!(session.workspace.backing.plaintext.as_ptr(), plaintext);
        assert_eq!(session.workspace.backing.aad.as_ptr(), aad);
        assert_eq!(session.registered_reader_id(), id);
        assert!(
            session
                .workspace
                .backing
                .plaintext
                .iter()
                .all(|byte| *byte == 0)
        );
    }
    assert_eq!(fixture.node.cache_stats()?.entries, 0);
    session.close()?;
    assert_eq!(fixture.memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        before.live_reservations
    );
    drop(quote);
    fixture.close().await
}

#[tokio::test]
async fn prepared_points_keep_both_domains_on_the_same_snapshot_across_writes_and_rotation()
-> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"old")?;
    let mut old = fixture.session(64)?;
    fixture.stores.application().rotate_data_key().await?;
    fixture.write(b"new")?;
    let mut current = fixture.session(64)?;
    for _ in 0..2 {
        assert_eq!(
            old.application_get("payload", b"key", 64)?,
            Some(b"old".as_slice())
        );
        assert_eq!(
            current.application_get("payload", b"key", 64)?,
            Some(b"new".as_slice())
        );
        assert_eq!(
            old.custody_get("payload", b"key", 64)?,
            Some(b"old".as_slice())
        );
        assert_eq!(
            current.custody_get("payload", b"key", 64)?,
            Some(b"new".as_slice())
        );
    }
    old.close()?;
    current.close()?;
    fixture.close().await
}

#[tokio::test]
async fn prepared_points_retain_full_fit_cache_and_check_expiry_on_hits_and_absence() -> Result<()>
{
    for key in [b"key".as_slice(), b"absent".as_slice()] {
        let fixture = Fixture::new(8 << 20).await?;
        fixture.write(b"resident")?;
        let mut session = fixture.session(64)?;
        assert_eq!(
            session.application_get("payload", b"key", 64)?,
            Some(b"resident".as_slice())
        );
        let before = fixture.node.cache_stats()?;
        for _ in 0..3 {
            assert_eq!(
                session.application_get("payload", b"key", 64)?,
                Some(b"resident".as_slice())
            );
        }
        let after = fixture.node.cache_stats()?;
        assert!(after.hits > before.hits);
        assert_eq!(
            (after.misses, after.evictions),
            (before.misses, before.evictions)
        );
        assert!(after.resident_bytes <= 8 << 20);
        fixture
            .clock
            .advance(MAX_KEY_LEASE + Duration::from_nanos(1));
        assert!(session.application_get("payload", key, 64).is_err());
        assert!(
            session
                .workspace
                .backing
                .plaintext
                .iter()
                .all(|byte| *byte == 0)
        );
        session.close()?;
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn prepared_points_check_peer_access_even_on_application_cache_hit_and_absence() -> Result<()>
{
    for key in [b"key".as_slice(), b"absent".as_slice()] {
        let fixture = Fixture::new(8 << 20).await?;
        fixture.write(b"secret")?;
        let mut session = fixture.session(64)?;
        assert!(session.application_get("payload", b"key", 64)?.is_some());
        fixture.stores.custody().store().seal();
        assert!(session.application_get("payload", key, 64).is_err());
        assert!(
            session
                .workspace
                .backing
                .plaintext
                .iter()
                .all(|byte| *byte == 0)
        );
        session.close()?;
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn prepared_points_authenticate_and_reject_wrong_identity_trailing_and_missing_key()
-> Result<()> {
    for malformed in 0..4 {
        let fixture = Fixture::new(0).await?;
        fixture.write(b"secret")?;
        let mut plaintext = encode_plain_record(
            "payload",
            if malformed == 1 { b"bad" } else { b"key" },
            b"secret",
        )?;
        if malformed == 2 {
            plaintext.push(0);
        }
        fixture.inject(&plaintext, malformed == 0)?;
        let mut session = fixture.session(64)?;
        let removed = if malformed == 3 {
            let id = fixture.stores.application().catalog.read().active.clone();
            let key = fixture
                .stores
                .application()
                .state
                .write()
                .keys
                .remove(&id)
                .unwrap();
            Some((id, key))
        } else {
            None
        };
        let error = session.application_get("payload", b"key", 64).unwrap_err();
        let text = format!("{error:#}");
        let expected = [
            "authentication failed",
            "identity mismatch",
            "trailing encrypted record data",
            "unavailable key",
        ][malformed];
        assert!(text.contains(expected), "{text}");
        assert!(
            session
                .workspace
                .backing
                .plaintext
                .iter()
                .all(|byte| *byte == 0)
        );
        if let Some((id, key)) = removed {
            fixture
                .stores
                .application()
                .state
                .write()
                .keys
                .insert(id, key);
        }
        session.close()?;
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn prepared_point_partial_construction_denial_retires_backing_and_registered_reader()
-> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"secret")?;
    let baseline = fixture.memory.snapshot();
    let view = fixture.stores.read_view()?;
    // Leave three slots for the four real point requests: output construction
    // fails after plaintext/shell/combined directory admission. No synthetic owner.
    let mut blockers = Vec::new();
    while fixture.memory.snapshot().live_reservations < 125 {
        blockers.push(fixture.memory.clone().reserve_installed(0)?);
    }
    let blocked = fixture.memory.snapshot();
    let error = match view.prepare_point_reads(7, 8, 64) {
        Ok(session) => {
            session.close()?;
            panic!("one-slot-short construction succeeded")
        }
        Err(error) => error,
    };
    let failure = error
        .downcast_ref::<NodeScopedReadFailure>()
        .expect("actual registered failure owner");
    assert!(
        matches!(&(failure.report().read_failure()), kasumi_kv::TerminalObservation::Returned(Err(kasumi_kv::BoundedReadError::Storage(
            kasumi_kv::StorageError::Core(native_error)
        ))) if matches!(native_error.rejected_cause(), Some(kasumi_kv::CoreErrorCause::CapacityDenied)))
    );
    // The failed operation's report remains owned by the error; all partial
    // point backing has already retired. Drop the actual diagnostic to retire
    // the remaining routine reader custody, then retry on the same owner.
    assert!(fixture.memory.snapshot().live_reservations <= blocked.live_reservations);
    drop(error);
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        blocked.live_reservations - 4
    );
    drop(blockers);
    assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
    let mut retry = fixture.session(64)?;
    assert_eq!(
        retry.application_get("payload", b"key", 64)?,
        Some(b"secret".as_slice())
    );
    // Local shape refusal clears plaintext and does not poison the real reader.
    assert!(retry.application_get("payload", b"key", 65).is_err());
    assert!(
        retry
            .workspace
            .backing
            .plaintext
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        retry.application_get("payload", b"key", 64)?,
        Some(b"secret".as_slice())
    );
    retry.close()?;
    fixture.close().await
}

#[tokio::test]
async fn prepared_point_handoff_reuses_backing_on_exact_roots_and_clears_short_suffix() -> Result<()>
{
    let fixture = Fixture::new(0).await?;
    let long = vec![73; 8193];
    fixture.write(&long)?;
    let baseline = fixture.memory.snapshot();
    let mut planning = fixture.session(long.len())?;
    let planning_id = planning.registered_reader_id().unwrap();
    assert_eq!(
        planning.application_get("payload", b"key", long.len())?,
        Some(long.as_slice())
    );
    let plaintext = planning.workspace.backing.plaintext.as_ptr();
    let ((), mut points) = planning.finish_with_workspace(Ok(()))?;
    assert!(RegisteredNodeRead::retained(fixture.memory.clone(), planning_id).is_none());
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    assert_eq!(
        fixture.memory.snapshot().live_reservations - baseline.live_reservations,
        4
    );
    assert!(points.backing.plaintext.iter().all(|byte| *byte == 0));
    let old = fixture.stores.read_view()?;
    fixture.write(b"short")?;
    let queued = fixture.stores.prepare_read_view()?;
    let queued_id = queued.registered_reader_id();
    let current = queued.begin()?;
    assert_eq!(current.registered_reader_id(), queued_id);
    let (result, requests) =
        crate::test_utils::source_quote_observer::measure(&fixture.memory, || {
            assert_eq!(
                points.application_get(&old, "payload", b"key", long.len())?,
                Some(long.as_slice())
            );
            assert_eq!(
                points.application_get(&current, "payload", b"key", long.len())?,
                Some(b"short".as_slice())
            );
            assert_eq!(points.backing.plaintext.as_ptr(), plaintext);
            let used = encode_plain_record("payload", b"key", b"short")?.len();
            assert!(
                points.backing.plaintext[used..]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            assert!(
                points
                    .custody_get(&current, "payload", b"absent", long.len())?
                    .is_none()
            );
            assert!(points.backing.plaintext.iter().all(|byte| *byte == 0));
            Ok::<_, anyhow::Error>(())
        });
    result?;
    assert_eq!((requests.count, requests.peak_slots), (0, 0));
    drop(points);
    old.close()?;
    current.close()?;
    assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
    fixture.close().await
}

#[tokio::test]
async fn prepared_point_handoff_checks_pair_authentication_and_expiry_without_admission()
-> Result<()> {
    let fixture = Fixture::new(0).await?;
    let foreign = Fixture::new(0).await?;
    fixture.write(b"secret")?;
    foreign.write(b"foreign")?;
    let ((), mut points) = fixture.session(64)?.finish_with_workspace(Ok(()))?;
    let foreign_view = foreign.stores.read_view()?;
    assert!(
        points
            .application_get(&foreign_view, "payload", b"key", 64)
            .is_err()
    );
    assert!(points.backing.plaintext.iter().all(|byte| *byte == 0));
    foreign_view.close()?;
    foreign.close().await?;
    // Native CRC is valid; the same transferred path must authenticate AEAD.
    fixture.inject(&encode_plain_record("payload", b"key", b"secret")?, true)?;
    let tampered = fixture.stores.read_view()?;
    let error = points
        .application_get(&tampered, "payload", b"key", 64)
        .unwrap_err();
    assert!(format!("{error:#}").contains("authentication failed"));
    assert!(points.backing.plaintext.iter().all(|byte| *byte == 0));
    tampered.close()?;
    fixture.write(b"fresh")?;
    let view = fixture.stores.read_view()?;
    assert!(
        points
            .application_get(&view, "payload", b"key", 64)?
            .is_some()
    );
    fixture
        .clock
        .advance(MAX_KEY_LEASE + Duration::from_nanos(1));
    let (result, requests) =
        crate::test_utils::source_quote_observer::measure(&fixture.memory, || {
            assert!(
                points
                    .application_get(&view, "payload", b"key", 64)
                    .is_err()
            );
            assert!(points.custody_get(&view, "payload", b"absent", 64).is_err());
            assert!(points.backing.plaintext.iter().all(|byte| *byte == 0));
            Ok::<_, anyhow::Error>(())
        });
    result?;
    assert_eq!(requests.count, 0);
    drop(points);
    view.close()?;
    fixture.close().await
}

#[tokio::test]
async fn prepared_point_final_capacity_quotes_real_overlap_and_refusal_keeps_original() -> Result<()>
{
    let fixture = Fixture::new(0).await?;
    fixture.write(b"secret")?;
    let mut planning = fixture.session(64)?;
    let original = planning.workspace.backing.plaintext.as_ptr();
    let held = fixture.memory.snapshot();
    let mut blockers = Vec::new();
    while fixture.memory.snapshot().live_reservations < 128 {
        blockers.push(fixture.memory.clone().reserve_installed(0)?);
    }
    let before_denial = fixture.memory.snapshot();
    let error = planning.ensure_capacity(7, 8, 8193).unwrap_err();
    assert!(error.downcast_ref::<io::Error>().is_some());
    assert_eq!(planning.workspace.backing.plaintext.as_ptr(), original);
    assert_eq!(
        fixture.memory.snapshot().used_bytes,
        before_denial.used_bytes
    );
    assert_eq!(
        planning.application_get("payload", b"key", 64)?,
        Some(b"secret".as_slice())
    );
    drop(blockers);
    let quote = fixture.stores.quote_read_memory()?;
    let before = fixture.memory.snapshot();
    let (result, overlap) =
        crate::test_utils::source_quote_observer::measure(&fixture.memory, || {
            planning.ensure_capacity(7, 8, 8193)
        });
    result?;
    assert_eq!(overlap.count, 4);
    assert_eq!(overlap.peak_slots, 4);
    assert!(overlap.peak_bytes <= quote.prepared_point_backing_bytes(7, 8, 8193)?);
    // Old and replacement buffers genuinely coexist until the successful swap.
    assert_ne!(planning.workspace.backing.plaintext.as_ptr(), original);
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        held.live_reservations
    );
    assert!(fixture.memory.snapshot().used_bytes > before.used_bytes);
    let ((), points) = planning.finish_with_workspace(Ok(()))?;
    drop(points);
    drop(quote);
    fixture.close().await
}

#[tokio::test]
async fn prepared_finish_preserves_original_and_actual_lease_drop_panic() -> Result<()> {
    #[derive(Debug)]
    struct Original(u64);
    impl std::fmt::Display for Original {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "original point body {}", self.0)
        }
    }
    impl std::error::Error for Original {}
    for transfer in [false, true] {
        let fixture = Fixture::new(0).await?;
        let session = fixture.session(64)?;
        let id = session.registered_reader_id().unwrap();
        let original = anyhow::Error::new(Original(713));
        let original_address = std::ptr::from_ref(original.downcast_ref::<Original>().unwrap());
        // The last actual lease is this workspace's native ciphertext output.
        fixture
            .memory
            .panic_on_last_point_lease_drop(Box::new(0x713_u64));
        let error = if transfer {
            session
                .finish_with_workspace::<()>(Err(original))
                .err()
                .unwrap()
        } else {
            session.finish::<()>(Err(original)).unwrap_err()
        };
        let failure = error
            .downcast_ref::<crate::NodeScopedReadFailure>()
            .unwrap();
        assert_eq!(failure.reader_id(), id);
        let body = failure
            .body_error()
            .unwrap()
            .downcast_ref::<Original>()
            .unwrap();
        assert_eq!(std::ptr::from_ref(body), original_address);
        assert_eq!(body.0, 713);
        for _ in 0..2 {
            assert_eq!(
                failure.try_retire_routine(),
                StorageCensusDisposition::Retained
            );
            let report = failure.report();
            let kasumi_kv::TerminalObservation::Panicked(payload) = report.body_panic() else {
                panic!("actual point retirement payload missing");
            };
            assert_eq!(payload.downcast_ref::<u64>(), Some(&0x713));
        }
        drop(error);
        // Explicit test-only acknowledgement of the deliberately injected
        // unknown panic, after proving routine cleanup keeps it retained.
        assert_eq!(
            RegisteredNodeRead::retained(fixture.memory.clone(), id)
                .unwrap()
                .retire(),
            StorageCensusDisposition::Retired
        );
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn prepared_transfer_preserves_native_failure_when_backing_retirement_also_panics()
-> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(&[31; 128])?;
    let baseline = fixture.memory.snapshot();
    let mut session = fixture.session(64)?;
    let id = session.registered_reader_id().unwrap();
    // A true registered native read rejects the ciphertext larger than the
    // admitted bound. The original report survives the returned read facade.
    let read_error = session.application_get("payload", b"key", 64).unwrap_err();
    assert!(
        read_error
            .downcast_ref::<crate::NodeScopedReadFailure>()
            .is_some()
    );
    drop(read_error);
    fixture
        .memory
        .panic_on_last_point_lease_drop(Box::new(0x714_u64));
    let error = session.finish_with_workspace(Ok(())).err().unwrap();
    let combined = error
        .downcast_ref::<crate::PointRetirementFailure>()
        .unwrap();
    combined.with_panic_payload(|payload| {
        assert_eq!(payload.downcast_ref::<u64>(), Some(&0x714));
    });
    let native = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<crate::NodeScopedReadFailure>())
        .unwrap();
    assert_eq!(native.reader_id(), id);
    assert!(matches!(
        native.report().read_failure(),
        kasumi_kv::TerminalObservation::Returned(Err(_))
    ));
    drop(error);
    // Native release and disposal completed before the independent backing
    // destructor failed. The combined diagnostic keeps both originals without
    // recreating a retired native registration.
    assert!(RegisteredNodeRead::retained(fixture.memory.clone(), id).is_none());
    assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
    assert_eq!(
        fixture.memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    assert_eq!(fixture.memory.snapshot().used_bytes, baseline.used_bytes);
    fixture.close().await
}

#[tokio::test]
async fn prepared_size_preflight_reuses_directory_then_authenticates_exact_snapshot() -> Result<()>
{
    let fixture = Fixture::new(0).await?;
    let value = vec![19; 8193];
    fixture.write(&value)?;
    let mut reads = fixture.session(0)?;
    let id = reads.registered_reader_id();
    fixture.write(b"new")?;
    let ((bound, observed), allocations, bytes) = measure_requested(|| {
        crate::test_utils::source_quote_observer::measure(&fixture.memory, || {
            let mut bound = 0;
            for _ in 0..3 {
                bound = reads
                    .application_value_bound("payload", b"key", 1 << 20)?
                    .unwrap();
                assert_eq!(
                    reads.custody_value_bound("payload", b"absent", 1 << 20)?,
                    None
                );
            }
            Ok::<_, anyhow::Error>(bound)
        })
    });
    let bound = bound?;
    assert_eq!((observed.count, allocations, bytes), (0, 0, 0));
    assert!((value.len()..value.len() + 128).contains(&bound));
    assert!(
        reads
            .workspace
            .backing
            .plaintext
            .iter()
            .all(|byte| *byte == 0)
    );
    reads.ensure_capacity(7, 8, bound)?;
    assert_eq!(reads.registered_reader_id(), id);
    assert_eq!(
        reads.application_get("payload", b"key", bound)?,
        Some(value.as_slice())
    );
    reads.close()?;
    // A size bound authenticates no content; actual AEAD corruption must still
    // be rejected by the unchanged physical decrypt implementation.
    fixture.inject(&encode_plain_record("payload", b"key", b"secret")?, true)?;
    let mut corrupted = fixture.session(0)?;
    let bound = corrupted
        .application_value_bound("payload", b"key", 64)?
        .unwrap();
    corrupted.ensure_capacity(7, 8, bound)?;
    let error = corrupted
        .application_get("payload", b"key", bound)
        .unwrap_err();
    assert!(format!("{error:#}").contains("authentication failed"));
    assert!(
        corrupted
            .workspace
            .backing
            .plaintext
            .iter()
            .all(|byte| *byte == 0)
    );
    corrupted.close()?;
    // Both domains remain checked on directory-only misses as on actual loans.
    let mut expired = fixture.session(0)?;
    fixture.clock.advance(std::time::Duration::from_secs(301));
    assert!(
        expired
            .application_value_bound("payload", b"absent", 64)
            .is_err()
    );
    expired.close()?;
    fixture.close().await
}

#[tokio::test]
async fn prepared_size_replacement_retains_actual_old_backing_drop_panic() -> Result<()> {
    let fixture = Fixture::new(0).await?;
    let mut reads = fixture.session(64)?;
    let id = reads.registered_reader_id().unwrap();
    fixture
        .memory
        .panic_on_last_point_lease_drop(Box::new(0x716_u64));
    let original = reads.ensure_capacity(7, 8, 8193).unwrap_err();
    // The actual replacement remains owned; its predecessor's destructor
    // cannot unwind past the session and discard the registered observation.
    assert!(original.downcast_ref::<NodeScopedReadFailure>().is_some());
    let error = reads.finish::<()>(Err(original)).unwrap_err();
    let failure = error.downcast_ref::<NodeScopedReadFailure>().unwrap();
    assert_eq!(failure.reader_id(), id);
    for _ in 0..2 {
        assert_eq!(
            failure.try_retire_routine(),
            StorageCensusDisposition::Retained
        );
        let report = failure.report();
        let kasumi_kv::TerminalObservation::Panicked(payload) = report.body_panic() else {
            panic!("actual old workspace retirement payload absent");
        };
        assert_eq!(payload.downcast_ref::<u64>(), Some(&0x716));
    }
    drop(error);
    assert_eq!(
        RegisteredNodeRead::retained(fixture.memory.clone(), id)
            .unwrap()
            .retire(),
        StorageCensusDisposition::Retired
    );
    fixture.close().await
}

#[path = "prepared_custody_visit_tests.rs"]
mod constructor_visit_tests;

#[path = "key_access_planner_tests.rs"]
mod key_access_planner_tests;
