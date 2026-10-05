//! One admitted authenticated plaintext allocation for ordinary tenant reads.
use super::*;

/// The authenticated fields borrow this buffer through their consuming owner.
/// Field order retires the zeroizing allocation before returning byte credit.
pub(crate) struct AdmittedPlaintextRecord {
    plaintext: Zeroizing<Vec<u8>>,
    _charge: DiskMemoryLease,
    provider: Arc<dyn NodeDiskMemoryAdmission>,
}

impl AdmittedPlaintextRecord {
    pub(crate) fn prepare(
        store: &TenantStore,
        disk_key: &[u8],
        envelope: &[u8],
        state: &KeyState,
    ) -> Result<Self> {
        Self::prepare_shape(store, disk_key, envelope, state, false)
    }

    pub(crate) fn prepare_retained(
        store: &TenantStore,
        disk_key: &[u8],
        envelope: &[u8],
        state: &KeyState,
    ) -> Result<Self> {
        Self::prepare_shape(store, disk_key, envelope, state, true)
    }

    // Only the two named Store producers select this private shape; no caller
    // supplies extra bytes, an opaque charge, or a replacement provider.
    fn prepare_shape(
        store: &TenantStore,
        disk_key: &[u8],
        envelope: &[u8],
        state: &KeyState,
        retained: bool,
    ) -> Result<Self> {
        let mut ciphertext = envelope;
        let id = std::str::from_utf8(take_bytes(&mut ciphertext)?)
            .context("invalid encrypted record key id")?;
        let data_key = state
            .keys
            .get(id)
            .context("encrypted record references an unavailable key")?;
        let plaintext_len = ciphertext
            .len()
            .checked_sub(40)
            .context("truncated encrypted record")?;
        ensure!(disk_key.len() == 96, "encrypted record identity mismatch");
        let tenant = store.tenant.as_bytes();
        ensure!(tenant.len() <= 1024, "invalid encrypted record tenant");

        // Parsing borrows the authenticated bytes, so there are no independent
        // namespace/key/value allocations. AAD and identity hashes stay inline.
        let plaintext_admitted = disk_memory::allocation::<u8>(u64::try_from(plaintext_len)?)?;
        let admitted = if retained {
            disk_memory::add(
                plaintext_admitted,
                crate::retained_plaintext_value::SharedPlaintextState::required_bytes()?,
            )?
        } else {
            plaintext_admitted
        };
        let provider = store.plaintext_memory_owner().clone();
        let charge = provider
            .clone()
            .reserve_installed(admitted)
            .context("record plaintext admission denied")?;

        const AAD_PREFIX: &[u8] = b"kasumi.encrypted-record.v1";
        const AAD_MAX: usize = AAD_PREFIX.len() + 8 + 1024 + 96;
        let mut aad = Zeroizing::new([0u8; AAD_MAX]);
        let aad_len = AAD_PREFIX.len() + 8 + tenant.len() + disk_key.len();
        aad[..AAD_PREFIX.len()].copy_from_slice(AAD_PREFIX);
        aad[AAD_PREFIX.len()..AAD_PREFIX.len() + 8]
            .copy_from_slice(&(tenant.len() as u64).to_be_bytes());
        aad[AAD_PREFIX.len() + 8..AAD_PREFIX.len() + 8 + tenant.len()].copy_from_slice(tenant);
        aad[AAD_PREFIX.len() + 8 + tenant.len()..aad_len].copy_from_slice(disk_key);

        let mut plaintext = Zeroizing::new(Vec::new());
        plaintext
            .try_reserve_exact(plaintext_len)
            .context("record plaintext allocation failed")?;
        ensure!(
            u64::try_from(plaintext.capacity())? <= plaintext_admitted,
            "record plaintext allocation exceeded admission"
        );
        plaintext.resize(plaintext_len, 0);
        decrypt_into(data_key, ciphertext, &aad[..aad_len], &mut plaintext)?;
        Ok(Self {
            plaintext,
            _charge: charge,
            provider,
        })
    }

    pub(crate) fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    pub(crate) fn require_memory(&self, provider: &Arc<dyn NodeDiskMemoryAdmission>) -> Result<()> {
        ensure!(
            self.is_from_memory(provider),
            "plaintext installed memory owner differs"
        );
        Ok(())
    }

    pub(crate) fn is_from_memory(&self, provider: &Arc<dyn NodeDiskMemoryAdmission>) -> bool {
        Arc::ptr_eq(&self.provider, provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{
        LocalKeyProvider, ManualClock, TestDiskMemory, node_storage_config, private_tempdir,
        retry_disk_registry, source_quote_observer,
    };

    const MEMORY_LIMIT: u64 = 256 << 20;

    struct Fixture {
        store: Arc<TenantStore>,
        node: NodeStore,
        memory: Arc<TestDiskMemory>,
        clock: Arc<ManualClock>,
        _directory: tempfile::TempDir,
        _scratch_directory: tempfile::TempDir,
    }
    impl Fixture {
        async fn new() -> Result<Self> {
            let directory = private_tempdir()?;
            let path = directory.path().join("admitted-visit.kv");
            let memory = TestDiskMemory::new(MEMORY_LIMIT, 4096);
            let disk = retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone()))?;
            let scratch_directory = private_tempdir()?;
            let scratch = ScratchDisk::fixture(scratch_directory.path(), memory.clone());
            // Exercise the installed registered group, not the synthetic direct
            // database branch selected by create_new_fixture.
            let node = NodeStore::create_new(
                &path,
                crate::test_utils::NODE_STORE_ID,
                disk,
                scratch,
                node_storage_config(),
            )
            .unwrap_or_else(|original| std::panic::panic_any(original));
            let clock = Arc::new(ManualClock::new());
            let store = TenantStore::initialize_catalog_fixture_with_clock(
                node.clone(),
                "tenant".into(),
                Arc::new(LocalKeyProvider::new([91; 32])),
                clock.clone(),
            )
            .await?;
            assert!(!node.body().db.has_fixture_direct_database());
            Ok(Self {
                store,
                node,
                memory,
                clock,
                _directory: directory,
                _scratch_directory: scratch_directory,
            })
        }
        async fn shutdown(self) -> Result<()> {
            self.store.shutdown().await?;
            self.node.shutdown().await?;
            Ok(())
        }
        fn envelope(&self, plaintext: &[u8]) -> Result<([u8; 96], Vec<u8>)> {
            let state = self.store.state.read();
            let catalog = self.store.catalog.read();
            let disk_key = inline_record_key(
                &self.store.tenant,
                "docs",
                b"key",
                state.keys.get(INDEX_KEY).unwrap(),
            );
            let mut envelope = Vec::new();
            append_bytes(&mut envelope, catalog.active.as_bytes())?;
            envelope.extend(encrypt(
                state.keys.get(&catalog.active).unwrap(),
                plaintext,
                &record_aad(&self.store.tenant, &disk_key),
            )?);
            Ok((disk_key, envelope))
        }
        fn replace_row(&self, disk_key: &[u8], envelope: &[u8]) -> Result<()> {
            let transaction = self.node.body().db.begin_write()?;
            transaction
                .open_table(RECORDS)?
                .insert(disk_key, envelope)?;
            transaction.commit()?;
            Ok(())
        }
    }

    fn charge_bytes(plaintext_len: usize) -> u64 {
        TestDiskMemory::required_reservation_bytes(
            disk_memory::allocation::<u8>(u64::try_from(plaintext_len).unwrap()).unwrap(),
        )
        .unwrap()
    }
    fn assert_resident_baseline(
        memory: &TestDiskMemory,
        baseline: crate::test_utils::TestDiskMemorySnapshot,
    ) {
        let current = memory.snapshot();
        assert_eq!(current.used_bytes, baseline.used_bytes);
        assert_eq!(current.live_reservations, baseline.live_reservations);
    }

    #[tokio::test]
    async fn one_plaintext_allocation_admits_actual_geometry_and_borrows_all_fields() -> Result<()>
    {
        let fixture = Fixture::new().await?;
        let value = vec![0x37; 128 << 10];
        let encoded = encode_plain_record("docs", b"key", &value)?;
        let (disk_key, envelope) = fixture.envelope(&encoded)?;
        let baseline = fixture.memory.snapshot();
        {
            let state = fixture.store.state.read();
            let ((owner, allocations, requested), observed) =
                source_quote_observer::measure(&fixture.memory, || {
                    crate::allocation_tests::measure_requested(|| {
                        let owner = AdmittedPlaintextRecord::prepare(
                            &fixture.store,
                            &disk_key,
                            &envelope,
                            &state,
                        )?;
                        let parsed = fixture.store.decode_record_fields(
                            &disk_key,
                            owner.plaintext(),
                            &state,
                        )?;
                        assert_eq!(parsed.namespace, "docs");
                        assert_eq!(parsed.key, b"key");
                        assert_eq!(parsed.value, value);
                        assert_eq!(
                            parsed.value.as_ptr(),
                            parsed.key.as_ptr().wrapping_add(parsed.key.len() + 4)
                        );
                        Ok::<_, anyhow::Error>(owner)
                    })
                });
            let owner = owner?;
            assert_eq!(allocations, 2, "one lease token and one plaintext buffer");
            assert!((encoded.len()..=encoded.len() + 256).contains(&requested));
            assert_eq!(observed.count, 1);
            assert!(!observed.overflow);
            assert_eq!(observed.requests[0], charge_bytes(encoded.len()));
            assert_eq!(observed.peak_bytes, charge_bytes(encoded.len()));
            assert_eq!(
                fixture.memory.snapshot().live_reservations,
                baseline.live_reservations + 1
            );
            drop(owner);
        }
        assert_resident_baseline(&fixture.memory, baseline);
        fixture.shutdown().await
    }

    #[tokio::test]
    async fn denied_plaintext_workspace_allocates_no_record_buffer_and_can_retry() -> Result<()> {
        let fixture = Fixture::new().await?;
        let encoded = encode_plain_record("docs", b"key", &vec![0x43; 128 << 10])?;
        let (disk_key, envelope) = fixture.envelope(&encoded)?;
        let baseline = fixture.memory.snapshot();
        let filler = MEMORY_LIMIT
            - baseline.bookkeeping_bytes
            - baseline.used_bytes
            - TestDiskMemory::required_reservation_bytes(0)?;
        let held = fixture.memory.clone().reserve_installed(filler)?;
        let full = fixture.memory.snapshot();
        {
            let state = fixture.store.state.read();
            let (result, _, requested) = crate::allocation_tests::measure_requested(|| {
                AdmittedPlaintextRecord::prepare(&fixture.store, &disk_key, &envelope, &state)
            });
            let error = result.err().expect("plaintext admission must be denied");
            assert!(format!("{error:#}").contains("record plaintext admission denied"));
            assert!(
                requested < encoded.len(),
                "denial allocated the plaintext buffer"
            );
            assert_resident_baseline(&fixture.memory, full);
            drop(error);
            drop(held);
            let owner =
                AdmittedPlaintextRecord::prepare(&fixture.store, &disk_key, &envelope, &state)?;
            assert_eq!(owner.plaintext(), encoded);
            drop(owner);
        }
        assert_resident_baseline(&fixture.memory, baseline);
        fixture.shutdown().await
    }

    #[tokio::test]
    async fn plaintext_backing_is_deallocated_before_its_credit_can_be_reused() -> Result<()> {
        let fixture = Fixture::new().await?;
        let encoded = encode_plain_record("docs", b"key", b"value")?;
        let (disk_key, envelope) = fixture.envelope(&encoded)?;
        let baseline = fixture.memory.snapshot();
        let owner = {
            let state = fixture.store.state.read();
            AdmittedPlaintextRecord::prepare(&fixture.store, &disk_key, &envelope, &state)?
        };
        let address = owner.plaintext().as_ptr() as usize;
        let observation = crate::allocation_tests::DeallocationObservation::new(true);
        struct Release<'a>(&'a crate::allocation_tests::DeallocationObservation);
        impl Drop for Release<'_> {
            fn drop(&mut self) {
                self.0.release();
            }
        }
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                crate::allocation_tests::observe_deallocation(
                    address as *const (),
                    &observation,
                    || drop(owner),
                );
            });
            let release = Release(&observation);
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while !observation.entered() && std::time::Instant::now() < deadline {
                std::thread::yield_now();
            }
            assert!(
                observation.entered(),
                "plaintext never reached System.dealloc"
            );
            assert_eq!(
                fixture.memory.snapshot().used_bytes,
                baseline.used_bytes + charge_bytes(encoded.len())
            );
            assert!(!observation.finished());
            drop(release);
            worker.join().unwrap();
        });
        assert!(observation.finished());
        assert_eq!(observation.count(), 1);
        assert_resident_baseline(&fixture.memory, baseline);
        fixture.shutdown().await
    }

    #[tokio::test]
    async fn installed_visit_holds_plaintext_credit_through_success_error_and_panic() -> Result<()>
    {
        let fixture = Fixture::new().await?;
        let value = vec![0x49; 128 << 10];
        fixture
            .store
            .write_batch(&[WriteOp::put("docs", b"key", value.clone())])?;
        // Warm the physical descriptor cache before comparing resident owners.
        fixture.store.visit("docs", value.len(), |_, _| Ok(()))?;
        let baseline = fixture.memory.snapshot();
        let plaintext_len = 12 + "docs".len() + b"key".len() + value.len();
        let mut calls = 0;
        let (result, observed) = source_quote_observer::measure(&fixture.memory, || {
            fixture.store.visit("docs", value.len(), |key, bytes| {
                assert_eq!((key, bytes), (b"key".as_slice(), value.as_slice()));
                assert_eq!(bytes.as_ptr(), key.as_ptr().wrapping_add(key.len() + 4));
                assert!(
                    fixture.memory.snapshot().used_bytes
                        >= baseline.used_bytes + charge_bytes(plaintext_len)
                );
                calls += 1;
                Ok(())
            })
        });
        result?;
        assert_eq!(calls, 1);
        assert!(observed.requests[..observed.count].contains(&charge_bytes(plaintext_len)));
        assert_resident_baseline(&fixture.memory, baseline);
        let error = fixture
            .store
            .visit("docs", value.len(), |_, _| {
                assert!(
                    fixture.memory.snapshot().used_bytes
                        >= baseline.used_bytes + charge_bytes(plaintext_len)
                );
                bail!("visitor refused record")
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "visitor refused record");
        assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
        assert_resident_baseline(&fixture.memory, baseline);
        drop(error);

        let failure = fixture
            .store
            .visit("docs", value.len(), |_, _| {
                assert!(
                    fixture.memory.snapshot().used_bytes
                        >= baseline.used_bytes + charge_bytes(plaintext_len)
                );
                std::panic::panic_any("visitor panic")
            })
            .unwrap_err()
            .downcast::<NodeScopedReadFailure>()
            .unwrap();
        assert_eq!(failure.stage(), "body panic");
        assert!(
            matches!(failure.report().body_panic(), kasumi_kv::TerminalObservation::Panicked(payload)
            if payload.downcast_ref::<&str>() == Some(&"visitor panic"))
        );
        let id = failure.reader_id();
        // The smaller original read report remains admitted; no plaintext or
        // copied value survives the callback's unwind.
        assert!(
            fixture.memory.snapshot().used_bytes
                < baseline.used_bytes + charge_bytes(plaintext_len)
        );
        drop(failure);
        let retained = RegisteredNodeRead::retained(fixture.memory.clone(), id).unwrap();
        assert_eq!(retained.retire(), StorageCensusDisposition::Retired);
        assert_resident_baseline(&fixture.memory, baseline);
        fixture.shutdown().await
    }

    #[tokio::test]
    async fn failed_authentication_parse_identity_and_size_release_the_workspace() -> Result<()> {
        let fixture = Fixture::new().await?;
        let valid = encode_plain_record("docs", b"key", b"value")?;
        let wrong_identity = encode_plain_record("docs", b"wrong", b"value")?;
        let oversized = encode_plain_record("docs", b"key", &[0x4d; 32])?;
        let mut trailing = valid.clone();
        trailing.push(0x51);
        let mut cases = Vec::new();
        for (plaintext, expected) in [
            (vec![0, 0, 0], "truncated record field"),
            (wrong_identity, "encrypted record identity mismatch"),
            (trailing, "trailing encrypted record data"),
            (oversized, "record value exceeds visit budget"),
        ] {
            let (key, envelope) = fixture.envelope(&plaintext)?;
            cases.push((key, envelope, expected));
        }
        let (key, mut invalid_tag) = fixture.envelope(&valid)?;
        *invalid_tag.last_mut().unwrap() ^= 1;
        cases.push((key, invalid_tag, "encrypted record authentication failed"));
        for (key, envelope, expected) in cases {
            fixture.replace_row(&key, &envelope)?;
            // A failed visit may first warm the same real descriptor set.
            let _ = fixture.store.visit("docs", 16, |_, _| Ok(()));
            let baseline = fixture.memory.snapshot();
            let mut called = false;
            let error = fixture
                .store
                .visit("docs", 16, |_, _| {
                    called = true;
                    Ok(())
                })
                .unwrap_err();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            assert!(!called);
            assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
            assert_resident_baseline(&fixture.memory, baseline);
        }
        fixture.shutdown().await
    }

    #[tokio::test]
    async fn expired_access_never_decrypts_or_calls_the_visitor() -> Result<()> {
        let fixture = Fixture::new().await?;
        fixture
            .store
            .write_batch(&[WriteOp::put("docs", b"key", b"value")])?;
        fixture
            .clock
            .advance(MAX_KEY_LEASE + Duration::from_secs(1));
        let before = fixture.memory.snapshot();
        let mut called = false;
        let (result, observed) = source_quote_observer::measure(&fixture.memory, || {
            fixture.store.visit("docs", 16, |_, _| {
                called = true;
                Ok(())
            })
        });
        assert!(result.is_err());
        assert!(!called);
        assert_eq!(observed.count, 0, "expired visit admitted a read workspace");
        assert_eq!(fixture.memory.storage_census().snapshot().readers, 0);
        assert_resident_baseline(&fixture.memory, before);
        fixture.shutdown().await
    }
}
