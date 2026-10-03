//! Real Engine funding, registered captured roots, and canonical encrypted loans.
use super::*;
use crate::admission::{AdmissionConfig, NodeAdmission};
use anyhow::{Context as _, Result};
use kasumi_store::{
    CustodyStore, NodeReadPhase, NodeStore, PreparedTenantPointWorkspace, RegisteredNodeOpening,
    RegisteredNodeRead, RegisteredSourceFundingFixture, SourcePoolPhase, TenantStorageSet,
    TenantStore, WriteOp,
    test_utils::{LocalKeyProvider, ManualClock},
};
use std::time::Duration;

struct Fixture {
    _directory: tempfile::TempDir,
    storage: crate::test_utils::FixtureStorage,
    node: Arc<NodeStore>,
    stores: Arc<TenantStorageSet>,
    clock: Arc<ManualClock>,
    opening: RegisteredNodeOpening,
}
impl Fixture {
    async fn new(cache: u64) -> Result<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (mut persistent, mut scratch) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        persistent.native_storage.cache.byte_limit = cache;
        scratch.native_cache_bytes = 0;
        let config = crate::test_utils::isolated_disk_admission_config(
            AdmissionConfig {
                max_inflight_bytes: Some(256 << 20),
                ..Default::default()
            },
            &persistent,
            &scratch,
        )?;
        let admission = NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let storage =
            crate::test_utils::FixtureStorage::with_admission(&persistent, &scratch, admission)?;
        let node = storage.create_new(
            directory.path().join("persistent/source-points.kv"),
            uuid::Uuid::from_u128(771),
        )?;
        let clock = Arc::new(ManualClock::default());
        let stores = Self::domains(&node, &clock, "source-points").await?;
        let opening = RegisteredNodeOpening::retained(
            node.persistent_disk().memory().clone(),
            node.registered_opening_id().unwrap(),
        )
        .context("actual registered opening absent")?;
        Ok(Self {
            _directory: directory,
            storage,
            node,
            stores,
            clock,
            opening,
        })
    }
    async fn domains(
        node: &Arc<NodeStore>,
        clock: &Arc<ManualClock>,
        tenant: &str,
    ) -> Result<Arc<TenantStorageSet>> {
        let app = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            tenant.into(),
            Arc::new(LocalKeyProvider::new([161; 32])),
            clock.clone(),
        )
        .await?;
        let custody = TenantStore::initialize_catalog_fixture_with_clock(
            node.clone(),
            CustodyStore::catalog_name(tenant),
            Arc::new(LocalKeyProvider::new([162; 32])),
            clock.clone(),
        )
        .await?;
        kasumi_store::test_utils::with_domains(app, custody)
    }
    fn core(&self) -> &Arc<MemoryCore> {
        self.storage.admission.memory()
    }
    fn write(&self, bytes: &[u8]) -> Result<()> {
        self.stores.write_batch(
            &[WriteOp::put("payload", b"key", bytes)],
            &[WriteOp::put("payload", b"key", bytes)],
        )
    }
    fn backing(&self) -> Result<PreparedTenantPointWorkspace> {
        let points = self.stores.read_view()?.prepare_point_reads(16, 16, 128)?;
        points
            .finish_with_workspace(Ok(()))
            .map(|(_, workspace)| workspace)
    }
    fn source(&self) -> Result<RegisteredSourceFundingFixture> {
        let source = self.opening.queue_registered_source_funding_fixture()?;
        source.install();
        assert_eq!(source.phase(), Some(SourcePoolPhase::Ready));
        Ok(source)
    }
    fn reader(&self, source: &RegisteredSourceFundingFixture, slot: usize) -> RegisteredNodeRead {
        RegisteredNodeRead::retained(
            self.node.persistent_disk().memory().clone(),
            source.reader(slot).unwrap().id(),
        )
        .unwrap()
    }
    fn fill_all(&self) -> Result<Reservation> {
        Ok(self
            .storage
            .admission
            .reserve_resident(self.core().data.max_bytes - self.core().snapshot().reserved_bytes)?)
    }
    fn finish_source(&self, mut source: RegisteredSourceFundingFixture) {
        for slot in 0..3 {
            source.release_read(slot);
        }
        source.seal();
        source.drain();
        assert_eq!(source.phase(), Some(SourcePoolPhase::Finished));
        let id = source.id();
        drop(source);
        self.core().storage_census.drain_owner(id);
        assert_eq!(self.core().storage_census.snapshot().source_pools, 0);
    }
    async fn close(self) -> Result<()> {
        self.stores.shutdown().await?;
        drop(self.opening);
        self.node.shutdown().await?;
        Ok(())
    }
}

#[tokio::test]
async fn protected_source_actual_encrypted_current_and_history_need_no_new_ordinary_grant()
-> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"old")?;
    let first_backing = fixture.backing()?;
    let second_backing = fixture.backing()?;
    let mut source = fixture.source()?;
    source.queue(0, 0)?;
    source.prepare(0);
    let pressure = fixture.fill_all()?;
    assert!(fixture.storage.admission.reserve_resident(1).is_err());
    let before = fixture.core().snapshot();
    source.capture(0);
    let id = source.reader(0).unwrap().id();
    assert_eq!(
        source.reader(0).unwrap().begin(),
        NodeReadPhase::SourceCaptured
    );
    assert!(
        source
            .reader(0)
            .unwrap()
            .record_bytes(b"arbitrary", 128)
            .is_err()
    );
    let mut first = first_backing.bind_source(&fixture.stores, fixture.reader(&source, 0))?;
    assert_eq!(first.registered_reader_id(), id);
    assert_eq!(
        first.application_get("payload", b"key", 128)?,
        Some(b"old".as_slice())
    );
    assert_eq!(
        first.custody_get("payload", b"key", 128)?,
        Some(b"old".as_slice())
    );
    assert!(first.application_get("payload", b"absent", 128)?.is_none());
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations
    );
    drop(pressure);

    source.prepare_history(0);
    assert!(first.application_get("payload", b"key", 128).is_err());
    source.defer_next_committed_marker(0);
    source.commit_history(0);
    assert_eq!(source.history_progress(0), Some((1, true, false, false)));
    assert!(first.custody_get("payload", b"key", 128).is_err());
    source.commit_history(0);
    assert!(source.history_complete(0));
    assert_eq!(source.history_progress(0), Some((1, true, true, true)));
    fixture.write(b"new")?;
    source.queue(1, 0)?;
    source.prepare(1);
    let pressure = fixture.fill_all()?;
    assert!(fixture.storage.admission.reserve_resident(1).is_err());
    let before = fixture.core().snapshot();
    source.capture(1);
    let mut second = second_backing.bind_source(&fixture.stores, fixture.reader(&source, 1))?;
    assert_eq!(
        second.application_get("payload", b"key", 128)?,
        Some(b"new".as_slice())
    );
    assert_eq!(
        first.application_get("payload", b"key", 128)?,
        Some(b"old".as_slice())
    );
    assert_eq!(
        first.custody_get("payload", b"key", 128)?,
        Some(b"old".as_slice())
    );
    assert!(second.custody_get("payload", b"absent", 128)?.is_none());
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations
    );
    drop(pressure);
    source.release_read(0);
    source.release_read(1);
    first.close()?;
    second.close()?;
    fixture.finish_source(source);
    fixture.close().await
}

#[tokio::test]
async fn protected_source_binding_rejects_foreign_pair_provider_and_uncaptured_owner() -> Result<()>
{
    for mode in ["pair", "provider", "native", "uncaptured"] {
        let fixture = Fixture::new(0).await?;
        fixture.write(b"secret")?;
        let backing = fixture.backing()?;
        let foreign = if mode == "provider" {
            Some(Fixture::new(0).await?)
        } else {
            None
        };
        let other_pair = if mode == "pair" {
            Some(Fixture::domains(&fixture.node, &fixture.clock, "other-pair").await?)
        } else {
            None
        };
        let other_node = if mode == "native" {
            Some(fixture.storage.create_new(
                fixture._directory.path().join("persistent/other-source.kv"),
                uuid::Uuid::from_u128(772),
            )?)
        } else {
            None
        };
        let other_opening = other_node.as_ref().map(|node| {
            RegisteredNodeOpening::retained(
                node.persistent_disk().memory().clone(),
                node.registered_opening_id().unwrap(),
            )
            .unwrap()
        });
        let source_fixture = foreign.as_ref().unwrap_or(&fixture);
        let mut source = if let Some(opening) = &other_opening {
            let source = opening.queue_registered_source_funding_fixture()?;
            source.install();
            source
        } else {
            source_fixture.source()?
        };
        source.queue(0, 0)?;
        source.prepare(0);
        if mode != "uncaptured" {
            source.capture(0);
        }
        let reader = RegisteredNodeRead::retained(
            source_fixture.node.persistent_disk().memory().clone(),
            source.reader(0).unwrap().id(),
        )
        .unwrap();
        let stores = other_pair.as_ref().unwrap_or(&fixture.stores);
        let error = backing
            .bind_source(stores, reader)
            .err()
            .context("foreign or unready source was accepted")?;
        match mode {
            "pair" => assert!(
                error
                    .chain()
                    .any(|e| e.to_string().contains("another storage pair"))
            ),
            "provider" => assert!(
                error
                    .chain()
                    .any(|e| e.to_string().contains("memory owners differ"))
            ),
            "native" => assert!(error.chain().any(|e| {
                e.downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::InvalidInput)
            })),
            "uncaptured" => assert!(error.chain().any(|e| {
                e.downcast_ref::<kasumi_store::NodeReadAccessError>()
                    .is_some()
            })),
            _ => unreachable!(),
        }
        assert_eq!(source.reader(0).unwrap().phase(), NodeReadPhase::Finished);
        drop(error);
        source_fixture.finish_source(source);
        if let Some(pair) = other_pair {
            pair.shutdown().await?;
        }
        drop(other_opening);
        if let Some(node) = other_node {
            node.shutdown().await?;
        }
        if let Some(foreign) = foreign {
            foreign.close().await?;
        }
        fixture.close().await?;
    }
    // A real ordinary Active root has no protected source purpose. Even with
    // matching pair/provider/opening, it cannot be promoted by this binder.
    let fixture = Fixture::new(0).await?;
    let backing = fixture.backing()?;
    let reader = fixture.opening.queue_read()?;
    let id = reader.id();
    assert_eq!(reader.begin(), NodeReadPhase::Active);
    let error = backing
        .bind_source(&fixture.stores, reader)
        .err()
        .context("ordinary root was promoted to a protected source")?;
    assert!(matches!(
        error.downcast_ref::<kasumi_store::NodeReadAccessError>(),
        Some(kasumi_store::NodeReadAccessError::Unavailable)
    ));
    assert!(
        RegisteredNodeRead::retained(fixture.node.persistent_disk().memory().clone(), id).is_none()
    );
    drop(error);
    fixture.close().await?;
    Ok(())
}

#[tokio::test]
async fn protected_source_encrypted_loans_recheck_expiry_for_hits_misses_and_absence() -> Result<()>
{
    for cache in [0, 8 << 20] {
        for key in [b"key".as_slice(), b"absent".as_slice()] {
            let fixture = Fixture::new(cache).await?;
            fixture.write(b"resident")?;
            let backing = fixture.backing()?;
            let mut source = fixture.source()?;
            source.queue(0, 0)?;
            source.prepare(0);
            source.capture(0);
            let mut points = backing.bind_source(&fixture.stores, fixture.reader(&source, 0))?;
            assert_eq!(
                points.application_get("payload", b"key", 128)?,
                Some(b"resident".as_slice())
            );
            let before = fixture.node.cache_stats()?;
            assert_eq!(
                points.application_get("payload", b"key", 128)?,
                Some(b"resident".as_slice())
            );
            let after = fixture.node.cache_stats()?;
            if cache != 0 {
                assert!(after.hits > before.hits);
            }
            fixture
                .clock
                .advance(kasumi_store::MAX_KEY_LEASE + Duration::from_nanos(1));
            assert!(points.application_get("payload", key, 128).is_err());
            assert!(points.custody_get("payload", key, 128).is_err());
            source.release_read(0);
            points.close()?;
            fixture.finish_source(source);
            fixture.close().await?;
        }
    }
    Ok(())
}

#[path = "source_history_abort_tests.rs"]
mod history_abort_tests;

#[path = "production_source_capacity_tests.rs"]
mod production_capacity_tests;

#[path = "single_domain_source_points_tests.rs"]
mod single_domain_source_points_tests;

#[path = "log_source_publication_tests.rs"]
mod log_source_publication_tests;
