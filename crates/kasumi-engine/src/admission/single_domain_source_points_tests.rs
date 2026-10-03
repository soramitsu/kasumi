//! A single custody domain uses real protected roots, never a fabricated pair.
use super::*;
use kasumi_store::{PreparedTenantReadWorkspace, RegisteredSourceCapacity};

fn backing(store: &Arc<TenantStore>) -> Result<PreparedTenantReadWorkspace> {
    let points = store.read_view()?.prepare_point_reads(16, 16, 128)?;
    points
        .finish_with_workspace(Ok(()))
        .map(|(_, workspace)| workspace)
}

fn retire_capacity(fixture: &Fixture, capacity: RegisteredSourceCapacity) {
    let id = capacity.owner_id();
    let kasumi_store::SourceCapacityClose::Retiring(retirement) = capacity.close() else {
        panic!("actual source capacity did not finish cleanly");
    };
    assert_eq!(retirement.id(), id);
    assert_eq!(
        retirement.retry(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    assert_eq!(fixture.core().storage_census.snapshot().source_pools, 0);
}

#[tokio::test]
async fn single_domain_current_next_roots_reuse_one_actual_backing_under_full_pressure()
-> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"old")?;
    // A custody-only caller has no application key access. Construct and use
    // every following owner through the sole actual custody Store.
    fixture.stores.application().seal();
    let points = backing(fixture.stores.custody().store())?;
    let capacity = fixture
        .stores
        .custody()
        .store()
        .queue_source_capacity()?
        .install()?;
    let old = capacity.prepare(0)?;
    let old_id = old.reader_id();
    let next = capacity.prepare(1)?;
    let next_id = next.reader_id();
    let (old, points) = points.bind_source(fixture.stores.custody().store(), old.capture()?)?;
    fixture
        .stores
        .custody()
        .store()
        .write_batch(&[WriteOp::put("payload", b"key", b"new")])?;
    let pressure = fixture.fill_all()?;
    assert!(fixture.storage.admission.reserve_resident(1).is_err());
    let before = fixture.core().snapshot();
    let (next, mut points) =
        points.bind_source(fixture.stores.custody().store(), next.capture()?)?;
    assert_eq!(old.registered_reader_id(), old_id);
    assert_eq!(next.registered_reader_id(), next_id);
    assert_ne!(old_id, next_id);
    for _ in 0..3 {
        let mut loan = old.point_reads(&mut points)?;
        assert_eq!(loan.value_capacity(), 128);
        assert_eq!(loan.get("payload", b"key", 128)?, Some(b"old".as_slice()));
        assert!(loan.get("payload", b"absent", 128)?.is_none());
        drop(loan);
        let mut loan = next.point_reads(&mut points)?;
        assert_eq!(loan.get("payload", b"key", 128)?, Some(b"new".as_slice()));
        assert!(loan.get("payload", b"key", 129).is_err());
        assert_eq!(loan.get("payload", b"key", 128)?, Some(b"new".as_slice()));
    }
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations
    );
    old.close()?;
    next.close()?;
    for id in [old_id, next_id] {
        assert!(
            RegisteredNodeRead::retained(fixture.node.persistent_disk().memory().clone(), id)
                .is_none()
        );
    }
    points.retire().expect("actual point backing retirement");
    drop(pressure);
    retire_capacity(&fixture, capacity);
    fixture.close().await
}

#[tokio::test]
async fn single_domain_source_loans_recheck_expiry_for_cached_records_and_absence() -> Result<()> {
    for cache in [0, 8 << 20] {
        let fixture = Fixture::new(cache).await?;
        fixture.write(b"resident")?;
        let points = backing(fixture.stores.custody().store())?;
        let capacity = fixture
            .stores
            .custody()
            .store()
            .queue_source_capacity()?
            .install()?;
        let (source, mut points) = points.bind_source(
            fixture.stores.custody().store(),
            capacity.prepare(0)?.capture()?,
        )?;
        let mut loan = source.point_reads(&mut points)?;
        assert_eq!(
            loan.get("payload", b"key", 128)?,
            Some(b"resident".as_slice())
        );
        let before = fixture.node.cache_stats()?;
        assert_eq!(
            loan.get("payload", b"key", 128)?,
            Some(b"resident".as_slice())
        );
        let after = fixture.node.cache_stats()?;
        if cache != 0 {
            assert!(after.hits > before.hits);
        }
        fixture
            .clock
            .advance(kasumi_store::MAX_KEY_LEASE + Duration::from_nanos(1));
        assert!(loan.get("payload", b"key", 128).is_err());
        assert!(loan.get("payload", b"absent", 128).is_err());
        drop(loan);
        assert!(source.point_reads(&mut points).is_err());
        source.close()?;
        points.retire().expect("actual point backing retirement");
        retire_capacity(&fixture, capacity);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn single_domain_binder_rejects_foreign_store_provider_native_and_ordinary_reader()
-> Result<()> {
    for mode in ["store", "provider", "native", "ordinary"] {
        let fixture = Fixture::new(0).await?;
        fixture.write(b"secret")?;
        let points = backing(fixture.stores.custody().store())?;
        let foreign = if mode == "provider" {
            Some(Fixture::new(0).await?)
        } else {
            None
        };
        let other = if mode == "native" {
            Some(
                fixture.storage.create_new(
                    fixture
                        ._directory
                        .path()
                        .join("persistent/single-source-other.kv"),
                    uuid::Uuid::from_u128(773),
                )?,
            )
        } else {
            None
        };
        let other_opening = other.as_ref().map(|node| {
            RegisteredNodeOpening::retained(
                node.persistent_disk().memory().clone(),
                node.registered_opening_id().unwrap(),
            )
            .unwrap()
        });
        let actual = foreign.as_ref().unwrap_or(&fixture);
        let opening = other_opening.as_ref().unwrap_or(&actual.opening);
        let capacity = if mode == "ordinary" {
            None
        } else {
            Some(opening.queue_source_capacity()?.install()?)
        };
        let reader = if let Some(capacity) = &capacity {
            capacity.prepare(0)?.capture()?
        } else {
            let reader = opening.queue_read()?;
            assert_eq!(reader.begin(), NodeReadPhase::Active);
            reader
        };
        let id = reader.id();
        let store = if mode == "store" {
            fixture.stores.application()
        } else {
            fixture.stores.custody().store()
        };
        let error = points
            .bind_source(store, reader)
            .err()
            .context("invalid source identity accepted")?;
        match mode {
            "store" => assert!(error.to_string().contains("another Store")),
            "provider" => assert!(error.to_string().contains("memory owners differ")),
            "native" => assert!(error.chain().any(|e| {
                e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::InvalidInput)
            })),
            "ordinary" => assert!(matches!(
                error.downcast_ref::<kasumi_store::NodeReadAccessError>(),
                Some(kasumi_store::NodeReadAccessError::Unavailable)
            )),
            _ => unreachable!(),
        }
        drop(error);
        assert!(
            RegisteredNodeRead::retained(actual.node.persistent_disk().memory().clone(), id)
                .is_none()
        );
        if let Some(capacity) = capacity {
            retire_capacity(actual, capacity);
        }
        drop(other_opening);
        if let Some(node) = other {
            node.shutdown().await?;
        }
        if let Some(foreign) = foreign {
            foreign.close().await?;
        }
        fixture.close().await?;
    }
    Ok(())
}
