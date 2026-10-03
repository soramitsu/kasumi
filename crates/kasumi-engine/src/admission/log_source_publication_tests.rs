//! Real Engine funding and exact Store publication/capture ownership.
use super::*;
use kasumi_store::{NamespaceReplacement, RegisteredSourceCapacity, SourceCapacityClose};

fn retire(fixture: &Fixture, source: RegisteredSourceCapacity) {
    let SourceCapacityClose::Retiring(retirement) = source.close() else {
        panic!("actual source pool did not positively finish");
    };
    assert_eq!(
        retirement.retry(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    assert_eq!(fixture.core().storage_census.snapshot().source_pools, 0);
}

#[tokio::test]
async fn paired_publication_captures_its_exact_replacement_before_later_writes() -> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"discarded")?;
    let points = fixture.backing()?;
    let capacity = fixture.stores.queue_source_capacity()?.install()?;
    let mut source = capacity.prepare(0)?;
    let id = source.reader_id();
    fixture
        .stores
        .write_batch_replacing_capturing_source(
            &[WriteOp::put("next", b"key", b"first-app")],
            &[WriteOp::put("next", b"key", b"first-custody")],
            &[NamespaceReplacement::empty("payload")],
            &[NamespaceReplacement::empty("payload")],
            &mut source,
        )?
        .into_result()?;
    assert_eq!(source.phase(), NodeReadPhase::SourceCaptured);
    let repeated = fixture
        .stores
        .write_batch_replacing_capturing_source(
            &[WriteOp::put("next", b"key", b"must-not-publish")],
            &[],
            &[],
            &[],
            &mut source,
        )
        .err()
        .context("captured source was reused")?;
    assert_eq!(repeated.to_string(), "publication source is not prepared");
    let other = Fixture::domains(&fixture.node, &fixture.clock, "other-source-domain").await?;
    let writes = [WriteOp::put("next", b"key", b"must-not-publish")];
    let refused = other
        .write_batch_replacing_capturing_source(&writes, &writes, &[], &[], &mut source)
        .err()
        .context("same-native different domain reused captured source")?;
    assert_eq!(refused.to_string(), "publication source is not prepared");
    assert!(
        other
            .application()
            .get_bounded("next", b"key", 128)?
            .is_none()
    );
    assert!(
        other
            .custody()
            .store()
            .get_bounded("next", b"key", 128)?
            .is_none()
    );
    other.shutdown().await?;
    drop(other);
    fixture.stores.write_batch(
        &[WriteOp::put("next", b"key", b"later-app")],
        &[WriteOp::put("next", b"key", b"later-custody")],
    )?;
    let mut selected = points.bind_source(&fixture.stores, source.capture()?)?;
    assert_eq!(selected.registered_reader_id(), id);
    let pressure = fixture.fill_all()?;
    let before = fixture.core().snapshot();
    assert_eq!(
        selected.application_get("next", b"key", 128)?,
        Some(b"first-app".as_slice())
    );
    assert_eq!(
        selected.custody_get("next", b"key", 128)?,
        Some(b"first-custody".as_slice())
    );
    assert!(selected.application_get("payload", b"key", 128)?.is_none());
    assert!(selected.custody_get("payload", b"key", 128)?.is_none());
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations
    );
    selected.close()?;
    drop(pressure);
    retire(&fixture, capacity);
    fixture.close().await
}

#[tokio::test]
async fn sole_domain_publication_captures_without_application_access() -> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.stores.application().seal();
    let store = fixture.stores.custody().store();
    let (_, points) = store
        .read_view()?
        .prepare_point_reads(16, 16, 128)?
        .finish_with_workspace(Ok(()))?;
    let capacity = store.queue_source_capacity()?.install()?;
    let mut source = capacity.prepare(0)?;
    store.write_batch_capturing_source(
        &[WriteOp::put("payload", b"key", b"captured")],
        &mut source,
    )?;
    store.write_batch(&[WriteOp::put("payload", b"key", b"later")])?;
    let (selected, mut points) = points.bind_source(store, source.capture()?)?;
    assert_eq!(
        selected
            .point_reads(&mut points)?
            .get("payload", b"key", 128)?,
        Some(b"captured".as_slice())
    );
    selected.close()?;
    points.retire().expect("actual point retirement");
    retire(&fixture, capacity);
    fixture.close().await
}

#[tokio::test]
async fn source_publication_rejects_foreign_provider_before_any_write() -> Result<()> {
    let fixture = Fixture::new(0).await?;
    let foreign = Fixture::new(0).await?;
    let capacity = foreign.stores.queue_source_capacity()?.install()?;
    let mut source = capacity.prepare(0)?;
    for paired in [false, true] {
        let writes = [WriteOp::put("payload", b"key", b"forbidden")];
        let error = if paired {
            fixture
                .stores
                .write_batch_replacing_capturing_source(&writes, &[], &[], &[], &mut source)
                .err()
        } else {
            fixture
                .stores
                .custody()
                .store()
                .write_batch_capturing_source(&writes, &mut source)
                .err()
        }
        .context("foreign prepared source accepted")?;
        assert_eq!(error.to_string(), "publication source provider differs");
        assert_eq!(source.phase(), NodeReadPhase::SourcePrepared);
        assert!(
            fixture
                .stores
                .application()
                .get_bounded("payload", b"key", 16)?
                .is_none()
        );
        assert!(
            fixture
                .stores
                .custody()
                .store()
                .get_bounded("payload", b"key", 16)?
                .is_none()
        );
    }
    source.cancel_settled()?;
    retire(&foreign, capacity);
    foreign.close().await?;
    fixture.close().await
}
