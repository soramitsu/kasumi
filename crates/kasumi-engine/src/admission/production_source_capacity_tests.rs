//! The production facade consumes the same real installed two-right pool.
use super::*;
use std::io;

#[tokio::test]
async fn production_current_next_source_owners_reuse_positive_retirement_under_pressure()
-> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"current")?;
    // These actual buffers are independent of the native/report rights. The
    // future Engine cohort composes their concrete quote; this test owns all
    // overlap explicitly rather than granting a synthetic capacity allowance.
    let current_backing = fixture.backing()?;
    let next_backing = fixture.backing()?;
    let replacement_backing = fixture.backing()?;
    let capacity = fixture.opening.queue_source_capacity()?.install()?;
    let current = capacity.prepare(0)?;
    let next = capacity.prepare(1)?;
    let current_id = current.reader_id();
    let next_id = next.reader_id();
    assert_ne!(current_id, next_id);
    let pressure = fixture.fill_all()?;
    assert!(fixture.storage.admission.reserve_resident(1).is_err());
    let before = fixture.core().snapshot();
    let mut current = current_backing.bind_source(&fixture.stores, current.capture()?)?;
    let mut next = next_backing.bind_source(&fixture.stores, next.capture()?)?;
    assert_eq!(
        current.application_get("payload", b"key", 128)?,
        Some(b"current".as_slice())
    );
    assert_eq!(
        next.custody_get("payload", b"key", 128)?,
        Some(b"current".as_slice())
    );
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations
    );
    current.close()?;
    assert!(
        RegisteredNodeRead::retained(fixture.node.persistent_disk().memory().clone(), current_id)
            .is_none()
    );
    let replacement_before = fixture.core().snapshot();
    let replacement = capacity.prepare(0)?;
    assert_ne!(replacement.reader_id(), current_id);
    let mut replacement =
        replacement_backing.bind_source(&fixture.stores, replacement.capture()?)?;
    assert_eq!(
        replacement.application_get("payload", b"key", 128)?,
        Some(b"current".as_slice())
    );
    assert_eq!(next.registered_reader_id(), next_id);
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        replacement_before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        replacement_before.live_reservations
    );
    replacement.close()?;
    next.close()?;
    drop(pressure);
    capacity.seal();
    capacity.drain();
    assert_eq!(capacity.phase(), Some(SourcePoolPhase::Finished));
    let id = capacity.owner_id();
    drop(capacity);
    fixture.core().storage_census.drain_owner(id);
    assert_eq!(fixture.core().storage_census.snapshot().source_pools, 0);
    fixture.close().await
}

#[tokio::test]
async fn production_prepared_source_cancellation_retires_its_exact_unused_right() -> Result<()> {
    let fixture = Fixture::new(0).await?;
    let capacity = fixture.opening.queue_source_capacity()?.install()?;
    let prepared = capacity.prepare(1)?;
    let id = prepared.reader_id();
    assert_eq!(prepared.phase(), NodeReadPhase::SourcePrepared);
    assert_eq!(
        prepared.cancel()?,
        kasumi_store::StorageCensusDisposition::Retired
    );
    assert!(
        RegisteredNodeRead::retained(fixture.node.persistent_disk().memory().clone(), id).is_none()
    );
    let next = capacity.prepare(1)?;
    assert_ne!(next.reader_id(), id);
    assert_eq!(
        next.cancel()?,
        kasumi_store::StorageCensusDisposition::Retired
    );
    capacity.seal();
    capacity.drain();
    assert_eq!(capacity.phase(), Some(SourcePoolPhase::Finished));
    let id = capacity.owner_id();
    drop(capacity);
    fixture.core().storage_census.drain_owner(id);
    fixture.close().await
}

struct SelectionGrant {
    reservation: Reservation,
    memory: Arc<MemoryCore>,
}
impl kasumi_raft::SelectionWorkspace for SelectionGrant {
    fn require_memory(&self, read: &kasumi_raft::SelectionReadIdentity<'_>) -> Result<()> {
        let memory: Arc<dyn kasumi_store::NodeDiskMemoryAdmission> = self.memory.clone();
        read.require_memory(&memory)
    }
    fn ensure_peak(&mut self, bytes: u64) -> Result<()> {
        kasumi_query::QueryWorkspace::ensure_peak(&mut self.reservation, bytes)?;
        Ok(())
    }
    fn retain(&mut self, bytes: u64) -> Result<()> {
        self.ensure_peak(bytes)?;
        self.reservation.retain(bytes);
        Ok(())
    }
}
impl Fixture {
    fn selection_grant(&self) -> Result<SelectionGrant> {
        Ok(SelectionGrant {
            reservation: self
                .storage
                .admission
                .reserve_application_source(256 << 10)?,
            memory: self.core().clone(),
        })
    }
}

#[tokio::test]
async fn production_source_selection_uses_exact_encrypted_root_and_preowned_small_shape()
-> Result<()> {
    use kasumi_raft::{ApplicationBoundaryRef, ApplicationSelectionMode, RaftLimits};
    let fixture = Fixture::new(0).await?;
    let image = kasumi_store::SnapshotImage::from_bytes(
        fixture.node.scratch_disk(),
        b"protected selected bootstrap",
    )?;
    let manifest = kasumi_store::ApplicationBootstrapManifest {
        format: 2,
        bytes: image.len(),
        chunks: 1,
        digest: image.sha256().to_owned(),
    };
    let mut custody = Vec::from(kasumi_raft::initial_storage_identity(
        1,
        "protected-selected-root",
    )?);
    custody.push(WriteOp::put(
        "raft.meta",
        b"application_bootstrap_sha256",
        serde_json::to_vec(image.sha256())?,
    ));
    fixture.stores.initialize_state(
        &[WriteOp::put(
            "engine.bootstrap",
            b"manifest",
            serde_json::to_vec(&manifest)?,
        )],
        &custody,
    )?;
    let backing = || -> Result<PreparedTenantPointWorkspace> {
        fixture
            .stores
            .read_view()?
            .prepare_point_reads(32, 64, 256)?
            .finish_with_workspace(Ok(()))
            .map(|(_, points)| points)
    };
    let first_backing = backing()?;
    let second_backing = backing()?;
    let first_grant = fixture.selection_grant()?;
    let second_grant = fixture.selection_grant()?;
    let capacity = fixture.opening.queue_source_capacity()?.install()?;
    let first = capacity.prepare(0)?.capture()?;
    // Production immutable bootstrap identity cannot be overwritten, even by
    // this local fixture. Keep that refusal and use the mutable applied row to
    // make the later authenticated root fail canonical cursor decoding.
    let mut overwritten = Vec::from(kasumi_raft::initial_storage_identity(
        1,
        "protected-selected-root",
    )?);
    overwritten.push(WriteOp::put(
        "raft.meta",
        b"application_bootstrap_sha256",
        serde_json::to_vec(&"00".repeat(32))?,
    ));
    let rejected = fixture
        .stores
        .write_batch(
            &[WriteOp::put(
                "engine.bootstrap",
                b"manifest",
                serde_json::to_vec(&manifest)?,
            )],
            &overwritten,
        )
        .unwrap_err();
    assert!(
        rejected
            .to_string()
            .contains("initial bootstrap identity is write-once")
    );
    fixture.stores.write_batch(
        &[],
        &[WriteOp::put("raft.meta", b"applied", b"not-json".to_vec())],
    )?;
    let second = capacity.prepare(1)?.capture()?;
    let pressure = fixture.fill_all()?;
    assert!(fixture.storage.admission.reserve_resident(1).is_err());
    let before = fixture.core().snapshot();
    let (first, mut first_backing) = first_backing
        .bind_source(&fixture.stores, first)?
        .into_source();
    let mut second = second_backing.bind_source(&fixture.stores, second)?;
    let mut loan = first.point_reads(&mut first_backing)?;
    assert_eq!(loan.value_capacity(), 256);
    let selected = kasumi_raft::selected_application_at_source_loan(
        &mut loan,
        ApplicationBoundaryRef::Bootstrap(&image),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        first_grant,
        None,
    )?;
    drop(loan);
    assert_eq!(selected.bootstrap().digest, image.sha256());
    assert!(selected.applied().is_none());
    let failure = kasumi_raft::selected_application_at_source(
        &mut second,
        ApplicationBoundaryRef::Bootstrap(&image),
        ApplicationSelectionMode::Serving,
        &RaftLimits::default(),
        second_grant,
        None,
    )
    .err()
    .context("new malformed applied cursor accepted")?;
    assert!(
        failure
            .original_error()
            .chain()
            .any(|cause| cause.downcast_ref::<serde_json::Error>().is_some())
    );
    let after = fixture.core().snapshot();
    assert!(after.reserved_bytes <= before.reserved_bytes);
    assert_eq!(after.live_reservations, before.live_reservations);
    // Neither source proof reopens the current root or asks for a format-sized
    // 2MiB plaintext buffer. Even absence is read through the actual old pin.
    assert!(
        first
            .point_reads(&mut first_backing)?
            .custody_get("raft.meta", b"applied", 256)?
            .is_none()
    );
    drop((selected, failure));
    first.close()?;
    drop(first_backing);
    second.close()?;
    drop(pressure);
    capacity.seal();
    capacity.drain();
    assert_eq!(capacity.phase(), Some(SourcePoolPhase::Finished));
    let id = capacity.owner_id();
    drop(capacity);
    fixture.core().storage_census.drain_owner(id);
    drop(image);
    fixture.close().await
}

#[tokio::test]
async fn production_source_history_escape_refusal_restores_current_then_reuses_exact_lane()
-> Result<()> {
    let fixture = Fixture::new(0).await?;
    fixture.write(b"old-public-root")?;
    let old_backing = fixture.backing()?;
    let capacity = fixture.opening.queue_source_capacity()?.install()?;
    let old = capacity.prepare(0)?.capture()?;
    let old_id = old.id();
    let (old, mut backing) = old_backing.bind_source(&fixture.stores, old)?.into_source();
    let pressure = fixture.fill_all()?;
    let before = fixture.core().snapshot();
    let failure = old
        .retain_history()
        .err()
        .context("unfunded public history escaped")?;
    assert!(
        matches!(failure.downcast_ref::<kasumi_store::SourceHistoryRefusal>(),
        Some(kasumi_store::SourceHistoryRefusal::Metadata(error))
        if error.kind() == io::ErrorKind::OutOfMemory)
    );
    let actual =
        RegisteredNodeRead::retained(fixture.node.persistent_disk().memory().clone(), old_id)
            .unwrap();
    assert_eq!(actual.phase(), NodeReadPhase::SourceCaptured);
    assert!(!actual.report().has_failures());
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations
    );
    assert_eq!(
        old.point_reads(&mut backing)?
            .application_get("payload", b"key", 128)?,
        Some(b"old-public-root".as_slice())
    );
    drop((actual, failure, pressure));
    assert!(old.retain_history()?);
    assert!(old.retain_history()?); // An escaped root does not acquire history twice.
    fixture.write(b"new-current-root")?;
    let next = capacity.prepare(0)?;
    assert_ne!(next.reader_id(), old_id);
    let (next, mut backing) = backing
        .bind_source(&fixture.stores, next.capture()?)?
        .into_source();
    let pressure = fixture.fill_all()?;
    let before = fixture.core().snapshot();
    assert_eq!(
        old.point_reads(&mut backing)?
            .application_get("payload", b"key", 128)?,
        Some(b"old-public-root".as_slice())
    );
    assert_eq!(
        next.point_reads(&mut backing)?
            .application_get("payload", b"key", 128)?,
        Some(b"new-current-root".as_slice())
    );
    assert_eq!(
        fixture.core().snapshot().reserved_bytes,
        before.reserved_bytes
    );
    assert_eq!(
        fixture.core().snapshot().live_reservations,
        before.live_reservations
    );
    drop(pressure);
    drop(backing);
    old.close()?;
    next.close()?;
    capacity.seal();
    capacity.drain();
    assert_eq!(capacity.phase(), Some(SourcePoolPhase::Finished));
    let id = capacity.owner_id();
    drop(capacity);
    fixture.core().storage_census.drain_owner(id);
    fixture.close().await
}
