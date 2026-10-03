use super::*;
use crate::primary_tree::{
    ObjectId,
    records::{self, Attempt, Epoch, GcState, Inventory, InventoryPhase, ResourceKind},
    stage::{CanonicalDto, PrimaryStage},
};
use sha2::{Digest, Sha256};

#[path = "primary_stage_bulk_tests.rs"]
mod bulk_collections;
#[path = "primary_stage_catalog_tests.rs"]
mod catalogs;
#[path = "primary_stage_fixed_tests.rs"]
mod fixed_objects;

fn engine(fixture: &Fixture) -> Result<TenantEngine> {
    crate::test_utils::install_fixture_audit_placement(fixture.stores.application())?;
    let engine = TenantEngine::from_bootstrap("selected-sources", &fixture.image)?;
    engine.install_storage_access(fixture.stores.application())?;
    engine.install_application_sources(fixture.roots.clone(), &fixture.image)?;
    Ok(engine)
}
fn read<T>(
    fixture: &Fixture,
    namespace: &str,
    key: &[u8],
    max: usize,
    lend: impl FnOnce(Option<&[u8]>) -> Result<T>,
) -> Result<T> {
    let mut grant = fixture.storage.admission.reserve_document_source(4096)?;
    let mut reader = fixture.roots.open_primary_current()?;
    let result = reader.with_record(&mut grant, 4096, namespace, key, max, lend);
    let closed = reader.close();
    let result = result?;
    closed?;
    Ok(result)
}
fn decode<T>(result: std::result::Result<T, crate::primary_tree::CodecError>) -> Result<T> {
    result.map_err(|error| anyhow::anyhow!("test primary decode: {error:?}"))
}
fn pending(fixture: &Fixture) -> Result<(GcState, Epoch, Attempt)> {
    let gc = read(
        fixture,
        "engine.primary.meta",
        b"gc",
        records::GC_BYTES,
        |bytes| decode(GcState::decode(bytes.context("gc absent")?)),
    )?;
    let id = gc.building.context("building epoch absent")?;
    let epoch = read(
        fixture,
        "engine.primary.epochs",
        &id,
        records::EPOCH_BYTES,
        |bytes| decode(Epoch::decode(bytes.context("epoch absent")?)),
    )?;
    let attempt = read(
        fixture,
        "engine.primary.attempts",
        &epoch.pending.context("pending absent")?,
        records::ATTEMPT_BYTES,
        |bytes| decode(Attempt::decode(bytes.context("attempt absent")?)),
    )?;
    Ok((gc, epoch, attempt))
}
fn key(id: ObjectId) -> [u8; 24] {
    let mut key = [0; 24];
    key[..16].copy_from_slice(&id.attempt);
    key[16..].copy_from_slice(&id.ordinal.to_le_bytes());
    key
}
fn chunk_key(id: ObjectId, ordinal: u64) -> [u8; 32] {
    let mut out = [0; 32];
    out[..24].copy_from_slice(&key(id));
    out[24..].copy_from_slice(&ordinal.to_le_bytes());
    out
}
fn document(bytes: usize) -> kasumi_types::Document {
    kasumi_types::Document {
        id: "a".into(),
        version: 1,
        body: serde_json::json!({"payload":"x".repeat(bytes)}),
    }
}

// Synchronous multi-chunk work must leave an executor worker for real key renewal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_stage_large_encrypted_object_and_old_selected_pin_survive_current_abort()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    // Input + independent expected serialization have separate real ownership.
    let input = fixture
        .storage
        .admission
        .reserve_document_source(20 << 20)?;
    let doc = document(5 << 20);
    let expected = serde_json::to_vec(&doc)?;
    let expected_hash: [u8; 32] = Sha256::digest(&expected).into();
    let mut authority = engine.lock_primary_apply()?;
    let latest = fixture.roots.gate.lock().unwrap().latest.clone();
    let stage = PrimaryStage::begin_fresh(&mut authority)?;
    assert!(CellWeak::ptr_eq(
        &latest,
        &fixture.roots.gate.lock().unwrap().latest
    ));
    let (stage, reference) = stage.stage_dto([17; 16], CanonicalDto::Live(&doc))?;
    assert!(reference.encoded_bytes > 4 << 20);
    assert_eq!(reference.sha256, expected_hash);
    let mut bytes = 0;
    let mut hash = Sha256::new();
    let stage = stage.visit_staged(reference, [17; 16], ResourceKind::Live, |chunk| {
        bytes += chunk.len();
        hash.update(chunk);
        Ok(())
    })?;
    assert_eq!(bytes, expected.len());
    assert_eq!(<[u8; 32]>::from(hash.finalize()), expected_hash);
    // Real canonical Bootstrap selection captures this same native generation;
    // this is an immutable I/O regression, not primary serving activation.
    let selected = fixture.select()?;
    stage.close()?;
    drop(authority);
    let mut authority = engine.lock_primary_apply()?;
    let mut stage = PrimaryStage::resume_abort(&mut authority)?.context("pending stage absent")?;
    let mut complete = false;
    for _ in 0..8 {
        let (next, done) = stage.abort_step(64)?;
        stage = next;
        if done {
            complete = true;
            break;
        }
    }
    assert!(complete);
    let mut bytes = 0;
    let mut hash = Sha256::new();
    stage = stage.visit_selected(
        &selected,
        reference,
        [17; 16],
        ResourceKind::Live,
        |chunk| {
            bytes += chunk.len();
            hash.update(chunk);
            Ok(())
        },
    )?;
    assert_eq!(bytes, expected.len());
    assert_eq!(<[u8; 32]>::from(hash.finalize()), expected_hash);
    assert!(read(
        &fixture,
        "engine.primary.chunks",
        &chunk_key(reference.id, 0),
        65_676,
        |bytes| Ok(bytes.is_none())
    )?);
    assert!(read(
        &fixture,
        "engine.primary.inventory",
        &key(reference.id),
        records::INVENTORY_BYTES,
        |bytes| Ok(bytes.is_none())
    )?);
    stage.close()?;
    assert!(PrimaryStage::resume_abort(&mut authority)?.is_none());
    drop(authority);
    drop(selected);
    drop(expected);
    drop(doc);
    drop(input);
    engine.seal();
    drop(engine);
    fixture.close().await
}

#[tokio::test]
async fn primary_stage_partial_high_water_and_abort_resume_are_atomic() -> Result<()> {
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
    let doc = document(140_000);
    let mut authority = engine.lock_primary_apply()?;
    let error = PrimaryStage::begin_fresh(&mut authority)?
        .interrupt_after_chunks(1)
        .stage_dto([19; 16], CanonicalDto::Live(&doc))
        .err()
        .context("interruption did not fire")?;
    assert!(error.to_string().contains("after durable primary chunk"));
    let (_, epoch, attempt) = pending(&fixture)?;
    assert_eq!(attempt.next_object, 1);
    assert_eq!(attempt.live_resources, 1);
    assert_eq!(epoch.live_resources, 1);
    let id = ObjectId {
        attempt: attempt.id,
        ordinal: 0,
    };
    let inventory = read(
        &fixture,
        "engine.primary.inventory",
        &key(id),
        records::INVENTORY_BYTES,
        |bytes| decode(Inventory::decode(bytes.context("inventory absent")?)),
    )?;
    assert_eq!(inventory.phase, InventoryPhase::Allocating);
    assert_eq!(inventory.completed_units, 1);
    assert!(inventory.total_units > 1);
    assert!(read(
        &fixture,
        "engine.primary.chunks",
        &chunk_key(id, 0),
        65_676,
        |bytes| Ok(bytes.is_some())
    )?);
    assert!(read(
        &fixture,
        "engine.primary.chunks",
        &chunk_key(id, 1),
        65_676,
        |bytes| Ok(bytes.is_none())
    )?);
    // This injected interruption follows a positively acknowledged transaction,
    // not ambiguous native commit. Drop its retained resources before recovery.
    drop(error);
    drop(authority);
    let mut authority = engine.lock_primary_apply()?;
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("partial stage absent")?;
    let (stage, complete) = stage.abort_step(1)?;
    assert!(!complete);
    stage.close()?;
    drop(authority);
    let mut authority = engine.lock_primary_apply()?;
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("abort state absent")?;
    let (stage, complete) = stage.abort_step(1)?;
    assert!(!complete);
    let (_, epoch, attempt) = pending(&fixture)?;
    assert_eq!(attempt.abort_object_cursor, 1);
    assert_eq!(attempt.live_resources, 0);
    assert_eq!(epoch.live_resources, 0);
    assert!(read(
        &fixture,
        "engine.primary.inventory",
        &key(id),
        records::INVENTORY_BYTES,
        |bytes| Ok(bytes.is_none())
    )?);
    assert!(read(
        &fixture,
        "engine.primary.chunks",
        &chunk_key(id, 0),
        65_676,
        |bytes| Ok(bytes.is_none())
    )?);
    stage.close()?;
    drop(authority);
    let mut authority = engine.lock_primary_apply()?;
    let stage = PrimaryStage::resume_abort(&mut authority)?.context("empty linkage absent")?;
    let (stage, complete) = stage.abort_step(1)?;
    assert!(complete);
    stage.close()?;
    assert!(PrimaryStage::resume_abort(&mut authority)?.is_none());
    drop(authority);
    drop(doc);
    drop(input);
    engine.seal();
    drop(engine);
    fixture.close().await
}

#[tokio::test]
async fn primary_stage_rejects_payload_corruption_before_lending_and_keeps_old_pin_exact()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
    let doc = document(80_000);
    let mut authority = engine.lock_primary_apply()?;
    let (stage, reference) =
        PrimaryStage::begin_fresh(&mut authority)?.stage_dto([23; 16], CanonicalDto::Live(&doc))?;
    let old = fixture.select()?;
    let mut data = read(
        &fixture,
        "engine.primary.chunks",
        &chunk_key(reference.id, 0),
        65_676,
        |bytes| Ok(bytes.context("chunk absent")?.to_vec()),
    )?;
    data[140] ^= 1;
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            "engine.primary.chunks",
            chunk_key(reference.id, 0),
            data,
        )],
        &[],
    )?;
    let mut hash = Sha256::new();
    let stage = stage.visit_selected(&old, reference, [23; 16], ResourceKind::Live, |bytes| {
        hash.update(bytes);
        Ok(())
    })?;
    assert_eq!(<[u8; 32]>::from(hash.finalize()), reference.sha256);
    let mut calls = 0;
    let error = stage
        .visit_staged(reference, [23; 16], ResourceKind::Live, |_| {
            calls += 1;
            Ok(())
        })
        .err()
        .context("corruption was accepted")?;
    assert_eq!(calls, 0);
    assert!(error.to_string().contains("digest differs"));
    drop(error);
    // Payload-only corruption does not hide the exact framed chunk during
    // uncommitted abort; cleanup removes its owned keys through the journal.
    let mut stage = PrimaryStage::resume_abort(&mut authority)?.context("stage absent")?;
    loop {
        let (next, complete) = stage.abort_step(64)?;
        stage = next;
        if complete {
            break;
        }
    }
    stage.close()?;
    drop(authority);
    drop(old);
    drop(doc);
    drop(input);
    engine.seal();
    drop(engine);
    fixture.close().await
}

#[tokio::test]
async fn primary_stage_nonselection_readers_and_denied_begin_do_not_publish_or_write() -> Result<()>
{
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let mut authority = engine.lock_primary_apply()?;
    let latest = fixture.roots.gate.lock().unwrap().latest.clone();
    let mut occupied = Vec::new();
    while let Ok(grant) = fixture.storage.admission.reserve_resident(0) {
        occupied.push(grant);
    }
    assert!(PrimaryStage::begin_fresh(&mut authority).is_err());
    drop(occupied);
    assert!(CellWeak::ptr_eq(
        &latest,
        &fixture.roots.gate.lock().unwrap().latest
    ));
    assert!(read(
        &fixture,
        "engine.primary.meta",
        b"gc",
        records::GC_BYTES,
        |bytes| Ok(bytes.is_none())
    )?);
    let reader = fixture.roots.open_primary_current()?;
    {
        let gate = fixture.roots.gate.lock().unwrap();
        assert!(CellWeak::ptr_eq(&latest, &gate.latest));
        assert!(
            gate.cells
                .values()
                .any(|cell| cell.position.get().is_none()
                    && cell.workspace.lock().unwrap().is_none())
        );
    }
    reader.close()?;
    drop(authority);
    engine.seal();
    drop(engine);
    fixture.close().await
}

#[tokio::test]
async fn primary_stage_partial_attempt_resumes_after_actual_encrypted_reopen() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let first_engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
    let doc = document(140_000);
    let mut authority = first_engine.lock_primary_apply()?;
    let error = PrimaryStage::begin_fresh(&mut authority)?
        .interrupt_after_chunks(1)
        .stage_dto([29; 16], CanonicalDto::Live(&doc))
        .err()
        .context("interruption absent")?;
    let (_, before_epoch, before_attempt) = pending(&fixture)?;
    drop(error);
    drop(authority);
    drop(doc);
    drop(input);
    first_engine.seal();
    drop(first_engine);
    std::future::poll_fn(|cx| fixture.roots.poll_drain(cx)).await?;
    assert!(fixture.roots.is_drained());
    fixture.storage.admission.drain_snapshot_startups().await?;
    fixture.stores.shutdown().await?;
    fixture.node.shutdown().await?;
    // Final startup drain seals one runtime facade, not the installed core.
    // The reopen uses the production fresh-facade constructor over that same
    // actual persistent/scratch provider and unchanged aggregate policy.
    let admission = NodeAdmission::from_memory(fixture.storage.admission.memory().clone())?;
    assert!(admission.shares_memory(&fixture.storage.admission));
    assert!(!Arc::ptr_eq(&admission, &fixture.storage.admission));
    fixture.storage.admission = admission;
    fixture.node = fixture.storage.open_existing(
        fixture._directory.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
    )?;
    fixture.stores = TenantStorageSet::open_existing_fixture(
        fixture.node.clone(),
        "selected-sources".into(),
        Arc::new(LocalKeyProvider::new([119; 32])),
        Arc::new(LocalKeyProvider::new([120; 32])),
    )
    .await?;
    let (roots, binding) = SourceRoots::new(
        fixture.stores.clone(),
        fixture.storage.admission.clone(),
        RaftLimits::default(),
    )?;
    fixture.roots = roots;
    fixture._buffers = fixture.storage.admission.snapshot_buffer_owner()?;
    fixture.roots.bind_lifecycle(&fixture._buffers, binding)?;
    let reopened_engine = engine(&fixture)?;
    let (_, after_epoch, after_attempt) = pending(&fixture)?;
    assert_eq!(before_epoch, after_epoch);
    assert_eq!(before_attempt, after_attempt);
    let mut authority = reopened_engine.lock_primary_apply()?;
    let mut stage =
        PrimaryStage::resume_abort(&mut authority)?.context("reopened pending attempt absent")?;
    let mut complete = false;
    for _ in 0..4 {
        let (next, done) = stage.abort_step(1)?;
        stage = next;
        if done {
            complete = true;
            break;
        }
    }
    assert!(complete);
    stage.close()?;
    assert!(PrimaryStage::resume_abort(&mut authority)?.is_none());
    drop(authority);
    reopened_engine.seal();
    drop(reopened_engine);
    fixture.close().await
}

#[tokio::test]
async fn primary_stage_native_bound_failure_keeps_original_diagnostic_through_positive_close()
-> Result<()> {
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
    let doc = document(128);
    let mut authority = engine.lock_primary_apply()?;
    let (stage, reference) =
        PrimaryStage::begin_fresh(&mut authority)?.stage_dto([31; 16], CanonicalDto::Live(&doc))?;
    // Real encrypted row exceeds the caller's bounded native read, so refusal
    // occurs before application framing/JSON can synthesize a corruption error.
    fixture.stores.write_batch(
        &[kasumi_store::WriteOp::put(
            "engine.primary.chunks",
            chunk_key(reference.id, 0),
            vec![0; 65_677],
        )],
        &[],
    )?;
    let error = stage
        .visit_staged(reference, [31; 16], ResourceKind::Live, |_| {
            panic!("native refusal lent data")
        })
        .err()
        .context("native refusal absent")?;
    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<kasumi_store::NodeScopedReadFailure>())
        .context("original native failure missing")?;
    let id = failure.reader_id();
    let original_address = failure as *const _ as usize;
    assert!(failure.report().has_failures());
    assert!(
        fixture
            .roots
            .gate
            .lock()
            .unwrap()
            .cells
            .values()
            .any(|cell| cell.failure.get().is_some())
    );
    drop(authority);
    engine.seal();
    drop(engine);
    // Existing startup custody performs the final close while the returned
    // error still owns its actual stage resources. No error string replaces
    // the immutable original report, and no new cleanup admission is needed.
    let _outcome = std::future::poll_fn(|cx| fixture.roots.poll_drain(cx)).await;
    assert!(fixture.roots.is_drained());
    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<kasumi_store::NodeScopedReadFailure>())
        .unwrap();
    assert_eq!(failure as *const _ as usize, original_address);
    assert_eq!(failure.reader_id(), id);
    assert_eq!(
        failure.try_retire_routine(),
        kasumi_store::StorageCensusDisposition::Retired
    );
    assert!(failure.report().has_failures());
    drop(doc);
    drop(input);
    fixture.close().await?;
    let failure = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<kasumi_store::NodeScopedReadFailure>())
        .unwrap();
    assert_eq!(failure.reader_id(), id);
    assert!(failure.report().has_failures());
    drop(error);
    Ok(())
}

#[tokio::test]
async fn primary_stage_archive_and_definition_keep_exact_dto_and_kind_identity() -> Result<()> {
    let fixture = Fixture::new().await?;
    let engine = engine(&fixture)?;
    let input = fixture.storage.admission.reserve_document_source(1 << 20)?;
    // Both parent and child are unsorted with preserve_order enabled, so the
    // canonical schema path must hold their borrowed-entry scratch together.
    let mut child = serde_json::Map::new();
    child.insert("z".into(), serde_json::json!(true));
    child.insert("a".into(), serde_json::json!(null));
    let mut schema = serde_json::Map::new();
    schema.insert("z".into(), serde_json::Value::Object(child));
    schema.insert("a".into(), serde_json::json!("object"));
    let definition = kasumi_types::CollectionDefinition {
        name: "docs".into(),
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        schema: serde_json::Value::Object(schema),
        indexes: Vec::new(),
        strict_read_audit: false,
    };
    let archived = kasumi_types::ArchivedDocument {
        version: 7,
        archive_id: "archive".into(),
        chunk_index: 3,
        document_sha256: "ab".repeat(32),
        document_bytes: 80_000,
        indexed_fields: std::collections::BTreeMap::from([("field".into(), serde_json::json!(17))]),
    };
    let definition_expected = serde_json::to_vec(&definition)?;
    let archive_expected = serde_json::to_vec(&archived)?;
    let mut authority = engine.lock_primary_apply()?;
    let stage = PrimaryStage::begin_fresh(&mut authority)?;
    let (stage, definition_ref) =
        stage.stage_dto([37; 16], CanonicalDto::Definition(&definition))?;
    let (mut stage, archive_ref) = stage.stage_dto([37; 16], CanonicalDto::Archived(&archived))?;
    for (reference, kind, expected) in [
        (
            definition_ref,
            ResourceKind::Definition,
            definition_expected.as_slice(),
        ),
        (
            archive_ref,
            ResourceKind::Archived,
            archive_expected.as_slice(),
        ),
    ] {
        let expected_hash: [u8; 32] = Sha256::digest(expected).into();
        assert_eq!(reference.sha256, expected_hash);
        let mut hash = Sha256::new();
        let mut bytes = 0;
        stage = stage.visit_staged(reference, [37; 16], kind, |part| {
            hash.update(part);
            bytes += part.len();
            Ok(())
        })?;
        assert_eq!(bytes, expected.len());
        assert_eq!(<[u8; 32]>::from(hash.finalize()), expected_hash);
    }
    let mut calls = 0;
    let error = stage
        .visit_staged(definition_ref, [37; 16], ResourceKind::Archived, |_| {
            calls += 1;
            Ok(())
        })
        .err()
        .context("different DTO kind was accepted")?;
    assert_eq!(calls, 0);
    assert!(error.to_string().contains("inventory differs"));
    drop(error);
    let mut stage = PrimaryStage::resume_abort(&mut authority)?.context("pending stage absent")?;
    loop {
        let (next, done) = stage.abort_step(64)?;
        stage = next;
        if done {
            break;
        }
    }
    stage.close()?;
    drop(authority);
    drop(definition_expected);
    drop(archive_expected);
    drop(definition);
    drop(archived);
    drop(input);
    engine.seal();
    drop(engine);
    fixture.close().await
}
